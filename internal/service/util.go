package service

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Sprintf 便捷格式化导出（供 handler 使用）。
func Sprintf(format string, a ...interface{}) string {
	return fmt.Sprintf(format, a...)
}

// 通用工具函数：JSON 编解码、原子写、命令执行。与各模块共享，避免重复实现。

func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// atomicWrite 字节级原子写（同目录 tmp + rename）。
func atomicWrite(file string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// runOK 执行命令并返回是否成功(退出码为0且无致命错误)。
func runOK(name string, args ...string) bool {
	cmd := exec.Command(name, args...)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// runOut 执行命令并返回 stdout；失败返回空串。
func runOut(timeout time.Duration, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	// 用命令自身超时(外部工具如 timeout) 或依赖系统；此处暂不强制
	out, _ := cmd.Output()
	return string(out)
}