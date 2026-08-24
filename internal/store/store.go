// Package store 提供 data/ 目录下 JSON 文件的原子读写能力。
// 与 Python 版 load/save 行为对齐：临时文件 + os.Rename 原子替换，避免写半截。
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// AtomicSave 将 v 序列化为 JSON 并原子写入 file。
// 目录不存在时自动创建；写入过程写 tmp 再 rename，崩溃不产生半成品文件。
func AtomicSave(file string, v interface{}) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// AtomicSaveRaw 将原始字节原子写入 file（用于无缩进的历史数据）。
func AtomicSaveRaw(file string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// LoadJSON 读取并解析 JSON 文件，失败(不存在/损坏)时返回零值+错误。
func LoadJSON(file string, v interface{}) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}