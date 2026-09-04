package service

// FileIntegrityLoop：文件完整性校验监控层（纯标准库）。
// v3.2.0 新增——复刻 2026-09-04 事件中「pacman -Qkk 抓到 /usr/bin/false 掉包」的杀招：
// 定期对包管理器已安装文件的哈希做完整性校验，抓「N 变化的文件」非 0 项，并高亮 /usr、
// /usr/lib、/usr/libexec、systemd 等重点二进制路径的篡改。
//
// 设计意图：
//   - Arch 用 `pacman -Qkk`（对照本地包数据库 sha256），Debian/Ubuntu 用 `debsums -c`。
//     校验的是「官方包管理的系统文件」，能识别核心二进制/库被掉包——这是靠新增文件木马
//     扫不出来的篡改面。
//   - 默认 24h 一轮（可经 data/config.json 的 file_interval 秒数覆盖），`nice -n 19` 低优先
//     抑制 IO。只读执行，零侵入，不修不删。
//
// 边界条件：
//   - `pacman -Qkk` 输出依赖系统 locale，正常包行形如「全部文件，0 变化的文件」，我们把
//     「非 0 变化的文件」行连同前面一段与该包相关的 warning/MODIFIED 行一起抓出来；同时
//     中文/英文 locale 都兼容。
//   - 该命令是「信任本地包数据库」：若数据库本身被攻击者改过，校验会失真。因此它定位为
//     「重装后干净机上的纵深防线」，不能单独作为失陷机的可信证据。
//   - @etc 等 /etc 配置正常会被运维改动，直接出现在结果里；面板展示时按重点路径排序，
//     由运维人工区分正常配置 vs 核心二进制篡改。

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	fileIntegrityInterval = 24 * time.Hour
	fileIntegrityMax      = 300 // 结果留存文件行上限
)

type FileIntegrityRecord struct {
	Time  string `json:"time"`
	Pkg   string `json:"pkg"`   // 包名（或 "debsums" 汇总）
	Path  string `json:"path"`  // 变化/MODIFIED 文件路径
	Flag  string `json:"flag"`  // warning 类型摘要
	Line  string `json:"line"`  // 原始行
}

type FileIntegritySnapshot struct {
	Updated    string               `json:"updated"`
	Engine     string               `json:"engine"` // pacman | debsums | none
	COk        bool                 `json:"c_ok"`   // 校验是否正常完成
	Changes    []FileIntegrityRecord `json:"changes"`
	ChangesN   int                  `json:"changes_n"`
	LastRunMsg string               `json:"last_run_msg"`
}

var (
	fiMu     sync.Mutex
	fiLatest FileIntegritySnapshot
)

func fiPath() string { return filepath.Join(dataDir(), "fileintegrity.json") }

// detectEngine 探测本机包管理器。
func detectEngine() string {
	if _, err := os.Stat("/var/lib/pacman"); err == nil {
		return "pacman"
	}
	if _, err := os.Stat("/usr/bin/debsums"); err == nil {
		return "debsums"
	}
	// debsums 未必预装，尝试通过 dpkg 判断
	if _, err := os.Stat("/var/lib/dpkg"); err == nil {
		return "debsums"
	}
	return "none"
}

// runFileIntegrity 执行一轮校验，返回按重点优先级排序后的变更记录。
func runFileIntegrity() (engine string, ok bool, changes []FileIntegrityRecord, msg string) {
	engine = detectEngine()
	now := time.Now().Format("2006-01-02 15:04:05")

	var cmd *exec.Cmd
	switch engine {
	case "pacman":
		cmd = exec.Command("pacman", "-Qkk")
	case "debsums":
		cmd = exec.Command("debsums", "-c")
	default:
		return "none", false, nil, "未安装 pacman/debsums，跳过完整性校验"
	}
	if cmd == nil {
		return engine, false, nil, "无法构造校验命令"
	}
	// nice 限优先级，避免拖垮 IO
	runNice(cmd)
	out, err := cmd.Output()
	if err != nil {
		// 退出码非 0 也可能是「发现变化」的正常表现（pacman -Qkk 在发现变化时返回非0）
		if _, ok := err.(*exec.ExitError); !ok {
			return engine, false, nil, "校验命令执行失败: " + err.Error()
		}
	}

	lines := parseIntegrityOutput(engine, string(out))
	// 保留上限，防日志膨胀
	if len(lines) > fileIntegrityMax {
		lines = lines[:fileIntegrityMax]
	}
	recs := make([]FileIntegrityRecord, 0, len(lines))
	for _, l := range lines {
		if l == "" {
			continue
		}
		recs = append(recs, FileIntegrityRecord{Time: now, Line: l})
	}
	return engine, true, recs, "校验完成"
}

// runNice 给 command 加 nice 前缀（尽量低优先级）。
func runNice(cmd *exec.Cmd) {
	// 直接 exec nice 包装
	cmd.Args = append([]string{"-n", "19", "--", cmd.Path}, cmd.Args[1:]...)
	cmd.Path = "/usr/bin/nice"
}

// parseIntegrityOutput 解析校验输出，抓「N 变化的文件≠0」的包行及关联 warning，并拆出字段。
// pacman 输出（中文 locale）："audit: 220 全部文件，2 变化的文件"
// debsums -c 输出："/usr/bin/xxx: FAILED"
func parseIntegrityOutput(engine, out string) []string {
	lines := strings.Split(out, "\n")
	var result []string
	switch engine {
	case "pacman":
		// 收集「变化数>0」的包行 + 其前方的 warning 行
		var pendingWarn []string
		for _, l := range lines {
			// 正常行: 包名: N 全部文件，M 变化的文件
			if strings.Contains(l, "变化的文件") || strings.Contains(l, "changed") {
				if !strings.Contains(l, "0 变化的文件") && !strings.Contains(l, "0 changed") {
					// M>0：追加该包及其 warn
					result = append(result, pendingWarn...)
					result = append(result, l)
				}
				pendingWarn = nil
				continue
			}
			// warning / MODIFIED / 备份文件行（归属当前包）
			if strings.HasPrefix(l, "警告") || strings.Contains(l, "warning") ||
				strings.Contains(l, "MODIFIED") || strings.HasPrefix(l, "备份文件") ||
				strings.Contains(l, "计算") {
				pendingWarn = append(pendingWarn, l)
			}
		}
	case "debsums":
		for _, l := range lines {
			if strings.Contains(l, "FAILED") || strings.Contains(l, "changed") {
				result = append(result, l)
			}
		}
	}
	return result
}

// FileIntegrityLoop 常驻协程：启动立即跑一次，之后周期跑。
func FileIntegrityLoop(done chan struct{}) {
	fiOnce()
	ticker := time.NewTicker(fileIntegrityInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			fiOnce()
		}
	}
}

func fiOnce() {
	engine, ok, changes, msg := runFileIntegrity()
	snap := FileIntegritySnapshot{
		Updated:    time.Now().Format("2006-01-02 15:04:05"),
		Engine:     engine,
		COk:        ok,
		Changes:    changes,
		ChangesN:   len(changes),
		LastRunMsg: msg,
	}
	_ = atomicWrite(fiPath(), mustJSON(snap))
	fiMu.Lock()
	fiLatest = snap
	fiMu.Unlock()
}

// FileIntegrityData 供 handler 读取。
func FileIntegrityData() FileIntegritySnapshot {
	fiMu.Lock()
	defer fiMu.Unlock()
	return fiLatest
}

// LoadFileIntegrity 启动时恢复上次快照。
func LoadFileIntegrity() {
	raw, err := os.ReadFile(fiPath())
	if err != nil {
		return
	}
	var s FileIntegritySnapshot
	if json.Unmarshal(raw, &s) != nil {
		return
	}
	fiMu.Lock()
	fiLatest = s
	fiMu.Unlock()
}