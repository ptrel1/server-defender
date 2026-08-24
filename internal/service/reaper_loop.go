package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// 进程自愈 (Reaper)：巡检并收割失控的高 CPU 孤儿进程。
// 与 Python reaper.py 相同的三重安全防御：
//   1. 目标指令白名单
//   2. 豁免服务白名单
//   3. 触发条件：运行>900s 且 (孤儿 PPID==1 或 CPU>=50%)
const (
	reaperInterval = 30 * time.Second
	maxRuntime     = 900 * time.Second
	highCPU        = 50.0
)

var (
	targetCommands = map[string]bool{"grep": true, "egrep": true, "fgrep": true,
		"find": true, "sed": true, "awk": true, "xargs": true}
	safeCommands = map[string]bool{"node": true, "python": true, "python3": true,
		"java": true, "mysqld": true, "postgres": true, "kilo": true, "bash": true,
		"zsh": true, "fish": true, "sh": true, "sshd": true, "nginx": true,
		"frpc": true, "frps": true, "supervisord": true, "systemd": true,
		"docker": true, "containerd": true, "tail": true, "journalctl": true}

	reaperMu  sync.Mutex
	reapFile  = filepath.Join(dataDir(), "reaper_events.json")
)

// ReapEvent 与 Python reaper_events.json 结构对齐。
type ReapEvent struct {
	PID    int    `json:"pid"`
	Comm   string `json:"comm"`
	User   string `json:"user"`
	CPU    float64 `json:"cpu"`
	ETime  string `json:"etime"`
	Args   string `json:"args"`
	Reason string `json:"reason"`
	Time   string `json:"time"`
}

// ProcessInfo ps 输出的进程记录。
type ProcessInfo struct {
	PID, PPID int
	User      string
	CPU, Mem  float64
	ETime     string
	Comm      string
	Args      string
}

// HighCPUProcesses 获取 CPU 占用 TOP N 进程（供面板展示）。
func HighCPUProcesses(limit int) []ProcessInfo {
	out := runOut(5*time.Second, "ps", "-eo", "pid,ppid,user,%cpu,%mem,etime,comm,args", "--sort=-%cpu")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	procs := []ProcessInfo{}
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		if p, ok := parsePSLine(line); ok {
			if limit > 0 && len(procs) < limit {
				procs = append(procs, p)
			}
		}
	}
	return procs
}

// parsePSLine 解析 ps 输出的一行。
func parsePSLine(line string) (ProcessInfo, bool) {
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return ProcessInfo{}, false
	}
	p := ProcessInfo{}
	var err error
	p.PID, err = strconv.Atoi(fields[0])
	if err != nil {
		return ProcessInfo{}, false
	}
	p.PPID, _ = strconv.Atoi(fields[1])
	p.User = fields[2]
	p.CPU, _ = strconv.ParseFloat(fields[3], 64)
	p.Mem, _ = strconv.ParseFloat(fields[4], 64)
	p.ETime = fields[5]
	p.Comm = fields[6]
	args := strings.Join(fields[7:], " ")
	if len(args) > 200 {
		args = args[:200]
	}
	p.Args = args
	return p, true
}

// parseElapsed 把 "mm:ss" / "hh:mm:ss" / "dd-hh:mm:ss" 转为秒。
func parseElapsed(etime string) time.Duration {
	e := strings.TrimSpace(etime)
	days := 0
	if idx := strings.IndexByte(e, '-'); idx > 0 {
		d, err := strconv.Atoi(e[:idx])
		if err == nil {
			days = d
		}
		e = e[idx+1:]
	}
	parts := strings.Split(e, ":")
	if len(parts) == 2 {
		m, _ := strconv.Atoi(parts[0])
		s, _ := strconv.Atoi(parts[1])
		return time.Duration(days*86400+m*60+s) * time.Second
	}
	if len(parts) == 3 {
		h, _ := strconv.Atoi(parts[0])
		m, _ := strconv.Atoi(parts[1])
		s, _ := strconv.Atoi(parts[2])
		return time.Duration(days*86400+h*3600+m*60+s) * time.Second
	}
	return 0
}

// inspectAndReap 执行一轮巡检，返回本轮收割事件。
func inspectAndReap() []ReapEvent {
	reaped := []ReapEvent{}
	curPID := os.Getpid()
	out := runOut(5*time.Second, "ps", "-eo", "pid,ppid,user,%cpu,%mem,etime,comm,args")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		cpu, _ := strconv.ParseFloat(fields[3], 64)
		etime := fields[5]
		comm := strings.ToLower(fields[6])
		baseComm := comm
		if idx := strings.LastIndexByte(baseComm, '/'); idx >= 0 {
			baseComm = baseComm[idx+1:]
		}
		if pid <= 1 || pid == curPID {
			continue
		}
		if safeCommands[baseComm] {
			continue
		}
		if !targetCommands[baseComm] {
			continue
		}
		if parseElapsed(etime) < maxRuntime {
			continue
		}
		isOrphan := ppid == 1
		isHigh := cpu >= highCPU
		if !isOrphan && !isHigh {
			continue
		}
		reasons := []string{}
		if isOrphan {
			reasons = append(reasons, "孤儿进程(PPID=1)")
		}
		if isHigh {
			reasons = append(reasons, fmt.Sprintf("高CPU占用(%.0f%%)", cpu))
		}
		reason := fmt.Sprintf("运行已达 %s (>%d分钟), %s", etime, maxRuntime/600, strings.Join(reasons, ", "))
		fmt.Printf("[reaper] 发现失控进程 PID=%d COMM=%s 原因:%s\n", pid, fields[6], reason)

		// 优雅终止 → 强杀
		if syscall.Kill(pid, syscall.SIGTERM) == nil {
			time.Sleep(500 * time.Millisecond)
			if syscall.Kill(pid, 0) == nil {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}
		reaped = append(reaped, ReapEvent{
			PID: pid, Comm: fields[6], User: fields[2], CPU: cpu,
			ETime: etime, Args: strings.Join(fields[7:], " "), Reason: reason,
			Time: time.Now().Format("2006-01-02 15:04:05"),
		})
	}
	if len(reaped) > 0 {
		existing := LoadReaperEvents()
		merged := append(reaped, existing...)
		if len(merged) > 50 {
			merged = merged[:50]
		}
		_ = saveReaperEvents(merged)
	}
	return reaped
}

func LoadReaperEvents() []ReapEvent {
	ev := []ReapEvent{}
	if b, err := os.ReadFile(reapFile); err == nil {
		_ = jsonUnmarshal(b, &ev)
	}
	return ev
}

func saveReaperEvents(ev []ReapEvent) error {
	b, _ := jsonMarshal(ev)
	return atomicWrite(reapFile, b)
}

// KillByPID 手动按 PID 终止进程（面板 "终止" 按钮）。
func KillByPID(pid int) (bool, string) {
	if pid <= 1 {
		return false, "禁止终止系统核心进程"
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return false, err.Error()
	}
	return true, "已强制终止进程"
}

// ReaperLoop 后台巡检协程。
func ReaperLoop(done <-chan struct{}) {
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			reaperMu.Lock()
			inspectAndReap()
			reaperMu.Unlock()
		}
	}
}

// 以下为等价导出入口，供 handler 使用。