package service

// ProcTraceLoop：执行来源追溯（纯标准库）。
// v3.3.0 新增——回答「命令从哪个入口/谁触发进来的」：基于 auditd 的 execve 审计
// （`ausearch -k PROC_EXEC` / `aureport -x`，本机已配 `-a always,exit -S execve -k PROC_EXEC`），
// 对可疑进程（ProcGuard 发现的伪 kernel 线程 / setuid 掉包 / RCE 特征）回查其父链与触发者，
// 定位攻击路径（由 sshd→pam_exec、cron、systemd unit、手动 shell 哪个环节拉起）。
//
// 数据源：
//   - `aureport -x`：exec 事件列表（时间、exe 路径、host 会话来源、auid）。
//   - `ausearch -k PROC_EXEC`：原始 SYSCALL，含 pid/ppid/comm/exe/auid —— 用于建父链。
//
// 设计意图：
//   - 纯只读，零侵入；周期性（60s）刷新最近 exec 快照，落盘 data/proctrace.json。
//   - 核心 `TracePID(pid)`：输入可疑 PID，回溯父链 + 触发者，输出「来源画像」。
//   - 抽纯函数 `resolveSource` 便于无污染单测（不依赖真实 auditd）。
//
// 边界（诚实）：
//   - 追溯的是「本地谁触发/谁拉起」；公网来源 IP 不在本模块（无访问日志的 web/RCE 入口 → 来源
//     是网络侧，需靠 web 日志，本模块只给本地触发链）。
//   - audit 日志受保留期限制：距今过远(典型 /var/log/audit 30天)的 exec 已被轮转，追溯不到。
//     因此本模块价值在「今后再发生能当场溯源」（重装后新机上启用），不在追很久以前的旧账。
//   - 基线/来源画像同样依赖「干净机部署」，失陷机上的历史 exec 无意义。

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	procTraceInterval = 60 * time.Second
	procTraceMax      = 2000 // exec 事件缓存上限（避免长驻膨胀）
)

// AuditExec 单条 exec 审计事件（用于建父链/来源画像）。
type AuditExec struct {
	Time string `json:"time"`
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe"`
	AUid int64  `json:"auid"`
	Host string `json:"host,omitempty"` // 会话来源 host（aureport 提供，可能为空）
}

// TraceResult 对某 PID 的「来源画像」。
type TraceResult struct {
	TargetPID  int    `json:"target_pid"`
	TargetExe  string `json:"target_exe"`
	Triggered  string `json:"triggered"` // 由父链推断的触发环节描述
	PPID       int    `json:"ppid"`
	ParentComm string `json:"parent_comm"`
	ParentExe  string `json:"parent_exe"`
	Time       string `json:"time"`
	Chain      []string `json:"chain"` // PID 自顶向下的父子链描述，如 ["systemd(1)","pam_exec(?>","pam-helper(2159)"]
}

type ProcTraceSnapshot struct {
	Updated string       `json:"updated"`
	Execs   []AuditExec  `json:"execs"`   // 最近 exec 快照（供面板/内部追溯）
	Traces  []TraceResult `json:"traces"` // 对「可疑 PID」的追溯结果
}

var (
	ptMu     sync.Mutex
	ptLatest ProcTraceSnapshot
)

func ptPath() string { return filepath.Join(dataDir(), "proctrace.json") }

// loadAuditExecs 调 ausearch 拉最近 exec 事件（只读，不含 bus 系统命令）。
func loadAuditExecs(limit int) []AuditExec {
	var execs []AuditExec
	// ausearch 原生输出含 pid/ppid/exe/comm/auid；grep 关键字段几节
	raw, _ := exec.Command("ausearch", "-k", "PROC_EXEC").Output()
	// 按事件块解析（type=SYSCALL ... pid= ppid= comm= exe= auid=）
	cur := AuditExec{}
	var block []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "type=SYSCALL") {
			if cur.PID != 0 {
				execs = append(execs, cur)
			}
			cur = AuditExec{}
			block = strings.Fields(line)
		} else {
			block = nil
		}
		// 从 SYSCALL 行提取 pid/ppid/comm/exe/auid
		if strings.HasPrefix(line, "type=SYSCALL") {
			for _, f := range block {
				switch {
				case strings.HasPrefix(f, "pid="):
					if n, err := strconv.Atoi(strings.TrimPrefix(f, "pid=")); err == nil {
						cur.PID = n
					}
				case strings.HasPrefix(f, "ppid="):
					if n, err := strconv.Atoi(strings.TrimPrefix(f, "ppid=")); err == nil {
						cur.PPID = n
					}
				case strings.HasPrefix(f, "auid="):
					if n, err := strconv.ParseInt(strings.TrimPrefix(f, "auid="), 10, 64); err == nil {
						cur.AUid = n
					}
				case strings.HasPrefix(f, "comm="):
					cur.Comm = strings.Trim(f[5:], `"`)
				case strings.HasPrefix(f, "exe="):
					cur.Exe = strings.Trim(f[4:], `"`)
				}
			}
		}
	}
	if cur.PID != 0 {
		execs = append(execs, cur)
	}
	if len(execs) > limit {
		execs = execs[len(execs)-limit:]
	}
	// 跳过无 PID 的噪声
	filtered := execs[:0]
	for _, e := range execs {
		if e.PID > 0 {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// resolveSource 纯函数：从 exec 事件集回溯某 PID 的父链并推断触发环节。
// 不依赖真实 auditd，便于单测。
func resolveSource(pid int, execs []AuditExec) TraceResult {
	res := TraceResult{TargetPID: pid}
	byPID := map[int]AuditExec{}
	for _, e := range execs {
		byPID[e.PID] = e
	}
	e, ok := byPID[pid]
	if !ok {
		res.Triggered = "exec 快照中无此 PID（可能超保留期或未在该快照窗口执行）"
		return res
	}
	res.TargetExe = e.Exe
	res.Time = e.Time
	res.PPID = e.PPID
	res.ParentExe = ""
	if pe, ok2 := byPID[e.PPID]; ok2 {
		res.ParentExe = pe.Exe
		res.ParentComm = pe.Comm
	}
	// 自顶向下链表：从 pid=1(systemd/PID1) 向下拼到 target
	seq := []string{}
	cur := pid
	for depth := 0; depth < 12 && cur > 0; depth++ {
		ce, ok := byPID[cur]
		if !ok {
			seq = append(seq, strconv.Itoa(cur)+"(?)")
			break
		}
		name := ce.Comm
		if name == "" {
			name = ce.Exe
		}
		seq = append(seq, strconv.Itoa(cur)+"("+name+")")
		cur = ce.PPID
	}
	// 反转成自顶向下
	for i, j := 0, len(seq)-1; i < j; i, j = i+1, j-1 {
		seq[i], seq[j] = seq[j], seq[i]
	}
	res.Chain = seq
	res.Triggered = inferTrigger(res, byPID)
	return res
}

func inferTrigger(res TraceResult, byPID map[int]AuditExec) string {
	// 借助父链名推断触发环节
	lower := strings.ToLower(res.ParentExe + " " + res.ParentComm)
	switch {
	case strings.Contains(lower, "sshd"):
		return "SSH 会话触发（登录/命令执行）"
	case strings.Contains(lower, "pam_exec") || strings.Contains(lower, "pam"):
		return "PAM 钩子触发（pam_exec 注入）"
	case strings.Contains(lower, "cron") || strings.Contains(lower, "systemd-timer"):
		return "定时任务触发（cron/timer）"
	case strings.Contains(lower, "su") || strings.Contains(lower, "sudo"):
		return "提权触发（su/sudo）"
	case strings.Contains(lower, "systemd"):
		return "systemd 进程拉起"
	case strings.Contains(lower, "bash") || strings.Contains(lower, "sh"):
		return "shell 手动/脚本触发"
	}
	return "未知触发环节（父进程: " + res.ParentComm + "）"
}

// traceSuspicious 对一组可疑 PID 逐个追溯来源。execs 为当前 exec 快照。
func traceSuspicious(suspicious []int, execs []AuditExec) []TraceResult {
	var traces []TraceResult
	for _, pid := range suspicious {
		traces = append(traces, resolveSource(pid, execs))
	}
	return traces
}

// ProcTraceLoop 常驻协程：周期刷新 exec 快照。
func ProcTraceLoop(done chan struct{}) {
	ptOnce()
	ticker := time.NewTicker(procTraceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			ptOnce()
		}
	}
}

func ptOnce() {
	execs := loadAuditExecs(procTraceMax)
	snap := ProcTraceSnapshot{Updated: time.Now().Format("2006-01-02 15:04:05"), Execs: execs}
	// 可疑来源：对接 ProcGuard 当前发现的伪 kthread PID（若有）
	suspicious := currentSuspiciousPIDs()
	if len(suspicious) > 0 {
		snap.Traces = traceSuspicious(suspicious, execs)
	}
	_ = atomicWrite(ptPath(), mustJSON(snap))
	ptMu.Lock()
	ptLatest = snap
	ptMu.Unlock()
}

// currentSuspiciousPIDs 从 ProcGuard 当前快照取伪 kernel 线程 PID（作为待追溯源）。
func currentSuspiciousPIDs() []int {
	pd := ProcGuardData()
	var out []int
	for _, a := range pd.Alerts {
		if a.Kind == "fkthread" && a.PID > 0 {
			out = append(out, a.PID)
		}
	}
	return out
}

// ProcTraceData 供 handler 读取。
func ProcTraceData() ProcTraceSnapshot {
	ptMu.Lock()
	defer ptMu.Unlock()
	return ptLatest
}

// LoadProcTrace 启动时恢复上次快照。
func LoadProcTrace() {
	raw, err := os.ReadFile(ptPath())
	if err != nil {
		return
	}
	var s ProcTraceSnapshot
	if json.Unmarshal(raw, &s) != nil {
		return
	}
	ptMu.Lock()
	ptLatest = s
	ptMu.Unlock()
}