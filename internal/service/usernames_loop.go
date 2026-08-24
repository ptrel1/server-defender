package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// usernames.json 状态结构（与 Python 版对齐）。
type UsernamesState struct {
	IPs        map[string]*IPRecord `json:"ips"`
	Whitelist  []string             `json:"whitelist"`
}

type IPRecord struct {
	Users    []string `json:"users"`
	Banned   bool     `json:"banned"`
	Reason   string   `json:"reason,omitempty"`
	Location string   `json:"location,omitempty"`
	Time     string   `json:"time,omitempty"`
}

const (
	stateFile  = "usernames.json"
	banFile    = "perm_ban.txt"
	relayHost  = "root@47.98.244.173" // 中转机地址
	threshold  = 100                  // 用户名风暴阈值
	saveEvery  = 30 * time.Second
)

var (
	reFail   = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from ([\d\.:a-fA-F]+) port`)
	reAccept = regexp.MustCompile(`Accepted publickey for (\S+) from ([\d\.:a-fA-F]+)`)
	ignoreIP = map[string]bool{"127.0.0.1": true, "::1": true, "127.0.0.2": true}

	stateMu sync.Mutex
)

func statePath() string { return filepath.Join(dataDir(), stateFile) }
func banPath() string   { return filepath.Join(dataDir(), banFile) }

// BanFilePath 导出封禁列表路径(供 handler 读取)。
func BanFilePath() string { return banPath() }

// StateFilePath 导出状态文件路径。
func StateFilePath() string { return statePath() }

func loadUsernamesState() *UsernamesState {
	s := &UsernamesState{IPs: map[string]*IPRecord{}}
	data, err := os.ReadFile(statePath())
	if err == nil {
		_ = jsonUnmarshal(data, s)
	}
	if s.IPs == nil {
		s.IPs = map[string]*IPRecord{}
	}
	return s
}

func saveUsernamesState(s *UsernamesState) {
	b, _ := jsonMarshal(s)
	if len(b) > 0 {
		_ = atomicWrite(statePath(), b)
	}
}

// writeBanFile 生成面板读取的封禁列表 (ip\t原因\t时间\t归属地)。
func writeBanFile(s *UsernamesState) {
	var sb strings.Builder
	for ip, rec := range s.IPs {
		if rec.Banned {
			reason := rec.Reason
			if reason == "" {
				reason = fmt.Sprintf("不同账号数:%d", len(rec.Users))
			}
			loc := rec.Location
			if loc == "" {
				loc = "未知"
			}
			sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\n", ip, reason, rec.Time, loc))
		}
	}
	_ = atomicWrite(banPath(), []byte(sb.String()))
}

// isBannedLocal 检查 iptables 是否已存在该 IP 的 DROP 规则。
func isBannedLocal(ip string) bool {
	return runOK("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
}

// banLocal 本机下发永久封禁。
func banLocal(ip string) {
	_ = runOK("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	_ = runOK("iptables-save")
}

// syncRelay 同步封禁到中转机。
func syncRelay(ip string) {
	cmd := fmt.Sprintf("iptables -C INPUT -s %s -j DROP >/dev/null 2>&1 || iptables -A INPUT -s %s -j DROP; iptables-save >/dev/null", ip, ip)
	_ = exec.Command("ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=8", relayHost, cmd).Run()
}

// applyAllBans 启动时重放所有已封 IP。
func applyAllBans(s *UsernamesState) {
	for ip, rec := range s.IPs {
		if rec.Banned && !isBannedLocal(ip) {
			banLocal(ip)
		}
	}
	writeBanFile(s)
}

// UsernamesLoop 常驻循环：跟随 journalctl sshd 日志，实时封禁境外/风暴 IP。
func UsernamesLoop(done <-chan struct{}) {
	state := loadUsernamesState()
	applyAllBans(state)
	lastSave := time.Now()

	for {
		// 每次迭代重新启动 journalctl -f(可重启续写)；配合 done 退出
		proc := exec.Command("journalctl", "-f", "-u", "sshd", "-o", "cat")
		proc.Stdout = nil // 用 pipe 逐行读
		stdout, err := proc.StdoutPipe()
		if err != nil {
			fmt.Println("[usernames] stdout pipe err:", err)
			select {
			case <-time.After(5 * time.Second):
				continue
			case <-done:
				return
			}
		}
		if err := proc.Start(); err != nil {
			fmt.Println("[usernames] start err:", err)
			select {
			case <-time.After(5 * time.Second):
				continue
			case <-done:
				return
			}
		}

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			stateMu.Lock()
			changed := handleSSHLine(state, line, &lastSave)
			stateMu.Unlock()
			if changed {
				saveUsernamesState(state)
				writeBanFile(state)
			}
			// 周期持久化
			if time.Since(lastSave) > saveEvery {
				saveUsernamesState(state)
				lastSave = time.Now()
			}
			select {
			case <-done:
				_ = proc.Process.Kill()
				_ = proc.Wait()
				return
			default:
			}
		}
		_ = proc.Wait()
		select {
		case <-done:
			return
		case <-time.After(3 * time.Second):
			// journalctl 进程异常退出后自动重启
		}
	}
}

func handleSSHLine(state *UsernamesState, line string, lastSave *time.Time) bool {
	// 1) 成功登录 → 自动白名单
	if m := reAccept.FindStringSubmatch(line); m != nil {
		ip := m[2]
		if !ignoreIP[ip] && !containsStr(state.Whitelist, ip) {
			state.Whitelist = append(state.Whitelist, ip)
			fmt.Println("[usernames] auto-whitelist", ip)
		}
		return true
	}
	// 2) 失败尝试 → 判定地理与用户名
	m := reFail.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	user, ip := m[1], m[2]
	if ignoreIP[ip] || containsStr(state.Whitelist, ip) {
		return false
	}
	rec, ok := state.IPs[ip]
	if !ok {
		rec = &IPRecord{}
		state.IPs[ip] = rec
	}
	if !containsStr(rec.Users, user) {
		rec.Users = append(rec.Users, user)
	}
	geo := QueryGeo(ip)
	rec.Location = geo.Location
	isCN := geo.IsCN

	shouldBan := false
	reason := ""
	if !isCN {
		shouldBan = true
		reason = "境外IP拦截 (" + geo.Location + ")"
	} else if len(rec.Users) > threshold {
		shouldBan = true
		reason = fmt.Sprintf("用户名风暴 (不同账号:%d)", len(rec.Users))
	}
	if shouldBan && !rec.Banned {
		rec.Banned = true
		rec.Reason = reason
		rec.Time = time.Now().Format("2006-01-02 15:04:05")
		if !isBannedLocal(ip) {
			banLocal(ip)
		}
		syncRelay(ip)
		fmt.Printf("PERM-BANNED [%s] %s\n", reason, ip)
		return true
	}
	return false
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}