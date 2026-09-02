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
	stateFile = "usernames.json"
	banFile   = "perm_ban.txt"
	saveEvery = 30 * time.Second
)

var (
	reFail   = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from ([\d\.:a-fA-F]+) port`)
	reAccept = regexp.MustCompile(`Accepted publickey for (\S+) from ([\d\.:a-fA-F]+)`)
	// 密码登录成功：境外 IP 无论密码对错都要封禁（20260828 事件教训）
	reAcceptPass = regexp.MustCompile(`Accepted password for (?:invalid user )?(\S+) from ([\d\.:a-fA-F]+)`)
	ignoreIP     = map[string]bool{"127.0.0.1": true, "::1": true, "127.0.0.2": true}

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

// isBannedLocal 检查 iptables 是否已存在该 IP 的 DROP 规则（入+出双向，20260831 起双向封禁）。
func isBannedLocal(ip string) bool {
	bin := "iptables"
	if strings.Contains(ip, ":") {
		bin = "ip6tables"
	}
	inOK := runOK(bin, "-C", "INPUT", "-s", ip, "-j", "DROP")
	outOK := runOK(bin, "-C", "OUTPUT", "-d", ip, "-j", "DROP")
	return inOK && outOK
}

// banLocal 本机下发永久封禁（IPv4/IPv6 自适应；入+出双向：INPUT 防扫描连入，OUTPUT 防 C2 回连/矿池上报）。
func banLocal(ip string) {
	bin := "iptables"
	if strings.Contains(ip, ":") {
		bin = "ip6tables"
	}
	_ = runOK(bin, "-C", "INPUT", "-s", ip, "-j", "DROP")
	_ = runOK(bin, "-A", "INPUT", "-s", ip, "-j", "DROP")
	_ = runOK(bin, "-C", "OUTPUT", "-d", ip, "-j", "DROP")
	_ = runOK(bin, "-A", "OUTPUT", "-d", ip, "-j", "DROP")
	_ = runOK(bin+"-save")
}

// syncRelay 同步封禁到中转机（本机即中转机时跳过，避免自己 ssh 自己）。
func syncRelay(ip string) {
	if isRelaySelf() {
		return
	}
	bin := "iptables"
	if strings.Contains(ip, ":") {
		bin = "ip6tables"
	}
	// 中转机同步：入(INPUT)+出(OUTPUT)+转发(FORWARD) 三链（中转机为网关角色，20260831 双向封禁）
	cmd := fmt.Sprintf(
		"%s -C INPUT -s %s -j DROP >/dev/null 2>&1 || %s -A INPUT -s %s -j DROP; "+
			"%s -C OUTPUT -d %s -j DROP >/dev/null 2>&1 || %s -A OUTPUT -d %s -j DROP; "+
			"%s -C FORWARD -s %s -j DROP >/dev/null 2>&1 || %s -A FORWARD -s %s -j DROP; "+
			"iptables-save >/dev/null",
		bin, ip, bin, ip, bin, ip, bin, ip, bin, ip, bin, ip)
	_ = exec.Command("ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=8", Conf().RelayHost, cmd).Run()
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
	WriteDefaultConfig()
	state := loadUsernamesState()
	go syncWhitelistToF2B(state.Whitelist) // 启动即同步一次，弥合两套白名单
	prevWL := len(state.Whitelist)
	applyAllBans(state)
	lastSave := time.Now()

	for {
		// 每次迭代重新启动 journalctl -f(可重启续写)；配合 done 退出
		// 同时跟 sshd(RHEL/arch) 与 ssh(Debian/Ubuntu) 两个 unit 名，避免中转机上空转
		proc := exec.Command("journalctl", "-f", "-u", "sshd", "-u", "ssh", "-o", "cat")
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
			wl := len(state.Whitelist)
			stateMu.Unlock()
			if changed {
				saveUsernamesState(state)
				writeBanFile(state)
			}
			// 白名单增长(新公钥登录) → 同步进 fail2ban ignoreip
			if wl > prevWL {
				prevWL = wl
				stateMu.Lock()
				wlCopy := append([]string(nil), state.Whitelist...)
				stateMu.Unlock()
				go syncWhitelistToF2B(wlCopy)
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
	// 1) 公钥成功登录 → 自动白名单
	if m := reAccept.FindStringSubmatch(line); m != nil {
		ip := m[2]
		if !ignoreIP[ip] && !containsStr(state.Whitelist, ip) {
			state.Whitelist = append(state.Whitelist, ip)
			fmt.Println("[usernames] auto-whitelist", ip)
		}
		return true
	}
	// 1b) 密码成功登录 → 境外 IP 一律封禁（无论账号密码对不对）
	if m := reAcceptPass.FindStringSubmatch(line); m != nil {
		ip := m[2]
		if ignoreIP[ip] || containsStr(state.Whitelist, ip) {
			return false
		}
		geo := QueryGeo(ip)
		if !geo.IsCN {
			return banIPOnce(state, ip, "境外IP密码登录成功 ("+geo.Location+")", geo.Location)
		}
		return false
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

	shouldBan := false
	reason := ""
	if geoUnknown(geo) {
		shouldBan = true
		reason = "归属地未知IP拦截 (查询失败按境外处理)"
	} else if !geo.IsCN {
		shouldBan = true
		reason = "境外IP拦截 (" + geo.Location + ")"
	} else if len(rec.Users) > Conf().Threshold {
		shouldBan = true
		reason = fmt.Sprintf("用户名风暴 (不同账号:%d)", len(rec.Users))
	}
	if shouldBan {
		return banIPOnce(state, ip, reason, geo.Location)
	}
	return false
}

// geoUnknown 判定归属地是否查询失败（fail-close：未知按境外封但 reason 单独标注）。
func geoUnknown(geo GeoInfo) bool {
	return geo.Country == "未知" || geo.Location == "归属地未识别"
}

// banIPOnce 封禁一个 IP（去重），下发本机 iptables 并同步中转机。
func banIPOnce(state *UsernamesState, ip, reason, location string) bool {
	rec, ok := state.IPs[ip]
	if !ok {
		rec = &IPRecord{}
		state.IPs[ip] = rec
	}
	rec.Location = location
	if rec.Banned {
		return false
	}
	rec.Banned = true
	rec.Reason = reason
	rec.Time = time.Now().Format("2006-01-02 15:04:05")
	if !isBannedLocal(ip) {
		banLocal(ip)
	}
	syncRelay(ip)
	fmt.Printf("PERM-BANNED [%s] %s\n", reason, ip)
	go notifyBan(ip, reason, rec.Location, rec.Time)
	go collectEvidence(ip, reason)
	return true
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}