package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// frps-ssh 隧道自动识别与防御同步。
//
// 背景：frp 隧道定义在客户端(frpc)，frps 服务端无本地静态清单；SSH 转发端口一连接即回
// `SSH-2.0-...` banner，可据此可靠识别。本模块每日一次探测 frps 进程监听的 TCP 端口，
// ① 判定哪些是 SSH 隧道（banner 命中）；② 顺带做端口有效性判定（TCP 连通 + 是否有响应）；
// ③ 把有效 SSH 端口自动并入 fail2ban `frps-ssh` jail 的 port（并保留仍存活的手动基线，清掉失效项）。

const (
	frpsSSHScanEvery    = 24 * time.Hour // 探测节奏：一天一次足够（隧道极少变，省资源）
	frpsSSHProbeTimeout = 3 * time.Second
	frpsSSHJailConf     = "/etc/fail2ban/jail.d/frps-ssh.conf"
	frpsSSHBanner       = "SSH-2.0-"
)

// SSHPortKind 单个 frp 端口的类型/有效性判定。
type SSHPortKind string

const (
	KindSSH    SSHPortKind = "ssh"    // 有效 SSH 隧道（连上且回 SSH banner）
	KindTCP    SSHPortKind = "tcp"    // 连上但非 SSH（HTTP/TLS/自定义）
	KindDown   SSHPortKind = "down"   // 连不上（隧道失效/未监听）
	KindSkipped SSHPortKind = "skip"  // 跳过（系统端口等黑名单）
)

// PortProbe 单个端口探测结果。
type PortProbe struct {
	Port int         `json:"port"`
	Kind SSHPortKind `json:"kind"`
}

// FrpsSSHInfo 面板展示用快照。
type FrpsSSHInfo struct {
	Ports   []int       `json:"ports"`   // 判定为有效 SSH 的端口（已并入防御）
	Probes  []PortProbe `json:"probes"`  // 全部 frp 端口逐项有效性
	At      string      `json:"at"`      // 最近一次探测时间
	Next    string      `json:"next"`    // 下次探测时间
	Err     string      `json:"error"`
}

var (
	sshMu     sync.RWMutex
	sshPorts  []int
	sshProbes []PortProbe
	scannedAt time.Time
	scanErr   string
)

// skipPorts 明确不探测的本机系统端口（即便被 frps 进程看到也跳过，避免误报）。
var skipPorts = map[int]bool{
	22: true, 53: true, 80: true, 443: true, 8443: true,
	5013: true, 8899: true, 7001: true, 3128: true, 3306: true,
}

// DetectedSSHPorts 返回已并入防御的 frp SSH 端口（副本）。
func DetectedSSHPorts() []int {
	sshMu.RLock()
	defer sshMu.RUnlock()
	return append([]int{}, sshPorts...)
}

// FrpsSSHInfoNow 返回当前识别状态快照（供 handler 渲染）。
func FrpsSSHInfoNow() FrpsSSHInfo {
	sshMu.RLock()
	defer sshMu.RUnlock()
	info := FrpsSSHInfo{
		Ports:  append([]int{}, sshPorts...),
		Probes: append([]PortProbe{}, sshProbes...),
		At:     scannedAt.Format("2006-01-02 15:04:05"),
		Err:    scanErr,
	}
	if !scannedAt.IsZero() {
		info.Next = scannedAt.Add(frpsSSHScanEvery).Format("2006-01-02 15:04:05")
	}
	return info
}

// FrpsSSHLoop 周期扫描：启动立即一次 + 每 24h 一次。
func FrpsSSHLoop(done chan struct{}) {
	scanFrpsSSH()
	ticker := time.NewTicker(frpsSSHScanEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			scanFrpsSSH()
		case <-done:
			return
		}
	}
}

func scanFrpsSSH() {
	ports := frpsListeningPorts()
	if len(ports) == 0 {
		setSSHState(nil, nil, "未检测到 frps 监听端口")
		return
	}
	var probes []PortProbe
	var ssh []int
	for _, p := range ports {
		if skipPorts[p] {
			probes = append(probes, PortProbe{Port: p, Kind: KindSkipped})
			continue
		}
		kind, ok := probePort(p)
		probes = append(probes, PortProbe{Port: p, Kind: kind})
		if ok {
			ssh = append(ssh, p)
		}
	}
	sort.Ints(ssh)
	setSSHState(ssh, probes, "")
	if len(ssh) > 0 {
		syncFrpsSSHJailPorts(ssh, ports)
	}
}

func setSSHState(ssh []int, probes []PortProbe, errMsg string) {
	sshMu.Lock()
	defer sshMu.Unlock()
	sshPorts = append([]int{}, ssh...)
	sshProbes = append([]PortProbe{}, probes...)
	scannedAt = time.Now()
	scanErr = errMsg
}

// frpsListeningPorts 用 `ss -ltnp` 枚举 frps 进程监听的 TCP 端口。
func frpsListeningPorts() []int {
	out, err := exec.Command("ss", "-ltnp").Output()
	if err != nil {
		return nil
	}
	var ports []int
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "frps") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		addr := f[3] // 如 *:53308 / 0.0.0.0:22 / [::]:22
		idx := strings.LastIndex(addr, ":")
		if idx < 0 || idx == len(addr)-1 {
			continue
		}
		p, err := strconv.Atoi(addr[idx+1:])
		if err != nil || p <= 0 || p > 65535 {
			continue
		}
		ports = append(ports, p)
	}
	return uniqueInts(ports)
}

// probePort 连接目标端口并读首包：
//   - 连上且读回 `SSH-2.0-` → KindSSH（有效 SSH 隧道）
//   - 连上但非 SSH banner → KindTCP（普通隧道，不并入防御）
//   - 连不上 → KindDown（失效）
func probePort(port int) (SSHPortKind, bool) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), frpsSSHProbeTimeout)
	if err != nil {
		return KindDown, false
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(frpsSSHProbeTimeout))
	buf := make([]byte, 32)
	n, rerr := conn.Read(buf)
	if rerr != nil || n < len(frpsSSHBanner) {
		return KindTCP, false
	}
	if strings.HasPrefix(string(buf[:n]), frpsSSHBanner) {
		return KindSSH, true
	}
	return KindTCP, false
}

func uniqueInts(in []int) []int {
	m := map[int]bool{}
	var out []int
	for _, v := range in {
		if !m[v] {
			m[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// syncFrpsSSHJailPorts 把当前有效 SSH 端口并入 fail2ban frps-ssh jail 的 port：
//   - 只并入"仍存活(在 listeners 里)"的既有基线端口，自动清掉不再监听的失效项；
//   - 仅当 port 行实际变化时才写盘 + reload，避免每天空转。
func syncFrpsSSHJailPorts(detected []int, listeners []int) {
	data, err := os.ReadFile(frpsSSHJailConf)
	if err != nil {
		return
	}
	live := map[int]bool{} // 当前 frps 仍在监听的端口（用于保留存活基线、清失效）
	for _, p := range listeners {
		live[p] = true
	}
	set := map[int]bool{}
	for _, p := range detected {
		set[p] = true
	}
	lines := strings.Split(string(data), "\n")
	idx := -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "port") && !strings.HasPrefix(t, "#") && strings.Contains(line, "=") {
			idx = i
			// 保留既存、且当前仍存活的手动/历史端口
			rhs := line[strings.Index(line, "=")+1:]
			for _, f := range strings.FieldsFunc(rhs, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
				if p, e := strconv.Atoi(strings.TrimSpace(f)); e == nil && p > 0 && live[p] {
					set[p] = true
				}
			}
			break
		}
	}
	var sorted []int
	for p := range set {
		sorted = append(sorted, p)
	}
	sort.Ints(sorted)
	newLine := "port = " + intsToCSV(sorted)
	if idx >= 0 && lines[idx] == newLine {
		return // 无变化，不写盘不 reload
	}
	if idx >= 0 {
		lines[idx] = newLine
	} else {
		lines = append(lines, newLine)
	}
	_ = os.WriteFile(frpsSSHJailConf, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	_ = exec.Command("fail2ban-client", "reload", "frps-ssh").Run()
}

func intsToCSV(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}

// FrpsSSHPortsSummary 供 handler 组合探针展示文本。
func FrpsSSHPortsSummary() string {
	info := FrpsSSHInfoNow()
	var b strings.Builder
	for _, pr := range info.Probes {
		fmt.Fprintf(&b, ":%d=%s ", pr.Port, pr.Kind)
	}
	return strings.TrimSpace(b.String())
}