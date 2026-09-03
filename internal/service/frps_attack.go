package service

// frps_attack.go — SSH 攻击「目标端口」归因采集（v3.1.0 新增）。
//
// 背景：SSH 防御已并入 frp SSH 隧道（frps-ssh），攻击目标不再只有本机 22，
// 还包括 frps 监听的公网隧道端口（如 50022/50122/52222）。而真实 sshd 只监听 22，
// lastb/journalctl 无法区分攻击走的是哪条隧道；唯一能区分"目标端口"的数据源是 frps。
//
// 数据链路：tail frps.log 的 `get a user connection [<公网源IP>:<源端口>]` 行，
// 提取 (公网源IP, 隧道名, 时间)，再经「隧道名→目标端口」映射（config.json 的
// frps_tunnel_ports，可热加载）把攻击关联到具体公网端口；映射缺失时退化为
// "frp 隧道组"，供面板标注。全程不依赖 frps dashboard（生产已关闭），零生产改动。
//
// 防御性设计：
//   - frps 日志路径可被环境变量 FRPS_LOG 覆盖，默认 /main/app/log/frps.log；
//   - 数据落盘 data/frps_attacks.json，重启不丢；
//   - 隧道映射不存在时仍能标记"观测到 frp 隧道攻击"，不丢信息。

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	frpsLogDefault    = "/main/app/log/frps.log" // 中转机 frps 日志（frps -c frps.toml）
	frpsConnectEvery  = 3 * time.Second          // tail 进程异常退出后的重启间隔
	frpsSaveEvery     = 30 * time.Second         // 周期落盘
	frpsAttackFile    = "frps_attacks.json"
	frpsAttackRetainH = 24 // 仅保留最近 24h 观测，避免无限增长
)

// reFrpsConn 匹配 frps 日志连接行。真实行格式（方括号从后往前数，最后一个 `[隧道名]` 才是代理名）：
//
//	2026-09-03 16:32:03.245 [I] [proxy/proxy.go:256] [863e...] [<隧道名>] get a user connection [<公网源IP>:<源端口>]
//	组1: 隧道名（代理名）                组2: 公网源IP
// 只锚定 `[隧道名] get a user connection [IP:port]`，避免被 `[I]/[proxy]/[client-id]` 干扰。
var reFrpsConn = regexp.MustCompile(`\[([^\]]+)\] get a user connection \[([0-9a-fA-F:.]+):\d+\]`)

var (
	frpsAtkMu     sync.RWMutex
	frpsAttacks   = map[string]map[string]time.Time{} // 源IP -> 隧道名 -> 最近观测时间
	frpsAtkLoaded = false
)

func frpsAttackPath() string { return filepath.Join(dataDir(), frpsAttackFile) }

func frpsLogPath() string {
	if p := os.Getenv("FRPS_LOG"); p != "" {
		return p
	}
	return frpsLogDefault
}

// loadFrpsAttacks 启动时载入历史观测（重启不丢）。
func loadFrpsAttacks() {
	frpsAtkMu.Lock()
	defer frpsAtkMu.Unlock()
	if frpsAtkLoaded {
		return
	}
	data, err := os.ReadFile(frpsAttackPath())
	if err == nil {
		_ = jsonUnmarshal(data, &frpsAttacks)
	}
	if frpsAttacks == nil {
		frpsAttacks = map[string]map[string]time.Time{}
	}
	frpsAtkLoaded = true
}

// saveFrpsAttacks 原子落盘（仅保存 24h 内的观测）。
func saveFrpsAttacks() {
	frpsAtkMu.RLock()
	snap := map[string]map[string]string{}
	cutoff := time.Now().Add(-frpsAttackRetainH * time.Hour)
	for ip, ps := range frpsAttacks {
		live := map[string]string{}
		for name, t := range ps {
			if t.After(cutoff) {
				live[name] = t.Format(time.RFC3339)
			}
		}
		if len(live) > 0 {
			snap[ip] = live
		}
	}
	frpsAtkMu.RUnlock()
	b, _ := jsonMarshal(snap)
	if len(b) > 0 {
		_ = atomicWrite(frpsAttackPath(), b)
	}
}

// recordFrpsAttack 记录一条 (源IP, 隧道名) 观测。
func recordFrpsAttack(ip, proxy string, t time.Time) {
	if ip == "" || proxy == "" {
		return
	}
	frpsAtkMu.Lock()
	if frpsAttacks[ip] == nil {
		frpsAttacks[ip] = map[string]time.Time{}
	}
	frpsAttacks[ip][proxy] = t
	frpsAtkMu.Unlock()
}

// handleFrpsLine 解析单行日志并记录（供循环与单元测试复用）。
func handleFrpsLine(line string) {
	m := reFrpsConn.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return
	}
	// m[1]=隧道名(代理名)，m[2]=公网源IP；时间取处理时刻（near-realtime，足够归因展示）。
	recordFrpsAttack(m[2], m[1], time.Now())
}

// FrpsAttackLoop 常驻协程：tail frps.log，实时采集 SSH 攻击对应隧道（目标端口归因）。
func FrpsAttackLoop(done <-chan struct{}) {
	loadFrpsAttacks()
	lastSave := time.Now()
	for {
		proc := exec.Command("tail", "-F", "-n", "0", frpsLogPath())
		stdout, err := proc.StdoutPipe()
		if err != nil {
			select {
			case <-time.After(frpsConnectEvery):
				continue
			case <-done:
				return
			}
		}
		if err := proc.Start(); err != nil {
			select {
			case <-time.After(frpsConnectEvery):
				continue
			case <-done:
				return
			}
		}
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			handleFrpsLine(scanner.Text())
			if time.Since(lastSave) > frpsSaveEvery {
				saveFrpsAttacks()
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
		case <-time.After(frpsConnectEvery):
			// tail 异常退出后自动重启续读
		}
	}
}

// tunnelPortForProxy 解析某隧道名对应的公网目标端口。
// 优先级：config.json 的 frps_tunnel_ports（热加载）→ 空（返回0，表示仅隧道组）。
func tunnelPortForProxy(proxy string) int {
	if proxy == "" {
		return 0
	}
	return Conf().FrpsTunnelPorts[proxy]
}

// HasFrpsAttack 判断该源 IP 是否观测到 frp 隧道攻击（用于区分"直连 22"与"隧道"）。
func HasFrpsAttack(ip string) bool {
	frpsAtkMu.RLock()
	defer frpsAtkMu.RUnlock()
	if frpsAttacks[ip] == nil {
		return false
	}
	cutoff := time.Now().Add(-frpsAttackRetainH * time.Hour)
	for _, t := range frpsAttacks[ip] {
		if t.After(cutoff) {
			return true
		}
	}
	return false
}

// AttackedPortsForIP 返回该源 IP 在 frp 隧道上攻击到的目标端口列表（去重升序）。
// 若观测到隧道但无端口映射，返回空列表（调用方应展示"frp 隧道组"）。
func AttackedPortsForIP(ip string) []int {
	frpsAtkMu.RLock()
	ps, ok := frpsAttacks[ip]
	frpsAtkMu.RUnlock()
	if !ok {
		return nil
	}
	set := map[int]bool{}
	for name := range ps {
		if p := tunnelPortForProxy(name); p > 0 {
			set[p] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// AttackedPortsLabel 输出面板展示用的紧凑文本，如 ":22" / ":50022,:52222" / "frp 隧道组"。
func AttackedPortsLabel(ip string) string {
	if ports := AttackedPortsForIP(ip); len(ports) > 0 {
		s := make([]string, len(ports))
		for i, p := range ports {
			s[i] = ":" + strconv.Itoa(p)
		}
		return strings.Join(s, ",")
	}
	if HasFrpsAttack(ip) {
		return "frp 隧道组"
	}
	return ":22"
}