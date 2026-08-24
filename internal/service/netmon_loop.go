package service

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NetMon：网络监控采集层（与 netmon.py 对齐，纯标准库）。

const (
	historyInterval = 600 * time.Second // 10 分钟采样
	historyRetain   = 4320              // 30 天
	alertCooldown   = 1800 * time.Second

	synThreshold    = 30
	connThreshold   = 5000
	ipConnThreshold = 80
	ipScanThreshold = 30
	bwThreshold     = 50 * 1024 * 1024
)

type NicStats struct {
	Name      string  `json:"name"`
	Physical  bool    `json:"physical"`
	RXBytes   uint64  `json:"rx_bytes"`
	TXBytes   uint64  `json:"tx_bytes"`
	RXRate    float64 `json:"rx_rate"` // bytes/s
	TXRate    float64 `json:"tx_rate"`
}

type ConnStates struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type TopIP struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
	Ports int    `json:"ports"`
}

type ConnStats struct {
	TCPTotal    int        `json:"tcp_total"`
	UDPTotal    int        `json:"udp_total"`
	States      []ConnStates `json:"states"`
	SynRecv     int        `json:"syn_recv"`
	Established int        `json:"established"`
	TimeWait    int        `json:"time_wait"`
	TopIPs      []TopIP    `json:"top_ips"`
	TopPorts    []TopPort  `json:"top_ports"`
}

type TopPort struct {
	Port  int `json:"port"`
	Count int `json:"count"`
}

type Alert struct {
	Time  string `json:"time"`
	Level string `json:"level"`
	Title string `json:"title"`
	Detail string `json:"detail"`
}

type HistoryPoint struct {
	Time        string  `json:"time"`
	Ts          int64   `json:"ts"`
	RXRate      float64 `json:"rx_rate"`
	TXRate      float64 `json:"tx_rate"`
	TCPTotal    int     `json:"tcp_total"`
	UDPTotal    int     `json:"udp_total"`
	SynRecv     int     `json:"syn_recv"`
	Established int     `json:"established"`
}

var (
	alertsFile    = filepath.Join(dataDir(), "netmon_alerts.json")
	historyFile   = filepath.Join(dataDir(), "netmon_history.json")
	nicCacheMu    sync.Mutex
	nicPrev       = map[string]NicStats{}
	nicCacheTime  time.Time
	connCacheMu   sync.Mutex
	connCacheTime time.Time
	connCache     *ConnStats
	frpsCacheTime time.Time
	frpsCache     map[string]interface{}
	frpsCacheMu   sync.Mutex
)

// readProcNetDev 读取 /proc/net/dev。
func readProcNetDev() map[string]NicStats {
	m := map[string]NicStats{}
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(data), "\n")[2:] {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		nic := strings.TrimSpace(line[:idx])
		parts := strings.Fields(line[idx+1:])
		if len(parts) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(parts[0], 10, 64)
		tx, _ := strconv.ParseUint(parts[8], 10, 64)
		m[nic] = NicStats{Name: nic, RXBytes: rx, TXBytes: tx,
			Physical: isPhysicalNIC(nic)}
	}
	return m
}

func isPhysicalNIC(nic string) bool {
	if nic == "lo" {
		return false
	}
	if strings.HasPrefix(nic, "docker") || strings.HasPrefix(nic, "br-") ||
		strings.HasPrefix(nic, "veth") || strings.HasPrefix(nic, "virbr") ||
		strings.HasPrefix(nic, "tun") || strings.HasPrefix(nic, "tap") ||
		strings.HasPrefix(nic, "vnet") {
		return false
	}
	if _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/device", nic)); err == nil {
		return true
	}
	return false
}

// NicRateStats 计算网卡实时速率（差分）。
func NicRateStats(includeVirtual bool) []NicStats {
	now := time.Now()
	cur := readProcNetDev()
	nicCacheMu.Lock()
	defer nicCacheMu.Unlock()
	stats := []NicStats{}
	for nic, v := range cur {
		if !v.Physical && !includeVirtual {
			continue
		}
		if prev, ok := nicPrev[nic]; ok {
			dt := now.Sub(nicCacheTime).Seconds()
			if dt > 0 {
				v.RXRate = maxF(0, float64(v.RXBytes-prev.RXBytes)/dt)
				v.TXRate = maxF(0, float64(v.TXBytes-prev.TXBytes)/dt)
			}
		}
		v.Name = nic
		stats = append(stats, v)
		nicPrev[nic] = v
	}
	nicCacheTime = now
	sort.Slice(stats, func(i, j int) bool { return stats[i].Name < stats[j].Name })
	return stats
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// splitHostPort 解析 'host:port'（含 IPv6）→ (host, port)。port 可为空。
func splitHostPort(addr string) (string, int) {
	if addr == "" || addr == "*:*" {
		return "", 0
	}
	host := addr
	if strings.HasPrefix(addr, "[") { // IPv6
		if m := regexp.MustCompile(`\[([^\]]+)\]:(\d+)`).FindStringSubmatch(addr); m != nil {
			p, _ := strconv.Atoi(m[2])
			return m[1], p
		}
		return "", 0
	}
	if strings.Count(addr, ":") == 1 {
		last := strings.LastIndexByte(addr, ':')
		host = addr[:last]
		p, _ := strconv.Atoi(addr[last+1:])
		return host, p
	}
	return "", 0
}

// ConnStatsSnapshot 采集连接状态（2 秒缓存）。
func ConnStatsSnapshot() ConnStats {
	connCacheMu.Lock()
	defer connCacheMu.Unlock()
	if connCache != nil && time.Since(connCacheTime) < 2*time.Second {
		return *connCache
	}
	cs := buildConnStats()
	connCache = &cs
	connCacheTime = time.Now()
	return cs
}

func buildConnStats() ConnStats {
	cs := ConnStats{States: []ConnStates{}, TopIPs: []TopIP{}, TopPorts: []TopPort{}}
	statesMap := map[string]int{}
	ipCount := map[string]int{}
	ipPorts := map[string]map[int]bool{}
	portCount := map[int]int{}
	tcpTotal := 0

	if out := runOut(5*time.Second, "ss", "-tan"); out != "" {
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 || fields[0] == "State" || fields[0] == "LISTEN" {
				continue
			}
			state := fields[0]
			peerHost, _ := splitHostPort(fields[4])
			_, localPort := splitHostPort(fields[3])
			tcpTotal++
			statesMap[state]++
			if peerHost != "" && peerHost != "127.0.0.1" && peerHost != "::1" && peerHost != "0.0.0.0" && peerHost != "*" {
				ipCount[peerHost]++
				if ipPorts[peerHost] == nil {
					ipPorts[peerHost] = map[int]bool{}
				}
				const portGuess = 0
				_ = portGuess
				// 记录对端端口数
				if p, _ := splitHostPort(fields[4]); p != peerHost && p != "" {
					_ = p
				}
				if pp := portOf(fields[4]); pp > 0 {
					ipPorts[peerHost][pp] = true
				}
			}
			if localPort > 0 {
				portCount[localPort]++
			}
		}
	}
	// 按降序列出状态
	for name, n := range statesMap {
		cs.States = append(cs.States, ConnStates{Name: name, Count: n})
	}
	sort.Slice(cs.States, func(i, j int) bool { return cs.States[i].Count > cs.States[j].Count })
	if n := cs.States; len(n) > 9 {
		cs.States = n[:9]
	}
	cs.SynRecv = statesMap["SYN-RECV"]
	cs.Established = statesMap["ESTAB"]
	cs.TimeWait = statesMap["TIME-WAIT"]
	cs.TCPTotal = tcpTotal

	// TOP IP
	for ip, c := range ipCount {
		cs.TopIPs = append(cs.TopIPs, TopIP{IP: ip, Count: c, Ports: len(ipPorts[ip])})
	}
	sort.Slice(cs.TopIPs, func(i, j int) bool { return cs.TopIPs[i].Count > cs.TopIPs[j].Count })
	if len(cs.TopIPs) > 10 {
		cs.TopIPs = cs.TopIPs[:10]
	}
	// TOP 本地端口
	for p, c := range portCount {
		cs.TopPorts = append(cs.TopPorts, TopPort{Port: p, Count: c})
	}
	sort.Slice(cs.TopPorts, func(i, j int) bool { return cs.TopPorts[i].Count > cs.TopPorts[j].Count })
	if len(cs.TopPorts) > 10 {
		cs.TopPorts = cs.TopPorts[:10]
	}

	// UDP
	if out := runOut(5*time.Second, "ss", "-un"); out != "" {
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 1 && fields[0] != "State" && strings.TrimSpace(line) != "" {
				cs.UDPTotal++
			}
		}
	}
	return cs
}

// portOf 提取 'host:port' 的端口号。
func portOf(addr string) int {
	_, p := splitHostPort(addr)
	return p
}

// ListenPort 本机监听端口。
type ListenPort struct {
	Addr    string `json:"addr"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Process string `json:"process"`
}

// ListenPorts 获取监听端口（root 时带进程名）。
func ListenPorts() []ListenPort {
	args := []string{"-tln"}
	if os.Geteuid() == 0 {
		args = []string{"-tlnp"}
	}
	out := runOut(5*time.Second, "ss", args...)
	if out == "" {
		return []ListenPort{}
	}
	list := []ListenPort{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "LISTEN" {
			continue
		}
		host, port := splitHostPort(fields[3])
		if port == 0 {
			continue
		}
		proc := ""
		if m := regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`).FindStringSubmatch(line); m != nil {
			proc = m[1] + "(" + m[2] + ")"
		}
		list = append(list, ListenPort{Addr: fields[3], Host: host, Port: port, Process: proc})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Port < list[j].Port })
	return list
}

// CheckAlerts 判定告警（带冷却窗口），返回新增告警并持久化。
var lastAlert = map[string]time.Time{}

func CheckAlerts(conn ConnStats, nics []NicStats) []Alert {
	now := time.Now()
	newAlerts := []Alert{}
	fire := func(key, level, title, detail string) {
		if since := now.Sub(lastAlert[key]); since < alertCooldown {
			return
		}
		lastAlert[key] = now
		newAlerts = append(newAlerts, Alert{Time: now.Format("2006-01-02 15:04:05"),
			Level: level, Title: title, Detail: detail})
	}
	if conn.SynRecv > synThreshold {
		fire("syn", "danger", "TCP 半连接堆积", fmt.Sprintf("SYN_RECV=%d，疑似 SYN Flood 攻击", conn.SynRecv))
	}
	if conn.TCPTotal > connThreshold {
		fire("total", "warning", "连接总数异常", fmt.Sprintf("TCP 连接总数=%d", conn.TCPTotal))
	}
	for _, ip := range conn.TopIPs {
		if ip.Count > ipConnThreshold {
			fire("storm:"+ip.IP, "warning", "单 IP 连接风暴", fmt.Sprintf("%s 活跃连接 %d 个", ip.IP, ip.Count))
		}
		if ip.Ports > ipScanThreshold {
			fire("scan:"+ip.IP, "danger", "疑似端口扫描", fmt.Sprintf("%s 在 %d 个端口上建立连接", ip.IP, ip.Ports))
		}
	}
	for _, nic := range nics {
		if nic.RXRate > bwThreshold {
			fire("bw:"+nic.Name, "warning", "入站带宽异常", fmt.Sprintf("%s RX=%.1f MB/s", nic.Name, nic.RXRate/1024/1024))
		}
	}
	if len(newAlerts) > 0 {
		existing := LoadAlerts()
		merged := append(newAlerts, existing...)
		if len(merged) > 50 {
			merged = merged[:50]
		}
		_ = SaveAlerts(merged)
	}
	return newAlerts
}

func LoadAlerts() []Alert {
	al := []Alert{}
	if b, err := os.ReadFile(alertsFile); err == nil {
		_ = json.Unmarshal(b, &al)
	}
	return al
}

func SaveAlerts(al []Alert) error {
	b, _ := json.Marshal(al)
	return atomicWrite(alertsFile, b)
}

// SampleHistory 采集一个历史节点。
func SampleHistory() HistoryPoint {
	nics := NicRateStats(false)
	conn := ConnStatsSnapshot()
	var rx, tx float64
	for _, n := range nics {
		rx += n.RXRate
		tx += n.TXRate
	}
	return HistoryPoint{Time: time.Now().Format("2006-01-02 15:04:05"),
		Ts: time.Now().Unix(), RXRate: rx, TXRate: tx,
		TCPTotal: conn.TCPTotal, UDPTotal: conn.UDPTotal,
		SynRecv: conn.SynRecv, Established: conn.Established}
}

// HistoryLoop 后台 10 分钟采样。
func HistoryLoop(done <-chan struct{}) {
	ticker := time.NewTicker(historyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			points := GetHistoryPoints()
			p := SampleHistory()
			points = append(points, p)
			if len(points) > historyRetain {
				points = points[len(points)-historyRetain:]
			}
			_ = SaveHistoryPoints(points)
		}
	}
}

// GetHistoryPoints 读取全量历史点。
func GetHistoryPoints() []HistoryPoint {
	pts := []HistoryPoint{}
	if b, err := os.ReadFile(historyFile); err == nil {
		_ = json.Unmarshal(b, &pts)
	}
	return pts
}

// SaveHistoryPoints 原子写历史点（无缩进）。
func SaveHistoryPoints(pts []HistoryPoint) error {
	b, _ := json.Marshal(pts)
	return atomicWrite(historyFile, b)
}

// FrpsCredential 运行时从 frps.toml 读取 dashboard 凭据（不硬编码）。
type FrpsCredential struct {
	User, Password string
}

var frpsTomlCandidates = []string{
	"/main/app/github/frp/frps.toml",
	"/main/app/github/frp/frp_0.60.0_linux_amd64/frps.toml",
	"/etc/frps.toml",
}

func loadFrpsCredential() (FrpsCredential, bool) {
	reUser := regexp.MustCompile(`webServer\.user\s*=\s*"([^"]+)"`)
	rePwd := regexp.MustCompile(`webServer\.password\s*=\s*"([^"]+)"`)
	for _, path := range frpsTomlCandidates {
		if b, err := os.ReadFile(path); err == nil {
			txt := string(b)
			u := reUser.FindStringSubmatch(txt)
			p := rePwd.FindStringSubmatch(txt)
			if len(u) == 2 && len(p) == 2 {
				return FrpsCredential{User: u[1], Password: p[1]}, true
			}
		}
	}
	return FrpsCredential{}, false
}

// FrpsTraffic frps 隧道流量统计。
func FrpsTraffic() map[string]interface{} {
	frpsCacheMu.Lock()
	defer frpsCacheMu.Unlock()
	if frpsCache != nil && time.Since(frpsCacheTime) < 30*time.Second {
		return frpsCache
	}
	result := map[string]interface{}{"available": false, "proxies": []map[string]interface{}{}, "error": ""}
	cred, ok := loadFrpsCredential()
	if !ok {
		result["error"] = "未检测到 frps dashboard 配置"
		frpsCache, frpsCacheTime = result, time.Now()
		return result
	}
	req, _ := http.NewRequest("GET", "http://127.0.0.1:7500/api/proxy/traffic", nil)
	req.SetBasicAuth(cred.User, cred.Password)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		result["error"] = "frps API 访问失败: " + err.Error()
		frpsCache, frpsCacheTime = result, time.Now()
		return result
	}
	defer resp.Body.Close()
	var d struct {
		Proxies []map[string]interface{} `json:"proxies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		result["error"] = "frps 响应解析失败"
		frpsCache, frpsCacheTime = result, time.Now()
		return result
	}
	items := []map[string]interface{}{}
	for _, p := range d.Proxies {
		name, _ := p["name"].(string)
		typ, _ := p["type"].(string)
		ti, _ := p["traffic_in"].(float64)
		to, _ := p["traffic_out"].(float64)
		items = append(items, map[string]interface{}{
			"name": name, "type": typ, "traffic_in": ti, "traffic_out": to})
	}
	result = map[string]interface{}{"available": true, "proxies": items, "error": ""}
	frpsCache, frpsCacheTime = result, time.Now()
	return result
}

// FmtBytes 字节格式化。
func FmtBytes(n float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	for _, u := range units {
		if n < 1024 || u == "TB" {
			if u == "B" {
				return fmt.Sprintf("%d %s", int(n), u)
			}
			return fmt.Sprintf("%.1f %s", n, u)
		}
		n /= 1024
	}
	return fmt.Sprintf("%.1f TB", n)
}

// FmtRate 字节/秒速率格式化。
func FmtRate(bps float64) string {
	if bps >= 1024*1024 {
		return fmt.Sprintf("%.2f MB/s", bps/1024/1024)
	}
	if bps >= 1024 {
		return fmt.Sprintf("%.1f KB/s", bps/1024)
	}
	return fmt.Sprintf("%.0f B/s", bps)
}

// 供 handler 使用 net 包避免未使用告警
var _ = net.ParseIP