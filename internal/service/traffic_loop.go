// TrafficLoop：月度流量用量统计（v3.5.0 新增）。
//
// 设计定位（低负载 + 按端口/进程归因，最佳努力式）：
//   - L1（必做，零开销）：基于 /proc/net/dev 累计字节计数器差分，得到每物理网卡
//     的「日/月总流量（入 + 出）」。与 HistoryLoop 共用同一来源但使用独立差分基准，
//     互不干扰。
//   - L2（可选增强，可降级）：若内核开启 nf_conntrack 记账
//     （sysctl net.netfilter.nf_conntrack_acct=1）且以 root 运行，则批量读取
//     /proc/net/nf_conntrack 的连接字节计数，按本机监听端口聚合，并映射回进程名
//     （ss -tlnp）。记账未开启/无权读取时优雅降级为「仅网卡总流量」，前端给出提示。
//
// 负载控制：60s 采样一次、单次批量读、内存增量聚合、只落「每日小型 JSON」，
// 月度汇总按需由日表内存聚合生成，不落分钟级明细、不逐连接调子进程。
package service

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	trafficInterval = 60 * time.Second // 低频采样（月度统计无需秒级）
	connPurgeAge    = 15 * time.Minute // conntrack 连接基准清理阈值
	trafficRetain   = 400              // 保留最近约 13 个月的天数

	// L2 备选后端（nftables 按端口计数）：用于不支持 /proc/net/nf_conntrack dump 的内核
	// （如阿里云中转机），在不开 conntrack 记账的前提下按监听端口拿到字节（纯计数器，低开销）。
	trafNftTable  = "traffic_mon"          // 隔离表，policy accept，仅计数不拦包
	trafNftListen = "traffic_mon_port_sync" // （保留，未用）
	trafNftSync   = 5 * time.Minute         // 端口集低频同步（重建表，重置基准）
)

// PortTraffic 单端口/进程在某日的流量（字节）。
type PortTraffic struct {
	Port int    `json:"port"`
	Proc string `json:"proc"` // 进程名（ss -tlnp 解析，可能为空）
	RX   uint64 `json:"rx"`   // 入站字节
	TX   uint64 `json:"tx"`   // 出站字节
}

// DayTraffic 单日流量汇总。
type DayTraffic struct {
	Date  string                  `json:"date"`
	RX    uint64                  `json:"rx"`
	TX    uint64                  `json:"tx"`
	Ports map[string]*PortTraffic `json:"ports,omitempty"` // key=strconv(port)
}

// MonthTraffic 月度聚合（服务层内部结构）。
type MonthTraffic struct {
	Month     string
	RX        uint64
	TX        uint64
	Ports     map[int]*PortTraffic
	PortsList []*PortTraffic // 按总量降序的端口明细（供 handler 直接序列化）
}

// connBytes conntrack 单连接字节快照（最佳努力）。first=原始方向字节，second=应答方向字节。
type connBytes struct {
	proto    string
	src, dst string
	sport    int
	dport    int
	first    uint64
	second   uint64
	lastSeen time.Time
}

func (c connBytes) key() string {
	return c.proto + "|" + c.src + "|" + strconv.Itoa(c.sport) + "|" + c.dst + "|" + strconv.Itoa(c.dport)
}

var (
	trafficFile  = filepath.Join(dataDir(), "traffic_daily.json")
	trafficMu    sync.Mutex
	trafDays     = map[string]*DayTraffic{} // date -> DayTraffic
	curDay       string                     // 当前累计到哪天，跨天时重置差分基准
	trafNICRX    = map[string]uint64{}      // nic 累计 RX（差分基准）
	trafNICTX    = map[string]uint64{}      // nic 累计 TX（差分基准）
	trafConn     = map[string]connBytes{}   // conntrack 连接字节基准
	trafAcctOK   bool                       // L2 是否真正跑通（conntrack 或 nft 后端），供前端提示
	localIPs     = map[string]bool{}
	localIPT     time.Time
	listenCache  = map[int]string{} // port -> proc
	listenCacheT time.Time
	// nftables 计数后端状态（阿里云等无 conntrack dump 时启用）
	trafNftSyncedAt time.Time
	trafNftPorts    []int
	trafNftBaseline = map[string]uint64{} // counter 名(in_X/out_X) -> 累计字节基准
)

// loadTraffic 启动时从磁盘载入既有日表。
func loadTraffic() {
	trafficMu.Lock()
	defer trafficMu.Unlock()
	trafDays = map[string]*DayTraffic{}
	if b, err := os.ReadFile(trafficFile); err == nil {
		var days []*DayTraffic
		if json.Unmarshal(b, &days) == nil {
			for _, d := range days {
				if d == nil {
					continue
				}
				if d.Ports == nil {
					d.Ports = map[string]*PortTraffic{}
				}
				trafDays[d.Date] = d
			}
		}
	}
	trafAcctOK = conntrackAcctEnabled()
}

// TrafficLoop 常驻协程：低频采样并落盘。
func TrafficLoop(done <-chan struct{}) {
	loadTraffic()
	ticker := time.NewTicker(trafficInterval)
	defer ticker.Stop()
	sampleTraffic() // 启动首采（对齐 HistoryLoop 行为，避免重启空窗）
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			sampleTraffic()
		}
	}
}

// sampleTraffic 单次采样：NIC 差分 + conntrack L2 归因 → 入日表 → 落盘。
func sampleTraffic() {
	now := time.Now()
	date := now.Format("2006-01-02")

	trafficMu.Lock()
	// 跨天（或首采）：重置差分基准，避免跨日污染；按需开新天。
	if curDay != date {
		curDay = date
		trafNICRX = map[string]uint64{}
		trafNICTX = map[string]uint64{}
		trafConn = map[string]connBytes{}
	}
	d := trafDays[date]
	if d == nil {
		d = &DayTraffic{Date: date, Ports: map[string]*PortTraffic{}}
		trafDays[date] = d
	}

	// ---- L1：网卡累计字节差分（/proc/net/dev，零子进程、零内核依赖） ----
	curNIC := readProcNetDev()
	for nic, v := range curNIC {
		if !v.Physical {
			continue
		}
		if prevRX, ok := trafNICRX[nic]; ok {
			if v.RXBytes >= prevRX {
				d.RX += v.RXBytes - prevRX
			}
		}
		if prevTX, ok := trafNICTX[nic]; ok {
			if v.TXBytes >= prevTX {
				d.TX += v.TXBytes - prevTX
			}
		}
		trafNICRX[nic] = v.RXBytes
		trafNICTX[nic] = v.TXBytes
	}

	// ---- L2：按端口/进程归因。优先 conntrack 后端；不可用（无 /proc/net/nf_conntrack
	// dump，如阿里云）时回退 nftables 计数后端（同样按监听端口）。 ----
	if !sampleConntrackInto(now, d) {
		sampleNftInto(now, d)
	}

	trafficMu.Unlock()

	persistTraffic()
}

// conntrackAcctEnabled 读取内核记账开关。
func conntrackAcctEnabled() bool {
	b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}

// localIPSet 枚举本机接口 IP（含缓存，降频）。
func localIPSet() map[string]bool {
	if len(localIPs) > 0 && time.Since(localIPT) < 5*time.Minute {
		return localIPs
	}
	set := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				set[ipnet.IP.String()] = true
			}
		}
	}
	localIPs, localIPT = set, time.Now()
	return localIPs
}

// listenPortProc 端口→进程 映射（ss -tlnp，缓存 60s 降频）。
func listenPortProc() map[int]string {
	if len(listenCache) > 0 && time.Since(listenCacheT) < 60*time.Second {
		return listenCache
	}
	m := map[int]string{}
	for _, lp := range ListenPorts() {
		m[lp.Port] = lp.Process
	}
	listenCache, listenCacheT = m, time.Now()
	return m
}

// sampleConntrackInto 批量读 conntrack，把连接字节增量归因到今日 d 的对应端口。
// 返回 true 表示 conntrack 后端本次生效；false 表示不可用（由调用方回退 nft 后端）。
func sampleConntrackInto(now time.Time, d *DayTraffic) bool {
	if !conntrackAcctEnabled() {
		trafAcctOK = false
		return false
	}
	data, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		trafAcctOK = false
		return false
	}
	local := localIPSet()
	listen := listenPortProc()
	portOf := func(port int) *PortTraffic {
		k := strconv.Itoa(port)
		p := d.Ports[k]
		if p == nil {
			proc := ""
			if listen != nil {
				proc = listen[port]
			}
			p = &PortTraffic{Port: port, Proc: proc}
			d.Ports[k] = p
		}
		return p
	}

	seen := map[string]bool{}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		cb, ok := parseConnLine(line)
		if !ok {
			continue
		}
		k := cb.key()
		seen[k] = true
		cb.lastSeen = now

		// 判断本机角色与端口：入站(远端→本机端口) vs 出站(本机端口→远端)
		var lp int
		var isInbound bool
		switch {
		case local[cb.dst]:
			// 入站：原始方向字节=入站(RX)，应答方向=出站(TX)
			lp = cb.dport
			isInbound = true
		case local[cb.src]:
			// 出站：原始方向字节=出站(TX)，应答方向=入站(RX)
			lp = cb.sport
			isInbound = false
		default:
			continue // 与本机无关的连接（纯转发/frps 内层），跳过
		}

		if prev, ok := trafConn[k]; ok {
			// 增量归因（计数器只增不减；回绕/重置则跳过；无实际增量不建端口条目，避免 0 字节噪音）
			if cb.first >= prev.first {
				if delta := cb.first - prev.first; delta > 0 {
					p := portOf(lp)
					if isInbound {
						p.RX += delta
					} else {
						p.TX += delta
					}
				}
			}
			if cb.second >= prev.second {
				if delta := cb.second - prev.second; delta > 0 {
					p := portOf(lp)
					if isInbound {
						p.TX += delta
					} else {
						p.RX += delta
					}
				}
			}
		}
		trafConn[k] = cb
	}
	// 清理不再活跃的连接基准（按 lastSeen 超龄淘汰）
	for k, cb := range trafConn {
		if !seen[k] && now.Sub(cb.lastSeen) > connPurgeAge {
			delete(trafConn, k)
		}
	}
	trafAcctOK = true
	return true
}

// ---- L2 备选后端：nftables 按监听端口字节计数 ----
// 用于内核不导出 /proc/net/nf_conntrack dump 的主机（如阿里云中转机）。
// 原理：隔离表 traffic_mon（in/out 两条 base chain，policy accept，只计数不拦包），
// 每条监听端口各建一个命名计数器（in_P/out_P），tcp+udp 双规则计数。
// 每采样周期读一次计数器做差分，归入当日端口流量。低频同步端口集（重建表+重置基准）。

// trafficPortOf 取/建今日 d 中指定端口的流量条目（带进程名）。
func trafficPortOf(d *DayTraffic, port int, listen map[int]string) *PortTraffic {
	k := strconv.Itoa(port)
	p := d.Ports[k]
	if p == nil {
		proc := ""
		if listen != nil {
			proc = listen[port]
		}
		p = &PortTraffic{Port: port, Proc: proc}
		d.Ports[k] = p
	}
	return p
}

// syncNftTable 重建 traffic_mon 隔离表（删除+重建，含当前监听端口的命名计数器）。
func syncNftTable(ports []int) bool {
	// 清空旧表（不存在则忽略错误）
	_ = exec.Command("nft", "delete", "table", "ip", "traffic_mon").Run()
	var b strings.Builder
	b.WriteString("add table ip traffic_mon\n")
	b.WriteString("add chain ip traffic_mon in { type filter hook input priority 0; policy accept; }\n")
	b.WriteString("add chain ip traffic_mon out { type filter hook output priority 0; policy accept; }\n")
	for _, p := range ports {
		ps := strconv.Itoa(p)
		in := "in_" + ps
		out := "out_" + ps
		b.WriteString("add counter ip traffic_mon " + in + "\n")
		b.WriteString("add rule ip traffic_mon in tcp dport " + ps + " counter name " + in + "\n")
		b.WriteString("add rule ip traffic_mon in udp dport " + ps + " counter name " + in + "\n")
		b.WriteString("add counter ip traffic_mon " + out + "\n")
		b.WriteString("add rule ip traffic_mon out tcp sport " + ps + " counter name " + out + "\n")
		b.WriteString("add rule ip traffic_mon out udp sport " + ps + " counter name " + out + "\n")
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	return cmd.Run() == nil
}

// readNftCounters 读取 traffic_mon 表命名计数器当前累计字节（name -> bytes）。
// 找不到 nft 或读取失败返回 nil。
func readNftCounters() map[string]uint64 {
	out := runOut(8*time.Second, "nft", "-j", "list", "table", "ip", "traffic_mon")
	if out == "" {
		return nil
	}
	var parsed struct {
		Nftables []map[string]interface{} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return nil
	}
	res := map[string]uint64{}
	for _, el := range parsed.Nftables {
		if el == nil {
			continue
		}
		// 顶层带 bytes/packets 的命名计数器：el["counter"]{name, family, handle, bytes, packets}
		c, ok := el["counter"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := c["name"].(string)
		if name == "" {
			continue
		}
		bv, ok := c["bytes"].(float64)
		if !ok {
			// 兜底：bytes 也可能在 el 顶层
			if bv2, ok2 := el["bytes"].(float64); ok2 {
				bv = bv2
			} else {
				continue
			}
		}
		res[name] = uint64(bv)
	}
	return res
}

// sampleNftInto 用 nftables 计数后端把端口字节增量归因到今日 d。
func sampleNftInto(now time.Time, d *DayTraffic) {
	if _, err := exec.LookPath("nft"); err != nil {
		trafAcctOK = false
		return
	}
	listen := listenPortProc()
	ports := make([]int, 0, len(listen))
	for p := range listen {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	// 端口集变化或超周期：重建表并重置基准
	if time.Since(trafNftSyncedAt) > trafNftSync || !samePorts(trafNftPorts, ports) {
		if !syncNftTable(ports) {
			trafAcctOK = false
			return
		}
		trafNftPorts = ports
		trafNftSyncedAt = now
		trafNftBaseline = map[string]uint64{}
	}

	cur := readNftCounters()
	if cur == nil {
		trafAcctOK = false
		return
	}
	for name, bytes := range cur {
		sep := strings.LastIndexByte(name, '_')
		if sep <= 0 || sep == len(name)-1 {
			continue
		}
		dir := name[:sep] // in/out
		p, err := strconv.Atoi(name[sep+1:])
		if err != nil {
			continue
		}
		prev, seen := trafNftBaseline[name]
		trafNftBaseline[name] = bytes
		if !seen || bytes < prev {
			continue
		}
		delta := bytes - prev
		if delta == 0 {
			continue
		}
		pt := trafficPortOf(d, p, listen)
		if dir == "in" {
			pt.RX += delta
		} else {
			pt.TX += delta
		}
	}
	trafAcctOK = true
}

// samePorts 比较两个端口集是否一致（均已排序）。
func samePorts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parseConnLine 解析单行 conntrack 为连接字节快照。字段缺失/无记账字节则返回 false。
// 内核格式示例（记账开启时）：ipv4 2 tcp 6 431999 ESTABLISHED src=A dst=B sport=P
// dport=Q src=B dst=A sport=Q dport=P [ASSURED] secs=.. bytes=.. pkts=.. bytes=.. pkts=.. use=..
// 防御式解析：只取首个出现的 src/dst/sport/dport（原始方向）+ 按序收集 bytes= 前两个。
func parseConnLine(line string) (connBytes, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return connBytes{}, false
	}
	m := map[string]string{}
	bytesVals := []uint64{}
	for _, f := range fields {
		if kv := strings.SplitN(f, "=", 2); len(kv) == 2 {
			k, v := kv[0], kv[1]
			if k == "bytes" {
				if n, err := strconv.ParseUint(v, 10, 64); err == nil {
					bytesVals = append(bytesVals, n)
				}
			} else if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
	}
	if len(bytesVals) < 2 {
		return connBytes{}, false
	}
	proto := ""
	if len(fields) > 2 {
		proto = fields[2]
	}
	var sport, dport int
	if v, err := strconv.Atoi(m["sport"]); err == nil {
		sport = v
	}
	if v, err := strconv.Atoi(m["dport"]); err == nil {
		dport = v
	}
	return connBytes{proto: proto, src: m["src"], dst: m["dst"],
		sport: sport, dport: dport, first: bytesVals[0], second: bytesVals[1]}, true
}

func persistTraffic() {
	trafficMu.Lock()
	days := make([]*DayTraffic, 0, len(trafDays))
	for _, d := range trafDays {
		days = append(days, d)
	}
	sort.Slice(days, func(i, j int) bool { return days[i].Date < days[j].Date })
	// 限制保留天数：磁盘与内存都只留最近 trafficRetain 天，长期运行不膨胀
	if len(days) > trafficRetain {
		days = days[len(days)-trafficRetain:]
		trimmed := map[string]*DayTraffic{}
		for _, d := range days {
			trimmed[d.Date] = d
		}
		trafDays = trimmed
	}
	trafficMu.Unlock()

	b, err := json.Marshal(days)
	if err != nil {
		return
	}
	_ = atomicWrite(trafficFile, b)
}

// GetTrafficAcct 返回 L2 是否跑通（供前端提示）。
func GetTrafficAcct() bool {
	trafficMu.Lock()
	defer trafficMu.Unlock()
	return trafAcctOK
}

// TrafficMonths 由日表按月份内存聚合，返回 新→旧 排序的月度汇总。
func TrafficMonths() []*MonthTraffic {
	trafficMu.Lock()
	defer trafficMu.Unlock()
	months := map[string]*MonthTraffic{}
	dates := make([]string, 0, len(trafDays))
	for date := range trafDays {
		dates = append(dates, date)
	}
	sort.Strings(dates)
	for _, date := range dates {
		mm := date[:7]
		mt := months[mm]
		if mt == nil {
			mt = &MonthTraffic{Month: mm, Ports: map[int]*PortTraffic{}}
			months[mm] = mt
		}
		d := trafDays[date]
		mt.RX += d.RX
		mt.TX += d.TX
		for _, p := range d.Ports {
			mp := mt.Ports[p.Port]
			if mp == nil {
				mp = &PortTraffic{Port: p.Port, Proc: p.Proc}
				mt.Ports[p.Port] = mp
			}
			mp.RX += p.RX
			mp.TX += p.TX
		}
	}
	res := make([]*MonthTraffic, 0, len(months))
	for _, mt := range months {
		res = append(res, mt)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Month > res[j].Month })
	for _, mt := range res {
		// 端口按总量降序
		ps := make([]*PortTraffic, 0, len(mt.Ports))
		for _, p := range mt.Ports {
			ps = append(ps, p)
		}
		sort.Slice(ps, func(i, j int) bool {
			return ps[i].RX+ps[i].TX > ps[j].RX+ps[j].TX
		})
		mt.PortsList = ps
	}
	return res
}