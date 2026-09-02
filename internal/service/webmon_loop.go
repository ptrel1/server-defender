package service

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WebMon：域名访问监控采集层（纯标准库）。
// 设计意图：
//   - 监控公网 nginx 上各域名 vhost 的 access_log（log_format timed），
//     按域名+IP 聚合访问行为，产出趋势折线图数据与风险告警。
//   - 数据源是公网机 nginx 日志，本模块以「增量 tail + 轮转检测」方式消费，
//     对业务零侵入；日志缺失/无流量时静默等待，不影响其他模块。
// 边界条件：
//   - 首次打开/轮转时从「文件末尾往前最多回扫 2MB」开始，兼顾重启后今日 KPI
//     不失真与低开销；单轮消费上限 8MB，防日志洪峰拖垮扫描周期；
//   - 行解析失败直接丢弃（脏行多为轮转竞态，不值得重试）；
//   - IP 明细只保留 48h，10 分钟趋势桶只保留 24h，防止长驻内存膨胀。

const (
	webmonScanInterval = 3 * time.Second  // 日志增量扫描周期
	webmonSaveInterval = 60 * time.Second // 统计落盘周期
	webmonDetailTTL    = 48 * time.Hour   // IP 明细保留窗口
	webmonBucketTTL    = 24 * time.Hour   // 趋势桶保留窗口
	webmonBucketLen    = int64(600)       // 桶宽 10 分钟
	webmonAlertMax     = 200              // 告警留存量
	webmonAlertDedupe  = 10 * time.Minute // 同 IP 同规则告警去重窗口
	webmonRateWindow   = 5 * time.Minute  // 频率类告警统计窗口
	webmonFreqLimit    = 300              // 5 分钟请求数告警阈值
	webmonScanLimit    = 50               // 5 分钟 4xx 数告警阈值
	webmonPathsCap     = 20               // 每 IP 保留的路径 TOP 上限
	webmonRecentCap    = 50               // 最近访问记录留存量
	webmonBackscanMax  = int64(2 << 20)   // 首次打开回扫字节上限（2MB）
)

// webmonLogs 监控的域名日志清单（与公网 nginx vhost access_log 一一对应）。
var webmonLogs = []struct {
	Path   string
	Domain string
}{
	{"/var/log/nginx/dsh.ptrel.cc.cd.access.log", "dsh.ptrel.cc.cd"},
	{"/var/log/nginx/dsh2.ptrel.cc.cd.access.log", "dsh2.ptrel.cc.cd"},
}

// WebHit 单条访问记录（最近访问流展示用）。
type WebHit struct {
	Time   string `json:"time"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	UA     string `json:"ua"`
}

// WebIPStat 单个 IP 在某域名下的聚合画像。
type WebIPStat struct {
	IP     string           `json:"ip"`
	Domain string           `json:"domain"`
	Count  int64            `json:"count"`  // 窗口内总请求
	First  string           `json:"first"`
	Last   string           `json:"last"`
	LastTs int64            `json:"last_ts"`
	Today  int64            `json:"today"`  // 今日请求数（本地时区）
	Status map[string]int   `json:"status"` // "2xx"/"3xx"/"4xx"/"5xx" 计数
	UA     string           `json:"ua"`
	Paths  map[string]int64 `json:"paths"` // 路径→次数（封顶 webmonPathsCap）
}

// WebBucket 10 分钟趋势桶；IPs=-1 表示重启后未知（展示按 0 处理）。
type WebBucket struct {
	Time  string `json:"time"`
	Ts    int64  `json:"ts"`
	Count int64  `json:"count"`
	IPs   int    `json:"ips"`
}

// WebMonSnapshot 供 handler 层消费的整体快照（值拷贝，锁内组装避免撕裂读）。
type WebMonSnapshot struct {
	TodayRequests int64                  `json:"today_requests"`
	TodayIPs      int                    `json:"today_ips"`
	DomainToday   map[string]int64       `json:"domain_today"`
	TotalRequests int64                  `json:"total_requests"`
	TotalIPs      int                    `json:"total_ips"`
	Buckets       map[string][]WebBucket `json:"buckets"` // domain → 升序桶
	TopIPs        []WebIPStat            `json:"top_ips"`
	Recent        []WebHit               `json:"recent"`
}

type webmonState struct {
	mu            sync.RWMutex
	domainIPs     map[string]map[string]*WebIPStat     // domain → ip → 画像
	buckets       map[string]map[int64]*WebBucket      // domain → bucketTs → 桶
	bucketIPs     map[string]map[int64]map[string]bool // domain → bucketTs → ip 集合
	recent        []WebHit
	todayDate     string // "2006-01-02"（本地时区）
	todayRequests int64
	todayIPSet    map[string]bool
	totalRequests int64
	offs          map[string]int64        // 各日志文件已消费偏移（进程内，重启后回扫兜底）
	rateMu        sync.Mutex              // 保护 rateHits（s.mu 已被 record 持有时仍需写窗口）
	rateHits      map[string][]int64      // ip → 窗口内命中时间戳；key 前缀 "4:" 为 4xx 旁路
	alertDedupe   map[string]time.Time    // 告警去重：dedupeKey → 上次触发时间
}

func newWebmonState() *webmonState {
	return &webmonState{
		domainIPs:   map[string]map[string]*WebIPStat{},
		buckets:     map[string]map[int64]*WebBucket{},
		bucketIPs:   map[string]map[int64]map[string]bool{},
		todayIPSet:  map[string]bool{},
		offs:        map[string]int64{},
		rateHits:    map[string][]int64{},
		alertDedupe: map[string]time.Time{},
	}
}

var webmon = newWebmonState()

// WebMonLoop 常驻采集协程：增量 tail 各域名日志 + 周期落盘 + 过期清理。
func WebMonLoop(done <-chan struct{}) {
	webmon.load()
	go func() {
		ticker := time.NewTicker(webmonScanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// 兜底防线：日志内容不可信（防御性架构），解析对畸形行虽已防御，
				// 任何漏网 panic 也只丢一轮扫描，不允许拖垮封禁/自愈等兄弟协程。
				func() {
					defer func() {
						if r := recover(); r != nil {
							fmt.Println("[webmon] scan recover:", r)
						}
					}()
					for _, lg := range webmonLogs {
						webmon.consumeLog(lg.Path, lg.Domain)
					}
				}()
			}
		}
	}()
	for {
		select {
		case <-done:
			return
		case <-time.After(webmonSaveInterval):
			webmon.prune()
			webmon.save()
		}
	}
}

// consumeLog 增量读取单个日志文件；仅消费完整行，偏移以完整行为准。
// 轮转/截断检测：文件小于上次偏移时回到「末尾回扫」重新开始。
func (s *webmonState) consumeLog(path, domain string) {
	f, err := os.Open(path)
	if err != nil {
		return // 文件尚未产生（如新域名无流量），静默等待
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return
	}
	off, known := s.offs[path]
	backscan := !known || st.Size() < off // 首次打开或轮转：本块为历史回扫
	if backscan {
		// 从末尾回扫最多 2MB
		off = st.Size() - webmonBackscanMax
		if off < 0 {
			off = 0
		}
	}
	if st.Size() == off {
		return
	}
	if _, err := f.Seek(off, 0); err != nil {
		return
	}

	// 读入缓冲，仅保留最后一个 \n 之前的完整行
	var data []byte
	buf := make([]byte, 32*1024)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if len(data) > 8<<20 { // 单轮消费上限 8MB
				break
			}
		}
		if rerr != nil || n == 0 {
			break
		}
	}
	lastNL := bytes.LastIndexByte(data, '\n')
	if lastNL < 0 {
		return // 连一条完整行都没有，偏移不动
	}
	s.ingestLines(data[:lastNL+1], domain, !backscan)
	s.offs[path] = off + int64(lastNL+1)
}

// ingestLines 逐行解析入库；太老的回扫行与解析失败行直接丢弃。
// allowAlerts=false（历史回扫块）时只入统计不触发频率告警，避免重启后补发旧窗口告警。
func (s *webmonState) ingestLines(chunk []byte, domain string, allowAlerts bool) {
	now := time.Now()
	sc := bufio.NewScanner(bytes.NewReader(chunk))
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		hit, ts, ok := parseTimedLine(line)
		if !ok || ts.IsZero() {
			continue
		}
		if now.Sub(ts) > webmonDetailTTL {
			continue
		}
		hit.Domain = domain
		s.record(hit, ts, allowAlerts)
	}
}

// parseTimedLine 解析 nginx log_format timed：
// <ip> - <time_local> "<request>" <status> <bytes> "<referer>" "<ua>" rt=.. urt=..
// 设计说明：手工切片而非正则，单行 O(n) 且无回溯风险；异常请求（如 TLS 裸流量
// 打到日志里的 "\x16..."）method/path 降级为 "-"，不影响统计。
func parseTimedLine(line string) (WebHit, time.Time, bool) {
	var hit WebHit
	idx := strings.Index(line, " - ")
	if idx <= 0 {
		return hit, time.Time{}, false
	}
	hit.IP = line[:idx]
	rest := line[idx+3:]

	// time_local 段：第一个引号之前
	q1 := strings.IndexByte(rest, '"')
	if q1 < 0 {
		return hit, time.Time{}, false
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", strings.TrimSpace(rest[:q1]))
	if err != nil {
		return hit, time.Time{}, false
	}

	// request 段：第一对引号
	rest = rest[q1+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return hit, time.Time{}, false
	}
	req := rest[:q2]
	rest = rest[q2+1:]

	// status bytes 段
	fields := strings.Fields(strings.TrimSpace(rest))
	if len(fields) < 2 {
		return hit, time.Time{}, false
	}
	status, err := strconv.Atoi(fields[0])
	if err != nil {
		return hit, time.Time{}, false
	}

	// referer/UA 两段引号串：依次定位 4 个引号 r1..r4，
	// r1..r2 为 referer，r3..r4 为 UA（修复：旧实现只跳一层引号，取到的是 referer）。
	// P0 修复：每个引号必须存在，任何缺失整行按脏行丢弃——
	// 旧实现 IndexByte 返回 -1 时 rest[-1:] 直接 panic（常驻协程无 recover 会拖垮进程）。
	quotes := make([]int, 0, 4)
	start := 0
	for i := 0; i < 4; i++ {
		pos := strings.IndexByte(rest[start:], '"')
		if pos < 0 {
			return hit, time.Time{}, false
		}
		start += pos
		quotes = append(quotes, start)
		start++
	}
	hit.UA = rest[quotes[2]+1 : quotes[3]]
	if len(hit.UA) > 200 {
		hit.UA = hit.UA[:200]
	}

	parts := strings.Fields(req)
	hit.Method, hit.Path = "-", "-"
	if len(parts) >= 2 {
		hit.Method = parts[0]
		hit.Path = parts[1]
	} else if req != "" && req != "-" {
		hit.Path = req
	}
	if len(hit.Path) > 120 {
		hit.Path = hit.Path[:120]
	}
	hit.Status = status
	return hit, ts, true
}

// webmonAlertReq 待落盘的告警请求（record 锁内收集、锁外落盘）。
type webmonAlertReq struct {
	level, title, detail, dedupeKey string
	ts                              time.Time
}

// record 将一条命中写入各聚合结构（今日 KPI / IP 画像 / 趋势桶 / 频率窗口）。
// 告警只在此收集，I/O 由锁外 emitAlert 落盘（P2-1：不持 s.mu 做文件 I/O）。
func (s *webmonState) record(h WebHit, ts time.Time, allowAlerts bool) {
	var pending []webmonAlertReq
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.aggregate(h, ts)
		if allowAlerts {
			s.collectRateAlerts(h, ts, &pending)
		}
	}()
	for _, a := range pending {
		s.emitAlert(a)
	}
}

// aggregate 单条命中的全部内存聚合（调用方持有 s.mu）。
func (s *webmonState) aggregate(h WebHit, ts time.Time) {

	// ---- 频率窗口（含 4xx 旁路），先于告警判定更新 ----
	now := ts.Unix()
	s.rateMu.Lock()
	s.rateHits[h.IP] = append(s.rateHits[h.IP], now)
	if h.Status >= 400 {
		s.rateHits["4:"+h.IP] = append(s.rateHits["4:"+h.IP], now)
	}
	s.rateMu.Unlock()

	// ---- 今日 KPI（本地时区零点重置；回扫历史行日期只会更旧，跨天分支仅在真实新一天触发）----
	today := ts.Format("2006-01-02")
	if s.todayDate == "" {
		s.todayDate = today
	}
	if today == s.todayDate {
		s.todayRequests++
		s.todayIPSet[h.IP] = true
	} else if today > s.todayDate {
		s.todayDate = today
		s.todayRequests = 1
		s.todayIPSet = map[string]bool{h.IP: true}
	}
	s.totalRequests++

	// ---- IP 画像 ----
	dm := s.domainIPs[h.Domain]
	if dm == nil {
		dm = map[string]*WebIPStat{}
		s.domainIPs[h.Domain] = dm
	}
	st := dm[h.IP]
	if st == nil {
		st = &WebIPStat{IP: h.IP, Domain: h.Domain,
			Status: map[string]int{}, Paths: map[string]int64{},
			First: ts.Format("01-02 15:04")}
		dm[h.IP] = st
	}
	st.Count++
	if today == s.todayDate {
		st.Today++
	}
	st.Last = ts.Format("01-02 15:04")
	st.LastTs = ts.Unix()
	if h.UA != "" {
		st.UA = h.UA
	}
	st.Status[statusClass(h.Status)]++
	s.bumpPath(st, h.Path)

	// ---- 趋势桶 ----
	bk := s.buckets[h.Domain]
	if bk == nil {
		bk = map[int64]*WebBucket{}
		s.buckets[h.Domain] = bk
	}
	bip := s.bucketIPs[h.Domain]
	if bip == nil {
		bip = map[int64]map[string]bool{}
		s.bucketIPs[h.Domain] = bip
	}
	bts := ts.Unix() / webmonBucketLen
	b := bk[bts]
	if b == nil {
		b = &WebBucket{Ts: bts * webmonBucketLen, Time: ts.Format("01-02 15:04")}
		bk[bts] = b
		bip[bts] = map[string]bool{}
	}
	b.Count++
	bip[bts][h.IP] = true
	b.IPs = len(bip[bts])

	// ---- 最近访问流 ----
	h.Time = ts.Format("01-02 15:04:05")
	s.recent = append(s.recent, h)
	if len(s.recent) > webmonRecentCap {
		s.recent = s.recent[len(s.recent)-webmonRecentCap:]
	}

}

// bumpPath 维护路径 TOP：封顶时只淘汰仅出现过一次的最旧计数路径，
// 保证扫描型新路径仍可见、高频路径不被挤掉。
func (s *webmonState) bumpPath(st *WebIPStat, path string) {
	if _, dup := st.Paths[path]; !dup && len(st.Paths) >= webmonPathsCap {
		minK, minV := "", int64(1<<62)
		for k, v := range st.Paths {
			if v < minV {
				minK, minV = k, v
			}
		}
		if minV < 2 {
			delete(st.Paths, minK)
		}
	}
	st.Paths[path]++
}

// collectRateAlerts 基于滑动窗口判定频率异常与扫描探测，只收集不落盘（调用方持有 s.mu）。
func (s *webmonState) collectRateAlerts(h WebHit, ts time.Time, out *[]webmonAlertReq) {
	cutoff := ts.Add(-webmonRateWindow).Unix()
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	total := pruneHits(s.rateHits, h.IP, cutoff)
	if total > webmonFreqLimit {
		*out = append(*out, webmonAlertReq{level: "warning", title: "访问频率异常",
			detail:   fmt.Sprintf("%s 5 分钟内请求 %d 次（阈值 %d），最近路径 %s", h.IP, total, webmonFreqLimit, h.Path),
			dedupeKey: h.IP + ":freq", ts: ts})
	}
	bad := pruneHits(s.rateHits, "4:"+h.IP, cutoff)
	if bad > webmonScanLimit {
		*out = append(*out, webmonAlertReq{level: "warning", title: "疑似扫描探测",
			detail:   fmt.Sprintf("%s 5 分钟内 4xx 响应 %d 次（阈值 %d），最近路径 %s", h.IP, bad, webmonScanLimit, h.Path),
			dedupeKey: h.IP + ":scan", ts: ts})
	}
}

// webmonAlertMu 保护 alertDedupe 与告警文件 I/O；独立于 s.mu，保证聚合临界区内零 I/O。
var webmonAlertMu sync.Mutex

// emitAlert 落盘一条告警（10 分钟同 key 去重）。必须在 s.mu 之外调用。
func (s *webmonState) emitAlert(a webmonAlertReq) {
	webmonAlertMu.Lock()
	defer webmonAlertMu.Unlock()
	if last, ok := s.alertDedupe[a.dedupeKey]; ok && a.ts.Sub(last) < webmonAlertDedupe {
		return
	}
	s.alertDedupe[a.dedupeKey] = a.ts
	alerts := loadWebAlerts()
	alerts = append(alerts, Alert{
		Time: a.ts.Format("01-02 15:04:05"), Level: a.level, Title: a.title, Detail: a.detail,
	})
	if len(alerts) > webmonAlertMax {
		alerts = alerts[len(alerts)-webmonAlertMax:]
	}
	saveWebAlerts(alerts)
}

// pruneHits 裁剪窗口外时间戳并返回窗口内数量。
func pruneHits(m map[string][]int64, key string, cutoff int64) int {
	hits := m[key]
	kept := hits[:0]
	for _, t := range hits {
		if t >= cutoff {
			kept = append(kept, t)
		}
	}
	m[key] = kept
	return len(kept)
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}

// ---- 持久化（data/webmon_stats.json / data/webmon_alerts.json）----

type webmonPersist struct {
	SavedAt       string                       `json:"saved_at"`
	TodayDate     string                       `json:"today_date"`
	TodayRequests int64                        `json:"today_requests"`
	TodayIPs      []string                     `json:"today_ips"`
	TotalRequests int64                        `json:"total_requests"`
	Domains       map[string]*webmonDomainSnap `json:"domains"`
	Recent        []WebHit                     `json:"recent"`
}

type webmonDomainSnap struct {
	IPs     []WebIPStat `json:"ips"`
	Buckets []WebBucket `json:"buckets"`
}

func webmonStatsFile() string  { return filepath.Join(dataDir(), "webmon_stats.json") }
func webmonAlertsFile() string { return filepath.Join(dataDir(), "webmon_alerts.json") }

func (s *webmonState) save() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p := webmonPersist{
		SavedAt:       time.Now().Format("2006-01-02 15:04:05"),
		TodayDate:     s.todayDate,
		TodayRequests: s.todayRequests,
		TotalRequests: s.totalRequests,
		Domains:       map[string]*webmonDomainSnap{},
	}
	for ip := range s.todayIPSet {
		p.TodayIPs = append(p.TodayIPs, ip)
	}
	for domain, dm := range s.domainIPs {
		ds := &webmonDomainSnap{}
		for _, st := range dm {
			ds.IPs = append(ds.IPs, *st)
		}
		for _, b := range s.buckets[domain] {
			ds.Buckets = append(ds.Buckets, *b)
		}
		sort.Slice(ds.Buckets, func(i, j int) bool { return ds.Buckets[i].Ts < ds.Buckets[j].Ts })
		p.Domains[domain] = ds
	}
	if len(s.recent) > 0 {
		p.Recent = append([]WebHit(nil), s.recent...)
	}
	if b, err := jsonMarshal(p); err == nil {
		_ = atomicWrite(webmonStatsFile(), b)
	}
}

func (s *webmonState) load() {
	b, err := os.ReadFile(webmonStatsFile())
	if err != nil {
		return
	}
	var p webmonPersist
	if jsonUnmarshal(b, &p) != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.todayDate = p.TodayDate
	s.todayRequests = p.TodayRequests
	s.totalRequests = p.TotalRequests
	for _, ip := range p.TodayIPs {
		s.todayIPSet[ip] = true
	}
	for domain, ds := range p.Domains {
		dm := map[string]*WebIPStat{}
		for _, st := range ds.IPs {
			v := st
			if v.Status == nil {
				v.Status = map[string]int{}
			}
			if v.Paths == nil {
				v.Paths = map[string]int64{}
			}
			dm[v.IP] = &v
		}
		s.domainIPs[domain] = dm
		bk := map[int64]*WebBucket{}
		bip := map[int64]map[string]bool{}
		for _, bu := range ds.Buckets {
			v := bu
			bk[v.Ts] = &v
			bip[v.Ts] = map[string]bool{} // ip 集合不回放，桶内 IP 数以落盘值为下限
		}
		s.buckets[domain] = bk
		s.bucketIPs[domain] = bip
	}
	if len(p.Recent) > webmonRecentCap {
		p.Recent = p.Recent[len(p.Recent)-webmonRecentCap:]
	}
	s.recent = p.Recent
}

// prune 清理过期明细与桶（每落盘周期执行一次）。
func (s *webmonState) prune() {
	cutoff := time.Now().Add(-webmonDetailTTL).Unix()
	bCutoff := time.Now().Add(-webmonBucketTTL).Unix()
	// 显式 Unlock（不用 defer）：后半段还要拿 rateMu/alertMu 做回收，
	// 保持「s.mu → rateMu/alertMu」单向加锁顺序，避免交叉持锁。
	s.mu.Lock()
	for _, dm := range s.domainIPs {
		for ip, st := range dm {
			if st.LastTs < cutoff {
				delete(dm, ip)
			}
		}
	}
	for domain, bk := range s.buckets {
		for bts := range bk {
			if bts < bCutoff {
				delete(bk, bts)
				delete(s.bucketIPs[domain], bts)
			}
		}
	}
	s.mu.Unlock()
	// P2-2：频率窗口/去重表只裁值不删 key，长期被扫描会缓慢膨胀，这里顺手回收。
	s.rateMu.Lock()
	for k, v := range s.rateHits {
		if len(v) == 0 {
			delete(s.rateHits, k)
		}
	}
	s.rateMu.Unlock()
	webmonAlertMu.Lock()
	stale := time.Now().Add(-webmonAlertDedupe)
	for k, t := range s.alertDedupe {
		if t.Before(stale) {
			delete(s.alertDedupe, k)
		}
	}
	webmonAlertMu.Unlock()
}

func loadWebAlerts() []Alert {
	b, err := os.ReadFile(webmonAlertsFile())
	if err != nil {
		return nil
	}
	var a []Alert
	if jsonUnmarshal(b, &a) != nil {
		return nil
	}
	return a
}

func saveWebAlerts(a []Alert) {
	if b, err := jsonMarshal(a); err == nil {
		_ = atomicWrite(webmonAlertsFile(), b)
	}
}

// LoadWebAlerts 导出告警（handler 用）。
func LoadWebAlerts() []Alert {
	a := loadWebAlerts()
	if len(a) > webmonAlertMax {
		a = a[len(a)-webmonAlertMax:]
	}
	return a
}

// GetWebMonSnapshot 导出快照入口（handler 用）。
func GetWebMonSnapshot() WebMonSnapshot { return webmon.snapshot() }

// deepCopyIPStat 复制 IP 画像并克隆内嵌 map（快照值拷贝必须切断与聚合结构的共享）。
func deepCopyIPStat(st WebIPStat) WebIPStat {
	status := make(map[string]int, len(st.Status))
	for k, v := range st.Status {
		status[k] = v
	}
	paths := make(map[string]int64, len(st.Paths))
	for k, v := range st.Paths {
		paths[k] = v
	}
	st.Status, st.Paths = status, paths
	return st
}

// snapshot 组装整体快照（值拷贝，锁内完成避免撕裂读）。
func (s *webmonState) snapshot() WebMonSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := WebMonSnapshot{
		TodayRequests: s.todayRequests,
		TodayIPs:      len(s.todayIPSet),
		DomainToday:   map[string]int64{},
		TotalRequests: s.totalRequests,
		Buckets:       map[string][]WebBucket{},
	}
	var all []WebIPStat
	for domain, dm := range s.domainIPs {
		var today int64
		for _, st := range dm {
			today += st.Today
			all = append(all, *st)
		}
		snap.DomainToday[domain] = today
		snap.TotalIPs += len(dm)

		list := make([]WebBucket, 0, len(s.buckets[domain]))
		for _, b := range s.buckets[domain] {
			v := *b
			// P1-b：重启后 ip 集合不回放（空 map 非 nil），取「集合现值 vs 落盘值」较大者，
			// 避免把恢复的桶 IP 数覆盖成 0。
			if n := len(s.bucketIPs[domain][v.Ts]); n > v.IPs {
				v.IPs = n
			}
			list = append(list, v)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Ts < list[j].Ts })
		snap.Buckets[domain] = list
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Today > all[j].Today })
	for i := range all {
		all[i] = deepCopyIPStat(all[i]) // P1-c：handler 锁外读 map，必须深拷贝切断共享
	}
	if len(all) > 20 {
		all = all[:20]
	}
	snap.TopIPs = all
	if len(s.recent) > 0 {
		snap.Recent = append([]WebHit(nil), s.recent...)
	}
	return snap
}
