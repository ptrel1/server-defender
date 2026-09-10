package service

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConfigSentinelLoop：配置哨兵 + 出站哨兵（v3.8.0 新增，纯标准库）。
//
// 背景（20260910）：dsh2shell 攻击战役复发——攻击者经 dsh-web API 向
// ~/.dsh/settings.yaml 注入恶意 provider（baseURL 指向 C2 裸 HTTP 端口）+
// .credentials.yaml 写入 DSH2SHELL_* 引用，且把审批策略改 never。从注入到
// 发现隔了 3~6 天，现有 fileintegrity（只管系统包文件）/netmon（只管入站）
// 均打不中。本模块提供两层监控：
//
//  A. 配置哨兵：轮询关键配置文件哈希，变更时按规则扫描——
//     ① canary：内容出现 dsh2shell 特征（历史战役金丝雀名）；
//     ② provider-raw-ip：provider baseURL 指向公网 IP 的非标端口裸 HTTP；
//     ③ risky-key：凭据文件出现 sk-dsh2shell 类可疑 key（只记 key 名，不落值）；
//     ④ approval-never：审批/安全开关被翻成 never。
//     命中 ①② 且能提取 IP → 经 BanHook 自动封禁（复用 BlockIP 双向+中转机同步）。
//  B. 出站哨兵：解析 /proc/net/tcp(6) ESTABLISHED，统计本机到公网 IP 非常见
//     端口的出站连接；同端口连接数≥3 或命中历史 C2 端口即告警（只告警不封，
//     避免误杀；实锤封禁由 A 层触发）。
//
// 边界条件：
//   - 哈希状态与记录持久化在 data/config_sentinel.json，重启不丢基线；
//   - 凭据文件只记录 key 名与命中规则，绝不写入 key 值；
//   - 出站白名单端口较宽（DNS/ntp/代理/隧道等），宁漏勿误报，调优靠积累。
//   - 仅 root 部署机可读全部文件；读失败按「权限不足」记录而非告警噪音。

const (
	sentinelInterval   = 5 * time.Minute
	sentinelStateFile  = "data/config_sentinel.json"
	sentinelMaxRecords = 200
	outboundMaxRecords = 100
)

// 默认监控文件（绝对路径；服务以 root 运行，os.UserHomeDir=/root 会落空，
// dsh 配置实际在 /home/a1/.dsh，20260910 部署首轮回归修正）。
var sentinelDefaultFiles = []string{
	"/home/a1/.dsh/settings.yaml",
	"/home/a1/.dsh/.credentials.yaml",
	"/home/a1/.dsh/AGENTS.md",
}

// 出站哨兵放行端口：常见明文/基础设施端口，出现不代表异常。
var outboundAllowPorts = map[int]bool{
	20: true, 21: true, 22: true, 25: true, 53: true, 80: true, 110: true,
	123: true, 143: true, 443: true, 465: true, 587: true, 993: true,
	995: true, 853: true, 3000: true, 3012: true, 5000: true, 5010: true,
	5011: true, 5244: true, 7500: true, 8080: true, 8443: true, 8899: true,
	9000: true, 9999: false, // 9999 曾是 dsh2shell C2 端口 → 显式不放行
	40022: true, 50022: true, 50122: true, 53012: true, 53080: true, 53103: true,
	7001: true, // frps bindPort（本机 frpc → 中转机长连接，20260910 首轮误报修正）
}

// 历史 C2 端口（20260831/0910 dsh2shell 战役实锤），命中直接告警。
var knownC2Ports = map[int]bool{9999: true, 5888: true, 4603: true}

type SentinelRecord struct {
	Time  string   `json:"time"`
	File  string   `json:"file"`
	Rules []string `json:"rules"`      // 命中规则名
	IP    string   `json:"ip,omitempty"` // 提取到的 C2 IP（已自动封禁）
	Note  string   `json:"note,omitempty"`
}

type OutboundRecord struct {
	Time   string `json:"time"`
	Remote string `json:"remote"` // ip:port
	Conns  int    `json:"conns"`
	Reason string `json:"reason"` // c2-port / multi-conn
}

type SentinelSnapshot struct {
	Updated   string            `json:"updated"`
	Hashes    map[string]string `json:"hashes"` // file -> sha256（上次基线）
	Records   []SentinelRecord  `json:"records"`
	Outbound  []OutboundRecord  `json:"outbound"`
	BannedIPs []string          `json:"banned_ips"`
}

var (
	sentinelMu      sync.Mutex
	sentinel        SentinelSnapshot
	sentinelLoaded  bool
	// BanHook 由 main 注入 handler.BlockIP（避免 service→handler 依赖环）。
	BanHook func(ip string) (bool, string)
)

var (
	reDsh2shell  = regexp.MustCompile(`(?i)dsh2shell`)
	reBaseURLIP  = regexp.MustCompile(`baseURL:\s*http://(\d+\.\d+\.\d+\.\d+):(\d+)`)
	reRiskyKey   = regexp.MustCompile(`(?i)^\s*([A-Z0-9_]*DSH2SHELL[A-Z0-9_]*):`)
	reApprovalNV = regexp.MustCompile(`(?i)(approval|approve_policy|confirm)\s*[=:]\s*["']?never`)
)

func loadSentinel() {
	if sentinelLoaded {
		return
	}
	sentinelLoaded = true
	sentinel = SentinelSnapshot{Hashes: map[string]string{}}
	b, err := os.ReadFile(sentinelStateFile)
	if err == nil {
		_ = json.Unmarshal(b, &sentinel)
		if sentinel.Hashes == nil {
			sentinel.Hashes = map[string]string{}
		}
	}
}

func saveSentinel() {
	b, err := json.MarshalIndent(&sentinel, "", " ")
	if err == nil {
		_ = os.MkdirAll(filepath.Dir(sentinelStateFile), 0o755)
		_ = os.WriteFile(sentinelStateFile, b, 0o600)
	}
}

func isPublicIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

// scanSentinelFile 对单文件做变更检测+规则扫描，返回命中记录（无变更返回 nil）。
func scanSentinelFile(path string) *SentinelRecord {
	f, err := os.Open(path)
	if err != nil {
		return &SentinelRecord{Time: now(), File: path, Rules: []string{"read-fail"}, Note: err.Error()}
	}
	defer f.Close()

	h := sha256.New()
	var hitRules []string
	var c2IP, note string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		h.Write([]byte(line + "\n"))
		if reDsh2shell.MatchString(line) && !containsStr(hitRules, "canary-dsh2shell") {
			hitRules = append(hitRules, "canary-dsh2shell")
		}
		if m := reBaseURLIP.FindStringSubmatch(line); m != nil {
			port, _ := strconv.Atoi(m[2])
			// 公网 IP + 非 443/80 端口 = provider 指向裸 HTTP C2 的强特征
			if port != 80 && port != 443 {
				if !containsStr(hitRules, "provider-raw-ip") {
					hitRules = append(hitRules, "provider-raw-ip")
				}
				c2IP, note = m[1], strings.TrimSpace(line)
			}
		}
		if m := reRiskyKey.FindStringSubmatch(line); m != nil && !containsStr(hitRules, "risky-key") {
			hitRules = append(hitRules, "risky-key")
			note = "可疑凭据 key 名: " + m[1] + "（值不入日志）"
		}
		if reApprovalNV.MatchString(line) && !containsStr(hitRules, "approval-never") {
			hitRules = append(hitRules, "approval-never")
			note = strings.TrimSpace(line)
		}
	}
	sum := hex.EncodeToString(h.Sum(nil))
	old, ok := sentinel.Hashes[path]
	sentinel.Hashes[path] = sum
	if ok && old == sum {
		return nil // 无变更
	}
	if len(hitRules) == 0 {
		return nil // 变更但未命中规则（正常运维改动），仅刷新基线
	}
	return &SentinelRecord{Time: now(), File: path, Rules: hitRules, IP: c2IP, Note: note}
}

// containsStr 复用 usernames_loop.go 同名工具，本文件不再重复定义。

// scanOutbound 统计 ESTABLISHED 出站到公网非白名单端口的连接。
func scanOutbound() []OutboundRecord {
	type key struct{ ip string; port int }
	agg := map[key]int{}
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // 表头
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 4 || fs[3] != "01" { // 01=ESTABLISHED
				continue
			}
			remote := fs[2]
			hostPort := strings.Split(remote, ":")
			if len(hostPort) != 2 {
				continue
			}
			rawIP := hostPort[0]
			var ip net.IP
			if len(rawIP) == 8 { // IPv4 做 little-endian 字序还原
				b := make(net.IP, 4)
				for i := 0; i < 4; i++ {
					v, _ := strconv.ParseUint(rawIP[i*2:i*2+2], 16, 64)
					b[3-i] = byte(v)
				}
				ip = b
			} else if len(rawIP) == 32 {
				ip = make(net.IP, 16)
				for i := 0; i < 16; i++ {
					v, _ := strconv.ParseUint(rawIP[i*2:i*2+2], 16, 64)
					ip[15-i] = byte(v)
				}
			}
			port, _ := strconv.ParseInt(hostPort[1], 16, 32)
			if !isPublicIP(ip) || outboundAllowPorts[int(port)] {
				continue
			}
			agg[key{ip.String(), int(port)}]++
		}
		f.Close()
	}
	var out []OutboundRecord
	for k, n := range agg {
		reason := ""
		if knownC2Ports[k.port] {
			reason = "c2-port"
		} else if n >= 3 {
			reason = "multi-conn"
		}
		if reason != "" {
			out = append(out, OutboundRecord{Time: now(), Remote: fmt.Sprintf("%s:%d", k.ip, k.port), Conns: n, Reason: reason})
		}
	}
	if len(out) > outboundMaxRecords {
		out = out[:outboundMaxRecords]
	}
	return out
}

// ConfigSentinelLoop 主循环：每 5min 跑一轮 A+B。
func ConfigSentinelLoop(done <-chan struct{}) {
	loadSentinel()
	// 启动即跑一轮（首次只建基线，通常无告警）
	runSentinelOnce()
	t := time.NewTicker(sentinelInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			runSentinelOnce()
		}
	}
}

func runSentinelOnce() {
	sentinelMu.Lock()
	defer sentinelMu.Unlock()
	for _, rel := range sentinelDefaultFiles {
		if rec := scanSentinelFile(rel); rec != nil {
			// 自动封禁：canary/provider 命中且提取到 C2 IP
			if rec.IP != "" && (containsStr(rec.Rules, "canary-dsh2shell") || containsStr(rec.Rules, "provider-raw-ip")) {
				if !containsStr(sentinel.BannedIPs, rec.IP) {
					if BanHook != nil {
						BanHook(rec.IP)
					}
					sentinel.BannedIPs = append(sentinel.BannedIPs, rec.IP)
					rec.Note = strings.TrimSpace(rec.Note + " | 已自动双向封禁 " + rec.IP)
				}
			}
			sentinel.Records = append(sentinel.Records, *rec)
		}
	}
	if len(sentinel.Records) > sentinelMaxRecords {
		sentinel.Records = sentinel.Records[len(sentinel.Records)-sentinelMaxRecords:]
	}
	if ob := scanOutbound(); len(ob) > 0 {
		sentinel.Outbound = append(sentinel.Outbound, ob...)
		if len(sentinel.Outbound) > outboundMaxRecords {
			sentinel.Outbound = sentinel.Outbound[len(sentinel.Outbound)-outboundMaxRecords:]
		}
	}
	sentinel.Updated = now()
	saveSentinel()
}

// SentinelSnapshotView 供 dashboard 渲染。
func SentinelSnapshotView() SentinelSnapshot {
	sentinelMu.Lock()
	defer sentinelMu.Unlock()
	return sentinel
}

func now() string { return time.Now().Format("01-02 15:04:05") }
