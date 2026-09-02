package service

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// IP 标记系统：允许对任意 IP 打上「标签 + 注释 + 颜色」，用于面板各处直观辨认。
// 三层标记（合并时手动优先）：
//
//	L1 自动识别：白名单(usernames.json.whitelist)→白名单，黑名单(perm_ban.txt 已封)→已封禁，本机回环→本地
//	L2 手动标记：data/ip_tags.json 中用户自定义的 {标签, 注释, 颜色}
type IPTag struct {
	Tag   string `json:"tag"`            // 简短标签，如 白名单/已封禁/家庭宽带
	Note  string `json:"note"`           // 详细注释，如 我的固定宽带出口
	Color string `json:"color"`          // 可选 green/red/blue/yellow/gray，空串=auto
	Auto  bool   `json:"auto,omitempty"` // 是否为自动识别，手动标记为 false
}

type IPTagsState struct {
	Custom map[string]IPTag `json:"custom"` // 用户手动标记,key=IP
}

var (
	tagsFile = filepath.Join(dataDir(), "ip_tags.json")
	tagsMu   sync.Mutex
)

// IPTagsPath 导出标记文件路径（供 handler/测试）。
func IPTagsPath() string { return tagsFile }

func loadIPTagsState() *IPTagsState {
	s := &IPTagsState{Custom: map[string]IPTag{}}
	data, err := os.ReadFile(tagsFile)
	if err == nil {
		_ = jsonUnmarshal(data, s)
	}
	if s.Custom == nil {
		s.Custom = map[string]IPTag{}
	}
	return s
}

func saveIPTagsState(s *IPTagsState) {
	b, _ := jsonMarshal(s)
	if len(b) > 0 {
		_ = atomicWrite(tagsFile, b)
	}
}

// ipTagAuto 层1自动识别。
func ipTagAuto(ip string) (IPTag, bool) {
	if isPrivateOrLoopback(ip) {
		return IPTag{Tag: "本地", Note: "本机/私网地址", Color: "blue", Auto: true}, true
	}
	state := loadUsernamesState()
	for _, wl := range state.Whitelist {
		if strings.TrimSpace(wl) == ip {
			return IPTag{Tag: "白名单", Note: "公钥登录自动放行", Color: "green", Auto: true}, true
		}
	}
	if isIPBanned(ip) {
		return IPTag{Tag: "已封禁", Note: "命中封禁规则", Color: "red", Auto: true}, true
	}
	return IPTag{}, false
}

// isIPBanned 检查 IP 是否在 perm_ban.txt 中。
func isIPBanned(ip string) bool {
	b, err := os.ReadFile(banPath())
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == ip {
			return true
		}
	}
	return false
}

// ipPatternMatch 判断标记 key(pattern) 是否匹配具体 IP。
// 支持三种形式：
//   - 精确 IP：如 192.168.1.10
//   - 通配符：如 36.18.x.x / 36.18.*.*（x 或 * 均可，仅按 IPv4 四段匹配）
//   - CIDR：如 36.18.0.0/16
func ipPatternMatch(pattern, ip string) bool {
	p := strings.TrimSpace(pattern)
	ip = strings.TrimSpace(ip)
	// CIDR
	if strings.Contains(p, "/") {
		_, ipnet, err := net.ParseCIDR(p)
		if err != nil {
			return p == ip
		}
		return ipnet.Contains(net.ParseIP(ip))
	}
	// 含通配符(x/*)：按 IPv4 四段匹配
	pp := strings.Split(p, ".")
	ii := strings.Split(ip, ".")
	if len(pp) == 4 && len(ii) == 4 {
		for i := 0; i < 4; i++ {
			if pp[i] == "x" || pp[i] == "*" {
				continue
			}
			if pp[i] != ii[i] {
				return false
			}
		}
		return true
	}
	return p == ip
}

// patternSpecificity 返回 pattern 的"具体度"（值越大越具体，越优先）。
// 精确 IP=4；三段通配如 36.18.x.x=2；二段通配如 36.x.x.x=0；CIDR 按前缀长度折算。
func patternSpecificity(pattern string) int {
	p := strings.TrimSpace(pattern)
	if strings.Contains(p, "/") {
		if _, ipnet, err := net.ParseCIDR(p); err == nil {
			ones, _ := ipnet.Mask.Size()
			return ones
		}
		return 0
	}
	pp := strings.Split(p, ".")
	score := 0
	for _, seg := range pp {
		if seg != "x" && seg != "*" {
			score++
		}
	}
	return score
}

// findCustomTag 在自定义标记中找匹配该 IP 的标记；精确优先、再按具体度降序取最具体一条。
func findCustomTag(custom map[string]IPTag, ip string) (IPTag, bool) {
	best := IPTag{}
	found := false
	bestSpec := -1
	for pattern, tag := range custom {
		if !ipPatternMatch(pattern, ip) {
			continue
		}
		spec := patternSpecificity(pattern)
		if spec > bestSpec {
			best = tag
			bestSpec = spec
			found = true
		}
	}
	return best, found
}

// ResolveIPTag 返回某 IP 的最终标记（手动优先，否则自动；均无返回 false）。
func ResolveIPTag(ip string) (IPTag, bool) {
	tagsMu.Lock()
	custom := loadIPTagsState().Custom
	tagsMu.Unlock()
	if t, ok := findCustomTag(custom, ip); ok {
		return t, true
	}
	return ipTagAuto(ip)
}

// ResolveTagForIP 返回某 IP 命中的标记及其 pattern key（供编辑回填）；无则返回零值。
func ResolveTagForIP(ip string) (IPTag, string) {
	tagsMu.Lock()
	custom := loadIPTagsState().Custom
	tagsMu.Unlock()
	best := IPTag{}
	bestPattern := ""
	bestSpec := -1
	for pattern, tag := range custom {
		if !ipPatternMatch(pattern, ip) {
			continue
		}
		spec := patternSpecificity(pattern)
		if spec > bestSpec {
			best = tag
			bestPattern = pattern
			bestSpec = spec
		}
	}
	return best, bestPattern
}

// ResolveIPTagAll 返回全部 IP→最终标记映射（手动 + 自动合并），供面板一次性注入。
func ResolveIPTagAll() map[string]IPTag {
	out := map[string]IPTag{}
	tagsMu.Lock()
	custom := loadIPTagsState().Custom
	tagsMu.Unlock()
	for ip, tag := range custom {
		out[ip] = tag
	}
	state := loadUsernamesState()
	for _, wl := range state.Whitelist {
		wl = strings.TrimSpace(wl)
		if wl == "" {
			continue
		}
		if _, ok := out[wl]; ok {
			continue
		}
		out[wl] = IPTag{Tag: "白名单", Note: "公钥登录自动放行", Color: "green", Auto: true}
	}
	if _, ok := out["127.0.0.1"]; !ok {
		out["127.0.0.1"] = IPTag{Tag: "本地", Note: "本机回环", Color: "blue", Auto: true}
	}
	if _, ok := out["::1"]; !ok {
		out["::1"] = IPTag{Tag: "本地", Note: "本机回环", Color: "blue", Auto: true}
	}
	for ip := range readBannedSet() {
		if _, ok := out[ip]; ok {
			continue
		}
		out[ip] = IPTag{Tag: "已封禁", Note: "命中封禁规则", Color: "red", Auto: true}
	}
	return out
}

func readBannedSet() map[string]bool {
	set := map[string]bool{}
	b, err := os.ReadFile(banPath())
	if err != nil {
		return set
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] != "" {
			set[fields[0]] = true
		}
	}
	return set
}

// UpsertIPTag 新增或更新自定义标记。
func UpsertIPTag(ip string, tag IPTag) error {
	tagsMu.Lock()
	defer tagsMu.Unlock()
	s := loadIPTagsState()
	s.Custom[ip] = tag
	saveIPTagsState(s)
	return nil
}

// RemoveIPTag 移除自定义标记（不影响自动识别）。
func RemoveIPTag(ip string) error {
	tagsMu.Lock()
	defer tagsMu.Unlock()
	s := loadIPTagsState()
	delete(s.Custom, ip)
	saveIPTagsState(s)
	return nil
}
