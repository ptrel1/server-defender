package handler

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"server-defender/internal/service"
)

// 本文件：fail2ban / iptables / lastb / dmesg 采集 + 对应 render 片段函数。
// 与 app.py 的 get_fail2ban_status / get_iptables_blocked / get_syn_flood /
// get_lastb_stats 及 render_* 对齐。

// Shell 包装：执行命令返回 stdout。
func sh(cmd string, args ...string) string {
	out, err := exec.Command(cmd, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// F2BInfo 描述一个 fail2ban jail 状态。
type F2BInfo struct {
	BannedCount int
	TotalBanned int
	TotalFailed int
	BannedList  []string
}

// Fail2banStatus 读取 sshd 与 frps-ssh 两个 jail 的状态。
func Fail2banStatus() (sshd, frps F2BInfo) {
	sshd = parseF2BJail("sshd")
	frps = parseF2BJail("frps-ssh")
	return
}

func parseF2BJail(jail string) F2BInfo {
	var info F2BInfo
	out := sh("fail2ban-client", "status", jail)
	if out == "" {
		return info
	}
	if m := regexp.MustCompile(`Banned IP list:\s*(.*)`).FindStringSubmatch(out); m != nil {
		info.BannedList = strings.Fields(m[1])
	}
	if m := regexp.MustCompile(`Total banned:\s*(\d+)`).FindStringSubmatch(out); m != nil {
		fmt.Sscanf(m[1], "%d", &info.TotalBanned)
	}
	if m := regexp.MustCompile(`Total failed:\s*(\d+)`).FindStringSubmatch(out); m != nil {
		fmt.Sscanf(m[1], "%d", &info.TotalFailed)
	}
	info.BannedCount = len(info.BannedList)
	return info
}

// IPTABLES 封禁列表。
type BlockedIP struct {
	Num  string
	Pkts string
	Src  string
}

func IptablesBlocked() []BlockedIP {
	out := sh("iptables", "-L", "INPUT", "-v", "-n", "--line-numbers")
	blk := []BlockedIP{}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "DROP") || strings.Contains(line, "REJECT") {
			parts := strings.Fields(line)
			if len(parts) >= 9 {
				if parts[8] != "0.0.0.0/0" {
					blk = append(blk, BlockedIP{Num: parts[0], Pkts: parts[1], Src: parts[8]})
				}
			}
		}
	}
	return blk
}

// SynEntry SYN Flood 内核日志条目。
type SynEntry struct {
	Time string
	Port string
}

func SynFlood() []SynEntry {
	out := sh("dmesg", "-T")
	entries := []SynEntry{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "SYN flood") && !strings.Contains(line, "possible SYN flooding") {
			continue
		}
		entry := SynEntry{Time: "Recently", Port: "Unknown"}
		if m := regexp.MustCompile(`\[(.*?)\]`).FindStringSubmatch(line); m != nil {
			entry.Time = m[1]
		}
		if m := regexp.MustCompile(`port (\d+)`).FindStringSubmatch(line); m != nil {
			entry.Port = m[1]
		}
		entries = append(entries, entry)
	}
	return entries
}

type LastbStats struct {
	Total    int
	TopIPs   []TopCounter
	TopUsers []TopCounter
	Recent   []RecentEntry
}

type TopCounter struct {
	Name  string
	Count int
}

type RecentEntry struct {
	User string
	IP   string
}

func GetLastbStats() LastbStats {
	out := sh("lastb", "-n", "300")
	var st LastbStats
	ipCount := map[string]int{}
	userCount := map[string]int{}
	topIPs := []TopCounter{}
	topUsers := []TopCounter{}
	recent := []RecentEntry{}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" || strings.Contains(line, "btmp begins") {
			continue
		}
		st.Total++
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			user := parts[0]
			ip := parts[2]
			userCount[user]++
			if ip != "127.0.0.1" && ip != "::1" && ip != "0.0.0.0" && ip != "localhost" {
				ipCount[ip]++
			}
			if len(recent) < 10 {
				recent = append(recent, RecentEntry{User: user, IP: ip})
			}
		}
	}
	topIPs = sortCounters(ipCount, 8)
	topUsers = sortCounters(userCount, 8)
	return LastbStats{Total: st.Total, TopIPs: topIPs, TopUsers: topUsers, Recent: recent}
}

func sortCounters(m map[string]int, limit int) []TopCounter {
	items := make([]TopCounter, 0, len(m))
	for k, v := range m {
		items = append(items, TopCounter{Name: k, Count: v})
	}
	// 简单选择排序（数据量小，避免引入排序包依赖）
	for i := 0; i < len(items) && i < limit; i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].Count > items[i].Count {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

// ---------- render 片段函数 (对齐 app.py render_*) ----------

func tagDangerCls(count int) string {
	if count >= 50 {
		return "tag-danger"
	}
	if count >= 10 {
		return "tag-warning"
	}
	return "tag-blue"
}

func RenderF2BHTML(f F2BInfo, jailLabel string) string {
	if len(f.BannedList) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无动态封禁 IP</span></div>"
	}
	var sb strings.Builder
	fastLoc := func(ip string) string {
		loc, ok := service.QueryGeoFast(ip)
		if !ok {
			return "查询中…"
		}
		return loc
	}
	if jailLabel == "frps" {
		sb.WriteString("<table><tr><th>#</th><th>IP 地址</th><th>归属地</th><th>防护状态</th></tr>")
		for i, ip := range f.BannedList {
			fmt.Fprintf(&sb, "<tr><td>%d</td><td class=\"ip-cell\">%s</td><td style=\"color:var(--text-secondary)\">%s</td><td><span class=\"tag tag-warning\">隧道隔离中</span></td></tr>", i+1, ip, fastLoc(ip))
		}
	} else {
		sb.WriteString("<table><tr><th>#</th><th>IP 地址</th><th>归属地</th><th>状态</th></tr>")
		for i, ip := range f.BannedList {
			fmt.Fprintf(&sb, "<tr><td>%d</td><td class=\"ip-cell\">%s</td><td style=\"color:var(--text-secondary)\">%s</td><td><span class=\"tag tag-danger\">封禁中</span></td></tr>", i+1, ip, fastLoc(ip))
		}
	}
	return sb.String() + "</table>"
}

func RenderTopIPsHTML(tops []TopCounter) string {
	if len(tops) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无高频攻击记录</span></div>"
	}
	var sb strings.Builder
	sb.WriteString("<table><tr><th>#</th><th>攻击来源 IP</th><th>归属地</th><th>探测次数</th></tr>")
	for i, item := range tops {
		loc, ok := service.QueryGeoFast(item.Name)
		if !ok {
			loc = "查询中…"
		}
		fmt.Fprintf(&sb, "<tr><td>%d</td><td class=\"ip-cell\">%s</td><td style=\"color:var(--text-secondary)\">%s</td><td><span class=\"tag %s\">%d 次</span></td></tr>",
			i+1, item.Name, loc, tagDangerCls(item.Count), item.Count)
	}
	return sb.String() + "</table>"
}

func RenderTopUsersHTML(users []TopCounter) string {
	if len(users) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无记录</span></div>"
	}
	var sb strings.Builder
	sb.WriteString("<table><tr><th>#</th><th>被尝试账号</th><th>探测频次</th></tr>")
	for i, item := range users {
		fmt.Fprintf(&sb, "<tr><td>%d</td><td class=\"user-cell\">%s</td><td><span class=\"tag %s\">%d 次</span></td></tr>",
			i+1, item.Name, tagDangerCls(item.Count), item.Count)
	}
	return sb.String() + "</table>"
}

func RenderRecentHTML(recent []RecentEntry) string {
	if len(recent) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无攻击记录</span></div>"
	}
	var sb strings.Builder
	sb.WriteString("<table><tr><th>#</th><th>尝试账号</th><th>来源 IP</th><th>归属地</th></tr>")
	for i, r := range recent {
		loc, ok := service.QueryGeoFast(r.IP)
		if !ok {
			loc = "查询中…"
		}
		fmt.Fprintf(&sb, "<tr><td>%d</td><td class=\"user-cell\">%s</td><td class=\"ip-cell\">%s</td><td style=\"color:var(--text-secondary)\">%s</td></tr>", i+1, r.User, r.IP, loc)
	}
	return sb.String() + "</table>"
}