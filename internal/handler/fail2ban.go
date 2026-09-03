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
	// 双向封禁展示（20260831）：INPUT(-s 封入) + OUTPUT(-d 封出)，出向行目的地址在第 9 列
	seen := map[string]bool{}
	blk := []BlockedIP{}
	chains := []struct{ name, dir string }{{"INPUT", "in"}, {"OUTPUT", "out"}}
	for _, ch := range chains {
		out := sh("iptables", "-L", ch.name, "-v", "-n", "--line-numbers")
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "DROP") && !strings.Contains(line, "REJECT") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 9 {
				continue
			}
			// INPUT 行 parts[8] 为源地址；OUTPUT 行 parts[8] 为目的地址
			if parts[8] == "0.0.0.0/0" {
				continue
			}
			key := ch.dir + ":" + parts[8]
			if seen[key] {
				continue
			}
			seen[key] = true
			blk = append(blk, BlockedIP{Num: parts[0], Pkts: parts[1], Src: parts[8] + "(" + ch.dir + ")"})
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
	Last  string // 该IP最后一次探测时间(事件流/TOP展示用)
}

type RecentEntry struct {
	User string
	IP   string
	Time string // 该次尝试发生时间
}

// 月名→数字短码，用于 lastb 时间格式化为 月-日 时:分
var lastbMonthShort = map[string]string{
	"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
	"Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}

// parseLastbTime 从 lastb 行 parts 提取可读时间。lastb 行格式:
//
//	user tty IP Mon dd hh:mm - hh:mm (00:00)
//
// parts[4]=月 parts[5]=日 parts[6]=起始hh:mm
func parseLastbTime(parts []string) string {
	if len(parts) < 7 {
		return ""
	}
	mon := lastbMonthShort[parts[4]]
	day := parts[5]
	if len(day) == 1 {
		day = "0" + day
	}
	return mon + "-" + day + " " + parts[6]
}

func GetLastbStats() LastbStats {
	out := sh("lastb", "-n", "300")
	var st LastbStats
	ipCount := map[string]int{}
	userCount := map[string]int{}
	ipLast := map[string]string{} // ip -> 最后探测时间
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
			ts := parseLastbTime(parts)
			userCount[user]++
			if ip != "127.0.0.1" && ip != "::1" && ip != "0.0.0.0" && ip != "localhost" {
				ipCount[ip]++
				// 记录该 IP 最后一次探测时间（lastb 按时间倒序，首个出现即最近）
				if _, seen := ipLast[ip]; !seen && ts != "" {
					ipLast[ip] = ts
				}
			}
			if len(recent) < 10 {
				recent = append(recent, RecentEntry{User: user, IP: ip, Time: ts})
			}
		}
	}
	// 把每个 IP 的最后时间并入 TopCounter
	topIPs = sortCounters(ipCount, 8)
	for i := range topIPs {
		topIPs[i].Last = ipLast[topIPs[i].Name]
	}
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
	sb.WriteString("<table><tr><th>#</th><th>攻击来源 IP</th><th>归属地</th><th>目标端口</th><th>探测次数</th><th>最近活跃</th></tr>")
	for i, item := range tops {
		loc, ok := service.QueryGeoFast(item.Name)
		if !ok {
			loc = "查询中…"
		}
		last := item.Last
		if last == "" {
			last = "-"
		}
		fmt.Fprintf(&sb, "<tr><td>%d</td><td class=\"ip-cell\">%s%s</td><td style=\"color:var(--text-secondary)\">%s</td><td><span class=\"tag tag-blue\">%s</span></td><td><span class=\"tag %s\">%d 次</span></td><td class=\"time-cell\">%s</td></tr>",
			i+1, item.Name, IPTagBadgeHTML(item.Name), loc, service.AttackedPortsLabel(item.Name), tagDangerCls(item.Count), item.Count, last)
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
	sb.WriteString("<table><tr><th>#</th><th>时间</th><th>尝试账号</th><th>来源 IP</th><th>目标端口</th><th>归属地</th></tr>")
	for i, r := range recent {
		loc, ok := service.QueryGeoFast(r.IP)
		if !ok {
			loc = "查询中…"
		}
		ts := r.Time
		if ts == "" {
			ts = "-"
		}
		fmt.Fprintf(&sb, "<tr><td>%d</td><td class=\"time-cell\">%s</td><td class=\"user-cell\">%s</td><td class=\"ip-cell\">%s%s</td><td><span class=\"tag tag-blue\">%s</span></td><td style=\"color:var(--text-secondary)\">%s</td></tr>", i+1, ts, r.User, r.IP, IPTagBadgeHTML(r.IP), service.AttackedPortsLabel(r.IP), loc)
	}
	return sb.String() + "</table>"
}
