package handler

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"server-defender/internal/service"
)

// 本文件：读当前封禁列表(perm_ban.txt)渲染永久封禁卡片。
// 数据由 service.UsernamesLoop 后台协程写入。

// UsernameBan 面板展示的一行永久封禁。
type UsernameBan struct {
	IP, Reason, Time, Location string
}

// UsernameBans 读取 perm_ban.txt。
func UsernameBans() []UsernameBan {
	b, err := os.ReadFile(service.BanFilePath())
	if err != nil {
		return []UsernameBan{}
	}
	bans := []UsernameBan{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		ban := UsernameBan{IP: "-", Reason: "-", Time: "-", Location: "-"}
		if len(parts) > 0 {
			ban.IP = parts[0]
		}
		if len(parts) > 1 {
			ban.Reason = parts[1]
		}
		if len(parts) > 2 {
			ban.Time = parts[2]
		}
		if len(parts) > 3 {
			ban.Location = parts[3]
		}
		bans = append(bans, ban)
	}
	return bans
}

// RenderUsernamesHTML 渲染「用户名风暴封禁」卡片（仅境内 IP 爆破类）。
func RenderUsernamesHTML(bans []UsernameBan) string {
	var storm []UsernameBan
	for _, b := range bans {
		if !strings.Contains(b.Reason, "境外") {
			storm = append(storm, b)
		}
	}
	if len(storm) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>无国内 IP 用户名风暴记录</span></div>"
	}
	return renderBanTable(storm)
}

// RenderForeignBansHTML 渲染「境外 IP 阻断」主表。
func RenderForeignBansHTML(bans []UsernameBan) string {
	var foreign []UsernameBan
	for _, b := range bans {
		if strings.Contains(b.Reason, "境外") {
			foreign = append(foreign, b)
		}
	}
	if len(foreign) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无境外拦截记录</span></div>"
	}
	return renderBanTable(foreign)
}

// RenderRegionAggHTML 渲染境外封禁的归属地聚合筛选条。
// 设计心理学：帕累托法则——只平铺 Top5 高频地区，长尾折叠进「其他 N 个地区」，
// 避免聚合条自身成为过载区；去掉冗余迷你条形符号，数字即大小编码。
func RenderRegionAggHTML(bans []UsernameBan) string {
	counts := map[string]int{}
	order := []string{}
	foreign := 0
	for _, b := range bans {
		if !strings.Contains(b.Reason, "境外") {
			continue
		}
		foreign++
		r := shortRegion(b.Location)
		if r == "" || r == "-" || r == "未知" {
			r = "未知"
		}
		if counts[r] == 0 {
			order = append(order, r)
		}
		counts[r]++
	}
	if foreign == 0 {
		return ""
	}
	sort.Slice(order, func(i, j int) bool { return counts[order[i]] > counts[order[j]] })

	const topN = 5
	var sb strings.Builder
	sb.WriteString("<div class=\"region-agg\" id=\"region-agg\">")
	fmtF(&sb, "<span class=\"region-chip active\" data-region=\"*\" onclick=\"filterRegion('*')\">全部 %d</span>", foreign)

	for i, r := range order {
		short := r
		runes := []rune(short)
		titleAttr := ""
		if len(runes) > 10 {
			short = string(runes[:10]) + "…"
			titleAttr = fmt.Sprintf(" title=\"%s\"", r)
		}
		if i >= topN {
			fmtF(&sb, "<span class=\"region-chip region-extra\" data-region=\"%s\"%s style=\"display:none\" onclick=\"filterRegion(this.dataset.region)\">%s %d</span>", r, titleAttr, short, counts[r])
		} else {
			fmtF(&sb, "<span class=\"region-chip\" data-region=\"%s\"%s onclick=\"filterRegion(this.dataset.region)\">%s %d</span>", r, titleAttr, short, counts[r])
		}
	}

	if extra := len(order) - topN; extra > 0 {
		extraN := 0
		for _, r := range order[topN:] {
			extraN += counts[r]
		}
		fmtF(&sb, "<span class=\"region-chip region-toggle\" onclick=\"toggleRegionExtra(true)\">其他 %d 个地区 · %d ▾</span>", extra, extraN)
		sb.WriteString("<span class=\"region-chip region-collapse\" style=\"display:none\" onclick=\"toggleRegionExtra(false)\">收起 ▴</span>")
	}
	sb.WriteString("</div>")
	return sb.String()
}

// countForeignBans 统计境外拦截条数。
func countForeignBans(bans []UsernameBan) int {
	n := 0
	for _, b := range bans {
		if strings.Contains(b.Reason, "境外") {
			n++
		}
	}
	return n
}

// shortRegion 压缩超长归属地为地区主体名。
func shortRegion(loc string) string {
	loc = strings.TrimSpace(loc)
	// "美国加利福尼亚州洛杉矶Level3通信(DIA)" → 取国家部分已由 geo 层保证较长，这里再做显示级截断的取前缀逻辑交给前端；
	// 服务端仅剥离括号备注与运营商尾巴常见词。
	for _, cut := range []string{"Google云计算数据中心", "云计算数据中心", "Level3通信(DIA)", "(DIA)", "社会保险安全部"} {
		loc = strings.ReplaceAll(loc, cut, "")
	}
	return loc
}

func renderBanTable(list []UsernameBan) string {
	var sb strings.Builder
	sb.WriteString("<table><tr><th>#</th><th>来源 IP</th><th>归属地</th><th>触发规则</th><th>时间</th></tr>")
	for i, b := range list {
		cls := "tag-danger"
		reason := b.Reason
		if idx := strings.Index(reason, "("); idx > 0 && strings.HasPrefix(reason, "境外IP拦截") {
			reason = reason[idx+1 : len(reason)-1]
		} else if strings.Contains(reason, "不同账号数") {
			cls = "tag-warning"
			reason = "账号风暴"
		}
		loc := b.Location
		runes := []rune(loc)
		titleAttr := ""
		if len(runes) > 12 {
			loc = string(runes[:12]) + "…"
			titleAttr = fmt.Sprintf(" title=\"%s\"", b.Location)
		}
		fmtF(&sb, "<tr class=\"ban-row\" data-region=\"%s\"><td>%d</td><td class=\"ip-cell\">%s</td><td%s style=\"color:var(--text-primary)\">%s</td><td><span class=\"tag %s\">%s</span></td><td class=\"time-cell\">%s</td></tr>",
			shortRegion(loc), i+1, b.IP, titleAttr, loc, cls, reason, b.Time)
	}
	return sb.String() + "</table>"
}

// 便捷格式化，避免每处 import fmt。
func fmtF(b *strings.Builder, format string, a ...interface{}) {
	b.WriteString(sprintf(format, a...))
}

func sprintf(format string, a ...interface{}) string {
	return service.Sprintf(format, a...)
}