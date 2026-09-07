package handler

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"server-defender/internal/service"
)

// 本文件：域名访问监控 (WebMon) 的数据组装与 HTML 片段渲染。
// 数据从 service.GetWebMonSnapshot 获取；趋势折线在前端用 Chart.js 绘制。

// webmonDomainColors 折线配色（与面板 Apple 风格色板一致）。
var webmonDomainColors = map[string]string{
	"dsh.ptrel.cc.cd":  "#0a84ff",
	"dsh2.ptrel.cc.cd": "#30d158",
}

// webmonDomainTitle 域名 → 实例角色副标题。新增监控域名缺省用「今日请求数」。
var webmonDomainTitle = map[string]string{
	"dsh.ptrel.cc.cd":  "主实例今日请求数",
	"dsh2.ptrel.cc.cd": "救援实例今日请求数",
}

// webmonFallbackOrder 兜底显示顺序：仅当无任何桶/今日数据时用于防空白页，
// 不再作为展示顺序依据——展示顺序一律按「今日请求数降序」动态计算（不写死）。
var webmonFallbackOrder = []string{"dsh.ptrel.cc.cd", "dsh2.ptrel.cc.cd"}

// WebMonData 组装 /api/webmon 返回数据。
func WebMonData() map[string]interface{} {
	snap := service.GetWebMonSnapshot()

	// ---- 按「今日请求数降序」动态决定域名展示顺序（替代硬编码 dsh→dsh2 固定次序）----
	domainStats := webmonDomainStats(&snap)

	// ---- 趋势折线：合并各域名的桶时间轴，保证各条线 x 轴对齐 ----
	tsSet := map[int64]bool{}
	for _, bs := range snap.Buckets {
		for _, b := range bs {
			if time.Since(time.Unix(b.Ts, 0)) < 24*time.Hour {
				tsSet[b.Ts] = true
			}
		}
	}
	tsList := make([]int64, 0, len(tsSet))
	for ts := range tsSet {
		tsList = append(tsList, ts)
	}
	sort.Slice(tsList, func(i, j int) bool { return tsList[i] < tsList[j] })

	labels := make([]string, 0, len(tsList))
	for _, ts := range tsList {
		labels = append(labels, time.Unix(ts, 0).Format("01-02 15:04"))
	}
	// dataset 顺序与卡片一致：均来自 webmonDomainStats（今日请求数降序）。
	datasets := make([]map[string]interface{}, 0, len(domainStats))
	for _, ds := range domainStats {
		domain := ds["domain"].(string)
		idx := map[int64]int64{}
		for _, b := range snap.Buckets[domain] {
			idx[b.Ts] = b.Count
		}
		counts := make([]int64, 0, len(tsList))
		for _, ts := range tsList {
			counts = append(counts, idx[ts])
		}
		datasets = append(datasets, map[string]interface{}{
			"label": domain, "data": counts, "color": ds["color"],
		})
	}

	return map[string]interface{}{
		"today_requests": snap.TodayRequests,
		"today_ips":      snap.TodayIPs,
		"total_requests": snap.TotalRequests,
		"total_ips":      snap.TotalIPs,
		"per_domain":     snap.DomainToday,
		"domain_stats":   domainStats,
		"trend_labels":   labels,
		"trend_datasets": datasets,
		"top_ips_html":   RenderWebMonTopIPsHTML(snap.TopIPs),
		"recent_html":    RenderWebMonRecentHTML(snap.Recent),
		"alerts_html":    RenderWebMonAlertsHTML(),
		"alerts_count":   len(service.LoadWebAlerts()),
		"time":           time.Now().Format("2006-01-02 15:04:05"),
	}
}

// webmonDomainStats 计算按「今日请求数降序」的域名统计，供实例卡片与趋势图共用同一顺序。
// 域名全集 = 24h 趋势桶 + 今日有流量 + 兜底列表；保证低流量日实例仍可见（今日次数为 0）。
// 边界/风险：平列次数时按域名稳定排序，避免每次轮询刷新顺序抖动。
func webmonDomainStats(snap *service.WebMonSnapshot) []map[string]interface{} {
	seen := map[string]bool{}
	order := make([]string, 0, len(snap.Buckets)+len(snap.DomainToday)+len(webmonFallbackOrder))
	add := func(d string) {
		if !seen[d] {
			seen[d] = true
			order = append(order, d)
		}
	}
	for d := range snap.Buckets {
		add(d)
	}
	for d := range snap.DomainToday {
		add(d)
	}
	for _, d := range webmonFallbackOrder {
		add(d)
	}
	sort.Slice(order, func(i, j int) bool {
		ci, cj := snap.DomainToday[order[i]], snap.DomainToday[order[j]]
		if ci != cj {
			return ci > cj // 今日请求数降序 = 最高访问在前
		}
		return order[i] < order[j]
	})
	out := make([]map[string]interface{}, 0, len(order))
	for i, d := range order {
		c, _ := webmonDomainColors[d]
		if c == "" {
			c = webmonDefaultColor(i)
		}
		t, _ := webmonDomainTitle[d]
		if t == "" {
			t = "今日请求数"
		}
		out = append(out, map[string]interface{}{
			"domain": d,
			"count":  snap.DomainToday[d],
			"color":  c,
			"title":  t,
		})
	}
	return out
}

// webmonDefaultColor 超出固定配色的新增域名按序取扩展色（Apple 风格拓展色板）。
func webmonDefaultColor(i int) string {
	palette := []string{"#bf5af2", "#ff9f0a", "#ff375f", "#64d2ff", "#ffd60a", "#ac8e68"}
	return palette[i%len(palette)]
}

// RenderWebMonTopIPsHTML 渲染访问来源 TOP IP 表（含归属地，异常 IP 标红）。
func RenderWebMonTopIPsHTML(tops []service.WebIPStat) string {
	if len(tops) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">🌐</div><span>暂无域名访问记录</span></div>"
	}
	var sb strings.Builder
	sb.WriteString("<table><tr><th>#</th><th>IP</th><th>域名</th><th>归属地</th><th>今日</th><th>4xx</th><th>最近访问</th></tr>")
	for i, st := range tops {
		loc, ok := service.QueryGeoFast(st.IP)
		if !ok {
			loc = "查询中…"
		}
		bad := st.Status["4xx"] + st.Status["5xx"]
		cls := "tag-blue"
		switch {
		case st.Today > 200:
			cls = "tag-danger"
		case st.Today > 50:
			cls = "tag-warning"
		}
		fmt.Fprintf(&sb,
			"<tr><td>%d</td><td class=\"ip-cell\">%s%s</td><td style=\"color:var(--text-secondary)\">%s</td><td style=\"color:var(--text-secondary)\">%s</td>"+
				"<td><span class=\"tag %s\">%d</span></td><td class=\"time-cell\">%s</td><td class=\"time-cell\">%s</td></tr>",
			i+1, st.IP, IPTagBadgeHTML(st.IP), st.Domain, loc, cls, st.Today, statusCell(bad), st.Last)
	}
	return sb.String() + "</table>"
}

// statusCell 状态码概要徽标。
func statusCell(bad int) string {
	if bad == 0 {
		return "-"
	}
	if bad > 50 {
		return fmt.Sprintf("<span class=\"tag tag-danger\">%d</span>", bad)
	}
	return fmt.Sprintf("<span class=\"tag tag-warning\">%d</span>", bad)
}

// RenderWebMonRecentHTML 渲染最近访问记录流（4xx/5xx 高亮）。
func RenderWebMonRecentHTML(recent []service.WebHit) string {
	if len(recent) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">⌛</div><span>暂无访问记录</span></div>"
	}
	var sb strings.Builder
	sb.WriteString("<table><tr><th>时间</th><th>IP</th><th>域名</th><th>请求</th><th>状态</th></tr>")
	// 倒序展示：最新在前
	for i := len(recent) - 1; i >= 0 && i >= len(recent)-20; i-- {
		h := recent[i]
		statusCls := "tag tag-blue"
		if h.Status >= 500 {
			statusCls = "tag tag-danger"
		} else if h.Status >= 400 {
			statusCls = "tag tag-warning"
		}
		summary := h.Method + " " + h.Path
		if len(summary) > 60 {
			summary = summary[:60] + "…"
		}
		fmt.Fprintf(&sb,
			"<tr><td class=\"time-cell\">%s</td><td class=\"ip-cell\">%s%s</td><td style=\"color:var(--text-secondary)\">%s</td>"+
				"<td style=\"font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-primary)\">%s</td><td><span class=\"%s\">%d</span></td></tr>",
			h.Time, h.IP, IPTagBadgeHTML(h.IP), h.Domain, summary, statusCls, h.Status)
	}
	return sb.String() + "</table>"
}

// RenderWebMonAlertsHTML 渲染 WebMon 告警条（最近 5 条）。
func RenderWebMonAlertsHTML() string {
	alerts := service.LoadWebAlerts()
	var sb strings.Builder
	count := 0
	for _, a := range alerts {
		if count >= 5 {
			break
		}
		cls := "tag-danger"
		if a.Level != "danger" {
			cls = "tag-warning"
		}
		fmt.Fprintf(&sb, "<div class=\"net-alert-item\"><span class=\"tag %s\">%s</span><span style=\"color:var(--text-secondary)\">%s</span><span class=\"time-cell\">%s</span></div>",
			cls, a.Title, a.Detail, a.Time)
		count++
	}
	if count == 0 {
		sb.WriteString("<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>访问状态平稳，无异常告警</span></div>")
	}
	return sb.String()
}
