package handler

import (
	"fmt"
	"strings"

	"server-defender/internal/service"
)

// 本文件：网络监控 (NetMon) 各板块的 render 片段函数。
// 数据从 service 层获取，输出与 Python 版一致的 HTML 片段。

// RenderNicsHTML 渲染网卡实时流量列表。
func RenderNicsHTML(nics []service.NicStats) string {
	var sb strings.Builder
	if len(nics) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">🔌</div><span>未检测到网卡</span></div>"
	}
	for _, n := range nics {
		cls := ""
		if !n.Physical {
			cls = "nic-virtual"
		}
		label := n.Name
		if !n.Physical {
			label = "· " + n.Name
		}
		fmt.Fprintf(&sb, "<div class=\"nic-row %s\"><span style=\"font-family:'JetBrains Mono',monospace;color:var(--text-primary)\">%s</span><span style=\"color:var(--text-secondary)\">入 %s / 出 %s</span></div>",
			cls, label, byteFmt(n.RXBytes), byteFmt(n.TXBytes))
	}
	return sb.String() + "<div class=\"nic-row\" style=\"font-size:11px;color:var(--text-muted);border-bottom:none;\">点击右上角按钮切换物理/全部网卡视图</div>"
}

// byteFmt 将 uint64 字节数格式化为人类可读。
func byteFmt(n uint64) string {
	return service.FmtBytes(float64(n))
}

// RenderNetAlertsHTML 渲染异常告警条。
func RenderNetAlertsHTML() string {
	alerts := service.LoadAlerts()
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
		sb.WriteString("<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>网络状态平稳，无异常告警</span></div>")
	}
	return sb.String()
}

// RenderNetTopIPsHTML 渲染 TOP 对端 IP（含归属地）。
func RenderNetTopIPsHTML(tops []service.TopIP) string {
	if len(tops) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">🌐</div><span>暂无外部连接</span></div>"
	}
	var sb strings.Builder
	sb.WriteString("<table><tr><th>#</th><th>对端 IP</th><th>归属地</th><th>连接数</th><th>端口数</th></tr>")
	for i, item := range tops {
		if i >= 8 {
			break
		}
		loc := service.QueryGeo(item.IP).Location
		cls := "tag-danger"
		if item.Count < 80 {
			cls = "tag-warning"
		}
		if item.Count < 20 {
			cls = "tag-blue"
		}
		fmt.Fprintf(&sb, "<tr><td>%d</td><td class=\"ip-cell\">%s</td><td style=\"color:var(--text-secondary)\">%s</td><td><span class=\"tag %s\">%d</span></td><td class=\"time-cell\">%d</td></tr>",
			i+1, item.IP, loc, cls, item.Count, item.Ports)
	}
	return sb.String() + "</table>"
}

// RenderNetStatesHTML 渲染 TCP 状态分布。
func RenderNetStatesHTML(states []service.ConnStates) string {
	var sb strings.Builder
	if len(states) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">🔀</div><span>暂无连接</span></div>"
	}
	sb.WriteString("<div class=\"state-flex\">")
	for _, s := range states {
		cls := "tag-blue"
		if s.Name == "SYN-RECV" || s.Name == "SYN-SENT" || s.Name == "LAST-ACK" {
			cls = "tag-danger"
		}
		fmt.Fprintf(&sb, "<div class=\"state-chip\"><span class=\"tag %s\">%s</span><span style=\"font-family:'JetBrains Mono',monospace;color:var(--text-primary)\">%d</span></div>",
			cls, s.Name, s.Count)
	}
	sb.WriteString("</div>")
	return sb.String()
}

// RenderNetListensHTML 渲染监听端口。
func RenderNetListensHTML(listens []service.ListenPort) string {
	var sb strings.Builder
	if len(listens) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">⌛</div><span>数据加载中...</span></div>"
	}
	sb.WriteString("<table><tr><th>端口</th><th>监听地址</th><th>进程</th></tr>")
	for i, item := range listens {
		if i >= 20 {
			break
		}
		proc := item.Process
		if proc == "" {
			proc = "-"
		}
		fmt.Fprintf(&sb, "<tr><td><span class=\"tag tag-blue\">%d</span></td><td style=\"color:var(--text-secondary)\">%s</td><td style=\"color:var(--text-primary)\">%s</td></tr>",
			item.Port, item.Addr, proc)
	}
	return sb.String() + "</table>"
}

// RenderFrpsHTML 渲染 frps 隧道流量。
func RenderFrpsHTML() string {
	data := service.FrpsTraffic()
	available, _ := data["available"].(bool)
	if !available {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">🔌</div><span>本机未运行 frps 服务端（隧道统计仅公网机可见）</span></div>"
	}
	proxies, _ := data["proxies"].([]map[string]interface{})
	var sb strings.Builder
	if len(proxies) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无活跃隧道</span></div>"
	}
	// 按总流量排序(简单选择)
	for i := 0; i < len(proxies) && i < 15; i++ {
		for j := i + 1; j < len(proxies); j++ {
			ti, _ := proxies[j]["traffic_in"].(float64)
			to, _ := proxies[j]["traffic_out"].(float64)
			ti2, _ := proxies[i]["traffic_in"].(float64)
			to2, _ := proxies[i]["traffic_out"].(float64)
			if ti+to > ti2+to2 {
				proxies[i], proxies[j] = proxies[j], proxies[i]
			}
		}
	}
	sb.WriteString("<table><tr><th>隧道名</th><th>类型</th><th>入站流量</th><th>出站流量</th></tr>")
	for _, p := range proxies {
		name, _ := p["name"].(string)
		typ, _ := p["type"].(string)
		ti, _ := p["traffic_in"].(float64)
		to, _ := p["traffic_out"].(float64)
		fmt.Fprintf(&sb, "<tr><td style=\"color:var(--text-primary)\"><b>%s</b></td><td><span class=\"tag tag-blue\">%s</span></td><td style=\"font-family:'JetBrains Mono',monospace\">%s</td><td style=\"font-family:'JetBrains Mono',monospace\">%s</td></tr>",
			name, typ, service.FmtBytes(ti), service.FmtBytes(to))
	}
	return sb.String() + "</table>"
}