// Package handler 提供 Web 面板各板块的采集与 HTML 片段渲染。
// 路由装配在 main 包，本包只负责单板块数据与渲染，保持职责单一。
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"server-defender/internal/service"
)

// JSON 辅助函数（供 main 包使用）

// WriteJSON 输出 JSON 响应。
func WriteJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// DecodeJSON 解析请求体 JSON。
func DecodeJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// DashboardData 聚合所有板块数据，返回给前端 /api/data。
// 该函数被 main 包的路由处理器调用。
func DashboardData(includeVirtual bool) map[string]interface{} {
	sshd, frpsF2B := Fail2banStatus()
	lastb := GetLastbStats()
	unames := UsernameBans()
	_ = service.HighCPUProcesses(6) // procs 无独立字段，通过 render 片段输出
	reaperEvents := service.LoadReaperEvents()
	nics := service.NicRateStats(includeVirtual)
	conn := service.ConnStatsSnapshot()
	_ = service.CheckAlerts(conn, nics) // 触发告警判定并持久化
	allAlerts := service.LoadAlerts()

	var netTotalRX, netTotalTX float64
	for _, n := range nics {
		if n.Physical {
			netTotalRX += n.RXRate
			netTotalTX += n.TXRate
		}
	}

	return map[string]interface{}{
		// 安全板块 (KPI)
		"total_attacks":         lastb.Total,
		"f2b_banned_count":      sshd.BannedCount,
		"f2b_total_banned":      sshd.TotalBanned,
		"frps_f2b_banned_count": frpsF2B.BannedCount,
		"frps_f2b_total_banned": frpsF2B.TotalBanned,
		"unames_count":          len(unames),
		"reaper_count":          len(reaperEvents),
		// HTML 片段
		"f2b_html":           RenderF2BHTML(sshd, "sshd"),
		"frps_f2b_html":      RenderF2BHTML(frpsF2B, "frps"),
		"top_ips_html":       RenderTopIPsHTML(lastb.TopIPs),
		"top_users_html":     RenderTopUsersHTML(lastb.TopUsers),
		"recent_html":        RenderRecentHTML(lastb.Recent),
		"unames_html":        RenderUsernamesHTML(unames),
		"foreign_bans_count": countForeignBans(unames),
		"foreign_bans_html":  RenderForeignBansHTML(unames),
		"region_agg_html":    RenderRegionAggHTML(unames),
		"top_procs_html":     RenderTopProcsHTML(),
		"reaper_events_html": RenderReaperEventsHTML(),
		"calendar":           service.AttackCalendar(90, lastb.Total), // 攻击日历热力图(近90天)
		// NetMon
		"net_total_rx":     netTotalRX,
		"net_total_tx":     netTotalTX,
		"nics_html":        RenderNicsHTML(nics),
		"alerts_html":      RenderNetAlertsHTML(),
		"alerts_count":     len(allAlerts),
		"net_top_ips_html": RenderNetTopIPsHTML(conn.TopIPs),
		"net_states_html":  RenderNetStatesHTML(conn.States),
		"net_listens_html": RenderNetListensHTML(service.ListenPorts()),
		"frps_html":        RenderFrpsHTML(),
		// 历史趋势 (最近24h)
		"history": recentHistory(),
		// 时间
		"time": time.Now().Format("2006-01-02 15:04:05"),
	}
}

// ExportBansCSV 导出当前封禁列表为 CSV（月度安全报告用）。
func ExportBansCSV(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=bans_"+time.Now().Format("20060102")+".csv")
	w.Write([]byte("\ufeffip,归属地,触发规则,时间\n"))
	for _, b := range UsernameBans() {
		row := fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\"\n", b.IP, b.Location, b.Reason, b.Time)
		w.Write([]byte(row))
	}
}

// recentHistory 返回最近 24 小时的历史采样点（供折线图）。
func recentHistory() []service.HistoryPoint {
	all := service.GetHistoryPoints()
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	result := make([]service.HistoryPoint, 0, len(all))
	for _, p := range all {
		if p.Ts >= cutoff {
			result = append(result, p)
		}
	}
	return result
}
