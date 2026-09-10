package handler

import (
	"fmt"
	"strings"

	"server-defender/internal/service"
)

// 本文件：配置哨兵（A 层配置变更扫描 + B 层出站连接哨兵）面板渲染与路由。
// 设计意图：把「dsh2shell 类注入」从 3~6 天的人肉发现压缩到 5 分钟内告警+自动封禁。
// 展示分两块：命中记录表（含自动封禁动作）与可疑出站连接表（只告警）。

func RenderSentinelHTML() string {
	s := service.SentinelSnapshotView()
	var b strings.Builder
	b.WriteString("<table><tr><th>时间</th><th>文件</th><th>命中规则</th><th>C2</th><th>说明</th></tr>")
	if len(s.Records) == 0 {
		b.WriteString(`<tr><td colspan="5" style="color:var(--text-secondary)">暂无命中记录（基线监控中）</td></tr>`)
	}
	for i := len(s.Records) - 1; i >= 0 && i >= len(s.Records)-30; i-- {
		r := s.Records[i]
		danger := ""
		if len(r.Rules) > 0 && r.Rules[0] != "read-fail" {
			danger = ` class="text-danger"`
		}
		b.WriteString(fmt.Sprintf("<tr%s><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			danger, r.Time, shortPath(r.File), strings.Join(r.Rules, ", "), r.IP, r.Note))
	}
	b.WriteString("</table>")
	return b.String()
}

func RenderOutboundHTML() string {
	s := service.SentinelSnapshotView()
	var b strings.Builder
	b.WriteString("<table><tr><th>时间</th><th>远端</th><th>连接数</th><th>原因</th></tr>")
	if len(s.Outbound) == 0 {
		b.WriteString(`<tr><td colspan="4" style="color:var(--text-secondary)">无可疑出站连接</td></tr>`)
	}
	for i := len(s.Outbound) - 1; i >= 0 && i >= len(s.Outbound)-30; i-- {
		r := s.Outbound[i]
		b.WriteString(fmt.Sprintf(`<tr class="text-warning"><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>`,
			r.Time, r.Remote, r.Conns, r.Reason))
	}
	b.WriteString("</table>")
	return b.String()
}

func shortPath(p string) string {
	if i := strings.Index(p, "/.dsh/"); i >= 0 {
		return "~" + p[i:]
	}
	return p
}
