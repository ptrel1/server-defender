package handler

import (
	"fmt"
	"strings"

	"server-defender/internal/service"
)

// 本文件：进程监控与自愈收割的 render 片段函数。
// 数据来自 service.ReaperLoop 巡检结果（高CPU进程、收割事件）。

// RenderTopProcsHTML 渲染实时 TOP 负载进程（带一键终止按钮）。
func RenderTopProcsHTML() string {
	procs := service.HighCPUProcesses(6)
	var sb strings.Builder
	if len(procs) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>系统运行平稳，无高负载异常进程</span></div>"
	}
	sb.WriteString("<table><tr><th>PID</th><th>用户</th><th>%CPU</th><th>运行时长</th><th>命令</th><th>操作</th></tr>")
	for _, p := range procs {
		cls := "tag-success"
		if p.CPU >= 50.0 {
			cls = "tag-danger"
		} else if p.CPU >= 20.0 {
			cls = "tag-warning"
		}
		fmt.Fprintf(&sb, "<tr><td><b>%d</b></td><td>%s</td><td><span class=\"tag %s\">%.1f%%</span></td><td class=\"time-cell\">%s</td><td title=\"%s\" style=\"color:var(--text-primary)\">%s</td><td><button class=\"btn-terminate\" onclick=\"doKillProcess(%d, '%s')\">终止</button></td></tr>",
			p.PID, p.User, cls, p.CPU, p.ETime, p.Args, p.Comm, p.PID, p.Comm)
	}
	return sb.String() + "</table>"
}

// RenderReaperEventsHTML 渲染自愈收割战报。
func RenderReaperEventsHTML() string {
	events := service.LoadReaperEvents()
	var sb strings.Builder
	if len(events) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>系统自愈引擎正常，无失控孤儿进程</span></div>"
	}
	sb.WriteString("<table><tr><th>时间</th><th>PID</th><th>命令</th><th>收割原因</th></tr>")
	for i, ev := range events {
		if i >= 8 {
			break
		}
		fmt.Fprintf(&sb, "<tr><td class=\"time-cell\">%s</td><td>%d</td><td style=\"color:var(--text-primary)\"><b>%s</b></td><td><span class=\"tag tag-warning\">%s</span></td></tr>",
			ev.Time, ev.PID, ev.Comm, ev.Reason)
	}
	return sb.String() + "</table>"
}