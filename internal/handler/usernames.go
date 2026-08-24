package handler

import (
	"os"
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

// RenderUsernamesHTML 渲染境外拦截与用户名封禁卡片。
func RenderUsernamesHTML(bans []UsernameBan) string {
	if len(bans) == 0 {
		return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>系统平稳，暂无永久封禁 IP</span></div>"
	}
	var sb strings.Builder
	sb.WriteString("<table><tr><th>#</th><th>来源 IP</th><th>拦截策略 / 原因</th><th>归属地</th><th>时间</th></tr>")
	for i, b := range bans {
		cls := "tag-danger"
		if !strings.Contains(b.Reason, "境外") {
			cls = "tag-warning"
		}
		loc := b.Location
		fmtF(&sb, "<tr><td>%d</td><td class=\"ip-cell\">%s</td><td><span class=\"tag %s\">%s</span></td><td style=\"color:var(--text-primary)\">%s</td><td class=\"time-cell\">%s</td></tr>",
			i+1, b.IP, cls, b.Reason, loc, b.Time)
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