package handler

import (
	"fmt"
	"html"
	"strings"

	"server-defender/internal/service"
)

// frpsSSHInfo 返回当前 frp-ssh 识别状态（供 dashboard 注入字段）。
func frpsSSHInfo() service.FrpsSSHInfo { return service.FrpsSSHInfoNow() }

// RenderFrpsSSHHTML 渲染「frp SSH 隧道自动识别」卡（放防御页）。
// 只展示防御相关：已并入 frps-ssh jail 的 SSH 端口 + 更新时间；端口有效性明细另见 RenderFrpsSSHPortsHTML（放总览）。
func RenderFrpsSSHHTML() string {
	info := service.FrpsSSHInfoNow()
	var b strings.Builder
	b.WriteString(`<div style="display:flex;flex-direction:column;gap:6px;font-size:12px;">`)

	if len(info.Ports) == 0 {
		if info.Err != "" {
			fmt.Fprintf(&b, `<div style="color:#ff5e52">未识别到 SSH 隧道：%s</div>`, html.EscapeString(info.Err))
		} else {
			b.WriteString(`<div style="color:var(--text-muted)">暂未识别到 frp SSH 隧道端口（下次探测后自动更新）</div>`)
		}
	} else {
		b.WriteString(`<div style="color:var(--text-secondary)">已并入 SSH 防御 (frps-ssh) 的隧道端口：</div>`)
		b.WriteString(`<div style="display:flex;flex-wrap:wrap;gap:6px;">`)
		for _, p := range info.Ports {
			fmt.Fprintf(&b, `<span style="background:rgba(255,69,58,.15);color:#ff5e52;border:1px solid rgba(255,69,58,.35);padding:2px 9px;border-radius:6px;font-size:11px;font-weight:600;">:%d</span>`, p)
		}
		b.WriteString(`</div>`)
		b.WriteString(`<div style="color:var(--text-secondary)">→ 逐端口有效性在「总览 · 🔌 frp 隧道端口有效性」查看</div>`)
	}

	b.WriteString(`<div style="color:var(--text-muted);font-size:11px;margin-top:6px;">更新 <span id="frps-ssh-at">-</span> · 下次 <span id="frps-ssh-next">-</span></div>`)
	b.WriteString(`</div>`)
	return b.String()
}

// RenderFrpsSSHPortsHTML 渲染「frp 隧道端口有效性」卡（放总览，与攻击日历同区）。
// 逐端口标注 ssh/tcp/down/skip，纯态势感知展示。
func RenderFrpsSSHPortsHTML() string {
	info := service.FrpsSSHInfoNow()
	var b strings.Builder
	b.WriteString(`<div style="display:flex;flex-direction:column;gap:8px;font-size:12px;">`)

	if len(info.Probes) == 0 {
		if info.Err != "" {
			fmt.Fprintf(&b, `<div style="color:#ffb340">暂无探测结果：%s</div>`, html.EscapeString(info.Err))
		} else {
			b.WriteString(`<div style="color:var(--text-muted)">等待每日探测…</div>`)
		}
	} else {
		b.WriteString(`<div style="display:flex;flex-wrap:wrap;gap:6px;">`)
		for _, pr := range info.Probes {
			color, label := "#52dc74", "ssh"
			switch pr.Kind {
			case service.KindSSH:
				color, label = "#ff5e52", "ssh"
			case service.KindTCP:
				color, label = "#4da3ff", "tcp"
			case service.KindDown:
				color, label = "#ffb340", "down"
			default:
				color, label = "#b0b0b8", "skip"
			}
			fmt.Fprintf(&b, `<span style="background:rgba(0,0,0,.28);border:1px solid %s55;color:%s;padding:2px 8px;border-radius:5px;font-size:11px;font-family:monospace;">:%d · %s</span>`, color, color, pr.Port, label)
		}
		b.WriteString(`</div>`)
		b.WriteString(`<div style="color:var(--text-muted);font-size:10.5px;">色标：红=SSH 隧道(已入防御) / 蓝=普通 TCP / 黄=失效(down) / 灰=跳过</div>`)
	}

	b.WriteString(`<div style="color:var(--text-muted);font-size:11px;margin-top:4px;">更新 <span id="frps-ssh-at2">-</span> · 下次 <span id="frps-ssh-next2">-</span></div>`)
	b.WriteString(`</div>`)
	return b.String()
}