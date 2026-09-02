package handler

import (
	"net/http"
	"strings"

	"server-defender/internal/service"
)

// IP 标记：面板各处 IP 单元格的可视化徽标渲染 + 管理 API。
// 标记来源见 service.iptags.go（自动识别白/黑名单/本地 + 用户自定义 data/ip_tags.json）。

// tagColorClass 颜色→CSS class 映射（空/未知→tag-blue）。
var tagColorClass = map[string]string{
	"green":  "tag-green",
	"red":    "tag-danger",
	"blue":   "tag-blue",
	"yellow": "tag-warning",
	"gray":   "tag-gray",
}

// tagIcons 颜色/类型→图标 映射（冗余编码：颜色+图标双通道，色弱也可读）。
// 自动标记(白名单/已封禁/本地)用专属语义图标；自定义按颜色给通用图标。
var tagIcons = map[string]string{
	"whitelist": "🛡️", // 白名单
	"banned":    "🚫",  // 已封禁
	"local":     "🏠",  // 本地
	// 自定义颜色图标
	"green":  "✅",
	"red":    "❌",
	"blue":   "🔵",
	"yellow": "⚠️",
	"gray":   "○",
}

// IPTagBadgeHTML 渲染单个 IP 的标记徽标（颜色+图标双通道）；无标记返回空串。
func IPTagBadgeHTML(ip string) string {
	tag, ok := service.ResolveIPTag(ip)
	if !ok || strings.TrimSpace(tag.Tag) == "" {
		return ""
	}
	cls := tagColorClass[tag.Color]
	if cls == "" {
		cls = "tag-blue"
	}
	// 图标：按类型/颜色选择
	icon := ""
	if tag.Auto {
		switch tag.Tag {
		case "白名单":
			icon = tagIcons["whitelist"]
		case "已封禁":
			icon = tagIcons["banned"]
		case "本地":
			icon = tagIcons["local"]
		}
	} else {
		icon = tagIcons[tag.Color]
	}
	note := strings.TrimSpace(tag.Note)
	h := "<span class=\"tag " + cls + " ip-tag\""
	if note != "" {
		h += " title=\"" + escAttr(note) + "\""
	}
	h += ">"
	if icon != "" {
		h += icon + " "
	}
	h += escAttr(tag.Tag) + "</span>"
	return h
}

// IPTagsData 注入前端的数据：标记映射。
func IPTagsData() map[string]interface{} {
	return map[string]interface{}{
		"ips":         service.ResolveIPTagAll(),
		"custom_path": service.IPTagsPath(),
	}
}

// HandleIPTags 处理 /api/iptags：GET 查询，POST 增改，DELETE 删除。
func HandleIPTags(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// ?ip=X 查询该 IP 命中的标记（含通配符/CIDR 命中），用于编辑回填
		if qip := strings.TrimSpace(r.URL.Query().Get("ip")); qip != "" {
			tag, pattern := service.ResolveTagForIP(qip)
			WriteJSON(w, map[string]interface{}{"code": 0, "ip": qip, "pattern": pattern,
				"tag": tag.Tag, "note": tag.Note, "color": tag.Color, "found": tag.Tag != ""})
			return
		}
		WriteJSON(w, IPTagsData())
	case http.MethodPost:
		var req struct {
			IP    string `json:"ip"`
			Tag   string `json:"tag"`
			Note  string `json:"note"`
			Color string `json:"color"`
		}
		_ = DecodeJSON(r, &req)
		ip := strings.TrimSpace(req.IP)
		if ip == "" || strings.TrimSpace(req.Tag) == "" {
			WriteJSON(w, map[string]interface{}{"code": 1, "msg": "ip 与 tag 不能为空"})
			return
		}
		err := service.UpsertIPTag(ip, service.IPTag{
			Tag: strings.TrimSpace(req.Tag), Note: strings.TrimSpace(req.Note), Color: req.Color,
		})
		code, msg := 0, "ok"
		if err != nil {
			code, msg = 1, err.Error()
		}
		WriteJSON(w, map[string]interface{}{"code": code, "msg": msg})
	case http.MethodDelete:
		var req struct {
			IP string `json:"ip"`
		}
		_ = DecodeJSON(r, &req)
		err := service.RemoveIPTag(strings.TrimSpace(req.IP))
		code, msg := 0, "ok"
		if err != nil {
			code, msg = 1, err.Error()
		}
		WriteJSON(w, map[string]interface{}{"code": code, "msg": msg})
	default:
		WriteJSON(w, map[string]interface{}{"code": 1, "msg": "method not allowed"})
	}
}

// escAttr HTML 属性转义（防注入）。
func escAttr(s string) string {
	repl := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return repl.Replace(s)
}
