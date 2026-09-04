package handler

// BootGuard handler：启动面基线监控。
// v3.2.1 新增——枚举开机执行路径，干净机身基线，diff 拦截"开机自动拉起"类持久化。

import (
	"net/http"

	"server-defender/internal/service"
)

// BootGuardDataHandler 返回最新启动面快照。
func BootGuardDataHandler(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, service.BootGuardData())
}

// BootRebuildBaselineHandler 运维确认后重建启动面基线（POST）。
func BootRebuildBaselineHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteJSON(w, map[string]interface{}{"code": 1, "msg": "method not allowed"})
		return
	}
	ok := service.RebuildBootBaseline()
	if !ok {
		WriteJSON(w, map[string]interface{}{"code": 1, "msg": "rebuild failed"})
		return
	}
	WriteJSON(w, map[string]interface{}{"code": 0, "msg": "boot baseline rebuilt"})
}