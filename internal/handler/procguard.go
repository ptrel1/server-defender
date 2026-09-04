package handler

// ProcGuard handler：进程级安全（伪内核线程 + setuid-root）监控。
// v3.2.0 新增面板数据源，无需 CDN，JSON 由前端渲染卡片。

import (
	"net/http"

	"server-defender/internal/service"
)

// ProcGuardDataHandler 返回最新进程安全快照。
func ProcGuardDataHandler(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, service.ProcGuardData())
}

// FileIntegrityDataHandler 返回最新文件完整性快照。
func FileIntegrityDataHandler(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, service.FileIntegrityData())
}