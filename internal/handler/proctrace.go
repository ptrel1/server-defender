package handler

// ProcTrace handler：执行来源追溯。
// v3.3.0 新增——对可疑进程回查父链，回答「命令从哪个入口/谁触发进来的」。

import (
	"net/http"

	"server-defender/internal/service"
)

// ProcTraceDataHandler 返回最近 exec 快照 + 可疑进程来源画像。
func ProcTraceDataHandler(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, service.ProcTraceData())
}