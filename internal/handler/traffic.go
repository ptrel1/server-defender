package handler

import (
	"net/http"

	"server-defender/internal/service"
)

// 月度流量用量统计 API（v3.5.0 新增）。
// 前端懒加载（进入网络页/切换月份时调用），不并入 /api/data 的 4s 轮询，避免无谓 IO。

// portJSON 单端口月度明细（序列化用）。
type portJSON struct {
	Port int    `json:"port"`
	Proc string `json:"proc"`
	RX   uint64 `json:"rx"`
	TX   uint64 `json:"tx"`
}

// monthJSON 单月汇总。
type monthJSON struct {
	Month string      `json:"month"`
	RX    uint64      `json:"rx"`
	TX    uint64      `json:"tx"`
	Ports []*portJSON `json:"ports"`
}

// HandleTraffic 返回按月份聚合的流量用量（新→旧序）。
func HandleTraffic(w http.ResponseWriter, r *http.Request) {
	months := service.TrafficMonths()
	list := make([]*monthJSON, 0, len(months))
	for _, mt := range months {
		ps := make([]*portJSON, 0, len(mt.PortsList))
		for _, p := range mt.PortsList {
			ps = append(ps, &portJSON{Port: p.Port, Proc: p.Proc, RX: p.RX, TX: p.TX})
		}
		list = append(list, &monthJSON{Month: mt.Month, RX: mt.RX, TX: mt.TX, Ports: ps})
	}
	note := "按端口/应用归因需 root 运行并开启 conntrack 记账"
	if service.GetTrafficAcct() {
		note = ""
	}
	WriteJSON(w, map[string]interface{}{
		"acct":   service.GetTrafficAcct(),
		"note":   note,
		"months": list,
	})
}