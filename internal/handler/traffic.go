package handler

import (
	"net/http"
	"time"

	"server-defender/internal/service"
)

// 月度流量用量统计 API（v3.5.0 新增；v3.7.0 扩展天/小时粒度）。
// 前端懒加载（进入网络页/切换月份/天时调用），不并入 /api/data 的 4s 轮询，避免无谓 IO。

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

// HandleTraffic 返回按月/天/小时聚合的流量用量（v3.7.0 扩展天/小时粒度）。
//
// GET /api/traffic?month=2026-09&day=2026-09-07
//   - month 缺省=最新月；day 缺省=今天
//   - 响应：months(月选择器) + days(所选月按天) + hours(所选日按小时,固定24槽) + ports(端口TOP)
func HandleTraffic(w http.ResponseWriter, r *http.Request) {
	months := service.TrafficMonths()
	mlist := make([]*monthJSON, 0, len(months))
	for _, mt := range months {
		ps := make([]*portJSON, 0, len(mt.PortsList))
		for _, p := range mt.PortsList {
			ps = append(ps, &portJSON{Port: p.Port, Proc: p.Proc, RX: p.RX, TX: p.TX})
		}
		mlist = append(mlist, &monthJSON{Month: mt.Month, RX: mt.RX, TX: mt.TX, Ports: ps})
	}

	// 选中月（缺省最新月）→ 天粒度明细
	qMonth := r.URL.Query().Get("month")
	sel := service.MonthTraffic{Month: qMonth}
	if len(months) > 0 {
		sel = *months[0]
		for _, mt := range months {
			if mt.Month == qMonth {
				sel = *mt
				break
			}
		}
	}

	// 选中日（缺省今天）→ 小时粒度
	qDay := r.URL.Query().Get("day")
	today := time.Now().Format("2006-01-02")
	if len(qDay) != 10 {
		qDay = today
	}

	note := "按端口/应用归因需 root 运行并开启 conntrack 记账或可用 nft"
	if service.GetTrafficAcct() {
		note = ""
	}
	WriteJSON(w, map[string]interface{}{
		"acct":   service.GetTrafficAcct(),
		"note":   note,
		"months": mlist,
		"month":  sel.Month,
		"days":   sel.Days,
		"day":    qDay,
		"hours":  service.TrafficDayHours(qDay),
		"ports":  sel.PortsList,
	})
}