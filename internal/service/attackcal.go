package service

import (
	"sort"
	"time"
)

// AttackDay 日历热力图一天的数据。
type AttackDay struct {
	Date  string `json:"date"`  // YYYY-MM-DD
	Count int    `json:"count"` // 该日封禁事件数
	Real  int    `json:"real"`  // 该日实时探测事件数(仅当日从lastb补充,历史为0)
}

// AttackCalendar 返回近 days 天的每日攻击/封禁热度，用于面板 Git 风格日历色块图。
// 数据源：usernames.json 中 banned 记录的封禁时间（历史按日聚合）+ 当日实时探测（由调用方注入）。
func AttackCalendar(days int, todayReal int) []AttackDay {
	if days <= 0 {
		days = 90
	}
	// 按日聚合封禁事件
	counts := map[string]int{}
	state := loadUsernamesState()
	for _, rec := range state.IPs {
		if rec == nil || !rec.Banned || rec.Time == "" {
			continue
		}
		if len(rec.Time) >= 10 {
			counts[rec.Time[:10]]++
		}
	}
	// 抠出近 days 天
	now := time.Now()
	out := make([]AttackDay, 0, days)
	for i := days - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i)
		key := d.Format("2006-01-02")
		real := 0
		if i == 0 {
			real = todayReal
		}
		out = append(out, AttackDay{Date: key, Count: counts[key], Real: real})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Date < out[b].Date })
	return out
}
