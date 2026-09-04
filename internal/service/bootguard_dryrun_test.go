package service

import (
"os"
"testing"
)

func TestCollectBootDryRun(t *testing.T) {
tmp := t.TempDir()
os.Setenv("DEFENDER_DATA_DIR", tmp)
items := collectBootFaces()
t.Logf("===== total=%d =====", len(items))
faceCnt := map[string]int{}
unknown := 0
for _, it := range items {
faceCnt[it.Face]++
if !it.Official {
unknown++
}
}
for k, v := range faceCnt {
t.Logf("  face %-10s %4d", k, v)
}
t.Logf("---- 非官方项 %d 条 (高危面才算unknown)----", unknown)
for _, it := range items {
if !it.Official {
t.Logf("  [%s] %s", it.Face, it.Path)
}
}
}

func TestBootBaselineOnce(t *testing.T) {
tmp := t.TempDir()
os.Setenv("DEFENDER_DATA_DIR", tmp)
snap := scanBootGuard() // 首跑=建基线
t.Logf("首跑: items=%d unknown=%d alerts=%d (首跑应建基线,alerts=0)", len(snap.Items), len(snap.Unknown), len(snap.Alerts))
if len(snap.Alerts) != 0 {
t.Errorf("首跑应无告警(刚建基线), 实际 alerts=%d", len(snap.Alerts))
}
// 模拟新增一个恶意启动项, 再跑应报新增
// 追加一个不存在的 systemd unit 到 items 再 diff——通过手动构造 baseline 冲突验证 diff
}



// 核心价值：纯函数 diffBootFaces 应第一时间检出「启动面新增的恶意项」。
func TestBootDiffDetectInjection(t *testing.T) {
now := "2026-09-04 00:00:00"
// 建立基线：干净状态 3 项
base := map[string]BootItem{
"systemd|nginx.service":  {Path: "nginx.service", Face: "systemd"},
"systemd|getty@.service": {Path: "getty@.service", Face: "systemd"},
"cron|<root>@reboot x":   {Path: "<root>@reboot x", Face: "cron"},
}
// 注入恶意自启项（如 irqbalancerd.service / pam-helper）
current := []BootItem{
{Path: "nginx.service", Face: "systemd", Official: true},
{Path: "getty@.service", Face: "systemd", Official: true},
{Path: "<root>@reboot x", Face: "cron", Official: false},
// 恶意新增
{Path: "irqbalancerd.service", Face: "systemd", Official: false},
{Path: "<root>@reboot /usr/libexec/pam-helper", Face: "cron", Official: false},
}
alerts := diffBootFaces(base, current, now)
t.Logf("diff alerts = %d (注入2项应有2条added)", len(alerts))
for _, a := range alerts {
t.Logf("  [%s] %s %s", a.Kind, a.Face, a.Path)
}
if len(alerts) != 2 {
t.Errorf("期望检出2条 injected added, 实际 %d", len(alerts))
}
var kinds, added map[string]bool = map[string]bool{}, map[string]bool{}
_ = kinds
for _, a := range alerts {
if a.Kind == "added" {
added[a.Path] = true
}
}
if !added["irqbalancerd.service"] || !added["<root>@reboot /usr/libexec/pam-helper"] {
t.Errorf("未检出注入项: %v", added)
}

// 缺失检测:从 current 移除一项(模拟攻击者清理/替换)
currentMissing := []BootItem{
{Path: "nginx.service", Face: "systemd", Official: true},
}
alerts2 := diffBootFaces(base, currentMissing, now)
t.Logf("缺失 alerts = %d", len(alerts2))
}
