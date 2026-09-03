package service

import (
	"testing"
	"time"
)

// 用中转机 frps.log 真实行样例验证解析：必须正确拿到隧道名与公网源 IP。
func TestHandleFrpsLineReal(t *testing.T) {
	lines := []struct {
		line  string
		proxy string
		ip    string
	}{
		{
			"2026-09-03 16:32:03.245 [I] [proxy/proxy.go:256] [863e2593eb7eabd3] [a5.MCPHub3002] get a user connection [117.185.159.175:20721]",
			"a5.MCPHub3002", "117.185.159.175",
		},
		{
			"2026-09-03 16:33:39.617 [I] [proxy/proxy.go:256] [863e2593eb7eabd3] [b2.ssh] get a user connection [127.0.0.1:41254]",
			"b2.ssh", "127.0.0.1",
		},
		{
			"2026-09-03 16:33:48.266 [I] [proxy/proxy.go:256] [863e2593eb7eabd3] [a5.gitea3103] get a user connection [115.206.31.222:49790]",
			"a5.gitea3103", "115.206.31.222",
		},
	}
	for _, c := range lines {
		handleFrpsLine(c.line)
		frpsAtkMu.RLock()
		_, ok := frpsAttacks[c.ip][c.proxy]
		frpsAtkMu.RUnlock()
		if !ok {
			t.Fatalf("line not parsed: %q -> want proxy=%q ip=%q", c.line, c.proxy, c.ip)
		}
	}
}

func TestAttackedPortsLabel(t *testing.T) {
	// 直连未观测 → :22
	if got := AttackedPortsLabel("1.2.3.4"); got != ":22" {
		t.Fatalf("unattacked ip label = %q, want :22", got)
	}
	// b2.ssh 已内置映射 50022 → 具体端口
	handleFrpsLine("2026-09-03 16:33:39.617 [I] [proxy/proxy.go:256] [863e2593eb7eabd3] [b2.ssh] get a user connection [9.9.9.9:1111]")
	if got := AttackedPortsLabel("9.9.9.9"); got != ":50022" {
		t.Fatalf("mapped label = %q, want :50022", got)
	}
	// 观测到隧道但无映射 → frp 隧道组
	handleFrpsLine("2026-09-03 16:32:03.245 [I] [proxy/proxy.go:256] [863e2593eb7eabd3] [a5.unknown-tunnel] get a user connection [8.8.8.8:2222]")
	if got := AttackedPortsLabel("8.8.8.8"); got != "frp 隧道组" {
		t.Fatalf("unmapped label = %q, want frp 隧道组", got)
	}
}

var _ = time.Time{} // 保留 time 引用（如需基于时间做后续断言）