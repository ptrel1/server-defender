package service

import (
	"os"
	"testing"
)

// TestSamePorts nft 端口集比较。
func TestSamePorts(t *testing.T) {
	if !samePorts([]int{22, 443, 8899}, []int{22, 443, 8899}) {
		t.Fatal("相同端口集应相等")
	}
	if samePorts([]int{22, 443}, []int{22, 443, 8899}) {
		t.Fatal("不同长度应不等")
	}
	if samePorts([]int{22, 443}, []int{22, 88}) {
		t.Fatal("不同内容应不等")
	}
}

// TestTrafficPortOf 端口条目取/建与进程名写入。
func TestTrafficPortOf(t *testing.T) {
	d := &DayTraffic{Date: "2026-09-07", Ports: map[string]*PortTraffic{}}
	listen := map[int]string{443: "nginx(9)", 22: "sshd(1)"}
	p := trafficPortOf(d, 22, listen)
	if p.Port != 22 || p.Proc != "sshd(1)" {
		t.Fatalf("新建条目错误: %+v", p)
	}
	p.RX += 100
	p2 := trafficPortOf(d, 22, listen)
	if p2.RX != 100 {
		t.Fatalf("应复用既有条目: %+v", p2)
	}
}

// TestParseConnLine 验证 conntrack 记账行解析（含 IPv6 地址中的冒号，分割须按 '=' 而非空格）。
func TestParseConnLine(t *testing.T) {
	// 会计账开启时的典型行（原始方向：远端 9.9.9.9:5555 → 本机 1.2.3.4:443）
	line := "ipv4 2 tcp 6 431999 ESTABLISHED src=9.9.9.9 dst=1.2.3.4 sport=5555 dport=443 " +
		"src=1.2.3.4 dst=9.9.9.9 sport=443 dport=5555 [ASSURED] secs=10 bytes=12345 pkts=9 " +
		"bytes=67890 pkts=12 use=1"
	cb, ok := parseConnLine(line)
	if !ok {
		t.Fatalf("应解析成功")
	}
	if cb.proto != "tcp" || cb.dst != "1.2.3.4" {
		t.Fatalf("proto/dst 解析错误: %+v", cb)
	}
	// 原始方向端口：sport=5555(远端), dport=443(本机)
	if cb.sport != 5555 || cb.dport != 443 {
		t.Fatalf("端口解析错误: sport=%d dport=%d", cb.sport, cb.dport)
	}
	if cb.first != 12345 || cb.second != 67890 {
		t.Fatalf("字节解析错误: first=%d second=%d", cb.first, cb.second)
	}
	// IPv6 分隔符正确性：地址含 ':' 不应被误切
	line6 := "ipv6 2 tcp 6 431999 ESTABLISHED src=2001:db8::1 dst=2001:db8::2 sport=40000 dport=8080 " +
		"src=2001:db8::2 dst=2001:db8::1 sport=8080 dport=40000 [ASSURED] secs=5 bytes=100 pkts=1 bytes=200 pkts=1 use=1"
	cb6, ok6 := parseConnLine(line6)
	if !ok6 {
		t.Fatalf("IPv6 行应解析成功")
	}
	if cb6.src != "2001:db8::1" || cb6.dst != "2001:db8::2" || cb6.dport != 8080 {
		t.Fatalf("IPv6 解析错误: %+v", cb6)
	}
	// 无记账字节（bytes 不足 2 个）→ 不应解析成功
	noAcct := "ipv4 2 tcp 6 100 ESTABLISHED src=1.2.3.4 dst=2.2.2.2 sport=1 dport=2 src=2.2.2.2 dst=1.2.3.4 sport=2 dport=1 [ASSURED] use=1"
	if _, ok := parseConnLine(noAcct); ok {
		t.Fatalf("无记账字节行应解析失败")
	}
}

// TestTrafficMonthsAgg 验证日表→月度按端口聚合与排序。
func TestTrafficMonthsAgg(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("DEFENDER_DATA_DIR", tmp)

	trafficMu.Lock()
	curDay = "2026-09-07"
	trafDays = map[string]*DayTraffic{
		"2026-09-06": {
			Date: "2026-09-06", RX: 1000, TX: 500,
			Ports: map[string]*PortTraffic{
				"22":   {Port: 22, Proc: "sshd(123)", RX: 700, TX: 300},
				"443":  {Port: 443, Proc: "nginx(9)", RX: 300, TX: 200},
			},
		},
		"2026-09-07": {
			Date: "2026-09-07", RX: 2000, TX: 1000,
			Ports: map[string]*PortTraffic{
				"22":  {Port: 22, Proc: "sshd(123)", RX: 500, TX: 200},
				"443": {Port: 443, Proc: "nginx(9)", RX: 1500, TX: 800},
			},
		},
		"2026-08-31": {
			Date: "2026-08-31", RX: 99, TX: 10,
			Ports: map[string]*PortTraffic{
				"1080": {Port: 1080, Proc: "frps(7)", RX: 99, TX: 10},
			},
		},
	}
	trafficMu.Unlock()

	months := TrafficMonths()
	if len(months) != 2 {
		t.Fatalf("月份数应为 2，实际 %d", len(months))
	}
	// 新→旧排序：9 月在前
	if months[0].Month != "2026-09" {
		t.Fatalf("应 9 月在前: %s", months[0].Month)
	}
	sep := months[0]
	if sep.RX != 3000 || sep.TX != 1500 {
		t.Fatalf("9月总量错误: rx=%d tx=%d", sep.RX, sep.TX)
	}
	if len(sep.PortsList) != 2 {
		t.Fatalf("9月端口数应为 2，实际 %d", len(sep.PortsList))
	}
	// 端口按总量降序：443(2700) > 22(1700)
	if sep.PortsList[0].Port != 443 || sep.PortsList[1].Port != 22 {
		t.Fatalf("端口排序错误: %d, %d", sep.PortsList[0].Port, sep.PortsList[1].Port)
	}
	// 端口跨天聚合正确
	for _, p := range sep.PortsList {
		if p.Port == 22 {
			rx := p.RX
			if rx != 1200 { // 700+500
				t.Fatalf("22 端口 rx 聚合错误: %d", rx)
			}
			if p.Proc != "sshd(123)" {
				t.Fatalf("22端口 proc 未保留")
			}
		}
	}
	trafDays = map[string]*DayTraffic{}
}