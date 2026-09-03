package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefenderConfig 运行时可调配置，存于 data/config.json，循环每轮重载（改完即生效，无需重启）。
type DefenderConfig struct {
	Threshold int    `json:"threshold"` // 用户名风暴阈值（不同账号数）
	// RateThreshold 请求速率阈值：同一 IP 在统计窗口内的 SSH 失败次数达到该值即封。
	// 替换旧"单账号爆破"规则（10分钟10次过紧，会误伤智能体试老密码），改为更宽松的速率封禁。
	RateThreshold int `json:"rate_threshold"`
	// RateWindowMin 请求速率统计窗口（分钟），窗口外的失败计数自动丢弃。
	RateWindowMin int    `json:"rate_window_min"`
	RelayHost     string `json:"relay_host"`    // 中转机 ssh 地址（同步封禁用）
	NotifyCmd     string `json:"notify_cmd"`    // 封禁通知命令（sh 执行；可用 $BAN_IP/$BAN_REASON/$BAN_LOCATION/$BAN_TIME 环境变量；空=关闭）
	GeoMemTTLH    int    `json:"geo_mem_ttl_h"` // geo 内存缓存 TTL（小时）
	// FrpsTunnelPorts frp 隧道名 -> 公网目标端口 映射（SSH 攻击目标端口归因用，热加载）。
	// key 为 frps.log `get a user connection` 行中的隧道名（如 b2.ssh），value 为远端端口（如 50022）。
	// 缺失映射时面板对观测到的 frp 隧道攻击显示"frp 隧道组"而非具体端口。
	FrpsTunnelPorts map[string]int `json:"frps_tunnel_ports,omitempty"`
}

var (
	confMu   sync.RWMutex
	confCur  = defaultConfig()
	confLast time.Time
)

func defaultConfig() DefenderConfig {
	return DefenderConfig{
		Threshold:     100,
		RateThreshold: 1000,
		RateWindowMin: 60,
		RelayHost:     "root@47.98.244.173",
		NotifyCmd:     "",
		GeoMemTTLH:    24,
		// 内置当前已知 SSH 隧道名->远端端口（可在 data/config.json 增补，最权威）。
		// 说明：frps 服务端无静态清单，故此处为人工基线 + 运行时热加载覆盖。
		FrpsTunnelPorts: map[string]int{
			"b2.ssh": 50022, // 客户端机 b2 SSH 隧道
		},
	}
}

func confPath() string { return filepath.Join(dataDir(), "config.json") }

// Conf 返回当前配置（自动热加载：距上次加载超过 30s 时重读文件）。
func Conf() DefenderConfig {
	confMu.RLock()
	c, last := confCur, confLast
	confMu.RUnlock()
	if time.Since(last) < 30*time.Second {
		return c
	}
	data, err := os.ReadFile(confPath())
	if err != nil {
		confMu.Lock()
		confLast = time.Now()
		confMu.Unlock()
		return c
	}
	nc := defaultConfig()
	if json.Unmarshal(data, &nc) == nil {
		confMu.Lock()
		confCur, confLast = nc, time.Now()
		confMu.Unlock()
		return nc
	}
	confMu.Lock()
	confLast = time.Now()
	confMu.Unlock()
	return c
}

// WriteDefaultConfig 若无配置文件则写出默认配置（首次部署友好）。
func WriteDefaultConfig() {
	p := confPath()
	if _, err := os.Stat(p); err == nil {
		return
	}
	_ = os.MkdirAll(dataDir(), 0o755)
	b, _ := json.MarshalIndent(defaultConfig(), "", "  ")
	_ = os.WriteFile(p, b, 0o644)
}
