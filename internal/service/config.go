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
	Threshold  int    `json:"threshold"`       // 用户名风暴阈值（不同账号数）
	RelayHost  string `json:"relay_host"`      // 中转机 ssh 地址（同步封禁用）
	NotifyCmd  string `json:"notify_cmd"`      // 封禁通知命令（sh 执行；可用 $BAN_IP/$BAN_REASON/$BAN_LOCATION/$BAN_TIME 环境变量；空=关闭）
	GeoMemTTLH int    `json:"geo_mem_ttl_h"`   // geo 内存缓存 TTL（小时）
}

var (
	confMu   sync.RWMutex
	confCur  = defaultConfig()
	confLast time.Time
)

func defaultConfig() DefenderConfig {
	return DefenderConfig{
		Threshold:  100,
		RelayHost:  "root@47.98.244.173",
		NotifyCmd:  "",
		GeoMemTTLH: 24,
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
