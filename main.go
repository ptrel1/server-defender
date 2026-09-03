// Server Defender — 服务器安全与自愈中心 (Go 版 v3.0.2)
// 结构标准化：数据目录改为「运行目录/data」（DEFENDER_DATA_DIR 可覆盖），不再跟二进制走；
// 清理 internal/store 死代码、根目录旧二进制/备份，补齐 config/logs/skill/doc/test 标准目录。
// v3.0.1: 攻击日历改近一年(365天)+格子14px，铺满卡片消除空置。
// 单二进制，内含 Web 面板 + 后台常驻协程：
//   - usernames_loop: journalctl sshd 实时封禁(境外/风暴)
//   - reaper_loop:    巡检收割失控孤儿进程
//   - history_loop:   NetMon 10 分钟采样
//   - webmon_loop:    域名访问监控（nginx 日志 tail / IP 聚合 / 趋势 / 告警）
//   - frps_ssh_loop:  每日识别 frp SSH 隧道端口并同步 frps-ssh 防御(自动) + 端口有效性判定
//
// 全程仅用 Go 标准库，前端 HTML/CSS/JS/Chart.js 通过 //go:embed 打包。
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"server-defender/internal/handler"
	"server-defender/internal/service"
)

//go:embed internal/static
var staticFS embed.FS

func main() {
	// 前台运行直到收到退出信号；后台协程由 context 控制。
	done := make(chan struct{})
	go service.UsernamesLoop(done)
	go service.ReaperLoop(done)
	go service.HistoryLoop(done)
	// WebMon：域名访问监控（日志文件缺失时静默等待，不影响其他模块）
	go service.WebMonLoop(done)
	// frps-ssh：每日识别 frp SSH 隧道端口并同步 frps-ssh 防御（banner 探测 + 端口有效性判定）
	go service.FrpsSSHLoop(done)

	// 解析静态资源
	sub, err := fs.Sub(staticFS, "internal/static")
	if err != nil {
		fmt.Println("[main] embed fs sub err:", err)
		os.Exit(1)
	}
	staticHandler := http.FileServer(http.FS(sub))

	mux := http.NewServeMux()

	// 静态资源（chart.js / favicon）
	mux.Handle("/chart.umd.js", staticHandler)
	mux.Handle("/favicon.svg", staticHandler)

	// 页面
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// API：聚合数据
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		includeVirtual := r.URL.Query().Get("virtual") == "1"
		handler.WriteJSON(w, handler.DashboardData(includeVirtual))
	})

	// 封禁列表 CSV 导出
	mux.HandleFunc("/api/bans/export", func(w http.ResponseWriter, r *http.Request) {
		handler.ExportBansCSV(w)
	})

	// IP 标记管理（GET 查询 / POST 增改 / DELETE 删除）
	mux.HandleFunc("/api/iptags", handler.HandleIPTags)

	// 手动封禁
	mux.HandleFunc("/api/block_ip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			handler.WriteJSON(w, map[string]interface{}{"code": 1, "msg": "method not allowed"})
			return
		}
		var req struct {
			IP string `json:"ip"`
		}
		_ = handler.DecodeJSON(r, &req)
		ok, msg := handler.BlockIP(strings.TrimSpace(req.IP))
		code := 0
		if !ok {
			code = 1
		}
		handler.WriteJSON(w, map[string]interface{}{"code": code, "msg": msg})
	})

	// 手动终止进程
	mux.HandleFunc("/api/reaper/kill", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			handler.WriteJSON(w, map[string]interface{}{"code": 1, "msg": "method not allowed"})
			return
		}
		var req struct {
			PID int `json:"pid"`
		}
		_ = handler.DecodeJSON(r, &req)
		ok, msg := handler.KillProcess(req.PID)
		code := 0
		if !ok {
			code = 1
		}
		handler.WriteJSON(w, map[string]interface{}{"code": code, "msg": msg})
	})

	// 域名访问监控（WebMon）：IP 聚合 / 趋势 / 告警
	mux.HandleFunc("/api/webmon", func(w http.ResponseWriter, r *http.Request) {
		handler.WriteJSON(w, handler.WebMonData())
	})

	// 前端日志上报（浏览器 JS 异常 / 环境快照，排查本地渲染问题）
	mux.HandleFunc("/api/client_log", handler.PostClientLog)

	// 调试触发采样：立即产生一个历史采样点（仅本机/受信来源用，用于排障避免等待采样周期）
	mux.HandleFunc("/api/dev/sample", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			handler.WriteJSON(w, map[string]interface{}{"code": 1, "msg": "method not allowed"})
			return
		}
		p := service.SampleHistory()
		points := service.GetHistoryPoints()
		points = append(points, p)
		const retain30d = 4320 // 与服务端 historyRetain 一致（30 天）
		if len(points) > retain30d {
			points = points[len(points)-retain30d:]
		}
		_ = service.SaveHistoryPoints(points)
		handler.WriteJSON(w, map[string]interface{}{"code": 0, "msg": "sampled",
			"tcp_total": p.TCPTotal, "rx_kbs": int(p.RXRate / 1024), "tx_kbs": int(p.TXRate / 1024)})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8899"
	}
	addr := "0.0.0.0:" + port
	fmt.Println("[server-defender] v3.0.2 Go 版启动，监听", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Println("[main] server err:", err)
		os.Exit(1)
	}
}
