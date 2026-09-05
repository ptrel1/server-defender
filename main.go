// Server Defender — 服务器安全与自愈中心 (Go 版 v3.3.1)
// v3.3.1: Reaper 误杀治理——CPU 持续采样确认 + grep/find 遍历参数豁免 + 文案分钟数修正。
// v3.3.0: 执行来源追溯(ProcTrace)——基于 auditd execve 审计，对可疑进程回查父链，
//         回答"命令从哪个入口/谁触发进来的"(PAM/SSH/cron/su/systemd 触发判定)。
// v3.2.1: 启动面基线(BootGuard)——枚举全部开机执行路径(systemd/cron/sysv/pam/preload/
//         profile/module/boot/uefi)，干净机身基线+dirty diff，拦截"开机自动拉起"类持久化。
// v3.2.0: 进程级安全(ProcGuard) + 文件完整性(FileIntegrity)——复刻 2026-09-04 Pickai/ComfyUI
//         入侵复盘的两个杀招：userland 伪装内核线程检测 + setuid-root 掉包检测 +
//         pacman -Qkk / debsums 系统文件完整性校验。
// v3.1.0: SSH 攻击「目标端口」归因——新增 FrpsAttackLoop 解析 frps.log，
//         事件流/TOP IP 展示每条攻击命中的目标端口（frp 隧道端口或 :22）。
// 结构标准化：数据目录改为「运行目录/data」（DEFENDER_DATA_DIR 可覆盖），不再跟二进制走；
// 清理 internal/store 死代码、根目录旧二进制/备份，补齐 config/logs/skill/doc/test 标准目录。
// 单二进制，内含 Web 面板 + 后台常驻协程：
//   - usernames_loop: journalctl sshd 实时封禁(境外/风暴)
//   - reaper_loop:    巡检收割失控孤儿进程
//   - history_loop:   NetMon 10 分钟采样
//   - webmon_loop:    域名访问监控（nginx 日志 tail / IP 聚合 / 趋势 / 告警）
//   - frps_ssh_loop:  每日识别 frp SSH 隧道端口并同步 frps-ssh 防御(自动) + 端口有效性判定
//   - frps_attack_loop: 实时 tail frps.log 记录 SSH 攻击命中隧道（目标端口归因）
//   - procguard_loop:  进程级安全——userland 伪装内核线程 + setuid-root 掉包检测
//   - fileintegrity_loop: 文件完整性——pacman -Qkk / debsums -c 抓系统文件掉包
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
	// frps-attack：实时 tail frps.log 记录 SSH 攻击命中隧道（目标端口归因，供事件流/TOP IP 展示）
	go service.FrpsAttackLoop(done)
	// procguard：进程级安全——userland 伪装内核线程 + setuid-root 掉包检测（v3.2.0 新增）
	service.LoadProcGuard()
	go service.ProcGuardLoop(done)
	// fileintegrity：文件完整性校验——pacman -Qkk / debsums -c 抓系统文件掉包（v3.2.0 新增）
	service.LoadFileIntegrity()
	go service.FileIntegrityLoop(done)
	// bootguard：启动面基线——枚举开机执行路径(systemd/cron/sysv/pam/preload/profile/module/boot/uefi)，diff 拦截开机自启木马（v3.2.1 新增）
	service.LoadBootGuard()
	go service.BootGuardLoop(done)
	// proctrace：执行来源追溯——基于 auditd execve 审计，对可疑进程回查父链/触发环节（v3.3.0 新增）
	service.LoadProcTrace()
	go service.ProcTraceLoop(done)

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

	// 进程级安全（伪内核线程 + setuid-root 掉包）——v3.2.0 新增
	mux.HandleFunc("/api/procguard", handler.ProcGuardDataHandler)
	// 运维确认后重建 setuid 基线（只读基线模型需显式重建）
	mux.HandleFunc("/api/procguard/baseline", handler.RebuildBaselineHandler)

	// 文件完整性（pacman -Qkk / debsums -c 抓系统文件掉包）——v3.2.0 新增
	mux.HandleFunc("/api/fileintegrity", handler.FileIntegrityDataHandler)

	// 启动面基线（systemd/cron/sysv/pam/preload/profile/module/boot/uefi 枚举+diff）——v3.2.1 新增
	mux.HandleFunc("/api/bootguard", handler.BootGuardDataHandler)
	mux.HandleFunc("/api/bootguard/baseline", handler.BootRebuildBaselineHandler)

	// 执行来源追溯（auditd exec 父链回查）——v3.3.0 新增
	mux.HandleFunc("/api/proctrace", handler.ProcTraceDataHandler)

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
	fmt.Println("[server-defender] v3.1.0 Go 版启动，监听", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Println("[main] server err:", err)
		os.Exit(1)
	}
}
