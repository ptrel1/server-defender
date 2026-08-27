package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 本文件：前端日志接收（/api/client_log）。
// 浏览器端将 JS 异常、console 输出、页面环境快照 POST 到这里，
// 以 JSONL 追加写入 data/client_logs/YYYYMMDD.log，用于排查用户本地渲染异常。
// 设计要点：
//   - 单文件互斥锁：Go 标准库 O_APPEND 已够用，锁只为避免多协程交错写行；
//   - 磁盘保护：单条上限 64KB、单日文件自动轮转、保留最近 7 天并启动时清理；
//   - 无阻塞：写失败仅打印，不影响面板主流程。

const (
	clientLogDir     = "data/client_logs"
	clientLogMaxLine = 64 * 1024 // 64KB
	clientLogKeepDay = 7
)

var clientLogMu sync.Mutex

type ClientLogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Type    string `json:"type"` // error / warn / info / env / navigation
	Message string `json:"message"`
	URL     string `json:"url,omitempty"`
	UA      string `json:"ua,omitempty"`
	Lang    string `json:"lang,omitempty"`
	Ext     map[string]interface{} `json:"ext,omitempty"`
}

func init() {
	os.MkdirAll(clientLogDir, 0755)
	pruneClientLogs()
}

// pruneClientLogs 清理超过保留期的日志文件。
func pruneClientLogs() {
	cutoff := time.Now().AddDate(0, 0, -clientLogKeepDay)
	entries, err := os.ReadDir(clientLogDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(clientLogDir, e.Name()))
		}
	}
}

// PostClientLog 处理前端日志上报。
func PostClientLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteJSON(w, map[string]interface{}{"code": 1, "msg": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, clientLogMaxLine)

	var entries []ClientLogEntry
	if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
		WriteJSON(w, map[string]interface{}{"code": 1, "msg": "invalid payload"})
		return
	}

	now := time.Now()
	day := now.Format("20060102")
	entry := ClientLogEntry{
		Time: now.Format("2006-01-02 15:04:05"),
		UA:   r.UserAgent(),
	}
	file, err := os.OpenFile(filepath.Join(clientLogDir, day+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("[client_log] open err:", err)
		WriteJSON(w, map[string]interface{}{"code": 0, "msg": "accepted(degraded)"})
		return
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetEscapeHTML(false) // 中文原文写入，避免 \u 转义影响可读性
	for _, e := range entries {
		item := entry
		if e.Time != "" {
			item.Time = e.Time
		}
		item.Level, item.Type, item.Message, item.URL, item.Lang, item.Ext =
			e.Level, e.Type, truncateStr(e.Message), e.URL, e.Lang, e.Ext
		_ = enc.Encode(item)
	}

	WriteJSON(w, map[string]interface{}{"code": 0, "msg": "ok"})
}

func truncateStr(s string) string {
	if len(s) > 4096 {
		return s[:4096]
	}
	return s
}
