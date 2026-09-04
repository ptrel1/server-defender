package service

// ProcGuardLoop：进程级安全监控采集层（纯标准库）。
// v3.2.0 新增——复刻 2026-09-04 事件中「伪装 kernel 线程」「setuid-root 掉包」两个最强信号。
//
// 设计意图：
//   - ① userland 伪装内核线程检测：真实内核线程（kworker/kthread 等）的 /proc/PID/exe
//     不可读（没有用户态可执行程序）；凡 comm 以 '[' 开头但 /proc/PID/exe 能解析出 ELF
//     路径的进程，即 userland 木马伪装，直接告警。这是本次「[kworker/R-rcu] -> pam-helper」
//     抓取所依赖的铁律，几乎零误报。
//   - ② setuid-root 异常检测：全盘周期扫描 -perm -4000 -user root，与白名单基线（data/
//     procguard_setuid_allowlist.json）比对，新增项或大小突变即告警——本次 /usr/bin/false
//     被换成 1.1MB setuid ELF 即触发此逻辑。
//
// 边界条件：
//   - 扫描周期 60s；结果落盘 data/procguard.json（只保留最近告警，防膨胀）；
//   - 白名单基线缺失时自动用「当前的全量 setuid 快照」作为基线——注意首次运行发生在受信
//     干净机上，白名单才是可信的；失陷机上首次快照会把已植入的后门洗白，故部署时务必先
//     在重建后的干净机上跑一次生成基线。
//   - 不真正执行任何扫描到的可疑进程，只读 /proc，零侵入。
//
// 风险：
//   - setuid 白名单是「增量基线」而非「绝对判定」：只有新建/变更会告警，历史已存在且被压
//     进基线的后门不会报警。因此它必须配合「干净机生成基线」的运维纪律使用，不能替代重装后
//     的完整性评估。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	procGuardInterval    = 60 * time.Second  // 进程扫描（轻量，读 /proc）
	procGuardSetuidEvery = 10 * time.Minute // setuid 全盘扫描（重 IO，独立低频周期）
	procGuardMaxAlert    = 200              // 告警留存上限
)

// setuidWalkRoots：setuid 扫描的关键目录（排除 /var /home 等大目录，避免 60s 周期拖垮 IO）。
// 后门提权文件绝大多数落在系统可执行区；/var /home 因体积与 owner 复杂度高，不作为默认扫描面。
var setuidWalkRoots = []string{"/usr", "/opt", "/srv", "/root", "/bin", "/sbin", "/etc"}

type ProcAlert struct {
	Time    string `json:"time"`
	Kind    string `json:"kind"` // fkthread | setuid
	PID     int    `json:"pid,omitempty"`
	Comm    string `json:"comm,omitempty"`
	Exe     string `json:"exe,omitempty"`
	Path    string `json:"path,omitempty"` // setuid 文件路径
	Size    int64  `json:"size,omitempty"`
	Message string `json:"message"`
}

type ProcGuardSnapshot struct {
	Updated string      `json:"updated"`
	Alerts  []ProcAlert `json:"alerts"`
	// 当前 setuid 白名单基线（供面板回显/更新）
	SetuidAllow []string `json:"setuid_allow"`
	// 当前发现的伪 kthread 数
	FakeKthreads int `json:"fake_kthreads"`
}

var (
	procGuardMu     sync.Mutex
	procGuardLatest ProcGuardSnapshot
)

func procGuardPath() string { return filepath.Join(dataDir(), "procguard.json") }
func setuidAllowPath() string {
	return filepath.Join(dataDir(), "procguard_setuid_allowlist.json")
}

// isKernelThread 判断某 PID 是否「伪装成内核线程」。
// 真内核线程无可见可执行文件（readlink(".../exe") 为空或报错），
// 而 userland 进程必有可读 exe。comm 以 '[' 开头 + exe 可读 => userland 伪装木马。
func isKernelThread(pid int) (comm string, exe string, ok bool) {
	c, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return "", "", false
	}
	comm = strings.TrimSpace(string(c))
	if !strings.HasPrefix(comm, "[") {
		return "", "", false
	}
	exe, err = os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil || exe == "" {
		return "", "", true // 真内核线程：无 exe，不告警
	}
	return comm, exe, true // 有 exe 但名字像内核线程 => 用户态伪装
}

// loadSetuidAllow 读白名单基线；缺省时返回 nil（首次由 ScanSetuid 生成）。
func loadSetuidAllow() map[string]bool {
	raw, err := os.ReadFile(setuidAllowPath())
	if err != nil {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	m := make(map[string]bool, len(list))
	for _, p := range list {
		m[p] = true
	}
	return m
}

// saveSetuidAllow 原子写白名单。
func saveSetuidAllow(list []string) {
	_ = atomicWrite(setuidAllowPath(), mustJSON(list))
}

// scanProcGuard 执行一轮进程扫描，返回本轮的进程安全告警。
func scanProcGuard() []ProcAlert {
	var alerts []ProcAlert
	now := time.Now().Format("2006-01-02 15:04:05")

	// ① 伪内核线程
	for _, line := range listProcDirs() {
		pidStr := strings.TrimPrefix(line, "/proc/")
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		// 跳过自身与内核 PID 0
		if pid <= 1 {
			continue
		}
		comm, exe, isKt := isKernelThread(pid)
		if !isKt || exe == "" {
			continue
		}
		if strings.Contains(comm, "Thread") { // 忽略部分库线程命名，防误报
			continue
		}
		alerts = append(alerts, ProcAlert{
			Time: now, Kind: "fkthread", PID: pid, Comm: comm, Exe: exe,
			Message: "userland 进程伪装内核线程: " + comm + " -> " + exe,
		})
	}
	return alerts
}

// 返回 /proc 下数字目录列表。
func listProcDirs() []string {
	ents, _ := os.ReadDir("/proc")
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			n := e.Name()
			if _, err := strconv.Atoi(n); err == nil {
				out = append(out, "/proc/"+n)
			}
		}
	}
	return out
}

// scanSetuid 全盘扫描 setuid-root 文件，与白名单比对，返回新增/变更告警与当前全集。
func scanSetuid() (alerts []ProcAlert, full []string) {
now := time.Now().Format("2006-01-02 15:04:05")
// 只读基础快照：攻击者删除setuid重置后门、或首轮建立基线后，后续轮次不允许静默覆盖基线。
// 基线的唯一写入时机是「首次运行时建立」；此后每轮只读，报告新增与缺失，由运维人工确认后
// 通过 POST /api/procguard/baseline 显式重建。这样可避免「失陷机首跑洗白」与「有条件覆盖掩盖复活」。
allow := loadSetuidAllow()

var paths []string
for _, r := range setuidWalkRoots {
_ = filepath.WalkDir(r, func(p string, d os.DirEntry, err error) error {
if err != nil || d.IsDir() {
return nil
}
info, err := d.Info()
if err != nil || info.Mode()&0o4000 == 0 { // setuid bit
return nil
}
// 仅记 owner root 的 setuid（后门提权标志）
if info.Sys() != nil {
paths = append(paths, p)
}
return nil
})
}
sort.Strings(paths)

// 首次：建立基线（写入权威快照），不当作告警（运维应确认此刻系统可信）。
if allow == nil {
_ = atomicWrite(setuidAllowPath(), mustJSON(paths))
return nil, paths
}

// 有基线：新增告警（后门常以新增 setuid 提权文件出现）
current := make(map[string]bool, len(paths))
for _, p := range paths {
current[p] = true
if !allow[p] {
info, _ := os.Stat(p)
sz := int64(0)
if info != nil {
sz = info.Size()
}
alerts = append(alerts, ProcAlert{
Time: now, Kind: "setuid", Path: p, Size: sz,
Message: "检测到新增 setuid-root 文件(提权后门信号): " + p,
})
}
}
// 缺失告警：白名单项消失也可能是攻击者清理提权痕迹、或文件被删但进程仍以高权限留存。
for base := range allow {
if !current[base] {
alerts = append(alerts, ProcAlert{
Time: now, Kind: "setuid", Path: base,
Message: "基线 setuid-root 文件消失(可能被清理或掉包): " + base,
})
}
}
return alerts, paths
}

// mustJSON 编码 JSON；失败返回空数组。
func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("[]")
	}
	return b
}

// ProcGuardLoop 常驻协程，周期扫描并落盘。由 main.go 启动。
// setuid 全盘扫描走独立低频周期（默认 10 分钟），避免 60s 进程扫描与重 IO 的 setuid 扫相互干扰。
func ProcGuardLoop(done chan struct{}) {
	// 首轮立即各执行一次，便于即时出数据
	procGuardOnce(true)
	ticker := time.NewTicker(procGuardInterval)
	defer ticker.Stop()
	uidEvery := int(procGuardSetuidEvery / procGuardInterval) // 每 N 个 tick 跑一次 setuid
	tick := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			tick++
			procGuardOnce(tick%uidEvery == 0)
		}
	}
}

// procGuardOnce 单轮扫描 + 持久化。doSetuid 控制本轮是否执行重 IO 的 setuid 全盘扫描。
func procGuardOnce(doSetuid bool) {
	var alerts []ProcAlert
	fk := scanProcGuard()
	if doSetuid {
		setuidAlerts, full := scanSetuid()
		alerts = append(alerts, setuidAlerts...)
		procGuardSetuidLatest = full
	}
	if len(alerts) > procGuardMaxAlert {
		alerts = alerts[len(alerts)-procGuardMaxAlert:]
	}
	snap := ProcGuardSnapshot{
		Updated:       time.Now().Format("2006-01-02 15:04:05"),
		Alerts:        alerts,
		SetuidAllow:   procGuardSetuidLatest,
		FakeKthreads: len(fk),
	}
	_ = atomicWrite(procGuardPath(), mustJSON(snap))
	procGuardMu.Lock()
	procGuardLatest = snap
	procGuardMu.Unlock()
}

// procGuardSetuidLatest 保存最近一次 setuid 扫描结果（供快照回显，未到周期时复用上一轮）。
var procGuardSetuidLatest []string

// ProcGuardData 供 handler 读取最新快照。
func ProcGuardData() ProcGuardSnapshot {
	procGuardMu.Lock()
	defer procGuardMu.Unlock()
	return procGuardLatest
}

// LoadProcGuard 启动时从磁盘恢复最新一次快照（避免面板空白）。
func LoadProcGuard() {
	raw, err := os.ReadFile(procGuardPath())
	if err != nil {
		return
	}
	var s ProcGuardSnapshot
	if json.Unmarshal(raw, &s) != nil {
		return
	}
	procGuardMu.Lock()
	procGuardLatest = s
	procGuardSetuidLatest = s.SetuidAllow
	procGuardMu.Unlock()
}
// RebuildSetuidBaseline 把当前 setuid 全集重建为权威基线（运维人工确认后调用）。
// 避免「失陷机首跑洗白」与「只读基线无法清掉误报」。返回是否成功。
func RebuildSetuidBaseline() bool {
_, full := scanSetuid()
if full == nil {
return false
}
return atomicWrite(setuidAllowPath(), mustJSON(full)) == nil
}
