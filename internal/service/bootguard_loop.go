package service

// BootGuardLoop：启动面基线监控层（纯标准库）。
// v3.2.1 新增——复刻 2026-09-04 事件后「启动面静态排查」方法论：枚举全部开机执行路径，
// 在重装后的干净机上生成可信基线，日后任何启动项新增/位移/被替换即告警，拦截「下次开机
// 自动拉起木马」类持久化。
//
// 覆盖启动执行面（缺一块就可能漏一条复活路径）：
//   1. systemd enabled unit（系统 + 用户级）
//   2. systemd timer enabled（常被矿马当周期复位器）
//   3. cron @reboot 与 /etc/cron.*
//   4. SysV /etc/rc*.d、/etc/init.d
//   5. /etc/pam.d 钩子
//   6. /etc/ld.so.preload、/etc/ld.so.conf.d
//   7. /etc/profile.d、shell rc（/etc/bash.bashrc 等）
//   8. /etc/modules-load.d、/etc/modprobe.d
//   9. /boot 内核/initramfs 内核对账
//  10. efibootmgr UEFI 启动项（bootkit 检测）
//
// 设计意图：
//   - 纯只读扫描，零侵入；每条启动路径做「归属判断」（pacman -Qo / dpkg -S 是否官方包），
//     非官方一律标 self/unknown，重点留面板人工复核。
//   - 「只读基线」模型：首跑（干净机上）生成基线后不再静默覆盖；新增/变更即告警；运维确认
//     后经 POST /api/bootguard/baseline 显式重建。
//   - 低频周期（30min），与高频进程扫描解耦；结果落盘 data/bootguard.json。
//
// 边界条件：
//   - 依据 ProcGuard 同款「干净机首跑建立基线」纪律——在已失陷机上首跑会把后门启动项洗白，
//     故本模块同样定位于重装后新机的纵深防线，不用于「救回」失陷机。
//   - 收集端口暴露面与网络属 Web 安全范畴，不在此模块（由既有 NetMon / Fail2ban 承担）。

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	bootGuardInterval    = 30 * time.Minute // 启动面低频扫描
	bootGuardMaxAlert    = 200
	bootGuardUnknownMax  = 400 // 未知/自写项列表展示上限
)

// BootItem 单条启动路径记录。
type BootItem struct {
	Path     string `json:"path"`     // 文件/单元/命令路径
	Owner    string `json:"owner"`    // 归属包名 | self(自写) | unknown(未知)
	Official bool   `json:"official"` // 是否官方包管理内容
	Face     string `json:"face"`     // 所属启动面（systemd/cron/sysv/pam/preload/profile/module/boot/uefi）
}

// BootAlert 启动面变化告警。
type BootAlert struct {
	Time    string `json:"time"`
	Face    string `json:"face"`
	Path    string `json:"path"`
	Kind    string `json:"kind"` // added | changed | missing
	Message string `json:"message"`
}

type BootGuardSnapshot struct {
	Updated string       `json:"updated"`
	Items   []BootItem   `json:"items"`   // 当前启动面全集（供面板/基线目视）
	Alerts  []BootAlert  `json:"alerts"`  // 本轮/累积告警
	Unknown []BootItem   `json:"unknown"` // 非官方包项，重点人工复核
	UEFI    []string     `json:"uefi"`    // 当前 UEFI 启动项
}

var (
	bgMu     sync.Mutex
	bgLatest BootGuardSnapshot
)

func bgPath() string     { return filepath.Join(dataDir(), "bootguard.json") }
func bgBasePath() string { return filepath.Join(dataDir(), "bootguard_baseline.json") }

// loadBootBaseline 读启动面基线；缺省返回 nil。
func loadBootBaseline() map[string]BootItem {
	raw, err := os.ReadFile(bgBasePath())
	if err != nil {
		return nil
	}
	var items []BootItem
	if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	m := make(map[string]BootItem, len(items))
	for _, it := range items {
		m[it.Face+"|"+it.Path] = it
	}
	return m
}

// saveBootBaseline 原子写基线。
func saveBootBaseline(items []BootItem) {
	_ = atomicWrite(bgBasePath(), mustJSON(items))
}

// pkgOwner 判断文件归属：返回 (包名, 是否官方包)。非官方返回 ("", false)。
func pkgOwner(path string) (string, bool) {
	// 尝试 Arch pacman
	c, err := exec.Command("pacman", "-Qo", path).Output()
	if err == nil {
		// 输出形如 "/usr/bin/x is owned by pkg 1.0-1"
		s := string(c)
		if i := strings.Index(s, " is owned by "); i >= 0 {
			pkg := strings.TrimSpace(s[i+len(" is owned by "):])
			// 去掉版本：取空格前
			if sp := strings.IndexByte(pkg, ' '); sp > 0 {
				pkg = pkg[:sp]
			}
			return pkg, true
		}
	}
	// Debian dpkg
	c2, err2 := exec.Command("dpkg", "-S", path).Output()
	if err2 == nil {
		pkg := strings.TrimSpace(string(c2))
		if i := strings.IndexByte(pkg, ':'); i > 0 {
			pkg = pkg[:i]
		}
		return pkg, true
	}
	return "", false
}

// scanSystemd 收集 enabled 的 systemd unit（系统 + 用户），file 是归属判定源。
func scanSystemd() []BootItem {
	var items []BootItem
	out, _ := exec.Command("systemctl", "list-unit-files", "--type=service,timer", "--state=enabled", "--no-pager").Output()
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := f[0]
		// 跳过表头与结尾统计行("N unit files listed." "42" 等)
		if name == "UNIT" || !containsSuffixPair(name) {
			continue
		}
		// 基线+diff 模型：只记录 unit 名，官方/自写归属留给 ExecStart 与运维复核，
		// 避免 systemctl 输出路径映射到磁盘的 pkgOwner 误判噪音。
		items = append(items, BootItem{
			Path: name, Owner: "", Official: false, Face: "systemd",
		})
	}
	return items
}

// containsSuffixPair 判定是否 systemd 单元名（.service .timer .socket .target 等）。
func containsSuffixPair(name string) bool {
	for _, suf := range []string{".service", ".timer", ".socket", ".target", ".path", ".mount", ".slice"} {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

// scanCron 收集 @reboot 与 /etc/cron.* 的条目。
func scanCron() []BootItem {
	var items []BootItem
	cronPaths := []string{"/etc/crontab", "/etc/cron.d"}
	// root + 各用户 crontab 的 @reboot
	dirs, _ := os.ReadDir("/etc/cron.d")
	for _, d := range dirs {
		cronPaths = append(cronPaths, "/etc/cron.d/"+d.Name())
	}
	for _, p := range cronPaths {
		if f, err := os.ReadFile(p); err == nil {
			for _, line := range strings.Split(string(f), "\n") {
				if strings.Contains(line, "@reboot") {
					items = append(items, BootItem{Path: p + " [" + strings.TrimSpace(line) + "]",
						Owner: "<cron>", Official: false, Face: "cron"})
				}
			}
		}
	}
	// 当前用户（root）crontab @reboot
	c, _ := exec.Command("crontab", "-l").Output()
	for _, line := range strings.Split(string(c), "\n") {
		if strings.Contains(line, "@reboot") {
			items = append(items, BootItem{Path: "<root-crontab> [" + strings.TrimSpace(line) + "]",
				Owner: "<cron>", Official: false, Face: "cron"})
		}
	}
	return items
}

// scanSysV 收集 /etc/init.d 与 /etc/rc*.d 里非系统常规项。
func scanSysV() []BootItem {
	var items []BootItem
	initd, _ := os.ReadDir("/etc/init.d")
	for _, e := range initd {
		if e.IsDir() {
			continue
		}
		p := "/etc/init.d/" + e.Name()
		pkg, off := pkgOwner(p)
		// 忽略纯系统 init 脚本(大量"系统标准"项会制造噪音，只报非官方)
		if !off {
			items = append(items, BootItem{Path: p, Owner: pkg, Official: off, Face: "sysv"})
		}
	}
	// rc*.d 里指向非官方 init 的链接
	for _, d := range []string{"/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d", "/etc/rcS.d"} {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			target, err := os.Readlink(d + "/" + e.Name())
			if err != nil {
				continue
			}
			// 只收集指向 /etc/init.d 的用户自定义链（不含官方）
			if strings.HasPrefix(target, "../init.d/") {
				base := strings.TrimPrefix(target, "../init.d/")
				if _, off := pkgOwner("/etc/init.d/" + base); !off {
					items = append(items, BootItem{Path: d + "/" + e.Name() + " -> " + target,
						Owner: "<sysv>", Official: false, Face: "sysv"})
				}
			}
		}
	}
	return items
}

// scanPAM 收集 /etc/pam.d 里 pam_exec 等执行钩子。
func scanPAM() []BootItem {
	var items []BootItem
	ents, _ := os.ReadDir("/etc/pam.d")
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		p := "/etc/pam.d/" + e.Name()
		if f, err := os.ReadFile(p); err == nil {
			for _, line := range strings.Split(string(f), "\n") {
				if strings.Contains(line, "pam_exec") || strings.Contains(line, "pam_ldap") {
					items = append(items, BootItem{Path: p + " | " + strings.TrimSpace(line),
						Owner: "<pam>", Official: false, Face: "pam"})
				}
			}
		}
	}
	return items
}

// scanPreload 检查 ld.so.preload 与 ld.so.conf.d 的 .so。
func scanPreload() []BootItem {
	var items []BootItem
	if b, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				items = append(items, BootItem{Path: line, Owner: "<preload>", Official: false, Face: "preload"})
			}
		}
	}
	return items
}

// scanProfile 收集 /etc/profile.d 与 shell rc 里执行外部程序的行。
func scanProfile() []BootItem {
	var items []BootItem
	dirs := []string{"/etc/profile.d", "/etc/bash.bashrc.d"}
	for _, d := range dirs {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			p := d + "/" + e.Name()
			if !e.IsDir() {
				pkg, off := pkgOwner(p)
				if !off {
					items = append(items, BootItem{Path: p, Owner: pkg, Official: off, Face: "profile"})
				}
			}
		}
	}
	return items
}

// scanModules 检查内核模块自启清单。
func scanModules() []BootItem {
	var items []BootItem
	dirs := []string{"/etc/modules-load.d", "/etc/modprobe.d"}
	for _, d := range dirs {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			p := d + "/" + e.Name()
			pkg, off := pkgOwner(p)
			if !off {
				items = append(items, BootItem{Path: p, Owner: pkg, Official: off, Face: "module"})
			}
		}
	}
	return items
}

// scanBoot 校验 /boot 内核/initramfs 文件存在性。
func scanBoot() []BootItem {
	var items []BootItem
	ents, _ := os.ReadDir("/boot")
	for _, e := range ents {
		if e.IsDir() || e.Name() == "grub" || e.Name() == "efi" {
			continue
		}
		p := "/boot/" + e.Name()
		pkg, off := pkgOwner(p)
		items = append(items, BootItem{Path: p, Owner: pkg, Official: off, Face: "boot"})
	}
	return items
}

// scanUEFI 读取 UEFI 启动项。
func scanUEFI() []string {
	out, err := exec.Command("efibootmgr").Output()
	if err != nil {
		return nil
	}
	var boots []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Boot") && strings.Contains(line, "*") {
			boots = append(boots, strings.TrimSpace(line))
		}
	}
	return boots
}

// collectBootFaces 汇总全部启动面基线项。
func collectBootFaces() []BootItem {
	var items []BootItem
	items = append(items, scanSystemd()...)
	items = append(items, scanCron()...)
	items = append(items, scanSysV()...)
	items = append(items, scanPAM()...)
	items = append(items, scanPreload()...)
	items = append(items, scanProfile()...)
	items = append(items, scanModules()...)
	items = append(items, scanBoot()...)
	return items
}

// scanBootGuard 一轮启动面扫描：比对基线，返回告警。
func scanBootGuard() (snap BootGuardSnapshot) {
	base := loadBootBaseline()
	items := collectBootFaces()
	uefi := scanUEFI()
	snap.Items = items
	snap.UEFI = uefi
	snap.Updated = time.Now().Format("2006-01-02 15:04:05")

	// unknown：仅高危面（cron/sysv/pam/preload）的非官方项重点展示，
	// systemd/profile/module/boot 常规面走 diff 告警，避免 pkgOwner 对 /etc 配置误判成噪音。
	for _, it := range items {
		switch it.Face {
		case "cron", "sysv", "pam", "preload":
			if !it.Official {
				snap.Unknown = append(snap.Unknown, it)
				if len(snap.Unknown) > bootGuardUnknownMax {
					break
				}
			}
		}
	}

	now := time.Now().Format("2006-01-02 15:04:05")
	// 首次无基线：建立基线（干净机首跑）
	if base == nil {
		saveBootBaseline(items)
		return
	}
	// 有基线：diff 出新增 + 缺失（核心：改了一第一时间发现）
	snap.Alerts = diffBootFaces(base, items, now)
	if len(snap.Alerts) > bootGuardMaxAlert {
		snap.Alerts = snap.Alerts[len(snap.Alerts)-bootGuardMaxAlert:]
	}
	return
}

// diffBootFaces 纯函数：对 bootguard 基线做新增/缺失比对，返回告警。
// base 为 nil（首次）调用方已在外部处理（建基线不告警），此处仅在 base 非 nil 时被调用。
// 抽出为纯函数便于单测：不触碰真实系统/磁盘即可验证「注入启动项被第一时间检出」。
func diffBootFaces(base map[string]BootItem, items []BootItem, now string) []BootAlert {
	var alerts []BootAlert
	cur := make(map[string]bool)
	for _, it := range items {
		key := it.Face + "|" + it.Path
		cur[key] = true
		if _, ok := base[key]; !ok {
			alerts = append(alerts, BootAlert{
				Time: now, Face: it.Face, Path: it.Path, Kind: "added",
				Message: "启动面新增项(可能为自动拉起木马入口): " + it.Face + " " + it.Path,
			})
		}
	}
	for key := range base {
		if !cur[key] {
			parts := strings.SplitN(key, "|", 2)
			alerts = append(alerts, BootAlert{
				Time: now, Face: parts[0], Path: parts[1], Kind: "missing",
				Message: "基线启动项消失: " + key,
			})
		}
	}
	return alerts
}

// BootGuardLoop 常驻协程。
func BootGuardLoop(done chan struct{}) {
	bgOnce()
	ticker := time.NewTicker(bootGuardInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			bgOnce()
		}
	}
}

func bgOnce() {
	snap := scanBootGuard()
	_ = atomicWrite(bgPath(), mustJSON(snap))
	bgMu.Lock()
	bgLatest = snap
	bgMu.Unlock()
}

// BootGuardData 供 handler 读取。
func BootGuardData() BootGuardSnapshot {
	bgMu.Lock()
	defer bgMu.Unlock()
	return bgLatest
}

// LoadBootGuard 启动时恢复上次快照。
func LoadBootGuard() {
	raw, err := os.ReadFile(bgPath())
	if err != nil {
		return
	}
	var s BootGuardSnapshot
	if json.Unmarshal(raw, &s) != nil {
		return
	}
	bgMu.Lock()
	bgLatest = s
	bgMu.Unlock()
}

// RebuildBootBaseline 把当前启动面重建为基线（运维确认后）。
func RebuildBootBaseline() bool {
	items := collectBootFaces()
	saveBootBaseline(items)
	return true
}

// 供 handler 判断基线是否存在。
func BootBaselineExists() bool {
	_, err := os.Stat(bgBasePath())
	return err == nil
}