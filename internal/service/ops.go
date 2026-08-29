package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// isRelaySelf 判断本机是否就是中转机（接口地址包含 relay IP 则无需 ssh 同步自己）。
func isRelaySelf() bool {
	relayIP := Conf().RelayHost
	if i := strings.Index(relayIP, "@"); i >= 0 {
		relayIP = relayIP[i+1:]
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipn := a.(*net.IPNet); ipn != nil && ipn.IP.String() == relayIP {
			return true
		}
	}
	return false
}

// notifyBan 封禁通知：执行用户配置的命令，注入 BAN_* 环境变量。
func notifyBan(ip, reason, location, when string) {
	cmd := Conf().NotifyCmd
	if strings.TrimSpace(cmd) == "" {
		return
	}
	c := exec.Command("sh", "-c", cmd)
	c.Env = append(os.Environ(),
		"BAN_IP="+ip,
		"BAN_REASON="+reason,
		"BAN_LOCATION="+location,
		"BAN_TIME="+when,
	)
	if err := c.Run(); err != nil {
		fmt.Println("[notify] failed:", err)
	}
}

// syncWhitelistToF2B 把 defender 白名单同步进 fail2ban 各 jail 的 ignoreip。
// 背景：defender 与 fail2ban 是两套独立封禁体系，白名单互不相通——
// 曾出现"自己人 IP 被 frps-ssh 按高频连接误封"（20260829 事件）。
// 双保险：1) fail2ban-client 运行时 addignoreip（立即生效）；
//         2) jail 配置文件持久化（防 fail2ban 重启丢失），仅处理含 ignoreip 行的 conf。
func syncWhitelistToF2B(whitelist []string) {
	if len(whitelist) == 0 {
		return
	}
	jails := []string{"frps-ssh", "sshd"}
	for _, ip := range whitelist {
		for _, j := range jails {
			_ = exec.Command("fail2ban-client", "set", j, "addignoreip", ip).Run()
		}
	}
	// 持久化到 frps-ssh.conf（该文件已有 ignoreip 行；sshd jail 未自定义则跳过）
	conf := "/etc/fail2ban/jail.d/frps-ssh.conf"
	data, err := os.ReadFile(conf)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	have := map[string]bool{}
	for _, ip := range whitelist {
		have[ip] = true
	}
	changed := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "ignoreip") {
			fields := strings.Fields(line[strings.Index(line, "=")+1:])
			for _, f := range fields {
				have[f] = true
			}
			var out []string
			for f := range have {
				out = append(out, f)
			}
			sort.Strings(out)
			lines[i] = "ignoreip = " + strings.Join(out, " ")
			changed = true
			break
		}
	}
	if changed {
		_ = os.WriteFile(conf, []byte(strings.Join(lines, "\n")), 0o644)
		_ = exec.Command("fail2ban-client", "reload", "frps-ssh").Run()
	}
}

// collectEvidence 封禁时自动取证：抓取该 IP 的日志行 + 当前会话，落盘 data/evidence/。
func collectEvidence(ip, reason string) {
	dir := filepath.Join(dataDir(), "evidence")
	_ = os.MkdirAll(dir, 0o755)
	name := filepath.Join(dir, fmt.Sprintf("%s_%s.log", ip, time.Now().Format("20060102_150405")))
	var sb strings.Builder
	fmt.Fprintf(&sb, "# 封禁自动取证  IP=%s  原因=%s  时间=%s\n\n", ip, reason, time.Now().Format("2006-01-02 15:04:05"))
	// 1) auth 日志中该 IP 的全部记录（优先文件，退回 journalctl）
	out, err := exec.Command("sh", "-c",
		"(grep -h '"+ip+"' /var/log/auth.log /var/log/secure 2>/dev/null || journalctl -u ssh -u sshd --no-pager 2>/dev/null | grep '"+ip+"') | tail -300").Output()
	if err == nil && len(out) > 0 {
		sb.WriteString("## 相关日志(最近300行)\n")
		sb.Write(out)
		sb.WriteString("\n")
	}
	// 2) 当时在线会话
	if out, err := exec.Command("sh", "-c", "w; echo; last -20").Output(); err == nil {
		sb.WriteString("## 当时会话与最近登录\n")
		sb.Write(out)
		sb.WriteString("\n")
	}
	_ = os.WriteFile(name, []byte(sb.String()), 0o600)
}
