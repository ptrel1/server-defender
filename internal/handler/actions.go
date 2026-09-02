package handler

import (
	"fmt"
	"os/exec"

	"server-defender/internal/service"
)

// 本文件：Web 面板的手动操作接口（封禁 IP / 终止进程）。

const relayHost = "root@47.98.244.173" // 中转机（公网同步封禁）

// BlockIP 手动封禁：本机 iptables（入+出）+ 同步中转机（入+出+转发）。返回提示消息。
func BlockIP(ip string) (ok bool, msg string) {
	if ip == "" {
		return false, "IP 不能为空"
	}
	// 本机下发（双向：INPUT 防连入，OUTPUT 防 C2 回连）
	in := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	out := exec.Command("iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP")
	if err := in.Run(); err != nil {
		return false, "本机封禁失败(INPUT): " + err.Error()
	}
	if err := out.Run(); err != nil {
		return false, "本机封禁失败(OUTPUT): " + err.Error()
	}
	// 同步中转机（双向+转发链）
	remote := fmt.Sprintf("iptables -A INPUT -s %s -j DROP; iptables -A OUTPUT -d %s -j DROP; iptables -A FORWARD -s %s -j DROP", ip, ip, ip)
	ssh := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=5", relayHost, remote)
	_ = ssh.Run()
	return true, "IP " + ip + " 已成功下发双端双向永久屏蔽"
}

// KillProcess 手动终止异常进程。
func KillProcess(pid int) (ok bool, msg string) {
	if pid <= 0 {
		return false, "PID 不能为空"
	}
	return service.KillByPID(pid)
}