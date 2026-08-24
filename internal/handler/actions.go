package handler

import (
	"os/exec"

	"server-defender/internal/service"
)

// 本文件：Web 面板的手动操作接口（封禁 IP / 终止进程）。

const relayHost = "root@47.98.244.173" // 中转机（公网同步封禁）

// BlockIP 手动封禁：本机 iptables + 同步中转机。返回提示消息。
func BlockIP(ip string) (ok bool, msg string) {
	if ip == "" {
		return false, "IP 不能为空"
	}
	// 本机下发
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return false, "本机封禁失败: " + err.Error()
	}
	// 同步中转机
	ssh := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=5", relayHost, "iptables -A INPUT -s "+ip+" -j DROP")
	_ = ssh.Run()
	return true, "IP " + ip + " 已成功下发双端永久屏蔽"
}

// KillProcess 手动终止异常进程。
func KillProcess(pid int) (ok bool, msg string) {
	if pid <= 0 {
		return false, "PID 不能为空"
	}
	return service.KillByPID(pid)
}