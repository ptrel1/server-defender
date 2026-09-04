package service

import (
"strings"
"testing"
)

// 核心：resolveSource 应把可疑 PID 回溯到触发环节（父链 → PAM/SSH/cron）。
func TestResolveSource_TracePAM(t *testing.T) {
execs := []AuditExec{
{PID: 1, PPID: 0, Comm: "systemd", Exe: "/usr/lib/systemd/systemd"},
{PID: 100, PPID: 1, Comm: "pam_exec.so", Exe: "/usr/lib/security/pam_exec.so"},
{PID: 2159, PPID: 100, Comm: "pam-helper", Exe: "/usr/libexec/pam-helper"},
}
r := resolveSource(2159, execs)
t.Logf("来源画像: target=%s parent=%s trigger=%s chain=%v",
r.TargetExe, r.ParentExe, r.Triggered, strings.Join(r.Chain, " -> "))
if !strings.Contains(r.Triggered, "PAM") {
t.Errorf("期望 PAM 触发判定, 实际: %s", r.Triggered)
}
if len(r.Chain) < 3 {
t.Errorf("期望不少于3级父链(systemd->pam_exec->pam-helper), 实际 %d", len(r.Chain))
}
}

// 单测 SSH 会话触发场景。
func TestResolveSource_TraceSSH(t *testing.T) {
execs := []AuditExec{
{PID: 1, PPID: 0, Comm: "systemd", Exe: "/usr/lib/systemd/systemd"},
{PID: 500, PPID: 1, Comm: "sshd", Exe: "/usr/bin/sshd"},
{PID: 4200, PPID: 500, Comm: "sh", Exe: "/usr/bin/sh"},
}
r := resolveSource(4200, execs)
t.Logf("trigger=%s chain=%v", r.Triggered, strings.Join(r.Chain, " -> "))
if !strings.Contains(r.Triggered, "SSH") {
t.Errorf("期望 SSH 触发判定, 实际: %s", r.Triggered)
}
}

// PID 不在快照中：应明确提示不可追溯(如已超审计保留期)。
func TestResolveSource_NotInSnapshot(t *testing.T) {
execs := []AuditExec{{PID: 1, PPID: 0, Comm: "systemd", Exe: "/usr/lib/systemd/systemd"}}
r := resolveSource(999999, execs)
t.Logf("trigger=%s", r.Triggered)
if !strings.Contains(r.Triggered, "不可追溯") && !strings.Contains(r.Triggered, "无") {
t.Errorf("期望提示无法追溯, 实际: %s", r.Triggered)
}
}
