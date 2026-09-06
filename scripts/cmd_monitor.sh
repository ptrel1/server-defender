#!/bin/bash
# cmd_monitor.sh — 可疑命令监控（方案A配套，每5分钟 cron）
# 设计意图：增量扫描 auditd execve 记录，命中可疑模式(下载执行/持久化/提权)即告警
# 告警日志: /home/a1/cmd_alarm.log；状态文件记录上次检查位置，避免重复告警
# 边界: 只读+追加日志，不自动清理（清理仍由 auto_clean.sh 决策）；依赖 auditd

LOG=/home/a1/cmd_alarm.log
STATE=/tmp/cmd_monitor_offset
AUDIT_LOG=/var/log/audit/audit.log
PATTERNS='curl[^"]*\|(ba)?sh|wget[^"]*\|(ba)?sh|authorized_keys|chmod [-u+]*[su]*[+ ]*s|useradd|/tmp/[a-zA-Z0-9._-]+\.sh|/dev/tcp/'

{ echo "===== [$(date "+%F %T")] cmd_monitor run ====="
  sudo -n true 2>/dev/null || exec sudo -S bash "$0" < /dev/null
  [ -f "$STATE" ] || echo 0 > "$STATE"
  last=$(cat "$STATE")
  cur=$(stat -c %s $AUDIT_LOG 2>/dev/null || echo 0)
  # 日志轮转: 当前比记录点小 → 从头查
  [ "$cur" -lt "$last" ] && last=0
  tail -c +$((last+1)) $AUDIT_LOG 2>/dev/null | grep -a EXECVE | \
    grep -aE "$PATTERNS" | while read -r line; do
        ts=$(echo "$line" | grep -aoE "audit\([0-9.]+" | tr -d 'audit(' | cut -d. -f1)
        t=$(date -d @$ts "+%F %T" 2>/dev/null)
        echo "[$t] ${line:0:400}"
    done >> $LOG
  echo $cur > "$STATE"
  } >> ${LOG}.run 2>&1
