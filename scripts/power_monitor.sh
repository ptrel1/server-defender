#!/bin/bash
# power_monitor.sh - 功率异常监控（CPU负载/GPU功耗/温度/高CPU进程）
# v2.0 (20260906): 配置外置 /etc/defender-monitor.conf；root 身份运行
set -u
CONFIG=/etc/defender-monitor.conf
[ -f "$CONFIG" ] && . "$CONFIG" || { echo "missing $CONFIG"; exit 1; }

LOG="$LOGDIR/power_monitor.log"
ALARM_LOG="$LOGDIR/power_alarm.log"
BIN_DIR=${BIN_DIR:-/usr/local/sbin}

# ===== 采集数据 =====
LOAD=$(uptime | grep -oP 'average: \K[^,]+' | tr -d ' ')
LOAD_NUM=$(echo "$LOAD" | head -1)

GPU_POWER=$(nvidia-smi --query-gpu=power.draw --format=csv,noheader,nounits 2>/dev/null | head -1 | tr -d ' ')
GPU_TEMP=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits 2>/dev/null | head -1 | tr -d ' ')
GPU_UTIL=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null | head -1 | tr -d ' ')

# ===== 检查可疑高CPU进程 =====
SUSPICIOUS_PROCS=$(ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3+0 > '"$SUSPICIOUS_CPU"' {printf "%s(CPU:%.1f%%) ", $11, $3}' | head -3)

# ===== 评估 =====
ALARM=""
[ "$(echo "$LOAD_NUM > $CPU_LOAD_THRESHOLD" | bc -l 2>/dev/null)" = "1" ] && ALARM="${ALARM}CPU_LOAD:${LOAD_NUM} "
[ "$(echo "${GPU_POWER:-0} > $GPU_POWER_THRESHOLD" | bc -l 2>/dev/null)" = "1" ] && ALARM="${ALARM}GPU_POWER:${GPU_POWER}W "
[ "$(echo "${GPU_TEMP:-0} > $GPU_TEMP_THRESHOLD" | bc -l 2>/dev/null)" = "1" ] && ALARM="${ALARM}GPU_TEMP:${GPU_TEMP}°C "
[ -n "$SUSPICIOUS_PROCS" ] && ALARM="${ALARM}SUSPICIOUS_PROCS:${SUSPICIOUS_PROCS}"

# ===== 记录日志 =====
echo "[$(date "+%Y-%m-%d %H:%M:%S")] LOAD=${LOAD_NUM} GPU=${GPU_POWER:-N/A}W/${GPU_TEMP:-N/A}°C/${GPU_UTIL:-N/A}%" >> "$LOG"

if [ -n "$ALARM" ]; then
    echo "==========================================" >> "$ALARM_LOG"
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] ⚠️ 异常告警!" >> "$ALARM_LOG"
    echo "  $ALARM" >> "$ALARM_LOG"
    echo "  TOP 进程:" >> "$ALARM_LOG"
    ps aux --sort=-%cpu 2>/dev/null | head -6 >> "$ALARM_LOG"
    echo "==========================================" >> "$ALARM_LOG"
    echo "⚠️ 功率异常: $ALARM"
    "$BIN_DIR/auto_clean.sh" "$ALARM"
fi
