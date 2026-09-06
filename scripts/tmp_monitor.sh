#!/bin/bash
# tmp_monitor.sh - 监控 /tmp 隐藏可执行文件 + crontab + systemd user service 变更
# v2.0 (20260906): 配置外置 /etc/defender-monitor.conf；root 身份运行（-u 指定监控用户）
set -u
CONFIG=/etc/defender-monitor.conf
[ -f "$CONFIG" ] && . "$CONFIG" || { echo "missing $CONFIG"; exit 1; }

LOG="$LOGDIR/tmp_monitor.log"
TMP_CACHE="$CACHE_DIR/tmp_monitor.cache"
CRON_CACHE="$CACHE_DIR/cron_monitor.cache"
SD_CACHE="$CACHE_DIR/sd_monitor.cache"
UHOME="$MONITOR_USER_HOME"
mkdir -p "$CACHE_DIR"

echo "[$(date "+%Y-%m-%d %H:%M:%S")] 检查开始" >> "$LOG"

# 1. 监控 /tmp 隐藏可执行文件
current_tmp=$(ls -la /tmp/ 2>/dev/null | grep '^-...x' | grep '^\.' | grep -vE '\.X|\.ICE|\.font|\.wine|\.com\.' | awk '{print $NF}')
CHANGED=""

if [ ! -f "$TMP_CACHE" ]; then
    echo "$current_tmp" > "$TMP_CACHE"
else
    new_tmp=$(comm -13 <(sort "$TMP_CACHE") <(echo "$current_tmp" | sort) 2>/dev/null)
    if [ -n "$new_tmp" ]; then
        echo "⚠️  /tmp 新增隐藏可执行文件!" >> "$LOG"
        echo "$new_tmp" >> "$LOG"
        CHANGED=1
    fi
    echo "$current_tmp" > "$TMP_CACHE"
fi

# 2. 监控 crontab 变更（root 运行须 -u 指定监控用户）
current_cron=$(crontab -u "$MONITOR_USER" -l 2>/dev/null | md5sum)
if [ ! -f "$CRON_CACHE" ]; then
    echo "$current_cron" > "$CRON_CACHE"
else
    if [ "$(cat "$CRON_CACHE")" != "$current_cron" ]; then
        echo "⚠️  crontab 被修改!" >> "$LOG"
        crontab -u "$MONITOR_USER" -l 2>/dev/null >> "$LOG"
        echo "$current_cron" > "$CRON_CACHE"
        CHANGED=1
    fi
fi

# 3. 监控 systemd user service 变更（监控用户家目录，非 root 的）
usd="$UHOME/.config/systemd/user"
sd_files=$(find "$usd" -name '*.service' -type f 2>/dev/null | sort | xargs md5sum 2>/dev/null)
current_sd=$(echo "$sd_files" | md5sum)
if [ ! -f "$SD_CACHE" ]; then
    echo "$current_sd" > "$SD_CACHE"
else
    if [ "$(cat "$SD_CACHE")" != "$current_sd" ]; then
        echo "⚠️  systemd user service 被修改!" >> "$LOG"
        find "$usd" -name '*.service' -newer "$SD_CACHE" -ls 2>/dev/null >> "$LOG"
        echo "$current_sd" > "$SD_CACHE"
        CHANGED=1
    fi
fi

# 有变更时触发自动清理
[ -n "$CHANGED" ] && "$BIN_DIR/auto_clean.sh" "监控检测到变更"

exit 0
