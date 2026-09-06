#!/bin/bash
# ========================================
# 取证 + 自动清理脚本
# 检测到挖矿后: 先取证、再封禁、最后清理
# 每次触发产生一个带时间戳的证据包
# ========================================

# v2.0 (20260906): 配置外置 /etc/defender-monitor.conf；root 身份运行，sudo 已移除
set -u
CONFIG=/etc/defender-monitor.conf
[ -f "$CONFIG" ] && . "$CONFIG" || { echo "missing $CONFIG"; exit 1; }
LOG="$LOGDIR/auto_clean.log"

# ========== 白名单：这些 IP 永远不会被自动封禁 ==========
# 用于阻止误封基础设施 IP（frp 隧道、内网网关等）
WHITELIST_IPS=(
    "47.98.244.173"  # 阿里云公网服务器（frps）
)

# ========== 进程白名单：这些进程永远不会被当作木马 kill ==========
# 用于防止误杀正常业务/游戏进程（尤其 GPU 计算进程）
# 匹配规则：进程名或完整命令行中含以下关键词则跳过
WHITELIST_PROCS=(
    "Overwatch"     # 守望先锋游戏
    "Battle.net"    # 战网客户端
    "OxygenNotIncluded"  # 缺氧 (Oxygen Not Included) 游戏
    "steam"         # Steam 客户端（含 steamwebhelper/steamapps）
    "steamwebhelper"
    "comfyui"       # ComfyUI 绘图（GPU）
    "kilo"          # Kilo/AI 助手（避免误杀）
    "wine"          # Wine/Proton 运行时
    "xalia"
    "containerd"    # 正常容器运行时
    "promtail"      # Loki 日志采集（docker 内正常运行）
)

# 判断某 PID 是否命中进程白名单（命中返回 0）
is_whitelisted_proc() {
    local pid="$1"
    local cmd
    cmd=$(ps -p "$pid" -o args= 2>/dev/null)
    local comm
    comm=$(ps -p "$pid" -o comm= 2>/dev/null)
    for kw in "${WHITELIST_PROCS[@]}"; do
        case "$cmd$comm" in
            *"$kw"*) return 0 ;;
        esac
    done
    return 1
}

cleanup() {
    local reason="$1"
    local TS=$(date "+%Y%m%d_%H%M%S")
    local DIR="${EVIDENCE_DIR}/${TS}"
    mkdir -p "$DIR"

    echo "==========================================" >> "$LOG"
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] 🔴 触发清理: $reason" >> "$LOG"
    echo "  证据保存至: $DIR" >> "$LOG"

    # ========== 取证阶段（清理前保留所有线索）==========

    # — 快照 A: 系统概览 —
    uptime > "$DIR/uptime.txt"
    top -b -n 1 > "$DIR/top.txt" 2>/dev/null
    nvidia-smi > "$DIR/nvidia-smi.txt" 2>/dev/null

    # — 快照 B: 完整进程树 —
    ps aux --sort=-%cpu > "$DIR/ps_all.txt" 2>/dev/null
    pstree -a -p -l > "$DIR/pstree.txt" 2>/dev/null

    # — 快照 C: 网络连接 —
    ss -tlnp > "$DIR/ss_listen.txt" 2>/dev/null
    ss -tnp | grep ESTAB > "$DIR/ss_established.txt" 2>/dev/null

    # — 快照 D: crontab —
    crontab -u "$MONITOR_USER" -l > "$DIR/crontab_before.txt" 2>/dev/null

    # — 快照 E: /tmp 文件清单 —
    ls -la /tmp/ > "$DIR/tmp_list.txt" 2>/dev/null

    # — 快照 F: 可疑进程详情 —
    # 找出可疑 PID
    SUSPICIOUS=""
    # 特征: 隐藏文件进程 (以.开头) + CPU>50%
    # 注意: GPU 计算进程全列入会导致误杀游戏(如 Overwatch)，故用白名单过滤
    while IFS=' ' read -r pid cpu gpu name; do
        [ -z "$pid" ] && continue
        is_whitelisted_proc "$pid" && continue
        SUSPICIOUS="$SUSPICIOUS $pid"
    done < <(
        ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3+0>50 && $11 ~ /^\./' | awk '{print $2, $3, "0", $11}'
        nvidia-smi --query-compute-apps=pid,process_name --format=csv,noheader 2>/dev/null | awk -F',' '{print $1, "0", "0", $2}'
    )

    # 已知的恶意进程名关键词（仅匹配伪装进程，排除系统正常服务）
    for kw in "\.ssh-keyd" "\.systemd-hlp" "\.udisks-hlp" "\.rsyslog-hlp" "\.pam-helper" "\.avahi-sock" "\.systemd-hlp"; do
        for pid in $(ps aux 2>/dev/null | grep "$kw" | grep -v grep | grep -v auto_clean | awk '{print $2}'); do
            SUSPICIOUS="$SUSPICIOUS $pid"
        done
    done

    SUSPICIOUS=$(echo "$SUSPICIOUS" | tr ' ' '\n' | sort -un | tr '\n' ' ')

    for pid in $SUSPICIOUS; do
        local pd="$DIR/pid_${pid}"
        mkdir -p "$pd"

        # 进程基本信息
        ps -p "$pid" -o pid,ppid,user,lstart,args > "$pd/info.txt" 2>/dev/null

        # 父进程链（一直追溯到 PID 1）
        echo "Parent chain:" > "$pd/parent_chain.txt"
        cp="$pid"
        for i in $(seq 1 20); do
            ppid=$(ps -o ppid= -p "$cp" 2>/dev/null | tr -d ' ')
            [ -z "$ppid" ] && break
            ps -p "$ppid" -o pid,user,lstart,args --no-headers 2>/dev/null >> "$pd/parent_chain.txt"
            cp="$ppid"
            [ "$cp" = "1" ] || [ "$cp" = "0" ] && break
        done

        # 进程树（显示子进程）
        pstree -aps "$pid" > "$pd/process_tree.txt" 2>/dev/null

        # 网络连接
        ss -tnp 2>/dev/null | grep "$pid" > "$pd/network.txt" 2>/dev/null

        # 打开的文件（排除 socket/pipe）
        ls -la /proc/$pid/fd/ 2>/dev/null | grep -v 'socket\|anon_inode\|pipe\|eventfd' > "$pd/open_files.txt"

        # 环境变量
        cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' > "$pd/environ.txt"

        # 工作目录
        ls -la /proc/$pid/cwd 2>/dev/null > "$pd/cwd.txt"

        # 命令行参数
        cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' > "$pd/cmdline.txt"

        echo "  📸 已取证 PID $pid → $pd" >> "$LOG"
    done

    # ========== 封禁阶段（先断网，防止继续通信）==========

    # 从进程网络连接中提取目标 IP（仅精确匹配对端端口 8029/5001）
    for proto_ip in $(ss -tnp 2>/dev/null | awk '$5 ~ /:(8029|5001)$/ {print $5}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u); do
        # 跳过白名单 IP，防止误封基础设施
        local skip=0
        for wip in "${WHITELIST_IPS[@]}"; do
            [ "$proto_ip" = "$wip" ] && skip=1 && break
        done
        [ "$skip" = "1" ] && continue

        echo "$proto_ip" >> "$DIR/blocked_ips.txt"
        nft add rule ip filter OUTPUT ip daddr "$proto_ip" counter drop 2>/dev/null
        echo "  🚫 封禁矿池: $proto_ip" >> "$LOG"
    done
    nft list ruleset > /etc/nftables.conf 2>/dev/null

    # ========== 清理阶段 ==========

    # — 杀进程 —
    # 双保险: kill 前再次校验白名单，确保不误杀游戏/正常业务进程
    for pid in $SUSPICIOUS; do
        if is_whitelisted_proc "$pid"; then
            echo "  ⏭️  跳过白名单进程 PID $pid（防误杀）" >> "$LOG"
            continue
        fi
        kill -9 "$pid" 2>/dev/null && echo "  ✅ Kill PID $pid" >> "$LOG"
    done

    # — 保存 + 删除 /tmp 恶意文件 —
    mkdir -p "$DIR/malware_samples"
    for f in /tmp/.*; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        echo "$name" | grep -qE '^\.(X|ICE|font|wine|com\.|wsl|tmp_monitor|ps_)' && continue

        # ⚠️ 显式排除共享库(.so)：终端渲染库等正常库常以随机名出现在 /tmp（如 .79dff...so），
        #    曾被误判为木马算法库误删。仅当文件是"ELF 可执行文件"时才当木马处理。
        echo "$name" | grep -qE '\.so$' && continue

        if file "$f" 2>/dev/null | grep -qE 'ELF.*executable'; then
            cp "$f" "$DIR/malware_samples/$name" 2>/dev/null  # 保留样本
            rm -f "$f" && echo "  ✅ 删除 /tmp/$name（已保留样本）" >> "$LOG"
        fi
    done

    # — 清理 crontab —
    crontab -u "$MONITOR_USER" -l > "$DIR/crontab_before.txt" 2>/dev/null
    NEW_CRON=$(crontab -u "$MONITOR_USER" -l 2>/dev/null | grep -vE 'snt-|@reboot.*/tmp|pgrep.*-f|sys\.sh')
    echo "$NEW_CRON" | crontab -u "$MONITOR_USER" - 2>/dev/null
    crontab -u "$MONITOR_USER" -l > "$DIR/crontab_after.txt" 2>/dev/null
    echo "  ✅ crontab 已清理" >> "$LOG"

    # — 清理 systemd user 服务 —
    for svc in clipboardd plugin-indexer session-hook session-metrics ssh-proxy; do
        if runuser -u "$MONITOR_USER" -- systemctl --user list-unit-files 2>/dev/null | grep -q "$svc"; then
            # 保存服务文件副本
            [ -f "$MONITOR_USER_HOME/.config/systemd/user/$svc.service" ] && cp "$MONITOR_USER_HOME/.config/systemd/user/$svc.service" "$DIR/malware_samples/$svc.service"
            [ -f "$MONITOR_USER_HOME/.config/systemd/user/$svc.timer" ] && cp "$MONITOR_USER_HOME/.config/systemd/user/$svc.timer" "$DIR/malware_samples/$svc.timer"
            runuser -u "$MONITOR_USER" -- systemctl --user stop "$svc" 2>/dev/null
            runuser -u "$MONITOR_USER" -- systemctl --user disable "$svc" 2>/dev/null
            runuser -u "$MONITOR_USER" -- systemctl --user mask "$svc" 2>/dev/null
            rm -f "$MONITOR_USER_HOME/.config/systemd/user/$svc.service" "$MONITOR_USER_HOME/.config/systemd/user/$svc.timer" 2>/dev/null
            echo "  ✅ 清理 systemd: $svc" >> "$LOG"
        fi
    done
    runuser -u "$MONITOR_USER" -- systemctl --user daemon-reload 2>/dev/null

    echo "[$(date "+%Y-%m-%d %H:%M:%S")] ✅ 清理完成，证据包: $DIR" >> "$LOG"
    echo "==========================================" >> "$LOG"
}

# 被 power_monitor.sh 触发: 传入告警原因
if [ -n "${1:-}" ]; then
    cleanup "$1"
else
    # 直接调用: 检查当前是否需要清理
    NEED_CLEAN=""

    # 检查 CPU 负载
    LOAD=$(uptime | grep -oP 'average: \K[^,]+' | head -1)
    [ "$(echo "$LOAD > $CPU_LOAD_THRESHOLD" | bc -l 2>/dev/null)" = "1" ] && NEED_CLEAN="CPU_LOAD=${LOAD}"

    # 检查 GPU 功率
    GPU_POWER=$(nvidia-smi --query-gpu=power.draw --format=csv,noheader,nounits 2>/dev/null | head -1 | tr -d ' ')
    [ "$(echo "${GPU_POWER:-0} > $GPU_POWER_THRESHOLD" | bc -l 2>/dev/null)" = "1" ] && NEED_CLEAN="${NEED_CLEAN} GPU_POWER=${GPU_POWER}W"

    # 检查可疑进程
    SUSP_COUNT=$(ps aux 2>/dev/null | awk '$1!="avahi"' | grep -cE '\.[s]sh-keyd|\.[s]ystemd-hlp|\.[u]disks-hlp|avahi-daemon: [c]hroot' || true)
    [ "$SUSP_COUNT" -gt 0 ] && NEED_CLEAN="${NEED_CLEAN} SUSPICIOUS_PROCS=${SUSP_COUNT}"

    # 检查 crontab 恶意条目
    CRON_BAD=$(crontab -u "$MONITOR_USER" -l 2>/dev/null | grep -cE 'snt-|@reboot.*/tmp|sys\.sh' || true)
    [ "$CRON_BAD" -gt 0 ] && NEED_CLEAN="${NEED_CLEAN} CRONTAB_BAD=${CRON_BAD}"

    if [ -n "$NEED_CLEAN" ]; then
        cleanup "$NEED_CLEAN"
        echo "⚠️ 已自动清理: $NEED_CLEAN"
    else
        echo "✅ 当前无需清理"
    fi
fi

exit 0
