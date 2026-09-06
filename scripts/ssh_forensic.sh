#!/bin/bash
# ssh_forensic.sh - SSH 会话取证回放（方案A，基于 auditd 原始日志）
# 用法:
#   ssh_forensic.sh 2026-09-05 16:40 [16:55]   # 日期 + 起[止]时间
#   ssh_forensic.sh -30m                        # 最近30分钟
# 说明: 本机 audit 日志有行粘连，ausearch 解析失配，故直接 awk 原始日志按 epoch 过滤
# 版本: v1.1 (20260906) 依赖: root; auditd rules 提供 PROC_EXEC/NET_CONNECT key
set -u
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "need root"; exit 1; }

LOGS=$(ls -tr /var/log/audit/audit.log* 2>/dev/null)
[ -z "$LOGS" ] && { echo "no audit logs"; exit 1; }

# 按窗口过滤: 提取行内 audit( 后的 epoch 秒, 落在 [S,E] 则输出
WIN() { awk -v S="$EPOCH_S" -v E="$EPOCH_E" '{ n=index($0,"audit("); if(n==0) next; e=substr($0,n+6); split(e,a,"."); t=a[1]+0; if(t>=S && t<=E) print }' "$@"; }

A="${1:-}"
case "$A" in
  "")  sed -n '5,9p' "$0"; exit 0 ;;
  -[0-9]*)
       REL="${A#-}"; U="${REL: -1}"; N="${REL%?}"
       case "$U" in m) M=60;; h) M=3600;; d) M=86400;; *) M=60;; esac
       EPOCH_S=$(( $(date +%s) - ${N:-30} * M )); EPOCH_E=$(date +%s) ;;
  *)   T2="${2:-00:00:00}"; T3="${3:-23:59:59}"
       EPOCH_S=$(date -d "$A $T2" +%s)
       EPOCH_E=$(date -d "$A $T3" +%s) ;;
esac
echo "== 窗口: $(date -d @"$EPOCH_S" "+%F %T") ~ $(date -d @"$EPOCH_E" "+%F %T") =="

echo ""
echo "== [1] SSH 登录（来源IP/账号/会话）=="
cat $LOGS | WIN | grep -a "type=USER_LOGIN" | \
    grep -aoE 'addr=[0-9a-fA-F:.]+|acct="[^"]+"' | paste -sd' ' - | fold -w 200 | head -10
cat $LOGS | WIN | grep -ac "type=USER_LOGIN" | xargs echo "  登录事件数:"

echo ""
echo "== [2] 会话命令回放（ses|auid|tty 分组，每会话最多80条）=="
cat $LOGS | WIN | awk '
/type=SYSCALL/ && /PROC_EXEC/ {
    ses=""; auid=""; tty="?"
    if (match($0,/ses=[0-9]+/)) ses=substr($0,RSTART+4,RLENGTH-4)
    if (match($0,/AUID="[a-z0-9_]+"/)) auid=substr($0,RSTART+6,RLENGTH-7)
    if (match($0,/tty=[a-z0-9()\/-]+/)) tty=substr($0,RSTART+4,RLENGTH-4)
    key=ses"|"auid"|"tty
}
/type=EXECVE/ {
    line=$0; out=""
    while (match(line,/a[0-9]+="[^"]*"/)) {
        arg=substr(line,RSTART,RLENGTH)
        gsub(/a[0-9]+="/,"",arg); sub(/"$/,"",arg)
        out=out" "arg
        line=substr(line,RSTART+RLENGTH)
    }
    cnt[key]++
    if (cnt[key]<=80) printf "[%s] %s\n", key, out
}
' | awk '!seen[$0]++' | head -250

echo ""
echo "== [3] 外连目标 TOP25 =="
cat $LOGS | WIN | grep -a "type=SOCKADDR" | \
    grep -aoE "laddr=[0-9.]+ +lport=[0-9]+" | sort | uniq -c | sort -rn | head -25

echo ""
echo "== [4] 可疑特征命中 =="
cat $LOGS | WIN | grep -a EXECVE | \
    grep -aE 'curl[^"]*\|(ba)?sh|wget[^"]*\|(ba)?sh|payload\.sh|authorized_keys|chmod [^"]*u\+s|useradd|/tmp/[a-zA-Z0-9._-]+\.sh|/dev/tcp/' | \
    cut -c1-300 | head -10
CNT=$(cat $LOGS | WIN | grep -a EXECVE | grep -acE 'curl[^"]*\|(ba)?sh|payload\.sh|authorized_keys|useradd' || true)
echo "  命中数: $CNT"
