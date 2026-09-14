#!/usr/bin/env bash
# server-defender 部署脚本（三态自适应：源码打包态 / 离线单平台态 / 离线多平台态）
#
# 本文件由 `psupd capsule init` 生成，遵循「部署胶囊协议」
# （规范真源：ptrelskill cross/capsule-protocol.md；契约：同目录 capsule.toml）。
#
# 判态规则（无需任何参数区分）：
#   上级存在 go.mod        → 源码打包态（开发机：先构建/组装，再部署）
#   同目录 bin/server-defender     → 离线单平台态（直接用该二进制）
#   同目录 bin/<os>-<arch>/ → 离线多平台态（按 uname 自动挑选匹配平台的二进制）
#
# 用法：
#   ./deploy/deploy.sh --pack                 # 仅打包（源码态）
#   sudo ./deploy/deploy.sh                   # 打包 + 部署（源码态）
#   sudo ./deploy.sh                          # 离线部署（目标机，任意位置均可）
#   --user <运行用户> 指定 supervisor 运行用户；--version 查看脚本版本
set -euo pipefail

SCRIPT_VERSION="1.0.0"
APP="server-defender"
BIN="server-defender"          # 运行载体文件名（可与 app 名不同，如 postsup/psupd）
RUN_USER="root"
# ── 契约声明的部署身份与运行权限（由 psupd capsule init 从 capsule.toml 注入）──
# deploy_as: root | sudo | user —— **三选一，严格互斥**（协议 §3.4.2）
DEPLOY_AS="root"
RUN_AS_ROOT="true"           # true/false
RUN_GROUPS=""             # 空格分隔的组名（空=无要求）
RUN_PATHS=""               # 空格分隔的路径（空=无要求）

PACK_ONLY=0
# 安全边界：默认保守（不动系统资源）。见协议 §3.4.2
CREATE_USER=0   # --create-user 才允许 useradd
FIX_INCLUDE=0   # --fix-include 才允许改 supervisor 主配置
# 降级部署（supervisord 非 root 却要管 run_as_root=true 的服务时）
DEGRADE_USER=""
ALLOW_DEGRADE=0
ASSUME_YES=0
NON_INTERACTIVE=0
DEGRADED=0
DRY_RUN=0       # --dry-run 只打印计划，不落盘

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --pack)    PACK_ONLY=1; shift ;;
    --version) echo "$APP 部署脚本 v$SCRIPT_VERSION"; exit 0 ;;
    --user)    RUN_USER="${2:?--user 需要参数,如: --user a1}"; shift 2 ;;
    # 安全边界开关（协议 §3.4.2）：默认**不动系统级资源**，需显式开启
    --create-user)  CREATE_USER=1; shift ;;
    --fix-include)  FIX_INCLUDE=1; shift ;;
    --dry-run)      DRY_RUN=1; shift ;;
    --yes|-y)       ASSUME_YES=1; shift ;;
    --non-interactive) ASSUME_YES=1; NON_INTERACTIVE=1; shift ;;
    --fallback-user) DEGRADE_USER="${2:?--fallback-user 需要参数}"; shift 2 ;;
    --allow-degrade) ALLOW_DEGRADE=1; shift ;;
    *) echo "[ERROR] 未知参数: $1" >&2
       echo "        支持: --pack / --user <用户> / --create-user / --fix-include / --dry-run / --version" >&2
       exit 1 ;;
  esac
done

SUPERVISORCTL="${SUPERVISORCTL:-supervisorctl}"
CONF_D="/etc/supervisor/conf.d"
SVC="psup-server-defender"
# supervisor 配置**文件名**从契约读取（本机约定：文件名 = 服务名，如 psup-buka-wms.conf）。
# ⚠️ 不能硬编码 $APP.conf —— buka-wms 的 app 名是 buka-wms 而服务名是 psup-buka-wms，
#    写错文件名会与既有 conf 并存，导致同一 [program] 被定义两次（实踩）。
# 契约可能在本目录（离线包形态）或上级（源码树 deploy/ 形态）——两处都要找。
CAPSULE_FILE=""
for _c in "$SCRIPT_DIR/capsule.toml" "$SCRIPT_DIR/../capsule.toml"; do
  [ -f "$_c" ] && { CAPSULE_FILE="$_c"; break; }
done
CONF_NAME=""
[ -n "$CAPSULE_FILE" ] && CONF_NAME="$(grep -m1 -E '^[[:space:]]*conf[[:space:]]*=' "$CAPSULE_FILE" 2>/dev/null \
            | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//')"
[ -n "$CONF_NAME" ] || CONF_NAME="server-defender.conf"

# ── 日志辅助（分级 + 步骤编号）──
STEP_NO=0
STEP_TOTAL=6
log()  { echo "==> $*"; }
info() { echo "    · $*"; }
step() { STEP_NO=$((STEP_NO + 1)); echo ""; echo "═══ 步骤 $STEP_NO/$STEP_TOTAL: $* ═══"; }
warn() { echo "[WARN] $*" >&2; }
err()  { echo "[ERROR] $*" >&2; }
die()  { err "$@"; exit 1; }
hint() { echo "        ↳ $*" >&2; }

# ── 三态探测(协议 cross/capsule-protocol.md §3) ──
#   1. 离线多平台态:同目录 bin/<os>-<arch>/ 存在 → uname 自动挑平台(合并包场景)
#   2. 离线单平台态:同目录 bin/server-defender 或 server-defender 存在 → 直接用
#   3. 源码打包态  :上级有 go.mod → 构建/组装后部署
# 边界:源码态下 deploy/ 同目录永远没有二进制(产物在 release/server-defender/ 或 bin/),不会误判;
#       离线态优先判定,即使包被放回源码树内也按离线包处理
MODE=""
RELEASE_DIR=""
# 单/多平台的**正确判据**：bin/ 下是否存在 <os>-<arch> 形式的子目录
#（早期误用 `[ -d bin ]`：单平台包的二进制本就放在 bin/ 下，会被误判成多平台态 → 部署失败）
_have_platform_dirs() {
  local d="$SCRIPT_DIR/bin"
  [ -d "$d" ] || return 1
  local sub
  for sub in "$d"/*/; do
    [ -d "$sub" ] || continue
    case "$(basename "$sub")" in
      *-*) return 0 ;;   # 形如 linux-amd64
    esac
  done
  return 1
}

if [ -f "$SCRIPT_DIR/bin/server-defender" ]; then
  # 单平台包：二进制直接位于 bin/ 下（capsule-build.sh 的单平台产物形态）
  MODE="offline"
  RELEASE_DIR="$SCRIPT_DIR"
  BIN_PATH="$SCRIPT_DIR/bin/server-defender"
elif _have_platform_dirs; then
  # 多平台包：二进制位于 bin/<os>-<arch>/ 下（合并包形态）
  MODE="offline-multi"
  RELEASE_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/server-defender" ]; then
  # 离线单平台（二进制在包根，如 postsup 现有 release 包形态）
  MODE="offline"
  RELEASE_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../go.mod" ]; then
  MODE="source"
  RELEASE_DIR="$SCRIPT_DIR/release/server-defender"
else
  echo "[ERROR] 无法定位部署上下文:脚本目录($SCRIPT_DIR)既无二进制也无源码(../go.mod)" >&2
  echo "        离线部署请上传完整 server-defender 包（契约 + 二进制 + server-defender.conf + deploy.sh）" >&2
  exit 1
fi

# ══════════════════════════════════════════════════════════════════
# ── 部署权限校验（协议 §3.4.2.1 修订版）：统一 sudo 执行 ──
# ══════════════════════════════════════════════════════════════════
# 设计（20260914 修订，替代原「三类严格互斥」）：
#   · **开发者**在契约里写清"需要什么权限"（run_as_root / run_groups / run_paths）；
#   · **部署者**一律 `sudo ./deploy.sh` —— 脚本只要求 euid==0，
#     不区分"root 直登"还是"sudo 提权"。
#
# 为什么放弃三类互斥：`sudo su`/`sudo -i`/`sudo bash` 都能拿到完整 root 权限，
# 但 SUDO_USER 由 sudo **主动写入**（审计用途）且 su 默认不清理 ——
# 于是"最自然的提权操作"反而被拒，而"怎么变成 root 的"对部署结果毫无影响。
# 真正该约束的是「**服务以谁的身份运行**」，那由 run_as_root 显式声明。
EUID_NOW="$(id -u)"
ELEVATED_VIA_SUDO="${SUDO_USER:-}"

if [ "$EUID_NOW" -ne 0 ]; then
  echo "[ERROR] 本脚本需要 root 权限（当前 euid=$EUID_NOW，用户 $(id -un)）。" >&2
  echo "" >&2
  echo "        请用以下任一方式重新执行：" >&2
  echo "            sudo ./deploy.sh" >&2
  echo "            sudo -i  然后 ./deploy.sh" >&2
  echo "" >&2
  case "$RUN_AS_ROOT" in
    true)  echo "        说明：本服务声明 run_as_root=true，需 root 权限部署。" >&2 ;;
    false) echo "        说明：本服务服务进程将以 $RUN_USER 运行，但部署动作（写 supervisor 配置）仍需 root。" >&2 ;;
  esac
  exit 1
fi

if [ -n "$ELEVATED_VIA_SUDO" ]; then
  log "部署权限: root（经 sudo 提权，操作者=$ELEVATED_VIA_SUDO）"
else
  log "部署权限: root（root 直登）"
fi
log "服务运行身份: $( [ "$RUN_AS_ROOT" = "true" ] && echo "root（契约声明 run_as_root=true）" || echo "$RUN_USER（契约声明 run_as_root=false）" )"

# ── 路径安全校验（协议 §3.4.1 红线）──
# 为什么必须有：脚本含 `chown -R "$RUN_USER" "$RELEASE_DIR"`。
# 若 RELEASE_DIR 落在系统目录（尤其 `/`），会递归改写整机属主 —— 灾难性且不可逆。
# 另：CONF_NAME 来自包内契约，若不可信可写成 `../../supervisord.conf` 实现路径穿越写任意文件。
case "$RELEASE_DIR" in
  /|/etc|/etc/*|/usr|/usr/*|/bin|/bin/*|/sbin|/sbin/*|/lib|/lib/*|/lib64|/lib64/*|/boot|/boot/*|/var|/var/*|/home|/home/*|/root|/root/*|/opt|/opt/*|/main)
    echo "[ERROR] 部署目录落在系统敏感路径，拒绝执行: $RELEASE_DIR" >&2
    echo "        请把胶囊放到独立目录（如 /main/app/<app>/），目录名建议与服务名一致。" >&2
    exit 1
    ;;
esac
# 契约里的 conf 必须是**纯文件名**（禁含 / 与 ..）——防路径穿越写任意文件
case "$CONF_NAME" in
  */*|.|..)
    echo "[ERROR] 契约 deploy.conf 必须是纯文件名（不含 / ），实际: $CONF_NAME" >&2
    echo "        这可能是被篡改的契约；请核对包内 capsule.toml。" >&2
    exit 1
    ;;
esac

# ── 平台自动挑选(离线多平台态):uname → bin/<os>-<arch>/server-defender ──
# 设计纪律:未命中时**必须报错并列出包内已有平台**,绝不「随便挑一个」——
#          宁可中止,不可把错误平台的二进制部署上去(会 Exec format error)。
# BIN_PATH 可能已在探测阶段设定（单平台包），此处只为多平台态兜底
: "${BIN_PATH:=}"
detect_binary() {
  local os arch
  case "$(uname -s)" in
    Linux)  os=linux  ;;
    Darwin) os=darwin ;;
    *)      echo "[ERROR] 不支持的操作系统: $(uname -s)" >&2; return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64)  arch=amd64   ;;
    aarch64|arm64) arch=arm64   ;;
    armv7l|armv6l) arch=arm     ;;
    i386|i686)     arch=386     ;;
    loongarch64)   arch=loong64 ;;
    riscv64)       arch=riscv64 ;;
    *)             echo "[ERROR] 不支持的架构: $(uname -m)" >&2; return 1 ;;
  esac
  local cand="$RELEASE_DIR/bin/${os}-${arch}/server-defender"
  if [ -f "$cand" ]; then
    echo "$cand"; return 0
  fi
  echo "[ERROR] 本机为 ${os}-${arch},但包内无匹配产物。包内已有平台:" >&2
  ls -1 "$RELEASE_DIR/bin" 2>/dev/null | sed 's/^/    /' >&2 || echo "    (bin/ 为空)" >&2
  echo "        请下载对应平台包,或在开发机执行 ./scripts/capsule-build.sh 产出。" >&2
  return 1
}

# 载体路径：探测阶段已确定的**不覆盖**（单平台包在 bin/ 或包根，两种位置都要尊重）。
# ⚠️ 曾因这里无条件赋值 `BIN_PATH="$SCRIPT_DIR/server-defender"`，把探测阶段已正确设定的
#    `bin/server-defender` 覆盖成不存在的包根路径 → 部署失败。
if [ "$MODE" = "offline-multi" ]; then
  BIN_PATH="$(detect_binary)" || exit 1
elif [ "$MODE" = "offline" ] && [ -z "${BIN_PATH:-}" ]; then
  BIN_PATH="$SCRIPT_DIR/server-defender"     # 兜底：二进制在包根（postsup 现有 release 形态）
  [ -f "$BIN_PATH" ] || BIN_PATH="$SCRIPT_DIR/bin/server-defender"
fi

# 模式与载体（多平台态已选定具体平台二进制；单平台/源码态此行为空或稍后补算）
log "$APP 部署脚本 v$SCRIPT_VERSION（模式: $MODE）${BIN_PATH:+ | 载体: $BIN_PATH}"

# ── 打包（仅源码态；供开发机产出胶囊）──
do_pack() {
  # ⚠️ 变量顺序红线：源码根与构建参数必须**先定义后使用**。
  # 实踩：曾把 SRC_ROOT/CMD_PKG/LDFLAGS 的定义放在使用之后 →
  # `set -u` 下报 "SRC_ROOT: 未绑定的变量"，**源码打包态完全不可用**；
  # 而离线部署态走另一分支，测不出来，只有真跑 --pack 才暴露。
  local SRC_ROOT
  SRC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
  local CMD_PKG LDFLAGS_TPL LDFLAGS VER
  CMD_PKG="$(grep -m1 -E '^[[:space:]]*cmd[[:space:]]*=' "$SRC_ROOT/capsule.toml" 2>/dev/null \
             | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//' || true)"
  LDFLAGS_TPL="$(grep -m1 -E '^[[:space:]]*ldflags[[:space:]]*=' "$SRC_ROOT/capsule.toml" 2>/dev/null \
             | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//' || true)"
  VER="$(grep -m1 -E '^[[:space:]]*version[[:space:]]*=' "$SRC_ROOT/capsule.toml" 2>/dev/null \
        | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//' || true)"
  [ -n "$CMD_PKG" ] || CMD_PKG="./cmd/$APP"
  [ -n "$LDFLAGS_TPL" ] || LDFLAGS_TPL='-s -w -X main.version={version}'
  LDFLAGS="$(printf '%s' "$LDFLAGS_TPL" | sed -e "s|{version}|${VER}|g" -e "s|{bin}|${BIN}|g")"

  [ -f "$SRC_ROOT/capsule.toml" ] || { echo "[ERROR] 源码根未找到 capsule.toml: $SRC_ROOT" >&2; exit 1; }
  mkdir -p "$RELEASE_DIR"
  if ! command -v go >/dev/null 2>&1; then
    [ -f "$RELEASE_DIR/$BIN" ] || { echo "[ERROR] 未安装 go 且 release 内无已有 $BIN，无法打包" >&2; exit 1; }
    warn "未安装 go，沿用 release 内已有 $BIN"
  else
    # sudo 下 HOME 切到 root 会丢 GOMODCACHE；还原原始用户身份做离线构建
    # CGO_ENABLED=0 强制纯 Go 静态编译：目标机零 glibc 依赖
    local BUILD_GO="go"
    if [ -n "${SUDO_USER:-}" ] && command -v sudo >/dev/null 2>&1; then
      BUILD_GO="sudo -n -u $SUDO_USER env CGO_ENABLED=0 GOPROXY=off GOFLAGS=-mod=mod go"
    else
      export CGO_ENABLED=0
    fi
    log "Go 离线构建（GOPROXY=off，身份: ${SUDO_USER:-当前用户}）"
    (cd "$SRC_ROOT" && $BUILD_GO build -trimpath -ldflags "$LDFLAGS" -o "$RELEASE_DIR/$BIN" "$CMD_PKG") \
      || { echo "[ERROR] go build 失败" >&2; exit 1; }
  fi
  # 契约与模板随包分发（自包含）
  for f in capsule.toml deploy.sh "$CONF_NAME"; do
    [ -f "$SCRIPT_DIR/$f" ] && cp "$SCRIPT_DIR/$f" "$RELEASE_DIR/$f" 2>/dev/null || true
  done
  [ -f "$SCRIPT_DIR/deploy.sh" ] && cp "$SCRIPT_DIR/deploy.sh" "$RELEASE_DIR/deploy.sh" && chmod +x "$RELEASE_DIR/deploy.sh"
  # 静态资源（运行时读磁盘时必须随包；内嵌则可忽略）
  for d in web static; do
    [ -d "$SRC_ROOT/$d" ] && { rm -rf "$RELEASE_DIR/$d"; cp -r "$SRC_ROOT/$d" "$RELEASE_DIR/$d"; }
  done
  # 脱敏配置模板（绝不拷真实配置）
  # 脱敏配置模板：路径**从契约读取**（各项目命名不一：ops.toml / env.toml / config.toml），
  # 统一复制为包内 config.template.toml（与 capsule-build.sh 的产出命名一致）。
  local CFG_TPL
  CFG_TPL="$(grep -m1 -E '^[[:space:]]*template[[:space:]]*=' "$SRC_ROOT/capsule.toml" 2>/dev/null \
             | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//')"
  if [ -n "$CFG_TPL" ] && [ -f "$SRC_ROOT/$CFG_TPL" ]; then
    cp "$SRC_ROOT/$CFG_TPL" "$RELEASE_DIR/config.template.toml"
  else
    warn "未找到配置模板（契约 config.template=${CFG_TPL:-未声明}）；包内无模板，首启将自动生成默认配置"
  fi
  log "打包完成: $RELEASE_DIR/"
  log "离线部署: 将该文件夹整体上传目标机 /main/app/ 下，执行 sudo ./deploy.sh"
}

# ── 部署（各态通用；路径均按包实际位置生成）──
# 渲染 supervisor conf 模板：**所有占位符替换的唯一真源**（新增 @HOME@）。
render_conf() {
  local tpl="$1"
  local home
  home="$(getent passwd "$RUN_USER" 2>/dev/null | cut -d: -f6 || true)"
  if [ -z "$home" ]; then
    if [ "$RUN_USER" = "root" ]; then home="/root"; else home="/home/$RUN_USER"; fi
  fi
  sed -e "s|@DIR@|$RELEASE_DIR|g" \
      -e "s|@USER@|$RUN_USER|g" \
      -e "s|@HOME@|$home|g" \
      -e "s|@BIN@|$BIN_PATH|g" \
      "$tpl"
}

diagnose_start_failure() {
  local REASON="${1:-未知}"
  err "启动 $SVC 失败，开始诊断"
  local ST_OUT
  ST_OUT="$("$SUPERVISORCTL" status "$SVC" 2>&1 || true)"
  echo "$ST_OUT" | sed 's/^/  /' >&2

  echo "" >&2
  echo "  ── 现场快照（请连同本段一起反馈）──" >&2
  {
    echo "  supervisord 身份 : ${SUP_USER:-?} (pid ${SUP_PID:-无})"
    echo "  部署者身份     : $(id -un) (euid=$(id -u)${SUDO_USER:+ ; SUDO_USER=$SUDO_USER})"
    echo "  服务运行用户   : $RUN_USER"
    echo "  运行载体     : $BIN_PATH"
    echo "  载体权限     : $(stat -c '%U:%G %a' "$BIN_PATH" 2>/dev/null || echo 缺失)"
    echo "  logs/ 属主与权限 : $(stat -c '%U:%G %a' "$RELEASE_DIR/logs" 2>/dev/null || echo 缺失)"
    echo "  conf 落点    : $CONF_DEST"
    echo "  包内 ops.toml  : $([ -f "$RELEASE_DIR/ops.toml" ] && echo 存在 || echo '缺失(首次启动会自动生成)')"
  } | sed 's/^/  /' >&2

  # 按状态文本给出**定向**根因与修复命令（而不是让用户自己猜）
  echo "" >&2
  case "$ST_OUT" in
    *EACCES*|*"making dispatchers"*)
    err "根因：supervisord 打不开日志文件（EACCES）"
    hint "supervisord 在 fork 前以**自己的身份**打开 stdout_logfile；"
    hint "若 logs/ 属主与 supervisord 身份不一致即失败（手工前台能跑、supervisor 拉起必挂）"
    hint "修复: sudo chown -R ${SUP_USER:-<supervisord用户>} '$RELEASE_DIR/logs'"
    hint "    sudo chmod 755 '$RELEASE_DIR/logs'"
    hint "    然后: sudo $SUPERVISORCTL restart $SVC"
    ;;
    *"no such process"*)
    err "根因：supervisor 未加载本包配置"
    hint "确认主配置含 [include] files = $CONF_D/*.conf"
    hint "检查: grep -A2 '\[include' ${SUP_CONF:-/etc/supervisord.conf}"
    hint "然后: sudo $SUPERVISORCTL reread && sudo $SUPERVISORCTL update $SVC"
    ;;
    *STARTING*)
    err "根因：服务仍在 STARTING —— 它**没失败，只是没等够**"
    hint "supervisor 状态机：spawn → STARTING（持续 startsecs 秒）→ RUNNING"
    hint "若程序初始化较慢（首次生成配置/迁移数据等），startsecs 内没就绪属正常"
    hint "处置：多等几秒查看 —— $SUPERVISORCTL status $SVC"
    hint "     若长期停在 STARTING，再看下方程序日志判断是否卡住"
    ;;
    *BACKOFF*|*FATAL*)
    err "根因：进程启动后立即退出（BACKOFF/FATAL）"
    hint "多为程序自身报错（端口占用/配置非法/依赖缺失）——见下方日志尾部"
    ;;
    *"can't setuid"*|*setuid*)
    err "根因：supervisord 无法切换到 user=$RUN_USER"
    hint "检查该用户是否存在: id $RUN_USER"
    ;;
    *)
    warn "未识别的失败形态，见下方日志尾部"
    ;;
  esac

  # supervisor 主日志（多个候选位置都扫，不只第一个存在的）
  echo "" >&2
  local FOUND_LOG=0
  for LOGF in /var/log/supervisor/supervisord.log /var/log/supervisord.log \
        /main/log/supervisor/supervisord.log /tmp/supervisord.log; do
    if [ -f "$LOGF" ]; then
    echo "  ── $LOGF 尾部（⚠️ 含历史记录）──" >&2
    tail -20 "$LOGF" 2>/dev/null | sed 's/^/  /' >&2 || true
    FOUND_LOG=1
    fi
  done
  [ "$FOUND_LOG" -eq 0 ] && hint "未找到 supervisord 日志（试: sudo find / -maxdepth 5 -name 'supervisord.log'）"

  # 本服务日志
  for LF in "$RELEASE_DIR/logs/$SVC.log" "$RELEASE_DIR/logs/$SVC.err.log" \
            "$RELEASE_DIR/logs/${APP:-$SVC}.log" "$RELEASE_DIR/logs/${APP:-$SVC}.err.log"; do
    if [ -s "$LF" ]; then
    echo "  ── $(basename "$LF") 尾部（⚠️ 含历史记录）──" >&2
    tail -20 "$LF" | sed 's/^/  /' >&2 || true
    fi
  done

  # 手工前台试跑（最直接的排除法：程序能不能独立起来）
  echo "" >&2
  hint "手动前台验证（能起来=问题在 supervisor 侧；不能=问题在程序侧）:"
  hint "  sudo '$BIN_PATH' --config '$RELEASE_DIR/ops.toml'"

  echo "" >&2
  hint "可回滚: cp $CONF_DEST.bak $CONF_DEST 2>/dev/null; $SUPERVISORCTL update $SVC"
  return 1
}

do_deploy() {
  # 载体路径：探测阶段已确定（单平台直接在 bin/ 或包根；多平台由 detect_binary 选定）。
  # ⚠️ 曾因条件写成 `[ -d bin ]` 而误判：单平台包的二进制也在 bin/ 下，
  #    会被当成多平台去挑 bin/<os>-<arch>/ → 报"无匹配产物"而部署失败。
  #    现严格按 MODE 判定，多平台态才调用 detect_binary。
  if [ "$MODE" = "offline-multi" ]; then
    # 多平台：重新确认（探测阶段已选，此处幂等兜底）
    if [ -z "${BIN_PATH:-}" ] || [ ! -f "$BIN_PATH" ]; then
      BIN_PATH="$(detect_binary)" || exit 1
    fi
  elif [ "$MODE" = "source" ]; then
    BIN_PATH="$RELEASE_DIR/$BIN"
  fi
  local BIN="$BIN_PATH"
  [ -n "$BIN" ] && [ -f "$BIN" ] || { echo "[ERROR] 未找到运行载体: ${BIN:-未确定}（源码态请先 --pack）" >&2; exit 1; }
  [ -f "$RELEASE_DIR/$CONF_NAME" ] || { echo "[ERROR] 缺少 supervisor 模板 $CONF_NAME" >&2; exit 1; }

  command -v "$SUPERVISORCTL" >/dev/null 2>&1 \
    || { echo "[ERROR] 未找到 supervisorctl，请先安装 supervisor" >&2; exit 1; }

  # supervisor 主配置探测：配置必须写到实际被 [include] 覆盖的位置
  # 注意：include 目录判断必须**路径精确比较**，禁子串匹配——
  #      /main/app/supervisor/conf.d 同样含 "conf.d" 子串却不是默认目录。
  #      INI 同名 key 后者覆盖，故 files 只解析**最后一行**。
  local SUP_CONF="" INC_LINE="" TARGET_DIR="" INC_DIR="" p SUP_CONF_BAK=""
  SUP_CONF="$(ps -eo args 2>/dev/null | grep '[s]upervisord' | grep -oE '\-c[= ]+[^ ]+' | head -1 | sed -E 's/^-c[= ]+//')"
  if [ -z "$SUP_CONF" ]; then
    for p in /etc/supervisor/supervisord.conf /etc/supervisord.conf /etc/supervisor/supervisor.conf; do
      [ -f "$p" ] && { SUP_CONF="$p"; break; }
    done
  fi
  # supervisord 进程身份探测（决定 logs/ 属主能否写入 —— EACCES 根因）
  local SUP_BIN SUP_PID SUP_CMD
  SUP_BIN="$(command -v supervisord 2>/dev/null || echo "")"
  SUP_PID="$(pgrep -x supervisord 2>/dev/null | head -1 || true)"
  if [ -n "${SUP_PID:-}" ]; then
    SUP_USER="$(ps -o user= -p "$SUP_PID" 2>/dev/null | tr -d ' ' || true)"
    SUP_CMD="$(ps -o args= -p "$SUP_PID" 2>/dev/null | head -c 200 || true)"
  else
    SUP_USER=""; SUP_CMD=""
  fi
  [ -n "${SUP_USER:-}" ] || SUP_USER="$(id -un)"
  log "supervisord 身份: ${SUP_USER}（pid ${SUP_PID:-未运行}）"
  [ -n "$SUP_CMD" ] && info "进程: $SUP_CMD"

  # ── 前置检查：supervisord 身份 vs 契约 run_as_root（**在任何写操作之前**）──
  #
  # supervisor 硬约束（源码 options.py drop_privileges）：
  #   current_uid == uid  → 无需切换，放行
  #   current_uid != 0    → 返回 "Can't drop privilege as nonroot user"
  # 即：supervisord **自己必须是 root** 才能把子进程 setuid 到 root。
  # 若 supervisord 以普通用户运行而契约要求 run_as_root=true → 必然 spawn 失败：
  #   supervisor: couldn't setuid to 0: Can't drop privilege as nonroot user
  # 与其等到启动失败留一堆现场，不如**提前拦住并给出选择**。
  if [ "$RUN_AS_ROOT" = "true" ] && [ -n "${SUP_USER:-}" ] && [ "$SUP_USER" != "root" ]; then
    echo "" >&2
    err "权限模型冲突：supervisord 无法以 root 启动本服务"
    hint "supervisord 当前以 **$SUP_USER** 运行，而契约声明 run_as_root=true"
    hint "supervisor 硬约束：非 root 的 supervisord 不能把子进程 setuid 到 root"
    hint "（源码 options.py: if current_uid != 0: return \"Can't drop privilege as nonroot user\"）"
    echo "" >&2
    echo "  可选处置：" >&2
    echo "    [1] 降级部署 —— 本服务改以 $SUP_USER 运行（立刻可用）" >&2
    echo "        代价：PostSup 将无法管理其他 supervisor 服务（需 root 才能操作）" >&2
    echo "    [2] 中止部署 —— 先让 supervisord 以 root 运行（保持契约语义）" >&2
    echo "        做法：改 systemd 单元或 /etc/supervisord.conf 的 [supervisord] user，" >&2
    echo "              重启 supervisord（**会重启它管理的所有服务**）后重跑本脚本" >&2
    echo "    [3] 仅查看诊断 —— 不部署，只打印排查步骤" >&2
    echo "" >&2

    CHOICE=""
    # 决策优先级：显式 --fallback-user > --allow-degrade > 交互询问 > 默认中止
    if [ -n "$DEGRADE_USER" ]; then
      CHOICE="1"
      info "已按 --fallback-user $DEGRADE_USER 选择降级部署（非交互）"
    elif [ "$ALLOW_DEGRADE" -eq 1 ]; then
      DEGRADE_USER="$SUP_USER"
      CHOICE="1"
      info "已按 --allow-degrade 选择降级到 $SUP_USER（非交互）"
    elif [ "$DRY_RUN" -eq 0 ] && [ -t 0 ] && [ -t 1 ] && [ "$ASSUME_YES" -eq 0 ]; then
      # 仅真实交互终端才询问（管道/CI/--yes 一律走默认中止，避免卡住自动化）
      printf "  请选择 [1/2/3]（默认 2 中止）: " >&2
      read -r REPLY || REPLY=""
      case "$REPLY" in
        1|y|Y) CHOICE="1" ;;
        3|d|D) CHOICE="3" ;;
        *)     CHOICE="2" ;;
      esac
    else
      CHOICE="2"
      [ "$DRY_RUN" -eq 1 ] && info "（dry-run：仅展示冲突，不落盘；默认将中止）"
    fi

    case "$CHOICE" in
      1)
        # 降级：把运行用户改为 supervisord 身份，**不改契约文件**（仅本次部署生效）
        DEGRADE_USER="${DEGRADE_USER:-$SUP_USER}"
        if ! id "$DEGRADE_USER" >/dev/null 2>&1; then
          die "降级目标用户不存在: $DEGRADE_USER"
        fi
        warn "【降级部署】服务将以 **$DEGRADE_USER** 运行（契约仍声明 run_as_root=true，未改动）"
        hint "PostSup 将无法管理其他 supervisor 服务（需 root 才能操作）——这是降级的代价"
        hint "如要恢复：让 supervisord 以 root 运行后重新部署"
        RUN_USER="$DEGRADE_USER"
        RUN_AS_ROOT="false"
        DEGRADED=1
        ;;
      3)
        hint "排查步骤："
        hint "  1) 确认 supervisord 启动方式: ps -eo user,pid,args | grep '[s]upervisord'"
        hint "  2) 若为 systemd: systemctl cat supervisor | grep -E 'User|ExecStart'"
        hint "  3) 若直接启动: grep -A5 '^\\[supervisord\\]' /etc/supervisord.conf"
        hint "  4) 改为 root 后重启 supervisord（注意会重启其管理的所有服务）"
        exit 1
        ;;
      *)
        err "已中止部署（未做任何改动）"
        hint "如确要降级部署，重跑并加: --fallback-user $SUP_USER"
        exit 1
        ;;
    esac
  fi

  if [ -n "$SUP_CONF" ] && [ -f "$SUP_CONF" ]; then
    log "supervisor 主配置: $SUP_CONF"
    INC_LINE="$(sed -n '/^\[include\]/,/^\[/p' "$SUP_CONF" | grep -E '^[[:space:]]*files?[[:space:]]*=' | tail -1 | sed -E 's/^[^=]*=[[:space:]]*//' || true)"
    if [ -n "$INC_LINE" ]; then
      log "include files: $INC_LINE"
      INC_DIR="$(dirname "$(echo "$INC_LINE" | awk '{print $1}')")"
      if [ "$INC_DIR" = "$CONF_D" ]; then
        TARGET_DIR="$CONF_D"
      else
        # include 可能含**多个**目录（本机实况：/etc/supervisor.d/*.ini 与
        # /main/server/supervisor/conf.d/*.conf 并存）。**不能取第一个存在的目录** ——
        # 本机 /etc/supervisor.d 存在但为空，生产配置全在 /main/server/supervisor/conf.d，
        # 写进空目录会成"死配置"：reread 无更新 → 服务根本起不来（实踩）。
        # 判据优先级（从「最可信」到「兜底」）：
        #   1. 已存在本服务配置的目录（升级场景，位置最可信）
        #   2. 含同类 *.conf 配置的目录（同机既有约定）
        #   3. 首个存在的目录（兜底）
        local first_existing=""
        for p in $INC_LINE; do
          local d
          d="$(dirname "$p")"
          [ -d "$d" ] || continue
          [ -z "$first_existing" ] && first_existing="$d"
          # 1) 已有本服务配置 → 就地覆盖（升级）
          if [ -f "$d/$CONF_NAME" ]; then
            TARGET_DIR="$d"; break
          fi
          # 2) 该目录已有 *.conf 配置文件 → 沿用同机约定
          if [ -z "$TARGET_DIR" ] && ls "$d"/*.conf >/dev/null 2>&1; then
            TARGET_DIR="$d"
          fi
        done
        if [ -z "$TARGET_DIR" ]; then
          if [ -n "$first_existing" ]; then
            TARGET_DIR="$first_existing"
            warn "include 各目录均无既有 *.conf，退而写入首个存在目录: $TARGET_DIR"
          else
            TARGET_DIR="$INC_DIR"
            mkdir -p "$TARGET_DIR" 2>/dev/null \
              || { echo "[ERROR] include 目录不存在且无法创建: $TARGET_DIR" >&2; exit 1; }
          fi
        fi
        log "include 指向 $TARGET_DIR，配置将写入该目录（非默认 $CONF_D）"
      fi
    fi
    if [ -z "$TARGET_DIR" ]; then
      # 协议 §3.4.2：修改 supervisor **主配置**属系统级改动 —— 默认只提示，
      # 需显式 --fix-include 才动（目标机可能已有既有组织约定）。
      if [ "$FIX_INCLUDE" -ne 1 ]; then
        echo "[ERROR] 主配置 $SUP_CONF 未配置 [include]，本包配置不会被加载。" >&2
        echo "        请手动补入以下内容后重跑（或加 --fix-include 让脚本自动补）:" >&2
        echo "            [include]" >&2
        echo "            files = $CONF_D/*.conf" >&2
        exit 1
      fi
      # 改前备份：append [include] 是**语义级**改动（INI 重名 section 后者覆盖），
      # 一旦主配置本有 include 而解析失配，原有目录会被顶掉 → 其他服务集体消失。
      SUP_CONF_BAK="$SUP_CONF.bak-$(date +%Y%m%d-%H%M%S)"
      cp "$SUP_CONF" "$SUP_CONF_BAK" 2>/dev/null \
        || { echo "[ERROR] 无法备份主配置 $SUP_CONF，拒绝修改（--fix-include 已开启）" >&2; exit 1; }
      log "已备份主配置 -> $SUP_CONF_BAK"
      if printf '\n[include]\nfiles = %s/*.conf\n' "$CONF_D" >> "$SUP_CONF" 2>/dev/null; then
        TARGET_DIR="$CONF_D"
        log "主配置无 [include]，已按 --fix-include 补入 -> $CONF_D/*.conf"
        log "如需回滚: cp $SUP_CONF_BAK $SUP_CONF"
      else
        echo "[ERROR] 无法写入主配置 $SUP_CONF；请手动补入 [include] files = $CONF_D/*.conf" >&2
        exit 1
      fi
    fi
  else
    warn "无法定位 supervisor 主配置，按默认 $CONF_D 写入"
    TARGET_DIR="$CONF_D"
  fi
  [ -d "$TARGET_DIR" ] || mkdir -p "$TARGET_DIR"
  local CONF_DEST="$TARGET_DIR/$CONF_NAME"
  mkdir -p "$RELEASE_DIR/logs"

  # 运行用户处理：缺失才创建；已存在则不动账号，仅提示不符项
  if ! id "$RUN_USER" >/dev/null 2>&1; then
    if [ "$CREATE_USER" -ne 1 ]; then
      # 协议 §3.4.2：默认**不创建系统账号**（改系统账户属越界行为）——
      # 报错并给出可复制命令，由运维决定；需自动建时显式加 --create-user
      echo "[ERROR] 运行用户 $RUN_USER 不存在。" >&2
      echo "        二选一：① 指定已有用户:  --user <已有用户>" >&2
      echo "                ② 允许脚本创建:  --create-user（将执行 useradd -r -m -s /bin/bash $RUN_USER）" >&2
      exit 1
    fi
    log "运行用户 $RUN_USER 不存在，按 --create-user 创建"
    useradd -r -m -s /bin/bash "$RUN_USER" 2>/dev/null \
      || { echo "[ERROR] 创建用户 $RUN_USER 失败（需 root）" >&2; exit 1; }
    getent group supervisor >/dev/null 2>&1 && usermod -aG supervisor "$RUN_USER" 2>/dev/null \
      || warn "未能加入 supervisor 组，服务管理功能可能受限"
  else
    id -nG "$RUN_USER" 2>/dev/null | grep -qw supervisor \
      || warn "$RUN_USER 不在 supervisor 组，服务管理功能可能受限"
  fi

  # ── 运行权限校验（协议 §3.4.2）：契约声明的 run_groups / run_paths 必须满足 ──
  # 目的：把"这软件运行需要什么"从口头约定变成**部署时校验**，避免"装上了但跑不起来"。
  local _miss=0
  for g in $RUN_GROUPS; do
    [ -z "$g" ] && continue
    if id -nG "$RUN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$g"; then
      log "运行权限: $RUN_USER 已在组 $g ✓"
    else
      warn "运行权限缺失: $RUN_USER 不在组 $g（本服务需要该组权限）"
      echo "        修复: sudo usermod -aG $g $RUN_USER  然后重启服务" >&2
      _miss=1
    fi
  done
  for pth in $RUN_PATHS; do
    [ -z "$pth" ] && continue
    if [ -r "$pth" ] 2>/dev/null; then
      log "运行权限: 路径 $pth 可读 ✓"
    else
      warn "运行权限缺失: 路径 $pth 不可读（本服务需要访问它）"
      echo "        修复: 确认运行用户 $RUN_USER 对该路径有读权限（如加入 adm 组）" >&2
      _miss=1
    fi
  done
  if [ "$_miss" -eq 1 ]; then
    warn "存在运行权限缺口（见上）。若确认无碍可继续；否则修复后重启服务。"
  fi

  # 包目录属主与写权限：psupd 首启需写配置/数据，属主必须归运行用户

  # ── dry-run 预检（协议 §3.4.6）：到这里已做完所有**只读**探测与校验，
  #    下一步就要产生副作用（chown/写配置/useradd）。故在此打印计划并退出，一步不动。
  if [ "$DRY_RUN" -eq 1 ]; then
    echo ""
    echo "════════ dry-run 预检结果（未做任何改动）════════"
    echo "  模式        : $MODE"
    echo "  部署目录    : $RELEASE_DIR"
    echo "  运行载体    : ${BIN_PATH:-（源码态，构建后生成）}"
    echo "  运行用户    : $RUN_USER"
    echo "  服务名      : $SVC"
    echo "  配置文件名  : $CONF_NAME"
    echo "  supervisor 目录: ${TARGET_DIR:-（待探测）}"
    echo ""
    echo "  将要执行（如去掉 --dry-run）："
    echo "    1. 属主归一: chown -R $RUN_USER $RELEASE_DIR"
    [ "$CREATE_USER" -eq 1 ] && echo "    2. 创建用户: useradd -r -m -s /bin/bash $RUN_USER" || echo "    2. 不创建用户（未加 --create-user；用户不存在则报错退出）"
    echo "    3. 写配置  : $TARGET_DIR/$CONF_NAME（已存在则先备份为 .bak）"
    [ "$FIX_INCLUDE" -eq 1 ] && echo "    4. 主配置   : 必要时补 [include]（--fix-include 已开启）" || echo "    4. 主配置   : 不动（未加 --fix-include）"
    echo "    5. 加载服务 : supervisorctl reread + update $SVC（仅本服务）"
    echo "    6. 启动     : supervisorctl restart|start $SVC"
    echo "═══════════════════════════════════════════════"
    exit 0
  fi
  # （实踩：目录不可写 → 首启即退 BACKOFF）——归一后仍不可写则硬中止，绝不带病部署
  if chown -R "$RUN_USER:$RUN_USER" "$RELEASE_DIR" 2>/dev/null \
     || chown -R "$RUN_USER" "$RELEASE_DIR" 2>/dev/null \
     || sudo -n chown -R "$RUN_USER" "$RELEASE_DIR" 2>/dev/null; then
    log "包目录属主已统一为 $RUN_USER"
  fi

  # ── logs/ 属主须匹配 **supervisord 身份**（EACCES 根因）──
  # ⚠️ 必须在「属主归一 chown -R」**之后**：否则刚设的属主会被递归 chown 改回。
  if [ -z "${SUP_USER:-}" ]; then SUP_USER="$(id -un)"; fi
  if [ "$SUP_USER" != "$RUN_USER" ]; then
    if chown "$SUP_USER" "$RELEASE_DIR/logs" 2>/dev/null; then
      info "logs/ 属主设为 supervisord 身份: $SUP_USER（与运行用户 $RUN_USER 不同，为可写性所需）"
    fi
  fi
  chmod 755 "$RELEASE_DIR/logs" 2>/dev/null || true
  if [ "$SUP_USER" != "root" ] && command -v su >/dev/null 2>&1; then
    if ! su -s /bin/sh "$SUP_USER" -c "touch '$RELEASE_DIR/logs/.wtest' && rm -f '$RELEASE_DIR/logs/.wtest'" 2>/dev/null; then
      err "logs/ 对 supervisord 身份($SUP_USER)不可写 —— 会导致启动 EACCES(BACKOFF)"
      hint "修复: sudo chown -R $SUP_USER '$RELEASE_DIR/logs' && sudo chmod 755 '$RELEASE_DIR/logs'"
      exit 1
    fi
    info "logs/ 可写性校验通过（身份 $SUP_USER）"
  fi
  if ! sudo -u "$RUN_USER" test -w "$RELEASE_DIR" 2>/dev/null; then
    echo "[ERROR] $RUN_USER 对 $RELEASE_DIR 无写权限（会导致启动即退）" >&2
    echo "        手动修复后重跑: sudo chown -R $RUN_USER $RELEASE_DIR" >&2
    exit 1
  fi
  # 兜底：无论何种解压方式（zip 会丢权限位）都确保可执行
  chmod +x "$BIN" 2>/dev/null || true

  # ── 凭据护栏（保守策略：宁可不改，不覆盖现场）──
  # 背景：按宪法规矩，SECRET_KEY / BOOTSTRAP_USERS 等明文**只落 supervisor conf 一份**；
  #      而 conf 模板要进 git，必须留空（不能带真实值）。
  # 风险：若用空值模板覆盖现场 conf，服务会以空 SECRET_KEY 启动（会话可预测）
  #      = 安全退化，且原凭据永久丢失。
  # 策略：**检测到现场 conf 含非空凭据时，完全不覆盖**，只提示人工合并 ——
  #      这与 migrate「只补缺失、绝不覆盖」的原则一致，避免脆弱的字符串搬运
  #      （实测：用 sed/awk 搬运含引号/逗号的 JSON 型凭据极易出错）。
  local CRED_RE='(SECRET_KEY|BOOTSTRAP_USERS|PASSWORD|TOKEN|API_KEY)="[^"]+"'
  if [ -f "$CONF_DEST" ] && grep -qE "$CRED_RE" "$CONF_DEST" 2>/dev/null; then
    cp "$CONF_DEST" "$CONF_DEST.bak" 2>/dev/null || true
    warn "现场配置 $CONF_DEST 含凭据（SECRET_KEY/BOOTSTRAP_USERS 等）。"
    warn "为避免覆盖现场凭据，**本次不生成 supervisor 配置**（保留原文件不动）。"
    warn "如需更新该配置，请人工合并以下差异后执行: supervisorctl reread && supervisorctl update"
    warn "  期望内容（占位符已替换，凭据处为空）："
    render_conf "$RELEASE_DIR/$CONF_NAME" | sed 's/^/      /' >&2
    warn "  当前现场（已备份到 $CONF_DEST.bak）："
    sed 's/^/      /' "$CONF_DEST" | sed -E 's/((SECRET_KEY|BOOTSTRAP_USERS|PASSWORD|TOKEN|API_KEY)=")[^"]+/\1<REDACTED>/' >&2
    echo "" >&2
    echo "  提示：若本次只是换二进制（无配置变更），可忽略本提示。" >&2
    echo "        部署将继续进行（二进制已就位），但 supervisor 配置保持现场版本。" >&2
    SKIP_CONF_WRITE=1
  fi

  # ── 无条件备份（协议 §3.4.4）：只要目标 conf 已存在，写之前一律先备份 ──
  # 反例（实踩）：备份逻辑曾只写在"含凭据"分支里 → 无凭据的同名 conf 被**静默覆盖**，
  # 用户既没备份也不知道被改了。
  if [ -f "$CONF_DEST" ] && [ "${SKIP_CONF_WRITE:-0}" -eq 0 ]; then
    if cp "$CONF_DEST" "$CONF_DEST.bak" 2>/dev/null; then
      log "已备份原配置 -> $CONF_DEST.bak"
    else
      warn "无法备份 $CONF_DEST（将继续，但请自行确认可回滚）"
    fi
  fi

  if [ "${SKIP_CONF_WRITE:-0}" -eq 0 ]; then
    # 写权限预检（协议 §3.4.2）：user 类要求目标机**已预配** conf 目录写权限。
    # 若直接写会报裸 shell 错误（"权限不够"），对用户毫无指引 —— 故先友好检测。
    local CONF_DIR_W
    CONF_DIR_W="$(dirname "$CONF_DEST")"
    if ! { [ -w "$CONF_DIR_W" ] || [ -w "$CONF_DEST" ]; }; then
      echo "[ERROR] 无权限写入 supervisor 配置: $CONF_DEST" >&2
      case "$DEPLOY_AS" in
        user)
          echo "        本服务声明 deploy_as=user（纯普通用户部署），要求目标机预先配好写权限。" >&2
          echo "        一次性预配（管理员执行，之后普通用户可免 sudo 部署）:" >&2
          echo "            sudo setfacl -m u:$(id -un):rwx $CONF_DIR_W" >&2
          echo "        或改用 sudo 部署（把契约改为 deploy_as = \"sudo\"）。" >&2
          ;;
        sudo) echo "        请用 sudo 执行: sudo ./deploy.sh" >&2 ;;
        root) echo "        请用 root 执行本脚本。" >&2 ;;
      esac
      exit 1
    fi
    log "写入 supervisor 配置 -> $CONF_DEST"
    render_conf "$RELEASE_DIR/$CONF_NAME" > "$CONF_DEST"
    chmod 644 "$CONF_DEST"
  fi

  # ── 非侵入加载（协议 §3.4.3）：只操作**本服务**，不触碰同机其他服务 ──
  # 为什么：`supervisorctl update`（无参数）是**全局**操作，会连带处理其他服务的
  # 新增/移除/重启 —— 在已有其他服务的目标机上可能造成意外中断。
  # `update <name>` 是 supervisor 原生用法，只处理该 program。
  # reread/update 输出透出（不吞）：available/added/错误信息对诊断至关重要
  local REREAD_OUT
  if ! REREAD_OUT="$("$SUPERVISORCTL" reread 2>&1)"; then
    echo "$REREAD_OUT" | sed 's/^/    /' >&2
    echo "[ERROR] supervisorctl reread 失败；最常见根因：主配置未 include $CONF_D" >&2
    exit 1
  fi
  echo "$REREAD_OUT" | sed 's/^/    /'
  if echo "$REREAD_OUT" | grep -qF "$SVC"; then
    log "检测到本服务配置变化 → update $SVC（仅本服务，不影响其他）"
    "$SUPERVISORCTL" update "$SVC" || { echo "[ERROR] supervisorctl update $SVC 失败" >&2; exit 1; }
  else
    # 无变化时：若 program 尚未加载（首次部署但 reread 未提示），仍尝试 update <SVC>
    if "$SUPERVISORCTL" status "$SVC" >/dev/null 2>&1; then
      log "配置无变化且服务已加载 → 跳过 update"
    else
      log "服务尚未加载 → update $SVC（仅本服务）"
      "$SUPERVISORCTL" update "$SVC" 2>/dev/null || true
    fi
  fi

  if ! "$SUPERVISORCTL" restart "$SVC" >/dev/null 2>&1 && ! "$SUPERVISORCTL" start "$SVC" >/dev/null 2>&1; then
    diagnose_start_failure "supervisorctl restart/start 失败"
    exit 1
  fi

  # ── 轮询等待进入 RUNNING（**不能用固定 sleep**）──
  #
  # 实踩（用户现场）：脚本原先 `sleep 2` 后判定，而 conf 的 `startsecs=3`，
  #   supervisor 的状态机是 spawn → STARTING（持续 startsecs 秒）→ RUNNING
  #   （源码 process.py transitions: `if now - self.laststart > self.config.startsecs`
  #    才把 STARTING 置为 RUNNING）。
  #   ⇒ **2 秒时服务仍在 STARTING，健康服务被误判为启动失败**，
  #     用户看到 `postsup  STARTING` + 一段"未识别失败形态" + 陈旧的日志尾部，
  #     极易被误导去查错误方向（本次就是这样绕了远路）。
  #
  # 修法：按 startsecs 动态等（从 conf 读，缺省 3），加余量并轮询，
  #   只在**确认失败**（BACKOFF/FATAL/STOPPED/EXITED）或超时才判失败。
  local START_SECS
  START_SECS="$(grep -m1 -E '^[[:space:]]*startsecs[[:space:]]*=' "$CONF_DEST" 2>/dev/null \
                | sed -E 's/^[^=]*=[[:space:]]*//' || true)"
  case "$START_SECS" in
    ''|*[!0-9]*) START_SECS=3 ;;   # 非数字/缺失 → 用 supervisor 默认 3
  esac
  local WAIT_MAX=$((START_SECS + 7))   # 余量：允许程序初始化比 startsecs 慢
  local waited=0 st=""
  info "等待服务进入 RUNNING（startsecs=${START_SECS}s，最多等 ${WAIT_MAX}s）"
  while [ "$waited" -lt "$WAIT_MAX" ]; do
    st="$("$SUPERVISORCTL" status "$SVC" 2>/dev/null || true)"
    if echo "$st" | grep -q RUNNING; then
      break
    fi
    # 已明确失败 → 立即停，不必等满
    if echo "$st" | grep -qE 'BACKOFF|FATAL|STOPPED|EXITED'; then
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done

  if echo "$st" | grep -q RUNNING; then
    log "完成（${waited}s 后进入 RUNNING）。运行数据 logs/、data/ 均在包目录内"
  else
    diagnose_start_failure "启动后 ${waited}s 仍未进入 RUNNING（当前: $(echo "$st" | tr -s ' ' | cut -c1-80)）"
  fi
}

case "$MODE" in
  source)
    do_pack
    [ "$PACK_ONLY" -eq 1 ] && exit 0
    do_deploy
    ;;
  offline|offline-multi)
    [ "$PACK_ONLY" -eq 1 ] && { warn "离线包内无源码，--pack 无意义，已忽略"; exit 0; }
    do_deploy
    ;;
esac
