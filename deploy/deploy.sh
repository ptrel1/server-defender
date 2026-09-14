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
PACK_ONLY=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --pack)    PACK_ONLY=1; shift ;;
    --version) echo "$APP 部署脚本 v$SCRIPT_VERSION"; exit 0 ;;
    --user)    RUN_USER="${2:?--user 需要参数,如: --user a1}"; shift 2 ;;
    *) echo "[ERROR] 未知参数: $1（支持 --pack / --user <用户> / --version）" >&2; exit 1 ;;
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

log()  { echo "==> $*"; }
warn() { echo "[WARN] $*" >&2; }

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
  # 构建入口与 ldflags 从契约读取（各项目 cmd 目录与版本注入路径不一：
  # postsup 是 cmd/psupd + -X main.version；buka-wms 是 cmd/buka-wms + 其 internal/version.Version）
  local CMD_PKG LDFLAGS_TPL LDFLAGS
  CMD_PKG="$(grep -m1 -E '^[[:space:]]*cmd[[:space:]]*=' "$SRC_ROOT/capsule.toml" 2>/dev/null \
             | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//')"
  LDFLAGS_TPL="$(grep -m1 -E '^[[:space:]]*ldflags[[:space:]]*=' "$SRC_ROOT/capsule.toml" 2>/dev/null \
             | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//')"
  [ -n "$CMD_PKG" ] || CMD_PKG="./cmd/$APP"
  [ -n "$LDFLAGS_TPL" ] || LDFLAGS_TPL='-s -w -X main.version={version}'
  local VER
  VER="$(grep -m1 -E '^[[:space:]]*version[[:space:]]*=' "$SRC_ROOT/capsule.toml" 2>/dev/null \
        | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//')"
  LDFLAGS="$(printf '%s' "$LDFLAGS_TPL" | sed -e "s|{version}|${VER}|g" -e "s|{bin}|${BIN}|g")"

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
  local SUP_CONF="" INC_LINE="" TARGET_DIR="" INC_DIR="" p
  SUP_CONF="$(ps -eo args 2>/dev/null | grep '[s]upervisord' | grep -oE '\-c[= ]+[^ ]+' | head -1 | sed -E 's/^-c[= ]+//')"
  if [ -z "$SUP_CONF" ]; then
    for p in /etc/supervisor/supervisord.conf /etc/supervisord.conf /etc/supervisor/supervisor.conf; do
      [ -f "$p" ] && { SUP_CONF="$p"; break; }
    done
  fi
  if [ -n "$SUP_CONF" ] && [ -f "$SUP_CONF" ]; then
    log "supervisor 主配置: $SUP_CONF"
    INC_LINE="$(sed -n '/^\[include\]/,/^\[/p' "$SUP_CONF" | grep -E '^[[:space:]]*files?[[:space:]]*=' | tail -1 | sed -E 's/^[^=]*=[[:space:]]*//')"
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
      if printf '\n[include]\nfiles = %s/*.conf\n' "$CONF_D" >> "$SUP_CONF" 2>/dev/null; then
        TARGET_DIR="$CONF_D"
        log "主配置无 [include]，已补入 -> $CONF_D/*.conf（不影响已有服务）"
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
    log "运行用户 $RUN_USER 不存在，自动创建"
    useradd -r -m -s /bin/bash "$RUN_USER" 2>/dev/null \
      || { echo "[ERROR] 创建用户 $RUN_USER 失败（需 root；或 --user <已有用户>）" >&2; exit 1; }
    getent group supervisor >/dev/null 2>&1 && usermod -aG supervisor "$RUN_USER" 2>/dev/null \
      || warn "未能加入 supervisor 组，服务管理功能可能受限"
  else
    id -nG "$RUN_USER" 2>/dev/null | grep -qw supervisor \
      || warn "$RUN_USER 不在 supervisor 组，服务管理功能可能受限"
  fi

  # 包目录属主与写权限：psupd 首启需写配置/数据，属主必须归运行用户
  # （实踩：目录不可写 → 首启即退 BACKOFF）——归一后仍不可写则硬中止，绝不带病部署
  if chown -R "$RUN_USER:$RUN_USER" "$RELEASE_DIR" 2>/dev/null \
     || chown -R "$RUN_USER" "$RELEASE_DIR" 2>/dev/null \
     || sudo -n chown -R "$RUN_USER" "$RELEASE_DIR" 2>/dev/null; then
    log "包目录属主已统一为 $RUN_USER"
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
    sed -e "s|@DIR@|$RELEASE_DIR|g" -e "s|@USER@|$RUN_USER|g" -e "s|@BIN@|$BIN_PATH|g" \
        "$RELEASE_DIR/$CONF_NAME" | sed 's/^/      /' >&2
    warn "  当前现场（已备份到 $CONF_DEST.bak）："
    sed 's/^/      /' "$CONF_DEST" | sed -E 's/((SECRET_KEY|BOOTSTRAP_USERS|PASSWORD|TOKEN|API_KEY)=")[^"]+/\1<REDACTED>/' >&2
    echo "" >&2
    echo "  提示：若本次只是换二进制（无配置变更），可忽略本提示。" >&2
    echo "        部署将继续进行（二进制已就位），但 supervisor 配置保持现场版本。" >&2
    SKIP_CONF_WRITE=1
  fi

  if [ "${SKIP_CONF_WRITE:-0}" -eq 0 ]; then
    log "写入 supervisor 配置 -> $CONF_DEST"
    sed -e "s|@DIR@|$RELEASE_DIR|g" \
        -e "s|@USER@|$RUN_USER|g" \
        -e "s|@BIN@|$BIN_PATH|g" \
        "$RELEASE_DIR/$CONF_NAME" > "$CONF_DEST"
    chmod 644 "$CONF_DEST"
  fi

  # reread/update 输出透出（不吞）：available/added/错误信息对诊断至关重要
  "$SUPERVISORCTL" reread || {
    echo "[ERROR] supervisorctl reread 失败；最常见根因：主配置未 include $CONF_D" >&2; exit 1; }
  "$SUPERVISORCTL" update || { echo "[ERROR] supervisorctl update 失败" >&2; exit 1; }

  if ! "$SUPERVISORCTL" restart "$SVC" >/dev/null 2>&1 && ! "$SUPERVISORCTL" start "$SVC" >/dev/null 2>&1; then
    echo "[ERROR] 启动 $SVC 失败，诊断信息:" >&2
    "$SUPERVISORCTL" status "$SVC" 2>&1 | sed 's/^/    /' >&2 || true
    if "$SUPERVISORCTL" status "$SVC" 2>&1 | grep -q "no such process"; then
      echo "    ── 根因提示：supervisor 未加载本包配置 ──" >&2
      echo "    确认主配置含 [include] files = $CONF_D/*.conf；若无，补上后 reread && update" >&2
    fi
    for LOGF in /var/log/supervisor/supervisord.log /var/log/supervisord.log; do
      [ -f "$LOGF" ] && { echo "    ── $LOGF 尾部 ──" >&2; tail -15 "$LOGF" 2>/dev/null | sed 's/^/    /' >&2 || true; break; }
    done
    [ -f "$RELEASE_DIR/logs/$APP.log" ] && { echo "    ── 程序日志尾部 ──" >&2; tail -15 "$RELEASE_DIR/logs/$APP.log" | sed 's/^/    /' >&2 || true; }
    echo "        可回滚: cp $CONF_DEST.bak $CONF_DEST 2>/dev/null; $SUPERVISORCTL update" >&2
    exit 1
  fi

  sleep 2
  if "$SUPERVISORCTL" status "$SVC" 2>/dev/null | grep -q RUNNING; then
    log "完成。运行数据 logs/、data/ 均在包目录内"
  else
    echo "[ERROR] $SVC 未进入 RUNNING 状态:" >&2
    "$SUPERVISORCTL" status "$SVC" 2>&1 | sed 's/^/    /' >&2 || true
    echo "        详情: $SUPERVISORCTL tail $SVC stderr" >&2
    exit 1
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
