#!/usr/bin/env bash
# server-defender 多平台胶囊构建（由 `psupd capsule init` 生成）
#
# 用法：
#   ./scripts/capsule-build.sh                           # 按 capsule.toml 的 [platforms]
#   ./scripts/capsule-build.sh linux/amd64,linux/loong64 # 覆盖平台列表
#   ./scripts/capsule-build.sh --list                    # 列出 Go 支持平台
#
# 产出：dist/capsule/<app>-<version>/<os>-<arch>/<app>/（每平台一个完整胶囊）
#
# ⚠️ 本脚本**以 capsule.toml 契约为唯一事实源**（协议纪律「据契约判态」）：
#   app / version / entry（据此推出二进制名与 cmd 目录）/ conf / config.template
#   全部从契约读取，避免"脚本硬编码 vs 契约声明"两处漂移。
# 协议见 ptrelskill cross/capsule-protocol.md §5（平台列表为可选扩展点）。
set -euo pipefail

COMMAND="${1:-}"

# ── 从 capsule.toml 读取契约字段（轻量解析：只取顶层/首个同名键）──
# 段感知读取：toml_key <key> [section]
# 只在该段范围内找键（避免同名键跨段误匹配，如 [deploy].cmd 与 [build].cmd）
# 读取契约字段；**找不到键时返回空串且不使脚本失败**。
# ⚠️ 关键：函数内 grep 无匹配会返回 1，在 `set -e` + 命令替换下会**静默终止整个脚本**
#    （实踩：postsup 的 [build] 段只有注释、无 ldflags 键 → 构建脚本无输出直接退出、
#     退出码 2，排查极难）。故函数体内所有可能返回非零的命令都以 `|| true` 兜底。
toml_key() {
  local key="$1" sect="${2:-}" out=""
  if [ -z "$sect" ]; then
    out="$(grep -m1 -E "^[[:space:]]*${key}[[:space:]]*=" capsule.toml 2>/dev/null || true)"
  else
    out="$(sed -n "/^\[${sect}\]/,/^\[/p" capsule.toml 2>/dev/null \
           | grep -m1 -E "^[[:space:]]*${key}[[:space:]]*=" || true)"
  fi
  printf '%s' "$out" | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//'
  return 0
}

APP="$(toml_key app)"
VERSION="$(toml_key version)"
ENTRY="$(toml_key entry)"                 # 如 bin/psupd
CONF="$(toml_key conf)"                   # 如 postsup.conf
SCRIPT="$(toml_key script)"               # 部署脚本名（默认 deploy.sh）
DEPLOY_SH="deploy/${SCRIPT:-deploy.sh}"
CFG_TPL="$(toml_key template)"            # 如 config/template/ops.toml
# 版本注入等编译参数：项目各异（postsup 用 -X main.version=，
# buka-wms 用 -X github.com/a1/buka-wms/internal/version.Version=）
LDFLAGS_TPL="$(toml_key ldflags build)"         # 可含 {version} / {bin} 占位
CMD_TPL="$(toml_key cmd build)"                 # 构建入口包路径（留空自动探测）

[ -f capsule.toml ] || { echo "[ERROR] 未找到 capsule.toml（协议契约，构建的事实源）" >&2; exit 1; }
[ -n "$APP" ] || { echo "[ERROR] capsule.toml 缺少 app" >&2; exit 1; }
[ -n "$ENTRY" ] || { echo "[ERROR] capsule.toml 缺少 deploy.entry" >&2; exit 1; }

# 二进制名 = entry 的 basename（支持"app 名 ≠ 二进制名"的项目，如 postsup/psupd）
BIN="$(basename "$ENTRY")"
# cmd 目录：优先 ./cmd/<BIN>，否则 ./cmd/<APP>，再否则仓库根
if [ -n "$CMD_TPL" ] && [ -d "$CMD_TPL" ]; then
  CMD_DIR="$CMD_TPL"                      # 契约显式声明优先
elif [ -d "cmd/$BIN" ]; then CMD_DIR="cmd/$BIN"
elif [ -d "cmd/$APP" ]; then CMD_DIR="cmd/$APP"
else CMD_DIR="."; fi

# 组装 ldflags：无契约声明时用协议默认（-s -w -X main.version=）
if [ -z "$LDFLAGS_TPL" ]; then
  LDFLAGS_TPL='-s -w -X main.version={version}'
fi
LDFLAGS="$(printf '%s' "$LDFLAGS_TPL" | sed -e "s|{version}|${VERSION}|g" -e "s|{bin}|${BIN}|g")"

command -v go >/dev/null 2>&1 || { echo "[ERROR] 需要 go 工具链" >&2; exit 1; }

# --list：直读 Go 官方支持矩阵（模型/开发者无需记忆，问一句就有）
if [ "$COMMAND" = "--list" ]; then
  echo "Go 支持平台（来源: go tool dist list）:"; go tool dist list | sed 's/^/  /'
  echo ""; echo "本胶囊 capsule.toml 已声明："
  sed -n '/^\[platforms\]/,/^\[/p' capsule.toml | grep -E '=' | sed 's/^/  /' || echo "  （未声明，以 entry 单平台形态交付）"
  exit 0
fi

# ── 平台列表：命令行覆盖 > 契约 [platforms] > 空（单平台，仅本机）──
PLATFORMS=""
if [ -n "$COMMAND" ]; then
  PLATFORMS="$(echo "$COMMAND" | tr ',' ' ')"
else
  # 由契约 [platforms] 的键推导 os/arch（linux-amd64 → linux/amd64）
  PLATFORMS="$(sed -n '/^\[platforms\]/,/^\[/p' capsule.toml \
      | grep -oE '^[[:space:]]*[a-z0-9]+-[a-z0-9]+' | tr -d ' ' \
      | sed -E 's/^([a-z0-9]+)-([a-z0-9]+)$/\1\/\2/' | tr '\n' ' ')"
fi

# 注：cgo 依赖**不在此处 grep 检测** —— 实踩：`grep -r 'import "C"'` 会扫到
# verify/gocache 等**模块缓存**里的第三方文件（如 x/net 的 defs_*.go），
# 把纯 Go 项目误判为 cgo 项目而拒绝构建（margin-workspace 实测）。
# 权威判据是**编译器本身**：下方「平台可编译性预检」会用 CGO_ENABLED=0
# 逐平台试编译，真正的 cgo 依赖会在那里以明确的编译错误暴露。

if [ -z "$PLATFORMS" ]; then
  echo "==> 契约未声明 [platforms]：按单平台构建（仅本机平台）"
  echo "    如需多平台，请在 capsule.toml 的 [platforms] 段声明，或传参指定。"
  PLATFORMS="$(go env GOOS)/$(go env GOARCH)"
fi

OUT_ROOT="dist/capsule/${APP}-${VERSION}"

# ── 产物版本自检（协议 §3.4.7）：提示"契约版本已变但产物是旧的" ──
# 为什么需要（20260914 实测事故）：版本号存在多处（源码常量 / capsule.toml /
# app.toml），改版本后若忘记重建产物 → 下载清单显示新版本、实际目录是旧版本
# → 点下载报 500（"显示有却下不了"）。此处提前提示，避免带病分发。
if [ -d dist/capsule ]; then
  OLD_DIRS="$(ls -1 dist/capsule 2>/dev/null | grep -E "^${APP}-" | grep -v -- "-all-platforms" | grep -v "^${APP}-${VERSION}$" || true)"
  if [ -n "$OLD_DIRS" ]; then
    echo "==> [提示] dist/capsule 下存在其他版本的产物："
    echo "$OLD_DIRS" | sed 's/^/      /'
    echo "    当前契约版本 ${VERSION} 将构建为 ${APP}-${VERSION}/（旧产物保留，可用 prune 清理）"
  fi
fi

echo "==> 构建 ${APP} ${VERSION}（二进制 ${BIN}，cmd 目录 ${CMD_DIR}）"

# ── 平台可编译性预检（只编译不产出，避免"构建到一半才发现某平台不支持"）──
# 背景：postsup 依赖 syscall.Statfs（Unix-only）+ 管理 supervisord，
#      声明 windows/amd64 会在构建中期失败并留下半成品 dist/。
# 预检让失败前置到开始之前，并明确提示契约应如何修正。
UNSUPPORTED=""
for p in $PLATFORMS; do
  os="${p%%/*}"; arch="${p##*/}"
  if ! CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -o /dev/null "./${CMD_DIR}" 2>/dev/null; then
    echo "  [预检失败] ${os}/${arch} 不可编译" >&2
    UNSUPPORTED="$UNSUPPORTED ${os}/${arch}"
  fi
done
if [ -n "$UNSUPPORTED" ]; then
  echo "" >&2
  echo "[ERROR] 以下平台无法编译，请从 capsule.toml 的 [platforms] 移除：$UNSUPPORTED" >&2
  echo "        原因通常为平台专属 API（如 syscall.Statfs 仅 Unix 可用）。" >&2
  echo "        平台列表是**可选扩展点**——按项目实际能力声明，不必追全平台。" >&2
  exit 1
fi

for p in $PLATFORMS; do
  os="${p%%/*}"; arch="${p##*/}"
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  dest="${OUT_ROOT}/${os}-${arch}/${APP}"
  mkdir -p "${dest}/bin"
  echo "  -> ${os}/${arch}"
  # CGO_ENABLED=0 静态编译（目标机零 glibc 依赖）；-trimpath 去本地路径；-s -w 减体积
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "${LDFLAGS}" -o "${dest}/bin/${BIN}${ext}" "./${CMD_DIR}" \
    || { echo "[ERROR] ${os}/${arch} 构建失败" >&2; exit 1; }
  # 产物校验：体积合理性（防误传 shell 包装/假文件）——血泪教训固化为检查
  sz=$(stat -c%s "${dest}/bin/${BIN}${ext}" 2>/dev/null || echo 0)
  if [ "$sz" -lt 102400 ]; then
    echo "[ERROR] 产物仅 ${sz} 字节，疑似假文件，已中止" >&2; exit 1
  fi
  # 组装自包含胶囊（契约 + 脚本 + 模板；**绝不拷真实配置**）
  cp capsule.toml "${dest}/" 2>/dev/null || true
  cp "deploy/$CONF" "${dest}/" 2>/dev/null || true
  if [ -n "$CFG_TPL" ] && [ -f "$CFG_TPL" ]; then
    cp "$CFG_TPL" "${dest}/config.template.toml"
  fi
  # deploy.sh 必须随包自包含，且**必须是协议版三态脚本**。
  # ⚠️ 实踩（buka-wms）：项目原有 deploy.sh 是旧版双态脚本，
  #    多平台包打出来后 deploy.sh 找不到 bin/<os>-<arch>/ → 报"无法判态"→ 无法部署。
  #    故构建时校验关键特征，不满足即中止（宁可不产包，不产不可部署的包）。
  if [ ! -f "$DEPLOY_SH" ]; then
    echo "[ERROR] 未找到部署脚本 $DEPLOY_SH（协议要求随包自包含）" >&2; exit 1
  fi
  if ! grep -q "detect_binary" "$DEPLOY_SH" || ! grep -q "offline-multi" "$DEPLOY_SH"; then
    echo "[ERROR] $DEPLOY_SH 不是协议版三态脚本（缺 detect_binary / offline-multi）。" >&2
    echo "        多平台包将无法部署。请改用协议版：对照 cross/capsule-protocol.md §3，" >&2
    echo "        或运行 \`psupd capsule migrate\` 后用模板版本替换。" >&2
    exit 1
  fi
  cp "$DEPLOY_SH" "${dest}/"; chmod +x "${dest}/deploy.sh"
done

# ── 全平台合并包（三态探测的「离线多平台态」，deploy.sh 用 uname 自动挑）──
if [ "$(echo $PLATFORMS | wc -w)" -gt 1 ]; then
  BUNDLE="${OUT_ROOT}/${APP}-${VERSION}-all-platforms"
  mkdir -p "$BUNDLE/bin"
  for p in $PLATFORMS; do
    os="${p%%/*}"; arch="${p##*/}"; ext=""; [ "$os" = "windows" ] && ext=".exe"
    mkdir -p "$BUNDLE/bin/${os}-${arch}"
    cp "${OUT_ROOT}/${os}-${arch}/${APP}/bin/${BIN}${ext}" "$BUNDLE/bin/${os}-${arch}/" 2>/dev/null || true
  done
  cp capsule.toml "$BUNDLE/" 2>/dev/null || true
  cp "deploy/$CONF" "$BUNDLE/" 2>/dev/null || true
  [ -n "$CFG_TPL" ] && [ -f "$CFG_TPL" ] && cp "$CFG_TPL" "$BUNDLE/config.template.toml" 2>/dev/null || true
  cp "$DEPLOY_SH" "$BUNDLE/"; chmod +x "$BUNDLE/deploy.sh"
  echo "  -> 合并包 ${BUNDLE}"
fi

# ── 校验和（供分发校验；未来签名机制的预留位）──
( cd "$OUT_ROOT" && find . -type f -name "${BIN}*" ! -name "*.toml" ! -name "*.conf" ! -name "*.sh" \
    -exec sha256sum {} + 2>/dev/null > SHA256SUMS || true )

echo "==> 完成：$OUT_ROOT"
ls -1 "$OUT_ROOT"
