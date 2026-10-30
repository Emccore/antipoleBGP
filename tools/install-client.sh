#!/usr/bin/env bash
# antipoleBGP 隧道客户端 · 一键安装（Linux / macOS）
#
# 用法（联网一行装完）：
#   curl -fsSL https://raw.githubusercontent.com/Emccore/antipoleBGP/main/tools/install-client.sh | sudo bash
#
# 带参数直接建连接（不进入交互问答）：
#   curl -fsSL ... | sudo bash -s -- --server '[2600:1:2:ff00::1]:18281' \
#       --token <令牌> --map 8080 --map 9000 --name web
#
# 在源码目录里直接跑（离线/内网）：
#   sudo bash tools/install-client.sh
#
# 卸载：sudo bash tools/install-client.sh --uninstall
set -euo pipefail

# 仓库原始文件地址前缀（fork 后改这一行，或用 ANTIPOLE_RAW 覆盖）
RAW=${ANTIPOLE_RAW:-https://raw.githubusercontent.com/Emccore/antipoleBGP/main}
LIB_DIR=/usr/local/lib/antipole-c
BIN=/usr/local/bin/antipole-c
CONF_DIR=/etc/antipole-c

c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_red=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
ok()   { printf '%s✓%s %s\n' "$c_grn" "$c_off" "$*"; }
warn() { printf '%s!%s %s\n' "$c_ylw" "$c_off" "$*"; }
die()  { printf '%s✗%s %s\n' "$c_red" "$c_off" "$*" >&2; exit 1; }
step() { printf '\n%s▸ %s%s\n' "$c_dim" "$*" "$c_off"; }

usage() {
    cat <<'EOF'
antipoleBGP 隧道客户端一键安装（Linux / macOS）

  curl -fsSL <脚本地址> | sudo bash
  curl -fsSL <脚本地址> | sudo bash -s -- --server '[aaaa::1]:18281' --token <令牌> \
        --map 8080 --map 9000 [--name web] [--cert-domain www.example.com]

  sudo bash install-client.sh             # 源码目录内离线安装（进入交互问答）
  sudo bash install-client.sh --uninstall # 卸载（连配置与证书一起删）
EOF
    exit 0
}

# ---------------- 参数 ----------------
SERVER=""; TOKEN=""; NAME="web"; CERT_DOMAIN=""; ASSUME_YES=0; UNINSTALL=0
declare -a MAPS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --server)      SERVER=${2:-}; shift 2 ;;
        --token)       TOKEN=${2:-}; shift 2 ;;
        --map)         MAPS+=("${2:-}"); shift 2 ;;
        --name)        NAME=${2:-web}; shift 2 ;;
        --cert-domain) CERT_DOMAIN=${2:-}; shift 2 ;;
        --uninstall)   UNINSTALL=1; shift ;;
        -y|--yes)      ASSUME_YES=1; shift ;;
        -h|--help)     usage ;;
        *) die "未知参数：$1（--help 查看用法）" ;;
    esac
done

# ---------------- 环境 ----------------
if [ "$(id -u)" != "0" ]; then
    # 本地文件才能自提权重跑；curl | bash 形式必须由调用方带 sudo
    if [ -f "${BASH_SOURCE[0]:-$0}" ] && command -v sudo >/dev/null 2>&1; then
        warn "需要管理员权限，正在用 sudo 重新执行…"
        exec sudo -E bash "${BASH_SOURCE[0]:-$0}" "$@"
    fi
    die "请用管理员权限运行：curl -fsSL <脚本地址> | sudo bash"
fi

step "检查运行环境"
PY=$(command -v python3 || command -v python || true)
if [ -z "$PY" ]; then
    warn "未找到 Python 3，尝试自动安装…"
    if   command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq python3
    elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q python3
    elif command -v yum     >/dev/null 2>&1; then yum install -y -q python3
    elif command -v apk     >/dev/null 2>&1; then apk add --no-cache python3
    elif command -v brew    >/dev/null 2>&1; then brew install python3
    else die "请先手动安装 python3（客户端只需标准库，无第三方依赖）"; fi
    PY=$(command -v python3 || command -v python || true)
fi
[ -n "$PY" ] || die "Python 3 安装失败，请手动安装后重试"
ok "Python: $("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"

OS=$(uname -s)
HAS_SYSTEMD=0
[ "$OS" = "Linux" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && HAS_SYSTEMD=1
ok "系统: $OS $(uname -m)$([ "$HAS_SYSTEMD" = 1 ] && echo '（systemd，开机自启）' || echo '（无 systemd，用后台进程）')"

# ---------------- 卸载 ----------------
if [ "$UNINSTALL" = 1 ]; then
    step "卸载"
    if [ "$HAS_SYSTEMD" = 1 ]; then
        for unit in /etc/systemd/system/antipole-c@*.service; do
            [ -e "$unit" ] || continue
            systemctl disable --now "$(basename "$unit" .service)" >/dev/null 2>&1 || true
        done
        rm -f /etc/systemd/system/antipole-c@.service
        systemctl daemon-reload || true
    fi
    pkill -f "$LIB_DIR/antipole-tunnel.py" 2>/dev/null || true
    rm -rf "$LIB_DIR" "$BIN" "$CONF_DIR"
    ok "已卸载（配置与证书已一并删除）"
    exit 0
fi

# ---------------- 取文件 ----------------
step "获取客户端文件"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
HERE=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi

fetch() {   # fetch <文件名> <目标>：本地（脚本同目录）优先，否则从仓库 tools/ 下载
    local name=$1 dest=$2
    if [ -n "$HERE" ] && [ -f "$HERE/$name" ]; then
        cp "$HERE/$name" "$dest"; ok "$name（本地）"; return
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 "$RAW/tools/$name" -o "$dest" || die "下载失败：$RAW/tools/$name"
    elif command -v wget >/dev/null 2>&1; then
        wget -qT 15 "$RAW/tools/$name" -O "$dest" || die "下载失败：$RAW/tools/$name"
    else
        die "系统缺少 curl/wget，无法下载；请先安装其一"
    fi
    ok "$name（已下载）"
}

fetch antipole-tunnel.py "$TMP/antipole-tunnel.py"
fetch antipole-c         "$TMP/antipole-c"

# ---------------- 安装 ----------------
step "安装到 $LIB_DIR"
install -d -m 0755 "$LIB_DIR"
install -m 0755 "$TMP/antipole-tunnel.py" "$LIB_DIR/antipole-tunnel.py"
install -m 0755 "$TMP/antipole-c" "$BIN"
mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR"
"$BIN" install "$TMP/antipole-tunnel.py" >/dev/null
ok "命令已就位：antipole-c"

# ---------------- 建连接 ----------------
ask() {   # ask <提示> <默认值>：无终端（如 CI）时直接取默认值
    local prompt=$1 def=${2:-} ans=""
    if ! [ -r /dev/tty ]; then echo "$def"; return; fi
    printf '%s%s ' "$prompt" "${def:+[$def] }" >&2
    read -r ans < /dev/tty || ans=""
    echo "${ans:-$def}"
}

if [ -z "$SERVER" ]; then
    step "填写连接信息（直接回车用括号内默认值）"
    printf '%s\n' "  接入地址形如 [2a14:7583:ef30:fe00::1]:18281（服务端「隧道」一栏可查）"
    SERVER=$(ask "接入地址" "")
    [ -n "$SERVER" ] || die "接入地址不能为空"
fi
if [ -z "$TOKEN" ]; then
    TOKEN=$(ask "账号令牌（Token）" "")
    [ -n "$TOKEN" ] || die "令牌不能为空"
fi
if [ ${#MAPS[@]} -eq 0 ]; then
    raw=$(ask "要映射的本机端口（多个用空格或逗号分隔，如 8080 9000)" "")
    [ -n "$raw" ] || die "至少需要一个端口"
    IFS=$' ,\t' read -r -a MAPS <<< "$raw"
fi

case "$NAME" in
    *[!A-Za-z0-9._-]*) die "连接名只允许字母数字与 . _ -" ;;
esac
[ -f "$CONF_DIR/$NAME.ini" ] && NAME="${NAME}-$(date +%s)"

args=(add "$NAME" --server "$SERVER" --token "$TOKEN")
for m in "${MAPS[@]}"; do args+=(--map "$m"); done
[ -n "$CERT_DOMAIN" ] && args+=(--cert-domain "$CERT_DOMAIN")

step "建立连接「$NAME」"
"$BIN" "${args[@]}"

# ---------------- 收尾提示 ----------------
printf '\n'
ok "安装完成，隧道已在后台常驻（断线自动重连、开机自启）"
printf '%s\n' \
"  查看状态   antipole-c status $NAME" \
"  查看日志   antipole-c log $NAME 50" \
"  停止/启动  antipole-c stop $NAME  /  antipole-c start $NAME" \
"  申请证书   antipole-c cert $NAME www.example.com" \
"  全部连接   antipole-c list" \
"  卸载       sudo bash install-client.sh --uninstall"
