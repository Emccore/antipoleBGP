#!/usr/bin/env bash
# ============================================================
#  antipoleBGP 出口调度管理系统 一键安装脚本（V1.1）
#
#  支持的发行版与包管理器：
#    - Debian / Ubuntu                  -> apt
#    - CentOS / RHEL / Rocky / AlmaLinux -> dnf / yum
#    - Alpine                           -> apk
#  支持的 CPU 架构：
#    - x86_64 (amd64)、aarch64 (arm64)
#
#  使用方式：
#    A. 项目位于本机：cd antipole && bash install.sh
#    B. 远程执行安装器：PREFIX=<你的/48> bash <(curl -fsSL <安装器URL>)
#    C. 自动下载项目包：REMOTE=<项目压缩包URL> bash install.sh
#
#  环境变量：
#    PREFIX        已广播的前缀（建议 /48，允许 /32~/64，如 2600:xxxx:xxxx:xxxx::/48）
#    ADMIN_TOKEN   管理 API 访问令牌（缺省随机生成）
#    ADMIN_ALLOW   管理 API 来源白名单（逗号分隔）
#    REMOTE        项目压缩包地址（跳过本地文件拷贝）
#    GH            GitHub 下载镜像前缀（覆盖默认镜像列表）
# ============================================================
set -euo pipefail

INST_VERSION="V1.1"
APP_DIR=${APP_DIR:-/root/antipole}
CONF_DIR=${CONF_DIR:-/etc/antipole}
APT_UPDATED=0

say(){ printf "\033[1;34m[antipole v%s]\033[0m %s\n" "$INST_VERSION" "$*"; }
die(){ printf "\033[1;31m[antipole 失败]\033[0m %s\n" "$*"; exit 1; }

# ---------- 0. 环境检测（操作系统 / 包管理器 / CPU 架构 / systemd） ----------

detect_pkg_mgr() {
    case "$(uname -s)" in
        Linux) ;;
        *) die "当前仅支持 Linux 平台，检测到: $(uname -s)" ;;
    esac
    if   command -v apt-get >/dev/null 2>&1; then PM=apt
    elif command -v dnf     >/dev/null 2>&1; then PM=dnf
    elif command -v yum     >/dev/null 2>&1; then PM=yum
    elif command -v apk     >/dev/null 2>&1; then PM=apk
    else die "未检测到受支持的包管理器（apt/dnf/yum/apk），请手动安装依赖后重试"; fi
    say "包管理器: $PM"
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)        ARCH=amd64 ;;
        aarch64|arm64)       ARCH=arm64 ;;
        *) die "不支持的 CPU 架构: $(uname -m)（仅支持 x86_64 / aarch64）" ;;
    esac
    say "CPU 架构: $ARCH"
}

detect_systemd() {
    HAS_SYSTEMD=0
    [ -d /run/systemd/system ] && HAS_SYSTEMD=1
    if [ "$HAS_SYSTEMD" = "1" ]; then
        say "检测到 systemd，注册系统服务"
    else
        echo "    未检测到 systemd，将生成手工启停脚本"
    fi
}

# 按包管理器安装缺失的命令：pkg_ensure wg ip curl ...
pkg_ensure() {
    local missing=""
    local p
    for p in "$@"; do
        command -v "$p" >/dev/null 2>&1 || missing="$missing $p"
    done
    [ -n "$missing" ] || return 0
    say "安装缺失依赖:$missing"
    case $PM in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            if [ "$APT_UPDATED" = "0" ]; then
                apt-get update -y
                APT_UPDATED=1
            fi
            apt-get install -y $missing
            ;;
        dnf) dnf install -y $missing ;;
        yum) yum install -y $missing ;;
        apk) apk add --no-cache $missing ;;
    esac
}

# 可选组件（DNS64/NAT64 用）：安装失败不阻断，服务运行期自动降级
pkg_ensure_optional() {
    local missing=""
    local p
    for p in "$@"; do
        command -v "$p" >/dev/null 2>&1 || missing="$missing $p"
    done
    [ -n "$missing" ] || return 0
    echo "    可选组件缺失（功能将降级）:$missing"
    case $PM in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            [ "$APT_UPDATED" = "0" ] && { apt-get update -y; APT_UPDATED=1; }
            apt-get install -y $missing >/dev/null 2>&1 || true
            ;;
        dnf) dnf install -y $missing >/dev/null 2>&1 || true ;;
        yum) yum install -y $missing >/dev/null 2>&1 || true ;;
        apk) apk add --no-cache $missing >/dev/null 2>&1 || true ;;
    esac
    return 0
}

ensure_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        pkg_ensure python3
    fi
    local ok
    ok=$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 8) else 0)' 2>/dev/null || echo 0)
    if [ "$ok" != "1" ]; then
        die "需要 Python 3.8 及以上，当前: $(python3 --version 2>&1 || echo 未知)"
    fi
    if ! python3 -m pip --version >/dev/null 2>&1; then
        pkg_ensure pip3
    fi
    say "Python $(python3 --version 2>&1)"
}

check_wireguard() {
    if [ -d /sys/module/wireguard ] || grep -qw wireguard /proc/modules 2>/dev/null; then
        return 0
    fi
    if command -v modprobe >/dev/null 2>&1 && modprobe wireguard 2>/dev/null; then
        return 0
    fi
    echo "    提示: 未检测到 WireGuard 内核模块。内核 5.6+ 默认内置；"
    echo "          若 WG 用户无法握手，请检查内核版本或 wireguard-tools 安装情况"
}

# 清理 Debian 11 (bullseye) 已 EOL 的 backports 源，避免 apt update 404
cleanup_apt_sources() {
    local f
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
        [ -f "$f" ] || continue
        sed -i -e '/bullseye-backports/d' -e '/buster-backports/d' "$f" 2>/dev/null || true
    done
}

# ---------- 1. 获取项目文件 ----------
fetch_project() {
    SRC_DIR=""
    if [ -n "${REMOTE:-}" ]; then
        say "从远端下载项目: $REMOTE"
        TMP=$(mktemp -d)
        curl -fsSL "$REMOTE" -o "$TMP/src.tar.gz" || die "项目包下载失败: $REMOTE"
        tar xzf "$TMP/src.tar.gz" -C "$TMP"
        SRC_DIR=$(ls -d "$TMP"/*/ | head -1)
        [ -n "$SRC_DIR" ] || die "项目包结构不正确"
    elif [ -d "$(dirname "${BASH_SOURCE[0]}")/app" ]; then
        SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    else
        die "未找到项目文件。请将项目目录放置于本机后执行 bash install.sh，或使用 REMOTE=<项目压缩包URL> 自动下载"
    fi
}

# ---------- 2. Xray（固定版本 + SHA256 校验，防止下载到被篡改的二进制） ----------
install_xray() {
    local base zip asset want_sha
    XRAY_VER=v26.3.27
    if [ "$ARCH" = "arm64" ]; then
        asset="Xray-linux-arm64-v8a.zip"; want_sha="$XRAY_ARM64_SHA256"
    else
        asset="Xray-linux-64.zip";        want_sha="$XRAY_AMD64_SHA256"
    fi
    for base in "${GH:-https://v6.gh-proxy.org/https://github.com}" \
                "https://g.10242048.shop" \
                "https://github.com" \
                "https://ghfast.top/https://github.com"; do
        zip=/tmp/xray.zip
        echo "    下载源: $base ($asset)"
        if curl -fsSL --connect-timeout 20 \
                "${base}/XTLS/Xray-core/releases/download/${XRAY_VER}/${asset}" \
                -o "$zip" 2>/dev/null \
           && [ -s "$zip" ] \
           && echo "${want_sha}  ${zip}" | sha256sum -c - >/dev/null 2>&1 \
           && unzip -l "$zip" 2>/dev/null | grep -q ' xray$'; then
            mkdir -p /tmp/xray-x
            unzip -o "$zip" -d /tmp/xray-x >/dev/null
            install -m0755 /tmp/xray-x/xray /usr/local/bin/xray
            rm -f "$zip"
            echo "    Xray 安装完成: $(/usr/local/bin/xray version 2>/dev/null | head -1)"
            return 0
        fi
        rm -f "$zip"
    done
    return 1
}

# ---------- 3. wgcf（WARP 客户端，固定版本 + SHA256 校验） ----------
install_wgcf() {
    local base asset want_sha
    WGCF_VER=2.2.22
    if [ "$ARCH" = "arm64" ]; then
        asset="wgcf_${WGCF_VER}_linux_arm64"; want_sha="$WGCF_ARM64_SHA256"
    else
        asset="wgcf_${WGCF_VER}_linux_amd64"; want_sha="$WGCF_AMD64_SHA256"
    fi
    for base in "${GH:-https://v6.gh-proxy.org/https://github.com}" \
                "https://g.10242048.shop" \
                "https://github.com" \
                "https://ghfast.top/https://github.com"; do
        if curl -fsSL --connect-timeout 10 \
                "${base}/ViRb3/wgcf/releases/download/v${WGCF_VER}/${asset}" \
                -o /tmp/wgcf 2>/dev/null \
           && echo "${want_sha}  /tmp/wgcf" | sha256sum -c - >/dev/null 2>&1; then
            install -m0755 /tmp/wgcf /usr/local/bin/wgcf
            rm -f /tmp/wgcf
            return 0
        fi
        rm -f /tmp/wgcf
    done
    return 1
}

# ---------- 4. acme.sh（证书签发） ----------
install_acme() {
    local home_acme="/root/.acme.sh/acme.sh"
    [ -f "$home_acme" ] && return 0
    if ! curl -fsSL https://get.acme.sh | sh -s email=admin@example.com 2>/dev/null; then
        echo "    官方安装脚本不可达，尝试 gitee 镜像…"
        curl -fsSL https://gitee.com/neilpang/acme.sh/raw/master/install.sh -o /tmp/acme-i.sh \
            && { [ -s /tmp/acme-i.sh ] && sh /tmp/acme-i.sh -s email=admin@example.com 2>/dev/null; } \
            || echo "    acme.sh 安装失败；需要使用证书时手动安装"
    fi
}

# ---------- 5. Python 依赖 ----------
install_py_deps() {
    local req="$APP_DIR/requirements.txt"
    python3 -m pip install --break-system-packages -r "$req" >/dev/null 2>&1 \
        || python3 -m pip install -r "$req" \
        || die "Python 依赖安装失败（aiohttp/pyyaml），请检查网络与 pip 源"
    python3 -c "import aiohttp, yaml" 2>/dev/null \
        || die "Python 依赖导入校验失败"
}

# ---------- 6. 生成配置 ----------
gen_config() {
    if [ -f "$CONF_DIR/config.yaml" ]; then
        echo "    配置文件已存在，保留现有配置"
        return 0
    fi
    say "生成配置 $CONF_DIR/config.yaml"
    PREFIX="${PREFIX:-}"
    while [ -z "$PREFIX" ]; do
        printf "输入已 BGP 广播的前缀（建议 /48，允许 /32~/64，示例 2600:xxxx:xxxx:xxxx::/48）: "
        read -r PREFIX
    done
    TOKEN="${ADMIN_TOKEN:-$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)}"
    ALLOW="${ADMIN_ALLOW:-}"
    ALLOW_LINE=$([ -n "$ALLOW" ] && printf 'admin_allow: ["%s" ]' "${ALLOW//,/\", \"}" || printf 'admin_allow: []')

    cat > "$CONF_DIR/config.yaml" <<EOF
server:
  host: "0.0.0.0"
  port: 9090
  admin_token: "$TOKEN"
  view_token: ""
  $ALLOW_LINE
network:
  prefix: "$PREFIX"
  wg_iface: "wg0"
  wg_port: 51820
  wg_addr: "fd00:1::1/64"
  wg_v4_addr: "10.7.0.1/24"
  internal_net: "fd00:1::/64"
  route_table_base: 100
  public_ip: ""
  warp_mark: 4096
  warp_table: 51820
  tc_enabled: true
  tc_wan: ""
rotation:
  min_interval: 1800
  max_interval: 7200
  start_seq: 1
xray:
  enabled: true
  bin: "/usr/local/bin/xray"
  conf: "/etc/antipole/xray.json"
  port: 80
  api_port: 10085
  sni_dest: "www.apple.com"
  dest_ip: "2600:1402:b800:d8a::1aca"
  ufp: "chrome"
  fallback: "127.0.0.1:50080"
  # 敏感域名清单由 main.py 内置默认值提供，无需在此重复配置
  trojan:
    enabled: false
    port: 2054
    cert: "/etc/antipole/tls.crt"
    key: "/etc/antipole/tls.key"
warp:
  enabled: true
  wgcf: "/usr/local/bin/wgcf"
  iface: "wg-warp"
  profile: "/etc/antipole/warp-profile.conf"
  # 多账号负载均衡（可选）：每个追加的 WARP 账号建一条独立隧道，用户 v4 流量按 id 均分
  profiles: []
  endpoints: []
dns64:
  enabled: true
  iface: "nat64"
  prefix: "64:ff9b::/96"
  v4_net: "10.44.0.0/16"
  dns_v6: "fd00:1::1"
  forward: ["2606:4700:4700::1111", "2001:4860:4860::8888"]
abuse:
  login_fails: 5
  login_ban_s: 900
  register_per_hour: 3
  default_quota_mb: 0
  default_mbps: 0
  quota_check_s: 10
  quota_warn_pct: 90
alerts:
  webhook: ""
  cert_days: 14
db:
  path: "/etc/antipole/data.sqlite3"
  keys_dir: "/etc/antipole/keys"
EOF
    chmod 600 "$CONF_DIR/config.yaml"   # 配置文件包含管理令牌，权限收紧为 600
    echo "    管理 API Token: $TOKEN   （记录保存后，亦可修改 $CONF_DIR/config.yaml）"
    echo "    管理 API 白名单: ${ALLOW:-未设置（建议在配置中补充）}"
}

# ---------- 7. 注册系统服务 ----------
setup_service() {
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null 2>&1 || true
    cat > /etc/sysctl.d/99-antipole.conf <<EOF
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.forwarding=1
EOF

    if [ "$HAS_SYSTEMD" = "1" ]; then
        cat > /etc/systemd/system/antipole.service <<EOF
[Unit]
Description=antipoleBGP main service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 -m app.main $CONF_DIR/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
MemoryMax=400M
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable antipole >/dev/null 2>&1 || true
    else
        cat > "$APP_DIR/antipole.sh" <<'EOF'
#!/usr/bin/env bash
# antipoleBGP 手工启停脚本（无 systemd 环境）
APP_DIR=/root/antipole
CONF_DIR=/etc/antipole
PIDFILE=/run/antipole.pid
LOGFILE=/var/log/antipole.log
case "${1:-start}" in
  start)
    cd "$APP_DIR"
    nohup python3 -m app.main "$CONF_DIR/config.yaml" >>"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    echo "antipole 已启动 (pid $(cat "$PIDFILE"))"
    ;;
  stop)
    [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "antipole 已停止"
    ;;
  restart) "$0" stop; sleep 1; "$0" start ;;
  *) echo "用法: $0 {start|stop|restart}"; exit 1 ;;
esac
EOF
        chmod +x "$APP_DIR/antipole.sh"
    fi
}

# ---------- 主流程 ----------
detect_pkg_mgr
detect_arch
detect_systemd

say "[1/8] 环境依赖"
fetch_project
[ "$PM" = "apt" ] && cleanup_apt_sources
pkg_ensure wg ip python3 curl nft openssl unzip pgrep
pkg_ensure_optional tayga unbound
ensure_python
check_wireguard

say "[2/8] Xray"
XRAY_AMD64_SHA256=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
XRAY_ARM64_SHA256=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c
if [ ! -x /usr/local/bin/xray ]; then
    if ! install_xray; then
        echo "    Xray 下载或校验失败（网络问题）。可先以纯 WG 模式运行，网络恢复后重新执行 install.sh 补装"
    fi
else
    echo "    Xray 已安装，跳过"
fi
# 交由 antipole 进程托管，移除潜在的官方 systemd 服务，避免双份管理
rm -f /etc/systemd/system/xray.service /usr/lib/systemd/system/xray.service 2>/dev/null || true

say "[3/8] wgcf"
WGCF_AMD64_SHA256=268d187e649870b603ad2e5c1b74a696251f6c2f6f075c726a174a0039b0b1e2
WGCF_ARM64_SHA256=e5ff08d3aae5374935211053b2d64d96daaa3f1aec8e9a1dab7418125585a011
if [ ! -x /usr/local/bin/wgcf ]; then
    if ! install_wgcf; then
        echo "    wgcf 下载或校验失败；WARP 出口将不可用（纯 v6 模式仍可使用）"
    fi
else
    echo "    wgcf 已安装，跳过"
fi

say "[4/8] acme.sh"
install_acme

say "[5/8] 项目文件与配置"
mkdir -p "$APP_DIR" "$CONF_DIR" "$CONF_DIR/keys"
if [ "$SRC_DIR" != "$APP_DIR" ]; then
    cp -r "$SRC_DIR/app" "$SRC_DIR/test_smoke.py" "$APP_DIR/"
    cp "$SRC_DIR/requirements.txt" "$APP_DIR/"
    [ -f "$SRC_DIR/mc_index.html" ] && cp "$SRC_DIR/mc_index.html" "$APP_DIR/" || true
else
    echo "    项目已位于 $APP_DIR，跳过拷贝"
fi
chmod 700 "$CONF_DIR/keys"
install_py_deps
gen_config

# 管理命令
cat > /usr/local/bin/antipole <<'EOF'
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/root/antipole")
from app.cli import main
main()
EOF
chmod +x /usr/local/bin/antipole

say "[6/8] 内核参数与服务注册"
setup_service

say "[7/8] WARP 注册"
if [ -x /usr/local/bin/wgcf ] && [ ! -f "$CONF_DIR/warp-profile.conf" ]; then
    (cd "$CONF_DIR" \
        && /usr/local/bin/wgcf register --accept-tos >/dev/null 2>&1 \
        && /usr/local/bin/wgcf generate >/dev/null 2>&1) \
        || echo "    WARP 注册未完成，antipole 启动时将自动重试"
fi

say "[8/8] 自检与启动"
(cd "$APP_DIR" && python3 test_smoke.py) || die "离线自检未通过，请检查上方输出"

if [ "$HAS_SYSTEMD" = "1" ]; then
    systemctl restart antipole
    sleep 3
    systemctl is-active antipole >/dev/null 2>&1 || {
        echo "    服务启动异常:"; journalctl -u antipole -n 30 --no-pager; exit 1
    }
else
    "$APP_DIR/antipole.sh" start
fi

echo
echo "================================================================"
echo " antipoleBGP v$INST_VERSION 安装完成"
echo "   管理 API : http://<服务器IP>:9090   （JSON API 与 /api/metrics）"
echo "   Token    : 见上方输出（或 $CONF_DIR/config.yaml）"
echo "   WG 端口  : 51820/udp     VLESS : 80/tcp"
echo "   项目目录 : $APP_DIR     配置: $CONF_DIR/config.yaml"
echo "   常用命令 :"
echo "     antipole status"
echo "     antipole user add alice"
echo "     antipole cert issue gw.example.com"
echo "   完整命令 : antipole help"
echo "   防火墙放行（未配置时）:"
echo "     bash $APP_DIR/deploy/firewall.sh"
echo "================================================================"
