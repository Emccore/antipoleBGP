#!/usr/bin/env bash
# antipole-dns · 一键安装（Linux 服务器）
#
# 联网安装（仓库 raw）：
#   curl -fsSL https://raw.githubusercontent.com/Emccore/antipoleBGP/main/dns/install-dns.sh | sudo bash
# 源码目录内安装：
#   sudo bash dns/install-dns.sh
# 卸载：
#   sudo bash dns/install-dns.sh --uninstall
#
# 做什么：
#   1. 安装 python3 / python3-yaml / unzip
#   2. 安装 mosdns v5.3.1 二进制（已存在则跳过）
#   3. 部署 dnsctl → /usr/local/bin/dnsctl，配置 → /etc/antipole-dns/
#   4. 写入 mosdns systemd 单元（与现网一致），渲染配置并落盘
#   5. 首次 geosite 初始表 → dnsctl doctor 全量自检
# 不动的东西：现有 /etc/mosdns/config.yaml 会先备份；unbound/证书/nginx 一概不碰。
set -euo pipefail

RAW=${ANTIPOLE_RAW:-https://raw.githubusercontent.com/Emccore/antipoleBGP/main}
MOSDNS_VER=v5.3.1
DIR=/etc/antipole-dns
BIN=/usr/local/bin/dnsctl
MOSDNS_BIN=/usr/local/bin/mosdns
UNIT=/etc/systemd/system/mosdns.service

c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_red=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
ok()   { printf '%s✓%s %s\n' "$c_grn" "$c_off" "$*"; }
warn() { printf '%s!%s %s\n' "$c_ylw" "$c_off" "$*"; }
die()  { printf '%s✗%s %s\n' "$c_red" "$c_off" "$*" >&2; exit 1; }
step() { printf '\n%s▸ %s%s\n' "$c_dim" "$*" "$c_off"; }

[ "$(id -u)" = 0 ] || die "请用 root 运行（sudo bash install-dns.sh）"

# ---------- 卸载 ----------
if [ "${1:-}" = "--uninstall" ]; then
    step "卸载 antipole-dns"
    systemctl disable --now mosdns >/dev/null 2>&1 || true
    rm -f "$BIN" "$UNIT"
    systemctl daemon-reload || true
    warn "mosdns.service 与 dnsctl 已移除；配置保留在 $DIR 与 /etc/mosdns（手动删除）"
    ok "卸载完成"
    exit 0
fi

# ---------- 取文件 ----------
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
HERE=""
if [ -f "${BASH_SOURCE[0]}" ]; then HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); fi

fetch() {   # fetch <文件名> <目标>
    local name=$1 dest=$2
    if [ -n "$HERE" ] && [ -f "$HERE/$name" ]; then
        cp "$HERE/$name" "$dest"; ok "$name（本地）"; return
    fi
    curl -fsSL --connect-timeout 10 "$RAW/dns/$name" -o "$dest" \
        || die "下载失败：$RAW/dns/$name"
    ok "$name（已下载）"
}

step "检查依赖"
yaml_pkg=python3-yaml
if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then yaml_pkg=python3-pyyaml; fi
if command -v apk >/dev/null 2>&1; then yaml_pkg=py3-yaml; fi
need=()
command -v curl >/dev/null 2>&1 || need+=(curl)
command -v unzip >/dev/null 2>&1 || need+=(unzip)
python3 --version >/dev/null 2>&1 || need+=(python3)
python3 -c "import yaml" >/dev/null 2>&1 || need+=("$yaml_pkg")
if [ ${#need[@]} -gt 0 ]; then
    warn "安装缺失依赖：${need[*]}"
    if   command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq "${need[@]}"
    elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q "${need[@]}"
    elif command -v yum     >/dev/null 2>&1; then yum install -y -q "${need[@]}"
    elif command -v apk     >/dev/null 2>&1; then apk add --no-cache "${need[@]}"
    fi
fi
python3 -c "import yaml" >/dev/null 2>&1 || die "PyYAML 不可用：请手动安装 $yaml_pkg"
command -v curl >/dev/null 2>&1 || die "缺少 curl"
command -v unzip >/dev/null 2>&1 || die "缺少 unzip"
ok "python3 + PyYAML + curl + unzip 就绪"

step "安装 mosdns 二进制"
if [ -x "$MOSDNS_BIN" ] && "$MOSDNS_BIN" version 2>/dev/null | grep -q "v5"; then
    ok "已存在：$("$MOSDNS_BIN" version 2>/dev/null | head -1)"
else
    arch=$(uname -m); case "$arch" in x86_64) ga=amd64 ;; aarch64) ga=arm64 ;; *) die "不支持的架构：$arch" ;; esac
    curl -fsSL --connect-timeout 15 "https://github.com/IrineSistiana/mosdns/releases/download/${MOSDNS_VER}/mosdns-linux-${ga}.zip" \
        -o "$TMP/mosdns.zip" || die "mosdns 下载失败（也可手动放置 $MOSDNS_BIN）"
    unzip -o -q "$TMP/mosdns.zip" -d "$TMP/m"
    install -m 0755 "$(find "$TMP/m" -name mosdns -type f | head -1)" "$MOSDNS_BIN"
    ok "mosdns 已安装（$("$MOSDNS_BIN" version 2>/dev/null | head -1)）"
fi

step "部署 dnsctl 与配置"
fetch dnsctl.py        "$TMP/dnsctl.py"
fetch dns.example.yaml "$TMP/dns.example.yaml"
fetch geosite_cn.txt   "$TMP/geosite_cn.txt"
install -m 0755 "$TMP/dnsctl.py" "$BIN"
mkdir -p "$DIR"
[ -f "$DIR/dns.yaml" ] && { ok "配置已存在，保留 $DIR/dns.yaml"; } \
                       || { install -m 600 "$TMP/dns.example.yaml" "$DIR/dns.yaml"; ok "已写入 $DIR/dns.yaml（按需修改后 dnsctl apply）"; }
[ -f "$DIR/geosite_cn.txt" ] || install -m 644 "$TMP/geosite_cn.txt" "$DIR/geosite_cn.txt"
ok "程序与初始配置就位"

step "systemd 服务单元"
if [ -f "$UNIT" ]; then
    ok "已存在 $UNIT（不覆盖）"
else
    cat > "$UNIT" <<EOF
[Unit]
Description=antipole-dns (mosdns DNS resolver)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$MOSDNS_BIN start -c /etc/mosdns/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
MemoryMax=256M
CPUQuota=50%
LimitNOFILE=65535
WorkingDirectory=$DIR

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    ok "单元已写入 $UNIT"
fi

step "渲染配置并落盘"
# 现有 /etc/mosdns/config.yaml 会被 dnsctl 自动备份后覆盖（内容与现网等价）
"$BIN" -c "$DIR/dns.yaml" apply -y --restart || warn "apply 未全部成功（证书路径等按需修改 dns.yaml）"

step "自检"
"$BIN" -c "$DIR/dns.yaml" doctor || warn "doctor 有告警，逐项排查后重跑：dnsctl doctor"

printf '\n'
ok "antipole-dns 安装完成"
printf '%s\n' \
"  手动查询   dnsctl test www.qq.com --udp 127.0.0.1:53" \
"  全面自检   dnsctl doctor" \
"  改配置     vi $DIR/dns.yaml && dnsctl apply" \
"  更新分流表 dnsctl geosite update" \
"  开广告拦截 dnsctl blocklist update --enable  然后在 dns.yaml 设 enabled: true 并 apply"
