#!/bin/bash
# 端口放行（nftables 版）。用 ufw 的话: ufw allow 9090/tcp; ufw allow 51820/udp; ufw allow 80/tcp
# 53/443/8443 是机器上的 DNS 服务，这里一个都不碰
# 默认对全网开放（管理 API 认证靠 token）；想限管理面来源，把下面第2段替换成白名单版
set -euo pipefail

MNG_PORT=9090        # 管理 API（JSON + metrics）
WG_PORT=51820        # WireGuard
XRAY_PORT=80         # VLESS Reality 入站（HTTP 端口 + SNI 伪装）
# TROJAN_PORT=2054   # 开了 trojan 再放行

nft add table inet antipole-fw 2>/dev/null || true
nft 'add chain inet antipole-fw input { type filter hook input priority -10 ; policy accept ; }' 2>/dev/null || true

# 本机为流量转发节点（WG 全隧道 + NAT64 借道 WARP），ufw 默认 FORWARD DROP 会阻断用户流量转发，
# 必须将默认转发策略放开。ufw 规则持久化，修改一次即可。
if command -v ufw >/dev/null 2>&1 && grep -q 'DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw 2>/dev/null; then
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    ufw reload >/dev/null 2>&1 || true
    echo "已把 ufw 默认转发策略改为 ACCEPT（WG/NAT64 转发必需）"
fi

# 管理 API / WG / VLESS 端口放行
nft add rule inet antipole-fw input tcp dport $MNG_PORT accept
nft add rule inet antipole-fw input udp dport $WG_PORT accept
nft add rule inet antipole-fw input tcp dport $XRAY_PORT accept

# 只限管理 API 来源的写法（把上面那行 tcp dport $MNG_PORT 换掉）：
#   ADMIN_SOURCES="1.2.3.4,5.6.7.8"
#   nft add rule inet antipole-fw input tcp dport $MNG_PORT ip saddr "{ $ADMIN_SOURCES }" accept
#   nft add rule inet antipole-fw input tcp dport $MNG_PORT drop

echo "规则已加：管理 API $MNG_PORT、WG $WG_PORT、VLESS $XRAY_PORT 对全网开放。"
echo "开机生效需要把规则写入 /etc/nftables.conf，请自行追加。"