# -*- coding: utf-8 -*-
"""
管理命令层：antipole 全部子命令。

命令直接读写同一份配置与数据库，并对运行中的服务发送 SIGHUP 触发热载
（systemd: ExecReload），不重启、不中断连接。整条命令持独占文件锁，
与服务端的共享锁互斥，避免并发修改内核状态。

用法：antipole <子命令> [参数]
"""
import argparse
import asyncio
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import core, edge, net, web

CONF_PATH = Path("/etc/antipole/config.yaml")
BASE = Path(__file__).resolve().parent.parent


def _cfg_path() -> str:
    return str(CONF_PATH) if CONF_PATH.exists() else str(BASE / "config.yaml")


def _setup(cfg: dict):
    import os
    os.umask(0o077)
    Path(cfg["db"]["path"]).parent.mkdir(parents=True, exist_ok=True)
    Path(cfg["db"]["keys_dir"]).mkdir(parents=True, exist_ok=True)
    core.init(cfg["db"]["path"])
    core.setup_mutex(cfg)
    core.setup_pools(cfg)
    net.setup(cfg)
    edge.setup(cfg)
    edge.setup_guard(cfg)
    # 复用 Web 层的用户创建逻辑（保证 CLI 与 API 行为一致）
    web.setup(cfg, None, None, None)
    cfg["_wg_pub"] = ""


def _resolve(ident: str):
    """按 ID 或用户名定位用户。"""
    user = core.get_user(int(ident)) if ident.isdigit() else core.get_user_by_name(ident)
    if not user:
        sys.exit(f"未找到用户: {ident}")
    return user


async def _reload_service(cfg):
    """通知运行中的服务热载 Xray 配置。"""
    if CONF_PATH.exists():
        await core.cmd("systemctl", "reload", "antipole", check=False)
    else:
        print("(非部署环境，跳过 SIGHUP 通知)")


def _fmt_size(mb: float) -> str:
    return f"{mb / 1024:.1f}G" if mb >= 1024 else f"{mb:.1f}M"


# ============================================================
# 状态与查询
# ============================================================

def _tunnel_snapshot() -> tuple:
    """隧道在线数与映射端口数。

    CLI 是独立进程，拿不到主服务内存里的会话表，此时回退到运行时快照
    （主服务每 10 秒写入一次），避免把正常在线的隧道显示成 0。
    """
    live = edge.tunnel_sessions()
    if live["count"] or live["ports"]:
        return live["count"], live["ports"]
    now = core.now_ms()
    valid = {user["id"] for user in core.list_users()}
    fresh = [r for uid, r in core.list_runtime_stats().items()
             if uid in valid and (now - r["ts"]) / 1000 < 120]
    return (sum(1 for r in fresh if r["tunnel_on"]),
            sum(r["ports"] for r in fresh))


async def cmd_status(cfg, args):
    free = total = 0
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            kb = int(value.strip().split()[0])
            if key == "MemAvailable":
                free = kb
            elif key == "MemTotal":
                total = kb
    except OSError:
        pass
    peers = await net.wg_dump()
    online = sum(1 for i in peers.values()
                 if i["handshake"] and time.time() - i["handshake"] / 1e9 < 300)
    warp_up = await net.warp_is_up()
    bgp = await net.bgp_status()
    tunnel_online, tunnel_ports = _tunnel_snapshot()
    rotation = cfg["rotation"]

    print(f"前缀     : {cfg['network']['prefix']}")
    ranges = cfg["network"].get("ranges") or {}
    range_desc = ", ".join(f"{key or '主段'}={value}" for key, value in ranges.items())
    print(f"命名网段 : {range_desc}")
    print(f"地址守护 : {'开启（仅已分配地址可达本机）' if cfg['network'].get('guard_allocated', True) else '关闭'}")
    if rotation.get("enabled"):
        print(f"轮换     : {rotation.get('min_interval', 1800)//60}~"
              f"{rotation.get('max_interval', 7200)//60} 分钟/每用户随机"
              f"（隧道用户不参与）")
    else:
        print("地址绑定 : 永久固定（每个用户的 /128 与账户绑定，不做轮换）")
    print(f"内存     : {free/1024:.0f}MB 可用 / {total/1024:.0f}MB")
    print(f"用户     : {len(core.list_users())}   在线: {online}")
    print(f"Xray     : {'运行中' if edge.xray_running() else '未运行'}  (VLESS :{cfg['xray']['port']})")
    print(f"WARP     : {'UP ' + (await net.warp_v4()) if warp_up else 'DOWN'}")
    print(f"DNS64    : {'ON (' + cfg['dns64']['iface'] + ')' if await net.dns64_up() else 'OFF'}")
    print(f"BGP      : {','.join(bgp['daemons']) if bgp['daemons'] else '未检测到'} "
          f"{'正常' if bgp['alive'] else '提醒：BGP 守护进程未运行'}")
    print(f"隧道     : {'开启 :' + str(cfg['tunnel'].get('port', 18281)) if edge.tunnel_enabled() else '关闭'}"
          f"   在线 {tunnel_online}   已映射端口 {tunnel_ports}"
          f"   隧道用户 {len(core.list_tunnel_users())}")
    print(f"注册服务 : {'开启 :' + str(cfg['server'].get('register_port', 18290)) if cfg['server'].get('register_enabled') else '关闭'}")
    if bgp["detail"]:
        print(bgp["detail"].rstrip())

    # 活动地址健康状态（在线、累计流量、实时速率、隧道连接）
    await _print_health(cfg)


def _human_rate(bps: int) -> str:
    if bps <= 0:
        return "-"
    if bps >= 1048576:
        return f"{bps / 1048576:.1f}MB/s"
    if bps >= 1024:
        return f"{bps / 1024:.1f}KB/s"
    return f"{bps}B/s"


async def _print_health(cfg):
    """列出全部用户的活动地址健康状态、累计流量与实时速率。"""
    users = core.list_users()
    if not users:
        return
    stats = core.list_runtime_stats()
    now = core.now_ms()
    print()
    print("活动地址健康状态")
    print(f"{'ID':<4}{'名称':<14}{'出口/128':<42}{'状态':<12}{'连接':<6}"
          f"{'端口':<6}{'上行速率':<11}{'下行速率':<11}{'累计':<12}{'配额用量'}")
    active = 0
    for user in users:
        record = stats.get(user["id"], {})
        age = (now - record["ts"]) / 1000 if record else None
        fresh = age is not None and age < 120
        online = bool(record.get("online")) and fresh
        tunnel_on = bool(record.get("tunnel_on")) and fresh
        if online or tunnel_on:
            active += 1
        if not user["enabled"]:
            state = "已禁用"
        elif online and tunnel_on:
            state = "在线(双通道)"
        elif online:
            state = "在线(接入)"
        elif tunnel_on:
            state = "在线(隧道)"
        else:
            state = "离线"
        used = (user["used_up"] + user["used_down"]) / 1048576
        quota = user["quota_mb"]
        if quota:
            pct = (user["used_up"] + user["used_down"]) * 100.0 / (quota * 1048576)
            quota_desc = f"{pct:.0f}%/{_fmt_size(quota)}"
        else:
            quota_desc = "不限"
        print(f"{user['id']:<4}{user['name']:<14}{user['egress_ip']:<42}"
              f"{state:<12}{record.get('conns', 0):<6}{record.get('ports', 0):<6}"
              f"{_human_rate(record.get('up_bps', 0)):<11}"
              f"{_human_rate(record.get('down_bps', 0)):<11}"
              f"{_fmt_size(used):<12}{quota_desc}")
    print(f"合计 {len(users)} 个用户，其中 {active} 个在线")


async def cmd_users(cfg, args):
    print(f"{'ID':<4}{'名称':<16}{'网段':<10}{'出口/128':<42}{'流量':<16}{'限速':<7}{'状态':<8}{'在线'}")
    peers = await net.wg_dump()
    now = int(time.time())
    for user in core.list_users():
        handshake = peers.get(user["pubkey"], {}).get("handshake", 0)
        online = "是" if handshake and now - handshake / 1e9 < 300 else "-"
        used = (user["used_up"] + user["used_down"]) / 1048576
        quota = f"/{_fmt_size(user['quota_mb'])}" if user["quota_mb"] else ""
        print(f"{user['id']:<4}{user['name']:<16}{(user.get('range_name') or '主段'):<10}"
              f"{user['egress_ip']:<42}{_fmt_size(used) + quota:<16}"
              f"{str(user['max_mbps']) + 'M' if user['max_mbps'] else '-':<7}"
              f"{'启用' if user['enabled'] else '禁用':<8}{online}")


async def cmd_user_get(cfg, args):
    user = _resolve(args.user)
    peers = await net.wg_dump()
    handshake = peers.get(user["pubkey"], {}).get("handshake", 0)
    online = "在线" if handshake and time.time() - handshake / 1e9 < 300 else "-"
    domain = core.primary_domain()
    tunnel = core.get_tunnel_user(user["id"])
    print(f"ID       : {user['id']}")
    print(f"名称     : {user['name']}")
    print(f"命名网段 : {user.get('range_name') or '主段'}")
    print(f"内网     : {user['internal_ip']}"
          + (f" / {core.internal_v4(user['id'])}" if core.internal_v4(user["id"]) else ""))
    print(f"出口/128 : {user['egress_ip']}")
    print(f"流量     : {(user['used_up'] + user['used_down']) / 1048576:.1f}M"
          f"{' / ' + str(user['quota_mb']) + 'M' if user['quota_mb'] else ''}")
    print(f"限速     : {str(user['max_mbps']) + 'Mbps' if user['max_mbps'] else '不限'}")
    print(f"状态     : {'启用' if user['enabled'] else '禁用'}   在线: {online}")
    if edge.GUARD and edge.GUARD.is_protected(user):
        left = (user["protect_until"] - core.now_ms()) // 1000
        print(f"熔断     : 保护中（剩余 {left} 秒）")
    if tunnel:
        print(f"隧道     : 已映射 {len(core.list_tunnel_maps(user['id']))} 个端口，"
              f"用量 {_fmt_size(tunnel['used_bytes'] / 1048576)}"
              f"（公网端口与用户本地端口 1:1 对应）")
    print(f"创建时间 : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(user['created_at']/1000))}")
    print(f"VLESS    : {edge.vless_link(user, domain)}")


async def cmd_link(cfg, args):
    user = _resolve(args.user)
    print(edge.vless_link(user, core.primary_domain()))


async def cmd_wg(cfg, args):
    user = _resolve(args.user)
    pub = await net.wg_server_pub()
    server_ip = (cfg["server"].get("public_ip")
                 or cfg["network"].get("public_ip") or "")
    if not server_ip:
        sys.exit("无法确定公网地址，请在配置中设置 server.public_ip")
    v4 = core.internal_v4(user["id"])
    print("[Interface]")
    print(f"Address = {user['internal_ip']}/128")
    if v4:
        print(f"Address = {v4}/32")
    print(f"PrivateKey = {user['privkey']}")
    print(f"DNS = {cfg['dns64']['dns_v6'] if cfg['dns64'].get('enabled', True) else '2001:4860:4860::8888, 1.1.1.1'}")
    print()
    print("[Peer]")
    print(f"PublicKey = {pub}")
    print(f"Endpoint = {server_ip}:{cfg['network']['wg_port']}")
    print(f"AllowedIPs = {'0.0.0.0/0, ::/0' if cfg['warp']['enabled'] and v4 else '::/0'}")
    print("PersistentKeepalive = 25")


# ============================================================
# 用户管理
# ============================================================

async def cmd_user_add(cfg, args):
    from .web import create_user_internal
    name = args.name
    if len(name) > 32:
        sys.exit("用户名过长")
    if core.get_user_by_name(name):
        sys.exit("用户名已存在")
    range_name = getattr(args, "range", "") or ""
    if range_name and range_name not in (cfg["network"].get("ranges") or {}):
        sys.exit(f"命名网段不存在: {range_name}")
    user = await create_user_internal(name, range_name)
    domain = core.primary_domain()
    print(f"用户 {name} 已创建 (id={user['id']}, 网段 {range_name or '主段'}, 出口 {user['egress_ip']})")
    print(f"VLESS: {edge.vless_link(user, domain)}")
    print(f"WG 配置: antipole wg {user['id']}")


async def cmd_create(cfg, args):
    await cmd_user_add(cfg, args)
    user = core.get_user_by_name(args.name)
    extras = []
    if getattr(args, "rate", 0):
        core.update_user(user["id"], max_mbps=max(0, int(args.rate)))
        await net.tc_set_rate(user["id"], max(0, int(args.rate)))
        extras.append(f"限速 {args.rate}Mbps")
    if getattr(args, "quota", 0):
        core.update_user(user["id"], quota_mb=max(0, int(args.quota)))
        extras.append(f"配额 {args.quota}MB")
    if extras:
        print("附加设置: " + "、".join(extras))


async def cmd_user_del(cfg, args):
    from .web import purge_user
    user = _resolve(args.user)
    await purge_user(user["id"], user)
    print(f"用户 {user['name']} 已删除（内核状态、限速、隧道与地址登记一并清理）")


async def cmd_user_toggle(cfg, args):
    user = _resolve(args.user)
    enable = not user["enabled"]
    core.update_user(user["id"], enabled=1 if enable else 0)
    if enable:
        await net.wg_add_peer(user["id"], user["pubkey"])
    else:
        await net.wg_del_peer(user["id"], user["pubkey"])
    await edge.sync_user(core.get_user(user["id"]), enable)
    print(f"{user['name']}: {'已启用' if enable else '已禁用'}"
          f"（代理侧动态生效，既有连接不受影响）")


async def cmd_user_rotate(cfg, args):
    user = _resolve(args.user)
    if not cfg["rotation"].get("enabled"):
        sys.exit("地址与账户绑定（rotation.enabled=false），轮换已关闭；确需轮换请先在配置中开启")
    if core.get_tunnel_user(user["id"]):
        sys.exit(f"{user['name']} 为隧道用户，静态地址用于端口映射与证书，不允许轮换")
    egress = await net.Rotator(cfg).rotate_one(user)
    print(f"{user['name']}: 出口已轮换至 {egress}")


async def cmd_user_rate(cfg, args):
    user = _resolve(args.user)
    mbps = max(0, int(args.mbps))
    core.update_user(user["id"], max_mbps=mbps)
    if core.get_tunnel_user(user["id"]):
        core.update_tunnel_user(user["id"], max_mbps=mbps)
    print(f"{user['name']}: {await net.tc_set_rate(user['id'], mbps)}")


async def cmd_user_quota(cfg, args):
    user = _resolve(args.user)
    quota = max(0, int(args.mb))
    core.update_user(user["id"], quota_mb=quota)
    if core.get_tunnel_user(user["id"]):
        core.update_tunnel_user(user["id"], quota_mb=quota)
    print(f"{user['name']}: 流量配额 {quota}MB")


async def cmd_user_limit(cfg, args):
    """统一限速与配额：同时作用于常规接入与隧道接入。"""
    user = _resolve(args.user)
    traffic = max(0, int(args.traffic or 0))
    speed = max(0, int(getattr(args, "speed", 0) or 0))
    core.update_user(user["id"], quota_mb=traffic, max_mbps=speed)
    has_tunnel = bool(core.get_tunnel_user(user["id"]))
    if has_tunnel:
        core.update_tunnel_user(user["id"], quota_mb=traffic, max_mbps=speed)
    result = await net.tc_set_rate(user["id"], speed)
    scope = "常规接入 + 隧道接入" if has_tunnel else "常规接入"
    print(f"{user['name']}: 配额 {traffic}MB、限速 {speed}Mbps（作用于{scope}）；{result}")


async def cmd_user_reset(cfg, args):
    user = _resolve(args.user)
    core.update_user(user["id"], used_up=0, used_down=0)
    if core.get_tunnel_user(user["id"]):
        core.update_tunnel_user(user["id"], used_bytes=0)
    print(f"{user['name']}: 流量计数已清零")


# ============================================================
# 隧道管理
# ============================================================

def _tunnel_endpoint() -> str:
    """客户端接入点：隧道专属网段的首地址（未启用隧道时退回占位符）。"""
    addr = net.tunnel_control_addr()
    return f"[{addr}]" if addr else "<服务器IP>"


async def cmd_tunnel_add(cfg, args):
    import secrets
    from .web import create_user_internal
    if not edge.tunnel_enabled():
        sys.exit("隧道功能未启用（配置 tunnel.enabled=true 后重启服务）")
    name = args.name
    if core.get_user_by_name(name):
        sys.exit("用户名已存在")
    range_name = (getattr(args, "range", "") or "").strip() \
        or cfg["tunnel"].get("range", "tunnel")
    user = await create_user_internal(name, range_name)
    token = secrets.token_hex(16)
    core.add_tunnel_user(user["id"], token,
                         max(0, getattr(args, "quota", 0)),
                         max(0, getattr(args, "rate", 0)))
    print(f"隧道用户 {name} 已创建 (id={user['id']})")
    print(f"  静态地址 : {user['egress_ip']}（网段 {range_name}，永久固定）")
    print(f"  端口映射 : 用户本地端口 = 公网端口（一一对应，无需申请）")
    print(f"  访问方式 : <{user['egress_ip']}>:<端口> == 用户主机 127.0.0.1:<端口>")
    print(f"  接入地址 : {_tunnel_endpoint()}:{cfg['tunnel'].get('port', 18281)}（隧道网段首地址，固定不变）")
    print(f"  Token    : {token}")
    print(f"  客户端   : python3 tools/antipole-tunnel.py "
          f"--server {_tunnel_endpoint()}:{cfg['tunnel'].get('port', 18281)} --token {token} --map <本地端口>")


async def cmd_tunnel_del(cfg, args):
    await cmd_user_del(cfg, args)


async def cmd_tunnel_toggle(cfg, args):
    await cmd_user_toggle(cfg, args)


async def cmd_tunnel_list(cfg, args):
    rows = core.list_tunnel_users()
    if not rows:
        print("暂无隧道用户，使用 antipole tunnel add <名称> 创建")
        return
    print(f"{'ID':<4}{'名称':<16}{'静态地址':<42}{'映射':<6}"
          f"{'限速':<8}{'配额':<10}{'用量':<10}{'状态'}")
    for row in rows:
        quota = _fmt_size(row["quota_mb"]) if row["quota_mb"] else "不限"
        print(f"{row['user_id']:<4}{row['user_name']:<16}{row['egress_ip']:<42}"
              f"{row['port_count']:<6}"
              f"{str(row['max_mbps']) + 'M' if row['max_mbps'] else '-':<8}"
              f"{quota:<10}{_fmt_size(row['used_bytes'] / 1048576):<10}"
              f"{'启用' if row['user_enabled'] else '禁用'}")


async def cmd_tunnel_token(cfg, args):
    user = _resolve(args.user)
    row = core.get_tunnel_user(user["id"])
    if not row:
        sys.exit(f"{user['name']} 不是隧道用户")
    print(f"Token  : {row['token']}")
    endpoint = _tunnel_endpoint()
    print(f"Server : {endpoint}:{cfg['tunnel'].get('port', 18281)}")
    print(f"客户端 : python3 tools/antipole-tunnel.py "
          f"--server {endpoint}:{cfg['tunnel'].get('port', 18281)} "
          f"--token {row['token']} --map 8080")


async def cmd_tunnel_limit(cfg, args):
    """tunnel limit <用户> <流量MB> [速度Mbps]：隧道侧独立的配额与限速。"""
    user = _resolve(args.user)
    if not core.get_tunnel_user(user["id"]):
        sys.exit(f"{user['name']} 不是隧道用户")
    traffic = max(0, int(args.traffic or 0))
    speed = max(0, int(getattr(args, "speed", 0) or 0))
    core.update_tunnel_user(user["id"], quota_mb=traffic, max_mbps=speed)
    if speed:
        core.update_user(user["id"], max_mbps=speed)
        await net.tc_set_rate(user["id"], speed)
    print(f"{user['name']}: 隧道配额 {traffic}MB、限速 {speed}Mbps")


async def cmd_tunnel_show(cfg, args):
    user = _resolve(args.user)
    row = core.get_tunnel_user(user["id"])
    if not row:
        sys.exit(f"{user['name']} 不是隧道用户")
    online = any(s.uid == user["id"] for s in edge._sessions.values())
    print(f"隧道用户 : {row['user_name']}")
    print(f"静态地址 : {row['egress_ip']}（{row['range_name'] or '主段'}）")
    print(f"连接状态 : {'在线' if online else '离线'}")
    print(f"配额     : {_fmt_size(row['quota_mb']) if row['quota_mb'] else '不限'}"
          f"   已用 {_fmt_size(row['used_bytes'] / 1048576)}")
    print(f"限速     : {str(row['max_mbps']) + 'Mbps' if row['max_mbps'] else '不限'}")
    maps = core.list_tunnel_maps(user["id"])
    if maps:
        print("端口映射（公网端口与用户本地端口一致，一一对应）:")
        for item in maps:
            print(f"  {row['egress_ip']}:{item['remote_port']}"
                  f"  →  用户主机 {item['local_ip']}:{item['local_port']}")
    else:
        print("端口映射 : 暂无（客户端 --map 声明后自动建立）")


async def cmd_tunnel_ports(cfg, args):
    """列出被禁止或被占用的端口，便于用户挑一个可用的映射端口。"""
    tun = cfg["tunnel"]
    min_port = int(tun.get("min_port", 1))
    deny = sorted({int(x) for x in (tun.get("deny_ports") or [])})
    hosts = await edge.host_ports()

    print("保留端口（可选收紧项）："
          + ("、".join(str(p) for p in deny) if deny else "无（默认全开 1-65535）"))
    if min_port > 1:
        print(f"特权端口：小于 {min_port} 全部禁止")
    print("主机 IPv6 通配监听（物理上无法映射，换端口即可）：")
    if hosts:
        for port in sorted(hosts):
            print(f"  {port:<8}{hosts[port]}")
    else:
        print("  无（ss 不可用或没有 IPv6 通配监听）")
    print("提示：用户 /128 相互独立，同一端口号可同时被多个用户映射；仅主机以 IPv6 通配"
          "地址占用的端口不可用（IPv4 通配与绑在具体地址上的服务都不冲突）。")


# ============================================================
# 命名网段
# ============================================================

async def cmd_range_list(cfg, args):
    ranges = cfg["network"].get("ranges") or {}
    print(f"{'名称':<12}{'前缀':<46}{'用户数':<8}{'用途'}")
    for name, prefix in ranges.items():
        count = sum(1 for u in core.list_users()
                    if (u.get("range_name") or "") == name)
        usage = "隧道专属" if name == "tunnel" else ("默认" if name == "" else "业务分段")
        print(f"{(name or '主段'):<12}{prefix:<46}{count:<8}{usage}")


def _update_config(mutator):
    """读取配置、应用修改、写回（保持 600 权限）。"""
    cfg = core.load_config(_cfg_path())
    mutator(cfg)
    core.save_config(cfg, _cfg_path())


async def cmd_range_add(cfg, args):
    name, prefix = args.name, args.prefix
    try:
        core.V6Pool(prefix)
    except ValueError as e:
        sys.exit(f"前缀不合法: {e}")

    def mutate(conf):
        conf["network"].setdefault("ranges", {})[name] = prefix

    _update_config(mutate)
    print(f"已添加命名网段 {name} -> {prefix}（重启服务生效）")


async def cmd_range_del(cfg, args):
    name = args.name
    if name == "tunnel":
        sys.exit("隧道专属网段不可删除（可在配置中改用 tunnel_range 重定向）")

    def mutate(conf):
        (conf["network"].get("ranges") or {}).pop(name, None)

    _update_config(mutate)
    count = sum(1 for u in core.list_users() if (u.get("range_name") or "") == name)
    print(f"已移除命名网段 {name}（{count} 个用户仍引用，重启后回退主段）")


async def cmd_range_apply(cfg, args):
    """无损应用网段变更：仅重建内核路由与地址守护，不改动既有用户地址。"""
    await net.addr_guard_init()
    for user in core.list_users():
        if not user["enabled"]:
            continue
        try:
            await net.wg_add_peer(user["id"], user["pubkey"])
        except Exception as e:
            print(f"  用户 {user['name']} 重建失败: {e}")
    print("网段变更已无损应用：既有用户地址保持不变，"
          "内核路由与地址守护已重建")


async def cmd_range_move(cfg, args):
    """把某网段下的全部用户迁移到目标网段（逐个轮换，不中断服务）。"""
    src, dst = args.src, args.dst
    ranges = cfg["network"].get("ranges") or {}
    if dst not in ranges:
        sys.exit(f"目标网段不存在: {dst}")
    targets = [u for u in core.list_users() if (u.get("range_name") or "") == src]
    if not targets:
        print(f"网段 {src or '主段'} 下没有用户")
        return
    rotator = net.Rotator(cfg)
    tunnel_uids = {row["user_id"] for row in core.list_tunnel_users()}
    migrated = skipped = 0
    for user in targets:
        if user["id"] in tunnel_uids:
            print(f"  {user['name']} 跳过：隧道用户地址与账户绑定（端口映射/证书依赖），不迁移")
            skipped += 1
            continue
        core.update_user(user["id"], range_name=dst)
        fresh = core.get_user(user["id"])
        core.update_user(user["id"], rotate_seq=0)
        try:
            egress = await rotator.rotate_one(core.get_user(user["id"]))
            print(f"  {fresh['name']} -> {egress}")
            migrated += 1
        except Exception as e:
            print(f"  {fresh['name']} 迁移失败: {e}")
    tail = f"，跳过隧道用户 {skipped} 个" if skipped else ""
    print(f"已迁移 {migrated} 个用户：{src or '主段'} -> {dst}{tail}")


# ============================================================
# 自助注册服务
# ============================================================

async def cmd_register(cfg, args):
    action = args.action
    if action == "show":
        enabled = cfg["server"].get("register_enabled", False)
        print(f"自助注册: {'已开启' if enabled else '已关闭'}   "
              f"端口 {cfg['server'].get('register_port', 18290)}")
        return

    def mutate(conf):
        conf["server"]["register_enabled"] = (action == "on")
        if getattr(args, "port", 0):
            conf["server"]["register_port"] = int(args.port)

    _update_config(mutate)
    port = getattr(args, "port", 0) or cfg["server"].get("register_port", 18290)
    state = "开启" if action == "on" else "关闭"
    print(f"自助注册已{state}（端口 {port}）；执行 systemctl restart antipole 生效")


# ============================================================
# 接入域名
# ============================================================

async def cmd_domains(cfg, args):
    rows = core.list_domains()
    if not rows:
        print("暂无接入域名（用户连接将使用服务器 IP）")
        return
    for item in rows:
        print(f"[{item['id']}] {item['domain']:<32} IP={item['ip'] or '-':<18} "
              f"端口={item['port'] or '默认':<8} "
              f"{'启用' if item['enabled'] else '停用'} {item['note']}")


async def cmd_domain_add(cfg, args):
    try:
        did = core.add_domain(args.domain, args.ip or "", args.port or 0,
                            args.note or "")
    except Exception:
        sys.exit("域名已存在或格式不正确")
    print(f"已添加接入域名 (id={did})")


async def cmd_domain_ip(cfg, args):
    domain = core.get_domain(int(args.id))
    if not domain:
        sys.exit(f"域名 id {args.id} 不存在")
    core.update_domain(int(args.id), ip=args.ip)
    print(f"{domain['domain']} -> {args.ip}")


async def cmd_domain_del(cfg, args):
    domain = core.get_domain(int(args.id))
    if not domain:
        sys.exit(f"域名 id {args.id} 不存在")
    core.delete_domain(int(args.id))
    print(f"已删除接入域名: {domain['domain']}")


async def cmd_domain_toggle(cfg, args):
    domain = core.get_domain(int(args.id))
    if not domain:
        sys.exit(f"域名 id {args.id} 不存在")
    enabled = 0 if domain["enabled"] else 1
    core.update_domain(int(args.id), enabled=enabled)
    await _reload_service(cfg)
    print(f"{domain['domain']}: {'已启用' if enabled else '已停用'}")


# ============================================================
# 邀请码 / 备份 / 日志 / 版本
# ============================================================

async def cmd_invite(cfg, args):
    import secrets
    count = max(1, min(50, getattr(args, "count", 1) or 1))
    for _ in range(count):
        print(core.add_invite(secrets.token_urlsafe(12)))
    if count > 1:
        print(f"(共 {count} 个)")


async def cmd_invites(cfg, args):
    rows = core.list_invites()
    if not rows:
        print("暂无邀请码，使用 antipole invite 生成")
        return
    print(f"{'邀请码':<24}{'创建时间':<20}{'状态':<8}{'使用者'}")
    for row in rows:
        created = time.strftime("%Y-%m-%d %H:%M",
                                time.localtime(row["created_at"] / 1000))
        print(f"{row['code']:<24}{created:<20}"
              f"{'已使用' if row['used'] else '未使用':<8}{row['used_by'] or ''}")


async def cmd_abuse(cfg, args):
    rows = core.list_abuse(limit=args.n or 30)
    if not rows:
        print("暂无滥用事件记录")
        return
    print(f"{'时间':<20}{'类型':<14}{'对象':<20}{'详情'}")
    for row in rows:
        when = time.strftime("%Y-%m-%d %H:%M:%S",
                             time.localtime(row["ts"] / 1000))
        print(f"{when:<20}{row['kind']:<14}{row['subject']:<20}{row['detail']}")


async def cmd_backup(cfg, args):
    src = Path(cfg["db"]["path"])
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dst = src.with_name(f"data.sqlite3.bak.{stamp}")
    shutil.copy2(src, dst)
    print(f"已备份: {dst}")


async def cmd_log(cfg, args):
    proc = await asyncio.create_subprocess_exec(
        "journalctl", "-u", "antipole", "-n", str(args.n or 50), "--no-pager",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    out, _ = await proc.communicate()
    print(out.decode(errors="replace"))


async def cmd_version(cfg, args):
    from . import __version__
    print(f"antipoleBGP V{__version__}")


# ============================================================
# 证书（acme.sh）
# ============================================================

def _acme() -> Path:
    for path in (Path.home() / ".acme.sh" / "acme.sh",
                 Path("/root/.acme.sh/acme.sh")):
        if path.exists():
            return path
    return Path("acme.sh")


def _cert_dir(domain: str) -> Path:
    return Path("/etc/antipole/certs") / domain


async def cmd_cert_issue(cfg, args):
    domain = args.domain
    acme = _acme()
    if not acme.exists():
        sys.exit("未找到 acme.sh，请先安装："
                 "curl https://get.acme.sh | sh -s email=you@example.com")
    record = None
    for row in core.list_domains():
        if row["domain"] == domain:
            record = row
            break
    if record is None:
        print(f"域名 {domain} 不在接入列表，可先执行 "
              f"antipole domain add {domain}")
    answer = input(f"为 {domain} 申请证书？域名需已解析至本机 (y/N): ").strip().lower()
    if answer not in ("y", "yes"):
        sys.exit("已取消")

    cert_dir = _cert_dir(domain)
    cert_dir.mkdir(parents=True, exist_ok=True)
    crt = str(cert_dir / "fullchain.pem")
    key = str(cert_dir / "key.pem")
    issue = [str(acme), "--issue", "-d", domain]
    issue += ["--webroot", args.webroot] if args.webroot else ["--standalone"]
    output = await core.cmd(*issue, check=False)
    print(output[-600:] if output else "(acme.sh 无输出)")
    if not any(k in output for k in ("Your cert is in", "Cert success", "already")):
        sys.exit("申请失败，请确认域名解析与 80 端口可用性")
    await core.cmd(str(acme), "--install-cert", "-d", domain,
                   "--key-file", key, "--fullchain-file", crt,
                   "--reloadcmd", "antipole cert reload --silent", check=False)
    if record:
        core.update_domain(record["id"], cert_crt=crt, cert_key=key,
                         cert_at=int(time.time()))
    elif args.auto_add:
        core.add_domain(domain, "", 0, "auto cert")
    print(f"证书已就绪:\n  {crt}\n  {key}")
    await _reload_service(cfg)


async def cmd_cert_renew(cfg, args):
    acme = _acme()
    if not acme.exists():
        sys.exit("未找到 acme.sh")
    await core.cmd(str(acme), "--renew", "-d", args.domain,
                   *("--force",) if args.force else (), check=False)
    print("续期完成（或无需续期），续期钩子将自动热载 Xray")


async def cmd_cert_list(cfg, args):
    for item in core.list_domains():
        extra = ""
        if item["cert_crt"]:
            days = await _cert_days(item["cert_crt"])
            extra = f"  剩余 {days} 天" if days is not None else "  证书不可读"
        print(f"[{item['id']}] {item['domain']:<32}"
              f"{'有证书' if item['cert_crt'] else '无证书':<8}{extra}")


async def _cert_days(crt: str):
    from .web import _cert_days_left
    return await _cert_days_left(crt)


async def cmd_cert_check(cfg, args):
    from .web import _cert_days_left
    seen = False
    for item in core.list_domains():
        if not item["cert_crt"]:
            print(f"[{item['id']}] {item['domain']:<32} 无证书")
            continue
        seen = True
        days = await _cert_days_left(item["cert_crt"])
        if days is None:
            print(f"[{item['id']}] {item['domain']:<32} 证书不可读")
            continue
        flag = "已过期" if days < 0 else ("临近到期" if days <= 14 else "正常")
        print(f"[{item['id']}] {item['domain']:<32} 剩余 {days:>4} 天  {flag}")
    if not seen:
        print("暂无证书，使用 antipole cert issue <域名> 申请")
    print("服务端每 6 小时自动巡检，临近到期时写入日志并可推送 alerts.webhook")


async def cmd_cert_reload(cfg, args):
    await _reload_service(cfg)
    if not getattr(args, "silent", False):
        print("已通知运行中的服务热载配置")


# ============================================================
# 入口
# ============================================================

_HELP = """\
antipoleBGP 出口调度管理系统 V3.20 管理命令

  状态与查询
    antipole status                    系统状态（网段/隧道/注册/BGP/WARP）
    antipole users                     用户列表
    antipole user get <用户>           用户详情（含隧道与熔断状态）
    antipole link <用户>               VLESS 分享链接
    antipole wg <用户>                 WireGuard 客户端配置
    antipole domains                   接入域名列表
    antipole invites                   邀请码列表
    antipole abuse [-n 30]             滥用事件记录
    antipole log [-n 50]               最近日志
    antipole version                   版本信息

  用户管理
    antipole create <名称> [--rate Mbps] [--quota MB] [--range 网段]
    antipole user add <名称> [--range 网段]
    antipole user del <用户>           删除用户（清理内核/隧道/限速/地址登记）
    antipole user toggle <用户>        启用 / 禁用
    antipole user rotate <用户>        立即轮换出口
    antipole user rate <用户> <Mbps>   限速（0 解除）
    antipole user quota <用户> <MB>    配额（0 不限）
    antipole user limit <用户> <MB> [Mbps]   同时设置配额与限速（常规+隧道）
    antipole user reset <用户>         清零流量计数

  隧道（类 frp 的 TCP 端口映射，端口 1:1 对应）
    antipole tunnel add <名称> [--rate Mbps] [--quota MB] [--range 网段]
    antipole tunnel list               隧道用户列表
    antipole tunnel ports              服务器自身占用的端口（不可用于映射）
    antipole tunnel show <用户>        静态地址 / 映射明细 / 用量与限速
    antipole tunnel token <用户>       查看连接 Token
    antipole tunnel limit <用户> <MB> [Mbps]   隧道侧独立配额与限速
    antipole tunnel toggle <用户>      启用 / 禁用
    antipole tunnel del <用户>         删除隧道用户

  命名网段（多业务 IP 分段）
    antipole range list                网段列表与用量
    antipole range add <名称> <前缀>   新增网段
    antipole range del <名称>          移除网段
    antipole range apply               无损应用网段变更（重建内核与地址守护）
    antipole range move <源> <目标>    批量迁移网段内用户

  自助注册服务
    antipole register show             查看注册服务状态
    antipole register on [--port N]    开启（默认端口 18290）
    antipole register off              关闭

  接入域名与证书
    antipole domain add <域名> [--ip IP] [--port N] [--note 备注]
    antipole domain ip <id> <IP>       换 IP（用户侧零改动）
    antipole domain toggle <id>        启用 / 停用
    antipole domain del <id>           删除
    antipole cert issue <域名> [--webroot 路径] [--auto-add]
    antipole cert renew <域名> [--force]
    antipole cert check                查询全部证书剩余天数
    antipole cert list                 证书列表
    antipole cert reload [--silent]    热载 Xray

  DNS 网关（转发至 dnsctl）
    antipole dns status | doctor       DNS 服务状态 / 全面自检
    antipole dns test <域名> [--udp|--dot 地址]   手动查询
    antipole dns apply / render        配置落盘 / 预览
    antipole dns geosite update        更新国内分流表
    antipole dns blocklist update      更新广告拦截表
    antipole dns addr|domain switch    切换接入地址 / 追加域名
    antipole dns cert renew|password   手动重签证书 / 查看 mTLS 密码
    antipole dns guard                 反滥用加固（防 DNS 反射）

  其他
    antipole invite [--count N]        生成邀请码
    antipole backup                    手动备份数据库

除查询类外，所有修改配置的命令会自动触发热载，不重启、不中断连接。
"""


async def cmd_dns(cfg, args):
    """DNS 网关管理：透传至 dnsctl（antipole dns <status|doctor|test|apply|...>）。"""
    exe = shutil.which("dnsctl") or "/usr/local/bin/dnsctl"
    if not os.path.exists(exe):
        print("dnsctl 未安装：先部署 antipole-dns（bash dns/install-dns.sh）")
        return 1
    r = subprocess.run([exe] + (args.rest or []))
    sys.exit(r.returncode)


async def cmd_help(cfg, args):
    print(_HELP)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="antipole", description="antipoleBGP 管理命令")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("help", help="显示帮助")
    sub.add_parser("version", help="版本信息")
    sub.add_parser("status", help="系统状态")
    sub.add_parser("users", help="用户列表")

    create_p = sub.add_parser("create", help="快速创建用户")
    create_p.add_argument("name")
    create_p.add_argument("--rate", type=int, default=0)
    create_p.add_argument("--quota", type=int, default=0)
    create_p.add_argument("--range", default="")

    user_p = sub.add_parser("user", help="用户管理")
    user_sub = user_p.add_subparsers(dest="action", required=True)
    node = user_sub.add_parser("add")
    node.add_argument("name")
    node.add_argument("--range", default="")
    for name in ("del", "toggle", "rotate", "get", "reset"):
        node = user_sub.add_parser(name)
        node.add_argument("user")
    node = user_sub.add_parser("rate")
    node.add_argument("user")
    node.add_argument("mbps", type=int)
    node = user_sub.add_parser("quota")
    node.add_argument("user")
    node.add_argument("mb", type=int)
    node = user_sub.add_parser("limit")
    node.add_argument("user")
    node.add_argument("traffic", type=int)
    node.add_argument("speed", type=int, nargs="?", default=0)

    tunnel_p = sub.add_parser("tunnel", help="隧道管理")
    tunnel_sub = tunnel_p.add_subparsers(dest="action", required=True)
    node = tunnel_sub.add_parser("add")
    node.add_argument("name")
    node.add_argument("--rate", type=int, default=0)
    node.add_argument("--quota", type=int, default=0)
    node.add_argument("--range", default="")
    tunnel_sub.add_parser("list")
    tunnel_sub.add_parser("ports")
    node = tunnel_sub.add_parser("del")
    node.add_argument("user")
    node = tunnel_sub.add_parser("toggle")
    node.add_argument("user")
    node = tunnel_sub.add_parser("token")
    node.add_argument("user")
    node = tunnel_sub.add_parser("show")
    node.add_argument("user")
    node = tunnel_sub.add_parser("limit")
    node.add_argument("user")
    node.add_argument("traffic", type=int)
    node.add_argument("speed", type=int, nargs="?", default=0)

    range_p = sub.add_parser("range", help="命名网段管理")
    range_sub = range_p.add_subparsers(dest="action", required=True)
    range_sub.add_parser("list")
    node = range_sub.add_parser("add")
    node.add_argument("name")
    node.add_argument("prefix")
    node = range_sub.add_parser("del")
    node.add_argument("name")
    range_sub.add_parser("apply")
    node = range_sub.add_parser("move")
    node.add_argument("src")
    node.add_argument("dst")

    reg_p = sub.add_parser("register", help="自助注册服务")
    reg_sub = reg_p.add_subparsers(dest="action", required=True)
    node = reg_sub.add_parser("on")
    node.add_argument("--port", type=int, default=0)
    reg_sub.add_parser("off")
    reg_sub.add_parser("show")

    node = sub.add_parser("link", help="VLESS 链接")
    node.add_argument("user")
    node = sub.add_parser("wg", help="WG 客户端配置")
    node.add_argument("user")

    sub.add_parser("domains", help="接入域名列表")
    domain_p = sub.add_parser("domain", help="接入域名管理")
    domain_sub = domain_p.add_subparsers(dest="action", required=True)
    node = domain_sub.add_parser("add")
    node.add_argument("domain")
    node.add_argument("--ip", default="")
    node.add_argument("--port", type=int, default=0)
    node.add_argument("--note", default="")
    node = domain_sub.add_parser("ip")
    node.add_argument("id", type=int)
    node.add_argument("ip")
    node = domain_sub.add_parser("del")
    node.add_argument("id", type=int)
    node = domain_sub.add_parser("toggle")
    node.add_argument("id", type=int)

    node = sub.add_parser("invite", help="生成邀请码")
    node.add_argument("--count", type=int, default=1)
    sub.add_parser("invites", help="邀请码列表")
    node = sub.add_parser("abuse", help="滥用事件记录")
    node.add_argument("-n", type=int, default=30)
    sub.add_parser("backup", help="手动备份数据库")
    node = sub.add_parser("log", help="最近日志")
    node.add_argument("-n", type=int, default=50)

    node = sub.add_parser("dns", help="DNS 网关管理（转发至 dnsctl）")
    node.add_argument("rest", nargs=argparse.REMAINDER,
                      help="dnsctl 参数，如 dns status / dns doctor / dns cert renew")

    cert_p = sub.add_parser("cert", help="证书管理")
    cert_sub = cert_p.add_subparsers(dest="action", required=True)
    node = cert_sub.add_parser("issue")
    node.add_argument("domain")
    node.add_argument("--webroot", default="")
    node.add_argument("--auto-add", action="store_true")
    cert_sub.add_parser("list")
    node = cert_sub.add_parser("renew")
    node.add_argument("domain")
    node.add_argument("--force", action="store_true")
    node = cert_sub.add_parser("reload")
    node.add_argument("--silent", action="store_true")
    cert_sub.add_parser("check")
    return parser


ROUTES = {
    "help": cmd_help,
    "version": cmd_version,
    "status": cmd_status,
    "users": cmd_users,
    "create": cmd_create,
    "link": cmd_link,
    "wg": cmd_wg,
    "domains": cmd_domains,
    "invite": cmd_invite,
    "invites": cmd_invites,
    "abuse": cmd_abuse,
    "backup": cmd_backup,
    "log": cmd_log,
    "dns": cmd_dns,
}

_SUBROUTES = {
    "user": {"add": cmd_user_add, "del": cmd_user_del, "toggle": cmd_user_toggle,
             "rotate": cmd_user_rotate, "rate": cmd_user_rate,
             "quota": cmd_user_quota, "limit": cmd_user_limit,
             "get": cmd_user_get, "reset": cmd_user_reset},
    "tunnel": {"add": cmd_tunnel_add, "del": cmd_tunnel_del,
               "toggle": cmd_tunnel_toggle, "list": cmd_tunnel_list,
               "ports": cmd_tunnel_ports,
               "token": cmd_tunnel_token, "limit": cmd_tunnel_limit,
               "show": cmd_tunnel_show},
    "range": {"list": cmd_range_list, "add": cmd_range_add,
              "del": cmd_range_del, "apply": cmd_range_apply,
              "move": cmd_range_move},
    "register": {"on": cmd_register, "off": cmd_register, "show": cmd_register},
    "domain": {"add": cmd_domain_add, "ip": cmd_domain_ip,
               "del": cmd_domain_del, "toggle": cmd_domain_toggle},
    "cert": {"issue": cmd_cert_issue, "list": cmd_cert_list,
             "renew": cmd_cert_renew, "reload": cmd_cert_reload,
             "check": cmd_cert_check},
}


async def _dispatch(cfg, args):
    if args.cmd in _SUBROUTES:
        table = _SUBROUTES[args.cmd]
        handler = table.get(args.action)
        if handler is None:
            sys.exit(f"未知子命令: {args.cmd} {args.action}")
        await handler(cfg, args)
        return
    handler = ROUTES.get(args.cmd)
    if handler is None:
        sys.exit(f"未知命令: {args.cmd}")
    await handler(cfg, args)


async def _run(cfg, args):
    with core.tx().exclusive():
        try:
            await net.refresh_reserved()   # 登记本机地址，避免分配冲突
        except Exception:
            pass
        await _dispatch(cfg, args)


def main():
    args = build_parser().parse_args()
    cfg = core.load_config(_cfg_path())
    cfg["_path"] = _cfg_path()
    _setup(cfg)
    asyncio.run(_run(cfg, args))


if __name__ == "__main__":
    main()