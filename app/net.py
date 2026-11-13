# -*- coding: utf-8 -*-
"""
网络/内核层：WireGuard、WARP 多隧道、路由与策略路由、tc 限速、DNS64/NAT64、
出口轮换，以及已分配地址白名单守护。

设计原则：
  - 所有内核变更幂等（先删后加 / replace），可重复执行；
  - 出口轮换只改内核路由 src，不重载 Xray，连接不中断；
  - 地址守护：仅已分配给用户的 /128 允许进入本机与转发，
    前缀内未分配地址一律丢弃，保证每个地址的独立性。
"""
import asyncio
import ipaddress
import os
import re
import time
from pathlib import Path

from . import core
from .core import (V6Pool, addr_for, cmd, have_bin, internal_ip,
                   internal_v4, list_enabled_users, list_users, pool, tx)

CFG = None

# 命令结果的轻量缓存（广播/公钥/网关等低频变化数据）
_cache = {"gw": {"dev": None, "gw": None, "ts": 0}, "wan": None}


def setup(cfg: dict):
    global CFG
    CFG = cfg


def _child_preexec(parent_pid: int):
    """子进程死亡继承：主进程终止（含 SIGKILL）后，子进程同步接收 SIGTERM，
    避免 xray/tayga/unbound 成为孤儿进程继续占用端口 / tun 设备。"""
    def _fn():
        import ctypes
        import signal
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.prctl(1, signal.SIGTERM)      # PR_SET_PDEATHSIG = 1
        except Exception:
            pass
        try:
            if os.getppid() != parent_pid:     # 父进程已在 fork 间隙退出
                os._exit(1)
        except Exception:
            pass
    return _fn


# ---------- 网关探测（缓存 60s） ----------

async def default_gw() -> tuple:
    c = _cache["gw"]
    if c["gw"] and time.time() - c["ts"] < 60:
        return c["dev"], c["gw"]
    out = await cmd("ip", "-6", "route", "show", "default", check=False)
    dev = gw = None
    for i, token in enumerate(out.split()):
        if token == "dev" and i + 1 < len(out.split()):
            dev = out.split()[i + 1]
        if token == "via" and i + 1 < len(out.split()):
            gw = out.split()[i + 1]
    if not dev:
        raise RuntimeError("未找到默认 IPv6 网关，请检查 ip -6 route")
    c.update({"dev": dev, "gw": gw, "ts": time.time()})
    return dev, gw


async def wan_dev() -> str:
    """出口网卡（tc 限速使用）。配置可指定，缺省取默认网关所在网卡。"""
    if _cache["wan"]:
        return _cache["wan"]
    if CFG["network"].get("tc_wan"):
        _cache["wan"] = CFG["network"]["tc_wan"]
        return _cache["wan"]
    dev, _ = await default_gw()
    _cache["wan"] = dev
    return dev


async def wan_v6() -> str:
    """出口网卡的全局 IPv6 地址（首个）。用于把入站监听收敛到主地址，
    把其余地址的端口（尤其是 80）留给证书校验与用户映射。"""
    dev = await wan_dev()
    out = await cmd("ip", "-6", "-o", "addr", "show", "dev", dev, check=False)
    for line in out.splitlines():
        match = re.search(r"inet6\s+([0-9a-fA-F:]+)/\d+\s+scope\s+global", line)
        if match and not match.group(1).startswith("fe80"):
            return match.group(1)
    return ""


# ---------- WireGuard ----------

def _keys_dir() -> Path:
    return Path(CFG["db"]["keys_dir"])


def _kpath(name: str) -> str:
    return str(_keys_dir() / name)


def _n() -> dict:
    return CFG["network"]


def user_mark(user_id: int) -> int:
    """VLESS 用户出站的 fwmark。轮换只改内核路由 src，xray 配置不用重载。"""
    return _n().get("user_mark_base", 0x40000000) + user_id


async def wg_server_pub() -> str:
    _keys_dir().mkdir(parents=True, exist_ok=True)
    priv = _kpath("server.priv")
    pub = _kpath("server.pub")
    if not (Path(priv).exists() and Path(priv).read_text().strip()):
        key = await cmd("wg", "genkey")
        Path(priv).write_text(key)
        Path(pub).write_text(await cmd("wg", "pubkey", stdin=key))
        Path(priv).chmod(0o600)
    return Path(pub).read_text().strip()


async def wg_ensure() -> str:
    """wg0 不存在则建，返回服务端公钥。幂等。"""
    nc = _n()
    out = await cmd("ip", "link", "show", nc["wg_iface"], check=False)
    if not out or "does not exist" in out:
        await cmd("ip", "link", "add", nc["wg_iface"], "type", "wireguard")
        pub = await wg_server_pub()
        await cmd("wg", "set", nc["wg_iface"], "listen-port", str(nc["wg_port"]),
                  "private-key", _kpath("server.priv"))
        await cmd("ip", "-6", "addr", "add", nc["wg_addr"], "dev",
                  nc["wg_iface"], "nodad", check=False)
        await cmd("ip", "-4", "addr", "add", nc.get("wg_v4_addr", "10.7.0.1/24"),
                  "dev", nc["wg_iface"], check=False)
        await cmd("ip", "-6", "route", "replace", nc["internal_net"],
                  "dev", nc["wg_iface"])
        await cmd("ip", "link", "set", nc["wg_iface"], "up")
    for sysp in ("/proc/sys/net/ipv6/conf/all/forwarding",
                 f"/proc/sys/net/ipv6/conf/{nc['wg_iface']}/forwarding"):
        try:
            Path(sysp).write_text("1")
        except OSError:
            pass
    return await wg_server_pub()


def _table(user_id: int) -> int:
    return _n()["route_table_base"] + user_id


async def wg_add_peer(user_id: int, pubkey: str):
    """添加 peer、隧道路由与独立路由表，并在 lo 挂载出口地址。幂等。"""
    nc = _n()
    await cmd("ip", "link", "set", nc["wg_iface"], "up", check=False)   # 常驻确保接口 up
    ip6 = internal_ip(user_id)
    user = core.get_user(user_id)
    if not user:
        raise RuntimeError(f"用户 {user_id} 不存在")
    await cmd("wg", "set", nc["wg_iface"], "peer", pubkey,
              "allowed-ips", f"{ip6}/128", "persistent-keepalive", "25")
    await cmd("ip", "-6", "route", "replace", f"{ip6}/128", "dev", nc["wg_iface"])
    v4 = internal_v4(user_id)
    if v4:
        await cmd("ip", "-4", "route", "replace", f"{v4}/32", "dev",
                  nc["wg_iface"], check=False)
    await _bind_egress(user_id, user["egress_ip"])
    await addr_guard_add(user["egress_ip"])
    # 多 WARP 隧道负载均衡：用户 v4 流量按 id 精确分流到所属隧道
    await _warp_user_rule(user_id)


async def wg_del_peer(user_id: int, pubkey: str):
    nc = _n()
    await cmd("wg", "set", nc["wg_iface"], "peer", pubkey, "remove", check=False)
    await cmd("ip", "-6", "route", "del", f"{internal_ip(user_id)}/128",
              "dev", nc["wg_iface"], check=False)
    v4 = internal_v4(user_id)
    if v4:
        await cmd("ip", "-4", "route", "del", f"{v4}/32", "dev",
                  nc["wg_iface"], check=False)
    await _unbind_egress(user_id)
    # 多 WARP 隧道负载均衡：移除该用户的 v4 分流规则
    await _warp_del_user_rule(user_id)


async def _bind_egress(user_id: int, egress: str):
    nc = _n()
    ip6 = internal_ip(user_id)
    tbl = _table(user_id)
    # 幂等：删同 pref 旧规则再添
    await cmd("ip", "-6", "rule", "del", "from", f"{ip6}/128",
              "lookup", str(tbl), check=False)
    await cmd("ip", "-6", "rule", "add", "from", f"{ip6}/128",
              "lookup", str(tbl), "pref", str(tbl))
    # VLESS 出站走同一张表：按 fwmark 进（轮换只动内核 src，xray 配置不用重载）
    mark = user_mark(user_id)
    await cmd("ip", "-6", "rule", "del", "fwmark", hex(mark),
              "lookup", str(tbl), check=False)
    await cmd("ip", "-6", "rule", "add", "fwmark", hex(mark),
              "lookup", str(tbl), "pref", str(tbl))
    # 先将 /128 挂载至 lo（路由 src 必须是本地已存在的地址），再建立 default
    await cmd("ip", "-6", "addr", "add", f"{egress}/128", "dev", "lo",
              "nodad", check=False)
    dev, gw = await default_gw()
    await cmd("ip", "-6", "route", "replace", "default", "via", gw, "dev", dev,
              "src", egress, "table", str(tbl))
    # DNS64/NAT64 合成前缀指到 nat64（用户表内，优先于 default）
    for args in dns64_routes_for(tbl):
        await cmd(*args, check=False)


async def wg_rotate_egress(user_id: int, egress: str, old_egress: str):
    """轮换出口：先挂载新出口并更新路由 src，再移除旧地址，避免切换空窗。"""
    nc = _n()
    tbl = _table(user_id)
    await cmd("ip", "-6", "addr", "add", f"{egress}/128", "dev", "lo",
              "nodad", check=False)
    dev, gw = await default_gw()
    await cmd("ip", "-6", "route", "replace", "default", "via", gw, "dev", dev,
              "src", egress, "table", str(tbl))
    for args in dns64_routes_for(tbl):
        await cmd(*args, check=False)
    # 地址守护：先登记新出口再注销旧出口，切换过程无拒绝窗口
    await addr_guard_add(egress)
    if old_egress and old_egress != egress:
        await cmd("ip", "-6", "addr", "del", f"{old_egress}/128", "dev", "lo",
                  check=False)
        await addr_guard_del(old_egress)


async def _unbind_egress(user_id: int):
    nc = _n()
    tbl = _table(user_id)
    await cmd("ip", "-6", "rule", "del", "from", f"{internal_ip(user_id)}/128",
              "lookup", str(tbl), check=False)
    mark = user_mark(user_id)
    await cmd("ip", "-6", "rule", "del", "fwmark", hex(mark),
              "lookup", str(tbl), check=False)
    await cmd("ip", "-6", "route", "flush", "table", str(tbl), check=False)
    user = core.get_user(user_id)
    if user and user["egress_ip"]:
        await cmd("ip", "-6", "addr", "del", f"{user['egress_ip']}/128",
                  "dev", "lo", check=False)
        await addr_guard_del(user["egress_ip"])


async def wg_dump() -> dict:
    """wg show dump -> {pubkey: {internal, handshake, endpoint}}"""
    out = await cmd("wg", "show", _n()["wg_iface"], "dump", check=False)
    peers = {}
    for idx, line in enumerate(out.splitlines()):
        if idx == 0 or not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 5:
            continue
        try:
            internal = ipaddress.ip_interface(fields[2].split(",")[0]).ip.compressed
        except ValueError:
            internal = None
        peers[fields[0]] = {"internal": internal, "handshake": int(fields[4] or 0),
                       "endpoint": fields[3] or None}
    return peers


# ---------- 已分配地址守护 ----------
# 广播前缀内的地址若无业务占用，不应被路由到本机（否则任意 /128 均可达本机，
# 破坏地址独立性并放大攻击面）。实现方式：nftables interval 集合保存已分配 /128，
# 在 prerouting 早期放行集合内地址、丢弃前缀内其余地址。集合查找为 O(1)，
# 用户增删时增量更新元素，不做全量重写。

_ADDR_TABLE = "antipole-addr"
_ADDR_SET = "allocated"
_ADDR_CHUNK = 500        # 单次 nft 调用批量写入的元素数（避免命令过长）


def _guard_on() -> bool:
    return bool(CFG["network"].get("guard_allocated", True)) and have_bin("nft")


async def ensure_local_v6(addr: str):
    """确保一个 /128 绑在本机 lo 上（幂等）：BGP /48 内的固定服务接入地址
    （如 VLESS 统一入口）不随实例重建变化，必须在服务启动时先于监听存在。
    存在性判断用 `show dev lo` 输出过滤——`addr show <地址>` 会被当作设备名，
    永远返回空，导致重复 add 撞 RTNETLINK File exists。
    """
    addr = (addr or "").strip()
    if not addr:
        return
    out = await cmd("ip", "-6", "addr", "show", "dev", "lo", check=False)
    if addr in out:
        return
    await cmd("ip", "-6", "addr", "add", f"{addr}/128", "dev", "lo")
    print(f"[net] 本机服务地址已就绪 {addr}")


def _guard_prefixes() -> list:
    prefixes = [p for p in (CFG["network"].get("ranges") or {}).values() if p]
    return prefixes or [CFG["network"]["prefix"]]


async def local_v6_addresses() -> set:
    """本机全部非链路本地 IPv6 地址。

    这些地址承载本机自身服务（如既有 DNS 业务），必须始终放行且不得分配给用户，
    否则地址守护会误伤本机业务，或用户地址与本机业务地址冲突。
    """
    out = await cmd("ip", "-6", "-o", "addr", "show", check=False)
    addrs = set()
    for line in out.splitlines():
        match = re.search(r"inet6\s+([0-9a-fA-F:]+)/", line)
        if match and not match.group(1).startswith("fe80"):
            addrs.add(match.group(1))
    return addrs


async def refresh_reserved():
    """刷新保留地址集合：本机地址 + 配置的额外放行项。"""
    addrs = await local_v6_addresses()
    addrs |= set(CFG["network"].get("guard_extra_allow") or [])
    core.set_reserved(addrs)
    return addrs


async def addr_guard_init():
    """重建地址守护表与规则（幂等）。返回是否启用。"""
    if not _guard_on():
        return False
    prefixes = _guard_prefixes()
    await cmd("nft", "delete", "table", "inet", _ADDR_TABLE, check=False)
    await cmd("nft", "add", "table", "inet", _ADDR_TABLE)
    await cmd("nft", "add", "set", "inet", _ADDR_TABLE, _ADDR_SET,
              "{ type ipv6_addr ; flags interval ; }")
    await cmd("nft", "add", "chain", "inet", _ADDR_TABLE, "guard",
              "{ type filter hook prerouting priority -150 ; policy accept ; }")
    # 顺序敏感：先放行集合内地址，再丢弃前缀内其余地址
    await cmd("nft", "add", "rule", "inet", _ADDR_TABLE, "guard",
              f"ip6 daddr @{_ADDR_SET}", "accept")
    for prefix in prefixes:
        await cmd("nft", "add", "rule", "inet", _ADDR_TABLE, "guard",
                  f"ip6 daddr {prefix}", "drop")
    await addr_guard_sync()
    print(f"[net] 地址守护已启用：仅已分配地址与本机地址可路由至本机"
          f"（前缀 {', '.join(prefixes)}）")
    return True


async def addr_guard_sync():
    """按数据库地址 + 本机地址 + 额外放行项全量重写集合（批量写入）。"""
    if not _guard_on():
        return
    addrs = {u["egress_ip"] for u in list_users() if u.get("egress_ip")}
    addrs |= await refresh_reserved()
    ordered = sorted(addrs)
    await cmd("nft", "flush", "set", "inet", _ADDR_TABLE, _ADDR_SET, check=False)
    for i in range(0, len(ordered), _ADDR_CHUNK):
        chunk = ", ".join(ordered[i:i + _ADDR_CHUNK])
        await cmd("nft", "add", "element", "inet", _ADDR_TABLE, _ADDR_SET,
                  f"{{ {chunk} }}", check=False)


async def addr_guard_add(addr: str):
    """登记一个已分配地址。"""
    if not _guard_on() or not addr:
        return
    await cmd("nft", "add", "element", "inet", _ADDR_TABLE, _ADDR_SET,
              f"{{ {addr} }}", check=False)


async def addr_guard_del(addr: str):
    """注销一个地址（用户删除/轮换旧出口）。"""
    if not _guard_on() or not addr:
        return
    await cmd("nft", "delete", "element", "inet", _ADDR_TABLE, _ADDR_SET,
              f"{{ {addr} }}", check=False)


# ---------- 隧道控制面 ----------

def tunnel_control_addr() -> str:
    """隧道控制面接入地址：隧道专属网段的第一个可用地址。

    控制面固定占用该地址，客户端统一以它作为接入点；与用户出口地址同属隧道
    网段，但独立保留，不会被分配给任何用户。
    """
    tunnel_range = (_n().get("tunnel_range") or "").strip()
    if not tunnel_range:
        return ""
    net6 = ipaddress.IPv6Network(tunnel_range, strict=False)
    if net6.num_addresses <= 1:
        return ""
    return str(net6.network_address + 1)


async def ensure_tunnel_addr() -> str:
    """把隧道控制地址挂载到 lo 并登记放行（幂等；隧道未启用时跳过）。"""
    if not CFG["tunnel"].get("enabled"):
        return ""
    addr = tunnel_control_addr()
    if not addr:
        return ""
    await cmd("ip", "-6", "addr", "add", f"{addr}/128", "dev", "lo", "nodad",
              check=False)
    await addr_guard_add(addr)
    return addr


# ---------- 端口放行 ----------
# 隧道控制端口、用户映射端口、自助注册端口都是运行时才确定的，无法预置到静态防火墙
# 脚本里，必须由程序按需放行，否则流量会被系统防火墙（ufw/iptables）丢弃。

_FW_TABLE = "antipole-fw"
_FW_SET = "dynamic_ports"
_fw_backend = None            # None 未探测 / True 用 ufw / False 用 nft 集合


async def _fw_use_ufw() -> bool:
    """探测一次主防火墙形态：ufw 生效时写 ufw 规则，否则退回 nft 集合。"""
    global _fw_backend
    if _fw_backend is None:
        if not have_bin("ufw"):
            _fw_backend = False
        else:
            out = await cmd("ufw", "status", check=False)
            _fw_backend = "Status: active" in out
    return _fw_backend


async def _fw_nft_ready():
    """准备 nft 兜底表、input 链与动态端口集合（幂等）。"""
    if not have_bin("nft"):
        return False
    await cmd("nft", "add", "table", "inet", _FW_TABLE, check=False)
    await cmd("nft", "add", "chain", "inet", _FW_TABLE, "input",
              "{ type filter hook input priority -10 ; policy accept ; }",
              check=False)
    await cmd("nft", "add", "set", "inet", _FW_TABLE, _FW_SET,
              "{ type inet_service ; }", check=False)
    rules = await cmd("nft", "list", "chain", "inet", _FW_TABLE, "input",
                      check=False)
    if f"@{_FW_SET}" not in rules:
        await cmd("nft", "add", "rule", "inet", _FW_TABLE, "input",
                  f"tcp dport @{_FW_SET} accept", check=False)
    return True


async def fw_open(port: int):
    """放行一个入站 TCP 端口（重复调用幂等）。

    防火墙异常不应影响映射建立，因此内部吞掉错误并打印提示。
    """
    try:
        port = int(port)
        if not 0 < port < 65536:
            return
        if await _fw_use_ufw():
            await cmd("ufw", "allow", f"{port}/tcp", check=False)
            return
        if not await _fw_nft_ready():
            return
        await cmd("nft", "add", "element", "inet", _FW_TABLE, _FW_SET,
                  f"{{ {port} }}", check=False)
    except Exception as e:
        print(f"[net] 端口 {port} 放行失败: {e}")


async def fw_close(port: int):
    """撤销端口放行（该端口已无任何监听时调用）。"""
    try:
        port = int(port)
        if not 0 < port < 65536:
            return
        if await _fw_use_ufw():
            await cmd("ufw", "delete", "allow", f"{port}/tcp", check=False)
            return
        if not await _fw_nft_ready():
            return
        await cmd("nft", "delete", "element", "inet", _FW_TABLE, _FW_SET,
                  f"{{ {port} }}", check=False)
    except Exception as e:
        print(f"[net] 端口 {port} 撤销放行失败: {e}")


# ---------- WARP ----------

async def warp_profile() -> Path:
    """wgcf 未注册时执行注册并生成 profile。"""
    warp = CFG["warp"]
    profile = Path(warp["profile"])
    if profile.exists():
        return profile
    profile.parent.mkdir(parents=True, exist_ok=True)
    workdir = profile.parent
    await cmd(warp["wgcf"], "register", "--accept-tos", "--config",
              str(workdir / "wgcf-account.toml"), cwd=str(workdir), timeout=60)
    await cmd(warp["wgcf"], "generate", "--config",
              str(workdir / "wgcf-account.toml"), "--profile", str(profile),
              cwd=str(workdir), timeout=30)
    # profile 里有 WARP 私钥，权限收紧
    try:
        profile.chmod(0o600)
        (workdir / "wgcf-account.toml").chmod(0o600)
    except OSError:
        pass
    return profile


async def _endpoint_v6(endpoint: str) -> str:
    """endpoint 为域名时优先解析 v6（v6-only 机器上 wg 可能优先选中不可达的 v4 地址）。"""
    host, _, port = endpoint.rpartition(":")
    if not host or host.startswith("["):
        return endpoint
    try:
        ipaddress.ip_address(host)
        return endpoint
    except ValueError:
        pass
    out = await cmd("getent", "ahostsv6", host, check=False, timeout=10)
    for line in out.splitlines():
        fields = line.split()
        if fields and ":" in fields[0]:
            return f"[{fields[0]}]:{port}"
    return endpoint


# WARP 隧道状态（多账号负载均衡）：每隧道独立维护
#   _warp_state[iface] = {"eps": [...], "ep_i": 0, "peer_pub": "..."}
_warp_state = {}


def _warp_iface(index: int) -> str:
    """第 index 条（1 起）WARP 隧道接口名。第一条保持配置原名，后续加 -N 后缀。"""
    warp = CFG["warp"]
    return warp["iface"] if index == 1 else f"{warp['iface']}-{index}"


def _warp_mark(index: int) -> int:
    return _n()["warp_mark"] + (index - 1)


def _warp_table(index: int) -> int:
    return _n()["warp_table"] + (index - 1)


def _warp_tunnel_count() -> int:
    """隧道总数：主 profile + profiles 列表追加的账号。"""
    warp = CFG["warp"]
    return 1 + len([p for p in (warp.get("profiles") or []) if p])


def _warp_tunnel_index(user_id: int) -> int:
    """用户分到第几条隧道（1 起，按 id 均分，出口 IP 固定不漂移）。"""
    return (user_id - 1) % _warp_tunnel_count() + 1


async def _parse_warp_profile(path) -> dict:
    profile = Path(path)
    text = profile.read_text()
    priv = addrs = peer_pub = endpoint = mtu = None
    sec = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            sec = line.strip("[]").lower()
            continue
        if "=" in line and sec == "interface":
            k, v = line.split("=", 1)
            if k.strip() == "PrivateKey":
                priv = v.strip()
            elif k.strip() == "Address":
                addrs = (addrs or []) + [item.strip() for item in v.split(",")]
            elif k.strip() == "MTU":
                mtu = v.strip()
        elif "=" in line and sec == "peer":
            k, v = line.split("=", 1)
            if k.strip() == "PublicKey":
                peer_pub = v.strip()
            elif k.strip() == "Endpoint":
                endpoint = v.strip()
    if not (priv and peer_pub and endpoint):
        raise RuntimeError("WARP profile 字段不全")
    return {"priv": priv, "peer_pub": peer_pub, "endpoint": endpoint,
            "v4": next((a for a in (addrs or []) if ":" not in a), None),
            "v6": next((a for a in (addrs or []) if ":" in a), None),
            "mtu": mtu}


async def _warp_profiles() -> list:
    """解析全部 WARP 账号 profile（主 + 追加）。缺失的跳过。"""
    warp = CFG["warp"]
    paths = [warp["profile"]]
    paths += [p for p in (warp.get("profiles") or []) if p]
    out = []
    for idx, path in enumerate(paths, 1):
        p = Path(path)
        if not p.is_file():
            print(f"[net] WARP profile 缺失，跳过第 {idx} 条隧道: {path}")
            continue
        try:
            out.append(await _parse_warp_profile(path))
        except Exception as e:
            print(f"[net] WARP profile 解析失败，跳过第 {idx} 条隧道 {path}: {e}")
    return out


async def _warp_endpoints(profile: dict) -> list:
    """endpoint 列表：profile 自带的一个 + 配置里 warp.endpoints 追加的。
    域名统一 v6 优先解析，去重。"""
    eps = [profile["endpoint"]]
    for e in (CFG["warp"].get("endpoints") or []):
        e = (e or "").strip()
        if e and e not in eps:
            eps.append(e)
    return [await _endpoint_v6(e) for e in eps]


async def _warp_handshaked(iface: str = None) -> bool:
    iface = iface or CFG["warp"]["iface"]
    hs = await cmd("wg", "show", iface, "latest-handshakes", check=False)
    return any(len(fields) >= 2 and (fields[1].strip() or "0") != "0"
               for fields in (ln.split("\t") for ln in hs.splitlines()))


async def _warp_tunnel_up(profile: dict, iface: str, mark: int, table: int) -> bool:
    """建立单条 WARP 隧道（wg 接口 + mark 路由 + 多 endpoint 握手）。重启安全。"""
    await cmd("ip", "link", "del", iface, check=False)
    await cmd("ip", "link", "add", iface, "type", "wireguard")
    kf = _keys_dir() / f"{iface}.priv"
    _keys_dir().mkdir(parents=True, exist_ok=True)
    kf.write_text(profile["priv"])
    kf.chmod(0o600)
    await cmd("wg", "set", iface, "private-key", str(kf))
    if profile["v4"]:
        await cmd("ip", "-4", "addr", "add", profile["v4"], "dev", iface, check=False)
    if profile["v6"]:
        await cmd("ip", "-6", "addr", "add", profile["v6"], "dev", iface, check=False)
    await cmd("ip", "link", "set", iface, "up", "mtu", profile["mtu"] or "1280")
    # mark 专用表路由；main 表保持不动（wg-quick 会改写 main 表，不采用）
    await cmd("ip", "-4", "route", "replace", "default", "dev", iface,
              "table", str(table))
    await cmd("ip", "-4", "rule", "del", "fwmark", hex(mark), check=False)
    await cmd("ip", "-4", "rule", "add", "fwmark", hex(mark),
              "lookup", str(table), "pref", "100")
    # 多 endpoint 逐个尝试握手（每次等待 2.5s 验证真实握手），避免单点依赖
    st = _warp_state.setdefault(iface, {"eps": [], "ep_i": 0, "peer_pub": profile["peer_pub"]})
    st["peer_pub"] = profile["peer_pub"]
    eps = st["eps"] or await _warp_endpoints(profile)
    st["eps"] = eps
    hsed = False
    for k in range(len(eps)):
        ep = eps[(st["ep_i"] + k) % len(eps)]
        await cmd("wg", "set", iface, "peer", profile["peer_pub"], "endpoint", ep,
                  "allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25")
        await asyncio.sleep(2.5)
        if await _warp_handshaked(iface):
            hsed = True
            st["ep_i"] = (st["ep_i"] + k + 1) % len(eps)
            break
    print(f"[net] WARP 握手 {iface}: {'已握手' if hsed else '还没握手'} "
          f"(v4={profile['v4'] or '无'})")
    return hsed


async def warp_up() -> bool:
    """建全部 WARP 隧道（多账号负载均衡）。重启安全（先拆后建）。

    隧道总数 = 1 + len(warp.profiles)。用户 v4 流量按 id 均分到各隧道
    （_warp_tunnel_index），每条隧道独立 mark/路由表，互不影响。
    单隧道时行为与旧版完全一致。
    """
    warp = CFG["warp"]
    if not warp["enabled"]:
        return False
    if not have_bin(warp["wgcf"]):
        print("[net] 没找到 wgcf，WARP 跳过")
        return False
    global _warp_state
    _warp_state = {}
    profiles = await _warp_profiles()
    if not profiles:
        print("[net] 无可用 WARP profile，跳过")
        return False
    up = 0
    first_v4 = ""
    for idx, profile in enumerate(profiles, 1):
        iface = _warp_iface(idx)
        mark = _warp_mark(idx)
        table = _warp_table(idx)
        if await _warp_tunnel_up(profile, iface, mark, table):
            up += 1
            if not first_v4:
                first_v4 = profile["v4"] or ""
        else:
            print(f"[net] WARP 第 {idx} 条隧道 {iface} 握手失败，"
                  f"将由健康轮询继续重试")
    print(f"[net] WARP 隧道就绪: {up}/{len(profiles)}")

    # NAT64（10.44.0.0/16）走第一条 WARP 隧道
    d64net = CFG["dns64"].get("v4_net", "10.44.0.0/16") if CFG["dns64"].get("enabled") else ""
    if d64net:
        if first_v4:
            await cmd("ip", "-4", "rule", "del", "from", d64net, "lookup",
                      str(_warp_table(1)), check=False)
            await cmd("ip", "-4", "rule", "add", "from", d64net, "lookup",
                      str(_warp_table(1)), "pref", "200")
        else:
            await cmd("ip", "-4", "rule", "del", "from", d64net, "lookup",
                      str(_warp_table(1)), check=False)

    # WG 转发进来的 v4 打 mark：
    #   单隧道 -> 统一打主 mark（原行为）
    #   多隧道 -> 由 wg_add_peer 按用户 id 精确分流（见 _warp_user_rule）
    if have_bin("nft"):
        await cmd("nft", "delete", "table", "ip", "antipole", check=False)
        await cmd("nft", "add", "table", "ip", "antipole")
        await cmd("nft", "add", "chain", "ip", "antipole", "mangle-fwd",
                  "{ type filter hook forward priority mangle ; }")
        if len(profiles) == 1:
            await cmd("nft", "add", "rule", "ip", "antipole", "mangle-fwd",
                      f'iifname "{_n()["wg_iface"]}" meta mark set {_warp_mark(1)}')
        else:
            for user in list_enabled_users():
                await _warp_user_rule(user["id"])
    # NAT64 源地址借道 WARP 的 SNAT（有 v4 才算数）
    if first_v4:
        await _n64_snat()
    return up > 0


async def _warp_del_user_rule_handles(v4: str):
    """按 handle 删除该用户 saddr 相关的所有分流规则（nft delete rule 必须用 handle）。"""
    if not v4:
        return
    out = await cmd("nft", "-a", "list", "chain", "ip", "antipole", "mangle-fwd",
                    check=False)
    for line in out.splitlines():
        if v4 in line:
            m = re.search(r"handle (\d+)", line)
            if m:
                await cmd("nft", "delete", "rule", "ip", "antipole", "mangle-fwd",
                          "handle", m.group(1), check=False)


async def _warp_user_rule(user_id: int):
    """多隧道时：把用户 v4 流量精确打标到其所属隧道（出口地址挂载由 _bind_egress 负责）。"""
    if _warp_tunnel_count() <= 1:
        return
    v4 = internal_v4(user_id)
    if not v4:
        return
    mark = _warp_mark(_warp_tunnel_index(user_id))
    await _warp_del_user_rule_handles(v4)
    await cmd("nft", "add", "rule", "ip", "antipole", "mangle-fwd",
              "iifname", _n()["wg_iface"], "ip", "saddr", v4,
              "counter", "meta", "mark", "set", hex(mark))


async def _warp_del_user_rule(user_id: int):
    """多隧道时：删除该用户的 v4 打标规则。"""
    if _warp_tunnel_count() <= 1:
        return
    await _warp_del_user_rule_handles(internal_v4(user_id))


async def warp_health_loop(cfg: dict):
    """WARP 健康轮询：遍历全部隧道，握手丢了的单独换 endpoint 重试。"""
    while True:
        await asyncio.sleep(45)
        try:
            warp = cfg["warp"]
            if not warp.get("enabled"):
                continue
            n = _warp_tunnel_count()
            for idx in range(1, n + 1):
                iface = _warp_iface(idx)
                st = _warp_state.get(iface)
                if not st or not st["eps"]:
                    continue
                if not await _warp_handshaked(iface):
                    ep = st["eps"][st["ep_i"] % len(st["eps"])]
                    st["ep_i"] = (st["ep_i"] + 1) % len(st["eps"])
                    print(f"[net] WARP 握手丢失 {iface}，切换 endpoint -> {ep}")
                    await cmd("wg", "set", iface, "peer", st["peer_pub"],
                              "endpoint", ep, "allowed-ips", "0.0.0.0/0",
                              "persistent-keepalive", "25")
        except Exception as e:
            print(f"[net] WARP 健康检查出错: {e}")


async def warp_is_up() -> bool:
    out = await cmd("ip", "link", "show", CFG["warp"]["iface"], check=False)
    return bool(out) and "does not exist" not in out


async def warp_v4() -> str:
    if not await warp_is_up():
        return ""
    out = await cmd("ip", "-4", "-o", "addr", "show", "dev",
                    CFG["warp"]["iface"], check=False)
    for line in out.splitlines():
        m = re.search(r"inet\s+(\S+)", line)
        if m:
            return m.group(1).split("/")[0]
    return ""


# ---------- BGP 状态（仅监控联动，不做变更） ----------

async def bgp_status() -> dict:
    """探测 BGP 守护进程：bird/bird6/frr。尽力而为，缺工具也能跑。"""
    info = {"daemons": [], "alive": False, "detail": ""}
    for proc_name in ("bird", "bird6", "bgpd", "zebra"):
        if await cmd("pgrep", "-x", proc_name, check=False):
            info["daemons"].append(proc_name)
    info["alive"] = bool(info["daemons"])
    try:
        if have_bin("birdc"):
            out = await cmd("birdc", "-s", "/run/bird/bird.ctl", "show",
                            "protocols", check=False, timeout=5)
            info["detail"] = out[:400]
        elif have_bin("vtysh"):
            out = await cmd("vtysh", "-c", "show bgp ipv6 summary",
                            check=False, timeout=5)
            info["detail"] = out[:400]
    except Exception:
        info["detail"] = ""
    return info


# ---------- tc 限速 ----------

def _rate_class(user_id: int) -> int:
    return 100 + user_id


async def _tc_exe() -> bool:
    return have_bin("tc")


async def tc_ensure_root(dev: str):
    """出口网卡挂 htb 根。默认叶 1:10（不限速用户走这）。已挂就跳过。"""
    out = await cmd("tc", "qdisc", "show", "dev", dev, check=False)
    if "htb" in out:
        return
    await cmd("tc", "qdisc", "add", "dev", dev, "root", "handle", "1:", "htb",
              "default", "10")
    await cmd("tc", "class", "add", "dev", dev, "parent", "1:", "classid",
              "1:1", "htb", "rate", "1000mbit")
    await cmd("tc", "class", "add", "dev", dev, "parent", "1:1", "classid",
              "1:10", "htb", "rate", "1000mbit")


async def tc_set_rate(user_id: int, mbps: int):
    """给用户出口 v6 限速（mbps=0 解除）。包按源 /128 识别。

    每个用户使用独立的 filter prio（= 100+id），增删仅作用于自身的规则，
    避免全量删除 prio 1 filter 而影响其他用户的限速配置。
    """
    if not await _tc_exe():
        print("[net] 未找到 tc，限速功能不可用（安装 iproute2 即可）")
        return "tc 不可用"
    if not CFG["network"].get("tc_enabled", True):
        return "限速已关闭"
    user = core.get_user(user_id)
    if not user:
        return "用户不存在"
    try:
        with tx().shared():   # 与 CLI 的 tc 操作互斥（根 qdisc 检查+创建不是原子的）
            dev = await wan_dev()
            await tc_ensure_root(dev)
            cid = f"1:{_rate_class(user_id)}"
            prio = str(_rate_class(user_id))
            # 先删这个用户的旧 filter（按独立 prio），再删 class；只动自己的
            await cmd("tc", "filter", "del", "dev", dev, "parent", "1:",
                      "protocol", "ipv6", "prio", prio, check=False)
            await cmd("tc", "class", "del", "dev", dev, "parent", "1:1",
                      "classid", cid, check=False)
            if mbps > 0:
                await cmd("tc", "class", "add", "dev", dev, "parent", "1:1",
                          "classid", cid, "htb", "rate", f"{mbps}mbit",
                          "ceil", "1000mbit")
                await cmd("tc", "filter", "add", "dev", dev, "parent", "1:",
                          "protocol", "ipv6", "prio", prio, "u32", "match",
                          "ip6", "src", f"{user['egress_ip']}/128", "flowid", cid)
            return f"限速 {mbps}Mbps" if mbps > 0 else "限速已解除"
    except Exception as e:
        print(f"[net] 限速失败: {e}")
        return f"限速失败: {e}"


# ---------- DNS64 / NAT64（纯 v6 用户访问纯 v4 网站） ----------
# 数据面用 tayga（NAT64，tun 设备），DNS 面用 unbound（DNS64，只在 wg 隧道内答）。
# 两条进程都由本进程拉起、崩溃自启；SNAT 让 NAT64 源地址能出公网。

_dns64_proc = {}
_dns64_argv = {}
_dns64_stop = False
_D64_IFACE = None


def _d64() -> dict:
    return CFG["dns64"]


def _d64_enabled() -> bool:
    return CFG["dns64"].get("enabled", True)


def _d64_iface() -> str:
    global _D64_IFACE
    if _D64_IFACE is None:
        _D64_IFACE = CFG["dns64"]["iface"]
    return _D64_IFACE


def dns64_routes_for(user_table: int) -> list:
    """给某个用户路由表补的 64:ff9b 路由命令，由 bind/轮换侧执行。"""
    if not _d64_enabled():
        return []
    return [("ip", "-6", "route", "replace", CFG["dns64"]["prefix"],
             "dev", _d64_iface(), "table", str(user_table))]


def build_dns64_confs(d64: dict) -> dict:
    """生成 tayga / unbound 配置文本（纯函数，可测）。"""
    # 64:ff9b WKP 时 tayga 强制要 ipv6-addr，且不能在 64:ff9b 内；用一个独立专用地址
    self6 = "2001:db8:64::1"
    # 上游 DNS：v6-only 机器无法访问 v4 的 1.1.1.1，默认全部采用 v6 可达的解析器
    fwd = d64.get("forward") or ["2606:4700:4700::1111", "2001:4860:4860::8888"]
    if isinstance(fwd, str):
        fwd = [fwd]
    fwd_lines = "".join(f"  forward-addr: {resolver}\n" for resolver in fwd)
    return {
        "tayga": (
            f"tun-device {d64['iface']}\n"
            "ipv4-addr 10.44.0.1\n"
            f"ipv6-addr {self6}\n"
            f"prefix {d64['prefix']}\n"
            f"dynamic-pool {d64['v4_net']}\n"
        ),
        "unbound": (
            "server:\n"
            "  verbosity: 0\n"
            f"  interface: {d64['dns_v6']}\n"
            "  port: 53\n"
            f"  access-control: {d64['dns_v6']}/128 allow\n"
            f"  module-config: \"dns64 iterator\"\n"
            f"  dns64-prefix: {d64['prefix']}\n"
            "  do-daemonize: no\n"
            "  log-queries: no\n"
            "forward-zone:\n"
            '  name: "."\n' + fwd_lines
        ),
    }


async def dns64_up() -> bool:
    """nat64 接口在不在（状态展示用）。"""
    out = await cmd("ip", "link", "show", _d64_iface(), check=False)
    return bool(out) and "does not exist" not in out


async def dns64_setup():
    """建 tayga + unbound + SNAT + 主表路由。缺包就跳过并提示。"""
    if not _d64_enabled():
        return False
    if not have_bin("tayga") or not have_bin("unbound"):
        print("[dns64] 缺 tayga/unbound，先装: apt-get install tayga unbound；已跳过")
        return False
    d64 = _d64()
    etc = Path("/etc/antipole")
    etc.mkdir(parents=True, exist_ok=True)
    confs = build_dns64_confs(d64)
    (etc / "tayga.conf").write_text(confs["tayga"])
    # unbound 的配置放 /etc/unbound（AppArmor 等安全策略只放行 unbound 读那里）
    uconf_path = Path("/etc/unbound/antipole.conf")
    uconf_path.parent.mkdir(parents=True, exist_ok=True)
    uconf_path.write_text(confs["unbound"])

    # tun 设备（幂等）
    await cmd("ip", "tuntap", "add", d64["iface"], "mode", "tun", check=False)
    await cmd("tayga", "--mktun", f"--config={etc}/tayga.conf", check=False)
    await cmd("ip", "link", "set", d64["iface"], "up", check=False)
    # tayga 不会自动给 tun 设备配置地址，需手动添加。仅添加 ipv6-addr：
    # ipv4-addr(10.44.0.1) 不应挂载为内核本地地址——否则出向流量被 martian 源校验
    # 丢弃、回包被本地投递而无法转回 v6，导致 NAT64 链路中断（已验证）
    for ln in confs["tayga"].splitlines():
        if ln.startswith("ipv6-addr"):
            a = ln.split()[1]
            await cmd("ip", "-6", "addr", "add", f"{a}/128",
                      "dev", d64["iface"], check=False)
            break

    # 进程（tayga 使用 -d 强制前台运行，否则其后台化会产生孤儿进程占用 tun 设备）
    # 先清理上次崩溃残留的孤儿进程（按本系统配置路径精确匹配，不影响其他实例）
    await cmd("pkill", "-f", "tayga -d --config=/etc/antipole/tayga.conf",
              check=False)
    await cmd("pkill", "-f", "unbound -c /etc/unbound/antipole.conf",
              check=False)
    await asyncio.sleep(0.5)
    if _dns64_proc.get("tayga") is None or _dns64_proc["tayga"].returncode is not None:
        await _dns64_spawn("tayga", "tayga", "-d", f"--config={etc}/tayga.conf")
    if _dns64_proc.get("unbound") is None or _dns64_proc["unbound"].returncode is not None:
        await _dns64_spawn("unbound", "unbound", "-c", str(uconf_path))

    # IPv6 路由把合成前缀指到 tayga（main 表给 Xray 出站，用户表在 bind 时加）
    await cmd("ip", "-6", "route", "replace", d64["prefix"], "dev", d64["iface"],
              check=False)
    # v4 动态池回包指回 tayga 的 tun（NAT64 回程没有这条就丢了；
    # 出向走的是 `from 10.44.0.0/16 lookup warp_table` 规则，优先级高于这里）
    await cmd("ip", "-4", "route", "replace", d64["v4_net"], "dev", d64["iface"],
              check=False)

    # NAT64 池出公网做 SNAT（WARP 可用时经 wg-warp 转发，否则使用原生 v4 出口）
    await _n64_snat()

    # sysctl
    for p in ("/proc/sys/net/ipv4/conf/all/forwarding",
              "/proc/sys/net/ipv4/ip_forward",
              "/proc/sys/net/ipv4/conf/all/accept_local"):
        try:
            Path(p).write_text("1")
        except OSError:
            pass
    print(f"[dns64] 就绪 prefix={d64['prefix']} dns={d64['dns_v6']}")
    return True


async def _n64_snat():
    """NAT64 池 + WG 客户端 v4 出公网的 SNAT。
    WARP 有 v4 就借道 WARP 隧道（v6-only 机器的唯一 v4 出路），否则走原生 v4 出口。
    多隧道时对所有隧道都加 SNAT（隧道内用户的 v4 各自走自己的隧道）。"""
    if not _d64_enabled():
        return
    d64 = _d64()
    w4 = await warp_v4() if CFG["warp"]["enabled"] else ""
    oifs = []
    if w4:
        for idx in range(1, _warp_tunnel_count() + 1):
            iface = _warp_iface(idx)
            if await _warp_handshaked(iface):
                oifs.append(iface)
    if not oifs:
        oifs = [await wan_dev()]
    try:
        v4net = str(ipaddress.ip_network(
            _n().get("wg_v4_addr", "10.7.0.1/24"), strict=False))
    except ValueError:
        v4net = "10.7.0.0/24"
    try:
        await cmd("nft", "delete", "table", "ip", "antipole-nat", check=False)
        await cmd("nft", "add", "table", "ip", "antipole-nat")
        await cmd("nft", "add", "chain", "ip", "antipole-nat", "postrouting",
                  "{ type nat hook postrouting priority srcnat ; }")
        for oif in oifs:
            for subnet in (d64["v4_net"], v4net):
                await cmd("nft", "add", "rule", "ip", "antipole-nat", "postrouting",
                          f"ip saddr {subnet} oifname \"{oif}\" masquerade")
        print(f"[dns64] NAT64 SNAT -> {', '.join(oifs)}")
    except Exception as e:
        print(f"[dns64] NAT64 SNAT 没配上（v4 出口可能不通）: {e}")


async def _dns64_spawn(name: str, *argv):
    _dns64_argv[name] = argv
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            preexec_fn=_child_preexec(os.getpid()))
        _dns64_proc[name] = proc
        asyncio.create_task(_dns64_watch(name, proc))
    except Exception as e:
        print(f"[dns64] 起 {name} 失败: {e}")


async def _dns64_watch(name, proc):
    try:
        await proc.wait()
    except Exception:
        pass
    if _dns64_stop:
        return
    await asyncio.sleep(2)
    if not _dns64_stop and CFG["dns64"].get("enabled", True):
        await _dns64_spawn(name, *_dns64_argv.get(name, (name,)))


def dns64_stop():
    global _dns64_stop
    _dns64_stop = True
    for name, p in _dns64_proc.items():
        if p is not None and p.returncode is None:
            try:
                p.terminate()
            except Exception:
                pass


# ---------- 轮换 ----------

class Rotator:
    """出口轮换：默认关闭，地址与账户绑定、永久不变。

    打开 `rotation.enabled` 后才会按"每用户独立、随机时间点、随机间隔"换 IP
    （模拟 ISP 租约，避免固定规律被风控识破）；隧道用户的静态地址是端口映射与
    证书的锚点，即使开启轮换也不参与。
    """

    def __init__(self, cfg: dict):
        rot_cfg = cfg["rotation"]
        self.enabled = bool(rot_cfg.get("enabled", False))
        self.min_interval = int(rot_cfg.get("min_interval", 1800))   # 30 分钟
        self.max_interval = int(rot_cfg.get("max_interval", 7200))   # 2 小时
        self.start_seq = rot_cfg["start_seq"]
        self.online = {}
        self._next = {}            # user_id -> 下一次轮换的绝对时间戳
        self._tick = 30            # 调度粒度（秒）
        self._tasks = []           # 常驻任务引用

    async def run(self):
        if not self.enabled:
            # 地址与账户绑定：不做任何轮换，也不建立轮换任务
            print("[rotate] 出口轮换未启用（rotation.enabled=false），地址永久绑定账户")
            return
        # 轮换任务长期运行，必须持有强引用（asyncio 仅持弱引用，可能被回收）
        self._tasks = [asyncio.ensure_future(self._rotate()),
                       asyncio.ensure_future(self._status())]

    @staticmethod
    def _rand_delay(lo: int, hi: int) -> int:
        return __import__("random").randint(lo, hi)

    def _schedule(self, user_id: int, now: int):
        """为用户安排随机轮换时刻。新用户首轮额外延迟，避免启动阶段集中轮换。"""
        lo = self.min_interval
        if not self._next.get(user_id):
            lo = max(self.min_interval, 600)   # 上线首轮至少 10 分钟后
        self._next[user_id] = now + self._rand_delay(lo, self.max_interval)

    async def _rotate(self):
        await asyncio.sleep(10)               # 等启动初始化完
        sem = asyncio.Semaphore(4)            # 有界并发：用户多了也不串行积压

        async def _rotate_one_locked(user):
            async with sem:
                try:
                    await self.rotate_one(user)
                    print(f"[rotate] {user['name']} @{time.strftime('%H:%M:%S')} "
                          f"下次 +{self._rand_delay(self.min_interval, self.max_interval)//60}~{self.max_interval//60}min")
                except Exception as e:
                    print(f"[rotate] 用户 {user['name']} 轮换失败: {e}")
                finally:
                    self._schedule(user["id"], int(time.time()))

        while True:
            now = int(time.time())
            try:
                tunnel_uids = {row["user_id"] for row in core.list_tunnel_users()}
                due = []
                for user in list_enabled_users():
                    if user["id"] in tunnel_uids:
                        continue           # 隧道用户地址永久绑定，不参与轮换
                    self._schedule(user["id"], now) if user["id"] not in self._next else None
                    if self._next.get(user["id"], 0) <= now:
                        due.append(user)
                # 同一批到期的并发轮换（各自独立路由表，互不干扰），不串行排队
                if due:
                    await asyncio.gather(*(_rotate_one_locked(user) for user in due))
            except Exception as e:
                print(f"[rotate] 轮换出错: {e}")
            await asyncio.sleep(self._tick)

    async def _status(self):
        while True:
            try:
                await self.refresh_status()
            except Exception as e:
                print(f"[rotate] 状态刷新出错: {e}")
            await asyncio.sleep(60)

    async def rotate_one(self, user: dict) -> str:
        """轮换单个用户的出口 /128（保持在其所属命名网段内）。单用户失败不影响其他用户。

        隧道用户例外：其静态地址被端口映射、证书校验与用户侧配置长期引用，
        换掉会让已建立的映射与已签发证书失配，因此直接拒绝。
        """
        if core.get_tunnel_user(user["id"]):
            raise RuntimeError(
                f"{user['name']} 为隧道用户，静态地址与账户绑定（用于端口映射与证书），不允许轮换")
        with tx().shared():    # 与 CLI 互斥：避免与 `antipole user rotate` 并发修改
            seq = user["rotate_seq"]
            range_name = user.get("range_name", "") or ""
            # 排除其他用户地址与本机保留地址，避免冲突
            others = core.used_egress_ips(exclude_user_id=user["id"])
            while True:
                seq += 1
                egress = addr_for(range_name, seq)
                if egress not in others:
                    break
            await wg_rotate_egress(user["id"], egress, user["egress_ip"])
            core.update_user(user["id"], egress_ip=egress, rotate_seq=seq)
            # 限速 listener 跟着新出口走（filter 按 src 匹配）
            if user["max_mbps"]:
                await tc_set_rate(user["id"], user["max_mbps"])
            return egress

    async def refresh_status(self):
        peers = await wg_dump()
        now = int(time.time())
        for user in list_users():
            info = peers.get(user["pubkey"])
            if info and info["handshake"] and now - info["handshake"] / 1e9 < 300:
                self.online[user["id"]] = int(info["handshake"] / 1e9)
            else:
                self.online.pop(user["id"], None)