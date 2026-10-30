# -*- coding: utf-8 -*-
"""
管理 Web 层（整合）：管理 REST API、自助注册服务、Prometheus 指标、防滥用与配额巡检。

对外两个监听：
  1. 管理面（server.port，默认 9090）：全量 API，需令牌；
  2. 注册面（server.register_port，默认 18290）：仅在 server.register_enabled 时开启，
     提供极简注册页与注册/登录接口，默认关闭。

认证：X-Admin-Token 或 Authorization: Bearer；恒定时间比较；
角色分权 admin（全权）/ view（只读）；失败次数超限按来源 IP 临时封禁。
"""
import asyncio
import hmac
import ipaddress
import re
import secrets
import time
import uuid as uuidlib

from aiohttp import web

from . import core, edge, net

_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-_.]*[A-Za-z0-9])?$")

CFG = None
GUARD = None
ROTATOR = None
_CONN = None


def setup(cfg: dict, guard, rotator, conn):
    global CFG, GUARD, ROTATOR, _CONN
    CFG = cfg
    GUARD = guard
    ROTATOR = rotator
    _CONN = conn


# ============================================================
# 一、响应与认证
# ============================================================

def json_ok(data):
    return web.json_response({"ok": True, "data": data})


def json_err(msg, status=400):
    return web.json_response({"ok": False, "error": msg}, status=status)


def _client_ip(request) -> str:
    remote = request.remote or ""
    try:
        return str(ipaddress.ip_address(remote))
    except ValueError:
        return remote.split(":")[0] or "unknown"


class Guard:
    """防滥用：登录失败封禁、注册限流（单 IP 与全局）、来源封禁。"""

    def __init__(self, cfg: dict):
        abuse = cfg["abuse"]
        self.login_fails = int(abuse["login_fails"])
        self.login_ban_s = int(abuse["login_ban_s"])
        self.reg_per_hour = int(abuse["register_per_hour"])
        self.reg_global_per_hour = int(abuse.get("register_global_per_hour", 60))
        self.ban_s = int(abuse.get("ban_s", 1800))
        self._fail = {}
        self._reg = {}
        self._global_reg = []
        self._ban = {}
        self._lock = __import__("threading").Lock()

    def login_blocked(self, ip: str) -> int:
        with self._lock:
            left = self._ban.get(ip, 0) - time.time()
        return int(left) if left > 0 else 0

    def login_fail(self, ip: str):
        now = time.time()
        with self._lock:
            rec = self._fail.setdefault(ip, [0, 0.0])
            rec[0] += 1
            rec[1] = now
            if rec[0] >= self.login_fails:
                # 达到阈值即真正拉黑来源（此前只记时间戳，封禁未生效）
                rec[0] = 0
                self._ban[ip] = now + self.login_ban_s
                banned = True
            else:
                banned = False
        if banned:
            core.log_abuse("ban", ip, f"管理接口连续认证失败 {self.login_fails} 次，"
                                      f"封禁 {self.login_ban_s}s")

    def login_ok(self, ip: str):
        with self._lock:
            self._fail.pop(ip, None)

    def ban(self, ip: str, seconds: int = None):
        with self._lock:
            self._ban[ip] = time.time() + (seconds or self.ban_s)
        core.log_abuse("ban", ip, f"封禁 {seconds or self.ban_s}s")

    def reg_allowed(self, ip: str) -> bool:
        """注册限流：单 IP 与全局双阈值。"""
        now = time.time()
        with self._lock:
            ts = [t for t in self._reg.get(ip, []) if now - t < 3600]
            if len(ts) >= self.reg_per_hour:
                return False
            self._global_reg = [t for t in self._global_reg if now - t < 3600]
            if len(self._global_reg) >= self.reg_global_per_hour:
                return False
            ts.append(now)
            self._reg[ip] = ts
            self._global_reg.append(now)
            return True

    def cleanup(self):
        now = time.time()
        with self._lock:
            for ip in list(self._fail):
                if now - self._fail[ip][1] > self.login_ban_s:
                    self._fail.pop(ip, None)
            for ip in list(self._reg):
                self._reg[ip] = [t for t in self._reg[ip] if now - t < 3600]
                if not self._reg[ip]:
                    self._reg.pop(ip, None)
            for ip in list(self._ban):
                if self._ban[ip] <= now:
                    self._ban.pop(ip, None)
            self._global_reg = [t for t in self._global_reg if now - t < 3600]


def _token_from(request) -> str:
    got = request.headers.get("X-Admin-Token", "")
    if not got:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            got = auth[7:]
    return got


def _match_token(got: str):
    server = CFG.get("server", {})
    admin = server.get("admin_token")
    if admin and hmac.compare_digest(got, admin):
        return "admin"
    view = server.get("view_token")
    if view and hmac.compare_digest(got, view):
        return "view"
    return None


def _require(request, need: str = "admin"):
    ip = _client_ip(request)
    left = GUARD.login_blocked(ip)
    if left:
        return json_err(f"来源已封禁，{left} 秒后重试", 429)
    role = _match_token(_token_from(request))
    if role is None:
        GUARD.login_fail(ip)
        return json_err("令牌无效", 401)
    if need == "admin" and role != "admin":
        return json_err("只读令牌无此操作权限", 403)
    return None


# ============================================================
# 二、用户
# ============================================================

_server_ip_cache = {}


async def _server_ip() -> str:
    """对外公布的接入地址：优先 server.public_ip，其次探测。"""
    configured = (CFG["server"].get("public_ip")
                  or CFG["network"].get("public_ip"))
    if configured:
        return configured
    if _server_ip_cache.get("ip"):
        return _server_ip_cache["ip"]
    for url in ("https://ipv4.icanhazip.com", "https://ipv6.icanhazip.com"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "3", url,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await proc.communicate()
            ip = out.decode().strip()
            ipaddress.ip_address(ip)
            _server_ip_cache["ip"] = ip
            return ip
        except Exception:
            continue
    return ""


async def gen_wg_key() -> tuple:
    priv = await core.cmd("wg", "genkey")
    pub = await core.cmd("wg", "pubkey", stdin=priv)
    return priv, pub


def _user_view(user: dict, online: dict = None):
    used = user["used_up"] + user["used_down"]
    tunnel = core.get_tunnel_user(user["id"])
    return {
        "id": user["id"],
        "name": user["name"],
        "internal_ip": user["internal_ip"],
        "internal_v4": core.internal_v4(user["id"]),
        "egress_ip": user["egress_ip"],
        "range": user.get("range_name", ""),
        "enabled": bool(user["enabled"]),
        "quota_mb": user["quota_mb"],
        "used_mb": round(used / 1048576, 1),
        "max_mbps": user["max_mbps"],
        "protected": edge.GUARD.is_protected(user) if edge.GUARD else False,
        "handshake": (online or {}).get(user["id"]) or 0,
        "created_at": user["created_at"],
        "tunnel": {
            "port_count": tunnel["port_count"] if tunnel else None,
            "quota_mb": tunnel["quota_mb"] if tunnel else None,
            "max_mbps": tunnel["max_mbps"] if tunnel else None,
            "used_mb": round(tunnel["used_bytes"] / 1048576, 1) if tunnel else None,
            "maps": len(core.list_tunnel_maps(user["id"])) if tunnel else 0,
        } if tunnel else None,
    }


async def create_user_internal(name: str, range_name: str = "",
                               password: str = "", quota_mb: int = None,
                               max_mbps: int = None):
    """创建用户内核与库记录（管理面与注册面共用）。"""
    with core.tx().shared():
        uid = core.next_user_id()
        egress, seq = core.alloc_egress(range_name)
        priv, pub = await gen_wg_key()
        core.add_user(uid, name, core.internal_ip(uid), egress, seq, pub, priv,
                    str(uuidlib.uuid4()), 
                    quota_mb if quota_mb is not None else CFG["abuse"]["default_quota_mb"],
                    max_mbps if max_mbps is not None else CFG["abuse"].get("default_mbps", 0),
                    range_name)
        if password:
            core.update_user(uid, password_hash=core.hash_password(password))
        await net.wg_add_peer(uid, pub)
        user = core.get_user(uid)
        if user["max_mbps"]:
            await net.tc_set_rate(uid, user["max_mbps"])
        # 代理侧动态加入（API 不可用时回退整体热载），避免新增用户中断既有连接
        await edge.sync_user(user, True)
        return user


async def create_user(request):
    if (err := _require(request)):
        return err
    data = await request.json()
    name = (data.get("name") or "").strip()
    if not _NAME_RE.match(name or ""):
        return json_err("用户名仅允许字母数字._-，最长 32 位")
    if core.get_user_by_name(name):
        return json_err("用户名已存在")
    range_name = (data.get("range") or "").strip()
    if range_name and range_name not in (CFG["network"].get("ranges") or {}):
        return json_err("指定的命名网段不存在")
    user = await create_user_internal(name, range_name)
    return json_ok(_user_view(user, ROTATOR.online))


async def list_users_api(request):
    if (err := _require(request, "view")):
        return err
    return json_ok([_user_view(u, ROTATOR.online) for u in core.list_users()])


async def get_user_api(request):
    if (err := _require(request, "view")):
        return err
    user = core.get_user(int(request.match_info["uid"]))
    if not user:
        return json_err("用户不存在", 404)
    return json_ok(_user_view(user, ROTATOR.online))


async def update_user(request):
    if (err := _require(request)):
        return err
    uid = int(request.match_info["uid"])
    user = core.get_user(uid)
    if not user:
        return json_err("用户不存在", 404)
    data = await request.json()
    msgs = []
    with core.tx().shared():
        if "enabled" in data:
            enable = bool(data["enabled"])
            core.update_user(uid, enabled=1 if enable else 0)
            if enable:
                await net.wg_add_peer(uid, user["pubkey"])
            else:
                await net.wg_del_peer(uid, user["pubkey"])
            msgs.append("已启用" if enable else "已禁用")
            await edge.sync_user(core.get_user(uid), enable)

        if "quota_mb" in data:
            core.update_user(uid, quota_mb=max(0, int(data["quota_mb"] or 0)))
            msgs.append(f"配额 {data['quota_mb']}MB")

        if "max_mbps" in data:
            mbps = max(0, int(data["max_mbps"] or 0))
            core.update_user(uid, max_mbps=mbps)
            msgs.append(await net.tc_set_rate(uid, mbps))

        if "range" in data:
            new_range = (data.get("range") or "").strip()
            if new_range and new_range not in (CFG["network"].get("ranges") or {}):
                return json_err("指定的命名网段不存在")
            core.update_user(uid, range_name=new_range)
            msgs.append(f"网段切换至 {new_range or '主段'}（下次轮换生效）")

        if data.get("reset_traffic"):
            core.update_user(uid, used_up=0, used_down=0)
            core.update_tunnel_user(uid, used_bytes=0)
            msgs.append("流量已清零")

        if data.get("rotate"):
            egress = await ROTATOR.rotate_one(core.get_user(uid))
            msgs.append(f"已换出口 {egress}")

        if data.get("clear_protection"):
            core.update_user(uid, protect_until=0)
            msgs.append("已解除熔断")

    return json_ok({"user": _user_view(core.get_user(uid), ROTATOR.online),
                    "messages": msgs})


async def delete_user(request):
    if (err := _require(request)):
        return err
    uid = int(request.match_info["uid"])
    user = core.get_user(uid)
    if not user:
        return json_err("用户不存在", 404)
    await purge_user(uid, user)
    return json_ok({"deleted": uid})


async def purge_user(uid: int, user: dict = None):
    """彻底清理用户：内核状态、限速、隧道会话、地址守护与库记录。"""
    user = user or core.get_user(uid)
    if not user:
        return
    with core.tx().shared():
        # 断开隧道会话（若在线）
        for session in list(edge._sessions.values()):
            if session.uid == uid:
                await session.close()
        try:
            await net.wg_del_peer(uid, user["pubkey"])
        except Exception:
            pass
        try:
            await net.tc_set_rate(uid, 0)
        except Exception:
            pass
        await net.addr_guard_del(user["egress_ip"])
        core.delete_user(uid)
        core.clear_runtime_stat(uid)
        if ROTATOR:
            ROTATOR.online.pop(uid, None)
        await edge.sync_user(user, False)


async def user_wg_config(request):
    if (err := _require(request)):
        return err
    user = core.get_user(int(request.match_info["uid"]))
    if not user:
        return json_err("用户不存在", 404)
    server_ip = await _server_ip()
    if not server_ip:
        return json_err("无法确定公网地址，请在配置中设置 server.public_ip")
    return web.Response(text=wg_config_text(user, server_ip),
                        content_type="text/plain",
                        headers={"Content-Disposition":
                                 f'attachment; filename="wg-{user["name"]}.conf"'})


def wg_config_text(user: dict, server_ip: str) -> str:
    pub = CFG.get("_wg_pub") or ""
    v4 = core.internal_v4(user["id"])
    addr = f"Address = {user['internal_ip']}/128"
    if v4:
        addr += f"\nAddress = {v4}/32"
    allowed = "0.0.0.0/0, ::/0" if CFG["warp"]["enabled"] and v4 else "::/0"
    dns = (CFG["dns64"]["dns_v6"] if CFG["dns64"].get("enabled", True)
           else "2001:4860:4860::8888, 1.1.1.1")
    return ("[Interface]\n"
            f"{addr}\n"
            f"PrivateKey = {user['privkey']}\n"
            f"DNS = {dns}\n"
            "\n[Peer]\n"
            f"PublicKey = {pub}\n"
            f"Endpoint = {server_ip}:{CFG['network']['wg_port']}\n"
            f"AllowedIPs = {allowed}\n"
            "PersistentKeepalive = 25\n")


async def user_link(request):
    if (err := _require(request)):
        return err
    user = core.get_user(int(request.match_info["uid"]))
    if not user:
        return json_err("用户不存在", 404)
    domain = core.primary_domain()
    return json_ok({"link": edge.vless_link(user, domain),
                    "domain": domain["domain"] if domain else None})


# ============================================================
# 三、接入域名
# ============================================================

def _domain_view(domain: dict):
    return {"id": domain["id"], "domain": domain["domain"], "ip": domain["ip"],
            "port": domain["port"], "note": domain["note"],
            "enabled": bool(domain["enabled"])}


async def list_domains(request):
    if (err := _require(request, "view")):
        return err
    return json_ok([_domain_view(d) for d in core.list_domains()])


async def create_domain(request):
    if (err := _require(request)):
        return err
    data = await request.json()
    domain = (data.get("domain") or "").strip()
    if not _DOMAIN_RE.match(domain or ""):
        return json_err("域名格式不正确")
    ip = (data.get("ip") or "").strip()
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return json_err("IP 格式不正确")
    did = core.add_domain(domain, ip, int(data.get("port") or 0),
                        (data.get("note") or "").strip()[:80])
    return json_ok(_domain_view(core.get_domain(did)))


async def update_domain(request):
    if (err := _require(request)):
        return err
    did = int(request.match_info["did"])
    if not core.get_domain(did):
        return json_err("域名不存在", 404)
    data = await request.json()
    fields = {}
    if data.get("domain"):
        if not _DOMAIN_RE.match(data["domain"].strip()):
            return json_err("域名格式不正确")
        fields["domain"] = data["domain"].strip()
    if "ip" in data:
        value = (data["ip"] or "").strip()
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return json_err("IP 格式不正确")
        fields["ip"] = value
    if "port" in data:
        fields["port"] = max(0, int(data["port"] or 0))
    if "note" in data:
        fields["note"] = (data["note"] or "").strip()[:80]
    if "enabled" in data:
        fields["enabled"] = 1 if data["enabled"] else 0
    core.update_domain(did, **fields)
    return json_ok(_domain_view(core.get_domain(did)))


async def delete_domain(request):
    if (err := _require(request)):
        return err
    did = int(request.match_info["did"])
    if not core.get_domain(did):
        return json_err("域名不存在", 404)
    core.delete_domain(did)
    return json_ok({"deleted": did})


# ============================================================
# 四、邀请码
# ============================================================

async def create_invite(request):
    if (err := _require(request)):
        return err
    data = {}
    try:
        data = await request.json()
    except Exception:
        pass
    count = max(1, min(50, int(data.get("count") or 1)))
    codes = [db.add_invite(secrets.token_urlsafe(12)) for _ in range(count)]
    return json_ok({"invites": codes, "invite": codes[0]})


# ============================================================
# 五、隧道 API
# ============================================================

async def list_tunnels(request):
    if (err := _require(request, "view")):
        return err
    out = []
    for row in core.list_tunnel_users():
        out.append({
            "user_id": row["user_id"], "name": row["user_name"],
            "egress_ip": row["egress_ip"], "range": row["range_name"],
            "port_count": row["port_count"],
            "quota_mb": row["quota_mb"], "max_mbps": row["max_mbps"],
            "used_mb": round(row["used_bytes"] / 1048576, 1),
            "enabled": bool(row["user_enabled"]),
            "maps": core.list_tunnel_maps(row["user_id"]),
        })
    return json_ok(out)


async def create_tunnel(request):
    if (err := _require(request)):
        return err
    if not edge.tunnel_enabled():
        return json_err("隧道功能未启用（tunnel.enabled=false）")
    data = await request.json()
    name = (data.get("name") or "").strip()
    if not _NAME_RE.match(name or ""):
        return json_err("用户名格式不正确")
    if core.get_user_by_name(name):
        return json_err("用户名已存在")
    range_name = (data.get("range") or "").strip() or CFG["tunnel"].get("range", "tunnel")
    user = await create_user_internal(name, range_name)
    token = secrets.token_hex(16)
    core.add_tunnel_user(user["id"], token,
                         max(0, int(data.get("quota_mb") or 0)),
                         max(0, int(data.get("max_mbps") or 0)))
    return json_ok({"user_id": user["id"], "name": name, "token": token,
                    "egress_ip": user["egress_ip"],
                    "access": f"<{user['egress_ip']}>:<端口> 对应 用户主机:<端口>"})


async def update_tunnel(request):
    if (err := _require(request)):
        return err
    uid = int(request.match_info["uid"])
    if not core.get_tunnel_user(uid):
        return json_err("隧道用户不存在", 404)
    data = await request.json()
    if "quota_mb" in data:
        core.update_tunnel_user(uid, quota_mb=max(0, int(data["quota_mb"] or 0)))
    if "max_mbps" in data:
        mbps = max(0, int(data["max_mbps"] or 0))
        core.update_tunnel_user(uid, max_mbps=mbps)
        core.update_user(uid, max_mbps=mbps)
        await net.tc_set_rate(uid, mbps)
    if "token" in data and data["token"]:
        core.update_tunnel_user(uid, token=str(data["token"])[:64])
    if data.get("reset_traffic"):
        core.update_tunnel_user(uid, used_bytes=0)
    return json_ok(core.get_tunnel_user(uid))


# ============================================================
# 六、状态 / 指标 / 滥用事件
# ============================================================

def _meminfo():
    try:
        data = {}
        with open("/proc/meminfo") as handle:
            for line in handle:
                key, value = line.split(":", 1)
                data[key] = int(value.strip().split()[0])
        return data.get("MemAvailable", 0), data.get("MemTotal", 0)
    except OSError:
        return 0, 0


async def status(request):
    if (err := _require(request, "view")):
        return err
    free, total = _meminfo()
    peers = await net.wg_dump()
    now = time.time()
    online = sum(1 for i in peers.values()
                 if i["handshake"] and now - i["handshake"] / 1e9 < 300)
    warp_on = await net.warp_is_up() if CFG["warp"]["enabled"] else False
    sessions = edge.tunnel_sessions()
    return json_ok({
        "mem_free_mb": round(free / 1048576, 1),
        "mem_total_mb": round(total / 1048576, 1),
        "users": len(core.list_users()),
        "online": online,
        "rotation_enabled": bool(CFG["rotation"].get("enabled", False)),
        "rotation_min_s": CFG["rotation"].get("min_interval", 1800),
        "rotation_max_s": CFG["rotation"].get("max_interval", 7200),
        "prefix": CFG["network"]["prefix"],
        "ranges": CFG["network"].get("ranges", {}),
        "guard_allocated": bool(CFG["network"].get("guard_allocated", True)),
        "xray": edge.xray_running(),
        "xray_port": CFG["xray"]["port"],
        "warp": warp_on,
        "warp_v4": await net.warp_v4() if warp_on else "",
        "dns64": await net.dns64_up(),
        "bgp": await net.bgp_status(),
        "tc": CFG["network"].get("tc_enabled", True),
        "register_enabled": bool(CFG["server"].get("register_enabled", False)),
        "register_port": CFG["server"].get("register_port", 18290),
        "tunnel_enabled": edge.tunnel_enabled(),
        "tunnel_port": CFG["tunnel"].get("port", 18281),
        "tunnel_online": sessions["count"],
        "tunnel_ports": sessions["ports"],
        "tunnel_users": len(core.list_tunnel_users()),
        "certs": await cert_status(),
    })


def _prom_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


async def metrics(request):
    if (err := _require(request, "view")):
        return err
    peers = await net.wg_dump()
    now = time.time()
    online = sum(1 for i in peers.values()
                 if i["handshake"] and now - i["handshake"] / 1e9 < 300)
    free, total = _meminfo()
    warp_on = await net.warp_is_up() if CFG["warp"]["enabled"] else False
    bgp = await net.bgp_status()
    users = core.list_users()
    sessions = edge.tunnel_sessions()
    out = [
        "# HELP antipole_users_total 已注册用户数",
        "# TYPE antipole_users_total gauge",
        f"antipole_users_total {len(users)}",
        "# HELP antipole_online_users 在线用户数（300 秒内有握手）",
        "# TYPE antipole_online_users gauge",
        f"antipole_online_users {online}",
        "# HELP antipole_mem_available_bytes 可用内存（字节）",
        "# TYPE antipole_mem_available_bytes gauge",
        f"antipole_mem_available_bytes {free * 1024}",
        "# HELP antipole_mem_total_bytes 总内存（字节）",
        "# TYPE antipole_mem_total_bytes gauge",
        f"antipole_mem_total_bytes {total * 1024}",
        "# HELP antipole_xray_running Xray 进程运行状态",
        "# TYPE antipole_xray_running gauge",
        f"antipole_xray_running {1 if edge.xray_running() else 0}",
        "# HELP antipole_warp_up WARP 接口状态",
        "# TYPE antipole_warp_up gauge",
        f"antipole_warp_up {1 if warp_on else 0}",
        "# HELP antipole_bgp_alive BGP 守护进程状态",
        "# TYPE antipole_bgp_alive gauge",
        f"antipole_bgp_alive {1 if bgp['alive'] else 0}",
        "# HELP antipole_tc_enabled tc 限速开关",
        "# TYPE antipole_tc_enabled gauge",
        f"antipole_tc_enabled {1 if CFG['network'].get('tc_enabled', True) else 0}",
        "# HELP antipole_tunnel_sessions 在线隧道会话数",
        "# TYPE antipole_tunnel_sessions gauge",
        f"antipole_tunnel_sessions {sessions['count']}",
        "# HELP antipole_tunnel_ports 已映射公网端口数",
        "# TYPE antipole_tunnel_ports gauge",
        f"antipole_tunnel_ports {sessions['ports']}",
        "# HELP antipole_user_traffic_bytes 用户累计流量（字节）",
        "# TYPE antipole_user_traffic_bytes counter",
        "# HELP antipole_user_enabled 用户启用状态",
        "# TYPE antipole_user_enabled gauge",
        "# HELP antipole_user_quota_mb 用户配额（MB，0 为不限）",
        "# TYPE antipole_user_quota_mb gauge",
        "# HELP antipole_user_protected 用户是否处于熔断保护",
        "# TYPE antipole_user_protected gauge",
    ]
    for user in users:
        label = _prom_label(user["name"])
        protected = 1 if (edge.GUARD and edge.GUARD.is_protected(user)) else 0
        out.append(f'antipole_user_traffic_bytes{{user="{label}",direction="up"}} {user["used_up"]}')
        out.append(f'antipole_user_traffic_bytes{{user="{label}",direction="down"}} {user["used_down"]}')
        out.append(f'antipole_user_enabled{{user="{label}"}} {1 if user["enabled"] else 0}')
        out.append(f'antipole_user_quota_mb{{user="{label}"}} {user["quota_mb"]}')
        out.append(f'antipole_user_protected{{user="{label}"}} {protected}')
    return web.Response(
        text="\n".join(out) + "\n",
        headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"})


async def abuse_list(request):
    if (err := _require(request, "view")):
        return err
    return json_ok(core.list_abuse(limit=100))


async def health(request):
    """活动地址健康状态：在线、速率、隧道连接与端口映射。"""
    if (err := _require(request, "view")):
        return err
    stats = core.list_runtime_stats()
    now = core.now_ms()
    out = []
    for user in core.list_users():
        record = stats.get(user["id"], {})
        tunnel = core.get_tunnel_user(user["id"])
        out.append({
            "id": user["id"], "name": user["name"],
            "egress_ip": user["egress_ip"],
            "range": user.get("range_name", ""),
            "enabled": bool(user["enabled"]),
            "online": bool(record.get("online")),
            "tunnel_online": bool(record.get("tunnel_on")),
            "conns": record.get("conns", 0),
            "ports": record.get("ports", 0),
            "up_bps": record.get("up_bps", 0),
            "down_bps": record.get("down_bps", 0),
            "sample_age_s": round((now - record["ts"]) / 1000, 1) if record else None,
            "used_mb": round((user["used_up"] + user["used_down"]) / 1048576, 1),
            "quota_mb": user["quota_mb"],
            "tunnel_used_mb": round(tunnel["used_bytes"] / 1048576, 1) if tunnel else None,
            "max_mbps": user["max_mbps"],
            "protected": edge.GUARD.is_protected(user) if edge.GUARD else False,
        })
    return json_ok(out)


# ============================================================
# 七、证书到期
# ============================================================

async def _cert_days_left(crt: str):
    try:
        proc = await asyncio.create_subprocess_exec(
            "openssl", "x509", "-noout", "-enddate", "-in", crt,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), 10)
    except Exception:
        return None
    match = re.search(r"notAfter=(.*)", out.decode(errors="replace"))
    if not match:
        return None
    import datetime
    try:
        exp = datetime.datetime.strptime(
            match.group(1).strip().replace(" GMT", ""), "%b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return (exp - datetime.datetime.utcnow()).days


async def cert_status():
    result = []
    for domain in core.list_domains():
        left = await _cert_days_left(domain["cert_crt"]) if domain.get("cert_crt") else None
        result.append({"domain": domain["domain"], "days_left": left})
    return result


async def cert_alert_loop(cfg):
    """每 6 小时巡检证书剩余天数，临近到期输出告警并可推送 webhook。"""
    alerts = cfg.get("alerts") or {}
    webhook = (alerts.get("webhook") or "").strip()
    warn_days = max(1, int(alerts.get("cert_days") or 14))
    alerted = {}
    while True:
        await asyncio.sleep(3600 * 6)
        try:
            for domain in core.list_domains():
                if not domain.get("cert_crt"):
                    continue
                left = await _cert_days_left(domain["cert_crt"])
                if left is None:
                    continue
                low = left <= warn_days
                if low and not alerted.get(domain["domain"]):
                    msg = (f"[cert] 证书 {domain['domain']} 剩余 {left} 天"
                           f"（阈值 {warn_days} 天）")
                    print(msg)
                    if webhook:
                        try:
                            await _notify_webhook(webhook, "antipoleBGP 证书告警", msg)
                        except Exception as e:
                            print(f"[cert] webhook 推送失败: {e}")
                alerted[domain["domain"]] = low
        except Exception as e:
            print(f"[cert] 巡检出错: {e}")


async def _notify_webhook(url: str, title: str, text: str):
    import aiohttp
    async with aiohttp.ClientSession() as session:
        await session.post(url, json={"title": title, "text": text},
                           timeout=aiohttp.ClientTimeout(total=10))


# ============================================================
# 八、配额与流量巡检
# ============================================================

async def stats_loop(cfg):
    """流量统计与健康快照：统计差值 -> 内存缓冲批量落库，并写入速率与在线状态。

    速率快照写入 runtime_stats 表，供 CLI 与 API 在独立进程读取，
    避免跨进程共享内存的复杂度。
    """
    interval = max(2, int(cfg["abuse"].get("quota_check_s") or 10))
    while True:
        await asyncio.sleep(interval)
        try:
            current = await edge.fetch_stats()
            per_user = edge.user_traffic(edge.stats_diff(current))
            now = time.time()

            # 隧道会话状态快照
            session_conns = {}
            for session in list(edge._sessions.values()):
                session_conns[session.uid] = len(session.conns)

            # WG 在线状态（300 秒内有握手）
            peers = await net.wg_dump()
            online_uids = set()
            for user in core.list_users():
                info = peers.get(user["pubkey"])
                if info and info["handshake"] \
                        and now - info["handshake"] / 1e9 < 300:
                    online_uids.add(user["id"])

            # 速率：本次增量 / 采样间隔
            rates = {}
            for name, (up, down) in per_user.items():
                user = core.get_user_by_name(name)
                if user:
                    core.buffer_traffic(user["id"], up, down)
                    rates[user["id"]] = (int(up / interval), int(down / interval))

            for user in core.list_users():
                uid = user["id"]
                up_bps, down_bps = rates.get(uid, (0, 0))
                tunnel = core.get_tunnel_user(uid)
                core.set_runtime_stat(
                    uid, up_bps=up_bps, down_bps=down_bps,
                    conns=session_conns.get(uid, 0),
                    online=1 if uid in online_uids else 0,
                    tunnel_on=1 if uid in session_conns else 0,
                    ports=len(core.list_tunnel_maps(uid)) if tunnel else 0)

            core.flush_traffic()
        except Exception as e:
            print(f"[stats] 统计出错: {e}")


async def quota_loop(cfg):
    """配额巡检：超限即断开（代理侧拆 peer 与限速，隧道侧关闭会话）。"""
    interval = max(5, int(cfg["abuse"].get("quota_check_s") or 10))
    warn_pct = int(cfg["abuse"].get("quota_warn_pct") or 90)
    warned = set()
    while True:
        await asyncio.sleep(interval)
        try:
            core.flush_traffic()
            for user in core.list_users():
                if not user["enabled"]:
                    continue
                quota = user["quota_mb"]
                used = user["used_up"] + user["used_down"]
                tunnel = core.get_tunnel_user(user["id"])
                if tunnel:
                    tquota = tunnel["quota_mb"] or quota
                    if tquota > 0:
                        tused = tunnel["used_bytes"]
                        if tused * 100.0 / (tquota * 1048576) >= warn_pct \
                                and f"t{user['id']}" not in warned:
                            warned.add(f"t{user['id']}")
                            print(f"[abuse] {user['name']} 隧道用量已达 "
                                  f"{tused * 100.0 / (tquota * 1048576):.0f}%")
                        if tused > tquota * 1048576:
                            for session in list(edge._sessions.values()):
                                if session.uid == user["id"]:
                                    await session.close()
                            core.log_abuse("tunnel_quota", user["name"],
                                           f"超配额 {tquota}MB")
                            print(f"[abuse] {user['name']} 隧道超配额，已断开")
                if quota <= 0:
                    continue
                pct = used * 100.0 / (quota * 1048576)
                if pct < warn_pct:
                    warned.discard(user["id"])
                elif user["id"] not in warned:
                    warned.add(user["id"])
                    print(f"[abuse] {user['name']} 用量已达 {pct:.0f}%")
                if used > quota * 1048576:
                    with core.tx().shared():
                        core.update_user(user["id"], enabled=0)
                        try:
                            await net.wg_del_peer(user["id"], user["pubkey"])
                        except Exception:
                            pass
                        try:
                            await net.tc_set_rate(user["id"], 0)
                        except Exception:
                            pass
                    warned.discard(user["id"])
                    core.log_abuse("quota", user["name"], f"超配额 {quota}MB")
                    print(f"[abuse] {user['name']} 超配额，已禁用")
                    await edge.sync_user(user, False)
        except Exception as e:
            print(f"[abuse] 配额巡检出错: {e}")


async def abuse_sweep_loop():
    """定期清理熔断状态与滥用事件历史。"""
    while True:
        await asyncio.sleep(300)
        try:
            if edge.GUARD:
                await edge.GUARD.sweep()
            if GUARD:
                GUARD.cleanup()
            core.prune_abuse(keep_days=7)
        except Exception as e:
            print(f"[abuse] 清理出错: {e}")


# ============================================================
# 九、自助注册服务
# ============================================================

async def _register(request):
    ip = _client_ip(request)
    if GUARD.login_blocked(ip):
        return json_err("来源已封禁", 429)
    data = await request.json()
    name = (data.get("name") or "").strip()
    password = (data.get("password") or "").strip()
    code = (data.get("invite") or "").strip()
    if not (name and password and code):
        return json_err("用户名、密码与邀请码均为必填")
    if not _NAME_RE.match(name):
        return json_err("用户名格式不正确")
    if len(password) < 8:
        return json_err("密码长度至少 8 位")
    if core.get_user_by_name(name):
        return json_err("用户名已存在", 409)
    if not GUARD.reg_allowed(ip):
        GUARD.ban(ip, 3600)
        return json_err("注册过于频繁，来源已临时封禁", 429)
    if not core.consume_invite(code, name):
        return json_err("邀请码无效或已使用", 403)
    try:
        user = await create_user_internal(name, "", password=password)
    except Exception as e:
        return json_err(f"创建失败: {e}", 500)
    return json_ok({"name": name, "uid": user["id"],
                    "egress_ip": user["egress_ip"]})


async def _login(request):
    ip = _client_ip(request)
    if GUARD.login_blocked(ip):
        return json_err("来源已封禁", 429)
    data = await request.json()
    name = (data.get("name") or "").strip()
    password = (data.get("password") or "").strip()
    user = core.get_user_by_name(name)
    if not user or not core.verify_password(password, user.get("password_hash", "")):
        GUARD.login_fail(ip)
        return json_err("用户名或密码错误", 401)
    GUARD.login_ok(ip)
    domain = core.primary_domain()
    tunnel = core.get_tunnel_user(user["id"])
    server_ip = await _server_ip()
    return json_ok({
        "name": user["name"],
        "egress_ip": user["egress_ip"],
        "range": user.get("range_name", ""),
        "vless": edge.vless_link(user, domain),
        "wg": wg_config_text(user, server_ip) if server_ip else "",
        "tunnel_token": tunnel["token"] if tunnel else None,
        "quota_mb": user["quota_mb"],
        "used_mb": round((user["used_up"] + user["used_down"]) / 1048576, 1),
        "max_mbps": user["max_mbps"],
    })


_REGISTER_PAGE = """<!doctype html><meta charset="utf-8">
<title>antipoleBGP 注册</title>
<style>body{font:14px/1.6 system-ui;max-width:420px;margin:60px auto;padding:0 16px}
input,button{width:100%;padding:9px;margin:6px 0;box-sizing:border-box}
pre{background:#f5f5f5;padding:10px;white-space:pre-wrap}</style>
<h3>账号注册</h3>
<form id="f">
<input name="name" placeholder="用户名（字母数字._-）" required>
<input name="password" type="password" placeholder="密码（至少 8 位）" required>
<input name="invite" placeholder="邀请码" required>
<button>注册</button></form>
<pre id="out"></pre>
<script>
document.getElementById('f').onsubmit = async (e) => {
  e.preventDefault();
  const body = {};
  new FormData(e.target).forEach((v, k) => body[k] = v);
  const r = await fetch('/api/register', {method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  document.getElementById('out').textContent = JSON.stringify(await r.json(), null, 2);
};
</script>"""


async def _index(request):
    return web.Response(text=_REGISTER_PAGE, content_type="text/html")


# ============================================================
# 十、应用组装
# ============================================================

def make_app() -> web.Application:
    app = web.Application(client_max_size=64 * 1024)
    allow = CFG["server"].get("admin_allow") or []
    if allow:
        @web.middleware
        async def allow_mw(request, handler):
            ip = _client_ip(request)
            if ip not in allow and ip not in ("127.0.0.1", "::1"):
                return json_err("来源不在白名单", 403)
            return await handler(request)
        app.middlewares.append(allow_mw)

    router = app.router
    router.add_get("/api/status", status)
    router.add_get("/api/metrics", metrics)
    router.add_get("/api/abuse", abuse_list)
    router.add_get("/api/health", health)
    router.add_post("/api/users", create_user)
    router.add_get("/api/users", list_users_api)
    router.add_get("/api/users/{uid:\\d+}", get_user_api)
    router.add_patch("/api/users/{uid:\\d+}", update_user)
    router.add_delete("/api/users/{uid:\\d+}", delete_user)
    router.add_get("/api/users/{uid:\\d+}/wg", user_wg_config)
    router.add_get("/api/users/{uid:\\d+}/link", user_link)
    router.add_get("/api/tunnels", list_tunnels)
    router.add_post("/api/tunnels", create_tunnel)
    router.add_patch("/api/tunnels/{uid:\\d+}", update_tunnel)
    router.add_get("/api/domains", list_domains)
    router.add_post("/api/domains", create_domain)
    router.add_patch("/api/domains/{did:\\d+}", update_domain)
    router.add_delete("/api/domains/{did:\\d+}", delete_domain)
    router.add_post("/api/invites", create_invite)
    return app


def make_register_app() -> web.Application:
    app = web.Application(client_max_size=32 * 1024)
    app.router.add_get("/", _index)
    app.router.add_post("/api/register", _register)
    app.router.add_post("/api/login", _login)
    return app