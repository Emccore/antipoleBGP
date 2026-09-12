# -*- coding: utf-8 -*-
"""
REST API（aiohttp）+ 防滥用机制 + 流量配额巡检。
认证采用管理令牌（恒定时间比较，防时序侧信道），多次认证失败按来源 IP 临时封禁。
"""
import asyncio
import hmac
import ipaddress
import secrets
import time

from aiohttp import web

from . import db, net, proxy

# 用户名/域名白名单字符，防注入
_NAME_RE = __import__("re").compile(r"^[A-Za-z0-9_.\-]{1,32}$")
_DOMAIN_RE = __import__("re").compile(
    r"^[A-Za-z0-9]([A-Za-z0-9\-_.]*[A-Za-z0-9])?$")


# ---------- 响应 ----------

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
    """登录封禁与注册限流，基于内存滑动窗口实现。"""

    def __init__(self, cfg: dict):
        abuse_cfg = cfg["abuse"]
        self.login_fails = abuse_cfg["login_fails"]
        self.login_ban_s = abuse_cfg["login_ban_s"]
        self.reg_per_hour = abuse_cfg["register_per_hour"]
        self._fail = {}
        self._reg = {}
        self._lock = __import__("threading").Lock()

    def login_blocked(self, ip: str) -> int:
        rec = self._fail.get(ip)
        if not rec:
            return 0
        with self._lock:
            left = rec[1] - time.time()
        return int(left) if left > 0 else 0

    def login_fail(self, ip: str):
        with self._lock:
            rec = self._fail.setdefault(ip, [0, 0])
            rec[0] += 1
            if rec[0] >= self.login_fails:
                rec[1] = time.time() + self.login_ban_s
                rec[0] = 0

    def login_ok(self, ip: str):
        with self._lock:
            self._fail.pop(ip, None)

    def reg_allowed(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            ts = [t for t in self._reg.get(ip, []) if now - t < 3600]
            if len(ts) >= self.reg_per_hour:
                return False
            ts.append(now)
            self._reg[ip] = ts
            return True

    def cleanup(self):
        now = time.time()
        with self._lock:
            for ip in list(self._fail):
                if now - self._fail[ip][1] > self.login_ban_s:
                    del self._fail[ip]
            for ip in list(self._reg):
                self._reg[ip] = [t for t in self._reg[ip] if now - t < 3600]
                if not self._reg[ip]:
                    del self._reg[ip]


def _token_from(request) -> str:
    """令牌来源：X-Admin-Token 请求头，或 Authorization: Bearer（供 Prometheus 等抓取工具使用）。"""
    got = request.headers.get("X-Admin-Token", "")
    if not got:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            got = auth[7:]
    return got


def _match_token(cfg, got: str):
    """按配置里的 admin_token / view_token 匹配，返回角色；都不对返回 None。
    恒定时间比较，防时序侧信道。"""
    server_cfg = cfg.get("server", {})
    admin = server_cfg.get("admin_token")
    if admin and hmac.compare_digest(got, admin):
        return "admin"
    view = server_cfg.get("view_token")
    if view and hmac.compare_digest(got, view):
        return "view"
    return None


def _require(request, need: str = "admin"):
    """认证 + 角色门槛：need=admin 只放管理员；need=view 只读 token 也行。"""
    guard = request.app["guard"]
    ip = _client_ip(request)
    left = guard.login_blocked(ip)
    if left:
        return json_err(f"封禁中，{left} 秒后再试", 429)
    role = _match_token(request.app["cfg"], _token_from(request))
    if role is None:
        guard.login_fail(ip)
        return json_err("token 不对", 401)
    if need == "admin" and role != "admin":
        return json_err("只读 token 不能执行该操作", 403)
    return None


def _require_admin(request):
    return _require(request, "admin")


# ---------- 工具 ----------

async def _gen_wg_key() -> tuple:
    priv = await net.cmd("wg", "genkey")
    pub = await net.cmd("wg", "pubkey", stdin=priv)
    return priv, pub


_server_ip_cache = {}


async def _server_ip(cfg) -> str:
    """公网地址：优先取配置 public_ip；否则探测 v4，不可用时再探测 v6（纯 v6 机器）。"""
    v = (cfg["network"] or {}).get("public_ip")
    if v:
        return v
    if _server_ip_cache.get("ip"):
        return _server_ip_cache["ip"]
    for url in ("https://ipv4.icanhazip.com", "https://ipv6.icanhazip.com"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "3", url,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await proc.communicate()
            ip = out.decode().strip()
            ipaddress.ip_address(ip)   # 地址非法时抛出异常
            _server_ip_cache["ip"] = ip
            return ip
        except Exception:
            continue
    return ""


def _user_view(user: dict, online: dict = None):
    used = user["used_up"] + user["used_down"]
    return {
        "id": user["id"],
        "name": user["name"],
        "internal_ip": user["internal_ip"],
        "internal_v4": net.internal_v4(user["id"]),
        "egress_ip": user["egress_ip"],
        "enabled": bool(user["enabled"]),
        "quota_mb": user["quota_mb"],
        "used_mb": round(used / 1048576, 1),
        "max_mbps": user["max_mbps"],
        "handshake": (online or {}).get(user["id"]) or 0,
        "created_at": user["created_at"],
    }


async def _new_user(cfg, name: str):
    """建用户（管理/注册共用）：key、uuid、/128、peer、代理、限速。"""
    with net.tx().shared():    # 与 CLI 互斥：避免与 `antipole user add` 并发执行
        uid = db.next_user_id()
        taken = {user["egress_ip"] for user in db.list_users()}
        seq = cfg["rotation"]["start_seq"]
        egress = net.pool().addr(seq)
        while egress in taken:
            seq += 1
            egress = net.pool().addr(seq)
        priv, pub = await _gen_wg_key()
        uuid = str(__import__("uuid").uuid4())
        db.add_user(name, net.internal_ip(uid), egress, seq, pub, priv, uuid,
                    cfg["abuse"]["default_quota_mb"],
                    cfg["abuse"].get("default_mbps", 0))
        await net.wg_add_peer(uid, pub)
        user = db.get_user(uid)
        if user["max_mbps"]:
            await net.tc_set_rate(uid, user["max_mbps"])
        return user


# ---------- 用户 ----------

async def create_user(request):
    if (err := _require_admin(request)):
        return err
    data = await request.json()
    name = (data.get("name") or "").strip()
    if not _NAME_RE.match(name or ""):
        return json_err("用户名只能字母数字._-，最长 32 位")
    if db.get_user_by_name(name):
        return json_err("用户名已存在")
    user = await _new_user(request.app["cfg"], name)
    await proxy.reload()
    return json_ok(_user_view(user, request.app["rot"].online))


async def list_users(request):
    if (err := _require(request, "view")):
        return err
    return json_ok([_user_view(user, request.app["rot"].online)
                    for user in db.list_users()])


async def get_user(request):
    if (err := _require(request, "view")):
        return err
    user = db.get_user(int(request.match_info["uid"]))
    if not user:
        return json_err("用户不存在", 404)
    return json_ok(_user_view(user, request.app["rot"].online))


async def update_user(request):
    if (err := _require_admin(request)):
        return err
    uid = int(request.match_info["uid"])
    user = db.get_user(uid)
    if not user:
        return json_err("用户不存在", 404)
    data = await request.json()
    msgs = []
    with net.tx().shared():    # 与 CLI 互斥：防止与 CLI 并发修改产生冲突
        if "enabled" in data:
            enable = bool(data["enabled"])
            db.update_user(uid, enabled=1 if enable else 0)
            if enable:
                await net.wg_add_peer(uid, user["pubkey"])
            else:
                await net.wg_del_peer(uid, user["pubkey"])
            msgs.append("已启用" if enable else "已禁用")
            await proxy.reload()

        if "quota_mb" in data:
            db.update_user(uid, quota_mb=max(0, int(data["quota_mb"] or 0)))
            msgs.append(f"配额 {data['quota_mb']}MB")

        if "max_mbps" in data:
            mbps = max(0, int(data["max_mbps"] or 0))
            db.update_user(uid, max_mbps=mbps)
            result = await net.tc_set_rate(uid, mbps)
            msgs.append(result)

        if data.get("reset_traffic"):
            db.update_user(uid, used_up=0, used_down=0)
            msgs.append("流量已清零")

        if data.get("rotate"):
            # 轮换仅修改内核路由（出站走 fwmark），xray 无需重载，连接不中断
            egress = await request.app["rot"].rotate_one(db.get_user(uid))
            msgs.append(f"已换 {egress}")

    return json_ok({"user": _user_view(db.get_user(uid), request.app["rot"].online),
                    "messages": msgs})


async def delete_user(request):
    if (err := _require_admin(request)):
        return err
    uid = int(request.match_info["uid"])
    user = db.get_user(uid)
    if not user:
        return json_err("用户不存在", 404)
    with net.tx().shared():    # 与 CLI 互斥
        await net.wg_del_peer(uid, user["pubkey"])
        await net.tc_set_rate(uid, 0)          # 移除限速 class
        db.delete_user(uid)
        request.app["rot"].online.pop(uid, None)
        await proxy.reload()
    return json_ok({"deleted": uid})


async def user_wg_config(request):
    if (err := _require_admin(request)):
        return err
    user = db.get_user(int(request.match_info["uid"]))
    if not user:
        return json_err("用户不存在", 404)
    cfg = request.app["cfg"]
    pub = await net.wg_server_pub()
    server_ip = await _server_ip(cfg)
    if not server_ip:
        return json_err("拿不到公网 IP，去 config.yaml 填 network.public_ip")
    v4 = net.internal_v4(user["id"])
    addr = f"Address = {user['internal_ip']}/128"
    if v4:
        addr += f"\nAddress = {v4}/32"
    allowed = "0.0.0.0/0, ::/0" if cfg["warp"]["enabled"] and v4 else "::/0"
    # DNS64 启用时将 DNS 指向隧道内 64:ff9b 合成器，使纯 v6 用户可访问 v4 站点
    dns = (cfg["dns64"]["dns_v6"] if cfg["dns64"].get("enabled", True)
           else "2001:4860:4860::8888, 1.1.1.1")
    conf = (
        "[Interface]\n"
        f"{addr}\n"
        f"PrivateKey = {user['privkey']}\n"
        f"DNS = {dns}\n"
        "\n[Peer]\n"
        f"PublicKey = {pub}\n"
        f"Endpoint = {server_ip}:{cfg['network']['wg_port']}\n"
        f"AllowedIPs = {allowed}\n"
        "PersistentKeepalive = 25\n"
    )
    return web.Response(text=conf, content_type="text/plain",
                        headers={"Content-Disposition":
                                 f'attachment; filename="wg-{user["name"]}.conf"'})


async def user_link(request):
    if (err := _require_admin(request)):
        return err
    user = db.get_user(int(request.match_info["uid"]))
    if not user:
        return json_err("用户不存在", 404)
    domain = db.primary_domain()
    return json_ok({"link": proxy.vless_link(user, domain),
                    "domain": domain["domain"] if domain else None})


# ---------- 接入域名 ----------

def _domain_view(domain: dict):
    return {"id": domain["id"], "domain": domain["domain"], "ip": domain["ip"],
            "port": domain["port"], "note": domain["note"], "enabled": bool(domain["enabled"])}


async def list_domains(request):
    if (err := _require(request, "view")):
        return err
    return json_ok([_domain_view(domain) for domain in db.list_domains()])


async def create_domain(request):
    if (err := _require_admin(request)):
        return err
    data = await request.json()
    domain = (data.get("domain") or "").strip()
    if not _DOMAIN_RE.match(domain or ""):
        return json_err("域名格式不对")
    ip = data.get("ip") or ""
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return json_err("IP 格式不对")
    did = db.add_domain(domain, ip, int(data.get("port") or 0),
                        (data.get("note") or "").strip()[:80])
    return json_ok(_domain_view(db.get_domain(did)))


async def update_domain(request):
    if (err := _require_admin(request)):
        return err
    did = int(request.match_info["did"])
    if not db.get_domain(did):
        return json_err("域名不存在", 404)
    data = await request.json()
    fields = {}
    if "domain" in data and data["domain"]:
        if not _DOMAIN_RE.match((data["domain"] or "").strip()):
            return json_err("域名格式不对")
        fields["domain"] = (data["domain"] or "").strip()
    if "ip" in data:
        v = (data["ip"] or "").strip()
        if v:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                return json_err("IP 格式不对")
        fields["ip"] = v
    if "port" in data:
        fields["port"] = max(0, int(data["port"] or 0))
    if "note" in data:
        fields["note"] = (data["note"] or "").strip()[:80]
    if "enabled" in data:
        fields["enabled"] = 1 if data["enabled"] else 0
    db.update_domain(did, **fields)
    return json_ok(_domain_view(db.get_domain(did)))


async def delete_domain(request):
    if (err := _require_admin(request)):
        return err
    did = int(request.match_info["did"])
    if not db.get_domain(did):
        return json_err("域名不存在", 404)
    db.delete_domain(did)
    return json_ok({"deleted": did})


# ---------- 邀请码 / 注册 ----------

async def create_invite(request):
    if (err := _require_admin(request)):
        return err
    code = secrets.token_urlsafe(12)
    conn = request.app["dbinv"]
    with conn:
        conn.execute("INSERT INTO invites(code, created_at, used) VALUES(?,?,0)",
                     (code, int(time.time())))
    return json_ok({"invite": code})


async def register(request):
    data = await request.json()
    name = (data.get("name") or "").strip()
    code = (data.get("invite") or "").strip()
    if not name or not code:
        return json_err("邀请码和用户名都要填")
    if not _NAME_RE.match(name):
        return json_err("用户名只能字母数字._-，最长 32 位")
    guard = request.app["guard"]
    ip = _client_ip(request)
    if not guard.reg_allowed(ip):
        return json_err("注册太勤了，一小时后再来", 429)
    conn = request.app["dbinv"]
    row = conn.execute("SELECT * FROM invites WHERE code=? AND used=0",
                     (code,)).fetchone()
    if not row:
        return json_err("邀请码无效或已用过", 403)
    if db.get_user_by_name(name):
        return json_err("用户名已存在")
    user = await _new_user(request.app["cfg"], name)
    with conn:
        conn.execute("UPDATE invites SET used=1, used_by=? WHERE code=?",
                     (name, code))
    await proxy.reload()
    domain = db.primary_domain()
    return json_ok({"name": name, "vless": proxy.vless_link(user, domain),
                    "domain": domain["domain"] if domain else None})


# ---------- 状态 ----------

async def status(request):
    if (err := _require(request, "view")):
        return err
    cfg = request.app["cfg"]
    free, total = _meminfo()
    peers = await net.wg_dump()
    online = sum(1 for i in peers.values()
                 if i["handshake"] and time.time() - i["handshake"] / 1e9 < 300)
    warp_on = await net.warp_is_up() if cfg["warp"]["enabled"] else False
    bgp = await net.bgp_status()
    d64 = await net.dns64_up()
    return json_ok({
        "mem_free_mb": round(free / 1048576, 1),
        "mem_total_mb": round(total / 1048576, 1),
        "users": len(db.list_users()),
        "online": online,
        "interval_s": cfg["rotation"].get("min_interval", 1800),
        "rotation_min_s": cfg["rotation"].get("min_interval", 1800),
        "rotation_max_s": cfg["rotation"].get("max_interval", 7200),
        "prefix": cfg["network"]["prefix"],
        "xray": proxy._waitpid(),
        "xray_port": cfg["xray"]["port"],
        "warp": warp_on,
        "warp_v4": await net.warp_v4() if warp_on else "",
        "dns64": d64,
        "bgp": bgp,
        "tc": cfg["network"].get("tc_enabled", True),
        "certs": await cert_status(),
    })


def _meminfo():
    try:
        data = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                data[k] = int(v.strip().split()[0])
        return data.get("MemAvailable", 0), data.get("MemTotal", 0)
    except OSError:
        return 0, 0


# ---------- 证书到期 ----------

async def _cert_days_left(crt: str):
    """openssl 读证书 notAfter，返回剩余天数；读不出返回 None。"""
    try:
        proc = await asyncio.create_subprocess_exec(
            "openssl", "x509", "-noout", "-enddate", "-in", crt,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), 10)
    except Exception:
        return None
    m = __import__("re").search(r"notAfter=(.*)", out.decode(errors="replace"))
    if not m:
        return None
    import datetime
    try:
        exp = datetime.datetime.strptime(
            m.group(1).strip().replace(" GMT", ""), "%b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return (exp - datetime.datetime.utcnow()).days


async def cert_status():
    """所有接入域名的证书剩余天数列表（状态接口用）。"""
    res = []
    for domain in db.list_domains():
        left = await _cert_days_left(domain["cert_crt"]) if domain.get("cert_crt") else None
        res.append({"domain": domain["domain"], "days_left": left})
    return res


async def cert_alert_loop(cfg):
    """每 6 小时检查证书剩余天数，临近到期时输出告警日志并可推送 webhook。"""
    alerts_cfg = cfg.get("alerts") or {}
    webhook = (alerts_cfg.get("webhook") or "").strip()
    warn_days = max(1, int(alerts_cfg.get("cert_days") or 14))
    alerted = {}          # domain -> 是否已告警
    while True:
        await asyncio.sleep(3600 * 6)
        try:
            for domain in db.list_domains():
                if not domain.get("cert_crt"):
                    continue
                left = await _cert_days_left(domain["cert_crt"])
                if left is None:
                    continue
                low = left <= warn_days
                if low and not alerted.get(domain["domain"]):
                    msg = (f"[cert] 证书 {domain['domain']} 还有 {left} 天到期"
                           f"（告警阈值 {warn_days} 天）")
                    print(msg)
                    if webhook:
                        try:
                            await _notify_webhook(webhook, "antipoleBGP 证书告警", msg)
                        except Exception as e:
                            print(f"[cert] webhook 通知失败: {e}")
                alerted[domain["domain"]] = low
        except Exception as e:
            print(f"[cert] 检查出错: {e}")


async def _notify_webhook(url: str, title: str, text: str):
    import aiohttp
    async with aiohttp.ClientSession() as s:
        await s.post(url, json={"title": title, "text": text},
                     timeout=aiohttp.ClientTimeout(total=10))


# ---------- 配额巡检 ----------

async def quota_loop(cfg, on_disable=None):
    """拉 xray counter -> 差值入库 -> 超配额自动禁用。
    间隔可配（abuse.quota_check_s，默认 10s）缩小超限窗口；
    超限时立即清理内核状态（peer 与 tc），终止用户流量。"""
    interval = max(5, int(cfg["abuse"].get("quota_check_s") or 10))
    warn_pct = int(cfg["abuse"].get("quota_warn_pct") or 90)
    warned = set()
    while True:
        try:
            cur = await proxy.fetch_stats()
            per_user = proxy.user_traffic(proxy.stats_diff(cur))
            changed = False
            for name, (up, down) in per_user.items():
                user = db.get_user_by_name(name)
                if not user:
                    continue
                db.add_traffic(user["id"], up, down)
                quota = user["quota_mb"]
                used = user["used_up"] + user["used_down"] + up + down
                if quota > 0 and user["enabled"]:
                    pct = used * 100.0 / (quota * 1048576)
                    if pct < warn_pct:
                        warned.discard(name)
                    elif name not in warned:
                        warned.add(name)
                        print(f"[abuse] {name} 已用 {pct:.0f}% 配额({quota}MB)")
                if quota > 0 and user["enabled"] and used > quota * 1048576:
                    with net.tx().shared():   # 与 CLI 互斥
                        db.update_user(user["id"], enabled=0)
                        try:
                            await net.wg_del_peer(user["id"], user["pubkey"])
                        except Exception:
                            pass
                        try:
                            await net.tc_set_rate(user["id"], 0)   # 移除限速 filter/class
                        except Exception:
                            pass
                    warned.discard(name)
                    changed = True
                    print(f"[abuse] {name} 超配额({quota}MB)，已自动禁用")
            if changed:
                await proxy.reload()
                if on_disable:
                    await on_disable()
        except Exception as e:
            print(f"[abuse] 巡检出错: {e}")
        await asyncio.sleep(interval)


# ---------- Metrics（Prometheus 文本格式） ----------

def _prom_label(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


async def metrics(request):
    """Prometheus 暴露端点：需要 admin 或 view token（X-Admin-Token / Bearer）。"""
    if (err := _require(request, "view")):
        return err
    cfg = request.app["cfg"]
    peers = await net.wg_dump()
    now = int(time.time())
    online = sum(1 for i in peers.values()
                 if i["handshake"] and now - i["handshake"] / 1e9 < 300)
    free, total = _meminfo()
    warp_on = await net.warp_is_up() if cfg["warp"]["enabled"] else False
    bgp = await net.bgp_status()
    users = db.list_users()
    lines = []
    lines.append("# HELP antipole_users_total 已注册用户数")
    lines.append("# TYPE antipole_users_total gauge")
    lines.append(f"antipole_users_total {len(users)}")
    lines.append("# HELP antipole_online_users 在线用户数（300s 内握手）")
    lines.append("# TYPE antipole_online_users gauge")
    lines.append(f"antipole_online_users {online}")
    lines.append("# HELP antipole_mem_available_bytes 可用内存")
    lines.append("# TYPE antipole_mem_available_bytes gauge")
    lines.append(f"antipole_mem_available_bytes {free * 1024}")
    lines.append("# HELP antipole_mem_total_bytes 总内存")
    lines.append("# TYPE antipole_mem_total_bytes gauge")
    lines.append(f"antipole_mem_total_bytes {total * 1024}")
    lines.append("# HELP antipole_xray_running Xray 进程是否在跑")
    lines.append("# TYPE antipole_xray_running gauge")
    lines.append(f"antipole_xray_running {1 if proxy._waitpid() else 0}")
    lines.append("# HELP antipole_warp_up WARP 接口是否在线")
    lines.append("# TYPE antipole_warp_up gauge")
    lines.append(f"antipole_warp_up {1 if warp_on else 0}")
    lines.append("# HELP antipole_bgp_alive BGP 守护进程是否存活")
    lines.append("# TYPE antipole_bgp_alive gauge")
    lines.append(f"antipole_bgp_alive {1 if bgp['alive'] else 0}")
    lines.append("# HELP antipole_tc_enabled tc 限速开关")
    lines.append("# TYPE antipole_tc_enabled gauge")
    lines.append(f"antipole_tc_enabled {1 if cfg['network'].get('tc_enabled', True) else 0}")
    lines.append("# HELP antipole_user_traffic_bytes 用户累计流量")
    lines.append("# TYPE antipole_user_traffic_bytes counter")
    lines.append("# HELP antipole_user_enabled 用户是否启用")
    lines.append("# TYPE antipole_user_enabled gauge")
    lines.append("# HELP antipole_user_quota_mb 用户配额 MB（0=不限）")
    lines.append("# TYPE antipole_user_quota_mb gauge")
    for user in users:
        name = _prom_label(user["name"])
        lines.append(f'antipole_user_traffic_bytes{{user="{name}",direction="up"}} {user["used_up"]}')
        lines.append(f'antipole_user_traffic_bytes{{user="{name}",direction="down"}} {user["used_down"]}')
        lines.append(f'antipole_user_enabled{{user="{name}"}} {1 if user["enabled"] else 0}')
        lines.append(f'antipole_user_quota_mb{{user="{name}"}} {user["quota_mb"]}')
    return web.Response(
        text="\n".join(lines) + "\n",
        headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"})


# ---------- 组装 ----------

def make_app(cfg, rot, conn, guard) -> web.Application:
    app = web.Application(client_max_size=64 * 1024)
    app["cfg"] = cfg
    app["rot"] = rot
    app["dbinv"] = conn
    app["guard"] = guard

    allow = cfg["server"].get("admin_allow") or []
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
    router.add_post("/api/users", create_user)
    router.add_get("/api/users", list_users)
    router.add_get("/api/users/{uid:\\d+}", get_user)
    router.add_patch("/api/users/{uid:\\d+}", update_user)
    router.add_delete("/api/users/{uid:\\d+}", delete_user)
    router.add_get("/api/users/{uid:\\d+}/wg", user_wg_config)
    router.add_get("/api/users/{uid:\\d+}/link", user_link)
    router.add_get("/api/domains", list_domains)
    router.add_post("/api/domains", create_domain)
    router.add_patch("/api/domains/{did:\\d+}", update_domain)
    router.add_delete("/api/domains/{did:\\d+}", delete_domain)
    router.add_post("/api/invites", create_invite)
    router.add_post("/api/register", register)
    return app