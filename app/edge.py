# -*- coding: utf-8 -*-
"""
接入边缘层（整合）：Xray 代理管理 + TCP 端口映射隧道 + 反滥用防护。

三部分职责：
  1. 反滥用：令牌桶限速、连接速率与并发上限、异常熔断、认证爆破封禁；
  2. 代理：Xray 子进程托管（SIGHUP 热载、崩溃自启）、配置生成、流量统计；
  3. 隧道：类 Cloudflare Tunnel 的多路复用端口映射，用户主机经单条出向连接
     将本地端口映射到服务器公网端口，端口一一对应、永久固定。

隧道为纯转发：主机不解析、不改写、不检查报文内容，只做长度上限保护，
I/O 以大块搬运为主，尽量避免每字节的额外开销。

隧道协议（单条 TCP 控制连接上复用）：
  文本命令（换行分隔）
    C→S  HELLO <token>             握手
    C→S  A <local_port> [local_ip] 声明端口映射
    C→S  PING / K                  保活 / 断开
    S→C  OK <ip6> / OKP <port> / PONG / ERRA / ERRP <port>
  二进制帧（首字节类型 + 4 字节连接号）
    S→C  N <cid><len><payload>     新公网连接（payload 含本地端口与地址）
    S→C  D <cid><len><payload>     下行数据
    C→S  U <cid><len><payload>     上行数据
    X <cid>                        连接关闭
转发路径为裸 Protocol：收到数据就地切帧并直接写入对端 transport，不排队、
不起任务、不 await；对端写不动时用 pause_reading 回压来源，内存占用有界。
"""
import asyncio
import base64
import errno as errno_mod
import json
import os
import re
import secrets
import shutil
import ssl
import struct
import tempfile
import threading
import time
from pathlib import Path

from . import core
from . import net
from .core import cmd, have_bin

CFG = None


def setup(cfg: dict):
    global CFG
    CFG = cfg


# ============================================================
# 一、反滥用
# ============================================================

class AbuseGuard:
    """反滥用总控：连接速率窗口、并发上限、熔断处置、事件记录。

    与业务解耦：隧道与代理仅需在关键点调用 note_conn / note_bytes /
    is_protected，由本类决定是否降速或拒绝。
    """

    def __init__(self, cfg: dict):
        abuse = cfg["abuse"]
        self.conn_rate = int(cfg["tunnel"].get("conn_rate_per_user", 120))
        self.conn_max = int(cfg["tunnel"].get("max_conns_per_user", 256))
        self.protect_mbps = int(abuse.get("protect_mbps", 1))
        self.protect_s = int(abuse.get("protect_s", 600))
        # 控制面爆破防护：按来源 IP 统计失败与新建连接
        self.auth_fails = int(abuse.get("auth_fails", 8))
        self.auth_window_s = int(abuse.get("auth_window_s", 300))
        self.auth_ban_s = int(abuse.get("auth_ban_s", 900))
        self.conn_burst = int(abuse.get("conn_burst_per_min", 60))
        self._window = {}          # uid -> [窗口起点, 计数]
        self._conns = {}           # uid -> 当前并发连接数
        self._ip_fail = {}         # ip -> [窗口起点, 失败次数]
        self._ip_conn = {}         # ip -> [窗口起点, 新建连接数]
        self._ip_ban = {}          # ip -> 解封时间戳（monotonic）
        self._lock = None          # 延迟到运行中的事件循环里创建（Py3.9 要求）

    def _lk(self) -> asyncio.Lock:
        """惰性创建锁：本类可能在事件循环启动前被实例化（如离线自检）。"""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    # ---- 连接计数 ----
    #
    # 只在事件循环线程内读写字典，天然串行，因此不加锁：转发路径必须全同步，
    # 任何 await 都会把开销摊到每个数据块上。

    def note_conn(self, uid: int) -> bool:
        """登记一次新建连接。超过速率或并发上限返回 False（调用方应拒绝）。

        conn_rate / conn_max 任一为 0 表示该项不限制（高并发场景可整体放开，
        异常流量仍由熔断与来源封禁兜底）。
        """
        cur = self._conns.get(uid, 0)
        if self.conn_max and cur >= self.conn_max:
            return False
        if self.conn_rate:
            now = time.monotonic()
            slot = self._window.get(uid)
            if slot is None or now - slot[0] >= 1.0:
                self._window[uid] = [now, 1]
            else:
                slot[1] += 1
                if slot[1] > self.conn_rate:
                    return False
        self._conns[uid] = cur + 1
        return True

    def drop_conn(self, uid: int):
        cur = self._conns.get(uid, 0)
        if cur > 1:
            self._conns[uid] = cur - 1
        else:
            self._conns.pop(uid, None)

    # ---- 控制面爆破防护（按来源 IP）----
    #
    # 以下三个方法只做纯字典读写、无 await，均在事件循环线程内执行，
    # 因此天然串行、无需加锁。

    def ip_banned(self, ip: str) -> int:
        """来源封禁剩余秒数，0 表示未封禁。"""
        left = self._ip_ban.get(ip, 0.0) - time.monotonic()
        return int(left) + 1 if left > 0 else 0

    def note_conn_ip(self, ip: str) -> bool:
        """登记一次控制连接建立；同源每分钟超过 conn_burst 次返回 False。"""
        if not self.conn_burst:
            return True
        now = time.monotonic()
        slot = self._ip_conn.get(ip)
        if slot is None or now - slot[0] >= 60:
            self._ip_conn[ip] = [now, 1]
            return True
        slot[1] += 1
        return slot[1] <= self.conn_burst

    def note_fail(self, ip: str) -> bool:
        """登记一次握手/令牌失败；窗口内达到阈值即封禁，返回是否刚被封禁。"""
        now = time.monotonic()
        slot = self._ip_fail.get(ip)
        if slot is None or now - slot[0] >= self.auth_window_s:
            self._ip_fail[ip] = [now, 1]
            return False
        slot[1] += 1
        if slot[1] < self.auth_fails:
            return False
        self._ip_fail.pop(ip, None)
        self._ip_ban[ip] = now + self.auth_ban_s
        return True

    # ---- 熔断 ----

    def is_protected(self, user: dict) -> bool:
        return int(user.get("protect_until") or 0) > core.now_ms()

    async def trip(self, uid: int, subject: str, reason: str):
        """触发熔断：限速到保护带宽 + 记录事件，保护期内不放开。"""
        until = core.now_ms() + self.protect_s * 1000
        core.update_user(uid, protect_until=until)
        core.update_tunnel_user(uid, max_mbps=self.protect_mbps)
        core.log_abuse("trip", subject, reason)
        print(f"[abuse] {subject} 触发熔断（{reason}），"
              f"限速至 {self.protect_mbps}Mbps，持续 {self.protect_s}s")
        try:
            from . import net
            await net.tc_set_rate(uid, self.protect_mbps)
        except Exception:
            pass

    async def sweep(self):
        """定期清理窗口计数、过期封禁与熔断（避免内存与状态残留）。"""
        now = time.monotonic()
        async with self._lk():
            for uid in list(self._window):
                if now - self._window[uid][0] >= 60:
                    self._window.pop(uid, None)
        for ip in list(self._ip_fail):
            if now - self._ip_fail[ip][0] >= self.auth_window_s:
                self._ip_fail.pop(ip, None)
        for ip in list(self._ip_conn):
            if now - self._ip_conn[ip][0] >= 60:
                self._ip_conn.pop(ip, None)
        for ip in list(self._ip_ban):
            if self._ip_ban[ip] <= now:
                self._ip_ban.pop(ip, None)
        for user in core.list_users():
            if user.get("protect_until") and user["protect_until"] <= core.now_ms():
                # 熔断到期必须把限速一并还原：只清 protect_until 的话，
                # 隧道用户的 max_mbps 会永远停在保护带宽上（曾把线上用户锁在 1Mbps）。
                core.update_user(user["id"], protect_until=0)
                await self.release(user)

    async def release(self, user: dict):
        """解除熔断：还原隧道限速与 tc 规则，并刷新在线会话的限速闸门。"""
        core.update_tunnel_user(user["id"], max_mbps=0)
        rate = (core.get_tunnel_user(user["id"]) or {}).get("user_max_mbps") or 0
        session = _session_of(user["id"])
        if session is not None:
            session.set_rate(rate)
        try:
            from . import net
            await net.tc_set_rate(user["id"], rate)
        except Exception:
            pass

    def banned_sources(self) -> dict:
        """当前被封禁的控制面来源（管理接口展示用）。"""
        now = time.monotonic()
        return {ip: int(until - now) + 1
                for ip, until in self._ip_ban.items() if until > now}


GUARD = None


def setup_guard(cfg: dict):
    global GUARD
    GUARD = AbuseGuard(cfg)


# ============================================================
# 二、Xray 代理管理
# ============================================================

_proc = None
_stop = False
_last_stats = {}
_stats_lock = threading.Lock()


def _x() -> dict:
    return CFG["xray"]


def _vless_listen() -> str:
    """VLESS 入站监听地址：优先 xray.listen（统一指定的固定 /128），
    留空回退本机主地址。

    不占用通配地址，隧道网段的 /128 才能把 80 等端口留给证书校验与用户映射
    （Reality 入站不处理明文 HTTP，通配监听会把 :80 全部吃掉）。
    """
    return (_x().get("listen") or "").strip() \
        or (CFG.get("_wan_v6") or "").strip() or "::"


async def ensure_listen_addr():
    """确保 VLESS 入站地址在机（/128 上 lo）：动态主地址随实例重建变化，
    BGP /48 内固定地址才是稳定接入点。幂等，服务每次启动都会执行。"""
    from . import net
    addr = (_x().get("listen") or "").strip()
    if not addr or addr == "::":
        return
    await net.ensure_local_v6(addr)


def _kp(name: str) -> Path:
    return Path(CFG["db"]["keys_dir"]) / name


async def ensure_keys():
    """x25519 与 shortId 密钥：未生成时创建，已存在时复用。"""
    keys_dir = _kp("")
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_f, pub_f, sid_f = _kp("x25519.priv"), _kp("x25519.pub"), _kp("shortid")
    if not (priv_f.exists() and pub_f.exists() and sid_f.exists()):
        out = await cmd(_x()["bin"], "x25519", timeout=20)
        priv = pub = ""
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("PrivateKey:") or stripped.startswith("Private key:"):
                priv = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Password (PublicKey):") \
                    or stripped.startswith("Public key:"):
                pub = stripped.split(":", 1)[1].strip()
        if not priv or not pub:
            raise RuntimeError("xray x25519 输出异常: " + out[:200])
        priv_f.write_text(priv)
        pub_f.write_text(pub)
        sid_f.write_text(secrets.token_hex(4))
        priv_f.chmod(0o600)
    return pub_f.read_text().strip(), sid_f.read_text().strip()


def build_config(users) -> dict:
    """生成 Xray 配置：每用户独立 freedom 出站（fwmark 走其路由表）+ WARP 分流 v4。"""
    from . import net
    xc = _x()
    warp_on = CFG["warp"]["enabled"]
    warp_mark = CFG["network"]["warp_mark"]
    pub, sid = _kp("x25519.pub").read_text().strip(), _kp("shortid").read_text().strip()
    sni = xc["sni_dest"]

    clients = [{"id": user["uuid"], "email": user["name"], "flow": "xtls-rprx-vision"}
               for user in users]
    vless_settings = {"clients": clients, "decryption": "none"}
    # Reality 流量不经过 fallbacks（非授权握手直接代理到 dest），生成它纯属
    # 多余特征；明文 HTTP 伪装由 main.py 的 mc 伪装站点在 80 端口承担
    if xc.get("dest_ip"):
        dip = xc["dest_ip"].strip()
        dest = f"[{dip}]:443" if ":" in dip and not dip.startswith("[") else f"{dip}:443"
    else:
        dest = f"{sni}:443"
    inbounds = [{
        "tag": "api", "listen": "127.0.0.1", "port": xc["api_port"],
        "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"},
    }, {
        "tag": "vless-in", "listen": _vless_listen(), "port": xc["port"],
        "protocol": "vless",
        "settings": vless_settings,
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {
                "dest": dest, "serverNames": [sni],
                "privateKey": _kp("x25519.priv").read_text().strip(),
                "shortIds": [sid],
            },
        },
    }]
    if xc["trojan"]["enabled"] and clients:
        pd = core.primary_domain()
        cert = pd["cert_crt"] if pd and pd["cert_crt"] else xc["trojan"]["cert"]
        key = pd["cert_key"] if pd and pd["cert_key"] else xc["trojan"]["key"]
        inbounds.append({
            "tag": "trojan-in", "listen": "::", "port": xc["trojan"]["port"],
            "protocol": "trojan",
            "settings": {"clients": [{"password": c["id"], "email": c["email"]}
                                     for c in clients]},
            "streamSettings": {
                "network": "tcp", "security": "tls",
                "tlsSettings": {"certificates": [
                    {"certificateFile": cert, "keyFile": key}]},
            },
        })

    warp4 = {"tag": "warp4", "protocol": "freedom",
             "settings": {"domainStrategy": "UseIPv4"}}
    if warp_on:
        warp4["streamSettings"] = {"sockopt": {"mark": warp_mark}}

    outbounds = [warp4]
    for user in users:
        outbounds.append(user_outbound(user))
    outbounds.append({"tag": "direct", "protocol": "freedom"})

    rules = [{"inboundTag": ["api"], "outboundTag": "api"}]
    sensitive = _sensitive_domains()
    for user in users:
        rules.extend(user_rules(user, sensitive))

    return {
        "log": {"loglevel": "warning"},
        "api": {"services": ["HandlerService", "RoutingService", "StatsService"],
                "tag": "api"},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True,
                                    "statsUserDownlink": True}},
                   "system": {"statsInboundUplink": True,
                              "statsInboundDownlink": True}},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }


def _sensitive_domains() -> list:
    return [("domain:" + d) for d in _x().get("sensitive_domains") or []]


def user_outbound(user) -> dict:
    """单用户独立出站：按用户 mark 走其策略路由表（决定出口地址）。"""
    return {"tag": f"user-{user['id']}", "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv6"},
            "streamSettings": {"sockopt": {"mark": net.user_mark(user["id"])}}}


def _rule_tags(user) -> list:
    return [f"u{user['id']}-sen", f"u{user['id']}-v4", f"u{user['id']}-out"]


def user_rules(user, sensitive: list) -> list:
    """用户分流规则：敏感域名走自有出口 → IPv4 借道 WARP → 其余走自有出口。

    带 ruleTag，便于通过 Xray API 动态删除（增删用户无需重启 xray）。
    """
    rules = []
    if sensitive:
        rules.append({"ruleTag": f"u{user['id']}-sen", "type": "field",
                      "user": [user["name"]], "domain": sensitive,
                      "outboundTag": f"user-{user['id']}"})
    rules.append({"ruleTag": f"u{user['id']}-v4", "type": "field",
                  "user": [user["name"]], "ip": ["0.0.0.0/0"],
                  "outboundTag": "warp4"})
    rules.append({"ruleTag": f"u{user['id']}-out", "type": "field",
                  "user": [user["name"]],
                  "outboundTag": f"user-{user['id']}"})
    return rules


# ---------- Xray 动态用户管理（HandlerService API） ----------
# 增删单个用户只需改运行中的 xray 实例，不再 SIGHUP 重启（避免已有连接被中断）。
# API 不可用时由调用方回退到整体热载。

_api_lock = None            # 延迟创建：模块导入早于事件循环，Py3.9 下不能提前绑定


def _api_lk() -> asyncio.Lock:
    """xray api 串行锁（惰性创建，避免绑定到已废弃的事件循环）。"""
    global _api_lock
    if _api_lock is None:
        _api_lock = asyncio.Lock()
    return _api_lock


async def _api_call(sub: str, payload: dict = None, extra: tuple = ()) -> bool:
    """调用一次 xray api 子命令；payload 以临时 JSON 文件传入。成功返回 True。"""
    args = [_x()["bin"], "api", sub,
            f"--server=127.0.0.1:{_x()['api_port']}", *extra]
    path = ""
    if payload is not None:
        fd, path = tempfile.mkstemp(suffix=".json", dir="/tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        args.append(path)
    try:
        async with _api_lk():
            await cmd(*args, timeout=20)
        return True
    except Exception as e:
        print(f"[edge] xray api {sub} 调用失败: {e}")
        return False
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _dynamic_inbound(user, port: int) -> dict:
    """构造 API 用的最小 VLESS 入站定义（只需 tag/协议/端口与目标账号）。"""
    return {
        "tag": "vless-in", "protocol": "vless", "listen": "::", "port": port,
        "settings": {"decryption": "none", "clients": [{
            "id": user["uuid"], "email": user["name"],
            "flow": "xtls-rprx-vision"}]},
        "streamSettings": {"network": "tcp", "security": "none"},
    }


async def xray_user_add(user) -> bool:
    """动态加入用户：出站 + 路由规则 + VLESS 账号（幂等，先清同名再添加）。"""
    if not CFG["xray"]["enabled"] or not xray_running():
        return False
    if _x()["trojan"]["enabled"]:
        return False          # 同时启用 trojan 时涉及两种入站，交给整体热载
    uid = user["id"]
    await _api_call("rmo", None, (f"user-{uid}",))
    ok = await _api_call("ado", {"outbounds": [user_outbound(user)]})
    await _api_call("rmrules", None, tuple(_rule_tags(user)))
    ok = await _api_call("adrules",
                         {"routing": {"rules": user_rules(user, _sensitive_domains())}},
                         ("--append",)) and ok
    await _api_call("rmu", None, ("-tag=vless-in", user["name"]))
    ok = await _api_call("adu", {"inbounds": [
        _dynamic_inbound(user, _x()["port"])]}) and ok
    return ok


async def xray_user_del(user) -> bool:
    """动态移除用户：VLESS 账号 + 路由规则 + 出站。"""
    if not CFG["xray"]["enabled"] or not xray_running():
        return False
    named = [await _api_call("rmu", None, ("-tag=vless-in", user["name"]))]
    named.append(await _api_call("rmrules", None, tuple(_rule_tags(user))))
    named.append(await _api_call("rmo", None, (f"user-{user['id']}",)))
    return all(named)


async def sync_user(user, present: bool):
    """用户启停/增删的统一入口：优先动态生效，失败回退整体热载。"""
    ok = await (xray_user_add(user) if present else xray_user_del(user))
    if not ok:
        print("[edge] 动态应用失败，回退整体热载")
        await reload()


def _xray_pid():
    """查找运行中的 xray 进程 pid（SIGHUP 触发 re-exec，需按 pid 追踪）。"""
    import subprocess
    try:
        out = subprocess.check_output(["pgrep", "-f", "xray run -config"],
                                      stderr=subprocess.DEVNULL).decode().split()
    except Exception:
        return None
    me = str(os.getpid())
    for pid_str in out:
        if pid_str == me:
            continue
        try:
            with open(f"/proc/{pid_str}/cmdline", "rb") as handle:
                if b"xray" in handle.read():
                    return int(pid_str)
        except OSError:
            continue
    return None


def xray_running() -> bool:
    return _xray_pid() is not None


async def reload():
    """写入配置并 SIGHUP 热载；进程不存在则拉起。

    Reality 密钥不可用时（未安装 Xray 或首次运行）安全跳过，
    避免调用方（如用户删除流程）因代理不可用而失败。
    """
    if not CFG["xray"]["enabled"]:
        return
    try:
        await ensure_keys()
    except Exception as e:
        print(f"[edge] Reality 密钥不可用，跳过配置热载: {e}")
        return
    conf = _x()["conf"]
    Path(conf).parent.mkdir(parents=True, exist_ok=True)
    users = core.list_enabled_users()
    Path(conf).write_text(json.dumps(build_config(users), indent=2,
                                     ensure_ascii=False))
    pid = _xray_pid()
    if pid is not None:
        try:
            os.kill(pid, __import__("signal").SIGHUP)
            await asyncio.sleep(1.2)
            return
        except ProcessLookupError:
            pass
    await spawn()


async def spawn():
    """启动 xray 子进程（死亡继承：主进程终止后自动退出，避免孤儿占用端口）。"""
    global _stop
    if xray_running():
        return
    if not Path(_x()["bin"]).exists():
        print("[edge] xray 二进制不存在，跳过")
        return
    from . import net
    _stop = False
    proc = await asyncio.create_subprocess_exec(
        _x()["bin"], "run", "-config", _x()["conf"],
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        preexec_fn=net._child_preexec(os.getpid()))
    _spawn_bg(_supervise(proc))


async def _supervise(proc):
    """子进程退出处理：正常停止忽略；re-exec 由新进程接管；崩溃则重启。"""
    try:
        await proc.wait()
    except Exception:
        pass
    if _stop or proc.returncode == 0:
        return
    await asyncio.sleep(2)
    if xray_running():
        return
    print(f"[edge] xray 异常退出 (code={proc.returncode})，2 秒后重启")
    await asyncio.sleep(2)
    if not _stop:
        await spawn()


def stop():
    global _stop
    _stop = True
    pid = _xray_pid()
    if pid is not None:
        try:
            os.kill(pid, __import__("signal").SIGTERM)
        except ProcessLookupError:
            pass


async def fetch_stats() -> dict:
    if not CFG["xray"]["enabled"] or not xray_running():
        return {}
    try:
        out = await cmd(_x()["bin"], "api", "statsquery",
                        f"--server=127.0.0.1:{_x()['api_port']}", check=False)
        data = json.loads(out or "{}")
        return {stat["name"]: int(stat.get("value", 0))
                for stat in data.get("stat", [])}
    except Exception:
        return {}


def stats_diff(current: dict) -> dict:
    """与上次快照求差。空结果不更新快照（xray 停摆恢复后不重复计数）。"""
    with _stats_lock:
        if not current:
            return {}
        diff = {}
        for key, value in current.items():
            if ">>>" not in key:
                continue
            delta = value - _last_stats.get(key, 0)
            if delta > 0:
                diff[key] = delta
        _last_stats.clear()
        _last_stats.update(current)
        return diff


def user_traffic(diff: dict) -> dict:
    """统计差值 -> {用户名: (上行, 下行)}。"""
    res = {}
    for key, value in diff.items():
        parts = key.split(">>>")
        if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
            name, direction = parts[1], parts[3]
            up, down = res.get(name, (0, 0))
            res[name] = (up + value, down) if direction == "uplink" else (up, down + value)
    return res


def vless_link(user: dict, domain=None) -> str:
    """分享链接接入地址优先级：
    xray.announce（自填域名，AAAA 指向 listen 地址）> xray.listen（固定 /128）
    > 接入域名表 > 公网 IP。客户端实际连接的仍是同一入站（listen 地址），域名
    只是别名，因此换域名不需要改任何监听。"""
    xc = _x()
    announce = (xc.get("announce") or "").strip()
    fixed = (xc.get("listen") or "").strip()
    if announce:
        host, port = announce, xc["port"]
    elif fixed and fixed != "::":
        host, port = f"[{fixed}]", xc["port"]
    elif domain:
        host, port = domain["domain"], domain["port"] or xc["port"]
    else:
        host = (CFG["server"].get("public_ip")
                or CFG["network"].get("public_ip") or "SERVER_IP")
        port = xc["port"]
    pub = _kp("x25519.pub").read_text().strip()
    sid = _kp("shortid").read_text().strip()
    query = (f"encryption=none&flow=xtls-rprx-vision&security=reality"
             f"&sni={xc['sni_dest']}&fp={xc['ufp']}&pbk={pub}&sid={sid}&type=tcp")
    return f"vless://{user['uuid']}@{host}:{port}?{query}#{user['name']}"


# ============================================================
# 三、TCP 端口映射隧道
# ============================================================

_sessions = {}          # token -> TunnelSession
# uid -> [TunnelSession, ...]：按用户索引，避免公网上每条新连接都线性扫描全部会话
_sessions_by_uid = {}
_listeners = {}         # (uid, port) -> PublicListener
# 僵尸会话顶替阈值（秒）：旧会话连续这么久没有任何保活/流量即视为已死
# （客户端默认 15s 一发 PING，90s = 连丢 6 个周期），允许新连接直接顶替。
# 客户端崩溃、切网或 NAT 表项被静默回收时 TCP 未必立刻报错，若不顶替，
# 用户会被一条"看着还在"的死会话锁在门外最长 idle_timeout×2。
_TAKEOVER_AFTER_S = 90
_tls_ctx = None
_srv = None
# 转发粒度：大块搬运可把每字节的 Python 开销摊薄一个数量级（1 核机器上收益最明显）。
# 仅做长度上限保护，不解析、不检查内容——主机只负责转发。
_DOWN_CHUNK = 262144             # 写缓冲高水位（超过即暂停来源读取形成背压）
_FRAME_MAX = 1048576             # 单帧载荷上限（远大于搬运粒度，留出余量）
_BULK_RATE = 768 * 1024          # 突发判定：250ms 滑窗内平均速率超过该值即视为大流量
_cert_busy = set()               # 正在申请证书的用户 id（避免重复触发 ACME 限流）
_bg_tasks = set()                # 后台任务强引用（asyncio 只持弱引用，需自行保活）


def _spawn_bg(coro):
    """登记后台任务，避免执行中被垃圾回收，异常也不静默丢失。"""
    task = asyncio.ensure_future(coro)
    _bg_tasks.add(task)

    def _done(t):
        _bg_tasks.discard(t)
        if t.cancelled():
            return
        exc = t.exception()
        if exc:
            print(f"[edge] 后台任务异常: {exc!r}")

    task.add_done_callback(_done)
    return task


def _tun() -> dict:
    return CFG["tunnel"]


def tunnel_enabled() -> bool:
    return bool(_tun().get("enabled", False))


def _pace(proto, n: int):
    """突发大流量下的聚批读取：短暂停读，让内核把数据攒成大块再交付一次。

    本机实测每次读事件的固定开销约 60~80µs（与块大小几乎无关，主要在内核与
    事件循环的 C 层），把 5KB 的读攒成 30KB 就能省下一个数量级的 CPU。突发判定
    用 250ms 滑窗速率，普通网页/SSH 这类小流量永远低于阈值，不会被停读，
    因此只有大流量才会多出这点流水线延迟（对吞吐无影响）。
    """
    session = proto.session
    # 握手完成前还没有会话（例如刚建立的连接只发了 HELLO），此时不参与聚批
    if not n or session is None or proto.pace_timer is not None \
            or not session.pace_s:
        return
    if not session.note_rate(n):
        return
    try:
        proto.transport.pause_reading()
    except Exception:
        return
    proto.pace_timer = asyncio.get_running_loop().call_later(
        session.pace_s, _pace_done, proto)


def _pace_done(proto):
    proto.pace_timer = None
    try:
        proto.transport.resume_reading()
    except Exception:
        pass


# ---------- 数据面中继（Go 进程，只搬字节） ----------
#
# 控制面（鉴权、映射决策、防火墙、计费）留在本进程；数据面交给亲和的编译语言进程：
# 每条公网连接与用户客户端的回连在 Go 里用 splice 直连搬运，Python 不再逐字节过手。

_RELAY = None
_relay_maps = {}          # (uid, port) -> True，表示该映射由中继进程承载


def _relay_ready() -> bool:
    return _RELAY is not None and _RELAY.ready


async def _start_mapping(session, local_port: int, local_ip: str):
    """建立映射监听：直连会话交给中继进程，其余用本进程的监听器。

    返回 (是否成功, 失败原因)；直接交给中继时不需要在本地保存监听器。
    """
    listen_addr = (_tun().get("bind") or "").strip() or session.ip6
    if session.direct and _relay_ready():
        reply = await _RELAY.cmd("listen", uid=session.uid, port=local_port,
                                 bind=listen_addr, rate=session.rate_bytes)
        print(f"[relay] {session.name} 端口 {local_port} 数据面监听"
              f"{'成功' if reply.get('ok') else '失败：' + str(reply.get('err'))}")
        if reply.get("ok"):
            _relay_maps[(session.uid, local_port)] = session
            return True, ""
        return False, f"数据面监听失败：{reply.get('err') or '未知原因'}"
    listener = PublicListener(session, listen_addr, local_port)
    ok, reason = await listener.start()
    if ok:
        # 端口号与用户本地端口一致，需在系统防火墙上放行，公网方可直达用户主机
        _listeners[(session.uid, local_port)] = listener
    return ok, reason


class RelayLink:
    """与数据面中继进程的本地 IPC：命令下行、事件上行（换行分隔 JSON）。"""

    def __init__(self, cfg):
        tun = cfg["tunnel"]
        self.proc = None
        self.server = None
        self.sock_path = (tun.get("relay_sock")
                          or "/run/antipole-relay.sock").strip()
        self.reader = None
        self.writer = None
        self.ready = False
        self._seq = 0
        self._waiters = {}       # id -> Future（命令回执）
        self._task = None

    async def start(self):
        self._task = _spawn_bg(self._serve())

    async def _serve(self):
        """先建本地 IPC 服务端（中继进程作为客户端重连），再拉起并守护它。"""
        try:
            Path(self.sock_path).unlink(missing_ok=True)
        except OSError:
            pass
        try:
            self.server = await asyncio.start_unix_server(self._on_link,
                                                          path=self.sock_path)
            os.chmod(self.sock_path, 0o600)
        except OSError as e:
            print(f"[relay] IPC 地址不可用：{e}")
            return
        _spawn_bg(self._keep_proc())
        print(f"[relay] 等待数据面接入 {self.sock_path}")

    async def _keep_proc(self):
        """守护中继进程：退出即重新拉起，不影响控制面。"""
        binary = (_tun().get("relay_bin") or "").strip()
        if binary and not os.path.isabs(binary):
            binary = str(Path(__file__).resolve().parent.parent / binary)
        # 块大小埋点（tunnel.relay_stat_file，留空关闭）：文件按行追加统计
        stat_file = (_tun().get("relay_stat_file") or "").strip()
        if stat_file and not os.path.isabs(stat_file):
            stat_file = str(Path(__file__).resolve().parent.parent / stat_file)
        if stat_file:
            try:
                Path(stat_file).parent.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                print(f"[relay] 埋点文件目录不可用，已关闭统计：{e}")
                stat_file = ""
        # 崩溃诊断：数据面 stdout/stderr 落盘（超 1MB 滚动一份 .1），
        # 否则 Go 的 panic 栈会被 DEVNULL 吞掉，出问题无从查起
        relay_log = None
        try:
            log_path = Path(__file__).resolve().parent.parent / "logs" / "relay.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            if log_path.exists() and log_path.stat().st_size > (1 << 20):
                log_path.replace(log_path.with_name("relay.log.1"))
            relay_log = open(log_path, "ab", buffering=0)
        except OSError as e:
            print(f"[relay] 崩溃日志不可写，已回退丢弃：{e}")
        while True:
            if self.proc is None or self.proc.returncode is not None:
                if self.proc is not None:
                    print(f"[relay] 数据面进程已退出（code={self.proc.returncode}），重新拉起")
                argv = [binary, "-sock", self.sock_path,
                        "-relay-port", str(int(_tun().get("relay_port", 18282))),
                        "-bulk-pause-ms", str(int(_tun().get("bulk_pause_ms", 4))),
                        "-relay-bind", ",".join(await tunnel_listen_addrs())]
                # 数据面与控制面同样启用 TLS 包裹（默认加密），复用同一张证书
                cert = (_tun().get("cert") or "").strip()
                key = (_tun().get("key") or "").strip()
                if cert and key:
                    argv += ["-cert", cert, "-key", key]
                if stat_file:
                    argv += ["-stat-file", stat_file]
                try:
                    self.proc = await asyncio.create_subprocess_exec(
                        *argv,
                        stdout=relay_log if relay_log else asyncio.subprocess.DEVNULL,
                        stderr=relay_log if relay_log else asyncio.subprocess.DEVNULL)
                except Exception as e:
                    print(f"[relay] 拉起数据面进程失败：{e}")
            await asyncio.sleep(3)

    async def _restore_mappings(self):
        """数据面（重）接入后，把仍在线的中继映射重新下发。

        Go 进程崩溃重启会丢掉全部监听；不补这一步，公网端口会一直哑着，
        直到用户重连。这里按登记表原样重建，用户无感。
        """
        restored = 0
        for (uid, port), session in list(_relay_maps.items()):
            if _session_of(uid) is not session:
                continue
            bind = (_tun().get("bind") or "").strip() or session.ip6
            reply = await self.cmd("listen", uid=uid, port=port, bind=bind,
                                   rate=session.rate_bytes)
            if reply.get("ok"):
                restored += 1
        if restored:
            print(f"[relay] 数据面重启后已恢复 {restored} 个端口映射")

    async def _on_link(self, reader, writer):
        """中继进程接入：接管这条 IPC 直到断开。"""
        if self.ready:
            writer.close()
            return
        self.reader, self.writer, self.ready = reader, writer, True
        print("[relay] 数据面已就绪")
        _spawn_bg(self._restore_mappings())
        try:
            await self._read_loop()
        except (ConnectionError, OSError) as e:
            print(f"[relay] 数据面连接中断：{e}")
        finally:
            self.ready = False
            self.reader = self.writer = None
            for fut in list(self._waiters.values()):
                if not fut.done():
                    fut.cancel()
            self._waiters.clear()
            try:
                writer.close()
            except Exception:
                pass

    async def _read_loop(self):
        while True:
            line = await self.reader.readline()
            if not line:
                return
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            event = msg.get("ev")
            if event == "conn":
                await self._on_conn(msg)
            elif event == "done":
                self._on_done(msg)
            elif event == "err":
                print(f"[relay] {msg.get('why')}")
            else:
                fut = self._waiters.pop(msg.get("id"), None)
                if fut is not None and not fut.done():
                    fut.set_result(msg)

    async def cmd(self, action: str, timeout: float = 8.0, **kw) -> dict:
        """下发一条命令并等待回执；中继不在线时直接失败。"""
        writer = self.writer
        if writer is None:
            return {"ok": False, "err": "数据面未连接"}
        self._seq += 1
        rid = self._seq
        payload = dict(kw, cmd=action, id=rid)
        fut = asyncio.get_running_loop().create_future()
        self._waiters[rid] = fut
        try:
            writer.write((json.dumps(payload) + "\n").encode())
            await writer.drain()
            return await asyncio.wait_for(fut, timeout)
        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            return {"ok": False, "err": str(e)[:80]}
        finally:
            self._waiters.pop(rid, None)

    async def _reply(self, payload: dict):
        writer = self.writer
        if writer is None:
            return
        try:
            writer.write((json.dumps(payload) + "\n").encode())
            await writer.drain()
        except (ConnectionError, OSError):
            pass

    async def _on_conn(self, msg: dict):
        """公网连接到达：并发/配额把关后发一次性回连凭据给客户端。"""
        uid = int(msg.get("uid", 0))
        port = int(msg.get("port", 0))
        cid = msg.get("id")
        session = _session_of(uid)
        if session is None or session.closed:
            await self._reply({"cmd": "reject", "id": cid, "why": "会话不在线"})
            return
        if GUARD is not None and not GUARD.note_conn(uid):
            core.log_abuse("conn_rate", session.name, f"端口 {port} 连接过频")
            _spawn_bg(session._trip_if_abusive("新建连接速率超限"))
            await self._reply({"cmd": "reject", "id": cid, "why": "连接过频"})
            return
        quota = session.user["quota_mb"] or session.user["user_quota_mb"] or 0
        if quota > 0 and session.used >= quota * 1048576:
            await self._reply({"cmd": "reject", "id": cid, "why": "已超配额"})
            return
        nonce = secrets.token_hex(8)
        local_ip = session.remotes.get(port, "127.0.0.1")
        session.send_line(f"R {nonce} {port} {local_ip}")
        await self._reply({"cmd": "accept", "id": cid, "nonce": nonce})

    def _on_done(self, msg: dict):
        """一条管道结束：按字节数记账并释放并发计数。"""
        uid = int(msg.get("uid", 0))
        n = int(msg.get("up", 0)) + int(msg.get("down", 0))
        if GUARD is not None:
            GUARD.drop_conn(uid)
        core.buffer_tunnel_bytes(uid, n)
        session = _session_of(uid)
        if session is not None:
            session.used += n
            session._last_active = time.monotonic()


def _session_of(uid: int):
    live = _sessions_by_uid.get(uid)
    return live[0] if live else None


class Gate:
    """同步令牌桶：转发路径不能 await，超额时由调用方暂停来源读取、定时恢复。"""

    __slots__ = ("rate", "_allow", "_ts", "_timer", "_loop", "_resume")

    def __init__(self, rate: int, loop, resume):
        self.rate = rate
        self._allow = float(rate)
        self._ts = time.monotonic()
        self._timer = None
        self._loop = loop
        self._resume = resume

    def take(self, n: int) -> bool:
        """记一次用量；返回 False 表示超额，调用方应暂停来源读取。"""
        if self._timer is not None:
            return False                      # 恢复定时器未触发前持续背压
        now = time.monotonic()
        self._allow = min(self.rate * 1.5,
                          self._allow + (now - self._ts) * self.rate)
        self._ts = now
        self._allow -= n
        if self._allow < 0:
            self._timer = self._loop.call_later(-self._allow / self.rate, self._wake)
            return False
        return True

    def _wake(self):
        self._timer = None
        self._allow = 0.0
        self._resume()

    def release(self):
        """会话结束：取消待触发的恢复回调，避免打到已关闭的连接上。"""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None


class TunnelSession:
    """一个隧道用户的控制会话：映射、公网连接、限速与背压。

    转发路径全同步：收到数据直接写对端 transport，不建队列、不起任务、不 await。
    背压交给 transport 的水位回调（pause_writing）与 pause_reading，内存占用有界。
    """

    __slots__ = ("user", "uid", "name", "token", "ip6", "transport", "maps",
                 "remotes", "conns", "_cid", "gate", "closed", "used",
                 "_last_active", "_idle_task", "declaring", "pace_s",
                 "_win_ts", "_win_bytes", "_bulk", "direct", "rate_bytes")

    def __init__(self, user, transport, direct: bool = False):
        self.user = user
        self.uid = user["user_id"]
        self.direct = direct          # 客户端支持回连：数据面走 Go 中继进程
        self.name = user["user_name"]
        self.token = user["token"]
        self.transport = transport
        self.ip6 = user["egress_ip"]
        self.maps = {}          # remote_port -> local_port
        self.remotes = {}       # remote_port -> local_ip
        self.conns = {}         # cid -> PublicProtocol
        self.declaring = set()  # 正在声明的端口，避免并发重复绑定
        self._cid = 0
        rate = (user["max_mbps"] or user["user_max_mbps"] or 0)
        self.rate_bytes = rate * 1024 * 1024 // 8
        self.gate = (Gate(self.rate_bytes,
                          asyncio.get_running_loop(), self.resume_sources)
                     if rate else None)
        self.closed = False
        self.used = user["used_bytes"]
        self._last_active = time.monotonic()
        self._idle_task = None
        self.pace_s = max(0.0, float(_tun().get("bulk_pause_ms", 4)) / 1000.0)
        self._win_ts = self._last_active
        self._win_bytes = 0
        self._bulk = False

    def note_rate(self, n: int) -> bool:
        """250ms 滑窗速率判定：返回是否处于突发大流量（用于聚批读取）。"""
        now = time.monotonic()
        span = now - self._win_ts
        if span >= 0.25:
            self._bulk = self._win_bytes / span >= _BULK_RATE
            self._win_bytes = 0
            self._win_ts = now
        self._win_bytes += n
        return self._bulk

    def set_rate(self, mbps: int):
        """重设该会话的限速（熔断到期恢复限速时调用），立即生效。"""
        rate = int(mbps or 0) * 1024 * 1024 // 8
        self.rate_bytes = rate
        if self.direct and _relay_ready():
            _spawn_bg(_RELAY.cmd("update", uid=self.uid, rate=rate))
        if self.gate is not None:
            self.gate.release()
            self.gate = None
        if rate:
            self.gate = Gate(rate, asyncio.get_running_loop(), self.resume_sources)
        self.resume_sources()

    # ---- 发送（同步写 transport，无队列无 drain） ----

    def send_line(self, line: str):
        if self.closed:
            return
        try:
            self.transport.write(line.encode() + b"\n")
        except Exception:
            pass

    def send_frame(self, kind: bytes, cid: int, payload: bytes = b"") -> bool:
        if self.closed:
            return False
        try:
            self.transport.write(kind + struct.pack("!II", cid, len(payload))
                                 + payload)
            return True
        except Exception:
            return False

    # ---- 背压与限速 ----

    def pause_sources(self):
        """对端写得慢：暂停来源读取，把压力交回发送方（TCP 窗口自然限流）。"""
        if self.closed:
            return
        try:
            self.transport.pause_reading()
        except Exception:
            pass
        for conn in self.conns.values():
            conn.pause()

    def resume_sources(self):
        if self.closed:
            return
        try:
            self.transport.resume_reading()
        except Exception:
            pass
        for conn in self.conns.values():
            conn.resume()

    # ---- 双向转发 ----

    def deliver_up(self, cid: int, payload: bytes):
        """隧道 -> 公网：客户端送来的数据写进对应公网连接。"""
        conn = self.conns.get(cid)
        if conn is None or conn.closed:
            return
        n = len(payload)
        now = time.monotonic()
        self.used += n
        self._last_active = now
        conn.last_active = now
        core.buffer_tunnel_bytes(self.uid, n)
        transport = conn.transport
        if transport is None:
            return
        try:
            transport.write(payload)
        except Exception:
            self.drop_conn(cid)
            return
        if self.gate is not None and not self.gate.take(n):
            self.pause_sources()

    def deliver_down(self, conn, data: bytes):
        """公网 -> 隧道：公网数据封装成 D 帧写进控制连接。"""
        if self.closed or conn.closed:
            return
        n = len(data)
        self._last_active = time.monotonic()
        conn.last_active = self._last_active
        self.used += n
        core.buffer_tunnel_bytes(self.uid, n)
        try:
            self.transport.write(b"D" + struct.pack("!II", conn.cid, n) + data)
        except Exception:
            return
        if self.gate is not None and not self.gate.take(n):
            self.pause_sources()

    # ---- 公网连接 ----

    def adopt(self, conn) -> bool:
        """公网连接建立：并发/速率/配额把关后分配连接号并通知客户端。"""
        if self.closed:
            return False
        if GUARD is not None and not GUARD.note_conn(self.uid):
            core.log_abuse("conn_rate", self.name, f"端口 {conn.remote_port} 连接过频")
            _spawn_bg(self._trip_if_abusive("新建连接速率超限"))
            return False
        quota = self.user["quota_mb"] or self.user["user_quota_mb"] or 0
        if quota > 0 and self.used >= quota * 1048576:
            return False
        self._cid += 1
        cid = self._cid
        conn.cid = cid
        self.conns[cid] = conn
        payload = struct.pack("!H", conn.local_port) + conn.local_ip.encode()
        if not self.send_frame(b"N", cid, payload):
            self.conns.pop(cid, None)
            return False
        return True

    def drop_conn(self, cid: int):
        conn = self.conns.pop(cid, None)
        if conn is None:
            return
        conn.close()
        self.send_frame(b"X", cid)
        if GUARD is not None:
            GUARD.drop_conn(self.uid)

    # ---- 空闲看护 ----

    def start_idle(self):
        self._idle_task = asyncio.create_task(self._idle_watchdog())

    async def _idle_watchdog(self):
        """空闲看护：按时间戳回收空闲连接，定时器开销从每帧一次降到每 30s 一次。"""
        idle = int(_tun().get("idle_timeout", 300))
        span = min(30, max(5, idle // 4))
        while not self.closed:
            await asyncio.sleep(span)
            if self.closed:
                return
            now = time.monotonic()
            if now - self._last_active > idle * 2:
                await self.close()
                return
            for conn in list(self.conns.values()):
                if now - conn.last_active > idle:
                    self.drop_conn(conn.cid)

    # ---- 一键申请 HTTPS 证书 ----

    async def request_cert(self, domain: str):
        """按用户请求签发证书（HTTP-01），完成后回传证书与私钥。

        域名必须解析到该用户的静态地址。校验文件由 Xray 的 :80 回落链转发到本机
        校验目录服务，因此不需要额外占用任何公网端口，用户也不必先映射 80。
        """
        domain = (domain or "").strip().lower()
        if not re.match(r"^[a-z0-9]([a-z0-9\-.]{0,250})[a-z0-9]$", domain) \
                or ".." in domain:
            self.send_line("ERRT 域名格式不合法")
            return
        acme = Path("/root/.acme.sh/acme.sh")
        if not acme.exists():
            self.send_line("ERRT 服务端未安装 acme.sh")
            return
        if self.uid in _cert_busy:
            self.send_line("ERRT 上一次申请仍在进行")
            return
        try:
            resolved = await cmd("getent", "ahosts", domain, check=False)
        except Exception:
            resolved = ""
        if self.ip6 not in resolved:
            self.send_line(
                f"ERRT 域名未解析到本机隧道地址 {self.ip6}（请先添加 AAAA 记录）")
            return

        cert, key = await self._cached_cert(domain)
        if cert is None:
            _cert_busy.add(self.uid)
            core.log_abuse("cert", self.name, f"申请证书 {domain}")
            try:
                cert, key = await self._issue(acme, domain)
            except Exception as e:
                self.send_line(f"ERRT 签发失败：{str(e)[:120]}")
                return
            finally:
                _cert_busy.discard(self.uid)
            print(f"[tunnel] {self.name} 证书已签发 {domain}")
        self.send_line("CERT "
                       + base64.b64encode(cert).decode() + " "
                       + base64.b64encode(key).decode())

    async def _cached_cert(self, domain: str):
        """复用仍在有效期内的已签发证书（Let's Encrypt 生产签发、剩余 ≥30 天）。

        客户端每次重连都会查一次证书，手动点「一键申请」也可能连点几下；每次都
        真去下单会很快撞上 LE 的重复证书限额（每域名每周 5 张）。这里直接回传
        已有证书，只有确实临近到期或证书缺失/非生产签发时才真正走 ACME。
        """
        crt = Path(f"/root/.acme.sh/{domain}_ecc/fullchain.cer")
        key = Path(f"/root/.acme.sh/{domain}_ecc/{domain}.key")
        if not (crt.is_file() and key.is_file()):
            return None
        issuer = await cmd("openssl", "x509", "-issuer", "-noout",
                           "-in", str(crt), check=False)
        if "Let's Encrypt" not in issuer or "STAGING" in issuer.upper():
            return None
        end = await cmd("openssl", "x509", "-enddate", "-noout",
                        "-in", str(crt), check=False)
        match = re.search(r"notAfter=(.+)", end)
        try:
            left = (ssl.cert_time_to_seconds(match.group(1).strip())
                    - time.time()) / 86400
        except (AttributeError, ValueError):
            return None
        if left < 30:
            return None
        print(f"[tunnel] {self.name} 复用已签发证书 {domain}（剩余 {left:.0f} 天）")
        return crt.read_bytes(), key.read_bytes()

    async def _issue(self, acme: Path, domain: str):
        """执行签发：校验期间在用户静态地址的 80 端口临时提供校验文件。"""
        workdir = Path(tempfile.mkdtemp(prefix="antipole-cert-"))
        webroot = Path(_x().get("acme_webroot", "/etc/antipole/acme-webroot"))
        challenge = webroot / ".well-known" / "acme-challenge"
        challenge.mkdir(parents=True, exist_ok=True)
        # 清理可能残留的失效订单，避免 ACME 侧返回 authorization 状态错误
        shutil.rmtree(Path("/root/.acme.sh") / f"{domain}_ecc", ignore_errors=True)

        async def handler(reader, writer):
            try:
                head = await asyncio.wait_for(reader.read(2048), 10)
                parts = head.split(b" ")
                path = parts[1].decode(errors="replace") if len(parts) > 1 else "/"
                name = os.path.basename(path)
                target = challenge / name
                if name and ".." not in name and target.is_file():
                    body = target.read_bytes()
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                                 b"Content-Length: " + str(len(body)).encode()
                                 + b"\r\nConnection: close\r\n\r\n" + body)
                else:
                    writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                                 b"Connection: close\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        server = None
        # HTTP-01 校验必须落在该用户的静态地址 80 端口上，而这个端口常被该账号
        # 自己的映射占着（例如把 80 映射到本机网站）：先临时撤下映射让出端口，
        # 校验完按原参数恢复（期间站点短暂不可达）；防火墙也要同步放行。
        mapped_ip = self.remotes.get(80) if 80 in self.maps else None
        if mapped_ip is not None:
            # unlisten 会连带撤掉 80 的防火墙放行，所以放行统一放在其后
            await unlisten(self.uid, 80, self)
            print(f"[tunnel] {self.name} 申请证书：临时让出 80 端口"
                  f"（原映射校验后自动恢复）")
        await net.fw_open(80)          # 校验期间 80 必须对外可达
        try:
            if await cmd("ip", "-6", "addr", "show", self.ip6, check=False) == "":
                await cmd("ip", "-6", "addr", "add", self.ip6 + "/128",
                          "dev", "lo", check=False)
            try:
                server = await asyncio.start_server(handler, self.ip6, 80)
            except OSError as e:
                raise RuntimeError(
                    f"80 端口不可用（{e.strerror or e}）："
                    f"该地址的 80 被主机服务或其他占用，先释放再试")
            env = {"HOME": "/root", "PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:"
                                                           "/sbin:/bin")}
            # webroot 模式：校验文件由上面这个本机 80 端口服务提供，acme.sh 只负责
            # 写文件并调用 ACME。不可加 --standalone（将与该监听争用 80 端口），
            # 也不能写裸 --log（该参数需要一个值，会把后一个参数吞掉导致解析失败）。
            out = await asyncio.create_subprocess_exec(
                str(acme), "--issue", "-d", domain, "-w", str(webroot),
                "--keylength", "ec-256", "--force",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                env=env)
            text, _ = await out.communicate()
            log = text.decode(errors="replace")
            crt = Path(f"/root/.acme.sh/{domain}_ecc/fullchain.cer")
            key = Path(f"/root/.acme.sh/{domain}_ecc/{domain}.key")
            if not crt.is_file() or not key.is_file():
                # 报错时优先带出 ACME 的校验失败原因，否则给最后几行
                lines = [x for x in log.strip().splitlines() if x.strip()]
                why = next((x for x in reversed(lines) if "error" in x.lower()
                            or "invalid" in x.lower()), "")
                tail = " / ".join(lines[-3:])
                raise RuntimeError((why + " ｜ " + tail if why and why not in tail
                                    else tail) or "acme.sh 未产出证书")
            return crt.read_bytes(), key.read_bytes()
        finally:
            if server is not None:
                server.close()
                try:
                    await server.wait_closed()
                except Exception:
                    pass
            shutil.rmtree(workdir, ignore_errors=True)
            if mapped_ip is not None:      # 让出的 80 映射按原参数恢复
                ok, reason = await _start_mapping(self, 80, mapped_ip)
                if ok:
                    await net.fw_open(80)
                    self.maps[80] = 80
                    self.remotes[80] = mapped_ip
                    print(f"[tunnel] {self.name} 证书流程结束，80 映射已恢复")
                else:
                    print(f"[tunnel] {self.name} 80 映射恢复失败：{reason}")
            else:
                # 校验临时放行的端口保留：80 同时是 VLESS 入站（Reality），
                # fw_close 会全局删除放行把代理一并打断（V3.15 教训）
                await net.fw_open(80)

    # ---- 映射与生命周期 ----

    async def map_port(self, local_port: int, local_ip: str):
        """声明端口映射：在用户静态地址上监听该端口，公网端口与用户本地端口一致。

        返回 (公网端口, 失败原因)：成功时端口有值、原因为空；失败时端口为 None。
        """
        if local_port in self.maps:
            return local_port, ""                  # 重复声明视为幂等成功
        # 先过保护闸：特权端口与主机自身占用的端口一律不开放，避免用户占用主机服务端口
        denied = await port_denied(local_port)
        if denied:
            core.log_abuse("tunnel_bind", self.name, f"端口 {local_port} 被拒绝：{denied}")
            return None, denied
        ok, reason = await _start_mapping(self, local_port, local_ip)
        if not ok:
            core.log_abuse("tunnel_bind", self.name, f"端口 {local_port} 监听失败：{reason}")
            return None, reason
        await net.fw_open(local_port)
        self.maps[local_port] = local_port
        self.remotes[local_port] = local_ip
        core.add_tunnel_map(self.uid, local_port, local_port, local_ip)
        core.update_tunnel_user(self.uid, port_count=len(self.maps))
        return local_port, ""

    async def restore_maps(self):
        """重连后恢复历史映射（保留端口或已被占用的端口直接跳过）。"""
        for record in core.list_tunnel_maps(self.uid):
            port = record["local_port"]
            local_ip = record["local_ip"] or "127.0.0.1"
            denied = await port_denied(port)
            if denied:                     # 历史上存下的映射如今撞上保留端口，直接跳过
                print(f"[tunnel] {self.name} 跳过映射 {port}：{denied}")
                continue
            ok, reason = await _start_mapping(self, port, local_ip)
            if ok:
                self.maps[port] = port
                self.remotes[port] = local_ip
                await net.fw_open(port)
            else:
                print(f"[tunnel] {self.name} 恢复映射 {port} 失败：{reason}")

    async def close(self):
        if self.closed:
            return
        self.closed = True
        if self.gate is not None:
            self.gate.release()
        if self._idle_task is not None:
            self._idle_task.cancel()
        for cid in list(self.conns):
            conn = self.conns.pop(cid, None)
            if conn:
                conn.close()
                if GUARD is not None:
                    GUARD.drop_conn(self.uid)
        for remote_port in list(self.maps):
            await unlisten(self.uid, remote_port, self)
        self.maps.clear()
        # 只摘自己的登记：顶替场景下新会话可能已占住同一 token，
        # 无脑 pop 会把新会话从注册表里抹掉（映射与中继归属都会跟着乱）
        if _sessions.get(self.token) is self:
            _sessions.pop(self.token, None)
        live = _sessions_by_uid.get(self.uid)
        if live:
            live[:] = [s for s in live if s is not self]
            if not live:
                _sessions_by_uid.pop(self.uid, None)
        if self.direct and _relay_ready() and _session_of(self.uid) is None:
            # 会话下线：连同该用户在中继里的活跃管道一起收掉
            # （若同一用户已有新会话接入，则不动它的管道）
            _spawn_bg(_RELAY.cmd("kill", uid=self.uid))
        try:
            self.transport.close()
        except Exception:
            pass


class PublicProtocol(asyncio.Protocol):
    """一个公网连接的协议实现：数据到达即封装成 D 帧，无队列、无任务。"""

    __slots__ = ("session", "remote_port", "local_port", "local_ip", "cid",
                 "transport", "last_active", "closed", "pace_timer")

    def __init__(self, session, remote_port):
        self.session = session
        self.remote_port = remote_port
        self.local_port = remote_port
        self.local_ip = session.remotes.get(remote_port, "127.0.0.1")
        self.cid = 0
        self.transport = None
        self.last_active = time.monotonic()
        self.closed = False
        self.pace_timer = None

    def connection_made(self, transport):
        self.transport = transport
        try:
            # 写缓冲上限：给一块大载荷留余量，同时仍能对慢客户端形成背压
            transport.set_write_buffer_limits(high=_DOWN_CHUNK)
        except Exception:
            pass
        if not self.session.adopt(self):
            self.close()

    def data_received(self, data):
        if not self.closed:
            self.session.deliver_down(self, data)
            _pace(self, len(data))

    def pause_writing(self):
        self.session.pause_sources()

    def resume_writing(self):
        self.session.resume_sources()

    def connection_lost(self, exc):
        if self.pace_timer is not None:
            self.pace_timer.cancel()
            self.pace_timer = None
        if self.cid:
            self.session.drop_conn(self.cid)
        self.closed = True
        self.transport = None

    def pause(self):
        try:
            self.transport.pause_reading()
        except Exception:
            pass

    def resume(self):
        try:
            self.transport.resume_reading()
        except Exception:
            pass

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.transport.close()
        except Exception:
            pass


def _bind_reason(exc: OSError) -> str:
    """把端口绑定异常翻译成用户可读的原因。

    最常见的冲突是服务器自身服务以通配地址占用该端口（例如 nginx 监听 [::]:11451），
    此时内核在用户静态地址上的绑定必然失败，公网请求会落到通配服务上，
    表现为"访问到别的服务"（404 / 400 等），必须直接告诉用户换端口。
    """
    if exc.errno == errno_mod.EADDRINUSE:
        return "该端口已被服务器上的其他服务占用，请更换本地端口"
    if exc.errno == errno_mod.EACCES:
        return "该端口需要更高权限（1024 以下为特权端口），请改用 1024 以上端口"
    if exc.errno == errno_mod.EADDRNOTAVAIL:
        return "静态地址未就绪（内核尚未挂载），请重连或联系管理员"
    return f"监听失败：{exc.strerror or exc}"


class PublicListener:
    """公网端口监听器：绑定在用户的静态地址上，端口号与用户本地端口一致。

    由于每个隧道用户拥有独立静态 /128，同一端口号在不同用户之间互不冲突，
    因此无需在本机公网 IP 上占用任何端口，端口空间对用户完整可用。
    注意：若服务器自身已有服务以通配地址监听同一端口，该端口无法再被映射
    （内核不允许通配监听存在时再绑定具体地址），此时明确返回原因。
    """

    def __init__(self, session, listen_addr: str, port: int):
        self.session = session
        self.listen_addr = listen_addr
        self.port = port
        self.server = None

    async def start(self) -> tuple:
        """启动监听，返回 (是否成功, 失败原因)。放行防火墙由调用方统一处理。"""
        try:
            self.server = await asyncio.get_running_loop().create_server(
                lambda: PublicProtocol(self.session, self.port),
                self.listen_addr, self.port)
        except OSError as e:
            return False, _bind_reason(e)
        return True, ""

    async def stop(self):
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass


async def unlisten(uid: int, remote_port: int, session=None):
    """撤下一条映射：无论由本进程监听还是中继进程承载，都在此统一收尾。

    同一用户重连时可能存在「旧会话收尾」与「新会话建立映射」交错：归属不是自己
    就什么都不做，否则会把新会话刚建好的监听撤掉（表现为客户端显示映射就绪、
    公网却连不上）。
    """
    listener = _listeners.get((uid, remote_port))
    if listener is not None:
        if session is not None and listener.session is not session:
            return
        _listeners.pop((uid, remote_port), None)
        await listener.stop()
    else:
        owner = _relay_maps.get((uid, remote_port))
        if owner is None or (session is not None and owner is not session):
            return
        _relay_maps.pop((uid, remote_port), None)
        if _relay_ready():
            await _RELAY.cmd("unlisten", uid=uid, port=remote_port)
    # 同一端口号可能被其他用户映射（各自 /128 独立），确认无人再用再撤销放行
    still_used = any(key[1] == remote_port for key in _listeners) or \
        any(key[1] == remote_port for key in _relay_maps)
    if not still_used:
        await net.fw_close(remote_port)


async def _fail_auth(peer: str, reason: str):
    """认证/握手失败：同源计数、必要时封禁，并加入小延迟抬高爆破成本。"""
    banned = False
    if GUARD is not None:
        banned = GUARD.note_fail(peer)
        if banned:
            core.log_abuse("ban", peer, f"隧道控制面连续认证失败，"
                                        f"封禁 {GUARD.auth_ban_s}s（{reason}）")
            print(f"[abuse] 隧道来源 {peer} 连续认证失败，已封禁 {GUARD.auth_ban_s}s")
    await asyncio.sleep(0.2 if banned else 0.5)


class ControlProtocol(asyncio.Protocol):
    """隧道控制连接：握手、文本命令与二进制帧全部在回调内完成。

    协议解析不依赖 StreamReader：每收到一段数据就地切帧，切不完的留在缓冲里，
    没有 Future/任务唤醒，也没有每帧一次的 drain。
    """

    __slots__ = ("session", "transport", "buf", "peer", "authed", "closed",
                 "frame_max", "_authing", "pace_timer", "off")

    def __init__(self):
        self.session = None
        self.transport = None
        self.buf = bytearray()
        self.peer = ""
        self.authed = False
        self.closed = False
        self.frame_max = _FRAME_MAX
        self._authing = False
        self.pace_timer = None
        self.off = 0

    # ---- 连接生命周期 ----

    def connection_made(self, transport):
        self.transport = transport
        self.frame_max = int(_tun().get("frame_max", _FRAME_MAX))
        try:
            self.peer = (transport.get_extra_info("peername") or ("",))[0] or ""
            # 控制连接承载该用户全部映射的流量，写缓冲留出若干大帧的余量
            transport.set_write_buffer_limits(high=self.frame_max)
        except Exception:
            pass
        if GUARD is not None:
            left = GUARD.ip_banned(self.peer)
            if left:
                self.reject(f"banned:{left}")
                return
            if not GUARD.note_conn_ip(self.peer):
                core.log_abuse("rate", self.peer, "控制连接建立过于频繁")
                self.reject("rate")

    def connection_lost(self, exc):
        self.closed = True
        if self.pace_timer is not None:
            self.pace_timer.cancel()
            self.pace_timer = None
        session = self.session
        if session is not None:
            print(f"[tunnel] 用户下线 uid={session.uid}")
            _spawn_bg(session.close())

    def pause_writing(self):
        if self.session is not None:
            self.session.pause_sources()

    def resume_writing(self):
        if self.session is not None:
            self.session.resume_sources()

    def reject(self, reason: str):
        """拒绝连接并给出原因码，便于客户端定位问题。"""
        if self.closed:
            return
        self.closed = True
        try:
            self.transport.write(f"ERRA {reason}\n".encode())
            self.transport.close()
        except Exception:
            pass

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.transport.close()
        except Exception:
            pass

    # ---- 数据解析 ----

    def data_received(self, data):
        if self.closed:
            return
        if data:
            self.buf += data                 # 只拷新到的一段，不重拷已缓存的半帧
        elif not self.buf:
            return
        if self._parse():
            _pace(self, len(data))

    def _parse(self) -> bool:
        """在累积缓冲上按偏移切帧。返回 False 表示连接已关闭。

        帧通常比单次读大（例如 192KB 帧、46KB 读），因此缓冲里会长期存在半帧：
        - 新数据只做一次 append，已缓存部分不再重拷；
        - 载荷按偏移一次取出（memoryview + bytes，单次拷贝）；
        - 整帧消费完直接清空缓冲，不清空时也只在大偏移处压缩一次。
        """
        buf = self.buf
        off = self.off
        size = len(buf)
        if not self.authed:
            if self._authing:
                self.off = off                 # 认证进行中：一律不消费，完成后一起解析
                return True
            idx = buf.find(b"\n", off)
            if idx < 0:
                if size - off > 512:
                    self.reject("protocol")
                    return False
                self.off = off                 # 半行：留待后续数据补齐
                return True
            line = bytes(buf[off:idx]).decode(errors="replace").strip()
            self.off = idx + 1                 # 认证期间的剩余字节留在缓冲里
            if not self._authing:
                self._authing = True
                _spawn_bg(self._auth(line))
            return True

        session = self.session
        while off < size:
            first = buf[off]
            if first == 0x55:              # 'U' 上行数据帧
                if size - off < 9:
                    break
                cid = int.from_bytes(buf[off + 1:off + 5], "big")
                length = int.from_bytes(buf[off + 5:off + 9], "big")
                if length > self.frame_max:      # 仅长度上限保护：超长帧断开
                    core.log_abuse("frame_oversize", session.name, f"len={length}")
                    self.close()
                    return False
                if size - off < 9 + length:
                    break                        # 半帧，等后续数据
                start = off + 9
                payload = bytes(memoryview(buf)[start:start + length])
                off = start + length
                session.deliver_up(cid, payload)
            elif first == 0x58:            # 'X' 连接关闭
                if size - off < 9:
                    break
                cid = int.from_bytes(buf[off + 1:off + 5], "big")
                off += 9
                session.drop_conn(cid)
            else:                          # 文本命令
                idx = buf.find(b"\n", off)
                if idx < 0:
                    if size - off > 4096:
                        self.close()
                        return False
                    break
                line = bytes(buf[off:idx]).decode(errors="replace").strip()
                off = idx + 1
                if not self._command(line):
                    return False
        if off >= size:
            buf.clear()
            self.off = 0
        elif off >= 65536:
            del buf[:off]                      # 压缩一次，避免缓冲无限增长
            self.off = 0
        else:
            self.off = off
        return True

    def _command(self, line: str) -> bool:
        """处理一条文本命令；返回 False 表示应停止继续解析。"""
        session = self.session
        if line == "PING":
            # 保活同时续活：判定"僵尸会话"与空闲回收都以此时间戳为准，
            # 只要客户端还在发 PING，会话就不会被误判为已死
            if session is not None:
                session._last_active = time.monotonic()
            if not self.closed:
                self.transport.write(b"PONG\n")
        elif line == "K":
            self.close()
            return False
        elif line.startswith("A "):
            parts = line.split(" ")
            try:
                local_port = int(parts[1])
            except (ValueError, IndexError):
                session.send_line("ERRP 0")
                return True
            if not (0 < local_port < 65536):
                session.send_line("ERRP 0")
                return True
            local_ip = parts[2] if len(parts) > 2 and parts[2] else "127.0.0.1"
            if local_port in session.maps:          # 重复声明：直接回结果
                session.send_line(f"OKP {local_port}")
                return True
            if local_port in session.declaring:     # 上一次声明还在处理
                return True
            session.declaring.add(local_port)
            _spawn_bg(self._declare(local_port, local_ip))
        elif line.startswith("T "):
            # 证书申请耗时较长，异步执行，避免阻塞控制通道上的其他命令与数据帧
            _spawn_bg(session.request_cert(line[2:].strip()))
        return True

    async def _declare(self, local_port: int, local_ip: str):
        session = self.session
        try:
            remote_port, reason = await session.map_port(local_port, local_ip)
        finally:
            session.declaring.discard(local_port)
        if remote_port:
            session.send_line(f"OKP {remote_port}")
        else:
            session.send_line(f"ERRP {local_port} {reason}")

    # ---- 握手 ----

    async def _auth(self, hello: str):
        if not hello.startswith("HELLO "):
            await _fail_auth(self.peer, "protocol")
            self.reject("protocol")
            return
        token = hello[6:].strip()
        direct = False
        if " " in token:                   # HELLO <token> [能力标记]，r1 = 支持回连数据面
            token, _, caps = token.partition(" ")
            direct = "r1" in caps.split()
        token = token.strip()
        old = _sessions.get(token)
        if old is not None:
            # 同一账号只允许一条会话。旧会话若已无保活，说明客户端已死或链路已断，
            # 此时直接顶替（并把旧连接关掉，让失联的旧客户端别再重连）；
            # 旧会话仍在正常保活则拒绝，避免两个活客户端互相顶来顶去造成抖动。
            if time.monotonic() - old._last_active <= _TAKEOVER_AFTER_S:
                self.reject("duplicate")
                return
            print(f"[tunnel] 接管僵尸会话 uid={old.uid}"
                  f"（{int(time.monotonic() - old._last_active)}s 无保活）")
            try:
                old.transport.write(b"ERRA duplicate\n")
            except Exception:
                pass
            await old.close()
            if token in _sessions:      # 并发顶替：让最后到达的那条生效
                self.reject("duplicate")
                return
        user = core.get_tunnel_user_by_token(token)
        if not user or not user["user_enabled"]:
            await _fail_auth(self.peer, "auth")
            self.reject("auth")
            return
        if GUARD is not None and GUARD.is_protected(user):
            self.reject("protected")
            return
        session = TunnelSession(user, self.transport, direct=direct and _relay_ready())
        self.session = session
        _sessions[token] = session
        _sessions_by_uid.setdefault(session.uid, []).append(session)
        self.transport.write(f"OK {session.ip6}\n".encode())
        session.start_idle()
        print(f"[tunnel] {session.name} 上线 ip6={session.ip6}"
              f"{'（数据面：中继）' if session.direct else ''}")
        # 先把历史映射恢复完再开闸解析命令：客户端收到 OK 后会立刻重新声明映射，
        # 若两者并发绑定同一端口，必然有一个报 EADDRINUSE。
        try:
            await session.restore_maps()
        except Exception as e:
            print(f"[tunnel] {session.name} 恢复映射出错: {e}")
        self.authed = True
        self._authing = False
        if self.buf and not self.closed:
            self.data_received(b"")        # 认证期间到达的数据继续解析


async def tunnel_listen_addrs() -> list:
    """控制面与数据面的监听地址列表。

    默认 = 本机全部 IPv6 地址中剔除用户 /128，再补 IPv4 通配：客户端用任何本机
    地址接入都能连上（隧道接入地址、主地址、业务地址，以及历史配置里用过的其他
    本机地址），同时不占用任何用户 /128 的端口——用户地址的端口空间完整归其所有。
    tunnel.listen 显式配置时以其为准（支持逗号分隔多地址，"::" 即全地址通配）。
    """
    explicit = (_tun().get("listen") or "").strip()
    if explicit:
        return [item.strip() for item in explicit.split(",") if item.strip()]
    user_addrs = {u["egress_ip"] for u in core.list_users() if u.get("egress_ip")}
    addrs = [addr for addr in sorted(await net.local_v6_addresses())
             if addr not in user_addrs]
    ctrl = net.tunnel_control_addr()
    if ctrl and ctrl not in addrs:
        addrs.insert(0, ctrl)
    addrs.append("0.0.0.0")
    return addrs


async def tunnel_start():
    """启动隧道控制监听（tunnel.enabled 时生效）。"""
    global _tls_ctx, _srv, _RELAY
    if not tunnel_enabled():
        print("[edge] 隧道功能未启用（tunnel.enabled=false）")
        return
    tun = _tun()
    # 监听地址收敛到本机业务地址（见 tunnel_listen_addrs），不在用户 /128 上占端口
    addrs = await tunnel_listen_addrs()
    if tun.get("sni") and tun.get("cert") and tun.get("key"):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(tun["cert"], tun["key"])
            _tls_ctx = ctx
        except Exception as e:
            print(f"[edge] TLS 证书装载失败，隧道回退明文: {e}")
            _tls_ctx = None
    port = int(tun.get("port", 18281))
    try:
        _srv = await asyncio.get_running_loop().create_server(
            ControlProtocol, addrs, port, ssl=_tls_ctx)
    except OSError as e:
        print(f"[edge] 隧道控制端口 {port} 监听失败: {e}")
        return
    mode = "TLS" if _tls_ctx else "明文"
    await net.fw_open(port)
    # 数据面中继：编译语言进程只搬字节，控制面仍在本进程
    relay_bin = (_tun().get("relay_bin") or "").strip()
    if relay_bin and not os.path.isabs(relay_bin):
        relay_bin = str(Path(__file__).resolve().parent.parent / relay_bin)
    if relay_bin and os.path.isfile(relay_bin):
        _RELAY = RelayLink(CFG)
        await _RELAY.start()
        await net.fw_open(int(_tun().get("relay_port", 18282)))
        print(f"[relay] 数据面端口 {_tun().get('relay_port', 18282)} 已放行")
    else:
        print("[relay] 未找到中继程序，数据面继续由本进程承载")
    ctrl = net.tunnel_control_addr()
    print(f"[edge] 隧道控制端口 {','.join(addrs)}:{port} 已就绪（{mode}，"
          f"接入地址 {ctrl or '任意本机地址'}，"
          f"单用户并发{('上限 %s' % tun.get('max_conns_per_user')) if tun.get('max_conns_per_user') else '不限'}）")


def tunnel_stop():
    for token in list(_sessions):
        _spawn_bg(_sessions[token].close())
    _sessions.clear()
    if _srv:
        _srv.close()
    if _RELAY is not None and _RELAY.proc is not None:
        try:
            _RELAY.proc.terminate()
        except Exception:
            pass


def tunnel_sessions():
    return {"count": len(_sessions),
            "direct": sum(1 for s in _sessions.values() if s.direct),
            "users": sorted(s.name for s in _sessions.values()),
            "ports": len(_listeners) + len(_relay_maps),
            "banned": GUARD.banned_sources() if GUARD else {}}


_host_ports_cache = {"ts": 0.0, "data": {}}
_HOST_PORTS_TTL = 5.0          # 秒：避免一次连接里连续声明多个端口时重复扫监听表


async def host_ports() -> dict:
    """主机以 IPv6 通配地址监听的 TCP 端口 -> 进程名。

    只有 IPv6 通配监听（`[::]` / `*:端口`）会与用户静态地址（IPv6 /128）上的绑定
    冲突：内核不允许通配监听存在时再往具体地址绑同一端口，因此这类端口物理上无法
    映射，必须提前拒绝并说明原因。IPv4 通配（`0.0.0.0`）只占 IPv4，与用户地址
    无关；绑在本机具体地址上的服务（如 VLESS 只监听主地址的 80）同样不冲突，
    用户仍可映射同号端口，故不参与判定。
    """
    now = time.monotonic()
    if _host_ports_cache["data"] and now - _host_ports_cache["ts"] < _HOST_PORTS_TTL:
        return _host_ports_cache["data"]
    if not have_bin("ss"):
        return {}
    out = await cmd("ss", "-lntHp", check=False)
    ports = {}
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        # 仅 IPv6 通配才算占用用户地址：* / [::] / ::；0.0.0.0 为 IPv4 通配，跳过
        addr, _, port = fields[3].rpartition(":")
        if not port.isdigit() or addr not in ("*", "[::]", "::"):
            continue
        match = re.search(r'users:\(\("([^"]+)"', line)
        ports[int(port)] = match.group(1) if match else "未知"
    _host_ports_cache.update({"ts": now, "data": ports})
    return ports


async def port_denied(port: int) -> str:
    """端口是否禁止映射，返回拒绝原因（允许时返回空串）。

    设计上只硬保留必要端口（默认仅 22），其余端口能否使用一律看物理占用：
    主机若已用通配地址监听该端口，用户就不可能绑定成功，此时给出明确原因。
    """
    tun = _tun()
    min_port = int(tun.get("min_port", 1))
    if port < min_port:
        return f"端口 {port} 属于特权端口（小于 {min_port}），不允许映射"
    if port in {int(x) for x in (tun.get("deny_ports") or [])}:
        return f"端口 {port} 为服务器保留端口，不允许映射"
    hosts = await host_ports()
    if port in hosts:
        return f"该端口已被服务器上的 {hosts[port]} 占用，请更换本地端口"
    return ""