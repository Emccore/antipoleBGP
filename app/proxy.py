# -*- coding: utf-8 -*-
"""
代理层（Xray 管理）：
  - 由本进程直接拉起 Xray 子进程，配置与进程状态保持一致
  - reload 采用 SIGHUP，Xray 平滑热载配置，用户连接不中断
  - 崩溃自动重启，保障服务可用性
  - 出站设计：每用户一个 freedom(fwmark 走其独立路由表) + warp4(mark) 分流 v4
"""
import asyncio
import json
import re
import secrets
import threading
from pathlib import Path

try:
    from typing import Optional
except ImportError:
    Optional = None

CFG = None
_proc = None
_stop = False
_last_stats = {}
_stats_lock = None


def setup(cfg: dict):
    global CFG, _stats_lock
    CFG = cfg
    _stats_lock = threading.Lock()


async def cmd(*args, check=True, timeout=15) -> str:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise RuntimeError(f"{' '.join(args)} 超时")
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {err.decode(errors='replace').strip()[:200]}")
    return out.decode(errors="replace").strip()


def _x() -> dict:
    return CFG["xray"]


def _kp(name: str) -> Path:
    return Path(CFG["db"]["keys_dir"]) / name


# ---------- Reality 密钥 ----------

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
            # Xray 26.xc 输出: PrivateKey: / Password (PublicKey): / Hash32:
            # 老版本: Private key: / Public key:
            if stripped.startswith("PrivateKey:") or stripped.startswith("Private key:"):
                priv = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Password (PublicKey):") or stripped.startswith("Public key:"):
                pub = stripped.split(":", 1)[1].strip()
        if not priv or not pub:
            raise RuntimeError("xray x25519 输出不对劲: " + out[:200])
        priv_f.write_text(priv)
        pub_f.write_text(pub)
        sid_f.write_text(secrets.token_hex(4))
        priv_f.chmod(0o600)
    return pub_f.read_text().strip(), sid_f.read_text().strip()


# ---------- 配置生成 ----------

def build_config(users) -> dict:
    xc = _x()
    warp = CFG["warp"]["enabled"]
    mark = CFG["network"]["warp_mark"]
    pub, sid = _kp("x25519.pub").read_text().strip(), _kp("shortid").read_text().strip()
    sni = xc["sni_dest"]

    clients = [{"id": user["uuid"], "email": user["name"], "flow": "xtls-rprx-vision"}
               for user in users]
    vless_settings = {"clients": clients, "decryption": "none"}
    # 80 同端口 HTTP 回退：非 VLESS 流量转发至本机真实 MC 首页（伪装为普通网站）
    fallback = xc.get("fallback")
    if fallback:
        vless_settings["fallbacks"] = [{"dest": fallback}]
    # Reality dest：可固定 IP（dest_ip），避免服务器出站 DNS 波动导致握手不稳
    if xc.get("dest_ip"):
        dip = xc["dest_ip"].strip()
        dest = f"[{dip}]:443" if ":" in dip and not dip.startswith("[") else f"{dip}:443"
    else:
        dest = f"{sni}:443"
    inbounds = [{
        "tag": "api", "listen": "127.0.0.1", "port": xc["api_port"],
        "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"},
    }, {
        "tag": "vless-in", "listen": "::", "port": xc["port"],
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
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }]
    if xc["trojan"]["enabled"] and clients:
        tclients = [{"password": client["id"], "email": client["email"]}
                    for client in clients]
        # 优先使用接入域名已申请的证书，缺省回退至配置路径
        from . import db
        pd = db.primary_domain()
        cert = pd["cert_crt"] if pd and pd["cert_crt"] else xc["trojan"]["cert"]
        key = pd["cert_key"] if pd and pd["cert_key"] else xc["trojan"]["key"]
        inbounds.append({
            "tag": "trojan-in", "listen": "::", "port": xc["trojan"]["port"],
            "protocol": "trojan", "settings": {"clients": tclients},
            "streamSettings": {
                "network": "tcp", "security": "tls",
                "tlsSettings": {"certificates": [
                    {"certificateFile": cert, "keyFile": key}]},
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        })

    warp4 = {"tag": "warp4", "protocol": "freedom",
             "settings": {"domainStrategy": "UseIPv4"}}
    if warp:
        warp4["streamSettings"] = {"sockopt": {"mark": mark}}

    outbounds = [warp4]
    from . import net as _net
    for user in users:
        # 用 fwmark 走用户自己的路由表（src=当前 /128）：轮换只动内核，xray 不用重载
        outbounds.append({
            "tag": f"user-{user['id']}", "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv6"},
            "streamSettings": {"sockopt": {"mark": _net.user_mark(user["id"])}}})
    outbounds.append({"tag": "direct", "protocol": "freedom"})

    rules = [{"inboundTag": ["api"], "outboundTag": "api"}]
    # 敏感域名单：这些站对 WARP 共享 v4 段有针对风控（Google 反复弹验证码等），
    # 强制走用户的 v6 /128 出口（绕开 WARP 共享段）。默认只放确认双栈的服务，纯 v4 目标会失败。
    sensitive = [("domain:" + domain) for domain in xc.get("sensitive_domains") or []]
    for user in users:
        if sensitive:
            rules.append({"type": "field", "user": [user["name"]],
                          "domain": sensitive, "outboundTag": f"user-{user['id']}"})
        rules.append({"type": "field", "user": [user["name"]],
                      "ip": ["0.0.0.0/0"], "outboundTag": "warp4"})
        rules.append({"type": "field", "user": [user["name"]],
                      "outboundTag": f"user-{user['id']}"})

    return {
        "log": {"loglevel": "warning"},
        "api": {"services": ["StatsService"], "tag": "api"},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True,
                                    "statsUserDownlink": True}},
                   "system": {"statsInboundUplink": True,
                              "statsInboundDownlink": True}},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }


# ---------- 进程管理 ----------

def _xray_pid():
    """查找正在运行的 xray run 进程 pid（SIGHUP 触发 re-exec，需按 pid 追踪）。"""
    import subprocess
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", "xray run -config"],
            stderr=subprocess.DEVNULL).decode().split()
    except Exception:
        return None
    me = str(__import__("os").getpid())
    for pid_str in out:
        if pid_str == me:
            continue
        try:
            with open(f"/proc/{pid_str}/cmdline", "rb") as f:
                if b"xray" in f.read():
                    return int(pid_str)
        except OSError:
            continue
    return None


def _waitpid() -> bool:
    return _xray_pid() is not None


async def reload():
    """写配置 + SIGHUP 热载。xray 收到 SIGHUP 会 re-exec（旧进程退、新进程接）。
    此处仅发送信号，由 supervisor 接管新 pid，不重复拉起，避免崩溃循环。"""
    if not CFG["xray"]["enabled"]:
        return
    from . import db
    conf = _x()["conf"]
    Path(conf).parent.mkdir(parents=True, exist_ok=True)
    users = db.list_enabled_users()
    Path(conf).write_text(json.dumps(build_config(users), indent=2,
                                     ensure_ascii=False))
    pid = _xray_pid()
    if pid is not None:
        try:
            __import__("os").kill(pid, __import__("signal").SIGHUP)
            await asyncio.sleep(1.2)   # 等 re-exec 接管
            return
        except ProcessLookupError:
            pass
    await spawn()


async def spawn():
    """启动 xray 子进程（启用死亡继承：主进程终止后 xray 一并退出，避免成为占用端口的孤儿进程）。"""
    if _waitpid():
        return
    if not Path(_x()["bin"]).exists():
        print("[proxy] xray 二进制不存在，跳过")
        return
    from . import net as _net
    proc = await asyncio.create_subprocess_exec(
        _x()["bin"], "run", "-config", _x()["conf"],
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        preexec_fn=_net._child_preexec(__import__("os").getpid()))
    asyncio.create_task(_supervise(proc))


async def _supervise(proc):
    """子进程退出：正常停止不管；reload 的 re-exec 由新进程接管；真崩溃才拉起。"""
    try:
        await proc.wait()
    except Exception:
        pass
    if _stop or proc.returncode == 0:
        return
    # reload 触发 re-exec：旧进程退出是预期，等新 xray 接管
    await asyncio.sleep(2)
    if _xray_pid() is not None:
        return
    print(f"[proxy] xray 异常退出 (code={proc.returncode})，2 秒后重启…")
    await asyncio.sleep(2)
    if not _stop:
        await spawn()


def stop():
    global _stop
    _stop = True
    pid = _xray_pid()
    if pid is not None:
        try:
            __import__("os").kill(pid, __import__("signal").SIGTERM)
        except ProcessLookupError:
            pass


# ---------- 流量统计 ----------

async def fetch_stats() -> dict:
    if not CFG["xray"]["enabled"] or not _waitpid():
        return {}
    try:
        out = await cmd(_x()["bin"], "api", "statsquery",
                        f"--server=127.0.0.1:{_x()['api_port']}", check=False)
        data = json.loads(out or "{}")
        return {stat["name"]: int(stat.get("value", 0)) for stat in data.get("stat", [])}
    except Exception:
        return {}


def stats_diff(current: dict) -> dict:
    """跟上次快照做差值。空结果不动快照（xray 停摆恢复后不重复计数）。"""
    with _stats_lock:
        if not current:
            return {}
        diff = {}
        for k, v in current.items():
            if ">>>" not in k:
                continue
            delta = v - _last_stats.get(k, 0)
            if delta > 0:
                diff[k] = delta
        _last_stats.clear()
        _last_stats.update(current)
        return diff


def user_traffic(diff: dict) -> dict:
    """{name: (up, down)}"""
    res = {}
    for k, v in diff.items():
        parts = k.split(">>>")
        if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
            name, direction = parts[1], parts[3]
            up, down = res.get(name, (0, 0))
            res[name] = (up + v, down) if direction == "uplink" else (up, down + v)
    return res


# ---------- 分享链接 ----------

def vless_link(user: dict, domain=None) -> str:
    xc = _x()
    if domain:
        host = domain["domain"]
        port = domain["port"] or xc["port"]
    else:
        host = CFG["network"].get("public_ip") or "SERVER_IP"
        port = xc["port"]
    pub = _kp("x25519.pub").read_text().strip()
    sid = _kp("shortid").read_text().strip()
    query = (f"encryption=none&flow=xtls-rprx-vision&security=reality"
         f"&sni={xc['sni_dest']}&fp={xc['ufp']}&pbk={pub}&sid={sid}&type=tcp")
    return f"vless://{user['uuid']}@{host}:{port}?{query}#{user['name']}"