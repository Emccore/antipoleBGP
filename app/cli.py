# -*- coding: utf-8 -*-
"""
antipole 管理命令（CLI）。

直接读配置 + 操作同一份 DB/内核，改完 Xray 配置后给运行中的服务发 SIGHUP
（systemd: ExecReload），触发服务热载新配置，不重启、不中断连接。

用法: antipole <子命令> [参数]
"""
import argparse
import asyncio
import json
import shutil
import sys
import time
from pathlib import Path

from . import db, net, proxy
from .main import BASE, load_config


def _cfg_path() -> str:
    path = Path("/etc/antipole/config.yaml")
    return str(path) if path.exists() else str(BASE / "config.yaml")


def _setup(cfg: dict):
    __import__("os").umask(0o077)   # 权限收紧：新建文件 600 / 目录 700
    Path(cfg["db"]["path"]).parent.mkdir(parents=True, exist_ok=True)
    Path(cfg["db"]["keys_dir"]).mkdir(parents=True, exist_ok=True)
    db.init(cfg["db"]["path"])
    net.init_pool(cfg["network"]["prefix"], cfg["rotation"]["start_seq"])
    net.setup(cfg)
    proxy.setup(cfg)


def _resolve(user: str):
    """按 id 或名字找用户，找不到报错退出。"""
    user = db.get_user(int(user)) if user.isdigit() else db.get_user_by_name(user)
    if not user:
        sys.exit(f"找不到用户: {user}")
    return user


async def _reload_service(cfg):
    """通知运行中的 antipole 服务重新生成 Xray 配置。"""
    if Path("/etc/antipole").exists():
        await net.cmd("systemctl", "reload", "antipole", check=False)
    else:
        print("(本机非部署环境，跳过 SIGHUP 通知)")


def _acme() -> Path:
    for path in (Path.home() / ".acme.sh" / "acme.sh",
              Path("/root/.acme.sh/acme.sh")):
        if path.exists():
            return path
    return Path("acme.sh")


def _cert_dir(domain: str) -> Path:
    return Path("/etc/antipole/certs") / domain


def _fmt_used(user: dict) -> str:
    mb = (user["used_up"] + user["used_down"]) / 1048576
    quota_str = f"/{user['quota_mb']}M" if user["quota_mb"] else ""
    return f"{mb:.1f}M{quota_str}"


# ---------- 子命令 ----------

async def cmd_status(cfg, args):
    free, total = 0, 0
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            kb = int(v.strip().split()[0])
            if k == "MemAvailable":
                free = kb
            elif k == "MemTotal":
                total = kb
    except OSError:
        pass
    peers = await net.wg_dump()
    online = sum(1 for i in peers.values()
                 if i["handshake"] and time.time() - i["handshake"] / 1e9 < 300)
    warp = await net.warp_is_up()
    bgp = await net.bgp_status()
    xray = proxy._waitpid()

    print(f"前缀     : {cfg['network']['prefix']}")
    rot_cfg = cfg["rotation"]
    print(f"轮换         : {rot_cfg.get('min_interval',1800)//60}~{rot_cfg.get('max_interval',7200)//60} 分钟/每用户随机")
    print(f"内存     : {free/1024:.0f}MB 可用 / {total/1024:.0f}MB")
    print(f"用户     : {len(db.list_users())}  在线: {online}")
    print(f"WG       : {net._n()['wg_iface']} :{cfg['network']['wg_port']}")
    print(f"Xray     : {'运行中' if xray else '未运行'}  (VLESS :{cfg['xray']['port']})")
    print(f"WARP     : {'UP ' + (await net.warp_v4()) if warp else 'DOWN'}")
    print(f"DNS64    : {'ON (' + net._d64_iface() + ')' if await net.dns64_up() else 'OFF'}")
    print(f"BGP      : {','.join(bgp['daemons']) if bgp['daemons'] else '未检测到'} "
          f"{'OK' if bgp['alive'] else '提醒：BGP 守护进程没跑'}")
    if bgp["detail"]:
        print(bgp["detail"].rstrip())


async def cmd_users(cfg, args):
    hdr = f"{'ID':<4}{'名称':<16}{'出口/128':<32}{'流量':<14}{'限速':<7}{'状态':<8}{'在线'}"
    print(hdr)
    rot_online = {}
    for user in db.list_users():
        rot_online[user["id"]] = 0
    peers = await net.wg_dump()
    now = int(time.time())
    for user in db.list_users():
        handshake = peers.get(user["pubkey"], {}).get("handshake", 0)
        online = "是" if handshake and now - handshake / 1e9 < 300 else "-"
        print(f"{user['id']:<4}{user['name']:<16}{user['egress_ip']:<32}"
              f"{_fmt_used(user):<14}{str(user['max_mbps'])+'M' if user['max_mbps'] else '-':<7}"
              f"{'启用' if user['enabled'] else '禁用':<8}{online}")


async def cmd_user_add(cfg, args):
    from .api import _new_user
    name = args.name
    if len(name) > 32:
        sys.exit("用户名太长")
    if db.get_user_by_name(name):
        sys.exit("用户名已存在")
    user = await _new_user(cfg, name)
    await _reload_service(cfg)
    domain = db.primary_domain()
    print(f"用户 {name} 已创建 (id={user['id']}, 出口 {user['egress_ip']})")
    print(f"VLESS: {proxy.vless_link(user, domain)}")
    print(f"WG 配置: antipole wg {user['id']}")


async def cmd_create(cfg, args):
    """快速创建用户：create <名字> [--rate Mbps] [--quota MB]，一步给链接。"""
    await cmd_user_add(cfg, args)
    # 同时设置限速/配额（可选）
    if getattr(args, "rate", 0):
        db.update_user(db.get_user_by_name(args.name)["id"], max_mbps=max(0, int(args.rate)))
        await net.tc_set_rate(db.get_user_by_name(args.name)["id"], max(0, int(args.rate)))
    if getattr(args, "quota", 0):
        db.update_user(db.get_user_by_name(args.name)["id"], quota_mb=max(0, int(args.quota)))
    extra = []
    if args.rate:
        extra.append(f"限速 {args.rate}M")
    if args.quota:
        extra.append(f"配额 {args.quota}MB")
    if extra:
        print("附: " + ", ".join(extra))


async def cmd_user_del(cfg, args):
    user = _resolve(args.user)
    await net.wg_del_peer(user["id"], user["pubkey"])
    await net.tc_set_rate(user["id"], 0)
    db.delete_user(user["id"])
    await _reload_service(cfg)
    print(f"用户 {user['name']} 已删除")


async def cmd_user_toggle(cfg, args):
    user = _resolve(args.user)
    enable = not user["enabled"]
    db.update_user(user["id"], enabled=1 if enable else 0)
    if enable:
        await net.wg_add_peer(user["id"], user["pubkey"])
    else:
        await net.wg_del_peer(user["id"], user["pubkey"])
    await _reload_service(cfg)
    print(f"{user['name']}: {'已启用' if enable else '已禁用'}")


async def cmd_user_rotate(cfg, args):
    user = _resolve(args.user)
    rot = net.Rotator(cfg)
    # 轮换只动内核路由（出站走 fwmark），xray 不用重载
    egress = await rot.rotate_one(user)
    print(f"{user['name']}: 出口换成 {egress}")


async def cmd_user_rate(cfg, args):
    user = _resolve(args.user)
    mbps = max(0, int(args.mbps))
    db.update_user(user["id"], max_mbps=mbps)
    result = await net.tc_set_rate(user["id"], mbps)
    print(f"{user['name']}: {result}")


async def cmd_user_quota(cfg, args):
    user = _resolve(args.user)
    mb = max(0, int(args.mb))
    db.update_user(user["id"], quota_mb=mb)
    print(f"{user['name']}: 流量配额 {mb}MB")


async def cmd_user_get(cfg, args):
    """用户详情：流量/配额/限速/状态/在线/出口，管理功能的命令行版本。"""
    user = _resolve(args.user)
    peers = await net.wg_dump()
    now = int(time.time())
    handshake = peers.get(user["pubkey"], {}).get("handshake", 0)
    online = "在线" if handshake and now - handshake / 1e9 < 300 else "-"
    domain = db.primary_domain()
    print(f"ID      : {user['id']}")
    print(f"名称    : {user['name']}")
    print(f"内网    : {user['internal_ip']}" + (f" / {net.internal_v4(user['id'])}" if net.internal_v4(user['id']) else ""))
    print(f"出口/128: {user['egress_ip']}")
    print(f"流量    : {_fmt_used(user)}   (up {user['used_up']/1048576:.1f}M / down {user['used_down']/1048576:.1f}M)")
    print(f"配额    : {str(user['quota_mb'])+'MB' if user['quota_mb'] else '不限'}")
    print(f"限速    : {str(user['max_mbps'])+'Mbps' if user['max_mbps'] else '不限'}")
    print(f"状态    : {'启用' if user['enabled'] else '禁用'}   在线: {online}")
    print(f"创建时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(user['created_at']/1000))}")
    print(f"VLESS   : {proxy.vless_link(user, domain)}" if domain else "VLESS   : 没配接入域名，链接退化为服务器 IP")


async def cmd_user_reset(cfg, args):
    """清零用户流量计数（配额巡检依据该计数判断）。"""
    user = _resolve(args.user)
    db.update_user(user["id"], used_up=0, used_down=0)
    print(f"{user['name']}: 流量已清零")


async def cmd_link(cfg, args):
    user = _resolve(args.user)
    domain = db.primary_domain()
    print(proxy.vless_link(user, domain))


async def cmd_wg(cfg, args):
    user = _resolve(args.user)
    import ipaddress
    from .api import _server_ip
    pub = await net.wg_server_pub()
    server_ip = await _server_ip(cfg)
    if not server_ip:
        sys.exit("拿不到公网 IP，去 config.yaml 填 network.public_ip")
    v4 = net.internal_v4(user["id"])
    addr = f"Address = {user['internal_ip']}/128"
    if v4:
        addr += f"\nAddress = {v4}/32"
    allowed = "0.0.0.0/0, ::/0" if cfg["warp"]["enabled"] and v4 else "::/0"
    dns = (cfg["dns64"]["dns_v6"] if cfg["dns64"].get("enabled", True)
           else "2001:4860:4860::8888, 1.1.1.1")
    print("[Interface]")
    print(addr)
    print(f"PrivateKey = {user['privkey']}")
    print(f"DNS = {dns}")
    print()
    print("[Peer]")
    print(f"PublicKey = {pub}")
    print(f"Endpoint = {server_ip}:{cfg['network']['wg_port']}")
    print(f"AllowedIPs = {allowed}")
    print("PersistentKeepalive = 25")


async def cmd_domains(cfg, args):
    for domain in db.list_domains():
        print(f"[{domain['id']}] {domain['domain']:<30} IP={domain['ip'] or '-':<16} "
              f"端口={domain['port'] or '默认':<6} {'启用' if domain['enabled'] else '停用'} {domain['note']}")


async def cmd_domain_add(cfg, args):
    try:
        did = db.add_domain(args.domain, args.ip or "", args.port or 0, args.note or "")
    except Exception:
        sys.exit("域名已存在或格式不对")
    print(f"已添加 (id={did})")


async def cmd_domain_ip(cfg, args):
    domain = db.get_domain(int(args.id))
    if not domain:
        sys.exit(f"域名 id {args.id} 不存在")
    db.update_domain(int(args.id), ip=args.ip)
    print(f"{domain['domain']} -> {args.ip}")


async def cmd_domain_del(cfg, args):
    domain = db.get_domain(int(args.id))
    if not domain:
        sys.exit(f"域名 id {args.id} 不存在")
    db.delete_domain(int(args.id))
    print(f"已删除: {domain['domain']}")


async def cmd_domain_toggle(cfg, args):
    domain = db.get_domain(int(args.id))
    if not domain:
        sys.exit(f"域名 id {args.id} 不存在")
    en = 0 if domain["enabled"] else 1
    db.update_domain(int(args.id), enabled=en)
    await _reload_service(cfg)
    print(f"{domain['domain']}: {'已启用' if en else '已停用'}")


async def cmd_invite(cfg, args):
    """生成一次性邀请码（自助注册用）。"""
    import secrets as _secrets
    n = max(1, min(50, getattr(args, "count", 1) or 1))
    for _ in range(n):
        print(db.add_invite(_secrets.token_urlsafe(12)))
    if n > 1:
        print(f"(共 {n} 个)")


async def cmd_invites(cfg, args):
    rows = db.list_invites()
    if not rows:
        print("还没有邀请码，antipole invite 生成")
        return
    print(f"{'邀请码':<22}{'创建时间':<19}{'状态':<6}{'使用者'}")
    for row in rows:
        print(f"{row['code']:<22}"
              f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(row['created_at']/1000)):<19}"
              f"{'已用' if row['used'] else '未用':<6}{row['used_by'] or ''}")


async def cmd_version(cfg, args):
    from . import __version__
    print(f"antipoleBGP {__version__}")


async def cmd_backup(cfg, args):
    src = Path(cfg["db"]["path"])
    day = time.strftime("%Y%m%d-%H%M%S")
    dst = src.with_name(f"data.sqlite3.bak.{day}")
    shutil.copy2(src, dst)
    print(f"已备份: {dst}")


async def cmd_log(cfg, args):
    n = args.n or 50
    proc = await asyncio.create_subprocess_exec(
        "journalctl", "-user", "antipole", "-n", str(n), "--no-pager",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    out, _ = await proc.communicate()
    print(out.decode(errors="replace"))


# ---------- 证书（acme.sh） ----------

async def cmd_cert_issue(cfg, args):
    """申请域名证书（Let's Encrypt），写回接入域名记录并热载。"""
    domain = args.domain
    acme = _acme()
    if not acme.exists():
        sys.exit("未找到 acme.sh，请先执行: curl https://get.acme.sh | sh -s email=you@example.com")
    domain = None
    for row in db.list_domains():
        if row["domain"] == domain:
            domain = row
            break
    if domain is None:
        print(f"域名 {domain} 不在接入列表，请先执行: antipole domain add {domain}")
    while True:
        n = input(f"给 {domain} 申请证书？域名要先解析到这台机器 (y/N): ").strip().lower()
        if n in ("y", "yes"):
            break
        if not n:
            sys.exit("取消")

    cert_dir = _cert_dir(domain)
    cert_dir.mkdir(parents=True, exist_ok=True)
    crt = str(cert_dir / "fullchain.pem")
    key = str(cert_dir / "key.pem")

    # 申请：首选 standalone（要 80 空闲），可以 --webroot 改走文件验证
    issue = [str(acme), "--issue", "-domain", domain]
    if args.webroot:
        issue += ["--webroot", args.webroot]
    else:
        issue += ["--standalone"]
    r = await net.cmd(*issue, check=False)
    print(r[-600:] if r else "(acme.sh 无输出)")
    if "Your cert is in" not in r and "Cert success" not in r and "already" not in r:
        sys.exit(f"\n申请失败，上面是 acme.sh 输出。域名解析到本机了吗？80/443 端口空着吗？")

    # 装到固定位置，续期后自动 reload xray
    await net.cmd(
        str(acme), "--install-cert", "-domain", domain,
        "--key-file", key, "--fullchain-file", crt,
        "--reloadcmd", "antipole cert reload --silent", check=False)

    now = int(time.time())
    if domain:
        db.update_domain(domain["id"], cert_crt=crt, cert_key=key, cert_at=now)
    elif args.auto_add:
        db.add_domain(domain, "", 0, "auto cert")
    print(f"\n证书已就位:\n  {crt}\n  {key}")
    print("已写回接入域名记录，正在热载 Xray…")
    await _reload_service(cfg)


async def cmd_cert_renew(cfg, args):
    acme = _acme()
    if not acme.exists():
        sys.exit("没找到 acme.sh")
    await net.cmd(str(acme), "--renew", "-domain", args.domain,
                  *(("--force",) if args.force else ()), check=False)
    print("续期完成（或无需续期）。续期钩子会自动 reload Xray。")


async def cmd_cert_list(cfg, args):
    for domain in db.list_domains():
        extra = ""
        if domain["cert_crt"]:
            extra = f"  证书文件: {domain['cert_crt']}"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "openssl", "x509", "-noout", "-enddate",
                    "-in", domain["cert_crt"],
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL)
                out, _ = await proc.communicate()
                extra += "  ·  " + out.decode(errors="replace").replace(
                    "notAfter=", "到期: ").strip()
            except Exception:
                pass
        print(f"[{domain['id']}] {domain['domain']:<30} {'有证书' if domain['cert_crt'] else '无证书':<8}{extra}")
    print("\nacme.sh 续期任务由它自己的 cron 管，续完自动重载 Xray。")


async def cmd_cert_check(cfg, args):
    """手动查询全部证书剩余天数（服务端每 6 小时自动巡检）。"""
    from .api import _cert_days_left
    any_cert = False
    for domain in db.list_domains():
        if not domain["cert_crt"]:
            print(f"[{domain['id']}] {domain['domain']:<30} 无证书")
            continue
        any_cert = True
        left = await _cert_days_left(domain["cert_crt"])
        if left is None:
            print(f"[{domain['id']}] {domain['domain']:<30} 证书读不出来（文件没了？）")
        else:
            flag = "已过期!" if left < 0 else ("快到期" if left <= 14 else "OK")
            print(f"[{domain['id']}] {domain['domain']:<30} 剩余 {left:>4} 天  {flag}")
    if not any_cert:
        print("还没有任何证书。antipole cert issue <域名> 申请。")
    print("服务端每 6 小时自动巡检一次，临近到期时写入日志并推送 alerts.webhook（如已配置）。")


async def cmd_cert_reload(cfg, args):
    await _reload_service(cfg)
    if not getattr(args, "silent", False):
        print("已通知运行中的服务热载配置")


# ---------- 入口 ----------

_HELP = """\
antipoleBGP 管理命令

  状态/查询
    antipole status                     系统状态（BGP/WARP/Xray/内存/在线/证书）
    antipole users                      用户列表
    antipole user get <user>            单个用户详情（流量/配额/限速/在线）
    antipole link <user>                vless 分享链接
    antipole wg <user>                  WG 客户端配置
    antipole domains                    接入域名列表
    antipole invites                    邀请码列表
    antipole log [-n 50]                最近日志
    antipole version                    版本信息

  用户
    antipole create <name> [--rate Mbps] [--quota MB]   快速建用户并给链接
    antipole user add <name>            建用户
    antipole user del <user>            删用户（peer/xray/限速一起清）
    antipole user toggle <user>         启用/禁用
    antipole user rotate <user>         立即换出口
    antipole user rate <user> <Mbps>    限速（0 解除）
    antipole user quota <user> <MB>     配额（0 不限）
    antipole user reset <user>          清零用户流量

  邀请码（自助注册）
    antipole invite [--count N]         生成一次性邀请码
    （用户拿邀请码 POST /api/register 自助注册）

  接入域名 / 证书
    antipole domain add <domain> [--ip IP] [--port N] [--note 备注]
    antipole domain ip <id> <IP>        换 IP，用户侧零改动
    antipole domain toggle <id>         启用/停用
    antipole domain del <id>            删除域名
    antipole cert issue <domain> [--webroot 路径] [--auto-add]
    antipole cert renew <domain> [--force]
    antipole cert check                 查所有证书剩余天数
    antipole cert list                  证书列表（含到期时间）
    antipole cert reload [--silent]     续期钩子：热载 Xray

  其他
    antipole backup                     手动备份数据库

所有修改配置的命令会自动向运行中的服务发送 SIGHUP 触发热载，不重启、不中断连接。
"""


async def cmd_help(cfg, args):
    print(_HELP)


def main():
    parser = argparse.ArgumentParser(prog="antipole", description="antipoleBGP 管理命令")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("help", help="显示本帮助")
    sub.add_parser("version", help="版本信息")
    sub.add_parser("status", help="系统状态")
    sub.add_parser("users", help="用户列表")
    create_p = sub.add_parser("create", help="快速创建用户")
    create_p.add_argument("name")
    create_p.add_argument("--rate", type=int, default=0, help="限速 Mbps（0=不限）")
    create_p.add_argument("--quota", type=int, default=0, help="流量配额 MB（0=不限）")
    user_p = sub.add_parser("user", help="用户操作: add/del/toggle/rotate/rate/quota/get/reset")
    user_sub = user_p.add_subparsers(dest="action", required=True)
    subp = user_sub.add_parser("add", help="建用户")
    subp.add_argument("name")
    sp = user_sub.add_parser("del", help="删除用户")
    sp.add_argument("user")
    sp = user_sub.add_parser("toggle", help="启用/禁用")
    sp.add_argument("user")
    sp = user_sub.add_parser("rotate", help="换出口")
    sp.add_argument("user")
    sp = user_sub.add_parser("rate", help="限速 Mbps (0=不限)")
    sp.add_argument("user")
    sp.add_argument("mbps", type=int)
    sp = user_sub.add_parser("quota", help="流量配额 MB (0=不限)")
    sp.add_argument("user")
    sp.add_argument("mb", type=int)
    sp = user_sub.add_parser("get", help="用户详情")
    sp.add_argument("user")
    sp = user_sub.add_parser("reset", help="清零用户流量")
    sp.add_argument("user")

    link_p = sub.add_parser("link", help="vless 链接")
    link_p.add_argument("user")
    wg_p = sub.add_parser("wg", help="WG 客户端配置")
    wg_p.add_argument("user")

    sub.add_parser("domains", help="接入域名列表")
    sub.add_parser("invite", help="生成邀请码").add_argument("--count", type=int, default=1)
    sub.add_parser("invites", help="邀请码列表")
    domain_p = sub.add_parser("domain", help="域名管理: add/ip/del/toggle")
    domain_sub = domain_p.add_subparsers(dest="action", required=True)
    subp = domain_sub.add_parser("add")
    subp.add_argument("domain")
    subp.add_argument("--ip", default="")
    subp.add_argument("--port", type=int, default=0)
    subp.add_argument("--note", default="")
    subp = domain_sub.add_parser("ip", help="换 IP")
    subp.add_argument("id", type=int)
    subp.add_argument("ip")
    subp = domain_sub.add_parser("del", help="删除域名")
    subp.add_argument("id", type=int)
    subp = domain_sub.add_parser("toggle", help="启用/停用")
    subp.add_argument("id", type=int)

    sub.add_parser("backup", help="手动备份数据库")
    log_p = sub.add_parser("log", help="最近日志")
    log_p.add_argument("-n", type=int, default=50)

    cert_p = sub.add_parser("cert", help="证书管理: issue/list/renew/reload/check")
    cert_sub = cert_p.add_subparsers(dest="action", required=True)
    subp = cert_sub.add_parser("issue", help="申请域名证书 (acme.sh, 需要 80 端口)")
    subp.add_argument("domain")
    subp.add_argument("--webroot", default="", help="走 webroot 验证（默认为 standalone）")
    subp.add_argument("--auto-add", action="store_true", help="域名不在接入列表也自动加进去")
    subp = cert_sub.add_parser("list", help="证书列表")
    subp = cert_sub.add_parser("renew", help="手动续期")
    subp.add_argument("domain")
    subp.add_argument("--force", action="store_true")
    subp = cert_sub.add_parser("reload", help="续期完成后的钩子：热载 Xray")
    subp.add_argument("--silent", action="store_true")
    subp = cert_sub.add_parser("check", help="查所有证书剩余天数")

    args = parser.parse_args()
    cfg = load_config(_cfg_path())
    _setup(cfg)

    handlers = {
        "help": cmd_help,
        "version": cmd_version,
        "status": cmd_status,
        "users": cmd_users,
        "create": cmd_create,
        "user": cmd_user_router,
        "link": cmd_link,
        "wg": cmd_wg,
        "domains": cmd_domains,
        "invite": cmd_invite,
        "invites": cmd_invites,
        "domain": cmd_domain_router,
        "backup": cmd_backup,
        "log": cmd_log,
        "cert": cmd_cert_router,
    }
    # 与主服务互斥：整条命令持独占锁（在 asyncio 任务内拿，嵌套的 shared 才能复用同一栈），
    # 服务端改内核/DB 时让路，反之亦然
    asyncio.run(_run_cmd_locked(handlers[args.cmd], cfg, args))


async def _run_cmd_locked(handler, cfg, args):
    with net.tx().exclusive():
        await handler(cfg, args)


async def cmd_cert_router(cfg, args):
    table = {"issue": cmd_cert_issue, "list": cmd_cert_list,
             "renew": cmd_cert_renew, "reload": cmd_cert_reload,
             "check": cmd_cert_check}
    await table[args.action](cfg, args)


async def cmd_user_router(cfg, args):
    table = {"add": cmd_user_add, "del": cmd_user_del, "toggle": cmd_user_toggle,
             "rotate": cmd_user_rotate, "rate": cmd_user_rate,
             "quota": cmd_user_quota, "get": cmd_user_get,
             "reset": cmd_user_reset}
    await table[args.action](cfg, args)


async def cmd_domain_router(cfg, args):
    table = {"add": cmd_domain_add, "ip": cmd_domain_ip,
             "del": cmd_domain_del, "toggle": cmd_domain_toggle}
    await table[args.action](cfg, args)


if __name__ == "__main__":
    main()