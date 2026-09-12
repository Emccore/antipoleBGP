# -*- coding: utf-8 -*-
"""antipoleBGP 入口：配置 → 网络 → 代理 → 后台任务 → Web。单一服务，Xray 由本进程拉起。"""
import asyncio
import shutil
import sqlite3
import sys
from pathlib import Path

import yaml
from aiohttp import web

from . import api, db, net, proxy

BASE = Path(__file__).resolve().parent.parent

DEFAULTS = {
    "server": {"host": "::", "port": 9090,
               "admin_token": "change-me", "admin_allow": [],
               "view_token": ""},
    "network": {
        "prefix": "2001:db8:abcd::/48",
        "wg_iface": "wg0",
        "wg_port": 51820,
        "wg_addr": "fd00:1::1/64",
        "wg_v4_addr": "10.7.0.1/24",
        "internal_net": "fd00:1::/64",
        "route_table_base": 100,
        "public_ip": "",
        "warp_mark": 4096,
        "warp_table": 51820,
        "user_mark_base": 0x40000000,   # VLESS 用户出站 fwmark 基址（轮换不用重载 xray）
        "tc_enabled": True,
        "tc_wan": "",
    },
    "rotation": {"min_interval": 1800, "max_interval": 7200, "start_seq": 1},
    "xray": {
        "enabled": True,
        "bin": "/usr/local/bin/xray",
        "conf": "/etc/antipole/xray.json",
        "port": 80,        # HTTP 端口，VLESS 与 MC 首页回退同端口
        "api_port": 10085,
        "sni_dest": "www.apple.com",   # Reality dest，服务器必须稳定可达
        "dest_ip": "2600:1402:b800:d8a::1aca",
        "ufp": "chrome",
        "fallback": "127.0.0.1:50080",     # 非 VLESS 流量回退至本地 MC 首页
        # 敏感域名单：这些站对 WARP 共享 v4 段有针对风控，强制走用户自己的动态 v6 /128 出口。
        # 用 domain: 匹配主域+子域；仅收录双栈服务（纯 v4 域名强制走 v6 将失败，请勿添加）
        "sensitive_domains": [
            # Google 系列
            "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
            "ggpht.com", "youtube.com", "youtu.be", "google-analytics.com",
            "googlesyndication.com", "google.com.hk", "google.com.tw",
            # 微软
            "microsoft.com", "microsoftonline.com", "live.com", "office.com",
            "windows.com", "msn.com", "outlook.com", "onedrive.com", "bing.com",
            # Apple
            "apple.com", "icloud.com", "me.com",
            # Meta
            "facebook.com", "fbsbx.com", "fallback.com", "instagram.com",
            "whatsapp.com", "fbcdn.net",
            # X / Twitter
            "x.com", "twitter.com", "t.co", "twimg.com",
            # 电商 / 支付
            "amazon.com", "paypal.com", "paypalobjects.com",
            # 通讯
            "telegram.org", "t.me",
            # AI / 开发者
            "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
            "anthropic.com", "claude.ai", "github.com", "githubusercontent.com",
            # 社媒 / 内容
            "linkedin.com", "spotify.com", "netflix.com", "tiktok.com",
            "tiktokcdn.com", "reddit.com", "redditmedia.com", "discord.com",
            "discordapp.com", "snapchat.com", "twitch.tv",
            # Cloudflare 自身管理面
            "cloudflare.com", "cloudflareinsights.com",
        ],
        "trojan": {"enabled": False, "port": 2054, "cert": "", "key": ""},
    },
    "warp": {
        "enabled": True,
        "wgcf": "/usr/local/bin/wgcf",
        "iface": "wg-warp",
        "profile": "/etc/antipole/warp-profile.conf",
        # 多账号负载均衡（可选）：每个追加的 WARP 账号建一条独立隧道，
        # 用户 v4 流量按 id 均分到各隧道。每项是一个 wgcf 生成的 profile 路径。
        "profiles": [],
        "endpoints": [],   # 备用 WARP endpoint（故障切换用）
    },
    "dns64": {
        "enabled": True,
        "iface": "nat64",
        "prefix": "64:ff9b::/96",
        "v4_net": "10.44.0.0/16",
        "dns_v6": "fd00:1::1",
        "forward": ["2606:4700:4700::1111", "2001:4860:4860::8888"],
    },
    "abuse": {
        "login_fails": 5,
        "login_ban_s": 900,
        "register_per_hour": 3,
        "default_quota_mb": 0,
        "default_mbps": 0,
        "quota_check_s": 10,     # 配额巡检间隔（缩小超限窗口）
        "quota_warn_pct": 90,    # 用量达到配额百分比时触发告警
    },
    "alerts": {
        "webhook": "",           # 证书/配额等告警推送 URL（可选），POST {"title","text"}
        "cert_days": 14,         # 证书剩多少天开始告警
    },
    "db": {"path": "/etc/antipole/data.sqlite3",
           "keys_dir": "/etc/antipole/keys"},
}


def _merge(base: dict, override: dict):
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path: str) -> dict:
    cfg = _merge(DEFAULTS.copy(), {})
    cfg_file = Path(path)
    if cfg_file.exists():
        _merge(cfg, yaml.safe_load(cfg_file.read_text(encoding="utf-8")) or {})
    return cfg


async def bootstrap(cfg):
    """初始化网络环境。各步骤独立容错，单项失败不影响整体启动。"""
    try:
        pub = await net.wg_ensure()
        print(f"WG 就绪 {net._n()['wg_iface']} pub={pub[:16]}...")
    except Exception as e:
        print(f"[boot] WG 初始化失败（后续用户将无法连接）: {e}")

    # DNS64/NAT64（先起，让后面用户表的路由能指向 nat64 接口）
    try:
        await net.dns64_setup()
    except Exception as e:
        print(f"[boot] DNS64 初始化失败（纯 v6 用户访问纯 v4 站点将受限）: {e}")

    # WARP 隧道（先于用户状态重建：多隧道分流规则依赖 nft 表与隧道 mark）
    if cfg["warp"]["enabled"]:
        try:
            up = await net.warp_up()
            if up:
                print(f"WARP 就绪 v4={await net.warp_v4()}")
            else:
                print("[boot] WARP 没起来（v4 走本机出口）")
        except Exception as e:
            print(f"[boot] WARP 没起来（v4 走本机出口）: {e}")

    try:
        for user in db.list_users():
            if user["enabled"]:
                await net.wg_add_peer(user["id"], user["pubkey"])
            else:
                await net.wg_del_peer(user["id"], user["pubkey"])
        print("存量用户内核状态已重建")
    except Exception as e:
        print(f"[boot] 重建用户状态出错: {e}")

    if cfg["xray"]["enabled"]:
        try:
            await proxy.ensure_keys()
            await proxy.reload()
            print(f"Xray 配置已生成 {cfg['xray']['conf']}")
        except Exception as e:
            print(f"[boot] Xray 初始化失败（代理不可用，WG 仍可用）: {e}")


async def _start_mc_fallback(cfg):
    """80 上非 VLESS 流量转发的本地真实 MC 首页（读项目根的 mc_index.html）。"""
    fallback = (cfg["xray"].get("fallback") or "").strip()
    if not fallback:
        return
    try:
        port = int(fallback.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return
    html = BASE / "mc_index.html"
    if not html.exists():
        print("[mc] 没找到 mc_index.html，fallback 首页跳过")
        return
    data = html.read_bytes()
    from aiohttp import web
    async def handler(_):
        return web.Response(body=data, content_type="text/html")
    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/{x:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    print(f"[mc] fallback 首页已就绪 127.0.0.1:{port}（真实 MC 官网首页）")


async def db_backup_loop(db_path: str):
    """每日备份 SQLite 数据库，保留最近 7 份。"""
    src = Path(db_path)
    while True:
        try:
            await asyncio.sleep(3600 * 24)
            day = __import__("time").strftime("%Y%m%d")
            dst = src.with_name(f"data.sqlite3.bak.{day}")
            shutil.copy2(src, dst)
            # 清理老的
            for old in sorted(src.parent.glob("data.sqlite3.bak.*"))[:-7]:
                old.unlink(missing_ok=True)
            print("[bk] 每日备份完成", day)
        except Exception as e:
            print(f"[bk] 备份失败: {e}")


async def run(cfg):
    await bootstrap(cfg)

    # 80 同端口回退：真实 MC 首页（Xray fallback 目标）
    try:
        await _start_mc_fallback(cfg)
    except Exception as e:
        print(f"[mc] fallback 首页启动失败: {e}")

    rot = net.Rotator(cfg)
    asyncio.create_task(rot.run())

    guard = api.Guard(cfg)
    asyncio.create_task(api.quota_loop(cfg))
    asyncio.create_task(_loop(
        1800, guard.cleanup, "guard 清理"))
    asyncio.create_task(db_backup_loop(cfg["db"]["path"]))
    asyncio.create_task(api.cert_alert_loop(cfg))
    if cfg["warp"]["enabled"]:
        asyncio.create_task(net.warp_health_loop(cfg))

    # CLI（antipole 命令）修改数据库后发送 SIGHUP，此处重载 Xray 配置，不重启、不中断连接
    if hasattr(__import__("signal"), "SIGHUP"):
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(
            __import__("signal").SIGHUP,
            lambda: asyncio.create_task(
                _hup_safe("SIGHUP 重载", proxy.reload)))

    conn = sqlite3.connect(cfg["db"]["path"], check_same_thread=False, timeout=5)
    conn.row_factory = sqlite3.Row

    app = api.make_app(cfg, rot, conn, guard)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, cfg["server"]["host"], int(cfg["server"]["port"]))
    await site.start()
    print(f"管理 API http://{cfg['server']['host']}:{cfg['server']['port']}"
          f" 来源白名单: {cfg['server'].get('admin_allow') or '不限制'}")

    try:
        await asyncio.Event().wait()
    finally:
        proxy.stop()
        net.dns64_stop()
        await runner.cleanup()


async def _hup_safe(name, fn):
    try:
        await fn()
    except Exception as e:
        print(f"[{name}] 失败: {e}")


async def _loop(secs, fn, name):
    while True:
        try:
            fn()
        except Exception as e:
            print(f"[{name}] 出错: {e}")
        await asyncio.sleep(secs)


def main():
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else str(BASE / "config.yaml")
    cfg = load_config(cfg_path)

    # 权限收紧：新建文件默认 600、目录 700（库里有用户私钥，config 里有管理 token）
    __import__("os").umask(0o077)
    for dir_path in (Path(cfg["db"]["path"]).parent, Path(cfg["db"]["keys_dir"])):
        dir_path.mkdir(parents=True, exist_ok=True)
        try:
            dir_path.chmod(0o700)
        except OSError:
            pass

    db.init(cfg["db"]["path"])
    net.init_pool(cfg["network"]["prefix"], cfg["rotation"]["start_seq"])
    net.setup(cfg)
    proxy.setup(cfg)

    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print("\n收工")


if __name__ == "__main__":
    main()