# -*- coding: utf-8 -*-
"""
antipoleBGP 出口调度管理系统 V3.20 —— 进程入口。

启动顺序：配置 -> 基础设施 -> 网络内核 -> 地址守护 -> 代理/隧道 -> 后台任务 -> Web。
全部组件由单一进程托管，任一组件初始化失败仅降级自身，不影响整体可用性。
"""
import asyncio
import gc
import os
import shutil
import signal
import sqlite3
import sys
from pathlib import Path

from aiohttp import web

from . import core, edge, net, web as webmod

BASE = Path(__file__).resolve().parent.parent
STATIC = BASE  # 保留静态资源根（MC 首页等）


async def bootstrap(cfg):
    """初始化网络环境。各步骤独立容错，单项失败不影响整体启动。"""
    # 隧道控制面地址：挂载在隧道专属网段的首地址上，供客户端统一接入
    try:
        addr = await net.ensure_tunnel_addr()
        if addr:
            print(f"隧道控制地址已就绪 {addr}")
    except Exception as e:
        print(f"[boot] 隧道控制地址挂载失败: {e}")

    # 再登记本机地址为保留地址：既避免被分配给用户，也确保地址守护放行本机业务
    try:
        reserved = await net.refresh_reserved()
        print(f"本机保留地址已登记 {len(reserved)} 个")
    except Exception as e:
        print(f"[boot] 保留地址登记失败: {e}")

    try:
        pub = await net.wg_ensure()
        print(f"WG 已就绪 {cfg['network']['wg_iface']} 公钥={pub[:16]}…")
    except Exception as e:
        print(f"[boot] WG 初始化失败（用户将无法连接）: {e}")

    # 缓存本机主地址：VLESS 入站收敛到它，隧道网段的端口留给证书校验与用户映射
    try:
        cfg["_wan_v6"] = await net.wan_v6()
        if cfg["_wan_v6"]:
            print(f"入站监听地址 {cfg['_wan_v6']}")
    except Exception:
        cfg["_wan_v6"] = ""

    try:
        await net.dns64_setup()
    except Exception as e:
        print(f"[boot] DNS64/NAT64 初始化失败（纯 v6 用户访问纯 v4 站点受限）: {e}")

    try:
        for user in core.list_users():
            if user["enabled"]:
                await net.wg_add_peer(user["id"], user["pubkey"])
            else:
                await net.wg_del_peer(user["id"], user["pubkey"])
        print("存量用户内核状态已重建")
    except Exception as e:
        print(f"[boot] 重建存量用户状态出错: {e}")

    try:
        await net.addr_guard_init()
    except Exception as e:
        print(f"[boot] 地址守护初始化失败（未分配地址可能可达本机）: {e}")

    if cfg["warp"]["enabled"]:
        try:
            if await net.warp_up():
                print(f"WARP 已就绪 v4={await net.warp_v4()}")
            else:
                print("[boot] WARP 未建立（v4 走本机出口）")
        except Exception as e:
            print(f"[boot] WARP 初始化失败（v4 走本机出口）: {e}")

    if cfg["xray"]["enabled"]:
        try:
            await edge.ensure_listen_addr()   # 固定接入地址先于监听就位
            await edge.ensure_keys()
            await edge.reload()
            await net.fw_open(cfg["xray"]["port"])   # 入站端口持久放行
            print(f"Xray 配置已生成 {cfg['xray']['conf']}")
        except Exception as e:
            print(f"[boot] Xray 初始化失败（代理不可用，WG 仍可用）: {e}")

    # 缓存服务端 WG 公钥，供 WG 配置生成复用（避免每次生成都读文件/执行命令）
    try:
        cfg["_wg_pub"] = await net.wg_server_pub()
    except Exception:
        cfg["_wg_pub"] = ""


# 常驻任务强引用：asyncio 只持弱引用，不保存的话任务可能在执行中被回收
_TASKS = set()


def spawn(coro):
    """登记常驻后台任务，异常不静默丢失。"""
    task = asyncio.ensure_future(coro)
    _TASKS.add(task)

    def _done(t):
        _TASKS.discard(t)
        if not t.cancelled() and t.exception():
            print(f"[main] 后台任务异常: {t.exception()!r}")

    task.add_done_callback(_done)
    return task


async def _start_mc_fallback(cfg):
    """80 端口非 VLESS 流量的本地回退站点（读取项目根 mc_index.html）。"""
    fallback = (cfg["xray"].get("fallback") or "").strip()
    if not fallback:
        return
    try:
        port = int(fallback.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return
    html = BASE / "mc_index.html"
    if not html.exists():
        print("[mc] 未找到 mc_index.html，跳过回退站点")
        return
    data = html.read_bytes()

    async def handler(_):
        return web.Response(body=data, content_type="text/html")

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", port).start()
    # 公网伪装：接入地址的 80 端口对外提供同一站点。443 上的 Reality 对
    # 探测者呈现 apple.com，80 上有真实网站响应——组合起来才是一台
    # "正常服务器"的画像；空端口/拒绝响应本身反倒是特征。
    listen = (cfg["xray"].get("listen") or "").strip()
    if listen and listen != "::":
        try:
            await web.TCPSite(runner, listen, 80).start()
            print(f"[mc] 伪装站点已就绪 [{listen}]:80")
        except OSError as e:
            print(f"[mc] 伪装站点绑定失败（80 可能被占用）: {e}")
    print(f"[mc] 回退站点已就绪 127.0.0.1:{port}")


async def db_backup_loop(db_path: str):
    """每日备份数据库，保留最近 7 份。"""
    src = Path(db_path)
    while True:
        try:
            await asyncio.sleep(3600 * 24)
            day = __import__("time").strftime("%Y%m%d")
            shutil.copy2(src, src.with_name(f"data.sqlite3.bak.{day}"))
            for old in sorted(src.parent.glob("data.sqlite3.bak.*"))[:-7]:
                old.unlink(missing_ok=True)
            print(f"[backup] 每日备份完成 {day}")
        except Exception as e:
            print(f"[backup] 备份失败: {e}")


async def _hup_safe(name, fn):
    try:
        await fn()
    except Exception as e:
        print(f"[{name}] 失败: {e}")


async def run(cfg):
    """常驻主循环：启动全部组件并在事件循环里长期运行。"""
    # 启动期对象一次性移入永久代，减少后续 GC 对稳定对象的反复扫描
    gc.collect()
    gc.freeze()
    await bootstrap(cfg)

    try:
        await _start_mc_fallback(cfg)
    except Exception as e:
        print(f"[mc] 回退站点启动失败: {e}")

    rotator = net.Rotator(cfg)
    spawn(rotator.run())

    conn = sqlite3.connect(cfg["db"]["path"], check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row

    guard = webmod.Guard(cfg)
    webmod.setup(cfg, guard, rotator, conn)
    edge.setup_guard(cfg)

    # 后台任务
    spawn(webmod.stats_loop(cfg))
    spawn(webmod.quota_loop(cfg))
    spawn(webmod.cert_alert_loop(cfg))
    spawn(webmod.abuse_sweep_loop())
    spawn(db_backup_loop(cfg["db"]["path"]))
    spawn(edge.tunnel_start())
    spawn(net.bgp_guard_loop())
    if cfg["warp"]["enabled"]:
        spawn(net.warp_health_loop(cfg))

    # CLI 修改配置后发送 SIGHUP，此处热载 Xray 配置
    if hasattr(signal, "SIGHUP"):
        asyncio.get_running_loop().add_signal_handler(
            signal.SIGHUP,
            lambda: spawn(_hup_safe("SIGHUP 热载", edge.reload)))

    app = webmod.make_app()
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, cfg["server"]["host"],
                      int(cfg["server"]["port"])).start()
    print(f"管理 API http://{cfg['server']['host']}:{cfg['server']['port']}"
          f" 白名单: {cfg['server'].get('admin_allow') or '不限制'}")

    reg_runner = None
    if cfg["server"].get("register_enabled"):
        reg_app = webmod.make_register_app()
        reg_runner = web.AppRunner(reg_app)
        await reg_runner.setup()
        port = int(cfg["server"].get("register_port", 18290))
        await web.TCPSite(reg_runner, cfg["server"]["host"], port).start()
        await net.fw_open(port)
        print(f"自助注册 http://{cfg['server']['host']}:{port} 已开启")

    try:
        await asyncio.Event().wait()
    finally:
        edge.stop()
        edge.tunnel_stop()
        net.dns64_stop()
        if reg_runner:
            await reg_runner.cleanup()
        await runner.cleanup()


def main():
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else str(BASE / "config.yaml")
    cfg = core.load_config(cfg_path)
    cfg["_path"] = cfg_path

    os.umask(0o077)
    for directory in (Path(cfg["db"]["path"]).parent, Path(cfg["db"]["keys_dir"])):
        directory.mkdir(parents=True, exist_ok=True)
        try:
            directory.chmod(0o700)
        except OSError:
            pass

    core.init(cfg["db"]["path"])
    core.setup_mutex(cfg)
    core.setup_pools(cfg)
    net.setup(cfg)
    edge.setup(cfg)

    # 可选加速：装了 uvloop 就用它。同一套 asyncio 语义的 C 实现循环，实测每事件
    # 开销明显低于标准实现（本机 1 核：转发同样的 100MB，13.5 vs 17.4 ms/MB），
    # 未安装时自动退回标准库实现，不影响部署。
    try:
        import uvloop
    except ImportError:
        print("[boot] 事件循环使用标准 asyncio 实现")
    else:
        uvloop.install()
        print(f"[boot] 事件循环使用 uvloop {uvloop.__version__}")

    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()