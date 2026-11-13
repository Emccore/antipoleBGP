#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
antipoleBGP 隧道客户端（Windows 图形界面版）。

填写「接入地址」与「UserID（隧道令牌）」，点「连接」即可：
  * 自动建立隧道，界面显示取到的公网地址（本账号静态 /128）
  * 端口映射按「一行一个」填写，公网端口与本机端口一一对应
  * 底部实时显示连接数、上下行速率与运行日志

配置保存在程序同目录的 antipole-tunnel-gui.json，下次打开自动回填。
命令行参数 --check 用于打包后自检（不启动界面）。
"""
import asyncio
import importlib.util
import json
import os
import queue
import sys
import threading
from pathlib import Path

APP = "antipole 隧道客户端"
LOG_KEEP = 500                 # 界面日志保留行数（超出自动丢弃最旧的）
__version__ = "1.0"


def base_dir() -> Path:
    """exe 打包后取 exe 所在目录，否则取脚本目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def load_client():
    """加载隧道客户端模块（与图形界面同目录或打包内嵌）。"""
    candidates = [base_dir() / "antipole-tunnel.py"]
    if getattr(sys, "_MEIPASS", None):
        candidates.insert(0, Path(sys._MEIPASS) / "antipole-tunnel.py")
    candidates.append(Path(__file__).resolve().parent / "antipole-tunnel.py")
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location("antipole_tunnel_client", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise FileNotFoundError("未找到 antipole-tunnel.py（请与图形客户端放在同一目录）")


class Options:
    """与命令行客户端一致的参数容器。"""

    def __init__(self, server, token, maps, retry=5, ping=15, stats=10,
                 cert=None, cert_dir=".", cert_domain=None, cert_renew_days=30):
        self.server = server
        self.token = token
        self.maps = maps
        self.retry = retry
        self.ping = ping
        self.stats = stats
        self.sni = ""
        self.insecure = False
        self.once = False
        self.cert = cert
        self.cert_dir = cert_dir
        self.cert_domain = cert_domain
        self.cert_renew_days = cert_renew_days


class Worker(threading.Thread):
    """后台线程里跑 asyncio 事件循环，stdout 经由队列送回界面。"""

    def __init__(self, opt, out: queue.Queue, mode="run"):
        super().__init__(daemon=True)
        self.opt = opt
        self.out = out
        self.mode = mode
        self.loop = None
        self.task = None
        self.client_module = load_client()

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        module = self.client_module
        # 先取出队列：内层类里的 self 指向自身，不能再用 self.out
        out_queue = self.out

        class Tee:
            def write(self, text):
                if text.strip():
                    out_queue.put(("log", text.rstrip()))

            def flush(self):
                pass

        old = sys.stdout
        sys.stdout = Tee()
        try:
            coro = (module.request_cert(self.opt) if self.mode == "cert"
                    else module.run(self.opt))
            self.task = self.loop.create_task(coro)
            self.loop.run_until_complete(self.task)
        except asyncio.CancelledError:
            pass
        except Exception as e:                       # noqa: BLE001
            self.out.put(("log", f"运行出错：{e}"))
        finally:
            sys.stdout = old
            self.loop.close()
            self.out.put(("state", "stopped" if self.mode == "run" else "cert-done"))

    def stop(self):
        try:
            if self.loop and self.task:
                self.loop.call_soon_threadsafe(self.task.cancel)
        except RuntimeError:
            pass        # 事件循环已关闭：线程本就要退出


def run_gui():
    import tkinter as tk
    from tkinter import messagebox, scrolledtext, ttk

    root = tk.Tk()
    root.title(f"{APP} v{__version__}")
    root.geometry("1000x820")
    root.minsize(920, 720)

    try:
        client = load_client()
    except Exception as e:                        # noqa: BLE001
        root.withdraw()
        messagebox.showerror(APP, f"初始化失败：{e}")
        return

    cfg_path = base_dir() / "antipole-tunnel-gui.json"
    saved = {}
    if cfg_path.is_file():
        try:
            saved = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            saved = {}

    frame = ttk.Frame(root, padding=12)
    frame.pack(fill="x")
    frame.columnconfigure(1, weight=1)

    ttk.Label(frame, text="接入地址").grid(row=0, column=0, sticky="w", pady=5)
    server_var = tk.StringVar(value=saved.get("server", ""))
    ttk.Entry(frame, textvariable=server_var, width=64).grid(
        row=0, column=1, columnspan=3, sticky="we", pady=5)

    ttk.Label(frame, text="UserID").grid(row=1, column=0, sticky="w", pady=5)
    token_var = tk.StringVar(value=saved.get("token", ""))
    ttk.Entry(frame, textvariable=token_var, width=64, show="*").grid(
        row=1, column=1, columnspan=3, sticky="we", pady=5)

    ttk.Label(frame, text="端口映射").grid(row=2, column=0, sticky="nw", pady=5)
    maps_text = tk.Text(frame, height=6, width=48)
    maps_text.grid(row=2, column=1, columnspan=3, sticky="we", pady=5)
    maps_text.insert("1.0", saved.get("maps", "8080"))
    ttk.Label(frame, text="每行一个端口，如 8080 或 127.0.0.1:9000；公网端口与本机端口一一对应"
              ).grid(row=3, column=1, columnspan=3, sticky="w")

    ttk.Separator(frame, orient="horizontal").grid(
        row=4, column=0, columnspan=4, sticky="we", pady=10)

    ttk.Label(frame, text="申请证书").grid(row=5, column=0, sticky="w", pady=5)
    domain_var = tk.StringVar(value=saved.get("domain", ""))
    ttk.Entry(frame, textvariable=domain_var, width=40).grid(
        row=5, column=1, sticky="we", pady=5)
    cert_btn = ttk.Button(frame, text="一键申请 HTTPS 证书")
    cert_btn.grid(row=5, column=2, padx=8, pady=5)
    ttk.Label(frame, text="需先给域名添加 AAAA 记录，指向本账号的公网地址；证书保存到 certs 目录"
              ).grid(row=6, column=1, columnspan=3, sticky="w")

    renew_var = tk.BooleanVar(value=bool(saved.get("renew", False)))
    renew_days_var = tk.StringVar(value=str(saved.get("renew_days", 30)))
    renew_chk = ttk.Checkbutton(frame, text="证书自动续期", variable=renew_var)
    renew_chk.grid(row=7, column=0, sticky="w", pady=5)
    days_box = ttk.Frame(frame)
    days_box.grid(row=7, column=1, columnspan=3, sticky="w", pady=5)
    ttk.Label(days_box, text="剩余不足").pack(side="left")
    ttk.Entry(days_box, textvariable=renew_days_var, width=6).pack(side="left", padx=4)
    ttk.Label(days_box, text="天时自动重签（连接期间每 12 小时检查一次）").pack(side="left")

    state_var = tk.StringVar(value="未连接")
    ip_var = tk.StringVar(value="-")
    rate_var = tk.StringVar(value="-")

    info = ttk.Frame(root, padding=(12, 0))
    info.pack(fill="x")
    info.columnconfigure(1, weight=1)
    ttk.Label(info, text="状态：").grid(row=0, column=0, sticky="w")
    ttk.Label(info, textvariable=state_var, foreground="#0a7").grid(
        row=0, column=1, sticky="w")
    ttk.Label(info, text="公网地址：").grid(row=0, column=2, sticky="w", padx=(16, 0))
    ttk.Label(info, textvariable=ip_var, foreground="#06c").grid(
        row=0, column=3, sticky="w")
    ttk.Label(info, text="速率：").grid(row=1, column=0, sticky="w", pady=(5, 0))
    ttk.Label(info, textvariable=rate_var).grid(row=1, column=1, columnspan=3,
                                                sticky="w", pady=(5, 0))

    buttons = ttk.Frame(root, padding=12)
    buttons.pack(fill="x")
    log_box = scrolledtext.ScrolledText(root, height=22, state="disabled")
    log_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    events = queue.Queue()
    holder = {"worker": None, "cert_worker": None}

    def append_log(line: str):
        log_box.configure(state="normal")
        log_box.insert("end", line + "\n")
        # 自动清理：仅保留最近 LOG_KEEP 行（海量连接下避免界面与内存过载）
        total = int(log_box.index("end-1c").split(".")[0])
        if total > LOG_KEEP:
            log_box.delete("1.0", f"{total - LOG_KEEP}.0")
        log_box.see("end")
        log_box.configure(state="disabled")

    def save_cfg():
        try:
            cfg_path.write_text(json.dumps({
                "server": server_var.get().strip(),
                "token": token_var.get().strip(),
                "maps": maps_text.get("1.0", "end").strip(),
                "domain": domain_var.get().strip(),
                "renew": bool(renew_var.get()),
                "renew_days": renew_days(),
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as e:              # 目录只读等情况不阻断使用
            print(f"[gui] 配置保存失败: {e}")

    def renew_days() -> int:
        try:
            value = int(renew_days_var.get().strip())
        except ValueError:
            return 30
        return value if value > 0 else 30

    def connect():
        if holder["worker"]:
            messagebox.showinfo(APP, "已在连接中，请先断开")
            return
        if holder["cert_worker"]:
            messagebox.showinfo(APP, "证书申请进行中，请稍候再连接")
            return
        server = server_var.get().strip()
        token = token_var.get().strip()
        raw = maps_text.get("1.0", "end").strip().splitlines()
        if not server or not token or not raw:
            messagebox.showwarning(APP, "接入地址、UserID、端口映射都不能为空")
            return
        try:
            maps = [client.parse_map(x.strip()) for x in raw if x.strip()]
        except ValueError as e:
            messagebox.showerror(APP, str(e))
            return
        save_cfg()
        # 勾选自动续期时，把域名与阈值交给客户端，连接后在会话内定时重签
        renew_domain = domain_var.get().strip() if renew_var.get() else ""
        if renew_var.get() and not renew_domain:
            messagebox.showwarning(APP, "已勾选自动续期，请填写证书域名")
            return
        state_var.set("连接中…")
        ip_var.set("-")
        holder["worker"] = Worker(Options(
            server, token, maps,
            cert_domain=renew_domain or None,
            cert_renew_days=renew_days(),
            cert_dir=str(base_dir() / "certs")), events)
        holder["worker"].start()

    def request_certificate():
        if holder["worker"]:
            messagebox.showinfo(APP, "正在连接中，证书申请会单独建立连接，请先断开")
            return
        server = server_var.get().strip()
        token = token_var.get().strip()
        domain = domain_var.get().strip()
        if not server or not token:
            messagebox.showwarning(APP, "请先填写接入地址与 UserID")
            return
        if not domain:
            messagebox.showwarning(APP, "请填写要申请证书的域名")
            return
        save_cfg()
        cert_dir = base_dir() / "certs"
        state_var.set("申请证书中…")
        append_log(f"开始申请证书 {domain}（需域名已解析到本账号公网地址）")
        worker = Worker(Options(server, token, [], cert=domain, cert_dir=str(cert_dir)),
                        events, mode="cert")
        holder["cert_worker"] = worker
        cert_btn.configure(state="disabled")
        worker.start()

    def disconnect():
        worker = holder["worker"]
        if worker:
            worker.stop()
            holder["worker"] = None
        state_var.set("未连接")
        rate_var.set("-")

    def pump():
        try:
            while True:
                kind, payload = events.get_nowait()
                if kind == "log":
                    append_log(payload)
                    if "静态地址" in payload:
                        state_var.set("已连接")
                        ip_var.set(payload.split("静态地址")[-1].strip())
                    if payload.startswith("[状态]"):
                        rate_var.set(payload.replace("[状态]", "").strip())
                    if "证书已保存" in payload or "证书已更新" in payload:
                        state_var.set("证书已就绪")
                elif kind == "state" and payload == "stopped":
                    if holder["worker"]:
                        holder["worker"] = None
                        state_var.set("未连接")
                elif kind == "state" and payload == "cert-done":
                    holder["cert_worker"] = None
                    cert_btn.configure(state="normal")
                    if state_var.get() == "申请证书中…":
                        state_var.set("证书申请结束")
        except queue.Empty:
            pass
        root.after(200, pump)

    def open_cert_dir():
        """打开证书输出目录（不存在时先创建）。"""
        target = base_dir() / "certs"
        try:
            target.mkdir(exist_ok=True)
        except OSError:
            pass
        if hasattr(os, "startfile"):
            os.startfile(str(target))

    def quit_app():
        """真正退出：停线程、销毁窗口、兜底强杀，保证不留后台进程。"""
        disconnect()
        if holder["cert_worker"]:
            holder["cert_worker"].stop()
        try:
            root.destroy()
        finally:
            os._exit(0)

    def on_close():
        # 关闭窗口 = 最小化后台继续转发（不中断隧道），点任务栏图标可恢复；
        # 需要停止请点「退出」按钮
        root.iconify()
        append_log("窗口已最小化，隧道继续在后台运行（点「退出」才会停止）")

    cert_btn.configure(command=request_certificate)
    ttk.Button(buttons, text="连接", command=connect).pack(side="left")
    ttk.Button(buttons, text="断开", command=disconnect).pack(side="left", padx=8)
    ttk.Button(buttons, text="打开证书目录",
               command=open_cert_dir).pack(side="left")
    ttk.Button(buttons, text="清空日志",
               command=lambda: (log_box.configure(state="normal"),
                                log_box.delete("1.0", "end"),
                                log_box.configure(state="disabled"))).pack(side="left", padx=8)
    ttk.Button(buttons, text="退出", command=quit_app).pack(side="left")
    ttk.Label(buttons, text=f"配置文件：{cfg_path.name}").pack(side="right")

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(200, pump)
    root.mainloop()


if __name__ == "__main__":
    if "--check" in sys.argv:
        module = load_client()
        print(f"{APP} v{__version__} 自检通过")
        print(f"  客户端模块 : {module.__file__}")
        print(f"  配置目录   : {base_dir()}")
        print(f"  映射解析   : {module.parse_map('8080')} / {module.parse_map('127.0.0.1:9000')}")
        sys.exit(0)
    run_gui()