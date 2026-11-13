#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
antipoleBGP 隧道客户端：把本机 TCP 端口映射到公网，公网端口与本机端口一一对应。

跨平台：Windows / Linux / macOS，仅需 Python 3.8+，无第三方依赖。

用法：
  python antipole-tunnel.py --server [2600:1:2:ff00::1]:18281 --token <token> \
      --map 8080 --map 127.0.0.1:9000

配置文件（--config client.ini，命令行参数优先）：
  [client]
  server = [2600:1:2:ff00::1]:18281
  token  = 3ca8aa246308a4d30073bae8940388db
  map    = 8080
  map    = 127.0.0.1:9000
  retry  = 5          # 断线重连间隔（秒）
  ping   = 60         # 保活间隔（秒），0 表示不发送
  stats  = 10         # 状态输出间隔（秒），0 表示不输出

协议：单条出向长连接多路复用；控制命令为文本行，数据为二进制帧。
"""
import argparse
import asyncio
import base64
import configparser
import os
import signal
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

__version__ = "1.0"

HELP_EPILOG = """
示例：
  Windows   py -3 antipole-tunnel.py --server [2600:1:2:ff00::1]:18281 --token xxx --map 8080
            antipole-tunnel.bat --server [2600:1:2:ff00::1]:18281 --token xxx --map 8080
  Linux     python3 antipole-tunnel.py --server [2600:1:2:ff00::1]:18281 --token xxx --map 8080
  macOS     python3 antipole-tunnel.py --server [2600:1:2:ff00::1]:18281 --token xxx --map 8080
  申请证书  python3 antipole-tunnel.py --server [2600:1:2:ff00::1]:18281 --token xxx \
                --cert www.example.com --cert-dir ./certs
  自动续期  python3 antipole-tunnel.py --server [2600:1:2:ff00::1]:18281 --token xxx \
                --map 8080 --cert-domain www.example.com --cert-dir ./certs
  查看剩余  python3 antipole-tunnel.py --cert-status --cert-dir ./certs

映射写法：8080 等价于 127.0.0.1:8080；可重复多次，每个端口独立一条公网通道。
证书模式：域名先加 AAAA 记录指向本账号静态地址，签发后得到 tls.crt / tls.key。
自动续期：填写 --cert-domain 后，客户端每 12 小时检查一次本地证书，
          剩余天数低于 --cert-renew-days（默认 30 天）时经当前隧道自动重签并覆盖。
"""


def _console_utf8():
    """Windows 控制台按 UTF-8 输出，避免中文乱码；其它平台无副作用。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


CHUNK = 262144             # 单次搬运字节：大块读取可显著摊薄每字节开销
PIPE_CHUNK = 65536         # 直连通道起步缓冲：空闲/交互连接的常驻内存档
PIPE_CHUNK_MAX = 262144    # 持续读满（下游有积压）时的加倍上限：块越大每 MB 系统调用越少
# TLS 包裹为可选能力：默认走明文 TCP（服务端 tunnel.sni/cert/key 与客户端 --sni
# 同时配置才启用加密），避免证书/域名配置抬高使用门槛
DEFAULT_SNI = ""


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def human_rate(bytes_per_sec: float) -> str:
    return human_bytes(bytes_per_sec) + "/s"


def cert_days_left(path) -> float:
    """证书剩余天数；文件缺失或无法解析时返回 -1（调用方据此决定是否续期）。"""
    path = Path(path)
    if not path.is_file():
        return -1.0
    try:
        info = ssl._ssl._test_decode_cert(str(path))
        return (ssl.cert_time_to_seconds(info["notAfter"]) - time.time()) / 86400
    except Exception:
        return -1.0


def parse_server(text: str):
    """解析 服务器地址:端口，兼容 [IPv6]:端口 写法。"""
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("--server 需为 地址:端口，IPv6 写成 [地址]:端口")
    return host.strip("[]"), int(port)


def parse_map(item: str):
    """解析 8080 或 127.0.0.1:9000。"""
    if ":" in item:
        ip, _, port = item.rpartition(":")
    else:
        ip, port = "127.0.0.1", item
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"映射写法有误：{item}")
    return ip or "127.0.0.1", int(port)


def effective_sni(opt) -> str:
    """生效的 TLS SNI：显式配置优先，否则用内置默认；--no-tls 关闭加密。"""
    if getattr(opt, "no_tls", False):
        return ""
    return (getattr(opt, "sni", "") or "").strip() or DEFAULT_SNI


def ssl_context(opt):
    """按需构造 TLS 上下文（默认明文，仅 --sni 时启用）。"""
    if not effective_sni(opt):
        return None
    ctx = ssl.create_default_context()
    if getattr(opt, "insecure", False):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# SLA 目标下的链路参数：心跳与探测都要「快发现、快恢复」。
# 中间设备（家用 NAT/运营商防火墙）的 TCP 表项普遍 30~60s 就回收，
# 应用层心跳必须比其更密；内核 keepalive 各平台默认普遍长达 2 小时，须显式设定。
PING_INTERVAL = 15          # 应用层心跳（秒）：密到足以保住 NAT 表项、疏到不构成流量
KA_IDLE = 10                # 内核 keepalive 空闲多久后开始探测（秒）
KA_INTVL = 3                # 探测间隔（秒）
KA_CNT = 3                  # 探测几次仍无响应即判死（总 ~19s）
FAST_RETRIES = 3            # 断线后先快速重试的次数（1s/2s/3s），闪断秒级恢复


def _set_keepalive_params(sock):
    """按平台显式设置 TCP keepalive 节奏（不设则系统默认可能长达 2 小时）。"""
    if sys.platform == "win32":
        try:
            # (开关, 首次空闲 ms, 探测间隔 ms)；Windows 无探测次数概念（固定 10 次）
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, KA_IDLE * 1000, KA_INTVL * 1000))
            return
        except (OSError, AttributeError):
            pass
    for opt, value in ((socket.TCP_KEEPIDLE, KA_IDLE), (socket.TCP_KEEPINTVL, KA_INTVL),
                       (socket.TCP_KEEPCNT, KA_CNT)):
        try:
            sock.setsockopt(socket.IPPROTO_TCP, opt, value)
        except (OSError, AttributeError):
            pass


def _enable_keepalive_sock(sock):
    """转发连接的 socket 调优：保活 + 关 Nagle（尽力而为，平台不支持则忽略）。

    关 Nagle 让每个数据块立即出手，避免小包被攒住等 ACK；转发路径上这是延迟与
    吞吐的双收益项。
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    _set_keepalive_params(sock)


def _enable_keepalive(writer):
    """对流包装的连接打开 TCP 保活。

    高延迟链路上中间设备静默回收映射表项时，两端都不会收到通知；保活探测能让内核
    尽早发现并报错，触发重连。
    """
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    _set_keepalive_params(sock)


def _nonblock_socket(host: str):
    """按地址族建一个非阻塞 socket，交给事件循环做连接与收发。"""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    return sock


def _sock_addr(host: str, port: int):
    """构造 sock_connect 地址：IPv6 用 4 元组（Windows 上 2 元组会报 WSAEINVAL）。"""
    return (host, port, 0, 0) if ":" in host else (host, port)


def _close_sock(sock):
    try:
        sock.close()
    except OSError:
        pass


def _shutdown_write(sock):
    """半关写方向：发 FIN 让对方读到 EOF，本端仍可继续读对向在途数据。

    一个方向结束时若直接 close 掉共享 socket，对向仍在途的数据会被内核回以
    RST，表现为大流量传输被截断（客户端侧 WinError 1236）。
    """
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass


class Stats:
    """上下行字节统计与速率换算。"""

    def __init__(self):
        self.up = 0
        self.down = 0
        self._up_base = 0
        self._down_base = 0
        self._ts = time.monotonic()

    def rates(self):
        now = time.monotonic()
        span = max(now - self._ts, 1e-6)
        up = (self.up - self._up_base) / span
        down = (self.down - self._down_base) / span
        self._up_base, self._down_base, self._ts = self.up, self.down, now
        return up, down


class SlaStats:
    """会话可用率统计：SLA = 在线时长 / 客户端运行总时长。"""

    def __init__(self):
        self.up_since = None          # 客户端启动时刻
        self.online = 0.0             # 历史累计在线秒数
        self.online_since = None      # 当前在线起点（None = 离线中）
        self.disconnects = 0          # 断线次数（不含首次连接）


class DuplicateSession(Exception):
    """服务端拒绝了本次握手：同一账号已有一条在用会话。

    这类失败重连一百次也不会成功（除非对方下线），因此调用方应停止重试并提示用户，
    而不是像普通断线那样无限退避重连。
    """


class TunnelClient:
    """一个隧道账号的连接与端口映射会话。"""

    def __init__(self, opt, sla: "SlaStats | None" = None):
        self.opt = opt
        self.host, self.port = parse_server(opt.server)
        # 数据面回连端口：默认控制端口 +1（服务端 tunnel.relay_port 对应）
        self.relay_port = int(getattr(opt, "relay_port", 0) or 0) or self.port + 1
        self.direct = not getattr(opt, "no_direct", False)
        self.token = opt.token
        self.maps = opt.maps                       # [(local_ip, local_port)]
        self.ip6 = ""
        self.reader = None
        self.writer = None
        self.local = {}                            # cid -> [reader, writer]；None 表示正在连接本机
        self.pending = {}                          # cid -> 待写入本机端口的缓冲（连接建立前的下行数据）
        self.pending_max = 4 << 20                 # 单连接缓冲上限（超过则断开，避免内存堆积）
        self.remote = {}                           # 公网端口 -> (local_ip, local_port)
        self.stats = Stats()
        self.cert_domain = (getattr(opt, "cert_domain", "") or "").strip()
        self.cert_dir = Path(getattr(opt, "cert_dir", ".") or ".")
        self._cert_future = None
        self._wlock = asyncio.Lock()
        self._tasks = set()
        self._stopping = False
        self._last_recv = time.monotonic()         # 最近一次收到服务端数据（含 PONG）
        self._pipes = 0                            # 直连通道计数（用于日志限流）
        self._pipe_errs = 0                        # 直连通道异常收尾计数（日志限流）
        self.sni = effective_sni(opt)              # 生效 SNI（默认启用 TLS 包裹）
        self.sla = sla or SlaStats()
        if self.sla.up_since is None:
            self.sla.up_since = time.monotonic()

    # ---------- 连接与握手 ----------

    async def connect(self):
        ssl_ctx = ssl_context(self.opt)
        # 连接超时：高延迟/被黑洞的链路若只依赖系统 TCP 超时，客户端会卡住两分钟不重连
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ssl_ctx,
                                        server_hostname=self.sni or None,
                                        limit=1 << 20), 15)
        except asyncio.TimeoutError:
            raise ConnectionError(f"连接 {self.host}:{self.port} 超时（15 秒）")
        _enable_keepalive(self.writer)
        # r1：声明本客户端支持「回连数据面」，由服务端决定是否启用
        caps = b" r1" if self.direct else b""
        self.writer.write(b"HELLO " + self.token.encode() + caps + b"\n")
        await self.writer.drain()
        line = await asyncio.wait_for(self.reader.readline(), 20)
        hello = line.decode(errors="replace").strip()
        if hello.startswith("ERRA duplicate"):
            raise DuplicateSession(hello)
        if not hello.startswith("OK "):
            raise ConnectionError(f"认证失败：{hello or '无响应'}")
        self.ip6 = hello[3:].strip()
        print(f"已连接 {self.host}:{self.port}，静态地址 {self.ip6}")
        await self.declare_maps()

    async def declare_maps(self):
        for local_ip, local_port in self.maps:
            self.writer.write(f"A {local_port} {local_ip}\n".encode())
            await self.writer.drain()
            resp = (await asyncio.wait_for(self.reader.readline(), 20)) \
                .decode(errors="replace").strip()
            if resp.startswith("OKP "):
                public_port = int(resp.split(" ", 1)[1])
                self.remote[public_port] = (local_ip, local_port)
                print(f"映射就绪：公网 [{self.ip6}]:{public_port}"
                      f"  ==  本机 {local_ip}:{local_port}")
            elif resp.startswith("ERRP"):
                # 服务端会附带失败原因（如端口被服务器自身服务占用），直接透出以便定位
                parts = resp.split(" ", 2)
                why = parts[2].strip() if len(parts) > 2 and parts[2].strip() \
                    else "端口被占用或静态地址未就绪"
                self.remote.pop(local_port, None)
                print(f"映射失败：本机 {local_ip}:{local_port} —— {why}")
            else:
                self.remote.pop(local_port, None)
                print(f"映射失败：{local_ip}:{local_port} -> {resp or '无响应'}"
                      f"（端口被占用或地址未就绪）")

    # ---------- 帧收发 ----------

    async def write_frame(self, kind: bytes, cid: int, payload: bytes = b""):
        async with self._wlock:
            self.writer.write(kind + struct.pack("!I", cid)
                              + struct.pack("!I", len(payload)) + payload)
            await self.writer.drain()

    async def _spawn(self, coro):
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def handle_local(self, cid: int, local_ip: str, local_port: int):
        """公网连接到达：连本机端口，回传数据。

        连接建立前到达的下行数据先入缓冲，避免竞态丢包（大文件传输必须无丢字节）。
        """
        try:
            lr, lw = await asyncio.wait_for(
                asyncio.open_connection(local_ip, local_port), 15)
        except (OSError, asyncio.TimeoutError) as e:
            print(f"本机服务不可达 {local_ip}:{local_port}（{e}）")
            self.local.pop(cid, None)
            self.pending.pop(cid, None)
            await self.write_frame(b"X", cid)
            return
        self.local[cid] = (lr, lw)
        buffered = self.pending.pop(cid, None)
        if buffered:
            try:
                lw.write(bytes(buffered))
                await lw.drain()
            except (ConnectionError, OSError):
                pass
        try:
            while not self._stopping:
                chunk = await lr.read(CHUNK)          # 大块搬运：摊薄每字节的封装开销
                if not chunk:
                    break
                self.stats.up += len(chunk)
                await self.write_frame(b"U", cid, chunk)
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            await self.write_frame(b"X", cid)
            self.local.pop(cid, None)
            self.pending.pop(cid, None)
            try:
                lw.close()
            except Exception:
                pass

    async def deliver_down(self, cid: int, payload: bytes):
        if cid not in self.local:                # 连接已关闭，直接丢弃
            return
        local = self.local[cid]
        if local is None:                        # 还在连接本机端口：先入缓冲
            buffer = self.pending.setdefault(cid, bytearray())
            if len(buffer) + len(payload) > self.pending_max:
                self.local.pop(cid, None)
                self.pending.pop(cid, None)
                await self.write_frame(b"X", cid)
                return
            buffer += payload
            return
        try:
            local[1].write(payload)
            await local[1].drain()
        except (ConnectionError, OSError):
            pass

    async def loop(self):
        reader = self.reader
        while True:
            first = await reader.readexactly(1)
            self._last_recv = time.monotonic()
            if first == b"N":
                cid, length = struct.unpack("!II", await reader.readexactly(8))
                payload = await reader.readexactly(length)
                local_port = struct.unpack("!H", payload[:2])[0]
                local_ip = payload[2:].decode(errors="replace") or "127.0.0.1"
                # 先占位再异步连接：随后的下行数据进入缓冲，不会因竞态被丢弃
                self.local[cid] = None
                self.pending[cid] = bytearray()
                await self._spawn(self.handle_local(cid, local_ip, local_port))
            elif first == b"D":
                cid, length = struct.unpack("!II", await reader.readexactly(8))
                payload = await reader.readexactly(length)
                self.stats.down += len(payload)
                await self.deliver_down(cid, payload)
            elif first == b"X":
                # 帧头统一为 类型 + 连接号(4B) + 长度(4B)，X 帧长度为 0 也要读掉，否则流错位
                cid = struct.unpack("!II", await reader.readexactly(8))[0]
                self.pending.pop(cid, None)
                local = self.local.pop(cid, None)
                if local:
                    try:
                        local[1].close()
                    except Exception:
                        pass
            elif first in (b"P", b"O", b"C", b"E", b"R"):   # 文本响应（PONG/OKP/CERT/ERRT/R）
                # 首字节已被读出，需拼回后再解析，否则前缀丢失导致识别失败
                rest = await reader.readline()
                line = (first + rest).decode(errors="replace").strip()
                if line.startswith("R "):
                    await self._on_direct(line)
                else:
                    self._feed_cert_line(line)
            else:
                raise ConnectionError(f"未知帧类型 {first!r}，协议流已错位")

    # ---------- 直连数据面（回连） ----------

    async def _on_direct(self, line: str):
        """收到 R <nonce> <本地端口> [本地地址]：为本条公网连接开一条独立回连通道。

        该通道不承载隧道协议封装，建立后就是原始字节直通，服务端由编译语言进程
        按块攒批搬运，因此大流量下两端都省掉了逐帧解析开销。
        """
        parts = line.split()
        if len(parts) < 3 or not parts[2].isdigit():
            return
        nonce = parts[1]
        local_port = int(parts[2])
        local_ip = parts[3] if len(parts) > 3 and parts[3] else "127.0.0.1"
        await self._spawn(self.direct_pipe(nonce, local_ip, local_port))

    async def direct_pipe(self, nonce: str, local_ip: str, local_port: int):
        """明文走裸 socket 快路径（省掉流包装与逐块分配），启用 TLS 时退回包装。"""
        if self.sni:
            await self._direct_stream(nonce, local_ip, local_port)
            return
        loop = asyncio.get_running_loop()
        relay_sock = local_sock = None
        try:
            relay_sock = _nonblock_socket(self.host)
            local_sock = _nonblock_socket(local_ip)
            await asyncio.wait_for(
                loop.sock_connect(relay_sock, _sock_addr(self.host, self.relay_port)), 15)
            await asyncio.wait_for(
                loop.sock_connect(local_sock, _sock_addr(local_ip, local_port)), 15)
            await loop.sock_sendall(relay_sock, f"R {nonce}\n".encode())
        except (OSError, asyncio.TimeoutError) as e:
            print(f"直连通道建立失败（{e}）：{local_ip}:{local_port}")
            _close_sock(relay_sock)
            _close_sock(local_sock)
            return
        _enable_keepalive_sock(relay_sock)
        _enable_keepalive_sock(local_sock)
        self._log_pipe(f"直连通道：公网 ↔ 本机 {local_ip}:{local_port}（nonce {nonce[:8]}）")
        await self._pump_raw(relay_sock, local_sock)

    def _log_pipe(self, text: str):
        """连接级日志限流：前 20 条逐条打印，之后每 100 条一条，海量连接时不刷屏。"""
        self._pipes += 1
        if self._pipes <= 20 or self._pipes % 100 == 0:
            print(f"{text}（累计 {self._pipes} 条直连通道）")

    def _log_pipe_err(self, direction: str, exc: Exception):
        """方向异常收尾：EOF 属正常，其余才值得打印（同样限流）。"""
        if isinstance(exc, (asyncio.IncompleteReadError,)) or not str(exc):
            return
        self._pipe_errs += 1
        if self._pipe_errs <= 20 or self._pipe_errs % 100 == 0:
            print(f"直连方向结束：{direction} {type(exc).__name__}: {exc}"
                  f"（累计 {self._pipe_errs} 次）")

    async def _pump_raw(self, relay_sock, local_sock):
        """裸 socket 双向搬运：起步 64KB 复用缓冲，持续读满自适应加倍到 256KB。

        与中继同款策略：块越大，每 MB 摊到的 read/sendall 与事件唤醒越少；
        流量回落立即缩回起步档，空闲/交互连接的内存占用与原先持平。
        """
        loop = asyncio.get_running_loop()

        async def pump(src, dst, counter, tag):
            buf = bytearray(PIPE_CHUNK)
            full = 0
            try:
                while not self._stopping:
                    n = await loop.sock_recv_into(src, buf)
                    if not n:
                        break
                    if n == len(buf):
                        full += 1
                        # 连续读满说明下游有积压：缓冲翻倍（上限 256KB），
                        # 让每 MB 的系统调用次数随块增大持续下降
                        if full >= 3 and len(buf) < PIPE_CHUNK_MAX:
                            buf = bytearray(min(len(buf) * 4, PIPE_CHUNK_MAX))
                            full = 0
                    else:
                        full = 0
                        # 块明显变小即流量回落，缓冲归还到起步档
                        if len(buf) > PIPE_CHUNK and n < PIPE_CHUNK:
                            buf = bytearray(PIPE_CHUNK)
                    setattr(self.stats, counter, getattr(self.stats, counter) + n)
                    await loop.sock_sendall(dst, memoryview(buf)[:n])
            except (OSError, ConnectionError) as e:
                self._log_pipe_err(tag, e)
            finally:
                _shutdown_write(dst)      # 只半关，保留对向仍在途的数据

        try:
            await asyncio.gather(
                pump(relay_sock, local_sock, "down", "公网→本机"),
                pump(local_sock, relay_sock, "up", "本机→公网"))
        finally:
            _close_sock(relay_sock)
            _close_sock(local_sock)

    async def _direct_stream(self, nonce: str, local_ip: str, local_port: int):
        """TLS 包裹下的直连通道（流包装路径）。"""
        try:
            relay_r, relay_w = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.relay_port,
                                        ssl=ssl_context(self.opt),
                                        server_hostname=self.sni or None,
                                        limit=1 << 20), 15)
        except (OSError, asyncio.TimeoutError) as e:
            print(f"数据面回连失败（{e}），该连接已丢弃")
            return
        _enable_keepalive(relay_w)
        try:
            relay_w.write(f"R {nonce}\n".encode())
            await relay_w.drain()
            local_r, local_w = await asyncio.wait_for(
                asyncio.open_connection(local_ip, local_port, limit=1 << 20), 15)
        except (OSError, asyncio.TimeoutError) as e:
            print(f"本机服务不可达 {local_ip}:{local_port}（{e}）")
            relay_w.close()
            return
        self._log_pipe(f"直连通道：公网 ↔ 本机 {local_ip}:{local_port}（nonce {nonce[:8]}）")
        await self._pump_pair(relay_r, relay_w, local_r, local_w)

    async def _pump_pair(self, relay_r, relay_w, local_r, local_w):
        """两个方向各一个协程纯搬运，不加任何协议头。"""

        async def to_relay():
            try:
                while not self._stopping:
                    chunk = await local_r.read(CHUNK)
                    if not chunk:
                        break
                    self.stats.up += len(chunk)
                    relay_w.write(chunk)
                    await relay_w.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                # 只半关写方向，让对端读到 EOF；直接 close 会 RST 掉对向在途数据
                try:
                    relay_w.write_eof()
                except (AttributeError, OSError, RuntimeError):
                    pass

        async def to_local():
            try:
                while not self._stopping:
                    chunk = await relay_r.read(CHUNK)
                    if not chunk:
                        break
                    self.stats.down += len(chunk)
                    local_w.write(chunk)
                    await local_w.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                try:
                    local_w.write_eof()
                except (AttributeError, OSError, RuntimeError):
                    pass

        try:
            await asyncio.gather(to_relay(), to_local(), return_exceptions=True)
        finally:
            for writer in (relay_w, local_w):
                try:
                    writer.close()
                except Exception:
                    pass

    # ---------- 证书自动续期 ----------

    async def cert_task(self):
        """证书自动续期：剩余天数低于阈值时，经当前会话申请新证书。

        复用同一条已建立的隧道会话（协议支持在控制连接上直接申请），因此不会与
        映射业务抢令牌，也不会因同一账号双会话被服务端拒绝。
        """
        if not self.cert_domain:
            return
        while not self._stopping:
            try:
                await self.ensure_cert()
            except Exception as e:                   # noqa: BLE001
                print(f"证书续期出错：{e}")
            await asyncio.sleep(12 * 3600)

    async def ensure_cert(self):
        threshold = int(getattr(self.opt, "cert_renew_days", 30) or 30)
        crt = self.cert_dir / "tls.crt"
        left = cert_days_left(crt)
        if left >= threshold:
            return
        tip = f"剩余 {left:.0f} 天" if left >= 0 else "本地无有效证书"
        print(f"证书需续期（{tip}，阈值 {threshold} 天），申请 {self.cert_domain} …")
        if await self.renew_cert(self.cert_domain):
            print(f"证书已更新：{crt}（剩余 {cert_days_left(crt):.0f} 天）")

    async def renew_cert(self, domain: str) -> bool:
        """在现有会话上发起申请，等待服务端回传证书。"""
        if not self.writer or self.writer.is_closing():
            return False
        future = asyncio.get_running_loop().create_future()
        self._cert_future = future
        self.writer.write(f"T {domain}\n".encode())
        await self.writer.drain()
        try:
            result = await asyncio.wait_for(future, 300)
        except asyncio.TimeoutError:
            print("等待签发结果超时")
            return False
        finally:
            self._cert_future = None
        if not result:
            return False
        cert, key = result
        try:
            self.cert_dir.mkdir(parents=True, exist_ok=True)
            (self.cert_dir / "tls.crt").write_bytes(cert)
            key_path = self.cert_dir / "tls.key"
            key_path.write_bytes(key)
            os.chmod(key_path, 0o600)
        except OSError as e:
            print(f"证书写入失败：{e}")
            return False
        return True

    def _feed_cert_line(self, line: str) -> bool:
        """把服务端的 CERT/ERRT 文本行交给等待中的续期任务。返回是否已消费。"""
        future = self._cert_future
        if not future or future.done():
            return False
        if line.startswith("CERT "):
            parts = line.split(" ")
            if len(parts) == 3:
                future.set_result((base64.b64decode(parts[1]),
                                   base64.b64decode(parts[2])))
                return True
            future.set_result(None)
            return True
        if line.startswith("ERRT"):
            print("证书申请失败：" + line[4:].strip())
            future.set_result(None)
            return True
        return False

    # ---------- 保活与状态 ----------

    def sla_mark_online(self):
        """连上即开始累计在线时长（SLA = 在线时长 / 运行总时长）。"""
        self.sla.online_since = time.monotonic()

    def sla_mark_offline(self):
        if self.sla.online_since is not None:
            self.sla.online += time.monotonic() - self.sla.online_since
            self.sla.online_since = None
            self.sla.disconnects += 1     # 从在线转为离线才算一次断线

    def sla_percent(self) -> float:
        total = self.sla.up_since and (time.monotonic() - self.sla.up_since) or 0
        online = self.sla.online
        if self.sla.online_since is not None:
            online += time.monotonic() - self.sla.online_since
        return online / total * 100 if total > 0 else 100.0

    async def keepalive(self):
        while not self._stopping:
            await asyncio.sleep(self.opt.ping)
            # 假活检测：链路被中间设备静默丢弃时，写 PING 往往仍“成功”，
            # 且无法收到 PONG；两个周期内无任何下行即判定断开并重连
            if time.monotonic() - self._last_recv > self.opt.ping * 2 + 5:
                print("保活无响应，判定链路已失效，断开重连")
                self.writer.close()
                return
            try:
                self.writer.write(b"PING\n")
                await self.writer.drain()
            except (ConnectionError, OSError):
                return

    async def report(self):
        while not self._stopping:
            await asyncio.sleep(self.opt.stats)
            up, down = self.stats.rates()
            active = sum(1 for conn in self.local.values() if conn)
            print(f"[状态] 映射 {len(self.remote)} 个  活跃连接 {active}  "
                  f"上行 {human_rate(up)}  下行 {human_rate(down)}  "
                  f"累计 ↑{human_bytes(self.stats.up)} ↓{human_bytes(self.stats.down)}  "
                  f"SLA {self.sla_percent():.2f}%（断线 {self.sla.disconnects} 次）")

    # ---------- 关闭 ----------

    async def close(self):
        self._stopping = True
        for cid, local in list(self.local.items()):
            if not local:
                continue
            try:
                local[1].close()
            except Exception:
                pass
        self.local.clear()
        self.pending.clear()
        for task in list(self._tasks):
            task.cancel()
        try:
            self.writer.close()
        except Exception:
            pass


async def request_cert(opt) -> int:
    """一键申请 HTTPS 证书：连上服务端请求签发，落地为本地证书文件。

    前置条件：域名已添加 AAAA 记录，指向本账号的隧道静态地址。
    """
    host, port = parse_server(opt.server)
    ssl_ctx = ssl_context(opt)            # 默认走 TLS（见 effective_sni）
    sni = effective_sni(opt)
    try:
        reader, writer = await asyncio.open_connection(
            host, port, ssl=ssl_ctx, server_hostname=sni or None)
    except OSError as e:
        print(f"连接失败：{e}")
        return 1
    writer.write(b"HELLO " + opt.token.encode() + b"\n")
    await writer.drain()
    hello = (await asyncio.wait_for(reader.readline(), 20)) \
        .decode(errors="replace").strip()
    if hello.startswith("ERRA duplicate"):
        print("该账号已有一条在用会话（另一台设备或残留进程）；"
              "证书申请会单独建立连接，请先停掉对方再申请。")
        writer.close()
        return 1
    if not hello.startswith("OK "):
        print(f"认证失败：{hello or '无响应'}")
        writer.close()
        return 1
    ip6 = hello[3:].strip()
    print(f"已连接 {host}:{port}，静态地址 {ip6}")
    print(f"正在申请证书 {opt.cert}（域名需已解析到 {ip6}，约需 10~60 秒）…")
    writer.write(f"T {opt.cert}\n".encode())
    await writer.drain()
    try:
        while True:
            line = (await asyncio.wait_for(reader.readline(), 240)) \
                .decode(errors="replace").strip()
            if line.startswith("CERT "):
                parts = line.split(" ")
                if len(parts) != 3:
                    print("服务端返回格式异常")
                    return 1
                crt = base64.b64decode(parts[1])
                key = base64.b64decode(parts[2])
                outdir = Path(opt.cert_dir).expanduser()
                outdir.mkdir(parents=True, exist_ok=True)
                crt_path = outdir / "tls.crt"
                key_path = outdir / "tls.key"
                crt_path.write_bytes(crt)
                key_path.write_bytes(key)
                try:
                    os.chmod(key_path, 0o600)
                except OSError:
                    pass
                print(f"证书已保存：\n  {crt_path}\n  {key_path}")
                print("本地服务用这两份文件启用 HTTPS 即可，"
                      "例如 uvicorn/nginx/caddy 直接引用；"
                      "映射 443 端口后公网即可以 https://" + opt.cert + " 访问。")
                return 0
            if line.startswith("ERRT"):
                print("申请失败：" + line[4:].strip())
                return 1
            if not line:
                print("服务端已断开")
                return 1
    except asyncio.TimeoutError:
        print("等待签发结果超时（可稍后重试，acme.sh 可能仍在后台处理）")
        return 1
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def run(opt):
    # SLA 策略：闪断（网络抖动、NAT 表项回收）用 1s/2s/3s 快速重试把恢复时间压到
    # 秒级；连续快速重试仍失败说明是较长的故障，转入指数退避（retry 起步、30s 封顶）
    # 避免服务端过载。SLA 统计跨所有重连共享，状态行持续可见。
    base = max(1, opt.retry)
    sla = SlaStats()
    sla.up_since = time.monotonic()
    fast_left = FAST_RETRIES
    while True:
        client = TunnelClient(opt, sla)
        tasks = []
        try:
            await client.connect()
            client.sla_mark_online()
            fast_left = FAST_RETRIES              # 连上即恢复快速重试额度
            base = max(1, opt.retry)
            if opt.ping:
                tasks.append(asyncio.ensure_future(client.keepalive()))
            if opt.stats:
                tasks.append(asyncio.ensure_future(client.report()))
            if getattr(opt, "cert_domain", ""):
                tasks.append(asyncio.ensure_future(client.cert_task()))
            await client.loop()
            print("连接已断开")
        except DuplicateSession:
            # 重连无意义：账号被另一条会话占用，退避重试仅产生无效日志
            print("该账号已有一条在用会话（另一台设备或残留进程正在连接）。")
            print("同一账号同一时间只允许一条隧道：请先停掉对方，"
                  "或等旧会话约 3 分钟无保活后重试。")
            return
        except (ConnectionError, OSError, asyncio.IncompleteReadError) as e:
            print(f"连接中断：{e}")
        except asyncio.CancelledError:
            raise
        finally:
            client.sla_mark_offline()
            for task in tasks:
                task.cancel()
            await client.close()
        if opt.once:
            return
        if fast_left:
            wait = (1, 2, 3)[FAST_RETRIES - fast_left]
            fast_left -= 1
            print(f"{wait} 秒后快速重连（{FAST_RETRIES - fast_left}/{FAST_RETRIES}）…"
                  f"SLA {client.sla_percent():.2f}%")
        else:
            wait = base
            base = min(base * 2, 30)
            print(f"{wait} 秒后重连…（Ctrl+C 退出）SLA {client.sla_percent():.2f}%"
                  f"（断线 {client.sla.disconnects} 次）")
        await asyncio.sleep(wait)


def load_config(path: str):
    """读取 ini 配置文件，返回与命令行一致的取值（未设置项为 None）。"""
    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")
    node = parser["client"] if parser.has_section("client") else parser.defaults()

    def number(key):
        try:
            return node.getint(key)
        except (configparser.NoOptionError, ValueError):
            return None

    maps = [parse_map(item) for item in node.get("map", "").splitlines() if item.strip()]

    def text(key):
        try:
            return (node.get(key, "") or "").strip()
        except (configparser.NoOptionError, ValueError):
            return ""

    return {
        "server": text("server"),
        "token": text("token"),
        "sni": text("sni"),
        "maps": maps,
        "retry": number("retry"),
        "ping": number("ping"),
        "stats": number("stats"),
        "cert": text("cert"),
        "cert_domain": text("cert_domain"),
        "cert_renew_days": number("cert_renew_days"),
        "cert_dir": text("cert_dir"),
    }


def main():
    _console_utf8()
    parser = argparse.ArgumentParser(
        prog="antipole-tunnel", description="antipoleBGP 隧道客户端（跨平台）",
        epilog=HELP_EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", help="配置文件路径（ini）")
    parser.add_argument("--server", help="接入地址:端口，IPv6 写成 [地址]:端口")
    parser.add_argument("--token", help="隧道用户 Token")
    parser.add_argument("--map", action="append", default=[],
                        help="本地端口映射，可多次：8080 或 127.0.0.1:9000")
    parser.add_argument("--retry", type=int, default=None, help="断线重连间隔秒（默认 5）")
    parser.add_argument("--ping", type=int, default=None,
                        help=f"保活间隔秒（默认 {PING_INTERVAL}，0 关闭）；"
                             f"密心跳保住 NAT 表项并加快断线发现")
    parser.add_argument("--stats", type=int, default=None, help="状态输出间隔秒（默认 10，0 关闭）")
    parser.add_argument("--sni", help="TLS 包裹的 SNI（服务端启用加密时才需要，默认明文 TCP）")
    parser.add_argument("--no-tls", action="store_true",
                        help="强制明文 TCP（默认即明文，保留该开关便于脚本显式声明）")
    parser.add_argument("--relay-port", type=int, default=0,
                        help="数据面回连端口（默认=控制端口+1，即服务端 relay_port）")
    parser.add_argument("--no-direct", action="store_true",
                        help="关闭直连数据面，退回单连接多路复用模式")
    parser.add_argument("--insecure", action="store_true", help="TLS 下跳过证书校验")
    parser.add_argument("--cert", help="一键申请 HTTPS 证书（填写域名，需已解析到本账号静态地址）")
    parser.add_argument("--cert-dir", default=".", help="证书输出目录（默认当前目录）")
    parser.add_argument("--cert-domain",
                        help="开启证书自动续期（填写域名，剩余天数不足时自动重签）")
    parser.add_argument("--cert-renew-days", type=int, default=None,
                        help="证书剩余天数低于该值时自动续期（默认 30）")
    parser.add_argument("--cert-status", action="store_true",
                        help="只查看本地证书剩余天数后退出")
    parser.add_argument("--once", action="store_true", help="只连一次，断开即退出")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    file_cfg = load_config(args.config) if args.config else {}
    for key in ("server", "token", "sni"):
        if not getattr(args, key) and file_cfg.get(key):
            setattr(args, key, file_cfg[key])
    for key, default in (("retry", 5), ("ping", PING_INTERVAL), ("stats", 10)):
        if getattr(args, key) is None:
            value = file_cfg.get(key)
            setattr(args, key, default if value is None else value)
    args.maps = [parse_map(item) for item in args.map] or file_cfg.get("maps") or []
    for key in ("cert", "cert_domain"):
        if not getattr(args, key) and file_cfg.get(key):
            setattr(args, key, file_cfg[key])
    if args.cert_renew_days is None:
        args.cert_renew_days = file_cfg.get("cert_renew_days") or 30
    if not args.cert_dir or args.cert_dir == ".":
        args.cert_dir = file_cfg.get("cert_dir") or args.cert_dir

    if args.cert_status:                 # 只查询本地证书有效期
        left = cert_days_left(Path(args.cert_dir) / "tls.crt")
        if left < 0:
            print(f"未找到可用证书：{Path(args.cert_dir) / 'tls.crt'}")
            sys.exit(1)
        print(f"证书剩余 {left:.0f} 天（自动续期阈值 {args.cert_renew_days} 天）")
        sys.exit(0 if left >= args.cert_renew_days else 2)

    missing = [name for name in ("server", "token") if not getattr(args, name)]
    if args.cert:                       # 证书模式：只需账号，不需要端口映射
        if missing:
            parser.error("缺少必填项：" + "、".join(f"--{n}" for n in missing))
        try:
            sys.exit(asyncio.run(request_cert(args)))
        except KeyboardInterrupt:
            print("\n已取消")
    if missing or not args.maps:
        parser.error("缺少必填项：" + "、".join(
            ([f"--{n}" for n in missing] + ([] if args.maps else ["--map"]))))

    try:
        asyncio.run(_main(args))
    except KeyboardInterrupt:
        print("\n已退出")


async def _main(args):
    loop = asyncio.get_running_loop()
    task = asyncio.ensure_future(run(args))
    if hasattr(signal, "SIGTERM"):        # Windows 无 SIGTERM，Ctrl+C 即可
        try:
            loop.add_signal_handler(signal.SIGTERM, task.cancel)
        except (NotImplementedError, RuntimeError):
            pass
    print(f"antipole 隧道客户端 v{__version__}  映射端口 {len(args.maps)} 个")
    try:
        await task
    except asyncio.CancelledError:
        print("收到终止信号，已退出")


if __name__ == "__main__":
    main()