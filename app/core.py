# -*- coding: utf-8 -*-
"""
基础设施层（整合）：配置装载、进程互斥锁、SQLite 存储、IPv6 地址池、命令执行。

设计目标：把与业务无关的底层能力集中在单一模块，上层（网络/边缘/管理）只依赖本模块，
避免碎片化。全部能力均为可重入、可并发调用。

并发模型：
  - 数据库：单连接 + WAL + 线程锁，写操作微秒级，不阻塞事件循环；
  - 流量计数：内存累加 + 定时批量落库，避免高并发下每包写库；
  - 进程锁：flock 实现，服务端持共享锁、CLI 持独占锁，contextvars 保证任务级隔离。
"""
import asyncio
import contextlib
import contextvars
import copy
import ipaddress
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import yaml

# ============================================================
# 一、配置
# ============================================================

# 敏感域名默认清单：这些站点对 WARP 共享 v4 段有风控策略，强制走用户自有 v6 出口。
# 仅收录双栈服务（纯 v4 域名强制走 v6 会失败）。使用 domain: 前缀匹配主域与子域。
DEFAULT_SENSITIVE_DOMAINS = [
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
    "facebook.com", "fbsbx.com", "fb.com", "instagram.com",
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
    # Cloudflare 管理面
    "cloudflare.com", "cloudflareinsights.com",
]

DEFAULTS = {
    "server": {
        "host": "::",
        "port": 9090,
        "admin_token": "change-me",
        "view_token": "",
        "admin_allow": [],
        "register_enabled": False,     # 自助注册服务开关（默认关闭）
        "register_port": 18290,        # 自助注册监听端口
        "public_ip": "",               # 对外公布的接入地址（留空自动探测）
    },
    "network": {
        "prefix": "2001:db8:abcd::/48",   # 已 BGP 广播的前缀（建议 /48，允许 /32~/64）
        "wg_iface": "wg0",
        "wg_port": 51820,
        "wg_addr": "fd00:1::1/64",
        "wg_v4_addr": "10.7.0.1/24",
        "internal_net": "fd00:1::/64",
        "route_table_base": 100,
        "warp_mark": 4096,
        "warp_table": 51820,
        "user_mark_base": 0x40000000,
        "tc_enabled": True,
        "tc_wan": "",
        "ranges": {},                  # 命名网段 {名称: 前缀}，多业务分段
        "tunnel_range": "",            # 隧道专属网段，留空自动取主前缀最后一个 /56
        "guard_allocated": True,       # 仅允许已分配地址路由到本机（地址独立性）
        "guard_extra_allow": [],       # 地址守护额外放行（如本机承载的其他业务地址）
    },
    "tunnel": {
        "enabled": False,              # TCP 端口映射隧道开关（默认关闭）
        "port": 18281,                 # 控制端口
        # 控制面/数据面监听地址：留空 = 收敛到本机业务地址（隧道接入地址 + 主地址
        # + IPv4），不在用户 /128 上占端口；显式填写（逗号分隔）则以其为准，
        # "::" 为全地址通配。
        "listen": "",
        "range": "tunnel",             # 隧道用户所属命名网段
        "bind": "",                    # 用户端口监听基址（留空 = 用户静态地址，端口 1:1）
        "sni": "",                     # TLS 包裹时的 SNI（留空不启用 TLS）
        "cert": "",                    # TLS 证书路径（与 sni 配合）
        "key": "",
        # 反滥用阈值：面向"单用户数万连接"的规模放宽（连接本身很便宜：
        # 中继侧空闲连接仅 4KB 缓冲），异常时仍可由熔断/封禁兜底
        "max_conns_per_user": 0,       # 单用户并发连接上限（0 = 不限）
        "conn_rate_per_user": 0,       # 单用户新建连接速率（个/秒，0 = 不限）
        "frame_max": 1048576,          # 单帧载荷上限（仅长度保护，不做内容检查）
        "bulk_pause_ms": 4,            # 大流量聚批读取的停读毫秒数（0 = 关闭）
        # 数据面中继：转发字节交给编译语言进程（splice 直搬），控制面仍在本进程；
        # relay_bin 留空即关闭该能力，老客户端与老路径不受影响。
        "relay_bin": "bin/antipole-relay",
        "relay_sock": "/run/antipole-relay.sock",
        "relay_port": 18282,           # 客户端回连端口（公网需放行）
        "idle_timeout": 300,           # 空闲连接回收（秒）
        # 端口策略：用户 /128 之间、用户与主机之间互不干扰，端口默认全开
        # （1-65535），能否使用只看物理占用——端口若被主机以 IPv6 通配地址占用
        # （如 sshd 的 22、nginx 的 443），用户绑不上，会给出明确原因。
        # min_port / deny_ports 保留为可选的收紧开关。
        "min_port": 1,
        "deny_ports": [],
    },
    # 地址与账户绑定：分配的 /128 永久不变，默认不做轮换。
    # 仅在明确需要"出口调度"时才把 enabled 打开；隧道用户的地址是端口映射与证书的锚点，
    # 任何情况下都不参与轮换。
    "rotation": {"enabled": False, "min_interval": 1800, "max_interval": 7200,
                 "start_seq": 1},
    "xray": {
        "enabled": True,
        "bin": "/usr/local/bin/xray",
        "conf": "/etc/antipole/xray.json",
        "port": 80,
        "api_port": 10085,
        "sni_dest": "www.apple.com",
        "dest_ip": "",
        "ufp": "chrome",
        "fallback": "",
        "acme_port": 18081,            # ACME 校验文件服务（经 :80 回落链对外）
        "acme_webroot": "/etc/antipole/acme-webroot",
        "sensitive_domains": list(DEFAULT_SENSITIVE_DOMAINS),
        "trojan": {"enabled": False, "port": 2054, "cert": "", "key": ""},
    },
    "warp": {
        "enabled": True,
        "wgcf": "/usr/local/bin/wgcf",
        "iface": "wg-warp",
        "profile": "/etc/antipole/warp-profile.conf",
        "profiles": [],
        "endpoints": [],
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
        "auth_fails": 8,                  # 隧道控制面同一来源认证失败次数上限
        "auth_window_s": 300,             # 认证失败计数窗口（秒）
        "auth_ban_s": 900,                # 隧道爆破来源封禁时长（秒）
        "conn_burst_per_min": 60,         # 同一来源每分钟新建控制连接上限
        "register_per_hour": 3,
        "register_global_per_hour": 60,   # 全局注册速率上限（每小时）
        "default_quota_mb": 0,
        "default_mbps": 0,
        "quota_check_s": 10,
        "quota_warn_pct": 90,
        "protect_mbps": 1,                # 触发熔断后的保护带宽（Mbps）
        "protect_s": 600,                 # 熔断保护时长（秒）
        "ban_s": 1800,                    # 滥用来源封禁时长（秒）
    },
    "alerts": {"webhook": "", "cert_days": 14},
    "db": {"path": "/etc/antipole/data.sqlite3", "keys_dir": "/etc/antipole/keys"},
}


def _merge(base: dict, override: dict):
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path: str) -> dict:
    """装载配置：默认值 + 用户覆盖（深合并）。

    使用深拷贝，避免嵌套字典被多份配置共享而互相污染默认值。
    """
    cfg = copy.deepcopy(DEFAULTS)
    p = Path(path)
    if p.exists():
        _merge(cfg, yaml.safe_load(p.read_text(encoding="utf-8")) or {})
    return normalize(cfg)


def normalize(cfg: dict) -> dict:
    """规范化配置：前缀取规范形式、派生命名网段池、补齐隧道段与默认值。"""
    nc = cfg["network"]
    net6 = ipaddress.IPv6Network(nc["prefix"], strict=False)
    nc["prefix"] = str(net6)          # 归一化，避免带主机位的前缀造成显示与地址池不一致
    ranges = dict(nc.get("ranges") or {})
    ranges.setdefault("", str(net6))
    tunnel_range = (nc.get("tunnel_range") or "").strip()
    if not tunnel_range and net6.prefixlen <= 56:
        # 默认保留主前缀最后一个 /56 作为隧道业务专属段（空白保留）
        tunnel_range = str(list(net6.subnets(new_prefix=56))[-1])
    if tunnel_range:
        ranges["tunnel"] = tunnel_range
    nc["ranges"] = ranges
    nc["tunnel_range"] = tunnel_range
    cfg["tunnel"].setdefault("range", "tunnel")
    return cfg


def save_config(cfg: dict, path: str = None):
    """写回配置文件（保持 600 权限）。"""
    target = Path(path or cfg.get("_path") or "/etc/antipole/config.yaml")
    data = {k: v for k, v in cfg.items() if not k.startswith("_")}
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
                      encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


# ============================================================
# 二、进程互斥锁
# ============================================================

try:
    import fcntl
    _LOCK_SH, _LOCK_EX = fcntl.LOCK_SH, fcntl.LOCK_EX
except ImportError:          # 非 Linux（开发机）降级为无操作
    fcntl = None
    _LOCK_SH, _LOCK_EX = 1, 2

_stack = contextvars.ContextVar("antipole_mutex_stack", default=None)


class Mutex:
    """进程级文件锁：服务端持共享锁、CLI 持独占锁，同任务内可重入。"""

    def __init__(self, path: str, timeout: float = 60.0):
        self.path = Path(path)
        self.timeout = timeout

    def _open(self) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        return os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)

    def _lock(self, fd: int, mode: int):
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"等锁超时: {self.path} "
                        f"({'SH' if mode == _LOCK_SH else 'EX'})")
                time.sleep(0.05)

    @contextlib.contextmanager
    def shared(self):
        with self._acquire(_LOCK_SH):
            yield

    @contextlib.contextmanager
    def exclusive(self):
        with self._acquire(_LOCK_EX):
            yield

    @contextlib.contextmanager
    def _acquire(self, mode: int):
        if fcntl is None:
            yield
            return
        st = _stack.get()
        created = st is None
        if created:
            st = []
            _stack.set(st)
        if not st or mode > st[-1][1]:
            fd = self._open()
            self._lock(fd, mode)
            st.append((fd, mode))
        try:
            yield
        finally:
            if st and st[-1][1] == mode:
                fd, _ = st.pop()
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
            if created and not st:
                _stack.set(None)


_mutex = None


def setup_mutex(cfg: dict):
    global _mutex
    _mutex = Mutex(str(Path(cfg["db"]["path"]).parent / ".antipole.lock"))


def tx() -> Mutex:
    """全局互斥锁：服务端写内核/库时持 shared，CLI 整条命令持 exclusive。"""
    return _mutex


# ============================================================
# 三、SQLite 存储
# ============================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT UNIQUE NOT NULL,
    internal_ip   TEXT NOT NULL,
    egress_ip     TEXT NOT NULL,
    rotate_seq    INTEGER NOT NULL,
    pubkey        TEXT NOT NULL,
    privkey       TEXT NOT NULL,
    uuid          TEXT NOT NULL,
    quota_mb      INTEGER NOT NULL DEFAULT 0,     -- 代理/隧道统一配额，0 = 不限
    used_up       INTEGER NOT NULL DEFAULT 0,
    used_down     INTEGER NOT NULL DEFAULT 0,
    max_mbps      INTEGER NOT NULL DEFAULT 0,     -- 统一带宽上限，0 = 不限
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    range_name    TEXT NOT NULL DEFAULT '',       -- 所属命名网段
    password_hash TEXT NOT NULL DEFAULT '',       -- 注册口令哈希
    protect_until INTEGER NOT NULL DEFAULT 0,     -- 反滥用熔断截止时间戳
    note          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled);
CREATE TABLE IF NOT EXISTS tunnel_users (
    user_id    INTEGER PRIMARY KEY,
    token      TEXT UNIQUE NOT NULL,
    port_count INTEGER NOT NULL DEFAULT 0,        -- 已声明的映射端口数
    quota_mb   INTEGER NOT NULL DEFAULT 0,        -- 隧道独立配额（0 = 跟随 users）
    used_bytes INTEGER NOT NULL DEFAULT 0,
    max_mbps   INTEGER NOT NULL DEFAULT 0,        -- 隧道独立限速（0 = 跟随 users）
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tunnel_maps (
    user_id     INTEGER NOT NULL,
    local_port  INTEGER NOT NULL,
    local_ip    TEXT NOT NULL DEFAULT '127.0.0.1',
    remote_port INTEGER NOT NULL,                 -- 等于 local_port（端口 1:1 对应）
    PRIMARY KEY(user_id, local_port)
);
CREATE TABLE IF NOT EXISTS invites (
    code       TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    used_by    TEXT
);
CREATE TABLE IF NOT EXISTS domains (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT UNIQUE NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    port       INTEGER NOT NULL DEFAULT 0,
    note       TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    cert_crt   TEXT NOT NULL DEFAULT '',
    cert_key   TEXT NOT NULL DEFAULT '',
    cert_at    INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS abuse_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    subject    TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_abuse_ts ON abuse_events(ts);
CREATE TABLE IF NOT EXISTS runtime_stats (
    user_id   INTEGER PRIMARY KEY,                -- 运行时健康与速率快照（供 CLI/API 读取）
    ts        INTEGER NOT NULL,
    up_bps    INTEGER NOT NULL DEFAULT 0,         -- 上行速率（字节/秒）
    down_bps  INTEGER NOT NULL DEFAULT 0,         -- 下行速率（字节/秒）
    conns     INTEGER NOT NULL DEFAULT 0,         -- 隧道并发连接数
    online    INTEGER NOT NULL DEFAULT 0,         -- WG 是否在线（300 秒内有握手）
    tunnel_on INTEGER NOT NULL DEFAULT 0,         -- 隧道会话是否在线
    ports     INTEGER NOT NULL DEFAULT 0          -- 已映射端口数
);
"""

_conn = None
_lock = threading.Lock()
_traffic_buf = {}          # uid -> [up, down] 待落库缓冲
_tunnel_buf = {}           # uid -> bytes 待落库缓冲


def init(db_path: str):
    global _conn
    _conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")
    _conn.execute("PRAGMA busy_timeout=8000")
    _conn.execute("PRAGMA cache_size=-8000")
    _conn.row_factory = sqlite3.Row
    _conn.executescript(SCHEMA)
    _upgrade()
    _conn.commit()
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        pass


def _upgrade():
    """旧库补列/补表，已存在则跳过。

    注意：涉及新增列的索引必须在此处（补列之后）创建，
    否则旧库在 SCHEMA 阶段会因列不存在而失败。
    """
    cols = {
        "users": [("uuid", "TEXT NOT NULL DEFAULT ''"),
                  ("quota_mb", "INTEGER NOT NULL DEFAULT 0"),
                  ("used_up", "INTEGER NOT NULL DEFAULT 0"),
                  ("used_down", "INTEGER NOT NULL DEFAULT 0"),
                  ("max_mbps", "INTEGER NOT NULL DEFAULT 0"),
                  ("range_name", "TEXT NOT NULL DEFAULT ''"),
                  ("password_hash", "TEXT NOT NULL DEFAULT ''"),
                  ("protect_until", "INTEGER NOT NULL DEFAULT 0"),
                  ("note", "TEXT NOT NULL DEFAULT ''")],
        "domains": [("cert_crt", "TEXT NOT NULL DEFAULT ''"),
                    ("cert_key", "TEXT NOT NULL DEFAULT ''"),
                    ("cert_at", "INTEGER NOT NULL DEFAULT 0")],
    }
    for table, items in cols.items():
        existing = {r[1] for r in _conn.execute(f"PRAGMA table_info({table})")}
        for name, ddl in items:
            if name not in existing:
                _conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
    # 依赖新增列的索引：必须在补列完成后创建
    _conn.execute("CREATE INDEX IF NOT EXISTS idx_users_range ON users(range_name)")


@contextmanager
def db_cursor():
    with _lock:
        cursor = _conn.cursor()
        yield cursor
        _conn.commit()


def raw_conn():
    """返回底层连接（供注册服务等直接使用，需自行加锁）。"""
    return _conn


def now_ms() -> int:
    return int(time.time() * 1000)


# ---------- 用户 ----------

def list_users():
    with db_cursor() as cursor:
        return [dict(r) for r in cursor.execute("SELECT * FROM users ORDER BY id")]


def list_enabled_users():
    with db_cursor() as cursor:
        return [dict(r) for r in cursor.execute(
            "SELECT * FROM users WHERE enabled=1 ORDER BY id")]


def get_user(user_id: int):
    with db_cursor() as cursor:
        row = cursor.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_name(name: str):
    with db_cursor() as cursor:
        row = cursor.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
    return dict(row) if row else None


def add_user(user_id, name, internal_ip, egress_ip, seq, pubkey, privkey, uuid,
             quota_mb=0, max_mbps=0, range_name=""):
    """插入用户记录。

    id 由调用方显式指定：内网地址、路由表号、限速类号均由 id 派生，
    若交给自增主键决定，历史删除过的库会出现预测 id 与实际 id 不一致。
    """
    with db_cursor() as cursor:
        cursor.execute(
            "INSERT INTO users(id,name,internal_ip,egress_ip,rotate_seq,pubkey,privkey,"
            "uuid,quota_mb,max_mbps,enabled,created_at,range_name) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?)",
            (user_id, name, internal_ip, egress_ip, seq, pubkey, privkey, uuid,
             quota_mb, max_mbps, now_ms(), range_name))


def update_user(user_id: int, **fields):
    whitelist = {"name", "egress_ip", "rotate_seq", "pubkey", "privkey", "uuid",
                 "quota_mb", "used_up", "used_down", "max_mbps", "enabled",
                 "range_name", "password_hash", "protect_until", "note"}
    sets, args = [], []
    for k, v in fields.items():
        if k in whitelist:
            sets.append(f"{k}=?")
            args.append(v)
    if not sets:
        return
    args.append(user_id)
    with db_cursor() as cursor:
        cursor.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", args)


def delete_user(user_id: int):
    with db_cursor() as cursor:
        cursor.execute("DELETE FROM tunnel_maps WHERE user_id=?", (user_id,))
        cursor.execute("DELETE FROM tunnel_users WHERE user_id=?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id=?", (user_id,))


def next_user_id() -> int:
    with db_cursor() as cursor:
        row = cursor.execute("SELECT MAX(id) m FROM users").fetchone()
        return (row["m"] or 0) + 1


def used_egress_ips(exclude_user_id: int = None):
    """已占用的出口地址，含保留地址（本机地址、其他业务地址），确保分配不冲突。"""
    with db_cursor() as cursor:
        if exclude_user_id:
            rows = cursor.execute("SELECT egress_ip FROM users WHERE id!=?",
                                  (exclude_user_id,))
        else:
            rows = cursor.execute("SELECT egress_ip FROM users")
        taken = {r[0] for r in rows}
    taken |= _reserved_addrs
    return taken


# 保留地址（由网络层在启动时注入：本机全部 IPv6 地址 + 额外放行项）
_reserved_addrs = set()


def set_reserved(addrs):
    """登记需避让的地址（既不被分配给用户，也始终允许路由至本机）。"""
    _reserved_addrs.clear()
    _reserved_addrs.update(a for a in (addrs or set()) if a)


def reserved_addrs() -> set:
    return set(_reserved_addrs)


# ---------- 流量计数（内存缓冲 + 批量落库） ----------

def buffer_traffic(user_id: int, up: int, down: int):
    """累加到内存缓冲，由 flush_traffic() 定时批量写库。"""
    cur = _traffic_buf.get(user_id)
    if cur is None:
        _traffic_buf[user_id] = [up, down]
    else:
        cur[0] += up
        cur[1] += down


def buffer_tunnel_bytes(user_id: int, n: int):
    _tunnel_buf[user_id] = _tunnel_buf.get(user_id, 0) + n


def flush_traffic():
    """把缓冲的流量计数批量落库（单事务，避免高并发逐条写）。"""
    with _lock:
        if not _traffic_buf and not _tunnel_buf:
            return
        tb, nb = dict(_traffic_buf), dict(_tunnel_buf)
        _traffic_buf.clear()
        _tunnel_buf.clear()
        try:
            cursor = _conn.cursor()
            for uid, (up, down) in tb.items():
                cursor.execute(
                    "UPDATE users SET used_up=used_up+?, used_down=used_down+? WHERE id=?",
                    (up, down, uid))
            for uid, n in nb.items():
                cursor.execute(
                    "UPDATE tunnel_users SET used_bytes=used_bytes+? WHERE user_id=?",
                    (n, uid))
            _conn.commit()
        except sqlite3.Error:
            # 落库失败则回滚缓冲，下一轮重试，避免计数丢失
            for uid, (up, down) in tb.items():
                cur = _traffic_buf.setdefault(uid, [0, 0])
                cur[0] += up
                cur[1] += down
            for uid, n in nb.items():
                _tunnel_buf[uid] = _tunnel_buf.get(uid, 0) + n


def add_traffic(user_id: int, up: int, down: int):
    """立即落库（CLI/低并发路径使用）。"""
    with db_cursor() as cursor:
        cursor.execute(
            "UPDATE users SET used_up=used_up+?, used_down=used_down+? WHERE id=?",
            (up, down, user_id))


# ---------- 隧道用户 ----------

def add_tunnel_user(user_id: int, token: str,
                    quota_mb: int = 0, max_mbps: int = 0):
    with db_cursor() as cursor:
        cursor.execute(
            "INSERT OR REPLACE INTO tunnel_users(user_id,token,port_count,"
            "quota_mb,used_bytes,max_mbps,created_at) VALUES(?,?,0,?,0,?,?)",
            (user_id, token, quota_mb, max_mbps, now_ms()))


def get_tunnel_user(user_id: int):
    with db_cursor() as cursor:
        row = cursor.execute(
            "SELECT t.*, u.name AS user_name, u.enabled AS user_enabled, "
            "u.egress_ip, u.range_name, u.quota_mb AS user_quota_mb, "
            "u.max_mbps AS user_max_mbps, u.protect_until "
            "FROM tunnel_users t JOIN users u ON u.id=t.user_id WHERE t.user_id=?",
            (user_id,)).fetchone()
    return dict(row) if row else None


def get_tunnel_user_by_token(token: str):
    with db_cursor() as cursor:
        row = cursor.execute(
            "SELECT t.*, u.name AS user_name, u.enabled AS user_enabled, "
            "u.egress_ip, u.range_name, u.quota_mb AS user_quota_mb, "
            "u.max_mbps AS user_max_mbps, u.protect_until "
            "FROM tunnel_users t JOIN users u ON u.id=t.user_id WHERE t.token=?",
            (token,)).fetchone()
    return dict(row) if row else None


def list_tunnel_users():
    with db_cursor() as cursor:
        return [dict(r) for r in cursor.execute(
            "SELECT t.*, u.name AS user_name, u.enabled AS user_enabled, "
            "u.egress_ip, u.range_name, u.quota_mb AS user_quota_mb, "
            "u.max_mbps AS user_max_mbps "
            "FROM tunnel_users t JOIN users u ON u.id=t.user_id ORDER BY t.user_id")]


def update_tunnel_user(user_id: int, **fields):
    whitelist = {"token", "port_count", "quota_mb", "used_bytes", "max_mbps"}
    sets, args = [], []
    for k, v in fields.items():
        if k in whitelist:
            sets.append(f"{k}=?")
            args.append(v)
    if not sets:
        return
    args.append(user_id)
    with db_cursor() as cursor:
        cursor.execute(f"UPDATE tunnel_users SET {','.join(sets)} WHERE user_id=?", args)


def add_tunnel_map(user_id: int, local_port: int, remote_port: int,
                   local_ip: str = "127.0.0.1"):
    with db_cursor() as cursor:
        cursor.execute(
            "INSERT OR REPLACE INTO tunnel_maps(user_id,local_port,local_ip,remote_port) "
            "VALUES(?,?,?,?)", (user_id, local_port, local_ip, remote_port))


def list_tunnel_maps(user_id: int = None):
    with db_cursor() as cursor:
        if user_id is None:
            rows = cursor.execute("SELECT * FROM tunnel_maps ORDER BY user_id, local_port")
        else:
            rows = cursor.execute(
                "SELECT * FROM tunnel_maps WHERE user_id=? ORDER BY local_port", (user_id,))
        return [dict(r) for r in rows]


# ---------- 邀请码 ----------

def add_invite(code: str):
    with db_cursor() as cursor:
        cursor.execute("INSERT INTO invites(code,created_at,used) VALUES(?,?,0)",
                       (code, now_ms()))
        return code


def list_invites():
    with db_cursor() as cursor:
        return [dict(r) for r in cursor.execute(
            "SELECT * FROM invites ORDER BY created_at DESC")]


def consume_invite(code: str, used_by: str) -> bool:
    """原子消费邀请码：成功返回 True，已用/不存在返回 False。"""
    with db_cursor() as cursor:
        cursor.execute("UPDATE invites SET used=1, used_by=? WHERE code=? AND used=0",
                       (used_by, code))
        return cursor.rowcount > 0


# ---------- 接入域名 ----------

def list_domains():
    with db_cursor() as cursor:
        return [dict(r) for r in cursor.execute("SELECT * FROM domains ORDER BY id")]


def get_domain(domain_id: int):
    with db_cursor() as cursor:
        row = cursor.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
    return dict(row) if row else None


def add_domain(domain: str, ip: str = "", port: int = 0, note: str = ""):
    with db_cursor() as cursor:
        cursor.execute("INSERT INTO domains(domain,ip,port,note,enabled,created_at) "
                       "VALUES(?,?,?,?,1,?)", (domain, ip, port, note, now_ms()))
        return cursor.lastrowid


def update_domain(domain_id: int, **fields):
    whitelist = {"domain", "ip", "port", "note", "enabled",
                 "cert_crt", "cert_key", "cert_at"}
    sets, args = [], []
    for k, v in fields.items():
        if k in whitelist:
            sets.append(f"{k}=?")
            args.append(v)
    if not sets:
        return
    args.append(domain_id)
    with db_cursor() as cursor:
        cursor.execute(f"UPDATE domains SET {','.join(sets)} WHERE id=?", args)


def delete_domain(domain_id: int):
    with db_cursor() as cursor:
        cursor.execute("DELETE FROM domains WHERE id=?", (domain_id,))


def primary_domain():
    for d in list_domains():
        if d["enabled"]:
            return d
    return None


# ---------- 滥用事件 ----------

def log_abuse(kind: str, subject: str, detail: str = ""):
    with db_cursor() as cursor:
        cursor.execute("INSERT INTO abuse_events(ts,kind,subject,detail) VALUES(?,?,?,?)",
                       (now_ms(), kind, subject, detail))


def list_abuse(limit: int = 50):
    with db_cursor() as cursor:
        return [dict(r) for r in cursor.execute(
            "SELECT * FROM abuse_events ORDER BY id DESC LIMIT ?", (limit,))]


def prune_abuse(keep_days: int = 7):
    cutoff = now_ms() - keep_days * 86400 * 1000
    with db_cursor() as cursor:
        cursor.execute("DELETE FROM abuse_events WHERE ts < ?", (cutoff,))


# ---------- 运行时状态快照 ----------

def set_runtime_stat(user_id: int, up_bps: int = 0, down_bps: int = 0,
                     conns: int = 0, online: int = 0, tunnel_on: int = 0,
                     ports: int = 0):
    with db_cursor() as cursor:
        cursor.execute(
            "INSERT INTO runtime_stats(user_id,ts,up_bps,down_bps,conns,online,"
            "tunnel_on,ports) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET ts=excluded.ts, "
            "up_bps=excluded.up_bps, down_bps=excluded.down_bps, "
            "conns=excluded.conns, online=excluded.online, "
            "tunnel_on=excluded.tunnel_on, ports=excluded.ports",
            (user_id, now_ms(), up_bps, down_bps, conns, online, tunnel_on, ports))


def list_runtime_stats() -> dict:
    with db_cursor() as cursor:
        rows = cursor.execute("SELECT * FROM runtime_stats").fetchall()
    return {row["user_id"]: dict(row) for row in rows}


def clear_runtime_stats():
    with db_cursor() as cursor:
        cursor.execute("DELETE FROM runtime_stats")


def clear_runtime_stat(user_id: int):
    """删除单个用户的运行时快照（用户被彻底删除时调用）。"""
    with db_cursor() as cursor:
        cursor.execute("DELETE FROM runtime_stats WHERE user_id=?", (user_id,))


# ============================================================
# 四、命令执行
# ============================================================

async def cmd(*args, check=True, stdin=None, timeout=15, cwd=None) -> str:
    """执行系统命令，带超时；超时终止进程并抛错，避免阻塞事件循环。"""
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd)
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(input=stdin.encode() if stdin else None), timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise RuntimeError(f"{' '.join(args)} 超时")
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} 失败: "
                           f"{err.decode(errors='replace').strip()[:200]}")
    return out.decode(errors="replace").strip()


def have_bin(name: str) -> bool:
    """命令是否存在于 PATH。"""
    return any(Path(p).joinpath(name).exists()
               for p in os.environ.get("PATH", "").split(os.pathsep) if p)


# ============================================================
# 五、IPv6 地址池（多命名网段）
# ============================================================

def _mix_seq(s: int) -> int:
    """splitmix64 位混合：相邻序号映射到离散地址，双射且无状态。"""
    s = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    s ^= s >> 30
    s = (s * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    s ^= s >> 27
    s = (s * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    s ^= s >> 31
    return s & 0xFFFFFFFFFFFFFFFF


class V6Pool:
    """地址池：在给定前缀内为序号派生唯一 /128 地址（建议 /48，允许 /32~/64）。"""

    def __init__(self, prefix: str, start_seq: int = 1):
        network = ipaddress.IPv6Network(prefix, strict=False)
        if network.prefixlen > 64:
            raise ValueError(
                f"前缀过短: /{network.prefixlen}，可用地址不足，请使用 /64 或更短（如 /48）")
        self.network = network
        self.start_seq = start_seq

    def addr(self, seq: int) -> str:
        mixed = _mix_seq(seq)
        base = int(self.network.network_address)
        host_bits = 128 - self.network.prefixlen
        value = base | (mixed & ((1 << host_bits) - 1))
        groups = [(value >> (112 - 16 * i)) & 0xFFFF for i in range(8)]
        return ":".join(f"{g:x}" for g in groups)


_pools = {}
_default_pool = None
_start_seq = 1


def setup_pools(cfg: dict):
    """初始化全部命名网段池。"""
    global _default_pool, _start_seq
    _pools.clear()
    _default_pool = None
    _start_seq = int(cfg["rotation"].get("start_seq", 1))
    ranges = cfg["network"].get("ranges") or {}
    for name, prefix in ranges.items():
        if not prefix:
            continue
        try:
            pool = V6Pool(prefix, _start_seq)
        except ValueError as e:
            print(f"[core] 网段 {name or '主段'}({prefix}) 初始化失败: {e}")
            continue
        _pools[name] = pool
        if name == "":
            _default_pool = pool
    if _default_pool is None and _pools:
        _default_pool = next(iter(_pools.values()))


def pool(name: str = "") -> V6Pool:
    """取指定命名网段的地址池；不存在则回退默认段。"""
    if name and name in _pools:
        return _pools[name]
    if _default_pool is None:
        raise RuntimeError("地址池未初始化")
    return _default_pool


def addr_for(name: str, seq: int) -> str:
    return pool(name).addr(seq)


def alloc_egress(range_name: str, taken: set = None) -> tuple:
    """在指定网段内分配一个未被占用的出口地址，返回 (地址, 序号)。"""
    taken = taken if taken is not None else used_egress_ips()
    seq = _start_seq
    while True:
        candidate = addr_for(range_name or "", seq)
        if candidate not in taken:
            return candidate, seq
        seq += 1


def range_of(addr: str):
    """判断某地址属于哪个命名网段（取最长前缀匹配，避免被父网段吞掉）。"""
    try:
        target = ipaddress.IPv6Address(addr)
    except ValueError:
        return None
    best_name = None
    best_len = -1
    for name, pool_obj in _pools.items():
        if target in pool_obj.network and pool_obj.network.prefixlen > best_len:
            best_name = name
            best_len = pool_obj.network.prefixlen
    return best_name


def internal_ip(user_id: int) -> str:
    return f"fd00:1::{user_id:x}"


def internal_v4(user_id: int) -> str:
    return f"10.7.0.{user_id}" if 1 <= user_id <= 254 else ""


# ============================================================
# 六、口令哈希
# ============================================================

def hash_password(password: str) -> str:
    import hashlib
    return hashlib.sha256(("antipole$" + password).encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    import hmac
    return bool(hashed) and hmac.compare_digest(hash_password(password), hashed)