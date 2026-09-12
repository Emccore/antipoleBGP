# -*- coding: utf-8 -*-
"""
SQLite 存储：用户 / 邀请码 / 接入域名。
单连接 + WAL，写少读多。所有写操作共用同一把锁，操作均为微秒级，事件循环不会被阻塞。
"""
import sqlite3
import threading
import time
from contextlib import contextmanager

_lock = threading.Lock()
_conn = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,  -- AUTOINCREMENT: id 不在删除后复用，路由表号/内网地址才不串
    name        TEXT UNIQUE NOT NULL,
    internal_ip TEXT NOT NULL,
    egress_ip   TEXT NOT NULL,
    rotate_seq  INTEGER NOT NULL,
    pubkey      TEXT NOT NULL,
    privkey     TEXT NOT NULL,
    uuid        TEXT NOT NULL,
    quota_mb    INTEGER NOT NULL DEFAULT 0,     -- 流量配额，0 = 不限
    used_up     INTEGER NOT NULL DEFAULT 0,
    used_down   INTEGER NOT NULL DEFAULT 0,
    max_mbps    INTEGER NOT NULL DEFAULT 0,     -- 带宽上限 Mbps，0 = 不限
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled);
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
    cert_crt   TEXT NOT NULL DEFAULT '',    -- ACME 证书路径（全链）
    cert_key   TEXT NOT NULL DEFAULT '',
    cert_at    INTEGER NOT NULL DEFAULT 0,  -- 申请时间戳
    created_at INTEGER NOT NULL
);
"""


def init(db_path: str):
    global _conn
    _conn = sqlite3.connect(db_path, check_same_thread=False, timeout=5)
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")
    _conn.execute("PRAGMA busy_timeout=5000")
    _conn.row_factory = sqlite3.Row
    _conn.executescript(SCHEMA)
    _upgrade()
    _conn.commit()
    # 数据库存储用户私钥，文件权限必须收紧（644 权限下任意用户均可读取）
    try:
        import os
        os.chmod(db_path, 0o600)
    except OSError:
        pass


def _upgrade():
    """为旧版本数据库补充缺失列，已存在则跳过。"""
    for table, cols in (
        ("users", [("uuid", "ALTER TABLE users ADD COLUMN uuid TEXT NOT NULL DEFAULT ''"),
                   ("quota_mb", "ALTER TABLE users ADD COLUMN quota_mb INTEGER NOT NULL DEFAULT 0"),
                   ("used_up", "ALTER TABLE users ADD COLUMN used_up INTEGER NOT NULL DEFAULT 0"),
                   ("used_down", "ALTER TABLE users ADD COLUMN used_down INTEGER NOT NULL DEFAULT 0"),
                   ("max_mbps", "ALTER TABLE users ADD COLUMN max_mbps INTEGER NOT NULL DEFAULT 0")]),
        ("domains", [("cert_crt", "ALTER TABLE domains ADD COLUMN cert_crt TEXT NOT NULL DEFAULT ''"),
                     ("cert_key", "ALTER TABLE domains ADD COLUMN cert_key TEXT NOT NULL DEFAULT ''"),
                     ("cert_at", "ALTER TABLE domains ADD COLUMN cert_at INTEGER NOT NULL DEFAULT 0")]),
    ):
        existing = {row[1] for row in _conn.execute(f"PRAGMA table_info({table})")}
        for col, ddl in cols:
            if col not in existing:
                _conn.execute(ddl)


@contextmanager
def db():
    with _lock:
        cursor = _conn.cursor()
        yield cursor
        _conn.commit()


def now_ms():
    return int(time.time() * 1000)


# ---------- 用户 ----------

def list_users():
    with db() as cursor:
        return [dict(row) for row in cursor.execute("SELECT * FROM users ORDER BY id")]


def list_enabled_users():
    with db() as cursor:
        return [dict(row) for row in cursor.execute(
            "SELECT * FROM users WHERE enabled=1 ORDER BY id")]


def get_user(user_id: int):
    with db() as cursor:
        row = cursor.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_name(name: str):
    with db() as cursor:
        row = cursor.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
    return dict(row) if row else None


def add_user(name, internal_ip, egress_ip, seq, pubkey, privkey, uuid,
             quota_mb=0, max_mbps=0):
    with db() as cursor:
        cursor.execute(
            "INSERT INTO users(name,internal_ip,egress_ip,rotate_seq,pubkey,"
            "privkey,uuid,quota_mb,max_mbps,enabled,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,1,?)",
            (name, internal_ip, egress_ip, seq, pubkey, privkey, uuid,
             quota_mb, max_mbps, now_ms()),
        )
        return cursor.lastrowid


def update_user(user_id: int, **fields):
    whitelist = {"name", "egress_ip", "rotate_seq", "pubkey", "privkey", "uuid",
                 "quota_mb", "used_up", "used_down", "max_mbps", "enabled"}
    sets, args = [], []
    for k, v in fields.items():
        if k in whitelist:
            sets.append(f"{k}=?")
            args.append(v)
    if not sets:
        return
    args.append(user_id)
    with db() as cursor:
        cursor.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", args)


def delete_user(user_id: int):
    with db() as cursor:
        cursor.execute("DELETE FROM users WHERE id=?", (user_id,))


def next_user_id():
    with db() as cursor:
        row = cursor.execute("SELECT MAX(id) m FROM users").fetchone()
        return (row["m"] or 0) + 1


def add_traffic(user_id: int, up: int, down: int):
    with db() as cursor:
        cursor.execute(
            "UPDATE users SET used_up=used_up+?, used_down=used_down+? WHERE id=?",
            (up, down, user_id))


# ---------- 邀请码 ----------

def add_invite(code: str):
    with db() as cursor:
        cursor.execute("INSERT INTO invites(code, created_at, used) VALUES(?,?,0)",
                    (code, now_ms()))
        return code


def list_invites():
    with db() as cursor:
        return [dict(row) for row in cursor.execute(
            "SELECT * FROM invites ORDER BY created_at DESC")]


# ---------- 接入域名 ----------

def list_domains():
    with db() as cursor:
        return [dict(row) for row in cursor.execute("SELECT * FROM domains ORDER BY id")]


def get_domain(domain_id: int):
    with db() as cursor:
        row = cursor.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
    return dict(row) if row else None


def add_domain(domain: str, ip: str = "", port: int = 0, note: str = ""):
    with db() as cursor:
        cursor.execute("INSERT INTO domains(domain,ip,port,note,enabled,created_at) "
                    "VALUES(?,?,?,?,1,?)", (domain, ip, port, note, now_ms()))
        return cursor.lastrowid


def update_domain(domain_id: int, **fields):
    whitelist = {"domain", "ip", "port", "note", "enabled"}
    sets, args = [], []
    for k, v in fields.items():
        if k in whitelist:
            sets.append(f"{k}=?")
            args.append(v)
    if not sets:
        return
    args.append(domain_id)
    with db() as cursor:
        cursor.execute(f"UPDATE domains SET {','.join(sets)} WHERE id=?", args)


def delete_domain(domain_id: int):
    with db() as cursor:
        cursor.execute("DELETE FROM domains WHERE id=?", (domain_id,))


def primary_domain():
    for domain in list_domains():
        if domain["enabled"]:
            return domain
    return None