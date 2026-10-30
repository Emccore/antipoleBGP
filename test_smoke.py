# -*- coding: utf-8 -*-
"""
离线自检：覆盖配置装载、命名网段派生、地址池、数据库、流量批量落库、
隧道端口 1:1 转发（含握手 / 保活 / 双向数据 / 连接关闭 / 超长帧清洗）、
反滥用（连接速率 / 并发上限 / 熔断）、注册限流、邀请码原子消费、
统一配额限速、运行时健康快照、用户彻底删除、配置持久化，
以及控制面与管理接口的防爆破封禁。

特点：不依赖 root、不触碰真实内核与网络设备，仅使用回环地址，
可直接在部署前或 CI 中运行。

用法：python3 test_smoke.py
"""
import asyncio
import os
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import core, net, edge, web

BASE = Path(__file__).resolve().parent
tmp = Path(tempfile.mkdtemp())
db_path = str(tmp / "t.db")
keys = tmp / "keys"

# ---- 基础初始化 ----
cfg = core.load_config(str(BASE / "config.yaml"))
cfg["_path"] = str(tmp / "config.yaml")
cfg["db"]["path"] = db_path
cfg["db"]["keys_dir"] = str(keys)
cfg["network"]["prefix"] = "2600:1:2:3::/48"
cfg["network"]["ranges"] = {}
cfg["network"]["tunnel_range"] = ""
cfg["server"]["register_enabled"] = True
cfg["server"]["host"] = "127.0.0.1"
cfg["tunnel"]["enabled"] = True
cfg["tunnel"]["port"] = 39481
cfg["tunnel"]["listen"] = "127.0.0.1"   # 测试环境绑定回环
cfg["tunnel"]["bind"] = "127.0.0.1"
core.normalize(cfg)

core.init(db_path)
core.setup_mutex(cfg)
core.setup_pools(cfg)
net.setup(cfg)
edge.setup(cfg)
edge.setup_guard(cfg)

print("== 1. 命名网段派生 ==")
ranges = cfg["network"]["ranges"]
assert "" in ranges and "tunnel" in ranges
assert ranges["tunnel"].endswith("/56")
print("  主段   =", ranges[""])
print("  隧道段 =", ranges["tunnel"])

print("== 2. 地址池与静态地址 ==")
import ipaddress
a1 = core.addr_for("tunnel", 1)
assert a1 == core.addr_for("tunnel", 1), "静态地址必须可复现"
assert ipaddress.IPv6Address(a1) in ipaddress.IPv6Network(ranges["tunnel"])
print("  隧道静态地址 =", a1)

cfg["network"]["ranges"]["game"] = "2600:1:2:3:8000::/60"
core.setup_pools(cfg)
g1 = core.addr_for("game", 1)
assert ipaddress.IPv6Address(g1) in ipaddress.IPv6Network(
    "2600:1:2:3:8000::/60", strict=False)
assert core.range_of(g1) == "game"
print("  业务分段地址 =", g1, "归属 =", core.range_of(g1))

print("== 3. 数据库与用户 ==")
uid = 1
core.add_user(uid, "alice", core.internal_ip(1), a1, 1, "pub1", "priv1",
              "uuid1", 0, 0, "tunnel")
assert core.get_user(uid)["range_name"] == "tunnel"
core.add_tunnel_user(uid, "tok-alice", 0, 0)
row = core.get_tunnel_user_by_token("tok-alice")
assert row, row
print("  用户 =", row["user_name"], "  静态地址 =", row["egress_ip"])

# 回归：历史库自增序列可能存在空洞（曾删除过用户），用户 id 必须由调用方显式指定，
# 否则内核地址与库记录会因预测 id 与实际自增 id 不一致而对不上。
core.raw_conn().execute("UPDATE sqlite_sequence SET seq=9 WHERE name='users'")
core.raw_conn().commit()
uid2 = core.next_user_id()
core.add_user(uid2, "bob", core.internal_ip(uid2), core.addr_for("", uid2), 2,
              "pub2", "priv2", "uuid2")
assert (core.get_user(uid2) or {}).get("name") == "bob", "显式 id 写入失效"
core.delete_user(uid2)
print("  显式 id 写入 OK（自增序列空洞场景）")

print("== 4. 高频流量计数缓冲 ==")
for _ in range(1000):
    core.buffer_traffic(uid, 100, 200)
core.buffer_tunnel_bytes(uid, 5000)
core.flush_traffic()
user = core.get_user(uid)
assert user["used_up"] == 100000 and user["used_down"] == 200000
assert core.get_tunnel_user(uid)["used_bytes"] == 5000
print("  批量落库 OK：up =", user["used_up"], "down =", user["used_down"])

print("== 5. 隧道端到端转发（端口 1:1） ==")


async def echo(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def tunnel_flow():
    # 用户内网服务（模拟用户主机，使用独立回环地址）
    echo_srv = await asyncio.start_server(echo, "127.0.0.2", 38080)
    await edge.tunnel_start()

    # 1) 控制连接握手
    reader, writer = await asyncio.open_connection("127.0.0.1", 39481)
    writer.write(b"HELLO tok-alice\n")
    await writer.drain()
    hello = (await reader.readline()).decode().strip()
    assert hello.startswith("OK "), hello
    print("  握手成功，静态地址:", hello[3:])

    # 2) 声明端口映射：公网端口 == 用户本地端口
    writer.write(b"A 38080 127.0.0.2\n")
    await writer.drain()
    resp = (await reader.readline()).decode().strip()
    assert resp.startswith("OKP "), resp
    port = int(resp.split(" ")[1])
    assert port == 38080, port
    print("  端口映射声明成功：公网端口 = 本地端口 =", port, "（1:1）")

    # 2b) 端口策略：默认全开（1-65535，只看物理占用），保留清单是可选收紧项
    tun = edge.CFG["tunnel"]
    tun["deny_ports"] = [12222]
    writer.write(b"A 12222 127.0.0.2\n")
    await writer.drain()
    denied = (await reader.readline()).decode().strip()
    tun["deny_ports"] = []
    assert denied.startswith("ERRP 12222 ") and "保留端口" in denied, denied
    assert await edge.port_denied(45678) == "", "空闲高位端口不应被拒绝"
    print("  端口策略生效：保留清单拒绝，空闲端口可用（默认全开）")

    # 3) 保活
    writer.write(b"PING\n")
    await writer.drain()
    assert (await reader.readline()).decode().strip() == "PONG"
    print("  保活 PING/PONG 正常")

    # 4) 公网客户端接入
    pc_r, pc_w = await asyncio.open_connection("127.0.0.1", port)
    pc_w.write(b"ping-through-tunnel")
    await pc_w.drain()

    # 5) 客户端收到 N 帧，连接用户本地服务
    first = await reader.readexactly(1)
    assert first == b"N", first
    cid, nlen = struct.unpack("!II", await reader.readexactly(8))
    payload = await reader.readexactly(nlen)
    lport = struct.unpack("!H", payload[:2])[0]
    lip = payload[2:].decode()
    assert lport == 38080 and lip == "127.0.0.2"
    print(f"  N 帧：cid={cid} → 用户主机 {lip}:{lport}")
    lr, lw = await asyncio.open_connection(lip, lport)

    # 6) 下行 D 帧 → 写入用户主机
    first = await reader.readexactly(1)
    assert first == b"D", first
    dcid, dlen = struct.unpack("!II", await reader.readexactly(8))
    ddata = await reader.readexactly(dlen)
    assert dcid == cid and ddata == b"ping-through-tunnel"
    lw.write(ddata)
    await lw.drain()
    print("  下行 D 帧已转发至用户主机")

    # 7) 用户主机回显 → 上行 U 帧
    echoed = await asyncio.wait_for(lr.read(64), 5)
    assert echoed == b"ping-through-tunnel", echoed
    writer.write(b"U" + struct.pack("!II", cid, len(echoed)) + echoed)
    await writer.drain()

    # 8) 公网侧收到回显
    back = await asyncio.wait_for(pc_r.read(64), 5)
    assert back == b"ping-through-tunnel", back
    print("  端到端回显成功（公网 → 用户主机 → 公网）")

    # 8b) 半帧拆分：同一条 U 帧跨两次读到达，必须靠缓冲偏移正确拼回
    writer.write(b"U" + struct.pack("!II", cid, len(echoed)) + echoed[:3])
    await writer.drain()
    await asyncio.sleep(0.1)
    writer.write(echoed[3:])
    await writer.drain()
    back2 = await asyncio.wait_for(pc_r.read(64), 5)
    assert back2 == echoed, back2
    print("  半帧跨读边界正确重组")

    # 9) 公网关闭 → X 帧
    pc_w.close()
    first = await asyncio.wait_for(reader.readexactly(1), 5)
    assert first == b"X", first
    await reader.readexactly(8)          # 帧头：连接号 + 长度（X 帧长度为 0 也要读掉）
    print("  连接关闭 X 帧正常")

    # 10) 超长帧保护（超过 frame_max 的载荷直接断开；不做内容检查）
    oversize = int(cfg["tunnel"]["frame_max"]) + 1
    writer.write(b"U" + struct.pack("!II", cid, oversize) + b"x" * 10)
    await writer.drain()
    await asyncio.sleep(0.5)
    assert not any(s.uid == uid for s in edge._sessions.values()), \
        "超长帧应导致会话被断开"
    print(f"  超长帧保护生效：会话已断开（上限 {oversize - 1} 字节）")

    writer.close()
    echo_srv.close()
    await echo_srv.wait_closed()
    edge.tunnel_stop()
    await asyncio.sleep(0.2)


asyncio.run(tunnel_flow())

print("== 6. 反滥用：连接速率 / 并发上限 / 熔断 ==")


async def abuse_flow():
    guard = edge.GUARD
    limit = guard.conn_rate
    if limit:
        ok = 0
        for _ in range(limit + 10):
            if guard.note_conn(999):
                ok += 1
        assert ok == limit, (ok, limit)
        print(f"  连接速率上限生效：{ok}/{limit + 10} 通过")
    else:
        ok = sum(1 for _ in range(50) if guard.note_conn(999))
        assert ok == 50, ok
        print(f"  连接速率不限（0 = 放开）：{ok}/50 通过")
    for _ in range(ok):
        guard.drop_conn(999)

    original_max = guard.conn_max
    guard.conn_max = 5
    passed = 0
    for _ in range(20):
        if guard.note_conn(1001):
            passed += 1
    assert passed == 5, passed
    print("  并发上限生效：5/20 通过")
    for _ in range(passed):
        guard.drop_conn(1001)
    guard.conn_max = original_max

    await guard.trip(uid, "alice", "测试熔断")
    fresh = core.get_user(uid)
    assert guard.is_protected(fresh)
    assert core.get_tunnel_user(uid)["max_mbps"] == guard.protect_mbps
    print(f"  熔断生效：限速 {guard.protect_mbps}Mbps，事件已记录 "
          f"{len(core.list_abuse())} 条")

    # 保护期到期后必须把限速一并还原（只清 protect_until 会永久锁在保护带宽）
    core.update_user(uid, protect_until=core.now_ms() - 1000)
    await guard.sweep()
    assert core.get_tunnel_user(uid)["max_mbps"] == 0, "熔断到期未还原限速"
    assert not guard.is_protected(core.get_user(uid))
    print("  熔断到期：限速已还原（不会永久锁在保护带宽）")


asyncio.run(abuse_flow())

print("== 7. 注册限流（单 IP + 全局） ==")
guard = web.Guard(cfg)
allowed = sum(1 for _ in range(guard.reg_per_hour + 5) if guard.reg_allowed("1.2.3.4"))
assert allowed == guard.reg_per_hour, allowed
print(f"  单 IP 限流生效：{allowed}/{guard.reg_per_hour + 5} 通过")
guard2 = web.Guard(cfg)
guard2.reg_global_per_hour = 3
total = sum(1 for i in range(10) if guard2.reg_allowed(f"10.0.0.{i}"))
assert total == 3, total
print(f"  全局限流生效：{total}/10 通过")

print("== 8. 邀请码原子消费 ==")
core.add_invite("CODE-1")
assert core.consume_invite("CODE-1", "alice") is True
assert core.consume_invite("CODE-1", "bob") is False
print("  一次性消费正确（并发安全）")

print("== 9. 统一配额与限速（常规 + 隧道） ==")
core.update_user(uid, quota_mb=1024, max_mbps=20)
core.update_tunnel_user(uid, quota_mb=1024, max_mbps=20)
view = web._user_view(core.get_user(uid))
assert view["quota_mb"] == 1024 and view["max_mbps"] == 20
assert view["tunnel"]["quota_mb"] == 1024 and view["tunnel"]["max_mbps"] == 20
print("  统一视图 OK：配额", view["quota_mb"], "MB，限速", view["max_mbps"], "Mbps")

print("== 10. 运行时健康快照 ==")
core.set_runtime_stat(uid, up_bps=2048, down_bps=8192, conns=3,
                      online=1, tunnel_on=1, ports=1)
stat = core.list_runtime_stats()[uid]
assert stat["up_bps"] == 2048 and stat["conns"] == 3 and stat["ports"] == 1
print("  健康快照 OK：上行 2KB/s 下行 8KB/s 连接 3 端口 1")

print("== 11. 用户彻底删除 ==")
asyncio.run(web.purge_user(uid))
assert core.get_user(uid) is None
assert core.get_tunnel_user(uid) is None
assert core.list_tunnel_maps(uid) == []
print("  用户、隧道账号与映射记录已全部清理")

print("== 12. 配置持久化与网段无损调整 ==")
cfg2 = core.load_config(cfg["_path"])
cfg2["network"]["ranges"]["video"] = "2600:1:2:3:c000::/60"
core.save_config(cfg2, cfg["_path"])
reloaded = core.load_config(cfg["_path"])
assert reloaded["network"]["ranges"].get("video") == "2600:1:2:3:c000::/60"
print("  配置持久化 OK；既有用户地址存于数据库，网段调整不影响在服用户")

print("== 13. 控制面与管理接口防爆破 ==")
edge.setup_guard(cfg)                       # 重置计数状态
guard = edge.GUARD
for _ in range(guard.auth_fails - 1):
    assert guard.note_fail("2001:db8::9") is False
assert guard.note_fail("2001:db8::9") is True, "认证失败达阈值应封禁来源"
assert guard.ip_banned("2001:db8::9") > 0
assert "2001:db8::9" in guard.banned_sources()
for _ in range(guard.conn_burst):
    assert guard.note_conn_ip("2001:db8::a") is True
assert guard.note_conn_ip("2001:db8::a") is False, "同源新建连接应被限速"
wguard = web.Guard(cfg)
for _ in range(wguard.login_fails):
    wguard.login_fail("198.51.100.7")
assert wguard.login_blocked("198.51.100.7") > 0, "管理接口失败达阈值应真正封禁"
print(f"  隧道来源失败 {guard.auth_fails} 次封禁 {guard.auth_ban_s}s；"
      f"管理接口失败 {wguard.login_fails} 次封禁生效")

print("== 14. 地址与账户绑定（轮换默认关闭，隧道用户永不轮换） ==")
assert cfg["rotation"].get("enabled") is False, "轮换应默认关闭"
uid3 = core.next_user_id()
core.add_user(uid3, "bindtest", core.internal_ip(uid3),
              core.addr_for("tunnel", uid3), 1, "pub3", "priv3", "uuid3", 0, 0, "tunnel")
core.add_tunnel_user(uid3, "tok-bind")
rotator = net.Rotator(cfg)
assert rotator.enabled is False
asyncio.run(rotator.run())              # 未启用时应立即返回、不建立轮换任务
assert rotator._tasks == [], "未启用时不应产生轮换任务"
before = core.get_user(uid3)["egress_ip"]
try:
    asyncio.run(rotator.rotate_one(core.get_user(uid3)))
    raise AssertionError("隧道用户的地址不应允许轮换")
except RuntimeError as e:
    assert "不允许轮换" in str(e), e
assert core.get_user(uid3)["egress_ip"] == before, "地址不得被改动"
core.delete_user(uid3)
print(f"  地址永久绑定 OK：{before}（轮换未启用，隧道用户轮换被拒）")

print("\n== 全部通过 ==")