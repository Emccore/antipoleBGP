#!/usr/bin/env python3
# antipole-dns · DNS 网关管理程序（dnsctl）
#
# 把「mosdns 分流递归 + unbound(WG dns64) + 证书/防火墙/监听」整套 DNS 系统统一成
# 一个可管理的程序：配置即代码（dns.yaml → 渲染 mosdns/unbound 配置），带拨测自检、
# 广告拦截、分流表更新与热重载。渲染出的配置与手工调优版逐字兼容，可无缝接管现网。
#
#   dnsctl render [-c 配置] [-o 目录]          渲染配置（落盘前预览，目录缺省=打印 diff）
#   dnsctl apply  [-c 配置] [--restart]        备份旧配置 → 落盘 → 热重载（--restart 整重启）
#   dnsctl doctor                              全面自检：服务/端口/证书/上游拨测/样例解析
#   dnsctl test <域名> [A|AAAA] [--udp a:p|--dot a:p]   手动查询（默认本机 53）
#   dnsctl status                              服务与监听一览
#   dnsctl geosite update [--url] [--no-reload]  更新国内分流表（Loyalsoldier direct-list）
#   dnsctl blocklist update [--url] [--enable]   更新广告拦截表（StevenBlack hosts）
#   dnsctl version                             版本信息
#
# 依赖：python3 + PyYAML（apt install python3-yaml）；其余仅标准库。
import argparse
import difflib
import glob
import os
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

VERSION = "1.0.0"
DEFAULT_CONF = "/etc/antipole-dns/dns.yaml"
GEOSITE_URL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"
BLOCKLIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
DOT_HANDSHAKE_TIMEOUT = 5
QUERY_TIMEOUT = 4


# ---------------- 配置 ----------------

def load_config(path):
    try:
        import yaml
    except ImportError:
        sys.exit("缺少 PyYAML：apt install python3-yaml（或 pip3 install pyyaml）")
    if not os.path.exists(path):
        sys.exit(f"配置不存在：{path}（首次请从 dns.example.yaml 复制）")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ---------------- 渲染 ----------------

def _q(s):
    return f'"{s}"'


def render_mosdns(cfg):
    up = cfg.get("upstreams", {})
    dom = up.get("domestic", [])
    fgn = up.get("foreign", [])
    cache = cfg.get("cache", {})
    lis = cfg.get("listen", {})
    dot = lis.get("dot", {})
    bl = cfg.get("blocklist", {})
    cert, key = dot.get("cert", ""), dot.get("key", "")

    L = []
    A = L.append
    A("log:")
    A(f"  level: {cfg.get('general', {}).get('log_level', 'info')}")
    A("")
    A("plugins:")
    A("  # 国内域名匹配器：必须是 domain_set 类型插件，qname 匹配器才能引用它")
    A("  - tag: geosite_cn")
    A("    type: domain_set")
    A("    args:")
    A("      files:")
    A(f"        - {_q(cfg.get('geosite_cn', ''))}")
    A("")
    if bl.get("enabled"):
        A("  # 广告/跟踪拦截：命中直接回空记录")
        A("  - tag: black_hole")
        A("    type: black_hole")
        A("    args:")
        A("      ipv4: 0.0.0.0")
        A("      ipv6: ::")
        A("  - tag: blocklist")
        A("    type: domain_set")
        A("    args:")
        A("      files:")
        A(f"        - {_q(bl.get('file', ''))}")
        A("")
    A("  # 缓存：加速重复查询，lazy 模式")
    A("  - tag: cache")
    A("    type: cache")
    A("    args:")
    A(f"      size: {cache.get('size', 20480)}")
    A(f"      lazy_cache_ttl: {cache.get('lazy_ttl', 86400)}")
    A("")
    A("  # 国内上游：明文 UDP，快；多路上游 + 并发，掉一个自动用剩余的")
    A("  - tag: forward_local")
    A("    type: forward")
    A("    args:")
    A(f"      concurrent: {min(2, max(1, len(dom)))}")
    A("      upstreams:")
    for u in dom:
        A(f"        - addr: {_q(u)}")
    A("")
    A("  # 国外上游：多路加密 DoT，主连不上自动切下一个")
    A("  - tag: forward_remote")
    A("    type: forward")
    A("    args:")
    A(f"      concurrent: {min(2, max(1, len(fgn)))}")
    A("      upstreams:")
    for u in fgn:
        A(f"        - addr: {_q(u)}")
        if u.startswith("tls://"):
            A("          enable_pipeline: true")
    A("")
    A("  # 主逻辑：先查缓存；拦截表命中回空；命中国内域名走国内，其余走国外加密")
    A("  - tag: main_sequence")
    A("    type: sequence")
    A("    args:")
    A("      - exec: $cache")
    if bl.get("enabled"):
        A('      - matches: "qname $blocklist"')
        A("        exec: $black_hole")
    A('      - matches: "qname $geosite_cn"')
    A("        exec: $forward_local")
    A("      - exec: $forward_remote")
    A("")
    local = lis.get("local", "127.0.0.1:53")
    A("  # 本地 53：只给本机解析用，不对外")
    A("  - tag: udp_local")
    A("    type: udp_server")
    A("    args:")
    A("      entry: main_sequence")
    A(f"      listen: {_q(local)}")
    A("  - tag: tcp_local")
    A("    type: tcp_server")
    A("    args:")
    A("      entry: main_sequence")
    A(f"      listen: {_q(local)}")
    A("")
    A("  # DoT：手机\"私人 DNS\"固定走 853；另保留自定义端口备用（大陆 DPI 可能干扰 853）。")
    for i, addr in enumerate(dot.get("listens", [])):
        tag = "dot_server" if i == 0 else f"dot_server_{i}"
        A(f"  - tag: {tag}")
        A("    type: tcp_server")
        A("    args:")
        A("      entry: main_sequence")
        A(f"      listen: {_q(addr)}")
        A(f"      cert: {_q(cert)}")
        A(f"      key: {_q(key)}")
    A("")
    doh = lis.get("doh_inner", "")
    if doh:
        A("  # DoH：内部明文端点，只给本机 nginx 反代用，不直接对外。")
        A("  # 注意：v5.3 http_server 用 entries[]（path+exec），不是 entry/path。")
        A("  - tag: doh_inner")
        A("    type: http_server")
        A("    args:")
        A(f"      listen: {_q(doh)}")
        A("      entries:")
        A("        - path: /dns-query")
        A("          exec: main_sequence")
    return "\n".join(L) + "\n"


def render_unbound(cfg):
    wg = cfg.get("wg", {})
    if not wg.get("enabled"):
        return ""
    ups = wg.get("upstreams", [])
    L = []
    A = L.append
    A("server:")
    A("  verbosity: 0")
    A(f"  interface: {wg.get('interface', 'fd00:1::1')}")
    A("  port: 53")
    A(f"  access-control: {wg.get('interface', 'fd00:1::1')}/128 allow")
    A('  module-config: "dns64 iterator"')
    A(f'  dns64-prefix: {wg.get("dns64_prefix", "64:ff9b::/96")}')
    A("  do-daemonize: no")
    A("  log-queries: no")
    A("forward-zone:")
    A('  name: "."')
    for u in ups:
        A(f"  forward-addr: {u}")
    return "\n".join(L) + "\n"


def render(cfg):
    """返回 [(路径, 内容), ...]；wg 未启用时只返回 mosdns 一份。"""
    out = [(cfg.get("paths", {}).get("mosdns_conf", "/etc/mosdns/config.yaml"),
            render_mosdns(cfg))]
    wg = cfg.get("wg", {})
    if wg.get("enabled") and wg.get("conf"):
        out.append((wg["conf"], render_unbound(cfg)))
    return out


# ---------------- apply ----------------

def sh(cmd, check=False):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)


def diff_preview(path, new):
    if not os.path.exists(path):
        return f"+++ 新文件 {path}"
    with open(path, encoding="utf-8", errors="replace") as f:
        old = f.read()
    if old == new:
        return ""
    d = difflib.unified_diff(old.splitlines(), new.splitlines(),
                             fromfile=path, tofile=path + " (新)", lineterm="")
    return "\n".join(d)


def do_apply(cfg, restart=False, yes=False):
    targets = render(cfg)
    acted = False
    for path, content in targets:
        d = diff_preview(path, content)
        if not d:
            print(f"= {path} 无变化，跳过")
            continue
        print(d)
        if not yes:
            try:
                if input(f"写入 {path} ? [y/N] ").strip().lower() not in ("y", "yes"):
                    print("跳过"); continue
            except EOFError:
                pass
        if os.path.exists(path):
            bak = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
            shutil.copy2(path, bak)
            print(f"  已备份 → {bak}")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o600)
        print(f"✓ 已写入 {path}")
        acted = True
    if not acted:
        print("配置无变化")
        return
    # 与本配置相关的服务
    mosdns_path = cfg.get("paths", {}).get("mosdns_conf", "")
    if mosdns_path and os.path.dirname(mosdns_path) == "/etc/mosdns":
        if restart:
            r = sh("systemctl restart mosdns")
            print("✓ mosdns 已重启" if r.returncode == 0 else f"✗ 重启失败：{r.stderr.strip()}")
        else:
            r = sh("systemctl reload mosdns")
            if r.returncode == 0:
                print("✓ mosdns 已热重载")
            else:
                print("! 热重载失败，尝试整体重启…")
                r = sh("systemctl restart mosdns")
                print("✓ mosdns 已重启" if r.returncode == 0 else f"✗ 重启失败：{r.stderr.strip()}")
    wg = cfg.get("wg", {})
    if wg.get("enabled") and wg.get("conf") and os.path.exists("/usr/sbin/unbound"):
        if sh("pgrep -x unbound").returncode == 0:
            r = sh("systemctl try-restart unbound 2>/dev/null || kill -HUP $(pgrep -x unbound)")
            print("✓ unbound 已重载" if r.returncode == 0 else "! unbound 重载失败（若由 antipole 托管，随其管理即可）")
        else:
            print("· unbound 未运行（由 antipole 服务按需拉起）")


# ---------------- 裸 DNS 拨测（无第三方依赖） ----------------

def build_query(name, qtype):
    tid = random.getrandbits(16)
    head = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    name = name.strip(".")
    q = b"".join(bytes([len(part.encode())]) + part.encode()
                 for part in name.split(".")) + b"\x00"
    return head + q + struct.pack(">HH", qtype, 1)


def _skip_name(data, off):
    while True:
        n = data[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        off += 1 + n


def parse_answer_ips(data, qtype=None):
    try:
        _, _, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
        off = 12
        for _ in range(qd):
            off = _skip_name(data, off) + 4
        ips = []
        for _ in range(an):
            off = _skip_name(data, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntop(socket.AF_INET, data[off:off + 4]))
            elif rtype == 28 and rdlen == 16:
                ips.append(socket.inet_ntop(socket.AF_INET6, data[off:off + 16]))
            off += rdlen
        return ips
    except Exception:
        return []


def query_udp(server, name, qtype=1, timeout=QUERY_TIMEOUT):
    host, port = _split_hostport(server, 53)
    payload = build_query(name, qtype)
    tid = struct.unpack(">H", payload[:2])[0]
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
        deadline = time.time() + timeout
        while time.time() < deadline:
            data, _ = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid:
                return parse_answer_ips(data)
        return []
    finally:
        s.close()


def _split_hostport(server, dport=53):
    server = server.strip()
    if server.startswith("["):                       # [v6]:port
        host, _, rest = server[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else dport
    if server.count(":") == 1:                       # host:port
        host, p = server.rsplit(":", 1)
        return host, int(p)
    return server, dport                             # 裸地址


def query_tcp(server, name, qtype=1, timeout=QUERY_TIMEOUT, tls=False):
    host, port = _split_hostport(server, 853 if tls else 53)
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    raw = socket.socket(fam, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((host, port))
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE          # 拨测只验可达与可解析
            s = ctx.wrap_socket(raw)
        else:
            s = raw
        payload = build_query(name, qtype)
        s.sendall(struct.pack(">H", len(payload)) + payload)
        ln = struct.unpack(">H", s.recv(2))[0]
        data = b""
        while len(data) < ln:
            chunk = s.recv(ln - len(data))
            if not chunk:
                break
            data += chunk
        return parse_answer_ips(data)
    finally:
        raw.close()


def query(server, name, qtype=1, mode="udp", timeout=QUERY_TIMEOUT):
    if mode == "dot":
        return query_tcp(server, name, qtype, timeout, tls=True)
    if mode == "tcp":
        return query_tcp(server, name, qtype, timeout, tls=False)
    return query_udp(server, name, qtype, timeout)


# ---------------- doctor ----------------

def _cert_days(host, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(fam, socket.SOCK_STREAM) as r:
        r.settimeout(DOT_HANDSHAKE_TIMEOUT)
        s = ctx.wrap_socket(r)
        s.connect((host, port))
        der = s.getpeercert(binary_form=True)
        s.close()
    import tempfile
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as t:
        t.write(pem); tmp = t.name
    try:
        out = sh(f"openssl x509 -in {tmp} -noout -enddate").stdout.strip()
    finally:
        os.unlink(tmp)
    end = datetime.strptime(out.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return (end - datetime.now(timezone.utc)).days


def cmd_doctor(cfg):
    ok = warn = bad = 0

    def good(msg):
        nonlocal ok; ok += 1; print(f"  ✓ {msg}")

    def warn_(_msg):
        nonlocal warn; warn += 1; print(f"  ! {_msg}")

    def bad_(msg):
        nonlocal bad; bad += 1; print(f"  ✗ {msg}")

    print("▸ 服务状态")
    for svc in ("mosdns",):
        r = sh(f"systemctl is-active {svc}")
        (good if r.stdout.strip() == "active" else bad_)(f"{svc}: {r.stdout.strip() or 'unknown'}")
    if sh("pgrep -x unbound").returncode == 0:
        good("unbound: 运行中（WG 内网 DNS）")
    else:
        warn_("unbound: 未运行（由 antipole 按需拉起，若无 WG 用户可忽略）")

    print("▸ 本机监听")
    lis = cfg.get("listen", {})
    local = lis.get("local", "127.0.0.1:53")
    for addr, label in [(local, "本地 53"), (lis.get("doh_inner", ""), "内部 DoH")]:
        if not addr:
            continue
        h, p = _split_hostport(addr)
        try:
            fam = socket.AF_INET6 if ":" in h else socket.AF_INET
            with socket.create_connection((h, p), 3):
                good(f"{label} {addr} 可达")
        except Exception as e:
            bad_(f"{label} {addr} 不可达：{e}")

    dot = lis.get("dot", {})
    if dot.get("listens"):
        print("▸ DoT 证书")
        seen = set()
        for addr in dot["listens"]:
            h, p = _split_hostport(addr)
            if (h, p) in seen:
                continue
            seen.add((h, p))
            try:
                days = _cert_days(h, p)
                (good if days >= 15 else warn_)(f"{addr} 证书剩余 {days} 天")
            except Exception as e:
                bad_(f"{addr} TLS 握手失败：{e}")

    print("▸ 上游拨测")
    up = cfg.get("upstreams", {})
    for u in up.get("domestic", []):
        try:
            ips = query(u, "www.qq.com", 1, "udp", 3)
            (good if ips else bad_)(f"国内 {u} → {','.join(ips[:2]) or '无记录'}")
        except Exception as e:
            bad_(f"国内 {u} 拨测失败：{e}")
    for u in up.get("foreign", []):
        try:
            ips = query(u.replace("tls://", ""), "www.google.com", 1, "dot", 5)
            (good if ips else bad_)(f"国外 {u} → {','.join(ips[:2]) or '无记录'}")
        except Exception as e:
            bad_(f"国外 {u} 拨测失败：{e}")

    print("▸ 端到端解析（本机入口）")
    for domain, label in [("www.baidu.com", "国内路径"), ("www.google.com", "国外路径")]:
        try:
            ips = query(local, domain, 1, "udp", 5)
            (good if ips else bad_)(f"{label} {domain} → {','.join(ips[:2]) or '无记录'}")
        except Exception as e:
            bad_(f"{label} {domain} 失败：{e}")

    print(f"\n结果：{ok} 通过 / {warn} 提醒 / {bad} 异常")
    return 0 if bad == 0 else 1


# ---------------- status / test ----------------

def cmd_status(cfg):
    for svc in ("mosdns",):
        r = sh(f"systemctl is-active {svc}")
        print(f"{svc}: {r.stdout.strip()}")
    out = sh("ss -lntup 2>/dev/null | grep -E ':(53|853|25353|8080)\\b'").stdout
    print(out.strip() or "（无相关监听）")
    geo = cfg.get("geosite_cn", "")
    bl = cfg.get("blocklist", {})
    for f, label in [(geo, "分流表"), (bl.get("file") if bl.get("enabled") else None, "拦截表")]:
        if f and os.path.exists(f):
            n = sum(1 for _ in open(f, encoding="utf-8", errors="ignore"))
            print(f"{label}: {f}（{n} 条）")
        else:
            print(f"{label}: 未配置或不存在")


def cmd_test(args, cfg):
    server = args.dot or args.udp or cfg.get("listen", {}).get("local", "127.0.0.1:53")
    mode = "dot" if args.dot else "udp"
    qtype = 28 if (args.type or "A").upper() == "AAAA" else 1
    t0 = time.time()
    try:
        ips = query(server, args.domain, qtype, mode, args.timeout)
    except Exception as e:
        print(f"✗ 查询失败：{e}")
        return 1
    ms = (time.time() - t0) * 1000
    print(f"{args.domain} {('AAAA' if qtype == 28 else 'A')} via {mode} {server}  {ms:.0f}ms")
    for ip in ips:
        print(f"  {ip}")
    if not ips:
        print("  （无记录）")
    return 0 if ips else 2


# ---------------- 换地址 / 换域名 / 反滥用 ----------------

NGINX_MTLS_CONF = "/etc/nginx-mtls/nginx.conf"


def _sub_tree(root, old, new, globs=()):
    """替换 root 下（含 glob 追加）文本文件中的 old→new，返回改动文件清单。"""
    files = []
    for p in [root] + [f for g in globs for f in __import__("glob").glob(g)]:
        if not os.path.isfile(p) or os.path.islink(p):
            continue
        try:
            t = open(p, encoding="utf-8").read()
        except Exception:
            continue
        if old in t:
            shutil.copy2(p, p + ".bak-swap")
            open(p, "w", encoding="utf-8").write(t.replace(old, new))
            files.append(p)
    return files


def _reload_all():
    sh("systemctl reload mosdns || systemctl restart mosdns")
    r = sh(f"/opt/nginx-mtls/sbin/nginx -t -c {NGINX_MTLS_CONF}")
    if r.returncode == 0:
        sh(f"/opt/nginx-mtls/sbin/nginx -c {NGINX_MTLS_CONF} -s reload")
        print("✓ mosdns / nginx-mtls 已重载")
    else:
        print(f"✗ nginx -t 失败，未重载：{r.stderr.strip()}")


def cmd_addr(args, cfg):
    """addr switch <旧地址> <新地址>：换 DoT/DoH/mTLS 接入地址（证书与域名不受影响）。"""
    old, new = args.old.strip("[]"), args.new.strip("[]")
    if old == new:
        return
    y = open(args.config, encoding="utf-8").read()
    if f"[{old}]" not in y:
        sys.exit(f"配置里找不到 [{old}]")
    open(args.config, "w", encoding="utf-8").write(y.replace(f"[{old}]", f"[{new}]"))
    changed = [args.config]
    changed += _sub_tree(NGINX_MTLS_CONF, f"[{old}]", f"[{new}]")
    changed += _sub_tree(NGINX_MTLS_CONF, old, new, globs=["/etc/nginx-mtls/stream.d/*.conf"])
    print("已替换：" + ", ".join(dict.fromkeys(changed)))
    sh("ufw allow proto tcp from any to any port 853,25353,11451,80 2>/dev/null || true")
    cfg2 = load_config(args.config)
    do_apply(cfg2, restart=True, yes=True)
    print(f"\n完成。请把相关域名 AAAA 记录改指 [{new}]（Cloudflare 控制台）。")


def cmd_domain(args, cfg):
    """domain switch <新域名>：重签证书+换 server_name（新域名 AAAA 需已指向本服务器）。"""
    dom = args.domain
    dot = cfg.get("listen", {}).get("dot", {})
    cert = dot.get("cert", "")
    try:
        old = subprocess.run(["openssl", "x509", "-in", cert, "-noout", "-subject"],
                             capture_output=True, text=True).stdout
        old = old.split("CN =")[-1].strip()
    except Exception:
        sys.exit("无法从现有证书读取当前域名")
    print(f"换域名：{old} → {dom}")
    r = sh(f"/root/.acme.sh/acme.sh --issue -d {dom} -w /var/www/acme --keylength ec-256 --server letsencrypt")
    if r.returncode != 0:
        print(r.stdout[-500:]); sys.exit("签发失败：确认新域名 AAAA 已指向本服务器（80 已自动可达）")
    d = f"/etc/antipole-dns/cert/{dom}"
    os.makedirs(d, exist_ok=True)
    r = sh(f"/root/.acme.sh/acme.sh --install-cert -d {dom} --ecc "
           f"--fullchain-file {d}/fullchain.pem --key-file {d}/key.pem "
           f"--reloadcmd 'systemctl reload mosdns; /opt/nginx-mtls/sbin/nginx -c {NGINX_MTLS_CONF} -s reload; logger -t acme-cert \"{dom} renewed\"'")
    print(r.stdout.strip().splitlines()[-1] if r.stdout else "")
    y = open(args.config, encoding="utf-8").read()
    open(args.config, "w", encoding="utf-8").write(
        y.replace("/etc/antipole-dns/cert/us-dns-fullchain.pem", f"{d}/fullchain.pem")
         .replace("/etc/antipole-dns/cert/us-dns-key.pem", f"{d}/key.pem"))
    changed = _sub_tree(NGINX_MTLS_CONF, old, dom) + _sub_tree(
        NGINX_MTLS_CONF, old, dom, globs=["/etc/nginx-mtls/stream.d/*.conf"])
    print("nginx 引用已替换：" + (", ".join(dict.fromkeys(changed)) or "（无）"))
    do_apply(load_config(args.config), restart=True, yes=True)
    print(f"\n完成。请把 DNS 记录改指新域名 {dom}。旧证书保留在 /root/.acme.sh/。")


def cmd_guard(args, cfg):
    """反滥用兜底：对外 53/udp 显式拒绝（防 DNS 反射放大），WG 内网放行。"""
    print("▸ 对外 53/udp 监听检查")
    out = sh("ss -lunp | grep ':53 '").stdout
    bad = [l for l in out.splitlines()
           if l and not re.search(r"(127\.0\.0\.1|\[?fd00:1::1\]?|\[?::1\]?|127\.0\.0\.53)", l)]
    if bad:
        print("  ✗ 发现对外 53/udp 监听（反射风险）：")
        for l in bad:
            print("    " + l)
    else:
        print("  ✓ 仅本机/WG 内网监听，无反射风险")
    print("▸ 防火墙兜底（放行 WG 内网 → 拒绝其余 53/udp）")
    sh("ufw insert 1 allow proto udp from fd00:1::/64 to any port 53 2>/dev/null")
    sh("ufw insert 1 allow proto udp from 10.7.0.0/24 to any port 53 2>/dev/null")
    r = sh("ufw deny proto udp from any to any port 53")
    print("  ✓ " + (r.stdout.strip().splitlines()[-1] if r.stdout else "规则已写入"))
    r = sh("ufw status | grep '53/udp'")
    print("  " + "\n  ".join(r.stdout.strip().splitlines()))
    return 1 if bad else 0


# ---------------- 分流表 / 拦截表 ----------------

def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "antipole-dns/" + VERSION})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="replace")


def _to_mosdns_domainset(text):
    """v2ray/hosts 列表 → mosdns domain_set 文本。"""
    lines = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith(("#", "!")):
            continue
        if s.startswith("+."):
            lines.append("domain:" + s[2:])
        elif s.startswith("."):
            lines.append("domain:" + s[1:])
        elif s.startswith("full:"):
            lines.append(s)
        elif " " in s or "\t" in s:                  # hosts 格式：0.0.0.0 域名
            parts = s.split()
            if len(parts) == 2 and parts[0].replace(".", "").isdigit():
                d = parts[1]
                if d:
                    lines.append("full:" + d)
        elif "/" in s or "=" in s:
            continue                                  # 其他格式跳过
        else:
            lines.append("full:" + s)
    return "\n".join(dict.fromkeys(lines)) + "\n"


def _update_table(url, dest, label, convert=True):
    print(f"下载 {label}：{url}")
    text = _fetch(url)
    data = _to_mosdns_domainset(text) if convert else text
    n = data.count("\n")
    if os.path.exists(dest):
        shutil.copy2(dest, dest + ".bak")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        f.write(data)
    print(f"✓ {dest}（{n} 条，旧文件已存 .bak）")
    return n


def cmd_geosite(cfg, args):
    dest = cfg.get("geosite_cn") or "/etc/antipole-dns/geosite_cn.txt"
    n = _update_table(args.url or GEOSITE_URL, dest, "国内分流表")
    print(f"国内分流表已更新（{n} 条）。运行 dnsctl apply 或 systemctl reload mosdns 生效。")
    if not args.no_reload and sh("systemctl is-active mosdns").stdout.strip() == "active":
        r = sh("systemctl reload mosdns")
        print("✓ mosdns 已热重载" if r.returncode == 0 else "! 热重载失败，请手动 dnsctl apply --restart")


def cmd_blocklist(cfg, args):
    bl = cfg.get("blocklist", {})
    dest = bl.get("file") or "/etc/antipole-dns/blocklist.txt"
    n = _update_table(args.url or BLOCKLIST_URL, dest, "广告拦截表")
    if args.enable and not bl.get("enabled"):
        bl["enabled"] = True
        print("已在运行内存中开启拦截，但请编辑配置文件把 blocklist.enabled 改为 true 以持久化，再 dnsctl apply")
    print(f"广告拦截表已更新（{n} 条）。启用拦截需 blocklist.enabled: true 后 dnsctl apply。")


# ---------------- CLI ----------------

def main():
    ap = argparse.ArgumentParser(prog="dnsctl", description="antipole-dns · DNS 网关管理程序")
    ap.add_argument("-c", "--config", default=DEFAULT_CONF)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("render", help="渲染配置（预览）")
    p.add_argument("-o", "--out", help="输出目录（缺省打印 diff）")
    p.add_argument("-y", "--yes", action="store_true")
    p.set_defaults(fn=lambda a, c: _cmd_render(c, a))

    p = sub.add_parser("apply", help="落盘并重载")
    p.add_argument("--restart", action="store_true", help="整体重启而非热重载")
    p.add_argument("-y", "--yes", action="store_true", help="免确认")
    p.set_defaults(fn=lambda a, c: do_apply(c, a.restart, a.yes))

    p = sub.add_parser("doctor", help="全面自检")
    p.set_defaults(fn=lambda a, c: cmd_doctor(c))

    p = sub.add_parser("status", help="服务与监听")
    p.set_defaults(fn=lambda a, c: cmd_status(c))

    p = sub.add_parser("test", help="手动 DNS 查询")
    p.add_argument("domain")
    p.add_argument("type", nargs="?", default="A")
    p.add_argument("--udp", help="明文 UDP 上游 [host]:port")
    p.add_argument("--dot", help="DoT 上游 [host]:port")
    p.add_argument("--timeout", type=float, default=QUERY_TIMEOUT)
    p.set_defaults(fn=cmd_test)

    p = sub.add_parser("geosite", help="国内分流表")
    p.add_argument("action", choices=["update"])
    p.add_argument("--url")
    p.add_argument("--no-reload", action="store_true")
    p.set_defaults(fn=lambda a, c: cmd_geosite(c, a) if a.action == "update" else None)

    p = sub.add_parser("blocklist", help="广告拦截表")
    p.add_argument("action", choices=["update"])
    p.add_argument("--url")
    p.add_argument("--enable", action="store_true")
    p.set_defaults(fn=lambda a, c: cmd_blocklist(c, a) if a.action == "update" else None)

    p = sub.add_parser("addr", help="换接入地址")
    p.add_argument("action", choices=["switch"])
    p.add_argument("old", help="旧地址（不带端口）")
    p.add_argument("new", help="新地址（不带端口）")
    p.set_defaults(fn=lambda a, c: cmd_addr(a, c) if a.action == "switch" else None)

    p = sub.add_parser("domain", help="一键换域名（自动重签证书）")
    p.add_argument("action", choices=["switch"])
    p.add_argument("domain", help="新域名（AAAA 需已指向本服务器）")
    p.set_defaults(fn=lambda a, c: cmd_domain(a, c) if a.action == "switch" else None)

    p = sub.add_parser("guard", help="反滥用加固（防 DNS 反射）")
    p.set_defaults(fn=cmd_guard)

    p = sub.add_parser("version", help="版本")
    p.set_defaults(fn=lambda a, c: print(f"antipole-dns (dnsctl) v{VERSION}"))

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return
    if args.cmd == "version":
        print(f"antipole-dns (dnsctl) v{VERSION}")
        return
    cfg = load_config(args.config)
    sys.exit(args.fn(args, cfg) or 0)


def _cmd_render(cfg, args):
    targets = render(cfg)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for path, content in targets:
            name = os.path.basename(path)
            with open(os.path.join(args.out, name), "w", encoding="utf-8") as f:
                f.write(content)
            print(f"✓ {os.path.join(args.out, name)}  (→ {path})")
        return 0
    for path, content in targets:
        d = diff_preview(path, content)
        print(d if d else f"= {path} 与现行一致")
    return 0


if __name__ == "__main__":
    main()
