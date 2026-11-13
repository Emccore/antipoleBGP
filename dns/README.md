# antipole-dns · DNS 网关程序

把服务器上「mosdns 分流递归 + unbound(WG dns64) + DoT 证书 + 防火墙放行」这套手工维护的
DNS 系统，收敛成**一个可管理的程序**：配置即代码、命令化运维、自检拨测、一键部署。

## 它解决什么

| 原来的痛点 | 现在 |
| --- | --- |
| mosdns/unbound 配置手工编辑，改错无从预览 | `dns.yaml` 单一事实来源，`render` 预览 diff，`apply` 备份后落盘 |
| 国内分流表只有 7 行 CN 顶级域，大量国内域名走了国外加密上游（慢） | `dnsctl geosite update` 一键拉取全量国内域名表（数万条）并热重载 |
| 上游挂了/证书过期只能等用户报障 | `dnsctl doctor` 全量拨测：上游 UDP/DoT、证书剩余天数、端到端解析 |
| 想临时查个域名走哪条路 | `dnsctl test qq.com --udp ...` / `--dot ...` 自带裸 DNS 客户端 |
| 广告拦截要改配置重启 | `dnsctl blocklist update --enable` 拉取 StevenBlack 表，`enabled: true` 即生效 |
| 换机/重建只能凭记忆恢复 | `install-dns.sh` 一键装齐（mosdns 二进制 + 程序 + 配置 + systemd 单元 + 自检） |

## 组成

```
dns/
  dnsctl.py          主程序（python3 + PyYAML，其余仅标准库）
  dns.example.yaml   配置模板（默认值即现网行为）
  geosite_cn.txt     国内分流初始表（可用 geosite update 扩到全量）
  install-dns.sh     服务器一键安装 / --uninstall
```

## 命令

```bash
dnsctl render                 # 渲染 mosdns/unbound 配置（打印与现网的 diff）
dnsctl apply [--restart]      # 备份旧配置 → 落盘 → 热重载（mosdns SIGHUP）
dnsctl doctor                 # 自检：服务/端口/证书天数/上游拨测/端到端解析
dnsctl status                 # 服务状态 + 监听 + 分流/拦截表规模
dnsctl test qq.com --udp 127.0.0.1:53
dnsctl test google.com --dot [2606:4700:4700::1111]:853
dnsctl geosite update         # 更新国内分流表（Loyalsoldier direct-list，数万条）
dnsctl blocklist update --enable   # 更新广告拦截表；配合 dns.yaml enabled: true
```

## 配置（dns.yaml）

```yaml
upstreams:
  domestic: ["2400:3200::1", "2402:4e00::"]        # 国内明文 UDP
  foreign:  ["tls://[2606:4700:4700::1111]:853", …] # 国外加密 DoT
blocklist: { enabled: false, file: /etc/antipole-dns/blocklist.txt }
listen:
  local: "127.0.0.1:53"            # 本机
  doh_inner: "127.0.0.1:8080"      # 内部 DoH（nginx 反代对外）
  dot: { cert: …, key: …, listens: ["[v6]:853", "[v6]:25353", …] }
wg:                                 # unbound（WireGuard 内网 dns64）
  enabled: true
  conf: /etc/unbound/antipole.conf
  interface: fd00:1::1
  dns64_prefix: "64:ff9b::/96"
```

分流逻辑（main_sequence）：**缓存查询 → 拦截表命中返回空记录（可选）→ 国内域名经国内上游 → 其余经国外加密 DoT**。

## 安装

```bash
# 联网（GitHub raw）
curl -fsSL https://raw.githubusercontent.com/Emccore/antipoleBGP/main/dns/install-dns.sh | sudo bash
# 或源码目录内
sudo bash dns/install-dns.sh
sudo bash dns/install-dns.sh --uninstall
```

安装脚本行为：装依赖（python3/PyYAML/unzip/curl）→ 装 mosdns v5.3.1（已存在则跳过）→
`dnsctl` 装到 `/usr/local/bin`、配置落 `/etc/antipole-dns/` → 写 systemd 单元（不覆盖已有）→
`apply` 落盘配置（旧文件自动备份）→ `doctor` 全量自检。
现有 `/etc/mosdns/config.yaml`、unbound、证书、nginx 均只备份不破坏。

## 安全说明

- `apply` 落盘前自动备份为 `<路径>.bak-<时间戳>`；geosite/blocklist 更新同理留 `.bak`。
- `dns.yaml` 含证书路径等敏感信息，权限 600。
- 渲染器已做逐行回归：与此前手工调优版配置语义等价（仅注释措辞与 IPv6 规范化写法差异）。
