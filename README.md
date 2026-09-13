# antipoleBGP 出口调度管理系统

**软件版本：V1.1**　　**软件简称：antipoleBGP**

antipoleBGP 出口调度管理系统是一套基于 BGP 的 IPv6 出口调度与安全代理管理软件。系统在服务器上广播一个 /48（支持 /32~/64 范围）前缀，为每个注册用户分配独立的 /128 IPv6 出口地址，并按互联网服务商（ISP）租约规律随机轮换出口；同时集成 VLESS Reality 代理与 WARP IPv4 出口，支持 WireGuard 全隧道与代理协议两种接入方式。

- 纯 Python 实现（asyncio + aiohttp + sqlite + yaml），无外部运行时依赖
- 单一服务进程统一管理全部网络组件（WireGuard / Xray / WARP / NAT64 / 限速 / 轮换）
- 全部管理操作通过 `antipole` 命令行完成；可选启用 JSON API 与 Prometheus 指标

---

## 目录

1. [系统架构](#1-系统架构)
2. [技术规格](#2-技术规格)
3. [目录结构](#3-目录结构)
4. [部署](#4-部署)
5. [配置说明](#5-配置说明)
6. [操作手册（CLI）](#6-操作手册cli)
7. [REST API](#7-rest-api)
8. [安全设计](#8-安全设计)
9. [可靠性设计](#9-可靠性设计)
10. [DNS64 / NAT64](#10-dns64--nat64)
11. [证书管理](#11-证书管理)
12. [备份与日志](#12-备份与日志)
13. [故障排查](#13-故障排查)
14. [软件著作权登记](#14-软件著作权登记)
15. [版本历史](#15-版本历史)
16. [版权与许可](#16-版权与许可)

---

## 1. 系统架构

### 1.1 流量路径

```
用户 ── WG 全隧道 ──> wg0（fd00:1::x / 10.7.0.x）
                        │ ip rule 依据内网地址进入各自独立路由表
                        │ default 路由 src=当前 /128（30min~2h 随机轮换）
                        ├─> v6 出网（前缀已广播，/128 为独立出口）
                        ├─> v4 流量打 mark 走 WARP 隧道
                        └─> DNS64 合成 64:ff9b:: 地址 → tayga → WARP（纯 v4 站点）

用户 ── VLESS Reality ──> Xray :80（HTTP 端口 + SNI 伪装，真实 TLS 握手）
                            │ v6 目标 → fwmark 进入用户独立路由表（src=当前 /128）
                            └─ v4 目标 → mark 走 WARP
```

### 1.2 设计要点

| 机制 | 说明 |
|---|---|
| 出口轮换 | 仅修改内核路由 src，毫秒级完成，Xray 无需重载，用户连接零中断 |
| WARP 隔离 | 使用 fwmark 专用路由表，不影响 53/443/8443 端口的 DNS 服务 |
| 出口限速 | tc/htb 按用户 /128 识别，每用户独立 filter 规则 |

---

## 2. 技术规格

| 项目 | 规格 |
|---|---|
| 运行环境 | Linux（Debian 11/12、Ubuntu 22/24、CentOS/RHEL 8+、Rocky/AlmaLinux、Alpine） |
| CPU 架构 | x86_64 (amd64)、aarch64 (arm64) |
| Python | ≥ 3.8（asyncio / aiohttp ≥ 3.9 / PyYAML ≥ 6.0） |
| 接入协议 | WireGuard（全隧道）、VLESS Reality（TCP :80） |
| 管理端口 | 9090（JSON API + Prometheus metrics，可选） |
| 数据存储 | SQLite（WAL 模式，用户/接入域名/邀请码） |
| 轮换策略 | 每用户独立随机时刻、随机间隔（默认 30min~2h） |
| 配额控制 | 每 10s 巡检，超限立即断开并移除限速规则 |

---

## 3. 目录结构

```
app/
  main.py   程序入口与配置加载（Xray 由本进程拉起，崩溃自动重启）
  net.py    网络层：WG / WARP / 地址池 / 轮换 / BGP 监控 / tc 限速
  proxy.py  代理层：Xray 配置生成 / SIGHUP 热载 / 流量统计 / 分享链接
  api.py    REST API / 防滥用 / 配额巡检 / Prometheus 指标 / 证书告警
  db.py     数据层：SQLite（用户 / 接入域名 / 邀请码）
  cli.py    管理命令层：antipole 全部子命令
  lock.py   进程级文件锁（CLI 与主服务互斥）
deploy/
  deploy.sh       部署入口（转发至 install.sh）
  firewall.sh     防火墙规则（nftables/ufw）
docs/
  用户操作手册.md  软件著作权登记文档鉴别材料
reports/
  软著登记合规审查报告.md  软著申请合规核查与材料清单
tools/
  gen_copyright.py 源程序鉴别材料生成工具
copyright/         生成的源程序鉴别材料（前30页/后30页）
config.yaml       配置文件模板
install.sh        自适应安装脚本
test_smoke.py     离线自检（全 mock，不操作真实系统）
```

---

## 4. 部署

### 4.1 部署要求

- 已通过 bird/frr 宣告 /48（或更大范围）前缀，且服务器可访问互联网
- 512MB 内存、1 vCPU 即可满足常规规模
- root 权限

### 4.2 一键安装

将项目放置于服务器（如 `/root/antipole`），执行：

```bash
bash install.sh
```

安装脚本具备环境自适应能力：

- **发行版检测**：自动识别 apt / dnf / yum / apk 并选用对应包管理器
- **架构检测**：自动识别 amd64 / arm64，下载对应架构的 Xray / wgcf 二进制
- **依赖补齐**：仅安装缺失的依赖，可选组件（DNS64/NAT64）缺失时自动降级
- **Python 校验**：检测 Python ≥ 3.8 并安装 pip 依赖，安装后校验可导入
- **服务注册**：检测 systemd；无 systemd 时生成手工启停脚本

可通过环境变量跳过交互：

```bash
PREFIX=2600:xxxx:xxxx:xxxx::/48 ADMIN_ALLOW=1.2.3.4 bash install.sh
```

自动下载项目包安装：

```bash
REMOTE=https://example.com/antipole.tar.gz PREFIX=你的/48 bash install.sh
```

| 环境变量 | 说明 |
|---|---|
| `PREFIX` | 已广播的前缀（建议 /48，允许 /32~/64） |
| `ADMIN_TOKEN` | 管理 API 访问令牌（缺省随机生成） |
| `ADMIN_ALLOW` | 管理 API 来源白名单（逗号分隔） |
| `REMOTE` | 项目压缩包地址 |
| `GH` | GitHub 下载镜像前缀 |

### 4.3 手动部署

```bash
bash deploy/deploy.sh
```

修改 `/etc/antipole/config.yaml` 中以下必填项：

```yaml
server:
  admin_token: "强随机令牌"
  admin_allow: ["管理来源IP"]
network:
  prefix: "你的/48"
```

重启服务并配置防火墙：

```bash
systemctl restart antipole
bash deploy/firewall.sh
```

---

## 5. 配置说明

配置文件路径：`/etc/antipole/config.yaml`（权限 600）。

| 段落 | 关键项 | 说明 |
|---|---|---|
| `server` | `admin_token` | 管理令牌（全权），部署后必须修改 |
| `server` | `view_token` | 只读令牌（可选），仅可访问状态/列表/指标类端点 |
| `server` | `admin_allow` | 管理 API 来源白名单，留空即不限制 |
| `network` | `prefix` | 已广播的前缀（建议 /48，允许 /32~/64） |
| `network` | `tc_enabled` / `tc_wan` | 限速开关 / 出口网卡（留空自动探测） |
| `rotation` | `min_interval` / `max_interval` | 每用户轮换间隔区间（秒） |
| `xray` | `sni_dest` / `dest_ip` | Reality 伪装目标及其固定 IP |
| `warp` | `endpoints` | 备用 WARP endpoint 列表，单点故障时自动切换 |
| `dns64` | `prefix` / `v4_net` | DNS64/NAT64 合成前缀与内部 v4 池 |
| `abuse` | `quota_check_s` / `quota_warn_pct` | 配额巡检间隔（默认 10s）/ 用量告警阈值（默认 90%） |
| `alerts` | `webhook` / `cert_days` | 证书到期告警推送地址（可选）/ 告警阈值天数（默认 14） |
| `db` | `path` / `keys_dir` | 数据库与密钥目录（自动收紧至 600/700 权限） |

---

## 6. 操作手册（CLI）

### 6.1 状态与查询

```bash
antipole help                      # 命令帮助
antipole version                   # 版本信息
antipole status                    # 系统状态（BGP/WARP/Xray/内存/在线/证书）
antipole users                     # 用户列表
antipole user get alice            # 用户详情（流量/配额/限速/在线状态）
antipole link alice                # VLESS 分享链接
antipole wg alice                  # WG 客户端配置
antipole domains                   # 接入域名列表
antipole invites                   # 邀请码列表
antipole log -n 50                 # 最近日志
```

### 6.2 用户管理

```bash
antipole create alice              # 快速创建用户并输出 VLESS 链接
antipole create bob --rate 20 --quota 10240   # 创建用户并设置限速/配额
antipole user add alice            # 创建用户
antipole user del alice            # 删除用户（清理 peer/Xray/限速）
antipole user toggle alice         # 启用 / 禁用
antipole user rotate alice         # 立即轮换出口
antipole user rate alice 20        # 设置限速 20Mbps（0 解除）
antipole user quota alice 10240    # 设置配额 MB（0 不限）
antipole user reset alice          # 清零流量计数
```

### 6.3 接入域名管理

```bash
antipole domain add gw.example.com --ip 1.2.3.4
antipole domain ip 1 9.9.9.9       # 更换指向 IP，用户侧零改动
antipole domain toggle 1           # 启用 / 停用
antipole domain del 1              # 删除
```

### 6.4 邀请码与自助注册

```bash
antipole invite --count 3          # 生成 3 个一次性邀请码
```

用户通过注册接口自助开户：

```bash
curl -X POST http://IP:9090/api/register \
     -H 'Content-Type: application/json' \
     -d '{"name":"alice","invite":"<邀请码>"}'
```

注册频率限制：每 IP 每小时 3 次（可配置）。

### 6.5 数据备份

```bash
antipole backup                    # 手动备份数据库
```

---

## 7. REST API

管理 API 监听 9090 端口，认证通过 `X-Admin-Token` 或 `Authorization: Bearer` 请求头传递令牌，采用恒定时间比较防止时序侧信道。

| 方法 | 路径 | 所需角色 | 功能 |
|---|---|---|---|
| GET | `/api/status` | 任意令牌 | 系统状态（含证书剩余天数） |
| GET | `/api/metrics` | 任意令牌 | Prometheus 文本格式指标 |
| POST | `/api/users` | admin | 创建用户 |
| GET | `/api/users` | 任意令牌 | 用户列表 |
| GET | `/api/users/{id}` | 任意令牌 | 用户详情 |
| PATCH | `/api/users/{id}` | admin | 更新用户（enabled/rotate/quota_mb/max_mbps/reset_traffic） |
| DELETE | `/api/users/{id}` | admin | 删除用户 |
| GET | `/api/users/{id}/link` | admin | VLESS 链接（含用户标识，仅 admin） |
| GET | `/api/users/{id}/wg` | admin | WG 客户端配置（含私钥，仅 admin） |
| GET/POST/PATCH/DELETE | `/api/domains` | 按读/写分角色 | 接入域名管理 |
| POST | `/api/invites` | admin | 生成邀请码 |
| POST | `/api/register` | 公开 | 自助注册 |

### Prometheus 接入示例

```yaml
scrape_configs:
  - job_name: antipole
    metrics_path: /api/metrics
    bearer_token: <view_token 或 admin_token>
    static_configs:
      - targets: ['服务器IP:9090']
```

指标包括：用户总数、在线数、内存、Xray/WARP/BGP 状态、tc 开关、每用户流量计数、启用状态与配额。

---

## 8. 安全设计

| 安全项 | 实现 |
|---|---|
| 令牌分权 | `admin_token` 全权；`view_token` 只读；恒定时间比较 |
| 暴力破解防护 | 同一来源 IP 认证失败达阈值后临时封禁（可配置） |
| 文件权限 | 进程 `umask 077`；config.yaml、数据库（含用户私钥）、WARP profile、密钥目录均收紧至 600/700 |
| 二进制完整性 | 安装脚本固定 Xray/wgcf 版本并校验 SHA256，镜像下载不一致即拒绝 |
| 进程互斥 | CLI 与主服务共享文件锁（shared/exclusive），避免并发修改内核与数据库状态 |
| 孤儿进程防护 | Xray/tayga/unbound 启用死亡继承，主进程异常退出后子进程自动终止；启动时按配置路径清理残留进程 |
| 限速规则隔离 | 每用户独立 filter 优先级，规则增删仅作用于自身 |
| 输入校验 | 用户名/域名白名单正则，注册频率限制 |

---

## 9. 可靠性设计

| 机制 | 说明 |
|---|---|
| 出口轮换 | 每用户独立随机时刻与间隔；到期用户并发轮换（有界并发），避免大量用户时串行积压；单用户失败不影响整体 |
| 配额控制 | 每 10s 统计流量差值入库；超限立即断开对端并移除限速规则，消除超限窗口；用量达 90% 提前告警 |
| WARP 容错 | 多 endpoint 依次尝试握手，握手丢失时健康轮询自动切换 endpoint |
| Xray 守护 | 崩溃后自动重启；SIGHUP 平滑热载配置 |
| 证书监控 | 每 6 小时检查证书剩余天数，低于阈值输出告警日志，可选推送 webhook |
| 数据备份 | 每日自动复制 SQLite，保留 7 天 |
| 命令超时 | 所有系统命令均带超时，避免事件循环阻塞 |

---

## 10. DNS64 / NAT64

- **DNS64**：unbound 在 WG 隧道地址 `fd00:1::1:53` 应答，为无 AAAA 记录的域名合成 `64:ff9b::` 前缀地址；上游 DNS 使用 v6 可达的解析器
- **NAT64**：tayga 完成 IPv6/IPv4 转换，转换后的流量借道 WARP 隧道出网；WARP 不可用时自动回退原生 v4 出口

关键注意事项（代码中已处理）：

- ufw 默认 FORWARD 策略为 DROP，须改为 ACCEPT（防火墙脚本自动处理）
- tayga 的 ipv4-addr 不应挂载为内核本地地址，否则触发 martian 源校验丢包
- 需启用 `net.ipv4.conf.all.accept_local=1`
- WARP endpoint 优先 v6 解析，避免选择不可达的 v4 地址

---

## 11. 证书管理

```bash
antipole cert issue gw.example.com              # standalone 验证（需 80 端口空闲）
antipole cert issue gw.example.com --webroot /var/www/html
antipole cert check                             # 查询全部证书剩余天数
antipole cert renew gw.example.com              # 手动续期
```

- 证书安装至 `/etc/antipole/certs/<域名>/`，并写回接入域名记录
- acme.sh 自带 cron 自动续期，续期后自动热载 Xray 配置
- 启用 Trojan 时自动优先使用接入域名证书

---

## 12. 备份与日志

- **自动备份**：每日复制 SQLite 至 `data.sqlite3.bak.YYYYMMDD`，保留最近 7 份
- **手动备份**：`antipole backup`
- **日志查看**：`antipole log -n 50` 或 `journalctl -u antipole`

---

## 13. 故障排查

| 现象 | 排查方向 |
|---|---|
| `antipole status` 显示 WARP DOWN | 检查 `/etc/antipole/warp-profile.conf` 是否存在；确认服务器可出公网 |
| BGP 守护进程未检测到 | 状态接口标记 `bgp.alive=false` 并记录告警日志；不影响 WG/代理运行 |
| 用户限速不生效 | 确认 `tc_enabled: true` 且已安装 iproute2；`tc_wan` 留空时自动探测出口网卡 |
| 更换服务器 | 修改接入域名指向 IP（`antipole domain ip <id> <IP>`），用户配置无需变更 |
| 服务启动失败 | 查看 `journalctl -u antipole -n 50`；确认 config.yaml 权限与语法 |

---

## 14. 版本历史

| 版本 | 说明 |
|---|---|
| V1.1 | 重构安装脚本（发行版/架构自适应、依赖按需安装、二进制 SHA256 校验）；地址池支持 /32~/64 任意前缀；移除 Web 管理界面，管理操作全面迁移至 CLI；新增只读令牌、Prometheus 指标端点、WARP 多 endpoint 容错、证书到期告警；修复 tc 限速规则误删、配额超限窗口、孤儿进程、CLI 与服务并发冲突等问题；统一文件权限与安全基线 | |
| V1.0 | 初始版本。实现 /48 广播下的每用户 /128 出口调度、随机轮换、VLESS Reality 代理、WARP 出口与 DNS64/NAT64 |

---

## 15. 版权与许可
未经授权不得用于商业分发；部署使用请遵守所在国家/地区法律法规。

本系统依赖以下开源组件：Xray-core（MPL-2.0）、wgcf、acme.sh、tayga、unbound、WireGuard、aiohttp。
