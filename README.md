# antipoleBGP 出口调度管理系统

**版本：V3.21**

antipoleBGP 是一套面向多用户运营场景的 IPv6 出口调度与网络接入管理系统。系统基于 BGP 广播前缀，为每个用户分配独立的 /128 IPv6 出口地址，**地址与账户绑定、永久不变**（如需按租约轮换可在配置中显式开启，隧道用户始终不参与）；在此基础上提供 VLESS Reality 代理接入、WireGuard 全隧道接入、类 frp 的 TCP 端口映射隧道、多业务命名网段、可选自助注册服务、反滥用防护与地址独立性守护。

控制面为纯 Python 实现（asyncio + aiohttp + SQLite + YAML），由单一进程托管；隧道数据面另由独立 Go 进程承载（单文件、仅标准库，`tunnel.relay_bin` 留空即回到纯 Python 路径）。

***

## 目录

1. [系统架构](#1-系统架构)
2. [核心能力](#2-核心能力)
3. [代码结构](#3-代码结构)
4. [部署](#4-部署)
5. [配置说明](#5-配置说明)
6. [命令手册](#6-命令手册)
7. [端口映射隧道](#7-端口映射隧道)
8. [命名网段与多业务分段](#8-命名网段与多业务分段)
9. [自助注册服务](#9-自助注册服务)
10. [安全与反滥用](#10-安全与反滥用)
11. [性能与并发设计](#11-性能与并发设计)
12. [REST API](#12-rest-api)
13. [故障排查](#13-故障排查)
14. [版本历史](#14-版本历史)

***

## 1. 系统架构

### 1.1 流量路径

```
用户 ── WireGuard 全隧道 ──> wg0（fd00:1::x / 10.7.0.x）
                              │ ip rule 依据内网地址进入各自独立路由表
                              │ default 路由 src = 该账户固定的 /128（地址与账户绑定，不轮换）
                              ├─> IPv6 出网（广播前缀内，/128 为独立出口）
                              ├─> IPv4 流量打 fwmark 走 WARP 隧道（支持多隧道负载分担）
                              └─> DNS64 合成地址 → tayga → WARP（访问纯 IPv4 站点）

用户 ── VLESS Reality ──> Xray :80（HTTP 端口 + SNI 伪装，真实 TLS 握手）
                            ├─> IPv6 目标 → fwmark 进入用户独立路由表（src = 当前 /128）
                            └─> IPv4 目标 → mark 走 WARP

公网 ──> <用户静态地址>:<任意端口>
          │ BGP 前缀路由至本机
          │ 地址守护校验（仅已分配地址放行）
          ├─> 数据面中继（Go）+ 客户端回连通道直通 → 用户主机 127.0.0.1:<同一端口>
          └─> 控制连接多路复用（老客户端 / 未启用中继时）
```

### 1.2 组件分工

| 组件     | 职责                                                  |
| ------ | --------------------------------------------------- |
| `core` | 配置装载与规范化、SQLite 存储、进程互斥锁、IPv6 地址池、命令执行              |
| `net`  | WireGuard、WARP 多隧道、策略路由、tc 限速、DNS64/NAT64、出口轮换、地址守护 |
| `edge` | Xray 托管、TCP 端口映射隧道、反滥用限流与熔断                         |
| `web`  | 管理 API、自助注册、Prometheus 指标、配额巡检、证书告警                 |
| `cli`  | `antipole` 全部管理命令                                   |
| `main` | 进程入口与后台任务编排                                         |
| 数据面中继（Go，独立进程） | 隧道字节搬运：只搬字节、零解析，按流量自适应攒批；准入、计费与防火墙仍由 `edge` 决定 |

***

## 2. 核心能力

| 能力     | 说明                                        |
| ------ | ----------------------------------------- |
| 独立出口   | 广播前缀内每用户独立 /128 出口，与账户绑定、永久不变（轮换默认关闭）     |
| 代理接入   | VLESS Reality（HTTP 端口 + SNI 伪装，真实 TLS 握手） |
| 隧道接入   | 类 frp 的 TCP 端口映射，公网端口与用户本地端口 1:1 对应；数据面由 Go 中继独立进程承载，按流量自适应攒批 |
| 多业务分段  | 不同 IP 段分配给不同业务，支持无损调整与批量迁移                |
| 地址独立性  | 前缀内仅已分配地址可路由至本机，其余一律丢弃                    |
| 反滥用    | 连接速率与并发上限、异常熔断、流量清洗、认证爆破封禁、注册限流           |
| 证书托管   | 客户端一键申请 Let's Encrypt 证书并在会话内自动续期         |
| 统一限速配额 | 常规接入与隧道接入共用一套配额与限速，亦可分别设置                 |
| 可选注册   | 自助注册服务默认关闭，开启后监听独立端口                      |
| 监控     | 状态查询、活动地址健康快照、Prometheus 指标               |

***

## 3. 代码结构

```
app/
  core.py   基础设施：配置 / 存储 / 锁 / 地址池 / 命令执行
  net.py    网络内核：WG / WARP / 路由 / 限速 / DNS64 / 轮换 / 地址守护
  edge.py   接入边缘：Xray 托管 / 端口映射隧道 / 反滥用
  web.py    管理面：REST API / 自助注册 / 指标 / 巡检 / 证书告警
  cli.py    命令层：antipole 全部子命令
  main.py   入口：启动顺序与后台任务编排
tools/
  antipole-relay/          数据面中继（Go 单文件、仅标准库；构建产物为 bin/antipole-relay）
  antipole-tunnel.py       隧道客户端（跨平台单文件，Windows / Linux / macOS）
  antipole-tunnel-gui.py   Windows 图形客户端源码（PyInstaller 打包为 exe）
  antipole-tunnel.bat      Windows 命令行启动器（自动挑选 Python 3）
  antipole-c               Linux 客户端管理脚本（systemd 托管多连接）
  build-win-exe.bat        打包 exe 的脚本
bin/
  antipole-relay          数据面中继二进制（可选，自行编译放入；缺失时用 Python 数据面）
dist/
  antipole-tunnel.exe      Windows 图形客户端（单文件，双击即用；二进制由 Releases 分发，不入库）
.github/workflows/
  build-client.yml        打 tag 时在 GitHub 机器上打包 exe 并挂到 Release 资产
deploy/
  deploy.sh            部署入口
  firewall.sh          防火墙规则
  antipole.service     systemd 服务定义
config.yaml            配置模板
install.sh             自适应安装脚本
test_smoke.py          离线自检（无需 root，不触碰真实内核）
```

***

## 4. 部署

### 4.1 前置条件

* 已通过 bird / frr 宣告前缀（建议 /48，支持 /32\~/64）

* 服务器可访问互联网，具备公网 IPv4 与 IPv6

* root 权限；512MB 内存、1 vCPU 可满足常规规模

### 4.2 一键安装

```bash
bash install.sh
```

安装脚本自动完成：

* **发行版适配**：识别 apt / dnf / yum / apk 并选择对应包管理器

* **架构适配**：识别 amd64 / arm64，下载对应架构二进制

* **依赖按需安装**：仅安装缺失项，可选组件缺失时自动降级

* **二进制完整性校验**：固定 Xray / wgcf 版本并校验 SHA256

* **服务注册**：检测 systemd 并注册服务，无 systemd 时生成启停脚本

* **离线自检**：运行 `test_smoke.py`，通过后才启动服务

数据面中继（可选）：`tunnel.relay_bin` 指向的 Go 程序不在安装脚本内构建，需要时在项目目录自行编译：

```bash
cd tools/antipole-relay
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../../bin/antipole-relay .
```

未构建或 `relay_bin` 留空时，隧道数据面自动由 Python 进程承载，功能不受影响（见 7.3）。

非交互安装：

```bash
PREFIX=2600:xxxx:xxxx:xxxx::/48 ADMIN_ALLOW=1.2.3.4 bash install.sh
```

| 环境变量          | 说明                   |
| ------------- | -------------------- |
| `PREFIX`      | 已广播的前缀               |
| `ADMIN_TOKEN` | 管理 API 令牌（缺省随机生成并打印） |
| `ADMIN_ALLOW` | 管理 API 来源白名单（逗号分隔）   |
| `REMOTE`      | 项目压缩包地址（自动下载安装）      |
| `GH`          | GitHub 下载镜像前缀        |

### 4.3 手动部署

```bash
bash deploy/deploy.sh
```

修改 `/etc/antipole/config.yaml` 后重启服务并放行端口：

```bash
systemctl restart antipole
bash deploy/firewall.sh
```

***

## 5. 配置说明

配置文件位于 `/etc/antipole/config.yaml`（权限自动收紧为 600）。

| 段落        | 关键项                                         | 说明                      |
| --------- | ------------------------------------------- | ----------------------- |
| `server`  | `admin_token` / `view_token`                | 管理令牌（全权）/ 只读令牌          |
| `server`  | `admin_allow`                               | 管理 API 来源白名单，留空不限制      |
| `server`  | `register_enabled` / `register_port`        | 自助注册开关与端口（默认 18290）     |
| `network` | `prefix`                                    | 已广播前缀（自动归一化）            |
| `network` | `ranges`                                    | 命名网段 `{名称: 前缀}`，用于多业务分段 |
| `network` | `tunnel_range`                              | 隧道专属网段，留空自动取主前缀最后一个 /56 |
| `network` | `guard_allocated`                           | 地址独立性守护开关（默认开启）         |
| `tunnel`  | `enabled` / `port`                          | 隧道开关与客户端控制端口（默认 18281）  |
| `tunnel`  | `bind`                                      | 监听基址，留空表示绑定用户静态地址       |
| `tunnel`  | `listen`                                    | 控制面/数据面监听地址（留空 = 本机业务地址；`::` = 全地址通配，逗号分隔多地址） |
| `tunnel`  | `min_port` / `deny_ports`                   | 可选收紧项：特权端口下限（默认 1 = 不限制）与保留端口清单（默认空 = 全开） |
| `tunnel`  | `sni` / `cert` / `key`                      | TLS 包裹参数（国内网络建议启用）      |
| `tunnel`  | `max_conns_per_user` / `conn_rate_per_user` | 单用户并发与新建连接速率上限          |
| `tunnel`  | `frame_max` / `idle_timeout`                | 单帧上限（仅长度保护）与空闲回收         |
| `tunnel`  | `bulk_pause_ms`                             | 聚批停读基准毫秒数（默认 4，0=关闭）；数据面中继按流量自适应放大到 4 倍 |
| `tunnel`  | `relay_bin` / `relay_sock` / `relay_port`   | 数据面中继（Go 进程只搬字节）；`relay_bin` 留空即关闭，老客户端不受影响 |
| `tunnel`  | `relay_stat_file`                           | 数据面块大小埋点输出（相对项目根，留空关闭；超 4MB 自动滚动一份 `.1`） |
| `warp`    | `profiles` / `endpoints`                    | 多 WARP 账号负载分担与备用端点      |
| `abuse`   | `protect_mbps` / `protect_s`                | 熔断后保护带宽与持续时长            |
| `alerts`  | `webhook` / `cert_days`                     | 告警推送地址与证书告警阈值           |

***

## 6. 命令手册

`antipole help` 可查看全部命令。所有修改类命令执行后自动触发热载，不重启、不中断连接。

### 6.1 状态与查询

```bash
antipole status                     # 系统状态 + 活动地址健康状态表
antipole users                      # 用户列表
antipole user get alice             # 单用户详情（含隧道与熔断状态）
antipole link alice                 # VLESS 分享链接
antipole wg alice                   # WireGuard 客户端配置
antipole domains                    # 接入域名列表
antipole invites                    # 邀请码列表
antipole abuse -n 30                # 滥用事件记录
antipole log -n 50                  # 最近日志
antipole version                    # 版本信息
```

`antipole status` 除组件状态外，输出全部用户的活动地址健康状态：

```
活动地址健康状态
ID  名称          出口/128                            状态          连接 端口 上行速率   下行速率   累计   配额用量
1   alice        2600:1:2:ff00:910a:2dec:8902:5cc1   在线(双通道)   7    2    10.0KB/s  1.0MB/s   3.2G   32%/10.0G
2   bob          2600:1:2:ff00:1c4f:8a02:91bb:77e1   在线(隧道)     3    1    0B/s      0B/s      128M   不限
合计 2 个用户，其中 2 个在线
```

字段含义：`状态` 区分双通道/单通道在线与离线；`连接` 为隧道并发连接数；`端口` 为已映射端口数；速率为最近一次采样周期（默认 10 秒）的平均值；`配额用量` 为累计流量占配额百分比。

### 6.2 用户管理

```bash
antipole create alice                              # 创建用户并输出连接信息
antipole create bob --rate 20 --quota 10240        # 附带限速与配额
antipole create bob --range game                   # 指定命名网段
antipole user add alice --range game
antipole user del alice                            # 删除用户（彻底清理）
antipole user toggle alice                         # 启用 / 禁用
antipole user rotate alice                         # 立即轮换出口（默认关闭；隧道用户不允许）
antipole user rate alice 20                        # 限速（0 解除）
antipole user quota alice 10240                    # 配额（0 不限）
antipole user limit alice 10240 20                 # 同时设置配额与限速
antipole user reset alice                          # 清零流量计数
```

`user limit` 为统一入口：同时作用于常规接入与隧道接入；隧道账号存在时两侧同步生效。
`user del` 会一并清理内核 peer、路由规则、限速规则、隧道会话、端口监听、地址登记与数据库记录。
用户的增删与启停通过 Xray HandlerService API 动态生效（账号、出站与分流规则一并增删），
不重启 xray，因此已有代理连接与在线用户不受影响；接口不可用时自动回退整体热载。

### 6.3 隧道管理

```bash
antipole tunnel add alice                          # 创建隧道用户
antipole tunnel add bob --rate 20 --quota 10240
antipole tunnel list                               # 隧道用户列表
antipole tunnel ports                              # 服务器自身占用的端口（不可用于映射）
antipole tunnel show alice                         # 静态地址 / 映射明细 / 用量
antipole tunnel token alice                        # 查看连接 Token
antipole tunnel limit alice 10240 20               # 隧道侧独立配额与限速
antipole tunnel toggle alice                       # 启用 / 禁用
antipole tunnel del alice                          # 删除隧道用户
```

### 6.4 命名网段管理

```bash
antipole range list                                # 网段列表与用量
antipole range add game 2600:1:2:3:8000::/60       # 新增业务网段
antipole range del game                            # 移除网段
antipole range apply                               # 无损应用变更（重建内核与地址守护）
antipole range move "" game                        # 批量迁移网段内用户
```

### 6.5 自助注册与证书

```bash
antipole register show                             # 查看注册服务状态
antipole register on --port 18290                  # 开启自助注册
antipole register off                              # 关闭

antipole cert issue gw.example.com --webroot /var/www/html
antipole cert check                                # 查询证书剩余天数
antipole cert renew gw.example.com
antipole cert reload --silent                      # 热载 Xray（续期钩子）
```

### 6.6 其他

```bash
antipole invite --count 3                          # 生成一次性邀请码
antipole backup                                    # 手动备份数据库
```

***

## 7. 端口映射隧道

隧道用于把用户主机的 TCP 服务开放到公网，行为与 frp 类似，但端口语义不同：**公网端口与用户本地端口完全一致，且监听在用户专属的静态地址上，不占用服务器本机任何端口**。

### 7.1 端口与地址语义

* 每个隧道用户在连接成功后获得唯一静态 /128 地址，永久固定

* 该地址位于默认保留的隧道专属 /56 网段内，与其他业务互不干扰

* 公网访问 `<用户静态地址>:N` 即等价于访问该用户主机的 `127.0.0.1:N`

* 端口号 1:1 对应，无端口池、无端口映射表冲突；同一端口号在不同用户之间互不影响

* 服务器公网地址上不占用用户端口（控制/数据面端口绑定本机业务地址，见 7.2），端口空间对用户完整可用（1-65535，唯一限制是主机仍以 IPv6 通配监听的端口）

* 控制面接入点固定为隧道专属网段的第一个地址（如 `2600:1:2:ff00::1`），随服务启动自动挂载并保留，不参与用户地址分配

### 7.2 服务端开启

```yaml
tunnel:
  enabled: true
  port: 18281
  relay_bin: bin/antipole-relay   # 数据面中继（可选，留空则由 Python 进程搬字节）
  listen: ""                      # 留空 = 本机业务地址（隧道接入地址 + 主地址 + IPv4）
```

重启服务后即可创建隧道用户：

```bash
antipole tunnel add alice
```

输出包含静态地址、接入地址、访问方式与连接 Token。

控制端口与用户映射端口都由程序在系统防火墙（ufw / nftables）上按需放行，无需事先写死规则。
云厂商网络防火墙（Vultr Cloud Firewall、安全组等）的端口过滤与目标地址无关：改用隧道网段内的
地址接入并不能绕过，必须在控制台按端口放行。这层过滤发生在网卡之前，主机侧 `tcpdump` 抓不到
SYN，表现为连接一直超时。由于每个用户独占自己的 /128、彼此互不干扰，云侧直接放行全端口
（TCP 1-65535）即可，一次配置覆盖所有用户与所有端口。

用户 /128 相互独立：同一端口号可被不同用户同时映射；主机自身服务也收敛在本机地址上，
用户地址的端口空间完整可用（1-65535）。唯一限制是仍以 IPv6 通配地址（`listen [::]:端口`）
监听的进程，客户端会直接提示"该端口已被服务器上的其他服务占用"，可用
`antipole tunnel ports` 查看完整清单。绑在本机具体地址上的服务与 IPv4 通配监听都不影响
用户 IPv6 地址上的同号端口。

主机服务收窄（部署建议，收窄后用户即可使用这些端口）：

| 服务 | 做法 | 备注 |
| --- | --- | --- |
| sshd | `ListenAddress <本机 2001 地址>` | 只允许 Vultr 分配的地址接受 SSH；IPv4 与用户/隧道地址不监听 |
| nginx / nginx-mtls | `listen [<服务地址>]:443 ssl;`（2053/11451 同理） | 服务地址 = 域名 AAAA 指向的自有地址，另可加主地址兼容旧客户端 |
| mosdns（DoT） | `listen: "[<服务地址>]:853"`（25353 同理） | 多入口可写多条 `tcp_server` |
| systemd-resolved | `LLMNR=no` | 释放 5355（LLMNR 与用户地址无关，直接关掉） |
| bird（BGP） | 保持通配 | BIRD 2.x 不支持指定绑定地址；179 为协议端口，用户不需要，作为唯一例外 |

隧道控制端口（18281）与数据面回连端口（18282）由程序自动收敛（见 `tunnel.listen`），无需手工处理。

### 7.3 数据面中继（Go）

`tunnel.relay_bin` 非空时，字节搬运交给独立进程，控制面（鉴权、准入、计费、防火墙）仍在本进程：

* 控制端口与数据面回连端口默认绑定**本机全部 IPv6 地址（剔除用户 /128）** 再补 IPv4 通配：客户端用任意本机地址接入都能连上（隧道接入地址、主地址、业务地址，以及历史配置里用过的其他本机地址），同时不在任何用户 /128 上占端口；`tunnel.listen` 可显式指定
* 按块大小自适应攒批：基准停读 `bulk_pause_ms`，检测到吞吐型流量（大块）放大到 4 倍、小块交互流量立即回落；实测同一 200MB 转发块均值 38KB → 100KB、CPU 11.1 → 8.1 ms/MB（同场对比内核 splice 零拷贝但不攒批反而 17.8 ms/MB，故未采用）；配合 `tcp_notsent_lowat` 后同链路实测 **5.0 ms/MB**
* 限速用户仍走用户态令牌桶循环以保证限速准确，不限速用户走自适应循环
* 可选块大小埋点：`relay_stat_file` 指向文件后，中继每 5 秒按 ≤4K / ≤16K / ≤64K / ≤256K / >256K 分桶追加一行统计（含双向块数、字节数与活跃管道数），方便定位转发开销；文件超过 4MB 自动滚动一份 `.1`
* 客户端在 `HELLO` 尾部声明 `r1` 能力后走独立回连通道（直连）；老客户端与 `--no-direct` 继续走控制连接多路复用，两条路径都由本进程做准入与计费
* 高延迟链路加固：两端数据连接开 TCP 保活（30s）、等待客户端回连与握手超时放宽到 20s/15s
* **海量连接内存策略**：空闲/交互连接每方向只常驻 4KB；连续读满（说明有积压）才从池里借 256KB 大缓冲，块回落即归还——单连接常驻开销 ~8KB，实测 1800 条并发活跃连接时中继 RSS 仅 ~33MB，服务端 `LimitNOFILE` 提到 1048576、somaxconn/syn_backlog 调到 8192，单用户并发上限默认 8192、新建速率 600/s（面向"单用户数万连接"）

### 7.4 客户端部署（用户主机）

客户端为单文件脚本，**Windows / Linux / macOS 通用，仅需 Python 3.8+，无第三方依赖**。
Windows 另提供图形界面版（`dist\antipole-tunnel.exe`，从 Releases 下载或本机打包；填接入地址与 UserID，连接后直接显示取到的
公网地址）；Linux 用 `tools/antipole-c` 统一管理（systemd 常驻，见 7.8）。

```bash
# Windows（命令行或双击 tools\antipole-tunnel.bat）
py -3 tools\antipole-tunnel.py --server [2600:1:2:ff00::1]:18281 --token <用户Token> ^
    --map 443 --map 8080 --map 127.0.0.1:9000

# Linux / macOS
python3 tools/antipole-tunnel.py --server [2600:1:2:ff00::1]:18281 --token <用户Token> \
    --map 443 --map 8080 --map 127.0.0.1:9000
```

`--server` 用 `antipole tunnel add` 输出的接入地址（隧道网段首地址）；IPv6 字面量写成 `[地址]:端口`。

常用参数：

| 参数                  | 说明                                   |
| ------------------- | ------------------------------------ |
| `--config`          | 读取 ini 配置文件，命令行参数优先                  |
| `--map`             | 端口映射，可重复；`8080` 等价于 `127.0.0.1:8080` |
| `--retry`           | 断线重连基础间隔秒（默认 5；断线后先 1s/2s/3s 快速重试 3 次，再从该值指数退避至 30）                |
| `--ping`            | 保活间隔秒（默认 15，0 关闭），保住家用 NAT 表项并加快断线发现      |
| `--stats`           | 状态输出间隔秒（默认 10，0 关闭）                  |
| `--sni`             | 服务端启用 TLS 包裹时填写 SNI                  |
| `--cert`            | 一键申请 HTTPS 证书（填写域名，见 7.6）            |
| `--cert-domain`     | 开启证书自动续期（填写域名）                       |
| `--cert-renew-days` | 剩余天数低于该值时自动重签（默认 30）                 |
| `--cert-status`     | 只查询本地证书剩余天数后退出（0 有效 / 2 需续期 / 1 无证书） |

配置文件示例（`--config client.ini`）：

```ini
[client]
server = [2600:1:2:ff00::1]:18281
token  = 3ca8aa246308a4d30073bae8940388db
map    = 443
map    = 127.0.0.1:9000
retry  = 5
ping   = 15
stats  = 10
cert_domain     = www.example.com
cert_renew_days = 30
cert_dir        = ./certs
```

运行时输出：

```
antipole 隧道客户端 v1.0  映射端口 2 个
已连接 2600:1:2:ff00::1:18281，静态地址 2600:1:2:ff00:910a:2dec:8902:5cc1
映射就绪：公网 [2600:1:2:ff00:910a:2dec:8902:5cc1]:443  ==  本机 127.0.0.1:443
映射就绪：公网 [2600:1:2:ff00:910a:2dec:8902:5cc1]:9000  ==  本机 127.0.0.1:9000
映射失败：本机 127.0.0.1:11451 —— 该端口已被服务器上的其他服务占用，请更换本地端口
[状态] 映射 2 个  活跃连接 3  上行 1.2MB/s  下行 3.4MB/s  累计 ↑120.5MB ↓340.2MB
```

长期运行（Linux 服务器/树莓派等）可交给 systemd：

```ini
# /etc/systemd/system/antipole-tunnel.service
[Unit]
Description=antipoleBGP tunnel client
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /path/to/antipole-tunnel.py --config /etc/antipole-tunnel.ini
Restart=always
RestartSec=5
User=nobody

[Install]
WantedBy=multi-user.target
```

连接具备以下特性：

* 单条出向长连接承载全部服务，用户主机无需开放任何入站端口

* 断线自动重连（`--retry` 可调间隔），重连后自动恢复既有端口映射

* 保活探测（PING/PONG）与空闲回收，避免僵死连接占用资源

* 同一账号单会话：已有在用会话时新连接被拒（客户端收到 `ERRA duplicate` 后停止重连并提示），旧会话连续 90 秒无保活（连丢 6 个心跳）则视为已死、允许新连接直接顶替，客户端崩溃/切网后约一分半即可自行恢复

* 映射以用户为粒度限速与计量，双向流量均计入配额

* 实时状态行输出映射数、活跃连接数与上下行速率，便于确认链路质量

### 7.5 限速与配额

```bash
antipole tunnel limit alice 10240 20    # 隧道侧：配额 10G、限速 20Mbps
antipole user limit alice 10240 20      # 统一设置：常规接入与隧道接入同时生效
antipole tunnel limit alice 0 0         # 解除限制
```

### 7.6 一键申请 HTTPS 证书

隧道用户不需要自己折腾 ACME：把域名解析到自己的隧道静态地址，客户端一条命令即可拿到证书。

```bash
python3 tools/antipole-tunnel.py --server [2600:1:2:ff00::1]:18281 \
    --token <用户Token> --cert www.example.com --cert-dir ./certs
# Linux 客户端管理脚本同样支持：antipole-c cert <连接名> www.example.com
```

执行流程：客户端请求签发 → 服务端校验域名确实解析到本账号静态地址（防止被当作公共证书代理）→
在验证期间于该地址的 80 端口临时提供校验文件 → acme.sh 通过 Let's Encrypt 完成 HTTP-01 →
证书与私钥回传客户端，落地为 `tls.crt` / `tls.key`（私钥权限 600）。

* 证书 90 天有效，服务端已配置 acme.sh 续期任务；客户端亦可自动续期（见下）

* 要求域名添加 **AAAA** 记录指向隧道静态地址（IPv4 域名不适用）

* 校验只临时占用 80 端口，因此 VLESS 入站监听收敛在本机主地址上，隧道网段的端口全留给用户

* 该地址的 80 端口**被本账号自己的映射占着也能申请**：服务端会临时撤下这条映射让出端口，
  校验完自动按原参数恢复（期间站点短暂不可达，通常十几秒）；校验所需的防火墙放行也自动完成

* 已签发且剩余 ≥30 天的 Lets Encrypt 证书会直接复用（客户端重连、连点申请都不会重复下单），
  只有临近到期或证书缺失时才真正走 ACME，避免撞上 Let's Encrypt 的重复证书限额

#### 证书自动续期

两种客户端都支持自动续期：客户端在会话内每 12 小时检查一次本地证书，剩余天数不足阈值时
经**当前已建立的隧道**向服务端重签并覆盖本地文件，无需重新连接、不与端口映射抢资源。

```bash
# 命令行客户端：填 --cert-domain 即开启，等待续期期间保持连接
python3 tools/antipole-tunnel.py --server [2600:1:2:ff00::1]:18281 --token <用户Token> \
    --map 443 --cert-domain www.example.com --cert-renew-days 30 --cert-dir ./certs

# 查看本地证书剩余天数（0 表示仍在阈值之上，2 表示需要续期，1 表示本地无证书）
python3 tools/antipole-tunnel.py --cert-status --cert-dir ./certs
```

Windows 图形客户端勾选「证书自动续期」并填好域名即可，证书统一落在 exe 同目录的 `certs\`。
Linux 用 `antipole-c` 时见 7.8（`add --cert-domain`、`renew`、`status` 均可查/触发续期）。

### 7.7 国内网络适配

WireGuard 使用的 UDP 流量在国内链路上常被 QoS 限速，因此国内用户建议：

1. 优先使用 VLESS Reality 代理接入（TCP + 真实 TLS 握手，抗干扰能力强）
2. 隧道场景启用 TLS 包裹，使控制连接表现为标准 HTTPS 流量：

```yaml
tunnel:
  sni: gw.example.com           # 证书对应域名
  cert: /etc/antipole/certs/gw.example.com/fullchain.pem
  key: /etc/antipole/certs/gw.example.com/key.pem
```

TLS 启用后服务端自动以 TLS 监听控制端口，客户端无需额外参数即可连接（SNI 与证书域名一致）。

### 7.8 客户端管理（Linux `antipole-c` / Windows 安装脚本）

Linux 上用一个脚本管理多条隧道连接，背后交给 systemd 常驻（无 systemd 时退回 nohup 后台）。

**一键安装（推荐）**：一条命令装好客户端、建连接、开机自启，全程问答，无需记参数。

```bash
# Linux / macOS：装好后自动进入问答（接入地址、令牌、端口）
curl -fsSL https://raw.githubusercontent.com/Emccore/antipoleBGP/main/tools/install-client.sh | sudo bash

# 也可以直接带参数，不进入问答
curl -fsSL https://raw.githubusercontent.com/Emccore/antipoleBGP/main/tools/install-client.sh | sudo bash -s -- \
    --server '[2600:1:2:ff00::1]:18281' --token <用户Token> --map 8080 --map 9000

# Windows：装图形客户端并创建桌面快捷方式（程序从 Releases 下载，受网络限制不入库）
irm https://raw.githubusercontent.com/Emccore/antipoleBGP/main/tools/install-client.ps1 | iex
```

Windows 也可以直接下载单文件客户端：<https://github.com/Emccore/antipoleBGP/releases/latest/download/antipole-tunnel.exe>
（同名 `.sha256` 一并提供，安装脚本会自动比对）。打 tag（如 `v3.21.0`）时 GitHub Actions 自动打包新 exe 并上传到对应 Release，
本地网络无需上传二进制；需要自定义版本时用 `tools/build-win-exe.bat` 在本机打包。

装完会打印常用命令（状态 / 日志 / 停止 / 申请证书 / 卸载）。

手动安装与多连接管理：

```bash
sudo install -m 755 tools/antipole-c /usr/local/bin/antipole-c
sudo antipole-c install                                  # 安装客户端与 systemd 模板
sudo antipole-c add web --server [2600:1:2:ff00::1]:18281 \
        --token <用户Token> --map 80 --map 443           # 创建并启动连接
sudo antipole-c add web --server [2600:1:2:ff00::1]:18281 \
        --token <用户Token> --map 443 --cert-domain www.example.com \
        --cert-renew-days 30                             # 同时开启证书自动续期
sudo antipole-c list                                     # 列出全部连接与运行状态
sudo antipole-c status web                               # 状态摘要（含证书剩余天数与最近日志）
sudo antipole-c log web 50                               # 查看日志
sudo antipole-c cert web www.example.com                 # 一键申请证书并开启自动续期
sudo antipole-c renew web                                # 立即检查证书，临近过期则触发重签
sudo antipole-c restart web / del web                    # 重启 / 删除
```

配置位于 `/etc/antipole-c/<名称>.ini`（权限 600），证书落地在 `/etc/antipole-c/<名称>/`。
常驻客户端每 12 小时自检一次证书有效期，低于阈值时经当前会话自动重签，无需人工干预。

***

## 8. 命名网段与多业务分段

系统允许把不同的 IP 段分配给不同业务，实现流量隔离与独立计费口径。

### 8.1 段结构

配置项 `network.ranges` 为 `{名称: 前缀}`，载入时自动补齐：

* 主段（名称为空）：取 `network.prefix`

* 隧道段（名称 `tunnel`）：取主前缀最后一个 /56，作为隧道业务专属，默认空白保留

```yaml
network:
  prefix: "2600:1:2::/48"
  ranges:
    game: "2600:1:2:8000::/60"
    video: "2600:1:2:c000::/60"
  tunnel_range: "2600:1:2:ff00::/56"
```

### 8.2 无损调整

用户地址在创建时写入数据库，网段配置变更只影响新分配：

* 修改 `ranges` 或 `tunnel_range` 后，执行 `antipole range apply` 重建内核路由与地址守护，**在服用户地址保持不变、连接不中断**

* 需要把既有用户迁入新段时，使用 `antipole range move <源> <目标>`，逐用户轮换至目标段

* 地址归属判定采用最长前缀匹配，子段不会被父段吞并

***

## 9. 自助注册服务

默认关闭。开启后监听独立端口（默认 18290），与 9090 管理面完全隔离。

```bash
antipole register on --port 18290
systemctl restart antipole
```

提供的接口：

| 方法   | 路径              | 说明                                    |
| ---- | --------------- | ------------------------------------- |
| GET  | `/`             | 极简注册表单（单个 HTML 页面）                    |
| POST | `/api/register` | 注册：用户名 + 密码（≥8 位）+ 邀请码                |
| POST | `/api/login`    | 登录：返回自身 VLESS 链接、WG 配置、隧道 Token、配额与用量 |

注册产生的账号使用主段地址，可由管理员后续调整网段或配额。注册限流采用单 IP 与全局双阈值，超限来源自动临时封禁。

***

## 10. 安全与反滥用

### 10.1 访问控制

| 措施    | 说明                                             |
| ----- | ---------------------------------------------- |
| 令牌分权  | `admin_token` 全权，`view_token` 只读；恒定时间比较，防时序侧信道 |
| 来源白名单 | `admin_allow` 限定管理面来源，本机地址始终放行                 |
| 认证封禁  | 认证失败达阈值后按来源 IP 临时封禁，封禁期内即使令牌正确也一律拒绝            |
| 请求延迟  | 隧道控制面握手或令牌校验失败时插入延迟，抬高暴力枚举的时间成本                |
| 输入校验  | 用户名与域名白名单正则；注册密码长度下限                           |

### 10.2 隧道与注册反滥用

| 措施       | 说明                                                        |
| -------- | --------------------------------------------------------- |
| 连接速率上限   | 单用户新建连接速率超过 `conn_rate_per_user` 时拒绝新连接                   |
| 并发上限     | 单用户并发连接超过 `max_conns_per_user` 时拒绝新连接                     |
| 异常熔断     | 触发阈值后自动把该用户限速至保护带宽并记录事件，保护期结束后自动解除                        |
| 流量清洗     | 单帧超过 `frame_max` 立即断开连接并记录；空闲连接按 `idle_timeout` 回收        |
| 端口监听失败记录 | 端口绑定失败写入滥用事件（含具体原因），便于排查恶意占用                              |
| 控制面爆破防护  | 同一来源认证失败达 `auth_fails` 次即封禁 `auth_ban_s` 秒，并限制单来源每分钟新建连接数 |
| 注册限流     | 单 IP 与全局双阈值；超限来源封禁                                        |

```yaml
abuse:
  login_fails: 5              # 管理接口认证失败次数上限
  login_ban_s: 900            # 管理接口来源封禁时长（秒）
  auth_fails: 8               # 隧道控制面认证失败次数上限
  auth_window_s: 300          # 隧道失败计数窗口（秒）
  auth_ban_s: 900             # 隧道爆破来源封禁时长（秒）
  conn_burst_per_min: 60      # 同一来源每分钟新建控制连接上限
```

当前被封禁的来源可在 `GET /api/status` 的 `tunnel.banned` 字段中查看。

滥用事件可通过 `antipole abuse` 查看，或经 `GET /api/abuse` 获取。

### 10.3 地址独立性

广播前缀内的地址若无业务占用，不应被路由至本机。系统在 nftables 中维护已分配地址集合，于 `prerouting` 早期放行集合内地址，并对前缀内其余地址执行丢弃：

```
chain guard {
    ip6 daddr @allocated accept
    ip6 daddr <各命名网段前缀> drop
}
```

* 集合采用 interval 类型，查找为常数复杂度，不随用户规模线性增长

* 用户创建、轮换、删除时增量增删元素，不做全量重写

* 主机服务同样收敛在本机地址（隧道控制/数据面端口绑定隧道接入地址 + 主地址 + IPv4，不再通配），用户 /128 不会被主机或其他用户占住端口，端口空间完整归其所有

* 元素批量写入（单次最多 500 条），规模较大时仍只产生数次 nft 调用

* 可通过 `network.guard_allocated: false` 关闭；关闭后前缀内任意地址均可到达本机

***

## 11. 性能与并发设计

### 11.1 高并发关键设计

| 设计             | 目的                                             |
| -------------- | ---------------------------------------------- |
| 转发路径裸 Protocol | 隧道收发在 `data_received` 回调内就地切帧、直写对端 transport，不建队列、不起任务、不 await（实测量级：比 StreamReader 逐帧 await 省 4~5 倍 CPU） |
| 水位背压           | 对端写不动时由 transport 水位回调暂停来源读取（`pause_reading`），无队列堆积、内存有界 |
| 突发聚批读取         | 持续大流量时短暂停读，让内核把数据攒成大块再交付：5500 字节/次的小读攒到 46KB/次，单核上限从 ~48MB/s 提到 ~110MB/s；普通网页/SSH 速率低于阈值，不会被停读（`tunnel.bulk_pause_ms`，0=关闭） |
| 数据面自适应攒批       | Go 中继按块大小自适应停读（基准 4ms ↔ 16ms），并把最大缓冲读满视为"仍有积压"直接续读——避免停读把大带宽时延链路的吞吐卡在上限；实测同一 200MB 转发，块均值 38KB→100KB、CPU 11.1→8.1 ms/MB；同场对比内核 splice 零拷贝但不攒批（块仅 ~3KB）反而 17.8 ms/MB，故未采用；配合 `tcp_notsent_lowat=128KB`（发送队列不在内核囤积）后真实链路实测 **5.0 ms/MB** |
| 长连接保活与假活检测     | 应用层心跳默认 15s（保住 NAT 表项、两个周期 ~35s 即发现假活）；控制与数据连接的内核 TCP keepalive 显式设为空闲 10s/间隔 3s/3 次判死；中继两侧数据连接保活 15s；断线后先 1s/2s/3s 快速重试 3 次（闪断秒级恢复），再指数退避 30s 封顶；客户端持续输出 SLA（在线时长/运行总时长）与断线次数，目标会话可用率 ≥98% |
| 海量连接低成本常驻      | 中继读缓冲按需升降档（空闲每方向 4KB ↔ 突发 256KB 池化），单连接常驻 ~8KB；系统 `LimitNOFILE=1048576`、`somaxconn=8192`；单用户并发上限 8192、新建速率 600/s；实测 600 条并发连接回环全通、1800 条时中继 RSS ~33MB |
| 客户端直连快路径        | 明文直连通道用裸 socket（`recv_into`/`sendall` + 起步 64KB 复用缓冲、持续读满自适应加倍到 256KB，流量回落即缩回），省掉流包装与逐块分配；TLS 时自动退回流包装路径；GUI 关窗只最小化到后台（隧道不断），需停止请点「退出」 |
| TLS 可选与日志清理  | 传输默认明文 TCP，TLS 包裹为可选：服务端配 `tunnel.sni/cert/key` 且客户端带 `--sni` 才启用（中继与证书共用同一张）；GUI 日志自动只留最近 500 行、连接级日志前 20 条逐条后每 100 条汇总 |
| 单份拷贝解析         | 按偏移直接在收到的字节段上取载荷，不再“整段入缓冲再切出来”，省掉每字节 2 次拷贝 |
| glibc 堆调参       | 部署单元注入 `MALLOC_TRIM_THRESHOLD_` 等参数，转发期间的缺页从 ~1870/s 降到 ~400/s |
| 流量计数内存缓冲       | 计数先在内存累加，由巡检周期批量落库（单事务），避免每包写数据库               |
| 出口轮换有界并发       | 到期用户并发轮换，受信号量约束，用户规模增大时不会串行积压                  |
| 内核集合查找         | 地址守护使用 nftables 集合，用户增删为增量操作                   |
| 命令超时与缓存        | 全部系统命令带超时；网关、网卡等低频数据缓存复用                       |
| 数据库写入收敛        | WAL 模式 + 单连接 + 线程锁；批量提交，写放大可控                  |

### 11.2 运行时快照

服务端每个采样周期（默认 10 秒）计算各用户上下行速率、隧道并发连接数、已映射端口数与在线状态，写入运行时状态表。CLI 与 API 在独立进程读取该表，因此 `antipole status` 无需与主服务共享内存即可展示实时健康状态；超过 120 秒未更新的快照会被判定为过期，不计入在线。

***

## 12. REST API

管理面默认监听 9090，认证使用 `X-Admin-Token` 或 `Authorization: Bearer`。

| 方法                          | 路径                             | 权限        | 说明                    |
| --------------------------- | ------------------------------ | --------- | --------------------- |
| GET                         | `/api/status`                  | 只读        | 系统状态（组件、隧道、注册、网段、证书）  |
| GET                         | `/api/health`                  | 只读        | 活动地址健康状态（在线、速率、连接、配额） |
| GET                         | `/api/metrics`                 | 只读        | Prometheus 文本指标       |
| GET                         | `/api/abuse`                   | 只读        | 滥用事件                  |
| POST / GET                  | `/api/users`                   | 写 / 只读    | 创建用户 / 用户列表           |
| GET / PATCH / DELETE        | `/api/users/{id}`              | 读 / 写 / 写 | 详情 / 更新 / 删除          |
| GET                         | `/api/users/{id}/wg` / `/link` | 写         | 客户端配置与分享链接            |
| GET / POST                  | `/api/tunnels`                 | 读 / 写     | 隧道用户列表 / 创建           |
| PATCH                       | `/api/tunnels/{id}`            | 写         | 隧道配额、限速、Token、流量清零    |
| GET / POST / PATCH / DELETE | `/api/domains`                 | 读 / 写     | 接入域名管理                |
| POST                        | `/api/invites`                 | 写         | 生成邀请码（`count` 支持批量）   |

Prometheus 采集示例：

```yaml
scrape_configs:
  - job_name: antipole
    metrics_path: /api/metrics
    bearer_token: <view_token 或 admin_token>
    static_configs:
      - targets: ['服务器地址:9090']
```

指标包含用户总数、在线数、内存、Xray/WARP/BGP 状态、隧道会话与端口数、每用户上下行累计流量、启用状态、配额与熔断状态。

***

## 13. 故障排查

| 现象                       | 排查方向                                                                                                |
| ------------------------ | --------------------------------------------------------------------------------------------------- |
| 隧道客户端报 `ERRA auth`       | Token 不正确或用户已禁用：`antipole tunnel token <用户>` 核对                                                     |
| 隧道客户端报 `ERRA duplicate`  | 同一 Token 已有一条在用会话（另一台设备或残留进程）。客户端会就此退出、不再重连；停掉对方实例即可。若对方其实已崩溃/切网，服务端判定 90 秒无保活后自动放行新连接顶替 |
| 映射声明返回 `ERRP`            | 客户端会直接显示失败原因：端口被服务器自身服务占用时换一个端口即可（`antipole tunnel ports` 可查清单）                                     |
| 访问映射端口却返回别的服务的 404 / 400 | 该端口被服务器自身的 IPv6 通配监听占用，请求落到了那个服务上：换端口，或按上文"主机服务收窄"把该服务的 `listen [::]:端口` 收到它自己的地址（`antipole tunnel ports` 可查清单） |
| 公网访问映射端口无响应              | `antipole status` 查看隧道是否在线与端口计数；确认地址守护已包含该地址；确认云厂商防火墙已放行该端口（建议 TCP 1-65535 一次放行）                                        |
| 隧道端口连接超时（客户端或映射访问）       | 云厂商防火墙未放行该端口；其过滤与目标地址无关，换隧道网段内地址也不能绕过，建议整段放行；`tcpdump -ni <网卡> tcp port <端口>` 抓不到 SYN 即为上游丢弃               |
| 用户限速不生效                  | 确认 `network.tc_enabled: true` 且系统已安装 iproute2                                                       |
| 未分配地址可访问本机               | 确认 `network.guard_allocated: true` 且系统已安装 nftables；执行 `antipole range apply` 重建守护                   |
| WARP 不可用                 | 检查 `/etc/antipole/warp-profile.conf` 是否存在与服务器出网能力                                                   |
| 服务启动失败                   | `antipole log -n 50` 查看日志；确认配置文件权限与语法                                                               |

***

## 14. 版本历史

| 版本   | 说明                                                                                                                                                                                                                                                                                                                                                                                 |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| V3.21 | 开源发布与一键安装：① 源码推送至 `Emccore/antipoleBGP`（配置与二进制不入库，防密钥泄漏、绕开本地上传体积限制）；② `tools/install-client.sh` ——Linux/macOS 一条命令装完即问答建连接（自动装 python3、写入 systemd 模板、开机自启，支持 `--server/--token/--map/--cert-domain` 非交互直连与 `--uninstall`）；③ `tools/install-client.ps1` ——Windows 一条命令装图形客户端：从 Release 下载、SHA256 比对、去网络标记、建桌面快捷方式、`-Uninstall` 卸载；④ `.github/workflows/build-client.yml` ——打 tag（如 `v3.21.0`）即在 GitHub 机器上打包 exe 并上传 Release 资产（含 `.sha256`），本地网络无需上传 11MB 二进制；⑤ README 增补客户端安装段与 Release 分发说明 |
| V3.20 | 代理伪装强化：① Reality 入站 **80 → 443**——在明文 HTTP 端口上跑 TLS 流量是 DPI 一眼可辨的特征，迁移后与 dest 真实站点（apple.com 的 443）完全对齐，非授权探测者拿到的就是 Apple EV 证书（实测 `openssl s_client` 返回 `CN=www.apple.com` / Apple Public EV CA）；链接端口自动跟随为 `network.2008828.xyz:443`；② **80 端口改为真实网站**（mc 伪装站点公网化）——接入地址 80 常驻 MC 首页（实测 200 / 557KB），"443 有 apple.com TLS + 80 有真实网站"组合成正常服务器画像，空端口/拒绝响应本身反倒是特征；③ 去掉 Reality 下无意义的 `fallbacks` 生成（Reality 非授权流量直接代理 dest，fallbacks 纯属多余配置特征）；④ 提醒：客户端链接端口需更新为 443 |
| V3.19 | VLESS 统一固定接入地址 + 修复代理被打断：① 新增 `xray.listen`——VLESS 入站监听与**全部分享链接**统一指定 BGP /48 内的固定 /128（现 `2a14:7583:ef30:1145::1`），不再依赖随实例重建变化的 Vultr 动态主地址，链接永不失效；服务启动时自动把该地址挂上 lo（幂等）并加入地址守护集合，持久放行入站端口；`vless_link`/`user get`/`link` 输出全部统一；② 新增 `xray.announce` **自填域名**——分享链接地址优先级 `announce > listen > 域名表 > 公网 IP`，AAAA 记录指向 listen 地址即可（现 `network.2008828.xyz`），换别名域名只改这一处、无需动任何监听；③ 定位并修复"常规连接用不了"根因——V3.15 证书流程结束时的 `fw_close(80)` 是**全局删除**放行，把同端口的 VLESS 入站一并打断；现证书流程结束时改为保留放行（幂等 `fw_open`），且 Xray 启动即放行入站端口，杜绝再次互相误删；④ `ensure_local_v6` 存在性判断修正：`ip addr show <地址>` 会被 iproute2 当设备名永远返回空，导致重复 add 撞 `File exists` 崩掉整个 Xray 初始化，改为 `show dev lo` 输出过滤；⑤ `tunnel_range` 显式固定 `fe00::/56`（隧道接入地址 `fe00::1` 客户端已固化，不能走"主前缀最后一个 /56"自动派生漂移）；⑥ 恢复线上配置事故：服务实际读取 `/etc/antipole/config.yaml`（此前部署只同步 /root 下无效副本），误以开发模板覆盖后已从 20260924 备份 + 运行日志交叉核对重建（`tunnel_range`/`admin_allow`/`warp profiles` 等以最新运行行为为准），工作区 config.yaml 同步替换为线上真实配置防再犯 |
| V3.18 | 极限压榨与 splice 实验定论：① 完整实现内核 **splice 零拷贝**搬运（1MB 池化管道、EAGAIN 精细状态机——源取空立即排空防"管道占满→窗口 0→上游互等"死锁、EOF 先排空再上报、错误路径清管防脏池串数据），修掉两版初稿的死锁与尾部 99 字节错乱；② **实测定论：5MB/s 级 WAN 瓶颈链路上 splice 反而 20 ms/MB**（劣化 4 倍）——排空速率受限使 1MB 管道永远填不满，模式碎片化 + poller 挂起/唤醒次数暴涨；read+自适应攒批在同链路 **5.0 ms/MB 仍是最优**（splice 省的用户态拷贝 ~1.5ms 抵不过碎片化调度开销）。故 splice 做成 `-splice` 开关**默认关闭**，回环/内网等高吞吐场景可开（此时零拷贝优势成立）；③ 2ms/MB 结论：瓶颈在内核 TCP 协议栈逐包处理与 WAN 排空速率（物理约束），1 vCPU + 5MB/s 链路上 5.0 已贴近下限；200MB 完整性复核 `size=209715200`、`exit=0` |
| V3.17 | 转发效率再上一档 + 内核调优补齐：① 客户端直连通道搬运缓冲**自适应化**——起步 64KB，连续读满 3 次加倍至 256KB（每 MB 的 read/sendall 系统调用随块增大持续下降），流量回落立即缩回起步档，空闲连接内存与原先持平（与中继同款已验证设计）；② 服务端新增 `tcp_notsent_lowat=131072`（发送队列不在内核囤积，降低排队延迟与内存）与 `tcp_mtu_probing=1`（PMTU 黑洞自动探测，消除大流量偶发卡死）；③ **补齐欠账**——此前版本声称的内核调优（somaxconn/backlog 8192、rmem/wmem 上限 64MB、BBR+fq、fs.file-max）从未写入 install.sh，新装环境拿不到；现全部固化为 `/etc/sysctl.d/99-antipole.conf`（幂等，安装即生效），服务单元 `LimitNOFILE` 同步修正 65536→1048576；④ 实测 200MB 真实链路转发：中继 **5.0 ms/MB**（此前 6.9~7.7，-30%+，CPU 共 1.00s）、客户端 1.17 ms/MB、`size=209715200` 完整无截断 |
| V3.16 | 链路保活与 SLA 加固（目标会话可用率 ≥98%）：① 应用层心跳默认 60s → **15s**（密到保住家用 NAT/运营商防火墙普遍 30~60s 回收的 TCP 表项，疏到不构成流量负担）；② 内核 TCP keepalive 按平台**显式设定**（空闲 10s、探测间隔 3s、3 次判死；各平台默认动辄 2 小时形同虚设，Windows 用 `SIO_KEEPALIVE_VALS`），覆盖控制连接与全部直连数据通道；③ 中继两侧数据连接保活 30s → 15s；④ 断线重连改为**快速重试**：先按 1s/2s/3s 连试 3 次（闪断秒级恢复），再转入指数退避 30s 封顶；⑤ 客户端内置 **SLA 统计**（在线时长/运行总时长 + 断线次数），状态行与重连提示中持续可见；⑥ 服务端僵尸会话顶替阈值 180s → 90s（连丢 6 个心跳即放行顶替）。实测：服务端防火墙丢包闪断 6s，密集心跳下 TCP 连接存活、恢复即通（SLA 100%）；真断线 3.3 秒内完成重连且映射与直连通道自动重建 |
| V3.15 | 证书签发链路修通（此前从未成功过）：① 修正 acme.sh 调用姿势——去掉与之冲突的 `--standalone` 与需要取值的裸 `--log`（后者会吞掉后一个参数，触发 `shift: can't shift that many`），改为纯 webroot 模式；② 校验期间自动放行系统防火墙 80（此前 ufw 未放行 80，Let's Encrypt 必然校验超时），结束后收回；③ 该地址 80 被**本账号自己的映射**占用时（例如把 80 映射到本机网站）自动临时撤下映射让出端口，校验完按原参数恢复并重新放行，站点只中断十几秒；④ 新增证书复用：已签发且剩余 ≥30 天的生产证书直接回传，客户端每次重连/连点申请不再重复下单，规避 Let's Encrypt 每周 5 张的重复证书限额；⑤ 报错信息优先带出 ACME 的校验失败原因。实测 host.2008828.xyz 真实签发成功（SAN 正确、90 天、`--cert-status` 可读），复用路径与独立申请模式均验证通过 |
| V3.14 | 单会话健壮性：① 服务端把保活（PING/PONG）计入活动时间戳，并新增**僵死会话顶替**——旧会话连续 3 分钟无保活即视为客户端已死（崩溃、切网、NAT 表项被静默回收），新连接直接接管并关闭旧连接，用户不再被"看着还在"的死会话锁在门外最长 10 分钟；仍正常保活的会话照旧拒绝，避免两个活客户端互顶抖动；② 会话摘除改为按对象身份判定，顶替场景下旧会话收尾不会误删新会话的登记与映射；③ 客户端把 `ERRA duplicate` 视为**不可重试**失败：停止无限退避重连并给出可操作提示（原先会每 5~30 秒刷屏重试），证书申请路径同样提示需先停掉对方实例 |
| V3.13 | 高并发解限与转发修复：① 反滥用并发/新建连接上限支持 **0 = 不限**（默认放开，异常流量仍由熔断与来源封禁兜底）；② 修掉中继转发的**大流量截断**根因——一个方向结束时直接 close 共享连接会把对向在途数据 RST 掉，Go 侧与客户端两侧均改为**半关闭**（`CloseWrite`/`write_eof`/`shutdown(SHUT_WR)`，两个方向都结束才真正关闭；100MB 实测 `size=104857600`、`curl_exit=0`）；③ 修掉 `0.0.0.0:18282` 监听被当双栈通配、与已绑定 IPv6 地址冲突的 `EADDRINUSE`（IPv4 显式用 `tcp4`）；④ 修掉中继 `copyDirection` 缓冲换档早于写出导致的**越界 panic**（大流量下偶发崩溃的根源）；⑤ 中继连接开 `TCP_NODELAY` + 30s 保活；⑥ 中继崩溃日志落盘 `logs/relay.log`（超 1MB 滚动），中继重连后按已登记映射自动重建监听；⑦ `_session_of` 改 O(1) 索引；⑧ 修掉图形客户端 `quit_app` 定义晚于按钮创建导致启动即 `UnboundLocalError`、exe 双击无反应的缺陷，打包脚本补齐客户端动态加载所需隐藏导入（`ssl`/`socket`/`struct`/`argparse`/`base64`/`signal`/`configparser`） |
| V3.12 | 传输默认改回明文 TCP（TLS 包裹转为可选：服务端 `tunnel.sni/cert/key` + 客户端 `--sni` 同时有才启用，避免证书/域名细节把客户端挡在门外）；GUI 关闭窗口改为**最小化后台继续转发**（新增「退出」按钮用于真正停止并退出）；中继攒批加"积压续读"——最大缓冲读满时不再停读，解除大带宽时延链路被停读卡出的吞吐上限 |
| V3.11 | 默认加密与日志治理：① 隧道控制面与直连数据面默认走 TLS 包裹（客户端内置默认 SNI，`--sni` 可覆盖、`--no-tls` 回退明文；服务端配 `tunnel.sni/cert/key` 后控制监听与中继回连端口同证书加密，数据面裸 socket 快路径自动切换为 TLS 流路径）；② GUI 日志自动清理（只保留最近 500 行），客户端连接级日志限流（前 20 条逐条、之后每 100 条汇总），海量连接下不再刷屏 |
| V3.10 | 海量连接与客户端效率：① 中继读缓冲改为按需升降档（空闲每方向 4KB、连续读满才借 256KB 池化大缓冲，块回落即还）——单连接常驻 ~8KB，1800 并发时 RSS 仅 ~33MB；② 系统调优：服务 `LimitNOFILE=1048576`、`somaxconn`/`tcp_max_syn_backlog`/`netdev_max_backlog`=8192、`fs.file-max`=2097152；③ 反滥用阈值放宽到单用户并发 8192、新建 600/s（面向单用户数万连接，异常仍有熔断兜底）；④ 客户端直连通道改裸 socket 快路径（`recv_into`/`sendall` + 64KB 复用缓冲，修 Windows 下 IPv6 `sock_connect` 需 4 元组的坑），TLS 自动退回流包装；⑤ GUI 关闭窗口即 `os._exit` 彻底退出，不再残留后台转发；实测 600 并发连接回环全通 |
| V3.9 | 弱网/高延迟链路稳定性修复：① 控制面与数据面监听改为**本机全部地址（剔除用户 /128）+ IPv4 通配**，修掉上一版把监听收窄到少数地址后、客户端用其他本机地址（如业务地址）接入就完全连不上的回归；② 中继两侧数据连接开 TCP 保活、等待回连与握手超时放宽到 20s/15s、单方向读缓冲 1MB→256KB（高并发内存更省）；③ 客户端补连接超时 15s、TCP 保活、两个 PING 周期无下行即判定假活断开重连、连上后重连退避复位（此前弱网下客户端会卡在"以为在线"或长时间不重连）；④ 重新打包 GUI exe |
| V3.8 | 主机服务监听全部收窄：sshd 仅监听 Vultr 分配的 2001 主地址（IPv4 与用户/隧道地址不再接受 SSH），nginx-mtls 的 443/2053、mosdns 的 853/25353 收到业务地址 + 主地址，systemd-resolved 关闭 LLMNR 释放 5355；收窄后实测用户 /128 上 22/443/853/2053/25353/5355 均可绑定，唯余 BGP 的 179（BIRD 2.x 无法指定绑定地址）；README 新增"主机服务收窄"部署表 |
| V3.7 | 用户地址与端口完全独立：隧道控制端口与数据面回连端口不再通配监听，收敛到本机业务地址（隧道接入地址 + 主地址 + IPv4，`tunnel.listen` 可显式覆盖），不在任何用户 /128 上占端口；端口策略改为默认全开（1-65535），去掉 22 硬保留，能否映射只看物理占用，且判定只认 IPv6 通配监听（IPv4 通配与绑在具体地址上的服务不再误伤）；同一端口号可在不同用户间同时映射；`antipole tunnel ports` 输出与自检用例同步更新 |
| V3.6 | 数据面中继加块大小埋点（`tunnel.relay_stat_file`，留空关闭、超 4MB 自动滚动）并据此定位：单 vCPU 小机器上循环开销约 77% 在内核态、单次系统调用数十微秒，块大小直接决定成本——同场 200MB 转发实测：固定 4ms 攒批 11.1 ms/MB（块均值 38KB）、内核 splice 零拷贝但不攒批 17.8 ms/MB（块仅 ~3KB，反而更差）、自适应攒批（4ms↔16ms，块均值 100KB）8.1 ms/MB，遂采用自适应攒批，基准由 `tunnel.bulk_pause_ms` 控制（0=关闭）；限速用户仍走用户态令牌桶循环 |
| V3.5 | 数据面搬到编译语言进程：新增 Go 中继 `tools/antipole-relay`（单文件、仅标准库、静态二进制，`bin/antipole-relay`），由主进程拉起并守护，经 `/run/antipole-relay.sock` 上的 JSON-IPC 受控——公网监听、连接准入、计费与防火墙仍由 Python 控制面决定，字节搬运改由 Go 完成（每字节不再经过 Python 事件循环）；客户端在 `HELLO` 尾部声明 `r1` 能力并按 `R <nonce>` 指令回连独立通道直通本地服务，老客户端继续走原有多路复用路径，`relay_bin` 留空即整体关闭；客户端新增 `--relay-port` / `--no-direct` |
| V3.4 | 转发路径极致优化（纯转发、不做任何内容处理）：隧道收发改为裸 Protocol，在回调内就地切帧并直写对端 transport，去掉会话级队列/单写协程/逐帧 await 与 StreamReader 缓冲层，背压改由 transport 水位回调 + `pause_reading` 承担；新增突发聚批读取 `tunnel.bulk_pause_ms`（默认 4ms，仅持续大流量触发，小请求零额外延迟），每次读从 ~5.5KB 提到 ~46KB；解析改为在累积缓冲上按偏移切帧（新数据只追加一次，已缓存的半帧不再重拷，载荷单次取出），并补上“半帧跨读边界重组”自检用例；事件循环启用 uvloop；服务端注入 glibc 堆调参（缺页 ~1870/s → ~400/s）；实测同一 100MB 转发：单核 CPU 20.8 → 7.3~9.5 ms/MB，吞吐 10 → 50 Mbps，折算单核上限 ~48 → ~110 MB/s；同时修复熔断到期只清 `protect_until`、不还原 `max_mbps`，导致被熔断用户永久锁在保护带宽（1Mbps）的缺陷 |
| V3.3 | 地址与账户绑定：新增 `rotation.enabled`（默认关闭），分配出去的 /128 永久不变，隧道用户因其地址承载端口映射与证书校验而永不参与轮换，`range move` 自动跳过隧道用户；端口策略：设计上仅保留 22（`deny_ports`，另留 `min_port` 可选收紧开关），其余端口一律可用，能否映射只看物理占用（主机通配监听才冲突），被拒原因回传客户端，配合把 DoH 的 11451 监听从 `[::]` 收窄到自有地址、该端口对隧道开放，新增 `antipole tunnel ports`；修复图形客户端日志回传的 `Tee` 自身引用错误、安装脚本 CRLF 行尾导致 Linux 上无法执行、以及 Py3.9 下 asyncio 原语在事件循环之外创建（含 xray api 锁绑定到废弃循环）的缺陷 |
| V3.2 | 两种客户端（命令行与 Windows 图形界面）均支持证书自动续期：会话内每 12 小时自检，剩余天数低于阈值即经当前隧道重签并覆盖本地文件，新增 `--cert-domain` / `--cert-renew-days` / `--cert-status` 与图形界面复选框；`antipole-c` 增加 `add --cert-domain`、`renew` 子命令与证书剩余天数展示；服务端补齐防爆破：修复管理接口认证封禁未真正生效的缺陷，隧道控制面新增按来源 IP 的认证失败计数、封禁与每分钟新建连接限制，失败时插入延迟                                                                                                         |
| V3.1 | 代理用户改由 Xray HandlerService API 动态增删（adu/rmu + 出站与路由规则），增删改启停不再重启 xray、既有连接不中断；隧道客户端支持一键申请 Let's Encrypt 证书（服务端校验域名归属后经静态地址 80 端口完成 HTTP-01）；新增 Windows 图形客户端 `antipole-tunnel.exe`（PyInstaller 单文件，填接入地址与 UserID 连接并显示公网地址）与 Linux 管理脚本 `antipole-c`（systemd 托管多连接）；VLESS 入站收敛到本机主地址，隧道网段端口全留给证书校验与用户映射                                                                            |
| V3.0 | 模块整合为六个（core/net/edge/web/cli/main）；隧道端口语义改为用户静态地址 + 端口 1:1 对应，不占用服务器端口；控制面接入地址固定为隧道网段首地址并随启动自动挂载；控制端口与映射端口按需自动放行系统防火墙；跨平台隧道客户端（配置文件、保活、实时速率状态行、Windows 启动器）；新增地址独立性守护、多业务命名网段无损调整、连接速率与并发上限、异常熔断与流量清洗、运行时健康快照；`status` 输出活动地址健康状态；统一用户限速与配额入口；配置装载改为深拷贝并归一化前缀；用户 id 由调用方显式指定，避免自增序列空洞导致记录错位；修复任务泄漏、命名冲突、前缀匹配等缺陷                                                                   |
| V2.0 | 新增隧道层（TCP 端口映射）、可选自助注册服务、命名网段、隧道限速与配额命令                                                                                                                                                                                                                                                                                                                                            |
| V1.1 | 安装脚本自适应当前发行版与架构、CLI 化管理、只读令牌、Prometheus 指标、WARP 多端点、证书告警、权限与安全基线统一                                                                                                                                                                                                                                                                                                                 |
| V1.0 | 初始版本：每用户独立 /128 出口与随机轮换、VLESS Reality、WARP 与 DNS64/NAT64                                                                                                                                                                                                                                                                                                                           |

