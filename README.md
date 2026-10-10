# NetSentinel · 网络配置变更监测与溯源工具

持续监测 Windows 网络配置，一旦发现变化，自动回答两个问题：

1. **变了什么** —— 细到字段级（哪个网卡的哪个字段、从什么值变成什么值）
2. **为什么变、谁改的** —— 给出原因、源头、置信度与证据链

零第三方依赖，只用 Windows 自带的 PowerShell + Python 标准库，可离线运行。

**[查看示例报告 →](docs/example-report.html)**（已脱敏，直接用浏览器打开）

- 仓库：<https://github.com/TanTaiwoo07/NetSentinel>
- 示例报告在线版（需先在仓库 Settings → Pages 里把源设为 `main` / `/docs`）：
  <https://tantaiwoo07.github.io/NetSentinel/example-report.html>

---

## 隐私说明

本工具会读取大量本机网络信息，其中属于个人隐私的有：**主机名、用户名、MAC 地址、
真实 IP 与路由、DNS、WiFi 名称(SSID)、hosts 文件内容、已安装软件列表**。

因此做了两层保护：

1. **`data/` 整个目录不入库** —— `.gitignore` 已排除（`data/` 下的快照、事件日志、
   报告都是运行产物，只留在本地）。
2. **`demo` 命令默认脱敏** —— 生成可分享的示例报告时自动替换上述敏感项：
   - 公网 IPv4 → RFC 5737 文档保留段 `203.0.113.0/24`；IPv6 → `2001:db8::/32`
   - MAC → 局部管理地址 `0A-00-00-XX-XX-XX`（非真实厂商）
   - 主机名 → `DEMO-PC`，用户名 → `user`
   - SSID / 网络名 → `Office-WiFi` 等通用名
   - hosts 内容、已安装软件列表 → 整体替换
   - 事件日志改用合成数据（真实事件含历史 SSID 等无法穷举脱敏的自由文本）

   映射是确定性的（同一原值每次得到同一替换值），因此对比与归因逻辑不受影响。

```bash
python run.py demo                    # 脱敏（默认，可分享）
python run.py demo --no-sanitize      # 保留真实数据，仅供本地排查
python run.py demo --out docs/example-report.html
```

> 若要把自己的报告分享出去，请务必确认用的是脱敏版本。

---

## 快速开始

**方式一：双击批处理**

| 文件 | 作用 |
|---|---|
| `启动监测.bat` | 开始持续监测（默认 5 秒采样一次），Ctrl+C 停止后自动生成报告 |
| `生成报告.bat` | 根据已记录的事件生成 HTML 报告并打开 |
| `查看网络状态.bat` | 打印当前网络配置速览 |
| `开启注册表审计.bat` | **（管理员）**开启注册表审计，让工具能直接指认"哪个进程改的" |

**方式二：命令行**

```bash
python run.py status                 # 当前网络配置速览
python run.py snapshot               # 采集并归档一次快照
python run.py diff                   # 对比最近两次快照 + 归因
python run.py watch -i 5             # 持续监测（间隔 5 秒）
python run.py watch -i 5 -d 600      # 只跑 10 分钟
python run.py report                 # 生成 HTML 报告 → data/report.html
python run.py explain INC-0001       # 查看某次变化的完整归因
python run.py demo                   # 演示（不改动系统，不写入事件日志）
python run.py reset                  # 清空事件日志
```

> 采集一次全量快照约 2–4 秒，因此实际采样间隔会略大于设定值。
> Windows 防火墙 / 安全日志等部分数据需要管理员权限才能读取。

---

## 监测范围

| 类别 | 具体项 |
|---|---|
| 网卡适配器 | 状态、MAC、MTU、速率、驱动版本、新增/移除（含虚拟网卡） |
| IP 地址 | IPv4/IPv6 地址、前缀长度、来源（DHCP / 手动 / RA / 系统） |
| IP 接口 | DHCP 开关、接口 Metric（优先级）、连接状态 |
| DNS | 各接口 DNS 服务器、后缀搜索列表、连接专用后缀、注册表 NameServer |
| 路由表 | 目的前缀、下一跳、Metric、协议（Dhcp / NetMgmt / Ras） |
| 代理 | 用户级/计算机级 IE 代理、PAC 自动配置脚本、WPAD 自动检测、WinHTTP 代理 |
| 网络位置 | 公用/专用/域类别、IPv4/IPv6 连通性判定 |
| hosts | 文件哈希、修改时间、逐条条目增删 |
| VPN | 系统 VPN 连接配置的增删与参数 |
| 无线 | SSID、连接状态、BSSID、信道 |
| 防火墙 | 三个配置文件的启用状态与默认动作 |
| 注册表 | `Tcpip\Parameters` / `Tcpip6\Parameters`（IPv6 开关）等 |
| 服务与进程 | 网络相关服务的状态，以及具备改网能力的进程清单 |

**已知噪声字段已自动忽略**：无线信号强度、网卡协商速率、DHCP 租约到期时间戳。
它们每时每刻都在变，记录只会淹没真正的配置变更。

---

## 归因：三层证据

工具的结论不是猜测，而是按证据强度分层给出：

| 层级 | 证据来源 | 置信度 | 说明 |
|---|---|---|---|
| **A. 系统审计** | Windows 安全日志 4663 | 最高（0.97） | 内核直接记录"哪个进程改了哪条注册表"，可直接指认执行者。**需先开启注册表审计** |
| **B. 事件日志** | DHCP / WLAN / RAS / NetworkProfile / NCSI 等 40+ 类事件 | 0.65–0.85 | 系统自己给出的原因说明 |
| **C. 启发式规则** | 变更特征 + 进程/服务/安装记录 | 0.4–0.9 | 例如"DNS 变成 127.0.0.1"必然是本机 DNS 接管 |

主结论的选取顺序为 **A > 机制规则 > 环境证据**。
环境证据（"某进程正在运行"）被明确标注为**存在性证据**——它只说明该进程有条件改，不能证明就是它改的。

### 能识别的源头类型

- **代理软件**：Clash 系列（7890/7891/7897）、v2rayN（10808/10809）、Shadowsocks/R（1080/1087）、
  Trojan、sing-box、Fiddler/Charles（8888）、Proxifier、蓝灯
- **VPN / 虚拟局域网**：WireGuard、OpenVPN/TAP、Cisco AnyConnect、FortiClient、
  GlobalProtect、深信服 EasyConnect、Tailscale、ZeroTier、Hamachi、Radmin
- **虚拟化平台**：Hyper-V、WSL2、Docker Desktop、VMware、VirtualBox
- **本地 DNS 过滤**：AdGuard、Acrylic DNS Proxy、dnsmasq
- **其他**：向日葵/ToDesk 远程控制、Npcap/WinPcap 抓包驱动、校园网认证客户端（iNode/锐捷）
- **网络侧**：路由器/光猫 DHCP 下发、公共 DNS（114DNS、阿里 AliDNS、腾讯 DNSPod、Cloudflare 等）
- **系统侧**：Windows 更新与驱动更新、组策略/域下发、手动脚本（`netsh`、`route add -p`、PowerShell）

### 典型判定示例

| 观测到的变化 | 结论 |
|---|---|
| 新增 `0.0.0.0/1` + `128.0.0.0/1` 两条路由 | VPN/代理客户端开启「全局模式 / TUN 模式」——绕过默认网关的经典手法（0.92） |
| DNS 变成 `127.0.0.1` | 本机 DNS 代理接管（代理软件做 fake-ip 分流或广告过滤）（0.88） |
| 系统代理指向 `127.0.0.1:7897` | Clash 系列混合代理端口（0.90） |
| IP 变成 `169.254.x.x` | DHCP 获取失败：网线松动 / WiFi 未真正连上 / 校园网 802.1X 未认证（0.85） |
| `Tcpip6\Parameters\DisabledComponents` 变化 | VPN 客户端为防 IPv6 泄漏而禁用（0.72） |
| 出现 `WireGuard Tunnel` 网卡 | WireGuard 安装或启动后创建虚拟网卡（0.90） |
| 防火墙配置文件被关闭 | 第三方安全软件接管 / 组策略下发 / 手动关闭（0.80） |
| hosts 新增 `0.0.0.0 xxx.com` | 广告拦截工具或安装程序写入的屏蔽规则（0.68） |

---

## 进阶：精确锁定"哪个进程改的"

默认模式下，Windows 不记录"谁改了注册表"。开启注册表审计后，
NetSentinel 能直接从安全日志 4663 读出执行修改的**进程完整路径**，这是铁证。

```bat
开启注册表审计.bat        :: 需管理员权限
```

或手动执行：

```cmd
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
```

开启后，安全日志会记录对 `Tcpip\Parameters`、`Internet Settings`、`hosts` 等
网络配置对象的访问，NetSentinel 自动提取其中的**进程名 + 对象路径**，
在报告中以「🔒 Windows 安全审计记录」区块展示，置信度 0.97。

不需要时用 `关闭注册表审计.bat` 复原（审计日志增长较快）。

**备选方案**：Sysinternals Process Monitor，过滤
`Operation = RegSetValue` 且 `Path` 含 `Tcpip\Parameters` 或 `Internet Settings`。

---

## 目录结构

```
netsentinel/
├── run.py                    入口
├── README.md / LICENSE (MIT) / .gitignore
├── 启动监测.bat / 生成报告.bat / 查看网络状态.bat
├── 开启注册表审计.bat / 关闭注册表审计.bat
├── docs/
│   └── example-report.html   示例报告（已脱敏，可直接打开或部署到 GitHub Pages）
├── netsentinel/
│   ├── collect.py            PowerShell 采集层（含编码处理与枚举映射）
│   ├── diffing.py            快照归一化 + 字段级差异对比
│   ├── evidence.py           证据库（事件日志解读表、进程/服务/软件归属表、公共 DNS 与代理端口表）
│   ├── attribute.py          归因引擎（规则集 + 证据融合 + 主结论选取）
│   ├── sanitize.py           隐私脱敏（快照 + 敏感串映射 + 全局替换）
│   ├── report.py             单文件 HTML 报告生成（暗色、离线可用）
│   ├── store.py              快照归档与事件 JSONL 存储
│   ├── demo.py               示例报告生成 + 自检
│   └── cli.py                命令行
└── data/                     【.gitignore 已排除，不入库】
    ├── snapshots/            历史快照（按时间命名的 JSON）
    └── events.jsonl          变更事件日志
```

---

## 已知局限

1. **未开启审计时无法直接指认进程** —— 只能给出"具备条件的高概率候选"，报告中已明确标注。
2. **采样间隔内多次变化会被合并** —— 一次 diff 只记录净变化，中间过程可能丢失。
3. **IPv6 链路本地地址（fe80::/10）会因重启变化**，属正常现象。
4. **域环境下的配置通常由 GPO 周期性覆盖**，本地修改属无效操作，工具会提示此情况。
5. 部分数据（防火墙配置、安全日志）需管理员权限才能完整读取。
