"""
证据层：把 Windows 事件日志、进程、服务、软件安装记录翻译成可读的「线索」。
"""

from __future__ import annotations

import re
from datetime import datetime

# ---------------------------------------------------------------------------
# 事件日志解读表：(Provider 正则, 事件 ID) -> (含义, 权重)
#   权重 3 = 直接指向原因；2 = 强相关；1 = 弱相关
# ---------------------------------------------------------------------------

KEY_EVENTS: dict[tuple[str, int], tuple[str, int]] = {
    # DHCP 客户端
    ("Dhcp-Client", 50036): ("DHCP 客户端成功获取/续订 IP 租约", 3),
    ("Dhcp-Client", 50037): ("DHCP 租约续订成功", 3),
    ("Dhcp-Client", 50038): ("DHCP 租约即将到期，正在续订", 2),
    ("Dhcp-Client", 50039): ("DHCP 客户端重启了适配器", 3),
    ("Dhcp-Client", 50040): ("DHCP 客户端停止（适配器断开或被禁用）", 3),
    ("Dhcp-Client", 50041): ("DHCP 客户端启动（适配器接入网络）", 3),
    ("Dhcp-Client", 50042): ("DHCP 客户端进入休眠/等待状态", 1),
    ("Dhcp-Client", 50043): ("DHCP 客户端媒体已断开", 3),
    ("Dhcp-Client", 50044): ("DHCP 客户端媒体已连接", 3),
    ("Dhcp-Client", 50045): ("DHCP 客户端重置适配器", 3),
    ("Dhcp-Client", 50046): ("DHCP 客户端检测到 IP 地址冲突", 3),
    ("Dhcp-Client", 50047): ("DHCP 客户端租约被拒绝（服务器不响应/NACK）", 3),
    ("Dhcp-Client", 1001): ("DHCP 租约丢失（服务器无响应或网络断开）", 3),
    ("Dhcp-Client", 1002): ("DHCP 服务器拒绝了本机的 IP 请求", 3),
    ("Dhcp-Client", 1003): ("无法续订 IP 地址租约", 3),
    # TCPIP
    ("Tcpip", 4198): ("TCP/IP 检测到 IP 地址冲突", 3),
    ("Tcpip", 4199): ("TCP/IP 检测到地址冲突并已禁用该地址", 3),
    ("Tcpip", 4201): ("TCP/IP 检测到与本机 IP 冲突的另一台主机", 3),
    ("Tcpip", 4227): ("TCP 并发连接数达到安全上限（半开连接限制）", 2),
    ("Tcpip", 4231): ("TCP/IP 请求被拒绝：另一程序已占用该地址/端口", 2),
    # 网络位置识别
    ("NetworkProfile", 4004): ("网络位置感知(NLA)重新识别本网络并写入配置文件", 3),
    ("NetworkProfile", 10000): ("网络连接配置文件创建/更新", 2),
    ("NetworkProfile", 10001): ("网络连接配置文件状态变更", 2),
    ("NetworkProfile", 10002): ("网络连接配置文件已删除", 2),
    ("NlaSvc", 1000): ("网络位置感知服务(NlaSvc)状态变更", 2),
    # WLAN
    ("WLAN-AutoConfig", 8000): ("无线网卡开始连接网络", 3),
    ("WLAN-AutoConfig", 8001): ("无线网络连接成功", 3),
    ("WLAN-AutoConfig", 8002): ("无线网络连接失败", 3),
    ("WLAN-AutoConfig", 8003): ("无线网络已断开", 3),
    ("WLAN-AutoConfig", 11000): ("无线扫描开始", 1),
    ("WLAN-AutoConfig", 11004): ("无线配置（配置文件）已修改", 3),
    ("WLAN-AutoConfig", 11005): ("无线配置文件已添加", 3),
    ("WLAN-AutoConfig", 11006): ("无线配置文件已删除", 3),
    ("WLAN-AutoConfig", 12011): ("无线断开：信号丢失或被 AP 踢出", 3),
    ("WLAN-AutoConfig", 12013): ("无线连接失败：认证/密钥/超时", 3),
    ("WLAN-AutoConfig", 12014): ("无线连接失败：网络不可见", 3),
    ("WLAN-AutoConfig", 12017): ("无线连接失败：4-way handshake 超时", 3),
    # VPN / RAS
    ("RasClient", 20200): ("VPN/拨号连接开始", 3),
    ("RasClient", 20201): ("VPN/拨号连接建立成功", 3),
    ("RasClient", 20202): ("VPN/拨号连接已断开", 3),
    ("RasClient", 20220): ("VPN 连接参数协商完成", 2),
    ("RasClient", 20221): ("VPN 隧道已建立", 3),
    ("RasClient", 20226): ("VPN 连接失败", 3),
    ("RasClient", 20250): ("VPN 连接断开", 3),
    ("RasClient", 20253): ("VPN 连接被用户/策略终止", 3),
    ("RasMan", 20200): ("路由与远程访问服务处理连接请求", 2),
    ("RasMan", 20274): ("VPN 连接失败（认证或服务器无响应）", 3),
    ("VPN-Client", 300): ("VPN 连接状态变更", 2),
    # NCSI（联网状态指示器）
    ("NCSI", 4000): ("联网状态指示器探测活动（判断能否上网）", 2),
    ("NCSI", 4001): ("NCSI 判定：Internet 可达", 2),
    ("NCSI", 4002): ("NCSI 判定：Internet 不可达", 2),
    ("NCSI", 4004): ("NCSI 主动探测（网络状态变化触发）", 2),
    # 服务控制管理器
    ("Service Control Manager", 7045): ("系统中安装了新服务（通常是软件安装/驱动安装）", 3),
    ("Service Control Manager", 7036): ("服务状态变更（启动/停止）", 2),
    ("Service Control Manager", 7035): ("服务被启动", 2),
    ("Service Control Manager", 7040): ("服务的启动类型被修改", 3),
    ("Service Control Manager", 7011): ("服务启动超时", 2),
    # 组策略
    ("GroupPolicy", 8001): ("组策略应用完成（域/本地策略下发）", 3),
    ("GroupPolicy", 8004): ("组策略正在应用网络相关策略", 3),
    ("GroupPolicy", 5312): ("组策略已刷新", 2),
    # NetCfg（网络绑定/组件变更）
    ("NetCfg", 10000): ("网络组件（协议/客户端/服务）绑定变更", 3),
    ("NetCfg", 10001): ("网络组件绑定变更提交", 3),
    # DNS 客户端
    ("Dns-Client", 1016): ("DNS 客户端配置已更新", 3),
    ("Dns-Client", 1018): ("DNS 服务器列表已应用", 3),
    ("Dns-Client", 1019): ("DNS 客户端服务状态变更", 2),
    ("DNS-Client", 1016): ("DNS 客户端配置已更新", 3),
    ("DNS-Client", 1018): ("DNS 服务器列表已应用", 3),
    # Windows 更新
    ("WindowsUpdateClient", 19): ("Windows 更新成功安装（可能包含网卡驱动）", 2),
    ("WindowsUpdateClient", 20): ("Windows 更新安装失败", 2),
    ("WindowsUpdateClient", 43): ("Windows 更新已开始安装", 2),
    ("WindowsUpdateClient", 44): ("Windows 更新服务已开始下载", 1),
    # Winsock / 目录
    ("Winsock", 10000): ("Winsock 目录（LSP）发生变更 —— 通常由安全软件/代理软件注入", 3),
    # 安全审计（需管理员权限开启注册表审计后才有）
    ("Security-Auditing", 4663): ("注册表/文件对象被访问或修改（安全审计记录）", 3),
    ("Security-Auditing", 4688): ("有新进程被创建（安全审计记录）", 2),
}

# 事件 Provider -> 与之相关的变更类别（用于过滤掉不相关的事件噪音）
PROVIDER_CATEGORIES: list[tuple[str, set[str] | str]] = [
    (r"Dhcp|Dhcp-Client", {"address", "ip_interface", "dns", "route",
                           "tcpip_interface", "dns_client", "network_profile"}),
    (r"WLAN-AutoConfig|Wlan", {"wlan", "adapter", "address", "dns", "route", "network_profile"}),
    (r"RasClient|RasMan|RasSstp|VPN|Ike|Sstp", {"vpn", "route", "adapter", "address", "dns"}),
    (r"NetworkProfile|NlaSvc|NCSI|NetProfm|Netman", {"network_profile", "dns", "address", "wlan"}),
    (r"Dns-Client|DNS-Client", {"dns", "dns_client", "dns_global", "tcpip_interface"}),
    (r"Tcpip|NetBT", {"address", "route", "ip_interface", "tcpip_interface", "ipv6_global"}),
    (r"NetCfg|Service Control Manager|WindowsUpdateClient",
     {"service", "adapter", "firewall", "ipv6_global"}),
    (r"GroupPolicy", "*"),
    (r"Security-Auditing", "*"),
    (r"Winsock", {"service", "proxy", "adapter"}),
    (r"NetCfg", {"adapter", "service"}),
]

# 值得追踪的「网络配置对象」关键字（用于安全审计 4663 的过滤）
AUDIT_OBJECT_PATTERNS = [
    (r"Tcpip\\Parameters|Tcpip6\\Parameters", "TCP/IP 参数（IP、DNS、网关、IPv6 开关）"),
    (r"Internet Settings", "Internet 选项（系统代理 / PAC）"),
    (r"drivers\\etc\\hosts", "hosts 文件"),
    (r"NetworkCards|ConnectionManager|NetworkList", "网络适配器与网络列表配置"),
    (r"Services\\Dhcp|Services\\Dnscache|Services\\NlaSvc|Services\\Tdx", "网络相关服务配置"),
    (r"Winsock|Winsock2", "Winsock 目录（LSP 注入点）"),
    (r"Policies\\Microsoft\\Windows\\Network", "网络组策略"),
]


def event_relevant(clue: dict, categories: set[str]) -> bool:
    """判断一条事件线索是否与本次变更的类别相关。"""
    if not categories:
        return True
    prov = clue.get("provider") or ""
    for pat, cats in PROVIDER_CATEGORIES:
        if re.search(pat, prov, re.I):
            if cats == "*":
                return True
            return bool(cats & categories)
    return False


OBJ_RE = re.compile(r"(?:对象名(?:称)?|Object Name)\s*[:：]\s*(.+)")
PROC_RE = re.compile(r"(?:进程名(?:称)?|Process Name)\s*[:：]\s*(.+)")


def extract_audit_hits(events: list[dict]) -> list[dict]:
    """从安全审计 4663/4688 中提取「谁改了哪个网络配置对象」。

    这是铁证级溯源：Windows 直接记录了执行修改的进程路径。
    前提是已开启注册表审计（管理员权限执行 auditpol /set /subcategory:"Registry" ...）。
    """
    hits = []
    for e in events:
        if (e.get("Provider") or "") != "Microsoft-Windows-Security-Auditing":
            continue
        msg = e.get("Message") or ""
        mobj = OBJ_RE.search(msg)
        mproc = PROC_RE.search(msg)
        if not mobj:
            continue
        obj = mobj.group(1).strip()
        proc = (mproc.group(1).strip() if mproc else "")
        what = None
        for pat, desc in AUDIT_OBJECT_PATTERNS:
            if re.search(pat, obj, re.I):
                what = desc
                break
        if not what:
            continue
        hits.append({
            "time": e.get("Time"),
            "id": e.get("Id"),
            "object": obj,
            "object_desc": what,
            "process": proc,
        })
    return hits

# 按消息文本兜底匹配： (正则, 含义, 权重)
KEY_TEXT: list[tuple[str, str, int]] = [
    (r"netsh", "检测到 netsh 命令活动（网络配置命令行工具）", 2),
    (r"proxy", "事件涉及代理(proxy)配置", 2),
    (r"\bVPN\b|vpn", "事件涉及 VPN 连接", 2),
    (r"DNS server", "事件涉及 DNS 服务器配置", 2),
    (r"default gateway|网关", "事件涉及默认网关", 2),
    (r"network adapter|网络适配器|网卡", "事件涉及网卡适配器", 1),
    (r"Winsock|LSP", "Winsock 分层服务提供程序(LSP)变更 —— 常由代理/安全软件引起", 3),
    (r"Group Policy|组策略", "组策略下发", 3),
    (r"installed|已安装", "软件/驱动安装活动", 2),
    (r"driver|驱动", "驱动程序活动", 2),
]

# 进程名关键词 -> (归属软件类别, 权重)
PROC_HINTS: list[tuple[str, str, int]] = [
    (r"clash", "Clash 系列代理客户端（Clash for Windows / Clash Verge / Clash Meta）", 3),
    (r"verge", "Clash Verge Rev", 3),
    (r"v2ray|xray|v2rayn|xray-core", "V2Ray / Xray 内核（v2rayN 等客户端）", 3),
    (r"sing-box|singbox", "sing-box 代理内核", 3),
    (r"shadowsocks|shadowsocksr|ssr\.exe|ssr-win|\bssr_", "Shadowsocks / ShadowsocksR 客户端", 3),
    (r"trojan|naiveproxy|hysteria|tuic", "Trojan / NaiveProxy / Hysteria 类代理客户端", 3),
    (r"wireguard|\bwg\.exe|\bwg\d", "WireGuard VPN", 3),
    (r"openvpn|tap-?windows", "OpenVPN 客户端", 3),
    (r"anyconnect|vpnagent|vpnui", "Cisco AnyConnect VPN", 3),
    (r"forticlient|forti", "FortiClient VPN", 3),
    (r"globalprotect|pangp|pan-gp", "Palo Alto GlobalProtect VPN", 3),
    (r"easyconnect|sangfor|svpn", "深信服 EasyConnect VPN", 3),
    (r"zerotier", "ZeroTier One（虚拟局域网）", 3),
    (r"tailscale", "Tailscale（虚拟局域网）", 3),
    (r"hamachi|logmein", "LogMeIn Hamachi（虚拟局域网）", 3),
    (r"radmin", "Radmin VPN", 3),
    (r"wsl|wslservice|wslhost", "WSL（Linux 子系统）", 2),
    (r"docker|com\.docker", "Docker Desktop", 3),
    (r"vmware|vmnet", "VMware 虚拟机", 2),
    (r"vbox|virtualbox", "Oracle VirtualBox 虚拟机", 2),
    (r"adguard", "AdGuard（广告过滤 / 本地 DNS 过滤）", 3),
    (r"acrylic", "Acrylic DNS Proxy（本地 DNS 代理）", 3),
    (r"dnsmasq", "dnsmasq（本地 DNS 服务）", 3),
    (r"fiddler", "Fiddler（HTTP 抓包代理）", 3),
    (r"charles", "Charles（HTTP 抓包代理）", 3),
    (r"proxifier|proxifier\.exe", "Proxifier（强制走代理）", 3),
    (r"lantern|蓝灯", "Lantern（蓝灯）", 3),
    (r"netsh", "netsh.exe —— 系统自带网络配置命令行工具，说明有人在（或有脚本）执行网络配置命令", 3),
    (r"rasphone|rasdial", "系统 VPN/拨号客户端（rasphone / rasdial）", 3),
    (r"powershell|pwsh", "PowerShell 脚本在执行（可能包含网络配置命令）", 2),
    (r"msiexec|setup\.exe|installer", "安装程序正在运行（MSI / Setup / Installer）", 2),
    (r"thunder|迅雷|xunlei", "迅雷（会创建虚拟网卡/LSP）", 2),
    (r"360|qhsafe|huorong|火绒|kafe", "安全软件（360 / 火绒等，常接管网络过滤）", 2),
]

# 服务关键词 -> 归属
SVC_HINTS: list[tuple[str, str, int]] = [
    (r"\btap\b|tap-?windows|tap0\d|openvpn", "OpenVPN TAP 适配器服务", 3),
    (r"wireguard", "WireGuard 隧道服务", 3),
    (r"zerotier", "ZeroTier One 服务", 3),
    (r"tailscale", "Tailscale 服务", 3),
    (r"docker", "Docker Desktop 服务", 3),
    (r"vpn|rasman|ikestore|policyagent|sstp", "系统 VPN / 远程访问相关服务", 2),
    (r"dhcp", "DHCP 客户端/服务器服务", 3),
    (r"nlasvc|netprofm", "网络位置感知(NLA)服务", 3),
    (r"\bdns(cache|client|srv)?\b|dnscache", "DNS 客户端服务", 2),
    (r"mpssvc", "Windows Defender 防火墙服务", 3),
    (r"winhttp|webproxy", "WinHTTP Web 代理自动发现服务", 3),
    (r"wlansvc|wlanautoconfig", "WLAN 自动配置服务", 3),
    (r"dot3svc", "有线 802.1X 认证服务（校园网/企业网络常用）", 3),
]

# 网卡名/描述 -> 归属软件
VNIC_PATTERNS: list[tuple[str, str]] = [
    (r"Hyper-V", "Hyper-V / WSL2 / Docker Desktop（基于 Hyper-V 的虚拟交换机）"),
    (r"WSL", "WSL（Windows Subsystem for Linux）虚拟交换机"),
    (r"Docker", "Docker Desktop"),
    (r"VirtualBox", "Oracle VirtualBox"),
    (r"VMware|VMnet", "VMware Workstation / Player"),
    (r"TAP-|tap-windows|OpenVPN", "OpenVPN / TAP-Windows 虚拟网卡"),
    (r"WireGuard", "WireGuard VPN"),
    (r"ZeroTier", "ZeroTier One"),
    (r"Tailscale", "Tailscale"),
    (r"Hamachi|LogMeIn", "LogMeIn Hamachi"),
    (r"AnyConnect", "Cisco AnyConnect VPN"),
    (r"Fortinet|Forti", "FortiClient VPN"),
    (r"PANGP|GlobalProtect|PanGp", "Palo Alto GlobalProtect VPN"),
    (r"Sangfor|EasyConnect", "深信服 EasyConnect VPN"),
    (r"Radmin", "Radmin VPN"),
    (r"iNode|Ruijie|锐捷", "校园网认证客户端（iNode / 锐捷）"),
    (r"Npcap|WinPcap|NPCAP", "Npcap / WinPcap 抓包驱动（Wireshark、Nmap 等安装）"),
    (r"Sunlogin|Oray|向日葵|贝锐", "向日葵远程控制"),
    (r"ToDesk", "ToDesk 远程控制"),
    (r"Bluetooth", "蓝牙个人局域网"),
]

# 公共 DNS 归属
KNOWN_DNS: dict[str, str] = {
    "114.114.114.114": "114DNS（南京信风）", "114.114.115.115": "114DNS 备用",
    "223.5.5.5": "阿里 AliDNS", "223.6.6.6": "阿里 AliDNS 备用",
    "2400:3200::1": "阿里 AliDNS(IPv6)", "2400:3200:baba::1": "阿里 AliDNS(IPv6)",
    "119.29.29.29": "腾讯 DNSPod", "119.28.28.28": "腾讯 DNSPod 备用",
    "182.254.116.116": "腾讯 DNSPod 备用", "182.254.118.118": "腾讯 DNSPod 备用",
    "1.2.4.8": "CNNIC SDNS（中国互联网络信息中心）", "210.2.4.8": "CNNIC SDNS 备用",
    "8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS 备用",
    "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS 备用",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9 备用",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS 备用",
    "101.226.4.6": "中国电信 DNS", "218.30.118.6": "中国电信 DNS 备用",
    "123.125.81.6": "中国联通 DNS", "140.207.198.6": "中国联通 DNS 备用",
    "211.136.192.6": "中国移动 DNS", "211.136.150.66": "中国移动 DNS 备用",
    "117.50.10.10": "华为云 DNS", "117.50.11.11": "华为云 DNS 备用",
    "180.76.76.76": "百度 DNS", "223.5.5.5": "阿里 AliDNS",
    "156.154.70.1": "Comodo Secure DNS", "156.154.71.1": "Comodo Secure DNS",
}

# 本机代理端口归属
PROXY_PORTS: dict[str, str] = {
    "7890": "Clash 系列默认 HTTP/混合端口",
    "7891": "Clash 默认 SOCKS 端口",
    "7897": "Clash 混合代理端口",
    "1080": "Shadowsocks / 通用 SOCKS5 端口",
    "1081": "v2rayN 旧版 HTTP 端口",
    "1087": "ShadowsocksR 默认端口",
    "10808": "v2rayN SOCKS 端口",
    "10809": "v2rayN HTTP 端口",
    "2080": "Shadowsocks 旧版端口",
    "8888": "Fiddler / Charles 抓包代理",
    "8889": "Fiddler 备用端口",
    "8899": "通用本地代理端口",
    "8080": "通用 HTTP 代理端口",
    "3128": "Squid 代理",
    "20171": "Lantern（蓝灯）",
    "33210": "Lantern（蓝灯）",
    "53": "本地 DNS 服务（DNS 代理）",
    "5353": "mDNS / 本地 DNS 代理",
    "4780": "ZeroNet / 通用本地端口",
    "6152": "Surge / 通用本地端口",
}


def interpret_events(events: list[dict]) -> list[dict]:
    """把原始事件翻译成带含义和权重的线索。"""
    out = []
    for e in events:
        prov = (e.get("Provider") or "").strip()
        eid = e.get("Id")
        msg = (e.get("Message") or "").strip()
        meaning, weight = None, 1
        for (p_re, pid), (m, w) in KEY_EVENTS.items():
            if re.search(p_re, prov, re.I) and eid == pid:
                meaning, weight = m, w
                break
        if meaning is None:
            for pat, m, w in KEY_TEXT:
                if re.search(pat, msg, re.I) or re.search(pat, prov, re.I):
                    meaning, weight = m, w
                    break
        if meaning is None:
            continue
        out.append({
            "time": e.get("Time"),
            "provider": prov,
            "id": eid,
            "level": e.get("Level"),
            "log": e.get("Log"),
            "meaning": meaning,
            "weight": weight,
            "message": msg[:300],
        })
    out.sort(key=lambda x: (-(x["weight"]), x["time"] or ""))
    return out


def hint_from_text(text: str | None, table: list[tuple[str, str, int]]) -> tuple[str, int] | None:
    if not text:
        return None
    for pat, name, w in table:
        if re.search(pat, text, re.I):
            return name, w
    return None


# 位于系统受保护目录下的进程，只用「进程名」严格匹配，避免命令行/路径里的
# 偶然子串造成误判（例如 NisSrv.exe 被 ssr 模式命中）。
SYSTEM_PATH_RE = re.compile(
    r"^(?:[A-Za-z]:)?\\(?:"
    r"Windows\\(?:System32|SysWOW64|WinSxS|SystemApps|servicing|Microsoft\.NET|ImmersiveControlPanel)|"
    r"Program Files\\(?:Windows Defender|WindowsApps|Windows NT)|"
    r"ProgramData\\Microsoft\\Windows Defender|"
    r"Windows\\UUS\\Packages)",
    re.I)


def hint_for_process(proc: dict) -> tuple[str, int] | None:
    """为进程判定归属。系统目录下的进程只按进程名匹配，避免路径/命令行误判。"""
    name = str(proc.get("Name") or "")
    exe = str(proc.get("ExecutablePath") or "")
    if exe and SYSTEM_PATH_RE.search(exe):
        return hint_from_text(name, PROC_HINTS)
    blob = " ".join(str(proc.get(k) or "") for k in ("Name", "CommandLine", "ExecutablePath"))
    return hint_from_text(blob, PROC_HINTS)


def vnic_owner(text: str) -> str | None:
    for pat, name in VNIC_PATTERNS:
        if re.search(pat, text, re.I):
            return name
    return None


def dns_owner(ip: str) -> str | None:
    ip = ip.strip()
    if ip in KNOWN_DNS:
        return KNOWN_DNS[ip]
    if ip.startswith("2400:3200") or ip.startswith("2402:4e00") or ip.startswith("2408:"):
        return "运营商/公共 IPv6 DNS"
    return None


def proxy_port_owner(server: str) -> tuple[str, str] | None:
    """从代理服务器串推断归属软件，返回 (软件名, 判定依据)。"""
    if not server:
        return None
    s = server.strip()
    host, _, port = s.rpartition(":")
    if not port.isdigit():
        return None
    if host.lower() in ("127.0.0.1", "localhost", "::1", "[::1]"):
        owner = PROXY_PORTS.get(port)
        if owner:
            return owner, f"本机回环端口 {port}"
        return "本机运行的代理/抓包类软件", f"代理指向本机回环地址端口 {port}"
    return "局域网或远程代理服务器（如路由器上的代理、公司代理）", f"代理指向 {host}:{port}"


def parse_dmtf(t: str | None) -> str | None:
    """把 WMI DMTF 时间转成 ISO。"""
    if not t:
        return None
    try:
        if "." in t:
            t = t.split(".")[0]
        return datetime.strptime(t, "%Y%m%d%H%M%S").isoformat() + "Z"
    except Exception:
        return None
