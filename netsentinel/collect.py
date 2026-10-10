"""
网络配置采集层。

通过一次性 PowerShell 调用抓取系统网络状态全量快照：
网卡 / IP / DNS / 路由 / 代理 / hosts / 网络配置文件 / VPN / 防火墙 /
注册表 Tcpip 参数 / WiFi / 网络相关服务与进程 / 近期安装软件。

设计原则：零第三方依赖，仅依赖 Windows 自带 PowerShell，便于离线运行。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# PowerShell 采集脚本（保持 ASCII-only，避免 PS 5.1 读取 ps1 的编码问题）
# ---------------------------------------------------------------------------

PS_COLLECT = r"""
param([string]$OutFile)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Arr { param($x) if ($null -eq $x) { return @() } return @($x) }

$r = [ordered]@{}
$r.collected_at = (Get-Date).ToUniversalTime().ToString('o')
$r.hostname = $env:COMPUTERNAME
$r.username = "$env:USERDOMAIN\$env:USERNAME"
$r.ps_version = $PSVersionTable.PSVersion.ToString()
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -First 1
$r.os_caption = $os.Caption
$r.os_build = $os.BuildNumber
$r.uptime = $os.LastBootUpTime

$r.adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Select-Object Name,InterfaceDescription,ifIndex,ifAlias,Status,MacAddress,
                  LinkSpeed,MediaType,MtuSize,AdminStatus,MediaConnectionState,
                  InterfaceGuid,DriverVersion,DriverDate)

$r.ip_interfaces = @(Get-NetIPInterface -ErrorAction SilentlyContinue |
    Select-Object ifIndex,InterfaceAlias,AddressFamily,Dhcp,Metric,ConnectionState,
                  Forwarding,NlMtu,InterfaceMetric,AutomaticMetric,RouterDiscovery)

$r.addresses = @(Get-NetIPAddress -ErrorAction SilentlyContinue |
    Select-Object ifIndex,InterfaceAlias,IPAddress,PrefixLength,AddressFamily,Type,
                  PrefixOrigin,SuffixOrigin,SkipAsSource)

$r.dns_servers = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
    Select-Object ifIndex,InterfaceAlias,AddressFamily,ServerAddresses)

$r.dns_clients = @(Get-DnsClient -ErrorAction SilentlyContinue |
    Select-Object ifIndex,InterfaceAlias,ConnectionSpecificSuffix,
                  ConnectionSpecificSuffixSearchList,RegisterThisConnectionsAddress,
                  UseSuffixWhenRegistering)

$r.dns_global = @(Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue |
    Select-Object SuffixSearchList,UseSuffixWhenRegistering)

$r.routes = @(Get-NetRoute -ErrorAction SilentlyContinue |
    Select-Object ifIndex,InterfaceAlias,DestinationPrefix,NextHop,RouteMetric,
                  Protocol,State,AddressFamily,Publish)

$r.profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias,InterfaceIndex,Name,NetworkCategory,
                  IPv4Connectivity,IPv6Connectivity,DomainAuthenticationKind)

# ---------------- proxy ----------------
$iePath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$ie = Get-ItemProperty -Path $iePath -ErrorAction SilentlyContinue
$r.proxy_user = [ordered]@{
    ProxyEnable   = $ie.ProxyEnable
    ProxyServer   = $ie.ProxyServer
    ProxyOverride = $ie.ProxyOverride
    AutoConfigURL = $ie.AutoConfigURL
    AutoDetect    = $ie.AutoDetect
}

$iePath2 = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$ie2 = Get-ItemProperty -Path $iePath2 -ErrorAction SilentlyContinue
$r.proxy_machine = [ordered]@{
    ProxyEnable   = $ie2.ProxyEnable
    ProxyServer   = $ie2.ProxyServer
    ProxyOverride = $ie2.ProxyOverride
    AutoConfigURL = $ie2.AutoConfigURL
}

# 注意：netsh 的中文输出与 hosts 文件编码由 Python 端处理（见 collect.py 下方），
# 这里不直接捕获，避免 PowerShell 按系统代码页解码造成乱码。

# ---------------- tcpip registry ----------------
$tcpIf = @()
$base = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
if (Test-Path $base) {
    foreach ($k in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
        $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
        if ($null -eq $p) { continue }
        $tcpIf += [ordered]@{
            Guid              = $k.PSChildName
            NameServer        = $p.NameServer
            DhcpNameServer    = $p.DhcpNameServer
            IPAddress         = $p.IPAddress
            DhcpIPAddress     = $p.DhcpIPAddress
            SubnetMask        = $p.SubnetMask
            DefaultGateway    = $p.DefaultGateway
            DhcpDefaultGateway= $p.DhcpDefaultGateway
            DhcpServer        = $p.DhcpServer
            Domain            = $p.Domain
            DhcpDomain        = $p.DhcpDomain
            SearchList        = $p.SearchList
            EnableDHCP        = $p.EnableDHCP
            Lease             = $p.Lease
            LeaseObtainedTime = $p.LeaseObtainedTime
            LeaseTerminatesTime = $p.LeaseTerminatesTime
        }
    }
}
$r.tcpip_interfaces = $tcpIf

$tp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction SilentlyContinue
$r.tcpip_global = [ordered]@{
    Domain     = $tp.Domain
    SearchList = $tp.SearchList
    DhcpDomain = $tp.DhcpDomain
    NV_Domain  = $tp.'NV Domain'
    Hostname   = $tp.Hostname
}

$t6 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -ErrorAction SilentlyContinue
$r.ipv6_global = [ordered]@{ DisabledComponents = $t6.DisabledComponents }

# ---------------- vpn / firewall / domain ----------------
$r.vpn_connections = @(Get-VpnConnection -ErrorAction SilentlyContinue |
    Select-Object Name,ServerAddress,TunnelType,AuthenticationMethod,SplitTunneling,ConnectionStatus)

$r.firewall = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue |
    Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction)

$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1
$r.domain = [ordered]@{ PartOfDomain = $cs.PartOfDomain; Domain = $cs.Domain; UserDnsDomain = $env:USERDNSDOMAIN }

$polPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation'
$r.gpo_network_present = (Test-Path $polPath)

# ---------------- services & processes ----------------
$svcKw = 'vpn|clash|v2ray|xray|sing-box|shadowsock|trojan|wireguard|openvpn|anyconnect|forti|' +
         'globalprotect|pangp|zerotier|hamachi|tailscale|wsl|docker|vmware|vbox|virtualbox|' +
         'adguard|acrylic|dnsmasq|fiddler|charles|proxifier|lantern|dhcp|nla|dot3|wlansvc|' +
         'rasman|tap|netman|iphlp|dns|mpssvc|winhttp|webproxy|netprofm|nlasvc|ikestore|' +
         'policyagent|sstpsvc|eap|netsetup|ncbservice|wlanautoconfig|netlogon'
$r.services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $svcKw -or $_.DisplayName -match $svcKw -or $_.PathName -match $svcKw } |
    Select-Object Name,DisplayName,State,StartMode,PathName,ProcessId)

$procKw = 'vpn|clash|v2ray|xray|sing|shadowsock|ssr|trojan|wireguard|openvpn|anyconnect|forti|' +
          'globalprotect|pangp|zerotier|hamachi|tailscale|wsl|docker|vmware|vbox|virtualbox|' +
          'adguard|acrylic|dnsmasq|fiddler|charles|proxifier|lantern|netsh|rasphone|rasdial|' +
          'powershell|wscript|cscript|msiexec|innounp|setup|installer'
$r.processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $procKw -or $_.CommandLine -match $procKw } |
    Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate)

# ---------------- recently installed software ----------------
$unPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
$apps = @()
foreach ($p in $unPaths) {
    $apps += @(Get-ItemProperty $p -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation)
}
$r.installed_apps = @($apps | Where-Object { $_.InstallDate -and $_.InstallDate -match '^\d{8}$' } |
    Sort-Object InstallDate -Descending | Select-Object -First 80)

$json = $r | ConvertTo-Json -Depth 8 -Compress
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutFile, $json, $enc)
"""

PS_EVENTS = r"""
param([string]$OutFile, [string]$StartTime, [string]$EndTime)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$st = ([datetime]::Parse($StartTime)).ToUniversalTime()
$et = ([datetime]::Parse($EndTime)).ToUniversalTime()

$logs = @(
    'System',
    'Application',
    'Microsoft-Windows-Dhcp-Client/Admin',
    'Microsoft-Windows-Dhcp-Client/Operational',
    'Microsoft-Windows-NetworkProfile/Operational',
    'Microsoft-Windows-WLAN-AutoConfig/Operational',
    'Microsoft-Windows-RasClient/Operational',
    'Microsoft-Windows-NCSI/Operational',
    'Microsoft-Windows-Dns-Client/Operational',
    'Microsoft-Windows-NetCfg/Operational',
    'Microsoft-Windows-WindowsUpdateClient/Operational',
    'Microsoft-Windows-GroupPolicy/Operational',
    'Microsoft-Windows-NetworkLocationWizard/Operational',
    'Microsoft-Windows-VPN-Client/Operational'
)

# Security 日志需管理员权限；若已开启注册表审计，4663 能直接给出「哪个进程改了哪条注册表」。
$secEvents = @(Get-WinEvent -FilterHashtable `
    @{LogName='Security'; Id=@(4663,4688); StartTime=$st; EndTime=$et} `
    -MaxEvents 200 -ErrorAction SilentlyContinue)

$interesting = 'Dhcp|Dhcp-Client|Tcpip|Tcpip6|NetBT|RasMan|RasClient|RasSstp|RasAgileVpn|' +
    'NlaSvc|NetProfm|Netman|WLAN-AutoConfig|NetworkProfile|ipnathlp|NetCfg|' +
    'Service Control Manager|GroupPolicy|Dns-Client|DNS-Client|NCSI|' +
    'NetworkLocationWizard|VPN-Client|Winsock|WindowsUpdateClient|Microsoft-Windows-Network'

$events = @()
foreach ($e in $secEvents) {
    $msg = ''
    try { $msg = $e.Message } catch { $msg = '' }
    $events += [ordered]@{
        Time     = $e.TimeCreated.ToUniversalTime().ToString('o')
        Log      = 'Security'
        Provider = 'Microsoft-Windows-Security-Auditing'
        Id       = $e.Id
        Level    = $e.LevelDisplayName
        Task     = $e.TaskDisplayName
        Message  = $msg
    }
}
foreach ($lg in $logs) {
    $items = @()
    if ($lg -eq 'System' -or $lg -eq 'Application') {
        $items = @(Get-WinEvent -FilterHashtable @{LogName=$lg; StartTime=$st; EndTime=$et} `
                   -MaxEvents 300 -ErrorAction SilentlyContinue |
                   Where-Object { $_.ProviderName -match $interesting })
    } else {
        $items = @(Get-WinEvent -FilterHashtable @{LogName=$lg; StartTime=$st; EndTime=$et} `
                   -MaxEvents 150 -ErrorAction SilentlyContinue)
    }
    foreach ($e in $items) {
        $msg = ''
        try { $msg = $e.Message } catch { $msg = '' }
        if ($msg.Length -gt 600) { $msg = $msg.Substring(0, 600) }
        $events += [ordered]@{
            Time     = $e.TimeCreated.ToUniversalTime().ToString('o')
            Log      = $lg
            Provider = $e.ProviderName
            Id       = $e.Id
            Level    = $e.LevelDisplayName
            Task     = $e.TaskDisplayName
            Message  = $msg
        }
    }
}

$out = [ordered]@{ events = @($events | Sort-Object Time) }
$json = $out | ConvertTo-Json -Depth 6 -Compress
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutFile, $json, $enc)
"""


def _find_powershell() -> str:
    """定位可用的 PowerShell 可执行文件。"""
    for exe in ("powershell.exe", "pwsh.exe"):
        try:
            r = subprocess.run(
                [exe, "-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"],
                capture_output=True, timeout=20,
            )
            if r.returncode == 0 and r.stdout.strip():
                return exe
        except Exception:
            continue
    raise RuntimeError("未找到可用的 PowerShell（powershell.exe / pwsh.exe）")


def _run_ps(script: str, args: list[str], timeout: int = 120) -> dict:
    """执行 PowerShell 脚本并返回解析后的 JSON。"""
    exe = _find_powershell()
    tmpdir = tempfile.mkdtemp(prefix="netsentinel_")
    ps1 = Path(tmpdir) / "collect.ps1"
    out = Path(tmpdir) / "out.json"
    ps1.write_text(script, encoding="ascii", errors="ignore")
    cmd = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
           "-File", str(ps1)] + args + ["-OutFile", str(out)]
    # 注意：OutFile 参数需放在脚本参数之后
    proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if not out.exists():
        raise RuntimeError(
            f"PowerShell 采集失败 (exit={proc.returncode})\n"
            f"STDERR: {proc.stderr.decode('utf-8', 'ignore')[:800]}"
        )
    text = out.read_text(encoding="utf-8", errors="replace")
    try:
        ps1.unlink(missing_ok=True)
        out.unlink(missing_ok=True)
        Path(tmpdir).rmdir()
    except Exception:
        pass
    return json.loads(text)


def _norm_list(v: Any) -> list:
    """PowerShell 单元素数组会被压平成对象，统一归一化成列表。"""
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


# ---------------------------------------------------------------------------
# 枚举值 -> 可读文本（PowerShell 序列化 CIM 枚举时给出的是数字）
# ---------------------------------------------------------------------------

ENUM_MAPS: dict[str, dict[int, str]] = {
    "AddressFamily": {2: "IPv4", 23: "IPv6", 4: "IPv4", 6: "IPv6"},
    "NetworkCategory": {0: "公用网络", 1: "专用网络", 2: "域网络"},
    "DomainAuthenticationKind": {0: "无", 1: "LDAP", 2: "TLS", 3: "Windows 集成"},
    "IPv4Connectivity": {0: "无网络", 1: "无流量", 2: "仅子网", 3: "本地网络", 4: "Internet"},
    "IPv6Connectivity": {0: "无网络", 1: "无流量", 2: "仅子网", 3: "本地网络", 4: "Internet"},
    "Protocol": {1: "Other", 2: "Local", 3: "NetMgmt(管理配置)", 4: "IcmpRedirect",
                 5: "RouterDiscovery", 6: "Ras(拨号/VPN)", 7: "Dhcp"},
    "State": {0: "Alive", 1: "Alive", 2: "Dead"},
    "PrefixOrigin": {0: "Other", 1: "手动(Manual)", 2: "系统(WellKnown)", 3: "DHCP",
                     4: "路由通告(RA)"},
    "SuffixOrigin": {0: "Other", 1: "手动(Manual)", 2: "系统(WellKnown)", 3: "DHCP",
                     4: "路由通告(RA)"},
    "Type": {0: "未知", 1: "单播", 2: "任播", 3: "组播"},
    "Dhcp": {0: "关闭", 1: "启用"},
    "EnableDHCP": {0: "关闭(静态)", 1: "启用"},
    "ConnectionState": {0: "已断开", 1: "连接中", 2: "已连接", 3: "断开中"},
    "AdminStatus": {1: "已启用", 2: "已禁用", 3: "测试中"},
    "MediaConnectionState": {0: "未知", 1: "已连接", 2: "已断开"},
    "Publish": {0: "否", 1: "是", 2: "Age"},
    "Forwarding": {0: "否", 1: "是"},
    "AutomaticMetric": {0: "否", 1: "是"},
    "RouterDiscovery": {0: "禁用", 1: "启用", 2: "由 DHCP 控制"},
    "Enabled": {0: "关闭", 1: "启用"},
    "ProxyEnable": {0: "关闭", 1: "启用"},
    "AutoDetect": {0: "关闭", 1: "启用"},
    "RegisterThisConnectionsAddress": {0: "否", 1: "是"},
    "SkipAsSource": {0: "否", 1: "是"},
    "SplitTunneling": {0: "关闭", 1: "启用"},
}


def _map_field(field: str, v: Any) -> Any:
    m = ENUM_MAPS.get(field)
    if m and isinstance(v, int) and not isinstance(v, bool):
        return m.get(v, v)
    if m and isinstance(v, str) and v.strip().isdigit():
        return m.get(int(v.strip()), v)
    return v


def _normalize_rows(rows: list) -> list:
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append({k: _map_field(k, v) for k, v in r.items()})
        else:
            out.append(r)
    return out


def normalize(snap: dict) -> dict:
    """把快照中的枚举数字转成可读文本，便于对比与展示。"""
    for f in ("adapters", "ip_interfaces", "addresses", "routes", "profiles",
              "firewall", "dns_servers", "dns_clients", "dns_global",
              "vpn_connections", "tcpip_interfaces"):
        if f in snap:
            snap[f] = _normalize_rows(snap[f])
    for f in ("proxy_user", "proxy_machine"):
        if f in snap and isinstance(snap[f], dict):
            snap[f] = {k: _map_field(k, v) for k, v in snap[f].items()}
    return snap


LIST_FIELDS = (
    "adapters", "ip_interfaces", "addresses", "dns_servers", "dns_clients",
    "dns_global", "routes", "profiles", "vpn_connections", "firewall",
    "tcpip_interfaces", "installed_apps", "services", "processes",
    "winhttp_raw", "wlan_raw",
)


def _decode(raw: bytes) -> str:
    """外部控制台程序（netsh）与 hosts 文件的输出可能是 UTF-8 或 GBK，做严格探测。"""
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    for enc in ("gbk", "cp936", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _netsh(args: list[str]) -> list[str]:
    try:
        r = subprocess.run(["netsh"] + args, capture_output=True, timeout=30)
        raw = r.stdout or b""
    except Exception:
        return []
    return [l.rstrip() for l in _decode(raw).splitlines()]


def _read_hosts() -> dict:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    p = Path(root) / "System32" / "drivers" / "etc" / "hosts"
    info: dict = {"Path": str(p), "Exists": False, "Sha256": None,
                  "MTime": None, "Size": 0, "Lines": []}
    try:
        if not p.exists():
            return info
        raw = p.read_bytes()
        txt = _decode(raw)
        st = p.stat()
        from datetime import datetime, timezone
        info.update({
            "Exists": True,
            "Sha256": hashlib.sha256(raw).hexdigest(),
            "MTime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
            "Size": len(raw),
            "Lines": [l.strip() for l in txt.splitlines()
                      if l.strip() and not l.strip().startswith("#")],
        })
    except Exception:
        pass
    return info


def collect_snapshot() -> dict:
    """采集一次完整的网络配置快照。"""
    data = _run_ps(PS_COLLECT, [])
    for f in LIST_FIELDS:
        if f in data:
            data[f] = _norm_list(data[f])
    data["hosts"] = _read_hosts()
    data["wlan_raw"] = _netsh(["wlan", "show", "interfaces"])
    data["winhttp_raw"] = _netsh(["winhttp", "show", "proxy"])
    data["_schema"] = 1
    return normalize(data)


def collect_events(start: datetime, end: datetime, timeout: int = 90) -> list[dict]:
    """采集指定时间窗内的网络相关 Windows 事件日志。"""
    args = ["-StartTime", start.strftime("%Y-%m-%d %H:%M:%S"),
            "-EndTime", end.strftime("%Y-%m-%d %H:%M:%S")]
    try:
        data = _run_ps(PS_EVENTS, args, timeout=timeout)
    except Exception:
        return []
    return _norm_list((data or {}).get("events"))


# ---------------------------------------------------------------------------
# netsh wlan 输出解析（中英文环境兼容）
# ---------------------------------------------------------------------------

def parse_wlan(raw_lines: list[str]) -> dict:
    """解析 netsh wlan show interfaces。多网卡时只取第一个接口块。"""
    info: dict = {"connected": False, "ssid": None, "signal": None,
                  "interface": None, "bssid": None, "channel": None}
    if not raw_lines:
        return info
    started = False
    for line in raw_lines:
        if ":" not in line and "：" not in line:
            continue
        sep = ":" if ":" in line else "："
        key, _, val = line.partition(sep)
        key = key.strip()
        val = val.strip()
        low = key.lower()
        if low in ("name", "接口名称", "名称", "interface name"):
            if started:
                break          # 进入第二个接口块，停止
            started = True
            info["interface"] = val or None
        elif low.startswith("ssid"):
            info["ssid"] = val or None
        elif low in ("state", "状态", "status"):
            info["connected"] = any(w in val for w in ("connected", "已连接"))
        elif "信号" in low or low.startswith("signal"):
            info["signal"] = val or None
        elif "bssid" in low:
            info["bssid"] = val or None
        elif "信道" in low or low.startswith("channel"):
            info["channel"] = val or None
    return info


def parse_winhttp(raw_lines: list[str]) -> dict:
    """解析 netsh winhttp show proxy 输出。"""
    txt = "\n".join(raw_lines or [])
    m = re.search(r"(?:代理服务器|Proxy Server)\s*[:：]\s*(.+)", txt, re.I)
    server = m.group(1).strip() if m else None
    bypass = None
    m2 = re.search(r"(?:绕过列表|Bypass List)\s*[:：]\s*(.+)", txt, re.I)
    if m2:
        bypass = m2.group(1).strip()
    if server and server.lower() in ("direct access", "直接访问", "(none)", "无"):
        server = None
    return {"server": server, "bypass": bypass, "raw": txt.strip(),
            "sha": hashlib.sha256(txt.strip().encode("utf-8", "ignore")).hexdigest()[:16]}
