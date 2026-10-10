"""
隐私脱敏层。

在生成可分享的示例报告前，把快照中的个人 identifiable 信息替换掉：
主机名、用户名、MAC 地址、真实 IP / 路由、DNS、SSID 与网络名、
hosts 内容、已安装软件列表、进程命令行中的用户路径。

设计原则：
- 保留「结构特征」（地址类别、APIPA、回环、隧道网段、变更形态），
  因为报告的价值在于展示这类特征，而不是具体数值。
- 公网 IPv4 映射到 RFC 5737 文档保留段 203.0.113.0/24；
  IPv6 映射到 RFC 3849 文档保留段 2001:db8::/32。
- 映射确定性：同一原值每次得到同一替换值，保证两次快照仍可正确对比。
"""

from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

FAKE_HOST = "DEMO-PC"
FAKE_USER = "user"
FAKE_OS = "Microsoft Windows 11"

_NET_NAMES = ["Office-WiFi", "Home-5G", "Campus-Net", "Guest-WiFi",
              "Lab-Ethernet", "Mobile-Hotspot"]


def _h(s: str, salt: str = "") -> int:
    return int(hashlib.sha256((salt + str(s)).encode("utf-8", "ignore")).hexdigest()[:8], 16)


def _is_ipv4(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s.strip()))


def _is_ipv6(s: str) -> bool:
    return ":" in s and not _is_ipv4(s)


def sanitize_ip(ip: str) -> str:
    """替换 IP，但保留其类别特征（APIPA / 回环 / 私有段 / 隧道段）。"""
    if not ip:
        return ip
    s = str(ip).strip()
    if _is_ipv6(s):
        m = re.match(r"^(fe80::[0-9a-fA-F:.]+)%(\d+)$", s)
        if m:
            return f"fe80::{_h(m.group(1)) % 0xFFFF:x}:{_h(m.group(1), 'b') % 0xFFFF:x}%{m.group(2)}"
        if s.lower().startswith("fec0:") or s.lower().startswith("fe80"):
            return f"fe80::{_h(s) % 0xFFFF:x}:{_h(s, 'b') % 0xFFFF:x}"
        if s == "::1":
            return s
        return f"2001:db8:{_h(s) % 0xFFFF:x}:{_h(s, 'b') % 0xFFFF:x}::1"
    if not _is_ipv4(s):
        return s
    if s in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "1.1.1.1"):
        return s
    if s.startswith("127."):
        return "127.0.0.1"
    n = [int(x) for x in s.split(".")]
    tail = _h(s) % 254 + 1
    if n[0] == 169 and n[1] == 254:
        return f"169.254.{_h(s, 'a') % 256}.{tail}"          # 保留 APIPA 特征
    if n[0] == 10:
        return f"10.0.{_h(s, 'a') % 256}.{tail}"
    if n[0] == 172 and 16 <= n[1] <= 31:
        return f"172.16.{_h(s, 'a') % 256}.{tail}"
    if n[0] == 192 and n[1] == 168:
        return f"192.168.1.{tail}"
    if n[0] == 198 and n[1] == 18:
        return f"198.18.0.{tail}"                             # 保留 TUN 隧道特征
    if n[0] == 100 and 64 <= n[1] <= 127:
        return f"100.64.0.{tail}"                             # CGNAT
    return f"203.0.113.{tail}"                                # 公网 -> 文档保留段


def sanitize_prefix(prefix: str) -> str:
    if "/" not in prefix:
        return sanitize_ip(prefix)
    net, _, plen = prefix.partition("/")
    return f"{sanitize_ip(net)}/{plen}"


def sanitize_mac(mac: str) -> str:
    """换成局部管理地址（第二字符为 2/6/A/E 即非真实厂商），保留确定性。"""
    if not mac:
        return mac
    return "0A-00-00-{:02X}-{:02X}-{:02X}".format(
        _h(mac, "m1") % 256, _h(mac, "m2") % 256, _h(mac, "m3") % 256)


def sanitize_guid(guid: str) -> str:
    if not guid:
        return guid
    h = hashlib.sha256(str(guid).encode("utf-8", "ignore")).hexdigest()
    return f"{{{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}}}"


def sanitize_domain(d: str) -> str:
    if not d:
        return d
    s = str(d).strip()
    if re.search(r"\bexample\.(com|net|org|internal|local)\b", s, re.I):
        return s
    return "example.internal" if "local" in s.lower() or "lan" in s.lower() else "example.com"


def sanitize_netname(name: str) -> str:
    if not name:
        return name
    return _NET_NAMES[_h(str(name), "net") % len(_NET_NAMES)]


def sanitize_hosts(hosts: dict | None) -> dict:
    """替换为示例条目 —— hosts 里常含个人习惯访问的站点，属敏感信息。"""
    if not hosts:
        return {"Path": r"C:\Windows\System32\drivers\etc\hosts", "Exists": True,
                "Sha256": "0" * 64, "MTime": None, "Size": 0, "Lines": []}
    h = dict(hosts)
    n = len(h.get("Lines") or [])
    h["Lines"] = [f"127.0.0.1 local{i}.example.com" for i in range(1, min(n, 6) + 1)]
    h["Sha256"] = hashlib.sha256("demo".encode()).hexdigest()
    h["Size"] = 1024
    h["MTime"] = None
    return h


def sanitize_path(p: str) -> str:
    """去掉路径中的真实用户名。"""
    if not p:
        return p
    s = str(p)
    s = re.sub(r"([A-Za-z]:\\Users\\)[^\\]+", r"\1" + FAKE_USER, s)
    s = re.sub(r"(\\Users\\)[^\\]+", r"\1" + FAKE_USER, s)
    return s


def sanitize_snapshot(snap: dict) -> dict:
    """对整份快照做脱敏。"""
    s = copy.deepcopy(snap)
    real_host = str(s.get("hostname") or "")
    real_user_full = str(s.get("username") or "")
    real_user = real_user_full.split("\\")[-1] if real_user_full else ""

    s["hostname"] = FAKE_HOST
    s["username"] = f"{FAKE_HOST}\\{FAKE_USER}"
    s["os_caption"] = FAKE_OS
    s["os_build"] = "26100"
    s["ps_version"] = "5.1"
    s["domain"] = {"PartOfDomain": False, "Domain": "WORKGROUP", "UserDnsDomain": None}
    s["gpo_network_present"] = False

    for a in s.get("adapters", []) or []:
        if a.get("MacAddress"):
            a["MacAddress"] = sanitize_mac(a["MacAddress"])
        if a.get("InterfaceGuid"):
            a["InterfaceGuid"] = sanitize_guid(a["InterfaceGuid"])

    for a in s.get("addresses", []) or []:
        if a.get("IPAddress"):
            a["IPAddress"] = sanitize_ip(a["IPAddress"])

    for d in s.get("dns_servers", []) or []:
        addrs = d.get("ServerAddresses") or []
        if isinstance(addrs, str):
            addrs = [addrs]
        d["ServerAddresses"] = [sanitize_ip(x) for x in addrs]

    for r in s.get("routes", []) or []:
        if r.get("DestinationPrefix"):
            r["DestinationPrefix"] = sanitize_prefix(r["DestinationPrefix"])
        if r.get("NextHop"):
            r["NextHop"] = sanitize_ip(r["NextHop"])

    for c in s.get("dns_clients", []) or []:
        for k in ("ConnectionSpecificSuffix", "ConnectionSpecificSuffixSearchList"):
            if c.get(k):
                c[k] = sanitize_domain(c[k])
    for g in s.get("dns_global", []) or []:
        if g.get("SuffixSearchList"):
            g["SuffixSearchList"] = sanitize_domain(g["SuffixSearchList"])

    for p in s.get("profiles", []) or []:
        p["Name"] = sanitize_netname(p.get("Name"))

    for t in s.get("tcpip_interfaces", []) or []:
        t["Guid"] = sanitize_guid(t.get("Guid"))
        for k in ("IPAddress", "DhcpIPAddress", "DefaultGateway", "DhcpDefaultGateway",
                  "DhcpServer", "NameServer", "DhcpNameServer"):
            v = t.get(k)
            if isinstance(v, list):
                t[k] = [sanitize_ip(x) if (_is_ipv4(x) or _is_ipv6(x)) else x for x in v]
            elif isinstance(v, str):
                if "," in v and all(_is_ipv4(x.strip()) for x in v.split(",") if x.strip()):
                    t[k] = ",".join(sanitize_ip(x.strip()) for x in v.split(","))
                elif _is_ipv4(v) or _is_ipv6(v):
                    t[k] = sanitize_ip(v)
        for k in ("Domain", "DhcpDomain", "SearchList"):
            if t.get(k):
                t[k] = sanitize_domain(t[k])
        t["Lease"] = None
        t["LeaseObtainedTime"] = None
        t["LeaseTerminatesTime"] = None

    tg = s.get("tcpip_global") or {}
    for k in ("Domain", "SearchList", "DhcpDomain", "NV_Domain"):
        if tg.get(k):
            tg[k] = sanitize_domain(tg[k])
    tg["Hostname"] = FAKE_HOST.lower()
    s["tcpip_global"] = tg

    # VPN 服务器地址
    for v in s.get("vpn_connections", []) or []:
        if v.get("ServerAddress"):
            v["ServerAddress"] = sanitize_domain(v["ServerAddress"])
        if v.get("Name"):
            v["Name"] = "Demo VPN"

    # hosts
    s["hosts"] = sanitize_hosts(s.get("hosts"))

    # 已安装软件列表整体隐去（属于设备使用习惯）
    s["installed_apps"] = []

    # 进程 / 服务：路径脱敏
    for p in s.get("processes", []) or []:
        for k in ("CommandLine", "ExecutablePath"):
            if p.get(k):
                p[k] = sanitize_path(p[k])
    for sv in s.get("services", []) or []:
        if sv.get("PathName"):
            sv["PathName"] = sanitize_path(sv["PathName"])

    # netsh 原始输出：替换 SSID / BSSID / 物理地址
    new_wlan = []
    for line in s.get("wlan_raw", []) or []:
        line = re.sub(r"(SSID\s*[:：]\s*)(.+)", lambda m: m.group(1) + "Office-WiFi", line)
        line = re.sub(r"(BSSID\s*[:：]\s*)([0-9a-fA-F:]{11,})",
                      lambda m: m.group(1) + "0a:00:00:11:22:33", line)
        line = re.sub(r"(物理地址\s*[:：]\s*)([0-9a-fA-F:]{11,})",
                      lambda m: m.group(1) + "0a:00:00:11:22:33", line)
        line = re.sub(r"(配置文件\s*[:：]\s*)(.+)", lambda m: m.group(1) + "Office-WiFi", line)
        new_wlan.append(line)
    s["wlan_raw"] = new_wlan
    s["winhttp_raw"] = ["", "当前的 WinHTTP 代理服务器设置:", "", "    直接访问(没有代理服务器)。"]

    # 最后兜底：把残留的主机名 / 用户名从任意字符串里抹掉
    s = _scrub_strings(s, [x for x in (real_host, real_user) if x and len(x) >= 3])
    return s


def build_mapping(snap: dict) -> dict[str, str]:
    """从原始快照中收集敏感字符串及其替代值。

    用于清理「事件日志消息」这类自由文本 —— 它们不在结构化字段里，
    却可能包含 SSID、IP、用户名等。
    """
    m: dict[str, str] = {}
    host = str(snap.get("hostname") or "")
    if host:
        m[host] = FAKE_HOST
    user = str(snap.get("username") or "")
    if user:
        m[user] = f"{FAKE_HOST}\\{FAKE_USER}"
        short = user.split("\\")[-1]
        if short:
            m[short] = FAKE_USER

    for p in snap.get("profiles", []) or []:
        n = str(p.get("Name") or "")
        if n:
            m[n] = sanitize_netname(n)

    # 直接从 netsh 原始输出提取 SSID / BSSID / 物理地址（事件日志消息里也会出现）
    for line in snap.get("wlan_raw", []) or []:
        line = str(line)
        for pat, repl in (
            (r"^\s*SSID\s*[:：]\s*(.+)$", "Office-WiFi"),
            (r"^\s*(?:AP\s*)?BSSID\s*[:：]\s*([0-9a-fA-F:]{11,})\s*$", "0a:00:00:11:22:33"),
            (r"^\s*(?:物理地址|Physical address)\s*[:：]\s*([0-9a-fA-F:\-]{11,})\s*$",
             "0a-00-00-11-22-33"),
            (r"^\s*配置文件\s*[:：]\s*(.+)$", "Office-WiFi"),
        ):
            mm = re.match(pat, line)
            if mm:
                m[mm.group(1).strip()] = repl

    for a in snap.get("adapters", []) or []:
        mac = str(a.get("MacAddress") or "")
        if mac:
            m[mac] = sanitize_mac(mac)
            m[mac.replace("-", ":")] = sanitize_mac(mac).replace("-", ":")

    for a in snap.get("addresses", []) or []:
        ip = str(a.get("IPAddress") or "")
        if ip and not ip.startswith(("127.", "::1", "0.0.0.0", "fe80")):
            m[ip] = sanitize_ip(ip)

    for d in snap.get("dns_servers", []) or []:
        for x in (d.get("ServerAddresses") or []):
            x = str(x)
            if x:
                m[x] = sanitize_ip(x)

    for r in snap.get("routes", []) or []:
        nh = str(r.get("NextHop") or "")
        if nh and nh not in ("0.0.0.0", "::"):
            m[nh] = sanitize_ip(nh)

    for t in snap.get("tcpip_interfaces", []) or []:
        for k in ("Domain", "DhcpDomain"):
            v = t.get(k)
            if v:
                m[str(v)] = sanitize_domain(str(v))

    for line in (snap.get("hosts") or {}).get("Lines") or []:
        parts = str(line).split()
        if len(parts) >= 2:
            host_part = parts[1]
            if host_part and "." in host_part:
                m[host_part] = f"local{_h(host_part) % 90 + 1}.example.com"

    # 过滤过短或纯数字的键，避免误伤
    return {k: v for k, v in m.items()
            if len(k) >= 5 and not k.isdigit() and k not in ("0.0.0.0", "255.255.255.255")}


def apply_mapping(obj: Any, mapping: dict[str, str]) -> Any:
    """递归做字符串替换，长键优先，避免子串误替换。"""
    if not mapping:
        return obj
    ordered = sorted(mapping.items(), key=lambda kv: -len(kv[0]))
    pat = re.compile("|".join(re.escape(k) for k, _ in ordered), re.I)
    table = {k.lower(): v for k, v in ordered}

    def _sub(s: str) -> str:
        return pat.sub(lambda m: table.get(m.group(0).lower(), m.group(0)), s)

    def _walk(o):
        if isinstance(o, str):
            return _sub(o)
        if isinstance(o, list):
            return [_walk(x) for x in o]
        if isinstance(o, dict):
            return {k: _walk(v) for k, v in o.items()}
        return o

    return _walk(obj)


def _scrub_strings(obj: Any, needles: list[str]) -> Any:
    if not needles:
        return obj
    if isinstance(obj, str):
        out = obj
        for n in needles:
            out = re.sub(re.escape(n), FAKE_USER if n != needles[0] else FAKE_HOST,
                         out, flags=re.I)
        return out
    if isinstance(obj, list):
        return [_scrub_strings(x, needles) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub_strings(v, needles) for k, v in obj.items()}
    return obj


def sanitize_incident(inc: dict) -> dict:
    """事件里可能携带主机名/用户名与原始证据文本。"""
    out = copy.deepcopy(inc)
    out["host"] = FAKE_HOST
    out["user"] = f"{FAKE_HOST}\\{FAKE_USER}"
    at = out.get("attribution") or {}
    for f in at.get("findings") or []:
        f["evidence"] = [_scrub_strings(e, []) for e in (f.get("evidence") or [])]
    out["clues"] = []
    out["audit_hits"] = []
    return out
