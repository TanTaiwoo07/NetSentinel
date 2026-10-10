"""
快照对比层：把两次采集结果归一化为「实体字典」，逐字段比对产出变更列表。
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .collect import parse_wlan, parse_winhttp

# 严重级别
CRITICAL = "critical"
WARNING = "warning"
NOTICE = "notice"
INFO = "info"

SEVERITY_ORDER = {CRITICAL: 0, WARNING: 1, NOTICE: 2, INFO: 3}


def _s(v: Any) -> str:
    """把任意值转成可比较的稳定字符串。"""
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ",".join(_s(x) for x in v)
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return f"{v:g}"
    return str(v).strip()


def _join(*parts: Any) -> str:
    return "|".join(_s(p) for p in parts)


def _dns_key(row: dict) -> str:
    alias = _s(row.get("InterfaceAlias")) or f"if{row.get('ifIndex')}"
    fam = _s(row.get("AddressFamily")) or "IPv4"
    return f"{alias}::{fam}"


def index_snapshot(snap: dict) -> dict[str, dict[str, dict[str, str]]]:
    """把快照展开为 {category: {entity_key: {field: value}}}。"""
    idx: dict[str, dict[str, dict[str, str]]] = {}

    def put(cat: str, key: str, fields: dict[str, Any]) -> None:
        idx.setdefault(cat, {})[key] = {k: _s(v) for k, v in fields.items()}

    # --- 网卡 ---
    for a in snap.get("adapters", []):
        name = _s(a.get("Name")) or _s(a.get("ifAlias")) or f"if{a.get('ifIndex')}"
        put("adapter", name, {
            "描述": a.get("InterfaceDescription"),
            "状态": a.get("Status"),
            "MAC": a.get("MacAddress"),
            "MTU": a.get("MtuSize"),
            "速率": a.get("LinkSpeed"),
            "介质": a.get("MediaType"),
            "管理状态": a.get("AdminStatus"),
            "驱动版本": a.get("DriverVersion"),
            "GUID": a.get("InterfaceGuid"),
        })

    # --- IP 接口 ---
    for i in snap.get("ip_interfaces", []):
        alias = _s(i.get("InterfaceAlias")) or f"if{i.get('ifIndex')}"
        fam = _s(i.get("AddressFamily")) or "IPv4"
        put("ip_interface", f"{alias}::{fam}", {
            "DHCP": i.get("Dhcp"),
            "Metric": i.get("InterfaceMetric") if i.get("InterfaceMetric") is not None else i.get("Metric"),
            "连接状态": i.get("ConnectionState"),
            "转发": i.get("Forwarding"),
            "MTU": i.get("NlMtu"),
            "自动Metric": i.get("AutomaticMetric"),
        })

    # --- IP 地址 ---
    for a in snap.get("addresses", []):
        alias = _s(a.get("InterfaceAlias")) or f"if{a.get('ifIndex')}"
        fam = _s(a.get("AddressFamily")) or "IPv4"
        ip = _s(a.get("IPAddress"))
        if not ip:
            continue
        put("address", f"{alias}::{fam}::{ip}", {
            "前缀长度": a.get("PrefixLength"),
            "类型": a.get("Type"),
            "前缀来源": a.get("PrefixOrigin"),
            "后缀来源": a.get("SuffixOrigin"),
            "跳过源": a.get("SkipAsSource"),
        })

    # --- DNS 服务器 ---
    for d in snap.get("dns_servers", []):
        servers = d.get("ServerAddresses") or []
        if isinstance(servers, str):
            servers = [servers]
        put("dns", _dns_key(d), {"服务器": sorted(_s(x) for x in servers)})

    # --- DNS 客户端（后缀 / 搜索列表）---
    for c in snap.get("dns_clients", []):
        alias = _s(c.get("InterfaceAlias")) or f"if{c.get('ifIndex')}"
        put("dns_client", alias, {
            "连接专用后缀": c.get("ConnectionSpecificSuffix"),
            "后缀搜索列表": c.get("ConnectionSpecificSuffixSearchList"),
            "注册此连接地址": c.get("RegisterThisConnectionsAddress"),
        })

    for g in snap.get("dns_global", []):
        put("dns_global", "global", {
            "全局搜索列表": g.get("SuffixSearchList"),
            "注册时使用后缀": g.get("UseSuffixWhenRegistering"),
        })

    # --- 路由 ---
    for r in snap.get("routes", []):
        prefix = _s(r.get("DestinationPrefix"))
        nh = _s(r.get("NextHop")) or "0.0.0.0"
        alias = _s(r.get("InterfaceAlias")) or f"if{r.get('ifIndex')}"
        put("route", _join(prefix, nh, alias), {
            "前缀": prefix,
            "下一跳": nh,
            "接口": alias,
            "Metric": r.get("RouteMetric"),
            "协议": r.get("Protocol"),
            "状态": r.get("State"),
            "发布": r.get("Publish"),
        })

    # --- 网络连接配置文件（公用/专用/域）---
    for p in snap.get("profiles", []):
        alias = _s(p.get("InterfaceAlias")) or f"if{p.get('InterfaceIndex')}"
        put("network_profile", alias, {
            "网络名": p.get("Name"),
            "类别": p.get("NetworkCategory"),
            "IPv4连通性": p.get("IPv4Connectivity"),
            "IPv6连通性": p.get("IPv6Connectivity"),
            "域认证": p.get("DomainAuthenticationKind"),
        })

    # --- 代理 ---
    pu = snap.get("proxy_user") or {}
    put("proxy", "当前用户(IE/系统)", {
        "启用": pu.get("ProxyEnable"),
        "服务器": pu.get("ProxyServer"),
        "绕过列表": pu.get("ProxyOverride"),
        "自动配置脚本": pu.get("AutoConfigURL"),
        "自动检测": pu.get("AutoDetect"),
    })
    pm = snap.get("proxy_machine") or {}
    put("proxy", "计算机级(IE/系统)", {
        "启用": pm.get("ProxyEnable"),
        "服务器": pm.get("ProxyServer"),
        "绕过列表": pm.get("ProxyOverride"),
        "自动配置脚本": pm.get("AutoConfigURL"),
    })
    wh = parse_winhttp(snap.get("winhttp_raw", []))
    put("proxy", "WinHTTP(系统服务)", {
        "服务器": wh["server"] or "",
        "绕过列表": wh["bypass"] or "",
    })

    # --- 注册表 Tcpip 接口 ---
    for t in snap.get("tcpip_interfaces", []):
        guid = _s(t.get("Guid"))
        put("tcpip_interface", guid, {
            "NameServer": t.get("NameServer"),
            "DhcpNameServer": t.get("DhcpNameServer"),
            "IPAddress": t.get("IPAddress"),
            "DhcpIPAddress": t.get("DhcpIPAddress"),
            "SubnetMask": t.get("SubnetMask"),
            "DefaultGateway": t.get("DefaultGateway"),
            "DhcpDefaultGateway": t.get("DhcpDefaultGateway"),
            "DhcpServer": t.get("DhcpServer"),
            "Domain": t.get("Domain"),
            "DhcpDomain": t.get("DhcpDomain"),
            "SearchList": t.get("SearchList"),
            "EnableDHCP": t.get("EnableDHCP"),
            "租约到期": t.get("LeaseTerminatesTime"),
        })

    tg = snap.get("tcpip_global") or {}
    put("tcpip_global", "global", {
        "Domain": tg.get("Domain"),
        "SearchList": tg.get("SearchList"),
        "DhcpDomain": tg.get("DhcpDomain"),
        "NV_Domain": tg.get("NV_Domain"),
        "Hostname": tg.get("Hostname"),
    })

    iv = snap.get("ipv6_global") or {}
    put("ipv6_global", "global", {"DisabledComponents": iv.get("DisabledComponents")})

    # --- hosts ---
    h = snap.get("hosts") or {}
    put("hosts_file", "hosts", {
        "SHA256": h.get("Sha256"),
        "修改时间": h.get("MTime"),
        "大小": h.get("Size"),
        "有效行数": len(h.get("Lines") or []),
    })
    for line in h.get("Lines") or []:
        put("hosts_entry", _s(line), {"存在": "true"})

    # --- WiFi ---
    wl = parse_wlan(snap.get("wlan_raw", []))
    put("wlan", "无线", {
        "SSID": wl.get("ssid") or "",
        "已连接": "true" if wl.get("connected") else "false",
        "信号": wl.get("signal") or "",
        "信道": wl.get("channel") or "",
        "BSSID": wl.get("bssid") or "",
    })

    # --- VPN 连接 ---
    for v in snap.get("vpn_connections", []):
        put("vpn", _s(v.get("Name")), {
            "服务器": v.get("ServerAddress"),
            "隧道类型": v.get("TunnelType"),
            "认证方式": v.get("AuthenticationMethod"),
            "分流": v.get("SplitTunneling"),
            "状态": v.get("ConnectionStatus"),
        })

    # --- 防火墙 ---
    for f in snap.get("firewall", []):
        put("firewall", _s(f.get("Name")), {
            "启用": f.get("Enabled"),
            "入站默认": f.get("DefaultInboundAction"),
            "出站默认": f.get("DefaultOutboundAction"),
        })

    # --- 网络相关服务 ---
    for sv in snap.get("services", []):
        put("service", _s(sv.get("Name")), {
            "显示名": sv.get("DisplayName"),
            "状态": sv.get("State"),
            "启动类型": sv.get("StartMode"),
            "路径": sv.get("PathName"),
            "PID": sv.get("ProcessId"),
        })

    return idx


CATEGORY_LABEL = {
    "adapter": "网卡适配器",
    "ip_interface": "IP 接口",
    "address": "IP 地址",
    "dns": "DNS 服务器",
    "dns_client": "DNS 客户端后缀",
    "dns_global": "DNS 全局设置",
    "route": "路由表",
    "network_profile": "网络位置配置",
    "proxy": "代理设置",
    "tcpip_interface": "Tcpip 接口(注册表)",
    "tcpip_global": "Tcpip 全局(注册表)",
    "ipv6_global": "IPv6 全局",
    "hosts_file": "hosts 文件",
    "hosts_entry": "hosts 条目",
    "wlan": "无线连接",
    "vpn": "VPN 连接",
    "firewall": "防火墙配置",
    "service": "网络相关服务",
}

# 忽略项：噪声大且无归因价值
IGNORE_CATEGORIES = set()

# 高频抖动字段：每时每刻都在变，记录它们只会淹没真正的配置变更
IGNORE_FIELDS = {
    ("wlan", "信号"),              # 无线信号强度随环境实时波动
    ("adapter", "速率"),           # 无线协商速率随信号变化
    ("tcpip_interface", "租约到期"),  # DHCP 租约到期时间戳随续约刷新
}


def _severity(cat: str, subject: str, field: str | None, kind: str) -> str:
    """为变更定级。"""
    if cat == "firewall" and field == "启用":
        return CRITICAL if kind != "added" else NOTICE
    if cat == "route" and ("0.0.0.0/0" in subject or "::/0" in subject):
        return WARNING
    if cat in ("dns", "proxy", "hosts_file", "hosts_entry"):
        return WARNING
    if cat == "adapter" and field == "状态":
        return NOTICE
    if cat == "network_profile" and field == "类别":
        return WARNING
    if cat == "ipv6_global":
        return WARNING
    if cat == "service":
        return NOTICE
    if cat == "address" or cat == "adapter" or cat == "wlan" or cat == "vpn":
        return NOTICE
    return INFO


def diff_snapshots(old: dict, new: dict) -> list[dict]:
    """对比两次快照，返回变更列表。"""
    a = index_snapshot(old)
    b = index_snapshot(new)
    changes: list[dict] = []

    for cat in sorted(set(a) | set(b)):
        if cat in IGNORE_CATEGORIES:
            continue
        oa, ob = a.get(cat, {}), b.get(cat, {})
        for key in sorted(set(oa) | set(ob)):
            fo, fn = oa.get(key), ob.get(key)
            if fo is None and fn is not None:
                changes.append(_mk(cat, key, "added", None, "", _fmt_fields(fn)))
                continue
            if fo is not None and fn is None:
                changes.append(_mk(cat, key, "removed", None, _fmt_fields(fo), ""))
                continue
            if fo == fn:
                continue
            for field in sorted(set(fo) | set(fn)):
                if (cat, field) in IGNORE_FIELDS:
                    continue
                vo, vn = fo.get(field, ""), fn.get(field, "")
                if vo == vn:
                    continue
                changes.append(_mk(cat, key, "changed", field, vo, vn))
    changes.sort(key=lambda c: (SEVERITY_ORDER.get(c["severity"], 9), c["category"], c["subject"]))
    return changes


def _mk(cat: str, subject: str, kind: str, field: str | None, old: str, new: str) -> dict:
    label = CATEGORY_LABEL.get(cat, cat)
    if kind == "added":
        summary = f"新增{label}：{subject}"
        if new:
            summary += f"  {new}"
    elif kind == "removed":
        summary = f"移除{label}：{subject}"
        if old:
            summary += f"  （原有：{old}）"
    else:
        summary = f"{label}「{subject}」的 {field}：{_show(old)} → {_show(new)}"
    return {
        "category": cat,
        "category_label": label,
        "subject": subject,
        "kind": kind,
        "field": field,
        "old": old,
        "new": new,
        "severity": _severity(cat, subject, field, kind),
        "summary": summary,
    }


def _fmt_fields(fields: dict[str, str]) -> str:
    parts = [f"{k}={_show(v)}" for k, v in fields.items() if v not in ("", "false")]
    return "  ".join(parts[:6])


def _show(v: Any) -> str:
    v = _s(v)
    if v == "":
        return "（空）"
    return v if len(v) <= 80 else v[:77] + "..."
