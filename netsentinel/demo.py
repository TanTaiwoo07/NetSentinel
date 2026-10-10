"""
演示 / 自检模式。

以本机真实快照为基线，叠加若干典型「网络被改动」场景，跑完整的
差异检测 + 归因链路，生成可视化报告。用于验证规则库是否正确，
也便于在不改动真实系统的前提下了解工具能力。

注意：本模式不会修改任何真实系统配置，也不会写入 events.jsonl。
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import attribute as AT
from . import collect as CO
from . import store as ST
from .diffing import diff_snapshots
from .evidence import interpret_events
from .report import build_report

from .collect import normalize  # noqa: F401


def _set_dns(snap: dict, alias: str, servers: list[str]) -> None:
    for d in snap.get("dns_servers", []):
        if d.get("InterfaceAlias") == alias and d.get("AddressFamily") == "IPv4":
            d["ServerAddresses"] = list(servers)


def _route(snap, prefix, nexthop, alias, metric=0, proto="NetMgmt(管理配置)"):
    snap.setdefault("routes", []).append({
        "ifIndex": 99, "InterfaceAlias": alias, "DestinationPrefix": prefix,
        "NextHop": nexthop, "RouteMetric": metric, "Protocol": proto,
        "State": "Alive", "AddressFamily": "IPv4", "Publish": "否",
    })


def _primary_iface(snap: dict) -> str:
    """挑一个当前有 IPv4 地址的「上网」接口。"""
    best = None
    for a in snap.get("addresses", []):
        ip = a.get("IPAddress") or ""
        if a.get("AddressFamily") != "IPv4":
            continue
        if ip.startswith(("169.254.", "127.")):
            continue
        best = a.get("InterfaceAlias")
        if ip.startswith(("192.168.", "172.", "10.")):
            return best
    return best or "以太网"


SCENARIOS = ["代理软件启动", "VPN 接入", "hosts 被篡改", "DHCP 获取失败", "防火墙被关闭"]


def _scenario_proxy(base: dict) -> dict:
    s = copy.deepcopy(base)
    iface = _primary_iface(s)
    s["proxy_user"] = dict(s.get("proxy_user") or {})
    s["proxy_user"]["ProxyEnable"] = "启用"
    s["proxy_user"]["ProxyServer"] = "127.0.0.1:7897"
    s["proxy_user"]["ProxyOverride"] = "localhost;127.*"
    _set_dns(s, iface, ["127.0.0.1"])
    _route(s, "0.0.0.0/1", "198.18.0.1", iface)
    _route(s, "128.0.0.0/1", "198.18.0.1", iface)
    return s


def _scenario_vpn(base: dict) -> dict:
    s = copy.deepcopy(base)
    iface = _primary_iface(s)
    s.setdefault("adapters", []).append({
        "Name": "WireGuard Tunnel", "InterfaceDescription": "WireGuard Tunnel",
        "ifIndex": 98, "ifAlias": "WireGuard Tunnel", "Status": "Up",
        "MacAddress": "", "LinkSpeed": "100 Gbps", "MediaType": "802.3",
        "MtuSize": 1420, "AdminStatus": "已启用", "MediaConnectionState": "已连接",
        "InterfaceGuid": "{deadbeef-0000-0000-0000-000000000000}",
        "DriverVersion": "1.0.0.0", "DriverDate": "",
    })
    s["ipv6_global"] = {"DisabledComponents": 255}
    for r in s.get("routes", []):
        if r.get("DestinationPrefix") == "0.0.0.0/0" and r.get("InterfaceAlias") == iface:
            r["NextHop"] = "10.8.0.1"
            r["Protocol"] = "Ras(拨号/VPN)"
    _set_dns(s, iface, ["10.8.0.1"])
    return s


def _scenario_hosts(base: dict) -> dict:
    s = copy.deepcopy(base)
    h = dict(s.get("hosts") or {})
    lines = list(h.get("Lines") or [])
    lines += ["0.0.0.0 tracking.example.com", "0.0.0.0 ads.example.net",
              "127.0.0.1 activate.example-soft.com"]
    h["Lines"] = lines
    h["Sha256"] = "demo" + (h.get("Sha256") or "")[4:]
    h["MTime"] = datetime.now(timezone.utc).isoformat()
    s["hosts"] = h
    return s


def _scenario_dhcp(base: dict) -> dict:
    s = copy.deepcopy(base)
    iface = _primary_iface(s)
    for a in s.get("addresses", []):
        if a.get("InterfaceAlias") == iface and a.get("AddressFamily") == "IPv4" \
                and not (a.get("IPAddress") or "").startswith(("169.254.", "127.")):
            a["IPAddress"] = "169.254.31.187"
            a["PrefixLength"] = 16
            a["PrefixOrigin"] = "系统(WellKnown)"
            a["SuffixOrigin"] = "系统(WellKnown)"
    _set_dns(s, iface, [])
    for p in s.get("profiles", []):
        if p.get("InterfaceAlias") == iface:
            p["IPv4Connectivity"] = "仅子网"
    return s


def _scenario_firewall(base: dict) -> dict:
    s = copy.deepcopy(base)
    for f in s.get("firewall", []):
        if f.get("Name") == "Public":
            f["Enabled"] = "关闭"
    return s


def _synth_events(scenario: str, when: datetime) -> list[dict]:
    """脱敏模式下的合成事件。

    真实事件日志是自由文本，可能夹带历史连接过的 SSID、网关等无法穷举脱敏的信息，
    因此生成可分享的示例报告时改用合成数据 —— 既能展示「事件日志证据」这一层，
    又完全不含本机真实信息。
    """
    iso = when.isoformat()

    def ev(log, provider, eid, level, msg):
        return {"Time": iso, "Log": log, "Provider": provider, "Id": eid,
                "Level": level, "Task": "", "Message": msg}

    table = {
        "VPN 接入": [
            ev("Microsoft-Windows-RasClient/Operational", "Microsoft-Windows-RasClient",
               20201, "信息", "VPN 连接已建立。隧道类型：WireGuard。"),
            ev("Microsoft-Windows-NetworkProfile/Operational",
               "Microsoft-Windows-NetworkProfile", 4004, "信息",
               "网络位置感知已识别新网络并写入连接配置文件。"),
        ],
        "DHCP 获取失败": [
            ev("Microsoft-Windows-Dhcp-Client/Admin", "Microsoft-Windows-Dhcp-Client",
               1001, "警告", "计算机在网络卡上丢失了对 IP 地址的租约，DHCP 服务器未响应。"),
            ev("Microsoft-Windows-NCSI/Operational", "Microsoft-Windows-NCSI",
               4002, "警告", "NCSI 判定：当前无 Internet 连接。"),
        ],
        "hosts 被篡改": [
            ev("Security", "Microsoft-Windows-Security-Auditing", 4663, "信息",
               "已尝试访问对象。\n\n对象:\n\t对象服务器:\tSecurity\n\t对象类型:\tFile\n"
               "\t对象名:\t\\Device\\HarddiskVolume2\\Windows\\System32\\drivers\\etc\\hosts\n\n"
               "进程信息:\n\t进程 ID:\t0x1a2b\n"
               "\t进程名:\tC:\\Program Files\\DemoEditor\\editor.exe\n\n"
               "访问请求信息:\n\t访问:\t\tWriteData"),
        ],
        "防火墙被关闭": [
            ev("Microsoft-Windows-GroupPolicy/Operational", "Microsoft-Windows-GroupPolicy",
               8001, "信息", "已完成组策略处理，其中包含防火墙策略。"),
        ],
        "代理软件启动": [],
    }
    return table.get(scenario, [])


BUILDERS = {
    "代理软件启动": _scenario_proxy,
    "VPN 接入": _scenario_vpn,
    "hosts 被篡改": _scenario_hosts,
    "DHCP 获取失败": _scenario_dhcp,
    "防火墙被关闭": _scenario_firewall,
}


def run_demo(sanitize: bool = True, out: Path | None = None) -> Path:
    print("采集本机真实基线快照…")
    raw = CO.collect_snapshot()
    mapping: dict = {}
    if sanitize:
        from .sanitize import (apply_mapping, build_mapping, sanitize_incident,
                               sanitize_snapshot)
        mapping = build_mapping(raw)
        base = sanitize_snapshot(raw)
        print(f"  已启用隐私脱敏（{len(mapping)} 项敏感串：主机名/用户名/MAC/IP/SSID/hosts/软件列表）")
    else:
        base = raw
    now = datetime.now(timezone.utc)
    real_events: list[dict] = []
    if not sanitize:
        print("拉取近期 Windows 事件日志作为证据…")
        real_events = CO.collect_events(now - timedelta(hours=3), now)
        print(f"  获得 {len(real_events)} 条原始事件")

    incidents = []
    for i, name in enumerate(SCENARIOS, 1):
        cur = BUILDERS[name](base)
        changes = diff_snapshots(base, cur)
        if not changes:
            print(f"  · 场景「{name}」未产生差异，跳过")
            continue
        ts = (now - timedelta(minutes=(len(SCENARIOS) - i) * 37)).isoformat()
        evts = _synth_events(name, now - timedelta(minutes=(len(SCENARIOS) - i) * 37)) \
            if sanitize else real_events
        res = AT.attribute(changes, base, cur, evts)
        inc = {
            "id": f"INC-{i:04d}",
            "detected_at": ts,
            "window": [ts, ts],
            "changes": changes,
            "attribution": res,
            "clues": res.get("clues") or [],
            "audit_hits": res.get("audit_hits") or [],
            "host": cur.get("hostname"),
            "user": cur.get("username"),
            "scenario": name,
        }
        if sanitize:
            inc = sanitize_incident(inc)
        incidents.append(inc)
        s = res["summary"]
        print(f"  · {name}：{len(changes)} 项变化 → 置信度 {s['confidence']:.0%}　{s['primary_source']}")

    if sanitize:
        # 事件日志消息等自由文本里仍可能夹带真实 SSID / IP / 用户名
        incidents = apply_mapping(incidents, mapping)

    target = Path(out) if out else ST.DATA_DIR / "report_demo.html"
    note = ("示例报告 · 已脱敏（基于真实结构模拟，未改动任何系统配置）" if sanitize
            else "示例报告 · 含本机真实数据，请勿外传")
    p = build_report(incidents, base, out=target, note=note)
    print(f"\n✓ 示例报告已生成：{p}")
    return p
