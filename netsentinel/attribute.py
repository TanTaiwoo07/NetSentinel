"""
归因引擎：把「变更列表 + 证据线索」翻译成「原因 + 源头 + 置信度 + 建议」。
"""

from __future__ import annotations

import re
from typing import Any

from . import evidence as EV
from .diffing import CRITICAL, INFO, NOTICE, WARNING
from .evidence import interpret_events

# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

LOCALHOST = {"127.0.0.1", "::1", "localhost", "[::1]", "0:0:0:0:0:0:0:1"}


def sel(changes: list[dict], category: str | None = None, kind: str | None = None,
        field: str | None = None) -> list[dict]:
    out = changes
    if category:
        out = [c for c in out if c["category"] == category]
    if kind:
        out = [c for c in out if c["kind"] == kind]
    if field:
        out = [c for c in out if c["field"] == field]
    return out


def _split(v: str) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip() and x.strip() != "（空）"]


def _finding(rule, title, cause, source, confidence, evidence=None, advice="", severity=INFO):
    return {
        "rule": rule, "title": title, "cause": cause, "source": source,
        "confidence": round(max(0.0, min(0.98, confidence)), 2),
        "evidence": list(evidence or []), "advice": advice, "severity": severity,
    }


def _proc_hits(snap: dict) -> list[dict]:
    hits = []
    for p in snap.get("processes", []):
        r = EV.hint_for_process(p)
        if r:
            hits.append({
                "pid": p.get("ProcessId"), "name": p.get("Name"),
                "exe": p.get("ExecutablePath"),
                "cmd": (p.get("CommandLine") or "")[:220],
                "owner": r[0], "weight": r[1],
            })
    hits.sort(key=lambda x: -x["weight"])
    return hits


def _svc_hits(snap: dict) -> list[dict]:
    hits = []
    for s in snap.get("services", []):
        blob = " ".join(str(s.get(k) or "") for k in ("Name", "DisplayName", "PathName"))
        r = EV.hint_from_text(blob, EV.SVC_HINTS)
        if r:
            hits.append({
                "name": s.get("Name"), "display": s.get("DisplayName"),
                "state": s.get("State"), "path": s.get("PathName"),
                "owner": r[0], "weight": r[1],
            })
    hits.sort(key=lambda x: -x["weight"])
    return hits


# ---------------------------------------------------------------------------
# 规则集：每个函数返回 Finding 列表
# ---------------------------------------------------------------------------

def rule_dns(changes, ctx):
    out = []
    for c in sel(changes, "dns"):
        subject = c["subject"]
        new_list = _split(c["new"]) if c["kind"] != "removed" else []
        old_list = _split(c["old"]) if c["kind"] != "added" else []
        if not new_list and not old_list:
            continue

        if any(x in LOCALHOST for x in new_list):
            owner_guess = "本机运行的 DNS 代理/过滤软件"
            for h in ctx["proc_hits"]:
                if re.search(r"clash|adguard|acrylic|dnsmasq|v2ray|xray|sing|trojan|surge|surge", h["name"] or "", re.I):
                    owner_guess = h["owner"]
                    if h.get("exe"):
                        owner_guess += f"（进程 {h['name']}，路径 {h['exe']}）"
                    break
            out.append(_finding(
                "R-DNS-LOCAL", f"DNS 被改为本机回环地址（{subject}）",
                "DNS 服务器被指向 127.0.0.1 / ::1，即由本机运行的 DNS 代理或过滤程序接管解析。"
                "这是代理软件做域名分流（fake-ip / 规则匹配）或广告过滤软件做拦截的典型做法。",
                f"源头：{owner_guess}", 0.88,
                [c["summary"]],
                "如果这是你自己装的代理/过滤软件，属预期行为；若不是，检查该程序是否未经许可常驻，"
                "并在「设置 → 网络和 Internet」中把 DNS 改回自动(DHCP)。",
                WARNING))

        elif not new_list and old_list:
            out.append(_finding(
                "R-DNS-EMPTY", f"DNS 服务器列表被清空（{subject}）",
                "该接口的 DNS 服务器变为空：常见原因有接口断开、DHCP 未下发 DNS、"
                "VPN/隧道断开后未恢复、或有人把 DNS 设置清空。",
                "源头：网络断开 / DHCP 未分配 / 代理或 VPN 软件退出时未还原配置", 0.65,
                [c["summary"]],
                "先确认网络是否连通；若长期无 DNS，手动指定公共 DNS（如 223.5.5.5）或检查路由器 DHCP 配置。",
                WARNING))

        else:
            owners = []
            for ip in new_list:
                o = EV.dns_owner(ip)
                if o:
                    owners.append(f"{ip}（{o}）")
                elif re.match(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)", ip):
                    owners.append(f"{ip}（局域网地址，通常为路由器/光猫自身）")
                elif ip.startswith("fe80") or ip.startswith("169.254"):
                    owners.append(f"{ip}（链路本地地址，非正常 DNS）")
                else:
                    owners.append(f"{ip}（未知归属）")
            is_dhcp = any(x in ("DhcpNameServer",) for x in (c.get("field") or ""))
            src = ("源头：路由器/光猫通过 DHCP 下发" if all(
                re.match(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|fe80|2408|2409|240e)", i) for i in new_list
            ) and new_list else
                "源头：手动设置、或软件/脚本写入注册表 Tcpip\\Parameters\\Interfaces\\<GUID>\\NameServer")
            conf = 0.72 if src.startswith("源头：路由器") else 0.62
            out.append(_finding(
                "R-DNS-CHANGE", f"DNS 服务器变更（{subject}）",
                "DNS 解析服务器由 " + (",".join(old_list) or "（空）") + " 变更为 " + ",".join(new_list) + "。"
                "归属判定：" + "、".join(owners),
                src, conf, [c["summary"]],
                "公共 DNS 通常可提升解析速度与稳定性；若被改为陌生地址，需警惕 DNS 劫持。",
                WARNING))

    # 注册表层的 DNS
    for c in sel(changes, "tcpip_interface"):
        if c["field"] in ("NameServer", "DhcpNameServer"):
            out.append(_finding(
                "R-DNS-REG", f"注册表 DNS 配置变更（接口 {c['subject'][:12]}…）",
                f"注册表 HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{c['subject']} "
                f"的 {c['field']} 被改写。手动配置改的是 NameServer，DHCP 下发改的是 DhcpNameServer。",
                "源头："
                + ("DHCP 服务器（路由器）下发" if c["field"] == "DhcpNameServer"
                   else "手动设置 / 脚本 / 第三方软件写入（非 DHCP）"),
                0.7, [c["summary"]],
                "若你没有手动改过 DNS，重点排查常驻的代理、安全、校园网认证类软件。",
                WARNING))
    return out


def rule_proxy(changes, ctx):
    out = []
    for c in sel(changes, "proxy"):
        scope = c["subject"]
        if c["field"] == "服务器":
            new = c["new"]
            r = EV.proxy_port_owner(new)
            if r:
                owner, basis = r
                out.append(_finding(
                    "R-PROXY-LOCAL", f"系统代理变更（{scope}）",
                    f"系统代理被设置为 {new}。{basis}，说明本机有程序在接管 HTTP/HTTPS 流量。",
                    f"源头：{owner}", 0.9, [c["summary"]],
                    "确认该代理软件是否为你主动安装运行。关闭代理软件后若仍残留，"
                    "需到「设置 → 网络和 Internet → 代理」中手动关闭。",
                    WARNING))
            elif new.strip() and new.strip() != "（空）":
                out.append(_finding(
                    "R-PROXY-REMOTE", f"系统代理变更（{scope}）",
                    f"系统代理被设置为 {new}，指向一台远程/局域网代理服务器。",
                    "源头：公司/校园网策略下发、路由器上的代理服务、或手动填写的代理地址", 0.7,
                    [c["summary"]],
                    "确认该代理服务器是否可信；企业/校园环境下通常为合规配置。",
                    WARNING))
            else:
                out.append(_finding(
                    "R-PROXY-CLEAR", f"系统代理被清空（{scope}）",
                    "系统代理服务器地址被清空（未关闭代理开关则会导致无法上网）。",
                    "源头：代理软件退出时清理配置，或用户/脚本手动清除", 0.6,
                    [c["summary"]], "若代理开关仍为开启状态，请一并关闭。", WARNING))
        elif c["field"] == "启用":
            on = str(c["new"]).strip()
            if on in ("1", "true", "True"):
                out.append(_finding(
                    "R-PROXY-ON", f"系统代理被开启（{scope}）",
                    "Internet 选项中的代理开关由关变开。开启后流量会经过指定代理服务器。",
                    "源头：代理/抓包软件启动，或用户/脚本手动开启", 0.75, [c["summary"]],
                    "不需要时及时关闭，否则可能出现部分网站打不开。", WARNING))
            else:
                out.append(_finding(
                    "R-PROXY-OFF", f"系统代理被关闭（{scope}）",
                    "Internet 选项中的代理开关由开变关。",
                    "源头：代理软件正常退出并还原配置，或用户/脚本手动关闭", 0.7,
                    [c["summary"]], "属正常清理行为。", INFO))
        elif c["field"] == "自动配置脚本":
            out.append(_finding(
                "R-PROXY-PAC", f"代理自动配置脚本(PAC)变更（{scope}）",
                f"PAC/自动配置脚本地址变为 {c['new'] or '（空）'}。PAC 会按脚本规则决定哪些流量走代理。",
                "源头：企业/校园网组策略下发、代理软件写入、或手动填写", 0.72,
                [c["summary"]], "检查该 PAC 地址是否可信，脚本内容可能决定全部流量走向。", WARNING))
        elif c["field"] == "自动检测":
            out.append(_finding(
                "R-PROXY-WPAD", f"自动检测设置(WAPD)变更（{scope}）",
                "「自动检测设置」开关变化。开启后系统会通过 WPAD 协议在内网自动寻找代理。",
                "源头：软件安装/网络环境切换，或手动修改。注意 WPAD 存在被内网劫持的风险。",
                0.6, [c["summary"]], "非企业环境建议关闭「自动检测设置」。", WARNING))
        elif c["field"] in ("服务器",) and "WinHTTP" in scope:
            out.append(_finding(
                "R-WINHTTP", "WinHTTP 系统级代理变更",
                "WinHTTP 代理（影响系统服务、Windows 更新、部分 UWP 应用）发生变化，"
                "只能通过 netsh winhttp 命令修改。",
                "源头：执行了 netsh winhttp set proxy 的脚本/软件/管理员，或公司镜像环境配置",
                0.8, [c["summary"]],
                "如需还原：管理员权限执行 netsh winhttp reset proxy。", WARNING))
    return out


def rule_routes(changes, ctx):
    out = []
    added = sel(changes, "route", kind="added")
    removed = sel(changes, "route", kind="removed")
    prefixes = {c["subject"].split("|")[0] for c in added}
    if {"0.0.0.0/1", "128.0.0.0/1"} <= prefixes:
        out.append(_finding(
            "R-VPN-SPLIT", "出现 VPN 全局接管路由（0.0.0.0/1 + 128.0.0.0/1）",
            "新增了两条覆盖整个 IPv4 地址空间的路由（0.0.0.0/1 与 128.0.0.0/1）。"
            "这是绕过默认网关的经典手法：两条更具体的路由优先级高于 0.0.0.0/0，从而让全部流量走隧道。",
            "源头：VPN / 代理客户端开启「全局模式 / TUN 模式」", 0.92,
            [c["summary"] for c in added][:4],
            "若只需部分流量走代理，改用「规则模式 / 分流模式」即可撤销这两条路由。", WARNING))

    removed_prefixes = {c["subject"].split("|")[0] for c in removed}

    for c in added:
        prefix = c["subject"].split("|")[0]
        proto = "NetMgmt" if "NetMgmt" in c["new"] else ("Ras" if "Ras" in c["new"] else "")
        if prefix in ("0.0.0.0/0", "::/0"):
            if prefix in removed_prefixes:
                old_hop = next((r["subject"].split("|")[1] for r in removed
                                if r["subject"].split("|")[0] == prefix), "?")
                out.append(_finding(
                    "R-DEFAULTGW-SWITCH", f"默认网关切换（{prefix}）",
                    f"默认路由的下一跳由 {old_hop} 切换为 {c['subject'].split('|')[1]}，"
                    "即出口设备发生更换。",
                    "源头：" + ("VPN/拨号连接建立，隧道接管出口（协议 Ras）" if proto == "Ras"
                                else "切换网络、路由器变更、DHCP 重新分配或脚本改写了网关"),
                    0.86, [c["summary"]],
                    "网关切换会改变全部外网流量的出口，若非预期需检查是否有程序劫持出口。",
                    WARNING))
                continue
            out.append(_finding(
                "R-DEFAULTGW-ADD", f"新增默认路由 {prefix}",
                "默认网关路由被添加。默认路由决定所有非本地流量的出口。",
                "源头："
                + ("VPN/拨号连接建立（协议 Ras）" if proto == "Ras"
                   else "手工或脚本执行 route add / netsh（协议 NetMgmt）"),
                0.85, [c["summary"]], "确认该网关是否为预期出口。", WARNING))
        elif proto == "NetMgmt":
            out.append(_finding(
                "R-ROUTE-PERSIST", f"新增静态路由 {prefix}",
                "新增了一条协议为 NetMgmt（管理配置，通常是持久路由）的路由。",
                "源头：route add -p 持久路由 / netsh 命令 / VPN 客户端添加的专线路由", 0.8,
                [c["summary"]],
                "若不需要，用 route delete 或 netsh 删除；持久路由重启后仍在。", NOTICE))

    for c in sel(changes, "route", kind="changed"):
        if c["field"] == "下一跳" and c["subject"].startswith(("0.0.0.0/0", "::/0")):
            out.append(_finding(
                "R-DEFAULTGW-CHANGE", "默认网关（下一跳）发生切换",
                f"默认路由的下一跳由 {c['old']} 变为 {c['new']}。出口设备换了。",
                "源头：切换了网络（WiFi/有线）、路由器变更、DHCP 重新分配、或 VPN 接管出口",
                0.78, [c["summary"]],
                "校园网/企业网环境下常因重新拨号或 AP 漫游触发；若频繁发生，检查网关稳定性。",
                WARNING))
        elif c["field"] == "Metric":
            out.append(_finding(
                "R-ROUTE-METRIC", f"路由 Metric 变更（{c['subject'].split('|')[0]}）",
                "路由优先级（Metric）调整。Metric 越小优先级越高，多出口时会切换主用链路。",
                "源头：VPN 客户端调整优先级、多网卡切换、或手动调整", 0.6, [c["summary"]],
                "Metric 变化会直接改变流量走哪块网卡。", NOTICE))

    if removed and not added and not sel(changes, "route", kind="changed"):
        out.append(_finding(
            "R-ROUTE-BATCH", f"路由表批量删除（{len(removed)} 条）",
            "多条路由同时消失，通常意味着某个网络接口整体下线。",
            "源头：网卡断开/禁用、VPN 断开、系统休眠唤醒后的网络重建", 0.7,
            [c["summary"] for c in removed][:3], "结合网卡状态变化一起判断。", NOTICE))
    return out


def rule_adapters(changes, ctx):
    out = []
    for c in sel(changes, "adapter", kind="added"):
        name = c["subject"]
        owner = EV.vnic_owner(name + " " + (c["new"] or ""))
        if owner:
            out.append(_finding(
                "R-VNIC-NEW", f"新增虚拟网卡：{name}",
                "系统中出现了一块新的虚拟网络适配器，通常随虚拟化/VPN/远程控制类软件一起安装。",
                f"源头：{owner}（安装或启动后创建了虚拟网卡）", 0.9, [c["summary"]],
                "若非你主动安装，建议检查该软件是否需要保留；卸载后网卡会自动移除。", NOTICE))
        else:
            out.append(_finding(
                "R-ADAPTER-NEW", f"新增网卡：{name}",
                "系统中出现一块新的网络适配器。",
                "源头：新硬件插入（USB 网卡/手机共享网络）、驱动安装、或软件创建虚拟网卡",
                0.6, [c["summary"]], "确认是否为预期设备。", NOTICE))

    for c in sel(changes, "adapter", kind="removed"):
        out.append(_finding(
            "R-VNIC-REMOVE", f"网卡消失：{c['subject']}",
            "一块网络适配器从系统中移除。",
            "源头：软件卸载 / 网卡被禁用 / 驱动回滚或更新 / 设备拔出", 0.7, [c["summary"]],
            "若是虚拟网卡，说明对应软件已被卸载或禁用。", NOTICE))

    for c in sel(changes, "adapter", kind="changed"):
        if c["field"] == "状态":
            up = ("Up" in c["new"]) or ("已连接" in c["new"])
            out.append(_finding(
                "R-ADAPTER-STATE", f"网卡状态变更：{c['subject']} → {c['new']}",
                f"网卡连接状态由 {c['old']} 变为 {c['new']}。",
                "源头：" + ("网络接入（插网线 / 连上 WiFi / 驱动启用）" if up
                            else "拔线 / WiFi 断开 / 被禁用 / 飞行模式 / 驱动禁用"),
                0.75, [c["summary"]],
                "状态变化会连带触发 IP、DNS、路由的一串变更，属上游原因。", NOTICE))
        elif c["field"] == "MTU":
            out.append(_finding(
                "R-MTU", f"网卡 MTU 变更：{c['subject']} → {c['new']}",
                "MTU（最大传输单元）变化。隧道/PPPoE/VPN 通常会把 MTU 调小以容纳封装头。",
                "源头：VPN 或 PPPoE 拨号、网卡驱动、或手动设置", 0.7, [c["summary"]],
                "MTU 不匹配会导致部分网站打不开或大包丢包。", NOTICE))
        elif c["field"] in ("驱动版本", "描述"):
            out.append(_finding(
                "R-DRIVER", f"网卡驱动变更：{c['subject']}",
                f"网卡的 {c['field']} 发生变化。",
                "源头：Windows 更新推送驱动 / 厂商驱动安装 / 驱动回滚", 0.75, [c["summary"]],
                "驱动更新常带来短暂断网与配置重置。", NOTICE))
    return out


def rule_addresses(changes, ctx):
    out = []
    for c in sel(changes, "address"):
        ip = c["subject"].split("::")[-1]
        if c["kind"] == "added":
            if ip.startswith("169.254."):
                out.append(_finding(
                    "R-IP-APIPA", f"获得 APIPA 地址 {ip}",
                    "拿到 169.254.x.x 说明 DHCP 请求没有收到响应，系统自动分配了链路本地地址（无法正常上网）。",
                    "源头：DHCP 服务器不可达 —— 网线松动、WiFi 未真正连上、"
                    "校园网 802.1X 认证未完成、路由器 DHCP 池耗尽或关闭",
                    0.85, [c["summary"]],
                    "先确认物理连接与认证状态；校园网需先完成认证再获取地址。", WARNING))
            else:
                origin = ""
                m = re.search(r"前缀来源=(\w+)", c["new"])
                if m:
                    origin = m.group(1)
                src = {"Dhcp": "DHCP 服务器（路由器）分配",
                       "Manual": "手动设置的静态 IP",
                       "RouterAdvertisement": "IPv6 路由通告(SLAAC)自动生成",
                       "WellKnown": "系统自动生成（回环/链路本地等已知地址）"}.get(origin, "系统自动配置")
                out.append(_finding(
                    "R-IP-NEW", f"新增 IP 地址 {ip}",
                    f"接口获得新地址 {ip}（来源：{origin or '未知'}）。",
                    f"源头：{src}", 0.8 if origin != "Manual" else 0.72, [c["summary"]],
                    "静态 IP 需确认与所在网段匹配，否则无法上网。", NOTICE))
        elif c["kind"] == "removed":
            out.append(_finding(
                "R-IP-DEL", f"IP 地址被移除 {ip}",
                "接口上的一个 IP 地址失效或被删除。",
                "源头：网络断开 / DHCP 租约到期 / 地址被手动删除 / VPN 断开", 0.7,
                [c["summary"]], "结合网卡状态与事件日志判断。", NOTICE))
    return out


def rule_hosts(changes, ctx):
    out = []
    if sel(changes, "hosts_file"):
        added = sel(changes, "hosts_entry", kind="added")
        removed = sel(changes, "hosts_entry", kind="removed")
        kind_desc, owner = [], "未知来源"
        for a in added:
            line = a["subject"]
            ip = line.split()[0] if line.split() else ""
            if ip in ("0.0.0.0", "127.0.0.1", "::1"):
                kind_desc.append(f"屏蔽型条目（{line}）")
            else:
                kind_desc.append(f"指向型条目（{line}）")
        if added and all(l.split()[0] in ("0.0.0.0", "127.0.0.1", "::1") for l in (a["subject"].split() and a["subject"] for a in added) if l):
            owner = "广告拦截/隐私保护类工具，或软件安装时写入的屏蔽规则"
        elif added:
            owner = "某个安装程序或脚本（含破解工具、开发调试、本地服务配置）"
        if removed and not added:
            owner = "软件卸载后的清理，或手动编辑删除"
            kind_desc.append(f"删除 {len(removed)} 条")
        out.append(_finding(
            "R-HOSTS", "hosts 文件被修改",
            "hosts 文件是本地域名解析的最高优先级来源，修改它会直接改变域名解析结果。变更内容："
            + "；".join(kind_desc[:8]) + ("…" if len(kind_desc) > 8 else ""),
            f"源头：{owner}", 0.68,
            [c["summary"] for c in sel(changes, "hosts_file")] + [a["subject"] for a in added[:8]],
            "检查新增条目是否必要；hosts 被篡改为指向陌生 IP 是典型的钓鱼/劫持手法，"
            "建议核对文件 C:\\Windows\\System32\\drivers\\etc\\hosts。",
            WARNING))
    return out


def rule_profile(changes, ctx):
    out = []
    for c in sel(changes, "network_profile"):
        if c["field"] == "类别":
            out.append(_finding(
                "R-PROFILE-CAT", f"网络位置类别变更：{c['subject']} → {c['new']}",
                f"网络类别由 {c['old']} 变为 {c['new']}（公用/专用/域）。"
                "类别决定防火墙规则集与网络发现行为。",
                "源头：网络位置感知(NLA)重新识别网络、切换了不同网络、域加入/退出、或手动修改",
                0.8, [c["summary"]],
                "设为「公用」会收紧防火墙，可能导致局域网共享/投屏/打印机不可用。", WARNING))
        elif c["field"] in ("IPv4连通性", "IPv6连通性"):
            out.append(_finding(
                "R-PROFILE-CONN", f"网络连通性判定变更：{c['subject']} → {c['new']}",
                "系统对该网络的连通性判定（Internet/本地/无）发生变化。",
                "源头：实际网络可用性变化，或 NCSI 探测被拦截（某些代理/防火墙会屏蔽探测地址）",
                0.6, [c["summary"]],
                "若判定为「无网络」但浏览器能上网，通常是代理软件屏蔽了 msftconnecttest.com。",
                NOTICE))
    return out


def rule_firewall(changes, ctx):
    out = []
    for c in sel(changes, "firewall"):
        if c["field"] == "启用" and str(c["new"]).strip().lower() not in ("1", "true", "True"):
            out.append(_finding(
                "R-FW-OFF", f"防火墙配置文件被关闭：{c['subject']}",
                f"{c['subject']} 防火墙被关闭。这会让该网络下的所有入站防护失效。",
                "源头：第三方安全软件接管后关闭系统防火墙、组策略下发、或手动关闭", 0.8,
                [c["summary"]],
                "强烈建议重新开启。部分杀毒软件会主动关闭 Windows 防火墙并接管，属预期；"
                "否则需排查是否有程序越权修改。", CRITICAL))
    return out


def rule_ipv6(changes, ctx):
    out = []
    for c in sel(changes, "ipv6_global"):
        out.append(_finding(
            "R-IPV6", "IPv6 启用状态变更",
            f"注册表 Tcpip6\\Parameters\\DisabledComponents 由 {c['old'] or '（空）'} 变为 {c['new'] or '（空）'}。"
            "该值控制 IPv6 各组件的启用与否，是 VPN/代理软件最常动的开关之一。",
            "源头：VPN 或代理客户端为避免 IPv6 泄漏而禁用、网络排障脚本、或手动修改", 0.72,
            [c["summary"]],
            "常见取值：0x0 全开、0xff 完全禁用、0x20 优先 IPv4。", WARNING))
    return out


def rule_searchlist(changes, ctx):
    out = []
    for c in sel(changes, "dns_client") + sel(changes, "dns_global") + sel(changes, "tcpip_global"):
        if c["field"] in ("后缀搜索列表", "全局搜索列表", "SearchList", "连接专用后缀", "Domain", "DhcpDomain"):
            is_domainish = bool(re.search(r"\.(com|cn|net|local|ad|edu|internal|corp)\b", c["new"] or "", re.I))
            out.append(_finding(
                "R-SEARCHLIST", f"DNS 后缀/搜索列表变更（{c['subject']}）",
                f"{c['field']} 由 {c['old'] or '（空）'} 变为 {c['new'] or '（空）'}。"
                "DNS 后缀决定「只输主机名」时如何补全域名，直接影响内网资源访问。",
                "源头：" + ("域环境/公司网络通过 DHCP Option 15 或组策略下发"
                            if is_domainish else "手动设置或本地脚本修改"),
                0.68, [c["summary"]],
                "企业/校园网环境下通常为策略下发，属预期。", NOTICE))
    return out


def rule_wlan(changes, ctx):
    out = []
    for c in sel(changes, "wlan"):
        if c["field"] == "SSID":
            out.append(_finding(
                "R-WLAN-SSID", f"WiFi 网络切换：{c['old'] or '（无）'} → {c['new'] or '（无）'}",
                "无线连接的 SSID 发生变化，说明切换了热点或断开了 WiFi。",
                "源头：用户手动切换、系统自动漫游到信号更强的 AP、或原热点断连", 0.85,
                [c["summary"]], "切换热点会连带引发 IP/DNS/路由的一整串变化。", NOTICE))
        elif c["field"] == "已连接":
            out.append(_finding(
                "R-WLAN-STATE", f"无线连接状态：{'已连接' if c['new'] == 'true' else '已断开'}",
                "无线网卡的连接状态变化。",
                "源头：WiFi 开关、离开信号覆盖、AP 踢出、认证失败、飞行模式", 0.75,
                [c["summary"]], "这是下游 IP/DNS 变化的常见根因。", NOTICE))
    return out


def rule_vpn(changes, ctx):
    out = []
    for c in sel(changes, "vpn"):
        if c["kind"] == "added":
            out.append(_finding(
                "R-VPN-NEW", f"新增 VPN 连接配置：{c['subject']}",
                "系统 VPN 连接列表中新增了条目。",
                "源头：用户手动创建、企业/校园 IT 下发的部署脚本、或 VPN 客户端安装时写入",
                0.75, [c["summary"]], "确认该 VPN 服务器是否可信。", WARNING))
        elif c["kind"] == "removed":
            out.append(_finding(
                "R-VPN-DEL", f"VPN 连接配置被删除：{c['subject']}",
                "系统 VPN 连接列表中移除了条目。",
                "源头：手动删除、VPN 客户端卸载、或组策略清理", 0.6, [c["summary"]], "", NOTICE))
    return out


def rule_ip_interface(changes, ctx):
    out = []
    for c in sel(changes, "ip_interface"):
        if c["field"] == "Metric":
            out.append(_finding(
                "R-IFACE-METRIC", f"接口优先级(Metric)变更：{c['subject']} → {c['new']}",
                "接口的路由度量值变化，决定多网卡并存时优先使用哪一块。",
                "源头：VPN 客户端降低自身 Metric 以抢占出口、多网卡切换、或手动调整", 0.72,
                [c["summary"]], "VPN 接管出口时典型表现为该接口 Metric 变小。", NOTICE))
        elif c["field"] == "DHCP":
            out.append(_finding(
                "R-IFACE-DHCP", f"接口 DHCP 开关变更：{c['subject']} → {c['new']}",
                "接口的 DHCP 启用状态变化。关闭 DHCP 后需手动指定 IP 与 DNS。",
                "源头：手动改为静态 IP、脚本/软件修改、或网络修复向导重置", 0.7,
                [c["summary"]], "DHCP 关闭但没配静态 IP 会直接断网。", WARNING))
    return out


def rule_services(changes, ctx):
    out = []
    for c in sel(changes, "service"):
        if c["kind"] == "added":
            out.append(_finding(
                "R-SVC-NEW", f"新增网络相关服务：{c['subject']}",
                "系统中出现一个新的网络相关服务。",
                "源头：软件/驱动安装时注册的服务（事件日志 7045 可确认安装来源）", 0.8,
                [c["summary"]], "检查服务可执行文件路径判断归属软件。", NOTICE))
        elif c["field"] == "状态":
            out.append(_finding(
                "R-SVC-STATE", f"服务状态变更：{c['subject']} → {c['new']}",
                f"服务 {c['subject']} 的运行状态发生变化。",
                "源头：软件启动/退出、系统启动、或手动启停服务", 0.7, [c["summary"]],
                "网络类服务启停常伴随网络配置重建。", NOTICE))
    return out


# ---------------------------------------------------------------------------
# 通用证据规则（对每个事件都执行，用于强化/修正归因）
# ---------------------------------------------------------------------------

def rule_audit(changes, ctx):
    """Windows 安全审计（4663）直接记录的执行者 —— 铁证级溯源。"""
    out = []
    for h in ctx.get("audit_hits", [])[:5]:
        proc = h.get("process") or "（未记录进程名）"
        short = proc.replace("\\", "/").split("/")[-1]
        out.append(_finding(
            "R-AUDIT", f"安全审计捕获到修改者：{short}",
            f"Windows 安全审计记录了进程「{proc}」对本机网络配置对象「{h['object_desc']}」的访问/修改，"
            f"完整对象路径：{h['object']}。这是系统内核级记录，可直接指认执行者。",
            f"源头：进程 {proc}（Windows 安全审计事件 {h['id']}，{h['time']}）",
            0.97,
            [f"对象：{h['object']}", f"进程：{proc}"],
            "该记录由 Windows 审计子系统产生，可信度最高。若该进程不属于你已知的软件，"
            "请核对其数字签名（右键 → 属性 → 数字签名）与安装来源。",
            WARNING))
    return out


def rule_event_evidence(changes, ctx):
    out = []
    for clue in ctx["clues"][:4]:
        if clue["weight"] < 2:
            continue
        conf = 0.85 if clue["weight"] == 3 else 0.65
        out.append(_finding(
            "E-EVENT", f"事件日志证据：{clue['provider']} (ID {clue['id']})",
            clue["meaning"],
            f"源头线索：Windows 事件日志 {clue['log']} / {clue['provider']}，"
            f"发生时间 {clue['time']}（权重 {clue['weight']}）",
            conf,
            [f"[{clue['level'] or '信息'}] {clue['message'][:240]}"],
            "事件日志是判断根因最直接的证据，优先采信。",
            WARNING if clue["weight"] == 3 else INFO))
    return out


def rule_process_evidence(changes, ctx):
    out = []
    for h in ctx["proc_hits"][:4]:
        if h["weight"] < 3:
            continue
        out.append(_finding(
            "E-PROC", f"具备改网能力的相关进程：{h['name']} (PID {h['pid']})",
            f"变更发生时，进程 {h['name']} 正在运行，它属于「{h['owner']}」这类"
            "有能力修改网络配置的程序。"
            "注意：这只是「存在性」证据 —— 说明它有条件改，不能证明本次就是它改的。",
            f"候选源头：进程 {h['name']}" + (f"　路径：{h['exe']}" if h.get("exe") else ""),
            0.62,
            [f"命令行：{h['cmd']}" if h.get("cmd") else f"进程：{h['name']}"],
            "想确认到底是不是它改的，需要开启注册表审计（见「开启注册表审计.bat」）"
            "或用 Process Monitor 抓 RegSetValue。", INFO))
    return out


def rule_service_evidence(changes, ctx):
    out = []
    for h in ctx["svc_hits"][:3]:
        if h["weight"] < 3 or h["state"] != "Running":
            continue
        out.append(_finding(
            "E-SVC", f"运行中的网络服务：{h['name']}（{h['display']}）",
            f"服务 {h['name']} 正在运行，归属「{h['owner']}」。",
            f"候选源头：服务 {h['name']}" + (f"　可执行文件：{h['path']}" if h.get("path") else ""),
            0.55, [f"状态：{h['state']}　路径：{h.get('path') or '—'}"],
            "网络类服务在启动时会重写 IP/DNS/路由配置。", INFO))
    return out


def rule_install_evidence(changes, ctx):
    """仅当出现「结构性」变更（新网卡 / 新服务 / 驱动 / 防火墙）时才关联软件安装。

    否则 Windows 更新每天刷新大量软件的 InstallDate，会产生大量无意义线索。
    """
    out = []
    today = ctx.get("today")
    if not today:
        return out
    cats = {c["category"] for c in changes}
    if not (cats & {"adapter", "service", "firewall", "ipv6_global"}):
        return out
    for app in ctx.get("recent_apps", [])[:4]:
        if app.get("InstallDate") == today:
            out.append(_finding(
                "E-INSTALL", f"同期安装的软件：{app.get('DisplayName')}",
                f"检测到软件「{app.get('DisplayName')}」的安装日期与本次网络变更同日"
                f"（InstallDate={app.get('InstallDate')}，发行者：{app.get('Publisher') or '未知'}）。",
                f"候选源头：软件安装 —— {app.get('DisplayName')}"
                + (f"（{app.get('InstallLocation') or ''}）" if app.get("InstallLocation") else ""),
                0.42, [f"版本：{app.get('DisplayVersion') or '—'}　发行者：{app.get('Publisher') or '未知'}"],
                "安装 VPN/虚拟机/代理/抓包/安全类软件几乎必然改动网络配置。"
                "注意 Windows 更新会刷新部分软件的 InstallDate，此线索仅供参照。", INFO))
    return out


def rule_gpo(changes, ctx):
    out = []
    dom = ctx.get("domain") or {}
    if not (dom.get("PartOfDomain") or dom.get("UserDnsDomain")):
        return out
    out.append(_finding(
        "E-GPO", "设备处于域环境中",
        f"本机已加入域「{dom.get('Domain') or dom.get('UserDnsDomain')}」，"
        "网络配置可能由域控制器通过组策略(GPO)统一下发，本地修改会被周期性覆盖。",
        f"源头线索：域/组织策略（{dom.get('Domain') or dom.get('UserDnsDomain')}）", 0.5,
        [f"PartOfDomain={dom.get('PartOfDomain')}"],
        "若配置反复被改回，基本可确定是 GPO 下发；需联系管理员或用 gpresult /h 查看实际策略。",
        NOTICE))
    return out


RULES = [
    rule_audit,
    rule_adapters, rule_addresses, rule_dns, rule_proxy, rule_routes,
    rule_hosts, rule_profile, rule_firewall, rule_ipv6, rule_searchlist,
    rule_wlan, rule_vpn, rule_ip_interface, rule_services,
    rule_event_evidence, rule_process_evidence, rule_service_evidence,
    rule_install_evidence, rule_gpo,
]


def fallback(changes, ctx) -> list[dict]:
    if not changes:
        return []
    cats = sorted({c["category_label"] for c in changes})
    return [_finding(
        "E-FALLBACK", "未匹配到明确规则",
        f"本次共 {len(changes)} 项配置发生变化，涉及：{'、'.join(cats)}。"
        "现有的启发式规则未能给出高置信度归因。",
        "源头：暂无法自动确定", 0.3,
        [c["summary"] for c in changes[:6]],
        "要精确定位「哪个进程改的」，可开启注册表审计后用 Sysinternals Process Monitor 复现："
        "管理员权限执行 auditpol /set /subcategory:\"Registry\" /success /failure，"
        "再用 ProcMon 过滤 RegSetValue 且 Path 含 Tcpip\\Parameters 或 Internet Settings。",
        INFO)]


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def _pick_primary(findings: list[dict]) -> dict | None:
    """主结论的选择顺序：安全审计 > 机制规则(R-*) > 环境证据(E-*)。

    机制规则直接解释「这个变化本身是什么、由什么引起」，优先级高于
    仅仅说明「这段时间系统还发生了什么」的环境证据。
    """
    tiers = [
        [f for f in findings if f["rule"] == "R-AUDIT"],
        [f for f in findings if f["rule"].startswith("R-")],
        [f for f in findings if f["rule"].startswith("E-") and f["rule"] != "E-FALLBACK"],
        findings,
    ]
    for t in tiers:
        if t:
            return max(t, key=lambda f: f["confidence"])
    return None


def attribute(changes: list[dict], old_snap: dict, new_snap: dict,
              raw_events: list[dict]) -> dict:
    """对一次变更集合做归因，返回结构化结论。"""
    from datetime import datetime

    categories = {c["category"] for c in changes}
    clues = [c for c in interpret_events(raw_events) if EV.event_relevant(c, categories)]
    audit_hits = EV.extract_audit_hits(raw_events)

    proc_hits = _proc_hits(new_snap) + _proc_hits(old_snap)
    seen: set[str] = set()
    uniq_procs = []
    for p in proc_hits:
        k = p["name"] or ""
        if k and k not in seen:
            seen.add(k)
            uniq_procs.append(p)
    svc_hits = _svc_hits(new_snap)
    today = datetime.now().strftime("%Y%m%d")
    ctx = {
        "clues": clues,
        "audit_hits": audit_hits,
        "proc_hits": uniq_procs,
        "svc_hits": svc_hits,
        "recent_apps": new_snap.get("installed_apps", []),
        "domain": new_snap.get("domain") or {},
        "today": today,
    }

    findings: list[dict] = []
    for r in RULES:
        try:
            findings.extend(r(changes, ctx) or [])
        except Exception as e:  # 单条规则失败不影响整体
            findings.append(_finding("E-RULEERROR", f"规则 {r.__name__} 执行异常",
                                     str(e), "内部错误", 0.1, [], "", INFO))

    # 证据强化：存在高权重直接证据时，提升相关推断的可信度
    strong = any(f["rule"].startswith(("E-EVENT", "E-PROC")) and f["confidence"] >= 0.85
                 for f in findings)
    if strong:
        # 证据只用于「补足」弱推断，上限低于强规则，避免弱规则反超
        for f in findings:
            if f["rule"].startswith("R-") and f["confidence"] < 0.85:
                f["confidence"] = round(min(0.88, f["confidence"] + 0.06), 2)

    if not any(f["rule"].startswith(("R-", "E-EVENT", "E-PROC")) for f in findings):
        findings.extend(fallback(changes, ctx))

    findings.sort(key=lambda f: -f["confidence"])

    # 综合结论
    primary = _pick_primary(findings)
    others = [f for f in findings
              if f is not primary and f["rule"] != "E-FALLBACK" and f["confidence"] >= 0.55]
    seen_src: set[str] = set()
    contributing = []
    for f in others:
        key = f["source"][:60]
        if key in seen_src:
            continue
        seen_src.add(key)
        contributing.append({"source": f["source"], "cause": f["cause"],
                             "confidence": f["confidence"]})
        if len(contributing) >= 5:
            break
    summary = {
        "primary_cause": primary["cause"] if primary else "无",
        "primary_source": primary["source"] if primary else "无",
        "confidence": primary["confidence"] if primary else 0.0,
        "contributing": contributing,
    }
    sev = min((c["severity"] for c in changes),
              key=lambda s: {"critical": 0, "warning": 1, "notice": 2, "info": 3}.get(s, 9),
              default="info")

    # 记录阈值：只有「能给出机制解释」或「涉及高风险项」的变化才值得入库，
    # 否则系统自身的持续抖动会把事件日志淹没。
    has_mechanism = any(f["rule"].startswith("R-") for f in findings)
    risky = any(c["severity"] in (CRITICAL, WARNING) for c in changes)
    record = bool(has_mechanism or risky)

    return {"findings": findings, "summary": summary, "severity": sev, "record": record,
            "evidence_count": len(clues) + len(uniq_procs) + len(svc_hits) + len(audit_hits),
            "audit_hits": audit_hits,
            "clues": clues[:12]}
