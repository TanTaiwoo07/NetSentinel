"""命令行入口。"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import attribute as AT
from . import collect as CO
from . import store as ST
from .diffing import diff_snapshots, index_snapshot
from .evidence import interpret_events

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SEV_MARK = {"critical": "🔴", "warning": "🟠", "notice": "🔵", "info": "⚪"}
SEV_CN = {"critical": "严重", "warning": "警告", "notice": "注意", "info": "信息"}


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _local(iso: str | None) -> str:
    d = _ts(iso)
    if not d:
        return iso or "—"
    return d.astimezone().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------

def cmd_status(args) -> int:
    print("正在采集当前网络状态…")
    snap = CO.collect_snapshot()
    idx = index_snapshot(snap)
    print(f"\n主机：{snap.get('hostname')}　用户：{snap.get('username')}　"
          f"采集时间：{_local(snap.get('collected_at'))}")
    print("=" * 78)

    print("\n【网卡】")
    for a in snap.get("adapters", []):
        print(f"  · {a.get('Name')}　[{a.get('Status')}]　{a.get('InterfaceDescription')}")
        print(f"      MAC={a.get('MacAddress')}　速率={a.get('LinkSpeed')}　MTU={a.get('MtuSize')}")

    print("\n【IP 地址】")
    for k, v in idx.get("address", {}).items():
        print(f"  · {k}　前缀={v.get('前缀长度')}　来源={v.get('前缀来源')}")

    print("\n【DNS】")
    for k, v in idx.get("dns", {}).items():
        print(f"  · {k}　{ v.get('服务器') or '（空）'}")

    print("\n【默认路由】")
    for k, v in idx.get("route", {}).items():
        if v.get("前缀") in ("0.0.0.0/0", "::/0"):
            print(f"  · {v.get('前缀')} → {v.get('下一跳')}　接口={v.get('接口')}　"
                  f"Metric={v.get('Metric')}　协议={v.get('协议')}")

    print("\n【代理】")
    for k, v in idx.get("proxy", {}).items():
        en = v.get("启用")
        print(f"  · {k}：启用={en or '—'}　服务器={v.get('服务器') or '—'}　"
              f"PAC={v.get('自动配置脚本') or '—'}")

    print("\n【网络位置】")
    for k, v in idx.get("network_profile", {}).items():
        print(f"  · {k}　{v.get('网络名')}　类别={v.get('类别')}　IPv4={v.get('IPv4连通性')}")

    print("\n【无线】")
    for k, v in idx.get("wlan", {}).items():
        print(f"  · SSID={v.get('SSID') or '—'}　已连接={v.get('已连接')}　信号={v.get('信号') or '—'}")

    print("\n【防火墙】")
    for k, v in idx.get("firewall", {}).items():
        print(f"  · {k}　启用={v.get('启用')}")

    h = snap.get("hosts") or {}
    print(f"\n【hosts】{h.get('Path')}　SHA256={str(h.get('Sha256'))[:16]}…　"
          f"有效行数={len(h.get('Lines') or [])}　修改时间={_local(h.get('MTime'))}")
    return 0


def cmd_snapshot(args) -> int:
    snap = CO.collect_snapshot()
    p = ST.save_snapshot(snap)
    idx = index_snapshot(snap)
    total = sum(len(v) for v in idx.values())
    print(f"✓ 快照已保存：{p}")
    print(f"  采集时间：{_local(snap.get('collected_at'))}　实体总数：{total}")
    for cat in sorted(idx):
        print(f"    - {cat}: {len(idx[cat])}")
    return 0


def cmd_diff(args) -> int:
    files = ST.list_snapshots()
    if args.base:
        base = ST.load_snapshot(Path(args.base))
    else:
        if len(files) < 2:
            print("至少需要 2 个快照。先运行 snapshot 命令，或用 --base 指定。")
            return 1
        base = ST.load_snapshot(files[-2])
    if args.to:
        cur = ST.load_snapshot(Path(args.to))
    else:
        if not files:
            print("当前没有任何快照。先运行 snapshot 命令。")
            return 1
        cur = ST.load_snapshot(files[-1])
    changes = diff_snapshots(base, cur)
    print(f"对比：{_local(base.get('collected_at'))}  →  {_local(cur.get('collected_at'))}")
    _print_changes(changes)

    if changes and not args.no_attribute:
        t0 = (_ts(base.get("collected_at")) or datetime.now(timezone.utc)) - timedelta(minutes=3)
        t1 = (_ts(cur.get("collected_at")) or datetime.now(timezone.utc)) + timedelta(minutes=2)
        evts = CO.collect_events(t0, t1)
        res = AT.attribute(changes, base, cur, evts)
        _print_attribution(res)
    return 0


def _print_changes(changes: list[dict]) -> None:
    if not changes:
        print("\n未检测到任何变化。")
        return
    print(f"\n检测到 {len(changes)} 项变化：")
    print("-" * 78)
    for c in changes:
        mark = {"added": "+", "removed": "-", "changed": "~"}[c["kind"]]
        print(f" {mark} {SEV_MARK.get(c['severity'], '·')} [{c['category_label']}] {c['summary']}")


def _print_attribution(res: dict) -> None:
    print("\n" + "=" * 78)
    print("归因分析")
    print("=" * 78)
    s = res["summary"]
    print(f"\n▶ 最可能的原因：{s['primary_cause']}")
    print(f"▶ 最可能的源头：{s['primary_source']}")
    print(f"▶ 置信度：{s['confidence']:.0%}　事件级别：{SEV_CN.get(res['severity'], res['severity'])}")
    if s["contributing"]:
        print("\n其他可能的贡献因素：")
        for c in s["contributing"]:
            print(f"  · [{c['confidence']:.0%}] {c['source']} —— {c['cause']}")
    print("\n证据与依据：")
    for f in res["findings"][:8]:
        print(f"\n  [{f['confidence']:.0%}] {f['title']}（{f['rule']}）")
        print(f"      原因：{f['cause']}")
        print(f"      源头：{f['source']}")
        for e in f["evidence"][:3]:
            print(f"      证据：{e}")
        if f["advice"]:
            print(f"      建议：{f['advice']}")


def cmd_watch(args) -> int:
    interval = max(2, args.interval)
    print(f"NetSentinel 开始监测（间隔 {interval}s）。Ctrl+C 停止。")
    print(f"事件日志：{ST.EVENTS_FILE}\n")
    base = CO.collect_snapshot()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 基线快照已建立（{_local(base.get('collected_at'))}）")
    t_end = None
    if args.duration:
        t_end = time.time() + args.duration
    n = 0
    try:
        while True:
            if t_end and time.time() > t_end:
                print("\n达到设定时长，监测结束。")
                break
            time.sleep(interval)
            cur = CO.collect_snapshot()
            changes = diff_snapshots(base, cur)
            if changes:
                n += 1
                t0 = (_ts(base.get("collected_at")) or datetime.now(timezone.utc)) - timedelta(minutes=3)
                t1 = (_ts(cur.get("collected_at")) or datetime.now(timezone.utc)) + timedelta(minutes=2)
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ⚡ 检测到 {len(changes)} 项变化，正在溯源…")
                evts = CO.collect_events(t0, t1)
                res = AT.attribute(changes, base, cur, evts)
                if not res.get("record", True):
                    # 系统自身抖动（如租约刷新、信号波动）且无可解释机制，不入库
                    base = cur
                    continue
                inc = {
                    "id": ST.next_incident_id(),
                    "detected_at": cur.get("collected_at"),
                    "window": [base.get("collected_at"), cur.get("collected_at")],
                    "changes": changes,
                    "attribution": res,
                    "clues": res.get("clues") or [],
                    "audit_hits": res.get("audit_hits") or [],
                    "host": cur.get("hostname"),
                    "user": cur.get("username"),
                }
                ST.append_incident(inc)
                print(f"{inc['id']}　{SEV_MARK.get(res['severity'])} "
                      f"{SEV_CN.get(res['severity'])}　置信度 {res['summary']['confidence']:.0%}")
                print(f"  原因：{res['summary']['primary_cause']}")
                print(f"  源头：{res['summary']['primary_source']}")
            base = cur
    except KeyboardInterrupt:
        print("\n监测已停止。")
    print(f"\n共记录 {n} 次变更事件。运行 `python run.py report` 查看完整报告。")
    return 0


def cmd_report(args) -> int:
    from .report import build_report
    incs = ST.load_incidents()
    latest = ST.load_latest_snapshot()
    if latest is None:
        latest = CO.collect_snapshot()
        ST.save_snapshot(latest)
    out = build_report(incs, latest)
    print(f"✓ 报告已生成：{out}")
    return 0


def cmd_explain(args) -> int:
    incs = ST.load_incidents()
    target = [i for i in incs if i["id"].lower() == args.incident.lower()]
    if not target:
        print(f"未找到事件 {args.incident}。当前共有 {len(incs)} 条记录。")
        for i in incs[-10:]:
            print(f"  {i['id']}　{_local(i.get('detected_at'))}　{len(i.get('changes', []))} 项变化")
        return 1
    inc = target[0]
    print("=" * 78)
    print(f"事件 {inc['id']}　检测时间：{_local(inc.get('detected_at'))}")
    print(f"窗口：{_local((inc.get('window') or ['', ''])[0])} → {_local((inc.get('window') or ['', ''])[1])}")
    print("=" * 78)
    _print_changes(inc.get("changes", []))
    _print_attribution(inc.get("attribution") or {"summary": {}, "findings": [], "severity": "info"})
    if inc.get("clues"):
        print("\n原始事件日志线索：")
        for c in inc["clues"]:
            print(f"  · [{c['time']}] {c['provider']}/{c['id']}：{c['meaning']}")
    return 0


def cmd_demo(args) -> int:
    from pathlib import Path
    from .demo import run_demo
    out = run_demo(sanitize=not args.no_sanitize,
                   out=Path(args.out) if args.out else None)
    print("\n提示：示例模式不改动系统配置，也不写入 events.jsonl。")
    if args.no_sanitize:
        print("⚠ 未脱敏：报告含本机真实数据，请勿外传。")
    return 0


def cmd_reset(args) -> int:
    ST.clear_incidents()
    print("✓ 事件日志已清空。")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netsentinel",
        description="NetSentinel —— 网络配置变更监测与溯源：发现变化，并回答「为什么变」「谁改的」。")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("status", help="显示当前网络配置速览").set_defaults(func=cmd_status)
    sub.add_parser("snapshot", help="采集并归档一次快照").set_defaults(func=cmd_snapshot)

    d = sub.add_parser("diff", help="对比两次快照并归因")
    d.add_argument("--base", help="基线快照文件路径（默认倒数第二个）")
    d.add_argument("--to", help="目标快照文件路径（默认最新）")
    d.add_argument("--no-attribute", action="store_true", help="只做差异对比，不做归因")
    d.set_defaults(func=cmd_diff)

    w = sub.add_parser("watch", help="持续监测，自动记录变化并溯源")
    w.add_argument("-i", "--interval", type=int, default=5, help="采样间隔秒数（默认 5）")
    w.add_argument("-d", "--duration", type=int, default=0, help="运行时长秒数（默认不限）")
    w.set_defaults(func=cmd_watch)

    sub.add_parser("report", help="生成 HTML 可视化报告").set_defaults(func=cmd_report)

    e = sub.add_parser("explain", help="查看某次变化的详细归因")
    e.add_argument("incident", help="事件 ID，如 INC-0001")
    e.set_defaults(func=cmd_explain)

    d = sub.add_parser("demo", help="生成示例报告：模拟典型变化，验证归因链路"
                                    "（不改动系统、不写入事件日志，默认脱敏）")
    d.add_argument("--no-sanitize", action="store_true",
                   help="不做隐私脱敏（报告含本机真实数据，仅供本地排查）")
    d.add_argument("--out", help="报告输出路径（默认 data/report_demo.html）")
    d.set_defaults(func=cmd_demo)

    sub.add_parser("reset", help="清空事件日志").set_defaults(func=cmd_reset)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"[错误] {type(e).__name__}: {e}", file=sys.stderr)
        return 1
