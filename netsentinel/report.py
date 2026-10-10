"""HTML 可视化报告生成（单文件、离线可用、暗色主题）。"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from . import store as ST
from .diffing import index_snapshot

SEV_CN = {"critical": "严重", "warning": "警告", "notice": "注意", "info": "信息"}
KIND_CN = {"added": "新增", "removed": "移除", "changed": "变更"}

HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetSentinel 网络变更溯源报告</title>
<style>
:root{
  --bg:#0d1117; --panel:#151b26; --panel2:#1b2330; --line:#263041; --line2:#1f2836;
  --txt:#e6edf3; --dim:#8b98a9; --dim2:#6b7787;
  --acc:#4da3ff; --acc2:#2d7dd2;
  --crit:#ff5f56; --warn:#ffb454; --note:#4da3ff; --info:#8b98a9; --ok:#3fd68a;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
  font:14px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 80px}
header{border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:22px}
h1{margin:0 0 6px;font-size:24px;letter-spacing:.5px}
h1 .icon{color:var(--crit)}
.sub{color:var(--dim);font-size:13px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0 26px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.stat .n{font-size:26px;font-weight:600;line-height:1.2}
.stat .l{color:var(--dim);font-size:12px;margin-top:2px}
h2{font-size:17px;margin:30px 0 12px;padding-left:10px;border-left:3px solid var(--acc)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:14px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}
.kv{display:grid;grid-template-columns:110px 1fr;gap:4px 12px;font-size:13px}
.kv .k{color:var(--dim)}
.kv .v{word-break:break-all;font-family:Consolas,Menlo,monospace;font-size:12.5px}
.badge{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11.5px;border:1px solid;vertical-align:middle}
.b-crit{color:var(--crit);border-color:rgba(255,95,86,.4);background:rgba(255,95,86,.1)}
.b-warn{color:var(--warn);border-color:rgba(255,180,84,.4);background:rgba(255,180,84,.1)}
.b-note{color:var(--note);border-color:rgba(77,163,255,.4);background:rgba(77,163,255,.1)}
.b-info{color:var(--info);border-color:rgba(139,152,169,.4);background:rgba(139,152,169,.1)}
.b-ok{color:var(--ok);border-color:rgba(63,214,138,.4);background:rgba(63,214,138,.1)}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 6px}
.filters button{background:var(--panel2);border:1px solid var(--line);color:var(--dim);
  padding:5px 13px;border-radius:18px;cursor:pointer;font-size:12.5px}
.filters button.on{background:rgba(77,163,255,.15);border-color:var(--acc);color:var(--acc)}
input.search{background:var(--panel2);border:1px solid var(--line);color:var(--txt);
  padding:6px 12px;border-radius:18px;width:240px;font-size:12.5px;outline:none}
.tl{position:relative;padding-left:22px;margin-top:8px}
.tl:before{content:"";position:absolute;left:6px;top:6px;bottom:6px;width:2px;background:var(--line)}
.inc{position:relative;background:var(--panel);border:1px solid var(--line);
  border-radius:10px;padding:14px 16px;margin-bottom:14px}
.inc:before{content:"";position:absolute;left:-20px;top:20px;width:10px;height:10px;border-radius:50%;
  background:var(--note);box-shadow:0 0 0 3px rgba(77,163,255,.15)}
.inc.s-critical:before{background:var(--crit);box-shadow:0 0 0 3px rgba(255,95,86,.18)}
.inc.s-warning:before{background:var(--warn);box-shadow:0 0 0 3px rgba(255,180,84,.18)}
.inc.s-info:before{background:var(--info);box-shadow:0 0 0 3px rgba(139,152,169,.15)}
.inc-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;cursor:pointer}
.inc-id{font-family:Consolas,monospace;font-weight:600;letter-spacing:.5px}
.inc-time{color:var(--dim);font-size:12.5px}
.inc-title{color:var(--dim);font-size:12.5px;margin-left:auto}
.conf{font-family:Consolas,monospace;font-size:13px;font-weight:600}
.conf.hi{color:var(--ok)} .conf.mid{color:var(--warn)} .conf.lo{color:var(--dim)}
.body{margin-top:12px;display:none}
.inc.open .body{display:block}
.concl{background:var(--panel2);border:1px solid var(--line2);border-radius:8px;padding:12px 14px;margin-bottom:12px}
.concl .row{display:grid;grid-template-columns:76px 1fr;gap:8px;margin-bottom:6px;font-size:13px}
.concl .row:last-child{margin-bottom:0}
.concl .lb{color:var(--dim)}
.chg{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:4px}
.chg th{text-align:left;color:var(--dim);font-weight:500;border-bottom:1px solid var(--line);
  padding:6px 8px;font-size:12px}
.chg td{padding:6px 8px;border-bottom:1px solid var(--line2);vertical-align:top;word-break:break-all}
.chg td.mono{font-family:Consolas,Menlo,monospace}
.k-added{color:var(--ok)} .k-removed{color:var(--crit)} .k-changed{color:var(--warn)}
.find{background:var(--panel2);border:1px solid var(--line2);border-left:3px solid var(--acc);
  border-radius:6px;padding:10px 12px;margin-bottom:8px;font-size:12.8px}
.find .t{font-weight:600;margin-bottom:4px}
.find .t .rid{color:var(--dim2);font-family:Consolas,monospace;font-size:11.5px;margin-left:6px}
.find .m{color:var(--dim);margin:3px 0}
.find .m b{color:var(--txt);font-weight:600}
.ev{color:var(--dim2);font-family:Consolas,Menlo,monospace;font-size:11.5px;
  margin:4px 0 0 14px;padding-left:8px;border-left:1px solid var(--line)}
.ev li{margin:2px 0}
.adv{color:var(--ok);font-size:12.5px;margin-top:6px}
.evt{font-size:12px;color:var(--dim);margin:3px 0;padding-left:12px;border-left:2px solid var(--line)}
.evt b{color:var(--txt);font-weight:500}
.empty{color:var(--dim);text-align:center;padding:40px 0}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--dim2);font-size:12px}
.tag{display:inline-block;background:var(--panel2);border:1px solid var(--line);color:var(--dim);
  border-radius:4px;padding:0 6px;font-size:11.5px;margin-right:4px;font-family:Consolas,monospace}
details summary{cursor:pointer;color:var(--dim);font-size:12.5px;margin:8px 0}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1><span class="icon">◆</span> NetSentinel · 网络配置变更溯源报告</h1>
  <div class="sub" id="meta"></div>
</header>

<div class="stats" id="stats"></div>

<h2>当前网络状态</h2>
<div class="grid2" id="current"></div>

<h2>变更事件时间线</h2>
<div class="filters">
  <button class="on" data-f="all">全部</button>
  <button data-f="critical">严重</button>
  <button data-f="warning">警告</button>
  <button data-f="notice">注意</button>
  <button data-f="info">信息</button>
  <input class="search" id="q" placeholder="搜索原因 / 源头 / 对象…">
</div>
<div class="tl" id="timeline"></div>

<footer id="foot"></footer>
</div>

<script>
const DATA = window.__DATA__;
const SEV = {critical:'严重',warning:'警告',notice:'注意',info:'信息'};
const KIND = {added:'新增',removed:'移除',changed:'变更'};
const esc = s => String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function confCls(c){return c>=0.8?'hi':(c>=0.6?'mid':'lo');}

function renderMeta(){
  const d = DATA;
  document.getElementById('meta').innerHTML =
    `${d.note?`<span class="badge b-warn">${esc(d.note)}</span> `:''}`+
    `主机 <b>${esc(d.host||'-')}</b> · 用户 <b>${esc(d.user||'-')}</b> · `+
    `系统 ${esc(d.os||'-')} · 报告生成于 ${esc(d.generated)} · 数据源：本地事件日志 events.jsonl`;
  document.getElementById('foot').innerHTML =
    `NetSentinel v1.0 · 共 ${d.incidents.length} 次变更事件 / ${d.total_changes} 项配置变化 · `+
    `归因基于事件日志、进程与服务的启发式规则，置信度仅供参考，关键决策请结合人工核对。`;
}

function renderStats(){
  const inc = DATA.incidents;
  const sev = {critical:0,warning:0,notice:0,info:0};
  inc.forEach(i=>sev[i.attribution?.severity||'info']++);
  const hiConf = inc.filter(i=>(i.attribution?.summary?.confidence||0)>=0.8).length;
  const cards = [
    ['变更事件', inc.length, '次网络配置变动'],
    ['配置变化项', DATA.total_changes, '条细粒度差异'],
    ['严重 / 警告', sev.critical+' / '+sev.warning, '需优先关注'],
    ['高置信归因', hiConf, '置信度 ≥ 80%'],
  ];
  document.getElementById('stats').innerHTML = cards.map(([l,n,s])=>
    `<div class="stat"><div class="n">${n}</div><div class="l">${l} · ${s}</div></div>`).join('');
}

function panel(title, rows){
  return `<div class="panel"><div style="font-weight:600;margin-bottom:8px">${title}</div>
    <div class="kv">${rows.map(([k,v])=>`<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`).join('')}</div></div>`;
}

function renderCurrent(){
  const c = DATA.current||{};
  const rows = (o)=>Object.entries(o||{}).map(([k,v])=>[k, typeof v==='object'?JSON.stringify(v):v]);
  let html = '';
  html += panel('网卡适配器', (c.adapters||[]).map(a=>[a.n, `${a.s} · ${a.d||''} · MTU ${a.mtu||'-'}`]));
  html += panel('IP 地址', (c.addresses||[]).map(a=>[a.k, `${a.ip} /${a.pl||''} · ${a.origin||''}`]));
  html += panel('DNS 服务器', (c.dns||[]).map(d=>[d.k, d.v||'（空）']));
  html += panel('默认路由', (c.routes||[]).map(r=>[r.k, `→ ${r.nh} · Metric ${r.m} · ${r.p}`]));
  html += panel('代理设置', (c.proxy||[]).map(p=>[p.k, `启用=${p.en||'-'} 服务器=${p.sv||'-'} PAC=${p.pac||'-'}`]));
  html += panel('网络位置 / 无线 / 防火墙',
    (c.misc||[]).map(m=>[m.k, m.v]));
  document.getElementById('current').innerHTML = html;
}

function renderTimeline(){
  const tl = document.getElementById('timeline');
  if(!DATA.incidents.length){
    tl.innerHTML = `<div class="empty">暂无变更事件。运行 <span class="tag">python run.py watch</span> 开始监测。</div>`;
    return;
  }
  tl.innerHTML = DATA.incidents.map(inc=>{
    const a = inc.attribution||{};
    const s = a.summary||{};
    const sev = a.severity||'info';
    const conf = s.confidence||0;
    const chg = inc.changes||[];
    return `<div class="inc s-${sev}" data-sev="${sev}" data-txt="${esc((s.primary_cause||'')+' '+(s.primary_source||'')+' '+chg.map(c=>c.subject+c.summary).join(' '))}">
      <div class="inc-head" onclick="this.parentElement.classList.toggle('open')">
        <span class="inc-id">${esc(inc.id)}</span>
        <span class="badge b-${sev==='critical'?'crit':sev==='warning'?'warn':sev==='notice'?'note':'info'}">${SEV[sev]||sev}</span>
        <span class="inc-time">${esc(inc.detected_local||inc.detected_at)}</span>
        <span class="inc-title">${chg.length} 项变化 · 点击展开</span>
      </div>
      <div class="body">
        <div class="concl">
          <div class="row"><div class="lb">可能原因</div><div>${esc(s.primary_cause||'—')}</div></div>
          <div class="row"><div class="lb">变更源头</div><div>${esc(s.primary_source||'—')}</div></div>
          <div class="row"><div class="lb">置信度</div>
            <div><span class="conf ${confCls(conf)}">${(conf*100).toFixed(0)}%</span>
            ${(s.contributing||[]).length?`<span style="color:var(--dim);font-size:12px;margin-left:10px">另有 ${s.contributing.length} 项次要因素</span>`:''}</div></div>
        </div>
        ${(s.contributing||[]).length?`<div class="concl" style="background:transparent;border-style:dashed">
          <div style="color:var(--dim);font-size:12.5px;margin-bottom:6px">次要 / 并列因素</div>
          ${s.contributing.map(c=>`<div style="font-size:12.5px;margin:4px 0">
            <span class="conf ${confCls(c.confidence)}">${(c.confidence*100).toFixed(0)}%</span>
            ${esc(c.source)} —— <span style="color:var(--dim)">${esc(c.cause)}</span></div>`).join('')}</div>`:''}
        <details open><summary>配置差异明细（${chg.length}）</summary>
        <table class="chg"><thead><tr><th>类别</th><th>对象</th><th>类型</th><th>字段</th><th>原值</th><th>新值</th></tr></thead><tbody>
        ${chg.map(c=>`<tr>
          <td>${esc(c.category_label)}</td>
          <td class="mono">${esc(c.subject)}</td>
          <td class="k-${c.kind}">${KIND[c.kind]||c.kind}</td>
          <td>${esc(c.field||'—')}</td>
          <td class="mono" style="color:var(--dim)">${esc(c.old||'—')}</td>
          <td class="mono">${esc(c.new||'—')}</td></tr>`).join('')}
        </tbody></table></details>
        ${(a.findings||[]).length?`<details open><summary>归因依据与证据链（${a.findings.length}）</summary>
          ${a.findings.map(f=>`<div class="find">
            <div class="t">${esc(f.title)}<span class="rid">${esc(f.rule)} · ${(f.confidence*100).toFixed(0)}%</span></div>
            <div class="m"><b>原因：</b>${esc(f.cause)}</div>
            <div class="m"><b>源头：</b>${esc(f.source)}</div>
            ${(f.evidence||[]).length?`<ul class="ev">${f.evidence.slice(0,6).map(e=>`<li>${esc(e)}</li>`).join('')}</ul>`:''}
            ${f.advice?`<div class="adv">↳ 建议：${esc(f.advice)}</div>`:''}
          </div>`).join('')}</details>`:''}
        ${(inc.audit_hits||[]).length?`<details open><summary>🔒 Windows 安全审计记录（可直接指认执行者，${inc.audit_hits.length}）</summary>
          ${inc.audit_hits.map(h=>`<div class="find" style="border-left-color:var(--ok)">
            <div class="t">进程 ${esc(String(h.process||'').split('\\\\').pop())} 修改了「${esc(h.object_desc)}」</div>
            <div class="ev" style="list-style:none;margin-left:0"><li>对象：${esc(h.object)}</li>
            <li>进程：${esc(h.process||'—')}</li><li>时间：${esc((h.time||'').slice(0,19).replace('T',' '))}</li></div>
          </div>`).join('')}</details>`:''}
        ${(inc.clues||[]).length?`<details><summary>Windows 事件日志线索（${inc.clues.length}）</summary>
          ${inc.clues.map(c=>`<div class="evt"><b>${esc((c.time||'').slice(0,19).replace('T',' '))}</b>
            ${esc(c.provider)}/${c.id} · ${esc(c.meaning)}</div>`).join('')}</details>`:''}
      </div></div>`;
  }).join('');
  document.querySelectorAll('.inc-head').forEach((h,i)=>{ if(i===0) h.parentElement.classList.add('open'); });
}

function bindFilters(){
  document.querySelectorAll('.filters button').forEach(b=>{
    b.onclick=()=>{
      document.querySelectorAll('.filters button').forEach(x=>x.classList.remove('on'));
      b.classList.add('on');
      const f=b.dataset.f;
      document.querySelectorAll('.inc').forEach(el=>{
        el.style.display = (f==='all'||el.dataset.sev===f)?'':'none';
      });
      applySearch();
    };
  });
  document.getElementById('q').oninput = applySearch;
}
function applySearch(){
  const q = document.getElementById('q').value.trim().toLowerCase();
  document.querySelectorAll('.inc').forEach(el=>{
    if(!q) { el.style.display=''; return; }
    el.style.display = (el.dataset.txt||'').toLowerCase().includes(q)?'':'none';
  });
}

renderMeta(); renderStats(); renderCurrent(); renderTimeline(); bindFilters();
</script>
</body></html>
"""


def _fmt_time(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return d.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def build_current(snap: dict) -> dict:
    idx = index_snapshot(snap)
    adapters = []
    for k, v in idx.get("adapter", {}).items():
        adapters.append({"n": k, "s": v.get("状态", ""), "d": v.get("描述", ""), "mtu": v.get("MTU", "")})
    addresses = []
    for k, v in idx.get("address", {}).items():
        parts = k.split("::")
        addresses.append({"k": parts[0], "ip": parts[-1], "pl": v.get("前缀长度", ""),
                          "origin": v.get("前缀来源", "")})
    dns = [{"k": k, "v": v.get("服务器", "")} for k, v in idx.get("dns", {}).items()]
    routes = []
    for k, v in idx.get("route", {}).items():
        if v.get("前缀") in ("0.0.0.0/0", "::/0"):
            routes.append({"k": v.get("接口", ""), "nh": v.get("下一跳", ""),
                           "m": v.get("Metric", ""), "p": v.get("协议", "")})
    proxy = [{"k": k, "en": v.get("启用", "-"), "sv": v.get("服务器", ""), "pac": v.get("自动配置脚本", "")}
             for k, v in idx.get("proxy", {}).items()]
    misc = []
    for k, v in idx.get("network_profile", {}).items():
        misc.append({"k": f"网络 {k}", "v": f"{v.get('网络名','')} · 类别 {v.get('类别','')} · IPv4 {v.get('IPv4连通性','')}"})
    for k, v in idx.get("wlan", {}).items():
        misc.append({"k": "无线", "v": f"SSID {v.get('SSID') or '—'} · 已连接 {v.get('已连接')} · 信号 {v.get('信号') or '—'}"})
    for k, v in idx.get("firewall", {}).items():
        misc.append({"k": f"防火墙 {k}", "v": f"启用 {v.get('启用')}"})
    h = snap.get("hosts") or {}
    misc.append({"k": "hosts", "v": f"{len(h.get('Lines') or [])} 条规则 · SHA {str(h.get('Sha256'))[:12]} · 修改于 {_fmt_time(h.get('MTime'))}"})
    iv = (snap.get("ipv6_global") or {}).get("DisabledComponents")
    misc.append({"k": "IPv6", "v": f"DisabledComponents = {iv if iv is not None else '（默认全开）'}"})
    return {"adapters": adapters, "addresses": addresses, "dns": dns,
            "routes": routes, "proxy": proxy, "misc": misc}


def build_report(incidents: list[dict], latest: dict, out: Path | None = None,
                 note: str = "") -> Path:
    for inc in incidents:
        inc["detected_local"] = _fmt_time(inc.get("detected_at"))
    data = {
        "note": note,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": latest.get("hostname"),
        "user": latest.get("username"),
        "os": latest.get("os_caption"),
        "incidents": incidents,
        "total_changes": sum(len(i.get("changes") or []) for i in incidents),
        "current": build_current(latest),
    }
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    html = HTML.replace("window.__DATA__", payload)
    out = Path(out) if out else ST.REPORT_FILE
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out
