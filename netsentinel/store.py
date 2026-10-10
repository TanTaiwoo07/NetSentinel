"""存储层：快照归档 + 事件（incident）JSONL 日志。"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SNAP_DIR = DATA_DIR / "snapshots"
EVENTS_FILE = DATA_DIR / "events.jsonl"
REPORT_FILE = DATA_DIR / "report.html"


def _ensure() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SNAP_DIR.mkdir(parents=True, exist_ok=True)


def save_snapshot(snap: dict) -> Path:
    _ensure()
    ts = snap.get("collected_at") or datetime.utcnow().isoformat() + "Z"
    name = re.sub(r"[:.]", "-", ts).replace("Z", "") + ".json"
    p = SNAP_DIR / name
    p.write_text(json.dumps(snap, ensure_ascii=False, indent=1), encoding="utf-8")
    return p


def list_snapshots() -> list[Path]:
    _ensure()
    return sorted(SNAP_DIR.glob("*.json"))


def load_snapshot(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def load_latest_snapshot() -> dict | None:
    files = list_snapshots()
    return load_snapshot(files[-1]) if files else None


def next_incident_id() -> str:
    _ensure()
    if not EVENTS_FILE.exists():
        return "INC-0001"
    n = 0
    for line in EVENTS_FILE.read_text(encoding="utf-8").splitlines():
        if line.strip():
            n += 1
    return f"INC-{n + 1:04d}"


def append_incident(inc: dict) -> None:
    _ensure()
    with EVENTS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(inc, ensure_ascii=False) + "\n")


def load_incidents() -> list[dict]:
    _ensure()
    if not EVENTS_FILE.exists():
        return []
    out = []
    for line in EVENTS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def clear_incidents() -> None:
    _ensure()
    if EVENTS_FILE.exists():
        EVENTS_FILE.unlink()
