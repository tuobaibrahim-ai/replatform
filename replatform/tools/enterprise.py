"""قدرات مؤسسية: سجل تدقيق بسلسلة تجزئة، وتقرير أسطول مساحات العمل.

كلتاهما ميزة تجارية (audit_export / fleet_report) لكن التنفيذ شفاف:
لا يقرأ عيّنات ولا يرسل شيئاً عبر الشبكة.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from ..core.config import ROOT
from ..core.workspace import Workspace
from . import licensing

AUDIT_PATH = ROOT / "audit.jsonl"
GENESIS = "0" * 64


def _canonical(data: dict) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _read_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            entries.append({"_corrupt": line[:120]})
    return entries


def record(event: str, path: str | Path | None = None, **fields) -> dict:
    """يضيف حدثاً موقّعاً بالسلسلة إلى سجل التدقيق."""
    target = Path(path) if path is not None else AUDIT_PATH
    entries = _read_entries(target)
    previous = entries[-1].get("hash", GENESIS) if entries else GENESIS
    entry = {
        "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "event": event,
        "version": __version__,
        **fields,
        "prev": previous,
    }
    entry["hash"] = hashlib.sha256(previous.encode("ascii") + _canonical(entry)).hexdigest()
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
    return entry


def verify_chain(path: str | Path | None = None) -> dict:
    """يتحقق من كل رابط في السلسلة ويكشف أول كسر."""
    target = Path(path) if path is not None else AUDIT_PATH
    entries = _read_entries(target)
    previous = GENESIS
    for index, entry in enumerate(entries):
        if "_corrupt" in entry:
            return {"ok": False, "entries": len(entries), "broken_at": index,
                    "reason": "سطر غير صالح في السجل"}
        expected = entry.get("hash")
        body = {key: value for key, value in entry.items() if key != "hash"}
        actual = hashlib.sha256(previous.encode("ascii") + _canonical(body)).hexdigest()
        if entry.get("prev") != previous or expected != actual:
            return {"ok": False, "entries": len(entries), "broken_at": index,
                    "reason": "تجزئة غير متطابقة (تلاعب أو تعديل يدوي)"}
        previous = expected
    return {"ok": True, "entries": len(entries), "head": previous, "broken_at": None,
            "reason": "السلسلة سليمة"}


def export_audit(dest: str | Path, path: str | Path | None = None,
                 enforce: bool = True) -> dict:
    """يصدّر سجل التدقيق مع إثبات السلسلة (يتطلب audit_export)."""
    if enforce:
        licensing.require_feature("audit_export")
    target = Path(path) if path is not None else AUDIT_PATH
    chain = verify_chain(target)
    payload = {
        "schema": 1,
        "product": "REPLATFORM",
        "version": __version__,
        "exported": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "chain": chain,
        "entries": _read_entries(target),
    }
    payload["sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    output = Path(dest)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def fleet_report(dest: str | Path | None = None, enforce: bool = True) -> dict:
    """ملخّص كل مساحات العمل (يتطلب fleet_report) بلا بيانات عيّنات."""
    if enforce:
        licensing.require_feature("fleet_report")
    rows: list[dict[str, str | int]] = []
    for workspace in Workspace.list_all():
        meta = workspace.safe_meta()
        target = meta.get("target") or {}
        rows.append({
            "id": workspace.id,
            "name": target.get("name") or meta.get("name") or "",
            "kind": target.get("kind") or meta.get("kind") or "",
            "created": meta.get("created") or "",
            "version": meta.get("version") or "",
            "agent_status": (meta.get("agent") or {}).get("status") or "",
            "analyzers": len(meta.get("analyzers") or []),
        })
    kinds: dict[str, int] = {}
    for row in rows:
        key = str(row["kind"] or "unknown")
        kinds[key] = kinds.get(key, 0) + 1
    payload = {
        "schema": 1,
        "product": "REPLATFORM",
        "version": __version__,
        "generated": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "total": len(rows),
        "kinds": kinds,
        "workspaces": rows,
    }
    payload["sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    if dest is not None:
        output = Path(dest)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
    return payload
