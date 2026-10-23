"""الحالة الدائمة: الملف المستهدف الحالي."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from . import util
from .config import ROOT

STATE_PATH = ROOT / "state.json"
HASH_LIMIT = 512 * 1024 * 1024  # تجزئة فقط للملفات < 512MB


def _read() -> dict:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write(data: dict) -> None:
    util.atomic_write_text(
        STATE_PATH, json.dumps(data, ensure_ascii=False, indent=2)
    )


def set_target(path: str | Path) -> dict:
    target = Path(path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"ملف غير موجود: {target}")
    size = target.stat().st_size
    data = {
        "target": str(target),
        "name": target.name,
        "kind": util.file_kind(target),
        "size": size,
        "sha256": util.sha256_file(target) if size <= HASH_LIMIT else "",
        "set_at": datetime.now().isoformat(timespec="seconds"),
    }
    _write(data)
    return data


def get_state() -> dict:
    return _read()


def get_target() -> Path | None:
    data = _read()
    raw = data.get("target")
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_file() else None


def clear_target() -> None:
    _write({})
