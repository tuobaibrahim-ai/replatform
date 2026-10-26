"""إدارة مساحات العمل (Workspaces) — كل تحليل يُحفظ في مجلد مستقل."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from .config import WORKSPACES_DIR
from . import util
from .. import __version__

MAX_SLUG = 40


def slugify(text: str) -> str:
    text = re.sub(r"[^\w\-]+", "-", text, flags=re.UNICODE).strip("-_.")
    return text[:MAX_SLUG] or "target"


class Workspace:
    """مساحة عمل: meta.json + artifacts/ + agent/ + report.html + timeline.jsonl"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.artifacts_dir = self.path / "artifacts"
        self.agent_dir = self.path / "agent"

    @property
    def id(self) -> str:
        return self.path.name

    # ---------- الإنشاء والاكتشاف ----------

    @classmethod
    def create(cls, target: Path, name: str | None = None, extra: dict | None = None) -> "Workspace":
        WORKSPACES_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        wsid = f"{stamp}-{slugify(name or Path(target).name)}"
        path = WORKSPACES_DIR / wsid
        suffix = 0
        while path.exists():
            suffix += 1
            path = WORKSPACES_DIR / f"{wsid}-{suffix}"
        path.mkdir(parents=True)
        ws = cls(path)
        ws.artifacts_dir.mkdir(exist_ok=True)
        ws.agent_dir.mkdir(exist_ok=True)
        meta: dict = {
            "id": ws.id,
            "name": name or Path(target).name,
            "target": {
                "path": str(Path(target).resolve()),
                "name": Path(target).name,
            },
            "created": datetime.now().isoformat(timespec="seconds"),
            "version": __version__,
            "analyzers": [],
            "agent": {},
        }
        if extra:
            meta.update(extra)
        ws._write_json(ws.path / "meta.json", meta)
        ws.add_event("create", f"إنشاء مساحة العمل للهدف {meta['target']['name']}")
        return ws

    @classmethod
    def list_all(cls) -> list["Workspace"]:
        if not WORKSPACES_DIR.exists():
            return []
        return sorted(
            (cls(p) for p in WORKSPACES_DIR.iterdir() if p.is_dir() and (p / "meta.json").exists()),
            key=lambda w: w.id,
            reverse=True,
        )

    @classmethod
    def find(cls, wsid: str) -> "Workspace":
        all_ws = cls.list_all()
        candidates = [w for w in all_ws if w.id == wsid]
        if not candidates:
            candidates = [w for w in all_ws if w.id.startswith(wsid)]
        if not candidates:
            candidates = [w for w in all_ws if wsid.lower() in w.id.lower()]
        if not candidates:
            raise FileNotFoundError(f"مساحة العمل غير موجودة: {wsid}")
        if len(candidates) > 1:
            raise ValueError(
                "معرّف غير فريد، اختر واحداً:\n" + "\n".join(f"  {w.id}" for w in candidates)
            )
        return candidates[0]

    # ---------- الأساسيات ----------

    @staticmethod
    def _write_json(path: Path, payload: dict) -> None:
        util.atomic_write_text(
            path, json.dumps(payload, ensure_ascii=False, indent=2)
        )

    @property
    def meta(self) -> dict:
        return json.loads((self.path / "meta.json").read_text("utf-8"))

    def safe_meta(self) -> dict:
        """meta مع بديل آمن حتى لا يُسقط لوحة التحكم ملف تالف واحد."""
        try:
            return self.meta
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return {
                "id": self.id,
                "name": "(meta تالف)",
                "kind": "",
                "created": "",
                "target": {},
            }

    def update_meta(self, **updates) -> None:
        meta = self.meta
        meta.update(updates)
        self._write_json(self.path / "meta.json", meta)

    def add_event(self, kind: str, message: str, data: dict | None = None) -> None:
        event: dict = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "kind": kind,
            "message": message,
        }
        if data:
            event["data"] = data
        with open(self.path / "timeline.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    def timeline(self) -> list[dict]:
        path = self.path / "timeline.jsonl"
        if not path.exists():
            return []
        events = []
        for line in path.read_text("utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    # ---------- المخرجات ----------

    def save_artifact(self, name: str, payload: dict) -> Path:
        path = self.artifacts_dir / f"{name}.json"
        self._write_json(path, payload)
        return path

    def load_artifact(self, name: str) -> dict | None:
        path = self.artifacts_dir / f"{name}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text("utf-8"))

    def all_artifacts(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        if self.artifacts_dir.exists():
            for path in sorted(self.artifacts_dir.glob("*.json")):
                try:
                    out[path.stem] = json.loads(path.read_text("utf-8"))
                except json.JSONDecodeError:
                    continue
        return out

    def save_agent(self, name: str, payload: dict) -> Path:
        path = self.agent_dir / f"{name}.json"
        self._write_json(path, payload)
        return path

    def load_agent(self, name: str) -> dict | None:
        path = self.agent_dir / f"{name}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text("utf-8"))
        except json.JSONDecodeError:
            return None

    def write_text(self, relpath: str, text: str) -> Path:
        path = self.path / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, "utf-8")
        return path
