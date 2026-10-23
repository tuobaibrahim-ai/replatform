"""موحّد المحللات: واجهة الإضافة (Plugin API) + التشغيل."""

from __future__ import annotations

import importlib.util
import time
from dataclasses import dataclass
from pathlib import Path

from ..core import util
from ..core.config import PLUGINS_DIR


@dataclass
class Target:
    path: Path
    name: str
    kind: str
    size: int
    sha256: str

    @classmethod
    def from_path(cls, path: str | Path, max_mb: int | None = None) -> "Target":
        p = Path(path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"الهدف غير موجود: {p}")
        if not p.is_file():
            raise ValueError(f"الهدف ليس ملفاً: {p}")
        size = p.stat().st_size
        if max_mb is not None and size > int(max_mb) * 1024 * 1024:
            raise ValueError(
                f"حجم الملف ({util.human_size(size)}) يتجاوز الحد "
                f"({int(max_mb)} MB) — عدّل analysis.max_file_mb عند الحاجة."
            )
        return cls(
            path=p,
            name=p.name,
            kind=util.file_kind(p),
            size=size,
            sha256=util.sha256_file(p),
        )


class Analyzer:
    """للإضافات: اضبط name/description ثم نفّذ can_handle و run."""

    name = "base"
    description = ""
    optional = False  # إن كان True لا يُشغَّل تلقائياً (يتطلب --only)

    def can_handle(self, target: Target) -> bool:  # noqa: ARG002
        return False

    def run(self, target: Target, ws) -> dict:  # noqa: ARG002
        raise NotImplementedError


_BUILTINS: list[Analyzer] | None = None


def _load_plugins() -> list[Analyzer]:
    plugins: list[Analyzer] = []
    if not PLUGINS_DIR.exists():
        return plugins
    for path in sorted(PLUGINS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"replatform_plugin_{path.stem}", path)
            if not spec or not spec.loader:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] فشل تحميل إضافة {path.name}: {exc}")
            continue
        for attr in vars(module).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, Analyzer)
                and attr is not Analyzer
                and getattr(attr, "name", "base") != "base"
            ):
                plugins.append(attr())
    return plugins


def load_analyzers() -> list[Analyzer]:
    global _BUILTINS
    if _BUILTINS is None:
        from . import (
            apk_analyzer, disasm_analyzer, ghidra_analyzer,
            pe_analyzer, strings_analyzer, yara_analyzer,
        )

        _BUILTINS = [
            pe_analyzer.PEAnalyzer(),
            apk_analyzer.APKAnalyzer(),
            strings_analyzer.StringsAnalyzer(),
            yara_analyzer.YARAAnalyzer(),
            disasm_analyzer.DisasmAnalyzer(),
            ghidra_analyzer.GhidraAnalyzer(),
        ] + _load_plugins()
    return _BUILTINS


def run_analyzers(target: Target, ws, only: set[str] | None = None) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for analyzer in load_analyzers():
        if only is not None:
            if analyzer.name not in only:
                continue
        elif getattr(analyzer, "optional", False):
            continue
        if not analyzer.can_handle(target):
            continue
        started = time.time()
        ws.add_event("analyzer_start", analyzer.name)
        try:
            result = analyzer.run(target, ws)
            result.setdefault("analyzer", analyzer.name)
            result.setdefault("seconds", round(time.time() - started, 2))
            ws.save_artifact(analyzer.name, result)
            ws.add_event("analyzer_done", analyzer.name, {"seconds": result["seconds"]})
            results[analyzer.name] = result
        except Exception as exc:  # noqa: BLE001
            error = {"analyzer": analyzer.name, "error": f"{type(exc).__name__}: {exc}",
                     "seconds": round(time.time() - started, 2)}
            ws.save_artifact(analyzer.name, error)
            ws.add_event("analyzer_error", analyzer.name, {"error": error["error"]})
            results[analyzer.name] = error
    return results
