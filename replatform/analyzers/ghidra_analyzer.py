"""محلل Ghidra headless (اختياري — يُشغَّل عند الطلب فقط)."""

from __future__ import annotations

from ..core.config import load_config
from ..tools import ghidra_tools
from . import Analyzer, Target


class GhidraAnalyzer(Analyzer):
    name = "ghidra"
    description = "تفكيك متقدم (Ghidra headless): الدوال وتفكيك نقطة الدخول"
    optional = True

    def can_handle(self, target: Target) -> bool:
        cfg = load_config()["analysis"]
        if target.kind not in ("PE", "ELF"):
            return False
        limit = int(cfg.get("ghidra_max_mb", 150)) * 1024 * 1024
        return target.size <= limit and ghidra_tools.available()

    def run(self, target: Target, ws) -> dict:  # noqa: ARG002
        cfg = load_config()["analysis"]
        result = ghidra_tools.analyze(
            str(target.path),
            decompile=bool(cfg.get("ghidra_decompile", True)),
            decompile_limit=int(cfg.get("ghidra_decompile_limit", 6)),
        )
        result["score"] = 0
        result["verdict"] = "info"
        findings: list[str] = []
        if result.get("error"):
            findings.append(f"Ghidra: {result['error']}")
        elif result.get("function_count"):
            findings.append(f"Ghidra: {result['function_count']} دالة")
        result["findings"] = findings
        return result
