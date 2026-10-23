"""محلل YARA: يطابق الملف مع قواعد rules/*.yar."""

from __future__ import annotations

from ..core.config import load_config
from ..tools import yara_engine
from . import Analyzer, Target

HIGH_MARKERS = ("ransom", "credential", "suspicious", "meterpreter", "cobalt", "keylog")


class YARAAnalyzer(Analyzer):
    name = "yara"
    description = "محرك قواعد YARA (حزم، مؤشرات، سلوك مشبوه)"

    def can_handle(self, target: Target) -> bool:  # noqa: ARG002
        return bool(load_config()["analysis"].get("yara", True)) and yara_engine.available()

    def run(self, target: Target, ws) -> dict:  # noqa: ARG002
        cfg = load_config()["analysis"]
        try:
            max_mb = int(cfg.get("yara_max_mb", 512))
            timeout = int(cfg.get("yara_timeout", 180))
        except (TypeError, ValueError):
            max_mb, timeout = 512, 180
        if target.size > max_mb * 1024 * 1024:
            return {
                "skipped": True,
                "reason": f"الملف أكبر من حد YARA ({max_mb} MB)",
                "matches": [],
                "score": 0,
                "verdict": "info",
                "findings": [],
            }
        result = yara_engine.scan(str(target.path), timeout=max(10, min(timeout, 600)))
        if not result.get("available"):
            return {
                "skipped": True,
                "reason": result.get("error", "غير متاح"),
                "matches": [],
                "score": 0,
                "verdict": "info",
                "findings": [],
            }

        matches = result.get("matches") or []
        score = 0
        findings: list[str] = []
        for match in matches:
            name = match.get("rule", "")
            weight = 2 if any(marker in name.lower() for marker in HIGH_MARKERS) else 1
            score += weight
            count = len(match.get("strings") or [])
            findings.append(f"قاعدة YARA: {name} ({count} تطابق نصي)")
        score = min(score, 6)
        verdict = "critical" if score >= 5 else ("warn" if score >= 2 else "info")
        return {
            "available": True,
            "rules_file_count": result.get("rules_file_count", 0),
            "matches": matches,
            "count": len(matches),
            "score": score,
            "verdict": verdict,
            "findings": findings,
            "stderr": result.get("stderr", ""),
        }
