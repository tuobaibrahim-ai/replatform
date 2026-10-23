"""محرك YARA عبر CLI الرسمي (yara64.exe)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from ..core.config import ROOT, TOOLS_DIR

RULES_DIR = ROOT / "rules"
_MATCH_LINE = re.compile(r"^0x([0-9a-fA-F]+):(\$[^\s:]+):\s?(.*)$")


def find_binary() -> str:
    candidates = [
        TOOLS_DIR / "yara" / "yara64.exe",
        TOOLS_DIR / "yara" / "yara.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return shutil.which("yara64") or shutil.which("yara") or ""


def available() -> bool:
    return bool(find_binary() and RULES_DIR.exists())


def rule_files(rules_dir: Path | None = None) -> list[str]:
    base = Path(rules_dir or RULES_DIR)
    if not base.exists():
        return []
    return [str(p) for p in sorted(base.glob("*.yar"))]


def scan(path: str, rules_dir: Path | None = None, timeout: int = 180) -> dict:
    """يفحص ملفاً بقواعد YARA. يعيد نتائج منظمة."""
    binary = find_binary()
    if not binary:
        return {"available": False, "error": "YARA غير مثبت في tools/yara", "matches": []}
    rules = rule_files(rules_dir)
    if not rules:
        return {"available": False, "error": "لا توجد قواعد في rules/", "matches": []}
    try:
        proc = subprocess.run(
            [binary, "-s", "-w", *rules, str(path)],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": True, "error": f"{type(exc).__name__}: {exc}", "matches": []}

    if proc.returncode not in (0, 1):  # 1 = لا تطابقات عند بعض النسخ
        return {
            "available": True,
            "error": (proc.stderr or proc.stdout or "").strip()[:800],
            "matches": [],
        }

    matches: list[dict] = []
    current: dict | None = None
    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        hit = _MATCH_LINE.match(line)
        if hit:
            if current is None:
                continue
            current["strings"].append({
                "offset": int(hit.group(1), 16),
                "id": hit.group(2),
                "data": hit.group(3)[:120],
            })
            continue
        if line.startswith("error") or line.startswith("warning"):
            continue
        current = {"rule": line.split()[0], "strings": []}
        matches.append(current)

    return {
        "available": True,
        "rules_file_count": len(rules),
        "matches": matches,
        "count": len(matches),
        "stderr": (proc.stderr or "").strip()[:500],
    }
