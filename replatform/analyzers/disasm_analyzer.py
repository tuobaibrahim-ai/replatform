"""محلل تفكيك بدون واجهة عبر Rizin (المرفق مع Cutter)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from ..core.config import load_config
from . import Analyzer, Target

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
TREE_RE = re.compile(r"[╎└─<>│├┌┐┘┬┴┼]")


def find_rizin() -> str:
    candidates = [shutil.which("rizin") or ""]
    packages = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Packages"
    if packages.exists():
        candidates += [str(p) for p in packages.glob("Rizin*/**/rizin.exe")]
    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(env)
        if root:
            candidates += [
                str(Path(root) / "Cutter" / "rizin.exe"),
                str(Path(root) / "rizin" / "bin" / "rizin.exe"),
            ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return ""


def available() -> bool:
    return bool(find_rizin())


def _clean(line: str) -> str:
    return TREE_RE.sub(" ", ANSI_RE.sub("", line)).strip()


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def quick(path: str, timeout: int = 180, deep: bool = True) -> dict:
    binary = find_rizin()
    if not binary:
        return {"available": False, "error": "rizin غير متوفر"}

    base = [binary, "-q", "-e", "scr.color=0", "-e", "anal.timeout=90"]
    analysis = "aa; aac" if deep else "aa"
    info = _run([*base, "-c", f"iI~arch; iI~bits; {analysis}; aflj", path], timeout)
    if info is None:
        return {"available": True, "error": "انتهت مهلة التحليل", "function_count": 0}

    lines = info.stdout.splitlines()
    arch = bits = ""
    json_start = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("arch"):
            arch = stripped.split(maxsplit=1)[-1]
        elif stripped.startswith("bits"):
            bits = stripped.split(maxsplit=1)[-1]
        elif stripped.startswith("[") and json_start is None:
            json_start = index
    functions: list[dict] = []
    if json_start is not None:
        try:
            payload = json.loads("\n".join(lines[json_start:]))
            functions = [
                {
                    "name": item.get("name", ""),
                    "offset": f"0x{int(item.get('offset', 0)):X}",
                    "size": item.get("size", 0),
                }
                for item in payload
                if isinstance(item, dict)
            ]
        except (json.JSONDecodeError, ValueError):
            functions = []
    functions.sort(key=lambda f: f["size"], reverse=True)

    entry = _run([*base, "-c", "s entry0; pd 40", path], timeout)
    entry_lines: list[str] = []
    if entry is not None:
        for line in entry.stdout.splitlines():
            cleaned = _clean(line)
            if "0x" in cleaned:
                entry_lines.append(re.sub(r"\s+", " ", cleaned))

    return {
        "available": True,
        "arch": arch,
        "bits": bits,
        "function_count": len(functions),
        "top_functions": functions[:15],
        "entry_disasm": entry_lines[:40],
        "rizin": binary,
    }


class DisasmAnalyzer(Analyzer):
    name = "disasm"
    description = "تفكيك بدون واجهة (Rizin): الدوال، نقطة الدخول، أهم الدوال"

    def can_handle(self, target: Target) -> bool:
        cfg = load_config()["analysis"]
        if not cfg.get("disasm", True):
            return False
        if target.kind not in ("PE", "ELF"):
            return False
        limit = int(cfg.get("disasm_max_mb", 200)) * 1024 * 1024
        return target.size <= limit and available()

    def run(self, target: Target, ws) -> dict:  # noqa: ARG002
        deep = bool(load_config()["analysis"].get("disasm_deep", True))
        result = quick(str(target.path), deep=deep)
        result["score"] = 0
        result["verdict"] = "info"
        result["findings"] = []
        if result.get("function_count"):
            result["findings"] = [f"عدد الدوال المكتشفة: {result['function_count']}"]
        return result
