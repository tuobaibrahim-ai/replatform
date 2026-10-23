"""سجل الأدوات الخارجية والقدرات المتاحة."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .config import TOOLS_DIR
from .util import run_version

_WINGET = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet"
_EXTRA_DIRS = [
    _WINGET / "Links",
    _WINGET / "Packages",
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
]


def _resolve(executable: str) -> str:
    """يبحث عن تنفيذي في PATH ثم مواقع Winget المعروفة."""
    found = shutil.which(executable)
    if found:
        return found
    direct = Path(executable)
    if direct.exists():
        return str(direct)
    stem = direct.name.lower()
    names = [stem] if stem.endswith(".exe") else [stem, f"{stem}.exe"]
    for base in _EXTRA_DIRS:
        if not base.exists():
            continue
        for name in names:
            if base.name == "Packages":
                for item in base.iterdir():
                    candidate = item / name
                    if candidate.exists():
                        return str(candidate)
                    for sub in item.rglob(name):
                        return str(sub)
            else:
                candidate = base / name
                if candidate.exists():
                    return str(candidate)
                for sub in base.glob(f"*/{name}"):
                    return str(sub)
    return ""


def _seven_zip() -> str:
    return _resolve("7z.exe")


def detect_tools() -> list[dict]:
    """يفحص توفر الأدوات ويعيد إصداراتها."""
    from ..tools.ghidra_tools import find_headless, find_java_home
    from ..tools.yara_engine import find_binary

    jadx = TOOLS_DIR / "jadx-cli" / "bin" / "jadx.bat"
    apktool = TOOLS_DIR / "apktool.jar"
    yara_bin = find_binary()
    headless = find_headless()
    jdk_home = find_java_home()
    checks = [
        ("Java", ["java", "-version"]),
        ("JDK (Ghidra)", [str(Path(jdk_home) / "bin" / "javac.exe"), "-version"] if jdk_home else []),
        ("apktool", ["java", "-jar", str(apktool), "--version"] if apktool.exists() else []),
        ("jadx", [str(jadx), "--version"] if jadx.exists() else []),
        ("Detect It Easy", ["diec", "--version"]),
        ("ADB", ["adb", "version"]),
        ("7-Zip", [seven] if (seven := _seven_zip()) else []),
        ("Cutter", ["cutter"]),
        ("YARA", [yara_bin] if yara_bin else []),
        ("Ghidra", [headless] if headless else []),
        ("Python", [sys.executable, "--version"]),
    ]
    result = []
    for name, cmd in checks:
        if not cmd:
            result.append({"name": name, "ok": False, "version": "", "path": ""})
            continue
        resolved = _resolve(cmd[0])
        if not resolved:
            result.append({"name": name, "ok": False, "version": "", "path": ""})
            continue
        no_run = {"Cutter", "YARA", "Ghidra"}
        version = "(مثبت)" if name in no_run else run_version([resolved, *cmd[1:]], timeout=25)
        result.append({"name": name, "ok": True, "version": version, "path": resolved})
    return result


def tool_matrix() -> dict[str, bool]:
    """خريطة سريعة: هل الأداة متاحة؟"""
    return {item["name"]: item["ok"] for item in detect_tools()}
