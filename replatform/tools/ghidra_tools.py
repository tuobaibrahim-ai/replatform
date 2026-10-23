"""تكامل Ghidra headless — تفكيك متقدم وتصدير الدوال."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core.config import ROOT, TOOLS_DIR

SCRIPT_DIR = ROOT / "scripts" / "ghidra"
SAFE_NAME = re.compile(r"^[A-Za-z0-9_$@.?:]+$")


def find_headless() -> str:
    candidates = [
        shutil.which("analyzeHeadless") or "",
        shutil.which("analyzeHeadless.bat") or "",
    ]
    bases = [
        TOOLS_DIR / "ghidra",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs",
        Path(os.environ.get("USERPROFILE", "")) / "ghidra",
    ]
    for base in bases:
        if not base or not Path(base).exists():
            continue
        direct = list(Path(base).glob("*/support/analyzeHeadless.bat"))
        nested = list(Path(base).glob("ghidra*/support/analyzeHeadless.bat"))
        candidates += [str(p) for p in direct + nested]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return ""


def find_java_home() -> str:
    """يبحث عن JDK (وليس JRE) — Ghidra يحتاج javac لتجميع السكربتات."""
    candidates: list[Path] = []
    env_home = os.environ.get("JAVA_HOME", "").strip()
    if env_home:
        candidates.append(Path(env_home))
    candidates += [p for p in sorted(TOOLS_DIR.glob("jdk*")) if p.is_dir()]
    candidates += [p for p in sorted(TOOLS_DIR.glob("jdk*/*")) if p.is_dir()]
    for env in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        root = os.environ.get(env)
        if not root:
            continue
        for pattern in ("Eclipse Adoptium/jdk-*", "Java/jdk-*", "Microsoft/jdk-*",
                        "Zulu/zulu-*", "Programs/Eclipse Adoptium/jdk-*"):
            candidates += [p for p in Path(root).glob(pattern) if p.is_dir()]
    for candidate in candidates:
        if (candidate / "bin" / "javac.exe").exists():
            return str(candidate)
    return ""


def available() -> bool:
    return bool(find_headless())


def _wrap(executable: str, arguments: list[str]) -> list[str]:
    if executable.lower().endswith((".bat", ".cmd")):
        # cmd /c يفسّر & | > داخل الوسائط؛ list2cmdline يضعها بين علامات اقتباس.
        command = subprocess.list2cmdline([executable, *arguments])
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", command]
    return [executable, *arguments]


def analyze(
    path: str,
    timeout: int = 900,
    decompile: bool = True,
    decompile_limit: int = 6,
    renames: dict[str, str] | None = None,
) -> dict:
    headless = find_headless()
    if not headless:
        return {"available": False, "error": "Ghidra غير مثبت (لم يُعثر على analyzeHeadless)"}
    if not SCRIPT_DIR.exists():
        return {"available": True, "error": f"سكربت Ghidra مفقود: {SCRIPT_DIR}"}

    decompile_limit = max(0, min(int(decompile_limit), 50))
    rename_pairs: list[str] = []
    for old, new in (renames or {}).items():
        old, new = str(old).strip(), str(new).strip()
        if not old or not new:
            continue
        if not SAFE_NAME.fullmatch(old) or not SAFE_NAME.fullmatch(new):
            raise ValueError(f"اسم دالة غير صالح في إعادة التسمية: {old}={new}")
        rename_pairs.append(f"{old}~{new}")

    project_dir = Path(tempfile.mkdtemp(prefix="re_ghidra_proj_"))
    out_dir = Path(tempfile.mkdtemp(prefix="re_ghidra_out_"))
    out_json = out_dir / "functions.json"
    args = [
        str(project_dir), "re_project",
        "-import", str(path),
        "-scriptPath", str(SCRIPT_DIR),
        "-postScript", "ExportFunctions.java", str(out_json),
        "decompile" if decompile else "no",
        str(decompile_limit),
    ]
    if rename_pairs:
        args.append(",".join(rename_pairs))
    args += ["-deleteProject", "-analysisTimeoutPerFile", "300"]
    cmd = _wrap(headless, args)
    env = os.environ.copy()
    java_home = find_java_home()
    if java_home:
        env["JAVA_HOME"] = java_home
        env["PATH"] = str(Path(java_home) / "bin") + os.pathsep + env.get("PATH", "")
    try:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace", cwd=str(ROOT), env=env,
            )
        except subprocess.TimeoutExpired:
            return {"available": True, "error": f"انتهت مهلة تحليل Ghidra ({timeout}ث)"}
        except OSError as exc:
            return {"available": True, "error": f"{type(exc).__name__}: {exc}"}

        if not out_json.exists():
            tail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-1200:]
            return {
                "available": True,
                "error": f"لم يُنتج Ghidra ملف النتائج (رمز {proc.returncode})",
                "log": tail,
            }
        try:
            data = json.loads(out_json.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"available": True, "error": f"تعذر قراءة نتائج Ghidra: {exc}"}
    finally:
        shutil.rmtree(project_dir, ignore_errors=True)
        shutil.rmtree(out_dir, ignore_errors=True)

    functions = data.get("functions") or []
    functions.sort(key=lambda f: f.get("size", 0), reverse=True)
    data["top_functions"] = functions[:15]
    data["function_count"] = data.get("function_count", len(functions))
    data["available"] = True
    data["engine"] = headless
    return data
