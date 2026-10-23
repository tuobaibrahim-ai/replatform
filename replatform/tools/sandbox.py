"""عزل ديناميكي اختياري عبر Windows Sandbox — لا يشغّل العينة على المضيف أبداً."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from ..core import util
from ..core.config import ROOT

SANDBOX_DIR = ROOT / "sandbox"
MAX_SAMPLE_BYTES = 512 * 1024 * 1024
MAX_WAIT_SECONDS = 3600
WATCHDOG_GRACE_SECONDS = 60


def _terminate_process_tree(pid: int, timeout: float = 10.0) -> bool:
    """يُنهي شجرة عملية Sandbox بعد انتهاء المهلة (Windows أولاً)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            proc = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=max(2.0, float(timeout)),
            )
            return proc.returncode == 0
        os.kill(pid, signal.SIGTERM)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def find_sandbox() -> str:
    override = os.environ.get("RE_WINDOWS_SANDBOX", "").strip()
    if override and Path(override).is_file():
        return override
    candidates = [
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "WindowsSandbox.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WindowsApps" / "WindowsSandbox.exe",
    ]
    found = shutil.which("WindowsSandbox.exe")
    if found:
        candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return ""


def available() -> bool:
    return bool(find_sandbox())


def _logon_command(sample_name: str, timeout: int) -> str:
    # كل الأوامر داخل الصندوق؛ الناتج يُكتب في مجلد قابل للكتابة فقط.
    quoted = f"C:\\RE_SAMPLE\\{sample_name}"
    return (
        "cmd.exe /c "
        f"\"{quoted} > C:\\RE_OUT\\stdout.txt 2>&1 "
        f"& timeout /t {timeout} /nobreak > C:\\RE_OUT\\timeout.txt "
        f"& shutdown /s /t 0\""
    )


def build_plan(
    target: str | Path,
    out: str | Path | None = None,
    timeout: int = 120,
    network: bool = False,
) -> dict:
    """ينشئ ملف .wsb ومجلدات معزولة. لا ينفّذ شيئاً."""
    source = Path(target).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"العينة غير موجودة: {source}")
    size = source.stat().st_size
    if size > MAX_SAMPLE_BYTES:
        raise ValueError("العينة أكبر من حد Sandbox (512MB)")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in source.stem)[:40]
    plan_dir = Path(out).resolve() if out else SANDBOX_DIR / f"{stamp}-{stem}"
    samples = plan_dir / "sample"
    output = plan_dir / "output"
    samples.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)

    # اسم ثابت آمن داخل الصندوق يمنع حقن أوامر عبر اسم ملف غريب.
    safe_name = f"sample{source.suffix.lower()}" if source.suffix else "sample.bin"
    copied = samples / safe_name
    shutil.copy2(source, copied)
    digest = util.sha256_file(copied)

    wsb = plan_dir / "sandbox.wsb"
    networking = "Enable" if network else "Disable"
    command = escape(_logon_command(safe_name, max(5, min(int(timeout), 3600))))
    wsb_text = f"""<Configuration>
  <Networking>{networking}</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{escape(str(samples))}</HostFolder>
      <SandboxFolder>C:\\RE_SAMPLE</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{escape(str(output))}</HostFolder>
      <SandboxFolder>C:\\RE_OUT</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>{command}</Command>
  </LogonCommand>
</Configuration>
"""
    wsb.write_text(wsb_text, "utf-8")
    payload = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "target": str(source),
        "sample": str(copied),
        "sha256": digest,
        "size": size,
        "kind": util.file_kind(source),
        "runnable": source.suffix.lower() in (".exe", ".scr", ".com"),
        "wsb": str(wsb),
        "output_dir": str(output),
        "network": bool(network),
        "timeout": int(timeout),
        "sandbox_available": available(),
        "executed": False,
    }
    (plan_dir / "plan.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), "utf-8"
    )
    (plan_dir / "README.txt").write_text(
        "REPLATFORM — خطة عزل Windows Sandbox\n"
        "تحذير: فتح ملف sandbox.wsb يشغّل LogonCommand تلقائياً (أي العينة).\n"
        "1) راجع plan.json و sandbox.wsb قبل أي فتح.\n"
        "2) للتشغيل الصريح: repl.py sandbox ... --run --yes\n"
        "3) الشبكة معطلة افتراضياً، ومجلد العينة للقراءة فقط.\n"
        "4) النتائج في output/stdout.txt بعد إغلاق الصندوق.\n",
        "utf-8",
    )
    return payload


def run_plan(plan: dict, confirmed: bool = False, wait: bool = True) -> dict:
    """يشغّل Sandbox فقط بعد تأكيد صريح، وعلى عينة PE."""
    if not confirmed:
        raise ValueError("التشغيل يتطلب --run --yes (تأكيد صريح).")
    if plan.get("kind") != "PE" or not plan.get("runnable"):
        raise ValueError("التشغيل الديناميكي يدعم ملفات PE القابلة للتنفيذ فقط (.exe/.scr/.com).")
    exe = find_sandbox()
    if not exe:
        raise RuntimeError(
            "Windows Sandbox غير مثبت. فعّل الميزة من Windows Features أو استخدم VM خارجية."
        )
    wsb = Path(plan["wsb"]).resolve()
    if not wsb.is_file():
        raise FileNotFoundError(wsb)
    if wsb.suffix.lower() != ".wsb" or wsb.stat().st_size > 1024 * 1024:
        raise ValueError("ملف Sandbox غير صالح أو أكبر من الحد الآمن.")
    proc = subprocess.Popen([exe, str(wsb)])
    result = {
        **plan,
        "executed": True,
        "sandbox_exe": exe,
        "pid": proc.pid,
        "watchdog": bool(wait),
        "watchdog_triggered": False,
    }
    if wait:
        try:
            requested = max(30, int(plan.get("timeout", 120)) + WATCHDOG_GRACE_SECONDS)
        except (TypeError, ValueError):
            requested = 180
        wait_seconds = min(requested, MAX_WAIT_SECONDS)
        result["wait_seconds"] = wait_seconds
        try:
            proc.wait(timeout=wait_seconds)
        except subprocess.TimeoutExpired:
            terminated = _terminate_process_tree(proc.pid)
            result["watchdog_triggered"] = True
            result["terminated"] = terminated
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                result["terminated"] = False
            result["error"] = (
                "انتهت مهلة انتظار Sandbox؛ أُرسل أمر إنهاء شجرة العملية"
                + ("" if terminated else " لكن تعذّر التأكد من الإنهاء")
                + ". راجع output/ وأغلق أي نافذة متبقية يدوياً."
            )
        result["returncode"] = proc.returncode
    return result
