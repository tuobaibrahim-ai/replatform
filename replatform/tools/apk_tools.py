"""أدوات APK: فك، بناء، توقيع، كود Java، تثبيت."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

from ..core.config import TOOLS_DIR, load_config
from ..core.registry import _resolve


def _tail(text: str, lines: int = 12) -> str:
    rows = [ln.rstrip() for ln in (text or "").splitlines() if ln.strip()]
    return "\n".join(rows[-lines:])


def _run(cmd: list[str], timeout: int) -> dict:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "command": cmd}
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "command": cmd,
        "stdout": _tail(proc.stdout),
        "stderr": _tail(proc.stderr),
    }


def _apktool_cmd() -> list[str]:
    jar = TOOLS_DIR / "apktool.jar"
    if not jar.exists():
        raise FileNotFoundError(f"apktool.jar غير موجود: {jar}")
    return [str(_resolve("java") or "java"), "-jar", str(jar)]


def _require_apk(path: Path) -> None:
    if not path.is_file() or path.suffix.lower() != ".apk":
        raise ValueError(f"مطلوب ملف APK: {path}")
    from ..analyzers.apk_analyzer import validate_apk

    validate_apk(path)


def decode(
    apk: str | Path,
    out: str | Path | None = None,
    timeout: int | None = None,
    force: bool = False,
) -> dict:
    apk = Path(apk).resolve()
    _require_apk(apk)
    target = Path(out).resolve() if out else apk.with_name(f"{apk.stem}-decoded")
    if target.exists():
        if not force:
            raise FileExistsError(
                f"مجلد الناتج موجود: {target} — استخدم --force لإعادة الفك "
                "(سيُحذف المجلد الحالي بما فيه من تعديلات)."
            )
        if target.is_symlink() or not target.is_dir():
            raise ValueError(
                f"مسار الناتج ليس مجلداً عادياً: {target} — ارفض الحذف الآمن."
            )
        if target == apk.parent or apk.is_relative_to(target):
            raise ValueError("مسار الناتج يحتوي ملف APK الأصلي — اختر مجلداً منفصلاً.")
        looks_decoded = (target / "apktool.yml").exists() or (
            target / "AndroidManifest.xml"
        ).exists()
        if not looks_decoded:
            raise ValueError(
                f"المجلد الموجود لا يبدو ناتج فك apktool: {target} — "
                "احذفه يدوياً أو اختر --out مختلفاً."
            )
        shutil.rmtree(target, ignore_errors=True)
    if target.is_relative_to(apk):
        raise ValueError("مسار الناتج داخل ملف APK — غير صالح.")
    timeout = timeout or load_config()["analysis"]["apk_decode_timeout"]
    result = _run([*_apktool_cmd(), "d", "-f", str(apk), "-o", str(target)], timeout)
    result["output"] = str(target)
    result["manifest"] = (target / "AndroidManifest.xml").exists()
    if result.get("ok") and not result["manifest"]:
        result["ok"] = False
        result["error"] = "انتهى apktool دون إنتاج AndroidManifest.xml — الناتج غير مكتمل."
    return result


def build(project: str | Path, out: str | Path | None = None, timeout: int = 900) -> dict:
    project = Path(project).resolve()
    if not project.is_dir():
        raise ValueError(f"مجلد مشروع غير موجود: {project}")
    target = Path(out).resolve() if out else project.with_name(f"{project.name}-rebuilt.apk")
    result = _run([*_apktool_cmd(), "b", str(project), "-o", str(target)], timeout)
    result["output"] = str(target)
    result["built"] = target.exists()
    return result


def _verify_signed(path: Path) -> dict:
    """يتحقق من ZIP ومن وجود مخطط توقيع فعلي، لا من رسالة الموقّع فقط."""
    from ..analyzers.apk_analyzer import signing_info

    result: dict = {"zip_valid": False, "schemes": [], "ok": False}
    try:
        with zipfile.ZipFile(path) as zf:
            bad = zf.testzip()
            result["zip_valid"] = bad is None
            if bad:
                result["zip_error"] = f"مدخل تالف: {bad}"
    except (OSError, zipfile.BadZipFile) as exc:
        result["zip_error"] = f"{type(exc).__name__}: {exc}"
    info = signing_info(str(path))
    result["schemes"] = info.get("schemes") or []
    result["signing"] = info
    if info.get("error"):
        result["signing_error"] = info["error"]
    result["ok"] = bool(result["zip_valid"] and result["schemes"])
    return result


def sign(apk: str | Path, out_dir: str | Path | None = None, timeout: int = 600) -> dict:
    apk = Path(apk).resolve()
    _require_apk(apk)
    jar = TOOLS_DIR / "uber-apk-signer.jar"
    if not jar.exists():
        raise FileNotFoundError(f"uber-apk-signer.jar غير موجود: {jar}")
    target_dir = Path(out_dir).resolve() if out_dir else apk.parent / "signed"
    if target_dir.exists():
        if target_dir.is_symlink() or not target_dir.is_dir():
            raise ValueError(f"مسار الإخراج ليس مجلداً عادياً: {target_dir}")
    else:
        target_dir.mkdir(parents=True, exist_ok=True)

    # نوقّع داخل مجلد مؤقت معزول حتى لا نلتقط ملفاً قديماً في مجلد الإخراج.
    temp_dir = Path(tempfile.mkdtemp(prefix=".re-sign-", dir=target_dir))
    try:
        result = _run([str(_resolve("java") or "java"), "-jar", str(jar),
                       "--apks", str(apk), "--out", str(temp_dir)], timeout)
        candidates = [
            path for path in temp_dir.rglob("*.apk")
            if path.is_file() and path.stat().st_size > 0
        ]
        if not candidates:
            log = f"{result.get('stdout', '')}\n{result.get('stderr', '')}".lower()
            result["signed"] = False
            result["verified"] = False
            if "already signed" in log:
                result["error"] = (
                    "APK موقّع مسبقاً — أعد البناء أولاً للحصول على نسخة غير موقّعة."
                )
            elif result.get("ok"):
                result["ok"] = False
                result["error"] = "انتهى الموقّع دون إنتاج ملف APK جديد"
            return result

        produced = max(candidates, key=lambda path: path.stat().st_mtime)
        final = target_dir / produced.name
        if final.resolve() == apk:
            final = target_dir / f"{apk.stem}-signed{apk.suffix}"
        if final.exists():
            stamp = time.strftime("%Y%m%d-%H%M%S")
            final = target_dir / f"{final.stem}-{stamp}{final.suffix}"
        shutil.move(str(produced), str(final))

        verification = _verify_signed(final)
        result["output"] = str(final)
        result["signed"] = True
        result["verified"] = verification["ok"]
        result["schemes"] = verification["schemes"]
        result["zip_valid"] = verification["zip_valid"]
        result["verification"] = verification
        if not verification["ok"]:
            result["ok"] = False
            result["error"] = (
                "أُنتج ملف لكن التحقق فشل: "
                + (verification.get("zip_error") or "لا يوجد مخطط توقيع معروف.")
            )
        return result
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def java_src(apk: str | Path, out: str | Path | None = None, timeout: int = 1800) -> dict:
    apk = Path(apk).resolve()
    _require_apk(apk)
    jadx = TOOLS_DIR / "jadx-cli" / "bin" / "jadx.bat"
    if not jadx.exists():
        raise FileNotFoundError(f"jadx CLI غير موجود: {jadx}")
    target = Path(out).resolve() if out else apk.with_name(f"{apk.stem}-java")
    result = _run([str(jadx), "-d", str(target), "--no-res", str(apk)], timeout)
    files = sum(1 for _ in target.rglob("*.java")) if target.exists() else 0
    result["output"] = str(target)
    result["java_files"] = files
    # jadx يُرجع رمز خطأ عند وجود أخطاء فك جزئية — نعتبره ناجحاً إن أُنتج كود
    result["ok"] = bool(files) or result.get("ok", False)
    match = re.search(
        r"finished with errors,\s*count:\s*(\d+)",
        f"{result.get('stdout', '')}\n{result.get('stderr', '')}",
    )
    if match:
        result["error_count"] = int(match.group(1))
    return result


def devices(timeout: int = 30) -> dict:
    adb = _resolve("adb")
    if not adb:
        return {"ok": False, "error": "adb غير متاح"}
    result = _run([adb, "devices"], timeout)
    result["output"] = result.get("stdout", "")
    return result


def install(apk: str | Path, timeout: int = 300) -> dict:
    apk = Path(apk).resolve()
    _require_apk(apk)
    adb = _resolve("adb")
    if not adb:
        return {"ok": False, "error": "adb غير متاح"}
    result = _run([adb, "install", "-r", str(apk)], timeout)
    result["output"] = str(apk)
    return result
