"""تصدير التقارير: HTML → PDF عبر متصفح مثبّت (بدون مكتبات خارجية)."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def find_browser() -> str:
    """يبحث عن Edge/Chrome. يمكن تثبيت المسار عبر RE_BROWSER."""
    override = os.environ.get("RE_BROWSER", "").strip()
    if override and Path(override).is_file():
        return override

    candidates: list[Path] = []
    for env in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        root = os.environ.get(env)
        if not root:
            continue
        candidates += [
            Path(root) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            Path(root) / "Google" / "Chrome" / "Application" / "chrome.exe",
        ]
    for name in ("msedge", "chrome", "chrome.exe", "msedge.exe"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return ""


def html_to_pdf(
    html_path: str | Path,
    pdf_path: str | Path | None = None,
    timeout: int = 120,
) -> Path:
    """يحوّل تقرير HTML محلياً إلى PDF. يرفض العمل إن لم يوجد متصفح."""
    source = Path(html_path).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"ملف HTML غير موجود: {source}")
    target = Path(pdf_path).resolve() if pdf_path else source.with_suffix(".pdf")
    target.parent.mkdir(parents=True, exist_ok=True)
    browser = find_browser()
    if not browser:
        raise RuntimeError(
            "لا يوجد Edge/Chrome لتصدير PDF. ثبّت أحدهما أو اضبط RE_BROWSER."
        )

    profile = Path(tempfile.mkdtemp(prefix="re_pdf_profile_"))
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{target.stem}.", suffix=".pdf", dir=target.parent
    )
    os.close(fd)
    temporary = Path(temp_name)
    temporary.unlink(missing_ok=True)
    args = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-component-update",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-pdf-header-footer",
        "--print-to-pdf-no-header",
        "--run-all-compositor-stages-before-draw",
        "--virtual-time-budget=2500",
        f"--user-data-dir={profile}",
        f"--print-to-pdf={temporary}",
        source.as_uri(),
    ]
    try:
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"انتهت مهلة تصدير PDF ({timeout}ث)") from exc
        except OSError as exc:
            raise RuntimeError(f"تعذر تشغيل المتصفح: {exc}") from exc

        if not temporary.is_file() or temporary.stat().st_size < 512:
            detail = ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()[-600:]
            raise RuntimeError(f"لم يُنتج المتصفح ملف PDF صالحاً. {detail}")
        with open(temporary, "rb") as handle:
            if handle.read(5) != b"%PDF-":
                raise RuntimeError("الناتج ليس ملف PDF صالحاً")
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    return target
