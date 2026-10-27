"""ترقية آمنة من حزمة محمولة، مع نسخة تراجع كاملة.

الترقية لا تلمس بيانات المستخدم: `config.json` و`workspaces/` و`plugins/`
و`license.json` و`audit.jsonl` تُنقل إلى النسخة الجديدة قبل التبديل. أي فشل
يعيد الحالة السابقة.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
import zipfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path, PurePosixPath

from .. import __version__
from ..core import stdio
from ..core.util import sha256_file


class UpgradeError(RuntimeError):
    """فشل تحقق أو تثبيت حزمة الترقية."""


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


@contextlib.contextmanager
def _safe_cwd(directory: Path) -> Iterator[None]:
    """ينتقل مؤقتاً خارج `directory` قبل إعادة تسميته.

    على Windows يمنع النظام إعادة تسمية مجلد هو مجلد العمل الحالي للعملية
    (`WinError 32`). هذا يحدث في التدفق الموثّق عندما يشغّل المستخدم الترقية من
    داخل مجلد التثبيت. ننتقل إلى مجلد مؤقت ثم نعيد مجلد العمل الأصلي.
    """
    original = Path.cwd()
    try:
        inside = original.resolve().is_relative_to(directory.resolve())
    except (OSError, ValueError):
        inside = False
    if not inside:
        yield
        return
    os.chdir(tempfile.gettempdir())
    try:
        yield
    finally:
        try:
            os.chdir(original)
        except OSError:
            os.chdir(tempfile.gettempdir())


def verify_bundle(bundle: str | Path, expected_sha256: str = "") -> dict:
    """يتحقق من البصمة وبنية ZIP قبل أي استخراج."""
    path = Path(bundle)
    if not path.is_file():
        raise UpgradeError(f"الحزمة غير موجودة: {path}")
    digest = sha256_file(path)
    if expected_sha256 and digest.lower() != expected_sha256.strip().lower():
        raise UpgradeError(
            f"بصمة الحزمة لا تطابق المتوقع.\nمتوقع: {expected_sha256}\nفعلي: {digest}"
        )
    with zipfile.ZipFile(path) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        if not names:
            raise UpgradeError("الحزمة فارغة")
        roots = {PurePosixPath(name).parts[0] for name in names}
        if len(roots) != 1:
            raise UpgradeError(f"حزمة غير متوقعة: عدة جذور {sorted(roots)[:3]}")
        root = roots.pop()
        for name in names:
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts:
                raise UpgradeError(f"مسار غير آمن داخل الحزمة: {name}")
        required = {"repl.py", "replatform/__init__.py"}
        missing = [item for item in required if f"{root}/{item}" not in names]
        if missing:
            raise UpgradeError(f"حزمة ناقصة: {', '.join(missing)}")
        version = root.rsplit("-", 1)[-1] if "-" in root else ""
    return {"ok": True, "sha256": digest, "root": root, "version": version,
            "files": len(names)}


def _extract(archive: zipfile.ZipFile, staging: Path, root: str) -> int:
    count = 0
    for info in archive.infolist():
        if info.is_dir():
            continue
        pure = PurePosixPath(info.filename)
        relative = Path(*pure.parts[1:])
        destination = (staging / relative).resolve()
        if staging.resolve() not in destination.parents and destination != staging.resolve():
            raise UpgradeError(f"مسار يخرج من الهدف: {info.filename}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as source, open(destination, "wb") as target:
            shutil.copyfileobj(source, target)
        count += 1
    return count


def install_bundle(
    bundle: str | Path,
    target: str | Path,
    expected_sha256: str = "",
    preserve: tuple[str, ...] = (
        "config.json",
        "workspaces",
        "plugins",
        "license.json",
        "audit.jsonl",
        "audit.jsonl.lock",
        "audit-export.json",
    ),
    dry_run: bool = False,
) -> dict:
    """يثبّت الحزمة في `target` مع الاحتفاظ بالبيانات ونسخة تراجع."""
    destination = Path(target).resolve()
    info = verify_bundle(bundle, expected_sha256)
    stamp = _stamp()
    staging = destination.parent / f".{destination.name}.staging-{stamp}"
    backup = destination.parent / f"{destination.name}.backup-{stamp}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    preserved: list[str] = []
    try:
        with zipfile.ZipFile(bundle) as archive:
            files = _extract(archive, staging, info["root"])
        for name in preserve:
            source = destination / name
            if not source.exists():
                continue
            staged = staging / name
            if staged.exists():
                continue
            if source.is_dir():
                shutil.copytree(source, staged)
            else:
                shutil.copy2(source, staged)
            preserved.append(name)
        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "version": info["version"],
                "sha256": info["sha256"],
                "files": files,
                "preserved": preserved,
                "target": str(destination),
            }
        moved_old = False
        with _safe_cwd(destination):
            if destination.exists():
                os.replace(destination, backup)
                moved_old = True
            try:
                os.replace(staging, destination)
            except OSError:
                if moved_old:
                    os.replace(backup, destination)
                raise
        return {
            "ok": True,
            "dry_run": False,
            "from_version": __version__,
            "version": info["version"],
            "sha256": info["sha256"],
            "files": files,
            "preserved": preserved,
            "backup": str(backup) if moved_old else None,
            "target": str(destination),
        }
    except OSError as exc:
        raise UpgradeError(
            f"تعذّر استبدال المجلد (قد يكون قيد الاستخدام): {exc}. "
            "أغلق كل طرفيات REPLATFORM ثم أعد المحاولة."
        ) from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def rollback(backup: str | Path, target: str | Path) -> dict:
    """يعيد النسخة السابقة مكان التثبيت الحالي."""
    source = Path(backup).resolve()
    destination = Path(target).resolve()
    if not source.is_dir():
        raise UpgradeError(f"نسخة التراجع غير موجودة: {source}")
    failed = destination.parent / f"{destination.name}.failed-{_stamp()}"
    with _safe_cwd(destination):
        if destination.exists():
            os.replace(destination, failed)
        try:
            os.replace(source, destination)
        except OSError:
            if failed.exists():
                os.replace(failed, destination)
            raise
    return {"ok": True, "restored": str(destination), "failed_copy": str(failed)}


def _main(argv: list[str] | None = None) -> int:
    import argparse

    stdio.configure()
    parser = argparse.ArgumentParser(prog="upgrade", description="ترقية REPLATFORM من حزمة")
    parser.add_argument("bundle", help="ملف ZIP المحمول")
    parser.add_argument("--target", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--sha256", default="", help="البصمة المتوقعة")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = install_bundle(args.bundle, args.target, args.sha256, dry_run=args.dry_run)
    except UpgradeError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
