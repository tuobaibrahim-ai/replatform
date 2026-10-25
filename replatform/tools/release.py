"""أدوات الإصدار: SBOM (CycloneDX)، بصمات SHA-256، وحزمة محمولة.

تعمل بالمعيار فقط (بلا اعتمادات خارجية) لتكون قابلة للتشغيل في CI وأي جهاز.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import uuid
import zipfile
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

from .. import __version__

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_DEPS = ("pefile", "asn1crypto", "certifi")
CHECKSUM_NAME = "SHA256SUMS"
SBOM_NAME = "SBOM.cdx.json"

# احتياطي موثّق عند غياب بيانات الحزمة (بيئات بلا تثبيت).
_LICENSE_FALLBACK = {
    "pefile": "MIT",
    "asn1crypto": "MIT",
    "certifi": "MPL-2.0",
}


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dependency_component(name: str) -> dict:
    try:
        dist = metadata.distribution(name)
        version = dist.version
        license_text = (
            (dist.metadata.get("License-Expression") or "")
            or (dist.metadata.get("License") or "")
            or ""
        ).strip()
    except metadata.PackageNotFoundError:
        version = "not-installed"
        license_text = ""
    if not license_text or len(license_text) > 80:
        license_text = _LICENSE_FALLBACK.get(name, "unknown")
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name}@{version}",
        "licenses": [{"license": {"id": license_text}}],
    }


def build_sbom(dist_dir: str | Path, version: str | None = None) -> Path:
    """يكتب SBOM بصيغة CycloneDX 1.5 بجانب حزم الإصدار."""
    directory = Path(dist_dir)
    directory.mkdir(parents=True, exist_ok=True)
    release = version or __version__
    components = [_dependency_component(name) for name in RUNTIME_DEPS]
    components.append(
        {
            "type": "application",
            "name": "replatform",
            "version": release,
            "purl": f"pkg:pypi/replatform@{release}",
            "licenses": [{"license": {"id": "MIT"}}],
        }
    )
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'replatform-{release}')}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "component": {
                "type": "application",
                "name": "replatform",
                "version": release,
            },
            "tools": [{"name": "replatform.release", "version": release}],
        },
        "components": components,
    }
    path = directory / SBOM_NAME
    path.write_text(json.dumps(bom, ensure_ascii=False, indent=2), "utf-8")
    return path


def write_checksums(dist_dir: str | Path) -> Path:
    """يكتب SHA256SUMS لكل ملفات التوزيع (عدا ملف البصمات نفسه)."""
    directory = Path(dist_dir)
    files = sorted(
        path for path in directory.iterdir()
        if path.is_file() and path.name != CHECKSUM_NAME
    )
    if not files:
        raise FileNotFoundError(f"لا ملفات توزيع في: {directory}")
    lines = [f"{sha256_file(path)}  {path.name}" for path in files]
    target = directory / CHECKSUM_NAME
    target.write_text("\n".join(lines) + "\n", "utf-8")
    return target


def verify_checksums(dist_dir: str | Path) -> dict:
    """يتحقق من البصمات ويعيد تقريراً صريحاً (بلا استثناء عند التلف)."""
    directory = Path(dist_dir)
    manifest = directory / CHECKSUM_NAME
    if not manifest.is_file():
        return {"ok": False, "error": "ملف SHA256SUMS غير موجود", "checked": 0}
    checked = 0
    problems: list[str] = []
    for line in manifest.read_text("utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        path = directory / name
        if not path.is_file():
            problems.append(f"مفقود: {name}")
            continue
        if sha256_file(path) != digest:
            problems.append(f"بصمة مختلفة: {name}")
            continue
        checked += 1
    return {"ok": not problems, "checked": checked, "problems": problems}


_PORTABLE_FILES = (
    "repl.py",
    "replatform.cmd",
    "install.ps1",
    "README.md",
    "README.en.md",
    "LICENSE",
    "CHANGELOG.md",
    "PLATFORM.md",
    "INTEGRATIONS.md",
    "SECURITY.md",
    "SUPPORT.md",
    "COMMERCIAL.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "THIRD_PARTY_NOTICES.md",
    "CITATION.cff",
    "config.example.json",
    "requirements.txt",
    "pyproject.toml",
    "MANIFEST.in",
)
_PORTABLE_DIRS = ("replatform", "rules", "skills", "docs", "scripts", "tests")


def _iter_portable_files() -> list[Path]:
    files: list[Path] = []
    for name in _PORTABLE_FILES:
        path = ROOT / name
        if path.is_file():
            files.append(path)
    for name in _PORTABLE_DIRS:
        base = ROOT / name
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
                continue
            files.append(path)
    return files


def _portable_readme(version: str) -> str:
    return f"""REPLATFORM {version} — portable distribution
================================================

1) Install Python 3.11+ from https://www.python.org/downloads/windows/
2) Open PowerShell in this folder and run:
       powershell -ExecutionPolicy Bypass -File .\\install.ps1
3) Start the platform:
       .\\replatform.cmd version
       .\\replatform.cmd tools

External tools (apktool, jadx, Ghidra, YARA, Rizin) are NOT bundled.
See PLATFORM.md and docs/DEPLOYMENT.md for optional tool setup.

Security: never run untrusted samples on the host. Dynamic analysis is
restricted to Windows Sandbox with explicit confirmation.

License: MIT (see LICENSE). Commercial support: see COMMERCIAL.md.
"""


def build_portable(out_dir: str | Path, version: str | None = None) -> Path:
    """ينشئ حزمة ZIP محمولة قابلة للتوزيع (بلا أدوات خارجية أو عيّنات)."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    release = version or __version__
    target = directory / f"replatform-{release}-portable.zip"
    files = _iter_portable_files()
    if not files:
        raise FileNotFoundError("لا ملفات مصدر لتجميع الحزمة المحمولة")
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            relative = path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(f"replatform-{release}/{relative}")
            info.date_time = (2026, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
        info = zipfile.ZipInfo(f"replatform-{release}/PORTABLE-README.txt")
        info.date_time = (2026, 1, 1, 0, 0, 0)
        archive.writestr(info, _portable_readme(release))
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m replatform.tools.release",
        description="أدوات إصدار REPLATFORM: SBOM، بصمات، حزمة محمولة.",
    )
    parser.add_argument("--dist", default=str(ROOT / "dist"), help="مجلد التوزيع")
    parser.add_argument("--out", default=str(ROOT / "dist"), help="مجلد الإخراج")
    parser.add_argument("--version", default=__version__)
    parser.add_argument("--portable", action="store_true", help="ابنِ حزمة ZIP محمولة")
    parser.add_argument("--verify", action="store_true", help="تحقق من البصمات")
    args = parser.parse_args(argv)

    if args.portable:
        path = build_portable(args.out, args.version)
        print(f"portable: {path}")
    if args.verify:
        report = verify_checksums(args.dist)
        print(json.dumps(report, ensure_ascii=False))
        return 0 if report["ok"] else 1
    sbom = build_sbom(args.dist, args.version)
    checksums = write_checksums(args.dist)
    print(f"sbom: {sbom}")
    print(f"checksums: {checksums}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
