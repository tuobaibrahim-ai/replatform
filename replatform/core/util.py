"""أدوات مساعدة عامة."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path


def atomic_write_text(path: str | Path, text: str, encoding: str = "utf-8") -> None:
    """كتابة ذرّية: لا يترك ملفاً نصف مكتوب إذا انقطع التنفيذ."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def human_size(num: int) -> str:
    value = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def file_kind(path: str | Path) -> str:
    """PE / APK / ELF / ZIP / other"""
    try:
        with open(path, "rb") as fh:
            magic = fh.read(8)
    except OSError:
        return "other"
    if magic[:2] == b"MZ":
        return "PE"
    if magic[:4] == b"\x7fELF":
        return "ELF"
    if magic[:2] == b"PK":
        try:
            import zipfile
            with zipfile.ZipFile(path) as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    return "APK"
        except Exception:  # noqa: BLE001
            pass
        return "ZIP"
    return "other"


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def authenticode(path: str | Path) -> dict:
    """فحص توقيع Authenticode عبر PowerShell (موثوق على ويندوز)."""
    if os.name != "nt":
        return {"status": "n/a", "signer": ""}
    script = (
        f"$s = Get-AuthenticodeSignature -LiteralPath {_ps_quote(str(path))};"
        "Write-Output $s.Status;"
        "if ($s.SignerCertificate) {"
        "  Write-Output $s.SignerCertificate.Subject;"
        "  Write-Output $s.SignerCertificate.Thumbprint;"
        "  Write-Output $s.SignerCertificate.Issuer;"
        "  Write-Output ($s.SignerCertificate.NotAfter.ToString('o'));"
        "}"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "signer": "", "error": str(exc)}
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    result = {
        "status": lines[0] if lines else "unknown",
        "signer": lines[1] if len(lines) > 1 else "",
    }
    if len(lines) > 2:
        result["thumbprint"] = lines[2]
    if len(lines) > 3:
        result["issuer"] = lines[3]
    if len(lines) > 4:
        result["not_after"] = lines[4]
    return result


def run_version(cmd: list[str], timeout: int = 20) -> str:
    """ينفذ أمر إصدار ويعيد أول سطر مفيد."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    for stream in (proc.stdout, proc.stderr):
        for line in (stream or "").splitlines():
            line = line.strip()
            if line:
                return line
    return ""
