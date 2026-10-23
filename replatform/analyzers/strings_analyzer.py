"""محلل النصوص: استخراج النصوص القابلة للطباعة والمؤشرات المهمة."""

from __future__ import annotations

import mmap
import re
from pathlib import Path

from ..core.config import load_config
from . import Analyzer, Target

ASCII_RE = re.compile(rb"[\x20-\x7E]{6,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7E]\x00){6,}")
MAX_STRING_CHARS = 512
MAX_PATTERN_CHARS = 300

_CACHE: dict[tuple, dict] = {}

NOTABLE = [
    ("URL", re.compile(r"https?://[^\s\"'<>]{4,120}", re.I)),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("Domain", re.compile(r"\b[a-z0-9][a-z0-9\-]{1,40}\.(?:com|net|org|io|ru|cn|info|xyz|top|onion)\b", re.I)),
    ("Registry", re.compile(r"(?:SOFTWARE|SYSTEM|HKEY_)[\\A-Za-z0-9_]+", re.I)),
    ("Command", re.compile(r"\b(?:powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32)\b", re.I)),
    ("Crypto", re.compile(r"\b(?:AES|RSA|DES|RC4|ChaCha20|Base64)\b")),
]


def scan(path: str, limit: int = 2000) -> dict:
    file_path = Path(path)
    stat = file_path.stat()
    try:
        max_mb = int(load_config().get("analysis", {}).get("strings_max_mb", 512))
    except (TypeError, ValueError):
        max_mb = 512
    if stat.st_size > max_mb * 1024 * 1024:
        raise ValueError(
            f"حجم الملف ({stat.st_size / (1024 * 1024):.1f} MB) يتجاوز حد "
            f"استخراج النصوص ({max_mb} MB) — عدّل analysis.strings_max_mb."
        )
    key = (str(file_path.resolve()), stat.st_mtime_ns, stat.st_size, limit)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    with open(file_path, "rb") as fh:
        if stat.st_size == 0:
            result = _scan_bytes(b"", limit)
        else:
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                result = _scan_bytes(mapped, limit)
    if len(_CACHE) >= 8:
        _CACHE.clear()
    _CACHE[key] = result
    return result


def _scan_bytes(data, limit: int) -> dict:
    found: list[str] = []
    for match in ASCII_RE.finditer(data):
        found.append(
            match.group()[:MAX_STRING_CHARS].decode("ascii", errors="replace")
        )
        if len(found) >= limit:
            break
    for match in UTF16_RE.finditer(data):
        try:
            found.append(
                match.group()[: MAX_STRING_CHARS * 2].decode("utf-16-le")
            )
        except UnicodeDecodeError:
            continue
        if len(found) >= limit * 2:
            break
    unique = list(dict.fromkeys(found))
    notable: dict[str, list[str]] = {}
    haystack = "\n".join(unique)
    for label, pattern in NOTABLE:
        hits = list(dict.fromkeys(
            m if isinstance(m, str) else m.group() for m in pattern.findall(haystack)
        ))
        if hits:
            notable[label] = hits[:20]
    return {"total": len(found), "unique": len(unique), "strings": unique, "notable": notable}


_UNSAFE_PATTERN = re.compile(r"\\[1-9]|\([^)]*[+*][^)]*\)\s*[+*{]")


def _validate_pattern(pattern: str) -> None:
    if len(pattern) > MAX_PATTERN_CHARS:
        raise ValueError(
            f"النمط طويل جداً ({len(pattern)} > {MAX_PATTERN_CHARS} حرف)"
        )
    if _UNSAFE_PATTERN.search(pattern):
        raise ValueError(
            "نمط regex يحتوي تكراراً متداخلاً/مرجعاً خلفياً قد يسبب تعليقاً — بسّطه."
        )


def search(path: str, pattern: str, maximum: int = 40) -> list[str]:
    _validate_pattern(pattern)
    regex = re.compile(pattern, re.I)
    result: list[str] = []
    for text in scan(path)["strings"]:
        if regex.search(text):
            result.append(text)
            if len(result) >= maximum:
                break
    return result


class StringsAnalyzer(Analyzer):
    name = "strings"
    description = "استخراج النصوص والمؤشرات (URLs, IPs, أوامر, مسارات)"

    def can_handle(self, target: Target) -> bool:
        return target.kind in ("PE", "APK", "ELF", "ZIP", "other")

    def run(self, target: Target, ws) -> dict:  # noqa: ARG002
        maximum = load_config()["analysis"]["strings_max"]
        data = scan(str(target.path), limit=maximum * 10)
        return {
            "total": data["total"],
            "unique": data["unique"],
            "notable": data["notable"],
            "sample": data["strings"][:maximum],
        }
