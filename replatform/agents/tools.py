"""أدوات وكلاء الذكاء الاصطناعي (قراءة فقط + معاينة تعديل)."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

from ..analyzers import apk_analyzer, pe_analyzer, strings_analyzer
from ..core import util
from ..core.config import load_config

TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "analyze_file",
            "description": "تحليل سريع لملف تنفيذي (PE أو APK): النوع، الحجم، التجزئة، والخصائص الأساسية.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "مسار الملف"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "strings_search",
            "description": "بحث في النصوص المستخرجة من ملف عن نمط regex (مثل URL أو اسم دالة).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "pattern": {"type": "string", "description": "تعبير نمطي (regex)"},
                    "max_results": {"type": "integer"},
                },
                "required": ["path", "pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "hexdump",
            "description": "عرض محتوى ثنائي عند إزاحة محددة (للفحص اليدوي).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "offset": {"type": "integer", "description": "الإزاحة بالبايت"},
                    "length": {"type": "integer", "description": "عدد البايتات (حد أقصى 1024)"},
                },
                "required": ["path", "offset"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "apk_manifest",
            "description": "فك وقراءة AndroidManifest.xml من APK (الحزمة، الأذونات، المكونات، التوقيع).",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "patch_preview",
            "description": "معاينة تعديل ثنائي (لا يكتب شيئاً): يبحث عن نمط hex أو نص ويعرض الإزاحات.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "find": {"type": "string", "description": "hex:48 8B ??  أو str:نص"},
                    "limit": {"type": "integer"},
                },
                "required": ["path", "find"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "intel_lookup",
            "description": (
                "استعلام قراءة فقط عن مؤشر أو حزمة أو ثغرة من تكامل خارجي "
                "(NVD, CISA KEV, OSV, GitHub, Hugging Face, VirusTotal, OTX, "
                "MalwareBazaar, AbuseIPDB, Shodan, URLhaus, ThreatFox). يتطلب تفعيل "
                "integrations.agent_enabled. لا ترسل محتوى ملفات أو أسراراً."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "connector": {
                        "type": "string",
                        "description": "معرّف الموصل (مثال: nvd, osv, virustotal)",
                    },
                    "query": {
                        "type": "string",
                        "description": "مؤشر أو استعلام نصي فقط (بلا محتوى ملفات)",
                    },
                },
                "required": ["connector", "query"],
            },
        },
    },
]

_APK_CACHE: dict[str, dict] = {}
_ALLOWED_ROOTS: list[Path] = []
MAX_PREVIEW_BYTES = 256 * 1024 * 1024


def configure(allowed_roots: list[str | Path]) -> None:
    """تقييد أدوات القراءة على الهدف/مساحة العمل (حماية من قراءة ملفات اعتباطية)."""
    global _ALLOWED_ROOTS
    _ALLOWED_ROOTS = [
        Path(root).resolve() for root in allowed_roots if str(root).strip()
    ]


def _checked(path: str | Path) -> Path:
    p = Path(path).resolve()
    if _ALLOWED_ROOTS and not any(
        (root.is_file() and p == root) or (root.is_dir() and p.is_relative_to(root))
        for root in _ALLOWED_ROOTS
    ):
        raise PermissionError(f"مسار خارج نطاق التحليل المسموح به: {p}")
    return p


def _too_large(size: int) -> str | None:
    limit = int(load_config()["analysis"].get("max_file_mb", 1024)) * 1024 * 1024
    if size > limit:
        return f"الملف يتجاوز حد التحليل ({util.human_size(size)} > {util.human_size(limit)})"
    return None


def analyze_file(path: str) -> dict:
    p = _checked(path)
    if not p.is_file():
        return {"error": f"ملف غير موجود: {path}"}
    if error := _too_large(p.stat().st_size):
        return {"error": error}
    kind = util.file_kind(p)
    base = {
        "path": str(p.resolve()),
        "name": p.name,
        "kind": kind,
        "size": p.stat().st_size,
        "size_human": util.human_size(p.stat().st_size),
        "sha256": util.sha256_file(p),
    }
    try:
        if kind == "PE":
            base["pe"] = pe_analyzer.quick_summary(str(p))
            base["signature"] = util.authenticode(p)
        elif kind == "APK":
            summary = _APK_CACHE.get(
                f"{p}|{p.stat().st_mtime_ns}|{p.stat().st_size}"
            )
            if summary is None:
                summary = apk_analyzer.quick_summary(str(p))
                if len(_APK_CACHE) >= 32:
                    _APK_CACHE.clear()
                _APK_CACHE[f"{p}|{p.stat().st_mtime_ns}|{p.stat().st_size}"] = summary
            base["apk"] = summary
    except Exception as exc:  # noqa: BLE001
        base["error"] = f"{type(exc).__name__}: {exc}"
    return base


def strings_search(path: str, pattern: str, max_results: int = 40) -> dict:
    p = _checked(path)
    if not p.is_file():
        return {"error": f"ملف غير موجود: {path}"}
    if error := _too_large(p.stat().st_size):
        return {"error": error}
    if len(pattern) > 500:
        return {"error": "النمط طويل جداً (الحد 500 حرف)"}
    try:
        hits = strings_analyzer.search(
            str(p), pattern, maximum=max(1, min(int(max_results), 200))
        )
        return {"pattern": pattern, "count": len(hits), "results": hits}
    except (re.error, ValueError) as exc:
        return {"error": f"نمط regex غير صالح: {exc}"}


def hexdump(path: str, offset: int = 0, length: int = 256) -> dict:
    p = _checked(path)
    if not p.is_file():
        return {"error": f"ملف غير موجود: {path}"}
    length = max(1, min(int(length), 1024))
    offset = max(0, int(offset))
    with open(p, "rb") as fh:
        fh.seek(offset)
        data = fh.read(length)
    lines = []
    for row in range(0, len(data), 16):
        chunk = data[row:row + 16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + row:08X}  {hexpart:<48} |{text}|")
    return {"offset": offset, "length": len(data), "dump": lines}


def _tool_timeout() -> int:
    try:
        return max(10, min(int(load_config()["agent"].get("tool_timeout", 120)), 600))
    except (TypeError, ValueError):
        return 120


def apk_manifest(path: str) -> dict:
    p = _checked(path)
    if not p.is_file():
        return {"error": f"ملف غير موجود: {path}"}
    try:
        decoded = apk_analyzer.decode_apk(str(p), timeout=_tool_timeout())
        manifest = apk_analyzer.parse_manifest(decoded["xml"], decoded["meta"])
        manifest["signing"] = apk_analyzer.signing_info(str(p))
        manifest["abis"] = apk_analyzer._native_libs(str(p))
        return manifest
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


def patch_preview(path: str, find: str, limit: int = 10) -> dict:
    p = _checked(path)
    if not p.is_file():
        return {"error": f"ملف غير موجود: {path}"}
    size = p.stat().st_size
    if size > MAX_PREVIEW_BYTES:
        return {
            "error": f"الملف كبير جداً للمعاينة ({util.human_size(size)}) — "
                     f"الحد {util.human_size(MAX_PREVIEW_BYTES)}"
        }
    limit = max(1, min(int(limit), 100))
    kind, _, rest = find.partition(":")
    if kind not in ("hex", "str"):
        return {"error": "الصيغة: hex:48 8B ?? أو str:نص"}
    data = p.read_bytes()
    matches: list[dict] = []
    if kind == "hex":
        try:
            tokens = rest.split()
            pattern = b"".join(
                b"." if tok in ("?", "??") else re.escape(bytes.fromhex(tok))
                for tok in tokens
            )
            regex = re.compile(pattern, re.DOTALL)
        except ValueError as exc:
            return {"error": f"نمط hex غير صالح: {exc}"}
        for m in regex.finditer(data):
            matches.append({"offset": m.start(), "context": _context(data, m.start())})
            if len(matches) >= limit:
                break
    else:
        needle = rest.encode("utf-8", errors="replace")
        pos = data.find(needle)
        while pos != -1 and len(matches) < limit:
            matches.append({"offset": pos, "context": _context(data, pos)})
            pos = data.find(needle, pos + 1)
    return {"file": str(p), "find": find, "count": len(matches), "matches": matches}


def _context(data: bytes, offset: int) -> str:
    start = max(0, offset - 16)
    chunk = data[start:start + 64]
    hexpart = " ".join(f"{b:02X}" for b in chunk)
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"{hexpart} |{text}|"


def intel_lookup(connector: str, query: str) -> dict:
    """أداة وكيل اختيارية لاستعلامات خارجية قراءة فقط (معطّلة افتراضياً)."""
    cfg = load_config()
    integrations = cfg.get("integrations") or {}
    if not isinstance(integrations, dict):
        integrations = {}
    if not bool(integrations.get("agent_enabled", False)):
        return {
            "error": (
                "تكاملات الوكيل معطّلة. فعّل integrations.agent_enabled "
                "في config.json بعد مراجعة سياسة البيانات."
            )
        }
    from ..integrations import connectors

    return connectors.lookup(
        connector, query, limit=5, allow_network=True
    )


_EXECUTORS: dict[str, Callable[..., dict]] = {
    "analyze_file": analyze_file,
    "strings_search": strings_search,
    "hexdump": hexdump,
    "apk_manifest": apk_manifest,
    "patch_preview": patch_preview,
    "intel_lookup": intel_lookup,
}


def execute(name: str, args: dict) -> dict:
    handler = _EXECUTORS.get(name)
    if not handler:
        return {"error": f"أداة غير معروفة: {name}"}
    try:
        return handler(**args)
    except TypeError as exc:
        return {"error": f"معاملات غير صحيحة: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


def tool_result_json(result: dict, limit: int = 6000) -> str:
    text = json.dumps(result, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return text
    return text[:limit] + ' …[اقتُطع الناتج]'
