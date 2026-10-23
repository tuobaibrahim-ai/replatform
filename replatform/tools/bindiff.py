"""مقارنة نسختين (bin-diff) لملفات PE و APK."""

from __future__ import annotations

import hashlib
import html
import json
import re
import zipfile
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

from ..analyzers import apk_analyzer, pe_analyzer
from ..core import util
from ..core.config import ROOT, load_config

MAX_SIMILARITY_BYTES = 128 * 1024 * 1024
MAX_CDC_BYTES = 32 * 1024 * 1024
MAX_PARSE_BYTES = 256 * 1024 * 1024
MAX_APK_BYTES = 512 * 1024 * 1024
MAX_APK_ENTRIES = 50000
MAX_IMPORT_DLLS = 250
MAX_IMPORT_FUNCTIONS = 500
MAX_SECTIONS = 200
SMALL_FILE_BYTES = 8192
CHUNK = 1024
CDC_MIN = 512
CDC_MAX = 16 * 1024
CDC_WINDOW = 64
CDC_BASE = 257
CDC_MOD = 1 << 64
CDC_POW = pow(CDC_BASE, CDC_WINDOW - 1, CDC_MOD)
CDC_MASK = (1 << 11) - 1  # متوسط ~2KB لكل كتلة
DIFFS_DIR = ROOT / "diffs"


def _cfg_limit(key: str, default: int, minimum: int = 1, maximum: int = 1_000_000) -> int:
    try:
        value = int(load_config().get("analysis", {}).get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


# ---------------------------------------------------------------------------
# معلومات الملفات
# ---------------------------------------------------------------------------

def file_meta(path: Path) -> dict:
    size = path.stat().st_size
    meta = {
        "path": str(path.resolve()),
        "name": path.name,
        "kind": util.file_kind(path),
        "size": size,
        "sha256": util.sha256_file(path),
    }
    if meta["kind"] == "PE":
        meta["signature"] = util.authenticode(path)
    return meta


def _chunk_counter(path: Path) -> tuple[Counter, int]:
    counter: Counter = Counter()
    total = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            counter[hashlib.blake2b(block, digest_size=8).digest()] += len(block)
            total += len(block)
    return counter, total


def _cdc_counter(path: Path) -> tuple[Counter, int]:
    """تقسيم محتوى معتمد على Gear hash — يتحمّل الإدراج/الحذف المبكر.

    الحدود تتحدد بالمحتوى لا بالإزاحة، لذلك إدراج بايت في البداية لا يغيّر
    بصمات الكتل اللاحقة. تُحسب البصمة incrementally دون تحميل الملف كاملاً.
    """
    counter: Counter = Counter()
    total = 0
    chunk = bytearray()
    window: deque[int] = deque(maxlen=CDC_WINDOW)
    rolling = 0
    mask = CDC_MOD - 1
    with open(path, "rb") as fh:
        while True:
            block = fh.read(1 << 20)
            if not block:
                break
            for byte in block:
                if len(window) == CDC_WINDOW:
                    old = window.popleft()
                    rolling = ((rolling - old * CDC_POW) * CDC_BASE + byte) & mask
                else:
                    rolling = (rolling * CDC_BASE + byte) & mask
                window.append(byte)
                chunk.append(byte)
                total += 1
                if len(chunk) >= CDC_MIN and (
                    (rolling & CDC_MASK) == 0 or len(chunk) >= CDC_MAX
                ):
                    counter[hashlib.blake2b(chunk, digest_size=8).digest()] += len(chunk)
                    chunk.clear()
    if chunk:
        counter[hashlib.blake2b(chunk, digest_size=8).digest()] += len(chunk)
    return counter, total


def similarity_info(path_a: Path, path_b: Path) -> dict:
    size_a = path_a.stat().st_size
    size_b = path_b.stat().st_size
    if size_a > MAX_SIMILARITY_BYTES or size_b > MAX_SIMILARITY_BYTES:
        return {
            "score": None,
            "method": "none",
            "reason": "الملف أكبر من حد المقارنة (128MB)",
        }
    if max(size_a, size_b) <= SMALL_FILE_BYTES:
        import difflib

        data_a = path_a.read_bytes()
        data_b = path_b.read_bytes()
        score = 100.0 if not data_a and not data_b else round(
            difflib.SequenceMatcher(None, data_a, data_b).ratio() * 100, 2
        )
        return {"score": score, "method": "difflib"}
    if max(size_a, size_b) <= MAX_CDC_BYTES:
        counter_a, total_a = _cdc_counter(path_a)
        counter_b, total_b = _cdc_counter(path_b)
        method = "cdc"
    else:
        counter_a, total_a = _chunk_counter(path_a)
        counter_b, total_b = _chunk_counter(path_b)
        method = "fixed"
    if not total_a and not total_b:
        return {"score": 100.0, "method": method}
    common = sum(min(count, counter_b.get(key, 0)) for key, count in counter_a.items())
    score = round(200.0 * common / (total_a + total_b), 2)
    return {"score": score, "method": method}


def similarity(path_a: Path, path_b: Path) -> float | None:
    return similarity_info(path_a, path_b)["score"]


def _pe_info(path: Path) -> dict:
    import pefile

    max_parse_mb = _cfg_limit("bindiff_max_parse_mb", MAX_PARSE_BYTES // (1024 * 1024), 1, 4096)
    if path.stat().st_size > max_parse_mb * 1024 * 1024:
        return {
            "skipped": True,
            "reason": f"PE أكبر من حد التحليل العميق ({max_parse_mb}MB)",
        }
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories()
    try:
        sections = []
        for section in pe.sections[:MAX_SECTIONS]:
            name = section.Name.rstrip(b"\x00").decode(errors="replace")
            data = section.get_data()
            try:
                entropy = round(section.get_entropy(), 2)
            except Exception:  # noqa: BLE001
                entropy = 0.0
            sections.append({
                "name": name,
                "vsize": section.Misc_VirtualSize,
                "raw": section.SizeOfRawData,
                "entropy": entropy,
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        imports: dict[str, list[str]] = {}
        imports_truncated = False
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:MAX_IMPORT_DLLS]:
                dll = entry.dll.decode(errors="replace")
                names = sorted({
                    imp.name.decode(errors="replace")
                    for imp in entry.imports if imp.name
                })
                if len(names) > MAX_IMPORT_FUNCTIONS:
                    names = names[:MAX_IMPORT_FUNCTIONS]
                    imports_truncated = True
                imports[dll] = names
            if len(pe.DIRECTORY_ENTRY_IMPORT) > MAX_IMPORT_DLLS:
                imports_truncated = True
        return {
            "arch": pe_analyzer.ARCH.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
            "entry_point": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}",
            "image_base": f"0x{pe.OPTIONAL_HEADER.ImageBase:X}",
            "compile_time": _compile_time(pe.FILE_HEADER.TimeDateStamp),
            "dotnet": bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress),
            "sections": sections,
            "sections_truncated": len(pe.sections) > MAX_SECTIONS,
            "imports": imports,
            "imports_truncated": imports_truncated,
        }
    finally:
        pe.close()


def _compile_time(stamp: int) -> str:
    try:
        return datetime.fromtimestamp(stamp, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
    except (OSError, OverflowError, ValueError):
        return "غير صالح"


def _apk_info(path: Path) -> dict:
    max_apk_mb = _cfg_limit("apk_max_mb", MAX_APK_BYTES // (1024 * 1024), 1, 4096)
    if path.stat().st_size > max_apk_mb * 1024 * 1024:
        return {"skipped": True, "reason": f"APK أكبر من حد المقارنة ({max_apk_mb}MB)"}
    max_entries = _cfg_limit("bindiff_max_apk_entries", MAX_APK_ENTRIES, 100, 500000)
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            return {
                "skipped": True,
                "reason": f"عدد مدخلات APK يتجاوز حد المقارنة ({max_entries})",
            }
        files: dict[str, str] = {}
        for info in infos:
            if info.filename.endswith("/"):
                continue
            files[info.filename] = f"{info.CRC:08X}"
    decoded = apk_analyzer.decode_apk(
        str(path), timeout=apk_analyzer.load_config()["analysis"]["apk_decode_timeout"]
    )
    manifest = apk_analyzer.parse_manifest(decoded["xml"], decoded["meta"])
    signing = apk_analyzer.signing_info(str(path))
    return {
        "manifest": manifest,
        "signing": signing,
        "files": files,
    }


# ---------------------------------------------------------------------------
# المقارنة
# ---------------------------------------------------------------------------

def _diff_pe(a: dict, b: dict, highlights: list[str]) -> dict:
    if a.get("skipped") or b.get("skipped"):
        return {
            "skipped": True,
            "reason": a.get("reason") or b.get("reason") or "تجاوز حد التحليل",
        }
    properties = []
    for key, label in (
        ("arch", "المعمارية"), ("entry_point", "نقطة الدخول"),
        ("image_base", "ImageBase"), ("compile_time", "وقت البناء"),
        ("dotnet", ".NET"),
    ):
        if a.get(key) != b.get(key):
            highlights.append(f"تغيّر {label}: {a.get(key)} → {b.get(key)}")
        properties.append({
            "field": label, "a": a.get(key), "b": b.get(key),
            "changed": a.get(key) != b.get(key),
        })

    sections_a = {s["name"]: s for s in a["sections"]}
    sections_b = {s["name"]: s for s in b["sections"]}
    sections = []
    for name in dict.fromkeys(list(sections_a) + list(sections_b)):
        sec_a, sec_b = sections_a.get(name), sections_b.get(name)
        if sec_a and sec_b:
            status = "same" if sec_a["sha256"] == sec_b["sha256"] else "changed"
        else:
            status = "added" if sec_b else "removed"
        sections.append({
            "name": name, "status": status,
            "entropy_a": (sec_a or {}).get("entropy"),
            "entropy_b": (sec_b or {}).get("entropy"),
            "size_a": (sec_a or {}).get("vsize"),
            "size_b": (sec_b or {}).get("vsize"),
        })
        if status == "added":
            highlights.append(f"قسم جديد: {name} (إنتروبيا {sec_b['entropy']})")
        elif status == "removed":
            highlights.append(f"قسم محذوف: {name}")

    imports_a, imports_b = a["imports"], b["imports"]
    added: dict[str, list[str]] = {}
    removed: dict[str, list[str]] = {}
    for dll in sorted(set(imports_a) | set(imports_b)):
        fns_a = set(imports_a.get(dll, []))
        fns_b = set(imports_b.get(dll, []))
        if fns_b - fns_a:
            added[dll] = sorted(fns_b - fns_a)
        if fns_a - fns_b:
            removed[dll] = sorted(fns_a - fns_b)

    indicator_fns = {fn for fns in pe_analyzer.INDICATORS.values() for fn in fns}
    new_suspicious = sorted({fn for fns in added.values() for fn in fns if fn in indicator_fns})
    if new_suspicious:
        highlights.append("دوال حساسة جديدة: " + ", ".join(new_suspicious[:8]))

    return {
        "properties": properties,
        "sections": sections,
        "imports": {"added": added, "removed": removed},
    }


def _diff_apk(a: dict, b: dict, highlights: list[str]) -> dict:
    if a.get("skipped") or b.get("skipped"):
        return {
            "skipped": True,
            "reason": a.get("reason") or b.get("reason") or "تجاوز حد التحليل",
        }
    ma, mb = a["manifest"], b["manifest"]
    fields = [
        ("package", "الحزمة"), ("version_name", "الإصدار"),
        ("version_code", "رقم الإصدار"), ("min_sdk", "minSdk"),
        ("target_sdk", "targetSdk"), ("exported", "مكونات مُصدّرة"),
    ]
    manifest_rows = []
    for key, label in fields:
        changed = ma.get(key) != mb.get(key)
        manifest_rows.append({"field": label, "a": ma.get(key), "b": mb.get(key), "changed": changed})
        if changed and key in ("version_name", "version_code", "target_sdk"):
            highlights.append(f"تغيّر {label}: {ma.get(key)} → {mb.get(key)}")

    pa, pb = set(ma.get("permissions") or []), set(mb.get("permissions") or [])
    perm_added = sorted(pb - pa)
    perm_removed = sorted(pa - pb)
    if perm_added:
        highlights.append(f"أذونات جديدة: {', '.join(p.split('.')[-1] for p in perm_added[:8])}")

    app_a, app_b = ma.get("application") or {}, mb.get("application") or {}
    for key, label in (("debuggable", "debuggable"), ("cleartext", "usesCleartextTraffic")):
        if app_a.get(key) != app_b.get(key):
            highlights.append(f"تغيّر {label}: {app_a.get(key)} → {app_b.get(key)}")

    files_a, files_b = a["files"], b["files"]
    files_added = sorted(set(files_b) - set(files_a))
    files_removed = sorted(set(files_a) - set(files_b))
    files_changed = sorted(
        name for name in set(files_a) & set(files_b) if files_a[name] != files_b[name]
    )
    if len(files_added) > 50 or len(files_removed) > 50:
        highlights.append("تغيّر كبير في محتوى الحزمة")

    sa, sb = a["signing"], b["signing"]
    schemes_a = ",".join(sa.get("schemes") or [
        k for k in ("v1", "v2", "v3", "v3_1", "v4") if sa.get(k)
    ]) or "غير موقّع"
    schemes_b = ",".join(sb.get("schemes") or [
        k for k in ("v1", "v2", "v3", "v3_1", "v4") if sb.get(k)
    ]) or "غير موقّع"
    if schemes_a != schemes_b:
        highlights.append(f"تغيّر التوقيع: {schemes_a} → {schemes_b}")
    certs_a = {c.get("sha256") for c in sa.get("certs", [])}
    certs_b = {c.get("sha256") for c in sb.get("certs", [])}
    if certs_a and certs_b and certs_a != certs_b:
        highlights.append("تغيّرت شهادة التوقيع")

    union = set(files_a) | set(files_b)
    unchanged = len(union) - len(files_added) - len(files_removed) - len(files_changed)
    content_similarity = round(100.0 * unchanged / len(union), 2) if union else None

    return {
        "manifest": manifest_rows,
        "permissions": {"added": perm_added, "removed": perm_removed},
        "files": {
            "added": files_added[:200],
            "removed": files_removed[:200],
            "changed": files_changed[:200],
            "added_count": len(files_added),
            "removed_count": len(files_removed),
            "changed_count": len(files_changed),
            "unchanged_count": unchanged,
        },
        "signing": {"a": schemes_a, "b": schemes_b},
        "similarity": content_similarity,
    }


def diff_files(path_a: Path, path_b: Path) -> dict:
    meta_a, meta_b = file_meta(path_a), file_meta(path_b)
    highlights: list[str] = []
    result = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "a": meta_a,
        "b": meta_b,
        "size_delta": meta_b["size"] - meta_a["size"],
        "similarity": None,
        "similarity_method": "none",
        "binary_similarity": None,
        "pe": None,
        "apk": None,
        "highlights": highlights,
        "limits": {
            "max_parse_mb": _cfg_limit(
                "bindiff_max_parse_mb", MAX_PARSE_BYTES // (1024 * 1024), 1, 4096
            ),
            "max_apk_entries": _cfg_limit(
                "bindiff_max_apk_entries", MAX_APK_ENTRIES, 100, 500000
            ),
        },
    }
    if meta_a["kind"] == meta_b["kind"] == "APK":
        # مقارنة APK على مستوى محتوى الملفات لا البايتات المضغوطة.
        result["apk"] = _diff_apk(_apk_info(path_a), _apk_info(path_b), highlights)
        if result["apk"].get("skipped"):
            result["similarity"] = None
            result["similarity_method"] = "none"
            result["similarity_reason"] = result["apk"]["reason"]
            highlights.append(result["apk"]["reason"])
        else:
            result["similarity"] = result["apk"].get("similarity")
            result["similarity_method"] = "apk-content"
    else:
        sim = similarity_info(path_a, path_b)
        result["similarity"] = sim["score"]
        result["similarity_method"] = sim["method"]
        result["binary_similarity"] = sim["score"]
        if sim.get("reason"):
            result["similarity_reason"] = sim["reason"]
        if meta_a["kind"] == meta_b["kind"] == "PE":
            result["pe"] = _diff_pe(_pe_info(path_a), _pe_info(path_b), highlights)
            if result["pe"].get("skipped"):
                highlights.append(result["pe"]["reason"])
        elif meta_a["kind"] != meta_b["kind"]:
            highlights.append(f"نوعان مختلفان: {meta_a['kind']} مقابل {meta_b['kind']}")
    result["identical"] = meta_a["sha256"] == meta_b["sha256"]
    return result


# ---------------------------------------------------------------------------
# تقرير HTML
# ---------------------------------------------------------------------------

def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _table(headers: list[str], rows: list[list]) -> str:
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


METHOD_LABEL = {
    "cdc": "بصمات محتوى (CDC)",
    "fixed": "كتل ثابتة (ملف كبير)",
    "difflib": "مقارنة دقيقة (ملف صغير)",
    "apk-content": "محتوى الحزمة",
    "none": "غير محسوبة",
}


def render_html(result: dict) -> str:
    a, b = result["a"], result["b"]
    sim = result["similarity"]
    sim_text = f"{sim}%" if sim is not None else "غير محسوبة (ملفات كبيرة)"
    if result.get("identical"):
        sim_text = "متطابقان 100%"
    method = METHOD_LABEL.get(result.get("similarity_method", "none"), result.get("similarity_method", ""))
    cards = f"""
<div class="cards">
  <div class="card"><span>التشابه</span><b>{_esc(sim_text)}</b><small>{_esc(method)}</small></div>
  <div class="card"><span>فرق الحجم</span><b>{result['size_delta']:+,}</b></div>
  <div class="card"><span>نوع الملف</span><b>{_esc(a['kind'])} → {_esc(b['kind'])}</b></div>
</div>"""

    body: list[str] = [_table(
        ["الخاصية", "النسخة A", "النسخة B"],
        [
            ["الاسم", a["name"], b["name"]],
            ["الحجم", f"{a['size']:,}", f"{b['size']:,}"],
            ["SHA256", a["sha256"][:32] + "…", b["sha256"][:32] + "…"],
        ],
    )]

    if result.get("pe"):
        pe = result["pe"]
        if pe.get("skipped"):
            body.append("<h2>خصائص PE</h2><p>" + _esc(pe.get("reason", "تم التخطي")) + "</p>")
        else:
            body.append("<h2>خصائص PE</h2>" + _table(
                ["الخاصية", "A", "B"],
                [[row["field"], row["a"], row["b"]] for row in pe["properties"]],
            ))
            body.append("<h2>الأقسام</h2>" + _table(
                ["القسم", "الحالة", "الإنتروبيا A", "الإنتروبيا B", "الحجم A", "الحجم B"],
                [[s["name"], s["status"], s["entropy_a"], s["entropy_b"], s["size_a"], s["size_b"]]
                 for s in pe["sections"]],
            ))
            for label, key in (("استيرادات مضافة", "added"), ("استيرادات محذوفة", "removed")):
                data = pe["imports"][key]
                if data:
                    body.append(f"<h2>{label}</h2>" + _table(
                        ["المكتبة", "الدوال"],
                        [[dll, ", ".join(fns)] for dll, fns in data.items()],
                    ))

    if result.get("apk"):
        apk = result["apk"]
        if apk.get("skipped"):
            body.append("<h2>مقارنة APK</h2><p>" + _esc(apk.get("reason", "تم التخطي")) + "</p>")
        else:
            body.append("<h2>خصائص البيان</h2>" + _table(
                ["الخاصية", "A", "B"],
                [[row["field"], row["a"], row["b"]] for row in apk["manifest"]],
            ))
            perms = apk["permissions"]
            body.append("<h2>الأذونات</h2>" + _table(
                ["مضافة", "محذوفة"],
                [[", ".join(perms["added"]) or "—", ", ".join(perms["removed"]) or "—"]],
            ))
            files = apk["files"]
            body.append("<h2>ملفات الحزمة</h2>" + _table(
                ["الحالة", "العدد", "أمثلة"],
                [
                    ["مضافة", files["added_count"], ", ".join(files["added"][:8])],
                    ["محذوفة", files["removed_count"], ", ".join(files["removed"][:8])],
                    ["متغيرة", files["changed_count"], ", ".join(files["changed"][:8])],
                    ["غير متغيرة", files.get("unchanged_count", 0), "—"],
                ],
            ))
            body.append("<h2>التوقيع</h2>" + _table(
                ["A", "B"], [[apk["signing"]["a"], apk["signing"]["b"]]],
            ))

    highlights = result.get("highlights") or []
    highlights_html = (
        "<section><h2>نقاط تستحق الانتباه</h2><ul>"
        + "".join(f"<li>{_esc(item)}</li>" for item in highlights)
        + "</ul></section>"
    ) if highlights else ""

    return f"""<!DOCTYPE html>
<html dir="rtl" lang="ar"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>REPLATFORM — مقارنة نسختين</title>
<style>
 :root {{ color-scheme: dark; }}
 * {{ box-sizing: border-box; }}
 body {{ margin:0; padding:24px; font-family:'Segoe UI',Tahoma,sans-serif;
        background:#0b1220; color:#dbe4f0; }}
 h1 {{ font-size:21px; margin:0 0 6px; }}
 h2 {{ font-size:15px; margin:20px 0 10px; color:#93c5fd; }}
 .meta {{ color:#8ba3c7; font-size:12.5px; line-height:1.9; }}
 .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
           gap:12px; margin:16px 0; }}
 .card {{ background:#111c31; border:1px solid #1e2f4d; border-radius:12px;
          padding:12px 16px; }}
 .card span {{ display:block; font-size:11.5px; color:#8ba3c7; margin-bottom:6px; }}
 .card b {{ font-size:20px; }}
 .card small {{ display:block; color:#6f86a8; font-size:10.5px; margin-top:4px; }}
 section, .box {{ background:#0f1a2e; border:1px solid #1e2f4d;
                  border-radius:14px; padding:18px; margin-bottom:16px; }}
 table {{ width:100%; border-collapse:collapse; margin:6px 0; }}
 th {{ text-align:right; font-size:11.5px; color:#93b4dd; padding:7px 8px;
       border-bottom:1px solid #1e2f4d; }}
 td {{ padding:7px 8px; border-bottom:1px solid #16233b; font-size:12.5px;
       vertical-align:top; word-break:break-word; }}
 code {{ font-family:Consolas,monospace; background:#111c31; padding:1px 6px;
         border-radius:5px; direction:ltr; display:inline-block; font-size:11.5px; }}
 ul {{ margin:4px 0; padding-inline-start:20px; }}
 li {{ margin:4px 0; font-size:13px; }}
 footer {{ color:#5f7595; font-size:11.5px; text-align:center; margin-top:18px; }}
</style></head><body>
<h1>مقارنة نسختين — {_esc(a['name'])} مقابل {_esc(b['name'])}</h1>
<div class="meta">
  A: <code>{_esc(a['path'])}</code><br>
  B: <code>{_esc(b['path'])}</code><br>
  أُنشئ: {_esc(result['generated'])}
</div>
{cards}
<div class="box">{body[0]}</div>
{''.join(f'<section>{part}</section>' for part in body[1:])}
{highlights_html}
<footer>REPLATFORM — bin-diff</footer>
</body></html>"""


def run(path_a: str | Path, path_b: str | Path) -> dict:
    a, b = Path(path_a).resolve(), Path(path_b).resolve()
    for path in (a, b):
        if not path.is_file():
            raise FileNotFoundError(f"ملف غير موجود: {path}")
    result = diff_files(a, b)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    slug_a = re.sub(r"[^\w.-]+", "-", a.stem)[:30].strip("-") or "a"
    slug_b = re.sub(r"[^\w.-]+", "-", b.stem)[:30].strip("-") or "b"
    out_dir = DIFFS_DIR / f"{stamp}-{slug_a}-vs-{slug_b}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "diff.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), "utf-8"
    )
    report = out_dir / "report.html"
    report.write_text(render_html(result), "utf-8")
    result["output_dir"] = str(out_dir)
    result["report"] = str(report)
    return result
