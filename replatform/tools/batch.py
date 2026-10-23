"""فحص دفعات — تحليل سريع لعدة ملفات وإنتاج ملخص HTML/JSON/CSV."""

from __future__ import annotations

import csv
import html
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path

from ..analyzers import Target, run_analyzers
from ..core import util
from ..core.config import ROOT

SCANS_DIR = ROOT / "scans"
KNOWN_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi",  # PE
    ".apk",                                                  # APK
    ".elf", ".so",                                           # ELF
}
SKIP_DIRS = {
    "workspaces", "diffs", "scans", "sandbox", "tools", "plugins", "scripts",
    "__pycache__", ".git", ".venv", "node_modules", "decoded", "java_src",
}
VERDICT_AR = {"critical": "مرتفع", "warn": "متوسط", "info": "منخفض"}
VERDICT_ORDER = {"critical": 0, "warn": 1, "info": 2}


class _NullWS:
    """مساحة عمل وهمية: الفحص السريع لا يحفظ آثاراً لكل ملف."""

    def add_event(self, *args, **kwargs) -> None:  # noqa: ARG002
        pass

    def save_artifact(self, *args, **kwargs) -> None:  # noqa: ARG002
        pass


def collect_files(
    root: Path,
    recursive: bool = True,
    max_files: int = 50,
    max_mb: int = 128,
    all_files: bool = False,
) -> list[Path]:
    root = Path(root)
    max_bytes = max_mb * 1024 * 1024
    if max_files <= 0:
        return []
    if root.is_file():
        try:
            if root.is_symlink() or root.stat().st_size > max_bytes:
                return []
        except OSError:
            return []
        if root.suffix.lower() not in KNOWN_EXTS and not all_files:
            return []
        return [root]
    if not root.is_dir():
        return []
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in SKIP_DIRS and not Path(dirpath, name).is_symlink()
        )
        for name in sorted(filenames):
            path = Path(dirpath) / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                if path.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            if path.suffix.lower() not in KNOWN_EXTS:
                if not all_files:
                    continue
            files.append(path)
            if len(files) >= max_files:
                return files
        if not recursive:
            break
    return files


def analyze_file(path: Path, only: set[str], max_mb: int | None = None) -> dict:
    target = Target.from_path(path, max_mb=max_mb)
    started = time.time()
    results = run_analyzers(target, _NullWS(), only)
    score = 0
    findings: list[str] = []
    errors: list[str] = []
    for name, artifact in results.items():
        if artifact.get("error"):
            errors.append(f"{name}: {artifact['error']}")
            continue
        score = max(score, int(artifact.get("score") or 0))
        findings.extend(artifact.get("findings") or [])
    verdict = "critical" if score >= 5 else ("warn" if score >= 2 else "info")
    return {
        "path": str(path),
        "name": path.name,
        "kind": target.kind,
        "size": target.size,
        "sha256": target.sha256,
        "score": score,
        "verdict": verdict,
        "findings": findings[:8],
        "errors": errors,
        "analyzers": sorted(results),
        "seconds": round(time.time() - started, 2),
    }


def scan(
    root: str | Path,
    recursive: bool = True,
    only: set[str] | None = None,
    max_files: int = 50,
    max_mb: int = 128,
    all_files: bool = False,
    progress=None,
) -> dict:
    root = Path(root).resolve()
    if not root.exists():
        raise FileNotFoundError(f"المسار غير موجود: {root}")
    only = only or {"pe", "apk", "strings", "yara"}

    files = collect_files(root, recursive, max_files, max_mb, all_files)
    started = time.time()
    rows: list[dict] = []
    for index, path in enumerate(files, 1):
        try:
            row = analyze_file(path, only, max_mb)
        except Exception as exc:  # noqa: BLE001
            size = path.stat().st_size if path.exists() else 0
            row = {
                "path": str(path), "name": path.name, "kind": util.file_kind(path),
                "size": size, "sha256": "", "score": 0, "verdict": "info",
                "findings": [], "errors": [f"{type(exc).__name__}: {exc}"],
                "analyzers": [], "seconds": 0,
            }
        rows.append(row)
        if progress:
            progress(index, len(files), row)

    rows.sort(key=lambda r: (VERDICT_ORDER.get(r["verdict"], 9), -r["score"], r["name"].lower()))
    elapsed = round(time.time() - started, 2)
    counts = {
        verdict: sum(1 for row in rows if row["verdict"] == verdict)
        for verdict in ("critical", "warn", "info")
    }
    result = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "recursive": recursive,
        "analyzers": sorted(only),
        "max_files": max_files,
        "max_mb": max_mb,
        "file_count": len(rows),
        "elapsed_seconds": elapsed,
        "counts": counts,
        "rows": rows,
    }

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"[^\w.-]+", "-", root.name or "scan")[:40].strip("-") or "scan"
    out_dir = SCANS_DIR / f"{stamp}-{slug}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), "utf-8"
    )
    _write_csv(out_dir / "summary.csv", rows)
    report = out_dir / "summary.html"
    report.write_text(render_html(result), "utf-8")

    result["output_dir"] = str(out_dir)
    result["report"] = str(report)
    result["json"] = str(out_dir / "summary.json")
    result["csv"] = str(out_dir / "summary.csv")
    return result


# بادئات تُفسَّر كصيغ في Excel/LibreOffice عند فتح CSV.
# نضيف علامة اقتباس مفردة حتى تبقى البيانات نصاً ولا تُنفَّذ.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value) -> str:
    """يحيّد حقن الصيغ في خلية CSV دون حذف المحتوى الأصلي."""
    text = "" if value is None else str(value)
    if text.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + text
    return text


def _write_csv(path: Path, rows: list[dict]) -> None:
    fields = ["name", "kind", "size", "score", "verdict", "sha256",
              "findings", "errors", "path", "seconds"]
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=fields, extrasaction="ignore", quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        for row in rows:
            values = {
                **row,
                "findings": " | ".join(row.get("findings") or []),
                "errors": " | ".join(row.get("errors") or []),
            }
            writer.writerow({field: _csv_cell(values.get(field)) for field in fields})


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def render_html(result: dict) -> str:
    counts = result["counts"]
    cards = f"""
<div class="cards">
  <div class="card"><span>ملفات مفحوصة</span><b>{result['file_count']}</b></div>
  <div class="card crit"><span>مرتفع</span><b>{counts['critical']}</b></div>
  <div class="card warn"><span>متوسط</span><b>{counts['warn']}</b></div>
  <div class="card info"><span>منخفض</span><b>{counts['info']}</b></div>
  <div class="card"><span>المدة</span><b>{result['elapsed_seconds']}ث</b></div>
</div>"""

    rows_html = []
    for row in result["rows"]:
        findings = "؛ ".join(row.get("findings") or []) or "—"
        errors = "؛ ".join(row.get("errors") or [])
        note = f'<div class="err">{_esc(errors)}</div>' if errors else ""
        rows_html.append(
            "<tr>"
            f'<td><b>{_esc(row["name"])}</b><div class="path">{_esc(row["path"])}</div>{note}</td>'
            f'<td>{_esc(row["kind"])}</td>'
            f'<td>{_esc(util.human_size(row["size"]))}</td>'
            f'<td>{_esc(row["score"])}/10</td>'
            f'<td><span class="badge {_esc(row["verdict"])}">{_esc(VERDICT_AR.get(row["verdict"], row["verdict"]))}</span></td>'
            f'<td>{_esc(findings)}</td>'
            f'<td>{_esc(row["seconds"])}ث</td>'
            "</tr>"
        )

    table = (
        "<table><thead><tr><th>الملف</th><th>النوع</th><th>الحجم</th>"
        "<th>الدرجة</th><th>الحكم</th><th>أهم النتائج</th><th>الزمن</th></tr></thead><tbody>"
        + "".join(rows_html)
        + "</tbody></table>"
    ) if rows_html else '<div class="note">لا ملفات مطابقة للفحص.</div>'

    analyzers = ", ".join(result["analyzers"])
    return f"""<!DOCTYPE html>
<html dir="rtl" lang="ar"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>REPLATFORM — فحص دفعات</title>
<style>
 :root {{ color-scheme: dark; }}
 * {{ box-sizing: border-box; }}
 body {{ margin:0; padding:24px; font-family:'Segoe UI',Tahoma,sans-serif;
        background:#0b1220; color:#dbe4f0; }}
 h1 {{ font-size:21px; margin:0 0 6px; }}
 h2 {{ font-size:15px; margin:20px 0 10px; color:#93c5fd; }}
 .meta {{ color:#8ba3c7; font-size:12.5px; line-height:1.9; }}
 .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
           gap:12px; margin:16px 0; }}
 .card {{ background:#111c31; border:1px solid #1e2f4d; border-radius:12px;
          padding:12px 16px; }}
 .card span {{ display:block; font-size:11.5px; color:#8ba3c7; margin-bottom:6px; }}
 .card b {{ font-size:20px; }}
 .card.crit b {{ color:#f87171; }}
 .card.warn b {{ color:#fbbf24; }}
 .card.info b {{ color:#4ade80; }}
 section {{ background:#0f1a2e; border:1px solid #1e2f4d;
            border-radius:14px; padding:18px; margin-bottom:16px; overflow-x:auto; }}
 table {{ width:100%; border-collapse:collapse; }}
 th {{ text-align:right; font-size:11.5px; color:#93b4dd; padding:7px 8px;
       border-bottom:1px solid #1e2f4d; white-space:nowrap; }}
 td {{ padding:8px; border-bottom:1px solid #16233b; font-size:12.5px;
       vertical-align:top; }}
 .path {{ color:#61789a; font-size:10.5px; direction:ltr; text-align:left;
          word-break:break-all; margin-top:2px; }}
 .err {{ color:#f87171; font-size:10.5px; margin-top:3px; }}
 .badge {{ display:inline-block; padding:2px 9px; border-radius:999px;
           font-size:11px; white-space:nowrap; }}
 .badge.critical {{ background:#3b1219; color:#fca5a5; border:1px solid #7f1d1d; }}
 .badge.warn {{ background:#3b2d0c; color:#fcd34d; border:1px solid #78350f; }}
 .badge.info {{ background:#0f2e1d; color:#86efac; border:1px solid #14532d; }}
 .note {{ color:#8ba3c7; font-size:12.5px; }}
 footer {{ color:#5f7595; font-size:11.5px; text-align:center; margin-top:18px; }}
</style></head><body>
<h1>فحص دفعات — {_esc(Path(result['root']).name or result['root'])}</h1>
<div class="meta">
  المسار: <code>{_esc(result['root'])}</code><br>
  المحللات: {_esc(analyzers)} — تكراري: {'نعم' if result['recursive'] else 'لا'}<br>
  أُنشئ: {_esc(result['generated'])}
</div>
{cards}
<section>{table}</section>
<footer>REPLATFORM — فحص دفعات (ليس بديلاً عن التحليل الكامل لكل ملف)</footer>
</body></html>"""
