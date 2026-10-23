"""لوحة تقرير HTML موحدة لكل مساحة عمل."""

from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime
from pathlib import Path

from .. import __version__
from ..core.export import html_to_pdf

VERDICT_LABEL = {"critical": "مرتفع", "warn": "متوسط", "info": "منخفض"}
VERDICT_CLASS = {"critical": "v-critical", "warn": "v-warn", "info": "v-info"}


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _table(headers: list[str], rows: list[list]) -> str:
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _section(title: str, content: str, note: str = "") -> str:
    note_html = f'<div class="note">{note}</div>' if note else ""
    return f'<section><h2>{_esc(title)}</h2>{note_html}{content}</section>'


def _pe_section(artifact: dict) -> str:
    summary = artifact.get("summary") or {}
    signature = artifact.get("signature") or {}
    protections = summary.get("protections") or {}
    active = ", ".join(
        label for label, key in
        (("ASLR", "aslr"), ("DEP", "dep"), ("CFG", "cfg"), ("HEA", "high_entropy_va"))
        if protections.get(key)
    ) or "لا شيء"

    facts = _table(
        ["الخاصية", "القيمة"],
        [
            ["المعمارية", summary.get("arch", "")],
            ["نقطة الدخول", summary.get("entry_point", "")],
            ["ImageBase", summary.get("image_base", "")],
            ["وقت البناء", summary.get("compile_time", "")],
            [".NET", "نعم" if summary.get("dotnet") else "لا"],
            ["الحمايات", active],
            ["التوقيع", f"{signature.get('status', '')} {signature.get('signer', '')}".strip()],
            ["بصمة الشهادة", signature.get("thumbprint", "") or "-"],
            ["انتهاء الشهادة", signature.get("not_after", "") or "-"],
            ["عدد دوال الاستيراد", summary.get("import_functions", 0)],
        ],
    )
    sections = _table(
        ["القسم", "الحجم الافتراضي", "الإنتروبيا"],
        [[s.get("name"), s.get("vsize"), s.get("entropy")] for s in summary.get("sections", [])],
    )
    imports = _table(
        ["المكتبة", "عدد الدوال"],
        [[i.get("dll"), i.get("functions")] for i in summary.get("imports", [])[:40]],
    )
    return facts + "<h3>الأقسام</h3>" + sections + "<h3>الاستيرادات</h3>" + imports


def _apk_section(artifact: dict) -> str:
    manifest = artifact.get("manifest") or {}
    signing = artifact.get("signing") or {}
    perms = manifest.get("permissions") or []
    components = manifest.get("components") or {}
    certs = signing.get("certs") or []
    facts = _table(
        ["الخاصية", "القيمة"],
        [
            ["الحزمة", manifest.get("package", "")],
            ["الإصدار", f"{manifest.get('version_name', '')} ({manifest.get('version_code', '')})"],
            ["minSdk / targetSdk", f"{manifest.get('min_sdk', '?')} / {manifest.get('target_sdk', '?')}"],
            ["النشاط الرئيسي", manifest.get("main_activity", "") or "غير محدد"],
            ["debuggable", "نعم" if (manifest.get("application") or {}).get("debuggable") else "لا"],
            ["usesCleartextTraffic", "نعم" if (manifest.get("application") or {}).get("cleartext") else "لا"],
            ["صلاحية التطبيق", (manifest.get("application") or {}).get("permission", "") or "لا شيء"],
            ["المكونات", f"أنشطة {components.get('activities', 0)} | خدمات {components.get('services', 0)} | مستقبلات {components.get('receivers', 0)} | مزودون {components.get('providers', 0)}"],
            ["مكونات مُصدّرة", manifest.get("exported", 0)],
            ["مُصدّرة بلا permission", manifest.get("exported_without_permission", 0)],
            ["exported بلا قيمة صريحة (31+)", manifest.get("exported_missing_explicit", 0)],
            ["التوقيع", ", ".join(signing.get("schemes") or [
                k for k in ("v1", "v2", "v3", "v3_1", "v4") if signing.get(k)
            ]) or "غير موقّع"],
            ["v4 sidecar", signing.get("v4_file", "") or "لا يوجد"],
            ["الشهادات", "; ".join(c.get("subject") or c.get("sha256", "")[:16] for c in certs) or "-"],
            ["المكتبات الأصلية", ", ".join(f"{abi} ({count})" for abi, count in (artifact.get("abis") or {}).items()) or "لا يوجد"],
        ],
    )
    perm_rows = [[p] for p in perms] or [["لا أذونات"]]
    return facts + "<h3>الأذونات (" + str(len(perms)) + ")</h3>" + _table(["الإذن"], perm_rows)


def _strings_section(artifact: dict) -> str:
    notable = artifact.get("notable") or {}
    parts = [f"<p>إجمالي: <b>{artifact.get('total', 0)}</b> — فريد: <b>{artifact.get('unique', 0)}</b></p>"]
    if notable:
        for label, values in notable.items():
            parts.append(f"<h3>{_esc(label)}</h3><ul>" +
                         "".join(f"<li><code>{_esc(v)}</code></li>" for v in values) + "</ul>")
    else:
        parts.append('<div class="note">لا مؤشرات بارزة.</div>')
    return "".join(parts)


def _yara_section(artifact: dict) -> str:
    if artifact.get("skipped"):
        return f'<div class="note">تم التخطي: {_esc(artifact.get("reason", ""))}</div>'
    matches = artifact.get("matches") or []
    head = f'<p>القواعد المفحوصة: <b>{artifact.get("rules_file_count", 0)}</b> — التطابقات: <b>{len(matches)}</b></p>'
    if not matches:
        return head + '<div class="note">لا تطابقات مع القواعد الحالية.</div>'
    rows = [[m.get("rule", ""), len(m.get("strings") or [])] for m in matches]
    parts = [head, _table(["القاعدة", "عدد التطابقات"], rows)]
    for match in matches[:15]:
        strings = match.get("strings") or []
        if not strings:
            continue
        parts.append(f'<h3>{_esc(match.get("rule", ""))}</h3><ul>' + "".join(
            f'<li><code>{_esc(s.get("id", ""))}</code> عند '
            f'<code>0x{int(s.get("offset", 0)):X}</code>: {_esc(s.get("data", ""))}</li>'
            for s in strings[:10]
        ) + "</ul>")
    return "".join(parts)


def _disasm_section(artifact: dict) -> str:
    if not artifact.get("available"):
        return f'<div class="note">غير متاح: {_esc(artifact.get("error", ""))}</div>'
    facts = _table(
        ["الخاصية", "القيمة"],
        [
            ["المعمارية", f'{artifact.get("arch", "?")} / {artifact.get("bits", "?")} بت'],
            ["عدد الدوال", artifact.get("function_count", 0)],
            ["المحرك", artifact.get("engine") or artifact.get("rizin", "")],
        ],
    )
    functions = artifact.get("top_functions") or []
    func_table = _table(
        ["الدالة", "الإزاحة", "الحجم"],
        [[f.get("name"), f.get("offset"), f.get("size")] for f in functions],
    ) if functions else ""
    entry = artifact.get("entry_disasm") or []
    entry_html = (
        f'<h3>تفكيك نقطة الدخول</h3><pre class="md">{_esc(chr(10).join(entry))}</pre>'
        if entry else ""
    )
    return facts + ("<h3>أهم الدوال</h3>" + func_table if func_table else "") + entry_html


def _ghidra_section(artifact: dict) -> str:
    if not artifact.get("available"):
        return f'<div class="note">غير متاح: {_esc(artifact.get("error", ""))}</div>'
    facts = _table(
        ["الخاصية", "القيمة"],
        [
            ["البرنامج", artifact.get("program", "")],
            ["اللغة", artifact.get("language", "")],
            ["ImageBase", artifact.get("image_base", "")],
            ["عدد الدوال", artifact.get("function_count", 0)],
            ["دوال فُكّت إلى pseudocode", artifact.get("decompiled_count", 0)],
            ["المحرك", artifact.get("engine", "")],
        ],
    )
    functions = artifact.get("top_functions") or []
    func_table = _table(
        ["الدالة", "العنوان", "الحجم"],
        [[f.get("name"), f.get("entry"), f.get("size")] for f in functions],
    ) if functions else ""
    code_parts: list[str] = []
    for function in functions[:4]:
        lines = function.get("pseudocode") or []
        if lines:
            code_parts.append(
                f'<h3>{_esc(function.get("name", ""))} — pseudocode</h3>'
                f'<pre class="md">{_esc(chr(10).join(lines))}</pre>'
            )
    entry = artifact.get("entry_disasm") or []
    entry_html = (
        f'<h3>تفكيك نقطة الدخول</h3><pre class="md">{_esc(chr(10).join(entry))}</pre>'
        if entry else ""
    )
    return (
        facts
        + ("<h3>أهم الدوال</h3>" + func_table if func_table else "")
        + "".join(code_parts)
        + entry_html
    )


def _agent_section(ws) -> str:
    result = ws.load_agent("result")
    llm = ws.load_agent("llm")
    parts: list[str] = []
    if result:
        summary = result.get("summary_md") or ""
        meta = _table(
            ["الوضع", "النموذج", "الحكم", "الدرجة"],
            [[result.get("mode", ""), result.get("model", ""),
              VERDICT_LABEL.get(result.get("verdict", ""), result.get("verdict", "")),
              result.get("score", "")]],
        )
        parts.append(meta)
        parts.append(f'<pre class="md">{_esc(summary)}</pre>')
    if llm and llm.get("answer"):
        parts.append("<h3>إجابة النموذج اللغوي</h3>")
        parts.append(f'<pre class="md">{_esc(llm["answer"])}</pre>')
    if not parts:
        return '<div class="note">لم يُشغَّل وكيل التحليل.</div>'
    return "".join(parts)


def _timeline_section(events: list[dict]) -> str:
    if not events:
        return '<div class="note">لا أحداث.</div>'
    rows = [[e.get("ts", ""), e.get("message", "")] for e in events]
    return _table(["الوقت", "الحدث"], rows)


def render(ws) -> Path:
    meta = ws.meta
    target = meta.get("target") or {}
    artifacts = ws.all_artifacts()
    agent = ws.load_agent("result") or {}
    verdict = agent.get("verdict", "info")
    score = agent.get("score", max((a.get("score", 0) for a in artifacts.values()), default=0))
    findings = agent.get("findings") or [
        f for a in artifacts.values() for f in (a.get("findings") or [])
    ]

    cards = f"""
<div class="cards">
  <div class="card {VERDICT_CLASS.get(verdict, 'v-info')}">
    <span>الحكم</span><b>{_esc(VERDICT_LABEL.get(verdict, verdict))}</b>
  </div>
  <div class="card"><span>درجة الخطورة</span><b>{_esc(score)}/10</b></div>
  <div class="card"><span>النتائج</span><b>{len(findings)}</b></div>
  <div class="card"><span>المحللات</span><b>{len(artifacts)}</b></div>
</div>"""

    body: list[str] = []
    if "pe" in artifacts and not artifacts["pe"].get("error"):
        body.append(_section("تحليل PE", _pe_section(artifacts["pe"])))
    if "apk" in artifacts and not artifacts["apk"].get("error"):
        body.append(_section("تحليل APK", _apk_section(artifacts["apk"])))
    if "disasm" in artifacts and not artifacts["disasm"].get("error"):
        body.append(_section("تفكيك بدون واجهة (Rizin)", _disasm_section(artifacts["disasm"])))
    if "yara" in artifacts and not artifacts["yara"].get("error"):
        body.append(_section("قواعد YARA", _yara_section(artifacts["yara"])))
    if "ghidra" in artifacts and not artifacts["ghidra"].get("error"):
        body.append(_section("Ghidra headless", _ghidra_section(artifacts["ghidra"])))
    if "strings" in artifacts and not artifacts["strings"].get("error"):
        body.append(_section("المؤشرات النصية", _strings_section(artifacts["strings"])))
    body.append(_section("الوكيل الذكي", _agent_section(ws)))
    body.append(_section("الخط الزمني", _timeline_section(ws.timeline())))

    page = f"""<!DOCTYPE html>
<html dir="rtl" lang="ar"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>REPLATFORM — {_esc(meta.get('name', ''))}</title>
<style>
 :root {{ color-scheme: dark; }}
 * {{ box-sizing: border-box; }}
 body {{ margin:0; padding:24px; font-family:'Segoe UI',Tahoma,sans-serif;
        background:#0b1220; color:#dbe4f0; }}
 header {{ margin-bottom:20px; }}
 h1 {{ font-size:22px; margin:0 0 6px; }}
 h2 {{ font-size:17px; margin:0 0 12px; color:#93c5fd; }}
 h3 {{ font-size:14px; margin:16px 0 8px; color:#a5b4fc; }}
 .meta {{ color:#8ba3c7; font-size:13px; line-height:1.9; }}
 .meta code {{ background:#111c31; padding:1px 6px; border-radius:5px; }}
 .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
           gap:12px; margin:18px 0 22px; }}
 .card {{ background:#111c31; border:1px solid #1e2f4d; border-radius:12px;
          padding:12px 16px; }}
 .card span {{ display:block; font-size:12px; color:#8ba3c7; margin-bottom:6px; }}
 .card b {{ font-size:22px; }}
 .v-critical b {{ color:#f87171; }} .v-warn b {{ color:#fbbf24; }}
 .v-info b {{ color:#4ade80; }}
 section {{ background:#0f1a2e; border:1px solid #1e2f4d; border-radius:14px;
            padding:18px; margin-bottom:16px; }}
 table {{ width:100%; border-collapse:collapse; margin:6px 0 4px; }}
 th {{ text-align:right; font-size:12px; color:#93b4dd; padding:7px 8px;
       border-bottom:1px solid #1e2f4d; }}
 td {{ padding:7px 8px; border-bottom:1px solid #16233b; font-size:13px;
       vertical-align:top; }}
 td:first-child {{ color:#9fb3d1; }}
 code {{ font-family:Consolas,monospace; direction:ltr; display:inline-block;
         background:#111c31; padding:1px 6px; border-radius:5px; font-size:12px; }}
 ul {{ margin:4px 0 10px; padding-inline-start:20px; }}
 li {{ margin:2px 0; font-size:13px; }}
 pre.md {{ background:#111c31; border:1px solid #1e2f4d; border-radius:10px;
           padding:14px; white-space:pre-wrap; font-size:13px; line-height:1.8; }}
 .note {{ color:#8ba3c7; font-size:13px; }}
 footer {{ color:#5f7595; font-size:12px; text-align:center; margin-top:20px; }}
</style></head><body>
<header>
  <h1>تقرير REPLATFORM — {_esc(meta.get('name', ''))}</h1>
  <div class="meta">
    الهدف: <code>{_esc(target.get('path', ''))}</code><br>
    النوع: {_esc(meta.get('kind', ''))} — الحجم: {_esc(meta.get('size_human', ''))}<br>
    SHA256: <code>{_esc(meta.get('sha256', ''))}</code><br>
    أُنشئ: {_esc(meta.get('created', ''))} — مساحة العمل: <code>{_esc(ws.id)}</code>
  </div>
</header>
{cards}{''.join(body)}
<footer>REPLATFORM v{_esc(meta.get('version', '1.0.0'))} — وُلّد {datetime.now():%Y-%m-%d %H:%M}</footer>
</body></html>"""

    out = ws.path / "report.html"
    out.write_text(page, "utf-8")
    ws.add_event("report", "توليد تقرير HTML")
    return out


def export_json(ws) -> Path:
    """تقرير JSON كامل للتدقيق/الأتمتة، مع بصمة SHA256 للـ HTML."""
    html_path = render(ws)
    payload = {
        "format": "replatform-report",
        "version": __version__,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "meta": ws.safe_meta(),
        "artifacts": ws.all_artifacts(),
        "agent": ws.load_agent("result"),
        "agent_llm": ws.load_agent("llm"),
        "timeline": ws.timeline(),
        "html_sha256": hashlib.sha256(html_path.read_bytes()).hexdigest(),
    }
    out = ws.path / "report.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), "utf-8")
    ws.add_event("report_json", "تصدير تقرير JSON")
    return out


def export_pdf(ws) -> Path:
    """تقرير PDF مع دعم العربية عبر Edge/Chrome headless."""
    html_path = render(ws)
    out = ws.path / "report.pdf"
    html_to_pdf(html_path, out)
    ws.add_event("report_pdf", "تصدير تقرير PDF")
    return out
