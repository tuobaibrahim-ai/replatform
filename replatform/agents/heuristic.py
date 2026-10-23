"""الوكيل الاستكشافي بلا نموذج لغوي: تحليل آلي + استنتاج قواعدي."""

from __future__ import annotations

from datetime import datetime


def _bullet(items: list[str], empty: str = "لا يوجد") -> str:
    return "\n".join(f"- {item}" for item in items) if items else empty


def triage(ws, target_meta: dict, artifacts: dict[str, dict]) -> dict:
    """يبني تقريراً استنتاجياً من مخرجات المحللات — يعمل بدون API."""
    name = target_meta.get("name", "الهدف")
    kind = target_meta.get("kind", "")
    sha = target_meta.get("sha256", "")
    size = target_meta.get("size", 0)

    findings: list[str] = []
    next_steps: list[str] = []
    score = 0
    verdict = "info"

    for artifact in artifacts.values():
        if artifact.get("error"):
            findings.append(f"[{artifact.get('analyzer')}] خطأ: {artifact['error']}")
            continue
        score = max(score, int(artifact.get("score") or 0))
        findings.extend(artifact.get("findings") or [])

    if score >= 5:
        verdict = "critical"
    elif score >= 2:
        verdict = "warn"

    if kind == "PE":
        pe = artifacts.get("pe") or {}
        summary = pe.get("summary") or {}
        prot = summary.get("protections") or {}
        enabled = [label for label, key in
                   (("ASLR", "aslr"), ("DEP", "dep"), ("CFG", "cfg"), ("HEA", "high_entropy_va"))
                   if prot.get(key)]
        next_steps = [
            "افتح الملف في Cutter: `cutter <file>` لخريطة الاستدعاءات",
            "شغّل `diec <file>` لتأكيد المُجمِّع/الحزمة",
            "قارن SHA256 في VirusTotal (للفحص الخارجي)",
        ]
        extra = [
            f"المعمارية: {summary.get('arch', '?')}",
            f"نقطة الدخول: {summary.get('entry_point', '?')}",
            f"حمايات مفعّلة: {', '.join(enabled) or 'لا شيء'}",
            f"عدد الاستيرادات: {summary.get('import_functions', 0)} دالة",
        ]
    elif kind == "APK":
        apk = artifacts.get("apk") or {}
        manifest = apk.get("manifest") or {}
        next_steps = [
            "اعرض الكود: `jadx <file> -d out`",
            "افك التغليف للتعديل: `apktool d <file> -o decoded`",
            "راجع المكونات المُصدّرة قبل النشر",
        ]
        extra = [
            f"الحزمة: {manifest.get('package', '?')}",
            f"الإصدار: {manifest.get('version_name', '?')}",
            f"minSdk/targetSdk: {manifest.get('min_sdk', '?')}/{manifest.get('target_sdk', '?')}",
            f"عدد الأذونات: {len(manifest.get('permissions') or [])}",
            f"مكوّنات مُصدّرة: {manifest.get('exported', 0)}",
        ]
    else:
        extra = [f"النوع المكتشف: {kind or 'غير معروف'}"]
        next_steps = ["حدد نوع الملف بدقة قبل أي تحليل أعمق"]

    strings = artifacts.get("strings") or {}
    notable = strings.get("notable") or {}
    if notable:
        extra.append(f"مؤشرات نصية: {', '.join(notable.keys())}")

    summary_md = "\n".join([
        f"# خلاصة تحليل: {name}",
        "",
        f"- النوع: {kind or 'غير معروف'}",
        f"- الحجم: {size:,} بايت",
        f"- SHA256: `{sha}`",
        f"- درجة الخطورة: {score}/10 — { {'critical': 'مرتفع', 'warn': 'متوسط', 'info': 'منخفض'}[verdict] }",
        f"- وقت التوليد: {datetime.now():%Y-%m-%d %H:%M}",
        "",
        "## حقائق",
        _bullet(extra),
        "",
        "## نتائج",
        _bullet(findings),
        "",
        "## خطوات تالية",
        _bullet(next_steps),
    ]) + "\n"

    result = {
        "mode": "heuristic",
        "model": "rules-v1",
        "verdict": verdict,
        "score": score,
        "findings": findings,
        "next_steps": next_steps,
        "summary_md": summary_md,
        "generated": datetime.now().isoformat(timespec="seconds"),
    }
    ws.write_text("agent/summary.md", summary_md)
    ws.save_agent("result", result)
    ws.add_event("agent_done", "تحليل استكشافي قواعدي", {"verdict": verdict, "score": score})
    return result
