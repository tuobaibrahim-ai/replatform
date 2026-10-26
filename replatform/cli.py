"""واجهة سطر الأوامر الموحدة لمنصة REPLATFORM."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from . import __version__
from .agents import heuristic
from .agents.loop import run_agent
from .agents.provider import ProviderError, build_provider
from .analyzers import Target, load_analyzers, run_analyzers
from .core import state
from .core import stdio
from .core.config import (
    CONFIG_PATH,
    ROOT,
    api_key,
    load_config,
    mask_secret,
    save_config,
)
from .core.config import ConfigMigrationError
from .core.config import migrate_config_file
from .core.export import html_to_pdf
from .core.registry import detect_tools
from .core.workspace import Workspace
from .reports import export_json, export_pdf, render
from .tools import apk_tools, benchmark, bindiff, doctor, enterprise, licensing, patcher, sandbox
from .tools import upgrade as upgrade_tool

try:
    for _stream in (sys.stdout, sys.stderr):
        _reconfigure = getattr(_stream, "reconfigure", None)
        if callable(_reconfigure):
            _reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass


def _color(text: str, code: str) -> str:
    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        return f"\033[{code}m{text}\033[0m"
    return text


def _ok(text: str) -> str:
    return _color(text, "32")


def _warn(text: str) -> str:
    return _color(text, "33")


def _err(text: str) -> str:
    return _color(text, "31")


def _cyan(text: str) -> str:
    return _color(text, "36")


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    out = [line, "-" * len(line)]
    for row in rows:
        out.append("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(out)


def _resolve_target(arg: str | None) -> Path:
    """يستخدم المسار الممرَّر أو الملف الحالي المحدد بـ use."""
    if arg:
        return Path(arg)
    current = state.get_target()
    if current:
        return current
    raise FileNotFoundError(
        "لم تحدد ملفاً. استخدم: python repl.py use <ملف>  أو مرّر المسار مباشرة."
    )


# --------------------------------------------------------------------------
# الأوامر
# --------------------------------------------------------------------------

def cmd_tools(_args) -> int:
    tools = detect_tools()
    print(_cyan("أدوات المنصة:"))
    for tool in tools:
        mark = _ok("✓") if tool["ok"] else _err("✗")
        version = tool["version"] or "غير متاح"
        print(f"  {mark} {tool['name']:<16} {version}")
    return 0


def cmd_inventory(args) -> int:
    script = ROOT / "agents" / "inventory_agent.ps1"
    if not script.exists():
        print(_err("سكربت الجرد غير موجود."), file=sys.stderr)
        return 1
    out = args.out or str(ROOT / "agents" / "out" / "installed.csv")
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-OutCsv", out]
    return subprocess.call(cmd)


def _agent_context(results: dict, limit: int = 3000) -> str:
    """ملخص مضغوط من المحللات ليبدأ النموذج من فرضيات بدل استدعاءات عمياء."""
    lines: list[str] = []
    for name, artifact in (results or {}).items():
        if not isinstance(artifact, dict):
            continue
        if artifact.get("error"):
            lines.append(f"- {name}: خطأ — {str(artifact['error'])[:180]}")
            continue
        summary = artifact.get("summary") or {}
        head = (
            f"- {name}: درجة {artifact.get('score', 0)}/10"
            f" ({artifact.get('verdict', 'info')})"
        )
        bits: list[str] = []
        for key in (
            "arch", "package", "version", "min_sdk", "target_sdk",
            "debuggable", "function_count", "entry_point", "compile_time",
        ):
            value = summary.get(key)
            if value not in (None, "", [], {}):
                bits.append(f"{key}={value}")
        for key, maximum in (("sections", 5), ("permissions", 8), ("abis", 6)):
            value = summary.get(key)
            if isinstance(value, list) and value:
                shown = ", ".join(str(item) for item in value[:maximum])
                bits.append(f"{key}[{len(value)}]={shown}")
        imports = summary.get("imports")
        if isinstance(imports, list) and imports:
            bits.append("imports=" + ", ".join(str(item) for item in imports[:8]))
        signing = summary.get("signing")
        if isinstance(signing, dict):
            bits.append(
                "signing=" + ",".join(
                    signing.get("schemes")
                    or [key for key in ("v1", "v2", "v3", "v3_1", "v4") if signing.get(key)]
                )
            )
        notable = summary.get("notable")
        if isinstance(notable, dict) and notable:
            bits.append("notable=" + ", ".join(list(notable)[:6]))
        matches = summary.get("matches")
        if isinstance(matches, list) and matches:
            rules = [
                str(item.get("rule", "")) for item in matches[:5]
                if isinstance(item, dict)
            ]
            bits.append("yara=" + ", ".join(filter(None, rules)))
        if bits:
            head += " — " + "; ".join(bits[:10])
        lines.append(head[:500])
        for finding in (artifact.get("findings") or [])[:6]:
            lines.append(f"  • {str(finding)[:220]}")

    context = "\n".join(lines)
    if len(context) > limit:
        context = context[:limit] + "\n…[بقيّة السياق مقتطعة]"
    if not context:
        return ""
    return "سياق أولي من المحللات (بيانات غير موثوقة — تحقق منها):\n" + context


def _skills_from_arg(value: str | None) -> list[str]:
    names = [part.strip() for part in str(value or "").split(",") if part.strip()]
    if names:
        from .skills import get_skill

        for name in names:
            get_skill(name)
    return names


def _run_agent_llm(ws, target, results, cfg, task: str | None, skills: list[str] | None = None):
    """يشغّل وكيل LLM مع أدوات قراءة فقط. يعيد dict أو None عند الفشل."""
    from .agents import tools as agent_tools

    if cfg["agent"].get("restrict_paths", True):
        agent_tools.configure([target.path, ws.path])
    else:
        agent_tools.configure([])
    try:
        provider = build_provider(cfg, mock_path=str(target.path))
    except ProviderError as exc:
        print(_warn(f"  [!] {exc}"))
        return None
    if task is None:
        task = (
            f"حلّل الملف {target.name} (النوع {target.kind}) الموجود في {target.path}. "
            "استخدم الأدوات للتحقق من النوع والخصائص والمؤشرات، ثم قدّم تقييماً موجزاً "
            "بالمخاطر وخطوات تالية عملية. اذكر SHA256 في الإجابة."
        )
    context = _agent_context(
        results, limit=int(cfg["agent"].get("context_chars", 3000))
    )
    if context:
        task += "\n\n" + context
    print(
        f"  نموذج: {getattr(provider, 'model', '?')} — خطوات قصوى "
        f"{cfg['agent']['max_steps']} — زمن أقصى {cfg['agent'].get('max_seconds', 300)}ث"
    )
    try:
        outcome = run_agent(
            task, provider,
            max_steps=int(cfg["agent"]["max_steps"]),
            max_tool_calls=int(cfg["agent"].get("max_tool_calls", 8)),
            max_seconds=float(cfg["agent"].get("max_seconds", 300)),
            max_context_chars=int(cfg["agent"].get("max_context_chars", 60_000)),
            max_tool_result_chars=int(cfg["agent"].get("max_tool_result_chars", 6_000)),
            skills=skills,
        )
    except ProviderError as exc:
        print(_warn(f"  [!] تعذر إكمال الوكيل: {exc}"))
        return None
    usage = outcome.get("usage") or {}
    if usage.get("total_tokens"):
        print(
            f"  tokens: {usage['total_tokens']} "
            f"(prompt {usage.get('prompt_tokens', 0)}, "
            f"completion {usage.get('completion_tokens', 0)})"
        )
    if outcome.get("context_tokens") is not None:
        print(
            f"  سياق: {outcome['context_tokens']} توكن "
            f"({outcome.get('tokenizer', '')})"
        )
    print(f"  الزمن: {outcome.get('seconds', 0)}ث")
    answer = outcome.get("answer") or ""
    ws.save_agent("llm", {
        "mode": "llm",
        "model": outcome.get("model"),
        "status": outcome.get("status"),
        "answer": answer,
        "usage": usage,
        "context_tokens": outcome.get("context_tokens"),
        "tokenizer": outcome.get("tokenizer"),
        "seconds": outcome.get("seconds"),
        "steps": [
            {"tool": s["tool"], "args": s["args"],
             "result": (json.dumps(s["result"], ensure_ascii=False)[:1500])}
            for s in outcome.get("steps", [])
        ],
    })
    ws.write_text("agent/answer.md", answer + "\n")
    ws.add_event("agent_llm", "تشغيل وكيل النموذج اللغوي", {"model": outcome.get("model")})
    return outcome


def cmd_analyze(args) -> int:
    cfg = load_config()
    skills = _skills_from_arg(getattr(args, "skill", None))
    target = Target.from_path(
        _resolve_target(args.target),
        max_mb=int(cfg["analysis"].get("max_file_mb", 1024)),
    )
    only = {n.strip() for n in args.only.split(",")} if args.only else None
    if only is not None:
        known = {analyzer.name for analyzer in load_analyzers()}
        unknown = only - known
        if unknown:
            raise ValueError(
                f"محللات غير معروفة: {', '.join(sorted(unknown))} — المتاح: {', '.join(sorted(known))}"
            )
    ws = Workspace.create(
        target.path,
        name=args.name,
        extra={
            "kind": target.kind,
            "size": target.size,
            "size_human": f"{target.size:,}",
            "sha256": target.sha256,
        },
    )
    ws.update_meta(kind=target.kind, size=target.size,
                   size_human=f"{target.size:,}", sha256=target.sha256)

    print(_cyan(f"=== تحليل: {target.name} ==="))
    print(f"  النوع: {target.kind} — {target.size:,} بايت")
    print(f"  SHA256: {target.sha256}")
    print(f"  مساحة العمل: {ws.id}\n")

    print(_cyan("[1/3] المحللات:"))
    results = run_analyzers(target, ws, only)
    if not results:
        print(_warn("  لا محلل ينطبق على هذا النوع."))
    for name, result in results.items():
        if result.get("error"):
            print(f"  {_err('✗')} {name}: {result['error']}")
        else:
            print(f"  {_ok('✓')} {name} ({result.get('seconds', 0)}ث)")

    print(_cyan("\n[2/3] وكيل التحليل:"))
    result = heuristic.triage(ws, {
        "name": target.name, "kind": target.kind,
        "sha256": target.sha256, "size": target.size,
    }, results)
    print(f"  الوضع: قواعدي — الحكم: {result['verdict']} ({result['score']}/10)")

    mode = args.agent or cfg["agent"]["default_mode"]
    if mode == "llm":
        outcome = _run_agent_llm(ws, target, results, cfg, args.task, skills)
        if outcome:
            print(f"  الإجابة: {outcome['answer'][:200]}")
    elif mode == "none":
        print("  (تم التخطي)")

    print(_cyan("\n[3/3] التقرير:"))
    report = render(ws)
    print(f"  {_ok('✓')} {report}")
    print(f"\nلعرضه: {_cyan(f'python repl.py ws open {ws.id}')}")
    if args.open:
        os.startfile(report) if os.name == "nt" else None
    return 0


def cmd_agent(args) -> int:
    """تحليل كامل + مهمة مخصصة للوكيل."""
    cfg = load_config()
    skills = _skills_from_arg(getattr(args, "skill", None))
    target = Target.from_path(
        _resolve_target(args.target),
        max_mb=int(cfg["analysis"].get("max_file_mb", 1024)),
    )
    ws = Workspace.create(
        target.path, name=f"agent-{target.name}",
        extra={"kind": target.kind, "size": target.size,
               "size_human": f"{target.size:,}", "sha256": target.sha256},
    )
    print(_cyan(f"=== وكيل REPLATFORM — {target.name} ==="))
    print(f"  المهمة: {args.task or '(تحليل عام)'}\n")

    results = run_analyzers(target, ws)
    heuristic.triage(ws, {"name": target.name, "kind": target.kind,
                          "sha256": target.sha256, "size": target.size}, results)

    mode = args.mode or cfg["agent"]["default_mode"]
    if mode == "llm":
        outcome = _run_agent_llm(ws, target, results, cfg, args.task, skills)
        if outcome:
            print(outcome.get("answer") or outcome.get("status"))
        else:
            print(_warn("تعذر تشغيل النموذج — استخدم التقرير القواعدي."))
    else:
        summary = (ws.agent_dir / "summary.md").read_text("utf-8")
        print(summary)

    report = render(ws)
    print(_ok(f"\n✓ التقرير: {report}"))
    return 0


def cmd_use(args) -> int:
    data = state.set_target(args.path)
    print(_ok(f"✓ الملف المستهدف: {data['target']}"))
    print(f"  النوع: {data['kind']} — الحجم: {data['size']:,} بايت")
    if data["sha256"]:
        print(f"  SHA256: {data['sha256']}")
    print("\nالخطوات التالية:")
    print(f"  {_cyan('python repl.py analyze')}            تحليل كامل (بلا مسار)")
    print(f"  {_cyan('python repl.py agent --mode llm')}   وكيل ذكي على الملف الحالي")
    patch_hint = _cyan('python repl.py patch --find "str:X" --replace "str:Y"')
    print(f"  {patch_hint}")
    if data["kind"] == "APK":
        print(f"  {_cyan('python repl.py apk decode')}         فك APK (smali + موارد)")
        print(f"  {_cyan('python repl.py apk java')}           كود Java للقراءة/التطوير")
        print(f"  {_cyan('python repl.py apk build <مجلد>')}   إعادة بناء")
        print(f"  {_cyan('python repl.py apk sign <ملف>')}     توقيع")
        print(f"  {_cyan('python repl.py apk install <ملف>')}  تثبيت على جهاز متصل")
    return 0


def cmd_current(_args) -> int:
    data = state.get_state()
    if not data.get("target"):
        print("لا ملف مستهدف. استخدم: python repl.py use <ملف>")
        return 0
    print(f"الملف: {data['target']}")
    print(f"النوع: {data['kind']} — الحجم: {int(data.get('size') or 0):,} بايت")
    if data.get("sha256"):
        print(f"SHA256: {data['sha256']}")
    print(f"حُدّد: {data.get('set_at', '')}")
    return 0


def cmd_patch(args) -> int:
    target = _resolve_target(args.target)
    result = patcher.patch(
        target, args.find, args.replace,
        encoding=args.enc, apply=args.apply, all_matches=args.all,
        allow_system=args.allow_system, allow_resize=args.allow_resize,
        max_show=args.max_show,
    )
    print(_cyan(f"=== تعديل: {Path(result['file']).name} ==="))
    print(f"  الملف: {result['file']}")
    print(f"  الحجم: {result['size']:,} بايت")
    print(f"  SHA256 (قبل): {result['sha256_before']}")
    print(f"  التطابقات: {result['count']}\n")
    if not result["count"]:
        print(_warn("لا تطابقات — لم يتغير شيء."))
        return 1
    for index, match in enumerate(result["matches"], 1):
        print(f"  #{index}  {match['offset_hex']}")
        print(f"      {match['context']}")
    if result["count"] > len(result["matches"]):
        print(f"  ... و{result['count'] - len(result['matches'])} تطابق آخر")
    if result.get("length_warning"):
        print(_warn("\n⚠ طول الاستبدال يختلف عن البحث — قد تتأثر إزاحات الملف."))
    if result.get("rolled_back"):
        print(_err("\n✗ فشل التحقق بعد الكتابة — أُعيدت النسخة الأصلية تلقائياً."))
        if result.get("pe_error"):
            print(_err(f"  PE: {result['pe_error']}"))
        if result.get("zip_error"):
            print(_err(f"  ZIP: {result['zip_error']}"))
        if result.get("rollback_error"):
            print(_err(f"  تعذر الاسترجاع: {result['rollback_error']}"))
            print(f"  استرجع يدوياً من: {result.get('backup', '')}")
        return 2
    if not result["applied"]:
        print(_warn("\n[معاينة فقط] لم يُكتب شيء. أضف --apply للتنفيذ (نسخة احتياطية تلقائية)."))
        return 0
    print(_ok(f"\n✓ نُفّذ {result['replaced']} استبدال."))
    print(f"  نسخة احتياطية: {result['backup']}")
    print(f"  SHA256 (بعد): {result.get('sha256_after', '')}")
    if result.get("pe_valid") is True:
        print(_ok(f"✓ بنية PE سليمة — نقطة الدخول {result['entry_point']}"))
    elif result.get("pe_valid") is False:
        print(_err(f"✗ بنية PE تالفة: {result.get('pe_error')}"))
        print("  استرجع النسخة الاحتياطية أعلاه.")
        return 2
    if result.get("zip_valid") is True:
        print(_ok("✓ بنية ZIP/APK سليمة (اجتاز فحص CRC)"))
    elif result.get("zip_valid") is False:
        print(_err(f"✗ بنية ZIP/APK تالفة: {result.get('zip_error')}"))
        return 2
    print("ℹ إن كان الملف موقّعاً فقد بُطل التوقيع — أعد توقيعه عند الحاجة.")
    return 0


def cmd_apk(args) -> int:
    action = args.action
    if action == "devices":
        result = apk_tools.devices()
    elif action == "build":
        if not args.target:
            raise FileNotFoundError("حدد مجلد المشروع: python repl.py apk build <مجلد>")
        result = apk_tools.build(args.target, args.out)
    else:
        target = _resolve_target(args.target)
        if action == "decode":
            result = apk_tools.decode(target, args.out, force=args.force)
        elif action == "sign":
            result = apk_tools.sign(target, args.out)
        elif action == "java":
            result = apk_tools.java_src(target, args.out)
        elif action == "install":
            result = apk_tools.install(target)
        else:
            print(_err(f"إجراء غير معروف: {action}"))
            return 1

    status = _ok("✓ نجح") if result.get("ok") else _err("✗ فشل")
    print(f"=== APK {action} — {status} ===")
    if result.get("output"):
        print(f"  الناتج: {result['output']}")
    if result.get("manifest") is not None:
        print(f"  البيان: {'موجود' if result['manifest'] else 'مفقود'}")
    if result.get("java_files") is not None:
        print(f"  ملفات Java: {result['java_files']:,}")
    if result.get("error_count") is not None:
        print(f"  أخطاء فك جزئية: {result['error_count']} (طبيعية في التطبيقات الكبيرة)")
    if result.get("signed") is not None:
        print(f"  موقّع: {'نعم' if result['signed'] else 'لا'}")
    if result.get("error"):
        print(_err(f"  خطأ: {result['error']}"))
    for stream in ("stdout", "stderr"):
        text = (result.get(stream) or "").strip()
        if text:
            print(f"  [{stream}]\n{text}")
    return 0 if result.get("ok") else 2


def cmd_diff(args) -> int:
    print(_cyan("=== مقارنة نسختين (bin-diff) ==="))
    result = bindiff.run(args.a, args.b)
    a, b = result["a"], result["b"]
    print(f"  A: {a['path']}")
    print(f"  B: {b['path']}")
    print(f"  النوع: {a['kind']} — الحجم: {a['size']:,} → {b['size']:,} ({result['size_delta']:+,})")
    if result.get("identical"):
        print("  الملفان متطابقان تماماً (SHA256 نفسه)")
    elif result["similarity"] is not None:
        method = bindiff.METHOD_LABEL.get(
            result.get("similarity_method", ""), result.get("similarity_method", "")
        )
        print(f"  التشابه: {result['similarity']}% — {method}")
    if result.get("pe"):
        pe = result["pe"]
        if pe.get("skipped"):
            print(_warn(f"  PE: {pe.get('reason', 'تم تخطي التحليل العميق')}"))
        else:
            changed = [s for s in pe["sections"] if s["status"] != "same"]
            print(f"  أقسام متغيرة/مضافة/محذوفة: {len(changed)}")
            added = sum(len(v) for v in pe["imports"]["added"].values())
            removed = sum(len(v) for v in pe["imports"]["removed"].values())
            print(f"  استيرادات مضافة: {added} — محذوفة: {removed}")
    if result.get("apk"):
        apk = result["apk"]
        if apk.get("skipped"):
            print(_warn(f"  APK: {apk.get('reason', 'تم تخطي التحليل العميق')}"))
        else:
            files = apk["files"]
            print(
                f"  أذونات مضافة: {len(apk['permissions']['added'])} — "
                f"محذوفة: {len(apk['permissions']['removed'])}"
            )
            print(
                f"  ملفات: +{files['added_count']} / "
                f"-{files['removed_count']} / ~{files['changed_count']}"
            )
            print(f"  التوقيع: {apk['signing']['a']} → {apk['signing']['b']}")
    for item in result.get("highlights") or []:
        print(_warn(f"  ⚠ {item}"))
    print(_ok(f"\n✓ التقرير: {result['report']}"))
    if args.pdf:
        pdf = html_to_pdf(result["report"], Path(result["report"]).with_suffix(".pdf"))
        result["pdf"] = str(pdf)
        print(_ok(f"✓ PDF: {pdf}"))
    if args.open and os.name == "nt":
        os.startfile(result.get("pdf") or result["report"])
    return 0


def cmd_ghidra(args) -> int:
    from .tools import ghidra_tools

    if not ghidra_tools.available():
        print(_err("Ghidra غير مثبت (لم يُعثر على analyzeHeadless)."))
        print("  ضع نسخة Ghidra في tools\\ghidra\\<version>\\ أو ثبّتها في Program Files.")
        return 2
    target = Target.from_path(
        _resolve_target(args.target),
        max_mb=int(load_config()["analysis"].get("ghidra_max_mb", 150)),
    )
    if target.kind not in ("PE", "ELF"):
        print(_err("Ghidra في هذه المنصة يدعم PE/ELF فقط."))
        return 2
    ws = Workspace.create(
        target.path, name=f"ghidra-{target.name}",
        extra={"kind": target.kind, "size": target.size,
               "size_human": f"{target.size:,}", "sha256": target.sha256},
    )
    print(_cyan(f"=== Ghidra headless: {target.name} ==="))
    print("  جارٍ التحليل المتقدم… قد يستغرق دقائق حسب حجم الملف.\n")
    renames: dict[str, str] = {}
    for item in args.rename or []:
        if "=" not in item:
            raise ValueError(f"صيغة إعادة التسمية يجب أن تكون old=new: {item}")
        old, new = item.split("=", 1)
        renames[old] = new
    artifact = ghidra_tools.analyze(
        str(target.path),
        decompile=not args.no_decompile,
        decompile_limit=args.decompile_limit,
        renames=renames,
    )
    artifact["score"] = 0
    artifact["verdict"] = "info"
    findings: list[str] = []
    if artifact.get("error"):
        findings.append(f"Ghidra: {artifact['error']}")
    elif artifact.get("function_count"):
        findings.append(f"Ghidra: {artifact['function_count']} دالة")
        if artifact.get("decompiled_count"):
            findings.append(f"Ghidra: {artifact['decompiled_count']} pseudocode")
    artifact["findings"] = findings
    ws.save_artifact("ghidra", artifact)
    results = {"ghidra": artifact}
    if artifact.get("error"):
        print(_err(f"  ✗ {artifact['error']}"))
        if artifact.get("log"):
            print(artifact["log"][-800:])
        return 2

    heuristic.triage(ws, {"name": target.name, "kind": target.kind,
                          "sha256": target.sha256, "size": target.size}, results)
    print(f"  البرنامج: {artifact.get('program', '')} — اللغة: {artifact.get('language', '')}")
    print(f"  عدد الدوال: {artifact.get('function_count', 0)} — "
          f"pseudocode: {artifact.get('decompiled_count', 0)} — "
          f"أُعيدت تسميتها: {artifact.get('renamed_count', 0)}")
    for function in (artifact.get("top_functions") or [])[:8]:
        print(f"    {function.get('name')}  {function.get('entry')}  ({function.get('size')} بايت)")
    for function in (artifact.get("top_functions") or []):
        code = function.get("pseudocode") or []
        if code:
            print(f"\n  pseudocode — {function.get('name')}:")
            for line in code[:8]:
                print(f"    {line}")
            break
    entry = artifact.get("entry_disasm") or []
    if entry:
        print("\n  تفكيك نقطة الدخول:")
        for line in entry[:10]:
            print(f"    {line}")
    report = render(ws)
    print(_ok(f"\n✓ التقرير: {report}"))
    return 0


def cmd_benchmark(args) -> int:
    print(_cyan("=== تقييم قبول الوكيل (بلا شبكة) ==="))
    result = benchmark.run_benchmark()
    for case in result["cases"]:
        mark = _ok("✓") if case["ok"] else _err("✗")
        detail = case["detail"] if case["ok"] else case["error"]
        print(f"  {mark} {case['case']:<14} {case['seconds']:>5.2f}ث — {detail}")
    print(
        f"\n  النتيجة: {result['passed']}/{result['total']} "
        f"({result['score']}%) — {result['seconds']}ث — {result['tokenizer']}"
    )
    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2), "utf-8")
        print(f"  JSON: {out}")
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] == result["total"] else 1


def cmd_sandbox(args) -> int:
    print(_cyan("=== عزل ديناميكي (Windows Sandbox) ==="))
    target = _resolve_target(args.target)
    try:
        plan = sandbox.build_plan(
            target,
            out=args.out,
            timeout=args.timeout,
            network=args.network,
        )
    except (OSError, ValueError) as exc:
        print(_err(f"  ✗ {exc}"))
        return 2

    print(f"  العينة: {plan['sample']}")
    print(f"  SHA256: {plan['sha256']}")
    print(f"  الشبكة: {'مفعّلة (خطر)' if plan['network'] else 'معطلة'}")
    print(f"  الخطة: {plan['wsb']}")
    print(f"  النتائج: {plan['output_dir']}")
    if not plan.get("sandbox_available"):
        print(_warn("  Windows Sandbox غير مثبت؛ الخطة جاهزة للتشغيل على جهاز يدعمه."))

    if args.json:
        print(json.dumps(plan, ensure_ascii=False, indent=2))

    if args.run:
        if not args.yes:
            print(_err("  ✗ التشغيل يتطلب --yes بعد مراجعة العينة."))
            return 2
        try:
            result = sandbox.run_plan(plan, confirmed=args.yes)
        except (OSError, RuntimeError, ValueError) as exc:
            print(_err(f"  ✗ {exc}"))
            return 2
        print(_ok(f"  ✓ شُغّل Sandbox (PID {result.get('pid')})"))
        if result.get("error"):
            print(_warn(f"  {result['error']}"))
    else:
        print(
            "  لم يُنفّذ شيء. راجع sandbox.wsb أولاً؛ فتحه يشغّل العينة تلقائياً،"
            " أو استخدم --run --yes."
        )
    return 0


def cmd_scan(args) -> int:
    from .tools import batch

    only = {name.strip() for name in args.only.split(",")} if args.only else (
        {"pe", "apk", "strings", "yara"} | ({"disasm"} if args.deep else set())
    )
    known = {analyzer.name for analyzer in load_analyzers()}
    unknown = only - known
    if unknown:
        raise ValueError(
            f"محللات غير معروفة: {', '.join(sorted(unknown))} — المتاح: {', '.join(sorted(known))}"
        )
    print(_cyan("=== فحص دفعات ==="))
    print(f"  المسار: {Path(args.path).resolve()}")
    print(f"  المحللات: {', '.join(sorted(only))} — حد الملفات: {args.max}\n")

    def progress(index: int, total: int, row: dict) -> None:
        mark = {"critical": _err("✗"), "warn": _warn("!"), "info": _ok("·")}[row["verdict"]]
        print(f"  {mark} [{index}/{total}] {row['name'][:44]:<44} "
              f"{row['kind']:<5} {row['score']}/10  {row['seconds']}ث")

    result = batch.scan(
        args.path, recursive=not args.no_recursive, only=only,
        max_files=max(0, args.max), max_mb=max(1, args.max_mb), all_files=args.all,
        progress=progress,
    )
    counts = result["counts"]
    print(_cyan("\n=== الملخص ==="))
    if not result["file_count"]:
        print(_warn("  لا ملفات مطابقة (جرّب --all أو تحقق من الامتدادات)."))
    print(f"  الملفات: {result['file_count']} — مرتفع: {counts['critical']} "
          f"— متوسط: {counts['warn']} — منخفض: {counts['info']}")
    print(f"  المدة: {result['elapsed_seconds']}ث")
    print(f"  {_ok('✓')} التقرير: {result['report']}")
    print(f"  JSON: {result['json']}")
    print(f"  CSV:  {result['csv']}")
    if args.pdf:
        pdf = html_to_pdf(result["report"], Path(result["report"]).with_suffix(".pdf"))
        result["pdf"] = str(pdf)
        print(f"  PDF:  {pdf}")
    if args.open and os.name == "nt":
        os.startfile(result.get("pdf") or result["report"])
    return 0


def cmd_selftest(args) -> int:
    from .tools import selftest

    print(_cyan("=== الاختبار الذاتي ==="))
    checks = selftest.run_selftest(full=args.full)
    marks = {"ok": _ok("✓"), "skip": _warn("○"), "fail": _err("✗")}
    for check in checks:
        detail = f" — {check['detail']}" if check["detail"] else ""
        print(f"  {marks[check['status']]} {check['name']:<18} "
              f"{check['seconds']:>5}ث{detail}")
    ok = sum(1 for check in checks if check["status"] == "ok")
    failed = sum(1 for check in checks if check["status"] == "fail")
    skipped = sum(1 for check in checks if check["status"] == "skip")
    print()
    if failed:
        print(_err(f"النتيجة: {ok} ناجح، {failed} فاشل، {skipped} متخطى"))
        return 1
    print(_ok(f"النتيجة: {ok} ناجح، 0 فاشل، {skipped} متخطى"))
    return 0


def cmd_serve(args) -> int:
    from .web.server import serve

    cfg = load_config().get("web", {})
    host = args.host or cfg.get("host") or "127.0.0.1"
    port = args.port if args.port is not None else int(cfg.get("port", 8765))
    env_name = cfg.get("token_env", "RE_WEB_TOKEN")
    token = args.token or os.environ.get(env_name) or cfg.get("token") or ""
    allowed = args.allowed_host or list(cfg.get("allowed_hosts") or [])
    serve(
        port=port, open_browser=args.open, host=host,
        token=token, allowed_hosts=allowed,
    )
    return 0


def cmd_ws(args) -> int:
    if args.action == "list":
        workspaces = Workspace.list_all()
        if not workspaces:
            print("لا توجد مساحات عمل بعد. جرّب: python repl.py analyze <ملف>")
            return 0
        rows = []
        for ws in workspaces:
            meta = ws.safe_meta()
            result = ws.load_agent("result") or {}
            rows.append([ws.id, meta.get("name", ""), meta.get("kind", ""),
                         result.get("verdict", ""), meta.get("created", "")])
        print(_table(["المعرّف", "الاسم", "النوع", "الحكم", "أُنشئ"], rows))
        return 0

    if not args.id:
        raise ValueError("حدّد معرّف مساحة العمل (استخدم ws list لعرضها).")
    ws = Workspace.find(args.id)
    if args.action == "show":
        meta = ws.safe_meta()
        print(json.dumps(meta, ensure_ascii=False, indent=2))
        agent_result = ws.load_agent("result")
        if agent_result:
            print("\n" + agent_result.get("summary_md", ""))
        return 0

    if args.action in ("open", "report", "pdf"):
        report = render(ws)
        output = report
        if args.action == "pdf" or args.pdf:
            output = export_pdf(ws)
            print(_ok(f"✓ PDF: {output}"))
        if args.json:
            data = export_json(ws)
            print(_ok(f"✓ JSON: {data}"))
        if args.action != "pdf" and not args.pdf:
            print(_ok(f"✓ {report}"))
        if args.action == "open" and os.name == "nt":
            os.startfile(output)
        return 0
    return 1


def cmd_config(args) -> int:
    if args.action == "init":
        if CONFIG_PATH.exists() and not args.force:
            print(_warn(f"config.json موجود مسبقاً: {CONFIG_PATH} (استخدم --force للاستبدال)"))
            return 0
        cfg = load_config()
        cfg["provider"]["api_key"] = ""
        save_config(cfg)
        print(_ok(f"✓ أُنشئ {CONFIG_PATH}"))
        print("  اضبط المفتاح: setx RE_API_KEY \"sk-...\"  أو عدّل provider.api_key")
        return 0
    if args.action == "show":
        cfg = load_config()
        safe = json.loads(json.dumps(cfg))
        safe["provider"]["api_key"] = mask_secret(api_key(cfg))
        print(json.dumps(safe, ensure_ascii=False, indent=2))
        return 0
    if args.action == "migrate":
        report = migrate_config_file(dry_run=args.dry_run)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            for note in report["notes"]:
                print(f"  • {note}")
            if report["dry_run"]:
                print(_warn("معاينة فقط — لم يُكتب أي تغيير."))
            elif report["changed"]:
                print(_ok(f"✓ هُجر المخطط {report['from']} → {report['to']}"))
                print(f"  نسخة احتياطية: {report['backup']}")
            else:
                print(_ok(f"✓ لا هجرة مطلوبة (المخطط {report['to']})"))
        return 0
    return 1


def cmd_doctor(args) -> int:
    only = tuple(part.strip() for part in (args.only or "").split(",") if part.strip())
    report = doctor.run_checks(only)
    if args.bundle:
        target = doctor.build_bundle(args.bundle, report)
        report["bundle"] = str(target)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 1
    print(f"REPLATFORM {report['version']} — تشخيص الجاهزية")
    marks = {"ok": "✓", "warn": "!", "fail": "✗"}
    for item in report["checks"]:
        print(f"  {marks[item['status']]} {item['title']}: {item['detail']}")
        if item["hint"]:
            print(f"      → {item['hint']}")
    counts = report["counts"]
    summary = f"ناجح {counts['ok']} · تحذير {counts['warn']} · فشل {counts['fail']}"
    print(_ok(summary) if report["ok"] else _err(summary))
    if report.get("bundle"):
        print(f"  حزمة التشخيص: {report['bundle']}")
    return 0 if report["ok"] else 1


def cmd_license(args) -> int:
    if args.action == "status":
        state = licensing.status()
    elif args.action == "activate":
        if not args.file:
            raise ValueError("حدّد ملف الترخيص: license activate <ملف>")
        state = licensing.activate(args.file)
        print(_ok(f"✓ فُعّل ترخيص {state['license_id']} ({state['tier']})"))
    elif args.action == "deactivate":
        removed = licensing.deactivate()
        print(_ok("✓ حُذف الترخيص المحلي") if removed else _warn("لا ترخيص محلي"))
        return 0
    elif args.action == "features":
        state = licensing.status()
        for feature in state["features"]:
            print(f"  • {feature}")
        return 0 if state["valid"] else 1
    else:
        return 1
    if args.json:
        print(json.dumps(state, ensure_ascii=False, indent=2))
        return 0 if state["valid"] else 1
    print(f"الفئة: {state['tier']}")
    if state["valid"]:
        print(f"العميل: {state['customer']} · المقاعد: {state['seats']}")
        print(f"ينتهي: {state['expires'] or 'بلا نهاية'}"
              + (f" (متبقٍ {state['days_left']} يوماً)" if state["days_left"] is not None else ""))
        print(f"الاستحقاقات: {', '.join(state['features'])}")
        if state["grace"]:
            print(_warn("! فترة سماح — جدّد الاشتراك"))
    else:
        print(_warn(state["reason"]))
        print("  النواة MIT تعمل كاملة. للترقية: docs/COMMERCIAL.md")
    return 0 if state["valid"] else 1


def cmd_audit(args) -> int:
    if args.action == "record":
        if not args.event:
            raise ValueError("حدّد الحدث: audit record --event <اسم>")
        entry = enterprise.record(args.event, target=args.target or "")
        print(_ok(f"✓ سُجّل الحدث ({entry['hash'][:12]}…)"))
        return 0
    if args.action == "verify":
        report = enterprise.verify_chain()
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json
              else (_ok(f"✓ السلسلة سليمة ({report['entries']} حدثاً)") if report["ok"]
                    else _err(f"✗ كسر عند الحدث {report['broken_at']}: {report['reason']}")))
        return 0 if report["ok"] else 1
    if args.action == "export":
        out = args.out or str(ROOT / "audit-export.json")
        payload = enterprise.export_audit(out)
        print(_ok(f"✓ صُدّر سجل التدقيق: {out}"))
        print(f"  البصمة: {payload['sha256'][:16]}…")
        return 0
    return 1


def cmd_fleet(args) -> int:
    payload = enterprise.fleet_report(args.out)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    print(f"مساحات العمل: {payload['total']}")
    for kind, count in sorted(payload["kinds"].items()):
        print(f"  • {kind}: {count}")
    if args.out:
        print(_ok(f"✓ التقرير: {args.out}"))
    print(f"  البصمة: {payload['sha256'][:16]}…")
    return 0


def cmd_upgrade(args) -> int:
    if args.rollback:
        report = upgrade_tool.rollback(args.rollback, args.target or ROOT)
        print(_ok(f"✓ استُعيدت النسخة السابقة في {report['restored']}"))
        return 0
    if not args.bundle:
        raise ValueError("حدّد حزمة الترقية: upgrade <zip> [--sha256 ...]")
    if not args.dry_run and not args.yes:
        raise ValueError(
            "الترقية تستبدل ملفات التثبيت. أعد الأمر مع --yes بعد قراءة "
            "--dry-run (بياناتك config/workspaces/license محفوظة)."
        )
    report = upgrade_tool.install_bundle(
        args.bundle,
        args.target or ROOT,
        expected_sha256=args.sha256 or "",
        dry_run=args.dry_run,
    )
    if report.get("dry_run"):
        print(_warn("معاينة ترقية — لم يُكتب أي تغيير."))
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    print(_ok(f"✓ رُقّي إلى {report['version']} ({report['files']} ملفاً)"))
    print(f"  محفوظ: {', '.join(report['preserved']) or '(لا شيء)'}")
    if report.get("backup"):
        print(f"  تراجع: python repl.py upgrade --rollback \"{report['backup']}\"")
    return 0


PLUGIN_TEMPLATE = '''"""إضافة محلل مخصص — REPLATFORM Plugin API.

أعد تسمية name واختبر: python repl.py analyze <ملف> --only {name}
"""

from replatform.analyzers import Analyzer, Target


class MyAnalyzer(Analyzer):
    name = "{name}"
    description = "{description}"

    def can_handle(self, target: Target) -> bool:
        return True  # عدّل الشرط حسب نوع الملف

    def run(self, target: Target, ws) -> dict:
        return {{
            "score": 0,
            "verdict": "info",
            "findings": [],
            "note": f"الملف {{target.name}} بمساحة {{target.size}} بايت",
        }}
'''


def cmd_plugin(args) -> int:
    if args.action != "new":
        return 1
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.name):
        print(_err("اسم الإضافة يجب أن يكون معرّفاً برمجياً: حروف إنجليزية/أرقام/_، ولا يبدأ برقم."))
        return 2
    plugins_dir = ROOT / "plugins"
    plugins_dir.mkdir(exist_ok=True)
    path = plugins_dir / f"{args.name}.py"
    if path.exists():
        print(_err(f"الإضافة موجودة: {path}"))
        return 1
    path.write_text(
        PLUGIN_TEMPLATE.format(name=args.name, description="وصف الإضافة"),
        "utf-8",
    )
    print(_ok(f"✓ أُنشئت الإضافة: {path}"))
    print("  عدّلها ثم شغّل: python repl.py analyze <ملف> --only " + args.name)
    return 0


def cmd_version(_args) -> int:
    print(f"REPLATFORM v{__version__}")
    print(f"الجذر: {ROOT}")
    return 0


def cmd_integrations(args) -> int:
    """كتالوج وفحص واستعلامات التكاملات الخارجية (قراءة فقط)."""
    from .integrations import catalog, connectors
    from .integrations.http import IntegrationError

    action = args.action
    try:
        if action == "list":
            rows = [
                [
                    connector.id,
                    connector.category,
                    connector.name,
                    "مفتاح" if connector.requires_key else "بدون مفتاح",
                    connector.auth_env or "-",
                ]
                for connector in catalog.list_connectors(args.id)
            ]
            print(_cyan("موصلات التكامل (قراءة فقط، HTTPS فقط):"))
            print(_table(["المعرّف", "الفئة", "الاسم", "الاعتماد", "متغير البيئة"], rows))
            print("\nللمصادر والمستودعات والخدمات المجانية: "
                  f"{_cyan('python repl.py integrations resources')}")
            print("للمهارات المحلية: " + _cyan("python repl.py skills list"))
            return 0

        if action == "resources":
            rows = [
                [
                    resource.category,
                    resource.name,
                    resource.free_tier or "-",
                    resource.url,
                ]
                for resource in catalog.list_resources(args.id)
            ]
            print(_cyan("مصادر ومستودعات وخدمات (تحقق من الشروط الحالية):"))
            print(_table(["الفئة", "الاسم", "الطبقة المجانية", "الرابط"], rows))
            return 0

        if action == "show":
            if not args.id:
                raise IntegrationError("حدد معرّف الموصل: integrations show <id>")
            connector = catalog.get_connector(args.id)
            state = connectors.status(connector.id)
            print(_cyan(f"{connector.name} ({connector.id})"))
            print(f"  الفئة: {connector.category}")
            print(f"  الوصف: {connector.description}")
            print(f"  المضيف: {connector.host} — HTTPS فقط")
            print(f"  الوثائق: {connector.docs}")
            print(f"  قراءة فقط: {connector.read_only} — رفع عيّنات: {connector.sample_upload}")
            print(f"  مفتاح مطلوب: {connector.requires_key} — "
                  f"المتغير: {connector.auth_env or '(لا يوجد)'}")
            print(f"  الإعداد الحالي: {'مضبوط' if state['configured'] else 'غير مضبوط'}")
            return 0

        if action == "check":
            ids = [args.id] if args.id else [c.id for c in catalog.list_connectors()]
            results = []
            for connector_id in ids:
                item = connectors.status(connector_id)
                if args.live:
                    item["probe"] = connectors.probe(
                        connector_id, allow_network=args.yes
                    )
                results.append(item)
            if args.json:
                print(json.dumps(results, ensure_ascii=False, indent=2))
                return 0
            rows = [
                [
                    item["id"],
                    "نعم" if item["configured"] else "لا",
                    "مطلوب" if item["requires_key"] else "اختياري",
                    (item.get("probe") or {}).get("tls", "-"),
                ]
                for item in results
            ]
            print(_cyan("حالة التكاملات (بلا اتصال افتراضياً):"))
            print(_table(["المعرّف", "الإعداد", "المفتاح", "TLS"], rows))
            if not args.live:
                print("\nلفحص TLS فعلياً: " + _cyan("integrations check --live --yes"))
            return 0

        if action == "search":
            if not args.id or not args.query:
                raise IntegrationError(
                    "الصيغة: integrations search <id> \"<query>\" [--limit 5] [--yes]"
                )
            result = connectors.lookup(
                args.id,
                args.query,
                limit=args.limit,
                allow_network=args.yes,
            )
            if args.json:
                print(json.dumps(result, ensure_ascii=False))
            else:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0

        raise IntegrationError(f"إجراء غير معروف: {action}")
    except (IntegrationError, KeyError, ValueError) as exc:
        print(_err(str(exc)), file=sys.stderr)
        return 2


def cmd_skills(args) -> int:
    """عرض المهارات المحلية أو تفاصيل مهارة."""
    from .skills import SkillError, get_skill, list_skills

    try:
        if args.action == "list":
            rows = [
                [skill["name"], skill["category"], skill["title"]]
                for skill in list_skills()
            ]
            print(_cyan("مهارات الوكلاء المحلية:"))
            print(_table(["الاسم", "الفئة", "العنوان"], rows))
            print("\nللتفاصيل: " + _cyan("python repl.py skills show <name>"))
            return 0
        if not args.name:
            raise SkillError("حدد اسم المهارة: skills show <name>")
        skill = get_skill(args.name)
        print(_cyan(f"{skill.title} ({skill.name})"))
        print(f"  الفئة: {skill.category}")
        print(f"  الوصف: {skill.description}")
        if skill.tags:
            print(f"  الوسوم: {', '.join(skill.tags)}")
        if skill.source:
            print(f"  المصدر: {skill.source}")
        print()
        print(skill.body)
        return 0
    except (SkillError, ValueError) as exc:
        print(_err(str(exc)), file=sys.stderr)
        return 2


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repl.py",
        description="REPLATFORM — منصة هندسة عكسية وتحليل برمجيات",
    )
    parser.add_argument("--version", action="version", version=f"REPLATFORM {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("tools", help="عرض الأدوات المتاحة").set_defaults(func=cmd_tools)
    sub.add_parser("version", help="إصدار المنصة").set_defaults(func=cmd_version)

    p_int = sub.add_parser(
        "integrations", help="تكاملات خارجية قراءة فقط (APIs، مصادر، خدمات)"
    )
    p_int.add_argument(
        "action", choices=("list", "show", "check", "search", "resources")
    )
    p_int.add_argument("id", nargs="?", help="معرّف الموصل أو فئة المصادر")
    p_int.add_argument("query", nargs="?", help="استعلام البحث")
    p_int.add_argument("--limit", type=int, default=5, help="حد النتائج (1-25)")
    p_int.add_argument("--live", action="store_true", help="فحص TLS فعلي (check)")
    p_int.add_argument("--yes", action="store_true", help="السماح بالشبكة صراحةً")
    p_int.add_argument("--json", action="store_true", help="إخراج JSON")
    p_int.set_defaults(func=cmd_integrations)

    p_sk = sub.add_parser("skills", help="مهارات الوكلاء المحلية")
    p_sk.add_argument("action", choices=("list", "show"))
    p_sk.add_argument("name", nargs="?", help="اسم المهارة")
    p_sk.set_defaults(func=cmd_skills)

    p_inv = sub.add_parser("inventory", help="جرد البرامج المثبتة")
    p_inv.add_argument("--out", help="مسار CSV الناتج")
    p_inv.set_defaults(func=cmd_inventory)

    p_an = sub.add_parser("analyze", help="تحليل كامل لملف")
    p_an.add_argument("target", nargs="?", help="ملف PE أو APK (افتراضي: الملف المحدد بـ use)")
    p_an.add_argument("--name", help="اسم مساحة العمل")
    p_an.add_argument("--only", help="محللات محددة (pe,apk,strings)")
    p_an.add_argument("--agent", choices=("heuristic", "llm", "none"),
                      help="وضع الوكيل (افتراضي من config)")
    p_an.add_argument("--task", help="مهمة مخصصة لنموذج LLM")
    p_an.add_argument("--skill", help="مهارة محلية أو قائمة مفصولة بفواصل (مثال: malware-triage,pe-analysis)")
    p_an.add_argument("--open", action="store_true", help="فتح التقرير بعد الانتهاء")
    p_an.set_defaults(func=cmd_analyze)

    p_ag = sub.add_parser("agent", help="تشغيل وكيل ذكي على ملف")
    p_ag.add_argument("target", nargs="?")
    p_ag.add_argument("--task", help="المهمة المطلوبة")
    p_ag.add_argument("--mode", choices=("heuristic", "llm"))
    p_ag.add_argument("--skill", help="مهارة محلية أو قائمة مفصولة بفواصل")
    p_ag.set_defaults(func=cmd_agent)

    p_use = sub.add_parser("use", help="تحديد الملف المستهدف الحالي")
    p_use.add_argument("path", help="ملف EXE أو APK")
    p_use.set_defaults(func=cmd_use)

    sub.add_parser("current", help="عرض الملف المستهدف").set_defaults(func=cmd_current)

    p_patch = sub.add_parser("patch", help="تعديل ثنائي آمن (معاينة افتراضياً)")
    p_patch.add_argument("target", nargs="?", help="الملف (افتراضي: المحدد بـ use)")
    p_patch.add_argument("--find", required=True, help='hex:48 8B ?? أو str:نص')
    p_patch.add_argument("--replace", required=True, help="نمط الاستبدال بنفس الصيغة")
    p_patch.add_argument("--enc", choices=("ascii", "utf16le"), default="ascii")
    p_patch.add_argument("--all", action="store_true", help="كل التطابقات")
    p_patch.add_argument("--apply", action="store_true", help="تنفيذ الكتابة")
    p_patch.add_argument("--allow-system", action="store_true")
    p_patch.add_argument("--allow-resize", action="store_true",
                         help="السماح بتغيير طول PE/APK/ZIP (خطير)")
    p_patch.add_argument("--max-show", type=int, default=10)
    p_patch.set_defaults(func=cmd_patch)

    p_apk = sub.add_parser("apk", help="تعديل وتطوير APK")
    p_apk.add_argument("action", choices=("decode", "build", "sign", "java", "install", "devices"))
    p_apk.add_argument("target", nargs="?", help="ملف APK أو مجلد مشروع (build)")
    p_apk.add_argument("--out", help="مسار الناتج")
    p_apk.add_argument("--force", action="store_true",
                       help="السماح باستبدال مجلد فك موجود (decode)")
    p_apk.set_defaults(func=cmd_apk)

    p_serve = sub.add_parser("serve", help="واجهة ويب محلية/محمية")
    p_serve.add_argument("--host", default=None, help="عنوان الاستماع (افتراضي 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=None)
    p_serve.add_argument("--token", help="رمز وصول (أو RE_WEB_TOKEN)")
    p_serve.add_argument("--allowed-host", action="append", default=None,
                         help="مضيف مسموح إضافي (مثال: 192.168.1.5)")
    p_serve.add_argument("--open", action="store_true", help="فتح المتصفح")
    p_serve.set_defaults(func=cmd_serve)

    p_diff = sub.add_parser("diff", help="مقارنة نسختين (bin-diff)")
    p_diff.add_argument("a", help="النسخة الأولى")
    p_diff.add_argument("b", help="النسخة الثانية")
    p_diff.add_argument("--open", action="store_true")
    p_diff.add_argument("--pdf", action="store_true", help="تصدير التقرير PDF")
    p_diff.set_defaults(func=cmd_diff)

    p_gh = sub.add_parser("ghidra", help="تحليل Ghidra headless (متقدم)")
    p_gh.add_argument("target", nargs="?", help="ملف PE/ELF (افتراضي: المحدد بـ use)")
    p_gh.add_argument("--no-decompile", action="store_true",
                      help="تخطي توليد pseudocode (أسرع)")
    p_gh.add_argument("--decompile-limit", type=int, default=6,
                      help="عدد الدوال المفككة إلى pseudocode (افتراضي 6)")
    p_gh.add_argument("--rename", action="append", default=None,
                      help="إعادة تسمية دالة: FUN_00401000=parse_config (قابل للتكرار)")
    p_gh.set_defaults(func=cmd_ghidra)

    p_sandbox = sub.add_parser(
        "sandbox", help="خطة عزل ديناميكي عبر Windows Sandbox (لا تشغيل افتراضي)"
    )
    p_sandbox.add_argument("target", nargs="?", help="العينة (افتراضي: المحدد بـ use)")
    p_sandbox.add_argument("--out", help="مجلد الخطة")
    p_sandbox.add_argument("--timeout", type=int, default=120,
                           help="مدة التشغيل داخل الصندوق بالثواني")
    p_sandbox.add_argument("--network", action="store_true",
                           help="تفعيل الشبكة داخل الصندوق (خطر — معطلة افتراضياً)")
    p_sandbox.add_argument("--run", action="store_true",
                           help="تشغيل Sandbox فعلياً (يتطلب --yes)")
    p_sandbox.add_argument("--yes", action="store_true", help="تأكيد صريح للتشغيل")
    p_sandbox.add_argument("--json", action="store_true", help="طباعة الخطة JSON")
    p_sandbox.set_defaults(func=cmd_sandbox)

    p_bench = sub.add_parser(
        "benchmark", help="تقييم قبول سريع للوكيل (MockProvider، بلا شبكة)"
    )
    p_bench.add_argument("--json", action="store_true", help="طباعة النتيجة JSON")
    p_bench.add_argument("--out", help="حفظ النتيجة في ملف JSON")
    p_bench.set_defaults(func=cmd_benchmark)

    p_scan = sub.add_parser("scan", help="فحص دفعات لمجلد أو ملف")
    p_scan.add_argument("path", help="ملف أو مجلد")
    p_scan.add_argument("--max", type=int, default=50, help="أقصى عدد ملفات (افتراضي 50)")
    p_scan.add_argument("--max-mb", type=int, default=128, help="أقصى حجم للملف (ميغابايت)")
    p_scan.add_argument("--no-recursive", action="store_true", help="بلا مجلدات فرعية")
    p_scan.add_argument("--all", action="store_true",
                        help="كل الملفات (وليس الامتدادات المعروفة فقط)")
    p_scan.add_argument("--deep", action="store_true", help="إضافة تفكيك Rizin (أبطأ)")
    p_scan.add_argument("--only", help="محللات محددة: pe,yara,...")
    p_scan.add_argument("--open", action="store_true", help="فتح التقرير")
    p_scan.add_argument("--pdf", action="store_true", help="تصدير تقرير PDF")
    p_scan.set_defaults(func=cmd_scan)

    p_st = sub.add_parser("selftest", help="اختبار ذاتي للمنصة")
    p_st.add_argument("--full", action="store_true", help="يشمل APK وRizin (أبطأ)")
    p_st.set_defaults(func=cmd_selftest)

    p_ws = sub.add_parser("ws", help="إدارة مساحات العمل")
    p_ws.add_argument("action", choices=("list", "show", "open", "report", "pdf"))
    p_ws.add_argument("id", nargs="?", help="معرّف مساحة العمل")
    p_ws.add_argument("--pdf", action="store_true", help="تصدير PDF")
    p_ws.add_argument("--json", action="store_true", help="تصدير JSON")
    p_ws.set_defaults(func=cmd_ws)

    p_cfg = sub.add_parser("config", help="إعدادات المنصة")
    p_cfg.add_argument("action", choices=("init", "show", "migrate"))
    p_cfg.add_argument("--force", action="store_true")
    p_cfg.add_argument("--dry-run", action="store_true", help="معاينة الهجرة بلا كتابة")
    p_cfg.add_argument("--json", action="store_true")
    p_cfg.set_defaults(func=cmd_config)

    p_doc = sub.add_parser("doctor", help="تشخيص جاهزية التثبيت وحزمة دعم")
    p_doc.add_argument("--json", action="store_true")
    p_doc.add_argument("--only", help="فحوص محددة: python,config,tools")
    p_doc.add_argument("--bundle", nargs="?", const="doctor-bundle.zip",
                       help="كتابة حزمة تشخيص (بلا أسرار)")
    p_doc.set_defaults(func=cmd_doctor)

    p_lic = sub.add_parser("license", help="الترخيص التجاري والاستحقاقات (offline)")
    p_lic.add_argument("action", choices=("status", "activate", "deactivate", "features"))
    p_lic.add_argument("file", nargs="?", help="ملف الترخيص عند التفعيل")
    p_lic.add_argument("--json", action="store_true")
    p_lic.set_defaults(func=cmd_license)

    p_audit = sub.add_parser("audit", help="سجل تدقيق بسلسلة تجزئة (مؤسسي)")
    p_audit.add_argument("action", choices=("record", "verify", "export"))
    p_audit.add_argument("--event", help="اسم الحدث عند التسجيل")
    p_audit.add_argument("--target", help="الهدف المرتبط بالحدث")
    p_audit.add_argument("--out", help="ملف التصدير")
    p_audit.add_argument("--json", action="store_true")
    p_audit.set_defaults(func=cmd_audit)

    p_fleet = sub.add_parser("fleet", help="تقرير أسطول مساحات العمل (مؤسسي)")
    p_fleet.add_argument("action", choices=("report",))
    p_fleet.add_argument("--out", help="ملف التقرير JSON")
    p_fleet.add_argument("--json", action="store_true")
    p_fleet.set_defaults(func=cmd_fleet)

    p_up = sub.add_parser("upgrade", help="ترقية آمنة من حزمة محمولة مع تراجع")
    p_up.add_argument("bundle", nargs="?", help="ملف ZIP المحمول")
    p_up.add_argument("--sha256", help="البصمة المتوقعة للحزمة")
    p_up.add_argument("--target", help="مجلد التثبيت (افتراضي: الجذر)")
    p_up.add_argument("--dry-run", action="store_true")
    p_up.add_argument("--rollback", help="استعادة نسخة تراجع")
    p_up.add_argument("--yes", action="store_true", help="تأكيد صريح للترقية")
    p_up.set_defaults(func=cmd_upgrade)

    p_pl = sub.add_parser("plugin", help="إدارة الإضافات")
    p_pl.add_argument("action", choices=("new",))
    p_pl.add_argument("name")
    p_pl.set_defaults(func=cmd_plugin)

    return parser


def main(argv: list[str] | None = None) -> int:
    stdio.configure()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except (
        ConfigMigrationError,
        licensing.LicenseError,
        licensing.EntitlementError,
        upgrade_tool.UpgradeError,
    ) as exc:
        print(_err(str(exc)), file=sys.stderr)
        return 3
    except FileNotFoundError as exc:
        print(_err(str(exc)), file=sys.stderr)
        return 2
    except ValueError as exc:
        print(_err(str(exc)), file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as exc:
        print(_err(str(exc)), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
