"""اختبار ذاتي شامل للمنصة — يتحقق من المكوّنات الأساسية دون تعديل بيانات المستخدم."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import tempfile
import time
from pathlib import Path

from ..agents.loop import compact_messages, run_agent
from ..agents.provider import MockProvider
from ..analyzers import Target, load_analyzers
from ..core import state, util
from ..core.config import ROOT, load_config
from ..core.workspace import Workspace
from ..reports import render
from . import bindiff, ghidra_tools, patcher, yara_engine


class Skip(Exception):
    """تُرفع عند تعذّر الفحص لسبب بيئي (ليست فشلاً)."""


class _NullWS:
    def add_event(self, *args, **kwargs) -> None:
        pass

    def save_artifact(self, *args, **kwargs) -> None:
        pass


def _find_pe_sample() -> Path | None:
    candidates = [
        ROOT / "bin" / "7z-a.exe",
        ROOT / "bin" / "7z-b.exe",
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "notepad.exe",
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "calc.exe",
    ]
    return next((path for path in candidates if path.is_file()), None)


def _run(checks: list[dict], name: str, fn) -> None:
    started = time.time()
    try:
        detail = fn() or ""
        checks.append({"name": name, "status": "ok", "detail": str(detail),
                       "seconds": round(time.time() - started, 2)})
    except Skip as exc:
        checks.append({"name": name, "status": "skip", "detail": str(exc),
                       "seconds": round(time.time() - started, 2)})
    except Exception as exc:  # noqa: BLE001
        checks.append({"name": name, "status": "fail",
                       "detail": f"{type(exc).__name__}: {exc}",
                       "seconds": round(time.time() - started, 2)})


# ---------------------------------------------------------------------------
# الفحوص
# ---------------------------------------------------------------------------

def _check_config() -> str:
    cfg = load_config()
    assert "analysis" in cfg and "agent" in cfg, "بنية الإعدادات ناقصة"
    assert int(cfg["analysis"]["strings_max"]) > 0, "strings_max غير صالح"
    return "config.json أو الافتراضي"


def _check_analyzers() -> str:
    names = {analyzer.name for analyzer in load_analyzers()}
    required = {"pe", "apk", "strings", "yara", "disasm"}
    missing = required - names
    assert not missing, f"محللات مفقودة: {', '.join(sorted(missing))}"
    return ", ".join(sorted(names))


def _check_state() -> str:
    data = state.get_state()
    assert isinstance(data, dict), "حالة غير صالحة"
    return f"الهدف الحالي: {data.get('name', 'لا يوجد')}"


def _check_report(temp: Path) -> str:
    sample = temp / "selftest-sample.txt"
    sample.write_text("REPLATFORM selftest\n", "utf-8")
    ws = Workspace.create(sample, name="selftest-report")
    try:
        report = render(ws)
        text = report.read_text("utf-8")
        assert report.exists() and "REPLATFORM" in text and "report.html" == report.name
        return f"تقرير صالح ({len(text):,} حرف)"
    finally:
        shutil.rmtree(ws.path, ignore_errors=True)


def _check_exports(temp: Path) -> str:
    from ..reports import export_json, export_pdf

    sample = temp / "export-sample.txt"
    sample.write_text("REPLATFORM export selftest\n", "utf-8")
    ws = Workspace.create(sample, name="selftest-export")
    try:
        data = export_json(ws)
        payload = json.loads(data.read_text("utf-8"))
        assert payload.get("format") == "replatform-report", "تنسيق JSON غير صالح"
        assert payload.get("meta", {}).get("name") == "selftest-export"
        try:
            pdf = export_pdf(ws)
        except RuntimeError as exc:
            if "Edge/Chrome" in str(exc) or "متصفح" in str(exc):
                raise Skip("لا يوجد Edge/Chrome لاختبار PDF") from exc
            raise
        assert pdf.is_file() and pdf.read_bytes()[:5] == b"%PDF-", "PDF غير صالح"
        return f"JSON + PDF ({pdf.stat().st_size:,} بايت)"
    finally:
        shutil.rmtree(ws.path, ignore_errors=True)


def _check_diff(temp: Path) -> str:
    a = temp / "diff-a.txt"
    b = temp / "diff-b.txt"
    a.write_text("REPLATFORM selftest baseline\n" * 20, "utf-8")
    b.write_text(a.read_text("utf-8"), "utf-8")
    same = bindiff.diff_files(a, b)
    assert same["identical"] is True, "لم يُكتشف التطابق"
    assert same["similarity"] == 100.0, f"تشابه غير متوقع: {same['similarity']}"

    b.write_text(a.read_text("utf-8") + "tail-change\n", "utf-8")
    changed = bindiff.diff_files(a, b)
    assert changed["identical"] is False, "لم يُكتشف الاختلاف"
    assert changed["similarity"] is not None and changed["similarity"] < 100

    base = hashlib.shake_256(b"replatform-cdc-selftest").digest(300_000)
    cdc_a = temp / "diff-cdc-a.bin"
    cdc_b = temp / "diff-cdc-b.bin"
    cdc_a.write_bytes(base)
    cdc_b.write_bytes(b"INSERTED-HEADER-" * 12 + base)
    shifted = bindiff.diff_files(cdc_a, cdc_b)
    assert shifted["similarity_method"] == "cdc", shifted["similarity_method"]
    assert shifted["similarity"] is not None and shifted["similarity"] >= 80, (
        f"CDC لم يتحمل الإزاحة: {shifted['similarity']}"
    )
    return (
        f"تطابق 100% — تغيّر {changed['similarity']}% — "
        f"CDC {shifted['similarity']}%"
    )


def _check_patch(temp: Path, pe_sample: Path | None) -> str:
    if not pe_sample:
        raise Skip("لا عينة PE متاحة")
    copy = temp / "patch-sample.exe"
    shutil.copy2(pe_sample, copy)
    before = util.sha256_file(copy)
    result = patcher.patch(copy, "str:MZ", "str:MZ", apply=False)
    assert result["applied"] is False, "المعاينة كتبت إلى الملف"
    assert result["count"] >= 1, "لم يُعثر على ترويسة MZ"
    assert util.sha256_file(copy) == before, "تغيّر الملف أثناء المعاينة"
    return f"{result['count']} تطابق (معاينة فقط، بلا كتابة)"


def _check_patch_apply(temp: Path) -> str:
    sample = temp / "patch-wildcard.bin"
    sample.write_bytes(b"A\x0aB\x00A\x0aB")
    result = patcher.patch(
        sample, "hex:41 ?? 42", "hex:41 00 42", apply=True, all_matches=True
    )
    assert result["count"] == 2, f"عدد تطابقات غير متوقع: {result['count']}"
    assert result["applied"] is True, "لم يُطبَّق التعديل"
    assert sample.read_bytes() == b"A\x00B\x00A\x00B", "البدل الخاطئ لم يطابق 0x0A"
    backup = Path(result["backup"])
    assert backup.is_file() and backup.read_bytes() == b"A\x0aB\x00A\x0aB", "النسخة الاحتياطية غير سليمة"
    return "بدل ?? يطابق 0x0A + نسخة احتياطية"


def _check_patch_backups(temp: Path) -> str:
    sample = temp / "patch-backup.bin"
    sample.write_bytes(b"AAAA")
    first = patcher.patch(sample, "hex:41", "hex:42", apply=True)
    second = patcher.patch(sample, "hex:41", "hex:42", apply=True)
    assert first["backup"] != second["backup"], "تصادم اسم النسخة الاحتياطية"
    assert Path(first["backup"]).read_bytes() == b"AAAA", "النسخة الأولى تغيّرت"
    assert sample.read_bytes() == b"BBAA", f"نتيجة غير متوقعة: {sample.read_bytes()!r}"
    return "نسختان فريدتان في الثانية نفسها"


def _check_patch_overlap(temp: Path) -> str:
    sample = temp / "patch-overlap.bin"
    original = b"aaa"
    sample.write_bytes(original)
    for apply in (False, True):
        try:
            patcher.patch(
                sample, "str:aa", "str:bb", apply=apply, all_matches=True
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"قبل تداخل str مع --all (apply={apply})")
        assert sample.read_bytes() == original, "تغيّر الملف بعد رفض التداخل"
        assert not list(temp.glob(sample.name + ".bak.*")), (
            "أُنشئت نسخة احتياطية رغم رفض التداخل"
        )

    single = patcher.patch(sample, "str:aa", "str:bb", apply=True)
    assert single["applied"] is True and single["replaced"] == 1, single
    assert sample.read_bytes() == b"bba", sample.read_bytes()
    return "رفض التداخل قبل الكتابة — التطابق الواحد يعمل"


def _check_batch_limits(temp: Path) -> str:
    from . import batch

    root = temp / "batch-limits"
    root.mkdir()
    oversized = root / "oversized.bin"
    oversized.write_bytes(b"M" * (2 * 1024 * 1024))

    assert batch.collect_files(oversized, max_mb=1) == [], "تجاوز حد الحجم لملف جذري"
    assert batch.collect_files(oversized, max_mb=2, all_files=True) == [oversized], (
        "رُفض ملف جذري ضمن الحد"
    )
    assert batch.collect_files(oversized, max_mb=2) == [], (
        "لم يُفلتر امتداد الملف الجذري"
    )
    assert batch.collect_files(
        oversized, max_mb=2, all_files=True, max_files=0
    ) == [], "تجاهل max_files=0 لملف جذري"
    try:
        batch.analyze_file(oversized, {"pe"}, max_mb=1)
    except ValueError:
        pass
    else:
        raise AssertionError("analyze_file لم يفرض max_mb على الملف الجذري")

    link = root / "linked.bin"
    try:
        os.symlink(oversized, link)
    except (OSError, NotImplementedError):
        note = "symlink غير متاح في البيئة"
    else:
        assert batch.collect_files(link, max_mb=2, all_files=True) == [], (
            "قبل symlink جذري"
        )
        note = "symlink جذري مرفوض"
    return f"الحجم/الامتداد/العدد مطبّق على ملف جذري + {note}"


def _check_csv_injection(temp: Path) -> str:
    from . import batch

    payloads = [
        '=HYPERLINK("http://evil.example","x")',
        "+1+1",
        "-2+3",
        "@SUM(A1:A2)",
        "\tcmd /c calc",
        "\rcmd /c calc",
    ]
    rows = [
        {
            "name": payload,
            "kind": "PE",
            "size": 10,
            "score": 1,
            "verdict": "info",
            "sha256": "0" * 64,
            "findings": [payload],
            "errors": [payload],
            "path": payload,
            "seconds": 0.1,
        }
        for payload in payloads
    ]
    out = temp / "summary.csv"
    batch._write_csv(out, rows)
    with out.open(encoding="utf-8-sig", newline="") as fh:
        parsed = list(csv.reader(fh))
    header = parsed[0]
    assert header[0] == "name" and header[-1] == "seconds", header
    assert len(parsed) == len(payloads) + 1, len(parsed)
    columns = [header.index(name) for name in ("name", "findings", "errors", "path")]
    for index, payload in enumerate(payloads, start=1):
        cells = parsed[index]
        for column in columns:
            assert cells[column] == "'" + payload, (column, cells[column])
    return f"{len(payloads)} صيغة محيّدة في name/findings/errors/path"


def _check_apk_decode_guard(temp: Path) -> str:
    sample = ROOT / "apk" / "test.apk"
    if not sample.is_file():
        raise Skip("لا عينة APK")
    from . import apk_tools

    victim = temp / "not-a-decode-dir"
    victim.mkdir()
    (victim / "important.txt").write_text("keep", "utf-8")
    try:
        apk_tools.decode(sample, out=victim, force=True)
    except ValueError:
        pass
    else:
        raise AssertionError("قبل حذف مجلد لا يبدو ناتج apktool")
    assert (victim / "important.txt").exists(), "حُذف مجلد غير آمن"
    return "حماية --force من حذف مجلدات عشوائية"


def _check_agent_paths(temp: Path) -> str:
    from ..agents import tools as agent_tools

    allowed = temp / "agent-allowed.bin"
    outside = temp / "agent-outside.bin"
    allowed.write_bytes(b"allowed")
    outside.write_bytes(b"secret")
    agent_tools.configure([allowed])
    try:
        denied = agent_tools.execute("hexdump", {"path": str(outside), "offset": 0})
        accepted = agent_tools.execute("hexdump", {"path": str(allowed), "offset": 0})
    finally:
        agent_tools.configure([])
    assert denied.get("error"), "لم يُمنع المسار خارج النطاق"
    assert accepted.get("dump"), "مُنع المسار المسموح بالخطأ"
    return "المسارات مقيّدة بالهدف"


def _check_apk_sidecar(temp: Path) -> str:
    sample = ROOT / "apk" / "test.apk"
    if not sample.is_file():
        raise Skip("لا عينة APK (apk/test.apk)")
    from ..analyzers.apk_analyzer import signing_info

    copy = temp / "sidecar.apk"
    shutil.copy2(sample, copy)
    Path(str(copy) + ".idsig").write_bytes(b"REPLATFORM-v4-selftest")
    info = signing_info(str(copy))
    assert info.get("v4") is True, "لم يُكتشف v4 sidecar"
    assert "v4" in (info.get("schemes") or []), info.get("schemes")
    assert info.get("v4_sha256"), "بصمة v4 مفقودة"
    return "v3.1/v4 sidecar مكتشف"


def _check_sandbox_plan(temp: Path) -> str:
    import xml.etree.ElementTree as ET

    from . import sandbox

    sample = temp / "sandbox-sample.bin"
    sample.write_bytes(b"REPLATFORM sandbox selftest\n" * 8)
    plan = sandbox.build_plan(sample, out=temp / "sandbox-plan", timeout=15)
    wsb = Path(plan["wsb"])
    assert wsb.is_file(), "لم يُكتب ملف .wsb"
    root = ET.parse(wsb).getroot()  # noqa: S314 — ملف .wsb ناتج محلي موثوق
    assert root.findtext("Networking") == "Disable", "الشبكة غير معطلة"
    folders = root.findall("./MappedFolders/MappedFolder")
    assert len(folders) == 2, "عدد المجلدات المعزولة غير متوقع"
    assert folders[0].findtext("ReadOnly") == "true", "مجلد العينة قابل للكتابة"
    assert Path(plan["sample"]).is_file(), "لم تُنسخ العينة"
    assert plan["sha256"] == util.sha256_file(sample), "بصمة العينة غير مطابقة"
    return f"خطة .wsb معزولة ({plan['kind']}) — Sandbox={'نعم' if plan['sandbox_available'] else 'لا'}"


def _check_web_auth(temp: Path) -> str:
    import http.cookiejar
    import threading
    import urllib.error
    import urllib.parse
    import urllib.request

    from ..web.server import make_server

    try:
        make_server("0.0.0.0", 0, "", [])  # noqa: S104 — اختبار سلبي: يجب أن يُرفض
    except ValueError:
        pass
    else:
        raise AssertionError("سمح بخادم غير محلي بلا رمز")

    server = make_server("127.0.0.1", 0, "selftest-token", [])
    port = server.server_address[1]
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    )
    thread.start()

    def get(path: str, headers: dict | None = None):
        request = urllib.request.Request(  # noqa: S310 — خادم اختبار محلي على loopback
            f"http://127.0.0.1:{port}{path}", headers=headers or {}
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 — loopback فقط
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code

    try:
        assert get("/") == 401, "الواجهة مفتوحة بلا رمز"
        assert get("/", {"Authorization": "Bearer selftest-token"}) == 200
        assert get("/api/status", {"Authorization": "Bearer selftest-token"}) == 200
        assert get("/", {"Host": "evil.example"}) == 403

        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar)
        )
        body = urllib.parse.urlencode(
            {"token": "selftest-token", "next": "/"}
        ).encode()
        login = urllib.request.Request(
            f"http://127.0.0.1:{port}/login",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with opener.open(login, timeout=5) as response:
            assert response.status == 200, response.status
        with opener.open(f"http://127.0.0.1:{port}/", timeout=5) as response:
            assert response.status == 200, response.status

        reject = urllib.parse.urlencode({"path": str(temp)}).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/analyze",
            data=reject,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with opener.open(request, timeout=5) as response:
            assert "error=" in response.geturl(), response.geturl()
        return "رمز + Bearer + كوكي + رفض Host + رفض مجلد كهدف"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _check_web_analyze_guard(temp: Path) -> str:
    from ..web import server as web_server

    inside = (ROOT / "apk" / "test.apk").resolve()
    if not inside.is_file():
        raise Skip("لا عينة APK (apk/test.apk)")
    outside = temp / "web-outside.bin"
    outside.write_bytes(b"MZ")
    directory = temp / "web-dir"
    directory.mkdir()
    system_file = (
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "kernel32.dll"
    )
    if not system_file.is_file():
        raise Skip("لا ملف نظام متاح لاختبار الرفض")

    assert web_server.resolve_analyze_target(
        str(inside), remote=True, allowed_roots=[]
    ) == inside
    assert web_server.resolve_analyze_target(
        str(outside), remote=False, allowed_roots=[]
    ) == outside.resolve()

    for raw, remote in (
        (str(directory), False),
        (str(outside), True),
        (str(system_file), False),
        ("", False),
        ("bad\x00path", False),
    ):
        try:
            web_server.resolve_analyze_target(
                raw, remote=remote, allowed_roots=[]
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"قبل هدف تحليل غير آمن: {raw!r} (remote={remote})")

    link = temp / "web-link.apk"
    try:
        os.symlink(inside, link)
    except (OSError, NotImplementedError):
        note = "symlink غير متاح"
    else:
        try:
            web_server.resolve_analyze_target(
                str(link), remote=False, allowed_roots=[]
            )
        except ValueError:
            note = "symlink مرفوض"
        else:
            raise AssertionError("قبل symlink كهدف تحليل")

    with web_server._analysis_slot():
        try:
            with web_server._analysis_slot():
                pass
        except web_server.AnalysisBusy:
            pass
        else:
            raise AssertionError("لم يُمنع تحليلان متزامنان")
    return f"مسار/جذور/نظام/قفل تحليل + {note}"


def _check_integrations() -> str:
    from ..integrations import catalog, connectors
    from ..integrations.http import IntegrationError, SafeHTTPClient

    ids = [connector.id for connector in catalog.CONNECTORS]
    assert len(ids) == len(set(ids)), "معرّفات موصلات مكررة"
    for connector in catalog.CONNECTORS:
        assert connector.base_url.startswith("https://"), connector.id
        assert connector.host, connector.id
        assert connector.docs.startswith("https://"), connector.id
        assert connector.read_only, connector.id
        assert not connector.sample_upload, connector.id
    for resource in catalog.RESOURCES:
        assert resource.url.startswith("https://"), resource.name
        assert resource.category, resource.name

    client = SafeHTTPClient({"example.com"})
    for bad in (
        "http://example.com/v1",
        "https://evil.example/v1",
        "https://example.com:8443/v1",
        "https://user:pass@example.com/v1",
        "ftp://example.com/v1",
    ):
        try:
            client.get_json(bad)
        except IntegrationError:
            pass
        else:
            raise AssertionError(f"قبل عميل HTTP رابطاً غير آمن: {bad}")

    from ..integrations.http import _NoRedirect

    try:
        _NoRedirect().redirect_request(
            None, None, 302, "Found", {}, "https://evil.example/"
        )
    except IntegrationError:
        pass
    else:
        raise AssertionError("قبل عميل التكامل إعادة توجيه")

    class _FakeResponse:
        def __init__(self, body: bytes, declared: int | None = None) -> None:
            self.body = body
            self.headers = {
                "Content-Length": str(len(body) if declared is None else declared)
            }

        def read(self, limit: int) -> bytes:
            return self.body[:limit]

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

    class _FakeOpener:
        def __init__(self, response: _FakeResponse) -> None:
            self.response = response

        def open(self, request, timeout=None):
            return self.response

    capped = SafeHTTPClient({"example.com"}, max_bytes=1024)
    capped._opener = _FakeOpener(_FakeResponse(b"{" + b"x" * 4096 + b"}"))  # type: ignore[assignment]
    try:
        capped.get_json("https://example.com/v1")
    except IntegrationError as exc:
        assert "الحد" in str(exc), str(exc)
    else:
        raise AssertionError("قبل عميل التكامل استجابة تتجاوز السقف")

    declared = SafeHTTPClient({"example.com"}, max_bytes=1024)
    declared._opener = _FakeOpener(_FakeResponse(b"{}", declared=4096))  # type: ignore[assignment]
    try:
        declared.get_json("https://example.com/v1")
    except IntegrationError as exc:
        assert "الحد" in str(exc), str(exc)
    else:
        raise AssertionError("قبل Content-Length أكبر من السقف")

    original = connectors._integration_cfg
    connectors._integration_cfg = lambda: {
        "enabled": False,
        "timeout": 1,
        "max_response_mb": 1,
    }
    try:
        try:
            connectors.lookup("nvd", "CVE-2024-3400")
        except IntegrationError:
            pass
        else:
            raise AssertionError("قبل استعلاماً والتكاملات معطّلة")
    finally:
        connectors._integration_cfg = original

    try:
        connectors.lookup(
            "virustotal", "a" * 64, allow_network=True
        )
    except IntegrationError as exc:
        assert "VIRUSTOTAL_API_KEY" in str(exc), str(exc)
    else:
        raise AssertionError("قبل VirusTotal بلا مفتاح")

    status = connectors.status("nvd")
    assert status["read_only"] and not status["sample_upload"], status
    try:
        catalog.get_connector("does-not-exist")
    except KeyError:
        pass
    else:
        raise AssertionError("قبل موصلاً غير معروف")
    return "كتالوج HTTPS + allowlist + سقف + تعطيل افتراضي + مفتاح إلزامي"


def _check_skills() -> str:
    from ..skills import SkillError, compose_skills, get_skill, list_skills

    skills = list_skills()
    names = {skill["name"] for skill in skills}
    expected = {
        "malware-triage",
        "pe-analysis",
        "apk-analysis",
        "yara-authoring",
        "threat-intel",
        "secure-code-review",
        "ai-agent-safety",
        "cloud-db-hardening",
        "re-ethics",
    }
    assert expected.issubset(names), f"مهارات ناقصة: {sorted(expected - names)}"
    skill = get_skill("malware-triage")
    assert skill.body and skill.category == "malware", skill
    composed = compose_skills(["malware-triage", "pe-analysis"])
    assert "منهجية الفرز" in composed and "تحليل PE" in composed, composed[:200]
    try:
        get_skill("../etc/passwd")
    except SkillError:
        pass
    else:
        raise AssertionError("قبل اسم مهارة غير صالح")

    outcome = run_agent(
        "مهمة اختبار المهارة",
        MockProvider([{"role": "assistant", "content": "تم"}]),
        max_steps=1,
        skills=["malware-triage"],
    )
    system = outcome["messages"][0]["content"]
    assert "منهجية الفرز" in system, "لم تُحقن المهارة في مطالبة الوكيل"
    return f"{len(skills)} مهارات + حقن آمن في الوكيل"


def _check_yara(temp: Path) -> str:
    if not yara_engine.available():
        raise Skip("YARA غير متوفر")
    sample = temp / "yara-sample.bin"
    sample.write_text(
        "VirtualAllocEx WriteProcessMemory CreateRemoteThread powershell -enc AAAA\n",
        "utf-8",
    )
    result = yara_engine.scan(str(sample))
    assert not result.get("error"), result.get("error")
    rules = [match["rule"] for match in result.get("matches") or []]
    assert rules, "لا تطابقات مع القواعد"
    return ", ".join(rules)


def _check_ghidra() -> str:
    headless = ghidra_tools.find_headless()
    if not headless:
        raise Skip("Ghidra غير مثبت")
    jdk = ghidra_tools.find_java_home()
    if not jdk:
        raise Skip("JDK 21+ غير متوفر (Ghidra يحتاجه)")
    return f"جاهز — JDK {Path(jdk).name}"


def _check_pe(pe_sample: Path | None) -> str:
    if not pe_sample:
        raise Skip("لا عينة PE متاحة")
    from ..analyzers.pe_analyzer import PEAnalyzer

    target = Target.from_path(pe_sample)
    artifact = PEAnalyzer().run(target, _NullWS())
    summary = artifact.get("summary") or {}
    assert summary.get("arch"), "تعذر قراءة معمارية PE"
    return f"{summary['arch']} — {len(summary.get('sections') or [])} أقسام"


def _check_apk() -> str:
    sample = ROOT / "apk" / "test.apk"
    if not sample.is_file():
        raise Skip("لا عينة APK (apk/test.apk)")
    from ..analyzers.apk_analyzer import APKAnalyzer

    artifact = APKAnalyzer().run(Target.from_path(sample), _NullWS())
    manifest = artifact.get("manifest") or {}
    assert manifest.get("package"), "تعذر قراءة بيان APK"
    for key in (
        "exported",
        "exported_components",
        "exported_without_permission",
        "exported_missing_explicit",
        "main_activity",
    ):
        assert key in manifest, f"حقل exported ناقص: {key}"
    signing = artifact.get("signing") or {}
    for key in ("v1", "v2", "v3", "v3_1", "v4", "schemes"):
        assert key in signing, f"حقل توقيع ناقص: {key}"
    return f"{manifest['package']} — {manifest.get('version_name', '?')}"


def _check_disasm(pe_sample: Path | None) -> str:
    if not pe_sample:
        raise Skip("لا عينة PE متاحة")
    from ..analyzers.disasm_analyzer import DisasmAnalyzer

    analyzer = DisasmAnalyzer()
    target = Target.from_path(pe_sample)
    if not analyzer.can_handle(target):
        raise Skip("rizin غير متوفر")
    started = time.time()
    artifact = analyzer.run(target, _NullWS())
    elapsed = round(time.time() - started, 2)
    count = int(artifact.get("function_count") or 0)
    assert count > 0, "لم تُكتشف دوال"
    return f"{count} دالة في {elapsed}ث"


def _check_agent_loop(temp: Path) -> str:
    from ..agents import tools as agent_tools

    sample = temp / "agent-sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 32 + b"http://example.com/agent-test")
    agent_tools.configure([sample])
    script: list[dict] = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "c1",
                "type": "function",
                "function": {
                    "name": "analyze_file",
                    "arguments": json.dumps({"path": str(sample)}, ensure_ascii=False),
                },
            }],
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "c2",
                "type": "function",
                "function": {
                    "name": "strings_search",
                    "arguments": json.dumps(
                        {"path": str(sample), "pattern": "http", "max_results": 5},
                        ensure_ascii=False,
                    ),
                },
            }],
        },
        {"role": "assistant", "content": "إجابة نهائية"},
    ]
    try:
        outcome = run_agent(
            "حلّل العينة", MockProvider(script),
            max_steps=5, max_tool_calls=2, max_seconds=10,
            max_context_chars=8000,
        )
    finally:
        agent_tools.configure([])
    assert outcome["status"] == "done", outcome["status"]
    assert outcome["answer"] == "إجابة نهائية", outcome["answer"]
    assert len(outcome["steps"]) == 2, len(outcome["steps"])
    assert outcome["steps"][0]["result"].get("size") == sample.stat().st_size
    assert outcome["steps"][1]["result"].get("count", 0) >= 1
    return "دورة أداتين + إجابة نهائية"


def _check_agent_limits(temp: Path) -> str:
    from ..agents import tools as agent_tools

    messages: list[dict] = [
        {"role": "system", "content": "س" * 100},
        {"role": "user", "content": "م" * 100},
    ]
    for index in range(6):
        messages.append({
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": f"c{index}",
                "type": "function",
                "function": {"name": "hexdump", "arguments": "{}"},
            }],
        })
        messages.append({
            "role": "tool",
            "tool_call_id": f"c{index}",
            "content": "x" * 1000,
        })
    after = compact_messages(messages, 2500)
    assert after <= 2500, f"لم يُضغط السياق: {after}"

    single: list[dict] = [
        {"role": "system", "content": "س" * 100},
        {"role": "user", "content": "م" * 100},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "c1",
                "type": "function",
                "function": {"name": "hexdump", "arguments": "{}"},
            }],
        },
        {"role": "tool", "tool_call_id": "c1", "content": "x" * 10000},
    ]
    after_single = compact_messages(single, 2000)
    assert after_single <= 2000, f"لم تُضغط نتيجة أداة واحدة كبيرة: {after_single}"

    from ..analyzers import strings_analyzer

    long_file = temp / "agent-long-strings.bin"
    long_file.write_bytes(b"A" * 2000)
    scanned = strings_analyzer.scan(str(long_file))
    assert scanned["strings"], "لم تُستخرج نصوص"
    assert max(len(item) for item in scanned["strings"]) <= 512, "نص طويل بلا سقف"
    try:
        strings_analyzer.search(str(long_file), "(x+)+$")
    except ValueError:
        pass
    else:
        raise AssertionError("قبل نمط regex خطر")

    class _Slow:
        model = "slow"

        def chat(self, messages, tools=None):
            time.sleep(0.15)
            return {"content": "متأخر"}

    slow = run_agent("اختبر المهلة", _Slow(), max_steps=2, max_seconds=0.05)
    assert slow["status"] == "timeout", slow["status"]
    assert slow.get("context_tokens", 0) > 0, "لم يُحسب السياق بالتوكنات"
    assert slow.get("tokenizer"), "محرك حساب التوكنات مفقود"

    sample = temp / "agent-limits.bin"
    sample.write_bytes(b"0123456789ABCDEF")

    class _Loop:
        model = "loop"

        def chat(self, messages, tools=None):
            return {
                "content": None,
                "tool_calls": [{
                    "id": "c",
                    "type": "function",
                    "function": {
                        "name": "hexdump",
                        "arguments": json.dumps(
                            {"path": str(sample), "offset": 0, "length": 8}
                        ),
                    },
                }],
            }

    agent_tools.configure([sample])
    try:
        looped = run_agent(
            "استدعِ الأداة دائماً", _Loop(),
            max_steps=2, max_tool_calls=1, max_seconds=10,
        )
    finally:
        agent_tools.configure([])
    assert looped["status"] == "max_steps", looped["status"]
    assert len(looped["steps"]) == 2, len(looped["steps"])
    return "ضغط السياق + مهلة زمنية + حد خطوات"


def _check_agent_timeout_strict(temp: Path) -> str:
    calls: list[str] = []

    class _SlowTools:
        model = "slow-tools"

        def chat(self, messages, tools=None):
            time.sleep(0.15)
            return {
                "content": None,
                "tool_calls": [{
                    "id": "late",
                    "type": "function",
                    "function": {
                        "name": "hexdump",
                        "arguments": json.dumps(
                            {"path": str(temp), "offset": 0}
                        ),
                    },
                }],
            }

    def executor(name, args):
        calls.append(name)
        return {"ok": True}

    outcome = run_agent(
        "لا تنفّذ أدوات بعد المهلة", _SlowTools(),
        max_steps=2, max_seconds=0.05, executor=executor,
    )
    assert outcome["status"] == "timeout", outcome["status"]
    assert not calls, f"نُفّذت أداة بعد انتهاء المهلة: {calls}"
    return "لا تنفيذ لأدوات بعد انتهاء المهلة"


def _check_provider_guard(temp: Path) -> str:
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from ..agents.provider import OpenAIProvider, ProviderError

    def cfg_for(url: str) -> dict:
        return {
            "provider": {
                "base_url": url,
                "model": "selftest",
                "timeout": 5,
                "retries": 0,
            }
        }

    for bad in (
        "http://example.com/v1",
        "https://user:pass@example.com/v1",
        "ftp://example.com/v1",
    ):
        try:
            OpenAIProvider(cfg_for(bad))
        except ProviderError:
            pass
        else:
            raise AssertionError(f"قبل مزوّداً غير آمن: {bad}")

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            if self.path.startswith("/big/"):
                body = b"{" + b" " * 4096 + b"}"
            elif self.path.startswith("/redirect/"):
                self.send_response(302)
                self.send_header("Location", "ftp://example.com/steal")
                self.end_headers()
                return
            else:
                body = json.dumps({
                    "choices": [{
                        "message": {"role": "assistant", "content": "ok"},
                    }],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        provider = OpenAIProvider(cfg_for(f"{base}/v1"))
        message = provider.chat([{"role": "user", "content": "hi"}])
        assert message.get("content") == "ok", message

        big = OpenAIProvider(cfg_for(f"{base}/big/v1"))
        big.max_response_bytes = 512
        try:
            big.chat([{"role": "user", "content": "hi"}])
        except ProviderError as exc:
            assert "الحد" in str(exc), str(exc)
        else:
            raise AssertionError("قبل استجابة تتجاوز الحد")

        redirect = OpenAIProvider(cfg_for(f"{base}/redirect/v1"))
        try:
            redirect.chat([{"role": "user", "content": "hi"}])
        except ProviderError as exc:
            assert "مخطط" in str(exc) or "توجيه" in str(exc), str(exc)
        else:
            raise AssertionError("قبل إعادة توجيه غير آمنة")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    return "HTTPS إلزامي + سقف استجابة + رفض redirect"


def run_selftest(full: bool = False) -> list[dict]:
    checks: list[dict] = []
    temp = Path(tempfile.mkdtemp(prefix="re_selftest_"))
    pe_sample = _find_pe_sample()
    try:
        _run(checks, "config", _check_config)
        _run(checks, "analyzers", _check_analyzers)
        _run(checks, "state", _check_state)
        _run(checks, "workspace/report", lambda: _check_report(temp))
        _run(checks, "exports (PDF/JSON)", lambda: _check_exports(temp))
        _run(checks, "diff", lambda: _check_diff(temp))
        _run(checks, "patch (dry-run)", lambda: _check_patch(temp, pe_sample))
        _run(checks, "patch (apply)", lambda: _check_patch_apply(temp))
        _run(checks, "patch (backups)", lambda: _check_patch_backups(temp))
        _run(checks, "patch (overlap guard)", lambda: _check_patch_overlap(temp))
        _run(checks, "batch (limits)", lambda: _check_batch_limits(temp))
        _run(checks, "batch (csv injection)", lambda: _check_csv_injection(temp))
        _run(checks, "agent (paths)", lambda: _check_agent_paths(temp))
        _run(checks, "agent (loop)", lambda: _check_agent_loop(temp))
        _run(checks, "agent (limits)", lambda: _check_agent_limits(temp))
        _run(checks, "agent (timeout strict)", lambda: _check_agent_timeout_strict(temp))
        _run(checks, "provider (guard)", lambda: _check_provider_guard(temp))
        _run(checks, "apk (decode guard)", lambda: _check_apk_decode_guard(temp))
        _run(checks, "apk (v4 sidecar)", lambda: _check_apk_sidecar(temp))
        _run(checks, "sandbox (plan)", lambda: _check_sandbox_plan(temp))
        _run(checks, "web (auth)", lambda: _check_web_auth(temp))
        _run(checks, "web (analyze guard)", lambda: _check_web_analyze_guard(temp))
        _run(checks, "integrations (catalog/http)", _check_integrations)
        _run(checks, "skills (local/agent)", _check_skills)
        _run(checks, "yara", lambda: _check_yara(temp))
        _run(checks, "ghidra", _check_ghidra)
        _run(checks, "pe", lambda: _check_pe(pe_sample))
        if full:
            _run(checks, "apk", _check_apk)
            _run(checks, "disasm", lambda: _check_disasm(pe_sample))
    finally:
        shutil.rmtree(temp, ignore_errors=True)
    return checks
