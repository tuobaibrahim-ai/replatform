"""واجهة ويب محلية (stdlib فقط) — لوحة تحكم REPLATFORM."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import subprocess
import sys
import threading
import time
import webbrowser
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urlparse

SERVER: dict = {"token": "", "allowed_hosts": set(), "host": "127.0.0.1"}
COOKIE_NAME = "replatform_token"

from .. import __version__
from ..core.config import ROOT, load_config
from ..core.export import html_to_pdf
from ..core.registry import detect_tools
from ..core.state import get_state
from ..core.workspace import Workspace
from ..tools.patcher import is_system_path

VERDICT_LABEL = {"critical": "مرتفع", "warn": "متوسط", "info": "منخفض"}

CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin:0; padding:26px; font-family:'Segoe UI',Tahoma,sans-serif;
       background:#0b1220; color:#dbe4f0; }
header h1 { margin:0 0 4px; font-size:24px; }
header p { margin:0 0 20px; color:#8ba3c7; font-size:13px; }
h2 { font-size:16px; margin:0 0 12px; color:#93c5fd; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
        gap:14px; margin-bottom:16px; }
.card, section { background:#0f1a2e; border:1px solid #1e2f4d;
                 border-radius:14px; padding:16px; margin-bottom:16px; }
.card p { margin:6px 0; font-size:13px; color:#9fb3d1; }
.card b { color:#dbe4f0; }
a { color:#7dd3fc; text-decoration:none; }
a:hover { text-decoration:underline; }
input[type=text] { width:100%; padding:10px 12px; border-radius:9px;
  border:1px solid #2a3f63; background:#111c31; color:#dbe4f0;
  font-family:Consolas,monospace; font-size:12px; direction:ltr; }
button { margin-top:10px; padding:9px 18px; border-radius:9px; border:0;
  background:#2563eb; color:#fff; font-size:13px; cursor:pointer; }
button:hover { background:#1d4ed8; }
.chips { display:flex; flex-wrap:wrap; gap:7px; }
.chip { font-size:11.5px; padding:3px 9px; border-radius:999px;
  background:#16233b; border:1px solid #24385a; }
.chip.ok { color:#86efac; } .chip.bad { color:#fca5a5; }
table { width:100%; border-collapse:collapse; }
th { text-align:right; font-size:11.5px; color:#93b4dd; padding:7px 8px;
     border-bottom:1px solid #1e2f4d; }
td { padding:7px 8px; border-bottom:1px solid #16233b; font-size:12.5px;
     vertical-align:top; }
.badge { font-size:11px; padding:2px 8px; border-radius:999px; }
.badge.critical { background:#3b1216; color:#fca5a5; }
.badge.warn { background:#3a2c0d; color:#fcd34d; }
.badge.info { background:#0d3321; color:#86efac; }
.hint { color:#7089a8; font-size:11.5px; }
.err { background:#3b1216; border:1px solid #7f1d1d; color:#fecaca;
       padding:10px 14px; border-radius:10px; margin-bottom:14px; font-size:13px; }
footer { color:#5f7595; font-size:11.5px; text-align:center; margin-top:22px; }
"""


def esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def page(body: str, title: str = "REPLATFORM") -> str:
    scope = "محمية برمز وصول" if SERVER.get("token") else "محلية"
    return f"""<!DOCTYPE html>
<html dir="rtl" lang="ar"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title><style>{CSS}</style></head>
<body>{body}
<footer>REPLATFORM v{__version__} — واجهة {scope}</footer>
</body></html>"""


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


_ANALYZE_LOCK = threading.Lock()
MAX_ANALYZE_PATH = 4096
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class AnalysisBusy(RuntimeError):
    """يُرفع عند وجود تحليل ويب قيد التنفيذ بالفعل."""


@contextmanager
def _analysis_slot():
    """يمنع تحليلين متزامنين من التداخل على مساحات العمل نفسها."""
    if not _ANALYZE_LOCK.acquire(blocking=False):
        raise AnalysisBusy("يوجد تحليل قيد التنفيذ بالفعل — انتظر انتهاءه.")
    try:
        yield
    finally:
        _ANALYZE_LOCK.release()


def _is_loopback(host: str) -> bool:
    value = (host or "").strip().lower()
    return value in LOOPBACK_HOSTS or value.startswith("127.")


def _configured_roots() -> list[Path]:
    roots: list[Path] = []
    for value in load_config().get("web", {}).get("allowed_roots") or []:
        try:
            roots.append(Path(str(value)).expanduser().resolve())
        except (OSError, RuntimeError, ValueError):
            continue
    return roots


def resolve_analyze_target(
    raw: str,
    *,
    remote: bool = False,
    allowed_roots: list[Path] | None = None,
) -> Path:
    """يتحقق من هدف التحليل ويمنع المسارات غير الآمنة أو الخارجة عن الجذور."""
    text = str(raw or "").strip().strip('"')
    if not text or len(text) > MAX_ANALYZE_PATH or "\x00" in text:
        raise ValueError("مسار التحليل غير صالح.")
    candidate = Path(text).expanduser()
    if candidate.is_symlink():
        raise ValueError("لا يُسمح بتحليل رابط رمزي (symlink) عبر الويب.")
    try:
        target = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"المسار غير موجود: {text}") from exc
    if not target.is_file():
        raise ValueError("هدف التحليل يجب أن يكون ملفاً عادياً.")
    if is_system_path(target):
        raise ValueError("ملفات مجلدات النظام مرفوضة كهدف تحليل عبر الويب.")

    raw_roots = (
        list(allowed_roots) if allowed_roots is not None else _configured_roots()
    )
    roots = [Path(root).expanduser().resolve() for root in raw_roots]
    if remote and not roots:
        roots = [ROOT.resolve()]
    if roots and not any(target.is_relative_to(root) for root in roots):
        raise ValueError("المسار خارج الجذور المسموح بها للتحليل عبر الويب.")
    return target


def _workspace_for(candidates: list[Workspace], target: Path) -> Workspace | None:
    """يختار مساحة العمل التي تطابق الهدف، لا أول مساحة ظهرت بالصدفة."""
    wanted = str(target).casefold()
    for workspace in candidates:
        try:
            meta = workspace.meta
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        current = str((meta.get("target") or {}).get("path") or "")
        if current and current.casefold() == wanted:
            return workspace
    return candidates[0] if candidates else None


def login_page(error: str = "", next_path: str = "/") -> str:
    error_html = f'<div class="err">{esc(error)}</div>' if error else ""
    body = f"""
<header><h1>REPLATFORM — دخول</h1>
<p>الواجهة محمية برمز وصول.</p></header>
<section class="card" style="max-width:430px;margin:40px auto;">
  {error_html}
  <form method="post" action="/login">
    <input type="hidden" name="next" value="{esc(next_path)}">
    <input type="password" name="token" placeholder="رمز الوصول" autofocus
           style="width:100%;padding:10px 12px;border-radius:9px;border:1px solid #2a3f63;background:#111c31;color:#dbe4f0;">
    <button type="submit">دخول</button>
  </form>
  <p class="hint">لا تشارك الرمز. الجلسة تُحفظ في كوكي HttpOnly.</p>
</section>"""
    return page(body, "دخول — REPLATFORM")


_TOOLS_CACHE: dict = {"at": 0.0, "data": []}


def _tools_cached(ttl: float = 30.0) -> list:
    now = time.monotonic()
    if _TOOLS_CACHE["data"] and now - _TOOLS_CACHE["at"] < ttl:
        return _TOOLS_CACHE["data"]
    data = detect_tools()
    _TOOLS_CACHE.update({"at": now, "data": data})
    return data


def dashboard(error: str = "") -> str:
    tools = _tools_cached()
    chips = "".join(
        f'<span class="chip {"ok" if t["ok"] else "bad"}">'
        f'{"✓" if t["ok"] else "✗"} {esc(t["name"])}</span>'
        for t in tools
    )
    state = get_state()
    current = state.get("target") or ""
    current_html = (
        f'<p>الاسم: <b>{esc(state.get("name", ""))}</b></p>'
        f'<p>النوع: <b>{esc(state.get("kind", ""))}</b> — الحجم: <b>{int(state.get("size") or 0):,}</b> بايت</p>'
        f'<p style="direction:ltr;font-family:Consolas,monospace;font-size:11px;word-break:break-all;">{esc(current)}</p>'
        if current else '<p>لم تحدد ملفاً بعد. استخدم <b>repl.py use &lt;file&gt;</b> أو النموذج المجاور.</p>'
    )

    rows = []
    for workspace in Workspace.list_all()[:60]:
        meta = workspace.safe_meta()
        verdict = (workspace.load_agent("result") or {}).get("verdict", "")
        badge = (
            f'<span class="badge {esc(verdict)}">{esc(VERDICT_LABEL.get(verdict, ""))}</span>'
            if verdict else ""
        )
        rows.append(
            f'<tr><td><a href="/report/{esc(workspace.id)}">{esc(workspace.id)}</a></td>'
            f'<td>{esc(meta.get("name", ""))}</td>'
            f'<td>{esc(meta.get("kind", ""))}</td>'
            f'<td>{badge}</td>'
            f'<td>{esc(meta.get("created", ""))}</td>'
            f'<td><a href="/report/{esc(workspace.id)}/pdf">PDF</a> · '
            f'<a href="/report/{esc(workspace.id)}/json">JSON</a></td></tr>'
        )
    table = (
        '<table><thead><tr><th>المعرّف</th><th>الاسم</th><th>النوع</th>'
        '<th>الحكم</th><th>أُنشئ</th><th>تصدير</th></tr></thead><tbody>'
        + ("".join(rows) or '<tr><td colspan="6" class="hint">لا مساحات عمل بعد.</td></tr>')
        + "</tbody></table>"
    )

    diffs_dir = ROOT / "diffs"
    diff_rows = []
    if diffs_dir.exists():
        for entry in sorted((p for p in diffs_dir.iterdir() if p.is_dir()), reverse=True)[:20]:
            if (entry / "report.html").exists():
                diff_rows.append(
                    f'<tr><td><a href="/diff/{esc(entry.name)}">{esc(entry.name)}</a> · '
                    f'<a href="/diff/{esc(entry.name)}/pdf">PDF</a></td></tr>'
                )
    diffs_html = (
        '<section><h2>مقارنات النسخ (bin-diff)</h2><table><tbody>'
        + "".join(diff_rows) + "</tbody></table></section>"
    ) if diff_rows else ""

    scans_dir = ROOT / "scans"
    scan_rows = []
    if scans_dir.exists():
        for entry in sorted((p for p in scans_dir.iterdir() if p.is_dir()), reverse=True)[:20]:
            if not (entry / "summary.html").exists():
                continue
            label = entry.name
            summary = entry / "summary.json"
            if summary.exists():
                try:
                    data = json.loads(summary.read_text("utf-8"))
                    label = (f"{entry.name} — {data.get('file_count', 0)} ملف، "
                             f"مرتفع {data.get('counts', {}).get('critical', 0)}")
                except (OSError, json.JSONDecodeError):
                    pass
            scan_rows.append(
                f'<tr><td><a href="/scan/{esc(entry.name)}">{esc(label)}</a> · '
                f'<a href="/scan/{esc(entry.name)}/pdf">PDF</a></td></tr>'
            )
    scans_html = (
        '<section><h2>فحوصات الدفعات (scan)</h2><table><tbody>'
        + "".join(scan_rows) + "</tbody></table></section>"
    ) if scan_rows else ""

    error_html = f'<div class="err">{esc(error)}</div>' if error else ""
    body = f"""
<header><h1>REPLATFORM</h1><p>لوحة تحكم محلية — تحليل وتعديل EXE / APK</p></header>
{error_html}
<div class="grid">
  <section class="card"><h2>الملف المستهدف الحالي</h2>{current_html}</section>
  <section class="card"><h2>تحليل سريع</h2>
    <form method="post" action="/api/analyze">
      <input type="text" name="path" value="{esc(current)}"
             placeholder="C:\\path\\to\\app.exe  /  app.apk">
      <button type="submit">تحليل الآن</button>
    </form>
    <p class="hint">يُنفَّذ على هذا الجهاز فقط. المسار يجب أن يكون موجوداً.</p>
  </section>
  <section class="card"><h2>الأدوات</h2><div class="chips">{chips}</div></section>
</div>
<section><h2>مساحات العمل</h2>{table}</section>
{diffs_html}
{scans_html}
"""
    return page(body)


class Handler(BaseHTTPRequestHandler):
    server_version = f"REPLATFORM/{__version__}"

    def log_message(self, *_args) -> None:  # تقليل الضجيج
        pass

    def _send(
        self,
        code: int,
        content: str | bytes,
        ctype: str = "text/html; charset=utf-8",
        cookies: list[str] | None = None,
    ) -> None:
        body = content if isinstance(content, bytes) else content.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; "
            "form-action 'self'; base-uri 'none'",
        )
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, cookies: list[str] | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _host_allowed(self, host: str | None = None) -> bool:
        value = (host if host is not None else
                 (urlparse(f"//{self.headers.get('Host', '')}").hostname or ""))
        value = value.lower()
        if not value or value in ("127.0.0.1", "localhost", "::1"):
            return True
        return value in SERVER["allowed_hosts"]

    def _local_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        return self._host_allowed(parsed.hostname or "")

    def _cookie_ok(self) -> bool:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:  # noqa: BLE001
            return False
        morsel = cookie.get(COOKIE_NAME)
        return bool(morsel and SERVER["token"]
                    and hmac.compare_digest(morsel.value, _token_hash(SERVER["token"])))

    def _header_ok(self) -> bool:
        header = (self.headers.get("Authorization") or "").strip()
        if not header.lower().startswith("bearer "):
            return False
        return bool(SERVER["token"] and hmac.compare_digest(
            header[7:].strip(), SERVER["token"]
        ))

    def _authorized(self) -> bool:
        return not SERVER["token"] or self._cookie_ok() or self._header_ok()

    def _login_cookie(self) -> str:
        return (
            f"{COOKIE_NAME}={_token_hash(SERVER['token'])}; Path=/; "
            "HttpOnly; SameSite=Strict; Max-Age=43200"
        )

    def _safe_next(self, value: str) -> str:
        if not value.startswith("/") or value.startswith("//") or "\\" in value:
            return "/"
        return value

    def _unauthorized(self, parsed) -> None:
        if parsed.path.startswith("/api/"):
            return self._send(
                401, json.dumps({"error": "unauthorized"}, ensure_ascii=False),
                "application/json; charset=utf-8",
            )
        return self._send(401, login_page(next_path=self._safe_next(parsed.path)))

    def _handle_login(self, parsed) -> None:
        query = parse_qs(parsed.query)
        target = self._safe_next((query.get("next") or ["/"])[0])
        # لا نقبل الرمز في الرابط (قد يتسرب في السجل/Referer)؛ POST أو Bearer فقط.
        return self._send(200, login_page(next_path=target))

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_allowed():
            return self._send(403, page("<h2>403 — مضيف غير مسموح</h2>"))
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return None
        if path == "/login":
            return self._handle_login(parsed)
        if not self._authorized():
            return self._unauthorized(parsed)
        if path == "/":
            query = parse_qs(parsed.query)
            error = (query.get("error") or [""])[0]
            return self._send(200, dashboard(error))
        if path == "/api/status":
            payload = {
                "tools": _tools_cached(),
                "workspaces": [
                    {"id": w.id, "meta": w.safe_meta()}
                    for w in Workspace.list_all()[:60]
                ],
                "current": get_state(),
            }
            return self._send(200, json.dumps(payload, ensure_ascii=False),
                              "application/json; charset=utf-8")
        if path.startswith("/diff/"):
            rest = unquote(path.split("/diff/", 1)[1].strip("/"))
            want_pdf = rest.endswith("/pdf")
            name = rest.rsplit("/", 1)[0] if want_pdf else rest
            if not name or name != Path(name).name:
                return self._send(404, page("<h2>404</h2>"))
            report = ROOT / "diffs" / name / "report.html"
            if not report.exists():
                return self._send(404, page("<h2>تقرير المقارنة غير موجود</h2>"))
            if want_pdf:
                try:
                    pdf = report.with_suffix(".pdf")
                    if not pdf.exists():
                        html_to_pdf(report, pdf)
                    return self._send(200, pdf.read_bytes(), "application/pdf")
                except Exception as exc:  # noqa: BLE001
                    return self._send(500, page(f"<h2>تعذر تصدير PDF</h2><p class='hint'>{esc(exc)}</p>"))
            return self._send(200, report.read_text("utf-8"))

        if path.startswith("/scan/"):
            rest = unquote(path.split("/scan/", 1)[1].strip("/"))
            want_pdf = rest.endswith("/pdf")
            name = rest.rsplit("/", 1)[0] if want_pdf else rest
            if not name or name != Path(name).name:
                return self._send(404, page("<h2>404</h2>"))
            report = ROOT / "scans" / name / "summary.html"
            if not report.exists():
                return self._send(404, page("<h2>تقرير الفحص غير موجود</h2>"))
            if want_pdf:
                try:
                    pdf = report.with_suffix(".pdf")
                    if not pdf.exists():
                        html_to_pdf(report, pdf)
                    return self._send(200, pdf.read_bytes(), "application/pdf")
                except Exception as exc:  # noqa: BLE001
                    return self._send(500, page(f"<h2>تعذر تصدير PDF</h2><p class='hint'>{esc(exc)}</p>"))
            return self._send(200, report.read_text("utf-8"))
        if path.startswith("/report/"):
            rest = unquote(path.split("/report/", 1)[1].strip("/"))
            want_pdf = rest.endswith("/pdf")
            want_json = rest.endswith("/json")
            wsid = rest.rsplit("/", 1)[0] if (want_pdf or want_json) else rest
            try:
                workspace = Workspace.find(wsid)
            except (FileNotFoundError, ValueError, OSError):
                return self._send(404, page("<h2>التقرير غير موجود</h2>"))
            try:
                from ..reports import export_json, export_pdf, render

                if want_json:
                    return self._send(
                        200, export_json(workspace).read_text("utf-8"),
                        "application/json; charset=utf-8",
                    )
                if want_pdf:
                    pdf = export_pdf(workspace)
                    return self._send(200, pdf.read_bytes(), "application/pdf")
                report = workspace.path / "report.html"
                if not report.exists():
                    render(workspace)
                return self._send(200, report.read_text("utf-8"))
            except Exception as exc:  # noqa: BLE001
                return self._send(
                    500,
                    page(f"<h2>تعذر إنشاء التقرير</h2><p class='hint'>{esc(exc)}</p>"),
                )
        return self._send(404, page("<h2>404</h2>"))

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_allowed() or not self._local_origin():
            return self._send(403, page("<h2>403 — طلب غير محلي</h2>"))
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length < 0 or length > 16 * 1024:
                return self._send(413, page("<h2>413 — الطلب كبير</h2>"))
            form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
            supplied = (form.get("token") or [""])[0]
            target = self._safe_next((form.get("next") or ["/"])[0])
            if SERVER["token"] and hmac.compare_digest(supplied, SERVER["token"]):
                return self._redirect(target, [self._login_cookie()])
            return self._send(401, login_page("رمز غير صحيح", target))
        if not self._authorized():
            return self._unauthorized(parsed)
        if parsed.path != "/api/analyze":
            return self._send(404, page("<h2>404</h2>"))
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length < 0 or length > 64 * 1024:
            return self._send(413, page("<h2>413 — الطلب كبير</h2>"))
        form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        raw_target = (form.get("path") or [""])[0]
        remote = not _is_loopback(str(self.client_address[0]))
        try:
            target = resolve_analyze_target(raw_target, remote=remote)
        except ValueError as exc:
            return self._redirect("/?" + urlencode({"error": str(exc)}))
        try:
            with _analysis_slot():
                before = {w.id for w in Workspace.list_all()}
                proc = subprocess.run(
                    [sys.executable, str(ROOT / "repl.py"), "analyze", str(target)],
                    capture_output=True, text=True, timeout=900,
                    encoding="utf-8", errors="replace",
                )
                new = [w for w in Workspace.list_all() if w.id not in before]
                workspace = _workspace_for(new, target)
        except AnalysisBusy as exc:
            return self._redirect("/?" + urlencode({"error": str(exc)}))
        except subprocess.TimeoutExpired:
            return self._redirect("/?" + urlencode({"error": "انتهت مهلة التحليل (15 دقيقة)"}))
        except OSError as exc:
            return self._redirect("/?" + urlencode({"error": f"تعذر تشغيل التحليل: {exc}"}))
        if workspace:
            return self._redirect(f"/report/{workspace.id}")
        detail = (proc.stderr or proc.stdout or "").strip()[-400:]
        return self._redirect("/?" + urlencode({"error": detail or "فشل التحليل"}))


def make_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    token: str = "",
    allowed_hosts: list[str] | None = None,
) -> ThreadingHTTPServer:
    """ينشئ الخادم دون تشغيله (مفيد للاختبار والتحقق من الإعداد)."""
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not token:
        raise ValueError(
            "الاستماع على واجهة غير محلية يتطلب رمز وصول (--token أو RE_WEB_TOKEN)."
        )
    SERVER["token"] = token or ""
    SERVER["host"] = host
    SERVER["allowed_hosts"] = {
        value.strip().lower() for value in (allowed_hosts or []) if value.strip()
    }
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd


def serve(
    port: int = 8765,
    open_browser: bool = False,
    host: str = "127.0.0.1",
    token: str = "",
    allowed_hosts: list[str] | None = None,
) -> None:
    httpd = make_server(host, port, token, allowed_hosts)
    bound_host, bound_port = httpd.server_address[:2]
    display_host = "127.0.0.1" if bound_host in ("0.0.0.0", "::") else bound_host  # noqa: S104 — مقارنة لا ربط
    url = f"http://{display_host}:{bound_port}/"
    print(f"واجهة REPLATFORM جاهزة: {url}")
    if token:
        print("  - محمية برمز وصول (Authorization: Bearer أو شاشة الدخول).")
    else:
        print("  - محلية فقط (127.0.0.1). أوقفها بـ Ctrl+C.")
    if open_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nإيقاف…")
    finally:
        httpd.server_close()
