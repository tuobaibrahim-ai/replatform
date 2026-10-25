"""عميل HTTP آمن للتكاملات الخارجية.

القيود الإلزامية:
- HTTPS فقط، ومنفذ 443 فقط.
- مضيف مسموح صراحةً (allowlist) لكل موصل.
- رفض كل إعادة توجيه.
- مهلة زمنية وسقف استجابة بالبايت.
- لا يخزّن مفاتيح ولا يطبعها؛ المفاتيح تُقرأ من البيئة.
"""

from __future__ import annotations

import json as jsonlib
import ssl
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = 20.0
DEFAULT_MAX_BYTES = 8 * 1024 * 1024
USER_AGENT = "REPLATFORM-Integrations/1.0 (read-only; security research)"


class IntegrationError(RuntimeError):
    """خطأ تكامل آمن وقابل للعرض للمستخدم."""


def _ssl_context() -> ssl.SSLContext:
    """سياق TLS يتحقق من الشهادة والمضيف، مع حزمة CA حديثة عند توفرها.

    Python على Windows قد لا يضم بعض سلاسل الشهادات الحديثة (مثل SwissSign
    المستخدمة في URLhaus)؛ certifi يوفّر حزمة موثوقة دون تعطيل التحقق.
    """
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except (ImportError, OSError):
        return ssl.create_default_context()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """يمنع أي إعادة توجيه، حتى لا يُسحب الطلب إلى مضيف غير مسموح."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise IntegrationError(f"إعادة توجيه مرفوضة ({code}): {newurl}")


def _validated_url(url: str, allowed_hosts: set[str]) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    if parsed.scheme.lower() != "https":
        raise IntegrationError("التكاملات الخارجية تتطلب https:// فقط.")
    if parsed.username or parsed.password:
        raise IntegrationError("لا يُسمح ببيانات دخول داخل الرابط.")
    if parsed.fragment:
        raise IntegrationError("روابط التكامل لا تقبل fragment.")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise IntegrationError("الرابط بلا مضيف صالح.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise IntegrationError("منفذ غير صالح في رابط التكامل.") from exc
    if port not in (None, 443):
        raise IntegrationError("يُسمح بالمنفذ 443 فقط.")
    if host not in allowed_hosts:
        raise IntegrationError(f"مضيف غير مسموح: {host}")
    return parsed


class SafeHTTPClient:
    """عميل JSON مقيد لمضيف واحد أو أكثر من المضيفين المصرح بهم."""

    def __init__(
        self,
        allowed_hosts: set[str] | list[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        user_agent: str = USER_AGENT,
    ) -> None:
        hosts = {
            str(host).strip().lower().rstrip(".")
            for host in allowed_hosts
            if str(host).strip()
        }
        if not hosts:
            raise IntegrationError("قائمة المضيفين المسموحين فارغة.")
        self.allowed_hosts = hosts
        self.timeout = max(3.0, min(float(timeout), 120.0))
        self.max_bytes = max(1024, min(int(max_bytes), 64 * 1024 * 1024))
        self.user_agent = user_agent
        self._opener = urllib.request.build_opener(
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=_ssl_context()),
        )

    def get_json(
        self,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> object:
        return self._request("GET", url, params=params, headers=headers)

    def post_json(
        self,
        url: str,
        *,
        payload: dict | None = None,
        form: dict | None = None,
        headers: dict | None = None,
    ) -> object:
        if payload is not None and form is not None:
            raise IntegrationError("لا يمكن إرسال JSON وform معاً.")
        return self._request(
            "POST", url, json_payload=payload, form_payload=form, headers=headers
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        json_payload: dict | None = None,
        form_payload: dict | None = None,
        headers: dict | None = None,
    ) -> object:
        parsed = _validated_url(url, self.allowed_hosts)
        if params:
            query = urllib.parse.urlencode(
                {key: value for key, value in params.items() if value is not None},
                doseq=True,
            )
            if query:
                parsed = parsed._replace(query=query)
        target = urllib.parse.urlunsplit(parsed)

        request_headers = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        for key, value in (headers or {}).items():
            if value is not None and str(value) != "":
                request_headers[str(key)] = str(value)

        data: bytes | None = None
        if json_payload is not None:
            data = jsonlib.dumps(json_payload, ensure_ascii=False).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        elif form_payload is not None:
            data = urllib.parse.urlencode(form_payload).encode("utf-8")
            request_headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded"
            )

        request = urllib.request.Request(  # noqa: S310 — هدف https + allowlist مضيفين
            target, data=data, headers=request_headers, method=method
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                declared = response.headers.get("Content-Length")
                if declared:
                    try:
                        declared_bytes = int(declared)
                    except ValueError:
                        declared_bytes = 0
                    if declared_bytes > self.max_bytes:
                        raise IntegrationError(
                            "استجابة التكامل تتجاوز الحد المسموح "
                            f"({self.max_bytes // (1024 * 1024)} MB)."
                        )
                raw = response.read(self.max_bytes + 1)
        except IntegrationError:
            raise
        except urllib.error.HTTPError as exc:
            body = exc.read(512).decode("utf-8", errors="replace").strip()
            raise IntegrationError(f"HTTP {exc.code}: {body[:400]}") from exc
        except OSError as exc:
            raise IntegrationError(f"تعذر الاتصال بالتكامل: {exc}") from exc

        if len(raw) > self.max_bytes:
            raise IntegrationError(
                "استجابة التكامل تتجاوز الحد المسموح "
                f"({self.max_bytes // (1024 * 1024)} MB)."
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IntegrationError("استجابة التكامل ليست UTF-8 صالحة.") from exc
        try:
            return jsonlib.loads(text)
        except jsonlib.JSONDecodeError as exc:
            raise IntegrationError(f"استجابة JSON غير صالحة: {exc}") from exc
