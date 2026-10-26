"""مزوّدو نماذج الذكاء الاصطناعي: OpenAI-compatible + Mock للاختبار."""

from __future__ import annotations

import copy
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from ..core.config import api_key


class ProviderError(RuntimeError):
    pass


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """يمنع إعادة التوجيه الخطرة (خفض HTTPS أو تغيير المضيف/المنفذ)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        original = urllib.parse.urlparse(req.full_url)
        target = urllib.parse.urlparse(newurl)
        if target.scheme not in ("http", "https"):
            raise ProviderError(
                f"إعادة توجيه إلى مخطط غير مدعوم: {target.scheme or '(فارغ)'}"
            )
        if original.scheme == "https" and target.scheme != "https":
            raise ProviderError("إعادة توجيه من HTTPS إلى HTTP مرفوضة.")
        if (target.hostname or "").lower() != (original.hostname or "").lower():
            raise ProviderError("إعادة توجيه إلى مضيف مختلف مرفوضة.")
        original_port = original.port or (443 if original.scheme == "https" else 80)
        target_port = target.port or (443 if target.scheme == "https" else 80)
        if target_port != original_port:
            raise ProviderError("إعادة توجيه إلى منفذ مختلف مرفوضة.")
        return new


class OpenAIProvider:
    """أي خدمة متوافقة مع /chat/completions (OpenAI, DeepSeek, Groq, Ollama...)."""

    def __init__(self, cfg: dict) -> None:
        provider = cfg.get("provider", {})
        self.base_url = (provider.get("base_url") or "").rstrip("/")
        self.model = provider.get("model") or "gpt-4o-mini"
        self.key = api_key(cfg)
        self.timeout = max(5.0, min(float(provider.get("timeout") or 120), 600.0))
        self.temperature = max(
            0.0,
            min(
                float(
                    provider.get("temperature")
                    if provider.get("temperature") is not None
                    else 0.2
                ),
                2.0,
            ),
        )
        self.retries = max(0, min(int(provider.get("retries", 2)), 5))
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ProviderError(
                "provider.base_url غير صالح — مثال: https://api.openai.com/v1"
            )
        if parsed.username or parsed.password:
            raise ProviderError(
                "provider.base_url لا يجوز أن يحتوي بيانات دخول — استخدم api_key."
            )
        self.host = (parsed.hostname or "").lower()
        self.is_local = self.host in ("127.0.0.1", "localhost", "::1")
        if parsed.scheme == "http" and not self.is_local:
            raise ProviderError(
                "provider.base_url يجب أن يستخدم https:// — "
                "يُسمح بـ http للمضيف المحلي فقط."
            )
        try:
            limit_mb = int(provider.get("max_response_mb", 8))
        except (TypeError, ValueError):
            limit_mb = 8
        self.max_response_bytes = max(1, min(limit_mb, 64)) * 1024 * 1024
        self._opener = urllib.request.build_opener(_SafeRedirectHandler())

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        if not self.key and not self.is_local:
            raise ProviderError(
                "لا يوجد مفتاح API. اضبط RE_API_KEY في البيئة أو config.json "
                "(provider.api_key)، أو استخدم نموذجاً محلياً على 127.0.0.1."
            )
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        request = urllib.request.Request(  # noqa: S310 — المخطط https مُتحقَّق في __init__
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            for attempt in range(self.retries + 1):
                try:
                    with self._opener.open(request, timeout=self.timeout) as response:
                        declared = response.headers.get("Content-Length")
                        if declared:
                            try:
                                declared_bytes = int(declared)
                            except ValueError:
                                declared_bytes = 0
                            if declared_bytes > self.max_response_bytes:
                                raise ProviderError(
                                    "استجابة المزوّد تتجاوز الحد المسموح "
                                    f"({self.max_response_bytes // (1024 * 1024)} MB)."
                                )
                        raw_bytes = response.read(self.max_response_bytes + 1)
                except urllib.error.HTTPError as exc:
                    body = exc.read(1024).decode("utf-8", errors="replace")[:500]
                    if exc.code in (429, 500, 502, 503, 504) and attempt < self.retries:
                        time.sleep(min(5.0, 1.0 * (attempt + 1)))
                        continue
                    raise ProviderError(f"HTTP {exc.code}: {body}") from exc
                except (urllib.error.URLError, TimeoutError) as exc:
                    if attempt < self.retries:
                        time.sleep(min(5.0, 1.0 * (attempt + 1)))
                        continue
                    raise ProviderError(f"تعذر الاتصال بالمزوّد: {exc}") from exc

                if len(raw_bytes) > self.max_response_bytes:
                    raise ProviderError(
                        "استجابة المزوّد تتجاوز الحد المسموح "
                        f"({self.max_response_bytes // (1024 * 1024)} MB)."
                    )
                try:
                    raw = raw_bytes.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ProviderError("استجابة المزوّد ليست UTF-8 صالحة.") from exc
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ProviderError(f"استجابة JSON غير صالحة: {exc}") from exc
                break
        except ProviderError:
            raise
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"استجابة غير متوقعة: {data}") from exc
        if not isinstance(message, dict):
            raise ProviderError("استجابة المزوّد لا تحتوي رسالة صالحة")
        message["_usage"] = data.get("usage") or {}
        return message


class MockProvider:
    """مزوّد اختباري: يعيد سلسلة ردود جاهزة (لا يحتاج شبكة أو مفتاح)."""

    def __init__(self, script: list[dict]) -> None:
        self.script = script
        self.index = 0
        self.model = "mock"

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:  # noqa: ARG002
        if self.index >= len(self.script):
            return {"role": "assistant", "content": "(انتهى السكربت التجريبي)"}
        message = copy.deepcopy(self.script[self.index])
        self.index += 1
        return message


def build_provider(cfg: dict, mock_path: str | None = None) -> "OpenAIProvider | MockProvider":
    """ينشئ المزوّد المناسب. RE_PROVIDER=mock أو provider.type=mock للاختبار."""
    provider = cfg.get("provider", {})
    kind = str(provider.get("type") or "openai-compatible").lower()
    if kind not in ("mock", "openai-compatible", "openai", "ollama", "local"):
        raise ProviderError(
            f"نوع مزوّد غير مدعوم: {kind} — المدعوم: openai-compatible, ollama, mock"
        )
    if os.environ.get("RE_PROVIDER") == "mock" or kind == "mock":
        target = (
            mock_path
            or provider.get("mock_path")
            or os.environ.get("RE_MOCK_PATH", "")
        )
        script: list[dict] = [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": "call_mock_1",
                    "type": "function",
                    "function": {"name": "analyze_file",
                                 "arguments": json.dumps({"path": target}, ensure_ascii=False)},
                }],
            },
            {
                "role": "assistant",
                "content": "تم استلام نتيجة التحليل. الملف سليم البنية وفق الفحص الآلي.",
            },
        ]
        return MockProvider(script)
    return OpenAIProvider(cfg)
