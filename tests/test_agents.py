"""اختبارات الوكلاء: المزوّدون، الأدوات، الحلقة، وضغط السياق (بلا شبكة)."""

from __future__ import annotations

import io
import json
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from replatform.agents import loop, provider, tools, tokenizer


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, data: bytes | str) -> Path:
        path = self.tmp / name
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path


# ---------------------------------------------------------------------------
# المزوّدون
# ---------------------------------------------------------------------------


def _cfg(**provider_overrides) -> dict:
    base = {
        "base_url": "https://api.example.test/v1",
        "model": "test-model",
        "api_key": "",
        "api_key_env": "RE_TEST_KEY",
        "timeout": 30,
        "temperature": 0.2,
        "retries": 0,
        "max_response_mb": 8,
    }
    base.update(provider_overrides)
    return {"provider": base}


class _FakeResponse:
    def __init__(self, body: bytes, content_length: str | None = None) -> None:
        self._body = body
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def read(self, limit: int | None = None) -> bytes:
        return self._body if limit is None else self._body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


class _FakeOpener:
    def __init__(self, response=None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.requests: list = []

    def open(self, request, timeout=None):  # noqa: ARG002
        self.requests.append(request)
        if self.error:
            raise self.error
        return self.response


def _provider_with(response=None, error=None, **overrides) -> tuple:
    fake = _FakeOpener(response, error)
    with patch.object(provider.urllib.request, "build_opener", return_value=fake):
        instance = provider.OpenAIProvider(_cfg(**overrides))
    return instance, fake


class ProviderInitTests(unittest.TestCase):
    def test_https_base_url_is_accepted(self) -> None:
        instance, _ = _provider_with()
        self.assertEqual(instance.host, "api.example.test")
        self.assertFalse(instance.is_local)

    def test_local_http_is_allowed(self) -> None:
        for host in ("127.0.0.1", "localhost", "[::1]"):
            instance, _ = _provider_with(base_url=f"http://{host}:11434/v1")
            self.assertTrue(instance.is_local)

    def test_remote_http_is_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            _provider_with(base_url="http://api.example.test/v1")

    def test_credentials_in_url_are_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            _provider_with(base_url="https://user:pass@api.example.test/v1")

    def test_invalid_base_url_is_rejected(self) -> None:
        for value in ("", "not-a-url", "ftp://api.example.test/v1"):
            with self.assertRaises(provider.ProviderError):
                _provider_with(base_url=value)

    def test_limits_are_clamped(self) -> None:
        instance, _ = _provider_with(
            timeout=1, temperature=9, retries=99, max_response_mb=999
        )
        self.assertEqual(instance.timeout, 5.0)
        self.assertEqual(instance.temperature, 2.0)
        self.assertEqual(instance.retries, 5)
        self.assertEqual(instance.max_response_bytes, 64 * 1024 * 1024)

    def test_missing_key_blocks_remote_chat(self) -> None:
        instance, _ = _provider_with()
        with self.assertRaises(provider.ProviderError):
            instance.chat([{"role": "user", "content": "hi"}])

    def test_local_provider_does_not_require_key(self) -> None:
        instance, _ = _provider_with(
            base_url="http://127.0.0.1:11434/v1",
            max_response_mb=1,
        )
        body = json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}
        ).encode()
        instance._opener = _FakeOpener(_FakeResponse(body))
        message = instance.chat([{"role": "user", "content": "hi"}])
        self.assertEqual(message["content"], "ok")


class ProviderChatTests(unittest.TestCase):
    def _chat(self, response=None, error=None, **overrides):
        instance, fake = _provider_with(response, error, **overrides)
        instance.key = "secret"
        return instance.chat([{"role": "user", "content": "hi"}]), fake

    def test_success_attaches_usage_and_auth_header(self) -> None:
        body = json.dumps(
            {
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            }
        ).encode()
        message, fake = self._chat(_FakeResponse(body))
        self.assertEqual(message["content"], "ok")
        self.assertEqual(message["_usage"]["total_tokens"], 5)
        request = fake.requests[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer secret")
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["model"], "test-model")

    def test_tools_are_sent(self) -> None:
        body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
        instance, fake = _provider_with(_FakeResponse(body))
        instance.key = "k"
        instance.chat([{"role": "user", "content": "hi"}], tools=[{"type": "function"}])
        payload = json.loads(fake.requests[0].data.decode("utf-8"))
        self.assertEqual(payload["tool_choice"], "auto")
        self.assertIn("tools", payload)

    def test_declared_content_length_over_limit_is_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            self._chat(_FakeResponse(b"{}", content_length=str(9 * 1024 * 1024)))

    def test_actual_body_over_limit_is_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            self._chat(_FakeResponse(b"x" * (1024 * 1024 + 1)), max_response_mb=1)

    def test_invalid_utf8_is_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            self._chat(_FakeResponse(b"\xff\xfe\x00"))

    def test_invalid_json_is_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            self._chat(_FakeResponse(b"{not json"))

    def test_unexpected_shape_is_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            self._chat(_FakeResponse(b'{"choices": []}'))

    def test_http_error_is_wrapped(self) -> None:
        error = urllib.error.HTTPError(
            "https://api.example.test/v1/chat/completions",
            401,
            "unauthorized",
            {},
            io.BytesIO(b"bad key"),
        )
        with self.assertRaises(provider.ProviderError) as ctx:
            self._chat(error=error)
        self.assertIn("HTTP 401", str(ctx.exception))

    def test_transport_error_is_wrapped(self) -> None:
        with self.assertRaises(provider.ProviderError):
            self._chat(error=urllib.error.URLError("offline"))

    def test_retry_on_500_then_success(self) -> None:
        error = urllib.error.HTTPError(
            "https://api.example.test/v1/chat/completions",
            500,
            "server error",
            {},
            io.BytesIO(b"boom"),
        )
        instance, fake = _provider_with(error=error, retries=1)
        instance.key = "k"
        body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()

        def flaky(request, timeout=None):  # noqa: ARG001
            fake.requests.append(request)
            if len(fake.requests) == 1:
                raise error
            return _FakeResponse(body)

        fake.open = flaky
        with patch.object(provider.time, "sleep"):
            message = instance.chat([{"role": "user", "content": "hi"}])
        self.assertEqual(message["content"], "ok")
        self.assertEqual(len(fake.requests), 2)


class RedirectGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.handler = provider._SafeRedirectHandler()
        self.request = provider.urllib.request.Request("https://api.example.test/v1")

    def test_cross_host_redirect_is_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            self.handler.redirect_request(
                self.request, None, 302, "found", {}, "https://evil.test/v1"
            )

    def test_https_downgrade_is_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            self.handler.redirect_request(
                self.request, None, 302, "found", {}, "http://api.example.test/v1"
            )

    def test_port_change_is_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            self.handler.redirect_request(
                self.request, None, 302, "found", {}, "https://api.example.test:8443/v1"
            )

    def test_same_host_redirect_is_allowed(self) -> None:
        redirected = self.handler.redirect_request(
            self.request, None, 302, "found", {}, "https://api.example.test/v2"
        )
        self.assertIsNotNone(redirected)


class MockProviderTests(unittest.TestCase):
    def test_script_is_deep_copied_and_exhausts(self) -> None:
        script = [{"role": "assistant", "content": "first"}]
        mock = provider.MockProvider(script)
        first = mock.chat([])
        first["content"] = "mutated"
        self.assertEqual(script[0]["content"], "first")
        self.assertIn("انتهى", mock.chat([])["content"])

    def test_build_provider_mock_from_config(self) -> None:
        cfg = {"provider": {"type": "mock", "mock_path": "sample.exe"}}
        built = provider.build_provider(cfg)
        self.assertIsInstance(built, provider.MockProvider)
        call = built.chat([])
        self.assertEqual(call["tool_calls"][0]["function"]["name"], "analyze_file")
        self.assertIn("sample.exe", call["tool_calls"][0]["function"]["arguments"])

    def test_build_provider_mock_from_env(self) -> None:
        cfg = {"provider": {"type": "openai-compatible"}}
        with patch.dict("os.environ", {"RE_PROVIDER": "mock"}):
            self.assertIsInstance(provider.build_provider(cfg), provider.MockProvider)

    def test_unknown_provider_type_is_rejected(self) -> None:
        with self.assertRaises(provider.ProviderError):
            provider.build_provider({"provider": {"type": "unknown"}})


# ---------------------------------------------------------------------------
# أدوات الوكيل
# ---------------------------------------------------------------------------


class ToolGuardTests(TempDirTest):
    def setUp(self) -> None:
        super().setUp()
        tools.configure([])
        self.addCleanup(tools.configure, [])

    def test_configure_restricts_paths(self) -> None:
        allowed = self.tmp / "allowed"
        allowed.mkdir()
        inside = allowed / "a.txt"
        inside.write_text("x", "utf-8")
        outside = self.tmp / "outside.txt"
        outside.write_text("x", "utf-8")
        tools.configure([allowed])
        self.assertEqual(tools._checked(inside), inside.resolve())
        with self.assertRaises(PermissionError):
            tools._checked(outside)

    def test_configure_accepts_single_file(self) -> None:
        target = self.write("one.bin", b"data")
        tools.configure([target])
        self.assertEqual(tools._checked(target), target.resolve())

    def test_execute_unknown_tool(self) -> None:
        self.assertIn("غير معروفة", tools.execute("nope", {})["error"])

    def test_execute_bad_arguments(self) -> None:
        self.assertIn("معاملات", tools.execute("hexdump", {"bogus": 1})["error"])

    def test_tool_result_json_truncates(self) -> None:
        text = tools.tool_result_json({"x": "y" * 100}, limit=20)
        self.assertIn("اقتُطع", text)
        self.assertLessEqual(len(text), 40)


class ToolBehaviorTests(TempDirTest):
    def setUp(self) -> None:
        super().setUp()
        tools.configure([])
        self.addCleanup(tools.configure, [])

    def test_analyze_file_missing(self) -> None:
        self.assertIn("غير موجود", tools.analyze_file(str(self.tmp / "no.bin"))["error"])

    def test_analyze_file_plain_text(self) -> None:
        path = self.write("note.txt", "hello world")
        result = tools.analyze_file(str(path))
        self.assertEqual(result["kind"], "other")
        self.assertEqual(result["name"], "note.txt")
        self.assertEqual(len(result["sha256"]), 64)

    def test_analyze_file_pe_uses_quick_summary(self) -> None:
        path = self.write("a.exe", b"MZ" + b"\0" * 32)
        with patch.object(tools.pe_analyzer, "quick_summary", return_value={"arch": "x64"}):
            with patch.object(tools.util, "authenticode", return_value={"valid": False}):
                result = tools.analyze_file(str(path))
        self.assertEqual(result["pe"]["arch"], "x64")
        self.assertFalse(result["signature"]["valid"])

    def test_analyze_file_reports_parser_error(self) -> None:
        path = self.write("a.exe", b"MZ" + b"\0" * 32)
        with patch.object(
            tools.pe_analyzer, "quick_summary", side_effect=ValueError("bad pe")
        ):
            result = tools.analyze_file(str(path))
        self.assertIn("ValueError", result["error"])

    def test_analyze_file_rejects_oversized(self) -> None:
        path = self.write("big.bin", b"x" * 16)
        with patch.object(tools, "_too_large", return_value="too big"):
            self.assertEqual(tools.analyze_file(str(path))["error"], "too big")

    def test_apk_summary_is_cached(self) -> None:
        path = self.write("a.apk", b"PK")
        with patch.object(tools.util, "file_kind", return_value="APK"):
            with patch.object(
                tools.apk_analyzer, "quick_summary", return_value={"package": "x"}
            ) as mocked:
                first = tools.analyze_file(str(path))
                second = tools.analyze_file(str(path))
        self.assertEqual(first["apk"], {"package": "x"})
        self.assertEqual(second["apk"], {"package": "x"})
        self.assertEqual(mocked.call_count, 1)

    def test_strings_search(self) -> None:
        path = self.write("s.bin", b"alpha-string beta-string ALPHA-STRING")
        result = tools.strings_search(str(path), "alpha")
        self.assertEqual(result["count"], 1)

    def test_strings_search_rejects_bad_pattern(self) -> None:
        path = self.write("s.bin", b"alpha-string")
        self.assertIn("regex", tools.strings_search(str(path), "(a+)+b")["error"])
        self.assertIn("طويل", tools.strings_search(str(path), "a" * 501)["error"])

    def test_strings_search_missing_file(self) -> None:
        self.assertIn(
            "غير موجود", tools.strings_search(str(self.tmp / "no"), "x")["error"]
        )

    def test_hexdump(self) -> None:
        path = self.write("h.bin", bytes(range(32)))
        result = tools.hexdump(str(path), offset=16, length=16)
        self.assertEqual(result["offset"], 16)
        self.assertEqual(result["length"], 16)
        self.assertEqual(len(result["dump"]), 1)
        self.assertIn("00000010", result["dump"][0])

    def test_hexdump_missing_file(self) -> None:
        self.assertIn("غير موجود", tools.hexdump(str(self.tmp / "no"))["error"])

    def test_apk_manifest_on_non_apk_reports_error(self) -> None:
        path = self.write("a.apk", b"not a zip")
        self.assertIn("error", tools.apk_manifest(str(path)))

    def test_patch_preview_hex_and_str(self) -> None:
        path = self.write("p.bin", b"\x01\x02\x03hello\x01\x02\x03")
        hex_result = tools.patch_preview(str(path), "hex:01 ?? 03")
        self.assertEqual(hex_result["count"], 2)
        str_result = tools.patch_preview(str(path), "str:hello")
        self.assertEqual(str_result["count"], 1)

    def test_patch_preview_rejects_bad_spec(self) -> None:
        path = self.write("p.bin", b"data")
        self.assertIn("الصيغة", tools.patch_preview(str(path), "bin:41")["error"])
        self.assertIn("hex", tools.patch_preview(str(path), "hex:zz")["error"])

    def test_patch_preview_missing_file(self) -> None:
        self.assertIn(
            "غير موجود", tools.patch_preview(str(self.tmp / "no"), "str:x")["error"]
        )

    def test_intel_lookup_disabled_by_default(self) -> None:
        with patch.object(
            tools, "load_config", return_value={"integrations": {"agent_enabled": False}}
        ):
            result = tools.intel_lookup("nvd", "log4j")
        self.assertIn("معطّلة", result["error"])

    def test_intel_lookup_enabled_delegates(self) -> None:
        with patch.object(
            tools, "load_config", return_value={"integrations": {"agent_enabled": True}}
        ):
            with patch(
                "replatform.integrations.connectors.lookup",
                return_value={"found": True},
            ) as mocked:
                result = tools.intel_lookup("nvd", "log4j")
        self.assertTrue(result["found"])
        mocked.assert_called_once()


# ---------------------------------------------------------------------------
# حلقة الوكيل
# ---------------------------------------------------------------------------


class _Executor:
    def __init__(self, result=None) -> None:
        self.result = result or {"ok": True}
        self.calls: list[tuple] = []

    def __call__(self, name, args):
        self.calls.append((name, args))
        return self.result


class _SlowProvider:
    model = "slow"

    def chat(self, messages, tools=None):  # noqa: ARG002
        time.sleep(0.05)
        return {"role": "assistant", "content": "late"}


class LoopTextTests(unittest.TestCase):
    def test_text_accepts_str_list_and_none(self) -> None:
        self.assertEqual(loop._text("x"), "x")
        self.assertEqual(loop._text([{"text": "a"}, "b"]), "ab")
        self.assertEqual(loop._text(None), "")
        self.assertEqual(loop._text(3), "3")

    def test_message_chars_includes_tool_calls(self) -> None:
        messages = [
            {"role": "assistant", "content": None, "tool_calls": [{"id": "1"}]},
        ]
        self.assertGreater(loop._message_chars(messages), 0)


class CompactTests(unittest.TestCase):
    def _long_messages(self) -> list[dict]:
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "task " * 200},
        ]
        for index in range(4):
            messages.append(
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"id": f"c{index}", "function": {"name": "x"}}],
                }
            )
            messages.append({"role": "tool", "tool_call_id": f"c{index}", "content": "y" * 400})
        return messages

    def test_no_compaction_below_limit(self) -> None:
        messages = self._long_messages()
        before = loop._message_chars(messages)
        self.assertEqual(loop.compact_messages(messages, 10_000_000), before)

    def test_compaction_shrinks_and_removes_old_groups(self) -> None:
        messages = self._long_messages()
        before = loop._message_chars(messages)
        after = loop.compact_messages(messages, 900, keep_recent_tools=1)
        self.assertLess(after, before)
        self.assertTrue(any(m.get("role") == "tool" for m in messages))

    def test_zero_limit_is_noop(self) -> None:
        messages = self._long_messages()
        self.assertEqual(loop.compact_messages(messages, 0), loop._message_chars(messages))


class LoopRunTests(unittest.TestCase):
    def _tool_call(self, name="analyze_file", arguments=None, call_id="c1") -> dict:
        return {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": arguments
                        if isinstance(arguments, str)
                        else json.dumps(arguments or {"path": "x"}),
                    },
                }
            ],
        }

    def test_tool_then_answer(self) -> None:
        mock = provider.MockProvider(
            [
                self._tool_call(arguments={"path": "x"}),
                {"role": "assistant", "content": "final"},
            ]
        )
        executor = _Executor({"kind": "PE"})
        result = loop.run_agent("analyse", mock, executor=executor)
        self.assertEqual(result["status"], "done")
        self.assertEqual(result["answer"], "final")
        self.assertEqual(len(result["steps"]), 1)
        self.assertEqual(executor.calls[0][0], "analyze_file")
        self.assertIn("kind", result["messages"][-2]["content"])

    def test_invalid_json_arguments_are_reported(self) -> None:
        mock = provider.MockProvider(
            [
                self._tool_call(arguments="{not json"),
                {"role": "assistant", "content": "done"},
            ]
        )
        executor = _Executor()
        result = loop.run_agent("analyse", mock, executor=executor)
        self.assertEqual(executor.calls, [])
        self.assertIn("JSON", result["steps"][0]["result"]["error"])

    def test_tool_call_budget(self) -> None:
        calls = [
            self._tool_call(call_id=f"c{i}") for i in range(2)
        ]
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [call["tool_calls"][0] for call in calls],
        }
        mock = provider.MockProvider(
            [message, {"role": "assistant", "content": "done"}]
        )
        executor = _Executor()
        result = loop.run_agent("analyse", mock, executor=executor, max_tool_calls=1)
        self.assertEqual(len(executor.calls), 1)
        self.assertIn("الحد الأقصى", result["messages"][-2]["content"])

    def test_max_steps_is_reported(self) -> None:
        mock = provider.MockProvider([self._tool_call() for _ in range(5)])
        result = loop.run_agent("analyse", mock, executor=_Executor(), max_steps=2)
        self.assertEqual(result["status"], "max_steps")
        self.assertEqual(len(result["steps"]), 2)

    def test_timeout_is_reported(self) -> None:
        result = loop.run_agent("analyse", _SlowProvider(), max_seconds=0.01)
        self.assertEqual(result["status"], "timeout")

    def test_usage_is_accumulated(self) -> None:
        mock = provider.MockProvider(
            [
                {
                    "role": "assistant",
                    "content": "ok",
                    "_usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
                }
            ]
        )
        result = loop.run_agent("analyse", mock)
        self.assertEqual(result["usage"]["total_tokens"], 5)

    def test_skills_are_composed_into_system_prompt(self) -> None:
        mock = provider.MockProvider([{"role": "assistant", "content": "ok"}])
        result = loop.run_agent("analyse", mock, skills=["re-ethics"])
        self.assertIn("مهارات محمّلة", result["messages"][0]["content"])

    def test_skills_as_string(self) -> None:
        mock = provider.MockProvider([{"role": "assistant", "content": "ok"}])
        result = loop.run_agent("analyse", mock, skills="re-ethics")
        self.assertIn("مهارات محمّلة", result["messages"][0]["content"])


class TokenizerTests(unittest.TestCase):
    def test_count_text_and_engine(self) -> None:
        self.assertEqual(tokenizer.count_text(""), 0)
        self.assertGreaterEqual(tokenizer.count_text("hello"), 1)
        self.assertIsInstance(tokenizer.engine_name("unknown-model"), str)

    def test_count_messages_with_tool_calls(self) -> None:
        messages = [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"id": "1", "function": {"name": "x"}}],
            },
            {"role": "tool", "tool_call_id": "1", "content": "{}"},
        ]
        self.assertGreater(tokenizer.count_messages(messages), 10)


if __name__ == "__main__":
    unittest.main()
