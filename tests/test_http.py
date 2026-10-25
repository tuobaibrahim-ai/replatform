"""اختبارات عميل التكاملات الآمن: allowlist، HTTPS، حدود الاستجابة، والأخطاء."""

from __future__ import annotations

import io
import json
import ssl
import unittest
import urllib.error
from unittest.mock import patch

from replatform.integrations import http


class _Response:
    def __init__(self, body: bytes, content_length: str | None = None) -> None:
        self.body = body
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def read(self, limit: int | None = None) -> bytes:
        return self.body if limit is None else self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


class _Opener:
    def __init__(self, response=None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.requests: list = []

    def open(self, request, timeout=None):  # noqa: ARG002
        self.requests.append(request)
        if self.error:
            raise self.error
        return self.response


def _client(max_bytes: int = 8 * 1024 * 1024) -> http.SafeHTTPClient:
    return http.SafeHTTPClient(["api.example.test"], max_bytes=max_bytes)


class UrlValidationTests(unittest.TestCase):
    def test_accepts_https_on_default_port(self) -> None:
        parsed = http._validated_url(
            "https://api.example.test/v1/path", {"api.example.test"}
        )
        self.assertEqual(parsed.hostname, "api.example.test")

    def test_accepts_explicit_443(self) -> None:
        http._validated_url("https://api.example.test:443/x", {"api.example.test"})

    def test_rejects_http(self) -> None:
        with self.assertRaises(http.IntegrationError):
            http._validated_url("http://api.example.test/x", {"api.example.test"})

    def test_rejects_credentials(self) -> None:
        with self.assertRaises(http.IntegrationError):
            http._validated_url(
                "https://user:pass@api.example.test/x", {"api.example.test"}
            )

    def test_rejects_fragment(self) -> None:
        with self.assertRaises(http.IntegrationError):
            http._validated_url(
                "https://api.example.test/x#frag", {"api.example.test"}
            )

    def test_rejects_other_port(self) -> None:
        with self.assertRaises(http.IntegrationError):
            http._validated_url(
                "https://api.example.test:8443/x", {"api.example.test"}
            )

    def test_rejects_unknown_host(self) -> None:
        with self.assertRaises(http.IntegrationError):
            http._validated_url("https://evil.test/x", {"api.example.test"})

    def test_rejects_empty_host(self) -> None:
        with self.assertRaises(http.IntegrationError):
            http._validated_url("https:///x", {"api.example.test"})

    def test_rejects_invalid_port(self) -> None:
        with self.assertRaises(http.IntegrationError):
            http._validated_url(
                "https://api.example.test:notaport/x", {"api.example.test"}
            )

    def test_redirect_handler_always_refuses(self) -> None:
        with self.assertRaises(http.IntegrationError):
            http._NoRedirect().redirect_request(None, None, 302, "found", {}, "https://x")


class ClientInitTests(unittest.TestCase):
    def test_empty_allowlist_is_rejected(self) -> None:
        with self.assertRaises(http.IntegrationError):
            http.SafeHTTPClient([])

    def test_values_are_clamped(self) -> None:
        client = http.SafeHTTPClient(["API.Example.Test."], timeout=1, max_bytes=1)
        self.assertEqual(client.allowed_hosts, {"api.example.test"})
        self.assertEqual(client.timeout, 3.0)
        self.assertEqual(client.max_bytes, 1024)

    def test_ssl_context_verifies(self) -> None:
        context = http._ssl_context()
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertTrue(context.verify_mode == ssl.CERT_REQUIRED)


class RequestTests(unittest.TestCase):
    def test_get_json_with_params_and_headers(self) -> None:
        client = _client()
        fake = _Opener(_Response(b'{"ok": true}'))
        client._opener = fake
        result = client.get_json(
            "https://api.example.test/v1",
            params={"q": "a b", "skip": None},
            headers={"Auth-Key": "secret", "Empty": ""},
        )
        self.assertTrue(result["ok"])
        request = fake.requests[0]
        self.assertIn("q=a+b", request.full_url)
        self.assertNotIn("skip", request.full_url)
        self.assertEqual(request.get_header("Auth-key"), "secret")
        self.assertIsNone(request.get_header("Empty"))
        self.assertIn("REPLATFORM-Integrations", request.get_header("User-agent"))

    def test_post_json_payload(self) -> None:
        client = _client()
        fake = _Opener(_Response(b"[]"))
        client._opener = fake
        self.assertEqual(
            client.post_json("https://api.example.test/v1", payload={"a": 1}), []
        )
        request = fake.requests[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(request.data), {"a": 1})
        self.assertIn("application/json", request.get_header("Content-type"))

    def test_post_form(self) -> None:
        client = _client()
        fake = _Opener(_Response(b"{}"))
        client._opener = fake
        client.post_json("https://api.example.test/v1", form={"a": "b c"})
        request = fake.requests[0]
        self.assertEqual(request.data, b"a=b+c")
        self.assertIn("x-www-form-urlencoded", request.get_header("Content-type"))

    def test_payload_and_form_together_are_rejected(self) -> None:
        client = _client()
        with self.assertRaises(http.IntegrationError):
            client.post_json(
                "https://api.example.test/v1", payload={"a": 1}, form={"b": 2}
            )

    def test_declared_length_over_limit(self) -> None:
        client = _client(max_bytes=1024)
        client._opener = _Opener(_Response(b"{}", content_length="2048"))
        with self.assertRaises(http.IntegrationError):
            client.get_json("https://api.example.test/v1")

    def test_actual_body_over_limit(self) -> None:
        client = _client(max_bytes=1024)
        client._opener = _Opener(_Response(b"x" * 1025))
        with self.assertRaises(http.IntegrationError):
            client.get_json("https://api.example.test/v1")

    def test_invalid_utf8(self) -> None:
        client = _client()
        client._opener = _Opener(_Response(b"\xff\xfe"))
        with self.assertRaises(http.IntegrationError):
            client.get_json("https://api.example.test/v1")

    def test_invalid_json(self) -> None:
        client = _client()
        client._opener = _Opener(_Response(b"{oops"))
        with self.assertRaises(http.IntegrationError):
            client.get_json("https://api.example.test/v1")

    def test_http_error_is_wrapped(self) -> None:
        client = _client()
        client._opener = _Opener(
            error=urllib.error.HTTPError(
                "https://api.example.test/v1",
                429,
                "rate limited",
                {},
                io.BytesIO(b"slow down"),
            )
        )
        with self.assertRaises(http.IntegrationError) as ctx:
            client.get_json("https://api.example.test/v1")
        self.assertIn("HTTP 429", str(ctx.exception))

    def test_network_error_is_wrapped(self) -> None:
        client = _client()
        client._opener = _Opener(error=OSError("offline"))
        with self.assertRaises(http.IntegrationError):
            client.get_json("https://api.example.test/v1")

    def test_redirect_guard_is_installed(self) -> None:
        with patch.object(http.urllib.request, "build_opener") as mocked:
            http.SafeHTTPClient(["api.example.test"])
        handlers = mocked.call_args.args
        self.assertTrue(any(isinstance(h, http._NoRedirect) for h in handlers))


if __name__ == "__main__":
    unittest.main()
