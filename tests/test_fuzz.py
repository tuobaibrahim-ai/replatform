"""Fuzzing حتمي للمحللات والمدخلات الحرجة.

الهدف: التأكد أن المدخلات العشوائية لا تُسقط العملية باستثناءات غير متوقعة،
وأن كل رفض يمر عبر ValueError/IntegrationError المعلنة. البذرة ثابتة
لتبقى النتائج قابلة لإعادة الإنتاج في CI.
"""

from __future__ import annotations

import random
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from replatform.analyzers import apk_analyzer, strings_analyzer
from replatform.integrations import connectors
from replatform.integrations import http as integration_http
from replatform.tools import patcher
from replatform.web import server

SEED = 20261025
ITERATIONS = 300
ALPHABET = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ":/\\?&=%.-_ \t\n\r\x00\x01\x7f<>\"'{}[]()$^*+|~`"
    "ابتثجحخدذرزسشصضطظعغفقكلمنهوي"
)


def _random_text(rng: random.Random, maximum: int = 80) -> str:
    length = rng.randrange(0, maximum)
    return "".join(rng.choice(ALPHABET) for _ in range(length))


class ParserFuzzTests(unittest.TestCase):
    def test_parse_spec_only_raises_value_error(self) -> None:
        rng = random.Random(SEED)
        for _ in range(ITERATIONS):
            spec = _random_text(rng, 60)
            try:
                patcher.parse_spec(spec, "ascii", allow_wild=True)
            except ValueError:
                pass
            except Exception as exc:  # noqa: BLE001
                self.fail(f"استثناء غير متوقع لنمط {spec!r}: {type(exc).__name__}: {exc}")

    def test_clean_query_only_raises_integration_error(self) -> None:
        rng = random.Random(SEED + 1)
        for _ in range(ITERATIONS):
            query = _random_text(rng, 700)
            try:
                connectors._clean_query(query)
            except connectors.IntegrationError:
                pass
            except Exception as exc:  # noqa: BLE001
                self.fail(f"استثناء غير متوقع للاستعلام: {type(exc).__name__}: {exc}")

    def test_indicator_kind_only_raises_integration_error(self) -> None:
        rng = random.Random(SEED + 2)
        for _ in range(ITERATIONS):
            value = _random_text(rng, 90)
            try:
                connectors._indicator_kind(value)
            except connectors.IntegrationError:
                pass
            except Exception as exc:  # noqa: BLE001
                self.fail(f"استثناء غير متوقع للمؤشر {value!r}: {type(exc).__name__}")

    def test_validated_url_only_raises_integration_error(self) -> None:
        rng = random.Random(SEED + 3)
        for _ in range(ITERATIONS):
            url = _random_text(rng, 120)
            try:
                integration_http._validated_url(url, {"api.example.test"})
            except integration_http.IntegrationError:
                pass
            except Exception as exc:  # noqa: BLE001
                self.fail(f"استثناء غير متوقع للرابط {url!r}: {type(exc).__name__}")

    def test_manifest_parser_only_raises_parse_or_value_error(self) -> None:
        rng = random.Random(SEED + 4)
        for _ in range(ITERATIONS):
            text = _random_text(rng, 200)
            try:
                apk_analyzer.parse_manifest(text)
            except (ET.ParseError, ValueError):
                pass
            except Exception as exc:  # noqa: BLE001
                self.fail(f"استثناء غير متوقع للبيان: {type(exc).__name__}: {exc}")

    def test_pattern_validator_only_raises_value_error(self) -> None:
        rng = random.Random(SEED + 5)
        for _ in range(ITERATIONS):
            pattern = _random_text(rng, 400)
            try:
                strings_analyzer._validate_pattern(pattern)
            except ValueError:
                pass
            except Exception as exc:  # noqa: BLE001
                self.fail(f"استثناء غير متوقع للنمط: {type(exc).__name__}: {exc}")

    def test_regex_search_never_crashes_unexpectedly(self) -> None:
        rng = random.Random(SEED + 6)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"
            path.write_bytes(b"alpha-string\nhttps://example.test/x\n")
            for _ in range(ITERATIONS):
                pattern = _random_text(rng, 120)
                try:
                    strings_analyzer.search(str(path), pattern)
                except (ValueError, re.error):
                    pass
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"استثناء غير متوقع للبحث: {type(exc).__name__}: {exc}")


class PathFuzzTests(unittest.TestCase):
    def test_resolve_target_only_raises_value_error(self) -> None:
        rng = random.Random(SEED + 7)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for _ in range(ITERATIONS):
                raw = _random_text(rng, 120)
                try:
                    server.resolve_analyze_target(raw, allowed_roots=[root])
                except ValueError:
                    pass
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"استثناء غير متوقع للمسار: {type(exc).__name__}: {exc}")


class ValidManifestPropertyTests(unittest.TestCase):
    """مدخلات شبه صحيحة: الخصائص الأساسية يجب أن تبقى متسقة."""

    def test_random_manifests_keep_invariants(self) -> None:
        rng = random.Random(SEED + 8)
        for _ in range(120):
            package = f"com.example.{rng.randrange(10_000)}"
            target_sdk = rng.choice(["", "21", "30", "31", "34", "abc"])
            exported = rng.choice(["", "true", "false", "TRUE"])
            permission = rng.choice(["", "android.permission.X"])
            xml = (
                f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                f'package="{package}">'
                f'<uses-sdk android:minSdkVersion="21" '
                f'android:targetSdkVersion="{target_sdk}"/>'
                f'<application android:permission="{permission}">'
                f'<activity android:name=".Main" android:exported="{exported}">'
                f'<intent-filter><action android:name="android.intent.action.MAIN"/>'
                f'</intent-filter></activity>'
                f"</application></manifest>"
            )
            result = apk_analyzer.parse_manifest(xml)
            self.assertEqual(result["package"], package)
            self.assertEqual(result["components"]["activities"], 1)
            self.assertGreaterEqual(result["exported"], 0)
            self.assertGreaterEqual(result["exported_without_permission"], 0)
            self.assertGreaterEqual(result["exported_missing_explicit"], 0)


if __name__ == "__main__":
    unittest.main()
