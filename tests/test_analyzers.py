"""اختبارات المحللات النصية/PE، الوكيل القواعدي، وحواجز الويب."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from replatform.agents import heuristic
from replatform.analyzers import pe_analyzer, strings_analyzer
from replatform.core.workspace import Workspace
from replatform.core import workspace as workspace_mod
from replatform.web import server


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, data: bytes | str) -> Path:
        path = self.tmp / name
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path


class StringsTests(TempDirTest):
    def test_scan_extracts_notable_indicators(self) -> None:
        payload = (
            b"GET http://evil.test/payload.exe HTTP/1.1\n"
            b"8.8.8.8\n"
            b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            b"powershell -enc AAAA\n"
            b"-----BEGIN RSA PRIVATE KEY-----\n"
        )
        path = self.write("s.bin", payload)
        result = strings_analyzer.scan(str(path))
        self.assertGreater(result["total"], 0)
        self.assertIn("URL", result["notable"])
        self.assertIn("IP", result["notable"])
        self.assertIn("Registry", result["notable"])
        self.assertIn("Command", result["notable"])
        self.assertIn("Crypto", result["notable"])

    def test_scan_empty_file(self) -> None:
        path = self.write("empty.bin", b"")
        result = strings_analyzer.scan(str(path))
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["notable"], {})

    def test_scan_cache_returns_same_object(self) -> None:
        path = self.write("c.bin", b"hello world hello world")
        first = strings_analyzer.scan(str(path))
        second = strings_analyzer.scan(str(path))
        self.assertIs(first, second)

    def test_scan_respects_size_limit(self) -> None:
        path = self.write("big.bin", b"a" * 2048)
        with patch.object(
            strings_analyzer, "load_config", return_value={"analysis": {"strings_max_mb": 0}}
        ):
            with self.assertRaises(ValueError):
                strings_analyzer.scan(str(path))

    def test_search_finds_matches(self) -> None:
        path = self.write("s.txt", b"alpha-string\nbeta-string\nALPHA-STRING\n")
        self.assertEqual(len(strings_analyzer.search(str(path), "alpha")), 2)

    def test_search_rejects_dangerous_pattern(self) -> None:
        path = self.write("s.txt", b"alpha-string")
        with self.assertRaises(ValueError):
            strings_analyzer.search(str(path), "(a+)+b")
        with self.assertRaises(ValueError):
            strings_analyzer.search(str(path), r"(a)\1")


class PeTests(TempDirTest):
    def test_quick_summary_on_real_pe(self) -> None:
        sample = Path(__file__).resolve().parents[1] / "bin" / "7z-a.exe"
        if not sample.is_file():
            self.skipTest("عينة PE المحلية غير متاحة")
        summary = pe_analyzer.quick_summary(str(sample))
        self.assertTrue(summary["arch"].startswith("x"))
        self.assertGreater(len(summary["sections"]), 0)
        self.assertGreater(summary["import_functions"], 0)
        self.assertIn("aslr", summary["protections"])
        self.assertTrue(summary["entry_point"].startswith("0x"))

    def test_missing_pe_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            pe_analyzer.quick_summary(str(self.tmp / "nope.exe"))


class HeuristicTests(TempDirTest):
    def setUp(self) -> None:
        super().setUp()
        self._patch = patch.object(workspace_mod, "WORKSPACES_DIR", self.tmp / "ws")
        self._patch.start()
        self.addCleanup(self._patch.stop)
        target = self.write("sample.exe", b"MZ" + b"\0" * 10)
        self.ws = Workspace.create(target)

    def test_pe_triage_is_critical_and_persisted(self) -> None:
        artifacts = {
            "pe": {
                "score": 7,
                "findings": ["غير موقّع"],
                "summary": {
                    "arch": "x64",
                    "entry_point": "0x1000",
                    "import_functions": 42,
                    "protections": {"aslr": True, "dep": True, "cfg": False},
                },
            },
            "strings": {"notable": {"urls": ["http://x"]}},
        }
        result = heuristic.triage(
            self.ws, {"name": "sample.exe", "kind": "PE", "sha256": "a" * 64, "size": 12}, artifacts
        )
        self.assertEqual(result["verdict"], "critical")
        self.assertEqual(result["score"], 7)
        self.assertTrue((self.ws.path / "agent" / "summary.md").is_file())
        self.assertEqual(self.ws.load_agent("result")["mode"], "heuristic")
        self.assertEqual(self.ws.timeline()[-1]["kind"], "agent_done")
        self.assertIn("x64", result["summary_md"])

    def test_apk_triage_mentions_exported(self) -> None:
        artifacts = {
            "apk": {
                "score": 3,
                "manifest": {
                    "package": "com.test",
                    "version_name": "1.0",
                    "min_sdk": 21,
                    "target_sdk": 33,
                    "permissions": ["INTERNET"],
                    "exported": 2,
                },
            }
        }
        result = heuristic.triage(
            self.ws, {"name": "a.apk", "kind": "APK", "sha256": "b" * 64, "size": 100}, artifacts
        )
        self.assertEqual(result["verdict"], "warn")
        self.assertIn("com.test", result["summary_md"])
        self.assertIn("مكوّنات مُصدّرة: 2", result["summary_md"])

    def test_error_artifact_is_reported(self) -> None:
        artifacts = {"yara": {"error": "timeout", "analyzer": "yara"}}
        result = heuristic.triage(self.ws, {"name": "x", "kind": "PE"}, artifacts)
        self.assertEqual(result["verdict"], "info")
        self.assertTrue(any("timeout" in item for item in result["findings"]))


class WebGuardTests(TempDirTest):
    def test_loopback_detection(self) -> None:
        self.assertTrue(server._is_loopback("127.0.0.1"))
        self.assertTrue(server._is_loopback("localhost"))
        self.assertFalse(server._is_loopback("10.0.0.5"))

    def test_token_hash_is_stable(self) -> None:
        self.assertEqual(server._token_hash("abc"), server._token_hash("abc"))
        self.assertNotEqual(server._token_hash("abc"), server._token_hash("abd"))
        self.assertEqual(len(server._token_hash("abc")), 64)

    def test_esc_neutralizes_html(self) -> None:
        escaped = server.esc("<script>alert(1)</script>")
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)

    def test_resolve_accepts_regular_file(self) -> None:
        target = self.write("ok.bin", b"data")
        resolved = server.resolve_analyze_target(str(target), allowed_roots=[self.tmp])
        self.assertEqual(resolved, target.resolve())

    def test_resolve_rejects_directory_and_missing(self) -> None:
        with self.assertRaises(ValueError):
            server.resolve_analyze_target(str(self.tmp), allowed_roots=[self.tmp])
        with self.assertRaises(ValueError):
            server.resolve_analyze_target(str(self.tmp / "nope.bin"), allowed_roots=[self.tmp])

    def test_resolve_rejects_system_path(self) -> None:
        with self.assertRaises(ValueError):
            server.resolve_analyze_target(r"C:\Windows\System32\kernel32.dll")

    def test_resolve_rejects_outside_roots(self) -> None:
        other = self.tmp / "other"
        other.mkdir()
        target = self.write("ok.bin", b"data")
        with self.assertRaises(ValueError):
            server.resolve_analyze_target(str(target), allowed_roots=[other])

    def test_resolve_rejects_empty_and_control(self) -> None:
        for raw in ("", "   ", "a\x00b"):
            with self.assertRaises(ValueError):
                server.resolve_analyze_target(raw, allowed_roots=[self.tmp])


if __name__ == "__main__":
    unittest.main()
