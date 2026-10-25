"""اختبارات محرك YARA وتقارير المقارنة (بلا تنفيذ ثنائيات خارجية)."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from replatform.tools import bindiff, sandbox, yara_engine


class YaraTests(unittest.TestCase):
    def test_rule_files_lists_yar(self) -> None:
        files = yara_engine.rule_files()
        self.assertTrue(files)
        self.assertTrue(all(name.endswith(".yar") for name in files))

    def test_missing_binary_is_reported(self) -> None:
        with patch.object(yara_engine, "find_binary", return_value=""):
            result = yara_engine.scan("x.exe")
        self.assertFalse(result["available"])
        self.assertIn("YARA", result["error"])

    def test_no_rules_is_reported(self) -> None:
        with patch.object(yara_engine, "find_binary", return_value="yara64"):
            with patch.object(yara_engine, "rule_files", return_value=[]):
                result = yara_engine.scan("x.exe")
        self.assertFalse(result["available"])
        self.assertIn("rules", result["error"])

    def test_parses_matches(self) -> None:
        stdout = (
            "Suspicious_WinAPI_Combo x.exe\n"
            "0x100:$a: CreateProcessW\n"
            "0x200:$b: VirtualAlloc\n"
            "Another_Rule x.exe\n"
            "0x300:$c: powershell\n"
        )
        proc = SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        with patch.object(yara_engine, "find_binary", return_value="yara64"):
            with patch.object(yara_engine, "rule_files", return_value=["a.yar"]):
                with patch.object(yara_engine.subprocess, "run", return_value=proc):
                    result = yara_engine.scan("x.exe")
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["matches"][0]["rule"], "Suspicious_WinAPI_Combo")
        self.assertEqual(result["matches"][0]["strings"][0]["offset"], 0x100)
        self.assertEqual(len(result["matches"][1]["strings"]), 1)

    def test_error_returncode_is_reported(self) -> None:
        proc = SimpleNamespace(returncode=2, stdout="", stderr="syntax error")
        with patch.object(yara_engine, "find_binary", return_value="yara64"):
            with patch.object(yara_engine, "rule_files", return_value=["a.yar"]):
                with patch.object(yara_engine.subprocess, "run", return_value=proc):
                    result = yara_engine.scan("x.exe")
        self.assertEqual(result["matches"], [])
        self.assertIn("syntax error", result["error"])

    def test_timeout_is_handled(self) -> None:
        with patch.object(yara_engine, "find_binary", return_value="yara64"):
            with patch.object(yara_engine, "rule_files", return_value=["a.yar"]):
                with patch.object(
                    yara_engine.subprocess,
                    "run",
                    side_effect=subprocess.TimeoutExpired("yara64", 1),
                ):
                    result = yara_engine.scan("x.exe")
        self.assertTrue(result["available"])
        self.assertIn("TimeoutExpired", result["error"])


class BindiffReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_render_html_contains_both_names(self) -> None:
        a = self.tmp / "old.bin"
        b = self.tmp / "new.bin"
        a.write_bytes(b"A" * 512)
        b.write_bytes(b"A" * 256 + b"B" * 256)
        result = bindiff.diff_files(a, b)
        html = bindiff.render_html(result)
        self.assertIn("old.bin", html)
        self.assertIn("new.bin", html)
        self.assertIn("<html", html.lower())


class SandboxAvailabilityTests(unittest.TestCase):
    def test_available_returns_bool(self) -> None:
        self.assertIsInstance(sandbox.available(), bool)
        self.assertIsInstance(sandbox.find_sandbox(), str)

    def test_plan_rejects_oversized_sample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "big.exe"
            sample.write_bytes(b"MZ" + b"\0" * 16)
            with patch.object(sandbox, "MAX_SAMPLE_BYTES", 4):
                with self.assertRaises(ValueError):
                    sandbox.build_plan(sample, out=Path(tmp) / "plan")


if __name__ == "__main__":
    unittest.main()
