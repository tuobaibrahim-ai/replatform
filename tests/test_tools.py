"""اختبارات أدوات التعديل والمقارنة والعزل (بلا تنفيذ عيّنات)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from replatform.tools import bindiff, patcher, sandbox


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, data: bytes) -> Path:
        path = self.tmp / name
        path.write_bytes(data)
        return path


class ParseSpecTests(unittest.TestCase):
    def test_str_spec(self) -> None:
        kind, value, tokens = patcher.parse_spec("str:hello", "utf-8", allow_wild=False)
        self.assertEqual(kind, "str")
        self.assertEqual(value, b"hello")
        self.assertIsNone(tokens)

    def test_hex_spec_with_wildcard(self) -> None:
        kind, pattern, tokens = patcher.parse_spec("hex:4D 5A ?? 00", "utf-8", allow_wild=True)
        self.assertEqual(kind, "hex")
        self.assertEqual(len(tokens), 4)
        self.assertIsNotNone(pattern.search(b"MZ\x90\x00"))

    def test_hex_wildcard_rejected_for_replacement(self) -> None:
        with self.assertRaises(ValueError):
            patcher.parse_spec("hex:41 ??", "utf-8", allow_wild=False)

    def test_invalid_specs(self) -> None:
        for spec in ("hello", "bin:41", "str:", "hex:zz"):
            with self.assertRaises(ValueError):
                patcher.parse_spec(spec, "utf-8", allow_wild=True)

    @unittest.skipUnless(os.name == "nt", "مسارات النظام المفحوصة خاصة بـ Windows")
    def test_system_path_detection(self) -> None:
        self.assertTrue(patcher.is_system_path(Path(r"C:\Windows\System32\kernel32.dll")))
        self.assertFalse(patcher.is_system_path(Path.cwd() / "sample.exe"))


class PatchTests(TempDirTest):
    def test_preview_does_not_write(self) -> None:
        path = self.write("a.bin", b"AAAA")
        result = patcher.patch(path, "str:AAAA", "str:BBBB")
        self.assertEqual(result["count"], 1)
        self.assertFalse(result["applied"])
        self.assertEqual(path.read_bytes(), b"AAAA")

    def test_apply_creates_backup_and_changes_bytes(self) -> None:
        path = self.write("a.bin", b"xAAAAy")
        result = patcher.patch(path, "str:AAAA", "str:BBBB", apply=True)
        self.assertTrue(result["applied"])
        self.assertEqual(path.read_bytes(), b"xBBBBy")
        backups = list(self.tmp.glob("a.bin.bak.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"xAAAAy")

    def test_resize_rejected_for_pe(self) -> None:
        path = self.write("app.exe", b"MZ" + b"\0" * 10 + b"AAAA")
        with self.assertRaises(ValueError):
            patcher.patch(path, "str:AAAA", "str:BB", apply=True)

    def test_resize_rolls_back_when_pe_is_invalid(self) -> None:
        original = b"MZ" + b"\0" * 10 + b"AAAA"
        path = self.write("app.exe", original)
        result = patcher.patch(
            path, "str:AAAA", "str:BB", apply=True, allow_resize=True
        )
        self.assertTrue(result["length_warning"])
        self.assertFalse(result["pe_valid"])
        self.assertTrue(result["rolled_back"])
        self.assertFalse(result["applied"])
        self.assertEqual(path.read_bytes(), original)

    def test_overlapping_all_matches_rejected(self) -> None:
        path = self.write("a.bin", b"aaa")
        with self.assertRaises(ValueError):
            patcher.patch(path, "str:aa", "str:bb", apply=True, all_matches=True)
        self.assertEqual(path.read_bytes(), b"aaa")

    def test_hex_wildcard_patch(self) -> None:
        path = self.write("a.bin", b"\x01\x02\x03")
        patcher.patch(
            path,
            "hex:01 ?? 03",
            "hex:AA BB CC",
            apply=True,
        )
        self.assertEqual(path.read_bytes(), b"\xAA\xBB\xCC")

    def test_missing_file(self) -> None:
        with self.assertRaises(FileNotFoundError):
            patcher.patch(self.tmp / "nope.bin", "str:a", "str:b")


class BindiffTests(TempDirTest):
    def test_identical_files(self) -> None:
        a = self.write("a.bin", b"REPLATFORM" * 100)
        b = self.write("b.bin", a.read_bytes())
        self.assertAlmostEqual(bindiff.similarity(a, b), 100.0, places=2)
        result = bindiff.diff_files(a, b)
        self.assertTrue(result["identical"])
        self.assertEqual(result["size_delta"], 0)

    def test_different_files_lower_similarity(self) -> None:
        a = self.write("a.bin", b"A" * 4096)
        b = self.write("b.bin", b"B" * 8192)
        score = bindiff.similarity(a, b)
        self.assertIsNotNone(score)
        self.assertLess(score, 1.0)

    def test_diff_reports_limits(self) -> None:
        a = self.write("a.bin", b"A" * 128)
        b = self.write("b.bin", b"B" * 256)
        result = bindiff.diff_files(a, b)
        self.assertIn("max_parse_mb", result["limits"])
        self.assertIn("max_apk_entries", result["limits"])
        self.assertIn(result["similarity_method"], {"cdc", "difflib"})


class SandboxPlanTests(TempDirTest):
    def test_plan_is_isolated_and_offline_by_default(self) -> None:
        sample = self.write("sample.exe", b"MZ" + b"\0" * 64)
        plan = sandbox.build_plan(sample, out=self.tmp / "plan", timeout=30)
        wsb = Path(plan["wsb"]).read_text("utf-8")
        self.assertIn("<Networking>Disable</Networking>", wsb)
        self.assertIn("C:\\RE_SAMPLE", wsb)
        self.assertIn("C:\\RE_OUT", wsb)
        self.assertTrue((self.tmp / "plan" / "sample" / "sample.exe").is_file())
        self.assertEqual(plan["kind"], "PE")
        self.assertTrue(plan["runnable"])
        self.assertFalse(plan["executed"])

    def test_network_requires_explicit_flag(self) -> None:
        sample = self.write("sample.exe", b"MZ" + b"\0" * 64)
        plan = sandbox.build_plan(sample, out=self.tmp / "p2", network=True)
        wsb = Path(plan["wsb"]).read_text("utf-8")
        self.assertIn("<Networking>Enable</Networking>", wsb)

    def test_run_requires_confirmation(self) -> None:
        sample = self.write("sample.exe", b"MZ" + b"\0" * 64)
        plan = sandbox.build_plan(sample, out=self.tmp / "p3")
        with self.assertRaises(ValueError):
            sandbox.run_plan(plan, confirmed=False)

    def test_run_rejects_non_pe(self) -> None:
        sample = self.write("notes.txt", b"hello")
        plan = sandbox.build_plan(sample, out=self.tmp / "p4")
        self.assertFalse(plan["runnable"])
        with self.assertRaises(ValueError):
            sandbox.run_plan(plan, confirmed=True)


if __name__ == "__main__":
    unittest.main()
