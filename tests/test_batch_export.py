"""اختبارات الفحص بالدفعات وتصدير PDF (بلا أدوات خارجية)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from replatform.core import export
from replatform.tools import batch


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, data: bytes | str = b"x") -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path


class CsvSafetyTests(unittest.TestCase):
    def test_formula_prefixes_are_neutralized(self) -> None:
        for value in ("=cmd", "+1", "-1", "@x", "\tx", "\rx"):
            self.assertTrue(batch._csv_cell(value).startswith("'"))

    def test_plain_values_are_unchanged(self) -> None:
        self.assertEqual(batch._csv_cell("file.exe"), "file.exe")
        self.assertEqual(batch._csv_cell(None), "")

    def test_csv_has_bom_and_quotes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.csv"
            batch._write_csv(
                path,
                [
                    {
                        "name": "=evil.exe",
                        "kind": "PE",
                        "size": 1,
                        "score": 1,
                        "verdict": "warn",
                        "sha256": "a" * 64,
                        "findings": ["a", "b"],
                        "errors": [],
                        "path": "C:/x",
                        "seconds": 0.1,
                    }
                ],
            )
            raw = path.read_bytes()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        text = raw.decode("utf-8-sig")
        self.assertIn("'=evil.exe", text)
        self.assertIn("a | b", text)


class CollectFilesTests(TempDirTest):
    def test_collects_known_extensions_recursively(self) -> None:
        self.write("a.exe", b"MZ")
        self.write("sub/b.apk", b"PK")
        self.write("c.txt", b"text")
        files = batch.collect_files(self.tmp)
        names = sorted(path.name for path in files)
        self.assertEqual(names, ["a.exe", "b.apk"])

    def test_all_files_includes_unknown(self) -> None:
        self.write("c.txt", b"text")
        self.assertEqual(len(batch.collect_files(self.tmp, all_files=True)), 1)

    def test_non_recursive_stops_at_top(self) -> None:
        self.write("a.exe", b"MZ")
        self.write("sub/b.exe", b"MZ")
        names = [path.name for path in batch.collect_files(self.tmp, recursive=False)]
        self.assertEqual(names, ["a.exe"])

    def test_max_files_and_size_limits(self) -> None:
        for index in range(3):
            self.write(f"{index}.exe", b"MZ")
        self.assertEqual(len(batch.collect_files(self.tmp, max_files=2)), 2)
        self.assertEqual(batch.collect_files(self.tmp, max_files=0), [])
        self.assertEqual(batch.collect_files(self.tmp, max_mb=0), [])

    def test_single_file_and_missing(self) -> None:
        target = self.write("one.exe", b"MZ")
        self.assertEqual(batch.collect_files(target), [target])
        self.assertEqual(batch.collect_files(self.tmp / "nope"), [])

    def test_skip_dirs_are_ignored(self) -> None:
        self.write("workspaces/a.exe", b"MZ")
        self.write("ok.exe", b"MZ")
        names = [path.name for path in batch.collect_files(self.tmp)]
        self.assertEqual(names, ["ok.exe"])


class AnalyzeFileTests(TempDirTest):
    def test_scores_and_findings_are_aggregated(self) -> None:
        target = self.write("a.exe", b"MZ" + b"\0" * 16)
        artifacts = {
            "pe": {"score": 6, "findings": ["unsigned"]},
            "strings": {"score": 2, "findings": ["url"]},
            "yara": {"error": "timeout"},
        }
        with patch.object(batch, "run_analyzers", return_value=artifacts):
            row = batch.analyze_file(target, {"pe", "strings", "yara"})
        self.assertEqual(row["score"], 6)
        self.assertEqual(row["verdict"], "critical")
        self.assertIn("unsigned", row["findings"])
        self.assertIn("yara: timeout", row["errors"])
        self.assertEqual(row["analyzers"], ["pe", "strings", "yara"])


class ScanTests(TempDirTest):
    def setUp(self) -> None:
        super().setUp()
        self.write("a.exe", b"MZ" + b"\0" * 8)
        self.write("b.txt", b"text")
        self._patch = patch.object(batch, "SCANS_DIR", self.tmp / "scans")
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _row(self, path: Path, verdict: str = "warn", score: int = 3) -> dict:
        return {
            "path": str(path), "name": path.name, "kind": "PE", "size": 10,
            "sha256": "a" * 64, "score": score, "verdict": verdict,
            "findings": ["f"], "errors": [], "analyzers": ["pe"], "seconds": 0.1,
        }

    def test_scan_writes_json_csv_html(self) -> None:
        with patch.object(batch, "analyze_file", side_effect=lambda p, *a: self._row(p)):
            result = batch.scan(self.tmp)
        self.assertEqual(result["file_count"], 1)
        self.assertEqual(result["counts"]["warn"], 1)
        self.assertTrue(Path(result["output_dir"]).is_dir())
        for key in ("report", "json", "csv"):
            self.assertTrue(Path(result[key]).is_file(), key)
        data = json.loads(Path(result["json"]).read_text("utf-8"))
        self.assertEqual(data["file_count"], 1)

    def test_scan_sorts_critical_first(self) -> None:
        self.write("c.exe", b"MZ")
        rows = {
            "a.exe": self._row(self.tmp / "a.exe", "info", 0),
            "c.exe": self._row(self.tmp / "c.exe", "critical", 9),
        }
        with patch.object(batch, "analyze_file", side_effect=lambda p, *a: rows[p.name]):
            result = batch.scan(self.tmp)
        self.assertEqual(result["rows"][0]["verdict"], "critical")

    def test_scan_records_analyzer_failure(self) -> None:
        with patch.object(batch, "analyze_file", side_effect=RuntimeError("boom")):
            result = batch.scan(self.tmp)
        self.assertEqual(result["file_count"], 1)
        self.assertIn("boom", result["rows"][0]["errors"][0])

    def test_missing_root_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            batch.scan(self.tmp / "nope")


class RenderTests(TempDirTest):
    def test_html_escapes_untrusted_names(self) -> None:
        result = {
            "generated": "now", "root": str(self.tmp), "recursive": True,
            "analyzers": ["pe"], "max_files": 1, "max_mb": 1,
            "file_count": 1, "elapsed_seconds": 0.1,
            "counts": {"critical": 0, "warn": 1, "info": 0},
            "rows": [
                {
                    "name": "<script>.exe", "path": "<img src=x>", "kind": "PE",
                    "size": 10, "score": 3, "verdict": "warn",
                    "findings": ["<b>x</b>"], "errors": ["<err>"], "seconds": 0.1,
                }
            ],
        }
        html = batch.render_html(result)
        self.assertNotIn("<script>.exe", html)
        self.assertIn("&lt;script&gt;.exe", html)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)
        self.assertIn("&lt;err&gt;", html)

    def test_empty_scan_message(self) -> None:
        result = {
            "generated": "now", "root": "x", "recursive": False,
            "analyzers": [], "max_files": 1, "max_mb": 1,
            "file_count": 0, "elapsed_seconds": 0,
            "counts": {"critical": 0, "warn": 0, "info": 0}, "rows": [],
        }
        self.assertIn("لا ملفات", batch.render_html(result))


class ExportTests(TempDirTest):
    def test_browser_override(self) -> None:
        fake = self.write("browser.exe", b"x")
        with patch.dict("os.environ", {"RE_BROWSER": str(fake)}):
            self.assertEqual(export.find_browser(), str(fake))

    def test_missing_html_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            export.html_to_pdf(self.tmp / "nope.html")

    def test_no_browser_raises(self) -> None:
        source = self.write("r.html", "<html></html>")
        with patch.object(export, "find_browser", return_value=""):
            with self.assertRaises(RuntimeError):
                export.html_to_pdf(source)

    def test_converts_pdf_via_fake_browser(self) -> None:
        source = self.write("r.html", "<html></html>")

        def fake_run(args, **kwargs):  # noqa: ARG001
            target = next(a for a in args if a.startswith("--print-to-pdf="))
            Path(target.split("=", 1)[1]).write_bytes(b"%PDF-1.7\n" + b"x" * 600)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(export, "find_browser", return_value="chrome.exe"):
            with patch.object(export.subprocess, "run", side_effect=fake_run):
                output = export.html_to_pdf(source)
        self.assertEqual(output.suffix, ".pdf")
        self.assertTrue(output.read_bytes().startswith(b"%PDF-"))

    def test_non_pdf_output_is_rejected(self) -> None:
        source = self.write("r.html", "<html></html>")

        def fake_run(args, **kwargs):  # noqa: ARG001
            target = next(a for a in args if a.startswith("--print-to-pdf="))
            Path(target.split("=", 1)[1]).write_bytes(b"not a pdf" * 100)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(export, "find_browser", return_value="chrome.exe"):
            with patch.object(export.subprocess, "run", side_effect=fake_run):
                with self.assertRaises(RuntimeError):
                    export.html_to_pdf(source)

    def test_timeout_and_oserror_are_wrapped(self) -> None:
        source = self.write("r.html", "<html></html>")
        with patch.object(export, "find_browser", return_value="chrome.exe"):
            with patch.object(
                export.subprocess,
                "run",
                side_effect=export.subprocess.TimeoutExpired("chrome", 1),
            ):
                with self.assertRaises(RuntimeError):
                    export.html_to_pdf(source)
            with patch.object(export.subprocess, "run", side_effect=OSError("boom")):
                with self.assertRaises(RuntimeError):
                    export.html_to_pdf(source)


if __name__ == "__main__":
    unittest.main()
