"""اختبارات إضافية: واجهة المحللات، الإضافات، YARA، التفكيك، وسجل الأدوات."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from replatform.analyzers import (
    Analyzer,
    Target,
    disasm_analyzer,
    ghidra_analyzer,
    run_analyzers,
    yara_analyzer,
)
import replatform.analyzers as analyzers
from replatform.core import registry


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


class TargetTests(TempDirTest):
    def test_from_path_collects_metadata(self) -> None:
        path = self.write("a.exe", b"MZ" + b"\0" * 16)
        target = Target.from_path(path)
        self.assertEqual(target.name, "a.exe")
        self.assertEqual(target.kind, "PE")
        self.assertEqual(len(target.sha256), 64)

    def test_missing_and_directory_are_rejected(self) -> None:
        with self.assertRaises(FileNotFoundError):
            Target.from_path(self.tmp / "nope")
        with self.assertRaises(ValueError):
            Target.from_path(self.tmp)

    def test_size_limit(self) -> None:
        path = self.write("a.bin", b"x" * 32)
        with self.assertRaises(ValueError):
            Target.from_path(path, max_mb=0)


class FakeWorkspace:
    def __init__(self) -> None:
        self.events: list[tuple] = []
        self.artifacts: dict[str, dict] = {}

    def add_event(self, kind, name, extra=None) -> None:
        self.events.append((kind, name, extra))

    def save_artifact(self, name, data) -> None:
        self.artifacts[name] = data


class _Good(Analyzer):
    name = "good"

    def can_handle(self, target) -> bool:
        return True

    def run(self, target, ws) -> dict:  # noqa: ARG002
        return {"score": 1}


class _Failing(Analyzer):
    name = "failing"

    def can_handle(self, target) -> bool:
        return True

    def run(self, target, ws) -> dict:  # noqa: ARG002
        raise RuntimeError("boom")


class _Optional(Analyzer):
    name = "optional"
    optional = True

    def can_handle(self, target) -> bool:
        return True

    def run(self, target, ws) -> dict:  # noqa: ARG002
        return {}


class _WrongKind(Analyzer):
    name = "wrong"

    def can_handle(self, target) -> bool:
        return False

    def run(self, target, ws) -> dict:  # noqa: ARG002
        return {}


class RunAnalyzersTests(TempDirTest):
    def setUp(self) -> None:
        super().setUp()
        self.target = Target.from_path(self.write("a.bin", b"data"))

    def test_skips_optional_and_incompatible(self) -> None:
        ws = FakeWorkspace()
        with patch.object(
            analyzers, "load_analyzers", return_value=[_Good(), _Optional(), _WrongKind()]
        ):
            results = run_analyzers(self.target, ws)
        self.assertEqual(set(results), {"good"})
        self.assertEqual(results["good"]["analyzer"], "good")

    def test_error_is_captured_and_persisted(self) -> None:
        ws = FakeWorkspace()
        with patch.object(analyzers, "load_analyzers", return_value=[_Failing()]):
            results = run_analyzers(self.target, ws)
        self.assertIn("RuntimeError", results["failing"]["error"])
        self.assertIn("failing", ws.artifacts)
        self.assertEqual(ws.events[-1][0], "analyzer_error")

    def test_only_filter(self) -> None:
        ws = FakeWorkspace()
        with patch.object(analyzers, "load_analyzers", return_value=[_Good(), _Failing()]):
            results = run_analyzers(self.target, ws, only={"failing"})
        self.assertEqual(set(results), {"failing"})


class PluginLoaderTests(TempDirTest):
    def test_loads_valid_plugin_and_skips_broken(self) -> None:
        plugins = self.tmp / "plugins"
        plugins.mkdir()
        (plugins / "good.py").write_text(
            "from replatform.analyzers import Analyzer\n"
            "class Custom(Analyzer):\n"
            "    name = 'custom'\n"
            "    description = 'x'\n"
            "    def can_handle(self, target):\n"
            "        return True\n"
            "    def run(self, target, ws):\n"
            "        return {}\n",
            "utf-8",
        )
        (plugins / "broken.py").write_text("raise RuntimeError('bad plugin')\n", "utf-8")
        (plugins / "_ignored.py").write_text("raise RuntimeError('ignored')\n", "utf-8")
        with patch.object(analyzers, "PLUGINS_DIR", plugins):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                loaded = analyzers._load_plugins()
        self.assertEqual([item.name for item in loaded], ["custom"])
        self.assertIn("broken.py", out.getvalue())

    def test_builtins_are_loaded_once(self) -> None:
        original = analyzers._BUILTINS
        try:
            analyzers._BUILTINS = None
            with patch.object(analyzers, "_load_plugins", return_value=[]):
                first = analyzers.load_analyzers()
                second = analyzers.load_analyzers()
            self.assertIs(first, second)
            self.assertEqual(len(first), 6)
        finally:
            analyzers._BUILTINS = original


class YaraAnalyzerTests(TempDirTest):
    def setUp(self) -> None:
        super().setUp()
        self.target = Target.from_path(self.write("a.bin", b"data"))

    def test_skips_oversized_target(self) -> None:
        with patch.object(
            yara_analyzer,
            "load_config",
            return_value={"analysis": {"yara_max_mb": 0, "yara_timeout": 5}},
        ):
            result = yara_analyzer.YARAAnalyzer().run(self.target, FakeWorkspace())
        self.assertTrue(result["skipped"])
        self.assertIn("أكبر", result["reason"])

    def test_skips_when_engine_unavailable(self) -> None:
        with patch.object(
            yara_analyzer, "load_config", return_value={"analysis": {}}
        ):
            with patch.object(
                yara_analyzer.yara_engine,
                "scan",
                return_value={"available": False, "error": "no binary"},
            ):
                result = yara_analyzer.YARAAnalyzer().run(self.target, FakeWorkspace())
        self.assertTrue(result["skipped"])
        self.assertEqual(result["reason"], "no binary")

    def test_scores_high_and_normal_matches(self) -> None:
        matches = [
            {"rule": "Ransomware_Note", "strings": [{"id": "$a"}]},
            {"rule": "UPX_Packed", "strings": []},
        ]
        with patch.object(
            yara_analyzer, "load_config", return_value={"analysis": {}}
        ):
            with patch.object(
                yara_analyzer.yara_engine,
                "scan",
                return_value={
                    "available": True,
                    "matches": matches,
                    "rules_file_count": 19,
                },
            ):
                result = yara_analyzer.YARAAnalyzer().run(self.target, FakeWorkspace())
        self.assertEqual(result["score"], 3)
        self.assertEqual(result["verdict"], "warn")
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["rules_file_count"], 19)

    def test_can_handle_respects_toggle(self) -> None:
        with patch.object(
            yara_analyzer, "load_config", return_value={"analysis": {"yara": False}}
        ):
            self.assertFalse(yara_analyzer.YARAAnalyzer().can_handle(self.target))
        with patch.object(
            yara_analyzer, "load_config", return_value={"analysis": {"yara": True}}
        ):
            with patch.object(yara_analyzer.yara_engine, "available", return_value=True):
                self.assertTrue(yara_analyzer.YARAAnalyzer().can_handle(self.target))


class DisasmTests(TempDirTest):
    def test_clean_removes_ansi_and_tree_glyphs(self) -> None:
        self.assertEqual(disasm_analyzer._clean("\x1b[31m│ 0x1000 mov\x1b[0m"), "0x1000 mov")

    def test_find_rizin_uses_path(self) -> None:
        binary = self.write("rizin.exe", b"x")
        with patch.object(disasm_analyzer.shutil, "which", return_value=str(binary)):
            with patch.dict("os.environ", {"LOCALAPPDATA": str(self.tmp / "none"),
                                           "ProgramFiles": str(self.tmp / "none"),
                                           "ProgramFiles(x86)": str(self.tmp / "none")}):
                self.assertEqual(disasm_analyzer.find_rizin(), str(binary))

    def test_quick_parses_functions_and_entry(self) -> None:
        def fake_run(cmd, timeout):  # noqa: ARG001
            if any("aflj" in str(part) for part in cmd):
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "arch x86\nbits 64\n"
                        '[{"name":"main","offset":4096,"size":100},'
                        '{"name":"helper","offset":8192,"size":50}]'
                    ),
                    stderr="",
                )
            return SimpleNamespace(returncode=0, stdout="0x1000 mov eax, 1\n", stderr="")

        with patch.object(disasm_analyzer, "find_rizin", return_value="rizin"):
            with patch.object(disasm_analyzer, "_run", side_effect=fake_run):
                result = disasm_analyzer.quick("a.exe")
        self.assertEqual(result["arch"], "x86")
        self.assertEqual(result["bits"], "64")
        self.assertEqual(result["function_count"], 2)
        self.assertEqual(result["top_functions"][0]["name"], "main")
        self.assertIn("0x1000", result["entry_disasm"][0])

    def test_quick_timeout_and_bad_json(self) -> None:
        with patch.object(disasm_analyzer, "find_rizin", return_value="rizin"):
            with patch.object(disasm_analyzer, "_run", return_value=None):
                self.assertIn("مهلة", disasm_analyzer.quick("a.exe")["error"])
        with patch.object(disasm_analyzer, "find_rizin", return_value="rizin"):
            with patch.object(
                disasm_analyzer,
                "_run",
                return_value=SimpleNamespace(returncode=0, stdout="arch x86\n[not-json", stderr=""),
            ):
                self.assertEqual(disasm_analyzer.quick("a.exe")["function_count"], 0)

    def test_unavailable(self) -> None:
        with patch.object(disasm_analyzer, "find_rizin", return_value=""):
            self.assertFalse(disasm_analyzer.available())
            self.assertFalse(disasm_analyzer.quick("a.exe")["available"])

    def test_analyzer_can_handle_and_run(self) -> None:
        target = Target.from_path(self.write("a.exe", b"MZ" + b"\0" * 16))
        with patch.object(
            disasm_analyzer, "load_config", return_value={"analysis": {}}
        ):
            with patch.object(disasm_analyzer, "available", return_value=True):
                self.assertTrue(disasm_analyzer.DisasmAnalyzer().can_handle(target))
            with patch.object(
                disasm_analyzer,
                "quick",
                return_value={"function_count": 2, "available": True},
            ):
                result = disasm_analyzer.DisasmAnalyzer().run(target, FakeWorkspace())
        self.assertEqual(result["score"], 0)
        self.assertIn("2", result["findings"][0])


class GhidraAnalyzerTests(TempDirTest):
    def test_can_handle_and_run(self) -> None:
        target = Target.from_path(self.write("a.exe", b"MZ" + b"\0" * 16))
        with patch.object(
            ghidra_analyzer, "load_config", return_value={"analysis": {}}
        ):
            with patch.object(ghidra_analyzer.ghidra_tools, "available", return_value=True):
                self.assertTrue(ghidra_analyzer.GhidraAnalyzer().can_handle(target))
            with patch.object(
                ghidra_analyzer.ghidra_tools,
                "analyze",
                return_value={"function_count": 5, "error": None},
            ):
                result = ghidra_analyzer.GhidraAnalyzer().run(target, FakeWorkspace())
        self.assertEqual(result["score"], 0)
        self.assertIn("5", result["findings"][0])

    def test_can_handle_rejects_non_pe(self) -> None:
        target = Target.from_path(self.write("a.bin", b"data"))
        with patch.object(
            ghidra_analyzer, "load_config", return_value={"analysis": {}}
        ):
            self.assertFalse(ghidra_analyzer.GhidraAnalyzer().can_handle(target))


class RegistryTests(TempDirTest):
    def test_resolve_uses_path(self) -> None:
        with patch.object(registry.shutil, "which", return_value=r"C:\bin\x.exe"):
            self.assertEqual(registry._resolve("x"), r"C:\bin\x.exe")

    def test_resolve_accepts_direct_path(self) -> None:
        target = self.write("tool.exe", b"x")
        with patch.object(registry.shutil, "which", return_value=""):
            self.assertEqual(registry._resolve(str(target)), str(target))

    def test_resolve_missing(self) -> None:
        with patch.object(registry.shutil, "which", return_value=""):
            with patch.object(registry, "_EXTRA_DIRS", []):
                self.assertEqual(registry._resolve("definitely-not-a-tool"), "")


if __name__ == "__main__":
    unittest.main()
