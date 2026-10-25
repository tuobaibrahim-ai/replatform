"""اختبارات تكامل Ghidra headless (بلا Ghidra حقيقي)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from replatform.tools import ghidra_tools


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)


class DiscoveryTests(TempDirTest):
    def test_wrap_bat_uses_cmd(self) -> None:
        cmd = ghidra_tools._wrap(r"C:\x\analyzeHeadless.bat", ["-import", "a.exe"])
        self.assertEqual(cmd[0].lower(), (os.environ.get("COMSPEC") or "cmd.exe").lower())
        self.assertIn("/c", cmd)

    def test_wrap_exe_is_direct(self) -> None:
        self.assertEqual(
            ghidra_tools._wrap(r"C:\x\headless.exe", ["-import", "a.exe"]),
            [r"C:\x\headless.exe", "-import", "a.exe"],
        )

    def test_find_headless_in_tools_dir(self) -> None:
        script = self.tmp / "ghidra" / "support" / "analyzeHeadless.bat"
        script.parent.mkdir(parents=True)
        script.write_text("@echo off", "utf-8")
        with patch.object(ghidra_tools, "TOOLS_DIR", self.tmp):
            with patch.object(ghidra_tools.shutil, "which", return_value=""):
                with patch.dict(
                    "os.environ",
                    {"ProgramFiles": str(self.tmp), "LOCALAPPDATA": str(self.tmp),
                     "USERPROFILE": str(self.tmp)},
                ):
                    self.assertEqual(ghidra_tools.find_headless(), str(script))

    def test_find_headless_missing(self) -> None:
        with patch.object(ghidra_tools, "TOOLS_DIR", self.tmp / "none"):
            with patch.object(ghidra_tools.shutil, "which", return_value=""):
                with patch.dict(
                    "os.environ",
                    {"ProgramFiles": str(self.tmp), "LOCALAPPDATA": str(self.tmp),
                     "USERPROFILE": str(self.tmp)},
                ):
                    self.assertEqual(ghidra_tools.find_headless(), "")

    def test_find_java_home(self) -> None:
        javac = self.tmp / "jdk-21" / "bin" / "javac.exe"
        javac.parent.mkdir(parents=True)
        javac.write_bytes(b"x")
        with patch.object(ghidra_tools, "TOOLS_DIR", self.tmp):
            with patch.dict("os.environ", {"JAVA_HOME": ""}):
                self.assertEqual(
                    ghidra_tools.find_java_home(), str(self.tmp / "jdk-21")
                )

    def test_available_reflects_discovery(self) -> None:
        with patch.object(ghidra_tools, "find_headless", return_value=""):
            self.assertFalse(ghidra_tools.available())
        with patch.object(ghidra_tools, "find_headless", return_value="x"):
            self.assertTrue(ghidra_tools.available())


class AnalyzeTests(TempDirTest):
    def test_missing_ghidra_is_reported(self) -> None:
        with patch.object(ghidra_tools, "find_headless", return_value=""):
            result = ghidra_tools.analyze("x.exe")
        self.assertFalse(result["available"])
        self.assertIn("Ghidra", result["error"])

    def test_missing_script_is_reported(self) -> None:
        with patch.object(ghidra_tools, "find_headless", return_value="headless.exe"):
            with patch.object(ghidra_tools, "SCRIPT_DIR", self.tmp / "missing"):
                result = ghidra_tools.analyze("x.exe")
        self.assertTrue(result["available"])
        self.assertIn("مفقود", result["error"])

    def test_invalid_rename_is_rejected(self) -> None:
        with patch.object(ghidra_tools, "find_headless", return_value="headless.exe"):
            with patch.object(ghidra_tools, "SCRIPT_DIR", self.tmp):
                with self.assertRaises(ValueError):
                    ghidra_tools.analyze("x.exe", renames={"bad name": "x"})

    def _run_success(self, args, **kwargs):  # noqa: ARG001
        index = args.index("-postScript")
        output = Path(args[index + 2])
        output.write_text(
            json.dumps(
                {
                    "functions": [
                        {"name": "small", "entry": "0x1", "size": 10},
                        {"name": "big", "entry": "0x2", "size": 100},
                    ],
                    "function_count": 2,
                }
            ),
            "utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    def test_success_sorts_and_marks_available(self) -> None:
        with patch.object(ghidra_tools, "find_headless", return_value="headless.exe"):
            with patch.object(ghidra_tools, "SCRIPT_DIR", self.tmp):
                with patch.object(ghidra_tools, "find_java_home", return_value=""):
                    with patch.object(ghidra_tools.subprocess, "run", side_effect=self._run_success):
                        result = ghidra_tools.analyze(
                            "x.exe", renames={"FUN_1": "parse_config"}, decompile_limit=999
                        )
        self.assertTrue(result["available"])
        self.assertEqual(result["function_count"], 2)
        self.assertEqual(result["top_functions"][0]["name"], "big")
        self.assertEqual(result["engine"], "headless.exe")

    def test_timeout_is_reported(self) -> None:
        with patch.object(ghidra_tools, "find_headless", return_value="headless.exe"):
            with patch.object(ghidra_tools, "SCRIPT_DIR", self.tmp):
                with patch.object(
                    ghidra_tools.subprocess,
                    "run",
                    side_effect=ghidra_tools.subprocess.TimeoutExpired("x", 1),
                ):
                    result = ghidra_tools.analyze("x.exe")
        self.assertIn("مهلة", result["error"])

    def test_oserror_is_reported(self) -> None:
        with patch.object(ghidra_tools, "find_headless", return_value="headless.exe"):
            with patch.object(ghidra_tools, "SCRIPT_DIR", self.tmp):
                with patch.object(ghidra_tools.subprocess, "run", side_effect=OSError("boom")):
                    result = ghidra_tools.analyze("x.exe")
        self.assertIn("OSError", result["error"])

    def test_missing_output_is_reported(self) -> None:
        proc = SimpleNamespace(returncode=1, stdout="out", stderr="err")
        with patch.object(ghidra_tools, "find_headless", return_value="headless.exe"):
            with patch.object(ghidra_tools, "SCRIPT_DIR", self.tmp):
                with patch.object(ghidra_tools.subprocess, "run", return_value=proc):
                    result = ghidra_tools.analyze("x.exe")
        self.assertIn("لم يُنتج", result["error"])
        self.assertIn("err", result["log"])

    def test_invalid_output_json_is_reported(self) -> None:
        def bad_run(args, **kwargs):  # noqa: ARG001
            index = args.index("-postScript")
            Path(args[index + 2]).write_text("{broken", "utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(ghidra_tools, "find_headless", return_value="headless.exe"):
            with patch.object(ghidra_tools, "SCRIPT_DIR", self.tmp):
                with patch.object(ghidra_tools.subprocess, "run", side_effect=bad_run):
                    result = ghidra_tools.analyze("x.exe")
        self.assertIn("تعذر قراءة", result["error"])


if __name__ == "__main__":
    unittest.main()
