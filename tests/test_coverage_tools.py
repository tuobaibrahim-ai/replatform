"""اختبارات تغطية إضافية لأدوات الإصدار والتشغيل — بلا شبكة أو تنفيذ عيّنات.

تستهدف: benchmark، apk_tools، sandbox، وbindiff. كل العيّنات تُبنى محلياً،
وأي عملية خارجية تُحاكى (mock) حتى تبقى الاختبارات حتمية وآمنة.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from replatform.tools import apk_tools, benchmark, bindiff, sandbox


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, data: bytes | str) -> Path:
        path = self.tmp / name
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path


def _make_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
    return path


def _fake_run(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------


class BenchmarkCoverageTests(unittest.TestCase):
    def test_all_benchmark_cases_pass(self) -> None:
        result = benchmark.run_benchmark()
        self.assertEqual(result["total"], len(benchmark.CASES))
        self.assertEqual(result["passed"], result["total"])
        self.assertEqual(result["score"], 100.0)
        self.assertTrue(all(case["ok"] for case in result["cases"]))
        self.assertGreater(result["seconds"], 0)

    def test_failed_case_is_reported_without_crashing(self) -> None:
        def boom(_temp: Path) -> str:
            raise RuntimeError("boom")

        with patch.object(benchmark, "CASES", (("boom", boom),)):
            result = benchmark.run_benchmark()
        self.assertEqual(result["passed"], 0)
        self.assertEqual(result["score"], 0.0)
        self.assertIn("RuntimeError: boom", result["cases"][0]["error"])


# ---------------------------------------------------------------------------
# apk_tools
# ---------------------------------------------------------------------------


class ApkToolsCoverageTests(TempDirTest):
    def test_tail_keeps_last_non_empty_lines(self) -> None:
        self.assertEqual(apk_tools._tail("a\n\nb\nc\n", 2), "b\nc")
        self.assertEqual(apk_tools._tail("", 2), "")

    def test_run_success_and_os_error(self) -> None:
        with patch.object(
            apk_tools.subprocess,
            "run",
            return_value=_fake_run(stdout="line\n", stderr="warn\n"),
        ):
            result = apk_tools._run(["x"], 5)
        self.assertTrue(result["ok"])
        self.assertEqual(result["stdout"], "line")
        self.assertEqual(result["stderr"], "warn")

        with patch.object(apk_tools.subprocess, "run", side_effect=OSError("boom")):
            result = apk_tools._run(["x"], 5)
        self.assertFalse(result["ok"])
        self.assertIn("OSError", result["error"])

    def test_apktool_command_requires_jar(self) -> None:
        with patch.object(apk_tools, "TOOLS_DIR", self.tmp / "tools"):
            with self.assertRaises(FileNotFoundError):
                apk_tools._apktool_cmd()

        tools = self.tmp / "tools"
        tools.mkdir()
        (tools / "apktool.jar").write_bytes(b"x")
        with patch.object(apk_tools, "TOOLS_DIR", tools), patch.object(
            apk_tools, "_resolve", return_value="java"
        ):
            self.assertEqual(
                apk_tools._apktool_cmd(), ["java", "-jar", str(tools / "apktool.jar")]
            )

    def test_require_apk_rejects_missing_and_wrong_suffix(self) -> None:
        with self.assertRaises(ValueError):
            apk_tools._require_apk(self.tmp / "missing.apk")
        with self.assertRaises(ValueError):
            apk_tools._require_apk(self.write("a.txt", b"x"))

    def test_decode_success_and_missing_manifest(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")

        def fake_run(cmd, _timeout):
            target = Path(cmd[cmd.index("-o") + 1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "AndroidManifest.xml").write_text("<manifest/>", "utf-8")
            return {"ok": True}

        with patch.object(apk_tools, "_apktool_cmd", return_value=["java"]), patch.object(
            apk_tools, "_run", side_effect=fake_run
        ):
            result = apk_tools.decode(apk, out=self.tmp / "out")
        self.assertTrue(result["ok"])
        self.assertTrue(result["manifest"])
        self.assertEqual(result["output"], str((self.tmp / "out").resolve()))

        def empty_run(cmd, _timeout):
            Path(cmd[cmd.index("-o") + 1]).mkdir(parents=True, exist_ok=True)
            return {"ok": True}

        with patch.object(apk_tools, "_apktool_cmd", return_value=["java"]), patch.object(
            apk_tools, "_run", side_effect=empty_run
        ):
            result = apk_tools.decode(apk, out=self.tmp / "out2")
        self.assertFalse(result["ok"])
        self.assertIn("AndroidManifest.xml", result["error"])

    def test_decode_refuses_existing_outputs(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")
        existing = self.tmp / "existing"
        existing.mkdir()
        with self.assertRaises(FileExistsError):
            apk_tools.decode(apk, out=existing)

        not_dir = self.write("not-dir", b"x")
        with self.assertRaises(ValueError):
            apk_tools.decode(apk, out=not_dir, force=True)

        with self.assertRaises(ValueError):
            apk_tools.decode(apk, out=self.tmp, force=True)

        random_dir = self.tmp / "random"
        random_dir.mkdir()
        (random_dir / "keep.txt").write_text("x", "utf-8")
        with self.assertRaises(ValueError):
            apk_tools.decode(apk, out=random_dir, force=True)

    def test_decode_force_replaces_previous_apktool_output(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")
        target = self.tmp / "decoded"
        target.mkdir()
        (target / "apktool.yml").write_text("old", "utf-8")

        def fake_run(cmd, _timeout):
            out = Path(cmd[cmd.index("-o") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / "AndroidManifest.xml").write_text("<manifest/>", "utf-8")
            return {"ok": True}

        with patch.object(apk_tools, "_apktool_cmd", return_value=["java"]), patch.object(
            apk_tools, "_run", side_effect=fake_run
        ):
            result = apk_tools.decode(apk, out=target, force=True)
        self.assertTrue(result["ok"])
        self.assertFalse((target / "apktool.yml").exists())

    def test_decode_rejects_output_inside_apk(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")
        with self.assertRaises(ValueError):
            apk_tools.decode(apk, out=apk / "nested")

    def test_build_requires_directory_and_reports_output(self) -> None:
        with self.assertRaises(ValueError):
            apk_tools.build(self.tmp / "missing")
        project = self.tmp / "project"
        project.mkdir()
        with patch.object(apk_tools, "_apktool_cmd", return_value=["java"]), patch.object(
            apk_tools, "_run", return_value={"ok": True}
        ):
            result = apk_tools.build(project)
        self.assertFalse(result["built"])
        self.assertTrue(result["output"].endswith("project-rebuilt.apk"))

    def test_verify_signed_handles_bad_zip_and_signing_error(self) -> None:
        broken = self.write("broken.apk", b"nope")
        result = apk_tools._verify_signed(broken)
        self.assertFalse(result["zip_valid"])
        self.assertIn("zip_error", result)

        valid = _make_apk(self.tmp / "ok.apk")
        with patch(
            "replatform.analyzers.apk_analyzer.signing_info",
            return_value={"error": "boom", "schemes": []},
        ):
            result = apk_tools._verify_signed(valid)
        self.assertFalse(result["ok"])
        self.assertEqual(result["signing_error"], "boom")

        with patch(
            "replatform.analyzers.apk_analyzer.signing_info",
            return_value={"schemes": ["v2"]},
        ):
            result = apk_tools._verify_signed(valid)
        self.assertTrue(result["ok"])
        self.assertEqual(result["schemes"], ["v2"])

    def test_sign_requires_signer_jar(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")
        with patch.object(apk_tools, "TOOLS_DIR", self.tmp / "tools"):
            with self.assertRaises(FileNotFoundError):
                apk_tools.sign(apk)

    def test_sign_rejects_output_file(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")
        tools = self.tmp / "tools"
        tools.mkdir()
        (tools / "uber-apk-signer.jar").write_bytes(b"x")
        output = self.write("output-file", b"x")
        with patch.object(apk_tools, "TOOLS_DIR", tools):
            with self.assertRaises(ValueError):
                apk_tools.sign(apk, out_dir=output)

    def test_sign_reports_no_produced_apk(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")
        tools = self.tmp / "tools"
        tools.mkdir()
        (tools / "uber-apk-signer.jar").write_bytes(b"x")
        with patch.object(apk_tools, "TOOLS_DIR", tools), patch.object(
            apk_tools, "_resolve", return_value="java"
        ), patch.object(
            apk_tools,
            "_run",
            return_value={"ok": True, "stdout": "already signed", "stderr": ""},
        ):
            result = apk_tools.sign(apk, out_dir=self.tmp / "signed")
        self.assertFalse(result["signed"])
        self.assertIn("موقّع مسبقاً", result["error"])

        with patch.object(apk_tools, "TOOLS_DIR", tools), patch.object(
            apk_tools, "_resolve", return_value="java"
        ), patch.object(
            apk_tools, "_run", return_value={"ok": True, "stdout": "", "stderr": ""}
        ):
            result = apk_tools.sign(apk, out_dir=self.tmp / "signed2")
        self.assertFalse(result["signed"])
        self.assertIn("دون إنتاج", result["error"])

    def test_sign_reports_failed_verification(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")
        tools = self.tmp / "tools"
        tools.mkdir()
        (tools / "uber-apk-signer.jar").write_bytes(b"x")

        def fake_run(cmd, _timeout):
            out = Path(cmd[cmd.index("--out") + 1])
            (out / "signed.apk").write_bytes(b"fake apk")
            return {"ok": True, "stdout": "", "stderr": ""}

        with patch.object(apk_tools, "TOOLS_DIR", tools), patch.object(
            apk_tools, "_resolve", return_value="java"
        ), patch.object(
            apk_tools, "_run", side_effect=fake_run
        ), patch.object(
            apk_tools,
            "_verify_signed",
            return_value={
                "ok": False,
                "zip_valid": False,
                "schemes": [],
                "zip_error": "bad zip",
            },
        ):
            result = apk_tools.sign(apk, out_dir=self.tmp / "signed")
        self.assertTrue(result["signed"])
        self.assertFalse(result["verified"])
        self.assertFalse(result["ok"])
        self.assertIn("التحقق فشل", result["error"])

    def test_sign_success_and_name_collisions(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")
        tools = self.tmp / "tools"
        tools.mkdir()
        (tools / "uber-apk-signer.jar").write_bytes(b"x")
        out_dir = self.tmp / "signed"
        out_dir.mkdir()
        (out_dir / "signed.apk").write_bytes(b"old")

        def fake_run(cmd, _timeout):
            out = Path(cmd[cmd.index("--out") + 1])
            (out / "signed.apk").write_bytes(b"new")
            return {"ok": True, "stdout": "", "stderr": ""}

        with patch.object(apk_tools, "TOOLS_DIR", tools), patch.object(
            apk_tools, "_resolve", return_value="java"
        ), patch.object(
            apk_tools, "_run", side_effect=fake_run
        ), patch.object(
            apk_tools,
            "_verify_signed",
            return_value={"ok": True, "zip_valid": True, "schemes": ["v2"]},
        ):
            result = apk_tools.sign(apk, out_dir=out_dir)
        self.assertTrue(result["ok"])
        self.assertTrue(result["verified"])
        self.assertNotEqual(Path(result["output"]).name, "signed.apk")
        self.assertEqual(Path(result["output"]).read_bytes(), b"new")

    def test_sign_renames_when_output_equals_input(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")
        tools = self.tmp / "tools"
        tools.mkdir()
        (tools / "uber-apk-signer.jar").write_bytes(b"x")

        def fake_run(cmd, _timeout):
            out = Path(cmd[cmd.index("--out") + 1])
            (out / "a.apk").write_bytes(b"signed")
            return {"ok": True, "stdout": "", "stderr": ""}

        with patch.object(apk_tools, "TOOLS_DIR", tools), patch.object(
            apk_tools, "_resolve", return_value="java"
        ), patch.object(
            apk_tools, "_run", side_effect=fake_run
        ), patch.object(
            apk_tools,
            "_verify_signed",
            return_value={"ok": True, "zip_valid": True, "schemes": ["v2"]},
        ):
            result = apk_tools.sign(apk, out_dir=self.tmp)
        self.assertEqual(Path(result["output"]).name, "a-signed.apk")

    def test_java_src_requires_jadx_and_counts_files(self) -> None:
        apk = _make_apk(self.tmp / "a.apk")
        with patch.object(apk_tools, "TOOLS_DIR", self.tmp / "tools"):
            with self.assertRaises(FileNotFoundError):
                apk_tools.java_src(apk)

        tools = self.tmp / "tools"
        (tools / "jadx-cli" / "bin").mkdir(parents=True)
        (tools / "jadx-cli" / "bin" / "jadx.bat").write_text("", "utf-8")

        def fake_run(cmd, _timeout):
            target = Path(cmd[cmd.index("-d") + 1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "Main.java").write_text("class Main {}", "utf-8")
            return {
                "ok": False,
                "stdout": "finished with errors, count: 3",
                "stderr": "",
            }

        with patch.object(apk_tools, "TOOLS_DIR", tools), patch.object(
            apk_tools, "_run", side_effect=fake_run
        ):
            result = apk_tools.java_src(apk, out=self.tmp / "java")
        self.assertTrue(result["ok"])
        self.assertEqual(result["java_files"], 1)
        self.assertEqual(result["error_count"], 3)

        with patch.object(apk_tools, "TOOLS_DIR", tools), patch.object(
            apk_tools, "_run", return_value={"ok": False, "stdout": "", "stderr": ""}
        ):
            result = apk_tools.java_src(apk, out=self.tmp / "empty-java")
        self.assertFalse(result["ok"])
        self.assertEqual(result["java_files"], 0)

    def test_devices_and_install_handle_missing_adb(self) -> None:
        with patch.object(apk_tools, "_resolve", return_value=""):
            self.assertFalse(apk_tools.devices()["ok"])
            apk = _make_apk(self.tmp / "a.apk")
            self.assertFalse(apk_tools.install(apk)["ok"])

        apk = _make_apk(self.tmp / "a.apk")
        with patch.object(apk_tools, "_resolve", return_value="adb"), patch.object(
            apk_tools, "_run", return_value={"ok": True, "stdout": "List of devices"}
        ):
            self.assertEqual(apk_tools.devices()["output"], "List of devices")
            result = apk_tools.install(apk)
        self.assertTrue(result["ok"])
        self.assertEqual(result["output"], str(apk.resolve()))


# ---------------------------------------------------------------------------
# sandbox
# ---------------------------------------------------------------------------


class SandboxCoverageTests(TempDirTest):
    def test_terminate_rejects_invalid_pids(self) -> None:
        self.assertFalse(sandbox._terminate_process_tree("abc"))
        self.assertFalse(sandbox._terminate_process_tree(0))
        self.assertFalse(sandbox._terminate_process_tree(-5))

    def test_terminate_handles_windows_taskkill_failure(self) -> None:
        with patch.object(sandbox.os, "name", "nt"), patch.object(
            sandbox.subprocess, "run", return_value=SimpleNamespace(returncode=1)
        ):
            self.assertFalse(sandbox._terminate_process_tree(123))

    def test_terminate_handles_posix_and_os_error(self) -> None:
        with patch.object(sandbox.os, "name", "posix"), patch.object(
            sandbox.os, "kill"
        ) as kill:
            self.assertTrue(sandbox._terminate_process_tree(123))
        kill.assert_called_once()
        with patch.object(sandbox.os, "name", "posix"), patch.object(
            sandbox.os, "kill", side_effect=OSError("denied")
        ):
            self.assertFalse(sandbox._terminate_process_tree(123))

    def test_find_sandbox_honours_override(self) -> None:
        exe = self.write("WindowsSandbox.exe", b"x")
        with patch.dict(os.environ, {"RE_WINDOWS_SANDBOX": str(exe)}):
            self.assertEqual(sandbox.find_sandbox(), str(exe))

    def test_find_sandbox_falls_back_to_path(self) -> None:
        exe = self.write("WindowsSandbox.exe", b"x")
        empty = self.tmp / "empty"
        empty.mkdir()
        env = {
            "RE_WINDOWS_SANDBOX": str(self.tmp / "missing.exe"),
            "WINDIR": str(empty),
            "LOCALAPPDATA": str(empty),
        }
        with patch.dict(os.environ, env), patch.object(
            sandbox.shutil, "which", return_value=str(exe)
        ):
            self.assertEqual(sandbox.find_sandbox(), str(exe))

    def test_find_sandbox_missing(self) -> None:
        empty = self.tmp / "empty"
        empty.mkdir()
        env = {"RE_WINDOWS_SANDBOX": "", "WINDIR": str(empty), "LOCALAPPDATA": str(empty)}
        with patch.dict(os.environ, env), patch.object(
            sandbox.shutil, "which", return_value=""
        ):
            self.assertEqual(sandbox.find_sandbox(), "")
        with patch.object(sandbox, "find_sandbox", return_value=""):
            self.assertFalse(sandbox.available())

    def test_build_plan_missing_and_suffixless_sample(self) -> None:
        with self.assertRaises(FileNotFoundError):
            sandbox.build_plan(self.tmp / "missing.exe", out=self.tmp / "p")
        sample = self.write("sample", b"MZ" + b"\0" * 8)
        plan = sandbox.build_plan(sample, out=self.tmp / "p", timeout=1)
        self.assertTrue((self.tmp / "p" / "sample" / "sample.bin").is_file())
        self.assertFalse(plan["runnable"])
        self.assertIn("/t 5", Path(plan["wsb"]).read_text("utf-8"))

    def test_run_plan_rejects_unsafe_inputs(self) -> None:
        sample = self.write("sample.exe", b"MZ" + b"\0" * 8)
        plan = sandbox.build_plan(sample, out=self.tmp / "p")
        with self.assertRaises(ValueError):
            sandbox.run_plan(plan, confirmed=False)
        with patch.object(sandbox, "find_sandbox", return_value=""):
            with self.assertRaises(RuntimeError):
                sandbox.run_plan(plan, confirmed=True)

        missing = dict(plan, wsb=str(self.tmp / "missing.wsb"))
        with patch.object(sandbox, "find_sandbox", return_value="exe"):
            with self.assertRaises(FileNotFoundError):
                sandbox.run_plan(missing, confirmed=True)

        wrong = self.write("bad.txt", b"x")
        with patch.object(sandbox, "find_sandbox", return_value="exe"):
            with self.assertRaises(ValueError):
                sandbox.run_plan(dict(plan, wsb=str(wrong)), confirmed=True)

        huge = self.write("huge.wsb", b"x" * (1024 * 1024 + 1))
        with patch.object(sandbox, "find_sandbox", return_value="exe"):
            with self.assertRaises(ValueError):
                sandbox.run_plan(dict(plan, wsb=str(huge)), confirmed=True)

    def test_run_plan_without_waiting(self) -> None:
        sample = self.write("sample.exe", b"MZ" + b"\0" * 8)
        plan = sandbox.build_plan(sample, out=self.tmp / "p")
        proc = SimpleNamespace(pid=123, returncode=0)
        with patch.object(sandbox, "find_sandbox", return_value="exe"), patch.object(
            sandbox.subprocess, "Popen", return_value=proc
        ):
            result = sandbox.run_plan(plan, confirmed=True, wait=False)
        self.assertTrue(result["executed"])
        self.assertFalse(result["watchdog"])
        self.assertEqual(result["pid"], 123)

    def test_run_plan_waits_and_reports_returncode(self) -> None:
        sample = self.write("sample.exe", b"MZ" + b"\0" * 8)
        plan = sandbox.build_plan(sample, out=self.tmp / "p", timeout=30)
        proc = SimpleNamespace(
            pid=123, returncode=0, wait=lambda timeout=None: 0
        )
        with patch.object(sandbox, "find_sandbox", return_value="exe"), patch.object(
            sandbox.subprocess, "Popen", return_value=proc
        ):
            result = sandbox.run_plan(plan, confirmed=True, wait=True)
        self.assertEqual(result["wait_seconds"], 90)
        self.assertEqual(result["returncode"], 0)
        self.assertFalse(result["watchdog_triggered"])

    def test_run_plan_watchdog_terminates_stuck_process(self) -> None:
        sample = self.write("sample.exe", b"MZ" + b"\0" * 8)
        plan = sandbox.build_plan(sample, out=self.tmp / "p", timeout=30)
        plan["timeout"] = "not-a-number"

        class StuckProc:
            pid = 123
            returncode = 0

            def __init__(self) -> None:
                self.calls = 0

            def wait(self, timeout=None):
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired("exe", timeout)
                return 0

        proc = StuckProc()
        with patch.object(sandbox, "find_sandbox", return_value="exe"), patch.object(
            sandbox.subprocess, "Popen", return_value=proc
        ), patch.object(
            sandbox, "_terminate_process_tree", return_value=True
        ):
            result = sandbox.run_plan(plan, confirmed=True, wait=True)
        self.assertEqual(result["wait_seconds"], 180)
        self.assertTrue(result["watchdog_triggered"])
        self.assertTrue(result["terminated"])
        self.assertIn("مهلة", result["error"])

    def test_run_plan_watchdog_reports_unconfirmed_termination(self) -> None:
        sample = self.write("sample.exe", b"MZ" + b"\0" * 8)
        plan = sandbox.build_plan(sample, out=self.tmp / "p", timeout=30)

        class StuckProc:
            pid = 123
            returncode = 0

            def __init__(self) -> None:
                self.calls = 0

            def wait(self, timeout=None):
                self.calls += 1
                raise subprocess.TimeoutExpired("exe", timeout)

        with patch.object(sandbox, "find_sandbox", return_value="exe"), patch.object(
            sandbox.subprocess, "Popen", return_value=StuckProc()
        ), patch.object(
            sandbox, "_terminate_process_tree", return_value=False
        ):
            result = sandbox.run_plan(plan, confirmed=True, wait=True)
        self.assertTrue(result["watchdog_triggered"])
        self.assertFalse(result["terminated"])
        self.assertIn("تعذّر التأكد", result["error"])


# ---------------------------------------------------------------------------
# bindiff
# ---------------------------------------------------------------------------


def _pe_section(name=b".text", data=b"x", entropy=6.0):
    return SimpleNamespace(
        Name=name,
        Misc_VirtualSize=len(data),
        SizeOfRawData=len(data),
        get_data=lambda: data,
        get_entropy=lambda: entropy,
    )


def _pe_import(dll: bytes, names: list[bytes]):
    return SimpleNamespace(
        dll=dll, imports=[SimpleNamespace(name=name) for name in names]
    )


def _fake_pe(sections=None, imports=None):
    directories = [SimpleNamespace(VirtualAddress=0) for _ in range(15)]
    pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x8664, TimeDateStamp=0),
        OPTIONAL_HEADER=SimpleNamespace(
            AddressOfEntryPoint=0x1000,
            ImageBase=0x140000000,
            DATA_DIRECTORY=directories,
        ),
        sections=[_pe_section()] if sections is None else sections,
        parse_data_directories=lambda: None,
        close=lambda: None,
    )
    if imports is not None:
        pe.DIRECTORY_ENTRY_IMPORT = imports
    return pe


class BindiffCoverageTests(TempDirTest):
    def test_cfg_limit_validates_and_clamps(self) -> None:
        with patch.object(
            bindiff, "load_config", return_value={"analysis": {"x": "bad"}}
        ):
            self.assertEqual(bindiff._cfg_limit("x", 10), 10)
        with patch.object(
            bindiff, "load_config", return_value={"analysis": {"x": 0}}
        ):
            self.assertEqual(bindiff._cfg_limit("x", 10, minimum=5), 5)
        with patch.object(
            bindiff, "load_config", return_value={"analysis": {"x": 999}}
        ):
            self.assertEqual(bindiff._cfg_limit("x", 10, maximum=100), 100)

    def test_file_meta_adds_signature_for_pe(self) -> None:
        path = self.write("a.exe", b"MZ" + b"\0" * 8)
        with patch.object(bindiff.util, "file_kind", return_value="PE"), patch.object(
            bindiff.util, "authenticode", return_value={"status": "Valid"}
        ):
            meta = bindiff.file_meta(path)
        self.assertEqual(meta["kind"], "PE")
        self.assertEqual(meta["signature"]["status"], "Valid")

    def test_chunk_and_cdc_counters_cover_all_bytes(self) -> None:
        path = self.write("big.bin", os.urandom(20000))
        counter, total = bindiff._chunk_counter(path)
        self.assertEqual(total, 20000)
        self.assertEqual(sum(counter.values()), total)

        counter, total = bindiff._cdc_counter(path)
        self.assertEqual(total, 20000)
        self.assertEqual(sum(counter.values()), total)
        self.assertGreaterEqual(len(counter), 2)

        empty = self.write("empty.bin", b"")
        counter, total = bindiff._cdc_counter(empty)
        self.assertEqual((counter, total), (counter.__class__(), 0))
        counter, total = bindiff._chunk_counter(empty)
        self.assertEqual(total, 0)

    def test_similarity_info_selects_method(self) -> None:
        empty_a = self.write("a.bin", b"")
        empty_b = self.write("b.bin", b"")
        self.assertEqual(bindiff.similarity_info(empty_a, empty_b)["score"], 100.0)

        small_a = self.write("small-a.bin", b"A" * 100)
        small_b = self.write("small-b.bin", b"A" * 50 + b"B" * 50)
        info = bindiff.similarity_info(small_a, small_b)
        self.assertEqual(info["method"], "difflib")
        self.assertIsNotNone(info["score"])

        medium = self.write("medium.bin", os.urandom(9000))
        info = bindiff.similarity_info(medium, medium)
        self.assertEqual(info["method"], "cdc")
        self.assertEqual(info["score"], 100.0)

        with patch.object(bindiff, "MAX_CDC_BYTES", 100):
            info = bindiff.similarity_info(medium, medium)
        self.assertEqual(info["method"], "fixed")

        with patch.object(bindiff, "MAX_SIMILARITY_BYTES", 1):
            info = bindiff.similarity_info(medium, medium)
            self.assertEqual(info["method"], "none")
            self.assertIn("reason", info)
            self.assertIsNone(bindiff.similarity(medium, medium))

    def test_similarity_info_one_empty_file_scores_zero(self) -> None:
        empty = self.write("e.bin", b"")
        data = self.write("d.bin", os.urandom(9000))
        info = bindiff.similarity_info(empty, data)
        self.assertEqual(info["score"], 0.0)

    def test_compile_time_invalid(self) -> None:
        self.assertEqual(bindiff._compile_time(10**18), "غير صالح")

    def test_pe_info_parses_sections_and_imports(self) -> None:
        path = self.write("a.exe", b"MZ" + b"\0" * 64)
        fake = _fake_pe(
            imports=[
                _pe_import(b"KERNEL32.dll", [b"CreateFileW", b"VirtualAlloc"]),
                _pe_import(b"USER32.dll", [b"MessageBoxA"]),
            ]
        )
        with patch("pefile.PE", return_value=fake):
            info = bindiff._pe_info(path)
        self.assertEqual(info["arch"], "x64")
        self.assertEqual(len(info["sections"]), 1)
        self.assertFalse(info["sections_truncated"])
        self.assertFalse(info["imports_truncated"])
        self.assertIn("KERNEL32.dll", info["imports"])
        self.assertEqual(info["imports"]["KERNEL32.dll"], ["CreateFileW", "VirtualAlloc"])

    def test_pe_info_truncates_large_structures(self) -> None:
        path = self.write("a.exe", b"MZ" + b"\0" * 64)
        fake = _fake_pe(
            sections=[_pe_section(b".a"), _pe_section(b".b")],
            imports=[
                _pe_import(b"K", [b"A", b"B"]),
                _pe_import(b"L", [b"C"]),
            ],
        )
        with patch("pefile.PE", return_value=fake), patch.object(
            bindiff, "MAX_SECTIONS", 1
        ), patch.object(
            bindiff, "MAX_IMPORT_DLLS", 1
        ), patch.object(
            bindiff, "MAX_IMPORT_FUNCTIONS", 1
        ):
            info = bindiff._pe_info(path)
        self.assertTrue(info["sections_truncated"])
        self.assertTrue(info["imports_truncated"])
        self.assertEqual(len(info["sections"]), 1)
        self.assertEqual(info["imports"]["K"], ["A"])

    def test_pe_info_skips_oversized_file(self) -> None:
        path = self.write("a.exe", b"MZ")
        with patch.object(bindiff, "_cfg_limit", return_value=0):
            info = bindiff._pe_info(path)
        self.assertTrue(info["skipped"])

    def test_diff_pe_reports_property_section_and_import_changes(self) -> None:
        a = {
            "arch": "x86",
            "entry_point": "0x1",
            "image_base": "0x2",
            "compile_time": "t1",
            "dotnet": False,
            "sections": [
                {"name": ".text", "sha256": "a", "entropy": 5.0, "vsize": 10},
                {"name": ".old", "sha256": "o", "entropy": 4.0, "vsize": 5},
            ],
            "imports": {"K": ["A", "B"]},
        }
        b = {
            "arch": "x64",
            "entry_point": "0x1",
            "image_base": "0x2",
            "compile_time": "t2",
            "dotnet": True,
            "sections": [
                {"name": ".text", "sha256": "b", "entropy": 6.0, "vsize": 20},
                {"name": ".new", "sha256": "n", "entropy": 7.0, "vsize": 8},
            ],
            "imports": {"K": ["B", "CreateRemoteThread"], "L": ["X"]},
        }
        highlights: list[str] = []
        result = bindiff._diff_pe(a, b, highlights)
        statuses = {row["name"]: row["status"] for row in result["sections"]}
        self.assertEqual(statuses, {".text": "changed", ".old": "removed", ".new": "added"})
        self.assertEqual(result["imports"]["added"]["K"], ["CreateRemoteThread"])
        self.assertEqual(result["imports"]["removed"]["K"], ["A"])
        self.assertTrue(any("دوال حساسة جديدة" in item for item in highlights))
        self.assertTrue(any("قسم جديد" in item for item in highlights))
        self.assertTrue(any("قسم محذوف" in item for item in highlights))

    def test_diff_apk_reports_manifest_permissions_files_and_signing(self) -> None:
        a = {
            "manifest": {
                "package": "com.demo",
                "version_name": "1.0",
                "version_code": 1,
                "min_sdk": 21,
                "target_sdk": 30,
                "exported": 1,
                "permissions": ["android.permission.INTERNET"],
                "application": {"debuggable": False, "cleartext": False},
            },
            "signing": {"schemes": ["v1"], "certs": [{"sha256": "a"}]},
            "files": {"a.txt": "1", "b.txt": "2", "old.txt": "3"},
        }
        b = {
            "manifest": {
                "package": "com.demo",
                "version_name": "2.0",
                "version_code": 2,
                "min_sdk": 21,
                "target_sdk": 33,
                "exported": 2,
                "permissions": ["android.permission.CAMERA"],
                "application": {"debuggable": True, "cleartext": True},
            },
            "signing": {"v2": True, "certs": [{"sha256": "b"}]},
            "files": {"a.txt": "9", "b.txt": "2", "new.txt": "4"},
        }
        highlights: list[str] = []
        result = bindiff._diff_apk(a, b, highlights)
        self.assertEqual(result["permissions"]["added"], ["android.permission.CAMERA"])
        self.assertEqual(result["permissions"]["removed"], ["android.permission.INTERNET"])
        self.assertEqual(result["files"]["added"], ["new.txt"])
        self.assertEqual(result["files"]["removed"], ["old.txt"])
        self.assertEqual(result["files"]["changed"], ["a.txt"])
        self.assertEqual(result["files"]["unchanged_count"], 1)
        self.assertEqual(result["similarity"], 25.0)
        self.assertEqual(result["signing"], {"a": "v1", "b": "v2"})
        self.assertTrue(any("تغيّر الإصدار" in item for item in highlights))
        self.assertTrue(any("أذونات جديدة" in item for item in highlights))
        self.assertTrue(any("debuggable" in item for item in highlights))
        self.assertTrue(any("شهادة" in item for item in highlights))

    def test_diff_apk_flags_large_content_change(self) -> None:
        a = {"manifest": {}, "signing": {}, "files": {}}
        b = {
            "manifest": {},
            "signing": {},
            "files": {f"f{index}.txt": "1" for index in range(51)},
        }
        highlights: list[str] = []
        result = bindiff._diff_apk(a, b, highlights)
        self.assertEqual(result["files"]["added_count"], 51)
        self.assertTrue(any("تغيّر كبير" in item for item in highlights))
        self.assertEqual(result["similarity"], 0.0)

    def test_diff_files_handles_different_kinds(self) -> None:
        meta_a = {"path": "C:/a", "name": "a.exe", "kind": "PE", "size": 10, "sha256": "a" * 64}
        meta_b = {"path": "C:/b", "name": "b.bin", "kind": "other", "size": 20, "sha256": "b" * 64}
        with patch.object(bindiff, "file_meta", side_effect=[meta_a, meta_b]), patch.object(
            bindiff, "similarity_info", return_value={"score": 50.0, "method": "cdc"}
        ):
            result = bindiff.diff_files(Path("a"), Path("b"))
        self.assertEqual(result["similarity_method"], "cdc")
        self.assertTrue(any("نوعان مختلفان" in item for item in result["highlights"]))

    def test_diff_files_pe_and_apk_paths(self) -> None:
        meta_pe_a = {"path": "C:/a", "name": "a.exe", "kind": "PE", "size": 10, "sha256": "a" * 64}
        meta_pe_b = {"path": "C:/b", "name": "b.exe", "kind": "PE", "size": 12, "sha256": "b" * 64}
        pe_info = {
            "arch": "x64",
            "entry_point": "0x1",
            "image_base": "0x2",
            "compile_time": "t",
            "dotnet": False,
            "sections": [],
            "imports": {},
        }
        with patch.object(
            bindiff, "file_meta", side_effect=[meta_pe_a, meta_pe_b]
        ), patch.object(
            bindiff, "similarity_info", return_value={"score": 90.0, "method": "cdc"}
        ), patch.object(
            bindiff, "_pe_info", side_effect=[pe_info, pe_info]
        ):
            result = bindiff.diff_files(Path("a"), Path("b"))
        self.assertIsNotNone(result["pe"])
        self.assertFalse(result["pe"].get("skipped"))

        meta_apk_a = {"path": "C:/a", "name": "a.apk", "kind": "APK", "size": 10, "sha256": "a" * 64}
        meta_apk_b = {"path": "C:/b", "name": "b.apk", "kind": "APK", "size": 12, "sha256": "b" * 64}
        apk_info = {
            "manifest": {},
            "signing": {},
            "files": {"a": "1"},
        }
        with patch.object(
            bindiff, "file_meta", side_effect=[meta_apk_a, meta_apk_b]
        ), patch.object(
            bindiff, "_apk_info", side_effect=[apk_info, apk_info]
        ):
            result = bindiff.diff_files(Path("a"), Path("b"))
        self.assertEqual(result["similarity_method"], "apk-content")
        self.assertEqual(result["similarity"], 100.0)

        with patch.object(
            bindiff, "file_meta", side_effect=[meta_apk_a, meta_apk_b]
        ), patch.object(
            bindiff, "_apk_info",
            side_effect=[{"skipped": True, "reason": "big"}, {"skipped": True, "reason": "big"}],
        ):
            result = bindiff.diff_files(Path("a"), Path("b"))
        self.assertIsNone(result["similarity"])
        self.assertEqual(result["similarity_method"], "none")
        self.assertEqual(result["similarity_reason"], "big")

    def test_diff_files_reports_similarity_reason(self) -> None:
        meta = {"path": "C:/a", "name": "a.bin", "kind": "other", "size": 10, "sha256": "a" * 64}
        with patch.object(bindiff, "file_meta", side_effect=[meta, meta]), patch.object(
            bindiff,
            "similarity_info",
            return_value={"score": None, "method": "none", "reason": "too big"},
        ):
            result = bindiff.diff_files(Path("a"), Path("b"))
        self.assertEqual(result["similarity_reason"], "too big")

    def test_render_html_covers_pe_and_apk_sections(self) -> None:
        result = {
            "a": {"name": "a.exe", "kind": "PE", "path": "C:/a", "size": 10, "sha256": "a" * 64},
            "b": {"name": "b.exe", "kind": "PE", "path": "C:/b", "size": 15, "sha256": "b" * 64},
            "size_delta": 5,
            "similarity": 50.0,
            "similarity_method": "cdc",
            "identical": False,
            "pe": {
                "properties": [{"field": "arch", "a": "x86", "b": "x64"}],
                "sections": [
                    {
                        "name": ".text",
                        "status": "changed",
                        "entropy_a": 5.0,
                        "entropy_b": 6.0,
                        "size_a": 10,
                        "size_b": 20,
                    }
                ],
                "imports": {"added": {"K": ["A"]}, "removed": {"L": ["B"]}},
            },
            "apk": {
                "manifest": [{"field": "package", "a": "com.a", "b": "com.b"}],
                "permissions": {"added": ["P1"], "removed": ["P2"]},
                "files": {
                    "added": ["x"],
                    "removed": ["y"],
                    "changed": ["z"],
                    "added_count": 1,
                    "removed_count": 1,
                    "changed_count": 1,
                    "unchanged_count": 2,
                },
                "signing": {"a": "v1", "b": "v2"},
            },
            "highlights": ["نقطة مهمة"],
            "generated": "2026-01-01T00:00:00",
        }
        html = bindiff.render_html(result)
        for needle in (
            "a.exe",
            "b.exe",
            "arch",
            ".text",
            "K",
            "L",
            "com.a",
            "P1",
            "x",
            "v2",
            "نقطة مهمة",
            "50.0%",
        ):
            self.assertIn(needle, html)

    def test_render_html_marks_identical_and_unknown_method(self) -> None:
        result = {
            "a": {"name": "a.bin", "kind": "other", "path": "C:/a", "size": 1, "sha256": "a" * 64},
            "b": {"name": "b.bin", "kind": "other", "path": "C:/b", "size": 1, "sha256": "a" * 64},
            "size_delta": 0,
            "similarity": 100.0,
            "similarity_method": "custom",
            "identical": True,
            "pe": None,
            "apk": None,
            "highlights": [],
            "generated": "2026-01-01T00:00:00",
        }
        html = bindiff.render_html(result)
        self.assertIn("متطابقان 100%", html)
        self.assertIn("custom", html)
        self.assertNotIn("نقاط تستحق الانتباه", html)

    def test_run_writes_json_and_html_report(self) -> None:
        a = self.write("old.bin", b"A" * 128)
        b = self.write("new.bin", b"A" * 64 + b"B" * 64)
        out = self.tmp / "diffs"
        with patch.object(bindiff, "DIFFS_DIR", out):
            result = bindiff.run(a, b)
        self.assertTrue(Path(result["report"]).is_file())
        self.assertTrue((Path(result["output_dir"]) / "diff.json").is_file())
        data = json.loads((Path(result["output_dir"]) / "diff.json").read_text("utf-8"))
        self.assertEqual(data["a"]["name"], "old.bin")

    def test_run_rejects_missing_files(self) -> None:
        with self.assertRaises(FileNotFoundError):
            bindiff.run(self.tmp / "missing-a.bin", self.tmp / "missing-b.bin")


if __name__ == "__main__":
    unittest.main()
