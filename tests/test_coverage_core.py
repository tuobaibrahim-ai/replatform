"""اختبارات تغطية إضافية للنواة والمحللات — بلا شبكة أو عينات خارجية.

تستهدف الفروع التي لم تكن مغطاة في 1.4.0: util، registry، export،
__main__، pe_analyzer، وapk_analyzer. كل العيّنات تُبنى داخل الاختبار.
"""

from __future__ import annotations

import hashlib
import io
import os
import runpy
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from replatform import cli
from replatform.analyzers import apk_analyzer, pe_analyzer
from replatform.analyzers import Target
from replatform.core import export, registry, util


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, data: bytes | str) -> Path:
        path = self.tmp / name
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path


def _limits(**overrides):
    def fake(key: str, default: int) -> int:
        return overrides.get(key, default)

    return fake


def _make_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


class UtilCoverageTests(TempDirTest):
    def test_atomic_write_removes_temp_file_on_failure(self) -> None:
        target = self.tmp / "out.txt"
        with patch.object(util.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                util.atomic_write_text(target, "x")
        self.assertFalse(target.exists())
        self.assertEqual(list(self.tmp.glob(".out.txt.*.tmp")), [])

    def test_file_kind_handles_missing_and_broken_zip(self) -> None:
        self.assertEqual(util.file_kind(self.tmp / "missing.bin"), "other")
        broken = self.write("broken.zip", b"PK\x03\x04garbage")
        self.assertEqual(util.file_kind(broken), "ZIP")

    def test_authenticode_non_windows_is_not_applicable(self) -> None:
        with patch.object(util.os, "name", "posix"):
            self.assertEqual(
                util.authenticode("x.exe"), {"status": "n/a", "signer": ""}
            )

    def test_authenticode_parses_all_signature_fields(self) -> None:
        proc = SimpleNamespace(
            stdout="Valid\nCN=Test\nTHUMB\nIssuer\n2027-01-01T00:00:00\n",
            stderr="",
        )
        with patch.object(util.os, "name", "nt"), patch.object(
            util.subprocess, "run", return_value=proc
        ):
            result = util.authenticode("x.exe")
        self.assertEqual(result["status"], "Valid")
        self.assertEqual(result["signer"], "CN=Test")
        self.assertEqual(result["thumbprint"], "THUMB")
        self.assertEqual(result["issuer"], "Issuer")
        self.assertEqual(result["not_after"], "2027-01-01T00:00:00")

    def test_authenticode_handles_errors_and_empty_output(self) -> None:
        with patch.object(util.os, "name", "nt"), patch.object(
            util.subprocess, "run", side_effect=OSError("boom")
        ):
            result = util.authenticode("x.exe")
        self.assertEqual(result["status"], "error")
        self.assertIn("boom", result["error"])

        proc = SimpleNamespace(stdout="", stderr="")
        with patch.object(util.os, "name", "nt"), patch.object(
            util.subprocess, "run", return_value=proc
        ):
            self.assertEqual(util.authenticode("x.exe")["status"], "unknown")

    def test_run_version_prefers_stdout_then_stderr(self) -> None:
        with patch.object(
            util.subprocess,
            "run",
            return_value=SimpleNamespace(stdout=" v1 \n", stderr=""),
        ):
            self.assertEqual(util.run_version(["x"]), "v1")
        with patch.object(
            util.subprocess,
            "run",
            return_value=SimpleNamespace(stdout="", stderr=" err "),
        ):
            self.assertEqual(util.run_version(["x"]), "err")
        with patch.object(util.subprocess, "run", side_effect=OSError):
            self.assertEqual(util.run_version(["x"]), "")

    def test_human_size_edges(self) -> None:
        self.assertEqual(util.human_size(1023), "1023 B")
        self.assertEqual(util.human_size(1024**3), "1.0 GB")
        self.assertEqual(util.human_size(1024**4), "1024.0 GB")


class RegistryCoverageTests(TempDirTest):
    def test_resolve_returns_direct_existing_path(self) -> None:
        target = self.write("tool.exe", b"x")
        with patch.object(registry.shutil, "which", return_value=""):
            self.assertEqual(registry._resolve(str(target)), str(target))

    def test_resolve_scans_extra_dirs_directly(self) -> None:
        base = self.tmp / "ProgramFiles"
        base.mkdir()
        (base / "tool.exe").write_bytes(b"x")
        with patch.object(registry.shutil, "which", return_value=""), patch.object(
            registry, "_EXTRA_DIRS", [base]
        ):
            self.assertEqual(registry._resolve("tool"), str(base / "tool.exe"))

    def test_resolve_scans_extra_dir_subfolders(self) -> None:
        base = self.tmp / "ProgramFiles"
        vendor = base / "Vendor"
        vendor.mkdir(parents=True)
        (vendor / "tool.exe").write_bytes(b"x")
        with patch.object(registry.shutil, "which", return_value=""), patch.object(
            registry, "_EXTRA_DIRS", [base]
        ):
            self.assertEqual(registry._resolve("tool"), str(vendor / "tool.exe"))

    def test_resolve_scans_winget_packages(self) -> None:
        packages = self.tmp / "Packages"
        package = packages / "pkg"
        package.mkdir(parents=True)
        (package / "tool.exe").write_bytes(b"x")
        with patch.object(registry.shutil, "which", return_value=""), patch.object(
            registry, "_EXTRA_DIRS", [packages]
        ):
            self.assertEqual(registry._resolve("tool"), str(package / "tool.exe"))

        nested = package / "sub"
        nested.mkdir()
        (nested / "other.exe").write_bytes(b"x")
        with patch.object(registry.shutil, "which", return_value=""), patch.object(
            registry, "_EXTRA_DIRS", [packages]
        ):
            self.assertEqual(registry._resolve("other"), str(nested / "other.exe"))

    def test_resolve_missing_returns_empty(self) -> None:
        with patch.object(registry.shutil, "which", return_value=""), patch.object(
            registry, "_EXTRA_DIRS", []
        ):
            self.assertEqual(registry._resolve("definitely-missing"), "")

    def test_seven_zip_delegates_to_resolve(self) -> None:
        with patch.object(registry, "_resolve", return_value="7z.exe") as resolve:
            self.assertEqual(registry._seven_zip(), "7z.exe")
        resolve.assert_called_once_with("7z.exe")

    def test_detect_tools_marks_every_tool_available(self) -> None:
        tools = self.tmp / "tools"
        (tools / "jadx-cli" / "bin").mkdir(parents=True)
        (tools / "jadx-cli" / "bin" / "jadx.bat").write_text("", "utf-8")
        (tools / "apktool.jar").write_bytes(b"x")
        with patch.object(registry, "TOOLS_DIR", tools), patch(
            "replatform.tools.ghidra_tools.find_headless", return_value="headless"
        ), patch(
            "replatform.tools.ghidra_tools.find_java_home", return_value=str(self.tmp)
        ), patch(
            "replatform.tools.yara_engine.find_binary", return_value="yara"
        ), patch.object(
            registry, "_resolve", side_effect=lambda exe: exe
        ), patch.object(
            registry, "run_version", return_value="v1"
        ):
            result = registry.detect_tools()
        rows = {row["name"]: row for row in result}
        self.assertTrue(all(row["ok"] for row in result))
        self.assertEqual(rows["Cutter"]["version"], "(مثبت)")
        self.assertEqual(rows["Java"]["version"], "v1")
        self.assertTrue(rows["JDK (Ghidra)"]["path"].endswith("javac.exe"))

    def test_detect_tools_reports_missing_tools(self) -> None:
        empty = self.tmp / "empty"
        empty.mkdir()
        with patch.object(registry, "TOOLS_DIR", empty), patch(
            "replatform.tools.ghidra_tools.find_headless", return_value=""
        ), patch(
            "replatform.tools.ghidra_tools.find_java_home", return_value=""
        ), patch(
            "replatform.tools.yara_engine.find_binary", return_value=""
        ), patch.object(
            registry, "_resolve", return_value=""
        ), patch.object(
            registry, "run_version", return_value=""
        ):
            result = registry.detect_tools()
        rows = {row["name"]: row for row in result}
        for name in ("Java", "apktool", "jadx", "7-Zip", "Ghidra", "YARA"):
            self.assertFalse(rows[name]["ok"], name)
        self.assertEqual(rows["Ghidra"]["version"], "")

    def test_tool_matrix_uses_detection(self) -> None:
        fake = [{"name": "Java", "ok": True}, {"name": "ADB", "ok": False}]
        with patch.object(registry, "detect_tools", return_value=fake):
            self.assertEqual(registry.tool_matrix(), {"Java": True, "ADB": False})


class ExportCoverageTests(TempDirTest):
    def test_find_browser_honours_override(self) -> None:
        browser = self.write("browser.exe", b"x")
        with patch.dict(os.environ, {"RE_BROWSER": str(browser)}):
            self.assertEqual(export.find_browser(), str(browser))

    def test_find_browser_falls_back_to_path(self) -> None:
        browser = self.write("chrome.exe", b"x")
        empty = self.tmp / "empty"
        empty.mkdir()
        env = {
            "RE_BROWSER": "",
            "ProgramFiles": str(empty),
            "ProgramFiles(x86)": str(empty),
            "LOCALAPPDATA": str(empty),
        }
        with patch.dict(os.environ, env, clear=False), patch.object(
            export.shutil, "which", return_value=str(browser)
        ):
            self.assertEqual(export.find_browser(), str(browser))

    def test_find_browser_missing(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch.object(
            export.shutil, "which", return_value=""
        ):
            self.assertEqual(export.find_browser(), "")

    def test_html_to_pdf_rejects_missing_source(self) -> None:
        with self.assertRaises(FileNotFoundError):
            export.html_to_pdf(self.tmp / "nope.html")

    def test_html_to_pdf_requires_browser(self) -> None:
        source = self.write("report.html", "<html></html>")
        with patch.object(export, "find_browser", return_value=""):
            with self.assertRaises(RuntimeError):
                export.html_to_pdf(source)

    def test_html_to_pdf_writes_valid_pdf(self) -> None:
        source = self.write("report.html", "<html></html>")

        def fake_run(args, **_kwargs):
            target = next(
                arg for arg in args if arg.startswith("--print-to-pdf=")
            ).split("=", 1)[1]
            Path(target).write_bytes(b"%PDF-1.7\n" + b"x" * 600)
            return SimpleNamespace(stdout="", stderr="")

        with patch.object(export, "find_browser", return_value="chrome"), patch.object(
            export.subprocess, "run", side_effect=fake_run
        ):
            target = export.html_to_pdf(source, self.tmp / "out.pdf")
        self.assertTrue(target.is_file())
        self.assertTrue(target.read_bytes().startswith(b"%PDF-"))

    def test_html_to_pdf_rejects_non_pdf_output(self) -> None:
        source = self.write("report.html", "<html></html>")

        def fake_run(args, **_kwargs):
            target = next(
                arg for arg in args if arg.startswith("--print-to-pdf=")
            ).split("=", 1)[1]
            Path(target).write_bytes(b"x" * 600)
            return SimpleNamespace(stdout="oops", stderr="bad")

        with patch.object(export, "find_browser", return_value="chrome"), patch.object(
            export.subprocess, "run", side_effect=fake_run
        ):
            with self.assertRaises(RuntimeError):
                export.html_to_pdf(source, self.tmp / "out.pdf")

    def test_html_to_pdf_reports_timeout_and_os_error(self) -> None:
        source = self.write("report.html", "<html></html>")
        with patch.object(export, "find_browser", return_value="chrome"), patch.object(
            export.subprocess,
            "run",
            side_effect=export.subprocess.TimeoutExpired("chrome", 1),
        ):
            with self.assertRaises(RuntimeError):
                export.html_to_pdf(source, self.tmp / "t.pdf")
        with patch.object(export, "find_browser", return_value="chrome"), patch.object(
            export.subprocess, "run", side_effect=OSError("boom")
        ):
            with self.assertRaises(RuntimeError):
                export.html_to_pdf(source, self.tmp / "o.pdf")


class MainModuleTests(unittest.TestCase):
    def test_module_entrypoint_exits_with_main_result(self) -> None:
        with patch.object(cli, "main", return_value=0):
            with self.assertRaises(SystemExit) as context:
                runpy.run_module("replatform", run_name="__main__", alter_sys=True)
        self.assertEqual(context.exception.code, 0)


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------


def _section(name=b".text", entropy=6.5, vsize=100, raw=200, data=b"x"):
    return SimpleNamespace(
        Name=name,
        Misc_VirtualSize=vsize,
        SizeOfRawData=raw,
        get_data=lambda: data,
        get_entropy=lambda: entropy,
    )


def _bad_entropy_section():
    def explode():
        raise ValueError("bad entropy")

    return SimpleNamespace(
        Name=b".bad",
        Misc_VirtualSize=1,
        SizeOfRawData=1,
        get_data=lambda: b"",
        get_entropy=explode,
    )


def _import(dll: bytes, names: list[bytes]):
    return SimpleNamespace(
        dll=dll, imports=[SimpleNamespace(name=name) for name in names]
    )


def _fake_pe(sections=None, imports=None, machine=0x8664, stamp=0, dotnet=0):
    directories = [SimpleNamespace(VirtualAddress=0) for _ in range(15)]
    directories[14] = SimpleNamespace(VirtualAddress=dotnet)
    optional = SimpleNamespace(
        AddressOfEntryPoint=0x1000,
        ImageBase=0x140000000,
        DllCharacteristics=0x140,
        DATA_DIRECTORY=directories,
    )
    pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=machine, TimeDateStamp=stamp),
        OPTIONAL_HEADER=optional,
        sections=[_section()] if sections is None else sections,
        parse_data_directories=lambda: None,
        close=lambda: None,
    )
    if imports is not None:
        pe.DIRECTORY_ENTRY_IMPORT = imports
    return pe


class PEAnalyzerCoverageTests(TempDirTest):
    def test_compile_time_invalid_stamp(self) -> None:
        self.assertEqual(pe_analyzer._compile_time(10**18), "غير صالح")

    def test_parse_uses_config_limit_and_closes(self) -> None:
        sample = self.write("a.exe", b"MZ")
        fake = _fake_pe()
        with patch.object(
            pe_analyzer, "load_config", return_value={"analysis": {}}
        ), patch.object(pe_analyzer.pefile, "PE", return_value=fake) as pe:
            self.assertIs(pe_analyzer._parse(str(sample)), fake)
        pe.assert_called_once()

    def test_parse_invalid_config_falls_back(self) -> None:
        sample = self.write("a.exe", b"MZ")
        fake = _fake_pe()
        with patch.object(
            pe_analyzer,
            "load_config",
            return_value={"analysis": {"pe_max_mb": "not-a-number"}},
        ), patch.object(pe_analyzer.pefile, "PE", return_value=fake):
            self.assertIs(pe_analyzer._parse(str(sample)), fake)

    def test_parse_rejects_oversized_file(self) -> None:
        sample = self.write("a.exe", b"MZ")
        with patch.object(
            pe_analyzer, "load_config", return_value={"analysis": {"pe_max_mb": 0}}
        ):
            with self.assertRaises(ValueError):
                pe_analyzer._parse(str(sample))

    def test_quick_summary_with_fake_pe(self) -> None:
        fake = _fake_pe(
            sections=[_section(), _bad_entropy_section()],
            imports=[_import(b"KERNEL32.dll", [b"CreateFileW", b"VirtualAlloc"])],
        )
        with patch.object(pe_analyzer, "_parse", return_value=fake):
            summary = pe_analyzer.quick_summary("x.exe")
        self.assertEqual(summary["arch"], "x64")
        self.assertEqual(summary["import_functions"], 2)
        self.assertTrue(summary["protections"]["aslr"])
        self.assertTrue(summary["protections"]["dep"])
        self.assertFalse(summary["dotnet"])
        self.assertEqual(summary["compile_time"], "1970-01-01 00:00 UTC")
        self.assertEqual(summary["sections"][1]["entropy"], 0.0)

    def test_quick_summary_unknown_machine_and_no_imports(self) -> None:
        fake = _fake_pe(machine=0x1234, imports=None, dotnet=1)
        with patch.object(pe_analyzer, "_parse", return_value=fake):
            summary = pe_analyzer.quick_summary("x.exe")
        self.assertEqual(summary["arch"], "0x1234")
        self.assertEqual(summary["imports"], [])
        self.assertTrue(summary["dotnet"])

    def test_can_handle_only_pe(self) -> None:
        analyzer = pe_analyzer.PEAnalyzer()
        self.assertTrue(analyzer.can_handle(Target(Path("a.exe"), "a.exe", "PE", 1, "a")))
        self.assertFalse(analyzer.can_handle(Target(Path("a.apk"), "a.apk", "APK", 1, "a")))

    def test_run_scores_critical_when_indicators_present(self) -> None:
        summary = {"sections": [{"name": "UPX0", "entropy": 7.5}]}
        fake = _fake_pe(
            imports=[
                _import(
                    b"K",
                    [b"WriteProcessMemory", b"VirtualAllocEx", b"IsDebuggerPresent"],
                )
            ]
        )
        with patch.object(pe_analyzer, "quick_summary", return_value=summary), patch.object(
            pe_analyzer.util, "authenticode", return_value={"status": "NotSigned"}
        ), patch.object(pe_analyzer, "_parse", return_value=fake):
            result = pe_analyzer.PEAnalyzer().run(
                Target(Path("a.exe"), "a.exe", "PE", 1, "a"), None
            )
        self.assertEqual(result["verdict"], "critical")
        self.assertGreaterEqual(result["score"], 5)
        self.assertIn("حقن عمليات", result["indicators"])
        self.assertTrue(any("UPX" in item for item in result["findings"]))

    def test_run_is_info_for_clean_pe(self) -> None:
        summary = {"sections": [{"name": ".text", "entropy": 6.0}]}
        fake = _fake_pe(imports=None)
        with patch.object(pe_analyzer, "quick_summary", return_value=summary), patch.object(
            pe_analyzer.util, "authenticode", return_value={"status": "Valid"}
        ), patch.object(pe_analyzer, "_parse", return_value=fake):
            result = pe_analyzer.PEAnalyzer().run(
                Target(Path("a.exe"), "a.exe", "PE", 1, "a"), None
            )
        self.assertEqual(result["verdict"], "info")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["indicators"], {})


# ---------------------------------------------------------------------------
# APK
# ---------------------------------------------------------------------------


def _v2_value(cert: bytes) -> bytes:
    def lp(data: bytes) -> bytes:
        return len(data).to_bytes(4, "little") + data

    certs_blob = lp(cert)
    signed_data = lp(b"") + lp(certs_blob)
    signer = lp(signed_data)
    signers = lp(signer)
    return lp(signers)


def _sig_block(pairs: list[tuple[int, bytes]]) -> bytes:
    body = b""
    for pair_id, value in pairs:
        body += (
            (4 + len(value)).to_bytes(8, "little")
            + pair_id.to_bytes(4, "little")
            + value
        )
    size = len(body) + 8 + 16
    return (
        size.to_bytes(8, "little")
        + body
        + size.to_bytes(8, "little")
        + b"APK Sig Block 42"
    )


def _apk_with_sig_block(path: Path, pairs: list[tuple[int, bytes]]) -> Path:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
    raw = buffer.getvalue()
    eocd = raw.rfind(b"PK\x05\x06")
    cd_offset = int.from_bytes(raw[eocd + 16:eocd + 20], "little")
    block = _sig_block(pairs)
    data = raw[:cd_offset] + block + raw[cd_offset:]
    eocd = data.rfind(b"PK\x05\x06")
    data = (
        data[:eocd + 16]
        + (cd_offset + len(block)).to_bytes(4, "little")
        + data[eocd + 20:]
    )
    path.write_bytes(data)
    return path


class APKAnalyzerCoverageTests(TempDirTest):
    def test_validate_rejects_non_apk_and_bad_zip(self) -> None:
        with self.assertRaises(ValueError):
            apk_analyzer.validate_apk(self.write("a.txt", b"x"))
        with self.assertRaises(ValueError):
            apk_analyzer.validate_apk(self.write("bad.apk", b"not a zip"))

    def test_validate_rejects_oversized_and_too_many_entries(self) -> None:
        big = self.write("big.apk", b"x" * (1024 * 1024 + 1))
        with patch.object(
            apk_analyzer, "_cfg_int", side_effect=_limits(apk_max_mb=1)
        ):
            with self.assertRaises(ValueError):
                apk_analyzer.validate_apk(big)

        many = self.tmp / "many.apk"
        with zipfile.ZipFile(many, "w") as zf:
            for index in range(1001):
                zf.writestr(f"f{index}.txt", b"x")
        with patch.object(
            apk_analyzer, "_cfg_int", side_effect=_limits(apk_max_entries=1000)
        ):
            with self.assertRaises(ValueError):
                apk_analyzer.validate_apk(many)

    def test_validate_rejects_uncompressed_bomb(self) -> None:
        bomb = self.tmp / "bomb.apk"
        _make_zip(bomb, {"big.bin": b"\0" * (2 * 1024 * 1024)})
        with patch.object(
            apk_analyzer,
            "_cfg_int",
            side_effect=_limits(apk_uncompressed_max_mb=1, apk_max_mb=10),
        ):
            with self.assertRaises(ValueError):
                apk_analyzer.validate_apk(bomb)

    def test_validate_accepts_regular_apk(self) -> None:
        path = _make_zip(self.tmp / "ok.apk", {"AndroidManifest.xml": b"<manifest/>"})
        info = apk_analyzer.validate_apk(path)
        self.assertEqual(info["entries"], 1)
        self.assertGreater(info["size"], 0)

    def test_decode_requires_apktool(self) -> None:
        path = _make_zip(self.tmp / "ok.apk", {"AndroidManifest.xml": b"<manifest/>"})
        with patch.object(apk_analyzer, "TOOLS_DIR", self.tmp / "tools"):
            with self.assertRaises(RuntimeError):
                apk_analyzer.decode_apk(str(path))

    def test_decode_reads_manifest_and_apktool_metadata(self) -> None:
        path = _make_zip(self.tmp / "ok.apk", {"AndroidManifest.xml": b"<manifest/>"})
        tools = self.tmp / "tools"
        tools.mkdir()
        (tools / "apktool.jar").write_bytes(b"x")

        def fake_run(cmd, **_kwargs):
            out = Path(cmd[cmd.index("-o") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / "AndroidManifest.xml").write_text("<manifest package='x'/>", "utf-8")
            (out / "apktool.yml").write_text(
                "minSdkVersion: '21'\ntargetSdkVersion: 33\n"
                "versionCode: '7'\nversionName: 1.2\n",
                "utf-8",
            )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(apk_analyzer, "TOOLS_DIR", tools), patch.object(
            apk_analyzer.subprocess, "run", side_effect=fake_run
        ):
            decoded = apk_analyzer.decode_apk(str(path))
            manifest_xml = apk_analyzer.decode_manifest(str(path))
        self.assertIn("package='x'", decoded["xml"])
        self.assertEqual(decoded["meta"]["min_sdk"], "21")
        self.assertEqual(decoded["meta"]["version_name"], "1.2")
        self.assertEqual(manifest_xml, decoded["xml"])

    def test_decode_reports_missing_or_oversized_manifest(self) -> None:
        path = _make_zip(self.tmp / "ok.apk", {"AndroidManifest.xml": b"<manifest/>"})
        tools = self.tmp / "tools"
        tools.mkdir()
        (tools / "apktool.jar").write_bytes(b"x")

        def empty_run(cmd, **_kwargs):
            Path(cmd[cmd.index("-o") + 1]).mkdir(parents=True, exist_ok=True)
            return SimpleNamespace(returncode=1, stdout="", stderr="")

        with patch.object(apk_analyzer, "TOOLS_DIR", tools), patch.object(
            apk_analyzer.subprocess, "run", side_effect=empty_run
        ):
            with self.assertRaises(RuntimeError):
                apk_analyzer.decode_apk(str(path))

        def huge_run(cmd, **_kwargs):
            out = Path(cmd[cmd.index("-o") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / "AndroidManifest.xml").write_text("x" * (65 * 1024), "utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(apk_analyzer, "TOOLS_DIR", tools), patch.object(
            apk_analyzer.subprocess, "run", side_effect=huge_run
        ), patch.object(
            apk_analyzer,
            "_cfg_int",
            side_effect=_limits(apk_manifest_max_kb=0),
        ):
            with self.assertRaises(RuntimeError):
                apk_analyzer.decode_apk(str(path))

    def test_decode_without_apktool_yml_uses_empty_meta(self) -> None:
        path = _make_zip(self.tmp / "ok.apk", {"AndroidManifest.xml": b"<manifest/>"})
        tools = self.tmp / "tools"
        tools.mkdir()
        (tools / "apktool.jar").write_bytes(b"x")

        def fake_run(cmd, **_kwargs):
            out = Path(cmd[cmd.index("-o") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / "AndroidManifest.xml").write_text("<manifest/>", "utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(apk_analyzer, "TOOLS_DIR", tools), patch.object(
            apk_analyzer.subprocess, "run", side_effect=fake_run
        ):
            decoded = apk_analyzer.decode_apk(str(path))
        self.assertEqual(decoded["meta"]["min_sdk"], "")

    def test_parse_manifest_rejects_doctype_and_entities(self) -> None:
        payloads = (
            '<!DOCTYPE manifest [<!ENTITY x "y">]><manifest>&x;</manifest>',
            '<manifest><!ENTITY x "y"></manifest>',
            '<!doctype manifest><manifest/>',
        )
        for payload in payloads:
            with self.subTest(payload=payload[:24]):
                with self.assertRaises(ValueError):
                    apk_analyzer.parse_manifest(payload)

    def test_parse_manifest_accepts_plain_xml(self) -> None:
        info = apk_analyzer.parse_manifest("<manifest package='ok'/>")
        self.assertEqual(info["package"], "ok")

    def test_sdk_int_parsing(self) -> None:
        self.assertEqual(apk_analyzer._sdk_int("33"), 33)
        self.assertEqual(apk_analyzer._sdk_int("33.0"), 33)
        self.assertIsNone(apk_analyzer._sdk_int("abc"))
        self.assertIsNone(apk_analyzer._sdk_int(None))

    def test_parse_manifest_merges_metadata_and_application_flags(self) -> None:
        xml = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.demo"><application android:debuggable="true"
            android:allowBackup="false" android:usesCleartextTraffic="true">
            <uses-feature android:name="android.hardware.camera"/>
            <activity-alias android:name=".Alias"/>
            </application></manifest>"""
        info = apk_analyzer.parse_manifest(
            xml,
            {"min_sdk": "21", "target_sdk": "33", "version_code": "7", "version_name": "1.2"},
        )
        self.assertEqual(info["package"], "com.demo")
        self.assertEqual(info["min_sdk"], "21")
        self.assertEqual(info["target_sdk"], "33")
        self.assertEqual(info["version_code"], "7")
        self.assertEqual(info["version_name"], "1.2")
        self.assertEqual(info["features"], ["android.hardware.camera"])
        self.assertEqual(info["components"]["activities"], 1)
        self.assertTrue(info["application"]["debuggable"])
        self.assertFalse(info["application"]["allow_backup"])
        self.assertTrue(info["application"]["cleartext"])

    def test_parse_manifest_truncates_exported_components(self) -> None:
        activities = "".join(
            f'<activity android:name=".A{index}" android:exported="true"/>'
            for index in range(201)
        )
        xml = (
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            f'package="p"><application>{activities}</application></manifest>'
        )
        info = apk_analyzer.parse_manifest(xml)
        self.assertEqual(info["exported"], 201)
        self.assertEqual(len(info["exported_components"]), 200)
        self.assertTrue(info["exported_truncated"])

    def test_cert_from_der_without_asn1_returns_digest(self) -> None:
        result = apk_analyzer._cert_from_der(b"not-a-certificate")
        self.assertEqual(result["sha256"], hashlib.sha256(b"not-a-certificate").hexdigest())

    def test_signing_info_unsigned_and_broken_zip(self) -> None:
        unsigned = _make_zip(self.tmp / "u.apk", {"AndroidManifest.xml": b"<manifest/>"})
        info = apk_analyzer.signing_info(str(unsigned))
        self.assertEqual(info["schemes"], [])
        broken = self.write("broken.apk", b"nope")
        self.assertIn("error", apk_analyzer.signing_info(str(broken)))

    def test_signing_info_detects_v1_and_v4(self) -> None:
        path = _make_zip(
            self.tmp / "v1.apk",
            {
                "AndroidManifest.xml": b"<manifest/>",
                "META-INF/CERT.RSA": b"fake-cert",
            },
        )
        Path(str(path) + ".idsig").write_bytes(b"signature")
        info = apk_analyzer.signing_info(str(path))
        self.assertTrue(info["v1"])
        self.assertTrue(info["v4"])
        self.assertEqual(len(info["certs"]), 1)
        self.assertIn("v4_sha256", info)

        with patch.object(apk_analyzer, "MAX_IDSIG_BYTES", 1):
            limited = apk_analyzer.signing_info(str(path))
        self.assertIn("v4_error", limited)

    def test_signing_info_rejects_oversized_v1_certificate(self) -> None:
        path = _make_zip(
            self.tmp / "v1big.apk",
            {
                "AndroidManifest.xml": b"<manifest/>",
                "META-INF/CERT.RSA": b"x" * 32,
            },
        )
        with patch.object(apk_analyzer, "MAX_IDSIG_BYTES", 1):
            info = apk_analyzer.signing_info(str(path))
        self.assertIn("error", info)

    def test_signing_info_entry_limit(self) -> None:
        path = self.tmp / "many.apk"
        with zipfile.ZipFile(path, "w") as zf:
            for index in range(1001):
                zf.writestr(f"f{index}", b"x")
        with patch.object(
            apk_analyzer, "_cfg_int", side_effect=_limits(apk_max_entries=1000)
        ):
            info = apk_analyzer.signing_info(str(path))
        self.assertIn("error", info)

    def test_signing_info_detects_v2_v3_and_v31(self) -> None:
        value = _v2_value(b"FAKECERT")
        path = _apk_with_sig_block(
            self.tmp / "signed.apk",
            [
                (0x7109871A, value),
                (0xF05368C0, b"\0\0\0\0"),
                (0x1B93AD61, value),
            ],
        )
        info = apk_analyzer.signing_info(str(path))
        self.assertTrue(info["v2"])
        self.assertTrue(info["v3"])
        self.assertTrue(info["v3_1"])
        self.assertEqual(len(info["certs"]), 1)
        self.assertIn("v3.1", info["schemes"])

    def test_sig_block_reader_paths(self) -> None:
        self.assertIsNone(apk_analyzer._apk_sig_block(str(self.write("tiny.apk", b"x"))))
        plain = _make_zip(self.tmp / "plain.apk", {"a.txt": b"x"})
        self.assertIsNone(apk_analyzer._apk_sig_block(str(plain)))

        signed = _apk_with_sig_block(self.tmp / "s.apk", [(0xF05368C0, b"\0\0\0\0")])
        block = apk_analyzer._apk_sig_block(str(signed))
        self.assertIsNotNone(block)
        self.assertTrue(block.endswith(b"APK Sig Block 42"))

        # مسار احتياطي: كتلة توقيع بلا EOCD صالح (مع بادئة 8 بايت).
        trailing = 64
        payload = b"p" * (trailing - 24)
        raw = (
            b"P" * 8
            + trailing.to_bytes(8, "little")
            + payload
            + trailing.to_bytes(8, "little")
            + b"APK Sig Block 42"
        )
        fallback = self.write("fallback.apk", raw)
        block = apk_analyzer._apk_sig_block(str(fallback))
        self.assertIsNotNone(block)

    def test_native_libs_counts_abis(self) -> None:
        path = _make_zip(
            self.tmp / "libs.apk",
            {
                "lib/arm64-v8a/liba.so": b"a",
                "lib/arm64-v8a/libb.so": b"b",
                "lib/x86/libc.so": b"c",
                "lib/only.so": b"d",
            },
        )
        self.assertEqual(
            apk_analyzer._native_libs(str(path)), {"arm64-v8a": 2, "x86": 1}
        )

    def test_quick_summary_composes_manifest_and_signing(self) -> None:
        xml = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.demo"><uses-sdk android:minSdkVersion="21"
            android:targetSdkVersion="33"/><application android:debuggable="true">
            <activity android:name=".Main"><intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter></activity></application></manifest>"""
        with patch.object(
            apk_analyzer, "decode_apk", return_value={"xml": xml, "meta": {}}
        ), patch.object(
            apk_analyzer,
            "signing_info",
            return_value={"schemes": ["v2"], "certs": [{"subject": "CN=demo"}]},
        ), patch.object(
            apk_analyzer, "_native_libs", return_value={"arm64-v8a": 1}
        ):
            summary = apk_analyzer.quick_summary("a.apk")
        self.assertEqual(summary["package"], "com.demo")
        self.assertEqual(summary["main_activity"], ".Main")
        self.assertTrue(summary["debuggable"])
        self.assertEqual(summary["certs"], ["CN=demo"])
        self.assertEqual(summary["abis"], {"arm64-v8a": 1})

    def test_can_handle_only_apk(self) -> None:
        analyzer = apk_analyzer.APKAnalyzer()
        self.assertTrue(analyzer.can_handle(Target(Path("a.apk"), "a.apk", "APK", 1, "a")))
        self.assertFalse(analyzer.can_handle(Target(Path("a.exe"), "a.exe", "PE", 1, "a")))

    def test_run_scores_critical_for_insecure_apk(self) -> None:
        manifest = {
            "permissions": [
                "android.permission.CAMERA",
                "android.permission.READ_SMS",
            ],
            "application": {"debuggable": True, "cleartext": True},
            "exported": 2,
            "exported_without_permission": 2,
            "exported_missing_explicit": 1,
            "exported_components": [{"name": ".A"}, {"name": ".B"}],
        }
        with patch.object(
            apk_analyzer, "decode_apk", return_value={"xml": "<manifest/>", "meta": {}}
        ), patch.object(
            apk_analyzer, "parse_manifest", return_value=manifest
        ), patch.object(
            apk_analyzer, "signing_info", return_value={"schemes": [], "certs": []}
        ), patch.object(
            apk_analyzer, "_native_libs", return_value={}
        ):
            result = apk_analyzer.APKAnalyzer().run(
                Target(Path("a.apk"), "a.apk", "APK", 1, "a"), None
            )
        self.assertEqual(result["verdict"], "critical")
        self.assertEqual(result["dangerous_permissions"], [
            "android.permission.CAMERA",
            "android.permission.READ_SMS",
        ])
        self.assertTrue(any("debuggable" in item for item in result["findings"]))
        self.assertTrue(any("permission" in item for item in result["findings"]))

    def test_run_is_info_for_clean_apk(self) -> None:
        manifest = {
            "permissions": [],
            "application": {},
            "exported": 0,
            "exported_without_permission": 0,
            "exported_missing_explicit": 0,
        }
        with patch.object(
            apk_analyzer, "decode_apk", return_value={"xml": "<manifest/>", "meta": {}}
        ), patch.object(
            apk_analyzer, "parse_manifest", return_value=manifest
        ), patch.object(
            apk_analyzer, "signing_info", return_value={"v2": True, "certs": []}
        ), patch.object(
            apk_analyzer, "_native_libs", return_value={}
        ):
            result = apk_analyzer.APKAnalyzer().run(
                Target(Path("a.apk"), "a.apk", "APK", 1, "a"), None
            )
        self.assertEqual(result["verdict"], "info")
        self.assertEqual(result["score"], 0)


if __name__ == "__main__":
    unittest.main()
