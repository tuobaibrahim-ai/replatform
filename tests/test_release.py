"""اختبارات أدوات الإصدار: SBOM، البصمات، والحزمة المحمولة."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from replatform.tools import release


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


class ChecksumTests(TempDirTest):
    def test_sha256_file_matches_hashlib(self) -> None:
        import hashlib

        path = self.write("a.bin", b"replatform")
        self.assertEqual(
            release.sha256_file(path), hashlib.sha256(b"replatform").hexdigest()
        )

    def test_write_and_verify_roundtrip(self) -> None:
        self.write("a.whl", b"wheel")
        self.write("b.zip", b"zip")
        manifest = release.write_checksums(self.tmp)
        self.assertTrue(manifest.is_file())
        lines = manifest.read_text("utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        report = release.verify_checksums(self.tmp)
        self.assertTrue(report["ok"])
        self.assertEqual(report["checked"], 2)

    def test_manifest_excludes_itself(self) -> None:
        self.write("a.whl", b"wheel")
        release.write_checksums(self.tmp)
        release.write_checksums(self.tmp)
        lines = (self.tmp / "SHA256SUMS").read_text("utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertNotIn("SHA256SUMS", lines[0])

    def test_verify_detects_tampering(self) -> None:
        target = self.write("a.whl", b"wheel")
        release.write_checksums(self.tmp)
        target.write_bytes(b"tampered")
        report = release.verify_checksums(self.tmp)
        self.assertFalse(report["ok"])
        self.assertIn("بصمة مختلفة", report["problems"][0])

    def test_verify_detects_missing_file(self) -> None:
        target = self.write("a.whl", b"wheel")
        release.write_checksums(self.tmp)
        target.unlink()
        report = release.verify_checksums(self.tmp)
        self.assertFalse(report["ok"])
        self.assertIn("مفقود", report["problems"][0])

    def test_verify_without_manifest(self) -> None:
        report = release.verify_checksums(self.tmp)
        self.assertFalse(report["ok"])
        self.assertEqual(report["checked"], 0)
        self.assertIn("SHA256SUMS", report["error"])

    def test_write_checksums_requires_files(self) -> None:
        with self.assertRaises(FileNotFoundError):
            release.write_checksums(self.tmp)

    def test_verify_ignores_blank_lines(self) -> None:
        self.write("a.whl", b"wheel")
        release.write_checksums(self.tmp)
        manifest = self.tmp / "SHA256SUMS"
        manifest.write_text(manifest.read_text("utf-8") + "\n\n", "utf-8")
        self.assertTrue(release.verify_checksums(self.tmp)["ok"])


class SbomTests(TempDirTest):
    def test_build_sbom_is_cyclonedx(self) -> None:
        path = release.build_sbom(self.tmp, "9.9.9")
        data = json.loads(path.read_text("utf-8"))
        self.assertEqual(data["bomFormat"], "CycloneDX")
        self.assertEqual(data["specVersion"], "1.5")
        self.assertTrue(data["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(data["metadata"]["component"]["version"], "9.9.9")
        names = {component["name"] for component in data["components"]}
        self.assertTrue({"pefile", "asn1crypto", "certifi", "replatform"} <= names)

    def test_application_component_has_purl_and_license(self) -> None:
        data = json.loads(release.build_sbom(self.tmp, "1.2.3").read_text("utf-8"))
        app = next(c for c in data["components"] if c["name"] == "replatform")
        self.assertEqual(app["purl"], "pkg:pypi/replatform@1.2.3")
        self.assertEqual(app["licenses"][0]["license"]["id"], "MIT")

    def test_serial_number_is_stable_for_version(self) -> None:
        first = json.loads(release.build_sbom(self.tmp, "1.0.0").read_text("utf-8"))
        second = json.loads(release.build_sbom(self.tmp, "1.0.0").read_text("utf-8"))
        self.assertEqual(first["serialNumber"], second["serialNumber"])

    def test_dependency_fallback_when_not_installed(self) -> None:
        with patch.object(
            release.metadata,
            "distribution",
            side_effect=release.metadata.PackageNotFoundError,
        ):
            component = release._dependency_component("pefile")
        self.assertEqual(component["version"], "not-installed")
        self.assertEqual(component["licenses"][0]["license"]["id"], "MIT")
        self.assertEqual(component["purl"], "pkg:pypi/pefile@not-installed")

    def test_long_license_string_falls_back(self) -> None:
        class _Dist:
            version = "1.0"
            metadata = {"License": "x" * 200}

        with patch.object(release.metadata, "distribution", return_value=_Dist()):
            component = release._dependency_component("certifi")
        self.assertEqual(component["licenses"][0]["license"]["id"], "MPL-2.0")

    def test_unknown_dependency_license_is_unknown(self) -> None:
        class _Dist:
            version = "1.0"
            metadata = {}

        with patch.object(release.metadata, "distribution", return_value=_Dist()):
            component = release._dependency_component("mystery")
        self.assertEqual(component["licenses"][0]["license"]["id"], "unknown")


class PortableTests(TempDirTest):
    def _fixture_root(self) -> Path:
        root = self.tmp / "src"
        (root / "replatform").mkdir(parents=True)
        (root / "replatform" / "__init__.py").write_text("__version__='1.2.3'", "utf-8")
        (root / "replatform" / "__pycache__").mkdir()
        (root / "replatform" / "__pycache__" / "x.pyc").write_bytes(b"junk")
        (root / "docs").mkdir()
        (root / "docs" / "ARCHITECTURE.md").write_text("# a", "utf-8")
        (root / "repl.py").write_text("print('x')", "utf-8")
        (root / "README.md").write_text("# readme", "utf-8")
        return root

    def test_bundle_layout_and_determinism(self) -> None:
        root = self._fixture_root()
        with patch.object(release, "ROOT", root):
            first = release.build_portable(self.tmp / "out1", "1.2.3")
            second = release.build_portable(self.tmp / "out2", "1.2.3")
        with zipfile.ZipFile(first) as archive:
            names = archive.namelist()
            readme = archive.read("replatform-1.2.3/PORTABLE-README.txt").decode("utf-8")
        self.assertIn("replatform-1.2.3/repl.py", names)
        self.assertIn("replatform-1.2.3/docs/ARCHITECTURE.md", names)
        self.assertFalse(any("__pycache__" in name for name in names))
        self.assertFalse(any(name.endswith(".pyc") for name in names))
        self.assertIn("1.2.3", readme)
        self.assertIn("install.ps1", readme)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_bundle_entries_have_fixed_timestamp(self) -> None:
        with patch.object(release, "ROOT", self._fixture_root()):
            bundle = release.build_portable(self.tmp / "out", "1.2.3")
        with zipfile.ZipFile(bundle) as archive:
            for info in archive.infolist():
                self.assertEqual(info.date_time, (2026, 1, 1, 0, 0, 0))
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED)

    def test_line_endings_are_normalized_inside_bundle(self) -> None:
        root = self._fixture_root()
        # شجرة عمل Windows قد تحمل CRLF، وCI يستلم LF: الناتج يجب أن يتطابق.
        (root / "README.md").write_bytes(b"# a\r\nline\r\n")
        (root / "install.ps1").write_bytes(b"Write-Host 'a'\nWrite-Host 'b'\n")
        with patch.object(release, "ROOT", root):
            bundle = release.build_portable(self.tmp / "out", "1.2.3")
        with zipfile.ZipFile(bundle) as archive:
            readme = archive.read("replatform-1.2.3/README.md")
            script = archive.read("replatform-1.2.3/install.ps1")
        self.assertNotIn(b"\r", readme)
        self.assertEqual(script, b"Write-Host 'a'\r\nWrite-Host 'b'\r\n")

    def test_normalize_bytes_handles_binary_untouched(self) -> None:
        payload = b"\x00\x01\r\n\x02"
        self.assertEqual(release._normalize_bytes(payload, "a.exe"), payload)

    def test_check_reproducible_reports_matching_digest(self) -> None:
        with patch.object(release, "ROOT", self._fixture_root()):
            report = release.check_reproducible("1.2.3")
        self.assertTrue(report["ok"])
        self.assertEqual(report["sha256"], report["second"])
        self.assertGreater(report["size"], 0)

    def test_sbom_honours_source_date_epoch(self) -> None:
        dist = self.tmp / "dist"
        with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            path = release.build_sbom(dist, "1.2.3")
        payload = json.loads(path.read_text("utf-8"))
        self.assertEqual(payload["metadata"]["timestamp"], "2023-11-14T22:13:20+00:00")

    def test_empty_source_raises(self) -> None:
        empty = self.tmp / "empty"
        empty.mkdir()
        with patch.object(release, "ROOT", empty):
            with self.assertRaises(FileNotFoundError):
                release.build_portable(self.tmp / "out", "1.2.3")

    def test_iter_portable_files_skips_missing(self) -> None:
        with patch.object(release, "ROOT", self._fixture_root()):
            files = release._iter_portable_files()
        names = {path.name for path in files}
        self.assertIn("repl.py", names)
        self.assertNotIn("x.pyc", names)


class MainTests(TempDirTest):
    def _root(self) -> Path:
        root = self.tmp / "src"
        (root / "replatform").mkdir(parents=True)
        (root / "replatform" / "__init__.py").write_text("", "utf-8")
        (root / "repl.py").write_text("", "utf-8")
        (root / "README.md").write_text("", "utf-8")
        return root

    def test_main_builds_bundle_sbom_and_checksums(self) -> None:
        dist = self.tmp / "dist"
        with patch.object(release, "ROOT", self._root()):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = release.main(
                    [
                        "--dist", str(dist),
                        "--out", str(dist),
                        "--portable",
                        "--version", "1.2.3",
                    ]
                )
        self.assertEqual(code, 0)
        self.assertTrue((dist / "replatform-1.2.3-portable.zip").is_file())
        self.assertTrue((dist / "SBOM.cdx.json").is_file())
        self.assertTrue((dist / "SHA256SUMS").is_file())
        self.assertIn("portable:", out.getvalue())
        self.assertTrue(release.verify_checksums(dist)["ok"])

    def test_main_verify_returns_zero_for_valid_artifacts(self) -> None:
        dist = self.tmp / "dist"
        dist.mkdir()
        (dist / "a.whl").write_bytes(b"wheel")
        release.write_checksums(dist)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release.main(["--dist", str(dist), "--verify"]), 0)

    def test_main_verify_returns_one_for_tampered_artifacts(self) -> None:
        dist = self.tmp / "dist"
        dist.mkdir()
        target = dist / "a.whl"
        target.write_bytes(b"wheel")
        release.write_checksums(dist)
        target.write_bytes(b"tampered")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release.main(["--dist", str(dist), "--verify"]), 1)

    def test_verify_does_not_rewrite_artifacts(self) -> None:
        with patch.object(release, "build_sbom") as sbom:
            with patch.object(release, "write_checksums") as checksums:
                with contextlib.redirect_stdout(io.StringIO()):
                    release.main(["--dist", str(self.tmp), "--verify"])
        sbom.assert_not_called()
        checksums.assert_not_called()

    def test_main_without_portable_only_writes_metadata(self) -> None:
        dist = self.tmp / "dist"
        (self.tmp / "dist").mkdir()
        (dist / "a.whl").write_bytes(b"wheel")
        with contextlib.redirect_stdout(io.StringIO()):
            code = release.main(["--dist", str(dist), "--version", "1.2.3"])
        self.assertEqual(code, 0)
        self.assertTrue((dist / "SBOM.cdx.json").is_file())
        self.assertFalse((dist / "replatform-1.2.3-portable.zip").exists())


if __name__ == "__main__":
    unittest.main()
