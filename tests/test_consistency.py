"""اختبارات اتساق الإصدار والحوكمة — تمنع انحراف الأرقام بين المصادر.

الإصدار مذكور في أربعة أماكن (الحزمة، `pyproject.toml`، `CITATION.cff`،
`CHANGELOG.md`) وفي وثائق المنتج. أي انحراف بينها يعني إصداراً غير قابل
للتحقق، لذلك يُفحَص آلياً في CI.
"""

from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

import replatform

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _text(name: str) -> str:
    return (ROOT / name).read_text("utf-8")


def _pyproject() -> dict:
    with open(ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)


def _citation_field(field: str) -> str:
    for line in _text("CITATION.cff").splitlines():
        if line.startswith(f"{field}:"):
            return line.split(":", 1)[1].strip().strip('"')
    return ""


class VersionConsistencyTests(unittest.TestCase):
    def test_package_version_is_semver(self) -> None:
        self.assertRegex(replatform.__version__, SEMVER)

    def test_pyproject_matches_package(self) -> None:
        self.assertEqual(_pyproject()["project"]["version"], replatform.__version__)

    def test_citation_matches_package(self) -> None:
        self.assertEqual(_citation_field("version"), replatform.__version__)

    def test_changelog_has_current_version_heading(self) -> None:
        headings = re.findall(r"^## (\d+\.\d+\.\d+) — (\d{4}-\d{2}-\d{2})$", _text("CHANGELOG.md"), re.M)
        self.assertTrue(headings, "لا يوجد أي عنوان إصدار في CHANGELOG.md")
        versions = [version for version, _ in headings]
        self.assertIn(replatform.__version__, versions)
        self.assertEqual(versions[0], replatform.__version__, "أحدث إصدار يجب أن يكون أول عنوان")

    def test_citation_release_date_matches_changelog(self) -> None:
        match = re.search(
            rf"^## {re.escape(replatform.__version__)} — (\d{{4}}-\d{{2}}-\d{{2}})$",
            _text("CHANGELOG.md"),
            re.M,
        )
        self.assertIsNotNone(match)
        self.assertEqual(_citation_field("date-released"), match.group(1))

    def test_readmes_mention_current_version(self) -> None:
        for name in ("README.md", "README.en.md"):
            with self.subTest(name=name):
                self.assertIn(replatform.__version__, _text(name))

    def test_quality_doc_title_matches_version(self) -> None:
        self.assertIn(replatform.__version__, _text("docs/QUALITY.md").splitlines()[0])

    def test_release_notes_document_is_not_stale(self) -> None:
        # ملف ملاحظات الإصدار المحلي (إن وُجد) يجب أن يطابق الإصدار الحالي.
        notes = ROOT / "docs" / "RELEASE_NOTES.md"
        if notes.is_file():
            self.assertIn(replatform.__version__, notes.read_text("utf-8"))


class PackagingConsistencyTests(unittest.TestCase):
    def test_required_metadata_files_exist(self) -> None:
        for name in (
            "LICENSE",
            "README.md",
            "CHANGELOG.md",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md",
            "SUPPORT.md",
            "COMMERCIAL.md",
            "THIRD_PARTY_NOTICES.md",
            "CITATION.cff",
            "MANIFEST.in",
            "requirements.txt",
            "config.example.json",
        ):
            with self.subTest(name=name):
                self.assertTrue((ROOT / name).is_file(), name)

    def test_package_declares_typed_marker(self) -> None:
        self.assertTrue((ROOT / "replatform" / "py.typed").is_file())

    def test_runtime_dependencies_are_minimal_and_pinned(self) -> None:
        deps = _pyproject()["project"]["dependencies"]
        self.assertEqual(len(deps), 3, deps)
        names = {dep.split(">=")[0].split("==")[0].strip() for dep in deps}
        self.assertEqual(names, {"pefile", "asn1crypto", "certifi"})

    def test_requirements_txt_matches_runtime_dependencies(self) -> None:
        declared = {
            dep.split(">=")[0].split("==")[0].strip()
            for dep in _pyproject()["project"]["dependencies"]
        }
        listed = {
            line.split(">=")[0].split("==")[0].strip()
            for line in _text("requirements.txt").splitlines()
            if line.strip() and not line.startswith("#")
        }
        self.assertEqual(listed, declared)

    def test_certifi_floor_blocks_known_vulnerability(self) -> None:
        # PYSEC-2026-4320 أُصلحت في 2026.10.19؛ لا يجوز النزول تحتها.
        for name in ("pyproject.toml", "requirements.txt"):
            with self.subTest(name=name):
                self.assertIn("certifi>=2026.10.19", _text(name))

    def test_coverage_gate_matches_quality_doc(self) -> None:
        gate = _pyproject()["tool"]["coverage"]["report"]["fail_under"]
        self.assertGreaterEqual(gate, 85)
        self.assertIn(f"≥ {gate}%", _text("docs/QUALITY.md"))

    def test_config_example_has_no_secrets(self) -> None:
        import json

        config = json.loads(_text("config.example.json"))
        provider = config.get("provider", {})
        self.assertEqual(provider.get("api_key", ""), "")
        self.assertTrue(provider.get("api_key_env"), "يجب أن يُقرأ المفتاح من متغير بيئة")


@unittest.skipUnless(
    (ROOT / ".github" / "workflows").is_dir(),
    "اختبارات الحوكمة تتطلب مستودعاً كاملاً (لا تُشحن .github في حزمة التوزيع).",
)
class WorkflowGuardTests(unittest.TestCase):
    def _workflow(self, name: str) -> str:
        return (ROOT / ".github" / "workflows" / name).read_text("utf-8")

    def test_ci_runs_every_quality_gate(self) -> None:
        ci = self._workflow("ci.yml")
        for step in (
            "ruff check",
            "compileall",
            "unittest discover",
            "coverage report",
            "pip_audit -r requirements.txt",
            "build",
            "release --dist dist --out dist --portable",
        ):
            with self.subTest(step=step):
                self.assertIn(step, ci)

    def test_release_workflow_verifies_tag_and_audits(self) -> None:
        release = self._workflow("release.yml")
        self.assertIn("Verify tag matches version", release)
        self.assertIn("pip_audit -r requirements.txt", release)
        self.assertIn("--verify", release)

    def test_ci_and_release_use_same_audit_command(self) -> None:
        ci = self._workflow("ci.yml")
        release = self._workflow("release.yml")
        command = "python -m pip_audit -r requirements.txt --progress-spinner off"
        self.assertIn(command, ci)
        self.assertIn(command, release)


if __name__ == "__main__":
    unittest.main()
