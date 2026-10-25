"""اختبارات النواة: الإعدادات، الحالة، مساحات العمل، المهارات، التقارير."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from replatform.core import config, state, util, workspace
from replatform.core.workspace import Workspace, slugify
from replatform import reports, skills
from replatform.agents import tokenizer


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, data: bytes | str) -> Path:
        path = self.tmp / name
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path


class UtilTests(TempDirTest):
    def test_sha256_matches_hashlib(self) -> None:
        import hashlib

        path = self.write("a.bin", b"replatform")
        self.assertEqual(util.sha256_file(path), hashlib.sha256(b"replatform").hexdigest())

    def test_human_size_units(self) -> None:
        self.assertEqual(util.human_size(0), "0 B")
        self.assertEqual(util.human_size(1024), "1.0 KB")
        self.assertEqual(util.human_size(5 * 1024 * 1024), "5.0 MB")

    def test_file_kind_detects_formats(self) -> None:
        import zipfile

        self.assertEqual(util.file_kind(self.write("x.exe", b"MZ" + b"\0" * 62)), "PE")
        self.assertEqual(util.file_kind(self.write("x.elf", b"\x7fELF" + b"\0" * 60)), "ELF")
        self.assertEqual(util.file_kind(self.write("x.txt", b"plain")), "other")

        zip_path = self.tmp / "x.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("a.txt", "x")
        self.assertEqual(util.file_kind(zip_path), "ZIP")

        apk_path = self.tmp / "x.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
        self.assertEqual(util.file_kind(apk_path), "APK")

    def test_atomic_write_text_is_utf8(self) -> None:
        path = self.tmp / "note.txt"
        util.atomic_write_text(path, "مرحبا")
        self.assertEqual(path.read_text("utf-8"), "مرحبا")
        self.assertFalse(path.read_bytes().startswith(b"\xef\xbb\xbf"))


class ConfigTests(TempDirTest):
    def test_merge_is_deep(self) -> None:
        base = {"a": {"b": 1, "c": 2}, "d": 3}
        merged = config._merge(base, {"a": {"b": 9}})
        self.assertEqual(merged["a"], {"b": 9, "c": 2})
        self.assertEqual(base["a"]["b"], 1, "الأصل يجب ألا يتغير")

    def test_load_config_falls_back_on_invalid_json(self) -> None:
        bad = self.write("config.json", "{not json")
        with patch.object(config, "CONFIG_PATH", bad):
            cfg = config.load_config()
        self.assertEqual(cfg["provider"]["timeout"], 120)
        self.assertFalse(cfg["integrations"]["enabled"])

    def test_load_config_merges_partial_override(self) -> None:
        path = self.write("config.json", json.dumps({"integrations": {"enabled": True}}))
        with patch.object(config, "CONFIG_PATH", path):
            cfg = config.load_config()
        self.assertTrue(cfg["integrations"]["enabled"])
        self.assertEqual(cfg["integrations"]["timeout"], 20)

    def test_api_key_precedence(self) -> None:
        cfg = {"provider": {"api_key_env": "CUSTOM_KEY", "api_key": "inline"}}
        with patch.dict(os.environ, {"CUSTOM_KEY": "env-key"}, clear=False):
            self.assertEqual(config.api_key(cfg), "env-key")
        with patch.dict(os.environ, {"RE_API_KEY": "global"}, clear=False):
            self.assertEqual(config.api_key(cfg), "global")
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(config.api_key(cfg), "inline")

    def test_mask_secret(self) -> None:
        self.assertEqual(config.mask_secret(""), "(غير مضبوط)")
        self.assertEqual(config.mask_secret("short"), "****")
        self.assertEqual(config.mask_secret("abcdefghijkl"), "abcd…ijkl")


class StateTests(TempDirTest):
    def test_set_get_clear(self) -> None:
        target = self.write("sample.exe", b"MZ" + b"\0" * 10)
        state_file = self.tmp / "state.json"
        with patch.object(state, "STATE_PATH", state_file):
            data = state.set_target(target)
            self.assertEqual(data["kind"], "PE")
            self.assertEqual(state.get_target(), target.resolve())
            state.clear_target()
            self.assertIsNone(state.get_target())

    def test_set_target_missing_file(self) -> None:
        with patch.object(state, "STATE_PATH", self.tmp / "state.json"):
            with self.assertRaises(FileNotFoundError):
                state.set_target(self.tmp / "nope.exe")

    def test_corrupt_state_is_ignored(self) -> None:
        bad = self.write("state.json", "{broken")
        with patch.object(state, "STATE_PATH", bad):
            self.assertEqual(state.get_state(), {})
            self.assertIsNone(state.get_target())


class WorkspaceTests(TempDirTest):
    def setUp(self) -> None:
        super().setUp()
        self._patch = patch.object(workspace, "WORKSPACES_DIR", self.tmp / "workspaces")
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_slugify(self) -> None:
        self.assertEqual(slugify("sample.exe"), "sample-exe")
        self.assertEqual(slugify("***"), "target")

    def test_create_list_find_and_artifacts(self) -> None:
        target = self.write("sample.exe", b"MZ" + b"\0" * 10)
        ws = Workspace.create(target, name="sample.exe")
        self.assertTrue((ws.path / "meta.json").is_file())
        self.assertEqual(ws.meta["name"], "sample.exe")

        ws.save_artifact("pe", {"score": 2})
        self.assertEqual(ws.load_artifact("pe"), {"score": 2})
        self.assertEqual(ws.all_artifacts(), {"pe": {"score": 2}})

        self.assertEqual([w.id for w in Workspace.list_all()], [ws.id])
        self.assertEqual(Workspace.find(ws.id).id, ws.id)

        ws.add_event("test", "حدث")
        self.assertEqual(ws.timeline()[-1]["message"], "حدث")

    def test_duplicate_names_get_unique_ids(self) -> None:
        target = self.write("same.exe", b"MZ" + b"\0" * 10)
        first = Workspace.create(target, name="same.exe")
        second = Workspace.create(target, name="same.exe")
        self.assertNotEqual(first.id, second.id)

    def test_corrupt_artifact_and_timeline_are_skipped(self) -> None:
        target = self.write("s.exe", b"MZ" + b"\0" * 10)
        ws = Workspace.create(target)
        (ws.artifacts_dir / "bad.json").write_text("{oops", "utf-8")
        (ws.path / "timeline.jsonl").write_text('{"kind":"ok"}\nnot-json\n', "utf-8")
        self.assertEqual(ws.all_artifacts(), {})
        self.assertEqual(len(ws.timeline()), 1)

    def test_safe_meta_survives_corruption(self) -> None:
        target = self.write("s.exe", b"MZ" + b"\0" * 10)
        ws = Workspace.create(target)
        (ws.path / "meta.json").write_text("{broken", "utf-8")
        self.assertEqual(ws.safe_meta()["name"], "(meta تالف)")


class SkillsAndTokenizerTests(unittest.TestCase):
    def test_skills_load_and_compose(self) -> None:
        loaded = skills.load_skills()
        self.assertGreaterEqual(len(loaded), 9)
        for skill in loaded.values():
            self.assertTrue(skill.name)
            self.assertTrue(skill.description)

    def test_unknown_skill_raises(self) -> None:
        with self.assertRaises(skills.SkillError):
            skills.get_skill("does-not-exist")

    def test_compose_returns_content(self) -> None:
        text = skills.compose_skills(["re-ethics"])
        self.assertIsInstance(text, str)
        self.assertGreater(len(text), 50)

    def test_tokenizer_counts(self) -> None:
        self.assertGreater(tokenizer.count_text("hello world"), 0)
        self.assertGreater(tokenizer.count_messages([{"role": "user", "content": "hi"}]), 0)
        self.assertIsInstance(tokenizer.engine_name(), str)


class ReportsTests(TempDirTest):
    def setUp(self) -> None:
        super().setUp()
        self._patch = patch.object(workspace, "WORKSPACES_DIR", self.tmp / "workspaces")
        self._patch.start()
        self.addCleanup(self._patch.stop)
        target = self.write("evil&co.exe", b"MZ" + b"\0" * 10)
        self.ws = Workspace.create(target)
        self.ws.update_meta(kind="PE", size_human="1.0 KB", sha256="a" * 64)
        self.ws.save_artifact(
            "pe",
            {
                "score": 6,
                "verdict": "warn",
                "findings": ["غير موقّع", "إنتروبيا عالية"],
                "machine": "x64",
                "sections": [{"name": ".text", "entropy": 7.1, "size": 512}],
                "imports": ["CreateProcessW"],
            },
        )

    def test_render_escapes_target_name(self) -> None:
        path = reports.render(self.ws)
        html = path.read_text("utf-8")
        self.assertIn("REPLATFORM", html)
        self.assertIn("evil&amp;co.exe", html)
        self.assertNotIn("evil&co.exe", html)
        self.assertIn("تحليل PE", html)
        self.assertIn("6/10", html)

    def test_export_json_roundtrip(self) -> None:
        path = reports.export_json(self.ws)
        data = json.loads(path.read_text("utf-8"))
        self.assertEqual(data["meta"]["kind"], "PE")
        self.assertIn("pe", data["artifacts"])

    def test_render_all_analyzer_sections(self) -> None:
        self.ws.save_artifact(
            "apk",
            {
                "score": 4,
                "manifest": {
                    "package": "com.demo",
                    "version_name": "2.0",
                    "version_code": 20,
                    "min_sdk": 24,
                    "target_sdk": 34,
                    "main_activity": ".Main",
                    "exported": 3,
                    "exported_without_permission": 2,
                    "exported_missing_explicit": 1,
                    "permissions": ["android.permission.INTERNET"],
                    "components": {"activities": 1, "services": 1, "receivers": 0, "providers": 0},
                    "application": {"debuggable": True, "cleartext": True, "permission": "demo.P"},
                },
                "signing": {"schemes": ["v1", "v2"], "certs": [{"subject": "CN=demo"}]},
                "abis": {"arm64-v8a": 2},
            },
        )
        self.ws.save_artifact(
            "strings",
            {"total": 10, "unique": 8, "notable": {"URL": ["http://evil.test"], "IP": ["8.8.8.8"]}},
        )
        self.ws.save_artifact(
            "yara",
            {
                "rules_file_count": 3,
                "matches": [
                    {"rule": "Suspicious", "strings": [{"id": "$a", "offset": 256, "data": "CreateProcessW"}]}
                ],
            },
        )
        self.ws.save_artifact(
            "disasm",
            {
                "available": True,
                "arch": "x86",
                "bits": 64,
                "function_count": 120,
                "top_functions": [{"name": "main", "offset": "0x1000", "size": 64}],
                "entry_disasm": ["mov eax, 1"],
            },
        )
        self.ws.save_artifact(
            "ghidra",
            {
                "available": True,
                "program": "sample.exe",
                "language": "x86:LE:64",
                "image_base": "0x140000000",
                "function_count": 9,
                "decompiled_count": 2,
                "top_functions": [{"name": "FUN_1", "entry": "0x140001000", "size": 10}],
            },
        )
        html = reports.render(self.ws).read_text("utf-8")
        for needle in ("com.demo", "arm64-v8a", "http://evil.test", "Suspicious",
                       "mov eax, 1", "sample.exe", "0x140001000"):
            self.assertIn(needle, html)


if __name__ == "__main__":
    unittest.main()
