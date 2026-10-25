"""اختبارات تغطية الوحدات الخمس الأضعف — بلا شبكة أو تنفيذ عيّنات.

تستهدف الفروع المتبقية في: patcher، tokenizer، strings_analyzer، yara_engine،
وskills. كل العمليات الخارجية محاكاة، وكل الملفات تُبنى داخل مجلد مؤقت.
"""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from replatform.agents import tokenizer
from replatform.analyzers import strings_analyzer
from replatform.core import util
from replatform.skills import (
    Skill,
    SkillError,
    _parse_front_matter,
    compose_skills,
    get_skill,
    list_skills,
    load_skills,
)
from replatform.tools import patcher, yara_engine


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, data: bytes | str) -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path


# ---------------------------------------------------------------------------
# patcher
# ---------------------------------------------------------------------------


class PatcherEdgeTests(TempDirTest):
    def test_is_system_path_skips_broken_directory(self) -> None:
        class BrokenDirectory:
            def __str__(self) -> str:
                return "broken"

            def resolve(self):
                raise OSError("boom")

        with patch.object(patcher, "SYSTEM_DIRS", [BrokenDirectory()]):
            self.assertFalse(patcher.is_system_path(self.write("a.bin", b"x")))

    def test_is_pe_rejects_other_suffixes(self) -> None:
        self.assertFalse(patcher.is_pe("notes.txt"))
        self.assertTrue(patcher.is_pe("APP.EXE"))

    def test_parse_hex_rejects_empty_and_bad_tokens(self) -> None:
        with self.assertRaises(ValueError):
            patcher._parse_hex("", True)
        with self.assertRaises(ValueError):
            patcher._parse_hex("4D ZZ", True)
        with self.assertRaises(ValueError):
            patcher._parse_hex("4D ??", False)

    def test_patch_rejects_mismatched_kinds_and_lengths(self) -> None:
        target = self.write("a.bin", b"ABCD")
        with self.assertRaises(ValueError):
            patcher.patch(target, "str:AB", "hex:41")
        with self.assertRaises(ValueError):
            patcher.patch(target, "hex:41 42", "hex:43")

    def test_patch_rejects_oversized_file(self) -> None:
        target = self.write("a.bin", b"ABCD")
        with patch.object(patcher, "MAX_PATCH_BYTES", 1):
            with self.assertRaises(ValueError):
                patcher.patch(target, "str:AB", "str:CD")

    def test_patch_rejects_system_path_without_permission(self) -> None:
        target = self.write("a.bin", b"ABCD")
        with patch.object(patcher, "SYSTEM_DIRS", [self.tmp]):
            with self.assertRaises(PermissionError):
                patcher.patch(target, "str:AB", "str:CD")

    def test_patch_removes_backup_when_copy_fails(self) -> None:
        target = self.write("a.bin", b"ABCD")
        with patch.object(patcher.shutil, "copy2", side_effect=OSError("denied")):
            with self.assertRaises(OSError):
                patcher.patch(target, "str:AB", "str:CD", apply=True)
        self.assertEqual(list(self.tmp.glob("a.bin.bak.*")), [])

    def test_patch_removes_temp_file_when_replace_fails(self) -> None:
        target = self.write("a.bin", b"ABCD")
        with patch.object(patcher.os, "replace", side_effect=OSError("busy")):
            with self.assertRaises(OSError):
                patcher.patch(target, "str:AB", "str:CD", apply=True)
        self.assertEqual(list(self.tmp.glob(".a.bin.*.patch_tmp")), [])
        self.assertEqual(target.read_bytes(), b"ABCD")

    def test_patch_hex_all_matches(self) -> None:
        target = self.write("a.bin", b"ABAB")
        result = patcher.patch(
            target, "hex:41 42", "hex:43 44", apply=True, all_matches=True
        )
        self.assertTrue(result["applied"])
        self.assertEqual(result["replaced"], 2)
        self.assertEqual(target.read_bytes(), b"CDCD")

    def test_patch_str_overlap_is_rejected_without_writing(self) -> None:
        target = self.write("a.bin", b"aaa")
        with self.assertRaises(ValueError) as context:
            patcher.patch(target, "str:aa", "str:bb", apply=True, all_matches=True)
        self.assertIn("متداخلة", str(context.exception))
        self.assertEqual(target.read_bytes(), b"aaa")

    def test_patch_pe_success_reports_entry_point(self) -> None:
        target = self.write("a.exe", b"MZ" + b"\x00" * 30)
        fake = SimpleNamespace(
            OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1000),
            parse_data_directories=lambda: None,
            close=lambda: None,
        )
        fake_module = SimpleNamespace(PE=lambda *_args, **_kwargs: fake)
        with patch.dict(sys.modules, {"pefile": fake_module}):
            result = patcher.patch(target, "str:ZZZ", "str:YYY", apply=True)
        # لا تطابق: لا كتابة، لكن مسار PE لا يُنفّذ إلا بعد التعديل.
        self.assertFalse(result["applied"])

        target.write_bytes(b"MZ" + b"\x00" * 26 + b"ZZZ")
        with patch.dict(sys.modules, {"pefile": fake_module}):
            result = patcher.patch(target, "str:ZZZ", "str:YYY", apply=True)
        self.assertTrue(result["applied"])
        self.assertTrue(result["pe_valid"])
        self.assertEqual(result["entry_point"], "0x1000")

    def test_patch_pe_failure_rolls_back(self) -> None:
        target = self.write("a.exe", b"MZ" + b"\x00" * 26 + b"ZZZ")
        original = target.read_bytes()

        def explode(*_args, **_kwargs):
            raise ValueError("bad pe")

        with patch.dict(sys.modules, {"pefile": SimpleNamespace(PE=explode)}):
            result = patcher.patch(target, "str:ZZZ", "str:YYY", apply=True)
        self.assertFalse(result["pe_valid"])
        self.assertIn("bad pe", result["pe_error"])
        self.assertTrue(result["rolled_back"])
        self.assertFalse(result["applied"])
        self.assertEqual(target.read_bytes(), original)

    def test_patch_pe_rollback_failure_is_reported(self) -> None:
        target = self.write("a.exe", b"MZ" + b"\x00" * 26 + b"ZZZ")

        def explode(*_args, **_kwargs):
            raise ValueError("bad pe")

        with patch.dict(sys.modules, {"pefile": SimpleNamespace(PE=explode)}), patch.object(
            patcher.shutil, "copy2", side_effect=[None, OSError("locked")]
        ):
            result = patcher.patch(target, "str:ZZZ", "str:YYY", apply=True)
        self.assertFalse(result["pe_valid"])
        self.assertIn("locked", result["rollback_error"])
        self.assertTrue(result["applied"])

    def test_patch_pe_close_failure_is_ignored(self) -> None:
        target = self.write("a.exe", b"MZ" + b"\x00" * 26 + b"ZZZ")

        def explode_close() -> None:
            raise RuntimeError("close failed")

        fake = SimpleNamespace(
            OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x10),
            parse_data_directories=lambda: None,
            close=explode_close,
        )
        with patch.dict(sys.modules, {"pefile": SimpleNamespace(PE=lambda *_a, **_k: fake)}):
            result = patcher.patch(target, "str:ZZZ", "str:YYY", apply=True)
        self.assertTrue(result["pe_valid"])
        self.assertEqual(result["entry_point"], "0x10")

    def test_patch_zip_comment_stays_valid(self) -> None:
        target = self.tmp / "a.zip"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("a.txt", b"hello")
            archive.comment = b"AAAA"
        result = patcher.patch(target, "str:AAAA", "str:BBBB", apply=True)
        self.assertTrue(result["applied"])
        self.assertTrue(result["zip_valid"])
        with zipfile.ZipFile(target) as archive:
            self.assertEqual(archive.comment, b"BBBB")

    def test_patch_broken_zip_is_rolled_back(self) -> None:
        target = self.write("fake.zip", b"AAAA")
        original = target.read_bytes()
        with patch.object(util, "file_kind", return_value="ZIP"):
            result = patcher.patch(target, "str:AAAA", "str:BBBB", apply=True)
        self.assertFalse(result["zip_valid"])
        self.assertIn("zip_error", result)
        self.assertTrue(result["rolled_back"])
        self.assertEqual(target.read_bytes(), original)

    def test_reserve_backup_retries_on_collision(self) -> None:
        target = self.write("a.bin", b"x")
        real_open = os.open
        calls = {"count": 0}

        def flaky_open(path, flags, *args, **kwargs):
            if calls["count"] == 0:
                calls["count"] += 1
                raise FileExistsError("exists")
            return real_open(path, flags, *args, **kwargs)

        with patch.object(patcher.os, "open", side_effect=flaky_open):
            backup = patcher._reserve_backup(target)
        self.assertTrue(backup.name.endswith("-1"))
        backup.unlink()

    def test_reserve_backup_gives_up_after_100_attempts(self) -> None:
        target = self.write("a.bin", b"x")
        with patch.object(patcher.os, "open", side_effect=FileExistsError):
            with self.assertRaises(FileExistsError):
                patcher._reserve_backup(target)


# ---------------------------------------------------------------------------
# tokenizer
# ---------------------------------------------------------------------------


class TokenizerEdgeTests(unittest.TestCase):
    def tearDown(self) -> None:
        tokenizer._encoding.cache_clear()

    def test_missing_tiktoken_falls_back_to_estimate(self) -> None:
        with patch.dict(sys.modules, {"tiktoken": None}):
            reloaded = importlib.reload(tokenizer)
            self.assertIsNone(reloaded.tiktoken)
            self.assertIsNone(reloaded._encoding("auto"))
            self.assertEqual(reloaded.engine_name(), "estimate:chars/4")
            self.assertEqual(reloaded.count_text("abcd"), 1)
        importlib.reload(tokenizer)

    def test_broken_tiktoken_returns_none(self) -> None:
        class Broken:
            def encoding_for_model(self, _name):
                raise ValueError("unknown model")

            def get_encoding(self, _name):
                raise ValueError("unknown encoding")

        with patch.object(tokenizer, "tiktoken", Broken()):
            tokenizer._encoding.cache_clear()
            self.assertIsNone(tokenizer._encoding("gpt-4"))
            self.assertEqual(tokenizer.engine_name("gpt-4"), "estimate:chars/4")

    def test_encode_failure_falls_back_to_estimate(self) -> None:
        class BrokenEncoding:
            name = "broken"

            def encode(self, _text, disallowed_special=()):
                raise RuntimeError("boom")

        class FakeTiktoken:
            def encoding_for_model(self, _name):
                return BrokenEncoding()

        with patch.object(tokenizer, "tiktoken", FakeTiktoken()):
            tokenizer._encoding.cache_clear()
            self.assertEqual(tokenizer.count_text("abcdefgh"), 2)

    def test_empty_text_and_messages(self) -> None:
        self.assertEqual(tokenizer.count_text(""), 0)
        self.assertEqual(tokenizer.count_messages([]), 0)

    def test_count_messages_includes_tool_calls(self) -> None:
        messages = [
            {"role": "assistant", "content": "", "tool_calls": [{"id": "1"}]},
            {"role": "tool", "content": "x", "tool_call_id": "call-1"},
        ]
        total = tokenizer.count_messages(messages)
        self.assertGreater(total, 16)


# ---------------------------------------------------------------------------
# strings_analyzer
# ---------------------------------------------------------------------------


class StringsEdgeTests(TempDirTest):
    def setUp(self) -> None:
        super().setUp()
        strings_analyzer._CACHE.clear()

    def tearDown(self) -> None:
        strings_analyzer._CACHE.clear()

    def test_invalid_config_falls_back_to_default(self) -> None:
        target = self.write("a.bin", b"ABCDEF")
        with patch.object(
            strings_analyzer, "load_config", return_value={"analysis": {"strings_max_mb": "x"}}
        ):
            result = strings_analyzer.scan(str(target))
        self.assertIn("ABCDEF", result["strings"])

    def test_cache_is_cleared_after_eight_entries(self) -> None:
        for index in range(9):
            target = self.write(f"f{index}.bin", f"STRING{index}".encode())
            strings_analyzer.scan(str(target))
        self.assertEqual(len(strings_analyzer._CACHE), 1)

    def test_ascii_limit_breaks_early(self) -> None:
        target = self.write("a.bin", b"AAAAAA BBBBBB CCCCCC")
        result = strings_analyzer.scan(str(target), limit=1)
        self.assertEqual(result["total"], 1)

    def test_utf16_strings_and_limit(self) -> None:
        data = b"A\x00B\x00C\x00D\x00E\x00F\x00" + b"\xff" + b"G\x00H\x00I\x00J\x00K\x00L\x00"
        target = self.write("u.bin", data)
        result = strings_analyzer.scan(str(target), limit=1)
        self.assertEqual(result["total"], 2)
        self.assertIn("ABCDEF", result["strings"])

    def test_empty_file_and_other_kind(self) -> None:
        target = self.write("empty.bin", b"")
        self.assertEqual(strings_analyzer.scan(str(target))["total"], 0)
        analyzer = strings_analyzer.StringsAnalyzer()
        self.assertTrue(analyzer.can_handle(SimpleNamespace(kind="other")))
        self.assertFalse(analyzer.can_handle(SimpleNamespace(kind="PE-NOT")))
        self.assertFalse(analyzer.can_handle(SimpleNamespace(kind="script")))

    def test_search_stops_at_maximum(self) -> None:
        target = self.write("a.bin", b"alpha1\nbeta22\ngamma3\ndelta4\n")
        self.assertEqual(len(strings_analyzer.search(str(target), r"[a-z]+", maximum=1)), 1)
        with self.assertRaises(ValueError):
            strings_analyzer.search(str(target), "x" * (strings_analyzer.MAX_PATTERN_CHARS + 1))
        with self.assertRaises(ValueError):
            strings_analyzer.search(str(target), r"(a+)+")

    def test_run_uses_configured_sample_limit(self) -> None:
        target = self.write("a.bin", b"oneone\ntwotwo\nthreethree\n")
        config = {"analysis": {"strings_max": 2, "strings_max_mb": 512}}
        with patch.object(strings_analyzer, "load_config", return_value=config):
            result = strings_analyzer.StringsAnalyzer().run(
                SimpleNamespace(path=target), None
            )
        self.assertEqual(len(result["sample"]), 2)
        self.assertIn("notable", result)


# ---------------------------------------------------------------------------
# yara_engine
# ---------------------------------------------------------------------------


class YaraEdgeTests(TempDirTest):
    def test_find_binary_prefers_tools_directory(self) -> None:
        tools = self.tmp / "tools"
        (tools / "yara").mkdir(parents=True)
        (tools / "yara" / "yara64.exe").write_bytes(b"x")
        with patch.object(yara_engine, "TOOLS_DIR", tools):
            self.assertTrue(yara_engine.find_binary().endswith("yara64.exe"))

        (tools / "yara" / "yara64.exe").unlink()
        (tools / "yara" / "yara.exe").write_bytes(b"x")
        with patch.object(yara_engine, "TOOLS_DIR", tools):
            self.assertTrue(yara_engine.find_binary().endswith("yara.exe"))

    def test_find_binary_falls_back_to_path(self) -> None:
        with patch.object(yara_engine, "TOOLS_DIR", self.tmp / "missing"), patch.object(
            yara_engine.shutil, "which", side_effect=["yara64", None]
        ):
            self.assertEqual(yara_engine.find_binary(), "yara64")
        with patch.object(yara_engine, "TOOLS_DIR", self.tmp / "missing"), patch.object(
            yara_engine.shutil, "which", return_value=""
        ):
            self.assertEqual(yara_engine.find_binary(), "")

    def test_available_requires_binary_and_rules(self) -> None:
        rules = self.tmp / "rules"
        rules.mkdir()
        with patch.object(yara_engine, "find_binary", return_value="yara"), patch.object(
            yara_engine, "RULES_DIR", rules
        ):
            self.assertTrue(yara_engine.available())
        with patch.object(yara_engine, "find_binary", return_value=""), patch.object(
            yara_engine, "RULES_DIR", rules
        ):
            self.assertFalse(yara_engine.available())

    def test_rule_files_missing_directory(self) -> None:
        self.assertEqual(yara_engine.rule_files(self.tmp / "missing"), [])

    def test_scan_parses_stdout_and_skips_noise(self) -> None:
        stdout = (
            "0x10:$a: before-any-rule\n"
            "\n"
            "warning: deprecated\n"
            "error: something\n"
            "Suspicious_Rule\n"
            "0x20:$b: hello\n"
        )
        proc = SimpleNamespace(returncode=0, stdout=stdout, stderr=" note ")
        with patch.object(yara_engine, "find_binary", return_value="yara"), patch.object(
            yara_engine, "rule_files", return_value=["r.yar"]
        ), patch.object(yara_engine.subprocess, "run", return_value=proc):
            result = yara_engine.scan("x.exe")
        self.assertTrue(result["available"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["matches"][0]["rule"], "Suspicious_Rule")
        self.assertEqual(
            result["matches"][0]["strings"],
            [{"offset": 0x20, "id": "$b", "data": "hello"}],
        )
        self.assertEqual(result["stderr"], "note")

    def test_scan_reports_process_error(self) -> None:
        proc = SimpleNamespace(returncode=2, stdout="", stderr="bad rules")
        with patch.object(yara_engine, "find_binary", return_value="yara"), patch.object(
            yara_engine, "rule_files", return_value=["r.yar"]
        ), patch.object(yara_engine.subprocess, "run", return_value=proc):
            result = yara_engine.scan("x.exe")
        self.assertIn("bad rules", result["error"])
        self.assertEqual(result["matches"], [])


# ---------------------------------------------------------------------------
# skills
# ---------------------------------------------------------------------------


def _skill(name: str = "demo", body: str = "body") -> Skill:
    return Skill(
        name=name,
        title="Demo",
        description="desc",
        category="cat",
        tags=(),
        source="",
        body=body,
        path=Path(f"{name}.md"),
    )


def _front_matter(name: str = "demo", body: str = "body") -> str:
    return (
        "---\n"
        f"name: {name}\n"
        "title: Demo\n"
        "description: desc\n"
        "category: cat\n"
        "tags: a, b\n"
        "---\n"
        f"{body}\n"
    )


class SkillsEdgeTests(TempDirTest):
    def parse(self, text: str, name: str = "demo.md") -> Skill:
        return _parse_front_matter(text, self.tmp / name)

    def test_rejects_missing_or_incomplete_front_matter(self) -> None:
        with self.assertRaises(SkillError):
            self.parse("no header")
        with self.assertRaises(SkillError):
            self.parse("---\nname: demo")

    def test_rejects_invalid_lines_and_missing_fields(self) -> None:
        with self.assertRaises(SkillError):
            self.parse("---\nbadline\n---\nbody")
        with self.assertRaises(SkillError):
            self.parse("---\nname: demo\n---\nbody")

    def test_rejects_bad_name_and_mismatched_stem(self) -> None:
        with self.assertRaises(SkillError):
            self.parse(_front_matter("BAD NAME"))
        with self.assertRaises(SkillError):
            self.parse(_front_matter("other"))

    def test_rejects_empty_or_oversized_body(self) -> None:
        with self.assertRaises(SkillError):
            self.parse(_front_matter("demo", body=""))
        with patch("replatform.skills.MAX_SKILL_CHARS", 3):
            with self.assertRaises(SkillError):
                self.parse(_front_matter("demo", body="long body"))

    def test_parses_tags_and_source(self) -> None:
        text = _front_matter("demo").replace("category: cat", "category: cat\nsource: local")
        skill = self.parse(text)
        self.assertEqual(skill.tags, ("a", "b"))
        self.assertEqual(skill.source, "local")

    def test_load_skills_without_directory(self) -> None:
        with patch("replatform.skills.SKILLS_DIR", self.tmp / "missing"):
            self.assertEqual(load_skills(), {})

    def test_load_skills_rejects_symlinks(self) -> None:
        skills = self.tmp / "skills"
        skills.mkdir()
        (skills / "demo.md").write_text(_front_matter(), "utf-8")
        with patch("replatform.skills.SKILLS_DIR", skills), patch.object(
            Path, "is_symlink", return_value=True
        ):
            with self.assertRaises(SkillError):
                load_skills()

    def test_load_skills_rejects_paths_outside_root(self) -> None:
        skills = self.tmp / "skills"
        skills.mkdir()
        (skills / "demo.md").write_text(_front_matter(), "utf-8")
        with patch("replatform.skills.SKILLS_DIR", skills), patch.object(
            Path, "is_relative_to", return_value=False
        ):
            with self.assertRaises(SkillError):
                load_skills()

    def test_load_skills_reports_read_errors(self) -> None:
        skills = self.tmp / "skills"
        skills.mkdir()
        (skills / "demo.md").write_text(_front_matter(), "utf-8")
        with patch("replatform.skills.SKILLS_DIR", skills), patch.object(
            Path, "read_text", side_effect=OSError("locked")
        ):
            with self.assertRaises(SkillError):
                load_skills()

    def test_load_skills_rejects_duplicate_names(self) -> None:
        skills = self.tmp / "skills"
        skills.mkdir()
        (skills / "a.md").write_text(_front_matter("a"), "utf-8")
        (skills / "b.md").write_text(_front_matter("b"), "utf-8")
        with patch("replatform.skills.SKILLS_DIR", skills), patch(
            "replatform.skills._parse_front_matter", return_value=_skill("dup")
        ):
            with self.assertRaises(SkillError):
                load_skills()

    def test_get_skill_validates_and_lists_available(self) -> None:
        with self.assertRaises(SkillError):
            get_skill("BAD!")
        with patch("replatform.skills.load_skills", return_value={}):
            with self.assertRaises(SkillError) as context:
                get_skill("missing")
        self.assertIn("(لا توجد)", str(context.exception))

    def test_compose_skills_handles_empty_and_truncation(self) -> None:
        self.assertEqual(compose_skills([]), "")
        with patch("replatform.skills.get_skill", return_value=_skill(body="x" * 100)):
            composed = compose_skills(["demo"], max_chars=10)
        self.assertIn("اقتُطعت", composed)

    def test_compose_skills_joins_blocks(self) -> None:
        with patch("replatform.skills.get_skill", return_value=_skill(body="short")):
            composed = compose_skills(["demo"])
        self.assertIn("Demo", composed)
        self.assertIn("short", composed)

    def test_list_skills_serializes_entries(self) -> None:
        with patch("replatform.skills.load_skills", return_value={"demo": _skill()}):
            rows = list_skills()
        self.assertEqual(rows[0]["name"], "demo")
        self.assertEqual(rows[0]["tags"], [])


if __name__ == "__main__":
    unittest.main()
