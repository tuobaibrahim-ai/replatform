"""اختبارات انحدار لواجهة الأوامر: لقطة الأوامر/الخيارات + التوزيع والأخطاء.

هذه الاختبارات تحمي أي تفكيك لاحق لـ `cli.py`: أي تغيير في سطح الأوامر
يجب أن يكون واعياً ومقصوداً.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from replatform import cli

# لقطة سطح الأوامر. حدّثها فقط عند تغيير واجهة CLI بشكل مقصود.
EXPECTED_COMMANDS = {
    "tools": {"-h", "--help"},
    "version": {"-h", "--help"},
    "integrations": {
        "-h", "--help", "--json", "--limit", "--live", "--yes",
        "<action>", "<id>", "<query>",
    },
    "skills": {"-h", "--help", "<action>", "<name>"},
    "inventory": {"-h", "--help", "--out"},
    "analyze": {
        "-h", "--help", "--agent", "--name", "--only", "--open", "--skill",
        "--task", "<target>",
    },
    "agent": {"-h", "--help", "--mode", "--skill", "--task", "<target>"},
    "use": {"-h", "--help", "<path>"},
    "current": {"-h", "--help"},
    "patch": {
        "-h", "--help", "--all", "--allow-resize", "--allow-system", "--apply",
        "--enc", "--find", "--max-show", "--replace", "<target>",
    },
    "apk": {"-h", "--help", "--force", "--out", "<action>", "<target>"},
    "serve": {
        "-h", "--help", "--allowed-host", "--host", "--open", "--port", "--token",
    },
    "diff": {"-h", "--help", "--open", "--pdf", "<a>", "<b>"},
    "ghidra": {"-h", "--help", "--decompile-limit", "--no-decompile", "--rename", "<target>"},
    "sandbox": {
        "-h", "--help", "--json", "--network", "--out", "--run", "--timeout",
        "--yes", "<target>",
    },
    "benchmark": {"-h", "--help", "--json", "--out"},
    "scan": {
        "-h", "--help", "--all", "--deep", "--max", "--max-mb", "--no-recursive",
        "--only", "--open", "--pdf", "<path>",
    },
    "selftest": {"-h", "--help", "--full"},
    "ws": {"-h", "--help", "--json", "--pdf", "<action>", "<id>"},
    "config": {"-h", "--help", "--force", "<action>"},
    "plugin": {"-h", "--help", "<action>", "<name>"},
}


def _subparsers(parser: argparse.ArgumentParser):
    return next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )


def _surface(parser: argparse.ArgumentParser) -> dict[str, set[str]]:
    surface: dict[str, set[str]] = {}
    for name, sub in _subparsers(parser).choices.items():
        options: set[str] = set()
        for action in sub._actions:
            if action.option_strings:
                options.update(action.option_strings)
            elif action.dest != "help":
                options.add(f"<{action.dest}>")
        surface[name] = options
    return surface


class ParserSnapshotTests(unittest.TestCase):
    def test_command_surface_is_unchanged(self) -> None:
        self.assertEqual(_surface(cli.build_parser()), EXPECTED_COMMANDS)

    def test_all_commands_have_handlers(self) -> None:
        parser = cli.build_parser()
        for name, sub in _subparsers(parser).choices.items():
            self.assertTrue(
                callable(sub.get_default("func")),
                f"الأمر {name} بلا دالة تنفيذ",
            )

    def test_version_flag(self) -> None:
        parser = cli.build_parser()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as ctx:
                parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("REPLATFORM", out.getvalue())


class MainDispatchTests(unittest.TestCase):
    def test_no_command_prints_help(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main([]), 0)
        self.assertIn("usage", out.getvalue().lower())

    def test_version_command(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["version"]), 0)
        self.assertIn("REPLATFORM v", out.getvalue())

    def test_missing_target_returns_2(self) -> None:
        with patch.object(cli.state, "get_target", return_value=None):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["patch", "--find", "str:a", "--replace", "str:b"]), 2)

    def test_value_error_returns_2(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["ws", "show"]), 2)
        self.assertIn("معرّف", err.getvalue())

    def test_keyboard_interrupt_returns_130(self) -> None:
        with patch.object(cli, "cmd_version", side_effect=KeyboardInterrupt):
            with patch.object(cli, "build_parser") as builder:
                parser = argparse.ArgumentParser()
                parser.add_argument("--version", action="store_true")
                parser.set_defaults(func=cli.cmd_version)
                builder.return_value = parser
                self.assertEqual(cli.main([]), 130)

    def test_file_not_found_returns_2(self) -> None:
        with patch.object(cli, "cmd_version", side_effect=FileNotFoundError("gone")):
            with patch.object(cli, "build_parser") as builder:
                parser = argparse.ArgumentParser()
                parser.set_defaults(func=cli.cmd_version)
                builder.return_value = parser
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(cli.main([]), 2)
                self.assertIn("gone", err.getvalue())


class HelperTests(unittest.TestCase):
    def test_table_aligns_columns(self) -> None:
        text = cli._table(["A", "BB"], [["1", "2"]])
        lines = text.splitlines()
        self.assertEqual(len(lines), 3)
        self.assertIn("A", lines[0])
        self.assertIn("BB", lines[0])
        self.assertTrue(set(lines[1]) == {"-"})

    def test_color_respects_no_color(self) -> None:
        with patch.object(cli.sys.stdout, "isatty", return_value=True):
            with patch.dict("os.environ", {"NO_COLOR": "1"}):
                self.assertEqual(cli._color("x", "32"), "x")
            with patch.dict("os.environ", {}, clear=True):
                self.assertIn("\033[32m", cli._color("x", "32"))

    def test_resolve_target_prefers_argument(self) -> None:
        self.assertEqual(cli._resolve_target("x.exe"), Path("x.exe"))

    def test_resolve_target_uses_state(self) -> None:
        with patch.object(cli.state, "get_target", return_value=Path("saved.exe")):
            self.assertEqual(cli._resolve_target(None), Path("saved.exe"))

    def test_resolve_target_raises_without_state(self) -> None:
        with patch.object(cli.state, "get_target", return_value=None):
            with self.assertRaises(FileNotFoundError):
                cli._resolve_target(None)

    def test_agent_context_formats_and_truncates(self) -> None:
        results = {
            "pe": {
                "score": 6,
                "verdict": "warn",
                "summary": {
                    "arch": "x64",
                    "sections": [".text", ".data"],
                    "imports": ["CreateProcessW"],
                },
                "findings": ["غير موقّع"],
            },
            "yara": {"error": "timeout"},
            "broken": "not a dict",
        }
        text = cli._agent_context(results, limit=5000)
        self.assertIn("pe: درجة 6/10", text)
        self.assertIn("arch=x64", text)
        self.assertIn("yara: خطأ", text)
        self.assertNotIn("broken", text)
        truncated = cli._agent_context(results, limit=60)
        self.assertIn("مقتطعة", truncated)

    def test_agent_context_empty(self) -> None:
        self.assertEqual(cli._agent_context({}), "")

    def test_skills_from_arg(self) -> None:
        self.assertEqual(cli._skills_from_arg(None), [])
        self.assertEqual(cli._skills_from_arg(" re-ethics , pe-analysis "), ["re-ethics", "pe-analysis"])
        with self.assertRaises(ValueError):
            cli._skills_from_arg("does-not-exist")


class CommandTests(unittest.TestCase):
    def test_cmd_plugin_creates_and_refuses_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cli, "ROOT", Path(tmp)):
                args = argparse.Namespace(action="new", name="my_plugin")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.cmd_plugin(args), 0)
                path = Path(tmp) / "plugins" / "my_plugin.py"
                self.assertTrue(path.is_file())
                self.assertIn("MyAnalyzer", path.read_text("utf-8"))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.cmd_plugin(args), 1)

    def test_cmd_plugin_rejects_invalid_name(self) -> None:
        args = argparse.Namespace(action="new", name="1bad")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.cmd_plugin(args), 2)

    def test_cmd_config_show_masks_key(self) -> None:
        cfg = {"provider": {"api_key": "secret"}}
        with patch.object(cli, "load_config", return_value=cfg):
            with patch.object(cli, "api_key", return_value="secret"):
                with patch.object(cli, "mask_secret", return_value="****"):
                    with contextlib.redirect_stdout(io.StringIO()) as out:
                        self.assertEqual(
                            cli.cmd_config(argparse.Namespace(action="show")), 0
                        )
        self.assertIn("****", out.getvalue())
        self.assertNotIn("secret", out.getvalue())

    def test_cmd_config_init_writes_without_key(self) -> None:
        saved: dict = {}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cli, "CONFIG_PATH", Path(tmp) / "config.json"):
                with patch.object(cli, "load_config", return_value={"provider": {"api_key": "x"}}):
                    with patch.object(cli, "save_config", side_effect=saved.update):
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.assertEqual(
                                cli.cmd_config(argparse.Namespace(action="init", force=False)), 0
                            )
        self.assertEqual(saved["provider"]["api_key"], "")

    def test_cmd_config_init_respects_existing_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / "config.json"
            existing.write_text("{}", "utf-8")
            with patch.object(cli, "CONFIG_PATH", existing):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(
                        cli.cmd_config(argparse.Namespace(action="init", force=False)), 0
                    )
        self.assertIn("موجود", out.getvalue())

    def test_cmd_ws_list_empty(self) -> None:
        with patch.object(cli.Workspace, "list_all", return_value=[]):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(
                    cli.cmd_ws(argparse.Namespace(action="list", id=None, pdf=False, json=False)),
                    0,
                )
        self.assertIn("لا توجد", out.getvalue())

    def test_cmd_skills_list(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.cmd_skills(argparse.Namespace(action="list", name=None)), 0)
        self.assertIn("مهارات", out.getvalue())

    def test_cmd_integrations_list(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.cmd_integrations(
                argparse.Namespace(
                    action="list", id=None, query=None, limit=5, live=False,
                    yes=False, json=False,
                )
            )
        self.assertEqual(code, 0)
        self.assertIn("nvd", out.getvalue())


if __name__ == "__main__":
    unittest.main()
