"""اختبارات دورة الحياة التجارية: الهجرة، التشخيص، الترقية، الترخيص، التدقيق."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import zipfile
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

from replatform.core import config as config_module
from replatform.tools import doctor, enterprise, licensing, upgrade


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


class ConfigMigrationTests(TempDirTest):
    def test_version_one_is_migrated_with_backup(self) -> None:
        path = self.write(
            "config.json",
            json.dumps({
                "api_key": "sk-legacy",
                "language": "en",
                "provider": {"model": "custom"},
                "analysis": {"yara": False},
            }),
        )
        report = config_module.migrate_config_file(path)
        self.assertTrue(report["ok"])
        self.assertTrue(report["changed"])
        self.assertEqual(report["from"], 1)
        self.assertEqual(report["to"], 2)
        self.assertTrue(Path(report["backup"]).is_file())
        data = json.loads(path.read_text("utf-8"))
        self.assertEqual(data["config_version"], 2)
        self.assertEqual(data["provider"]["api_key"], "sk-legacy")
        self.assertEqual(data["ui"]["language"], "en")
        self.assertFalse(data["analysis"]["yara"] is True)
        self.assertEqual(data["analysis"]["yara"], False)
        self.assertFalse(data["integrations"]["enabled"])
        self.assertFalse(data["integrations"]["agent_enabled"])
        self.assertNotIn("api_key", data)
        self.assertNotIn("language", data)

    def test_migration_is_idempotent(self) -> None:
        path = self.write("config.json", json.dumps({"config_version": 2}))
        report = config_module.migrate_config_file(path)
        self.assertFalse(report["changed"])
        self.assertIsNone(report["backup"])

    def test_newer_version_is_rejected(self) -> None:
        path = self.write("config.json", json.dumps({"config_version": 99}))
        with self.assertRaises(config_module.ConfigMigrationError):
            config_module.migrate_config_file(path)

    def test_dry_run_does_not_write(self) -> None:
        original = json.dumps({"provider": {"model": "keep"}})
        path = self.write("config.json", original)
        report = config_module.migrate_config_file(path, dry_run=True)
        self.assertTrue(report["dry_run"])
        self.assertEqual(path.read_text("utf-8"), original)
        self.assertIsNone(report["backup"])

    def test_missing_file_reports_defaults(self) -> None:
        report = config_module.migrate_config_file(self.tmp / "absent.json")
        self.assertTrue(report["ok"])
        self.assertFalse(report["changed"])
        self.assertIn("لا يوجد config.json", report["notes"][0])

    def test_existing_provider_key_wins_over_legacy(self) -> None:
        data, notes = config_module.migrate_config(
            {"api_key": "old", "provider": {"api_key": "new"}}
        )
        self.assertEqual(data["provider"]["api_key"], "new")
        self.assertTrue(any("أُهمل" in note for note in notes))

    def test_unknown_keys_survive_migration(self) -> None:
        data, _ = config_module.migrate_config({"custom": {"keep": 1}})
        self.assertEqual(data["custom"], {"keep": 1})

    def test_defaults_include_version(self) -> None:
        self.assertEqual(config_module.config_version(config_module.DEFAULTS), 2)


class DoctorTests(TempDirTest):
    def test_run_checks_reports_counts(self) -> None:
        report = doctor.run_checks(only=("python", "platform"))
        self.assertEqual(len(report["checks"]), 2)
        self.assertEqual(report["counts"]["fail"], 0)
        self.assertTrue(report["ok"])
        self.assertIn("version", report)

    def test_redaction_hides_secrets_at_any_depth(self) -> None:
        path = self.write(
            "config.json",
            json.dumps({
                "provider": {"api_key": "sk-secret"},
                "web": {"token": "tok-secret"},
                "integrations": {"connectors": [{"api_key": "deep-secret"}]},
                "safe": "visible",
            }),
        )
        with patch.object(config_module, "CONFIG_PATH", path):
            redacted = doctor.redacted_config()
        text = json.dumps(redacted)
        self.assertNotIn("sk-secret", text)
        self.assertNotIn("tok-secret", text)
        self.assertNotIn("deep-secret", text)
        self.assertIn("visible", text)

    def test_bundle_contains_no_secrets(self) -> None:
        path = self.write(
            "config.json", json.dumps({"provider": {"api_key": "sk-very-secret"}})
        )
        with patch.object(config_module, "CONFIG_PATH", path):
            target = doctor.build_bundle(self.tmp / "out" / "diag.zip",
                                         report=doctor.run_checks(only=("python",)))
        self.assertTrue(target.is_file())
        with zipfile.ZipFile(target) as archive:
            names = set(archive.namelist())
            blob = b"".join(archive.read(name) for name in names)
        self.assertEqual(
            names, {"doctor.json", "environment.txt", "config.redacted.json", "README.txt"}
        )
        self.assertNotIn(b"sk-very-secret", blob)


class LicensingTests(unittest.TestCase):
    SEED = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    PUBLIC = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )

    def test_rfc8032_vector_one(self) -> None:
        self.assertEqual(licensing.ed25519_public_key(self.SEED), self.PUBLIC)
        signature = licensing.ed25519_sign(self.SEED, b"")
        self.assertEqual(
            signature.hex(),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        self.assertTrue(licensing.ed25519_verify(self.PUBLIC, b"", signature))

    def test_rfc8032_vector_two(self) -> None:
        seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        message = bytes.fromhex("72")
        signature = licensing.ed25519_sign(seed, message)
        self.assertTrue(
            licensing.ed25519_verify(licensing.ed25519_public_key(seed), message, signature)
        )

    def test_rejects_tampered_payload(self) -> None:
        payload = self._payload()
        signed = licensing.sign_license(payload, self.SEED)
        signed["seats"] = 9999
        state = licensing.verify_license(signed, self.PUBLIC)
        self.assertFalse(state["valid"])
        self.assertIn("توقيع", state["reason"])

    def test_rejects_wrong_key(self) -> None:
        signed = licensing.sign_license(self._payload(), self.SEED)
        other = licensing.ed25519_public_key(b"\x01" * 32)
        self.assertFalse(licensing.verify_license(signed, other)["valid"])

    def test_expired_license_is_community(self) -> None:
        payload = self._payload(expires=(date.today() - timedelta(days=60)).isoformat())
        state = licensing.verify_license(
            licensing.sign_license(payload, self.SEED), self.PUBLIC
        )
        self.assertFalse(state["valid"])
        self.assertEqual(state["tier"], "community")

    def test_grace_period_keeps_entitlements(self) -> None:
        payload = self._payload(expires=(date.today() - timedelta(days=3)).isoformat())
        state = licensing.verify_license(
            licensing.sign_license(payload, self.SEED), self.PUBLIC
        )
        self.assertTrue(state["valid"])
        self.assertTrue(state["grace"])
        self.assertIn("audit_export", state["features"])

    def test_unknown_tier_rejected(self) -> None:
        payload = self._payload(tier="platinum")
        state = licensing.verify_license(
            licensing.sign_license(payload, self.SEED), self.PUBLIC
        )
        self.assertFalse(state["valid"])

    def test_activate_and_deactivate(self) -> None:
        target = Path(tempfile.mkdtemp()) / "license.json"
        source = target.parent / "incoming.json"
        signed = licensing.sign_license(self._payload(), self.SEED)
        source.write_text(json.dumps(signed), encoding="utf-8")
        with patch.dict(os.environ, {"RE_LICENSE_PUBKEY": self.PUBLIC.hex()}):
            state = licensing.activate(source, target)
            self.assertTrue(state["valid"])
            self.assertTrue(target.is_file())
            self.assertTrue(licensing.status(target)["valid"])
            self.assertTrue(licensing.has_feature("audit_export", target))
            self.assertFalse(licensing.has_feature("fleet_report", target))
            self.assertTrue(licensing.deactivate(target))
            self.assertFalse(licensing.status(target)["valid"])

    def test_activate_rejects_invalid_file(self) -> None:
        source = Path(tempfile.mkdtemp()) / "bad.json"
        source.write_text(json.dumps({"tier": "enterprise", "signature": "AAAA"}),
                          encoding="utf-8")
        with self.assertRaises(licensing.LicenseError):
            licensing.activate(source, source.parent / "license.json")

    def test_require_feature_message_is_actionable(self) -> None:
        target = Path(tempfile.mkdtemp()) / "none.json"
        with self.assertRaises(licensing.EntitlementError) as ctx:
            licensing.require_feature("audit_export", target)
        self.assertIn("docs/COMMERCIAL.md", str(ctx.exception))

    def _payload(self, **overrides) -> dict:
        payload = {
            "schema": licensing.LICENSE_SCHEMA,
            "license_id": "RE-TEST-1",
            "tier": "professional",
            "customer": "ACME",
            "seats": 5,
            "issued": date.today().isoformat(),
            "expires": (date.today() + timedelta(days=365)).isoformat(),
            "features": [],
        }
        payload.update(overrides)
        return payload


class EnterpriseTests(TempDirTest):
    def test_chain_detects_tampering(self) -> None:
        path = self.tmp / "audit.jsonl"
        enterprise.record("analyze", path=path, target="a.exe")
        enterprise.record("report", path=path, target="a.exe")
        self.assertTrue(enterprise.verify_chain(path)["ok"])
        lines = path.read_text("utf-8").splitlines()
        payload = json.loads(lines[0])
        payload["target"] = "b.exe"
        lines[0] = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = enterprise.verify_chain(path)
        self.assertFalse(report["ok"])
        self.assertEqual(report["broken_at"], 0)

    def test_export_is_gated(self) -> None:
        path = self.tmp / "audit.jsonl"
        enterprise.record("analyze", path=path)
        with patch.object(licensing, "require_feature", side_effect=licensing.EntitlementError("x")):
            with self.assertRaises(licensing.EntitlementError):
                enterprise.export_audit(self.tmp / "out.json", path)

    def test_export_writes_chain_proof(self) -> None:
        path = self.tmp / "audit.jsonl"
        enterprise.record("analyze", path=path, target="a.exe")
        payload = enterprise.export_audit(self.tmp / "out.json", path, enforce=False)
        written = json.loads((self.tmp / "out.json").read_text("utf-8"))
        self.assertTrue(written["chain"]["ok"])
        self.assertEqual(written["sha256"], payload["sha256"])
        self.assertEqual(written["entries"][0]["event"], "analyze")

    def test_fleet_report_aggregates_workspaces(self) -> None:
        class FakeWorkspace:
            def __init__(self, wid: str, kind: str) -> None:
                self.id = wid
                self._kind = kind

            def safe_meta(self) -> dict:
                return {
                    "id": self.id,
                    "created": "2026-01-01T00:00:00",
                    "version": "1.5.0",
                    "target": {"name": f"{self.id}.bin", "kind": self._kind},
                    "analyzers": [{"name": "pe"}],
                    "agent": {"status": "done"},
                }

        fake = [FakeWorkspace("ws1", "pe"), FakeWorkspace("ws2", "pe"),
                FakeWorkspace("ws3", "apk")]
        with patch.object(enterprise.Workspace, "list_all", return_value=fake):
            report = enterprise.fleet_report(enforce=False)
        self.assertEqual(report["total"], 3)
        self.assertEqual(report["kinds"], {"pe": 2, "apk": 1})
        self.assertEqual(len(report["sha256"]), 64)


class LicenseAdminTests(TempDirTest):
    def test_keygen_issue_verify_roundtrip(self) -> None:
        import contextlib
        import io

        from replatform.tools import license_admin

        key = self.tmp / "private.key"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(license_admin.main(["keygen", "--out", str(key)]), 0)
        self.assertEqual(len(key.read_bytes()), 32)
        public = licensing.ed25519_public_key(key.read_bytes()).hex()

        out = self.tmp / "license.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = license_admin.main([
                "issue", "--tier", "enterprise", "--customer", "ACME",
                "--seats", "3", "--days", "30", "--key", str(key),
                "--out", str(out),
            ])
        self.assertEqual(code, 0)
        data = json.loads(out.read_text("utf-8"))
        self.assertEqual(data["tier"], "enterprise")
        self.assertIn("signature", data)

        with patch.dict(os.environ, {"RE_LICENSE_PUBKEY": public}):
            state = licensing.verify_license(data)
            self.assertTrue(state["valid"])
            self.assertIn("fleet_report", state["features"])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(license_admin.main(["verify", str(out)]), 0)

    def test_keygen_refuses_overwrite(self) -> None:
        from replatform.tools import license_admin

        key = self.tmp / "private.key"
        key.write_bytes(b"x" * 32)
        with self.assertRaises(SystemExit):
            license_admin.main(["keygen", "--out", str(key)])

    def test_issue_rejects_missing_key(self) -> None:
        from replatform.tools import license_admin

        with self.assertRaises(SystemExit):
            license_admin.main([
                "issue", "--tier", "professional", "--customer", "ACME",
                "--key", str(self.tmp / "absent.key"), "--out", str(self.tmp / "o.json"),
            ])


class SecretScanTests(TempDirTest):
    def test_detects_high_confidence_token(self) -> None:
        from replatform.tools import secretscan

        token = "sk-" + "a" * 32
        findings = secretscan.scan_text(f'key = "{token}"', "replatform/x.py")
        self.assertTrue(any(item["rule"] == "openai" for item in findings))
        self.assertNotIn(token, json.dumps(findings), "يجب تقنيع القيمة")

    def test_nosecret_marker_is_honoured(self) -> None:
        from replatform.tools import secretscan

        token = "sk-" + "b" * 32
        line = f'key = "{token}"  # nosecret: fixture'
        self.assertEqual(secretscan.scan_text(line, "tests/t.py"), [])

    def test_generic_assignment_ignored_in_tests(self) -> None:
        from replatform.tools import secretscan

        line = 'api_key = "real-looking-value-123"'
        self.assertEqual(secretscan.scan_text(line, "tests/t.py"), [])
        self.assertTrue(secretscan.scan_text(line, "replatform/mod.py"))

    def test_scan_directory_reports_findings(self) -> None:
        from replatform.tools import secretscan

        self.write("app/leak.py", 'value = "ghp_' + "c" * 36 + '"\n')
        report = secretscan.scan(self.tmp)
        self.assertFalse(report["ok"])
        self.assertEqual(report["count"], 1)
        self.assertEqual(report["findings"][0]["path"], "app/leak.py")


class LifecycleCliTests(TempDirTest):
    def _run(self, argv: list[str]) -> tuple[int, str]:
        import contextlib
        import io

        from replatform import cli

        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            code = cli.main(argv)
        return code, stream.getvalue()

    def test_config_migrate_dry_run(self) -> None:
        path = self.write("config.json", json.dumps({"provider": {"model": "m"}}))
        with patch.object(config_module, "CONFIG_PATH", path):
            code, out = self._run(["config", "migrate", "--dry-run", "--json"])
        self.assertEqual(code, 0)
        self.assertIn('"dry_run": true', out)
        self.assertEqual(json.loads(path.read_text("utf-8")), {"provider": {"model": "m"}})

    def test_license_status_community(self) -> None:
        with patch.dict(os.environ, {"RE_LICENSE_PATH": str(self.tmp / "none.json")}):
            code, out = self._run(["license", "status"])
        self.assertEqual(code, 1)
        self.assertIn("community", out)

    def test_doctor_json_subset(self) -> None:
        code, out = self._run(["doctor", "--only", "python,platform", "--json"])
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual(len(report["checks"]), 2)

    def test_upgrade_requires_explicit_yes(self) -> None:
        code, out = self._run(["upgrade", str(self.tmp / "x.zip")])
        self.assertEqual(code, 2)
        self.assertIn("--yes", out)


class UpgradeTests(TempDirTest):
    def _bundle(self, version: str = "9.9.9", extra: dict | None = None) -> Path:
        target = self.tmp / f"replatform-{version}-portable.zip"
        root = f"replatform-{version}"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr(f"{root}/repl.py", "print('new')\n")
            archive.writestr(f"{root}/replatform/__init__.py", "__version__ = '9.9.9'\n")
            archive.writestr(f"{root}/docs/NEWS.md", "new\n")
            for name, data in (extra or {}).items():
                archive.writestr(f"{root}/{name}", data)
        return target

    def _install(self, name: str = "install") -> Path:
        target = self.tmp / name
        (target / "workspaces" / "ws1").mkdir(parents=True)
        (target / "workspaces" / "ws1" / "meta.json").write_text("{}", encoding="utf-8")
        (target / "config.json").write_text('{"provider": {}}', encoding="utf-8")
        (target / "repl.py").write_text("print('old')\n", encoding="utf-8")
        return target

    def test_verify_bundle_reports_version(self) -> None:
        info = upgrade.verify_bundle(self._bundle())
        self.assertTrue(info["ok"])
        self.assertEqual(info["version"], "9.9.9")
        self.assertEqual(info["files"], 3)

    def test_install_preserves_user_data_and_keeps_backup(self) -> None:
        target = self._install()
        report = upgrade.install_bundle(self._bundle(), target)
        self.assertTrue(report["ok"])
        self.assertIn("config.json", report["preserved"])
        self.assertIn("workspaces", report["preserved"])
        self.assertEqual((target / "repl.py").read_text("utf-8"), "print('new')\n")
        self.assertTrue((target / "config.json").is_file())
        self.assertTrue((target / "workspaces" / "ws1" / "meta.json").is_file())
        backup = Path(report["backup"])
        self.assertEqual((backup / "repl.py").read_text("utf-8"), "print('old')\n")

    def test_rollback_restores_previous_install(self) -> None:
        target = self._install()
        report = upgrade.install_bundle(self._bundle(), target)
        restored = upgrade.rollback(report["backup"], target)
        self.assertTrue(restored["ok"])
        self.assertEqual((target / "repl.py").read_text("utf-8"), "print('old')\n")

    def test_checksum_mismatch_aborts(self) -> None:
        with self.assertRaises(upgrade.UpgradeError):
            upgrade.install_bundle(self._bundle(), self._install(), expected_sha256="0" * 64)

    def test_zip_slip_is_rejected(self) -> None:
        target = self.tmp / "evil.zip"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("replatform-9.9.9/repl.py", "x")
            archive.writestr("replatform-9.9.9/../escape.txt", "x")
        with self.assertRaises(upgrade.UpgradeError):
            upgrade.verify_bundle(target)

    def test_missing_required_file_is_rejected(self) -> None:
        target = self.tmp / "partial.zip"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("replatform-9.9.9/README.md", "x")
        with self.assertRaises(upgrade.UpgradeError):
            upgrade.verify_bundle(target)

    def test_dry_run_leaves_target_untouched(self) -> None:
        target = self._install()
        report = upgrade.install_bundle(self._bundle(), target, dry_run=True)
        self.assertTrue(report["dry_run"])
        self.assertEqual((target / "repl.py").read_text("utf-8"), "print('old')\n")
        self.assertFalse((target / "docs").exists())

    def test_main_reports_error_as_json(self) -> None:
        import contextlib
        import io

        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = upgrade._main([str(self.tmp / "absent.zip"), "--target", str(self.tmp)])
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(stream.getvalue())["ok"])
