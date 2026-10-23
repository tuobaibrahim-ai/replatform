"""اختبارات انحدار مستقلة لأهم تحصينات REPLATFORM.

تعمل دون شبكة أو عينات خارجية. تُشغَّل عبر:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from replatform.analyzers import apk_analyzer
from replatform.integrations import catalog, connectors
from replatform.integrations import http as integration_http
from replatform.tools import apk_tools, bindiff, sandbox

ROOT = Path(__file__).resolve().parents[1]


def _write_zip(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


class ManifestExportTests(unittest.TestCase):
    def test_android12_infers_intent_filter_and_flags_missing_explicit(self) -> None:
        xml = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="test"><uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
            <application>
              <activity android:name=".Main">
                <intent-filter>
                  <action android:name="android.intent.action.MAIN"/>
                  <category android:name="android.intent.category.LAUNCHER"/>
                </intent-filter>
              </activity>
              <service android:name=".Exported" android:exported="true"/>
              <receiver android:name=".Protected" android:permission="test.P">
                <intent-filter><action android:name="test.ACTION"/></intent-filter>
              </receiver>
              <provider android:name=".Private"/>
            </application></manifest>"""
        info = apk_analyzer.parse_manifest(xml)
        self.assertEqual(info["exported"], 3)
        self.assertEqual(info["exported_inferred"], 2)
        self.assertEqual(info["exported_missing_explicit"], 2)
        self.assertEqual(info["exported_without_permission"], 2)
        self.assertEqual(info["main_activity"], ".Main")
        reasons = {item["name"]: item["reason"] for item in info["exported_components"]}
        self.assertEqual(reasons[".Main"], "intent-filter-default")
        self.assertEqual(reasons[".Exported"], "explicit")

    def test_explicit_false_is_respected(self) -> None:
        xml = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="test"><application>
            <activity android:name=".Hidden" android:exported="false">
              <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
            </activity></application></manifest>"""
        info = apk_analyzer.parse_manifest(xml)
        self.assertEqual(info["exported"], 0)
        self.assertEqual(info["exported_inferred"], 0)

    def test_application_permission_is_inherited(self) -> None:
        xml = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="test"><uses-sdk android:targetSdkVersion="33"/><application
            android:permission="test.APP_PERMISSION">
            <service android:name=".Exported" android:exported="true"/>
            </application></manifest>"""
        info = apk_analyzer.parse_manifest(xml)
        self.assertEqual(info["exported"], 1)
        self.assertEqual(info["exported_without_permission"], 0)
        self.assertEqual(
            info["exported_components"][0]["permission"], "test.APP_PERMISSION"
        )

    def test_legacy_provider_default_depends_on_target_sdk(self) -> None:
        legacy = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="test"><uses-sdk android:targetSdkVersion="16"/><application>
            <provider android:name=".LegacyProvider"/></application></manifest>"""
        modern = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="test"><uses-sdk android:targetSdkVersion="33"/><application>
            <provider android:name=".ModernProvider"/></application></manifest>"""
        old_info = apk_analyzer.parse_manifest(legacy)
        new_info = apk_analyzer.parse_manifest(modern)
        self.assertEqual(old_info["exported"], 1)
        self.assertEqual(
            old_info["exported_components"][0]["reason"], "provider-legacy-default"
        )
        self.assertEqual(new_info["exported"], 0)


class ApkSafetyTests(unittest.TestCase):
    def test_validate_apk_rejects_zip_bomb_ratio(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bomb.apk"
            _write_zip(path, {"big.bin": b"\x00" * (2 * 1024 * 1024)})

            def limits(key: str, default: int) -> int:
                return {
                    "apk_max_ratio": 10,
                    "apk_max_entries": 1000,
                    "apk_uncompressed_max_mb": 100,
                    "apk_max_mb": 10,
                }.get(key, default)

            with patch.object(apk_analyzer, "_cfg_int", side_effect=limits):
                with self.assertRaises(ValueError):
                    apk_analyzer.validate_apk(path)

    def test_decode_refuses_existing_file_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "sample.apk"
            target = Path(tmp) / "target-file"
            _write_zip(apk, {"AndroidManifest.xml": b"<manifest/>"})
            target.write_text("not a directory", "utf-8")
            with self.assertRaises(ValueError):
                apk_tools.decode(apk, out=target, force=True)

    def test_verify_signed_rejects_unsigned_zip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unsigned.apk"
            _write_zip(path, {"AndroidManifest.xml": b"<manifest/>"})
            result = apk_tools._verify_signed(path)
            self.assertFalse(result["ok"])
            self.assertTrue(result["zip_valid"])

    @unittest.skipUnless(
        (ROOT / "apk" / "test.apk").is_file()
        and (ROOT / "tools" / "uber-apk-signer.jar").is_file(),
        "يتطلب عينة APK وuber-apk-signer",
    )
    def test_sign_rejects_output_file(self) -> None:
        sample = ROOT / "apk" / "test.apk"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.apk"
            shutil.copy2(sample, source)
            target = Path(tmp) / "not-a-directory"
            target.write_text("x", "utf-8")
            with self.assertRaises(ValueError):
                apk_tools.sign(source, out_dir=target)

    @unittest.skipUnless(
        (ROOT / "apk" / "test.apk").is_file()
        and (ROOT / "tools" / "uber-apk-signer.jar").is_file(),
        "يتطلب عينة APK وuber-apk-signer",
    )
    def test_sign_isolates_output_and_verifies_schemes(self) -> None:
        sample = ROOT / "apk" / "test.apk"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.apk"
            shutil.copy2(sample, source)
            out_dir = Path(tmp) / "signed"

            def fake_run(cmd: list[str], timeout: int) -> dict:
                output = Path(cmd[cmd.index("--out") + 1])
                shutil.copy2(sample, output / "copy-signed.apk")
                return {"ok": True, "returncode": 0, "command": cmd,
                        "stdout": "", "stderr": ""}

            with patch.object(apk_tools, "_run", side_effect=fake_run):
                result = apk_tools.sign(source, out_dir=out_dir)
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["verified"], result)
            self.assertTrue(Path(result["output"]).is_file())
            self.assertIn("v2", result["schemes"])


class SandboxWatchdogTests(unittest.TestCase):
    def test_terminate_process_tree(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            self.assertTrue(sandbox._terminate_process_tree(proc.pid))
            proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)

    def test_watchdog_constants_are_bounded(self) -> None:
        self.assertGreaterEqual(sandbox.MAX_WAIT_SECONDS, 60)
        self.assertLessEqual(sandbox.MAX_WAIT_SECONDS, 24 * 3600)


class BindiffLimitTests(unittest.TestCase):
    def test_skipped_deep_analysis_is_reported(self) -> None:
        self.assertTrue(bindiff._diff_pe({"skipped": True}, {}, [])["skipped"])
        self.assertTrue(bindiff._diff_apk({"skipped": True}, {}, [])["skipped"])

    def test_render_html_handles_skipped_apk(self) -> None:
        result = {
            "a": {"name": "a.apk", "kind": "APK", "path": "C:/a.apk", "size": 10, "sha256": "a" * 64},
            "b": {"name": "b.apk", "kind": "APK", "path": "C:/b.apk", "size": 12, "sha256": "b" * 64},
            "size_delta": 2,
            "similarity": None,
            "similarity_method": "none",
            "identical": False,
            "pe": None,
            "apk": {"skipped": True, "reason": "تجاوز الحد"},
            "highlights": ["تجاوز الحد"],
            "generated": "2026-01-01T00:00:00",
        }
        html = bindiff.render_html(result)
        self.assertIn("تجاوز الحد", html)
        self.assertIn("a.apk", html)


class IntegrationExpansionTests(unittest.TestCase):
    def test_catalog_contains_safe_abusech_connectors(self) -> None:
        for connector_id in ("urlhaus", "threatfox"):
            connector = catalog.get_connector(connector_id)
            self.assertTrue(connector.read_only)
            self.assertFalse(connector.sample_upload)
            self.assertEqual(connector.auth_env, "ABUSECH_AUTH_KEY")
            self.assertEqual(connector.host, f"{connector_id}-api.abuse.ch")

    def test_urlhaus_and_threatfox_normalization(self) -> None:
        class FakeClient:
            def post_json(self, url, *, form=None, payload=None, headers=None):
                self.assert_key = (headers or {}).get("Auth-Key")
                if "urlhaus" in url:
                    return {
                        "query_status": "ok",
                        "url": "http://evil.example/x",
                        "url_status": "online",
                        "host": "evil.example",
                        "date_added": "2026-01-01",
                        "threat": "malware_download",
                        "tags": ["test"],
                        "payloads": [{"response_sha256": "a" * 64}],
                    }
                return {
                    "query_status": "ok",
                    "data": [{
                        "id": "1", "ioc": "evil.example", "ioc_type": "domain",
                        "threat_type": "botnet_cc", "malware": "win.test",
                        "malware_printable": "Test", "confidence_level": 50,
                    }],
                }

        fake = FakeClient()
        with patch.dict(os.environ, {"ABUSECH_AUTH_KEY": "test-key"}):
            with patch.object(connectors, "_client", lambda _connector: fake):
                urlhaus = connectors._urlhaus(
                    catalog.get_connector("urlhaus"), "http://evil.example/x", 5
                )
                threatfox = connectors._threatfox(
                    catalog.get_connector("threatfox"), "evil.example", 5
                )
        self.assertTrue(urlhaus["found"])
        self.assertFalse(urlhaus["sample_downloaded"])
        self.assertEqual(fake.assert_key, "test-key")
        self.assertTrue(threatfox["found"])
        self.assertEqual(threatfox["items"][0]["malware"], "win.test")
        self.assertFalse(threatfox["sample_downloaded"])

    def test_indicator_validation(self) -> None:
        self.assertEqual(connectors._indicator_kind("1.2.3.4"), "ip")
        self.assertEqual(connectors._indicator_kind("example.com"), "domain")
        self.assertEqual(connectors._indicator_kind("a" * 64), "file")
        self.assertEqual(connectors._indicator_kind("https://example.com/x"), "url")

    def test_tls_context_keeps_verification_enabled(self) -> None:
        context = integration_http._ssl_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)


if __name__ == "__main__":
    unittest.main()
