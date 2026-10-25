"""اختبارات تعاقدية للموصلات — بلا شبكة وبلا مفاتيح حقيقية.

تُغذّى استجابات نموذجية عبر عميل HTTP وهمي، للتأكد من صحة التطبيع
وسلامة الضوابط (قراءة فقط، عدم تنزيل عيّنات، رفض المؤشرات غير الصالحة).
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from replatform.integrations import connectors
from replatform.integrations.http import IntegrationError

KEY_ENVS = (
    "VIRUSTOTAL_API_KEY",
    "OTX_API_KEY",
    "MALWAREBAZAAR_AUTH_KEY",
    "ABUSEIPDB_API_KEY",
    "SHODAN_API_KEY",
    "ABUSECH_AUTH_KEY",
)

CLEAN_ENV = {name: "" for name in KEY_ENVS}


class FakeClient:
    """عميل وهمي يسجّل الطلبات ويعيد حمولة محددة أو يرفع خطأً."""

    def __init__(self, payload=None, error: str | None = None) -> None:
        self.payload = payload
        self.error = error
        self.calls: list[dict] = []

    def _respond(self):
        if self.error:
            raise IntegrationError(self.error)
        return self.payload

    def get_json(self, url, *, params=None, headers=None):
        self.calls.append({"method": "GET", "url": url, "params": params, "headers": headers})
        return self._respond()

    def post_json(self, url, *, payload=None, form=None, headers=None):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "payload": payload,
                "form": form,
                "headers": headers,
            }
        )
        return self._respond()


def _lookup(connector_id: str, query: str, payload=None, *, error=None, limit=5, env=None):
    client = FakeClient(payload, error)
    environment = dict(CLEAN_ENV)
    environment.update(env or {})
    with patch.dict(os.environ, environment, clear=False):
        with patch.object(connectors, "_client", return_value=client):
            result = connectors.lookup(
                connector_id, query, limit=limit, allow_network=True
            )
    return result, client


class LookupGuardTests(unittest.TestCase):
    def test_empty_query_rejected(self) -> None:
        with self.assertRaises(IntegrationError):
            connectors.lookup("nvd", "   ", allow_network=True)

    def test_control_characters_rejected(self) -> None:
        with self.assertRaises(IntegrationError):
            connectors.lookup("nvd", "cve\x00x", allow_network=True)

    def test_overlong_query_rejected(self) -> None:
        with self.assertRaises(IntegrationError):
            connectors.lookup("nvd", "a" * (connectors.MAX_QUERY + 1), allow_network=True)

    def test_limit_is_clamped(self) -> None:
        items = [{"cveID": f"CVE-{i}"} for i in range(40)]
        payload = {"vulnerabilities": items}
        result, _ = _lookup("cisa_kev", "CVE-", payload, limit=999)
        self.assertLessEqual(result["count"], 25)
        self.assertGreater(result["count"], 0)

    def test_unknown_connector_rejected(self) -> None:
        with self.assertRaises(KeyError):
            connectors.lookup("does-not-exist", "x", allow_network=True)

    def test_network_disabled_by_default(self) -> None:
        with patch.object(connectors, "_integration_cfg", return_value={"enabled": False}):
            with self.assertRaises(IntegrationError):
                connectors.lookup("nvd", "log4j")

    def test_result_is_flagged_read_only(self) -> None:
        result, _ = _lookup(
            "nvd",
            "log4j",
            {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]},
        )
        self.assertTrue(result["read_only"])
        self.assertFalse(result["sample_upload"])
        self.assertEqual(result["connector"], "nvd")


class NvdAndCisaTests(unittest.TestCase):
    def test_nvd_normalizes_cvss_and_description(self) -> None:
        payload = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-02T00:00:00.000",
                        "descriptions": [
                            {"lang": "es", "value": "texto"},
                            {"lang": "en", "value": "English description"},
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "references": [{"url": "https://example.test"}],
                    }
                }
            ],
        }
        result, _ = _lookup("nvd", "test", payload)
        self.assertEqual(result["count"], 1)
        item = result["items"][0]
        self.assertEqual(item["id"], "CVE-2024-0001")
        self.assertEqual(item["cvss"], 9.8)
        self.assertEqual(item["severity"], "CRITICAL")
        self.assertEqual(item["description"], "English description")
        self.assertEqual(item["references"], 1)

    def test_nvd_rejects_unexpected_shape(self) -> None:
        with self.assertRaises(IntegrationError):
            _lookup("nvd", "test", ["not", "a", "dict"])

    def test_cisa_kev_filters_matches(self) -> None:
        payload = {
            "catalogVersion": "2024.01.01",
            "dateReleased": "2024-01-01T00:00:00.000Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "requiredAction": "Apply updates",
                    "knownRansomwareCampaignUse": "Known",
                },
                {
                    "cveID": "CVE-2023-0002",
                    "vendorProject": "Other",
                    "product": "Thing",
                    "vulnerabilityName": "Unrelated",
                },
            ],
        }
        result, _ = _lookup("cisa_kev", "log4j", payload)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["cve"], "CVE-2021-44228")
        self.assertEqual(result["catalog_version"], "2024.01.01")

    def test_cisa_kev_empty_result(self) -> None:
        result, _ = _lookup("cisa_kev", "nothing-matches", {"vulnerabilities": []})
        self.assertEqual(result["count"], 0)


class SupplyChainTests(unittest.TestCase):
    def test_osv_parses_ecosystem_and_version(self) -> None:
        payload = {"vulns": [{"id": "GHSA-1", "summary": "bad", "aliases": ["CVE-1"]}]}
        result, client = _lookup("osv", "npm:lodash@4.17.20", payload)
        self.assertEqual(result["ecosystem"], "npm")
        self.assertEqual(result["package"], "lodash")
        self.assertEqual(result["version"], "4.17.20")
        self.assertEqual(result["count"], 1)
        self.assertEqual(client.calls[0]["payload"]["version"], "4.17.20")

    def test_osv_requires_ecosystem_prefix(self) -> None:
        with self.assertRaises(IntegrationError):
            connectors.lookup("osv", "lodash", allow_network=True)

    def test_github_sets_api_headers_and_maps_fields(self) -> None:
        payload = {
            "total_count": 1,
            "items": [
                {
                    "full_name": "owner/repo",
                    "html_url": "https://github.com/owner/repo",
                    "description": "desc",
                    "stargazers_count": 42,
                    "forks_count": 3,
                    "language": "Python",
                    "topics": ["security"],
                    "license": {"spdx_id": "MIT"},
                }
            ],
        }
        result, client = _lookup("github", "replatform", payload)
        self.assertEqual(result["items"][0]["full_name"], "owner/repo")
        self.assertEqual(result["items"][0]["license"], "MIT")
        headers = client.calls[0]["headers"]
        self.assertEqual(headers["Accept"], "application/vnd.github+json")
        self.assertEqual(headers["X-GitHub-Api-Version"], "2022-11-28")

    def test_github_rejects_overlong_query(self) -> None:
        with self.assertRaises(IntegrationError):
            connectors.lookup("github", "a" * 257, allow_network=True)

    def test_huggingface_dataset_prefix(self) -> None:
        payload = [{"id": "org/ds", "downloads": 5, "likes": 1, "tags": ["a"]}]
        result, client = _lookup("huggingface", "dataset:malware", payload)
        self.assertEqual(result["kind"], "datasets")
        self.assertTrue(client.calls[0]["url"].endswith("/api/datasets"))
        self.assertEqual(result["items"][0]["id"], "org/ds")


class MalwareIntelTests(unittest.TestCase):
    def test_virustotal_file_indicator(self) -> None:
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 12},
                    "reputation": -20,
                    "meaningful_name": "evil.exe",
                    "sha256": "a" * 64,
                }
            }
        }
        result, client = _lookup("virustotal", "a" * 64, payload, env={"VIRUSTOTAL_API_KEY": "k"})
        self.assertTrue(result["found"])
        self.assertEqual(result["kind"], "file")
        self.assertIn(f"/api/v3/files/{'a' * 64}", client.calls[0]["url"])
        self.assertEqual(result["attributes"]["last_analysis_stats"]["malicious"], 12)

    def test_virustotal_404_is_not_found(self) -> None:
        result, _ = _lookup(
            "virustotal",
            "8.8.8.8",
            error="HTTP 404: not found",
            env={"VIRUSTOTAL_API_KEY": "k"},
        )
        self.assertFalse(result["found"])
        self.assertEqual(result["items"], [])

    def test_virustotal_requires_key(self) -> None:
        with self.assertRaises(IntegrationError):
            connectors.lookup("virustotal", "8.8.8.8", allow_network=True)

    def test_otx_returns_pulses(self) -> None:
        payload = {
            "pulse_info": {
                "count": 1,
                "pulses": [{"name": "pulse", "modified": "m", "tags": ["t"]}],
            },
            "reputation": 0,
        }
        result, _ = _lookup("otx", "8.8.8.8", payload, env={"OTX_API_KEY": "k"})
        self.assertTrue(result["found"])
        self.assertEqual(result["pulse_count"], 1)
        self.assertEqual(result["pulses"][0]["name"], "pulse")

    def test_malwarebazaar_requires_hash(self) -> None:
        with self.assertRaises(IntegrationError):
            connectors.lookup(
                "malwarebazaar", "not-a-hash", allow_network=True
            )

    def test_malwarebazaar_ok_mapping_never_downloads(self) -> None:
        payload = {
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "a" * 64,
                    "sha1_hash": "b" * 40,
                    "md5_hash": "c" * 32,
                    "signature": "Emotet",
                    "file_type": "exe",
                    "file_size": 1024,
                    "tags": ["t"],
                }
            ],
        }
        result, _ = _lookup(
            "malwarebazaar", "a" * 64, payload, env={"MALWAREBAZAAR_AUTH_KEY": "k"}
        )
        self.assertTrue(result["found"])
        self.assertFalse(result["sample_downloaded"])
        self.assertEqual(result["items"][0]["signature"], "Emotet")

    def test_malwarebazaar_not_found_status(self) -> None:
        result, _ = _lookup(
            "malwarebazaar",
            "a" * 64,
            {"query_status": "hash_not_found"},
            env={"MALWAREBAZAAR_AUTH_KEY": "k"},
        )
        self.assertFalse(result["found"])
        self.assertEqual(result["status"], "hash_not_found")


class NetworkIntelTests(unittest.TestCase):
    def test_abuseipdb_validates_ip(self) -> None:
        with self.assertRaises(IntegrationError):
            connectors.lookup("abuseipdb", "not-an-ip", allow_network=True)

    def test_abuseipdb_maps_fields(self) -> None:
        payload = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "isp": "Google",
                "totalReports": 3,
                "isWhitelisted": True,
            }
        }
        result, _ = _lookup("abuseipdb", "8.8.8.8", payload, env={"ABUSEIPDB_API_KEY": "k"})
        self.assertEqual(result["attributes"]["isp"], "Google")
        self.assertTrue(result["attributes"]["whitelisted"])

    def test_shodan_requires_key(self) -> None:
        with self.assertRaises(IntegrationError):
            connectors.lookup("shodan", "8.8.8.8", allow_network=True)

    def test_shodan_maps_vulns_and_ports(self) -> None:
        payload = {
            "ip_str": "8.8.8.8",
            "ports": [53, 443],
            "org": "Google",
            "hostnames": ["dns.google"],
            "vulns": {"CVE-2020-1": {}},
        }
        result, _ = _lookup("shodan", "8.8.8.8", payload, env={"SHODAN_API_KEY": "k"})
        self.assertEqual(result["attributes"]["ports"], [53, 443])
        self.assertEqual(result["attributes"]["vulns"], ["CVE-2020-1"])


class AbuseChTests(unittest.TestCase):
    def test_urlhaus_url_payloads(self) -> None:
        payload = {
            "query_status": "ok",
            "url": "http://evil.test/a",
            "url_status": "online",
            "host": "evil.test",
            "threat": "malware_download",
            "tags": ["t"],
            "payloads": [
                {
                    "response_sha256": "a" * 64,
                    "response_md5": "b" * 32,
                    "file_type": "exe",
                    "response_size": 10,
                    "signature": "AgentTesla",
                }
            ],
        }
        result, client = _lookup(
            "urlhaus", "http://evil.test/a", payload, env={"ABUSECH_AUTH_KEY": "k"}
        )
        self.assertTrue(result["found"])
        self.assertEqual(result["attributes"]["payloads"][0]["signature"], "AgentTesla")
        self.assertIn("Auth-Key", client.calls[0]["headers"])

    def test_urlhaus_rejects_sha1(self) -> None:
        with self.assertRaises(IntegrationError):
            connectors.lookup(
                "urlhaus", "b" * 40, allow_network=True
            )

    def test_urlhaus_not_found(self) -> None:
        result, _ = _lookup(
            "urlhaus",
            "evil.test",
            {"query_status": "no_results"},
            env={"ABUSECH_AUTH_KEY": "k"},
        )
        self.assertFalse(result["found"])
        self.assertFalse(result["sample_downloaded"])

    def test_threatfox_hash_query(self) -> None:
        payload = {
            "query_status": "ok",
            "data": [
                {
                    "id": "1",
                    "ioc": "a" * 64,
                    "ioc_type": "sha256_hash",
                    "malware_printable": "Emotet",
                    "confidence_level": 90,
                    "tags": ["t"],
                }
            ],
        }
        result, client = _lookup(
            "threatfox", "a" * 64, payload, env={"ABUSECH_AUTH_KEY": "k"}
        )
        self.assertEqual(result["items"][0]["malware_printable"], "Emotet")
        self.assertEqual(client.calls[0]["payload"]["query"], "search_hash")

    def test_threatfox_ioc_query(self) -> None:
        result, client = _lookup(
            "threatfox",
            "evil.test",
            {"query_status": "ok", "data": [{"id": "2", "ioc": "evil.test"}]},
            env={"ABUSECH_AUTH_KEY": "k"},
        )
        self.assertTrue(result["found"])
        self.assertEqual(client.calls[0]["payload"]["query"], "search_ioc")
        self.assertTrue(client.calls[0]["payload"]["exact_match"])


class StatusTests(unittest.TestCase):
    def test_status_reports_missing_key(self) -> None:
        with patch.dict(os.environ, {"SHODAN_API_KEY": ""}, clear=False):
            data = connectors.status("shodan")
        self.assertFalse(data["configured"])
        self.assertTrue(data["requires_key"])

    def test_status_marks_keyless(self) -> None:
        data = connectors.status("cisa_kev")
        self.assertTrue(data["keyless"])
        self.assertFalse(data["sample_upload"])
        self.assertTrue(data["read_only"])


if __name__ == "__main__":
    unittest.main()
