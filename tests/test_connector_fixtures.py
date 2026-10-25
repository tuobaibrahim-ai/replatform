"""اختبارات عقدية على استجابات مسجّلة (fixtures) لكل موصل — بلا شبكة أو مفاتيح.

كل حمولة هنا **مُصنَّعة يدوياً** على شكل الاستجابة الموثّقة للخدمة، والهدف فحص
منطق التطبيع (normalization) لا الاتصال. أي تغيير في شكل المخرجات يجب أن يكون
واعياً ويُحدَّث معه الاختبار.
"""

from __future__ import annotations

import base64
import os
import unittest
from unittest.mock import patch

from replatform.integrations import connectors
from replatform.integrations.http import IntegrationError

SHA256 = "a" * 64
MD5 = "b" * 32
SHA1 = "c" * 40


class FakeClient:
    """عميل HTTP وهمي يعيد حمولة مسجّلة ويسجّل الطلبات."""

    def __init__(self, payload=None, *, error: str = "") -> None:
        self.payload = payload
        self.error = error
        self.calls: list[dict] = []

    def _record(self, method: str, url: str, **kwargs) -> dict:
        self.calls.append({"method": method, "url": url, **kwargs})
        if self.error:
            raise IntegrationError(self.error)
        return self.payload

    def get_json(self, url, params=None, headers=None):
        return self._record("GET", url, params=params, headers=headers)

    def post_json(self, url, payload=None, form=None, headers=None):
        return self._record("POST", url, payload=payload, form=form, headers=headers)


class ConnectorFixtureTest(unittest.TestCase):
    def run_connector(self, connector_id: str, query: str, payload, *, limit: int = 5, error: str = ""):
        fake = FakeClient(payload, error=error)
        with patch.object(connectors, "_client", return_value=fake), patch.object(
            connectors, "_auth_headers", return_value={}
        ):
            result = connectors._LOOKUPS[connector_id](
                connectors.get_connector(connector_id), query, limit
            )
        return result, fake


NVD_FIXTURE = {
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2023-11-07T03:35:26.340",
                "descriptions": [
                    {"lang": "es", "value": "texto"},
                    {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect"},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                    ]
                },
                "references": [{"url": "https://a"}, {"url": "https://b"}],
            }
        },
        {
            "cve": {
                "id": "CVE-2021-45046",
                "descriptions": [],
                "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 9.0}}]},
            }
        },
    ],
}


class NVDFixtureTests(ConnectorFixtureTest):
    def test_normalizes_cve_entries(self) -> None:
        result, fake = self.run_connector("nvd", "log4j", NVD_FIXTURE)
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["total_results"], 2)
        first = result["items"][0]
        self.assertEqual(first["id"], "CVE-2021-44228")
        self.assertEqual(first["cvss"], 10.0)
        self.assertEqual(first["severity"], "CRITICAL")
        self.assertTrue(first["description"].startswith("Apache Log4j2"))
        self.assertEqual(first["references"], 2)
        self.assertEqual(fake.calls[0]["params"]["resultsPerPage"], 5)
        self.assertIn("keywordSearch", fake.calls[0]["params"])

    def test_falls_back_to_cvss_v2_and_empty_description(self) -> None:
        result, _ = self.run_connector("nvd", "x", NVD_FIXTURE)
        second = result["items"][1]
        self.assertEqual(second["cvss"], 9.0)
        self.assertIsNone(second["severity"])
        self.assertEqual(second["description"], "")
        self.assertEqual(second["references"], 0)

    def test_rejects_non_object_payload(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("nvd", "x", ["not", "a", "dict"])

    def test_honours_limit(self) -> None:
        result, _ = self.run_connector("nvd", "x", NVD_FIXTURE, limit=1)
        self.assertEqual(result["count"], 1)


CISA_FIXTURE = {
    "catalogVersion": "2026.10.24",
    "dateReleased": "2026-10-24T00:00:00Z",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
            "shortDescription": "JNDI lookup",
            "requiredAction": "Apply updates.",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2020-0001",
            "vendorProject": "Vendor",
            "product": "Product",
            "vulnerabilityName": "Other",
            "shortDescription": "mentions log4j too",
            "requiredAction": "R" * 600,
            "dateAdded": "2020-01-01",
            "dueDate": "2020-02-01",
            "knownRansomwareCampaignUse": "Unknown",
        },
        "not-a-dict",
    ],
}


class CisaKevFixtureTests(ConnectorFixtureTest):
    def test_filters_by_casefolded_query(self) -> None:
        result, _ = self.run_connector("cisa_kev", "LOG4J", CISA_FIXTURE)
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["catalog_version"], "2026.10.24")
        self.assertEqual(result["items"][0]["cve"], "CVE-2021-44228")
        self.assertEqual(result["items"][0]["ransomware"], "Known")

    def test_truncates_required_action_and_skips_non_dicts(self) -> None:
        result, _ = self.run_connector("cisa_kev", "CVE-2020-0001", CISA_FIXTURE)
        self.assertEqual(result["count"], 1)
        self.assertEqual(len(result["items"][0]["required_action"]), 500)

    def test_respects_limit(self) -> None:
        result, _ = self.run_connector("cisa_kev", "log4j", CISA_FIXTURE, limit=1)
        self.assertEqual(result["count"], 1)

    def test_rejects_non_object_payload(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("cisa_kev", "x", [])


OSV_FIXTURE = {
    "vulns": [
        {
            "id": "GHSA-35jh-r3h4-6jhm",
            "summary": "Command Injection in lodash",
            "aliases": ["CVE-2021-23337"],
            "published": "2021-02-15T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "7.2"}],
        },
        "skip-me",
    ]
}


class OsvFixtureTests(ConnectorFixtureTest):
    def test_parses_ecosystem_package_and_version(self) -> None:
        result, fake = self.run_connector("osv", "npm:lodash@4.17.20", OSV_FIXTURE)
        self.assertEqual(result["package"], "lodash")
        self.assertEqual(result["ecosystem"], "npm")
        self.assertEqual(result["version"], "4.17.20")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["aliases"], ["CVE-2021-23337"])
        self.assertEqual(fake.calls[0]["payload"]["package"], {"name": "lodash", "ecosystem": "npm"})
        self.assertEqual(fake.calls[0]["payload"]["version"], "4.17.20")

    def test_supports_pypi_and_scoped_packages(self) -> None:
        result, fake = self.run_connector("osv", "PyPI:requests", OSV_FIXTURE)
        self.assertEqual(result["package"], "requests")
        self.assertEqual(result["ecosystem"], "PyPI")
        self.assertIsNone(result["version"])
        self.assertNotIn("version", fake.calls[0]["payload"])

        scoped, _ = self.run_connector("osv", "npm:@scope/pkg@1.0", OSV_FIXTURE)
        self.assertEqual(scoped["package"], "@scope/pkg")
        self.assertEqual(scoped["version"], "1.0")

    def test_rejects_bad_queries(self) -> None:
        for query in ("lodash", "unknown:pkg", "npm:"):
            with self.subTest(query=query):
                with self.assertRaises(IntegrationError):
                    self.run_connector("osv", query, OSV_FIXTURE)

    def test_rejects_non_object_payload(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("osv", "npm:x", [])


GITHUB_FIXTURE = {
    "total_count": 42,
    "items": [
        {
            "full_name": "owner/repo",
            "html_url": "https://github.com/owner/repo",
            "description": "d" * 500,
            "stargazers_count": 1200,
            "forks_count": 34,
            "language": "Python",
            "updated_at": "2026-10-01T00:00:00Z",
            "topics": ["malware", "analysis"],
            "license": {"spdx_id": "MIT"},
        },
        {"full_name": "no/license", "license": None, "topics": None},
        "skip-me",
    ],
}


class GithubFixtureTests(ConnectorFixtureTest):
    def test_normalizes_repositories(self) -> None:
        result, fake = self.run_connector("github", "replatform", GITHUB_FIXTURE)
        self.assertEqual(result["total_results"], 42)
        self.assertEqual(result["count"], 2)
        first = result["items"][0]
        self.assertEqual(first["stars"], 1200)
        self.assertEqual(first["license"], "MIT")
        self.assertEqual(len(first["description"]), 400)
        self.assertEqual(result["items"][1]["license"], None)
        self.assertEqual(result["items"][1]["topics"], [])
        headers = fake.calls[0]["headers"]
        self.assertEqual(headers["Accept"], "application/vnd.github+json")
        self.assertEqual(headers["X-GitHub-Api-Version"], "2022-11-28")

    def test_rejects_long_query(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("github", "x" * 257, GITHUB_FIXTURE)

    def test_rejects_non_object_payload(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("github", "x", [])


HF_FIXTURE = [
    {
        "id": "gpt2",
        "downloads": 100,
        "likes": 5,
        "pipeline_tag": "text-generation",
        "tags": [f"t{index}" for index in range(15)],
        "lastModified": "2026-01-01T00:00:00Z",
    },
    "skip-me",
]


class HuggingFaceFixtureTests(ConnectorFixtureTest):
    def test_models_search_and_tag_limit(self) -> None:
        result, fake = self.run_connector("huggingface", "gpt2", HF_FIXTURE)
        self.assertEqual(result["kind"], "models")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["id"], "gpt2")
        self.assertEqual(len(result["items"][0]["tags"]), 10)
        self.assertIn("/api/models", fake.calls[0]["url"])

    def test_dataset_prefix_switches_endpoint(self) -> None:
        result, fake = self.run_connector("huggingface", "dataset:malware", HF_FIXTURE)
        self.assertEqual(result["kind"], "datasets")
        self.assertIn("/api/datasets", fake.calls[0]["url"])
        self.assertEqual(fake.calls[0]["params"]["search"], "malware")

    def test_dict_payload_items(self) -> None:
        result, _ = self.run_connector("huggingface", "x", {"items": HF_FIXTURE[:1]})
        self.assertEqual(result["count"], 1)

    def test_rejects_empty_dataset_term(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("huggingface", "dataset:", HF_FIXTURE)


VT_FIXTURE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 60, "harmless": 5},
            "reputation": -100,
            "tags": [f"tag{index}" for index in range(25)],
            "meaningful_name": "evil.exe",
            "sha256": SHA256,
            "size": 1234,
            "country": "US",
            "as_owner": "EXAMPLE",
            "type_description": "PE32 executable",
        }
    }
}


class VirusTotalFixtureTests(ConnectorFixtureTest):
    def test_file_indicator_uses_hash_endpoint(self) -> None:
        result, fake = self.run_connector("virustotal", SHA256, VT_FIXTURE)
        self.assertTrue(result["found"])
        self.assertEqual(result["kind"], "file")
        self.assertEqual(result["attributes"]["meaningful_name"], "evil.exe")
        self.assertEqual(len(result["attributes"]["tags"]), 20)
        self.assertEqual(result["items"], [result["attributes"]])
        self.assertIn(f"/api/v3/files/{SHA256}", fake.calls[0]["url"])

    def test_url_indicator_is_base64_encoded(self) -> None:
        url = "https://evil.test/payload"
        expected = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        _, fake = self.run_connector("virustotal", url, VT_FIXTURE)
        self.assertIn(f"/api/v3/urls/{expected}", fake.calls[0]["url"])

    def test_missing_indicator_is_not_found(self) -> None:
        result, _ = self.run_connector(
            "virustotal", "1.2.3.4", None, error="HTTP 404: not found"
        )
        self.assertFalse(result["found"])
        self.assertEqual(result["kind"], "ip")
        self.assertEqual(result["items"], [])

    def test_rejects_non_object_payload(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("virustotal", SHA256, [])


OTX_FIXTURE = {
    "pulse_info": {
        "count": 2,
        "pulses": [
            {"name": "pulse-one", "modified": "2026-01-01", "tags": [f"t{index}" for index in range(12)]},
            {"name": "pulse-two"},
            "skip-me",
        ],
    },
    "reputation": 0,
    "validation": [{"source": "whitelist", "name": "example"}],
}


class OtxFixtureTests(ConnectorFixtureTest):
    def test_ip_indicator_and_pulses(self) -> None:
        result, fake = self.run_connector("otx", "8.8.8.8", OTX_FIXTURE)
        self.assertTrue(result["found"])
        self.assertEqual(result["kind"], "ip")
        self.assertEqual(result["pulse_count"], 2)
        self.assertEqual(len(result["pulses"]), 2)
        self.assertEqual(len(result["pulses"][0]["tags"]), 10)
        self.assertIn("/IPv4/8.8.8.8/general", fake.calls[0]["url"])

    def test_missing_indicator_is_not_found(self) -> None:
        result, _ = self.run_connector("otx", "evil.test", None, error="HTTP 404: nope")
        self.assertFalse(result["found"])
        self.assertEqual(result["kind"], "domain")

    def test_rejects_invalid_indicator(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("otx", "not an indicator", OTX_FIXTURE)


MB_FIXTURE = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": SHA256,
            "sha1_hash": SHA1,
            "md5_hash": MD5,
            "signature": "AgentTesla",
            "file_type": "exe",
            "file_size": 123,
            "first_seen": "2026-01-01",
            "last_seen": "2026-01-02",
            "tags": ["stealer"],
            "delivery_method": "email",
        }
    ],
}


class MalwareBazaarFixtureTests(ConnectorFixtureTest):
    def test_normalizes_sample_metadata_without_download(self) -> None:
        result, fake = self.run_connector("malwarebazaar", SHA256, MB_FIXTURE)
        self.assertTrue(result["found"])
        self.assertFalse(result["sample_downloaded"])
        self.assertEqual(result["items"][0]["signature"], "AgentTesla")
        self.assertEqual(result["items"][0]["tags"], ["stealer"])
        self.assertEqual(fake.calls[0]["form"], {"query": "get_info", "hash": SHA256})

    def test_unknown_hash_is_not_found(self) -> None:
        result, _ = self.run_connector(
            "malwarebazaar", SHA256, {"query_status": "hash_not_found"}
        )
        self.assertFalse(result["found"])
        self.assertEqual(result["status"], "hash_not_found")
        self.assertFalse(result["sample_downloaded"])

    def test_requires_hash(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("malwarebazaar", "evil.test", MB_FIXTURE)

    def test_rejects_non_object_payload(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("malwarebazaar", SHA256, [])


ABUSE_FIXTURE = {
    "data": {
        "ipAddress": "1.2.3.4",
        "abuseConfidenceScore": 100,
        "countryCode": "RU",
        "usageType": "Data Center",
        "isp": "Example ISP",
        "domain": "example.test",
        "totalReports": 12,
        "numDistinctUsers": 5,
        "lastReportedAt": "2026-01-01T00:00:00Z",
        "isWhitelisted": False,
    }
}


class AbuseIpDbFixtureTests(ConnectorFixtureTest):
    def test_normalizes_reputation(self) -> None:
        result, fake = self.run_connector("abuseipdb", "1.2.3.4", ABUSE_FIXTURE)
        self.assertTrue(result["found"])
        self.assertEqual(result["attributes"]["abuse_confidence"], 100)
        self.assertEqual(result["attributes"]["distinct_users"], 5)
        self.assertEqual(fake.calls[0]["params"]["maxAgeInDays"], 90)

    def test_normalizes_ipv6(self) -> None:
        result, _ = self.run_connector("abuseipdb", "2001:0db8::1", ABUSE_FIXTURE)
        self.assertEqual(result["indicator"], "2001:db8::1")

    def test_rejects_invalid_ip(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("abuseipdb", "999.1.1.1", ABUSE_FIXTURE)

    def test_rejects_non_object_payload(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("abuseipdb", "1.2.3.4", [])


SHODAN_FIXTURE = {
    "ip_str": "1.2.3.4",
    "ports": [80, 443],
    "org": "Example",
    "isp": "Example ISP",
    "country_name": "United States",
    "city": "Ashburn",
    "os": "Linux",
    "hostnames": [f"h{index}" for index in range(25)],
    "domains": [f"d{index}" for index in range(25)],
    "vulns": {"CVE-2021-44228": {}, "CVE-2020-0001": {}},
    "last_update": "2026-01-01T00:00:00Z",
}


class ShodanFixtureTests(ConnectorFixtureTest):
    def test_requires_environment_key(self) -> None:
        with patch.dict(os.environ, {"SHODAN_API_KEY": ""}):
            with self.assertRaises(IntegrationError):
                self.run_connector("shodan", "1.2.3.4", SHODAN_FIXTURE)

    def test_normalizes_host_and_sorts_vulns(self) -> None:
        with patch.dict(os.environ, {"SHODAN_API_KEY": "test-placeholder"}):
            result, fake = self.run_connector("shodan", "1.2.3.4", SHODAN_FIXTURE)
        self.assertTrue(result["found"])
        self.assertEqual(result["attributes"]["vulns"], ["CVE-2020-0001", "CVE-2021-44228"])
        self.assertEqual(len(result["attributes"]["hostnames"]), 20)
        self.assertEqual(len(result["attributes"]["domains"]), 20)
        self.assertEqual(fake.calls[0]["params"]["key"], "test-placeholder")

    def test_missing_host_is_not_found(self) -> None:
        with patch.dict(os.environ, {"SHODAN_API_KEY": "test-placeholder"}):
            result, _ = self.run_connector(
                "shodan", "1.2.3.4", None, error="HTTP 404: no host"
            )
        self.assertFalse(result["found"])

    def test_rejects_non_object_payload(self) -> None:
        with patch.dict(os.environ, {"SHODAN_API_KEY": "test-placeholder"}):
            with self.assertRaises(IntegrationError):
                self.run_connector("shodan", "1.2.3.4", [])


URLHAUS_URL_FIXTURE = {
    "query_status": "ok",
    "url": "https://evil.test/payload.exe",
    "url_status": "online",
    "host": "evil.test",
    "date_added": "2026-01-01",
    "threat": "malware_download",
    "tags": ["exe"],
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
    "payloads": [
        {
            "response_sha256": SHA256,
            "response_md5": MD5,
            "file_type": "exe",
            "response_size": 123,
            "signature": "AgentTesla",
            "firstseen": "2026-01-01",
        }
    ],
}

URLHAUS_FILE_FIXTURE = {
    "query_status": "ok",
    "sha256_hash": SHA256,
    "md5_hash": MD5,
    "file_type": "exe",
    "file_size": 123,
    "signature": "AgentTesla",
    "firstseen": "2026-01-01",
    "lastseen": "2026-01-02",
    "urlhaus_download": "https://urlhaus.abuse.ch/downloads/1/",
    "url_count": 3,
}

URLHAUS_HOST_FIXTURE = {
    "query_staus": "ok",
    "host": "evil.test",
    "firstseen": "2026-01-01",
    "url_count": 2,
    "blacklists": {"spamhaus_dbl": "not listed"},
    "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.test/",
    "urls": [
        {
            "url": "https://evil.test/a",
            "url_status": "online",
            "date_added": "2026-01-01",
            "threat": "malware_download",
            "tags": ["a"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/2/",
        }
    ],
}


class UrlhausFixtureTests(ConnectorFixtureTest):
    def test_url_indicator(self) -> None:
        result, fake = self.run_connector(
            "urlhaus", "https://evil.test/payload.exe", URLHAUS_URL_FIXTURE
        )
        self.assertTrue(result["found"])
        self.assertEqual(result["kind"], "url")
        self.assertEqual(result["attributes"]["status"], "online")
        self.assertEqual(result["attributes"]["payloads"][0]["sha256"], SHA256)
        self.assertFalse(result["sample_downloaded"])
        self.assertEqual(fake.calls[0]["form"], {"url": "https://evil.test/payload.exe"})

    def test_file_indicator_uses_sha256_form(self) -> None:
        result, fake = self.run_connector("urlhaus", SHA256, URLHAUS_FILE_FIXTURE)
        self.assertTrue(result["found"])
        self.assertEqual(fake.calls[0]["form"], {"sha256_hash": SHA256})
        self.assertEqual(result["attributes"]["url_count"], 3)

    def test_file_indicator_uses_md5_form(self) -> None:
        _, fake = self.run_connector("urlhaus", MD5, URLHAUS_FILE_FIXTURE)
        self.assertEqual(fake.calls[0]["form"], {"md5_hash": MD5})

    def test_sha1_is_rejected(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("urlhaus", SHA1, URLHAUS_FILE_FIXTURE)

    def test_host_indicator_accepts_typo_status_key(self) -> None:
        result, fake = self.run_connector("urlhaus", "evil.test", URLHAUS_HOST_FIXTURE)
        self.assertTrue(result["found"])
        self.assertEqual(result["kind"], "domain")
        self.assertEqual(result["attributes"]["blacklists"], {"spamhaus_dbl": "not listed"})
        self.assertEqual(result["count"], 1)
        self.assertEqual(fake.calls[0]["form"], {"host": "evil.test"})

    def test_no_results_is_not_found(self) -> None:
        result, _ = self.run_connector(
            "urlhaus", "evil.test", {"query_status": "no_results"}
        )
        self.assertFalse(result["found"])
        self.assertEqual(result["status"], "no_results")

    def test_rejects_non_object_payload(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("urlhaus", "evil.test", [])


THREATFOX_FIXTURE = {
    "query_status": "ok",
    "data": {
        "id": "1",
        "ioc": SHA256,
        "ioc_type": "sha256_hash",
        "threat_type": "payload",
        "malware": "win.agent_tesla",
        "malware_printable": "AgentTesla",
        "confidence_level": 90,
        "first_seen": "2026-01-01",
        "last_seen": "2026-01-02",
        "tags": [f"t{index}" for index in range(25)],
        "reference": "https://threatfox.abuse.ch/ioc/1/",
        "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla",
    },
}


class ThreatFoxFixtureTests(ConnectorFixtureTest):
    def test_file_indicator_wraps_single_object(self) -> None:
        result, fake = self.run_connector("threatfox", SHA256, THREATFOX_FIXTURE)
        self.assertTrue(result["found"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["malware_printable"], "AgentTesla")
        self.assertEqual(len(result["items"][0]["tags"]), 20)
        self.assertEqual(fake.calls[0]["payload"], {"query": "search_hash", "hash": SHA256})

    def test_ioc_indicator_uses_search_term(self) -> None:
        _, fake = self.run_connector("threatfox", "evil.test", THREATFOX_FIXTURE)
        self.assertEqual(
            fake.calls[0]["payload"],
            {"query": "search_ioc", "search_term": "evil.test", "exact_match": True},
        )

    def test_no_results_is_not_found(self) -> None:
        result, _ = self.run_connector(
            "threatfox", "evil.test", {"query_status": "no_result"}
        )
        self.assertFalse(result["found"])
        self.assertEqual(result["status"], "no_result")

    def test_rejects_non_object_payload(self) -> None:
        with self.assertRaises(IntegrationError):
            self.run_connector("threatfox", "evil.test", [])


class LookupContractTests(unittest.TestCase):
    def test_network_is_denied_by_default(self) -> None:
        with self.assertRaises(IntegrationError) as context:
            connectors.lookup("nvd", "log4j")
        self.assertIn("معطّلة", str(context.exception))

    def test_lookup_sets_safety_defaults(self) -> None:
        fake = FakeClient(NVD_FIXTURE)
        with patch.object(connectors, "_client", return_value=fake), patch.object(
            connectors, "_auth_headers", return_value={}
        ):
            result = connectors.lookup("nvd", "log4j", limit=999, allow_network=True)
        self.assertEqual(result["connector"], "nvd")
        self.assertTrue(result["read_only"])
        self.assertFalse(result["sample_upload"])
        self.assertEqual(fake.calls[0]["params"]["resultsPerPage"], 25)

    def test_lookup_rejects_empty_and_oversized_queries(self) -> None:
        for query in ("", "   ", "x" * 513, "bad\x01query"):
            with self.subTest(query=query[:20]):
                with self.assertRaises(IntegrationError):
                    connectors.lookup("nvd", query, allow_network=True)

    def test_lookup_rejects_unknown_connector(self) -> None:
        with self.assertRaises(KeyError):
            connectors.lookup("no-such-connector", "x", allow_network=True)


if __name__ == "__main__":
    unittest.main()
