"""موصلات قراءة فقط لواجهات API المهنية.

كل موصل:
- لا يرفع عيّنات ولا ملفات؛ يرسل استعلاماً/مؤشراً نصياً فقط.
- يستخدم HTTPS ومضيفاً مقيّداً وسقف استجابة.
- يقرأ المفتاح من متغير بيئة، ولا يكتبه في السجلات أو النتائج.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import socket
import ssl
import urllib.parse

from ..core.config import load_config
from .catalog import Connector, get_connector
from .http import IntegrationError, SafeHTTPClient, _ssl_context

MAX_QUERY = 512
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "crates": "crates.io",
    "crates.io": "crates.io",
    "packagist": "Packagist",
    "rubygems": "RubyGems",
    "hex": "Hex",
    "pub": "Pub",
    "swift": "SwiftURL",
}


def _integration_cfg() -> dict:
    value = load_config().get("integrations", {})
    return value if isinstance(value, dict) else {}


def _network_allowed(allow_network: bool) -> None:
    if allow_network:
        return
    if not bool(_integration_cfg().get("enabled", False)):
        raise IntegrationError(
            "التكاملات الخارجية معطّلة. فعّل integrations.enabled في config.json "
            "أو استخدم --yes للسماح بالشبكة صراحةً."
        )


def _client(connector: Connector) -> SafeHTTPClient:
    cfg = _integration_cfg()
    try:
        timeout = float(cfg.get("timeout", 20))
    except (TypeError, ValueError):
        timeout = 20.0
    try:
        global_mb = int(cfg.get("max_response_mb", 8))
    except (TypeError, ValueError):
        global_mb = 8
    max_mb = max(1, min(int(connector.max_response_mb), global_mb, 64))
    return SafeHTTPClient(
        {connector.host}, timeout=timeout, max_bytes=max_mb * 1024 * 1024
    )


def _auth_headers(connector: Connector) -> dict:
    if not connector.auth_env:
        return {}
    value = os.environ.get(connector.auth_env, "").strip()
    if not value:
        if connector.keyless:
            return {}
        raise IntegrationError(
            f"الموصل {connector.id} يتطلب متغير البيئة {connector.auth_env}."
        )
    if not connector.auth_header:
        return {}
    return {connector.auth_header: f"{connector.auth_prefix}{value}"}


def _clean_query(query: str) -> str:
    text = str(query or "").strip()
    if not text:
        raise IntegrationError("الاستعلام فارغ.")
    if len(text) > MAX_QUERY:
        raise IntegrationError(f"الاستعلام طويل جداً (الحد {MAX_QUERY} حرفاً).")
    if any(ord(char) < 32 for char in text):
        raise IntegrationError("الاستعلام يحتوي محارف تحكم غير مسموحة.")
    return text


def _indicator_kind(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if _HASH_RE.fullmatch(value):
        return "file"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        return "ip"
    if _DOMAIN_RE.fullmatch(value):
        return "domain"
    raise IntegrationError(
        "المؤشر يجب أن يكون تجزئة MD5/SHA1/SHA256، أو IP، أو نطاقاً، أو رابطاً."
    )


def _valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise IntegrationError("عنوان IP غير صالح.") from exc


def _cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if isinstance(entries, list) and entries:
            entry = entries[0] if isinstance(entries[0], dict) else {}
            data = entry.get("cvssData") or {}
            return data.get("baseScore"), (
                data.get("baseSeverity") or entry.get("baseSeverity")
            )
    return None, None


def _nvd(connector: Connector, query: str, limit: int) -> dict:
    client = _client(connector)
    data = client.get_json(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"keywordSearch": query, "resultsPerPage": limit},
        headers=_auth_headers(connector),
    )
    if not isinstance(data, dict):
        raise IntegrationError("استجابة NVD غير متوقعة.")
    items: list[dict] = []
    for wrapper in (data.get("vulnerabilities") or [])[:limit]:
        cve = wrapper.get("cve") or {}
        descriptions = cve.get("descriptions") or []
        description = next(
            (
                str(item.get("value") or "")
                for item in descriptions
                if isinstance(item, dict) and item.get("lang") == "en"
            ),
            "",
        )
        score, severity = _cvss(cve.get("metrics") or {})
        items.append(
            {
                "id": cve.get("id"),
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "cvss": score,
                "severity": severity,
                "description": description[:600],
                "references": len(cve.get("references") or []),
            }
        )
    return {
        "count": len(items),
        "total_results": data.get("totalResults"),
        "items": items,
    }


def _cisa_kev(connector: Connector, query: str, limit: int) -> dict:
    client = _client(connector)
    data = client.get_json(
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json",
        headers=_auth_headers(connector),
    )
    if not isinstance(data, dict):
        raise IntegrationError("استجابة CISA KEV غير متوقعة.")
    needle = query.casefold()
    fields = (
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "shortDescription",
        "requiredAction",
    )
    items: list[dict] = []
    for item in data.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        haystack = " ".join(str(item.get(field) or "") for field in fields).casefold()
        if needle not in haystack:
            continue
        items.append(
            {
                "cve": item.get("cveID"),
                "vendor": item.get("vendorProject"),
                "product": item.get("product"),
                "name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"),
                "due_date": item.get("dueDate"),
                "ransomware": item.get("knownRansomwareCampaignUse"),
                "required_action": (item.get("requiredAction") or "")[:500],
            }
        )
        if len(items) >= limit:
            break
    return {
        "count": len(items),
        "catalog_version": data.get("catalogVersion"),
        "date_released": data.get("dateReleased"),
        "items": items,
    }


def _osv(connector: Connector, query: str, limit: int) -> dict:
    ecosystem_key, separator, rest = query.partition(":")
    if not separator or ecosystem_key.casefold() not in _ECOSYSTEMS:
        raise IntegrationError(
            "صيغة OSV: ecosystem:package@version — مثال: npm:lodash@4.17.20 "
            "أو PyPI:requests@2.31.0."
        )
    ecosystem = _ECOSYSTEMS[ecosystem_key.casefold()]
    package = rest.strip()
    version = ""
    split_at = package.find("@", 1 if package.startswith("@") else 0)
    if split_at > 0:
        package, version = package[:split_at], package[split_at + 1 :]
    if not package:
        raise IntegrationError("اسم الحزمة مطلوب بعد ecosystem:.")
    body: dict = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        body["version"] = version
    client = _client(connector)
    data = client.post_json(
        "https://api.osv.dev/v1/query", payload=body, headers=_auth_headers(connector)
    )
    if not isinstance(data, dict):
        raise IntegrationError("استجابة OSV غير متوقعة.")
    items = []
    for vuln in (data.get("vulns") or [])[:limit]:
        if not isinstance(vuln, dict):
            continue
        items.append(
            {
                "id": vuln.get("id"),
                "summary": (vuln.get("summary") or "")[:500],
                "aliases": vuln.get("aliases") or [],
                "published": vuln.get("published"),
                "modified": vuln.get("modified"),
                "severity": vuln.get("severity") or [],
            }
        )
    return {
        "package": package,
        "ecosystem": ecosystem,
        "version": version or None,
        "count": len(items),
        "items": items,
    }


def _github(connector: Connector, query: str, limit: int) -> dict:
    if len(query) > 256:
        raise IntegrationError("استعلام GitHub طويل جداً (الحد 256 حرفاً).")
    headers = _auth_headers(connector)
    headers.setdefault("Accept", "application/vnd.github+json")
    headers.setdefault("X-GitHub-Api-Version", "2022-11-28")
    client = _client(connector)
    data = client.get_json(
        "https://api.github.com/search/repositories",
        params={
            "q": query,
            "per_page": limit,
            "sort": "stars",
            "order": "desc",
        },
        headers=headers,
    )
    if not isinstance(data, dict):
        raise IntegrationError("استجابة GitHub غير متوقعة.")
    items = []
    for repo in (data.get("items") or [])[:limit]:
        if not isinstance(repo, dict):
            continue
        license_info = repo.get("license") or {}
        items.append(
            {
                "full_name": repo.get("full_name"),
                "url": repo.get("html_url"),
                "description": (repo.get("description") or "")[:400],
                "stars": repo.get("stargazers_count"),
                "forks": repo.get("forks_count"),
                "language": repo.get("language"),
                "updated_at": repo.get("updated_at"),
                "topics": repo.get("topics") or [],
                "license": license_info.get("spdx_id")
                if isinstance(license_info, dict)
                else None,
            }
        )
    return {"count": len(items), "total_results": data.get("total_count"), "items": items}


def _huggingface(connector: Connector, query: str, limit: int) -> dict:
    kind = "datasets" if query.casefold().startswith("dataset:") else "models"
    term = query.split(":", 1)[1].strip() if kind == "datasets" else query
    if not term:
        raise IntegrationError("ابحث عن نموذج أو استخدم dataset:اسم.")
    client = _client(connector)
    data = client.get_json(
        f"https://huggingface.co/api/{kind}",
        params={
            "search": term,
            "limit": limit,
            "sort": "downloads",
            "direction": -1,
        },
        headers=_auth_headers(connector),
    )
    if isinstance(data, dict):
        raw_items = data.get("items") or data.get(kind) or []
    else:
        raw_items = data or []
    items = []
    for item in list(raw_items)[:limit]:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "id": item.get("id") or item.get("modelId"),
                "downloads": item.get("downloads"),
                "likes": item.get("likes"),
                "pipeline_tag": item.get("pipeline_tag"),
                "tags": (item.get("tags") or [])[:10],
                "updated_at": item.get("lastModified"),
            }
        )
    return {"kind": kind, "count": len(items), "items": items}


def _virustotal(connector: Connector, query: str, limit: int) -> dict:
    kind = _indicator_kind(query)
    if kind == "file":
        endpoint = f"/api/v3/files/{query}"
    elif kind == "ip":
        endpoint = f"/api/v3/ip_addresses/{_valid_ip(query)}"
    elif kind == "domain":
        endpoint = f"/api/v3/domains/{query}"
    else:
        url_id = base64.urlsafe_b64encode(query.encode("utf-8")).decode().rstrip("=")
        endpoint = f"/api/v3/urls/{url_id}"
    client = _client(connector)
    try:
        data = client.get_json(
            f"https://www.virustotal.com{endpoint}", headers=_auth_headers(connector)
        )
    except IntegrationError as exc:
        if "HTTP 404" in str(exc):
            return {"found": False, "kind": kind, "indicator": query, "items": []}
        raise
    if not isinstance(data, dict):
        raise IntegrationError("استجابة VirusTotal غير متوقعة.")
    attributes = (data.get("data") or {}).get("attributes") or {}
    summary = {
        "last_analysis_stats": attributes.get("last_analysis_stats") or {},
        "reputation": attributes.get("reputation"),
        "tags": (attributes.get("tags") or [])[:20],
    }
    for key in (
        "meaningful_name",
        "type_description",
        "size",
        "sha256",
        "md5",
        "sha1",
        "country",
        "as_owner",
        "network",
        "url",
        "last_final_url",
        "title",
        "last_analysis_date",
    ):
        if attributes.get(key) is not None:
            summary[key] = attributes[key]
    return {
        "found": True,
        "kind": kind,
        "indicator": query,
        "attributes": summary,
        "items": [summary],
    }


def _otx(connector: Connector, query: str, limit: int) -> dict:
    kind = _indicator_kind(query)
    type_map = {"file": "file", "ip": "IPv4", "domain": "domain", "url": "URL"}
    indicator_type = type_map[kind]
    quoted = urllib.parse.quote(query, safe="")
    client = _client(connector)
    try:
        data = client.get_json(
            f"https://otx.alienvault.com/api/v1/indicators/"
            f"{indicator_type}/{quoted}/general",
            headers=_auth_headers(connector),
        )
    except IntegrationError as exc:
        if "HTTP 404" in str(exc):
            return {"found": False, "kind": kind, "indicator": query, "items": []}
        raise
    if not isinstance(data, dict):
        raise IntegrationError("استجابة OTX غير متوقعة.")
    pulse_info = data.get("pulse_info") or {}
    pulses = []
    for pulse in (pulse_info.get("pulses") or [])[:limit]:
        if isinstance(pulse, dict):
            pulses.append(
                {
                    "name": pulse.get("name"),
                    "modified": pulse.get("modified"),
                    "tags": (pulse.get("tags") or [])[:10],
                }
            )
    return {
        "found": True,
        "kind": kind,
        "indicator": query,
        "pulse_count": pulse_info.get("count"),
        "pulses": pulses,
        "reputation": data.get("reputation"),
        "validation": data.get("validation"),
        "items": pulses,
    }


def _malwarebazaar(connector: Connector, query: str, limit: int) -> dict:
    if not _HASH_RE.fullmatch(query):
        raise IntegrationError("MalwareBazaar يتطلب تجزئة MD5/SHA1/SHA256.")
    client = _client(connector)
    data = client.post_json(
        "https://mb-api.abuse.ch/api/v1/",
        form={"query": "get_info", "hash": query},
        headers=_auth_headers(connector),
    )
    if not isinstance(data, dict):
        raise IntegrationError("استجابة MalwareBazaar غير متوقعة.")
    status = str(data.get("query_status") or "")
    if status and status != "ok":
        return {
            "found": False,
            "status": status,
            "indicator": query,
            "items": [],
            "sample_downloaded": False,
        }
    items = []
    for item in (data.get("data") or [])[:limit]:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "sha256": item.get("sha256_hash"),
                "sha1": item.get("sha1_hash"),
                "md5": item.get("md5_hash"),
                "signature": item.get("signature"),
                "file_type": item.get("file_type"),
                "file_size": item.get("file_size"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "tags": item.get("tags") or [],
                "delivery_method": item.get("delivery_method"),
            }
        )
    return {
        "found": bool(items),
        "status": status or "ok",
        "count": len(items),
        "items": items,
        "sample_downloaded": False,
    }


def _abuseipdb(connector: Connector, query: str, limit: int) -> dict:
    ip = _valid_ip(query)
    client = _client(connector)
    data = client.get_json(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers=_auth_headers(connector),
    )
    if not isinstance(data, dict):
        raise IntegrationError("استجابة AbuseIPDB غير متوقعة.")
    item = data.get("data") or {}
    summary = {
        "ip": item.get("ipAddress") or ip,
        "abuse_confidence": item.get("abuseConfidenceScore"),
        "country": item.get("countryCode"),
        "usage_type": item.get("usageType"),
        "isp": item.get("isp"),
        "domain": item.get("domain"),
        "total_reports": item.get("totalReports"),
        "distinct_users": item.get("numDistinctUsers"),
        "last_reported": item.get("lastReportedAt"),
        "whitelisted": item.get("isWhitelisted"),
    }
    return {"found": True, "indicator": ip, "attributes": summary, "items": [summary]}


def _shodan(connector: Connector, query: str, limit: int) -> dict:
    ip = _valid_ip(query)
    key = os.environ.get(connector.auth_env or "", "").strip()
    if not key:
        raise IntegrationError(
            f"الموصل {connector.id} يتطلب متغير البيئة {connector.auth_env}."
        )
    client = _client(connector)
    try:
        data = client.get_json(
            f"https://api.shodan.io/shodan/host/{ip}", params={"key": key}
        )
    except IntegrationError as exc:
        if "HTTP 404" in str(exc):
            return {"found": False, "indicator": ip, "items": []}
        raise
    if not isinstance(data, dict):
        raise IntegrationError("استجابة Shodan غير متوقعة.")
    summary = {
        "ip": data.get("ip_str") or ip,
        "ports": data.get("ports") or [],
        "org": data.get("org"),
        "isp": data.get("isp"),
        "country": data.get("country_name"),
        "city": data.get("city"),
        "os": data.get("os"),
        "hostnames": (data.get("hostnames") or [])[:20],
        "domains": (data.get("domains") or [])[:20],
        "vulns": sorted((data.get("vulns") or {}).keys())[:50],
        "last_update": data.get("last_update"),
    }
    return {"found": True, "indicator": ip, "attributes": summary, "items": [summary]}


def _urlhaus(connector: Connector, query: str, limit: int) -> dict:
    kind = _indicator_kind(query)
    headers = _auth_headers(connector)
    client = _client(connector)
    if kind == "url":
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        form = {"url": query}
    elif kind == "file":
        if len(query) == 40:
            raise IntegrationError(
                "URLhaus payload يدعم MD5 (32) أو SHA256 (64) فقط، وليس SHA1."
            )
        endpoint = "https://urlhaus-api.abuse.ch/v1/payload/"
        form = {"sha256_hash": query} if len(query) == 64 else {"md5_hash": query}
    else:
        endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
        form = {"host": query}
    data = client.post_json(endpoint, form=form, headers=headers)
    if not isinstance(data, dict):
        raise IntegrationError("استجابة URLhaus غير متوقعة.")
    status = str(data.get("query_status") or data.get("query_staus") or "")
    if status not in ("ok",):
        return {
            "found": False,
            "status": status or "no_results",
            "kind": kind,
            "indicator": query,
            "items": [],
            "sample_downloaded": False,
        }

    if kind == "url":
        payloads = []
        for item in (data.get("payloads") or [])[:limit]:
            if isinstance(item, dict):
                payloads.append(
                    {
                        "sha256": item.get("response_sha256"),
                        "md5": item.get("response_md5"),
                        "file_type": item.get("file_type"),
                        "size": item.get("response_size"),
                        "signature": item.get("signature"),
                        "first_seen": item.get("firstseen"),
                    }
                )
        item = {
            "url": data.get("url") or query,
            "status": data.get("url_status"),
            "host": data.get("host"),
            "date_added": data.get("date_added"),
            "threat": data.get("threat"),
            "tags": (data.get("tags") or [])[:20],
            "reference": data.get("urlhaus_reference"),
            "payloads": payloads,
        }
        return {
            "found": True,
            "kind": kind,
            "indicator": query,
            "attributes": item,
            "items": [item],
            "sample_downloaded": False,
        }

    if kind == "file":
        item = {
            "sha256": data.get("sha256_hash"),
            "md5": data.get("md5_hash"),
            "file_type": data.get("file_type"),
            "size": data.get("file_size"),
            "signature": data.get("signature"),
            "first_seen": data.get("firstseen"),
            "last_seen": data.get("lastseen"),
            "reference": data.get("urlhaus_download"),
            "url_count": data.get("url_count"),
        }
        return {
            "found": True,
            "kind": kind,
            "indicator": query,
            "attributes": item,
            "items": [item],
            "sample_downloaded": False,
        }

    urls = []
    for item in (data.get("urls") or [])[:limit]:
        if isinstance(item, dict):
            urls.append(
                {
                    "url": item.get("url"),
                    "status": item.get("url_status"),
                    "date_added": item.get("date_added"),
                    "threat": item.get("threat"),
                    "tags": (item.get("tags") or [])[:10],
                    "reference": item.get("urlhaus_reference"),
                }
            )
    summary = {
        "host": data.get("host") or query,
        "first_seen": data.get("firstseen"),
        "url_count": data.get("url_count"),
        "blacklists": data.get("blacklists") or {},
        "reference": data.get("urlhaus_reference"),
    }
    return {
        "found": True,
        "kind": kind,
        "indicator": query,
        "attributes": summary,
        "count": len(urls),
        "items": urls,
        "sample_downloaded": False,
    }


def _threatfox(connector: Connector, query: str, limit: int) -> dict:
    kind = _indicator_kind(query)
    headers = _auth_headers(connector)
    client = _client(connector)
    if kind == "file":
        payload = {"query": "search_hash", "hash": query}
    else:
        payload = {"query": "search_ioc", "search_term": query, "exact_match": True}
    data = client.post_json(
        "https://threatfox-api.abuse.ch/api/v1/", payload=payload, headers=headers
    )
    if not isinstance(data, dict):
        raise IntegrationError("استجابة ThreatFox غير متوقعة.")
    status = str(data.get("query_status") or "")
    if status != "ok":
        return {
            "found": False,
            "status": status or "no_results",
            "kind": kind,
            "indicator": query,
            "items": [],
            "sample_downloaded": False,
        }
    raw_items = data.get("data") or []
    if isinstance(raw_items, dict):
        raw_items = [raw_items]
    items = []
    for item in list(raw_items)[:limit]:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "id": item.get("id"),
                "ioc": item.get("ioc"),
                "ioc_type": item.get("ioc_type"),
                "threat_type": item.get("threat_type"),
                "malware": item.get("malware"),
                "malware_printable": item.get("malware_printable"),
                "confidence_level": item.get("confidence_level"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "tags": (item.get("tags") or [])[:20],
                "reference": item.get("reference"),
                "malpedia": item.get("malware_malpedia"),
            }
        )
    return {
        "found": bool(items),
        "status": status,
        "kind": kind,
        "indicator": query,
        "count": len(items),
        "items": items,
        "sample_downloaded": False,
    }


_LOOKUPS = {
    "nvd": _nvd,
    "cisa_kev": _cisa_kev,
    "osv": _osv,
    "github": _github,
    "huggingface": _huggingface,
    "virustotal": _virustotal,
    "otx": _otx,
    "malwarebazaar": _malwarebazaar,
    "abuseipdb": _abuseipdb,
    "shodan": _shodan,
    "urlhaus": _urlhaus,
    "threatfox": _threatfox,
}


def lookup(
    connector_id: str,
    query: str,
    limit: int = 5,
    *,
    allow_network: bool = False,
) -> dict:
    """ينفّذ استعلاماً قراءة فقط. لا يرسل أي محتوى ملفات."""
    _network_allowed(allow_network)
    connector = get_connector(connector_id)
    if not connector.read_only or connector.sample_upload:
        raise IntegrationError("الموصل ليس للقراءة فقط — مرفوض.")
    text = _clean_query(query)
    try:
        bounded_limit = max(1, min(int(limit), 25))
    except (TypeError, ValueError):
        bounded_limit = 5
    handler = _LOOKUPS.get(connector.id)
    if handler is None:
        raise IntegrationError(f"الموصل {connector.id} غير منفّذ بعد.")
    result = handler(connector, text, bounded_limit)
    if not isinstance(result, dict):
        raise IntegrationError("استجابة الموصل غير متوقعة.")
    result.setdefault("connector", connector.id)
    result.setdefault("source", connector.docs)
    result.setdefault("read_only", True)
    result.setdefault("sample_upload", False)
    return result


def status(connector_id: str) -> dict:
    """حالة الإعداد دون أي اتصال شبكي."""
    connector = get_connector(connector_id)
    configured = True
    if connector.auth_env:
        configured = bool(os.environ.get(connector.auth_env, "").strip())
    return {
        "id": connector.id,
        "name": connector.name,
        "category": connector.category,
        "requires_key": connector.requires_key,
        "auth_env": connector.auth_env,
        "configured": configured,
        "keyless": connector.keyless,
        "read_only": connector.read_only,
        "sample_upload": connector.sample_upload,
        "host": connector.host,
        "docs": connector.docs,
    }


def probe(connector_id: str, *, allow_network: bool = False, timeout: float = 5.0) -> dict:
    """فحص TLS للمضيف فقط، دون إرسال طلب API أو أي بيانات."""
    _network_allowed(allow_network)
    connector = get_connector(connector_id)
    try:
        with socket.create_connection(
            (connector.host, 443), timeout=max(1.0, min(float(timeout), 15.0))
        ) as raw, _ssl_context().wrap_socket(
            raw, server_hostname=connector.host
        ) as tls:
            return {
                "id": connector.id,
                "host": connector.host,
                "connected": True,
                "tls": tls.version(),
            }
    except (OSError, ssl.SSLError) as exc:
        raise IntegrationError(
            f"فشل فحص اتصال {connector.host}: {exc}"
        ) from exc
