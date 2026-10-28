#!/usr/bin/env python3
"""يبني صفحة الهبوط ويتحقق منها قبل النشر.

القالب في `site/index.template.html` والإعداد في `site/config.json`.
البريد اختياري: إن تُرك فارغاً يستخدم الزر حساب GitHub الرسمي. إن مُلئ،
يجب أن يكون بريداً حقيقياً غير placeholder، وإلا يرفض البناء.

الاستخدام:
    python scripts/site_tool.py build
    python scripts/site_tool.py check
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
SITE_DIR = ROOT / "site"
CONFIG_PATH = SITE_DIR / "config.json"
TEMPLATE_PATH = SITE_DIR / "index.template.html"
OUTPUT_PATH = SITE_DIR / "index.html"

TOKEN_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

REQUIRED_KEYS = {
    "version",
    "contact_email",
    "github",
    "repo",
    "releases",
    "pricing_url",
    "one_pager_url",
    "readiness_url",
    "security_url",
    "deploy_url",
    "sla_url",
    "eula_url",
    "commercial_url",
    "sales_url",
    "trademark_url",
    "license_url",
}
URL_KEYS = REQUIRED_KEYS - {"version", "contact_email"}

PLACEHOLDER_MARKERS = (
    "example.com",
    "your-email",
    "you@",
    "placeholder",
    "replace_me",
    "[[",
    "{{",
    "<insert",
    "todo",
)

REQUIRED_TEXT = (
    "REPLATFORM",
    "الأسعار",
    "الأمان",
    "MIT",
    "615",
    "94%",
    "Sigstore",
    "Windows",
    'lang="ar"',
    'dir="rtl"',
    "Content-Security-Policy",
    'name="referrer" content="no-referrer"',
)

FORBIDDEN_ASSET_PATTERNS = (
    re.compile(r"<script[^>]+src=", re.IGNORECASE),
    re.compile(r"<link[^>]+rel=[\"']stylesheet", re.IGNORECASE),
    re.compile(r"@import", re.IGNORECASE),
    re.compile(r"url\(\s*[\"']?https?://", re.IGNORECASE),
    re.compile(r"<img[^>]+src=[\"']https?://", re.IGNORECASE),
)

HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.IGNORECASE)


class SiteError(RuntimeError):
    """خطأ في الإعداد أو القالب أو الصفحة الناتجة."""


def _load_config(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SiteError(f"ملف الإعداد غير موجود: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SiteError(f"JSON غير صالح في {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SiteError("site/config.json يجب أن يكون كائناً JSON")
    missing = sorted(REQUIRED_KEYS - payload.keys())
    if missing:
        raise SiteError(f"مفاتيح ناقصة في site/config.json: {', '.join(missing)}")
    return payload


def _validate_email(value: str) -> str:
    email = value.strip()
    if not EMAIL_RE.match(email):
        raise SiteError(f"contact_email غير صالح: {value!r}")
    lowered = email.lower()
    for marker in PLACEHOLDER_MARKERS:
        if marker in lowered:
            raise SiteError(
                f"contact_email يحتوي placeholder ({marker!r}). "
                "استخدم بريداً حقيقياً أو اتركه فارغاً."
            )
    return email


def _contact_values(config: dict[str, object]) -> dict[str, str]:
    github = str(config["github"]).strip()
    email_raw = str(config.get("contact_email", "")).strip()
    if email_raw:
        email = _validate_email(email_raw)
        escaped = html.escape(email, quote=True)
        subject = quote("طلب عرض REPLATFORM")
        href = f"mailto:{email}?subject={subject}"
        return {
            "CONTACT_HREF": html.escape(href, quote=True),
            "CONTACT_LABEL": "اطلب عرضاً",
            "CONTACT_NOTE": f"أو راسلنا مباشرة: {escaped}",
            "FOOTER_CONTACT": (
                f'للتواصل: <a href="mailto:{escaped}">{escaped}</a> · '
                f'<a href="{html.escape(github, quote=True)}">GitHub</a>'
            ),
        }
    return {
        "CONTACT_HREF": html.escape(github, quote=True),
        "CONTACT_LABEL": "اطلب عرضاً عبر GitHub",
        "CONTACT_NOTE": "نرد عبر GitHub خلال أيام العمل. لا تُرسل عيّنات أو أسراراً.",
        "FOOTER_CONTACT": f'للتواصل: <a href="{html.escape(github, quote=True)}">GitHub</a>',
    }


def render() -> str:
    config = _load_config(CONFIG_PATH)
    version = str(config["version"])
    if not VERSION_RE.match(version):
        raise SiteError(f"version غير صالح: {version!r}")
    for key in URL_KEYS:
        value = str(config[key]).strip()
        if not value.startswith("https://"):
            raise SiteError(f"{key} يجب أن يبدأ بـ https:// (وجد: {value!r})")

    values: dict[str, str] = {key.upper(): str(value) for key, value in config.items()}
    values["YEAR"] = str(datetime.now(timezone.utc).year)
    values.update(_contact_values(config))

    try:
        template = TEMPLATE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SiteError(f"القالب غير موجود: {TEMPLATE_PATH}") from exc

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in values:
            raise SiteError(f"رمز غير معروف في القالب: {key}")
        return values[key]

    output = TOKEN_RE.sub(replace, template)
    if "{{" in output or "}}" in output:
        raise SiteError("بقيت رموز {{...}} غير مستبدلة في الصفحة")
    return output


def _check_hrefs(document: str) -> None:
    for href in HREF_RE.findall(document):
        if href.startswith(("https://", "mailto:", "#")):
            continue
        if href.startswith("http://"):
            raise SiteError(f"رابط غير مشفّر: {href}")
        raise SiteError(f"رابط غير مسموح: {href}")


def check_document(document: str) -> None:
    lowered = document.lower()
    for marker in PLACEHOLDER_MARKERS:
        if marker in lowered:
            raise SiteError(f"الصفحة تحتوي placeholder: {marker!r}")
    for text in REQUIRED_TEXT:
        if text not in document:
            raise SiteError(f"الصفحة تفتقد نصاً مطلوباً: {text!r}")
    for pattern in FORBIDDEN_ASSET_PATTERNS:
        if pattern.search(document):
            raise SiteError(f"الصفحة تحمّل أصلاً خارجياً: {pattern.pattern}")
    if "http://" in lowered:
        raise SiteError("الصفحة تحتوي رابط http:// غير مشفّر")
    if "javascript:" in lowered:
        raise SiteError("الصفحة تحتوي javascript: غير مسموح")
    if len(document.encode("utf-8")) > 250_000:
        raise SiteError("حجم الصفحة يتجاوز 250KB")
    _check_hrefs(document)


def build() -> int:
    document = render()
    check_document(document)
    OUTPUT_PATH.write_text(document, encoding="utf-8", newline="")
    size = OUTPUT_PATH.stat().st_size
    print(f"OK site/index.html ({size:,} بايت)")
    return 0


def check() -> int:
    document = render()
    check_document(document)
    try:
        current = OUTPUT_PATH.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SiteError("site/index.html غير موجود؛ شغّل build أولاً") from exc
    if current.replace("\r\n", "\n") != document:
        raise SiteError(
            "site/index.html لا يطابق القالب/الإعداد. شغّل: python scripts/site_tool.py build"
        )
    print(f"OK site/index.html مطابق ({len(document):,} حرفاً)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="site_tool", description="بناء/فحص صفحة الهبوط")
    parser.add_argument("action", choices=("build", "check"))
    args = parser.parse_args(argv)
    try:
        return build() if args.action == "build" else check()
    except SiteError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
