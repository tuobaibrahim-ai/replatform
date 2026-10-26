"""فاحص أسرار محلي (بلا شبكة أو اعتماديات) — بوابة CI وفحص ما قبل النشر.

يفحص أنماط المفاتيح عالية الثقة، وإسنادات الأسرار العامة في الكود، ويقنّع
القيمة في الناتج كي لا يتحول الفحص نفسه إلى تسريب.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from ..core import stdio

ROOT = Path(__file__).resolve().parents[2]

RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("openai", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), "مفتاح OpenAI/متوافق"),
    ("github", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}"), "رمز GitHub"),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}"), "رمز GitHub PAT"),
    ("aws", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "مفتاح AWS"),
    ("google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "مفتاح Google API"),
    ("slack", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "رمز Slack"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "مفتاح خاص"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "JWT"),
)

GENERIC = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*[\"']([^\"']{12,})[\"']"
)
_GENERIC_ALLOW = ("example", "placeholder", "your-", "changeme", "redacted", "dummy", "sample")
_SKIP_DIRS = {
    ".git", ".venv", "dist", "build", "__pycache__", ".ruff_cache", ".pytest_cache",
    ".mypy_cache", "node_modules", "workspaces", "tools", "bin", "apk", "diffs",
    "scans", "sandbox", "tmp", "agents", ".secrets",
}
_SKIP_SUFFIXES = {
    ".zip", ".whl", ".exe", ".dll", ".jar", ".apk", ".png", ".jpg", ".jpeg",
    ".gif", ".ico", ".pdf", ".pyc", ".gz", ".idsig",
}
# ملفات الاختبار تحتوي قيماً وهمية مقصودة؛ تُستثنى من القاعدة العامة فقط.
_GENERIC_EXEMPT = ("tests/", "docs/", "CHANGELOG.md")


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 6:
        return "***"
    return value[:4] + "…" + value[-2:]


def _iter_files(root: Path):
    import os

    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(current) / name
            if path.suffix.lower() in _SKIP_SUFFIXES:
                continue
            yield path


def scan_text(text: str, relative: str) -> list[dict]:
    findings: list[dict] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if "nosecret" in line:
            continue
        for rule, pattern, label in RULES:
            match = pattern.search(line)
            if match:
                findings.append({
                    "path": relative, "line": number, "rule": rule,
                    "label": label, "match": _mask(match.group(0)),
                })
        if not any(relative.startswith(prefix) for prefix in _GENERIC_EXEMPT):
            match = GENERIC.search(line)
            if match:
                value = match.group(2).strip()
                lowered = value.lower()
                if value.startswith("<") or any(word in lowered for word in _GENERIC_ALLOW):
                    continue
                findings.append({
                    "path": relative, "line": number, "rule": "assignment",
                    "label": "إسناد سرّي محتمل", "match": _mask(value),
                })
    return findings


def scan(root: str | Path = ROOT) -> dict:
    base = Path(root).resolve()
    findings: list[dict] = []
    scanned = 0
    for path in _iter_files(base):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:8192]:
            continue
        scanned += 1
        relative = path.relative_to(base).as_posix()
        findings.extend(scan_text(data.decode("utf-8", errors="ignore"), relative))
    return {
        "ok": not findings,
        "scanned": scanned,
        "findings": findings,
        "count": len(findings),
    }


def main(argv: list[str] | None = None) -> int:
    stdio.configure()
    parser = argparse.ArgumentParser(prog="secretscan", description="فحص الأسرار قبل النشر")
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = scan(args.root)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif report["ok"]:
        print(f"✓ لا أسرار: فُحص {report['scanned']} ملفاً")
    else:
        for item in report["findings"]:
            print(f"✗ {item['path']}:{item['line']} — {item['label']} ({item['match']})")
        print(f"✗ {report['count']} نتيجة في {report['scanned']} ملفاً")
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
