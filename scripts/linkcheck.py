#!/usr/bin/env python3
"""يفحص الروابط النسبية في وثائق المشروع (Markdown).

يمنع أن تُشحن حزمة بيع أو وثيقة نشر بروابط مكسورة. يستثني المجلدات
المولّدة والأدوات الخارجية الكبيرة، ويتجاهل الروابط الخارجية والمراسَلات
والمراسي (#).

الاستخدام:
    python scripts/linkcheck.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# مجلدات لا تُفحص: مولّدة، أو أدوات خارجية ضخمة، أو بيانات تشغيل محلية.
SKIP_DIRS = {
    ".git",
    ".venv",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "agents",
    "bin",
    "diffs",
    "dist",
    "node_modules",
    "replatform.egg-info",
    "sandbox",
    "scans",
    "tools",
    "workspaces",
}

SKIP_PREFIXES = ("http://", "https://", "mailto:", "tel:", "data:", "#")

# [نص](هدف) أو [نص](هدف "عنوان")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def iter_docs() -> list[Path]:
    docs: list[Path] = []
    for path in ROOT.rglob("*.md"):
        relative = path.relative_to(ROOT)
        if set(relative.parts) & SKIP_DIRS:
            continue
        docs.append(path)
    return sorted(docs)


def check() -> list[str]:
    problems: list[str] = []
    for doc in iter_docs():
        text = doc.read_text(encoding="utf-8", errors="replace")
        for match in LINK_RE.finditer(text):
            target = match.group(1).strip()
            if target.startswith(SKIP_PREFIXES):
                continue
            path_part = target.split("#", 1)[0]
            if not path_part:
                continue
            if not (doc.parent / path_part).resolve().exists():
                problems.append(f"{doc.relative_to(ROOT)} -> {target}")
    return problems


def main() -> int:
    problems = check()
    if problems:
        print(f"FAIL: {len(problems)} رابط مكسور", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"OK روابط الوثائق سليمة ({len(iter_docs())} ملفاً)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
