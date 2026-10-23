"""سجل مهارات محلي للوكلاء.

المهارات ملفات Markdown موثوقة داخل مجلد `skills/` فقط. لا تُحمّل من الشبكة
ولا تُنفّذ؛ تُحقن كإرشادات منهجية في مطالبة الوكيل عند طلبها صراحةً.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..core.config import ROOT

SKILLS_DIR = ROOT / "skills"
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
MAX_SKILL_CHARS = 12_000
MAX_TOTAL_CHARS = 20_000
_REQUIRED = ("name", "title", "description", "category")


class SkillError(ValueError):
    """مهارة غير صالحة أو غير موجودة."""


@dataclass(frozen=True)
class Skill:
    name: str
    title: str
    description: str
    category: str
    tags: tuple[str, ...]
    source: str
    body: str
    path: Path


def _parse_front_matter(text: str, path: Path) -> Skill:
    if not text.startswith("---"):
        raise SkillError(f"{path.name}: ترويسة front matter مفقودة.")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise SkillError(f"{path.name}: front matter غير مكتمل.")
    meta: dict[str, str] = {}
    for raw_line in parts[1].splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(":")
        if not separator:
            raise SkillError(f"{path.name}: سطر front matter غير صالح: {line}")
        meta[key.strip().lower()] = value.strip().strip('"').strip("'")
    missing = [key for key in _REQUIRED if not meta.get(key)]
    if missing:
        raise SkillError(f"{path.name}: حقول ناقصة: {', '.join(missing)}")
    name = meta["name"].strip().lower()
    if not _NAME_RE.fullmatch(name):
        raise SkillError(f"{path.name}: اسم مهارة غير صالح: {name}")
    if name != path.stem.lower():
        raise SkillError(f"{path.name}: الاسم يجب أن يطابق اسم الملف.")
    body = parts[2].strip()
    if not body:
        raise SkillError(f"{path.name}: متن المهارة فارغ.")
    if len(body) > MAX_SKILL_CHARS:
        raise SkillError(f"{path.name}: المتن يتجاوز {MAX_SKILL_CHARS} حرفاً.")
    tags = tuple(
        tag.strip()
        for tag in meta.get("tags", "").split(",")
        if tag.strip()
    )
    return Skill(
        name=name,
        title=meta["title"],
        description=meta["description"],
        category=meta["category"],
        tags=tags,
        source=meta.get("source", ""),
        body=body,
        path=path,
    )


def load_skills() -> dict[str, Skill]:
    """يحمّل كل المهارات المحلية ويتحقق من صحتها وعدم تكرار الأسماء."""
    if not SKILLS_DIR.is_dir():
        return {}
    root = SKILLS_DIR.resolve()
    skills: dict[str, Skill] = {}
    for path in sorted(SKILLS_DIR.glob("*.md")):
        if path.is_symlink():
            raise SkillError(f"{path.name}: الروابط الرمزية غير مسموحة في المهارات.")
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            raise SkillError(f"{path.name}: خارج مجلد المهارات.")
        try:
            text = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise SkillError(f"{path.name}: تعذر القراءة: {exc}") from exc
        skill = _parse_front_matter(text, resolved)
        if skill.name in skills:
            raise SkillError(f"اسم مهارة مكرر: {skill.name}")
        skills[skill.name] = skill
    return skills


def get_skill(name: str) -> Skill:
    wanted = str(name or "").strip().lower()
    if not _NAME_RE.fullmatch(wanted):
        raise SkillError(f"اسم مهارة غير صالح: {name}")
    skill = load_skills().get(wanted)
    if skill is None:
        available = ", ".join(sorted(load_skills())) or "(لا توجد)"
        raise SkillError(f"مهارة غير موجودة: {wanted} — المتاح: {available}")
    return skill


def compose_skills(names: list[str] | tuple[str, ...], max_chars: int = MAX_TOTAL_CHARS) -> str:
    """يدمج مهارات مختارة في كتلة إرشادات واحدة مع سقف حجم."""
    if not names:
        return ""
    blocks: list[str] = []
    total = 0
    for name in names:
        skill = get_skill(name)
        block = f"## {skill.title} (`{skill.name}`)\n{skill.body}".strip()
        if total + len(block) > max_chars:
            blocks.append("…[بقيّة المهارات اقتُطعت لتوفير السياق]")
            break
        blocks.append(block)
        total += len(block) + 2
    return "\n\n".join(blocks)


def list_skills() -> list[dict]:
    return [
        {
            "name": skill.name,
            "title": skill.title,
            "description": skill.description,
            "category": skill.category,
            "tags": list(skill.tags),
            "source": skill.source,
        }
        for skill in load_skills().values()
    ]
