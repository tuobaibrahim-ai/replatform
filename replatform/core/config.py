"""الإعدادات العامة والمسارات."""

from __future__ import annotations

import copy
import json
import os
import shutil
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = ROOT / "tools"
WORKSPACES_DIR = ROOT / "workspaces"
PLUGINS_DIR = ROOT / "plugins"
CONFIG_PATH = ROOT / "config.json"

# نسخة مخطط الإعدادات. تُرفع مع كل تغيير غير متوافق في البنية.
# 1 = المخطط الضمني قبل إدخال الحقل config_version.
# 2 = حقل نسخة صريح + ضمان الافتراضات الآمنة للتكاملات.
CONFIG_VERSION = 2

DEFAULTS: dict = {
    "config_version": CONFIG_VERSION,
    "provider": {
        "type": "openai-compatible",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "api_key_env": "RE_API_KEY",
        "api_key": "",
        "timeout": 120,
        "temperature": 0.2,
        "retries": 2,
        "max_response_mb": 8,
    },
    "agent": {
        "max_steps": 8,
        "default_mode": "heuristic",
        "restrict_paths": True,
        "max_tool_calls": 8,
        "max_seconds": 300,
        "max_context_chars": 60000,
        "max_tool_result_chars": 6000,
        "context_chars": 3000,
        "tool_timeout": 120,
    },
    "analysis": {
        "max_file_mb": 1024,
        "strings_max": 300,
        "strings_max_mb": 512,
        "pe_max_mb": 512,
        "apk_max_mb": 512,
        "apk_uncompressed_max_mb": 2048,
        "apk_max_entries": 50000,
        "apk_max_ratio": 200,
        "apk_manifest_max_kb": 8192,
        "apk_decode_timeout": 300,
        "yara": True,
        "yara_max_mb": 512,
        "yara_timeout": 180,
        "disasm": True,
        "disasm_max_mb": 200,
        "disasm_deep": True,
        "ghidra_max_mb": 150,
        "ghidra_decompile": True,
        "ghidra_decompile_limit": 6,
        "bindiff_max_parse_mb": 256,
        "bindiff_max_apk_entries": 50000,
    },
    "web": {
        "host": "127.0.0.1",
        "port": 8765,
        "token": "",
        "token_env": "RE_WEB_TOKEN",
        "allowed_hosts": [],
        "allowed_roots": [],
    },
    "integrations": {
        "enabled": False,
        "agent_enabled": False,
        "timeout": 20,
        "max_response_mb": 8,
    },
    "ui": {
        "language": "ar",
    },
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


class ConfigMigrationError(RuntimeError):
    """فشل هجرة الإعدادات (نسخة أحدث، أو مسار هجرة غير معروف)."""


def config_version(data: dict) -> int:
    """نسخة المخطط في قاموس إعدادات؛ غياب الحقل يعني المخطط الضمني 1."""
    raw = data.get("config_version", 1)
    if isinstance(raw, bool):
        return 1
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 1


def _migrate_1_to_2(data: dict) -> tuple[dict, list[str]]:
    """1 → 2: توحيد الموضع القديم للمفاتيح، وضمان الافتراضات الآمنة.

    القاعدة: لا نحذف قيمة يضعها المستخدم؛ إن كان الموضع الجديد مشغولاً
    نحتفظ به ونذكر أن القديم أُهمل.
    """
    notes: list[str] = []
    legacy_key = data.pop("api_key", None)
    if legacy_key:
        provider = data.setdefault("provider", {})
        if isinstance(provider, dict) and not provider.get("api_key"):
            provider["api_key"] = legacy_key
            notes.append("نُقل api_key العلوي إلى provider.api_key")
        else:
            notes.append("أُهمل api_key العلوي لأن provider.api_key مضبوط مسبقاً")
    legacy_lang = data.pop("language", None)
    if legacy_lang:
        ui = data.setdefault("ui", {})
        if isinstance(ui, dict) and not ui.get("language"):
            ui["language"] = legacy_lang
            notes.append("نُقل language العلوي إلى ui.language")
        else:
            notes.append("أُهمل language العلوي لأن ui.language مضبوط مسبقاً")
    integrations = data.setdefault("integrations", {})
    if isinstance(integrations, dict):
        for key in ("enabled", "agent_enabled"):
            if key not in integrations:
                integrations[key] = False
                notes.append(f"ضُبط integrations.{key} على false (افتراضي آمن)")
    data["config_version"] = 2
    return data, notes


_MIGRATIONS: dict[int, Callable[[dict], tuple[dict, list[str]]]] = {
    1: _migrate_1_to_2,
}


def migrate_config(data: dict) -> tuple[dict, list[str]]:
    """يطبّق الهجرات تباعاً. يعيد (الإعدادات المهاجرة، الملاحظات).

    يرفض الإعدادات القادمة من إصدار أحدث بدل إتلافها بصمت.
    """
    version = config_version(data)
    if version > CONFIG_VERSION:
        raise ConfigMigrationError(
            f"config.json من إصدار أحدث ({version} > {CONFIG_VERSION}). "
            "حدّث REPLATFORM بدل الرجوع لإصدار أقدم."
        )
    migrated = copy.deepcopy(data)
    notes: list[str] = []
    while version < CONFIG_VERSION:
        step = _MIGRATIONS.get(version)
        if step is None:
            raise ConfigMigrationError(f"لا يوجد مسار هجرة من النسخة {version}")
        migrated, step_notes = step(migrated)
        notes.extend(step_notes)
        new_version = config_version(migrated)
        if new_version <= version:
            raise ConfigMigrationError(f"هجرة {version} لم ترفع نسخة المخطط")
        version = new_version
    return migrated, notes


def read_config_raw(path: Path | None = None) -> dict:
    """يقرأ الملف كما هو بلا دمج (لأغراض الهجرة والتشخيص)."""
    target = Path(path) if path is not None else CONFIG_PATH
    if not target.exists():
        return {}
    try:
        data = json.loads(target.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _backup_path(target: Path, version: int) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = target.with_name(f"{target.name}.v{version}.{stamp}.bak")
    counter = 1
    while candidate.exists():
        candidate = target.with_name(f"{target.name}.v{version}.{stamp}-{counter}.bak")
        counter += 1
    return candidate


def migrate_config_file(path: Path | None = None, dry_run: bool = False) -> dict:
    """يهاجر ملف الإعدادات على القرص مع نسخة احتياطية قبل الكتابة."""
    target = Path(path) if path is not None else CONFIG_PATH
    raw = read_config_raw(target)
    before = config_version(raw)
    if not raw:
        return {
            "ok": True,
            "changed": False,
            "from": before,
            "to": before,
            "path": str(target),
            "backup": None,
            "notes": ["لا يوجد config.json — ستُستخدم الافتراضات"],
        }
    migrated, notes = migrate_config(raw)
    changed = migrated != raw
    report = {
        "ok": True,
        "changed": changed,
        "from": before,
        "to": config_version(migrated),
        "path": str(target),
        "backup": None,
        "notes": notes,
        "dry_run": dry_run,
    }
    if not changed or dry_run:
        return report
    backup = _backup_path(target, before)
    shutil.copy2(target, backup)
    report["backup"] = str(backup)
    from . import util

    util.atomic_write_text(target, json.dumps(migrated, ensure_ascii=False, indent=2) + "\n")
    return report


def load_config() -> dict:
    data: dict = {}
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text("utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    return _merge(DEFAULTS, data)


def save_config(cfg: dict) -> None:
    from . import util

    util.atomic_write_text(
        CONFIG_PATH, json.dumps(cfg, ensure_ascii=False, indent=2)
    )


def api_key(cfg: dict) -> str:
    provider = cfg.get("provider", {})
    env_name = provider.get("api_key_env", "RE_API_KEY")
    return (
        os.environ.get("RE_API_KEY")
        or os.environ.get(env_name)
        or provider.get("api_key")
        or ""
    )


def mask_secret(value: str) -> str:
    if not value:
        return "(غير مضبوط)"
    if len(value) <= 8:
        return "****"
    return value[:4] + "…" + value[-4:]
