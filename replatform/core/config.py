"""الإعدادات العامة والمسارات."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = ROOT / "tools"
WORKSPACES_DIR = ROOT / "workspaces"
PLUGINS_DIR = ROOT / "plugins"
CONFIG_PATH = ROOT / "config.json"

DEFAULTS: dict = {
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


def load_config() -> dict:
    data: dict = {}
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text("utf-8"))
        except (json.JSONDecodeError, OSError):
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
