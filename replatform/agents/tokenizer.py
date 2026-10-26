"""تقدير/حساب التوكنات — tiktoken اختياري، وإلا تقدير محافظ بالحروف."""

from __future__ import annotations

import importlib
import json
import math
from functools import lru_cache
from typing import Any

try:  # اختياري بالكامل؛ لا نكسر التشغيل إن لم يكن مثبتاً.
    tiktoken: Any = importlib.import_module("tiktoken")
except Exception:  # noqa: BLE001
    tiktoken = None


@lru_cache(maxsize=8)
def _encoding(name: str):
    if tiktoken is None:
        return None
    try:
        if name and name != "auto":
            return tiktoken.encoding_for_model(name)
    except Exception:  # noqa: BLE001
        pass
    for candidate in ("o200k_base", "cl100k_base"):
        try:
            return tiktoken.get_encoding(candidate)
        except Exception:  # noqa: BLE001
            continue
    return None


def count_text(text: str, model: str = "auto") -> int:
    if not text:
        return 0
    encoding = _encoding(model)
    if encoding is not None:
        try:
            return len(encoding.encode(text, disallowed_special=()))
        except Exception:  # noqa: BLE001
            pass
    return max(1, math.ceil(len(text) / 4))


def count_messages(messages: list[dict], model: str = "auto") -> int:
    """يحسب رسائل OpenAI (بما فيها tool_calls) مع هامش بنيوي بسيط."""
    total = 0
    for message in messages:
        total += 4
        total += count_text(str(message.get("role") or ""), model)
        total += count_text(str(message.get("content") or ""), model)
        for call in message.get("tool_calls") or []:
            total += 8 + count_text(
                json.dumps(call, ensure_ascii=False, separators=(",", ":")), model
            )
        if message.get("tool_call_id"):
            total += count_text(str(message["tool_call_id"]), model)
    return total


def engine_name(model: str = "auto") -> str:
    encoding = _encoding(model)
    if encoding is None:
        return "estimate:chars/4"
    return f"tiktoken:{encoding.name}"
