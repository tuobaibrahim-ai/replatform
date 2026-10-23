"""مقارنة قبول سريعة لوكيل REPLATFORM — بلا شبكة أو مفتاح (MockProvider)."""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from pathlib import Path

from ..agents import tokenizer
from ..agents.loop import compact_messages, run_agent
from ..agents.tools import configure, execute


def _case_path_guard(temp: Path) -> str:
    allowed = temp / "allowed.bin"
    outside = temp / "outside.bin"
    allowed.write_bytes(b"allowed")
    outside.write_bytes(b"secret")
    configure([allowed])
    try:
        denied = execute("hexdump", {"path": str(outside), "offset": 0})
        accepted = execute("hexdump", {"path": str(allowed), "offset": 0})
    finally:
        configure([])
    assert denied.get("error"), "المسار الخارجي لم يُرفض"
    assert accepted.get("dump"), "المسار المسموح لم يُقرأ"
    return "منع الخارج + قبول المسموح"


def _case_compaction(temp: Path) -> str:
    del temp
    messages: list[dict] = [
        {"role": "system", "content": "س" * 80},
        {"role": "user", "content": "م" * 80},
    ]
    for index in range(6):
        messages += [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": f"c{index}",
                    "type": "function",
                    "function": {"name": "hexdump", "arguments": "{}"},
                }],
            },
            {"role": "tool", "tool_call_id": f"c{index}", "content": "x" * 900},
        ]
    after = compact_messages(messages, 2200)
    assert after <= 2200, f"السياق لم يُضغط: {after}"
    assert any(message.get("tool_calls") for message in messages), "tool_calls ضاعت"
    return f"ضغط إلى {after} حرفاً"


def _case_timeout(temp: Path) -> str:
    del temp

    class Slow:
        model = "benchmark-slow"

        def chat(self, messages, tools=None):  # noqa: ARG002
            time.sleep(0.12)
            return {"content": "متأخر"}

    result = run_agent("مهلة", Slow(), max_steps=2, max_seconds=0.03)
    assert result["status"] == "timeout", result["status"]
    return "أوقف الوكيل عند المهلة"


def _case_usage(temp: Path) -> str:
    del temp

    class UsageProvider:
        model = "benchmark-usage"

        def chat(self, messages, tools=None):  # noqa: ARG002
            return {
                "content": "تم",
                "_usage": {
                    "prompt_tokens": 5,
                    "completion_tokens": 2,
                    "total_tokens": 7,
                },
            }

    result = run_agent("استهلاك", UsageProvider(), max_steps=1)
    assert result["usage"]["total_tokens"] == 7, result["usage"]
    assert result["context_tokens"] > 0, result["context_tokens"]
    assert result["tokenizer"], result["tokenizer"]
    return "تجميع usage + حساب السياق"


def _case_tool_budget(temp: Path) -> str:
    sample = temp / "loop.bin"
    sample.write_bytes(b"0123456789ABCDEF")

    class LoopProvider:
        model = "benchmark-loop"

        def chat(self, messages, tools=None):  # noqa: ARG002
            return {
                "content": None,
                "tool_calls": [{
                    "id": "c",
                    "type": "function",
                    "function": {
                        "name": "hexdump",
                        "arguments": json.dumps(
                            {"path": str(sample), "offset": 0, "length": 8}
                        ),
                    },
                }],
            }

    configure([sample])
    try:
        result = run_agent(
            "استدعِ الأداة دائماً", LoopProvider(),
            max_steps=2, max_tool_calls=1, max_seconds=5,
        )
    finally:
        configure([])
    assert result["status"] in ("max_steps", "max_tool_calls"), result["status"]
    assert len(result["steps"]) <= 2, len(result["steps"])
    return f"توقف عند {result['status']}"


CASES = (
    ("path_guard", _case_path_guard),
    ("compaction", _case_compaction),
    ("timeout", _case_timeout),
    ("usage/tokens", _case_usage),
    ("tool_budget", _case_tool_budget),
)


def run_benchmark() -> dict:
    temp = Path(tempfile.mkdtemp(prefix="re_bench_"))
    results = []
    started = time.monotonic()
    try:
        for name, case in CASES:
            case_started = time.monotonic()
            try:
                detail = case(temp)
                passed, error = True, ""
            except Exception as exc:  # noqa: BLE001
                passed, detail, error = False, "", f"{type(exc).__name__}: {exc}"
            results.append({
                "case": name,
                "ok": passed,
                "detail": detail,
                "error": error,
                "seconds": round(time.monotonic() - case_started, 2),
            })
    finally:
        shutil.rmtree(temp, ignore_errors=True)
    passed = sum(1 for result in results if result["ok"])
    return {
        "passed": passed,
        "total": len(results),
        "score": round(100 * passed / len(results), 1) if results else 0.0,
        "seconds": round(time.monotonic() - started, 2),
        "tokenizer": tokenizer.engine_name(),
        "cases": results,
    }
