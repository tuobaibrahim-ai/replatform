"""محلل PE: الأقسام، الاستيرادات، الحمايات، التوقيع، ومؤشرات أولية."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pefile

from ..core import util
from ..core.config import load_config
from . import Analyzer, Target

ARCH = {
    0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64",
    0x01C0: "ARM", 0x01C4: "ARMv7", 0x0200: "IA64",
}

INDICATORS = {
    "حقن عمليات": ["WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread",
                    "NtMapViewOfSection", "QueueUserAPC", "RtlCreateUserThread",
                    "SetWindowsHookExA", "SetWindowsHookExW"],
    "اتصال/تنزيل": ["InternetOpenUrlA", "InternetOpenUrlW", "URLDownloadToFileA",
                     "URLDownloadToFileW", "HttpSendRequestA", "HttpSendRequestW",
                     "WinHttpConnect", "InternetReadFile"],
    "ثبات/تسجيل": ["CreateServiceA", "CreateServiceW", "RegSetValueExA", "RegSetValueExW",
                    "SHSetValueA", "SHSetValueW", "RegCreateKeyExA", "RegCreateKeyExW"],
    "مكافحة تحليل": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                      "NtQueryInformationProcess", "OutputDebugStringA",
                      "OutputDebugStringW", "NtSetInformationThread"],
}


def _compile_time(stamp: int) -> str:
    try:
        return datetime.fromtimestamp(stamp, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
    except (OSError, OverflowError, ValueError):
        return "غير صالح"


def _parse(path: str) -> pefile.PE:
    try:
        limit_mb = int(load_config().get("analysis", {}).get("pe_max_mb", 512))
    except (TypeError, ValueError):
        limit_mb = 512
    size = Path(path).stat().st_size
    if size > limit_mb * 1024 * 1024:
        raise ValueError(
            f"حجم PE ({size / (1024 * 1024):.1f} MB) يتجاوز حد التحليل "
            f"({limit_mb} MB) — عدّل analysis.pe_max_mb."
        )
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories()
    return pe


def quick_summary(path: str) -> dict:
    """ملخص سريع لعرضه على وكلاء الذكاء الاصطناعي."""
    pe = _parse(path)
    try:
        arch = ARCH.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
        dllchar = pe.OPTIONAL_HEADER.DllCharacteristics
        imports = []
        functions = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="replace")
                count = len(entry.imports)
                functions += count
                imports.append({"dll": dll, "functions": count})
        sections = []
        for section in pe.sections:
            try:
                entropy = round(section.get_entropy(), 2)
            except Exception:  # noqa: BLE001
                entropy = 0.0
            sections.append({
                "name": section.Name.rstrip(b"\x00").decode(errors="replace"),
                "vsize": section.Misc_VirtualSize,
                "entropy": entropy,
            })
        return {
            "arch": arch,
            "entry_point": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}",
            "image_base": f"0x{pe.OPTIONAL_HEADER.ImageBase:X}",
            "protections": {
                "aslr": bool(dllchar & 0x40),
                "dep": bool(dllchar & 0x100),
                "cfg": bool(dllchar & 0x1000),
                "high_entropy_va": bool(dllchar & 0x20),
            },
            "dotnet": bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress),
            "compile_time": _compile_time(pe.FILE_HEADER.TimeDateStamp),
            "sections": sections,
            "imports": imports,
            "import_functions": functions,
        }
    finally:
        pe.close()


class PEAnalyzer(Analyzer):
    name = "pe"
    description = "تحليل بنية PE: المعمارية، الأقسام، الاستيرادات، الحمايات، التوقيع"

    def can_handle(self, target: Target) -> bool:
        return target.kind == "PE"

    def run(self, target: Target, ws) -> dict:  # noqa: ARG002
        summary = quick_summary(str(target.path))
        signature = util.authenticode(target.path)

        pe = _parse(str(target.path))
        try:
            hits: dict[str, list[str]] = {key: [] for key in INDICATORS}
            wanted = {fn: cat for cat, fns in INDICATORS.items() for fn in fns}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            fn = imp.name.decode(errors="replace")
                            if fn in wanted:
                                hits[wanted[fn]].append(fn)
        finally:
            pe.close()

        score = 0
        findings: list[str] = []
        if signature["status"] != "Valid":
            score += 1
            findings.append("غير موقّع أو توقيعه غير صالح (شائع في البناء المحلي)")
        max_entropy = max((s["entropy"] for s in summary["sections"]), default=0.0)
        if max_entropy >= 7.2:
            score += 2
            findings.append(f"إنتروبيا عالية ({max_entropy}) — احتمال ضغط/تشفير")
        if any(s["name"].upper().startswith("UPX") for s in summary["sections"]):
            score += 2
            findings.append("حزمة UPX")
        if len(hits["حقن عمليات"]) >= 2:
            score += 2
            findings.append("استدعاءات حقن عمليات: " + ", ".join(sorted(set(hits["حقن عمليات"]))[:5]))
        if hits["مكافحة تحليل"]:
            score += 1
            findings.append("مؤشرات مكافحة تحليل: " + ", ".join(sorted(set(hits["مكافحة تحليل"]))[:5]))

        verdict = "critical" if score >= 5 else ("warn" if score >= 2 else "info")
        return {
            "kind": "PE",
            "summary": summary,
            "signature": signature,
            "indicators": {k: sorted(set(v)) for k, v in hits.items() if v},
            "score": score,
            "verdict": verdict,
            "findings": findings,
        }
