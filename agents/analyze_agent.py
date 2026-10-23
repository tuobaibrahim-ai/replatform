#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""وكيل تحليل جماعي عالي الأداء للملفات التنفيذية (PE / APK / ELF).

- يمسح مجلداً كاملاً أو ملفات محددة بعدد خيوط متوازٍ
- فحص التوقيع الرقمي يتم بدفعة واحدة عبر PowerShell (سريع وموثوق)
- يكتشف البرامج في مفاتيح التشغيل التلقائي (Run/RunOnce)
- يولد تقرير CSV + تقرير HTML ملوّن حسب درجة الخطورة

الاستخدام:
  python analyze_agent.py <مجلد> -o report.csv --html report.html --workers 8
  python analyze_agent.py file.exe            # تحليل ملف واحد
  python analyze_agent.py <مجلد> --die       # إرفاق نتيجة Detect It Easy (أبطأ)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import html
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    import pefile
except ImportError:
    print("المطلوب: pip install pefile", file=sys.stderr)
    sys.exit(1)

DEFAULT_EXTS = ".exe,.dll,.sys,.scr,.ocx,.cpl,.drv,.apk"

# مؤشرات استدلال تحليلي (ليست أحكاماً نهائية — للمراجعة اليدوية فقط)
INDICATORS = {
    "حقن_عمليات": [
        "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread",
        "NtMapViewOfSection", "QueueUserAPC", "RtlCreateUserThread",
        "SetWindowsHookExA", "SetWindowsHookExW", "NtUnmapViewOfSection",
    ],
    "تحميل_اتصال": [
        "InternetOpenUrlA", "InternetOpenUrlW", "URLDownloadToFileA",
        "URLDownloadToFileW", "HttpSendRequestA", "HttpSendRequestW",
        "WinHttpConnect", "InternetReadFile", "WSAStartup",
    ],
    "ثبات_تسطير": [
        "CreateServiceA", "CreateServiceW", "RegSetValueExA", "RegSetValueExW",
        "SHSetValueA", "SHSetValueW", "RegCreateKeyExA", "RegCreateKeyExW",
    ],
    "مكافحة_تحليل": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
        "NtSetInformationThread",
    ],
}

ARCH = {
    0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64",
    0x01C0: "ARM", 0x01C4: "ARMv7", 0x0200: "IA64",
}

AUTORUN_PATHS: dict[str, str] = {}

# خريطة حالات التوقيع من PowerShell -> قيم موحدة
SIG_MAP = {
    "Valid": "valid",
    "NotSigned": "unsigned",
    "HashMismatch": "tampered",
    "NotTrusted": "untrusted",
    "UnknownError": "unknown",
}


def load_autorun_paths() -> None:
    """يقرأ مفاتيح التشغيل التلقائي مرة واحدة ويحولها لمسارات منخفضة."""
    if os.name != "nt":
        return
    import winreg

    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hkey, subkey in roots:
        try:
            with winreg.OpenKey(hkey, subkey) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    if not isinstance(value, str):
                        continue
                    m = re.match(r'"?([^"]+?\.exe)"?', value)
                    if m:
                        AUTORUN_PATHS[os.path.abspath(m.group(1)).lower()] = name
        except OSError:
            continue


def batch_signature_status(paths: list[str], timeout: float = 180.0) -> dict[str, str]:
    """فحص توقيع جميع الملفات في استدعاء PowerShell واحد (سريع)."""
    if os.name != "nt" or not paths:
        return {}
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$in=[Console]::In.ReadToEnd() -split \"`n\";"
        "foreach($p in $in){$p=$p.Trim();"
        "if($p -and (Test-Path -LiteralPath $p)){"
        "try{$s=Get-AuthenticodeSignature -LiteralPath $p;"
        "Write-Output ($p+'|'+$s.Status)}catch{Write-Output ($p+'|ERROR')}}}"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            input="\n".join(paths), capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"  ⚠ تعذر فحص التوقيع دفعة: {exc}", file=sys.stderr)
        return {}
    result: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if "|" not in line:
            continue
        path, _, status = line.rpartition("|")
        result[path.strip().lower()] = SIG_MAP.get(status.strip(), status.strip())
    return result


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_type(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            magic = fh.read(8)
    except OSError:
        return "unreadable"
    if magic[:2] == b"MZ":
        return "PE"
    if magic[:4] == b"\x7fELF":
        return "ELF"
    if magic[:2] == b"PK":
        try:
            import zipfile
            with zipfile.ZipFile(path) as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    return "APK"
        except Exception:  # noqa: BLE001
            pass
        return "ZIP"
    return "other"


def die_info(path: str) -> str:
    """يشغّل Detect It Easy اختيارياً ويعيد أول أسطر مفيدة."""
    try:
        proc = subprocess.run(
            ["diec", path], capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
        )
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()][:4]
        return " | ".join(lines)
    except (OSError, subprocess.TimeoutExpired):
        return ""


def analyze_one(path: str, with_die: bool) -> dict:
    """تحليل بنية الملف فقط — التوقيع يُفحص لاحقاً دفعة واحدة."""
    row: dict = {
        "الاسم": os.path.basename(path),
        "المسار": path,
        "النوع": "", "الحجم_KB": "", "SHA256": "", "المعمارية": "",
        "موقّع": "", "الحماية": "", "DOTNET": "", "البناء_UTC": "",
        "الأقسام": "", "أعلى_إنتروبيا": "", "المؤشرات": "",
        "تشغيل_تلقائي": "", "درجة": 0, "التوصية": "", "DIE": "", "خطأ": "",
        "_أسباب": [],
    }
    try:
        row["الحجم_KB"] = round(os.path.getsize(path) / 1024, 1)
        row["النوع"] = detect_type(path)
        row["SHA256"] = sha256_file(path)
        autorun = AUTORUN_PATHS.get(os.path.abspath(path).lower())
        row["تشغيل_تلقائي"] = autorun or ""

        score = 0
        reasons: list[str] = []

        if row["النوع"] == "PE":
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories()
            row["المعمارية"] = ARCH.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
            ts = pe.FILE_HEADER.TimeDateStamp
            row["البناء_UTC"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
            dllchar = pe.OPTIONAL_HEADER.DllCharacteristics
            prot = []
            if dllchar & 0x0040: prot.append("ASLR")
            if dllchar & 0x0100: prot.append("DEP")
            if dllchar & 0x1000: prot.append("CFG")
            if dllchar & 0x0020: prot.append("HEA")
            row["الحماية"] = ",".join(prot) or "-"
            com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            row["DOTNET"] = "نعم" if com.VirtualAddress else "لا"

            max_ent = 0.0
            upx = False
            row["الأقسام"] = len(pe.sections)
            for s in pe.sections:
                try:
                    max_ent = max(max_ent, s.get_entropy())
                except Exception:  # noqa: BLE001
                    pass
                if s.Name.rstrip(b"\x00").upper().startswith(b"UPX"):
                    upx = True
            row["أعلى_إنتروبيا"] = round(max_ent, 2)

            hits: dict[str, list[str]] = {k: [] for k in INDICATORS}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                wanted = {fn: cat for cat, fns in INDICATORS.items() for fn in fns}
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for f in entry.imports:
                        if f.name:
                            fn = f.name.decode(errors="replace")
                            if fn in wanted:
                                hits[wanted[fn]].append(fn)
            parts = [f"{cat}:{','.join(sorted(set(v))[:3])}" for cat, v in hits.items() if v]
            row["المؤشرات"] = "; ".join(parts)
            pe.close()

            if max_ent >= 7.2:
                score += 2
                reasons.append("إنتروبيا عالية")
            if upx:
                score += 2
                reasons.append("UPX")
            if len(hits["حقن_عمليات"]) >= 2:
                score += 2
                reasons.append("استدعاءات حقن")
            if hits["مكافحة_تحليل"]:
                score += 1
                reasons.append("مؤشرات مكافحة تحليل")
        if autorun:
            score += 1
            reasons.append("في التشغيل التلقائي")

        row["درجة"] = score
        row["_أسباب"] = reasons
        if with_die:
            row["DIE"] = die_info(path)
    except pefile.PEFormatError:
        row["خطأ"] = "ملف PE تالف"
    except Exception as exc:  # noqa: BLE001
        row["خطأ"] = f"{type(exc).__name__}: {exc}"
    return row


def apply_signature_scores(rows: list[dict], sigs: dict[str, str]) -> None:
    """يضيف درجة عدم التوقيع ويحدد التوصية النهائية."""
    for row in rows:
        status = sigs.get(os.path.abspath(row["المسار"]).lower(), "")
        if not status:
            row["موقّع"] = "غير متوفر"
        else:
            row["موقّع"] = status
            if status != "valid" and row["النوع"] == "PE":
                row["درجة"] += 2
                reasons = row.get("_أسباب", [])
                reasons.append("توقيع غير صالح" if status != "unsigned" else "غير موقّع")
                row["_أسباب"] = reasons
            elif status == "valid":
                pass
        if row["النوع"] == "APK":
            row["موقّع"] = "APK"
        evid = "; ".join(row.get("_أسباب", []))
        if evid:
            row["المؤشرات"] = (row["المؤشرات"] + "; " if row["المؤشرات"] else "") + evid
        row["درجة"] = int(row["درجة"])
        d = row["درجة"]
        row["التوصية"] = ("مرتفع — راجع يدوياً" if d >= 5
                          else "متوسط — يستحق المراجعة" if d >= 2
                          else "منخفض")


CSV_COLUMNS = ["الاسم", "المسار", "النوع", "الحجم_KB", "SHA256", "المعمارية", "موقّع",
               "الحماية", "DOTNET", "البناء_UTC", "الأقسام", "أعلى_إنتروبيا",
               "المؤشرات", "تشغيل_تلقائي", "درجة", "التوصية", "DIE", "خطأ"]


def write_html(rows: list[dict], out_path: str, target: str, seconds: float) -> None:
    total = len(rows)
    high = sum(1 for r in rows if r["درجة"] >= 5)
    mid = sum(1 for r in rows if 2 <= r["درجة"] < 5)
    low = total - high - mid
    esc = html.escape
    trs = []
    for r in sorted(rows, key=lambda x: -x["درجة"]):
        cls = "high" if r["درجة"] >= 5 else ("mid" if r["درجة"] >= 2 else "low")
        trs.append(
            f'<tr class="{cls}"><td>{esc(str(r["درجة"]))}</td><td>{esc(str(r["الاسم"]))}</td>'
            f'<td class="mono">{esc(str(r["SHA256"])[:16])}…</td>'
            f"<td>{esc(str(r['النوع']))}</td><td>{esc(str(r['المعمارية']))}</td>"
            f"<td>{esc(str(r['موقّع']))}</td><td>{esc(str(r['الحماية']))}</td>"
            f"<td>{esc(str(r['المؤشرات']))}</td><td>{esc(str(r['تشغيل_تلقائي']))}</td>"
            f"<td>{esc(str(r['التوصية']))}</td></tr>"
        )
    page = f"""<!DOCTYPE html>
<html dir="rtl" lang="ar"><head><meta charset="utf-8">
<title>تقرير تحليل البرامج</title>
<style>
 body{{font-family:'Segoe UI',Tahoma,sans-serif;background:#0f172a;color:#e2e8f0;margin:20px}}
 h1{{font-size:22px}} .stats{{display:flex;gap:16px;margin:14px 0}}
 .card{{background:#1e293b;border-radius:10px;padding:12px 20px;min-width:110px;text-align:center}}
 .card b{{display:block;font-size:26px}} .h{{color:#f87171}} .m{{color:#fbbf24}} .l{{color:#4ade80}}
 table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden}}
 th{{background:#334155;padding:9px;text-align:right;font-size:13px}}
 td{{padding:8px 9px;border-top:1px solid #283548;font-size:13px;text-align:right}}
 .mono{{font-family:Consolas,monospace;direction:ltr;text-align:left}}
 tr.high td:first-child{{color:#f87171;font-weight:bold}}
 tr.mid td:first-child{{color:#fbbf24;font-weight:bold}}
 tr.low td:first-child{{color:#4ade80}}
 .meta{{color:#94a3b8;font-size:13px;margin-top:6px}}
</style></head><body>
<h1>تقرير تحليل البرامج</h1>
<div class="meta">الهدف: {esc(target)} — {datetime.now().strftime('%Y-%m-%d %H:%M')} — زمن التحليل {seconds:.1f}ث</div>
<div class="stats">
 <div class="card"><b>{total}</b>ملف</div>
 <div class="card"><b class="h">{high}</b>مرتفع</div>
 <div class="card"><b class="m">{mid}</b>متوسط</div>
 <div class="card"><b class="l">{low}</b>منخفض</div>
</div>
<table><tr><th>الدرجة</th><th>الاسم</th><th>SHA256</th><th>النوع</th><th>المعمارية</th>
<th>موقّع</th><th>الحماية</th><th>المؤشرات</th><th>تشغيل تلقائي</th><th>التوصية</th></tr>
{''.join(trs)}</table></body></html>"""
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(page)


def collect_files(target: str, exts: set[str]) -> list[str]:
    found: list[str] = []
    if os.path.isfile(target):
        return [target]
    for root, _dirs, files in os.walk(target):
        for name in files:
            if os.path.splitext(name)[1].lower() in exts:
                found.append(os.path.join(root, name))
    return found


def main() -> None:
    ap = argparse.ArgumentParser(description="وكيل تحليل جماعي للملفات التنفيذية")
    ap.add_argument("target", help="مجلد أو ملف")
    ap.add_argument("-o", "--out", default=os.path.join(os.path.dirname(__file__), "out", "analysis.csv"))
    ap.add_argument("--html", default=os.path.join(os.path.dirname(__file__), "out", "report.html"))
    ap.add_argument("--workers", type=int, default=min(8, (os.cpu_count() or 4)))
    ap.add_argument("--ext", default=DEFAULT_EXTS, help="امتدادات مفصولة بفواصل")
    ap.add_argument("--die", action="store_true", help="إرفاق Detect It Easy (أبطأ)")
    ap.add_argument("--no-sign", action="store_true", help="تخطي فحص التوقيع")
    args = ap.parse_args()

    if not os.path.exists(args.target):
        print(f"غير موجود: {args.target}", file=sys.stderr)
        sys.exit(1)

    exts = {e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
            for e in args.ext.split(",") if e.strip()}
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.html)), exist_ok=True)

    print(f"[1/4] جمع الملفات من {args.target} ...", flush=True)
    files = collect_files(args.target, exts)
    print(f"      وُجد {len(files)} ملف — التحليل بـ {args.workers} خيوط", flush=True)
    if not files:
        sys.exit(0)

    load_autorun_paths()
    if AUTORUN_PATHS:
        print(f"      {len(AUTORUN_PATHS)} إدخال تشغيل تلقائي مفهرس", flush=True)

    print("[2/4] التحليل البنائي (متوازٍ) ...", flush=True)
    t0 = time.time()
    rows: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(analyze_one, f, args.die): f for f in files}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            rows.append(fut.result())
            done += 1
            if done % 50 == 0 or done == len(files):
                pct = done * 100 // len(files)
                print(f"      {done}/{len(files)} ({pct}%) — {time.time() - t0:.0f}ث", flush=True)

    sigs: dict[str, str] = {}
    if not args.no_sign:
        pe_rows = [r for r in rows if r["النوع"] in ("PE", "ELF")]
        if pe_rows:
            print(f"[3/4] فحص التوقيع الرقمي لـ {len(pe_rows)} ملف (دفعة واحدة) ...", flush=True)
            sigs = batch_signature_status([r["المسار"] for r in pe_rows])
            ok = sum(1 for v in sigs.values() if v == "valid")
            print(f"      تم فحص {len(sigs)} — {ok} موقّع صالحاً", flush=True)
        else:
            print("[3/4] لا ملفات PE لفحص التوقيع", flush=True)
    else:
        print("[3/4] تخطي فحص التوقيع", flush=True)

    apply_signature_scores(rows, sigs)
    elapsed = time.time() - t0

    print("[4/4] كتابة التقارير ...", flush=True)
    for row in rows:
        row.pop("_أسباب", None)
    with open(args.out, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    write_html(rows, args.html, args.target, elapsed)

    errors = sum(1 for r in rows if r["خطأ"])
    high = sum(1 for r in rows if r["درجة"] >= 5)
    print(f"\n✓ اكتمل التحليل: {len(rows)} ملف في {elapsed:.1f}ث ({errors} خطأ)")
    print(f"  CSV : {args.out}")
    print(f"  HTML: {args.html}")
    if high:
        print(f"  ⚠ {high} ملف بدرجة مرتفع — أعلى 5:")
        for r in sorted(rows, key=lambda x: -x["درجة"])[:5]:
            if r["درجة"] >= 2:
                print(f"    [{r['درجة']}] {r['الاسم']} — {r['التوصية']} ({r['المؤشرات']})")


if __name__ == "__main__":
    main()
