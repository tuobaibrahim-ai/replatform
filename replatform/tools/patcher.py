"""تعديل ثنائي آمن: معاينة افتراضية + نسخة احتياطية + تحقق من سلامة PE."""

from __future__ import annotations

import hashlib
import itertools
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

from ..core import util

SYSTEM_DIRS = [
    Path(os.environ.get("SystemRoot", r"C:\Windows")),
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
]
MAX_PATCH_BYTES = 256 * 1024 * 1024
CONTAINER_KINDS = ("PE", "APK", "ZIP")


def sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def is_system_path(path: str | Path) -> bool:
    resolved = Path(path).resolve()
    for directory in SYSTEM_DIRS:
        try:
            if str(directory) and resolved.is_relative_to(directory.resolve()):
                return True
        except (OSError, ValueError):
            continue
    return False


def is_pe(path: str | Path) -> bool:
    return str(path).lower().endswith((".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"))


def _parse_hex(text: str, allow_wild: bool) -> tuple[list[str], re.Pattern]:
    tokens = text.split()
    if not tokens:
        raise ValueError("نمط hex فارغ")
    pattern = bytearray()
    for token in tokens:
        if token in ("?", "??"):
            if not allow_wild:
                raise ValueError("علامة ?? غير مسموحة في نمط الاستبدال")
            pattern += b"."
        elif re.fullmatch(r"[0-9a-fA-F]{2}", token):
            pattern += re.escape(bytes.fromhex(token))
        else:
            raise ValueError(f"رمز hex غير صالح: {token!r}")
    return tokens, re.compile(bytes(pattern), re.DOTALL)


def parse_spec(spec: str, encoding: str, allow_wild: bool):
    kind, sep, rest = spec.partition(":")
    if not sep:
        raise ValueError(f"صيغة غير مدعومة: {spec!r} (استخدم hex: أو str:)")
    if kind == "hex":
        tokens, pattern = _parse_hex(rest, allow_wild)
        return "hex", pattern, tokens
    if kind == "str":
        if not rest:
            raise ValueError("نص البحث فارغ")
        return "str", rest.encode(encoding), None
    raise ValueError(f"صيغة غير مدعومة: {kind!r} (استخدم hex: أو str:)")


def hexdump(data: bytes, start: int, length: int = 48) -> str:
    chunk = data[start:start + length]
    hexpart = " ".join(f"{b:02X}" for b in chunk)
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"{hexpart:<60}  |{asc}|"


def patch(
    path: str | Path,
    find: str,
    replace: str,
    encoding: str = "ascii",
    apply: bool = False,
    all_matches: bool = False,
    allow_system: bool = False,
    allow_resize: bool = False,
    max_show: int = 10,
) -> dict:
    """ينفّذ (أو يعاين) تعديلاً ثنائياً. يعيد dict منظماً."""
    target = Path(path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"ملف غير موجود: {target}")
    if is_system_path(target) and not allow_system:
        raise PermissionError(
            "ملف داخل مجلدات النظام — مرفوض دون --allow-system (حماية من الكسر)."
        )

    find_kind, find_obj, find_tokens = parse_spec(find, encoding, allow_wild=True)
    repl_kind, repl_obj, repl_tokens = parse_spec(replace, encoding, allow_wild=False)
    if find_kind != repl_kind:
        raise ValueError("يجب أن يكون find و replace من النوع نفسه (hex أو str)")
    if find_kind == "hex" and len(repl_tokens) != len(find_tokens):
        raise ValueError(
            f"عدد رموز hex يجب أن يتساوى: find={len(find_tokens)} replace={len(repl_tokens)}"
        )

    size = target.stat().st_size
    if size > MAX_PATCH_BYTES:
        raise ValueError(
            f"الملف كبير جداً للتعديل المباشر ({util.human_size(size)}) — "
            f"الحد {util.human_size(MAX_PATCH_BYTES)}."
        )
    max_show = max(0, min(int(max_show), 100))
    file_kind = util.file_kind(target)
    resizing = find_kind == "str" and len(repl_obj) != len(find_obj)
    if resizing and file_kind in CONTAINER_KINDS and not allow_resize:
        raise ValueError(
            "تغيير طول ملف PE/APK/ZIP يفسد الإزاحات الداخلية. "
            "استخدم استبدالاً بنفس الطول، أو --allow-resize إن كنت تعرف ما تفعل."
        )

    data = bytearray(target.read_bytes())
    if find_kind == "hex":
        positions = [match.start() for match in find_obj.finditer(data)]
    else:
        positions = []
        index = data.find(find_obj)
        while index != -1:
            positions.append(index)
            index = data.find(find_obj, index + 1)

    # تطابقات str المتداخلة (مثل "aa" داخل "aaa") تجعل --all يكرّر النص
    # ويغيّر طول الملف أو يفسد البيانات. نرفض العملية كاملة قبل أي كتابة.
    if find_kind == "str" and all_matches and len(positions) > 1:
        span = len(find_obj)
        overlap = next(
            (
                (previous, current)
                for previous, current in itertools.pairwise(positions)
                if current < previous + span
            ),
            None,
        )
        if overlap is not None:
            first, second = overlap
            raise ValueError(
                "تطابقات str متداخلة — --all سيكرّر البيانات ويغيّر طول الملف. "
                f"أول تداخل عند 0x{first:X} و0x{second:X}. "
                "استخدم نمطاً أطول/فريداً، أو عدّل تطابقاً واحداً دون --all. "
                "لم يُكتب أي تغيير."
            )

    result = {
        "file": str(target),
        "size": len(data),
        "sha256_before": sha256_bytes(data),
        "find": find,
        "replace": replace,
        "count": len(positions),
        "matches": [],
        "applied": False,
        "length_warning": resizing,
        "allow_resize": allow_resize,
    }
    for offset in positions[:max_show]:
        result["matches"].append({
            "offset": offset,
            "offset_hex": f"0x{offset:08X}",
            "context": hexdump(data, max(0, offset - 16)),
        })

    if not positions or not apply:
        return result

    chosen = positions if all_matches else positions[:1]
    if find_kind == "hex":
        for offset in chosen:
            pos = offset
            for token in repl_tokens:
                if token not in ("?", "??"):
                    data[pos] = int(token, 16)
                pos += 1
    else:
        new = bytearray()
        last = 0
        for offset in chosen:
            new += data[last:offset]
            new += repl_obj
            last = offset + len(find_obj)
        new += data[last:]
        data = new

    backup = _reserve_backup(target)
    try:
        shutil.copy2(target, backup)
    except BaseException:
        backup.unlink(missing_ok=True)
        raise

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".patch_tmp", dir=target.parent
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    result["applied"] = True
    result["replaced"] = len(chosen)
    result["sha256_after"] = sha256_bytes(data)
    result["backup"] = str(backup)

    def _restore() -> None:
        try:
            shutil.copy2(backup, target)
            result["rolled_back"] = True
            result["applied"] = False
            result["sha256_after_restore"] = sha256_bytes(target.read_bytes())
        except OSError as exc:
            result["rollback_error"] = f"{type(exc).__name__}: {exc}"

    if file_kind == "PE":
        pe = None
        try:
            import pefile

            pe = pefile.PE(str(target), fast_load=True)
            pe.parse_data_directories()
            entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        except Exception as exc:  # noqa: BLE001
            result["pe_valid"] = False
            result["pe_error"] = str(exc)
            _restore()
        else:
            result["pe_valid"] = True
            result["entry_point"] = f"0x{entry:X}"
        finally:
            if pe is not None:
                try:
                    pe.close()
                except Exception:  # noqa: BLE001
                    pass

    if file_kind in ("APK", "ZIP") and size <= 128 * 1024 * 1024:
        try:
            with zipfile.ZipFile(target) as archive:
                bad = archive.testzip()
            if bad:
                raise zipfile.BadZipFile(f"مدخل تالف: {bad}")
        except (zipfile.BadZipFile, OSError) as exc:
            result["zip_valid"] = False
            result["zip_error"] = str(exc)
            _restore()
        else:
            result["zip_valid"] = True

    return result


def _reserve_backup(target: Path) -> Path:
    """يحجز اسم نسخة احتياطية فريداً (بدقة الميكروثانية + O_EXCL)."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    for index in range(100):
        name = f"{target.name}.bak.{stamp}"
        if index:
            name += f"-{index}"
        candidate = target.with_name(name)
        try:
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            continue
        os.close(fd)
        return candidate
    raise FileExistsError("تعذر إنشاء اسم فريد للنسخة الاحتياطية")
