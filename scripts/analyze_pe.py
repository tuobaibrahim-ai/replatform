"""تحليل تفصيلي لملفات PE (exe / dll) باستخدام pefile + capstone.

الاستخدام:
    python analyze_pe.py <path-to-file.exe>
"""

import sys
from datetime import datetime, timezone

import pefile


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n}"


def describe_characteristics(value: int, table: dict) -> str:
    return ", ".join(name for bit, name in table.items() if value & bit)


def main(path: str) -> None:
    pe = pefile.PE(path, fast_load=False)

    print("=" * 70)
    print(f"الملف          : {path}")
    print(f"الحجم          : {human(pe.OPTIONAL_HEADER.SizeOfImage)} (SizeOfImage)")
    print(f"نوع البناء      : {'64-bit (PE32+)' if pe.PE_TYPE == 0x20b else '32-bit (PE32)'}")
    print(f"نقطة الدخول RVA : 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
    print(f"ImageBase       : 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
    print(f"التوقيع         : {'موجود (Authenticode)' if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') else 'غير موقّع'}")

    ts = pe.FILE_HEADER.TimeDateStamp
    when = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"طابع زمني البناء : {when} (0x{ts:X})")

    dllchar = pe.OPTIONAL_HEADER.DllCharacteristics
    flags = {
        0x0020: "HIGH_ENTROPY_VA",
        0x0040: "DYNAMIC_BASE (ASLR)",
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT (DEP)",
        0x0400: "NO_SEH",
        0x0800: "APPCONTAINER",
        0x1000: "GUARD_CF",
        0x4000: "TERMINAL_SERVER_AWARE",
    }
    print(f"حماية النظام     : {describe_characteristics(dllchar, flags) or 'لا شيء'}")

    # مكتبات مستوردة
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("\n-- المكتبات المستوردة --")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            funcs = [f.name.decode(errors="replace") if f.name else f"#{f.ordinal}"
                     for f in entry.imports]
            preview = ", ".join(funcs[:6])
            more = f" ... (+{len(funcs) - 6})" if len(funcs) > 6 else ""
            print(f"  {entry.dll.decode(errors='replace'):30} {preview}{more}")

    # موارد
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        print("\n-- أنواع الموارد --")
        for res in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            name = res.name.string.decode(errors="replace") if res.name else pefile.RESOURCE_TYPE.get(res.struct.Id, res.struct.Id)
            count = len(res.directory.entries)
            print(f"  {name}: {count}")

    # أقسام
    print("\n-- الأقسام --")
    print(f"  {'الاسم':10} {'RVA':>10} {'الحجم':>10} {'الخصائص'}")
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        chars = s.Characteristics
        props = []
        if chars & 0x20000000: props.append("EXEC")
        if chars & 0x40000000: props.append("READ")
        if chars & 0x80000000: props.append("WRITE")
        print(f"  {name:10} 0x{s.VirtualAddress:08X} {human(s.Misc_VirtualSize):>10} {','.join(props)}")

    # تحليل كود نقطة الدخول بـ capstone (أول 30 تعليمة)
    try:
        import capstone
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        data = pe.get_data(ep, 128)
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64 if pe.PE_TYPE == 0x20b else capstone.CS_MODE_32
        md = capstone.Cs(arch, mode)
        md.detail = False
        print("\n-- أول التعليمات عند نقطة الدخول --")
        for i, ins in enumerate(md.disasm(data, pe.OPTIONAL_HEADER.ImageBase + ep)):
            print(f"  0x{ins.address:016X}: {ins.mnemonic:8} {ins.op_str}")
            if i >= 29:
                break
    except Exception as exc:  # noqa: BLE001
        print(f"\n(تعذر تفكك الكود: {exc})")

    pe.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
