"""استخراج النصوص القابلة للطباعة من ملف ثنائي (EXE / APK / أي ملف).

الاستخدام:
    python strings_extract.py <file> [--min 5] [--encoding all|ascii|utf16] [--filter كلمة]
"""

import argparse
import re
import sys

ASCII_RE = re.compile(rb"[\x20-\x7E]{%d,}")
UTF16_RE = re.compile((r"[\x20-\x7E]\x00{%d,}").encode("ascii"))  # placeholder


def extract_ascii(data: bytes, minimum: int) -> list[str]:
    return [m.group().decode("ascii") for m in re.finditer(rb"[\x20-\x7E]{%d,}" % minimum, data)]


def extract_utf16(data: bytes, minimum: int) -> list[str]:
    # نصوص UTF-16LE (شائعة في موارد PE)
    pattern = (rb"(?:[\x20-\x7E]\x00){%d,}" % minimum)
    out = []
    for m in re.finditer(pattern, data):
        try:
            out.append(m.group().decode("utf-16-le"))
        except UnicodeDecodeError:
            pass
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="استخراج النصوص من ملف ثنائي")
    ap.add_argument("file")
    ap.add_argument("--min", type=int, default=5, help="أقل طول للنص (افتراضي 5)")
    ap.add_argument("--encoding", choices=("all", "ascii", "utf16"), default="all")
    ap.add_argument("--filter", default=None, help="عرض فقط النصوص التي تحتوي على كلمة محددة")
    args = ap.parse_args()

    try:
        with open(args.file, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"خطأ: {exc}", file=sys.stderr)
        sys.exit(1)

    strings: list[str] = []
    if args.encoding in ("all", "ascii"):
        strings += extract_ascii(data, args.min)
    if args.encoding in ("all", "utf16"):
        strings += extract_utf16(data, args.min)

    if args.filter:
        needle = args.filter.lower()
        strings = [s for s in strings if needle in s.lower()]

    seen: set[str] = set()
    for s in strings:
        if s not in seen:
            seen.add(s)
            print(s)

    print(f"\n-- {len(seen)} نص فريد --", file=sys.stderr)


if __name__ == "__main__":
    main()
