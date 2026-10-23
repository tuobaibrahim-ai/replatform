#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""وكيل تعديل قديم (توافق خلفي) — يفوّض الآن إلى محرك REPLATFORM الآمن.

كل المنطق (معاينة، نسخة احتياطية فريدة، منع تغيير طول PE/APK/ZIP،
الاسترجاع التلقائي عند تلف البنية) موجود في replatform.tools.patcher
ويُستدعى عبر واجهة `repl.py patch`.

الاستخدام مطابق للسابق:
  python agents\\patch_agent.py app.exe --find "str:TRIAL" --replace "str:FULL"
  python agents\\patch_agent.py app.exe --find "hex:48 89 ?? C3" --replace "hex:31 C0 ?? C3" --apply

الطريقة المفضلة الآن:
  python repl.py patch app.exe --find ... --replace ... [--apply]
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from replatform.cli import main as cli_main  # noqa: E402


def main() -> None:
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        raise SystemExit(cli_main(["patch", "--help"]))
    if not args or args[0].startswith("-"):
        print(
            "الاستخدام: python agents\\patch_agent.py <ملف> --find ... --replace ... "
            "[--apply] [--all]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    raise SystemExit(cli_main(["patch", *args]))


if __name__ == "__main__":
    main()
