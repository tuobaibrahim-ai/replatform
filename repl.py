#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""نقطة الدخول: python repl.py <أمر>"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from replatform.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
