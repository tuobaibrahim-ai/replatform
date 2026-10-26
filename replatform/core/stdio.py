"""تهيئة ترميز الإخراج.

على طرفيات/أنابيب Windows بترميز cp1252 (شائع خارج الإعدادات العربية) تنهار
طباعة النص العربي أو الرموز مثل ✓ بـ `UnicodeEncodeError`. نضبط الترميز مرة
واحدة عند الدخول: UTF-8 عند إعادة التوجيه (ملفات/CI)، و`errors=replace` على
الطرفية التفاعلية حتى لا يتوقف البرنامج أبداً بسبب محرف غير قابل للترميز.
"""

from __future__ import annotations

import sys


def configure() -> None:
    """يضبط stdout/stderr بلا كسر عند غياب الدعم (StringIO، pythonw، إلخ)."""
    for stream in (sys.stdout, sys.stderr):
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            if stream.isatty():
                reconfigure(errors="replace")
            else:
                reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue
