"""إضافة محلل مخصص — REPLATFORM Plugin API (مثال حي).

هذا الملف يُحمَّل تلقائياً. انسخه إلى مجلد plugins باسم جديد وعدّل.

للاختبار: python repl.py analyze <ملف.demo> --only example
"""

from replatform.analyzers import Analyzer, Target


class ExampleAnalyzer(Analyzer):
    name = "example"
    description = "إضافة تجريبية: تعرض نوع الملف وحجمه فقط"

    def can_handle(self, target: Target) -> bool:
        # لا تتدخل في تحليلات PE/APK — امتداد مخصص فقط
        return target.path.suffix.lower() == ".demo"

    def run(self, target: Target, ws) -> dict:  # noqa: ARG002
        return {
            "score": 0,
            "verdict": "info",
            "findings": [],
            "note": f"تم تحليل {target.name} ({target.kind}, {target.size} بايت)",
        }
