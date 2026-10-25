# سجل التغييرات

## 1.4.0 — 2026-10-25

### طبقة المنتج (جديد)
- **حزمة محمولة** `replatform-<version>-portable.zip` ببناء حتمي (بلا `__pycache__`
  ولا عيّنات ولا أسرار) مع `install.ps1` و`replatform.cmd`.
- **SBOM** بصيغة CycloneDX 1.5، و`SHA256SUMS` لكل مخرجات التوزيع، وأداة تحقق
  `python -m replatform.tools.release --verify`.
- `python -m replatform` كواجهة موازية لـ `repl.py`، و`py.typed`، وبيانات حزمة
  صريحة، وروابط مشروع، ومصنفات Windows 10/11 وعربية/إنجليزية.
- حوكمة كاملة: `SECURITY.md`، `CONTRIBUTING.md`، `CODE_OF_CONDUCT.md`،
  `SUPPORT.md`، `COMMERCIAL.md`، `THIRD_PARTY_NOTICES.md`، `CITATION.cff`.
- توثيق هندسي: `docs/ARCHITECTURE.md`، `docs/DEPLOYMENT.md`، `docs/QUALITY.md`،
  `docs/ROADMAP.md`.
- أتمتة GitHub: قوالب Issues/PR، Dependabot، وRelease workflow يتحقق من تطابق
  الوسم، يبني الحزم، ينشئ SBOM والبصمات، وينشر Release.

### الجودة والاختبارات
- **325 اختبار `unittest`** (كانت 122)، وتغطية **75%** (كانت 48%) بحد CI **70%**.
- `tests/test_agents.py` (63): المزوّدون، إعادة التوجيه، الأدوات، الحلقة، ضغط
  السياق، التوكنات، والمزوّد الوهمي.
- `tests/test_http.py` (24): allowlist، HTTPS، حدود الاستجابة، الأخطاء.
- `tests/test_fuzz.py` (9): fuzzing حتمي ببذرة `20261025` لسبعة محللات مدخلات.
- `tests/test_cli.py` (25): لقطة سطح 21 أمراً + التوزيع + المساعدات.
- `tests/test_batch_export.py` (22): الدفعات، CSV injection، HTML، PDF.
- `tests/test_ghidra.py` (14) و`tests/test_analyzers_extra.py` (23).
- `tests/test_release.py` (23): SBOM، البصمات، الحزمة المحمولة، والتحقق.
- `pyproject.toml`: `fail_under = 70`، و`build` ضمن اعتمادات التطوير.
- CI يضيف بناء الحزم وتشغيل أدوات الإصدار (dry run) على Python 3.12.

### التغييرات
- الوصف الإنجليزي للحزمة ومصنفات أوسع؛ الإصدار في `pyproject.toml` و
  `replatform/__init__.py` و`CITATION.cff` متطابق.
- `--verify` في أداة الإصدار لا يعيد كتابة SBOM/البصمات (تحقق للقراءة فقط).
- `README.md` و`README.en.md` أُعيد بناؤهما كصفحة منتج بأرقام 1.4.0.

## 1.3.1 — 2026-10-25

### الجودة والاختبارات
- 112 اختبار `unittest` (كانت 17): تغطية النواة (إعدادات/حالة/مساحات عمل/تقارير)،
  أدوات التعديل والمقارنة والعزل، المحللات النصية وPE، الوكيل القواعدي، محرك YARA،
  وحواجز الواجهة.
- 34 اختباراً تعاقدياً للموصلات الاثني عشر بلا شبكة ولا مفاتيح: تطبيع الاستجابات،
  رفض المؤشرات غير الصالحة، وتأكيد أعلام القراءة فقط وعدم تنزيل العيّنات.
- قياس تغطية عبر `coverage` في CI بحد أدنى 45% لوحدات المنطق (تُستثنى نقاط الدخول
  المُختبَرة تكاملياً: `cli.py`, `selftest.py`, `web/server.py`).
- ترقية إجراءات CI إلى `actions/checkout@v5` و`actions/setup-python@v6`.

### المحتوى
- `rules/extended.yar`: 9 قواعد إضافية (PowerShell cradle، LSASS dumping، الفدية،
  UPX، مهام مجدولة، anti-debug، حقن عمليات، تعطيل Defender، Base64 PowerShell)،
  مُتحقَّق من تجميعها بـ yarac وخلوّها من إيجابيات كاذبة على ثنائي سليم.

### التوثيق
- `README.en.md`: دليل إنجليزي مختصر.
- تحديث أعداد الاختبارات والتغطية في `README.md`.

### التغليف
- `MANIFEST.in` يضمّ القواعد والمهارات والسكربتات والاختبارات في حزمة المصدر.
- ترخيص SPDX (`license = "MIT"` + `license-files`) وفق PEP 639 بدل الصيغة المهجورة.

## 1.3.0 — 2026-10-23

### الأمان والاعتمادية
- توقيع APK في مجلد مؤقت معزول، ثم التحقق من ZIP ومن مخططات v1/v2/v3/v3.1/v4 قبل اعتبار التوقيع ناجحاً.
- حماية `apk decode --force` من حذف ملف أو رابط أو مجلد لا يبدو ناتج apktool، ومن حذف أصل APK.
- حدود APK: الحجم، عدد المدخلات، الحجم غير المضغوط، نسبة الضغط (زيب بوم)، وحجم البيان بعد الفك.
- حدود PE/strings/YARA و`bindiff` مع نتائج `skipped` صريحة بدلاً من استنزاف الذاكرة.
- Sandbox watchdog ينهي شجرة العملية (`taskkill /T /F`) بعد المهلة، بسقف انتظار أقصى.
- عميل التكاملات يستخدم تحقق TLS إلزامياً مع حزمة CA حديثة (`certifi`) عند توفرها.

### التحليل
- دلالات `android:exported` في Android 12+: القيمة الصريحة، ثم استنتاج `intent-filter`، مع كشف غياب القيمة الصريحة عند `targetSdk >= 31` والمكونات المُصدّرة بلا `permission`.
- توريث `<application android:permission>` للمكونات، ومعاملة مزوّد المحتوى القديم (`targetSdk <= 16`) كمُصدَّر افتراضياً.
- كشف النشاط الرئيسي عبر `MAIN` + `LAUNCHER` معاً، وإضافة حقول `exported` إلى تقرير APK.
- رفض `apk sign` لمسار إخراج ليس مجلداً عادياً (ملف أو رابط).

### التكاملات
- إضافة `urlhaus` و`threatfox` (abuse.ch) كمـوصلات قراءة فقط عبر `ABUSECH_AUTH_KEY`.
- لا رفع عيّنات ولا تحميل ملفات؛ استعلامات ومؤشرات نصية فقط.

### الجودة والتوثيق
- `pyproject.toml`، `LICENSE` (MIT)، وCI على Windows عبر GitHub Actions.
- 17 اختبار `unittest` مستقل بلا شبكة أو عينات خارجية.
- تحديث `README.md` و`PLATFORM.md` و`INTEGRATIONS.md` و`config.example.json`.

## 1.2.0
- الإصدار المرجعي السابق بعد مراجعة الأمان الأولى.
