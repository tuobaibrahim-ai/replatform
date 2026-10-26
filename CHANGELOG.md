# سجل التغييرات

## 1.5.0 — 2026-10-26

### البناء وسلسلة التوريد
- **بناء حتمي فعلي:** تطبيع نهايات الأسطر داخل ZIP، بيانات `ZipInfo` ثابتة،
  و`ZIP_STORED` لإزالة تفاوت ضغط zlib بين البيئات. أمر جديد:
  `python -m replatform.tools.release --reproducible` يثبت تطابق البصمة.
- **قفل الاعتماديات:** `requirements.lock` و`requirements-dev.lock` مولّدان بـ
  `uv` مع بصمات `--require-hashes` (universal, Python 3.11).
- **فحص أنواع:** `mypy` مضاف كبوابة CI؛ أُصلحت 27 مشكلة أنواع حقيقية (خلط
  `bytes/int` في تحليل توقيع APK، `Path/str` في الويب، أنواع القواميس).

### دورة الحياة
- **هجرة إعدادات آمنة:** `config_version` صريح، هجرة 1→2، نسخة احتياطية
  `config.json.v1.<timestamp>.bak`، رفض الإعدادات من إصدار أحدث، وأمر
  `config migrate [--dry-run]`.
- **`doctor`:** فحص Python/النظام/الإعدادات/المزوّد/الاعتماديات/الأدوات/الكتابة/
  القرص/الترخيص، مع `--json` و`--bundle` لحزمة دعم تُقنّع كل الأسرار.
- **ترقية آمنة:** `upgrade` يتحقق من البصمة وبنية ZIP ويرفض zip-slip، ويحفظ
  `config.json`/`workspaces`/`plugins`/`license.json`، مع نسخة تراجع وأمر
  `--rollback`، وسكربتات `upgrade.ps1` و`uninstall.ps1`.

### التجاري والاشتراكات
- **تراخيص offline موقّعة:** Ed25519 مطبّق وفق RFC 8032 بلا اعتماديات، مع
  اختبار ضد متجهات RFC. المفتاح الخاص خارج المستودع، والعام مثبّت في الكود.
- **خطط واستحقاقات:** Community (MIT كاملة) / Professional / Enterprise،
  فترة سماح 14 يوماً، وأوامر `license status|activate|deactivate|features`.
- **قدرات مؤسسية:** `audit` (سجل بسلسلة تجزئة + تصدير بإثبات) و`fleet`
  (تقرير أسطول مساحات العمل) — جديد في 1.5.0 ومُرخَّص تجارياً.
- **وثائق تجارية:** `COMMERCIAL.md` محدّث، `docs/EULA.md`، `docs/SLA.md`،
  `docs/RESPONSIBLE_USE.md`، `docs/SALES.md`، `docs/RUNBOOK.md`، `TRADEMARK.md`.

### الجودة
- **604 اختباراً** (كانت 556) وتغطية **94%** بحد 90%؛ 44 اختباراً جديداً
  لدورة الحياة (هجرة/تشخيص/ترخيص/تدقيق/ترقية).
- إصلاح انحدار في `benchmark` كان يحسب النتيجة من آخر حالة بدل عدد الناجح.

### التوثيق
- تحديث `README*` و`docs/QUALITY.md` و`docs/ROADMAP.md` و`PROJECT_REPORT.md`.

## 1.4.2 — 2026-10-25

### الجودة والاختبارات
- **556 اختبار `unittest`** (كانت 433)، وتغطية **95%** (كانت 92%) بحد CI **90%**
  (كان 85%).
- `tests/test_connector_fixtures.py` (53): اختبارات عقدية على استجابات مسجّلة
  (fixtures) لكل الموصلات الاثني عشر — تطبيع الحقول، الحدود، وأخطاء 404،
  بلا شبكة أو مفاتيح.
- `tests/test_coverage_extra.py` (50): `patcher` (النسخ الاحتياطي والاسترجاع
  وفساد ZIP/PE)، `tokenizer` (غياب tiktoken والتراجع للتقدير)،
  `strings_analyzer` (الحدود والكاش)، `yara_engine` (تحليل المخرجات)،
  و`skills` (التحقق من front matter والروابط الرمزية والاقتطاع).
- `tests/test_consistency.py` (18): بوابة تمنع انحراف الإصدار بين
  `pyproject.toml` و`__init__.py` و`CITATION.cff` و`CHANGELOG.md`، وتتحقق من
  حوكمة الحزمة وبوابات CI.

### الأمان
- **فحص أمني ثابت في CI** عبر قواعد `flake8-bandit` (`S`) داخل `ruff` — مكافئ
  لـ `bandit` بلا اعتمادية إضافية، مع استثناءات موثّقة فقط
  (`S310`/`S314`/`S104` بعد التحقق، و`S603`/`S606`/`S607` لأن التنفيذ بقوائم
  وسائط بلا shell).
- **تحصين تحليل بيان APK**: رفض `DOCTYPE`/`ENTITY` قبل `ElementTree` لمنع
  هجمات تضخّم الكيانات (billion laughs)، مع اختبارات انحدار.

### التوثيق
- تحديث `docs/QUALITY.md` و`docs/ROADMAP.md` و`PROJECT_REPORT.md` و`README*`
  بالأرقام والحالة الفعلية، ورفع بوابة التغطية إلى 90%.

## 1.4.1 — 2026-10-25

### الجودة والاختبارات
- **433 اختبار `unittest`** (كانت 325)، وتغطية **92%** (كانت 75%) بحد CI **85%**
  (كان 70%).
- `tests/test_coverage_core.py` (57): `util`، `registry`، `export`، `__main__`،
  `pe_analyzer`، و`apk_analyzer` — بما يشمل التوقيع v1–v4 وحدود APK/PE.
- `tests/test_coverage_tools.py` (51): `benchmark`، `apk_tools`، `sandbox`
  (watchdog والمهلات)، و`bindiff` (CDC، تقارير HTML، حدود التحليل).
- الوحدات الأضعف: `benchmark` 19%→100%، `sandbox` 63%→100%، `pe_analyzer`
  52%→100%، `registry` 38%→98%، `util` 58%→98%، `apk_tools` 46%→99%،
  `bindiff` 32%→93%، `apk_analyzer` 65%→95%.

### الأمان وسلسلة التوريد
- `pip-audit` ضمن اعتمادات التطوير وخطوة CI على Python 3.12 (`-r requirements.txt`).
- رفع `certifi` إلى `>=2026.10.19` لمعالجة `PYSEC-2026-4320` (كان 2026.10.18).
- تحقق حي من الموصلات بلا مفاتيح: NVD وOSV وCISA KEV عبر TLSv1.3، دون رفع عيّنات.

### التغييرات
- ترقية `actions/checkout@v7` و`actions/setup-python@v7`.
- تحديث `docs/QUALITY.md` و`docs/ROADMAP.md` و`PROJECT_REPORT.md` و`README*`
  بالأرقام والحالة الفعلية.
- لا تغيير سلوكي في واجهة CLI أو المحللات؛ إصدار تقوية جودة وأمان.

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
