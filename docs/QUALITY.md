# الجودة والتحقق — REPLATFORM 1.4.0

## 1. بوابات الجودة

| البوابة | الأمر | الشرط |
|---|---|---|
| Lint | `python -m ruff check replatform tests repl.py` | صفر أخطاء |
| Compile | `python -m compileall -q replatform tests` | نجاح |
| Unit tests | `python -m unittest discover -s tests` | 325/325 |
| Coverage | `python -m coverage run -m unittest discover -s tests` | ≥ 70% |
| Self-test | `python -m replatform selftest` | نجاح |
| Full self-test | `python -m replatform selftest --full` | 29/29 (يدوي، أدوات خارجية) |
| Benchmark | `python -m replatform benchmark` | 5/5 |
| Release | `python -m replatform.tools.release --portable` | SBOM + بصمات + ZIP |

CI (`.github/workflows/ci.yml`) يشغّل Lint وCompile وUnit وCoverage وSelf-test
على Windows مع Python 3.12 و3.13.

## 2. الوضع الفعلي (2026-10-25)

| المؤشر | القيمة |
|---|---|
| اختبارات `unittest` | **325** |
| تغطية الوحدات | **75%** (الحد 70%) |
| اختبارات فاشلة | 0 |
| `ruff` | ناجح |
| `selftest --full` | 29/29 |
| `benchmark` | 5/5 |
| قواعد YARA | 19 |
| محللات | 6 |
| موصلات | 12 (قراءة فقط) |

## 3. توزيع الاختبارات

| الملف | العدد | التغطية |
|---|---|---|
| `tests/test_agents.py` | 63 | المزوّدون، إعادة التوجيه، الأدوات، الحلقة، الضغط، التوكنات |
| `tests/test_http.py` | 24 | allowlist، HTTPS، الحدود، الأخطاء، إعادة التوجيه |
| `tests/test_cli.py` | 25 | لقطة سطح 21 أمراً + التوزيع + المساعدات |
| `tests/test_analyzers_extra.py` | 23 | `Target`، التشغيل، الإضافات، YARA، Rizin، Ghidra، السجل |
| `tests/test_batch_export.py` | 22 | الدفعات، CSV injection، HTML، PDF |
| `tests/test_ghidra.py` | 14 | الاكتشاف، النجاح، المهلة، الأخطاء |
| `tests/test_fuzz.py` | 9 | fuzzing حتمي لسبعة محللات مدخلات |
| `tests/test_release.py` | 23 | SBOM، البصمات، الحزمة المحمولة، `--verify` |
| اختبارات 1.3.x | 122 | APK، patch، sandbox، تكاملات، تقارير، أمان |

## 4. سياسة التغطية

- الحد **70%** مفروض في `pyproject.toml` ويفشل البناء تحته.
- تُستثنى ثلاث نقاط دخول: `cli.py`، `tools/selftest.py`، `web/server.py`.
  **السبب:** تُختبَر تكاملياً (لقطة CLI + `selftest` + فحص يدوي للواجهة)،
  وقياسها كوحدات يُخفّض الرقم دون دلالة على جودة المنطق. الاستثناء موثّق في
  `pyproject.toml` ولا يُوسَّع بلا مراجعة.
- التغطية ليست هدفاً بحد ذاتها: كل إصلاح يضيف اختبار انحدار يفشل قبله.

## 5. الاختبار الحتمي (Fuzzing)

`tests/test_fuzz.py` ببذرة ثابتة `20261025`:

- 8 خصائص × 300 تكرار + 120 بياناً شبه صالح = 2,520 حالة.
- يتحقق أن المدخلات العشوائية تُرفض بـ `ValueError`/`IntegrationError` المعلنة،
  لا بـ `KeyError` أو `AttributeError` أو انهيار.
- يتحقق من ثوابت بيان APK: الحزمة، عدد الأنشطة، وعدم سالبية العدادات.
- **قابل لإعادة الإنتاج:** البذرة ثابتة، فلا تقلبات عشوائية في CI.

## 6. الاختبار الذاتي

`selftest` يفحص بيئة التشغيل الفعلية (لا بدائل وهمية):

- إصدار Python، وجود الاعتمادات، سلامة الإعدادات.
- PE/APK وهميان، YARA، patch + استرجاع، تقارير، CSV.
- `--full` يضيف APK حقيقي (فك/بناء/توقيع) وRizin وGhidra وSandbox عند توفرها.

## 7. مراجعة الإصدار (Release Checklist)

- [ ] `pyproject.toml` و`replatform/__init__.py` و`CITATION.cff` بنفس الإصدار.
- [ ] `CHANGELOG.md` يحتوي قسماً للإصدار بتاريخه.
- [ ] `ruff` + `compileall` + `unittest` + `coverage` + `selftest` ناجحة.
- [ ] `python -m replatform.tools.release --portable` ينتج ZIP وSBOM وبصمات.
- [ ] `python -m replatform.tools.release --verify` يعيد `ok: true`.
- [ ] فحص ZIP: لا `__pycache__`، لا عيّنات، لا `config.json`، لا `.venv`.
- [ ] بناء `sdist` و`wheel` والتحقق من محتواهما.
- [ ] وسم `vX.Y.Z` ودفعه، ثم GitHub Release بالمخرجات.
- [ ] CI أخضر على الوسم.

## 8. القيود المعروفة

| القيد | الأثر | الحالة |
|---|---|---|
| التكاملات بلا مفاتيح | لم تُجرَّب استجابات حية | موثّق؛ ينتظر مفاتيح المالك |
| المراقبة السلوكية | Sandbox يلتقط `stdout` فقط | حد معماري معلن |
| لا توقيع كود | Windows SmartScreen قد يحذّر | حزمة ZIP + بصمات بدلاً من installer موقّع |
| أدوات خارجية غير مضمَّنة | ميزات APK/Ghidra تتطلب تثبيتاً منفصلاً | مقصود (تراخيص وحجم) |
| تغطية 75% | أجزاء من `apk_tools`/`bindiff` غير مغطاة | مرشحة لـ 1.5 |
| `cli.py` كبير | صيانة أصعب | مؤجَّل بعد تثبيت اختبارات السطح |
