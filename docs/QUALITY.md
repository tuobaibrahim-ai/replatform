# الجودة والتحقق — REPLATFORM 1.4.1

## 1. بوابات الجودة

| البوابة | الأمر | الشرط |
|---|---|---|
| Lint | `python -m ruff check replatform tests repl.py` | صفر أخطاء |
| Compile | `python -m compileall -q replatform tests` | نجاح |
| Unit tests | `python -m unittest discover -s tests` | 433/433 |
| Coverage | `python -m coverage run -m unittest discover -s tests` | ≥ 85% |
| Dependency audit | `python -m pip_audit -r requirements.txt` | صفر ثغرات معروفة |
| Self-test | `python -m replatform selftest` | نجاح |
| Full self-test | `python -m replatform selftest --full` | 29/29 (يدوي، أدوات خارجية) |
| Benchmark | `python -m replatform benchmark` | 5/5 |
| Release | `python -m replatform.tools.release --portable` | SBOM + بصمات + ZIP |

CI (`.github/workflows/ci.yml`) يشغّل Lint وCompile وUnit وCoverage وDependency
audit وSelf-test على Windows مع Python 3.12 و3.13، إضافة إلى بناء الحزم
وتشغيل أدوات الإصدار (dry run) على Python 3.12.

## 2. الوضع الفعلي (2026-10-25)

| المؤشر | القيمة |
|---|---|
| اختبارات `unittest` | **433** |
| تغطية الوحدات | **92%** (الحد 85%) |
| اختبارات فاشلة | 0 |
| `ruff` | ناجح |
| `pip-audit` | صفر ثغرات معروفة |
| `selftest --full` | 29/29 |
| `benchmark` | 5/5 |
| قواعد YARA | 19 |
| محللات | 6 |
| موصلات | 12 (قراءة فقط) |
| موصلات جُرِّبت حياً | 3 بلا مفاتيح (NVD/OSV/CISA KEV) |

## 3. توزيع الاختبارات

| الملف | العدد | التغطية |
|---|---|---|
| `tests/test_agents.py` | 63 | المزوّدون، إعادة التوجيه، الأدوات، الحلقة، الضغط، التوكنات |
| `tests/test_coverage_core.py` | 57 | `util`، `registry`، `export`، `__main__`، `pe_analyzer`، `apk_analyzer` |
| `tests/test_coverage_tools.py` | 51 | `benchmark`، `apk_tools`، `sandbox`، `bindiff` |
| `tests/test_connectors.py` | 34 | الموصلات الاثنا عشر بلا شبكة أو مفاتيح |
| `tests/test_cli.py` | 25 | لقطة سطح 21 أمراً + التوزيع + المساعدات |
| `tests/test_core.py` | 24 | الإعدادات، الحالة، مساحات العمل، المهارات، التقارير |
| `tests/test_http.py` | 24 | allowlist، HTTPS، الحدود، الأخطاء، إعادة التوجيه |
| `tests/test_analyzers_extra.py` | 23 | `Target`، التشغيل، الإضافات، YARA، Rizin، Ghidra، السجل |
| `tests/test_release.py` | 23 | SBOM، البصمات، الحزمة المحمولة، `--verify` |
| `tests/test_batch_export.py` | 22 | الدفعات، CSV injection، HTML، PDF |
| `tests/test_analyzers.py` | 19 | PE، strings، الوكيل القواعدي، حواجز الويب |
| `tests/test_tools.py` | 19 | patch، bindiff، خطط Sandbox |
| `tests/test_hardening.py` | 17 | `android:exported`، حدود APK، التوقيع، watchdog، التكاملات |
| `tests/test_ghidra.py` | 14 | الاكتشاف، النجاح، المهلة، الأخطاء |
| `tests/test_engines.py` | 9 | YARA، تقارير المقارنة، حدود Sandbox |
| `tests/test_fuzz.py` | 9 | fuzzing حتمي لسبعة محللات مدخلات |

## 4. سياسة التغطية

- الحد **85%** مفروض في `pyproject.toml` ويفشل البناء تحته (الفعلي 92%).
- تُستثنى ثلاث نقاط دخول: `cli.py`، `tools/selftest.py`، `web/server.py`.
  **السبب:** تُختبَر تكاملياً (لقطة CLI + `selftest` + فحص يدوي للواجهة)،
  وقياسها كوحدات يُخفّض الرقم دون دلالة على جودة المنطق. الاستثناء موثّق في
  `pyproject.toml` ولا يُوسَّع بلا مراجعة.
- التغطية ليست هدفاً بحد ذاتها: كل إصلاح يضيف اختبار انحدار يفشل قبله.
- الوحدات التي كانت الأضعف في 1.4.0 (`benchmark` 19%، `bindiff` 32%،
  `registry` 38%، `apk_tools` 46%، `pe_analyzer` 52%، `util` 58%،
  `sandbox` 63%، `apk_analyzer` 65%) أصبحت بين 93% و100% في 1.4.1.

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
- `--full` يضيف APK حقيقياً (فك/بناء/توقيع) وRizin وGhidra وSandbox عند توفرها.

## 7. مراجعة الإصدار (Release Checklist)

- [ ] `pyproject.toml` و`replatform/__init__.py` و`CITATION.cff` بنفس الإصدار.
- [ ] `CHANGELOG.md` يحتوي قسماً للإصدار بتاريخه.
- [ ] `ruff` + `compileall` + `unittest` + `coverage` + `pip-audit` + `selftest` ناجحة.
- [ ] `python -m replatform.tools.release --portable` ينتج ZIP وSBOM وبصمات.
- [ ] `python -m replatform.tools.release --verify` يعيد `ok: true`.
- [ ] فحص ZIP: لا `__pycache__`، لا عيّنات، لا `config.json`، لا `.venv`.
- [ ] بناء `sdist` و`wheel` والتحقق من محتواهما.
- [ ] وسم `vX.Y.Z` ودفعه، ثم GitHub Release بالمخرجات.
- [ ] CI أخضر على الوسم.

## 8. القيود المعروفة

| القيد | الأثر | الحالة |
|---|---|---|
| موصلات ذات مفاتيح | لم تُجرَّب استجابات حية | موثّق؛ ينتظر مفاتيح المالك |
| المراقبة السلوكية | Sandbox يلتقط `stdout` فقط | حد معماري معلن |
| لا توقيع كود | Windows SmartScreen قد يحذّر | حزمة ZIP + بصمات بدلاً من installer موقّع |
| أدوات خارجية غير مضمَّنة | ميزات APK/Ghidra تتطلب تثبيتاً منفصلاً | مقصود (تراخيص وحجم) |
| `bandit` غير مُفعَّل | تحليل أمني ثابت إضافي | مؤجَّل؛ `pip-audit` وDependabot مفعّلان |
| `cli.py` كبير | صيانة أصعب | مؤجَّل بعد تثبيت اختبارات السطح |
