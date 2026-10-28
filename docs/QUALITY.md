# الجودة والتحقق — REPLATFORM 1.5.2

## 1. بوابات الجودة

| البوابة | الأمر | الشرط |
|---|---|---|
| Lint | `python -m ruff check replatform tests repl.py` | صفر أخطاء |
| فحص أمني ثابت | نفس الأمر أعلاه (قواعد `S` مدمجة) | صفر نتائج غير مبرَّرة |
| فحص الأنواع | `python -m mypy` | صفر أخطاء (47 ملفاً) |
| Compile | `python -m compileall -q replatform tests` | نجاح |
| Unit tests | `python -m unittest discover -s tests` | 615/615 |
| Coverage | `python -m coverage run -m unittest discover -s tests` | ≥ 90% |
| Dependency audit | `python -m pip_audit -r requirements.lock` | صفر ثغرات معروفة |
| Reproducible | `python -m replatform.tools.release --reproducible` | بصمتان متطابقتان |
| Self-test | `python -m replatform selftest` | نجاح |
| Full self-test | `python -m replatform selftest --full` | 29/29 (يدوي، أدوات خارجية) |
| Benchmark | `python -m replatform benchmark` | 5/5 |
| Release | `python -m replatform.tools.release --portable` | SBOM + بصمات + ZIP |

CI (`.github/workflows/ci.yml`) يشغّل Lint (مع `S`، ويغطي `scripts/`) وmypy
وCompile وUnit وCoverage وDependency audit وSelf-test على Windows 2022 و2025
مع Python 3.11–3.14، ويثبت الاعتماديات من `requirements-dev.lock` بالبصمات،
ويتحقق من البناء الحتمي، ويشغّل على Linux: `pip-audit` و`secretscan` وفحص
صفحة الهبوط (`scripts/site_tool.py check`) وفحص روابط الوثائق
(`scripts/linkcheck.py`) ومجموعة الاختبارات كاملة كإشارة قابلية نقل (المنتج
مدعوم على Windows فقط).

## 2. الوضع الفعلي (2026-10-26)

| المؤشر | القيمة |
|---|---|
| اختبارات `unittest` | **615** |
| تغطية الوحدات | **94%** (الحد 90%) |
| اختبارات فاشلة | 0 |
| `ruff` (بما فيه `S`) | ناجح |
| `mypy` | صفر أخطاء في 49 ملفاً |
| `pip-audit` | صفر ثغرات معروفة |
| `selftest --full` | 29/29 |
| `benchmark` | 5/5 |
| قواعد YARA | 19 |
| محللات | 6 |
| موصلات | 12 (قراءة فقط) |
| موصلات جُرِّبت حياً | 3 بلا مفاتيح (NVD/OSV/CISA KEV) |
| موصلات مغطاة باختبارات fixtures | 12/12 |

## 3. توزيع الاختبارات

| الملف | العدد | التغطية |
|---|---|---|
| `tests/test_agents.py` | 63 | المزوّدون، إعادة التوجيه، الأدوات، الحلقة، الضغط، التوكنات |
| `tests/test_coverage_core.py` | 59 | `util`، `registry`، `export`، `__main__`، `pe_analyzer`، `apk_analyzer` |
| `tests/test_connector_fixtures.py` | 53 | fixtures لكل الموصلات الاثني عشر (تطبيع + 404 + حدود) |
| `tests/test_lifecycle.py` | 55 | هجرة الإعدادات، doctor، الترخيص (RFC 8032)، التدقيق، الترقية/التراجع |
| `tests/test_coverage_tools.py` | 51 | `benchmark`، `apk_tools`، `sandbox`، `bindiff` |
| `tests/test_coverage_extra.py` | 50 | `patcher`، `tokenizer`، `strings_analyzer`، `yara_engine`، `skills` |
| `tests/test_connectors.py` | 34 | الكتالوج، HTTPS، المفاتيح، التعطيل الافتراضي |
| `tests/test_cli.py` | 25 | لقطة سطح 26 أمراً + التوزيع + المساعدات |
| `tests/test_core.py` | 24 | الإعدادات، الحالة، مساحات العمل، المهارات، التقارير |
| `tests/test_http.py` | 24 | allowlist، HTTPS، الحدود، الأخطاء، إعادة التوجيه |
| `tests/test_analyzers_extra.py` | 23 | `Target`، التشغيل، الإضافات، YARA، Rizin، Ghidra، السجل |
| `tests/test_release.py` | 23 | SBOM، البصمات، الحزمة المحمولة، `--verify` |
| `tests/test_batch_export.py` | 22 | الدفعات، CSV injection، HTML، PDF |
| `tests/test_analyzers.py` | 19 | PE، strings، الوكيل القواعدي، حواجز الويب |
| `tests/test_tools.py` | 19 | patch، bindiff، خطط Sandbox |
| `tests/test_consistency.py` | 18 | اتساق الإصدار والحوكمة وبوابات CI |
| `tests/test_hardening.py` | 17 | `android:exported`، حدود APK، التوقيع، watchdog، التكاملات |
| `tests/test_ghidra.py` | 14 | الاكتشاف، النجاح، المهلة، الأخطاء |
| `tests/test_engines.py` | 9 | YARA، تقارير المقارنة، حدود Sandbox |
| `tests/test_fuzz.py` | 9 | fuzzing حتمي لسبعة محللات مدخلات |

## 4. سياسة التغطية

- الحد **90%** مفروض في `pyproject.toml` ويفشل البناء تحته (الفعلي 94%).
- تُستثنى ثلاث نقاط دخول: `cli.py`، `tools/selftest.py`، `web/server.py`.
  **السبب:** تُختبَر تكاملياً (لقطة CLI + `selftest` + فحص يدوي للواجهة)،
  وقياسها كوحدات يُخفّض الرقم دون دلالة على جودة المنطق. الاستثناء موثّق في
  `pyproject.toml` ولا يُوسَّع بلا مراجعة.
- التغطية ليست هدفاً بحد ذاتها: كل إصلاح يضيف اختبار انحدار يفشل قبله.
- مسار التحسّن: 48% (1.3) → 75% (1.4.0) → 92% (1.4.1) → 95% (1.4.2) → 94% (1.5.0) → 94% (1.5.1) → **94% (1.5.2، إصلاحات فقط)**.

## 5. الفحص الأمني الثابت

بدل إضافة `bandit` (يفشل تثبيته على Python 3.15 لاحتياجه بناء PyYAML)، فُعّلت
قواعد **flake8-bandit** (`S`) داخل `ruff` — نفس المحرك، بلا اعتمادية جديدة،
وتعمل في CI على 3.12 و3.13.

| القاعدة | القرار | التبرير |
|---|---|---|
| `S101` | مستثناة في `selftest`/`benchmark`/`tests` | `assert` أداة تحقق مقصودة |
| `S110`/`S112` | مستثناة | تنظيف/فحص ترميزات بأفضل جهد |
| `S603`/`S606`/`S607` | مستثناة | تنفيذ بقوائم وسائط بلا shell؛ `S602` (`shell=True`) يبقى مفعّلاً |
| `S310` | `noqa` موضعي (3) | المخطط `https` مُتحقَّق، أو loopback في اختبار محلي |
| `S314` | `noqa` موضعي + تحصين | `apk_analyzer` يرفض `DOCTYPE`/`ENTITY` قبل التحليل |
| `S104` | `noqa` موضعي (2) | مقارنة/اختبار سلبي، لا ربط فعلي بكل الواجهات |

**تحصين 1.4.2:** `_parse_manifest_xml` يرفض أي `DOCTYPE` أو `ENTITY` قبل
`ElementTree.fromstring`، ما يمنع تضخّم الكيانات (billion laughs) من بيان APK
غير موثوق. يغطيه اختباران (رفض ثلاث صيغ + قبول XML عادي).

## 6. الاختبار الحتمي (Fuzzing)

`tests/test_fuzz.py` ببذرة ثابتة `20261025`:

- 8 خصائص × 300 تكرار + 120 بياناً شبه صالح = 2,520 حالة.
- يتحقق أن المدخلات العشوائية تُرفض بـ `ValueError`/`IntegrationError` المعلنة،
  لا بـ `KeyError` أو `AttributeError` أو انهيار.
- يتحقق من ثوابت بيان APK: الحزمة، عدد الأنشطة، وعدم سالبية العدادات.
- **قابل لإعادة الإنتاج:** البذرة ثابتة، فلا تقلبات عشوائية في CI.

## 7. الاختبار الذاتي

`selftest` يفحص بيئة التشغيل الفعلية (لا بدائل وهمية):

- إصدار Python، وجود الاعتمادات، سلامة الإعدادات.
- PE/APK وهميان، YARA، patch + استرجاع، تقارير، CSV.
- `--full` يضيف APK حقيقياً (فك/بناء/توقيع) وRizin وGhidra وSandbox عند توفرها.

## 8. مراجعة الإصدار (Release Checklist)

- [ ] `pyproject.toml` و`replatform/__init__.py` و`CITATION.cff` بنفس الإصدار
      (يفرضه `tests/test_consistency.py`).
- [ ] `CHANGELOG.md` يحتوي قسماً للإصدار بتاريخه.
- [ ] `ruff` (مع `S`) + `compileall` + `unittest` + `coverage` + `pip-audit` + `selftest` ناجحة.
- [ ] `python -m replatform.tools.release --portable` ينتج ZIP وSBOM وبصمات.
- [ ] `python -m replatform.tools.release --verify` يعيد `ok: true`.
- [ ] فحص ZIP: لا `__pycache__`، لا عيّنات، لا `config.json`، لا `.venv`.
- [ ] بناء `sdist` و`wheel` والتحقق من محتواهما.
- [ ] وسم `vX.Y.Z` ودفعه، ثم GitHub Release بالمخرجات.
- [ ] CI أخضر على الوسم.
- [ ] تنزيل الأصول المنشورة والتحقق من مطابقتها لـ `SHA256SUMS` المنشور.
- [ ] تشغيل `unittest` من الحزمة المنشورة نفسها.

## 9. القيود المعروفة

| القيد | الأثر | الحالة |
|---|---|---|
| موصلات ذات مفاتيح | لم تُجرَّب استجابات حية | التطبيع مغطى بـ fixtures؛ ينتظر مفاتيح المالك |
| المراقبة السلوكية | Sandbox يلتقط `stdout` فقط | حد معماري معلن |
| لا توقيع كود | Windows SmartScreen قد يحذّر | حزمة ZIP + بصمات بدلاً من installer موقّع |
| أدوات خارجية غير مضمَّنة | ميزات APK/Ghidra تتطلب تثبيتاً منفصلاً | مقصود (تراخيص وحجم) |
| `cli.py` كبير | صيانة أصعب | مؤجَّل بعد تثبيت اختبارات السطح |
