# تقرير حالة مشروع REPLATFORM

**الإصدار:** 1.4.2 · **تاريخ التقرير:** 2026-10-25 · **الترخيص:** MIT
**المستودع:** `https://github.com/tuobaibrahim-ai/replatform` (خاص) · **الفرع:** `master` · **الوسم:** `v1.4.2`

---

## 1. ملخص تنفيذي

REPLATFORM منصة ويندوز محلية للهندسة العكسية وتحليل البرمجيات، تجمع تحليل PE/APK
الثابت، YARA، التفكيك، مقارنة النسخ، فحص الدفعات، وكلاء ذكاء اصطناعي مقيدين،
وواجهة ويب محمية — مع مبدأ صارم: **لا تنفيذ للعيّنات على المضيف**، والعزل الديناميكي
اختياري وصريح عبر Windows Sandbox.

| المؤشر | القيمة |
|---|---|
| كود الإنتاج | 42 ملف Python · 8,768 سطراً |
| الاختبارات | 556 اختبار `unittest` |
| تغطية الوحدات | 95% (حد CI: 90%) |
| الاختبار الذاتي | 29/29 ناجح (`selftest --full`) |
| تقييم الوكيل | 5/5 (100%) في 1.2ث |
| أوامر CLI | 21 أمراً |
| المحللات | 6 |
| موصلات التكامل | 12 (قراءة فقط) |
| قواعد YARA | 19 قاعدة |
| مهارات الوكلاء | 9 |
| CI | Windows (Python 3.12 و3.13) — lint/compile/tests/coverage/audit/build |
| حالة Git | شجرة عمل 1.4.2 · الوسم `v1.4.2` |

---

## 2. المشكلة التي يحلها

تحليل البرمجيات الخبيثة وهندستها العكسية يتطلب عادةً أدوات متناثرة (apktool، jadx،
Ghidra، YARA، Rizin، محرر سداسي) وسكربتات يدوية، مع خطر تشغيل عيّنات على جهاز
العمل. REPLATFORM يوحّد ذلك في واجهة واحدة، ويعزل كل تحليل في مساحة عمل، ويجعل
العمليات الخطرة (التعديل، التنفيذ، الشبكة) **صريحة ومؤكَّدة** بدل أن تكون ضمنية.

---

## 3. القدرات الوظيفية

### 3.1 أوامر CLI (21)

`tools` · `version` · `integrations` · `skills` · `inventory` · `analyze` · `agent` ·
`use` · `current` · `patch` · `apk` · `serve` · `diff` · `ghidra` · `sandbox` ·
`benchmark` · `scan` · `selftest` · `ws` · `config` · `plugin`

### 3.2 المحللات

| المحلل | ما يستخرجه |
|---|---|
| `pe` | المعمارية، الأقسام والإنتروبيا، الاستيرادات، ASLR/DEP/CFG، .NET، توقيع Authenticode |
| `apk` | الحزمة، min/target SDK، الأذونات، المكونات المصدّرة، debuggable، cleartext، ABI، توقيع v1/v2/v3/v3.1/v4 + الشهادة |
| `strings` | ASCII/UTF-16، URLs، IPs، مسارات Registry، أوامر، مؤشرات Crypto |
| `yara` | مطابقة قواعد `rules/*.yar` |
| `disasm` | Rizin: عدد الدوال، أهم الدوال، تفكيك نقطة الدخول |
| `ghidra` | دوال Ghidra، pseudocode، إعادة تسمية، تفكيك نقطة الدخول |

الدرجة 0–10 شفافة (غير موقّع +2، إنتروبيا عالية +2، حزمة +2، حقن +2، قاعدة خطرة +2)
والحكم: منخفض / متوسط / مرتفع.

### 3.3 دورة APK

`decode` (آمن، يرفض الأهداف غير الصالحة ويحمي `--force`) → تعديل Smali/الموارد →
`build` → `sign` (مجلد مؤقت معزول + تحقق فعلي من v1/v2/v3/v3.1/v4) → `java`
(jadx) → `install` (adb).

### 3.4 التعديل والمقارنة والدفعات

- `patch`: معاينة افتراضية، نسخة احتياطية، استرجاع تلقائي عند الفشل، منع تغيير الطول
  إلا بـ `--allow-resize`، و`--all` آمن.
- `diff`: مقارنة PE وAPK مع CDC مقاوم للإزاحة وتقارير HTML/PDF/JSON.
- `scan`: فحص مجلد/ملف بدفعات مع ملخصات HTML/JSON/CSV وحدود صريحة.

### 3.5 الوكلاء والواجهة

- وكيل قواعدي بلا إنترنت، أو نموذج لغوي متوافق مع OpenAI عبر HTTPS فقط.
- أدوات الوكيل للقراءة فقط ومقيّدة بالهدف (`restrict_paths`)، بميزانيات خطوات/وقت.
- واجهة ويب محلية: رمز دخول، Bearer، كوكي، قائمة مضيفين مسموحة، قفل تحليل.

### 3.6 طبقة المنتج والإصدار

- `python -m replatform.tools.release`: SBOM (CycloneDX 1.5)، `SHA256SUMS`،
  حزمة ZIP محمولة حتمية، وأمر `--verify` للتحقق.
- `install.ps1`: بيئة افتراضية، اعتماديات، إعداد بلا مفاتيح، وتحقق تلقائي.
- `replatform.cmd`: مشغّل يستخدم `.venv` أو Python في PATH.
- حوكمة: سياسة أمان، مساهمة، سلوك، دعم، ترخيص تجاري، إشعارات أطراف ثالثة،
  وCITATION.cff.
- أتمتة: قوالب Issues/PR، Dependabot، وRelease workflow يتحقق من تطابق الوسم
  مع الإصدار قبل النشر.

---

## 4. البنية التقنية

```
replatform/
├── cli.py (1074)            واجهة الأوامر
├── core/                    config · registry · state · util · export · workspace
├── analyzers/               pe · apk · strings · yara · disasm
├── agents/                  tools · provider · loop · tokenizer · heuristic
├── tools/                   selftest(914) · bindiff(548) · batch · patcher ·
│                            apk_tools · sandbox · ghidra_tools · benchmark ·
│                            yara_engine · release (SBOM/بصمات/ZIP)
├── integrations/            connectors(758) · catalog(254) · http(171)
├── web/server.py (541)      لوحة التحكم
├── reports/__init__.py      تقارير HTML
└── docs/                    ARCHITECTURE · DEPLOYMENT · QUALITY · ROADMAP
```

أكبر الوحدات: `cli.py` 1074، `selftest.py` 914، `connectors.py` 758، `bindiff.py` 548،
`server.py` 541، `apk_analyzer.py` 519.

---

## 5. نموذج الأمان (الضوابط المطبَّقة)

| المجال | الضابط |
|---|---|
| التنفيذ | لا تنفيذ على المضيف؛ Sandbox يتطلب `--run --yes`، الشبكة معطلة افتراضياً |
| Sandbox | watchdog ينهي شجرة العملية (`taskkill /T /F`)، سقف 3600ث، `watchdog_triggered` مسجّل |
| APK | `validate_apk`: حجم، نسبة ضغط (zip bomb)، عدد مدخلات، فك بحدود زمنية |
| التوقيع | مجلد مؤقت معزول، رفض مسار إخراج غير مجلد، تحقق مخططات v1–v4 |
| patch | نسخة احتياطية + استرجاع تلقائي + منع تغيير الطول افتراضياً |
| الوكيل | مسارات مقيدة، `max_steps=8`، `tool_timeout=120`، مزوّد HTTPS فقط بلا redirect |
| الويب | رمز + Bearer + كوكي، رفض Host غير مسموح، منع استهداف مجلدات النظام |
| التكاملات | HTTPS فقط، allowlist، قراءة فقط، مفاتيح من البيئة، معطّلة افتراضياً |
| TLS | تحقق إلزامي للشهادة والمضيف مع `certifi` |
| البيانات | لا رفع عيّنات؛ استعلامات ومؤشرات نصية فقط؛ `config.json` مستبعد من Git |
| CSV | تحييد حقن الصيغ في مخرجات `scan` |

حدود التحليل الافتراضية: `max_file_mb=1024`، `pe/apk/strings/yara=512`،
`apk_uncompressed=2048`، `apk_max_entries=50000`، `disasm=200`، `ghidra=150`،
`bindiff_parse=256`، `integrations.timeout=20`.

---

## 6. التكاملات الخارجية (12 موصلاً، قراءة فقط)

| المعرّف | الفئة | الاعتماد |
|---|---|---|
| nvd · cisa_kev · osv | ثغرات/سلسلة توريد | بدون مفتاح |
| github · huggingface | كود/نماذج | اختياري |
| virustotal · otx · malwarebazaar | برمجيات خبيثة | مفتاح |
| abuseipdb · shodan | استخبارات/سطح هجوم | مفتاح |
| urlhaus · threatfox | abuse.ch | `ABUSECH_AUTH_KEY` |

**الحالة الفعلية:** الموصلات الثلاثة بلا مفاتيح (NVD/OSV/CISA KEV) جُرِّبت حياً
بنجاح عبر `integrations check <id> --live --yes` ومصافحة TLSv1.3. المفاتيح الأخرى
غائبة ⇒ تلك الموصلات معطّلة، ورفض غياب المفتاح مُختبَر بأمان.

---

## 7. البيئة والأدوات

Java 11 · JDK 21 (Ghidra) · apktool 3.0.3 · jadx 1.5.6 · Detect It Easy 3.21 ·
ADB 1.0.41 · 7-Zip 26.04 · Cutter (Rizin) · YARA · Ghidra · Python 3.15.0.

Windows Sandbox: الميزة `Containers-DisposableClientVM = Enabled`،
`vmcompute`/`vmms` يعملان، وتحقّق ميداني ناجح (VM فعلية + تنفيذ عينة PE غير ضارة
داخلها + إعادة `stdout.txt` إلى المضيف).

---

## 8. الجودة والتحقق

| البوابة | النتيجة |
|---|---|
| `ruff check replatform tests repl.py` | ناجح |
| `compileall` | ناجح |
| `unittest` (556) | 556/556 OK |
| `coverage` (وحدات المنطق) | 95% — الحد الأدنى 90% |
| `ruff` مع قواعد `S` | صفر نتائج غير مبرَّرة (فحص أمني ثابت) |
| `pip-audit -r requirements.txt` | صفر ثغرات معروفة |
| `selftest --full` | 29/29 (يشمل APK وRizin وGhidra وSandbox) |
| `benchmark` | 5/5 (path_guard, compaction, timeout, usage/tokens, tool_budget) |
| أدوات الإصدار | SBOM + بصمات + ZIP محمول؛ `--verify` يعيد `ok: true` |
| GitHub Actions | lint + compile + unit + coverage + dependency audit + build + release dry-run (3.12 و3.13) |

---

## 9. المخاطر والقيود (مرتبة)

**P0 — لا شيء مفتوح.**

**P1 — يحتاج قرار المالك:**

1. **موصلات المفاتيح غير مجرَّبة حياً:** لا مفاتيح API للموصلات التسعة ذات
   المفاتيح. الأثر: لا تحقق من صحة التطبيع على استجاباتها الحقيقية. **ما أُغلق:**
   التطبيع مغطى الآن بـ 53 اختباراً عقدياً على fixtures مصنّعة لكل الموصلات
   الاثني عشر (حدود، 404، صيغ مرفوضة). **المتبقي:** تزويد المفاتيح وتشغيل
   `integrations check <id> --live --yes` واستبدال fixtures باستجابات حية.
   (الموصلات الثلاثة بلا مفاتيح جُرِّبت حياً بنجاح.)
2. **المراقبة السلوكية محدودة:** Sandbox يلتقط `stdout` فقط؛ لا ETW/Procmon/تتبّع
   شبكة داخل الصندوق. الأثر: تحليل ديناميكي سطحي. المعالجة: VM بأدوات مراقبة.

**P2 — تحسينات:**

3. قواعد YARA 19 قاعدة محلية؛ لا حزم قواعد مجتمعية (Sigma/خ) بعد.
4. التغطية 95% (كانت 92%)؛ الهدف التالي 97% مع التركيز على `reports`
   و`catalog` و`disasm_analyzer`، ثم `cli.py` بعد تفكيكه.
5. CI يشغّل `selftest` السريع فقط؛ `--full` يحتاج أدوات خارجية غير متاحة على runners.
6. التوثيق عربي أساساً مع دليل إنجليزي (`README.en.md`) ووثائق هندسية في `docs/`.
7. لا توقيع كود؛ التوزيع ZIP + بصمات بدل installer موقّع (قرار متحفظ بلا شهادة).
8. الاعتماد على ثنائيات خارجية (Ghidra/JDK/jadx) غير مثبّتة عبر pip.
9. `cli.py` كبير (1074 سطراً) — مرشح للتفكيك بعد تثبيت لقطة سطح الأوامر.
10. **Windows فقط** في 1.4.2؛ لا دعم Linux للتحليل الثابت بعد.

---

## 10. التوصيات التالية

| الأولوية | الإجراء | المالك |
|---|---|---|
| P1 | تزويد `ABUSECH_AUTH_KEY` ثم `integrations check urlhaus --live --yes` | المالك |
| P1 | تحديد نطاق المراقبة السلوكية (VM + Procmon/ETW) | المالك |
| P2 | رفع التغطية إلى 97% (`reports`/`catalog`/`disasm_analyzer`) | الفريق |
| P2 | تفكيك `cli.py` إلى أوامر فرعية | الفريق |
| P2 | دراسة دعم Linux للتحليل الثابت بلا Sandbox | الفريق |
| P2 | installer موقّع عند توفر شهادة توقيع كود | الفريق |

---

## 11. سجل الإصدارات المختصر

- **1.4.2 (2026-10-25):** إغلاق فجوات الثقة — 556 اختباراً وتغطية 95% (حد 90%)،
  fixtures لكل الموصلات الاثني عشر، فحص أمني ثابت بقواعد `S` داخل `ruff`،
  تحصين بيان APK ضد `DOCTYPE`/`ENTITY`، وبوابة اتساق الإصدار والحوكمة.
- **1.4.1 (2026-10-25):** تقوية جودة — 433 اختباراً وتغطية 92% (حد 85%)،
  تغطية شبه كاملة للوحدات الأضعف، `pip-audit` في CI، رفع `certifi` إلى
  `>=2026.10.19`، وتحقق حي من NVD/OSV/CISA KEV.
- **1.4.0 (2026-10-25):** طبقة منتج — 325 اختباراً وتغطية 75% (حد 70%)،
  حزمة محمولة + SBOM + بصمات، حوكمة ووثائق هندسية، Dependabot وRelease workflow،
  و`python -m replatform`.
- **1.3.1 (2026-10-25):** جودة — 122 اختباراً (منها 34 تعاقدية للموصلات)،
  تغطية 48% بحد CI 45%، 9 قواعد YARA إضافية، `README.en.md`، وترقية إجراءات CI.
- **1.3.0 (2026-10-23):** تقوية شاملة — validate/decode/sign آمن، دلالات
  `android:exported`، حدود المحللات، Sandbox watchdog، URLhaus/ThreatFox،
  TLS مع certifi، 17 اختباراً، CI، MIT.
- **1.2.0:** الجرد الشامل ووكيل التحليل.
- **1.1.0:** الواجهة، YARA، Rizin، Ghidra، bin-diff، الدفعات.
