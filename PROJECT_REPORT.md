# تقرير حالة مشروع REPLATFORM

**الإصدار:** 1.3.0 · **تاريخ التقرير:** 2026-10-25 · **الترخيص:** MIT
**المستودع:** `https://github.com/tuobaibrahim-ai/replatform` (خاص) · **الفرع:** `master` · **الوسم:** `v1.3.0`

---

## 1. ملخص تنفيذي

REPLATFORM منصة ويندوز محلية للهندسة العكسية وتحليل البرمجيات، تجمع تحليل PE/APK
الثابت، YARA، التفكيك، مقارنة النسخ، فحص الدفعات، وكلاء ذكاء اصطناعي مقيدين،
وواجهة ويب محمية — مع مبدأ صارم: **لا تنفيذ للعيّنات على المضيف**، والعزل الديناميكي
اختياري وصريح عبر Windows Sandbox.

| المؤشر | القيمة |
|---|---|
| كود الإنتاج | 40 ملف Python · 8,547 سطراً |
| الاختبارات | 17 اختبار `unittest` (245 سطراً) |
| الاختبار الذاتي | 29/29 ناجح (`selftest --full`) |
| تقييم الوكيل | 5/5 (100%) في 0.53ث |
| أوامر CLI | 21 أمراً |
| المحللات | 6 |
| موصلات التكامل | 12 (قراءة فقط) |
| قواعد YARA | 10 قواعد في `rules/basic.yar` |
| مهارات الوكلاء | 9 |
| CI | 3 تشغيلات ناجحة على Windows (Python 3.12 و3.13) |
| حالة Git | شجرة نظيفة · 3 commits · وسم `v1.3.0` |

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

---

## 4. البنية التقنية

```
replatform/
├── cli.py (1074)            واجهة الأوامر
├── core/                    config · registry · state · util · export · workspace
├── analyzers/               pe · apk · strings · yara · disasm
├── agents/                  tools · provider · loop · tokenizer · heuristic
├── tools/                   selftest(914) · bindiff(548) · batch · patcher ·
│                            apk_tools · sandbox · ghidra_tools · benchmark · yara_engine
├── integrations/            connectors(758) · catalog(254) · http(171)
├── web/server.py (541)      لوحة التحكم
└── reports/__init__.py      تقارير HTML
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

**الحالة الفعلية:** كل المفاتيح غائبة ⇒ التكاملات معطّلة، ولم تُجرَّب استجابات حية.
تم التحقق من مصافحة TLS (TLSv1.3) ومن رفض غياب المفتاح بأمان.

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
| `unittest` (17) | 17/17 OK |
| `selftest --full` | 29/29 (يشمل APK وRizin وGhidra وSandbox) |
| `benchmark` | 5/5 (path_guard, compaction, timeout, usage/tokens, tool_budget) |
| GitHub Actions | 3/3 ناجحة (3.12 و3.13) — lint + compile + unit + selftest |

---

## 9. المخاطر والقيود (مرتبة)

**P0 — لا شيء مفتوح.**

**P1 — يحتاج قرار المالك:**

1. **التكاملات غير مجرَّبة حياً:** لا مفاتيح API. الأثر: لا تحقق من صحة التطبيع
   على استجابات حقيقية. المعالجة: تزويد `ABUSECH_AUTH_KEY` أولاً (يفعّل موصلين).
2. **المراقبة السلوكية محدودة:** Sandbox يلتقط stdout فقط؛ لا ETW/Procmon/تتبّع
   شبكة داخل الصندوق. الأثر: تحليل ديناميكي سطحي. المعالجة: VM بأدوات مراقبة.

**P2 — تحسينات:**

3. قواعد YARA عشر فقط؛ لا حزم قواعد مجتمعية.
4. لا قياس لتغطية الاختبارات (coverage) ولا fuzzing.
5. CI يشغّل `selftest` السريع فقط؛ `--full` يحتاج أدوات خارجية غير متاحة على runners.
6. التوثيق عربي بالكامل؛ لا README إنجليزي.
7. لا حزم إصدار (installer/wheel منشور) ولا توقيع كود للأداة.
8. الاعتماد على ثنائيات خارجية (Ghidra/JDK/jadx) غير مثبّتة عبر pip.
9. `cli.py` كبير (1074 سطراً) — مرشح للتفكيك إلى أوامر فرعية.

---

## 10. التوصيات التالية

| الأولوية | الإجراء | المالك |
|---|---|---|
| P1 | تزويد `ABUSECH_AUTH_KEY` ثم `integrations check urlhaus --live --yes` | المالك |
| P1 | تحديد نطاق المراقبة السلوكية (VM + Procmon/ETW) | المالك |
| P2 | إضافة coverage إلى CI ورفع القواعد المجتمعية | الفريق |
| P2 | تفكيك `cli.py` وإضافة README إنجليزي | الفريق |
| P2 | بناء حزمة إصدار ووسم `v1.3.1` عند أول تغيير وظيفي | الفريق |

---

## 11. سجل الإصدارات المختصر

- **1.3.0 (2026-10-23):** تقوية شاملة — validate/decode/sign آمن، دلالات
  `android:exported`، حدود المحللات، Sandbox watchdog، URLhaus/ThreatFox،
  TLS مع certifi، 17 اختباراً، CI، MIT.
- **1.2.0:** الجرد الشامل ووكيل التحليل.
- **1.1.0:** الواجهة، YARA، Rizin، Ghidra، bin-diff، الدفعات.
