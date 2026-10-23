# REPLATFORM — منصة الهندسة العكسية و تحليل البرامج

> 🚀 **منصة احترافية موحدة**: تحليل EXE و APK، مساحات عمل معزولة، تقارير HTML،
> وكلاء ذكاء اصطناعي (قواعدي بلا إنترنت أو نموذج لغوي بأدوات)، ونظام إضافات.

## البدء السريع

```powershell
python repl.py tools                 # الأدوات وإصداراتها
python repl.py use file.exe          # تحديد الملف المستهدف (يُحفظ)
python repl.py analyze               # تحليل + تقرير HTML (PE/APK)
python repl.py analyze app.apk --open
python repl.py patch --find "str:A" --replace "str:B"          # معاينة
python repl.py patch --find "str:A" --replace "str:B" --apply  # تنفيذ (نسخة احتياطية + استرجاع تلقائي)
python repl.py apk decode / build / sign / java                # دورة APK كاملة (--force لإعادة الفك بأمان)
python repl.py diff old.exe new.exe --pdf  # مقارنة نسختين + PDF
python repl.py ghidra file.exe --rename "FUN_00401000=parse_config"  # pseudocode
python repl.py scan samples\ --pdf   # فحص دفعات + PDF
python repl.py sandbox file.exe      # خطة Windows Sandbox (لا تشغيل افتراضي)
python repl.py ws report <id> --pdf --json  # تصدير PDF/JSON
python repl.py benchmark             # تقييم قبول الوكيل (5 حالات، بلا شبكة)
python repl.py selftest              # اختبار ذاتي سريع
python repl.py selftest --full       # يشمل APK وRizin (29 فحصاً)
python -m unittest discover -s tests -v  # اختبارات انحدار مستقلة (17 اختباراً)
python repl.py serve --open          # واجهة ويب محلية (أو --host + --token)
python repl.py inventory             # جرد البرامج المثبتة
python repl.py ws list               # مساحات العمل السابقة
```

التوثيق الكامل: **[PLATFORM.md](PLATFORM.md)** — يشمل تحديد الملف المستهدف،
أوامر التعديل والتطوير، YARA، التفكيك، واجهة الويب، إعداد النموذج اللغوي،
واجهة الإضافات، البنية الداخلية، والأمان.

---

# بيئة تحليل وتعديل ملفات EXE و APK

> ✅ **البيئة مُختبَرة بالكامل** — دورة عمل APK (فك ← بناء ← توقيع) وتحليل EXE تم اختبارها بنجاح على ملفات حقيقية.

## الأدوات المثبتة

### تحليل وتعديل APK
| الأداة | الوصف | الأمر |
|--------|-------|-------|
| **apktool 3.0.3** | فك وإعادة بناء APK (Smali) | `apktool d file.apk` / `apktool b folder` |
| **jadx 1.5.6** | تحويل APK إلى كود Java مفهوم | `jadx file.apk -d output` |
| **uber-apk-signer 1.3.0** | توقيع APK بعد التعديل | `java -jar uber-apk-signer.jar --apks file.apk` |
| **adb / fastboot** | التثبيت على الجهاز والاتصال | `adb install file.apk` |

### تحليل EXE
| الأداة | الوصف |
|--------|-------|
| **Detect It Easy (DIE) 3.21** | تحديد نوع الملف، الم compil، البورتايت، التشفير |
| **Cutter (Rizin)** | محلل شعاعي (Disassembler) ومحرر ثنائي |
| **Ghidra 12.1.4 + JDK 21** | تفكيك متقدم بدون واجهة وتصدير الدوال — `python repl.py ghidra file.exe` |
| **Python + pefile + capstone** | تحليل هياكل PE وتفكيك التعليمات البرمجية |

## سير العمل النموذجي

### APK: فك، تعديل، إعادة بناء، توقيع
```powershell
# 1) فك التغليف
java -jar tools\apktool.jar d app.apk -o app_decoded

# 2) تعديل الملفات (Smali في app_decoded\smali، الموارد في res\)

# 3) إعادة البناء
java -jar tools\apktool.jar b app_decoded -o app_modified.apk

# 4) التوقيع
java -jar tools\uber-apk-signer.jar --apks app_modified.apk

# 5) التثبيت على جهاز متصل
adb install app_modified-signed.apk
```

### APK: مشاهدة الكود المصدري فقط (بدون تعديل)
```powershell
jadx app.apk -d app_java        # كود Java مقروء
```

### EXE: تحليل أولي
```powershell
# تحديد النوع والحماية
powershell -File scripts\analyze-exe.ps1 -Path path\to\file.exe

# تحليل PE تفصيلي
& "C:\Program Files\Python315\python.exe" scripts\analyze_pe.py path\to\file.exe
```

## هيكل المجلدات
```
exe\
├── tools\              # أدوات التحليل
│   ├── apktool.jar     # فك/بناء APK
│   ├── uber-apk-signer.jar  # توقيع APK
│   └── jadx-cli\       # تحويل APK → Java
├── scripts\            # سكربتات تحليل جاهزة
│   ├── analyze-exe.ps1     # فحص سريع PE + SHA256
│   ├── analyze_pe.py       # تحليل PE تفصيلي
│   ├── strings_extract.py  # استخراج النصوص
│   └── apk-workflow.ps1    # دورة APK الكاملة
├── apk\                # ملفات APK ومشروعات الفك
├── bin\                # ملفات EXE قيد التحليل
└── README.md
```

## الوكلاء الآليون (`agents\`)

### 1) وكيل الجرد — `inventory_agent.ps1`
يجمع البرامج المثبتة من ثلاثة مصادر ويخرجها CSV:
- **Registry**: HKLM/HKCU (64-bit و 32-bit) مع تحديد الـ EXE الرئيسي لكل برنامج
- **Appx**: تطبيقات Microsoft Store
- **اختصارات**: سطح المكتب والقائمة ابدأ (يشمل البرامج المحمولة portable)

```powershell
.\agents\inventory_agent.ps1                    # → agents\out\installed.csv
```

### 2) وكيل التحليل — `analyze_agent.py`
تحليل جماعي **متوازٍ** (12 خيط على سبيل المثال) مع:
- تحديد النوع (PE/APK/ELF)، المعمارية، طابع البناء، حمايات النظام (ASLR/DEP/CFG)
- فحص التوقيع الرقمي **بدفعة واحدة** عبر PowerShell (موثوق وسريع — لا يعلّق)
- اكتشاف مؤشرات تحليلية: حقن عمليات، تنزيل، ثبات، مكافحة تحليل
- مطابقة الملفات مع مفاتيح التشغيل التلقائي (Run/RunOnce)
- درجة خطورة 0+ مع توصية، وتقرير **HTML ملوّن** + CSV

```powershell
python agents\analyze_agent.py "C:\Program Files" -o agents\out\analysis.csv --html agents\out\report.html --workers 12
python agents\analyze_agent.py file.exe           # ملف واحد
python agents\analyze_agent.py <مجلد> --die       # مع Detect It Easy (أبطأ)
python agents\analyze_agent.py <مجلد> --no-sign   # تخطي فحص التوقيع (أسرع)
```

### 3) وكيل التعديل — `patch_agent.py` (توافق خلفي)
الملف الآن **غلاف رفيع** يفوّض إلى `repl.py patch` والمحرك الموحّد
`replatform/tools/patcher.py`، فلا توجد نسخة ثانية من منطق التعديل فيها عيوب قديمة.
الطريقة المفضلة: `python repl.py patch`.

الحمايات:
1. **وضع العرض افتراضياً** — لا يكتب شيئاً بدون `--apply`
2. **نسخة احتياطية فريدة** لكل عملية (دقة ميكروثانية + حجز ذري)
3. **تحقق من PE/ZIP بعد الكتابة + استرجاع تلقائي** إن تلفت البنية
4. **منع تغيير طول PE/APK/ZIP** افتراضياً (`--allow-resize` للتجاوز الواعي)
5. **رفض مجلد النظام** (Windows) إلا بـ `--allow-system`
6. **بدل `??` يطابق أي بايت** — بما فيه `0x0A/0x0D` — ونصوص ascii/utf-16le

```powershell
# معاينة:
python agents\patch_agent.py app.exe --find "str:TRIAL" --replace "str:FULL"
# تطبيق أول تطابق:
python agents\patch_agent.py app.exe --find "hex:48 89 5C 24 08 C3" --replace "hex:31 C0 C3" --apply
# كل التطابقات:
python agents\patch_agent.py app.exe --find "str:Hello" --replace "str:World" --all --apply
# الطريقة الموصى بها:
python repl.py patch app.exe --find "str:Hello" --replace "str:World" --all --apply
```

### 4) المشغّل الموحد — `run_all.ps1`
يشغّل الجرد ثم التحليل ثم يعرض التقرير:
```powershell
.\agents\run_all.ps1                                # Program Files
.\agents\run_all.ps1 -ScanPath "D:\portable"        # مجلد برامج محمولة
.\agents\run_all.ps1 -SkipInventory -Workers 12
```

## التكاملات والمهارات المهنية
- كتالوج APIs ومستودعات وخدمات مجانية: `python repl.py integrations list`
- مصادر الذكاء الاصطناعي/البرمجة/الأمن/الاستضافة/قواعد البيانات: `python repl.py integrations resources`
- مهارات وكلاء محلية: `python repl.py skills list`
- تشغيل وكيل بمهارة: `python repl.py agent apk\test.apk --mode llm --skill malware-triage,apk-analysis`
- تكاملات abuse.ch الجديدة: `urlhaus` و`threatfox` (تتطلب `ABUSECH_AUTH_KEY`، قراءة فقط، وبلا رفع أو تحميل عيّنات)
- الدليل الكامل وسياسة الأمان: [`INTEGRATIONS.md`](INTEGRATIONS.md)

## تحصينات الإصدار 1.3.0
- **توقيع APK:** الإخراج داخل مجلد مؤقت معزول، ثم التحقق من ZIP ومن مخططات v1/v2/v3/v3.1/v4 قبل اعتبار التوقيع ناجحاً.
- **`android:exported`:** دلالات Android 12+ مع كشف المكونات المُصدّرة بلا `permission` وبلا قيمة صريحة عند `targetSdk >= 31`.
- **حدود APK:** رفض الملفات الضخمة، وعدد المدخلات الكبير، والزيب بوم (الحجم غير المضغوط/نسبة الضغط)، وحجم البيان بعد الفك.
- **حدود المحللات:** `pe_max_mb`, `strings_max_mb`, `yara_max_mb`, `yara_timeout`, وحدود `bindiff` مع تمثيل `skipped` بدلاً من استنزاف الذاكرة.
- **Sandbox watchdog:** إنهاء شجرة العملية تلقائياً بعد المهلة (`taskkill /T /F`) مع سقف انتظار أقصى.
- **الجودة:** `pyproject.toml`، `LICENSE` (MIT)، وCI على Windows عبر GitHub Actions.

## الاختبارات والمساهمة
```powershell
python -m unittest discover -s tests -v   # بلا شبكة أو عينات خارجية
python -m ruff check replatform tests repl.py
python repl.py selftest --full
```
الترخيص: MIT — راجع [`LICENSE`](LICENSE). وسجل التغييرات في [`CHANGELOG.md`](CHANGELOG.md).

## نتائج الاختبار الفعلي
| الاختبار | النتيجة |
|----------|---------|
| جرد البرامج | 297 برنامج (73 registry + 142 appx + 82 اختصار) |
| تحليل 29 ملف Python | 12 ثانية، 13 توقيعاً صالحاً مكتشفاً |
| تعديل 7z.exe نصاً | ✓ نسخ احتياطي مطابق + PE سليم + البرنامج يعمل |
| فحص التوقيع | يكشف Python Software Foundation ويحدد غير الموقّع بدقة |

## ملاحظات مهمة
- **إعادة تشغيل الطرفية** مطلوب مرة واحدة لتفعيل PATH الجديد (jadx, adb, cutter, diec).
- تطبيقات F-Droid الموقّعة بمفتاح التطوير تحتاج **إلغاء التثبيت أولاً** إن كانت التوقيعات مختلفة، أو استخدم `adb install -r`.
- `diec ملف.exe` يحدد النوع والمُجمِّع فوراً — نقطة البداية المثالية لأي تحليل EXE.
- لرؤية ملف PE في Cutter: `cutter ملف.exe` (تحليل شعاعي كامل مع خريطة استدعاءات).
