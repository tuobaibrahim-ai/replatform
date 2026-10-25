# REPLATFORM

**منصة ويندوز محلية للهندسة العكسية وتحليل البرمجيات — PE · APK · YARA · Ghidra · وكلاء ذكاء اصطناعي مقيدون.**

الإصدار **1.4.1** · رخصة **MIT** · Windows 10/11 · Python 3.11+ · حالة **Beta**

[English overview](README.en.md) · [التوثيق الكامل](PLATFORM.md) · [دليل النشر](docs/DEPLOYMENT.md) · [البنية](docs/ARCHITECTURE.md) · [الجودة](docs/QUALITY.md)

---

## لماذا REPLATFORM؟

تحليل عيّنة واحدة قد يحتاج apktool وjadx وGhidra وYARA ومحرراً سداسياً وسكربتات
متناثرة — مع خطر تشغيلها على جهاز العمل. REPLATFORM يوحّد ذلك في واجهة واحدة،
ويعزل كل تحليل في مساحة عمل، ويجعل العمليات الخطرة **صريحة ومؤكَّدة**:

- **لا تنفيذ للعيّنات على المضيف.** التحليل ثابت افتراضياً. التشغيل الديناميكي
  حصراً عبر Windows Sandbox وبإذن صريح.
- **لا رفع عيّنات.** التكاملات ترسل مؤشرات/استعلامات نصية فقط، وهي معطّلة افتراضياً.
- **لا أسرار في الملفات.** مفاتيح API من متغيرات البيئة فقط.
- **كل تعديل قابل للاسترجاع.** معاينة → نسخة احتياطية → كتابة → تحقق بنيوي →
  استرجاع تلقائي عند الفشل.

## البدء السريع

### حزمة محمولة (موصى به)

```powershell
# 1) نزّل replatform-1.4.1-portable.zip من صفحة الإصدارات وتحقق من البصمة
Get-FileHash .\replatform-1.4.1-portable.zip -Algorithm SHA256

# 2) فك الضغط ثم
cd replatform-1.4.1
powershell -ExecutionPolicy Bypass -File .\install.ps1

# 3) تحقق
.\replatform.cmd version
.\replatform.cmd tools
```

### من المصدر

```powershell
git clone https://github.com/tuobaibrahim-ai/replatform.git
cd replatform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m replatform version
```

### جولة في 60 ثانية

```powershell
python -m replatform use sample.exe        # حدّد الهدف (يُحفظ)
python -m replatform analyze --open        # تحليل + تقرير HTML
python -m replatform analyze app.apk --open
python -m replatform scan samples\ --pdf   # دفعات + PDF
python -m replatform diff old.exe new.exe  # مقارنة نسختين
python -m replatform sandbox sample.exe    # خطة Windows Sandbox (بلا تشغيل)
python -m replatform serve --open          # واجهة ويب محلية برمز دخول
python -m replatform selftest --full       # 29 فحصاً للبيئة والأدوات
```

## القدرات

| المجال | ما يقدّمه |
|---|---|
| **PE** | المعمارية، الأقسام والإنتروبيا، الاستيرادات، ASLR/DEP/CFG، .NET، توقيع Authenticode |
| **APK** | الحزمة، min/target SDK، الأذونات، المكونات المصدّرة، debuggable، cleartext، ABI، توقيع v1–v4 |
| **YARA** | 19 قاعدة محلية: حزم، اعتماد على PowerShell، LSASS dumping، UPX، anti-debug، توقيعات Defender |
| **التفكيك** | Rizin (دوال + نقطة دخول) وGhidra headless (pseudocode + إعادة تسمية) |
| **التعديل** | `patch` نصي/ست عشري بمعاينة ونسخة احتياطية واسترجاع تلقائي |
| **APK دورة كاملة** | `decode → build → sign → java → install` مع تحقق فعلي من التوقيع |
| **الدفعات** | `scan` لمجلد كامل → HTML/JSON/CSV مع تحييد حقن الصيغ |
| **المقارنة** | `diff` مقاوم للإزاحة + HTML/PDF/JSON |
| **الوكلاء** | قواعدي بلا إنترنت، أو LLM متوافق مع OpenAI عبر HTTPS فقط، بأدوات قراءة فقط |
| **الويب** | لوحة محلية برمز Bearer/كوكي، allowlist مضيفين، قفل تحليل |
| **التكاملات** | 12 موصلاً قراءة فقط (NVD، OSV، CISA KEV، VirusTotal، abuse.ch، ...) |

## الأمان أولاً

| الضابط | التنفيذ |
|---|---|
| التنفيذ | لا تنفيذ افتراضي؛ Sandbox يتطلب `--run --yes` |
| الشبكة | HTTPS فقط، allowlist، رفض إعادة التوجيه، سقف استجابة |
| المفاتيح | متغيرات بيئة فقط؛ لا تُكتب في `config.json` ولا السجلات |
| الملفات | `config.json` و`state.json` و`workspaces/` مستبعدة من Git |
| التعديل | نسخة احتياطية + تحقق PE/ZIP + استرجاع تلقائي |
| الويب | `127.0.0.1` افتراضياً، رفض Host غير مسموح، رفض مسارات النظام |
| سلسلة التوريد | 3 اعتمادات تشغيل فقط + SBOM + `SHA256SUMS` لكل إصدار |

التفاصيل الكاملة: [`SECURITY.md`](SECURITY.md) · [`INTEGRATIONS.md`](INTEGRATIONS.md).

## الجودة (مُتحقَّق منها)

| المؤشر | القيمة |
|---|---|
| اختبارات `unittest` | **433** — بلا شبكة أو عيّنات حقيقية |
| تغطية الوحدات | **92%** (حد CI: 85%) |
| fuzzing | 8 خصائص × 300 + 120 = 2,520 حالة، بذرة ثابتة |
| `selftest --full` | 29/29 |
| `benchmark` | 5/5 |
| CI | Windows · Python 3.12 و3.13 · lint + compile + tests + coverage + dependency audit + build + release dry-run |
| الإصدار | SBOM (CycloneDX 1.5) + `SHA256SUMS` + ZIP محمول حتمي |

```powershell
python -m ruff check replatform tests repl.py
python -m unittest discover -s tests
python -m coverage run -m unittest discover -s tests; python -m coverage report
python -m replatform selftest --full
```

## التوثيق

| الملف | المحتوى |
|---|---|
| [`PLATFORM.md`](PLATFORM.md) | المرجع الكامل: كل أمر، الإعدادات، YARA، الويب، الإضافات |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | الطبقات، تدفق البيانات، القرارات المعمارية |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | التثبيت، الشبكة المعزولة، الترقية، استكشاف الأخطاء |
| [`docs/QUALITY.md`](docs/QUALITY.md) | البوابات، توزيع الاختبارات، قائمة الإصدار |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | الأولويات P0/P1/P2 وغير المستهدف |
| [`INTEGRATIONS.md`](INTEGRATIONS.md) | الموصلات، المفاتيح، سياسة القراءة فقط |
| [`CHANGELOG.md`](CHANGELOG.md) | سجل التغييرات |

## الترخيص والبيع

- **النواة MIT** — استخدام شخصي وتجاري وتعديل وإعادة توزيع، بلا DRM ولا مفاتيح
  تفعيل. راجع [`LICENSE`](LICENSE).
- **الدخل من الخدمات**: دعم بأولوية، نشر مؤسسي، إضافات مخصصة، مراجعة أمنية،
  وتدريب. راجع [`COMMERCIAL.md`](COMMERCIAL.md).
- تراخيص الاعتمادات والأدوات الخارجية: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## القيود المعروفة

- **Windows فقط** في 1.4.1 (Sandbox وأدوات APK/PE مرتبطة بالمنصة).
- **الأدوات الخارجية غير مضمَّنة**: Ghidra/JDK/apktool/jadx/YARA/Rizin تُثبَّت
  منفصلة؛ بدونها تظهر المحللات المرتبطة `skipped`.
- **الموصلات المجانية الثلاثة** (NVD/OSV/CISA KEV) جُرِّبت حياً بنجاح (TLSv1.3)؛
  الموصلات ذات المفاتيح لم تُجرَّب لغياب مفاتيح المالك، ورفض غياب المفتاح مُختبَر.
- **المراقبة السلوكية محدودة**: Sandbox يلتقط `stdout` فقط، لا ETW/Procmon.
- **لا توقيع كود** بعد؛ التوزيع عبر ZIP + بصمات، لا installer موقّع.

## المساهمة

اقرأ [`CONTRIBUTING.md`](CONTRIBUTING.md) و[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
للثغرات: [`SECURITY.md`](SECURITY.md) (قناة خاصة، لا Issue عام).
للدعم: [`SUPPORT.md`](SUPPORT.md).

---

© 2026 REPLATFORM contributors · MIT
