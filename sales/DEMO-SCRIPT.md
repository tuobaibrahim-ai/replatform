# سيناريو العرض الحي — REPLATFORM (25 دقيقة)

> **داخلي.** لا تستخدم عيّنة خبيثة حقيقية في أي عرض. استخدم ملفات نظام
> سليمة (مثل `notepad.exe`) أو fixtures مصنّعة، ووضّح ذلك للمشتري.

## التحضير (قبل الاجتماع)

```powershell
# 1) تثبيت نظيف
cd C:\demo\replatform-1.5.2
powershell -ExecutionPolicy Bypass -File .\install.ps1

# 2) مجلد عرض بملفات سليمة
mkdir C:\demo\samples
copy C:\Windows\System32\notepad.exe C:\demo\samples\
copy C:\Windows\System32\mspaint.exe C:\demo\samples\
copy C:\Windows\System32\calc.exe    C:\demo\samples\

# 3) ترخيص تقييم (اختياري لعرض audit)
python -m replatform.tools.license_admin issue `
  --tier professional --customer "Demo" --seats 5 --days 30 `
  --out C:\demo\eval.json
python repl.py license activate C:\demo\eval.json
python repl.py license status
```

تحقق مسبقاً من: `python repl.py version` · `python repl.py doctor` ·
`python repl.py selftest`.

## الجدول

| الدقيقة | المحور | الأمر/الحركة |
|---:|---|---|
| 0–3 | المشكلة والنطاق | لا أوامر |
| 3–8 | تحليل PE | `use` + `analyze --open` |
| 8–11 | YARA وstrings | `analyze --only pe,yara,strings` |
| 11–15 | فحص دفعات | `scan C:\demo\samples --open` |
| 15–18 | مقارنة | `diff notepad.exe mspaint.exe --open` |
| 18–21 | Sandbox بلا تنفيذ | `sandbox notepad.exe` |
| 21–24 | الترخيص والتدقيق | `license status` + `audit verify` + `audit export` |
| 24–25 | الحدود والخطوة التالية | لا أوامر |

## 1. المشكلة (3 دقائق)

قل:

> «فريقك يحلّل عيّنة فيجمع خمس أدوات على جهاز العمل. النتيجة غير قابلة للتكرار،
> وقد يُشغَّل ملف بالخطأ. REPLATFORM يوحّد التحليل، يعزل كل هدف في مساحة عمل،
> ولا ينفّذ شيئاً على المضيف افتراضياً.»

لا تقل: «يكتشف كل malware» أو «يحل محل Ghidra».

## 2. تحليل PE (5 دقائق)

```powershell
python repl.py use C:\demo\samples\notepad.exe
python repl.py analyze --open
```

اعرض في التقرير:

- المعمارية، الأقسام، الإنتروبيا.
- الاستيرادات، وسمات الحماية (ASLR/DEP/CFG).
- توقيع Authenticode إن وُجد.
- ملاحظة: «هذا ملف نظام سليم؛ لا يوجد تنفيذ.»

رسالة البيع: **نتيجة واحدة منظمة، قابلة للحفظ والمقارنة.**

## 3. YARA وstrings (3 دقائق)

```powershell
python repl.py analyze C:\demo\samples\mspaint.exe --only pe,yara,strings
```

اعرض:

- القواعد المطابقة (أو عدمها) — 19 قاعدة محلية.
- عيّنة من strings مع الحدود.
- لا ادعِ أن غياب المطابقة يعني «آمن».

## 4. فحص دفعات (4 دقائق)

```powershell
python repl.py scan C:\demo\samples --open
```

اعرض:

- جدول الملفات، النتائج، الأخطاء.
- تقرير HTML واحد بدل خمسة تقارير.
- تحييد حقن الصيغ في CSV (اذكره، لا تعرض هجوماً).

رسالة البيع: **قابلية التكرار والمراجعة.**

## 5. مقارنة (3 دقائق)

```powershell
python repl.py diff C:\demo\samples\notepad.exe C:\demo\samples\mspaint.exe --open
```

وضّح: «هذان ملفان مختلفان لعرض البنية، وليسا نسختين. في حالة العميل،
`diff old.exe new.exe` يُظهر ما تغيّر بعد تحديث.»

## 6. Sandbox بلا تنفيذ (3 دقائق)

```powershell
python repl.py sandbox C:\demo\samples\notepad.exe
```

اعرض الخطة فقط. قل صراحةً:

> «لم ننفّذ شيئاً. التنفيذ يتطلب `--run --yes` داخل Windows Sandbox،
> والشبكة معطّلة افتراضياً. نحن لا نشغّل عيّنات على مضيف العميل.»

## 7. الترخيص والتدقيق (3 دقائق)

```powershell
python repl.py license status
python repl.py audit record --event demo --target notepad.exe
python repl.py audit verify
python repl.py audit export --out C:\demo\audit-export.json
```

اعرض:

- `tier=professional` و`features` و`days_left`.
- سلسلة سليمة وعدد الأحداث.
- ملف تصدير ببصمة SHA-256.

رسالة البيع: **دليل قابل للمراجعة، لا ادعاء.**

## 8. الحدود والخطوة التالية (دقيقة)

قل بوضوح:

- Windows فقط في 1.5.2.
- الأدوات الخارجية غير مضمّنة.
- لا شهادات SOC 2/ISO، ولا pentest خارجي، ولا شهادة توقيع كود.
- الترخيص offline ولا يفرض المقاعد تقنياً.
- التقييم 30 يوماً متاح.

ثم اطلب: «أرسل عدد المستخدمين والبيئة ومتطلبات الامتثال؛ أصدر عرضاً مكتوباً
صالحاً 30 يوماً.»

## خطة بديلة عند الفشل

| العرض | الإجراء |
|---|---|
| `analyze` بطيء | استخدم `--only pe` |
| Ghidra/Rizin غائب | وضّح أنها اختيارية وتظهر `skipped` |
| PDF لا يُنشأ | استخدم HTML (`--open`) |
| Sandbox غير متاح | اعرض الخطة فقط؛ لا تشغّل |
| الترخيص مرفوض | `license status --json` ثم أعد الإصدار |
| لا إنترنت | التحليل الثابت يعمل؛ عطّل التكاملات |

## ما لا تفعله

- لا تفتح عيّنة خبيثة أو تشغّلها.
- لا تدّعِ كشفاً كاملاً أو «صفر إنذارات كاذبة».
- لا تعرض بيانات عميل آخر.
- لا ترسل `license_private.key` أو `config.json`.
- لا تعطِ سعراً غير موجود في [`PRICING.md`](PRICING.md).
