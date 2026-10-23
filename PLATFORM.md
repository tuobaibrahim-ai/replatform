# REPLATFORM — منصة الهندسة العكسية

منصة موحدة لتحليل البرامج (EXE / APK) وهندستها العكسية وتعديلها وتطويرها،
بواجهة سطر أوامر واحدة، **ملف مستهدف دائم**، مساحات عمل معزولة، تقارير HTML،
واجهة ويب محلية، ونظام وكلاء ذكاء اصطناعي (قواعدي بلا إنترنت أو نموذج لغوي بأدوات).

---

## 1. البدء السريع

```powershell
python repl.py tools                    # فحص الأدوات وإصداراتها
python repl.py use app.exe              # حدد الملف المستهدف (يُحفظ)
python repl.py analyze                  # تحليل الملف الحالي + تقرير
python repl.py analyze app.apk --open   # تحليل APK وفتح التقرير
python repl.py serve --open             # واجهة ويب محلية
python repl.py inventory                # جرد البرامج المثبتة
python repl.py ws list                  # كل مساحات العمل
```

كل تحليل يُنشئ مجلداً مستقلاً في `workspaces\`:

```
workspaces\20261020-015129-targeted-calc\
├── meta.json          # بيانات الهدف (الاسم، النوع، SHA256، الحجم)
├── timeline.jsonl     # سجل زمني لكل خطوة
├── artifacts\         # نتائج المحللات (JSON)
│   ├── pe.json
│   ├── apk.json
│   ├── strings.json
│   ├── yara.json
│   └── disasm.json
├── agent\
│   ├── summary.md     # الخلاصة (قواعدية)
│   ├── answer.md      # إجابة النموذج اللغوي (إن استُخدم)
│   └── llm.json       # المحادثة الكاملة مع الأدوات
└── report.html        # لوحة التقرير النهائية
```

---

## 2. تحديد الملف المستهدف (EXE / APK)

بدل تكرار المسار في كل أمر:

```powershell
python repl.py use "C:\Apps\MyApp.exe"     # EXE
python repl.py use "C:\Apps\app.apk"       # APK
python repl.py current                     # ماذا محدد الآن؟
```

بعدها كل الأوامر تعمل على الملف نفسه دون تمرير مسار:
`analyze`، `agent`، `patch`، و`apk decode/sign/java/install`.
يمكن دائماً تمرير مسار صريح لتجاوز الملف المحدد:
`python repl.py analyze other.exe`.

الحالة تُحفظ في `state.json` (محلي فقط).

---

## 3. الأوامر

| الأمر | الوصف |
|-------|-------|
| `python repl.py tools` | جدول الأدوات المتاحة وإصداراتها |
| `python repl.py use <ملف>` | تحديد الملف المستهدف الدائم |
| `python repl.py current` | عرض الملف المستهدف |
| `python repl.py inventory [--out CSV]` | جرد البرامج المثبتة (Registry + Appx + اختصارات) |
| `python repl.py analyze [ملف] [--name] [--only pe,apk,strings,yara,disasm] [--agent heuristic\|llm\|none] [--task "…"] [--open]` | تحليل كامل |
| `python repl.py agent [ملف] [--task "…"] [--mode heuristic\|llm]` | تحليل + مهمة مخصصة للوكيل |
| `python repl.py patch [ملف] --find … --replace … [--apply] [--all] [--enc ascii\|utf16le] [--allow-system] [--allow-resize]` | تعديل ثنائي آمن (معاينة افتراضياً) |
| `python repl.py diff <A> <B> [--pdf] [--open]` | مقارنة نسختين PE/APK (CDC + PDF) |
| `python repl.py ghidra [ملف] [--no-decompile] [--decompile-limit N] [--rename old=new]` | Ghidra headless + pseudocode وإعادة تسمية |
| `python repl.py scan <مجلد\|ملف> [--all] [--deep] [--pdf] [--max N]` | فحص دفعات مع ملخص HTML/PDF/JSON/CSV |
| `python repl.py sandbox [ملف] [--out مجلد] [--network] [--run --yes]` | خطة عزل Windows Sandbox (تشغيل افتراضي: لا) |
| `python repl.py benchmark [--json] [--out ملف]` | تقييم قبول الوكيل: مسارات، ضغط، مهلة، tokens، ميزانية أدوات |
| `python repl.py selftest [--full]` | اختبار ذاتي للمنصة (مناسب لـ CI) |
| `python repl.py apk decode [ملف] [--out مجلد] [--force]` | فك APK إلى smali + موارد (قابل لإعادة البناء) |
| `python repl.py apk build <مجلد> [--out ملف]` | إعادة بناء APK من مجلد مفكوك |
| `python repl.py apk sign [ملف] [--out مجلد]` | توقيع APK (v1+v2+v3) |
| `python repl.py apk java [ملف] [--out مجلد]` | استخراج كود Java للقراءة/التطوير (jadx) |
| `python repl.py apk install [ملف]` / `apk devices` | تثبيت على جهاز متصل / عرض الأجهزة |
| `python repl.py ws list / show <id> / open <id> / report <id> [--pdf] [--json]` | إدارة مساحات العمل وتصدير HTML/PDF/JSON |
| `python repl.py serve [--host] [--port] [--token] [--allowed-host] [--open]` | واجهة ويب محلية أو محمية برمز |
| `python repl.py config init/show` | إنشاء/عرض الإعدادات (المفتاح مُقنّع) |
| `python repl.py plugin new <اسم>` | توليد إضافة محلل جديدة |

---

## 4. المحللات (Analyzers)

| المحلل | يغطي | ما يستخرجه |
|--------|------|-------------|
| `pe` | PE32/PE32+ | المعمارية، الأقسام والإنتروبيا، الاستيرادات، ASLR/DEP/CFG، .NET، التوقيع Authenticode، مؤشرات أولية |
| `apk` | APK | الحزمة، الإصدار، min/target SDK، الأذونات، المكونات المُصدّرة، debuggable، cleartext، ABI، توقيع v1/v2/v3/v3.1/v4 (sidecar) + الشهادة |
| `strings` | كل الأنواع | نصوص ASCII/UTF-16، URLs، عناوين IP، مسارات Registry، أوامر، Crypto |
| `yara` | كل الأنواع | مطابقة قواعد `rules/*.yar` (حزم، حقن، PowerShell مشفّر، نصوص فدية…) |
| `disasm` | PE / ELF | تفكيك بدون واجهة عبر Rizin: عدد الدوال، أهم الدوال، تفكيك نقطة الدخول |
| `ghidra` | PE / ELF | تفكيك متقدم عند الطلب: دوال Ghidra، pseudocode لأهم الدوال، إعادة تسمية، وتفكيك نقطة الدخول (اختياري) |

الدرجة **0–10** تُجمع من مؤشرات شفافة (غير موقّع +2، إنتروبيا عالية +2،
حزمة +2، حقن +2، قاعدة YARA خطرة +2…) والحكم: `منخفض` / `متوسط` / `مرتفع`.

### قواعد YARA
ضع ملفات `*.yar` في مجلد `rules\` وستُحمَّل تلقائياً في كل تحليل.
مثال:

```yara
rule My_Indicator
{
    strings:
        $a = "secret-marker" ascii wide
    condition:
        $a
}
```

### نظام الإضافات
كل ملف في `plugins\` يمكنه تعريف محلل جديد:

```python
from replatform.analyzers import Analyzer, Target

class MyAnalyzer(Analyzer):
    name = "myrule"
    description = "قاعدة مخصصة"

    def can_handle(self, target: Target) -> bool:
        return target.kind == "PE"

    def run(self, target: Target, ws) -> dict:
        return {"score": 1, "verdict": "warn",
                "findings": ["ملاحظة"], "custom": target.sha256}
```

```powershell
python repl.py plugin new myrule      # يولّد القالب
python repl.py analyze file.exe --only myrule
```

---

## 5. التعديل والتطوير

### أ) EXE / DLL — تعديل ثنائي آمن
```powershell
python repl.py use app.exe

# معاينة (لا يكتب شيئاً) — الافتراضي
python repl.py patch --find "str:TRIAL" --replace "str:FULL"

# تنفيذ فعلي (نسخة احتياطية إجبارية + تحقق من بنية PE)
python repl.py patch --find "hex:48 89 5C 24 08 C3" --replace "hex:31 C0 C3" --apply

# كل التطابقات
python repl.py patch --find "str:Hello" --replace "str:World" --all --apply
```
الضمانات: معاينة افتراضية، نسخة `*.bak.<وقت>` فريدة لكل عملية، إعادة تحليل PE بعد
الكتابة مع **استرجاع تلقائي** إن تلفت البنية، وفحص CRC لملفات APK/ZIP.
يُرفض تغيير طول ملفات PE/APK/ZIP افتراضياً (يفسد الإزاحات الداخلية) إلا مع
`--allow-resize`؛ ويرفض التعديل داخل مجلدات النظام إلا بـ `--allow-system`.
ملاحظة: أي تعديل على ملف موقّع يُبطل توقيعه الرقمي.

### ب) APK — دورة تعديل وتطوير كاملة
```powershell
python repl.py use app.apk
python repl.py apk decode                 # → app-decoded\ (smali + res + lib)
# إن كان المجلد موجوداً، يرفض الفك لحماية تعديلاتك — أعد الفك بـ:
python repl.py apk decode --force
# عدّل smali أو الموارد أو AndroidManifest.xml
python repl.py apk build app-decoded      # → app-decoded-rebuilt.apk
python repl.py apk sign app-decoded-rebuilt.apk   # → signed\...-debugSigned.apk
python repl.py apk install signed\...apk  # إن وُجد جهاز متصل
```
لقراءة الكود وفهمه (وليس لإعادة البناء):
```powershell
python repl.py apk java                   # → app-java\ (مصادر Java)
```

---

## 6. مقارنة النسخ (bin-diff)

قارن نسختين من نفس البرنامج/الحزمة لمعرفة ما تغيّر بالضبط:

```powershell
python repl.py diff old\app.exe new\app.exe --open
python repl.py diff old\app.apk new\app.apk
```

**التشابه:** CDC (Content-Defined Chunking) عبر نافذة Rolling Hash، لذلك لا يتأثر
بإدراج بايتات في بداية الملف؛ الملفات الصغيرة تُقارن بدقة، والكبيرة جداً (>32MB)
تستخدم كتلاً ثابتة. النوع يُعرض بجانب النسبة.

**PE:** خصائص الملف (نقطة الدخول، وقت البناء، .NET)، الأقسام (متغير/مضاف/محذوف +
الإنتروبيا)، والاستيرادات المضافة/المحذوفة مع تنبيه للدوال الحساسة الجديدة.

**APK:** خصائص البيان (الإصدار، SDK، المكوّنات المُصدّرة)، الأذونات المضافة/المحذوفة،
ملفات الحزمة (مضافة/محذوفة/متغيرة/غير متغيرة)، ومخططات التوقيع والشهادة.

المخرجات: `diffs\<وقت>-<A>-vs-<B>\report.html` + `diff.json`، و`--pdf` يضيف
`report.pdf`، وتظهر أيضاً في لوحة الويب المحلية.

---

## 7. Ghidra headless (تفكيك متقدم)

اختياري — يعمل عند توفره فقط، ولا يُشغَّل تلقائياً مع كل تحليل (لأنه أبطأ):

```powershell
python repl.py ghidra app.exe          # أو: analyze --only ghidra
python repl.py ghidra app.exe --decompile-limit 8
python repl.py ghidra app.exe --rename "FUN_00401000=parse_config"
python repl.py ghidra app.exe --no-decompile --rename "FUN_00401000=parse_config"
```

المتطلبات: نسخة Ghidra في `tools\ghidra\<version>\` (أو Program Files) + JDK 21+.
يُكتشف `JAVA_HOME` تلقائياً (يشمل `tools\jdk21\` المرفق) — لا حاجة لضبطه يدوياً.
يُصدّر عدد الدوال وأهمها وتفكيك نقطة الدخول، ويولّد pseudocode لأهم 6 دوال افتراضياً
(قابل للضبط عبر `analysis.ghidra_decompile_limit`). إعادة التسمية تُطبّق داخل جلسة
Ghidra المؤقتة وتظهر في التقرير؛ لا تُعدّل ملف PE نفسه.

---

## 8. عزل ديناميكي (Windows Sandbox)

التحليل الديناميكي لا يعمل على المضيف أبداً. الأمر `sandbox` ينشئ خطة `.wsb`
ومجلدات معزولة (العينة للقراءة فقط، النتائج قابلة للكتابة)، والشبكة معطلة افتراضياً:

```powershell
python repl.py sandbox app.exe --out sandbox\plan
python repl.py sandbox app.exe --network          # خطر: شبكة داخل الصندوق
python repl.py sandbox app.exe --run --yes        # تشغيل فعلي بعد المراجعة
```

يتطلب Windows Sandbox (Pro/Enterprise أو ميزة مفعّلة) وعينة PE قابلة للتنفيذ
(`.exe/.scr/.com`). على Windows Home أو عند غياب الميزة تبقى الخطة قابلة للفتح
على جهاز/VM يدعمها. **تحذير:** فتح `sandbox.wsb` يشغّل العينة تلقائياً عبر
`LogonCommand`؛ راجع الملف أولاً. `--run` يرفض العمل بلا `--yes`، ويرفض غير PE.
عند `--run` ينتظر المشغّل انتهاء Sandbox مع **watchdog**: بعد مهلة الخطة + 60 ثانية
(بحد أقصى 3600 ثانية) يُنهي شجرة العملية عبر `taskkill /T /F` ويسجّل
`watchdog_triggered`. لا يُنفّذ أي أمر على المضيف.

---

## 9. فحص الدفعات والاختبار الذاتي

### فحص الدفعات (scan)

لفحص مجلد كامل بسرعة وإيجاد الملفات الأكثر خطورة أولاً:

```powershell
python repl.py scan samples\ --max 100 --open
python repl.py scan downloads\ --all --no-recursive
python repl.py scan "C:\samples" --deep        # يضيف تفكيك Rizin (أبطأ)
```

- يعالج PE/APK/ELF تلقائياً، ويتخطى مجلدات المخرجات (`workspaces`, `diffs`,
  `scans`, `sandbox`, `tools`, ...) لمنع فحص نتائج المنصة نفسها.
- يستخدم محللات `pe, apk, strings, yara` افتراضياً، مع `--only` للتحكم.
- يرتب النتائج حسب الخطورة، ويعرض أهم النتائج لكل ملف.
- المخرجات: `scans\<وقت>-<اسم>\summary.html` + `summary.json` + `summary.csv`
  (بترميز UTF-8 BOM ليفتح مباشرة في Excel)؛ و`--pdf` يضيف `summary.pdf`.
- تظهر الفحوصات في لوحة الويب عبر `/scan/<name>` و`/scan/<name>/pdf`.

### الاختبار الذاتي (selftest)

```powershell
python repl.py selftest          # سريع (~5 ثوانٍ)
python repl.py selftest --full   # يشمل APK وRizin (أبطأ)
```

يتحقق من: الإعدادات، تسجيل المحللات، الحالة، توليد التقارير، محرك المقارنة،
التعديل الثنائي (معاينة فقط)، YARA، جاهزية Ghidra، وقارئ PE. لا يعدّل بياناتك (نسخة مؤقتة
تُحذف تلقائياً)، ويعيد رمز خروج `1` عند أي فشل — مناسب للسكربتات وCI.

---

## 10. وكلاء الذكاء الاصطناعي

### الوضع القواعدي (افتراضي، بلا إنترنت)
`replatform/agents/heuristic.py` يبني تقريراً استنتاجياً من مخرجات المحللات:
حقائق + نتائج + خطوات تالية. يعمل دائماً، بلا مفاتيح أو تكلفة.

### وضع النموذج اللغوي (LLM)
حلقة أدوات كاملة (tool calling): النموذج يستدعي أدوات حقيقية ويبني تحليله عليها.

**الأدوات المتاحة للنموذج (قراءة فقط):**
`analyze_file` — تحليل سريع • `strings_search` — بحث regex في النصوص •
`hexdump` — عرض ثنائي • `apk_manifest` — بيان APK • `patch_preview` — معاينة تعديل (لا يكتب) •
`intel_lookup` — استعلام استخباراتي قراءة فقط (معطّل افتراضياً عبر `integrations.agent_enabled`)

**قيود الأمان والموارد:** أدوات القراءة مقيّدة بالهدف الحالي ومساحة العمل
(`agent.restrict_paths` افتراضياً `true`)، ومخرجات الملفات تُعامَل كبيانات غير
موثوقة (لا تُنفَّذ تعليماتها). كل خطوة محدودة بعدد أدوات (`max_tool_calls`)،
والوكيل محدود بزمن كلي (`max_seconds`) وسياق مضغوط (`max_context_chars`)
وسقف لكل نتيجة أداة (`max_tool_result_chars`). يُمرَّر ملخص المحللات كسياق
أولي لتقليل الاستدعاءات، ويُتتبَّع استهلاك tokens عند توفره.

**الإعداد** (`config.json` — انسخ من `config.example.json`):
```json
{
  "provider": {
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4o-mini",
    "api_key_env": "RE_API_KEY",
    "retries": 2
  },
  "agent": {
    "max_steps": 8,
    "max_tool_calls": 8,
    "max_seconds": 300,
    "max_context_chars": 60000,
    "max_tool_result_chars": 6000,
    "context_chars": 3000,
    "tool_timeout": 120,
    "restrict_paths": true,
    "default_mode": "heuristic"
  },
  "web": {
    "host": "127.0.0.1",
    "port": 8765,
    "token_env": "RE_WEB_TOKEN",
    "allowed_hosts": []
  }
}
```

يُضاف `context_tokens` إلى نتيجة الوكيل (tiktoken إن كان مثبتاً، وإلا تقدير
حروف/4). إعدادات Ghidra: `analysis.ghidra_decompile` و`ghidra_decompile_limit`.

**حدود التحليل (`analysis`) في الإصدار 1.3.0:**

| المفتاح | الافتراضي | الغرض |
|---|---:|---|
| `max_file_mb` | 1024 | السقف العام لأي هدف |
| `pe_max_mb` | 512 | حد تحليل PE العميق |
| `strings_max_mb` | 512 | حد استخراج النصوص (mmap) |
| `apk_max_mb` | 512 | حد ملف APK |
| `apk_uncompressed_max_mb` | 2048 | حد المحتوى بعد فك الضغط |
| `apk_max_entries` | 50000 | حد عدد مدخلات ZIP |
| `apk_max_ratio` | 200 | حد نسبة الضغط (زيب بوم) |
| `apk_manifest_max_kb` | 8192 | حد `AndroidManifest.xml` بعد الفك |
| `yara_max_mb` | 512 | حد ملف فحص YARA |
| `yara_timeout` | 180 | مهلة YARA (10–600 ثانية) |
| `bindiff_max_parse_mb` | 256 | حد التحليل العميق في المقارنة |
| `bindiff_max_apk_entries` | 50000 | حد مدخلات APK في المقارنة |

عند تجاوز أي حد يُرفض الإجراء أو تُسجّل نتيجة `skipped` صريحة بدلاً من استنزاف
الذاكرة أو إنتاج نتائج ناقصة بصمت.

**تقييم القبول:** `python repl.py benchmark` يفحص خمس حالات دون شبكة: منع مسار
خارج النطاق، ضغط السياق مع الحفاظ على `tool_calls`، المهلة الكلية، تجميع
`usage` وحساب التوكنات، والتوقف عند ميزانية الأدوات. `--out` يحفظ النتيجة JSON
لتتبع الانحدار في CI.

**نموذج محلي بلا مفتاح:** أي مزوّد على `127.0.0.1`/`localhost` (مثل Ollama)
يعمل تلقائياً دون `RE_API_KEY`. للاختبار دون شبكة: `RE_PROVIDER=mock`
أو `"provider": {"type": "mock"}` — و`python repl.py analyze --agent llm`
يُظهر الزمن وtokens إن أعادها المزوّد.

أمثلة مزوّدين متوافقين:

| المزوّد | `base_url` | `model` |
|---------|-----------|---------|
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| Groq | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |
| Ollama (محلي) | `http://localhost:11434/v1` | `qwen2.5:14b` |

المفتاح:
```powershell
setx RE_API_KEY "sk-..."     # ثم أعد فتح الطرفية
# أو مؤقتاً:
$env:RE_API_KEY = "sk-..."
```

التشغيل:
```powershell
python repl.py analyze app.apk --agent llm --open
python repl.py agent --mode llm --task "ابحث عن مؤشرات اتصال شبكي"
```

اختبار بلا مفتاح (محاكاة):
```powershell
$env:RE_PROVIDER = "mock"
python repl.py agent --mode llm
```

---

## 11. واجهة الويب المحلية

```powershell
python repl.py serve --open      # http://127.0.0.1:8765
python repl.py serve --host 0.0.0.0 --token "رمز-قوي" --allowed-host 192.168.1.20
```

الواجهة ترفض الاستماع على واجهة غير محلية بلا رمز. عند ضبط الرمز:
- المتصفح: شاشة دخول تحفظ كوكي `HttpOnly` + `SameSite=Strict`.
- الأتمتة: `Authorization: Bearer <token>`.
- `--allowed-host` يضيف اسم/IP مسموحاً لترويسة Host (حماية DNS rebinding).
- كل مسارات التصدير `/report/<id>/pdf` و`/json`، و`/diff/.../pdf`، و`/scan/.../pdf`
  محمية بالرمز أيضاً.
- لوحة تعرض الأدوات المكتشفة، الملف المستهدف، وكل مساحات العمل مع حكم كل تحليل.
- نموذج «تحليل سريع»: أدخل مسار EXE/APK على الجهاز → تحليل كامل → فتح التقرير.
- عرض التقارير مباشرة عبر `/report/<id>`، ومقارنات النسخ عبر `/diff/<name>`،
  وفحوصات الدفعات عبر `/scan/<name>`.
- محلية افتراضياً (`127.0.0.1`)؛ أي استماع خارجي يتطلب رمزاً صريحاً، وبلا رفع
  ملفات أو تنفيذ أوامر عشوائية.

---

## 12. الأمان والنطاق

- أدوات النموذج **قراءة فقط**؛ لا يمكن للنموذج الكتابة أو التعديل. وهي مقيّدة
  بالهدف ومساحة العمل، وتُعامَل مخرجاتها كبيانات غير موثوقة.
- التعديل الفعلي عبر `patch` مع: معاينة افتراضية، نسخة احتياطية فريدة،
  تحقق من سلامة PE/ZIP واسترجاع تلقائي عند التلف، ورفض مجلد النظام.
- `apk` يعدّل نسخاً مفكوكة أنشأتها أنت، ولا يلمس الأصل؛ ولا يحذف مجلد فك موجود
  إلا بـ `--force` بعد التحقق من أنه مجلد عادي وناتج apktool وليس أصلاً أو رابطاً.
- **توقيع APK** يتم في مجلد مؤقت معزول، ثم يُنقل الناتج ويُتحقق من ZIP ومن
  مخططات v1/v2/v3/v3.1/v4؛ لا يُعلَن النجاح بناءً على رسالة الموقّع وحدها.
- **`android:exported`** يتبع دلالات Android 12+: القيمة الصريحة أولاً، ثم
  استنتاج `true` عند وجود `intent-filter`، مع كشف غياب القيمة الصريحة عند
  `targetSdk >= 31` والمكونات المُصدّرة بلا `permission`. تُورَّث صلاحية
  `<application android:permission>` للمكونات، ويُعامل مزوّد المحتوى القديم
  (`targetSdk <= 16`) كمُصدَّر افتراضياً.
- **Sandbox watchdog** ينهي شجرة العملية (`taskkill /T /F`) عند تجاوز المهلة،
  بسقف انتظار أقصى 3600 ثانية، ويوثّق `watchdog_triggered`.
- الحالة والإعدادات تُكتب ذرّياً (لا ملفات نصف مكتوبة عند الانقطاع)، وواجهة الويب
  ترفض المضيف/الأصل غير المحلي وتضع حدوداً لحجم الطلب.
- القراءة محدودة الحجم (strings عبر mmap، كتلة توقيع APK تُقرأ وحدها، وسقف
  للتعديل/المعاينة) لتجنّب استهلاك الذاكرة على الملفات الضخمة. تُطبَّق حدود
  `analysis` أعلاه على APK/PE/strings/YARA/bindiff، ويُرفض الزيب بوم قبل apktool.
- المنصة مخصصة لتحليل وتعديل برامج **تملك حق تحليلها/تعديلها** (برامجك،
  أبحاث أمنية، تعلّم هندسة عكسية). لا توفّر آلية لتجاوز تراخيص أو حمايات
  برامج الغير.

---

## 13. البنية

```
replatform\
├── cli.py                 # واجهة الأوامر
├── core\
│   ├── config.py          # الإعدادات والمفاتيح
│   ├── registry.py        # اكتشاف الأدوات
│   ├── state.py           # الملف المستهدف الحالي
│   ├── util.py            # تجزئة/نوع/توقيع
│   ├── export.py          # HTML → PDF عبر Edge/Chrome
│   └── workspace.py       # مساحات العمل
├── analyzers\
│   ├── __init__.py        # واجهة الإضافة + التشغيل
│   ├── pe_analyzer.py
│   ├── apk_analyzer.py
│   ├── strings_analyzer.py
│   ├── yara_analyzer.py
│   └── disasm_analyzer.py
├── agents\
│   ├── tools.py           # أدوات النموذج
│   ├── provider.py        # OpenAI-compatible + Mock
│   ├── loop.py            # حلقة الأدوات
│   ├── tokenizer.py       # tiktoken اختياري + تقدير
│   └── heuristic.py       # التحليل القواعدي
├── tools\
│   ├── yara_engine.py     # YARA CLI
│   ├── patcher.py         # التعديل الثنائي
│   ├── bindiff.py         # مقارنة النسخ + تقرير HTML
│   ├── ghidra_tools.py    # تكامل Ghidra headless
│   ├── batch.py           # فحص الدفعات + ملخص HTML/PDF/JSON/CSV
│   ├── selftest.py        # الاختبار الذاتي
│   ├── benchmark.py       # تقييم قبول الوكيل
│   ├── sandbox.py         # خطة Windows Sandbox المعزولة
│   └── apk_tools.py       # decode/build/sign/java/install
├── web\server.py          # لوحة التحكم المحلية
└── reports\__init__.py    # تقرير HTML
scripts\ghidra\            # سكربت تصدير Ghidra (Java)
rules\                     # قواعد YARA (*.yar)
plugins\                   # إضافات المستخدم (تُحمّل تلقائياً)
tools\ghidra\, tools\jdk21\ # Ghidra + JDK 21 (مستخرجان، اختياريان)
workspaces\                # مخرجات كل تحليل
diffs\                     # تقارير مقارنة النسخ
scans\                     # ملخصات فحص الدفعات
sandbox\                   # خطط Windows Sandbox (لا تُنفّذ تلقائياً)
```

---

## 14. استكشاف الأخطاء

| المشكلة | الحل |
|---------|------|
| `jadx/adb/diec غير متاح` | أعد فتح الطرفية (PATH جديد)، أو المنصة تبحث في مواقع Winget تلقائياً |
| `apktool` بطيء أول مرة | يفك الموارد لأول مرة؛ التحليلات اللاحقة أسرع |
| عربية مشوّشة في PowerShell 5.1 | استخدم Windows Terminal؛ المنصة تضبط UTF-8 في مخرجاتها |
| `لا يوجد مفتاح API` | `python repl.py config init` ثم `setx RE_API_KEY "..."` |
| `YARA غير مثبت` | تأكد من وجود `tools\yara\yara64.exe` |
| `rizin غير متوفر` | ثبّت Cutter (يأتي معه Rizin) أو أضف rizin إلى PATH |
| `Ghidra غير مثبت` | ضع نسخة Ghidra في `tools\ghidra\<version>\` أو Program Files |
| `JDK 21+ (64-bit) could not be found` | ثبّت JDK (لا JRE) في `tools\jdk21\` أو اضبط `JAVA_HOME` — المنصة تكتشفه تلقائياً |
| أول تشغيل Ghidra بطيء | يحلل الملف كاملاً عبر headless — قد يستغرق دقائق حسب الحجم |
| `مجلد الناتج موجود` عند `apk decode` | احمِ تعديلاتك: استخدم مجلداً آخر (`--out`) أو `--force` لإعادة الفك |
| `تغيير طول ملف PE/APK/ZIP يفسد الإزاحات` | استخدم استبدالاً بنفس الطول، أو `--allow-resize` إذا كنت تعرف ما تفعل |
| `مسار خارج نطاق التحليل المسموح به` | أدوات الوكيل مقيّدة بالهدف؛ عطّل `agent.restrict_paths` عند الحاجة |
| `403 — مضيف غير مسموح` | أضف IP/الاسم عبر `--allowed-host`، أو افتح عبر `127.0.0.1` |
| `لا يوجد Edge/Chrome` عند PDF | ثبّت أحدهما أو اضبط `RE_BROWSER` |
| `Windows Sandbox غير مثبت` | فعّل الميزة (Pro/Enterprise) أو استخدم VM خارجية؛ الخطة تبقى قابلة للفتح |
| `401` في الواجهة | استخدم POST للدخول أو `Authorization: Bearer <token>` |
| `الملف كبير جداً` | ارفع `analysis.max_file_mb` أو استخدم عينة أصغر (سقف التعديل 256MB) |

---

## 15. خارطة الطريق

- [x] واجهة ويب محلية (لوحة تحكم + تحليل)
- [x] محرك قواعد YARA
- [x] تفكيك بدون واجهة (Rizin) مع أهم الدوال ونقطة الدخول
- [x] تحديد ملف مستهدف دائم + أوامر تعديل/تطوير متكاملة
- [x] تكامل Ghidra headless (تصدير الدوال وتفكيك نقطة الدخول)
- [x] مقارنة نسختين (bin-diff) للـ PE و APK
- [x] فحص دفعات (scan) بملخصات HTML/JSON/CSV
- [x] اختبار ذاتي (selftest) قابل للتشغيل في CI
- [x] إعادة تسمية الدوال وتصدير pseudocode من Ghidra
- [x] مقارنة CDC مقاومة للإزاحة + تقارير PDF/JSON
- [x] توقيع APK v3.1/v4 (كشف) + مصادقة الويب الاختيارية
- [x] خطة تحليل ديناميكي معزولة عبر Windows Sandbox (تشغيل صريح فقط)
- [x] تقييم قبول الوكيل (`benchmark`) وحساب توكنات السياق
- [x] توقيع APK معزول + تحقق فعلي من مخططات التوقيع (1.3.0)
- [x] دلالات `android:exported` في Android 12+ وكشف المكونات غير المحمية (1.3.0)
- [x] حدود APK/PE/strings/YARA/bindiff ورفض الزيب بوم (1.3.0)
- [x] Sandbox watchdog + إنهاء شجرة العملية (1.3.0)
- [x] تكامل URLhaus/ThreatFox + TLS مع حزمة CA حديثة (1.3.0)
- [x] اختبارات `unittest` وCI على Windows (1.3.0)
