# التكاملات والمهارات في REPLATFORM

هذه الطبقة تربط المنصة بواجهات API ومستودعات ومهارات مهنية في مجالات الذكاء الاصطناعي، البرمجة، الأمن السيبراني، الاستضافة المجانية، وقواعد البيانات — دون المساس بعزل التحليل أو سرية العيّنات.

## المبادئ الأمنية

| القيد | التطبيق |
|---|---|
| HTTPS فقط | كل موصل يستخدم `https://` ومنفذ 443 فقط |
| TLS موثّق | تحقق إلزامي من الشهادة والمضيف، مع حزمة CA حديثة (`certifi`) عند توفرها |
| مضيف مسموح | كل موصل يحدد مضيفه، والعميل يرفض أي مضيف آخر |
| بلا إعادة توجيه | أي `3xx` يُرفض ولا يُتبع إلى مضيف آخر |
| سقف استجابة | حد بالبايت لكل استجابة (افتراضي 8MB، ويمكن رفعه حتى 64MB؛ الموصل يفرض سقفه الخاص أيضاً) |
| مهلة | مهلة اتصال/قراءة قابلة للضبط |
| مفاتيح من البيئة | لا تُكتب المفاتيح في الكود أو `config.json` أو السجلات |
| قراءة فقط | لا موصل يكتب أو يحذف أو يرفع ملفات |
| بلا رفع عيّنات | تُرسل مؤشرات/استعلامات نصية فقط، لا محتوى العينات |
| معطّل افتراضياً | `integrations.enabled=false` و`integrations.agent_enabled=false` |
| بيانات غير موثوقة | نتائج API تُعامل كبيانات للتحليل، لا كتعليمات |

> **قاعدة ذهبية:** لا ترفع عينة برمجية خبيثة إلى أي خدمة خارجية. استخدم التجزئة أو المؤشرات بعد مراجعة سياسة الخدمة.

## الإعداد

أضف إلى `config.json` (أو ابدأ من `config.example.json`):

```json
{
  "integrations": {
    "enabled": false,
    "agent_enabled": false,
    "timeout": 20,
    "max_response_mb": 8
  }
}
```

- `enabled`: يسمح لأوامر `integrations search` بالشبكة. يمكن تجاوزه لكل أمر بـ `--yes`.
- `agent_enabled`: يسمح لأداة الوكيل `intel_lookup` بالعمل. اتركها `false` إلا بعد مراجعة سياسة البيانات.
- `timeout`: مهلة كل طلب بالثواني (3–120).
- `max_response_mb`: سقف الاستجابة العام (1–64MB).

### متغيرات البيئة

| المتغير | الموصل | إلزامي؟ |
|---|---|---|
| `NVD_API_KEY` | NVD | لا (يرفع حد المعدل) |
| `GITHUB_TOKEN` | GitHub | لا (يرفع حد المعدل) |
| `HF_TOKEN` | Hugging Face | لا |
| `VIRUSTOTAL_API_KEY` | VirusTotal | نعم |
| `OTX_API_KEY` | AlienVault OTX | نعم |
| `MALWAREBAZAAR_AUTH_KEY` | MalwareBazaar | نعم |
| `ABUSECH_AUTH_KEY` | URLhaus وThreatFox | نعم (مفتاح abuse.ch مشترك) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | نعم |
| `SHODAN_API_KEY` | Shodan | نعم |

مثال PowerShell (للجلسة الحالية فقط):

```powershell
$env:NVD_API_KEY = "..."
$env:GITHUB_TOKEN = "..."
```

لا تضع المفاتيح في ملف يُرفع إلى مستودع. استخدم مدير أسرار أو متغيرات بيئة على الخادم.

## الأوامر

```powershell
# عرض الموصلات
python repl.py integrations list

# تفاصيل موصل
python repl.py integrations show nvd

# حالة الإعداد (بلا شبكة)
python repl.py integrations check

# فحص TLS فعلي دون إرسال طلب API
python repl.py integrations check nvd --live --yes

# استعلام قراءة فقط
python repl.py integrations search nvd "CVE-2024-3400" --limit 3 --yes
python repl.py integrations search osv "npm:lodash@4.17.20" --yes
python repl.py integrations search github "yara rules" --limit 5 --yes
python repl.py integrations search cisa_kev "PAN-OS" --yes
python repl.py integrations search huggingface "malware classifier" --yes

# مصادر ومستودعات وخدمات مجانية
python repl.py integrations resources
python repl.py integrations resources database
python repl.py integrations resources ai
```

`search` يطبع JSON منظمًا. استخدم `--json` لإخراج مضغوط.

## الموصلات الحالية

| المعرّف | الفئة | الاستخدام | مفتاح |
|---|---|---|---|
| `nvd` | ثغرات | بحث CVE وCVSS | اختياري |
| `cisa_kev` | استخبارات | الثغرات المستغلة فعلياً | لا |
| `osv` | سلسلة التوريد | ثغرات الحزم مفتوحة المصدر | لا |
| `github` | كود | بحث المستودعات العامة | اختياري |
| `huggingface` | ذكاء اصطناعي | بحث النماذج/البيانات | اختياري |
| `virustotal` | برمجيات خبيثة | سمعة ملف/رابط/نطاق/IP | نعم |
| `otx` | استخبارات | نبضات ومؤشرات مجتمعية | نعم |
| `malwarebazaar` | برمجيات خبيثة | بيانات وصفية حسب التجزئة | نعم |
| `abuseipdb` | استخبارات | سمعة عناوين IP | نعم |
| `shodan` | سطح الهجوم | منافذ وخدمات مكشوفة | نعم |
| `urlhaus` | برمجيات خبيثة | روابط/مضيفون/تجزئات حمولات | نعم (`ABUSECH_AUTH_KEY`) |
| `threatfox` | استخبارات | مؤشرات C2 وعائلات البرمجيات الخبيثة | نعم (`ABUSECH_AUTH_KEY`) |

### أمثلة استعلام

```powershell
# VirusTotal: تجزئة أو نطاق أو IP أو رابط
python repl.py integrations search virustotal "44d88612fea8a8f36de82e1278abb02f" --yes

# OTX: مؤشر
python repl.py integrations search otx "example.com" --yes

# MalwareBazaar: تجزئة فقط (لا تنزيل عيّنة)
python repl.py integrations search malwarebazaar "44d88612fea8a8f36de82e1278abb02f" --yes

# Shodan: IP
python repl.py integrations search shodan "8.8.8.8" --yes

# URLhaus: رابط أو نطاق/IP أو MD5/SHA256 (لا تنزيل عيّنة)
python repl.py integrations search urlhaus "http://example.com/payload" --yes
python repl.py integrations search urlhaus "44d88612fea8a8f36de82e1278abb02f" --yes

# ThreatFox: مؤشر أو تجزئة
python repl.py integrations search threatfox "example.com" --yes
python repl.py integrations search threatfox "44d88612fea8a8f36de82e1278abb02f" --yes
```

## المهارات المحلية

المهارات ملفات Markdown في `skills/`، تُحمّل محلياً فقط، وتُحقن في مطالبة الوكيل عند طلبها. لا تُنفّذ ولا تُحمّل من الشبكة.

```powershell
python repl.py skills list
python repl.py skills show malware-triage
python repl.py skills show threat-intel

# تشغيل الوكيل بمهارة أو أكثر
python repl.py agent apk\test.apk --mode llm --skill malware-triage,apk-analysis
python repl.py analyze apk\test.apk --agent llm --skill threat-intel
```

المهارات المتاحة:

- `malware-triage` — فرز أولي آمن.
- `pe-analysis` — تحليل PE.
- `apk-analysis` — تحليل أندرويد.
- `yara-authoring` — كتابة قواعد كشف.
- `threat-intel` — استخدام مصادر CVE/KEV/OTX.
- `secure-code-review` — مراجعة OWASP.
- `ai-agent-safety` — أمان الوكلاء وحقن المطالبات.
- `cloud-db-hardening` — تقوية السحابة وقواعد البيانات.
- `re-ethics` — الحدود القانونية والأخلاقية.

## ربط الوكيل

أداة `intel_lookup` متاحة للوكيل لكنها **معطّلة افتراضياً**. عند تفعيلها:

```json
{ "integrations": { "agent_enabled": true } }
```

يمكن للوكيل إرسال مؤشر/استعلام فقط. لا تمرير مسار ملف أو محتوى عينة. النتائج تُقصّ وتُعامل كبيانات غير موثوقة. راجع سجل `agent/steps.json` لمعرفة ما أُرسل.

## المصادر والخدمات المجانية

`python repl.py integrations resources` يعرض الكتالوج الكامل. أمثلة:

### الذكاء الاصطناعي
OpenRouter، GroqCloud، Google AI Studio، Mistral، Cloudflare Workers AI، Ollama، Hugging Face، LangChain، LlamaIndex، Model Context Protocol.

### البرمجة
GitHub، GitLab، Semgrep، Trivy، Snyk، OSV-Scanner، Stack Overflow API.

### الأمن السيبراني
MITRE ATT&CK، OWASP Cheat Sheets، PortSwigger Academy، HackTricks، YARA Rules، Sigma، Ghidra، Rizin، Malpedia، MISP، URLhaus، ThreatFox، Feodo Tracker.

### الاستضافة المجانية
Cloudflare Workers/Pages، Render، Koyeb، Railway، Vercel، Netlify، GitHub Pages، Oracle Cloud Free Tier، AWS Free Tier.

### قواعد البيانات
Supabase، Neon، Turso، Cloudflare D1، MongoDB Atlas، Upstash Redis، Redis Cloud، Aiven، CockroachDB Serverless، PocketBase.

> الحدود المجانية تتغير. الكتالوج معلوماتي بتاريخ أكتوبر 2026؛ تحقق من صفحة الخدمة قبل الاعتماد عليها. لا تضع بيانات إنتاج حساسة على طبقة مجانية دون مراجعة الشروط والنسخ الاحتياطي.

## حدود معروفة

- MITRE ATT&CK ليس موصلاً حياً هنا لأن ملف STIX الكامل كبير؛ استخدم رابطه في الكتالوج ونزّله عند الحاجة.
- MISP يحتاج خادماً وثقة تشغيلية؛ لم يُضف كموصل تلقائي.
- بعض الخدمات تغيّر حدود المعدل أو تتطلب مفتاحاً؛ الأخطاء تظهر برسالة واضحة.
- لا توجد كتابة أو رفع؛ إن احتجت تكاملاً كتابياً مستقبلاً فيجب تصميمه بموافقة بشرية ومسار تدقيق منفصل.

## مراجع البحث (أكتوبر 2026)

- NVD API 2.0: <https://nvd.nist.gov/developers/vulnerabilities>
- GitHub REST وحدود المعدل: <https://docs.github.com/rest/using-the-rest-api/rate-limits-for-the-rest-api>
- Hugging Face Hub API: <https://huggingface.co/docs/hub/api>
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- OSV API: <https://google.github.io/osv-scanner/>
- VirusTotal API v3: <https://docs.virustotal.com/reference/overview>
- AlienVault OTX API: <https://otx.alienvault.com/api>
- MalwareBazaar API: <https://bazaar.abuse.ch/api/>
- URLhaus API: <https://urlhaus-api.abuse.ch/>
- ThreatFox API: <https://threatfox-api.abuse.ch/>
- AbuseIPDB API: <https://docs.abuseipdb.com/>
- Shodan API: <https://developer.shodan.io/api>
- MITRE ATT&CK STIX: <https://github.com/mitre-attack/attack-stix-data>
- استضافة مجانية (Render/Koyeb/Railway/Cloudflare): راجع روابط الكتالوج.
- قواعد بيانات مجانية (Supabase/Neon/Turso/D1/Atlas/Upstash): راجع روابط الكتالوج.

> الحدود المجانية والأسعار تتغير باستمرار. ما ورد هنا معلوماتي وليس ضماناً تعاقدياً؛ تحقق من صفحة الخدمة وسياسة البيانات قبل الاستخدام.

## التحقق

- `selftest --full` يغطي كتالوج التكاملات، قيود HTTPS/allowlist/السقف، التعطيل الافتراضي، إلزام المفتاح، تحميل المهارات، وحقنها في الوكيل.
- `python -m unittest discover -s tests -v` يغطي URLhaus/ThreatFox (بمحاكاة عميل HTTP)، حدود APK، دلالات `exported`، توقيع APK، وحارس Sandbox — بلا شبكة أو عينات خارجية.
- اختبارات الشبكة الفعلية اختيارية ولا تعمل في `selftest` (بلا شبكة).
- `benchmark` يبقى بلا شبكة.
