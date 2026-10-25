# دليل النشر — REPLATFORM 1.4.2

## 1. المتطلبات

| المتطلب | الأدنى | الموصى به |
|---|---|---|
| نظام التشغيل | Windows 10 64-bit | Windows 11 64-bit |
| Python | 3.11 | 3.12 أو 3.13 |
| المعالج/الذاكرة | 2 نوى / 4 GB | 4 نوى / 8 GB |
| القرص | 200 MB (بلا أدوات خارجية) | 4 GB مع Ghidra/JDK |
| الشبكة | غير مطلوبة للتحليل الثابت | مطلوبة للتكاملات ومزوّد LLM |

**لا يعمل على Linux/macOS** في 1.4.2 (Windows Sandbox وأدوات APK/PE مرتبطة
بمنصة ويندوز). التحليل الثابت قد يعمل جزئياً، لكنه غير مدعوم.

## 2. خيارات التثبيت

### الخيار أ — حزمة محمولة (موصى به للبيع/التوزيع)

1. نزّل `replatform-1.4.2-portable.zip` من صفحة الإصدارات.
2. تحقق من البصمة:

```powershell
Get-FileHash .\replatform-1.4.2-portable.zip -Algorithm SHA256
Get-Content .\SHA256SUMS
```

3. فك الضغط إلى مجلد يملك المستخدم صلاحية الكتابة عليه (ليس `Program Files`).
4. ثبّت:

```powershell
cd replatform-1.4.2
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

5. شغّل:

```powershell
.\replatform.cmd version
.\replatform.cmd tools
```

`install.ps1` ينشئ `.venv`، ويثبّت `pefile` و`asn1crypto` و`certifi`، وينسخ
`config.example.json` إلى `config.json` (بلا مفاتيح)، ثم يشغّل `selftest`.

### الخيار ب — من المصدر

```powershell
git clone https://github.com/tuobaibrahim-ai/replatform.git
cd replatform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
replatform version
```

أو للتطوير:

```powershell
python -m pip install -e ".[dev]"
```

### الخيار ج — wheel مباشر

```powershell
python -m pip install replatform-1.4.2-py3-none-any.whl
replatform version
```

### الخيار د — شبكة معزولة (Air-gapped)

على جهاز متصل بالإنترنت، نزّل الحزم:

```powershell
python -m pip download -r requirements.txt -d wheels
```

انقل `wheels/` والحزمة المحمولة، ثم:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -WheelDir .\wheels
```

لتعطيل الشبكة كلياً بعد التثبيت: أبقِ `integrations.enabled=false` ولا تضبط
`provider.api_key_env` (أو استخدم `--mode heuristic`).

## 3. الإعداد

```powershell
Copy-Item config.example.json config.json
python -m replatform config show
```

القواعد:

- **لا مفاتيح في `config.json`.** ضع اسم متغير البيئة في `api_key_env`،
  والقيمة في بيئة النظام/المستخدم.
- `config.json` مستبعد من Git افتراضياً.
- التكاملات معطّلة افتراضياً:

```json
{
  "integrations": {
    "enabled": false,
    "agent_enabled": false,
    "timeout": 20
  }
}
```

- للتحليل بلا إنترنت: `agent.default_mode = "heuristic"`.

## 4. الأدوات الخارجية (اختيارية)

لا تُضمَّن في الحزمة. ثبّتها بنفسك ثم تحقق:

```powershell
python -m replatform tools
```

| الأداة | تُستخدم في | الاكتشاف |
|---|---|---|
| apktool + Java | `apk decode/build` | `tools\apktool.jar` أو PATH |
| jadx | `apk java` | `tools\jadx-cli\` أو PATH |
| uber-apk-signer | `apk sign` | `tools\uber-apk-signer.jar` |
| Ghidra + JDK 21 | `ghidra`, محلل `ghidra` | PATH، `tools\ghidra\`، `Program Files` |
| Rizin (Cutter) | محلل `disasm` | PATH، WinGet، `Program Files\Cutter` |
| YARA (`yara64.exe`) | محلل `yara` | `tools\yara\` أو PATH |
| adb | `apk install/devices` | PATH |

بدونها يعمل المنتج، لكن المحللات المرتبطة تظهر `skipped` أو تختفي من
`can_handle` بدل أن تفشل.

## 5. الواجهة الويب

### محلي (الافتراضي، آمن)

```powershell
python -m replatform serve --open
```

يستمع على `127.0.0.1` ويولّد رمزاً.

### شبكة داخلية

```powershell
$token = -join ((48..57) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
python -m replatform serve --host 0.0.0.0 --port 8765 --token $token --allowed-host myhost.corp
```

- افتح المنفذ في جدار الحماية لنطاق محدد فقط.
- **لا تعرضه على الإنترنت مباشرة.** إن لزم، ضع reverse proxy مع TLS
  (nginx/IIS) ومصادقة إضافية.
- الخادم HTTP محلي؛ TLS ليس مدمجاً.
- راجع سجل الوصول وراقب أي `Host` مرفوض.

## 6. الترقية

```powershell
# احتفظ بالإعدادات ومساحات العمل خارج مجلد التثبيت أو انسخها احتياطياً
Copy-Item config.json config.backup.json
Copy-Item workspaces workspaces.backup -Recurse

# حزمة جديدة
powershell -ExecutionPolicy Bypass -File .\install.ps1
python -m replatform selftest
```

- الإصدارات الثانوية قد تغيّر واجهة CLI الداخلية؛ راجع `CHANGELOG.md`.
- مساحات العمل بصيغة JSON مستقرة، لكن لا ضمان توافق رجعي كامل قبل 2.0.

## 7. التراجع (Rollback)

1. أوقف أي `serve`/`scan` جارٍ.
2. استعد المجلد السابق من النسخة الاحتياطية أو أعد تثبيت الحزمة السابقة.
3. استعد `config.json` و`workspaces/`.
4. شغّل `python -m replatform version` و`selftest`.

## 8. إلغاء التثبيت

```powershell
# من داخل مجلد التثبيت
Remove-Item .venv -Recurse -Force
```

ثم احذف المجلد. لا يكتب المثبّت في Registry ولا في `Program Files`، ولا يترك
خدمات أو مهام مجدولة.

## 9. استكشاف الأخطاء

| العرض | السبب المحتمل | الحل |
|---|---|---|
| `No module named pefile` | اعتماديات ناقصة | `.\install.ps1` أو `pip install -r requirements.txt` |
| `python` غير معروف | Python غير مثبت/PATH | ثبّت Python 3.11+ أو استخدم `-Python "C:\...\python.exe"` |
| `ExecutionPolicy` | سياسة PowerShell | `powershell -ExecutionPolicy Bypass -File .\install.ps1` |
| `selftest` يفشل في APK | Java/apktool غائب | ثبّت الأداة أو تجاهل الفحص الاختياري |
| `serve` يرفض Host | `--allowed-host` ناقص | أضف اسم المضيف الدقيق |
| `403` في التكاملات | مفتاح غائب | اضبط متغير البيئة المطلوب |
| PDF لا يُنشأ | لا Edge/Chrome | ثبّت متصفحاً أو `RE_BROWSER=<path>` |
| بطء تحليل PE كبير | حدود مرتفعة | خفّض `analysis.pe_max_mb` |

## 10. قائمة تحقق ما قبل الإنتاج

- [ ] تثبيت من حزمة متحقَّق من بصمتها (`SHA256SUMS`).
- [ ] `selftest` ناجح.
- [ ] `config.json` بلا مفاتيح، والتكاملات معطّلة إن لم تلزم.
- [ ] حساب مستخدم غير مسؤول.
- [ ] نسخ احتياطي مجدول لـ `workspaces/` و`config.json`.
- [ ] سياسة واضحة: لا تشغيل عيّنات على المضيف؛ Sandbox/VM فقط.
- [ ] مراجعة [`SECURITY.md`](../SECURITY.md) مع فريق الأمن.
