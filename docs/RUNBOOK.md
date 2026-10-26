# دليل التشغيل — RUNBOOK

إجراءات مختبرة للحالات التي تحتاج قراراً سريعاً.

## 1. فحص صحة التثبيت

```powershell
python repl.py doctor
python repl.py doctor --json
python repl.py doctor --bundle support.zip   # بلا أسرار، للمشاركة
```

`fail` واحد يعني توقفاً محتملاً. `warn` مقبول في بيئات بلا أدوات خارجية.

## 2. الترقية

```powershell
# 1) نزّل الحزمة وSHA256SUMS، ثم تحقق
Get-FileHash -Algorithm SHA256 .\replatform-1.5.0-portable.zip

# 2) معاينة (لا تغيير)
python repl.py upgrade .\replatform-1.5.0-portable.zip --dry-run

# 3) تطبيق مع البصمة
python repl.py upgrade .\replatform-1.5.0-portable.zip --sha256 <hash> --yes
```

يُحفظ تلقائياً: `config.json`, `workspaces/`, `plugins/`, `license.json`.
نسخة التراجع تُطبع في الناتج.

### التراجع

```powershell
python repl.py upgrade --rollback "<backup-path>"
```

## 3. هجرة الإعدادات

```powershell
python repl.py config migrate --dry-run   # معاينة
python repl.py config migrate             # نسخة احتياطية + كتابة
```

النسخة الاحتياطية: `config.json.v1.<timestamp>.bak`. لا تُحذف تلقائياً.

## 4. فشل الترقية بسبب ملف مقفول

الأعراض: `تعذّر استبدال المجلد (قد يكون قيد الاستخدام)`.

1. أغلق كل طرفيات وأوامر REPLATFORM وواجهة الويب.
2. أوقف أي مهمة مجدولة تستدعي `repl.py`.
3. أعد الأمر. إن تكرر، أعد تشغيل الجهاز (بقرارك) ثم أعد المحاولة.
4. إن بقي مجلد `.staging-*`، احذفه يدوياً بعد التأكد من عدم وجود عملية نشطة.

## 5. ترخيص لا يُقبل

```powershell
python repl.py license status --json
```

| الرسالة | السبب | الإجراء |
|---|---|---|
| توقيع غير صحيح | ملف معدّل أو مفتاح مختلف | أعد إصداره من المالك |
| انتهى الترخيص | تجاوز فترة السماح | جدّد |
| مخطط غير مدعوم | إصدار أحدث من المنتج | حدّث المنتج |
| لا مفتاح عام مثبّت | نسخة قديمة/معدّلة | استخدم إصداراً رسمياً |

## 6. تدوير مفتاح الترخيص

عند الاشتباه بتسريب المفتاح الخاص:

1. أنشئ زوجاً جديداً: `python -m replatform.tools.license_admin keygen --out <new>`.
2. حدّث `PINNED_PUBLIC_KEY` في `replatform/tools/licensing.py`.
3. أصدر إصداراً جديداً (1.5.x) ووزّعه.
4. أعد إصدار تراخيص العملاء الحاليين بالمفتاح الجديد وأرسلها.
5. أعلن للعملاء أن الترقية مطلوبة قبل تاريخ محدد.

التراخيص القديمة تبقى صالحة على الإصدارات القديمة فقط.

## 7. فقدان المفتاح الخاص

لا يمكن استرجاعه. الإجراء: توليد زوج جديد + إصدار نسخة + إعادة إصدار التراخيص
(انظر §6). لهذا يجب نسخ احتياطي مشفّر للمفتاح خارج الجهاز.

## 8. نسخ احتياطي واستعادة

**ما يجب نسخه:** `config.json`, `workspaces/`, `plugins/`, `license.json`,
`audit.jsonl` (إن استُخدم التدقيق).

**ما لا يجب نسخه:** `.venv/`, `__pycache__/`, `tools/*.jar`, `dist/`.

الاستعادة: فك الحزمة في مجلد جديد، ثم انسخ العناصر أعلاه، ثم `doctor`.

## 9. حادث أمني

1. اعزل الجهاز عن الشبكة.
2. احفظ `audit.jsonl` و`workspaces/` كما هي (لا تعدّل).
3. `python repl.py audit verify` لتحديد أول كسر.
4. دوّن الخط الزمني، وأبلغ `SECURITY.md` إن كان الحادث في المنتج.
5. لا تحذف الأدلة قبل انتهاء التحقيق.

## 10. استعادة كلمة/رمز الويب

`web.token` يُقرأ من `RE_WEB_TOKEN` أولاً. عند الاشتباه:

```powershell
setx RE_WEB_TOKEN "<رمز جديد عشوائي>"
```

أعد تشغيل `serve`. الرمز لا يُسجَّل في السجلات ولا في `doctor`.

## 11. إيقاف/إزالة

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1          # معاينة
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -Yes     # تنفيذ (يحفظ البيانات)
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -Yes -PurgeData  # حذف البيانات أيضاً
```

## 12. جهات الاتصال

- أمن: انظر `SECURITY.md`.
- دعم تجاري: انظر `docs/SLA.md`.
- تراخيص: `docs/SALES.md`.
