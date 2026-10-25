# المساهمة في REPLATFORM

شكراً لاهتمامك. هذا الدليل يوضح كيف تُعدّ بيئة تطوير، وما هي بوابات الجودة
قبل قبول أي تغيير.

## 1. قبل أن تبدأ

- افتح Issue للنقاش قبل الميزات الكبيرة أو تغيير واجهة CLI.
- للثغرات الأمنية: اتبع [`SECURITY.md`](SECURITY.md) ولا تفتح Issue عاماً.
- بالمساهمة، توافق على نشر مساهمتك تحت رخصة MIT (انظر [`LICENSE`](LICENSE)).

## 2. متطلبات البيئة

| المتطلب | الحد الأدنى |
|---|---|
| نظام التشغيل | Windows 10/11 (المنتج مُختبَر عليه) |
| Python | 3.11+ (CI على 3.12 و3.13) |
| Git | 2.40+ |
| PowerShell | 5.1+ |

الأدوات الخارجية (Ghidra، apktool، jadx، YARA، Rizin) **اختيارية** ولا يحتاجها
معظم التطوير؛ الاختبارات لا تستدعيها.

## 3. إعداد سريع

```powershell
git clone https://github.com/tuobaibrahim-ai/replatform.git
cd replatform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m replatform version
```

أو استخدم السكربت الجاهز:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Dev
```

## 4. بوابات الجودة (إلزامية)

```powershell
python -m ruff check replatform tests repl.py
python -m compileall -q replatform tests
python -m unittest discover -s tests -v
python -m coverage run -m unittest discover -s tests
python -m coverage report
python -m replatform selftest
```

| البوابة | الشرط |
|---|---|
| `ruff` | صفر أخطاء (القواعد: `F`, `E9`, `B`) |
| `compileall` | نجاح |
| `unittest` | كل الاختبارات ناجحة |
| `coverage` | ≥ 70% (الحد في `pyproject.toml`) |
| `selftest` | نجاح الفحوص السريعة |

`selftest --full` يحتاج أدوات خارجية، ويُشغَّل يدوياً قبل الإصدار لا في CI.

## 5. قواعد الاختبارات

- **بلا شبكة:** استخدم `unittest.mock` بدل أي اتصال حقيقي.
- **بلا عيّنات حقيقية:** أنشئ ملفات وهمية صغيرة داخل `tempfile.TemporaryDirectory`.
- **حتمية:** لا تعتمد على الوقت أو ترتيب ملفات غير مضمون؛ استخدم بذرة ثابتة
  للـ fuzzing (انظر `tests/test_fuzz.py`).
- **اختبار واحد لكل سلوك:** اسم الاختبار يصف السلوك المتوقع.
- أي إصلاح لخطأ يجب أن يضيف اختبار انحدار يفشل قبله وينجح بعده.
- تغيير واجهة CLI يتطلب تحديث لقطة سطح الأوامر في `tests/test_cli.py` **بوعي**.

## 6. الأسلوب

- اتبع أسلوب الكود المحيط: type hints، `from __future__ import annotations`،
  ودوال قصيرة.
- النصوص الموجّهة للمستخدم بالعربية، والرسائل البرمجية بالإنجليزية.
- لا تُدخل أسراراً أو مسارات شخصية أو أسماء مضيفين حقيقية في الكود أو الاختبارات.
- لا تضف اعتماداً جديداً إلا بضرورة واضحة؛ الاعتمادات الحالية ثلاثة فقط.
- لا تكسر التوافق مع Python 3.11 (لا `match` متقدم، لا `tomllib` للكتابة...).

## 7. الالتزامات (Commits)

استخدم رسائل واضحة بصيغة Conventional Commits:

```
feat(cli): add inventory --json
fix(apk): reject zip bombs with ratio > 200
test(agents): cover tool budget exhaustion
docs(security): document sandbox threat model
```

- التزم واحد = تغيير منطقي واحد.
- اذكر سبب التغيير في النص، لا وصفاً حرفياً للكود.
- لا تخلط إعادة التنسيق مع تغيير سلوك في نفس الالتزام.

## 8. طلب السحب (PR)

قائمة تحقق قبل الطلب:

- [ ] الاختبارات الجديدة/المحدّثة موجودة وناجحة محلياً.
- [ ] `ruff` و`compileall` و`coverage` ناجحة.
- [ ] لا أسرار ولا عيّنات ولا مخرجات مولّدة في الفرق.
- [ ] `CHANGELOG.md` محدّث إذا كان التغيير مرئياً للمستخدم.
- [ ] التوثيق محدّث (`README.md` أو `docs/` أو `PLATFORM.md`).
- [ ] وصف PR يشرح المشكلة والحل والأثر والمخاطر.

سيُشغَّل CI تلقائياً على Python 3.12 و3.13. لا تُدمج PR بCI أحمر.

## 9. الإبلاغ عن خطأ

استخدم قالب Issue. ضمّن:

- الإصدار (`python -m replatform version`).
- نظام التشغيل وإصدار Python.
- الأمر الدقيق والنتيجة المتوقعة والفعلية.
- مقتطف السجل (بلا مسارات شخصية أو مفاتيح).
- إن أمكن: ملفاً وهمياً يعيد إنتاج المشكلة، لا عيّنة حقيقية.

## 10. الترخيص

المشروع MIT. لا تُضف كوداً بترخيص غير متوافق (GPL/AGPL) إلى حزمة `replatform/`.
الأدوات الخارجية تُستدعى كعمليات منفصلة ولا تُضمَّن في التوزيع.
