# قائمة تحقق التسليم — REPLATFORM

> **داخلي.** لا تُعلن «تم التسليم» حتى تُنجز كل بند إلزامي. البنود الاختيارية
> موسومة.

## A. قبل الطلب

- [ ] استُكمل التأهيل: الاستخدام، المقاعد، البيئة، `audit`/`fleet`، الامتثال.
- [ ] لا طلب لتحليل عيّنات نيابة عن العميل أو تجاوز حمايات.
- [ ] عُرض [`ONE-PAGER.md`](ONE-PAGER.md) وأُرسل [`QUOTE-TEMPLATE.md`](QUOTE-TEMPLATE.md).
- [ ] السعر مطابق لـ [`PRICING.md`](PRICING.md) أو موثّق كاستثناء.
- [ ] عُبّئ [`ORDER-FORM.md`](ORDER-FORM.md) ووُقّع من الطرفين.
- [ ] إن لزم: [`DPA.md`](DPA.md) موقّعة.

## B. السداد

- [ ] صدرت فاتورة صحيحة (اسم قانوني، رقم ضريبي، بنود، عملة).
- [ ] استُلم السداد أو أمر شراء معتمد.
- [ ] سُجّل مرجع التحويل/الفاتورة في ملف العميل.
- [ ] لم تُطلب بيانات بطاقة عبر البريد.

## C. إصدار الترخيص

- [ ] حُدّدت الخطة والمقاعد والمدة بدقة.
- [ ] أُصدر الترخيص:

```powershell
python -m replatform.tools.license_admin issue `
  --tier professional `
  --customer "[الاسم القانوني]" `
  --seats [N] `
  --days 365 `
  --out "C:\secure\[customer]-[year].json"
```

- [ ] أُضيف `--feature fleet_report` فقط لخطة Enterprise.
- [ ] تم التحقق:

```powershell
python -m replatform.tools.license_admin verify "C:\secure\[customer]-[year].json"
```

- [ ] الناتج `"valid": true` والـ`features` متوقعة.
- [ ] لم يُنسخ `license_private.key` إلى أي مجلد مشترك.

## D. تجهيز الحزمة

- [ ] نُزّلت الحزمة من الإصدار الرسمي (لا من مصدر آخر).
- [ ] تم التحقق من البصمة:

```powershell
Get-FileHash -Algorithm SHA256 .\replatform-1.5.2-portable.zip
Get-Content .\SHA256SUMS
```

- [ ] (موصى به) تم التحقق من توقيع Sigstore:

```powershell
cosign verify-blob --bundle .\replatform-1.5.2-portable.zip.sigstore.json `
  --certificate-identity-regexp "https://github.com/tuobaibrahim-ai/replatform/.*" `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com `
  .\replatform-1.5.2-portable.zip
```

- [ ] أُرسل رابط الإصدار + البصمة + تعليمات التثبيت.
- [ ] أُرسل `license.json` عبر قناة مشفّرة أو بوابة العميل.

## E. التفعيل عند العميل

- [ ] ثُبّتت الحزمة في مجلد يملك المستخدم صلاحية الكتابة عليه.
- [ ] `.\replatform.cmd version` يعرض 1.5.2.
- [ ] `.\replatform.cmd license activate license.json` نجح.
- [ ] `.\replatform.cmd license status` يعرض الخطة والمقاعد و`days_left`.
- [ ] `.\replatform.cmd doctor --bundle` أُرسل للمالك (بلا أسرار).
- [ ] `audit verify` سليم إن كان `audit` مفعّلاً.
- [ ] أُضيف الترخيص إلى نسخة العميل الاحتياطية.

## F. الإغلاق

- [ ] أُرسل بريد/رسالة تأكيد بالتسليم وتاريخ الانتهاء.
- [ ] عُقدت جلسة تسليم قصيرة (15 دقيقة) أو أُرسل فيديو.
- [ ] عُرضت قناة الدعم وأوقاتها وفق [`docs/SLA.md`](../docs/SLA.md).
- [ ] سُجّل تذكير تجديد قبل 30 يوماً.
- [ ] حُفظت: العرض، الطلب، الفاتورة، إثبات السداد، نسخة الترخيص (بلا المفتاح
      الخاص)، مراسلات التسليم — **7 سنوات**.

## G. عند الفشل

| المشكلة | الإجراء |
|---|---|
| بصمة غير مطابقة | لا تثبّت. أعد التنزيل من الإصدار الرسمي وأبلغ المالك |
| ترخيص مرفوض | `license status --json`، تحقق من المدة/التوقيع، أعد الإصدار |
| `doctor` يفشل | أرسل الحزمة للمالك؛ لا تجرّب تعديلات عشوائية |
| العميل يطلب عيّنة خبيثة | ارفض؛ خارج النطاق |
| طلب استرداد | اتبع [`REFUND-POLICY.md`](REFUND-POLICY.md) |
| حادث أمني | اتبع [`SECURITY.md`](../SECURITY.md) وقناة الإفصاح الخاصة |

## H. التوقيع

**المسؤول:** `[الاسم]` — **التاريخ:** `[YYYY-MM-DD]`
**رقم الطلب:** `[RE-O-...]` — **رقم الترخيص:** `[RE-...]`
