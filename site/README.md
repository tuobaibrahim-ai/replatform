# صفحة الهبوط — site/

صفحة ثابتة عربية (RTL) بلا اعتماديات خارجية: لا خطوط CDN، لا JavaScript،
لا تحليلات. تُنشر كما هي على أي استضافة ثابتة (GitHub Pages، Netlify، IIS،
Nginx) أو تُفتح محلياً.

## 1. البناء

```powershell
python scripts/site_tool.py build
python scripts/site_tool.py check
```

- `build` يولّد `site/index.html` من `index.template.html` + `config.json`.
- `check` يفشل إذا:
  - بقي placeholder مثل `example.com` أو `[[` أو `{{`.
  - وُجد أصل خارجي (`<script src>`, `@import`, صورة من CDN).
  - وُجد رابط `http://` أو `javascript:`.
  - اختلّ النص المطلوب أو اتجاه RTL.
  - لم يطابق `index.html` القالب/الإعداد (نسيان إعادة البناء).

## 2. بريد التواصل

افتح `site/config.json`:

```json
{
  "contact_email": ""
}
```

- **فارغ:** الزر يستخدم حساب GitHub الرسمي (`github`). هذه هي الحالة الحالية،
  والصفحة قابلة للنشر فوراً.
- **بريد حقيقي:** ضعه ثم أعد البناء. السكربت يرفض أي بريد يحوي
  `example.com` أو `your-email` أو `placeholder` أو `[[`.

لا يوجد بريد مخترع في المستودع. إن أردت بريد بيع مخصصاً، أنشئه أولاً ثم ضعه.

## 3. النشر

### GitHub Pages

1. اجعل المستودع عاماً أو استخدم Pages في خطة تدعم المستودعات الخاصة.
2. انشر مجلد `site/` (أو الصفحة فقط) كـ Pages.
3. روابط الوثائق في الصفحة تشير إلى `github.com/.../blob/master/...`؛
   إن غيّرت المستودع أو الفرع، حدّث مفاتيح `*_url` في `config.json`.

### استضافة أخرى

ارفع `site/index.html` فقط. الصفحة مكتفية ذاتياً (CSS مضمّن، بلا أصول خارجية).

## 4. التحقق المنفذ

- `python scripts/site_tool.py check` — ناجح.
- Lighthouse (محلي): Accessibility **100**، Best Practices **100**، SEO **100**،
  بلا إخفاقات.
- لا تمرير أفقي عند عرض 1000px (تم الفحص عبر المتصفح).
- HTML دلالي، `lang="ar"`، `dir="rtl"`، تباين ألوان، `prefers-reduced-motion`.

## 5. ما يجب تحديثه مع كل إصدار

1. `version` في `site/config.json`.
2. الأرقام في القالب إن تغيّرت (الاختبارات/التغطية).
3. أعد `build` ثم `check` قبل النشر.

## 6. ما لا تفعله

- لا تضع بريداً وهمياً «مؤقتاً» — سكربت الفحص سيمنع النشر.
- لا تضف Google Analytics أو خطاً خارجياً؛ يخالف سياسة «بلا قياس».
- لا تعدّل `index.html` يدوياً؛ عدّل القالب ثم أعد البناء.
