# Shidox Free

ساب پروکسی با اسم‌های مرتب — پرچم کشور هر سرور + «Shidox Free»، و `+ CF` برای سرورهای کلادفلر. تکراری‌ها حذف شده‌اند (از هر سرور فقط یک کانفیگ).

ساب هر ۵ ساعت با GitHub Action به‌روز می‌شود؛ جمع‌آوری از کانال‌های تلگرامی خودمان است (نه کپی از ساب دیگری).

## لینک ساب زنده

```
https://raw.githubusercontent.com/naghibi-farshad/Shidox-Free/main/sub.txt
```

## فایل‌ها

- `sub.txt` — ساب با فرمت base64 (همین لینک بالا)
- `sub_plain.txt` — لیست سادهٔ لینک‌ها
- `stats.json` — آمار آخرین اجرا
- `scripts/collect.py` — جمع‌کننده (متن + فایل NPV)
- `history/archive.json` — آرشیو چرخشی ۴۸ ساعته

## کانال‌ها

متن (لینک v2ray): `@vpn_Click` ،`@FreakConfig` ،`@V2RAYROZ` ،`@prrofile_purple` ،`@V2rayBaaz` ،`@V2rayNGX` ،`@V2rayng_Fast` ،`@v2ray26`
فایل NPV: `@irCONFIG` ،`@ConfigX2ray`

## چطور کار می‌کند

- لینک‌های متنی از صفحهٔ عمومی کانال‌ها خوانده می‌شوند (بدون لاگین).
- فایل‌های `.npvt` و `.npvs` با سشن تلگرام (در Secrets ریپو) دانلود و با رمزگشای پایتون SaKit (لایسنس MIT) باز می‌شوند و به لینک v2ray تبدیل می‌شوند.
- کانفیگ‌ها تازه‌اند و تست نشده‌اند؛ ساب «تازه» می‌دهد، نه «تضمین‌شده».

<!-- SHIDOX:STATS:START -->
<!-- SHIDOX:STATS:END -->
