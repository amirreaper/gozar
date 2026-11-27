# رتبه‌بندی منابع به‌ازای هدف — نسخهٔ v1.7.0 (۲۰۲۶-۱۱-۱۴)

این سند **جایگزین** نسخهٔ قبلی است. تفاوت: منابع تازه اندازه‌گیری شده، سه فایل
حذف‌شده، و رتبه‌ها این بار با معیار «رسیده به هدف» شمرده شده‌اند.

**هدف:** `https://www.google.com.hk/search?q=...&udm=50` · **روش:** ۱۶ نود تصادفی
از هر سورس، ۴۸ سورس، ۶۸۸ اتصال · **خروجی خام:** `data/source-score.json`

## ۱) جمع هر tier

| tier | src | parsed | tested | reached | ok | per 1000 parsed |
|---|--:|--:|--:|--:|--:|--:|
| measured | 15 | 9338 | 240 | 35 | 0 | 3.75 |
| tested | 21 | 43534 | 336 | 32 | 0 | 0.74 |
| bulk | 7 | 12591 | 112 | 9 | 0 | 0.71 |

- `reached` = گوگل جواب داد (۲xx/۴xx/۵۰۳) · `ok` = بدنهٔ ۲۰۰ و **صفحه** بود (نه دیوار)
- `per 1000 parsed` = تعداد نودی که به‌ازای هر ۱۰۰۰ لینکِ خوانده‌شده به هدف رسید.
  این تنها معیاری است که «حجم» و «کارایی» را با هم می‌سنجد.

باز هم `ok=0` در هر سه tier: گوگل به هیچ نودی صفحهٔ نتایج نداد (دیوار JS).

## ۲) رتبه‌بندی همهٔ سورس‌ها (NEW = در این نسخه اضافه شد)

| # | tier | reach/tested | wall | body | KB/s | parsed | source |
|--:|---|--:|--:|--:|--:|--:|---|
| 1 | tested | 9/16 | 4 | 3KB | 3 | 1062 | `mrdevmohamed/v2ray-configs/main/All_Configs_Sub.txt` |
| 2 | tested | 7/16 | 5 | 3KB | 6 | 157 | **NEW** `noahclanman/free-xray-gcp/main/output/fast/configs.txt` |
| 3 | measured | 6/16 | 7 | 92KB | 35 | 831 | `0xRadikal/Free-v2ray-Configs/main/verified/configs.txt` |
| 4 | measured | 6/16 | 6 | 3KB | 5 | 596 | `0xRadikal/Free-v2ray-Configs/main/fast/configs.txt` |
| 5 | measured | 6/16 | 4 | 47KB | 35 | 403 | **NEW** `Diversan313/apex-parser/main/subs/main/alive_bl.txt` |
| 6 | measured | 4/16 | 8 | 92KB | 80 | 302 | `F0rc3Run/F0rc3Run/main/Best-Results/sub.txt` |
| 7 | measured | 4/16 | 3 | 47KB | 6 | 78 | **NEW** `luxxuria/harvester/main/ping_tested.txt` |
| 8 | bulk | 4/16 | 5 | 92KB | 40 | 44 | `snakem982/proxypool/main/source/v2ray-2.txt` |
| 9 | measured | 3/16 | 7 | 92KB | 55 | 485 | `0xRadikal/Free-v2ray-Configs/main/secure/configs.txt` |
| 10 | measured | 3/16 | 2 | 92KB | 87 | 164 | **NEW** `sakha1370/OpenRay/main/output/country/GB.txt` |
| 11 | bulk | 3/16 | 8 | 92KB | 82 | 140 | `roosterkid/openproxylist/main/V2RAY_BASE64.txt` |
| 12 | tested | 3/16 | 4 | 92KB | 85 | 409 | `free18/v2ray/main/v.txt` |
| 13 | measured | 2/16 | 0 | 47KB | 14 | 424 | `10Dream/sub-mod/main/sub/normal/10ium-telegram-configs-collector-trojan` |
| 14 | tested | 2/16 | 10 | 92KB | 105 | 199 | `mahdibland/ShadowsocksAggregator/master/Eternity.txt` |
| 15 | tested | 2/16 | 3 | 92KB | 100 | 303 | `peasoft/NoMoreWalls/master/list.txt` |
| 16 | tested | 2/16 | 4 | 92KB | 107 | 283 | **NEW** `ShatakVPN/ConfigForge-V2Ray/main/configs/at/all.txt` |
| 17 | measured | 1/16 | 3 | 92KB | 92 | 177 | `Mosifree/-FREE2CONFIG/main/Reality` |
| 18 | bulk | 1/16 | 0 | 3KB | 5 | 4294 | `mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt` |
| 19 | bulk | 1/16 | 1 | 48KB | 30 | 6673 | `mheidari98/.proxy/main/vless` |
| 20 | tested | 1/16 | 2 | 92KB | 15 | 4273 | `Surfboardv2ray/TGParse/main/configtg.txt` |
| 21 | tested | 1/16 | 0 | 3KB | 4 | 11692 | `morpheusadam/v2ray-config/main/subs/bundles/reality.txt` |
| 22 | tested | 1/16 | 3 | 92KB | 91 | 235 | `barry-far/V2ray-config/main/Sub1.txt` |
| 23 | tested | 1/16 | 7 | 92KB | 105 | 150 | `barry-far/V2ray-config/main/Sub2.txt` |
| 24 | tested | 1/16 | 1 | 47KB | 86 | 2137 | `Argh94/Proxy-List/main/All_Config.txt` |
| 25 | tested | 1/16 | 1 | 47KB | 10 | 349 | **NEW** `pie-with-jam/PulseProxy/main/githubmirror/15.txt` |
| 26 | tested | 1/16 | 2 | 92KB | 93 | 177 | **NEW** `V2HUBIR/V2HUBIR-Free-V2Ray-Configs-free-Sub/main/sub.txt` |
| 27 | measured | 0/16 | 0 | 0KB | 0 | 1347 | `morpheusadam/v2ray-config/main/subs/bundles/best.txt` |
| 28 | measured | 0/16 | 1 | 92KB | 9 | 2449 | `morpheusadam/v2ray-config/main/subs/bundles/iran.txt` |
| 29 | measured | 0/16 | 8 | 92KB | 119 | 430 | `4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs_tested.txt` |
| 30 | measured | 0/16 | 0 | 0KB | 0 | 376 | `ndsphonemy/proxy-sub/main/speed.txt` |
| 31 | measured | 0/16 | 4 | 92KB | 237 | 686 | `Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt` |
| 32 | measured | 0/16 | 0 | 0KB | 0 | 590 | `coldwater-10/V2ray-Config/main/Sub7.txt` |
| 33 | bulk | 0/16 | 0 | 0KB | 0 | 594 | `coldwater-10/V2ray-Config/main/Sub6.txt` |
| 34 | bulk | 0/16 | 0 | 0KB | 0 | 596 | `coldwater-10/V2ray-Config/main/Sub10.txt` |
| 35 | bulk | 0/16 | 0 | 0KB | 0 | 250 | **NEW** `Leon406/SubCrawler/main/sub/share/v2` |
| 36 | tested | 0/16 | 0 | 0KB | 0 | 2397 | `sevcator/5ubscrpt10n/main/mini/m1n1-5ub-69.txt` |
| 37 | tested | 0/16 | 0 | 0KB | 0 | 9091 | `Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_003.txt` |
| 38 | tested | 0/16 | 0 | 0KB | 0 | 6079 | `Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_014.txt` |
| 39 | tested | 0/16 | 1 | 92KB | 73 | 3676 | `MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt` |
| 40 | tested | 0/16 | 2 | 92KB | 77 | 251 | `MhdiTaheri/V2rayCollector_Py/main/sub/Mix/mix.txt` |
| 41 | tested | 0/16 | 0 | 0KB | 0 | 226 | `Barabama/FreeNodes/master/nodes/merged.txt` |
| 42 | tested | 0/16 | 0 | 0KB | 0 | 196 | `MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt` |
| 43 | tested | 0/16 | 1 | 92KB | 105 | 192 | `V2RayRoot/V2RayConfig/main/Config/vless.txt` |

## ۳) تصمیم‌هایی که از این جدول بیرون آمد

| تصمیم | دلیل |
|---|---|
| **افزوده:** `Diversan313/apex-parser` | ۴۰۳ لینک یکتا، ۶/۱۶ رسید — سومین سورس برتر همنشین با `0xRadikal` |
| **افزوده:** `luxxuria/harvester` | فقط ۷۸ لینک، ولی ۴/۱۶ → **بیشترین بازده به‌ازای لینک** در کل جدول |
| **افزوده:** `noahclanman/free-xray-gcp` | ۷/۱۶ (دومین در کل) و ۱۶۹ KB/s در یک ران، ولی ۸ دیوار → سرعت بالا، اطمینان کم |
| **افزوده:** `ShatakVPN/ConfigForge` | ۵۰ نود hysteria2 — پروتکلی که بقیهٔ سورس‌ها رهایش کرده‌اند |
| **حذف:** `mheidari98` trojan/ss/vmess | دو ران متوالی ۰/۱۶؛ همان ژنراتورِ vless که خودش ۰/۱۶ است |
| **رد:** `parvinxs/Sub.mahsa.xsparvin` | ۸۰۹ لینک یکتا — بزرگ‌ترین کاندید — و **۰/۱۴** |
| **رد:** `freedomnet25500`، `rtwo2/AT`، `iboxz/collector`، `amin4139`، `ysmoradi` | همه ۰/۱۴ |
| **۴۰۴ (سورس مرده):** `iPsycho1`، `Epodonios`، `yebekhe/PSG`، `soroushmirzaei`، `liMilCo`، `hans-thomas` | مسیرهای از کار افتاده |

## ۴) ترتیب tierها (دو بار سنجیده شد، دو نتیجه)

| ران | measured | tested | bulk |
|---|--:|--:|--:|
| ران قبلی (۳۸ سورس) | ۲٫۸ | ۰٫۴ | ۰٫۵ |
| این ران (۴۳ سورس، پس از add/drop) | **۳٫۷۵** | ۰٫۷۴ | ۰٫۷۱ |

`measured` در هر دو ران با فاصلهٔ ۵ برابر صدر است. `tested` و `bulk` در محدودهٔ
نویز یکدیگرند (۰٫۰۳ اختلاف در ۶۸۸ اتصال)، پس ترتیب کد روی `measured → tested → bulk`
است: **بزرگ‌تر آخر**، نه بر اساس یک اختلاف ناچیز. با `--propose` دوباره بسنجید.

## ۵) دستور

```bash
python3 -m proxyfinder.bot sources -t '<TARGET>' --per-source 16 --top 24 --propose
```

ورودی نامعتبر (هدف بدون `http(s)://` یا `--per-source 0`) حالا با کد ۲ رد می‌شود؛
قبلاً جدول خالی با کد خروج ۰ چاپ می‌کرد که «اینترنت مرده» به نظر می‌رسید.


---

## ۶) اصلاحیهٔ v1.7.2 — چرا این جدول **ترتیب** استخر نیست

این سند اول باعث شد ترتیب tierها با عدد همین جدول عوض شود. آن تصمیم **برگشت**،
چون سه اشکال داشت:

1. **این جدول تارگت را می‌سنجد، نه منبع را.** گوگل به هر IP دیتاسنتری `429` یا
   دیوار JS می‌دهد؛ در روز اندازه‌گیری همهٔ tierها نزدیک صفر شدند و ترتیب شد
   نتیجهٔ throttle گوگل.
2. **cascade زود متوقف می‌شود**؛ tierی که اول می‌آید تعیین می‌کند کدام آدرس‌ها
   اصلاً دیده شوند، پس «کارایی» یک tier تا حدی اثر خودش است.
3. **نمونه کوچک است** (۱۶ نود برای هر سورس)؛ نوسان ران‌به‌ران تا ۲ برابر.

سنجش مجدد روی یک تارگت تمیز (`example.com`, ۱۰ نود برای هر سورس):

| گروه | نتیجه |
|---|---|
| ۸ سورس تازه‌اضافه‌شده | **۳۱/۸۰ رسید (۳۹٪)**، ۲۷ صفحهٔ واقعی |
| ۳ سورس `mheidari98` که حذف شده بودند | **۴/۳۰ رسید (۱۳٪)** — زنده بودند |

یعنی هیچ‌کدام از آن فایل‌ها مرده نبودند؛ فقط گوگل آن روز بی‌فایده بود.
`mheidari98` trojan/ss/vmess **برگشت** (آخر tier `bulk`)، و در کد:
- ترتیب tierها = **اعتبار منبع**: `measured → tested → bulk`
- `PROVENANCE`: داخل هر tier، سورسِ خودسنجیده اول، سورسِ «فقط روی یک تارگت خوب
  بود» آخر.

**کاربرد درست این جدول:** پیدا کردن سورس مرده/تکراری، و دیدن اینکه خط شما چه
چیزی را می‌گیرد. **کاربرد غلط:** تعیین اینکه استخر از کدام منبع ساخته شود.
