# فهرست کامل فلگ‌ها — مرتب‌شده

تاریخ: ۲۰۲۶-۱۱-۱۴ · نسخه: v1.6.3
منبع: این جدول **از خودِ parser تولید می‌شود**، نه از حافظه:

```bash
python3 tools/flags_report.py          # خلاصه + موارد علامت‌خورده
python3 tools/flags_report.py --full   # هر فلگ در هر دستور
python3 tools/flags_report.py --md     # جدول markdown
```

---

## ۱) عدد کلی

```
231 ورودی فلگ در ۱۵ دستور  ←  ۶۰ تنظیم یکتا
```

یعنی خیلی از فلگ‌ها بین دستورهای `discover` / `check` / `loop` / `run` مشترک‌اند
(همه از والد `search` ارث می‌برند). این تکرار **درست** است: `bot discover -n 10` و
`bot check -n 10` باید یک معنا داشته باشند. پس تعداد ۲۳۱ عدد ترسناکی نیست؛
تعداد واقعی «تنظیم» ۶۰ است.

| گروه | تعداد تنظیم | چه چیزی |
|---|---|---|
| global | ۵ | مسیر config، سطح لاگ، نسخه، پوشهٔ داده، `--hard` |
| targets | ۵ | تارگت‌ها، حالت liveness، پروتکل‌ها، فایل ورودی، حالت داخلی |
| counts | ۲ | اندازهٔ best و bak |
| thresholds | ۶ | سقف پینگ سریع/نگهداری، کف سرعت واقعی، مبنای رتبه |
| filters | ۴ | فقط CDN، فقط SNI باز، فقط پورت امن، سقف هر پروتکل |
| speed | ۹ | کانکارنسی، پیش‌فیلتر، تایم‌اوت، فاصله‌گذاری |
| proof | ۵ | مدرک IP خروجی، SSL، بازآزمون DPI |
| maintenance | ۴ | آستانهٔ حذف، `--drop-dead`، بازهٔ loop |
| connect | ۱۰ | mode/port/pin/source/verify |
| tooling | ۱۰ | dpilab، calibrate، drop، list |

---

## ۲) چه چیزی حذف/پنهان شد (v1.6.3)

| فلگ | تصمیم | چرا |
|---|---|---|
| `--breaker` | **بی‌اثر شد** (پذیرفته می‌شود، کاری نمی‌کند) | مدارشکن از قبل همیشه روشن است (`test_breaker_streak=25`، `probe_breaker_window=400`). این فلگ فقط عددها را بی‌سروصدا عوض می‌کرد؛ حالا help هم همین را می‌گوید. |
| `--baseline-ms` | **از help پنهان شد** (هنوز کار می‌کند) | عدد ثابت دستی؛ جایگزینش `bot calibrate` است که از خط خودت اندازه می‌گیرد. |
| `--fast-factor` | **از help پنهان شد** | همان مشکل: ضریب پینگ دستی. `calibrate` صدک ۷۵ خط تو را می‌دهد. |
| `--no-verify-ssl` | نگه داشته شد | با `--verify-ssl` جفت است؛ حذفش رفتار قدیمی اسکریپت‌ها را عوض می‌کرد. |
| `--min-speed` | **معنایش درست شد** | قبلاً شمارهٔ **پینگ** را در `max_acceptable_ms` می‌نوشت (با برچسب «سرعت»!). حالا یک کف **KB/s** واقعی است که از صفحهٔ اثبات اندازه‌گیری می‌شود. |

هیچ فلگی که واقعاً کار می‌کند حذف نشد — چون هیچ‌کدام «بی‌مصرف» نبودند؛ فقط دو تا
**تکراری** بودند و یکی **گمراه‌کننده**. دلیلش ساده است: `apply_overrides` تنها
جایی است که فلگ‌ها را می‌خواند و همه‌شان به یک کلید config می‌رسند (تست قرارداد
جلوی فلگ بی‌اثر را می‌گیرد).

---

## ۳) `--hard` — پروفایل خط سخت

```bash
bot --hard discover -n 20        # هر جای دستور، مثل -q
bot discover --hard              # همان
bot --hard check                 # چک دوره‌ای روی خط فیلترشده
```

`--hard` یک «پروفایل» است: چند تنظیم را با هم عوض می‌کند، نه یک قابلیت جدید.

| تنظیم | عادی | `--hard` | دلیل |
|---|---|---|---|
| `probe_mode` | auto | **on** | پیش‌فیلتر TCP روی خط فیلترشده ارزان‌ترین فیلتر است |
| `test_concurrency` | 24 | **8** | روی خط خراب همه منتظر تایم‌اوت‌اند؛ ۲۴ تا انتظار هم‌زمان فقط خط را اشغال می‌کند |
| `batch_size` | 6 | **3** | هر پردازهٔ sing-box روی خط ضعیف گران است |
| `timeout` / `target_timeout` | 8 / 12 | **12 / 18** | خط پر از reset یک ثانیهٔ اضافه لازم دارد |
| `test_pace_ms` / `probe_pace_ms` | 50 / 15 | **120 / 30** | rate-limit هر IP را نمی‌زنیم |
| `test_breaker_streak` | 25 | **40** | وسط دورهٔ مرده متوقف نشویم |
| `backup_max_ms` | 4000 | **6000** | روی خط بد ۵ ثانیه هم قابل قبول است |
| `best_n` / `bak_n` | 50 / 100 | **30 / 60** | لیست کوتاه‌تر که واقعاً سالم باشد بهتر است |
| `frag_retry` | 0 | **12** | بازآزمون DPI برای نودهایی که روی TLS مردند |
| `strict_exit_proof` | False | **False** | روی خط بد باید به مدرک کمتر سخت گرفت |

قواعد مهم:

1. **هرچه خودت بنویسی، برنده است.** `bot --hard discover --concurrency 20` یعنی ۲۰.
2. **`--hard` روی config.json اولویت دارد** (چون درخواست صریح CLI است) و همان لحظه
   چاپ می‌کند چه چیزی را عوض کرد:
   ```
   HARD MODE — ... probe_mode=on, test_concurrency=8, ...
     timeout: 8 -> 12 (was in config.json)
   ```
3. پروفایل در `proxyfinder/config.py` → `HARD_MODE` است، نه پخش‌شده در کد.

---

## ۴) فلگ‌هایی که در عمل به هم وصل‌اند

| اگر این را می‌خواهی | از این استفاده کن | نه این |
|---|---|---|
| نود سریع‌تر (پینگ کمتر) | `--fast-max 800` | `--fast-factor` |
| نود پرسرعت‌تر (KB/s بیشتر) | `--min-speed 300` | — |
| نگه‌داشتن نود بیشتر | `--bak-max 6000 --bak 60` | `--breaker` |
| اعداد مناسب خط خودت | `bot calibrate --write` | `--baseline-ms` |
| فقط نودهایی که تلگرام/مرورگر می‌خواهد | `--safe-ports --cdn` | — |
| حالت سخت (خط فیلترشده) | `--hard` | ترکیب دستی ۶ فلگ |
| فقط زنده‌بودن، بدون تارگت | `-t ''` یا `--no-target` | — |

---

## ۵) جدول کامل (تولیدشده از parser)

| group | flag | config key | default | verdict | note |
|---|---|---|---|---|---|
| config | `--doctor` | `cfg_doctor` | `False` | new | only report stale/inconsistent keys |
| config | `--get` | `cfg_get` | `None` | new | print one effective value, script-friendly |
| config | `--config-out` | `cfg_out` | `None` | keep | file to read/write (default: the -c config) |
| config | `--set` | `cfg_set` | `None` | new | set one key in config.json (type-checked) |
| config | `--unset` | `cfg_unset` | `None` | new | drop a key so the shipped default wins |
| config | `--show` | `show` | `False` | keep | print the grouped table |
| connect | `--allow-no-target` | `allow_no_target` | `False` | pair | explicitly allow nodes without a target |
| connect | `--from` | `connect_from` | `best` | keep | best/bak/gen source |
| connect | `--mode` | `mode` | `None` | keep | proxy (SOCKS/HTTP) or tun |
| connect | `--no-pretest` | `no_pretest` | `False` | expert | skip the pre-connect test |
| connect | `--from` | `pick_from` | `best` | keep | best/bak/gen source |
| connect | `--pin` | `pin` | `None` | keep | pin one node (the long option), in connect/pick/list |
| connect | `--port` | `port` | `17805` | keep | local port |
| connect | `-n/--count` | `verify_count` | `10` | keep | how many to verify |
| connect | `--from` | `verify_from` | `best` | keep | best/bak/gen source |
| connect | `-t/--target` | `verify_targets` | `[]` | keep | verify against a different target |
| counts | `--bak` | `bak_n` | `None` | keep | size of bak |
| counts | `-n/--count` | `best_n` | `None` | keep | size of best |
| filters | `--cdn` | `cdn_only` | `-` | expert | Cloudflare-fronted IPs only |
| filters | `--list-mode` | `list_mode` | `None` | new | target (default): list = passed every target; live: every alive node |
| filters | `--max-per-proto` | `max_per_proto` | `None` | keep | protocol diversity cap |
| filters | `--max-per-subnet` | `max_per_subnet` | `None` | new | max candidates from one /24 (a host on 5 ports is one host) |
| filters | `--open-sni` | `open_sni` | `-` | expert | only SNIs `bot scan` proved open |
| filters | `--strict-target` | `require_target` | `False` | keep | OLD strict mode: list only target-OK nodes |
| filters | `--safe-ports` | `safe_ports` | `-` | expert | 443/8443/80/2083 only |
| global | `-c/--config` | `config` | `-` | keep | config file path |
| global | `-o/--data-dir` | `data_dir` | `-` | keep | where state/best/bak live |
| global | `-q/--quiet` | `quiet` | `False` | keep | log level |
| global | `-v/--verbose` | `verbose` | `False` | keep | log level |
| global | `--version` | `version` | `False` | keep | prints the version |
| maintenance | `--check-interval` | `check_interval` | `None` | keep | loop cadence |
| maintenance | `--discover-interval` | `discover_interval` | `None` | keep | loop cadence |
| maintenance | `--drop-dead` | `drop_dead` | `False` | keep | delete failures immediately |
| maintenance | `--prune-failures` | `prune_failures` | `None` | keep | failures before deletion |
| pool | `--reset` | `reset` | `False` | new | start from an empty pool (old state is archived) |
| proof | `--frag-retry` | `frag_retry` | `-` | expert | DPI-desync retest budget |
| proof | `--no-exit-proof` | `no_exit_proof` | `-` | pair | skip the exit-IP tunnel proof |
| proof | `--no-verify-ssl` | `no_verify_ssl` | `False` | pair | opposite of --verify-ssl |
| proof | `--strict-exit` | `strict_exit` | `-` | pair | reject nodes whose exit IP is unreadable |
| proof | `--verify-ssl` | `verify_ssl` | `False` | pair | verify TLS of the echo URL |
| speed | `--breaker` | `breaker_on` | `-` | remove | already on by default (25 fails / 400 probes) |
| speed | `--no-probe` | `no_probe` | `-` | pair | shortcut for --probe off |
| speed | `--pace` | `pace_ms` | `-` | expert | anti rate-limit jitter |
| speed | `--probe-concurrency` | `probe_concurrency` | `None` | expert | parallel TCP probes |
| speed | `--probe` | `probe_mode` | `-` | keep | auto/on/off pre-filter |
| speed | `--startup-delay` | `startup_delay` | `None` | expert | engine warm-up before the first request |
| speed | `--target-timeout` | `target_timeout` | `None` | expert | target/page timeout |
| speed | `--concurrency` | `test_concurrency` | `None` | expert | parallel tests (24 measured safe) |
| speed | `--timeout` | `timeout` | `None` | expert | echo timeout |
| targets | `--domestic` | `domestic_only` | `-` | keep | shutdown mode: .ir sources only |
| targets | `-i/--import` | `import_files` | `-` | keep | your own links/files first |
| targets | `--no-target` | `no_target` | `-` | pair | explicit liveness-only mode |
| targets | `-p/--protocols` | `protocols` | `None` | keep | comma list, aliases accepted |
| targets | `-t/--target` | `targets` | `None` | keep | repeatable, no cap; empty = liveness only |
| tg | `--fake-only` | `fake_only` | `False` | keep | tg: FakeTLS proxies only (best under DPI) |
| tg | `-n/--count` | `tg_count` | `20` | keep | tg: how many to print (all are written) |
| tg | `--timeout` | `tg_timeout` | `4.0` | expert | tg: TCP probe timeout |
| thresholds | `--bak-max` | `backup_max_ms` | `None` | keep | latency ceiling for keep |
| thresholds | `--baseline-ms` | `baseline_ms` | `None` | hide | legacy override; use `bot calibrate` |
| thresholds | `--fast-factor` | `fast_factor` | `None` | hide | legacy ping-based threshold; use `bot calibrate` |
| thresholds | `--fast-max` | `fast_max_ms` | `None` | keep | latency ceiling for fast |
| thresholds | `--latency-basis` | `latency_basis` | `-` | expert | rank by target time or echo time |
| thresholds | `--min-speed` | `min_speed_ms` | `None` | keep | REAL throughput floor in KB/s (fixed in v1.6.3) |
| tooling | `--budget` | `budget` | `120` | keep | dpilab time budget |
| tooling | `--config-out` | `config_out` | `config.json` | keep | calibrate: file to update |
| tooling | `count_run` | `count_run` | `10` | keep | run: positional count |
| tooling | `--drop` | `drop` | `()` | keep | list: drop nodes by id |
| tooling | `--force` | `force` | `False` | keep | run: skip the stored-node check |
| tooling | `--full` | `full` | `False` | expert | dpilab full sweep |
| tooling | `node_id` | `node_id` | `None` | keep | drop: node identifier |
| tooling | `--profile` | `profile` | `standard` | keep | calibrate: conservative/standard/fast |
| tooling | `--recheck` | `recheck` | `False` | keep | list: re-test before showing |
| tooling | `--write` | `write` | `False` | keep | calibrate: save the numbers |

---

> اگر این جدول و کد با هم فرق کردند، **کد درست است** — جدول را با
> `python3 tools/flags_report.py --md > docs/FLAGS.md` دوباره بساز.
