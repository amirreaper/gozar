# دو باگ گزارش ۲۰۲۶-۱۱-۳۰ (v2.1.3 / v2.1.4)

## ۱) `./gozar-dev` → `ERROR: gozar package not found.` — این باگ من بود

شما **داخل ریپو** بودید (`ls` نشانش می‌دهد: `gozar/` سر جایش است) ولی اسکریپت
می‌گفت پکیج نیست. علت: در v2.1.2 فایل `gozar/bot.py` را به `gozar/cli.py` تغییر
نام دادم و `gozar-dev` را جا گذاشتم — اسکریپت هنوز دنبال `gozar/bot.py` می‌گشت.

سه مشکل در همان فایل بود:

| مشکل | حالا |
|---|---|
| مسیر hard-code شدهٔ `gozar/bot.py` | در یک جا اعلام می‌شود: `ENTRY="gozar/cli.py"` — و تست وجود همان فایل را چک می‌کند |
| `exec python3 -m gozar.bot` | `exec "$PY" -m gozar` — نقطهٔ ورود یک واقعیتِ **پکیج** است، نه اسم فایلی که می‌شود تغییر نامش داد |
| `${PROXYFINDER_HOME}` — متغیر غلط‌املایی‌شدهٔ باقی‌مانده | فقط `GOZAR_HOME`؛ مقدار خرابش هم فقط هشدار می‌دهد و جست‌وجو را متوقف نمی‌کند |

تست‌شده: از ریشهٔ ریپو، از زیرپوشه، از طریق سیم‌لینک، با `GOZAR_HOME`، با
`GOZAR_HOME` خراب، و کلاً بدون چک‌اوت (کد خروج ۲ با پیام خوانا).

```bash
$ ./gozar-dev --version
gozar 2.1.4
```

## ۲) لانچر «چهار علت» می‌گفت و تمام — حالا می‌گوید چه تایپ کنید

در سیستم شما venv یک `gozar` **سالم** داشت و یک لانچر کهنه در `~/.local/bin`
جلویش را گرفته بود. توضیح چهار علت درست بود و بی‌فایده. حالا لانچر:

- همهٔ `gozar`های روی `PATH`، venv فعال، `~/.venv/bin/gozar`، `~/.gozar/bin/gozar`،
  `.venv` کنار پوشهٔ جاری، و `python -m gozar` را **اجرا** می‌کند و آن‌هایی که
  جواب می‌دهند را چاپ می‌کند؛
- از **pip همان مفسر** می‌پرسد و دو حالت را جدا می‌کند:

```
gozar: installed, but this launcher cannot import its own package.
  launcher   : /home/amir/.local/bin/gozar
  python     : /home/amir/.venv/bin/python3
  user site  : /home/amir/.local/lib/python3.13/site-packages  (enabled=False)
  gozar      : not importable
  reason     : ModuleNotFoundError: No module named 'gozar'

  WHAT TO TYPE INSTEAD — a working gozar was found on this machine:
      /home/amir/.venv/bin/gozar

  Those use their own interpreter, so they are unaffected by the launcher above.
  To make plain `gozar` work as well, delete or replace the broken one:
      rm /home/amir/.local/bin/gozar
```

و وقتی pip می‌گوید نصب هست ولی import نمی‌بیندش، دقیقاً می‌گوید کدام حالت است:

```
  pip (that python) : gozar 2.1.4 at /home/amir/.venv/lib/python3.13/site-packages
  -> pip put it exactly where python looks, so the package
     directory itself is damaged: reinstall with --force-reinstall
```

## ۳) توصیهٔ غلط خودمان — که در تست پیدا شد

هم لانچر و هم `selfcheck` داخل venv می‌گفتند `pip install --user ...`، ولی pip
داخل venv این را **رد می‌کند**:

```
ERROR: Can not perform a '--user' install. User site-packages are not visible in this virtualenv.
```

حالا هر دو وضعیت venv را تشخیص می‌دهند و `--user` را حذف می‌کنند و دلیلش را
می‌نویسند. `selfcheck` هم با فهرست دستورهایی تمام می‌شود که **همین حالا** تست و
تأیید شده‌اند:

```
  These work right now on this machine:
      /home/amir/.venv/bin/python3 -m gozar   # gozar 2.1.4
```

## کاری که الان بکنید

```bash
# ۱) داخل ریپو، همان دو دستور گزارش
git pull
./gozar-dev --version

# ۲) نصب تمیز و درست، در یک venv مخصوص خودش
python3 -m venv ~/.gozar
~/.gozar/bin/pip install "git+https://github.com/amirreaper/gozar.git"
~/.gozar/bin/gozar doctor

# ۳) اگر می‌خواهید `gozar` خالی هم کار کند، لانچر کهنه را بردارید
rm ~/.local/bin/gozar
```

## تست‌هایی که اجرا شدند

| مورد | نتیجه |
|---|---|
| `./gozar-dev` از ریشهٔ ریپو / زیرپوشه / سیم‌لینک | ✅ 2.1.4 |
| `GOZAR_HOME` درست / خراب / بدون چک‌اوت | ✅ 2.1.4 / هشدار / کد ۲ |
| `pip install git+…` در venv | ✅ 2.1.4 |
| `python -m gozar` | ✅ 2.1.4 |
| فایل تک‌تکه از ریلیز | ✅ 2.1.4 |
| لانچر خراب + venv سالم کنارش | ✅ **مسیر `venv/bin/gozar` را پیدا و پیشنهاد کرد** |
| لانچر خراب + `~/.venv` بدون فعال‌سازی | ✅ همان را پیدا کرد |
| داخل venv | ✅ دیگر `--user` پیشنهاد نمی‌دهد |
| قراردادها روی clone تازه از GitHub | **۳۲۹ PASS / ۰ FAIL** |
| اکشن ریلیز `v2.1.3` و `v2.1.4` | ✅ سبز |

## نسخه‌ها

- `v2.1.3` — `gozar-dev` و پیام لانچر
- `v2.1.4` — اصلاح `--user` داخل venv (چند دقیقه بعد از ۲.۱.۳ پیدا شد)
- `main` = `b2e19f8`
