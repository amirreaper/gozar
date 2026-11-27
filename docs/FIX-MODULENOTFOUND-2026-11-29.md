# ModuleNotFoundError — چه بود، چرا بود، چه شد (v2.1.2)

## خطایی که فرستادید

```
Successfully installed gozar-2.1.1
(amir) amir@laptop /work> gozar
Traceback (most recent call last):
  File "/home/amir/.local/bin/gozar", line 3, in <module>
    from gozar.bot import cli
ModuleNotFoundError: No module named 'gozar'
```

## تشخیص

اول یک چیز را قطعی کردم: **روی PyPI هیچ پکیجی به نام `gozar` وجود ندارد** —
هم `https://pypi.org/pypi/gozar/json` و هم `https://pypi.org/simple/gozar/`
جواب **۴۰۴** می‌دهند. پس `gozar-2.1.1` که pip نصب کرده، از خودِ ریپوی ما آمده.
یعنی **بسته واقعاً نصب شده بوده**؛ مشکل، pip نیست، **لانچر** است.

و «لانچر نمی‌تواند پکیج را import کند» دقیقاً چهار علت دارد. هر چهار را اینجا
بازتولید کردم:

| # | علت | چطور بازتولید شد | علامت |
|---|---|---|---|
| ۱ | user site-packages خاموش است (`PYTHONNOUSERSITE=1` یا `python -s`) | `PYTHONNOUSERSITE=1 ~/.local/bin/gozar` | **همان دو خط تریبک شما، عیناً** |
| ۲ | دو پایتون: pip در یکی، اسکریپت با دیگری | `head -1 $(command -v gozar)` | همان تریبک |
| ۳ | venv بدون `--system-site-packages` و نصب `--user` | نصب دستی در جای اشتباه | همان تریبک |
| ۴ | پوشهٔ `gozar/` بدون `__init__.py` | ساختن پوشهٔ خالی هم‌نام | `find_spec` → `origin=None` |

خود محتمل‌ترین حالت برای شما: پایتون `(amir)` روی لپ‌تاپ یا `PYTHONNOUSERSITE`
ست شده، یا `gozar` از یک شل با `-s` اجرا می‌شود.

## چه کاری روی کد انجام شد

**۱. لانچر دیگر stub نیست.** stub ستاپ‌تولز اولین دستورش `from gozar.cli import cli`
است، پس نمی‌تواند خطای خودش را توضیح بدهد. حالا `scripts/gozar` یک فایل واقعی
است که import داخل `try` دارد و این را چاپ می‌کند (تست‌شده با پاک کردن بسته از
یک venv نصب‌شده):

```
gozar: installed, but this launcher cannot import its own package.
  launcher   : /home/user/.local/bin/gozar
  python     : /usr/local/bin/python3
  user site  : /home/user/.local/lib/python3.13/site-packages  (enabled=False)
  gozar      : not importable
  reason     : ModuleNotFoundError: No module named 'gozar'

Four things cause this, and they need different fixes:
  1. user site-packages is disabled ...
  2. pip installed into a DIFFERENT python ...
  3. this is a venv ...
  4. a leftover `gozar` directory ...
```
کد خروج: **۲** (نه ۱، نه تریبک).

**۲. `gozar selfcheck` (دستور جدید)** — زنجیرهٔ کامل:
`لانچر → مفسرِ شبانگ → آیا آن مفسر ما را import می‌کند → ۲۱ ماژول → تأیید pip`.
تفاوت با `doctor`: `doctor` می‌گوید «می‌تواند وصل شود؟»، `selfcheck` می‌گوید
«اصلاً سالم نصب شد؟».

**۳. `scripts/gozar-rescue.py`** — همان تشخیص، مستقل، **هیچ‌چیز از پروژه import
نمی‌کند** (برای وقتی gozar اصلاً اجرا نمی‌شود):
```bash
python3 scripts/gozar-rescue.py
```

**۴. `gozar/bot.py` → `gozar/cli.py`** — دیگر چیزی در آن «بات» نیست، و همان اسم
قدیمی همان جایی است که تریبک شما به آن اشاره می‌کرد.

**۵. کامپلیت‌ها تولید می‌شوند، نه دست‌نویس** — `scripts/gen-completions.py` از
`argparse` می‌خواند و fish/bash/zsh می‌سازد. نسخهٔ دست‌نویس `engine`،
`selfcheck` و ~۱۲ پرچم را نداشت. `--check` در تست‌ها عقب‌افتادگی را قرمز می‌کند.

## کاری که خودتان الان بکنید

```bash
# ۱) اول تشخیص
gozar selfcheck
# اگر gozar اصلاً اجرا نمی‌شود:
python3 scripts/gozar-rescue.py        # از چک‌اوت

# ۲) راهی که هر چهار علت را کنار می‌زند
python3 -m venv ~/.gozar
~/.gozar/bin/pip install "git+https://github.com/amirreaper/gozar.git"
~/.gozar/bin/gozar doctor
```

## تست‌هایی که واقعاً اجرا شدند

| مسیر نصب | نتیجه |
|---|---|
| `pip install --user` (پایتون سیستم) | ✅ 2.1.2 |
| venv خالی | ✅ 2.1.2 |
| `pip install git+https://…` | ✅ 2.1.2 |
| فایل تک‌تکه `gozar.pyz` | ✅ 2.1.2 |
| `install.sh --system` | ✅ نصب و **اثبات** با همان مفسر |
| اجرای مستقیم از چک‌اوت | ✅ 2.1.2 |
| نصب‌شده + `PYTHONNOUSERSITE=1` | ✅ پیام کامل، کد خروج ۲ |
| بسته پاک‌شده از venv | ✅ پیام کامل، کد خروج ۲ |
| کامپلیت fish (fish 4.9.3) | ✅ `complete -C` |
| کامپلیت bash | ✅ `bash -n` + اجرای واقعی |
| کامپلیت zsh (zsh 5.9) | ✅ `_arguments` با ۱۱ مشخصه |
| قراردادها روی clone تازه از GitHub | **۳۱۲ PASS / ۰ FAIL** |
| اکشن ریلیز `v2.1.2` | ✅ سبز (pypi: skipped) |

## یک باگ که خودم ساختم و همان‌جا گرفتم

نسخهٔ اول `selfcheck` فایل `gozar.pyz` را «پوشهٔ بدون `__init__.py`» دید و
**FAIL** داد. با اجرای واقعی همان فایل مشخص شد: در یک zipapp ماژول‌ها داخل zip
هستند، نه روی دیسک. حالا آرشیو یک حکم مثبت جدا دارد و یک قرارداد هم آن را قفل
می‌کند.

## نسخه

- `v2.1.2` — تگ زده و منتشر شد
- `main` = `366bc4e`
- ریلیز: <https://github.com/amirreaper/gozar/releases/tag/v2.1.2>
