#!/usr/bin/env python3
"""gozar-rescue — diagnose `ModuleNotFoundError: No module named 'gozar'`.

Why this file exists
--------------------
`gozar selfcheck` needs gozar to be importable. The report this answers is
exactly the case where it is NOT:

    Successfully installed gozar-2.1.1
    (amir) amir@laptop /work> gozar
    Traceback (most recent call last):
      File "/home/amir/.local/bin/gozar", line 3, in <module>
        from gozar.cli import cli
    ModuleNotFoundError: No module named 'gozar'

So this script imports NOTHING from the project — standard library only. Run it
with the interpreter your launcher points at, or with your normal python3:

    python3 rescue.py

or without downloading anything:

    curl -fsSL https://raw.githubusercontent.com/amirreaper/gozar/main/scripts/gozar-rescue.py | python3 -

It prints: the interpreter, whether the user site is enabled, every `gozar`
launcher on PATH and whether that launcher's interpreter can import the package,
and the three commands that fix each case.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

PKG = "gozar"

PROBE = (
    "import json,sys,site\n"
    "d={'exe':sys.executable,'ver':'%d.%d.%d'%sys.version_info[:3],"
    "'venv':sys.prefix!=sys.base_prefix,'prefix':sys.prefix,"
    "'usersite':site.getusersitepackages(),'enabled':site.ENABLE_USER_SITE,"
    "'path':[p for p in sys.path if p]}\n"
    "try:\n"
    "    import gozar\n"
    "    d['found']=getattr(gozar,'__file__',None)\n"
    "    d['version']=getattr(gozar,'__version__','?')\n"
    "except Exception as e:\n"
    "    d['found']=None\n"
    "    d['error']=type(e).__name__+': '+str(e)\n"
    "print(json.dumps(d))\n"
)


def probe(interpreter):
    try:
        r = subprocess.run([interpreter, "-c", PROBE], capture_output=True,
                           text=True, timeout=25)
    except Exception as e:                                # noqa: BLE001
        return {"exe": interpreter, "found": None, "error": f"cannot run: {e}"}
    if not r.returncode:
        for line in reversed(r.stdout.strip().splitlines()):
            try:
                return json.loads(line)
            except ValueError:
                continue
    err = (r.stderr or "").strip().splitlines()
    return {"exe": interpreter, "found": None,
            "error": err[-1] if err else "probe failed"}


def launchers():
    out, seen = [], set()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = Path(d or ".") / "gozar"
        if p.exists() and os.access(p, os.X_OK):
            real = str(p.resolve())
            if real not in seen:
                seen.add(real)
                out.append(p)
    return out


def shebang(script):
    try:
        first = script.open("rb").readline()
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    parts = first[2:].decode("utf-8", "replace").split()
    return parts[0] if parts else None


def line(tag, msg):
    print(f"  [{tag}] {msg}")


def main():
    print("\n=== gozar rescue ===")
    print(f"  running under: {sys.executable}  "
          f"({sys.version_info.major}.{sys.version_info.minor}."
          f"{sys.version_info.micro})")

    me = probe(sys.executable)
    if me.get("found"):
        line("OK", f"this interpreter CAN import gozar: {me['found']} "
                   f"(version {me.get('version')})")
    else:
        line("!!", f"this interpreter CANNOT import gozar — {me.get('error')}")
        if me.get("enabled") is False:
            line("--", "user site-packages is DISABLED here (PYTHONNOUSERSITE "
                       "or python -s), so a `pip install --user` is invisible")
        if me.get("venv"):
            line("--", f"this is a venv ({me.get('prefix')}) — a --user install "
                       "does not go in there")

    found_any = False
    for script in launchers():
        found_any = True
        exe = shebang(script) or sys.executable
        info = probe(exe)
        if info.get("found"):
            line("OK", f"{script} -> {exe} sees gozar {info.get('version')}")
        else:
            line("!!", f"{script} -> {exe} CANNOT import gozar — "
                       f"{info.get('error')}")
            if info.get("enabled") is False:
                line("--", "  cause: that interpreter hides the user site "
                           "(PYTHONNOUSERSITE=1, or `-s`)")
                line("--", f"  fix  : unset PYTHONNOUSERSITE, then reinstall "
                           f"with:  {exe} -m pip install --user --force-reinstall "
                           "git+https://github.com/amirreaper/gozar.git")
            elif info.get("venv") and not Path(info.get("usersite", "")).exists():
                line("--", "  cause: venv without --system-site-packages and no "
                           "package inside it")
                line("--", f"  fix  : {exe} -m pip install "
                           "git+https://github.com/amirreaper/gozar.git")
            else:
                line("--", f"  fix  : {exe} -m pip install --user "
                           "--force-reinstall "
                           "git+https://github.com/amirreaper/gozar.git")
        print(f"       user site : {info.get('usersite')} "
              f"(enabled={info.get('enabled')})")
    if not found_any:
        line("--", "no `gozar` script on PATH — nothing to fix here, install it")

    print("\n  What to do, in order:")
    print("    1. use one interpreter for BOTH steps, by full path:")
    print("         /path/to/python3 -m pip install --user --force-reinstall \\")
    print("             git+https://github.com/amirreaper/gozar.git")
    print("         /path/to/python3 -m gozar --version")
    print("    2. only then trust the `gozar` command (it is the same python)")
    print("    3. cleanest fix, no user-site surprises:")
    print("         python3 -m venv ~/.gozar")
    print("         ~/.gozar/bin/pip install "
          "git+https://github.com/amirreaper/gozar.git")
    print("         ~/.gozar/bin/gozar doctor")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
