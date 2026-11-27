"""selfcheck — `gozar selfcheck`: did THIS install actually land intact?

`gozar doctor` answers "can gozar do its job on this line?" (engine, sources,
ping, a live tunnel test). This answers a different and much more basic
question: "is the gozar that you just ran the one you installed, with all its
files, on the interpreter its launcher points at?"

That question exists because of a real report (2026-11-28). The user ran

    pip install --user "git+https://github.com/amirreaper/gozar.git"
    gozar
    ModuleNotFoundError: No module named 'gozar'

and there are four completely different causes that produce those exact two
lines of traceback:

    1. the script in ~/.local/bin runs an interpreter that cannot see the
       user site (PYTHONNOUSERSITE=1, or python3 -s, or a venv without
       --system-site-packages).  -> reproduced here, byte for byte
    2. a broken .pth / leftover *namespace* directory called `gozar` that has
       no __init__.py, so the import resolves to something that is not us
    3. pip did land it, but in another interpreter's site-packages than the
       `python3` on PATH (two pythons: /usr/bin and /usr/local/bin)
    4. the install is fine and the PATH entry belongs to a different install
       (an old copy in ~/.local/bin shadowing the venv one)

A traceback cannot tell these apart, and "reinstall" fixes only one of them.
So this command prints the four facts that do:

    launcher -> interpreter -> sys.path -> the files themselves
"""
from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import core_ui as U
from .core_ui import FAIL, OK, WARN

# every module in the package; a missing one is a half-copied install
_EXPECTED = [
    "__init__", "__main__", "cli", "config", "core_ui", "core_sources",
    "core_parser", "core_runner", "core_test", "core_store", "core_output",
    "core_connect", "core_live", "core_score", "doctor",
    "doctor_checks", "engines", "thresholds", "ui_pick", "checker", "display",
]


def _pkg_dir() -> Path:
    return Path(__file__).resolve().parent


def _in_archive() -> bool:
    """True when the code is running from a zipapp (.pyz) — a single file.

    The files are real, they are just *inside a zip*: `Path(__file__)` points
    into `gozar.pyz/gozar/`, which has no directory entries, no __init__.py and
    no .py files on disk. Reporting that as "leftover namespace directory" was a
    false FAIL on the single-file runner (2026-11-14), the one install the user
    asked to keep. So the archive case gets its own, positive, verdict.
    """
    return ".pyz" in str(Path(__file__).resolve()) or \
        Path(sys.argv[0]).suffix == ".pyz"


def _read_shebang(script: Path) -> str | None:
    try:
        first = script.open("rb").readline()
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    text = first[2:].decode("utf-8", "replace").strip()
    return text.split()[0] if text else None


def find_launchers() -> list[tuple[Path, str | None]]:
    """Every `gozar` executable on PATH, with the interpreter it points at."""
    out: list[tuple[Path, str | None]] = []
    seen: set[str] = set()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        cand = Path(d) / "gozar"
        if cand.exists() and os.access(cand, os.X_OK):
            real = str(cand.resolve())
            if real in seen:
                continue
            seen.add(real)
            out.append((cand, _read_shebang(cand)))
    return out


def _interpreter_facts(exe: str) -> dict:
    """Ask an interpreter three questions: user site, sys.path, can it import us."""
    code = (
        "import json,site,sys;"
        "print(json.dumps({"
        "'exe': sys.executable,"
        "'ver': '%d.%d.%d' % sys.version_info[:3],"
        "'prefix': sys.prefix,"
        "'base': sys.base_prefix,"
        "'venv': sys.prefix != sys.base_prefix,"
        "'usersite': site.getusersitepackages(),"
        "'enabled': site.ENABLE_USER_SITE,"
        "'pkg': [p for p in sys.path if p.endswith('site-packages')],"
        "}))"
    )
    try:
        r = subprocess.run([exe, "-c", code], capture_output=True, text=True,
                           timeout=20)
    except Exception:                                    # noqa: BLE001
        return {}
    if r.returncode != 0:
        return {}
    try:
        import json
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:                                    # noqa: BLE001
        return {}


def _import_probe(exe: str) -> tuple[bool, str]:
    """Can `exe` import gozar AND does it get OUR copy?"""
    code = ("import gozar,sys;"
            "print(gozar.__file__);"
            "print(getattr(gozar,'__version__','?'))")
    try:
        r = subprocess.run([exe, "-c", code], capture_output=True, text=True,
                           timeout=20)
    except Exception as e:                               # noqa: BLE001
        return False, str(e)
    if r.returncode == 0:
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        return True, lines[0] if lines else "?"
    err = (r.stderr or "").strip().splitlines()
    return False, err[-1] if err else "import failed"


def run_selfcheck(cfg: dict | None = None, fix: bool = False) -> int:
    print("\n=== gozar selfcheck ===")
    ledger = U.Ledger()

    # 1. the running copy ------------------------------------------------------
    here = _pkg_dir()
    version = "?"
    try:
        from . import __version__ as version
    except Exception:                                    # noqa: BLE001
        pass
    ledger.check(OK, f"running copy: {here} (version {version})")
    if _in_archive():
        # a zipapp is self-contained: the files cannot be missing, and there is
        # no launcher situation to debug. Say that, once, and stop.
        ledger.check(OK, "single-file build (gozar.pyz): all modules are inside "
                         "the archive, nothing to install")
        from .engines import find_binary, source_of
        sb = find_binary("sing-box")
        if sb:
            ledger.check(OK, f"engine: {sb} ({source_of(sb)})")
        else:
            ledger.check(WARN, "engine missing — run:  gozar.pyz engine install")
        return ledger.summary("The single-file runner is intact.",
                              "problem(s) found.")
    if not (here / "__init__.py").exists():
        ledger.check(FAIL, "this package directory has no __init__.py — it is a "
                           "leftover namespace directory, not an install")
        U.bullet("delete it and reinstall:  pip install --user --force-reinstall "
                 "git+https://github.com/amirreaper/gozar.git")
    else:
        ledger.check(OK, "__init__.py present (this is a real package)")

    # 2. every module that should be here, is here -----------------------------
    missing = [m for m in _EXPECTED if not (here / f"{m}.py").exists()]
    if missing:
        ledger.check(FAIL, f"{len(missing)} module(s) missing: "
                           f"{', '.join(missing)}")
        U.bullet("this install is incomplete — reinstall (see the last line)")
    else:
        ledger.check(OK, f"all {len(_EXPECTED)} modules present")
        try:
            importlib.import_module(f"{__package__}.cli")
            ledger.check(OK, "the CLI module imports")
        except Exception as e:                           # noqa: BLE001
            ledger.check(FAIL, f"cli imports but fails: {type(e).__name__}: {e}")

    # 3. the launcher and the interpreter it points at -------------------------
    launchers = find_launchers()
    if not launchers:
        ledger.check(WARN, "no `gozar` on PATH — you are running the file "
                           "directly (fine for ./gozar.pyz)")
    for script, shebang in launchers:
        ledger.check(OK, f"launcher: {script} -> {shebang or '?'}")
        if not shebang:
            continue
        facts = _interpreter_facts(shebang)
        ok, where = _import_probe(shebang)
        if ok:
            # is it this very copy, or a second install shadowing it?
            same = str(Path(where).resolve().parent) == str(here)
            ledger.check(OK, f"{shebang} can import gozar ({where})")
            if not same:
                ledger.check(WARN, f"but that is a DIFFERENT copy than the one "
                                   f"running ({here}) — two installs, one PATH")
        else:
            ledger.check(FAIL, f"{shebang} CANNOT import gozar — {where}")
            if facts:
                if facts.get("enabled") is False:
                    ledger.check(WARN, "user site-packages is DISABLED for that "
                                       "interpreter (PYTHONNOUSERSITE / -s)")
                if facts.get("venv") and not facts.get("enabled"):
                    ledger.check(WARN, "it is a venv without "
                                       "--system-site-packages, so a --user "
                                       "install is invisible to it")
            _explain(script, shebang, facts)

    # 4. where did pip actually put it ----------------------------------------
    _pip_landing(ledger, here)

    # 5. the verdict ----------------------------------------------------------
    rc = ledger.summary("This install is intact and importable.",
                        "install problem(s) found.")
    if rc != U.EXIT_OK:
        _how_to_repair(here)
    return rc


def _explain(script: Path, shebang: str, facts: dict) -> None:
    """Name the cause, not just the symptom."""
    if facts.get("enabled") is False:
        U.bullet("cause: that interpreter hides the user site-packages dir that "
                 "pip --user wrote to")
        U.bullet(f"fix  : unset PYTHONNOUSERSITE (or drop -s), or reinstall "
                 f"with:  {shebang} -m pip install --user gozar")
        return
    usersite = facts.get("usersite")
    if usersite and not Path(usersite).exists():
        U.bullet(f"cause: {usersite} does not exist — pip never installed there")
        U.bullet(f"fix  : {shebang} -m pip install --user "
                 "git+https://github.com/amirreaper/gozar.git")
        return
    U.bullet(f"cause: `{shebang}` has no gozar in its sys.path")
    U.bullet(f"fix  : {shebang} -m pip install --user "
             "git+https://github.com/amirreaper/gozar.git")


def _pip_landing(ledger, here: Path) -> None:
    """Ask pip where gozar is installed, and whether that is where we are."""
    pip = shutil.which("pip") or shutil.which("pip3")
    if not pip:
        return
    try:
        r = subprocess.run([pip, "show", "gozar"], capture_output=True,
                           text=True, timeout=30)
    except Exception:                                    # noqa: BLE001
        return
    if r.returncode != 0:
        ledger.check(WARN, "pip show gozar: not installed by this pip — you are "
                           "probably running a checkout or a .pyz")
        return
    loc = next((ln.split(":", 1)[1].strip() for ln in r.stdout.splitlines()
                if ln.lower().startswith("location:")), "")
    ver = next((ln.split(":", 1)[1].strip() for ln in r.stdout.splitlines()
                if ln.lower().startswith("version:")), "")
    # a source checkout next to the installed copy is NOT a problem: pip's copy
    # is the one on PATH and this run is a deliberate `python -m gozar` from the
    # checkout. Only say "two installs" when the RUNNING copy is itself installed.
    running_from_checkout = (here.parent / ".git").exists()
    if loc and Path(loc).resolve() != here.parent and not running_from_checkout:
        ledger.check(WARN, f"pip's gozar ({ver}) lives in {loc}; the one running "
                           f"is {here.parent} — PATH/PYTHONPATH is picking a "
                           "different copy")
    else:
        ledger.check(OK, f"pip agrees: gozar {ver} at {loc}")


def _how_to_repair(here: Path) -> None:
    """One short block. Long enough to fix it, short enough to read."""
    py = sys.executable
    print("  " + U.bold("Three commands that fix every case above:"))
    print("      1. see which python the launcher uses:")
    print(f"           head -1 $(command -v gozar)      # -> the interpreter")
    print("      2. install with THAT interpreter, not whichever `pip` came first:")
    print(f"           {py} -m pip install --user --force-reinstall "
          "git+https://github.com/amirreaper/gozar.git")
    print("      3. if user site is disabled on purpose, use a venv instead:")
    print("           python3 -m venv ~/.gozar && ~/.gozar/bin/pip install "
          "git+https://github.com/amirreaper/gozar.git")
    print("           ~/.gozar/bin/gozar doctor")
    print()
