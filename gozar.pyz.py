#!/usr/bin/env python3
"""Build a single-file, executable gozar: ./gozar.pyz

Why: `pip install` is the right answer for a proper install, but a single file
you can `curl -O`, `chmod +x` and run is the fastest way to try it on a machine
where you do not want to touch the Python environment. A zipapp is exactly that
— one file, standard library only, no build tools.

    python3 gozar.pyz.py            # writes ./dist/gozar.pyz
    ./dist/gozar.pyz --help
    ./dist/gozar.pyz engine install
    ./dist/gozar.pyz discover -t https://example.com/ -n 20

Dependencies (aiohttp, aiohttp-socks) are NOT bundled: they are C-extension
wheels per platform. The pyz checks for them at startup and says what to run.
"""
from __future__ import annotations
import shutil
import subprocess
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "dist"

# The zipapp entry point: a tiny main that imports the real CLI.
MAIN = '''\
import sys

def main() -> int:
    try:
        import aiohttp  # noqa: F401
    except ModuleNotFoundError:
        sys.stderr.write(
            "gozar: this build needs its two dependencies:\\n"
            "    pip install aiohttp aiohttp-socks\\n"
            "or install from git:  pip install git+https://github.com/amirreaper/gozar.git\\n")
        return 2
    from gozar.bot import main as _main
    return _main(sys.argv[1:])

if __name__ == "__main__":
    sys.exit(main())
'''


def main() -> int:
    OUT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "app"
        stage.mkdir()
        # copy the package, minus caches
        shutil.copytree(ROOT / "gozar", stage / "gozar",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (stage / "__main__.py").write_text(MAIN)

        target = OUT / "gozar.pyz"
        zipapp.create_archive(stage, target, interpreter="/usr/bin/env python3",
                              compressed=True)
        target.chmod(0o755)

    size = target.stat().st_size
    print(f"  built: {target}  ({size / 1024:.0f}KB)")
    print("  run  : ./dist/gozar.pyz --version")
    # smoke test it right away: a broken zipapp is worse than none
    r = subprocess.run([sys.executable, str(target), "--version"],
                       capture_output=True, text=True)
    ok = r.returncode == 0
    print(f"  check: {r.stdout.strip() or r.stderr.strip().splitlines()[0] if (r.stdout or r.stderr) else 'no output'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
