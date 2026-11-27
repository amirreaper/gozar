"""engines — find (or fetch) the sing-box binary sing-box needs to test nodes.

Resolution order, best first. Every step is cheap and safe; nothing here ever
downloads inside a test loop.

  0. GOZAR_SINGBOX / SINGBOX_BIN      explicit, always wins
  1. ~/.local/share/gozar/engines/    what `gozar engine install` writes
  2. sing-box-bin (pip package)       `pip install sing-box-bin` -> get_bin_path()
  3. ./engines/sing-box               a git checkout that ran install.sh
  4. PATH, ~/.local/bin, /usr/local/bin, /usr/bin, /opt/sing-box

Why the pip package is in the list: it turns "download a 40MB binary from a
GitHub release, match your arch, chmod it" into `pip install sing-box-bin`.
It is a third-party repackaging of the official SagerNet release, so it is
used when present but never required, and doctor says which one it found.
"""
from __future__ import annotations

import os
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

# Where a downloaded engine lives. A pip install must never write into
# site-packages, so the user data dir is used there instead.
_HERE = Path(__file__).resolve().parent.parent
ENGINE_DIR = _HERE / "engines"
# site-packages (pip) and .pyz (single-file zipapp) are both read-only homes:
# engines must go to the user data dir in those cases.
_INSTALLED = any(k in str(_HERE) for k in ("site-packages", "dist-packages"))
if Path(sys.argv[0]).suffix == ".pyz" or ".pyz" in str(_HERE):
    _INSTALLED = True
if _INSTALLED:
    ENGINE_DIR = (Path(os.environ.get("XDG_DATA_HOME")
                       or Path.home() / ".local" / "share") / "gozar" / "engines")

_SEARCH_PATHS = [
    ENGINE_DIR,
    Path.home() / ".local" / "bin",
    Path.home() / ".local" / "share" / "gozar" / "engines",
    Path("/usr/local/bin"),
    Path("/usr/bin"),
    Path("/opt/sing-box"),
]

# What a user can type when nothing is found. Kept in one place so doctor,
# the CLI pre-flight and the README cannot drift apart.
INSTALL_HINTS = """\
gozar needs the sing-box binary (it does the real testing). Short version:

  gozar engine install                # download it here (recommended)
  pip install sing-box-bin            # or let pip carry it
  export GOZAR_SINGBOX=/path/to/sing-box

No network at all? Then one of:
  sudo apt install sing-box | sudo dnf install sing-box | nix profile install nixpkgs#sing-box
  (any sing-box on PATH is found automatically)"""


def _ensure_executable(path: Path) -> None:
    try:
        st = path.stat()
        if not (st.st_mode & stat.S_IXUSR):
            path.chmod(st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def _from_pip_package() -> Path | None:
    """sing-box-bin ships the official binaries for linux/mac/windows."""
    try:
        from sing_box_bin import get_bin_path       # type: ignore
    except Exception:
        return None
    try:
        p = Path(get_bin_path())
        return p if p.exists() else None
    except Exception:
        # e.g. unsupported architecture — fall through to the other sources
        return None


def find_binary(name: str) -> Path | None:
    """Locate a binary: env override, gozar engines dir, pip package, PATH."""
    env_name = name.upper().replace("-", "") + "_BIN"
    for var in (env_name, "SINGBOX_BIN" if name == "sing-box" else "", "GOZAR_SINGBOX"):
        if var:
            cand = os.environ.get(var)
            if cand and Path(cand).exists():
                _ensure_executable(Path(cand))
                return Path(cand)
    if name == "sing-box":
        packaged = _from_pip_package()
        if packaged is not None:
            _ensure_executable(packaged)
            return packaged
    bundled = ENGINE_DIR / name
    if bundled.exists():
        _ensure_executable(bundled)
        return bundled
    found = shutil.which(name)
    if found:
        return Path(found)
    for d in _SEARCH_PATHS:
        cand = d / name
        if cand.exists():
            _ensure_executable(cand)
            return cand
    return None


SINGBOX = find_binary("sing-box")


def first_version_line(binary) -> str | None:
    """`sing-box version 1.14.5`, or None if the binary will not run.

    The single place that asks a binary what it is. doctor, `engine status` and
    the post-install proof all print the same first line because they all call
    this — before, each one ran its own subprocess and formatted it differently.
    """
    if not binary:
        return None
    try:
        import subprocess
        out = subprocess.run([str(binary), "version"], capture_output=True,
                             text=True, timeout=10).stdout
    except Exception:                                    # noqa: BLE001
        return None
    for line in (out or "").splitlines():
        if line.strip():
            return line.strip()
    return None


def source_of(path: Path | None) -> str:
    """A short label for doctor: WHERE the binary came from, not just that it exists."""
    if path is None:
        return "not found"
    s = str(path)
    if "sing_box_bin" in s:
        return "pip package sing-box-bin"
    if s.startswith(str(ENGINE_DIR)):
        return "gozar engines dir"
    if s.startswith(str(Path.home() / ".local" / "bin")):
        return "~/.local/bin"
    for env in ("GOZAR_SINGBOX", "SINGBOX_BIN", "SINGBOX_BIN"):
        if os.environ.get(env) and Path(os.environ[env]) == path:
            return f"${env}"
    return "PATH" if shutil.which("sing-box") == s else str(path.parent)


def require_singbox() -> Path:
    """Return the engine or explain exactly how to get one (never a bare None)."""
    p = find_binary("sing-box")
    if p is None:
        raise SystemExit(
            "gozar: sing-box was not found.\n\n" + INSTALL_HINTS + "\n")
    return p


# ─────────────────────── downloading the official release ────────────────

_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"


def _arch_tag() -> str:
    m = platform.machine().lower()
    if sys.platform == "darwin":
        return {"arm64": "arm64", "aarch64": "arm64"}.get(m, "amd64")
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m.startswith("armv"):
        return "armv7"
    raise SystemExit(f"gozar: unsupported architecture for a download: {m}\n"
                     "       install sing-box yourself and set GOZAR_SINGBOX=...")


def confirm_install(assume_yes: bool = False) -> bool:
    """Ask before a 32MB download. Non-interactive runs need --yes.

    `assume_yes` answers the question for the user; it does not touch how much
    is printed (that is `quiet`). Two different intents, two different flags.
    """
    if assume_yes:
        return True
    import sys
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        # a pipe or a script: say what to do instead of hanging on input()
        print("gozar: not downloading without confirmation. Re-run with "
              "`gozar engine install --yes`, or `pip install sing-box-bin`.")
        return False
    try:
        ans = input(f"  download sing-box (~32MB) into {ENGINE_DIR}? [Y/n] ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans.strip().lower() in ("", "y", "yes")


def install_official(target_dir: Path | None = None, quiet: bool = False) -> Path:
    """Download the official sing-box release into the gozar engines dir.

    Only `gozar engine install` calls this. The test loop never does: a run must
    not depend on GitHub being reachable mid-test.
    """
    import json

    dest = Path(target_dir or ENGINE_DIR)
    dest.mkdir(parents=True, exist_ok=True)
    os_name = {"darwin": "darwin"}.get(sys.platform, "linux")
    arch = _arch_tag()

    def say(msg: str, status: str | None = None) -> None:
        if quiet:
            return
        if status:
            from . import core_ui as U
            U.say(status, msg.strip())
        else:
            print(msg, flush=True)

    say("looking up the latest sing-box release ...")
    try:
        with urllib.request.urlopen(_API, timeout=20) as r:
            rel = json.load(r)
    except Exception as e:                                   # noqa: BLE001
        raise SystemExit(f"gozar: could not reach GitHub to find the release: {e}\n\n"
                         + INSTALL_HINTS)
    tag = rel.get("tag_name", "").lstrip("v")
    asset = next((a for a in rel.get("assets", [])
                  if f"-{os_name}-{arch}." in a["name"]), None)
    if not asset:
        raise SystemExit(f"gozar: release {tag} has no {os_name}-{arch} build.\n\n"
                         + INSTALL_HINTS)
    say(f"downloading {asset['name']} ({asset['size'] / 1e6:.1f}MB) ...")
    with tempfile.TemporaryDirectory() as tmp:
        tgz = Path(tmp) / "sb.tar.gz"
        urllib.request.urlretrieve(asset["browser_download_url"], tgz)
        with tarfile.open(tgz) as tf:
            member = next((m for m in tf.getmembers()
                           if m.name.endswith("/sing-box") or m.name == "sing-box"), None)
            if member is None:
                raise SystemExit("gozar: the archive did not contain a sing-box binary")
            member.name = "sing-box"          # flatten: no nested dirs
            tf.extract(member, Path(tmp) / "out")
        out = Path(tmp) / "out" / "sing-box"
        final = dest / "sing-box"
        shutil.move(str(out), final)
    final.chmod(final.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    say(f"installed: {final}", "ok")
    # prove it runs BEFORE telling the user we are done: a downloaded binary
    # that cannot execute (wrong arch, blocked loader) must not look like success
    try:
        import subprocess
        v = subprocess.run([str(final), "version"], capture_output=True,
                           text=True, timeout=10).stdout.strip().splitlines()
        say(f"works: {v[0] if v else 'ran, but printed nothing'}", "ok")
    except Exception as e:                                   # noqa: BLE001
        raise SystemExit(f"gozar: downloaded {final} but it will not run: {e}\n"
                         "       try: pip install sing-box-bin")
    return final
