"""Resolve the sing-box binary from multiple locations."""
from __future__ import annotations
import os
import shutil
import stat
from pathlib import Path

# Where a downloaded engine lives. Two layouts are supported:
#   * a git checkout:  <repo>/engines/sing-box        (next to the package)
#   * a pip install:   ~/.local/share/gozar/engines/  (the package dir is
#     site-packages, which must never be written to)
ENGINE_DIR = Path(__file__).resolve().parent.parent / "engines"
if "site-packages" in str(ENGINE_DIR) or "dist-packages" in str(ENGINE_DIR):
    ENGINE_DIR = (Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
                  / "gozar" / "engines")

_SEARCH_PATHS = [
    ENGINE_DIR,
    Path.home() / ".local" / "bin",
    Path.home() / ".local" / "share" / "gozar" / "engines",
    Path("/usr/local/bin"),
    Path("/usr/bin"),
    Path("/opt/sing-box"),
]


def _ensure_executable(path: Path) -> None:
    try:
        st = path.stat()
        if not (st.st_mode & stat.S_IXUSR):
            path.chmod(st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def find_binary(name: str) -> Path | None:
    """Locate a binary by checking env override, engines/, PATH, install dirs."""
    # 0) explicit environment override (used by tools/devtest.sh to keep
    #    the heavy binary in /tmp instead of the workspace)
    env_name = name.upper().replace("-", "") + "_BIN"
    for var in (env_name, "SINGBOX_BIN" if name == "sing-box" else "", "GOZAR_SINGBOX"):
        if var:
            cand = os.environ.get(var)
            if cand and Path(cand).exists():
                _ensure_executable(Path(cand))
                return Path(cand)
    # 1) bundled in engines/
    bundled = ENGINE_DIR / name
    if bundled.exists():
        _ensure_executable(bundled)
        return bundled
    # 2) system PATH
    found = shutil.which(name)
    if found:
        return Path(found)
    # 3) common directories
    for d in _SEARCH_PATHS:
        cand = d / name
        if cand.exists():
            _ensure_executable(cand)
            return cand
    return None


SINGBOX = find_binary("sing-box")


def require_singbox() -> Path:
    if SINGBOX is None or not SINGBOX.exists():
        raise FileNotFoundError(
            "sing-box binary not found. Install it with `bash install.sh` "
            "or place it in ./engines/ , or install system-wide."
        )
    return SINGBOX
