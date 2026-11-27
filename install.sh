#!/usr/bin/env bash
# install.sh — get gozar working from a git checkout.
#
#   bash install.sh                 # engine only (the fast path, what most people want)
#   bash install.sh --venv          # + a local .venv with the two dependencies
#   bash install.sh --system        # + pip install --user (gozar on PATH)
#
# Rules this script follows:
#   * it never overwrites a working engine
#   * it never needs root
#   * when it cannot do something, it prints the exact command instead of failing
set -euo pipefail
cd "$(dirname "$0")"

WANT_VENV=0; WANT_SYSTEM=0
for a in "$@"; do
  case "$a" in
    --venv) WANT_VENV=1 ;;
    --system) WANT_SYSTEM=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

say() { printf "==> %s\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# 1) python
PY="${PYTHON:-python3}"
have "$PY" || { echo "ERROR: python3 is required (3.10 or newer)" >&2; exit 2; }
"$PY" - <<'PY' || { echo "ERROR: python 3.10+ is required" >&2; exit 2; }
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
say "python: $("$PY" -V)"

# 2) dependencies
if "$PY" -c "import aiohttp, aiohttp_socks" >/dev/null 2>&1; then
  say "dependencies: already available"
elif [ "$WANT_VENV" = 1 ]; then
  say "creating .venv and installing the two dependencies"
  "$PY" -m venv .venv
  ./.venv/bin/pip install -q -r requirements.txt
  say "dependencies: installed in .venv (the ./cli launcher picks it up)"
elif [ "$WANT_SYSTEM" = 1 ]; then
  say "installing gozar with pip --user"
  "$PY" -m pip install --user -q -e . 2>/dev/null || "$PY" -m pip install --user -q aiohttp aiohttp-socks
else
  cat <<'MSG'
    dependencies: NOT installed (aiohttp, aiohttp-socks)
      bash install.sh --venv        # local .venv, nothing system-wide
      bash install.sh --system      # pip install --user
      pip install gozar             # or just use the packaged version
MSG
fi

# 3) the engine
say "checking the testing engine (sing-box)"
"$PY" -m gozar engine status || true
if ! "$PY" -m gozar engine status >/dev/null 2>&1; then
  say "downloading the official sing-box release into ./engines"
  "$PY" -m gozar engine install --to "$(pwd)/engines" || {
    echo "    could not download. Alternatives:" >&2
    echo "      pip install sing-box-bin" >&2
    echo "      export GOZAR_SINGBOX=/path/to/sing-box" >&2
  }
fi

say "done — try:  ./cli --version   and   ./cli doctor"
