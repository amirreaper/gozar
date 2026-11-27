"""gozar — Collect, check and maintain public proxy lists."""
APP_NAME = "gozar"            # "gozar" = the passage through
__version__ = "2.0.0"

# Vendored third-party packages (vendor/ at repo root) take precedence over
# system site-packages. This keeps the bot working where `pip install --user`
# is not viable or persistent. Install with:
#   pip install --target=vendor -r requirements.txt
import sys as _sys
from pathlib import Path as _Path

_vendor = _Path(__file__).resolve().parent.parent / "vendor"
if _vendor.is_dir() and str(_vendor) not in _sys.path:
    _sys.path.insert(0, str(_vendor))
