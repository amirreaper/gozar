"""Entry point: python -m gozar -> the CLI (discover/check/connect/...)."""
from __future__ import annotations
import sys


def main() -> int:
    from .bot import main as _main
    return _main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
