"""core_ui — the small vocabulary every command speaks.

Why this module exists
---------------------
Commands were each printing their own opinion of the same three words: OK,
WARN, FAIL. doctor had `_ok/_warn/_fail`, cli.py printed coloured strings by
hand, engines.py printed bare lines. Nothing was wrong with any single one of
them — the problem is that "how a warning looks" was decided in nine places,
so it drifted (one said ``[WARN]``, another said ``warning:``, a third printed
in red for something that was not an error).

This is a *functional* module on purpose: no classes, no state, no instance
to pass around. Every function takes what it needs and returns a string or a
number. That makes it trivially testable and safe to call from any layer.

    Status   -> the three-level verdict vocabulary
    say      -> print one line in that vocabulary
    ledger   -> collect issues, print a summary, return the exit code
    rule     -> a section heading, so long commands read as chapters
    wrap     -> fold a long line to the terminal width
    bullet   -> indent a detail line under a status line
"""
from __future__ import annotations

import shutil
import sys
from typing import Iterable, Iterator, Sequence

from .display import BOLD, DIM, GRN, RED, RST, YEL, tty

# ── the vocabulary ────────────────────────────────────────────────────────────

OK = "ok"
WARN = "warn"
FAIL = "fail"

_TAG = {
    OK: ("[OK]", GRN),
    WARN: ("[WARN]", YEL),
    FAIL: ("[FAIL]", RED),
}

# Exit codes the whole tool agrees on. Anything that returns an int from a
# command must return one of these; tests/test_contracts.py enforces it.
EXIT_OK = 0          # did the job
EXIT_CANNOT_RUN = 2  # missing engine, bad flags, refused to act
EXIT_NOTHING = 3     # ran fine, nothing passed
EXIT_CANCELLED = 130  # Ctrl+C


def tag(status: str) -> str:
    """The bracketed, coloured marker for a status: '[OK]', '[WARN]', '[FAIL]'."""
    label, colour = _TAG.get(status, _TAG[OK])
    return f"{colour}{label}{RST}" if tty() else label


def line(status: str, message: str) -> str:
    """One status line, ready to print."""
    return f"  {tag(status)} {message}"


def say(status: str, message: str) -> None:
    """Print a status line. The only way a command is allowed to complain."""
    print(line(status, message))


def bullet(message: str) -> None:
    """A detail line under a status line — six spaces, never a new status."""
    print(f"      {DIM if tty() else ''}{message}{RST if tty() else ''}")


def dim(text: str) -> str:
    return f"{DIM}{text}{RST}" if tty() else text


def bold(text: str) -> str:
    return f"{BOLD}{text}{RST}" if tty() else text


def note(text: str) -> None:
    """Section heading: the start of a chapter in a long command."""
    print(f"\n  {text}")


def rule(title: str = "") -> None:
    """A blank line plus a heading — the way doctor separates its sections."""
    print(f"\n=== {title} ===" if title else "")


# ── the issue ledger ─────────────────────────────────────────────────────────

class Ledger:
    """Counts problems and decides what the exit code is.

    A doctor-style command has many independent checks and one verdict. Before
    this, each check did ``issues += 1`` in the middle of a 200-line function,
    so forgetting one was invisible. Now a check returns OK/WARN/FAIL and the
    ledger does the arithmetic.
    """

    __slots__ = ("fail", "warn")

    def __init__(self) -> None:
        self.fail = 0
        self.warn = 0

    def add(self, status: str) -> str:
        """Record a status, print the line yourself. Returns the status."""
        if status == FAIL:
            self.fail += 1
        elif status == WARN:
            self.warn += 1
        return status

    def check(self, status: str, message: str) -> str:
        """Record and print in one step — the common case."""
        say(status, message)
        return self.add(status)

    def summary(self, ok_text: str, fail_text: str) -> int:
        """Print the verdict and return the process exit code."""
        rule("summary")
        if self.fail == 0:
            print(f"  {GRN if tty() else ''}{ok_text}{RST if tty() else ''}\n")
            return EXIT_OK
        print(f"  {RED if tty() else ''}{self.fail} {fail_text}"
              f"{RST if tty() else ''}\n")
        return min(EXIT_NOTHING, EXIT_CANNOT_RUN)  # 2: cannot run


# ── text ────────────────────────────────────────────────────────────────────

def width(default: int = 78, cap: int = 100, stream=None) -> int:
    """Usable terminal width, clamped so one line never becomes a wall.

    Follows `stream` (stdout by default): when output is redirected to a file or
    a pipe the terminal size is meaningless, so the plain default is used.
    """
    stream = stream or sys.stdout
    try:
        if not stream.isatty():
            return default
        return max(40, min(cap, shutil.get_terminal_size((default, 24)).columns))
    except Exception:                                    # noqa: BLE001
        return default


def wrap(text: str, indent: int = 6, limit: int | None = None) -> str:
    """Fold long prose to the terminal, keeping the indent. Returns the block."""
    import textwrap
    w = max(30, (limit or width()) - indent)
    out = []
    for para in str(text).splitlines() or [""]:
        out.extend(textwrap.wrap(para, w) or [""])
    pad = " " * indent
    return "\n".join(pad + ln for ln in out)


def indent_of(lines: Iterable[str], pad: int = 6) -> list[str]:
    pre = " " * pad
    return [pre + ln for ln in lines]


def hints(lines: Sequence[str], pad: int = 6) -> None:
    """Print an install-hint block: the blank lines stay blank, the rest indents."""
    for ln in lines:
        print(" " * pad + ln if ln.strip() else ln)


def first_line(text: str | None, fallback: str = "") -> str:
    """First non-empty line of a tool's output — versions, one-line errors."""
    for ln in str(text or "").splitlines():
        if ln.strip():
            return ln.strip()
    return fallback


def plural(n: int, one: str, many: str | None = None) -> str:
    """'1 node' / '3 nodes' — the labels in every report got this wrong."""
    return f"{n} {one if n == 1 else (many or one + 's')}"


def truncate(text: str, n: int = 70, mark: str = "…") -> str:
    text = str(text)
    return text if len(text) <= n else text[: n - len(mark)] + mark


def table(rows: Iterable[Sequence[str]], gap: str = "  ") -> Iterator[str]:
    """Align columns by their widest cell; yields finished lines."""
    cells = [[str(c) for c in row] for row in rows]
    if not cells:
        return
    widths = [max(len(r[i]) for r in cells if i < len(r))
              for i in range(max(len(r) for r in cells))]
    for r in cells:
        yield gap.join(c.ljust(widths[i]) if i < len(r) - 1 else c
                       for i, c in enumerate(r))


def is_tty() -> bool:
    """Re-exported so callers do not import display just to ask this."""
    try:
        return sys.stdout.isatty() or tty()
    except Exception:                                    # noqa: BLE001
        return False
