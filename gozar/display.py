"""display — TTY-aware paint layer.

All decorative output lives here. Rules:
  - TTY gets color/bars/cards; pipes get plain text (auto-detected)
  - nothing in the data paths touches this; it is cosmetics only
"""
from __future__ import annotations

import sys

DIM = "\x1b[2m"; BOLD = "\x1b[1m"; RST = "\x1b[0m"
GRN = "\x1b[32m"; YEL = "\x1b[33m"; BLU = "\x1b[34m"; CYN = "\x1b[36m"
RED = "\x1b[31m"; GRY = "\x1b[90m"


def tty() -> bool:
    return sys.stderr.isatty() or sys.stdout.isatty()


def c(colour: str, text: str) -> str:
    return f"{colour}{text}{RST}" if tty() and text else text


def bar_ms(ms, max_ms=2200, width=8) -> str:
    """Latency bar: ▮ filled by time ratio; · when unknown."""
    if ms is None:
        return c(GRY, "·" * width)
    fill = round(width * min(max_ms, float(ms)) / max_ms)
    full = "▮" * fill
    rest = "▯" * (width - fill)
    return c(GRY, full + rest) if not tty() else f"{GRY}{full}{RST}{DIM}{rest}{RST}"


def age_str(ts, now: int | None = None) -> str:
    """Human age of a timestamp: 12s / 3m / 2h / 4d / —."""
    if not ts:
        return "—"
    import time as _t
    d = max(0, int((now or _t.time()) - int(ts)))
    if d < 60:
        return f"{d}s"
    if d < 3600:
        return f"{d // 60}m"
    if d < 86400:
        return f"{d // 3600}h"
    return f"{d // 86400}d"


def last_verdict(r: dict, now: int | None = None) -> str:
    """What the MOST RECENT check said, with its age: 'ok·2m', 'FAIL·5m (dead)'.

    Without this a re-check looks like it changed nothing: the latency column
    still shows the last good number and nothing says the node is gone.
    """
    age = age_str(r.get("last_check") or r.get("last_seen"), now)
    if r.get("alive_now") is False or r.get("tier") == "dead":
        why = r.get("last_result") or "dead"
        return c(RED, f"FAIL·{age}") + c(GRY, f" ({why})")
    res = r.get("last_result") or ("ok" if r.get("successes") else "—")
    # a node can be alive (carries a page) yet fail the target: say so plainly
    # instead of printing a generic "error" that looks like a dead node.
    from .core_store import target_now
    if r.get("alive_now") and r.get("target_ok_now") is not None and not target_now(r):
        # alive but target failed: the honest label is "no_target" (or "no_page"
        # when it could not even open a page), never a bare "error".
        res = "no_page" if r.get("page_ok") is False else "no_target"
    col = GRN if res == "ok" else (CYN if res == "no_target" else YEL)
    return c(col, f"{res}·{age}")


def is_stale(r: dict, max_age_s: int = 7200, now: int | None = None) -> bool:
    """True when the displayed numbers are old enough to be untrustworthy."""
    import time as _t
    ts = r.get("last_check") or r.get("last_ok") or r.get("last_seen")
    if not ts:
        return True
    return ((now or _t.time()) - int(ts)) > max_age_s


def node_mark(r: dict, fast_ms=1200) -> str:
    """One-glyph verdict for a result row (Style A).

    Order matters: a node that FAILED its last check is ☓ no matter what its
    stored latency or history says — otherwise a dead node keeps showing the
    ★/● it earned before it died.
    """
    if r.get("alive_now") is False or r.get("tier") == "dead":
        return c(RED, "☓")
    if r.get("leak"):
        return c(RED, "⚠")
    lat = r.get("latency")
    if not r.get("alive", True):
        return c(GRY, "☓")
    # "◆" = alive but NOT target-passing *right now*. The lifetime counter
    # (target_ok) must not be used here: a node that passed a target last month
    # and failed today is a gen node, not a best one.
    from .core_store import target_now
    if r.get("target_ok_now") is None:
        # liveness-only run (no targets configured): the node is alive and that
        # is all we claim — show the speed glyph, not the "no-target" diamond.
        if lat is not None and lat <= fast_ms:
            return c(GRN, "★")
        return c(YEL, "●")
    if r.get("tier") == "general" or not target_now(r):
        # ◆ = alive and usable (it IS listed in best/bak now), but it did not
        # clear every target on its last check: that is a rank, not a rejection.
        return c(CYN, "◆")
    if lat is not None and lat <= fast_ms:
        return c(GRN, "★")
    return c(YEL, "●")


def signal_dot(ms) -> str:
    if ms is None:
        return c(GRY, "●")
    if ms < 400:
        return c(GRN, "●")
    if ms < 1300:
        return c(YEL, "●")
    return c(RED, "●")


def fmt_ms(ms, fallback="    —") -> str:
    return f"{float(ms):>7.0f}ms".rstrip() if ms is not None else fallback


def progress_bar(done, total, width=14) -> str:
    frac = (done / total) if total else 0
    fill = round(width * frac)
    return "█" * fill + "░" * (width - fill)


def fancy_progress(tag, done, total, alive, fast, best_n, elapsed_s, tok=None) -> str:
    """Style C1 — the selected live status line."""
    tok_val = alive if tok is None else tok
    return (f"  {tag} {progress_bar(done, total)} {done}/{total}"
            f" | alive:{c(GRN, str(alive))}"
            f" | fast:{c(YEL, f'{fast}/{best_n}')}"
            f" | tok:{tok_val}"
            f" | {_dur(elapsed_s)}")


def _dur(s) -> str:
    s = int(s)
    return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"


def card(lines: list[tuple[str, str]], width=72, title: str = "summary") -> str:
    """Style B — boxed summary card. `lines` = [(label, value)].
    The label column auto-sizes so long labels (e.g. `gozar verify`) stay aligned."""
    out = []
    hdr = f"╭{'─'} {BOLD}{title}{RST} " if tty() else f"-- {title} "
    out.append(c(CYN, hdr) if tty() else hdr)
    lab_w = max([9] + [len(str(l)) for l, _ in lines])
    for label, value in lines:
        lab = c(GRY, str(label).rjust(lab_w))
        out.append(f"  {lab}  {value}")
    out.append(c(CYN, "╰" + "─" * min(width - 14, 58)))
    return "\n".join(out)

def list_row(idx: int, sid: str, r: dict, fast_ms: int = 1200) -> str:
    """Styled row for `bot list` (Style A): verdict glyph + protocol +
    server + latency bar + smoothed latency + short id + tag.

    The latency is greyed once it is stale, and `last:` always states what the
    most recent check actually decided, so an old number can never pass for a
    current measurement."""
    lab = node_mark(r, fast_ms)
    lat = r.get("avg_latency") or r.get("latency")
    lat_s = f"{lat:.0f}" if lat else "—"
    dead = r.get("alive_now") is False or r.get("tier") == "dead"
    stale = dead or is_stale(r)
    # "~" = this is the LAST KNOWN number, not a current measurement
    lat_cell = c(GRY, f"{'~' if dead else ''}{lat_s:>4}ms") if stale else f"{lat_s:>4}ms"
    proto = c(BLU, str(r.get("type", "?")).ljust(10))
    srv = f"{r.get('server', '?')}:{r.get('server_port', '?')}"
    stab = int(r.get("stability", 0) * 100)
    tg = f"{r.get('target_ok', 0)}/{r.get('checks', 0)}"
    ex = r.get("exit_loc") or ""
    ex_s = c(GRY, f" exit:{ex}") if ex else ""
    tag = (r.get("tag") or "").strip()[:26]
    return (f"  {lab} {GRN if tty() else ''}{idx:>2}{RST if tty() else ''} "
            f"[{sid}] {proto} {srv:<27} {bar_ms(lat)} {lat_cell}"
            f"  stab:{stab:>3}%  tgt:{tg:<5} last:{last_verdict(r)}{ex_s} {c(GRY, tag)}")
