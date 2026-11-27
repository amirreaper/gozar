"""Interactive node picker — stdlib-only.

`bot pick` opens a curses TUI (if a TTY is available) showing every stored
node with its short id, protocol, latency, stability and score. Golden nodes
(pinned with `g`) are immune to automatic pruning and are always listed
first — they are the "might come back in a few days" premium pool.

Keys:
  j/k or arrows  : move                Enter : connect to selected node
  g              : toggle golden pin   d     : delete node from state
  r              : quick TCP re-ping   c     : mass re-ping everything + resort
  f              : cycle filter (all / fast / backup / golden)
  q              : quit
Without a TTY it falls back to a numbered menu read from stdin, so it also
works over ssh without a terminal and inside scripts.
"""
from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

log = logging.getLogger("ui.pick")

UDP_PROTOCOLS = {"hysteria2", "tuic", "wireguard"}


def _persist_all(cfg: dict | None, state: dict, state_path: Path) -> None:
    """Save state.json AND rewrite best/bak/gen output files so any changes
    made in interactive pick mode (or before Ctrl+C exit) are always saved."""
    from . import core_output as output, core_store as store
    try:
        store.save(state_path, state)
        out_dir = state_path.parent
        best_n = cfg.get("best_n", 50) if cfg else 50
        bak_n = cfg.get("bak_n", cfg.get("backup_n", 50)) if cfg else 50
        gen_n = cfg.get("gen_n", 100) if cfg else 100
        req_t = bool(cfg.get("targets")) if cfg else True
        output.write_files(
            out_dir, state,
            best_n, bak_n,
            require_target=req_t,
            meta={"ts": int(__import__("time").time()),
                  "mode": "pick",
                  "total_state": len(state)},
            n_gen=gen_n,
        )
    except Exception as e:  # noqa: BLE001
        log.debug("pick persist error: %s", e)


def load_nodes(state: dict, require_target: bool = False,
               include_dead: bool = True) -> list[tuple[str, dict]]:
    """Return [(ident, rec), ...] sorted: golden first (pinned, newest pin
    first), then fast / backup / general / rest / dead by score.

    Nodes that FAILED their most recent check are kept in the list (so the
    `dead` filter can show them for bulk deletion) but the default view hides
    them — the picker must show the pool the last check actually produced,
    not the pool from the last successful run.
    """
    from .core_store import is_dead
    group_g, group_a, group_b, group_gen, group_c, group_d = [], [], [], [], [], []
    for ident, r in state.items():
        if r.get("successes", 0) < 1 and not r.get("golden"):
            continue
        from .core_store import target_now
        if require_target and not target_now(r) and not r.get("golden"):
            continue
        item = (ident, r)
        if is_dead(r):
            group_d.append(item)
        elif r.get("golden"):
            group_g.append(item)
        elif r.get("tier") == "fast":
            group_a.append(item)
        elif r.get("tier") == "backup":
            group_b.append(item)
        elif r.get("tier") == "general" or not target_now(r):
            group_gen.append(item)
        else:
            group_c.append(item)
    group_g.sort(key=lambda it: it[1].get("golden_ts", 0), reverse=True)
    keyf = lambda it: it[1].get("score", 0)
    for g in (group_a, group_b, group_gen, group_c, group_d):
        g.sort(key=keyf, reverse=True)
    out = group_g + group_a + group_b + group_gen + group_c
    return out + group_d if include_dead else out


def _lat(r: dict) -> str:
    if r.get("avg_latency"):
        return f"{r['avg_latency']:.0f}ms"
    if r.get("latency"):
        return f"{r['latency']:.0f}ms"
    return "  -  "


def row(idx: int, ident: str, r: dict, width: int = 100) -> str:
    """One display row for a node (styled glyphs/bars on TTY).

    Shows what the LAST check decided (`last:` column) and greys out numbers
    that are no longer current, so a dead node can never look healthy.
    """
    dead = r.get("alive_now") is False or r.get("tier") == "dead"
    tier = r.get("tier", "?")
    mark = {"fast": "F", "backup": "B", "general": "G", "dead": "X"}.get(tier, ".")
    if dead:
        mark = "X"
    if r.get("golden"):
        mark = "⭐"  # golden pin overrides the tier letter, alive or not
    glyph = {"F": "★", "B": "●", "G": "◆", "X": "☓", ".": "·", "⭐": "⭐"}.get(mark, "·")
    stab = r.get("stability", 0) * 100
    # tgt column = the CURRENT target verdict, not a lifetime ratio
    from .core_store import target_now
    if dead:
        tgt = "dead"
    elif r.get("target_ok_now") is None:
        tgt = "live"          # liveness-only run: no target was configured
    else:
        tgt = "ok" if target_now(r) else "—"
    tag = (r.get("tag") or "").strip()[:24]
    lat_raw = r.get("avg_latency") or r.get("latency")
    try:
        from . import display as D
        bar = D.bar_ms(lat_raw) if not dead else D.bar_ms(None)
        proto = D.c(D.BLU, f"{r.get('type','?'):<10}")
        tag_s = D.c(D.GRY, tag)
        # a dead/stale node must not present its old number as a live one
        lat_s = D.c(D.GRY, ("~" if dead else "") + _lat(r)) if (dead or D.is_stale(r)) else _lat(r)
        glyph = D.c(D.RED, glyph) if dead else glyph
        last = D.last_verdict(r)
        ex = r.get("exit_loc")
        ex_s = D.c(D.GRY, f"{ex}") if ex else "  "
    except Exception:  # noqa: BLE001
        bar, proto, tag_s, lat_s, last, ex_s = (
            "", f"{r.get('type','?'):<10}", tag, _lat(r), r.get("last_result", ""),
            r.get("exit_loc") or "")
    base = (f"{idx:>3} {glyph} [{ident[:8]}] {proto} "
            f"{bar} {lat_s:>7} {stab:>4.0f}% {tgt:>5} {ex_s:>2} {last:<18} "
            f"{r.get('server','?'):<17.17}:{r.get('server_port','?')} {tag_s}")
    return base[:width + 60]  # ansi codes add invisible width


def header(width: int = 100) -> str:
    return ("#   T ID       proto      latency stab  tgt  ex last              "
            "server           :port  tag").ljust(width)[:width - 1]


# ------------------------------------------------------------------ re-ping

async def quick_ping(rec: dict, timeout: float = 3.5) -> float | None:
    """Cheap liveness signal without spawning sing-box (TCP or QUIC UDP ping)."""
    from .checker import tcp_ping, udp_quic_ping
    host = rec.get("server")
    port = rec.get("server_port")
    if not host or not port:
        return None
    try:
        if rec.get("type") in UDP_PROTOCOLS:
            ms = await udp_quic_ping(host, int(port), timeout=min(timeout, 1.8))
            if ms is not None:
                return ms
        return await tcp_ping(host, int(port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return None


async def mass_ping(nodes: list, timeout: float = 2.8, workers: int = 64):
    """Mass check: parallel ping of every node. Returns (alive, total).
    per rec: probe_ms (persisted) + _last_ping (in-memory resort signal)."""
    sem = asyncio.Semaphore(max(1, workers))

    async def one(item):
        _ident, r = item
        async with sem:
            ms = await quick_ping(r, timeout=timeout)
        r["_last_ping"] = ms
        r["probe_ms"] = ms

    await asyncio.gather(*(one(it) for it in nodes), return_exceptions=True)
    alive = sum(1 for _, r in nodes if r.get("_last_ping") is not None)
    return alive, len(nodes)


def _group_key(r: dict) -> int:
    if r.get("alive_now") is False or r.get("tier") == "dead":
        return 9                      # failed the last check -> bottom
    if r.get("golden"):
        return 0
    return {"fast": 1, "backup": 2, "general": 3}.get(r.get("tier"), 4)


def resort(nodes: list) -> None:
    """Re-order in-place: golden first, then fast/backup/general/rest; freshly dead
    TCP-node entries sink inside each group; then score desc."""

    def key(item):
        _, r = item
        fresh_dead = ("_last_ping" in r and r["_last_ping"] is None
                      and r.get("type") not in UDP_PROTOCOLS)
        return (_group_key(r), 1 if fresh_dead else 0,
                -float(r.get("score", 0)))
    nodes.sort(key=key)


# Default view = exactly what the user asked for: the pool that PASSED the
# targets. The gen pool (alive but no target) is one keypress away ('g').
FILTER_CYCLE = ["golden", None, "fast", "backup", "general", "slow", "dead", "all"]
FILTER_LABEL = {
    "golden": "golden only (pinned)",
    None: "TARGET-OK (fast+bak)  ← default",
    "fast": "fast (target-ok)",
    "backup": "backup (target-ok, slower)",
    "general": "gen (alive, target NOT passed — general use)",
    "slow": "slow (connected, above backup ceiling)",
    "dead": "DEAD (failed last check — d deletes)",
    "all": "everything except dead",
}

USABLE_TIERS = ("fast", "backup", "general")


def _node_matches(r: dict, flt) -> bool:
    from .core_store import is_dead
    if flt == "golden":
        return bool(r.get("golden"))
    if flt == "dead":
        return r.get("alive_now") is False or r.get("tier") == "dead"
    if is_dead(r):
        return False           # dead nodes only ever appear under the dead filter
    from .core_store import target_now
    if flt is None:
        # default view = the nodes that passed the targets in their LAST check
        # (golden pins always stay visible on top, whatever their state)
        return bool(r.get("golden")) or (r.get("tier") in ("fast", "backup")
                                         and target_now(r))
    if flt == "all":
        return r.get("tier") in USABLE_TIERS or bool(r.get("golden"))
    if flt == "general":
        return r.get("tier") == "general" or not target_now(r)
    return r.get("tier") == flt


def section_rows(nodes: list, flt) -> list[tuple[str | None, int]]:
    """Flatten the view into printable lines: a section header followed by the
    matching node indices.

    Golden pins get their OWN block above everything else (they are the user's
    hand-picked nodes, usually few, and they must stay visible whatever their
    current state). Indices stay the underlying list index so every command
    (connect/delete/pin) keeps working unchanged.
    """
    gold, rest = [], []
    for i, (_ident, r) in enumerate(nodes):
        if not _node_matches(r, flt):
            continue
        (gold if r.get("golden") else rest).append(i)
    out: list[tuple[str | None, int]] = []
    if gold:
        out.append((f"⭐ GOLDEN — pinned by you ({len(gold)})", -1))
        out += [(None, i) for i in gold]
    if rest:
        if gold:
            out.append((f"— {' ' + str(FILTER_LABEL.get(flt) or '')} ({len(rest)})", -1))
        out += [(None, i) for i in rest]
    return out


# ------------------------------------------------------------------ TTY TUI

def _tui(nodes, state, state_path, ping_timeout=3.5, start_filter=None, cfg=None) -> str | None:
    """curses picker. Returns ident to connect, or None if aborted.
    Always saves state and outputs on every change and on Ctrl+C / exit."""
    import curses
    from . import core_store as store

    picked = {"ident": None}
    flt = {"v": start_filter}

    def run(stdscr):
        curses.curs_set(0)
        stdscr.timeout(-1)
        sel = 0
        offset = 0
        status = ""
        try:
            while True:
                view = [i for i, (_ident, r) in enumerate(nodes)
                        if _node_matches(r, flt["v"])]
                rows_view = section_rows(nodes, flt["v"])
                h, w = stdscr.getmaxyx()
                stdscr.erase()
                title = (f" pick - {len(view)}/{len(nodes)} nodes | "
                         f"{FILTER_LABEL[flt['v']]} | Enter=connect g=golden "
                         f"d=del r=ping c=mass-check f=filter q=quit ")
                stdscr.addnstr(0, 0, title.ljust(w), w - 1, curses.A_REVERSE)
                stdscr.addnstr(1, 0, header(w), w - 1, curses.A_BOLD | curses.A_UNDERLINE)
                body_h = h - 4
                if sel >= len(rows_view):
                    sel = max(0, len(rows_view) - 1)
                if sel < offset:
                    offset = sel
                if sel >= offset + body_h:
                    offset = sel - body_h + 1
                for line, (hdr, ni) in enumerate(rows_view[offset:offset + body_h]):
                    if hdr is not None:
                        stdscr.addnstr(2 + line, 0, hdr.ljust(w), w - 1,
                                       curses.A_BOLD | curses.A_UNDERLINE)
                        continue
                    ident, r = nodes[ni]
                    txt = row(ni, ident, r, w)
                    attr = curses.A_REVERSE if (offset + line) == sel else (
                        curses.A_BOLD if r.get("golden") or r.get("tier") == "fast"
                        else curses.A_NORMAL)
                    stdscr.addnstr(2 + line, 0, txt.ljust(w), w - 1, attr)
                if status:
                    stdscr.addnstr(h - 2, 0, status[:w - 1], w - 1, curses.A_BOLD)
                cyclic = f" [{sel + 1}/{len(view)}] " if view else " [empty] "
                stdscr.addnstr(h - 1, max(0, w - len(cyclic)), cyclic, w - 1,
                               curses.A_DIM)
                stdscr.refresh()
                try:
                    ch = stdscr.getch()
                except KeyboardInterrupt:
                    _persist_all(cfg, state, state_path)
                    return
                if ch in (ord("q"), 27, 3):  # q, ESC, or Ctrl+C (ASCII 3)
                    _persist_all(cfg, state, state_path)
                    return
                if ch in (ord("f"),):
                    ci = FILTER_CYCLE.index(flt["v"])
                    flt["v"] = FILTER_CYCLE[(ci + 1) % len(FILTER_CYCLE)]
                    sel = 0
                    offset = 0
                    status = f"filter: {FILTER_LABEL[flt['v']]}"
                    continue
                if ch in (ord("G"),):
                    # jump to the gen pool = alive but target NOT passed
                    flt["v"] = None if flt["v"] == "general" else "general"
                    sel = 0
                    offset = 0
                    status = f"view: {FILTER_LABEL[flt['v']]}"
                    continue
                if ch in (ord("c"),):
                    status = "mass re-check..."
                    stdscr.addnstr(h - 2, 0, status.ljust(w), w - 1, curses.A_BOLD)
                    stdscr.refresh()
                    try:
                        alive, tot = asyncio.run(mass_ping(nodes, timeout=ping_timeout))
                    except KeyboardInterrupt:
                        pass
                    resort(nodes)
                    _persist_all(cfg, state, state_path)
                    sel = 0
                    offset = 0
                    alive = sum(1 for _, r in nodes if r.get("_last_ping") is not None)
                    status = f"mass check saved: {alive}/{len(nodes)} alive - list re-sorted"
                    continue
                if not rows_view:
                    continue
                if ch in (curses.KEY_UP, ord("k")):
                    sel = (sel - 1) % len(rows_view)
                    while rows_view and rows_view[sel][0] is not None:
                        sel = (sel - 1) % len(rows_view)
                elif ch in (curses.KEY_DOWN, ord("j")):
                    sel = (sel + 1) % len(rows_view)
                    while rows_view and rows_view[sel][0] is not None:
                        sel = (sel + 1) % len(rows_view)
                elif ch in (ord("g"),):
                    ni = rows_view[sel][1]
                    ident, r = nodes[ni]
                    store.set_golden(state, ident, not r.get("golden"))
                    _persist_all(cfg, state, state_path)
                    resort(nodes)
                    status = (f"golden PINNED & saved: {r.get('server')}:{r.get('server_port')}"
                              if r.get("golden") else
                              f"unpinned & saved: {r.get('server')}:{r.get('server_port')}")
                elif ch in (ord("d"),):
                    ni = rows_view[sel][1]
                    ident, r = nodes[ni]
                    nodes.pop(ni)
                    state.pop(ident, None)
                    _persist_all(cfg, state, state_path)
                    status = f"deleted & saved: {r.get('server')}:{r.get('server_port')}"
                elif ch in (ord("r"),):
                    ni = rows_view[sel][1]
                    ident, r = nodes[ni]
                    status = "ping..."
                    stdscr.addnstr(h - 2, 0, status.ljust(w), w - 1, curses.A_BOLD)
                    stdscr.refresh()
                    ms = asyncio.run(quick_ping(r, timeout=ping_timeout))
                    r["probe_ms"] = ms
                    _persist_all(cfg, state, state_path)
                    if ms is None:
                        note = ("dead" if r.get("type") not in UDP_PROTOCOLS
                                else "UDP/TCP no reply (may still work via sing-box)")
                    else:
                        note = f"{ms:.0f}ms"
                    status = f"ping {r.get('server')}:{r.get('server_port')} -> {note} (saved)"
                elif ch in (curses.KEY_ENTER, 10, 13):
                    ni = rows_view[sel][1]
                    ident, r = nodes[ni]
                    picked["ident"] = ident
                    _persist_all(cfg, state, state_path)
                    return
        finally:
            _persist_all(cfg, state, state_path)

    import curses as _c
    try:
        _c.wrapper(run)
    except KeyboardInterrupt:
        _persist_all(cfg, state, state_path)
    return picked["ident"]


# --------------------------------------------------------------- stdin menu

def _menu(nodes, state, state_path, ping_timeout=3.5, start_filter=None, cfg=None) -> str | None:
    """Fallback picker for non-TTY: numbered list, command loop on stdin.
    Saves state & outputs after every action and on Ctrl+C / EOF."""
    from . import core_store as store
    w = 100
    flt = {"v": start_filter}

    def show():
        view = [i for i, (_ident, r) in enumerate(nodes)
                if _node_matches(r, flt["v"])]
        print(header(w))
        for hdr, i in section_rows(nodes, flt["v"]):
            if hdr is not None:
                print(hdr)
                continue
            print(row(i, nodes[i][0], nodes[i][1], w))
        print(f"--- {len(view)}/{len(nodes)} nodes | filter: {FILTER_LABEL[flt['v']]}")
        return view

    view = show()
    if not nodes:
        print("(no nodes)")
        return None
    try:
        from . import display as D
        def K(key, desc):
            return f"{D.c(D.CYN, key):} {desc}"
        print("\n" + "  |  ".join([
            K("N", "connect"), K("g N", "⭐ pin"),
            K("d N", "delete"), K("r N", "re-ping"),
            K("c", "rescan"), K("f", "filter"), K("gen", "show gen pool"),
            K("q", "quit"),
        ]))
    except Exception:  # noqa: BLE001
        print("\nN=connect | g N=toggle golden | d N=delete | r N=ping | "
              "c=mass-check | f=filter | q=quit")
    try:
        while True:
            try:
                line = input("pick> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nSaving all servers and closing...")
                _persist_all(cfg, state, state_path)
                return None
            if not line or line == "q":
                _persist_all(cfg, state, state_path)
                return None
            parts = line.split()
            try:
                if parts[0] == "c":
                    print("mass re-check (parallel ping)...", flush=True)
                    try:
                        alive, tot = asyncio.run(mass_ping(nodes, timeout=ping_timeout))
                    except KeyboardInterrupt:
                        alive = sum(1 for _, r in nodes if r.get("_last_ping") is not None)
                        tot = len(nodes)
                    resort(nodes)
                    _persist_all(cfg, state, state_path)
                    print(f"result: {alive}/{tot} alive - list re-sorted & saved")
                    view = show()
                elif parts[0] == "f":
                    ci = FILTER_CYCLE.index(flt["v"])
                    flt["v"] = FILTER_CYCLE[(ci + 1) % len(FILTER_CYCLE)]
                    view = show()
                elif parts[0].lower() in ("gen", "g0"):
                    # show the gen pool: alive nodes whose LAST target check failed
                    flt["v"] = None if flt["v"] == "general" else "general"
                    view = show()
                elif parts[0] == "g" and len(parts) == 2:
                    ni = view[int(parts[1])]
                    ident, r = nodes[ni]
                    store.set_golden(state, ident, not r.get("golden"))
                    _persist_all(cfg, state, state_path)
                    resort(nodes)
                    print(("golden PINNED & saved" if r.get("golden") else "unpinned & saved")
                          + f": {r.get('server')}:{r.get('server_port')}")
                    view = show()
                elif parts[0] == "d" and len(parts) == 2:
                    ni = view[int(parts[1])]
                    ident, r = nodes[ni]
                    nodes.pop(ni)
                    state.pop(ident, None)
                    _persist_all(cfg, state, state_path)
                    print(f"deleted & saved: {r.get('server')}:{r.get('server_port')}")
                    view = show()
                elif parts[0] == "r" and len(parts) == 2:
                    ni = view[int(parts[1])]
                    _, r = nodes[ni]
                    ms = asyncio.run(quick_ping(r, timeout=ping_timeout))
                    r["probe_ms"] = ms
                    _persist_all(cfg, state, state_path)
                    if ms is None:
                        print("ping: dead (or UDP-only node with no reply - saved)")
                    else:
                        print(f"ping: {ms:.0f}ms (saved)")
                else:
                    ni = view[int(parts[0])]
                    _persist_all(cfg, state, state_path)
                    return nodes[ni][0]
            except (ValueError, IndexError):
                print("invalid - use: N, or: g N / d N / r N / c / f / q")
    finally:
        _persist_all(cfg, state, state_path)


# ------------------------------------------------------------------ command

async def _own_ip_for_verify(cfg: dict) -> tuple[str | None, str | None]:
    """This machine's own public IP — the leak baseline for the live test."""
    if "_own_ip_cached" in cfg:
        return cfg["_own_ip_cached"], cfg.get("_own_loc_cached")
    try:
        from .checker import measure_own_ip
        ip, loc = await measure_own_ip(list(cfg.get("exit_probe_urls") or []), timeout=6.0)
    except Exception:                                       # noqa: BLE001
        ip, loc = None, None
    cfg["_own_ip_cached"] = ip
    cfg["_own_loc_cached"] = loc
    return ip, loc


def cmd_pick(cfg, port: int | None = None, mode: str | None = None,
             start_from: str = "all") -> int:
    from . import core_connect, core_store as store
    data = Path(cfg.get("data_dir", "data"))
    sp = data / "state.json"
    state = store.load(sp)
    # Load every non-dead node (golden/ fast/ backup/ gen) — the VIEW decides
    # what is on screen: by default only the target-ok pool, 'gen' key shows the
    # alive-but-no-target pool, so nothing is hidden from the user.
    nodes = load_nodes(state, require_target=False)
    if not nodes:
        log.error("No nodes in state. Run discover first.")
        return 2

    # starting filter: default = target-ok pool (None); --from gen opens the
    # gen pool; --from best/bak narrow to that tier; --from all shows everything
    start_filter = {"gen": "general", "all": "all"}.get(start_from)

    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            ident = _tui(nodes, state, sp, start_filter=start_filter, cfg=cfg)
        except Exception as e:  # noqa: BLE001
            log.warning("TUI failed (%s), falling back to text menu", e)
            ident = _menu(nodes, state, sp, start_filter=start_filter, cfg=cfg)
    else:
        ident = _menu(nodes, state, sp, start_filter=start_filter, cfg=cfg)

    _persist_all(cfg, state, sp)
    if ident is None:
        log.info("Saved state and output files. Nothing selected to connect.")
        return 0
    rec = state.get(ident)
    if rec is None:
        log.error("Selected node vanished from state.")
        return 2
    port = port or cfg.get("connect", {}).get("port", 2080)
    mode = mode or cfg.get("connect", {}).get("mode", "proxy")

    # ── live confirmation before connecting ────────────────────────────────
    # The whole point of pick is "connect to something that works". A stored
    # record can be minutes/hours old, so the chosen node is tested once more
    # (echo + page proof + exit proof). Dead → refuse, and say why.
    if cfg.get("verify_before_connect", True):
        from . import core_test as ct
        from . import core_runner as runner
        verify_cfg = ct.cfg_for_test_lite(cfg) if hasattr(ct, "cfg_for_test_lite") else dict(cfg)
        verify_cfg["_page_urls"] = [u for u in (cfg.get("page_probe_urls") or []) if u]
        try:
            own_ip, own_loc = asyncio.run(_own_ip_for_verify(cfg))
            verify_cfg["_own_ip"] = own_ip
            verify_cfg["_exit_urls"] = list(cfg.get("exit_probe_urls") or [])
            log.info("Verifying %s:%s before connecting (echo + page + exit proof)...",
                     rec.get("server"), rec.get("server_port"))
            res = asyncio.run(runner.test_config(
                __import__("gozar.core_parser", fromlist=["parse"]).parse(rec.get("raw", "")),
                echo_url=verify_cfg.get("echo_url"),
                target_url=verify_cfg.get("targets") or [],
                timeout=verify_cfg.get("timeout", 8),
                target_timeout=verify_cfg.get("target_timeout", 12),
                startup=verify_cfg.get("startup_delay", 0.8),
                verify_ssl=verify_cfg.get("verify_ssl", False),
                exit_urls=verify_cfg.get("_exit_urls"),
                own_ip=own_ip,
                verify_exit=verify_cfg.get("verify_exit_ip", True),
                page_urls=verify_cfg["_page_urls"],
            ))
        except Exception as e:                                  # noqa: BLE001
            log.warning("pre-connect verification could not run (%s) — connecting anyway", e)
            res = None
        if res is not None and not res.get("alive"):
            log.error("REFUSED: %s:%s did not pass the live test (%s) — it will not "
                      "carry your traffic. Nothing was connected.",
                      rec.get("server"), rec.get("server_port"),
                      res.get("error") or res.get("security") or "no proof")
            return 3
        if res is not None:
            log.info("live test OK: latency=%sms target=%s exit=%s%s",
                     res.get("latency"),
                     "ok" if res.get("target_ok") else "not-passed",
                     res.get("exit_ip") or "unverified",
                     f" ({res.get('exit_loc')})" if res.get("exit_loc") else "")

    log.info("Connecting to %s:%s (%s, %s)...", rec.get("server"),
             rec.get("server_port"), rec.get("type"), _lat(rec))
    return asyncio.run(core_connect.run_connect(
        data, mode=mode, port=port, pin_index=0, source="best", recs=[rec]))


def cmd_drop(cfg, short_id: str) -> int:
    """Delete a node by its short id (first chars of ident) or by list index."""
    from . import core_store as store
    data = Path(cfg.get("data_dir", "data"))
    sp = data / "state.json"
    state = store.load(sp)
    if not state:
        log.error("state is empty")
        return 2
    hits = [k for k in state if k.startswith(short_id)]
    if not hits:
        # maybe it was an index into the pick order
        nodes = load_nodes(state, require_target=False)
        try:
            ident = nodes[int(short_id)][0]
            hits = [ident]
        except (ValueError, IndexError):
            log.error("No node matches '%s'", short_id)
            return 2
    for k in hits:
        r = state.pop(k)
        log.info("deleted: %s %s:%s", r.get("type"), r.get("server"),
                 r.get("server_port"))
    store.save(sp, state)
    return 0
