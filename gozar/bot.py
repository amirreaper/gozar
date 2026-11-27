"""gozar CLI — find, test and connect through public proxy nodes."""
from __future__ import annotations
import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

from . import core_connect, core_output, core_store as store
from . import core_test as ct
from . import doctor
from .config import load_config, apply_preset, HARD_MODE

log = logging.getLogger("bot")

# ─────────────────────────── config loading ───────────────────────────

DEFAULT_CONFIG = "config.json"


PROTO_ALIASES = {"ss": "shadowsocks", "hy2": "hysteria2"}


def load_bot_config(path: str, preset: str | None = None) -> dict:
    cfg = load_config(path, preset=preset)
    # Normalize protocol aliases so filtering matches parser type names
    cfg["protocols"] = [PROTO_ALIASES.get(p, p) for p in
                        (cfg.get("protocols") or [])]
    # Normalize target_url / targets into a list
    targets = cfg.get("targets") or []
    if isinstance(targets, str):
        targets = [targets]
    if cfg.get("target_url") and cfg["target_url"] not in targets:
        targets.insert(0, cfg["target_url"])
    cfg["targets"] = [t for t in targets if t and str(t).strip()]
    # mode is explicit so every command can print it: target vs liveness-only
    cfg.setdefault("target_mode", "target" if cfg["targets"] else "liveness")
    return cfg


def apply_overrides(cfg: dict, args) -> dict:
    """Apply command-line options on top of config file values.

    Order: defaults -> config.json -> preset (--hard) -> explicit flags.
    A preset is a bundle, so it must beat config.json (which is often a
    `calibrate --write` dump); an explicit flag must beat the bundle.
    """
    def g(name, default=None):
        return getattr(args, name, default)

    if g("hard", False):
        _replaced = {k: (cfg.get(k), v) for k, v in HARD_MODE.items()
                     if k != "profiles" and cfg.get(k) != v}
        cfg = dict(cfg)
        cfg.update({k: v for k, v in HARD_MODE.items() if k != "profiles"})
        cfg["preset"] = "hard"
        log.warning("HARD MODE — filtered/throttled line preset applied "
                    "(concurrency=%s, batch=%s, probe=%s, timeouts=%s/%ss)",
                    cfg["test_concurrency"], cfg["batch_size"],
                    cfg["probe_mode"], cfg["timeout"], cfg["target_timeout"])
        for k, (was, now) in _replaced.items():
            log.warning("  %s: %s -> %s (was in config.json)", k, was, now)
    if getattr(args, "no_target", False):
        # explicit liveness-only mode: ignore the config's targets entirely
        cfg["targets"] = []
        cfg["target_mode"] = "liveness"
    elif g("targets"):
        # -t is repeatable AND accepts comma-separated lists; no artificial cap
        flat: list[str] = []
        for item in g("targets"):
            for part in str(item).replace(",", " ").split():
                part = part.strip()
                if part:
                    flat.append(part)
        if flat:
            cfg["targets"] = flat
            cfg["target_mode"] = "target"
        else:
            # `-t ''` -> liveness-only, same as --no-target
            cfg["targets"] = []
            cfg["target_mode"] = "liveness"
    if g("best_n") is not None:
        cfg["best_n"] = g("best_n")
    if g("bak_n") is not None:
        cfg["bak_n"] = g("bak_n")
    if g("protocols"):
        cfg["protocols"] = [PROTO_ALIASES.get(p.strip(), p.strip()) for p in
                            g("protocols").split(",") if p.strip()]
    if g("baseline_ms") is not None:
        cfg["baseline_ms_override"] = g("baseline_ms")
    if g("fast_max_ms") is not None:
        cfg["fast_max_ms"] = g("fast_max_ms")
    if g("fast_factor") is not None:
        cfg["fast_factor"] = g("fast_factor")
    if g("min_speed_ms") is not None:
        # --min-speed is a REAL throughput floor in KB/s (measured on the proof
        # page). It used to write a latency ceiling here, which is a different
        # thing: latency has its own flags (--fast-max / --bak-max).
        cfg["min_kbps"] = g("min_speed_ms")
    if g("backup_max_ms") is not None:
        cfg["backup_max_ms"] = g("backup_max_ms")
    if g("test_concurrency") is not None:
        cfg["test_concurrency"] = g("test_concurrency")
    if g("probe_concurrency") is not None:
        cfg["probe_concurrency"] = g("probe_concurrency")
    if g("max_per_proto") is not None:
        cfg["max_per_proto"] = g("max_per_proto")
    if g("max_per_subnet") is not None:
        cfg["max_per_subnet"] = g("max_per_subnet")
    if g("require_target"):
        cfg["require_target"] = True
    if g("list_mode"):
        cfg["list_mode"] = g("list_mode")
    if g("reset"):
        cfg["_reset_requested"] = True
    if g("timeout") is not None:
        cfg["timeout"] = g("timeout")
    if g("target_timeout") is not None:
        cfg["target_timeout"] = g("target_timeout")
    if g("startup_delay") is not None:
        cfg["startup_delay"] = g("startup_delay")
    if g("verify_ssl"):
        cfg["verify_ssl"] = True
    if g("no_verify_ssl"):
        cfg["verify_ssl"] = False
    if g("no_exit_proof"):
        cfg["verify_exit_ip"] = False
    if g("strict_exit"):
        cfg["verify_exit_ip"] = True
        cfg["strict_exit_proof"] = True
    if g("data_dir"):
        cfg["data_dir"] = g("data_dir")
    # anti rate-limit:
    if g("pace_ms") is not None:
        cfg["test_pace_ms"] = g("pace_ms")
        cfg["probe_pace_ms"] = g("pace_ms")
    if getattr(args, "no_probe", False):
        cfg["probe_mode"] = "off"
    if g("probe_mode"):
        cfg["probe_mode"] = g("probe_mode")
    if g("breaker_on"):
        # The breaker is ON by default (test_breaker_streak / probe_breaker_window
        # in config.py). The flag is kept so old scripts do not break, but it no
        # longer forces a different, undocumented threshold.
        cfg["breaker_ack"] = True
    if g("cdn_only"):
        cfg["cdn_only"] = True
    if g("open_sni"):
        cfg["open_sni"] = True
    if g("safe_ports"):
        cfg["safe_ports"] = True
    if g("import_files"):
        cfg["import_files"] = list(g("import_files"))
    if g("domestic_only"):
        cfg["domestic_only"] = True
    if g("latency_basis"):
        cfg["latency_basis"] = g("latency_basis")
    if g("prune_failures") is not None:
        cfg["prune_failures"] = g("prune_failures")
    if g("check_interval") is not None:
        cfg["check_interval"] = g("check_interval")
    if g("discover_interval") is not None:
        cfg["discover_interval"] = g("discover_interval")
    return cfg


def cfg_for_test(cfg: dict) -> dict:
    """Convert the CLI config into the format core_test expects."""
    from . import core_test as _ct
    _ct.PROBE_MODE[0] = cfg.get("probe_mode", "auto")
    c = dict(cfg)
    targets = c.get("targets", []) or []
    c["target_url"] = list(targets)
    return c


# ─────────────────────────── paths & output ───────────────────────────

def _paths(cfg):
    data = Path(cfg.get("data_dir", "data"))
    data.mkdir(parents=True, exist_ok=True)
    return data, data / "state.json"


def _speed_filtered(recs, min_kbps):
    """Rank by real throughput, then drop what cannot carry min_kbps.

    Nodes are ordered by measured page throughput (KB/s) first, so a
    56 KB/s node never sits above an 850 KB/s one just because its latency
    was smaller. A node WITHOUT a measurement keeps the latency-based order
    and is never dropped: unmeasured is not slow, and dropping it would empty
    the pool whenever the proof page failed for an unrelated reason.
    """
    recs = list(recs)
    if not min_kbps:
        return recs
    measured = [r for r in recs if r.get("page_kbps") is not None]
    unmeasured = [r for r in recs if r.get("page_kbps") is None]
    measured.sort(key=lambda r: float(r["page_kbps"]), reverse=True)
    kept = [r for r in measured if float(r["page_kbps"]) >= float(min_kbps)]
    return kept + unmeasured


def _write_outputs(cfg, state, meta):
    """Select and write best/bak/gen under the DEFAULT rule: alive and usable.

    Order of authority:
      1. the measurement (alive_now, page_ok, exit proof) — never negotiable
      2. the targets — target-OK nodes rank first and `.ok.txt` holds only them
      3. speed — orders two nodes that both earned their place, decides nothing

    The old code called `write_files(require_target=bool(cfg["targets"]))`, so a
    line where the target was blocked produced EMPTY best/bak while 8 nodes were
    demonstrably alive (the 2026-11-15 report). Now a node that carries traffic
    is never thrown away for missing one URL; it is simply ranked lower, and the
    strict list is one flag away (`require_target=True` / `--strict-target`).
    """
    from . import core_live
    data, _ = _paths(cfg)
    max_acc = cfg.get("max_acceptable_ms")
    min_kbps = cfg.get("min_kbps")
    best_n = cfg["best_n"]
    bak_n = cfg["bak_n"]
    gen_n = cfg.get("gen_n", 100)
    strict = bool(cfg.get("require_target"))      # opt-in, never implicit

    if cfg.get("list_mode", "target") == "live":
        best_recs, bak_recs = core_live.mix(state, max(best_n, bak_n))
        live_only = []
        degraded = False
    else:
        # default: the list is target-OK only; everything else alive stays in
        # the live pool instead of dying (user's rule, 2026-11-15)
        best_recs, bak_recs, live_only, degraded = core_live.split_lists(
            state, best_n, bak_n,
            live_fallback=bool(cfg.get("list_fallback")))
    # The live pool is computed HERE, before anything is asked about it.
    # It used to be computed at the bottom, while the "0 of N passed the
    # targets" warning near the top already dereferenced it: every run whose
    # best/bak came out empty died with
    #     UnboundLocalError: cannot access local variable 'gen_recs'
    # inside the very warning written to explain the empty list. That crash
    # masked the real event (no target-OK node) behind a traceback, and it is
    # what "exit does not happen / crash" looked like from outside.
    used0 = {store.ident(r) for r in best_recs} | {store.ident(r) for r in bak_recs}
    gen_recs = (live_only or core_live.live_recs(state, gen_n, exclude=used0))[:gen_n]

    if degraded:
        log.warning("No node passed every target — best/bak were filled from the "
                    "live pool because list_fallback is on. Treat them as "
                    "unproven.")
    elif not best_recs and not bak_recs and gen_recs:
        log.warning("0 of %d alive nodes passed the targets, so best/bak are "
                    "EMPTY by design: the alive pool is in %s/gen.txt "
                    "(connect with `--from gen`). Check whether the target is "
                    "blocked on your line: `gozar doctor`, or `gozar config --doctor`.",
                    len(gen_recs), data)
    elif not best_recs and not bak_recs:
        log.warning("No node survived this run: 0 passed a target and 0 are "
                    "usable alive nodes. Nothing was written over your previous "
                    "list unless the run says so. Try `gozar doctor` or "
                    "`gozar calibrate`.")
    if strict:
        best_recs = [r for r in best_recs if store.target_now(r)][:best_n]
        bak_recs = [r for r in bak_recs if store.target_now(r)][:bak_n]
    if max_acc or min_kbps:
        # one ordered pool -> a node rejected for speed must NOT reappear in bak
        pool = best_recs + bak_recs
        pool = [r for r in pool if not max_acc or (r.get("latency") or 99999) <= max_acc]
        pool = _speed_filtered(pool, min_kbps)
        best_recs = pool[:best_n]
        bak_recs = pool[best_n:best_n + bak_n]
    else:
        best_recs = best_recs[:best_n]
        bak_recs = bak_recs[:bak_n]

    used = {store.ident(r) for r in best_recs} | {store.ident(r) for r in bak_recs}
    # gen = alive and usable but not in the list: the "still alive" pool.
    # Recomputed after strict/speed filtering so a node dropped by a filter
    # lands in gen instead of vanishing from every file.
    if used != used0:
        gen_recs = (live_only or core_live.live_recs(state, gen_n, exclude=used))[:gen_n]
    meta = dict(meta or {})
    if degraded:
        meta["best_degraded"] = True
    core_output.write_records(data, best_recs, bak_recs, state, meta, gen_recs=gen_recs)
    core_output.write_target_list(data, [r for r in (best_recs + bak_recs)
                                         if store.target_now(r)])
    return best_recs, bak_recs


# ─────────────────────────── commands ───────────────────────────

def _print_run_table(summary):
    # full table of THIS run — one row per alive node, not just the fast counter
    rows = (summary or {}).get("run_nodes") or []
    if not rows:
        return
    from . import display as D
    print(f"\n-- alive nodes of this run: {len(rows)} --")
    for i, r in enumerate(rows, 1):
        lat = r.get("latency")
        lat_s = f"{lat:.0f}ms" if lat else "—"
        pr_s = f"{r['probe_ms']:.0f}" if r.get("probe_ms") is not None else "—"
        tgt = ("ok" if r.get("target_ok")
               else ("live" if r.get("target_ok") is None else "FAIL"))
        srv = f"{str(r['server'])}:{r['server_port']}"
        # show the glyph the node actually deserves: in liveness-only mode a
        # healthy node is ★/●, not the "no-target" diamond.
        row_view = {**r, "target_ok_now": (None if r.get("target_ok") is None
                                           else bool(r.get("target_ok")))}
        print(f"  {D.node_mark(row_view)} {D.c(D.BLU, str(r['type']).ljust(9))}"
              f" {srv:<28} {D.bar_ms(lat)} {lat_s:>7}  probe:{pr_s:>4}"
              f"  tgt:{tgt}")
    print("  marks: ★=fast ●=backup ◆=alive-but-no-target ☓=dead"
          "   | tgt:ok=passed  FAIL=did not pass  live=no target configured")


def load_or_reset_state(cfg, state_path):
    """Load the pool, or start a fresh one when the user asked for that.

    `discover` on an existing pool is a REFRESH (the old behaviour), but once a
    pool has accumulated dead ghosts it is useful to start over without deleting
    files by hand: `--reset` ARCHIVES the old state instead of destroying it,
    because golden pins and the run history live in it.
    """
    if cfg.get("_reset_requested"):
        old = store.load(state_path)
        if old:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            arch = state_path.with_name(f"state-archived-{stamp}.json")
            try:
                state_path.replace(arch)
                log.warning("--reset: moved %d stored node(s) to %s",
                            len(old), arch.name)
            except Exception as e:  # noqa: BLE001
                log.warning("--reset: could not archive state (%s)", e)
        return {}
    return store.load(state_path)


def _require_engine():
    """Fail before a run starts, not after 1,400 nodes were probed.

    Without this, a machine with no sing-box spent minutes fetching and probing
    candidates and then reported "0 nodes alive" — the tool blaming the pool for
    a missing dependency. Exit code 2 = "cannot run", distinct from 3 = "ran,
    nothing passed" and 0 = "good".
    """
    from . import engines as E
    found = E.find_binary("sing-box")
    if found is not None:
        return found
    log.error("the testing engine (sing-box) is not installed — nothing can be tested")
    print("\n" + E.INSTALL_HINTS + "\n", file=sys.stderr)
    raise SystemExit(2)


def cmd_discover(cfg):
    _require_engine()
    data, sp = _paths(cfg)
    ct.data_dir_hint[0] = data            # breakers + source stats live here
    state = load_or_reset_state(cfg, sp)
    try:
        summary = asyncio.run(ct.discover(cfg_for_test(cfg), state, sp))
    except KeyboardInterrupt:
        # Same contract as `check`: Ctrl+C is a normal way to stop a long run,
        # and whatever was found must survive it. The old code let the
        # KeyboardInterrupt escape as a traceback and wrote nothing.
        store.save(sp, state)
        log.warning("Interrupted. Partial state saved to %s — writing the lists "
                    "from what was found so far.", sp.name)
        summary = {"interrupted": True}
    state = store.prune(state, cfg.get("prune_failures", 6))
    store.save(sp, state)
    best, bak = _write_outputs(cfg, state, {"ts": int(time.time()),
                                            "mode": "discover", **summary})
    used = {store.ident(r) for r in best} | {store.ident(r) for r in bak}
    gen = store.general(state, cfg.get("gen_n", 100), exclude=used)
    n_ok = sum(1 for r in best + bak if store.target_now(r))
    log.info("Done: best=%d  bak=%d  live=%d  target-OK=%d  (dir: %s)",
             len(best), len(bak), len(gen), n_ok, data)
    if n_ok and n_ok < len(best) + len(bak):
        log.info("%d of %d listed nodes passed every target; the rest are alive and "
                 "carry traffic but missed one -- best/bak rank target-OK first and "
                 "data/ok.txt holds only the strict ones.",
                 n_ok, len(best) + len(bak))
    if not best and not bak:
        if gen:
            log.warning("Nothing survived the gates; %d node(s) are only in the live "
                        "pool (%s/gen.txt).", len(gen), data)
        else:
            log.warning("No suitable nodes found. Try relaxing target/speed thresholds.")
    _print_run_table(summary)
    return best, bak



def cmd_check(cfg, drop_dead=False):
    _require_engine()
    data, sp = _paths(cfg)
    ct.data_dir_hint[0] = data            # check-phase breakers are journaled too
    state = store.load(sp)
    if not state:
        log.error("No stored nodes. Run discover first.")
        return [], []
    tc = cfg_for_test(cfg)
    if drop_dead:
        tc["drop_dead_now"] = True   # failing this round deletes immediately (user request)
    try:
        summary = asyncio.run(ct.check(tc, state, sp))
    except KeyboardInterrupt:
        store.save(sp, state)
        log.warning("Interrupted. Partial state saved.")
        summary = {"interrupted": True}
    state = store.prune(state, cfg.get("prune_failures", 6))
    store.save(sp, state)
    best, bak = _write_outputs(cfg, state, {"ts": int(time.time()),
                                            "mode": "check", **summary})
    used = {store.ident(r) for r in best} | {store.ident(r) for r in bak}
    gen = store.general(state, cfg.get("gen_n", 100), exclude=used)
    log.info("Check done: best=%d  bak=%d  gen=%d  removed=%d",
             len(best), len(bak), len(gen), summary.get("removed", 0))
    counts = store.tier_counts(state)
    ndead = counts.get("dead", 0)
    log.info("Written to %s: best.txt=%d  bak.txt=%d  gen.txt=%d",
             data, len(best), len(bak), len(gen))
    if ndead:
        log.info("%d node(s) failed this check and left the pool — they are kept "
                 "in state.json as tier=dead (visible with `gozar pick` → f → dead, "
                 "deletable with d).", ndead)
    log.info("To prove a node really tunnels (not just answers), run: "
             "gozar verify -n 10 --from all")
    return best, bak


def cmd_calibrate(cfg, write=False, config_path="config.json", profile=None):
    """Measure this line and propose fast/keep thresholds + counts.

    Numbers that fit YOUR line instead of a hard-coded guess: the "fast" ceiling
    is the 75th percentile of the latencies that actually work here, the "keep"
    ceiling the 90th percentile (outliers only). `--write` saves them.
    """
    from . import thresholds as th
    from . import core_store as store
    data, sp = _paths(cfg)
    state = store.load(sp)
    rec = asyncio.run(th.calibrate(state, cfg))
    if profile and profile != "standard":
        rec = dict(rec)
        rec["recommended"] = th.apply_profile(rec["recommended"], profile)
        print(f"\n  profile: {profile} (measured numbers scaled, not invented)")
    print(th.render(rec, cfg))
    if write:
        p = Path(config_path)
        try:
            user = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        except Exception:                                     # noqa: BLE001
            user = {}
        user.update(rec["recommended"])
        p.write_text(json.dumps(user, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\n  [ok] written to {p} — picked up automatically from now on.")
    return 0


def cmd_loop(cfg):
    """Continuous loop: initial discover then periodic check."""
    data, sp = _paths(cfg)
    require_target = bool(cfg.get("targets"))

    async def arun():
        state = store.load(sp)
        last_disc = 0
        while True:
            now = time.time()
            current_best = store.best(state, cfg["best_n"], require_target=require_target)
            if (now - last_disc > cfg.get("discover_interval", 21600)
                    or len(current_best) < max(5, cfg["best_n"] // 3)):
                summary = await ct.discover(cfg_for_test(cfg), state, sp)
                last_disc = time.time()
            else:
                summary = await ct.check(cfg_for_test(cfg), state, sp)
            state = store.prune(state, cfg.get("prune_failures", 6))
            store.save(sp, state)
            best, bak = _write_outputs(
                cfg, state, {"ts": int(time.time()), "mode": "loop", **summary})
            log.info("Loop: best=%d bak=%d | sleeping %ds",
                     len(best), len(bak), cfg["check_interval"])
            await asyncio.sleep(cfg["check_interval"])
    asyncio.run(arun())


def cmd_run(cfg, n, mode, port, force):
    """Find at least N good nodes, verify them, then connect."""
    _require_engine()
    data, sp = _paths(cfg)
    state = store.load(sp)
    require_target = bool(cfg.get("targets"))
    best = store.best(state, n, require_target=require_target)

    if force or len(best) < n:
        log.info("Need %d good nodes, have %d. Running discover...", n, len(best))
        run_cfg = dict(cfg)
        run_cfg["best_n"] = max(n, cfg.get("best_n", 50))
        state = store.load(sp)
        summary = asyncio.run(ct.discover(cfg_for_test(run_cfg), state, sp))
        state = store.prune(state, cfg.get("prune_failures", 6))
        store.save(sp, state)
        best = store.best(state, n, require_target=require_target)
        _write_outputs(cfg, state, {"ts": int(time.time()), "mode": "run", **summary})

    if not best:
        log.error("No working nodes found. Adjust targets or min-speed.")
        return 2

    best = best[:n]
    log.info("%d good nodes ready. Running verification against targets...", len(best))

    test_cfg = cfg_for_test(cfg)
    test_cfg["timeout"] = max(cfg.get("timeout", 8), 10)
    test_cfg["target_timeout"] = max(cfg.get("target_timeout", 12), 15)

    async def verify():
        from . import core_parser as parser
        from .core_runner import test_config
        # Parallel verification with a small cap: each test spawns a sing-box
        # process (~1s startup), so serial checks waste 20-40s of real time.
        # Cap of 5 keeps CPU/RAM and the uplink sane on weak links (D4).
        sem = asyncio.Semaphore(min(5, cfg.get("test_concurrency", 14)))
        max_acc = cfg.get("max_acceptable_ms")
        min_kbps = cfg.get("min_kbps")

        async def one(rec):
            async with sem:
                c = parser.parse(rec.get("raw", ""))
                if not c:
                    return None
                r = await test_config(
                    c,
                    echo_url=cfg["echo_url"],
                    target_url=cfg.get("targets", []),
                    timeout=test_cfg["timeout"],
                    target_timeout=test_cfg["target_timeout"],
                    startup=cfg.get("startup_delay", 1.0),
                    verify_ssl=cfg.get("verify_ssl", False))
                ok = r.get("alive") and (not require_target or r.get("target_ok"))
                if ok and max_acc and (r.get("latency") or 99999) > max_acc:
                    ok = False
                # real throughput floor, measured on the proof page: a node that
                # answers everything but trickles is not usable for a browser
                if ok and min_kbps and r.get("page_kbps") is not None \
                        and float(r["page_kbps"]) < float(min_kbps):
                    ok = False
                mark = "OK" if ok else "FAIL"
                log.info("  [%s] %-11s %6sms  %s", mark, rec["type"],
                         r.get("latency", "-"), rec["server"])
                if ok:
                    rec["_verified_latency"] = r.get("latency")
                    return rec
                return None

        results = await asyncio.gather(*(one(rec) for rec in best))
        return [r for r in results if r is not None]

    verified = asyncio.run(verify())
    if not verified:
        log.error("None of the nodes passed verification. Use --force or re-run discover.")
        return 3
    log.info("%d/%d nodes verified.", len(verified), len(best))

    # Interactive chooser on a terminal — pick one node by number, Enter for
    # the auto urltest group, or 'q' to abort. Over pipes/scripts it skips.
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            print("\n 0) auto group (urltest) - best nodes together [default]")
            for i, rec in enumerate(verified, 1):
                lat = rec.get("_verified_latency")
                print(f" {i}) {rec.get('type','?'):<12} {lat if lat is not None else '-':>6}ms"
                      f"  {rec.get('server')}:{rec.get('server_port')}  "
                      f"{(rec.get('tag') or '')[:30]}")
            sel = input(" which? (Enter=group, number=single node, q=abort) -> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        if sel == "q":
            log.info("Aborted.")
            return 1
        if sel.isdigit():
            i = int(sel)
            if 1 <= i <= len(verified):
                chosen = verified[i - 1]
                log.info("single node selected: %s:%s (%s)",
                         chosen["server"], chosen["server_port"], chosen["type"])
                verified = [chosen]
            else:
                log.error("invalid number - continuing with the auto group.")
    log.info("Connecting...")

    conn_dir = data
    core_output.write_files(conn_dir, {}, 0, 0,
                            require_target=require_target,
                            meta={"ts": int(time.time()), "mode": "run"})
    core_output.write_records(conn_dir, verified, [], {},
                              {"ts": int(time.time()), "mode": "run"})
    return asyncio.run(core_connect.run_connect(
        conn_dir, mode=mode, port=port, pin_index=None, source="best", recs=verified))


def cmd_connect(cfg, mode, port, pin, source, pretest=True,
                allow_no_target=False):
    _require_engine()
    # short fuse: if the node list is untested in this session, run a quick
    # probe against the candidates so a dead node never reaches urltest
    if pretest:
        data, sp = _paths(cfg)
        state = store.load(sp)
        st = store.all_alive(state, require_target=False, allow_recent_fails=0)
        if not st:
            log.warning("no node survived the pre-test (0 consecutive fails) "
                        "— run `gozar discover` or `gozar check` first")
            return None
        best_recs, bak_recs = _write_outputs(cfg, state,
                                             {"ts": int(time.time()),
                                              "mode": "connect-pretest"})
        used = {store.ident(r) for r in best_recs} | {store.ident(r) for r in bak_recs}
        gen_recs = store.general(state, cfg.get("gen_n", 100), exclude=used)
        log.info("pre-test: %d usable node(s) (%d best, %d bak, %d gen) — connecting",
                 len(best_recs) + len(bak_recs) + len(gen_recs),
                 len(best_recs), len(bak_recs), len(gen_recs))
    data, _ = _paths(cfg)
    return asyncio.run(core_connect.run_connect(
        data, mode=mode, port=port, pin_index=pin, source=source,
        allow_no_target=allow_no_target))


def cmd_list(cfg, pin=(), drop=(), recheck=False):
    data, sp = _paths(cfg)
    best = json.loads((data / "best.json").read_text("utf-8")) if (data / "best.json").exists() else []
    bak = json.loads((data / "bak.json").read_text("utf-8")) if (data / "bak.json").exists() else []
    gen = json.loads((data / "gen.json").read_text("utf-8")) if (data / "gen.json").exists() else []

    def _sid(r):
        """Short stable id (same as `pick`/`drop`) from the raw config."""
        try:
            from . import core_parser as _p
            c = _p.parse(r.get("raw", ""))
            return store.ident(c)[:8] if c else "?"
        except Exception:  # noqa: BLE001
            return "?"

    from . import display as D
    print(f"\n{D.c(D.BOLD, 'BEST (Fast + Target OK)')} ({len(best)}):" + "  " + "-" * 38)
    fast_thr = cfg.get("fast_threshold_ms") or 1200
    for i, r in enumerate(best[:25], 0):
        print(D.list_row(i, _sid(r), r, fast_ms=fast_thr))
    if len(best) > 25:
        print(f"    ... and {len(best) - 25} more")
    print(f"\n{D.c(D.BOLD, 'BAK (Connected + Target OK, Slower)')} ({len(bak)}):" + "  " + "-" * 26)
    offset1 = len(best[:25])
    for i, r in enumerate(bak[:12], offset1):
        print(D.list_row(i, _sid(r), r, fast_ms=fast_thr))
    if len(bak) > 12:
        print(f"    ... and {len(bak) - 12} more")
    print(f"\n{D.c(D.BOLD, 'GEN (Connected, Target Not Reached)')} ({len(gen)}):" + "  " + "-" * 24)
    offset2 = offset1 + len(bak[:12])
    for i, r in enumerate(gen[:12], offset2):
        print(D.list_row(i, _sid(r), r, fast_ms=fast_thr))
    if len(gen) > 12:
        print(f"    ... and {len(gen) - 12} more")
    print("  marks: ★=fast ●=backup ◆=general(no-target) ☓=dead  ⭐/F/B/G=tier  stab=stability")
    try:
        _st = store.load(sp)
        _cnt = store.tier_counts(_st)
        if _cnt.get("dead"):
            _lc = max((r.get("last_check") or 0) for r in _st.values())
            _nd = _cnt["dead"]
            _ago = D.age_str(_lc) if _lc else "—"
            print("  " + D.c(D.GRY,
                  f"note: {_nd} node(s) failed their last check ({_ago} ago) and are "
                  f"hidden here —\n        see them with `gozar pick` then f → dead, "
                  f"or re-test with `gozar check`."))
    except Exception:  # noqa: BLE001
        pass

    # ── actions: --pin / --drop / --recheck operate on the displayed rows ──
    def _rows():
        return [r for r in best] + [r for r in bak] + [r for r in gen]

    def _ident_of(r):
        try:
            from . import core_parser as _p
            c = _p.parse(r.get("raw", ""))
            return store.ident(c) if c else None
        except Exception:  # noqa: BLE001
            return None

    if pin or drop or recheck:
        state = store.load(sp)
        all_rows = _rows()
        changed = 0
        for n in pin:
            r = all_rows[n - 1] if 0 < n <= len(all_rows) else None
            i = _ident_of(r) if r else None
            if i and store.set_golden(state, i, True):
                changed += 1
                log.info("pinned: row %d now in the golden pool ⭐", n)
        for n in drop:
            r = all_rows[n - 1] if 0 < n <= len(all_rows) else None
            i = _ident_of(r) if r else None
            if i and i in state:
                state.pop(i)
                changed += 1
                log.info("dropped: row %d removed from the pool", n)
        if changed:
            store.save(sp, state)
            _write_outputs(cfg, state, {"ts": int(time.time()),
                                        "mode": "list-actions"})
            print(f"\033[32m✓ {changed} action(s) applied\033[0m"
                  " — best/bak/gen files refreshed")
        if recheck:
            log.info("recheck: testing all stored nodes now...")
            st = store.load(sp)
            ct.data_dir_hint[0] = data
            summary = asyncio.run(ct.check(cfg_for_test(cfg), st, sp))
            store.save(sp, st)
            best2, bak2 = _write_outputs(cfg, st, {"ts": int(time.time()),
                                                   "mode": "recheck",
                                                   **summary})
            log.info("recheck done: best=%d bak=%d", len(best2), len(bak2))
    print()



def cmd_sources(cfg, *, per_source=20, top=None, target=None,
                write=False, show_rank=False):
    """`gozar sources score` — rank the sources by what they deliver for ONE target.

    The tier order is otherwise a judgement about a FILE (how well maintained it
    looks). This measures it: for every source, a bounded random sample of its
    nodes is tested against the target the user actually cares about, and the
    ones that produce working nodes move to the front.
    """
    from . import core_score
    from .core_sources import TIERS
    data, _ = _paths(cfg)
    tgt = [u for u in (target or cfg.get("targets") or []) if u]
    if not tgt:
        log.error("no target: pass -t URL (or set targets in config)")
        return 2
    # A target that is not a URL cannot be dialled through a tunnel, and the
    # silent failure looked like "every source is dead": 43 sources, 0 samples,
    # exit code 0. Fail loudly instead.
    bad = [u for u in tgt if not str(u).lower().startswith(("http://", "https://"))]
    if bad:
        log.error("target must start with http:// or https:// — got: %s", bad[0])
        return 2
    if per_source < 1:
        log.error("--per-source must be at least 1 (0 tests nothing and prints "
                  "an empty table that looks like a dead internet)")
        return 2
    log.info("scoring %d sources against: %s", sum(len(v) for v in TIERS.values()),
             ", ".join(tgt)[:90])
    log.info("sample per source: %d nodes (bounded so a 10k bundle cannot drown a "
             "300-line one)", per_source)

    def _on(row):
        if row["reachable"]:
            log.info("  %-9s %-52s parsed=%-5d tested=%-3d tcp=%-3d target-ok=%-3d "
                     "(%d%%) %s", row["tier"], row["url"].split("/")[-1][:50],
                     row["parsed"], row["sampled"], row["tcp_ok"], row["target_ok"],
                     round(100 * row["ok_rate"]),
                     f"{row['kbps']}KB/s" if row.get("kbps") else "")
        else:
            log.warning("  %-9s %-52s UNREACHABLE", row["tier"],
                        row["url"].split("/")[-1][:50])

    try:
        rows = asyncio.run(core_score.score_sources(
            cfg_for_test(cfg), tgt, per_source=per_source, on_source=_on))
    except KeyboardInterrupt:
        # Ctrl+C during a 40-minute sweep must still leave the numbers that
        # were collected. The rows are accumulated inside the coroutine, so
        # they are read back from the module-level buffer the scorer fills.
        rows = core_score.LAST_ROWS[0] if core_score.LAST_ROWS else []
        if not rows:
            print("\n  interrupted before any source finished — nothing saved")
            return 130
        print(f"\n  interrupted: saving the {len(rows)} source(s) that finished")
    ranked = core_score.rank(rows)
    tiers = core_score.summarise(rows)
    core_score.write(data, rows, tgt)

    print("\n  === per tier ===")
    print(f"  {'tier':10} {'src':>4} {'empty':>5} {'parsed':>7} {'tested':>6} "
          f"{'reached':>7} {'ok':>4} {'render':>6} {'rate':>5} {'per1k':>6}  protocols")
    for name, t in sorted(tiers.items(), key=lambda kv: -kv[1]["target_ok"]):
        mix = " ".join(f"{k[:4]}={v}" for k, v in list(t["proto_mix"].items())[:4])
        print(f"  {name:10} {t['sources']:4} {t['empty_urls']:5} {t['parsed']:7} "
              f"{t['sampled']:6} {t['reached']:7} {t['target_ok']:4} "
              f"{t['render_ok']:6} {t['ok_rate']*100:4.0f}% {t['per_1k_parsed']:6}  {mix}")

    print("\n  === sources that actually deliver this target ===")
    print(f"  {'#':>3} {'tier':9} {'ok/tested':>10} {'rate':>5} "
          f"{'body':>7} {'wall':>4} {'KB/s':>6}  source")
    shown = 0
    for i, r in enumerate(ranked, 1):
        if top and shown >= top:
            break
        if not r["sampled"]:
            continue
        # a github file URL is .../githubusercontent.com/<user>/<repo>/<branch>/<path>
        parts = r["url"].split("/")
        name = "/".join(parts[3:5] + [parts[6][:16]]) if len(parts) > 6 else r["url"]
        body = f"{(r['bytes'] or 0)//1024}KB" if r["bytes"] else "-"
        print(f"  {i:3} {r['tier']:9} {r['target_ok']:3}/{r['sampled']:<4} "
              f"{r['ok_rate']*100:4.0f}% {body:>7} {r['shell']:4} "
              f"{(r['kbps'] or 0):6.0f}  {name[:54]}")
        shown += 1

    # The metric that answers "how productive is this tier per link we paid
    # for". target_ok is 0 whenever the target itself is JS-walled, so the
    # per-tier story must be told with `reached` too.
    print(f"\n  === yield per 1000 parsed links ===")
    for name, tt in sorted(tiers.items(), key=lambda kv: -kv[1]["per_1k_reached"]):
        print(f"  {name:10} parsed={tt['parsed']:6}  reached={tt['reached']:4}  "
              f"=> {tt['per_1k_reached']:5} reached / 1000 parsed   "
              f"(ok={tt['target_ok']})")

    # print each unreachable source ONCE: the same repo appears in more than
    # one tier, and a duplicated list reads like a bigger failure than it is.
    dead = {}
    for r in rows:
        if not r["reachable"]:
            dead.setdefault(r["url"], r["tier"])
    if dead:
        print(f"\n  {len(dead)} source(s) unreachable this run (filtered or gone):")
        for url, tier in list(dead.items())[:8]:
            parts = url.split("/")
            name = "/".join(parts[3:5]) if len(parts) > 5 else url
            print(f"    {tier:9} {name}")

    print(f"\n  written: {data}/source-score.json")
    if show_rank:
        print("\n  === proposed TIERS order ===")
        by_tier = {}
        for r in ranked:
            by_tier.setdefault(r["tier"], []).append(r["url"])
        order = sorted(by_tier, key=lambda n: -tiers[n]["per_1k_reached"])
        vals = [tiers[n]["per_1k_reached"] for n in order]
        for n in order:
            print(f"  {n}: {len(by_tier[n])} source(s), "
                  f"{tiers[n]['per_1k_reached']} reached / 1000 parsed")
        if len(vals) > 1 and vals[0] - vals[1] < 0.5 * max(vals[0], 0.01):
            print("  note: the top two tiers are within noise of each other — "
                  "order them by size, not by this margin, and re-run before "
                  "changing the code.")
    return 0


def cmd_config(cfg, *, show=False, get_key=None, set_kv=None, unset_key=None,
               config_path=DEFAULT_CONFIG, doctor_hint=True):
    """`gozar config` — look at, and change, the settings that decide everything.

    Four jobs, one command, because they are the same job:
      (no args)      the whole effective config, grouped, with the SOURCE of
                     each value (default / config.json / overridden)
      --set k=v      change one key in config.json, type-checked against the
                     defaults (a string where a list belongs is a silent bug)
      --unset k      drop the key so the shipped default wins again
      --get k        print just that value, script-friendly
      --doctor       flag the keys that are stale or inconsistent
    """
    from . import config as C
    if not config_path:
        config_path = DEFAULT_CONFIG
    # Re-resolve from ONE path: the table, --get, --set and --unset must all
    # talk about the same file, or --set writes to A while --get reads B and the
    # user is told the change never happened.
    cfg = load_bot_config(config_path)
    file_cfg = C.read_config_file(config_path)

    def _emit(key):
        val = cfg.get(key)
        if isinstance(val, (list, tuple)):
            print("\n".join(str(x) for x in val))
        elif isinstance(val, dict):
            print(json.dumps(val, ensure_ascii=False))
        else:
            print(_cfg_fmt(val))

    changed = None
    if set_kv:
        changed = []
        for item in set_kv:
            if "=" not in item:
                log.error("--set needs key=value, got %r", item)
                return 2
            k, v = item.split("=", 1)
            k = k.strip()
            try:
                value = C.coerce_value(k, v)
            except ValueError as e:
                log.error("%s: %s", k, e)
                return 2
            old = file_cfg.get(k, C.DEFAULTS.get(k))
            C.write_config_key(config_path, k, value)
            changed.append((k, old, value))
        file_cfg = C.read_config_file(config_path)
        # re-resolve so --set twice in one call still lies to nobody
        cfg = load_bot_config(config_path)
    if unset_key:
        for k in unset_key:
            C.write_config_key(config_path, k, None)
        file_cfg = C.read_config_file(config_path)
        cfg = load_bot_config(config_path)
        changed = changed or []

    if get_key:
        # after --set/--unset, so `--unset k --get k` shows what the next run
        # will actually do instead of what the file said a moment ago
        _emit(get_key)
        return 0

    if changed:
        for k, old, new in changed:
            print(f"  {k}: {_cfg_fmt(old)} -> {_cfg_fmt(new)}")
        print(f"  saved to {config_path}")

    problems = _config_problems(cfg, file_cfg)
    if show or not (changed or get_key or doctor_hint):
        _print_config_table(cfg, file_cfg, config_path)
    if problems:
        print("\n  --- worth a look ---")
        for msg in problems:
            print(f"  ! {msg}")
    elif doctor_hint and not (show or changed or get_key):
        print("\n  no stale or inconsistent keys found")
    return 0


def _cfg_fmt(v) -> str:
    from .config import _fmt_val
    return _fmt_val(v)


def _print_config_table(cfg, file_cfg, config_path):
    from . import config as C
    from . import display as D
    print(f"\n  config: {config_path}"
          + ("" if file_cfg else "  (does not exist — everything below is the default)"))
    print("  source: default = shipped | config.json = the file sets it | "
          "overridden = it differs from the shipped default")
    group = None
    for g, k, val, src, note in C.describe_config(cfg, config_path, file_cfg):
        if g != group:
            print(f"\n  [{g}]")
            group = g
        colour = {"default": D.GRY, "config.json": D.CYN, "overridden": D.YEL}[src]
        mark = "" if src == "default" else "*"
        line = f"  {mark}{k:<22} {D.c(colour, _cfg_fmt(val))}"
        if note:
            line += f"   {D.c(D.GRY, note)}"
        print(line)


def _config_problems(cfg, file_cfg) -> list[str]:
    """The inconsistencies that actually cost nodes, in plain words."""
    from . import config as C
    out = []
    tg = cfg.get("targets") or []
    if not tg:
        out.append("targets is EMPTY - nodes are only checked for liveness, so a "
                   "node that answers but cannot browse still gets in. "
                   "Fix: gozar config --unset targets  (restores the 3 defaults)")
    blocked = [t for t in tg if any(d in str(t) for d in
               ("youtube.com", "twitter.com", "x.com", "instagram.com",
                "facebook.com"))]
    if blocked:
        out.append("targets include a site that is usually SNI-blocked on Iranian "
                   f"lines ({', '.join(blocked)}) - nodes will look 'failed' "
                   "while working fine. Use gstatic/wikipedia/telegram instead")
    if file_cfg.get("protocols") and "wireguard" not in (file_cfg.get("protocols") or []):
        fname = file_cfg.get("_path") or "config.json"
        out.append(f"{fname} pins a protocol list WITHOUT wireguard - the shipped "
                   "default includes it, and the file silently wins. "
                   f"Fix: gozar config --unset protocols")
    if cfg.get("min_kbps") and not (cfg.get("page_probe_urls") or []):
        out.append("min_kbps is set but page_probe_urls is empty - the speed "
                   "floor can never be measured, so it silently does nothing")
    if cfg.get("strict_exit_proof") and not cfg.get("verify_exit_ip"):
        out.append("strict_exit_proof is on while verify_exit_ip is off - "
                   "strict proof is dead code in that combination")
    pages = cfg.get("page_probe_urls") or []
    if pages and all(("generate_204" in str(u)) for u in pages):
        out.append("page_probe_urls holds ONLY generate_204 endpoints - that is "
                   "an echo check, not page proof. Add a real page, e.g. "
                   "https://en.wikipedia.org/wiki/Main_Page")
    tm = cfg.get("tier_max")
    if isinstance(tm, int) and 0 < tm < 300:
        out.append(f"tier_max={tm} tests only a slice of each tier - on a line "
                   "that can afford more, set it to 0")
    if (cfg.get("data_dir") or "data") == "data":
        pass  # normal; nothing to say
    return out


def cmd_status(cfg):
    from . import display as D
    data, sp = _paths(cfg)
    state = store.load(sp)
    from collections import Counter
    c = Counter(r.get("tier") for r in state.values() if r.get("successes", 0) > 0)
    proto = Counter(r.get("type") for r in state.values() if r.get("successes", 0) > 0)
    meta = json.loads((data / "meta.json").read_text("utf-8")) if (data / "meta.json").exists() else {}
    if D.tty():
        prot = " · ".join(f"{k} {v}" for k, v in proto.most_common(8))
        ng = sum(1 for r in state.values() if r.get("golden"))
        alive_t = sum(c.values())
        counts = store.tier_counts(state)
        last_chk = max((r.get("last_check") or 0) for r in state.values()) if state else 0
        rows = [
            ("pool", f"{len(state)} seen · {counts.get('usable',0)} usable · "
                     f"{counts.get('dead',0)} dead"),
            ("tiers", f"fast={counts.get('fast',0)}  bak={counts.get('backup',0)}"
                      f"  gen={counts.get('general',0)}  slow={counts.get('slow',0)}"
                      + (f"  gold={ng}" if ng else "")),
            ("freshness", f"last check {D.age_str(last_chk)} ago"
                          + (f" · died={meta.get('died','—')} revived={meta.get('revived','—')}"
                             if meta.get("died") is not None else "")),
            ("targets", (", ".join(cfg.get("targets", []))[:50] or "—")),
            ("last run", f"{meta.get('mode','—')} ({meta.get('ts','—')})"
                         f"  alive={meta.get('alive','—')} tested={meta.get('tested','—')}"),
        ]
        print(D.card(rows))
        if prot:
            print(" " * 2 + D.c(D.GRY, prot))
        return
    counts = store.tier_counts(state)
    print(f"  Total nodes seen: {len(state)}")
    print(f"  Usable: {counts.get('usable',0)}  | fast={counts.get('fast',0)} "
          f"bak={counts.get('backup',0)} gen={counts.get('general',0)} "
          f"slow={counts.get('slow',0)}  dead={counts.get('dead',0)}")
    from . import display as _D
    _lc = max((r.get("last_check") or 0) for r in state.values()) if state else 0
    if _lc:
        print(f"  Last check: {_D.age_str(_lc)} ago"
              + (f"  (died={meta.get('died')} revived={meta.get('revived')})"
                 if meta.get("died") is not None else ""))
    ngold = sum(1 for r in state.values() if r.get("golden"))
    if ngold:
        print(f"  Golden pinned: {ngold} (immune to pruning, listed first in pick)")
    print(f"  Protocols: {dict(proto)}")
    if meta:
        print(f"  Last run: {meta.get('mode')}  baseline={meta.get('baseline_ms')}ms  "
              f"threshold={meta.get('fast_threshold_ms')}ms  "
              f"target_ok={meta.get('target_ok', '-')}")
    targets = cfg.get("targets", [])
    if targets:
        print(f"  Targets: {', '.join(targets[:3])}" + (" ..." if len(targets) > 3 else ""))
    if cfg.get("min_kbps"):
        print(f"  Min throughput: {cfg['min_kbps']} KB/s (measured on the proof page)")
    if cfg.get("hard"):
        print("  Mode: HARD (filtered/throttled line preset)")
    print("-" * 60)


def cmd_verify(cfg, port=None, source="best", count=10, targets=None):
    if port is None:
        # verifying an already-running proxy does not need the engine
        _require_engine()
    """Prove whether nodes REALLY tunnel traffic (exit-IP proof).

    Two modes:
      --port N   verify an already-running local proxy (e.g. `gozar connect`'s 2080)
      default    verify stored nodes one by one through their own sing-box

    A 2xx/204 answer alone proves nothing: on interfered or transparent lines
    the request can be answered WITHOUT crossing the node. Comparing the
    observed exit IP against this machine's own public IP is the only reliable
    proof, so that is exactly what this command reports.
    """
    import asyncio as _a
    from . import display as D
    from .checker import (measure_own_ip, EXIT_PROBE_URLS, classify_body,
                          decode_body, browser_headers)
    from . import core_runner as runner

    tgts = list(targets or cfg.get("targets") or [])
    exit_urls = list(cfg.get("exit_probe_urls") or EXIT_PROBE_URLS)
    ua = cfg.get("user_agent") or runner.DEFAULT_UA
    verify_ssl = cfg.get("verify_ssl", False)

    own_ip, own_loc = _a.run(measure_own_ip(exit_urls, ua=ua))
    if own_ip:
        print(f"  your own line IP : {own_ip}" + (f" ({own_loc})" if own_loc else "")
              + "   ← anything exiting here is NOT tunneled")
    else:
        print(D.c(D.RED, "  could not determine your own public IP — "
                         "leak detection unavailable"))

    async def _probe(p, label):
        out = {"label": label}
        try:
            st, body, hdrs = await runner._test_via_socks(
                p, exit_urls[0], 8, ua, verify_ssl)
            from .checker import parse_exit_info
            ip, loc, colo = parse_exit_info(decode_body(body))
            if not ip:  # fall back to the other probes
                for u in exit_urls[1:]:
                    try:
                        st, body, hdrs = await runner._test_via_socks(
                            p, u, 8, ua, verify_ssl)
                        ip, loc, colo = parse_exit_info(decode_body(body))
                        if ip:
                            break
                    except Exception:  # noqa: BLE001
                        continue
            out.update(exit_ip=ip, exit_loc=loc, colo=colo, exit_status=st)
        except Exception as e:  # noqa: BLE001
            out.update(exit_ip=None, error=str(e)[:90])
        out["leak"] = bool(own_ip and out.get("exit_ip") == own_ip)
        out["target"] = {}
        for t in tgts:
            try:
                st, body, hdrs = await runner._test_via_socks(
                    p, t, 12, ua, verify_ssl)
                out["target"][t] = {"status": st,
                                    "sec": classify_body(st, body, hdrs)}
            except Exception as e:  # noqa: BLE001
                out["target"][t] = {"status": None, "sec": f"error:{str(e)[:40]}"}
        # curl-style UA: Cloudflare bot rules answer 403 to bare clients, which
        # users routinely misread as "the node is broken"
        if tgts:
            try:
                st, body, hdrs = await runner._test_via_socks(
                    p, tgts[0], 12, "curl/8.5.0", verify_ssl)
                out["curl_ua"] = {"status": st,
                                  "sec": classify_body(st, body, hdrs)}
            except Exception as e:  # noqa: BLE001
                out["curl_ua"] = {"status": None, "sec": f"error:{str(e)[:40]}"}
        return out

    def _verdict(o):
        if o.get("leak"):
            return D.c(D.RED, "LEAK ✗") + " (exit = your own line)"
        if not o.get("exit_ip"):
            return D.c(D.YEL, "UNVERIFIED ?") + f" ({o.get('error', 'no exit IP')})"
        secs = [v.get("sec") for v in o.get("target", {}).values()]
        if secs and all(s == "ok" for s in secs):
            return D.c(D.GRN, "TUNNELED ✓ target OK")
        if secs and any(s in ("cf_challenge", "cf_block") for s in secs):
            return D.c(D.YEL, "TUNNELED ✓ target CF-blocked")
        return D.c(D.GRN, "TUNNELED ✓")

    print()
    if port:
        # ── Mode A: verify a live local proxy port ──
        print(D.c(D.CYN, f"== verifying live local proxy on port {port} =="))
        o = _a.run(_probe(int(port), f"port {port}"))
        rows = [
            ("exit IP", f"{o.get('exit_ip') or '—'}"
                        + (f" ({o.get('exit_loc')})" if o.get("exit_loc") else "")
                        + (f" via {o.get('colo')}" if o.get("colo") else "")),
            ("own line IP", f"{own_ip or '—'}"),
            ("verdict", _verdict(o)),
        ]
        for t, v in o.get("target", {}).items():
            rows.append((f"target (browser)", f"{t[:40]} → HTTP {v.get('status')} [{v.get('sec')}]"))
        if o.get("curl_ua"):
            rows.append(("target (curl UA)",
                         f"HTTP {o['curl_ua'].get('status')} [{o['curl_ua'].get('sec')}]"))
        print(D.card(rows, title="tunnel proof"))
        if o.get("curl_ua") and o["curl_ua"].get("sec") in ("cf_challenge", "cf_block"):
            print("  " + D.c(D.YEL,
                  "note: the 403 you see with `curl` is Cloudflare rejecting curl's "
                  "User-Agent,\n        not a broken tunnel — the browser UA above "
                  "gets a different answer on the same proxy."))
        _print_curl_hint(port, tgts, ua)
        return 0

    # ── Mode B: verify stored nodes individually ──
    data, sp = _paths(cfg)
    state = store.load(sp)
    recs = []
    if source in ("best", "all"):
        recs += store.best(state, count if source == "best" else count * 3)
    if source in ("bak", "all"):
        recs += store.backup(state, count if source == "bak" else count * 3,
                             exclude={store.ident(r) for r in recs})
    if source in ("gen", "all"):
        recs += store.general(state, count if source == "gen" else count * 3,
                              exclude={store.ident(r) for r in recs})
    seen, uniq = set(), []
    for r in recs:
        k = store.ident(r)
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    uniq = uniq[:max(1, count)]
    if not uniq:
        print(D.c(D.YEL, f"  no stored '{source}' nodes to verify — run `gozar discover` first."))
        return 1

    from . import core_parser as parser
    cfgs = []
    for r in uniq:
        c = parser.parse(r.get("raw", ""))
        if c:
            cfgs.append(c)
    print(D.c(D.CYN, f"== verifying {len(cfgs)} stored '{source}' node(s) with exit-IP proof =="))
    results = _a.run(runner.test_configs_batch(
        cfgs, echo_url=cfg.get("echo_url", "https://www.google.com/generate_204"),
        target_url=tgts, timeout=cfg.get("timeout", 8),
        target_timeout=cfg.get("target_timeout", 12),
        startup=cfg.get("startup_delay", 0.8), ua=ua, verify_ssl=verify_ssl,
        exit_urls=exit_urls, own_ip=own_ip, verify_exit=True))

    by_ident = {}
    for c, r in results:
        by_ident[store.ident(c)] = (c, r)
    n_ok = n_leak = n_unver = n_dead = 0
    print()
    for c in cfgs:
        pair = by_ident.get(store.ident(c))
        r = pair[1] if pair else {"alive": False, "error": "not tested"}
        tag = str(c.get("tag") or c.get("server"))[:26]
        if r.get("leak"):
            plain, colour, n_leak = "LEAK ✗", D.RED, n_leak + 1
        elif not r.get("alive"):
            plain, colour, n_dead = "DEAD ✗", D.RED, n_dead + 1
        elif not r.get("exit_verified"):
            plain, colour, n_unver = "UNVERIFIED ?", D.YEL, n_unver + 1
        else:
            plain, colour, n_ok = "TUNNELED ✓", D.GRN, n_ok + 1
        mark = D.c(colour, plain.ljust(13))
        lat = r.get("latency")
        ex = r.get("exit_ip") or "—"
        loc = f" {r['exit_loc']}" if r.get("exit_loc") else ""
        tsec = r.get("security") or "—"
        # Say what the verdict actually is. A shell that the target serves to
        # every client (single-page app) is a PASS for that target, and
        # printing a bare "js_shell" next to "TUNNELED" made a working node look
        # broken — the exact confusion this round started with.
        if tsec == "js_shell":
            tsec = ("js_shell (target is an SPA → counted as OK)"
                    if r.get("target_ok") else "js_shell (no page)")
        elif tsec == "ok" and r.get("target_ok"):
            tsec = "ok"
        print(f"  {mark} {tag:28} {c.get('type','?'):11} "
              f"{(f'{lat:7.0f}ms' if lat is not None else '      — ')}  "
              f"exit={ex}{loc:4} target={tsec}")
        if r.get("error") and not r.get("alive"):
            print(f"      {D.c(D.GRY, str(r['error'])[:100])}")
    print()
    print(f"  summary: {D.c(D.GRN, f'tunneled={n_ok}')}  "
          f"{D.c(D.RED, f'leaked={n_leak}')}  "
          f"{D.c(D.YEL, f'unverified={n_unver}')}  "
          f"{D.c(D.RED, f'dead={n_dead}')}")
    if n_leak:
        print("  " + D.c(D.YEL,
              "leaked = the answer came from your own line, not through the node. "
              "These are\n           rejected automatically by discover/check too "
              "(verify_exit_ip)."))
    if n_unver:
        print("  " + D.c(D.GRY,
              "unverified = exit-IP probe unreachable through that node; the node "
              "may still work."))
    _print_curl_hint(cfg.get("connect", {}).get("port", 2080), tgts, ua)
    return 0


def _print_curl_hint(port, tgts, ua):
    from . import display as D
    if not tgts:
        return
    print()
    print("  " + D.c(D.GRY, "reproduce it yourself (note the browser -A; bare curl gets "
                            "Cloudflare-challenged):"))
    print("    " + D.c(D.CYN,
          f"curl -x socks5h://127.0.0.1:{port} -A \"{ua}\" -I {tgts[0]}"))
    print("    " + D.c(D.GRY,
          f"# without -A you get HTTP 403 + cf-mitigated: challenge — that is "
          f"Cloudflare\n    # blocking curl, NOT a broken node. Compare:"))
    print("    " + D.c(D.CYN, f"curl -x socks5h://127.0.0.1:{port} -I {tgts[0]}"))


# ─────────────────────────── engine management ───────────────────────────

def _help_text() -> str:
    """Bytes, not str: avoids the cp1252 crash on a Windows console."""
    return build_parser().format_help()


def _show_help_friendly() -> int:
    """Bare `gozar` should rarely be a bare traceback.

    Two real cases from 2026-11-27:
      * pip refuses to install a SECOND top-level command called `cli`
        (the dev launcher was named that), so one path died before main();
      * a fresh user types `gozar` and gets usage text with exit 2, which reads
        like an error. Terse help + 0 here, full help behind -h.
    """
    out = [
        "gozar — find, test and connect through public proxy nodes",
        "",
        "  gozar engine install        get the sing-box binary (do this once)",
        "  gozar discover -n 20 -t https://example.com/",
        "  gozar verify                prove the stored nodes really tunnel",
        "  gozar connect               local proxy on :2080",
        "",
        "  gozar -h                    every command, every flag",
        "",
    ]
    from . import APP_NAME, __version__
    out.append(f"  {APP_NAME} {__version__}")
    sys.stdout.write("\n".join(out) + "\n")
    return 0


def _flag(cfg, name, default=False):
    """Read a private run-flag (`_engine_force`, `_reset_requested`, ...).

    cfg is a dict everywhere in gozar, but a couple of code paths and older
    call sites hand in an object. Reading the dict key *or* the attribute in one
    place means a flag can never be silently dropped again — which is exactly
    how `--reinstall` ended up doing nothing on 2026-11-27.
    """
    if cfg is None:
        return default
    try:
        if name in cfg:
            return cfg[name]
    except TypeError:                       # not a mapping
        pass
    return getattr(cfg, name, default)


def cmd_engine(cfg, action="status", target=None, quiet=False):
    """`gozar engine status|install` — find or fetch the sing-box binary.

    A clone of this repo carries no binary (engines/ is git-ignored: it is 40MB).
    So "I cloned it, what now" has to be one command, and it has to tell the
    user exactly which of the four ways to get an engine they are using.
    """
    from . import engines as E

    found = E.find_binary("sing-box")
    if action == "status":
        if found is None:
            print("  engine : not found")
            print()
            print(E.INSTALL_HINTS)
            return 2
        print(f"  engine : {found}")
        print(f"  source : {E.source_of(found)}")
        v = None
        try:
            import subprocess
            out = subprocess.run([str(found), "version"], capture_output=True,
                                 text=True, timeout=10).stdout.splitlines()
            v = out[0] if out else None
        except Exception:                                    # noqa: BLE001
            pass
        print(f"  version: {v or 'could not run it'}")
        return 0 if v else 2
    if action == "install":
        dest = Path(target) if target else E.ENGINE_DIR
        # An engine found *outside* our own dir (PATH, pip package, $GOZAR_SINGBOX)
        # is somebody else's install: replacing it belongs to that tool, not to us.
        ours = found is not None and Path(found).parent == Path(dest)
        if ours and not _flag(cfg, "_engine_force"):
            print(f"  already installed: {found}")
            print("  nothing to do (use --reinstall to replace it)")
            return 0
        if found is not None and not ours:
            print(f"  found another engine: {found} ({E.source_of(found)})")
            print(f"  it is already usable — gozar prefers it. Installing a copy in {dest}")
            print("  is only needed if you want gozar to be self-contained.")
        if ours:
            print(f"  replacing the copy in {dest}")
        print(f"  target : {dest}")
        # --yes means "stop asking", NOT "stop talking": the download, the
        # verification and the final binary path must still be visible.
        assume_yes = _flag(cfg, "_engine_yes") or quiet
        if not E.confirm_install(assume_yes=assume_yes):
            print("  cancelled — nothing downloaded. The engine above still works.")
            return 2
        try:
            E.install_official(dest, quiet=quiet)
        except SystemExit as e:
            print(e)
            return 2
        return 0
        return 0
    log.error("unknown engine action: %s (use status or install)", action)
    return 2


# ─────────────────────────── argument parser ───────────────────────────

EPILOG = """\
Examples:
  # Gather up to 50 nodes that can open example.com, fastest first
  gozar discover -t https://example.com/ -n 50

  # Re-check stored nodes
  gozar check

  # Test multiple target sites at once
  gozar discover -t https://example.com/ -t https://en.wikipedia.org/ -n 30

  # Run continuously in the background
  gozar loop --check-interval 900 -n 50

  # Connect (local proxy on port 2080, auto urltest over best nodes)
  gozar connect

  # Full system tunnel (needs root)
  sudo -E gozar connect --mode tun

  # Interactive picker over stored nodes — Enter connects, d deletes
  gozar pick
  gozar drop 26e0e391

  # One command: find 10 good nodes, verify, then pick by number
  gozar run 10 --min-speed 700
"""


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default=argparse.SUPPRESS,
                        help="Config file path (default: config.json)")
    common.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    common.add_argument("-q", "--quiet", action="store_true",
                        help="Warnings and results only (less log noise)")
    common.add_argument("--version", action="store_true",
                        help="Show app name and version")

    search = argparse.ArgumentParser(add_help=False)
    search.add_argument("-t", "--target", dest="targets", action="append", metavar="URL",
                        help="Target URL to test — repeatable (-t A -t B) or comma-separated "
                             "(-t 'A,B,C'); there is no limit on how many. "
                             "Leave it empty to run in liveness-only mode.")
    search.add_argument("--no-target", dest="no_target", action="store_true",
                        default=argparse.SUPPRESS,
                        help="liveness-only mode: ignore targets from config.json and keep "
                             "every node that is really ALIVE (echo + page + exit proof). "
                             "Same as -t '' .")
    search.add_argument("-n", "--count", dest="best_n", type=int, metavar="N",
                        help="Number of good nodes for best")
    search.add_argument("--bak", dest="bak_n", type=int, metavar="N",
                        help="Number of backup nodes")
    search.add_argument("-p", "--protocols", metavar="LIST",
                        help="Protocols, comma-separated: hysteria2,vless,trojan,...")
    search.add_argument("--baseline-ms", type=int, metavar="MS",
                        help=argparse.SUPPRESS)
    search.add_argument("--fast-factor", type=float, metavar="F",
                        help=argparse.SUPPRESS)
    search.add_argument("--fast-max", dest="fast_max_ms", type=int, metavar="MS",
                        help="Max latency for 'fast' tier (default 500)")
    search.add_argument("--min-speed", dest="min_speed_ms", type=int, metavar="KBPS",
                        help="Minimum REAL throughput in KB/s (measured on the proof "
                             "page); slower nodes never enter best/bak. Latency has "
                             "its own flags: --fast-max / --bak-max.")
    search.add_argument("--bak-max", dest="backup_max_ms", type=int, metavar="MS",
                        help="Latencies above this are not stored at all")
    search.add_argument("--max-per-proto", type=int, metavar="N",
                        help="Max initial samples per protocol (0 = unlimited)")
    search.add_argument("--max-per-subnet", dest="max_per_subnet", type=int,
                        metavar="N",
                        help="Max candidates from one /24 so a single host cannot "
                             "fill the pool (default 6, 0 = off)")
    search.add_argument("--reset", dest="reset", action="store_true",
                        help="start from an EMPTY pool (the old state.json is "
                             "archived, not deleted)")
    search.add_argument("--list-mode", dest="list_mode",
                        choices=["target", "live"],
                        help="target (default): best/bak = passed every target, "
                             "the rest stay alive in gen; live: list every alive "
                             "node, target-OK first")
    search.add_argument("--strict-target", dest="require_target",
                        action="store_true",
                        help="OLD strict behaviour: list ONLY nodes that passed "
                             "every target (default: alive+usable, target-OK first)")
    search.add_argument("--concurrency", dest="test_concurrency", type=int, metavar="N",
                        help="Concurrent sing-box tests (default 14)")
    search.add_argument("--probe-concurrency", dest="probe_concurrency", type=int, metavar="N",
                        help="Concurrent TCP probes (default 400)")
    search.add_argument("--probe", dest="probe_mode", choices=["auto", "on", "off"],
                        default=argparse.SUPPRESS,
                        help="TCP/QUIC pre-filter: auto (default — decides per run by "
                             "sampling whether the line looks open), on (always), off "
                             "(never). It only changes how many candidates sing-box "
                             "starts for, never which ones PASS the real test.")
    search.add_argument("--no-probe", dest="no_probe", action="store_true",
                        default=argparse.SUPPRESS,
                        help="alias for --probe off")
    search.add_argument("--timeout", type=int, metavar="SEC", help="Echo timeout")
    search.add_argument("--target-timeout", type=int, metavar="SEC",
                        help="Per-target timeout")
    search.add_argument("--startup-delay", type=float, metavar="SEC",
                        help="sing-box startup delay per test")
    search.add_argument("--verify-ssl", action="store_true",
                        help="Enforce strict TLS verification")
    search.add_argument("--no-exit-proof", dest="no_exit_proof", action="store_true",
                        default=argparse.SUPPRESS,
                        help="disable the exit-IP tunnel proof (faster, but a 2xx "
                             "no longer proves traffic crossed the node)")
    search.add_argument("--strict-exit", dest="strict_exit", action="store_true",
                        default=argparse.SUPPRESS,
                        help="reject nodes whose exit IP cannot be read (paranoid "
                             "mode for interfered/transparent lines)")
    search.add_argument("--no-verify-ssl", action="store_true",
                        help="Disable TLS verification")
    search.add_argument("--pace", dest="pace_ms", type=int, metavar="MS",
                        default=argparse.SUPPRESS,
                        help="spread test/probe starts (random jitter 0..MS) — "
                             "anti rate-limit for lines that die after ~200 nodes")
    search.add_argument("--breaker", dest="breaker_on", action="store_true",
                        default=argparse.SUPPRESS,
                        help="accepted for compatibility: the circuit breaker is "
                             "always on (see test_breaker_streak / "
                             "probe_breaker_window in config.py)")
    search.add_argument("--latency-basis", dest="latency_basis",
                        choices=["echo", "target"], default=argparse.SUPPRESS,
                        help="latency ranking basis: echo (default) or target "
                             "(download time of the target site — closest to real UX)")
    common.add_argument("-o", "--data-dir", metavar="DIR",
                        default=argparse.SUPPRESS,
                        help="Output and state dir")
    search.add_argument("--cdn", dest="cdn_only", action="store_true",
                        default=argparse.SUPPRESS,
                        help="test ONLY Cloudflare-fronted nodes (CF ranges) — "
                             "the nodes that survive 'national internet' phases")
    search.add_argument("-i", "--import", dest="import_files", action="append",
                        metavar="FILE", default=argparse.SUPPRESS,
                        help="local file with raw node links (mixed lines or "
                             "base64 sub content); parsed+deduped links are "
                             "tested FIRST, before known nodes and tiers "
                             "(repeatable)")
    search.add_argument("--open-sni", dest="open_sni", action="store_true",
                        default=argparse.SUPPRESS,
                        help="keep ONLY nodes whose SNI is in today's open "
                             "corridor set (*.ir always passes; foreign hosts "
                             "from a saved shutdown profile + built-in safe list)")
    search.add_argument("--safe-ports", dest="safe_ports", action="store_true",
                        default=argparse.SUPPRESS,
                        help="keep ONLY nodes on filter-friendly ports "
                             "(443, 8443, 80, 2083)")
    search.add_argument("--domestic", dest="domestic_only", action="store_true",
                        default=argparse.SUPPRESS,
                        help="use ONLY domestic (.ir) sources from config "
                             "[domestic_sources] — for a full internet shutdown")

    p = argparse.ArgumentParser(
        prog="gozar",
        description="gozar - gather, test, maintain and connect "
                    "public nodes; survive filtering and shutdowns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
        parents=[common])
    # --hard works anywhere on the command line (like -q), so both
    # `gozar --hard discover` and `gozar discover --hard` are accepted.
    p.add_argument("--hard", action="store_true",
                   help="hard mode preset: the line is filtered/throttled. Full TCP "
                        "pre-filter, smaller batches, longer timeouts, keeps going past "
                        "dead spells, wider 'keep' ceiling. Any explicit flag or "
                        "config value still overrides it.")
    sub = p.add_subparsers(dest="cmd", metavar="<command>", required=False)

    sub.add_parser("discover", parents=[common, search],
                   help="Broadly gather and test until best is full",
                   description="Fetches configs from public sources, runs TCP probes, "
                               "and tests with sing-box until enough good nodes are found.")

    sp = sub.add_parser("check", parents=[common, search],
                        help="Re-check stored nodes and drop dead ones",
                        description="Re-checks currently stored best/bak nodes, "
                                    "drops dead ones, and re-tiers fast/slow.")
    sp.add_argument("--prune-failures", type=int, metavar="N",
                    help="Drop node after N consecutive failures")
    sp.add_argument("--drop-dead", dest="drop_dead", action="store_true",
                    help="immediately delete nodes failing THIS check (skip prune_failures wait)")

    sp = sub.add_parser("loop", parents=[common, search],
                        help="Run continuously: discover + periodic check",
                        description="Runs an initial discover then re-checks every "
                                    "check-interval seconds; re-discovers when best runs low.")
    sp.add_argument("--check-interval", type=int, metavar="SEC",
                    help="Seconds between checks (default 1800)")
    sp.add_argument("--discover-interval", type=int, metavar="SEC",
                    help="Min seconds between forced discovers")

    cn = sub.add_parser("connect", parents=[common],
                        help="Start sing-box with best nodes",
                        description="Brings up a local mixed proxy (SOCKS5+HTTP) or a "
                                    "full TUN tunnel using the auto urltest group.")
    cn.add_argument("--no-pretest", action="store_true",
                    help="skip the connect pre-test (connect may then pick a dead node)")
    cn.add_argument("--mode", choices=["proxy", "tun"], default=None,
                    help="Connection mode (default from config: proxy)")
    cn.add_argument("--port", type=int, default=None, help="Local mixed proxy port")
    cn.add_argument("--from", dest="connect_from", choices=["best", "bak", "gen", "all"],
                    default="best", help="Which list to use (best/bak/gen/all, default: best)")
    cn.add_argument("--allow-no-target", dest="allow_no_target", action="store_true",
                    help="allow falling back to the gen pool (alive nodes that did "
                         "NOT pass the targets) when no target-ok node exists")
    cn.add_argument("--pin", type=int, default=None, metavar="IDX",
                    help="Connect with a single pinned node by index (see bot list) "
                         "instead of the urltest auto group")
    rn = sub.add_parser("run", parents=[common, search],
                        help="Find N good nodes, verify, then connect",
                        description="All-in-one: discovers if needed, verifies each node "
                                    "against targets, then connects.")
    rn.add_argument("count_run", type=int, metavar="N", nargs="?", default=10,
                    help="Number of good nodes to connect with (default 10)")
    rn.add_argument("--mode", choices=["proxy", "tun"], default=None)
    rn.add_argument("--port", type=int, default=None)
    rn.add_argument("--force", action="store_true",
                    help="Force a fresh discover even if best is full")

    pk = sub.add_parser("pick", parents=[common],
                        help="Interactively pick a node and connect",
                        description="Opens an interactive picker (curses TUI on a "
                                    "terminal, numbered menu otherwise); golden-pinned "
                                    "nodes are listed first and never auto-pruned. "
                                    "Keys: Enter=connect g=golden d=delete.")
    pk.add_argument("--mode", choices=["proxy", "tun"], default=None)
    pk.add_argument("--port", type=int, default=None)
    pk.add_argument("--from", dest="pick_from", choices=["best", "bak", "gen", "all"],
                    default="best",
                    help="which pool to show first: best (target-ok, the default), "
                         "gen (alive but target NOT passed), all (everything). "
                         "Inside pick: f cycles filters, G toggles the gen pool.")

    dr = sub.add_parser("drop", parents=[common],
                        help="Delete a node from state by id or index",
                        description="Removes one node from the stored state. Accepts the "
                                    "short id shown by 'gozar pick'/'gozar list' or a list index.")
    dr.add_argument("node_id", metavar="ID", help="Short id (from pick/list) or index")

    # [WARP removed per user decision — nodes engine only]
    li = sub.add_parser("list", parents=[common], help="Show best and backup nodes",
                        description="Prints the best/backup pools. Actions:\n"
                                    "  --pin N...   mark row(s) golden (never auto-pruned)\n"
                                    "  --drop N...  delete row(s) from the pool\n"
                                    "  --recheck    re-test the shown pool now",
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    li.add_argument("--pin", nargs="+", type=int, default=(), metavar="N",
                    help="row number(s) to pin into the golden pool ⭐")
    li.add_argument("--drop", nargs="+", type=int, default=(), metavar="N",
                    help="row number(s) to delete from the pool")
    li.add_argument("--recheck", action="store_true",
                    help="re-test all stored nodes now")
    sub.add_parser("status", parents=[common], help="Overall stats and active config",
                   description="Shows node counts, tier distribution, protocols and targets.")
    vf = sub.add_parser("verify", parents=[common],
                        help="Prove nodes REALLY tunnel (exit-IP proof, not just 2xx)",
                        description="Answers 'is it actually connected?' with evidence:\n"
                                    "  • reads the public exit IP through the tunnel and\n"
                                    "    compares it with your own line IP (LEAK detection)\n"
                                    "  • shows the target's real HTTP verdict (ok / cf_challenge)\n"
                                    "  • shows why bare `curl` gets 403 while a browser works\n"
                                    "With --port N it verifies an already-running local proxy\n"
                                    "(e.g. the 2080 that `gozar connect` opens).\n"
                                    "Without it, stored nodes are verified one by one.",
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    vf.add_argument("--port", type=int, default=None, metavar="N",
                    help="verify a live local proxy port instead of stored nodes")
    vf.add_argument("--from", dest="verify_from", choices=["best", "bak", "gen", "all"],
                    default="best", help="which stored list to verify (default: best)")
    vf.add_argument("-n", "--count", dest="verify_count", type=int, default=10,
                    metavar="N", help="how many stored nodes to verify (default: 10)")
    vf.add_argument("-t", "--target", dest="verify_targets", action="append", default=[],
                    metavar="URL", help="target URL(s) to verify (default: config targets)")
    cal = sub.add_parser("calibrate", parents=[common],
                         help="Measure YOUR line and propose fast/keep ping ceilings "
                              "and best/bak/gen counts instead of hard-coded guesses",
                         description="Samples the line RTT and the latencies of the nodes "
                                     "already tested on this machine, then prints a config "
                                     "block; --write saves it to config.json.")
    cal.add_argument("--write", action="store_true",
                     help="write the recommended numbers into config.json")
    cal.add_argument("--profile", choices=["conservative", "standard", "fast"],
                     default="standard",
                     help="conservative = keep more nodes (fewer dead ends), "
                          "fast = fewer but quicker nodes (default: standard = "
                          "use the measured numbers as-is)")
    cal.add_argument("--config-out", dest="config_out", default="config.json",
                     metavar="FILE", help="file to update with --write (default config.json)")

    src = sub.add_parser("sources", parents=[common, search],
                         help="Score the sources against ONE target and rank them "
                              "by what they actually deliver",
                         description="Tests a bounded random sample from every "
                                     "source against the target you pass, then "
                                     "prints: per-tier totals, a ranked list of "
                                     "sources, and the unreachable ones. It never "
                                     "changes your pool; the result goes to "
                                     "data/source-score.json.",
                         epilog="example:\n"
                                "  bot sources -t '<your target url>' --per-source 20\n",
                         formatter_class=argparse.RawDescriptionHelpFormatter)
    src.add_argument("--per-source", type=int, default=20, metavar="N",
                     help="nodes to sample per source (default 20)")
    src.add_argument("--top", type=int, default=15, metavar="N",
                     help="how many ranked sources to print (default 15)")
    src.add_argument("--propose", action="store_true",
                     help="also print the proposed tier order")

    cf = sub.add_parser("config", parents=[common],
                        help="See and change the settings that decide every run "
                             "(grouped, with the source and reason of each value)",
                        description="Without arguments it prints the effective "
                                    "config, grouped, marking each value as "
                                    "default / config.json / overridden, with a "
                                    "one-line reason. --set writes ONE key without "
                                    "hand-editing JSON (type-checked against the "
                                    "defaults), --unset drops a key so the shipped "
                                    "default wins again, --doctor lists the "
                                    "combinations that silently cost nodes.",
                        epilog="examples:\n"
                               "  bot config\n"
                               "  bot config --set best_n=20 --set targets='"
                               "https://www.gstatic.com/generate_204,"
                               "https://api.telegram.org/'\n"
                               "  bot config --unset targets      # back to the defaults\n"
                               "  bot config --get targets\n"
                               "  bot config --doctor\n",
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    cf.add_argument("--show", action="store_true", help="print the table (default)")
    cf.add_argument("--get", dest="cfg_get", metavar="KEY",
                    help="print one effective value, nothing else")
    cf.add_argument("--set", dest="cfg_set", action="append", metavar="KEY=VALUE",
                    help="set one key in config.json (repeatable); lists accept "
                         "comma or space separated values")
    cf.add_argument("--unset", dest="cfg_unset", action="append", metavar="KEY",
                    help="remove a key from config.json (shipped default wins)")
    cf.add_argument("--doctor", dest="cfg_doctor", action="store_true",
                    help="only report the keys that are stale or inconsistent")
    cf.add_argument("--config-out", dest="cfg_out", default=None,
                    metavar="FILE", help="file to read/write (default: the -c "
                                         "config this run uses)")

    doc = sub.add_parser("doctor", parents=[common],
                         help="Run diagnostics (binary, packages, sources, ping, sample test)",
                         description="Checks that the bot and its dependencies are "
                                     "installed correctly and performs a small live "
                                     "connectivity test. Every check has a name; "
                                     "`--only` runs just one of them.")
    doc.add_argument("--only", metavar="CHECK", default=None,
                     help="run a single check (python, packages, engine, limits, "
                          "data, root, sources, sample, own_ip, targets)")
    doc.add_argument("--list-checks", dest="list_checks", action="store_true",
                     help="print the check names and exit")

    eng = sub.add_parser("engine", parents=[common],
                         help="Check or install the sing-box binary",
                         description="Where the testing engine comes from, and how to "
                                     "get it if it is missing. `install` downloads "
                                     "the official release into the gozar data dir.")
    eng.add_argument("engine_action", nargs="?", default="status",
                     choices=["status", "install"], help="status (default) or install")
    eng.add_argument("--to", dest="engine_dir", metavar="DIR",
                     help="install into DIR instead of the default data dir")
    eng.add_argument("--yes", dest="engine_yes", action="store_true",
                     help="do not ask before downloading")
    eng.add_argument("--reinstall", dest="engine_force", action="store_true",
                     help="replace an engine that is already present")
    return p


# ─────────────────────────── main ───────────────────────────

def main(argv=None):
    import sys as _s
    _argv = list(argv) if argv is not None else _s.argv[1:]
    # -q works ANYWHERE (before or after the subcommand); argparse placement
    # rules would otherwise silently drop it when written before the command
    _quiet = any(a in ("-q", "--quiet") for a in _argv)
    if _quiet:
        _argv = [a for a in _argv if a not in ("-q", "--quiet")]
    # --hard is a preset, not a per-command flag: strip it wherever it appears
    # and apply the whole bundle before config.json / explicit flags.
    _hard = "--hard" in _argv
    if _hard:
        _argv = [a for a in _argv if a != "--hard"]
    # --reset is a pool-level intent, not a per-command flag: accept it before
    # the subcommand too, so `gozar --reset discover` and `gozar discover --reset`
    # mean the same thing (one was silently rejected).
    _reset = "--reset" in _argv
    if _reset:
        _argv = [a for a in _argv if a != "--reset"]
    args = build_parser().parse_args(_argv)
    args.quiet = _quiet or getattr(args, "quiet", False)
    args.hard = _hard or getattr(args, "hard", False)
    args.reset = _reset or getattr(args, "reset", False)
    if getattr(args, "version", False):
        from . import APP_NAME, __version__
        print(f"{APP_NAME} {__version__}")
        return 0
    if not getattr(args, "cmd", None):
        return _show_help_friendly()
    _level = (logging.DEBUG if args.verbose
              else (logging.WARNING if getattr(args, "quiet", False)
                    else logging.INFO))
    logging.basicConfig(
        level=_level,
        format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    # Config resolution, in order: -c PATH, then the per-user location a pip
    # install can actually own (~/.config/gozar/config.json), then ./config.json
    # from a checkout. Before this, a pip install silently ran on defaults and
    # every `config --set` seemed to vanish.
    _config_arg = getattr(args, "config", None)
    if _config_arg:
        _cfg_path = Path(_config_arg)
    else:
        _user_cfg = (Path(os.environ.get("XDG_CONFIG_HOME")
                          or Path.home() / ".config") / "gozar" / "config.json")
        _cfg_path = _user_cfg if _user_cfg.exists() else Path(DEFAULT_CONFIG)
    cfg = load_bot_config(str(_cfg_path))
    cfg = apply_overrides(cfg, args)

    if args.cmd == "discover":
        cmd_discover(cfg)
    elif args.cmd == "check":
        cmd_check(cfg, drop_dead=getattr(args, "drop_dead", False))
    elif args.cmd == "loop":
        cmd_loop(cfg)
    elif args.cmd == "connect":
        mode = args.mode or cfg.get("connect", {}).get("mode", "proxy")
        port = args.port or cfg.get("connect", {}).get("port", 2080)
        source = getattr(args, "connect_from", "best")
        return cmd_connect(cfg, mode, port, args.pin, source,
                           pretest=not getattr(args, "no_pretest", False),
                           allow_no_target=getattr(args, "allow_no_target", False))
    elif args.cmd == "run":
        mode = args.mode or cfg.get("connect", {}).get("mode", "proxy")
        port = args.port or cfg.get("connect", {}).get("port", 2080)
        if getattr(args, "best_n", None) is None:
            cfg["best_n"] = args.count_run
        return cmd_run(cfg, args.count_run, mode, port, args.force)
    elif args.cmd == "pick":
        from . import ui_pick
        return ui_pick.cmd_pick(cfg, port=args.port, mode=args.mode,
                                start_from=getattr(args, "pick_from", "all"))
    elif args.cmd == "drop":
        from . import ui_pick
        return ui_pick.cmd_drop(cfg, args.node_id)
    elif args.cmd == "list":
        cmd_list(cfg, pin=getattr(args, "pin", ()),
                 drop=getattr(args, "drop", ()),
                 recheck=getattr(args, "recheck", False))
    elif args.cmd == "status":
        cmd_status(cfg)
    elif args.cmd == "verify":
        return cmd_verify(cfg, port=getattr(args, "port", None),
                          source=getattr(args, "verify_from", "best"),
                          count=getattr(args, "verify_count", 10),
                          targets=getattr(args, "verify_targets", None))
    elif args.cmd == "calibrate":
        return cmd_calibrate(cfg, write=getattr(args, "write", False),
                             config_path=getattr(args, "config_out", "config.json"),
                             profile=getattr(args, "profile", None))
    elif args.cmd == "sources":
        return cmd_sources(cfg, per_source=getattr(args, "per_source", 20),
                           top=getattr(args, "top", 15),
                           target=getattr(args, "targets", None),
                           show_rank=getattr(args, "propose", False))
    elif args.cmd == "config":
        from .config import DEFAULT_CONFIG as _DC
        return cmd_config(cfg,
                          show=getattr(args, "show", False),
                          get_key=getattr(args, "cfg_get", None),
                          set_kv=getattr(args, "cfg_set", None),
                          unset_key=getattr(args, "cfg_unset", None),
                          # the file this run loads (-c), unless --config-out says
                          # otherwise: writing to config.json while -c pointed at
                          # another file is how a "saved" change vanishes.
                          config_path=(getattr(args, "cfg_out", None)
                                       or getattr(args, "config", None) or _DC),
                          doctor_hint=bool(getattr(args, "cfg_doctor", False)))
    elif args.cmd == "engine":
        cfg["_engine_yes"] = bool(getattr(args, "engine_yes", False))
        cfg["_engine_force"] = bool(getattr(args, "engine_force", False))
        return cmd_engine(cfg, action=args.engine_action,
                          target=getattr(args, "engine_dir", None),
                          # -q silences; --yes only answers the prompt
                          quiet=bool(getattr(args, "quiet", False)))
    elif args.cmd == "doctor":
        if getattr(args, "list_checks", False):
            from .doctor_checks import registry
            for name, title, _fn in registry():
                print(f"  {name:<10} {title}")
            return 0
        return doctor.run_doctor(cfg, only=getattr(args, "only", None))
    return 0


def cli(argv=None):
    """Console-script entry point (`gozar`): identical to _run_main."""
    return _run_main(argv)


def _run_main(argv=None):
    """`main` with Ctrl+C treated as a normal ending, not a crash.

    Ctrl+C is how a user stops a long discover/check/sources run. It used to
    escape as a KeyboardInterrupt traceback (and, with a second Ctrl+C during
    shutdown, could leave the process looking stuck). One handler here covers
    every command; individual commands that can save partial work do so first.
    """
    try:
        return main(argv)
    except KeyboardInterrupt:
        print("\n\033[33minterrupted — partial results were saved where the "
              "command could save them\033[0m", file=sys.stderr)
        return 130
    except BrokenPipeError:
        # `gozar list | head` must not traceback
        try:
            sys.stderr.close()
        except Exception:  # noqa: BLE001
            pass
        return 0


if __name__ == "__main__":
    sys.exit(_run_main())
