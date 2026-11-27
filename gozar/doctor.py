"""doctor — `gozar doctor`: is this install able to do anything?

The command itself is small on purpose. The checks live in doctor_checks.py,
the wording lives in core_ui.py, and this file is only the running order:

    1. the static checks        (python, packages, engine, limits, data, root)
    2. the live checks          (sources, baseline ping, one end-to-end sample,
                                 own public IP, targets without a proxy)
    3. the report               (last run: where the candidates went)
    4. the verdict              (core_ui.Ledger -> exit code)

`engine` is a gate. If it is missing, steps 2's tunnel work is meaningless, so
it is skipped with one line instead of a traceback or a misleading "0 alive".
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from . import core_ui as U
from .core_ui import FAIL, OK, WARN
from .doctor_checks import last_run_report, registry, report, explain_failure

# kept as a module-level name so `gozar doctor` output and the live checks below
# stay readable; the actual implementations are near the bottom of the file


async def _check_sources(timeout=8):
    """How many source URLs answer, per tier. Names the ones being cut."""
    import aiohttp
    from .core_sources import TIERS
    headers = {"User-Agent": "Mozilla/5.0"}
    to = aiohttp.ClientTimeout(total=timeout)
    results = {}
    async with aiohttp.ClientSession(headers=headers, timeout=to) as s:
        for tier, urls in TIERS.items():
            async def head(u):
                try:
                    async with s.get(u) as r:
                        return (r.status == 200, u)
                except Exception:                        # noqa: BLE001
                    return (False, u)
            checks = await asyncio.gather(*(head(u) for u in urls))
            good_n = sum(1 for good, _ in checks if good)
            down = [u for good, u in checks if not good]
            results[tier] = (good_n, len(urls), down)
    return results


async def _sample_test():
    """Try a handful of configs from trusted sources until one connects.

    A single "SOCKS server failure" is not fatal — free nodes are flaky, so we
    test up to 5 candidates before warning.
    """
    import aiohttp
    from . import core_runner as runner
    from .core_parser import parse as parse_link
    from .core_sources import TRUSTED_SOURCES
    headers = {"User-Agent": "Mozilla/5.0"}
    to = aiohttp.ClientTimeout(total=15)
    candidates = []
    async with aiohttp.ClientSession(headers=headers, timeout=to) as s:
        for url in TRUSTED_SOURCES[:3]:
            try:
                async with s.get(url) as r:
                    text = await r.text(errors="ignore")
            except Exception:                            # noqa: BLE001
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                cfg = parse_link(line)
                if cfg:
                    candidates.append(cfg)
                if len(candidates) >= 5:
                    break
            if len(candidates) >= 5:
                break
    if not candidates:
        return None, {"error": "no parseable link in the first 3 sources",
                      "tried": 0, "errors": []}
    try:
        res = await runner.test_config(candidates[0])
    except Exception as e:                               # noqa: BLE001
        return None, {"error": f"{type(e).__name__}: {e}", "tried": 1,
                      "errors": [str(e)]}
    return candidates[0], res


def _engine_present(cfg: dict) -> bool:
    from .engines import find_binary
    return bool(find_binary("sing-box"))


def run_doctor(cfg: dict, only: str | None = None) -> int:
    """Entry point. `only` limits the run to one registered check, by name."""
    print("\n=== gozar doctor ===")
    ledger = U.Ledger()

    checks = registry()
    if only:
        # a live check is a single named step too, so --only works on both kinds
        live = {"sources": lambda l: _live_sources(cfg, l),
                "baseline": lambda l: _live_baseline(cfg, l),
                "sample": lambda l: _live_sample(cfg, l, _engine_present(cfg)),
                "own_ip": lambda l: _live_own_ip(cfg, l),
                "targets": lambda l: _live_targets(cfg, l)}
        if only in live:
            live[only](ledger)
            return ledger.summary("Check passed.", "issue(s) found.")
        checks = [c for c in checks if c[0] == only]
        if not checks:
            U.say(FAIL, f"no check called {only!r}")
            U.bullet("available: " + ", ".join(
                [n for n, _t, _f in registry()] + list(live)))
            return U.EXIT_CANNOT_RUN

    # 1. the static checks
    statuses: dict[str, str] = {}
    for name, title, _fn in checks:
        if name in ("sources", "sample", "own_ip", "targets"):
            continue
        statuses[name] = report(name, cfg, ledger)
        if statuses[name] == FAIL:
            explain_failure(name)

    engine_ok = statuses.get("engine", OK) != FAIL
    if only:
        return ledger.summary("All checks passed.", "issue(s) found.")

    # 2. the live checks
    _live_sources(cfg, ledger)
    _live_baseline(cfg, ledger)
    _live_sample(cfg, ledger, engine_ok)
    _live_own_ip(cfg, ledger)
    _live_targets(cfg, ledger)

    # 3. the report
    try:
        last_run_report(cfg)
    except Exception as e:                               # noqa: BLE001
        U.say(WARN, f"could not read the last run: {e}")

    # 4. the verdict
    rc = ledger.summary(
        "All checks passed. Ready to run `gozar discover`.",
        "issue(s) found. Fix them above and re-run doctor.")
    if rc != U.EXIT_OK and not engine_ok:
        print(f"  {U.bold('Nothing can be tested until the engine exists. One line:')}")
        print("      gozar engine install    (or: pip install sing-box-bin)\n")
    return rc


# ── the live checks ─────────────────────────────────────────────────────────

def _live_sources(cfg, ledger) -> None:
    U.note("Checking source reachability...")
    try:
        results = asyncio.run(_check_sources())
    except Exception as e:                               # noqa: BLE001
        ledger.check(WARN, f"could not check sources: {e}")
        return
    for tier, (good, total, down) in results.items():
        if good == total:
            ledger.check(OK, f"sources [{tier}]: {good}/{total} reachable")
        elif good >= total // 2:
            ledger.check(WARN, f"sources [{tier}]: {good}/{total} reachable "
                               "(partially filtered, ok)")
        else:
            ledger.check(FAIL, f"sources [{tier}]: only {good}/{total} reachable")
        for u in down:
            host = u.split("/")[2] if "/" in u else u
            repo = "/".join(u.split("/")[3:5])
            print(f"      {U.dim(f'✗ filtered/down: {host}/{repo}')}")


def _live_baseline(cfg, ledger) -> None:
    U.note("Measuring baseline ping...")
    try:
        from .checker import measure_baseline, describe_baseline
        bi = asyncio.run(measure_baseline(
            cfg.get("baseline_hosts", ["1.1.1.1:443", "8.8.8.8:443"])))
    except Exception as e:                               # noqa: BLE001
        ledger.check(WARN, f"could not measure baseline ping: {e}")
        return
    if bi.get("baseline_ms") is not None:
        ledger.check(OK, describe_baseline(bi["baseline_ms"], cfg))
    else:
        ledger.check(WARN, "could not measure baseline ping (offline?); "
                           "using lenient threshold")


def _live_sample(cfg, ledger, engine_ok: bool) -> None:
    if not engine_ok:
        # No engine means no tunnel. Running the sample anyway produced a
        # traceback from deep inside aiohttp (2026-11-27) — a missing binary is
        # a first-class answer, not a crash.
        U.note("Skipping the end-to-end test: no engine to drive it.")
        return
    U.note("Running one end-to-end test (may take ~15s)...")
    try:
        scfg, res = asyncio.run(_sample_test())
    except Exception as e:                               # noqa: BLE001
        ledger.check(WARN, f"sample test crashed: {type(e).__name__}: {e}")
        return
    if scfg and res and res.get("alive"):
        proof = ""
        if res.get("exit_verified"):
            proof = (f" exit={res.get('exit_ip')}"
                     + (f" ({res.get('exit_loc')})" if res.get("exit_loc") else "")
                     + " — tunnel PROVEN")
        elif res.get("leak"):
            proof = " LEAK: exit IP == your own line!"
        else:
            proof = " exit=unverified (no exit-IP proof)"
        ledger.check(OK, f"sample config works: {scfg['type']} {scfg['server']} "
                         f"latency={res.get('latency')}ms "
                         f"target_ok={res.get('target_ok')}{proof}")
        return
    if res and "error" in res:
        # "the install is broken" vs "the free pool is flaky": if every attempt
        # failed the SAME way it is the line or the engine; if they differ it is
        # just a bad sample.
        tried = res.get("tried") or 0
        errs = res.get("errors") or []
        same = len({e[:40] for e in errs}) == 1 if errs else False
        ledger.check(WARN, f"sample test: {tried} attempt(s) failed — {res['error']}")
        if same and tried >= 3:
            ledger.check(WARN, "  all attempts failed the SAME way — that points at "
                               "the line or the engine, not the pool "
                               "(`gozar calibrate`, `gozar doctor`)")
        else:
            ledger.check(WARN, "  failures differ — normal for free nodes; "
                               "`gozar discover` tests many more")
        return
    ledger.check(WARN, "no working sample found in the first 3 measured sources "
                       "(can still work; run discover to test more)")


def _live_own_ip(cfg, ledger) -> None:
    U.note("Reading your own public IP (tunnel-proof baseline)...")
    try:
        from .checker import measure_own_ip, EXIT_PROBE_URLS
        own, loc = asyncio.run(measure_own_ip(
            list(cfg.get("exit_probe_urls") or EXIT_PROBE_URLS)))
    except Exception as e:                               # noqa: BLE001
        ledger.check(WARN, f"tunnel-proof baseline failed: {e}")
        return
    if not own:
        ledger.check(WARN, "could not read your own public IP — leak detection "
                           "will be disabled (all exit-IP probes unreachable?)")
        return
    if cfg.get("verify_exit_ip", True):
        ledger.check(OK, f"your line IP = {own}" + (f" ({loc})" if loc else "")
                         + " — nodes exiting from this IP are rejected as leaks")
    else:
        ledger.check(WARN, f"your line IP = {own}, but verify_exit_ip is OFF: a 2xx "
                           "answer no longer proves traffic crossed the node")


def _live_targets(cfg, ledger) -> None:
    """Probe the targets with NO proxy: how filtered does this line look?"""
    targets = cfg.get("targets") or []
    if not targets:
        return
    U.note("Checking targets directly (no proxy)...")
    try:
        import aiohttp
        import time as _t
        from .core_runner import DEFAULT_UA
    except Exception as e:                               # noqa: BLE001
        ledger.check(WARN, f"could not probe targets: {e}")
        return

    async def probe_all():
        hdrs = {"User-Agent": DEFAULT_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9"}
        async with aiohttp.ClientSession(headers=hdrs) as s:
            for u in targets:
                t0 = _t.monotonic()
                try:
                    async with s.get(u, timeout=aiohttp.ClientTimeout(total=10),
                                     allow_redirects=True) as r:
                        dt = int((_t.monotonic() - t0) * 1000)
                        if r.status < 400:
                            ledger.check(OK, f"target {u} → HTTP {r.status} in {dt}ms")
                            if r.headers.get("server", "").lower() == "cloudflare":
                                # prove the point users keep tripping on: the SAME
                                # url answers 403 to a bare curl
                                try:
                                    async with s.get(
                                            u, timeout=aiohttp.ClientTimeout(total=10),
                                            headers={"User-Agent": "curl/8.5.0"},
                                            allow_redirects=True) as r2:
                                        if r2.status >= 400:
                                            print(f"      {U.dim(f'[note] behind '
                                                  f'Cloudflare: the same URL answers '
                                                  f'HTTP {r2.status} to a bare '
                                                  f'curl. That is a bot rule on the '
                                                  f'User-Agent, NOT a broken node.')}")
                                except Exception:        # noqa: BLE001
                                    pass
                        else:
                            ledger.check(WARN, f"target {u} → HTTP {r.status} "
                                               "without a proxy (filtered?)")
                except Exception as e:                   # noqa: BLE001
                    ledger.check(WARN, f"target {u} unreachable directly: "
                                       f"{type(e).__name__}")

    asyncio.run(probe_all())
