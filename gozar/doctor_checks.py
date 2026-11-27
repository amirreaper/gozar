"""doctor_checks — every check `gozar doctor` makes, as a plain function.

A check is a function of its inputs that returns one of three words:

    ok("sing-box 1.14.5")                       -> (OK, "sing-box 1.14.5")
    warn("ulimit -n is 512; ...")               -> (WARN, "ulimit ...")
    fail("sing-box not found — ...")            -> (FAIL, "sing-box ...")

No printing, no counters, no shared state. That means:

  * each check can be run on its own from a test (`checks.run("engine")`);
  * the reporting style is decided in one place (core_ui), not in each check;
  * adding a check is adding one function + one registry line;
  * `gozar doctor --only engine` and the full run share the same code path.

The registry at the bottom is the order a user sees. `engine` is special: it is
a *gate*. When it fails the tunnel checks cannot mean anything, so the runner
skips them and says why instead of producing a misleading verdict.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import core_ui as U
from .core_ui import FAIL, OK, WARN

# A check is: name -> (title, callable(cfg) -> (status, message))
_REGISTRY: list[tuple[str, str, object]] = []


def ok(msg: str):
    return (OK, msg)


def warn(msg: str):
    return (WARN, msg)


def fail(msg: str):
    return (FAIL, msg)


def check(name: str, title: str):
    """Register a check. The decorator keeps the list and the code together."""
    def _add(fn):
        _REGISTRY.append((name, title, fn))
        return fn
    return _add


def registry() -> list[tuple[str, str, object]]:
    return list(_REGISTRY)


def names() -> list[str]:
    return [n for n, _t, _f in _REGISTRY]


def run(name: str, cfg: dict):
    """Run one check by name. Returns (status, message) — never raises."""
    for n, _t, fn in _REGISTRY:
        if n == name:
            try:
                return fn(cfg)
            except Exception as e:                        # noqa: BLE001
                return fail(f"{name}: check crashed — {type(e).__name__}: {e}")
    return fail(f"no such check: {name}")


# ── the checks, in the order a user reads them ──────────────────────────────

@check("python", "Python version")
def python_check(cfg: dict):
    py = sys.version_info
    if py >= (3, 10):
        return ok(f"Python {py.major}.{py.minor}.{py.micro}")
    return fail(f"Python {py.major}.{py.minor} is too old; need 3.10+")


@check("packages", "Python packages")
def packages_check(cfg: dict):
    try:
        import aiohttp  # noqa: F401
    except ImportError as e:
        return fail(f"Missing package: {e}. Run: pip install -r requirements.txt")
    try:
        import aiohttp_socks  # noqa: F401
        return ok("Python packages (aiohttp, aiohttp-socks)")
    except ImportError:
        return ok("Python packages (aiohttp; using built-in HTTP mixed proxy fallback)")


@check("engine", "sing-box engine")
def engine_check(cfg: dict):
    """Ask the SAME resolver the runner uses.

    env override -> gozar engines dir -> pip sing-box-bin -> ./engines -> PATH.
    A second hand-rolled check here reported a Nix/brew install as MISSING while
    the runner was happily using it (2026-11-15), so there is exactly one
    resolver and doctor calls it.
    """
    from .engines import find_binary, first_version_line, source_of
    sb = find_binary("sing-box")
    if not (sb and Path(sb).exists()):
        return fail("sing-box not found — it does the real testing, "
                    "nothing runs without it")
    v = first_version_line(sb)
    if v:
        return ok(f"sing-box ({source_of(sb)}): {sb} [{v}]")
    return warn(f"sing-box ({source_of(sb)}): {sb} — it exists but did not answer "
                "`version`; the download may be corrupt (re-run "
                "`gozar engine install --reinstall`)")


@check("limits", "file descriptors")
def limits_check(cfg: dict):
    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except Exception:                                    # noqa: BLE001
        return ok("could not read ulimit (not fatal)")
    if soft >= 1024:
        return ok(f"ulimit -n: {soft}")
    return warn(f"ulimit -n is {soft}; run `ulimit -n 4096` for high concurrency")


@check("data", "data directory")
def data_check(cfg: dict):
    data_dir = Path(cfg.get("data_dir") or "data")
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        probe = data_dir / ".write_test"
        probe.write_text("ok")
        probe.unlink()
    except Exception as e:                               # noqa: BLE001
        return fail(f"Cannot write to {data_dir}: {e}")
    return ok(f"data dir writable: {data_dir}")


@check("root", "privileges")
def root_check(cfg: dict):
    try:
        root = os.geteuid() == 0
    except AttributeError:                               # non-POSIX
        return warn("cannot tell whether this is root; TUN mode may not work")
    if root:
        return ok("running as root (TUN mode available)")
    return warn("not running as root — sudo is ONLY needed for --mode tun "
                "(proxy mode works fine unprivileged)")


# ── the reporting half ───────────────────────────────────────────────────────

def report(name: str, cfg: dict, ledger: U.Ledger) -> str:
    """Run one check and print it. Returns the status so callers can gate."""
    status, message = run(name, cfg)
    ledger.check(status, message)
    return status


def explain_failure(name: str) -> None:
    """The short 'do this next' block for a failed check. Never a wall of text."""
    if name == "engine":
        from .engines import INSTALL_HINTS
        U.hints(INSTALL_HINTS.splitlines())
    elif name == "packages":
        U.hints(["pip install aiohttp aiohttp-socks",
                 "or, from a clone:  pip install -r requirements.txt"])
    elif name == "data":
        U.hints(["pick a writable place:  GOZAR_DATA_DIR=$HOME/.gozar gozar doctor"])


def last_run_report(cfg: dict) -> None:
    """Pools, stages and rejection reasons from the last discover/check run.

    This is the part that turns "0 alive" from a mystery into an answer: it
    shows where the candidates died, and whether one reason explains everything
    (a line problem) or the failures are spread out (a pool problem).
    """
    data = Path(cfg.get("data_dir") or "data")
    meta_p = data / "meta.json"
    state_p = data / "state.json"
    state = {}
    if state_p.exists():
        try:
            state = json.loads(state_p.read_text(encoding="utf-8"))
        except Exception:                                # noqa: BLE001
            state = {}
    recs = list(state.values())

    U.rule("last run: where the candidates went")
    if not recs:
        U.say(WARN, "no state yet — run `gozar discover` once")
        return

    from collections import Counter
    reasons: Counter = Counter()
    for r in recs:
        if r.get("alive_now"):
            continue
        reasons[classify_error(r.get("last_error") or "unknown")] += 1

    alive = sum(1 for r in recs if r.get("alive_now"))
    tok = sum(1 for r in recs if r.get("alive_now") and r.get("target_ok_now") is True)
    print(f"  stored nodes: {len(recs)}   alive: {alive}   target-OK: {tok}")
    if not reasons:
        print("  nothing was rejected.")
    else:
        print("  rejected, by reason:")
        for k, n in reasons.most_common(8):
            share = 100.0 * n / max(1, len(recs) - alive)
            print(f"    {n:5d}  ({share:4.1f}%)  {k}")
        dead = max(1, len(recs) - alive)
        top, n = reasons.most_common(1)[0]
        if n / dead >= 0.75 and alive == 0:
            U.say(WARN, f"[like the line, not the pool] one reason explains "
                         f"{100 * n / dead:.0f}% of the failures and nothing came "
                         "alive. A pool of 1000 nodes never behaves that uniformly "
                         "— check the line first: `gozar calibrate`, then re-run "
                         "with --no-probe, and try a mobile hotspot.")
        elif len(reasons) >= 3 and alive == 0:
            U.say(WARN, "[like a washout] failures are spread over several reasons "
                        "— this looks like a filtered line rather than bad links. "
                        "See docs/IRAN-LINES.md for what each carrier filters.")

    if meta_p.exists():
        try:
            meta = json.loads(meta_p.read_text(encoding="utf-8"))
        except Exception:                                # noqa: BLE001
            return
        pools = meta.get("pools") or {}
        if pools:
            print("  pools: unique -> raw -> reachable(TCP) -> actually tested")
            for name, p in sorted(pools.items()):
                print(f"    {name:<12} {p.get('parsed', 0):5d} -> "
                      f"{p.get('links', 0):5d} -> {p.get('reachable', 0):5d} -> "
                      f"{p.get('tested', 0):5d}")
        if meta.get("probe_sample"):
            print(f"  pre-filter: {meta['probe_sample']}")


def classify_error(err: str) -> str:
    """Turn a raw engine error into one human sentence. Order matters.

    A parse error also mentions a URL and a TLS error also mentions a host, so
    the most specific test has to run first — that is why this is a list of
    (predicate, label) and not an if/elif chain buried in a loop.
    """
    low = (err or "unknown").strip().lower()
    rules = [
        (lambda s: "decode config" in s or "unknown field" in s
         or "invalid config" in s,
         "engine rejected the config (parse/format) — fixable in the pool"),
        (lambda s: "restricted" in s or "protocol not supported" in s,
         "endpoint refused this protocol/key (restricted)"),
        (lambda s: "page" in s or "dns" in s,
         "echo answered but no page/DNS came through (dead or filtered mid-way)"),
        (lambda s: any(k in s for k in ("wrong version", "reset", "eof",
                                        "handshake", "ssl"))
         and "cannot connect" not in s,
         "connection reset / TLS handshake refused (typical of filtering)"),
        (lambda s: any(k in s for k in ("cannot connect", "timeout", "timed out",
                                        "refused")),
         "could not connect at all (TCP timeout / no route)"),
        (lambda s: "exit ip" in s or "leak" in s,
         "traffic did not cross the node (exit-IP proof failed)"),
    ]
    for pred, label in rules:
        if pred(low):
            return label
    return err[:70]
