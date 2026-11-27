"""Self-diagnostic command: checks that everything is set up correctly."""
from __future__ import annotations
import asyncio
import os
import shutil
import socket
import json
import sys
from pathlib import Path


def _ok(msg):
    print(f"  \033[32m[OK]\033[0m {msg}")


def _warn(msg):
    print(f"  \033[33m[WARN]\033[0m {msg}")


def _fail(msg):
    print(f"  \033[31m[FAIL]\033[0m {msg}")


async def _check_sources(timeout=8):
    """Check how many source URLs are reachable, and name the ones that are
    not — on a filtered line this is normal, we just want the user to know
    which ones are being cut so the cascade design does its job."""
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
                except Exception:
                    return (False, u)
            checks = await asyncio.gather(*(head(u) for u in urls))
            ok = sum(1 for good, _ in checks if good)
            down = [u for good, u in checks if not good]
            results[tier] = (ok, len(urls), down)
    return results


async def _sample_test():
    """Try a handful of configs from trusted sources until one connects.

    A single 'SOCKS server failure' is not fatal - free nodes are flaky,
    so we test up to 5 candidates before warning.
    """
    import aiohttp
    from . import core_parser as parser
    from . import core_runner as runner
    from .core_sources import TRUSTED_SOURCES
    headers = {"User-Agent": "Mozilla/5.0"}
    to = aiohttp.ClientTimeout(total=15)
    candidates = []
    try:
        async with aiohttp.ClientSession(headers=headers, timeout=to) as s:
            for url in TRUSTED_SOURCES[:3]:
                try:
                    async with s.get(url) as r:
                        if r.status != 200:
                            continue
                        text = await r.text(errors="ignore")
                except Exception:
                    continue
                for line in text.splitlines():
                    line = line.strip()
                    if "://" not in line:
                        continue
                    cfg = parser.parse(line)
                    if cfg and cfg["type"] in ("vless", "hysteria2", "anytls"):
                        candidates.append(cfg)
                        if len(candidates) >= 8:
                            break
                if len(candidates) >= 8:
                    break
    except Exception as e:
        return None, {"error": f"fetch failed: {e}"}

    from .checker import tcp_ping
    for c in candidates:
        c["_p"] = await tcp_ping(c["server"], c["server_port"], 2.0)
    candidates = [c for c in candidates if c.get("_p") is not None]
    candidates.sort(key=lambda c: c["_p"])

    last_err = None
    # try up to 8, not 5: on a filtered line the first few are expected to die,
    # and "sample test error" from a five-node sample says nothing about the
    # install. Each attempt is also reported, so a total failure is explained
    # node by node instead of as one mysterious verdict.
    errs = []
    for cfg in candidates[:8]:
        try:
            from .checker import EXIT_PROBE_URLS, measure_own_ip
            own_ip = getattr(_sample_test, "_own_ip", None)
            if own_ip is None:
                own_ip, _loc = await measure_own_ip()
                _sample_test._own_ip = own_ip
            res = await runner.test_config(
                cfg,
                echo_url="https://www.google.com/generate_204",
                target_url="https://www.gstatic.com/generate_204",
                timeout=6, target_timeout=8, startup=0.8,
                exit_urls=list(EXIT_PROBE_URLS), own_ip=own_ip,
                verify_exit=True)
            if res.get("alive") and res.get("target_ok"):
                return cfg, res
            last_err = res.get("error") or "alive=false"
            errs.append(last_err)
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
            errs.append(last_err)
    return None, {"error": last_err or "no configs in trusted sources",
                  "tried": len(candidates[:8]), "errors": errs}


def _print_last_run_report(cfg) -> None:
    """Pools, stages and rejection reasons from the last discover/check run."""
    data = Path(cfg.get("data_dir") or "data")
    meta_p = data / "meta.json"
    state_p = data / "state.json"
    state = {}
    if state_p.exists():
        try:
            state = json.loads(state_p.read_text(encoding="utf-8"))
        except Exception:                              # noqa: BLE001
            state = {}
    recs = list(state.values())

    print("\n=== last run: where the candidates went ===")
    if not recs:
        _warn("no state yet — run `bot discover` once")
        return

    from collections import Counter
    reasons = Counter()
    for r in recs:
        if r.get("alive_now"):
            continue
        err = (r.get("last_error") or "unknown").strip()
        low = err.lower()
        # order matters: a parse error also mentions a URL, a TLS error also
        # mentions a host. Most specific test first.
        if "decode config" in low or "unknown field" in low or "invalid config" in low:
            key = "engine rejected the config (parse/format) — fixable in the pool"
        elif "restricted" in low or "protocol not supported" in low:
            key = "endpoint refused this protocol/key (restricted)"
        elif "page" in low or "dns" in low:
            key = "echo answered but no page/DNS came through (dead or filtered mid-way)"
        elif "wrong version" in low or "reset" in low or "eof" in low \
                or "handshake" in low or "ssl" in low and "cannot connect" not in low:
            key = "connection reset / TLS handshake refused (typical of filtering)"
        elif "cannot connect" in low or "timeout" in low or "timed out" in low \
                or "refused" in low:
            key = "could not connect at all (TCP timeout / no route)"
        elif "exit ip" in low or "leak" in low:
            key = "traffic did not cross the node (exit-IP proof failed)"
        else:
            key = err[:70]
        reasons[key] += 1
    alive = sum(1 for r in recs if r.get("alive_now"))
    tok = sum(1 for r in recs if r.get("alive_now") and r.get("target_ok_now") is True)
    print(f"  stored nodes: {len(recs)}   alive: {alive}   target-OK: {tok}")
    if reasons:
        print("  rejected, by reason:")
        for k, n in reasons.most_common(8):
            share = 100.0 * n / max(1, len(recs) - alive)
            print(f"    {n:5d}  ({share:4.1f}%)  {k}")

        # the honest interpretation: one dominant reason is a LINE problem,
        # a long tail of different reasons is a POOL problem.
        top, n = reasons.most_common(1)[0]
        dead = max(1, len(recs) - alive)
        if n / dead >= 0.75 and alive == 0:
            print("  \033[33m[like the line, not the pool]\033[0m one reason explains "
                  f"{100*n/dead:.0f}% of the failures and nothing came alive. "
                  "A pool of 1000 nodes never behaves that uniformly — check the "
                  "line first: `bot calibrate`, then re-run with --no-probe, "
                  "and try a mobile hotspot on another carrier.")
        elif len(reasons) >= 3 and alive == 0:
            print("  \033[33m[like a washout]\033[0m failures are spread over several "
                  "reasons — this looks like a filtered line rather than bad links. "
                  "See docs/IRAN-LINES.md for what each carrier filters.")
    if meta_p.exists():
        try:
            meta = json.loads(meta_p.read_text(encoding="utf-8"))
            pools = meta.get("pools") or {}
            if pools:
                print("  pools: unique -> raw -> reachable(TCP) -> actually tested")
                for name, p in sorted(pools.items()):
                    print(f"    {name:<12} {p.get('parsed', 0):5d} -> "
                          f"{p.get('links', 0):5d} -> {p.get('reachable', 0):5d} -> "
                          f"{p.get('tested', 0):5d}")
            if meta.get("probe_sample"):
                print(f"  pre-filter: {meta['probe_sample']}")
        except Exception:                              # noqa: BLE001
            pass


def run_doctor(cfg):
    print("\n=== bot doctor ===")
    issues = 0

    # 1. Python
    py = sys.version_info
    if py >= (3, 10):
        _ok(f"Python {py.major}.{py.minor}.{py.micro}")
    else:
        _fail(f"Python {py.major}.{py.minor} is too old; need 3.10+")
        issues += 1

    # 2. Packages
    try:
        import aiohttp  # noqa
        try:
            import aiohttp_socks  # noqa
            _ok("Python packages (aiohttp, aiohttp-socks)")
        except ImportError:
            _ok("Python packages (aiohttp; using built-in HTTP mixed proxy fallback)")
    except ImportError as e:
        _fail(f"Missing package: {e}. Run: pip install -r requirements.txt")
        issues += 1

    # 3. sing-box
    # Resolve exactly the way the runner will: engines/ -> $SINGBOX_BIN /
    # $RAHYAB_SINGBOX -> PATH -> common dirs. Checking one path while the
    # runner uses another is how a working install gets reported as MISSING
    # (a Nix profile path is neither the bundled engines/ dir nor on PATH).
    from .engines import find_binary
    _sb = find_binary("sing-box")
    if _sb and Path(_sb).exists():
        _bundled = str(_sb).startswith(str(Path(__file__).resolve().parent.parent))
        _ok(f"sing-box{'' if _bundled else ' (system)'}: {_sb}")
        try:
            import subprocess
            v = subprocess.run([str(_sb), "version"], capture_output=True,
                               text=True, timeout=5).stdout.strip().splitlines()
            if v:
                _ok(f"sing-box version: {v[0]}")
        except Exception:
            pass
    else:
        _fail("sing-box not found. Run: bash install.sh "
              "(or set SINGBOX_BIN=/path/to/sing-box)")
        issues += 1

    # 4. ulimit
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft >= 1024:
            _ok(f"ulimit -n: {soft}")
        else:
            _warn(f"ulimit -n is {soft}; run `ulimit -n 4096` for high concurrency")
    except Exception:
        pass

    # 5. Data dir writable
    data_dir = Path(cfg.get("data_dir", "data"))
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        test_file = data_dir / ".write_test"
        test_file.write_text("ok")
        test_file.unlink()
        _ok(f"data dir writable: {data_dir}")
    except Exception as e:
        _fail(f"Cannot write to {data_dir}: {e}")
        issues += 1

    # 6. Root (only for TUN)
    if os.geteuid() == 0:
        _ok("running as root (TUN mode available)")
    else:
        _warn("not running as root — sudo is ONLY needed for --mode tun "
              "(proxy mode works fine unprivileged)")

    # 7. Sources
    print("\n  Checking source reachability...")
    try:
        results = asyncio.run(_check_sources())
        for tier, (ok, total, down) in results.items():
            if ok == total:
                _ok(f"sources [{tier}]: {ok}/{total} reachable")
            elif ok >= total // 2:
                _warn(f"sources [{tier}]: {ok}/{total} reachable (partially filtered, ok)")
            else:
                _fail(f"sources [{tier}]: only {ok}/{total} reachable")
                issues += 1
            # Name the cut sources explicitly — informational, never fatal.
            for u in down:
                host = u.split("/")[2] if "/" in u else u
                repo = "/".join(u.split("/")[3:5])
                print(f"      \033[90m✗ filtered/down: {host}/{repo}\033[0m")
    except Exception as e:
        _warn(f"could not check sources: {e}")

    # 8. Baseline ping
    print("\n  Measuring baseline ping...")
    from .checker import measure_baseline, describe_baseline
    bi = asyncio.run(measure_baseline(cfg.get("baseline_hosts",
        ["1.1.1.1:443", "8.8.8.8:443"])))
    if bi["baseline_ms"] is not None:
        _ok(describe_baseline(bi["baseline_ms"], cfg))
    else:
        _warn("could not measure baseline ping (offline?); using lenient threshold")

    # 9. End-to-end sample
    print("\n  Running one end-to-end test (may take ~15s)...")
    scfg, res = asyncio.run(_sample_test())
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
        _ok(f"sample config works: {scfg['type']} {scfg['server']} "
            f"latency={res.get('latency')}ms target_ok={res.get('target_ok')}{proof}")
    elif res and "error" in res:
        # Distinguish "the install is broken" from "the free pool is flaky":
        # if every attempt failed the same way it is the line or the engine,
        # if they failed in different ways it is just a bad sample.
        tried = res.get("tried") or 0
        errs = res.get("errors") or []
        same = len(set(e[:40] for e in errs)) == 1 if errs else False
        _warn(f"sample test: {tried} attempt(s) failed — {res['error']}")
        if same and tried >= 3:
            _warn("  all attempts failed the SAME way — that points at the line "
                  "or the engine, not the pool (`bot calibrate`, `bot doctor`)")
        else:
            _warn("  failures differ — normal for free nodes; `bot discover` "
                  "tests many more")
    else:
        _warn("no working sample found in the first 3 measured sources "
              "(can still work; run discover to test more)")

    # 8b. Tunnel-proof baseline (own public IP, read directly — no proxy)
    print("\n  Reading your own public IP (tunnel-proof baseline)...")
    try:
        from .checker import measure_own_ip, EXIT_PROBE_URLS
        _own, _oloc = asyncio.run(measure_own_ip(
            list(cfg.get("exit_probe_urls") or EXIT_PROBE_URLS)))
        if _own:
            if cfg.get("verify_exit_ip", True):
                _ok(f"your line IP = {_own}" + (f" ({_oloc})" if _oloc else "")
                    + " — nodes exiting from this IP are rejected as leaks")
            else:
                _warn(f"your line IP = {_own}, but verify_exit_ip is OFF: a 2xx "
                      f"answer no longer proves traffic crossed the node")
        else:
            _warn("could not read your own public IP — leak detection will be "
                  "disabled (all exit-IP probes unreachable on this line?)")
            issues += 1
    except Exception as e:  # noqa: BLE001
        _warn(f"tunnel-proof baseline failed: {e}")

    # 9. Direct target probe (no proxy) — shows how filtered/healthy each
    # target looks on THIS line before any node testing happens.
    targets = cfg.get("targets", []) or []
    if targets:
        print("\n  Checking targets directly (no proxy)...")
        try:
            import aiohttp as _aio
            import time as _t
            from .core_runner import DEFAULT_UA
            async def _probe_all():
                hdrs = {
                    "User-Agent": DEFAULT_UA,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                }
                async with _aio.ClientSession(headers=hdrs) as _s:
                    for u in targets:
                        t0 = _t.monotonic()
                        try:
                            async with _s.get(
                                    u, timeout=_aio.ClientTimeout(total=10),
                                    allow_redirects=True) as r:
                                dt = int((_t.monotonic() - t0) * 1000)
                                if r.status < 400:
                                    _ok(f"target {u} → HTTP {r.status} in {dt}ms")
                                    if (r.headers.get("server", "").lower()
                                            == "cloudflare"):
                                        # prove the point users keep tripping on:
                                        # the SAME url answers 403 to a bare curl
                                        try:
                                            async with _s.get(
                                                    u, timeout=_aio.ClientTimeout(total=10),
                                                    headers={"User-Agent": "curl/8.5.0"},
                                                    allow_redirects=True) as r2:
                                                if r2.status >= 400:
                                                    print(f"      \033[90m[note] behind "
                                                          f"Cloudflare: the same URL answers "
                                                          f"HTTP {r2.status} to a bare "
                                                          f"`curl` (cf-mitigated="
                                                          f"{r2.headers.get('cf-mitigated')}). "
                                                          f"That is a bot rule on the "
                                                          f"User-Agent, NOT a broken node — "
                                                          f"test with `bot verify` or "
                                                          f"curl -A <browser UA>.\033[0m")
                                        except Exception:  # noqa: BLE001
                                            pass
                                else:
                                    _warn(f"target {u} → HTTP {r.status} in {dt}ms")
                        except Exception as _e:
                            _warn(f"target {u} → unreachable ({str(_e)[:60]})")
            asyncio.run(_probe_all())
        except Exception as e:  # noqa: BLE001
            _warn(f"could not probe targets: {e}")

    if "anytls" in (cfg.get("protocols") or []):
        print("  \033[90m[note] anytls is parsed + testable, but no public source "
              "publishes it today — it will simply yield 0 nodes until one does.\033[0m")

    # ── last run: where did the candidates go? ───────────────────────────────
    # "1000 nodes tested, none alive" is impossible to debug without this
    # breakdown: a dead line, a DPI wall and a bad pool all look the same.
    try:
        _print_last_run_report(cfg)
    except Exception as e:                             # noqa: BLE001
        _warn(f"could not summarise the last run: {e}")

    print("\n=== summary ===")
    if issues == 0:
        print("  \033[32mAll checks passed. Ready to run `./bot discover`.\033[0m\n")
    else:
        print(f"  \033[31m{issues} issue(s) found. Fix them above and re-run doctor.\033[0m\n")
    return issues
