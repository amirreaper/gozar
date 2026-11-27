"""Discover and check cycles with tiered cascade fetching."""
from __future__ import annotations
import asyncio
import logging
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

import aiohttp

from . import core_output as output
from . import core_parser as parser
from . import core_runner as runner
from . import core_store as store
from . import display
from .checker import (measure_baseline, compute_fast_threshold,
                      describe_baseline, tcp_ping, udp_quic_ping,
                      is_cloudflare, port_is_safe, sni_is_open, load_open_sni,
                      measure_own_ip, EXIT_PROBE_URLS)
from .core_sources import (PROTOCOL_SOURCES, mirrors_for, tiers_with,
                           rank_sources, update_source_stats)

log = logging.getLogger("core.test")

# data_dir for the breaker journal — set by cmd_discover/cmd_check
data_dir_hint = [None]


# A CancelledError raised when the user hits Ctrl+C. We use this flag so
# callers know testing stopped early but partial results should be saved.
INTERRUPTED = False

# per-run pool accounting: how many links each tier yielded, parsed and how many
# actually reached the test. This is what turns "1000 candidates, none alive"
# into a readable funnel instead of a mystery.
POOLS: dict[str, dict] = {}


def _pool(name: str, **adds) -> None:
    d = POOLS.setdefault(name, {"links": 0, "parsed": 0, "tested": 0})
    for k, v in adds.items():
        d[k] = d.get(k, 0) + v


INTERRUPTED = False


async def _fetch_text(session, url):
    """Fetch one URL, trying GitHub mirrors if the primary fails.

    An unreachable source is NOT an error — it is a normal condition in a
    censored network. We report it quietly and move on (skip, never crash).
    Chain: plain fetch -> jsdelivr/ghfast mirrors of the same file. If every
    candidate fails the source is simply skipped; nothing else is tried.
    """
    last_err = None
    for idx, candidate in enumerate(mirrors_for(url)):
        try:
            async with session.get(candidate) as r:
                if r.status == 200:
                    return await r.text(errors="ignore")
                last_err = f"HTTP {r.status}"
                if idx == 0 and r.status == 404:
                    # Deleted repo/file on GitHub — don't waste time on mirrors
                    return ""
        except Exception as e:  # noqa: BLE001
            last_err = str(e)[:80]
            continue
    if last_err:
        log.debug("source unreachable after mirrors: %s (%s)", url[:70], last_err)
    return ""

# Pre-filter switch. The TCP/QUIC probe is purely an optimisation: it throws
# away candidates whose port never answers so sing-box does not have to start
# for them. `--no-probe` disables it (see docs/PERF.md: it is FASTER on a good
# line and SLOWER on a filtered one, and it can never change which nodes pass
# the real test — only how many of them get tried).
PROBE_ENABLED = [True]
# "auto" (default): decide per run from a 250-candidate sample — see probe().
# "on" = always pre-filter, "off" = never (--no-probe).
PROBE_MODE = ["auto"]


_VALID_SCHEMES = (
    "vless://", "vmess://", "trojan://", "ss://",
    "hy2://", "hysteria2://", "tuic://", "anytls://",
    # WARP pools ship WireGuard share links; the parser and the engine both
    # handle them, but the extractor used to drop them before they got there.
    "wireguard://", "wg://",
)


def _extract_links(text: str) -> list[str]:
    if not text:
        return []
    import base64
    out: list[str] = []
    b64_chunks: list[str] = []

    def _flush_b64():
        if not b64_chunks:
            return
        joined = "".join(b64_chunks).strip().replace("-", "+").replace("_", "/")
        b64_chunks.clear()
        if not joined:
            return
        try:
            dec = base64.b64decode(joined + "=" * (-len(joined) % 4), validate=False)
            for dl in dec.decode("utf-8", "ignore").splitlines():
                dl = dl.strip()
                if dl.lower().startswith(_VALID_SCHEMES):
                    out.append(dl)
        except Exception:
            pass

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            _flush_b64()
            continue
        if line.lower().startswith(_VALID_SCHEMES):
            _flush_b64()
            out.append(line)
        elif "://" not in line:
            # Try single-line base64 first; if it doesn't yield links, accumulate for multi-line base64
            try:
                s = line.replace("-", "+").replace("_", "/")
                dec = base64.b64decode(s + "=" * (-len(s) % 4), validate=False).decode("utf-8", "ignore")
                found_in_line = [dl.strip() for dl in dec.splitlines()
                                 if dl.strip().lower().startswith(_VALID_SCHEMES)]
                if found_in_line:
                    _flush_b64()
                    out.extend(found_in_line)
                    continue
            except Exception:
                pass
            b64_chunks.append(line)
        else:
            _flush_b64()
    _flush_b64()
    return out


def load_import_files(paths, protocols) -> tuple[list[dict], int]:
    """Read user-provided link files or direct link strings: mixed raw lines
    and/or base64 sub content. Returns (deduped configs, skipped/garbage count)."""
    cfgs, seen, skipped = [], set(), 0
    for item in paths or []:
        if not item or not str(item).strip():
            continue
        s = str(item).strip()
        if s.lower().startswith(_VALID_SCHEMES):
            links = [s]
        else:
            p = Path(s)
            if p.exists() and p.is_file():
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                    links = _extract_links(text)
                except Exception as e:  # noqa: BLE001
                    log.warning("import: cannot read %s: %s", s, e)
                    continue
            else:
                links = _extract_links(s)
                if not links:
                    log.warning("import: '%s' is neither a valid link nor an existing file", s[:80])
                    skipped += 1
                    continue
        for link in links:
            c = parser.parse(link)
            if not c or c["type"] not in protocols:
                skipped += 1
                continue
            k = store.ident(c)
            if k in seen:
                continue
            seen.add(k)
            cfgs.append(c)
    return cfgs, skipped


def collect_user_configs(cfg: dict) -> tuple[list[dict], int]:
    """Gather all user-supplied configs from custom_configs, import_files,
    and any non-HTTP entries placed in domestic_sources."""
    items = []
    for key in ("custom_configs", "import_files", "import-files"):
        val = cfg.get(key)
        if isinstance(val, str):
            items.append(val)
        elif isinstance(val, list):
            items.extend(val)
    for d in cfg.get("domestic_sources") or []:
        if isinstance(d, str) and d.strip() and not d.strip().lower().startswith(("http://", "https://")):
            items.append(d.strip())
    if not items:
        return [], 0
    return load_import_files(items, cfg["protocols"])


def _subnet_key(server: str, prefix: int = 24) -> str:
    """The /24 an IPv4 address belongs to, or the address itself for a v6/name.

    max_per_endpoint counts IP:port pairs, so five ports on ONE host all pass and
    the pool looks diverse while it is a single machine (2026-11-15: 5 of 8
    alive nodes were 82.38.31.180-203:8080). Counting the /24 too is the
    difference between "five nodes" and "one server with five doors".
    """
    s = str(server or "").strip()
    try:
        import ipaddress as _ip
        a = _ip.ip_address(s)
    except ValueError:
        return s.lower()
    if a.version == 4 and prefix < 32:
        net = _ip.ip_network(f"{s}/{prefix}", strict=False)
        return str(net)
    return str(a)


def _dedup_endpoints(cfgs: list[dict], max_per_endpoint: int = 3,
                     max_per_subnet: int = 0, subnet_prefix: int = 24) -> list[dict]:
    """Cap duplicate configs pointing to the exact same (server, server_port, type)
    so spammy public aggregators with 50 copies of the same dead IP:port do not
    choke probing or sing-box testing.

    `max_per_subnet` (0 = off) additionally caps how many candidates one /24 may
    contribute, so a single hosting box cannot fill the pool.
    """
    if (not max_per_endpoint or max_per_endpoint <= 0) and not max_per_subnet:
        return cfgs
    counts: dict[tuple, int] = defaultdict(int)
    subnets: dict[str, int] = defaultdict(int)
    out: list[dict] = []
    for c in cfgs:
        ep = (c.get("type", ""), str(c.get("server", "")).lower(), int(c.get("server_port") or 0))
        if max_per_endpoint and max_per_endpoint > 0 and counts[ep] >= max_per_endpoint:
            continue
        sk = _subnet_key(c.get("server"), subnet_prefix) if max_per_subnet else ""
        if max_per_subnet and subnets[sk] >= max_per_subnet:
            continue
        counts[ep] += 1
        if max_per_subnet:
            subnets[sk] += 1
        out.append(c)
    return out


# Protocols that actually carry a browser reliably where DPI is aggressive.
# Real-world Iran-style filtering: REALITY/TLS on TCP survives, plain
# vmess/shadowsocks on odd ports usually does not.
UDP_PROTO_NAMES = {"hysteria2", "tuic", "wireguard"}


def node_quality(c: dict, open_sni: set | None = None) -> float:
    """A cheap prior score used only to decide WHICH candidates get tested first.

    It cannot know whether a node works — that is what the real test is for —
    but it can stop a 6000-node vmess flood from consuming the whole test
    budget before one REALITY/TLS node is even tried. Measured facts that feed
    it (measured on real filtered lines):
      • TLS/REALITY on TCP:443 completes under aggressive filtering
      • plain TCP without TLS is trivially fingerprinted
      • non-standard ports get reset
      • plain VMess is the most often blocked family
    """
    score = 0.0
    t = c.get("type")
    tls = c.get("tls") or {}
    tr = c.get("transport") or {}
    if tls.get("reality"):
        score += 40
    elif tls.get("enabled"):
        score += 25
    elif t == "trojan" or t in UDP_PROTO_NAMES:
        score += 15        # trojan is TLS by definition; QUIC carries its own
    try:
        port = int(c.get("server_port") or 0)
    except (TypeError, ValueError):
        port = 0
    if port == 443:
        score += 12
    elif port in (8443, 2083, 2053, 2096):
        score += 6
    elif port in (80, 8080):
        score += 2
    sni = str(tls.get("server_name") or (tr.get("headers") or {}).get("Host") or "")
    if sni:
        score += 5
        if open_sni and sni.lower() in open_sni:
            score += 8
        if sni.lower().endswith(".ir"):
            score += 6
    if tr.get("type") in ("ws", "grpc", "httpupgrade", "http"):
        score += 4
    if t == "vmess":
        score -= 12        # biggest, noisiest, and the most commonly blocked pool
    if t == "shadowsocks":
        score -= 4
    if c.get("flow") == "xtls-rprx-vision":
        score += 6
    if tls.get("insecure"):
        score -= 2
    return score


def _sort_and_interleave(cfgs: list[dict], protocols: list[str],
                         open_sni: set | None = None) -> list[dict]:
    """Test cheap+likely-to-survive candidates FIRST, then interleave protocols.

    Order inside a protocol: (1) node_quality prior, (2) probe_ms. Reason: the
    cascade stops as soon as `best_n` fast nodes are found, so a flood of plain
    VMess on random ports could fill the whole budget while every REALITY node
    stayed untested at the tail of the queue.
    """
    if not cfgs:
        return []
    by_proto: dict[str, list[dict]] = defaultdict(list)
    for c in cfgs:
        by_proto[c.get("type", "")].append(c)
    for lst in by_proto.values():
        lst.sort(key=lambda c: (-node_quality(c, open_sni),
                                c.get("_probe_ms") or 9999))
    order = [p for p in protocols if p in by_proto]
    for p in by_proto:
        if p not in order:
            order.append(p)
    out: list[dict] = []
    idx = 0
    while True:
        added = False
        for p in order:
            lst = by_proto[p]
            if idx < len(lst):
                out.append(lst[idx])
                added = True
        if not added:
            break
        idx += 1
    return out


async def _fetch_sources(session, urls, protocols):
    """Fetch one list of URLs (bounded concurrency=6), parse, return {ident: cfg}."""
    found = {}
    sem = asyncio.Semaphore(6)
    ordered_urls = rank_sources(urls, data_dir_hint[0])

    async def _bounded_fetch(u):
        async with sem:
            return await _fetch_text(session, u)

    texts = await asyncio.gather(*(_bounded_fetch(u) for u in ordered_urls))
    url_stats = {}
    for u, t in zip(ordered_urls, texts):
        if not t:
            host = u.split("/")[2] if "/" in u else u
            log.info("    ✗ source unreachable (filtered/down), skipped: %s", host + "/" + "/".join(u.split("/")[3:5]))
            url_stats[u] = {"reachable": False, "parsed": 0}
    per_proto = defaultdict(int)
    for u, text in zip(ordered_urls, texts):
        if not text:
            continue
        parsed_here = 0
        for link in _extract_links(text):
            cfg = parser.parse(link)
            if not cfg or cfg["type"] not in protocols:
                continue
            parsed_here += 1
            k = store.ident(cfg)
            if k not in found:
                found[k] = cfg
                per_proto[cfg["type"]] += 1
        url_stats[u] = {"reachable": True, "parsed": parsed_here}
    update_source_stats(data_dir_hint[0], url_stats)
    return found, dict(per_proto)


async def gather_configs_cascade(protocols, max_per_proto=0, on_progress=None,
                                 stop_event: asyncio.Event | None = None,
                                 domestic=None, domestic_only: bool = False,
                                 tier_max: int = 0):
    """Fetch tiers one by one. Yields batches of new configs per tier.

    Caller decides whether to continue after testing each batch. Domestic
    (.ir) sources come first when supplied — they are meant to stay up
    during a full international shutdown.

    `tier_max` > 0 samples that many candidates per tier (randomly, so the tail
    of a huge bundle is not starved). The pool is no longer filtered by
    protocol/company/port: a huge tier is bounded by SIZE, and the real test
    alone decides what lives.
    """
    headers = {"User-Agent": "Mozilla/5.0"}
    timeout = aiohttp.ClientTimeout(total=25)
    seen: dict[str, dict] = {}
    tiers = tiers_with(domestic, domestic_only)
    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as s:
        for tier_name, urls in tiers.items():
            if stop_event is not None and stop_event.is_set():
                break
            eff_urls = list(urls)
            if tier_name == "trusted" and "hysteria2" in protocols:
                for hu in PROTOCOL_SOURCES.get("hysteria2", []):
                    if hu not in eff_urls:
                        eff_urls.append(hu)
            # WARP pools publish wireguard share links and nothing else, so the
            # bundle must be fetched explicitly — the tiers only carry what
            # their own pipelines chose to publish.
            if tier_name == "trusted" and "wireguard" in protocols:
                for wu in PROTOCOL_SOURCES.get("wireguard", []):
                    if wu not in eff_urls:
                        eff_urls.append(wu)
            log.info("Fetching tier '%s' (%d sources)...", tier_name, len(eff_urls))
            batch, per_proto = await _fetch_sources(s, eff_urls, protocols)
            new = {k: v for k, v in batch.items() if k not in seen}
            _pool(tier_name, fetched=len(batch), parsed=len(new))
            for k, v in new.items():
                seen[k] = v
            log.info("  tier '%s': %d new configs (%s)",
                     tier_name, len(new), per_proto)
            if on_progress:
                on_progress(tier_name, len(new), len(seen))
            if tier_max and len(new) > tier_max:
                # Sample, do not truncate: GitHub raw serves the file in a stable
                # order, so "the first 1500" would be the same 1500 every run and
                # the tail of the pool would never be tested.
                keys = list(new.keys())
                random.shuffle(keys)
                kept = {k: new[k] for k in keys[:tier_max]}
                log.info("  tier '%s': sampled %d of %d candidates "
                         "(tier_max=%d; raise it or set 0 for everything)",
                         tier_name, len(kept), len(new), tier_max)
                _pool(tier_name, skipped=len(new) - len(kept))
                new = kept
            if max_per_proto:
                by_proto = defaultdict(list)
                for c in new.values():
                    by_proto[c["type"]].append(c)
                capped = {}
                for proto, lst in by_proto.items():
                    random.shuffle(lst)
                    for c in lst[:max_per_proto]:
                        capped[store.ident(c)] = c
                yield tier_name, list(capped.values())
            else:
                yield tier_name, list(new.values())
        if stop_event is None or not stop_event.is_set():
            extra, per_proto = await _fetch_sources(
                s, [u for urls in (PROTOCOL_SOURCES.get(p, []) for p in protocols) for u in urls],
                protocols)
            new = {k: v for k, v in extra.items() if k not in seen}
            if new:
                log.info("Dedicated per-protocol sources: %d new (%s)",
                         len(new), per_proto)
                yield "dedicated", list(new.values())


# Protocols whose data path is UDP/QUIC.
UDP_PROTOCOLS = {"hysteria2", "tuic", "wireguard"}


async def probe(cfgs, concurrency=400, timeout=3.5, pace_ms=0,
                breaker_window=0, breaker_pause_s=0,
                stop_event: asyncio.Event | None = None):
    """TCP-ping + QUIC-UDP-ping 海选 candidates in bounded chunks so large tiers
    stay responsive to Ctrl+C and low on memory."""
    mode = PROBE_MODE[0]
    if mode == "auto" and len(cfgs) > 400:
        # Decide from a representative sample whether the pre-filter is worth it.
        # Open line  -> almost every port answers, so probing only costs seconds
        #               and sing-box has to judge them anyway.
        # Filtered line -> most ports are dead, so probing saves dozens of
        #               useless sing-box starts (the expensive part).
        import random as _rnd
        sample = _rnd.sample(cfgs, min(250, len(cfgs)))
        pairs = await asyncio.gather(
            *(tcp_ping(c["server"], int(c["server_port"]), min(timeout, 2.0))
              for c in sample), return_exceptions=True)
        reach = sum(1 for r in pairs if isinstance(r, float))
        ratio = reach / max(1, len(sample))
        log.info("pre-filter sample: %d/%d ports answered (%.0f%%) — %s",
                 reach, len(sample), 100 * ratio,
                 "skipping probe (line looks open)" if ratio >= 0.80
                 else "probing everything (line looks filtered)")
        if ratio >= 0.80:
            mode = "off"
    if mode == "off":
        # skip the pre-filter entirely: sing-box will decide (and reject) instead
        for c in cfgs:
            c["_probe_ms"] = 0.0
        log.info("pre-filter disabled — sing-box will judge all %d candidates",
                 len(cfgs))
        return list(cfgs)
    import random as _rnd
    sem = asyncio.Semaphore(concurrency)
    from collections import deque
    recent = deque(maxlen=max(1, breaker_window)) if breaker_window else None
    paused_until = [0.0]

    async def one(c):
        if stop_event is not None and stop_event.is_set():
            return c
        if pace_ms:
            await asyncio.sleep(_rnd.uniform(0, pace_ms / 1000.0))
        while True:
            now = time.monotonic()
            if now >= paused_until[0]:
                break
            await asyncio.sleep(0.5)
        async with sem:
            if stop_event is not None and stop_event.is_set():
                return c
            if c.get("type") in UDP_PROTOCOLS:
                ms = await udp_quic_ping(c["server"], c["server_port"], min(timeout, 1.8))
                if ms is None:
                    # Try TCP fallback or keep with low priority so NAT/strict-SNI QUIC hosts still get tested
                    ms = await tcp_ping(c["server"], c["server_port"], min(timeout, 1.5))
                c["_probe_ms"] = ms
            else:
                c["_probe_ms"] = await tcp_ping(c["server"], c["server_port"], timeout)
        if recent is not None and c.get("type") not in UDP_PROTOCOLS:
            recent.append(c["_probe_ms"] is not None)
            if len(recent) == recent.maxlen and not any(recent):
                paused_until[0] = time.monotonic() + breaker_pause_s
                recent.clear()
                log.warning(
                    "probe breaker: %d consecutive failures — pausing %ds "
                    "(line likely rate-limited)",
                    recent.maxlen or breaker_window, breaker_pause_s)
        return c

    chunk_size = 1500
    for i in range(0, len(cfgs), chunk_size):
        if stop_event is not None and stop_event.is_set():
            break
        await asyncio.gather(*(one(c) for c in cfgs[i:i + chunk_size]), return_exceptions=True)

    kept = []
    for c in cfgs:
        if c.get("_probe_ms") is not None:
            kept.append(c)
        elif c.get("type") in UDP_PROTOCOLS and (stop_event is None or not stop_event.is_set()):
            # Survive with a low sort priority instead of dying on the probe.
            c["_probe_ms"] = 9000.0
            kept.append(c)
    return kept


# Per-run tunnel-proof counters (leak = exit IP equals the user's own line IP)
LEAK_STATS = {"leak": 0, "unverified": 0}
# last progress count printed, so one result is not announced twice
_LAST_PROGRESS = [-1]
_MAX_LEAK_LOGS = 5


async def prepare_exit_proof(cfg: dict) -> None:
    """Measure this machine's own public IP (direct, no proxy) once per run.

    It becomes the tunnel-proof baseline: any node whose observed exit IP equals
    it is NOT carrying traffic (transparent interception / direct leak) and gets
    rejected instead of being reported as a healthy fast node.
    """
    LEAK_STATS["leak"] = 0
    LEAK_STATS["unverified"] = 0
    # page proof URLs travel with the config; empty list disables the gate
    cfg["_page_urls"] = [u for u in (cfg.get("page_probe_urls") or []) if u]
    if not cfg.get("verify_exit_ip", True):
        cfg["_own_ip"] = None
        cfg["_exit_urls"] = []
        return
    urls = list(cfg.get("exit_probe_urls") or EXIT_PROBE_URLS)
    cfg["_exit_urls"] = urls
    own_ip, own_loc = await measure_own_ip(urls, timeout=8.0,
                                           ua=cfg.get("user_agent"))
    cfg["_own_ip"] = own_ip
    if own_ip:
        log.info("Tunnel-proof baseline: your own line IP = %s%s — any node "
                 "exiting from this IP is rejected as a leak",
                 own_ip, f" ({own_loc})" if own_loc else "")
    else:
        log.warning("Could not determine your own public IP — exit-IP leak "
                    "verification is DISABLED for this run (nodes are still "
                    "tested, but 'alive' is not proof of tunneling)")


async def test_cfgs(cfgs, cfg_set, on_progress=None, early_stop_fast=0,
                    stop_event: asyncio.Event | None = None, start_fast: int = 0,
                    on_result=None):
    """Test configs with sing-box, batching many nodes per process.
    Calls `on_result(cfg, res)` immediately as each individual node completes so
    state & outputs are persisted incrementally in real time."""
    if not cfgs:
        return [], start_fast
    _LAST_PROGRESS[0] = -1
    concurrency = max(1, int(cfg_set.get("test_concurrency", 12)))
    batch_size = max(1, min(6, int(cfg_set.get("batch_size", 6))))
    worker_n = concurrency if batch_size == 1 else max(1, (concurrency + batch_size - 1) // batch_size)
    sem = asyncio.Semaphore(worker_n)
    results = []
    done = 0
    alive_n = 0
    tok_n = 0
    batch_fast = 0          # fast found inside this batch
    cumulative = start_fast  # fast across all batches so far
    lock = asyncio.Lock()
    queue: asyncio.Queue = asyncio.Queue()
    for c in cfgs:
        queue.put_nowait(c)

    pace_ms = cfg_set.get("test_pace_ms", 0)
    breaker_streak = cfg_set.get("test_breaker_streak", 0)
    batch_stop = asyncio.Event()

    def _should_stop() -> bool:
        return batch_stop.is_set() or (stop_event is not None and stop_event.is_set())

    async def _record_one(c: dict, r: dict):
        nonlocal done, alive_n, tok_n, batch_fast, cumulative
        r["probe_ms"] = c.get("_probe_ms")
        if r.get("leak"):
            LEAK_STATS["leak"] += 1
            if LEAK_STATS["leak"] <= _MAX_LEAK_LOGS:
                log.warning("[LEAK] %s — exit IP %s is your own line: traffic "
                            "never entered the tunnel (rejected)",
                            str(c.get("tag") or c.get("server"))[:40],
                            r.get("exit_ip"))
        elif r.get("alive") and cfg_set.get("verify_exit_ip", True) \
                and cfg_set.get("_own_ip") and not r.get("exit_verified"):
            LEAK_STATS["unverified"] += 1
            if cfg_set.get("strict_exit_proof"):
                # cannot prove the traffic crossed the node -> refuse to publish it
                r["alive"] = False
                r["target_ok"] = False
                r["security"] = "unverified"
                r["error"] = ("exit IP could not be read through this node "
                              "(strict_exit_proof: rejected)")
                if LEAK_STATS["unverified"] <= _MAX_LEAK_LOGS:
                    log.warning("[strict] %s — no exit-IP proof, rejected",
                                str(c.get("tag") or c.get("server"))[:40])
        if cfg_set.get("latency_basis") == "target" and r.get("alive"):
            tl = r.get("target_latency")
            if tl is not None:
                r["echo_latency"] = r.get("latency")
                r["latency"] = tl
        is_fast = (r.get("alive")
                   and r.get("latency") is not None
                   and (not cfg_set.get("target_url") or r.get("target_ok"))
                   and r["latency"] <= cfg_set.get("_fast_thr", 99999))
        async with lock:
            results.append((c, r))
            done += 1
            if r.get("alive"):
                alive_n += 1
                if r.get("target_ok"):
                    tok_n += 1
            if is_fast:
                batch_fast += 1
                cumulative += 1
            if on_result is not None:
                try:
                    on_result(c, r)
                except Exception as e:  # noqa: BLE001
                    log.debug("on_result error: %s", e)
            if on_progress and (done % 10 == 0 or r.get("alive") or done == len(cfgs)):
                # the final node used to print the same line twice (once because
                # it was alive, once because it was last); print each count once
                if done != _LAST_PROGRESS[0]:
                    _LAST_PROGRESS[0] = done
                    on_progress(done, len(cfgs), alive_n, tok_n,
                                batch_fast, cumulative)
            if early_stop_fast and cumulative >= early_stop_fast:
                batch_stop.set()

    async def worker():
        fails_streak = 0
        while True:
            if _should_stop():
                return
            chunk = []
            for _ in range(batch_size):
                try:
                    chunk.append(queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            if not chunk:
                return
            if pace_ms:
                await asyncio.sleep(random.uniform(0, pace_ms / 1000.0))
            async with sem:
                if _should_stop():
                    return
                if batch_size == 1 or len(chunk) == 1:
                    c = chunk[0]
                    try:
                        r = await runner.test_config(
                            c,
                            echo_url=cfg_set["echo_url"],
                            target_url=cfg_set.get("target_url", ""),
                            timeout=cfg_set.get("timeout", 8),
                            target_timeout=cfg_set.get("target_timeout", 12),
                            startup=cfg_set.get("startup_delay", 0.8),
                            verify_ssl=cfg_set.get("verify_ssl", False),
                            exit_urls=cfg_set.get("_exit_urls"),
                            own_ip=cfg_set.get("_own_ip"),
                            verify_exit=cfg_set.get("verify_exit_ip", True),
                            page_urls=cfg_set.get("_page_urls"),
                            shell_target_ok=cfg_set.get("shell_target_ok", True),
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:  # noqa: BLE001
                        r = {"alive": False, "error": f"test error: {e}"}
                    await _record_one(c, r)
                    batch_pairs = [(c, r)]
                else:
                    try:
                        batch_pairs = await runner.test_configs_batch(
                            chunk,
                            echo_url=cfg_set["echo_url"],
                            target_url=cfg_set.get("target_url", ""),
                            timeout=cfg_set.get("timeout", 8),
                            target_timeout=cfg_set.get("target_timeout", 12),
                            startup=cfg_set.get("startup_delay", 0.8),
                            verify_ssl=cfg_set.get("verify_ssl", False),
                            on_one_done=_record_one,
                            stop_check=_should_stop,
                            exit_urls=cfg_set.get("_exit_urls"),
                            own_ip=cfg_set.get("_own_ip"),
                            verify_exit=cfg_set.get("verify_exit_ip", True),
                            page_urls=cfg_set.get("_page_urls"),
                            shell_target_ok=cfg_set.get("shell_target_ok", True),
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:  # noqa: BLE001
                        log.debug("batch test error: %s", e)
                        batch_pairs = []

                if breaker_streak and batch_pairs:
                    if any(r.get("alive") for _, r in batch_pairs):
                        fails_streak = 0
                    else:
                        fails_streak += len(batch_pairs)
                        if fails_streak >= breaker_streak:
                            pause = min(30.0, 2.0 * (fails_streak / breaker_streak))
                            if (fails_streak >= breaker_streak
                                    and (fails_streak - len(batch_pairs)) < breaker_streak):
                                log.warning(
                                    "test breaker: %d consecutive failures — "
                                    "backing off %.1fs (line likely rate-limited)",
                                    fails_streak, pause)
                            await asyncio.sleep(pause)

    workers = [asyncio.create_task(worker()) for _ in range(worker_n)]
    try:
        await asyncio.gather(*workers, return_exceptions=True)
    except asyncio.CancelledError:
        if stop_event is not None:
            stop_event.set()
        for w in workers:
            if not w.done():
                w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        raise
    if on_progress and done != _LAST_PROGRESS[0]:
        # only if the last worker did not already announce this exact count
        _LAST_PROGRESS[0] = done
        on_progress(done, len(cfgs), alive_n, tok_n, batch_fast, cumulative)
    return results, cumulative


def _condition_filter(cfgs, cfg) -> list:
    """Apply the '#-flag' harsh-phase filters, each logged with its keep rate:
      cdn_only   — only Cloudflare-fronted IPs
      safe_ports — only ports the filter is known to leave alone (443/8443/80/2083)
      open_sni   — only nodes whose SNI is in today's open corridor set
    All three default OFF; general behaviour stays broad."""
    out = cfgs
    if cfg.get("cdn_only"):
        out = [c for c in out if is_cloudflare(c.get("server", ""))]
        log.info("filter[cdn]: kept %d/%d (Cloudflare-fronted)", len(out), len(cfgs))
    if cfg.get("safe_ports"):
        n0 = len(out)
        out = [c for c in out if port_is_safe(c)]
        log.info("filter[safe-ports]: kept %d/%d (443/8443/80/2083)", len(out), n0)
    if cfg.get("open_sni"):
        n0 = len(out)
        allow = load_open_sni(cfg.get("data_dir", "data"))
        out = [c for c in out if sni_is_open(c, allow)]
        log.info("filter[open-sni]: kept %d/%d (SNI in today's open set)",
                 len(out), n0)
    return out


def ui_progress(tag, best_n, echo_every=12.0):
    """Progress callback with two skins, chosen by stderr TTY-ness:
      - TTY  : single live status line rewritten in place (\r), throttled to
               ~4 fps; completion breaks the line so history stays clean.
      - pipe : heartbeat line every 25 done OR every `echo_every` seconds OR
               on completion (nothing ever stays silent)."""
    t0 = time.monotonic()
    last = [t0]
    tty = sys.stderr.isatty()

    if tty:
        def cb(d, t, a, tok, bf, cf):  # noqa: F811
            now = time.monotonic()
            if now - last[0] >= 0.25 or d == t:
                last[0] = now
                line = display.fancy_progress(tag, d, t, a, cf, best_n,
                                              now - t0, tok=tok)
                sys.stderr.write("\r" + line)
                sys.stderr.flush()
                if d == t and t:
                    # final: end the line, persist it as a log line too
                    sys.stderr.write("\r" + " " * 90 + "\r")
                    sys.stderr.flush()
                    log.info("  %s%d/%d | alive=%d tok=%d | batch_fast=%d | "
                             "fast=%d/%d | +%ds",
                             tag, d, t, a, tok, bf, cf, best_n, int(now - t0))
    else:
        def cb(d, t, a, tok, bf, cf):  # noqa: F811
            now = time.monotonic()
            if d % 25 == 0 or now - last[0] >= echo_every or d == t:
                last[0] = now
                log.info("  %s%d/%d | alive=%d tok=%d | batch_fast=%d | "
                         "fast=%d/%d | +%ds",
                         tag, d, t, a, tok, bf, cf, best_n, int(now - t0))
    return cb


def _update_state(state, results, fast_thr, backup_max, latency_basis="echo",
                  key_of=None):
    alive = 0
    target_ok = 0
    for c, r in results:
        # With latency_basis=target, rank by target download time (closest to
        # the real browsing experience) instead of the light echo ping.
        if latency_basis == "target" and r.get("alive"):
            tl = r.get("target_latency")
            if tl is not None:
                r = {**r, "latency": tl}
        store.upsert(state, c, r, fast_thr, backup_max,
                     key=(key_of(c) if key_of else None))
        if r.get("alive"):
            alive += 1
            if r.get("target_ok"):
                target_ok += 1
    return alive, target_ok


def _flush_state_and_outputs(cfg: dict, state: dict, state_path: Path,
                             baseline=None, fast_thr=None) -> None:
    """Atomically persist state.json AND best/bak/gen output files so that
    found servers are always on disk in real time (even mid-run or on Ctrl+C)."""
    try:
        store.save(state_path, state)
        out_dir = state_path.parent
        # Same rule as the final write: alive+usable, target-OK ranked first.
        # This is the file you read when a run is interrupted, so it must not
        # disagree with the one written at the end (it used to be strict here
        # and lenient there).
        from . import core_live
        if cfg.get("list_mode", "target") == "live":
            best_recs, bak_recs = core_live.mix(
                state, max(cfg.get("best_n", 50),
                           cfg.get("bak_n", cfg.get("backup_n", 50))))
            _lo = []
        else:
            best_recs, bak_recs, _lo, _deg = core_live.split_lists(
                state, cfg.get("best_n", 50),
                cfg.get("bak_n", cfg.get("backup_n", 50)))
        if cfg.get("require_target"):
            best_recs = [r for r in best_recs if store.target_now(r)]
            bak_recs = [r for r in bak_recs if store.target_now(r)]
        used = {store.ident(r) for r in best_recs + bak_recs}
        _gen = (_lo or core_live.live_recs(state, cfg.get("gen_n", 100),
                                           exclude=used))[:cfg.get("gen_n", 100)]
        output.write_records(
            out_dir, best_recs, bak_recs, state,
            {
                "ts": int(time.time()),
                "baseline_ms": baseline,
                "fast_threshold_ms": fast_thr,
                "total_state": len(state),
            },
            gen_recs=_gen,
        )
    except Exception as e:  # noqa: BLE001
        log.debug("incremental flush error: %s", e)


# The task that owns the run. SIGINT cancels it directly: setting a flag is not
# enough while a batch of sing-box processes is awaited.
RUN_TASK: list = [None]


def _install_sigint(stop_event: asyncio.Event, force_save=None) -> None:
    """Ctrl+C -> graceful stop: set stop_event instead of relying on
    exception propagation inside asyncio.run (which was flaky for users and
    burned partial saves). test/probe loops check stop_event themselves.

    First  Ctrl+C: stop cooperatively, keep everything found so far.
    Second Ctrl+C: flush state/outputs one last time and hard-exit(130) — an
    in-flight batch on a hung line must never trap the user.
    """
    import os
    import signal

    def _on_sigint():
        if stop_event.is_set():
            log.warning("Ctrl+C again — forcing exit now (everything found so "
                        "far is already saved)")
            if force_save is not None:
                try:
                    force_save()
                except Exception as e:  # noqa: BLE001
                    log.debug("force_save failed: %s", e)
            try:
                sys.stderr.flush()
                sys.stdout.flush()
            except Exception:  # noqa: BLE001
                pass
            os._exit(130)
        stop_event.set()
        # The cooperative stop only lands when the CURRENT await returns, and a
        # batch on a bad line can sit in it for minutes: sing-box startup plus
        # target_timeout per node. The user pressed Ctrl+C to stop now, so
        # cancel the run's own task — `finally` blocks still flush and save.
        # Feedback goes out BEFORE the cancel, or the cancelled task exits
        # silently and the terminal looks dead.
        log.warning("Ctrl+C received — stopping now, saving every node found so "
                    "far... (press again to force-quit)")
        try:
            sys.stderr.flush()
        except Exception:  # noqa: BLE001
            pass
        task = RUN_TASK[0]
        if task is not None and not task.done():
            task.cancel()

    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, _on_sigint)
        loop.add_signal_handler(signal.SIGTERM, _on_sigint)
    except (NotImplementedError, RuntimeError) as e:
        log.debug("loop signal handler unavailable (%s); falling back to "
                  "signal.signal", e)
        try:
            signal.signal(signal.SIGINT, lambda *_: _on_sigint())
            signal.signal(signal.SIGTERM, lambda *_: _on_sigint())
        except Exception:  # noqa: BLE001
            pass


def _collect_run_rows(results, run_rows):
    for c, r in results:
        if r.get("alive"):
            run_rows.append({
                "type": c.get("type"), "server": c.get("server"),
                "server_port": c.get("server_port"),
                "latency": r.get("latency"), "target_ok": r.get("target_ok"),
                "probe_ms": r.get("probe_ms"),
                })
    return run_rows


async def discover(cfg, state, state_path: Path):
    """Tiered cascade discover. Tests each tier's new configs before fetching
    the next tier. Stops early when best_n fast nodes found. Persists every
    found node incrementally in real time and saves cleanly on Ctrl+C."""
    global INTERRUPTED
    INTERRUPTED = False
    POOLS.clear()
    run_rows = []  # every node alive in THIS run — for the final table

    baseline = cfg.get("baseline_ms_override")
    if baseline:
        log.info("Baseline ping from config: %sms", baseline)
    else:
        bi = await measure_baseline(cfg["baseline_hosts"])
        baseline = bi["baseline_ms"]
    fast_thr = compute_fast_threshold(baseline, cfg)
    log.info("%s", describe_baseline(baseline, cfg))
    cfg["_fast_thr"] = fast_thr
    await prepare_exit_proof(cfg)

    # Re-check known good nodes first (cheap, no fetch)
    known = []
    for r in state.values():
        if r.get("successes", 0) > 0 and r.get("raw"):
            c = parser.parse(r["raw"])
            if c and c["type"] in cfg["protocols"]:
                known.append(c)

    best_n = cfg.get("best_n", 50)
    stop_event = asyncio.Event()
    RUN_TASK[0] = asyncio.current_task()
    _install_sigint(stop_event,
                    force_save=lambda: _flush_state_and_outputs(
                        cfg, state, state_path, baseline, fast_thr))
    total_alive = 0
    total_target_ok = 0
    total_tested = 0
    fast_total = 0  # cumulative fast count across all batches
    tier_stats = {}
    last_save_ts = [time.monotonic()]

    def _on_live_result(c: dict, r: dict):
        nonlocal total_alive, total_target_ok, total_tested
        a, tk = _update_state(state, [(c, r)], fast_thr, cfg["backup_max_ms"],
                              cfg.get("latency_basis", "echo"))
        total_tested += 1
        total_alive += a
        total_target_ok += tk
        if r.get("alive"):
            run_rows.append({
                "type": c.get("type"), "server": c.get("server"),
                "server_port": c.get("server_port"),
                "latency": r.get("latency"), "target_ok": r.get("target_ok"),
                "probe_ms": r.get("probe_ms"),
                })
        now = time.monotonic()
        # Flush immediately when an alive node is found, or every 3 seconds
        if r.get("alive") or (now - last_save_ts[0] >= 3.0):
            last_save_ts[0] = now
            _flush_state_and_outputs(cfg, state, state_path, baseline, fast_thr)

    try:
        # 0) user-imported / custom links FIRST — hand-picked, never dropped by TCP probe
        user_cfgs, skipped = collect_user_configs(cfg)
        if user_cfgs or skipped:
            log.info("User configs: %d valid links (%d skipped/invalid) — "
                     "testing FIRST", len(user_cfgs), skipped)
            await probe(user_cfgs, cfg.get("probe_concurrency", 400),
                        cfg.get("probe_timeout", 3.5),
                        pace_ms=cfg.get("probe_pace_ms", 0),
                        breaker_window=cfg.get("probe_breaker_window", 0),
                        breaker_pause_s=cfg.get("probe_breaker_pause_s", 20),
                        stop_event=stop_event)
            ucfgs = _condition_filter(user_cfgs, cfg)
            ucfgs.sort(key=lambda c: c.get("_probe_ms") or 9999)
            results, nfast = await test_cfgs(
                ucfgs, cfg, start_fast=0,
                on_progress=ui_progress("[user] ", best_n),
                stop_event=stop_event, on_result=_on_live_result)
            for uc, ur in results:
                if ur.get("alive"):
                    log.info("  [user ✓] %-10s %s:%s | echo=%sms target_ok=%s (%s)",
                             uc["type"], uc["server"], uc["server_port"],
                             ur.get("latency"), ur.get("target_ok"),
                             ur.get("security") or "ok")
                else:
                    log.info("  [user ✗] %-10s %s:%s | probe=%s err=%s",
                             uc["type"], uc["server"], uc["server_port"],
                             ur.get("probe_ms"), ur.get("error") or "dead")
            a = sum(1 for _, r in results if r.get("alive"))
            t = sum(1 for _, r in results if r.get("alive") and r.get("target_ok"))
            fast_total = nfast
            _flush_state_and_outputs(cfg, state, state_path, baseline, fast_thr)
            log.info("User import done: alive=%d target_ok=%d | fast=%d/%d",
                     a, t, fast_total, best_n)

        if known and fast_total < best_n and not stop_event.is_set():
            log.info("Re-checking %d known good nodes first...", len(known))
            kcfgs = await probe(known, cfg.get("probe_concurrency", 400),
                                cfg.get("probe_timeout", 3.5),
                                pace_ms=cfg.get("probe_pace_ms", 0),
                                breaker_window=cfg.get("probe_breaker_window", 0),
                                breaker_pause_s=cfg.get("probe_breaker_pause_s", 20),
                                stop_event=stop_event)
            kcfgs = _condition_filter(kcfgs, cfg)
            kcfgs = _sort_and_interleave(kcfgs, cfg["protocols"],
                                         load_open_sni(cfg.get("data_dir", "data")))
            results, nfast = await test_cfgs(
                kcfgs, cfg, start_fast=fast_total, early_stop_fast=best_n,
                on_progress=ui_progress("[known] ", best_n),
                stop_event=stop_event, on_result=_on_live_result)
            a = sum(1 for _, r in results if r.get("alive"))
            t = sum(1 for _, r in results if r.get("alive") and r.get("target_ok"))
            fast_total = nfast
            _flush_state_and_outputs(cfg, state, state_path, baseline, fast_thr)
            log.info("Known nodes: alive=%d target_ok=%d (fast total=%d/%d)",
                     a, t, fast_total, best_n)

        if fast_total >= best_n:
            log.info("Reached %d fast target-OK nodes from user/known pool. Skipping cascade.", best_n)
        elif not stop_event.is_set():
            async for tier_name, new_cfgs in gather_configs_cascade(
                    cfg["protocols"], cfg.get("max_per_proto", 0), stop_event=stop_event,
                    domestic=cfg.get("domestic_sources"),
                    domestic_only=cfg.get("domestic_only", False),
                    tier_max=cfg.get("tier_max", 0)):
                if not new_cfgs:
                    continue
                if stop_event.is_set() or fast_total >= best_n:
                    break
                deduped_cfgs = _dedup_endpoints(
                    new_cfgs, cfg.get("max_per_endpoint", 3),
                    max_per_subnet=cfg.get("max_per_subnet", 0),
                    subnet_prefix=cfg.get("subnet_prefix", 24))
                _pool(tier_name, links=len(new_cfgs), tested=len(deduped_cfgs))
                log.info("Tier '%s': probing %d candidates (%d raw, fast total=%d/%d)...",
                         tier_name, len(deduped_cfgs), len(new_cfgs), fast_total, best_n)
                cfgs = await probe(deduped_cfgs, cfg.get("probe_concurrency", 400),
                                   cfg.get("probe_timeout", 3.5),
                                   pace_ms=cfg.get("probe_pace_ms", 0),
                                   breaker_window=cfg.get("probe_breaker_window", 0),
                                   breaker_pause_s=cfg.get("probe_breaker_pause_s", 20),
                                   stop_event=stop_event)
                if stop_event.is_set():
                    break
                cfgs = _condition_filter(cfgs, cfg)
                cfgs = _sort_and_interleave(cfgs, cfg["protocols"],
                                            load_open_sni(cfg.get("data_dir", "data")))
                POOLS.setdefault(tier_name, {}).setdefault("parsed", len(new_cfgs))
                POOLS[tier_name]["reachable"] = len(cfgs)
                log.info("Tier '%s': %d reachable, testing (fast total=%d/%d)...",
                         tier_name, len(cfgs), fast_total, best_n)
                t0 = time.time()
                results, nfast = await test_cfgs(
                    cfgs, cfg, start_fast=fast_total, early_stop_fast=best_n,
                    on_progress=ui_progress(f"[{tier_name}] ", best_n),
                    stop_event=stop_event, on_result=_on_live_result)
                a = sum(1 for _, r in results if r.get("alive"))
                tk = sum(1 for _, r in results if r.get("alive") and r.get("target_ok"))
                fast_total = nfast
                tier_stats[tier_name] = {"tested": len(results), "alive": a,
                                         "target_ok": tk, "fast_total": fast_total,
                                         "fetched": len(new_cfgs),
                                         "reachable": len(cfgs)}
                if sys.stderr.isatty() or sys.stdout.isatty():
                    card_rows = [
                        ("fetched",   str(len(new_cfgs))),
                        ("reachable", str(len(cfgs))),
                        ("tested",    str(len(results))),
                        ("alive",     f"{a}   fast {fast_total}/{best_n}"
                                      f"   target-ok {tk}   no-target {a - tk}"),
                    ]
                    top = next((r for c, r in results if r.get("alive")), None)
                    if top:
                        card_rows.append(
                            ("top", f"{(top.get('latency') or 0):.0f}ms"
                                    f"  target {'ok' if top.get('target_ok') else '-'}"))
                    print(display.card(card_rows))
                _flush_state_and_outputs(cfg, state, state_path, baseline, fast_thr)
                log.info("Tier '%s' done in %.1fs: alive=%d target_ok=%d no_target=%d | total fast=%d/%d",
                         tier_name, time.time() - t0, a, tk, a - tk, fast_total, best_n)

                if fast_total >= best_n:
                    log.info("Reached %d/%d fast %s nodes. Stopping cascade.",
                             fast_total, best_n,
                             "ALIVE" if not cfg.get("target_url") else "target-OK")
                    break

    except (KeyboardInterrupt, asyncio.CancelledError):
        INTERRUPTED = True
    finally:
        if stop_event.is_set():
            INTERRUPTED = True
        _flush_state_and_outputs(cfg, state, state_path, baseline, fast_thr)
        if INTERRUPTED:
            log.warning("Ctrl+C / stop received — saved %d tested nodes (%d alive, "
                        "%d target-OK, %d general/no-target) to %s.",
                        total_tested, total_alive, total_target_ok,
                        max(0, total_alive - total_target_ok),
                        state_path.parent)

    run_rows.sort(key=lambda r: (not r.get("target_ok"),
                                 r.get("latency") or 99999))
    if LEAK_STATS["leak"]:
        log.warning("[tunnel-proof] %d node(s) rejected as LEAKED — their exit IP "
                    "was your own line IP, so the traffic never went through the "
                    "node (they would have shown up as fake 'alive' results).",
                    LEAK_STATS["leak"])
    if LEAK_STATS["unverified"]:
        log.warning("[tunnel-proof] %d alive node(s) could not be exit-IP verified "
                    "(probe unreachable) — kept, but flagged as unverified.",
                    LEAK_STATS["unverified"])
    return {
        "alive": total_alive, "target_ok": total_target_ok,
        "baseline_ms": baseline, "fast_threshold_ms": fast_thr,
        "tested": total_tested, "tiers": tier_stats,
        "interrupted": INTERRUPTED,
        "run_nodes": run_rows,
        "leaked": LEAK_STATS["leak"], "unverified": LEAK_STATS["unverified"],
        "own_ip": cfg.get("_own_ip"),
    }


async def check(cfg, state, state_path: Path):
    """Re-check stored nodes and drop dead ones.

    Nodes with >= N consecutive failures are deleted (N comes from
    cfg[prune_failures] or the --drop-dead flag). Golden-pinned nodes are
    always re-checked but NEVER auto-removed — they stay until the user
    unpins/deletes them in `bot pick`."""
    global INTERRUPTED
    INTERRUPTED = False
    baseline = cfg.get("baseline_ms_override")
    if not baseline:
        bi = await measure_baseline(cfg["baseline_hosts"])
        baseline = bi["baseline_ms"]
    fast_thr = compute_fast_threshold(baseline, cfg)
    log.info("%s", describe_baseline(baseline, cfg))
    cfg["_fast_thr"] = fast_thr
    await prepare_exit_proof(cfg)

    # Re-check every usable node across all 3 categories (fast, backup, general)
    # PLUS the ones that failed last time — they get another chance to come back.
    recs = store.all_alive(state, require_target=False, include_dead=True)
    n_dead_in = sum(1 for r in recs
                    if r.get("alive_now") is False or r.get("tier") == "dead")
    if n_dead_in:
        log.info("  (including %d node(s) that failed their last check — "
                 "retrying them for revival)", n_dead_in)
    have = {store.ident(r) for r in recs}
    for r in state.values():
        if r.get("golden") and store.ident(r) not in have and r.get("raw"):
            recs.append(r)
    _usable_in = sum(1 for r in recs
                     if not (r.get("alive_now") is False or r.get("tier") == "dead"))
    log.info("Re-checking %d stored nodes (%d usable + %d previously dead, "
             "retrying them for revival)...", len(recs), _usable_in,
             len(recs) - _usable_in)
    # Snapshot the pool BEFORE anything is mutated. It covers the whole state,
    # not just `recs`: nodes whose raw link no longer parses are not re-tested
    # this round, but the summary must still account for them.
    before = {k: (r.get("tier"), r.get("alive_now"), r.get("successes", 0))
              for k, r in state.items()}
    all_cfgs = []
    parse_loss = 0
    # remember which stored record each config came from: the result must land
    # on the record the pool actually holds, not on whatever identity a fresh
    # parse produces today (see store.upsert / docs/DEFECTS.md D18)
    cfg_key: dict[str, str] = {}
    stale_keys: set[str] = set()
    dup_groups: dict[str, list[str]] = {}
    # alive records win the mapping: a stale/duplicate record with the same raw
    # must not decide where the fresh result is written
    for k, r in sorted(state.items(),
                       key=lambda kv: (kv[1].get("alive_now") is False,
                                       -int(kv[1].get("successes", 0) or 0))):
        if not r.get("raw"):
            continue
        c = parser.parse(r.get("raw", ""))
        if not c:
            continue
        ck = store.ident(c)
        cfg_key.setdefault(ck, k)
        dup_groups.setdefault(ck, []).append(k)
        if ck != k and (r.get("alive_now") is not False and r.get("tier") != "dead"):
            stale_keys.add(k)
    # Two records that resolve to the SAME node are an integrity bug, not a pool
    # (the sabotaged-node test left 29 records for 9 nodes: the old record stayed
    # "alive" while a second record under the new identity was tested as dead).
    # Keep the survivor and delete the ghosts, or the pool grows forever.
    ghosts = 0
    for ck, keys in dup_groups.items():
        if len(keys) < 2:
            continue
        keep = cfg_key[ck]
        best_succ = max(int(state[k].get("successes", 0) or 0) for k in keys)
        for k in keys:
            if k == keep:
                continue
            keep_succ = int(state[keep].get("successes", 0) or 0)
            if int(state[k].get("successes", 0) or 0) > keep_succ and best_succ > keep_succ:
                state[keep] = state[k]      # adopt the richer history
            state.pop(k, None)
            ghosts += 1
        cfg_key[ck] = keep
    if ghosts:
        log.info("  merged %d duplicate record(s) that pointed at a node already "
                 "in the pool (same raw, different key)", ghosts)
    for r in recs:
        c = parser.parse(r.get("raw", ""))
        if c:
            all_cfgs.append(c)
        else:
            parse_loss += 1
    if stale_keys:
        log.info("  %d stored node(s) do not resolve to their stored key — their "
                 "fresh result is written to the record the pool actually holds",
                 len(stale_keys))
    if parse_loss:
        log.warning("note: %d stored nodes failed to parse (raw may be "
                    "stale/corrupted — use `bot drop` to clean)", parse_loss)
    if not all_cfgs:
        log.info("No nodes to check. Run discover first.")
        return {"alive": 0, "target_ok": 0, "tested": 0, "interrupted": False}

    stop_event = asyncio.Event()
    RUN_TASK[0] = asyncio.current_task()
    _install_sigint(stop_event,
                    force_save=lambda: _flush_state_and_outputs(
                        cfg, state, state_path, baseline, fast_thr))

    cfgs = await probe(all_cfgs, cfg.get("probe_concurrency", 300),
                       cfg.get("probe_timeout", 3.5),
                       pace_ms=cfg.get("probe_pace_ms", 0),
                       breaker_window=cfg.get("probe_breaker_window", 0),
                       breaker_pause_s=cfg.get("probe_breaker_pause_s", 20),
                       stop_event=stop_event)
    cfgs = _condition_filter(cfgs, cfg)
    cfgs.sort(key=lambda c: c.get("_probe_ms") or 9999)

    alive = 0
    tok = 0
    tested_n = 0
    last_save_ts = [time.monotonic()]

    def _on_check_result(c: dict, r: dict):
        nonlocal alive, tok, tested_n
        a, t = _update_state(state, [(c, r)], fast_thr, cfg["backup_max_ms"],
                             cfg.get("latency_basis", "echo"),
                             key_of=lambda _c: cfg_key.get(store.ident(_c)))
        tested_n += 1
        alive += a
        tok += t
        now = time.monotonic()
        if r.get("alive") or (now - last_save_ts[0] >= 3.0):
            last_save_ts[0] = now
            _flush_state_and_outputs(cfg, state, state_path, baseline, fast_thr)

    results = []
    try:
        results, _ = await test_cfgs(
            cfgs, cfg, early_stop_fast=0, stop_event=stop_event,
            on_progress=ui_progress("[check] ", 0),
            on_result=_on_check_result)

        # Only penalize probe-failed nodes if the run was NOT interrupted early
        if not stop_event.is_set():
            reachable_keys = {store.ident(c) for c in cfgs}
            probed_keys = {store.ident(c) for c in all_cfgs}
            for k in probed_keys - reachable_keys:
                r = state.get(k)
                if r and r.get("successes", 0) > 0:
                    store.mark_failed(
                        state, k, "probe: no TCP/UDP answer",
                        result_code="probe_dead")
    except (KeyboardInterrupt, asyncio.CancelledError):
        INTERRUPTED = True
    finally:
        if stop_event.is_set():
            INTERRUPTED = True
        pf = 1 if cfg.get("drop_dead_now") else cfg.get("prune_failures", 6)
        dead = [k for k, r in state.items()
                if r.get("consecutive_fails", 0) >= pf and r.get("successes", 0) > 0
                and not r.get("golden")]
        if dead and not INTERRUPTED:
            log.info("Removing %d dead nodes (consecutive_fails >= %d)...", len(dead), pf)
            for k in dead:
                state.pop(k, None)
        else:
            dead = []
        _flush_state_and_outputs(cfg, state, state_path, baseline, fast_thr)
        if INTERRUPTED:
            log.warning("Ctrl+C / stop during check — saved %d checked nodes "
                        "(%d alive, %d target-OK) cleanly.", tested_n, alive, tok)

    # ── what did this re-check actually change? ──
    counts = store.tier_counts(state)
    died, revived, promoted, demoted = [], [], 0, 0
    removed_keys = []
    for k, snap in before.items():
        old_tier, old_alive, old_succ = snap
        r = state.get(k)
        if r is None:
            removed_keys.append(k)       # pruned/deleted during this run
            continue
        if old_succ < 1 and r.get("successes", 0) < 1:
            continue                     # never worked — not a loss to report
        now_dead = r.get("alive_now") is False or r.get("tier") == "dead"
        was_dead = (old_alive is False) or (old_tier == "dead")
        if now_dead and not was_dead:
            died.append((k, r.get("last_result") or "dead"))
        elif was_dead and not now_dead:
            revived.append(k)
        elif not now_dead and old_tier in ("fast", "backup", "general"):
            new_tier = r.get("tier")
            if old_tier != new_tier:
                if new_tier == "fast":
                    promoted += 1
                elif old_tier == "fast":
                    demoted += 1
    log.info("Check results: alive=%d target_ok=%d no_target=%d (removed=%d), nodes now:%d",
             alive, tok, max(0, alive - tok), len(dead), len(state))
    log.info("Pool after check: %d usable = %d fast + %d bak + %d gen | dead=%d "
             "(%d died now, %d revived, %d promoted, %d demoted) | slow=%d",
             counts.get("usable", 0), counts.get("fast", 0), counts.get("backup", 0),
             counts.get("general", 0), counts.get("dead", 0), len(died),
             len(revived), promoted, demoted, counts.get("slow", 0))
    if died:
        # only nodes that were USABLE before this check count as "died now";
        # never-successful leftovers are reported separately, not as a loss
        real_died = [(k, w) for k, w in died
                     if state.get(k, {}).get("successes", 0) > 0 and w != "removed"]
        ghost = len(died) - len(real_died)
        show = real_died[:8]
        for k, why in show:
            r = state.get(k) or {}
            log.info("  ☓ %-11s %s:%s — %s (%s)", str(r.get("type") or "?"),
                     r.get("server") or "?", r.get("server_port") or "?",
                     why, r.get("last_error") or "no answer")
        if len(real_died) > len(show):
            log.info("  ☓ ... and %d more (see `bot pick` → f → dead)",
                     len(real_died) - len(show))
        if ghost:
            log.info("  (+%d node(s) that never passed a check are also marked dead)",
                     ghost)
        if removed_keys:
            log.info("  (%d node(s) left state entirely during this run)",
                     len(removed_keys))
        died = real_died
        log.info("  dead nodes left the pool; they stay in state and come back "
                 "automatically if they pass a later check (`bot drop` deletes "
                 "them for good).")
    if LEAK_STATS["leak"]:
        log.warning("[tunnel-proof] %d node(s) rejected as LEAKED (exit IP == your "
                    "own line IP) during this check.", LEAK_STATS["leak"])
    return {"alive": alive, "target_ok": tok, "baseline_ms": baseline,
            "fast_threshold_ms": fast_thr, "tested": tested_n,
            "removed": len(dead), "interrupted": INTERRUPTED,
            "leaked": LEAK_STATS["leak"], "unverified": LEAK_STATS["unverified"],
            "own_ip": cfg.get("_own_ip"),
            "died": len(died), "revived": len(revived),
            "promoted": promoted, "demoted": demoted, "counts": counts,
            "pools": {k: dict(v) for k, v in POOLS.items()}}
