"""Score every source against ONE target, so the ordering is evidence, not lore.

The tier order used to be a judgement call ("measured first because it is
maintained", "bulk last because it is big"). That is a guess about a file, and
the 2026-11-15 census already showed the guess fails: the same repository
produced both the best and the worst file of the run (batch_003: 7,689 new
nodes; batch_013: 1).

This module asks the only question that matters for a given target:
    for every source, of the nodes it published, how many actually CARRY that
    target?
and answers it with a bounded sample per source (default 20), so a 10,000-line
bundle cannot drown a 300-line one.

The output is a table plus `data/source-score.json`; `rank()` turns it into an
ordered list of sources that `TIERS` can adopt. Nothing here writes to the pool.
"""
from __future__ import annotations

import asyncio
import json
import random
import statistics
import time
from collections import defaultdict

from . import core_parser as parser
from . import core_store as store
from .core_sources import TIERS, PROTOCOL_SOURCES

FETCH_TIMEOUT = 40


async def _fetch(session, url: str) -> str | None:
    try:
        async with session.get(url, timeout=FETCH_TIMEOUT) as r:
            if r.status != 200:
                return None
            return await r.text(errors="ignore")
    except Exception:                                    # noqa: BLE001
        return None


def _extract(text: str, protocols) -> list[dict]:
    """Shared with the normal fetch path: base64 subscriptions included.

    A private extractor here counted base64-encoded sources as publishing zero
    nodes, which read as "dead source" in the report. The bot already knows how
    to unwrap them (core_test._extract_links) — use that, do not reimplement it.
    """
    from .core_test import _extract_links
    out, seen = [], set()
    for line in _extract_links(text):
        line = line.strip()
        c = parser.parse(line)
        if not c or c["type"] not in protocols:
            continue
        k = store.ident(c)
        if k in seen:
            continue
        seen.add(k)
        out.append(c)
    return out


# Rows completed so far in the current run. A Ctrl+C during a 40-minute sweep
# must not throw away the sources that already finished, and asyncio cancels the
# coroutine before returning, so the partial list has to live somewhere the
# caller can read. Cleared at the start of every run.
LAST_ROWS: list[list[dict]] = [[]]


async def score_sources(cfg, target: list[str], per_source: int = 20,
                        tiers: dict | None = None, on_source=None) -> list[dict]:
    """Fetch, sample, test. Returns one row per source, richest evidence first.

    `target` is the SAME list the bot normally uses, so a source is scored on the
    exact question the user will ask of the pool later.
    """
    import aiohttp
    from . import core_test as ct

    protocols = cfg.get("protocols") or ["vless"]
    tiers = tiers or TIERS
    rows: list[dict] = []
    # publish the (empty) buffer BEFORE the first await, so a Ctrl+C during the
    # sweep leaves the caller a list to read instead of an UnboundLocalError.
    LAST_ROWS[0] = rows

    # The target doubles as the page probe. Without this the throughput column
    # stays empty: core_test only measures page_kbps for URLs listed in
    # page_probe_urls, and it reads that list out of cfg in prepare_exit_proof,
    # which the normal CLI flows call but a direct test_cfgs() call does not.
    # Skipping it also disabled the own-IP leak baseline, so a node that was
    # silently NOT proxying could look alive here.
    tcfg = {**cfg, "target_url": target, "page_probe_urls": target}
    await ct.prepare_exit_proof(tcfg)
    headers = {"User-Agent": "Mozilla/5.0"}
    timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT)

    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as s:
        for tier_name, urls in tiers.items():
            for url in urls:
                text = await _fetch(s, url)
                row = {"tier": tier_name, "url": url, "reachable": bool(text),
                       "parsed": 0, "sampled": 0, "tcp_ok": 0, "alive": 0,
                       "target_ok": 0, "render_ok": 0, "reached": 0,
                       "throttled": 0, "shell": 0,
                       "proto_mix": {}, "bytes": None, "kbps": None, "ms": None}
                if text:
                    cfgs = _extract(text, protocols)
                    row["parsed"] = len(cfgs)
                    mix = defaultdict(int)
                    for c in cfgs:
                        mix[c["type"]] += 1
                    row["proto_mix"] = dict(sorted(mix.items(), key=lambda kv: -kv[1]))
                    random.shuffle(cfgs)
                    sample = cfgs[:per_source]
                    row["sampled"] = len(sample)
                    if sample:
                        t0 = time.time()
                        probed = await ct.probe(
                            sample, cfg.get("probe_concurrency", 200),
                            cfg.get("probe_timeout", 3.5))
                        row["tcp_ok"] = len(probed)
                        if probed:
                            res, _ = await ct.test_cfgs(
                                probed,
                                {**tcfg,
                                 "test_concurrency": cfg.get("test_concurrency", 10)})
                            oks, kbps, lat, sizes = [], [], [], []
                            for _c, r in res:
                                if r.get("alive"):
                                    row["alive"] += 1
                                # counted independently of target_ok: a wall is
                                # itself never target_ok, so nesting the wall
                                # counter inside that branch hid every wall.
                                if r.get("target_shell"):
                                    row["shell"] += 1
                                if r.get("target_ok"):
                                    row["target_ok"] += 1
                                    if not r.get("target_shell"):
                                        row["render_ok"] += 1
                                    oks.append(r)
                                if r.get("target_reached"):
                                    row["reached"] += 1
                                _sz = r.get("bytes") or r.get("page_bytes")
                                if _sz:
                                    sizes.append(int(_sz))
                                if r.get("page_throttled"):
                                    row["throttled"] += 1
                                if r.get("page_kbps"):
                                    kbps.append(float(r["page_kbps"]))
                                if r.get("latency"):
                                    lat.append(float(r["latency"]))
                            if kbps:
                                row["kbps"] = round(statistics.median(kbps), 1)
                            if lat:
                                row["ms"] = round(statistics.median(lat), 0)
                            if sizes:
                                # median body size: a 94KB body and a 3.3KB
                                # throttle page are different animals, and only
                                # the size tells them apart.
                                row["bytes"] = int(statistics.median(sizes))
                        row["secs"] = round(time.time() - t0, 1)
                # the honest ratio: of the nodes we could test, how many carried
                # the target? A source with 2/2 is not better than 40/200, so the
                # count travels with the rate and rank() uses both.
                row["ok_rate"] = round(row["target_ok"] / row["sampled"], 3) if row["sampled"] else 0.0
                row["render_rate"] = (round(row["render_ok"] / row["sampled"], 3)
                                      if row["sampled"] else 0.0)
                rows.append(row)
                if LAST_ROWS and LAST_ROWS[0] is not rows:
                    LAST_ROWS[0].append(row)
                if on_source:
                    on_source(row)
    return rows


def rank(rows: list[dict], min_sample: int = 5) -> list[dict]:
    """Order sources by what they actually deliver for this target.

    A source needs a real sample to be ranked at all (2 tested nodes say
    nothing); below that it is ordered by raw volume, so a small but perfect
    source cannot jump ahead of a large proven one. Ties go to the faster,
    fatter source.
    """
    def key(r):
        proven = r["sampled"] >= min_sample
        return (
            not proven,                       # proven sources first
            # A source that SERVES the page beats one that only reaches a wall.
            # When the target itself is JS-walled (Google serves its loader to
            # every exit IP today) NOTHING renders, and ranking by render alone
            # leaves the table shuffled: fall through to `reached` — nodes that
            # provably carried the request — so the order still means delivery.
            (-(r.get("render_ok") or 0), -(r["target_ok"]),
             -(r.get("reached") or 0)) if proven
            else (-(r["parsed"]), 0, 0),
            -r["ok_rate"],
            -(r["kbps"] or 0),
        )
    return sorted(rows, key=key)


def summarise(rows: list[dict]) -> dict:
    """Per-tier totals: this is what the TIERS ordering should be based on."""
    per = defaultdict(lambda: {"sources": 0, "parsed": 0, "sampled": 0,
                               "target_ok": 0, "render_ok": 0, "shell": 0,
                               "reached": 0, "alive": 0,
                               "dead_urls": 0, "empty_urls": 0,
                               "proto_mix": defaultdict(int)})
    for r in rows:
        t = per[r["tier"]]
        t["sources"] += 1
        t["parsed"] += r.get("parsed") or 0
        t["sampled"] += r.get("sampled") or 0
        t["target_ok"] += r.get("target_ok") or 0
        t["render_ok"] += r.get("render_ok") or 0
        t["shell"] += r.get("shell") or 0
        t["reached"] += r.get("reached") or 0
        t["alive"] += r.get("alive") or 0
        t["dead_urls"] += 0 if r.get("reachable") else 1
        # a reachable URL that yields ZERO parsable nodes is its own failure:
        # the file exists but publishes nothing this build can use (subscription
        # now serves base64/HTML, or every scheme is unsupported). Counting it
        # as reachable hid this — see dedupe/reach metrics in STATUS.
        t["empty_urls"] += 1 if (r.get("reachable") and not r.get("parsed")) else 0
        for k, v in (r.get("proto_mix") or {}).items():
            t["proto_mix"][k] += v
    for t in per.values():
        t["proto_mix"] = dict(sorted(t["proto_mix"].items(), key=lambda kv: -kv[1]))
        t["ok_rate"] = round(t["target_ok"] / t["sampled"], 3) if t["sampled"] else 0.0
        t["per_1k_parsed"] = round(1000 * t["target_ok"] / t["parsed"], 1) if t["parsed"] else 0.0
        # yield of *delivery*, not of page render: with a JS-walled target every
        # render count is 0 and the honest per-tier comparison is this one.
        t["per_1k_reached"] = round(1000 * t["reached"] / t["parsed"], 2) if t["parsed"] else 0.0
    return dict(per)


def write(data_dir, rows: list[dict], target: list[str]) -> None:
    from pathlib import Path
    p = Path(data_dir)
    p.mkdir(parents=True, exist_ok=True)
    (p / "source-score.json").write_text(json.dumps(
        {"ts": int(time.time()), "target": target, "sources": rows,
         "tiers": summarise(rows)}, ensure_ascii=False, indent=1), encoding="utf-8")
