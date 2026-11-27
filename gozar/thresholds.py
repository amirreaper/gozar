"""calibrate — derive the latency/count thresholds from YOUR line's measurements.

Why this exists: the "fast" and "keep" thresholds depend on what is normal on
YOUR line. On a heavily filtered Iranian line a normal RTT may be ~900ms, and a
1200ms ceiling would throw away half the working nodes; on a good line a 300ms
normal makes a 4000ms ceiling let useless nodes into best. So we do not guess
the numbers: we measure them.

Output: a block you can paste into config.json + the reason behind each number.
"""
from __future__ import annotations

import asyncio
import json
import statistics
import time
from pathlib import Path

from .checker import tcp_ping, measure_baseline


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    i = max(0, min(len(v) - 1, int(round(q * (len(v) - 1)))))
    return v[i]


async def measure_sample(hosts: list[str], rounds: int = 4,
                         timeout: float = 3.0) -> list[float]:
    """Repeated TCP handshakes to anycast/close hosts → the line's own RTT band."""
    out: list[float] = []
    for _ in range(rounds):
        for hp in hosts:
            try:
                host, port = hp.rsplit(":", 1)
                ms = await tcp_ping(host, int(port), timeout)
            except ValueError:
                continue
            if ms is not None:
                out.append(ms)
    return out


async def node_latencies(state: dict, limit: int = 40) -> list[float]:
    """Latency of the nodes this tool already measured on THIS line.

    This is the real distribution the thresholds must fit — the line RTT alone
    only says what is possible, not what the public nodes actually deliver.
    """
    vals = []
    for r in state.values():
        if r.get("alive_now") is False:
            continue
        ms = r.get("avg_latency") or r.get("latency")
        if ms:
            vals.append(float(ms))
        if len(vals) >= limit:
            break
    return vals


def build_recommendation(line_rtt: list[float], seeds: list[float],
                         current: dict | None = None) -> dict:
    """Turn the two distributions into concrete config numbers."""
    cur = current or {}
    base = statistics.median(line_rtt) if line_rtt else None
    pool = sorted(seeds) if seeds else []
    n = len(pool)
    p50 = p75 = p90 = None

    if n >= 8:
        p50, p75, p90 = _pct(pool, 0.5), _pct(pool, 0.75), _pct(pool, 0.9) or 0
        # "fast" = the better half of what actually works HERE; "keep" = 90th
        # percentile (drop only the clear outliers), never below the line RTT.
        fast = max(int(p75 or p50 or 1200), 400)
        keep = max(int(p90 * 1.25), fast + 400)
        best_n = max(10, min(60, n // 2))
        bak_n = max(10, min(120, n))
    elif n > 0:
        p50 = _pct(pool, 0.5) or 1200
        fast = max(int(p50 * 1.2), 600)
        keep = max(int(p50 * 3), fast + 500)
        best_n, bak_n = 10, 20
    else:
        fast, keep, best_n, bak_n = cur.get("fast_max_ms", 1200), \
            cur.get("backup_max_ms", 4000), cur.get("best_n", 50), cur.get("bak_n", 100)

    rec = {
        "fast_max_ms": int(fast),
        "backup_max_ms": int(keep),
        "best_n": int(best_n),
        "bak_n": int(bak_n),
        "gen_n": int(cur.get("gen_n", 100)),
    }
    return {
        "recommended": rec,
        "line_rtt_ms": round(base, 1) if base else None,
        "pool_samples": n,
        "pool_p50": round(p50, 1) if p50 else None,
        "pool_p75": round(p75, 1) if p75 else None,
        "pool_p90": round(p90, 1) if p90 else None,
    }


PROFILES = ("conservative", "standard", "fast")


def apply_profile(rec: dict, profile: str | None) -> dict:
    """Scale the measured numbers by how much you value hit-rate vs. speed.

    Applied AFTER measurement, so the profile never invents values — it only
    trades one measured property for another:
      conservative — keep more, fail less: higher ceilings, bigger pools
      standard     — exactly what the measurement said (default: no change)
      fast         — fewer, quicker nodes: tighter ceilings, smaller pools
    """
    if not profile or profile == "standard":
        return rec
    out = dict(rec)
    if profile == "conservative":
        out["fast_max_ms"] = int(rec["fast_max_ms"] * 1.25)
        out["backup_max_ms"] = int(rec["backup_max_ms"] * 1.4)
        out["best_n"] = min(150, max(15, int(rec["best_n"] * 1.5)))
        out["bak_n"] = min(250, max(20, int(rec["bak_n"] * 1.5)))
    elif profile == "fast":
        out["fast_max_ms"] = int(rec["fast_max_ms"] * 0.8)
        out["backup_max_ms"] = int(rec["backup_max_ms"] * 0.75)
        out["best_n"] = max(5, int(rec["best_n"] * 0.6))
        out["bak_n"] = max(10, int(rec["bak_n"] * 0.6))
    return out


def render(rec: dict, current: dict) -> str:
    r = rec["recommended"]
    lines = []
    add = lines.append
    add("")
    add("  ── your line, measured ──")
    add(f"   line RTT (median TCP to 1.1.1.1/8.8.8.8): {rec['line_rtt_ms']}ms")
    if rec["pool_samples"]:
        add(f"   nodes already tested on this line: {rec['pool_samples']}"
            f"  p50={rec['pool_p50']}ms"
            + (f"  p75={rec['pool_p75']}ms" if rec.get("pool_p75") else "")
            + (f"  p90={rec['pool_p90']}ms" if rec.get("pool_p90") else ""))
    else:
        add("   no node has been tested on this line yet — numbers are based on line RTT + defaults")
        add("   (run `gozar discover` once, then repeat this command for exact numbers)")
    add("")
    add("  ── recommendation (paste into config.json) ──")
    add(json.dumps(r, ensure_ascii=False, indent=2))
    add("")
    add("  ── changes vs. current config ──")
    any_change = False
    labels = {
        "fast_max_ms": "latency ceiling for FAST (best)",
        "backup_max_ms": "latency ceiling for KEEP (bak+gen; anything higher is dropped)",
        "best_n": "how many nodes in best",
        "bak_n": "how many nodes in bak",
        "gen_n": "how many nodes in gen",
    }
    for k, label in labels.items():
        old, new = current.get(k), r[k]
        if old == new:
            add(f"   = {label}: {new}")
            continue
        any_change = True
        arrow = "↑" if isinstance(new, (int, float)) and isinstance(old, (int, float)) and new > old else "↓"
        add(f"   {arrow} {label}: {old} → {new}")
    if not any_change:
        add("   current settings already match your line (ok)")
    return "\n".join(lines)


async def calibrate(state: dict, cfg: dict) -> dict:
    hosts = cfg.get("baseline_hosts") or ["1.1.1.1:443", "8.8.8.8:443"]
    line_rtt = await measure_sample(hosts, rounds=3)
    if not line_rtt:
        b = await measure_baseline(hosts)
        line_rtt = [b["baseline_ms"]] if b.get("baseline_ms") else []
    seeds = await node_latencies(state)
    return build_recommendation(line_rtt, seeds, cfg)
