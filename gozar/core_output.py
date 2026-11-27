"""Write best/bak files and sing-box configs."""
from __future__ import annotations
import json
import time
from pathlib import Path

from . import core_runner as runner
from . import core_store as store


def _write(out_dir: Path, best_recs, bak_recs, state: dict, meta: dict,
           gen_recs=None):
    out_dir.mkdir(parents=True, exist_ok=True)
    if gen_recs is None:
        used = {store.ident(r) for r in best_recs} | {store.ident(r) for r in bak_recs}
        gen_recs = store.general(state, 100, exclude=used) if state else []

    # Raw links (ready for any client — trailing newline ensures POSIX tools like cat work cleanly)
    def _join_raw(recs):
        lines = [r["raw"] for r in recs if r.get("raw")]
        return ("\n".join(lines) + "\n") if lines else ""

    (out_dir / "best.txt").write_text(_join_raw(best_recs), encoding="utf-8")
    (out_dir / "bak.txt").write_text(_join_raw(bak_recs), encoding="utf-8")
    (out_dir / "gen.txt").write_text(_join_raw(gen_recs), encoding="utf-8")

    (out_dir / "best.json").write_text(
        json.dumps(best_recs, ensure_ascii=False, indent=1), encoding="utf-8")
    (out_dir / "bak.json").write_text(
        json.dumps(bak_recs, ensure_ascii=False, indent=1), encoding="utf-8")
    (out_dir / "gen.json").write_text(
        json.dumps(gen_recs, ensure_ascii=False, indent=1), encoding="utf-8")

    def fmt(rows, label):
        lines = [f"# {label} - {len(rows)} nodes"]
        for r in rows:
            # exit proof: the public IP the traffic really left from, and whether
            # it was verified to differ from the user's own line
            ex = r.get("exit_ip") or "-"
            if r.get("exit_loc"):
                ex += f"({r['exit_loc']})"
            if r.get("leak"):
                ex += " LEAK!"
            elif r.get("exit_verified") is False and r.get("exit_ip") is None:
                ex += " unverified"
            lines.append(
                f"{r['type']:<11} {(r.get('latency') or 0):>7}ms  "
                f"probe={(r.get('probe_ms') or 0):>6}ms  score={r.get('score',0):<6} "
                f"stab={r.get('stability',0):<4} {r['server']}:{r['server_port']}  "
                f"exit={ex:<24} {(r.get('tag') or '')[:36]}")
        return "\n".join(lines)

    (out_dir / "best.summary.txt").write_text(
        fmt(best_recs, "BEST (alive + usable, target-OK first)"), encoding="utf-8")
    (out_dir / "bak.summary.txt").write_text(
        fmt(bak_recs, "BACKUP (rest of the live pool)"), encoding="utf-8")
    (out_dir / "gen.summary.txt").write_text(
        fmt(gen_recs, "LIVE overflow (alive, not listed in best/bak)"), encoding="utf-8")

    sb_path = out_dir / "singbox-best.json"
    sb_recs = best_recs or bak_recs or gen_recs
    sb_conf = build_singbox_config(sb_recs, mixed_port=None, tun=False)
    if sb_conf is not None:
        sb_path.write_text(json.dumps(sb_conf, ensure_ascii=False, indent=1), encoding="utf-8")

    (out_dir / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    return best_recs, bak_recs


def write_target_list(out_dir: Path, ok_recs) -> int:
    """`ok.txt` — only the nodes that passed EVERY target.

    best/bak are the default list (alive and usable, target-OK ranked first).
    This file is the strict subset, so the two questions -- "what works" and
    "what is proven against the filter" -- have two answers instead of one
    blurred one. It is always written, even when empty: a missing file is an
    error, an empty file is a measurement.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = [r["raw"] for r in (ok_recs or []) if r.get("raw")]
    (out_dir / "ok.txt").write_text(("\n".join(lines) + "\n") if lines else "",
                                    encoding="utf-8")
    return len(lines)


def write_records(out_dir: Path, best_recs, bak_recs, state: dict, meta: dict,
                  gen_recs=None):
    """Write files from pre-selected records (no re-selection)."""
    return _write(out_dir, list(best_recs), list(bak_recs), state, meta,
                  gen_recs=list(gen_recs) if gen_recs is not None else None)


def write_files(out_dir: Path, state: dict, n_best: int, n_bak: int,
                require_target: bool, meta: dict, n_gen: int = 100):
    """Select best/bak/gen from state and write."""
    best_recs = store.best(state, n_best, require_target=require_target)
    best_ids = {store.ident(r) for r in best_recs}
    bak_recs = store.backup(state, n_bak, require_target=require_target, exclude=best_ids)
    used_ids = best_ids | {store.ident(r) for r in bak_recs}
    gen_recs = store.general(state, n_gen, exclude=used_ids)
    return _write(out_dir, best_recs, bak_recs, state, meta, gen_recs=gen_recs)


# urltest picks the member to use, so it should measure THROUGHPUT, not just
# reachability — a node that answers a tiny request fast can still be slow at
# real downloads (docs/PERF.md).
#
# Size matters: 256KB made the selector the bottleneck (its own probe downloads
# 256KB before routing), which showed up as +75ms on first byte. 128KB is the
# compromise: enough to separate a slow node from a fast one, small enough that
# the check finishes in ~90ms on a healthy line.
URLTEST_URL = "https://speed.cloudflare.com/__down?bytes=131072"


def urltest_outbound(tags: list[str], url: str | None = None) -> dict:
    """The `auto` selector used by connect and by singbox-best.json."""
    return {
        "type": "urltest", "tag": "auto",
        "outbounds": list(tags),
        "url": url or URLTEST_URL,
        "interval": "3m", "tolerance": 80,
        # a bandwidth-based check every few minutes would otherwise tear down
        # the connection carrying it: keep live traffic on its member, and let
        # an idle server stop measuring.
        "interrupt_exist_connections": False,
        "idle_timeout": "30m",
    }


def build_singbox_config(recs, mixed_port=2080, tun=False):
    """Build a sing-box config with urltest over all nodes.
    If mixed_port is None, no inbound is added (group-only build)."""
    outbounds = []
    tags = []
    for i, r in enumerate(recs):
        if not r.get("raw"):
            continue
        from . import core_parser as parser
        cfg = parser.parse(r["raw"])
        if not cfg:
            continue
        tag = f"n{i}"
        ob = runner.build_outbound(cfg, tag)
        outbounds.append(ob)
        tags.append(tag)
    if not tags:
        return None
    outbounds.append(urltest_outbound(tags))
    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "block", "tag": "block"})

    inbounds = []
    route_final = "auto"
    if tun:
        inbounds.append({
            "type": "tun", "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 9000, "auto_route": True, "strict_route": True,
            "stack": "system",
        })
    if mixed_port is not None:
        inbounds.append({
            "type": "mixed", "tag": "mixed-in",
            "listen": "127.0.0.1", "listen_port": mixed_port,
        })
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "remote", "type": "https",
                 "server": "1.1.1.1", "detour": "auto"},
                {"tag": "local", "type": "local"},
            ],
            "final": "remote",
            "strategy": "prefer_ipv4",
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "remote",
            "final": route_final,
        },
        "experimental": {"cache_file": {"enabled": True}},
    }
