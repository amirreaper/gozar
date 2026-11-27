"""Persistent state for modern-protocol configs.

Freshness contract (added after the "check shows a stale pool" report):
every record carries `last_check` + `alive_now` + `last_result`, so the UI can
always tell "connected right now" from "this is an old number". A node that
fails a check moves to tier `dead`, drops out of best/bak/gen and out of the
picker, and only comes back when it passes again.
"""
from __future__ import annotations
import hashlib
import json
import time
from collections import Counter
from pathlib import Path


def ident(cfg: dict) -> str:
    """Stable unique key for a config (independent of label/order)."""
    key = "|".join(str(cfg.get(k, "")) for k in (
        "type", "server", "server_port", "uuid", "password", "method", "flow"))
    # Connection-relevant parameters
    tls = cfg.get("tls") or {}
    key += f"|{tls.get('server_name','')}|{bool(tls.get('reality'))}"
    tr = cfg.get("transport") or {}
    key += f"|{tr.get('type','')}|{tr.get('path','')}"
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)


def tier_for(latency: float | None, fast_thr: float, backup_max: float,
             target_ok: bool | None = None, total_target_ok: int = 0) -> str:
    if latency is None:
        return "unknown"
    if latency > backup_max:
        return "slow"
    # Category 3: Alive and within acceptable latency, but target check failed
    if target_ok is False and total_target_ok < 1:
        return "general"
    if latency <= fast_thr:
        return "fast"
    return "backup"


def is_dead(r: dict) -> bool:
    """True when the node failed its most recent check (golden pins exempt)."""
    if r.get("golden"):
        return False
    return r.get("alive_now") is False or r.get("tier") == "dead"


def target_ok_count(rec: dict) -> int:
    """How many target passes this record has accumulated (any time in its life)."""
    v = rec.get("target_ok")
    if isinstance(v, bool):
        return 1 if v else 0
    return int(v or 0)


def target_now(rec: dict) -> bool:
    """Did the node pass the configured targets in its MOST RECENT check?

    This is the only value selection may use. `target_ok` is a lifetime
    counter for statistics; a single pass months ago must never keep a node in
    `best` after today's target check failed (report: "not target-driven").
    Records written before the freshness contract are treated honestly:
    - explicit `target_ok_now` wins,
    - otherwise a dead record has no live proof,
    - otherwise fall back to the lifetime count (legacy behaviour).
    """
    if "target_ok_now" in rec:
        if rec.get("target_ok_now") is None:
            # liveness-only record: there is no target verdict to honour, so a
            # target-requiring selection must NOT treat it as passing.
            return False
        return bool(rec.get("target_ok_now"))
    if rec.get("alive_now") is False or rec.get("tier") == "dead":
        return False
    return target_ok_count(rec) >= 1


def _apply_fail(rec: dict, reason: str, leak: bool = False,
                result_code: str | None = None) -> None:
    """Shared bookkeeping for a failed check (real test or probe)."""
    now = int(time.time())
    rec["checks"] = rec.get("checks", 0) + 1
    rec["consecutive_fails"] = rec.get("consecutive_fails", 0) + 1
    rec["alive_now"] = False
    rec["last_check"] = now
    rec["last_fail"] = now
    rec["last_result"] = result_code or "dead"
    if "target_ok_now" in rec or rec.get("target_ok"):
        rec["target_ok_now"] = False
    rec["last_error"] = (reason or "no answer")[:120]
    # A dead node must never present its old latency as a current measurement.
    rec["latency"] = None
    if rec.get("tier") != "dead":
        rec["last_tier"] = rec.get("tier")
    rec["tier"] = "dead"
    if leak:
        rec["leak"] = True
        rec["leak_seen"] = now
    rec["exit_verified"] = False


def mark_failed(state: dict, key: str, reason: str, leak: bool = False,
                result_code: str | None = None) -> dict | None:
    """Mark a stored record as failed without re-running a test (used for nodes
    the probe phase never even reached)."""
    rec = state.get(key)
    if rec is None:
        return None
    _apply_fail(rec, reason, leak=leak, result_code=result_code)
    rec["stability"] = (round(rec.get("successes", 0) / rec["checks"], 3)
                        if rec.get("checks") else 0)
    rec["score"] = _score(rec)
    return rec


def upsert(state: dict, cfg: dict, result: dict, fast_thr: float,
           backup_max: float, key: str | None = None) -> dict:
    """Merge one test result into state.

    `key` overrides the derived identity. `check` passes the key the record is
    ALREADY stored under, because a stored record whose raw link re-parses into a
    slightly different config (a parser gaining a field, a hand-edited link, a
    provider changing SNI) would otherwise be written under a NEW identity and
    leave the old record sitting there as "alive" forever, re-tested by nothing.
    That is how two sabotaged nodes stayed in best after a full check.
    """
    i = key or ident(cfg)
    rec = state.get(i, {})
    now = int(time.time())
    rec.setdefault("checks", 0)
    rec.setdefault("successes", 0)
    rec.setdefault("target_ok", 0)
    rec.setdefault("consecutive_fails", 0)
    rec.setdefault("first_seen", now)
    rec["last_seen"] = now
    rec["last_check"] = now
    rec["type"] = cfg["type"]
    rec["server"] = cfg["server"]
    rec["server_port"] = cfg["server_port"]
    rec["tag"] = cfg.get("tag", "")
    rec["raw"] = cfg.get("raw", "")
    rec["probe_ms"] = result.get("probe_ms")
    if result.get("alive"):
        was_dead = rec.get("alive_now") is False or rec.get("tier") == "dead"
        prev_tier = rec.get("tier")
        rec["checks"] += 1
        rec["successes"] += 1
        rec["consecutive_fails"] = 0
        rec["last_ok"] = now
        rec["alive_now"] = True
        rec["latency"] = result.get("latency")
        rec["last_latency"] = result.get("latency")
        if result.get("echo_latency") is not None:
            rec["echo_latency"] = result.get("echo_latency")
        rec["security"] = result.get("security")
        rec["exit_ip"] = result.get("exit_ip") or rec.get("exit_ip")
        rec["exit_loc"] = result.get("exit_loc") or rec.get("exit_loc")
        rec["exit_verified"] = bool(result.get("exit_verified"))
        # keep the evidence, not just the verdict: the user must be able to see
        # WHY a node is in gen ("echo ok but the page came back 204/0B").
        for k in ("page_ok", "page_status", "page_bytes", "page_url",
                  "page_ms", "page_kbps", "page_throttled",
                  "target_reached", "target_throttled", "http_reached",
                  "target_shell", "target_bytes", "shell_expected"):
            if k in result:
                rec[k] = result[k]
        rec.pop("leak", None)
        rec.pop("last_error", None)
        rec.pop("last_fail", None)
        sec = result.get("security")
        rec["last_result"] = sec if sec and sec != "ok" else (
            "ok" if result.get("target_ok") else "no_target")
        if result.get("target_ok"):
            rec["target_ok"] += 1
        # freshness contract: what happened NOW, not in the lifetime counter.
        # None = the run had no targets at all (liveness-only mode) — that is a
        # different statement from "failed the target".
        rec["target_ok_now"] = (None if result.get("target_ok") is None
                                else bool(result.get("target_ok")))
        rec["tier"] = tier_for(
            result.get("latency"), fast_thr, backup_max,
            target_ok=result.get("target_ok"),
            total_target_ok=rec["target_ok"],
        )
        if was_dead:
            rec["revived_ts"] = now
        if prev_tier and prev_tier != "dead" and prev_tier != rec["tier"]:
            rec["tier_changed_ts"] = now
            rec["prev_tier"] = prev_tier
        # FIRST measurement seeds the running average (stable display value);
        # later checks weight it 60/40 toward the new result
        prev = rec.get("avg_latency")
        cur = result.get("latency") or 0
        rec["avg_latency"] = round(cur if prev is None else prev * 0.6 + cur * 0.4, 1)
    else:
        _apply_fail(rec, result.get("error") or "no answer",
                    leak=bool(result.get("leak")),
                    result_code=("leak" if result.get("leak")
                                 else (result.get("security") or "dead")))
    rec["stability"] = round(rec["successes"] / rec["checks"], 3) if rec["checks"] else 0
    rec["score"] = _score(rec)
    state[i] = rec
    return rec


def _score(rec: dict) -> float:
    stab = rec.get("stability", 0)
    succ = rec.get("successes", 0)
    # rank by the smoothed average — one good run should not buy/charge the
    # position of a node that averaged slower (and vice versa)
    lat = rec.get("avg_latency") or rec.get("latency") or 9999
    target_ratio = 0.0
    if rec.get("checks"):
        target_ratio = rec.get("target_ok", 0) / rec["checks"]
    s = stab * 50 + target_ratio * 30 + min(succ, 10) * 2
    s += max(0.0, (2000 - min(lat, 2000)) / 2000.0) * 20
    if rec.get("alive_now") is False or rec.get("tier") == "dead":
        s -= 50          # sink below every usable node, whatever its history
    return round(s, 2)


def prune(state: dict, max_fails: int = 6, max_age_days: int = 10) -> dict:
    now = int(time.time())
    out = {}
    for k, r in state.items():
        # Golden nodes are immune to any automatic pruning — they are kept
        # until the user removes them manually (g/d in `bot pick`).
        if r.get("golden"):
            out[k] = r
            continue
        if r.get("consecutive_fails", 0) >= max_fails and r.get("successes", 0) <= 2:
            continue
        # Age is measured from the last SUCCESS — a good node must survive a
        # quiet weekend of manual use; only nodes with no recent success rot
        # away (D6).
        anchor = r.get("last_ok") or r.get("first_seen", 0)
        if now - anchor > max_age_days * 86400:
            continue
        out[k] = r
    return out


def tier_counts(state: dict) -> dict:
    """Counts that MUST add up: fast + bak + gen == usable, dead excluded.

    The categories are derived from the same rule the selectors use
    (`target_now`), so the numbers printed after a check are exactly what
    best/bak/gen contain. Previously a node with tier "fast" but a failed
    target was counted as fast while also being excluded from best — the log
    and the files disagreed (28 alive vs 21 stored).
    """
    c = Counter()
    for r in state.values():
        if r.get("successes", 0) < 1:
            continue
        if r.get("golden"):
            c["golden"] += 1
        if is_dead(r):
            c["dead"] += 1
            continue
        tier = r.get("tier") or "unknown"
        if r.get("target_ok_now") is None and tier in ("fast", "backup"):
            # liveness-only run: no target verdict exists, the node is simply alive
            c[tier] += 1
        elif target_now(r) and tier in ("fast", "backup"):
            c[tier] += 1
        elif tier == "slow":
            c["slow"] += 1
        else:
            # alive, but did not pass the targets in its last check
            c["general"] += 1
    c["usable"] = c["fast"] + c["backup"] + c["general"]
    c["pool"] = sum(1 for r in state.values() if r.get("successes", 0) >= 1)
    return dict(c)


def _select(state, tier, n, require_target, allow_recent_fails=2):
    items = []
    for r in state.values():
        if r.get("successes", 0) < 1:
            continue
        if is_dead(r):
            continue
        if r.get("consecutive_fails", 0) > allow_recent_fails and not r.get("golden"):
            continue
        if require_target and not target_now(r):
            continue
        if r.get("tier") != tier:
            continue
        items.append(r)
    items.sort(key=lambda r: (r.get("score", 0), -(r.get("avg_latency") or r.get("latency") or 9999)), reverse=True)
    return items[:n]


def best(state, n, require_target=True):
    """Category 1: Fast nodes (with target OK when require_target=True)."""
    return _select(state, "fast", n, require_target)


def backup(state, n, require_target=True, exclude=None):
    """Category 2: Connected target-OK nodes that are slightly slower (or overflow from fast)."""
    exclude = exclude or set()
    out = []
    # Include overflow from 'fast' that didn't fit in best_n, plus 'backup'
    candidates = (
        _select(state, "fast", n + len(exclude), require_target)
        + _select(state, "backup", n + len(exclude), require_target)
    )
    if require_target:
        candidates = [r for r in candidates if target_now(r)]
    seen = set(exclude)
    for r in candidates:
        k = ident(r)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
        if len(out) >= n:
            break
    return out


def general(state, n=100, exclude=None, allow_recent_fails=2):
    """Category 3: Connected, healthy nodes that did NOT pass target check
    (target_ok == 0) — kept so the user never stays without a node and can
    still connect to general web."""
    exclude = exclude or set()
    items = []
    for r in state.values():
        if r.get("successes", 0) < 1:
            continue
        if is_dead(r):
            continue
        if r.get("consecutive_fails", 0) > allow_recent_fails and not r.get("golden"):
            continue
        if r.get("tier") == "slow":
            continue
        k = ident(r)
        if k in exclude:
            continue
        if not target_now(r) or r.get("tier") == "general":
            items.append(r)
    items.sort(key=lambda r: (r.get("score", 0), -(r.get("avg_latency") or r.get("latency") or 9999)), reverse=True)
    return items[:n]


def dead_nodes(state: dict):
    """Records that failed their most recent check (for `pick` → f → dead)."""
    return [r for r in state.values()
            if r.get("successes", 0) >= 1 and (r.get("alive_now") is False
                                               or r.get("tier") == "dead")]


def all_alive(state, require_target=True, allow_recent_fails=2,
              include_dead: bool = False):
    """Currently usable nodes.

    `include_dead=True` is for the re-check phase ONLY: nodes that failed their
    last check must be re-tested too, otherwise a single bad round would shrink
    the pool forever and nothing could ever be revived.
    """
    items = []
    for r in state.values():
        if r.get("successes", 0) < 1:
            continue
        if not include_dead and is_dead(r):
            continue
        if require_target and not target_now(r):
            continue
        # stale nodes: 3+ consecutive failures drops them out of outputs
        # (they stay in state until prune and can rise again — the state
        # file is memory; best/bak/connect want CURRENTLY useful nodes).
        # Golden pins still pass by design: the user chose them.
        if r.get("consecutive_fails", 0) > allow_recent_fails and not r.get("golden"):
            continue
        items.append(r)
    tier_order = {"fast": 0, "backup": 1, "general": 2, "slow": 3, "dead": 9}
    items.sort(key=lambda r: (tier_order.get(r.get("tier"), 4), -r.get("score", 0)))
    return items


# ───────────────────────── golden list ─────────────────────────

def set_golden(state: dict, ident: str, on: bool = True) -> dict | None:
    """Pin/unpin a node as golden. Returns the record or None."""
    r = state.get(ident)
    if r is None:
        return None
    if on:
        r["golden"] = True
        r["golden_ts"] = int(time.time())
    else:
        r.pop("golden", None)
        r.pop("golden_ts", None)
    return r


def golden(state: dict) -> list[tuple[str, dict]]:
    """[(ident, rec)] pinned golden, newest pin first — may include currently
    dead nodes on purpose (they might come back after a few days)."""
    items = [(k, r) for k, r in state.items() if r.get("golden")]
    items.sort(key=lambda it: it[1].get("golden_ts", 0), reverse=True)
    return items
