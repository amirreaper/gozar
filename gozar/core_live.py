"""The default mode: keep what is ALIVE and USABLE, not what passed a URL.

The old behaviour forced a choice between two bad defaults:
  * `targets` set  -> a node that carries traffic but cannot open the one URL
                      you happened to name is treated as garbage (on a filtered
                      line that is most nodes, and the report looks like a
                      total washout);
  * `targets` empty -> liveness-only, and nothing proves the node carries
                      anything but a 204.

The honest middle is one question, asked of every node:
    did it carry real HTTP both ways, prove a different exit IP, and pass the
    target list IF a target list exists?
That is "alive and usable". It is what `gen.txt` was always for, and it is what
best/bak need to be built from — speed only ranks a node AFTER this question.

This module owns that rule so the files, the counts, the display and the
tests cannot drift apart:

  verdict(rec)  -> ususable | no_target | no_page | leak | dead
  live_recs()   -> the usable set (golden always included), fastest first
  mix()         -> target-OK nodes first, then the live ones that missed a
                   target, so best/bak always have something in them

Nothing here invents measurement. Every field it reads is written by the tester.
"""
from __future__ import annotations

from . import core_store as store

# a node may be listed while it still has an untouched failure, because
# consecutive_fails is reviewed by the next `check`; anything beyond this is
# already on its way out (prune_failures decides the final exit).
_MAX_FAILS = 2


def verdict(rec: dict) -> str:
    """Why this node is (or is not) usable. One word, no guessing."""
    if not rec:
        return "dead"
    if rec.get("golden"):
        # pinned by the user: exempt from removal, and exempt from my opinion
        return "usable"
    if rec.get("leak"):
        return "leak"
    if rec.get("alive_now") is False or rec.get("tier") == "dead":
        return "dead"
    if rec.get("successes", 0) < 1:
        return "dead"
    # A page that came back 429/503 is a THROTTLE, not a dead node: the tunnel
    # carried the request and the host refused this exit IP. Treating it as
    # "no_page" buried healthy nodes (Google rate-limits datacenter ranges).
    if rec.get("page_ok") is False and not rec.get("page_throttled"):
        return "no_page"
    # 2xx + 94KB, but the body was a JavaScript bootstrap document: the tunnel
    # carried the request and the host answered, and still no page was served.
    # Calling that "usable" is what made a walled node look healthy.
    # only a shell the target does NOT serve to everyone (Google's wall) is
    # evidence against the node; a single-page-app target serves it to all.
    if (rec.get("target_shell") and not rec.get("shell_expected")
            and not rec.get("target_ok_now")):
        return "no_target"
    if rec.get("target_ok_now") is False:
        return "no_target"
    return "usable"


def is_usable(rec: dict, allow_recent_fails: bool = True) -> bool:
    """Alive and usable: carried HTTP, proved its exit, is not over the ceiling."""
    v = verdict(rec)
    if v not in ("usable", "no_target"):
        return False
    # "slow" is the user's own ceiling (backup_max_ms). A node past it is alive
    # but was explicitly declared too slow to list — honouring that here is what
    # kept a 12.3s node out of the files.
    if rec.get("tier") == "slow":
        return False
    if allow_recent_fails and not rec.get("golden"):
        if rec.get("consecutive_fails", 0) > _MAX_FAILS:
            return False
    return True


def _sort_key(rec: dict):
    """Target-OK first, then fastest. Speed NEVER decides the verdict, only
    the order of two nodes that both earned their place."""
    lat = rec.get("avg_latency") or rec.get("latency") or 99999
    return (0 if store.target_now(rec) else 1, lat, -(rec.get("score") or 0))


def live_recs(state: dict, n: int = 200, exclude=None,
              require_target: bool = False) -> list[dict]:
    """The live pool, best-first.

    `require_target=True` = strict mode (only nodes that passed every target).
    `require_target=False` = the DEFAULT: every alive+usable node, target-OK
    ones ranked first but the rest kept instead of thrown away.
    """
    exclude = exclude or set()
    out = []
    for r in state.values():
        if store.ident(r) in exclude:
            continue
        if not is_usable(r):
            continue
        if require_target and not store.target_now(r):
            continue
        out.append(r)
    out.sort(key=_sort_key)
    return out[:n] if n else out


def split_lists(state: dict, n_best: int, n_bak: int, exclude=None,
                live_fallback: bool = False):
    """(best, bak, live_only) under the rule the user asked for by name:

        a node that misses a target does NOT belong in the list, but it must
        not die either — it stays in the live pool (gen.txt) and can still be
        connected to (`--from gen`).

    best  = target-OK, fastest first (<= n_best)
    bak   = the remaining target-OK nodes (<= n_bak)
    live  = alive and usable but short of a target: listed nowhere, still kept

    `live_fallback` (off by default) is the escape hatch: if NOT ONE node passed
    the targets, the live pool fills best/bak instead and the caller is told.
    Empty lists are the honest default — what was missing in the 2026-11-15 run
    was not a filled list, it was an EXPLANATION, and that is what the caller
    prints (`bot list` / the end-of-run warning both name the reason).
    """
    live = live_recs(state, n=0, exclude=exclude)
    ok = [r for r in live if store.target_now(r)]
    rest = [r for r in live if not store.target_now(r)]
    best = ok[:n_best]
    bak = ok[n_best:n_best + n_bak]
    degraded = False
    if not best and not bak and live and live_fallback:
        best, bak = live[:n_best], live[n_best:n_best + n_bak]
        degraded = True
        rest = []
    return best, bak, rest, degraded


def mix(state: dict, n: int, exclude=None):
    """Split the live pool into (best, bak), target-OK ALWAYS ahead of the rest.

    One ordered list, split sequentially:
        [target-OK, fastest first] ++ [alive but missed a target, fastest first]
    first `n` -> best, remainder -> bak.

    The earlier version interleaved them (rest was appended inside best), so the
    two nodes that FAILED their target with 2.3s and 12.3s landed in best while
    three target-OK nodes at 299-435ms fell to bak. Ordering is the whole point
    of this function: a proven node is never behind an unproven one.
    """
    # n=0 -> the whole live pool: capping here would starve bak of exactly the
    # nodes best did not take (a 9-node pool with n=4 used to give bak=0).
    live = live_recs(state, n=0, exclude=exclude)
    ok = [r for r in live if store.target_now(r)]
    rest = [r for r in live if not store.target_now(r)]
    ordered = ok + rest
    best = ordered[:n]
    bak = ordered[n:]
    return best, bak
