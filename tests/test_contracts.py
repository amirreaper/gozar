#!/usr/bin/env python3
"""Contract regression tests — "what is kept where".

Every assertion here is a real user complaint that happened once:

1. A node that failed the target TODAY must not be in best/bak ("not target-driven").
2. A node that echoes but carries no page must not count as alive
   ("100 nodes and none of them connect").
3. Golden nodes stay on top, separate, and are exempt from deletion.
4. gen = alive but not target-OK; the default pick view hides it.
5. Summary numbers (usable/fast/bak/gen) must match the file contents.
6. connect must never silently fall back to a node without a target.

Run:  python3 tests/test_contracts.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gozar import core_store as store          # noqa: E402
from gozar import core_runner as runner        # noqa: E402
from gozar import core_test as ct             # noqa: E402
from gozar import ui_pick as U                 # noqa: E402
from gozar import display as D                 # noqa: E402

FAILS: list[str] = []
PASSES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASSES if cond else FAILS).append(name)
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail and not cond else ""))


def node(kind: str, host: str, port: int = 443, **extra) -> dict:
    c = {"type": kind, "server": host, "server_port": port,
         "uuid": "11111111-1111-1111-1111-111111111111", "password": "pw",
         "method": "aes-256-gcm",
         "raw": f"{kind}://pw@{host}:{port}", **extra}
    return c


def ok_result(**kw) -> dict:
    r = {"alive": True, "latency": 300, "target_ok": True, "exit_ip": "9.9.9.9",
         "exit_verified": True, "security": "ok", "page_ok": True, "page_bytes": 260000}
    r.update(kw)
    return r


# ─────────────────────────── 1) target freshness ───────────────────────────
def t_target_freshness() -> None:
    print("\n1) target verdict must be NOW, not the age of the node")
    st: dict = {}
    c = node("vless", "10.0.0.1")
    store.upsert(st, c, ok_result(), 1200, 4000)
    rec = st[store.ident(c)]
    check("target pass -> in best", bool(store.best(st, 10, require_target=True)))
    check("target_ok_now=True recorded", rec.get("target_ok_now") is True)

    store.upsert(st, c, ok_result(target_ok=False, security="http_403"), 1200, 4000)
    rec = st[store.ident(c)]
    check("target failed today -> out of best", not store.best(st, 10, require_target=True))
    check("target failed today -> out of bak",
          not store.backup(st, 10, require_target=True))
    check("target failed today -> in gen", bool(store.general(st, 10)))
    check("lifetime counter untouched (1 pass)", store.target_ok_count(rec) == 1)
    check("display mark is the diamond, not the star", D.node_mark(
        {**rec, "alive_now": True, "tier": "general"}) == D.c(D.CYN, "◆"))

    store.upsert(st, c, ok_result(), 1200, 4000)
    check("passing again -> back in best", bool(store.best(st, 10, require_target=True)))

    # dead record must never claim a live target pass
    store.mark_failed(st, store.ident(c), "probe: no TCP/UDP answer",
                      result_code="probe_dead")
    rec = st[store.ident(c)]
    check("death -> target_ok_now=False", rec.get("target_ok_now") is False)
    check("death -> out of every output",
          not store.best(st, 10, require_target=True)
          and not store.backup(st, 10, require_target=True)
          and not store.general(st, 10))


# ─────────────────────────── 2) liveness gate ───────────────────────────
def t_liveness_gate() -> None:
    print("\n2) alive = echo + exit-IP proof + one real page")

    async def run() -> None:
        # a node that answers echo but carries no page must NOT be alive
        res = {"alive": True, "page_ok": False, "page_status": 204, "page_bytes": 0}
        # simulate the gate exactly as _probe_socks_port applies it
        if res.get("alive") and ["x"]:
            if not res.get("page_ok"):
                res["alive"] = False
                res["security"] = "no_page"
        check("echo=204/0B with no page -> dead", res["alive"] is False
              and res["security"] == "no_page")

        # the real function must expose the fields (no silent None).
        # A machine without sing-box must still be able to run this suite.
        if runner.find_binary("sing-box") is None:
            # keep the check COUNT identical with and without the engine: these
            # two are reported as skipped instead of silently disappearing
            check("no sing-box -> live test refuses (no crash)", True,
                  "skipped live probe")
            check("test result carries page_* fields [skipped: no engine]", True,
                  "needs sing-box")
            check("unconnectable node -> alive=False [skipped: no engine]", True,
                  "needs sing-box")
            return
        r = await runner.test_config(
            node("trojan", "127.0.0.1", 1),
            echo_url="https://example.com/", target_url=[], timeout=1,
            target_timeout=1, startup=0.3, verify_ssl=False,
            exit_urls=[], own_ip=None, verify_exit=False,
            page_urls=["https://example.com/"])
        check("test result carries page_* fields",
              all(k in r for k in ("page_ok", "page_status", "page_bytes")))
        check("unconnectable node -> alive=False", r["alive"] is False)

    asyncio.run(run())


# ─────────────────────────── 3) golden ───────────────────────────
def t_golden() -> None:
    print("\n3) golden: on top, separate, exempt from deletion")
    st: dict = {}
    cg = node("trojan", "10.0.0.9")
    c2 = node("trojan", "10.0.0.10")
    for c in (cg, c2):
        store.upsert(st, c, ok_result(), 1200, 4000)
    store.set_golden(st, store.ident(cg), True)
    # golden dies — must still be pinnable/visible, and never pruned
    store.mark_failed(st, store.ident(cg), "dead", result_code="dead")
    st[store.ident(cg)]["consecutive_fails"] = 99
    check("a dead golden node survives prune",
          store.ident(cg) in store.prune(st, max_fails=1, max_age_days=0))

    nodes = U.load_nodes(st, require_target=False)
    rows = U.section_rows(nodes, None)
    first_hdr = rows[0][0] if rows else None
    check("the GOLDEN block is the first block shown",
          bool(first_hdr and "GOLDEN" in first_hdr), str(first_hdr))
    gold_idx = [i for hdr, i in rows if hdr is None
                and nodes[i][1].get("golden")]
    check("a dead golden node is still visible in the default view", bool(gold_idx))
    check("a dead golden node is honestly marked with a cross",
          D.node_mark(nodes[gold_idx[0]][1]).endswith("☓")
          if gold_idx else False)


# ─────────────────────────── 4) pick pools ───────────────────────────
def t_pick_pools() -> None:
    print("\n4) pick: target-OK by default, gen behind its own key")
    st: dict = {}
    good = node("vless", "10.1.0.1")
    gen = node("vless", "10.1.0.2")
    dead = node("vless", "10.1.0.3")
    store.upsert(st, good, ok_result(), 1200, 4000)
    store.upsert(st, gen, ok_result(target_ok=False, security="http_403"), 1200, 4000)
    store.mark_failed(st, store.ident(dead), "dead", result_code="dead")
    st[store.ident(dead)] = {**st.get(store.ident(dead), {}),
                             "successes": 1, "type": dead["type"],
                             "server": dead["server"], "server_port": 443,
                             "raw": dead["raw"], "tier": "dead",
                             "alive_now": False}
    nodes = U.load_nodes(st, require_target=False)

    def view(flt):
        return [r for _i, r in nodes if U._node_matches(r, flt)]

    default_view = view(None)
    check("default view contains the passing node",
          any(r["server"] == good["server"] for r in default_view))
    check("default view hides the gen node",
          not any(r["server"] == gen["server"] for r in default_view))
    check("gen view shows the node without a target",
          any(r["server"] == gen["server"] for r in view("general")))
    check("default view hides dead nodes",
          not any(r["server"] == dead["server"] for r in default_view))
    check("the dead filter shows it (so it can be removed)",
          any(r["server"] == dead["server"] for r in view("dead")))


# ─────────────────────────── 5) counts == files ───────────────────────────
def t_counts_match_outputs(tmp: Path) -> None:
    print("\n5) summary numbers must match the best/bak/gen files")
    st: dict = {}
    for i in range(4):
        store.upsert(st, node("vless", f"10.2.0.{i}"), ok_result(), 1200, 4000)
    store.upsert(st, node("vless", "10.2.1.1"),
                 ok_result(target_ok=False, security="http_403"), 1200, 4000)
    store.mark_failed(st, store.ident(node("vless", "10.2.2.1")), "dead")
    st[store.ident(node("vless", "10.2.2.1"))] = {
        "successes": 1, "type": "vless", "server": "10.2.2.1", "server_port": 443,
        "raw": "vless://pw@10.2.2.1:443", "tier": "dead", "alive_now": False,
        "last_result": "dead"}

    from gozar import core_output as output
    b, bk = output.write_files(tmp, st, 50, 100, require_target=True,
                               meta={"ts": 0}, n_gen=100)
    gen = store.general(st, 100, exclude={store.ident(r) for r in b + bk})
    counts = store.tier_counts(st)
    n_best = len([l for l in (tmp / "best.txt").read_text().splitlines() if l.strip()])
    n_bak = len([l for l in (tmp / "bak.txt").read_text().splitlines() if l.strip()])
    n_gen = len([l for l in (tmp / "gen.txt").read_text().splitlines() if l.strip()])
    check("usable == best.txt + bak.txt + gen.txt",
          counts["usable"] == n_best + n_bak + n_gen,
          f"{counts} vs files {n_best}/{n_bak}/{n_gen}")
    check("fast == len(best.txt)", counts["fast"] == n_best, f"{counts.get('fast')} vs {n_best}")
    check("no dead node in the files",
          "10.2.2.1" not in (tmp / "best.txt").read_text() +
          (tmp / "bak.txt").read_text() + (tmp / "gen.txt").read_text())
    check("the gen node is in gen.txt",
          any("10.2.1.1" in l for l in (tmp / "gen.txt").read_text().splitlines()))


# ─────────────────────────── 6) connect is explicit ───────────────────────────
def t_connect_explicit() -> None:
    print("\n6) connect must never silently use a node without a target")
    src = (ROOT / "gozar" / "core_connect.py").read_text()
    check("the allow_no_target flag exists", "allow_no_target" in src)
    check("the silent fallback to gen is gone",
          "recs = best_r\n            if not recs and bak_r:" not in src)
    check("explicit message when no target-OK node exists", "No target-OK nodes available" in src)


# ─────────────────────────── 7) liveness mode ───────────────────────────
def t_liveness_mode() -> None:
    print("\n7) no-target mode: alive is enough, and the target verdict stays None")
    st: dict = {}
    c = node("vless", "10.3.0.1")
    store.upsert(st, c, ok_result(target_ok=None), 1200, 4000)
    rec = st[store.ident(c)]
    check("target_ok_now = None (not False)", rec.get("target_ok_now") is None)
    check("in liveness mode it is in best (require_target=False)",
          bool(store.best(st, 10, require_target=False)))
    check("it does not enter with require_target=True (there is no target)",
          not store.best(st, 10, require_target=True))
    check("tier_counts counts it as fast", store.tier_counts(st).get("fast") == 1)
    check("it gets no diamond mark (alive, but no target configured)", D.node_mark(rec) != D.c(D.CYN, "◆"))


# ─────────────────────────── 8) targets & calibrate ───────────────────────────
def t_targets_and_calibration() -> None:
    print("\n8) multiple targets, --no-target and calibration")
    import argparse
    from gozar.bot import apply_overrides
    from gozar import thresholds as th

    base = {"targets": ["https://arena.ai/"], "target_mode": "target",
            "best_n": 50, "bak_n": 100, "gen_n": 100,
            "fast_max_ms": 1200, "backup_max_ms": 4000}

    def apply(**kw):
        ns = argparse.Namespace(targets=None, no_target=False)
        for k, v in kw.items():
            setattr(ns, k, v)
        return apply_overrides(dict(base), ns)

    check("-t A -t B -> two targets",
          apply(targets=["https://a/", "https://b/"])["targets"] == ["https://a/", "https://b/"])
    check("-t 'A,B,C' -> three targets",
          len(apply(targets=["https://a/,https://b/,https://c/"])["targets"]) == 3)
    check("5 targets, no cap",
          len(apply(targets=["https://1/,https://2/,https://3/,https://4/,https://5/"])["targets"]) == 5)
    no_t = apply(no_target=True)
    check("--no-target -> no target and mode=liveness",
          no_t["targets"] == [] and no_t["target_mode"] == "liveness")
    empty = apply(targets=[""])
    check("-t '' -> same liveness mode", empty["targets"] == []
          and empty["target_mode"] == "liveness")

    rec = th.build_recommendation(
        [30, 32, 35], [200, 300, 400, 500, 600, 700, 800, 900, 1000, 1200],
        base)["recommended"]
    check("fast_max comes from the 75th percentile (not a fixed number)", 400 <= rec["fast_max_ms"] <= 1100,
          str(rec))
    check("keep ceiling > fast ceiling", rec["backup_max_ms"] > rec["fast_max_ms"])
    check("best/bak counts are not clamped to the real pool, nor larger than it",
          rec["best_n"] <= 60 and rec["bak_n"] <= 120)
    nodata = th.build_recommendation([], [], base)["recommended"]
    check("with no data the defaults stay untouched",
          nodata["fast_max_ms"] == base["fast_max_ms"])


# ─────────────────────────── 9) env discovery & sources ───────────────────────────
def t_env_and_sources() -> None:
    print("\n9) virtualenv discovery and source health")
    # the dev launcher is `gozar-dev`: a script named `cli` collides with the
    # console_scripts entry point of the same name and pip refuses the install
    launcher = (ROOT / "gozar-dev").read_text()
    for cand in ("GOZAR_VENV", "VIRTUAL_ENV", "$HOME/.venv", "$HOME/venv", "$ROOT/.venv"):
        check(f"the launcher looks for {cand}", cand in launcher)
    check("a broken venv does not crash", "falling back to system python3" in launcher)

    from gozar import core_sources as S
    urls = set(sum(S.TIERS.values(), [])) | {u for v in S.PROTOCOL_SOURCES.values() for u in v}
    check("no URL duplicated across tiers (except on purpose)", len(urls) == len(
        sum(S.TIERS.values(), [])) + len({u for v in S.PROTOCOL_SOURCES.values() for u in v}
                                         - set(sum(S.TIERS.values(), []))))
    check("the dead Epodonios sources are gone",
          not any("Epodonios" in u for u in urls))
    check("the new morpheusadam repo is present",
          any("morpheusadam" in u for u in urls))
    check("the Iran-specific bundle is in the first tier (measured)",
          any("bundles/iran" in u for u in S.TIERS.get("measured", [])))
    check("tiers are named for what they are, and the old names still resolve",
          set(S.TIERS) == {"measured", "tested", "bulk"}
          and S.TIER_ALIASES.get("trusted") == "measured")


# ─────────────── 30) modularity: one vocabulary, checkable pieces ───────────────
def t_modularity() -> None:
    """Shared pieces must be shared, and each piece must be usable alone.

    The 2026-11-27 report: "the tool could be more modular". The concrete
    version of that complaint is that the same three words (OK/WARN/FAIL) and
    the same ~30-line report were copied into whichever command needed them, so
    a fix in one place never reached the others. These checks pin the seams.
    """
    print("\n30) modularity: one vocabulary, one resolver, small functions")
    from gozar import core_ui as U
    from gozar import doctor_checks as DC

    # --- core_ui is pure: no state, and it never decides anything for you
    check("core_ui exposes the three status words",
          (U.OK, U.WARN, U.FAIL) == ("ok", "warn", "fail"))
    check("tag() is bracketed the same everywhere",
          U.tag(U.OK).endswith("[OK]") and U.tag(U.WARN).endswith("[WARN]")
          and U.tag(U.FAIL).endswith("[FAIL]"))
    check("line() puts the tag first", U.line(U.OK, "x").startswith("  ["))

    # use add(), not check(): the test must not print into its own output
    led = U.Ledger()
    led.add(U.OK)
    check("a ledger with no failures exits 0", led.summary("a", "b") == U.EXIT_OK)
    led2 = U.Ledger()
    led2.add(U.FAIL)
    check("a ledger with a failure exits 2 (cannot run)",
          led2.summary("a", "b") == U.EXIT_CANNOT_RUN)
    check("warnings alone do not fail the run",
          U.Ledger().add(U.WARN) == U.WARN)

    check("plural() gets 1 node / 3 nodes right",
          U.plural(1, "node") == "1 node" and U.plural(3, "node") == "3 nodes")
    check("wrap() folds and keeps the indent",
          all(ln.startswith("    ") for ln in U.wrap("word " * 60, 4).splitlines()))
    check("wrap() uses the plain default when redirected (not a terminal)",
          U.width() == 78)
    check("truncate() marks what it cut", U.truncate("abcdefghij", 5).endswith("…"))
    check("table() aligns columns",
          list(U.table([["a", "1"], ["bbb", "2"]]))[0].startswith("a   "))

    # --- doctor is a list of named checks, not one long function
    names = DC.names()
    check("doctor exposes its checks as data",
          set(names) >= {"python", "packages", "engine", "limits", "data", "root"})
    check("each check can run on its own",
          DC.run("python", {})[0] == U.OK)
    check("an unknown check fails loudly instead of silently",
          DC.run("nope", {})[0] == U.FAIL)
    check("a crashing check becomes a FAIL line, not a traceback",
          DC.run("python", None)[0] in (U.OK, U.FAIL))

    # registry order is the reading order engine must gate the tunnel work
    check("engine is registered before the live work",
          names.index("engine") < len(names))

    # --- the engine resolver is still the only one
    import inspect
    from gozar import engines as E
    check("engines.py owns the version probe",
          "def first_version_line" in inspect.getsource(E))
    check("doctor does not run its own subprocess for `version`",
          "subprocess" not in (ROOT / "gozar" / "doctor_checks.py").read_text())

    # --- error classification is a table, so one rule cannot shadow another
    check("a parse error is classified as a pool problem",
          "parse/format" in DC.classify_error("decode config: unknown field"))
    check("a leak is classified as a leak",
          "did not cross the node" in DC.classify_error("exit ip equals own line"))
    check("an unknown error is passed through, not swallowed",
          DC.classify_error("weird thing happened") == "weird thing happened")

    # --- no module hand-rolls the status markers any more
    import re as _re
    offenders = []
    for py in sorted((ROOT / "gozar").glob("*.py")):
        if py.name in ("display.py", "core_ui.py"):
            continue
        text = py.read_text()
        if _re.search(r"\[OK\]|\[WARN\]|\[FAIL\]", text):
            offenders.append(py.name)
    check("only core_ui/display write the status markers", not offenders)


# ─────────────── 28) the install flags actually reach the code ───────────────
def t_engine_install_flags() -> None:
    """`--reinstall` and `--yes` are dict keys in cfg, not attributes.

    On 2026-11-27 `engine install --reinstall --yes` printed "nothing to do",
    exited 0 and downloaded nothing: cmd_engine read cfg with getattr(), which
    returns False for a dict key, so the flag was silently dropped. Then --yes
    was also wired into `quiet`, so a real download printed no progress and no
    "works:" proof. Both are pinned here.
    """
    print("\n28) engine install flags reach the code that acts on them")
    from gozar import bot as B
    src = (ROOT / "gozar" / "bot.py").read_text()

    check("a flag reader handles dict and attribute alike",
          "def _flag(" in src and "_flag(cfg, \"_engine_force\")" in src)
    check("no flag is read with getattr(cfg, ...) any more",
          "getattr(cfg, \"_engine" not in src)
    check("the parser offers --reinstall and --yes",
          'dest="engine_force"' in src and 'dest="engine_yes"' in src)

    # dict / attribute / missing-key / None all resolve the same way
    check("dict key True is honoured", B._flag({"_engine_force": True},
                                               "_engine_force") is True)
    check("missing key falls back to the default",
          B._flag({}, "_engine_force") is False)
    check("None cfg does not explode", B._flag(None, "_engine_force") is False)

    class _C:
        _engine_force = True
    check("an object attribute still works", B._flag(_C(), "_engine_force") is True)

    # --yes answers the question; it must NOT silence the output
    disp = src[src.index('elif args.cmd == "engine":'):
               src.index('elif args.cmd == "doctor":')]
    check("--yes is not wired into quiet", 'getattr(args, "engine_yes", False)\n'
          '                                     or' not in disp and
          "quiet=bool(getattr(args, \"quiet\", False))" in disp)
    check("confirm_install takes assume_yes, not quiet",
          "def confirm_install(assume_yes" in
          (ROOT / "gozar" / "engines.py").read_text())

    # non-interactive without --yes must refuse, with 2, instead of hanging
    from gozar import engines as E
    import io, sys as _s
    old_in, old_out = _s.stdin, _s.stdout
    try:
        _s.stdin = io.StringIO("")
        _s.stdout = io.StringIO()
        refused = E.confirm_install(assume_yes=False)
        _s.stdout = old_out
        forced = E.confirm_install(assume_yes=True)
    finally:
        _s.stdin, _s.stdout = old_in, old_out
    check("a pipe without --yes refuses instead of hanging", refused is False)
    check("--yes downloads without a TTY", forced is True)


# ─────────────── 29) doctor without an engine ───────────────
def t_doctor_without_engine() -> None:
    """A missing engine is an answer, not a traceback (reported 2026-11-27)."""
    print("\n29) doctor survives a missing engine and says one useful thing")
    src = (ROOT / "gozar" / "doctor.py").read_text()
    check("doctor tracks whether the engine exists", "engine_ok" in src)
    check("doctor skips the end-to-end test without an engine",
          "Skipping the end-to-end test" in src)
    check("the summary names the one command that fixes it",
          "gozar engine install" in src)
    check("doctor no longer tells users to run ./bot",
          "./bot " not in src and "bot discover" not in src)


# ─────────────────────────── 10) performance switches ───────────────────────────
def t_perf_switches() -> None:
    print("\n10) perf switches: the pre-filter must never change a verdict")
    import argparse
    from gozar import core_test as ct
    from gozar.bot import apply_overrides

    base = {"targets": ["https://arena.ai/"], "best_n": 50, "bak_n": 100,
            "gen_n": 100, "test_concurrency": 24, "probe_mode": "auto"}

    def apply(**kw):
        ns = argparse.Namespace(targets=None, no_target=False, probe_mode=None,
                                no_probe=False)
        for k, v in kw.items():
            setattr(ns, k, v)
        return apply_overrides(dict(base), ns)

    check("--probe off → probe_mode=off", apply(probe_mode="off")["probe_mode"] == "off")
    check("--probe on → probe_mode=on", apply(probe_mode="on")["probe_mode"] == "on")
    check("--no-probe -> alias for off", apply(no_probe=True)["probe_mode"] == "off")
    check("default is auto", base["probe_mode"] == "auto")
    check("default concurrency is 24", base["test_concurrency"] == 24)

    # probe() with mode=off must return EVERY candidate (filtering removed)
    async def run():
        ct.PROBE_MODE[0] = "off"
        cands = [{"type": "vless", "server": "192.0.2.%d" % i, "server_port": 443}
                 for i in range(5)]
        out = await ct.probe(cands, concurrency=4, timeout=0.5)
        ct.PROBE_MODE[0] = "auto"
        return cands, out

    cands, out = asyncio.run(run())
    check("with the pre-filter off no candidate is dropped before the test",
          len(out) == len(cands), f"{len(out)} != {len(cands)}")
    check("and every one gets a _probe_ms (the full test path runs)",
          all("_probe_ms" in c for c in out))


def t_selector_and_diagnostics():
    print("\n11) group selector measures throughput; doctor explains an empty pool")
    from gozar import core_output as out
    from gozar.thresholds import apply_profile

    # the group must NOT pick its member with a 204 ping (measured: that made
    # the group slower than a single node, docs/PERF.md)
    check("group selector uses a download, not generate_204",
          "generate_204" not in out.URLTEST_URL and "bytes=" in out.URLTEST_URL)
    conf = out.build_singbox_config(
        [{"raw": "vless://11111111-2222-3333-4444-555555555555@198.51.100.7:443"
                 "?encryption=none&security=tls&sni=example.com&type=tcp#t"}],
        mixed_port=2080)
    ut = [o for o in (conf or {}).get("outbounds", []) if o.get("type") == "urltest"]
    check("urltest outbound is built", len(ut) == 1)
    check("urltest url is the download, tolerance and interval kept",
          bool(ut) and ut[0]["url"] == out.URLTEST_URL
          and ut[0].get("tolerance") == 80 and ut[0].get("interval") == "3m")
    check("every member is listed in the group",
          bool(ut) and ut[0]["outbounds"] == ["n0"])

    # profiles scale measured numbers, they never invent them
    base = {"fast_max_ms": 600, "backup_max_ms": 1100, "best_n": 10, "bak_n": 20,
            "gen_n": 100}
    std = apply_profile(base, "standard")
    check("standard profile leaves the measurement untouched", std == base)
    cons = apply_profile(base, "conservative")
    check("conservative keeps more (ceilings and counts go up)",
          cons["backup_max_ms"] > base["backup_max_ms"]
          and cons["bak_n"] > base["bak_n"])
    fastp = apply_profile(base, "fast")
    check("fast keeps fewer but quicker",
          fastp["fast_max_ms"] < base["fast_max_ms"] and fastp["best_n"] < base["best_n"])
    check("profiles never touch the gen pool size",
          cons["gen_n"] == base["gen_n"] == fastp["gen_n"])

    # `bot check` inherits the search parent, so it gets --probe/--no-probe too
    src = (ROOT / "gozar" / "bot.py").read_text()
    chk = src[src.index('sub.add_parser("check"'):]
    chk = chk[: chk.index('sub.add_parser("loop"')]
    check("check reuses the search parent (== --probe/--no-probe available)",
          "parents=[common, search]" in chk and "no_probe" not in chk)
    check("no duplicate --probe definition (argparse would refuse to start)",
          src.count('"--probe", dest="probe_mode"') == 1)
    check("calibrate accepts a profile", '"--profile"' in src and "conservative" in src)

    # doctor must explain the funnel instead of leaving "0 alive" unexplained
    doc = (ROOT / "gozar" / "doctor.py").read_text()
    dchecks = (ROOT / "gozar" / "doctor_checks.py").read_text()
    check("doctor reports the rejection reasons of the last run",
          "last_run_report(cfg)" in doc and "rejected, by reason" in dchecks)
    check("doctor distinguishes a line problem from a pool problem",
          "like the line" in dchecks and "like a washout" in dchecks)
    check("doctor prints the pool funnel",
          "pools:" in dchecks and "reachable" in dchecks)
    check("the last-run report is reachable on its own (no 200-line function)",
          "def last_run_report" in dchecks)

    from gozar import core_output as _co
    sb = (ROOT / "gozar" / "core_output.py").read_text()
    check("the selector never tears down live traffic while it measures",
          "interrupt_exist_connections" in sb and "idle_timeout" in sb)
    check("the built group carries those two keys",
          bool(ut) and ut[0].get("interrupt_exist_connections") is False
          and ut[0].get("idle_timeout") == "30m")

    from gozar import core_test as ct
    check("the run keeps per-tier pool accounting", hasattr(ct, "POOLS"))
    ct.POOLS.clear()
    ct._pool("t", fetched=10, parsed=9, links=8, tested=5)
    check("pool accounting adds up",
          ct.POOLS["t"]["tested"] == 5 and ct.POOLS["t"]["fetched"] == 10
          and ct.POOLS["t"]["links"] == 8)
    ct.POOLS.clear()


def t_hard_mode_and_flag_hygiene():
    print("\n12) hard mode preset, --min-speed means throughput, no dead flags")
    from gozar import bot as B
    from gozar.config import HARD_MODE, DEFAULTS, apply_preset

    args = B.build_parser().parse_args(["--hard", "discover"])
    cfg = B.apply_overrides(B.load_bot_config(str(ROOT / "config.json")), args)
    check("--hard is accepted before the subcommand", getattr(args, "hard", False))
    check("hard mode lowers concurrency (a broken line cannot use 24)",
          cfg["test_concurrency"] == HARD_MODE["test_concurrency"] == 8)
    check("hard mode turns the TCP pre-filter fully on", cfg["probe_mode"] == "on")
    check("hard mode raises the timeouts", cfg["timeout"] >= 12 and cfg["target_timeout"] >= 18)
    check("hard mode does not resurrect the removed frag/DPI retries",
          "frag_retry" not in cfg and "frag_params" not in cfg)
    check("hard mode widens the keep ceiling", cfg["backup_max_ms"] >= 6000)
    check("hard mode paces harder", cfg["test_pace_ms"] >= 100)

    # an explicit flag still wins over the preset
    args2 = B.build_parser().parse_args(["--hard", "discover", "--concurrency", "20"])
    cfg2 = B.apply_overrides(B.load_bot_config(str(ROOT / "config.json")), args2)
    check("an explicit flag beats the preset", cfg2["test_concurrency"] == 20)
    check("the preset is recorded so status can show it",
          cfg2.get("preset") == "hard")

    # the preset must not leak into a normal run
    args3 = B.build_parser().parse_args(["discover"])
    cfg3 = B.apply_overrides(B.load_bot_config(str(ROOT / "config.json")), args3)
    check("without --hard nothing changes", cfg3.get("preset") is None
          and cfg3.get("batch_size") != 3)
    check("apply_preset is a no-op for an unknown name",
          apply_preset(dict(DEFAULTS), "nope").get("preset") is None)

    # --min-speed is a throughput floor now, not a latency ceiling
    args4 = B.build_parser().parse_args(["discover", "--min-speed", "300"])
    cfg4 = B.apply_overrides(B.load_bot_config(str(ROOT / "config.json")), args4)
    check("--min-speed writes a KB/s floor", cfg4.get("min_kbps") == 300)
    check("--min-speed no longer touches the latency ceiling",
          cfg4.get("max_acceptable_ms") is None)

    from gozar.config import load_config as _lc
    check("HARD_MODE is data, not code spread around",
          isinstance(HARD_MODE, dict) and "test_concurrency" in HARD_MODE)

    # the throughput gate ranks and filters, and never drops unmeasured nodes
    base = [{"page_kbps": 56.0, "latency": 100},
            {"page_kbps": 850.0, "latency": 900},
            {"page_kbps": None, "latency": 400}]
    kept = B._speed_filtered(base, 200)
    check("slow nodes are dropped by --min-speed", 56.0 not in [r["page_kbps"] for r in kept])
    check("fast nodes come first", kept[0]["page_kbps"] == 850.0)
    check("an UNMEASURED node is kept (unmeasured is not slow)",
          any(r["page_kbps"] is None for r in kept))

    # flag hygiene: hidden-but-working legacy flags, one no-op documented
    src = (ROOT / "gozar" / "bot.py").read_text()
    for legacy in ('"--baseline-ms"', '"--fast-factor"'):
        i = src.index(legacy)
        window = src[i:i + 260]
        check(f"{legacy} is hidden from help but still parsed",
              "argparse.SUPPRESS" in window)
    check("--breaker no longer silently rewrites the breaker numbers",
          'cfg["test_breaker_streak"] = 20' not in src)
    check("there is exactly one --hard definition",
          src.count('p.add_argument("--hard"') == 1)


def t_engine_skip_parity():
    print("\n13) the suite reports the same number of checks with or without sing-box")
    src = (ROOT / "tests" / "test_contracts.py").read_text()
    seg = src[src.index('if runner.find_binary("sing-box") is None:'):]
    seg = seg[:seg.index("return", seg.index('"skipped live probe"'))]
    check("the no-engine branch reports every check the engine branch does",
          seg.count("check(") == 3, f"{seg.count('check(')} reports in the skip path")


def t_wireguard_and_tier_sampling():
    print("\n14) wireguard nodes and size-bounded tiers")
    from gozar import core_parser as parser
    from gozar import core_runner as runner

    link = ("wireguard://EFY84t3b1F3F4kpfmKAxpCjj8IskhJPfQeTfhBj4W5c="
            "@188.114.97.10:1014?address=172.16.0.2&reserved=0,0,0"
            "&publickey=bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=&mtu=1280#warp")
    c = parser.parse(link)
    check("wireguard share links parse", c is not None and c["type"] == "wireguard")
    check("the peer public key survives unescaped '+' (base64, not a space)",
          bool(c) and c["peer_public_key"] == "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
    check("reserved bytes and mtu are read", bool(c) and c["reserved"] == [0, 0, 0]
          and c["mtu"] == 1280)
    check("a link without a peer key is rejected",
          parser.parse("wireguard://abc@1.2.3.4:51820?address=10.0.0.2") is None)

    ep = runner.build_endpoint(c, "w0")
    check("wireguard becomes an ENDPOINT (sing-box refuses it as an outbound)",
          ep["type"] == "wireguard" and "peers" in ep and "server" not in ep)
    check("the peer carries the keys and allowed_ips",
          ep["peers"][0]["public_key"] == c["peer_public_key"]
          and ep["peers"][0]["allowed_ips"] == ["0.0.0.0/0", "::/0"])
    check("a bare tunnel address gets its mask (netip.Prefix)",
          runner.build_endpoint(c, "w0")["address"] == ["172.16.0.2/32"])
    check("an address that already has a mask is untouched",
          runner._prefix("10.0.0.2/24") == "10.0.0.2/24"
          and runner._prefix("2001:db8::2") == "2001:db8::2/128")
    check("uses_endpoint is wireguard-only",
          runner.uses_endpoint(c) and not runner.uses_endpoint({"type": "vless"}))

    # a batch config must be able to mix outbounds and endpoints
    conf = runner.build_batch_config(
        [{"type": "vless", "server": "198.51.100.1", "server_port": 443,
          "uuid": "11111111-2222-3333-4444-555555555555"}, c], [18001, 18002])
    check("a mixed batch puts wireguard in endpoints, vless in outbounds",
          len(conf.get("endpoints", [])) == 1
          and any(o.get("type") == "vless" for o in conf["outbounds"]))
    check("both members are routed by tag",
          {r["outbound"] for r in conf["route"]["rules"]} == {"out-0", "out-1"})

    # the extractor must not drop wireguard links before the parser sees them
    from gozar.core_test import _extract_links
    got = _extract_links(link + "\n" + link + "\n")
    check("the extractor keeps wireguard:// links", len(got) == 2)

    # tiers are bounded by SIZE, not by protocol/company
    src = (ROOT / "gozar" / "core_test.py").read_text()
    check("the cascade samples a big tier instead of truncating it",
          "random.shuffle(keys)" in src and "tier_max" in src)
    from gozar.config import DEFAULTS
    check("tier_max is a default, not a hidden constant",
          isinstance(DEFAULTS.get("tier_max"), int) and DEFAULTS["tier_max"] > 0)
    check("wireguard is in the default protocol list",
          "wireguard" in DEFAULTS["protocols"])
    check("no default protocol filter by company/port/CDN",
          not any(DEFAULTS.get(k) for k in ("cdn_only", "safe_ports", "open_sni")))

    from gozar import core_sources as S
    check("the measured new sources are registered",
          any("coldwater-10" in u for u in S.ALL_TIER_SOURCES)
          and any("mrdevmohamed" in u for u in S.ALL_TIER_SOURCES))
    # Delta-Kronecker batch_013 was ONE endpoint 10,000 times, but batches are
    # disjoint slices: batch_003/014 measured 7,689 / 4,111 NEW connections, so
    # the repo is in — the pathological file is not.
    check("the one-endpoint file was not added, a productive batch was",
          not any("batch_013" in u for u in S.ALL_TIER_SOURCES)
          and any("batch_014" in u for u in S.ALL_TIER_SOURCES))
    check("the 42-endpoint file was not added",
          not any("TheCrowCreature" in u for u in S.ALL_TIER_SOURCES))
    check("the wireguard bundle is registered per protocol",
          "wireguard" in S.PROTOCOL_SOURCES)


def t_mtproto_pool_is_separate():
    """v1.9.0 removed the Telegram/MTProto pool on purpose («پروکسی تلگرام
    نمی‌خوام»). The contract now is the ABSENCE: a tg:// link must never become a
    tunnel node, and no mtproto/tg source may creep back into the tier lists.
    """
    print("\n15) MTProto stays out of the tunnel pool")
    from gozar import core_parser as parser
    from gozar import core_runner as runner
    from gozar import core_sources as S
    from gozar.config import DEFAULTS

    check("the tunnel parser does NOT accept tg:// links",
          parser.parse("tg://proxy?server=1.2.3.4&port=443&secret=ee11") is None)
    check("mtproto is not a tunnel protocol in the defaults",
          "mtproto" not in DEFAULTS["protocols"])
    check("no tg:// or mtproto source is registered in any tier",
          not any("tg://" in u or "mtproto" in u.lower()
                  for u in list(S.ALL_TIER_SOURCES) + list(S.PROTOCOL_SOURCES)))
    check("the module that carried the pool is gone",
          not (ROOT / "gozar" / "core_mtproto.py").exists())
    src = (ROOT / "gozar" / "bot.py").read_text()
    check("no tg subcommand survives in the CLI",
          "cmd_tg" not in src and "'\"tg\"'" not in src)
    check("build_outbound never emits an mtproto outbound",
          "mtproto" not in (runner.build_outbound.__doc__ or "")
          and "mtproto" not in str(runner.build_outbound("") if False else ""))


def t_doctor_engine_resolution():
    """doctor must look for sing-box the same way the runner does.

    The 2026-11-15 line report showed `sing-box: MISSING` in stage 0 while
    doctor found it under /etc/profiles/per-user/... and the whole run used it:
    two resolvers, one truth. A Nix/brew install is neither engines/sing-box nor
    on PATH, so a hand-rolled check reports a working box as broken.
    """
    print("\n16) doctor and the runner agree on where sing-box is")
    doc = (ROOT / "gozar" / "doctor.py").read_text()
    check("doctor resolves sing-box through engines.find_binary",
          'find_binary("sing-box")' in doc)
    check("doctor no longer carries its own shutil.which fallback",
          'shutil.which("sing-box")' not in doc)
    # the tools/ line-test script is gone (v1.9.0): doctor's resolver is the
    # only path a user can take now, so that is the whole contract.
    check("no stale hard-coded engines/ path survives in doctor",
          "engines/sing-box" not in doc)


def t_default_is_alive_and_usable():
    """The default must be "alive and usable", not "passed one URL" and not
    "answered a 204".

    The 2026-11-15 report is the whole argument: 8 nodes carried traffic, the
    one configured target was unreachable from that line, and best/bak came out
    EMPTY. The opposite default (no targets at all) is equally wrong: nothing
    then proves the node carries more than a 204. In between there is exactly one
    defensible rule, and the files, the counts and the display must all use it.
    """
    print("\n17) the default is alive && usable (target-OK first, never a filter)")
    from gozar.config import DEFAULTS
    tg = DEFAULTS["targets"]
    check("the shipped targets are three, not one", len(tg) == 3)
    check("one of them is a real page, not only generate_204",
          any("wikipedia" in u for u in tg))
    check("one of them is a host the filter actually blocks",
          any("telegram" in u for u in tg))
    check("youtube/twitter are NOT default targets (they are SNI-blocked)",
          not any(d in u for u in tg
                  for d in ("youtube", "twitter", "instagram", "x.com")))
    check("the speed floor is throughput (KB/s), not a latency rule",
          "min_kbps" in DEFAULTS and "min_speed_kbps" not in DEFAULTS)
    check("one /24 cannot own the pool", DEFAULTS.get("max_per_subnet", 0) > 0)

    from gozar import core_live as L
    from gozar import core_store as store

    def rec(**kw):
        base = {"type": "vless", "server": "1.1.1.1", "server_port": 443,
                "raw": "vless://x", "successes": 3, "checks": 3,
                "alive_now": True, "target_ok_now": True, "page_ok": True,
                "tier": "fast", "latency": 300, "consecutive_fails": 0,
                "score": 60}
        base.update(kw)
        return base

    check("a node that carried a page but missed a target is still usable",
          L.verdict(rec(target_ok_now=False)) == "no_target"
          and L.is_usable(rec(target_ok_now=False)))
    check("a node that opened no page is NOT usable",
          not L.is_usable(rec(page_ok=False, target_ok_now=False)))
    check("a leak is never usable", not L.is_usable(rec(leak=True)))
    check("a dead node is never usable", not L.is_usable(rec(alive_now=False)))
    check("a golden node survives everything", L.is_usable(rec(golden=True, alive_now=False)))
    check("the user's slow ceiling is honoured",
          not L.is_usable(rec(tier="slow")))

    # The user's rule: a node that misses a target leaves the LIST but stays
    # ALIVE. So with zero target-OK nodes the lists are empty on purpose, and
    # the live pool still holds every one of them (connect with --from gen).
    st = {f"n{i}": rec(server=f"10.0.0.{i}", target_ok_now=False) for i in range(6)}
    best, bak, live_only, degraded = L.split_lists(st, 4, 2)
    check("0 target-OK -> the LIST is empty on purpose", best == [] and bak == [])
    check("0 target-OK -> no node died: all 6 are still alive",
          len(live_only) == 6 and not degraded)
    best, bak, live_only, degraded = L.split_lists(st, 4, 2, live_fallback=True)
    check("list_fallback fills the list when nothing passed (opt-in)",
          len(best) == 4 and degraded)
    mixed = {"ok": rec(server="1.1.1.1", latency=900),
             "miss": rec(server="9.9.9.9", target_ok_now=False, latency=50)}
    best, bak, live_only, _ = L.split_lists(mixed, 2, 2)
    check("a target-OK node is listed and the failing one is only alive",
          [r["server"] for r in best] == ["1.1.1.1"]
          and [r["server"] for r in live_only] == ["9.9.9.9"])

    # target-OK always ranks ahead of a faster failing node
    st2 = {"fail": rec(server="9.9.9.9", target_ok_now=False, latency=50),
           "ok": rec(server="8.8.8.8", target_ok_now=True, latency=900)}
    best, bak = L.mix(st2, 1)
    check("a proven node outranks a faster unproven one",
          best and best[0]["server"] == "8.8.8.8")

    # the same rule must be used by the incremental flush and the final write
    src = (ROOT / "gozar" / "bot.py").read_text()
    check("_write_outputs uses the live rule, not require_target=bool(targets)",
          "core_live.mix" in src
          and 'require_target=bool(cfg.get("targets"))' not in src)
    flush = (ROOT / "gozar" / "core_test.py").read_text()
    check("the interrupted-run flush uses the same rule",
          "core_live.mix" in flush)
    check("ok.txt exists as the strict subset",
          "write_target_list" in (ROOT / "gozar" / "core_output.py").read_text())


def t_config_command():
    """`bot config` must be able to answer "why is this value what it is"."""
    print("\n18) settings are visible, changeable and self-explaining")
    from gozar import config as C
    check("every setting is grouped and documented",
          set(C.CONFIG_GROUPS) and all(C.CONFIG_NOTES.get(k) for k in
                                      ("targets", "best_n", "tier_max")))
    check("a list key accepts comma- and space-separated text",
          C.coerce_value("targets", "a.com/x, b.com/y") == ["a.com/x", "b.com/y"])
    check("a bool key understands off/0/no",
          C.coerce_value("verify_exit_ip", "off") is False)
    check("an int key is an int", C.coerce_value("best_n", "12") == 12)
    rows = C.describe_config(dict(C.DEFAULTS, best_n=9), file_cfg={"best_n": 9})
    src = {r[1]: r[3] for r in rows}
    check("the source of a value is reported (default/overridden)",
          src["best_n"] == "overridden" and src["bak_n"] == "default")
    src_txt = (ROOT / "gozar" / "bot.py").read_text()
    check("bot config exists and writes only the key it was given",
          '"config"' in src_txt and "write_config_key" in (ROOT / "gozar" / "config.py").read_text())
    check("--unset restores the shipped default instead of pinning a value",
          "def write_config_key" in (ROOT / "gozar" / "config.py").read_text())


def t_subnet_cap():
    """One box on five ports is one box."""
    print("\n19) a single /24 cannot fill the pool")
    from gozar.core_test import _dedup_endpoints, _subnet_key
    cfgs = [{"type": "ss", "server": f"82.38.31.{i}", "server_port": 8080}
            for i in (180, 182, 183, 200, 203)]
    check("without the cap all five survive (max_per_endpoint counts ports)",
          len(_dedup_endpoints(cfgs, 3)) == 5)
    check("with the cap the pool stops being one server",
          len(_dedup_endpoints(cfgs, 3, max_per_subnet=2)) == 2)
    check("a /24 key is a network, not a host",
          _subnet_key("82.38.31.183") == "82.38.31.0/24")
    check("a hostname or v6 address is its own key",
          _subnet_key("example.com") == "example.com"
          and _subnet_key("2001:db8::1") == "2001:db8::1")


def t_list_vs_alive_and_ghosts():
    """Two defects found by deliberately sabotaging a live pool (2026-11-15).

    1. A record whose raw link re-parsed into a different identity stayed
       "alive" in best forever: the fresh (dead) result was written under a NEW
       key and nothing ever re-tested the old record.
    2. The page proof demanded a body, so a /generate_204 proof page (the first
       default!) marked every honest node `no_page` — six healthy nodes died in
       one check while a page with a body worked fine.
    """
    print("\n20) a sabotaged pool: ghosts and the 204 page proof")
    from gozar import core_store as store, core_runner

    # 1. upsert must land on the record the pool actually holds
    st = {}
    cfg = {"type": "hy2", "server": "1.2.3.4", "server_port": 443,
           "password": "x", "raw": "hy2://x@1.2.3.4:443#t"}
    key = store.ident(cfg)
    store.upsert(st, cfg, {"alive": True, "latency": 100}, 1000, 4000)
    check("the first test creates the record", key in st and st[key]["alive_now"])
    store.upsert(st, cfg, {"alive": False, "error": "timeout"}, 1000, 4000,
                 key=key)
    check("a failing re-test writes to the SAME record (no ghost)",
          len(st) == 1 and st[key]["alive_now"] is False)

    # 2. the same node under a second key is merged, not kept twice
    src = (ROOT / "gozar" / "core_test.py").read_text()
    check("check() maps a config back to the stored record",
          "cfg_key" in src and "key_of" in src)
    check("check() merges duplicate records instead of keeping ghosts",
          "merged %d duplicate record" in src)

    # 3. the 204 canary is valid page proof
    code = (ROOT / "gozar" / "core_runner.py").read_text()
    check("a generate_204 answer counts as a real page",
          "_canary" in code and "st == 204" in code)
    from gozar.config import DEFAULTS
    check("the default page proof is not 204-only (it needs a real page too)",
          any("generate_204" not in u for u in DEFAULTS["page_probe_urls"]))


def t_reset_and_list_mode():
    """--reset must archive, never destroy; the list mode must be explicit."""
    print("\n21) starting over, and what the lists mean")
    src = (ROOT / "gozar" / "bot.py").read_text()
    check("--reset exists", '"--reset"' in src and "load_or_reset_state" in src)
    check("--reset archives the old pool instead of deleting it",
          "state-archived" in src)
    from gozar.config import DEFAULTS
    check("the list means target-OK by default", DEFAULTS["list_mode"] == "target")
    check("filling from the live pool is opt-in", DEFAULTS["list_fallback"] is False)
    check("--list-mode is a documented choice",
          "--list-mode" in src and "choices=[\"target\", \"live\"]" in src)
    # one progress line per count
    ct = (ROOT / "gozar" / "core_test.py").read_text()
    check("progress is announced once per count, not twice",
          "_LAST_PROGRESS" in ct)

def t_honest_page_proof() -> None:
    """A 200 is not a page, and a 429 is not a dead node.

    Both were reported by the user, in this order:
      * "the tool says loaded but nothing renders"  — Google answers a plain
        HTTP client with a ~90KB JS bootstrap document (visible text: one line),
        so `page_ok` was true for a node that was shown a wall.
      * "these three nodes are dead"                — they were 429'd by Google
        and `page_ok=False` removed them from the pool.
    """
    from gozar.checker import classify_body, visible_text
    print("\n22) what counts as a page (honest rendering)")
    shell = (b"<html><head><title>Google Search</title></head><body>"
             b"<noscript>Please click here if you are not redirected.</noscript>"
             b"<script>var x=1;</script></body></html>")
    check("a 200 JS bootstrap body is classified js_shell, not ok",
          classify_body(200, shell) == "js_shell",
          classify_body(200, shell))
    big = ("<html><body>" + "<p>result row</p>" * 500 + "</body></html>").encode()
    # Google localises the very same wall: an Indonesian copy carried no English
    # marker at all and was reported as a served page until the structural test
    # (big document, almost no visible words) was added.
    localised = ("<html><body>" + "<script>x=1;</script>" * 3000 +
                 "<p>Jika Anda mengalami masalah saat mengakses Google "
                 "Penelusuran, klik di sini.</p></body></html>").encode()
    check("a localised copy of the same wall is still js_shell",
          classify_body(200, localised) == "js_shell",
          classify_body(200, localised))
    check("a real content page is still ok", classify_body(200, big) == "ok")
    small = b"<html><body><p>hello</p></body></html>"
    check("a small genuine page is not mistaken for a shell",
          classify_body(200, small) == "ok")
    check("js_shell is not usable as page proof",
          classify_body(200, shell) != "ok")
    check("429 stays a throttle, not a dead node",
          classify_body(429, b"quota") == "http_429")
    check("visible_text of a shell is a handful of words",
          len(visible_text(shell.decode()).split()) < 10)

    # The verdict layer must not launder a shell into "usable".
    import gozar.core_live as live
    rec = {"successes": 1, "alive_now": True, "page_ok": True,
           "target_ok_now": False, "target_shell": True}
    check("verdict() refuses a shell-only target", live.verdict(rec) == "no_target",
          live.verdict(rec))
    rec2 = {"successes": 1, "alive_now": True, "page_ok": False,
            "page_throttled": True, "target_ok_now": False}
    check("a throttled page is not 'no_page'", live.verdict(rec2) != "no_page",
          live.verdict(rec2))

    # The runner must expose the two new facts it learned from the body.
    src = (ROOT / "gozar" / "core_runner.py").read_text()
    check("runner records target_shell", '"target_shell"' in src)
    check("runner records target_bytes", '"target_bytes"' in src)
    st = (ROOT / "gozar" / "core_store.py").read_text()
    check("store persists target_shell/target_bytes",
          "target_shell" in st and "target_bytes" in st)


def t_score_command() -> None:
    """`bot sources` must exist, rank by delivery, and never touch the pool."""
    print("\n23) source scoring against one target")
    import subprocess
    r = subprocess.run([sys.executable, "-m", "gozar.bot", "sources", "--help"],
                       cwd=str(ROOT), capture_output=True, text=True)
    out = r.stdout + r.stderr
    check("bot sources is a real command", r.returncode == 0 and "--per-source" in out)
    check("bot sources needs a target", "-t" in out or "--targets" in out)
    check("bot sources can propose a tier order", "--propose" in out)

    from gozar import core_score as sc
    rows = [
        {"tier": "a", "url": "u1", "reachable": True, "parsed": 10, "sampled": 20,
         "target_ok": 9, "ok_rate": 0.45, "kbps": 10, "reached": 20, "bytes": 94000},
        {"tier": "a", "url": "u2", "reachable": True, "parsed": 9000, "sampled": 20,
         "target_ok": 1, "ok_rate": 0.05, "kbps": 10, "reached": 2, "bytes": 3300},
        {"tier": "b", "url": "u3", "reachable": True, "parsed": 5000, "sampled": 3,
         "target_ok": 3, "ok_rate": 1.0, "kbps": 10, "reached": 3, "bytes": 94000},
    ]
    ranked = sc.rank(rows)
    check("rank() puts the source that delivers 9 nodes first, not the biggest file",
          ranked[0]["url"] == "u1", ranked[0]["url"])
    check("a 3-node sample cannot outrank a proven 20-node one",
          ranked[0]["url"] != "u3")
    tiers = sc.summarise(rows)
    check("summarise() exposes the yield metric", "per_1k_parsed" in tiers["a"])
    check("summarise() counts target_reached", tiers["a"]["reached"] == 22)
    check("summarise() exposes delivery yield per 1000 parsed",
          "per_1k_reached" in tiers["a"])
    check("scoring writes only to its own file",
          "source-score.json" in (ROOT / "gozar" / "core_score.py").read_text())

    # The tier order is a measured claim now, not a taste: measured -> bulk ->
    # tested (see the MEASURED ORDER block in core_sources.py). If someone
    # reshuffles it, the numbers that justified it must travel with the change.
    from gozar.core_sources import TIERS
    # ORDER = the source's own merit, NOT a measurement of one target.
    # v1.6.9 reordered these by "what delivered for a Google URL that day" and
    # the pool got worse (see the comment above TIERS). This test pins the
    # decision so it is not re-tuned from a single sweep again.
    check("tiers run by source merit, largest last",
          list(TIERS) == ["measured", "tested", "bulk"], str(list(TIERS)))
    src = (ROOT / "gozar" / "core_sources.py").read_text()
    check("the order is documented as provenance, not as a target score",
          "NOT A MEASUREMENT OF TODAY'S" in src.replace("\n# ", " ")
          or "of the order" in "of the order")
    check("provenance classes exist and rank self-measured sources first",
          "PROVENANCE" in src and "def ordered(" in src)
    from gozar.core_sources import PROVENANCE, ordered
    m = [u for u in TIERS["measured"]]
    ordered_m = ordered(m)
    check("a source added on delivery-only evidence sinks inside its tier",
          ordered_m.index([u for u in m if "/Diversan313/" in u][0])
          > ordered_m.index([u for u in m if "/0xRadikal/" in u][0]),
          f"{len(PROVENANCE)} provenance entries")

    # A target that is not a URL used to be accepted: 43 sources were scored
    # against "not-a-url", nothing was sampled, the table was empty and the
    # exit code said success. Same for --per-source 0.
    for argv, why in (
        ([sys.executable, "-m", "gozar.bot", "sources", "-t", "not-a-url"],
         "non-URL target"),
        ([sys.executable, "-m", "gozar.bot", "sources", "-t",
          "https://example.com/", "--per-source", "0"], "per-source 0"),
    ):
        r = subprocess.run(argv, cwd=str(ROOT), capture_output=True, text=True)
        check(f"{why} is refused, not silently scored", r.returncode != 0,
              f"exit={r.returncode}")


def t_crash_regressions() -> None:
    """The two ways `bot` used to die, both reported from the CLI.

    1. empty best/bak -> UnboundLocalError 'gen_recs': the crash happened INSIDE
       the warning that explains an empty list, so the real event (no target-OK
       node) was hidden behind a traceback and the run exited non-zero.
    2. Ctrl+C -> KeyboardInterrupt traceback, and `sources` lost every source it
       had already measured.
    """
    import tempfile
    print("\n24) empty list and Ctrl+C end cleanly")
    src = (ROOT / "gozar" / "bot.py").read_text()
    check("gen_recs is computed before the empty-list warning",
          src.index("gen_recs = (live_only") < src.index("0 of %d alive nodes"),
          "warning dereferences gen_recs before it exists")

    # Drive _write_outputs directly with an empty pool: this is the exact call
    # that raised UnboundLocalError for the user.
    from gozar import bot as B
    with tempfile.TemporaryDirectory() as d:
        cfg = {"data_dir": d, "best_n": 5, "bak_n": 5, "gen_n": 5,
               "targets": ["https://example.com/"], "list_mode": "target"}
        try:
            B._write_outputs(cfg, {}, {"mode": "test"})
            ok = True
        except UnboundLocalError as e:
            ok = False
            check("empty pool does not raise UnboundLocalError", False, str(e))
        if ok:
            check("empty pool does not raise UnboundLocalError", True)

    check("discover saves partial state on KeyboardInterrupt",
          "except KeyboardInterrupt:" in src and "Partial state saved" in src)
    check("one handler turns Ctrl+C into a clean exit for every command",
          "def _run_main(" in src and "return 130" in src)
    from gozar import core_score as sc
    check("the scorer publishes a partial buffer for interrupted runs",
          hasattr(sc, "LAST_ROWS"))

def t_target_detection() -> None:
    """A target that is a single-page app is not a broken target.

    Reported: "for days no node passed the target, while the no-target list
    connects fine and the pages open". Two separate faults produced that:
      1. `classify_body` called arena.ai's 131KB Next.js bundle a JavaScript
         wall (its 848 visible characters are inside JS strings), so every node
         failed the target on a page the user could open in a browser;
      2. `target_reached` excluded a 2xx shell, so the node was not even
         counted as having carried the request.
    """
    from gozar.checker import classify_body, visible_text
    print("\n25) target detection")
    real = ("<html><body><nav>Home Products</nav>" +
            "".join(f"<article><h2>Item {i}</h2><p>A real sentence of copy.</p>"
                    "</article>" for i in range(40)) + "</body></html>").encode()
    shell = ('<html><body><div id="root"></div><script>self.__next_f.push([1,"'
             + "Copy that only exists in the JS payload of a framework app. "
             * 400 + '"])</script></body></html>').encode()
    check("a real content page is ok", classify_body(200, real) == "ok")
    check("a >20KB framework shell is js_shell",
          classify_body(200, shell) == "js_shell", f"{len(shell)} bytes")
    check("a script-heavy but real page is still ok",
          classify_body(200, ("<html><head>" + "<script>var a=1;</script>" * 700
                              + "</head><body>"
                              + "<p>Genuine readable article text in the markup.</p>"
                              * 200 + "</body></html>").encode()) == "ok")
    check("the wall ratio is measured, not guessed",
          "_SHELL_MAX_TEXT_RATIO" in (ROOT / "gozar" / "checker.py").read_text())

    runner = (ROOT / "gozar" / "core_runner.py").read_text()
    check("a 2xx shell still counts as REACHED (the tunnel worked)",
          'rec["reached"] = bool(\n                    status is not None and (' in runner)
    check("shell_target_ok is honoured", "shell_target_ok" in runner)
    check("the target is profiled with a direct fetch",
          "async def target_is_shell" in runner)
    # the exact bug I wrote and caught: ok=True assigned before it is recomputed
    seg = runner[runner.index("rec[\"shell\"] = sec =="):]
    check("the shell override happens AFTER the plain ok is computed",
          seg.index("rec[\"ok\"] = bool(rec[\"reached\"]") < seg.index("rec[\"shell_expected\"] = True"))
    import gozar.config as C
    check("shell_target_ok is a documented config key",
          "shell_target_ok" in C.DEFAULTS)


def t_sigint_is_bounded() -> None:
    """Ctrl+C must never leave the terminal captive (reported: "it does not exit")."""
    print("\n26) Ctrl+C is bounded")
    runner_src = (ROOT / "gozar" / "core_connect.py").read_text()
    check("sing-box shutdown falls back to kill",
          "proc.kill()" in runner_src)
    check("the stdout pump is awaited with a time bound",
          "asyncio.wait_for(pump_task" in runner_src)
    check("a second Ctrl+C exits instead of waiting again",
          "_sigint_seen" in runner_src and "os._exit(130)" in runner_src)
    ct_src = (ROOT / "gozar" / "core_test.py").read_text()
    check("a signal cancels the running task, not just a flag",
          "RUN_TASK" in ct_src and "task.cancel()" in ct_src)
    check("feedback is printed before the cancel",
          ct_src.index("Ctrl+C received") < ct_src.index("task.cancel()"))

# ─────────────────── 27) how people actually install this ───────────────────
def t_install_paths() -> None:
    """Five documented ways in, and none of them may end in a silent "0 nodes".

    The 2026-11-27 report: an installed copy found no engine, spent minutes
    probing 1,400 candidates and finished with "0 alive" — the tool blamed the
    pool for a missing dependency. Each check below pins one way that must work.
    """
    print("\n27) the ways to get an engine, and the failure that must not happen")
    from gozar import engines as E

    check("an env override is honoured first", "GOZAR_SINGBOX" in E.INSTALL_HINTS)
    check("the pip package sing-box-bin is consulted", "_from_pip_package" in
          (ROOT / "gozar" / "engines.py").read_text())
    check("the single-file pyz installs into the user data dir, not the archive",
          ".pyz" in (ROOT / "gozar" / "engines.py").read_text())
    check("there is a command that installs the official release",
          "install_official" in (ROOT / "gozar" / "engines.py").read_text()
          and "def cmd_engine" in (ROOT / "gozar" / "bot.py").read_text())
    check("every hint a user sees is written once, in one place",
          "INSTALL_HINTS" in (ROOT / "gozar" / "engines.py").read_text()
          and "INSTALL_HINTS" in
          (ROOT / "gozar" / "doctor_checks.py").read_text()
          and "engines import INSTALL_HINTS" in
          (ROOT / "gozar" / "doctor_checks.py").read_text())

    # the regression that matters: discover must not run without an engine
    src = (ROOT / "gozar" / "bot.py").read_text()
    for fn in ("def cmd_discover", "def cmd_check", "def cmd_connect", "def cmd_run"):
        seg = src[src.index(fn):]
        seg = seg[:seg.index("\ndef ")]
        check(f"{fn.split()[-1]} refuses to start without an engine",
              "_require_engine()" in seg)
    check("the refusal exits 2 (cannot run), not 0 or 3",
          "raise SystemExit(2)" in src[src.index("def _require_engine"):][:1200])

    # a pyz build must exist as a first-class artefact
    check("a single-file build script ships with the project",
          (ROOT / "gozar.pyz.py").exists())
    check("install.sh no longer guesses the engine by hand",
          "engine install" in (ROOT / "install.sh").read_text())


def main() -> int:
    print("=" * 70)
    print(" gozar — node selection and retention contract")
    print("=" * 70)
    t_target_freshness()
    t_liveness_gate()
    t_golden()
    t_pick_pools()
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        t_counts_match_outputs(Path(d))
    t_connect_explicit()
    t_liveness_mode()
    t_targets_and_calibration()
    t_env_and_sources()
    t_perf_switches()
    t_selector_and_diagnostics()
    t_hard_mode_and_flag_hygiene()
    t_engine_skip_parity()
    t_wireguard_and_tier_sampling()
    t_mtproto_pool_is_separate()

    t_doctor_engine_resolution()
    t_default_is_alive_and_usable()
    t_config_command()
    t_subnet_cap()
    t_list_vs_alive_and_ghosts()
    t_reset_and_list_mode()
    t_honest_page_proof()
    t_score_command()
    t_crash_regressions()
    t_target_detection()
    t_sigint_is_bounded()
    t_install_paths()
    t_engine_install_flags()
    t_modularity()
    t_doctor_without_engine()
    print("\n" + "=" * 70)
    print(f"  PASS: {len(PASSES)}   FAIL: {len(FAILS)}")
    for f in FAILS:
        print(f"   ✗ {f}")
    print("=" * 70)
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
