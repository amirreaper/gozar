"""Bot config defaults + config.json reader.

The HTTP/SOCKS generation is gone; DEFAULTS is exactly what the modern
(vless/hysteria2/anytls) bot uses. config.json (optional) overrides any key
given a non-None value.
"""

import json
from pathlib import Path

DEFAULTS = {
    # all parser-supported protocols — universal by default; narrow with
    # -p vless,hysteria2 (aliases accepted: ss/shadowsocks, hy2/hysteria2)
    # anytls is excluded: no public source publishes it today (D9) — keeping it
    # in the defaults only produced a misleading green light. Add it back with
    # -p anytls once a source exists.
    "protocols": ["hysteria2", "vless", "trojan", "tuic", "vmess",
                  "shadowsocks", "wireguard"],

    # Real-world check targets (list of URLs; empty = liveness-only mode).
    #
    # Why these three and not one: a node that answers generate_204 has only
    # proved that *something* answered a 204. It has not proved it carries real
    # traffic, and it has not proved it reaches a site the filter actually
    # blocks. These three are deliberately different in kind:
    #
    #   gstatic/generate_204  the cheap canary. Every working tunnel reaches it;
    #                         a node that fails it is broken, not filtered.
    #   wikipedia.org         a REAL page (headers + body) — this is what
    #                         separates "echo answered" from "browsing works".
    #   api.telegram.org      a host that is hard-blocked on Iranian consumer
    #                         lines (measured 2026-11-15: tcp=closed direct).
    #                         Passing it means the node carries traffic the user
    #                         cannot get without one.
    #
    # All three must pass (squid `all_ok`), so a node in best/bak is one that
    # works for real browsing, not one that answers a 204.
    # Deliberately NOT here: youtube/twitter/instagram — they are blocked by SNI
    # on the line itself, so a node that "fails" them may still be perfect. Put
    # the targets you actually care about with -t; they are your call, not mine.
    "targets": [
        "https://www.gstatic.com/generate_204",
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://api.telegram.org/",
    ],
    "echo_url": "https://www.google.com/generate_204",

    # Speed floor for best/bak (KB/s, measured on the proof page). A node that
    # trickles 3KB/s passes every target and is still useless in a browser.
    # 0 = off. This is a THROUGHPUT floor, never a latency one: more speed must
    # never change a verdict, it only removes nodes that cannot carry a page.
    "min_kbps": 0,

    # What the LISTS mean.
    #   "target" (default) = best/bak hold only nodes that passed every target;
    #                        a node that missed one is not listed, but it is NOT
    #                        dropped — it stays alive in gen.txt and can still be
    #                        used with `--from gen`.
    #   "live"             = best/bak hold every alive+usable node, target-OK
    #                        ranked first (the v1.6.7 behaviour).
    # Safety valve in both modes: if nothing passed the targets, best/bak are
    # filled from the live pool and the run says so, instead of writing empty
    # files and looking like a washout.
    "list_mode": "target",

    # A target that is a single-page app serves a JavaScript shell to every
    # client, so an HTTP-only test can never prove it rendered (arena.ai).
    # true  = for such a target, "the host answered over the tunnel" IS success
    #         (the shell was fetched directly, without a tunnel, to detect it)
    # false = demand a rendered page even then (strict; expect an empty list)
    "shell_target_ok": True,
    # When NOT ONE node passes the targets, an empty best/bak is the honest
    # answer (the user asked for exactly that: "let a blocked site keep nodes
    # out of the list but alive"). The bot says so loudly and leaves the live
    # pool in gen.txt. Set this to true to fill the list from the live pool
    # instead, and treat it as unproven.
    "list_fallback": False,

    # Page proof ("really alive"): a generate_204 answer can come from a
    # transparent interceptor while the node carries nothing. Every node must
    # also open ONE real page (headers + body) through the tunnel, otherwise it
    # is not allowed into the live pool (gen). Cheap: runs in parallel with the
    # target check, so it adds ~0 wall-clock time.
    "page_probe_urls": [
        "https://www.gstatic.com/generate_204",
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://example.com/",
    ],

    # tunnel proof: require the observed exit IP to differ from this machine's
    # own public IP. Without it a 204 from a transparent interceptor makes a
    # dead node look "alive and fast" (see docs/DEFECTS.md D17).
    "verify_exit_ip": True,
    # when true, a node whose exit IP cannot be read is rejected instead of kept
    "strict_exit_proof": False,
    "exit_probe_urls": [
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://api.ipify.org?format=text",
        "https://api.ip.sb/ip",
        "https://icanhazip.com/",
        "https://checkip.amazonaws.com/",
        "https://ipinfo.io/ip",
        "https://ifconfig.me/ip",
    ],

    # how many candidates each tier may contribute per run. 0 = no cap (the
    # pre-v1.6.4 behaviour, when tiers were trusted to be small and clean).
    # Measured 2026-11-14: the "trusted" tier now carries real bundles of tens
    # of thousands of links, and testing 10-15k candidates x 8s is hours of work
    # for a marginally better pool — the alive rate is flat past ~1,500/tier.
    "tier_max": 1500,
    # skip a tier entirely once this many nodes are already proven alive
    "tier_skip_alive": 60,

    # storage caps
    "best_n": 50,
    "bak_n": 100,
    "gen_n": 100,
    "max_per_proto": 0,
    "max_per_endpoint": 3,
    # max_per_endpoint counts IP:port, so one host on five ports passes five
    # times. 6 per /24 keeps a genuine hosting cluster in, but stops one box
    # from owning the pool (2026-11-15: 5 of 8 alive nodes were one /24).
    # 0 = off.
    "max_per_subnet": 6,
    "subnet_prefix": 24,

    # baseline ping & thresholds
    "baseline_hosts": ["1.1.1.1:443", "1.0.0.1:443", "8.8.8.8:443", "9.9.9.9:443"],
    "baseline_ms_override": None,
    "fast_factor": 1.2,
    "fast_min_ms": 150,
    "fast_max_ms": 1200,       # user preference: a fast node stays under 1200ms
    "backup_max_ms": 4000,     # backup nodes are acceptable up to 4000ms
    "fast_tier_low": 1500,
    "fast_tier_mid": 2500,
    "fast_tier_high": 4000,
    "max_acceptable_ms": None,

    # probe phase (TCP ping)
    # "auto" = decide per run by sampling whether the line looks open
    # (>=80% of ports answering => the pre-filter costs more than it saves).
    # "on"/"off" force it. It never changes WHICH nodes pass the real test.
    "probe_mode": "auto",
    "probe_concurrency": 400,
    "probe_timeout": 3.5,
    # anti rate-limit (on by default — safe and useful for everyone):
    # 0..15ms jitter per probe start; 400 consecutive dead probes -> 20s pause
    "probe_pace_ms": 15,
    "probe_breaker_window": 400,
    "probe_breaker_pause_s": 20,

    # real sing-box test phase
    # measured on 2026-11-14: 14 / 40 / 80 concurrency produced IDENTICAL
    # verdicts for the same pool (docs/PERF.md). 24 is the sweet spot: faster
    # than 14 without pinning a weak CPU.
    "test_concurrency": 24,
    "timeout": 8,
    "target_timeout": 12,
    "startup_delay": 0.8,
    "verify_ssl": False,
    # anti rate-limit (on by default): 0..50ms jitter per test start;
    # 25 consecutive failures on one worker -> exponential backoff up to 30s
    "test_pace_ms": 50,
    "test_breaker_streak": 25,

    # latency basis for ranking (default target): download time of the first
    # successful target — closest to real UX; falls back to echo when no
    # target is configured.
    "latency_basis": "target",

    # domestic (.ir / self-hosted) config sources — fetched FIRST so they
    # still work during a full international shutdown; see `discover
    # --domestic` for the offline-only mode. Example entries:
    # "https://ir1.example.net/sub.txt", "https://backup.example.ir/nodes"
    "domestic_sources": [],

    # user-supplied raw links or local subscription files — always tested FIRST
    "custom_configs": [],
    "import_files": [],

    # cycles & upkeep
    "prune_failures": 6,
    "check_interval": 1800,
    "discover_interval": 21600,

    # paths
    "data_dir": "data",

    # connect
    "connect": {"mode": "proxy", "port": 2080},
}

# ─────────────────────────── presets ───────────────────────────
# A preset is a named bundle of settings for one situation. It is applied
# BEFORE explicit config/CLI values, so anything you type still wins.
#
# "hard" = hard mode: the line is filtered or throttled and every test is
# expensive, so land on real targets instead of failing everywhere:
#   * full TCP pre-filter (no sampling): it is the cheapest way to skip
#     endpoints the filter already killed, and auto would turn it off
#   * smaller batches and lower concurrency: on a broken line every process
#     waits for timeouts, and waiting on 24 of them at once mostly wastes the
#     line's bandwidth — 8 keeps the CPU/RAM and the uplink sane
#   * longer timeouts and slower pacing: reset-heavy lines need the extra
#     second, and pacing avoids tripping per-IP rate limits
#   * keep going past dead spells instead of stopping after a few fails
#   * accept nodes up to 6s and keep more of them (targets still decide best)
#   * conservative profile for calibrate --write
HARD_MODE = {
    "probe_mode": "on",
    "test_concurrency": 8,
    "batch_size": 3,
    "startup_delay": 1.2,
    "timeout": 12,
    "target_timeout": 18,
    "test_pace_ms": 120,
    "probe_pace_ms": 30,
    "test_breaker_streak": 40,
    "probe_breaker_window": 600,
    "backup_max_ms": 6000,
    "best_n": 30,
    "bak_n": 60,
    "strict_exit_proof": False,
    # A filtered line blackholes most public exit-IP probes, so exit proof
    # cannot be obtained for many nodes that ARE tunneling — with
    # strict_exit_proof on, hard mode would reject them all and report zero
    # nodes. Proof stays on where it works; `--strict-exit` still restores it.
    "page_probe_urls": ["https://www.gstatic.com/generate_204",
                        "https://www.google.com/generate_204",
                        "https://example.com/"],
    "profiles": {"calibrate": "conservative"},
}

PRESETS = {"hard": HARD_MODE}


def apply_preset(cfg: dict, name: str) -> dict:
    """Overlay a preset on top of the defaults (config.json/CLI still win)."""
    preset = PRESETS.get(name)
    if not preset:
        return cfg
    out = dict(cfg)
    out.update({k: v for k, v in preset.items() if k != "profiles"})
    out["preset"] = name
    return out


def load_config(path: str = "config.json", preset: str | None = None) -> dict:
    """Defaults -> preset -> config.json. Later wins; CLI overrides come after."""
    cfg = dict(DEFAULTS)
    if preset:
        cfg = apply_preset(cfg, preset)
    p = Path(path)
    if p.exists():
        try:
            user = json.loads(p.read_text(encoding="utf-8"))
            for k, v in user.items():
                if v is not None:
                    cfg[k] = v
        except Exception as e:  # noqa: BLE001
            print(f"[!] Failed to read {path}, using defaults: {e}")
    return cfg

# ─────────────────────────── config management ───────────────────────────
# A config that "is managed correctly" means three things the bot could not do
# before: you can see WHY a value is what it is, you can change ONE key without
# hand-editing JSON, and you can tell whether your config.json has drifted from
# the defaults (a stale config silently overrides every improvement: v1.6.5
# shipped better sources while config.json still pinned an old protocol list).
#
# Every key carries the group it belongs to and a one-line reason. The reason is
# the point: a value without a reason is a value nobody dares change.
CONFIG_GROUPS = {
    "what to test": ["targets", "echo_url", "page_probe_urls", "protocols",
                     "target_timeout", "verify_ssl"],
    "proof": ["verify_exit_ip", "strict_exit_proof", "exit_probe_urls",
              "min_kbps", "latency_basis"],
    "speed": ["fast_max_ms", "fast_factor", "fast_min_ms", "backup_max_ms",
              "baseline_ms_override", "max_acceptable_ms"],
    "how many": ["best_n", "bak_n", "gen_n", "max_per_endpoint", "max_per_proto"],
    "how hard": ["test_concurrency", "probe_concurrency", "batch_size",
                 "timeout", "startup_delay", "test_pace_ms", "probe_pace_ms",
                 "probe_mode", "probe_timeout",
                 "test_breaker_streak", "probe_breaker_window"],
    "pool size": ["tier_max", "tier_skip_alive", "prune_failures",
                  "check_interval", "discover_interval"],
    "sources": ["domestic_sources", "custom_configs", "import_files"],
    "paths/connect": ["data_dir", "connect", "baseline_hosts"],
}

CONFIG_NOTES = {
    "targets": "what a node must open to count as good; empty = liveness only",
    "echo_url": "the cheap canary every test starts with (204, no body)",
    "page_probe_urls": "one REAL page must open, or the node is not 'alive'",
    "protocols": "which schemes are parsed and tested at all",
    "verify_exit_ip": "reject a node whose exit IP is your own line (leak)",
    "strict_exit_proof": "reject a node when its exit IP cannot be read at all",
    "min_kbps": "throughput floor in KB/s; 0 = off (never a latency rule)",
    "fast_max_ms": "the 'fast' ceiling before calibration overrides it",
    "backup_max_ms": "slower than this is not stored at all",
    "best_n": "how many nodes best.txt holds",
    "bak_n": "how many nodes bak.txt holds",
    "gen_n": "how many alive-but-target-less nodes gen.txt holds",
    "max_per_endpoint": "max nodes per IP:port (one port cannot own best)",
    "max_per_proto": "max samples per protocol in the first pass (0 = all)",
    "test_concurrency": "parallel sing-box tests; lower it on a fragile line",
    "probe_concurrency": "parallel TCP probes; the cheapest filter there is",
    "batch_size": "nodes per sing-box process (blank = pick from concurrency)",
    "timeout": "seconds each node gets to start + answer the canary",
    "target_timeout": "seconds a node gets for the real target",
    "startup_delay": "wait after starting sing-box before the first request",
    "test_pace_ms": "random 0..N ms before each test start (anti rate-limit)",
    "probe_pace_ms": "random 0..N ms before each TCP probe",
    "probe_mode": "auto|on|off — TCP pre-filter before the expensive test",
    "probe_timeout": "seconds a TCP probe waits for a connect",
    "test_breaker_streak": "consecutive test fails before the breaker backs off",
    "probe_breaker_window": "dead probes in a row before a pause",
    "probe_breaker_pause_s": "how long that pause lasts",
    "verify_exit_ip": "reject a node whose exit IP is your own line (a leak)",
    "strict_exit_proof": "reject a node when its exit IP cannot be read at all",
    "min_kbps": "throughput floor in KB/s; 0 = off (never a latency rule)",
    "page_probe_urls": "one REAL page must open, or the node is not 'alive'",
    "shell_target_ok": "an SPA/JS-shell target still counts as reached (true)",
    "list_mode": "target = only target-passing nodes in best/bak; live = all alive",
    "list_fallback": "fill the list from alive nodes when none passed a target",
    "max_per_subnet": "max nodes per /24 (0 = off)",
    "subnet_prefix": "subnet size used by max_per_subnet",
    "fast_max_ms": "the 'fast' ceiling before calibration overrides it",
    "backup_max_ms": "slower than this is not stored at all",
    "check_interval": "seconds between checks in `loop`",
    "discover_interval": "seconds between discovers in `loop`",
    "tier_max": "sample size per tier; 0 = test everything (slow but thorough)",
    "prune_failures": "consecutive failures before a node is deleted for good",
    "data_dir": "where state.json and best/bak/gen live",
}

DEFAULT_CONFIG = "config.json"


def describe_config(cfg: dict, path: str | None = None,
                    file_cfg: dict | None = None) -> list[tuple]:
    """Return [(group, key, value, source, note)] for every known setting.

    `source` is the honest answer to "why is this value what it is":
      default      nothing set it, this is the shipped value
      config.json  the file set it (and it may be stale)
      overridden   the file set it AND it differs from the shipped default
    """
    rows: list[tuple] = []
    file_cfg = file_cfg if file_cfg is not None else {}
    seen = set()
    for group, keys in CONFIG_GROUPS.items():
        for k in keys:
            if k in seen:
                continue
            seen.add(k)
            val = cfg.get(k)
            if k in file_cfg and file_cfg.get(k) is not None:
                src = ("overridden" if val != DEFAULTS.get(k) else "config.json")
            else:
                src = "default"
            rows.append((group, k, val, src, CONFIG_NOTES.get(k, "")))
    for k in sorted(set(DEFAULTS) - seen):
        if k.startswith("_"):
            continue
        src = "config.json" if k in file_cfg and file_cfg.get(k) is not None else "default"
        rows.append(("other", k, cfg.get(k), src, CONFIG_NOTES.get(k, "")))
    return rows


def _fmt_val(v) -> str:
    if isinstance(v, (list, tuple)):
        if not v:
            return "[]"
        if len(v) == 1:
            return str(v[0])
        return f"{str(v[0])} (+{len(v) - 1})"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{a}={b}" for a, b in list(v.items())[:3]) + "}"
    if isinstance(v, bool):
        return "on" if v else "off"
    if v is None:
        return "—"
    return str(v)


def read_config_file(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:                                   # noqa: BLE001
        return {}


_COERCE_LIST = ("targets", "protocols", "page_probe_urls", "exit_probe_urls",
                "domestic_sources", "custom_configs", "import_files",
                "baseline_hosts")


def coerce_value(key: str, text: str):
    """Turn a command-line string into the type DEFAULTS says this key has.

    Deliberately strict about types and forgiving about shape: `targets` may be
    written as one URL, several spaces, or comma separated, because that is how
    people actually type it.
    """
    base = DEFAULTS.get(key)
    if key in _COERCE_LIST:
        parts = [x.strip() for x in str(text).replace(",", " ").split() if x.strip()]
        return parts
    if isinstance(base, bool):
        return str(text).strip().lower() in ("1", "true", "yes", "on", "y")
    if isinstance(base, int) and not isinstance(base, bool):
        return int(str(text).strip())
    if isinstance(base, float):
        return float(str(text).strip())
    if base is None:                       # accept a typed literal for unknown keys
        s = str(text).strip()
        if s.lower() in ("null", "none", "off", "-"):
            return None
        try:
            return json.loads(s)
        except Exception:                                # noqa: BLE001
            return s
    return str(text)


def write_config_key(path: str, key: str, value) -> dict:
    """Set ONE key in config.json, keeping everything else byte-identical."""
    p = Path(path)
    data = read_config_file(path)
    if value is None:
        data.pop(key, None)
    else:
        data[key] = value
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                 encoding="utf-8")
    return data
