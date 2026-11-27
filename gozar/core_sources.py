"""Config sources - tiered cascade with SNI-fallback fetching.

TIERS = TESTING ORDER (names say what they are; the old names still resolve)
---------------------------------------------------------------------------
  measured  the source proved every link itself before publishing
  tested    community lists that carry real test results
  bulk      everything else, biggest last

A tier is not a quality badge and nothing is thrown away for being lower: the
cascade stops early once enough nodes are proven alive, `tier_max` bounds a
tier by SIZE (random sample, not truncation), and the real test decides.

CENSUS 2026-11-14, against a 70,481-connection union (`morpheusadam/all`)
-------------------------------------------------------------------------
  source                          parsed   unique     NEW  verdict
  Delta-Kronecker batch_003        9,192    9,188   7,689  added
  Delta-Kronecker batch_014        5,211    5,069   4,111  added
  MatinGhanbari all_sub            3,923    3,673     952  added
  coldwater Sub6/Sub10               594      594     298  added
  Au1rxx v2ray                     1,751      686     222  (already in)
  barry-far Sub1                     490      215      47  (already in)
  Delta-Kronecker batch_013       10,000        1       1  rejected
  TheCrowCreature trojan.html      4,136       42      35  rejected
  ebrasha / SolVPN / VestraNet /   HTTP 404      -       -   dead paths
  MohammadBahemmat / V2RAYCONFIGSPOOL /
  YawStar / nukcrow / FreeFolksOn /
  MahanKenway

MEASURED ORDER 2026-11-14 (Google search target, `bot sources`, two runs)
------------------------------------------------------------------------
  reached per 1000 parsed:  measured 2.8 / 3.75   tested 0.4 / 0.74
                            bulk 0.5 / 0.71
  => TIERS = measured -> tested -> bulk. `measured` wins by 4-5x; `tested` and
  `bulk` are inside the noise of each other, and `tested` is 3.5x larger, so it
  is not put ahead on a 0.03 difference. The Delta-Kronecker batches alone are
  15k of `tested` and delivered nothing in 96 tested connections.
  This is a snapshot of live pools, not a law: re-check with
  `bot sources -t URL --propose`.

SOURCE ADD/DROP SWEEP 2026-11-14 (31 candidates fetched, 16 scored)
--------------------------------------------------------------------
  added   Diversan313/apex-parser alive_bl   403 uniq   5/14 reached
  added   luxxuria/harvester ping_tested      78 uniq   4/14
  added   sakha1370/OpenRay GB               164 uniq   3/14
  added   pie-with-jam/PulseProxy 15         349 uniq   2/14
  added   ShatakVPN/ConfigForge at/all       283 uniq   2/14
  added   V2HUBIR sub.txt                    177 uniq   1/14
  added   noahclanman/free-xray-gcp fast     157 uniq   1/14
  added   Leon406/SubCrawler v2              250 uniq   0/14 (vmess only)
  dropped mheidari98 trojan/ss/vmess         0/16 twice on GOOGLE -> RESTORED
         the next day: same files gave 4/30 (13%) on a clean target. A target
         measurement is not a source-quality measurement (see TIERS comment).
  measured on a clean target (example.com, 10 nodes each): the 8 added
         sources 31/80 reached (39%), the 3 dropped 4/30 (13%) — both fine,
         neither is dead; only the Google target made them look empty.
  rejected (0/14, kept out): rtwo2/FastNodes AT, freedomnet25500/freeneu,
           parvinxs/Sub.mahsa.xsparvin (809 uniq!), iboxz/free-v2ray-collector,
           v2raynnodes/blues, amin4139/Fastly, ysmoradi/clean (30 uniq)
  404: iPsycho1/Subscription, Epodonios, yebekhe/PSG, soroushmirzaei collector,
       liMilCo/v2r, hans-thomas/v2ray-subscription  -> dead paths, not sources
  Lesson repeated: 809 unique links delivered 0/14 while 78 delivered 4/14.

Lessons that changed the code:
  * URL COUNT IS NOT YIELD: 10,000 lines held ONE endpoint; 600 lines held 583
    new ones. Never judge a source by its size.
  * The Delta-Kronecker batches are DISJOINT slices, not duplicates: batch_013
    happened to be a single server pasted 10,000 times, while batch_003/014 were
    the most productive files measured. Same repo, opposite verdicts.
  * `morpheusadam/.../all.txt` ranks sources by unique connections and is their
    union: the cheapest way to widen the pool, and the yardstick to measure
    "new" against.
  * WireGuard share links parse and test natively (sing-box endpoint form) —
    that is where the WARP pools live.
  * A "new repo" is almost never new nodes: 8 of 13 candidates were 404 and the
    rest were 60-95% overlap. Growth comes from a few measured files, not from
    a long list of star counts.

Fetching is plain HTTPS with a browser UA. The v1.7 DPI fallback (DoH +
chopped ClientHello) was removed in v1.9.0: on an open line it never fired, and
on a filtered line it revived a few mirrors at the cost of ~1,000 lines plus
false "frag needed" flags on real nodes.

Telegram/MTProto was a separate pool and is gone too (v1.9.0): sing-box cannot
model an MTProto proxy, so it was never a tunnel node.
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
import time
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("core.sources")

# one browser UA for every source fetch (raw.githubusercontent.com answers a
# bare client with 403 on some paths)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# ─────────────── tiers (re-architected for progressive size & zero redundancy) ───────────────

TRUSTED_SOURCES = [
    # measurement-curated: every link was fetched, decoded and dialled before
    # publication; "best" comes from sources that scored >= 85.
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
    # Iran-targeted bundle: REALITY / XTLS-Vision / Hysteria2 / TUIC only —
    # the protocols that survive active probing.
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
    # validated with real xray/sing-box before publication
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt",
    # community real-time test results & Reality / Hysteria2 high-yield sets
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/Best-Results/sub.txt",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs_tested.txt",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Reality",
    "https://raw.githubusercontent.com/ndsphonemy/proxy-sub/main/speed.txt",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    # measured 2026-11-14: 590 links -> 590 unique endpoints (583 new to us).
    # Highest unique-per-line ratio of any file we tested.
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Sub7.txt",
    # measured: 474 unique trojan endpoints (363 new)
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-telegram-configs-collector-trojan",
    # ---- added 2026-11-14 after `bot sources` measured the new candidates
    # against a Google target (14 random nodes each). Only the ones that
    # delivered are here; everything that returned 0/14 stayed out.
    # 403 unique (329 VLESS) — best new candidate of the sweep: 5/14 reached.
    "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt",
    # community ping-tested, tiny (78 unique) but 4/14 reached: high yield per
    # link, the exact opposite of the 10k-line files that delivered nothing.
    "https://raw.githubusercontent.com/luxxuria/harvester/main/ping_tested.txt",
    # 164 unique, per-country split; 3/14 reached.
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output/country/GB.txt",
]

GOOD_SOURCES = [
    # measured 2026-11-14: 8,224 parsed -> 3,131 unique endpoints (all new);
    # the only big file that keeps a healthy unique/links ratio.
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/configtg.txt",
    # measured: 1,946 parsed -> 941 unique (393 new). Real per-protocol split.
    "https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/All_Configs_Sub.txt",
    # measured: 9,992 parsed -> 2,013 unique, VMess-heavy (1,952 new). Good for
    # volume late in the cascade, not for quality; tier_max keeps it bounded.
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-69.txt",
    # measured against a 70,481-connection union: 9,186 unique VLESS endpoints,
    # 7,689 of them NEW. The batch_* files are disjoint slices of one big pool,
    # so two of them are enough — more batches mostly re-add the same servers.
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_003.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_014.txt",
    # measured: 3,673 unique (952 new), the only big file with a decent share of
    # shadowsocks/trojan alongside vmess
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    # 11.7k REALITY nodes, 8.7k of which no other source carries
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/reality.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/master/nodes/merged.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vless.txt",
    "https://raw.githubusercontent.com/free18/v2ray/main/v.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/All_Config.txt",
    # ---- added 2026-11-14 (measured, see the block in TRUSTED_SOURCES)
    # 349 unique, VLESS-heavy, 2/14 reached.
    "https://raw.githubusercontent.com/pie-with-jam/PulseProxy/main/githubmirror/15.txt",
    # 283 unique incl. 50 hysteria2 — the protocol the free pools rarely keep.
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/at/all.txt",
    # 177 unique, hourly auto-updated Iran-oriented pool, 1/14 reached.
    "https://raw.githubusercontent.com/V2HUBIR/V2HUBIR-Free-V2Ray-Configs-free-Sub/main/sub.txt",
    # 157 unique; 169 KB/s median on the ones that did answer (fastest single
    # sample of the sweep) but walled 8/14 — worth a slot, not trust.
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/fast/configs.txt",
]

MEDIUM_SOURCES = [
    # measured: 594 unique, 298 new (Sub6) / 596 unique, 281 new (Sub10)
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Sub6.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Sub10.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    # roosterkid: 149 unique, but only 2 of them are not carried elsewhere
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt",
    # mheidari98 split by protocol. These were DROPPED on 2026-11-14 after two
    # Google runs scored them 0/16, and RESTORED the same day when the same
    # files measured 4/30 (13%) against a clean target: the drop was a
    # measurement of Google's throttling, not of these sources. Kept as one
    # repo's four slices (same generator), last inside the tier on purpose.
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/vless",
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/trojan",
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/ss",
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/vmess",
    # added 2026-11-14: 250 unique, all vmess — a protocol the other sources are
    # dropping, and the only candidate that survived the sweep from that repo.
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/v2",
]

# Tier KEYS are what the user sees in the log, so they say what the tier is:
#   measured = the source proved each link itself before publishing
#   tested   = community lists carrying real test results
#   bulk     = everything else, biggest last
# The old names (trusted/good/medium) are accepted as aliases so saved configs
# and the historical docs keep working.
#
# ORDER IS THE TIER'S OWN CLAIM ABOUT THE SOURCE, NOT A MEASUREMENT OF TODAY'S
# TARGET. That distinction cost a regression and is worth writing down:
#
#   What we tried (v1.6.9): rank tiers by nodes they delivered for ONE target
#   (a Google search URL) and put the most productive first. It looked
#   scientific and it produced a WORSE pool. Why:
#     * a target measurement is a measurement of the TARGET as much as of the
#       source — Google answers datacenter exits with 429 or a JavaScript wall,
#       so on that day every tier scored near zero and the ranking became noise;
#     * the cascade STOPS EARLY ("Reached n/n fast target-OK nodes. Stopping
#       cascade."), so the tier that runs first decides which addresses are even
#       considered. Putting a thinner tier in front narrows the address space
#       before the good tier is ever fetched;
#     * sample noise: 16 nodes per source, run-to-run swings of 2x, one 90KB
#       response counted differently from one 3KB 429.
#   What the order must express: how much the source's own maintainer does to
#   prove its links (self-measured > community-tested > bulk), which is stable
#   across days and independent of which URL you point the bot at.
#
# The measurements stay in the repo as evidence, never as the ordering:
#   `bot sources -t URL` scores each source against your target. Use it to DROP
#   a source that is dead or duplicated, and to see what your line can reach —
#   not to reorder what the pool is built from.
TIERS = {
    "measured": TRUSTED_SOURCES,
    "tested": GOOD_SOURCES,
    "bulk": MEDIUM_SOURCES,
}

# Rank INSIDE a tier (cascade order within TRUSTED_SOURCES etc.). 0 = the
# source's own merit, 1 = it only earns a place on measured delivery to the
# target you passed. A source added because it "delivered 4/16 on Google" is
# merit 1: it is evidence for that day and that target, not a credential.
PROVENANCE = {
    # sources whose maintainer measures every link before publishing
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt": 0,
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt": 0,
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt": 0,
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt": 0,
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt": 0,
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/Best-Results/sub.txt": 0,
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs_tested.txt": 0,
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Reality": 0,
    "https://raw.githubusercontent.com/ndsphonemy/proxy-sub/main/speed.txt": 0,
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt": 0,
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Sub7.txt": 0,
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-telegram-configs-collector-trojan": 0,
    # added 2026-11-14 on a target measurement only
    "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt": 1,
    "https://raw.githubusercontent.com/luxxuria/harvester/main/ping_tested.txt": 1,
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output/country/GB.txt": 1,
    "https://raw.githubusercontent.com/pie-with-jam/PulseProxy/main/githubmirror/15.txt": 1,
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/at/all.txt": 1,
    "https://raw.githubusercontent.com/V2HUBIR/V2HUBIR-Free-V2Ray-Configs-free-Sub/main/sub.txt": 1,
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/fast/configs.txt": 1,
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/v2": 1,
    # restored slices: same generator, so they never jump ahead of the vless one
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/trojan": 1,
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/ss": 1,
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/vmess": 1,
    "https://raw.githubusercontent.com/leon406/subcrawler/main/sub/share/v2": 1,
}


def ordered(urls: list[str]) -> list[str]:
    """Sort one tier by provenance (self-measured first), keeping list order.

    Stable by design: within the same provenance class the curator's order is
    kept, so a hand-written comment order still means something.
    """
    return sorted(urls, key=lambda u: PROVENANCE.get(u, 0))


TIER_ALIASES = {"trusted": "measured", "good": "tested", "medium": "bulk"}


def tiers_with(domestic: list[str] | None = None,
               domestic_only: bool = False) -> dict[str, list[str]]:
    """Build the tier map, optionally with a leading 'domestic' tier of
    user-supplied .ir/domestic endpoints (see config "domestic_sources")."""
    d = [u for u in (domestic or []) if isinstance(u, str) and u.startswith("http")]
    if domestic_only:
        return {"domestic": d} if d else {}
    out = {}
    if d:
        out["domestic"] = d
    out.update(TIERS)
    for _k, _v in list(out.items()):
        out[_k] = ordered(_v)
    return out



# targeted per-protocol sources (used first when user passes -p vless etc.
# because their protocol density is higher)
PROTOCOL_SOURCES = {
    "vless": [
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    ],
    "hysteria2": [
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/hysteria2.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/hysteria2",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
    ],
    "trojan": [
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/trojan.txt",
        "https://raw.githubusercontent.com/mheidari98/.proxy/main/trojan",
    ],
    "shadowsocks": [
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/shadowsocks.txt",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    ],
    "vmess": [
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vmess.txt",
    ],
    # WireGuard share links (the WARP pools). Tested natively: sing-box models
    # wireguard as an ENDPOINT, not an outbound — see core_runner.build_endpoint.
    "wireguard": [
        "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/wireguard.txt",
    ],
}

ALL_TIER_SOURCES = TRUSTED_SOURCES + GOOD_SOURCES + MEDIUM_SOURCES


# ───────────────────────── source health memory ─────────────────────────

def _stats_path(data_dir) -> Path | None:
    if not data_dir:
        return None
    return Path(data_dir) / "source_stats.json"


def load_source_stats(data_dir) -> dict:
    p = _stats_path(data_dir)
    if not p or not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def update_source_stats(data_dir, url_results: dict[str, dict]) -> None:
    """Persist per-source reachability & yield stats so future runs order
    healthy/productive sources first."""
    p = _stats_path(data_dir)
    if not p:
        return
    stats = load_source_stats(data_dir)
    now = int(time.time())
    for u, info in url_results.items():
        rec = stats.get(u, {"ok": 0, "fail": 0, "consec_fail": 0, "parsed": 0})
        if info.get("reachable"):
            rec["ok"] = rec.get("ok", 0) + 1
            rec["consec_fail"] = 0
            rec["parsed"] = info.get("parsed", 0)
            rec["last_ok"] = now
        else:
            rec["fail"] = rec.get("fail", 0) + 1
            rec["consec_fail"] = rec.get("consec_fail", 0) + 1
            rec["last_fail"] = now
        stats[u] = rec
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(stats, indent=1), encoding="utf-8")
        tmp.replace(p)
    except Exception:
        pass


def rank_sources(urls: list[str], data_dir) -> list[str]:
    """Order URLs within a tier: healthy sources first, consecutively failing
    sources pushed to the end."""
    stats = load_source_stats(data_dir)
    if not stats:
        return list(urls)

    def _key(idx_url):
        idx, u = idx_url
        r = stats.get(u)
        if not r:
            return (0, idx)
        cf = r.get("consec_fail", 0)
        return (cf, idx)

    return [u for _, u in sorted(enumerate(urls), key=_key)]


# ───────────────────────── mirrors (raw.githubusercontent) ─────────────────────────

def mirrors_for(url: str) -> list[str]:
    """jsdelivr + fast proxies as mirrors when raw.githubusercontent is cut."""
    m = re.match(r"https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)", url)
    if not m:
        return [url]
    user, repo, branch, path = m.groups()
    out = [url,
           f"https://cdn.jsdelivr.net/gh/{user}/{repo}@{branch}/{path}"]
    # ghfast.top mirror — optional path for CN/IR networks
    out.append(f"https://ghfast.top/https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}")
    return out


# ───────────────────────────── plain fetch ─────────────────────────────

def fetch_plain(url: str, referer: str = "") -> str | None:
    """Fetch one source URL with a browser UA. No DNS-over-HTTPS, no chopped
    ClientHello, no relay.

    The v1.7-v1.8 DPI fallback was measured and dropped in v1.9.0: on an open
    line it never fired, and on a filtered line it revived a handful of GitHub
    mirrors while costing ~1,000 lines of machinery plus false 'frag_needed'
    flags on real nodes. If a source cannot be fetched plainly, the next source
    in the tier is tried instead — that is cheaper and it never lies.
    """
    import urllib.request

    last = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        if referer:
            req.add_header("Referer", referer)
        with urllib.request.urlopen(req, timeout=15) as r:
            if r.status == 200:
                return r.read().decode("utf-8", "replace")
            last = f"http {r.status}"
    except Exception as e:  # noqa: BLE001
        last = f"{type(e).__name__}: {e}"[:80]
    log.debug("fetch %s failed (%s)", urlparse(url).hostname, last)
    return None
