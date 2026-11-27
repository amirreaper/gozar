"""Shared measurement tools — trimmed after the HTTP/SOCKS generation died.

Kept: baseline ping, fast-threshold computation, response classification,
IP extraction. Removed: all probe/verify logic of the dead HTTP/SOCKS era.
"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Optional

log = logging.getLogger("gozar.checker")

IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
# IPv6 exits are common behind Cloudflare-fronted nodes: without this the exit
# proof silently reports "unverified" for perfectly healthy nodes.
IP6_RE = re.compile(r"(?<![:.\w])((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})(?![:.\w])")

# common Cloudflare / security-page markers (all lowercase to match lowered body)
CF_CHALLENGE_MARKERS = [
    b"cf-browser-verification",
    b"cf-challenge",
    b"<title>just a moment...",
    b"<title>attention required",
    b"cloudflare ray id",
    b"_cf_chl_opt",
    b"challenges.cloudflare.com/turnstile",
]
BLOCK_MARKERS = [
    b"access denied",
    b"403 forbidden",
    b"request blocked",
    b"your ip has been banned",
]


def valid_ip(value) -> Optional[str]:
    """Normalize/validate an IPv4 or IPv6 literal; None when it is not an IP."""
    import ipaddress
    if not value:
        return None
    v = str(value).strip().strip("[]").split("%")[0]
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def _parse_ip(text: str) -> Optional[str]:
    """First IPv4 (preferred) or IPv6 literal found in a body."""
    if not text:
        return None
    try:
        data = json.loads(text)
        for key in ("ip", "query", "address"):
            got = valid_ip(data.get(key))
            if got:
                return got
    except Exception:  # noqa: BLE001
        pass
    m = IP_RE.search(text)
    if m:
        v4 = valid_ip(m.group(1))
        if v4:
            return v4
    for m6 in IP6_RE.finditer(text):
        v6 = valid_ip(m6.group(1))
        if v6 and ":" in v6:
            return v6
    return None


# ───────────────────────── tunnel proof (exit-IP verification) ─────────────────────────
# A 2xx/204 answer alone proves nothing: on interfered/transparent lines the
# request can be answered WITHOUT ever crossing the node (leak), so a dead node
# looks "alive and fast". Requiring the observed exit IP to differ from this
# machine's own public IP is the only reliable proof that traffic really went
# through the tunnel.
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# Cloudflare trace is first: one request yields ip= AND loc= (country) AND colo=,
# and the CF edge stays reachable even during national-internet phases.
EXIT_PROBE_URLS = (
    # first: one request yields ip= + loc= (country) + colo=, and the CF edge
    # usually stays reachable even during national-internet phases
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://api.ipify.org?format=text",
    "https://api.ip.sb/ip",
    "https://icanhazip.com/",
    "https://checkip.amazonaws.com/",
    "https://ipinfo.io/ip",
    "https://ifconfig.me/ip",
)


def browser_headers(ua: Optional[str] = None) -> dict:
    """Full realistic Chrome navigation headers (bare-UA clients get CF-challenged).

    NOTE: Accept-Encoding is deliberately NOT set. Declaring "br" while aiohttp
    has no brotli decoder yields an undecodable compressed body, which silently
    broke exit-IP and challenge-marker parsing. aiohttp advertises exactly the
    encodings it can decode on its own.
    """
    return {
        "User-Agent": ua or BROWSER_UA,
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,image/apng,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }


def decode_body(body) -> str:
    """Best-effort bytes -> text, transparently undoing gzip/deflate/brotli.

    Some servers compress even when we do not ask; without this the exit-IP and
    challenge-marker parsing silently sees binary garbage.
    """
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    import gzip
    import zlib
    raw = bytes(body)
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except Exception:  # noqa: BLE001
            pass
    else:
        for wbits in (-zlib.MAX_WBITS, zlib.MAX_WBITS, 47):
            try:
                raw = zlib.decompress(raw, wbits)
                break
            except Exception:  # noqa: BLE001
                continue
    try:  # brotli, only when a decoder happens to be installed
        import brotli  # type: ignore
        raw = brotli.decompress(raw)
    except Exception:  # noqa: BLE001
        pass
    try:
        return raw.decode("utf-8")
    except Exception:  # noqa: BLE001
        return raw.decode("latin-1", "ignore")


def parse_exit_info(text: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse an exit-IP probe body -> (ip, country_code, colo).

    Handles Cloudflare `/cdn-cgi/trace` key=value lines (ip=, loc=, colo=) as
    well as bare-IP / JSON bodies from ipify-style services.
    """
    if not text:
        return None, None, None
    t = text.strip()
    ip = loc = colo = None
    first = t.splitlines()[0] if t.splitlines() else ""
    if "=" in first and len(first) < 80 and not t.startswith("{"):
        kv = {}
        for line in t.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                kv[k.strip().lower()] = v.strip()
        ip = kv.get("ip")
        loc = kv.get("loc")
        colo = kv.get("colo")
    else:
        ip = _parse_ip(t)
    ip = valid_ip(ip) if ip else None
    if not ip:
        # salvage from a JSON/HTML body (or a compressed one, already decoded)
        ip = _parse_ip(t)
    if loc and (len(loc) != 2 or not loc.isalpha()):
        loc = None
    return ip, (loc.upper() if loc else None), (colo.upper() if colo else None)


async def measure_own_ip(urls=EXIT_PROBE_URLS, timeout: float = 8.0,
                         ua: Optional[str] = None) -> tuple[Optional[str], Optional[str]]:
    """Direct (NO proxy) baseline: this machine's own public IP + country code.

    Any node whose observed exit IP equals this value is not carrying traffic.
    """
    import aiohttp
    hdrs = browser_headers(ua)
    hdrs["Accept"] = "*/*"
    try:
        async with aiohttp.ClientSession(headers=hdrs) as s:
            for u in urls:
                try:
                    async with s.get(u, timeout=aiohttp.ClientTimeout(total=timeout),
                                     ssl=False) as r:
                        body = (await r.text())[:4000]
                    ip, loc, _ = parse_exit_info(body)
                    if ip:
                        return ip, loc
                except Exception:  # noqa: BLE001
                    continue
    except Exception as e:  # noqa: BLE001
        log.debug("measure_own_ip failed: %s", e)
    return None, None


# ---------------------------------------------------------------- baseline ping

async def udp_quic_ping(host: str, port: int, timeout: float = 1.5) -> Optional[float]:
    """Send an RFC 9000 §6 GREASE-version QUIC Long-Header packet (>=1200 bytes)
    over UDP and measure RTT to the server's Version Negotiation response.
    Returns RTT in ms, or None if unreachable/refused."""
    import os
    import time
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    class _QuicProbeProto(asyncio.DatagramProtocol):
        def connection_made(self, tr):
            pkt = (
                b"\xc0\x0a\x0a\x0a\x0a\x08"
                + os.urandom(8)
                + b"\x08"
                + os.urandom(8)
                + b"\x00" * 1177
            )
            tr.sendto(pkt)

        def datagram_received(self, data, addr):
            if not fut.done():
                fut.set_result(True)

        def error_received(self, exc):
            if not fut.done():
                fut.set_result(False)

    t0 = time.monotonic()
    tr = None
    try:
        tr, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(_QuicProbeProto, remote_addr=(host, int(port))),
            timeout=timeout,
        )
        ok = await asyncio.wait_for(fut, timeout=timeout)
        if ok:
            return round((time.monotonic() - t0) * 1000.0, 1)
        return None
    except Exception:  # noqa: BLE001
        return None
    finally:
        if tr is not None:
            tr.close()


async def tcp_ping(host: str, port: int, timeout: float = 4.0) -> Optional[float]:
    """TCP connect time to a host in milliseconds."""
    try:
        loop = asyncio.get_event_loop()
        t0 = loop.time()
        fut = asyncio.open_connection(host=host, port=port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        dt = (loop.time() - t0) * 1000.0
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return round(dt, 1)
    except Exception:  # noqa: BLE001
        return None


async def measure_baseline(hosts: list[str], timeout: float = 4.0) -> dict:
    """Median TCP connect to anycast hosts as baseline ping."""
    times: list[float] = []
    for hp in hosts:
        try:
            host, port = hp.rsplit(":", 1)
            port = int(port)
        except ValueError:
            continue
        for _ in range(2):
            dt = await tcp_ping(host, port, timeout)
            if dt is not None:
                times.append(dt)
    if not times:
        return {"baseline_ms": None, "fast_threshold_ms": 500, "samples": []}
    times.sort()
    median = times[len(times) // 2]
    samples = times[:6]
    return {"baseline_ms": round(median, 1), "samples": samples}


def compute_fast_threshold(baseline_ms: Optional[float], cfg: dict) -> float:
    """Return the 'fast' ceiling in ms.

    Resolution order:
      1. cfg['fast_max_ms'] > 0  -> manual ceiling (highest priority)
      2. Tiered model based on the user's baseline ping:
           < 200 ms   -> fast_tier_low   (default 1500)
           200..500   -> fast_tier_mid   (default 2500)
           > 500      -> fast_tier_high  (default 4000)
         (Designed for long-haul links where 500-1500ms is normal.)
      3. Legacy factor model if cfg['use_legacy_threshold'] is set.
    """
    manual = cfg.get("fast_max_ms")
    if manual and float(manual) > 0:
        return float(manual)
    if cfg.get("use_legacy_threshold"):
        factor = float(cfg.get("fast_factor", 1.2))
        fmin = float(cfg.get("fast_min_ms", 150))
        fmax = float(cfg.get("fast_max_ms_hardcap", 2000))
        if not baseline_ms:
            return fmax
        return max(fmin, min(fmax, baseline_ms * factor))
    if not baseline_ms:
        return float(cfg.get("fast_tier_high", 4000))
    b = float(baseline_ms)
    if b < 200:
        return float(cfg.get("fast_tier_low", 1500))
    if b <= 500:
        return float(cfg.get("fast_tier_mid", 2500))
    return float(cfg.get("fast_tier_high", 4000))


def describe_baseline(baseline_ms: Optional[float], cfg: dict) -> str:
    """Human-readable summary of the baseline and chosen thresholds."""
    if not baseline_ms:
        return f"Baseline: unknown  ->  fast ceiling: {compute_fast_threshold(None, cfg)}ms (lenient)"
    b = float(baseline_ms)
    if b < 200:
        tier = "<200ms (good connection)"
    elif b <= 500:
        tier = "200-500ms (average)"
    else:
        tier = ">500ms (slow/long haul)"
    fast = compute_fast_threshold(b, cfg)
    bak = float(cfg.get("backup_max_ms", 10000))
    manual = cfg.get("fast_max_ms")
    note = " (manual override)" if manual and float(manual) > 0 else ""
    return (f"Your ping: {b:.0f}ms  [{tier}]  ->  "
            f"fast ceiling: {fast:.0f}ms{note}, backup ceiling: {bak:.0f}ms")


# ---------------------------------------------------------------- classify

# A page smaller than this much visible text, containing no content markup,
# is a loader document rather than a page. 4096 is deliberately generous: a
# real search result, article or login form is far larger.
_SHELL_MAX_TEXT = 4096

# Structural signature of a loader document: this much markup carrying this
# few visible words cannot be a result page, an article or a form. Google's
# wall is ~93KB of script around 17 words.
_SHELL_MIN_BYTES = 20000
_SHELL_MAX_WORDS = 200
# Visible characters per byte of document. Measured anchors:
#   real content page            0.65
#   script-heavy but real page   0.11
#   arena.ai (Next.js shell)     0.0065
# 0.04 sits an order of magnitude below real pages and above framework shells.
_SHELL_MAX_TEXT_RATIO = 0.04

# Markers of a JavaScript bootstrap document. Matched case-insensitively.
# These catch small loaders; the structural test above catches localised ones.
_SHELL_MARKERS = (
    "if you are not redirected",
    "please click here",
    "enable javascript",
    "javascript is disabled",
    "requires javascript",
)


def _has_shell_markers(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _SHELL_MARKERS)


def visible_text(html: str) -> str:
    """Strip tags/scripts/styles so a "page" can be judged by words, not bytes."""
    import re
    txt = re.sub(r"(?is)<(script|style|noscript|template)[^>]*>.*?</\1>", " ", html)
    txt = re.sub(r"(?s)<[^>]+>", " ", txt)
    txt = re.sub(r"&[a-zA-Z#0-9]+;", " ", txt)
    return " ".join(txt.split())


def classify_body(status: int, body: bytes, headers: dict | None = None) -> str:
    # decode first: a compressed body would hide every challenge marker and let
    # a Cloudflare "Just a moment..." page be misread as a normal response
    low = decode_body(body)[:4000].lower().encode("utf-8", "ignore") if body else b""
    hdrs = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    if hdrs.get("cf-mitigated") == "challenge":
        return "cf_challenge"
    if status == 403:
        if any(m in low for m in CF_CHALLENGE_MARKERS) or "cf-ray" in hdrs:
            return "cf_block"
        if any(m in low for m in BLOCK_MARKERS):
            return "blocked"
        return "blocked"
    if status in (429, 503):
        if any(m in low for m in CF_CHALLENGE_MARKERS) or b"just a moment" in low or "cf-ray" in hdrs:
            return "cf_challenge"
    if 200 <= status < 400:
        # A 200 whose body is a SCRIPT SHELL is not a loaded page. Google (and a
        # growing number of single-page sites) answer a plain HTTP client with a
        # ~90KB bootstrap document whose only visible text is "please click here
        # if you are not redirected" and whose content is injected by JS later.
        # Byte count cannot tell that apart from a real page, so without this
        # check `page_ok` was true for every node that could open Google — and
        # the tool reported "target OK, page loaded" for a node that was shown a
        # wall. gbv=1 (Google basic HTML) now serves the same shell, so there is
        # no query parameter to dodge it either.
        _txt = decode_body(body) if body else ""
        # Judge by VISIBLE WORDS, not document size: the Google bootstrap
        # document is ~93KB of inline script around one line of text, so any
        # byte-based test sees a "full page".
        #
        # Two tests, because the marker test alone was fooled by localisation:
        # Google serves the same wall in Indonesian ("Jika Anda mengalami
        # masalah saat mengakses Google Penelusuran..."), which matched no
        # English phrase and was reported as a served page. The structural
        # test is language-independent: a big document with almost no words is
        # a loader, whatever it says.
        _vt = visible_text(_txt) if _txt else ""
        # (a) known loader/redirect wording — small pages, any size
        # (b) a BIG document with almost no words — Google's 93KB wall
        # (c) a BIG document whose text lives in the script payload — a
        #     framework shell (Next/Nuxt/Vite). arena.ai was called a wall by
        #     the old byte-and-word test purely because its 131KB bundle hides
        #     848 characters of UI copy in JS strings, and that single
        #     misclassification blanked the default target for every node.
        #     A page whose text is in the markup has a ratio two orders of
        #     magnitude higher (0.64 measured on a real page vs 0.007 here).
        if _txt and (
                (len(_vt) < _SHELL_MAX_TEXT and _has_shell_markers(_txt))
                or (len(body) >= _SHELL_MIN_BYTES
                    and len(_vt.split()) <= _SHELL_MAX_WORDS)
                or (len(body) >= _SHELL_MIN_BYTES
                    and len(_vt) / max(1, len(body)) < _SHELL_MAX_TEXT_RATIO)):
            return "js_shell"
        if (b"<title>just a moment" in low
                or b"<title>attention required" in low
                or b"cf-browser-verification" in low):
            return "cf_challenge"
        return "ok"
    return f"http_{status}"


# Cloudflare published IPv4 ranges — during "national internet" phases the CF
# edge often stays reachable when everything else is cut, so CF-fronted nodes
# are the highest-value candidates.
import ipaddress as _ip

CF_RANGES = tuple(_ip.ip_network(n) for n in (
    "104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15", "188.114.96.0/20",
    "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "173.245.48.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
))


def is_cloudflare(host: str) -> bool:
    """True when the node server is a literal IP inside Cloudflare ranges."""
    try:
        a = _ip.ip_address(str(host).strip())
    except ValueError:
        return False
    return any(a in n for n in CF_RANGES)


# ───────────── open-corridor filters (rahya 1.1.0) ─────────────
# Measured on a real filtered line (per-node autopsy, Oct 2026): the filter
# SNI-rejects exotic domains during the TLS handshake and resets uncommon
# ports — while google/gstatic/cloudflare/wikipedia/githubusercontent and
# ANY *.ir hostname complete TLS. These filters encode exactly that.

OPEN_SNI_DEFAULT = frozenset({
    "www.google.com", "google.com", "www.gstatic.com", "gstatic.com",
    "www.cloudflare.com", "cloudflare.com", "speed.cloudflare.com",
    "www.wikipedia.org", "wikipedia.org", "raw.githubusercontent.com",
    "one.one.one.one",
})

# ports measured to complete handshakes behind the filter
SAFE_PORTS = frozenset({443, 8443, 80, 2083})


def node_sni(c: dict) -> str:
    """The hostname the node's TLS would present (tls.server_name ->
    transport.host -> server), lowercased."""
    tls = c.get("tls") or {}
    tr = c.get("transport") or {}
    return (tls.get("server_name") or tr.get("host")
            or c.get("server") or "").strip().lower()


def _host_match(host: str, allow: set) -> bool:
    return host in allow or any(host.endswith("." + d) for d in allow)


def sni_is_open(c: dict, allow: set) -> bool:
    """True when the node's SNI is (sub)domain of today's open set, or a
    domestic *.ir hostname (measured: they always complete TLS)."""
    sni = node_sni(c)
    if not sni:
        return False
    if sni.endswith(".ir"):
        return True
    return _host_match(sni, allow)


def port_is_safe(c: dict) -> bool:
    try:
        return int(c.get("server_port") or 0) in SAFE_PORTS
    except (TypeError, ValueError):
        return False


def load_open_sni(data_dir) -> set:
    """Open-SNI pool: built-in defaults + hosts measured OPEN earlier and saved
    in data/shutdown_profile.json (written by the shutdown-mode probe)."""
    hosts = set(OPEN_SNI_DEFAULT)
    prof = Path(data_dir) / "shutdown_profile.json"
    try:
        obj = json.loads(prof.read_text(encoding="utf-8"))
        for h in obj.get("open", []) or []:
            hosts.add(str(h).strip().lower())
    except Exception:
        pass
    return hosts
