"""Build and run a temporary sing-box instance to test one config."""
# (English-only; kept for clarity)
from __future__ import annotations
import asyncio
import json
import logging
import socket
import time
from pathlib import Path
from typing import Optional

from .engines import find_binary

log = logging.getLogger("gozar.core")

# Resolved lazily; resolved at first use so that `--help` and list/status
# still work without sing-box installed.
_SINGBOX_PATH: Path | None = None


def singbox_path() -> Path:
    global _SINGBOX_PATH
    if _SINGBOX_PATH is None:
        found = find_binary("sing-box")
        if found is None:
            raise FileNotFoundError(
                "sing-box binary not found. Install it with `bash install.sh`, "
                "place it in ./engines/, or install it system-wide."
            )
        _SINGBOX_PATH = found
    return _SINGBOX_PATH


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def _prefix(addr: str) -> str:
    """sing-box wants a netip.Prefix: `172.16.0.2` must become `172.16.0.2/32`.

    Share links ship the bare address; without the mask the engine refuses the
    whole config ("cannot unmarshal array into ... netip.Prefix"), which would
    look like a dead node.
    """
    a = str(addr).strip()
    if not a or "/" in a:
        return a
    return a + ("/128" if ":" in a else "/32")


def build_endpoint(cfg: dict, tag: str = "proxy") -> dict:
    """Sing-box ENDPOINT form (used by wireguard, which is not an outbound).

    Verified against sing-box 1.14: a `wireguard` object inside `outbounds` is
    rejected ("unknown field server"); it must live in `endpoints` with the peer
    described as a list. `local_address` is the tunnel IP the pool handed us.
    """
    peers = [{
        "address": cfg["server"],
        "port": int(cfg["server_port"]),
        "public_key": cfg["peer_public_key"],
        "allowed_ips": ["0.0.0.0/0", "::/0"],
    }]
    if cfg.get("reserved"):
        peers[0]["reserved"] = list(cfg["reserved"])
    if cfg.get("keepalive"):
        peers[0]["persistent_keepalive_interval"] = int(cfg["keepalive"])
    return {
        "type": "wireguard", "tag": tag,
        "address": [_prefix(a) for a in (cfg.get("local_address") or ["172.16.0.2/32"])],
        "private_key": cfg["private_key"],
        "peers": peers,
        "mtu": int(cfg.get("mtu") or 1280),
    }


def uses_endpoint(cfg: dict) -> bool:
    """True for protocols that sing-box models as an endpoint, not an outbound."""
    return cfg.get("type") == "wireguard"


def build_outbound(cfg: dict, tag: str = "proxy") -> dict:
    """Build a sing-box outbound from a standard config dict."""
    from .core_parser import VALID_UTLS_FP
    t = cfg["type"]
    out: dict = {
        "type": t, "tag": tag,
        "server": cfg["server"], "server_port": int(cfg["server_port"]),
    }
    if t == "vless":
        out["uuid"] = cfg["uuid"]
        if cfg.get("flow"):
            out["flow"] = cfg["flow"]
    elif t == "vmess":
        out["uuid"] = cfg["uuid"]
        out["security"] = cfg.get("security", "auto")
        out["alter_id"] = int(cfg.get("alter_id", 0) or 0)
    elif t == "trojan":
        out["password"] = cfg["password"]
    elif t == "hysteria2":
        out["password"] = cfg.get("password", "")
        out["up_mbps"] = 30
        out["down_mbps"] = 80
        if cfg.get("obfs"):
            out["obfs"] = cfg["obfs"]
    elif t == "tuic":
        out["uuid"] = cfg["uuid"]
        out["password"] = cfg.get("password", "")
        if cfg.get("congestion_control"):
            out["congestion_control"] = cfg["congestion_control"]
        if cfg.get("udp_relay_mode"):
            out["udp_relay_mode"] = cfg["udp_relay_mode"]
    elif t == "shadowsocks":
        out["method"] = cfg["method"]
        out["password"] = cfg["password"]
    elif t == "anytls":
        out["password"] = cfg["password"]
    if cfg.get("tls"):
        tls = dict(cfg["tls"])
        if t in ("hysteria2", "tuic"):
            # QUIC protocols in sing-box do not support uTLS
            tls.pop("utls", None)
        elif isinstance(tls.get("utls"), dict):
            fp = tls["utls"].get("fingerprint", "chrome")
            if fp not in VALID_UTLS_FP:
                tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
                if fp == "unsafe":
                    tls["insecure"] = True
        out["tls"] = tls
    if cfg.get("transport"):
        out["transport"] = cfg["transport"]
    return out


def build_config(cfg: dict, local_port: int) -> dict:
    """Full sing-box config for testing a single entry."""
    inbound = {"type": "mixed", "tag": "in",
               "listen": "127.0.0.1", "listen_port": local_port}
    if uses_endpoint(cfg):
        return {
            "log": {"disabled": True, "timestamp": False},
            "inbounds": [inbound],
            "endpoints": [build_endpoint(cfg, "target")],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "target"},
        }
    out = build_outbound(cfg, "target")
    return {
        "log": {"disabled": True, "timestamp": False},
        "inbounds": [inbound],
        "outbounds": [out, {"type": "direct", "tag": "direct"}],
        "route": {"final": "target"},
    }


async def _wait_port_ready(port: int, proc, max_wait: float = 1.2) -> bool:
    """Wait until sing-box binds 127.0.0.1:port or exits early."""
    deadline = time.monotonic() + max(0.3, max_wait)
    while time.monotonic() < deadline:
        if proc.returncode is not None:
            return False
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=0.15)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            await asyncio.sleep(0.04)
    return proc.returncode is None


# Does the TARGET itself serve a JavaScript shell even when fetched directly,
# with no tunnel involved? Cached per process. This is the difference between
# "the node was shown a wall" (the node's problem, or Google's throttling) and
# "everyone is shown a wall" (single-page-app targets: arena.ai, most React
# dashboards). In the second case no HTTP-only client can prove rendering, so
# the honest criterion is that the host ANSWERED — and target_ok must not be
# permanently false for every node in the pool, which is what made a working
# line look like it had no working node at all.
_SHELL_TARGETS: dict[str, bool] = {}


async def target_is_shell(url: str, ua: str, verify_ssl: bool) -> bool:
    if not url:
        return False
    if url in _SHELL_TARGETS:
        return _SHELL_TARGETS[url]
    from .checker import classify_body
    verdict = False
    try:
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=12)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(url, headers={"User-Agent": ua},
                             ssl=(None if verify_ssl else False)) as r:
                body = await r.read()
                verdict = classify_body(r.status, body, dict(r.headers)) == "js_shell"
    except Exception as e:  # noqa: BLE001
        log.debug("target profile failed for %s (%s) — assuming a normal page", url, e)
        return False          # not cached: a transient failure must not stick
    _SHELL_TARGETS[url] = verdict
    if verdict:
        log.warning("Target %s serves a JavaScript shell on a DIRECT fetch too — "
                    "it is a single-page app, so no HTTP-only client can prove "
                    "the page rendered. For this target, target-ok means the "
                    "host answered over the tunnel (set shell_target_ok=false "
                    "in config to demand a rendered page anyway).", url)
    return verdict


async def _test_via_socks(local_port: int, url: str, timeout: float,
                          ua: str, verify_ssl: bool) -> tuple[int, bytes, dict]:
    import aiohttp
    from .checker import browser_headers
    eff_ua = DEFAULT_UA if (not ua or ua == "Mozilla/5.0") else ua
    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    headers = browser_headers(eff_ua)
    try:
        from aiohttp_socks import ProxyConnector
        connector = ProxyConnector.from_url(
            f"socks5://127.0.0.1:{local_port}", rdns=True, ssl=verify_ssl, limit=2)
        proxy_url = None
    except ImportError:
        # sing-box inbound is "mixed" (accepts both SOCKS5 and HTTP CONNECT proxy),
        # so native aiohttp HTTP proxy works with zero extra dependencies!
        connector = aiohttp.TCPConnector(ssl=verify_ssl, limit=2)
        proxy_url = f"http://127.0.0.1:{local_port}"
    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj,
                                         headers=headers) as s:
            async with s.get(url, proxy=proxy_url, allow_redirects=True) as resp:
                body = await resp.read()
                return resp.status, body, dict(resp.headers)
    finally:
        await connector.close()


def _normalize_targets(target_url) -> list[str]:
    if target_url is None:
        return []
    if isinstance(target_url, str):
        return [target_url] if target_url.strip() else []
    return [u for u in target_url if u and str(u).strip()]


async def _probe_exit_ip(port: int, exit_urls, timeout: float, ua: str,
                         verify_ssl: bool) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Fetch the observed public exit IP through the tunnel. Returns (ip, loc, colo)."""
    from .checker import parse_exit_info, decode_body
    for u in (exit_urls or []):
        try:
            status, body, _ = await asyncio.wait_for(
                _test_via_socks(port, u, timeout, ua, verify_ssl), timeout=timeout + 2)
            if not (200 <= status < 400):
                continue
            ip, loc, colo = parse_exit_info(decode_body(body))
            if ip:
                return ip, loc, colo
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            continue
    return None, None, None


async def _probe_socks_port(port: int, echo_url: str, targets: list[str],
                            timeout: float, target_timeout: float,
                            ua: str, verify_ssl: bool,
                            exit_urls=None, own_ip: str | None = None,
                            verify_exit: bool = True, page_urls=None,
                            shell_target_ok: bool = True) -> dict:
    """Run Echo + Exit-IP-proof + Page-proof + Target HTTP checks over a live
    local SOCKS5 port.

    The page proof exists because a `generate_204`-style answer can come from a
    transparent interceptor while the node itself carries nothing: such a node
    passed the old tester and then showed nothing in a browser."""
    from .checker import _parse_ip, classify_body, decode_body
    result = {"alive": False, "exit_ip": None, "latency": None,
              "target_ok": None, "targets": {}, "target_status": None,
              "security": None, "error": None, "leak": False,
              "exit_verified": False, "exit_loc": None,
              # page proof: a 204 from a transparent interceptor says nothing.
              # We require one REAL page (headers + body) through the tunnel.
              "page_ok": None, "page_status": None, "page_bytes": 0,
              "page_url": None, "page_ms": None, "page_kbps": None}
    start = time.monotonic()
    try:
        status, body, _ = await asyncio.wait_for(
            _test_via_socks(port, echo_url, timeout, ua, verify_ssl),
            timeout=timeout + 2)
        latency = (time.monotonic() - start) * 1000
        if 200 <= status < 400:
            result["alive"] = True
            result["latency"] = round(latency, 1)
            ip = _parse_ip(decode_body(body))
            if ip:
                result["exit_ip"] = ip
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)[:160]

    if not result["alive"]:
        return result

    # Exit-IP proof and target checks run concurrently so verification adds
    # ~0 wall-clock time.
    exit_task = None
    if verify_exit and exit_urls:
        exit_task = asyncio.ensure_future(
            _probe_exit_ip(port, exit_urls, timeout, ua, verify_ssl))

    async def _page():
        """Open one real page through the tunnel (browser UA): status + body size.

        Also records the page's own throughput estimate (bytes / time), which
        --hard uses as a minimum speed gate: latency alone cannot tell a node
        that carries 3KB/s from one that carries 3MB/s, and a node that only
        trickles makes browsing unusable even if every target answers.
        """
        nonlocal result
        for purl in (page_urls or []):
            try:
                _tp = time.monotonic()
                st, bd, _hd = await asyncio.wait_for(
                    _test_via_socks(port, purl, target_timeout, ua, verify_ssl),
                    timeout=target_timeout + 2)
                _secs = max(0.05, time.monotonic() - _tp)
                size = len(bd or b"")
                result["page_ms"] = round(_secs * 1000, 1)
                result["page_kbps"] = round((size / 1024.0) / _secs, 1)
                result["page_status"] = st
                result["page_bytes"] = size
                result["page_url"] = purl
                # any 2xx/3xx with a body means a real HTTP exchange happened;
                # 403 from a Cloudflare edge is also proof the traffic arrived.
                #
                # A /generate_204 endpoint is the exception that used to break
                # this: its contract IS "204 with an empty body", so demanding a
                # body rejected every honest node whenever the page-proof list
                # started with one (the defaults do). Ask the URL what it is.
                _canary = ("generate_204" in purl) or purl.rstrip("/").endswith("/204")
                # A 4xx with a body is a REAL exchange (the tunnel worked, the
                # remote just said no) but it is NOT proof that the page loaded.
                # Keep the two apart: `page_ok` = the page really arrived,
                # `http_reached` = something answered at all.
                _loaded = bool(200 <= st < 400
                               and (size > 0 or st == 304 or (st == 204 and _canary)))
                result["http_reached"] = True
                result["page_ok"] = _loaded
                if _loaded:
                    return
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                continue
        result["page_ok"] = False

    async def _targets():
        all_ok = True
        all_reached = True          # did ANY answer come back (2xx..4xx)?
        throttled_any = False
        for turl in targets:
            rec = {"status": None, "security": None, "ok": False}
            try:
                t0 = time.monotonic()
                status, body, resp_headers = await asyncio.wait_for(
                    _test_via_socks(port, turl, target_timeout, ua, verify_ssl),
                    timeout=target_timeout + 2)
                rec["latency"] = round((time.monotonic() - t0) * 1000, 1)
                sec = classify_body(status, body, resp_headers)
                rec["status"] = status
                rec["security"] = sec
                # `ok`   = the target really served this node (2xx/3xx, or 204
                #          for a canary URL)
                # `reached` = the target answered at all (incl. 403/429). This is
                #          the "usable" signal the default list mode asks about:
                #          a Google/Cloudflare 429 against a datacenter exit IP
                #          proves the tunnel carried the request, and is NOT the
                #          node's fault.
                _canary_t = ("generate_204" in turl) or turl.rstrip("/").endswith("/204")
                # "reached" = the host ANSWERED over the tunnel. It used to
                # exclude a 2xx whose body was a shell, which made a JS-walled
                # or framework target report reached=False for every node — the
                # reason a perfectly good target looked unreachable. What the
                # answer MEANS is `sec` (ok / js_shell / http_429 / blocked);
                # whether the tunnel worked is this flag.
                rec["reached"] = bool(
                    status is not None and (
                        (200 <= status < 400) or (400 <= status < 500)
                        or status == 503 or (_canary_t and status == 204)))
                rec["throttled"] = status in (429, 503)
                # a 2xx whose body is a JavaScript bootstrap document: the
                # node reached the host, but the page did not "load" for a
                # plain HTTP client. Recorded so the answer to "did we really
                # open the page?" is evidence, not a byte count.
                rec["shell"] = sec == "js_shell"
                if body:
                    rec["bytes"] = len(body)
                # A shell that the target serves to EVERY client says nothing
                # about this node: count it as served, but keep the flag so the
                # pool still knows the page proof was structural, not visual.
                # IMPORTANT: this must be decided AFTER the plain `ok` line.
                # Writing `rec["ok"] = True` before it was overwritten by the
                # next statement is how a fix silently does nothing.
                rec["ok"] = bool(rec["reached"] and sec == "ok") or bool(
                    _canary_t and status == 204)
                if (rec["shell"] and 200 <= (status or 0) < 300
                        and shell_target_ok
                        and await target_is_shell(turl, ua, verify_ssl)):
                    rec["shell_expected"] = True
                    rec["ok"] = True
                if not rec["ok"]:
                    all_ok = False
                if not rec["reached"]:
                    all_reached = False
                if rec["throttled"]:
                    throttled_any = True
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                rec["security"] = "error"
                rec["error"] = str(e)[:120]
                all_ok = False
            result["targets"][turl] = rec
        if result["targets"]:
            first = result["targets"][targets[0]]
            result["target_status"] = first["status"]
            result["security"] = first["security"]
            result["target_ok"] = all_ok
            # "usable": the target answered, even if it said 429/403. Kept
            # separate from target_ok so the list can be strict while the live
            # pool is not (that distinction is the whole point of list_mode).
            result["target_reached"] = all_reached
            result["target_throttled"] = throttled_any
            _t0 = result["targets"][targets[0]]
            result["target_shell"] = bool(_t0.get("shell"))
            result["target_bytes"] = _t0.get("bytes")
            ok_lat = [v.get("latency") for v in result["targets"].values()
                      if v.get("ok") and v.get("latency") is not None]
            result["target_latency"] = min(ok_lat) if ok_lat else None

    tgt_task = asyncio.ensure_future(_targets()) if targets else None
    page_task = asyncio.ensure_future(_page()) if page_urls else None
    try:
        if exit_task is not None:
            eip, eloc, _colo = await exit_task
            result["exit_ip"] = eip or result["exit_ip"]
            result["exit_loc"] = eloc
            result["exit_verified"] = bool(eip)
        if page_task is not None:
            await page_task
        if tgt_task is not None:
            await tgt_task
    except asyncio.CancelledError:
        for t in (exit_task, tgt_task, page_task):
            if t is not None and not t.done():
                t.cancel()
        raise

    # ── tunnel proof verdict ──
    # Exit IP identical to this machine's own public IP means the traffic never
    # crossed the node (transparent interception / direct leak): reject it, or a
    # dead node gets reported as "alive and fast".
    # ── liveness gate: echo alone is not proof of a working tunnel ──
    # A node counts as ALIVE (eligible for gen) only when it really carried
    # HTTP both ways. Without this, `bot pick` offered nodes that answered a
    # 204 but opened no page — exactly the "100 nodes, none of them connect" report.
    if result.get("alive") and page_urls:
        if not result.get("page_ok"):
            st = result.get("page_status")
            # Distinguish three different failures; they used to share one
            # message, which is why a 429 from a rate-limiting host looked like a
            # dead node:
            #   429 / 503   the host is throttling this exit IP (datacenter
            #               ranges are refused) — the node is FINE for the web,
            #               it just cannot pass THIS url. Let the targets decide.
            #   403         a plain block/challenge (Cloudflare). Traffic did
            #               arrive; keep it as evidence, not as proof.
            #   none        the request produced nothing at all -> dead.
            _throttled = st in (429, 503)
            result["page_throttled"] = bool(_throttled)
            if not (_throttled or st == 403):
                result["alive"] = False
                result["target_ok"] = False
                result["security"] = "no_page"
            _what = "a throttled" if _throttled else "no real"
            _why = (" (the host is rate-limiting this exit IP, not a dead node)"
                    if _throttled else "")
            result["error"] = (result.get("error") or
                               f"page proof failed (status={st}, "
                               f"{result.get('page_bytes')}B) — node answered but "
                               f"carried {_what} page{_why}")
    if verify_exit and own_ip and result.get("exit_verified"):
        if result["exit_ip"] == own_ip:
            result["leak"] = True
            result["alive"] = False
            result["target_ok"] = False
            result["security"] = "leak"
            result["error"] = (f"exit IP {result['exit_ip']} == own line IP "
                               f"(traffic never entered the tunnel)")
    return result


def build_batch_config(cfgs: list[dict], ports: list[int]) -> dict:
    """Build a single multi-inbound sing-box config to test N nodes in one process."""
    inbounds = []
    outbounds = []
    endpoints = []
    rules = []
    for i, (cfg, port) in enumerate(zip(cfgs, ports)):
        in_tag = f"in-{i}"
        out_tag = f"out-{i}"
        inbounds.append({
            "type": "mixed", "tag": in_tag,
            "listen": "127.0.0.1", "listen_port": port,
        })
        # wireguard is an endpoint, everything else an outbound; both can be
        # routed to by tag, so a batch may mix them freely
        if uses_endpoint(cfg):
            endpoints.append(build_endpoint(cfg, out_tag))
        else:
            outbounds.append(build_outbound(cfg, out_tag))
        rules.append({"inbound": [in_tag], "outbound": out_tag})
    outbounds.append({"type": "direct", "tag": "direct"})
    conf = {
        "log": {"disabled": True, "timestamp": False},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct"},
    }
    if endpoints:
        conf["endpoints"] = endpoints
    return conf


async def test_configs_batch(
    cfgs: list[dict],
    echo_url: str,
    target_url,
    timeout: float = 8,
    target_timeout: float = 12,
    startup: float = 0.8,
    ua: str = DEFAULT_UA,
    verify_ssl: bool = False,
    on_one_done=None,
    stop_check=None,
    exit_urls=None,
    own_ip: Optional[str] = None,
    verify_exit: bool = True,
    page_urls=None,
    shell_target_ok: bool = True,
) -> list[tuple[dict, dict]]:
    """Test a batch of configs concurrently inside ONE sing-box process.
    Calls `await on_one_done(cfg, res)` as each individual config completes so
    state can be saved incrementally in real time and early-stop can trigger
    immediately."""
    if not cfgs:
        return []
    targets = _normalize_targets(target_url)
    workdir = Path("/tmp/sbtest")
    workdir.mkdir(parents=True, exist_ok=True)
    ports: list[int] = []
    cfg_file: Path | None = None
    proc = None
    started = False

    for attempt in range(2):
        used_ports: set[int] = set()
        ports = []
        for _ in cfgs:
            p = free_port()
            while p in used_ports:
                p = free_port()
            used_ports.add(p)
            ports.append(p)
        sb_cfg = build_batch_config(cfgs, ports)
        cfg_file = workdir / f"batch-{ports[0]}-{len(cfgs)}.json"
        cfg_file.write_text(json.dumps(sb_cfg), encoding="utf-8")
        proc = await asyncio.create_subprocess_exec(
            str(singbox_path()), "run", "-c", str(cfg_file),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        ready = await _wait_port_ready(ports[0], proc, max_wait=max(0.8, startup * 1.5))
        if ready and proc.returncode is None:
            started = True
            break
        err = (await proc.stderr.read()).decode("utf-8", "ignore")[:160]
        try:
            cfg_file.unlink(missing_ok=True)
        except Exception:
            pass
        if attempt == 0 and ("bind" in err.lower() or "address already in use" in err.lower()):
            continue
        break

    if not started:
        # Fallback: one malformed config in the batch — test individually so
        # valid nodes in the batch are not lost.
        out_pairs = []

        async def _fb_one(c):
            if stop_check and stop_check():
                return
            r = await test_config(
                c, echo_url=echo_url, target_url=targets,
                timeout=timeout, target_timeout=target_timeout,
                startup=startup, ua=ua, verify_ssl=verify_ssl,
                exit_urls=exit_urls, own_ip=own_ip, verify_exit=verify_exit,
                page_urls=page_urls,
            )
            out_pairs.append((c, r))
            if on_one_done:
                await on_one_done(c, r)

        await asyncio.gather(*(_fb_one(c) for c in cfgs), return_exceptions=True)
        return out_pairs

    out_pairs: list[tuple[dict, dict]] = []
    tasks: list[asyncio.Task] = []

    async def _run_idx(c: dict, port: int):
        if stop_check and stop_check():
            return
        try:
            r = await _probe_socks_port(
                port, echo_url, targets, timeout, target_timeout, ua, verify_ssl,
                exit_urls=exit_urls, own_ip=own_ip, verify_exit=verify_exit,
                page_urls=page_urls,
                shell_target_ok=shell_target_ok)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            r = {"alive": False, "exit_ip": None, "latency": None,
                 "target_ok": None, "targets": {}, "target_status": None,
                 "security": None, "error": str(e)[:160]}
        out_pairs.append((c, r))
        if on_one_done:
            await on_one_done(c, r)
        if stop_check and stop_check():
            for t in tasks:
                if not t.done() and t is not asyncio.current_task():
                    t.cancel()

    try:
        tasks = [asyncio.create_task(_run_idx(c, p)) for c, p in zip(cfgs, ports)]
        await asyncio.gather(*tasks, return_exceptions=True)
        return out_pairs
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        if proc is not None and proc.returncode is None:
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                pass
        if cfg_file is not None:
            try:
                cfg_file.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass


async def test_config(cfg: dict, echo_url: str, target_url,
                      timeout: float = 10, target_timeout: float = 12,
                      startup: float = 1.0, ua: str = DEFAULT_UA,
                      verify_ssl: bool = False,
                      exit_urls=None, own_ip: Optional[str] = None,
                      verify_exit: bool = True, page_urls=None,
                      shell_target_ok: bool = True) -> dict:
    """Run and test one config via sing-box."""
    targets = _normalize_targets(target_url)
    result = {"alive": False, "exit_ip": None, "latency": None,
              "target_ok": None, "targets": {}, "target_status": None,
              "security": None, "error": None, "leak": False,
              "exit_verified": False, "exit_loc": None}
    if not singbox_path().exists():
        result["error"] = "sing-box not found"
        return result

    port = 0
    cfg_file = None
    proc = None
    workdir = Path("/tmp/sbtest")
    workdir.mkdir(parents=True, exist_ok=True)
    eff_cfg = cfg
    for attempt in range(2):
        port = free_port()
        sb_cfg = build_config(eff_cfg, port)
        cfg_file = workdir / f"cfg-{port}.json"
        cfg_file.write_text(json.dumps(sb_cfg), encoding="utf-8")

        proc = await asyncio.create_subprocess_exec(
            str(singbox_path()), "run", "-c", str(cfg_file),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        ready = await _wait_port_ready(port, proc, max_wait=max(0.8, startup * 1.5))
        if ready and proc.returncode is None:
            break  # bound ok
        err = (await proc.stderr.read()).decode("utf-8", "ignore")[:160]
        try:
            cfg_file.unlink(missing_ok=True)
        except Exception:
            pass
        if attempt == 0 and ("bind" in err.lower() or "address already in use" in err.lower()):
            log.debug("Port %d taken, retrying with a fresh one", port)
            continue
        return {"alive": False, "exit_ip": None, "latency": None,
                "target_ok": None, "targets": {}, "target_status": None,
                "security": None, "error": err or "sing-box failed to start",
                "leak": False, "exit_verified": False, "exit_loc": None}
    try:
        if proc.returncode is not None:
            err = await proc.stderr.read()
            result["error"] = err.decode("utf-8", "ignore")[:160]
            return result
        return await _probe_socks_port(
            port, echo_url, targets, timeout, target_timeout, ua, verify_ssl,
            exit_urls=exit_urls, own_ip=own_ip, verify_exit=verify_exit,
            page_urls=page_urls)
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                pass
        try:
            cfg_file.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass
