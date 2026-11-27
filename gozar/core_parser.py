"""Parse v2ray/xray/sing-box config links into a standard dict.

Each function returns:
{
  "type": "vless"|"hysteria2"|"trojan"|"shadowsocks"|"vmess"|"tuic"
          |"anytls"|"wireguard",
  "server": str, "server_port": int,
  "tag": str,
  ... protocol fields ...
  "tls": {...} | None,
  "transport": {...} | None,
}
or None if invalid/unsupported.
"""
from __future__ import annotations
import base64
import binascii
import json
import re
from urllib.parse import urlparse, parse_qs, unquote, urlencode

# Valid uTLS fingerprints supported by sing-box
VALID_UTLS_FP = frozenset({
    "chrome", "firefox", "edge", "safari", "360", "qq",
    "ios", "android", "random", "randomized",
})

# Valid Shadowsocks methods supported by sing-box
VALID_SS_METHODS = frozenset({
    "none", "plain",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf", "xchacha20",
})

SS_METHOD_ALIASES = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "AEAD_CHACHA20_POLY1305": "chacha20-ietf-poly1305",
    "AEAD_AES_128_GCM": "aes-128-gcm",
    "AEAD_AES_256_GCM": "aes-256-gcm",
    "dummy": "none",
}


def _b64d(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    # Strip any non-base64 trailing garbage (e.g. emojis or stray chars before #)
    s = re.sub(r"[^A-Za-z0-9+/=]", "", s)
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=False)


def _q(qs: dict, key: str, default=None):
    v = qs.get(key)
    if not v:
        return default
    return v[0]


def _clean_ws_path(raw_path: str) -> tuple[str, int | None]:
    """Extract Xray/v2rayN ?ed=N Early Data directive from WebSocket path
    and return (clean_path, max_early_data).
    Sending raw '?ed=2048' in the HTTP upgrade path to the server causes 404
    on Xray/Cloudflare WS endpoints."""
    path = raw_path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if "ed=" not in path:
        return path, None
    p = urlparse(path)
    qs = parse_qs(p.query, keep_blank_values=True)
    ed_vals = qs.pop("ed", None)
    ed_int = None
    if ed_vals:
        try:
            ed_int = int(str(ed_vals[0]).strip())
        except (ValueError, TypeError):
            ed_int = None
    new_query = urlencode(qs, doseq=True)
    clean = p.path or "/"
    if new_query:
        clean = f"{clean}?{new_query}"
    return clean, ed_int


def _transport(qs: dict, fallback_host: str = "") -> dict | None:
    t = (_q(qs, "type") or "tcp").lower()
    host_hdr = _q(qs, "host") or _q(qs, "sni") or _q(qs, "peer") or fallback_host
    if t == "ws":
        clean_path, ed_int = _clean_ws_path(_q(qs, "path", "/"))
        out: dict = {
            "type": "ws",
            "path": clean_path,
            "headers": {"Host": host_hdr} if host_hdr else {},
        }
        if ed_int and ed_int > 0:
            out["max_early_data"] = ed_int
            out["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return out
    if t in ("grpc", "gun"):
        return {"type": "grpc", "service_name": _q(qs, "serviceName", _q(qs, "path", ""))}
    if t == "httpupgrade":
        clean_path, _ = _clean_ws_path(_q(qs, "path", "/"))
        return {"type": "httpupgrade", "path": clean_path, "host": host_hdr or ""}
    if t in ("http", "h2"):
        hosts = _q(qs, "host", "") or host_hdr
        return {
            "type": "http",
            "hosts": [h for h in hosts.split(",") if h] if hosts else [],
            "path": _q(qs, "path", "/"),
        }
    if t in ("xhttp", "splithttp"):
        # Xray-only splithttp/xhttp is protocol-incompatible with sing-box
        return {"type": "_unsupported_xhttp"}
    return None


def _normalize_fp(fp: str | None) -> tuple[str | None, bool]:
    """Return (valid_singbox_fp_or_None, implies_insecure)."""
    if not fp:
        return None, False
    f = fp.strip().lower()
    if f in ("none", "off", "false", "0"):
        return None, False
    if f == "unsafe":
        return "chrome", True
    if f in VALID_UTLS_FP:
        return f, False
    return "chrome", False


def _tls(qs: dict, server_name: str | None, allow_utls: bool = True) -> dict | None:
    sec = (_q(qs, "security") or "").lower()
    if sec not in ("tls", "reality"):
        return None
    t: dict = {"enabled": True}
    # Fall back to 'host' parameter before raw server IP
    sni = _q(qs, "sni") or _q(qs, "peer") or _q(qs, "host") or server_name
    if sni:
        t["server_name"] = sni
    alpn = _q(qs, "alpn")
    if alpn:
        t["alpn"] = [a.strip() for a in unquote(alpn).split(",") if a.strip()]
    raw_fp = _q(qs, "fp", "chrome" if allow_utls else None)
    fp, fp_insecure = _normalize_fp(raw_fp)
    if allow_utls and fp:
        t["utls"] = {"enabled": True, "fingerprint": fp}
    insec = (_q(qs, "allowInsecure") or _q(qs, "insecure") or _q(qs, "skip-cert-verify") or "").lower()
    if insec in ("1", "true", "yes") or fp_insecure:
        t["insecure"] = True
    if sec == "reality":
        pbk = _q(qs, "pbk")
        if not pbk:
            return None
        t.pop("insecure", None)  # Reality does not use insecure flag
        t["reality"] = {"enabled": True, "public_key": pbk}
        sid = _q(qs, "sid")
        if sid:
            t["reality"]["short_id"] = sid
    return t


def _tag(parts, host: str, port: int = 0) -> str:
    tag = unquote(parts.fragment or "").strip()
    return tag or f"{host}:{port or parts.port or 0}"


def _extract_port_and_clean_url(url: str) -> tuple[str, int | None, list[str] | None]:
    """Handle port ranges like host:21000-21199,33000-33199 or special chars in
    userinfo before calling urlparse."""
    # If port contains range/comma (e.g. :21000-21199,33000-33199), rewrite to first port
    m = re.match(r"^([a-zA-Z0-9+.-]+://[^/]*?@[^/:?#]+):(\d+)-(\d+)(?:,[\d,-]+)?(.*)$", url)
    if m:
        prefix, p_start, p_end, rest = m.groups()
        port = int(p_start)
        # Extract all ranges for sing-box server_ports if needed
        raw_port_spec = url[len(prefix) + 1:len(url) - len(rest)]
        ranges = [r.replace("-", ":") for r in raw_port_spec.split(",") if "-" in r]
        return f"{prefix}:{port}{rest}", port, (ranges or None)
    return url, None, None


def parse_vless(url: str) -> dict | None:
    try:
        clean_url, _, _ = _extract_port_and_clean_url(url)
        p = urlparse(clean_url)
        if p.scheme not in ("vless", "vless:"):
            return None
        uuid = unquote(p.username or "").strip("[]")
        host = p.hostname
        port = p.port or 443
        if not uuid or not host or not port:
            return None
        qs = parse_qs(p.query)
        out = {
            "type": "vless", "server": host, "server_port": port,
            "uuid": uuid, "tag": _tag(p, host, port),
        }
        flow = _q(qs, "flow")
        if flow:
            out["flow"] = flow
        tls = _tls(qs, host)
        if tls:
            out["tls"] = tls
        tr = _transport(qs)
        if tr:
            if tr.get("type") == "_unsupported_xhttp":
                return None
            out["transport"] = tr
        return out
    except Exception:
        return None


def parse_trojan(url: str) -> dict | None:
    try:
        # Handle unescaped '#' or '[' inside password before '@'
        scheme, _, rest = url.partition("://")
        if "@" not in rest:
            return None
        userinfo, _, after_at = rest.rpartition("@")
        from urllib.parse import quote
        safe_url = f"{scheme}://{quote(unquote(userinfo), safe='')}@{after_at}"
        p = urlparse(safe_url)
        host = p.hostname
        port = p.port or 443
        if not host or not port:
            return None
        password = unquote(p.username or "")
        if not password:
            return None
        qs = parse_qs(p.query)
        out = {
            "type": "trojan", "server": host, "server_port": port,
            "password": password, "tag": _tag(p, host, port),
        }
        sec = (_q(qs, "security") or "tls").lower()
        if sec == "none":
            pass
        else:
            qs.setdefault("security", ["tls"])
            tls = _tls(qs, host)
            if tls:
                out["tls"] = tls
            else:
                out["tls"] = {"enabled": True, "server_name": _q(qs, "sni") or _q(qs, "host") or host}
        tr = _transport(qs)
        if tr:
            if tr.get("type") == "_unsupported_xhttp":
                return None
            out["transport"] = tr
        return out
    except Exception:
        return None


def parse_hysteria2(url: str) -> dict | None:
    try:
        clean_url, _, port_ranges = _extract_port_and_clean_url(url)
        p = urlparse(clean_url)
        if p.scheme not in ("hy2", "hysteria2"):
            return None
        host = p.hostname
        port = p.port or 443
        if not host or not port:
            return None
        user = unquote(p.username or "")
        pw = unquote(p.password or "")
        password = f"{user}:{pw}" if pw else user
        qs = parse_qs(p.query)
        out = {
            "type": "hysteria2", "server": host, "server_port": port,
            "password": password or "", "tag": _tag(p, host, port),
        }
        if port_ranges:
            out["server_ports"] = port_ranges
        tls: dict = {"enabled": True}
        sni = _q(qs, "sni") or _q(qs, "peer") or host
        tls["server_name"] = sni
        insec = (_q(qs, "insecure") or _q(qs, "allowInsecure") or _q(qs, "skip-cert-verify") or "").lower()
        if insec in ("1", "true", "yes"):
            tls["insecure"] = True
        pin = _q(qs, "pinSHA256")
        if pin:
            tls["certificate"] = {"sha256": pin}
        alpn = _q(qs, "alpn")
        if alpn:
            tls["alpn"] = [a.strip() for a in unquote(alpn).split(",") if a.strip()]
        # NOTE: Do NOT set tls["utls"] on hysteria2 — sing-box QUIC rejects uTLS
        # with "unsupported usage for uTLS" at connection time.
        out["tls"] = tls
        obfs = _q(qs, "obfs")
        obfs_pw = _q(qs, "obfs-password")
        if obfs and obfs.lower() != "none":
            out["obfs"] = {"type": obfs, "password": obfs_pw or ""}
        return out
    except Exception:
        return None


def parse_tuic(url: str) -> dict | None:
    try:
        p = urlparse(url)
        if not p.hostname:
            return None
        port = p.port or 443
        uuid = unquote(p.username or "")
        password = unquote(p.password or "")
        if not uuid:
            return None
        qs = parse_qs(p.query)
        out = {
            "type": "tuic", "server": p.hostname, "server_port": port,
            "uuid": uuid, "password": password, "tag": _tag(p, p.hostname, port),
        }
        cong = _q(qs, "congestion_control")
        if cong:
            out["congestion_control"] = cong
        udp_relay = _q(qs, "udp_relay_mode")
        if udp_relay:
            out["udp_relay_mode"] = udp_relay
        tls: dict = {"enabled": True}
        sni = _q(qs, "sni") or p.hostname
        tls["server_name"] = sni
        if (_q(qs, "insecure") or _q(qs, "allowInsecure") or "").lower() in ("1", "true", "yes"):
            tls["insecure"] = True
        if _q(qs, "alpn"):
            tls["alpn"] = [a.strip() for a in unquote(_q(qs, "alpn", "")).split(",") if a.strip()]
        out["tls"] = tls
        return out
    except Exception:
        return None


def parse_anytls(url: str) -> dict | None:
    """anytls://password@host:port/?sni=...&insecure=...#name"""
    try:
        p = urlparse(url)
        if not p.hostname:
            return None
        port = p.port or 443
        password = unquote(p.username or "")
        if not password:
            return None
        qs = parse_qs(p.query)
        out = {
            "type": "anytls", "server": p.hostname, "server_port": port,
            "password": password, "tag": _tag(p, p.hostname, port),
        }
        tls: dict = {"enabled": True}
        sni = _q(qs, "sni") or p.hostname
        tls["server_name"] = sni
        if (_q(qs, "insecure") or _q(qs, "allowInsecure") or "").lower() in ("1", "true", "yes"):
            tls["insecure"] = True
        alpn = _q(qs, "alpn")
        if alpn:
            tls["alpn"] = [a.strip() for a in unquote(alpn).split(",") if a.strip()]
        fp, fp_insec = _normalize_fp(_q(qs, "fp"))
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if fp_insec:
            tls["insecure"] = True
        out["tls"] = tls
        return out
    except Exception:
        return None


def parse_wireguard(url: str) -> dict | None:
    """wireguard://PRIVATE_KEY@HOST:PORT?publickey=PUB&address=IP[/32]&... 

    This is the share-link form used by the WireGuard-for-WARP pools (and by
    sing-box's own `wireguard://` links). sing-box speaks it natively, so such a
    node is testable exactly like any other — it needs no separate engine.

    Fields: `publickey` (peer public key), `address` (tunnel IP), `reserved`
    (WARP's 3-byte client id), `mtu`, `keepalive`. `privatekey` may also come as
    a query parameter instead of the userinfo (both forms exist in the wild).
    """
    try:
        p = urlparse(url)
        if not p.hostname:
            return None
        # WARP links carry base64 public keys containing "+" and "/" unencoded.
        # parse_qs reads "+" as a space, which would corrupt the key (and a
        # corrupted key cannot be told apart from a dead node later).
        qs = parse_qs(p.query.replace("+", "%2B"))
        port = p.port or 51820
        priv = unquote(p.username or "") or _q(qs, "privatekey") or ""
        pub = _q(qs, "publickey") or _q(qs, "peer_public_key") or ""
        if not priv or not pub:
            return None
        # keys are base64; sing-box wants them verbatim, so keep them as-is
        addr = _q(qs, "address") or _q(qs, "ip") or ""
        local = [a.strip() for a in unquote(addr).replace(",", " ").split() if a.strip()]
        out = {
            "type": "wireguard", "server": p.hostname, "server_port": port,
            "private_key": unquote(priv), "peer_public_key": unquote(pub),
            "local_address": local or ["172.16.0.2/32"],
            "tag": _tag(p, p.hostname, port),
        }
        mtu = _q(qs, "mtu")
        out["mtu"] = int(mtu) if mtu and mtu.isdigit() else 1280
        ka = _q(qs, "keepalive") or _q(qs, "persistent_keepalive_interval")
        if ka and ka.isdigit():
            out["keepalive"] = int(ka)
        res = _q(qs, "reserved")
        if res:
            parts = [x for x in unquote(res).replace(",", " ").split() if x]
            if len(parts) == 3 and all(x.isdigit() for x in parts):
                out["reserved"] = [int(x) for x in parts]
        # WARP pools ship a junk-noise flag; sing-box has no such option, so it
        # is recorded but not passed through (the node is still testable).
        if _q(qs, "wnoise"):
            out["wnoise"] = _q(qs, "wnoise")
        return out
    except Exception:
        return None


def parse_shadowsocks(url: str) -> dict | None:
    try:
        if not url.lower().startswith("ss://"):
            return None
        body = url[5:]
        tag = ""
        if "#" in body:
            body, tag = body.split("#", 1)
            tag = unquote(tag).strip()
        # Strip query string (?type=tcp, ?outline=1, ?plugin=...) after host:port
        query_str = ""
        if "?" in body:
            body, query_str = body.split("?", 1)
        body = body.rstrip("/")
        # If there is a plugin parameter, skip (sing-box requires external plugin binary)
        if query_str and "plugin=" in query_str:
            return None
        # SIP002 format: method:password@host:port
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            userinfo = unquote(userinfo)
            # userinfo may be base64-encoded
            if ":" not in userinfo:
                try:
                    decoded = _b64d(userinfo).decode("utf-8", "ignore")
                    if ":" in decoded:
                        userinfo = decoded
                except (binascii.Error, ValueError):
                    pass
            method, _, password = userinfo.partition(":")
            # host:port
            if hostport.count(":") >= 2 and hostport.startswith("["):
                host, _, port_s = hostport.rpartition(":")
                host = host.strip("[]")
            else:
                host, _, port_s = hostport.rpartition(":")
            port = int(port_s.strip("/"))
        else:
            # Legacy format: base64(method:password@host:port)
            try:
                decoded = _b64d(body).decode("utf-8", "ignore")
            except Exception:
                return None
            method, _, rest = decoded.partition(":")
            password, _, hostport = rest.rpartition("@")
            hostport = hostport.split("?")[0].rstrip("/")
            host, _, port_s = hostport.rpartition(":")
            port = int(port_s.strip("/"))
        method = method.strip()
        method = SS_METHOD_ALIASES.get(method, method.lower())
        if method not in VALID_SS_METHODS:
            return None
        if not method or not password or not host or not port:
            return None
        return {
            "type": "shadowsocks", "server": host, "server_port": port,
            "method": method, "password": password, "tag": tag or f"{host}:{port}",
        }
    except Exception:
        return None


def parse_vmess(url: str) -> dict | None:
    try:
        body = url[len("vmess://"):]
        frag_tag = ""
        if "#" in body and "@" not in body.split("#", 1)[0]:
            body, frag_tag = body.split("#", 1)
            frag_tag = unquote(frag_tag).strip()
        # Classic base64 JSON format
        if "@" not in body and not body.startswith("{"):
            try:
                decoded = _b64d(body).decode("utf-8", "ignore").strip()
                if decoded.startswith("{"):
                    try:
                        c = json.loads(decoded)
                    except json.JSONDecodeError:
                        # Recover malformed JSON where "ps" has unescaped quotes/brackets
                        fixed = re.sub(r'"ps"\s*:\s*[^,}]*([,}])', r'"ps": ""\1', decoded)
                        c = json.loads(fixed)
                    return _vmess_from_json(c, fallback_tag=frag_tag)
            except Exception:
                pass
        # Newer vless-like format
        p = urlparse(url)
        port = p.port or 443
        if not p.hostname or not port or not p.username:
            return None
        qs = parse_qs(p.query)
        out = {
            "type": "vmess", "server": p.hostname, "server_port": port,
            "uuid": p.username,
            "security": _q(qs, "encryption", "auto") or "auto",
            "alter_id": int(_q(qs, "aid", "0") or 0),
            "tag": _tag(p, p.hostname, port),
        }
        tls = _tls(qs, p.hostname)
        if tls:
            out["tls"] = tls
        tr = _transport(qs)
        if tr:
            if tr.get("type") == "_unsupported_xhttp":
                return None
            out["transport"] = tr
        return out
    except Exception:
        return None


def _vmess_from_json(c: dict, fallback_tag: str = "") -> dict | None:
    try:
        host = str(c.get("add") or "").strip()
        port = int(str(c.get("port") or 0).strip() or 0)
        uuid = str(c.get("id") or "").strip()
        if not host or not port or not uuid:
            return None
        try:
            aid = int(str(c.get("aid") or 0).strip() or 0)
        except ValueError:
            aid = 0
        scy = str(c.get("scy") or c.get("security") or "auto").strip() or "auto"
        if scy == "none":
            scy = "zero"
        tag_raw = str(c.get("ps") or fallback_tag or f"{host}:{port}")
        out = {
            "type": "vmess", "server": host, "server_port": port,
            "uuid": uuid, "security": scy,
            "alter_id": aid,
            "tag": unquote(tag_raw).strip(),
        }
        net = str(c.get("net") or "tcp").strip().lower()
        if net in ("xhttp", "splithttp", "kcp", "mkcp", "quic"):
            return None
        tls_val = str(c.get("tls") or "").strip().lower()
        tls_on = tls_val in ("tls", "1", "true", "yes")
        ws_host = str(c.get("host") or "").strip()
        sni = str(c.get("sni") or ws_host or host).strip()
        if tls_on:
            tls: dict = {
                "enabled": True,
                "server_name": sni,
            }
            alpn = str(c.get("alpn") or "").strip()
            if alpn:
                tls["alpn"] = [a.strip() for a in unquote(alpn).split(",") if a.strip()]
            fp, fp_insec = _normalize_fp(str(c.get("fp") or "chrome"))
            if fp:
                tls["utls"] = {"enabled": True, "fingerprint": fp}
            insec_val = str(c.get("insecure") or c.get("allowInsecure") or c.get("skip-cert-verify") or c.get("verify_cert") or "").strip().lower()
            if insec_val in ("1", "true", "yes") or fp_insec:
                tls["insecure"] = True
            out["tls"] = tls
        hdr_host = ws_host or (sni if sni != host else "")
        if net == "ws":
            clean_path, ed_int = _clean_ws_path(str(c.get("path") or "/"))
            tr: dict = {
                "type": "ws",
                "path": clean_path,
                "headers": {"Host": hdr_host} if hdr_host else {},
            }
            if ed_int and ed_int > 0:
                tr["max_early_data"] = ed_int
                tr["early_data_header_name"] = "Sec-WebSocket-Protocol"
            out["transport"] = tr
        elif net == "httpupgrade":
            clean_path, _ = _clean_ws_path(str(c.get("path") or "/"))
            out["transport"] = {"type": "httpupgrade", "path": clean_path, "host": hdr_host}
        elif net in ("grpc", "gun"):
            out["transport"] = {"type": "grpc", "service_name": str(c.get("path") or c.get("serviceName") or "")}
        elif net in ("h2", "http"):
            out["transport"] = {"type": "http", "path": str(c.get("path") or "/"),
                                "hosts": [h.strip() for h in hdr_host.split(",") if h.strip()] if hdr_host else []}
        return out
    except Exception:
        return None


def parse(url: str) -> dict | None:
    u = url.strip()
    if not u or u.startswith("#"):
        return None
    low = u.lower()
    result = None
    if low.startswith("vless://"):
        result = parse_vless(u)
    elif low.startswith("hy2://") or low.startswith("hysteria2://"):
        result = parse_hysteria2(u)
    elif low.startswith("tuic://"):
        result = parse_tuic(u)
    elif low.startswith("anytls://"):
        result = parse_anytls(u)
    elif low.startswith("trojan://"):
        result = parse_trojan(u)
    elif low.startswith("ss://"):
        result = parse_shadowsocks(u)
    elif low.startswith("vmess://"):
        result = parse_vmess(u)
    elif low.startswith("wireguard://") or low.startswith("wg://"):
        result = parse_wireguard(u)
    if result is not None:
        result["raw"] = u
    return result
