#!/usr/bin/env python3
"""Port of SaKit's src/lib/links.ts (MIT) to Python.

Builds v2ray links (ss / vmess / vless / trojan / socks5 / http) from
decrypted NPV profile objects (v2rayProfile) or standard v2ray outbounds.
This is a faithful port of the TypeScript logic, including its dispatch
order and fallbacks. See SaKit test/links.test.mjs for the expected
behaviour (63 assertions).
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def b64encode_unicode(s: str) -> str:
    """JS: btoa(unescape(encodeURIComponent(s))) == base64 of UTF-8 bytes."""
    return base64.b64encode(str(s).encode("utf-8")).decode("ascii")


def _enc(s: str) -> str:
    """JS encodeURIComponent: leaves A-Z a-z 0-9 - _ . ! ~ * ' ( ) unescaped."""
    return urllib.parse.quote(str(s), safe="-_.!~*'()")


def _qs(pairs) -> str:
    """JS URLSearchParams.toString(): application/x-www-form-urlencoded."""
    return urllib.parse.urlencode(
        [(k, str(v)) for k, v in pairs], quote_via=urllib.parse.quote_plus
    )


def _s(v) -> str:
    """JS String(x ?? ''): None -> '', otherwise str()."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def format_host_port(host, port=None) -> str:
    h = _s(host).strip()
    p = _s(port).strip() if port is not None else ""
    if not h:
        return ""
    bracketed = f"[{h}]" if (":" in h and not h.startswith("[")) else h
    return f"{bracketed}:{p}" if p else bracketed


def unbracket_host(host) -> str:
    h = _s(host).strip()
    if h.startswith("[") and h.endswith("]"):
        return h[1:-1]
    return h


def has_tls(p: dict) -> bool:
    return _s(p.get("security")).lower() in ("tls", "reality")


def is_reality(p: dict) -> bool:
    return _s(p.get("security")).lower() == "reality"


def read_config_type(p: dict) -> str:
    raw = p.get("configType")
    v = "" if raw is None else _s(raw).strip()
    if v == "1":
        return "vmess"
    if v in ("2", "3"):
        return "shadowsocks"
    if v == "4":
        return "socks"
    if v == "5":
        return "vless"
    if v == "6":
        return "trojan"
    if v == "":
        if is_reality(p) or p.get("publicKey") or p.get("flow") or p.get("encryption") == "none":
            return "vless"
        if p.get("headerType") == "http" and (p.get("security") in ("none", None, "")):
            return "vless"
        if p.get("username") and p.get("password") and not UUID_RE.match(_s(p.get("password"))):
            return "socks"
        pw = _s(p.get("password"))
        if UUID_RE.match(pw):
            return "vmess"
        if has_tls(p) or p.get("sni"):
            return "trojan"
    return "unknown"


# ---------------------------------------------------------------------------
# 1. Profile-based link generators (v2rayProfile)
# ---------------------------------------------------------------------------

def build_shadowsocks_from_profile(item: dict):
    p = item.get("v2rayProfile") or {}
    if not p.get("server") or not p.get("serverPort"):
        return None
    remark = _s(item.get("name") or p.get("remarks")).strip()
    method = _s(p.get("method")).strip()
    if method and ":" in method:
        user_info = method
    elif method and p.get("password"):
        user_info = f"{method}:{p['password']}"
    elif p.get("password"):
        user_info = _s(p.get("password"))
    else:
        return None
    user = b64encode_unicode(user_info)
    endpoint = format_host_port(p.get("server"), p.get("serverPort"))
    return {"kind": "shadowsocks", "label": "ss",
            "value": f"ss://{user}@{endpoint}#{_enc(remark)}"}


def build_vmess_from_profile(item: dict):
    p = item.get("v2rayProfile") or {}
    ident = _s(p.get("password"))
    if not p.get("server") or not UUID_RE.match(ident):
        return None
    method = p.get("method")
    inner = {
        "v": "2",
        "ps": _s(item.get("name") or p.get("remarks")).strip(),
        "add": unbracket_host(p.get("server")),
        "port": _s(p.get("serverPort")),
        "id": ident,
        "aid": _s(p.get("alterId") if p.get("alterId") is not None else "0"),
        "scy": method if (method and len(_s(method)) < 32) else "auto",
        "net": p.get("network") or "tcp",
        "type": p.get("headerType") or "none",
        "host": p.get("host") or "",
        "path": p.get("path") or "",
        "tls": "tls" if has_tls(p) else "",
        "sni": p.get("sni") or "",
        "fp": p.get("fingerPrint") or "",
        "alpn": p.get("alpn") or "",
    }
    return {"kind": "vmess", "label": "vmess",
            "value": "vmess://" + b64encode_unicode(
                json.dumps(inner, ensure_ascii=False, separators=(",", ":")))}


def build_vless_from_profile(item: dict):
    p = item.get("v2rayProfile") or {}
    ident = _s(p.get("password"))
    if not p.get("server") or not p.get("serverPort") or not UUID_RE.match(ident):
        return None
    remark = _s(item.get("name") or p.get("remarks")).strip()
    reality = is_reality(p)
    sec = "reality" if reality else ("tls" if has_tls(p) else (p.get("security") or "none"))
    pairs = [("security", sec)]
    net = p.get("network") or "tcp"
    pairs.append(("type", net))
    if p.get("headerType") and p.get("headerType") != "none":
        pairs.append(("headerType", p["headerType"]))
    if p.get("host"):
        pairs.append(("host", p["host"]))
    if p.get("path"):
        pairs.append(("path", p["path"]))
    if reality:
        if p.get("publicKey"):
            pairs.append(("pbk", p["publicKey"]))
        if p.get("shortId"):
            pairs.append(("sid", p["shortId"]))
        if p.get("fingerPrint"):
            pairs.append(("fp", p["fingerPrint"]))
        if p.get("spiderX"):
            pairs.append(("spx", p["spiderX"]))
    if p.get("sni"):
        pairs.append(("sni", p["sni"]))
    if p.get("alpn"):
        pairs.append(("alpn", p["alpn"]))
    if p.get("fingerPrint") and not reality:
        pairs.append(("fp", p["fingerPrint"]))
    if p.get("flow"):
        pairs.append(("flow", p["flow"]))
    if p.get("insecure") is True or p.get("insecure") == "true":
        pairs.append(("allowInsecure", "1"))
    if p.get("encryption") and p.get("encryption") != "none":
        pairs.append(("encryption", p["encryption"]))
    endpoint = format_host_port(p.get("server"), p.get("serverPort"))
    return {"kind": "vless", "label": "vless",
            "value": f"vless://{ident}@{endpoint}?{_qs(pairs)}#{_enc(remark)}"}


def build_trojan_from_profile(item: dict):
    p = item.get("v2rayProfile") or {}
    pw = _s(p.get("password"))
    if not p.get("server") or not p.get("serverPort") or not pw:
        return None
    if not has_tls(p) and not p.get("sni"):
        return None
    remark = _s(item.get("name") or p.get("remarks")).strip()
    pairs = [("type", p.get("network") or "tcp")]
    if p.get("path"):
        pairs.append(("path", p["path"]))
    if p.get("host"):
        pairs.append(("host", p["host"]))
    pairs.append(("security", "reality" if is_reality(p) else ("tls" if has_tls(p) else "none")))
    if p.get("sni"):
        pairs.append(("sni", p["sni"]))
    if p.get("fingerPrint"):
        pairs.append(("fp", p["fingerPrint"]))
    if p.get("alpn"):
        pairs.append(("alpn", p["alpn"]))
    if p.get("insecure") is True or p.get("insecure") == "true":
        pairs.append(("allowInsecure", "1"))
    endpoint = format_host_port(p.get("server"), p.get("serverPort"))
    return {"kind": "trojan", "label": "trojan",
            "value": f"trojan://{_enc(pw)}@{endpoint}?{_qs(pairs)}#{_enc(remark)}"}


def build_socks_from_profile(item: dict):
    p = item.get("v2rayProfile") or {}
    if not p.get("server") or not p.get("serverPort"):
        return None
    remark = _s(item.get("name") or p.get("remarks")).strip()
    pw = _s(p.get("password"))
    user = ""
    if p.get("username"):
        user = f"{_enc(p['username'])}:{_enc(pw)}@"
    scheme = "http" if (_s(p.get("configType")) == "4" and _s(p.get("scheme")).lower() == "http") else "socks5"
    endpoint = format_host_port(p.get("server"), p.get("serverPort"))
    return {"kind": "socks", "label": scheme,
            "value": f"{scheme}://{user}{endpoint}#{_enc(remark)}"}


def build_profile_link(item: dict):
    p = item.get("v2rayProfile") or {}
    if not p.get("server") or not p.get("serverPort"):
        return None
    cfg = _s(p.get("configType")).strip()
    pw = _s(p.get("password")).strip()
    reality = is_reality(p)

    # 1. SOCKS5 / HTTP
    if cfg == "4" or read_config_type(p) == "socks" or (p.get("username") and pw and not UUID_RE.match(pw)):
        return build_socks_from_profile(item)

    # 2. Shadowsocks
    method = _s(p.get("method")).strip().lower()
    is_ss_method = bool(method and (
        method.startswith("2022-") or "gcm" in method or "poly1305" in method
        or "cfb" in method or "ctr" in method or "chacha" in method))
    if (cfg in ("2", "3") or read_config_type(p) == "shadowsocks"
            or (is_ss_method and cfg not in ("1", "5") and not UUID_RE.match(pw))):
        return build_shadowsocks_from_profile(item)

    # 3. VLESS
    if (cfg == "5" or read_config_type(p) == "vless" or reality
            or p.get("publicKey") or p.get("flow") or p.get("encryption") == "none"):
        if UUID_RE.match(pw):
            return build_vless_from_profile(item)
        if has_tls(p) or p.get("sni"):
            return build_trojan_from_profile(item)
        return None

    # 4. Trojan
    if cfg == "6" or read_config_type(p) == "trojan" or (pw and not UUID_RE.match(pw) and (has_tls(p) or p.get("sni"))):
        return build_trojan_from_profile(item)

    # 5. VMess
    if cfg == "1" or read_config_type(p) == "vmess":
        if UUID_RE.match(pw):
            return build_vmess_from_profile(item)

    # Fallback UUID checks
    if UUID_RE.match(pw):
        if p.get("headerType") == "http" and (p.get("security") in ("none", None, "")):
            return build_vless_from_profile(item)
        return build_vmess_from_profile(item)
    if has_tls(p) or p.get("sni"):
        return build_trojan_from_profile(item)
    return None


# ---------------------------------------------------------------------------
# 2. Outbound-based link generators (standard v2ray JSON outbounds)
# ---------------------------------------------------------------------------

def build_vless_from_outbound(ob: dict, remark: str):
    try:
        ss = ob.get("streamSettings") or {}
        st = ob.get("settings") or {}
        vnext = ((st.get("vnext") or [None])[0]) or {}
        user = ((vnext.get("users") or [None])[0]) or {}
        if not user.get("id") or not vnext.get("address"):
            return None
        net = ss.get("network") or "tcp"
        sec = ss.get("security") or "none"
        tls = ss.get("tlsSettings") or {}
        pairs = [("encryption", user.get("encryption") or "none")]
        if sec == "reality":
            reality = ss.get("realitySettings") or {}
            pairs.append(("security", "reality"))
            if reality.get("serverName") or tls.get("serverName"):
                pairs.append(("sni", reality.get("serverName") or tls.get("serverName")))
            if reality.get("fingerprint") or tls.get("fingerprint"):
                pairs.append(("fp", reality.get("fingerprint") or tls.get("fingerprint")))
            if reality.get("publicKey"):
                pairs.append(("pbk", reality["publicKey"]))
            if reality.get("shortId"):
                pairs.append(("sid", reality["shortId"]))
            if reality.get("spiderX"):
                pairs.append(("spx", reality["spiderX"]))
            if user.get("flow"):
                pairs.append(("flow", user["flow"]))
        else:
            pairs.append(("security", "tls" if sec == "tls" else "none"))
            if sec == "tls":
                if tls.get("serverName"):
                    pairs.append(("sni", tls["serverName"]))
                if tls.get("fingerprint"):
                    pairs.append(("fp", tls["fingerprint"]))
                alpn = tls.get("alpn")
                if isinstance(alpn, list):
                    alpn = ",".join(alpn)
                if alpn:
                    pairs.append(("alpn", alpn))
                if tls.get("allowInsecure"):
                    pairs.append(("allowInsecure", "1"))
        if net == "ws":
            w = ss.get("wsSettings") or {}
            pairs.append(("type", "ws"))
            if w.get("path"):
                pairs.append(("path", w["path"]))
            host = ((w.get("headers") or {}).get("Host")) or tls.get("serverName") or ""
            if host:
                pairs.append(("host", host))
        elif net == "xhttp":
            x = ss.get("xhttpSettings") or {}
            pairs.append(("type", "xhttp"))
            if x.get("path"):
                pairs.append(("path", x["path"]))
            if x.get("host"):
                pairs.append(("host", x["host"]))
            if x.get("mode"):
                pairs.append(("mode", x["mode"]))
        elif net == "tcp":
            pairs.append(("type", "tcp"))
            t = ss.get("tcpSettings") or {}
            header = t.get("header") or {}
            if header.get("type") and header["type"] != "none":
                pairs.append(("headerType", header["type"]))
            host = ((header.get("request") or {}).get("headers") or {}).get("Host")
            if host:
                pairs.append(("host", ",".join(host) if isinstance(host, list) else _s(host)))
        else:
            pairs.append(("type", net))
        endpoint = format_host_port(vnext.get("address"), vnext.get("port") if vnext.get("port") is not None else 443)
        return {"kind": "vless", "label": "vless",
                "value": f"vless://{user['id']}@{endpoint}?{_qs(pairs)}#{_enc(remark)}"}
    except Exception:
        return None


def build_vmess_from_outbound(ob: dict, remark: str):
    try:
        ss = ob.get("streamSettings") or {}
        st = ob.get("settings") or {}
        vnext = ((st.get("vnext") or [None])[0]) or {}
        user = ((vnext.get("users") or [None])[0]) or {}
        if not user.get("id") or not vnext.get("address"):
            return None
        net = ss.get("network") or "tcp"
        sec = ss.get("security") or "none"
        tls = ss.get("tlsSettings") or {}
        ws = ss.get("wsSettings") or {}
        tcp = ss.get("tcpSettings") or {}
        header = tcp.get("header") or {}
        ws_host = ((ws.get("headers") or {}).get("Host")) or ""
        hdr_host = ((header.get("request") or {}).get("headers") or {}).get("Host") or ""
        if isinstance(hdr_host, list):
            hdr_host = ",".join(hdr_host)
        host = ws_host or _s(hdr_host) or tls.get("serverName") or ""
        alpn = tls.get("alpn")
        if isinstance(alpn, list):
            alpn = ",".join(alpn)
        inner = {
            "v": "2",
            "ps": remark,
            "add": unbracket_host(vnext.get("address")),
            "port": _s(vnext.get("port") if vnext.get("port") is not None else 443),
            "id": user["id"],
            "aid": _s(user.get("alterId") if user.get("alterId") is not None else 0),
            "scy": user.get("security") or "auto",
            "net": net,
            "type": header.get("type") or "none",
            "host": host,
            "path": ws.get("path") or "",
            "tls": "tls" if sec == "tls" else "",
            "sni": tls.get("serverName") or "",
            "fp": tls.get("fingerprint") or "",
            "alpn": alpn or "",
        }
        return {"kind": "vmess", "label": "vmess",
                "value": "vmess://" + b64encode_unicode(
                    json.dumps(inner, ensure_ascii=False, separators=(",", ":")))}
    except Exception:
        return None


def build_trojan_from_outbound(ob: dict, remark: str):
    try:
        ss = ob.get("streamSettings") or {}
        st = ob.get("settings") or {}
        srv = ((st.get("servers") or [None])[0]) or {}
        if not srv.get("password") or not srv.get("address"):
            return None
        net = ss.get("network") or "tcp"
        sec = ss.get("security") or "none"
        tls = ss.get("tlsSettings") or {}
        pairs = []
        if net == "ws":
            w = ss.get("wsSettings") or {}
            pairs.append(("type", "ws"))
            if w.get("path"):
                pairs.append(("path", w["path"]))
            host = ((w.get("headers") or {}).get("Host")) or ""
            if host:
                pairs.append(("host", host))
        else:
            pairs.append(("type", net))
        pairs.append(("security", "tls" if sec == "tls" else "none"))
        if sec == "tls":
            if tls.get("serverName"):
                pairs.append(("sni", tls["serverName"]))
            if tls.get("fingerprint"):
                pairs.append(("fp", tls["fingerprint"]))
            alpn = tls.get("alpn")
            if isinstance(alpn, list):
                alpn = ",".join(alpn)
            if alpn:
                pairs.append(("alpn", alpn))
            if tls.get("allowInsecure"):
                pairs.append(("allowInsecure", "1"))
        endpoint = format_host_port(srv.get("address"), srv.get("port") if srv.get("port") is not None else 443)
        return {"kind": "trojan", "label": "trojan",
                "value": f"trojan://{_enc(srv['password'])}@{endpoint}?{_qs(pairs)}#{_enc(remark)}"}
    except Exception:
        return None


def build_http_from_outbound(ob: dict, remark: str):
    try:
        st = ob.get("settings") or {}
        srv = ((st.get("servers") or [None])[0]) or {}
        u = ((srv.get("users") or [None])[0]) or {}
        addr = srv.get("address") or ob.get("address")
        port = srv.get("port") or ob.get("port") or 1080
        if not addr:
            return None
        auth = f"{_enc(u['user'])}:{_enc(u.get('pass') or '')}@" if u.get("user") else ""
        endpoint = format_host_port(addr, port)
        return {"kind": "http", "label": "http",
                "value": f"http://{auth}{endpoint}#{_enc(remark)}"}
    except Exception:
        return None


def build_socks_from_outbound(ob: dict, remark: str):
    try:
        st = ob.get("settings") or {}
        srv = ((st.get("servers") or [None])[0]) or {}
        u = ((srv.get("users") or [None])[0]) or {}
        addr = srv.get("address") or ob.get("address")
        port = srv.get("port") or ob.get("port") or 1080
        if not addr:
            return None
        auth = f"{_enc(u['user'])}:{_enc(u.get('pass') or '')}@" if u.get("user") else ""
        endpoint = format_host_port(addr, port)
        return {"kind": "socks", "label": "socks5",
                "value": f"socks5://{auth}{endpoint}#{_enc(remark)}"}
    except Exception:
        return None


def build_shadowsocks_from_outbound(ob: dict, remark: str):
    try:
        st = ob.get("settings") or {}
        srv = ((st.get("servers") or [None])[0]) or {}
        if not srv.get("address") or not srv.get("password") or not srv.get("method"):
            return None
        creds = b64encode_unicode(f"{srv['method']}:{srv['password']}")
        endpoint = format_host_port(srv.get("address"), srv.get("port") if srv.get("port") is not None else 8388)
        return {"kind": "shadowsocks", "label": "ss",
                "value": f"ss://{creds}@{endpoint}#{_enc(remark)}"}
    except Exception:
        return None


def build_link_from_outbound(ob: dict, remark: str):
    proto = _s(ob.get("protocol")).lower()
    if proto == "vless":
        return build_vless_from_outbound(ob, remark)
    if proto == "vmess":
        return build_vmess_from_outbound(ob, remark)
    if proto == "trojan":
        return build_trojan_from_outbound(ob, remark)
    if proto == "http":
        return build_http_from_outbound(ob, remark)
    if proto == "socks":
        return build_socks_from_outbound(ob, remark)
    if proto == "shadowsocks":
        return build_shadowsocks_from_outbound(ob, remark)
    return None


# ---------------------------------------------------------------------------
# 3. Unified entry transformation
# ---------------------------------------------------------------------------

def create_entry_from_item(item: dict, source_file: str | None = None):
    """Transform a raw config item (NPV decryption or JSON) into an entry.

    Returns None for metadata-only items (e.g. lockConfig).
    """
    if not item or not isinstance(item, dict):
        return None
    # Ignore entries without a server/profile (e.g. lockConfig metadata).
    if not item.get("v2rayProfile") and not item.get("server") and not item.get("address"):
        return None

    profile = item.get("v2rayProfile") or {}
    name = _s(item.get("name") or profile.get("remarks")).strip() or "بدون نام"
    if profile.get("server"):
        address = format_host_port(profile.get("server"), profile.get("serverPort"))
    else:
        address = _s(item.get("address") or "نامشخص")

    proto = "نامشخص"
    net = _s(profile.get("network") or "نامشخص")
    tls = _s(profile.get("security") or "نامشخص")
    links = []
    custom_json = None

    # 1. First priority: embedded v2rayJson (standard full v2ray config).
    if profile.get("v2rayJson"):
        try:
            full = profile["v2rayJson"]
            if isinstance(full, str):
                full = json.loads(full)
            outs = (full or {}).get("outbounds") or []
            proxy = next((o for o in outs if o.get("tag") == "proxy"), outs[0] if outs else None)
            if proxy:
                proto = _s(proxy.get("protocol") or "نامشخص")
                ss = proxy.get("streamSettings") or {}
                if ss.get("network"):
                    net = _s(ss["network"])
                if ss.get("security"):
                    tls = _s(ss["security"])
                link = build_link_from_outbound(proxy, name)
                if link:
                    links.append(link)
            custom_json = json.dumps(full, indent=2, ensure_ascii=False)
        except Exception:
            pass  # fall back to profile-level extraction below

    # 2. Second priority: build from profile.
    if not links:
        link = build_profile_link(item)
        if link:
            links.append(link)
            proto = link["kind"]
            if proto == "vless":
                if profile.get("security") == "reality" or profile.get("publicKey"):
                    tls = "reality"
                elif profile.get("security"):
                    tls = _s(profile["security"])
            if proto == "shadowsocks" and (net == "نامشخص" or not profile.get("network")):
                net = "tcp"

    entry = {
        "name": name,
        "address": address,
        "proto": proto,
        "net": net,
        "tls": tls,
        "links": links,
        "customJson": custom_json,
        "json": json.dumps(item, indent=2, ensure_ascii=False),
    }
    if source_file:
        entry["sourceFile"] = source_file
    return entry


def parse_decrypted_text(text: str):
    """Extract config items from a decryptor's text output.

    Handles the '===== blob #N =====' sections (decrypt_npvt.py / npvs.py
    style) as well as a bare JSON document. Returns a list of dict items.
    """
    items = []
    if "===== blob #" in text:
        parts = re.split(r"===== blob #\d+ =====", text)
    else:
        parts = [text]
    for part in parts:
        part = part.strip()
        if not part:
            continue
        try:
            doc = json.loads(part)
        except Exception:
            continue
        if isinstance(doc, list):
            items.extend([d for d in doc if isinstance(d, dict)])
        elif isinstance(doc, dict):
            items.append(doc)
    return items
