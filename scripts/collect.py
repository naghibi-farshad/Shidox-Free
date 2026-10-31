#!/usr/bin/env python3
"""
Shidox Free collector — Telegram V2Ray + NPV harvester.

Runs on GitHub Actions every 5 hours (and locally for testing):

  1. Text configs: reads the public preview (t.me/s/<channel>) of the
     channels below, keeps posts from the last 24h, extracts
     vless/vmess/trojan/ss/... URIs (plus base64 subscription blobs).
     No login needed.
  2. NPV files: with a Telethon session (env TG_SESSION + TG_API_ID +
     TG_API_HASH), downloads .npvt/.npvs attachments posted in the last
     24h, decrypts them with SaKit's Python decryptors (MIT), and builds
     v2ray links from the decrypted profiles (port of SaKit links.ts).
     Without those env vars this step is skipped with a warning.
  3. Merges everything into a rolling 48h archive, dedupes to one
     config per server (scheme + host + port), renames to
     "<flag> Shidox Free" (+ " + CF" for Cloudflare-fronted servers),
     and publishes:
        sub.txt        - base64-encoded subscription (live sub)
        sub_plain.txt  - plain URI list
        stats.json     - totals / per-channel counts
        history/archive.json - rolling archive state
        README.md      - stats block between SHIDOX markers

Usage:  python scripts/collect.py [--no-npv] [--out DIR]
"""

from __future__ import annotations

import argparse
import base64
import html
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).resolve().parent))
from npv_links import create_entry_from_item, parse_decrypted_text  # noqa: E402

BASE = Path(__file__).resolve().parent.parent
SUB_TXT = BASE / "sub.txt"
SUB_PLAIN = BASE / "sub_plain.txt"
ARCHIVE = BASE / "history" / "archive.json"
STATS_JSON = BASE / "stats.json"
README = BASE / "README.md"
SCRIPTS = Path(__file__).resolve().parent

V2RAY_CHANNELS = [
    "vpn_Click",
    "FreakConfig",
    "V2RAYROZ",
    "prrofile_purple",
    "V2rayBaaz",
    "V2rayNGX",
    "V2rayng_Fast",
    "v2ray26",
]

NPV_CHANNELS = [
    "irCONFIG",
    "ConfigX2ray",
]

ALL_TEXT_CHANNELS = V2RAY_CHANNELS + NPV_CHANNELS

SCAN_WINDOW = timedelta(hours=24)
RETENTION = timedelta(hours=48)
REQUEST_DELAY = 1.3

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

CONFIG_RE = re.compile(
    r"(?:vless|vmess|trojan|ss|ssr|tuic|hysteria2|hysteria|hy2|socks5|warp|wireguard)://[^\s<>\"'`«»\[\]\u200c]+",
    re.IGNORECASE,
)
B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=]{100,}")
TRAILING = ".,;:)]}>»،؛'\""

BRAND = "Shidox Free"

CF_FALLBACK_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]


# ---------------------------------------------------------------------------
# URI helpers (from the earlier axiom_build.py, same semantics)
# ---------------------------------------------------------------------------

def b64decode_loose(s: str) -> bytes:
    s = re.sub(r"\s+", "", s)
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        return base64.urlsafe_b64decode(s)


def extract_host(line: str):
    line = line.strip()
    scheme = line.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            payload = line.split("://", 1)[1].split("#")[0].split("?")[0]
            j = json.loads(b64decode_loose(payload).decode("utf-8", "replace"))
            return scheme, j.get("add")
        if scheme == "ss":
            rest = line.split("://", 1)[1].split("#")[0]
            if "@" in rest:
                userinfo, hostport = rest.rsplit("@", 1)
                if re.fullmatch(r"[A-Za-z0-9+/=_-]+", userinfo or "") and ":" not in userinfo:
                    try:
                        userinfo = b64decode_loose(userinfo).decode("utf-8", "replace")
                    except Exception:
                        pass
                return scheme, hostport.split(":")[0].strip("[]") or None
            dec = b64decode_loose(rest).decode("utf-8", "replace")
            m = re.search(r"@([^:/]+)", dec)
            return scheme, m.group(1) if m else None
        return scheme, urllib.parse.urlparse(line).hostname
    except Exception:
        return scheme, None


def server_key(line: str):
    """One config per server: (scheme, host, port). Name/UUID ignored."""
    line = line.strip()
    scheme = line.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            payload = line.split("://", 1)[1].split("#")[0]
            j = json.loads(b64decode_loose(payload).decode("utf-8", "replace"))
            return (scheme, (j.get("add") or "").lower(), j.get("port"))
        if scheme == "ss":
            rest = line.split("://", 1)[1].split("#")[0]
            query = ""
            if "?" in rest:
                rest, query = rest.split("?", 1)
            if "@" in rest:
                userinfo, hostport = rest.rsplit("@", 1)
                if re.fullmatch(r"[A-Za-z0-9+/=_-]+", userinfo or "") and ":" not in userinfo:
                    try:
                        userinfo = b64decode_loose(userinfo).decode("utf-8", "replace")
                    except Exception:
                        pass
            else:
                dec = b64decode_loose(rest).decode("utf-8", "replace")
                if "@" in dec:
                    userinfo, hostport = dec.rsplit("@", 1)
                else:
                    userinfo, hostport = dec, ""
            _method, _, _pw = userinfo.partition(":")
            host, _, port = hostport.partition(":")
            return (scheme, host.lower().strip("[]"), port)
        u = urllib.parse.urlparse(line)
        return (scheme, (u.hostname or "").lower(), u.port)
    except Exception:
        return (scheme, None, None)


def geoip_batch(queries, tries=3):
    for attempt in range(tries):
        try:
            body = json.dumps([{"query": q, "fields": "status,country,countryCode,query"}
                               for q in queries]).encode()
            req = urllib.request.Request("http://ip-api.com/batch", data=body,
                                         headers={"Content-Type": "application/json"})
            resp = json.loads(urllib.request.urlopen(req, timeout=60).read().decode())
            return {r["query"]: r for r in resp}
        except Exception as e:
            print(f"  geoip batch attempt {attempt + 1} failed: {e}")
            time.sleep(5)
    return {}


def flag(cc):
    if not cc or cc == "??":
        return "\U0001f310"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)


def is_sinkhole(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr in ipaddress.ip_network("198.18.0.0/15") or addr.is_private or addr.is_reserved
    except Exception:
        return True


def load_cf_nets():
    nets = []
    for url in ("https://www.cloudflare.com/ips-v4/", "https://www.cloudflare.com/ips-v6/"):
        try:
            txt = urllib.request.urlopen(url, timeout=20).read().decode()
            nets += [ipaddress.ip_network(ln.strip()) for ln in txt.splitlines() if ln.strip()]
        except Exception as e:
            print(f"  fetch {url} failed: {e}")
    if not nets:
        nets = [ipaddress.ip_network(c) for c in CF_FALLBACK_V4]
        print("  using hardcoded fallback CF ranges")
    return nets


# ---------------------------------------------------------------------------
# Text harvesting (public pages, no login)
# ---------------------------------------------------------------------------

def extract_links_from_html(raw_html: str):
    """URIs in the message HTML, plus URIs hidden in base64 blobs."""
    found = []
    for m in CONFIG_RE.findall(raw_html):
        found.append(m)
    # base64 subscription blobs: decode, then extract URIs from the text
    for tok in B64_TOKEN_RE.findall(raw_html):
        if len(tok) % 4 != 0:
            continue
        try:
            dec = b64decode_loose(tok).decode("utf-8", "replace")
        except Exception:
            continue
        if "://" in dec:
            found.extend(CONFIG_RE.findall(dec))
    return found


def fetch_channel(session: requests.Session, channel: str, now: datetime):
    """Return (items, error). items = [(datetime, raw_config_str), ...].

    Retries up to 3 times with a fresh session per attempt: t.me stalls
    a reused connection after the first channel, a new session recovers.
    """
    url = f"https://t.me/s/{channel}"
    last_err = None
    for attempt in range(3):
        try:
            s = requests.Session()
            r = s.get(url, headers={"User-Agent": UA}, timeout=30)
            if r.status_code != 200:
                return [], f"HTTP {r.status_code}"
            break
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            print(f"  @{channel} fetch attempt {attempt + 1} failed: {last_err}")
            time.sleep(5 * (attempt + 1))
    else:
        return [], last_err or "fetch failed"
    soup = BeautifulSoup(r.text, "html.parser")
    msgs = soup.select("div.tgme_widget_message")
    if not msgs:
        return [], "channel hidden/empty in public preview"
    items = []
    for m in msgs:
        t = m.find("time")
        if not t or not t.get("datetime"):
            continue
        try:
            dt = datetime.fromisoformat(t["datetime"])
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if now - dt > SCAN_WINDOW:
            continue
        raw = html.unescape(str(m))
        for link in extract_links_from_html(raw):
            items.append((dt, link))
    return items, None


# ---------------------------------------------------------------------------
# NPV harvesting (Telethon session, optional)
# ---------------------------------------------------------------------------

def download_npv_files(tmpdir: Path):
    """Download .npvt/.npvs attachments from the NPV channels (last 24h).

    Needs env TG_SESSION, TG_API_ID, TG_API_HASH. Returns a list of
    (channel, path) pairs. Returns [] (with a warning) when the session
    is not configured, so text-only runs still work.
    """
    session_str = os.environ.get("TG_SESSION", "").strip()
    api_id = os.environ.get("TG_API_ID", "").strip()
    api_hash = os.environ.get("TG_API_HASH", "").strip()
    if not (session_str and api_id and api_hash):
        print("::warning::TG_SESSION/TG_API_ID/TG_API_HASH not set — skipping NPV download")
        return []
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
    except ImportError:
        print("::warning::telethon not installed — skipping NPV download")
        return []

    import asyncio

    async def _run():
        client = TelegramClient(StringSession(session_str), int(api_id), api_hash)
        await client.connect()
        if not await client.is_user_authorized():
            print("::warning::Telegram session not authorized — skipping NPV download")
            await client.disconnect()
            return []
        now = datetime.now(timezone.utc)
        got = []
        for ch in NPV_CHANNELS:
            try:
                entity = await client.get_entity(ch)
            except Exception as e:
                print(f"  @{ch} NPV: cannot resolve channel: {e}")
                continue
            count = 0
            try:
                async for msg in client.iter_messages(entity, limit=60):
                    if msg.date is None or now - msg.date > SCAN_WINDOW:
                        continue
                    fname = ""
                    if msg.file:
                        fname = msg.file.name or ""
                    if not fname.lower().endswith((".npvt", ".npvs")):
                        continue
                    dest = tmpdir / f"{ch}_{msg.id}_{fname}"
                    try:
                        await msg.download_media(file=dest)
                    except Exception as e:
                        print(f"  @{ch} NPV: download failed for {fname}: {e}")
                        continue
                    got.append((ch, dest))
                    count += 1
            except Exception as e:
                print(f"  @{ch} NPV: history read failed: {e}")
            print(f"  @{ch} NPV: {count} file(s) downloaded")
        await client.disconnect()
        return got

    return asyncio.run(_run())


def decrypt_npv_file(path: Path, workdir: Path):
    """Decrypt one .npvt/.npvs file with SaKit's Python decryptors.

    Returns a list of v2ray link strings (may be empty). Failures are
    logged and skipped (unsupported version, passphrase, bound file...).
    """
    workdir.mkdir(parents=True, exist_ok=True)
    outdir = workdir / "out"
    outdir.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix.lower()
    script = SCRIPTS / ("decrypt_npvt.py" if suffix == ".npvt" else "npvs.py")
    if not script.exists():
        print(f"  decrypt: missing {script.name}, skipping {path.name}")
        return []
    if suffix == ".npvs":
        # SaKit tables are not vendored in the repo (one is binary);
        # fetch them from SaKit's repo on demand.
        tables = SCRIPTS / "npvs_gen2_tables.bin.z"
        if not tables.exists():
            try:
                urllib.request.urlretrieve(
                    "https://raw.githubusercontent.com/AmirStillAlive/SaKit/main/npvs_gen2_tables.bin.z",
                    tables)
                print("  gen2 tables downloaded")
            except Exception as e:
                print(f"  gen2 tables download failed: {e}")
        for name in ("npvs_tables.json",):
            t = SCRIPTS / name
            if not t.exists():
                try:
                    urllib.request.urlretrieve(
                        f"https://raw.githubusercontent.com/AmirStillAlive/SaKit/main/{name}", t)
                    print(f"  {name} downloaded")
                except Exception as e:
                    print(f"  {name} download failed: {e}")
    else:
        t = SCRIPTS / "npv_tables.json"
        if not t.exists():
            try:
                urllib.request.urlretrieve(
                    "https://raw.githubusercontent.com/AmirStillAlive/SaKit/main/npv_tables.json", t)
                print("  npv_tables.json downloaded")
            except Exception as e:
                print(f"  npv_tables.json download failed: {e}")
    proc = subprocess.run(
        [sys.executable, str(script), str(path), str(outdir)],
        cwd=str(SCRIPTS), capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        print(f"  decrypt: {path.name} failed: {(proc.stdout + proc.stderr).strip().splitlines()[-1:]}")
        return []
    links = []
    for txt_file in sorted(outdir.glob("*.txt")):
        try:
            text = txt_file.read_text(encoding="utf-8")
        except Exception:
            continue
        for item in parse_decrypted_text(text):
            entry = create_entry_from_item(item, source_file=path.name)
            if entry:
                links.extend(l["value"] for l in entry["links"])
        txt_file.unlink()
    return links


# ---------------------------------------------------------------------------
# README stats block
# ---------------------------------------------------------------------------

RX_STATS_BLOCK = re.compile(
    re.escape("<!-- SHIDOX:STATS:START -->") + r".*?" + re.escape("<!-- SHIDOX:STATS:END -->"),
    re.DOTALL,
)


def update_readme(stats: dict) -> None:
    lines = [
        "| کانال (Channel) | کانفیگ‌ها | تازه‌ی ۲۴س | وضعیت / Status |",
        "|---|---:|---:|:---:|",
    ]
    for c in stats["perChannel"]:
        status = "OK" if c["ok"] else f"FAIL ({c.get('error') or 'error'})"
        lines.append(f"| `@{c['id']}` | {c['count']} | {c['fresh']} | {status} |")
    block = f"""<!-- SHIDOX:STATS:START -->
> این بخش به‌صورت خودکار توسط GitHub Action بازنویسی می‌شود / Auto-regenerated by CI.
**آخرین به‌روزرسانی / Last update (UTC):** `{stats["lastRun"]}`
**مجموع کانفیگ‌ها:** **{stats["total"]}** · **تازه‌ی ۲۴ ساعته:** **{stats["fresh24h"]}** · **چرخه‌ی نگهداری:** ۴۸ ساعت · **کانال‌های سالم:** {sum(1 for c in stats["perChannel"] if c["ok"])}/{len(stats["perChannel"])}
{chr(10).join(lines)}
<!-- SHIDOX:STATS:END -->"""
    if not README.exists():
        return
    txt = README.read_text(encoding="utf-8")
    if RX_STATS_BLOCK.search(txt):
        txt = RX_STATS_BLOCK.sub(lambda _: block, txt)
    else:
        txt = txt.rstrip() + "\n\n" + block + "\n"
    README.write_text(txt, encoding="utf-8")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-npv", action="store_true")
    ap.add_argument("--out", default=None, help="override output dir (testing)")
    args = ap.parse_args()

    global SUB_TXT, SUB_PLAIN, ARCHIVE, STATS_JSON, README
    if args.out:
        outdir = Path(args.out)
        outdir.mkdir(parents=True, exist_ok=True)
        SUB_TXT = outdir / "sub.txt"
        SUB_PLAIN = outdir / "sub_plain.txt"
        ARCHIVE = outdir / "archive.json"
        STATS_JSON = outdir / "stats.json"
        README = outdir / "README.md"

    now = datetime.now(timezone.utc)
    now_ts = int(now.timestamp())
    print(f"::group::Shidox Free collector — {now.isoformat(timespec='seconds')}")

    session = requests.Session()

    # ---- rolling archive: load + prune everything older than 48h ----
    try:
        archive = json.loads(ARCHIVE.read_text(encoding="utf-8"))
    except Exception:
        archive = {"version": 1, "entries": []}
    entries = [
        e for e in archive.get("entries", [])
        if now_ts - int(e.get("firstSeen", now_ts)) <= RETENTION.total_seconds()
    ]
    pruned = len(archive.get("entries", [])) - len(entries)
    keys = {e["key"] for e in entries}
    print(f"archive: {len(entries)} kept, {pruned} pruned (>{RETENTION})")

    per_channel: dict[str, dict] = {
        ch: {"id": ch, "count": 0, "fresh": 0, "ok": True, "error": None}
        for ch in ALL_TEXT_CHANNELS
    }
    fresh_keys: set[str] = set()

    def add_entry(raw_link: str, channel: str, dt: datetime, kind: str):
        key = server_key(raw_link)
        if key in keys or key[1] is None:
            return
        keys.add(key)
        fresh_keys.add(str(key))
        entries.append({
            "key": [str(k) if k is not None else None for k in key],
            "config": raw_link,
            "channel": channel,
            "protocol": raw_link.split("://", 1)[0].lower(),
            "kind": kind,
            "firstSeen": now_ts,
            "src": int(dt.timestamp()),
        })

    # ---- 1. text configs from public pages ----
    for ch in ALL_TEXT_CHANNELS:
        try:
            items, err = fetch_channel(session, ch, now)
        except Exception as exc:
            items, err = [], f"{type(exc).__name__}: {exc}"
        if err:
            per_channel[ch]["ok"] = False
            per_channel[ch]["error"] = err
            print(f"  @{ch:<16} scan FAILED: {err}")
        else:
            print(f"  @{ch:<16} {len(items)} config hits (24h)")
        seen_here: set[str] = set()
        for dt, raw_link in items:
            link = html.unescape(raw_link).strip().rstrip(TRAILING)
            if "://" not in link:
                continue
            base = link.split("#", 1)[0]
            if base in seen_here:
                continue
            seen_here.add(base)
            per_channel[ch]["fresh"] += 1
            add_entry(base, ch, dt, "text")
        time.sleep(REQUEST_DELAY)

    # ---- 2. NPV files ----
    npv_links_total = 0
    npv_files_total = 0
    if not args.no_npv:
        import tempfile
        with tempfile.TemporaryDirectory(prefix="shidox-npv-") as td:
            tmpdir = Path(td)
            downloaded = download_npv_files(tmpdir)
            npv_files_total = len(downloaded)
            for ch, path in downloaded:
                workdir = tmpdir / f"dec_{path.stem}"
                links = decrypt_npv_file(path, workdir)
                npv_links_total += len(links)
                seen_here = set()
                for link in links:
                    base = link.split("#", 1)[0]
                    if base in seen_here:
                        continue
                    seen_here.add(base)
                    per_channel[ch]["fresh"] += 1
                    add_entry(base, ch, now, "npv")
            print(f"NPV: {npv_files_total} file(s), {npv_links_total} link(s)")

    # ---- final aggregation ----
    entries.sort(key=lambda e: e["firstSeen"], reverse=True)
    for e in entries:
        bucket = per_channel.get(e["channel"])
        if bucket:
            bucket["count"] += 1
    total = len(entries)
    fresh = len(fresh_keys)

    raw_lines = [e["config"] for e in entries]

    # ---- GeoIP + rename ----
    hosts = sorted({extract_host(l)[1] for l in raw_lines if extract_host(l)[1]})
    geo = {}
    for i in range(0, len(hosts), 100):
        geo.update(geoip_batch(hosts[i:i + 100]))
    failed = [h for h in hosts if geo.get(h, {}).get("status") != "success"]
    if failed:
        ok = {}
        for h in failed:
            try:
                ip = socket.gethostbyname(h)
                if not is_sinkhole(ip):
                    ok[h] = ip
            except Exception:
                pass
        ips = sorted(set(ok.values()))
        ipgeo = {}
        for i in range(0, len(ips), 50):
            ipgeo.update(geoip_batch(ips[i:i + 50]))
        for h, ip in ok.items():
            g = ipgeo.get(ip, {})
            geo[h] = {"status": g.get("status"), "country": g.get("country"),
                      "countryCode": g.get("countryCode"), "via_ip": ip}

    cf_nets = load_cf_nets()
    ip_cache, cf_cache = {}, {}

    def host_ip(host):
        if host in ip_cache:
            return ip_cache[host]
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = None
        if ip and is_sinkhole(ip):
            ip = None
        ip_cache[host] = ip
        return ip

    def is_cf(host):
        if host in cf_cache:
            return cf_cache[host]
        result = False
        try:
            result = any(ipaddress.ip_address(host) in n for n in cf_nets)
        except ValueError:
            ip = host_ip(host)
            if ip:
                try:
                    result = any(ipaddress.ip_address(ip) in n for n in cf_nets)
                except ValueError:
                    result = False
        cf_cache[host] = result
        return result

    out_lines = []
    for line in raw_lines:
        scheme, host = extract_host(line)
        cc = (geo.get(host, {}) or {}).get("countryCode") or "??"
        name = f"{flag(cc)} {BRAND}"
        if host and is_cf(host):
            name += " + CF"
        if scheme == "vmess":
            payload = line.split("://", 1)[1].split("#")[0]
            j = json.loads(b64decode_loose(payload).decode("utf-8", "replace"))
            j["ps"] = name
            new_payload = base64.b64encode(
                json.dumps(j, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode()
            out_lines.append("vmess://" + new_payload)
        else:
            out_lines.append(line.split("#", 1)[0] + "#" + urllib.parse.quote(name, safe=""))

    plain = "\n".join(out_lines) + "\n"
    b64sub = base64.b64encode(plain.encode()).decode()
    SUB_TXT.parent.mkdir(parents=True, exist_ok=True)
    SUB_TXT.write_text(b64sub + "\n", encoding="utf-8")
    SUB_PLAIN.write_text(plain, encoding="utf-8")

    stats = {
        "version": 1,
        "brand": BRAND,
        "lastRun": now.isoformat(timespec="seconds"),
        "total": total,
        "fresh24h": fresh,
        "npvFiles": npv_files_total,
        "npvLinks": npv_links_total,
        "updateEveryHours": 5,
        "retentionHours": int(RETENTION.total_seconds() // 3600),
        "perChannel": list(per_channel.values()),
    }
    STATS_JSON.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
    ARCHIVE.write_text(json.dumps({"version": 1, "entries": entries}, ensure_ascii=False), encoding="utf-8")
    update_readme(stats)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        rows = "\n".join(
            f"| `@{c['id']}` | {c['count']} | {c['fresh']} | {'OK' if c['ok'] else 'FAIL'} |"
            for c in stats["perChannel"])
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"## Shidox Free — {stats['total']} configs (fresh 24h: {stats['fresh24h']}, NPV: {stats['npvLinks']} links from {stats['npvFiles']} files)\n\n"
                    f"| Channel | Configs | Fresh | Status |\n|---|---:|---:|:---:|\n{rows}\n")

    print(f"RESULT: total={total} fresh24h={fresh} npv_links={npv_links_total} "
          f"per-channel={[(c['id'], c['count']) for c in stats['perChannel']]}")
    print("::endgroup::")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(f"::error::fatal: {exc}")
        sys.exit(1)
