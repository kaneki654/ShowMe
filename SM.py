import os
import sys
import time
import socket
import json
import threading
import concurrent.futures
import shutil
import subprocess
import ssl
import secrets
from datetime import datetime
from pathlib import Path
import re
import ipaddress
from ipaddress import ip_address
__author__ = "G0Ju.VBS"
# On Windows the console's default code page (e.g. cp1252) can't encode the
# box-drawing / bullet / arrow characters used throughout the UI, which makes
# rich abort with UnicodeEncodeError before the menu even appears. Force UTF-8
# on the output streams before the Console is built so the banner and tables
# render instead of crashing at startup.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
MISSING = []
try:
    import requests
except ImportError:
    MISSING.append("requests")
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich.columns import Columns
    from rich.rule import Rule
    from rich import box
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich.padding import Padding
except ImportError:
    MISSING.append("rich")
if MISSING:
    print(f"[!] Missing packages: {', '.join(MISSING)}")
    print(f"    Run: pip install {' '.join(MISSING)}")
    sys.exit(1)
console = Console()
C = {
    "accent":   "#00FF41",                 
    "danger":   "#FF3131",
    "warn":     "#FFB000",
    "info":     "#00BFFF",
    "muted":    "#555555",
    "white":    "#E8E8E8",
    "purple":   "#BD00FF",
    "cyan":     "#00FFFF",
    "gold":     "#FFD700",
}
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "GhostRecon/2.0"})
if os.getenv("NVD_API_KEY"):
    SESSION.headers.update({"apiKey": os.getenv("NVD_API_KEY")})
TIMEOUT = 8
COMMON_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,
    465,587,993,995,1433,1521,3306,3389,5432,5900,
    6379,8080,8443,8888,9200,9300,27017,27018,6667,
]
TOP_100_PORTS = [
    7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,
    144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,
    646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,
    1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,
    5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,
    8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,
    49154,49155,49156,49157,
]
NVD_CACHE_PATH = Path.home() / ".cache" / "showme" / "nvd_cvss.json"
NVD_CACHE_TTL = 7 * 24 * 3600
NVD_API_KEY = os.getenv("NVD_API_KEY")
WORDLIST_PATH = Path(__file__).resolve().parent / "wordlists" / "subdomains.txt"
INLINE_FALLBACK_WORDLIST = [
    "www","mail","webmail","smtp","pop","pop3","imap","ftp","sftp","ssh","vpn",
    "remote","portal","api","dev","staging","stage","test","qa","uat","prod",
    "admin","administrator","root","dashboard","cpanel","whm","webdisk","ns1",
    "ns2","dns","mx","mx1","blog","shop","store","cdn","static","assets","img",
    "images","media","video","download","files","docs","help","support","kb",
]
SEVERITY = {
    "critical": ("bold red",       "[CRIT]"),
    "high":     ("bold #FF6600",   "[HIGH]"),
    "medium":   ("bold yellow",    "[MED] "),
    "low":      ("bold green",     "[LOW] "),
    "info":     ("bold cyan",      "[INFO]"),
    "unknown":  ("dim white",      "[ ?  ]"),
}
BANNER = r"""
 _________.__                    _____
 /   _____/|  |__   ______  _  __/     \   ____
 \_____  \ |  |  \ /  _ \ \/ \/ /  \ /  \_/ __ \
 /        \|   Y  (  <_> )     /    Y    \  ___/
/_______  /|___|  /\____/ \/\_/\____|__  /\___  >
        \/      \/                     \/     \/
"""
MINI_BANNER = "[bold #00FF41][ GHOST RECON v2.0 ][/] [dim]// Advanced OSINT Framework // By G0Ju.VBS[/]"
def animate_banner():
    os.system("clear" if os.name != "nt" else "cls")
    lines = BANNER.strip("\n").splitlines()
    for i, line in enumerate(lines):
        col = f"#{hex(0 + i * 36)[2:].zfill(2)}FF{hex(65 + i * 30)[2:].zfill(2)}"
        console.print(f"[bold {C['accent']}]{line}[/]")
        time.sleep(0.04)
    console.print()
    console.print(Align.center(f"[dim {C['muted']}]PASSIVE OSINT ·BY G0Ju.VBS[/]"))
    console.print(Align.center(f"[dim {C['muted']}]{'─' * 62}[/]"))
    console.print()
    time.sleep(0.3)
def glitch_text(text: str, duration: float = 0.6):
    chars = "!@#$%^&*<>?/\\|~`"
    import random
    steps = int(duration / 0.05)
    for i in range(steps):
        ratio = i / steps
        glitched = "".join(
            c if random.random() < ratio else random.choice(chars)
            for c in text
        )
        console.print(f"\r[bold {C['accent']}]{glitched}[/]", end="")
        time.sleep(0.05)
    console.print(f"\r[bold {C['accent']}]{text}[/]")
def type_print(text: str, style: str = "", delay: float = 0.018):
    for ch in text:
        console.print(f"[{style}]{ch}[/]" if style else ch, end="")
        sys.stdout.flush()
        time.sleep(delay)
    console.print()
def spinner_task(label: str, fn, *args, **kwargs):
    result = [None]
    error  = [None]
    def worker():
        try:
            result[0] = fn(*args, **kwargs)
        except Exception as e:
            error[0] = e
    with Progress(
        SpinnerColumn(spinner_name="dots2", style=f"bold {C['accent']}"),
        TextColumn(f"[{C['info']}]{label}[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task(label, total=None)
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        while t.is_alive():
            prog.advance(task)
            time.sleep(0.05)
        t.join()
    if error[0]:
        raise error[0]
    return result[0]
def section_header(title: str, icon: str = "+"):
    console.print()
    console.rule(f"[bold {C['accent']}]{icon} {title}[/]", style=C['muted'])
def print_kv(key: str, val, style_val: str = C['white']):
    k = f"[{C['muted']}]{key:<22}[/]"
    if isinstance(val, list):
        if not val:
            console.print(f"  {k} [dim]-[/]")
        else:
            console.print(f"  {k} [{style_val}]{val[0]}[/]")
            for v in val[1:]:
                console.print(f"  {'':22} [{style_val}]{v}[/]")
    else:
        console.print(f"  {k} [{style_val}]{val if val else '-'}[/]")
_RATE_LOCKS = {}
_LAST_CALL = {}
_HOST_MIN_INTERVAL = {
    "api.hackertarget.com": 1.5,
    "internetdb.shodan.io": 0.4,
    "crt.sh": 1.0,
    "urlscan.io": 1.0,
    "api.bgpview.io": 0.6,
    "ip-api.com": 0.3,
    "ipwho.is": 0.3,
    "dns.google": 0.1,
    "services.nvd.nist.gov": 0.6 if NVD_API_KEY else 6.0,
}
def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ""
    except Exception:
        return ""
def _throttle(host: str):
    interval = _HOST_MIN_INTERVAL.get(host, 0.0)
    if interval <= 0:
        return
    lock = _RATE_LOCKS.setdefault(host, threading.Lock())
    with lock:
        last = _LAST_CALL.get(host, 0.0)
        delta = time.time() - last
        if delta < interval:
            time.sleep(interval - delta)
        _LAST_CALL[host] = time.time()
def safe_get(url: str, params: dict = None, json_resp: bool = True, timeout: int = TIMEOUT, max_retries: int = 4):
    host = _host_of(url)
    backoff = 1.0
    last_status = 0
    last_err = ""
    for attempt in range(max_retries):
        _throttle(host)
        r = None
        try:
            r = SESSION.get(url, params=params, timeout=timeout)
            status = r.status_code
            if status == 429 or 500 <= status < 600:
                last_status = status
                retry_after = r.headers.get("Retry-After")
                wait = float(retry_after) if retry_after and retry_after.replace(".", "", 1).isdigit() else backoff
                wait = min(wait, 15.0)
                time.sleep(wait)
                backoff = min(backoff * 2, 15.0)
                continue
            r.raise_for_status()
            return r.json() if json_resp else r.text
        except requests.exceptions.HTTPError as e:
            last_status = r.status_code if r is not None else 0
            last_err = str(e)
            if last_status in (400, 401, 403, 404, 410):
                return {"_http_error": last_err, "_status": last_status}
            time.sleep(backoff)
            backoff = min(backoff * 2, 15.0)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_err = str(e)
            time.sleep(backoff)
            backoff = min(backoff * 2, 15.0)
        except Exception as e:
            return {"_error": str(e)}
    if last_status:
        return {"_http_error": last_err or f"HTTP {last_status}", "_status": last_status}
    return {"_error": last_err or "max retries exceeded"}
def resolve(target: str):
    if is_ip(target):
        return target, None
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except Exception:
        return None, target
def is_ip(s: str) -> bool:
    try:
        ip_address(s)
        return True
    except ValueError:
        return False
def mod_geo(ip: str):
    section_header("GEOLOCATION", ">")
    data = safe_get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"}
    )
    if "_error" in data or data.get("status") == "fail":
        console.print(f"  [dim]No geodata for {ip}[/]")
        return
    print_kv("IP",       data.get("query"),                    C['cyan'])
    print_kv("Location", f"{data.get('city')}, {data.get('regionName')}, {data.get('country')}")
    print_kv("Coords",   f"{data.get('lat')}, {data.get('lon')}", C['muted'])
    print_kv("Timezone", data.get("timezone"))
    print_kv("ISP",      data.get("isp"),     C['warn'])
    print_kv("Org",      data.get("org"),     C['warn'])
    print_kv("ASN",      data.get("as"),      C['purple'])
def mod_shodan(ip: str) -> dict:
    section_header("SHODAN INTERNET DB  (no key)", ">")
    data = safe_get(f"https://internetdb.shodan.io/{ip}")
    if "_http_error" in data and data.get("_status") == 404:
        console.print(f"  [dim]No Shodan data indexed for {ip}[/]")
        return {}
    if "_error" in data:
        console.print(f"  [dim red]Error: {data['_error']}[/]")
        return {}
    ports     = data.get("ports", [])
    hostnames = data.get("hostnames", [])
    cpes      = data.get("cpes", [])
    tags      = data.get("tags", [])
    vulns     = data.get("vulns", [])
    print_kv("Open Ports",  [str(p) for p in sorted(ports)], C['cyan'])
    print_kv("Hostnames",   hostnames, C['accent'])
    print_kv("CPEs",        cpes,      C['muted'])
    print_kv("Tags",        tags,      C['warn'])
    if vulns:
        console.print()
        console.print(f"  [bold {C['danger']}]>> {len(vulns)} CVE(s) FOUND <<[/]")
        cvss = fetch_cvss_many(sorted(vulns))
        for cve in sorted(vulns):
            sev_style, sev_label = _cve_severity(cve, cvss)
            score = cvss.get(cve, {}).get("score")
            score_txt = f"[dim](CVSS {score})[/] " if isinstance(score, (int, float)) else ""
            console.print(f"    [{sev_style}]{sev_label}[/] [{C['white']}]{cve}[/]  {score_txt}"
                          f"[link=https://nvd.nist.gov/vuln/detail/{cve}][dim u]nvd.nist.gov[/][/link]")
    else:
        print_kv("CVEs", "None in database", C['accent'])
    return data
def _cve_severity(cve_id, cvss_dict=None):
    if cvss_dict:
        entry = cvss_dict.get(cve_id)
        if entry:
            sev = str(entry.get("severity", "")).lower()
            if sev in SEVERITY:
                return SEVERITY[sev]
    return SEVERITY["unknown"]
def fetch_cvss(cve_id, cache):
    now = time.time()
    cached = cache.get(cve_id)
    if cached and (now - cached.get("fetched", 0)) < NVD_CACHE_TTL:
        return cached if cached.get("severity") else None
    data = safe_get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve_id}, timeout=15)
    if not isinstance(data, dict) or "_error" in data or "_http_error" in data:
        return None
    if data.get("totalResults", 0) == 0:
        cache[cve_id] = {"fetched": now, "severity": None, "score": None, "vector": None}
        return None
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    metrics = (vulns[0].get("cve") or {}).get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = metrics.get(key)
        if m:
            cdata = (m[0] or {}).get("cvssData") or {}
            score = cdata.get("baseScore")
            sev_raw = cdata.get("baseSeverity") or (m[0] or {}).get("baseSeverity")
            sev = str(sev_raw).lower() if sev_raw else None
            if sev == "none":
                sev = "info"
            if sev not in SEVERITY:
                sev = "high" if sev == "high" else sev if sev in SEVERITY else None
            if not sev and isinstance(score, (int, float)):
                if score >= 9.0:   sev = "critical"
                elif score >= 7.0: sev = "high"
                elif score >= 4.0: sev = "medium"
                elif score > 0.0:  sev = "low"
                else:              sev = "info"
            vector = cdata.get("vectorString")
            entry = {"fetched": now, "severity": sev, "score": score, "vector": vector}
            cache[cve_id] = entry
            return entry
    cache[cve_id] = {"fetched": now, "severity": None, "score": None, "vector": None}
    return None
def fetch_cvss_many(cve_ids, cap=10):
    cache = _cache_load()
    now = time.time()
    result = {}
    misses = []
    for cve in cve_ids:
        c = cache.get(cve)
        if c and (now - c.get("fetched", 0)) < NVD_CACHE_TTL:
            if c.get("severity"):
                result[cve] = c
        else:
            misses.append(cve)
    if not misses:
        return result
    rate = _HOST_MIN_INTERVAL.get("services.nvd.nist.gov", 6.0)
    est_seconds = int(len(misses) * rate)
    to_fetch = misses
    if len(misses) > cap:
        console.print(f"  [{C['warn']}]{len(misses)} uncached CVE(s). Fresh NVD fetch takes ~{est_seconds}s.[/]")
        try:
            if not Confirm.ask(f"  [{C['info']}]?[/] Fetch CVSS for all {len(misses)}?", default=False):
                to_fetch = misses[:cap]
                console.print(f"  [dim]Limiting to first {cap} CVEs.[/]")
        except (KeyboardInterrupt, EOFError):
            to_fetch = misses[:cap]
    try:
        with Progress(
            SpinnerColumn(spinner_name="dots2", style=f"bold {C['accent']}"),
            TextColumn(f"[{C['info']}]Fetching CVSS from NVD[/]"),
            BarColumn(bar_width=30, style=C['muted'], complete_style=C['accent']),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task("", total=len(to_fetch))
            for cve in to_fetch:
                try:
                    entry = fetch_cvss(cve, cache)
                    if entry and entry.get("severity"):
                        result[cve] = entry
                except Exception:
                    pass
                prog.advance(task)
    except KeyboardInterrupt:
        console.print(f"  [{C['warn']}]NVD fetch interrupted, showing partial data.[/]")
    _cache_save(cache)
    return result
def mod_ipwho(ip: str):
    section_header("NETWORK / WHOIS", ">")
    data = safe_get(f"https://ipwho.is/{ip}")
    if "_error" in data or not data.get("success", True):
        console.print("  [dim]No network data[/]")
        return
    conn = data.get("connection", {})
    print_kv("ASN",        conn.get("asn"),    C['purple'])
    print_kv("AS Org",     conn.get("org"),    C['warn'])
    print_kv("ISP",        conn.get("isp"))
    print_kv("Domain",     conn.get("domain"))
    print_kv("Type",       data.get("type"),   C['cyan'])
    print_kv("Continent",  data.get("continent"))
    print_kv("EU Member",  str(data.get("is_eu", False)))
def mod_bgpview(ip: str):
    section_header("NETWORK / ASN  (RIPEstat)", ">")
    # RIPEstat first (reliable, keyless); fall back to BGPView if unreachable.
    data = safe_get("https://stat.ripe.net/data/network-info/data.json",
                    params={"resource": ip}, timeout=10, max_retries=2)
    prefix, asn = None, None
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        d = data["data"]
        prefix = d.get("prefix")
        asns = d.get("asns") or []
        asn = asns[0] if asns else None
    if prefix or asn:
        if prefix:
            print_kv("Prefix", prefix, C['white'])
        if asn:
            print_kv("ASN", f"AS{asn}", C['purple'])
            ov = safe_get("https://stat.ripe.net/data/as-overview/data.json",
                          params={"resource": f"AS{asn}"}, timeout=10, max_retries=2)
            if isinstance(ov, dict) and isinstance(ov.get("data"), dict):
                holder = ov["data"].get("holder")
                if holder:
                    print_kv("AS Holder", holder, C['cyan'])
        return
    bg = safe_get(f"https://api.bgpview.io/ip/{ip}")
    if isinstance(bg, dict) and bg.get("status") == "ok":
        prefixes = bg.get("data", {}).get("prefixes", [{}])
        if prefixes:
            first = prefixes[0]
            a = first.get("asn", {})
            print_kv("Prefix", first.get("prefix"))
            print_kv("ASN", a.get("asn"), C['purple'])
            print_kv("Name", a.get("name"), C['cyan'])
            print_kv("Description", a.get("description"), C['muted'])
            return
    console.print("  [dim]No network / ASN data[/]")
def mod_dns(domain: str):
    section_header("DNS RECORDS  (Google DoH)", ">")
    types = ["A","AAAA","NS","MX","TXT","CNAME","SOA"]
    for rtype in types:
        data = safe_get("https://dns.google/resolve", params={"name": domain, "type": rtype})
        answers = [a.get("data","") for a in data.get("Answer",[])] if "_error" not in data else []
        if answers:
            print_kv(rtype, answers, C['accent'] if rtype == "A" else C['white'])
        time.sleep(0.08)
def mod_subdomains_passive(domain):
    data = safe_get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    if isinstance(data, dict):
        return []
    subs = set()
    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain) and name != domain:
                subs.add(name)
    return sorted(subs)
def _detect_wildcard(domain):
    try:
        r1 = socket.gethostbyname(f"{secrets.token_hex(8)}.{domain}")
    except Exception:
        return (False, None)
    try:
        r2 = socket.gethostbyname(f"{secrets.token_hex(8)}.{domain}")
    except Exception:
        return (True, r1)
    if r1 == r2:
        return (True, r1)
    return (True, None)
def _load_wordlist(path=None):
    p = Path(path) if path else WORDLIST_PATH
    try:
        if p.exists():
            words = []
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    words.append(line)
            if words:
                return words
    except Exception:
        pass
    return list(INLINE_FALLBACK_WORDLIST)
def mod_subdomains_bruteforce(domain, wordlist_path=None, workers=40):
    words = _load_wordlist(wordlist_path)
    found = []
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(2.0)
    try:
        with Progress(
            SpinnerColumn(spinner_name="dots2", style=f"bold {C['accent']}"),
            TextColumn(f"[{C['info']}]Brute-forcing {len(words)} names[/]"),
            BarColumn(bar_width=30, style=C['muted'], complete_style=C['accent']),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task("", total=len(words))
            def try_one(w):
                host = f"{w}.{domain}"
                try:
                    ip = socket.gethostbyname(host)
                    return (host, ip)
                except Exception:
                    return None
                finally:
                    prog.advance(task)
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                try:
                    for result in ex.map(try_one, words):
                        if result:
                            found.append(result)
                except KeyboardInterrupt:
                    console.print(f"\n  [{C['warn']}]Brute-force interrupted, showing partial results.[/]")
    finally:
        socket.setdefaulttimeout(old_timeout)
    found.sort()
    return found
def mod_subdomains(domain, bruteforce=True, wordlist_path=None):
    section_header("SUBDOMAIN ENUMERATION", ">")
    console.print(f"  [dim]Detecting wildcard DNS...[/]")
    is_wc, wc_ip = _detect_wildcard(domain)
    if is_wc:
        msg = f"Wildcard DNS detected (IP={wc_ip})" if wc_ip else "Unstable wildcard DNS detected"
        console.print(f"  [{C['warn']}]{msg}. Brute-force skipped to avoid false positives.[/]")
        bruteforce = False
    else:
        console.print(f"  [dim]No wildcard.[/]")
    console.print(f"  [dim]Querying {len(PASSIVE_SOURCES)} passive sources "
                  f"(crt.sh, OTX, Anubis, CertSpotter, Wayback, RapidDNS, HackerTarget)...[/]")
    passive_map, counts = spinner_task("Aggregating passive DNS sources", gather_passive_subdomains, domain)
    passive_set = set(passive_map)
    brute = []
    if bruteforce:
        brute = mod_subdomains_bruteforce(domain, wordlist_path=wordlist_path)
    brute_set = {h for h, _ip in brute}
    for h in brute_set:
        passive_map.setdefault(h, set()).add("brute")
    all_names = sorted(passive_set | brute_set)
    tree = Tree(f"[bold {C['accent']}]{domain}[/]")
    MAXSHOW = 300
    for name in all_names[:MAXSHOW]:
        srcs = sorted(passive_map.get(name, set()))
        tag = " ".join(f"[dim cyan]{s}[/]" for s in srcs)
        tree.add(f"[{C['cyan']}]{mesc(name)}[/]  {tag}")
    if len(all_names) > MAXSHOW:
        tree.add(f"[dim]... and {len(all_names) - MAXSHOW} more (in export/report)[/]")
    console.print(Padding(tree, (0, 4)))
    breakdown = ", ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda x: -x[1]))
    console.print(f"\n  [dim]Sources: {breakdown}[/]")
    console.print(
        f"  [dim]Total: {len(all_names)} unique "
        f"(passive={len(passive_set)}, brute={len(brute_set)}, "
        f"overlap={len(passive_set & brute_set)})[/]"
    )
    return all_names
def mod_reverse_ip(ip: str):
    section_header("REVERSE IP LOOKUP  (hackertarget)", ">")
    text = safe_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", json_resp=False)
    if isinstance(text, dict):
        console.print("  [dim]Error or rate limited[/]")
        return
    lines = [l for l in text.strip().splitlines() if l]
    total = len(lines)
    show  = lines[:40]
    for l in show:
        console.print(f"  [{C['cyan']}]>[/] [{C['white']}]{l}[/]")
    if total > 40:
        console.print(f"  [dim]... and {total-40} more[/]")
def mod_host_records(domain: str):
    section_header("HOST RECORDS  (hackertarget)", ">")
    text = safe_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", json_resp=False)
    if isinstance(text, dict):
        console.print("  [dim]Error or rate limited[/]")
        return
    lines = [l for l in text.strip().splitlines() if l]
    t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C['accent']}", padding=(0,2))
    t.add_column("HOSTNAME",   style=C['cyan'])
    t.add_column("IP ADDRESS", style=C['white'])
    for line in lines[:50]:
        parts = line.split(",")
        if len(parts) == 2:
            t.add_row(parts[0].strip(), parts[1].strip())
    console.print(Padding(t, (0,2)))
_NMAP_PATH_CACHE = [None, False]
def _nmap_path():
    if not _NMAP_PATH_CACHE[1]:
        _NMAP_PATH_CACHE[0] = shutil.which("nmap")
        _NMAP_PATH_CACHE[1] = True
    return _NMAP_PATH_CACHE[0]
def _probe(port, sock):
    try:
        if port in (80, 8080, 8888, 8000, 8081, 81):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 6379:
            sock.sendall(b"PING\r\n")
        elif port in (443, 8443, 993, 995):
            return "[TLS]"
        sock.settimeout(0.8)
        raw = sock.recv(512)
        if not raw:
            return ""
        if port == 3306 and len(raw) > 4:
            raw = raw[4:]
        text = raw.decode(errors="replace").strip()
        return text.splitlines()[0][:80] if text else ""
    except Exception:
        return ""
def mod_port_scan(ip, port_spec=None, grab_banner=True):
    try:
        ports = _parse_port_spec(port_spec) if port_spec not in (None, "") else list(COMMON_PORTS)
    except ValueError as e:
        console.print(f"  [{C['danger']}]Invalid port spec: {e}[/]")
        return []
    section_header(f"PORT SCANNER  [socket]  ({len(ports)} ports)", ">")
    open_ports = []
    with Progress(
        SpinnerColumn(spinner_name="arc", style=f"bold {C['accent']}"),
        TextColumn(f"[{C['info']}]Scanning {len(ports)} ports[/]"),
        BarColumn(bar_width=30, style=C['muted'], complete_style=C['accent']),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        task = prog.add_task("", total=len(ports))
        def scan_one(port):
            try:
                with socket.create_connection((ip, port), timeout=1.2) as s:
                    banner = _probe(port, s) if grab_banner else ""
                    return (port, True, banner)
            except Exception:
                return (port, False, "")
            finally:
                prog.advance(task)
        workers = min(100, max(20, len(ports)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            try:
                for result in ex.map(scan_one, ports):
                    port, is_open, banner = result
                    if is_open:
                        open_ports.append((port, banner))
            except KeyboardInterrupt:
                console.print(f"\n  [{C['warn']}]Port scan interrupted! Showing partial results...[/]")
    open_ports.sort()
    _render_port_table(open_ports)
    return open_ports
def _render_port_table(open_ports):
    if not open_ports:
        console.print(f"  [{C['warn']}]No open ports detected (firewall/filtered)[/]")
        return
    t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C['accent']}", padding=(0,2))
    t.add_column("PORT",    style=C['cyan'],    width=8)
    t.add_column("SERVICE", style=C['purple'],  width=20)
    t.add_column("STATE",   style=C['accent'],  width=8)
    t.add_column("BANNER",  style=C['muted'])
    for port, banner in open_ports:
        svc = _svc(port)
        t.add_row(str(port), svc, "OPEN", banner[:70] if banner else "")
    console.print(Padding(t, (0,2)))
def mod_port_scan_nmap(ip, port_spec=None):
    nmap = _nmap_path()
    if not nmap:
        return mod_port_scan(ip, port_spec)
    spec = str(port_spec).strip() if port_spec else ""
    if not spec or spec.lower() in ("common", "default"):
        spec = ",".join(str(p) for p in COMMON_PORTS)
    elif spec.lower() == "top100":
        spec = ",".join(str(p) for p in TOP_100_PORTS)
    elif spec.lower() == "all":
        spec = "1-65535"
    section_header(f"PORT SCANNER  [nmap -sV]  (ports {spec[:40]}{'...' if len(spec) > 40 else ''})", ">")
    open_ports = []
    raw_output = ""
    try:
        with Progress(
            SpinnerColumn(spinner_name="arc", style=f"bold {C['accent']}"),
            TextColumn(f"[{C['info']}]Running nmap -sV (this may take a while)[/]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as prog:
            prog.add_task("", total=None)
            proc_g = subprocess.run(
                [nmap, "-Pn", "-sV", "-T3", "--open", "-oG", "-", "-p", spec, ip],
                capture_output=True, text=True, timeout=600, check=False
            )
            proc_n = subprocess.run(
                [nmap, "-Pn", "-sV", "-T3", "--open", "-p", spec, ip],
                capture_output=True, text=True, timeout=600, check=False
            )
            raw_output = proc_n.stdout or ""
            for line in (proc_g.stdout or "").splitlines():
                if "Ports:" not in line:
                    continue
                _, _, ports_part = line.partition("Ports:")
                for entry in ports_part.split(","):
                    m = re.match(r"\s*(\d+)/open/tcp//([^/]*)//([^/]*)//", entry)
                    if not m:
                        continue
                    port = int(m.group(1))
                    svc = m.group(2).strip()
                    version = m.group(3).replace("\\x2f", "/").strip()
                    banner = f"{svc} {version}".strip() if svc or version else ""
                    open_ports.append((port, banner))
    except subprocess.TimeoutExpired:
        console.print(f"  [{C['warn']}]nmap timed out after 10 minutes. Partial results may be empty.[/]")
    except KeyboardInterrupt:
        console.print(f"\n  [{C['warn']}]nmap interrupted![/]")
    except Exception as e:
        console.print(f"  [{C['danger']}]nmap error: {e}[/]")
        return mod_port_scan(ip, port_spec)
    open_ports.sort()
    _render_port_table(open_ports)
    if raw_output.strip():
        trimmed = "\n".join(raw_output.splitlines()[:40])
        console.print(Panel(trimmed, title="[dim]nmap raw output[/]", border_style=C['muted'], padding=(0,1)))
    return open_ports
def mod_port_scan_auto(ip, port_spec=None, grab_banner=True, force_socket=False):
    if _nmap_path() and not force_socket:
        return mod_port_scan_nmap(ip, port_spec)
    return mod_port_scan(ip, port_spec, grab_banner=grab_banner)
_TLS_VERSIONS = [
    ("TLSv1",   "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
    ("TLSv1.2", "TLSv1_2"),
    ("TLSv1.3", "TLSv1_3"),
]
_WEAK_CIPHER_RE = re.compile(r"RC4|3DES|MD5|EXPORT|NULL|DES-CBC", re.IGNORECASE)
def _tls_format_cert_time(s):
    try:
        secs = ssl.cert_time_to_seconds(s)
        return datetime.utcfromtimestamp(secs).strftime("%Y-%m-%d %H:%M:%S UTC"), secs
    except Exception:
        return s, None
def _tls_probe_version(host, port, version_name):
    try:
        ver_enum = getattr(ssl.TLSVersion, version_name)
    except (AttributeError, ValueError):
        return "DISABLED IN CLIENT", None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ver_enum
            ctx.maximum_version = ver_enum
        except (ValueError, OSError):
            return "DISABLED IN CLIENT", None
    except Exception:
        return "DISABLED IN CLIENT", None
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return "SUPPORTED", ss.cipher()
    except ssl.SSLError as e:
        msg = str(e)
        if "NO_PROTOCOLS_AVAILABLE" in msg or "no protocols" in msg.lower():
            return "DISABLED IN CLIENT", None
        return "NOT OFFERED", None
    except (socket.timeout, ConnectionError, OSError):
        return "NOT OFFERED", None
def mod_tls(host, port=443, probe_versions=True):
    section_header(f"TLS / CERTIFICATE  ({host}:{port})", ">")
    result = {"host": host, "port": port}
    ctx_verify = ssl.create_default_context()
    verified = False
    verify_err = ""
    negotiated = {}
    cert = None
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx_verify.wrap_socket(sock, server_hostname=host) as ss:
                verified = True
                negotiated["version"] = ss.version()
                negotiated["cipher"] = ss.cipher()
                c = ss.getpeercert()
                if c:
                    cert = c
    except ssl.SSLCertVerificationError as e:
        verify_err = f"{e.reason or str(e)}"
    except (socket.timeout, ConnectionError, OSError, ssl.SSLError) as e:
        console.print(f"  [{C['danger']}]TLS connect failed: {e}[/]")
        return {"error": str(e)}
    if not cert:
        try:
            import tempfile
            with socket.create_connection((host, port), timeout=8) as sock:
                ctx_perm = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_perm.check_hostname = False
                ctx_perm.verify_mode = ssl.CERT_NONE
                with ctx_perm.wrap_socket(sock, server_hostname=host) as ss:
                    if not negotiated.get("version"):
                        negotiated["version"] = ss.version()
                    if not negotiated.get("cipher"):
                        negotiated["cipher"] = ss.cipher()
                    der = ss.getpeercert(binary_form=True)
                    if der:
                        pem = ssl.DER_cert_to_PEM_cert(der)
                        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as tf:
                            tf.write(pem)
                            tmp_path = tf.name
                        try:
                            cert = ssl._ssl._test_decode_cert(tmp_path)
                        except Exception:
                            cert = None
                        finally:
                            try:
                                os.unlink(tmp_path)
                            except Exception:
                                pass
        except Exception as e:
            console.print(f"  [{C['warn']}]Permissive handshake failed: {e}[/]")
    result["verified"] = verified
    if not verified and verify_err:
        print_kv("Verification", f"FAILED — {verify_err}", C['danger'])
    else:
        print_kv("Verification", "OK" if verified else "UNKNOWN", C['accent'] if verified else C['warn'])
    if negotiated.get("version"):
        print_kv("Negotiated TLS", negotiated["version"], C['accent'])
    cipher_tuple = negotiated.get("cipher")
    if cipher_tuple:
        cname, cver, cbits = cipher_tuple
        weak = bool(_WEAK_CIPHER_RE.search(cname))
        print_kv("Cipher", f"{cname} ({cbits} bits)", C['danger'] if weak else C['cyan'])
        if weak:
            console.print(f"  [{C['danger']}]  -> WEAK cipher flagged[/]")
        result["cipher"] = cname
    if cert and isinstance(cert, dict) and "_der_only" not in cert:
        subj = dict(x[0] for x in cert.get("subject", ()) if x)
        issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
        print_kv("Subject CN", subj.get("commonName", "-"), C['white'])
        print_kv("Issuer",     f"{issuer.get('commonName','-')} ({issuer.get('organizationName','-')})", C['purple'])
        sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
        if sans:
            print_kv("SANs", sans, C['cyan'])
        nb, _ = _tls_format_cert_time(cert.get("notBefore", ""))
        na, na_secs = _tls_format_cert_time(cert.get("notAfter", ""))
        print_kv("Not Before", nb, C['muted'])
        if na_secs is not None:
            days_left = int((na_secs - time.time()) // 86400)
            color = C['danger'] if days_left <= 0 else (C['warn'] if days_left < 30 else C['accent'])
            print_kv("Not After", f"{na}  ({days_left} days left)", color)
            result["days_left"] = days_left
        else:
            print_kv("Not After", na, C['muted'])
        result["subject_cn"] = subj.get("commonName")
        result["issuer"] = issuer.get("commonName")
        result["sans"] = sans
    elif cert and "_der_only" in cert:
        print_kv("Certificate", "Present (DER only, parser unavailable)", C['warn'])
    else:
        print_kv("Certificate", "Not retrievable", C['warn'])
    if probe_versions:
        console.print()
        t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C['accent']}", padding=(0,2))
        t.add_column("VERSION", style=C['cyan'], width=10)
        t.add_column("STATUS",  style=C['white'], width=24)
        t.add_column("CIPHER (if supported)", style=C['muted'])
        version_results = {}
        for display, attr in _TLS_VERSIONS:
            status, cipher = _tls_probe_version(host, port, attr)
            if status == "SUPPORTED":
                is_deprecated = attr in ("TLSv1", "TLSv1_1")
                style = C['danger'] if is_deprecated else C['accent']
                label = f"[{style}]{'[SUPPORTED]' + (' DEPRECATED' if is_deprecated else '')}[/]"
            elif status == "DISABLED IN CLIENT":
                label = f"[dim]{status}[/]"
            else:
                label = f"[{C['muted']}]{status}[/]"
            cipher_txt = cipher[0] if cipher else ""
            t.add_row(display, label, cipher_txt)
            version_results[display] = status
        console.print(Padding(t, (0, 2)))
        result["versions"] = version_results
    return result
def _svc(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"
def _parse_port_spec(s):
    if s is None:
        return list(COMMON_PORTS)
    s = str(s).strip().lower()
    if not s or s in ("common", "default"):
        return list(COMMON_PORTS)
    if s == "top100":
        return list(TOP_100_PORTS)
    if s == "all":
        return list(range(1, 65536))
    ports = set()
    for chunk in s.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if lo_i < 1 or hi_i > 65535 or lo_i > hi_i:
                raise ValueError(f"invalid range: {chunk}")
            ports.update(range(lo_i, hi_i + 1))
        else:
            n = int(chunk)
            if n < 1 or n > 65535:
                raise ValueError(f"invalid port: {chunk}")
            ports.add(n)
    return sorted(ports)
def _cache_load():
    try:
        if NVD_CACHE_PATH.exists():
            with NVD_CACHE_PATH.open("r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        pass
    return {}
def _cache_save(cache):
    try:
        NVD_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with NVD_CACHE_PATH.open("w") as f:
            json.dump(cache, f)
    except Exception:
        pass
def mod_http_headers(target: str):
    section_header("HTTP HEADERS", ">")
    for scheme in ("https","http"):
        url = f"{scheme}://{target}"
        try:
            r = SESSION.head(url, timeout=TIMEOUT, allow_redirects=True)
            print_kv("Status",  f"{r.status_code} {r.reason}", C['accent'] if r.ok else C['danger'])
            print_kv("Final URL", str(r.url)[:80], C['cyan'])
            interesting = [
                "server","x-powered-by","x-frame-options","content-security-policy",
                "strict-transport-security","x-content-type-options","set-cookie",
                "cf-ray","x-cache","via","x-aspnet-version","x-generator",
            ]
            for h in interesting:
                v = r.headers.get(h)
                if v:
                    style = C['danger'] if h in ("set-cookie","x-powered-by","server") else C['muted']
                    print_kv(h, v[:100], style)
            break
        except Exception as e:
            console.print(f"  [dim]  {scheme.upper()} failed: {e}[/]")
def mod_whois(domain: str):
    section_header("WHOIS  (hackertarget)", ">")
    text = safe_get(f"https://api.hackertarget.com/whois/?q={domain}", json_resp=False)
    if isinstance(text, dict):
        console.print("  [dim]Error or rate limited[/]")
        return
    skip_kw = (">>>","NOTICE","TERMS","For more","http","abuse","whois.","WHOIS")
    for line in text.splitlines():
        if not line.strip() or any(k in line for k in skip_kw):
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            if v.strip():
                print_kv(k.strip(), v.strip())
def mass_scan(targets: list):
    # NOTE: NVD CVSS enrichment is intentionally NOT wired into mass_scan. With the
    # unauthenticated NVD rate limit (~6s/req), bulk-scanning N targets with M CVEs
    # each would block for minutes. CVSS labels live only in mod_shodan (DEEP SCAN / CVE CHECK).
    os.system("clear" if os.name != "nt" else "cls")
    console.print(Align.center(MINI_BANNER))
    console.print()
    glitch_text(f"  MASS RECON  //  {len(targets)} targets queued")
    console.print(f"  [dim]Querying Shodan InternetDB + port data for each target...[/]\n")
    results = []
    with Progress(
        SpinnerColumn(spinner_name="line", style=f"bold {C['accent']}"),
        TextColumn(f"[{C['info']}]{{task.description}}[/]"),
        BarColumn(bar_width=40, style=C['muted'], complete_style=C['accent']),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%  {task.completed}/{task.total}"),
        console=console,
    ) as prog:
        task = prog.add_task("Scanning", total=len(targets))
        try:
            for raw in targets:
                raw = raw.strip()
                if not raw or raw.startswith("#"):
                    prog.advance(task)
                    continue
                prog.update(task, description=f"[{C['info']}]{raw:<35}[/]")
                ip, domain = resolve(raw)
                if not ip:
                    results.append({
                        "target": raw, "ip": "?", "ports": [], "vulns": [], "cves": []
                    })
                    prog.advance(task)
                    continue
                geo  = safe_get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "country,city,isp,org"},
                    timeout=6
                )
                shod = safe_get(f"https://internetdb.shodan.io/{ip}", timeout=6)
                entry = {
                    "target":  raw,
                    "ip":      ip,
                    "country": geo.get("countryCode","??") if "_error" not in geo else "??",
                    "org":     (geo.get("org") or geo.get("isp",""))[:30],
                    "ports":   shod.get("ports",[]) if "_error" not in shod else [],
                    "hostnames": shod.get("hostnames",[]) if "_error" not in shod else [],
                    "cpes":    shod.get("cpes",[])    if "_error" not in shod else [],
                    "vulns":   shod.get("vulns",[])   if "_error" not in shod else [],
                    "tags":    shod.get("tags",[])     if "_error" not in shod else [],
                }
                results.append(entry)
                prog.advance(task)
                time.sleep(0.2)
        except KeyboardInterrupt:
            console.print(f"\n  [{C['warn']}]Scan interrupted! Showing partial results...[/]")
            time.sleep(1)                           
    console.print()
    console.rule(f"[bold {C['accent']}]>> MASS RECON RESULTS[/]", style=C['muted'])
    console.print()
    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {C['accent']}",
        border_style=C['muted'],
        padding=(0,1),
        expand=True,
    )
    t.add_column("TARGET",    style=C['cyan'],   min_width=20)
    t.add_column("IP",        style=C['white'],  width=16)
    t.add_column("CC",        style=C['purple'], width=5)
    t.add_column("ORG",       style=C['muted'],  max_width=28)
    t.add_column("PORTS",     style=C['info'],   max_width=22)
    t.add_column("CVEs",      style=C['danger'], width=6)
    t.add_column("VULNS",     style=C['danger'], max_width=40)
    vuln_count = 0
    for r in results:
        ports_str = ",".join(str(p) for p in sorted(r["ports"])[:8])
        if len(r["ports"]) > 8:
            ports_str += f"+{len(r['ports'])-8}"
        vulns = r["vulns"]
        cve_count = len(vulns)
        vuln_str  = "  ".join(vulns[:3])
        if cve_count > 3:
            vuln_str += f" +{cve_count-3}"
        if vulns:
            vuln_count += 1
        style = "on #1a0000" if vulns else ""
        t.add_row(
            r["target"],
            r["ip"],
            r.get("country",""),
            r.get("org",""),
            ports_str or "-",
            str(cve_count) if cve_count else "-",
            f"[bold red]{vuln_str}[/]" if vulns else "[dim]-[/]",
            style=style,
        )
    console.print(t)
    console.print()
    console.print(f"  [{C['accent']}]Scanned:[/]   {len(results)} targets")
    console.print(f"  [{C['danger']}]Vulnerable:[/] {vuln_count} targets with known CVEs")
    console.print(f"  [{C['muted']}]Data source: Shodan InternetDB (public, passive)[/]")
    console.print()
    if Confirm.ask(f"  [{C['info']}]?[/] Export results to JSON?", default=False):
        fname = f"ghost_mass_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname,"w") as f:
            json.dump(results, f, indent=2)
        console.print(f"  [{C['accent']}]Saved → {fname}[/]")
    _pause()
def deep_scan(target: str):
    os.system("clear" if os.name != "nt" else "cls")
    console.print(Align.center(MINI_BANNER))
    console.print()
    ip, domain = resolve(target)
    if not ip:
        console.print(f"  [{C['danger']}]Could not resolve: {target}[/]")
        _pause()
        return
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    console.print(Panel(
        f"[bold {C['accent']}]TARGET[/]   {target}\n"
        f"[bold {C['accent']}]IP[/]       {ip}\n"
        f"[bold {C['accent']}]DOMAIN[/]   {domain or '—'}\n"
        f"[bold {C['accent']}]TIME[/]     {ts}",
        title="[bold]DEEP SCAN[/]",
        border_style=C['accent'],
    ))
    spinner_task("Geolocating",           mod_geo,         ip);   time.sleep(0.1)
    spinner_task("Querying Shodan IDB",   mod_shodan,      ip);   time.sleep(0.1)
    spinner_task("Network WHOIS",         mod_ipwho,       ip);   time.sleep(0.1)
    spinner_task("BGPView",               mod_bgpview,     ip);   time.sleep(0.1)
    spinner_task("Reverse IP",            mod_reverse_ip,  ip);   time.sleep(0.1)
    deep_open_ports = mod_port_scan_auto(ip)
    tls_host = domain if domain and domain != ip else ip
    for p, _b in deep_open_ports:
        if p in (443, 8443, 993, 995):
            try:
                mod_tls(tls_host, p, probe_versions=False)
            except Exception as e:
                console.print(f"  [{C['warn']}]TLS probe on :{p} failed: {e}[/]")
    if domain and domain != ip:
        spinner_task("DNS Records",       mod_dns,         domain); time.sleep(0.1)
        mod_subdomains(domain); time.sleep(0.1)
        spinner_task("Host records",      mod_host_records,domain); time.sleep(0.1)
        spinner_task("HTTP headers",      mod_http_headers,domain); time.sleep(0.1)
        spinner_task("WHOIS",             mod_whois,       domain)
    elif domain is None:
        spinner_task("Reverse DNS",       mod_http_headers, ip)
    mod_http_probe([tls_host]); time.sleep(0.1)
    try:
        mod_favicon(tls_host)
    except Exception as e:
        console.print(f"  [{C['warn']}]Favicon probe failed: {e}[/]")
    time.sleep(0.1)
    try:
        mod_exposures(tls_host)
    except Exception as e:
        console.print(f"  [{C['warn']}]Exposure scan failed: {e}[/]")
    section_header("SCAN COMPLETE", "*")
    console.print(f"  [{C['accent']}]Finished: {datetime.utcnow().strftime('%H:%M:%S UTC')}[/]")
    _pause()
def quick_lookup(target: str):
    os.system("clear" if os.name != "nt" else "cls")
    console.print(Align.center(MINI_BANNER))
    console.print()
    ip, domain = resolve(target)
    if not ip:
        console.print(f"  [{C['danger']}]Cannot resolve: {target}[/]")
        _pause()
        return
    mod_geo(ip)
    mod_shodan(ip)
    mod_ipwho(ip)
    mod_bgpview(ip)
    _pause()
def subdomain_hunt(domain: str):
    os.system("clear" if os.name != "nt" else "cls")
    console.print(Align.center(MINI_BANNER))
    console.print()
    mod_subdomains(domain)
    spinner_task("Fetching host records",     mod_host_records, domain)
    spinner_task("DNS Records",               mod_dns, domain)
    _pause()
def _pause():
    console.print()
    Prompt.ask(f"  [{C['muted']}]press ENTER to continue[/]", default="")
def _input_target(label: str = "Enter target (IP or domain)") -> str:
    return Prompt.ask(f"  [{C['accent']}]>>[/] {label}").strip()
def _input_targets_list() -> list:
    console.print(f"  [{C['info']}]Enter targets one per line (blank line to finish):[/]")
    targets = []
    while True:
        line = Prompt.ask(f"  [{C['accent']}]  +[/]", default="").strip()
        if not line:
            break
        targets.append(line)
    return targets
def _or_load_file(targets: list) -> list:
    if Confirm.ask(f"  [{C['info']}]?[/] Load targets from a file?", default=False):
        path = Prompt.ask(f"  [{C['accent']}]>>[/] File path").strip()
        try:
            with open(path) as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception as e:
            console.print(f"  [{C['danger']}]Error: {e}[/]")
    return targets
def _show_dorks():
    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style=f"bold {C['accent']}", border_style=C['muted'], padding=(0,2))
    t.add_column("Category", style=C['cyan'])
    t.add_column("Filters & Syntax", style=C['white'])
    t.add_row("HTTP / Web", "http.title, http.server, http.body, http.status, http.favicon.hash, tech")
    t.add_row("SSL / TLS", "ssl, ssl.cert.subject.cn, ssl.cert.issuer.org, ssl.cert.expired:true")
    t.add_row("Domain / Net", "hostname, domain, subdomain, ip, port")
    t.add_row("Geo / Org", "org, asn, isp, country")
    t.add_row("Compound / OR", "AND implicit. Comma/pipe for OR (e.g. port:80,443 country:US|CA)")
    t.add_row("Wildcards", "Use * for wildcards in domains/ssl (e.g. ssl:\"*.example.com\")")
    console.print(Panel(t, title="[bold]Dork Filter Cheat Sheet[/]", border_style=C['accent']))
    console.print(f"  [dim]Example: http.title:\"Dashboard\" port:8080 country:US[/]")
def advanced_search():
    os.system("clear" if os.name != "nt" else "cls")
    console.print(Align.center(MINI_BANNER))
    console.print()
    console.print("  Type 'help' for Dork Filter Cheat Sheet")
    query = Prompt.ask(f"  [{C['accent']}]>>[/] Enter advanced query").strip()
    if query.lower() == "help":
        _show_dorks()
        query = Prompt.ask(f"  [{C['accent']}]>>[/] Enter advanced query").strip()
    if not query:
        return
    for wrong, right in {"http:title:": "http.title:", "http:server:": "http.server:", "http:body:": "http.body:", "http:status:": "http.status:", "ssl:cert:": "ssl.cert."}.items():
        query = query.replace(wrong, right)
    filters = {}
    for m in re.finditer(r'([a-zA-Z0-9_.-]+):("([^"]+)"|([^\s]+))', query):
        val = m.group(3) if m.group(3) else m.group(4)
        filters[m.group(1)] = [v.strip() for v in re.split(r'[,|]', val)]
    if not filters:
        console.print(f"  [{C['warn']}]Invalid syntax. Ensure you use colons (e.g., http.title:\"Dashboard\")[/]")
        _pause()
        return
    valid_keys = {"http.title", "http.server", "http.status", "http.body", "http.favicon.hash", "tech", "ssl", "ssl.cert.issuer.cn", "ssl.cert.issuer.org", "ssl.cert.subject.cn", "ssl.cert.expired", "hostname", "domain", "subdomain", "ip", "port", "country", "org", "asn", "isp"}
    unknown = [k for k in filters if k not in valid_keys]
    if unknown:
        console.print(f"  [{C['warn']}]Unknown filter(s): {', '.join(unknown)}. Check syntax (use '.' like http.title)[/]")
        _pause()
        return
    primary_filters = {"http.title", "http.server", "http.status", "http.body", "http.favicon.hash", "tech", "ssl", "ssl.cert.issuer.cn", "ssl.cert.subject.cn", "hostname", "domain", "subdomain", "ip"}
    if not any(k in filters for k in primary_filters):
        console.print(f"  [{C['warn']}]Primary filter required (e.g., http.title, ip, domain). 'port' and 'country' are post-filters only.[/]")
        _pause()
        return
    urlscan_map = {"http.title": "page.title", "http.server": "page.server", "tech": "page.server", "http.status": "page.statusCode", "http.body": "page.text", "http.favicon.hash": "hash"}
    ips = set()
    diag = []
    with Progress(SpinnerColumn(spinner_name="dots2", style=f"bold {C['accent']}"),TextColumn(f"[{C['info']}]Searching...[/]"),console=console,transient=True) as prog:
        task = prog.add_task("Search", total=None)
        if any(k in urlscan_map for k in filters):
            q_parts = []
            for k in filters:
                if k in urlscan_map:
                    for v in filters[k]:
                        q_parts.append(f'{urlscan_map[k]}:"{v}"')
            q_str = " AND ".join(q_parts)
            try:
                data = safe_get("https://urlscan.io/api/v1/search/", params={"q": q_str})
                if isinstance(data, dict) and "_error" not in data:
                    before = len(ips)
                    for r in data.get("results", []):
                        val = r.get("page", {}).get("ip")
                        if val: ips.add(val)
                    diag.append(f"urlscan ({q_str}) → {len(ips)-before} IPs from {len(data.get('results', []))} hits")
                else:
                    err = data.get("_error", "unknown") if isinstance(data, dict) else str(type(data).__name__)
                    diag.append(f"urlscan ({q_str}) → ERROR: {err}")
            except Exception as e:
                diag.append(f"urlscan ({q_str}) → EXCEPTION: {e}")
        crtsh_keys = {"ssl", "hostname", "domain", "subdomain", "ssl.cert.issuer.cn", "ssl.cert.issuer.org", "ssl.cert.subject.cn"}
        for k in crtsh_keys:
            if k in filters:
                for v in filters[k]:
                    try:
                        data = safe_get("https://crt.sh/", params={"q": f"%{v.replace('*', '%')}%", "output": "json"})
                        if isinstance(data, list):
                            before = len(ips)
                            seen_hosts = 0
                            for entry in data:
                                if "not_after" in entry:
                                    try:
                                        if datetime.strptime(entry["not_after"], "%Y-%m-%dT%H:%M:%S") < datetime.now():
                                            continue
                                    except: pass
                                for n in entry.get("name_value","").splitlines():
                                    seen_hosts += 1
                                    ip, _ = resolve(n.strip().lstrip("*."))
                                    if ip: ips.add(ip)
                            diag.append(f"crt.sh ({k}:{v}) → {len(ips)-before} IPs resolved from {seen_hosts} names")
                        else:
                            err = data.get("_error", "unknown") if isinstance(data, dict) else str(type(data).__name__)
                            diag.append(f"crt.sh ({k}:{v}) → ERROR: {err}")
                    except Exception as e:
                        diag.append(f"crt.sh ({k}:{v}) → EXCEPTION: {e}")
        if "ip" in filters:
            for ip_val in filters["ip"]:
                try:
                    for ip in ipaddress.ip_network(ip_val, strict=False):
                        ips.add(str(ip))
                except Exception: pass
    ips = list(ips)[:100]
    if not ips:
        console.print(f"  [{C['warn']}]No IPs gathered.[/]")
        for line in diag:
            console.print(f"  [{C['muted']}]• {line}[/]")
        if not diag:
            console.print(f"  [{C['muted']}]• No source was queried — primary filters matched no known backend.[/]")
        _pause()
        return
    results = []
    cached_data = {}
    with Progress(SpinnerColumn(spinner_name="line", style=f"bold {C['accent']}"),TextColumn(f"[{C['info']}]{{task.description}}[/]"),BarColumn(bar_width=40, style=C['muted'], complete_style=C['accent']),TextColumn("[progress.percentage]{task.percentage:>3.0f}%  {task.completed}/{task.total}"),console=console) as prog:
        task = prog.add_task("Enriching", total=len(ips))
        def fetch_ip(ip):
            return ip, safe_get(f"http://ip-api.com/json/{ip}", params={"fields": "countryCode,isp,org,as"}, timeout=6), safe_get(f"https://internetdb.shodan.io/{ip}", timeout=6)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                futures = {ex.submit(fetch_ip, ip): ip for ip in ips}
                for future in concurrent.futures.as_completed(futures):
                    ip = futures[future]
                    try:
                        ip, geo, shod = future.result()
                        if isinstance(geo, dict) and isinstance(shod, dict):
                            cached_data[ip] = {"geo": geo, "shod": shod}
                            match = True
                            if "port" in filters:
                                if not any(int(p) in shod.get("ports", []) for p in filters["port"]): match = False
                            if "country" in filters:
                                if not any(c.lower() == str(geo.get("countryCode", "")).lower() for c in filters["country"]): match = False
                            if "org" in filters:
                                if not any(o.lower() in str(geo.get("org", "")).lower() for o in filters["org"]): match = False
                            if "asn" in filters:
                                if not any(a.lower() in str(geo.get("as", "")).lower() for a in filters["asn"]): match = False
                            if "isp" in filters:
                                if not any(i.lower() in str(geo.get("isp", "")).lower() for i in filters["isp"]): match = False
                            if match:
                                results.append({"ip": ip, "country": geo.get("countryCode", "??"), "org": (geo.get("org") or geo.get("isp", ""))[:30], "ports": shod.get("ports", []), "vulns": shod.get("vulns", [])})
                    except Exception: pass
                    prog.update(task, description=f"[{C['info']}]{ip:<15}[/]")
                    prog.advance(task)
        except KeyboardInterrupt:
            console.print(f"\n  [{C['warn']}]Enrichment interrupted! Showing partial results...[/]")
            time.sleep(1)
    if not results and ips:
        console.print(f"  [{C['warn']}]0 results matched all filters. Auto-relaxing post-filters...[/]")
        post_filters = ["port", "country", "org", "asn", "isp"]
        for pf in post_filters:
            if pf in filters:
                count = 0
                for ip, data in cached_data.items():
                    geo, shod = data["geo"], data["shod"]
                    match = True
                    for k in filters:
                        if k == pf or k not in post_filters: continue
                        if k == "port" and not any(int(p) in shod.get("ports", []) for p in filters["port"]): match = False
                        if k == "country" and not any(c.lower() == str(geo.get("countryCode", "")).lower() for c in filters["country"]): match = False
                        if k == "org" and not any(o.lower() in str(geo.get("org", "")).lower() for o in filters["org"]): match = False
                        if k == "asn" and not any(a.lower() in str(geo.get("as", "")).lower() for a in filters["asn"]): match = False
                        if k == "isp" and not any(i.lower() in str(geo.get("isp", "")).lower() for i in filters["isp"]): match = False
                    if match: count += 1
                if count > 0:
                    console.print(f"  [{C['info']}]Suggestion: Found {count} results by dropping '{pf}' filter.[/]")
    _cvss_cache = _cache_load()
    def _is_high(c):
        entry = _cvss_cache.get(c)
        if not entry:
            return False
        return str(entry.get("severity", "")).lower() in ("high", "critical")
    results.sort(key=lambda x: (-len(x.get("vulns", [])), -sum(1 for c in x.get("vulns", []) if _is_high(c)), -sum(1 for p in x.get("ports", []) if p in (3306, 27017, 6379, 5432)), str(x.get("country") or "")))
    console.print()
    console.rule(f"[bold {C['accent']}]>> ADVANCED SEARCH RESULTS[/]", style=C['muted'])
    console.print()
    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style=f"bold {C['accent']}", border_style=C['muted'], padding=(0,1), expand=True)
    t.add_column("IP", style=C['white'], width=16)
    t.add_column("CC", style=C['purple'], width=5)
    t.add_column("ORG", style=C['muted'], max_width=28)
    t.add_column("PORTS", style=C['info'], max_width=22)
    t.add_column("CVEs", style=C['danger'], width=6)
    for r in results:
        ports_str = ",".join(str(p) for p in sorted(r["ports"])[:8])
        if len(r["ports"]) > 8: ports_str += f"+{len(r['ports'])-8}"
        cve_count = len(r["vulns"])
        t.add_row(r["ip"], r.get("country",""), r.get("org",""), ports_str or "-", str(cve_count) if cve_count else "-")
    console.print(t)
    console.print()
    if Confirm.ask(f"  [{C['info']}]?[/] Export results to JSON?", default=False):
        fname = f"ghost_adv_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname,"w") as f: json.dump(results, f, indent=2)
        console.print(f"  [{C['accent']}]Saved → {fname}[/]")
    _pause()
# ============================================================================
#  POWER MODULES (v3.0)
#  Multi-source passive DNS · httpx-lite probing · tech fingerprinting ·
#  favicon pivoting · wayback harvesting · ASN expansion · exposure checks ·
#  full report export.  Keyless, cross-platform, stdlib + requests + rich.
# ============================================================================
import base64
from urllib.parse import urlparse, urljoin
from rich.markup import escape as mesc

_HOST_MIN_INTERVAL.update({
    "otx.alienvault.com":  0.5,
    "jldc.me":             1.0,
    "api.certspotter.com": 2.0,
    "web.archive.org":     1.0,
    "rapiddns.io":         1.5,
    "stat.ripe.net":       0.2,
})

# ---------------------------------------------------------------------------
#  MurmurHash3 (x86_32) — pure Python, matches mmh3.hash() used by Shodan
# ---------------------------------------------------------------------------
def _mmh3_32(data, seed=0):
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed & 0xffffffff
    rounded_end = length & 0xfffffffc
    for i in range(0, rounded_end, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
             ((data[i + 2] & 0xff) << 16) | ((data[i + 3] & 0xff) << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2] & 0xff) << 16
    if tail >= 2:
        k1 |= (data[rounded_end + 1] & 0xff) << 8
    if tail >= 1:
        k1 |= (data[rounded_end] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    if h1 & 0x80000000:
        h1 = -((h1 ^ 0xffffffff) + 1)
    return h1

def favicon_hash(fav_bytes):
    try:
        return _mmh3_32(base64.encodebytes(fav_bytes))
    except Exception:
        return None

def _raw_get(url, timeout=TIMEOUT, allow_redirects=True):
    host = _host_of(url)
    _throttle(host)
    try:
        return SESSION.get(url, timeout=timeout, allow_redirects=allow_redirects)
    except Exception:
        return None

# ---------------------------------------------------------------------------
#  Passive subdomain sources  (all keyless)
# ---------------------------------------------------------------------------
def _src_crtsh(domain):
    out = set()
    data = safe_get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=20, max_retries=2)
    if isinstance(data, list):
        for e in data:
            for n in str(e.get("name_value", "")).splitlines():
                n = n.strip().lstrip("*.").lower()
                if n.endswith("." + domain) and "@" not in n:
                    out.add(n)
    return out

def _src_otx(domain):
    out = set()
    data = safe_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=12, max_retries=2)
    if isinstance(data, dict):
        for rec in data.get("passive_dns", []) or []:
            n = str(rec.get("hostname", "")).strip().lower().rstrip(".")
            if n.endswith("." + domain):
                out.add(n)
    return out

def _src_anubis(domain):
    out = set()
    data = safe_get(f"https://jldc.me/anubis/subdomains/{domain}")
    if isinstance(data, list):
        for n in data:
            n = str(n).strip().lower()
            if n.endswith("." + domain):
                out.add(n)
    return out

def _src_certspotter(domain):
    out = set()
    data = safe_get("https://api.certspotter.com/v1/issuances",
                    params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"}, timeout=15, max_retries=2)
    if isinstance(data, list):
        for e in data:
            for n in e.get("dns_names", []) or []:
                n = str(n).strip().lstrip("*.").lower()
                if n.endswith("." + domain):
                    out.add(n)
    return out

def _src_wayback(domain):
    out = set()
    data = safe_get("http://web.archive.org/cdx/search/cdx",
                    params={"url": f"*.{domain}/*", "output": "json",
                            "fields": "original", "collapse": "urlkey", "limit": "15000"}, timeout=25)
    if isinstance(data, list) and data:
        for row in data[1:]:
            u = row[0] if isinstance(row, list) and row else None
            if not u:
                continue
            try:
                h = (urlparse(u).hostname or "").lower()
            except Exception:
                h = ""
            if h.endswith("." + domain):
                out.add(h)
    return out

def _src_rapiddns(domain):
    out = set()
    text = safe_get(f"https://rapiddns.io/subdomain/{domain}", params={"full": "1"}, json_resp=False, timeout=15, max_retries=2)
    if isinstance(text, str):
        for m in re.finditer(r"([a-zA-Z0-9_][a-zA-Z0-9_.-]*\." + re.escape(domain) + r")", text):
            out.add(m.group(1).strip().lower())
    return out

def _src_hackertarget(domain):
    out = set()
    text = safe_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", json_resp=False)
    if isinstance(text, str) and "," in text and "error" not in text.lower():
        for line in text.splitlines():
            n = line.split(",")[0].strip().lower()
            if n.endswith("." + domain):
                out.add(n)
    return out

# NOTE: wayback (archive.org CDX) is intentionally NOT a passive subdomain
# source — the *.domain/* CDX query routinely takes 90s+ and often times out,
# which would gate the whole parallel gather on its slowest member. It lives on
# as its own dedicated feature (mod_wayback) with a lighter host-scoped query.
PASSIVE_SOURCES = {
    "crt.sh":       _src_crtsh,
    "otx":          _src_otx,
    "anubis":       _src_anubis,
    "certspotter":  _src_certspotter,
    "rapiddns":     _src_rapiddns,
    "hackertarget": _src_hackertarget,
}

def gather_passive_subdomains(domain):
    """Query every passive source in parallel. Returns (host->set(sources), source->count)."""
    results = {}
    counts = {}
    def run(item):
        name, fn = item
        try:
            return name, fn(domain)
        except Exception:
            return name, set()
    items = list(PASSIVE_SOURCES.items())
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(items)) as ex:
        for name, subs in ex.map(run, items):
            counts[name] = len(subs)
            for h in subs:
                results.setdefault(h, set()).add(name)
    return results, counts

# ---------------------------------------------------------------------------
#  httpx-lite: live HTTP probing + tech fingerprinting
# ---------------------------------------------------------------------------
_TECH_HEADER = [
    ("server", r"nginx", "nginx"), ("server", r"apache", "Apache"),
    ("server", r"microsoft-iis", "IIS"), ("server", r"cloudflare", "Cloudflare"),
    ("server", r"litespeed", "LiteSpeed"), ("server", r"openresty", "OpenResty"),
    ("server", r"gws", "Google-Web-Server"), ("server", r"cowboy", "Erlang/Cowboy"),
    ("x-powered-by", r"php", "PHP"), ("x-powered-by", r"asp\.net", "ASP.NET"),
    ("x-powered-by", r"express", "Express"), ("x-powered-by", r"next\.js", "Next.js"),
    ("x-aspnet-version", r".", "ASP.NET"), ("x-drupal-cache", r".", "Drupal"),
    ("x-generator", r"drupal", "Drupal"), ("x-generator", r"wordpress", "WordPress"),
    ("x-shopify-stage", r".", "Shopify"), ("via", r"varnish", "Varnish"),
    ("x-served-by", r"cache", "Fastly/Varnish"), ("cf-ray", r".", "Cloudflare"),
]
_TECH_COOKIE = [
    (r"phpsessid", "PHP"), (r"asp\.net_sessionid", "ASP.NET"), (r"jsessionid", "Java"),
    (r"laravel_session", "Laravel"), (r"ci_session", "CodeIgniter"),
    (r"wordpress_|wp-settings", "WordPress"), (r"_shopify", "Shopify"),
    (r"django", "Django"), (r"connect\.sid", "Express"),
]
_TECH_BODY = [
    (r"wp-content|wp-includes", "WordPress"), (r"/sites/(all|default)/|Drupal\.settings", "Drupal"),
    (r'content="Joomla', "Joomla"), (r"__NEXT_DATA__|/_next/", "Next.js"),
    (r"ng-version|angular\.js", "Angular"), (r"data-reactroot|react-dom", "React"),
    (r"csrfmiddlewaretoken|__admin_media_prefix__", "Django"),
    (r"laravel_session|Laravel", "Laravel"), (r"cdn\.shopify\.com|Shopify\.", "Shopify"),
    (r"/wp-json/|wp-emoji", "WordPress"), (r"Magento|/static/version\d", "Magento"),
    (r"vue(\.min)?\.js|__vue__", "Vue.js"), (r"jquery(\.min)?\.js", "jQuery"),
    (r"bootstrap(\.min)?\.(js|css)", "Bootstrap"), (r"gatsby", "Gatsby"),
]

def fingerprint_tech(resp):
    techs = set()
    headers = {k.lower(): str(v) for k, v in resp.headers.items()}
    for hname, pat, label in _TECH_HEADER:
        v = headers.get(hname)
        if v and re.search(pat, v, re.IGNORECASE):
            techs.add(label)
    cookies = headers.get("set-cookie", "")
    for pat, label in _TECH_COOKIE:
        if re.search(pat, cookies, re.IGNORECASE):
            techs.add(label)
    try:
        body = resp.text[:250000]
    except Exception:
        body = ""
    for pat, label in _TECH_BODY:
        if re.search(pat, body, re.IGNORECASE):
            techs.add(label)
    return sorted(techs)

def _title_of(body):
    if not body:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""

def http_probe_one(host, timeout=6):
    host = host.strip()
    candidates = [host] if host.startswith(("http://", "https://")) else [f"https://{host}", f"http://{host}"]
    for url in candidates:
        r = _raw_get(url, timeout=timeout)
        if r is None:
            continue
        try:
            body = r.text
        except Exception:
            body = ""
        return {
            "host": host, "url": str(r.url), "status": r.status_code,
            "server": r.headers.get("Server", "") or "",
            "title": _title_of(body), "length": len(r.content or b""),
            "tech": fingerprint_tech(r),
            "redirected": str(r.url).rstrip("/") != url.rstrip("/"),
        }
    return None

def http_probe_many(hosts, workers=25):
    uniq, seen = [], set()
    for h in hosts:
        h = h.strip()
        if h and h not in seen:
            seen.add(h); uniq.append(h)
    results = []
    if not uniq:
        return results
    with Progress(
        SpinnerColumn(spinner_name="dots2", style=f"bold {C['accent']}"),
        TextColumn(f"[{C['info']}]Probing {len(uniq)} hosts[/]"),
        BarColumn(bar_width=30, style=C['muted'], complete_style=C['accent']),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(), console=console, transient=True,
    ) as prog:
        task = prog.add_task("", total=len(uniq))
        def work(h):
            try:
                return http_probe_one(h)
            finally:
                prog.advance(task)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            try:
                for res in ex.map(work, uniq):
                    if res:
                        results.append(res)
            except KeyboardInterrupt:
                console.print(f"\n  [{C['warn']}]Probe interrupted, showing partial results.[/]")
    results.sort(key=lambda r: (r["status"], r["host"]))
    return results

def _status_style(code):
    if 200 <= code < 300: return C['accent']
    if 300 <= code < 400: return C['info']
    if 400 <= code < 500: return C['warn']
    return C['danger']

def _render_probe_table(results):
    if not results:
        console.print(f"  [{C['warn']}]No live HTTP services found[/]")
        return
    t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C['accent']}", padding=(0, 1), expand=True)
    t.add_column("URL", style=C['cyan'], max_width=40)
    t.add_column("ST", width=4)
    t.add_column("SERVER", style=C['purple'], max_width=18)
    t.add_column("TECH", style=C['white'], max_width=26)
    t.add_column("TITLE", style=C['muted'], max_width=38)
    for r in results:
        t.add_row(
            mesc(r["url"][:40]),
            f"[{_status_style(r['status'])}]{r['status']}[/]",
            mesc((r["server"] or "-")[:18]),
            mesc(", ".join(r["tech"])[:26] or "-"),
            mesc((r["title"] or "-")[:38]),
        )
    console.print(Padding(t, (0, 2)))

def mod_http_probe(hosts):
    total = len({h.strip() for h in hosts if h.strip()})
    section_header(f"HTTP PROBE  (httpx-lite)  ({total} host(s))", ">")
    results = http_probe_many(hosts)
    _render_probe_table(results)
    console.print(f"\n  [dim]Live: {len(results)}/{total}[/]")
    return results

# ---------------------------------------------------------------------------
#  Favicon hash (Shodan pivot)
# ---------------------------------------------------------------------------
def get_favicon_hash(target):
    base = target if target.startswith(("http://", "https://")) else "https://" + target
    fav_url = urljoin(base, "/favicon.ico")
    r = _raw_get(base)
    if r is not None:
        try:
            m = re.search(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*>', r.text, re.IGNORECASE)
            if m:
                hm = re.search(r'href=["\']([^"\']+)["\']', m.group(0), re.IGNORECASE)
                if hm:
                    fav_url = urljoin(str(r.url), hm.group(1))
        except Exception:
            pass
    fr = _raw_get(fav_url)
    if fr is None or fr.status_code != 200 or not fr.content:
        return None, fav_url
    return favicon_hash(fr.content), fav_url

def mod_favicon(target):
    section_header("FAVICON HASH  (Shodan pivot)", ">")
    h, url = get_favicon_hash(target)
    if h is None:
        console.print(f"  [dim]No favicon retrievable at {mesc(url)}[/]")
        return None
    print_kv("Favicon URL", url, C['cyan'])
    print_kv("mmh3 hash", str(h), C['gold'])
    console.print(f"  [dim]Shodan dork:[/] [bold {C['accent']}]http.favicon.hash:{h}[/]")
    console.print(f"  [dim]Pivots to every internet host serving this same icon (often related infra).[/]")
    return h

# ---------------------------------------------------------------------------
#  Wayback URL harvesting  (gau/waybackurls-lite)
# ---------------------------------------------------------------------------
def mod_wayback(domain, interactive=True):
    section_header("WAYBACK URLS  (archive.org CDX)", ">")
    target = urlparse(domain).hostname if domain.startswith(("http://", "https://")) else domain
    target = (target or domain).strip()
    console.print(f"  [dim]Querying archive.org (can be slow)...[/]")
    data = safe_get("http://web.archive.org/cdx/search/cdx",
                    params={"url": f"{target}/*", "output": "json",
                            "fields": "original", "collapse": "urlkey", "limit": "10000"},
                    timeout=15, max_retries=1)
    if isinstance(data, dict):
        console.print("  [dim]archive.org unreachable or timed out (CDX is often slow/blocked).[/]")
        return []
    if not isinstance(data, list) or len(data) < 2:
        console.print("  [dim]No archived URLs found[/]")
        return []
    urls, seen = [], set()
    for row in data[1:]:
        u = row[0] if isinstance(row, list) and row else None
        if u and u not in seen:
            seen.add(u); urls.append(u)
    params, exts = set(), {}
    for u in urls:
        pu = urlparse(u)
        for kv in pu.query.split("&"):
            k = kv.split("=")[0].strip()
            if k:
                params.add(k)
        last = pu.path.rsplit("/", 1)[-1]
        if "." in last:
            ext = last.rsplit(".", 1)[-1].lower()
            if ext and len(ext) <= 6 and ext.isalnum():
                exts[ext] = exts.get(ext, 0) + 1
    console.print(f"  [{C['accent']}]{len(urls)}[/] unique archived URLs")
    notable = {k: v for k, v in exts.items()
               if k in ("js", "json", "php", "asp", "aspx", "jsp", "xml", "env", "bak",
                        "sql", "zip", "config", "yml", "yaml", "txt", "log", "old", "swp")}
    if notable:
        print_kv("Notable file types", [f"{k} ({v})" for k, v in sorted(notable.items(), key=lambda x: -x[1])], C['warn'])
    if params:
        plist = sorted(params)
        print_kv(f"URL parameters ({len(plist)})", plist[:40], C['cyan'])
    console.print(f"\n  [dim]Sample:[/]")
    for u in urls[:15]:
        console.print(f"    [{C['muted']}]{mesc(u[:110])}[/]")
    if len(urls) > 15:
        console.print(f"    [dim]... and {len(urls) - 15} more[/]")
    if interactive and Confirm.ask(f"  [{C['info']}]?[/] Export all {len(urls)} URLs to file?", default=False):
        fname = f"ghost_wayback_{re.sub(r'[^A-Za-z0-9_.-]', '_', target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write("\n".join(urls))
            console.print(f"  [{C['accent']}]Saved → {fname}[/]")
        except Exception as e:
            console.print(f"  [{C['danger']}]Save failed: {e}[/]")
    return urls

# ---------------------------------------------------------------------------
#  ASN / netblock expansion  (BGPView)
# ---------------------------------------------------------------------------
def _ripe(call, resource, timeout=12):
    data = safe_get(f"https://stat.ripe.net/data/{call}/data.json",
                    params={"resource": resource}, timeout=timeout, max_retries=2)
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return data["data"]
    return None

def mod_asn(query):
    section_header("ASN / NETBLOCK EXPANSION  (RIPEstat)", ">")
    q = query.strip()
    m = re.match(r"^(?:AS)?(\d+)$", q, re.IGNORECASE)
    asn = int(m.group(1)) if m else None
    if asn is None:
        d = _ripe("searchcomplete", q)
        suggestions = []
        for cat in (d or {}).get("categories", []):
            if cat.get("category") == "ASNs":
                suggestions = cat.get("suggestions", []) or []
        if suggestions:
            console.print(f"  [dim]Matched ASNs for '{mesc(q)}':[/]")
            for sug in suggestions[:10]:
                console.print(f"    [{C['purple']}]{mesc(str(sug.get('value')))}[/] "
                              f"[dim]{mesc(str(sug.get('description', '')))}[/]")
            m2 = re.match(r"^AS?(\d+)$", str(suggestions[0].get("value", "")), re.IGNORECASE)
            asn = int(m2.group(1)) if m2 else None
        if asn is None:
            console.print(f"  [{C['warn']}]No ASN found for '{mesc(q)}'. Try 'AS15169' or a more specific org name.[/]")
            return []
    ov = _ripe("as-overview", f"AS{asn}")
    holder = (ov or {}).get("holder", "") or ""
    console.print(f"  [dim]AS{asn}[/] [{C['cyan']}]{mesc(holder)}[/] [dim]— fetching announced prefixes...[/]")
    d = _ripe("announced-prefixes", f"AS{asn}", timeout=20)
    prefixes = (d or {}).get("prefixes", []) or []
    if not prefixes:
        console.print("  [dim]No prefix data[/]")
        return []
    v4 = [p["prefix"] for p in prefixes if p.get("prefix") and ":" not in p["prefix"]]
    v6 = [p["prefix"] for p in prefixes if p.get("prefix") and ":" in p["prefix"]]
    def _hosts(pref):
        try:
            return ipaddress.ip_network(pref, strict=False).num_addresses
        except Exception:
            return 0
    total_ips = sum(_hosts(p) for p in v4)
    t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C['accent']}", padding=(0, 2))
    t.add_column("IPv4 PREFIX", style=C['cyan'])
    t.add_column("HOSTS", style=C['white'], justify="right")
    for pref in v4[:80]:
        t.add_row(pref, f"{_hosts(pref):,}")
    console.print(Padding(t, (0, 2)))
    console.print(f"\n  [dim]AS{asn} {mesc(holder)}: {len(v4)} IPv4 prefixes "
                  f"({total_ips:,} addresses), {len(v6)} IPv6 prefixes[/]")
    if len(v4) > 80:
        console.print(f"  [dim]... {len(v4) - 80} more IPv4 prefixes (full set in return value)[/]")
    return v4 + v6

# ---------------------------------------------------------------------------
#  Exposure / misconfig scan  (nuclei-lite)
# ---------------------------------------------------------------------------
_EXPOSURES = [
    ("/.git/config",              "Exposed .git repository",     r"\[core\]|repositoryformatversion"),
    ("/.env",                     "Exposed .env secrets",        r"(APP_KEY|DB_PASSWORD|SECRET|AWS_ACCESS|API_KEY)\s*="),
    ("/.aws/credentials",         "Exposed AWS credentials",     r"aws_access_key_id"),
    ("/config.php.bak",           "Backup config file",          r"(password|db_|define\()"),
    ("/server-status",            "Apache mod_status exposed",   r"Apache Server Status"),
    ("/actuator/env",             "Spring Boot actuator exposed", r'"(propertySources|activeProfiles)"'),
    ("/phpinfo.php",              "phpinfo() exposed",           r"phpinfo\(\)|<title>PHP "),
    ("/.well-known/security.txt", "security.txt present",        r"(?i)contact\s*:"),
    ("/wp-login.php",             "WordPress login exposed",     r"(?i)wordpress|wp-submit"),
    ("/.svn/entries",             "Exposed .svn directory",      r"^\d+[\r\n]|svn:"),
    ("/backup.sql",               "Exposed SQL backup",          r"(INSERT INTO|CREATE TABLE)"),
    ("/.DS_Store",                "Exposed .DS_Store",           r"Bud1|\x00\x00\x00"),
]
_SEC_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy",   "CSP"),
    ("x-frame-options",           "X-Frame-Options"),
    ("x-content-type-options",    "X-Content-Type-Options"),
    ("referrer-policy",           "Referrer-Policy"),
    ("permissions-policy",        "Permissions-Policy"),
]

def mod_exposures(target):
    section_header("EXPOSURE / MISCONFIG SCAN  (nuclei-lite)", ">")
    base = target.strip()
    if not base.startswith(("http://", "https://")):
        probe = http_probe_one(base)
        base = probe["url"] if probe else "https://" + base
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    console.print(f"  [dim]Target base: {mesc(root)}[/]")
    r = _raw_get(root)
    if r is not None:
        hl = {k.lower(): v for k, v in r.headers.items()}
        present = [label for key, label in _SEC_HEADERS if key in hl]
        missing = [label for key, label in _SEC_HEADERS if key not in hl]
        print_kv("Security headers", present or ["(none)"], C['accent'])
        if missing:
            print_kv("Missing headers", missing, C['warn'])
        score = int(100 * len(present) / len(_SEC_HEADERS))
        col = C['danger'] if score < 34 else (C['warn'] if score < 67 else C['accent'])
        print_kv("Header hygiene", f"{score}%", col)
        if hl.get("server"):
            print_kv("Server banner leak", hl["server"], C['warn'])
        if hl.get("x-powered-by"):
            print_kv("X-Powered-By leak", hl["x-powered-by"], C['warn'])
    console.print(f"\n  [dim]Probing {len(_EXPOSURES)} sensitive paths...[/]")
    findings = []
    def check(item):
        path, label, pat = item
        try:
            rr = _raw_get(root + path, allow_redirects=False)
            if rr is not None and rr.status_code == 200 and rr.text and re.search(pat, rr.text[:8000]):
                return (path, label, rr.status_code, len(rr.content))
        except Exception:
            return None
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for res in ex.map(check, _EXPOSURES):
            if res:
                findings.append(res)
    if findings:
        console.print(f"  [bold {C['danger']}]>> {len(findings)} EXPOSURE(S) FOUND <<[/]")
        for path, label, code, ln in findings:
            console.print(f"    [{C['danger']}](!)[/] [{C['white']}]{mesc(label)}[/] "
                          f"[dim]{mesc(root + path)} ({code}, {ln}B)[/]")
    else:
        console.print(f"  [{C['accent']}]No obvious exposed files / misconfigurations found.[/]")
    return findings

# ---------------------------------------------------------------------------
#  Full report export  (JSON + HTML + Markdown)
# ---------------------------------------------------------------------------
def _report_md(rep):
    s = rep["sections"]
    L = [f"# Recon Report — {rep['target']}", "",
         f"- **IP:** {rep['ip']}",
         f"- **Domain:** {rep.get('domain') or '—'}",
         f"- **Generated:** {rep['generated']}", ""]
    if "geolocation" in s:
        g = s["geolocation"]
        L += ["## Geolocation",
              f"- Location: {g.get('city')}, {g.get('regionName')}, {g.get('country')}",
              f"- ISP: {g.get('isp')} | Org: {g.get('org')} | AS: {g.get('as')}", ""]
    if s.get("open_ports"):
        L += ["## Open Ports"] + [f"- **{p['port']}** {p['banner']}" for p in s["open_ports"]] + [""]
    if "shodan" in s:
        sh = s["shodan"]
        L += ["## Shodan InternetDB", f"- Ports: {sh.get('ports')}", f"- CVEs: {sh.get('vulns')}", ""]
    if "tls" in s:
        L += ["## TLS"] + [f"- {k}: {v}" for k, v in s["tls"].items()] + [""]
    if "http" in s:
        h = s["http"]
        L += ["## HTTP", f"- URL: {h.get('url')} ({h.get('status')})",
              f"- Server: {h.get('server')} | Tech: {', '.join(h.get('tech', []))}",
              f"- Title: {h.get('title')}", ""]
    if "favicon" in s:
        L += ["## Favicon", f"- {s['favicon']['shodan_dork']}", ""]
    if "dns" in s:
        L += ["## DNS"] + [f"- {k}: {', '.join(v)}" for k, v in s["dns"].items() if v] + [""]
    if "subdomains" in s:
        sub = s["subdomains"]
        L += [f"## Subdomains ({sub['count']})", f"- Sources: {sub['sources']}"]
        L += [f"- {h}" for h in sub["hosts"][:1000]] + [""]
    if "exposures" in s and s["exposures"]:
        L += ["## Exposures"] + [f"- **{lbl}** — {p}" for p, lbl, _c, _n in s["exposures"]] + [""]
    return "\n".join(L)

def _report_html(rep):
    import html as _h
    def e(x): return _h.escape(str(x))
    s = rep["sections"]
    parts = []
    def sec(title, inner):
        parts.append(f"<section><h2>{e(title)}</h2>{inner}</section>")
    def kv(d):
        return "<table>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in d.items()) + "</table>"
    if "geolocation" in s:
        g = s["geolocation"]
        sec("Geolocation", kv({"Location": f"{g.get('city')}, {g.get('regionName')}, {g.get('country')}",
                               "ISP": g.get("isp"), "Org": g.get("org"), "AS": g.get("as")}))
    if s.get("open_ports"):
        rows = "".join(f"<tr><td>{e(p['port'])}</td><td>{e(p['banner'])}</td></tr>" for p in s["open_ports"])
        sec("Open Ports", f"<table><tr><th>Port</th><th>Banner</th></tr>{rows}</table>")
    if "shodan" in s:
        sh = s["shodan"]
        sec("Shodan InternetDB", kv({"Ports": sh.get("ports"), "CVEs": sh.get("vulns"),
                                     "CPEs": sh.get("cpes"), "Tags": sh.get("tags")}))
    if "tls" in s:
        sec("TLS", kv(s["tls"]))
    if "http" in s:
        h = s["http"]
        sec("HTTP", kv({"URL": h.get("url"), "Status": h.get("status"), "Server": h.get("server"),
                        "Tech": ", ".join(h.get("tech", [])), "Title": h.get("title")}))
    if "favicon" in s:
        sec("Favicon", kv({"Hash": s["favicon"]["hash"], "Shodan dork": s["favicon"]["shodan_dork"]}))
    if "dns" in s:
        sec("DNS", kv({k: ", ".join(v) for k, v in s["dns"].items() if v}))
    if "subdomains" in s:
        sub = s["subdomains"]
        lis = "".join(f"<li>{e(h)}</li>" for h in sub["hosts"][:2000])
        sec(f"Subdomains ({sub['count']})",
            f"<p class='muted'>Sources: {e(sub['sources'])}</p><ul class='cols'>{lis}</ul>")
    if s.get("exposures"):
        rows = "".join(f"<tr class='bad'><td>{e(lbl)}</td><td>{e(p)}</td></tr>" for p, lbl, _c, _n in s["exposures"])
        sec("Exposures", f"<table><tr><th>Finding</th><th>Path</th></tr>{rows}</table>")
    css = """
    :root{color-scheme:dark}
    body{background:#0b0f0b;color:#d8f5d8;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:0;padding:2rem}
    h1{color:#00FF41;border-bottom:1px solid #1f2f1f;padding-bottom:.5rem}
    h2{color:#00FFFF;margin-top:2rem;font-size:1.05rem;text-transform:uppercase;letter-spacing:.06em}
    section{margin-bottom:1.5rem}
    table{border-collapse:collapse;width:100%;max-width:960px}
    th,td{text-align:left;padding:.35rem .7rem;border-bottom:1px solid #182818;vertical-align:top}
    th{color:#7fdca0;font-weight:600;white-space:nowrap;width:1%}
    .muted{color:#5f7f5f}
    ul.cols{columns:3;-webkit-columns:3;list-style:none;padding:0;font-size:12px}
    ul.cols li{color:#8fe8ff;break-inside:avoid}
    tr.bad td{color:#ff6b6b}
    .meta{color:#5f7f5f;font-size:12px;margin-bottom:1.5rem}
    """
    header = (f"<h1>GhostRecon Report — {e(rep['target'])}</h1>"
              f"<div class='meta'>IP {e(rep['ip'])} · Domain {e(rep.get('domain') or '—')} · {e(rep['generated'])}</div>")
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>GhostRecon — {e(rep['target'])}</title><style>{css}</style></head>"
            f"<body>{header}{''.join(parts)}</body></html>")

def full_report(target):
    os.system("clear" if os.name != "nt" else "cls")
    console.print(Align.center(MINI_BANNER)); console.print()
    ip, domain = resolve(target)
    if not ip:
        console.print(f"  [{C['danger']}]Could not resolve: {mesc(target)}[/]"); _pause(); return
    rep = {"target": target, "ip": ip, "domain": domain,
           "generated": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), "sections": {}}
    console.print(Panel(f"[bold {C['accent']}]FULL REPORT[/]  {mesc(target)}  →  {ip}",
                        border_style=C['accent']))
    geo = safe_get(f"http://ip-api.com/json/{ip}",
                   params={"fields": "status,country,regionName,city,lat,lon,isp,org,as,query"})
    if isinstance(geo, dict) and geo.get("status") == "success":
        rep["sections"]["geolocation"] = geo
    shod = mod_shodan(ip)
    if isinstance(shod, dict) and shod:
        rep["sections"]["shodan"] = {k: shod.get(k) for k in ("ports", "hostnames", "cpes", "tags", "vulns")}
    ports = mod_port_scan_auto(ip)
    rep["sections"]["open_ports"] = [{"port": p, "banner": b} for p, b in ports]
    host_for_tls = domain or ip
    tls_ports = [p for p, _ in ports if p in (443, 8443, 993, 995)] or [443]
    try:
        tls = mod_tls(host_for_tls, tls_ports[0], probe_versions=False)
        rep["sections"]["tls"] = {k: tls.get(k) for k in
                                  ("verified", "subject_cn", "issuer", "sans", "days_left", "cipher") if k in tls}
    except Exception:
        pass
    probe = http_probe_one(host_for_tls)
    if probe:
        rep["sections"]["http"] = probe
    fav, favurl = get_favicon_hash(host_for_tls)
    if fav is not None:
        rep["sections"]["favicon"] = {"hash": fav, "url": favurl, "shodan_dork": f"http.favicon.hash:{fav}"}
    if domain:
        pmap, counts = spinner_task("Aggregating passive subdomains", gather_passive_subdomains, domain)
        rep["sections"]["subdomains"] = {"count": len(pmap), "sources": counts, "hosts": sorted(pmap)}
        dns = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            d = safe_get("https://dns.google/resolve", params={"name": domain, "type": rtype})
            if isinstance(d, dict):
                dns[rtype] = [a.get("data", "") for a in d.get("Answer", [])]
        rep["sections"]["dns"] = dns
    try:
        exp = mod_exposures(host_for_tls)
        if exp:
            rep["sections"]["exposures"] = exp
    except Exception:
        pass
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    base = f"ghost_report_{safe}_{stamp}"
    outputs = {"JSON": (base + ".json", lambda: json.dumps(rep, indent=2, default=str)),
               "HTML": (base + ".html", lambda: _report_html(rep)),
               "Markdown": (base + ".md", lambda: _report_md(rep))}
    section_header("REPORT SAVED", "*")
    for label, (path, render) in outputs.items():
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(render())
            print_kv(label, path, C['accent'])
        except Exception as e:
            console.print(f"  [{C['danger']}]{label} save failed: {e}[/]")
    _pause()

MENU_ITEMS = [
    ("1",  "DEEP SCAN",         "Full recon: geo, ports, TLS, subs, http, favicon, exposure"),
    ("2",  "MASS SCAN",         "Bulk scan — CVEs, ports, geo for many targets"),
    ("3",  "QUICK LOOKUP",      "Fast IP geo + Shodan + ASN / network info"),
    ("4",  "SUBDOMAIN HUNTER",  "6 passive sources + wordlist brute-force + wildcard"),
    ("5",  "PORT SCANNER",      "nmap (-sV) if available, else multi-threaded socket"),
    ("6",  "CVE CHECK",         "Shodan InternetDB CVEs with real CVSS from NVD"),
    ("7",  "ADVANCED SEARCH",   "Full query syntax workflow (http, ssl, ports, geo)"),
    ("8",  "TLS / CERT",        "Cert details + supported TLS versions + cipher"),
    ("9",  "HTTP PROBE",        "httpx-lite: live hosts, status, tech, titles"),
    ("10", "WAYBACK URLS",      "Harvest archived URLs, params & files (archive.org)"),
    ("11", "ASN / NETBLOCKS",   "Expand an ASN or org into all its IP prefixes"),
    ("12", "EXPOSURE SCAN",     "nuclei-lite: secrets, misconfigs, security headers"),
    ("13", "FAVICON HASH",      "Shodan favicon pivot (mmh3)"),
    ("14", "FULL REPORT",       "Run everything → JSON + HTML + Markdown report"),
    ("0",  "EXIT",              ""),
]
def print_menu():
    os.system("clear" if os.name != "nt" else "cls")
    console.print(Align.center(f"[bold {C['accent']}]{BANNER}[/]"))
    console.print(Align.center(f"[dim {C['muted']}] made by G0Ju.VBS {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC[/]"))
    console.print()
    for num, name, desc in MENU_ITEMS:
        if num == "0":
            console.print(f"  [{C['muted']}][ 0] {name}[/]")
        else:
            console.print(
                f"  [{C['muted']}][[/][bold {C['accent']}]{num:>2}[/][{C['muted']}]][/] "
                f"[bold {C['white']}]{name:<18}[/]"
                f"[{C['muted']}]{desc}[/]"
            )
    console.print()
def main():
    try:
        animate_banner()
    except KeyboardInterrupt:
        pass
    while True:
        try:
            print_menu()
            choice = Prompt.ask(
                f"  [{C['accent']}]GHOST[/][{C['muted']}](Ctrl+C to menu)>[/]",
                choices=[n for n, *_ in MENU_ITEMS],
                show_choices=False,
            ).strip()
            if choice == "1":
                t = _input_target()
                if t:
                    deep_scan(t)
            elif choice == "2":
                console.print(f"\n  [{C['info']}]Mass Scan Mode[/] — enter IPs or domains\n")
                targets = _input_targets_list()
                targets = _or_load_file(targets)
                if targets:
                    mass_scan(targets)
                else:
                    console.print(f"  [{C['warn']}]No targets entered.[/]")
                    time.sleep(1)
            elif choice == "3":
                t = _input_target()
                if t:
                    quick_lookup(t)
            elif choice == "4":
                t = _input_target("Enter domain (e.g. example.com)")
                if t:
                    subdomain_hunt(t)
            elif choice == "5":
                t = _input_target()
                if t:
                    ip, _ = resolve(t)
                    if ip:
                        os.system("clear" if os.name != "nt" else "cls")
                        console.print(Align.center(MINI_BANNER)); console.print()
                        backend = "nmap" if _nmap_path() else "socket"
                        console.print(f"  [dim]Backend: {backend} | install nmap for -sV/version detection[/]")
                        spec = Prompt.ask(
                            f"  [{C['accent']}]>>[/] Port spec (Enter=common, e.g. 22,80,443  1-1000  top100)",
                            default=""
                        ).strip()
                        mod_port_scan_auto(ip, port_spec=spec or None)
                        _pause()
                    else:
                        console.print(f"  [{C['danger']}]Cannot resolve {t}[/]")
                        time.sleep(1)
            elif choice == "6":
                t = _input_target("Enter IP address")
                if t:
                    ip, _ = resolve(t)
                    if ip:
                        os.system("clear" if os.name != "nt" else "cls")
                        console.print(Align.center(MINI_BANNER)); console.print()
                        spinner_task("Checking Shodan InternetDB", mod_shodan, ip)
                        _pause()
            elif choice == "7":
                advanced_search()
            elif choice == "8":
                host = _input_target("Enter host (e.g. example.com)")
                if host:
                    port_str = Prompt.ask(
                        f"  [{C['accent']}]>>[/] Port",
                        default="443"
                    ).strip() or "443"
                    try:
                        port = int(port_str)
                    except ValueError:
                        console.print(f"  [{C['danger']}]Invalid port: {port_str}[/]")
                        time.sleep(1)
                        continue
                    os.system("clear" if os.name != "nt" else "cls")
                    console.print(Align.center(MINI_BANNER)); console.print()
                    try:
                        mod_tls(host, port, probe_versions=True)
                    except Exception as e:
                        console.print(f"  [{C['danger']}]TLS analysis failed: {e}[/]")
                    _pause()
            elif choice == "9":
                t = _input_target("Enter host(s) — comma-separated, or a single domain")
                if t:
                    os.system("clear" if os.name != "nt" else "cls")
                    console.print(Align.center(MINI_BANNER)); console.print()
                    if "," in t:
                        hosts = [x.strip() for x in t.split(",") if x.strip()]
                    else:
                        hosts = [t]
                        _ip, dom = resolve(t)
                        if dom and Confirm.ask(
                            f"  [{C['info']}]?[/] Also enumerate + probe passive subdomains of {dom}?", default=True):
                            pmap, _c = spinner_task("Gathering passive subdomains", gather_passive_subdomains, dom)
                            hosts = sorted(set(hosts) | set(pmap))
                    mod_http_probe(hosts)
                    _pause()
            elif choice == "10":
                t = _input_target("Enter domain (e.g. example.com)")
                if t:
                    os.system("clear" if os.name != "nt" else "cls")
                    console.print(Align.center(MINI_BANNER)); console.print()
                    mod_wayback(t)
                    _pause()
            elif choice == "11":
                q = _input_target("Enter ASN (e.g. AS15169) or org name (e.g. cloudflare)")
                if q:
                    os.system("clear" if os.name != "nt" else "cls")
                    console.print(Align.center(MINI_BANNER)); console.print()
                    mod_asn(q)
                    _pause()
            elif choice == "12":
                t = _input_target("Enter target URL or host")
                if t:
                    os.system("clear" if os.name != "nt" else "cls")
                    console.print(Align.center(MINI_BANNER)); console.print()
                    console.print(f"  [{C['warn']}]Active checks — only scan hosts you are authorized to test.[/]")
                    mod_exposures(t)
                    _pause()
            elif choice == "13":
                t = _input_target("Enter host / domain")
                if t:
                    os.system("clear" if os.name != "nt" else "cls")
                    console.print(Align.center(MINI_BANNER)); console.print()
                    mod_favicon(t)
                    _pause()
            elif choice == "14":
                t = _input_target()
                if t:
                    full_report(t)
            elif choice == "0":
                console.print(f"\n  [{C['accent']}]Stay ghostly.[/]\n")
                sys.exit(0)
        except KeyboardInterrupt:
            console.print(f"\n  [{C['warn']}]Returning to menu...[/]")
            time.sleep(1)
            continue
        except Exception as e:
            console.print(f"\n  [{C['danger']}]Error: {e}[/]")
            time.sleep(2)
            continue
if __name__ == "__main__":
    main()
