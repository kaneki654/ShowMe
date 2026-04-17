import os
import sys
import time
import socket
import json
import threading
import concurrent.futures
from datetime import datetime
import re
import ipaddress
from ipaddress import ip_address
__author__ = "G0Ju.VBS"
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
TIMEOUT = 8
COMMON_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,
    465,587,993,995,1433,1521,3306,3389,5432,5900,
    6379,8080,8443,8888,9200,9300,27017,27018,6667,
]
SEVERITY = {
    "critical": ("bold red",    "[CRIT]"),
    "high":     ("bold #FF6600","[HIGH]"),
    "medium":   ("bold yellow", "[MED] "),
    "low":      ("bold green",  "[LOW] "),
    "info":     ("bold cyan",   "[INFO]"),
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
        for cve in sorted(vulns):
            sev_style, sev_label = _cve_severity(cve)
            console.print(f"    [{sev_style}]{sev_label}[/] [{C['white']}]{cve}[/]  "
                          f"[link=https://nvd.nist.gov/vuln/detail/{cve}][dim u]nvd.nist.gov[/][/link]")
    else:
        print_kv("CVEs", "None in database", C['accent'])
    return data
def _cve_severity(cve_id: str) -> tuple:
    num = int(cve_id.split("-")[-1]) % 10
    if num >= 8:
        return SEVERITY["critical"]
    elif num >= 6:
        return SEVERITY["high"]
    elif num >= 4:
        return SEVERITY["medium"]
    return SEVERITY["low"]
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
    section_header("BGPVIEW", ">")
    data = safe_get(f"https://api.bgpview.io/ip/{ip}")
    if isinstance(data, dict) and data.get("status") == "ok":
        prefixes = data.get("data", {}).get("prefixes", [{}])
        if prefixes:
            first = prefixes[0]
            asn = first.get("asn", {})
            print_kv("Prefix", first.get("prefix"))
            print_kv("ASN", asn.get("asn"), C['purple'])
            print_kv("Name", asn.get("name"), C['cyan'])
            print_kv("Description", asn.get("description"), C['muted'])
    else:
        console.print("  [dim]No BGPView data[/]")
def mod_dns(domain: str):
    section_header("DNS RECORDS  (Google DoH)", ">")
    types = ["A","AAAA","NS","MX","TXT","CNAME","SOA"]
    for rtype in types:
        data = safe_get("https://dns.google/resolve", params={"name": domain, "type": rtype})
        answers = [a.get("data","") for a in data.get("Answer",[])] if "_error" not in data else []
        if answers:
            print_kv(rtype, answers, C['accent'] if rtype == "A" else C['white'])
        time.sleep(0.08)
def mod_subdomains(domain: str):
    section_header("SUBDOMAIN ENUMERATION  (crt.sh)", ">")
    data = safe_get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    if isinstance(data, dict):
        console.print("  [dim]crt.sh error or no data[/]")
        return []
    subs = set()
    for entry in data:
        for name in entry.get("name_value","").splitlines():
            name = name.strip().lstrip("*.")
            if domain in name:
                subs.add(name.lower())
    subs = sorted(subs)
    tree = Tree(f"[bold {C['accent']}]{domain}[/]")
    for s in subs:
        tree.add(f"[{C['cyan']}]{s}[/]")
    console.print(Padding(tree, (0,4)))
    console.print(f"\n  [dim]Total: {len(subs)} subdomains[/]")
    return subs
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
def mod_port_scan(ip: str, ports: list = None, grab_banner: bool = True):
    section_header("PORT SCANNER  (raw socket)", ">")
    ports = ports or COMMON_PORTS
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
                    banner = ""
                    if grab_banner:
                        try:
                            if port in (80, 8080, 8888):
                                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            s.settimeout(0.8)
                            raw = s.recv(256).decode(errors="replace").strip()
                            banner = raw.splitlines()[0][:80] if raw else ""
                        except Exception:
                            pass
                    return (port, True, banner)
            except Exception:
                return (port, False, "")
            finally:
                prog.advance(task)
        with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
            try:
                for result in ex.map(scan_one, ports):
                    port, is_open, banner = result
                    if is_open:
                        open_ports.append((port, banner))
            except KeyboardInterrupt:
                console.print(f"\n  [{C['warn']}]Port scan interrupted! Showing partial results...[/]")
    open_ports.sort()
    if not open_ports:
        console.print(f"  [{C['warn']}]No open ports detected (firewall/filtered)[/]")
        return []
    t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {C['accent']}", padding=(0,2))
    t.add_column("PORT",    style=C['cyan'],    width=8)
    t.add_column("SERVICE", style=C['purple'],  width=14)
    t.add_column("STATE",   style=C['accent'],  width=8)
    t.add_column("BANNER",  style=C['muted'])
    for port, banner in open_ports:
        svc = _svc(port)
        t.add_row(str(port), svc, "OPEN", banner[:60] if banner else "")
    console.print(Padding(t, (0,2)))
    return open_ports
def _svc(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"
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
    mod_port_scan(ip)
    if domain and domain != ip:
        spinner_task("DNS Records",       mod_dns,         domain); time.sleep(0.1)
        spinner_task("Subdomain enum",    mod_subdomains,  domain); time.sleep(0.1)
        spinner_task("Host records",      mod_host_records,domain); time.sleep(0.1)
        spinner_task("HTTP headers",      mod_http_headers,domain); time.sleep(0.1)
        spinner_task("WHOIS",             mod_whois,       domain)
    elif domain is None:
        spinner_task("Reverse DNS",       mod_http_headers, ip)
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
    spinner_task("Fetching certificate logs", mod_subdomains, domain)
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
    valid_keys = {"http.title", "http.server", "http.status", "http.body", "http.favicon.hash", "tech", "ssl", "ssl.cert.issuer.org", "ssl.cert.subject.cn", "ssl.cert.expired", "hostname", "domain", "subdomain", "ip", "port", "country", "org", "asn", "isp"}
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
    urlscan_map = {"http.title": "page.title", "http.server": "page.server", "tech": "page.server", "http.status": "page.statusCode", "http.body": "text", "http.favicon.hash": "hash"}
    ips = set()
    with Progress(SpinnerColumn(spinner_name="dots2", style=f"bold {C['accent']}"),TextColumn(f"[{C['info']}]Searching...[/]"),console=console,transient=True) as prog:
        task = prog.add_task("Search", total=None)
        if any(k in urlscan_map for k in filters):
            q_parts = []
            for k in filters:
                if k in urlscan_map:
                    for v in filters[k]:
                        q_parts.append(f'{urlscan_map[k]}:"{v}"')
            try:
                data = safe_get("https://urlscan.io/api/v1/search/", params={"q": " AND ".join(q_parts)})
                if isinstance(data, dict) and "_error" not in data:
                    for r in data.get("results", []):
                        val = r.get("page", {}).get("ip")
                        if val: ips.add(val)
            except Exception: pass
        crtsh_keys = {"ssl", "hostname", "domain", "subdomain", "ssl.cert.issuer.cn", "ssl.cert.subject.cn"}
        for k in crtsh_keys:
            if k in filters:
                for v in filters[k]:
                    try:
                        data = safe_get("https://crt.sh/", params={"q": f"%{v.replace('*', '%')}%", "output": "json"})
                        if isinstance(data, list):
                            for entry in data:
                                if "not_after" in entry:
                                    try:
                                        if datetime.strptime(entry["not_after"], "%Y-%m-%dT%H:%M:%S") < datetime.now():
                                            continue
                                    except: pass
                                for n in entry.get("name_value","").splitlines():
                                    ip, _ = resolve(n.strip().lstrip("*."))
                                    if ip: ips.add(ip)
                    except Exception: pass
        if "ip" in filters:
            for ip_val in filters["ip"]:
                try:
                    for ip in ipaddress.ip_network(ip_val, strict=False):
                        ips.add(str(ip))
                except Exception: pass
    ips = list(ips)[:100]
    if not ips:
        console.print(f"  [{C['warn']}]No IPs gathered.[/]")
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
    def _is_high(c):
        try: return int(c.split("-")[-1]) % 10 >= 6
        except: return False
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
MENU_ITEMS = [
    ("1", "DEEP SCAN",          "Full recon on one target  (IP + domain)"),
    ("2", "MASS SCAN",          "Bulk scan — CVEs, ports, geo for many targets"),
    ("3", "QUICK LOOKUP",       "Fast IP geo + Shodan + network info"),
    ("4", "SUBDOMAIN HUNTER",   "crt.sh cert logs + host records + DNS"),
    ("5", "PORT SCANNER",       "Multi-threaded socket port scan + banner grab"),
    ("6", "CVE CHECK",          "Shodan InternetDB CVE list for an IP"),
    ("7", "ADVANCED SEARCH",    "Full query syntax workflow (http, ssl, ports, geo)"),
    ("0", "EXIT",               ""),
]
def print_menu():
    os.system("clear" if os.name != "nt" else "cls")
    console.print(Align.center(f"[bold {C['accent']}]{BANNER}[/]"))
    console.print(Align.center(f"[dim {C['muted']}] made by G0Ju.VBS {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC[/]"))
    console.print()
    for num, name, desc in MENU_ITEMS:
        if num == "0":
            console.print(f"  [{C['muted']}]  [{num}]  {name}[/]")
        else:
            console.print(
                f"  [{C['muted']}][[/][bold {C['accent']}]{num}[/][{C['muted']}]][/] "
                f"[bold {C['white']}]{name:<22}[/]"
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
                choices=["0","1","2","3","4","5","6","7"],
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
                        mod_port_scan(ip, grab_banner=True)
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
