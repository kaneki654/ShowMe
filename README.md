# ShowMe

```
 _________.__                    _____
 /   _____/|  |__   ______  _  __/     \   ____
 \_____  \ |  |  \ /  _ \ \/ \/ /  \ /  \_/ __ \
 /        \|   Y  (  <_> )     /    Y    \  ___/
/_______  /|___|  /\____/ \/\_/\____|__  /\___  >
        \/      \/                     \/     \/
```

A terminal-based passive OSINT / reconnaissance framework written in Python. It queries multiple public APIs for information on an IP or domain, scans ports, grabs banners, enumerates subdomains via certificate transparency, and checks known CVEs — all from a single interactive menu.

**Author:** G0Ju.VBS

---

## Features

All features are exposed through the interactive menu in `SM.py`:

1. **DEEP SCAN** — Full recon on one target (IP or domain). Resolves the target, pulls geo / ISP / ASN data, Shodan InternetDB info (open ports, hostnames, CVEs), BGP view records, reverse-DNS of the IP, WHOIS, DNS records, and runs a port scan with banner grabbing.
2. **MASS SCAN** — Bulk mode. Feeds a list of IPs or domains (entered manually or loaded from a file) and collects geo, ISP, open ports, and CVE counts for each target in parallel.
3. **QUICK LOOKUP** — Fast lightweight recon: geo / ASN / ISP + Shodan InternetDB summary.
4. **SUBDOMAIN HUNTER** — Enumerates subdomains of a domain via `crt.sh` certificate transparency logs, plus hackertarget host records and Google DNS record lookups (A, AAAA, MX, NS, TXT, CNAME).
5. **PORT SCANNER** — Multi-threaded raw-socket scanner over a default common-port list (21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 9300, 27017, 27018, 6667). Grabs a short banner on open ports (sends `HEAD / HTTP/1.0` on web ports).
6. **CVE CHECK** — Pulls the CVE list associated with an IP from Shodan InternetDB.
7. **ADVANCED SEARCH** — Interactive query builder using filter syntax (e.g. `http.title:"Dashboard" port:8080 country:US`, `ssl.cert.subject.cn:*.example.com`, `hostname:*.gov`). Queries urlscan.io and crt.sh depending on filters used. Results can be exported to JSON.

Extras:
- Animated ASCII banner, colored output, and a "glitch" text effect using `rich`.
- Graceful handling of `Ctrl+C` to return to the menu instead of crashing.
- Severity-tagged CVE output with clickable NVD links (`https://nvd.nist.gov/vuln/detail/<CVE-ID>`).
- Optional JSON export from Advanced Search (`ghost_adv_YYYYMMDD_HHMMSS.json`).

---

## APIs / data sources used

No API keys are required — every service used has a free/unauthenticated endpoint.

| Source | Endpoint | Used for |
|---|---|---|
| ip-api | `http://ip-api.com/json/<ip>` | Geo, country, region, city, ISP, org, AS |
| Shodan InternetDB | `https://internetdb.shodan.io/<ip>` | Open ports, hostnames, vulnerabilities (CVEs), tags |
| ipwho.is | `https://ipwho.is/<ip>` | Extended geo / connection info |
| BGPView | `https://api.bgpview.io/ip/<ip>` | ASN / prefix / RIR info |
| Google DNS-over-HTTPS | `https://dns.google/resolve` | A, AAAA, MX, NS, TXT, CNAME records |
| crt.sh | `https://crt.sh/?q=%.<domain>&output=json` | Certificate transparency / subdomain enumeration |
| HackerTarget | `https://api.hackertarget.com/reverseiplookup/`, `/hostsearch/`, `/whois/` | Reverse IP, host records, WHOIS |
| urlscan.io | `https://urlscan.io/api/v1/search/` | Advanced query search over scanned URLs |
| NVD (link only) | `https://nvd.nist.gov/vuln/detail/<CVE>` | CVE reference links in the CVE panel |

Port banner grabbing is done via raw sockets — no external API.

---

## Requirements

- Python 3.8+
- `requests`
- `rich`

Install:
```bash
pip install requests rich
```

---

## Usage

```bash
python3 SM.py
```

Then pick an option from the menu. Targets can be either an IP (`8.8.8.8`) or a domain (`example.com`) — the tool resolves as needed.

---

## Disclaimer

This tool performs only **passive** lookups against public APIs, with the single exception of the port scanner (option 5), which opens direct TCP sockets to the target. Running a port scanner against a host you do not own or have written permission to test may be illegal in your jurisdiction. Use responsibly — the author is not responsible for misuse.
