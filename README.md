# ShowMe

```
 _________.__                    _____
 /   _____/|  |__   ______  _  __/     \   ____
 \_____  \ |  |  \ /  _ \ \/ \/ /  \ /  \_/ __ \
 /        \|   Y  (  <_> )     /    Y    \  ___/
/_______  /|___|  /\____/ \/\_/\____|__  /\___  >
        \/      \/                     \/     \/
```

A terminal-based OSINT / reconnaissance framework written in Python. It queries multiple public APIs for information on an IP or domain, scans ports (via Nmap when available), brute-forces subdomains, inspects TLS certificates, and checks known CVEs against real CVSS scores from NVD — all from a single interactive menu.

**Author:** G0Ju.VBS

---

## Features

All features are exposed through the interactive menu in `SM.py`:

1. **DEEP SCAN** — Full recon on one target. Resolves the target, pulls geo / ISP / ASN data, Shodan InternetDB info (open ports, hostnames, CVEs with real CVSS scores), BGP view records, reverse-DNS, WHOIS, DNS records, port scan with banner grabbing, subdomain enumeration (passive + brute-force), and **auto-runs TLS analysis on any open TLS port** (443, 8443, 993, 995).
2. **MASS SCAN** — Bulk mode. Feeds a list of IPs or domains (entered manually or loaded from a file) and collects geo, ISP, open ports, and CVE counts for each target in parallel. *Note: mass scan intentionally does not fetch full CVSS details to stay within NVD rate limits.*
3. **QUICK LOOKUP** — Fast lightweight recon: geo / ASN / ISP + Shodan InternetDB summary.
4. **SUBDOMAIN HUNTER** — Passive enumeration via `crt.sh` certificate transparency **plus** wordlist brute-force (~1100 common names bundled) **plus** hackertarget host records and Google DNS record lookups. Includes wildcard-DNS detection to avoid false positives.
5. **PORT SCANNER** — Auto-detects `nmap` and uses it with `-sV -Pn -T3 --open` for service/version detection, falling back to a multi-threaded Python socket scanner with per-protocol banner probes (HTTP, FTP, SSH, SMTP, MySQL, Redis, etc.) when Nmap is not installed. Accepts custom port specs: `22,80,443`, `1-1000`, `top100`, or blank for the default common-port list.
6. **CVE CHECK** — Pulls the CVE list from Shodan InternetDB and enriches each CVE with **real CVSS v3.1/v3.0/v2 scores and severity** fetched from the NVD API (with disk cache + rate-limit respect).
7. **ADVANCED SEARCH** — Interactive query builder using filter syntax (e.g. `http.title:"Dashboard" port:8080 country:US`, `ssl.cert.subject.cn:*.example.com`, `hostname:*.gov`). Queries urlscan.io and crt.sh. Results can be exported to JSON.
8. **TLS / CERT ANALYSIS** — Standalone TLS inspector. Takes host + optional port (default 443), returns:
   - Certificate **verification status** (including reason on failure for self-signed / expired / chain errors).
   - Subject CN, issuer CN + organization, all DNS `subjectAltName` entries.
   - `Not Before` / `Not After` + computed days-until-expiry (color-coded: danger when expired, warn when <30 days).
   - Negotiated TLS version + cipher suite (weak ciphers flagged: `RC4`, `3DES`, `MD5`, `EXPORT`, `NULL`).
   - Support matrix for TLSv1 / TLSv1.1 / TLSv1.2 / TLSv1.3 — each probed with a dedicated handshake, classified as `[SUPPORTED]` (deprecated versions colored red per RFC 8996), `[NOT OFFERED]`, or `[DISABLED IN CLIENT]`.

Extras:
- Animated ASCII banner, colored output, and a "glitch" text effect using `rich`.
- Graceful handling of `Ctrl+C` to return to the menu instead of crashing.
- CVE output shows real CVSS scores and links to `nvd.nist.gov`.
- Optional JSON export from Advanced Search (`ghost_adv_YYYYMMDD_HHMMSS.json`).
- Per-host rate limiting and automatic retries with exponential backoff on every API call.
- NVD responses cached to `~/.cache/showme/nvd_cvss.json` (7-day TTL) — subsequent runs are instant for already-seen CVEs.

---

## CVE severity via NVD

When Shodan InternetDB reports CVEs for a target, ShowMe looks each one up in the **official NVD API** (`https://services.nvd.nist.gov/rest/json/cves/2.0`) and renders the real `baseScore` and `baseSeverity` (CVSS v3.1 → v3.0 → v2 fallback chain).

- **Disk cache** at `~/.cache/showme/nvd_cvss.json` with a 7-day TTL — fetched CVEs survive across sessions.
- **Rate-limit respecting** — NVD's public API allows 5 requests / 30 s without a key. ShowMe throttles accordingly.
- **Batch cap** — when uncached CVEs for a single scan exceed 10, the tool prompts before launching a long fetch.
- **Optional API key** — set `NVD_API_KEY` in the environment to raise the rate cap to 50 requests / 30 s. ShowMe automatically sends the key and drops its internal throttle.
- **Mass scan** does NOT trigger per-CVE NVD lookups — the rate limit would make bulk scans unusable.

```bash
export NVD_API_KEY="your-key-here"   # optional, get one at https://nvd.nist.gov/developers/request-an-api-key
python3 SM.py
```

---

## Port scanner

Menu option 5 (and the port-scan phase of DEEP SCAN) uses a two-tier backend:

1. **Nmap** — if `nmap` is on `PATH`, ShowMe invokes it with `nmap -Pn -sV -T3 --open -oG -` (plus a parallel `-oN -` run for the power-user raw output panel). Results are parsed into the standard port / service / version / state table.
2. **Socket fallback** — pure Python, multi-threaded (up to 100 workers), with per-protocol banner probes:
   - HTTP — `HEAD / HTTP/1.0`
   - Redis — `PING` → `+PONG`
   - FTP / SSH / SMTP / MySQL — read greeting banner
   - TLS ports (443/8443/993/995) — marked `[TLS]` (inspect with menu option 8)

**Port spec** (accepted in both backends):

| Spec | Meaning |
|---|---|
| _empty_ | 32 common ports (ShowMe default) |
| `22,80,443` | comma-separated list |
| `1-1000` | inclusive range |
| `22,80,1000-1010` | mix of lists and ranges |
| `top100` | Nmap's top-100 ports |
| `all` | 1-65535 (slow!) |

---

## Subdomain enumeration

Menu option 4 runs three sources and merges the results into a single tree:

1. **Passive** — `crt.sh` certificate transparency logs.
2. **Wildcard detection** — resolves two cryptographically random hostnames under the target domain first. If both resolve (to the same or different IPs), wildcard DNS is flagged and brute-force is skipped to avoid false positives.
3. **Brute-force** — multi-threaded DNS resolution of a ~1100-entry wordlist bundled at `wordlists/subdomains.txt`. The wordlist is hand-curated and covers common infrastructure naming (`www`, `mail`, `api`, `dev`, `admin`, `staging`, cloud-region variants, CI/CD tools, monitoring stacks, etc.).

Each result is tagged with its source (`[crt.sh]`, `[brute]`, or both when the same host appeared in both). Overlap count is shown in the summary line.

If the wordlist file is missing, ShowMe falls back to a small inline list (~30 names) and keeps working.

---

## TLS / certificate analysis

Menu option 8 takes `host` + `port` and produces a full certificate + cipher + protocol report. It also runs automatically from DEEP SCAN whenever port 443, 8443, 993, or 995 is open (version probing skipped in that context for speed).

Implementation uses pure Python stdlib (`ssl` + `socket`) — no OpenSSL shell-out, no extra dependencies.

Test endpoints known to return interesting results:
- `example.com:443` — valid cert, modern TLS.
- `expired.badssl.com:443` — long-expired cert (negative days-left, verification failed).
- `self-signed.badssl.com:443` — verification fails, cert still inspected.
- `rc4.badssl.com:443` — weak-cipher flag.
- `tls-v1-0.badssl.com:1010`, `tls-v1-1.badssl.com:1011`, `tls-v1-2.badssl.com:1012` — forced single-version endpoints for testing the version matrix.

---

## Rate limiting & retries

All outbound HTTP requests go through a single `safe_get()` helper that enforces:

- **Per-host throttling** — a minimum interval between consecutive requests to the same host, so parallel mass-scans don't burst the same API. Current intervals:
  - `services.nvd.nist.gov` — 6.0 s (0.6 s with `NVD_API_KEY`)
  - `api.hackertarget.com` — 1.5 s
  - `crt.sh` — 1.0 s
  - `urlscan.io` — 1.0 s
  - `api.bgpview.io` — 0.6 s
  - `internetdb.shodan.io` — 0.4 s
  - `ip-api.com`, `ipwho.is` — 0.3 s
  - `dns.google` — 0.1 s
- **Retry with exponential backoff** — up to 4 attempts, backoff doubling from 1 s up to a 15 s cap.
- **`429 Too Many Requests` handling** — respects the server's `Retry-After` header when present, otherwise falls back to the backoff schedule.
- **`5xx` server errors** — retried with backoff.
- **`4xx` client errors** (400/401/403/404/410) — returned immediately without retry.
- **Connection errors / timeouts** — retried with backoff.

This mainly matters for HackerTarget (famously strict free-tier rate limits) and for MASS SCAN workloads, but it applies to every source.

---

## APIs / data sources used

No API keys are required for the core feature set — every service used has a free/unauthenticated endpoint. An optional NVD API key raises the CVSS lookup rate cap.

| Source | Endpoint | Used for |
|---|---|---|
| ip-api | `http://ip-api.com/json/<ip>` | Geo, country, region, city, ISP, org, AS |
| Shodan InternetDB | `https://internetdb.shodan.io/<ip>` | Open ports, hostnames, vulnerabilities (CVE IDs), tags |
| NVD API | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>` | Real CVSS v3.1/v3.0/v2 scores & severity (+ optional API key) |
| ipwho.is | `https://ipwho.is/<ip>` | Extended geo / connection info |
| BGPView | `https://api.bgpview.io/ip/<ip>` | ASN / prefix / RIR info |
| Google DNS-over-HTTPS | `https://dns.google/resolve` | A, AAAA, MX, NS, TXT, CNAME records |
| crt.sh | `https://crt.sh/?q=%.<domain>&output=json` | Certificate transparency / subdomain enumeration |
| HackerTarget | `https://api.hackertarget.com/reverseiplookup/`, `/hostsearch/`, `/whois/` | Reverse IP, host records, WHOIS |
| urlscan.io | `https://urlscan.io/api/v1/search/` | Advanced query search over scanned URLs |

Port scanning (Nmap + socket fallback) and TLS analysis run directly against the target — no third-party API.

---

## Requirements

- Python 3.8+
- `requests`
- `rich`
- **Optional:** `nmap` binary on `PATH` — enables service/version detection. Without it, ShowMe falls back to the socket scanner.

Install Python deps:
```bash
pip install requests rich
```

Install Nmap (optional but recommended):
```bash
# Debian/Ubuntu
sudo apt install nmap
# macOS
brew install nmap
# Arch
sudo pacman -S nmap
```

Optional NVD API key:
```bash
export NVD_API_KEY="your-key-here"
```

---

## Usage

```bash
python3 SM.py
```

Then pick an option from the menu. Targets can be either an IP (`8.8.8.8`) or a domain (`example.com`) — the tool resolves as needed.

---

## Project layout

```
ShowMe/
├── SM.py                       # the tool (single file)
├── README.md
└── wordlists/
    └── subdomains.txt          # ~1100 common subdomain names (brute-force)
```

---

## Disclaimer

This tool performs passive lookups against public APIs, with two exceptions: the port scanner (option 5 and the DEEP SCAN port phase) opens direct TCP sockets (or invokes Nmap), and the TLS module (option 8 and DEEP SCAN TLS auto-run) opens TLS connections. Running a port scanner — or repeatedly handshaking TLS against — a host you do not own or have written permission to test may be illegal in your jurisdiction. Use responsibly — the author is not responsible for misuse.
