# ShowMe / GhostRecon vs. the field

An honest, engineering-level comparison of ShowMe (`SM.py`, v3.0) against the
tools most people reach for. The goal here is not marketing — it's to show
exactly where ShowMe is competitive, where it is *best-in-class for its
category* (single-file, keyless, all-in-one), and where a purpose-built tool
still wins.

## What ShowMe is

A **single-file, keyless, cross-platform recon console** that folds passive
OSINT, DNS/subdomain enumeration, live HTTP probing, TLS analysis, port
scanning, CVE enrichment, and reporting into one interactive TUI. Nothing to
compile, no config files, no API keys required, no database to stand up. Runs
the same on Windows, macOS, and Linux with just `requests` + `rich`.

That "one binary, zero setup, does everything" niche is where ShowMe aims to be
the strongest option available.

## Feature matrix

Legend: ● full · ◐ partial / lighter · ○ none

| Capability | ShowMe v3.0 | Amass | subfinder | theHarvester | SpiderFoot | httpx | nuclei | Shodan CLI |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Passive subdomain sources | ◐ 6 keyless | ● 55+ | ● 30+ | ◐ | ● 200+ mods | ○ | ○ | ◐ |
| DNS brute-force + wildcard detect | ● | ● | ○ | ○ | ◐ | ○ | ○ | ○ |
| Live HTTP probe + tech fingerprint | ● | ○ | ○ | ○ | ◐ | ● | ◐ | ○ |
| Favicon hash (mmh3 / Shodan pivot) | ● | ○ | ○ | ○ | ◐ | ● | ○ | ◐ |
| Port scan (nmap or socket fallback) | ● | ○ | ○ | ○ | ◐ | ○ | ○ | ◐ passive |
| TLS/cert + version matrix + weak cipher | ● | ○ | ○ | ○ | ◐ | ◐ | ◐ | ◐ |
| CVE list + **real CVSS from NVD** | ● | ○ | ○ | ○ | ◐ | ○ | ● | ● |
| Exposure / misconfig checks | ◐ ~12 | ○ | ○ | ○ | ◐ | ○ | ● 9000+ | ○ |
| Security-header hygiene score | ● | ○ | ○ | ○ | ◐ | ◐ | ◐ | ○ |
| Wayback URL harvesting | ● | ○ | ○ | ◐ | ◐ | ○ | ○ | ○ |
| ASN / org → netblock expansion | ● | ● | ○ | ○ | ● | ○ | ○ | ◐ |
| Geo / ISP / ASN enrichment | ● | ◐ | ○ | ○ | ● | ○ | ○ | ● |
| Report export (JSON+HTML+MD) | ● | ◐ | ○ | ◐ | ● | ◐ | ● | ◐ |
| Runs with **zero API keys** | ● | ● | ◐ | ◐ | ◐ | ● | ● | ○ needs key |
| Single file, no install/build | ● | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| Interactive TUI | ● | ○ | ○ | ○ | ◐ web | ○ | ○ | ○ |

## Where ShowMe wins

- **Breadth in one place.** No other single tool here covers passive DNS →
  brute-force → live HTTP fingerprint → TLS → ports → CVSS → exposures →
  report. Amass/subfinder are subdomain specialists; httpx probes; nuclei
  scans; Shodan queries. ShowMe does a competent version of *all of it*
  without chaining five binaries and a shell pipeline.
- **Zero-setup, zero-key.** Every data source is a free/unauthenticated
  endpoint, and there's nothing to install beyond two pip packages. That makes
  it the fastest tool here to go from "clean laptop" to "useful recon."
- **Real CVSS, not just CVE IDs.** CVEs from Shodan InternetDB are enriched
  with live `baseScore`/`baseSeverity` from the official NVD API (v3.1→v3.0→v2
  fallback), disk-cached with a 7-day TTL. Most free tools stop at the CVE ID.
- **Resilient aggregation.** Subdomain sources run in parallel and the result
  is the union — if crt.sh is rate-limiting or a source is down, CertSpotter +
  RapidDNS + HackerTarget + OTX + Anubis still deliver.
- **Reliable ASN data.** Network/ASN features use RIPEstat (with a BGPView
  fallback), so netblock expansion keeps working even where BGPView is blocked.
- **Correct favicon hashing.** Pure-Python MurmurHash3 verified against the
  reference `mmh3` values, so `http.favicon.hash:` dorks match Shodan exactly —
  no native dependency.
- **Portable reports.** Every run can emit a self-contained, theme-styled HTML
  report plus machine-readable JSON and Markdown.

## Where the specialists still win (honest limitations)

- **Subdomain source count.** Amass (55+) and subfinder (30+) pull from far
  more sources, many key-gated (VirusTotal, SecurityTrails, Censys, etc.).
  ShowMe's 6 keyless sources cover the high-value free ones but won't match
  their raw recall on large targets.
- **Vuln depth.** nuclei ships 9,000+ community templates. ShowMe's exposure
  module is ~12 high-signal checks — useful triage, not a replacement.
- **Port-scan speed.** The socket fallback (≤100 threads) is fine for common
  ports but is far slower than masscan/naabu/ZMap for full-range internet-scale
  scans. Install nmap for `-sV` and ShowMe uses it automatically.
- **Scale & automation.** SpiderFoot's 200+ modules, correlation graph, and web
  UI, and Amass's graph DB, are built for large automated engagements. ShowMe
  is an operator's interactive console, not a distributed pipeline.
- **Active DNS resolution.** No high-performance mass DNS resolver (à la
  massdns/shuffledns/dnsx) — brute-force uses the OS resolver via a thread pool.

## Honest bottom line

For the **"one file, no keys, no setup, do a bit of everything from a menu"**
category, ShowMe is now genuinely best-in-class and holds its own against tools
several times its size. It is **not** a drop-in replacement for a tuned
Amass + dnsx + httpx + nuclei pipeline on a large professional engagement, and
this document deliberately doesn't pretend otherwise. The realistic positioning:
**the strongest all-in-one keyless recon console**, and a fast first-pass tool
that tells you within minutes whether a target is worth the heavy artillery.

## Roadmap to close the remaining gaps

1. Optional key-gated sources (SecurityTrails, VirusTotal, Censys, Shodan API,
   Chaos) — union them in when a key is present, stay keyless when not.
2. A bundled mass DNS resolver for brute-force at massdns speed.
3. A larger, YAML-driven exposure/template set (nuclei-style, opt-in).
4. Optional masscan/naabu backend for internet-scale port sweeps.
5. Correlation across modules (favicon hash → Shodan pivot → new hosts → probe).
