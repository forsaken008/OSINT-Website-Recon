# Surface Recon

> **Legal Disclaimer:** This tool is provided for authorized security testing, educational purposes, and legitimate OSINT research only. You are solely responsible for how you use this software. The author(s) assume no liability for any misuse, illegal activity, or damages resulting from its use. Always obtain explicit written permission before performing reconnaissance on any target you do not own or have authorization to test. Unauthorized use may violate local, national, or international law.

---

A full-surface OSINT and active reconnaissance toolkit. Runs 19 modules across 6 phases — passive intelligence gathering, subdomain enumeration, port scanning, TLS analysis, security header grading, JS secret scanning, directory bruteforce, and more. Available as a CLI and a dark-theme desktop GUI.

---

## Installation

**Python 3.10+ required.**

```
pip install -r requirements.txt
```

Key dependencies: `aiohttp`, `aiodns`, `pydantic`, `dnspython`, `ipwhois`, `python-whois`, `typer`, `rich`, `loguru`, `pyyaml`, `pillow`

Optional but recommended:
- `sslyze` — deep TLS analysis (already in requirements.txt; falls back to manual SSL socket if import fails)
- `nmap` binary in PATH — service/version detection on open ports (falls back to async TCP connect)
- `subfinder` or `amass` binary in PATH — additional subdomain sources

---

## Quick Start

**CLI — full scan, text + JSON output:**
```
python recon.py example.com --output text,json
```

**CLI — passive only (no active connections to target):**
```
python recon.py example.com --passive-only
```

**GUI:**
```
python recon.py --gui
```
or double-click `run.vbs` on Windows.

---

## CLI Reference

```
python recon.py [OPTIONS] TARGET
python recon.py modules          ← list all available modules
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `TARGET` | required | Domain or URL (`example.com`, `https://example.com/path`) |
| `-o`, `--output` | `text` | Output format(s): `text`, `json`, `csv` — repeat or comma-separate for multiple |
| `-d`, `--output-dir` | `results/<domain>/` | Directory for output files |
| `--stdout` | off | Also print text report to stdout |
| `--subdomain-list` | off | Write plain host list for piping to httpx/nuclei/ffuf |
| `-m`, `--modules` | all | Comma-separated module list, e.g. `dns,ct_logs,subdomains` |
| `--passive-only` | off | Only passive modules — no connections to the target itself |
| `--thorough` | off | Enable AXFR, JS analysis, subdomain permutations, external tools |
| `--skip` | none | Comma-separated modules to exclude |
| `-c`, `--config` | `config.yaml` | Path to config file |
| `--proxy` | none | Proxy URL, e.g. `socks5://127.0.0.1:9050` |
| `-q`, `--quiet` | off | Suppress progress; write files only |
| `--no-color` | off | Disable colour output |

**Examples:**

```bash
# Deep scan with all output formats and Tor routing
python recon.py example.com --output text,json,csv --thorough --proxy socks5://127.0.0.1:9050

# Passive reconnaissance only (no active connections to target)
python recon.py example.com --passive-only --output json

# Subdomain enumeration only, write plain list for httpx
python recon.py example.com --modules ct_logs,api_sources,subdomains --subdomain-list

# Skip slow modules for a quick pass
python recon.py example.com --skip traceroute,dir_scan,js_analysis,email_harvest

# Just DNS + TLS
python recon.py example.com --modules dns,tls --output text --stdout
```

---

## GUI

Launch with `python recon.py --gui` or double-click `run.vbs`.

- **Target / Output Directory** — same as CLI; supports all URL forms
- **Output format** — text / json / csv checkboxes (any combination)
- **Module Selection** — collapsible panel; modules grouped by phase; Select All / Clear All buttons
- **Start Recon** — runs the engine in a background thread; progress streams to the log widget in real time
- **Cancel** — signals the async engine to stop cleanly after the current module
- **Open Results** — opens the per-domain output folder in Explorer

---

## Modules

All 19 modules, in scan order:

| Module | Phase | Type | What it does |
|--------|-------|------|--------------|
| `ip_whois` | Foundation | passive | Resolves IP, RDAP lookup — ASN, org, CIDR, country |
| `dns` | Foundation | passive | A/AAAA/MX/NS/TXT/SOA/CAA/SRV/PTR; SPF/DMARC/DKIM analysis |
| `axfr` | Foundation | active | Zone transfer attempt against every NS |
| `domain_whois` | Foundation | passive | Registrar, dates, nameservers, registrant; flags expiry <30 days |
| `ct_logs` | Passive OSINT | passive | All unique domains/subdomains from Certificate Transparency logs (crt.sh) |
| `wayback` | Passive OSINT | passive | Wayback CDX API: up to 50,000 archived URLs; flags 15 interesting patterns |
| `api_sources` | Passive OSINT | passive | Shodan, VirusTotal, AlienVault OTX, SecurityTrails (keys optional) |
| `subdomains` | Enumeration | active | aiodns brute-force (wordlist + permutations) + external tool passthrough; validated against 2 resolvers |
| `geo` | Network | passive | IP geolocation via ip-api.com / ipinfo.io fallback |
| `cdn` | Network | active | CDN detection from 19 header signatures + 10 ASN mappings; origin IP leak detection |
| `ports` | Active | active | nmap `-sV -sC` → async TCP connect fallback; 33 service mappings |
| `tls` | Active | active | sslyze: protocols, cipher suites, weak ciphers, cert info, OCSP, HSTS, Heartbleed, ROBOT |
| `headers` | Active | active | HSTS/CSP/XFO/XCTO/RP/PP analysis; Set-Cookie flags; server disclosure; A–F grade |
| `tech_detect` | Active | active | 80+ technology fingerprints: HTML/scripts/headers/meta/cookies/favicon MD5 |
| `js_analysis` | Active | active | Downloads JS files; extracts endpoints; scans for 15 secret patterns (AWS, tokens, JWTs…) |
| `dir_scan` | Active | active | Soft-404 calibrated path scan; content-verifies 30 exposed file types |
| `email_harvest` | Active | active | Multi-page crawl across apex + subdomains; filters noise/malformed addresses |
| `ping` | Diagnostics | active | 4-packet ICMP ping; parses avg latency (Windows + Unix) |
| `traceroute` | Diagnostics | active | Max 20 hops; reports hop count; handles ICMP-filtered targets |

---

## Output Formats

All output lands in `results/<domain>/` (or `--output-dir`).

| Format | File | Contents |
|--------|------|----------|
| `text` | `<domain>_<ts>.txt` | Full human-readable report, all sections |
| `json` | `<domain>_<ts>.json` | Complete `ScanResult` Pydantic model as JSON |
| `csv` | `<domain>_<ts>_subdomains.csv` etc. | One CSV per tabular module (subdomains, ports, paths, JS endpoints) |
| subdomain list | `<domain>_<ts>_subdomains.txt` | Plain hostname list, one per line — pipe to httpx/nuclei/ffuf |

---

## Configuration

Copy `config.yaml.example` to `config.yaml` and fill in any API keys you have. All keys are optional — the tool works without them.

```yaml
api_keys:
  shodan: ""
  virustotal: ""
  securitytrails: ""
  alienvault: ""         # free, no key required for basic OTX

proxy:
  enabled: false
  url: ""                # socks5://127.0.0.1:9050
  tor_autodetect: true   # auto-enable if Tor is detected on localhost:9050

scan:
  axfr_attempt: true
  js_analysis: true
  subdomain_permutations: true
  external_tools: true   # use subfinder/amass/nmap if in PATH
```

API keys can also be set via environment variables (override config file):

```
SHODAN_API_KEY=xxx
VT_API_KEY=xxx
SECURITYTRAILS_API_KEY=xxx
OTX_API_KEY=xxx
RECON_PROXY=socks5://127.0.0.1:9050
```

---

## Reading the Results

### Critical findings to look for

**Zone transfer success** (`axfr`) — the authoritative NS returned the full DNS zone. Every hostname, IP, and record in the domain is now enumerated. Critical misconfiguration.

**Exposed files** (`dir_scan`) — `.git/`, `.env`, PHP config, SQL dumps verified by body content (not just HTTP 200). These routinely contain credentials, API keys, and database connection strings.

**JS secrets** (`js_analysis`) — potential API keys, tokens, or credentials found in JavaScript source. Secret values are masked in output; context is shown.

**DMARC p=none** (`dns`) — domain accepts delivery of spoofed email. Anyone can send from `@example.com`.

**SPF +all / ?all** (`dns`) — SPF policy explicitly or implicitly permits any sender.

**Missing HSTS / CSP** (`headers`) — grade below B indicates missing or misconfigured security headers.

**CDN detected** (`cdn`) — geolocation, port scan, and traceroute reflect the CDN edge node. Origin infrastructure is hidden behind it. Check origin IP hints in the CDN report.

**TLS flags** (`tls`) — expired certificate, TLS 1.0/1.1 accepted, RSA key under 2048-bit, SHA-1 signature, or weak cipher suites.

---

## Project Structure

```
recon.py                  ← entry point (--gui → GUI, else CLI)
recon/
  cli.py                  ← typer CLI + rich progress display
  engine.py               ← 6-phase async scan orchestrator
  config.py               ← pydantic config (YAML + env vars)
  models.py               ← pydantic result models
  output.py               ← json / text / csv / subdomain-list writers
  rate_limiter.py         ← token bucket, per-service
  http_client.py          ← aiohttp session factory, rate-limited safe_get
  modules/
    dns/                  ← records, axfr, permutations
    passive/              ← ct_logs, wayback, domain_whois, email_harvest, api_sources
    active/               ← subdomain_enum, port_scan, dir_scan, tls_analysis,
    │                        tech_detect, headers, js_analysis
    network/              ← cdn_detect, geo, ip_whois, ping_trace
gui/
  app.py                  ← tkinter wrapper around Engine
wordlists/
  subdomains.txt          ← ~1000 subdomain prefixes
  paths.txt               ← ~500 admin/sensitive paths
fingerprints/
  technologies.json       ← 80+ Wappalyzer-format tech fingerprints
config.yaml.example       ← documented config template
DeepWebRecon.py           ← original monolithic GUI (still works standalone)
```

---

## Legacy GUI

`DeepWebRecon.py` is kept as a standalone fallback. It has no external dependency beyond `requests`, `dnspython`, `ipwhois`, and `pillow`, and runs without the full `requirements.txt`. Launch with `python DeepWebRecon.py` or the `run.vbs` double-click launcher.

---

> This tool is intended for **educational** and **authorized security testing** purposes only.
