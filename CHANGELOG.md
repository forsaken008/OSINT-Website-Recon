# Surface Recon — Changelog

---

## v2.0 — Complete Async Rewrite (2026-05-27)

### Architecture

- Entire scan engine extracted from the GUI into a standalone `recon/` package — zero Tkinter imports in any engine file
- All I/O rewritten as async: `aiohttp` replaces `requests`, `aiodns` replaces blocking DNS resolvers
- Pydantic v2 models replace raw dicts/strings for all module output — strongly typed, JSON-serialisable, diffable
- Token-bucket rate limiter (`recon/rate_limiter.py`) enforces per-service limits with jitter to prevent thundering-herd bursts against external APIs
- 6-phase scan orchestrator (`recon/engine.py`) runs modules in dependency order; phases that have no cross-dependencies run fully in parallel via `asyncio.gather`
- `loguru` replaces all `print()` / silent `except:` patterns throughout
- `recon.py` root entry point: `--gui` flag launches Tkinter GUI, otherwise delegates to Typer CLI

### New CLI (`recon/cli.py`)

- `python recon.py example.com` — full scan with live `rich` progress display
- `--output text,json,csv` — one or more output formats in a single run
- `--output-dir` — explicit output directory (defaults to `results/<domain>/`)
- `--modules dns,ct_logs,subdomains` — run any subset of modules
- `--passive-only` — only passive modules; no outbound connections to the target
- `--thorough` — enable all optional features (AXFR, JS analysis, subdomain permutations, external tools)
- `--skip` — exclude specific modules
- `--proxy socks5://127.0.0.1:9050` — per-session proxy / Tor routing
- `--quiet` — suppress progress output (file output only)
- `--subdomain-list` — write plain host list for piping to httpx/nuclei
- `python recon.py modules` — list all 19 modules with phase and active/passive type
- Graceful Ctrl+C — sets asyncio cancellation event, waits for current module to finish before exiting

### New GUI (`gui/app.py`)

- Thin Tkinter wrapper over `Engine` — same dark/neon aesthetic, all scan logic removed from the GUI layer
- Engine runs in a background thread with its own `asyncio` event loop; communicates back to Tkinter via `queue.Queue` drained by `root.after(50)`
- Module checkboxes grouped by phase: Foundation / Passive OSINT / Enumeration / Network / Active / Diagnostics (19 modules, up from 16 sections)
- Output format checkboxes (text / json / csv) replace hardcoded text-only log
- "Open Results" button opens the per-domain output directory (not just a single file)
- Cancellation properly signals the asyncio event from the Tkinter thread via `loop.call_soon_threadsafe`

### New Modules

- **`axfr`** — DNS zone transfer attempt against every NS record; reports full zone contents on success
- **`domain_whois`** (`python-whois`) — registrar, creation/expiry/updated dates, nameservers, registrant, DNSSEC; flags domains expiring within 30 days
- **`ct_logs`** — certificate transparency via crt.sh JSON API; returns all unique domains/subdomains ever seen in CT logs for the target
- **`api_sources`** — Shodan (host info, open ports, CVEs), VirusTotal (subdomain enum), AlienVault OTX (passive DNS, no key required), SecurityTrails; all gracefully no-op when keys are absent
- **`wayback`** — CDX API full URL harvest (up to 50,000 URLs, not a single snapshot); flags 15 interesting patterns (SQL files, archives, `.git`/`.env` refs, sensitive query params, admin paths)
- **`cdn`** — CDN detection from 19 response header signatures + 10 ASN mappings; consensus-votes across signals; reports origin IP hints from leak headers; marks geolocation result as CDN edge
- **`tls`** — deep TLS analysis via `sslyze` (with manual SSL socket fallback); reports all accepted/rejected protocol versions, cipher suites, weak ciphers, cert expiry, key size/type, OCSP stapling, CT embedding, Heartbleed, ROBOT, HSTS via TLS
- **`tech_detect`** — Wappalyzer-style fingerprinting from `fingerprints/technologies.json`; matches HTML patterns, script URLs, response headers, meta tags, cookies, and favicon MD5 hash; 80+ technologies
- **`js_analysis`** — downloads and analyses all same-domain JS files (cap: 30 scripts, 2 MB each); extracts endpoint URLs via regex; scans for 15 secret patterns (AWS keys, Bearer tokens, Stripe, Slack, GitHub tokens, JWT, Basic auth URLs, hardcoded passwords); masks actual secret values in output
- **`dir_scan`** — GET-based path scan with soft-404 calibration (MD5 baseline against 2 random paths to suppress false positives); content-verifies 30 exposed file types (`.git`, `.env`, PHP configs, SQL dumps, etc.) by checking body signatures, not just HTTP status
- **`email_harvest`** (expanded) — crawls up to 50 pages across the apex domain and up to 10 discovered subdomains; explicitly checks `/contact`, `/about`, `/team`, `/support`; filters noise domains and malformed addresses

### Improved Existing Modules

- **`subdomains`** — aiodns brute-force (semaphore=200) replaces ThreadPoolExecutor; resolves against a pool of 5 resolvers; confirms positives against 2 distinct resolvers; adds permutation generation from known labels; passthrough to subfinder/amass if in PATH; seeds from CT logs before brute-force
- **`ports`** — nmap `-sV -sC -T4 --open -oX -` with XML parser as tier 1; async TCP connect as fallback; 33 service mappings; reports service version strings
- **`headers`** — HSTS (max-age + includeSubDomains + preload), CSP (unsafe-inline/eval/wildcard/http: source detection), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Set-Cookie flag analysis (HttpOnly/Secure/SameSite), server version disclosure; produces A/B+/B/C/D/F grade
- **`dns`** — adds CAA records, SRV records, PTR reverse lookup; parses SPF (flags +all/?all/missing `all`/lookup-limit exceeded), DMARC (flags p=none/pct<100/missing rua), DKIM (probes 15 selectors)
- **`geo`** — primary: ip-api.com (HTTPS); fallback: ipinfo.io; marks result as CDN edge when CDN is detected
- **`ping`** / **`traceroute`** — max hops increased from 15 → 20 for traceroute; avg latency parsed from output on both Windows and Unix

### Output System (`recon/output.py`)

- `write_json` — full `ScanResult` serialised via Pydantic `.model_dump(mode="json")`
- `write_text` — human-readable report with all sections, matches original log format
- `write_csv` — one CSV per module that has tabular data (subdomains, ports, paths, JS endpoints)
- `write_subdomain_list` — plain hostname list, one per line, for piping to httpx/nuclei/ffuf

### Data Files

- `wordlists/subdomains.txt` — ~1000 curated subdomain prefixes (infrastructure, cloud, DevOps, CDN, auth, monitoring, databases, CI/CD, VPN, messaging)
- `wordlists/paths.txt` — ~500 path entries (admin panels, CMS backends, exposed credentials/config/git artifacts, backup archives, CI/CD tooling, monitoring dashboards, API/swagger, authentication endpoints)
- `fingerprints/technologies.json` — 80+ Wappalyzer-format technology fingerprints
- `config.yaml.example` — fully documented configuration template

### Config & Credentials

- `config.yaml` (YAML, optional) — centralises API keys, rate limits, DNS resolvers, proxy, wordlist paths, and scan-behaviour flags
- All API keys also readable from environment variables: `SHODAN_API_KEY`, `VT_API_KEY`, `SECURITYTRAILS_API_KEY`, `OTX_API_KEY`, `RECON_PROXY`

### Bug Fix

- `VT_API_KEY` environment variable was mapping to `("virustotal", "virustotal")` instead of `("api_keys", "virustotal")` — key was silently ignored

---

## v1.x — GUI Iteration (earlier)

### Bug Fixes

- Fixed thread-unsafe Tkinter access — scan thread no longer touches widgets directly; all updates go through a `queue.Queue` drained by `root.after()` on the main thread (P1)
- Fixed `messagebox` called from background thread (P1)
- Fixed start button never disabling, allowing multiple concurrent scan threads (P1)
- Fixed bare `except:` clauses swallowing `KeyboardInterrupt`/`SystemExit` (P1)
- Fixed SSL certificate RDN parsing crashing on multi-valued RDNs (P1)
- Fixed `btn()` factory `TypeError: multiple values for keyword argument 'fg'` crash on startup (P8)
- Fixed placeholder validation — old guard `"enter your victim url"` didn't match new placeholder, causing `/` in the string to produce an invalid log file path, crashing the scan thread before the done signal and locking the UI (P13)
- Fixed UI permanently locking after scan — root cause was `open()` using Windows cp1252 encoding; `✔`, `–`, `✕` characters raised `UnicodeEncodeError` mid-scan before the done signal was sent. Fixed with `encoding="utf-8"` and `try/except` in `write_log` (P14)
- Fixed done signal not sent if log file creation fails — `open()` now called in its own `try/except` before the `with` block (P18)
- Fixed geolocation `requests.get` hanging with no timeout — added `timeout=7` (P18)
- Fixed Delete Logs wiping `.gitkeep` placeholder file (P18)

### Features

- Added collapsible Advanced Options panel — toggle button reveals 16 checkboxes (one per scan section), all enabled by default; includes Select All / Clear All convenience buttons; enabled flags collected on the main thread before the scan starts and passed into `deep_recon()` as a plain dict (P20)
- Advanced Options panel auto-collapses on any click outside it; also collapses when Enter is pressed or Start Deep Recon is clicked (P21)
- Added validation: if Start is triggered with all sections unchecked, a popup reads "No scanning tools selected, please select a scanning tool and run again." (P21)
- Pulled IP resolution out of the WHOIS block into a shared step so Geolocation, Port Scanner, and Full Port Scan receive a valid IP even when the WHOIS section is unchecked (P20)
- Added Cancel button — sets a `threading.Event` checked before each scan section; saves partial log (P2)
- Added Clear Output button (P2)
- Added Open Log File button — cross-platform (`os.startfile` / `open` / `xdg-open`) (P2)
- Added common port scanner (17 ports, 1s timeout, parallel) as scan section 10 (P2)
- Added robots.txt & sitemap fetch as scan section 14 (P2)
- Added full port scan (1–65535, 500 threads, 0.5s timeout) — initially standalone button (P3), later merged as final section of deep recon (P16)
- Added Delete Logs button — confirmation dialog, skips `.gitkeep` (P15)
- Added URL entry placeholder that clears on focus and restores on blur (P12)
- Added Enter key binding on URL field to trigger scan (P12)
- Suppressed cmd window popup during ping and traceroute (`CREATE_NO_WINDOW`) (P17)
- Auto-scroll now only fires when user is at the bottom — free scrolling during scan (P17)
- Homepage response cached and reused across HTTP headers, CMS detection, and email harvesting sections (P1)

### UI

- Full dark mode — `DARK` palette dict, flat buttons, `hand2` cursor, accent green / danger red (P6)
- Neon green (`#39ff14`) output text (P7)
- Layout overhauled — grid-based control panel with full-width entries, buttons split left (actions) / right (utilities), resizable window, scrollbar on log output (P7)
- App icon — circular cropped radar PNG loaded via `tk.PhotoImage` / `iconphoto()` (P10, P11)

### Infrastructure

- `requirements.txt` replaced — original listed stdlib modules that can't be pip-installed; now contains only `requests`, `dnspython`, `ipwhois`, `pillow` (P1, P5)
- `run.bat` added — launches via `pythonw` (no console), uses `start ""` to detach so cmd closes immediately, uses `%~dp0` for portability (P5, P8, P9)
- `run.bat` replaced by `run.vbs` — VBScript launcher runs `pythonw.exe` with window style `0` (fully hidden); `wscript.exe` has no console by default so there is zero cmd flash on double-click (P20)
- `logs/` folder created — output directory defaults to `logs/` next to the script; `logs/*.txt` gitignored, `.gitkeep` keeps folder in repo (P5)
- `assets/` folder — icon moved from `icon/` (P19)
- `Installation.txt` removed — superseded by README (P19)
- `PLACEHOLDER` promoted to module-level constant (P13)
- Domain sanitised with `re.sub` before use in filenames — strips Windows-illegal characters (P13)

### Cleanup

- Removed unused imports: `json`, `from urllib.parse import urlparse`, `random` (P1, P4)
- Removed dead `COMMON_SUBDOMAINS` constant (P4)
- Moved `TOTAL_PORTS` to module level (P4)
- Renamed `wlog` → `write_log`, `l` → `ln` for clarity (P4)
- Changed futures dict to list in port scan (P4)
- `_full_port_scan_thread` and `run_full_port_scan` removed after merge into `deep_recon` (P16)
- `_on_scan_done` `is_full_scan` parameter removed (P16)
