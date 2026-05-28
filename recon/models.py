"""Pydantic data models for every module result and the top-level ScanResult."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── DNS ──────────────────────────────────────────────────────────────────────

class SPFAnalysis(BaseModel):
    raw: str
    includes: list[str] = []
    ip4_ranges: list[str] = []
    ip6_ranges: list[str] = []
    all_mechanism: str = ""    # "+all", "-all", "~all", "?all", ""
    flags: list[str] = []      # human-readable warnings


class DMARCRecord(BaseModel):
    raw: str
    policy: str = ""           # none / quarantine / reject
    subdomain_policy: str = ""
    pct: int = 100
    rua: list[str] = []
    ruf: list[str] = []
    flags: list[str] = []


class DKIMRecord(BaseModel):
    selector: str
    raw: str
    key_type: str = ""
    key_bits: Optional[int] = None


class CAARecord(BaseModel):
    tag: str       # issue / issuewild / iodef
    value: str


class DNSResult(BaseModel):
    records: dict[str, list[str]] = {}   # {"A": ["1.2.3.4"], "MX": [...]}
    spf_analysis: Optional[SPFAnalysis] = None
    dmarc: Optional[DMARCRecord] = None
    dkim_records: list[DKIMRecord] = []
    caa_records: list[CAARecord] = []
    axfr_success: bool = False
    axfr_records: list[str] = []
    errors: dict[str, str] = {}


# ── Domain WHOIS ──────────────────────────────────────────────────────────────

class DomainWhoisResult(BaseModel):
    registrar: Optional[str] = None
    created: Optional[str] = None
    expires: Optional[str] = None
    updated: Optional[str] = None
    status: list[str] = []
    name_servers: list[str] = []
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    dnssec: Optional[str] = None
    expiry_warning: bool = False    # True if <30 days to expiry
    raw: Optional[str] = None


# ── IP / Network ──────────────────────────────────────────────────────────────

class IPInfoResult(BaseModel):
    ip: str
    asn: str = ""
    asn_description: str = ""
    network_name: str = ""
    cidr: str = ""
    country: str = ""
    error: Optional[str] = None


# ── Geolocation ───────────────────────────────────────────────────────────────

class GeolocationResult(BaseModel):
    ip: str
    city: str = ""
    region: str = ""
    country: str = ""
    lat: float = 0.0
    lon: float = 0.0
    isp: str = ""
    org: str = ""
    cdn_edge: bool = False
    source: str = ""


# ── CDN ───────────────────────────────────────────────────────────────────────

class CDNResult(BaseModel):
    detected: bool = False
    provider: str = ""
    evidence: list[str] = []
    origin_hints: list[str] = []    # potential origin IP hints


# ── Certificate Transparency ──────────────────────────────────────────────────

class CTLogsResult(BaseModel):
    domains: list[str] = []
    total_certs: int = 0
    source: str = "crt.sh"


# ── Subdomain Enumeration ─────────────────────────────────────────────────────

class SubdomainFinding(BaseModel):
    host: str
    ip: Optional[str] = None
    sources: list[str] = []
    cdn: bool = False
    cdn_provider: Optional[str] = None


# ── Ports ─────────────────────────────────────────────────────────────────────

class PortFinding(BaseModel):
    port: int
    state: str          # open / closed / filtered
    service: str = ""
    version: Optional[str] = None
    banner: Optional[str] = None


# ── TLS ───────────────────────────────────────────────────────────────────────

class TLSResult(BaseModel):
    subject_cn: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    key_type: str = ""
    key_bits: int = 0
    sig_algorithm: str = ""
    sans: list[str] = []
    protocols_accepted: list[str] = []
    protocols_rejected: list[str] = []
    cipher_suites: list[str] = []
    weak_ciphers: list[str] = []
    hsts: bool = False
    hsts_max_age: int = 0
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False
    ocsp_stapling: bool = False
    ct_logs_embedded: bool = False
    flags: list[str] = []           # warnings / findings
    sslyze_used: bool = False


# ── HTTP & Security Headers ───────────────────────────────────────────────────

class HeaderAnalysisItem(BaseModel):
    header: str
    status: str     # pass / warn / fail
    detail: str


class HeadersResult(BaseModel):
    final_url: str = ""
    status_code: int = 0
    raw_headers: dict[str, str] = {}
    server: str = ""
    https_redirect: bool = False
    security_analysis: list[HeaderAnalysisItem] = []
    score: str = ""    # A / B / C / D / F (overall grade)


# ── Technology Fingerprinting ─────────────────────────────────────────────────

class TechFinding(BaseModel):
    name: str
    version: Optional[str] = None
    confidence: int = 100
    categories: list[str] = []


# ── Directory / Admin Panel Scanning ─────────────────────────────────────────

class DirectoryFinding(BaseModel):
    url: str
    status: int
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    redirect_to: Optional[str] = None


class ExposedFileFinding(BaseModel):
    url: str
    status: int
    verification: str   # e.g. "body contains [core]" / "body contains KEY= pattern"
    content_length: Optional[int] = None


# ── Wayback Machine ───────────────────────────────────────────────────────────

class WaybackResult(BaseModel):
    total_urls: int = 0
    unique_paths: list[str] = []
    all_urls: list[str] = []
    interesting: list[str] = []    # flagged paths


# ── Email Harvesting ──────────────────────────────────────────────────────────

# Top-level result is just list[str] on ScanResult.emails


# ── JavaScript Analysis ───────────────────────────────────────────────────────

class SecretFinding(BaseModel):
    pattern_name: str
    script_url: str
    context: str    # surrounding characters (not the full secret)


class JSAnalysisResult(BaseModel):
    scripts_analysed: int = 0
    endpoints: list[str] = []
    potential_secrets: list[SecretFinding] = []


# ── Ping / Traceroute ─────────────────────────────────────────────────────────

class PingResult(BaseModel):
    output: str = ""
    reachable: bool = False
    avg_ms: Optional[float] = None


class TracerouteResult(BaseModel):
    output: str = ""
    hops: int = 0
    timed_out: bool = False


# ── Top-level Scan Result ─────────────────────────────────────────────────────

class ScanResult(BaseModel):
    target: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    modules_run: list[str] = []
    errors: dict[str, str] = {}

    # Module results (all optional — only populated for enabled modules)
    dns: Optional[DNSResult] = None
    domain_whois: Optional[DomainWhoisResult] = None
    ip_info: Optional[IPInfoResult] = None
    geolocation: Optional[GeolocationResult] = None
    cdn: Optional[CDNResult] = None
    ct_logs: Optional[CTLogsResult] = None
    subdomains: list[SubdomainFinding] = []
    ports: list[PortFinding] = []
    tls: Optional[TLSResult] = None
    headers: Optional[HeadersResult] = None
    technologies: list[TechFinding] = []
    directories: list[DirectoryFinding] = []
    exposed_files: list[ExposedFileFinding] = []
    wayback: Optional[WaybackResult] = None
    emails: list[str] = []
    js_findings: Optional[JSAnalysisResult] = None
    ping: Optional[PingResult] = None
    traceroute: Optional[TracerouteResult] = None
