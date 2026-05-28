from __future__ import annotations

import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional, TextIO

from pydantic import BaseModel

from .models import ScanResult


class OutputFormat:
    JSON = "json"
    CSV = "csv"
    TEXT = "text"


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def write_json(result: ScanResult, dest: Path | TextIO) -> None:
    data = result.model_dump(mode="json", exclude_none=True)
    text = json.dumps(data, indent=2, default=_json_default, ensure_ascii=False)
    if isinstance(dest, Path):
        dest.write_text(text, encoding="utf-8")
    else:
        dest.write(text)
        dest.write("\n")


def write_text(result: ScanResult, dest: Path | TextIO) -> None:
    """Human-readable report — mirrors the original log format."""
    lines: list[str] = []

    def sep(title: str) -> None:
        bar = "=" * 42
        lines.append(f"\n{bar}\n[ {title.upper()} ]\n{bar}")

    lines.append(f"[*] Surface Recon — target: {result.target}")
    lines.append(f"[*] Scan started: {result.started_at.isoformat()}")

    if result.dns:
        sep("DNS Records")
        for rtype, values in result.dns.records.items():
            for v in values:
                lines.append(f"  {rtype}: {v}")
        if result.dns.spf_analysis:
            lines.append(f"\n  SPF: {result.dns.spf_analysis.raw}")
            if result.dns.spf_analysis.flags:
                for f in result.dns.spf_analysis.flags:
                    lines.append(f"  [!] {f}")
        if result.dns.dmarc:
            lines.append(f"\n  DMARC: {result.dns.dmarc.raw}")
            lines.append(f"  Policy: {result.dns.dmarc.policy}")
        if result.dns.axfr_success:
            lines.append("\n  [!] ZONE TRANSFER SUCCEEDED")
            for r in result.dns.axfr_records:
                lines.append(f"    {r}")

    if result.domain_whois:
        sep("Domain WHOIS")
        w = result.domain_whois
        for k, v in w.model_dump(exclude_none=True).items():
            lines.append(f"  {k}: {v}")

    if result.ip_info:
        sep("IP & Network (RDAP)")
        i = result.ip_info
        lines.append(f"  IP: {i.ip}")
        lines.append(f"  ASN: {i.asn}  ({i.asn_description})")
        lines.append(f"  Network: {i.network_name}  CIDR: {i.cidr}")
        lines.append(f"  Country: {i.country}")

    if result.geolocation:
        sep("Geolocation")
        g = result.geolocation
        lines.append(f"  City: {g.city}, {g.region}, {g.country}")
        lines.append(f"  ISP: {g.isp}")
        lines.append(f"  Coordinates: {g.lat},{g.lon}")
        lines.append(f"  Map: https://www.google.com/maps?q={g.lat},{g.lon}")
        if g.cdn_edge:
            lines.append("  [!] IP belongs to a CDN — location is edge node, not origin")

    if result.cdn:
        sep("CDN Detection")
        c = result.cdn
        if c.detected:
            lines.append(f"  Provider: {c.provider}")
            lines.append(f"  Evidence: {', '.join(c.evidence)}")
            lines.append("  [!] Port scan and geolocation reflect CDN, not origin")
        else:
            lines.append("  No CDN detected")

    if result.subdomains:
        sep("Subdomain Enumeration")
        lines.append(f"  Found: {len(result.subdomains)}")
        for s in sorted(result.subdomains, key=lambda x: x.host):
            ip_str = f" -> {s.ip}" if s.ip else " (unresolved)"
            cdn_str = f" [CDN:{s.cdn_provider}]" if s.cdn else ""
            lines.append(f"  {s.host}{ip_str}{cdn_str}  [{', '.join(s.sources)}]")

    if result.ports:
        sep("Open Ports")
        for p in sorted(result.ports, key=lambda x: x.port):
            ver = f"  {p.version}" if p.version else ""
            lines.append(f"  {p.port:5d}/tcp  {p.state:8s}  {p.service}{ver}")

    if result.tls:
        sep("TLS / SSL Analysis")
        t = result.tls
        lines.append(f"  Subject CN: {t.subject_cn}")
        lines.append(f"  Issuer: {t.issuer}")
        lines.append(f"  Valid: {t.not_before} → {t.not_after}")
        lines.append(f"  Key: {t.key_type} {t.key_bits}-bit  Sig: {t.sig_algorithm}")
        lines.append(f"  Protocols accepted: {', '.join(t.protocols_accepted)}")
        lines.append(f"  SANs: {', '.join(t.sans[:10])}{'...' if len(t.sans) > 10 else ''}")
        for flag in t.flags:
            lines.append(f"  [!] {flag}")

    if result.headers:
        sep("HTTP & Security Headers")
        h = result.headers
        for hdr, val in h.raw_headers.items():
            lines.append(f"  {hdr}: {val}")
        lines.append("")
        for item in h.security_analysis:
            icon = "✓" if item.status == "pass" else ("!" if item.status == "warn" else "✗")
            lines.append(f"  [{icon}] {item.header}: {item.detail}")

    if result.technologies:
        sep("Technology Fingerprinting")
        for t in result.technologies:
            ver = f" {t.version}" if t.version else ""
            lines.append(f"  {t.name}{ver}  (confidence: {t.confidence}%)")

    if result.directories:
        sep("Admin Panels & Sensitive Paths")
        for d in result.directories:
            lines.append(f"  {d.url}  [{d.status}]  {d.content_type or ''}")

    if result.exposed_files:
        sep("Exposed Files — VERIFIED")
        for f in result.exposed_files:
            lines.append(f"  [!] {f.url}  [{f.status}]  {f.verification}")

    if result.ct_logs:
        sep("Certificate Transparency Logs")
        lines.append(f"  Unique domains in CT logs: {len(result.ct_logs.domains)}")
        for d in sorted(result.ct_logs.domains)[:50]:
            lines.append(f"  {d}")
        if len(result.ct_logs.domains) > 50:
            lines.append(f"  ... and {len(result.ct_logs.domains) - 50} more")

    if result.wayback:
        sep("Wayback Machine — URL Harvest")
        w = result.wayback
        lines.append(f"  Total archived URLs: {w.total_urls}")
        lines.append(f"  Unique paths: {len(w.unique_paths)}")
        if w.interesting:
            lines.append(f"\n  Flagged interesting paths ({len(w.interesting)}):")
            for item in w.interesting:
                lines.append(f"  [!] {item}")

    if result.emails:
        sep("Email Addresses Found")
        for e in sorted(result.emails):
            lines.append(f"  {e}")

    if result.js_findings:
        sep("JavaScript Analysis")
        js = result.js_findings
        lines.append(f"  Scripts analysed: {js.scripts_analysed}")
        if js.endpoints:
            lines.append(f"\n  Endpoints ({len(js.endpoints)}):")
            for ep in sorted(js.endpoints)[:50]:
                lines.append(f"  {ep}")
        if js.potential_secrets:
            lines.append(f"\n  Potential secrets ({len(js.potential_secrets)}):")
            for s in js.potential_secrets:
                lines.append(f"  [!] {s.pattern_name} in {s.script_url}: ...{s.context}...")

    if result.ping:
        sep("Ping")
        lines.append(result.ping.output)

    if result.traceroute:
        sep("Traceroute")
        lines.append(result.traceroute.output)

    if result.domain_whois and result.domain_whois.expiry_warning:
        lines.append(f"\n[!] WARNING: domain expires in less than 30 days!")

    lines.append(f"\n[✔] Scan complete — {result.finished_at.isoformat() if result.finished_at else 'in progress'}")

    text = "\n".join(lines) + "\n"
    if isinstance(dest, Path):
        dest.write_text(text, encoding="utf-8")
    else:
        dest.write(text)


def write_csv(result: ScanResult, output_dir: Path) -> list[Path]:
    """Write one CSV per module that has tabular data. Returns list of created files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    base = f"{result.target}_{result.started_at.strftime('%Y%m%d_%H%M%S')}"

    if result.subdomains:
        p = output_dir / f"{base}_subdomains.csv"
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["host", "ip", "cdn", "cdn_provider", "sources"])
            w.writeheader()
            for s in result.subdomains:
                w.writerow({
                    "host": s.host, "ip": s.ip or "",
                    "cdn": s.cdn, "cdn_provider": s.cdn_provider or "",
                    "sources": "|".join(s.sources),
                })
        written.append(p)

    if result.ports:
        p = output_dir / f"{base}_ports.csv"
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["port", "state", "service", "version"])
            w.writeheader()
            for pt in result.ports:
                w.writerow({"port": pt.port, "state": pt.state, "service": pt.service, "version": pt.version or ""})
        written.append(p)

    if result.directories or result.exposed_files:
        p = output_dir / f"{base}_paths.csv"
        all_paths = list(result.directories or []) + list(result.exposed_files or [])
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["url", "status", "type"])
            w.writeheader()
            for item in all_paths:
                w.writerow({
                    "url": item.url, "status": item.status,
                    "type": getattr(item, "verification", "directory"),
                })
        written.append(p)

    if result.js_findings and result.js_findings.endpoints:
        p = output_dir / f"{base}_endpoints.csv"
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["endpoint"])
            w.writeheader()
            for ep in sorted(result.js_findings.endpoints):
                w.writerow({"endpoint": ep})
        written.append(p)

    return written


def write_subdomain_list(result: ScanResult, dest: Path) -> None:
    """Plain list of discovered hosts, one per line — suitable for piping to httpx/nuclei."""
    if result.subdomains:
        dest.write_text(
            "\n".join(sorted(s.host for s in result.subdomains)) + "\n",
            encoding="utf-8",
        )
