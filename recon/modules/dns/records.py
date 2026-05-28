from __future__ import annotations

import asyncio
import re
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.rdatatype
from loguru import logger

from ...config import Config
from ...models import (
    CAARecord,
    DKIMRecord,
    DMARCRecord,
    DNSResult,
    ScanResult,
    SPFAnalysis,
)
from ..base import BaseModule

# Common DKIM selectors to probe
_DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "selector1", "selector2",
    "smtp", "dkim", "key1", "key2", "mx", "s1", "s2",
    "zoho", "sendgrid", "mailchimp", "mandrill", "sparkpost",
]

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "SRV"]


class DNSRecordsModule(BaseModule):
    name = "dns"
    label = "DNS Records"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"Querying DNS records for {domain}")

        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = self.config.dns.resolvers[:4]
        resolver.lifetime = self.config.dns.timeout * 2

        dns_result = DNSResult()

        # ── Standard record types ─────────────────────────────────────────────
        tasks = {rtype: _query(resolver, domain, rtype) for rtype in _RECORD_TYPES}
        raw = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for rtype, outcome in zip(tasks.keys(), raw):
            if isinstance(outcome, Exception):
                if not isinstance(outcome, (dns.exception.NXDOMAIN, dns.resolver.NoAnswer)):
                    dns_result.errors[rtype] = str(outcome)
            elif outcome:
                dns_result.records[rtype] = outcome

        # ── PTR (reverse DNS on resolved IP) ─────────────────────────────────
        if "A" in dns_result.records:
            ip = dns_result.records["A"][0]
            ptr = await _ptr_lookup(resolver, ip)
            if ptr:
                dns_result.records["PTR"] = [ptr]

        # ── SPF analysis ──────────────────────────────────────────────────────
        txt_records = dns_result.records.get("TXT", [])
        spf_record = next((r for r in txt_records if r.startswith('"v=spf1') or r.startswith('v=spf1')), None)
        if spf_record:
            dns_result.spf_analysis = _parse_spf(spf_record.strip('"'))

        # ── DMARC ─────────────────────────────────────────────────────────────
        dmarc_raw = await _query(resolver, f"_dmarc.{domain}", "TXT")
        if dmarc_raw:
            dmarc_str = " ".join(dmarc_raw).strip('"')
            if "v=DMARC1" in dmarc_str:
                dns_result.dmarc = _parse_dmarc(dmarc_str)

        # ── DKIM probe ────────────────────────────────────────────────────────
        dkim_tasks = {
            sel: _query(resolver, f"{sel}._domainkey.{domain}", "TXT")
            for sel in _DKIM_SELECTORS
        }
        dkim_results = await asyncio.gather(*dkim_tasks.values(), return_exceptions=True)
        for sel, outcome in zip(dkim_tasks.keys(), dkim_results):
            if isinstance(outcome, list) and outcome:
                raw_val = " ".join(outcome).strip('"')
                if "p=" in raw_val:
                    dns_result.dkim_records.append(_parse_dkim(sel, raw_val))

        # ── CAA record parsing ────────────────────────────────────────────────
        caa_raw = await _query_raw(resolver, domain, "CAA")
        if caa_raw:
            for rdata in caa_raw:
                dns_result.caa_records.append(
                    CAARecord(tag=str(rdata.tag), value=str(rdata.value))
                )
        elif "A" in dns_result.records:
            dns_result.errors["CAA_warning"] = "No CAA record — any CA can issue certificates for this domain"

        result.dns = dns_result
        result.modules_run.append(self.name)

        counts = {k: len(v) for k, v in dns_result.records.items()}
        self.success(f"DNS complete — {counts}")
        return result


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _query(
    resolver: dns.asyncresolver.Resolver, name: str, rtype: str
) -> list[str]:
    try:
        answers = await resolver.resolve(name, rtype, lifetime=5)
        return [r.to_text() for r in answers]
    except (dns.exception.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception as exc:
        logger.debug(f"DNS query {rtype} {name}: {exc}")
        return []


async def _query_raw(resolver, name: str, rtype: str):
    try:
        return await resolver.resolve(name, rtype, lifetime=5)
    except Exception:
        return None


async def _ptr_lookup(resolver, ip: str) -> Optional[str]:
    try:
        rev = dns.reversename.from_address(ip)
        answers = await resolver.resolve(rev, "PTR", lifetime=5)
        return answers[0].to_text().rstrip(".")
    except Exception:
        return None


def _parse_spf(raw: str) -> SPFAnalysis:
    analysis = SPFAnalysis(raw=raw)
    for part in raw.split():
        if part.startswith("include:"):
            analysis.includes.append(part[8:])
        elif part.startswith("ip4:"):
            analysis.ip4_ranges.append(part[4:])
        elif part.startswith("ip6:"):
            analysis.ip6_ranges.append(part[4:])
        elif part in ("+all", "-all", "~all", "?all", "all"):
            analysis.all_mechanism = part

    if analysis.all_mechanism == "+all":
        analysis.flags.append("+all mechanism: ANY IP may send mail — severe misconfiguration")
    elif analysis.all_mechanism == "?all":
        analysis.flags.append("?all mechanism: neutral result — effectively no enforcement")
    elif analysis.all_mechanism == "":
        analysis.flags.append("No 'all' mechanism found — incomplete SPF record")

    if len(raw.split("include:")) - 1 > 10:
        analysis.flags.append("SPF record has >10 DNS lookups — may exceed RFC 7208 limit")

    return analysis


def _parse_dmarc(raw: str) -> DMARCRecord:
    rec = DMARCRecord(raw=raw)
    for part in raw.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k, v = k.strip().lower(), v.strip()
        if k == "p":
            rec.policy = v
        elif k == "sp":
            rec.subdomain_policy = v
        elif k == "pct":
            try:
                rec.pct = int(v)
            except ValueError:
                pass
        elif k == "rua":
            rec.rua = [a.strip() for a in v.split(",")]
        elif k == "ruf":
            rec.ruf = [a.strip() for a in v.split(",")]

    if rec.policy == "none":
        rec.flags.append("DMARC policy=none: emails failing DMARC are NOT rejected/quarantined")
    if rec.pct < 100:
        rec.flags.append(f"DMARC pct={rec.pct}: policy only applies to {rec.pct}% of mail")
    if not rec.rua:
        rec.flags.append("No rua= reporting address — DMARC failures are not reported")

    return rec


def _parse_dkim(selector: str, raw: str) -> DKIMRecord:
    rec = DKIMRecord(selector=selector, raw=raw)
    for part in raw.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k, v = k.strip().lower(), v.strip()
        if k == "k":
            rec.key_type = v
        elif k == "p":
            # Estimate key size from base64-encoded public key length
            # RSA-2048 ≈ 392 chars; RSA-1024 ≈ 216 chars
            key_len = len(v.replace(" ", ""))
            if key_len > 0:
                if rec.key_type in ("rsa", ""):
                    rec.key_bits = int(key_len * 6 / 8 * 8)  # rough bits estimate
    return rec
