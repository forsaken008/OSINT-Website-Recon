from __future__ import annotations

"""CDN detection from response headers and ASN data."""

from loguru import logger

from ...http_client import build_session, safe_get
from ...models import CDNResult, ScanResult
from ..base import BaseModule

# Known CDN header signatures: (header_name, substring_in_value, provider)
_CDN_HEADERS: list[tuple[str, str, str]] = [
    ("CF-Ray",           "",              "Cloudflare"),
    ("CF-Cache-Status",  "",              "Cloudflare"),
    ("Server",           "cloudflare",    "Cloudflare"),
    ("X-Served-By",      "",              "Fastly"),
    ("X-Cache",          "HIT",           "Fastly/CDN"),
    ("X-Cache",          "cloudfront",    "Amazon CloudFront"),
    ("Via",              "cloudfront",    "Amazon CloudFront"),
    ("X-CDN",            "",              "CDN"),
    ("Server",           "ECS",           "Akamai"),
    ("X-Check-Cacheable","",              "Akamai"),
    ("X-Varnish",        "",              "Varnish/Fastly"),
    ("Via",              "varnish",       "Varnish/Fastly"),
    ("Server",           "sucuri",        "Sucuri WAF"),
    ("X-Sucuri-ID",      "",              "Sucuri WAF"),
    ("X-Iinfo",          "",              "Incapsula"),
    ("X-CDN-Geo",        "",              "Incapsula"),
    ("Server",           "keycdn",        "KeyCDN"),
    ("X-Edge-IP",        "",              "CDN"),
    ("X-Azure-Ref",      "",              "Azure CDN"),
    ("X-Cache-Hits",     "",              "nginx/CDN"),
]

# Known CDN ASN numbers
_CDN_ASNS: dict[str, str] = {
    "13335": "Cloudflare",
    "54113": "Fastly",
    "20940": "Akamai",
    "16509": "Amazon CloudFront",
    "15169": "Google Cloud/CDN",
    "8075":  "Microsoft Azure",
    "30148": "Sucuri",
    "22120": "Incapsula",
    "46606": "Unified Layer",
    "55286": "B2 Net Solutions",
}


class CDNDetectModule(BaseModule):
    name = "cdn"
    label = "CDN Detection"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"CDN detection for {domain}")

        cdn_result = CDNResult()
        evidence: list[str] = []
        provider_votes: dict[str, int] = {}

        session = await build_session(self.config, service="target", timeout_secs=10)
        try:
            resp = await safe_get(session, f"https://{domain}", service="target")
            if resp is None:
                resp = await safe_get(session, f"http://{domain}", service="target")
            if resp is None:
                result.cdn = cdn_result
                return result

            headers = {k.lower(): v for k, v in resp.headers.items()}

            for hdr, value_contains, provider in _CDN_HEADERS:
                hdr_lower = hdr.lower()
                val = headers.get(hdr_lower, "")
                if val and (not value_contains or value_contains.lower() in val.lower()):
                    provider_votes[provider] = provider_votes.get(provider, 0) + 1
                    evidence.append(f"{hdr}: {val[:60]}")

            # Origin IP hints from response headers
            origin_hints: list[str] = []
            for hint_header in ("x-real-ip", "x-forwarded-for", "x-origin-ip", "x-original-ip"):
                val = headers.get(hint_header, "")
                if val:
                    origin_hints.append(f"{hint_header}: {val}")
        finally:
            await session.close()

        # ASN-based detection
        if result.ip_info and result.ip_info.asn:
            asn_num = result.ip_info.asn.replace("AS", "").strip()
            if asn_num in _CDN_ASNS:
                provider = _CDN_ASNS[asn_num]
                provider_votes[provider] = provider_votes.get(provider, 0) + 3
                evidence.append(f"ASN {asn_num} belongs to {provider}")

        if provider_votes:
            top_provider = max(provider_votes, key=lambda k: provider_votes[k])
            cdn_result.detected = True
            cdn_result.provider = top_provider
            cdn_result.evidence = evidence
            cdn_result.origin_hints = origin_hints
            self.warn(
                f"CDN detected: {top_provider} — IP/geolocation/ports reflect CDN edge, not origin"
            )
            if origin_hints:
                self.info(f"Origin IP hints found: {origin_hints}")
        else:
            self.success("No CDN detected")

        # Mark geolocation result as CDN edge if CDN detected
        if cdn_result.detected and result.geolocation:
            result.geolocation.cdn_edge = True

        result.cdn = cdn_result
        result.modules_run.append(self.name)
        return result
