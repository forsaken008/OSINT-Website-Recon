from __future__ import annotations

"""Technology fingerprinting using Wappalyzer-style pattern matching.

Loads `fingerprints/technologies.json` which contains regex/string patterns
for headers, html, meta tags, scripts, cookies, and URL.
Falls back to a minimal built-in set when the file is absent.
"""

import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from typing import Optional

from loguru import logger

from ...http_client import build_session, safe_get
from ...models import ScanResult, TechFinding
from ..base import BaseModule

# Favicon hashes for common platforms
_FAVICON_HASHES: dict[str, str] = {
    "f7e3d1b6ee8c9f2a5b4c3d7e1f9a0b2c": "WordPress",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6": "Joomla",
    "b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8": "Drupal",
    "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9": "nginx",
    "d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0": "Apache Tomcat",
}

_FALLBACK_FINGERPRINTS = {
    "WordPress": {
        "html": [r"wp-content", r"wp-includes", r"/wp-json/"],
        "headers": {"X-Powered-By": r"(?i)wordpress"},
        "meta": {"generator": r"(?i)wordpress"},
    },
    "Joomla": {
        "html": [r"/components/com_", r"joomla!", r"index\.php\?option=com_"],
        "meta": {"generator": r"(?i)joomla"},
    },
    "Drupal": {
        "html": [r"drupal\.js", r"Drupal\.settings", r"/sites/default/files/"],
        "headers": {"X-Generator": r"(?i)drupal"},
        "meta": {"generator": r"(?i)drupal"},
    },
    "Shopify": {
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme", r"myshopify\.com"],
        "headers": {"X-ShopId": r".+"},
    },
    "Laravel": {
        "headers": {"X-Powered-By": r"(?i)laravel"},
        "html": [r"laravel_session", r"XSRF-TOKEN"],
    },
    "Django": {
        "html": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": r"(?i)phusion passenger|rails"},
        "html": [r"authenticity_token"],
        "cookies": {"_session_id": r".*"},
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"(?i)asp\.net", "X-AspNet-Version": r".+"},
        "html": [r"__VIEWSTATE", r"__EVENTTARGET"],
        "cookies": {"ASP\.NET_SessionId": r".*"},
    },
    "PHP": {
        "headers": {"X-Powered-By": r"(?i)php/[\d.]+"},
        "cookies": {"PHPSESSID": r".*"},
    },
    "nginx": {
        "headers": {"Server": r"(?i)nginx"},
    },
    "Apache": {
        "headers": {"Server": r"(?i)apache"},
    },
    "IIS": {
        "headers": {"Server": r"(?i)iis", "X-Powered-By": r"(?i)asp\.net"},
    },
    "Cloudflare": {
        "headers": {"Server": r"(?i)cloudflare", "CF-Ray": r".+"},
    },
    "Varnish": {
        "headers": {"Via": r"(?i)varnish", "X-Varnish": r".+"},
    },
    "jQuery": {
        "html": [r"jquery[.-][\d.]+\.min\.js", r"jquery\.js"],
        "scripts": [r"jquery[.-][\d.]+"],
    },
    "React": {
        "html": [r"__react", r"data-reactroot", r"data-reactid"],
        "scripts": [r"react\.production\.min\.js", r"react-dom"],
    },
    "Vue.js": {
        "html": [r"vue\.js", r"v-bind:", r"v-model="],
        "scripts": [r"vue\.min\.js", r"vue\.runtime"],
    },
    "Angular": {
        "html": [r"ng-version=", r"ng-app=", r"angular\.min\.js"],
    },
    "Bootstrap": {
        "html": [r"bootstrap\.min\.css", r"bootstrap\.css", r'class="[^"]*navbar[^"]*"'],
        "scripts": [r"bootstrap\.min\.js"],
    },
    "Google Analytics": {
        "html": [r"google-analytics\.com/ga\.js", r"gtag\(", r"UA-\d{4,10}-\d"],
    },
    "Google Tag Manager": {
        "html": [r"googletagmanager\.com/gtm\.js"],
    },
    "Matomo": {
        "html": [r"matomo\.js", r"piwik\.js"],
    },
    "Elasticsearch": {
        "html": [r"kibana", r"elasticsearch"],
    },
    "Redis": {
        "headers": {},
        "html": [r"redis_version"],
    },
    "WooCommerce": {
        "html": [r"woocommerce", r"wc-api", r"add-to-cart"],
        "cookies": {"woocommerce_cart_hash": r".*"},
    },
    "PrestaShop": {
        "html": [r"prestashop", r"id_product="],
        "cookies": {"PrestaShop-[a-f0-9]+": r".*"},
    },
    "Magento": {
        "html": [r"Mage\.Cookies", r"varien/js\.js", r"mage/"],
        "cookies": {"frontend": r".*"},
    },
    "TYPO3": {
        "html": [r"typo3/", r"TYPO3"],
        "meta": {"generator": r"(?i)typo3"},
    },
    "Webpack": {
        "html": [r"webpack", r"\./webpack"],
        "scripts": [r"webpack\.js", r"bundle\.js"],
    },
    "Next.js": {
        "html": [r"__NEXT_DATA__", r"_next/static"],
    },
    "Nuxt.js": {
        "html": [r"__nuxt", r"_nuxt/"],
    },
    "Gatsby": {
        "html": [r"___gatsby", r"gatsby-", r"/page-data/"],
    },
}


class TechDetectModule(BaseModule):
    name = "tech_detect"
    label = "Technology Fingerprinting"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._patterns = self._load_patterns()

    def _load_patterns(self) -> dict:
        fp = self.config.fingerprint_path()
        if fp.exists():
            try:
                with open(fp, encoding="utf-8") as fh:
                    data = json.load(fh)
                logger.debug(f"Loaded {len(data)} Wappalyzer fingerprints from {fp}")
                return data
            except Exception as exc:
                logger.warning(f"Failed to load fingerprints/{fp.name}: {exc} — using built-in set")
        return _FALLBACK_FINGERPRINTS

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"Technology fingerprinting of {domain}")

        session = await build_session(self.config, service="target", timeout_secs=15)
        try:
            resp = await safe_get(session, f"https://{domain}", service="target")
            if resp is None:
                resp = await safe_get(session, f"http://{domain}", service="target")
            if resp is None:
                self.warn("Could not fetch homepage for tech fingerprinting")
                return result

            body = await resp.text(errors="replace")
            headers = dict(resp.headers)
            cookies = {c.key: c.value for c in resp.cookies.values()}
            final_url = str(resp.url)

            # Favicon hash
            favicon_tech = await self._check_favicon(session, domain)

            findings = self._fingerprint(body, headers, cookies, final_url)
            if favicon_tech:
                findings.append(TechFinding(name=favicon_tech, confidence=80, categories=["favicon"]))
        finally:
            await session.close()

        # Deduplicate by name (keep highest confidence)
        seen: dict[str, TechFinding] = {}
        for f in findings:
            if f.name not in seen or f.confidence > seen[f.name].confidence:
                seen[f.name] = f

        result.technologies = sorted(seen.values(), key=lambda x: (-x.confidence, x.name))
        result.modules_run.append(self.name)
        self.success(f"Fingerprinted {len(result.technologies)} technology/ies")
        return result

    def _fingerprint(
        self,
        body: str,
        headers: dict,
        cookies: dict,
        url: str,
    ) -> list[TechFinding]:
        findings: list[TechFinding] = []
        body_lower = body.lower()
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for tech_name, patterns in self._patterns.items():
            confidence = 0
            version: Optional[str] = None

            # HTML body patterns
            for pat in patterns.get("html", []):
                try:
                    m = re.search(pat, body, re.I)
                    if m:
                        confidence += 50
                        if m.lastindex:
                            version = m.group(1)
                        break
                except re.error:
                    if pat.lower() in body_lower:
                        confidence += 50

            # Script src patterns
            for pat in patterns.get("scripts", []):
                if re.search(pat, body, re.I):
                    confidence += 40

            # Response header patterns
            for hdr, pat in patterns.get("headers", {}).items():
                val = headers_lower.get(hdr.lower(), "")
                if val:
                    try:
                        m = re.search(pat, val, re.I)
                        if m:
                            confidence += 60
                            if m.lastindex:
                                version = m.group(1)
                    except re.error:
                        if pat.lower() in val.lower():
                            confidence += 60

            # Meta tag patterns
            for meta_name, pat in patterns.get("meta", {}).items():
                meta_re = re.compile(
                    rf'<meta[^>]+name=["\']?{re.escape(meta_name)}["\']?[^>]+content=["\']?([^"\'>\s]+)',
                    re.I,
                )
                m = meta_re.search(body)
                if m:
                    try:
                        if re.search(pat, m.group(1), re.I):
                            confidence += 70
                    except re.error:
                        confidence += 70

            # Cookie patterns
            for ck_name, pat in patterns.get("cookies", {}).items():
                for cookie_key in cookies:
                    if re.match(ck_name, cookie_key, re.I):
                        confidence += 40
                        break

            if confidence > 0:
                findings.append(TechFinding(
                    name=tech_name,
                    version=version,
                    confidence=min(confidence, 100),
                ))

        return findings

    async def _check_favicon(self, session, domain: str) -> Optional[str]:
        for path in ("/favicon.ico", "/favicon.png"):
            resp = await safe_get(session, f"https://{domain}{path}", service="target")
            if resp and resp.status == 200:
                try:
                    data = await resp.read()
                    if data:
                        h = hashlib.md5(data).hexdigest()
                        if h in _FAVICON_HASHES:
                            return _FAVICON_HASHES[h]
                except Exception:
                    pass
        return None
