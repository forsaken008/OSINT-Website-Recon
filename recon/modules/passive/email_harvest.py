from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from loguru import logger

from ...http_client import build_session, safe_get
from ...models import ScanResult
from ..base import BaseModule

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.ASCII,
)

# False-positive domains to skip
_IGNORE_DOMAINS = {
    "example.com", "sentry.io", "wixpress.com", "jquery.com",
    "schema.org", "w3.org", "openid.net", "googleapis.com",
    "cloudflare.com", "fastly.com", "akamai.com",
}

# Paths likely to contain contact info
_CONTACT_PATHS = [
    "/contact", "/contact-us", "/about", "/about-us",
    "/team", "/staff", "/people", "/support", "/help",
    "/legal", "/privacy", "/security", "/careers",
]

_MAX_PAGES = 50


class EmailHarvestModule(BaseModule):
    name = "email_harvest"
    label = "Email Harvesting"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"Email harvesting across {domain} and contact paths")

        found_emails: set[str] = set()
        visited: set[str] = set()

        session = await build_session(self.config, service="target", timeout_secs=15)
        try:
            # 1. Crawl known contact-y paths on the apex + subdomains
            targets = [domain] + [s.host for s in result.subdomains]
            for host in targets[:10]:  # cap at 10 hosts
                if self.is_cancelled():
                    break
                for path in _CONTACT_PATHS:
                    for scheme in ("https", "http"):
                        url = f"{scheme}://{host}{path}"
                        if url in visited:
                            continue
                        emails = await self._scrape(session, url, visited)
                        found_emails.update(emails)
                        if len(visited) >= _MAX_PAGES:
                            break
                    if len(visited) >= _MAX_PAGES:
                        break
                if len(visited) >= _MAX_PAGES:
                    break

            # 2. Scrape JS bundles we found during JS analysis (if available)
            if result.js_findings:
                for url in list(result.js_findings.endpoints)[:20]:
                    if not url.startswith("http"):
                        continue
                    emails = await self._scrape(session, url, visited)
                    found_emails.update(emails)
        finally:
            await session.close()

        # Filter noise
        cleaned = {
            e.lower() for e in found_emails
            if _is_valid(e, domain)
        }

        result.emails = sorted(cleaned)
        result.modules_run.append(self.name)
        self.success(f"Email harvest: {len(cleaned)} address(es) found")
        return result

    async def _scrape(
        self, session, url: str, visited: set[str]
    ) -> set[str]:
        if url in visited:
            return set()
        visited.add(url)

        resp = await safe_get(session, url, service="target")
        if resp is None:
            return set()

        try:
            text = await resp.text(errors="replace")
        except Exception:
            return set()

        return set(_EMAIL_RE.findall(text))


def _is_valid(email: str, target_domain: str) -> bool:
    """Basic false-positive filter."""
    email = email.lower()
    parts = email.split("@")
    if len(parts) != 2:
        return False
    local, mail_domain = parts

    if mail_domain in _IGNORE_DOMAINS:
        return False
    if mail_domain.endswith(".png") or mail_domain.endswith(".jpg"):
        return False
    if len(local) < 2 or len(mail_domain) < 4:
        return False

    return True
