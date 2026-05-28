from __future__ import annotations

"""JavaScript endpoint and secret extraction.

For each JS file linked from the homepage:
  1. Download the script
  2. Extract all URL-like strings (LinkFinder-style regex)
  3. Pattern-match against common secret signatures
  4. Return deduplicated endpoint list and flagged secrets with context
"""

import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from loguru import logger

from ...http_client import build_session, safe_get
from ...models import JSAnalysisResult, ScanResult, SecretFinding
from ..base import BaseModule

# ── Endpoint extraction regex ─────────────────────────────────────────────────
# Loosely based on LinkFinder — matches URL-like strings in JS source
_ENDPOINT_RE = re.compile(
    r"""(?:"|'|`)                              # opening quote
    (
        (?:[a-zA-Z]{1,10}://|//)               # absolute URL
        |(?:[a-zA-Z0-9_\-./]{0,100}/)          # relative path starting with label/
        |(?:/[a-zA-Z0-9_\-./]{1,100})          # /path
    )
    [a-zA-Z0-9_./:?=&\-#%+@!~,;]*             # path + query
    (?:"|'|`)                                  # closing quote
    """,
    re.VERBOSE,
)

# ── Secret patterns (pattern_name: regex) ────────────────────────────────────
_SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key":        re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":        re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Generic API Key":       re.compile(r"(?i)api[_\-]?key['\"\s:=]+[a-zA-Z0-9_\-]{20,}"),
    "Generic Secret":        re.compile(r"(?i)secret[_\-]?key['\"\s:=]+[a-zA-Z0-9_\-]{20,}"),
    "Bearer Token":          re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}"),
    "Stripe Live Key":       re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    "Stripe Publishable Key": re.compile(r"pk_live_[A-Za-z0-9]{24,}"),
    "Slack Token":           re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    "GitHub Token":          re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "Google API Key":        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Twilio Account SID":    re.compile(r"AC[a-z0-9]{32}"),
    "Twilio Auth Token":     re.compile(r"(?i)twilio.{0,20}['\"][a-f0-9]{32}['\"]"),
    "Private Key Header":    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "Basic Auth in URL":     re.compile(r"https?://[a-zA-Z0-9_\-]+:[^@\s/]{4,}@"),
    "Hardcoded Password":    re.compile(r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    "JWT":                   re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
}

_CONTEXT_WINDOW = 40    # chars on each side of secret match
_MAX_SCRIPT_SIZE = 2_000_000   # 2 MB cap per script
_MAX_SCRIPTS = 30


class JSAnalysisModule(BaseModule):
    name = "js_analysis"
    label = "JavaScript Analysis"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"JS analysis of scripts on {domain}")

        session = await build_session(self.config, service="target", timeout_secs=20)
        try:
            # Fetch homepage to collect script URLs
            resp = await safe_get(session, f"https://{domain}", service="target")
            if resp is None:
                resp = await safe_get(session, f"http://{domain}", service="target")
            if resp is None:
                self.warn("Could not fetch homepage for JS analysis")
                return result

            homepage = await resp.text(errors="replace")
            base_url = str(resp.url)
            script_urls = _extract_script_urls(homepage, base_url, domain)
            script_urls = script_urls[:_MAX_SCRIPTS]

            self.info(f"Found {len(script_urls)} same-domain script(s) to analyse")

            all_endpoints: set[str] = set()
            all_secrets: list[SecretFinding] = []

            for script_url in script_urls:
                if self.is_cancelled():
                    break
                endpoints, secrets = await self._analyse_script(session, script_url, domain)
                all_endpoints.update(endpoints)
                all_secrets.extend(secrets)
        finally:
            await session.close()

        result.js_findings = JSAnalysisResult(
            scripts_analysed=len(script_urls),
            endpoints=sorted(all_endpoints),
            potential_secrets=all_secrets,
        )
        result.modules_run.append(self.name)

        self.success(
            f"JS: {len(all_endpoints)} endpoint(s), {len(all_secrets)} potential secret(s)"
        )
        if all_secrets:
            for s in all_secrets:
                self.warn(f"Possible secret [{s.pattern_name}] in {s.script_url}")
        return result

    async def _analyse_script(
        self, session, url: str, domain: str
    ) -> tuple[set[str], list[SecretFinding]]:
        resp = await safe_get(session, url, service="target")
        if resp is None:
            return set(), []

        try:
            raw = await resp.content.read(_MAX_SCRIPT_SIZE)
            text = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.debug(f"JS script read error {url}: {exc}")
            return set(), []

        endpoints = _extract_endpoints(text, url, domain)
        secrets = _extract_secrets(text, url)
        return endpoints, secrets


# ── Extraction helpers ────────────────────────────────────────────────────────

def _extract_script_urls(html: str, base_url: str, domain: str) -> list[str]:
    """Pull <script src="..."> URLs that belong to the same domain."""
    script_src_re = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
    urls: list[str] = []
    for match in script_src_re.finditer(html):
        src = match.group(1)
        absolute = urljoin(base_url, src)
        parsed = urlparse(absolute)
        if parsed.netloc and (domain in parsed.netloc):
            urls.append(absolute)
    return urls


def _extract_endpoints(text: str, script_url: str, domain: str) -> set[str]:
    """Extract URL-like strings from JS source."""
    found: set[str] = set()
    for m in _ENDPOINT_RE.finditer(text):
        ep = m.group(1).strip("\"'`")
        if not ep or len(ep) < 2:
            continue
        # Skip obviously non-endpoint strings
        if any(ep.startswith(skip) for skip in ("#", "//", "/*", "data:", "javascript:")):
            continue
        if re.search(r"\.(png|jpg|jpeg|gif|svg|woff|ttf|eot|ico|css)$", ep, re.I):
            continue
        # Keep only paths that look like API/route endpoints
        if ep.startswith("/") or ep.startswith("http"):
            found.add(ep)
    return found


def _extract_secrets(text: str, script_url: str) -> list[SecretFinding]:
    """Run all secret patterns against script text, return findings with context."""
    findings: list[SecretFinding] = []
    for pattern_name, pattern in _SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            start = max(0, m.start() - _CONTEXT_WINDOW)
            end = min(len(text), m.end() + _CONTEXT_WINDOW)
            # Replace the actual match value with asterisks so we don't log secrets
            before = text[start:m.start()]
            after = text[m.end():end]
            masked = "*" * min(len(m.group(0)), 12)
            context = f"{before}{masked}{after}"
            # Sanitise context to a single line
            context = context.replace("\n", " ").replace("\r", "")[:100]

            findings.append(SecretFinding(
                pattern_name=pattern_name,
                script_url=script_url,
                context=context,
            ))
    return findings
