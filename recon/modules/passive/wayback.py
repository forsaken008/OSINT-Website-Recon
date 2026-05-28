from __future__ import annotations

import re
from urllib.parse import urlparse

from loguru import logger

from ...http_client import build_session, safe_get
from ...models import ScanResult, WaybackResult
from ..base import BaseModule

# Patterns that flag an archived URL as worth manual review
_INTERESTING_PATTERNS = [
    (re.compile(r"/admin", re.I),          "admin path"),
    (re.compile(r"/backup", re.I),         "backup path"),
    (re.compile(r"\.sql$", re.I),          "SQL file"),
    (re.compile(r"\.(tar\.gz|tgz|zip|rar|7z)$", re.I), "archive file"),
    (re.compile(r"\.bak$", re.I),          "backup file"),
    (re.compile(r"s3\.amazonaws\.com", re.I), "S3 bucket reference"),
    (re.compile(r"[\?&](id|user|pass|token|key|secret|api[_-]?key)=", re.I), "sensitive parameter"),
    (re.compile(r"/\.git/", re.I),         "git directory"),
    (re.compile(r"/\.env", re.I),          "env file"),
    (re.compile(r"/phpinfo", re.I),        "phpinfo"),
    (re.compile(r"/wp-admin", re.I),       "WordPress admin"),
    (re.compile(r"/(config|settings)\.", re.I), "config file"),
    (re.compile(r"/dev/|/test/|/staging/", re.I), "dev/test path"),
    (re.compile(r"\.json$", re.I),         "JSON file"),
    (re.compile(r"\.(xml|yaml|yml)$", re.I), "config/data file"),
]

_CDX_URL = (
    "https://web.archive.org/cdx/search/cdx"
    "?url=*.{domain}/*"
    "&output=json"
    "&fl=original"
    "&collapse=urlkey"
    "&limit=50000"
    "&matchType=domain"
)


class WaybackModule(BaseModule):
    name = "wayback"
    label = "Wayback Machine URL Harvest"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"Querying Wayback CDX API for *.{domain}/*")

        session = await build_session(self.config, service="archive_org", timeout_secs=60)
        try:
            urls = await self._fetch_cdx(session, domain)
        finally:
            await session.close()

        if not urls:
            self.warn("No archived URLs found")
            result.wayback = WaybackResult()
            result.modules_run.append(self.name)
            return result

        self.success(f"Wayback: {len(urls)} archived URLs retrieved")

        # Deduplicate paths (strip query strings for path-level view)
        unique_paths: set[str] = set()
        interesting: list[str] = []

        for url in urls:
            try:
                parsed = urlparse(url)
                unique_paths.add(parsed.path)
            except Exception:
                continue

            for pattern, label in _INTERESTING_PATTERNS:
                if pattern.search(url):
                    interesting.append(f"[{label}] {url}")
                    break

        result.wayback = WaybackResult(
            total_urls=len(urls),
            all_urls=urls,
            unique_paths=sorted(unique_paths),
            interesting=sorted(set(interesting)),
        )
        result.modules_run.append(self.name)

        if interesting:
            self.warn(f"{len(interesting)} interesting archived URLs flagged")

        return result

    async def _fetch_cdx(self, session, domain: str) -> list[str]:
        url = _CDX_URL.format(domain=domain)
        resp = await safe_get(session, url, service="archive_org", retries=2)
        if resp is None:
            return []

        try:
            data = await resp.json(content_type=None)
        except Exception as exc:
            logger.debug(f"Wayback CDX parse error: {exc}")
            return []

        # CDX JSON: first row is headers ["original"], rest are data rows
        if not data or len(data) < 2:
            return []

        urls: list[str] = []
        for row in data[1:]:
            if row and isinstance(row[0], str):
                urls.append(row[0])

        return urls
