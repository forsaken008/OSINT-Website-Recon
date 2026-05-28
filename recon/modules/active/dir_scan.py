from __future__ import annotations

"""Directory and sensitive-file scanner.

- Uses GET (not HEAD) — more accurate status codes, avoids WAF HEAD heuristics
- Deduplicates targets by resolved IP so CDN-backed subdomains aren't re-scanned
- Content-verifies exposed files rather than trusting status=200 alone
- Calibrates against a random baseline to detect soft-404 servers
"""

import asyncio
import hashlib
import os
import random
import string
from pathlib import Path
from typing import Optional

import aiohttp
from loguru import logger

from ...http_client import build_session, safe_get
from ...models import DirectoryFinding, ExposedFileFinding, ScanResult
from ..base import BaseModule

# Content verification signatures for sensitive files
_FILE_VERIFIERS: dict[str, list[str]] = {
    "/.git/HEAD":    ["ref: refs/heads/", "ref: refs/"],
    "/.git/config":  ["[core]"],
    "/.git/index":   [],                        # binary — any 200 is real
    "/.env":         ["=", "APP_", "DB_", "SECRET", "KEY"],
    "/.env.local":   ["="],
    "/.env.production": ["="],
    "/.env.backup":  ["="],
    "/config.php":   ["<?php", "define(", "$db"],
    "/wp-config.php": ["<?php", "DB_NAME", "define("],
    "/phpinfo.php":  ["PHP Version", "phpinfo()"],
    "/info.php":     ["PHP Version"],
    "/.htpasswd":    [":"],
    "/database.yml": ["adapter:", "database:"],
    "/database.yaml": ["adapter:", "database:"],
    "/settings.py":  ["SECRET_KEY", "DATABASES", "DEBUG"],
    "/db_backup.sql": ["INSERT INTO", "CREATE TABLE", "--"],
    "/backup.sql":   ["INSERT INTO", "CREATE TABLE"],
    "/dump.sql":     ["INSERT INTO", "CREATE TABLE"],
    "/.DS_Store":    [],                         # binary
    "/crossdomain.xml": ["<cross-domain-policy"],
    "/clientaccesspolicy.xml": ["<access-policy"],
    "/server-status": ["Apache Server Status", "Server Version"],
    "/actuator/env": ["activeProfiles", "propertySources"],
    "/actuator/health": ["status", "UP"],
    "/swagger.json": ["swagger", "openapi"],
    "/openapi.json": ["openapi"],
    "/graphql":      [],
    "/.svn/entries": ["10\n", "dir\n"],
    "/phpMyAdmin/":  ["phpMyAdmin", "pma_"],
}

_SENSITIVE_PATHS = sorted(_FILE_VERIFIERS.keys())


class DirectoryScanModule(BaseModule):
    name = "dir_scan"
    label = "Directory & Exposed Files"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        paths_file = self.config.wordlist_path("paths")
        admin_paths = _load_paths(paths_file)
        self.info(f"Dir scan: {len(admin_paths)} paths, {len(_SENSITIVE_PATHS)} sensitive file checks")

        # Build unique target set by IP (dedup CDN-shared subdomains)
        targets = _build_targets(domain, result)
        self.info(f"Unique targets after CDN dedup: {len(targets)}")

        session = await build_session(self.config, service="target", timeout_secs=10)
        try:
            dir_findings: list[DirectoryFinding] = []
            exp_findings: list[ExposedFileFinding] = []

            for host in targets:
                if self.is_cancelled():
                    break
                base_https = f"https://{host}"
                base_http = f"http://{host}"

                # Soft-404 calibration
                soft_404_hashes = await self._calibrate_soft404(session, base_https)

                # Admin / directory paths
                for path in admin_paths:
                    if self.is_cancelled():
                        break
                    for base in (base_https, base_http):
                        url = base + path
                        finding = await self._check_dir(session, url, soft_404_hashes)
                        if finding:
                            dir_findings.append(finding)
                            break  # found on https, don't also check http

                # Sensitive / exposed file paths
                for path in _SENSITIVE_PATHS:
                    if self.is_cancelled():
                        break
                    for base in (base_https, base_http):
                        url = base + path
                        finding = await self._check_exposed(session, url, path)
                        if finding:
                            exp_findings.append(finding)
                            break
        finally:
            await session.close()

        result.directories = dir_findings
        result.exposed_files = exp_findings
        result.modules_run.append(self.name)

        self.success(
            f"Dir scan: {len(dir_findings)} admin paths, {len(exp_findings)} exposed files"
        )
        if exp_findings:
            for f in exp_findings:
                self.warn(f"EXPOSED: {f.url} [{f.status}] — {f.verification}")
        return result

    async def _calibrate_soft404(self, session, base: str) -> set[str]:
        """
        GET two random 404-guaranteed paths. If both return 200 with the same
        body hash, this server uses soft-404s — remember those hashes to skip.
        """
        hashes: set[str] = set()
        random_paths = [
            "/" + "".join(random.choices(string.ascii_lowercase, k=12)),
            "/" + "".join(random.choices(string.ascii_lowercase, k=14)),
        ]
        for rp in random_paths:
            resp = await safe_get(session, base + rp, service="target")
            if resp and resp.status == 200:
                try:
                    body = await resp.read()
                    hashes.add(hashlib.md5(body[:512]).hexdigest())
                except Exception:
                    pass
        return hashes

    async def _check_dir(
        self,
        session,
        url: str,
        soft_404_hashes: set[str],
    ) -> Optional[DirectoryFinding]:
        resp = await safe_get(session, url, service="target")
        if resp is None:
            return None

        status = resp.status
        if status not in (200, 301, 302, 401, 403):
            return None

        if status == 200 and soft_404_hashes:
            try:
                body = await resp.read()
                h = hashlib.md5(body[:512]).hexdigest()
                if h in soft_404_hashes:
                    return None   # soft 404
            except Exception:
                pass

        redirect = None
        if status in (301, 302):
            redirect = resp.headers.get("Location", "")

        return DirectoryFinding(
            url=url,
            status=status,
            content_type=resp.headers.get("Content-Type", "").split(";")[0],
            content_length=_safe_int(resp.headers.get("Content-Length")),
            redirect_to=redirect,
        )

    async def _check_exposed(
        self, session, url: str, path: str
    ) -> Optional[ExposedFileFinding]:
        resp = await safe_get(session, url, service="target")
        if resp is None:
            return None
        if resp.status != 200:
            return None

        signatures = _FILE_VERIFIERS.get(path, [])

        if not signatures:
            # Binary file or no-signature check — any 200 counts
            try:
                cl = _safe_int(resp.headers.get("Content-Length"))
                if cl is not None and cl == 0:
                    return None
            except Exception:
                pass
            return ExposedFileFinding(
                url=url,
                status=200,
                verification="status 200 (binary/no-signature check)",
                content_length=_safe_int(resp.headers.get("Content-Length")),
            )

        try:
            body = await resp.text(errors="replace")
        except Exception:
            return None

        for sig in signatures:
            if sig in body:
                return ExposedFileFinding(
                    url=url,
                    status=200,
                    verification=f"body contains '{sig}'",
                    content_length=len(body.encode()),
                )

        return None   # 200 but body doesn't match expected content — likely false positive


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_paths(path: Path) -> list[str]:
    if not path.exists():
        logger.warning(f"Paths wordlist not found: {path} — using minimal built-in list")
        return [
            "/admin", "/administrator", "/wp-admin", "/cpanel",
            "/login", "/dashboard", "/panel", "/console",
            "/api", "/api/v1", "/api/v2", "/swagger.json",
            "/actuator", "/actuator/health", "/graphql",
        ]
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def _build_targets(domain: str, result: ScanResult) -> list[str]:
    """Build a deduplicated list of hosts to scan.

    Groups subdomains by IP and picks one representative per IP group to
    avoid redundant scans when multiple names point to the same server.
    """
    # Always include apex
    apex_ip = result.ip_info.ip if result.ip_info else None
    seen_ips: set[str] = set()
    targets: list[str] = []

    if apex_ip:
        seen_ips.add(apex_ip)
    targets.append(domain)

    for sub in result.subdomains:
        if sub.ip and sub.ip not in seen_ips:
            seen_ips.add(sub.ip)
            targets.append(sub.host)
        elif not sub.ip:
            targets.append(sub.host)  # unresolved — include anyway

    return targets


def _safe_int(val) -> Optional[int]:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None
