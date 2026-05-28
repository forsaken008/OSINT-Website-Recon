from __future__ import annotations

"""Scan orchestrator.

Instantiates and runs modules in dependency order.
Accepts a progress callback so the GUI and CLI both receive live updates.
"""

import asyncio
import urllib.parse
from datetime import datetime
from typing import Callable, Optional

from loguru import logger

from .config import Config
from .models import ScanResult
from .modules.base import ProgressCallback
from .modules.dns.axfr import AXFRModule
from .modules.dns.records import DNSRecordsModule
from .modules.active.dir_scan import DirectoryScanModule
from .modules.active.headers import HeadersModule
from .modules.active.js_analysis import JSAnalysisModule
from .modules.active.port_scan import PortScanModule
from .modules.active.subdomain_enum import SubdomainEnumModule
from .modules.active.tech_detect import TechDetectModule
from .modules.active.tls_analysis import TLSAnalysisModule
from .modules.network.cdn_detect import CDNDetectModule
from .modules.network.geo import GeolocationModule
from .modules.network.ip_whois import IPWhoisModule
from .modules.network.ping_trace import PingModule, TracerouteModule
from .modules.passive.api_sources import APISourcesModule
from .modules.passive.ct_logs import CTLogsModule
from .modules.passive.domain_whois import DomainWhoisModule
from .modules.passive.email_harvest import EmailHarvestModule
from .modules.passive.wayback import WaybackModule
from .rate_limiter import setup_rate_limits

# Canonical module order
_ALL_MODULES = [
    "ip_whois", "dns", "axfr", "domain_whois",
    "ct_logs", "api_sources",
    "subdomains",
    "geo", "cdn",
    "ports", "tls",
    "headers", "tech_detect",
    "dir_scan", "js_analysis",
    "wayback", "email_harvest",
    "ping", "traceroute",
]


class Engine:
    def __init__(
        self,
        config: Config,
        progress_cb: Optional[ProgressCallback] = None,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> None:
        self.config = config
        self._progress_cb = progress_cb or _noop
        self._cancel = cancel_event or asyncio.Event()

    async def scan(
        self,
        target: str,
        modules: Optional[list[str]] = None,
    ) -> ScanResult:
        """
        Run enabled modules against target.

        target: bare domain or URL — URL is normalised to bare domain
        modules: list of module names to run (None = all)
        """
        target = _normalise_target(target)
        enabled = set(modules or _ALL_MODULES)

        await setup_rate_limits(self.config)

        result = ScanResult(target=target, started_at=datetime.utcnow())
        self._progress_cb("engine", "info", f"Starting scan of {target}")

        def _mod(cls):
            return cls(
                config=self.config,
                progress_cb=self._progress_cb,
                cancel_event=self._cancel,
            )

        # ── Phase 1: Foundation ───────────────────────────────────────────────
        if "ip_whois" in enabled and not self._cancel.is_set():
            result = await _mod(IPWhoisModule).run(result)

        if "dns" in enabled and not self._cancel.is_set():
            result = await _mod(DNSRecordsModule).run(result)

        # AXFR depends on NS records from dns module
        if "axfr" in enabled and self.config.scan.axfr_attempt and not self._cancel.is_set():
            result = await _mod(AXFRModule).run(result)

        if "domain_whois" in enabled and not self._cancel.is_set():
            result = await _mod(DomainWhoisModule).run(result)

        # ── Phase 2: Passive OSINT (parallel) ─────────────────────────────────
        passive_tasks = []
        if "ct_logs" in enabled:
            passive_tasks.append(_mod(CTLogsModule).run(result))
        if "wayback" in enabled:
            passive_tasks.append(_mod(WaybackModule).run(result))

        if passive_tasks and not self._cancel.is_set():
            passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)
            for r in passive_results:
                if isinstance(r, Exception):
                    logger.error(f"Passive module error: {r}")
                else:
                    result = _merge(result, r)

        # API sources (runs after CT logs so it can add to subdomains list)
        if "api_sources" in enabled and not self._cancel.is_set():
            result = await _mod(APISourcesModule).run(result)

        # ── Phase 3: Subdomain enumeration ───────────────────────────────────
        if "subdomains" in enabled and not self._cancel.is_set():
            result = await _mod(SubdomainEnumModule).run(result)

        # ── Phase 4: Network info (parallel) ─────────────────────────────────
        net_tasks = []
        if "geo" in enabled:
            net_tasks.append(_mod(GeolocationModule).run(result))
        if "cdn" in enabled:
            net_tasks.append(_mod(CDNDetectModule).run(result))

        if net_tasks and not self._cancel.is_set():
            net_results = await asyncio.gather(*net_tasks, return_exceptions=True)
            for r in net_results:
                if isinstance(r, Exception):
                    logger.error(f"Network module error: {r}")
                else:
                    result = _merge(result, r)

        # ── Phase 5: Active scanning (parallel where possible) ───────────────
        active_tasks = []
        if "ports" in enabled:
            active_tasks.append(_mod(PortScanModule).run(result))
        if "tls" in enabled:
            active_tasks.append(_mod(TLSAnalysisModule).run(result))
        if "headers" in enabled:
            active_tasks.append(_mod(HeadersModule).run(result))
        if "tech_detect" in enabled:
            active_tasks.append(_mod(TechDetectModule).run(result))

        if active_tasks and not self._cancel.is_set():
            active_results = await asyncio.gather(*active_tasks, return_exceptions=True)
            for r in active_results:
                if isinstance(r, Exception):
                    logger.error(f"Active module error: {r}")
                else:
                    result = _merge(result, r)

        # JS analysis (runs after headers so it can use the homepage response)
        if "js_analysis" in enabled and self.config.scan.js_analysis and not self._cancel.is_set():
            result = await _mod(JSAnalysisModule).run(result)

        # Dir scan (runs after subdomains + CDN dedup)
        if "dir_scan" in enabled and not self._cancel.is_set():
            result = await _mod(DirectoryScanModule).run(result)

        # Email harvest (runs after JS analysis so it can use discovered endpoints)
        if "email_harvest" in enabled and not self._cancel.is_set():
            result = await _mod(EmailHarvestModule).run(result)

        # ── Phase 6: Network diagnostics (parallel) ───────────────────────────
        diag_tasks = []
        if "ping" in enabled:
            diag_tasks.append(_mod(PingModule).run(result))
        if "traceroute" in enabled:
            diag_tasks.append(_mod(TracerouteModule).run(result))

        if diag_tasks and not self._cancel.is_set():
            diag_results = await asyncio.gather(*diag_tasks, return_exceptions=True)
            for r in diag_results:
                if isinstance(r, Exception):
                    logger.error(f"Diagnostics module error: {r}")
                else:
                    result = _merge(result, r)

        result.finished_at = datetime.utcnow()
        elapsed = (result.finished_at - result.started_at).total_seconds()
        self._progress_cb(
            "engine", "success",
            f"Scan complete in {elapsed:.0f}s — {len(result.modules_run)} module(s) ran"
        )
        return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalise_target(target: str) -> str:
    """Strip scheme, path, port from any URL-like input."""
    target = target.strip()
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        target = parsed.netloc or parsed.path
    # Remove port
    if ":" in target:
        target = target.split(":")[0]
    return target.lower().lstrip("www.") if target.startswith("www.") else target.lower()


def _merge(base: ScanResult, update: ScanResult) -> ScanResult:
    """Merge non-None fields from update into base."""
    for field in update.model_fields:
        val = getattr(update, field, None)
        if val is None:
            continue
        base_val = getattr(base, field, None)
        if isinstance(val, list) and isinstance(base_val, list):
            # Merge lists, deduplicate by str representation
            existing = {str(x) for x in base_val}
            for item in val:
                if str(item) not in existing:
                    base_val.append(item)
                    existing.add(str(item))
        elif isinstance(val, dict) and isinstance(base_val, dict):
            base_val.update({k: v for k, v in val.items() if v})
        elif val and field not in ("target", "started_at"):
            setattr(base, field, val)
    return base


def _noop(module: str, level: str, message: str) -> None:
    pass
