from __future__ import annotations

"""Optional API-key-gated passive data sources.

Each source gracefully no-ops when no key is configured.
Results are merged into the main ScanResult — subdomains get added to
result.subdomains (with source tag), interesting IPs/ports get noted in
result.ip_info, threat intel is appended to result.errors as informational.
"""

import asyncio
from typing import Optional

from loguru import logger

from ...http_client import build_session, safe_get
from ...models import ScanResult, SubdomainFinding
from ..base import BaseModule


class APISourcesModule(BaseModule):
    name = "api_sources"
    label = "Passive API Sources (Shodan / VirusTotal / OTX)"

    async def run(self, result: ScanResult) -> ScanResult:
        keys = self.config.api_keys
        tasks = []

        if keys.shodan:
            tasks.append(self._shodan(result))
        if keys.virustotal:
            tasks.append(self._virustotal(result))
        if keys.alienvault or True:  # OTX basic queries need no key
            tasks.append(self._otx(result))
        if keys.securitytrails:
            tasks.append(self._securitytrails(result))

        if not tasks:
            self.info("No API keys configured — skipping API sources")
            return result

        await asyncio.gather(*tasks, return_exceptions=True)
        result.modules_run.append(self.name)
        return result

    # ── Shodan ────────────────────────────────────────────────────────────────

    async def _shodan(self, result: ScanResult) -> None:
        key = self.config.api_keys.shodan
        ip = result.ip_info.ip if result.ip_info else None
        if not ip:
            return

        self.info(f"Querying Shodan for {ip}")
        session = await build_session(self.config, service="shodan", timeout_secs=20)
        try:
            resp = await safe_get(
                session,
                f"https://api.shodan.io/shodan/host/{ip}?key={key}",
                service="shodan",
            )
            if resp and resp.status == 200:
                data = await resp.json()
                self._process_shodan(result, data)
            elif resp and resp.status == 401:
                self.warn("Shodan: invalid API key")
        except Exception as exc:
            logger.debug(f"Shodan error: {exc}")
        finally:
            await session.close()

    def _process_shodan(self, result: ScanResult, data: dict) -> None:
        ports = data.get("ports", [])
        if ports:
            self.success(f"Shodan: {len(ports)} open port(s) reported: {ports}")

        hostnames = data.get("hostnames", [])
        domain = result.target
        existing = {s.host for s in result.subdomains}
        for h in hostnames:
            h = h.lower()
            if h.endswith(f".{domain}") and h not in existing:
                result.subdomains.append(SubdomainFinding(host=h, sources=["shodan"]))
                existing.add(h)

        vulns = data.get("vulns", {})
        if vulns:
            self.warn(f"Shodan reports {len(vulns)} known vuln(s): {', '.join(list(vulns.keys())[:5])}")
            result.errors["shodan_vulns"] = ", ".join(vulns.keys())

    # ── VirusTotal ────────────────────────────────────────────────────────────

    async def _virustotal(self, result: ScanResult) -> None:
        key = self.config.api_keys.virustotal
        domain = result.target
        self.info(f"Querying VirusTotal passive DNS for {domain}")

        session = await build_session(self.config, service="virustotal", timeout_secs=20)
        try:
            resp = await safe_get(
                session,
                f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
                service="virustotal",
                headers={"x-apikey": key},
            )
            if resp and resp.status == 200:
                data = await resp.json()
                self._process_vt_subdomains(result, data)
            elif resp and resp.status in (401, 403):
                self.warn("VirusTotal: invalid or quota-exceeded API key")
        except Exception as exc:
            logger.debug(f"VT error: {exc}")
        finally:
            await session.close()

    def _process_vt_subdomains(self, result: ScanResult, data: dict) -> None:
        domain = result.target
        existing = {s.host for s in result.subdomains}
        found = 0
        for item in data.get("data", []):
            host = item.get("id", "").lower()
            if host.endswith(f".{domain}") and host not in existing:
                result.subdomains.append(SubdomainFinding(host=host, sources=["virustotal"]))
                existing.add(host)
                found += 1
        if found:
            self.success(f"VirusTotal: +{found} subdomain(s)")

    # ── AlienVault OTX ────────────────────────────────────────────────────────

    async def _otx(self, result: ScanResult) -> None:
        domain = result.target
        self.info(f"Querying AlienVault OTX for {domain}")
        headers = {}
        if self.config.api_keys.alienvault:
            headers["X-OTX-API-KEY"] = self.config.api_keys.alienvault

        session = await build_session(self.config, service="target", timeout_secs=20)
        try:
            resp = await safe_get(
                session,
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                service="target",
                headers=headers,
            )
            if resp and resp.status == 200:
                data = await resp.json()
                self._process_otx(result, data)
        except Exception as exc:
            logger.debug(f"OTX error: {exc}")
        finally:
            await session.close()

    def _process_otx(self, result: ScanResult, data: dict) -> None:
        domain = result.target
        existing = {s.host for s in result.subdomains}
        found = 0
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "").lower()
            if hostname.endswith(f".{domain}") and hostname not in existing:
                result.subdomains.append(SubdomainFinding(host=hostname, sources=["otx"]))
                existing.add(hostname)
                found += 1
        if found:
            self.success(f"OTX: +{found} subdomain(s)")

    # ── SecurityTrails ────────────────────────────────────────────────────────

    async def _securitytrails(self, result: ScanResult) -> None:
        key = self.config.api_keys.securitytrails
        domain = result.target
        self.info(f"Querying SecurityTrails for {domain}")

        session = await build_session(self.config, service="target", timeout_secs=20)
        try:
            resp = await safe_get(
                session,
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=true&include_inactive=true",
                service="target",
                headers={"apikey": key},
            )
            if resp and resp.status == 200:
                data = await resp.json()
                self._process_st(result, data, domain)
            elif resp and resp.status in (401, 403):
                self.warn("SecurityTrails: invalid API key")
        except Exception as exc:
            logger.debug(f"SecurityTrails error: {exc}")
        finally:
            await session.close()

    def _process_st(self, result: ScanResult, data: dict, domain: str) -> None:
        existing = {s.host for s in result.subdomains}
        found = 0
        for sub in data.get("subdomains", []):
            host = f"{sub}.{domain}".lower()
            if host not in existing:
                result.subdomains.append(SubdomainFinding(host=host, sources=["securitytrails"]))
                existing.add(host)
                found += 1
        if found:
            self.success(f"SecurityTrails: +{found} subdomain(s)")
