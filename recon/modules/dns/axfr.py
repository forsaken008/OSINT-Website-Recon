from __future__ import annotations

import asyncio
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.query
import dns.zone
from loguru import logger

from ...models import ScanResult
from ..base import BaseModule


class AXFRModule(BaseModule):
    name = "axfr"
    label = "DNS Zone Transfer"

    async def run(self, result: ScanResult) -> ScanResult:
        if result.dns is None:
            return result

        nameservers = result.dns.records.get("NS", [])
        if not nameservers:
            self.info("No NS records — skipping AXFR")
            return result

        domain = result.target
        self.info(f"Attempting AXFR against {len(nameservers)} nameserver(s)")

        for ns in nameservers:
            ns = ns.rstrip(".")
            if await self._try_axfr(domain, ns, result):
                break   # one success is enough

        result.modules_run.append(self.name)
        return result

    async def _try_axfr(self, domain: str, ns: str, result: ScanResult) -> bool:
        try:
            # Resolve NS hostname to IP
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = self.config.dns.resolvers[:2]
            ns_ips = await resolver.resolve(ns, "A", lifetime=5)
            ns_ip = ns_ips[0].to_text()
        except Exception as exc:
            logger.debug(f"AXFR: could not resolve NS {ns}: {exc}")
            return False

        try:
            # dns.query.xfr is synchronous — run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                None, _do_xfr, domain, ns_ip
            )
            if records:
                self.success(f"ZONE TRANSFER SUCCEEDED via {ns} ({ns_ip})!")
                result.dns.axfr_success = True  # type: ignore[union-attr]
                result.dns.axfr_records = records  # type: ignore[union-attr]
                return True
        except Exception as exc:
            logger.debug(f"AXFR {ns} ({ns_ip}): {exc}")

        return False


def _do_xfr(domain: str, ns_ip: str) -> list[str]:
    """Synchronous AXFR attempt. Returns list of record strings on success."""
    records: list[str] = []
    try:
        xfr = dns.query.xfr(ns_ip, domain, timeout=10, lifetime=30)
        zone = dns.zone.from_xfr(xfr)
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(f"{name} {rdataset.ttl} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
    except (dns.exception.FormError, EOFError):
        pass  # server refused or sent an empty zone
    return records
