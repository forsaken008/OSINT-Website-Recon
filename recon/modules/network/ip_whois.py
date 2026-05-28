from __future__ import annotations

import asyncio
import socket

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
from loguru import logger

from ...models import IPInfoResult, ScanResult
from ..base import BaseModule


class IPWhoisModule(BaseModule):
    name = "ip_whois"
    label = "IP & Network (RDAP)"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target

        # Resolve IP if not already done
        ip = None
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
        except Exception as exc:
            logger.warning(f"IP resolution failed for {domain}: {exc}")
            result.errors["ip_resolution"] = str(exc)
            result.modules_run.append(self.name)
            return result

        self.info(f"Resolved {domain} → {ip}")

        try:
            loop = asyncio.get_event_loop()
            rdap = await loop.run_in_executor(None, _lookup_rdap, ip)
        except IPDefinedError:
            rdap = IPInfoResult(
                ip=ip,
                error="Private/reserved IP address — RDAP not available",
            )
        except Exception as exc:
            logger.warning(f"RDAP lookup failed for {ip}: {exc}")
            rdap = IPInfoResult(ip=ip, error=str(exc))

        result.ip_info = rdap
        result.modules_run.append(self.name)
        self.success(f"IP: {ip}  ASN: {rdap.asn}  Org: {rdap.asn_description}")
        return result


def _lookup_rdap(ip: str) -> IPInfoResult:
    obj = IPWhois(ip)
    res = obj.lookup_rdap(depth=1)
    net = res.get("network", {})
    return IPInfoResult(
        ip=ip,
        asn=str(res.get("asn", "")),
        asn_description=res.get("asn_description", ""),
        network_name=net.get("name", ""),
        cidr=net.get("cidr", ""),
        country=net.get("country", ""),
    )
