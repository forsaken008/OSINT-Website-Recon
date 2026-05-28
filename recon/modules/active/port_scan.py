from __future__ import annotations

"""Port scanning module.

Priority:
  1. nmap (if in PATH) — service/version detection, NSE scripts, accurate
  2. python-nmap wrapper — same flags via Python API
  3. Async TCP connect fallback — no external dependency
"""

import asyncio
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

from loguru import logger

from ...models import PortFinding, ScanResult
from ..base import BaseModule

_COMMON_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 587: "smtp-submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2375: "docker", 2376: "docker-tls", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 4443: "https-alt", 5000: "upnp",
    5432: "postgres", 5900: "vnc", 5985: "winrm-http",
    6379: "redis", 6443: "k8s-api", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9000: "php-fpm", 9200: "elasticsearch", 9300: "elasticsearch",
    27017: "mongodb", 27018: "mongodb", 50000: "db2",
}


class PortScanModule(BaseModule):
    name = "ports"
    label = "Port Scanner"

    async def run(self, result: ScanResult) -> ScanResult:
        ip = result.ip_info.ip if result.ip_info else None
        if not ip:
            self.warn("No resolved IP — skipping port scan")
            return result

        thorough = self.config.scan.external_tools

        if shutil.which("nmap") and self.config.scan.external_tools:
            self.info(f"Using nmap for port scan on {ip}")
            findings = await self._nmap_scan(ip, thorough)
        else:
            self.info(f"nmap not found — using async TCP connect scan on {ip}")
            findings = await self._async_tcp_scan(ip)

        result.ports = findings
        result.modules_run.append(self.name)
        open_count = sum(1 for p in findings if p.state == "open")
        self.success(f"Port scan: {open_count} open port(s) found")
        return result

    # ── nmap ──────────────────────────────────────────────────────────────────

    async def _nmap_scan(self, ip: str, thorough: bool) -> list[PortFinding]:
        ports_arg = "-p-" if thorough else "--top-ports 1000"
        cmd = [
            "nmap", "-sV", "-sC", "-T4", "--open",
            "-oX", "-",   # XML output to stdout
            "--version-intensity", "5",
        ] + ports_arg.split() + [ip]

        try:
            loop = asyncio.get_event_loop()
            proc = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        cmd, capture_output=True, text=True, timeout=600
                    ),
                ),
                timeout=620,
            )
            return _parse_nmap_xml(proc.stdout)
        except asyncio.TimeoutError:
            self.warn("nmap timed out after 10 min — returning partial results")
            return []
        except Exception as exc:
            logger.warning(f"nmap error: {exc} — falling back to TCP connect scan")
            return await self._async_tcp_scan(ip)

    # ── Async TCP connect fallback ────────────────────────────────────────────

    async def _async_tcp_scan(self, ip: str) -> list[PortFinding]:
        """Rate-limited async TCP connect scan of common ports."""
        ports = list(_COMMON_SERVICES.keys())
        sem = asyncio.Semaphore(200)

        async def _check(port: int) -> Optional[PortFinding]:
            async with sem:
                try:
                    conn = asyncio.open_connection(ip, port)
                    _, writer = await asyncio.wait_for(conn, timeout=1.5)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return PortFinding(
                        port=port,
                        state="open",
                        service=_COMMON_SERVICES.get(port, "unknown"),
                    )
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None
                except Exception as exc:
                    logger.debug(f"TCP {ip}:{port} — {exc}")
                    return None

        tasks = [_check(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sorted(
            [r for r in results if isinstance(r, PortFinding)],
            key=lambda x: x.port,
        )


# ── nmap XML parser ───────────────────────────────────────────────────────────

def _parse_nmap_xml(xml_text: str) -> list[PortFinding]:
    findings: list[PortFinding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.debug(f"nmap XML parse error: {exc}")
        return findings

    for host in root.findall(".//host"):
        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = int(port_el.get("portid", 0))
            service_el = port_el.find("service")
            service_name = service_el.get("name", "") if service_el is not None else ""
            version = ""
            if service_el is not None:
                parts = [
                    service_el.get("product", ""),
                    service_el.get("version", ""),
                    service_el.get("extrainfo", ""),
                ]
                version = " ".join(p for p in parts if p).strip()

            banner = None
            for script in port_el.findall(".//script"):
                if script.get("id") == "banner":
                    banner = script.get("output", "")[:200]
                    break

            findings.append(PortFinding(
                port=portid,
                state="open",
                service=service_name or _COMMON_SERVICES.get(portid, "unknown"),
                version=version or None,
                banner=banner,
            ))

    return sorted(findings, key=lambda x: x.port)
