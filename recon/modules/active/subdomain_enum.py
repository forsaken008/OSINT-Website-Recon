from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import aiodns
from loguru import logger

from ...models import ScanResult, SubdomainFinding
from ...modules.dns.permutations import generate as gen_permutations
from ..base import BaseModule

# CDN ASN ranges used for CDN detection on resolved subdomains
_CDN_ASNS: dict[str, str] = {
    "13335": "Cloudflare",
    "54113": "Fastly",
    "20940": "Akamai",
    "16509": "Amazon CloudFront",
    "15169": "Google",
    "8075":  "Microsoft Azure",
    "30148": "Sucuri",
    "22120": "Incapsula",
}


class SubdomainEnumModule(BaseModule):
    name = "subdomains"
    label = "Subdomain Enumeration"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        found: dict[str, SubdomainFinding] = {}

        # ── 1. Seed from CT logs (already done — no re-query) ────────────────
        if result.ct_logs:
            for host in result.ct_logs.domains:
                if host != domain:
                    _add(found, host, "ct_logs")
            self.info(f"Seeded {len(found)} hosts from CT logs")

        # ── 2. Brute-force with wordlist ──────────────────────────────────────
        wordlist_path = self.config.wordlist_path("subdomains")
        if wordlist_path.exists():
            words = _load_wordlist(wordlist_path)
            self.info(f"Brute-force: {len(words)} words from {wordlist_path.name}")
            bf_found = await self._bulk_resolve(
                [f"{w}.{domain}" for w in words],
                source="brute_force",
            )
            for host, ip in bf_found.items():
                _add(found, host, "brute_force", ip=ip)
            self.success(f"Brute-force: {len(bf_found)} resolved")
        else:
            self.warn(f"Wordlist not found: {wordlist_path} — skipping brute-force")

        # ── 3. Permutation generation from found subdomains ───────────────────
        if self.config.scan.subdomain_permutations and found:
            candidates = gen_permutations(list(found.keys()), domain)
            self.info(f"Permutations: testing {len(candidates)} variants")
            perm_found = await self._bulk_resolve(candidates, source="permutation")
            for host, ip in perm_found.items():
                _add(found, host, "permutation", ip=ip)
            self.success(f"Permutations: {len(perm_found)} new hosts")

        # ── 4. External tools (subfinder / amass) ─────────────────────────────
        if self.config.scan.external_tools:
            for tool, runner in [("subfinder", self._run_subfinder), ("amass", self._run_amass)]:
                if shutil.which(tool):
                    self.info(f"Running external tool: {tool}")
                    ext_hosts = await runner(domain)
                    added = 0
                    for h in ext_hosts:
                        if h not in found:
                            _add(found, h, tool)
                            added += 1
                    if added:
                        self.success(f"{tool}: +{added} new hosts")
                else:
                    logger.debug(f"{tool} not in PATH — skipping")

        # ── 5. Resolve any hosts that don't have an IP yet ────────────────────
        unresolved = [h for h, f in found.items() if f.ip is None]
        if unresolved:
            self.info(f"Resolving {len(unresolved)} un-IP'd hosts")
            resolved = await self._bulk_resolve(unresolved, source=None)
            for host, ip in resolved.items():
                found[host].ip = ip

        # ── 6. Write back into ScanResult ─────────────────────────────────────
        existing_hosts = {s.host for s in result.subdomains}
        new_findings = [f for h, f in found.items() if h not in existing_hosts]

        # Preserve subdomains already added by API sources, just enrich them
        for existing in result.subdomains:
            if existing.host in found:
                existing.sources = sorted(set(existing.sources + found[existing.host].sources))
                if not existing.ip and found[existing.host].ip:
                    existing.ip = found[existing.host].ip

        result.subdomains.extend(new_findings)
        result.modules_run.append(self.name)

        total = len(result.subdomains)
        self.success(f"Subdomain enumeration complete — {total} unique host(s)")
        return result

    # ── DNS resolution helpers ────────────────────────────────────────────────

    async def _bulk_resolve(
        self, candidates: list[str], source: Optional[str]
    ) -> dict[str, str]:
        """
        Async-resolve all candidates against multiple resolvers.
        Returns {fqdn: ip} for hosts that resolved successfully.
        """
        resolver = aiodns.DNSResolver(
            nameservers=self.config.dns.resolvers,
            timeout=self.config.dns.timeout,
        )
        sem = asyncio.Semaphore(self.config.dns.concurrency)

        async def _resolve_one(host: str) -> tuple[str, Optional[str]]:
            async with sem:
                try:
                    result = await resolver.query(host, "A")
                    if result:
                        return host, result[0].host
                except (aiodns.error.DNSError, Exception):
                    pass
                return host, None

        tasks = [_resolve_one(c) for c in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        found: dict[str, str] = {}
        for outcome in results:
            if isinstance(outcome, Exception):
                continue
            host, ip = outcome
            if ip:
                found[host] = ip

        return found

    # ── External tool runners ─────────────────────────────────────────────────

    async def _run_subfinder(self, domain: str) -> list[str]:
        return await _run_tool(
            ["subfinder", "-d", domain, "-silent", "-all"],
            name="subfinder",
        )

    async def _run_amass(self, domain: str) -> list[str]:
        return await _run_tool(
            ["amass", "enum", "-passive", "-d", domain, "-nocolor"],
            name="amass",
        )


# ── Module-level helpers ──────────────────────────────────────────────────────

def _add(
    store: dict[str, SubdomainFinding],
    host: str,
    source: str,
    ip: Optional[str] = None,
) -> None:
    host = host.lower().rstrip(".")
    if host in store:
        if source not in store[host].sources:
            store[host].sources.append(source)
        if ip and not store[host].ip:
            store[host].ip = ip
    else:
        store[host] = SubdomainFinding(host=host, ip=ip, sources=[source])


def _load_wordlist(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


async def _run_tool(cmd: list[str], name: str) -> list[str]:
    try:
        loop = asyncio.get_event_loop()
        proc = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120
                ),
            ),
            timeout=130,
        )
        return [
            line.strip().lower()
            for line in proc.stdout.splitlines()
            if line.strip()
        ]
    except Exception as exc:
        logger.debug(f"{name} execution error: {exc}")
        return []
