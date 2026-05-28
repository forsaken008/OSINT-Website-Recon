from __future__ import annotations

import asyncio
import re
from typing import Optional

from loguru import logger

from ...http_client import build_session, safe_get
from ...models import CTLogsResult, ScanResult
from ..base import BaseModule

_WILDCARD_RE = re.compile(r"^\*\.")
_VALID_LABEL = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


class CTLogsModule(BaseModule):
    name = "ct_logs"
    label = "Certificate Transparency Logs"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"Querying crt.sh for *.{domain}")

        session = await build_session(self.config, service="crt_sh", timeout_secs=30)
        try:
            domains = await self._fetch_crtsh(session, domain)
        finally:
            await session.close()

        if not domains:
            self.warn("No CT log entries found — crt.sh may be rate-limiting or domain has no certs")
        else:
            self.success(f"CT logs: {len(domains)} unique hostnames found")

        result.ct_logs = CTLogsResult(
            domains=sorted(domains),
            total_certs=len(domains),
        )
        result.modules_run.append(self.name)
        return result

    async def _fetch_crtsh(
        self, session, domain: str, retries: int = 3
    ) -> list[str]:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        found: set[str] = set()

        resp = await safe_get(session, url, service="crt_sh", retries=retries)
        if resp is None:
            return []

        try:
            data = await resp.json(content_type=None)
        except Exception as exc:
            logger.debug(f"crt.sh JSON parse error: {exc}")
            return []

        apex = f".{domain}"
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.splitlines():
                name = name.strip().lower()
                # Strip leading wildcard
                name = _WILDCARD_RE.sub("", name)
                # Must end with the target apex
                if not (name == domain or name.endswith(apex)):
                    continue
                # Validate each label
                labels = name.split(".")
                if all(_VALID_LABEL.match(lbl) for lbl in labels):
                    found.add(name)

        return sorted(found)
