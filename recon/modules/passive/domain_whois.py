from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

import whois
from loguru import logger

from ...models import DomainWhoisResult, ScanResult
from ..base import BaseModule


class DomainWhoisModule(BaseModule):
    name = "domain_whois"
    label = "Domain WHOIS"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"WHOIS lookup for {domain}")

        try:
            # python-whois is synchronous — offload to thread pool
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
        except Exception as exc:
            logger.warning(f"WHOIS lookup failed for {domain}: {exc}")
            result.errors["domain_whois"] = str(exc)
            result.modules_run.append(self.name)
            return result

        whois_result = DomainWhoisResult()

        def _first(val) -> Optional[str]:
            if val is None:
                return None
            if isinstance(val, list):
                val = val[0] if val else None
            return str(val) if val is not None else None

        def _dt_str(val) -> Optional[str]:
            if val is None:
                return None
            if isinstance(val, list):
                val = val[0] if val else None
            if isinstance(val, datetime):
                return val.isoformat()
            return str(val) if val else None

        whois_result.registrar = _first(w.registrar)
        whois_result.created = _dt_str(w.creation_date)
        whois_result.expires = _dt_str(w.expiration_date)
        whois_result.updated = _dt_str(w.updated_date)
        whois_result.dnssec = _first(w.dnssec)
        whois_result.raw = str(w.text) if hasattr(w, "text") else None

        if w.status:
            statuses = w.status if isinstance(w.status, list) else [w.status]
            whois_result.status = [str(s) for s in statuses]

        if w.name_servers:
            ns_list = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
            whois_result.name_servers = sorted(set(str(n).lower() for n in ns_list if n))

        # Registrant fields vary by TLD and GDPR redaction
        for attr in ("org", "organization", "registrant_org", "registrant_organization"):
            val = getattr(w, attr, None)
            if val and not str(val).lower().startswith("redacted"):
                whois_result.registrant_org = str(val)
                break

        for attr in ("country", "registrant_country"):
            val = getattr(w, attr, None)
            if val:
                whois_result.registrant_country = str(val)
                break

        # Expiry warning: flag if less than 30 days away
        if whois_result.expires:
            try:
                exp_dt = datetime.fromisoformat(whois_result.expires.replace("Z", "+00:00"))
                exp_naive = exp_dt.replace(tzinfo=None) if exp_dt.tzinfo else exp_dt
                now = datetime.utcnow()
                days_left = (exp_naive - now).days
                if 0 <= days_left <= 30:
                    whois_result.expiry_warning = True
                    self.warn(f"Domain expires in {days_left} day(s)! ({whois_result.expires})")
            except Exception:
                pass

        result.domain_whois = whois_result
        result.modules_run.append(self.name)

        self.success(f"WHOIS: registrar={whois_result.registrar}, expires={whois_result.expires}")
        return result
