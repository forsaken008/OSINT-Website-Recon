from __future__ import annotations

from loguru import logger

from ...http_client import build_session, safe_get
from ...models import GeolocationResult, ScanResult
from ..base import BaseModule


class GeolocationModule(BaseModule):
    name = "geo"
    label = "Geolocation"

    async def run(self, result: ScanResult) -> ScanResult:
        ip = result.ip_info.ip if result.ip_info else None
        if not ip:
            self.warn("No resolved IP — skipping geolocation")
            return result

        self.info(f"Geolocating {ip}")

        session = await build_session(self.config, service="ip_api", timeout_secs=10)
        try:
            geo = await self._fetch(session, ip)
        finally:
            await session.close()

        result.geolocation = geo
        result.modules_run.append(self.name)
        if geo:
            self.success(f"Location: {geo.city}, {geo.region}, {geo.country} — ISP: {geo.isp}")
        return result

    async def _fetch(self, session, ip: str) -> GeolocationResult:
        # Primary: ip-api.com (free, HTTPS)
        resp = await safe_get(
            session,
            f"https://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as",
            service="ip_api",
        )
        if resp and resp.status == 200:
            try:
                data = await resp.json(content_type=None)
                if data.get("status") == "success":
                    return GeolocationResult(
                        ip=ip,
                        city=data.get("city", ""),
                        region=data.get("regionName", ""),
                        country=data.get("country", ""),
                        lat=float(data.get("lat", 0)),
                        lon=float(data.get("lon", 0)),
                        isp=data.get("isp", ""),
                        org=data.get("org", ""),
                        source="ip-api.com",
                    )
            except Exception as exc:
                logger.debug(f"ip-api.com parse error: {exc}")

        # Fallback: ipinfo.io
        resp2 = await safe_get(session, f"https://ipinfo.io/{ip}/json", service="ip_api")
        if resp2 and resp2.status == 200:
            try:
                data = await resp2.json(content_type=None)
                loc = data.get("loc", "0,0").split(",")
                return GeolocationResult(
                    ip=ip,
                    city=data.get("city", ""),
                    region=data.get("region", ""),
                    country=data.get("country", ""),
                    lat=float(loc[0]) if loc else 0.0,
                    lon=float(loc[1]) if len(loc) > 1 else 0.0,
                    isp=data.get("org", ""),
                    source="ipinfo.io",
                )
            except Exception as exc:
                logger.debug(f"ipinfo.io parse error: {exc}")

        self.warn("Both geolocation providers failed")
        return GeolocationResult(ip=ip)
