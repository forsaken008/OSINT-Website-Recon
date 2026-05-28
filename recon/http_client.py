from __future__ import annotations

import asyncio
import random
import socket
from typing import Optional

import aiohttp
from loguru import logger

from .config import Config
from .rate_limiter import RateLimiterRegistry, get_registry

# Current realistic browser UAs — updated pool prevents trivial fingerprinting
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.113 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
]

_BASE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


def random_ua() -> str:
    return random.choice(_USER_AGENTS)


def build_headers(custom_ua: Optional[str] = None) -> dict[str, str]:
    h = dict(_BASE_HEADERS)
    h["User-Agent"] = custom_ua or random_ua()
    return h


async def _detect_tor(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """Return True if a SOCKS5 listener is reachable on host:port."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=1.5
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def build_session(
    config: Config,
    service: str = "target",
    custom_ua: Optional[str] = None,
    timeout_secs: float = 15.0,
) -> aiohttp.ClientSession:
    """
    Create a fully configured aiohttp.ClientSession.

    Applies proxy/Tor settings, rotated User-Agent, and a shared connector.
    The caller is responsible for closing the session.
    """
    proxy_url: Optional[str] = None

    if config.proxy.enabled and config.proxy.url:
        proxy_url = config.proxy.url
        logger.debug(f"Using proxy: {proxy_url}")
    elif config.proxy.tor_autodetect and await _detect_tor():
        proxy_url = "socks5://127.0.0.1:9050"
        logger.info("Tor detected — routing through SOCKS5 127.0.0.1:9050")

    connector = aiohttp.TCPConnector(
        ssl=False,           # TLS verification handled per-request where needed
        limit=100,
        limit_per_host=10,
        ttl_dns_cache=300,
        use_dns_cache=True,
    )

    timeout = aiohttp.ClientTimeout(total=timeout_secs, connect=8.0, sock_read=timeout_secs)

    session = aiohttp.ClientSession(
        connector=connector,
        headers=build_headers(custom_ua),
        timeout=timeout,
        trust_env=True,
    )

    # Monkey-patch proxy onto the session so callers can retrieve it
    session._recon_proxy = proxy_url  # type: ignore[attr-defined]

    return session


async def safe_get(
    session: aiohttp.ClientSession,
    url: str,
    service: str = "target",
    retries: int = 2,
    **kwargs,
) -> Optional[aiohttp.ClientResponse]:
    """
    Rate-limited GET with retry on transient errors.
    Returns the response (caller must read body) or None on permanent failure.
    """
    registry = get_registry()
    proxy = getattr(session, "_recon_proxy", None)

    for attempt in range(retries + 1):
        await registry.acquire(service)
        try:
            resp = await session.get(
                url,
                proxy=proxy,
                allow_redirects=True,
                ssl=False,
                **kwargs,
            )
            if resp.status == 429:
                retry_after = float(resp.headers.get("Retry-After", "30"))
                logger.warning(f"Rate-limited by {service} — waiting {retry_after}s")
                await asyncio.sleep(retry_after)
                continue
            return resp
        except asyncio.TimeoutError:
            logger.debug(f"Timeout on {url} (attempt {attempt + 1})")
        except aiohttp.ClientConnectorError as exc:
            logger.debug(f"Connection error on {url}: {exc}")
            break
        except Exception as exc:
            logger.debug(f"Unexpected error on {url}: {exc}")
            if attempt == retries:
                break
        await asyncio.sleep(1.5 * (attempt + 1))

    return None
