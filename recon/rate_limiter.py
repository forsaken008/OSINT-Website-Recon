from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict
from typing import Optional


class TokenBucket:
    """Async token-bucket rate limiter with jitter."""

    def __init__(self, rate: float, per: float = 1.0, burst: Optional[float] = None) -> None:
        """
        rate: tokens to add per `per` seconds
        per:  refill interval in seconds (1.0 = per second, 60.0 = per minute)
        burst: max tokens (defaults to rate, i.e. no burst)
        """
        self._rate = rate / per          # tokens per second
        self._capacity = burst or rate
        self._tokens = float(self._capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0, jitter: float = 0.2) -> None:
        """Block until `tokens` are available, then consume them.

        jitter adds a random ±jitter fraction delay on top of the wait
        to prevent synchronized bursts from multiple callers.
        """
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)

                if self._tokens >= tokens:
                    self._tokens -= tokens
                    if jitter > 0:
                        wait = (1.0 / self._rate) * random.uniform(-jitter, jitter)
                        if wait > 0:
                            await asyncio.sleep(wait)
                    return

                wait = (tokens - self._tokens) / self._rate
                await asyncio.sleep(wait)


class RateLimiterRegistry:
    """Registry of named token-bucket limiters, one per service."""

    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    def _make_key(self, service: str) -> str:
        return service.lower().replace("-", "_")

    async def register(
        self,
        service: str,
        rate: float,
        per: float = 1.0,
        burst: Optional[float] = None,
    ) -> None:
        key = self._make_key(service)
        async with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(rate, per, burst)

    async def acquire(self, service: str, tokens: float = 1.0) -> None:
        key = self._make_key(service)
        bucket = self._buckets.get(key)
        if bucket is None:
            # Unregistered service — allow without limiting
            return
        await bucket.acquire(tokens)

    def acquire_sync(self, service: str) -> None:
        """Synchronous acquire for use in non-async code paths."""
        key = self._make_key(service)
        bucket = self._buckets.get(key)
        if bucket is None:
            return
        # In sync context, just sleep the minimum interval
        time.sleep(1.0 / bucket._rate)


_registry: Optional[RateLimiterRegistry] = None


def get_registry() -> RateLimiterRegistry:
    global _registry
    if _registry is None:
        _registry = RateLimiterRegistry()
    return _registry


async def setup_rate_limits(config) -> RateLimiterRegistry:
    """Initialise the global registry from the loaded Config object."""
    reg = get_registry()
    rl = config.rate_limits
    await reg.register("target",      rate=rl.target,      per=1.0)
    await reg.register("ip_api",      rate=rl.ip_api,      per=60.0)
    await reg.register("archive_org", rate=rl.archive_org, per=60.0)
    await reg.register("crt_sh",      rate=rl.crt_sh,      per=1.0)
    await reg.register("shodan",      rate=rl.shodan,       per=1.0)
    await reg.register("virustotal",  rate=rl.virustotal,   per=60.0)
    await reg.register("dns",         rate=config.dns.concurrency, per=1.0)
    return reg
