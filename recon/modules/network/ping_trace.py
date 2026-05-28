from __future__ import annotations

import asyncio
import os
import re
import subprocess

from ...models import PingResult, ScanResult, TracerouteResult
from ..base import BaseModule


class PingModule(BaseModule):
    name = "ping"
    label = "Ping"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"Pinging {domain}")

        param = "-n" if os.name == "nt" else "-c"
        cmd = ["ping", param, "4", domain]
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

        loop = asyncio.get_event_loop()
        try:
            proc = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        cmd, capture_output=True, text=True, timeout=30,
                        creationflags=flags,
                    ),
                ),
                timeout=35,
            )
            output = proc.stdout or proc.stderr or ""
            reachable = proc.returncode == 0
            avg_ms = _parse_avg_ms(output)
        except asyncio.TimeoutError:
            output = "Ping timed out after 30s."
            reachable = False
            avg_ms = None
        except Exception as exc:
            output = f"Ping failed: {exc}"
            reachable = False
            avg_ms = None

        result.ping = PingResult(output=output, reachable=reachable, avg_ms=avg_ms)
        result.modules_run.append(self.name)

        if reachable:
            self.success(f"Host is reachable  avg={avg_ms}ms" if avg_ms else "Host is reachable")
        else:
            self.warn("Host did not respond to ping (may be filtered)")
        return result


class TracerouteModule(BaseModule):
    name = "traceroute"
    label = "Traceroute"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"Traceroute to {domain}")

        if os.name == "nt":
            cmd = ["tracert", "-h", "20", domain]
        else:
            cmd = ["traceroute", "-m", "20", "-q", "1", domain]

        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        loop = asyncio.get_event_loop()

        timed_out = False
        try:
            proc = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        cmd, capture_output=True, text=True, timeout=90,
                        creationflags=flags,
                    ),
                ),
                timeout=95,
            )
            output = proc.stdout or proc.stderr or ""
        except asyncio.TimeoutError:
            output = "Traceroute timed out after 90s — target may be filtering ICMP TTL-exceeded."
            timed_out = True
        except FileNotFoundError:
            output = "traceroute/tracert not found on this system."
        except Exception as exc:
            output = f"Traceroute failed: {exc}"

        hops = len(re.findall(r"^\s*\d+\s", output, re.MULTILINE)) if not timed_out else 0

        result.traceroute = TracerouteResult(
            output=output, hops=hops, timed_out=timed_out
        )
        result.modules_run.append(self.name)

        if timed_out:
            self.warn("Traceroute timed out — path may be filtered")
        else:
            self.success(f"Traceroute complete — {hops} hop(s)")
        return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_avg_ms(output: str) -> float | None:
    # Windows: "Average = 12ms"  Unix: "min/avg/max/mdev = 1.2/2.3/3.4/0.5 ms"
    m = re.search(r"(?:Average\s*=\s*(\d+)ms|/(\d+(?:\.\d+)?)/)", output)
    if m:
        val = m.group(1) or m.group(2)
        try:
            return float(val)
        except ValueError:
            pass
    return None
