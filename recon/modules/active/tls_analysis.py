from __future__ import annotations

"""TLS / SSL analysis module.

Priority:
  1. sslyze Python library — comprehensive audit
  2. Manual ssl socket inspection — fallback when sslyze unavailable
"""

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

from loguru import logger

from ...models import ScanResult, TLSResult
from ..base import BaseModule

# Protocols in descending-security order
_PROTOCOL_LABELS: list[tuple[str, int]] = [
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
]

# Weak cipher substrings
_WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "MD5", "IDEA", "CAMELLIA_128_CBC",
]


class TLSAnalysisModule(BaseModule):
    name = "tls"
    label = "TLS / SSL Analysis"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"TLS analysis of {domain}:443")

        tls_result: Optional[TLSResult] = None

        # Try sslyze first
        try:
            import sslyze  # noqa: F401
            tls_result = await self._sslyze_scan(domain)
        except ImportError:
            logger.debug("sslyze not installed — using manual TLS inspection")
        except Exception as exc:
            logger.warning(f"sslyze failed: {exc} — falling back")

        # Manual fallback
        if tls_result is None:
            tls_result = await self._manual_scan(domain)

        result.tls = tls_result
        result.modules_run.append(self.name)

        if tls_result and tls_result.flags:
            for flag in tls_result.flags:
                self.warn(flag)
        else:
            self.success("TLS analysis complete")
        return result

    # ── sslyze ────────────────────────────────────────────────────────────────

    async def _sslyze_scan(self, domain: str) -> TLSResult:
        from sslyze import (
            Scanner, ServerNetworkLocation, ServerScanRequest,
            ScanCommand,
        )
        from sslyze.errors import ConnectionToServerFailed

        location = ServerNetworkLocation(hostname=domain, port=443)
        request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.SESSION_RENEGOTIATION,
                ScanCommand.HTTP_HEADERS,
            },
        )

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _run_sslyze, request)
        return result

    # ── Manual inspection ─────────────────────────────────────────────────────

    async def _manual_scan(self, domain: str) -> TLSResult:
        tls = TLSResult(sslyze_used=False)
        loop = asyncio.get_event_loop()

        # Primary certificate info
        cert_info = await loop.run_in_executor(None, _get_cert_info, domain)
        if cert_info:
            tls.subject_cn = cert_info.get("subject_cn", "")
            tls.issuer = cert_info.get("issuer", "")
            tls.not_before = cert_info.get("not_before", "")
            tls.not_after = cert_info.get("not_after", "")
            tls.sans = cert_info.get("sans", [])
            tls.key_bits = cert_info.get("key_bits", 0)
            tls.key_type = cert_info.get("key_type", "")
            tls.sig_algorithm = cert_info.get("sig_algorithm", "")

            # Expiry check
            try:
                exp = datetime.strptime(tls.not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.utcnow()).days
                if days_left < 0:
                    tls.flags.append(f"CERTIFICATE EXPIRED {abs(days_left)} days ago")
                elif days_left < 14:
                    tls.flags.append(f"Certificate expires in {days_left} days")
            except Exception:
                pass

            # Key strength
            if tls.key_bits and tls.key_bits < 2048 and tls.key_type.upper() == "RSA":
                tls.flags.append(f"Weak RSA key: {tls.key_bits} bits (minimum is 2048)")
            if "sha1" in tls.sig_algorithm.lower():
                tls.flags.append(f"SHA-1 signature algorithm is deprecated: {tls.sig_algorithm}")

        # Check which protocols are accepted
        for label, min_ver in _PROTOCOL_LABELS:
            accepted = await loop.run_in_executor(
                None, _test_protocol, domain, min_ver, min_ver
            )
            if accepted:
                tls.protocols_accepted.append(label)
            else:
                tls.protocols_rejected.append(label)

        # Check legacy protocols (TLS 1.0 / 1.1) — flag if accepted
        for label, const in [("TLS 1.1", "PROTOCOL_TLSv1_1"), ("TLS 1.0", "PROTOCOL_TLSv1")]:
            proto = getattr(ssl, const, None)
            if proto is None:
                continue
            accepted = await loop.run_in_executor(
                None, _test_legacy_protocol, domain, proto
            )
            if accepted:
                tls.protocols_accepted.append(label)
                tls.flags.append(f"{label} accepted — deprecated, should be disabled")

        # Cipher suite sample
        ctx = ssl.create_default_context()
        ciphers = ctx.get_ciphers()
        all_names = [c["name"] for c in ciphers]
        tls.cipher_suites = all_names[:20]
        tls.weak_ciphers = [
            c for c in all_names
            if any(p in c.upper() for p in _WEAK_CIPHER_PATTERNS)
        ]
        if tls.weak_ciphers:
            tls.flags.append(f"Weak cipher(s) in local config: {', '.join(tls.weak_ciphers[:3])}")

        tls.sslyze_used = False
        return tls


# ── Sync helpers (run in executor) ───────────────────────────────────────────

def _get_cert_info(domain: str) -> Optional[dict]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

        def _flat(field) -> dict:
            out = {}
            for rdn in field:
                for attr in rdn:
                    out[attr[0]] = attr[1]
            return out

        subject = _flat(cert.get("subject", ()))
        issuer = _flat(cert.get("issuer", ()))

        sans: list[str] = []
        for kind, val in cert.get("subjectAltName", ()):
            if kind == "DNS":
                sans.append(val)

        # Key info from cipher tuple: ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
        key_bits = cipher[2] if cipher else 0
        key_type = "RSA" if cipher and "RSA" in cipher[0] else "ECDSA"
        sig_algo = cert.get("signatureAlgorithm", "")

        return {
            "subject_cn": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
            "not_before": cert.get("notBefore", ""),
            "not_after": cert.get("notAfter", ""),
            "sans": sans,
            "key_bits": key_bits,
            "key_type": key_type,
            "sig_algorithm": sig_algo,
        }
    except Exception as exc:
        logger.debug(f"Certificate fetch failed: {exc}")
        return None


def _test_protocol(domain: str, min_ver, max_ver) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def _test_legacy_protocol(domain: str, proto) -> bool:
    try:
        ctx = ssl.SSLContext(proto)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def _run_sslyze(request) -> TLSResult:
    """Synchronous sslyze runner."""
    from sslyze import Scanner
    from sslyze.errors import ConnectionToServerFailed

    tls = TLSResult(sslyze_used=True)
    scanner = Scanner()
    scanner.queue_scans([request])
    for scan_result in scanner.get_results():
        if isinstance(scan_result, ConnectionToServerFailed):
            raise RuntimeError(f"sslyze connection failed: {scan_result.error_message}")
        _apply_sslyze_result(tls, scan_result)
    return tls


def _apply_sslyze_result(tls: TLSResult, scan_result) -> None:
    from sslyze import ScanCommand

    # Certificate info
    cert_info = scan_result.scan_commands_results.get(ScanCommand.CERTIFICATE_INFO)
    if cert_info:
        try:
            chain = cert_info.certificate_deployments[0]
            leaf = chain.received_certificate_chain[0]
            tls.subject_cn = str(leaf.subject.get_attributes_for_oid(
                leaf.subject.oid if hasattr(leaf.subject, "oid") else None
            ))
            tls.sans = [san.value for san in leaf.extensions.get_extension_for_class(
                __import__("cryptography.x509", fromlist=["SubjectAlternativeName"]).SubjectAlternativeName
            ).value if hasattr(san, "value")]
        except Exception:
            pass

    # Protocol flags
    _PROTO_MAP = {
        "SSL_2_0_CIPHER_SUITES": "SSL 2.0",
        "SSL_3_0_CIPHER_SUITES": "SSL 3.0",
        "TLS_1_0_CIPHER_SUITES": "TLS 1.0",
        "TLS_1_1_CIPHER_SUITES": "TLS 1.1",
        "TLS_1_2_CIPHER_SUITES": "TLS 1.2",
        "TLS_1_3_CIPHER_SUITES": "TLS 1.3",
    }
    for cmd_name, label in _PROTO_MAP.items():
        cmd = getattr(ScanCommand, cmd_name, None)
        if cmd is None:
            continue
        res = scan_result.scan_commands_results.get(cmd)
        if res and res.accepted_cipher_suites:
            tls.protocols_accepted.append(label)
            if label in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"):
                tls.flags.append(f"{label} is accepted — deprecated, must be disabled")
        else:
            tls.protocols_rejected.append(label)

    # Heartbleed
    hb = scan_result.scan_commands_results.get(ScanCommand.HEARTBLEED)
    if hb and hb.is_vulnerable_to_heartbleed:
        tls.flags.append("HEARTBLEED VULNERABLE")

    # ROBOT
    robot = scan_result.scan_commands_results.get(ScanCommand.ROBOT)
    if robot and "VULNERABLE" in str(robot.robot_result):
        tls.flags.append("ROBOT attack VULNERABLE")
