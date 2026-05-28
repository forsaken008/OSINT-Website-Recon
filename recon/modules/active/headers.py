from __future__ import annotations

"""HTTP & Security Headers analysis with scoring.

Checks all security-relevant headers, parses CSP and HSTS directives,
flags cookies missing security attributes, and assigns an overall grade.
"""

import re
from typing import Optional

from loguru import logger

from ...http_client import build_session, safe_get
from ...models import HeaderAnalysisItem, HeadersResult, ScanResult
from ..base import BaseModule

_CSP_UNSAFE = ["'unsafe-inline'", "'unsafe-eval'", "data:", "http:"]
_CSP_WILDCARD = re.compile(r"(?:^|\s)\*(?:\s|$|;)")


class HeadersModule(BaseModule):
    name = "headers"
    label = "HTTP & Security Headers"

    async def run(self, result: ScanResult) -> ScanResult:
        domain = result.target
        self.info(f"Fetching headers from {domain}")

        session = await build_session(self.config, service="target", timeout_secs=15)
        try:
            # Prefer HTTPS
            resp = await safe_get(session, f"https://{domain}", service="target")
            https_ok = resp is not None

            if not https_ok:
                resp = await safe_get(session, f"http://{domain}", service="target")

            if resp is None:
                self.warn("Could not reach target for header analysis")
                return result

            final_url = str(resp.url)
            status = resp.status
            raw_headers = dict(resp.headers)

            # Check if HTTP redirects to HTTPS
            https_redirect = False
            if not https_ok:
                r2 = await safe_get(session, f"http://{domain}", service="target")
                if r2 and str(r2.url).startswith("https://"):
                    https_redirect = True
        finally:
            await session.close()

        analysis = _analyse_headers(raw_headers, https_ok, https_redirect)
        grade = _grade(analysis)

        result.headers = HeadersResult(
            final_url=final_url,
            status_code=status,
            raw_headers={k: v for k, v in raw_headers.items()},
            server=raw_headers.get("Server", raw_headers.get("server", "")),
            https_redirect=https_redirect,
            security_analysis=analysis,
            score=grade,
        )
        result.modules_run.append(self.name)

        fails = sum(1 for a in analysis if a.status == "fail")
        warns = sum(1 for a in analysis if a.status == "warn")
        self.success(f"Header analysis: grade {grade} ({fails} fail, {warns} warn)")
        return result


# ── Analysis logic ────────────────────────────────────────────────────────────

def _analyse_headers(
    headers: dict[str, str], https_ok: bool, https_redirect: bool
) -> list[HeaderAnalysisItem]:
    items: list[HeaderAnalysisItem] = []
    h = {k.lower(): v for k, v in headers.items()}

    # ── HTTPS ─────────────────────────────────────────────────────────────────
    if not https_ok:
        items.append(HeaderAnalysisItem(
            header="HTTPS",
            status="fail",
            detail="Site not reachable over HTTPS",
        ))
    else:
        items.append(HeaderAnalysisItem(
            header="HTTPS", status="pass", detail="HTTPS available"
        ))

    # ── HSTS ──────────────────────────────────────────────────────────────────
    hsts = h.get("strict-transport-security", "")
    if not hsts:
        items.append(HeaderAnalysisItem(
            header="Strict-Transport-Security",
            status="fail",
            detail="Not set — browsers may visit over HTTP",
        ))
    else:
        max_age = _parse_hsts_max_age(hsts)
        issues = []
        if max_age < 15552000:
            issues.append(f"max-age={max_age} is below 180-day minimum ({15552000}s)")
        if "includesubdomains" not in hsts.lower():
            issues.append("missing includeSubDomains")
        if "preload" not in hsts.lower():
            issues.append("missing preload directive")
        if issues:
            items.append(HeaderAnalysisItem(
                header="Strict-Transport-Security",
                status="warn",
                detail=f"Present but weak: {'; '.join(issues)}",
            ))
        else:
            items.append(HeaderAnalysisItem(
                header="Strict-Transport-Security",
                status="pass",
                detail=f"max-age={max_age}, includeSubDomains, preload",
            ))

    # ── CSP ───────────────────────────────────────────────────────────────────
    csp = h.get("content-security-policy", "")
    if not csp:
        items.append(HeaderAnalysisItem(
            header="Content-Security-Policy",
            status="fail",
            detail="Not set",
        ))
    else:
        csp_issues = _analyse_csp(csp)
        if csp_issues:
            items.append(HeaderAnalysisItem(
                header="Content-Security-Policy",
                status="warn" if len(csp_issues) < 3 else "fail",
                detail="Issues: " + "; ".join(csp_issues),
            ))
        else:
            items.append(HeaderAnalysisItem(
                header="Content-Security-Policy",
                status="pass",
                detail="Present, no obvious weaknesses",
            ))

    # ── X-Frame-Options ───────────────────────────────────────────────────────
    xfo = h.get("x-frame-options", "")
    if not xfo:
        items.append(HeaderAnalysisItem(
            header="X-Frame-Options",
            status="warn",
            detail="Not set — clickjacking protection missing (CSP frame-ancestors preferred)",
        ))
    elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
        items.append(HeaderAnalysisItem(
            header="X-Frame-Options",
            status="warn",
            detail=f"Unexpected value: {xfo}",
        ))
    else:
        items.append(HeaderAnalysisItem(
            header="X-Frame-Options", status="pass", detail=xfo
        ))

    # ── X-Content-Type-Options ────────────────────────────────────────────────
    xcto = h.get("x-content-type-options", "")
    if xcto.lower() != "nosniff":
        items.append(HeaderAnalysisItem(
            header="X-Content-Type-Options",
            status="warn" if xcto else "fail",
            detail="Not set" if not xcto else f"Value should be 'nosniff', got: {xcto}",
        ))
    else:
        items.append(HeaderAnalysisItem(
            header="X-Content-Type-Options", status="pass", detail="nosniff"
        ))

    # ── Referrer-Policy ───────────────────────────────────────────────────────
    rp = h.get("referrer-policy", "")
    bad_policies = ("unsafe-url", "no-referrer-when-downgrade")
    if not rp:
        items.append(HeaderAnalysisItem(
            header="Referrer-Policy",
            status="warn",
            detail="Not set (browser default may leak full URL in Referer header)",
        ))
    elif any(bp in rp.lower() for bp in bad_policies):
        items.append(HeaderAnalysisItem(
            header="Referrer-Policy",
            status="warn",
            detail=f"Leaky policy: {rp}",
        ))
    else:
        items.append(HeaderAnalysisItem(
            header="Referrer-Policy", status="pass", detail=rp
        ))

    # ── Permissions-Policy ────────────────────────────────────────────────────
    pp = h.get("permissions-policy", "")
    if not pp:
        items.append(HeaderAnalysisItem(
            header="Permissions-Policy",
            status="warn",
            detail="Not set — browser features unrestricted",
        ))
    else:
        items.append(HeaderAnalysisItem(
            header="Permissions-Policy", status="pass", detail="Present"
        ))

    # ── Cookie flags ──────────────────────────────────────────────────────────
    set_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for raw_cookie in set_cookies:
        cookie_name = raw_cookie.split("=")[0].strip()
        lower = raw_cookie.lower()
        issues = []
        if "httponly" not in lower:
            issues.append("missing HttpOnly")
        if "secure" not in lower:
            issues.append("missing Secure")
        if "samesite" not in lower:
            issues.append("missing SameSite")
        elif "samesite=none" in lower and "secure" not in lower:
            issues.append("SameSite=None without Secure")
        if issues:
            items.append(HeaderAnalysisItem(
                header=f"Cookie: {cookie_name}",
                status="warn",
                detail=", ".join(issues),
            ))

    # ── Server header disclosure ──────────────────────────────────────────────
    server = h.get("server", "")
    if server and re.search(r"[\d.]", server):
        items.append(HeaderAnalysisItem(
            header="Server",
            status="warn",
            detail=f"Version disclosed: {server}",
        ))

    # ── X-Powered-By ─────────────────────────────────────────────────────────
    xpb = h.get("x-powered-by", "")
    if xpb:
        items.append(HeaderAnalysisItem(
            header="X-Powered-By",
            status="warn",
            detail=f"Technology disclosed: {xpb} — consider removing",
        ))

    return items


def _analyse_csp(csp: str) -> list[str]:
    issues: list[str] = []
    directives: dict[str, str] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = " ".join(tokens[1:])

    if "default-src" not in directives and "script-src" not in directives:
        issues.append("no default-src or script-src directive")

    for directive, value in directives.items():
        if "script" in directive or directive == "default-src":
            if "'unsafe-inline'" in value:
                issues.append(f"{directive}: 'unsafe-inline' allows XSS")
            if "'unsafe-eval'" in value:
                issues.append(f"{directive}: 'unsafe-eval' allows XSS")
            if _CSP_WILDCARD.search(value):
                issues.append(f"{directive}: wildcard (*) allows any origin")
            if "http:" in value:
                issues.append(f"{directive}: http: allows mixed content downgrade")

    return issues


def _parse_hsts_max_age(hsts: str) -> int:
    m = re.search(r"max-age=(\d+)", hsts, re.I)
    return int(m.group(1)) if m else 0


def _grade(items: list[HeaderAnalysisItem]) -> str:
    fails = sum(1 for i in items if i.status == "fail")
    warns = sum(1 for i in items if i.status == "warn")
    if fails >= 3:
        return "F"
    if fails == 2:
        return "D"
    if fails == 1 or warns >= 4:
        return "C"
    if warns >= 2:
        return "B"
    if warns == 1:
        return "B+"
    return "A"
