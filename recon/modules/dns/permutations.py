from __future__ import annotations

"""Generate subdomain permutations from a set of already-discovered hosts
and return the candidates for further DNS resolution.
"""

_PREFIXES = ["dev", "prod", "staging", "stg", "test", "uat", "qa", "api", "v2", "v3",
             "old", "new", "beta", "alpha", "internal", "private", "pub", "ext", "int"]
_SUFFIXES = ["dev", "prod", "staging", "stg", "test", "uat", "qa", "api", "2", "3",
             "old", "new", "beta", "bak", "backup"]


def generate(known_subdomains: list[str], domain: str) -> list[str]:
    """
    Given a list of FQDNs (e.g. ["api.example.com", "dev.example.com"]),
    return a deduplicated list of candidate FQDNs to resolve.

    Strategy:
    1. Extract the sub-label(s) before the apex
    2. Build prefix-X and X-suffix variants
    3. Append numeric suffixes (1–5)
    """
    candidates: set[str] = set()

    for fqdn in known_subdomains:
        # Strip apex to get the subdomain part
        if not fqdn.endswith(f".{domain}"):
            continue
        sub = fqdn[: -(len(domain) + 1)]  # e.g. "api" or "api.v2"
        labels = sub.split(".")
        for label in labels:
            if not label or label in ("www", "mail"):
                continue
            for prefix in _PREFIXES:
                candidates.add(f"{prefix}-{label}.{domain}")
                candidates.add(f"{prefix}{label}.{domain}")
            for suffix in _SUFFIXES:
                candidates.add(f"{label}-{suffix}.{domain}")
                candidates.add(f"{label}{suffix}.{domain}")
            for n in range(1, 6):
                candidates.add(f"{label}{n}.{domain}")

    # Remove already-known hosts
    known_set = set(known_subdomains)
    return sorted(candidates - known_set)
