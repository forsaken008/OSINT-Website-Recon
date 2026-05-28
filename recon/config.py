from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class APIKeys(BaseModel):
    shodan: str = ""
    virustotal: str = ""
    securitytrails: str = ""
    alienvault: str = ""


class RateLimits(BaseModel):
    target: float = 10.0       # req/sec against the scan target
    ip_api: float = 40.0       # req/min (limit is 45)
    archive_org: float = 8.0   # req/min
    crt_sh: float = 3.0        # req/sec
    shodan: float = 1.0        # req/sec
    virustotal: float = 4.0    # req/min (free tier)


class DNSConfig(BaseModel):
    resolvers: list[str] = Field(default_factory=lambda: [
        "8.8.8.8", "1.1.1.1", "9.9.9.9",
        "208.67.222.222", "8.8.4.4",
    ])
    concurrency: int = 200
    timeout: float = 3.0
    validation_resolvers: int = 2   # confirm positives against N resolvers


class ScanConfig(BaseModel):
    subdomain_permutations: bool = True
    axfr_attempt: bool = True
    js_analysis: bool = True
    content_verify_exposed: bool = True  # verify .git/.env body content
    soft_404_detection: bool = True
    external_tools: bool = True          # use subfinder/amass/nmap if in PATH


class ProxyConfig(BaseModel):
    enabled: bool = False
    url: str = ""               # e.g. socks5://127.0.0.1:9050
    tor_autodetect: bool = True


class WordlistConfig(BaseModel):
    subdomains: str = "wordlists/subdomains.txt"
    paths: str = "wordlists/paths.txt"


class Config(BaseModel):
    api_keys: APIKeys = Field(default_factory=APIKeys)
    rate_limits: RateLimits = Field(default_factory=RateLimits)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    wordlists: WordlistConfig = Field(default_factory=WordlistConfig)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        """Load from YAML, then overlay environment variable overrides."""
        data: dict[str, Any] = {}

        config_path = Path(path) if path else Path("config.yaml")
        if config_path.exists():
            with open(config_path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}

        # Environment variable overrides (no config file required)
        env_map = {
            "SHODAN_API_KEY": ("api_keys", "shodan"),
            "VT_API_KEY": ("api_keys", "virustotal"),
            "SECURITYTRAILS_API_KEY": ("api_keys", "securitytrails"),
            "OTX_API_KEY": ("api_keys", "alienvault"),
            "RECON_PROXY": ("proxy", "url"),
        }
        for env_var, (section, key) in env_map.items():
            value = os.environ.get(env_var)
            if value:
                data.setdefault(section, {})[key] = value
                if env_var == "RECON_PROXY":
                    data["proxy"]["enabled"] = True

        return cls.model_validate(data)

    def wordlist_path(self, name: str) -> Path:
        """Resolve a wordlist path relative to the project root."""
        raw = getattr(self.wordlists, name, "")
        p = Path(raw)
        if p.is_absolute():
            return p
        # Try relative to this file's parent's parent (project root)
        root = Path(__file__).parent.parent
        return root / p

    def fingerprint_path(self) -> Path:
        return Path(__file__).parent.parent / "fingerprints" / "technologies.json"
