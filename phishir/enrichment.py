"""Pluggable threat-intel enrichment providers.

The offline ``MockProvider`` is the default so the pipeline runs with no network
and no API keys. Real providers activate only when their env var is set AND the
caller opts in with ``--live`` / ``PHISHIR_LIVE=1``.
"""

from __future__ import annotations

import base64
import logging
import os
from abc import ABC, abstractmethod

import httpx

from .models import IOC, Enrichment

log = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(10.0)


class Provider(ABC):
    name: str = "base"
    supports: tuple[str, ...] = ()

    def can_handle(self, ioc: IOC) -> bool:
        return ioc.type in self.supports

    @abstractmethod
    def lookup(self, ioc: IOC) -> Enrichment: ...

    def _unknown(self, ioc: IOC, why: str) -> Enrichment:
        return Enrichment(self.name, ioc.value, ioc.type, "unknown", 0, {"note": why})


class MockProvider(Provider):
    """Deterministic offline intel. Matches fictional indicators used in samples/."""

    name = "mock"
    supports = ("url", "domain", "ip", "sha256", "md5", "email")

    BAD_TOKENS = ("login-verify", "secure-update", "account-suspend", "payr0ll", "micros0ft",
                  "invoice-portal", "reset-mfa")
    SUSPICIOUS_TOKENS = ("bit-ly.test", "redirect", ".zip", "wp-admin", "track")
    BAD_IPS = {"203.0.113.66", "198.51.100.23"}  # RFC 5737 documentation ranges
    BAD_HASHES = {
        # sha256 of the fictional sample attachment bytes in samples/
        "ede9708516dc2ca47e732688a905c69500d987fb51b9d2e20429d4c7fe12d9bf",
    }

    def lookup(self, ioc: IOC) -> Enrichment:
        v = ioc.value.lower()
        if v in self.BAD_HASHES or v in self.BAD_IPS or any(t in v for t in self.BAD_TOKENS):
            return Enrichment(self.name, ioc.value, ioc.type, "malicious", 90,
                              {"source": "mock-intel", "tags": ["phishing"]})
        if any(t in v for t in self.SUSPICIOUS_TOKENS):
            return Enrichment(self.name, ioc.value, ioc.type, "suspicious", 50,
                              {"source": "mock-intel"})
        return Enrichment(self.name, ioc.value, ioc.type, "clean", 0, {"source": "mock-intel"})


class VirusTotalProvider(Provider):
    name = "virustotal"
    supports = ("url", "domain", "ip", "sha256", "md5")
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, client: httpx.Client | None = None):
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=TIMEOUT)

    def _path(self, ioc: IOC) -> str:
        if ioc.type == "url":
            uid = base64.urlsafe_b64encode(ioc.value.encode()).decode().strip("=")
            return f"/urls/{uid}"
        if ioc.type == "domain":
            return f"/domains/{ioc.value}"
        if ioc.type == "ip":
            return f"/ip_addresses/{ioc.value}"
        return f"/files/{ioc.value}"

    def lookup(self, ioc: IOC) -> Enrichment:
        try:
            r = self.client.get(self.BASE + self._path(ioc), headers={"x-apikey": self.api_key})
            if r.status_code == 404:
                return self._unknown(ioc, "not found")
            r.raise_for_status()
            stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            log.warning("virustotal lookup failed: %s", exc)
            return self._unknown(ioc, "lookup error")
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        verdict = "malicious" if mal >= 3 else "suspicious" if (mal or sus) else "clean"
        return Enrichment(self.name, ioc.value, ioc.type, verdict, min(100, mal * 10 + sus * 5), stats)


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    supports = ("ip",)
    URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, client: httpx.Client | None = None):
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=TIMEOUT)

    def lookup(self, ioc: IOC) -> Enrichment:
        try:
            r = self.client.get(self.URL, params={"ipAddress": ioc.value, "maxAgeInDays": 90},
                                headers={"Key": self.api_key, "Accept": "application/json"})
            r.raise_for_status()
            data = r.json()["data"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            log.warning("abuseipdb lookup failed: %s", exc)
            return self._unknown(ioc, "lookup error")
        conf = int(data.get("abuseConfidenceScore", 0))
        verdict = "malicious" if conf >= 75 else "suspicious" if conf >= 25 else "clean"
        return Enrichment(self.name, ioc.value, ioc.type, verdict, conf,
                          {"country": data.get("countryCode"), "reports": data.get("totalReports")})


class URLhausProvider(Provider):
    name = "urlhaus"
    supports = ("url", "domain", "sha256", "md5")
    BASE = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, api_key: str, client: httpx.Client | None = None):
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=TIMEOUT)

    def lookup(self, ioc: IOC) -> Enrichment:
        if ioc.type == "url":
            ep, form = "/url/", {"url": ioc.value}
        elif ioc.type == "domain":
            ep, form = "/host/", {"host": ioc.value}
        else:
            ep, form = "/payload/", {f"{ioc.type}_hash": ioc.value}
        try:
            r = self.client.post(self.BASE + ep, data=form, headers={"Auth-Key": self.api_key})
            r.raise_for_status()
            data = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("urlhaus lookup failed: %s", exc)
            return self._unknown(ioc, "lookup error")
        if data.get("query_status") == "ok":
            return Enrichment(self.name, ioc.value, ioc.type, "malicious", 85,
                              {"threat": data.get("threat"), "status": data.get("url_status")})
        return Enrichment(self.name, ioc.value, ioc.type, "clean", 0,
                          {"query_status": data.get("query_status")})


def build_providers(live: bool | None = None) -> list[Provider]:
    """Return configured providers. Offline mock unless live mode + keys present."""
    if live is None:
        live = os.getenv("PHISHIR_LIVE", "0") == "1"
    if not live:
        return [MockProvider()]
    providers: list[Provider] = []
    if key := os.getenv("VT_API_KEY"):
        providers.append(VirusTotalProvider(key))
    if key := os.getenv("ABUSEIPDB_API_KEY"):
        providers.append(AbuseIPDBProvider(key))
    if key := os.getenv("URLHAUS_API_KEY"):
        providers.append(URLhausProvider(key))
    if not providers:
        log.warning("live mode requested but no API keys set; falling back to mock")
        providers.append(MockProvider())
    return providers


def enrich(iocs: list[IOC], providers: list[Provider]) -> list[Enrichment]:
    results = []
    for ioc in iocs:
        for p in providers:
            if p.can_handle(ioc):
                results.append(p.lookup(ioc))
    return results
