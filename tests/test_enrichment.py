import httpx

from phishir.enrichment import (
    AbuseIPDBProvider,
    MockProvider,
    URLhausProvider,
    VirusTotalProvider,
    build_providers,
    enrich,
)
from phishir.models import IOC


def ioc(t, v):
    return IOC(t, v, v, "test")


def test_default_is_offline_mock():
    ps = build_providers()
    assert [p.name for p in ps] == ["mock"]


def test_live_without_keys_falls_back():
    assert [p.name for p in build_providers(live=True)] == ["mock"]


def test_live_with_keys(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "x")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "y")
    assert {p.name for p in build_providers(live=True)} == {"virustotal", "abuseipdb"}


def test_mock_verdicts():
    m = MockProvider()
    assert m.lookup(ioc("url", "https://login-verify.x.test/")).verdict == "malicious"
    assert m.lookup(ioc("domain", "www.example.com")).verdict == "clean"


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_virustotal_parses_stats():
    def h(req):
        assert req.headers["x-apikey"] == "k"
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}})
    r = VirusTotalProvider("k", _client(h)).lookup(ioc("domain", "bad.test"))
    assert r.verdict == "malicious" and r.score == 50


def test_virustotal_error_is_unknown():
    r = VirusTotalProvider("k", _client(lambda req: httpx.Response(500))).lookup(ioc("ip", "203.0.113.1"))
    assert r.verdict == "unknown"


def test_abuseipdb():
    h = lambda req: httpx.Response(200, json={"data": {"abuseConfidenceScore": 80, "countryCode": "ZZ"}})
    assert AbuseIPDBProvider("k", _client(h)).lookup(ioc("ip", "203.0.113.1")).verdict == "malicious"


def test_urlhaus():
    h = lambda req: httpx.Response(200, json={"query_status": "no_results"})
    assert URLhausProvider("k", _client(h)).lookup(ioc("url", "https://a.test/")).verdict == "clean"


def test_enrich_respects_supported_types():
    out = enrich([ioc("email", "a@b.test")], [AbuseIPDBProvider("k", _client(lambda r: httpx.Response(500)))])
    assert out == []
