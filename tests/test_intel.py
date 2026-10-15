from phishir.intel import assess, correlate, stix_bundle
from phishir.models import IOC, Case, Enrichment, ParsedEmail


def _case():
    email = ParsedEmail(from_addr="a@evil.test", subject="x", headers={}, body_text="", body_html="",
                        auth=None, attachments=[]) if False else None
    iocs = [IOC("ip", "203.0.113.9", "203.0.113[.]9", "body"),
            IOC("domain", "evil.test", "evil[.]test", "body"),
            IOC("sha256", "a" * 64, "a" * 64, "attachment")]
    enr = [
        Enrichment("VirusTotal", "203.0.113.9", "ip", "malicious", 90, {}),
        Enrichment("AbuseIPDB", "203.0.113.9", "ip", "malicious", 80, {}),
        Enrichment("VirusTotal", "evil.test", "domain", "suspicious", 40, {}),
        Enrichment("URLhaus", "evil.test", "domain", "unknown", 0, {}),
        Enrichment("VirusTotal", "a" * 64, "sha256", "clean", 0, {}),
    ]
    return Case("CASE-1", "2026-10-15T00:00:00Z", email, iocs, enr, 80, "high", [],
                [{"technique_id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access"}],
                [])


def test_correlation_confidence():
    c = _case()
    ip = correlate("203.0.113.9", c.enrichments)
    assert ip["verdict"] == "malicious" and ip["confidence"] == "High" and ip["score"] == 85
    dom = correlate("evil.test", c.enrichments)
    assert dom["verdict"] == "suspicious" and dom["confidence"] == "Medium"
    assert correlate("1.2.3.4", c.enrichments)["verdict"] == "unknown"


def test_assess_orders_by_threat():
    a = assess(_case())
    assert a[0]["ioc"] == "203.0.113.9"           # malicious, highest score, first
    assert a[-1]["verdict"] in ("clean", "unknown")


def test_stix_bundle_valid():
    b = stix_bundle(_case())
    types = [o["type"] for o in b["objects"]]
    assert b["type"] == "bundle"
    inds = [o for o in b["objects"] if o["type"] == "indicator"]
    # only malicious/suspicious IOCs become indicators (ip + domain), not the clean hash
    assert {i["name"].split()[0] for i in inds} == {"ip", "domain"}
    ip_ind = next(i for i in inds if i["name"].startswith("ip"))
    assert ip_ind["pattern"] == "[ipv4-addr:value = '203.0.113.9']" and ip_ind["confidence"] == 85
    assert "attack-pattern" in types and "relationship" in types


def test_stix_min_verdict_filters():
    b = stix_bundle(_case(), min_verdict="malicious")
    inds = [o for o in b["objects"] if o["type"] == "indicator"]
    assert {i["name"].split()[0] for i in inds} == {"ip"}   # suspicious domain excluded
