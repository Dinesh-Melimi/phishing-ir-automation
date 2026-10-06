from phishir.iocs import defang, extract_iocs, refang
from phishir.parser import parse_eml


def test_defang_roundtrip():
    url = "https://evil.example.test/a.b"
    d = defang(url)
    assert d == "hxxps[://]evil[.]example[.]test/a[.]b"
    assert refang(d) == url


def test_extracts_url_domain_ip(sample):
    iocs = extract_iocs(parse_eml(sample("02_phish_credential_harvest.eml")))
    types = {(i.type, i.value) for i in iocs}
    assert ("domain", "login-verify.m365-alerts.test") in types
    assert ("ip", "203.0.113.66") in types
    assert any(t == "url" and "login-verify" in v for t, v in types)
    assert all(not i.defanged.startswith("http") for i in iocs)


def test_no_duplicates(sample):
    iocs = extract_iocs(parse_eml(sample("02_phish_credential_harvest.eml")))
    keys = [(i.type, i.value.lower()) for i in iocs]
    assert len(keys) == len(set(keys))


def test_private_ips_ignored():
    from phishir.iocs import _is_public_ip
    assert not _is_public_ip("10.0.0.1")
    assert not _is_public_ip("127.0.0.1")
    assert _is_public_ip("203.0.113.5")
