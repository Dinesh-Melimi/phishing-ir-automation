from phishir.parser import parse_eml


def test_benign_auth_passes(sample):
    e = parse_eml(sample("01_benign_newsletter.eml"))
    assert (e.auth.spf, e.auth.dkim, e.auth.dmarc) == ("pass", "pass", "pass")
    assert e.header_findings == []


def test_received_hops_ordered_origin_first(sample):
    e = parse_eml(sample("02_phish_credential_harvest.eml"))
    assert e.received_hops[0]["ip"] == "203.0.113.66"
    assert len(e.received_hops) == 2


def test_reply_to_and_display_spoof(sample):
    e = parse_eml(sample("02_phish_credential_harvest.eml"))
    joined = " ".join(e.header_findings)
    assert "Reply-To domain" in joined
    assert "claims 'microsoft'" in joined
    assert e.auth.dmarc == "fail"


def test_display_name_embedded_address(sample):
    e = parse_eml(sample("04_phish_payroll_bec.eml"))
    assert any("embeds a different address" in f for f in e.header_findings)


def test_attachment_hashed(sample):
    e = parse_eml(sample("03_phish_html_attachment.eml"))
    att = e.attachments[0]
    assert att.filename == "INV-20931.html"
    assert len(att.sha256) == 64 and len(att.md5) == 32
