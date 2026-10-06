import json

import pytest

from phishir.pipeline import analyze_file, write_outputs
from phishir.scoring import severity_for


@pytest.mark.parametrize("name,expected", [
    ("01_benign_newsletter.eml", "low"),
    ("02_phish_credential_harvest.eml", "critical"),
    ("03_phish_html_attachment.eml", "critical"),
    ("04_phish_payroll_bec.eml", "high"),
    ("05_benign_it_notice.eml", "low"),
])
def test_sample_severity(sample, name, expected):
    assert analyze_file(sample(name)).severity == expected


def test_score_is_explained(sample):
    case = analyze_file(sample("02_phish_credential_harvest.eml"))
    assert case.score == min(100, sum(r.points for r in case.reasons))
    assert {"dmarc_fail", "credential_lure", "link_text_mismatch", "intel_malicious"} <= {r.rule for r in case.reasons}


def test_mitre_mapping(sample):
    ids = {t["technique_id"] for t in analyze_file(sample("03_phish_html_attachment.eml")).mitre}
    assert "T1566.001" in ids
    ids = {t["technique_id"] for t in analyze_file(sample("02_phish_credential_harvest.eml")).mitre}
    assert {"T1566.002", "T1598.003", "T1656"} <= ids
    assert analyze_file(sample("01_benign_newsletter.eml")).mitre == []


def test_outputs_written(sample, tmp_path):
    case = analyze_file(sample("02_phish_credential_harvest.eml"))
    j, m = write_outputs(case, tmp_path)
    data = json.loads(j.read_text())
    assert data["severity"] == "critical"
    md = m.read_text()
    assert "## Why this score" in md and "hxxps[://]" in md
    assert "https://login-verify" not in md  # indicators must be defanged


@pytest.mark.parametrize("score,band", [(0, "low"), (20, "medium"), (45, "high"), (70, "critical")])
def test_bands(score, band):
    assert severity_for(score) == band
