import json

import pytest

from phishir.cli import main
from phishir.pipeline import analyze_file
from phishir.servicenow import create_incident, to_incident


def test_incident_fields_from_phish(sample):
    case = analyze_file(sample("02_phish_credential_harvest.eml"))
    inc = to_incident(case)
    assert inc["subcategory"] == "Phishing" and inc["correlation_id"] == case.case_id
    assert inc["impact"] in ("1", "2")                      # phish should not land as low impact
    assert "T1566" in inc["description"]                    # ATT&CK mapping carried into the ticket
    assert "[@]" in inc["description"] or "[.]" in inc["work_notes"]   # indicators stay defanged


def test_benign_is_low_priority(sample):
    inc = to_incident(analyze_file(sample("01_benign_newsletter.eml")))
    assert (inc["impact"], inc["urgency"]) == ("3", "3")


def test_create_requires_credentials(sample, monkeypatch):
    for k in ("SNOW_INSTANCE", "SNOW_USER", "SNOW_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(RuntimeError):
        create_incident(analyze_file(sample("02_phish_credential_harvest.eml")))


def test_cli_export(sample, tmp_path):
    assert main(["analyze", str(sample("04_phish_payroll_bec.eml")), "-o", str(tmp_path), "--servicenow", "export"]) == 0
    files = list(tmp_path.glob("*.servicenow.json"))
    assert files and json.loads(files[0].read_text())["category"] == "Security"
