import json
from datetime import timedelta
from pathlib import Path

from phishir.ato import Config, investigate, load_events, render_report
from phishir.cli import main

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "ato_events.jsonl"


def _inv():
    return investigate(load_events(SAMPLE))


def test_finds_compromised_accounts_and_pivots():
    d = _inv().to_dict()
    assert d["compromised"] == ["cust-0003", "cust-0005", "cust-0009"]  # 0009 via reused attacker device
    assert set(d["targeted_only"]) == {"cust-0001", "cust-0002", "cust-0004", "cust-0006", "cust-0007",
                                       "cust-0008"}
    assert d["indicators"]["ip"] == ["203.0.113.7"]
    assert d["indicators"]["device_id"] == ["d-att"]


def test_signals_mapped_to_mitre():
    kinds = {s["kind"]: s["mitre"] for s in _inv().to_dict()["signals"]}
    assert kinds["credential_stuffing"].startswith("T1110.004")
    assert kinds["sensitive_change_after_login"].startswith("T1098")
    assert kinds["api_burst"].startswith("T1119")


def test_legit_new_device_is_not_compromised():
    d = _inv().to_dict()
    assert "cust-0010" not in d["compromised"] and "cust-0010" not in d["targeted_only"]


def test_browser_user_agent_is_not_a_pivot():
    assert all(not ua.lower().startswith("mozilla") for ua in _inv().to_dict()["indicators"]["user_agent"])


def test_timeline_marks_attacker_events():
    tl = _inv().to_dict()["timelines"]["cust-0003"]
    attacker = [e["event"] for e in tl if e["attacker"]]
    assert attacker[-2:] == ["email_change", "payout_change"]
    assert not tl[0]["attacker"]  # the customer's own earlier login


def test_impossible_travel(tmp_path):
    rows = [
        {"ts": "2026-10-01T00:00:00Z", "account": "a", "event": "login", "result": "success", "ip": "1.1.1.1",
         "lat": 32.78, "lon": -96.80, "country": "US", "device_id": "d1"},
        {"ts": "2026-10-01T00:30:00Z", "account": "a", "event": "login", "result": "success", "ip": "2.2.2.2",
         "lat": 51.5, "lon": -0.12, "country": "GB", "device_id": "d1"},
        {"ts": "2026-10-01T00:40:00Z", "account": "a", "event": "mfa_change", "ip": "2.2.2.2"},
    ]
    p = tmp_path / "e.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows))
    inv = investigate(load_events(p))
    assert "impossible_travel" in {s.kind for s in inv.signals}
    assert inv.compromised == {"a"}


def test_thresholds_are_configurable():
    strict = Config(stuffing_accounts=20, stuffing_window=timedelta(minutes=5))
    assert "credential_stuffing" not in {s.kind for s in investigate(load_events(SAMPLE), strict).signals}


def test_report_and_cli(tmp_path, capsys):
    md = render_report(_inv())
    assert "**3 compromised accounts**" in md and "## Recommended actions" in md
    assert main(["ato", str(SAMPLE), "-o", str(tmp_path)]) == 0
    assert (tmp_path / "ato_report.md").exists() and (tmp_path / "ato_findings.json").exists()
    assert "3 compromised" in capsys.readouterr().out
