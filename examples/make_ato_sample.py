"""Generate samples/ato_events.jsonl: a synthetic credential-stuffing and account-takeover incident."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

T0 = datetime(2026, 10, 1, 3, 0, tzinfo=timezone.utc)
DALLAS = {"country": "US", "lat": 32.78, "lon": -96.80}
ATTACKER = {"ip": "203.0.113.7", "country": "NL", "lat": 52.37, "lon": 4.90,
            "user_agent": "python-requests/2.31"}
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def ev(ts, account, event, **kw):
    return {"ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "account": account, "event": event, **kw}


def build():
    out = []
    # Normal history: each customer logs in from home on their own device.
    for i in range(1, 11):
        a = f"cust-{i:04d}"
        for d in (3, 2, 1):
            out.append(ev(T0 - timedelta(days=d, hours=i), a, "login", result="success",
                          ip=f"192.0.2.{i}", device_id=f"d-{i}", user_agent=BROWSER, **DALLAS))
    # Credential stuffing: 8 accounts from one IP in 8 minutes.
    for i in range(1, 9):
        out.append(ev(T0 + timedelta(minutes=i), f"cust-{i:04d}", "login", result="failure", **ATTACKER))
    # Two succeed.
    out.append(ev(T0 + timedelta(minutes=12), "cust-0003", "login", result="success", device_id="d-att", **ATTACKER))
    out.append(ev(T0 + timedelta(minutes=14), "cust-0005", "login", result="success", device_id="d-att", **ATTACKER))
    # cust-0003: attacker changes email and payout account.
    out.append(ev(T0 + timedelta(minutes=16), "cust-0003", "email_change", **ATTACKER))
    out.append(ev(T0 + timedelta(minutes=18), "cust-0003", "payout_change", **ATTACKER))
    # cust-0005: attacker scrapes data through the API.
    for s in range(60):
        out.append(ev(T0 + timedelta(minutes=15, seconds=5 * s), "cust-0005", "api_call",
                      path="/v1/vehicles/inventory", **ATTACKER))
    # Same attacker device later used against cust-0009 from a different IP.
    out.append(ev(T0 + timedelta(hours=5), "cust-0009", "login", result="success", ip="198.51.100.99",
                  device_id="d-att", user_agent=BROWSER, country="DE", lat=50.11, lon=8.68))
    # Legit customer traveling (new device, plausible speed, no changes): should not be called compromised.
    out.append(ev(T0 + timedelta(days=1), "cust-0010", "login", result="success", ip="192.0.2.210",
                  device_id="d-10-phone", user_agent=BROWSER, country="US", lat=29.76, lon=-95.37))
    return sorted(out, key=lambda e: e["ts"])


if __name__ == "__main__":
    p = Path(__file__).resolve().parent.parent / "samples" / "ato_events.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in build()) + "\n")
    print(f"wrote {p}")
