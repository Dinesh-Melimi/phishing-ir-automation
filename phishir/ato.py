"""Customer account takeover (ATO) investigation from authentication, API and application logs.

Input is JSON Lines, one event per line:
    {"ts": "2026-10-01T03:12:09Z", "account": "cust-1042", "event": "login", "result": "failure",
     "ip": "203.0.113.7", "country": "US", "lat": 32.7, "lon": -96.8,
     "user_agent": "python-requests/2.31", "device_id": "d-9f2"}
Events: login, api_call, mfa_change, email_change, password_change, payout_change, phone_change.

The investigation:
  1. detects ATO signals (credential stuffing, logins from stuffing sources, impossible travel,
     new device, sensitive account changes after a suspicious login, API bursts),
  2. decides which accounts are compromised,
  3. pivots on the attacker's IPs, devices and user agents to find every other customer they
     touched (compromised vs targeted only),
  4. rebuilds a per-account timeline and writes a report for security, fraud and product teams.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

SENSITIVE = {"mfa_change", "email_change", "password_change", "payout_change", "phone_change"}
MITRE = {
    "credential_stuffing": "T1110.004 Credential Stuffing",
    "login_from_stuffing_source": "T1078 Valid Accounts",
    "impossible_travel": "T1078 Valid Accounts",
    "new_device": "T1078 Valid Accounts",
    "sensitive_change_after_login": "T1098 Account Manipulation",
    "api_burst": "T1119 Automated Collection",
}
GENERIC_UA = ("mozilla/5.0",)  # too common to pivot on alone


@dataclass
class Signal:
    kind: str
    account: str | None
    ts: str
    detail: str
    ip: str | None = None

    @property
    def mitre(self) -> str:
        return MITRE[self.kind]


@dataclass
class Config:
    stuffing_accounts: int = 5          # failures across this many accounts from one IP...
    stuffing_window: timedelta = timedelta(minutes=30)  # ...within this window
    travel_kmh: float = 900.0           # faster than a commercial flight
    change_window: timedelta = timedelta(hours=2)
    api_burst: int = 50                 # API calls within api_window after a suspicious login
    api_window: timedelta = timedelta(minutes=10)


@dataclass
class Investigation:
    signals: list[Signal] = field(default_factory=list)
    compromised: set[str] = field(default_factory=set)
    targeted: set[str] = field(default_factory=set)
    indicators: dict[str, set[str]] = field(default_factory=lambda: {"ip": set(), "device_id": set(),
                                                                     "user_agent": set()})
    timelines: dict[str, list[dict]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "compromised": sorted(self.compromised),
            "targeted_only": sorted(self.targeted - self.compromised),
            "indicators": {k: sorted(v) for k, v in self.indicators.items()},
            "signals": [{"kind": s.kind, "mitre": s.mitre, "account": s.account, "ts": s.ts,
                         "ip": s.ip, "detail": s.detail} for s in self.signals],
            "timelines": self.timelines,
        }


def _t(e: dict) -> datetime:
    return datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))


def load_events(path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        events = [json.loads(line) for line in fh if line.strip()]
    return sorted(events, key=_t)


def _km(a: dict, b: dict) -> float | None:
    if None in (a.get("lat"), a.get("lon"), b.get("lat"), b.get("lon")):
        return None
    p1, p2 = math.radians(a["lat"]), math.radians(b["lat"])
    dp, dl = p2 - p1, math.radians(b["lon"] - a["lon"])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


def stuffing_sources(events: list[dict], cfg: Config) -> dict[str, Signal]:
    fails = defaultdict(list)
    for e in events:
        if e["event"] == "login" and e.get("result") == "failure":
            fails[e["ip"]].append(e)
    out = {}
    for ip, evs in fails.items():
        start = 0
        for end in range(len(evs)):
            while _t(evs[end]) - _t(evs[start]) > cfg.stuffing_window:
                start += 1
            accounts = {x["account"] for x in evs[start:end + 1]}
            if len(accounts) >= cfg.stuffing_accounts:
                out[ip] = Signal("credential_stuffing", None, evs[start]["ts"],
                                 f"{len(accounts)} accounts failed from {ip} within "
                                 f"{int(cfg.stuffing_window.total_seconds() // 60)} min", ip)
                break
    return out


def investigate(events: list[dict], cfg: Config | None = None) -> Investigation:
    cfg = cfg or Config()
    inv = Investigation()
    stuffing = stuffing_sources(events, cfg)
    inv.signals += stuffing.values()

    by_acct = defaultdict(list)
    for e in events:
        by_acct[e["account"]].append(e)

    suspicious_sessions: list[dict] = []
    for acct, evs in by_acct.items():
        seen_devices: set[str] = set()
        last_ok: dict | None = None
        flagged: list[dict] = []
        for e in evs:
            if e["event"] == "login" and e.get("result") == "success":
                reasons = []
                if e["ip"] in stuffing:
                    reasons.append(("login_from_stuffing_source", f"successful login from stuffing IP {e['ip']}"))
                if last_ok:
                    km = _km(last_ok, e)
                    hours = max((_t(e) - _t(last_ok)).total_seconds() / 3600, 1 / 60)
                    if km is not None and km / hours > cfg.travel_kmh:
                        reasons.append(("impossible_travel",
                                        f"{last_ok.get('country')}->{e.get('country')} {km:.0f} km in "
                                        f"{hours * 60:.0f} min"))
                dev = e.get("device_id")
                if dev and seen_devices and dev not in seen_devices:
                    reasons.append(("new_device", f"first login from device {dev}"))
                for kind, detail in reasons:
                    inv.signals.append(Signal(kind, acct, e["ts"], detail, e["ip"]))
                if reasons:
                    flagged.append(e)
                if dev:
                    seen_devices.add(dev)
                last_ok = e
            elif e["event"] in SENSITIVE and any(timedelta(0) <= _t(e) - _t(f) <= cfg.change_window
                                                 for f in flagged):
                inv.signals.append(Signal("sensitive_change_after_login", acct, e["ts"],
                                          f"{e['event']} after suspicious login", e.get("ip")))
                inv.compromised.add(acct)

        for f in flagged:
            calls = [e for e in evs if e["event"] == "api_call" and timedelta(0) <= _t(e) - _t(f) <= cfg.api_window]
            if len(calls) >= cfg.api_burst:
                inv.signals.append(Signal("api_burst", acct, f["ts"],
                                          f"{len(calls)} API calls within {cfg.api_window} of suspicious login",
                                          f["ip"]))
                inv.compromised.add(acct)
            if f["ip"] in stuffing:
                inv.compromised.add(acct)
        if acct in inv.compromised:
            suspicious_sessions += flagged

    # Attacker indicators come only from suspicious sessions on compromised accounts, plus stuffing IPs.
    inv.indicators["ip"] |= set(stuffing)
    for s in suspicious_sessions:
        inv.indicators["ip"].add(s["ip"])
        if s.get("device_id"):
            inv.indicators["device_id"].add(s["device_id"])
        ua = (s.get("user_agent") or "").lower()
        if ua and not ua.startswith(GENERIC_UA):
            inv.indicators["user_agent"].add(s["user_agent"])

    # Pivot: every account that touched an attacker indicator.
    for e in events:
        if (e.get("ip") in inv.indicators["ip"] or e.get("device_id") in inv.indicators["device_id"]
                or e.get("user_agent") in inv.indicators["user_agent"]):
            inv.targeted.add(e["account"])
            if e["event"] == "login" and e.get("result") == "success" and (
                    e["ip"] in stuffing or e.get("device_id") in inv.indicators["device_id"]):
                inv.compromised.add(e["account"])  # attacker got in, even from a new IP

    for acct in sorted(inv.compromised):
        inv.timelines[acct] = [
            {"ts": e["ts"], "event": e["event"], "result": e.get("result", ""), "ip": e.get("ip"),
             "country": e.get("country"), "attacker": e.get("ip") in inv.indicators["ip"]
             or e.get("device_id") in inv.indicators["device_id"]}
            for e in by_acct[acct] if e["event"] != "api_call"
        ]
    return inv


def render_report(inv: Investigation, title: str = "Account Takeover Investigation") -> str:
    d = inv.to_dict()
    counts = defaultdict(int)
    for s in inv.signals:
        counts[s.kind] += 1
    lines = [f"# {title}", "",
             f"**{len(d['compromised'])} compromised accounts**, {len(d['targeted_only'])} more targeted "
             f"(attacker activity, no confirmed takeover).", "",
             "## Signals", "", "| Signal | MITRE ATT&CK | Count |", "|---|---|---|"]
    lines += [f"| {k} | {MITRE[k]} | {v} |" for k, v in sorted(counts.items())]
    lines += ["", "## Affected customers", "", "| Account | Status |", "|---|---|"]
    lines += [f"| {a} | compromised |" for a in d["compromised"]]
    lines += [f"| {a} | targeted |" for a in d["targeted_only"]]
    lines += ["", "## Attacker indicators", ""]
    for k, v in d["indicators"].items():
        if v:
            lines.append(f"- **{k}**: {', '.join(v)}")
    lines += ["", "## Timelines", ""]
    for acct, tl in d["timelines"].items():
        lines += [f"### {acct}", "", "| Time | Event | Result | IP | Country | Attacker |", "|---|---|---|---|---|---|"]
        lines += [f"| {e['ts']} | {e['event']} | {e['result']} | {e['ip']} | {e['country'] or ''} | "
                  f"{'yes' if e['attacker'] else ''} |" for e in tl]
        lines.append("")
    lines += ["## Recommended actions", "",
              "1. Compromised: revoke sessions and tokens, force password reset, re-enroll MFA, "
              "and reverse email, phone or payout changes made by the attacker.",
              "2. Targeted: require step-up authentication on next login and watch for repeat attempts.",
              "3. Block or rate-limit attacker IPs and device IDs at the edge (WAF/bot protection).",
              "4. Notify affected customers per policy; share indicators with the fraud team.",
              "5. Turn these signals into standing detections (SIEM rules) and track ATO rate as a metric."]
    return "\n".join(lines) + "\n"
