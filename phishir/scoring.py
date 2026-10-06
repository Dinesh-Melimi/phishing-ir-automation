"""Transparent, rule-based severity scoring.

Every point added is recorded as a ScoreReason so an analyst can see exactly why
an email scored the way it did. Weights live in one table for easy tuning.
"""

from __future__ import annotations

import re

from .models import IOC, Enrichment, ParsedEmail, ScoreReason

WEIGHTS = {
    "spf_fail": 15,
    "dkim_fail": 15,
    "dmarc_fail": 20,
    "reply_to_mismatch": 15,
    "return_path_mismatch": 5,
    "display_name_spoof": 20,
    "urgency_language": 10,
    "credential_lure": 15,
    "risky_attachment": 20,
    "financial_request": 15,
    "intel_malicious": 30,
    "intel_suspicious": 10,
    "url_ip_host": 10,
    "link_text_mismatch": 10,
}
RISKY_EXT = (".html", ".htm", ".js", ".vbs", ".exe", ".scr", ".iso", ".lnk", ".docm",
             ".xlsm", ".zip", ".one", ".hta")
URGENCY = re.compile(r"\b(urgent|immediately|within 24 hours|suspended|final notice|act now|expire[sd]?)\b", re.I)
CRED = re.compile(r"\b(verify your (account|identity)|password|sign[- ]in|login|mfa|credentials)\b", re.I)
FINANCIAL = re.compile(
    r"\b(direct deposit|wire transfer|bank (details|account)|gift cards?|change of (bank|payment))\b", re.I
)
ANCHOR = re.compile(r"""<a[^>]+href=["'](https?://[^"']+)["'][^>]*>\s*(https?://[^<\s]+)\s*</a>""", re.I)

SEVERITY_BANDS = [(70, "critical"), (45, "high"), (20, "medium"), (0, "low")]


def severity_for(score: int) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "low"


def score_email(
    email: ParsedEmail, iocs: list[IOC], enrichments: list[Enrichment]
) -> tuple[int, str, list[ScoreReason]]:
    reasons: list[ScoreReason] = []

    def hit(rule: str, detail: str) -> None:
        reasons.append(ScoreReason(rule, WEIGHTS[rule], detail))

    a = email.auth
    if a.spf in ("fail", "softfail"):
        hit("spf_fail", f"SPF={a.spf}")
    if a.dkim == "fail":
        hit("dkim_fail", "DKIM signature failed")
    if a.dmarc == "fail":
        hit("dmarc_fail", "DMARC policy evaluation failed")
    for f in email.header_findings:
        if f.startswith("Reply-To"):
            hit("reply_to_mismatch", f)
        elif f.startswith("Return-Path"):
            hit("return_path_mismatch", f)
        elif f.startswith("Display name"):
            hit("display_name_spoof", f)
            break  # count spoofing once

    text = f"{email.subject}\n{email.body_text}\n{email.body_html}"
    if m := URGENCY.search(text):
        hit("urgency_language", f"Urgency phrase: '{m.group(0)}'")
    if m := CRED.search(text):
        hit("credential_lure", f"Credential lure phrase: '{m.group(0)}'")
    if m := FINANCIAL.search(text):
        hit("financial_request", f"Payment/BEC request phrase: '{m.group(0)}'")
    for att in email.attachments:
        if att.filename.lower().endswith(RISKY_EXT):
            hit("risky_attachment", f"Attachment '{att.filename}' has a high-risk extension")
            break
    for href, shown in ANCHOR.findall(email.body_html):
        if href.split("/")[2].lower() != shown.split("/")[2].lower():
            hit("link_text_mismatch", f"Link text shows {shown} but points elsewhere")
            break
    if any(i.type == "url" and re.match(r"https?://\d+\.\d+\.\d+\.\d+", i.value) for i in iocs):
        hit("url_ip_host", "URL uses a raw IP address as host")

    mal = [e for e in enrichments if e.verdict == "malicious"]
    sus = [e for e in enrichments if e.verdict == "suspicious"]
    if mal:
        hit("intel_malicious", f"{len(mal)} IOC(s) flagged malicious by {sorted({e.provider for e in mal})}")
    elif sus:
        hit("intel_suspicious", f"{len(sus)} IOC(s) flagged suspicious")

    score = min(100, sum(r.points for r in reasons))
    return score, severity_for(score), reasons
