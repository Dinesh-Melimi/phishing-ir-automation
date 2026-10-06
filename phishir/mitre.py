"""Map observed behaviour to MITRE ATT&CK techniques."""

from __future__ import annotations

from .models import IOC, ParsedEmail, ScoreReason

TECHNIQUES = {
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Phishing: Spearphishing Link", "Initial Access"),
    "T1566.003": ("Phishing: Spearphishing via Service", "Initial Access"),
    "T1598.003": ("Phishing for Information: Spearphishing Link", "Reconnaissance"),
    "T1656": ("Impersonation", "Defense Evasion"),
    "T1204.001": ("User Execution: Malicious Link", "Execution"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
}


def _t(tid: str, why: str) -> dict[str, str]:
    name, tactic = TECHNIQUES[tid]
    return {"technique_id": tid, "name": name, "tactic": tactic, "evidence": why,
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}


def map_attack(email: ParsedEmail, iocs: list[IOC], reasons: list[ScoreReason], score: int) -> list[dict[str, str]]:
    if score < 20:
        return []  # don't label likely-benign mail with attack techniques
    rules = {r.rule for r in reasons}
    out = []
    if email.attachments and "risky_attachment" in rules:
        out += [_t("T1566.001", "High-risk attachment delivered by email"),
                _t("T1204.002", "Attachment requires user to open it")]
    if any(i.type == "url" for i in iocs):
        out.append(_t("T1566.002", "Email body contains link(s) to external resources"))
        out.append(_t("T1204.001", "Lure relies on the user clicking a link"))
    if "credential_lure" in rules:
        out.append(_t("T1598.003", "Content solicits credentials / account verification"))
    if "financial_request" in rules and not any(i.type == "url" for i in iocs) and not email.attachments:
        out.append(_t("T1566", "Text-only lure requesting payment or banking change (BEC)"))
    if rules & {"display_name_spoof", "reply_to_mismatch", "dmarc_fail"}:
        out.append(_t("T1656", "Sender identity is spoofed or impersonated"))
    return out
