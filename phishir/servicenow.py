"""Turn a phishing case into a ServiceNow incident.

`to_incident()` builds the record body (pure function, easy to test). `create_incident()` posts it to the
ServiceNow Table API only when SNOW_INSTANCE, SNOW_USER and SNOW_PASSWORD are set; credentials come from
the environment and are never written to disk or logs.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.request

from .models import Case

# ServiceNow impact/urgency: 1 = High, 2 = Medium, 3 = Low. Priority is derived from both.
SEVERITY_MAP = {"critical": (1, 1), "high": (1, 2), "medium": (2, 2), "low": (3, 3)}


def to_incident(case: Case, assignment_group: str = "Security Operations") -> dict:
    impact, urgency = SEVERITY_MAP.get(case.severity, (3, 3))
    e = case.email
    techniques = ", ".join(f"{t['technique_id']} {t['name']}" for t in case.mitre) or "none mapped"
    iocs = "\n".join(f"- {i.type}: {i.defanged}" for i in case.iocs) or "- none"
    verdicts = "\n".join(f"- {x.ioc} [{x.provider}] {x.verdict}" for x in case.enrichments
                         if x.verdict not in ("unknown", "clean")) or "- no malicious verdicts"
    actions = "\n".join(f"- {a}" for a in case.recommended_actions)
    return {
        "short_description": f"[{case.severity.upper()}] Reported phishing: {e.subject}"[:160],
        "category": "Security",
        "subcategory": "Phishing",
        "impact": str(impact),
        "urgency": str(urgency),
        "assignment_group": assignment_group,
        "correlation_id": case.case_id,
        "description": (
            f"Case {case.case_id} | score {case.score}/100\n"
            f"From: {e.from_display} <{e.from_address.replace('@', '[@]')}>\n"
            f"Auth: SPF={e.auth.spf} DKIM={e.auth.dkim} DMARC={e.auth.dmarc}\n"
            f"MITRE ATT&CK: {techniques}\n"
        ),
        "work_notes": f"Indicators (defanged):\n{iocs}\n\nThreat intel:\n{verdicts}\n\nRecommended actions:\n{actions}",
    }


def create_incident(case: Case, assignment_group: str = "Security Operations", timeout: int = 15) -> dict:
    inst, user, pwd = (os.environ.get(k) for k in ("SNOW_INSTANCE", "SNOW_USER", "SNOW_PASSWORD"))
    if not (inst and user and pwd):
        raise RuntimeError("Set SNOW_INSTANCE, SNOW_USER and SNOW_PASSWORD to create incidents")
    body = json.dumps(to_incident(case, assignment_group)).encode()
    req = urllib.request.Request(f"https://{inst}.service-now.com/api/now/table/incident", data=body, method="POST")
    token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())["result"]
