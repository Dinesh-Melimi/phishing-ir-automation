"""Optional webhook notification (Slack/Teams/SOAR). Disabled unless configured."""

from __future__ import annotations

import logging
import os

import httpx

from .models import Case

log = logging.getLogger(__name__)


def build_payload(case: Case) -> dict:
    return {
        "text": f"[{case.severity.upper()}] Phishing case {case.case_id} score={case.score}: {case.email.subject}",
        "case_id": case.case_id,
        "severity": case.severity,
        "score": case.score,
        "mitre": [t["technique_id"] for t in case.mitre],
    }


def post_webhook(case: Case, url: str | None = None, client: httpx.Client | None = None) -> bool:
    url = url or os.getenv("PHISHIR_WEBHOOK_URL")
    if not url or os.getenv("PHISHIR_WEBHOOK_ENABLED", "0") != "1":
        log.info("webhook disabled; skipping")
        return False
    if not url.startswith("https://"):
        log.warning("refusing non-HTTPS webhook URL")
        return False
    client = client or httpx.Client(timeout=10.0)
    try:
        client.post(url, json=build_payload(case)).raise_for_status()
        return True
    except httpx.HTTPError as exc:
        log.error("webhook post failed: %s", exc)
        return False
