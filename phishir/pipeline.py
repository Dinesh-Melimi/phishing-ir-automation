"""Orchestrates parse -> extract -> enrich -> score -> map -> report."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .enrichment import Provider, build_providers, enrich
from .iocs import extract_iocs
from .mitre import map_attack
from .models import Case
from .parser import parse_eml_bytes
from .report import to_json, to_markdown
from .scoring import score_email

ACTIONS = {
    "critical": [
        "Purge message from all mailboxes (e.g. search-and-purge)",
        "Block sender domain, URLs and hashes at email gateway, proxy and EDR",
        "Identify recipients who clicked; force password reset and revoke sessions",
        "Escalate to IR lead and open a major-incident bridge",
    ],
    "high": [
        "Quarantine message and block indicators at gateway/proxy",
        "Check proxy/EDR logs for clicks or attachment execution",
        "Notify affected users",
    ],
    "medium": [
        "Quarantine message pending analyst review",
        "Add indicators to watchlist",
    ],
    "low": ["Close as benign / spam after analyst confirmation", "Send reporter a thank-you note"],
}


def analyze_bytes(data: bytes, providers: list[Provider] | None = None) -> Case:
    providers = providers if providers is not None else build_providers()
    email = parse_eml_bytes(data)
    iocs = extract_iocs(email)
    enrichments = enrich(iocs, providers)
    score, severity, reasons = score_email(email, iocs, enrichments)
    now = datetime.now(timezone.utc)
    case_id = f"PHISH-{now:%Y%m%d}-{hashlib.sha256(data).hexdigest()[:8].upper()}"
    return Case(
        case_id=case_id,
        created_at=now.isoformat(timespec="seconds"),
        email=email,
        iocs=iocs,
        enrichments=enrichments,
        score=score,
        severity=severity,
        reasons=reasons,
        mitre=map_attack(email, iocs, reasons, score),
        recommended_actions=ACTIONS[severity],
    )


def analyze_file(path: str | Path, providers: list[Provider] | None = None) -> Case:
    return analyze_bytes(Path(path).read_bytes(), providers)


def write_outputs(case: Case, out_dir: str | Path) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    j = out / f"{case.case_id}.json"
    m = out / f"{case.case_id}.md"
    j.write_text(to_json(case), encoding="utf-8")
    m.write_text(to_markdown(case), encoding="utf-8")
    return j, m
