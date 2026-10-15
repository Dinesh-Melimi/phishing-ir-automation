"""Threat-intelligence layer: combine enrichments into a confidence-scored verdict per IOC and
export a STIX 2.1 bundle for sharing with a TIP or TAXII server.

CTI work weighs sources rather than trusting any single one: a malicious verdict from a
Luhn-validated, multi-source match outranks one low-confidence hit. Each IOC gets an admiralty-style
confidence (High/Medium/Low) from source agreement and a normalized score, plus the MITRE ATT&CK
context already attached to the case.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

VERDICT_RANK = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}
# STIX indicator pattern by IOC type.
STIX_PATTERN = {
    "ip": "[ipv4-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
    "email": "[email-addr:value = '{v}']",
}


def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def correlate(ioc_value, enrichments):
    """Combine all provider enrichments for one IOC into a single assessed verdict + confidence."""
    hits = [e for e in enrichments if e.ioc == ioc_value and e.verdict != "unknown"]
    if not hits:
        return {"verdict": "unknown", "confidence": "Low", "score": 0, "sources": [], "rationale": "no data"}
    verdict = max((e.verdict for e in hits), key=lambda v: VERDICT_RANK[v])
    agree = [e for e in hits if e.verdict == verdict]
    score = round(sum(e.score for e in agree) / len(agree))
    malicious_sources = [e.provider for e in hits if e.verdict in ("malicious", "suspicious")]
    if len(malicious_sources) >= 2 and verdict == "malicious":
        confidence = "High"
    elif malicious_sources and (verdict in ("malicious", "suspicious")):
        confidence = "Medium"
    else:
        confidence = "Low"
    return {"verdict": verdict, "confidence": confidence, "score": score,
            "sources": sorted({e.provider for e in hits}),
            "rationale": f"{verdict} per {', '.join(sorted(set(malicious_sources))) or 'sources'}"}


def assess(case) -> list[dict]:
    """Per-IOC intel assessment for a case (case.iocs + case.enrichments)."""
    out = []
    for ioc in case.iocs:
        a = correlate(ioc.value, case.enrichments)
        out.append({"ioc": ioc.value, "defanged": ioc.defanged, "type": ioc.type, **a})
    # highest-threat IOCs first
    return sorted(out, key=lambda x: (-VERDICT_RANK[x["verdict"]], -x["score"]))


def _id(prefix, seed):
    return f"{prefix}--{hashlib.sha1(seed.encode()).hexdigest()[:8]}-0000-4000-8000-{hashlib.sha1(seed.encode()).hexdigest()[8:20]}"  # noqa: E501,S324


def stix_bundle(case, assessments=None, min_verdict="suspicious"):
    """STIX 2.1 bundle of indicators for malicious/suspicious IOCs, plus attack-pattern refs."""
    assessments = assessments or assess(case)
    now = _ts()
    objects, indicator_ids = [], []
    for a in assessments:
        if VERDICT_RANK[a["verdict"]] < VERDICT_RANK[min_verdict]:
            continue
        pattern = STIX_PATTERN.get(a["type"])
        if not pattern:
            continue
        ind_id = _id("indicator", a["ioc"] + a["type"])
        indicator_ids.append(ind_id)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "created": now, "modified": now,
            "name": f"{a['type']} {a['defanged']}",
            "description": f"{a['verdict']} ({a['confidence']} confidence) - {a['rationale']}",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern.format(v=a["ioc"]), "pattern_type": "stix",
            "valid_from": now,
            "confidence": {"High": 85, "Medium": 50, "Low": 15}[a["confidence"]],
            "labels": sorted(a["sources"]),
        })
    for tech in getattr(case, "mitre", []) or []:
        tid = tech if isinstance(tech, str) else tech.get("technique_id", "")
        if not re.match(r"T\d{4}", tid):
            continue
        ap_id = _id("attack-pattern", tid)
        objects.append({
            "type": "attack-pattern", "spec_version": "2.1", "id": ap_id, "created": now, "modified": now,
            "name": tid,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
        })
        for ind_id in indicator_ids:
            objects.append({
                "type": "relationship", "spec_version": "2.1", "id": _id("relationship", ind_id + tid),
                "created": now, "modified": now, "relationship_type": "indicates",
                "source_ref": ind_id, "target_ref": ap_id,
            })
    return {"type": "bundle", "id": _id("bundle", case.case_id), "objects": objects}


def to_json(bundle) -> str:
    return json.dumps(bundle, indent=2)
