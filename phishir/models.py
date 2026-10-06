"""Plain dataclasses shared across the pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str


@dataclass
class AuthResults:
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"


@dataclass
class ParsedEmail:
    message_id: str
    subject: str
    from_address: str
    from_display: str
    from_domain: str
    reply_to: str | None
    return_path: str | None
    to: list[str]
    date: str | None
    auth: AuthResults
    received_hops: list[dict[str, str]]
    body_text: str
    body_html: str
    attachments: list[Attachment]
    header_findings: list[str] = field(default_factory=list)


@dataclass
class IOC:
    type: str  # url | domain | ip | sha256 | md5 | email
    value: str
    defanged: str
    source: str  # body | header | attachment


@dataclass
class Enrichment:
    provider: str
    ioc: str
    ioc_type: str
    verdict: str  # malicious | suspicious | clean | unknown
    score: int  # 0-100 provider confidence
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoreReason:
    rule: str
    points: int
    detail: str


@dataclass
class Case:
    case_id: str
    created_at: str
    email: ParsedEmail
    iocs: list[IOC]
    enrichments: list[Enrichment]
    score: int
    severity: str
    reasons: list[ScoreReason]
    mitre: list[dict[str, str]]
    recommended_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
