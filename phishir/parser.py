"""Parse .eml files and run header-level detections."""

from __future__ import annotations

import hashlib
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path

from .models import Attachment, AuthResults, ParsedEmail

# Brands commonly impersonated in display names. Fictional-safe list.
BRAND_KEYWORDS = (
    "microsoft", "office365", "outlook", "paypal", "apple", "amazon", "google",
    "docusign", "it support", "helpdesk", "payroll", "hr department", "bank",
)

_AUTH_RE = {
    "spf": re.compile(r"\bspf=(\w+)", re.I),
    "dkim": re.compile(r"\bdkim=(\w+)", re.I),
    "dmarc": re.compile(r"\bdmarc=(\w+)", re.I),
}
_FROM_RE = re.compile(r"\bfrom\s+(\S+)", re.I)
_BY_RE = re.compile(r"\bby\s+(\S+)", re.I)
_IP_IN_BRACKETS = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def _org_domain(domain: str) -> str:
    """Naive organizational domain (last two labels). Good enough for a demo."""
    parts = domain.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def parse_auth_results(msg: EmailMessage) -> AuthResults:
    raw = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or []))
    res = AuthResults()
    for key, rx in _AUTH_RE.items():
        m = rx.search(raw)
        if m:
            setattr(res, key, m.group(1).lower())
    if res.spf == "none":
        spf_hdr = str(msg.get("Received-SPF", ""))
        if spf_hdr:
            res.spf = spf_hdr.split()[0].lower()
    return res


def parse_received(msg: EmailMessage) -> list[dict[str, str]]:
    hops = []
    # Received headers are prepended, so reverse to get origin -> destination.
    for raw in reversed(msg.get_all("Received") or []):
        text = " ".join(str(raw).split())
        frm, by = _FROM_RE.search(text), _BY_RE.search(text)
        ip = _IP_IN_BRACKETS.search(text)
        hops.append({
            "from": frm.group(1) if frm else "",
            "by": by.group(1).rstrip(";") if by else "",
            "ip": ip.group(1) if ip else "",
            "raw": text[:300],
        })
    return hops


def _attachments(msg: EmailMessage) -> list[Attachment]:
    out = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        out.append(Attachment(
            filename=part.get_filename() or "unnamed",
            content_type=part.get_content_type(),
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            md5=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        ))
    return out


def _bodies(msg: EmailMessage) -> tuple[str, str]:
    text, html = "", ""
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, KeyError):
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if ctype == "text/plain":
            text += str(content)
        elif ctype == "text/html":
            html += str(content)
    return text, html


def header_findings(p: ParsedEmail) -> list[str]:
    findings: list[str] = []
    for mech in ("spf", "dkim", "dmarc"):
        val = getattr(p.auth, mech)
        if val in ("fail", "softfail", "permerror"):
            findings.append(f"{mech.upper()} result is '{val}'")
    if p.reply_to and _org_domain(_domain(p.reply_to)) != _org_domain(p.from_domain):
        findings.append(f"Reply-To domain ({_domain(p.reply_to)}) differs from From domain ({p.from_domain})")
    if p.return_path and _domain(p.return_path) and \
            _org_domain(_domain(p.return_path)) != _org_domain(p.from_domain):
        findings.append(f"Return-Path domain ({_domain(p.return_path)}) differs from From domain ({p.from_domain})")
    disp = p.from_display.lower()
    # Display name contains an email address that is not the real sender.
    embedded = re.findall(r"[\w.+-]+@[\w.-]+", disp)
    if any(e != p.from_address.lower() for e in embedded):
        findings.append(f"Display name embeds a different address: '{p.from_display}'")
    for brand in BRAND_KEYWORDS:
        if brand in disp and brand.replace(" ", "") not in p.from_domain.replace("-", ""):
            findings.append(f"Display name '{p.from_display}' claims '{brand}' but sender domain is {p.from_domain}")
            break
    return findings


def parse_eml_bytes(data: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(data)  # type: ignore[assignment]
    display, addr = parseaddr(str(msg.get("From", "")))
    reply_to = parseaddr(str(msg.get("Reply-To", "")))[1] or None
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1] or None
    text, html = _bodies(msg)
    parsed = ParsedEmail(
        message_id=str(msg.get("Message-ID", "")).strip(),
        subject=str(msg.get("Subject", "")),
        from_address=addr.lower(),
        from_display=display,
        from_domain=_domain(addr),
        reply_to=reply_to.lower() if reply_to else None,
        return_path=return_path.lower() if return_path else None,
        to=[a for _, a in getaddresses([str(v) for v in msg.get_all("To") or []])],
        date=str(msg.get("Date")) if msg.get("Date") else None,
        auth=parse_auth_results(msg),
        received_hops=parse_received(msg),
        body_text=text,
        body_html=html,
        attachments=_attachments(msg),
    )
    parsed.header_findings = header_findings(parsed)
    return parsed


def parse_eml(path: str | Path) -> ParsedEmail:
    return parse_eml_bytes(Path(path).read_bytes())
