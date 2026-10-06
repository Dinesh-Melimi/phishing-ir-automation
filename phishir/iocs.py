"""IOC extraction and defanging."""

from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import urlparse

from .models import IOC, ParsedEmail

URL_RE = re.compile(r"""\bhttps?://[^\s"'<>()\]]+""", re.I)
HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def defang(value: str) -> str:
    """Make an indicator non-clickable: http -> hxxp, '.' -> '[.]'."""
    v = re.sub(r"^http", "hxxp", value, flags=re.I)
    v = v.replace("://", "[://]") if v.lower().startswith("hxxp") else v
    return v.replace(".", "[.]").replace("@", "[@]")


def refang(value: str) -> str:
    return (value.replace("[.]", ".").replace("[://]", "://").replace("[@]", "@")
            .replace("hxxp", "http"))


def _is_public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    # Keep RFC 5737 documentation ranges so the fictional samples stay realistic.
    return not (ip.is_private and not _is_doc(ip)) and not (
        ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _is_doc(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip in n for n in _DOC_NETS)


def extract_iocs(email: ParsedEmail) -> list[IOC]:
    seen: set[tuple[str, str]] = set()
    out: list[IOC] = []

    def add(t: str, v: str, src: str) -> None:
        v = v.strip().rstrip(".,;")
        if not v or (t, v.lower()) in seen:
            return
        seen.add((t, v.lower()))
        out.append(IOC(type=t, value=v, defanged=defang(v), source=src))

    body = email.body_text + "\n" + html.unescape(email.body_html)
    urls = URL_RE.findall(body) + [h for h in HREF_RE.findall(email.body_html) if h.lower().startswith("http")]
    for u in urls:
        add("url", u, "body")
        host = (urlparse(u).hostname or "").lower()
        if host and not _is_public_ip(host) and not IPV4_RE.fullmatch(host):
            add("domain", host, "body")
        elif _is_public_ip(host):
            add("ip", host, "body")

    for hop in email.received_hops:
        if hop.get("ip") and _is_public_ip(hop["ip"]):
            add("ip", hop["ip"], "header")
    for ip in IPV4_RE.findall(body):
        if _is_public_ip(ip):
            add("ip", ip, "body")

    for addr in filter(None, [email.from_address, email.reply_to]):
        add("email", addr, "header")
    if email.from_domain:
        add("domain", email.from_domain, "header")
    if email.reply_to and "@" in email.reply_to:
        add("domain", email.reply_to.split("@", 1)[1], "header")

    for att in email.attachments:
        add("sha256", att.sha256, "attachment")
        add("md5", att.md5, "attachment")
    return out
