"""Render case output: JSON and a Markdown incident ticket."""

from __future__ import annotations

import json

from .models import Case


def to_json(case: Case) -> str:
    return json.dumps(case.to_dict(), indent=2, default=str)


def to_markdown(case: Case) -> str:
    e = case.email
    title = "Suspected Phishing" if case.severity != "low" else "Reported Email - Likely Benign"
    lines = [
        f"# Incident {case.case_id}: {title}",
        "",
        "| Field | Value |", "|---|---|",
        f"| Severity | **{case.severity.upper()}** ({case.score}/100) |",
        f"| Created | {case.created_at} |",
        f"| Subject | {e.subject} |",
        f"| From | {e.from_display} &lt;{e.from_address.replace('@', '[@]')}&gt; |",
        f"| Reply-To | {(e.reply_to or '-').replace('@', '[@]')} |",
        f"| Auth | SPF={e.auth.spf} DKIM={e.auth.dkim} DMARC={e.auth.dmarc} |",
        f"| Message-ID | `{e.message_id}` |",
        "", "## Why this score", "",
    ]
    lines += [f"- **+{r.points}** `{r.rule}` - {r.detail}" for r in case.reasons] or ["- No risk signals fired."]
    lines += ["", "## MITRE ATT&CK", ""]
    lines += [f"- [{t['technique_id']}]({t['url']}) {t['name']} ({t['tactic']}) - {t['evidence']}"
              for t in case.mitre] or ["- None mapped."]
    lines += ["", "## Indicators (defanged)", "", "| Type | Indicator | Source | Verdicts |", "|---|---|---|---|"]
    for i in case.iocs:
        v = ", ".join(f"{x.provider}:{x.verdict}" for x in case.enrichments if x.ioc == i.value) or "-"
        lines.append(f"| {i.type} | `{i.defanged}` | {i.source} | {v} |")
    lines += ["", "## Received path (origin -> recipient)", ""]
    lines += [f"{n}. {h['from'] or '?'} [{h['ip'] or '-'}] -> {h['by'] or '?'}"
              for n, h in enumerate(e.received_hops, 1)] or ["- No Received headers."]
    if e.attachments:
        lines += ["", "## Attachments", ""]
        lines += [f"- `{a.filename}` ({a.content_type}, {a.size} B) sha256 `{a.sha256}`" for a in e.attachments]
    lines += ["", "## Recommended actions", ""]
    lines += [f"- [ ] {a}" for a in case.recommended_actions]
    return "\n".join(lines) + "\n"
