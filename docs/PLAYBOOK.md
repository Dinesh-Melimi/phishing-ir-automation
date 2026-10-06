# Phishing Incident Response Playbook

This playbook follows the **NIST SP 800-61** incident handling lifecycle (Rev. 2 phases; Rev. 3 maps the same work onto CSF 2.0 functions, shown in brackets). `phishir` automates the steps marked **[auto]**.

| Field | Value |
|---|---|
| Scope | User-reported or gateway-flagged suspicious email |
| Owner | SOC Tier 1 (triage), Tier 2 / IR lead (critical) |
| Inputs | Original message as `.eml` (with full headers) |
| Outputs | Case JSON, incident ticket, containment actions, lessons learned |

---

## 1. Preparation  [Govern / Identify / Protect]

- Users get a **Report Phish** button that forwards the message as an attachment, which keeps the headers intact.
- Intel API keys (VirusTotal, AbuseIPDB, URLhaus) are stored in a secrets manager and injected as environment variables. They never go in git.
- The SOC has pre-approved permissions to: search-and-purge mail, block at the email gateway / web proxy / DNS, reset passwords, and revoke sessions.
- The webhook goes to a SOC channel or SOAR queue. The escalation contacts list is current.
- Severity thresholds and the scoring weights (`phishir/scoring.py`) are reviewed every quarter.

## 2. Detection and Analysis  [Detect]

| Step | Action | Tool |
|---|---|---|
| 2.1 | Get the original `.eml`. Never analyze a forwarded copy that has lost its headers. | Mail admin |
| 2.2 | Parse authentication: SPF / DKIM / DMARC | **[auto]** parser |
| 2.3 | Rebuild the Received path and identify the originating IP | **[auto]** parser |
| 2.4 | Check Reply-To / Return-Path mismatch and display-name spoofing | **[auto]** parser |
| 2.5 | Extract and defang IOCs (URLs, domains, IPs, attachment hashes) | **[auto]** iocs |
| 2.6 | Enrich IOCs with threat intel | **[auto]** enrichment |
| 2.7 | Score and assign severity, and record the reasons | **[auto]** scoring |
| 2.8 | Map to ATT&CK (T1566.x, T1598.003, T1204.x, T1656) | **[auto]** mitre |
| 2.9 | **Analyst validation.** Read the ticket's "Why this score" section and confirm or override the severity. | Human |
| 2.10 | **Scope.** Search the mail logs for the same sender, subject, URL or hash across all mailboxes, and check proxy, DNS and EDR logs for clicks or execution. | SIEM / EDR |

**Never** open links or attachments on an analyst workstation. Use a sandbox. Share only defanged IOCs in tickets and chat.

### Severity and SLA

| Severity | Score | Meaning | Response SLA |
|---|---|---|---|
| Critical | 70 or more | Confirmed malicious, credential harvest or payload | 15 min |
| High | 45 to 69 | Strong phishing or BEC indicators | 1 h |
| Medium | 20 to 44 | Suspicious, needs analyst review | 4 h |
| Low | under 20 | Likely benign or spam | 1 business day |

Escalate one level if **any user clicked or entered credentials**, if the target is a VIP or finance user, or if more than 10 recipients got the message.

## 3. Containment, Eradication and Recovery  [Respond / Recover]

### Containment
1. Quarantine or **purge** the message from every mailbox it reached.
2. **Block** the sender domain, URLs and IPs at the email gateway, web proxy and DNS. Block the hashes at the EDR.
3. For users who clicked: **reset the password, revoke sessions and tokens, re-register MFA**, and check mailbox rules for auto-forwarding.
4. For BEC: contact finance and **freeze or recall** any payment change. Verify out-of-band using a known phone number.

### Eradication
- Isolate the host and run a full EDR scan if an attachment was opened. Reimage it if a payload ran.
- Remove malicious inbox rules, OAuth app grants and persistence.

### Recovery
- Restore access once the account is clean and MFA is confirmed.
- Monitor the affected accounts for 14 days (impossible travel, new inbox rules, MFA changes).

## 4. Post-Incident Activity  [Identify / Improve]

- Close the ticket with root cause, timeline, and the IOCs that were blocked.
- Lessons learned within 5 business days for high and critical cases.
- Feed new IOCs into the blocklists and threat-intel platform. Add a sample (sanitized) to `samples/` with a regression test.
- Tune `WEIGHTS` if there was a false positive or false negative, and record the change in the PR.
- Give the reporter feedback, and give targeted awareness training if credentials were entered.
- Retain evidence (`.eml`, case JSON, ticket) according to the records retention policy.

## Metrics

- Mean time to triage (report received to severity assigned)
- Mean time to contain (severity assigned to message purged and IOCs blocked)
- Click rate and credential-submission rate per campaign
- False-positive rate of automated severity versus the analyst's final decision
