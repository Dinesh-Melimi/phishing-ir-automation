# Incident PHISH-20261006-AF202644: Suspected Phishing

| Field | Value |
|---|---|
| Severity | **CRITICAL** (100/100) |
| Created | 2026-10-06T21:01:36+00:00 |
| Subject | URGENT: Your mailbox will be suspended |
| From | Microsoft 365 Security &lt;no-reply[@]m365-alerts.test&gt; |
| Reply-To | helpdesk[@]collector.example.net |
| Auth | SPF=softfail DKIM=none DMARC=fail |
| Message-ID | `<m365-alert-7781@example.com>` |

## Why this score

- **+15** `spf_fail` - SPF=softfail
- **+20** `dmarc_fail` - DMARC policy evaluation failed
- **+15** `reply_to_mismatch` - Reply-To domain (collector.example.net) differs from From domain (m365-alerts.test)
- **+5** `return_path_mismatch` - Return-Path domain (bulk-sender.example.net) differs from From domain (m365-alerts.test)
- **+20** `display_name_spoof` - Display name 'Microsoft 365 Security' claims 'microsoft' but sender domain is m365-alerts.test
- **+10** `urgency_language` - Urgency phrase: 'URGENT'
- **+15** `credential_lure` - Credential lure phrase: 'Verify your account'
- **+10** `link_text_mismatch` - Link text shows https://login.microsoftonline.example.com/ but points elsewhere
- **+30** `intel_malicious` - 3 IOC(s) flagged malicious by ['mock']

## MITRE ATT&CK

- [T1566.002](https://attack.mitre.org/techniques/T1566/002/) Phishing: Spearphishing Link (Initial Access) - Email body contains link(s) to external resources
- [T1204.001](https://attack.mitre.org/techniques/T1204/001/) User Execution: Malicious Link (Execution) - Lure relies on the user clicking a link
- [T1598.003](https://attack.mitre.org/techniques/T1598/003/) Phishing for Information: Spearphishing Link (Reconnaissance) - Content solicits credentials / account verification
- [T1656](https://attack.mitre.org/techniques/T1656/) Impersonation (Defense Evasion) - Sender identity is spoofed or impersonated

## Indicators (defanged)

| Type | Indicator | Source | Verdicts |
|---|---|---|---|
| url | `hxxps[://]login-verify[.]m365-alerts[.]test/auth?u=alex` | body | mock:malicious |
| domain | `login-verify[.]m365-alerts[.]test` | body | mock:malicious |
| url | `hxxps[://]login[.]microsoftonline[.]example[.]com/` | body | mock:clean |
| domain | `login[.]microsoftonline[.]example[.]com` | body | mock:clean |
| ip | `203[.]0[.]113[.]66` | header | mock:malicious |
| email | `no-reply[@]m365-alerts[.]test` | header | mock:clean |
| email | `helpdesk[@]collector[.]example[.]net` | header | mock:clean |
| domain | `m365-alerts[.]test` | header | mock:clean |
| domain | `collector[.]example[.]net` | header | mock:clean |

## Received path (origin -> recipient)

1. unknown [203.0.113.66] -> relay.example.com
2. ? [-] -> mx.example.com

## Recommended actions

- [ ] Purge message from all mailboxes (e.g. search-and-purge)
- [ ] Block sender domain, URLs and hashes at email gateway, proxy and EDR
- [ ] Identify recipients who clicked; force password reset and revoke sessions
- [ ] Escalate to IR lead and open a major-incident bridge
