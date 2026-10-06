# Interview Walkthrough

This is a plain-English tour of every part of the project, followed by questions an interviewer is likely to ask and how to answer them.

## The 30-second pitch

> "Phishing is the most common way attackers get in, and SOC analysts repeat the same first steps for every reported email: check the headers, pull out the links, look them up in threat intel, decide how bad it is, and write a ticket. I built a small SOAR-style pipeline in Python that does those steps in under a second. It also explains its score so the analyst can trust or override it, maps the email to MITRE ATT&CK, and follows a NIST 800-61 playbook. It runs offline by default and has a CLI, an authenticated API, Docker, and CI with linting, security scanning and tests."

---

## Component by component

### 1. `parser.py`: reading the email
An `.eml` file is a raw email with all of its headers. I use Python's built-in `email` library, so there's no custom MIME parsing to get wrong.

- **SPF** asks whether the server that sent this mail is allowed to send for that domain.
- **DKIM** asks whether the message carries a valid cryptographic signature from the domain.
- **DMARC** asks whether SPF or DKIM passed *and* lined up with the visible From domain. It's the check that matters most against spoofing.
- These results come from the `Authentication-Results` header that our own mail server adds. I trust our MTA's verdict rather than re-verifying, because the attacker can't forge headers our server adds on receipt.
- **Received hops.** Every mail server adds a `Received` line at the top. Reading them bottom-up gives the path from origin to inbox, and the bottom-most external IP is usually the true sender.
- **Reply-To mismatch.** The mail says it's from `ceo@company` but replies go to `someone@freemail`. That's a classic BEC pattern.
- **Display-name spoofing.** The name says "Microsoft 365 Security" but the domain is `m365-alerts.test`. Or the name *contains* a fake address like `"jordan.lee@example.com" <attacker@freemail>`, because many mail clients show only the name.

### 2. `iocs.py`: indicators of compromise
- Pulls URLs from plain text and from HTML `href` attributes. The href matters because the visible text can lie.
- Pulls domains from URLs, IPs from Received headers and the body, sender addresses, and **SHA-256 and MD5 of each attachment**.
- **Defanging** (`https://bad.test` becomes `hxxps[://]bad[.]test`) means nobody clicks a live malicious link in a ticket or Slack.
- It skips private and loopback IPs because they're noise. It keeps RFC 5737 documentation ranges so the fictional samples behave realistically.

### 3. `enrichment.py`: threat intelligence
- A `Provider` base class with one method, `lookup(ioc)`. **VirusTotal**, **AbuseIPDB** and **URLhaus** each implement it. Adding a new source means writing one class (strategy pattern).
- **Mock provider by default.** The demo, the tests and CI never need keys or network access, and they're deterministic. Real providers only switch on with `--live` *and* a key in the environment.
- Failures such as timeouts, 429s or bad JSON come back as `unknown` instead of crashing. Triage should degrade gracefully.
- The HTTP providers are unit-tested with `httpx.MockTransport`, so no real calls are made.

### 4. `scoring.py`: an explainable severity score
- A table of rules, each worth some points (DMARC fail +20, credential lure +15, malicious intel +30, and so on).
- **Every point is stored with its reason.** The analyst sees *why* a score is 85, not just the number. That transparency is the main reason I chose rules over an ML model: it's auditable, easy to tune, and can't be gamed silently.
- The score is capped at 100 and mapped to low, medium, high or critical. Each band has its own recommended actions.

### 5. `mitre.py`: ATT&CK mapping
| Technique | When it's tagged |
|---|---|
| T1566.001 Spearphishing Attachment | Risky attachment present |
| T1566.002 Spearphishing Link | Email contains links |
| T1566 Phishing (BEC) | Text-only payment-change request |
| T1598.003 Phishing for Information | Asks for credentials |
| T1204.001 / .002 User Execution | Needs the user to click or open |
| T1656 Impersonation | Display-name spoof, Reply-To mismatch, DMARC fail |

If the score is low, no techniques are mapped, so benign mail doesn't get mislabeled.

### 6. `report.py` and `webhook.py`: outputs
- **Case JSON** is machine-readable, for a SIEM, SOAR or data lake.
- The **Markdown ticket** is ready to paste into Jira or ServiceNow. It contains the score reasons, ATT&CK links, a defanged IOC table, the hop path and an action checklist.
- The **webhook** is off by default and needs two settings plus an HTTPS URL. That's a safe default, so a demo can't spam a real channel.

### 7. `pipeline.py`, `cli.py`, `api.py`: orchestration and interfaces
- `pipeline.analyze_bytes()` is the single entry point that both the CLI and the API use.
- The CLI's `--fail-on high` returns exit code 2, so it can gate a scheduled job.
- The FastAPI `/analyze` endpoint takes an `X-API-Key` checked with `hmac.compare_digest` (constant time, which prevents timing attacks). It **fails closed** with a 503 if no key is configured and enforces a 10 MB upload limit.

### 8. Engineering hygiene
- **37 pytest tests** that run fully offline.
- **GitHub Actions**: ruff (lint plus `S` security rules), bandit (SAST), and pytest on Python 3.10, 3.11 and 3.12, plus a CLI smoke test. Workflow permissions are `contents: read` (least privilege).
- **Dockerfile**: slim base, **non-root user**, healthcheck, and no secrets baked in.
- Secrets live only in the environment. `.env` is ignored by git and `.env.example` documents the variables.

---

## Likely interview questions

**Q: Why rules instead of machine learning?**
A: Explainability and trust. A Tier 1 analyst has to justify an escalation, and "+20 DMARC fail, +30 URL flagged by VirusTotal" can be audited. ML could come later as one more *signal* (for example a URL-classifier score as a rule) without losing transparency.

**Q: An email passes SPF, DKIM and DMARC. Is it safe?**
A: No. Sample 04 shows why. A BEC attacker who registers their own lookalike or free-mail domain passes all three, because authentication proves *which domain* sent the mail, not that the domain is trustworthy. That's why I also score display-name tricks, Reply-To mismatch and financial-request language.

**Q: What's the difference between SPF, DKIM and DMARC?**
A: SPF authorizes sending IPs for the envelope domain. DKIM signs the message with the domain's key. DMARC requires one of them to pass *and align* with the header From, and it tells receivers what to do on failure (none, quarantine or reject).

**Q: How do you find the real origin of an email?**
A: Read the Received headers from bottom to top. The first hop added by *your own* trusted infrastructure records the external IP that connected to you. Anything below that line could be forged by the sender.

**Q: Why defang IOCs?**
A: So nobody accidentally clicks or auto-previews a malicious link in a ticket, chat or email. Chat apps also unfurl URLs, which can tip off the attacker or trigger the payload.

**Q: How would you scale this?**
A: Pull from the phishing mailbox with the Microsoft Graph API on a schedule, put each message on a queue, and run the pipeline in workers. Cache intel lookups by IOC with a TTL to respect rate limits (VirusTotal's free tier allows 4 requests per minute). Store cases in a database and push critical cases to SOAR or TheHive for automated purge and block.

**Q: How did you secure the API?**
A: An API key in a header, compared in constant time. It fails closed if unconfigured, enforces an upload size limit, runs as non-root in the container, and takes no secrets from code. In production I'd put it behind TLS and an API gateway with rate limiting, and switch to OAuth2 or mTLS for service-to-service calls.

**Q: What are the limitations?**
A: The organizational-domain check is naive (the fix is the Public Suffix List). It trusts upstream `Authentication-Results`. It doesn't detonate URLs or attachments. It only lightly handles lookalike domains (homoglyphs and typosquats). Those are all on the roadmap.

**Q: How do the outputs map to NIST 800-61?**
A: The pipeline automates *Detection and Analysis*. The ticket's recommended actions drive *Containment, Eradication and Recovery*. The playbook's lessons-learned step feeds back into the scoring weights and regression samples, which is *Post-Incident Activity*.

**Q: How would you handle a false positive?**
A: The analyst overrides the severity in the ticket. The sample is sanitized and added to `samples/` with a test that asserts the correct severity, and the weight is adjusted in a reviewed PR. The CI tests then guard against regressions.

**Q: What would you build next?**
A: Graph API ingestion with automatic purge for critical cases, STIX 2.1 export for intel sharing, lookalike-domain detection with edit distance and homoglyphs, and a sandbox detonation provider.

---

## Live demo script (2 minutes)

1. `make demo`: show the five lines of output.
2. Open the critical ticket and walk through "Why this score", the ATT&CK section and the defanged IOCs.
3. Open sample 04 (BEC). Point out that auth passes, yet the result is still HIGH, and explain why.
4. `make check`: lint, SAST and 37 tests all green.
5. Briefly show `enrichment.py`, where adding a provider is one class.
