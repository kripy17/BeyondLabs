# Security Policy

BeyondLabs is a local cybersecurity and SOC investigation toolkit for defensive analysis, lab practice, evidence handling, and report writing.

## Authorized Use

Use BeyondLabs only on systems, networks, files, indicators, and lab targets that you own or are explicitly authorized to assess. Active scanning, offensive lab workflows, enrichment, and file analysis should be performed only in approved environments.

## Sensitive Data

Do not commit secrets, API keys, provider tokens, real investigation data, malware samples, scan outputs, private IOCs, customer/client data, or other sensitive artifacts. Keep local `.env` files and provider credentials outside version control.

## Reporting Vulnerabilities

No private security email is configured yet. Until a private disclosure channel is available:

1. Open a public GitHub Issue only to request a private security contact.
2. Do not include exploit details, secrets, payloads, private indicators, customer/client data, or other sensitive material in that public issue.
3. A maintainer will move the discussion to a private channel or GitHub Security Advisory when available.

When this repository becomes public, GitHub private vulnerability reporting should be enabled.

Useful vulnerability reports should include:

- Affected component
- Impact
- Reproduction steps
- Environment
- Suggested fix, if known

## Safety Expectations

Security outputs should be honest and evidence-aware. Do not add fake threat intelligence, mocked successful security results, unsafe scan defaults, or workflows that automatically send private indicators to third-party providers without explicit user action.
