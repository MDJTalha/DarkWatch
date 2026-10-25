# Security Policy

## Scope and limitations

DarkWatch is under active development. The current FastAPI/SQLite branch is a defensive event-ingestion and analyst-triage foundation, not endpoint-protection software. Do not expose it directly to the public internet or send credentials, production logs, personal data, or other sensitive operational data to this repository.

## Reporting a suspected vulnerability

Please do not open a public issue or pull request containing an exploitable vulnerability, secrets, or sensitive logs.

1. If GitHub's private vulnerability reporting option is available for this repository, use **Report a vulnerability** on the repository's Security tab.
2. If private reporting is not available, contact the repository maintainer privately through their GitHub profile and request a secure reporting channel. Do not include exploit details in a public issue.
3. Include the affected commit or version, the impact you observed, minimal reproduction steps, and any safe proof-of-concept needed to validate the report. Redact tokens, personal information, and real target details.

## Triage and disclosure

The maintainer will assess reproducibility, affected scope, likely impact, and practical mitigations. If a report is valid, the maintainer will work toward a fix or mitigation and coordinate public disclosure so users have a reasonable opportunity to update. No response or remediation time guarantee is currently offered.

Please test only systems and data you own or are explicitly authorized to assess. Do not access, modify, or exfiltrate third-party data while validating a report.
