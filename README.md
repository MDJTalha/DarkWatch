# DarkWatch

Defensive security monitoring and threat-intelligence platform, built in verifiable phases.

**Status:** Phase 2 analyst workflow in development. This is not an endpoint protection product and does not guarantee prevention of intrusions. Do not expose it directly to the public internet without deployment hardening.

## Phase 1 scope
- FastAPI service with a minimal health endpoint.
- SQLite persistence for normalized security events and audit records.
- Authenticated event ingestion and event/summary reads; optional named tokens with roles (`admin`, `analyst`, `ingestor`, `viewer`) and actor-attributed audit rows.
- Input validation, bounded fields, IPv4/IPv6 source-address validation and canonicalization, parameterized SQL, and constant-time API-token comparison.
- Baseline HTTP security headers; the dashboard sets a restrictive Content Security Policy and API/dashboard responses disable caching.
- Deterministic starter severity classification and automated API tests.
- GitHub Actions CI.

## Requirements
Python 3.11 or newer. Windows, macOS, or Linux.

## Run locally on Windows PowerShell
    py -3.11 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    Copy-Item .env.example .env

Set a strong local API token before starting the server (legacy compatibility mode):

    $env:DARKWATCH_API_TOKEN = "replace-with-a-long-random-secret"
    $env:DARKWATCH_DB_PATH = ".\data\darkwatch.db"
    uvicorn darkwatch.main:app --reload

Open http://127.0.0.1:8000/health for liveness and http://127.0.0.1:8000/docs for API documentation. Health reveals no configuration or sensitive data.

## Send a test event
    $headers = @{ Authorization = "Bearer $env:DARKWATCH_API_TOKEN" }
    $body = @{
      source = "lab-agent-01"
      event_type = "failed_login"
      title = "Repeated failed login attempts"
      description = "Three failures observed in a local test lab."
      source_ip = "192.0.2.10"
      metadata = @{ count = 3; environment = "lab" }
    } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/events" -Headers $headers -ContentType "application/json" -Body $body
    Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8000/api/v1/events" -Headers $headers
    Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8000/api/v1/summary" -Headers $headers

Only monitor systems and logs you are authorized to monitor. This release accepts events submitted by an operator or trusted integration; it does not autonomously scan or collect data.

## Authentication and roles

For named identities, set `DARKWATCH_API_TOKENS` to a protected JSON array, for example:

    $env:DARKWATCH_API_TOKENS = '[{"token":"replace-with-a-random-secret-at-least-24-chars","username":"talha-admin","role":"admin"},{"token":"replace-with-another-random-secret","username":"analyst-one","role":"analyst"},{"token":"replace-with-a-third-random-secret","username":"read-only","role":"viewer"}]'

Each token must be at least 24 characters and usernames must be unique. Supported roles are `admin`, `analyst`, `ingestor`, and `viewer`. Admins and analysts can ingest and triage; ingestors can submit events; viewers can only read. All authenticated roles can read events and summaries. When `DARKWATCH_API_TOKENS` is configured, the legacy `DARKWATCH_API_TOKEN` is ignored. Without named-token configuration, the legacy shared token remains temporarily supported and has administrator-equivalent access. Use secret injection for real deployments and do not commit tokens.

## API
| Method | Endpoint | Access | Purpose |
|---|---|---|---|
| GET | /health | Public | Minimal liveness check |
| POST | /api/v1/events | Bearer token | Ingest normalized event |
| GET | /api/v1/events | Bearer token | List events; supports limit, offset, severity, triage_status, event_type, and q filters |
| GET | /api/v1/summary | Bearer token | Severity and triage-status counts |
| PATCH | /api/v1/events/{id}/status | Bearer token | Update triage status |
| POST | /api/v1/events/{id}/notes | Bearer token | Add analyst note |
| GET | /api/v1/events/{id}/notes | Bearer token | List analyst notes |
| GET | /dashboard | Local operator UI | Dashboard; API calls require bearer token |

Event-list query parameters:
- `limit`: 1–200 results per request (default 50).
- `offset`: zero-based pagination offset (default 0).
- `severity`: optional severity filter.
- `triage_status`: optional `new`, `investigating`, or `resolved` filter.
- `event_type`: optional event-type filter; surrounding whitespace and letter case are normalized.
- `q`: optional case-insensitive search across title, source, and description. Unicode case-folding is used for non-ASCII text.

The dashboard applies these filters on the server and provides Previous/Next pagination. Summary counts cover all stored events, not just the current page.

Allowed event types: failed_login, malware_detected, suspicious_process, firewall_block, configuration_change, data_exfiltration_suspected, and other. Classification is a starter rule, not proof an incident occurred.

## Database backup verification

Create a consistent backup to a new path in an existing directory:

    python -m darkwatch.backup --source .\\data\\darkwatch.db --destination .\\data\\backups\\darkwatch-backup.db

The utility refuses to overwrite an existing destination and verifies SQLite integrity, foreign-key consistency, and event/audit/note counts. The automated test uses synthetic data; perform a deployment-specific restore drill before relying on backups.

## Test
    python -m pytest -q

## Phased roadmap
1. **Foundation (this phase):** authenticated API, SQLite records, deterministic rules, audit trail, CI.
2. **Analyst workflow (current branch):** dashboard, search/filtering, triage status, notes. Deduplication and alert delivery remain planned.
3. **Threat intelligence:** explicitly configured trusted feeds, provenance, timestamps, indicator expiry, confidence, evidence links.
4. **Connectors:** opt-in ingestion adapters for authorized endpoints and security tools; retries and rate limits.
5. **Production hardening:** identity and roles, secret management, migrations, retention, backups, observability, deployment review, security testing.
6. **Detection quality:** versioned rules, labeled evaluation datasets, false-positive tracking, regression tests, documented limitations.

A phase is complete only when implementation, tests, and review evidence support that claim. Roadmap items are not current capabilities.

## Security reporting
Follow the private vulnerability-reporting process in [SECURITY.md](SECURITY.md). Do not include credentials, tokens, personal data, or sensitive production logs in public issues.

## Threat model

Review [THREAT_MODEL.md](THREAT_MODEL.md) for the initial repository-based threat model and documented residual risks. It is a draft, not an independent assessment or deployment approval.

## Deployment guidance
Review [DEPLOYMENT.md](DEPLOYMENT.md) before any deployment. The current service remains a development foundation and must not be exposed directly to the public internet.

## License
MIT. See LICENSE.