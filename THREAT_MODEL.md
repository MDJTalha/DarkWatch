# DarkWatch Threat Model (Development Review)

## Status and limits

This is an initial, repository-based threat-model draft for the current FastAPI/SQLite branch. It is not an independent security assessment, penetration test, compliance certification, or production approval. It must be reviewed against the actual deployment topology before external exposure.

## Scope

In scope:
- FastAPI service and /dashboard operator UI.
- Bearer-token authentication and named identities configured through DARKWATCH_API_TOKENS.
- Event ingestion, event listing/search, summary, triage status, analyst notes, and audit records.
- SQLite database, schema migrations, backup utility, CI and dependency auditing.

Out of scope until separately designed:
- Endpoint agents and their trustworthiness.
- Automated scanning, prevention, remediation, or autonomous collection.
- External threat-intelligence feeds, alert delivery, multi-tenant isolation, and cloud deployment.
- Reverse proxy, identity provider, host OS, secret manager, and backup storage implementation.

## Assets

1. API tokens and identity/role configuration.
2. Security-event records, source addresses, metadata, and analyst notes.
3. Audit records used to reconstruct analyst actions.
4. SQLite database and backup copies.
5. Availability and integrity of the analyst workflow.
6. Source code, dependency resolution, CI credentials, and release artifacts.

## Trust boundaries and data flow

- An operator or authorized integration sends JSON over HTTP to the API.
- The API validates bearer tokens and roles before protected operations.
- Pydantic validation and SQL parameter binding constrain event input and queries.
- The application reads/writes a local SQLite database.
- An operator-provided token stays in dashboard page memory; it is not intentionally persisted by the UI.
- CI installs declared dependencies, audits them with pip-audit, and runs tests across Python 3.11–3.13.
- Backup creation uses explicit source/destination paths and does not overwrite an existing destination.

For any networked deployment, TLS termination, firewall policy, secret injection, and log storage introduce additional trust boundaries that this repository cannot validate on its own.

## Threats, controls, and residual risk

| Threat | Current controls | Residual risk / required work |
|---|---|---|
| Unauthorized API access | Bearer authentication; constant-time token comparison; short/missing token configuration fails closed | Legacy shared-token mode remains compatible and is administrator-equivalent; retire it before external deployment |
| Excessive privileges | Named roles: admin, analyst, ingestor, viewer; viewer is read-only; ingestion and triage have role gates | Role policy has focused tests but needs broader threat-driven tests and deployment review |
| Oversized request body | 16 KiB application-level limit for declared and streamed request bodies | Configure independent reverse-proxy limits, rate limits, connection/timeouts, and monitoring |
| SQL injection | Parameterized queries; SQL-like search regression test | Continue review whenever queries or filters change |
| Malformed or oversized event fields | Pydantic field limits, allowed event types, source-IP parsing, metadata serialization cap | Add fuzzing and broader malformed-payload tests |
| Cross-site scripting in dashboard | Event values rendered with textContent; restrictive CSP; frame protections | CSP permits inline script/style for the current single-page UI; avoid unsafe HTML rendering and consider nonce/hash-based CSP if UI evolves |
| Audit repudiation or tampering | Actor-attributed records are linked by a SHA-256 hash chain; an administrator-only endpoint verifies the chain and reports the first invalid row | A privileged attacker can rewrite the whole database and recompute hashes; no external immutable sink or retention enforcement exists. Export or anchor audit evidence to separately controlled storage |
| Database corruption or failed upgrade | Versioned migrations; idempotence and legacy-data tests; SQLite backup/verification helper | Perform deployment-specific backup/restore and upgrade rehearsals; define RPO/RTO with the service owner |
| Secret leakage | Documentation advises secret injection and prohibits token logging/committing | Environment configuration may be exposed through process/operator access; use a managed secret store and least privilege |
| Dependency compromise | pip-audit in CI and supported-Python test matrix | Requirements use version ranges rather than a fully locked/hash-verified deployment artifact; review CI action pinning and release provenance |
| Denial of service | Bounded list page size and request body size | No application-level rate limiter, quotas, or deployment edge controls are implemented |
| Exposure through deployment errors | Deployment guide says not to expose directly to public internet | No real deployment has been validated; bind to loopback/private network and verify reverse-proxy configuration |

## Minimum external-deployment gates

- Disable legacy shared-token authentication; provision unique named tokens through a protected secret manager.
- Terminate TLS at a maintained reverse proxy; restrict ingress to authorized networks and clients.
- Configure request-rate, connection, and timeout controls at the network edge.
- Protect SQLite files and backups with least-privilege filesystem and storage access.
- Complete a restore drill and migration rehearsal on disposable copies; record recovery objectives.
- Establish audit retention and tamper-evidence, such as a separately protected append-only sink or a reviewed cryptographic integrity design.
- Add operational monitoring and alert ownership.
- Run a focused threat-driven test suite and obtain an independent security review.
- Verify CI against the exact release commit and document the release/rollback configuration.

## Assumptions

- Users are authorized to submit and view the event data they provide.
- Event contents may be sensitive and should not be sent to public issues or logs.
- The current deployment is development-only until the gates above have evidence.
- Severity classification is a deterministic starter rule and is not proof that an incident occurred.

## Review record

- Draft generated from the current repository implementation and deployment documentation.
- Independent reviewer: not yet assigned.
- Deployment-specific review: not yet performed.
