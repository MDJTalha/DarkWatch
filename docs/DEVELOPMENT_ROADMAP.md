# DarkWatch Development Roadmap

## Purpose

DarkWatch is a local-first security monitoring and analyst-workflow platform. Development must prioritize trustworthy evidence, secure defaults, explainable detections, and reproducible tests. It is not an endpoint protection product and must not claim to autonomously scan or collect telemetry unless a separately implemented and explicitly configured integration provides that capability.

## Working rules

- Keep local development and production secrets out of Git; never commit `.env`, API tokens, database files, or captured security events.
- Bind the development API to loopback by default. Do not expose it to a public network without an explicit deployment design and security review.
- Treat event payloads, external feeds, enrichment results, and imported indicators as untrusted input.
- Prefer additive schema migrations and explicit backup/restore procedures. Never delete user data as part of routine upgrades.
- Every security-relevant change needs tests, clear error behavior, and audit coverage where appropriate.
- Report only tests and controls that have actually been run and verified.

## Delivery sequence

### Phase 0 — Baseline and repository safety

- Confirm the active branch and commit before changes.
- Verify automated tests and record warnings.
- Confirm secrets, local databases, and generated data are excluded from version control.
- Document local startup, health checks, and configuration behavior.
- Keep the original local project and GitHub checkout separate until their histories and changes have been reviewed.

**Exit evidence:** clean, reproducible test run; documented configuration; no secrets or runtime data in the proposed changes.

### Phase 1 — Authentication and configuration hardening

- Establish one documented source of truth for configuration, including whether `.env` is loaded or environment variables must be exported by the shell.
- Fail safely when authentication is required but no token is configured.
- Use constant-time token comparison and avoid logging credentials.
- Protect analyst endpoints consistently; verify unauthenticated, invalid-token, and valid-token behavior with tests.
- Document token rotation and local-only binding.

**Exit evidence:** automated auth tests for each protected route and startup configuration tests.

### Phase 2 — Analyst workflow and event integrity

- Validate incoming event schemas and enforce payload-size and field-length limits.
- Normalize timestamps and severity/category fields deterministically.
- Provide stable pagination and filters for event queries.
- Make event ingestion and error responses predictable and auditable.
- Add tests for malformed payloads, duplicate submissions, boundary values, and database failures.

**Exit evidence:** API contract tests and database integration tests.

### Phase 3 — Detection and correlation

- Implement deterministic, versioned detection rules with explicit rationale and severity.
- Correlate related events using documented time windows and stable identifiers.
- Preserve source events and record which rule/version produced each finding.
- Add regression fixtures for true-positive, benign, malformed, and edge-case events.
- Avoid presenting unverified indicators or heuristic matches as confirmed compromise.

**Exit evidence:** reproducible rule tests, correlation tests, and traceable finding-to-event links.

### Phase 4 — Threat intelligence and scheduled acquisition

- Make external-feed acquisition opt-in and configurable.
- Validate feed formats and provenance; record retrieval time and source.
- Add bounded timeouts, retry/backoff, rate-limit handling, and clear failure states.
- Track indicator freshness and avoid silently treating stale feeds as current.
- Test offline operation and feed failures without losing existing records.

**Exit evidence:** mocked network tests, provenance records, and documented offline behavior.

### Phase 5 — Audit, backup, and recovery

- Record security-sensitive administrative actions without storing secrets.
- Define backup format, retention, integrity checks, and restore validation.
- Ensure backups are not placed in source control by default.
- Test recovery against a disposable database before documenting a restore as verified.

**Exit evidence:** automated audit tests and a tested backup/restore procedure.

### Phase 6 — Release readiness

- Add CI checks for supported Python versions, tests, dependency review, and secret scanning.
- Document limitations, threat model, deployment boundaries, and incident handling.
- Review access control, input validation, dependency risks, logging, and data retention.
- Do not describe DarkWatch as production-ready until the release checklist is evidenced.

**Exit evidence:** green CI, reviewed security checklist, and a release note listing known limitations.

## Immediate next implementation target

Resolve and test configuration/authentication behavior first. In particular, confirm whether the application loads `.env` automatically or relies exclusively on process environment variables. A saved `.env` file must not be assumed to affect an already-running server. Rotate any token that has been exposed in terminal output or chat, then verify authentication with a fresh local token without printing it.

## Definition of done

A change is complete only when:
1. The implementation is committed on a review branch.
2. Relevant automated tests pass.
3. Configuration and failure behavior are documented.
4. No secrets, local databases, or private event data are included.
5. Claims in the README and release notes match verified behavior.
