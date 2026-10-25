# Deployment and Operations Notes

## Current status

DarkWatch is a development foundation. This guide is a pre-deployment checklist, not evidence that a production deployment has been tested or approved. Do not expose the current service directly to the public internet.

## Network boundary

- Keep the service bound to loopback for local development.
- If another host must reach it, place it on a private network behind a maintained TLS-terminating reverse proxy and restrict access with a firewall or private-network policy.
- Permit inbound traffic only from the proxy or explicitly authorized clients.
- Do not assume forwarded headers are trustworthy unless the proxy and application are deliberately configured for that trust boundary.
- Do not expose interactive API documentation publicly unless access is intentionally controlled.

## Authentication secret

- Preferred: set `DARKWATCH_API_TOKENS` to a secret-injected JSON array of named identities, each with a unique `token` (at least 24 characters), `username`, and `role` (`admin`, `analyst`, `ingestor`, or `viewer`). Example shape: `[{"token":"<random-secret>","username":"analyst.alice","role":"analyst"}]`. Do not commit real tokens or place them in logs.
- When `DARKWATCH_API_TOKENS` is configured, it takes precedence and the legacy shared token is disabled.
- `DARKWATCH_API_TOKEN` remains as a temporary compatibility mode when the named-token variable is absent; it grants the legacy shared identity administrator access and should be retired after named tokens are configured.
- Use a cryptographically random value substantially longer than the application's 24-character minimum.
- Restrict access to the secret to the service operator and the process that needs it.
- To rotate the shared token, coordinate the new value with all authorized integrations, update the runtime secret, and restart/redeploy the service. The current shared-token design does not support per-user tokens or overlapping rotation windows.
- Named-token roles are enforced for event ingestion (`admin`, `analyst`, `ingestor`) and triage mutations (`admin`, `analyst`); all authenticated roles may read data. `viewer` is read-only. Store the JSON configuration in a protected secret manager and rotate credentials if exposed.

## Database and backups

- Set `DARKWATCH_DB_PATH` to a persistent path on a private local volume with restrictive filesystem permissions.
- Do not place the SQLite database on an untrusted or publicly served directory.
- Create a consistent backup using `python -m darkwatch.backup --source .\\data\\darkwatch.db --destination .\\data\\backups\\darkwatch-backup.db`. The destination must be a new file in an existing directory; the command verifies SQLite integrity, foreign keys, and table counts. Store backups separately with access controls, and periodically test restores into a disposable location. This utility has automated tests against synthetic databases; a real deployment backup/restore drill is still required.
- Do not run restore or migration experiments against the only copy of a real database.
- Define retention, recovery-point, and recovery-time objectives before production use.

## Logging and monitoring

- Send application and reverse-proxy logs to an access-controlled destination.
- Do not log bearer tokens, authorization headers, sensitive request bodies, or unnecessary personal data.
- Monitor service availability, repeated authentication failures, database errors, disk capacity, and backup/restore outcomes.
- Establish an owner and response process for alerts and dependency vulnerabilities.

## Threat model

Review [THREAT_MODEL.md](THREAT_MODEL.md) as an initial repository-based review. Validate its assumptions against the actual deployment and arrange independent security review before external exposure.

## Before any external deployment

- Replace legacy shared-token mode with named identities and role-based authorization.
- Add tamper-evidence, retention, and independent protection for actor-attributed audit records; actor attribution alone does not make the audit log tamper-proof.
- The application now rejects request bodies larger than 16 KiB, including streamed bodies; also enforce limits and rate controls at the reverse proxy and network edge.
- Versioned SQLite migrations are implemented and legacy schema upgrades are covered by automated tests; run a deployment-specific upgrade rehearsal and backup/restore drill on a disposable database copy before rollout.
- Complete backup/restore drills, threat modeling, and an independent security review.
- Confirm the CI dependency audit and full test suite pass for the exact release commit.
- Record the approved configuration and rollback plan.

Until these items are completed and evidenced, treat this service as an internal development tool only.
