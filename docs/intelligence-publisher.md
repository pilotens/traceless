# Central intelligence publisher

The publisher is a separate deployment boundary between the operator-only
scrape/analysis pipeline and customer-owned Traceless installations.

```text
scrape DB -> analysis/review -> publisher DB -> signed v2 feed -> customer-local DB
```

Raw scraped documents and customer-private inventory, architecture, findings and risk
never cross this boundary.

## Production trust surfaces

Run separate processes and PostgreSQL roles:

- `admin`: accounts, installations, entitlements and credentials;
- `ingest`: normalized imports and staging;
- `review`: publication, rejection and decision history;
- `feed`: signed customer delivery only;
- `migrator`: Alembic through the non-login schema owner.

The Compose publisher profile starts all four runtime surfaces on ports 8100–8103.
Production should place them behind separate ingress policies; ingest and review should
not be Internet-accessible.

## Migration

```bash
export TRACELESS_PUBLISHER_DATABASE_URL=postgresql+psycopg://publisher_migrator@localhost/traceless_publisher
export TRACELESS_PUBLISHER_MIGRATION_ROLE=publisher_owner
export TRACELESS_PUBLISHER_AUTO_CREATE_SCHEMA=false
python -m alembic -c publisher_alembic.ini upgrade head
```

The current committed publisher schema head is `p4e1c6a2f540`. SQLite remains
development/test-only. CI validates upgrade, drift check, downgrade to base and upgrade
back to head.

## Workflow

1. The scrape/analysis worker sends normalized records to the ingest surface with
   `publish=false` and a unique idempotency key.
2. A reviewer publishes or rejects the current staged revision with a mandatory reason.
3. Verified source revocations/deletions publish fail-closed tombstones immediately.
4. Customer installations pull `/v2/datapoints`; legacy `/v1/datapoints` is disabled in
   production.

Administrative actors are derived from OIDC or separate service identities. `X-Actor`
is never trusted. Missing production service keys do not fall back to development keys.

## Customer delivery

The v2 feed provides:

- Ed25519 signatures over the exact response bytes;
- SHA-256 content digests;
- frozen full/delta sequence boundaries;
- HMAC-protected cursors and sync tokens;
- entitlement/reset epochs;
- overlapping credentials for controlled rotation.

A reset is reconciled by stable provider/external identity. Existing local record IDs are
preserved, absent identities become tombstones and their findings/risks are retired. The
customer's inventory and architecture are never deleted.

## Publisher schema v4

The v4 publisher schema separates accounts from installations. One customer account can
have independent production, test, development and disaster-recovery installations,
each with its own credentials, TLP ceiling and provider/source-kind entitlements. New
installations are created through `/admin/v2/accounts` and
`/admin/v2/accounts/{account_key}/installations`; the legacy client table is retained
only as a compatibility path for existing deployments.

Revision history records the source kind and record type on every revision, plus
separate source, normalized, AI-analysis and complete-payload digests. A corrected
classification is staged as a new immutable revision and only becomes current after a
reviewer publishes it.

Import runs have a bounded lease. Runs left in `running` after a process crash are marked
`abandoned` and may be safely retried with the same idempotency key and manifest.

## Readiness and key rotation

Production readiness verifies the Alembic revision, optional expected PostgreSQL role,
and the configured active Ed25519 signing-key fingerprint. Deploy the new public key in
the registry before activating it for signing, retain the previous key for the overlap
window, and remove it only after customer installations have refreshed their trust set.

## Backup and capacity checks

`ops/postgres/publisher-backup.sh` writes a manifest and supports optional `age`
encryption through `PUBLISHER_BACKUP_AGE_RECIPIENT`. The restore drill validates schema,
row counts and deterministic content digests. `publisher_load_smoke.py` accepts explicit
error-rate, p95, p99 and minimum-throughput gates; choose environment-specific thresholds
and run it against a production-shaped dataset.

## Separate publisher administration UI

`apps/publisher-web` provides an internal administration surface on the publisher side of
the trust boundary. It supports customer accounts, multiple installations, one-time
credentials, review decisions, import-run status and signing-key inspection. The UI is
separate from the customer-local Traceless web application and uses independent admin and
reviewer identities when OIDC is not configured.

## Remaining production obligations

Production still requires managed TLS and secrets, shared edge rate limiting, encrypted
offsite backups with PITR, restore drills, monitoring/SLOs and an independent penetration
test. Air-gapped delivery should use a separately specified signed offline bundle rather
than weakening the online feed verification rules.
