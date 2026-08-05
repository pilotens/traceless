# Durable background jobs

Large normalized vulnerability imports and report rendering can run outside the API
process. The synchronous endpoints remain available for small, bounded API clients.
The web client always uses the queued endpoints for Nessus/normalized vulnerability
imports and report rendering, polls persisted status and supports cooperative
cancellation; it never falls back silently to a synchronous route.

## Enqueue

```http
POST /api/v1/operational/systems/{system_id}/vulnerability-scans/import/async
Content-Type: application/json
Idempotency-Key: optional-client-retry-key
```

The body is the existing normalized vulnerability import contract. Without a caller
key, its canonical SHA-256 digest provides content idempotency.

Nessus XML has a parallel endpoint:

```http
POST /api/v1/operational/systems/{system_id}/vulnerability-scans/import/nessus/async
Content-Type: application/xml
```

The API bounds and safely normalizes the XML before enqueue. The worker handles the
database-heavy correlation; the job stores normalized JSON plus the raw-file digest,
not the original XML.

```http
POST /api/v1/operational/systems/{system_id}/reports/async
Content-Type: application/json
Idempotency-Key: required-stable-request-key

{"format":"pdf","report_type":"management"}
```

Report jobs require a caller key because two identical format requests may represent
different intended report runs. Reusing a key with a changed payload returns `409`.

Approved external-intelligence records enqueue `intelligence_correlation` jobs for
eligible systems. A completed pull alone only populates the analyst review queue.
Correlation jobs use the same leases, retries, status polling and cancellation as
imports and reports.

## Inspect and control

```http
GET  /api/v1/operational/jobs?status=running&limit=50&offset=0
GET  /api/v1/operational/jobs/{job_id}
POST /api/v1/operational/jobs/{job_id}/cancel
POST /api/v1/operational/jobs/{job_id}/retry
```

Lists and details require operational read access. Enqueue, cancel and manual retry
require analyst/admin access. Every query is scoped to the authenticated organization;
foreign job IDs fail as `404`. Payload bodies and idempotency keys are never returned.

Statuses are `queued`, `running`, `completed`, `failed` and `cancelled`. Cancellation
of queued or running work is immediately persisted as terminal and revokes the current
attempt token. The worker's transaction can therefore no longer commit partial output;
an in-flight attempt detects the lost lease and rolls back. An expired non-cancelled
lease is reclaimed until the bounded attempt budget is exhausted.

## Run the worker

Apply Alembic migrations, then run a separate process against the same PostgreSQL DB:

```bash
traceless-job-worker
```

Use `--once` for one claim or `--poll-seconds N` to change idle polling. Configure
lease, heartbeat, retry delay and attempts with:

- `TRACELESS_BACKGROUND_JOB_WORKER_ID`
- `TRACELESS_BACKGROUND_JOB_LEASE_SECONDS`
- `TRACELESS_BACKGROUND_JOB_HEARTBEAT_SECONDS`
- `TRACELESS_BACKGROUND_JOB_RETRY_DELAY_SECONDS`
- `TRACELESS_BACKGROUND_JOB_MAX_ATTEMPTS`

Each payload is stored with an immutable canonical digest. The worker re-computes it
before execution and fails closed on mismatch. Worker errors return a generic API
message; internal exception detail is emitted only to operator logs.

Periodic heartbeat renewal is enabled on PostgreSQL. SQLite is development/test-only;
its database-wide writer lock makes a concurrent heartbeat unsafe, so local jobs rely
on the initial lease and phase-boundary updates instead.
