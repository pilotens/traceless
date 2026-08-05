# Traceless API

FastAPI control plane for Traceless. `/api/v1/operational/*` is the only product
surface; the old synthetic dashboard API has been removed.

## Implemented scope

- PostgreSQL persistence through SQLAlchemy and Alembic. SQLite is for local
  development and tests.
- OIDC RS256 access-token verification with fixed issuer, audience, JWKS URL and
  hostname allowlist.
- Organization-scoped service identities and OIDC principals with `admin`, `analyst`,
  `viewer` and `scanner` roles.
- Repository-enforced organization isolation with negative isolation tests.
- Projects, systems, time-limited scan authorizations and audit attribution.
- An isolated Nmap worker with fixed profiles, leases, heartbeats, retries,
  cancellation, crash recovery and execution-time scope validation.
- Safe Nmap XML and Naabu JSONL adapters.
- Durable assets, services, findings, evidence and finding lifecycle transitions.
- Separate immutable manual-architecture and observed-topology streams.
- Direct `.nessus` parsing and a normalized vulnerability-observation contract.
- Tenant-bound durable background jobs for large normalized imports and reports,
  with payload digests, idempotency, leases, heartbeats, retries and cancellation.
- CISA KEV, FIRST EPSS and NVD 2.0 direct adapters. Private threat data enters
  through the canonical tenant connector/import and analyst-review workflow.
- Tenant-scoped intelligence ingestion with independent source and AI provenance.
- Tenant-owned pull-only connectors for separately operated scraper/analysis APIs,
  with external credential references, durable sync runs/checkpoints and append-only
  intel revisions, plus an optional tenant schedule and isolated pull worker.
- Explainable risk assessment and frozen PDF, JSON and CSV reports.
- Bounded read-only NetBox snapshots and out-of-process extension contracts.

## Authentication and tenancy

Human users authenticate through the browser's OIDC Authorization Code + PKCE flow.
The API validates the access-token signature and claims locally. It maps the configured
organization and roles claims to an `AuthenticatedPrincipal` and scopes every
repository created by request handling to that organization.

Role claim mapping is explicit through `TRACELESS_OIDC_ROLE_MAP`; role names are not
accepted by coincidence. `GET /api/v1/auth/me` exposes the validated principal and
server-derived capabilities. Scanner identities have only scan-management access and
cannot browse operational data or ingest intelligence.

Machine integrations can use `TRACELESS_OPERATIONAL_API_KEY`. Its organization,
actor name and roles come only from server configuration. It is not suitable for a
browser bundle. Production startup requires configured OIDC or this service key.

The current tenant boundary is enforced in the application repository layer and is
covered by negative tests. PostgreSQL RLS remains a desirable defense-in-depth
control, not a completed feature. Project-level sharing and custom roles are also
outside the current scope.

The process-configured private NetBox integration is fenced separately because its
URL and credential are global to one API process. It requires
`TRACELESS_NETBOX_ORGANIZATION_ID` in production. Requests from any other
organization receive a generic 404 before an HTTP client is created. Private threat
intelligence does not have a process-global, system-scoped sync route; it must use the
organization-owned external connector or canonical import followed by analyst review.
CISA KEV, FIRST EPSS and NVD remain shared public upstreams; their imported results
are still persisted per organization.

In development/test without configured authentication, `X-Actor` supplies audit
attribution only. Do not expose that mode to an untrusted network.

## Run locally

Requires Python 3.12 and uv 0.11.28.

```bash
uv sync --locked --extra dev
.venv/bin/alembic upgrade head
.venv/bin/uvicorn traceless_api.main:app --reload --host 0.0.0.0 --port 8000
```

OpenAPI is available at `http://localhost:8000/docs` in development. Probes are
`/health/live` and `/health/ready`. Configuration uses `TRACELESS_` variables; see
`.env.example`.

## Scanner worker

Nmap is not distributed with Traceless. After operator installation, licensing
review, network isolation and explicit target authorization:

```bash
export TRACELESS_NMAP_ENABLED=true
python -m traceless_api.worker
```

The API cannot supply scanner flags. The worker uses `shell=False`, reviewed
non-privileged profiles, exact literal IP/CIDR scope, host/time/output limits and an
authorization valid for at most 24 hours. It leases jobs, emits heartbeats, honors
cancellation, recovers stale leases and stops after a bounded number of attempts.

## Import and report worker

Keep the synchronous import/report routes for bounded interactive work. Queue large
normalized imports and report rendering through the async endpoints, then run the
separate database worker:

```bash
traceless-job-worker
```

The worker verifies the immutable payload digest before processing. Job rows and
status APIs are organization-scoped; leases, periodic heartbeats, cancellation,
crash recovery and bounded retry are persisted in PostgreSQL. Report enqueue requires
an `Idempotency-Key`; normalized imports are content-idempotent by default. See
[`docs/background-jobs.md`](../../docs/background-jobs.md).

## Intelligence input

Collectors may push batches to:

`POST /api/v1/operational/intelligence/records/import`

The separately operated scraper/analysis service may instead be pulled through:

`POST /api/v1/operational/intelligence/sync/external`

An administrator first creates the organization-scoped configuration at
`PUT /api/v1/operational/intelligence/connectors/external`. The row stores an
allowlisted HTTPS endpoint and a reference into
`TRACELESS_EXTERNAL_INTELLIGENCE_CREDENTIALS`, represented as nested JSON
`{organization_key: {credential_reference: secret}}`, never the credential. Pulls do not
follow redirects and are bounded by page, byte, record and timeout limits. They
persist fenced/leased sync runs, snapshot-bound cursor checkpoints, cumulative page
and identity manifests, and append-only record revisions; unreasonable future timestamps are quarantined. Traceless never
performs website scraping. Set `sync_interval_seconds` to 60–2,592,000 seconds and
run `traceless-external-intelligence-worker --poll` for scheduled pulls, or leave it
`null` for manual-only operation. See
[`docs/external-intelligence-connector.md`](../../docs/external-intelligence-connector.md).

## Data semantics

- CVSS is technical severity, not likelihood.
- EPSS is a dated probability estimate from 0 to 1.
- CISA KEV is known-exploitation catalogue membership, not a score.
- Evidence confidence describes certainty in evidence; it is not exploit probability.
- Imported, inferred, observed and analyst-confirmed data remain distinguishable.
- Findings can exist without a CVE and retain lifecycle/evidence history across scans.

## Test

```bash
pytest
pytest --cov=traceless_api --cov-report=term-missing
```

CI additionally runs the migration chain and an API smoke test against PostgreSQL.
