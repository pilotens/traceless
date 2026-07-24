# Traceless

Traceless is a security-analysis platform under active development. Its implemented
operational path is:

**authorized input → observations → durable assets and findings → reviewed architecture → intelligence correlation → preliminary risk signal → frozen report**

The repository contains a persistent, tenant-scoped engineering slice of that path.
It is suitable for controlled development and pilot preparation, but deployment
hardening, backup/restore evidence, observability and an independent security review
are still required before exposure to an untrusted production network.

## What works now

- OIDC Authorization Code + PKCE for browser users. Access tokens remain in memory;
  state and verifier are short-lived session data.
- Local RS256 access-token verification with fixed issuer, audience and JWKS
  configuration. Token-provided key URLs are rejected.
- Server-enforced `admin`, `analyst`, `viewer` and `scanner` roles. A separate API key
  may be configured for a machine identity tied to one organization and a fixed role
  set; it is never a browser credential.
- Organization-, project- and system-scoped authorization with negative isolation
  tests. PostgreSQL deployments additionally force tenant RLS for the API runtime
  role and restore its transaction-local tenant scope after every commit boundary.
- Explicit IP/CIDR scan authorizations that expire within 24 hours, enforce scope and
  host limits, and retain audit attribution.
- A database-backed Nmap worker with fixed non-privileged profiles, leases,
  heartbeats, bounded retries, cancellation and stale-job recovery. Nmap is
  operator-installed and not distributed by Traceless.
- Bounded Nmap XML and Naabu JSONL imports through the same scope controls as live
  collection.
- Durable asset and finding identities with first/last seen data, observation counts,
  evidence strength and lifecycle states: open, fixed, accepted, false positive, out
  of scope and reopened.
- Separate manual architecture and observed-topology version streams. A scan cannot
  replace the current manually edited model.
- A React Flow editor with components, data flows, trust zones, immutable successor
  versions, optimistic concurrency, undo/redo and unsaved-change protection.
- Direct `.nessus` import plus a strict normalized JSON contract for separately
  operated Qualys, Greenbone/OpenVAS, Rapid7, Defender VM and future adapters.
  Non-CVE and unmatched observations remain visible and can be correlated again when
  inventory changes.
- CISA KEV, FIRST EPSS and NVD 2.0 adapters with provenance. Private threat data
  enters through the canonical tenant connector/import and analyst-review workflow.
  CVSS severity, EPSS probability, KEV membership, exposure, reachability, evidence
  confidence and contextual risk remain distinct signals.
- A tenant-scoped intelligence hub for news, MISP-derived records and vulnerability
  pipelines, with separate source/AI hashes, versioned AI provenance, lifecycle
  handling and indexed observables.
- A pull-only connector for normalized datapoints from a separately operated scraper
  or analysis service. Traceless does not scrape websites.
- Distinct management, technical and risk-register reports as frozen PDF, JSON and
  CSV snapshots with SHA-256 hashes and CSV formula neutralization.
- Tenant-scoped durable jobs for normalized/Nessus imports, approved-intelligence
  correlation and report rendering, with idempotency, fenced leases, heartbeat,
  retry and terminal cancellation. The web
  client uses only these queued paths and displays their status and cancellation.
- Bounded, read-only NetBox synchronization and out-of-process extension contracts.

## Important boundaries

- Nmap/Naabu provide discovery and service inventory, not a complete vulnerability
  assessment. Imported scanner findings remain evidence, not automatic proof.
- Nessus is the only directly parsed commercial scanner format. Other named products
  require their own external adapter to the normalized contract.
- Manual architecture and observed topology are different data. Formal proposed-change
  workflows are not implemented yet.
- Scanning is disabled by default and is only for targets the operator owns or is
  explicitly authorized to assess.
- Vulnerability imports and reports from the web client use the durable worker. Very large correlation runs,
  object-storage-backed upload/download and high-volume load evidence remain future
  production work.
- Deployment controls remain necessary: secret management, TLS, restricted egress,
  database backups, centralized logs, monitoring, rate limiting and penetration
  testing.

## Start locally

Requirements: Python 3.12, uv 0.11.28, Node.js 22, npm, and optionally Docker
Compose.

```bash
make install
make migrate
make dev-api
```

In another terminal:

```bash
make dev-web
```

Open `http://localhost:5173`. API health is available at
`http://localhost:8000/health/live`, readiness at
`http://localhost:8000/health/ready`, and local OpenAPI documentation at
`http://localhost:8000/docs`.

The default local database is SQLite. Configuration uses `TRACELESS_` variables;
see [`apps/api/.env.example`](apps/api/.env.example). Browser OIDC configuration uses
Vite variables; see [`apps/web/.env.example`](apps/web/.env.example). The local
PostgreSQL stack is available with:

```bash
make up
```

Compose provisions runtime roles idempotently, then a separate schema-owner service
applies Alembic before the API starts. The API role cannot migrate the schema. Compose also starts the
durable import/report worker and the external-intelligence scheduler as idle database
workers. The latter only polls organization-owned connectors that have an explicit
schedule; it contains no scraper or collector. The scanner worker remains deliberately
disabled in Compose.

To use a separately operated scraper/analysis API with Compose, inject its read-only
credential map and exact HTTPS hostname allowlist at startup; do not commit them:

```bash
export TRACELESS_EXTERNAL_INTELLIGENCE_CREDENTIALS='{"tenant-id":{"tenant-feed-primary":{"secret":"replace-with-a-secret","origin":"https://intel-pipeline.example.test"}}}'
export TRACELESS_INTELLIGENCE_ALLOWED_HOSTS='["www.cisa.gov","api.first.org","services.nvd.nist.gov","intel-pipeline.example.test"]'
make up
```

With no scheduled connector, the external-intelligence worker remains safely idle.
Traceless only pulls the normalized connector contract; all website scraping stays in
the separate program.

## Authentication

Production requires either:

1. OIDC issuer, audience and JWKS configuration for human users; or
2. a long random service API key scoped by server configuration to one organization
   and a fixed list of roles.

The browser flow uses Authorization Code + PKCE and sends the OIDC access token as a
Bearer token. The API derives subject, organization and roles only from verified
claims. Provider roles require an explicit `TRACELESS_OIDC_ROLE_MAP`; raw internal
role names are not trusted implicitly. The UI obtains its server-derived capabilities
from `GET /api/v1/auth/me`. Scanner identities cannot browse operational or
intelligence data. Development without either method permits `X-Actor` for audit
attribution; that mode is not authentication and must never be internet-facing.

## Scanner worker

Active scanning is disabled by default. Only enable it after licensing and installing
Nmap, confirming authorization for the exact targets and isolating the worker:

```bash
export TRACELESS_NMAP_ENABLED=true
make dev-worker
```

The API does not accept free-form flags, NSE scripts, credentials, brute-force
options or exploitation instructions. Public targets remain blocked unless an
operator explicitly changes policy.

## External intelligence

Your scraper or AI pipeline runs separately and exposes normalized, cursor-paginated
datapoints. Each organization owns a connector configuration containing an
allowlisted HTTPS endpoint and an external credential reference. Traceless pulls
bounded pages with Bearer or `X-API-Key`, persists snapshot-bound checkpoints and
append-only source revisions, verifies cumulative page/identity manifests across
resumes, and quarantines unreasonable future timestamps. Run and scheduler writes
use expiring random fencing tokens so reclaimed workers cannot overwrite newer state. It
imports source evidence and AI analysis without merging them. An optional per-tenant
interval is executed by a separate pull worker; `null` remains manual-only. See
[external intelligence connector](docs/external-intelligence-connector.md)
and [ingestion contract](docs/intelligence-ingestion.md).

## Verify

```bash
make lint
make test
make build
make audit
make compose-config
```

CI runs backend tests, applies the full Alembic history to PostgreSQL, checks for
model/migration drift, runs a PostgreSQL API smoke test, tests and builds the frontend,
validates dependency locks, and builds/starts the Compose stack with API, CSP/OIDC,
runtime-role and health smoke checks.

## Repository

```text
apps/web              React and TypeScript operational UI
apps/api              FastAPI API, worker, persistence, adapters and migrations
docs                  Architecture, security, integrations and roadmap
docker-compose.yml    Local PostgreSQL/API/web development stack
.github/workflows     Migration, test, build and dependency checks
```

See the [architecture](docs/architecture.md), [security model](docs/security.md),
[vulnerability import contract](docs/vulnerability-scan-imports.md) and
[roadmap](docs/roadmap.md) for current boundaries and remaining work.
