# API and publisher agent instructions

These instructions apply under `apps/api/` in addition to the repository-level
instructions.

## Structure

- `src/traceless_api/main.py`: customer API application
- `src/traceless_api/api/`: HTTP routes and request dependencies
- `src/traceless_api/services/`: domain behavior
- `src/traceless_api/db/`: SQLAlchemy models and session/tenant mechanics
- `src/traceless_api/worker.py`: authorized scanner worker
- `src/traceless_api/job_worker.py`: durable import/report jobs
- `src/traceless_api/external_intelligence_worker.py`: scheduled normalized-feed pulls
- `src/traceless_api/publisher/`: independent central publisher
- `migrations/`: customer database Alembic history
- `publisher_migrations/`: publisher database Alembic history
- `tests/`: API, worker, tenancy, migration, integration, and publisher tests

Keep HTTP parsing thin. Put reusable behavior in services and preserve repository
methods as the enforcement point for tenant and resource scope.

## Python rules

- Support Python 3.12 only.
- Use existing typing, Pydantic, SQLAlchemy, and FastAPI patterns.
- Do not add a dependency unless the standard library and existing dependencies are
  insufficient. Update `pyproject.toml` and `uv.lock` together.
- Do not catch broad exceptions merely to continue. Convert expected boundary errors
  deliberately and preserve useful audit attribution.
- Use timezone-aware timestamps and the database clock where lease or schedule
  eligibility depends on authoritative time.
- Keep external inputs bounded before expensive parsing, persistence, or correlation.

## Dependency security

- Do not suppress or broadly ignore a dependency advisory merely to make CI pass.
- For a vulnerable direct dependency, review the upstream security/changelog notes,
  move the manifest to the smallest supported fixed release line, and refresh the
  lock with `uv` rather than hand-editing hashes.
- For a vulnerable transitive or development dependency, update only the affected
  lock resolution unless an explicit direct constraint is required.
- A runtime dependency update requires the full API tests, hash-verified dependency
  audit, and the production-shaped container build before merge.
- Record removed APIs, changed platform requirements, or other upgrade risks in the
  pull request even when the test suite remains green.

## Database and tenancy

- Request sessions bind one immutable organization. Do not reuse or rebind a session
  across tenants.
- New tenant-owned tables require a non-null organization boundary, repository
  filtering, PostgreSQL RLS policy, grants for the intended runtime role, migrations,
  and negative isolation tests.
- Queue dispatch functions may return only minimal non-sensitive scheduling metadata.
  Worker payload reads happen after tenant binding.
- Runtime services use the API or worker role. Alembic uses the migration/schema owner.
- Do not substitute the managed database's administrative user for runtime roles.

## API and authentication

- Derive actor, tenant, roles, and resource assignments only from verified OIDC claims
  or the fixed server-side machine identity.
- Route authorization must be enforced server-side even when the UI hides an action.
- Keep errors for foreign and unknown tenant resources indistinguishable where the
  existing security model requires it.
- A schema-visible API change requires regeneration of the committed OpenAPI and
  TypeScript contracts from the repository root.

## Workers and integrations

- Preserve lease tokens/fencing, heartbeats, bounded retries, cancellation, stale-job
  recovery, and idempotency.
- Scanner execution uses fixed argument vectors with `shell=False`; never accept raw
  command text.
- HTTP integrations must validate tenant binding, exact origin/hostname, scheme, page
  and byte limits, timestamps, and redirect behavior before persistence.
- Tests must cover failure and cancellation paths, not only the successful path.

## Verification

For a focused change:

```bash
.venv/bin/ruff check .
.venv/bin/pytest path/to/relevant_test.py
```

For an API-complete change:

```bash
.venv/bin/pytest --cov=traceless_api --cov-report=term-missing
```

For migrations or PostgreSQL/RLS behavior, run the relevant PostgreSQL tests when a
database is available and rely on the full GitHub Actions matrix before merge. State
clearly when local cloud execution could not run Docker or PostgreSQL.
