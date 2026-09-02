# Traceless repository instructions

These instructions apply to the entire repository. More specific `AGENTS.md` files
may add rules for a subtree, but they must not weaken the security invariants below.

## Product mission and source of truth

Traceless is a tenant-scoped security-analysis platform. Its implemented operational
path is:

`authorized input -> observations -> durable assets and findings -> reviewed architecture -> intelligence correlation -> preliminary risk signal -> frozen report`

Before a broad change, read:

1. `README.md`
2. `docs/architecture.md`
3. `docs/security.md`
4. The closest contract or integration document for the code being changed

Describe only behavior that is implemented and tested. Do not silently strengthen
product, security, compliance, or production-readiness claims.

## Toolchain and setup

- Python: exactly 3.12
- Python environment and lock: `uv==0.11.28`, `apps/api/uv.lock`
- Node.js: major version 22
- JavaScript package manager: npm with committed lock files
- CI database: PostgreSQL 18
- Local lightweight tests may use SQLite where the existing tests permit it

For a fresh Codex cloud environment, run:

```bash
bash .codex/setup.sh
```

When a cached environment is resumed on another branch or commit, run:

```bash
bash .codex/maintenance.sh
```

Do not add credentials, production data, private feeds, or customer material to a
Codex environment. Ordinary development and CI do not require production secrets.

## Working method

1. Inspect the relevant implementation, tests, migrations, and documentation before
   editing.
2. Reproduce the problem or establish the current behavior.
3. Make the smallest coherent change that satisfies the task.
4. Add or update tests for every behavior change and regression fix.
5. Run targeted checks first, then all applicable repository checks.
6. Remove diagnostics, generated scratch files, temporary workflows, and bootstrap
   scripts before delivery.
7. Report exactly which checks ran, which did not run, and why.

Do not overwrite unrelated user changes. Do not rewrite large areas merely to match
personal style. Prefer existing abstractions and naming.

## Validation ladder

### API and publisher

```bash
cd apps/api
.venv/bin/ruff check .
.venv/bin/pytest path/to/relevant_test.py
.venv/bin/pytest --cov=traceless_api --cov-report=term-missing
```

### Customer web application

```bash
cd apps/web
npm run test
npm run build
```

### Publisher web application

```bash
cd apps/publisher-web
npm run test
npm run build
```

### Repository-wide checks

Run the applicable subset during development. Before proposing a merge, the complete
GitHub Actions workflow must pass.

```bash
make lint
make test
make build
make check-contract
make audit
make compose-config
```

`make compose-config` and the production-shaped Compose smoke test require Docker.
Never claim those checks passed when Docker is unavailable.

## API contracts and generated files

An API route, request model, response model, enum, or schema change must keep the
committed OpenAPI document and generated TypeScript contracts synchronized:

```bash
make generate-contract
make check-contract
```

Commit both `apps/web/openapi.json` and
`apps/web/src/generated/traceless-api/` when they legitimately change. Never
hand-edit generated API contracts.

## Database changes

- Production schema changes use Alembic. `Base.metadata.create_all()` is only for the
  existing local/test path.
- Preserve a separate schema-owner/migration role and least-privilege runtime roles.
  The API and workers must not become schema owners and must not acquire
  `BYPASSRLS`.
- Preserve forced tenant RLS and transaction-local tenant binding.
- Every migration needs upgrade coverage. Publisher migrations must also remain
  downgrade/upgrade clean where the existing CI requires it.
- Prefer expand-and-contract migrations. A destructive or irreversible change
  requires an explicit staged rollout, backup/restore plan, rollback decision, and
  approval in the task.
- Do not combine a schema change and an unrelated refactor.

## Security and architectural invariants

### Identity and authorization

- Browser authentication remains OIDC Authorization Code with PKCE.
- Authorization is based only on server-verified issuer, audience, signature, tenant,
  roles, and resource assignments.
- Provider roles map through the explicit role map. Never trust an internal-looking
  raw role name or unsigned browser-decoded claims.
- Development `X-Actor` attribution is not authentication and must never become an
  internet-facing fallback.
- Service API keys are server-side machine credentials, never browser credentials.

### Tenant isolation

- Every tenant-owned read and write must be organization-scoped.
- Project and system assignments must remain enforced in addition to organization
  scope.
- The API and worker PostgreSQL roles remain `NOBYPASSRLS`.
- Workers must claim minimal scheduling metadata, bind the claimed organization, and
  only then read payload or domain data.
- Never accept tenant identity, ownership, or authorization scope from unverified
  request data.
- Add negative cross-tenant tests whenever a new tenant-owned resource or lookup is
  introduced.

### Scanning

- Active scanning remains disabled by default.
- Do not enable public-target scanning, arbitrary flags, shell commands, NSE scripts,
  credential attacks, brute force, or exploitation.
- Only literal, approved IP/CIDR scope may reach the fixed scanner profiles.
- Preserve host, duration, output, retry, cancellation, and lease bounds.
- Nmap is operator-installed and is not distributed by this repository.

### Imports, integrations, and intelligence

- Keep request bodies, files, XML/JSON records, pages, redirects, timeouts, and record
  counts bounded.
- Preserve safe XML parsing and strict schemas.
- Network integrations require exact HTTPS origin/host allowlists, no silent
  redirects, tenant-bound credentials, and SSRF-safe behavior.
- Website scraping remains outside Traceless. The product consumes normalized
  contracts from separately operated collectors.
- Source facts, imported evidence, AI analysis, inference, and analyst decisions
  remain separate and retain provenance, timestamps, hashes, and lifecycle state.
- Generic or AI-derived data must not claim official CISA KEV, FIRST EPSS, or NVD
  authority.

### Jobs, reports, and publisher boundary

- Durable jobs remain idempotent, tenant-bound, fenced, leased, heartbeat-driven,
  retry-bounded, and cancellable.
- Frozen reports retain a coherent source snapshot, tenant scope, and integrity
  metadata.
- The central intelligence publisher remains a separate application, database,
  migration history, credential set, and trust boundary.
- Never route publisher administrative surfaces through the customer runtime merely
  to simplify deployment.

### Secrets and logs

- Never commit or print secrets, tokens, private keys, credentials, customer data, or
  production connection strings.
- `.env.example` files contain names and safe examples only.
- Logs and error messages must avoid credential values, raw tokens, sensitive report
  content, and unnecessary imported evidence.
- Do not grant Codex or CI access to production credentials.

## Documentation and claims

Update documentation when a change alters behavior, operator obligations,
configuration, security assumptions, or known limitations. Distinguish clearly
between:

- implemented behavior;
- controlled-pilot readiness;
- deployment obligations;
- future work.

Do not describe a test, scan, correlation, or inferred path as proof of exploitability
unless the implementation and evidence actually establish that claim.

## Code Review Rules

Flag the following as blocking unless the task explicitly provides a safe, tested
exception:

- a tenant-owned query without organization and resource scope;
- a runtime or worker role gaining schema ownership, broad grants, or `BYPASSRLS`;
- authentication or authorization based on unsigned or caller-controlled claims;
- a scanner path accepting arbitrary commands, flags, scripts, credentials, public
  targets, or unbounded scope;
- a connector permitting arbitrary hosts, redirects, insecure HTTP, cross-tenant
  credentials, or unbounded responses;
- source evidence and AI/inference being merged without separate provenance;
- a destructive migration without a staged rollout and rollback/restore plan;
- a secret, token, private key, customer record, or production URL in code, fixtures,
  logs, artifacts, or examples;
- a deployment change that bypasses CI, health checks, environment approval, backup
  controls, or least-privilege database roles;
- a production-readiness or security claim not supported by code, tests, and
  deployment evidence.

Prefer a narrow fix plus a regression test over a broad speculative rewrite.

## Pull requests and deployment

- Work on a dedicated branch and deliver changes through a pull request.
- Keep each pull request reviewable and scoped to one objective.
- Include a summary, security/tenant impact, migrations, configuration changes,
  verification evidence, deployment impact, rollback notes, and remaining risks.
- Do not merge a pull request with failing or missing required checks.
- Do not deploy directly from an agent branch.
- Production deployment may run only from protected `main`, after required CI checks
  and the configured production-environment approval.
- An agent may prepare and validate deployment configuration, but must not create,
  rotate, reveal, or use production secrets, modify production data, or bypass an
  approval gate.
