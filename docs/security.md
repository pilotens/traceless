# Security model

This document describes implemented controls and explicit deployment obligations. It
is not a claim that Traceless is production-ready.

## Identity, authorization and tenancy

- Browser users use OIDC Authorization Code + PKCE. The SPA stores the access token
  only in memory and stores only the short-lived state/verifier transaction in
  session storage.
- The API accepts RS256 access tokens only. Issuer, audience and JWKS URL are fixed
  operator configuration; embedded or token-directed key URLs are rejected.
- Verified claims select one organization. Provider roles map to `admin`, `analyst`,
  `viewer` or `scanner` only through the explicit `TRACELESS_OIDC_ROLE_MAP`; an
  internal-looking raw claim such as `admin` is never accepted implicitly.
- `GET /api/v1/auth/me` returns only the server-verified subject, organization, roles
  and capabilities. The browser never authorizes itself from unsigned JWT payloads.
- Scanner identities can submit authorized scan work but cannot browse operational
  collections or import/pull threat intelligence. Human read access is limited to
  admin, analyst and viewer roles.
- Every request repository is organization-scoped. Projects, systems, intelligence
  identities and audit records include that non-null boundary. Scanner workers
  resolve the owning organization from each persisted job before emitting audit.
  Negative tests exercise
  cross-organization object lookup and duplicate external identities.
- A machine may use one long random service API key. Its organization, actor and role
  set are server configuration. It is not a human identity or browser credential.
- Process-global private NetBox and internal-threat-feed credentials are each bound
  to one explicit organization UUID in production. Other organizations receive the
  same generic 404 for known, foreign and unknown system IDs before any HTTP client
  is created. The development/test fallback permits only the fixed default
  organization, never the requesting tenant dynamically. Public CISA KEV, FIRST EPSS
  and NVD sources remain shareable; their derived records stay tenant-scoped. The
  private feed's generated time and every record modification time must also fall
  within `TRACELESS_EXTERNAL_INTELLIGENCE_CLOCK_SKEW_SECONDS` of the local retrieval
  clock or the complete batch is rejected before persistence/correlation.
- PostgreSQL deployments force tenant RLS for the non-owner API role. The tenant GUC
  is bound from the verified principal and restored for every new transaction,
  including workflows that commit mid-request. Project/system assignments are also
  enforced in repository queries. The worker role is `NOBYPASSRLS` and has no
  cross-tenant queue policy. Audited `SECURITY DEFINER` dispatch functions return only
  queue ID, organization ID and non-sensitive scheduling metadata; their non-login
  owner can access only the queue tables. The executor then binds the claimed tenant
  before any payload, domain or audit query. Isolate worker network access and
  credentials because dispatch necessarily reveals claimed organization IDs and job
  execution remains trusted. Dispatch eligibility uses `clock_timestamp()` inside the
  definer functions; callers cannot supply a future time to steal active leases or run
  connectors early. Custom sharing policy is not yet implemented.

Development/test mode may use `X-Actor` for audit attribution when no authentication
method is configured. That mode is not authentication and must not be exposed.

## Safe scanning contract

Active scanning is disabled by default and is limited to assets the operator owns or
is explicitly authorized to assess.

1. A named owner approves literal IP/CIDR scope, purpose, fixed profile and an expiry
   no more than 24 hours away. Hostnames remain unsupported to avoid DNS rebinding.
2. Targets are normalized and constrained to the approved scope. Public Internet
   targets require an explicit server policy change. Special and out-of-scope ranges
   are rejected.
3. The worker claims jobs with a lease, emits heartbeats, honors cancellation,
   recovers stale leases and has bounded attempts. Remote-agent signing and mTLS are
   still required before remote worker deployment.
4. Profiles contain reviewed arguments only. The API accepts no shell text, arbitrary
   flags, NSE scripts, credential attacks, brute force or exploitation instructions.
5. Host count, duration and process output are bounded. Immediately before execution,
   the worker reconstructs the scope and verifies its stored SHA-256 digest.
6. Results retain tool/profile versions, timestamps, evidence hashes and audit
   lineage. Raw evidence is disabled by default; enabled retention requires encryption
   and an explicit retention policy.
7. Nmap licensing and distribution require separate product/legal review.

An open port proves reachability from one vantage point at one time. It does not prove
Internet exposure, an intended business flow or an exploitable vulnerability.

## Key threats

| Threat | Current treatment | Remaining obligation |
|---|---|---|
| Identity theft | OIDC PKCE, local signature/claim validation, short-lived access token handling | Provider revocation/session policy and deployment monitoring |
| Cross-tenant access | Server-side organization/resource scope, forced RLS for non-owner API/worker roles, minimal definer dispatch, tenant-bound execution and negative PostgreSQL tests | Broader adversarial testing and optional split dispatcher/executor processes |
| Scan command injection | Fixed argv, `shell=False`, no caller flags/scripts | Keep profiles reviewed and worker isolated |
| Scope bypass | Literal targets validated at submission and execution | Deployment kill switch and network enforcement |
| Malicious imports | Global and parser-specific size/count bounds, safe XML, strict schemas | Quarantine/review UX and fuzzing for every new format |
| Connector SSRF, confused deputy and stale writers | Tenant-owned credential-free HTTPS URLs, nested tenant secret references, private process credentials bound to one organization, exact host allowlists, pre-network tenant rejection, no redirects, cumulative snapshot manifests and randomly fenced run/scheduler leases | DNS pinning/revalidation, restricted network egress and worst-case import lease sizing |
| Poisoned source time | Future-dated external intel revisions are quarantined and cannot replace current state | Analyst review/repair workflow and upstream clock monitoring |
| Worker compromise | Leases, bounded retries/cancel, unprivileged fixed scans, non-bypass tenant execution and minimal non-login definer dispatch | Separate dispatcher/executor processes where required, signed remote jobs and mTLS |
| Misleading findings | Durable evidence, provenance, lifecycle, candidate status, separate signals | Analyst review UX and calibrated matching metrics |
| Report leakage | Tenant-scoped generation, escaped PDF, neutralized CSV, frozen hash | Short-lived object downloads and external storage policy |
| Supply-chain compromise | Locked dependencies and out-of-process extension contracts | Signed artifacts, hardened images and isolated extension runner |

## Data semantics

Facts, imports, inferences, AI analysis and analyst decisions remain separate. CVSS is
severity, EPSS is a dated probability estimate, KEV is catalogue membership and
evidence confidence is uncertainty—not exploit likelihood. The risk policy keeps
these inputs separate and records its version and rationale.

## Production obligations

Before untrusted production exposure, a deployment still needs secret management,
TLS termination, restrictive CORS/hosts and egress, database encryption and backups,
centralized redacted logs, metrics/alerts, rate limiting, restore drills, hardened
images, SAST/dependency/secret/IaC checks and an independent penetration test.

Report suspected vulnerabilities privately to the repository owner. Do not include
production data, credentials or an unauthorized scan in a report.
