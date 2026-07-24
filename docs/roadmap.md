# Roadmap

Status is evidence-based. `In progress` means implemented behavior exists but the
milestone still has explicit gaps.

## Milestone 0 — trustworthy product boundary (`in progress`)

Delivered: operational-only UI/API, PostgreSQL migrations, OIDC PKCE, local RS256
verification, four server-enforced roles, organization/project/system authorization,
forced non-owner PostgreSQL RLS, minimal definer worker dispatch, tenant-bound worker
execution, negative tenant tests, audit attribution and bounded requests.

Next: optional split dispatcher/executor roles, project sharing/custom roles, deployment
threat model and independent security review. A deterministic OpenAPI snapshot and generated frontend
contract are checked for drift in CI.

## Milestone 1 — durable assets, findings and topology (`in progress`)

Delivered: authorized discovery, leased scanner worker with heartbeat/retry/cancel,
Nmap/Naabu imports, stable assets/findings, evidence precedence, lifecycle transitions,
rerunnable correlation and separate manual/observed architecture streams. The editor
has immutable versions, concurrency protection, undo/redo and dirty-state warnings.

Next: formal asset/component bindings, merge/split review, multiple vantage points,
architecture publication and proposed-change workflows.

## Milestone 2 — vulnerability and threat intelligence (`in progress`)

Delivered: direct Nessus import, normalized external adapter contract, non-CVE and
unmatched observation retention, CISA KEV, FIRST EPSS, NVD, internal CTI, canonical
intelligence ingestion and a bounded pull-only connector for a separate scraper/AI
program. Tenant schedules, durable checkpoints, source revisions and isolated pull
workers are included.

Next: CVE List V5, range/applicability matching, CycloneDX/SBOM, OSV, additional
direct adapters and analyst matching queues.

## Milestone 3 — threat and risk analysis (`in progress`)

Delivered: a versioned preliminary risk policy that keeps severity and exploitation
signals distinct, records its rationale and can consume analyst-verified exposure,
reachability and control effectiveness from a versioned architecture. Verification
identity and time are server-derived. The UI labels the result as a decision-support
signal rather than a complete risk assessment.

Next: STRIDE, ATT&CK/CAPEC/CWE rules, attack paths, uncertainty calibration,
residual-risk treatment and policy administration.

## Milestone 4 — closed loop (`in progress`)

Delivered: durable finding/risk close/reopen behavior, distinct frozen management,
technical and risk-register reports, and tenant-scoped background jobs for normalized
or Nessus imports and report rendering. Jobs have idempotency, leases, heartbeat,
retry and cancellation.

Next: complete analysis manifests, treatment approvals, asynchronous high-volume
correlation, lineage UI, object storage and short-lived downloads.

## Milestone 5 — modules (`in progress`)

Delivered: versioned manifest, compatibility/capability/permission validation and
out-of-process transport contracts.

Next: signed packages, admin approval, isolated runner and one production-deployed
connector.

## Milestone 6 — production hardening (`in progress`)

Delivered: forced tenant RLS for the API role, separate owner migration and runtime
roles, static unprivileged web serving, restrictive CSP/security headers, structured
redacted request logs and Compose image/health/OIDC smoke coverage.

Next: optional split dispatcher/executor roles, restore/accessibility/load/air-gap tests,
monitoring and SLO evidence, restricted egress, managed secrets, Kubernetes/Helm where
justified and signed production artifacts.

No milestone is complete until normal, failure and partial states have automated
coverage and the documented verification commands pass in CI.
