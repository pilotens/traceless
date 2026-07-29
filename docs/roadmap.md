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

## Milestone 3 — threat and contextual risk analysis (`in progress`)

Delivered: a versioned risk policy that keeps severity and exploitation signals distinct,
records its rationale and consumes analyst-verified exposure, reachability and control
effectiveness. First-class published business-context versions now add business owner,
capabilities, processes, data categories, regulations, RTO/RPO and a multidimensional
impact profile. Current risks can be explicitly reassessed against an exact published
context version and retain that version in their rationale.

The posture value remains a deterministic operational indicator, not an externally
calibrated security score.

Next: formal risk-assessment approval, STRIDE, ATT&CK/CAPEC/CWE rules, system-bound
attack paths, uncertainty calibration and policy administration.

## Milestone 4 — closed-loop governance (`in progress`)

Delivered: supplementary many-source risk evidence, persistent treatments with strategy,
owner, priority, SLA/deadline, approval, external work-item references, verification
criteria and residual-risk fields. Treatments cannot close without residual risk and
verification criteria. Named controls have immutable point-in-time design/operating
effectiveness assessments. System and portfolio views identify unowned and overdue work.

Analysis manifests freeze scan, architecture, published context, risk policy, risks and
control-assessment identities behind a governance decision.

Next: richer treatment state-transition policy, formal risk-owner acceptance, comments
and attachments, generic work-item synchronization, Jira as the first production adapter,
period comparisons and treatment effectiveness trends.

## Milestone 5 — reporting and decision support (`in progress`)

Delivered: distinct frozen management, technical and risk-register reports, selectable
sections, SHA-256 integrity, TLP handling and tenant-scoped durable rendering jobs.

Next: include treatment status, residual risk, governance coverage, decisions required,
period-over-period change and analysis-manifest references in management reports. Add
object storage and short-lived download URLs for high-volume deployments.

## Milestone 6 — modules (`in progress`)

Delivered: versioned manifest, compatibility/capability/permission validation and
out-of-process transport contracts.

Next: stop expanding the framework until one production connector uses it. Then add
signed packages, admin approval and an isolated runner only where justified.

## Milestone 7 — production hardening (`in progress`)

Delivered: forced tenant RLS for the API role, separate owner migration and runtime
roles, static unprivileged web serving, restrictive CSP/security headers, structured
redacted request logs and Compose image/health/OIDC smoke coverage.

Next: browser E2E, accessibility and visual-regression gates; parser fuzzing; restore,
load and air-gap tests; monitoring/SLO evidence; restricted egress; managed secrets;
signed production artifacts and an independent penetration test.

## Deferred until prerequisites exist

- Autonomous remediation is deferred until approved treatments, scoped credentials,
  change windows, rollback plans and independent safety controls exist.
- Production attack-path claims are deferred until approved architecture, explicit
  asset/component bindings and control evidence can ground every edge.
- Multiple parallel ticketing and SIEM adapters are deferred until the generic work-item
  and event contracts have been proven by one production integration.

No milestone is complete until normal, failure and partial states have automated
coverage and the documented verification commands pass in CI.
