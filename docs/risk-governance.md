# Closed-loop cyber-risk governance

Traceless separates technical observation, analytical inference, risk decision and treatment
execution. The governance workflow is:

```text
published business context
        +
current reviewed evidence
        ↓
contextual risk reassessment
        ↓
approved treatment decision
        ↓
owned action with SLA/deadline
        ↓
verification evidence
        ↓
residual-risk assessment
        ↓
formal closure
```

## First-class business context

Business context is versioned independently from the architecture drawing. A context version
contains the business owner, capabilities, processes, data categories, regulations, RTO/RPO and
impact dimensions for confidentiality, integrity, availability, financial impact, regulatory
impact, reputation and safety.

Only one version is published for a system. Publishing a successor supersedes the previous
published version without deleting it.

## Contextual reassessment

`POST /api/v1/operational/systems/{system_id}/risks/reassess`

The endpoint requires a published context version. It reassesses current open risks and records:

- the exact context version and owner;
- the complete multidimensional impact profile;
- the selected maximum business-impact band and dimensions;
- RTO/RPO and applicable regulations;
- the risk-policy version and all original technical/exploitation signals.

The process does not turn CTI confidence into exploit probability and does not treat a high
business impact as proof that exploitation is likely.

## Risk evidence

A risk retains its primary generated source for compatibility, while `risk_evidence_links` adds
zero or more supplementary links to findings, threats, architecture, controls, attack-chain
analyses or manual reviewed evidence. This permits a risk decision to cite several evidence types
without copying or merging their source records.

## Treatments

A treatment is a persistent work object with:

- strategy: mitigate, avoid, transfer or accept;
- owner and optional approver;
- priority, SLA/deadline and status;
- verification criteria;
- optional external work-item system, key and URL;
- decision history and server-derived approval/verification identity;
- residual likelihood, impact, score and level.

A treatment cannot be closed without verification criteria and a residual-risk assessment.
Closing a treatment does not silently delete source evidence.

## Controls

Controls are named implementations attached to a system. Assessments are immutable point-in-time
records with design effectiveness, operating effectiveness, result, evidence reference, assessor
and optional validity date. A single percentage is therefore a derived view, not the only stored
control information.

## Analysis manifests

An analysis manifest freezes the scan generation, architecture snapshot, published business
context, risk-policy version, risk IDs and control-assessment IDs used for one governance purpose.
The canonical component list is SHA-256 fingerprinted and idempotent for identical inputs.

## Governance coverage

Coverage is deliberately named a coverage indicator rather than a security score. It describes
whether a system has:

- published business context;
- active treatments for open risks;
- owners for those treatments;
- current assessments for registered controls.

It does not claim that the system is secure. Technical posture, data quality, evidence freshness
and residual risk remain separate measures.

## Tenant boundary

All new governance tables are system- or risk-scoped and receive forced PostgreSQL RLS policies.
Request access remains constrained by organization, project and system assignments. Writes require
analyst access and server-derived audit attribution.
