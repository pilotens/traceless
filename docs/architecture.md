# Architecture

## Direction

Traceless is a modular monolith with a React client, a typed FastAPI control plane
and PostgreSQL as the system of record. Scanner execution and extension modules are
out of process. The API is not a privileged scanner or a plugin host.

```mermaid
flowchart LR
    Browser["React + OIDC PKCE"] --> API["FastAPI control plane"]
    API --> DB["PostgreSQL"]
    Worker["Leased scanner worker"] --> DB
    Worker --> Scanner["Operator-installed Nmap"]
    Sources["External scraper / MISP / scanners / public feeds"] --> Adapters["Bounded adapters"]
    Adapters --> API
    API --> Reports["Frozen reports"]
```

The operational API and UI are the only product surfaces. Synthetic demo routes and
hard-coded portfolio views have been removed.

## Product hierarchy

`Organization → Project → SecuritySystem → Observation/Scan → Asset/Finding → Architecture/Threat/Risk → Report`

- An organization is the enforced request and data boundary.
- A project groups systems inside an organization.
- A security system is the environment, application or network area being assessed.
- Assets and findings have stable identities across observation runs, with first/last
  seen metadata and explicit lifecycle transitions.
- Editing architecture creates an immutable successor with optimistic concurrency.
- Reports freeze one coherent source view: PostgreSQL uses a single repeatable-read
  transaction, while local/test databases require matching consecutive source
  fingerprints. Inventory rows are anchored to the selected completed scan. The
  frozen risk register retains closed risks tied to retired threats; management
  priorities include only open risks in the current evidence set. A complete
  general-purpose analysis run manifest remains future work.

## Evidence and lifecycle

Imported scanner observations are retained even when they have no CVE or cannot yet
be matched. Correlation may be rerun after inventory changes. Evidence records carry
source, timestamps and strength so generic enrichment cannot silently replace
stronger scanner evidence. A later observation can close or reopen the same finding
and linked risk rather than creating an unrelated record.

The finding lifecycle is:

`open ↔ reopened → fixed | accepted | false_positive | out_of_scope`

Analyst decisions and source observations remain distinct audit events.

## Assets are not architecture components

| Concept | Meaning | Created by discovery? | Current rule |
|---|---|---:|---|
| Asset | Reconciled runtime entity | Yes | Stable identity plus observation history |
| Observed topology | Graph derived from one or more observations | Yes | Separate version stream |
| Architecture component | Intentional design object | No | Immutable manual versions |
| Proposed change | Difference suggested by evidence | Yes | Must not overwrite manual architecture |

A new scan never becomes the current manual architecture. Formal asset-to-component
binding review and published architecture approval are still pending.

## Identity and tenant boundary

OIDC access tokens are verified locally from operator-configured RS256 keys, issuer
and audience. The authenticated principal supplies one organization and a fixed
operational role set. A separately configured service principal supports machine
integrations. Request repositories filter organization-owned data and internal
workers must opt into an explicit unscoped repository.

Request repositories enforce organization plus explicit project/system assignments.
PostgreSQL adds forced tenant RLS for the non-owner API role; a Session hook restores
the transaction-local tenant context after every commit. The non-bypass worker role
cannot read any tenant queue directly without a tenant GUC. Five audited
`SECURITY DEFINER` functions, owned by a non-login role with access only to the three
queue tables, lock and return minimal dispatch headers. A claim carries the
organization identifier, and every worker session binds that tenant before reading or
writing queue payloads, systems, assets, findings, reports, intelligence or audit
data. Lease expiry and schedule eligibility use the database clock, never a
worker-supplied timestamp. Organization IDs are necessarily visible to the dispatcher,
so worker credentials remain a cross-tenant scheduling trust boundary. Project sharing
and custom roles remain future work.

## Intelligence boundary

Scraping is intentionally outside Traceless. A separately deployed program gathers
and analyzes sources, then exposes normalized cursor-paginated datapoints. Traceless
can pull bounded pages from one fixed, allowlisted HTTPS URL or receive the canonical
push contract. Source material and AI classification have separate hashes, versions,
timestamps and lifecycle states.

Official CISA KEV, FIRST EPSS and NVD inputs remain separate authoritative adapters.
Generic or AI-derived records cannot assert official KEV membership.

## Extension boundary

Modules communicate through versioned API/event contracts and run out of process.
The registry validates capabilities and permissions but never imports or executes
plugin code. NetBox is a bounded read-only connector whose snapshots remain
unreviewed until an analyst promotes a change.

## Remaining architectural work

- Asynchronous high-volume correlation and object-storage-backed job payloads. Large
  imports and report generation already use durable tenant-scoped jobs.
- Formal architecture publication, asset bindings and proposed-change review.
- Optional separate dispatcher/executor roles and project-sharing policy.
- Signed remote worker jobs and mTLS.
- Object storage, HA/restore evidence and production observability.
- STRIDE/ATT&CK rules, attack paths, controls and residual-risk workflows.
