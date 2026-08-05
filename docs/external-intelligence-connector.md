# External intelligence pull connector

Traceless does not scrape websites. The separate collection/analysis program exposes
normalized datapoints over a read-only HTTPS API. An administrator first creates a
tenant-owned connector. The API accepts a credential reference, never the credential
value:

The Omvärld view exposes tenant configuration, schedule/checkpoint status, paginated
persisted run history and manual bounded synchronization. It also shows system findings
that require analyst review. New and changed records remain inert until an analyst
approves them; approval then queues correlation through the existing system job panel.

Tenant configuration, manual pull and review decisions require an organization-wide
admin or analyst identity (`project_ids=null` and `system_ids=null`). Resource-scoped
identities may read permitted intelligence and connector status, but the web client does
not expose tenant-wide mutation controls to them; the API enforces the same boundary.

```text
PUT /api/v1/operational/intelligence/connectors/external
Content-Type: application/json

{
  "endpoint": "https://intel-pipeline.example.test/v1/datapoints",
  "auth_scheme": "Bearer",
  "credential_reference": "tenant-feed-primary",
  "enabled": true,
  "sync_interval_seconds": 900
}
```

`sync_interval_seconds` is optional. `null` means manual-only; scheduled values are
bounded to 60 seconds through 30 days. Enabling a new schedule sets the first due
time to one interval after configuration. Disabling the connector clears its next
due time without deleting prior runs or checkpoints.

An administrator or analyst then starts a bounded pull with:

```text
POST /api/v1/operational/intelligence/sync/external
Content-Type: application/json

{"max_pages": 20}
```

The connector uses only `GET` against one configured URL. It never follows a URL
returned by the producer. It sends `limit` and, after the first page, the opaque
`cursor` as query parameters. Redirects are disabled.

## Producer response

```json
{
  "schema_version": "1.0",
  "feed_id": "separate-cyber-pipeline",
  "feed_version": "2026-07-21T08:00:00Z",
  "generated_at": "2026-07-21T08:00:00Z",
  "items": [
    {
      "status": "active",
      "status_changed_at": null,
      "status_reason": null,
      "record": {
        "source_kind": "news",
        "provider": "cyber-news-scraper",
        "external_id": "article-0042",
        "record_type": "threat",
        "title": "Campaign targeting exposed services",
        "summary": "A bounded, source-grounded summary.",
        "source_url": "https://publisher.example/article-0042",
        "published_at": "2026-07-21T06:00:00Z",
        "modified_at": "2026-07-21T06:30:00Z",
        "retrieved_at": "2026-07-21T06:35:00Z",
        "severity": "high",
        "confidence": 0.87,
        "cve_ids": ["CVE-2099-12345"],
        "cpes": [],
        "affected_products": ["Example Gateway"],
        "mitre_attack_ids": ["T1190"],
        "indicators": [],
        "tags": ["initial-access"],
        "sectors": ["finance"],
        "regions": ["SE"],
        "markings": ["TLP:CLEAR"],
        "valid_from": "2026-07-21T06:00:00Z",
        "valid_until": null,
        "revoked": false,
        "raw_evidence": {
          "source_id": "article-0042",
          "source_sha256": "producer-owned-source-digest",
          "excerpt": "Short evidence excerpt"
        },
        "ai_analysis": {
          "model_name": "internal-classifier",
          "model_version": "2026-07-20",
          "prompt_version": "4",
          "taxonomy_version": "3",
          "analyzed_at": "2026-07-21T06:40:00Z",
          "confidence": 0.87,
          "confidence_method": "calibrated classifier probability",
          "confidence_method_version": "2",
          "categories": ["initial-access"],
          "extracted_entities": {"products": ["Example Gateway"]},
          "rationale": "The affected product and exploit path are explicit."
        },
        "vulnerability": null
      }
    }
  ],
  "has_more": true,
  "next_cursor": "opaque-non-secret-cursor"
}
```

Every page in one pull must have identical `feed_id`, `feed_version` and
`generated_at`. A producer should implement snapshot or high-water-mark semantics so
the dataset cannot change halfway through pagination. An intermediate page must not
be empty. The final page returns `has_more=false` and `next_cursor=null`.

`provider + external_id` is the stable, case-insensitive identity. A page set must
not repeat an identity. The producer must update `modified_at` whenever source
evidence, AI analysis or lifecycle status changes. Replaying the same cursor range is
safe: the current canonical view is idempotent and older revisions cannot overwrite
newer ones. Every received version is nevertheless retained in an append-only
revision table with its raw evidence, canonical payload, source/analysis hashes,
feed snapshot and outcome (`applied`, `unchanged`, `superseded` or `quarantined`).

## Source lifecycle

Supported status values are `active`, `revoked` and `deleted`.

- `active` requires `record.revoked=false`.
- `revoked` and `deleted` require `record.revoked=true`, `status_changed_at` and a
  reason. `record.modified_at` must include that change.
- Deletion is a soft tombstone. Traceless does not destroy previously collected
  evidence, because doing so would break auditability. Both deleted and revoked
  records stop participating as active intelligence during correlation.
- A later, newer `active` revision can reopen a source record.

The connector preserves the producer's `raw_evidence` unchanged under
`raw_evidence.source`. It adds only a separate `source_lifecycle` object with status,
time, reason and a SHA-256 digest of the original source evidence. AI output remains
in `ai_analysis`; it never overwrites source evidence. Traceless also hashes the
stored source envelope and AI/normalized analysis independently.

Pulled AI results require model, model version, prompt version, taxonomy version,
analysis time, confidence method and confidence-method version. The canonical
record-level confidence must equal the AI confidence. A record without AI analysis
must omit record-level confidence; provider or analyst confidence needs a future
separately persisted provenance contract rather than an unattributed number.

## Configuration and security

```dotenv
TRACELESS_EXTERNAL_INTELLIGENCE_CREDENTIALS={"tenant-id":{"tenant-feed-primary":{"secret":"long-random-read-only-token","origin":"https://intel-pipeline.example.test"}}}
TRACELESS_INTELLIGENCE_ALLOWED_HOSTS=["www.cisa.gov","api.first.org","services.nvd.nist.gov","intel-pipeline.example.test"]
TRACELESS_EXTERNAL_INTELLIGENCE_CLOCK_SKEW_SECONDS=300
TRACELESS_EXTERNAL_INTELLIGENCE_STALE_RUN_SECONDS=3600
TRACELESS_EXTERNAL_INTELLIGENCE_HEARTBEAT_SECONDS=15
TRACELESS_EXTERNAL_INTELLIGENCE_WORKER_ID=external-intelligence-worker
TRACELESS_EXTERNAL_INTELLIGENCE_SCHEDULER_BATCH_SIZE=50
TRACELESS_EXTERNAL_INTELLIGENCE_SCHEDULE_CLAIM_SECONDS=300
TRACELESS_EXTERNAL_INTELLIGENCE_SCHEDULE_RETRY_SECONDS=300
```

`X-API-Key` is also supported as the authentication scheme. The URL must be
credential-free HTTPS with an exact allowlisted hostname and no query or fragment.
The secret map comes from the deployment secret store and is deliberately nested:
the outer key is the organization's exact `external_key`, and its value is another
object keyed by the exact connector `credential_reference`. Lookup is case-sensitive;
empty identifiers and case-variant duplicates are rejected at startup. This avoids
flat-key collisions when either identifier contains a colon. A tenant cannot select
another tenant's reference. Every secret is additionally pinned to one canonical HTTPS
origin (scheme, host and effective port); it cannot be sent to another allowlisted
recipient after a connector URL change. Each connector stores only its short
`credential_reference`. Tokens are never written to
the database, provenance, audit output or API responses. The producer should use a
read-only credential, rotate it, enforce rate limits and avoid secrets in cursors.
Network egress policy should independently restrict the configured hosts.

The page size, cumulative snapshot page count, cumulative snapshot record count,
response bytes and timeout are all bounded by `TRACELESS_EXTERNAL_INTELLIGENCE_*`
settings. The page and record limits continue across resumed calls; a producer that
still reports `has_more` at either ceiling is rejected rather than leaving an
unresumable checkpoint. If a smaller per-call page budget ends
before the source does, Traceless persists the opaque cursor together with
`feed_id`, `feed_version` and `generated_at`. The next call resumes automatically. A
caller-supplied cursor is rejected unless it exactly matches that checkpoint, and
every resumed page must match the bound snapshot. Accepted page digests and every
normalized `(provider, external_id)` identity are persisted with a snapshot UUID;
their cumulative counts and manifests must reproduce the checkpoint before resume.
This detects repeated identities across calls as well as corrupted checkpoint state.

`GET /api/v1/operational/intelligence/sync/external/status` exposes the latest durable
run, counts, snapshot metadata, safe schedule state and next due time, never the
cursor or credential. The connector configuration response likewise exposes only
the credential reference, interval and next due time. Completed snapshots clear the
checkpoint; partial and failed runs remain inspectable. `pages_fetched`,
`records_fetched`, `bytes_fetched` and `manifest_sha256` describe the full snapshot
through that run; `batch_pages_fetched`, `batch_records_fetched` and
`batch_bytes_fetched` identify only the current resumed call. Paginated history is
available from `GET /api/v1/operational/intelligence/sync/external/runs?limit=10&offset=0`.
The created/updated/unchanged/quarantined and source-lifecycle counters are
also batch outcomes, so their sum is checked against `batch_records_fetched`.

A completed pull creates or updates records in the tenant's `pending` review queue; it
does not correlate unapproved source data. `GET /intelligence/records?review_status=pending`
returns that queue. An analyst approves or rejects a record with
`PATCH /intelligence/records/{record_id}/review`. Approval automatically queues one
idempotent `intelligence_correlation` background job per eligible system. Rejection
requires a reason and queues the same bounded recalculation so a previously approved
revision cannot leave a stale threat or risk open. Repeating an unchanged review
decision is a no-op. Job status and cancellation use the ordinary tenant- and
resource-scoped jobs API.

For analyst-verified architecture risk context, verification identity and time are
derived from the authenticated principal and server clock. Clients provide the
environmental signal and evidence reference, but cannot choose the actor or timestamp.

Connector-row locking prevents overlapping pulls. Each run also has a
cryptographically random, persisted fencing token, heartbeat and lease expiry. Page
provenance, checkpoint changes, canonical imports, terminal state and failure state
commit only through a conditional update for the still-current, unexpired token.
Every accepted page and the pre-import boundary renew the heartbeat. A reclaimer
uses the lease expiry—not the run start time—and atomically invalidates the old token
before a new run starts. `TRACELESS_EXTERNAL_INTELLIGENCE_STALE_RUN_SECONDS` must be
longer than the upstream HTTP timeout plus a heartbeat interval and should also
cover the deployment's worst-case bounded canonical import phase. PostgreSQL workers
also renew the run and schedule claims independently every
`TRACELESS_EXTERNAL_INTELLIGENCE_HEARTBEAT_SECONDS` while work is in flight. SQLite
is development/test-only and uses the committed phase-boundary renewals to avoid its
database-wide writer-lock limitations.

Run scheduled pulls in a separate process against the same database:

```bash
traceless-external-intelligence-worker --poll --poll-seconds 5
# Or process one bounded due batch, for example from an external scheduler:
traceless-external-intelligence-worker --once
```

The local Compose stack includes this as the idle
`external-intelligence-worker` service. It depends on the healthy API (and therefore
the migrated PostgreSQL database), uses `TRACELESS_AUTO_CREATE_SCHEMA=false`, and
starts with `traceless-external-intelligence-worker --poll`. Supply
`TRACELESS_EXTERNAL_INTELLIGENCE_CREDENTIALS` and any custom
`TRACELESS_INTELLIGENCE_ALLOWED_HOSTS` through the operator environment or deployment
secret store before `docker compose up`; never add credential values to this file or
the repository. With no enabled connector carrying a non-null schedule, the service
only polls and remains idle. It invokes the bounded pull connector and never performs
website scraping; collection and scraping remain entirely in the separate program.

The worker claims only enabled, due tenant connectors with a short persisted lease
before network I/O. The same token is heartbeated after the run starts, after every
accepted page and before canonical import; renewal covers at least the run lease.
A crash before the pull therefore delays work only until that
lease expires, not for the tenant's full interval. On success the next due time is
the completion time plus the tenant interval; partial snapshots become due again
immediately but polling remains rate-limited, and failures use the bounded retry
delay. The worker calls the same `pull_external_intelligence` service used by the
API; it contains no collector or scraper. Persisted cursor checkpoints resume
partial snapshots. Schedule claims also carry a random fencing token, so an expired
scheduler cannot overwrite the next due time after a second worker reclaims it.
Connector/run locking prevents overlap and recovers stale runs. A failure in one organization is isolated and does not stop other due
organizations in the batch. The worker's HTTP client ignores proxy environment
variables and refuses redirects.

Failures mark the durable run as failed only while that worker still owns its lease.
No partial canonical intel update is committed, but fetched page digests and item
identities remain as failed-run provenance and are excluded from the accepted
checkpoint manifests. Source, feed and AI
timestamps beyond the configured skew are stored as quarantined revisions and cannot
replace the current record. The API never echoes a possibly sensitive upstream body.
