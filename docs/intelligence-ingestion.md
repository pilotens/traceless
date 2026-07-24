# Intelligence ingestion contract

Traceless accepts cyber-news, MISP-derived objects and vulnerability intelligence
through one canonical global feed. Source collectors remain independent: they map
their data to this contract and call:

```text
POST /api/v1/operational/intelligence/records/import
```

For the separately operated scraper/analysis program, Traceless can instead pull
cursor-paginated datapoints through an organization-scoped HTTPS connector. The
connector stores only a credential reference, binds persisted cursors to a feed
snapshot, verifies cumulative page/identity provenance across resumed calls and does
not contain scraping logic. An optional tenant interval is handled
by a separate scheduler process that calls the same pull service; a failure in one
tenant does not stop others. Run and schedule writes are protected by expiring,
randomly fenced leases. Its lifecycle, pagination and authentication contract is documented in
[external-intelligence-connector.md](external-intelligence-connector.md).

Private and external intelligence uses this canonical organization-scoped path and
must pass analyst review before correlation. There is no process-global,
system-scoped private-feed synchronization endpoint.

The global store is intentionally separate from a security system. The Omvärld UI
can therefore show unmatched news and intelligence. A deliberate correlation call
then evaluates current records against the latest completed scan of one system:

```text
POST /api/v1/operational/systems/{system_id}/intelligence/correlate
```

Correlation uses indexed observables instead of scanning every global record. It
selects candidates through current CVE findings, exact CPEs, CPE vendor/product
keys and normalized product terms, then applies the existing explainable match and
risk policies. No record becomes a system threat merely because it was ingested.

## Required envelope

```json
{
  "schema_version": "1.0",
  "feed_id": "internal-cyber-pipeline",
  "feed_version": "2026-07-18T12:00:00Z",
  "generated_at": "2026-07-18T12:00:00Z",
  "items": []
}
```

A request contains 1–1,000 items. Split larger exports into stable batches. Request
bodies remain subject to the API-wide size limit.

## Canonical record

The following example represents a cyber-news record analyzed by an internal AI:

```json
{
  "source_kind": "news",
  "provider": "internal-cyber-scraper",
  "external_id": "article-2026-0042",
  "record_type": "threat",
  "title": "Campaign targeting vulnerable Apache services",
  "summary": "A concise source-grounded summary.",
  "source_url": "https://news.example/article-2026-0042",
  "published_at": "2026-07-18T09:00:00Z",
  "modified_at": "2026-07-18T10:00:00Z",
  "retrieved_at": "2026-07-18T10:05:00Z",
  "severity": "high",
  "confidence": 0.88,
  "cve_ids": ["CVE-2099-12345"],
  "cpes": [],
  "affected_products": ["Apache httpd"],
  "mitre_attack_ids": ["T1190"],
  "indicators": [
    {"type": "domain", "value": "campaign.example", "role": "callback"},
    {"type": "file_sha256", "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "role": "artifact"}
  ],
  "tags": ["initial-access", "campaign"],
  "sectors": ["finance"],
  "regions": ["SE"],
  "markings": ["TLP:CLEAR"],
  "valid_from": "2026-07-18T09:00:00Z",
  "valid_until": null,
  "revoked": false,
  "raw_evidence": {
    "source_id": "article-2026-0042",
    "source_title": "Original source title",
    "source_excerpt": "Short evidence excerpt used for the analysis"
  },
  "ai_analysis": {
    "model_name": "internal-classifier",
    "model_version": "2026-07",
    "prompt_version": "3",
    "taxonomy_version": "2",
    "analyzed_at": "2026-07-18T10:04:00Z",
    "confidence": 0.88,
    "categories": ["initial-access"],
    "extracted_entities": {
      "products": ["Apache httpd"],
      "organizations": ["Example sector target"]
    },
    "rationale": "The product and technique are explicit in the evidence."
  },
  "vulnerability": null
}
```

`provider + external_id` is the stable deduplication identity; the provider part is
matched case-insensitively. A revision with an
older `modified_at` can never overwrite a newer record. Replaying an identical
revision is idempotent. Traceless calculates a SHA-256 hash for source evidence and
a separate hash for AI/normalized output; clients must not supply those hashes.
Every received revision is also appended to immutable provenance, including older,
identical and quarantined payloads. Unreasonable future source/feed/analysis times do
not update the canonical row; they remain reviewable with a clock-skew reason.

`raw_evidence` is limited to 256 KiB per record. Store large source objects in the
collector's controlled evidence store and send stable IDs, hashes, selected fields
and short excerpts. Do not copy entire copyrighted articles into this field by
default. Credentials, session tokens and personal data should not be included.

## Vulnerability record

A vulnerability record requires at least one CVE and structured signals with one
or more concrete CPE 2.3 names:

```json
{
  "source_kind": "vulnerability",
  "record_type": "vulnerability",
  "cve_ids": ["CVE-2099-12345"],
  "cpes": ["cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*"],
  "vulnerability": {
    "affected_cpes": ["cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*"],
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.72,
    "epss_percentile": 0.98,
    "cwe_ids": ["CWE-787"],
    "exploit_status": "active"
  }
}
```

The omitted common fields are still required. Generic feeds cannot set CISA KEV
membership. Traceless only applies `is_kev=true` through the configured official
CISA KEV adapter. An internal `exploit_status` remains provider evidence and is not
silently converted to KEV.

## Mapping the existing sources

| Existing data | Canonical mapping |
|---|---|
| Scraped cyber article | `source_kind=news`, usually `record_type=report` or `threat`; retain the original URL, publication/retrieval times and a bounded source excerpt. |
| MISP event/report | `source_kind=misp`; use the MISP UUID as `external_id`, preserve distribution/TLP markings, timestamps, tags, CVEs, ATT&CK techniques and affected products. |
| MISP indicator | `source_kind=misp`, `record_type=indicator`; retain validity/revocation fields and marking. Indicators are not interpreted as proof of compromise. |
| Vulnerability pipeline | `source_kind=vulnerability`, `record_type=vulnerability`; CVE and concrete affected CPEs are required for automatic service correlation. |
| AI classification | `ai_analysis`; always include model, prompt and taxonomy versions, analysis time and confidence. |

The producer should reject or quarantine a record when it cannot establish a stable
source identity or distinguish source fields from AI-derived fields. Product names
alone can produce lower-confidence candidates; exact CVE/CPE links are stronger.
Supported structured indicator types are `ipv4`, `ipv6`, `domain`, `url`,
`file_sha256` and `email`. IP/domain/URL host values can correlate with observed
asset addresses and hostnames only when the producer explicitly supplies role
`host` or `destination`; `unknown`, `source` and `callback` indicators do not create
an asset match. This prevents a MISP attacker/source IP from being mistaken for an
affected asset. Hash and email indicators remain global until a
separate endpoint, EDR or software source can supply defensible system evidence.

## Read API and UI behavior

The Omvärld UI uses the paginated endpoint:

```text
GET /api/v1/operational/intelligence/records
    ?source_kind=news
    &record_type=threat
    &query=Apache
    &limit=50
    &offset=0
```

Source/type filters use database indexes and all responses are paginated. Keyword
search currently covers title, summary, provider and external ID. A dedicated
PostgreSQL full-text index or external search module is the appropriate later
extension for very large free-text collections; it does not change the ingestion
contract or correlation keys.

The system correlation response reports records considered, CVE/service matches,
created findings, matched/created threats and risks. Re-running it is idempotent for
the current scan. Revoked or expired source records close their existing system risk
instead of disappearing from provenance.

## Security boundary

These are operational routes and use the same authentication boundary as scanning,
risk and reporting. Collectors should use a server-configured, organization-scoped
service identity rather than a human login; browser users use verified OIDC tokens.
Run high-volume collectors as separately deployed workers, keep credentials in their
secret store, and add deployment quotas and queue backpressure before high-volume
production use. Scanner identities are deliberately excluded from intelligence read
and import permissions.
