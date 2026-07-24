# Publisher v2 delivery and trust boundary

## Trust bootstrap

Each customer credential binding pins the exact HTTPS origin and one or more Ed25519
public keys. The connector verifies the digest and signature before parsing JSON. The
well-known key set supports rotation discovery only; it is not an initial trust source.

## Full and delta delivery

The first request receives a full current projection. The terminal page returns a signed
`next_sync_token`. Later requests receive only changes through a frozen sequence boundary.
Entitlement narrowing or a feed-epoch change returns `mode=full` and
`reset_required=true`.

The customer performs a stable reconciliation rather than truncating its cache:

1. upsert present identities;
2. retain stable local record IDs and review lineage;
3. tombstone identities absent from the completed authoritative snapshot;
4. retire affected findings, threats and risks;
5. persist the next sync token only after the transaction commits.

## Publication and credentials

Imports stage by default. Reviewers must provide an explicit reason to publish or reject.
Automatic publication is disabled by default in production and requires an allowlist.
Failed import runs are retained with a terminal error status.

Credentials are installation-scoped, stored only as SHA-256 digests and may overlap
during rotation. An enabled installation cannot revoke its final active credential.

## Database

The publisher uses normalized accounts, installations, credentials, entitlements, import
runs, publication decisions, current projections and signing-key metadata. Delivery
sequences are PostgreSQL `BIGINT`. Revisions, changes, decisions and audit history are
protected from physical deletion; immutable event tables are also protected from update.

The feed role can read only authentication/entitlement and delivery projection tables. It
cannot read raw revisions, import runs, publication decisions or audit history.
