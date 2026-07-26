/* eslint-disable */
/* tslint:disable */
// @ts-nocheck
/*
 * ---------------------------------------------------------------
 * ## THIS FILE WAS GENERATED VIA SWAGGER-TYPESCRIPT-API        ##
 * ##                                                           ##
 * ## AUTHOR: acacode                                           ##
 * ## SOURCE: https://github.com/acacode/swagger-typescript-api ##
 * ---------------------------------------------------------------
 */

/**
 * AiAnalysis
 * Derived AI output. It is versioned and never replaces source evidence.
 */
export interface AiAnalysis {
  /**
   * Analyzed At
   * @format date-time
   */
  analyzed_at: string;
  /**
   * Categories
   * @maxItems 50
   */
  categories?: string[];
  /**
   * Confidence
   * @min 0
   * @max 1
   */
  confidence: number;
  /** Confidence Method */
  confidence_method?: string | null;
  /** Confidence Method Version */
  confidence_method_version?: string | null;
  /** Extracted Entities */
  extracted_entities?: Record<string, string[]>;
  /**
   * Model Name
   * @minLength 2
   * @maxLength 200
   */
  model_name: string;
  /** Model Version */
  model_version?: string | null;
  /**
   * Prompt Version
   * @minLength 1
   * @maxLength 120
   */
  prompt_version: string;
  /** Rationale */
  rationale?: string | null;
  /**
   * Taxonomy Version
   * @minLength 1
   * @maxLength 120
   */
  taxonomy_version: string;
}

/** ApiRootResponse */
export interface ApiRootResponse {
  /**
   * Api Version
   * @default "v1"
   */
  api_version?: "v1";
  /**
   * Authentication
   * @default "oidc_or_scoped_service_key"
   */
  authentication?: "oidc_or_scoped_service_key";
  /**
   * Data Mode
   * @default "persistent_operational"
   */
  data_mode?: "persistent_operational";
  /**
   * External Collection
   * @default "normalized_pull_connector"
   */
  external_collection?: "normalized_pull_connector";
  /**
   * Name
   * @default "Traceless API"
   */
  name?: string;
  /**
   * Rbac Implemented
   * @default true
   */
  rbac_implemented?: true;
  /**
   * Tenant Isolation Implemented
   * @default true
   */
  tenant_isolation_implemented?: true;
  /** Version */
  version: string;
}

/** ArchitectureEdgeInput */
export interface ArchitectureEdgeInput {
  /** Encrypted */
  encrypted?: boolean | null;
  /**
   * Id
   * @minLength 1
   * @maxLength 120
   * @pattern ^[A-Za-z0-9:._/-]+$
   */
  id: string;
  /** Label */
  label?: string | null;
  /** Properties */
  properties?: Record<string, any>;
  /** Protocol */
  protocol?: string | null;
  /**
   * Source
   * @minLength 1
   * @maxLength 120
   */
  source: string;
  /**
   * Target
   * @minLength 1
   * @maxLength 120
   */
  target: string;
}

/** ArchitectureGraphInput */
export interface ArchitectureGraphInput {
  /**
   * Edges
   * @maxItems 2000
   */
  edges?: ArchitectureEdgeInput[];
  /**
   * Nodes
   * @maxItems 500
   */
  nodes?: ArchitectureNodeInput[];
  /**
   * Publication State
   * @default "draft"
   */
  publication_state?: "draft";
  /**
   * Risk Contexts
   * @maxItems 500
   */
  risk_contexts?: ArchitectureRiskContextInput[];
  /**
   * Schema Version
   * @default "1.0"
   */
  schema_version?: "1.0";
  /**
   * Warning
   * @maxLength 1000
   * @default "Manually edited architecture. Components, trust boundaries and data flows require review before the model is published."
   */
  warning?: string;
  /**
   * Zones
   * @maxItems 100
   */
  zones?: ArchitectureZoneInput[];
}

/** ArchitectureNodeInput */
export interface ArchitectureNodeInput {
  /**
   * Id
   * @minLength 1
   * @maxLength 120
   * @pattern ^[A-Za-z0-9:._/-]+$
   */
  id: string;
  /** Kind */
  kind:
    | "asset"
    | "service"
    | "server"
    | "database"
    | "user"
    | "security_control"
    | "gateway"
    | "queue"
    | "application"
    | "cloud"
    | "network"
    | "other";
  /**
   * Name
   * @minLength 1
   * @maxLength 160
   */
  name: string;
  position: ArchitecturePosition;
  /** Properties */
  properties?: Record<string, any>;
  /**
   * Provenance
   * @default "manual"
   */
  provenance?: "manual" | "observed" | "imported";
  /** Zone Id */
  zone_id?: string | null;
}

/** ArchitecturePosition */
export interface ArchitecturePosition {
  /**
   * X
   * @min -100000
   * @max 100000
   */
  x: number;
  /**
   * Y
   * @min -100000
   * @max 100000
   */
  y: number;
}

/**
 * ArchitectureRiskContextInput
 * Analyst-verified environmental context used by the risk policy.
 */
export interface ArchitectureRiskContextInput {
  /**
   * Asset Id
   * @format uuid
   */
  asset_id: string;
  /** Control Effectiveness */
  control_effectiveness?: number | null;
  /**
   * Evidence Reference
   * @minLength 2
   * @maxLength 1000
   */
  evidence_reference: string;
  /**
   * Exposure
   * @default "unknown"
   */
  exposure?: "external" | "internal" | "isolated" | "unknown";
  /** Reachable */
  reachable?: boolean | null;
  /** Service Id */
  service_id?: string | null;
}

/** ArchitectureSnapshotView */
export interface ArchitectureSnapshotView {
  /** Base Snapshot Id */
  base_snapshot_id: string | null;
  /** Change Note */
  change_note: string;
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /** Created By */
  created_by: string;
  /** Graph */
  graph: Record<string, any>;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Layer */
  layer: "manual" | "observed" | "proposal";
  /** Source Scan Id */
  source_scan_id: string | null;
  /** Source Type */
  source_type: "scan" | "manual" | "import";
  /** Status */
  status: "draft" | "published" | "superseded";
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /** Title */
  title: string;
  /**
   * Version
   * @min 1
   */
  version: number;
}

/** ArchitectureVersionCreate */
export interface ArchitectureVersionCreate {
  /** Base Snapshot Id */
  base_snapshot_id?: string | null;
  /**
   * Change Note
   * @maxLength 2000
   * @default ""
   */
  change_note?: string;
  graph: ArchitectureGraphInput;
  /**
   * Title
   * @minLength 2
   * @maxLength 160
   */
  title: string;
}

/** ArchitectureZoneInput */
export interface ArchitectureZoneInput {
  /**
   * Id
   * @minLength 1
   * @maxLength 120
   * @pattern ^[A-Za-z0-9:._/-]+$
   */
  id: string;
  /**
   * Name
   * @minLength 1
   * @maxLength 160
   */
  name: string;
  /**
   * Trust Boundary
   * @default "unconfirmed"
   */
  trust_boundary?:
    | "unconfirmed"
    | "external"
    | "untrusted"
    | "restricted"
    | "trusted";
}

/** AssetSourceSnapshotDetail */
export interface AssetSourceSnapshotDetail {
  /**
   * Manifest Sha256
   * @pattern ^[a-f0-9]{64}$
   */
  manifest_sha256: string;
  /** Approval State */
  approval_state: "unreviewed_source_snapshot";
  /**
   * Completed At
   * @format date-time
   */
  completed_at: string;
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Page Count
   * @min 0
   */
  page_count: number;
  /** Pages */
  pages: Record<string, any>[];
  /** Provider */
  provider: string;
  /**
   * Record Count
   * @min 0
   */
  record_count: number;
  /** Record Counts */
  record_counts: Record<string, number>;
  /** Records */
  records: Record<string, any>[];
  /** Source Base Url */
  source_base_url: string;
  /**
   * Started At
   * @format date-time
   */
  started_at: string;
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /**
   * Warning
   * @default "Source observations are unreviewed and do not modify an approved architecture."
   */
  warning?: string;
}

/** AssetSourceSnapshotSummary */
export interface AssetSourceSnapshotSummary {
  /**
   * Manifest Sha256
   * @pattern ^[a-f0-9]{64}$
   */
  manifest_sha256: string;
  /** Approval State */
  approval_state: "unreviewed_source_snapshot";
  /**
   * Completed At
   * @format date-time
   */
  completed_at: string;
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Page Count
   * @min 0
   */
  page_count: number;
  /** Provider */
  provider: string;
  /**
   * Record Count
   * @min 0
   */
  record_count: number;
  /** Record Counts */
  record_counts: Record<string, number>;
  /** Source Base Url */
  source_base_url: string;
  /**
   * Started At
   * @format date-time
   */
  started_at: string;
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
}

/** AssetView */
export interface AssetView {
  /**
   * First Seen At
   * @format date-time
   */
  first_seen_at: string;
  /** Hostname */
  hostname: string | null;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Inventory Status */
  inventory_status: "current" | "unobserved" | "stale";
  /**
   * Last Seen At
   * @format date-time
   */
  last_seen_at: string;
  /** Mac Address */
  mac_address: string | null;
  /**
   * Observation Count
   * @min 1
   */
  observation_count: number;
  /** Os Accuracy */
  os_accuracy: number | null;
  /** Os Family */
  os_family: string | null;
  /** Primary Ip */
  primary_ip: string;
  /**
   * Source Scan Id
   * @format uuid
   */
  source_scan_id: string;
  /** State */
  state: string;
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
}

/** BackgroundJobEnqueueResult */
export interface BackgroundJobEnqueueResult {
  /** Idempotent Replay */
  idempotent_replay: boolean;
  job: BackgroundJobView;
}

/** BackgroundJobList */
export interface BackgroundJobList {
  /** Items */
  items: BackgroundJobView[];
  /**
   * Limit
   * @min 1
   * @max 200
   */
  limit: number;
  /**
   * Offset
   * @min 0
   */
  offset: number;
  /**
   * Total
   * @min 0
   */
  total: number;
}

/** BackgroundJobRetryRequest */
export interface BackgroundJobRetryRequest {
  /**
   * Reason
   * @minLength 3
   * @maxLength 2000
   */
  reason: string;
}

/** BackgroundJobView */
export interface BackgroundJobView {
  /**
   * Payload Sha256
   * @pattern ^[a-f0-9]{64}$
   */
  payload_sha256: string;
  /**
   * Attempt Count
   * @min 0
   */
  attempt_count: number;
  /**
   * Available At
   * @format date-time
   */
  available_at: string;
  /** Cancel Requested At */
  cancel_requested_at: string | null;
  /** Completed At */
  completed_at: string | null;
  /** Error Code */
  error_code: string | null;
  /** Error Message */
  error_message: string | null;
  /** Heartbeat At */
  heartbeat_at: string | null;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Job Type */
  job_type:
    | "intelligence_correlation"
    | "normalized_vulnerability_import"
    | "report_generation";
  /** Lease Expires At */
  lease_expires_at: string | null;
  /**
   * Max Attempts
   * @min 1
   * @max 10
   */
  max_attempts: number;
  /**
   * Organization Id
   * @format uuid
   */
  organization_id: string;
  /**
   * Payload Schema Version
   * @min 1
   */
  payload_schema_version: number;
  /**
   * Requested At
   * @format date-time
   */
  requested_at: string;
  /** Requested By */
  requested_by: string;
  /** Result */
  result: Record<string, any>;
  /** Result Resource Id */
  result_resource_id: string | null;
  /** Result Resource Type */
  result_resource_type: string | null;
  /** Started At */
  started_at: string | null;
  /** Status */
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
}

/** CanonicalIntelFeed */
export interface CanonicalIntelFeed {
  /**
   * Feed Id
   * @minLength 2
   * @maxLength 120
   */
  feed_id: string;
  /**
   * Feed Version
   * @minLength 1
   * @maxLength 120
   */
  feed_version: string;
  /**
   * Generated At
   * @format date-time
   */
  generated_at: string;
  /**
   * Items
   * @maxItems 1000
   * @minItems 1
   */
  items: CanonicalIntelRecord[];
  /**
   * Schema Version
   * @default "1.0"
   */
  schema_version?: "1.0";
}

/**
 * CanonicalIntelRecord
 * One normalized record from a scraper, MISP or vulnerability pipeline.
 */
export interface CanonicalIntelRecord {
  /**
   * Affected Products
   * @maxItems 100
   */
  affected_products?: string[];
  ai_analysis?: AiAnalysis | null;
  /** Confidence */
  confidence?: number | null;
  /**
   * Cpes
   * @maxItems 100
   */
  cpes?: string[];
  /**
   * Cve Ids
   * @maxItems 100
   */
  cve_ids?: string[];
  /**
   * External Id
   * @minLength 2
   * @maxLength 160
   */
  external_id: string;
  /**
   * Indicators
   * @maxItems 500
   */
  indicators?: IndicatorObservable[];
  /**
   * Markings
   * @maxItems 50
   */
  markings?: string[];
  /**
   * Mitre Attack Ids
   * @maxItems 100
   */
  mitre_attack_ids?: string[];
  /**
   * Modified At
   * @format date-time
   */
  modified_at: string;
  /**
   * Provider
   * @minLength 2
   * @maxLength 100
   */
  provider: string;
  /** Published At */
  published_at?: string | null;
  /** Raw Evidence */
  raw_evidence: Record<string, any>;
  /** Record Type */
  record_type:
    | "report"
    | "threat"
    | "vulnerability"
    | "indicator"
    | "campaign"
    | "malware"
    | "threat_actor";
  /**
   * Regions
   * @maxItems 100
   */
  regions?: string[];
  /**
   * Retrieved At
   * @format date-time
   */
  retrieved_at: string;
  /**
   * Revoked
   * @default false
   */
  revoked?: boolean;
  /**
   * Sectors
   * @maxItems 100
   */
  sectors?: string[];
  /** Severity */
  severity?: "low" | "medium" | "high" | "critical" | null;
  /** Source Kind */
  source_kind: "news" | "misp" | "vulnerability" | "other";
  /** Source Url */
  source_url?: string | null;
  /**
   * Summary
   * @minLength 3
   * @maxLength 20000
   */
  summary: string;
  /**
   * Tags
   * @maxItems 100
   */
  tags?: string[];
  /**
   * Title
   * @minLength 3
   * @maxLength 500
   */
  title: string;
  /** Valid From */
  valid_from?: string | null;
  /** Valid Until */
  valid_until?: string | null;
  vulnerability?: VulnerabilitySignals | null;
}

/** CurrentPrincipalResponse */
export interface CurrentPrincipalResponse {
  /** Actor */
  actor: string;
  /** Authentication Method */
  authentication_method: "local" | "api_key" | "oidc" | "worker";
  /** Capabilities */
  capabilities: (
    | "read_operational"
    | "analyze"
    | "manage_scans"
    | "ingest_intelligence"
    | "administer"
  )[];
  /**
   * Organization Id
   * @format uuid
   */
  organization_id: string;
  /** Organization Name */
  organization_name: string;
  /** Project Ids */
  project_ids: string[] | null;
  /** Roles */
  roles: ("admin" | "analyst" | "viewer" | "scanner")[];
  /** Subject */
  subject: string;
  /** System Ids */
  system_ids: string[] | null;
}

/** ExternalIntelligenceCheckpointView */
export interface ExternalIntelligenceCheckpointView {
  /** Cursor Sha256 */
  cursor_sha256: string;
  /**
   * Identity Manifest Sha256
   * @pattern ^[0-9a-f]{64}$
   */
  identity_manifest_sha256: string;
  /**
   * Page Manifest Sha256
   * @pattern ^[0-9a-f]{64}$
   */
  page_manifest_sha256: string;
  /**
   * Bytes Completed
   * @min 1
   */
  bytes_completed: number;
  /**
   * Feed Generated At
   * @format date-time
   */
  feed_generated_at: string;
  /** Feed Id */
  feed_id: string;
  /** Feed Version */
  feed_version: string;
  /**
   * Pages Completed
   * @min 1
   */
  pages_completed: number;
  /**
   * Records Completed
   * @min 0
   */
  records_completed: number;
  /**
   * Snapshot Id
   * @format uuid
   */
  snapshot_id: string;
  /**
   * Updated At
   * @format date-time
   */
  updated_at: string;
}

/**
 * ExternalIntelligenceConnectorUpdate
 * Tenant-owned configuration; the referenced credential stays outside the DB.
 */
export interface ExternalIntelligenceConnectorUpdate {
  /**
   * Auth Scheme
   * @default "Bearer"
   */
  auth_scheme?: "Bearer" | "X-API-Key";
  /**
   * Credential Reference
   * @minLength 1
   * @maxLength 160
   * @pattern ^[A-Za-z0-9][A-Za-z0-9._:/-]*$
   */
  credential_reference: string;
  /**
   * Enabled
   * @default true
   */
  enabled?: boolean;
  /**
   * Endpoint
   * @minLength 12
   * @maxLength 2000
   */
  endpoint: string;
  /**
   * Sync Interval Seconds
   * Null keeps the connector in manual-only mode.
   */
  sync_interval_seconds?: number | null;
}

/** ExternalIntelligenceConnectorView */
export interface ExternalIntelligenceConnectorView {
  /** Auth Scheme */
  auth_scheme: "Bearer" | "X-API-Key";
  /**
   * Config Version
   * @min 1
   */
  config_version: number;
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /** Created By */
  created_by: string;
  /** Credential Reference */
  credential_reference: string;
  /** Enabled */
  enabled: boolean;
  /** Endpoint */
  endpoint: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Name */
  name: string;
  /** Next Sync At */
  next_sync_at: string | null;
  /**
   * Organization Id
   * @format uuid
   */
  organization_id: string;
  /** Sync Interval Seconds */
  sync_interval_seconds: number | null;
  /**
   * Updated At
   * @format date-time
   */
  updated_at: string;
}

/**
 * ExternalIntelligencePullRequest
 * An optional opaque continuation cursor and a bounded per-call page budget.
 */
export interface ExternalIntelligencePullRequest {
  /** Cursor */
  cursor?: string | null;
  /** Max Pages */
  max_pages?: number | null;
}

/** ExternalIntelligencePullResult */
export interface ExternalIntelligencePullResult {
  /**
   * Manifest Sha256
   * @pattern ^[0-9a-f]{64}$
   */
  manifest_sha256: string;
  /**
   * Active
   * @min 0
   */
  active: number;
  /**
   * Batch Bytes Fetched
   * @min 1
   */
  batch_bytes_fetched: number;
  /**
   * Batch Pages Fetched
   * @min 1
   */
  batch_pages_fetched: number;
  /**
   * Batch Records Fetched
   * @min 0
   */
  batch_records_fetched: number;
  /**
   * Bytes Fetched
   * @min 1
   */
  bytes_fetched: number;
  /** Complete */
  complete: boolean;
  /**
   * Correlation Jobs Queued
   * @min 0
   * @default 0
   */
  correlation_jobs_queued?: number;
  /**
   * Created
   * @min 0
   */
  created: number;
  /**
   * Deleted
   * @min 0
   */
  deleted: number;
  /** Feed Id */
  feed_id: string;
  /** Feed Version */
  feed_version: string;
  /** Next Cursor */
  next_cursor?: string | null;
  /**
   * Pages Fetched
   * @min 1
   */
  pages_fetched: number;
  /**
   * Quarantined
   * @min 0
   */
  quarantined: number;
  /**
   * Records Fetched
   * @min 0
   */
  records_fetched: number;
  /**
   * Revoked
   * @min 0
   */
  revoked: number;
  /**
   * Run Id
   * @format uuid
   */
  run_id: string;
  /**
   * Unchanged
   * @min 0
   */
  unchanged: number;
  /**
   * Updated
   * @min 0
   */
  updated: number;
  /** Warnings */
  warnings?: string[];
}

/** ExternalIntelligenceSyncRunList */
export interface ExternalIntelligenceSyncRunList {
  /** Items */
  items: ExternalIntelligenceSyncRunView[];
  /**
   * Limit
   * @min 1
   * @max 200
   */
  limit: number;
  /**
   * Offset
   * @min 0
   */
  offset: number;
  /**
   * Total
   * @min 0
   */
  total: number;
}

/** ExternalIntelligenceSyncRunView */
export interface ExternalIntelligenceSyncRunView {
  /** Manifest Sha256 */
  manifest_sha256: string | null;
  /** Next Cursor Sha256 */
  next_cursor_sha256: string | null;
  /** Start Cursor Sha256 */
  start_cursor_sha256: string | null;
  /**
   * Batch Bytes Fetched
   * @min 0
   */
  batch_bytes_fetched: number;
  /**
   * Batch Pages Fetched
   * @min 0
   */
  batch_pages_fetched: number;
  /**
   * Batch Records Fetched
   * @min 0
   */
  batch_records_fetched: number;
  /**
   * Bytes Fetched
   * @min 0
   */
  bytes_fetched: number;
  /** Completed At */
  completed_at: string | null;
  /**
   * Connector Id
   * @format uuid
   */
  connector_id: string;
  /**
   * Created Count
   * @min 0
   */
  created_count: number;
  /** Error Code */
  error_code: string | null;
  /** Feed Generated At */
  feed_generated_at: string | null;
  /** Feed Id */
  feed_id: string | null;
  /** Feed Version */
  feed_version: string | null;
  /**
   * Heartbeat At
   * @format date-time
   */
  heartbeat_at: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Lease Expires At */
  lease_expires_at: string | null;
  /**
   * Pages Fetched
   * @min 0
   */
  pages_fetched: number;
  /**
   * Quarantined Count
   * @min 0
   */
  quarantined_count: number;
  /**
   * Records Fetched
   * @min 0
   */
  records_fetched: number;
  /**
   * Snapshot Id
   * @format uuid
   */
  snapshot_id: string;
  /**
   * Started At
   * @format date-time
   */
  started_at: string;
  /** Started By */
  started_by: string;
  /** Status */
  status: "running" | "partial" | "completed" | "failed" | "quarantined";
  /**
   * Unchanged Count
   * @min 0
   */
  unchanged_count: number;
  /**
   * Updated Count
   * @min 0
   */
  updated_count: number;
}

/** ExternalIntelligenceSyncStatus */
export interface ExternalIntelligenceSyncStatus {
  checkpoint?: ExternalIntelligenceCheckpointView | null;
  /** Config Version */
  config_version?: number | null;
  /** Configured */
  configured: boolean;
  /** Connector Id */
  connector_id?: string | null;
  /**
   * Credential Available
   * @default false
   */
  credential_available?: boolean;
  /**
   * Enabled
   * @default false
   */
  enabled?: boolean;
  /** Endpoint */
  endpoint?: string | null;
  latest_run?: ExternalIntelligenceSyncRunView | null;
  /** Next Sync At */
  next_sync_at?: string | null;
  /**
   * Schedule State
   * @default "manual"
   */
  schedule_state?: "manual" | "disabled" | "scheduled" | "due";
  /** Sync Interval Seconds */
  sync_interval_seconds?: number | null;
}

/** FindingEvidenceView */
export interface FindingEvidenceView {
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /** Evidence Key */
  evidence_key: string;
  /** External Id */
  external_id: string;
  /**
   * Finding Id
   * @format uuid
   */
  finding_id: string;
  /**
   * First Seen At
   * @format date-time
   */
  first_seen_at: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Last Seen At
   * @format date-time
   */
  last_seen_at: string;
  /** Lifecycle Status */
  lifecycle_status:
    | "open"
    | "fixed"
    | "accepted"
    | "false_positive"
    | "out_of_scope"
    | "reopened";
  /**
   * Observation Count
   * @min 1
   */
  observation_count: number;
  /** Observation Id */
  observation_id: string | null;
  /** Payload */
  payload: Record<string, any>;
  /** Source Kind */
  source_kind: string;
  /** Source Name */
  source_name: string;
  /**
   * Strength
   * @min 0
   * @max 100
   */
  strength: number;
  /**
   * Updated At
   * @format date-time
   */
  updated_at: string;
}

/** FindingLifecycleUpdate */
export interface FindingLifecycleUpdate {
  /** Lifecycle Status */
  lifecycle_status:
    | "open"
    | "fixed"
    | "accepted"
    | "false_positive"
    | "out_of_scope"
    | "reopened";
  /**
   * Reason
   * @minLength 3
   * @maxLength 2000
   */
  reason: string;
}

/** FindingSummaryView */
export interface FindingSummaryView {
  /** Asset Id */
  asset_id: string | null;
  /** Cve Id */
  cve_id: string | null;
  /** Cvss Score */
  cvss_score: number | null;
  /** Epss Score */
  epss_score: number | null;
  /** Finding Type */
  finding_type: "vulnerability" | "misconfiguration" | "informational";
  /**
   * First Seen At
   * @format date-time
   */
  first_seen_at: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Inventory Status */
  inventory_status: "current" | "unobserved" | "stale" | "unknown";
  /** Is Kev */
  is_kev: boolean;
  /** Kev Due Date */
  kev_due_date: string | null;
  /**
   * Last Seen At
   * @format date-time
   */
  last_seen_at: string;
  /** Lifecycle Status */
  lifecycle_status:
    | "open"
    | "fixed"
    | "accepted"
    | "false_positive"
    | "out_of_scope"
    | "reopened";
  /**
   * Occurrence Count
   * @min 1
   */
  occurrence_count: number;
  /**
   * Primary Evidence Strength
   * @min 0
   * @max 100
   */
  primary_evidence_strength: number;
  /** Resolved At */
  resolved_at: string | null;
  /** Service Id */
  service_id: string | null;
  /** Status */
  status: "candidate" | "likely" | "confirmed" | "false_positive";
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /** Title */
  title: string;
}

/** FindingView */
export interface FindingView {
  /** Asset Id */
  asset_id: string | null;
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /** Cve Id */
  cve_id: string | null;
  /** Cvss Score */
  cvss_score: number | null;
  /** Cvss Vector */
  cvss_vector: string | null;
  /** Epss Percentile */
  epss_percentile: number | null;
  /** Epss Score */
  epss_score: number | null;
  /** Finding Type */
  finding_type: "vulnerability" | "misconfiguration" | "informational";
  /**
   * First Seen At
   * @format date-time
   */
  first_seen_at: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Inventory Status */
  inventory_status: "current" | "unobserved" | "stale" | "unknown";
  /** Is Kev */
  is_kev: boolean;
  /** Kev Due Date */
  kev_due_date: string | null;
  /**
   * Last Seen At
   * @format date-time
   */
  last_seen_at: string;
  /** Lifecycle Status */
  lifecycle_status:
    | "open"
    | "fixed"
    | "accepted"
    | "false_positive"
    | "out_of_scope"
    | "reopened";
  /**
   * Match Confidence
   * @min 0
   * @max 1
   */
  match_confidence: number;
  /** Match Reason */
  match_reason: string;
  /**
   * Occurrence Count
   * @min 1
   */
  occurrence_count: number;
  /**
   * Primary Evidence Strength
   * @min 0
   * @max 100
   */
  primary_evidence_strength: number;
  /** Resolved At */
  resolved_at: string | null;
  /** Scan Job Id */
  scan_job_id: string | null;
  /** Service Id */
  service_id: string | null;
  /** Sources */
  sources: Record<string, any>[];
  /** Stable Key */
  stable_key: string;
  /** Status */
  status: "candidate" | "likely" | "confirmed" | "false_positive";
  /**
   * Status Updated At
   * @format date-time
   */
  status_updated_at: string;
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /** Title */
  title: string;
}

/** GlobalIntelPage */
export interface GlobalIntelPage {
  /** Items */
  items: GlobalIntelRecordView[];
  /**
   * Limit
   * @min 1
   * @max 200
   */
  limit: number;
  /**
   * Offset
   * @min 0
   */
  offset: number;
  /**
   * Total
   * @min 0
   */
  total: number;
}

/** GlobalIntelRecordView */
export interface GlobalIntelRecordView {
  /** Analysis Sha256 */
  analysis_sha256: string | null;
  /** Raw Sha256 */
  raw_sha256: string;
  /** Affected Products */
  affected_products: string[];
  /** Ai Analysis */
  ai_analysis: Record<string, any> | null;
  /** Confidence */
  confidence: number | null;
  /** Cpes */
  cpes: string[];
  /** Cve Ids */
  cve_ids: string[];
  /** Distribution Tlp */
  distribution_tlp:
    | "TLP:CLEAR"
    | "TLP:GREEN"
    | "TLP:AMBER"
    | "TLP:AMBER+STRICT"
    | "TLP:RED";
  /** External Id */
  external_id: string;
  /**
   * Feed Generated At
   * @format date-time
   */
  feed_generated_at: string;
  /** Feed Id */
  feed_id: string;
  /** Feed Version */
  feed_version: string;
  /**
   * First Ingested At
   * @format date-time
   */
  first_ingested_at: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Indicators */
  indicators: Record<string, string>[];
  /**
   * Last Ingested At
   * @format date-time
   */
  last_ingested_at: string;
  /** Markings */
  markings: string[];
  /** Mitre Attack Ids */
  mitre_attack_ids: string[];
  /**
   * Modified At
   * @format date-time
   */
  modified_at: string;
  /** Provider */
  provider: string;
  /** Published At */
  published_at: string | null;
  /** Raw Evidence */
  raw_evidence: Record<string, any>;
  /** Record Type */
  record_type:
    | "report"
    | "threat"
    | "vulnerability"
    | "indicator"
    | "campaign"
    | "malware"
    | "threat_actor";
  /** Regions */
  regions: string[];
  /**
   * Retrieved At
   * @format date-time
   */
  retrieved_at: string;
  /** Review Note */
  review_note: string | null;
  /** Review Status */
  review_status: "pending" | "approved" | "rejected";
  /** Reviewed At */
  reviewed_at: string | null;
  /** Reviewed By */
  reviewed_by: string | null;
  /** Revoked */
  revoked: boolean;
  /** Sectors */
  sectors: string[];
  /** Severity */
  severity: "low" | "medium" | "high" | "critical" | null;
  /** Source Kind */
  source_kind: "news" | "misp" | "vulnerability" | "other";
  /** Source Url */
  source_url: string | null;
  /** Summary */
  summary: string;
  /** Tags */
  tags: string[];
  /** Title */
  title: string;
  /** Valid From */
  valid_from: string | null;
  /** Valid Until */
  valid_until: string | null;
  /** Vulnerability */
  vulnerability: Record<string, any> | null;
}

/** HTTPValidationError */
export interface HTTPValidationError {
  /** Detail */
  detail?: ValidationError[];
}

/** HealthResponse */
export interface HealthResponse {
  /**
   * Service
   * @default "traceless-api"
   */
  service?: string;
  /**
   * Status
   * @default "ok"
   */
  status?: "ok";
  /** Version */
  version: string;
}

/** IndicatorObservable */
export interface IndicatorObservable {
  /**
   * Role
   * @default "unknown"
   */
  role?:
    | "unknown"
    | "source"
    | "destination"
    | "host"
    | "callback"
    | "artifact";
  /** Type */
  type: "ipv4" | "ipv6" | "domain" | "url" | "file_sha256" | "email";
  /**
   * Value
   * @minLength 1
   * @maxLength 2000
   */
  value: string;
}

/** IntelCorrelationResult */
export interface IntelCorrelationResult {
  /**
   * Finding Matches
   * @min 0
   */
  finding_matches: number;
  /**
   * Findings Created
   * @min 0
   */
  findings_created: number;
  /**
   * Records Considered
   * @min 0
   */
  records_considered: number;
  /**
   * Risks Created
   * @min 0
   */
  risks_created: number;
  /**
   * Scan Id
   * @format uuid
   */
  scan_id: string;
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /**
   * Threat Records Matched
   * @min 0
   */
  threat_records_matched: number;
  /**
   * Threats Created
   * @min 0
   */
  threats_created: number;
  /**
   * Vulnerability Records Applied
   * @min 0
   */
  vulnerability_records_applied: number;
  /** Warnings */
  warnings?: string[];
}

/** IntelImportResult */
export interface IntelImportResult {
  /**
   * Created
   * @min 0
   */
  created: number;
  /**
   * Imported
   * @min 0
   */
  imported: number;
  /**
   * Quarantined
   * @min 0
   * @default 0
   */
  quarantined?: number;
  /**
   * Unchanged
   * @min 0
   */
  unchanged: number;
  /**
   * Updated
   * @min 0
   */
  updated: number;
  /** Warnings */
  warnings?: string[];
}

/** IntelReviewRequest */
export interface IntelReviewRequest {
  /** Decision */
  decision: "approved" | "rejected";
  /** Note */
  note?: string | null;
}

/** IntelReviewResult */
export interface IntelReviewResult {
  /** Correlation Job Ids */
  correlation_job_ids?: string[];
  record: GlobalIntelRecordView;
}

/** IntelligenceSyncResult */
export interface IntelligenceSyncResult {
  /**
   * Payload Sha256
   * @pattern ^[a-f0-9]{64}$
   */
  payload_sha256: string;
  /** Feed Version */
  feed_version: string;
  /**
   * Fetched
   * @min 0
   */
  fetched: number;
  /**
   * Matched
   * @min 0
   */
  matched: number;
  /** Provider */
  provider: string;
  /**
   * Updated
   * @min 0
   */
  updated: number;
  /** Warnings */
  warnings?: string[];
}

/** LiveScanCreate */
export interface LiveScanCreate {
  /**
   * Authorization Id
   * @format uuid
   */
  authorization_id: string;
  /**
   * Scanner
   * @default "nmap"
   */
  scanner?: "nmap";
}

/** OperationalSystemCreate */
export interface OperationalSystemCreate {
  /**
   * Criticality
   * @default "medium"
   */
  criticality?: "low" | "medium" | "high" | "critical";
  /**
   * Description
   * @maxLength 4000
   * @default ""
   */
  description?: string;
  /**
   * Name
   * @minLength 2
   * @maxLength 160
   */
  name: string;
  /**
   * Owner
   * @minLength 2
   * @maxLength 160
   */
  owner: string;
}

/** OperationalSystemView */
export interface OperationalSystemView {
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /** Criticality */
  criticality: "low" | "medium" | "high" | "critical";
  /**
   * Description
   * @maxLength 4000
   */
  description: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Name
   * @minLength 2
   * @maxLength 160
   */
  name: string;
  /**
   * Owner
   * @minLength 2
   * @maxLength 160
   */
  owner: string;
  /**
   * Project Id
   * @format uuid
   */
  project_id: string;
  /**
   * Updated At
   * @format date-time
   */
  updated_at: string;
}

/** Page[AssetView] */
export interface PageAssetView {
  /** Has More */
  has_more: boolean;
  /** Items */
  items: AssetView[];
  /**
   * Limit
   * @min 1
   * @max 200
   */
  limit: number;
  /**
   * Offset
   * @min 0
   */
  offset: number;
  /**
   * Total
   * @min 0
   */
  total: number;
}

/** Page[FindingSummaryView] */
export interface PageFindingSummaryView {
  /** Has More */
  has_more: boolean;
  /** Items */
  items: FindingSummaryView[];
  /**
   * Limit
   * @min 1
   * @max 200
   */
  limit: number;
  /**
   * Offset
   * @min 0
   */
  offset: number;
  /**
   * Total
   * @min 0
   */
  total: number;
}

/** Page[RiskSummaryView] */
export interface PageRiskSummaryView {
  /** Has More */
  has_more: boolean;
  /** Items */
  items: RiskSummaryView[];
  /**
   * Limit
   * @min 1
   * @max 200
   */
  limit: number;
  /**
   * Offset
   * @min 0
   */
  offset: number;
  /**
   * Total
   * @min 0
   */
  total: number;
}

/** Page[ServiceView] */
export interface PageServiceView {
  /** Has More */
  has_more: boolean;
  /** Items */
  items: ServiceView[];
  /**
   * Limit
   * @min 1
   * @max 200
   */
  limit: number;
  /**
   * Offset
   * @min 0
   */
  offset: number;
  /**
   * Total
   * @min 0
   */
  total: number;
}

/** Page[ThreatSummaryView] */
export interface PageThreatSummaryView {
  /** Has More */
  has_more: boolean;
  /** Items */
  items: ThreatSummaryView[];
  /**
   * Limit
   * @min 1
   * @max 200
   */
  limit: number;
  /**
   * Offset
   * @min 0
   */
  offset: number;
  /**
   * Total
   * @min 0
   */
  total: number;
}

/** Page[VulnerabilityObservationSummaryView] */
export interface PageVulnerabilityObservationSummaryView {
  /** Has More */
  has_more: boolean;
  /** Items */
  items: VulnerabilityObservationSummaryView[];
  /**
   * Limit
   * @min 1
   * @max 200
   */
  limit: number;
  /**
   * Offset
   * @min 0
   */
  offset: number;
  /**
   * Total
   * @min 0
   */
  total: number;
}

/** PipelineCollectionTotals */
export interface PipelineCollectionTotals {
  /**
   * Assets
   * @min 0
   */
  assets: number;
  /**
   * Findings
   * @min 0
   */
  findings: number;
  /**
   * Risks
   * @min 0
   */
  risks: number;
  /**
   * Services
   * @min 0
   */
  services: number;
  /**
   * Threats
   * @min 0
   */
  threats: number;
}

/** PipelineOverview */
export interface PipelineOverview {
  /** Assets */
  assets: AssetView[];
  /**
   * Collection Limit
   * @min 1
   * @max 200
   */
  collection_limit: number;
  collection_totals: PipelineCollectionTotals;
  /** Collections Truncated */
  collections_truncated: boolean;
  /** Findings */
  findings: FindingView[];
  latest_architecture: ArchitectureSnapshotView | null;
  latest_scan: ScanJobView | null;
  /** Risks */
  risks: RiskView[];
  /** Services */
  services: ServiceView[];
  system: OperationalSystemView;
  /** Threats */
  threats: ThreatView[];
}

/** ProjectCreate */
export interface ProjectCreate {
  /**
   * Description
   * @maxLength 4000
   * @default ""
   */
  description?: string;
  /**
   * Name
   * @minLength 2
   * @maxLength 160
   */
  name: string;
}

/** ProjectView */
export interface ProjectView {
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /**
   * Description
   * @maxLength 4000
   */
  description: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Name
   * @minLength 2
   * @maxLength 160
   */
  name: string;
  /**
   * Updated At
   * @format date-time
   */
  updated_at: string;
}

/** ReadinessResponse */
export interface ReadinessResponse {
  /** Checks */
  checks: Record<string, "ready" | "not_ready">;
  /** Status */
  status: "ready" | "not_ready";
}

/** ReportCreate */
export interface ReportCreate {
  /**
   * Format
   * @default "pdf"
   */
  format?: "pdf" | "json" | "csv";
  /**
   * Report Type
   * @default "management"
   */
  report_type?: "management" | "technical" | "risk_register";
  /** Sections */
  sections?:
    | (
        | "executive_summary"
        | "scope_methodology"
        | "architecture"
        | "assets_services"
        | "findings"
        | "threats"
        | "risks"
        | "vulnerability_observations"
        | "limitations"
      )[]
    | null;
}

/** ReportView */
export interface ReportView {
  /** Sha256 */
  sha256: string;
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /** Distribution Tlp */
  distribution_tlp:
    | "TLP:CLEAR"
    | "TLP:GREEN"
    | "TLP:AMBER"
    | "TLP:AMBER+STRICT"
    | "TLP:RED";
  /** Export Status */
  export_status: "available" | "withdrawn";
  /** Format */
  format: "pdf" | "json" | "csv";
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Report Type */
  report_type: "management" | "technical" | "risk_register";
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /** Withdrawal Reason */
  withdrawal_reason?: string | null;
}

/** RiskSummaryView */
export interface RiskSummaryView {
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /** Evidence Status */
  evidence_status: "current" | "unobserved" | "stale" | "unknown";
  /** Finding Id */
  finding_id: string | null;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Impact
   * @min 1
   * @max 5
   */
  impact: number;
  /** Level */
  level: "low" | "medium" | "high" | "critical";
  /**
   * Likelihood
   * @min 1
   * @max 5
   */
  likelihood: number;
  /**
   * Score
   * @min 1
   * @max 25
   */
  score: number;
  /** Status */
  status: "open" | "closed";
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /** Threat Id */
  threat_id: string | null;
  /** Title */
  title: string;
}

/** RiskView */
export interface RiskView {
  /** Closed At */
  closed_at: string | null;
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /** Evidence Status */
  evidence_status: "current" | "unobserved" | "stale" | "unknown";
  /** Finding Id */
  finding_id: string | null;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Impact
   * @min 1
   * @max 5
   */
  impact: number;
  /** Level */
  level: "low" | "medium" | "high" | "critical";
  /**
   * Likelihood
   * @min 1
   * @max 5
   */
  likelihood: number;
  /** Rationale */
  rationale: Record<string, any>;
  /**
   * Score
   * @min 1
   * @max 25
   */
  score: number;
  /** Status */
  status: "open" | "closed";
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /** Threat Id */
  threat_id: string | null;
  /** Title */
  title: string;
  /**
   * Updated At
   * @format date-time
   */
  updated_at: string;
}

/** ScanAuthorizationCreate */
export interface ScanAuthorizationCreate {
  /**
   * Approved By
   * @minLength 2
   * @maxLength 160
   */
  approved_by: string;
  /** Confirmation */
  confirmation: "Jag bekräftar att jag har tillstånd att skanna angivna mål.";
  /**
   * Expires At
   * @format date-time
   */
  expires_at: string;
  /**
   * Profile
   * @default "discovery"
   */
  profile?: "discovery" | "service_inventory";
  /**
   * Purpose
   * @minLength 10
   * @maxLength 2000
   */
  purpose: string;
  /**
   * Targets
   * @maxItems 64
   * @minItems 1
   */
  targets: string[];
}

/** ScanAuthorizationView */
export interface ScanAuthorizationView {
  /**
   * Scope Sha256
   * @pattern ^[a-f0-9]{64}$
   */
  scope_sha256: string;
  /** Approved By */
  approved_by: string;
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /**
   * Expires At
   * @format date-time
   */
  expires_at: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Profile */
  profile: "discovery" | "service_inventory";
  /** Purpose */
  purpose: string;
  /** Status */
  status: "active" | "expired" | "revoked";
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /** Targets */
  targets: string[];
}

/** ScanJobView */
export interface ScanJobView {
  /** Raw Evidence Sha256 */
  raw_evidence_sha256: string | null;
  /**
   * Attempt Count
   * @min 0
   */
  attempt_count: number;
  /**
   * Authorization Id
   * @format uuid
   */
  authorization_id: string;
  /** Cancel Requested At */
  cancel_requested_at: string | null;
  /** Claimed By */
  claimed_by: string | null;
  /** Completed At */
  completed_at: string | null;
  /** Error Code */
  error_code: string | null;
  /** Error Message */
  error_message: string | null;
  /** Heartbeat At */
  heartbeat_at: string | null;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /** Lease Expires At */
  lease_expires_at: string | null;
  /**
   * Max Attempts
   * @min 1
   * @max 10
   */
  max_attempts: number;
  /** Mode */
  mode: "live" | "import";
  /**
   * Requested At
   * @format date-time
   */
  requested_at: string;
  /** Result Summary */
  result_summary: Record<string, any>;
  /** Scanner */
  scanner: string;
  /** Started At */
  started_at: string | null;
  /** Status */
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
}

/** ServiceView */
export interface ServiceView {
  /**
   * Asset Id
   * @format uuid
   */
  asset_id: string;
  /**
   * Confidence
   * @min 0
   * @max 1
   */
  confidence: number;
  /** Cpes */
  cpes: string[];
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Port
   * @min 1
   * @max 65535
   */
  port: number;
  /** Product */
  product: string | null;
  /** Protocol */
  protocol: string;
  /**
   * Scan Job Id
   * @format uuid
   */
  scan_job_id: string;
  /** Service Name */
  service_name: string | null;
  /** State */
  state: string;
  /** Version */
  version: string | null;
}

/** ThreatSummaryView */
export interface ThreatSummaryView {
  /** Affected Products */
  affected_products: string[];
  /** Attack Patterns */
  attack_patterns: string[];
  /**
   * Confidence
   * @min 0
   * @max 1
   */
  confidence: number;
  /** External Id */
  external_id: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Ingested At
   * @format date-time
   */
  ingested_at: string;
  /** Matched Asset Ids */
  matched_asset_ids: string[];
  /**
   * Modified At
   * @format date-time
   */
  modified_at: string;
  /** Severity */
  severity: "low" | "medium" | "high" | "critical";
  /** Source */
  source: string;
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /** Title */
  title: string;
}

/** ThreatView */
export interface ThreatView {
  /** Affected Products */
  affected_products: string[];
  /** Attack Patterns */
  attack_patterns: string[];
  /** Confidence */
  confidence: number;
  /** Description */
  description: string;
  /** External Id */
  external_id: string;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Ingested At
   * @format date-time
   */
  ingested_at: string;
  /** Matched Asset Ids */
  matched_asset_ids: string[];
  /**
   * Modified At
   * @format date-time
   */
  modified_at: string;
  /** Provenance */
  provenance: Record<string, any>;
  /** Severity */
  severity: "low" | "medium" | "high" | "critical";
  /** Source */
  source: string;
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /** Title */
  title: string;
}

/** ValidationError */
export interface ValidationError {
  /** Context */
  ctx?: object;
  /** Input */
  input?: any;
  /** Location */
  loc: (string | number)[];
  /** Message */
  msg: string;
  /** Error Type */
  type: string;
}

/** VulnerabilityImportResult */
export interface VulnerabilityImportResult {
  /**
   * Idempotent Replay
   * @default false
   */
  idempotent_replay?: boolean;
  import_record: VulnerabilityScanImportView;
  /**
   * Imported
   * @min 0
   */
  imported: number;
  /**
   * Matched Assets
   * @min 0
   */
  matched_assets: number;
  /**
   * Matched Services
   * @min 0
   */
  matched_services: number;
  /**
   * Promoted Findings
   * @min 0
   */
  promoted_findings: number;
  /** Warnings */
  warnings?: string[];
}

/** VulnerabilityObservationInput */
export interface VulnerabilityObservationInput {
  /**
   * Asset Identifier
   * @minLength 1
   * @maxLength 500
   */
  asset_identifier: string;
  /**
   * Cpes
   * @maxItems 100
   */
  cpes?: string[];
  /**
   * Cve Ids
   * @maxItems 100
   */
  cve_ids?: string[];
  /** Cvss Score */
  cvss_score?: number | null;
  /** Cvss Vector */
  cvss_vector?: string | null;
  /**
   * Description
   * @maxLength 50000
   * @default ""
   */
  description?: string;
  /** Evidence */
  evidence?: Record<string, any>;
  /** Exploitable */
  exploitable?: boolean | null;
  /** Hostname */
  hostname?: string | null;
  /** Ip Address */
  ip_address?: string | null;
  /** Observed At */
  observed_at?: string | null;
  /** Port */
  port?: number | null;
  /** Product */
  product?: string | null;
  /** Protocol */
  protocol?: string | null;
  /**
   * Provider Finding Id
   * @minLength 1
   * @maxLength 160
   */
  provider_finding_id: string;
  /** Service Name */
  service_name?: string | null;
  /** Severity */
  severity: "info" | "low" | "medium" | "high" | "critical";
  /**
   * Solution
   * @maxLength 50000
   * @default ""
   */
  solution?: string;
  /**
   * State
   * @default "open"
   */
  state?:
    | "open"
    | "fixed"
    | "reopened"
    | "accepted"
    | "false_positive"
    | "out_of_scope"
    | "unknown";
  /**
   * Title
   * @minLength 1
   * @maxLength 500
   */
  title: string;
  /** Version */
  version?: string | null;
}

/** VulnerabilityObservationSummaryView */
export interface VulnerabilityObservationSummaryView {
  /** Asset Identifier */
  asset_identifier: string;
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /** Cve Ids */
  cve_ids: string[];
  /** Cvss Score */
  cvss_score: number | null;
  /** Hostname */
  hostname: string | null;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Import Id
   * @format uuid
   */
  import_id: string;
  /** Ip Address */
  ip_address: string | null;
  /** Match Confidence */
  match_confidence: number | null;
  /** Matched Asset Id */
  matched_asset_id: string | null;
  /** Matched Service Id */
  matched_service_id: string | null;
  /** Observed At */
  observed_at: string | null;
  /** Port */
  port: number | null;
  /** Protocol */
  protocol: string | null;
  /** Provider Finding Id */
  provider_finding_id: string;
  /** Severity */
  severity: "info" | "low" | "medium" | "high" | "critical";
  /** State */
  state: string;
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /** Title */
  title: string;
}

/** VulnerabilityObservationView */
export interface VulnerabilityObservationView {
  /**
   * Asset Identifier
   * @minLength 1
   * @maxLength 500
   */
  asset_identifier: string;
  /**
   * Cpes
   * @maxItems 100
   */
  cpes?: string[];
  /**
   * Created At
   * @format date-time
   */
  created_at: string;
  /**
   * Cve Ids
   * @maxItems 100
   */
  cve_ids?: string[];
  /** Cvss Score */
  cvss_score?: number | null;
  /** Cvss Vector */
  cvss_vector?: string | null;
  /**
   * Description
   * @maxLength 50000
   * @default ""
   */
  description?: string;
  /** Evidence */
  evidence?: Record<string, any>;
  /** Exploitable */
  exploitable?: boolean | null;
  /** Hostname */
  hostname?: string | null;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Import Id
   * @format uuid
   */
  import_id: string;
  /** Ip Address */
  ip_address?: string | null;
  /** Match Confidence */
  match_confidence?: number | null;
  /** Matched Asset Id */
  matched_asset_id: string | null;
  /** Matched Service Id */
  matched_service_id: string | null;
  /**
   * Observation Key
   * @pattern ^[a-f0-9]{64}$
   */
  observation_key: string;
  /** Observed At */
  observed_at?: string | null;
  /** Port */
  port?: number | null;
  /** Product */
  product?: string | null;
  /** Protocol */
  protocol?: string | null;
  /**
   * Provider Finding Id
   * @minLength 1
   * @maxLength 160
   */
  provider_finding_id: string;
  /** Service Name */
  service_name?: string | null;
  /** Severity */
  severity: "info" | "low" | "medium" | "high" | "critical";
  /**
   * Solution
   * @maxLength 50000
   * @default ""
   */
  solution?: string;
  /**
   * State
   * @default "open"
   */
  state?:
    | "open"
    | "fixed"
    | "reopened"
    | "accepted"
    | "false_positive"
    | "out_of_scope"
    | "unknown";
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
  /**
   * Title
   * @minLength 1
   * @maxLength 500
   */
  title: string;
  /** Version */
  version?: string | null;
}

/** VulnerabilityScanImportCreate */
export interface VulnerabilityScanImportCreate {
  /**
   * Observations
   * @maxItems 50000
   */
  observations: VulnerabilityObservationInput[];
  /** Provider */
  provider:
    | "nessus"
    | "qualys"
    | "greenbone"
    | "rapid7"
    | "defender_vm"
    | "generic";
  /** Report Metadata */
  report_metadata?: Record<string, any>;
  /** Scan Completed At */
  scan_completed_at?: string | null;
  /** Scan Started At */
  scan_started_at?: string | null;
  /** Scanner Version */
  scanner_version?: string | null;
  /**
   * Source Format
   * @default "normalized-json"
   */
  source_format?: "normalized-json";
  /**
   * Source Name
   * @minLength 1
   * @maxLength 255
   */
  source_name: string;
}

/** VulnerabilityScanImportView */
export interface VulnerabilityScanImportView {
  /**
   * Raw Sha256
   * @pattern ^[a-f0-9]{64}$
   */
  raw_sha256: string;
  /**
   * Asset Count
   * @min 0
   */
  asset_count: number;
  /**
   * Id
   * @format uuid
   */
  id: string;
  /**
   * Imported At
   * @format date-time
   */
  imported_at: string;
  /** Imported By */
  imported_by: string;
  /**
   * Matched Asset Count
   * @min 0
   */
  matched_asset_count: number;
  /**
   * Observation Count
   * @min 0
   */
  observation_count: number;
  /**
   * Promoted Finding Count
   * @min 0
   */
  promoted_finding_count: number;
  /** Provider */
  provider:
    | "nessus"
    | "qualys"
    | "greenbone"
    | "rapid7"
    | "defender_vm"
    | "generic";
  /** Report Metadata */
  report_metadata: Record<string, any>;
  /** Scan Completed At */
  scan_completed_at: string | null;
  /** Scan Started At */
  scan_started_at: string | null;
  /** Scanner Version */
  scanner_version: string | null;
  /** Source Format */
  source_format: string;
  /** Source Name */
  source_name: string;
  /**
   * System Id
   * @format uuid
   */
  system_id: string;
}

/** VulnerabilitySignals */
export interface VulnerabilitySignals {
  /**
   * Affected Cpes
   * @maxItems 100
   * @minItems 1
   */
  affected_cpes: string[];
  /** Cvss Score */
  cvss_score?: number | null;
  /** Cvss Vector */
  cvss_vector?: string | null;
  /**
   * Cwe Ids
   * @maxItems 100
   */
  cwe_ids?: string[];
  /** Epss Percentile */
  epss_percentile?: number | null;
  /** Epss Score */
  epss_score?: number | null;
  /**
   * Exploit Status
   * @default "unknown"
   */
  exploit_status?: "unknown" | "poc" | "active";
}
