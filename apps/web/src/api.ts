const API_V1_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '/api/v1').replace(/\/+$/, '');
const DEFAULT_OPERATIONAL_BASE_URL = `${API_V1_BASE_URL}/operational`;

export type Criticality = 'low' | 'medium' | 'high' | 'critical';
export type ScanProfile = 'discovery' | 'service_inventory';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ReportFormat = 'pdf' | 'json' | 'csv';
export type ReportType = 'management' | 'technical' | 'risk_register';
export type BackgroundJobType =
  | 'normalized_vulnerability_import'
  | 'report_generation'
  | 'intelligence_correlation';
export type BackgroundJobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type OperationalRole = 'admin' | 'analyst' | 'viewer' | 'scanner';
export type OperationalCapability =
  | 'read_operational'
  | 'analyze'
  | 'manage_scans'
  | 'ingest_intelligence'
  | 'administer';
export type IntelligenceProvider = 'kev' | 'epss' | 'nvd' | 'internal';
export type IntelSourceKind = 'news' | 'misp' | 'vulnerability' | 'other';
export type IntelReviewStatus = 'pending' | 'approved' | 'rejected';
export type DistributionTlp =
  | 'TLP:CLEAR'
  | 'TLP:GREEN'
  | 'TLP:AMBER'
  | 'TLP:AMBER+STRICT'
  | 'TLP:RED';
export type IntelRecordType =
  | 'report'
  | 'threat'
  | 'vulnerability'
  | 'indicator'
  | 'campaign'
  | 'malware'
  | 'threat_actor';

export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface OperationalSystem {
  id: string;
  project_id: string;
  name: string;
  description: string;
  owner: string;
  criticality: Criticality;
  created_at: string;
  updated_at: string;
}

export interface OperationalPrincipal {
  subject: string;
  actor: string;
  organization_id: string;
  organization_name: string;
  project_ids: string[] | null;
  system_ids: string[] | null;
  roles: OperationalRole[];
  capabilities: OperationalCapability[];
  authentication_method: 'local' | 'api_key' | 'oidc' | 'worker';
}

export interface ScanAuthorization {
  id: string;
  system_id: string;
  targets: string[];
  profile: ScanProfile;
  approved_by: string;
  purpose: string;
  expires_at: string;
  scope_sha256: string;
  status: 'active' | 'expired' | 'revoked';
  created_at: string;
}

export interface ScanJob {
  id: string;
  system_id: string;
  authorization_id: string;
  scanner: string;
  mode: 'live' | 'import';
  status: ScanStatus;
  requested_at: string;
  started_at: string | null;
  completed_at: string | null;
  raw_evidence_sha256: string | null;
  result_summary: Record<string, unknown>;
  error_code: string | null;
  error_message: string | null;
}

export interface Asset {
  id: string;
  system_id: string;
  source_scan_id: string;
  primary_ip: string;
  hostname: string | null;
  mac_address: string | null;
  state: string;
  os_family: string | null;
  os_accuracy: number | null;
  first_seen_at: string;
  last_seen_at: string;
  observation_count: number;
  inventory_status: 'current' | 'unobserved' | 'stale';
}

export interface Service {
  id: string;
  asset_id: string;
  scan_job_id: string;
  port: number;
  protocol: string;
  state: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  cpes: string[];
  confidence: number;
}

export interface Finding {
  id: string;
  system_id: string;
  scan_job_id: string | null;
  asset_id: string | null;
  service_id: string | null;
  stable_key: string;
  finding_type: 'vulnerability' | 'misconfiguration' | 'informational';
  cve_id: string | null;
  title: string;
  status: 'candidate' | 'likely' | 'confirmed' | 'false_positive';
  lifecycle_status: FindingLifecycleStatus;
  match_confidence: number;
  match_reason: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  is_kev: boolean;
  kev_due_date: string | null;
  sources: Record<string, unknown>[];
  primary_evidence_strength: number;
  first_seen_at: string;
  last_seen_at: string;
  status_updated_at: string;
  resolved_at: string | null;
  occurrence_count: number;
  created_at: string;
  inventory_status: 'current' | 'unobserved' | 'stale' | 'unknown';
}

export type FindingLifecycleStatus =
  | 'open'
  | 'fixed'
  | 'accepted'
  | 'false_positive'
  | 'out_of_scope'
  | 'reopened';

export interface FindingEvidence {
  id: string;
  finding_id: string;
  observation_id: string | null;
  evidence_key: string;
  source_kind: string;
  source_name: string;
  external_id: string;
  lifecycle_status: FindingLifecycleStatus;
  strength: number;
  payload: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
  observation_count: number;
  created_at: string;
  updated_at: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface FindingSummary {
  id: string;
  system_id: string;
  asset_id: string | null;
  service_id: string | null;
  finding_type: Finding['finding_type'];
  cve_id: string | null;
  title: string;
  status: Finding['status'];
  lifecycle_status: FindingLifecycleStatus;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  kev_due_date: string | null;
  primary_evidence_strength: number;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  occurrence_count: number;
  inventory_status: Finding['inventory_status'];
}

export interface Threat {
  id: string;
  system_id: string;
  source: string;
  external_id: string;
  title: string;
  description: string;
  severity: Criticality;
  confidence: number;
  attack_patterns: string[];
  affected_products: string[];
  matched_asset_ids: string[];
  provenance: Record<string, unknown>;
  modified_at: string;
  ingested_at: string;
}

export type ThreatSummary = Omit<Threat, 'description' | 'provenance'>;

export interface Risk {
  id: string;
  system_id: string;
  finding_id: string | null;
  threat_id: string | null;
  title: string;
  likelihood: number;
  impact: number;
  score: number;
  level: Criticality;
  status: 'open' | 'closed';
  rationale: Record<string, unknown>;
  created_at: string;
  evidence_status: 'current' | 'unobserved' | 'stale' | 'unknown';
}

export type RiskSummary = Omit<Risk, 'rationale'>;

export interface ArchitectureSnapshot {
  id: string;
  system_id: string;
  source_scan_id: string | null;
  base_snapshot_id: string | null;
  version: number;
  status: 'draft' | 'published' | 'superseded';
  source_type: 'scan' | 'manual' | 'import';
  layer: 'manual' | 'observed' | 'proposal';
  title: string;
  change_note: string;
  created_by: string;
  graph: Record<string, unknown>;
  created_at: string;
}

export interface ArchitecturePosition {
  x: number;
  y: number;
}

export type ArchitectureNodeKind =
  | 'asset'
  | 'service'
  | 'server'
  | 'database'
  | 'user'
  | 'security_control'
  | 'gateway'
  | 'queue'
  | 'application'
  | 'cloud'
  | 'network'
  | 'other';

export interface ArchitectureNodeInput {
  id: string;
  name: string;
  kind: ArchitectureNodeKind;
  position: ArchitecturePosition;
  zone_id: string | null;
  properties: Record<string, unknown>;
  provenance: 'manual' | 'observed' | 'imported';
}

export interface ArchitectureEdgeInput {
  id: string;
  source: string;
  target: string;
  label: string | null;
  protocol: string | null;
  encrypted: boolean | null;
  properties: Record<string, unknown>;
}

export interface ArchitectureZoneInput {
  id: string;
  name: string;
  trust_boundary: 'unconfirmed' | 'external' | 'untrusted' | 'restricted' | 'trusted';
}

export interface ArchitectureRiskContextInput {
  asset_id: string;
  service_id: string | null;
  exposure: 'external' | 'internal' | 'isolated' | 'unknown';
  reachable: boolean | null;
  control_effectiveness: number | null;
  evidence_reference: string;
}

export interface ArchitectureGraphInput {
  schema_version: '1.0';
  publication_state: 'draft';
  warning: string;
  zones: ArchitectureZoneInput[];
  nodes: ArchitectureNodeInput[];
  edges: ArchitectureEdgeInput[];
  risk_contexts: ArchitectureRiskContextInput[];
}

export interface ArchitectureVersionInput {
  title: string;
  change_note: string;
  base_snapshot_id: string | null;
  graph: ArchitectureGraphInput;
}

export type VulnerabilityProvider =
  | 'nessus'
  | 'qualys'
  | 'greenbone'
  | 'rapid7'
  | 'defender_vm'
  | 'generic';

export interface VulnerabilityScanImport {
  id: string;
  system_id: string;
  provider: VulnerabilityProvider;
  source_format: string;
  source_name: string;
  scanner_version: string | null;
  scan_started_at: string | null;
  scan_completed_at: string | null;
  imported_at: string;
  imported_by: string;
  raw_sha256: string;
  report_metadata: Record<string, unknown>;
  observation_count: number;
  asset_count: number;
  matched_asset_count: number;
  promoted_finding_count: number;
}

export interface VulnerabilityObservation {
  id: string;
  import_id: string;
  system_id: string;
  observation_key: string;
  provider_finding_id: string;
  asset_identifier: string;
  ip_address: string | null;
  hostname: string | null;
  port: number | null;
  protocol: string | null;
  service_name: string | null;
  product: string | null;
  version: string | null;
  cpes: string[];
  cve_ids: string[];
  title: string;
  description: string;
  solution: string;
  severity: Criticality | 'info';
  cvss_score: number | null;
  cvss_vector: string | null;
  state:
    | 'open'
    | 'fixed'
    | 'reopened'
    | 'accepted'
    | 'false_positive'
    | 'out_of_scope'
    | 'unknown';
  exploitable: boolean | null;
  evidence: Record<string, unknown>;
  observed_at: string | null;
  matched_asset_id: string | null;
  matched_service_id: string | null;
  match_confidence: number | null;
  created_at: string;
}

export interface VulnerabilityObservationSummary {
  id: string;
  import_id: string;
  system_id: string;
  provider_finding_id: string;
  asset_identifier: string;
  ip_address: string | null;
  hostname: string | null;
  port: number | null;
  protocol: string | null;
  cve_ids: string[];
  title: string;
  severity: Criticality | 'info';
  cvss_score: number | null;
  state: string;
  observed_at: string | null;
  matched_asset_id: string | null;
  matched_service_id: string | null;
  match_confidence: number | null;
  created_at: string;
}

export interface VulnerabilityImportResult {
  import_record: VulnerabilityScanImport;
  imported: number;
  matched_assets: number;
  matched_services: number;
  promoted_findings: number;
  idempotent_replay: boolean;
  warnings: string[];
}

export interface VulnerabilityObservationInput {
  provider_finding_id: string;
  asset_identifier: string;
  ip_address?: string | null;
  hostname?: string | null;
  port?: number | null;
  protocol?: string | null;
  service_name?: string | null;
  product?: string | null;
  version?: string | null;
  cpes?: string[];
  cve_ids?: string[];
  title: string;
  description?: string;
  solution?: string;
  severity: Criticality | 'info';
  cvss_score?: number | null;
  cvss_vector?: string | null;
  state?:
    | 'open'
    | 'fixed'
    | 'reopened'
    | 'accepted'
    | 'false_positive'
    | 'out_of_scope'
    | 'unknown';
  exploitable?: boolean | null;
  evidence?: Record<string, unknown>;
  observed_at?: string | null;
}

export interface VulnerabilityScanImportInput {
  provider: VulnerabilityProvider;
  source_name: string;
  source_format?: 'normalized-json';
  scanner_version?: string | null;
  scan_started_at?: string | null;
  scan_completed_at?: string | null;
  report_metadata?: Record<string, unknown>;
  observations: VulnerabilityObservationInput[];
}

export interface BackgroundJob {
  id: string;
  organization_id: string;
  system_id: string;
  job_type: BackgroundJobType;
  status: BackgroundJobStatus;
  payload_schema_version: number;
  payload_sha256: string;
  requested_by: string;
  requested_at: string;
  available_at: string;
  started_at: string | null;
  completed_at: string | null;
  lease_expires_at: string | null;
  heartbeat_at: string | null;
  attempt_count: number;
  max_attempts: number;
  cancel_requested_at: string | null;
  result: Record<string, unknown>;
  result_resource_type: string | null;
  result_resource_id: string | null;
  error_code: string | null;
  error_message: string | null;
}

export interface BackgroundJobEnqueueResult {
  job: BackgroundJob;
  idempotent_replay: boolean;
}

export interface BackgroundJobList {
  items: BackgroundJob[];
  total: number;
  limit: number;
  offset: number;
}

export interface BackgroundJobListOptions {
  status?: BackgroundJobStatus;
  jobType?: BackgroundJobType;
  systemId?: string;
  limit?: number;
  offset?: number;
}

export interface PipelineOverview {
  system: OperationalSystem;
  latest_scan: ScanJob | null;
  latest_architecture: ArchitectureSnapshot | null;
  assets: Asset[];
  services: Service[];
  findings: Finding[];
  threats: Threat[];
  risks: Risk[];
  collection_totals: {
    assets: number;
    services: number;
    findings: number;
    threats: number;
    risks: number;
  };
  collection_limit: number;
  collections_truncated: boolean;
}

export interface IntelligenceSyncResult {
  provider: string;
  fetched: number;
  matched: number;
  updated: number;
  feed_version: string;
  payload_sha256: string;
  warnings: string[];
}

export interface GlobalIntelRecord {
  id: string;
  source_kind: IntelSourceKind;
  provider: string;
  external_id: string;
  record_type: IntelRecordType;
  title: string;
  summary: string;
  source_url: string | null;
  published_at: string | null;
  modified_at: string;
  retrieved_at: string;
  severity: Criticality | null;
  confidence: number | null;
  cve_ids: string[];
  cpes: string[];
  affected_products: string[];
  mitre_attack_ids: string[];
  indicators: Array<Record<string, string>>;
  tags: string[];
  sectors: string[];
  regions: string[];
  markings: string[];
  distribution_tlp: DistributionTlp;
  review_status: IntelReviewStatus;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_note: string | null;
  valid_from: string | null;
  valid_until: string | null;
  revoked: boolean;
  raw_evidence: Record<string, unknown>;
  raw_sha256: string;
  ai_analysis: Record<string, unknown> | null;
  analysis_sha256: string | null;
  vulnerability: Record<string, unknown> | null;
  feed_id: string;
  feed_version: string;
  feed_generated_at: string;
  first_ingested_at: string;
  last_ingested_at: string;
}

export interface GlobalIntelPage {
  items: GlobalIntelRecord[];
  total: number;
  limit: number;
  offset: number;
}

export interface ExternalIntelligenceConnectorUpdate {
  endpoint: string;
  auth_scheme: 'Bearer' | 'X-API-Key';
  credential_reference: string;
  enabled: boolean;
  sync_interval_seconds: number | null;
}

export interface ExternalIntelligenceConnectorView extends ExternalIntelligenceConnectorUpdate {
  id: string;
  organization_id: string;
  name: string;
  next_sync_at: string | null;
  config_version: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ExternalIntelligenceCheckpoint {
  snapshot_id: string;
  cursor_sha256: string;
  feed_id: string;
  feed_version: string;
  feed_generated_at: string;
  pages_completed: number;
  records_completed: number;
  bytes_completed: number;
  page_manifest_sha256: string;
  identity_manifest_sha256: string;
  updated_at: string;
}

export interface ExternalIntelligenceSyncRun {
  id: string;
  connector_id: string;
  snapshot_id: string;
  status: 'running' | 'partial' | 'completed' | 'failed' | 'quarantined';
  started_by: string;
  started_at: string;
  completed_at: string | null;
  lease_expires_at: string | null;
  heartbeat_at: string;
  start_cursor_sha256: string | null;
  next_cursor_sha256: string | null;
  feed_id: string | null;
  feed_version: string | null;
  feed_generated_at: string | null;
  pages_fetched: number;
  records_fetched: number;
  batch_pages_fetched: number;
  batch_records_fetched: number;
  bytes_fetched: number;
  batch_bytes_fetched: number;
  created_count: number;
  updated_count: number;
  unchanged_count: number;
  quarantined_count: number;
  manifest_sha256: string | null;
  error_code: string | null;
}

export interface ExternalIntelligenceSyncRunList {
  items: ExternalIntelligenceSyncRun[];
  total: number;
  limit: number;
  offset: number;
}

export interface ExternalIntelligenceSyncStatus {
  configured: boolean;
  connector_id?: string | null;
  endpoint?: string | null;
  enabled?: boolean;
  schedule_state?: 'manual' | 'disabled' | 'scheduled' | 'due';
  sync_interval_seconds?: number | null;
  next_sync_at?: string | null;
  config_version?: number | null;
  credential_available?: boolean;
  checkpoint?: ExternalIntelligenceCheckpoint | null;
  latest_run?: ExternalIntelligenceSyncRun | null;
}

export interface ExternalIntelligencePullResult {
  run_id: string;
  feed_id: string;
  feed_version: string;
  pages_fetched: number;
  records_fetched: number;
  batch_pages_fetched: number;
  batch_records_fetched: number;
  bytes_fetched: number;
  batch_bytes_fetched: number;
  created: number;
  updated: number;
  unchanged: number;
  quarantined: number;
  active: number;
  revoked: number;
  deleted: number;
  complete: boolean;
  next_cursor?: string | null;
  manifest_sha256: string;
  correlation_jobs_queued: number;
  warnings: string[];
}

export interface IntelCorrelationResult {
  system_id: string;
  scan_id: string;
  records_considered: number;
  vulnerability_records_applied: number;
  finding_matches: number;
  findings_created: number;
  threat_records_matched: number;
  threats_created: number;
  risks_created: number;
  warnings: string[];
}

export interface GlobalIntelFilters {
  sourceKind?: IntelSourceKind;
  recordType?: IntelRecordType;
  query?: string;
  reviewStatus?: IntelReviewStatus;
  limit?: number;
  offset?: number;
}

export interface IntelReviewResult {
  record: GlobalIntelRecord;
  correlation_job_ids: string[];
}

export interface Report {
  id: string;
  system_id: string;
  format: ReportFormat;
  report_type: ReportType;
  sha256: string;
  distribution_tlp: DistributionTlp;
  export_status: 'available' | 'withdrawn';
  withdrawal_reason?: string | null;
  created_at: string;
}

export interface ReportDownload {
  blob: Blob;
  filename: string;
  sha256: string | null;
}

export interface AssetSourceSnapshot {
  id: string;
  system_id: string;
  provider: string;
  source_base_url: string;
  approval_state: 'unreviewed_source_snapshot';
  manifest_sha256: string;
  record_count: number;
  page_count: number;
  record_counts: Record<string, number>;
  started_at: string;
  completed_at: string;
  created_at: string;
}

export interface CreateProjectInput {
  name: string;
  description: string;
}

export interface CreateSystemInput {
  name: string;
  description: string;
  owner: string;
  criticality: Criticality;
}

export interface CreateAuthorizationInput {
  targets: string[];
  profile: ScanProfile;
  approved_by: string;
  purpose: string;
  expires_at: string;
  confirmation: 'Jag bekräftar att jag har tillstånd att skanna angivna mål.';
}

export interface OperationalApi {
  getCurrentPrincipal(): Promise<OperationalPrincipal>;
  listProjects(): Promise<Project[]>;
  createProject(input: CreateProjectInput): Promise<Project>;
  listSystems(projectId: string): Promise<OperationalSystem[]>;
  createSystem(projectId: string, input: CreateSystemInput): Promise<OperationalSystem>;
  createAuthorization(
    systemId: string,
    input: CreateAuthorizationInput,
  ): Promise<ScanAuthorization>;
  listScans(systemId: string): Promise<ScanJob[]>;
  queueNmapScan(systemId: string, authorizationId: string): Promise<ScanJob>;
  importNmapXml(systemId: string, authorizationId: string, xml: Blob): Promise<ScanJob>;
  getOverview(systemId: string): Promise<PipelineOverview>;
  listAssetPage(
    systemId: string,
    options?: { limit?: number; offset?: number },
  ): Promise<Page<Asset>>;
  listServicePage(
    systemId: string,
    options?: { assetId?: string; limit?: number; offset?: number },
  ): Promise<Page<Service>>;
  listThreatPage(
    systemId: string,
    options?: { limit?: number; offset?: number },
  ): Promise<Page<ThreatSummary>>;
  getThreat(systemId: string, threatId: string): Promise<Threat>;
  listArchitectureVersions(systemId: string): Promise<ArchitectureSnapshot[]>;
  saveArchitectureVersion(
    systemId: string,
    input: ArchitectureVersionInput,
  ): Promise<ArchitectureSnapshot>;
  importNessusReport(
    systemId: string,
    sourceName: string,
    report: Blob,
  ): Promise<VulnerabilityImportResult>;
  enqueueNessusImport(
    systemId: string,
    sourceName: string,
    report: Blob,
    idempotencyKey: string,
  ): Promise<BackgroundJobEnqueueResult>;
  enqueueNormalizedVulnerabilityImport(
    systemId: string,
    input: VulnerabilityScanImportInput,
    idempotencyKey: string,
  ): Promise<BackgroundJobEnqueueResult>;
  importVulnerabilityScan(
    systemId: string,
    input: Record<string, unknown>,
  ): Promise<VulnerabilityImportResult>;
  listVulnerabilityScans(systemId: string): Promise<VulnerabilityScanImport[]>;
  listVulnerabilityObservations(
    systemId: string,
    importId?: string,
  ): Promise<VulnerabilityObservation[]>;
  listVulnerabilityObservationPage(
    systemId: string,
    options?: { importId?: string; limit?: number; offset?: number },
  ): Promise<Page<VulnerabilityObservationSummary>>;
  getVulnerabilityObservation(
    systemId: string,
    observationId: string,
  ): Promise<VulnerabilityObservation>;
  listFindingPage(
    systemId: string,
    options?: {
      limit?: number;
      offset?: number;
      lifecycleStatus?: FindingLifecycleStatus;
      findingType?: Finding['finding_type'];
      needsReview?: boolean;
    },
  ): Promise<Page<FindingSummary>>;
  getFinding(systemId: string, findingId: string): Promise<Finding>;
  listFindingEvidence(systemId: string, findingId: string): Promise<FindingEvidence[]>;
  updateFindingLifecycle(
    systemId: string,
    findingId: string,
    lifecycleStatus: FindingLifecycleStatus,
    reason: string,
  ): Promise<Finding>;
  listRiskPage(
    systemId: string,
    options?: { limit?: number; offset?: number; status?: Risk['status'] },
  ): Promise<Page<RiskSummary>>;
  getRisk(systemId: string, riskId: string): Promise<Risk>;
  syncIntelligence(
    systemId: string,
    provider: IntelligenceProvider,
  ): Promise<IntelligenceSyncResult>;
  listGlobalIntel(filters?: GlobalIntelFilters): Promise<GlobalIntelPage>;
  reviewGlobalIntel(
    recordId: string,
    decision: 'approved' | 'rejected',
    note?: string,
  ): Promise<IntelReviewResult>;
  getExternalIntelligenceConnector(): Promise<ExternalIntelligenceConnectorView>;
  configureExternalIntelligenceConnector(
    input: ExternalIntelligenceConnectorUpdate,
  ): Promise<ExternalIntelligenceConnectorView>;
  getExternalIntelligenceSyncStatus(): Promise<ExternalIntelligenceSyncStatus>;
  listExternalIntelligenceSyncRuns(options?: {
    limit?: number;
    offset?: number;
  }): Promise<ExternalIntelligenceSyncRunList>;
  syncExternalIntelligence(maxPages?: number): Promise<ExternalIntelligencePullResult>;
  correlateGlobalIntel(systemId: string): Promise<IntelCorrelationResult>;
  syncNetBox(systemId: string): Promise<AssetSourceSnapshot>;
  listAssetSourceSnapshots(systemId: string): Promise<AssetSourceSnapshot[]>;
  listReports(systemId: string): Promise<Report[]>;
  createReport(systemId: string, format: ReportFormat, reportType: ReportType): Promise<Report>;
  enqueueReport(
    systemId: string,
    format: ReportFormat,
    reportType: ReportType,
    idempotencyKey: string,
  ): Promise<BackgroundJobEnqueueResult>;
  listBackgroundJobs(options?: BackgroundJobListOptions): Promise<BackgroundJobList>;
  getBackgroundJob(jobId: string): Promise<BackgroundJob>;
  cancelBackgroundJob(jobId: string): Promise<BackgroundJob>;
  downloadReport(reportId: string): Promise<ReportDownload>;
}

export class OperationalApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'OperationalApiError';
    this.status = status;
  }
}

interface ApiOptions {
  baseUrl?: string;
  identityUrl?: string;
  actor?: string;
  fetchImpl?: typeof fetch;
  getAccessToken?: () => string | null;
}

function errorDetail(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (!Array.isArray(value)) return null;
  const messages = value
    .map((item) => {
      if (typeof item !== 'object' || item === null || !('msg' in item)) return null;
      return typeof item.msg === 'string' ? item.msg : null;
    })
    .filter((item): item is string => item !== null);
  return messages.length > 0 ? messages.join(' · ') : null;
}

async function responseError(response: Response): Promise<OperationalApiError> {
  let message = `API-anropet misslyckades (${response.status})`;
  try {
    const body: unknown = await response.json();
    if (typeof body === 'object' && body !== null && 'detail' in body) {
      message = errorDetail(body.detail) ?? message;
    }
  } catch {
    // The status code remains useful when an intermediary returns a non-JSON error.
  }
  return new OperationalApiError(response.status, message);
}

function safeFilename(contentDisposition: string | null, fallback: string): string {
  const matched = contentDisposition?.match(/filename="?([^";]+)"?/i)?.[1];
  const candidate = (matched ?? fallback).split(/[\\/]/).at(-1) ?? fallback;
  const sanitized = candidate.replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 180);
  return sanitized || fallback;
}

export function createOperationalApi(options: ApiOptions = {}): OperationalApi {
  const baseUrl = (options.baseUrl ?? DEFAULT_OPERATIONAL_BASE_URL).replace(/\/+$/, '');
  const identityUrl = options.identityUrl ?? `${API_V1_BASE_URL}/auth/me`;
  const actor = options.actor ?? 'operational-workspace';
  const fetchImpl = options.fetchImpl ?? fetch;

  function requestHeaders(initialHeaders: HeadersInit | undefined): Headers {
    const headers = new Headers(initialHeaders);
    const accessToken = options.getAccessToken?.();
    if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
    return headers;
  }

  async function jsonAt<T>(url: string, init: RequestInit = {}): Promise<T> {
    const headers = requestHeaders(init.headers);
    headers.set('Accept', 'application/json');
    if (init.body !== undefined && !(init.body instanceof Blob)) {
      headers.set('Content-Type', 'application/json');
    }
    if ((init.method ?? 'GET') !== 'GET') headers.set('X-Actor', actor);
    const response = await fetchImpl(url, {
      ...init,
      credentials: 'same-origin',
      headers,
    });
    if (!response.ok) throw await responseError(response);
    return (await response.json()) as T;
  }

  const json = <T,>(path: string, init: RequestInit = {}) =>
    jsonAt<T>(`${baseUrl}${path}`, init);

  const systemPath = (systemId: string) => `/systems/${encodeURIComponent(systemId)}`;

  return {
    getCurrentPrincipal: () => jsonAt<OperationalPrincipal>(identityUrl),
    listProjects: () => json<Project[]>('/projects'),
    createProject: (input) =>
      json<Project>('/projects', { method: 'POST', body: JSON.stringify(input) }),
    listSystems: (projectId) =>
      json<OperationalSystem[]>(`/projects/${encodeURIComponent(projectId)}/systems`),
    createSystem: (projectId, input) =>
      json<OperationalSystem>(`/projects/${encodeURIComponent(projectId)}/systems`, {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    createAuthorization: (systemId, input) =>
      json<ScanAuthorization>(`${systemPath(systemId)}/scan-authorizations`, {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    listScans: (systemId) => json<ScanJob[]>(`${systemPath(systemId)}/scans`),
    queueNmapScan: (systemId, authorizationId) =>
      json<ScanJob>(`${systemPath(systemId)}/scans`, {
        method: 'POST',
        body: JSON.stringify({ authorization_id: authorizationId, scanner: 'nmap' }),
      }),
    importNmapXml: (systemId, authorizationId, xml) =>
      json<ScanJob>(
        `${systemPath(systemId)}/scans/import/nmap?authorization_id=${encodeURIComponent(authorizationId)}`,
        {
          method: 'POST',
          body: xml,
          headers: { 'Content-Type': 'application/xml' },
        },
      ),
    getOverview: (systemId) => json<PipelineOverview>(`${systemPath(systemId)}/overview`),
    listAssetPage: (systemId, options = {}) => {
      const parameters = new URLSearchParams();
      if (options.limit !== undefined) parameters.set('limit', String(options.limit));
      if (options.offset !== undefined) parameters.set('offset', String(options.offset));
      const suffix = parameters.size > 0 ? `?${parameters.toString()}` : '';
      return json<Page<Asset>>(`${systemPath(systemId)}/assets/page${suffix}`);
    },
    listServicePage: (systemId, options = {}) => {
      const parameters = new URLSearchParams();
      if (options.assetId) parameters.set('asset_id', options.assetId);
      if (options.limit !== undefined) parameters.set('limit', String(options.limit));
      if (options.offset !== undefined) parameters.set('offset', String(options.offset));
      const suffix = parameters.size > 0 ? `?${parameters.toString()}` : '';
      return json<Page<Service>>(`${systemPath(systemId)}/services/page${suffix}`);
    },
    listThreatPage: (systemId, options = {}) => {
      const parameters = new URLSearchParams();
      if (options.limit !== undefined) parameters.set('limit', String(options.limit));
      if (options.offset !== undefined) parameters.set('offset', String(options.offset));
      const suffix = parameters.size > 0 ? `?${parameters.toString()}` : '';
      return json<Page<ThreatSummary>>(`${systemPath(systemId)}/threats${suffix}`);
    },
    getThreat: (systemId, threatId) =>
      json<Threat>(`${systemPath(systemId)}/threats/${encodeURIComponent(threatId)}`),
    listArchitectureVersions: (systemId) =>
      json<ArchitectureSnapshot[]>(`${systemPath(systemId)}/architecture/versions`),
    saveArchitectureVersion: (systemId, input) =>
      json<ArchitectureSnapshot>(`${systemPath(systemId)}/architecture/versions`, {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    importNessusReport: (systemId, sourceName, report) =>
      json<VulnerabilityImportResult>(
        `${systemPath(systemId)}/vulnerability-scans/import/nessus?source_name=${encodeURIComponent(sourceName)}`,
        {
          method: 'POST',
          body: report,
          headers: { 'Content-Type': 'application/xml' },
        },
      ),
    enqueueNessusImport: (systemId, sourceName, report, idempotencyKey) =>
      json<BackgroundJobEnqueueResult>(
        `${systemPath(systemId)}/vulnerability-scans/import/nessus/async?source_name=${encodeURIComponent(sourceName)}`,
        {
          method: 'POST',
          body: report,
          headers: {
            'Content-Type': 'application/xml',
            'Idempotency-Key': idempotencyKey,
          },
        },
      ),
    enqueueNormalizedVulnerabilityImport: (systemId, input, idempotencyKey) =>
      json<BackgroundJobEnqueueResult>(
        `${systemPath(systemId)}/vulnerability-scans/import/async`,
        {
          method: 'POST',
          body: JSON.stringify(input),
          headers: { 'Idempotency-Key': idempotencyKey },
        },
      ),
    importVulnerabilityScan: (systemId, input) =>
      json<VulnerabilityImportResult>(`${systemPath(systemId)}/vulnerability-scans/import`, {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    listVulnerabilityScans: (systemId) =>
      json<VulnerabilityScanImport[]>(`${systemPath(systemId)}/vulnerability-scans`),
    listVulnerabilityObservations: (systemId, importId) => {
      const suffix = importId ? `?import_id=${encodeURIComponent(importId)}` : '';
      return json<VulnerabilityObservation[]>(
        `${systemPath(systemId)}/vulnerability-observations${suffix}`,
      );
    },
    listVulnerabilityObservationPage: (systemId, options = {}) => {
      const parameters = new URLSearchParams();
      if (options.importId) parameters.set('import_id', options.importId);
      if (options.limit !== undefined) parameters.set('limit', String(options.limit));
      if (options.offset !== undefined) parameters.set('offset', String(options.offset));
      const suffix = parameters.size > 0 ? `?${parameters.toString()}` : '';
      return json<Page<VulnerabilityObservationSummary>>(
        `${systemPath(systemId)}/vulnerability-observations/page${suffix}`,
      );
    },
    getVulnerabilityObservation: (systemId, observationId) =>
      json<VulnerabilityObservation>(
        `${systemPath(systemId)}/vulnerability-observations/${encodeURIComponent(observationId)}`,
      ),
    listFindingPage: (systemId, options = {}) => {
      const parameters = new URLSearchParams();
      if (options.limit !== undefined) parameters.set('limit', String(options.limit));
      if (options.offset !== undefined) parameters.set('offset', String(options.offset));
      if (options.lifecycleStatus) parameters.set('lifecycle_status', options.lifecycleStatus);
      if (options.findingType) parameters.set('finding_type', options.findingType);
      if (options.needsReview !== undefined) {
        parameters.set('needs_review', String(options.needsReview));
      }
      const suffix = parameters.size > 0 ? `?${parameters.toString()}` : '';
      return json<Page<FindingSummary>>(`${systemPath(systemId)}/findings${suffix}`);
    },
    getFinding: (systemId, findingId) =>
      json<Finding>(`${systemPath(systemId)}/findings/${encodeURIComponent(findingId)}`),
    listFindingEvidence: (systemId, findingId) =>
      json<FindingEvidence[]>(
        `${systemPath(systemId)}/findings/${encodeURIComponent(findingId)}/evidence`,
      ),
    updateFindingLifecycle: (systemId, findingId, lifecycleStatus, reason) =>
      json<Finding>(
        `${systemPath(systemId)}/findings/${encodeURIComponent(findingId)}/lifecycle`,
        {
          method: 'PATCH',
          body: JSON.stringify({ lifecycle_status: lifecycleStatus, reason }),
        },
      ),
    listRiskPage: (systemId, options = {}) => {
      const parameters = new URLSearchParams();
      if (options.limit !== undefined) parameters.set('limit', String(options.limit));
      if (options.offset !== undefined) parameters.set('offset', String(options.offset));
      if (options.status) parameters.set('status', options.status);
      const suffix = parameters.size > 0 ? `?${parameters.toString()}` : '';
      return json<Page<RiskSummary>>(`${systemPath(systemId)}/risks${suffix}`);
    },
    getRisk: (systemId, riskId) =>
      json<Risk>(`${systemPath(systemId)}/risks/${encodeURIComponent(riskId)}`),
    syncIntelligence: (systemId, provider) =>
      json<IntelligenceSyncResult>(
        `${systemPath(systemId)}/intelligence/sync/${encodeURIComponent(provider)}`,
        { method: 'POST' },
      ),
    listGlobalIntel: (filters = {}) => {
      const parameters = new URLSearchParams();
      if (filters.sourceKind) parameters.set('source_kind', filters.sourceKind);
      if (filters.recordType) parameters.set('record_type', filters.recordType);
      if (filters.query) parameters.set('query', filters.query);
      if (filters.reviewStatus) parameters.set('review_status', filters.reviewStatus);
      if (filters.limit !== undefined) parameters.set('limit', String(filters.limit));
      if (filters.offset !== undefined) parameters.set('offset', String(filters.offset));
      const suffix = parameters.size > 0 ? `?${parameters.toString()}` : '';
      return json<GlobalIntelPage>(`/intelligence/records${suffix}`);
    },
    reviewGlobalIntel: (recordId, decision, note) =>
      json<IntelReviewResult>(
        `/intelligence/records/${encodeURIComponent(recordId)}/review`,
        {
          method: 'PATCH',
          body: JSON.stringify({ decision, ...(note ? { note } : {}) }),
        },
      ),
    getExternalIntelligenceConnector: () =>
      json<ExternalIntelligenceConnectorView>('/intelligence/connectors/external'),
    configureExternalIntelligenceConnector: (input) =>
      json<ExternalIntelligenceConnectorView>('/intelligence/connectors/external', {
        method: 'PUT',
        body: JSON.stringify(input),
      }),
    getExternalIntelligenceSyncStatus: () =>
      json<ExternalIntelligenceSyncStatus>('/intelligence/sync/external/status'),
    listExternalIntelligenceSyncRuns: (options = {}) => {
      const parameters = new URLSearchParams();
      if (options.limit !== undefined) parameters.set('limit', String(options.limit));
      if (options.offset !== undefined) parameters.set('offset', String(options.offset));
      const suffix = parameters.size > 0 ? `?${parameters.toString()}` : '';
      return json<ExternalIntelligenceSyncRunList>(
        `/intelligence/sync/external/runs${suffix}`,
      );
    },
    syncExternalIntelligence: (maxPages = 10) =>
      json<ExternalIntelligencePullResult>('/intelligence/sync/external', {
        method: 'POST',
        body: JSON.stringify({ max_pages: maxPages }),
      }),
    correlateGlobalIntel: (systemId) =>
      json<IntelCorrelationResult>(`${systemPath(systemId)}/intelligence/correlate`, {
        method: 'POST',
      }),
    syncNetBox: (systemId) =>
      json<AssetSourceSnapshot>(`${systemPath(systemId)}/asset-sources/netbox/sync`, {
        method: 'POST',
      }),
    listAssetSourceSnapshots: (systemId) =>
      json<AssetSourceSnapshot[]>(`${systemPath(systemId)}/asset-sources/snapshots`),
    listReports: (systemId) => json<Report[]>(`${systemPath(systemId)}/reports`),
    createReport: (systemId, format, reportType) =>
      json<Report>(`${systemPath(systemId)}/reports`, {
        method: 'POST',
        body: JSON.stringify({ format, report_type: reportType }),
      }),
    enqueueReport: (systemId, format, reportType, idempotencyKey) =>
      json<BackgroundJobEnqueueResult>(`${systemPath(systemId)}/reports/async`, {
        method: 'POST',
        body: JSON.stringify({ format, report_type: reportType }),
        headers: { 'Idempotency-Key': idempotencyKey },
      }),
    listBackgroundJobs: (options = {}) => {
      const parameters = new URLSearchParams();
      if (options.status) parameters.set('status', options.status);
      if (options.jobType) parameters.set('job_type', options.jobType);
      if (options.systemId) parameters.set('system_id', options.systemId);
      if (options.limit !== undefined) parameters.set('limit', String(options.limit));
      if (options.offset !== undefined) parameters.set('offset', String(options.offset));
      const suffix = parameters.size > 0 ? `?${parameters.toString()}` : '';
      return json<BackgroundJobList>(`/jobs${suffix}`);
    },
    getBackgroundJob: (jobId) =>
      json<BackgroundJob>(`/jobs/${encodeURIComponent(jobId)}`),
    cancelBackgroundJob: (jobId) =>
      json<BackgroundJob>(`/jobs/${encodeURIComponent(jobId)}/cancel`, {
        method: 'POST',
      }),
    async downloadReport(reportId) {
      const headers = requestHeaders({ Accept: 'application/octet-stream' });
      const response = await fetchImpl(
        `${baseUrl}/reports/${encodeURIComponent(reportId)}/download`,
        { credentials: 'same-origin', headers },
      );
      if (!response.ok) throw await responseError(response);
      return {
        blob: await response.blob(),
        filename: safeFilename(
          response.headers.get('Content-Disposition'),
          `traceless-report-${reportId}`,
        ),
        sha256: response.headers.get('X-Content-SHA256'),
      };
    },
  };
}

export const operationalApi = createOperationalApi();
