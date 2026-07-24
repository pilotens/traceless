import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, test, vi } from 'vitest';

import type {
  Asset,
  BackgroundJob,
  BackgroundJobEnqueueResult,
  BackgroundJobList,
  BackgroundJobListOptions,
  ExternalIntelligenceSyncRunList,
  ExternalIntelligenceSyncStatus,
  GlobalIntelFilters,
  GlobalIntelPage,
  GlobalIntelRecord,
  IntelligenceSyncResult,
  OperationalApi,
  OperationalPrincipal,
  OperationalSystem,
  PipelineOverview,
  Project,
  Report,
  ReportFormat,
  ReportType,
  ScanAuthorization,
  ScanJob,
  VulnerabilityScanImportInput,
} from '../api';
import { OperationalWorkspace } from './OperationalWorkspace';

const now = '2026-07-17T12:00:00Z';

const principal: OperationalPrincipal = {
  subject: 'analyst-1',
  actor: 'oidc:analyst-1',
  organization_id: 'organization-1',
  organization_name: 'North-Bridge Security',
  project_ids: null,
  system_ids: null,
  roles: ['admin', 'analyst'],
  capabilities: [
    'read_operational',
    'analyze',
    'manage_scans',
    'ingest_intelligence',
    'administer',
  ],
  authentication_method: 'oidc',
};

const project: Project = {
  id: 'project-1',
  name: 'Betalplattform',
  description: 'Operativt projekt',
  created_at: now,
  updated_at: now,
};

const system: OperationalSystem = {
  id: 'system-1',
  project_id: project.id,
  name: 'Payment API',
  description: 'Internetnära betalningsflöde',
  owner: 'Security Team',
  criticality: 'critical',
  created_at: now,
  updated_at: now,
};

const authorization: ScanAuthorization = {
  id: 'authorization-1',
  system_id: system.id,
  targets: ['192.0.2.10/32'],
  profile: 'service_inventory',
  approved_by: 'Systemägare',
  purpose: 'Godkänd säkerhetsinventering inför riskanalys',
  expires_at: '2026-07-17T13:00:00Z',
  scope_sha256: 'a'.repeat(64),
  status: 'active',
  created_at: now,
};

const completedScan: ScanJob = {
  id: 'scan-1',
  system_id: system.id,
  authorization_id: authorization.id,
  scanner: 'nmap',
  mode: 'import',
  status: 'completed',
  requested_at: now,
  started_at: now,
  completed_at: now,
  raw_evidence_sha256: 'b'.repeat(64),
  result_summary: { assets_observed: 1, services_observed: 1 },
  error_code: null,
  error_message: null,
};

const queuedScan: ScanJob = {
  ...completedScan,
  id: 'scan-queued',
  mode: 'live',
  status: 'queued',
  started_at: null,
  completed_at: null,
  raw_evidence_sha256: null,
  result_summary: {},
};

const asset: Asset = {
  id: 'asset-1',
  system_id: system.id,
  source_scan_id: completedScan.id,
  primary_ip: '192.0.2.10',
  hostname: 'payments.example.test',
  mac_address: '02:42:ac:11:00:02',
  state: 'up',
  os_family: 'Linux 6.x',
  os_accuracy: 96,
  first_seen_at: now,
  last_seen_at: now,
  observation_count: 2,
  inventory_status: 'current',
};

const overview: PipelineOverview = {
  system,
  latest_scan: completedScan,
  latest_architecture: {
    id: 'architecture-1',
    system_id: system.id,
    source_scan_id: completedScan.id,
    base_snapshot_id: null,
    version: 1,
    status: 'draft',
    source_type: 'scan',
    layer: 'observed',
    title: 'Skanningshärlett arkitekturutkast',
    change_note: 'Automatiskt utkast från skanning.',
    created_by: 'scanner-pipeline',
    created_at: now,
    graph: {
      warning: 'Scanner observations create a reviewable draft.',
      zones: [
        {
          id: 'subnet:192.0.2.0/24',
          name: '192.0.2.0/24',
          trust_boundary: 'unconfirmed',
        },
      ],
      nodes: [
        {
          id: asset.id,
          name: 'payments.example.test',
          kind: 'asset',
          zone_id: 'subnet:192.0.2.0/24',
          properties: { ip: asset.primary_ip, os: asset.os_family },
        },
        {
          id: 'service:service-1',
          name: 'Apache httpd',
          kind: 'service',
          asset_id: asset.id,
          properties: { port: 443, protocol: 'tcp' },
        },
      ],
      edges: [{ id: 'edge-1', source: asset.id, target: 'service:service-1' }],
    },
  },
  assets: [asset],
  services: [
    {
      id: 'service-1',
      asset_id: asset.id,
      scan_job_id: completedScan.id,
      port: 443,
      protocol: 'tcp',
      state: 'open',
      service_name: 'https',
      product: 'Apache httpd',
      version: '0.0.0',
      cpes: ['cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*'],
      confidence: 1,
    },
  ],
  findings: [
    {
      id: 'finding-1',
      system_id: system.id,
      scan_job_id: completedScan.id,
      asset_id: asset.id,
      service_id: 'service-1',
      stable_key: 'cve:CVE-2099-12345:asset-1:service-1',
      finding_type: 'vulnerability',
      cve_id: 'CVE-2099-12345',
      title: 'Observed-version candidate',
      status: 'candidate',
      lifecycle_status: 'open',
      match_confidence: 0.8,
      match_reason: 'Exact CPE candidate match',
      cvss_score: 8.8,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
      epss_score: 0.73,
      epss_percentile: 0.98,
      is_kev: true,
      kev_due_date: '2026-08-05',
      sources: [],
      primary_evidence_strength: 80,
      first_seen_at: now,
      last_seen_at: now,
      status_updated_at: now,
      resolved_at: null,
      occurrence_count: 1,
      created_at: now,
      inventory_status: 'current',
    },
  ],
  threats: [
    {
      id: 'threat-1',
      system_id: system.id,
      source: 'internal-feed',
      external_id: 'indicator-1',
      title: 'Current campaign indicator',
      description: 'Correlated through a CVE reference.',
      severity: 'high',
      confidence: 0.85,
      attack_patterns: ['T1190'],
      affected_products: ['Apache httpd'],
      matched_asset_ids: [asset.id],
      provenance: { source: 'internal' },
      modified_at: now,
      ingested_at: now,
    },
  ],
  risks: [
    {
      id: 'risk-1',
      system_id: system.id,
      finding_id: 'finding-1',
      threat_id: null,
      title: 'Exploitation of CVE-2099-12345',
      likelihood: 5,
      impact: 5,
      score: 25,
      level: 'critical',
      status: 'open',
      rationale: { signals: { kev: true, epss: 0.73 } },
      created_at: now,
      evidence_status: 'current',
    },
  ],
  collection_totals: {
    assets: 1,
    services: 1,
    findings: 1,
    threats: 1,
    risks: 1,
  },
  collection_limit: 50,
  collections_truncated: false,
};

const report: Report = {
  id: 'report-1',
  system_id: system.id,
  format: 'pdf',
  report_type: 'management',
  sha256: 'c'.repeat(64),
  distribution_tlp: 'TLP:AMBER',
  export_status: 'available',
  withdrawal_reason: null,
  created_at: now,
};

const queuedImportJob: BackgroundJob = {
  id: 'job-import-1',
  organization_id: principal.organization_id,
  system_id: system.id,
  job_type: 'normalized_vulnerability_import',
  status: 'queued',
  payload_schema_version: 1,
  payload_sha256: '7'.repeat(64),
  requested_by: principal.actor,
  requested_at: now,
  available_at: now,
  started_at: null,
  completed_at: null,
  lease_expires_at: null,
  heartbeat_at: null,
  attempt_count: 0,
  max_attempts: 3,
  cancel_requested_at: null,
  result: {},
  result_resource_type: null,
  result_resource_id: null,
  error_code: null,
  error_message: null,
};

const completedImportJob: BackgroundJob = {
  ...queuedImportJob,
  status: 'completed',
  started_at: now,
  completed_at: now,
  attempt_count: 1,
  result: {
    imported: 1,
    matched_assets: 1,
    matched_services: 1,
    promoted_findings: 1,
  },
  result_resource_type: 'vulnerability_scan_import',
  result_resource_id: 'vuln-import-1',
};

const queuedReportJob: BackgroundJob = {
  ...queuedImportJob,
  id: 'job-report-1',
  job_type: 'report_generation',
  payload_sha256: '8'.repeat(64),
};

const completedReportJob: BackgroundJob = {
  ...queuedReportJob,
  status: 'completed',
  started_at: now,
  completed_at: now,
  attempt_count: 1,
  result: {
    format: report.format,
    report_type: report.report_type,
    sha256: report.sha256,
  },
  result_resource_type: 'report',
  result_resource_id: report.id,
};

const syncResult: IntelligenceSyncResult = {
  provider: 'CISA KEV',
  fetched: 1,
  matched: 1,
  updated: 1,
  feed_version: '2026.07.17',
  payload_sha256: 'd'.repeat(64),
  warnings: ['KEV är katalogmedlemskap, inte ett numeriskt riskmått.'],
};

const intelRecord: GlobalIntelRecord = {
  id: 'intel-1',
  source_kind: 'news',
  provider: 'internal-cyber-scraper',
  external_id: 'article-2026-42',
  record_type: 'threat',
  title: 'Aktuell kampanj riktar sig mot Apache-tjänster',
  summary: 'Källsammanfattning med normaliserade CVE- och produktreferenser.',
  source_url: 'https://news.example.test/article-2026-42',
  published_at: now,
  modified_at: now,
  retrieved_at: now,
  severity: 'high',
  confidence: 0.84,
  cve_ids: ['CVE-2099-12345'],
  cpes: [],
  affected_products: ['Apache httpd'],
  mitre_attack_ids: ['T1190'],
  indicators: [],
  tags: ['initial-access'],
  sectors: ['finance'],
  regions: ['SE'],
  markings: ['TLP:CLEAR'],
  distribution_tlp: 'TLP:CLEAR',
  review_status: 'pending',
  reviewed_by: null,
  reviewed_at: null,
  review_note: null,
  valid_from: null,
  valid_until: null,
  revoked: false,
  raw_evidence: { source_title: 'Aktuell kampanj' },
  raw_sha256: 'f'.repeat(64),
  ai_analysis: {
    model_name: 'internal-classifier',
    prompt_version: '3',
    taxonomy_version: '2',
    confidence: 0.84,
  },
  analysis_sha256: '1'.repeat(64),
  vulnerability: null,
  feed_id: 'cyber-news',
  feed_version: '42',
  feed_generated_at: now,
  first_ingested_at: now,
  last_ingested_at: now,
};

function createApi() {
  return {
    getCurrentPrincipal: vi.fn(async () => principal),
    listProjects: vi.fn(async () => [project]),
    createProject: vi.fn(async () => project),
    listSystems: vi.fn(async () => [system]),
    createSystem: vi.fn(async () => system),
    createAuthorization: vi.fn(async () => authorization),
    listScans: vi.fn(async () => [completedScan]),
    queueNmapScan: vi.fn(async () => queuedScan),
    importNmapXml: vi.fn(async () => completedScan),
    getOverview: vi.fn(async (_systemId: string) => overview),
    listAssetPage: vi.fn(async () => ({
      items: overview.assets,
      total: overview.collection_totals?.assets ?? overview.assets.length,
      limit: 50,
      offset: 0,
      has_more: false,
    })),
    listServicePage: vi.fn(async (
      _systemId: string,
      options?: { assetId?: string; limit?: number; offset?: number },
    ) => {
      const items = overview.services.filter(
        (service) => !options?.assetId || service.asset_id === options.assetId,
      );
      return { items, total: items.length, limit: 50, offset: 0, has_more: false };
    }),
    listThreatPage: vi.fn(async () => ({
      items: overview.threats.map(({ description: _description, provenance: _provenance, ...item }) => item),
      total: overview.collection_totals?.threats ?? overview.threats.length,
      limit: 50,
      offset: 0,
      has_more: false,
    })),
    getThreat: vi.fn(async (_systemId: string, threatId: string) => {
      const threat = overview.threats.find((item) => item.id === threatId);
      if (!threat) throw new Error('Threat not found');
      return threat;
    }),
    listArchitectureVersions: vi.fn(async () =>
      overview.latest_architecture ? [overview.latest_architecture] : [],
    ),
    saveArchitectureVersion: vi.fn(async (_systemId, input) => ({
      ...(overview.latest_architecture as NonNullable<PipelineOverview['latest_architecture']>),
      id: 'architecture-2',
      base_snapshot_id: overview.latest_architecture?.id ?? null,
      version: 2,
      source_type: 'manual' as const,
      layer: 'manual' as const,
      title: input.title,
      change_note: input.change_note,
      created_by: 'operational-workspace',
      graph: input.graph,
    })),
    importNessusReport: vi.fn(async () => ({
      import_record: {
        id: 'vuln-import-1',
        system_id: system.id,
        provider: 'nessus' as const,
        source_format: 'nessus-xml',
        source_name: 'payment.nessus',
        scanner_version: '10.8',
        scan_started_at: now,
        scan_completed_at: now,
        imported_at: now,
        imported_by: 'operational-workspace',
        raw_sha256: '9'.repeat(64),
        report_metadata: {},
        observation_count: 1,
        asset_count: 1,
        matched_asset_count: 1,
        promoted_finding_count: 1,
      },
      imported: 1,
      matched_assets: 1,
      matched_services: 1,
      promoted_findings: 1,
      idempotent_replay: false,
      warnings: [],
    })),
    enqueueNessusImport: vi.fn(
      async (
        _systemId: string,
        _sourceName: string,
        _report: Blob,
        _idempotencyKey: string,
      ): Promise<BackgroundJobEnqueueResult> => ({
        job: queuedImportJob,
        idempotent_replay: false,
      }),
    ),
    enqueueNormalizedVulnerabilityImport: vi.fn(
      async (
        _systemId: string,
        _input: VulnerabilityScanImportInput,
        _idempotencyKey: string,
      ): Promise<BackgroundJobEnqueueResult> => ({
        job: queuedImportJob,
        idempotent_replay: false,
      }),
    ),
    importVulnerabilityScan: vi.fn(async () => {
      throw new Error('not used in this fixture');
    }),
    listVulnerabilityScans: vi.fn(async () => []),
    listVulnerabilityObservations: vi.fn(async () => []),
    listVulnerabilityObservationPage: vi.fn(async () => ({
      items: [],
      total: 0,
      limit: 50,
      offset: 0,
      has_more: false,
    })),
    getVulnerabilityObservation: vi.fn(async () => {
      throw new Error('not used in this fixture');
    }),
    listFindingPage: vi.fn(async () => ({
      items: overview.findings.map((finding) => ({
        id: finding.id,
        system_id: finding.system_id,
        asset_id: finding.asset_id,
        service_id: finding.service_id,
        finding_type: finding.finding_type,
        cve_id: finding.cve_id,
        title: finding.title,
        status: finding.status,
        lifecycle_status: finding.lifecycle_status,
        cvss_score: finding.cvss_score,
        epss_score: finding.epss_score,
        is_kev: finding.is_kev,
        kev_due_date: finding.kev_due_date,
        primary_evidence_strength: finding.primary_evidence_strength,
        first_seen_at: finding.first_seen_at,
        last_seen_at: finding.last_seen_at,
        resolved_at: finding.resolved_at,
        occurrence_count: finding.occurrence_count,
        inventory_status: finding.inventory_status,
      })),
      total: overview.findings.length,
      limit: 50,
      offset: 0,
      has_more: false,
    })),
    getFinding: vi.fn(async () => overview.findings[0]!),
    listFindingEvidence: vi.fn(async () => []),
    updateFindingLifecycle: vi.fn(async (_systemId, _findingId, lifecycleStatus) => ({
      ...overview.findings[0]!,
      lifecycle_status: lifecycleStatus,
      status_updated_at: now,
      resolved_at: lifecycleStatus === 'open' || lifecycleStatus === 'reopened' ? null : now,
    })),
    listRiskPage: vi.fn(async () => ({
      items: overview.risks.map((risk) => ({
        id: risk.id,
        system_id: risk.system_id,
        finding_id: risk.finding_id,
        threat_id: risk.threat_id,
        title: risk.title,
        likelihood: risk.likelihood,
        impact: risk.impact,
        score: risk.score,
        level: risk.level,
        status: risk.status,
        created_at: risk.created_at,
        evidence_status: risk.evidence_status,
      })),
      total: overview.risks.length,
      limit: 50,
      offset: 0,
      has_more: false,
    })),
    getRisk: vi.fn(async () => overview.risks[0]!),
    syncIntelligence: vi.fn(async () => syncResult),
    listGlobalIntel: vi.fn(async (_filters?: GlobalIntelFilters) => ({
      items: [intelRecord],
      total: 1,
      limit: 50,
      offset: 0,
    })),
    reviewGlobalIntel: vi.fn(async (_recordId, decision, note) => ({
      record: {
        ...intelRecord,
        review_status: decision,
        reviewed_by: principal.actor,
        reviewed_at: now,
        review_note: note ?? null,
      },
      correlation_job_ids: ['job-correlation-1'],
    })),
    getExternalIntelligenceConnector: vi.fn(async () => ({
      id: 'connector-1',
      organization_id: principal.organization_id,
      name: 'external_datapoints',
      endpoint: 'https://intel.example.test/api/datapoints',
      auth_scheme: 'Bearer' as const,
      credential_reference: 'tenant/intel-reader',
      enabled: true,
      sync_interval_seconds: 3600,
      next_sync_at: '2026-07-17T13:00:00Z',
      config_version: 1,
      created_by: principal.actor,
      created_at: now,
      updated_at: now,
    })),
    configureExternalIntelligenceConnector: vi.fn(async (input) => ({
      id: 'connector-1',
      organization_id: principal.organization_id,
      name: 'external_datapoints',
      ...input,
      next_sync_at: input.sync_interval_seconds ? '2026-07-17T13:00:00Z' : null,
      config_version: 2,
      created_by: principal.actor,
      created_at: now,
      updated_at: now,
    })),
    getExternalIntelligenceSyncStatus: vi.fn(async (): Promise<ExternalIntelligenceSyncStatus> => ({
      configured: true,
      connector_id: 'connector-1',
      endpoint: 'https://intel.example.test/api/datapoints',
      enabled: true,
      schedule_state: 'scheduled' as const,
      sync_interval_seconds: 3600,
      next_sync_at: '2026-07-17T13:00:00Z',
      config_version: 1,
      credential_available: true,
      checkpoint: null,
      latest_run: null,
    })),
    listExternalIntelligenceSyncRuns: vi.fn(async (): Promise<ExternalIntelligenceSyncRunList> => ({
      items: [],
      total: 0,
      limit: 10,
      offset: 0,
    })),
    syncExternalIntelligence: vi.fn(async () => ({
      run_id: 'external-run-1',
      feed_id: 'cyber-news',
      feed_version: '42',
      pages_fetched: 1,
      records_fetched: 1,
      batch_pages_fetched: 1,
      batch_records_fetched: 1,
      bytes_fetched: 512,
      batch_bytes_fetched: 512,
      created: 1,
      updated: 0,
      unchanged: 0,
      quarantined: 0,
      active: 1,
      revoked: 0,
      deleted: 0,
      complete: true,
      next_cursor: null,
      manifest_sha256: 'f'.repeat(64),
      correlation_jobs_queued: 1,
      warnings: [],
    })),
    correlateGlobalIntel: vi.fn(async () => ({
      system_id: system.id,
      scan_id: completedScan.id,
      records_considered: 1,
      vulnerability_records_applied: 0,
      finding_matches: 1,
      findings_created: 0,
      threat_records_matched: 1,
      threats_created: 1,
      risks_created: 1,
      warnings: [],
    })),
    syncNetBox: vi.fn(async () => ({
      id: 'snapshot-1',
      system_id: system.id,
      provider: 'netbox',
      source_base_url: 'https://netbox.example.test/',
      approval_state: 'unreviewed_source_snapshot' as const,
      manifest_sha256: 'e'.repeat(64),
      record_count: 1,
      page_count: 1,
      record_counts: { device: 1 },
      started_at: now,
      completed_at: now,
      created_at: now,
    })),
    listAssetSourceSnapshots: vi.fn(async () => []),
    listReports: vi.fn(async () => [] as Report[]),
    createReport: vi.fn(async () => report),
    enqueueReport: vi.fn(
      async (
        _systemId: string,
        _format: ReportFormat,
        _reportType: ReportType,
        _idempotencyKey: string,
      ): Promise<BackgroundJobEnqueueResult> => ({
        job: queuedReportJob,
        idempotent_replay: false,
      }),
    ),
    listBackgroundJobs: vi.fn(async (
      _options?: BackgroundJobListOptions,
    ): Promise<BackgroundJobList> => ({
      items: [],
      total: 0,
      limit: 50,
      offset: 0,
    })),
    getBackgroundJob: vi.fn(async (_jobId: string) =>
      _jobId === queuedReportJob.id ? completedReportJob : completedImportJob,
    ),
    cancelBackgroundJob: vi.fn(async (jobId: string) => ({
      ...(jobId === queuedReportJob.id ? queuedReportJob : queuedImportJob),
      status: 'cancelled' as const,
      completed_at: now,
    })),
    downloadReport: vi.fn(async () => ({
      blob: new Blob(['%PDF-fixture'], { type: 'application/pdf' }),
      filename: 'traceless-management-report.pdf',
      sha256: report.sha256,
    })),
  } satisfies OperationalApi;
}

describe('OperationalWorkspace', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  test('loads operational data and supports asset and architecture drill-down', async () => {
    const user = userEvent.setup();
    const api = createApi();
    render(<OperationalWorkspace api={api} />);

    expect(await screen.findByRole('heading', { name: 'Payment API' })).toBeInTheDocument();
    expect(screen.getByText('Auktoriserad användning krävs')).toBeInTheDocument();
    expect(screen.getByText(/ingen kontinuerlig liveinsamling hävdas/i)).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: /Tillgångar/ }));
    await user.click(screen.getByRole('button', { name: /payments\.example\.test/ }));
    expect(screen.getByText(/Apache httpd 0\.0\.0/)).toBeInTheDocument();
    expect(screen.getByText(/sett från en skanningspunkt vid en tidpunkt/i)).toBeInTheDocument();
    expect(screen.getAllByText('Aktuell inventering').length).toBeGreaterThan(0);
    expect(screen.getByText('Observationer').parentElement).toHaveTextContent('2');

    await user.click(screen.getByRole('tab', { name: 'Arkitektur' }));
    expect(screen.getByText('Rita komponenter och dataflöden')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Arkitekturversion' })).toHaveValue(
      'architecture-1',
    );
    expect(screen.getByText('Apache httpd')).toBeInTheDocument();
    expect(screen.getByText(/2 komponenter/)).toBeInTheDocument();
  });

  test('moves a newly created system into a fresh fenced system context', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const createdSystem: OperationalSystem = {
      ...system,
      id: 'system-created',
      name: 'Settlement API',
    };
    api.createSystem.mockResolvedValue(createdSystem);
    api.getOverview.mockImplementation(async (systemId) => ({
      ...overview,
      system: systemId === createdSystem.id ? createdSystem : system,
    }));
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    const systemForm = screen.getByText('Nytt system').closest('details');
    expect(systemForm).not.toBeNull();
    await user.type(within(systemForm!).getByLabelText('Namn'), createdSystem.name);
    await user.type(within(systemForm!).getByLabelText('Ägare'), 'Platform Team');
    await user.click(within(systemForm!).getByRole('button', { name: 'Skapa system' }));

    await waitFor(() =>
      expect(api.createSystem).toHaveBeenCalledWith(project.id, {
        name: createdSystem.name,
        description: '',
        owner: 'Platform Team',
        criticality: 'medium',
      }),
    );
    expect(await screen.findByRole('heading', { name: createdSystem.name })).toBeInTheDocument();
    await waitFor(() => expect(api.getOverview).toHaveBeenCalledWith(createdSystem.id));
  });

  test('loads services for the selected asset instead of trusting the truncated overview', async () => {
    const user = userEvent.setup();
    const api = createApi();
    api.getOverview.mockResolvedValue({
      ...overview,
      services: [],
      collections_truncated: true,
    });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: /Tillgångar/ }));

    await waitFor(() =>
      expect(api.listServicePage).toHaveBeenCalledWith(system.id, {
        assetId: asset.id,
        limit: 50,
        offset: 0,
      }),
    );
    expect(await screen.findByText(/Apache httpd 0\.0\.0/)).toBeInTheDocument();
    expect(
      screen.queryByText(/Inga tjänster observerades för denna tillgång/i),
    ).not.toBeInTheDocument();
  });

  test('pages assets and selects the first asset on the requested page', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const lastAsset: Asset = {
      ...asset,
      id: 'asset-51',
      primary_ip: '192.0.2.61',
      hostname: 'last.example.test',
    };
    api.getOverview.mockResolvedValue({
      ...overview,
      collection_totals: { ...overview.collection_totals, assets: 51 },
      collections_truncated: true,
    });
    api.listAssetPage
      .mockResolvedValueOnce({
        items: [asset],
        total: 51,
        limit: 50,
        offset: 0,
        has_more: true,
      })
      .mockResolvedValueOnce({
        items: [lastAsset],
        total: 51,
        limit: 50,
        offset: 50,
        has_more: false,
      });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(await screen.findByRole('tab', { name: /Tillgångar51/ }));
    await user.click(screen.getByRole('button', { name: 'Nästa' }));

    await waitFor(() =>
      expect(api.listAssetPage).toHaveBeenLastCalledWith(system.id, {
        limit: 50,
        offset: 50,
      }),
    );
    expect(await screen.findAllByText('last.example.test')).not.toHaveLength(0);
    expect(screen.getByText('51–51 av 51')).toBeInTheDocument();
    await waitFor(() =>
      expect(api.listServicePage).toHaveBeenLastCalledWith(system.id, {
        assetId: lastAsset.id,
        limit: 50,
        offset: 0,
      }),
    );
  });

  test('pages threat summaries and loads large threat detail only when expanded', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const firstThreat = overview.threats[0]!;
    const firstSummary = {
      id: firstThreat.id,
      system_id: firstThreat.system_id,
      source: firstThreat.source,
      external_id: firstThreat.external_id,
      title: firstThreat.title,
      severity: firstThreat.severity,
      confidence: firstThreat.confidence,
      attack_patterns: firstThreat.attack_patterns,
      affected_products: firstThreat.affected_products,
      matched_asset_ids: firstThreat.matched_asset_ids,
      modified_at: firstThreat.modified_at,
      ingested_at: firstThreat.ingested_at,
    };
    api.getOverview.mockResolvedValue({
      ...overview,
      collection_totals: { ...overview.collection_totals, threats: 51 },
      collections_truncated: true,
    });
    api.listThreatPage
      .mockResolvedValueOnce({
        items: [firstSummary],
        total: 51,
        limit: 50,
        offset: 0,
        has_more: true,
      })
      .mockResolvedValueOnce({
        items: [{ ...firstSummary, id: 'threat-51', title: 'Sista hotet' }],
        total: 51,
        limit: 50,
        offset: 50,
        has_more: false,
      });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(await screen.findByRole('tab', { name: /Hot51/ }));
    expect(api.getThreat).not.toHaveBeenCalled();
    expect(screen.queryByText(firstThreat.description)).not.toBeInTheDocument();
    await user.click(screen.getByText(firstThreat.title));
    await waitFor(() => expect(api.getThreat).toHaveBeenCalledWith(system.id, firstThreat.id));
    expect(await screen.findByText(firstThreat.description)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Nästa' }));
    await waitFor(() =>
      expect(api.listThreatPage).toHaveBeenLastCalledWith(system.id, {
        limit: 50,
        offset: 50,
      }),
    );
    expect(await screen.findByText('Sista hotet')).toBeInTheDocument();
    expect(screen.getByText('51–51 av 51')).toBeInTheDocument();
  });

  test('does not claim that API data loaded when the initial request fails', async () => {
    const api = createApi();
    api.listProjects.mockRejectedValueOnce(new Error('Backend är inte tillgänglig'));
    render(<OperationalWorkspace api={api} />);

    expect(await screen.findByText('API-data kunde inte läsas')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Backend är inte tillgänglig');
    expect(screen.queryByText('API-data inläst')).not.toBeInTheDocument();
  });

  test('creates an exact authorization before queueing or importing Nmap data', async () => {
    const user = userEvent.setup();
    const api = createApi();
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.type(screen.getByLabelText('IP eller CIDR, en per rad'), '192.0.2.10');
    await user.type(screen.getByLabelText('Godkänd av'), 'Systemägare');
    await user.type(
      screen.getByLabelText('Syfte'),
      'Godkänd säkerhetsinventering inför riskanalys',
    );
    await user.click(screen.getByRole('checkbox', { name: /jag bekräftar/i }));
    await user.click(screen.getByRole('button', { name: 'Skapa auktorisering' }));

    await waitFor(() => expect(api.createAuthorization).toHaveBeenCalledOnce());
    expect(api.createAuthorization).toHaveBeenCalledWith(
      system.id,
      expect.objectContaining({
        targets: ['192.0.2.10'],
        profile: 'service_inventory',
        approved_by: 'Systemägare',
        confirmation: 'Jag bekräftar att jag har tillstånd att skanna angivna mål.',
      }),
    );

    await user.click(screen.getByRole('button', { name: /Köa extern Nmap-worker/ }));
    await waitFor(() => expect(api.queueNmapScan).toHaveBeenCalledWith(system.id, authorization.id));
    expect(screen.getByText(/det betyder inte att den körs/i)).toBeInTheDocument();

    const file = new File(['<nmaprun scanner="nmap"/>'], 'authorized-scan.xml', {
      type: 'application/xml',
    });
    await user.upload(screen.getByLabelText('Nmap XML-fil'), file);
    await user.click(screen.getByRole('button', { name: 'Validera och importera XML' }));
    await waitFor(() =>
      expect(api.importNmapXml).toHaveBeenCalledWith(system.id, authorization.id, file),
    );
  });

  test('starts with no scan target and clears system-scoped forms and files on system change', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const secondSystem: OperationalSystem = {
      ...system,
      id: 'system-2',
      name: 'Settlement API',
    };
    api.listSystems.mockResolvedValue([system, secondSystem]);
    api.getOverview.mockImplementation(async (systemId) => ({
      ...overview,
      system: systemId === secondSystem.id ? secondSystem : system,
    }));
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    const targetInput = screen.getByLabelText('IP eller CIDR, en per rad');
    expect(targetInput).toHaveValue('');
    expect(targetInput).toHaveAttribute('placeholder', 'Ange ett uttryckligen godkänt mål');
    await user.type(targetInput, '192.0.2.10');
    await user.type(screen.getByLabelText('Godkänd av'), 'Systemägare');
    await user.type(screen.getByLabelText('Syfte'), 'Avgränsad verifiering i testmiljö');
    await user.click(screen.getByRole('checkbox', { name: /jag bekräftar/i }));
    const nmapFile = new File(['<nmaprun/>'], 'first-system.xml', {
      type: 'application/xml',
    });
    await user.upload(screen.getByLabelText('Nmap XML-fil'), nmapFile);

    await user.click(screen.getByRole('tab', { name: /Fynd/ }));
    const vulnerabilityFile = new File(['<NessusClientData_v2/>'], 'first-system.nessus', {
      type: 'application/xml',
    });
    await user.upload(screen.getByLabelText('Sårbarhetsrapport'), vulnerabilityFile);
    expect((screen.getByLabelText('Sårbarhetsrapport') as HTMLInputElement).files?.[0]).toBe(
      vulnerabilityFile,
    );

    await user.selectOptions(screen.getByLabelText('Valt system'), secondSystem.id);
    await screen.findByRole('heading', { name: 'Settlement API' });

    expect(screen.getByLabelText('IP eller CIDR, en per rad')).toHaveValue('');
    expect(screen.getByLabelText('Godkänd av')).toHaveValue('');
    expect(screen.getByLabelText('Syfte')).toHaveValue('');
    expect(screen.getByRole('checkbox', { name: /jag bekräftar/i })).not.toBeChecked();
    expect(screen.getByLabelText('Nmap XML-fil')).toHaveValue('');
    expect(screen.getByLabelText('Sårbarhetsrapport')).toHaveValue('');
    expect(screen.getByRole('button', { name: /^Validera och köa import$/ })).toBeDisabled();
  });

  test('does not apply a late operational refresh after the selected system changes', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const secondSystem: OperationalSystem = {
      ...system,
      id: 'system-2',
      name: 'Settlement API',
      description: 'Separat avvecklingsflöde',
    };
    let resolveStaleOverview!: (value: PipelineOverview) => void;
    const staleOverview = new Promise<PipelineOverview>((resolve) => {
      resolveStaleOverview = resolve;
    });
    let firstSystemOverviewCalls = 0;
    api.listSystems.mockResolvedValue([system, secondSystem]);
    api.getOverview.mockImplementation(async (systemId) => {
      if (systemId === secondSystem.id) return { ...overview, system: secondSystem };
      firstSystemOverviewCalls += 1;
      return firstSystemOverviewCalls === 1 ? overview : staleOverview;
    });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('button', { name: 'Uppdatera' }));
    await waitFor(() => expect(api.getOverview).toHaveBeenCalledTimes(2));
    await user.selectOptions(screen.getByLabelText('Valt system'), secondSystem.id);
    expect(await screen.findByRole('heading', { name: 'Settlement API' })).toBeInTheDocument();

    await act(async () => {
      resolveStaleOverview(overview);
      await staleOverview;
    });

    expect(screen.getByRole('heading', { name: 'Settlement API' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Payment API' })).not.toBeInTheDocument();
    expect(screen.getByText('Separat avvecklingsflöde')).toBeInTheDocument();
  });

  test('draws a component, saves a new architecture version and imports Nessus evidence', async () => {
    const user = userEvent.setup();
    const api = createApi();
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: 'Arkitektur' }));
    await user.click(screen.getByRole('button', { name: /Databas/ }));
    const nameInput = screen.getByRole('textbox', { name: 'Komponentnamn' });
    await user.clear(nameInput);
    await user.type(nameInput, 'Transaktionsdatabas');
    await user.type(
      screen.getByPlaceholderText('Vad ändrades i den här versionen?'),
      'Lade till datalager',
    );
    await user.click(screen.getByRole('button', { name: /Spara som ny version/ }));
    await waitFor(() => expect(api.saveArchitectureVersion).toHaveBeenCalledOnce());
    expect(api.saveArchitectureVersion).toHaveBeenCalledWith(
      system.id,
      expect.objectContaining({
        base_snapshot_id: 'architecture-1',
        change_note: 'Lade till datalager',
        graph: expect.objectContaining({
          nodes: expect.arrayContaining([
            expect.objectContaining({ name: 'Transaktionsdatabas', kind: 'database' }),
          ]),
        }),
      }),
    );

    await user.click(screen.getByRole('tab', { name: /Fynd/ }));
    expect(screen.getByText('DIREKTSTÖD: TENABLE NESSUS')).toBeInTheDocument();
    expect(screen.getByText('Direkt filimport: Tenable Nessus')).toBeInTheDocument();
    expect(
      screen.getByText(/stöds ännu inte som direkta filformat/i),
    ).toBeInTheDocument();
    const nessusFile = new File(['<NessusClientData_v2/>'], 'payment.nessus', {
      type: 'application/xml',
    });
    await user.upload(screen.getByLabelText('Sårbarhetsrapport'), nessusFile);
    await user.click(screen.getByRole('button', { name: /^Validera och köa import$/ }));
    await waitFor(() =>
      expect(api.enqueueNessusImport).toHaveBeenCalledWith(
        system.id,
        'payment.nessus',
        nessusFile,
        expect.stringMatching(/^vulnerability-/),
      ),
    );
    expect(await screen.findByText(/Importjobbet slutfördes: 1 observationer/i)).toBeInTheDocument();
  });

  test('reuses the upload idempotency key after a failed enqueue', async () => {
    const user = userEvent.setup();
    const api = createApi();
    api.enqueueNessusImport
      .mockRejectedValueOnce(new Error('Tillfälligt nätverksfel'))
      .mockResolvedValueOnce({ job: queuedImportJob, idempotent_replay: false });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: /Fynd/ }));
    const nessusFile = new File(['<NessusClientData_v2/>'], 'retry.nessus', {
      type: 'application/xml',
    });
    await user.upload(screen.getByLabelText('Sårbarhetsrapport'), nessusFile);
    await user.click(screen.getByRole('button', { name: /^Validera och köa import$/ }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Tillfälligt nätverksfel');
    const firstKey = api.enqueueNessusImport.mock.calls[0]?.[3];

    await user.click(screen.getByRole('button', { name: /^Validera och köa import$/ }));
    await waitFor(() => expect(api.enqueueNessusImport).toHaveBeenCalledTimes(2));

    expect(firstKey).toMatch(/^vulnerability-/);
    expect(api.enqueueNessusImport.mock.calls[1]?.[3]).toBe(firstKey);
    expect(screen.queryByText(/NessusClientData_v2/)).not.toBeInTheDocument();
  });

  test('supports undo and redo and warns before discarding unsaved architecture changes', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: 'Arkitektur' }));
    expect(screen.getByText(/2 komponenter/)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Ångra senaste diagramändringen' }),
    ).toBeDisabled();

    await user.click(screen.getByRole('button', { name: /Databas/ }));
    expect(screen.getByText(/3 komponenter/)).toBeInTheDocument();
    expect(screen.getByText(/osparade arkitekturändringar/i)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Ångra senaste diagramändringen' }));
    expect(screen.getByText(/2 komponenter/)).toBeInTheDocument();
    expect(screen.queryByText(/osparade arkitekturändringar/i)).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Gör om senaste diagramändringen' }));
    expect(screen.getByText(/3 komponenter/)).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: /Fynd/ }));
    expect(confirm).toHaveBeenCalledOnce();
    expect(screen.getByText('Rita komponenter och dataflöden')).toBeInTheDocument();

    confirm.mockReturnValue(true);
    await user.click(screen.getByRole('tab', { name: /Fynd/ }));
    expect(screen.getByText('Direkt filimport: Tenable Nessus')).toBeInTheDocument();
  });

  test('keeps the architecture dirty when saving fails', async () => {
    const user = userEvent.setup();
    const api = createApi();
    api.saveArchitectureVersion.mockRejectedValueOnce(new Error('Versionskonflikt från API'));
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: 'Arkitektur' }));
    await user.click(screen.getByRole('button', { name: /Databas/ }));
    await user.click(screen.getByRole('button', { name: /Spara som ny version/ }));

    expect(await screen.findByText(/Versionskonflikt från API/)).toBeInTheDocument();
    expect(screen.getByText(/Osparade arkitekturändringar/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Spara som ny version/ })).not.toBeDisabled();
  });

  test('does not create and auto-switch project or system while dirty discard is rejected', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: 'Arkitektur' }));
    await user.click(screen.getByRole('button', { name: /Databas/ }));
    expect(screen.getByText(/Osparade arkitekturändringar/)).toBeInTheDocument();

    const projectDetails = screen.getByText('Nytt projekt').closest('details');
    expect(projectDetails).not.toBeNull();
    await user.type(within(projectDetails!).getByLabelText('Namn'), 'Nytt projekt');
    await user.click(within(projectDetails!).getByRole('button', { name: 'Skapa projekt' }));
    expect(api.createProject).not.toHaveBeenCalled();

    const systemDetails = screen.getByText('Nytt system').closest('details');
    expect(systemDetails).not.toBeNull();
    await user.type(within(systemDetails!).getByLabelText('Namn'), 'Nytt system');
    await user.type(within(systemDetails!).getByLabelText('Ägare'), 'Security Team');
    await user.click(within(systemDetails!).getByRole('button', { name: 'Skapa system' }));
    expect(api.createSystem).not.toHaveBeenCalled();
    expect(confirm).toHaveBeenCalledTimes(2);
    expect(screen.getByText(/Osparade arkitekturändringar/)).toBeInTheDocument();
  });

  test('keeps the manual layer editable when a newer observed topology exists', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const observed = overview.latest_architecture!;
    const manual = {
      ...observed,
      id: 'architecture-manual-2',
      version: 2,
      source_type: 'manual' as const,
      layer: 'manual' as const,
      base_snapshot_id: observed.id,
      title: 'Granskad betalarkitektur',
    };
    const newestObserved = {
      ...observed,
      id: 'architecture-observed-3',
      version: 3,
      layer: 'observed' as const,
      base_snapshot_id: observed.id,
    };
    api.getOverview.mockResolvedValue({ ...overview, latest_architecture: manual });
    api.listArchitectureVersions.mockResolvedValue([newestObserved, manual, observed]);
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: 'Arkitektur' }));
    expect(screen.getByText(/nya skanningar ersätter det inte/i)).toBeInTheDocument();
    expect(screen.queryByText(/historisk version av detta lager/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Databas/ }));
    await user.click(screen.getByRole('button', { name: /Spara som ny version/ }));

    await waitFor(() => expect(api.saveArchitectureVersion).toHaveBeenCalledOnce());
    expect(api.saveArchitectureVersion).toHaveBeenCalledWith(
      system.id,
      expect.objectContaining({ base_snapshot_id: manual.id }),
    );
  });

  test('shows non-CVE findings and lets an analyst document lifecycle decisions', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const nonCveFinding = {
      ...overview.findings[0]!,
      id: 'finding-tls',
      stable_key: 'scanner:nessus:plugin-104743:asset-1:443',
      finding_type: 'misconfiguration' as const,
      cve_id: null,
      title: 'TLS 1.0 is enabled',
      cvss_score: null,
      epss_score: null,
      epss_percentile: null,
      is_kev: false,
      kev_due_date: null,
    };
    api.getOverview.mockResolvedValue({ ...overview, findings: [nonCveFinding] });
    api.listFindingPage.mockResolvedValue({
      items: [
        {
          id: nonCveFinding.id,
          system_id: nonCveFinding.system_id,
          asset_id: nonCveFinding.asset_id,
          service_id: nonCveFinding.service_id,
          finding_type: nonCveFinding.finding_type,
          cve_id: nonCveFinding.cve_id,
          title: nonCveFinding.title,
          status: nonCveFinding.status,
          lifecycle_status: nonCveFinding.lifecycle_status,
          cvss_score: nonCveFinding.cvss_score,
          epss_score: nonCveFinding.epss_score,
          is_kev: nonCveFinding.is_kev,
          kev_due_date: nonCveFinding.kev_due_date,
          primary_evidence_strength: nonCveFinding.primary_evidence_strength,
          first_seen_at: nonCveFinding.first_seen_at,
          last_seen_at: nonCveFinding.last_seen_at,
          resolved_at: nonCveFinding.resolved_at,
          occurrence_count: nonCveFinding.occurrence_count,
          inventory_status: nonCveFinding.inventory_status,
        },
      ],
      total: 1,
      limit: 50,
      offset: 0,
      has_more: false,
    });
    api.getFinding.mockResolvedValue(nonCveFinding);
    api.updateFindingLifecycle.mockResolvedValue({
      ...nonCveFinding,
      lifecycle_status: 'accepted',
      resolved_at: now,
    });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: /Fynd/ }));
    await user.click(screen.getByText(/TLS 1\.0 is enabled/));
    expect(screen.getAllByText('Felkonfiguration').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Ej relevant')).toHaveLength(2);
    await user.selectOptions(
      screen.getByRole('combobox', { name: /Ny livscykelstatus/ }),
      'accepted',
    );
    await user.type(screen.getByRole('textbox', { name: /Motivering/ }), 'Kompenserad kontroll');
    await user.click(screen.getByRole('button', { name: 'Spara status' }));

    await waitFor(() =>
      expect(api.updateFindingLifecycle).toHaveBeenCalledWith(
        system.id,
        nonCveFinding.id,
        'accepted',
        'Kompenserad kontroll',
      ),
    );
  });

  test('hides mutation controls for a read-only viewer', async () => {
    const user = userEvent.setup();
    const api = createApi();
    api.getCurrentPrincipal.mockResolvedValue({
      ...principal,
      roles: ['viewer'],
      capabilities: ['read_operational'],
    });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    expect(screen.queryByText('Nytt projekt')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Skapa auktorisering' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /CISA KEV/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Köa rapport' })).not.toBeInTheDocument();
    expect(api.listGlobalIntel).not.toHaveBeenCalled();
    await user.click(screen.getByRole('tab', { name: /Omvärld/ }));
    expect(screen.queryByRole('heading', { name: 'Extern datapunktsconnector' })).not.toBeInTheDocument();
    expect(screen.getByText(/tenantens råa intelligensmaterial visas inte/i)).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Arkitektur' }));
    expect(screen.getByText(/Din roll har läsbehörighet/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Spara som ny version/ })).toBeDisabled();
  });

  test('shows only system-scoped jobs and lets an analyst cancel active work', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const foreignJob: BackgroundJob = {
      ...queuedReportJob,
      id: 'job-foreign',
      system_id: 'system-foreign',
    };
    api.listBackgroundJobs.mockResolvedValue({
      items: [queuedImportJob, foreignJob],
      total: 2,
      limit: 50,
      offset: 0,
    });
    api.getBackgroundJob.mockResolvedValue(queuedImportJob);
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await waitFor(() =>
      expect(api.listBackgroundJobs).toHaveBeenCalledWith({
        systemId: system.id,
        limit: 50,
        offset: 0,
      }),
    );
    const jobs = screen.getByRole('region', { name: 'Bakgrundsjobb' });
    expect(within(jobs).getByText('Sårbarhetsimport')).toBeInTheDocument();
    expect(within(jobs).queryByText('Rapportgenerering')).not.toBeInTheDocument();
    await waitFor(() =>
      expect(api.getBackgroundJob).toHaveBeenCalledWith(queuedImportJob.id),
    );
    expect(api.getBackgroundJob).not.toHaveBeenCalledWith(foreignJob.id);
    expect(within(jobs).queryByText(queuedImportJob.payload_sha256)).not.toBeInTheDocument();

    await user.click(within(jobs).getByRole('button', { name: 'Avbryt' }));
    await waitFor(() =>
      expect(api.cancelBackgroundJob).toHaveBeenCalledWith(queuedImportJob.id),
    );
    expect(await within(jobs).findByText(/Jobbet avbröts utan resultat/i)).toBeInTheDocument();
  });

  test('does not show job cancellation to a viewer', async () => {
    const api = createApi();
    api.getCurrentPrincipal.mockResolvedValue({
      ...principal,
      roles: ['viewer'],
      capabilities: ['read_operational'],
    });
    api.listBackgroundJobs.mockResolvedValue({
      items: [queuedImportJob],
      total: 1,
      limit: 50,
      offset: 0,
    });
    api.getBackgroundJob.mockResolvedValue(queuedImportJob);
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    const jobs = screen.getByRole('region', { name: 'Bakgrundsjobb' });
    expect(await within(jobs).findByText('Sårbarhetsimport')).toBeInTheDocument();
    expect(within(jobs).queryByRole('button', { name: 'Avbryt' })).not.toBeInTheDocument();
  });

  test('ignores a completed job response after switching systems', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const secondSystem: OperationalSystem = {
      ...system,
      id: 'system-job-2',
      name: 'Settlement Jobs',
    };
    let resolveOldJob!: (job: BackgroundJob) => void;
    const oldJobResponse = new Promise<BackgroundJob>((resolve) => {
      resolveOldJob = resolve;
    });
    api.listSystems.mockResolvedValue([system, secondSystem]);
    api.getOverview.mockImplementation(async (systemId) => ({
      ...overview,
      system: systemId === secondSystem.id ? secondSystem : system,
    }));
    api.listBackgroundJobs.mockImplementation(async (options) => ({
      items: options?.systemId === system.id ? [queuedImportJob] : [],
      total: options?.systemId === system.id ? 1 : 0,
      limit: 50,
      offset: 0,
    }));
    api.getBackgroundJob.mockImplementation(async () => oldJobResponse);
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });
    await waitFor(() => expect(api.getBackgroundJob).toHaveBeenCalledWith(queuedImportJob.id));

    await user.selectOptions(screen.getByLabelText('Valt system'), secondSystem.id);
    await screen.findByRole('heading', { name: secondSystem.name });
    await waitFor(() =>
      expect(api.listBackgroundJobs).toHaveBeenLastCalledWith({
        systemId: secondSystem.id,
        limit: 50,
        offset: 0,
      }),
    );
    const reportReadsAfterSwitch = api.listReports.mock.calls.length;

    await act(async () => {
      resolveOldJob(completedImportJob);
      await Promise.resolve();
    });

    expect(api.listReports).toHaveBeenCalledTimes(reportReadsAfterSwitch);
    expect(screen.queryByText(/Importjobbet slutfördes:/i)).not.toBeInTheDocument();
    expect(
      within(screen.getByRole('region', { name: 'Bakgrundsjobb' })).getByText(
        /Inga bakgrundsjobb/i,
      ),
    ).toBeInTheDocument();
  });

  test('does not expose intelligence ingestion to a scanner-only principal', async () => {
    const user = userEvent.setup();
    const api = createApi();
    api.getCurrentPrincipal.mockResolvedValue({
      ...principal,
      roles: ['viewer', 'scanner'],
      capabilities: ['read_operational', 'manage_scans'],
    });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: /Fynd/ }));
    expect(screen.queryByLabelText('Sårbarhetsrapport')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Validera och köa import$/ })).not.toBeInTheDocument();
  });

  test('uses server totals and pages high-cardinality findings', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const firstSummary = {
      id: overview.findings[0]!.id,
      system_id: overview.findings[0]!.system_id,
      asset_id: overview.findings[0]!.asset_id,
      service_id: overview.findings[0]!.service_id,
      finding_type: overview.findings[0]!.finding_type,
      cve_id: overview.findings[0]!.cve_id,
      title: overview.findings[0]!.title,
      status: overview.findings[0]!.status,
      lifecycle_status: overview.findings[0]!.lifecycle_status,
      cvss_score: overview.findings[0]!.cvss_score,
      epss_score: overview.findings[0]!.epss_score,
      is_kev: overview.findings[0]!.is_kev,
      kev_due_date: overview.findings[0]!.kev_due_date,
      primary_evidence_strength: overview.findings[0]!.primary_evidence_strength,
      first_seen_at: overview.findings[0]!.first_seen_at,
      last_seen_at: overview.findings[0]!.last_seen_at,
      resolved_at: overview.findings[0]!.resolved_at,
      occurrence_count: overview.findings[0]!.occurrence_count,
      inventory_status: overview.findings[0]!.inventory_status,
    };
    api.getOverview.mockResolvedValue({
      ...overview,
      collection_totals: { ...overview.collection_totals, findings: 51 },
      collections_truncated: true,
    });
    api.listFindingPage
      .mockResolvedValueOnce({
        items: [firstSummary],
        total: 51,
        limit: 50,
        offset: 0,
        has_more: true,
      })
      .mockResolvedValueOnce({
        items: [{ ...firstSummary, id: 'finding-51', title: 'Sista fyndet' }],
        total: 51,
        limit: 50,
        offset: 50,
        has_more: false,
      });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    const findingsTab = await screen.findByRole('tab', { name: /Fynd51/ });
    expect(await screen.findByText(/högst 50 poster per samling/i)).toBeInTheDocument();
    await user.click(findingsTab);
    await user.click(screen.getByRole('button', { name: 'Nästa' }));

    await waitFor(() =>
      expect(api.listFindingPage).toHaveBeenLastCalledWith(system.id, {
        limit: 50,
        offset: 50,
      }),
    );
    expect(await screen.findByText(/Sista fyndet/)).toBeInTheDocument();
    expect(screen.getByText('51–51 av 51')).toBeInTheDocument();
  });

  test('syncs configured intelligence and creates a checksummed report download', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const createObjectUrl = vi.fn(() => 'blob:operational-report');
    const revokeObjectUrl = vi.fn();
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectUrl });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeObjectUrl });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    api.listReports.mockResolvedValueOnce([]).mockResolvedValue([report]);
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('button', { name: /CISA KEV/ }));
    await waitFor(() => expect(api.syncIntelligence).toHaveBeenCalledWith(system.id, 'kev'));
    expect(screen.getByText(syncResult.warnings[0])).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Köa rapport' }));
    await waitFor(() =>
      expect(api.enqueueReport).toHaveBeenCalledWith(
        system.id,
        'pdf',
        'management',
        expect.stringMatching(/^report-/),
      ),
    );
    await user.click(await screen.findByRole('button', { name: /Ladda ned/ }));

    await waitFor(() => expect(api.downloadReport).toHaveBeenCalledWith(report.id));
    expect(createObjectUrl).toHaveBeenCalledOnce();
    expect(revokeObjectUrl).toHaveBeenCalledWith('blob:operational-report');
  });

  test('surfaces report marking and prevents download of a withdrawn snapshot', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const withdrawnReport: Report = {
      ...report,
      distribution_tlp: 'TLP:AMBER+STRICT',
      export_status: 'withdrawn',
      withdrawal_reason: 'Export withdrawn after stricter source reclassification',
    };
    api.listReports.mockResolvedValue([withdrawnReport]);
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: /Rapporter/ }));
    expect(screen.getByText(/TLP:AMBER\+STRICT/)).toBeInTheDocument();
    expect(screen.getByText(/Återkallad – export spärrad/)).toBeInTheDocument();
    expect(screen.getByText(withdrawnReport.withdrawal_reason!)).toBeInTheDocument();
    const download = screen.getByRole('button', {
      name: /Ledningsrapport: nedladdning spärrad/,
    });
    expect(download).toBeDisabled();
    await user.click(download);
    expect(api.downloadReport).not.toHaveBeenCalled();
  });

  test('refreshes a completed job exactly once before publishing terminal state', async () => {
    const user = userEvent.setup();
    const api = createApi();
    let resolveReportRefresh!: (reports: Report[]) => void;
    const delayedReports = new Promise<Report[]>((resolve) => {
      resolveReportRefresh = resolve;
    });
    api.listReports.mockResolvedValueOnce([]).mockImplementationOnce(async () => delayedReports);
    api.getBackgroundJob.mockResolvedValue(completedReportJob);
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('button', { name: 'Köa rapport' }));
    await waitFor(() => expect(api.getBackgroundJob).toHaveBeenCalledWith(queuedReportJob.id));
    await waitFor(() => expect(api.listReports).toHaveBeenCalledTimes(2));
    expect(screen.queryByText(/Rapportjobbet slutfördes/i)).not.toBeInTheDocument();
    expect(
      within(screen.getByRole('region', { name: 'Bakgrundsjobb' })).getByText(/Köat/),
    ).toBeInTheDocument();

    await act(async () => {
      resolveReportRefresh([report]);
      await delayedReports;
    });

    expect(await screen.findByText(/Rapportjobbet slutfördes/i)).toBeInTheDocument();
    expect(api.listReports).toHaveBeenCalledTimes(2);
    expect(api.getBackgroundJob).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole('button', { name: /Ladda ned/ })).toBeInTheDocument();
  });

  test('creates a fresh idempotency key for each intentional report request', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const secondQueuedReport = { ...queuedReportJob, id: 'job-report-2' };
    api.enqueueReport
      .mockResolvedValueOnce({ job: queuedReportJob, idempotent_replay: false })
      .mockResolvedValueOnce({ job: secondQueuedReport, idempotent_replay: false });
    api.getBackgroundJob.mockImplementation(async (jobId) => ({
      ...(jobId === secondQueuedReport.id ? secondQueuedReport : queuedReportJob),
      status: 'running' as const,
      started_at: now,
      attempt_count: 1,
    }));
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('button', { name: 'Köa rapport' }));
    await waitFor(() => expect(api.enqueueReport).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole('button', { name: 'Köa rapport' }));
    await waitFor(() => expect(api.enqueueReport).toHaveBeenCalledTimes(2));

    const firstKey = api.enqueueReport.mock.calls[0]?.[3];
    const secondKey = api.enqueueReport.mock.calls[1]?.[3];
    expect(firstKey).toMatch(/^report-/);
    expect(secondKey).toMatch(/^report-/);
    expect(secondKey).not.toBe(firstKey);
  });

  test('shows global intelligence separately and correlates it on demand', async () => {
    const user = userEvent.setup();
    const api = createApi();
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: /Omvärld/ }));
    expect(
      within(screen.getByRole('region', { name: 'Importerade omvärldsposter' })).getByText(
        intelRecord.title,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/råkälla och AI-analys lagras separat/i)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Korrelera mot valt system/ }));

    await waitFor(() => expect(api.correlateGlobalIntel).toHaveBeenCalledWith(system.id));
    expect(screen.getByText(/1 fyndmatchningar och 1 relevanta hotposter/i)).toBeInTheDocument();
  });

  test('configures and synchronizes the tenant connector and exposes the analyst review queue', async () => {
    const user = userEvent.setup();
    const api = createApi();
    api.getExternalIntelligenceSyncStatus.mockResolvedValue({
      configured: true,
      connector_id: 'connector-1',
      endpoint: 'https://intel.example.test/api/datapoints',
      enabled: true,
      schedule_state: 'scheduled',
      sync_interval_seconds: 3600,
      next_sync_at: '2026-07-17T13:00:00Z',
      config_version: 1,
      credential_available: true,
      checkpoint: null,
      latest_run: {
        id: 'external-run-1',
        connector_id: 'connector-1',
        snapshot_id: 'snapshot-1',
        status: 'completed',
        started_by: principal.actor,
        started_at: now,
        completed_at: now,
        lease_expires_at: null,
        heartbeat_at: now,
        start_cursor_sha256: null,
        next_cursor_sha256: null,
        feed_id: 'cyber-news',
        feed_version: '42',
        feed_generated_at: now,
        pages_fetched: 1,
        records_fetched: 1,
        batch_pages_fetched: 1,
        batch_records_fetched: 1,
        bytes_fetched: 512,
        batch_bytes_fetched: 512,
        created_count: 1,
        updated_count: 0,
        unchanged_count: 0,
        quarantined_count: 0,
        manifest_sha256: 'f'.repeat(64),
        error_code: null,
      },
    });
    api.listExternalIntelligenceSyncRuns.mockResolvedValue({
      items: [
        {
            id: 'external-run-1',
            connector_id: 'connector-1',
            snapshot_id: 'snapshot-1',
            status: 'completed',
            started_by: principal.actor,
            started_at: now,
            completed_at: now,
            lease_expires_at: null,
            heartbeat_at: now,
            start_cursor_sha256: null,
            next_cursor_sha256: null,
            feed_id: 'cyber-news',
            feed_version: '42',
            feed_generated_at: now,
            pages_fetched: 1,
            records_fetched: 1,
            batch_pages_fetched: 1,
            batch_records_fetched: 1,
            bytes_fetched: 512,
            batch_bytes_fetched: 512,
            created_count: 1,
            updated_count: 0,
            unchanged_count: 0,
            quarantined_count: 0,
            manifest_sha256: 'f'.repeat(64),
            error_code: null,
          },
      ],
      total: 1,
      limit: 10,
      offset: 0,
    });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: /Omvärld/ }));
    expect(await screen.findByRole('heading', { name: 'Extern datapunktsconnector' })).toBeInTheDocument();
    expect(screen.getByText('Schemalagd')).toBeInTheDocument();
    expect(screen.getByText('Körstatus och beständig historik')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Analytikerns granskningskö' })).toHaveTextContent(
      '1 poster väntar på godkännande eller avvisning',
    );

    await user.click(screen.getByRole('button', { name: 'Godkänn och köa korrelation' }));
    await waitFor(() =>
      expect(api.reviewGlobalIntel).toHaveBeenCalledWith(intelRecord.id, 'approved', undefined),
    );
    expect(await screen.findByText(/godkändes och 1 korrelationsjobb köades/)).toBeInTheDocument();

    await user.click(screen.getByText('Redigera tenantkonfiguration'));
    const endpoint = screen.getByLabelText('Extern datapunktsendpoint');
    await user.clear(endpoint);
    await user.type(endpoint, 'https://new-intel.example.test/api/datapoints');
    await user.click(screen.getByRole('button', { name: 'Spara connector' }));
    await waitFor(() =>
      expect(api.configureExternalIntelligenceConnector).toHaveBeenCalledWith(
        expect.objectContaining({
          endpoint: 'https://new-intel.example.test/api/datapoints',
          credential_reference: 'tenant/intel-reader',
          sync_interval_seconds: 3600,
        }),
      ),
    );

    await user.click(screen.getByRole('button', { name: /Synka normaliserade datapunkter/ }));
    await waitFor(() => expect(api.syncExternalIntelligence).toHaveBeenCalledWith(10));
    expect(await screen.findByText(/1 poster och 1 korrelationsjobb köades/)).toBeInTheDocument();
  });

  test('does not request organization-wide intelligence for a resource-scoped analyst', async () => {
    const user = userEvent.setup();
    const api = createApi();
    api.getCurrentPrincipal.mockResolvedValue({
      ...principal,
      project_ids: [project.id],
      system_ids: [system.id],
    });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });
    expect(screen.getByLabelText('Aktiv behörighetskontext')).toHaveTextContent('resursbegränsad');
    expect(screen.queryByText('Nytt projekt')).not.toBeInTheDocument();
    expect(screen.queryByText('Nytt system')).not.toBeInTheDocument();
    expect(api.listGlobalIntel).not.toHaveBeenCalled();

    await user.click(screen.getByRole('tab', { name: /Omvärld/ }));
    expect(screen.queryByRole('heading', { name: 'Extern datapunktsconnector' })).not.toBeInTheDocument();
    expect(
      screen.getByText(/kräver en organisationsomfattande analytiker- eller administratörsidentitet/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /Synka normaliserade datapunkter/ }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText('Redigera tenantkonfiguration')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('region', { name: 'Analytikerns granskningskö' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Godkänn och köa korrelation' }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Korrelera mot valt system/ })).toBeInTheDocument();
    expect(api.getExternalIntelligenceSyncStatus).not.toHaveBeenCalled();
    expect(api.listExternalIntelligenceSyncRuns).not.toHaveBeenCalled();
  });

  test('follows closure correlation jobs returned when an intelligence record is rejected', async () => {
    const user = userEvent.setup();
    const api = createApi();
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(screen.getByRole('tab', { name: /Omvärld/ }));
    await user.type(
      screen.getByLabelText(`Granskningsnotering för ${intelRecord.title}`),
      'Inte relevant i den verifierade miljön',
    );
    await user.click(screen.getByRole('button', { name: 'Avvisa' }));

    await waitFor(() =>
      expect(api.reviewGlobalIntel).toHaveBeenCalledWith(
        intelRecord.id,
        'rejected',
        'Inte relevant i den verifierade miljön',
      ),
    );
    expect(
      await screen.findByText(
        /1 omkorrelationsjobb köades för att stänga tidigare härledda samband/i,
      ),
    ).toBeInTheDocument();
    await waitFor(() => expect(api.listBackgroundJobs.mock.calls.length).toBeGreaterThan(1));
  });

  test('pages global intelligence and resets to the first page for a new search', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const secondPageRecord: GlobalIntelRecord = {
      ...intelRecord,
      id: 'intel-51',
      external_id: 'article-2026-51',
      title: 'Omvärldspost på sida två',
    };
    const filteredRecord: GlobalIntelRecord = {
      ...intelRecord,
      id: 'intel-filtered',
      external_id: 'article-filtered',
      title: 'Filtrerat Apache-resultat',
    };
    api.listGlobalIntel.mockImplementation(async (filters) => {
      if (filters?.reviewStatus === 'pending') {
        return {
          items: [intelRecord],
          total: 1,
          limit: 50,
          offset: 0,
        };
      }
      if (filters?.query === 'Apache' && filters.sourceKind === 'news') {
        return {
          items: [filteredRecord],
          total: 1,
          limit: 50,
          offset: 0,
        };
      }
      if (filters?.offset === 50) {
        return {
          items: [secondPageRecord],
          total: 51,
          limit: 50,
          offset: 50,
        };
      }
      return {
        items: [intelRecord],
        total: 51,
        limit: 50,
        offset: 0,
      };
    });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(await screen.findByRole('tab', { name: /Omvärld51/ }));
    await user.click(
      within(
        screen.getByRole('navigation', { name: 'Sidindelning för omvärldsposter' }),
      ).getByRole('button', { name: 'Nästa' }),
    );

    await waitFor(() =>
      expect(api.listGlobalIntel).toHaveBeenLastCalledWith({ limit: 50, offset: 50 }),
    );
    expect(await screen.findByText(secondPageRecord.title)).toBeInTheDocument();
    expect(screen.getByText('51–51 av 51')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Sök i omvärldsdata'), 'Apache');
    await user.selectOptions(screen.getByLabelText('Filtrera omvärldskälla'), 'news');
    await user.click(screen.getByRole('button', { name: 'Sök och filtrera' }));

    await waitFor(() =>
      expect(api.listGlobalIntel).toHaveBeenLastCalledWith({
        query: 'Apache',
        sourceKind: 'news',
        limit: 50,
        offset: 0,
      }),
    );
    expect(await screen.findByText(filteredRecord.title)).toBeInTheDocument();
    expect(screen.queryByText(secondPageRecord.title)).not.toBeInTheDocument();
  });

  test('ignores a stale intelligence page when the selected system changes', async () => {
    const user = userEvent.setup();
    const api = createApi();
    const secondSystem: OperationalSystem = {
      ...system,
      id: 'system-2',
      name: 'Settlement API',
    };
    const staleRecord: GlobalIntelRecord = {
      ...intelRecord,
      id: 'intel-stale',
      external_id: 'article-stale',
      title: 'Föråldrat svar från sida två',
    };
    const contextRecord: GlobalIntelRecord = {
      ...intelRecord,
      id: 'intel-new-context',
      external_id: 'article-new-context',
      title: 'Omvärldsdata för ny systemkontext',
    };
    let resolveStalePage!: (page: GlobalIntelPage) => void;
    const stalePage = new Promise<GlobalIntelPage>((resolve) => {
      resolveStalePage = resolve;
    });
    let firstPageRequests = 0;
    api.listSystems.mockResolvedValue([system, secondSystem]);
    api.getOverview.mockImplementation(async (systemId) => ({
      ...overview,
      system: systemId === secondSystem.id ? secondSystem : system,
    }));
    api.listGlobalIntel.mockImplementation(async (filters) => {
      if (filters?.reviewStatus === 'pending') {
        return {
          items: [intelRecord],
          total: 1,
          limit: 50,
          offset: 0,
        };
      }
      if (filters?.offset === 50) return stalePage;
      firstPageRequests += 1;
      return {
        items: firstPageRequests === 1 ? [intelRecord] : [contextRecord],
        total: 51,
        limit: 50,
        offset: 0,
      };
    });
    render(<OperationalWorkspace api={api} />);
    await screen.findByRole('heading', { name: 'Payment API' });

    await user.click(await screen.findByRole('tab', { name: /Omvärld51/ }));
    await user.click(
      within(
        screen.getByRole('navigation', { name: 'Sidindelning för omvärldsposter' }),
      ).getByRole('button', { name: 'Nästa' }),
    );
    await waitFor(() =>
      expect(api.listGlobalIntel).toHaveBeenLastCalledWith({ limit: 50, offset: 50 }),
    );

    await user.selectOptions(screen.getByLabelText('Valt system'), secondSystem.id);
    expect(await screen.findByText(contextRecord.title)).toBeInTheDocument();
    expect(api.listGlobalIntel).toHaveBeenCalledWith({ limit: 50, offset: 0 });

    resolveStalePage({
      items: [staleRecord],
      total: 51,
      limit: 50,
      offset: 50,
    });
    await waitFor(() => expect(screen.queryByText(staleRecord.title)).not.toBeInTheDocument());
    expect(screen.getByText(contextRecord.title)).toBeInTheDocument();
  });
});
