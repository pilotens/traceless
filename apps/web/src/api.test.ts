import { describe, expect, test, vi } from 'vitest';

import {
  createOperationalApi,
  OperationalApiError,
  type CreateAuthorizationInput,
  type ScanAuthorization,
  type ScanJob,
} from './api';

const authorization: ScanAuthorization = {
  id: 'authorization/1',
  system_id: 'system/1',
  targets: ['192.0.2.10/32'],
  profile: 'service_inventory',
  approved_by: 'Systemägare',
  purpose: 'Godkänd säkerhetsinventering inför riskanalys',
  expires_at: '2026-07-17T13:00:00Z',
  scope_sha256: 'a'.repeat(64),
  status: 'active',
  created_at: '2026-07-17T12:00:00Z',
};

const authorizationInput: CreateAuthorizationInput = {
  targets: ['192.0.2.10'],
  profile: 'service_inventory',
  approved_by: 'Systemägare',
  purpose: 'Godkänd säkerhetsinventering inför riskanalys',
  expires_at: '2026-07-17T13:00:00Z',
  confirmation: 'Jag bekräftar att jag har tillstånd att skanna angivna mål.',
};

const scan: ScanJob = {
  id: 'scan-1',
  system_id: 'system/1',
  authorization_id: authorization.id,
  scanner: 'nmap',
  mode: 'import',
  status: 'completed',
  requested_at: '2026-07-17T12:00:00Z',
  started_at: '2026-07-17T12:00:00Z',
  completed_at: '2026-07-17T12:01:00Z',
  raw_evidence_sha256: 'b'.repeat(64),
  result_summary: {},
  error_code: null,
  error_message: null,
};

describe('operational API client', () => {
  test('loads server-derived capabilities without decoding the access token in the browser', async () => {
    const accessToken = crypto.randomUUID();
    const principal = {
      subject: 'analyst-1',
      actor: 'oidc:analyst-1',
      organization_id: 'organization-1',
      organization_name: 'North-Bridge Security',
      project_ids: null,
      system_ids: null,
      roles: ['analyst'],
      capabilities: ['read_operational', 'analyze', 'ingest_intelligence'],
      authentication_method: 'oidc',
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(principal), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const api = createOperationalApi({
      fetchImpl: fetchMock as typeof fetch,
      getAccessToken: () => accessToken,
      identityUrl: 'https://api.example.test/api/v1/auth/me',
    });

    await expect(api.getCurrentPrincipal()).resolves.toEqual(principal);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://api.example.test/api/v1/auth/me');
    expect(new Headers(fetchMock.mock.calls[0]?.[1]?.headers).get('Authorization')).toBe(
      `Bearer ${accessToken}`,
    );
  });

  test('attaches the in-memory bearer token to JSON and report requests', async () => {
    const accessToken = crypto.randomUUID();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify([]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response('%PDF-fixture', {
          status: 200,
          headers: { 'Content-Type': 'application/pdf' },
        }),
      );
    const api = createOperationalApi({
      fetchImpl: fetchMock as typeof fetch,
      getAccessToken: () => accessToken,
    });

    await api.listProjects();
    await api.downloadReport('report-1');

    expect(new Headers(fetchMock.mock.calls[0]?.[1]?.headers).get('Authorization')).toBe(
      `Bearer ${accessToken}`,
    );
    expect(new Headers(fetchMock.mock.calls[1]?.[1]?.headers).get('Authorization')).toBe(
      `Bearer ${accessToken}`,
    );
  });

  test('uses the exact authorization and raw XML endpoints without query injection', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(authorization), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(scan), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    const api = createOperationalApi({
      baseUrl: 'https://api.example.test/api/v1/operational/',
      actor: 'security-analyst',
      fetchImpl: fetchMock as typeof fetch,
    });

    await api.createAuthorization('system/1', authorizationInput);
    const xml = new Blob(['<nmaprun scanner="nmap"/>'], { type: 'application/xml' });
    await api.importNmapXml('system/1', 'authorization/1?unexpected=true', xml);

    const [authorizationUrl, authorizationInit] = fetchMock.mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(authorizationUrl).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/scan-authorizations',
    );
    expect(authorizationInit.method).toBe('POST');
    expect(new Headers(authorizationInit.headers).get('X-Actor')).toBe('security-analyst');
    expect(JSON.parse(authorizationInit.body as string)).toEqual(authorizationInput);

    const [importUrl, importInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(importUrl).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/scans/import/nmap?authorization_id=authorization%2F1%3Funexpected%3Dtrue',
    );
    expect(importInit.body).toBe(xml);
    expect(new Headers(importInit.headers).get('Content-Type')).toBe('application/xml');
  });

  test('surfaces backend policy errors and sanitizes report filenames', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ detail: 'Public target requires separate approval' }), {
          status: 409,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response('%PDF-fixture', {
          status: 200,
          headers: {
            'Content-Disposition': 'attachment; filename="../../sensitive report.pdf"',
            'Content-Type': 'application/pdf',
            'X-Content-SHA256': 'c'.repeat(64),
          },
        }),
      );
    const api = createOperationalApi({
      fetchImpl: fetchMock as typeof fetch,
    });

    await expect(api.createAuthorization('system-1', authorizationInput)).rejects.toEqual(
      new OperationalApiError(409, 'Public target requires separate approval'),
    );

    const download = await api.downloadReport('report/1');
    expect(download.filename).toBe('sensitive-report.pdf');
    expect(download.sha256).toBe('c'.repeat(64));
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      '/api/v1/operational/reports/report%2F1/download',
    );
  });

  test('encodes vulnerability-report names and keeps vendor XML as an opaque body', async () => {
    const importResult = {
      import_record: {
        id: 'import-1',
        system_id: 'system/1',
        provider: 'nessus',
        source_format: 'nessus-xml',
        source_name: 'scan?scope=prod.nessus',
        scanner_version: null,
        scan_started_at: null,
        scan_completed_at: null,
        imported_at: '2026-07-18T12:00:00Z',
        imported_by: 'security-analyst',
        raw_sha256: 'd'.repeat(64),
        report_metadata: {},
        observation_count: 0,
        asset_count: 0,
        matched_asset_count: 0,
        promoted_finding_count: 0,
      },
      imported: 0,
      matched_assets: 0,
      matched_services: 0,
      promoted_findings: 0,
      idempotent_replay: false,
      warnings: [],
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(importResult), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const api = createOperationalApi({
      baseUrl: 'https://api.example.test/api/v1/operational',
      actor: 'security-analyst',
      fetchImpl: fetchMock as typeof fetch,
    });
    const report = new Blob(['<NessusClientData_v2/>'], { type: 'application/xml' });

    await api.importNessusReport('system/1', 'scan?scope=prod.nessus', report);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/vulnerability-scans/import/nessus?source_name=scan%3Fscope%3Dprod.nessus',
    );
    expect(init.body).toBe(report);
    expect(new Headers(init.headers).get('Content-Type')).toBe('application/xml');
    expect(new Headers(init.headers).get('X-Actor')).toBe('security-analyst');
  });

  test('uses scoped finding evidence and lifecycle endpoints', async () => {
    const updatedFinding = {
      id: 'finding/1',
      lifecycle_status: 'accepted',
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify([]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(updatedFinding), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    const api = createOperationalApi({
      baseUrl: 'https://api.example.test/api/v1/operational',
      fetchImpl: fetchMock as typeof fetch,
    });

    await api.listFindingEvidence('system/1', 'finding/1');
    await api.updateFindingLifecycle(
      'system/1',
      'finding/1',
      'accepted',
      'Kompenserad kontroll',
    );

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/findings/finding%2F1/evidence',
    );
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(url).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/findings/finding%2F1/lifecycle',
    );
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({
      lifecycle_status: 'accepted',
      reason: 'Kompenserad kontroll',
    });
  });

  test('uses tenant connector, bounded sync and paginated run-history endpoints', async () => {
    const fetchMock = vi.fn().mockImplementation(async () =>
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const api = createOperationalApi({
      baseUrl: 'https://api.example.test/api/v1/operational',
      fetchImpl: fetchMock as typeof fetch,
    });
    const connector = {
      endpoint: 'https://intel.example.test/api/datapoints',
      auth_scheme: 'Bearer' as const,
      credential_reference: 'tenant/intel-reader',
      enabled: true,
      sync_interval_seconds: 3600,
    };

    await api.getExternalIntelligenceConnector();
    await api.configureExternalIntelligenceConnector(connector);
    await api.getExternalIntelligenceSyncStatus();
    await api.listExternalIntelligenceSyncRuns({ limit: 10, offset: 20 });
    await api.syncExternalIntelligence(7);

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/intelligence/connectors/external',
    );
    const [, configureInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(configureInit.method).toBe('PUT');
    expect(JSON.parse(configureInit.body as string)).toEqual(connector);
    expect(fetchMock.mock.calls[2]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/intelligence/sync/external/status',
    );
    expect(fetchMock.mock.calls[3]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/intelligence/sync/external/runs?limit=10&offset=20',
    );
    const [syncUrl, syncInit] = fetchMock.mock.calls[4] as [string, RequestInit];
    expect(syncUrl).toBe(
      'https://api.example.test/api/v1/operational/intelligence/sync/external',
    );
    expect(syncInit.method).toBe('POST');
    expect(JSON.parse(syncInit.body as string)).toEqual({ max_pages: 7 });
  });

  test('filters tenant intelligence by review state and records explicit analyst decisions', async () => {
    const fetchMock = vi.fn().mockImplementation(async () =>
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const api = createOperationalApi({
      baseUrl: 'https://api.example.test/api/v1/operational',
      fetchImpl: fetchMock as typeof fetch,
    });

    await api.listGlobalIntel({
      sourceKind: 'news',
      reviewStatus: 'pending',
      limit: 25,
      offset: 50,
    });
    await api.reviewGlobalIntel('intel/1', 'rejected', 'Inte relevant för vår miljö');

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/intelligence/records?source_kind=news&review_status=pending&limit=25&offset=50',
    );
    const [reviewUrl, reviewInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(reviewUrl).toBe(
      'https://api.example.test/api/v1/operational/intelligence/records/intel%2F1/review',
    );
    expect(reviewInit.method).toBe('PATCH');
    expect(JSON.parse(reviewInit.body as string)).toEqual({
      decision: 'rejected',
      note: 'Inte relevant för vår miljö',
    });
  });

  test('uses bounded collection pages and on-demand detail endpoints', async () => {
    const emptyPage = { items: [], total: 0, limit: 50, offset: 0, has_more: false };
    const fetchMock = vi.fn().mockImplementation(async () =>
      new Response(JSON.stringify(emptyPage), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const api = createOperationalApi({
      baseUrl: 'https://api.example.test/api/v1/operational',
      fetchImpl: fetchMock as typeof fetch,
    });

    await api.listAssetPage('system/1', { limit: 25, offset: 50 });
    await api.listServicePage('system/1', {
      assetId: 'asset/1',
      limit: 20,
      offset: 40,
    });
    await api.listThreatPage('system/1', { limit: 10, offset: 20 });
    await api.getThreat('system/1', 'threat/1');
    await api.listFindingPage('system/1', {
      limit: 50,
      offset: 100,
      lifecycleStatus: 'open',
      findingType: 'misconfiguration',
    });
    await api.listRiskPage('system/1', { limit: 50, offset: 50, status: 'open' });
    await api.listVulnerabilityObservationPage('system/1', {
      importId: 'import/1',
      limit: 50,
      offset: 0,
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/assets/page?limit=25&offset=50',
    );
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/services/page?asset_id=asset%2F1&limit=20&offset=40',
    );
    expect(fetchMock.mock.calls[2]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/threats?limit=10&offset=20',
    );
    expect(fetchMock.mock.calls[3]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/threats/threat%2F1',
    );
    expect(fetchMock.mock.calls[4]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/findings?limit=50&offset=100&lifecycle_status=open&finding_type=misconfiguration',
    );
    expect(fetchMock.mock.calls[5]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/risks?limit=50&offset=50&status=open',
    );
    expect(fetchMock.mock.calls[6]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/vulnerability-observations/page?import_id=import%2F1&limit=50&offset=0',
    );
  });

  test('uses durable background-job endpoints and idempotency headers', async () => {
    const fetchMock = vi.fn().mockImplementation(async () =>
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const api = createOperationalApi({
      baseUrl: 'https://api.example.test/api/v1/operational',
      fetchImpl: fetchMock as typeof fetch,
    });
    const nessus = new Blob(['<NessusClientData_v2/>'], { type: 'application/xml' });
    const normalized = {
      provider: 'generic' as const,
      source_name: 'adapter.json',
      observations: [
        {
          provider_finding_id: 'finding-1',
          asset_identifier: 'host.example.test',
          title: 'Adapter finding',
          severity: 'high' as const,
        },
      ],
    };

    await api.enqueueNessusImport('system/1', 'scan prod.nessus', nessus, 'upload-key-123');
    await api.enqueueNormalizedVulnerabilityImport(
      'system/1',
      normalized,
      'upload-key-456',
    );
    await api.enqueueReport('system/1', 'pdf', 'technical', 'report-key-123');
    await api.listBackgroundJobs({
      status: 'running',
      jobType: 'report_generation',
      systemId: 'system/1',
      limit: 25,
      offset: 50,
    });
    await api.getBackgroundJob('job/1');
    await api.cancelBackgroundJob('job/1');

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/vulnerability-scans/import/nessus/async?source_name=scan%20prod.nessus',
    );
    let init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(init.method).toBe('POST');
    expect(init.body).toBe(nessus);
    expect(new Headers(init.headers).get('Idempotency-Key')).toBe('upload-key-123');

    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/vulnerability-scans/import/async',
    );
    init = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual(normalized);
    expect(new Headers(init.headers).get('Idempotency-Key')).toBe('upload-key-456');

    expect(fetchMock.mock.calls[2]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/systems/system%2F1/reports/async',
    );
    init = fetchMock.mock.calls[2]?.[1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({ format: 'pdf', report_type: 'technical' });
    expect(new Headers(init.headers).get('Idempotency-Key')).toBe('report-key-123');
    expect(fetchMock.mock.calls[3]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/jobs?status=running&job_type=report_generation&system_id=system%2F1&limit=25&offset=50',
    );
    expect(fetchMock.mock.calls[4]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/jobs/job%2F1',
    );
    expect(fetchMock.mock.calls[5]?.[0]).toBe(
      'https://api.example.test/api/v1/operational/jobs/job%2F1/cancel',
    );
    expect((fetchMock.mock.calls[5]?.[1] as RequestInit).method).toBe('POST');
  });
});
