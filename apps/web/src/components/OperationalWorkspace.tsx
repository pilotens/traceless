import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';

import {
  operationalApi,
  type ArchitectureSnapshot,
  type ArchitectureVersionInput,
  type Asset,
  type AssetSourceSnapshot,
  type BackgroundJob,
  type BackgroundJobEnqueueResult,
  type BackgroundJobList,
  type Criticality,
  type Finding,
  type FindingEvidence,
  type FindingLifecycleStatus,
  type FindingSummary,
  type GlobalIntelPage,
  type GlobalIntelRecord,
  type ExternalIntelligencePullResult,
  type IntelSourceKind,
  type IntelCorrelationResult,
  type IntelligenceProvider,
  type IntelligenceSyncResult,
  type OperationalApi,
  type OperationalCapability,
  type OperationalPrincipal,
  type PipelineOverview,
  type Page,
  type Project,
  type Report,
  type ReportFormat,
  type ReportType,
  type ScanAuthorization,
  type ScanJob,
  type ScanProfile,
  type Service,
  type Risk,
  type RiskSummary,
  type Threat,
  type ThreatSummary,
  type OperationalSystem,
  type VulnerabilityObservation,
  type VulnerabilityObservationSummary,
  type VulnerabilityScanImport,
  type VulnerabilityScanImportInput,
} from '../api';
import { Icon } from './Icon';
import { ExternalIntelligenceConnectorPanel } from './ExternalIntelligenceConnectorPanel';
import { OperationalArchitectureEditor } from './OperationalArchitectureEditor';
import { EmptyState, EntityCards, PaginationControls } from './operational/Presentation';
import {
  asErrorMessage,
  canReadOrganizationIntelligence,
  criticalityLabel,
  dateTimeLocal,
  findingLifecycleLabel,
  findingTypeLabel,
  formatDate,
  formatPercent,
  intelReviewStatusLabel,
  inventoryStatusLabel,
  reportExportStatusLabel,
  reportTypeLabel,
  scanStatusLabel,
} from './operational/formatters';

const AUTHORIZATION_CONFIRMATION =
  'Jag bekräftar att jag har tillstånd att skanna angivna mål.' as const;
const MAX_XML_BYTES = 16 * 1024 * 1024;
const MAX_VULNERABILITY_REPORT_BYTES = 32 * 1024 * 1024;
const COLLECTION_PAGE_SIZE = 50;
const BACKGROUND_JOB_POLL_MS = 2_000;

function emptyPage<T>(): Page<T> {
  return { items: [], total: 0, limit: COLLECTION_PAGE_SIZE, offset: 0, has_more: false };
}

type WorkspaceTab =
  | 'overview'
  | 'assets'
  | 'intel'
  | 'threats'
  | 'findings'
  | 'risks'
  | 'architecture'
  | 'reports';

interface OperationalWorkspaceProps {
  api?: OperationalApi;
}

interface SystemRequestContext {
  generation: number;
  systemId: string;
}

export function OperationalWorkspace({ api = operationalApi }: OperationalWorkspaceProps) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [principal, setPrincipal] = useState<OperationalPrincipal | null>(null);
  const [systems, setSystems] = useState<OperationalSystem[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [selectedSystemId, setSelectedSystemId] = useState('');
  const [overview, setOverview] = useState<PipelineOverview | null>(null);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [sourceSnapshots, setSourceSnapshots] = useState<AssetSourceSnapshot[]>([]);
  const [architectureVersions, setArchitectureVersions] = useState<ArchitectureSnapshot[]>([]);
  const [vulnerabilityScans, setVulnerabilityScans] = useState<VulnerabilityScanImport[]>([]);
  const [vulnerabilityObservationPage, setVulnerabilityObservationPage] = useState<
    Page<VulnerabilityObservationSummary>
  >(emptyPage);
  const [assetPage, setAssetPage] = useState<Page<Asset>>(emptyPage);
  const [threatPage, setThreatPage] = useState<Page<ThreatSummary>>(emptyPage);
  const [findingPage, setFindingPage] = useState<Page<FindingSummary>>(emptyPage);
  const [reviewFindingPage, setReviewFindingPage] = useState<Page<FindingSummary>>(emptyPage);
  const [riskPage, setRiskPage] = useState<Page<RiskSummary>>(emptyPage);
  const [backgroundJobs, setBackgroundJobs] = useState<BackgroundJobList>({
    items: [],
    total: 0,
    limit: COLLECTION_PAGE_SIZE,
    offset: 0,
  });
  const [authorization, setAuthorization] = useState<ScanAuthorization | null>(null);
  const [syncResult, setSyncResult] = useState<IntelligenceSyncResult | null>(null);
  const [intelPage, setIntelPage] = useState<GlobalIntelPage>({
    items: [],
    total: 0,
    limit: 50,
    offset: 0,
  });
  const [pendingIntelPage, setPendingIntelPage] = useState<GlobalIntelPage>({
    items: [],
    total: 0,
    limit: COLLECTION_PAGE_SIZE,
    offset: 0,
  });
  const [intelLoading, setIntelLoading] = useState(false);
  const [correlationResult, setCorrelationResult] = useState<IntelCorrelationResult | null>(null);
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('overview');
  const [architectureDirty, setArchitectureDirty] = useState(false);
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [selectedScanId, setSelectedScanId] = useState('');
  const [contextLoading, setContextLoading] = useState(true);
  const [contextLoadError, setContextLoadError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [projectName, setProjectName] = useState('');
  const [projectDescription, setProjectDescription] = useState('');
  const [systemName, setSystemName] = useState('');
  const [systemDescription, setSystemDescription] = useState('');
  const [systemOwner, setSystemOwner] = useState('');
  const [systemCriticality, setSystemCriticality] = useState<Criticality>('medium');
  const [targets, setTargets] = useState('');
  const [profile, setProfile] = useState<ScanProfile>('service_inventory');
  const [approvedBy, setApprovedBy] = useState('');
  const [purpose, setPurpose] = useState('');
  const [expiresAt, setExpiresAt] = useState(() => dateTimeLocal(60));
  const [confirmed, setConfirmed] = useState(false);
  const [xmlFile, setXmlFile] = useState<File | null>(null);
  const [vulnerabilityFile, setVulnerabilityFile] = useState<File | null>(null);
  const [vulnerabilityFormat, setVulnerabilityFormat] = useState<'nessus' | 'normalized-json'>(
    'nessus',
  );
  const [reportFormat, setReportFormat] = useState<ReportFormat>('pdf');
  const [reportType, setReportType] = useState<ReportType>('management');
  const [intelQuery, setIntelQuery] = useState('');
  const [intelSourceKind, setIntelSourceKind] = useState<IntelSourceKind | ''>('');
  const [appliedIntelFilters, setAppliedIntelFilters] = useState<{
    query?: string;
    sourceKind?: IntelSourceKind;
  }>({});
  const intelRequestSequence = useRef(0);
  const intelReviewRequestSequence = useRef(0);
  const backgroundJobPollSequence = useRef(0);
  const completedJobRefreshes = useRef(new Set<string>());
  const vulnerabilityUploadIdempotencyKey = useRef<string | null>(null);
  const systemContextGeneration = useRef(0);
  const selectedSystemIdRef = useRef('');

  function resetSystemFormState(): void {
    setTargets('');
    setProfile('service_inventory');
    setApprovedBy('');
    setPurpose('');
    setExpiresAt(dateTimeLocal(60));
    setConfirmed(false);
    setXmlFile(null);
    setVulnerabilityFile(null);
    setVulnerabilityFormat('nessus');
    vulnerabilityUploadIdempotencyKey.current = null;
    setReportFormat('pdf');
    setReportType('management');
  }

  function resetSystemData(): void {
    setOverview(null);
    setScans([]);
    setReports([]);
    setSourceSnapshots([]);
    setArchitectureVersions([]);
    setVulnerabilityScans([]);
    setVulnerabilityObservationPage(emptyPage());
    setAssetPage(emptyPage());
    setThreatPage(emptyPage());
    setFindingPage(emptyPage());
    setReviewFindingPage(emptyPage());
    setRiskPage(emptyPage());
    setBackgroundJobs({
      items: [],
      total: 0,
      limit: COLLECTION_PAGE_SIZE,
      offset: 0,
    });
    backgroundJobPollSequence.current += 1;
    completedJobRefreshes.current.clear();
    setAuthorization(null);
    setSyncResult(null);
    setCorrelationResult(null);
    setSelectedAssetId('');
    setSelectedScanId('');
    setArchitectureDirty(false);
    setBusyAction(null);
    setError(null);
    setNotice(null);
    resetSystemFormState();
  }

  function beginSystemContext(nextSystemId: string): void {
    systemContextGeneration.current += 1;
    selectedSystemIdRef.current = nextSystemId;
    resetSystemData();
    setSelectedSystemId(nextSystemId);
  }

  function captureSystemContext(systemId = selectedSystemIdRef.current): SystemRequestContext {
    return { generation: systemContextGeneration.current, systemId };
  }

  function isSystemContextCurrent(context: SystemRequestContext): boolean {
    return (
      context.systemId !== '' &&
      context.systemId === selectedSystemIdRef.current &&
      context.generation === systemContextGeneration.current
    );
  }

  function confirmArchitectureDiscard(): boolean {
    return (
      !architectureDirty ||
      window.confirm(
        'Du har osparade arkitekturändringar. Vill du kasta dem och lämna arkitekturvyn?',
      )
    );
  }

  function selectWorkspaceTab(nextTab: WorkspaceTab) {
    if (
      activeTab === 'architecture' &&
      nextTab !== 'architecture' &&
      !confirmArchitectureDiscard()
    ) {
      return;
    }
    setActiveTab(nextTab);
  }

  function selectProject(nextProjectId: string) {
    if (nextProjectId === selectedProjectId || confirmArchitectureDiscard()) {
      if (nextProjectId !== selectedProjectId) {
        beginSystemContext('');
        setSystems([]);
        resetGlobalIntelContext();
      }
      setSelectedProjectId(nextProjectId);
    }
  }

  function selectSystem(nextSystemId: string) {
    if (nextSystemId === selectedSystemId || confirmArchitectureDiscard()) {
      if (nextSystemId !== selectedSystemId) {
        beginSystemContext(nextSystemId);
        resetGlobalIntelContext();
      }
    }
  }

  useEffect(() => {
    let active = true;
    intelRequestSequence.current += 1;
    intelReviewRequestSequence.current += 1;
    setIntelPage({
      items: [],
      total: 0,
      limit: COLLECTION_PAGE_SIZE,
      offset: 0,
    });
    setIntelLoading(false);
    setPendingIntelPage({
      items: [],
      total: 0,
      limit: COLLECTION_PAGE_SIZE,
      offset: 0,
    });
    setContextLoading(true);
    setContextLoadError(null);
    api.getCurrentPrincipal()
      .then(async (nextPrincipal) => {
        if (!active) return;
        setPrincipal(nextPrincipal);
        if (!nextPrincipal.capabilities.includes('read_operational')) return;
        const [items] = await Promise.all([
          api.listProjects(),
          canReadOrganizationIntelligence(nextPrincipal)
            ? loadGlobalIntelPage(0, appliedIntelFilters)
            : Promise.resolve(),
        ]);
        if (!active) return;
        setProjects(items);
        setSelectedProjectId((current) =>
          current && items.some((item) => item.id === current) ? current : (items[0]?.id ?? ''),
        );
      })
      .catch((reason: unknown) => {
        if (!active) return;
        const message = asErrorMessage(reason);
        setContextLoadError(message);
        setError(message);
      })
      .finally(() => active && setContextLoading(false));
    return () => {
      active = false;
      intelRequestSequence.current += 1;
      intelReviewRequestSequence.current += 1;
    };
  }, [api]);

  useEffect(() => {
    let active = true;
    setSystems([]);
    if (selectedSystemIdRef.current) beginSystemContext('');
    if (!selectedProjectId) return () => undefined;
    setContextLoading(true);
    setContextLoadError(null);
    api
      .listSystems(selectedProjectId)
      .then((items) => {
        if (!active) return;
        setSystems(items);
        beginSystemContext(items[0]?.id ?? '');
      })
      .catch((reason: unknown) => {
        if (!active) return;
        const message = asErrorMessage(reason);
        setContextLoadError(message);
        setError(message);
      })
      .finally(() => active && setContextLoading(false));
    return () => {
      active = false;
    };
  }, [api, selectedProjectId]);

  useEffect(() => {
    let active = true;
    if (!selectedSystemId) return () => undefined;
    const context = captureSystemContext(selectedSystemId);
    setContextLoading(true);
    setContextLoadError(null);
    Promise.all([
      api.getOverview(selectedSystemId),
      api.listAssetPage(selectedSystemId, { limit: COLLECTION_PAGE_SIZE }),
      api.listThreatPage(selectedSystemId, { limit: COLLECTION_PAGE_SIZE }),
      api.listScans(selectedSystemId),
      api.listReports(selectedSystemId),
      api.listAssetSourceSnapshots(selectedSystemId),
      api.listArchitectureVersions(selectedSystemId),
      api.listVulnerabilityScans(selectedSystemId),
      api.listVulnerabilityObservationPage(selectedSystemId, { limit: COLLECTION_PAGE_SIZE }),
      api.listFindingPage(selectedSystemId, { limit: COLLECTION_PAGE_SIZE }),
      api.listRiskPage(selectedSystemId, { limit: COLLECTION_PAGE_SIZE }),
      api.listBackgroundJobs({
        systemId: selectedSystemId,
        limit: COLLECTION_PAGE_SIZE,
        offset: 0,
      }),
    ])
      .then(([
        nextOverview,
        nextAssetPage,
        nextThreatPage,
        nextScans,
        nextReports,
        nextSourceSnapshots,
        nextArchitectureVersions,
        nextVulnerabilityScans,
        nextVulnerabilityObservationPage,
        nextFindingPage,
        nextRiskPage,
        nextBackgroundJobs,
      ]) => {
        if (!active || !isSystemContextCurrent(context)) return;
        setOverview(nextOverview);
        setAssetPage(nextAssetPage);
        setThreatPage(nextThreatPage);
        setScans(nextScans);
        setReports(nextReports);
        setSourceSnapshots(nextSourceSnapshots);
        setArchitectureVersions(nextArchitectureVersions);
        setVulnerabilityScans(nextVulnerabilityScans);
        setVulnerabilityObservationPage(nextVulnerabilityObservationPage);
        setFindingPage(nextFindingPage);
        setRiskPage(nextRiskPage);
        setBackgroundJobs({
          ...nextBackgroundJobs,
          items: nextBackgroundJobs.items.filter(
            (job) => job.system_id === selectedSystemId,
          ),
        });
        nextBackgroundJobs.items.forEach((job) => {
          if (job.status === 'completed') completedJobRefreshes.current.add(job.id);
        });
        setSelectedAssetId(nextAssetPage.items[0]?.id ?? '');
        setSelectedScanId(nextScans[0]?.id ?? '');
      })
      .catch((reason: unknown) => {
        if (!active || !isSystemContextCurrent(context)) return;
        const message = asErrorMessage(reason);
        setContextLoadError(message);
        setError(message);
      })
      .finally(() => active && isSystemContextCurrent(context) && setContextLoading(false));
    return () => {
      active = false;
    };
  }, [api, selectedSystemId]);

  useEffect(() => {
    if (activeTab !== 'intel' || !selectedSystemId) return;
    const requests: Promise<void>[] = [loadReviewFindingPage(0)];
    if (principal && canReadOrganizationIntelligence(principal)) {
      requests.push(loadPendingIntelPage(0));
    }
    void Promise.all(requests).catch((reason: unknown) => {
      const context = captureSystemContext(selectedSystemId);
      if (isSystemContextCurrent(context)) setError(asErrorMessage(reason));
    });
  }, [activeTab, api, principal, selectedSystemId]);

  const activeBackgroundJobKey = backgroundJobs.items
    .filter((job) => job.status === 'queued' || job.status === 'running')
    .map((job) => job.id)
    .sort()
    .join(':');

  useEffect(() => {
    if (!selectedSystemId || !activeBackgroundJobKey) return () => undefined;
    const systemId = selectedSystemId;
    const jobIds = activeBackgroundJobKey.split(':');
    const pollId = ++backgroundJobPollSequence.current;
    let active = true;
    let timer: number | undefined;

    const isCurrent = () =>
      active && pollId === backgroundJobPollSequence.current;

    async function poll(): Promise<void> {
      let continuePolling = true;
      try {
        const updates = (await Promise.all(jobIds.map((jobId) => api.getBackgroundJob(jobId))))
          .filter((job) => job.system_id === systemId);
        if (!isCurrent()) return;
        const newlyCompleted = updates.filter(
          (job) =>
            job.status === 'completed' && !completedJobRefreshes.current.has(job.id),
        );
        newlyCompleted.forEach((job) => completedJobRefreshes.current.add(job.id));
        if (newlyCompleted.length > 0) {
          try {
            await refreshSystemData(systemId, isCurrent, false);
          } catch (reason) {
            newlyCompleted.forEach((job) => completedJobRefreshes.current.delete(job.id));
            throw reason;
          }
          if (!isCurrent()) return;
          setNotice(backgroundJobCompletionMessage(newlyCompleted));
        }
        if (!isCurrent()) return;
        setBackgroundJobs((current) => ({
          ...current,
          items: current.items.map(
            (job) => updates.find((updated) => updated.id === job.id) ?? job,
          ),
        }));
        continuePolling = updates.some(
          (job) => job.status === 'queued' || job.status === 'running',
        );
      } catch (reason) {
        if (isCurrent()) setError(asErrorMessage(reason));
      } finally {
        if (isCurrent() && continuePolling) {
          timer = window.setTimeout(() => void poll(), BACKGROUND_JOB_POLL_MS);
        }
      }
    }

    void poll();
    return () => {
      active = false;
      backgroundJobPollSequence.current += 1;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [activeBackgroundJobKey, api, selectedSystemId]);

  const selectedAsset =
    assetPage.items.find((asset) => asset.id === selectedAssetId) ?? assetPage.items[0] ?? null;
  const selectedScan = scans.find((scan) => scan.id === selectedScanId) ?? scans[0] ?? null;
  const selectedSystem =
    (overview?.system.id === selectedSystemId ? overview.system : null) ??
    systems.find((system) => system.id === selectedSystemId) ??
    null;
  const collectionTotals = overview?.collection_totals ?? {
    assets: assetPage.total,
    services: overview?.services.length ?? 0,
    findings: findingPage.total,
    threats: threatPage.total,
    risks: riskPage.total,
  };
  const intelPaginationPage = {
    ...intelPage,
    has_more: intelPage.offset + intelPage.items.length < intelPage.total,
  } satisfies Page<GlobalIntelRecord>;
  const hasCapability = (capability: OperationalCapability) =>
    principal?.capabilities.includes(capability) ?? false;
  const canRead = hasCapability('read_operational');
  const canAnalyze = hasCapability('analyze');
  const canManageScans = hasCapability('manage_scans');
  const canIngestIntelligence = hasCapability('ingest_intelligence');
  const canAdminister = hasCapability('administer');
  const hasOrganizationWideAccess =
    principal?.project_ids === null && principal.system_ids === null;
  const canReadGlobalIntelligence =
    principal !== null && canReadOrganizationIntelligence(principal);
  const canCreateProject = canAdminister && hasOrganizationWideAccess;
  const canCreateSystem = canAnalyze && principal?.system_ids === null;

  async function refreshSystemData(
    systemId: string,
    shouldApply: () => boolean = () => selectedSystemIdRef.current === systemId,
    includeBackgroundJobs = true,
  ): Promise<void> {
    const context = captureSystemContext(systemId);
    const [
      nextOverview,
      nextAssetPage,
      nextThreatPage,
      nextScans,
      nextReports,
      nextSourceSnapshots,
      nextArchitectureVersions,
      nextVulnerabilityScans,
      nextVulnerabilityObservationPage,
      nextFindingPage,
      nextRiskPage,
      nextBackgroundJobs,
    ] = await Promise.all([
      api.getOverview(systemId),
      api.listAssetPage(systemId, { limit: COLLECTION_PAGE_SIZE }),
      api.listThreatPage(systemId, { limit: COLLECTION_PAGE_SIZE }),
      api.listScans(systemId),
      api.listReports(systemId),
      api.listAssetSourceSnapshots(systemId),
      api.listArchitectureVersions(systemId),
      api.listVulnerabilityScans(systemId),
      api.listVulnerabilityObservationPage(systemId, { limit: COLLECTION_PAGE_SIZE }),
      api.listFindingPage(systemId, { limit: COLLECTION_PAGE_SIZE }),
      api.listRiskPage(systemId, { limit: COLLECTION_PAGE_SIZE }),
      includeBackgroundJobs
        ? api.listBackgroundJobs({
            systemId,
            limit: COLLECTION_PAGE_SIZE,
            offset: 0,
          })
        : Promise.resolve(null),
    ]);
    if (!shouldApply() || !isSystemContextCurrent(context)) return;
    setOverview(nextOverview);
    setAssetPage(nextAssetPage);
    setThreatPage(nextThreatPage);
    setScans(nextScans);
    setReports(nextReports);
    setSourceSnapshots(nextSourceSnapshots);
    setArchitectureVersions(nextArchitectureVersions);
    setVulnerabilityScans(nextVulnerabilityScans);
    setVulnerabilityObservationPage(nextVulnerabilityObservationPage);
    setFindingPage(nextFindingPage);
    setRiskPage(nextRiskPage);
    if (nextBackgroundJobs !== null) {
      setBackgroundJobs({
        ...nextBackgroundJobs,
        items: nextBackgroundJobs.items.filter((job) => job.system_id === systemId),
      });
      nextBackgroundJobs.items.forEach((job) => {
        if (job.status === 'completed') completedJobRefreshes.current.add(job.id);
      });
    }
    setSelectedAssetId((current) =>
      nextAssetPage.items.some((asset) => asset.id === current)
        ? current
        : (nextAssetPage.items[0]?.id ?? ''),
    );
    setSelectedScanId((current) => current || nextScans[0]?.id || '');
  }

  async function loadGlobalIntelPage(
    offset: number,
    filters = appliedIntelFilters,
  ): Promise<void> {
    const requestId = ++intelRequestSequence.current;
    setIntelLoading(true);
    try {
      const nextPage = await api.listGlobalIntel({
        ...filters,
        limit: COLLECTION_PAGE_SIZE,
        offset,
      });
      if (requestId !== intelRequestSequence.current) return;
      setIntelPage(nextPage);
    } catch (reason) {
      if (requestId !== intelRequestSequence.current) return;
      throw reason;
    } finally {
      if (requestId === intelRequestSequence.current) setIntelLoading(false);
    }
  }

  function requestGlobalIntelPage(
    offset: number,
    filters = appliedIntelFilters,
  ): void {
    setError(null);
    setNotice(null);
    void loadGlobalIntelPage(offset, filters).catch((reason: unknown) => {
      setError(asErrorMessage(reason));
    });
  }

  function resetGlobalIntelContext(): void {
    setIntelPage({
      items: [],
      total: 0,
      limit: COLLECTION_PAGE_SIZE,
      offset: 0,
    });
    if (principal && canReadOrganizationIntelligence(principal)) {
      requestGlobalIntelPage(0);
    }
  }

  async function loadPendingIntelPage(offset: number): Promise<void> {
    const requestId = ++intelReviewRequestSequence.current;
    const nextPage = await api.listGlobalIntel({
      reviewStatus: 'pending',
      limit: COLLECTION_PAGE_SIZE,
      offset,
    });
    if (requestId === intelReviewRequestSequence.current) setPendingIntelPage(nextPage);
  }

  async function loadAssetPage(offset: number): Promise<void> {
    const context = captureSystemContext();
    if (!context.systemId) return;
    const nextPage = await api.listAssetPage(context.systemId, {
      limit: COLLECTION_PAGE_SIZE,
      offset,
    });
    if (!isSystemContextCurrent(context)) return;
    setAssetPage(nextPage);
    setSelectedAssetId(nextPage.items[0]?.id ?? '');
  }

  async function loadThreatPage(offset: number): Promise<void> {
    const context = captureSystemContext();
    if (!context.systemId) return;
    const nextPage = await api.listThreatPage(context.systemId, {
        limit: COLLECTION_PAGE_SIZE,
        offset,
      });
    if (isSystemContextCurrent(context)) setThreatPage(nextPage);
  }

  async function loadFindingPage(offset: number): Promise<void> {
    const context = captureSystemContext();
    if (!context.systemId) return;
    const nextPage = await api.listFindingPage(context.systemId, {
        limit: COLLECTION_PAGE_SIZE,
        offset,
      });
    if (isSystemContextCurrent(context)) setFindingPage(nextPage);
  }

  async function loadReviewFindingPage(offset: number): Promise<void> {
    const context = captureSystemContext();
    if (!context.systemId) return;
    const nextPage = await api.listFindingPage(context.systemId, {
      limit: COLLECTION_PAGE_SIZE,
      offset,
      needsReview: true,
    });
    if (isSystemContextCurrent(context)) setReviewFindingPage(nextPage);
  }

  async function loadRiskPage(offset: number): Promise<void> {
    const context = captureSystemContext();
    if (!context.systemId) return;
    const nextPage = await api.listRiskPage(context.systemId, {
        limit: COLLECTION_PAGE_SIZE,
        offset,
      });
    if (isSystemContextCurrent(context)) setRiskPage(nextPage);
  }

  async function loadVulnerabilityObservationPage(offset: number): Promise<void> {
    const context = captureSystemContext();
    if (!context.systemId) return;
    const nextPage = await api.listVulnerabilityObservationPage(context.systemId, {
        limit: COLLECTION_PAGE_SIZE,
        offset,
      });
    if (isSystemContextCurrent(context)) setVulnerabilityObservationPage(nextPage);
  }

  async function runAction(
    label: string,
    work: () => Promise<void>,
    shouldApply: () => boolean = () => true,
  ): Promise<void> {
    if (shouldApply()) {
      setBusyAction(label);
      setError(null);
      setNotice(null);
    }
    try {
      await work();
    } catch (reason) {
      if (shouldApply()) setError(asErrorMessage(reason));
    } finally {
      if (shouldApply()) setBusyAction(null);
    }
  }

  function handleCreateProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!confirmArchitectureDiscard()) return;
    const startingGeneration = systemContextGeneration.current;
    void runAction('project', async () => {
      const created = await api.createProject({
        name: projectName,
        description: projectDescription,
      });
      setProjects((current) => [...current, created]);
      if (startingGeneration === systemContextGeneration.current) {
        beginSystemContext('');
        setArchitectureDirty(false);
        setSelectedProjectId(created.id);
        resetGlobalIntelContext();
      }
      setProjectName('');
      setProjectDescription('');
      setNotice(`Projektet ${created.name} skapades.`);
    });
  }

  function handleCreateSystem(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedProjectId) return;
    if (!confirmArchitectureDiscard()) return;
    const projectId = selectedProjectId;
    const startingGeneration = systemContextGeneration.current;
    void runAction('system', async () => {
      const created = await api.createSystem(projectId, {
        name: systemName,
        description: systemDescription,
        owner: systemOwner,
        criticality: systemCriticality,
      });
      if (startingGeneration === systemContextGeneration.current) {
        setSystems((current) => [...current, created]);
        setArchitectureDirty(false);
        beginSystemContext(created.id);
        resetGlobalIntelContext();
      }
      setSystemName('');
      setSystemDescription('');
      setSystemOwner('');
      setNotice(`Systemet ${created.name} skapades.`);
    });
  }

  function handleAuthorize(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const context = captureSystemContext();
    if (!context.systemId || !confirmed) return;
    const normalizedTargets = [
      ...new Set(
        targets
          .split(/[\n,]/)
          .map((target) => target.trim())
          .filter(Boolean),
      ),
    ];
    void runAction('authorization', async () => {
      const created = await api.createAuthorization(context.systemId, {
        targets: normalizedTargets,
        profile,
        approved_by: approvedBy,
        purpose,
        expires_at: new Date(expiresAt).toISOString(),
        confirmation: AUTHORIZATION_CONFIRMATION,
      });
      if (!isSystemContextCurrent(context)) return;
      setAuthorization(created);
      setNotice('Den tidsbegränsade skanningsauktoriseringen är aktiv.');
    }, () => isSystemContextCurrent(context));
  }

  function handleQueueScan() {
    const context = captureSystemContext();
    const currentAuthorization = authorization;
    if (!context.systemId || !currentAuthorization) return;
    void runAction('queue', async () => {
      const scan = await api.queueNmapScan(context.systemId, currentAuthorization.id);
      await refreshSystemData(context.systemId, () => isSystemContextCurrent(context));
      if (!isSystemContextCurrent(context)) return;
      setSelectedScanId(scan.id);
      setNotice(
        'Skanningen är köad. Det betyder inte att den körs förrän en separat, aktiverad worker hämtar jobbet.',
      );
    }, () => isSystemContextCurrent(context));
  }

  function handleImport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const context = captureSystemContext();
    const currentAuthorization = authorization;
    const currentFile = xmlFile;
    if (!context.systemId || !currentAuthorization || !currentFile) return;
    if (currentFile.size === 0) {
      setError('XML-filen är tom.');
      return;
    }
    if (currentFile.size > MAX_XML_BYTES) {
      setError('XML-filen överskrider klientgränsen 16 MiB. Serverns gräns kan vara lägre.');
      return;
    }
    void runAction('import', async () => {
      const scan = await api.importNmapXml(
        context.systemId,
        currentAuthorization.id,
        currentFile,
      );
      await refreshSystemData(context.systemId, () => isSystemContextCurrent(context));
      if (!isSystemContextCurrent(context)) return;
      setSelectedScanId(scan.id);
      setXmlFile(null);
      setNotice('Nmap XML validerades och importerades. Arkitekturen är fortfarande ett utkast.');
    }, () => isSystemContextCurrent(context));
  }

  async function handleSaveArchitecture(input: ArchitectureVersionInput): Promise<void> {
    const context = captureSystemContext();
    if (!context.systemId) throw new Error('Välj ett system innan arkitekturen sparas.');
    if (!canAnalyze) throw new Error('Din roll får inte spara arkitekturversioner.');
    setBusyAction('architecture-save');
    setError(null);
    setNotice(null);
    try {
      const created = await api.saveArchitectureVersion(context.systemId, input);
      if (!isSystemContextCurrent(context)) return;
      setArchitectureVersions((current) => [
        created,
        ...current.filter((version) => version.id !== created.id),
      ]);
      setOverview((current) =>
        current ? { ...current, latest_architecture: created } : current,
      );
      try {
        await refreshSystemData(context.systemId, () => isSystemContextCurrent(context));
        if (!isSystemContextCurrent(context)) return;
        setNotice(
          `Arkitekturversion v${created.version} sparades utan att skriva över tidigare evidens.`,
        );
      } catch (reason) {
        setError(
          `Arkitekturversion v${created.version} sparades, men arbetsytan kunde inte läsas om: ${asErrorMessage(reason)}`,
        );
      }
    } finally {
      if (isSystemContextCurrent(context)) setBusyAction(null);
    }
  }

  async function handleFindingLifecycleUpdate(
    findingId: string,
    lifecycleStatus: FindingLifecycleStatus,
    reason: string,
  ): Promise<Finding> {
    const context = captureSystemContext();
    if (!context.systemId) throw new Error('Välj ett system innan fyndet uppdateras.');
    if (!canAnalyze) throw new Error('Din roll får inte ändra fyndets livscykel.');
    setBusyAction(`finding-${findingId}`);
    setError(null);
    setNotice(null);
    try {
      const updated = await api.updateFindingLifecycle(
        context.systemId,
        findingId,
        lifecycleStatus,
        reason,
      );
      if (!isSystemContextCurrent(context)) return updated;
      setOverview((current) =>
        current
          ? {
              ...current,
              findings: current.findings.map((finding) =>
                finding.id === updated.id ? updated : finding,
              ),
            }
          : current,
      );
      setFindingPage((current) => ({
        ...current,
        items: current.items.map((finding) =>
          finding.id === updated.id
            ? {
                ...finding,
                status: updated.status,
                lifecycle_status: updated.lifecycle_status,
                resolved_at: updated.resolved_at,
                last_seen_at: updated.last_seen_at,
              }
            : finding,
        ),
      }));
      setReviewFindingPage((current) => ({
        ...current,
        items: current.items.filter((finding) => finding.id !== updated.id),
        total: Math.max(
          0,
          current.total - (current.items.some((finding) => finding.id === updated.id) ? 1 : 0),
        ),
      }));
      setNotice(`Fyndet markerades som ${findingLifecycleLabel(updated.lifecycle_status).toLowerCase()}.`);
      return updated;
    } finally {
      if (isSystemContextCurrent(context)) setBusyAction(null);
    }
  }

  function upsertBackgroundJob(job: BackgroundJob): void {
    if (job.system_id !== selectedSystemId) return;
    setBackgroundJobs((current) => {
      const exists = current.items.some((item) => item.id === job.id);
      return {
        ...current,
        items: [job, ...current.items.filter((item) => item.id !== job.id)],
        total: exists ? current.total : current.total + 1,
        offset: 0,
      };
    });
  }

  async function registerEnqueuedJob(
    job: BackgroundJob,
    context: SystemRequestContext,
  ): Promise<boolean> {
    if (!isSystemContextCurrent(context) || job.system_id !== context.systemId) return false;
    upsertBackgroundJob(job);
    if (job.status !== 'completed' || completedJobRefreshes.current.has(job.id)) {
      return false;
    }
    completedJobRefreshes.current.add(job.id);
    await refreshSystemData(job.system_id, () => isSystemContextCurrent(context));
    if (!isSystemContextCurrent(context)) return false;
    setNotice(backgroundJobCompletionMessage([job]));
    return true;
  }

  function handleVulnerabilityImport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const context = captureSystemContext();
    const currentFile = vulnerabilityFile;
    const currentFormat = vulnerabilityFormat;
    if (!context.systemId || !currentFile) return;
    if (currentFile.size === 0) {
      setError('Sårbarhetsrapporten är tom.');
      return;
    }
    if (currentFile.size > MAX_VULNERABILITY_REPORT_BYTES) {
      setError('Sårbarhetsrapporten överskrider klientgränsen 32 MiB.');
      return;
    }
    void runAction('vulnerability-import', async () => {
      const idempotencyKey =
        vulnerabilityUploadIdempotencyKey.current ??
        `vulnerability-${crypto.randomUUID()}`;
      vulnerabilityUploadIdempotencyKey.current = idempotencyKey;
      let result: BackgroundJobEnqueueResult;
      if (currentFormat === 'nessus') {
        result = await api.enqueueNessusImport(
          context.systemId,
          currentFile.name,
          currentFile,
          idempotencyKey,
        );
      } else {
        let parsed: unknown;
        try {
          parsed = JSON.parse(await currentFile.text());
        } catch {
          throw new Error('JSON-filen kunde inte tolkas.');
        }
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          throw new Error('Det normaliserade leverantörsunderlaget måste vara ett JSON-objekt.');
        }
        result = await api.enqueueNormalizedVulnerabilityImport(
          context.systemId,
          parsed as VulnerabilityScanImportInput,
          idempotencyKey,
        );
      }
      if (!isSystemContextCurrent(context)) return;
      const completedImmediately = await registerEnqueuedJob(result.job, context);
      if (!isSystemContextCurrent(context)) return;
      setVulnerabilityFile(null);
      vulnerabilityUploadIdempotencyKey.current = null;
      if (!completedImmediately) {
        setNotice(
          result.idempotent_replay
            ? 'Det befintliga importjobbet återanvändes och följs tills det är klart.'
            : 'Importjobbet köades. Resultatet visas när en worker har slutfört det.',
        );
      }
    }, () => isSystemContextCurrent(context));
  }

  function handleSync(provider: IntelligenceProvider) {
    const context = captureSystemContext();
    if (!context.systemId) return;
    void runAction(`sync-${provider}`, async () => {
      const result = await api.syncIntelligence(context.systemId, provider);
      if (!isSystemContextCurrent(context)) return;
      setSyncResult(result);
      await refreshSystemData(context.systemId, () => isSystemContextCurrent(context));
      if (!isSystemContextCurrent(context)) return;
      setNotice(`${result.provider}: ${result.matched} poster matchades.`);
    }, () => isSystemContextCurrent(context));
  }

  function handleNetBoxSync() {
    const context = captureSystemContext();
    if (!context.systemId) return;
    void runAction('sync-netbox', async () => {
      const snapshot = await api.syncNetBox(context.systemId);
      if (!isSystemContextCurrent(context)) return;
      setSourceSnapshots((current) => [
        snapshot,
        ...current.filter((item) => item.id !== snapshot.id),
      ]);
      setNotice(
        `NetBox: ${snapshot.record_count} källposter sparades som ogranskat underlag. Arkitekturen ändrades inte.`,
      );
    }, () => isSystemContextCurrent(context));
  }

  async function handleExternalIntelligenceSynced(
    _result: ExternalIntelligencePullResult,
  ): Promise<void> {
    const context = captureSystemContext();
    await Promise.all([
      loadGlobalIntelPage(0, appliedIntelFilters),
      loadPendingIntelPage(0),
      context.systemId
        ? refreshSystemData(context.systemId, () => isSystemContextCurrent(context))
        : Promise.resolve(),
    ]);
  }

  async function handleIntelReview(
    recordId: string,
    decision: 'approved' | 'rejected',
    note: string,
  ): Promise<void> {
    if (!canAnalyze || !hasOrganizationWideAccess) {
      throw new Error(
        'Granskning av globala datapunkter kräver organisationsomfattande analysbehörighet.',
      );
    }
    const context = captureSystemContext();
    await runAction(
      `intel-review-${recordId}`,
      async () => {
        const result = await api.reviewGlobalIntel(recordId, decision, note.trim() || undefined);
        if (!isSystemContextCurrent(context)) return;
        setPendingIntelPage((current) => ({
          ...current,
          items: current.items.filter((record) => record.id !== recordId),
          total: Math.max(0, current.total - 1),
        }));
        await Promise.all([
          loadGlobalIntelPage(0, appliedIntelFilters),
          refreshSystemData(context.systemId, () => isSystemContextCurrent(context)),
        ]);
        if (!isSystemContextCurrent(context)) return;
        setNotice(
          decision === 'approved'
            ? `Datapunkten godkändes och ${result.correlation_job_ids.length} korrelationsjobb köades.`
            : result.correlation_job_ids.length > 0
              ? `Datapunkten avvisades och ${result.correlation_job_ids.length} omkorrelationsjobb köades för att stänga tidigare härledda samband.`
              : 'Datapunkten avvisades. Inga nya omkorrelationsjobb behövdes.',
        );
      },
      () => isSystemContextCurrent(context),
    );
  }

  function handleIntelSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const filters = {
      ...(intelSourceKind ? { sourceKind: intelSourceKind } : {}),
      ...(intelQuery.trim() ? { query: intelQuery.trim() } : {}),
    };
    setAppliedIntelFilters(filters);
    setIntelPage({
      items: [],
      total: 0,
      limit: COLLECTION_PAGE_SIZE,
      offset: 0,
    });
    requestGlobalIntelPage(0, filters);
  }

  function handleIntelCorrelation() {
    const context = captureSystemContext();
    if (!context.systemId) return;
    void runAction('intel-correlation', async () => {
      const result = await api.correlateGlobalIntel(context.systemId);
      if (!isSystemContextCurrent(context)) return;
      setCorrelationResult(result);
      await Promise.all([
        refreshSystemData(context.systemId, () => isSystemContextCurrent(context)),
        canReadGlobalIntelligence
          ? loadGlobalIntelPage(0, appliedIntelFilters)
          : Promise.resolve(),
      ]);
      if (!isSystemContextCurrent(context)) return;
      setNotice(
        `Omvärldsdata korrelerades: ${result.finding_matches} fyndmatchningar och ${result.threat_records_matched} relevanta hotposter.`,
      );
    }, () => isSystemContextCurrent(context));
  }

  function handleCreateReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const context = captureSystemContext();
    if (!context.systemId || !canAnalyze) return;
    if (activeTab === 'architecture' && !confirmArchitectureDiscard()) return;
    void runAction('report', async () => {
      const result = await api.enqueueReport(
        context.systemId,
        reportFormat,
        reportType,
        `report-${crypto.randomUUID()}`,
      );
      if (!isSystemContextCurrent(context)) return;
      const completedImmediately = await registerEnqueuedJob(result.job, context);
      if (!isSystemContextCurrent(context)) return;
      setActiveTab('reports');
      if (!completedImmediately) {
        setNotice('Rapportjobbet köades. Filen visas när en worker har slutfört jobbet.');
      }
    }, () => isSystemContextCurrent(context));
  }

  function handleCancelBackgroundJob(job: BackgroundJob): void {
    const context = captureSystemContext(job.system_id);
    if (
      !canAnalyze ||
      !isSystemContextCurrent(context) ||
      (job.status !== 'queued' && job.status !== 'running')
    ) return;
    void runAction(`cancel-job-${job.id}`, async () => {
      const updated = await api.cancelBackgroundJob(job.id);
      if (!isSystemContextCurrent(context) || updated.system_id !== context.systemId) return;
      upsertBackgroundJob(updated);
      setNotice(
        updated.status === 'cancelled'
          ? 'Bakgrundsjobbet avbröts innan bearbetning.'
          : 'Begäran om avbrott registrerades och inväntar workern.',
      );
    }, () => isSystemContextCurrent(context));
  }

  function handleDownload(report: Report) {
    const context = captureSystemContext(report.system_id);
    if (!isSystemContextCurrent(context)) return;
    if (report.export_status !== 'available') {
      setNotice(null);
      setError(
        report.withdrawal_reason ??
          'Rapporten har återkallats efter en strängare informationsklassning.',
      );
      return;
    }
    void runAction(`download-${report.id}`, async () => {
      const download = await api.downloadReport(report.id);
      if (!isSystemContextCurrent(context)) return;
      if (download.sha256 !== null && download.sha256 !== report.sha256) {
        throw new Error('Nedladdningen stoppades eftersom kontrollsumman inte matchar rapporten.');
      }
      const url = URL.createObjectURL(download.blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = download.filename;
      anchor.rel = 'noopener';
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setNotice(
        'Rapportfilen hämtades; svarshuvudets kontrollsumma stämde med rapportposten när den fanns.',
      );
    }, () => isSystemContextCurrent(context));
  }

  const tabItems: Array<{ id: WorkspaceTab; label: string; count?: number }> = [
    { id: 'overview', label: 'Översikt' },
    { id: 'assets', label: 'Tillgångar', count: collectionTotals.assets },
    {
      id: 'intel',
      label: 'Omvärld',
      count: canReadGlobalIntelligence ? intelPage.total : reviewFindingPage.total,
    },
    { id: 'threats', label: 'Hot', count: collectionTotals.threats },
    { id: 'findings', label: 'Fynd', count: collectionTotals.findings },
    { id: 'risks', label: 'Risker', count: collectionTotals.risks },
    { id: 'architecture', label: 'Arkitektur' },
    { id: 'reports', label: 'Rapporter', count: reports.length },
  ];

  return (
    <main className="op-workspace">
      <header className="op-heading">
        <div>
          <span className="eyebrow">OPERATIV ANALYSKEDJA</span>
          <h1>Säkerhetsöversikt</h1>
          <p>Tidigare skanningar och beständig analysdata, med tydlig källstatus och osäkerhet.</p>
        </div>
        <button
          className="secondary-button"
          disabled={!canRead || !selectedSystemId || busyAction !== null}
          onClick={() => {
            const context = captureSystemContext();
            if (!context.systemId) return;
            void runAction(
              'refresh',
              () => refreshSystemData(context.systemId, () => isSystemContextCurrent(context)),
              () => isSystemContextCurrent(context),
            );
          }}
        >
          <Icon name="history" size={16} /> Uppdatera
        </button>
      </header>

      <div className="op-safety-banner" role="note">
        <Icon name="shield" size={19} />
        <div>
          <strong>Auktoriserad användning krävs</strong>
          <p>
            Endast system du äger eller uttryckligen får testa får skannas. En köad skanning är inte
            bevis på att en worker kör, och ett öppet portfynd är inte bevis på exponering eller
            exploaterbarhet.
          </p>
        </div>
      </div>

      {principal && (
        <div className="op-principal" aria-label="Aktiv behörighetskontext">
          <span><Icon name="user" size={15} /></span>
          <div>
            <strong>{principal.organization_name}</strong>
            <small>
              {principal.roles.join(', ') || 'Ingen tilldelad roll'} ·{' '}
              {hasOrganizationWideAccess ? 'organisationsomfattande' : 'resursbegränsad'}
            </small>
          </div>
        </div>
      )}

      {!contextLoading && principal && !canRead ? (
        <EmptyState title="Arbetsytan är inte tillgänglig för din roll">
          Kontot saknar läsbehörighet till operativa projekt. Inga produktkontroller visas.
        </EmptyState>
      ) : <section className="op-context panel" aria-label="Projekt och system">
        <div className="op-context__selectors">
          <label>
            <span>Projekt</span>
            <select
              aria-label="Valt projekt"
              value={selectedProjectId}
              onChange={(event) => selectProject(event.target.value)}
            >
              <option value="">Välj projekt</option>
              {projects.map((project) => (
                <option key={project.id} value={project.id}>{project.name}</option>
              ))}
            </select>
          </label>
          <label>
            <span>System</span>
            <select
              aria-label="Valt system"
              disabled={!selectedProjectId}
              value={selectedSystemId}
              onChange={(event) => selectSystem(event.target.value)}
            >
              <option value="">Välj system</option>
              {systems.map((system) => (
                <option key={system.id} value={system.id}>{system.name}</option>
              ))}
            </select>
          </label>
          <div className="op-context__state">
            {contextLoading ? (
              <span>Läser från API…</span>
            ) : contextLoadError ? (
              <span>API-data kunde inte läsas</span>
            ) : (
              <span>API-data inläst</span>
            )}
            <small>Ingen kontinuerlig liveinsamling hävdas.</small>
          </div>
        </div>

        {(canCreateProject || canCreateSystem) && <div className="op-create-grid">
          {canCreateProject && <details open>
            <summary>Nytt projekt</summary>
            <form onSubmit={handleCreateProject}>
              <label><span>Namn</span><input required minLength={2} value={projectName} onChange={(event) => setProjectName(event.target.value)} /></label>
              <label><span>Beskrivning</span><input value={projectDescription} onChange={(event) => setProjectDescription(event.target.value)} /></label>
              <button className="secondary-button" disabled={busyAction !== null}>Skapa projekt</button>
            </form>
          </details>}
          {canCreateSystem && <details open>
            <summary>Nytt system</summary>
            <form onSubmit={handleCreateSystem}>
              <label><span>Namn</span><input required minLength={2} value={systemName} onChange={(event) => setSystemName(event.target.value)} /></label>
              <label><span>Ägare</span><input required minLength={2} value={systemOwner} onChange={(event) => setSystemOwner(event.target.value)} /></label>
              <label><span>Beskrivning</span><input value={systemDescription} onChange={(event) => setSystemDescription(event.target.value)} /></label>
              <label>
                <span>Kritikalitet</span>
                <select value={systemCriticality} onChange={(event) => setSystemCriticality(event.target.value as Criticality)}>
                  <option value="low">Låg</option><option value="medium">Medel</option>
                  <option value="high">Hög</option><option value="critical">Kritisk</option>
                </select>
              </label>
              <button className="secondary-button" disabled={!selectedProjectId || busyAction !== null}>Skapa system</button>
            </form>
          </details>}
        </div>}
      </section>}

      {error && <div className="op-feedback op-feedback--error" role="alert"><Icon name="alert" size={17} /> {error}</div>}
      {notice && <div className="op-feedback op-feedback--success" role="status"><Icon name="check" size={17} /> {notice}</div>}

      {!canRead ? null : !selectedSystem ? (
        <EmptyState title="Välj eller skapa ett system">
          Arbetsflödet visas först när operational-API:t har ett valt system.
        </EmptyState>
      ) : (
        <>
          <section className="op-system-header panel">
            <div>
              <span className={`op-criticality op-criticality--${selectedSystem.criticality}`}>
                {criticalityLabel(selectedSystem.criticality)}
              </span>
              <h2>{selectedSystem.name}</h2>
              <p>{selectedSystem.description || 'Ingen systembeskrivning angiven.'}</p>
            </div>
            <dl>
              <div><dt>Ägare</dt><dd>{selectedSystem.owner}</dd></div>
              <div><dt>Senast uppdaterat</dt><dd>{formatDate(selectedSystem.updated_at)}</dd></div>
              <div><dt>System-ID</dt><dd className="mono">{selectedSystem.id}</dd></div>
            </dl>
          </section>

          <section className="op-metrics" aria-label="Operativ sammanfattning">
            {[
              ['Tillgångar', collectionTotals.assets, 'asset'],
              ['Tjänster', collectionTotals.services, 'server'],
              ['Hot', collectionTotals.threats, 'threat'],
              ['Fynd', collectionTotals.findings, 'vulnerability'],
              ['Risker', collectionTotals.risks, 'risk'],
              ['Arkitektur', overview?.latest_architecture?.status ?? 'Saknas', 'architecture'],
            ].map(([label, value, icon]) => (
              <article key={label}>
                <span><Icon name={icon as 'asset'} size={17} /></span>
                <div><strong>{value}</strong><small>{label}</small></div>
              </article>
            ))}
          </section>

          <section className="op-pipeline panel" aria-label="Analyskedja">
            {[
              ['1', 'Auktorisering', authorization?.status === 'active' ? 'Aktiv' : 'Saknas'],
              ['2', 'Skanning', overview?.latest_scan ? scanStatusLabel(overview.latest_scan.status) : 'Ej körd'],
              ['3', 'Inventering', `${collectionTotals.assets} tillgångar`],
              ['4', 'Hotdata', `${collectionTotals.threats} matchningar`],
              ['5', 'Fyndkorrelation', `${collectionTotals.findings} fynd`],
              ['6', 'Risk', `${collectionTotals.risks} bedömningar`],
              ['7', 'Rapport', `${reports.length} skapade`],
            ].map(([step, label, value]) => (
              <div key={step} className="op-pipeline__step">
                <span>{step}</span><strong>{label}</strong><small>{value}</small>
              </div>
            ))}
          </section>

          {(canAdminister || canManageScans || canAnalyze || canIngestIntelligence) && <section className="op-control-grid">
            {canAdminister && <article className="panel op-control-card op-control-card--wide">
              <header><span className="section-kicker">STEG 1</span><h2>Tidsbegränsad skanningsauktorisering</h2></header>
              <form className="op-form-grid" onSubmit={handleAuthorize}>
                <label className="op-form-grid__wide"><span>IP eller CIDR, en per rad</span><textarea placeholder="Ange ett uttryckligen godkänt mål" required value={targets} onChange={(event) => setTargets(event.target.value)} /></label>
                <label><span>Fast profil</span><select value={profile} onChange={(event) => setProfile(event.target.value as ScanProfile)}><option value="discovery">Discovery</option><option value="service_inventory">Service inventory</option></select></label>
                <label><span>Godkänd av</span><input required minLength={2} value={approvedBy} onChange={(event) => setApprovedBy(event.target.value)} /></label>
                <label className="op-form-grid__wide"><span>Syfte</span><textarea required minLength={10} value={purpose} onChange={(event) => setPurpose(event.target.value)} /></label>
                <label><span>Giltig till, högst 24 timmar</span><input required type="datetime-local" min={dateTimeLocal(5)} max={dateTimeLocal(24 * 60)} value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
                <label className="op-confirmation"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>{AUTHORIZATION_CONFIRMATION}</span></label>
                <button className="primary-button" disabled={!confirmed || busyAction !== null}>Skapa auktorisering</button>
              </form>
              {authorization && <footer><strong>Aktiv scope:</strong> {authorization.targets.join(', ')} · upphör {formatDate(authorization.expires_at)} · hash <span className="mono">{authorization.scope_sha256.slice(0, 12)}…</span></footer>}
            </article>}

            {canManageScans && <article className="panel op-control-card">
              <header><span className="section-kicker">STEG 2</span><h2>Skanning eller säker import</h2></header>
              <button className="primary-button" disabled={!authorization || busyAction !== null} onClick={handleQueueScan}><Icon name="scan" size={16} /> Köa extern Nmap-worker</button>
              <p className="op-caveat">Köning startar inte Nmap i webbläsaren. En separat worker måste vara aktiverad, isolerad och använda kundinstallerad/licensierad Nmap.</p>
              <form className="op-upload" onSubmit={handleImport}>
                <label><span>Nmap XML-fil</span><input key={`nmap-${selectedSystemId}`} type="file" accept=".xml,application/xml,text/xml" onChange={(event) => setXmlFile(event.target.files?.[0] ?? null)} /></label>
                <button className="secondary-button" disabled={!authorization || !xmlFile || busyAction !== null}>Validera och importera XML</button>
              </form>
            </article>}

            {canAnalyze && <article className="panel op-control-card">
              <header><span className="section-kicker">STEG 3–5</span><h2>Synkronisera hot- och exploateringsdata</h2></header>
              <div className="op-action-stack">
                <button disabled={busyAction !== null} onClick={handleNetBoxSync}>NetBox inventory <small>Read-only, ogranskat källsnapshot</small></button>
                <button disabled={busyAction !== null} onClick={() => handleSync('nvd')}>NVD CVE 2.0 <small>CPE-träff skapar endast kandidater</small></button>
                <button disabled={busyAction !== null} onClick={() => handleSync('kev')}>CISA KEV <small>Katalogmedlemskap, inte poäng</small></button>
                <button disabled={busyAction !== null} onClick={() => handleSync('epss')}>FIRST EPSS <small>Sannolikhet, inte verifierad exploatering</small></button>
                <button disabled={busyAction !== null} onClick={() => handleSync('internal')}>Intern hotfeed <small>Kräver serverkonfigurerad källa</small></button>
              </div>
              {sourceSnapshots[0] && <div className="op-sync-result"><strong>Senaste NetBox-snapshot</strong><span>{sourceSnapshots[0].record_count} poster · {sourceSnapshots[0].page_count} sidor · ogranskat</span><small>SHA-256 {sourceSnapshots[0].manifest_sha256.slice(0, 16)}… · ingen automatisk publicering till arkitekturen</small></div>}
              {syncResult && <div className="op-sync-result"><strong>{syncResult.provider}</strong><span>Hämtade {syncResult.fetched} · matchade {syncResult.matched} · uppdaterade {syncResult.updated}</span>{syncResult.warnings.map((warning) => <small key={warning}>{warning}</small>)}</div>}
            </article>}

            {canAnalyze && <article className="panel op-control-card">
              <header><span className="section-kicker">STEG 7</span><h2>Skapa fryst rapportunderlag</h2></header>
              <form className="op-report-form" onSubmit={handleCreateReport}>
                <label><span>Rapporttyp</span><select value={reportType} onChange={(event) => setReportType(event.target.value as ReportType)}><option value="management">Ledning</option><option value="technical">Teknisk</option><option value="risk_register">Riskregister</option></select></label>
                <label><span>Format</span><select value={reportFormat} onChange={(event) => setReportFormat(event.target.value as ReportFormat)}><option value="pdf">PDF</option><option value="json">JSON</option><option value="csv">CSV</option></select></label>
                <button className="primary-button" disabled={busyAction !== null}><Icon name="report" size={16} /> Köa rapport</button>
              </form>
              <p className="op-caveat">Rapporttyperna har separata innehållskontrakt. Varje rapport fryser aktuellt underlag och gör inte kandidater till bekräftade fakta.</p>
            </article>}
          </section>}

          <BackgroundJobPanel
            busy={busyAction !== null}
            canCancel={canAnalyze}
            jobs={backgroundJobs.items.filter((job) => job.system_id === selectedSystemId)}
            onCancel={handleCancelBackgroundJob}
          />

          <div className="op-tabs" role="tablist" aria-label="Operativ data">
            {tabItems.map((tab) => (
              <button key={tab.id} role="tab" aria-selected={activeTab === tab.id} className={activeTab === tab.id ? 'is-active' : ''} onClick={() => selectWorkspaceTab(tab.id)}>
                {tab.label}{tab.count !== undefined && <span>{tab.count}</span>}
              </button>
            ))}
          </div>

          {overview?.collections_truncated && (
            <div className="op-collection-note" role="note">
              Översikten visar högst {overview.collection_limit} poster per samling. Fynd, risker
              leverantörsobservationer, tillgångar och hot hämtas sidvis. Tjänster läses separat
              för den valda tillgången.
            </div>
          )}

          <section className="panel op-data-panel">
            {activeTab === 'overview' && (
              <div className="op-overview-grid">
                <div>
                  <header className="op-section-heading"><div><span className="section-kicker">HISTORIK</span><h2>Skanningar</h2></div></header>
                  {scans.length === 0 ? <EmptyState title="Ingen skanning ännu">Skapa först en auktorisering och köa en worker eller importera validerad Nmap XML.</EmptyState> : <div className="op-list">{scans.map((scan) => <button key={scan.id} className={selectedScan?.id === scan.id ? 'is-selected' : ''} onClick={() => setSelectedScanId(scan.id)}><span className={`op-status-dot op-status-dot--${scan.status}`} /><span><strong>{scan.mode === 'live' ? 'Extern Nmap-worker' : 'Importerad Nmap XML'}</strong><small>{formatDate(scan.requested_at)} · {scanStatusLabel(scan.status)}</small></span><Icon name="chevron" size={15} /></button>)}</div>}
                </div>
                <aside className="op-inspector">
                  <span className="section-kicker">VALD SKANNING</span>
                  {selectedScan ? <><h3>{scanStatusLabel(selectedScan.status)}</h3><dl><div><dt>Läge</dt><dd>{selectedScan.mode}</dd></div><div><dt>Scanner</dt><dd>{selectedScan.scanner}</dd></div><div><dt>Start</dt><dd>{formatDate(selectedScan.started_at)}</dd></div><div><dt>Slut</dt><dd>{formatDate(selectedScan.completed_at)}</dd></div></dl>{selectedScan.error_message && <p className="op-error-copy">{selectedScan.error_message}</p>}<pre>{JSON.stringify(selectedScan.result_summary, null, 2)}</pre></> : <p>Ingen skanning vald.</p>}
                </aside>
              </div>
            )}

            {activeTab === 'assets' && (
              <div className="op-overview-grid">
                <div>
                  <header className="op-section-heading">
                    <div><span className="section-kicker">OBSERVERADE</span><h2>Tillgångar</h2></div>
                    <small>Sett från en skanningspunkt vid en tidpunkt</small>
                  </header>
                  {assetPage.items.length > 0 ? (
                    <div className="op-list">
                      {assetPage.items.map((asset) => (
                        <button
                          key={asset.id}
                          className={selectedAsset?.id === asset.id ? 'is-selected' : ''}
                          onClick={() => setSelectedAssetId(asset.id)}
                        >
                          <span className="op-list__icon"><Icon name="server" size={16} /></span>
                          <span>
                            <strong>{asset.hostname ?? asset.primary_ip}</strong>
                            <small>
                              {asset.primary_ip} · {asset.state} ·{' '}
                              {inventoryStatusLabel(asset.inventory_status)}
                            </small>
                          </span>
                          <Icon name="chevron" size={15} />
                        </button>
                      ))}
                    </div>
                  ) : (
                    <EmptyState title="Inga observerade tillgångar">
                      En tom lista betyder bara att inget har observerats i den aktuella skanningen.
                    </EmptyState>
                  )}
                  <PaginationControls
                    ariaLabel="Sidindelning för tillgångar"
                    busy={busyAction !== null}
                    onPage={(offset) =>
                      void runAction('asset-page', () => loadAssetPage(offset))
                    }
                    page={assetPage}
                  />
                </div>
                <aside className="op-inspector">
                  {selectedAsset ? (
                    <AssetInspector key={`${selectedSystemId}:${selectedAsset.id}`} api={api} asset={selectedAsset} systemId={selectedSystemId} />
                  ) : (
                    <p>Ingen tillgång vald.</p>
                  )}
                </aside>
              </div>
            )}

            {activeTab === 'intel' && (
              <div className="op-intel">
                <header className="op-section-heading">
                  <div>
                    <span className="section-kicker">
                      {canReadGlobalIntelligence ? 'GLOBAL INTELLIGENCE' : 'SYSTEMKANDIDATER'}
                    </span>
                    <h2>
                      {canReadGlobalIntelligence
                        ? 'Omvärld och inkommande hotdata'
                        : 'Omvärldskorrelation för valt system'}
                    </h2>
                  </div>
                  <small>
                    {canReadGlobalIntelligence
                      ? 'Råkälla och AI-analys lagras separat. Poster blir systemhot eller risker först efter en spårbar match mot aktuell CVE, CPE, produkt eller tillgång.'
                      : 'Den här resursbegränsade vyn visar endast kandidater som redan har kopplats till valt system. Tenantens råa intelligensmaterial visas inte.'}
                  </small>
                </header>
                {canReadGlobalIntelligence && (
                  <ExternalIntelligenceConnectorPanel
                    api={api}
                    canAdminister={canAdminister && hasOrganizationWideAccess}
                    canSync={canIngestIntelligence && hasOrganizationWideAccess}
                    onSynced={handleExternalIntelligenceSynced}
                  />
                )}
                {!canReadGlobalIntelligence && (
                  <div className="op-collection-note" role="note">
                    Connectorstatus, synkhistorik, råposter och tenantgemensam granskningskö kräver
                    en organisationsomfattande analytiker- eller administratörsidentitet.
                  </div>
                )}
                {(canReadGlobalIntelligence || canAnalyze) && <div className="op-intel__controls">
                  {canReadGlobalIntelligence && <form onSubmit={handleIntelSearch}>
                    <label>
                      <span>Sök</span>
                      <input
                        aria-label="Sök i omvärldsdata"
                        minLength={2}
                        placeholder="Titel, leverantör eller externt ID"
                        value={intelQuery}
                        onChange={(event) => setIntelQuery(event.target.value)}
                      />
                    </label>
                    <label>
                      <span>Källa</span>
                      <select
                        aria-label="Filtrera omvärldskälla"
                        value={intelSourceKind}
                        onChange={(event) =>
                          setIntelSourceKind(event.target.value as IntelSourceKind | '')
                        }
                      >
                        <option value="">Alla källor</option>
                        <option value="news">Cybernyheter</option>
                        <option value="misp">MISP</option>
                        <option value="vulnerability">Sårbarhetsdata</option>
                        <option value="other">Övrigt</option>
                      </select>
                    </label>
                    <button
                      className="secondary-button"
                      disabled={intelLoading || busyAction !== null}
                    >
                      Sök och filtrera
                    </button>
                  </form>}
                  {canAnalyze && (
                    <button
                      className="primary-button"
                      disabled={!overview?.latest_scan || busyAction !== null}
                      onClick={handleIntelCorrelation}
                    >
                      <Icon name="threat" size={16} /> Korrelera mot valt system
                    </button>
                  )}
                </div>}
                {correlationResult && (
                  <div className="op-intel__result" role="status">
                    <strong>Senaste korrelationen</strong>
                    <span>
                      {correlationResult.records_considered} granskade ·{' '}
                      {correlationResult.findings_created} nya fynd ·{' '}
                      {correlationResult.threats_created} nya hot ·{' '}
                      {correlationResult.risks_created} nya risker
                    </span>
                  </div>
                )}
                {canReadGlobalIntelligence && <section className="op-review-queue" aria-label="Analytikerns granskningskö">
                  <header className="op-section-heading">
                    <div>
                      <span className="section-kicker">ANALYTIKERGRANSKNING</span>
                      <h3>Inkommande datapunkter</h3>
                    </div>
                    <small>
                      {pendingIntelPage.total} poster väntar på godkännande eller avvisning innan
                      de får köas för systemkorrelation.
                    </small>
                  </header>
                  {pendingIntelPage.items.length === 0 ? (
                    <p>Inga inkommande datapunkter väntar på granskning.</p>
                  ) : (
                    <div className="op-card-grid">
                      {pendingIntelPage.items.map((record) => (
                        <IntelReviewCard
                          busy={busyAction !== null}
                          canAnalyze={canAnalyze && hasOrganizationWideAccess}
                          key={`intel-review-${record.id}`}
                          onReview={handleIntelReview}
                          record={record}
                        />
                      ))}
                    </div>
                  )}
                  <PaginationControls
                    ariaLabel="Sidindelning för inkommande datapunkter"
                    busy={busyAction !== null}
                    onPage={(offset) =>
                      void runAction('intel-review-page', () => loadPendingIntelPage(offset))
                    }
                    page={{
                      ...pendingIntelPage,
                      has_more:
                        pendingIntelPage.offset + pendingIntelPage.items.length < pendingIntelPage.total,
                    }}
                  />
                </section>}
                <section className="op-review-queue" aria-label="Systemets kandidatkö">
                  <header className="op-section-heading">
                    <div>
                      <span className="section-kicker">EFTER KORRELATION</span>
                      <h3>Kandidater för valt system</h3>
                    </div>
                    <small>{reviewFindingPage.total} fyndkandidater behöver ett analytikerbeslut.</small>
                  </header>
                  {reviewFindingPage.items.length === 0 ? (
                    <p>Inga korrelerade kandidater väntar på granskning.</p>
                  ) : (
                    <div className="op-card-grid">
                      {reviewFindingPage.items.map((finding) => (
                        <FindingCard
                          api={api}
                          busy={busyAction !== null}
                          canAnalyze={canAnalyze}
                          finding={finding}
                          key={`review-${selectedSystemId}-${finding.id}`}
                          onLifecycleUpdate={handleFindingLifecycleUpdate}
                          systemId={selectedSystemId}
                        />
                      ))}
                    </div>
                  )}
                  <PaginationControls
                    ariaLabel="Sidindelning för systemets kandidatkö"
                    busy={busyAction !== null}
                    onPage={(offset) => void runAction('review-page', () => loadReviewFindingPage(offset))}
                    page={reviewFindingPage}
                  />
                </section>
                {canReadGlobalIntelligence && <>{intelLoading && intelPage.items.length === 0 ? (
                  <p role="status">Läser omvärldsdata…</p>
                ) : intelPage.items.length === 0 ? (
                  <EmptyState title="Ingen omvärldsdata har importerats">
                    Separata insamlingsprogram för scraping, MISP och sårbarhetsdata ansluts via
                    intelligence-API:ts kanoniska feedformat.
                  </EmptyState>
                ) : (
                  <div
                    aria-label="Importerade omvärldsposter"
                    className="op-card-grid"
                    role="region"
                  >
                    {intelPage.items.map((record) => (
                      <details className="op-entity-card op-intel-card" key={record.id}>
                        <summary>
                          <span className="op-intel-card__markings">
                            {record.severity && (
                              <span
                                className={`op-criticality op-criticality--${record.severity}`}
                              >
                                {criticalityLabel(record.severity)}
                              </span>
                            )}
                            <span className="op-provider-badge">{record.distribution_tlp}</span>
                            <span className={`op-review-state op-review-state--${record.review_status}`}>
                              {intelReviewStatusLabel(record.review_status)}
                            </span>
                          </span>
                          <strong>{record.title}</strong>
                          <small>
                            {record.provider} · {record.source_kind} · {formatDate(record.modified_at)}
                          </small>
                        </summary>
                        <p>{record.summary}</p>
                        <dl>
                          <div><dt>Typ</dt><dd>{record.record_type}</dd></div>
                          <div><dt>Konfidens</dt><dd>{formatPercent(record.confidence)}</dd></div>
                          <div><dt>CVE</dt><dd>{record.cve_ids.join(', ') || 'Saknas'}</dd></div>
                          <div><dt>ATT&amp;CK</dt><dd>{record.mitre_attack_ids.join(', ') || 'Saknas'}</dd></div>
                          <div><dt>Indikatorer</dt><dd>{record.indicators.length}</dd></div>
                          <div><dt>Rådata SHA-256</dt><dd className="mono">{record.raw_sha256.slice(0, 16)}…</dd></div>
                          <div><dt>AI-analys</dt><dd>{record.ai_analysis ? 'Versionerad' : 'Saknas'}</dd></div>
                        </dl>
                        {record.source_url && (
                          <a href={record.source_url} target="_blank" rel="noopener noreferrer">
                            Öppna källpost
                          </a>
                        )}
                        {record.ai_analysis && <pre>{JSON.stringify(record.ai_analysis, null, 2)}</pre>}
                      </details>
                    ))}
                  </div>
                )}
                <PaginationControls
                  ariaLabel="Sidindelning för omvärldsposter"
                  busy={intelLoading || busyAction !== null}
                  onPage={(offset) => requestGlobalIntelPage(offset)}
                  page={intelPaginationPage}
                /></>}
              </div>
            )}

            {activeTab === 'threats' && (
              <>
                <EntityCards title="Aktuella hotmatchningar" caveat="En matchning är kontextuell evidens, inte bevis på kompromettering." empty="Inga hot har matchats eller importerats.">
                  {threatPage.items.map((threat) => (
                    <ThreatCard
                      api={api}
                      key={`${selectedSystemId}:${threat.id}`}
                      systemId={selectedSystemId}
                      threat={threat}
                    />
                  ))}
                </EntityCards>
                <PaginationControls
                  busy={busyAction !== null}
                  onPage={(offset) =>
                    void runAction('threat-page', () => loadThreatPage(offset))
                  }
                  page={threatPage}
                />
              </>
            )}

            {activeTab === 'findings' && (
              <div className="op-vulnerability-workspace">
                <header className="op-section-heading">
                  <div>
                    <span className="section-kicker">DIREKTSTÖD: TENABLE NESSUS</span>
                    <h2>Sårbarhetsskanningar och korrelerade fynd</h2>
                  </div>
                  <small>Rå leverantörsevidens hålls åtskild från verifierade fynd.</small>
                </header>
                {canIngestIntelligence && <form className="op-vulnerability-import" onSubmit={handleVulnerabilityImport}>
                  <div>
                    <Icon name="vulnerability" size={21} />
                    <span>
                      <strong>Direkt filimport: Tenable Nessus</strong>
                      <small>
                        Qualys, Greenbone/OpenVAS, Rapid7 och Defender VM stöds ännu inte som
                        direkta filformat. De kräver en separat adapter till det versionerade
                        normaliseringskontraktet.
                      </small>
                    </span>
                  </div>
                  <label>
                    Format
                    <select
                      aria-label="Format för sårbarhetsskanning"
                      value={vulnerabilityFormat}
                      onChange={(event) => {
                        setVulnerabilityFormat(event.target.value as typeof vulnerabilityFormat);
                        vulnerabilityUploadIdempotencyKey.current = null;
                      }}
                    >
                      <option value="nessus">Tenable Nessus (.nessus XML)</option>
                      <option value="normalized-json">
                        Normaliserad JSON (separat adapter krävs)
                      </option>
                    </select>
                  </label>
                  <label>
                    Rapportfil
                    <input
                      key={`vulnerability-${selectedSystemId}-${vulnerabilityFormat}`}
                      accept={vulnerabilityFormat === 'nessus' ? '.nessus,.xml' : '.json'}
                      aria-label="Sårbarhetsrapport"
                      onChange={(event) => {
                        setVulnerabilityFile(event.target.files?.[0] ?? null);
                        vulnerabilityUploadIdempotencyKey.current = null;
                      }}
                      type="file"
                    />
                  </label>
                  <button
                    className="primary-button"
                    disabled={!vulnerabilityFile || busyAction !== null}
                    type="submit"
                  >
                    <Icon name="plus" size={15} /> Validera och köa import
                  </button>
                </form>}

                {vulnerabilityScans.length > 0 && (
                  <section className="op-import-history">
                    <h3>Importerade rapporter</h3>
                    <div>
                      {vulnerabilityScans.map((scan) => (
                        <article key={scan.id}>
                          <span className="op-provider-badge">{scan.provider}</span>
                          <span>
                            <strong>{scan.source_name}</strong>
                            <small>
                              {formatDate(scan.imported_at)} · {scan.observation_count} observationer ·{' '}
                              {scan.matched_asset_count}/{scan.asset_count} assets matchade
                            </small>
                          </span>
                          <span>
                            <strong>{scan.promoted_finding_count}</strong>
                            <small>Operativa fynd</small>
                          </span>
                        </article>
                      ))}
                    </div>
                  </section>
                )}

                {vulnerabilityObservationPage.total > 0 && (
                  <section className="op-import-observations">
                    <h3>Leverantörsobservationer</h3>
                    <div className="op-card-grid">
                      {vulnerabilityObservationPage.items.map((observation) => (
                        <VulnerabilityObservationCard
                          api={api}
                          key={`${selectedSystemId}:${observation.id}`}
                          observation={observation}
                          systemId={selectedSystemId}
                        />
                      ))}
                    </div>
                    <PaginationControls
                      busy={busyAction !== null}
                      onPage={(offset) =>
                        void runAction('observation-page', () =>
                          loadVulnerabilityObservationPage(offset),
                        )
                      }
                      page={vulnerabilityObservationPage}
                    />
                  </section>
                )}

                <EntityCards title="Korrelerade fynd" caveat="Sårbarheter, felkonfigurationer och informationsfynd behåller sin egen livscykel och evidenshistorik." empty="Inga operativa fynd har skapats.">
                  {findingPage.items.map((finding) => (
                    <FindingCard
                      api={api}
                      busy={busyAction !== null}
                      canAnalyze={canAnalyze}
                      finding={finding}
                      key={`${selectedSystemId}:${finding.id}`}
                      onLifecycleUpdate={handleFindingLifecycleUpdate}
                      systemId={selectedSystemId}
                    />
                  ))}
                </EntityCards>
                <PaginationControls
                  busy={busyAction !== null}
                  onPage={(offset) =>
                    void runAction('finding-page', () => loadFindingPage(offset))
                  }
                  page={findingPage}
                />
              </div>
            )}

            {activeTab === 'risks' && (
              <EntityCards title="Preliminära riskindikeringar" caveat="Poängen är ett beslutsunderlag med begränsad kontext. Exponering, nåbarhet och kontroller måste verifieras av en analytiker." empty="Inga riskindikeringar har beräknats.">
                {riskPage.items.map((risk) => (
                  <RiskCard api={api} key={`${selectedSystemId}:${risk.id}`} risk={risk} systemId={selectedSystemId} />
                ))}
              </EntityCards>
            )}
            {activeTab === 'risks' && (
              <PaginationControls
                busy={busyAction !== null}
                onPage={(offset) => void runAction('risk-page', () => loadRiskPage(offset))}
                page={riskPage}
              />
            )}

            {activeTab === 'architecture' && (
              <OperationalArchitectureEditor
                analystIdentity={principal?.actor ?? ''}
                key={selectedSystemId}
                busy={busyAction !== null}
                canEdit={canAnalyze}
                onSave={handleSaveArchitecture}
                snapshot={overview?.latest_architecture ?? null}
                systemName={selectedSystem?.name ?? 'System'}
                versions={architectureVersions}
                onDirtyChange={setArchitectureDirty}
              />
            )}

            {activeTab === 'reports' && (
              <EntityCards title="Frysta rapportunderlag" caveat="Varje fil representerar data vid skapandet och ska hanteras enligt organisationens informationsklassning." empty="Inga rapporter har skapats.">
                {reports.map((report) => (
                  <article
                    className={`op-report-row${report.export_status === 'withdrawn' ? ' op-report-row--withdrawn' : ''}`}
                    key={report.id}
                  >
                    <span><Icon name="report" size={18} /></span>
                    <div>
                      <strong>{reportTypeLabel(report.report_type)}</strong>
                      <small>
                        {report.format.toUpperCase()} · {formatDate(report.created_at)} ·{' '}
                        {report.distribution_tlp} · {reportExportStatusLabel(report.export_status)} ·{' '}
                        SHA-256 {report.sha256.slice(0, 12)}…
                      </small>
                      {report.withdrawal_reason && (
                        <small className="op-report-row__withdrawal" role="status">
                          {report.withdrawal_reason}
                        </small>
                      )}
                    </div>
                    <button
                      aria-label={
                        report.export_status === 'available'
                          ? `Ladda ned ${reportTypeLabel(report.report_type)}`
                          : `${reportTypeLabel(report.report_type)}: nedladdning spärrad`
                      }
                      className="secondary-button"
                      disabled={busyAction !== null || report.export_status !== 'available'}
                      onClick={() => handleDownload(report)}
                    >
                      <Icon name="download" size={15} />{' '}
                      {report.export_status === 'available' ? 'Ladda ned' : 'Spärrad'}
                    </button>
                  </article>
                ))}
              </EntityCards>
            )}
          </section>
        </>
      )}
    </main>
  );
}

function backgroundJobStatusLabel(status: BackgroundJob['status']): string {
  return {
    queued: 'Köat',
    running: 'Pågår',
    completed: 'Slutfört',
    failed: 'Misslyckat',
    cancelled: 'Avbrutet',
  }[status];
}

function backgroundJobTypeLabel(jobType: BackgroundJob['job_type']): string {
  return {
    intelligence_correlation: 'Omvärldskorrelation',
    normalized_vulnerability_import: 'Sårbarhetsimport',
    report_generation: 'Rapportgenerering',
  }[jobType];
}

function resultNumber(job: BackgroundJob, key: string): number | null {
  const value = job.result[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function resultString(job: BackgroundJob, key: string): string | null {
  const value = job.result[key];
  return typeof value === 'string' ? value : null;
}

function backgroundJobCompletionMessage(jobs: BackgroundJob[]): string {
  if (jobs.length > 1) return `${jobs.length} bakgrundsjobb slutfördes och systemdata lästes om.`;
  const job = jobs[0];
  if (!job) return 'Bakgrundsjobbet slutfördes och systemdata lästes om.';
  if (job.job_type === 'normalized_vulnerability_import') {
    const imported = resultNumber(job, 'imported');
    const promoted = resultNumber(job, 'promoted_findings');
    if (imported !== null && promoted !== null) {
      return `Importjobbet slutfördes: ${imported} observationer och ${promoted} operativa fynd.`;
    }
    return 'Importjobbet slutfördes och systemdata lästes om.';
  }
  if (job.job_type === 'intelligence_correlation') {
    return 'Omvärldskorrelationen slutfördes och systemdata lästes om.';
  }
  return 'Rapportjobbet slutfördes och den frysta rapporten är tillgänglig.';
}

function BackgroundJobResult({ job }: { job: BackgroundJob }) {
  if (job.status === 'queued') {
    return <small>Väntar på en aktiverad worker.</small>;
  }
  if (job.status === 'running') {
    return (
      <small>
        {job.cancel_requested_at
          ? 'Avbrott har begärts och inväntar workern.'
          : 'Bearbetas av worker.'}
      </small>
    );
  }
  if (job.status === 'failed') {
    return (
      <small role="alert">
        {job.error_code ?? 'job_failed'}: {job.error_message ?? 'Jobbet kunde inte slutföras.'}
      </small>
    );
  }
  if (job.status === 'cancelled') return <small>Jobbet avbröts utan resultat.</small>;
  if (job.job_type === 'normalized_vulnerability_import') {
    return (
      <small>
        {resultNumber(job, 'imported') ?? 0} observationer ·{' '}
        {resultNumber(job, 'matched_assets') ?? 0} matchade assets ·{' '}
        {resultNumber(job, 'promoted_findings') ?? 0} operativa fynd
      </small>
    );
  }
  if (job.job_type === 'intelligence_correlation') {
    return (
      <small>
        {resultNumber(job, 'finding_matches') ?? 0} fyndmatchningar ·{' '}
        {resultNumber(job, 'threat_records_matched') ?? 0} hotposter ·{' '}
        {resultNumber(job, 'risks_created') ?? 0} nya riskindikeringar
      </small>
    );
  }
  const format = resultString(job, 'format');
  const reportType = resultString(job, 'report_type');
  const sha256 = resultString(job, 'sha256');
  return (
    <small>
      {reportType ?? 'Rapport'} · {(format ?? 'fil').toUpperCase()}
      {sha256 ? ` · SHA-256 ${sha256.slice(0, 12)}…` : ''}
    </small>
  );
}

function BackgroundJobPanel({
  busy,
  canCancel,
  jobs,
  onCancel,
}: {
  busy: boolean;
  canCancel: boolean;
  jobs: BackgroundJob[];
  onCancel: (job: BackgroundJob) => void;
}) {
  return (
    <section className="panel op-import-history" aria-label="Bakgrundsjobb">
      <header className="op-section-heading">
        <div>
          <span className="section-kicker">BESTÄNDIG KÖ</span>
          <h2>Bakgrundsjobb för valt system</h2>
        </div>
        <small>Endast status och säkert resultat visas; jobbets payload exponeras aldrig.</small>
      </header>
      {jobs.length === 0 ? (
        <p>Inga bakgrundsjobb finns för valt system.</p>
      ) : (
        <div>
          {jobs.map((job) => {
            const cancellable = job.status === 'queued' || job.status === 'running';
            return (
              <article key={job.id}>
                <span className={`op-status-dot op-status-dot--${job.status}`} />
                <span>
                  <strong>{backgroundJobTypeLabel(job.job_type)}</strong>
                  <small>
                    {backgroundJobStatusLabel(job.status)} · begärt {formatDate(job.requested_at)} ·
                    försök {job.attempt_count}/{job.max_attempts}
                  </small>
                  <BackgroundJobResult job={job} />
                </span>
                {canCancel && cancellable && (
                  <button
                    className="secondary-button"
                    disabled={busy || job.cancel_requested_at !== null}
                    onClick={() => onCancel(job)}
                    type="button"
                  >
                    {job.cancel_requested_at ? 'Avbrott begärt' : 'Avbryt'}
                  </button>
                )}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function AssetInspector({
  api,
  asset,
  systemId,
}: {
  api: OperationalApi;
  asset: Asset;
  systemId: string;
}) {
  const [servicePage, setServicePage] = useState<Page<Service>>(emptyPage);
  const [loading, setLoading] = useState(true);
  const [localError, setLocalError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setServicePage(emptyPage());
    setLoading(true);
    setLocalError(null);
    api.listServicePage(systemId, {
      assetId: asset.id,
      limit: COLLECTION_PAGE_SIZE,
      offset: 0,
    })
      .then((page) => active && setServicePage(page))
      .catch((error: unknown) => active && setLocalError(asErrorMessage(error)))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [api, asset.id, systemId]);

  async function loadServicePage(offset: number): Promise<void> {
    setLoading(true);
    setLocalError(null);
    try {
      setServicePage(
        await api.listServicePage(systemId, {
          assetId: asset.id,
          limit: COLLECTION_PAGE_SIZE,
          offset,
        }),
      );
    } catch (error) {
      setLocalError(asErrorMessage(error));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <span className="section-kicker">TILLGÅNGSDETALJ</span>
      <h3>{asset.hostname ?? asset.primary_ip}</h3>
      <dl>
        <div><dt>IP</dt><dd className="mono">{asset.primary_ip}</dd></div>
        <div><dt>MAC</dt><dd>{asset.mac_address ?? 'Ej observerad'}</dd></div>
        <div><dt>OS</dt><dd>{asset.os_family ?? 'Okänt'}{asset.os_accuracy !== null ? ` (${asset.os_accuracy} %)` : ''}</dd></div>
        <div><dt>Inventeringsläge</dt><dd>{inventoryStatusLabel(asset.inventory_status)}</dd></div>
        <div><dt>Observationer</dt><dd>{asset.observation_count}</dd></div>
        <div><dt>Först sedd</dt><dd>{formatDate(asset.first_seen_at)}</dd></div>
        <div><dt>Senast sedd</dt><dd>{formatDate(asset.last_seen_at)}</dd></div>
      </dl>
      <h4>Observerade tjänster</h4>
      {loading && servicePage.items.length === 0 ? (
        <p>Läser tjänster för vald tillgång…</p>
      ) : servicePage.items.length === 0 && !localError ? (
        <p>Inga tjänster observerades för denna tillgång i den aktuella skanningen.</p>
      ) : (
        <div className="op-service-list">
          {servicePage.items.map((service) => (
            <div key={service.id}>
              <strong>{service.protocol}/{service.port}</strong>
              <span>{service.product ?? service.service_name ?? 'Okänd tjänst'} {service.version ?? ''}</span>
              <small>Konfidens {formatPercent(service.confidence)} · {service.cpes.join(', ') || 'CPE saknas'}</small>
            </div>
          ))}
        </div>
      )}
      {localError && <p className="op-error-copy" role="alert">{localError}</p>}
      <PaginationControls
        busy={loading}
        onPage={(offset) => void loadServicePage(offset)}
        page={servicePage}
      />
    </>
  );
}

function ThreatCard({
  api,
  systemId,
  threat,
}: {
  api: OperationalApi;
  systemId: string;
  threat: ThreatSummary;
}) {
  const [detail, setDetail] = useState<Threat | null>(null);
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  async function loadDetail() {
    if (detail || loading) return;
    setLoading(true);
    setLocalError(null);
    try {
      setDetail(await api.getThreat(systemId, threat.id));
    } catch (error) {
      setLocalError(asErrorMessage(error));
    } finally {
      setLoading(false);
    }
  }

  return (
    <details
      className="op-entity-card"
      onToggle={(event) => event.currentTarget.open && void loadDetail()}
    >
      <summary>
        <span className={`op-criticality op-criticality--${threat.severity}`}>
          {criticalityLabel(threat.severity)}
        </span>
        <strong>{threat.title}</strong>
        <small>{threat.source} · konfidens {formatPercent(threat.confidence)}</small>
      </summary>
      <dl>
        <div><dt>Externt ID</dt><dd>{threat.external_id}</dd></div>
        <div><dt>ATT&CK</dt><dd>{threat.attack_patterns.join(', ') || 'Saknas'}</dd></div>
        <div><dt>Matchade assets</dt><dd>{threat.matched_asset_ids.length}</dd></div>
      </dl>
      {loading && <p>Läser hotdetalj…</p>}
      {detail?.description && <p>{detail.description}</p>}
      {detail && <pre>{JSON.stringify(detail.provenance, null, 2)}</pre>}
      {localError && <p className="op-error-copy" role="alert">{localError}</p>}
    </details>
  );
}

function IntelReviewCard({
  busy,
  canAnalyze,
  onReview,
  record,
}: {
  busy: boolean;
  canAnalyze: boolean;
  onReview: (
    recordId: string,
    decision: 'approved' | 'rejected',
    note: string,
  ) => Promise<void>;
  record: GlobalIntelRecord;
}) {
  const [note, setNote] = useState('');

  return (
    <article className="op-entity-card op-intel-review-card">
      <header>
        <span className="op-provider-badge">{record.distribution_tlp}</span>
        <span>
          <strong>{record.title}</strong>
          <small>{record.provider} · {record.record_type} · {formatDate(record.modified_at)}</small>
        </span>
      </header>
      <p>{record.summary}</p>
      {canAnalyze ? (
        <div className="op-intel-review-card__actions">
          <label>
            Granskningsnotering
            <input
              aria-label={`Granskningsnotering för ${record.title}`}
              maxLength={2000}
              placeholder="Krävs vid avvisning"
              value={note}
              onChange={(event) => setNote(event.target.value)}
            />
          </label>
          <button
            className="secondary-button"
            disabled={busy || note.trim().length < 3}
            onClick={() => void onReview(record.id, 'rejected', note)}
            type="button"
          >
            Avvisa
          </button>
          <button
            className="primary-button"
            disabled={busy}
            onClick={() => void onReview(record.id, 'approved', note)}
            type="button"
          >
            Godkänn och köa korrelation
          </button>
        </div>
      ) : (
        <p>
          Identiteten kan läsa kön men saknar organisationsomfattande analysbehörighet för att
          fatta tenantgemensamma granskningsbeslut.
        </p>
      )}
    </article>
  );
}

function FindingCard({
  api,
  busy,
  canAnalyze,
  finding,
  onLifecycleUpdate,
  systemId,
}: {
  api: OperationalApi;
  busy: boolean;
  canAnalyze: boolean;
  finding: FindingSummary;
  onLifecycleUpdate: (
    findingId: string,
    lifecycleStatus: FindingLifecycleStatus,
    reason: string,
  ) => Promise<Finding>;
  systemId: string;
}) {
  const [evidence, setEvidence] = useState<FindingEvidence[] | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [detail, setDetail] = useState<Finding | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [nextLifecycle, setNextLifecycle] = useState<FindingLifecycleStatus>(
    finding.lifecycle_status,
  );
  const [reason, setReason] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);

  useEffect(() => {
    setNextLifecycle(finding.lifecycle_status);
  }, [finding.lifecycle_status]);

  async function loadEvidence() {
    setEvidenceLoading(true);
    setLocalError(null);
    try {
      setEvidence(await api.listFindingEvidence(systemId, finding.id));
    } catch (error) {
      setLocalError(asErrorMessage(error));
    } finally {
      setEvidenceLoading(false);
    }
  }

  async function loadDetail() {
    if (detail || detailLoading) return;
    setDetailLoading(true);
    setLocalError(null);
    try {
      setDetail(await api.getFinding(systemId, finding.id));
    } catch (error) {
      setLocalError(asErrorMessage(error));
    } finally {
      setDetailLoading(false);
    }
  }

  async function updateLifecycle(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLocalError(null);
    try {
      const updated = await onLifecycleUpdate(finding.id, nextLifecycle, reason.trim());
      setDetail(updated);
      setReason('');
      setEvidence(null);
    } catch (error) {
      setLocalError(asErrorMessage(error));
    }
  }

  const reference = finding.cve_id ?? detail?.stable_key ?? `Fynd ${finding.id.slice(0, 8)}`;
  return (
    <details
      className="op-entity-card op-finding-card"
      onToggle={(event) => event.currentTarget.open && void loadDetail()}
    >
      <summary>
        {finding.is_kev && <span className="op-kev">KEV</span>}
        <strong>{reference} · {finding.title}</strong>
        <small>
          {findingTypeLabel(finding.finding_type)} ·{' '}
          <span className={`op-lifecycle op-lifecycle--${finding.lifecycle_status}`}>
            {findingLifecycleLabel(finding.lifecycle_status)}
          </span>{' '}
          · {inventoryStatusLabel(finding.inventory_status)}{' '}
          · {finding.status === 'candidate'
            ? 'Kräver granskning'
            : finding.status === 'likely'
              ? 'Sannolik – kräver granskning'
              : finding.status === 'confirmed'
                ? 'Analytikerbekräftad'
                : 'Falsk positiv'}
        </small>
      </summary>
      {detailLoading && <p>Läser fynddetaljer…</p>}
      {detail?.match_reason && <p>{detail.match_reason}</p>}
      <div className="op-finding-metrics">
        <span><small>CVSS</small><strong>{finding.cvss_score ?? 'Ej relevant'}</strong></span>
        <span><small>EPSS</small><strong>{finding.cve_id ? formatPercent(finding.epss_score) : 'Ej relevant'}</strong></span>
        <span><small>Evidensstyrka</small><strong>{finding.primary_evidence_strength}/100</strong></span>
      </div>
      <dl>
        <div><dt>Typ</dt><dd>{findingTypeLabel(finding.finding_type)}</dd></div>
        <div><dt>Först sedd</dt><dd>{formatDate(finding.first_seen_at)}</dd></div>
        <div><dt>Senast sedd</dt><dd>{formatDate(finding.last_seen_at)}</dd></div>
        <div><dt>Observationer</dt><dd>{finding.occurrence_count}</dd></div>
        <div><dt>Inventeringsläge</dt><dd>{inventoryStatusLabel(finding.inventory_status)}</dd></div>
        <div><dt>Upplöst</dt><dd>{formatDate(finding.resolved_at)}</dd></div>
      </dl>
      {finding.kev_due_date && (
        <p>KEV-datum för federal amerikansk åtgärdsfrist: {finding.kev_due_date}.</p>
      )}

      <section className="op-finding-evidence">
        <div>
          <h4>Evidenshistorik</h4>
          <button
            className="secondary-button"
            disabled={evidenceLoading}
            onClick={() => void loadEvidence()}
            type="button"
          >
            {evidenceLoading ? 'Hämtar…' : evidence === null ? 'Visa evidens' : 'Uppdatera evidens'}
          </button>
        </div>
        {evidence?.length === 0 && <p>Ingen separat evidenspost finns.</p>}
        {evidence && evidence.length > 0 && (
          <div className="op-evidence-list">
            {evidence.map((item) => (
              <article key={item.id}>
                <strong>{item.source_name}</strong>
                <span>{item.source_kind} · {findingLifecycleLabel(item.lifecycle_status)}</span>
                <small>
                  Styrka {item.strength}/100 · {item.observation_count} observationer · senast{' '}
                  {formatDate(item.last_seen_at)}
                </small>
              </article>
            ))}
          </div>
        )}
      </section>

      {canAnalyze && (
        <form className="op-lifecycle-form" onSubmit={(event) => void updateLifecycle(event)}>
          <strong>Analytikerbeslut</strong>
          <label>
            Status
            <select
              aria-label={`Ny livscykelstatus för ${reference}`}
              value={nextLifecycle}
              onChange={(event) =>
                setNextLifecycle(event.target.value as FindingLifecycleStatus)
              }
            >
              <option value="open">Öppet</option>
              <option value="fixed">Åtgärdat</option>
              <option value="accepted">Accepterat</option>
              <option value="false_positive">Falsk positiv</option>
              <option value="out_of_scope">Utanför scope</option>
              <option value="reopened">Återöppnat</option>
            </select>
          </label>
          <label>
            Motivering
            <input
              aria-label={`Motivering för ${reference}`}
              minLength={3}
              required
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Dokumentera beslut och underlag"
            />
          </label>
          <button className="primary-button" disabled={busy || reason.trim().length < 3}>
            Spara status
          </button>
        </form>
      )}
      {localError && <p className="op-error-copy" role="alert">{localError}</p>}
    </details>
  );
}

function RiskCard({
  api,
  risk,
  systemId,
}: {
  api: OperationalApi;
  risk: RiskSummary;
  systemId: string;
}) {
  const [detail, setDetail] = useState<Risk | null>(null);
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  async function loadDetail() {
    if (detail || loading) return;
    setLoading(true);
    setLocalError(null);
    try {
      setDetail(await api.getRisk(systemId, risk.id));
    } catch (error) {
      setLocalError(asErrorMessage(error));
    } finally {
      setLoading(false);
    }
  }

  return (
    <details
      className="op-entity-card"
      onToggle={(event) => event.currentTarget.open && void loadDetail()}
    >
      <summary>
        <span className={`op-risk-score op-risk-score--${risk.level}`}>{risk.score}/25</span>
        <strong>{risk.title}</strong>
        <small>
          {criticalityLabel(risk.level)} · {risk.status} ·{' '}
          {inventoryStatusLabel(risk.evidence_status)}
        </small>
      </summary>
      <dl>
        <div><dt>Sannolikhet</dt><dd>{risk.likelihood}/5</dd></div>
        <div><dt>Konsekvens</dt><dd>{risk.impact}/5</dd></div>
        <div><dt>Evidensläge</dt><dd>{inventoryStatusLabel(risk.evidence_status)}</dd></div>
      </dl>
      {loading && <p>Läser riskdetaljer…</p>}
      {detail && <pre>{JSON.stringify(detail.rationale, null, 2)}</pre>}
      {localError && <p className="op-error-copy" role="alert">{localError}</p>}
    </details>
  );
}

function VulnerabilityObservationCard({
  api,
  observation,
  systemId,
}: {
  api: OperationalApi;
  observation: VulnerabilityObservationSummary;
  systemId: string;
}) {
  const [detail, setDetail] = useState<VulnerabilityObservation | null>(null);
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  async function loadDetail() {
    if (detail || loading) return;
    setLoading(true);
    setLocalError(null);
    try {
      setDetail(await api.getVulnerabilityObservation(systemId, observation.id));
    } catch (error) {
      setLocalError(asErrorMessage(error));
    } finally {
      setLoading(false);
    }
  }

  return (
    <details
      className="op-entity-card"
      onToggle={(event) => event.currentTarget.open && void loadDetail()}
    >
      <summary>
        <span
          className={`op-criticality op-criticality--${observation.severity === 'info' ? 'low' : observation.severity}`}
        >
          {observation.severity === 'info'
            ? 'Info'
            : criticalityLabel(observation.severity)}
        </span>
        <strong>{observation.title}</strong>
        <small>
          {observation.asset_identifier}
          {observation.port !== null
            ? ` · ${observation.protocol ?? 'port'}/${observation.port}`
            : ''}
        </small>
      </summary>
      <dl>
        <div><dt>Leverantörs-ID</dt><dd>{observation.provider_finding_id}</dd></div>
        <div><dt>CVE</dt><dd>{observation.cve_ids.join(', ') || 'Saknas'}</dd></div>
        <div><dt>CVSS</dt><dd>{observation.cvss_score ?? 'Saknas'}</dd></div>
        <div><dt>Status</dt><dd>{observation.state}</dd></div>
        <div><dt>Assetkoppling</dt><dd>{observation.matched_asset_id ? formatPercent(observation.match_confidence) : 'Omatchad'}</dd></div>
        <div><dt>Tjänstekoppling</dt><dd>{observation.matched_service_id ? 'Exakt endpoint' : 'Saknas'}</dd></div>
      </dl>
      {loading && <p>Läser observationens evidens…</p>}
      {detail?.description && <p>{detail.description}</p>}
      {detail?.solution && <p><strong>Åtgärd:</strong> {detail.solution}</p>}
      {detail && <pre>{JSON.stringify(detail.evidence, null, 2)}</pre>}
      {localError && <p className="op-error-copy" role="alert">{localError}</p>}
    </details>
  );
}
