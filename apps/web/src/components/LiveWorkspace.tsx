import { useCallback, useEffect, useMemo, useState } from 'react';

import type { OperationalApi, ReportFormat, ReportType } from '../api';
import '../operational.css';
import { MockupWorkspace, type WorkspaceTab } from './MockupWorkspace';

export interface LiveAssetRow {
  id: string; name: string; ip: string; type: string; env: string;
  services: number; seen: string; status: string; icon: string;
}
export interface LiveArchitectureNode { id: string; label: string; icon: string; zone: string; alerts: number }
export interface OperationalViewModel {
  status: 'connecting' | 'loading' | 'ready' | 'empty' | 'error';
  error: string;
  projects: Array<{ id: string; name: string }>;
  systems: Array<{ id: string; name: string }>;
  selectedProjectId: string;
  selectedSystemId: string;
  systemName: string;
  stats: {
    assets: number; activeAssets: number; services: number; internetAssets: number;
    unreviewedAssets: number; threats: number; criticalThreats: number; newThreats: number;
    findings: number; kevFindings: number; criticalFindings: number; verifiedFindings: number;
    risks: number; riskDistribution: { critical: number; high: number; medium: number; low: number };
    architectureStatus: string;
  };
  scans: string[][];
  assets: LiveAssetRow[];
  threatRows: string[][];
  findingRows: string[][];
  findingIds: string[];
  riskRows: string[][];
  architectureNodes: LiveArchitectureNode[];
  reportRows: string[][];
  reportIds: string[];
}
export interface OperationalActions {
  selectProject(id: string): void;
  selectSystem(id: string): void;
  refresh(): Promise<void>;
  updateFinding(id: string, decision: 'verify' | 'reject'): Promise<void>;
  createReport(format: string, reportType: string): Promise<void>;
  downloadReport(id: string): Promise<void>;
}

interface Props { api: OperationalApi; initialTab?: WorkspaceTab; onTabChange?: (tab: WorkspaceTab) => void }
type AnyRecord = Record<string, unknown>;
const emptyStats: OperationalViewModel['stats'] = {
  assets: 0, activeAssets: 0, services: 0, internetAssets: 0, unreviewedAssets: 0,
  threats: 0, criticalThreats: 0, newThreats: 0, findings: 0, kevFindings: 0,
  criticalFindings: 0, verifiedFindings: 0, risks: 0,
  riskDistribution: { critical: 0, high: 0, medium: 0, low: 0 }, architectureStatus: 'Saknas',
};
const asRecord = (value: unknown): AnyRecord => typeof value === 'object' && value !== null ? value as AnyRecord : {};
function text(value: unknown, ...keys: string[]): string {
  const source = asRecord(value);
  for (const key of keys) {
    if (typeof source[key] === 'string' && source[key]) return source[key] as string;
    if (typeof source[key] === 'number') return String(source[key]);
  }
  return '';
}
function count(value: unknown, ...keys: string[]): number {
  const source = asRecord(value);
  for (const key of keys) if (typeof source[key] === 'number') return source[key] as number;
  return 0;
}
const bool = (value: unknown, ...keys: string[]) => keys.some((key) => asRecord(value)[key] === true);
const list = (value: unknown, key = 'items'): unknown[] => Array.isArray(asRecord(value)[key]) ? asRecord(value)[key] as unknown[] : [];
function date(value: unknown): string {
  if (typeof value !== 'string' || !value) return '–';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString('sv-SE', { dateStyle: 'short', timeStyle: 'short' });
}
const severity = (value: string) => (({ critical: 'Kritisk', high: 'Hög', medium: 'Medel', low: 'Låg' } as Record<string, string>)[value] ?? value) || 'Okänd';
const inventory = (value: string) => (({ current: 'Aktiv', stale: 'Inaktiv', unobserved: 'Inaktiv', unknown: 'Ogranskad' } as Record<string, string>)[value] ?? value) || 'Ogranskad';
const architecture = (value: string) => (({ draft: 'Utkast', published: 'Publicerad', superseded: 'Ersatt' } as Record<string, string>)[value] ?? value) || 'Saknas';
function reportType(value: string): ReportType { return value === 'Teknisk rapport' ? 'technical' : value === 'Riskregister' ? 'risk_register' : 'management'; }
function normalizeNodes(snapshot: unknown): LiveArchitectureNode[] {
  const nodes = list(asRecord(snapshot).graph, 'nodes');
  const slots = [['internet','external','globe'],['waf','dmz','shield'],['api','app','cube'],['identity','app','user'],['internal','app','cube'],['database','data','database'],['logging','data','file']];
  return nodes.slice(0, 7).map((node, index) => ({
    id: slots[index][0], zone: slots[index][1], icon: slots[index][2],
    label: text(node, 'label', 'name', 'title', 'hostname') || `Komponent ${index + 1}`,
    alerts: count(node, 'alerts', 'risk_count', 'finding_count'),
  }));
}

export function LiveWorkspace({ api, initialTab = 'overview', onTabChange }: Props) {
  const [projects, setProjects] = useState<OperationalViewModel['projects']>([]);
  const [systems, setSystems] = useState<OperationalViewModel['systems']>([]);
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [selectedSystemId, setSelectedSystemId] = useState('');
  const [status, setStatus] = useState<OperationalViewModel['status']>('connecting');
  const [error, setError] = useState('');
  const [payload, setPayload] = useState({ stats: emptyStats, scans: [] as string[][], assets: [] as LiveAssetRow[], threatRows: [] as string[][], findingRows: [] as string[][], findingIds: [] as string[], riskRows: [] as string[][], architectureNodes: [] as LiveArchitectureNode[], reportRows: [] as string[][], reportIds: [] as string[] });

  useEffect(() => {
    let active = true;
    setStatus('connecting');
    api.listProjects().then((result) => {
      if (!active) return;
      const next = result.map(({ id, name }) => ({ id, name }));
      setProjects(next);
      if (!next.length) { setStatus('empty'); return; }
      const remembered = localStorage.getItem('traceless.project');
      setSelectedProjectId(next.some((item) => item.id === remembered) ? remembered! : next[0].id);
    }).catch((reason: unknown) => { if (active) { setError(reason instanceof Error ? reason.message : 'API:t kunde inte nås.'); setStatus('error'); } });
    return () => { active = false; };
  }, [api]);

  useEffect(() => {
    if (!selectedProjectId) return;
    let active = true;
    setStatus('loading'); setError(''); localStorage.setItem('traceless.project', selectedProjectId);
    api.listSystems(selectedProjectId).then((result) => {
      if (!active) return;
      const next = result.map(({ id, name }) => ({ id, name }));
      setSystems(next);
      if (!next.length) { setSelectedSystemId(''); setStatus('empty'); return; }
      const remembered = localStorage.getItem('traceless.system');
      setSelectedSystemId(next.some((item) => item.id === remembered) ? remembered! : next[0].id);
    }).catch((reason: unknown) => { if (active) { setError(reason instanceof Error ? reason.message : 'System kunde inte läsas.'); setStatus('error'); } });
    return () => { active = false; };
  }, [api, selectedProjectId]);

  const refresh = useCallback(async () => {
    if (!selectedSystemId) return;
    setStatus('loading'); setError(''); localStorage.setItem('traceless.system', selectedSystemId);
    try {
      const [overview, scansResult, assetPage, servicePage, threatPage, findingPage, riskPage, versions, reports] = await Promise.all([
        api.getOverview(selectedSystemId), api.listScans(selectedSystemId),
        api.listAssetPage(selectedSystemId, { limit: 200 }), api.listServicePage(selectedSystemId, { limit: 200 }),
        api.listThreatPage(selectedSystemId, { limit: 200 }), api.listFindingPage(selectedSystemId, { limit: 200 }),
        api.listRiskPage(selectedSystemId, { limit: 200 }), api.listArchitectureVersions(selectedSystemId), api.listReports(selectedSystemId),
      ]);
      const rawAssets = list(assetPage), rawServices = list(servicePage), rawThreats = list(threatPage), rawFindings = list(findingPage), rawRisks = list(riskPage);
      const names = new Map(rawAssets.map((asset, index) => [text(asset, 'id'), text(asset, 'hostname', 'name', 'value', 'key') || `Tillgång ${index + 1}`]));
      const serviceCounts = new Map<string, number>();
      rawServices.forEach((service) => { const id = text(service, 'asset_id'); serviceCounts.set(id, (serviceCounts.get(id) ?? 0) + 1); });
      const assets = rawAssets.map((asset, index): LiveAssetRow => {
        const source = asRecord(asset), metadata = asRecord(source.attributes ?? source.metadata), id = text(source, 'id'), kind = text(source, 'asset_type', 'type', 'kind');
        return { id, name: names.get(id) || `Tillgång ${index + 1}`, ip: text(source, 'ip_address', 'address') || text(metadata, 'ip_address', 'ip') || '–', type: kind || 'Tillgång', env: text(source, 'environment') || text(metadata, 'environment', 'miljo') || 'Okänd', services: serviceCounts.get(id) ?? 0, seen: date(source.last_seen_at ?? source.observed_at ?? source.updated_at), status: inventory(text(source, 'inventory_status', 'status')), icon: kind.includes('database') ? 'database' : kind.includes('identity') ? 'user' : kind.includes('application') ? 'cube' : 'server' };
      });
      const threatRows = rawThreats.map((item) => { const source = asRecord(item), patterns = list(source, 'attack_patterns').map(String), matched = list(source, 'matched_asset_ids'); return [severity(text(source, 'severity')), text(source, 'title') || 'Namnlöst hot', text(source, 'source') || 'Okänd källa', date(source.ingested_at ?? source.modified_at), `${Math.round(count(source, 'confidence') * 100)} %`, patterns[0] ?? '–', patterns.slice(1).join(', ') || 'Ingen ATT&CK-beskrivning', `${matched.length} matchade tillgångar`]; });
      const findingRows = rawFindings.map((item, index) => { const source = asRecord(item), epss = count(source, 'epss_score'), strength = count(source, 'primary_evidence_strength'), assetId = text(source, 'asset_id'); return [text(source, 'cve_id', 'title') || `Fynd ${index + 1}`, names.get(assetId) || assetId || 'Ej kopplad', text(source, 'service_id') || '–', count(source, 'cvss_score').toLocaleString('sv-SE', { maximumFractionDigits: 1 }), `${Math.round(epss * 100)} %`, bool(source, 'is_kev') ? 'Ja' : 'Nej', strength >= 70 ? 'Stark' : strength >= 40 ? 'Medel' : 'Svag']; });
      const riskRows = rawRisks.map((item, index) => { const source = asRecord(item); return [String(index + 1), text(source, 'title') || `Risk ${index + 1}`, text(source, 'asset_name', 'scope') || 'System', `${count(source, 'likelihood')}/5`, `${count(source, 'impact')}/5`, `${count(source, 'score')}/25`, severity(text(source, 'level')), text(source, 'owner') || 'Ej tilldelad']; });
      const reportRows = reports.map((item) => { const source = asRecord(item); return [text(source, 'title') || text(source, 'report_type', 'type') || 'Rapport', text(source, 'format').toUpperCase() || 'PDF', date(source.created_at), text(source, 'sha256', 'content_sha256', 'checksum') || 'Beräknas vid nedladdning']; });
      const distribution = { critical: 0, high: 0, medium: 0, low: 0 };
      rawRisks.forEach((item) => { const level = text(item, 'level') as keyof typeof distribution; if (level in distribution) distribution[level] += 1; });
      const latest = versions.at(-1), now = Date.now();
      setPayload({
        stats: { assets: count(assetPage, 'total'), activeAssets: assets.filter((item) => item.status === 'Aktiv').length, services: count(servicePage, 'total'), internetAssets: rawAssets.filter((item) => bool(item, 'internet_exposed', 'internet_facing') || bool(asRecord(item).attributes, 'internet_exposed', 'internet_facing')).length, unreviewedAssets: assets.filter((item) => item.status === 'Ogranskad').length, threats: count(threatPage, 'total'), criticalThreats: rawThreats.filter((item) => text(item, 'severity') === 'critical').length, newThreats: rawThreats.filter((item) => { const timestamp = Date.parse(text(item, 'ingested_at')); return Number.isFinite(timestamp) && now - timestamp < 86400000; }).length, findings: count(findingPage, 'total'), kevFindings: rawFindings.filter((item) => bool(item, 'is_kev')).length, criticalFindings: rawFindings.filter((item) => count(item, 'cvss_score') >= 9).length, verifiedFindings: rawFindings.filter((item) => ['likely','confirmed'].includes(text(item, 'status'))).length, risks: count(riskPage, 'total'), riskDistribution: distribution, architectureStatus: architecture(text(latest, 'status')) },
        scans: scansResult.slice(0, 5).map((item) => { const source = asRecord(item); return [text(source, 'environment', 'name') || 'Skanning', text(source, 'started_at', 'created_at'), text(source, 'completed_at', 'finished_at'), 'server', text(source, 'status') || 'unknown']; }),
        assets, threatRows, findingRows, findingIds: rawFindings.map((item) => text(item, 'id')), riskRows,
        architectureNodes: normalizeNodes(latest), reportRows, reportIds: reports.map((item) => text(item, 'id')),
      });
      setStatus('ready'); void overview;
    } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : 'Operativ data kunde inte läsas.'); setStatus('error'); }
  }, [api, selectedSystemId]);

  useEffect(() => { void refresh(); }, [refresh]);
  const actions = useMemo<OperationalActions>(() => ({
    selectProject(id) { setSelectedSystemId(''); setSelectedProjectId(id); },
    selectSystem: setSelectedSystemId,
    refresh,
    async updateFinding(id, decision) { if (!selectedSystemId || !id) return; try { await api.updateFindingLifecycle(selectedSystemId, id, decision === 'reject' ? 'false_positive' : 'open', decision === 'reject' ? 'Avvisad av analytiker.' : 'Verifierad av analytiker.'); await refresh(); } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : 'Fyndet kunde inte uppdateras.'); setStatus('error'); } },
    async createReport(format, type) { if (!selectedSystemId) return; try { await api.createReport(selectedSystemId, format.toLowerCase() as ReportFormat, reportType(type)); await refresh(); } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : 'Rapporten kunde inte skapas.'); setStatus('error'); } },
    async downloadReport(id) { if (!id) return; try { const result = asRecord(await api.downloadReport(id)), blob = result.blob; if (!(blob instanceof Blob)) throw new Error('Rapporten saknade filinnehåll.'); const url = URL.createObjectURL(blob), anchor = document.createElement('a'); anchor.href = url; anchor.download = text(result, 'filename') || `traceless-report-${id}`; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : 'Rapporten kunde inte laddas ned.'); setStatus('error'); } },
  }), [api, refresh, selectedSystemId]);
  const data: OperationalViewModel = { status, error, projects, systems, selectedProjectId, selectedSystemId, systemName: systems.find((item) => item.id === selectedSystemId)?.name ?? '', ...payload };
  return <div className="tm-live-shell"><LiveBar data={data} actions={actions} /><MockupWorkspace initialTab={initialTab} onTabChange={onTabChange} operational={data} actions={actions} /></div>;
}

function LiveBar({ data, actions }: { data: OperationalViewModel; actions: OperationalActions }) {
  return <div className={`tm-live-bar tm-live-bar--${data.status}`}><span className="tm-live-label"><i />LIVE</span><label>Projekt<select value={data.selectedProjectId} onChange={(event) => actions.selectProject(event.target.value)}><option value="">Välj projekt</option>{data.projects.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label>System<select value={data.selectedSystemId} disabled={!data.selectedProjectId} onChange={(event) => actions.selectSystem(event.target.value)}><option value="">Välj system</option>{data.systems.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><div><b>{data.status === 'ready' ? 'Ansluten' : data.status === 'error' ? 'API-fel' : data.status === 'empty' ? 'Ingen data' : 'Läser data'}</b><small>{data.error || data.systemName || (data.status === 'empty' ? 'Skapa projekt/system eller importera data via API:t.' : 'Operativ datakälla')}</small></div><button onClick={() => void actions.refresh()} disabled={!data.selectedSystemId || data.status === 'loading'}>↻ Uppdatera</button></div>;
}

export default LiveWorkspace;
