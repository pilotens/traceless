import type { Criticality, OperationalSystem, Page, Project, RiskSummary } from './api';

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '/api/v1').replace(/\/+$/, '');
const OPERATIONAL_BASE = `${API_BASE}/operational`;

export interface BusinessImpactProfile {
  confidentiality: number;
  integrity: number;
  availability: number;
  financial: number;
  regulatory: number;
  reputation: number;
  safety: number;
}

export interface SystemContextInput {
  business_owner: string;
  capabilities: string[];
  processes: string[];
  data_categories: string[];
  regulations: string[];
  recovery_time_objective_hours: number | null;
  recovery_point_objective_hours: number | null;
  impact_profile: BusinessImpactProfile;
}

export interface SystemContextVersion extends SystemContextInput {
  id: string;
  system_id: string;
  version: number;
  status: 'draft' | 'published' | 'superseded';
  created_by: string;
  created_at: string;
  published_by: string | null;
  published_at: string | null;
}

export interface RiskTreatmentInput {
  strategy: 'mitigate' | 'avoid' | 'transfer' | 'accept';
  title: string;
  description: string;
  owner: string;
  approver?: string | null;
  priority: Criticality;
  due_at?: string | null;
  sla_days?: number | null;
  verification_criteria: string;
  external_system?: string | null;
  external_key?: string | null;
  external_url?: string | null;
}

export interface RiskTreatment {
  id: string;
  system_id: string;
  risk_id: string;
  strategy: RiskTreatmentInput['strategy'];
  title: string;
  description: string;
  owner: string;
  approver: string | null;
  status: 'proposed' | 'approved' | 'in_progress' | 'verification' | 'closed' | 'cancelled';
  priority: Criticality;
  due_at: string | null;
  sla_days: number | null;
  verification_criteria: string;
  decision_note: string;
  external_system: string | null;
  external_key: string | null;
  external_url: string | null;
  residual_likelihood: number | null;
  residual_impact: number | null;
  residual_score: number | null;
  residual_level: Criticality | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  approved_by: string | null;
  approved_at: string | null;
  verified_by: string | null;
  verified_at: string | null;
  overdue: boolean;
}

export interface ControlInput {
  control_key: string;
  name: string;
  description: string;
  framework: string;
  owner: string;
  status: 'planned' | 'implemented' | 'retired';
}

export interface Control extends ControlInput {
  id: string;
  system_id: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface GovernanceOverview {
  system_id: string;
  published_context: SystemContextVersion | null;
  draft_context: SystemContextVersion | null;
  open_risks: number;
  risks_with_active_treatment: number;
  risks_without_owner: number;
  overdue_treatments: number;
  controls: number;
  controls_with_current_assessment: number;
  coverage_percent: number;
  latest_manifest: { id: string; source_fingerprint: string; created_at: string } | null;
}

export interface PortfolioGovernance {
  systems: Array<{
    system_id: string;
    system_name: string;
    project_id: string;
    criticality: Criticality;
    business_owner: string;
    open_risks: number;
    overdue_treatments: number;
    risks_without_owner: number;
    coverage_percent: number;
  }>;
  open_risks: number;
  overdue_treatments: number;
  risks_without_owner: number;
  average_coverage_percent: number;
}

interface GovernanceClientOptions {
  getAccessToken: () => string | null;
}

export function createGovernanceApi(options: GovernanceClientOptions) {
  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set('Accept', 'application/json');
    if (init.body !== undefined) headers.set('Content-Type', 'application/json');
    const token = options.getAccessToken();
    if (token) headers.set('Authorization', `Bearer ${token}`);
    if ((init.method ?? 'GET') !== 'GET') headers.set('X-Actor', 'risk-governance-workspace');
    const response = await fetch(`${OPERATIONAL_BASE}${path}`, {
      ...init,
      credentials: 'same-origin',
      headers,
    });
    if (!response.ok) {
      let message = `API-anropet misslyckades (${response.status})`;
      try {
        const body = (await response.json()) as { detail?: string };
        if (body.detail) message = body.detail;
      } catch {
        // Preserve the status-based message for non-JSON intermediaries.
      }
      throw new Error(message);
    }
    return (await response.json()) as T;
  }

  const systemPath = (systemId: string) => `/systems/${encodeURIComponent(systemId)}`;

  return {
    listProjects: () => request<Project[]>('/projects'),
    listSystems: (projectId: string) =>
      request<OperationalSystem[]>(`/projects/${encodeURIComponent(projectId)}/systems`),
    portfolio: () => request<PortfolioGovernance>('/portfolio/governance'),
    overview: (systemId: string) =>
      request<GovernanceOverview>(`${systemPath(systemId)}/governance/overview`),
    contexts: (systemId: string) =>
      request<SystemContextVersion[]>(`${systemPath(systemId)}/context/versions`),
    createContext: (systemId: string, input: SystemContextInput) =>
      request<SystemContextVersion>(`${systemPath(systemId)}/context/versions`, {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    publishContext: (systemId: string, contextId: string) =>
      request<SystemContextVersion>(
        `${systemPath(systemId)}/context/versions/${encodeURIComponent(contextId)}/publish`,
        { method: 'POST' },
      ),
    risks: (systemId: string) =>
      request<Page<RiskSummary>>(`${systemPath(systemId)}/risks?limit=200&status=open`),
    treatments: (systemId: string) =>
      request<RiskTreatment[]>(`${systemPath(systemId)}/treatments`),
    createTreatment: (systemId: string, riskId: string, input: RiskTreatmentInput) =>
      request<RiskTreatment>(
        `${systemPath(systemId)}/risks/${encodeURIComponent(riskId)}/treatments`,
        { method: 'POST', body: JSON.stringify(input) },
      ),
    updateTreatment: (systemId: string, treatmentId: string, input: Record<string, unknown>) =>
      request<RiskTreatment>(
        `${systemPath(systemId)}/treatments/${encodeURIComponent(treatmentId)}`,
        { method: 'PATCH', body: JSON.stringify(input) },
      ),
    controls: (systemId: string) => request<Control[]>(`${systemPath(systemId)}/controls`),
    createControl: (systemId: string, input: ControlInput) =>
      request<Control>(`${systemPath(systemId)}/controls`, {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    createManifest: (systemId: string) =>
      request<{ id: string; source_fingerprint: string; created_at: string }>(
        `${systemPath(systemId)}/analysis-manifests`,
        { method: 'POST', body: JSON.stringify({ purpose: 'risk_governance' }) },
      ),
  };
}

export type GovernanceApi = ReturnType<typeof createGovernanceApi>;
