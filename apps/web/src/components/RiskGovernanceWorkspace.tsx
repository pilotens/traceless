import { useEffect, useMemo, useState, type FormEvent } from 'react';

import type { Criticality, OperationalSystem, Project, RiskSummary } from '../api';
import {
  createGovernanceApi,
  type Control,
  type GovernanceOverview,
  type PortfolioGovernance,
  type RiskTreatment,
  type SystemContextInput,
  type SystemContextVersion,
} from '../governanceApi';
import { EmptyState } from './operational/Presentation';

interface RiskGovernanceWorkspaceProps {
  accessToken: string | null;
}

const defaultImpact = {
  confidentiality: 3,
  integrity: 3,
  availability: 3,
  financial: 3,
  regulatory: 3,
  reputation: 3,
  safety: 1,
};

function commaList(value: string): string[] {
  return [...new Set(value.split(',').map((item) => item.trim()).filter(Boolean))];
}

export function RiskGovernanceWorkspace({ accessToken }: RiskGovernanceWorkspaceProps) {
  const api = useMemo(
    () => createGovernanceApi({ getAccessToken: () => accessToken }),
    [accessToken],
  );
  const [projects, setProjects] = useState<Project[]>([]);
  const [systems, setSystems] = useState<OperationalSystem[]>([]);
  const [portfolio, setPortfolio] = useState<PortfolioGovernance | null>(null);
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [selectedSystemId, setSelectedSystemId] = useState('');
  const [overview, setOverview] = useState<GovernanceOverview | null>(null);
  const [contexts, setContexts] = useState<SystemContextVersion[]>([]);
  const [treatments, setTreatments] = useState<RiskTreatment[]>([]);
  const [controls, setControls] = useState<Control[]>([]);
  const [risks, setRisks] = useState<RiskSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [businessOwner, setBusinessOwner] = useState('');
  const [capabilities, setCapabilities] = useState('');
  const [processes, setProcesses] = useState('');
  const [dataCategories, setDataCategories] = useState('');
  const [regulations, setRegulations] = useState('');
  const [rto, setRto] = useState('');
  const [rpo, setRpo] = useState('');
  const [impact, setImpact] = useState(defaultImpact);

  const [selectedRiskId, setSelectedRiskId] = useState('');
  const [treatmentTitle, setTreatmentTitle] = useState('');
  const [treatmentOwner, setTreatmentOwner] = useState('');
  const [treatmentPriority, setTreatmentPriority] = useState<Criticality>('high');
  const [treatmentSla, setTreatmentSla] = useState('30');
  const [verificationCriteria, setVerificationCriteria] = useState('');

  const [controlKey, setControlKey] = useState('');
  const [controlName, setControlName] = useState('');
  const [controlOwner, setControlOwner] = useState('');
  const [controlFramework, setControlFramework] = useState('');

  const selectedSystem = systems.find((system) => system.id === selectedSystemId) ?? null;

  async function refreshSystem(systemId: string): Promise<void> {
    const [nextOverview, nextContexts, nextTreatments, nextControls, nextRisks] =
      await Promise.all([
        api.overview(systemId),
        api.contexts(systemId),
        api.treatments(systemId),
        api.controls(systemId),
        api.risks(systemId),
      ]);
    setOverview(nextOverview);
    setContexts(nextContexts);
    setTreatments(nextTreatments);
    setControls(nextControls);
    setRisks(nextRisks.items);
    setSelectedRiskId((current) =>
      nextRisks.items.some((risk) => risk.id === current)
        ? current
        : (nextRisks.items[0]?.id ?? ''),
    );
  }

  useEffect(() => {
    let active = true;
    Promise.all([api.listProjects(), api.portfolio()])
      .then(([nextProjects, nextPortfolio]) => {
        if (!active) return;
        setProjects(nextProjects);
        setPortfolio(nextPortfolio);
        setSelectedProjectId(nextProjects[0]?.id ?? '');
      })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : String(reason));
      });
    return () => {
      active = false;
    };
  }, [api]);

  useEffect(() => {
    if (!selectedProjectId) {
      setSystems([]);
      setSelectedSystemId('');
      return;
    }
    void api
      .listSystems(selectedProjectId)
      .then((items) => {
        setSystems(items);
        setSelectedSystemId(items[0]?.id ?? '');
      })
      .catch((reason: unknown) =>
        setError(reason instanceof Error ? reason.message : String(reason)),
      );
  }, [api, selectedProjectId]);

  useEffect(() => {
    if (!selectedSystemId) {
      setOverview(null);
      return;
    }
    void refreshSystem(selectedSystemId).catch((reason: unknown) =>
      setError(reason instanceof Error ? reason.message : String(reason)),
    );
  }, [api, selectedSystemId]);

  async function run(work: () => Promise<void>): Promise<void> {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await work();
      setPortfolio(await api.portfolio());
      if (selectedSystemId) await refreshSystem(selectedSystemId);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  function createContext(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedSystemId) return;
    const payload: SystemContextInput = {
      business_owner: businessOwner,
      capabilities: commaList(capabilities),
      processes: commaList(processes),
      data_categories: commaList(dataCategories),
      regulations: commaList(regulations),
      recovery_time_objective_hours: rto === '' ? null : Number(rto),
      recovery_point_objective_hours: rpo === '' ? null : Number(rpo),
      impact_profile: impact,
    };
    void run(async () => {
      const created = await api.createContext(selectedSystemId, payload);
      setNotice(`Verksamhetskontext v${created.version} skapades som utkast.`);
    });
  }

  function createTreatment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedSystemId || !selectedRiskId) return;
    void run(async () => {
      await api.createTreatment(selectedSystemId, selectedRiskId, {
        strategy: 'mitigate',
        title: treatmentTitle,
        description: '',
        owner: treatmentOwner,
        priority: treatmentPriority,
        sla_days: Number(treatmentSla),
        verification_criteria: verificationCriteria,
      });
      setTreatmentTitle('');
      setNotice('Riskåtgärden skapades och är nu spårbar.');
    });
  }

  function createControl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedSystemId) return;
    void run(async () => {
      await api.createControl(selectedSystemId, {
        control_key: controlKey,
        name: controlName,
        description: '',
        framework: controlFramework,
        owner: controlOwner,
        status: 'implemented',
      });
      setControlKey('');
      setControlName('');
      setNotice('Kontrollen skapades.');
    });
  }

  return (
    <main className="governance-workspace">
      <header className="governance-heading">
        <div>
          <span className="eyebrow">CLOSED-LOOP CYBERRISK</span>
          <h1>Riskbeslut, åtgärder och verifiering</h1>
          <p>
            Verksamhetskontext, riskägare, SLA, kontroller, residualrisk och lineage hålls
            åtskilda från tekniska observationer.
          </p>
        </div>
      </header>

      {error && <div className="op-feedback op-feedback--error" role="alert">{error}</div>}
      {notice && <div className="op-feedback op-feedback--success" role="status">{notice}</div>}

      {portfolio && (
        <section className="governance-metrics" aria-label="Riskstyrningsportfolio">
          <article><strong>{portfolio.open_risks}</strong><small>Öppna risker</small></article>
          <article><strong>{portfolio.risks_without_owner}</strong><small>Utan ägd åtgärd</small></article>
          <article><strong>{portfolio.overdue_treatments}</strong><small>Försenade åtgärder</small></article>
          <article><strong>{portfolio.average_coverage_percent}%</strong><small>Governance-täckning</small></article>
        </section>
      )}

      <section className="panel governance-selectors">
        <label>
          <span>Projekt</span>
          <select value={selectedProjectId} onChange={(event) => setSelectedProjectId(event.target.value)}>
            <option value="">Välj projekt</option>
            {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
          </select>
        </label>
        <label>
          <span>System</span>
          <select value={selectedSystemId} onChange={(event) => setSelectedSystemId(event.target.value)}>
            <option value="">Välj system</option>
            {systems.map((system) => <option key={system.id} value={system.id}>{system.name}</option>)}
          </select>
        </label>
        {selectedSystem && <p><strong>{selectedSystem.name}</strong> · {selectedSystem.owner}</p>}
      </section>

      {!selectedSystemId ? (
        <EmptyState title="Välj ett system">
          Governanceflödet är systembundet men aggregeras i portfolion.
        </EmptyState>
      ) : (
        <>
          {overview && (
            <section className="governance-metrics governance-metrics--system" aria-label="Systemets governance">
              <article><strong>{overview.coverage_percent}%</strong><small>Täckning</small></article>
              <article><strong>{overview.open_risks}</strong><small>Öppna risker</small></article>
              <article><strong>{overview.risks_with_active_treatment}</strong><small>Med aktiv åtgärd</small></article>
              <article><strong>{overview.controls_with_current_assessment}/{overview.controls}</strong><small>Bedömda kontroller</small></article>
            </section>
          )}

          <div className="governance-grid">
            <section className="panel">
              <span className="section-kicker">VERKSAMHETSKONTEXT</span>
              <h2>Ny versionshanterad kontext</h2>
              <form className="governance-form" onSubmit={createContext}>
                <label><span>Affärsägare</span><input required value={businessOwner} onChange={(event) => setBusinessOwner(event.target.value)} /></label>
                <label><span>Förmågor</span><input value={capabilities} onChange={(event) => setCapabilities(event.target.value)} placeholder="Betalningar, kundportal" /></label>
                <label><span>Processer</span><input value={processes} onChange={(event) => setProcesses(event.target.value)} /></label>
                <label><span>Datakategorier</span><input value={dataCategories} onChange={(event) => setDataCategories(event.target.value)} /></label>
                <label><span>Regelverk</span><input value={regulations} onChange={(event) => setRegulations(event.target.value)} placeholder="DORA, NIS2" /></label>
                <div className="governance-form__pair">
                  <label><span>RTO timmar</span><input min="0" step="0.5" type="number" value={rto} onChange={(event) => setRto(event.target.value)} /></label>
                  <label><span>RPO timmar</span><input min="0" step="0.5" type="number" value={rpo} onChange={(event) => setRpo(event.target.value)} /></label>
                </div>
                <div className="governance-impact">
                  {(Object.keys(impact) as Array<keyof typeof impact>).map((key) => (
                    <label key={key}><span>{key}</span><select value={impact[key]} onChange={(event) => setImpact((current) => ({ ...current, [key]: Number(event.target.value) }))}>{[1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                  ))}
                </div>
                <button className="primary-button" disabled={busy}>Skapa kontextutkast</button>
              </form>
              <div className="governance-list">
                {contexts.map((context) => (
                  <article key={context.id}>
                    <strong>v{context.version} · {context.status}</strong>
                    <span>{context.business_owner || 'Affärsägare saknas'}</span>
                    {context.status === 'draft' && (
                      <button disabled={busy} onClick={() => void run(async () => {
                        await api.publishContext(selectedSystemId, context.id);
                        setNotice(`Verksamhetskontext v${context.version} publicerades.`);
                      })}>Publicera</button>
                    )}
                  </article>
                ))}
              </div>
            </section>

            <section className="panel">
              <span className="section-kicker">RISKBEHANDLING</span>
              <h2>Ägd åtgärd med SLA</h2>
              <form className="governance-form" onSubmit={createTreatment}>
                <label><span>Risk</span><select required value={selectedRiskId} onChange={(event) => setSelectedRiskId(event.target.value)}><option value="">Välj risk</option>{risks.map((risk) => <option key={risk.id} value={risk.id}>{risk.title}</option>)}</select></label>
                <label><span>Åtgärd</span><input required value={treatmentTitle} onChange={(event) => setTreatmentTitle(event.target.value)} /></label>
                <label><span>Ansvarig</span><input required value={treatmentOwner} onChange={(event) => setTreatmentOwner(event.target.value)} /></label>
                <label><span>Prioritet</span><select value={treatmentPriority} onChange={(event) => setTreatmentPriority(event.target.value as Criticality)}><option value="low">Låg</option><option value="medium">Medel</option><option value="high">Hög</option><option value="critical">Kritisk</option></select></label>
                <label><span>SLA dagar</span><input min="0" type="number" value={treatmentSla} onChange={(event) => setTreatmentSla(event.target.value)} /></label>
                <label><span>Verifieringskriterier</span><textarea value={verificationCriteria} onChange={(event) => setVerificationCriteria(event.target.value)} /></label>
                <button className="primary-button" disabled={busy || !selectedRiskId}>Skapa riskåtgärd</button>
              </form>
              <div className="governance-list">
                {treatments.map((treatment) => (
                  <article className={treatment.overdue ? 'is-overdue' : ''} key={treatment.id}>
                    <strong>{treatment.title}</strong>
                    <span>{treatment.owner} · {treatment.status} · {treatment.priority}</span>
                    <small>{treatment.due_at ? new Date(treatment.due_at).toLocaleDateString('sv-SE') : 'Ingen deadline'}</small>
                    {treatment.status === 'proposed' && (
                      <button disabled={busy} onClick={() => void run(async () => {
                        await api.updateTreatment(selectedSystemId, treatment.id, {
                          status: 'approved',
                          decision_note: 'Godkänd i Traceless governanceflöde.',
                        });
                      })}>Godkänn</button>
                    )}
                  </article>
                ))}
              </div>
            </section>

            <section className="panel">
              <span className="section-kicker">KONTROLLER</span>
              <h2>Namngivna kontrollimplementationer</h2>
              <form className="governance-form" onSubmit={createControl}>
                <label><span>Kontroll-ID</span><input required value={controlKey} onChange={(event) => setControlKey(event.target.value)} placeholder="ISO27001-A.8.8" /></label>
                <label><span>Namn</span><input required value={controlName} onChange={(event) => setControlName(event.target.value)} /></label>
                <label><span>Ramverk</span><input value={controlFramework} onChange={(event) => setControlFramework(event.target.value)} /></label>
                <label><span>Ansvarig</span><input required value={controlOwner} onChange={(event) => setControlOwner(event.target.value)} /></label>
                <button className="primary-button" disabled={busy}>Skapa kontroll</button>
              </form>
              <div className="governance-list">
                {controls.map((control) => (
                  <article key={control.id}><strong>{control.control_key} · {control.name}</strong><span>{control.owner} · {control.status}</span></article>
                ))}
              </div>
            </section>

            <section className="panel">
              <span className="section-kicker">LINEAGE</span>
              <h2>Analysmanifest</h2>
              <p>Fryser vilka scan-, arkitektur-, kontext-, riskpolicy- och kontrollversioner som ligger bakom ett beslut.</p>
              <button className="secondary-button" disabled={busy} onClick={() => void run(async () => {
                const manifest = await api.createManifest(selectedSystemId);
                setNotice(`Analysmanifest ${manifest.source_fingerprint.slice(0, 12)}… skapades.`);
              })}>Skapa manifest</button>
              {overview?.latest_manifest && <p className="mono">{overview.latest_manifest.source_fingerprint}</p>}
            </section>
          </div>
        </>
      )}
    </main>
  );
}
