import { useState } from 'react';

import type { OperationalApi, PipelineOverview, Project, Report } from '../api';

const DEMO_PROJECT = '[DEMO] Traceless end-to-end';
const DEMO_SYSTEM = 'Demo Internet Gateway';
const DEMO_EXTERNAL_ID = 'traceless-demo-cve-2099-4242';
const AUTHORIZATION_CONFIRMATION =
  'Jag bekräftar att jag har tillstånd att skanna angivna mål.' as const;

const DEMO_NMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.99">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="100.64.42.10" addrtype="ipv4"/>
    <address addr="02:42:AC:11:00:42" addrtype="mac" vendor="Traceless Demo"/>
    <hostnames><hostname name="demo-gateway.internal" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Example Gateway" version="1.0.0" conf="10">
          <cpe>cpe:2.3:a:example:gateway:1.0.0:*:*:*:*:*:*:*</cpe>
        </service>
      </port>
    </ports>
    <os><osmatch name="Linux 6.x" accuracy="96"/></os>
  </host>
  <runstats><finished time="1784325600" exit="success"/></runstats>
</nmaprun>`;

interface DemoWorkspaceProps {
  api: OperationalApi;
  accessToken: string | null;
  locale: 'sv' | 'en';
}

interface DemoResult {
  project: Project;
  systemId: string;
  overview: PipelineOverview;
  report: Report;
}

const copy = {
  sv: {
    eyebrow: 'ISOLERAD DEMOMILJÖ',
    title: 'Verifiera hela kedjan med beständig demo-data',
    description:
      'Skapar eller återanvänder ett märkt demo-projekt i den riktiga databasen och kör inventering, intelligencegranskning, korrelation, finding, risk och rapport.',
    warning:
      'Demon använder endast privata RFC 6598-adresser och importerad XML. Ingen aktiv nätverksskanning startas.',
    run: 'Skapa eller uppdatera demo',
    running: 'Kör hela kedjan…',
    completed: 'Hela kedjan slutförd',
    project: 'Projekt',
    system: 'System-ID',
    assets: 'Tillgångar',
    services: 'Tjänster',
    findings: 'Findings',
    threats: 'Hot',
    risks: 'Risker',
    report: 'Rapport',
    persisted: 'Data är sparad i databasen och syns även i den operativa fliken.',
  },
  en: {
    eyebrow: 'ISOLATED DEMO ENVIRONMENT',
    title: 'Verify the complete chain with persisted demo data',
    description:
      'Creates or reuses a labelled demo project in the real database and runs inventory, intelligence review, correlation, finding, risk and report generation.',
    warning:
      'The demo uses only private RFC 6598 addresses and imported XML. No active network scan is started.',
    run: 'Create or update demo',
    running: 'Running the complete chain…',
    completed: 'Complete chain finished',
    project: 'Project',
    system: 'System ID',
    assets: 'Assets',
    services: 'Services',
    findings: 'Findings',
    threats: 'Threats',
    risks: 'Risks',
    report: 'Report',
    persisted: 'The data is persisted in the database and is also visible in the operational tab.',
  },
} as const;

function canonicalDemoFeed() {
  const now = new Date().toISOString();
  return {
    schema_version: '1.0',
    feed_id: 'traceless-demo-feed',
    feed_version: 'demo-1',
    generated_at: now,
    items: [
      {
        source_kind: 'vulnerability',
        provider: 'traceless-demo-publisher',
        external_id: DEMO_EXTERNAL_ID,
        record_type: 'vulnerability',
        title: 'Demo gateway remote-code-execution exposure',
        summary: 'Controlled demo intelligence matching the imported Example Gateway service.',
        modified_at: now,
        retrieved_at: now,
        severity: 'critical',
        confidence: 0.96,
        cve_ids: ['CVE-2099-4242'],
        cpes: ['cpe:2.3:a:example:gateway:1.0.0:*:*:*:*:*:*:*'],
        affected_products: ['Example Gateway'],
        mitre_attack_ids: ['T1190'],
        indicators: [],
        tags: ['demo', 'initial-access'],
        sectors: [],
        regions: ['SE'],
        markings: ['TLP:CLEAR'],
        revoked: false,
        raw_evidence: {
          demo: true,
          source: 'Traceless controlled end-to-end demo',
        },
        vulnerability: {
          affected_cpes: ['cpe:2.3:a:example:gateway:1.0.0:*:*:*:*:*:*:*'],
          cvss_score: 9.8,
          cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          epss_score: 0.91,
          epss_percentile: 0.99,
          exploit_status: 'proof_of_concept',
        },
      },
      {
        source_kind: 'news',
        provider: 'traceless-demo-publisher',
        external_id: 'traceless-demo-campaign-1',
        record_type: 'threat',
        title: 'Demo campaign targeting exposed gateways',
        summary: 'Controlled campaign record connected to CVE-2099-4242.',
        modified_at: now,
        retrieved_at: now,
        severity: 'high',
        confidence: 0.9,
        cve_ids: ['CVE-2099-4242'],
        cpes: [],
        affected_products: ['Example Gateway'],
        mitre_attack_ids: ['T1190'],
        indicators: [],
        tags: ['demo', 'campaign'],
        sectors: [],
        regions: ['SE'],
        markings: ['TLP:CLEAR'],
        revoked: false,
        raw_evidence: { demo: true, source: 'Traceless controlled campaign demo' },
      },
    ],
  };
}

export function DemoWorkspace({ api, accessToken, locale }: DemoWorkspaceProps) {
  const text = copy[locale];
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DemoResult | null>(null);

  async function importDemoIntelligence() {
    const headers = new Headers({
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Actor': 'traceless-demo-workspace',
    });
    if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
    const response = await fetch('/api/v1/operational/intelligence/records/import', {
      method: 'POST',
      credentials: 'same-origin',
      headers,
      body: JSON.stringify(canonicalDemoFeed()),
    });
    if (!response.ok) {
      throw new Error(`Demo intelligence import failed (${response.status})`);
    }
  }

  async function runDemo() {
    setBusy(true);
    setError(null);
    try {
      const projects = await api.listProjects();
      let project = projects.find((item) => item.name === DEMO_PROJECT);
      if (!project) {
        project = await api.createProject({
          name: DEMO_PROJECT,
          description: 'Persisted, isolated Traceless end-to-end demonstration data.',
        });
      }

      const systems = await api.listSystems(project.id);
      let system = systems.find((item) => item.name === DEMO_SYSTEM);
      if (!system) {
        system = await api.createSystem(project.id, {
          name: DEMO_SYSTEM,
          description: 'Controlled demo system populated through the real operational APIs.',
          owner: 'Traceless Demo',
          criticality: 'critical',
        });
      }

      let overview = await api.getOverview(system.id);
      if (overview.collection_totals.assets === 0) {
        const authorization = await api.createAuthorization(system.id, {
          targets: ['100.64.42.10/32'],
          profile: 'service_inventory',
          approved_by: 'Traceless Demo',
          purpose: 'Controlled imported demo inventory; no active scanning.',
          expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
          confirmation: AUTHORIZATION_CONFIRMATION,
        });
        await api.importNmapXml(
          system.id,
          authorization.id,
          new Blob([DEMO_NMAP_XML], { type: 'application/xml' }),
        );
      }

      const existing = await api.listGlobalIntel({ query: DEMO_EXTERNAL_ID, limit: 20 });
      if (existing.items.length === 0) {
        await importDemoIntelligence();
      }
      const pending = await api.listGlobalIntel({
        query: 'traceless-demo',
        reviewStatus: 'pending',
        limit: 50,
      });
      for (const record of pending.items) {
        await api.reviewGlobalIntel(
          record.id,
          'approved',
          'Approved automatically as isolated Traceless demo evidence.',
        );
      }

      await api.correlateGlobalIntel(system.id);
      overview = await api.getOverview(system.id);
      const reports = await api.listReports(system.id);
      let report = reports.find(
        (item) => item.report_type === 'management' && item.format === 'json',
      );
      if (!report) {
        report = await api.createReport(system.id, 'json', 'management');
      }
      setResult({ project, systemId: system.id, overview, report });
    } catch (value) {
      setError(value instanceof Error ? value.message : String(value));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="operational-workspace" aria-labelledby="demo-title">
      <div className="op-hero">
        <div>
          <p className="eyebrow">{text.eyebrow}</p>
          <h1 id="demo-title">{text.title}</h1>
          <p>{text.description}</p>
        </div>
        <button className="primary-button" disabled={busy} onClick={() => void runDemo()} type="button">
          {busy ? text.running : text.run}
        </button>
      </div>

      <div className="op-notice"><strong>{text.warning}</strong></div>
      {error && <div className="op-error-copy" role="alert">{error}</div>}

      {result && (
        <section className="op-section" aria-live="polite">
          <header className="op-section__header"><h2>{text.completed}</h2></header>
          <div className="op-summary-grid">
            <article><small>{text.project}</small><strong>{result.project.name}</strong></article>
            <article><small>{text.system}</small><strong>{result.systemId.slice(0, 8)}</strong></article>
            <article><small>{text.assets}</small><strong>{result.overview.collection_totals.assets}</strong></article>
            <article><small>{text.services}</small><strong>{result.overview.collection_totals.services}</strong></article>
            <article><small>{text.findings}</small><strong>{result.overview.collection_totals.findings}</strong></article>
            <article><small>{text.threats}</small><strong>{result.overview.collection_totals.threats}</strong></article>
            <article><small>{text.risks}</small><strong>{result.overview.collection_totals.risks}</strong></article>
            <article><small>{text.report}</small><strong>{result.report.sha256.slice(0, 12)}…</strong></article>
          </div>
          <p>{text.persisted}</p>
        </section>
      )}
    </section>
  );
}
