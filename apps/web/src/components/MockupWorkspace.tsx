import { useEffect, useMemo, useState, type ReactNode } from 'react';

import '../mockup.css';
import type { OperationalActions, OperationalViewModel } from './LiveWorkspace';

export type WorkspaceTab =
  | 'overview'
  | 'assets'
  | 'threats'
  | 'findings'
  | 'risks'
  | 'architecture'
  | 'reports';

interface MockupWorkspaceProps {
  initialTab?: WorkspaceTab;
  onTabChange?: (tab: WorkspaceTab) => void;
  operational?: OperationalViewModel;
  actions?: OperationalActions;
}

type IconName =
  | 'home' | 'chart' | 'database' | 'target' | 'bug' | 'shield' | 'network'
  | 'file' | 'history' | 'search' | 'cube' | 'globe' | 'eye' | 'server'
  | 'check' | 'alert' | 'sparkles' | 'link' | 'user' | 'cloud' | 'code'
  | 'download' | 'upload' | 'clock' | 'filter' | 'plus' | 'close';

function Icon({ name, size = 20 }: { name: IconName; size?: number }) {
  const common = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const };
  let shape: ReactNode;
  switch (name) {
    case 'home': shape = <><path d="m3 11 9-8 9 8" /><path d="M5 10v10h14V10M9 20v-6h6v6" /></>; break;
    case 'chart': shape = <><path d="M4 19V5M4 19h17" /><path d="m7 15 4-5 3 2 5-7" /></>; break;
    case 'database': shape = <><ellipse cx="12" cy="5" rx="7" ry="3" /><path d="M5 5v7c0 1.7 3.1 3 7 3s7-1.3 7-3V5M5 12v7c0 1.7 3.1 3 7 3s7-1.3 7-3v-7" /></>; break;
    case 'target': shape = <><circle cx="12" cy="12" r="7" /><circle cx="12" cy="12" r="2" /><path d="M12 1v4M12 19v4M1 12h4M19 12h4" /></>; break;
    case 'bug': shape = <><path d="M8 8h8v9a4 4 0 0 1-8 0V8Z" /><path d="M9 8a3 3 0 0 1 6 0M4 10h4M16 10h4M5 16h3M16 16h3M12 11v9" /></>; break;
    case 'shield': shape = <path d="M12 2 4.5 5v6.2c0 5.1 3.1 8.7 7.5 10.8 4.4-2.1 7.5-5.7 7.5-10.8V5L12 2Z" />; break;
    case 'network': shape = <><rect x="9" y="2" width="6" height="5" rx="1" /><rect x="2" y="17" width="6" height="5" rx="1" /><rect x="16" y="17" width="6" height="5" rx="1" /><path d="M12 7v5M5 17v-3h14v3" /></>; break;
    case 'file': shape = <><path d="M6 2h8l4 4v16H6z" /><path d="M14 2v5h5M9 12h6M9 16h6" /></>; break;
    case 'history': shape = <><path d="M4 7v5h5" /><path d="M5.2 16.8A8 8 0 1 0 4 9" /><path d="M12 7v5l3 2" /></>; break;
    case 'search': shape = <><circle cx="10.5" cy="10.5" r="6.5" /><path d="m16 16 5 5" /></>; break;
    case 'cube': shape = <><path d="m12 2 8 4.5v10L12 22l-8-5.5v-10z" /><path d="m4 6.5 8 5 8-5M12 11.5V22" /></>; break;
    case 'globe': shape = <><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" /></>; break;
    case 'eye': shape = <><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" /><circle cx="12" cy="12" r="2.5" /></>; break;
    case 'server': shape = <><rect x="3" y="3" width="18" height="7" rx="2" /><rect x="3" y="14" width="18" height="7" rx="2" /><path d="M7 6.5h.01M7 17.5h.01M11 6.5h7M11 17.5h7" /></>; break;
    case 'check': shape = <path d="m5 12 4 4L19 6" />; break;
    case 'alert': shape = <><path d="m12 2 10 18H2L12 2Z" /><path d="M12 8v5M12 17h.01" /></>; break;
    case 'sparkles': shape = <><path d="m8 3 1.2 3.2L12 7.5 9.2 8.8 8 12 6.8 8.8 4 7.5l2.8-1.3L8 3Z" /><path d="m17 12 .8 2.2L20 15l-2.2.8L17 18l-.8-2.2L14 15l2.2-.8L17 12Z" /></>; break;
    case 'link': shape = <><path d="m9 15-2 2a4 4 0 0 1-6-6l3-3a4 4 0 0 1 6 0" /><path d="m15 9 2-2a4 4 0 0 1 6 6l-3 3a4 4 0 0 1-6 0M8 12h8" /></>; break;
    case 'user': shape = <><circle cx="12" cy="7" r="4" /><path d="M4 22v-2a8 8 0 0 1 16 0v2" /></>; break;
    case 'cloud': shape = <path d="M6 19h12a4 4 0 0 0 .8-7.9A7 7 0 0 0 5.4 9.5 4.8 4.8 0 0 0 6 19Z" />; break;
    case 'code': shape = <><path d="m8 8-4 4 4 4M16 8l4 4-4 4M14 4l-4 16" /></>; break;
    case 'download': shape = <><path d="M12 3v12M7 10l5 5 5-5M4 21h16" /></>; break;
    case 'upload': shape = <><path d="M12 16V4M7 9l5-5 5 5M4 21h16" /></>; break;
    case 'clock': shape = <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>; break;
    case 'filter': shape = <path d="M3 5h18l-7 8v6l-4 2v-8L3 5Z" />; break;
    case 'plus': shape = <path d="M12 5v14M5 12h14" />; break;
    case 'close': shape = <path d="m5 5 14 14M19 5 5 19" />; break;
  }
  return <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" {...common}>{shape}</svg>;
}

const tabs: Array<{ id: WorkspaceTab; label: string }> = [
  { id: 'overview', label: 'Översikt' },
  { id: 'assets', label: 'Tillgångar' },
  { id: 'threats', label: 'Hot' },
  { id: 'findings', label: 'Sårbarheter' },
  { id: 'risks', label: 'Risker' },
  { id: 'architecture', label: 'Arkitektur' },
  { id: 'reports', label: 'Rapporter' },
];

const sideItems: Array<{ key: string; tab: WorkspaceTab; label: string; icon: IconName }> = [
  { key: 'home', tab: 'overview', label: 'Översikt', icon: 'home' },
  { key: 'analysis', tab: 'overview', label: 'Operativ analys', icon: 'chart' },
  { key: 'assets', tab: 'assets', label: 'Tillgångar', icon: 'database' },
  { key: 'threats', tab: 'threats', label: 'Hot', icon: 'target' },
  { key: 'findings', tab: 'findings', label: 'Sårbarheter', icon: 'bug' },
  { key: 'risks', tab: 'risks', label: 'Risker', icon: 'shield' },
  { key: 'architecture', tab: 'architecture', label: 'Arkitektur', icon: 'network' },
  { key: 'reports', tab: 'reports', label: 'Rapporter', icon: 'file' },
  { key: 'history', tab: 'overview', label: 'Tidigare skanningar', icon: 'history' },
];

function Severity({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'critical' | 'high' | 'medium' | 'low' | 'success' | 'neutral' }) {
  return <span className={`tm-pill tm-pill--${tone}`}>{children}</span>;
}

function Metric({ icon, label, value, tone = 'purple' }: { icon: IconName; label: string; value: ReactNode; tone?: string }) {
  return (
    <article className={`tm-metric tm-tone-${tone}`}>
      <span className="tm-metric-icon"><Icon name={icon} size={27} /></span>
      <div><small>{label}</small><strong>{value}</strong></div>
    </article>
  );
}

function SecurityBadge({ data }: { data?: OperationalViewModel }) {
  const [open, setOpen] = useState(false);
  const connected = !data || data.status === 'ready';
  const title = data ? 'Datastatus' : 'Säkerhetsstatus';
  const status = data ? (connected ? 'API anslutet' : data.status === 'error' ? 'API-fel' : 'Synkroniserar') : 'Skydd aktivt';
  return (
    <div className="tm-security-wrap">
      <button type="button" className="tm-security" onClick={() => setOpen((value) => !value)}>
        <span><Icon name="shield" size={26} /><i><Icon name="check" size={13} /></i></span>
        <div><small>{title}</small><strong>{status}</strong></div>
        <b>⌄</b>
      </button>
      {open && <div className="tm-security-popover"><strong>{data ? status : 'Alla skydd är aktiva'}</strong><small>{data ? (data.error || data.systemName || 'Ingen operativ datakälla vald') : 'Senast kontrollerat 09:14'}</small></div>}
    </div>
  );
}

function PageHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return <header className="tm-page-heading"><h1>{title}</h1>{subtitle && <p>{subtitle}</p>}</header>;
}

function OverviewPage({ notify, data, onNavigate }: { notify: (message: string) => void; data?: OperationalViewModel; onNavigate: (tab: WorkspaceTab) => void }) {
  const demoScans = [
    ['Produktion', '2024-05-20 02:15', '2024-05-20 02:47', 'server'],
    ['Staging', '2024-05-19 23:10', '2024-05-19 23:36', 'cloud'],
    ['Utveckling', '2024-05-19 18:05', '2024-05-19 18:29', 'code'],
    ['Datacenter', '2024-05-19 12:30', '2024-05-19 13:02', 'database'],
    ['AWS eu-west-1', '2024-05-18 06:45', '2024-05-18 07:21', 'cloud'],
  ] as const;
  const scans = data ? data.scans : demoScans;
  const stats = data?.stats;
  return (
    <div className="tm-page tm-overview-page">
      <PageHeader title="Säkerhetsöversikt" />
      <div className="tm-metrics tm-metrics--six">
        <Metric icon="database" label="Tillgångar" value={stats?.assets ?? 42} />
        <Metric icon="cube" label="Tjänster" value={stats?.services ?? 87} />
        <Metric icon="target" label="Hot" value={stats?.threats ?? 12} tone="red" />
        <Metric icon="bug" label="CVE-kandidater" value={stats?.findings ?? 18} tone="orange" />
        <Metric icon="shield" label="Risker" value={stats?.risks ?? 9} tone="red" />
        <Metric icon="network" label="Arkitektur" value={stats?.architectureStatus ?? 'Utkast'} />
      </div>
      <section className="tm-section tm-pipeline-section">
        <h2>Operativ analys</h2>
        <div className="tm-pipeline">
          {[
            ['Autkorisering', 'shield', 'assets'], ['Skanning', 'target', 'assets'], ['Inventering', 'database', 'assets'],
            ['Hotdata', 'globe', 'threats'], ['CVE-korrelation', 'link', 'findings'], ['Risk', 'shield', 'risks'], ['Rapport', 'file', 'reports'],
          ].map(([label, icon, target], index) => (
            <button type="button" key={label} onClick={() => onNavigate(target as WorkspaceTab)}>
              <b>{index + 1}</b><Icon name={icon as IconName} size={28} /><span>{label}</span>
            </button>
          ))}
        </div>
      </section>
      <div className="tm-overview-grid">
        <section className="tm-card tm-scan-card">
          <h2>{data ? (scans.length ? `Senaste skanning: ${data.systemName || 'valt system'}` : 'Ingen genomförd skanning') : 'Senaste skanning: Produktion'}</h2>
          <div className="tm-table-wrap"><table><thead><tr><th>Miljö</th><th>Starttid</th><th>Sluttid</th><th>Status</th><th /></tr></thead>
            <tbody>{scans.map(([name, start, end, icon, scanStatus]) => <tr key={`${name}-${start}`} onClick={() => notify(`Skanning för ${name}`)}><td><Icon name={icon as IconName} size={19} />{name}</td><td>{formatLiveDate(start, Boolean(data))}</td><td>{formatLiveDate(end, Boolean(data))}</td><td><Severity tone={scanStatus && !['completed', 'succeeded'].includes(scanStatus) ? 'high' : 'success'}>● {scanStatus || 'Slutförd'}</Severity></td><td>›</td></tr>)}</tbody>
          </table></div>
        </section>
        <section className="tm-card tm-risk-donut-card">
          <h2>Risker</h2>
          <div className="tm-donut-content"><div className={`tm-donut ${stats?.risks === 0 ? 'is-empty' : ''}`}><span><strong>{stats?.risks ?? 9}</strong><small>Risker</small></span></div>
            <ul><li><i className="red" />Kritisk <b>{stats?.riskDistribution.critical ?? 2}</b></li><li><i className="orange" />Hög <b>{stats?.riskDistribution.high ?? 3}</b></li><li><i className="amber" />Medel <b>{stats?.riskDistribution.medium ?? 2}</b></li><li><i className="green" />Låg <b>{stats?.riskDistribution.low ?? 2}</b></li></ul>
          </div>
          <div className="tm-highest-risk"><span>{stats?.risks === 0 ? 'Ingen öppen risk' : 'Högsta risk'}</span><Severity tone={stats?.risks === 0 ? 'neutral' : 'critical'}>{stats?.risks === 0 ? 'Saknas' : 'Kritisk'}</Severity></div>
        </section>
      </div>
    </div>
  );
}

function formatLiveDate(value: string, live: boolean): string {
  if (!live || !value) return value || '–';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString('sv-SE', { dateStyle: 'short', timeStyle: 'short' });
}

const assets = [
  { name: 'api-prod-01', ip: '10.20.0.15', type: 'Server', env: 'Produktion', services: 2, seen: 'idag 08:42', status: 'Aktiv', icon: 'cube' as IconName },
  { name: 'waf-prod-01', ip: '10.20.0.5', type: 'Applikation', env: 'Produktion', services: 1, seen: 'idag 08:41', status: 'Aktiv', icon: 'shield' as IconName },
  { name: 'db-prod-01', ip: '10.20.1.20', type: 'Databas', env: 'Produktion', services: 1, seen: 'idag 08:40', status: 'Aktiv', icon: 'database' as IconName },
  { name: 'identity-01', ip: '10.20.0.30', type: 'Tjänst', env: 'Produktion', services: 3, seen: 'igår 22:18', status: 'Aktiv', icon: 'user' as IconName },
  { name: 'logging-01', ip: '10.20.2.15', type: 'Tjänst', env: 'Produktion', services: 2, seen: 'igår 21:55', status: 'Inaktiv', icon: 'file' as IconName },
];

function AssetsPage({ notify, data, onNavigate }: { notify: (message: string) => void; data?: OperationalViewModel; onNavigate: (tab: WorkspaceTab) => void }) {
  const sourceAssets = data ? data.assets : assets;
  const [selected, setSelected] = useState<(typeof sourceAssets)[number] | null>(sourceAssets[0] ?? null);
  const [query, setQuery] = useState('');
  const [activeOnly, setActiveOnly] = useState(false);
  const [environment, setEnvironment] = useState('Alla miljöer');
  const [assetType, setAssetType] = useState('Alla typer');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  useEffect(() => setSelected(sourceAssets[0] ?? null), [data?.selectedSystemId, sourceAssets.length]);
  const filtered = sourceAssets.filter((asset) => `${asset.name} ${asset.ip} ${asset.type}`.toLowerCase().includes(query.toLowerCase()) && (!activeOnly || asset.status === 'Aktiv') && (environment === 'Alla miljöer' || asset.env === environment) && (assetType === 'Alla typer' || asset.type === assetType));
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visibleAssets = filtered.slice((page - 1) * pageSize, page * pageSize);
  const stats = data?.stats;
  function exportAssets() {
    const csv = ['Tillgång,IP-adress,Typ,Miljö,Tjänster,Senast sedd,Status', ...filtered.map((asset) => [asset.name, asset.ip, asset.type, asset.env, asset.services, asset.seen, asset.status].map((value) => `"${String(value).replaceAll('"', '""')}"`).join(','))].join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'traceless-assets.csv'; anchor.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    notify(`${filtered.length} tillgångar exporterades`);
  }
  return (
    <div className="tm-split-page">
      <div className="tm-page">
        <PageHeader title="Tillgångar" />
        <div className="tm-metrics tm-metrics--four">
          <Metric icon="eye" label="Observerade" value={stats?.assets ?? 42} />
          <Metric icon="server" label="Aktiva" value={stats?.activeAssets ?? 39} />
          <Metric icon="globe" label="Internetnära" value={stats?.internetAssets ?? 6} tone="red" />
          <Metric icon="alert" label="Ogranskade" value={stats?.unreviewedAssets ?? 8} tone="orange" />
        </div>
        <div className="tm-toolbar">
          <label className="tm-search"><Icon name="search" size={18} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Sök tillgångar" /></label>
          <button type="button" className={activeOnly ? 'active' : ''} onClick={() => { setActiveOnly((value) => !value); setPage(1); }}><Icon name="filter" size={17} /> {activeOnly ? 'Aktiva' : 'Filtrera'}</button>
          <select aria-label="Miljö" value={environment} onChange={(event) => { setEnvironment(event.target.value); setPage(1); }}><option>Alla miljöer</option>{Array.from(new Set(sourceAssets.map((asset) => asset.env))).map((value) => <option key={value}>{value}</option>)}</select>
          <select aria-label="Typ" value={assetType} onChange={(event) => { setAssetType(event.target.value); setPage(1); }}><option>Alla typer</option>{Array.from(new Set(sourceAssets.map((asset) => asset.type))).map((value) => <option key={value}>{value}</option>)}</select>
          <button type="button" className="tm-toolbar-export" onClick={exportAssets}><Icon name="download" size={17} /> Exportera</button>
        </div>
        <section className="tm-card tm-data-card">
          <div className="tm-table-wrap"><table><thead><tr><th>Tillgång</th><th>IP-adress</th><th>Typ</th><th>Miljö</th><th>Tjänster</th><th>Senast sedd</th><th>Status</th><th /></tr></thead>
            <tbody>{visibleAssets.map((asset) => <tr key={'id' in asset ? asset.id : asset.name} className={selected?.name === asset.name ? 'is-selected' : ''} onClick={() => setSelected(asset)}><td><Icon name={asset.icon as IconName} size={23} /><strong>{asset.name}</strong></td><td>{asset.ip}</td><td>{asset.type}</td><td>{asset.env}</td><td><span className="tm-count">{asset.services}</span></td><td>{asset.seen}</td><td><Severity tone={asset.status === 'Aktiv' ? 'success' : 'high'}>{asset.status}</Severity></td><td>›</td></tr>)}</tbody>
          </table></div>
          <footer className="tm-table-footer"><span>{filtered.length ? (page - 1) * pageSize + 1 : 0}–{Math.min(page * pageSize, filtered.length)} av {filtered.length}</span><select value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value)); setPage(1); }}><option value="10">10 per sida</option><option value="25">25 per sida</option><option value="50">50 per sida</option></select><div className="tm-pages"><button disabled={page === 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>‹</button>{Array.from({ length: pageCount }, (_, index) => index + 1).slice(0, 5).map((number) => <button key={number} className={page === number ? 'active' : ''} onClick={() => setPage(number)}>{number}</button>)}<button disabled={page === pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>›</button></div></footer>
        </section>
      </div>
      {selected && <AssetDrawer asset={selected} live={Boolean(data)} onClose={() => setSelected(null)} notify={notify} onNavigate={onNavigate} />}
    </div>
  );
}

function AssetDrawer({ asset, live, onClose, notify, onNavigate }: { asset: typeof assets[number] | OperationalViewModel['assets'][number]; live: boolean; onClose: () => void; notify: (message: string) => void; onNavigate: (tab: WorkspaceTab) => void }) {
  if (live) return <aside className="tm-drawer"><button className="tm-drawer-close" type="button" onClick={onClose}><Icon name="close" /></button><div className="tm-entity-title"><span><Icon name={asset.icon as IconName} size={28} /></span><div><h2>{asset.name}</h2><Severity tone={asset.status === 'Aktiv' ? 'success' : 'high'}>● {asset.status}</Severity></div></div><dl className="tm-detail-list"><div><dt><Icon name="globe" size={18} />IP-adress</dt><dd>{asset.ip}</dd></div><div><dt><Icon name="server" size={18} />Typ</dt><dd>{asset.type}</dd></div><div><dt><Icon name="server" size={18} />Miljö</dt><dd>{asset.env}</dd></div><div><dt><Icon name="clock" size={18} />Senast sedd</dt><dd>{asset.seen}</dd></div></dl><DrawerSection title="Observerade tjänster" count={String(asset.services)}><div className="tm-live-detail-note">Tjänstedetaljer läses från vald tillgång när underlaget innehåller tjänster.</div></DrawerSection><button type="button" className="tm-outline-action" onClick={() => onNavigate('architecture')}><Icon name="network" size={19} /> Visa i arkitekturen <span>↗</span></button></aside>;
  return <aside className="tm-drawer">
    <button className="tm-drawer-close" type="button" onClick={onClose}><Icon name="close" /></button>
    <div className="tm-entity-title"><span><Icon name={asset.icon as IconName} size={28} /></span><div><h2>{asset.name}</h2><Severity tone={asset.status === 'Aktiv' ? 'success' : 'high'}>● {asset.status}</Severity></div></div>
    <dl className="tm-detail-list"><div><dt><Icon name="globe" size={18} />IP-adress</dt><dd>{asset.ip}</dd></div><div><dt><Icon name="code" size={18} />Operativsystem</dt><dd>Linux</dd></div><div><dt><Icon name="server" size={18} />Miljö</dt><dd>Produktion</dd></div><div><dt><Icon name="target" size={18} />Exponering</dt><dd><Severity tone="critical">Internetnära</Severity> <Severity tone="critical">DMZ</Severity></dd></div><div><dt><Icon name="clock" size={18} />Senast sedd</dt><dd>idag 08:42</dd></div></dl>
    <DrawerSection title="Observerade tjänster" count="2"><div className="tm-list-row"><span>443/tcp</span><b>HTTPS</b><Severity tone="success">Öppen</Severity></div><div className="tm-list-row"><span>8443/tcp</span><b>API</b><Severity tone="success">Öppen</Severity></div></DrawerSection>
    <DrawerSection title="Proveniens" count="2"><button className="tm-list-row" onClick={() => notify('Nmap-proveniensen öppnades')}><span>Nmap service_inventory</span><small>idag 08:40</small><b>›</b></button><button className="tm-list-row" onClick={() => notify('NetBox-proveniensen öppnades')}><span>NetBox snapshot</span><small>idag 08:35</small><b>›</b></button></DrawerSection>
    <button type="button" className="tm-outline-action" onClick={() => onNavigate('architecture')}><Icon name="network" size={19} /> Visa i arkitekturen <span>↗</span></button>
  </aside>;
}

const threatRows = [
  ['Kritisk', 'Aktiv exploatering mot internetnära API', 'Intern hotfeed', 'idag 08:35', '91 %', 'T1190', 'Exploit Public-Facing Application', 'API-server · WAF / Gateway'],
  ['Hög', 'Credential access mot identitetstjänst', 'CISA KEV', 'idag 07:15', '78 %', 'T1550', 'Use Alternate Authentication Material', 'Identitet'],
  ['Hög', 'Ransomware mot exponerad filöverföring', 'MISP', 'igår 22:47', '72 %', 'T1486', 'Data Encrypted for Impact', 'Filöverföring'],
  ['Medel', 'API brute-force-kampanj', 'Intern hotfeed', 'igår 18:02', '61 %', 'T1110', 'Brute Force', 'API-server'],
  ['Medel', 'Skanning efter sårbar RDP', 'CISA KEV', 'igår 16:20', '54 %', 'T1021', 'Remote Services', 'Staging'],
];

function ThreatsPage({ data, notify }: { data?: OperationalViewModel; notify: (message: string) => void }) {
  const [selected, setSelected] = useState(0);
  const [page, setPage] = useState(1);
  const rows = data ? data.threatRows : threatRows;
  const stats = data?.stats;
  const pageSize = 5;
  const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
  const visibleRows = rows.slice((page - 1) * pageSize, page * pageSize);
  return <div className="tm-split-page">
    <div className="tm-page">
      <PageHeader title="Aktuella hot" subtitle="Matchade mot observerad teknik och aktuellt skanningsunderlag" />
      <div className="tm-metrics tm-metrics--four"><Metric icon="target" label="Matchade hot" value={stats?.threats ?? 12} tone="red" /><Metric icon="shield" label="Kritiska" value={stats?.criticalThreats ?? 3} tone="red" /><Metric icon="globe" label="Internetnära" value={stats?.internetAssets ?? 5} tone="orange" /><Metric icon="sparkles" label="Nya idag" value={stats?.newThreats ?? 2} /></div>
      <section className="tm-card tm-data-card"><div className="tm-table-wrap"><table><thead><tr><th>Allvarlighet</th><th>Hot</th><th>Källa</th><th>Konfidens</th><th>ATT&CK</th><th>Matchade tillgångar</th><th /></tr></thead><tbody>
        {visibleRows.map((row, index) => { const absoluteIndex = (page - 1) * pageSize + index; return <tr key={`${row[1]}-${absoluteIndex}`} className={selected === absoluteIndex ? 'is-selected' : ''} onClick={() => setSelected(absoluteIndex)}><td><Severity tone={row[0] === 'Kritisk' ? 'critical' : row[0] === 'Hög' ? 'high' : 'medium'}>{row[0]}</Severity></td><td><strong>{row[1]}</strong></td><td>{row[2]}<small>{row[3]}</small></td><td><strong>{row[4]}</strong><i className="tm-confidence" style={{ '--fill': row[4] } as React.CSSProperties} /></td><td><strong>{row[5]}</strong><small>{row[6]}</small></td><td>{row[7]}</td><td>›</td></tr>; })}
      </tbody></table></div><footer className="tm-table-footer"><span>Visar {rows.length ? (page - 1) * pageSize + 1 : 0}–{Math.min(page * pageSize, rows.length)} av {rows.length} hot</span><div className="tm-pages"><button disabled={page === 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>‹</button>{Array.from({ length: pageCount }, (_, index) => index + 1).map((number) => <button key={number} className={page === number ? 'active' : ''} onClick={() => setPage(number)}>{number}</button>)}<button disabled={page === pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>›</button></div></footer></section>
    </div>
    {selected >= 0 && rows[selected] && <ThreatDrawer row={rows[selected]} live={Boolean(data)} notify={notify} onClose={() => setSelected(-1)} />}
  </div>;
}

function DrawerSection({ title, count, children }: { title: string; count?: string; children: ReactNode }) {
  return <section className="tm-drawer-section"><header><h3>{title}</h3>{count && <span>{count}</span>}</header>{children}</section>;
}

function ThreatDrawer({ row, live, notify, onClose }: { row: string[]; live: boolean; notify: (message: string) => void; onClose: () => void }) {
  if (live) return <aside className="tm-drawer"><button className="tm-drawer-close" type="button" onClick={onClose}><Icon name="close" /></button><h2 className="tm-drawer-heading">{row[1]}</h2><Severity tone={row[0] === 'Kritisk' ? 'critical' : row[0] === 'Hög' ? 'high' : 'medium'}><Icon name="target" size={16} /> {row[0]}</Severity><div className="tm-mini-metrics"><div><small>Konfidens</small><strong>{row[4]}</strong></div><div><small>Matchade tillgångar</small><strong>{row[7]?.match(/\d+/)?.[0] ?? '0'}</strong></div><div><small>Källa</small><strong className="tm-small-value">{row[2]}</strong></div><div><small>ATT&CK</small><strong>{row[5]}</strong></div></div><DrawerSection title="Operativt underlag"><p>{row[6] || 'Ingen ytterligare ATT&CK-beskrivning finns i den aktuella hotposten.'}</p><div className="tm-live-detail-note">Källa uppdaterad {row[3]}. Endast fält från backend visas i live-läget.</div></DrawerSection></aside>;
  return <aside className="tm-drawer">
    <button className="tm-drawer-close" type="button" onClick={onClose}><Icon name="close" /></button>
    <h2 className="tm-drawer-heading">{row[1]}</h2><Severity tone={row[0] === 'Kritisk' ? 'critical' : 'high'}><Icon name="target" size={16} /> {row[0]}</Severity>
    <div className="tm-mini-metrics"><div><small>Konfidens</small><strong>{row[4]}</strong></div><div><small>Matchade tillgångar</small><strong>{row[7]?.match(/\d+/)?.[0] ?? '–'}</strong></div><div><small>Källa</small><strong className="tm-small-value">{row[2]}</strong></div><div><small>ATT&CK</small><strong>{row[5]}</strong></div></div>
    <DrawerSection title="Varför matchades hotet?"><p>Hotet matchar observerad exponering av API-server via internet samt kända sårbarheter med aktiv exploatering i det vilda.</p><ul className="tm-check-list"><li>Internetexponering bekräftad</li><li>Sårbar version identifierad</li><li>Aktiv exploatering rapporterad</li><li>Teknisk överensstämmelse med hotbeteende</li></ul></DrawerSection>
    <DrawerSection title="Påverkade komponenter"><div className="tm-list-row"><Icon name="cube" /><span><b>API-server</b><small>Applikation · Internetnära</small></span><Severity tone="critical">Kritisk</Severity><b>›</b></div><div className="tm-list-row"><Icon name="shield" /><span><b>WAF / Gateway</b><small>Säkerhetskomponent · Internetnära</small></span><Severity tone="high">Hög</Severity><b>›</b></div></DrawerSection>
    <DrawerSection title="Källa & proveniens"><button className="tm-list-row" onClick={() => notify('Hotkällans proveniens öppnades')}><span>Intern hotfeed · hämtad idag 08:35</span><b>›</b></button></DrawerSection>
    <div className="tm-callout tm-callout--danger"><Icon name="alert" /><div><strong>Matchning är inte bevis på kompromettering</strong><p>Verifiera och vidta åtgärder baserat på intern riskbedömning och ytterligare utredning.</p></div></div>
  </aside>;
}

const findings = [
  ['CVE-2025-24813', 'api-prod-01', '8443/tcp', '9,8', '72 %', 'Ja', 'Stark'],
  ['CVE-2024-3094', 'edge-proxy-02', '443/tcp', '9,1', '35 %', 'Nej', 'Medel'],
  ['CVE-2023-44487', 'filesrv-01', '445/tcp', '8,8', '18 %', 'Nej', 'Medel'],
  ['CVE-2024-6387', 'vpn-gw-01', '1194/udp', '7,5', '12 %', 'Nej', 'Svag'],
];

function FindingsPage({ notify, data, actions }: { notify: (message: string) => void; data?: OperationalViewModel; actions?: OperationalActions }) {
  const [selected, setSelected] = useState(0);
  const [filter, setFilter] = useState('Alla');
  const [page, setPage] = useState(1);
  const rows = data ? data.findingRows : findings;
  const stats = data?.stats;
  const filteredRows = rows.filter((row) => filter === 'Alla' || filter === 'Behöver verifieras' || (filter === 'KEV' && row[5] === 'Ja') || (filter === 'Hög EPSS' && Number.parseInt(row[4]) >= 50) || filter === 'Internetnära');
  const pageSize = 25;
  const pageCount = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const visibleRows = filteredRows.slice((page - 1) * pageSize, page * pageSize);
  return <div className="tm-split-page">
    <div className="tm-page">
      <PageHeader title="Sårbarhetskandidater" />
      <div className="tm-metrics tm-metrics--five"><Metric icon="bug" label="Kandidater" value={stats?.findings ?? 18} tone="orange" /><Metric icon="shield" label="KEV" value={stats?.kevFindings ?? 3} tone="red" /><Metric icon="target" label="CVSS ≥ 9,0" value={stats?.criticalFindings ?? 4} tone="red" /><Metric icon="globe" label="Internetnära" value={stats?.internetAssets ?? 5} tone="orange" /><Metric icon="shield" label="Verifierade" value={stats?.verifiedFindings ?? 1} tone="green" /></div>
      <div className="tm-chips">{['Alla', 'KEV', 'Hög EPSS', 'Internetnära', 'Behöver verifieras'].map((chip) => <button type="button" className={filter === chip ? 'active' : ''} onClick={() => { setFilter(chip); setPage(1); }} key={chip}>{chip}</button>)}</div>
      <section className="tm-card tm-data-card"><div className="tm-table-wrap"><table><thead><tr><th /><th>CVE</th><th>Tillgång / tjänst</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Matchning</th><th>Status</th><th /></tr></thead><tbody>
        {visibleRows.map((row) => { const absoluteIndex = rows.indexOf(row); return <tr key={`${row[0]}-${absoluteIndex}`} className={selected === absoluteIndex ? 'is-selected' : ''} onClick={() => setSelected(absoluteIndex)}><td><span className={`tm-checkbox ${selected === absoluteIndex ? 'checked' : ''}`}>{selected === absoluteIndex ? '✓' : ''}</span></td><td><strong className="tm-red-text">{row[0]}</strong></td><td><Icon name={absoluteIndex === 1 ? 'globe' : absoluteIndex === 2 ? 'database' : absoluteIndex === 3 ? 'shield' : 'cube'} size={23} /><span><strong>{row[1]}</strong><small>{row[2]}</small></span></td><td><Severity tone="critical">{row[3]}</Severity></td><td><Severity tone="high">{row[4]}</Severity></td><td><Severity tone={row[5] === 'Ja' ? 'critical' : 'neutral'}>{row[5]}</Severity></td><td><Severity tone={row[6] === 'Stark' ? 'success' : row[6] === 'Medel' ? 'medium' : 'neutral'}>{row[6]}</Severity></td><td><Severity tone="high">Kandidat</Severity></td><td>›</td></tr>; })}
      </tbody></table></div><footer className="tm-table-footer"><span>Visar {filteredRows.length ? (page - 1) * pageSize + 1 : 0}–{Math.min(page * pageSize, filteredRows.length)} av {filteredRows.length} kandidater</span><select value={pageSize} onChange={() => setPage(1)}><option value="25">25 per sida</option></select><div className="tm-pages"><button disabled={page === 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>‹</button>{Array.from({ length: pageCount }, (_, index) => index + 1).map((number) => <button key={number} className={page === number ? 'active' : ''} onClick={() => setPage(number)}>{number}</button>)}<button disabled={page === pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>›</button></div></footer></section>
    </div>
    {selected >= 0 && rows[selected] && <FindingDrawer row={rows[selected]} live={Boolean(data)} onClose={() => setSelected(-1)} notify={notify} onVerify={data && actions ? () => actions.updateFinding(data.findingIds[selected], 'verify') : undefined} onReject={data && actions ? () => actions.updateFinding(data.findingIds[selected], 'reject') : undefined} />}
  </div>;
}

function FindingDrawer({ row, live, onClose, notify, onVerify, onReject }: { row: string[]; live: boolean; onClose: () => void; notify: (message: string) => void; onVerify?: () => Promise<void>; onReject?: () => Promise<void> }) {
  if (live) return <aside className="tm-drawer"><button className="tm-drawer-close" type="button" onClick={onClose}><Icon name="close" /></button><h2 className="tm-drawer-heading">{row[0]}</h2><div className="tm-mini-metrics"><div><small>CVSS</small><strong className="tm-red-text">{row[3]}</strong></div><div><small>EPSS</small><strong className="tm-red-text">{row[4]}</strong></div><div><small>KEV</small><strong className="tm-red-text">{row[5]}</strong></div><div><small>Evidens</small><strong className="tm-orange-text">{row[6]}</strong></div></div><DrawerSection title="Berörd tillgång"><div className="tm-list-row"><Icon name="cube" /><span><b>{row[1]}</b><small>{row[2]}</small></span></div></DrawerSection><DrawerSection title="Analytikerbedömning"><div className="tm-action-row"><button className="success" onClick={() => onVerify && void onVerify()}>✓ Verifiera</button><button className="danger" onClick={() => onReject && void onReject()}>− Avvisa</button><button className="warning" onClick={() => notify('Kandidaten behölls')}>◷ Behåll som kandidat</button></div></DrawerSection><div className="tm-callout"><span>ⓘ</span><p>Bedömningen sparas via fyndets riktiga livscykel-API.</p></div></aside>;
  return <aside className="tm-drawer">
    <button className="tm-drawer-close" type="button" onClick={onClose}><Icon name="close" /></button><h2 className="tm-drawer-heading">{row[0]}</h2>
    <div className="tm-mini-metrics"><div><small>CVSS</small><strong className="tm-red-text">{row[3]}</strong></div><div><small>EPSS</small><strong className="tm-red-text">{row[4]}</strong></div><div><small>KEV</small><strong className="tm-red-text">{row[5]}</strong></div><div><small>Status</small><strong className="tm-orange-text">Kandidat</strong></div></div>
    <DrawerSection title="Matchningsgrund"><p>Produkt och versionsindikation från Nmap</p><div className="tm-score-line"><Severity tone="neutral">CPE-match (stark)</Severity><span>80 %</span></div><i className="tm-score-bar" /></DrawerSection>
    <DrawerSection title="Berörd tjänst"><button className="tm-list-row" onClick={() => notify('Den berörda tjänsten öppnades')}><Icon name="cube" /><span><b>api-prod-01 · 8443/tcp</b><small className="tm-orange-text">Exponerad mot Internet</small></span><b>›</b></button></DrawerSection>
    <DrawerSection title="Källor"><div className="tm-source-row"><span><Icon name="database" />NVD</span><span><Icon name="shield" />CISA KEV</span><span><Icon name="target" />FIRST EPSS</span></div></DrawerSection>
    <DrawerSection title="Analytikerbedömning"><div className="tm-action-row"><button className="success" onClick={() => onVerify ? void onVerify() : notify('Kandidaten verifierades')}>✓ Verifiera</button><button className="danger" onClick={() => onReject ? void onReject() : notify('Kandidaten avvisades')}>− Avvisa</button><button className="warning" onClick={() => notify('Kandidaten behölls')}>◷ Behåll som kandidat</button></div></DrawerSection>
    <div className="tm-callout"><span>ⓘ</span><p>CPE- och versionskorrelation är inte ensam bekräftelse på sårbarhet.</p></div>
  </aside>;
}

const riskRows = [
  ['1', 'Exploatering av internetnära API', 'API-server', '4/5', '5/5', '20/25', 'Kritisk', 'Säkerhetsansvarig'],
  ['2', 'Otillräcklig nätverkssegmentering', 'Nätverk', '3/5', '4/5', '12/25', 'Hög', 'Infrastrukturansvarig'],
  ['3', 'Kompromettering av identitetstjänst', 'Identitetstjänst', '3/5', '3/5', '9/25', 'Medel', 'IAM-ansvarig'],
  ['4', 'Otillräcklig loggtäckning', 'Loggning', '2/5', '3/5', '6/25', 'Medel', 'SOC-ansvarig'],
];

function RisksPage({ notify, data }: { notify: (message: string) => void; data?: OperationalViewModel }) {
  const [selected, setSelected] = useState(0);
  const rows = data ? data.riskRows : riskRows;
  const stats = data?.stats;
  return <div className="tm-split-page">
    <div className="tm-page">
      <PageHeader title="Riskregister" />
      <div className="tm-metrics tm-metrics--five"><Metric icon="shield" label="Öppna risker" value={stats?.risks ?? 9} /><Metric icon="shield" label="Kritiska" value={stats?.riskDistribution.critical ?? 2} tone="red" /><Metric icon="target" label="Höga" value={stats?.riskDistribution.high ?? 3} tone="orange" /><Metric icon="target" label="Medel" value={stats?.riskDistribution.medium ?? 2} tone="amber" /><Metric icon="target" label="Låga" value={stats?.riskDistribution.low ?? 2} tone="green" /></div>
      <section className="tm-card tm-matrix-card"><h2>Riskmatris (5×5) <small>ⓘ</small></h2><div className="tm-matrix-layout"><div className="tm-matrix-y"><span>5&nbsp; Mycket hög</span><span>4&nbsp; Hög</span><span>3&nbsp; Medel</span><span>2&nbsp; Låg</span><span>1&nbsp; Mycket låg</span></div><div><div className="tm-matrix">{Array.from({ length: 25 }, (_, index) => <i key={index}>{index === 4 && <b>1</b>}{index === 8 && <b className="orange">2</b>}</i>)}</div><div className="tm-matrix-x"><span>1 Mycket låg</span><span>2 Låg</span><span>3 Medel</span><span>4 Hög</span><span>5 Mycket hög</span></div></div><div className="tm-matrix-legend"><p>Poäng = Sannolikhet × Konsekvens</p><small>Skala 1–25</small><ul><li><i className="red" />20–25 <b>Kritisk</b></li><li><i className="orange" />11–19 <b>Hög</b></li><li><i className="amber" />6–10 <b>Medel</b></li><li><i className="green" />1–5 <b>Låg</b></li></ul></div></div></section>
      <section className="tm-card tm-data-card tm-risk-table"><div className="tm-table-wrap"><table><thead><tr><th>Risk</th><th>Tillgång</th><th>Sannolikhet</th><th>Konsekvens</th><th>Poäng</th><th>Nivå</th><th>Ägare</th><th>Status</th><th /></tr></thead><tbody>{rows.map((row, index) => <tr key={`${row[0]}-${index}`} className={selected === index ? 'is-selected' : ''} onClick={() => setSelected(index)}><td><i className={`tm-rank tm-rank-${Math.min(index + 1, 4)}`}>{row[0]}</i><strong>{row[1]}</strong></td><td><Icon name={index === 0 ? 'cube' : index === 1 ? 'network' : index === 2 ? 'user' : 'file'} />{row[2]}</td><td>{row[3]}</td><td>{row[4]}</td><td><strong>{row[5]}</strong></td><td><Severity tone={row[6] === 'Kritisk' ? 'critical' : row[6] === 'Hög' ? 'high' : 'medium'}>{row[6]}</Severity></td><td>{row[7]}</td><td><Severity>Öppen</Severity></td><td>›</td></tr>)}</tbody></table></div><footer className="tm-table-footer"><span>Visar {rows.length} av {stats?.risks ?? 9} risker</span><button onClick={() => notify(`Alla ${stats?.risks ?? rows.length} risker visas`)}>☷ Visa alla risker</button></footer></section>
    </div>
    {selected >= 0 && rows[selected] && <RiskDrawer row={rows[selected]} live={Boolean(data)} onClose={() => setSelected(-1)} notify={notify} />}
  </div>;
}

function RiskDrawer({ row, live, onClose, notify }: { row: string[]; live: boolean; onClose: () => void; notify: (message: string) => void }) {
  if (live) return <aside className="tm-drawer tm-risk-drawer"><button className="tm-drawer-close" type="button" onClick={onClose}><Icon name="close" /></button><h2 className="tm-drawer-heading"><i className="tm-rank tm-rank-1">{row[0]}</i> {row[1]}</h2><div className="tm-risk-score"><div><small>Riskpoäng</small><strong><em>{row[5]?.split('/')[0]}</em>/25</strong><Severity tone={row[6] === 'Kritisk' ? 'critical' : row[6] === 'Hög' ? 'high' : 'medium'}>{row[6]}</Severity></div><dl><div><dt>Sannolikhet</dt><dd><b>{row[3]?.split('/')[0]}</b>/5</dd></div><div><dt>Konsekvens</dt><dd><b>{row[4]?.split('/')[0]}</b>/5</dd></div><div><dt>Ägare</dt><dd><Icon name="user" size={16} /> {row[7]}</dd></div><div><dt>Omfattning</dt><dd>{row[2]}</dd></div></dl></div><DrawerSection title="Operativ riskpost"><div className="tm-live-detail-note">Den här sammanfattningen kommer direkt från riskregistret. Evidenskedja och åtgärdsplan visas först när motsvarande backendfält finns.</div></DrawerSection></aside>;
  return <aside className="tm-drawer tm-risk-drawer"><button className="tm-drawer-close" type="button" onClick={onClose}><Icon name="close" /></button><h2 className="tm-drawer-heading"><i className="tm-rank tm-rank-1">{row[0]}</i> {row[1]}</h2>
    <div className="tm-risk-score"><div><small>Riskpoäng</small><strong><em>{row[5]?.split('/')[0]}</em>/25</strong><Severity tone={row[6] === 'Kritisk' ? 'critical' : row[6] === 'Hög' ? 'high' : 'medium'}>{row[6]}</Severity></div><dl><div><dt>Sannolikhet</dt><dd><b>{row[3]?.split('/')[0]}</b>/5</dd></div><div><dt>Konsekvens</dt><dd><b>{row[4]?.split('/')[0]}</b>/5</dd></div><div><dt>Ägare</dt><dd><Icon name="user" size={16} /> {row[7]}</dd></div><div><dt>Status</dt><dd><Severity>Öppen</Severity></dd></div></dl></div>
    <DrawerSection title="Evidenskedja"><div className="tm-evidence"><div><Icon name="cube" /><b>API-server</b><small>Internetnära</small></div><span>→</span><div><Icon name="shield" /><b>CVE-2025-24813</b><small>CVSS 9.1 · Kritisk</small></div><span>→</span><div><Icon name="target" /><b>Aktiv exploatering</b><small>EPSS 72 %</small></div><span>→</span><div><Icon name="shield" /><b>Risk</b><small className="tm-red-text">20/25</small></div></div></DrawerSection>
    <DrawerSection title="Beräkningsgrund"><p>Sannolikhet 4/5 baseras på aktiva exploit-försök (EPSS 72 %) och exponering mot Internet.<br />Konsekvens 5/5 då systemet hanterar känslig kunddata och ger åtkomst till interna tjänster.</p></DrawerSection>
    <DrawerSection title="Befintliga kontroller"><ul className="tm-check-list"><li>WAF med OWASP Top 10-regler</li><li>Autentisering med OAuth2 och API-nycklar</li><li>Regelbunden sårbarhetsskanning och patchhantering</li></ul></DrawerSection>
    <DrawerSection title="Rekommenderad åtgärd"><div className="tm-recommend"><p>Uppgradera eller patcha berörd komponent, aktivera ytterligare WAF-regler och begränsa åtkomst.</p><button onClick={() => notify('Åtgärdsplan skapad')}>Skapa åtgärdsplan</button></div></DrawerSection>
    <div className="tm-drawer-actions"><button onClick={() => notify('Risken accepterades')}><Icon name="shield" /> Acceptera risk</button><button className="primary" onClick={() => notify('Åtgärdsplan skapad')}><Icon name="file" /> Skapa åtgärdsplan</button></div>
  </aside>;
}

const architectureNodes = [
  { id: 'internet', label: 'Internet', icon: 'globe' as IconName, zone: 'external', alerts: 2 },
  { id: 'waf', label: 'WAF / Gateway', icon: 'shield' as IconName, zone: 'dmz', alerts: 1 },
  { id: 'api', label: 'API-server', icon: 'cube' as IconName, zone: 'app', alerts: 4 },
  { id: 'identity', label: 'Identitet', icon: 'user' as IconName, zone: 'app', alerts: 0 },
  { id: 'internal', label: 'Intern tjänst', icon: 'cube' as IconName, zone: 'app', alerts: 1 },
  { id: 'database', label: 'Databas', icon: 'database' as IconName, zone: 'data', alerts: 3 },
  { id: 'logging', label: 'Loggning', icon: 'file' as IconName, zone: 'data', alerts: 1 },
];

function ArchitecturePage({ notify, data }: { notify: (message: string) => void; data?: OperationalViewModel }) {
  const [selected, setSelected] = useState('api');
  const [zoom, setZoom] = useState(100);
  const [expanded, setExpanded] = useState(false);
  const nodes = data ? data.architectureNodes : architectureNodes;
  return <div className="tm-architecture-page">
    <aside className="tm-arch-library"><h2>Komponenter</h2><button className="active" onClick={() => { if (nodes[0]) setSelected(nodes[0].id); notify('Alla komponenter visas'); }}><Icon name="server" />Alla komponenter <span>{nodes.length || 8}</span></button>{[['Nätverk','network','2'],['Applikation','cube','3'],['Tjänst','database','2'],['Databas','database','1'],['Identitet','user','1'],['Loggning','file','1']].map(([label, icon, count]) => <button key={label} onClick={() => { const node = nodes.find((item) => item.icon === icon); if (node) setSelected(node.id); notify(`${label} filtrerades`); }}><Icon name={icon as IconName} />{label}<span>{count}</span></button>)}<hr /><h2>Zoner</h2>{[['Extern zon','blue','2','external'],['DMZ','purple','2','dmz'],['Applikationszon','green','3','app'],['Databaszon','orange','1','data']].map(([label,tone,count,zone]) => <button key={label} onClick={() => { const node = nodes.find((item) => item.zone === zone); if (node) setSelected(node.id); notify(`${label} öppnades`); }}><i className={`tm-zone-dot ${tone}`} />{label}<span>{count}</span></button>)}<button className="tm-add-zone" onClick={() => notify('Ny zon tillagd')}><Icon name="plus" />Lägg till zon</button></aside>
    <div className={`tm-arch-canvas ${expanded ? 'is-expanded' : ''}`} style={{ '--tm-arch-zoom': zoom / 100 } as React.CSSProperties}>
      <div className="tm-zone tm-zone-external"><h3>Extern zon</h3>{nodes[0] && <ArchitectureNode node={nodes[0]} selected={selected} onSelect={setSelected} />}</div>
      <div className="tm-zone tm-zone-dmz"><h3>DMZ</h3>{nodes[1] && <ArchitectureNode node={nodes[1]} selected={selected} onSelect={setSelected} />}</div>
      <div className="tm-zone tm-zone-app"><h3>Applikationszon</h3>{nodes.slice(2, 5).map((node) => <ArchitectureNode key={node.id} node={node} selected={selected} onSelect={setSelected} />)}</div>
      <div className="tm-zone tm-zone-data"><h3>Databaszon</h3>{nodes.slice(5, 7).map((node) => <ArchitectureNode key={node.id} node={node} selected={selected} onSelect={setSelected} />)}</div>
      {data && nodes.length === 0 && <div className="tm-arch-empty"><Icon name="network" size={34} /><b>Ingen arkitektur publicerad</b><small>Importera eller skapa en arkitekturversion via API:t.</small></div>}
      <div className="tm-arch-controls"><button onClick={() => setZoom((value) => Math.max(50, value - 10))}>−</button><span>{zoom}%</span><button onClick={() => setZoom((value) => Math.min(150, value + 10))}>＋</button><button onClick={() => { setExpanded((value) => !value); notify(expanded ? 'Helskärmsläge stängdes' : 'Arkitekturen expanderades'); }}>⛶</button></div>
      <div className="tm-minimap"><i /><i /><i /><i /></div>
    </div>
    {(!data || nodes.length > 0) && <ArchitectureDrawer node={nodes.find((node) => node.id === selected) ?? nodes[0]} live={Boolean(data)} notify={notify} onClose={() => setSelected('')} />}
  </div>;
}

function ArchitectureNode({ node, selected, onSelect }: { node: typeof architectureNodes[number] | OperationalViewModel['architectureNodes'][number]; selected: string; onSelect: (id: string) => void }) {
  return <button type="button" className={`tm-arch-node tm-node-${node.id} ${selected === node.id ? 'selected' : ''}`} onClick={() => onSelect(node.id)}><Icon name={node.icon as IconName} /><strong>{node.label}</strong><Severity tone={node.alerts > 1 ? 'critical' : node.alerts ? 'high' : 'success'}>● {node.alerts}</Severity></button>;
}

function ArchitectureDrawer({ node, live, notify, onClose }: { node?: typeof architectureNodes[number] | OperationalViewModel['architectureNodes'][number]; live: boolean; notify: (message: string) => void; onClose: () => void }) {
  if (live && node) return <aside className="tm-drawer tm-arch-drawer"><button className="tm-drawer-close" type="button" onClick={onClose}><Icon name="close" /></button><small className="tm-kicker">Komponentdetalj</small><div className="tm-entity-title"><span><Icon name={node.icon as IconName} size={28} /></span><div><h2>{node.label}</h2><small>{node.zone}</small></div></div><div className="tm-mini-metrics"><div><small>Relaterade signaler</small><strong className={node.alerts ? 'tm-red-text' : ''}>{node.alerts}</strong></div></div><DrawerSection title="Operativ arkitektur"><div className="tm-live-detail-note">Komponenten kommer från den senaste arkitekturversionens graf. Inga demodetaljer blandas in.</div></DrawerSection></aside>;
  return <aside className="tm-drawer tm-arch-drawer"><button className="tm-drawer-close" type="button" onClick={onClose}><Icon name="close" /></button><small className="tm-kicker">Komponentdetalj</small><div className="tm-entity-title"><span><Icon name="cube" size={28} /></span><div><h2>API-server</h2><small>Applikation</small></div><Severity tone="success">● Aktiv</Severity></div><div className="tm-mini-metrics"><div><small>Risk</small><strong className="tm-red-text">20<em>/25</em></strong></div><div><small>Hot</small><strong className="tm-red-text">4</strong></div><div><small>CVE-kandidater</small><strong className="tm-orange-text">3</strong></div><div><small>Exponering</small><strong className="tm-red-text tm-small-value">Internetnära</strong></div></div>
    <DrawerSection title="Sårbarheter" count="3"><div className="tm-list-row"><span><b className="tm-red-text">CVE-2025-24813</b><small>CVSS 9.1 · Kritisk</small></span><Severity tone="critical">KEV</Severity><Severity tone="critical">EPSS 72 %</Severity><b>›</b></div><div className="tm-list-row"><span>CVE-2024-3094</span><Severity tone="high">EPSS 35 %</Severity><b>›</b></div><div className="tm-list-row"><span>CVE-2023-44487</span><Severity tone="medium">EPSS 18 %</Severity><b>›</b></div></DrawerSection>
    <DrawerSection title="Hot" count="4"><div className="tm-list-row"><span>Aktiv skanning från Internet</span><Severity tone="critical">Hög</Severity><b>›</b></div><div className="tm-list-row"><span>Känd exploatering i det vilda</span><Severity tone="critical">Hög</Severity><b>›</b></div><div className="tm-list-row"><span>API brute force-försök</span><Severity tone="medium">Medel</Severity><b>›</b></div></DrawerSection>
    <DrawerSection title="Risker" count="2"><div className="tm-list-row"><span>Otillräcklig segmentering</span><Severity tone="critical">Hög</Severity><b>›</b></div><div className="tm-list-row"><span>Exponering av API utan rate limiting</span><Severity tone="medium">Medel</Severity><b>›</b></div></DrawerSection>
    <DrawerSection title="Källa & bevis"><button className="tm-list-row" onClick={() => notify('Källa och bevis öppnades')}><span>Källa: Nmap + NVD + intern hotfeed</span><b>›</b></button></DrawerSection>
  </aside>;
}

function ReportsPage({ notify, data, actions }: { notify: (message: string) => void; data?: OperationalViewModel; actions?: OperationalActions }) {
  const [type, setType] = useState('Ledningsrapport');
  const [format, setFormat] = useState('PDF');
  const rows = data ? data.reportRows : [['Ledningsrapport – Produktion','PDF','idag 09:12','a9f3b7c2d4e6f8a1...'],['Teknisk rapport – Produktion','PDF','idag 09:12','d1c7e3a9b5f8c2d0...'],['Riskregister – Produktion','CSV','igår 16:47','7e2b1c9d4a6f8e3b...']];
  return <div className="tm-page tm-reports-page"><PageHeader title="Rapporter" subtitle="Frysta rapportunderlag med spårbar kontrollsumma" /><div className="tm-report-layout"><div>
      <section className="tm-card tm-report-create"><div><h2>Skapa ny rapport</h2><p>Välj rapporttyp och format</p><div className="tm-report-types">{[['Ledningsrapport','file','Sammanfattning för beslutsfattare'],['Teknisk rapport','code','Detaljerad teknisk analys'],['Riskregister','shield','Risker och åtgärdsrekommendationer']].map(([label,icon,desc]) => <button key={label} className={type === label ? 'active' : ''} onClick={() => setType(label)}><span><Icon name={icon as IconName} size={26} /></span><strong>{label}</strong><small>{desc}</small></button>)}</div></div><div className="tm-format"><h2>Format</h2><p>Välj exportformat</p><div>{['PDF','JSON','CSV'].map((item) => <button key={item} className={format === item ? 'active' : ''} onClick={() => setFormat(item)}><Icon name={item === 'JSON' ? 'code' : 'file'} size={18} />{item}</button>)}</div><button className="tm-create-report" onClick={() => actions ? void actions.createReport(format, type) : notify(`${type} skapades som ${format}`)}>Skapa rapport <span>›</span></button></div></section>
    <section className="tm-card tm-report-library"><h2>Rapportbibliotek</h2><p>Nedladdningsbara, frysta rapporter med verifierbar kontrollsumma</p><div className="tm-table-wrap"><table><thead><tr><th>Rapport</th><th>System</th><th>Format</th><th>Skapad</th><th>Underlag</th><th>SHA-256</th><th>Status</th><th /></tr></thead><tbody>{rows.map(([name,fmt,date,hash], index) => <tr key={`${name}-${index}`}><td><Icon name={index === 1 ? 'code' : index === 2 ? 'shield' : 'file'} /><strong>{name}</strong></td><td>{data?.systemName || 'Produktion'}</td><td><Severity tone={fmt === 'CSV' ? 'success' : 'critical'}>{fmt}</Severity></td><td>{date}</td><td>Fryst underlag</td><td>{hash} ▣</td><td><Severity tone="success">Klar</Severity></td><td><button onClick={() => data && actions ? void actions.downloadReport(data.reportIds[index]) : notify(`${name} laddas ned`)}><Icon name="download" /></button></td></tr>)}</tbody></table></div><button className="tm-more-reports" onClick={() => notify(data ? `Alla ${rows.length} rapporter är inlästa` : 'Fler demorapporter visas när de finns')}>Visa fler rapporter</button></section>
    </div>{data ? <LiveReportPreview data={data} actions={actions} /> : <ReportPreview notify={notify} />}</div></div>;
}

function LiveReportPreview({ data, actions }: { data: OperationalViewModel; actions?: OperationalActions }) {
  const latest = data.reportRows[0];
  if (!latest) return <aside className="tm-report-preview"><section className="tm-card tm-live-empty"><Icon name="file" size={35} /><h3>Inga rapporter skapade</h3><p>Skapa den första rapporten från det operativa underlaget.</p></section></aside>;
  return <aside className="tm-report-preview"><section className="tm-card tm-report-scope"><h3>Rapportens omfattning</h3><p><Icon name="server" />System <b>{data.systemName || 'Valt system'}</b></p><div><span><Icon name="database" />{data.stats.assets}<small>tillgångar</small></span><span><Icon name="target" />{data.stats.threats}<small>hot</small></span><span><Icon name="bug" />{data.stats.findings}<small>CVE-kandidater</small></span><span><Icon name="network" />{data.stats.risks}<small>risker</small></span></div></section><section className="tm-card tm-download-card"><p><span>✓</span><b>{latest[0]}</b><small>Skapad {latest[2]} · {latest[1]}</small></p><div><button onClick={() => actions && void actions.downloadReport(data.reportIds[0])}><Icon name="download" />Ladda ned rapport</button></div></section><div className="tm-callout"><span>ⓘ</span><p>Förhandsvisningen visar endast metadata som finns i den skapade rapportposten.</p></div></aside>;
}

function ReportPreview({ notify }: { notify: (message: string) => void }) {
  return <aside className="tm-report-preview"><section className="tm-card tm-report-scope"><h3>Rapportens omfattning</h3><p><Icon name="server" />System <b>Produktion</b></p><p><Icon name="clock" />Senaste slutförda skanning <b>Idag 09:12</b></p><div><span><Icon name="database" />42<small>tillgångar</small></span><span><Icon name="target" />12<small>hot</small></span><span><Icon name="bug" />18<small>CVE-kandidater</small></span><span><Icon name="network" />9<small>risker</small></span></div></section><section className="tm-paper"><header><div className="tm-logo-mark"><i /></div><b>traceless</b></header><h3>Traceless säkerhetsanalys</h3><p>Ledningsrapport<br />System: Produktion<br />Skapad: 2024-05-20 09:12</p><h4>Sammanfattning</h4><div className="tm-paper-metrics"><span>42<small>Tillgångar</small></span><span>12<small>Hot</small></span><span>18<small>CVE-kandidater</small></span><span>9<small>Risker</small></span></div><h4>Riskfördelning</h4><div className="tm-paper-chart"><div className="tm-donut" /><ul><li>● Kritisk&nbsp;&nbsp;2</li><li>● Hög&nbsp;&nbsp;&nbsp;3</li><li>● Medel&nbsp;&nbsp;2</li><li>● Låg&nbsp;&nbsp;&nbsp;&nbsp;2</li></ul></div></section><section className="tm-card tm-download-card"><p><span>✓</span><b>SHA-256 verifierad</b><small>Skapad idag 09:12</small></p><div><button onClick={() => notify('PDF laddas ned')}><Icon name="download" />Ladda ned PDF</button><button onClick={() => notify('JSON laddas ned')}><Icon name="code" />Ladda ned JSON</button></div></section><div className="tm-callout"><span>ⓘ</span><p>Rapporten fryser aktuellt underlag men verifierar inte kandidater automatiskt.</p></div></aside>;
}

export function MockupWorkspace({ initialTab = 'overview', onTabChange, operational, actions }: MockupWorkspaceProps) {
  const [tab, setTab] = useState<WorkspaceTab>(initialTab);
  const [sideActive, setSideActive] = useState(initialTab === 'overview' ? 'analysis' : initialTab);
  const [menuOpen, setMenuOpen] = useState(false);
  const [toast, setToast] = useState('');

  useEffect(() => setTab(initialTab), [initialTab]);

  function selectTab(next: WorkspaceTab, sideKey: string = next) {
    setTab(next);
    setSideActive(sideKey);
    setMenuOpen(false);
    onTabChange?.(next);
  }

  function notify(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(''), 2300);
  }

  const content = useMemo(() => {
    if (tab === 'assets') return <AssetsPage notify={notify} data={operational} onNavigate={(next) => selectTab(next)} />;
    if (tab === 'threats') return <ThreatsPage data={operational} notify={notify} />;
    if (tab === 'findings') return <FindingsPage notify={notify} data={operational} actions={actions} />;
    if (tab === 'risks') return <RisksPage notify={notify} data={operational} />;
    if (tab === 'architecture') return <ArchitecturePage notify={notify} data={operational} />;
    if (tab === 'reports') return <ReportsPage notify={notify} data={operational} actions={actions} />;
    return <OverviewPage notify={notify} data={operational} onNavigate={(next) => selectTab(next)} />;
  }, [tab, operational, actions]);

  return <div className="tm-app">
    <aside className={`tm-sidebar ${menuOpen ? 'open' : ''}`}>
      <div className="tm-brand"><div className="tm-logo-mark"><i /></div><strong>traceless</strong></div>
      <button className="tm-mobile-close" type="button" onClick={() => setMenuOpen(false)}><Icon name="close" /></button>
      <nav>{sideItems.map((item) => <button type="button" key={item.key} className={sideActive === item.key ? 'active' : ''} onClick={() => selectTab(item.tab, item.key)}><Icon name={item.icon} /><span>{item.label}</span></button>)}</nav>
      <div className="tm-sidebar-status"><span><Icon name="shield" size={30} /><i>✓</i></span><div><small>{operational ? 'Datastatus' : 'Säkerhetsstatus'}</small><strong><b />{operational ? (operational.status === 'ready' ? 'API anslutet' : 'Kontrollerar API') : 'Skydd aktivt'}</strong></div></div>
    </aside>
    {menuOpen && <button className="tm-scrim" type="button" aria-label="Stäng meny" onClick={() => setMenuOpen(false)} />}
    <main className="tm-main">
      <header className="tm-topbar"><button className="tm-menu-button" type="button" onClick={() => setMenuOpen(true)}>☰</button><nav>{tabs.map((item) => <button key={item.id} className={tab === item.id ? 'active' : ''} onClick={() => selectTab(item.id)}>{item.label}</button>)}</nav><SecurityBadge data={operational} />{tab === 'architecture' && <button className="tm-share" type="button" onClick={() => notify('Arkitekturlänk kopierad')}><Icon name="upload" /></button>}</header>
      <div className="tm-workspace">{content}</div>
    </main>
    {toast && <div className="tm-toast"><Icon name="check" size={17} />{toast}</div>}
  </div>;
}

export default MockupWorkspace;
