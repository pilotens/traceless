import { useCallback, useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import { createPublisherApi, type Account, type Credential, type ImportRun, type Installation, type PublisherEnvironment, type RecordView, type SigningKeySet, type Tlp } from './api';
import { OidcAuthProvider, readOidcConfiguration, useOidcAuth, type OidcAuthDependencies, type OidcConfiguration } from './auth';
import { I18nProvider, useI18n } from './i18n';

interface AppProps { oidcConfiguration?: OidcConfiguration; oidcDependencies?: OidcAuthDependencies; fetchImpl?: typeof fetch }
type Tab = 'overview' | 'accounts' | 'review' | 'imports' | 'keys';

function formatDate(value: string | null, locale: string, never: string) {
  if (!value) return never;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(parsed);
}
function splitValues(value: string) { return value.split(',').map((item) => item.trim()).filter(Boolean); }

function AuthenticationGate() {
  const auth = useOidcAuth();
  const { t } = useI18n();
  const busy = auth.status === 'checking' || auth.status === 'redirecting';
  return <main className="auth-page"><section className="auth-card"><div className="brand-mark">T</div><p className="eyebrow">TRACELESS</p><h1>{busy ? t('checking') : t('signIn')}</h1><p>{auth.errorMessage ?? t('oidcPrompt')}</p>{!busy && auth.canSignIn && <button className="button primary" onClick={() => void auth.signIn()}>{t('signIn')}</button>}</section></main>;
}

function PublisherWorkspace({ fetchImpl }: { fetchImpl?: typeof fetch }) {
  const auth = useOidcAuth();
  const { locale, setLocale, t } = useI18n();
  const [manualAdminToken, setManualAdminToken] = useState('');
  const [manualReviewerToken, setManualReviewerToken] = useState('');
  const [connectedTokens, setConnectedTokens] = useState({ admin: '', reviewer: '' });
  const [tab, setTab] = useState<Tab>('overview');
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [installations, setInstallations] = useState<Installation[]>([]);
  const [records, setRecords] = useState<RecordView[]>([]);
  const [imports, setImports] = useState<ImportRun[]>([]);
  const [keys, setKeys] = useState<SigningKeySet | null>(null);
  const [credentials, setCredentials] = useState<Record<string, Credential[]>>({});
  const [secret, setSecret] = useState<{ label: string; value: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const api = useMemo(
    () => createPublisherApi({
      getToken: (surface) => auth.accessToken ?? ((
        surface === 'review' ? connectedTokens.reviewer : connectedTokens.admin
      ) || null),
      fetchImpl,
    }),
    [auth.accessToken, connectedTokens, fetchImpl],
  );
  const authenticated = Boolean(auth.accessToken || (connectedTokens.admin && connectedTokens.reviewer));

  const load = useCallback(async () => {
    if (!authenticated) return;
    setBusy(true); setError(null);
    try {
      const [accountPage, installationPage, recordPage, importPage, keySet] = await Promise.all([
        api.listAccounts(), api.listInstallations(), api.listRecords(), api.listImports(), api.signingKeys(),
      ]);
      setAccounts(accountPage.items); setInstallations(installationPage.items); setRecords(recordPage.items); setImports(importPage.items); setKeys(keySet);
    } catch (value) { setError(value instanceof Error ? value.message : String(value)); }
    finally { setBusy(false); }
  }, [api, authenticated]);
  useEffect(() => { void load(); }, [load]);

  if (auth.status !== 'disabled' && auth.status !== 'authenticated') return <AuthenticationGate />;
  if (!authenticated) return <main className="auth-page"><section className="auth-card"><div className="brand-mark">T</div><p className="eyebrow">TRACELESS</p><h1>{t('serviceToken')}</h1><p>{t('serviceTokenHint')}</p><label>{t('adminToken')}<input type="password" value={manualAdminToken} onChange={(event) => setManualAdminToken(event.target.value)} /></label><label>{t('reviewerToken')}<input type="password" value={manualReviewerToken} onChange={(event) => setManualReviewerToken(event.target.value)} /></label><button className="button primary" disabled={manualAdminToken.trim().length < 16 || manualReviewerToken.trim().length < 16} onClick={() => { setConnectedTokens({ admin: manualAdminToken.trim(), reviewer: manualReviewerToken.trim() }); setManualAdminToken(''); setManualReviewerToken(''); }}>{t('connect')}</button></section></main>;

  const staged = records.filter((record) => record.publication_status === 'staged').length;
  const failed = imports.filter((run) => run.status === 'failed' || run.status === 'abandoned').length;
  return <div className="shell">
    <aside className="sidebar"><div className="brand"><div className="brand-mark">T</div><div><strong>traceless</strong><small>{t('product')}</small></div></div><nav>{(['overview','accounts','review','imports','keys'] as Tab[]).map((item) => <button key={item} className={tab === item ? 'active' : ''} onClick={() => setTab(item)}>{t(item)}</button>)}</nav><div className="sidebar-footer"><label>{t('language')}<select value={locale} onChange={(event) => setLocale(event.target.value as 'sv' | 'en')}><option value="sv">Svenska</option><option value="en">English</option></select></label><button className="button ghost" onClick={() => auth.status === 'authenticated' ? auth.signOut() : setConnectedTokens({ admin: '', reviewer: '' })}>{auth.status === 'authenticated' ? t('signOut') : t('disconnect')}</button></div></aside>
    <main className="content"><header className="topbar"><div><p className="eyebrow">TRACELESS</p><h1>{t('title')}</h1><p>{t('subtitle')}</p></div><button className="button" disabled={busy} onClick={() => void load()}>{busy ? t('loading') : t('refresh')}</button></header>{error && <div className="alert" role="alert">{error}</div>}
      {tab === 'overview' && <Overview accounts={accounts.length} installations={installations.length} staged={staged} failed={failed} activeKey={keys?.active_key_id ?? '—'} t={t} />}
      {tab === 'accounts' && <AccountsPanel accounts={accounts} installations={installations} credentials={credentials} api={api} reload={load} setCredentials={setCredentials} setSecret={setSecret} locale={locale} t={t} />}
      {tab === 'review' && <ReviewPanel records={records} api={api} reload={load} locale={locale} t={t} />}
      {tab === 'imports' && <ImportsPanel imports={imports} locale={locale} t={t} />}
      {tab === 'keys' && <KeysPanel keys={keys} locale={locale} t={t} />}
    </main>{secret && <SecretDialog secret={secret} close={() => setSecret(null)} t={t} />}
  </div>;
}

function Overview({ accounts, installations, staged, failed, activeKey, t }: { accounts: number; installations: number; staged: number; failed: number; activeKey: string; t: (key: any) => string }) {
  return <section className="metric-grid">{[[t('totalAccounts'),accounts],[t('totalInstallations'),installations],[t('stagedRecords'),staged],[t('failedImports'),failed],[t('activeKey'),activeKey]].map(([label,value]) => <article className="metric" key={String(label)}><small>{label}</small><strong>{value}</strong></article>)}</section>;
}

function AccountsPanel({ accounts, installations, credentials, api, reload, setCredentials, setSecret, locale, t }: any) {
  const [accountKey, setAccountKey] = useState(''); const [accountName, setAccountName] = useState('');
  const [selected, setSelected] = useState(accounts[0]?.account_key ?? '');
  const [form, setForm] = useState({ client_id:'', installation_key:'production', name:'Production', environment:'production' as PublisherEnvironment, region:'', max_tlp:'TLP:AMBER' as Tlp, providers:'', sourceKinds:'news,vulnerability' });
  useEffect(() => { if (!selected && accounts[0]) setSelected(accounts[0].account_key); }, [accounts, selected]);
  async function createAccount(event: FormEvent) { event.preventDefault(); await api.createAccount({ account_key: accountKey.trim(), name: accountName.trim(), enabled:true }); setAccountKey(''); setAccountName(''); await reload(); }
  async function createInstallation(event: FormEvent) { event.preventDefault(); if (!selected) throw new Error(t('accountRequired')); const result = await api.createInstallation(selected, { client_id: form.client_id.trim(), installation_key: form.installation_key.trim(), name: form.name.trim(), environment: form.environment, region: form.region.trim() || null, enabled:true, max_tlp:form.max_tlp, allowed_providers: splitValues(form.providers), allowed_source_kinds:splitValues(form.sourceKinds) }); setSecret({ label: result.installation.client_id, value: result.api_key }); await reload(); }
  async function loadCredentials(clientId:string) { const page = await api.listCredentials(clientId); setCredentials((current:any) => ({...current,[clientId]:page.items})); }
  async function rotate(clientId:string) { const result = await api.rotateCredential(clientId); setSecret({label:clientId,value:result.api_key}); await loadCredentials(clientId); }
  async function revoke(clientId:string, credentialId:string) { if (!window.confirm(t('confirmRevoke'))) return; await api.revokeCredential(clientId,credentialId); await loadCredentials(clientId); }
  return <div className="stack"><section className="panel"><header><h2>{t('createAccount')}</h2></header><form className="form-grid" onSubmit={(event) => void createAccount(event)}><label>{t('accountKey')}<input required pattern="[a-z0-9][a-z0-9._-]+" value={accountKey} onChange={e=>setAccountKey(e.target.value)} /></label><label>{t('accountName')}<input required minLength={2} value={accountName} onChange={e=>setAccountName(e.target.value)} /></label><button className="button primary">{t('create')}</button></form></section>
  <section className="panel"><header><h2>{t('createInstallation')}</h2></header><form className="form-grid" onSubmit={(event)=>void createInstallation(event)}><label>{t('accounts')}<select required value={selected} onChange={e=>setSelected(e.target.value)}><option value="">—</option>{accounts.map((account:Account)=><option key={account.id} value={account.account_key}>{account.name}</option>)}</select></label><label>{t('clientId')}<input required value={form.client_id} onChange={e=>setForm({...form,client_id:e.target.value})}/></label><label>{t('installationKey')}<input required value={form.installation_key} onChange={e=>setForm({...form,installation_key:e.target.value})}/></label><label>{t('accountName')}<input required value={form.name} onChange={e=>setForm({...form,name:e.target.value})}/></label><label>{t('environment')}<select value={form.environment} onChange={e=>setForm({...form,environment:e.target.value as PublisherEnvironment})}><option value="production">{t('production')}</option><option value="test">{t('test')}</option><option value="development">{t('development')}</option><option value="disaster_recovery">{t('disasterRecovery')}</option></select></label><label>{t('region')}<input value={form.region} onChange={e=>setForm({...form,region:e.target.value})}/></label><label>{t('maxTlp')}<select value={form.max_tlp} onChange={e=>setForm({...form,max_tlp:e.target.value as Tlp})}>{['TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT'].map(value=><option key={value}>{value}</option>)}</select></label><label>{t('providers')}<input value={form.providers} onChange={e=>setForm({...form,providers:e.target.value})} placeholder="cisa,nvd,central-analysis"/></label><label>{t('sourceKinds')}<input value={form.sourceKinds} onChange={e=>setForm({...form,sourceKinds:e.target.value})}/></label><button className="button primary">{t('create')}</button></form></section>
  <section className="panel"><header><h2>{t('totalInstallations')}</h2></header><div className="table"><div className="row head"><span>{t('clientId')}</span><span>{t('environment')}</span><span>{t('maxTlp')}</span><span>{t('lastSeen')}</span><span /></div>{installations.map((installation:Installation)=><div className="row" key={installation.id}><span><strong>{installation.name}</strong><small>{installation.client_id}</small></span><span>{installation.environment}{installation.region ? ` · ${installation.region}`:''}</span><span>{installation.max_tlp}</span><span>{formatDate(installation.last_seen_at,locale,t('never'))}</span><span className="actions"><button className="button small" onClick={()=>void loadCredentials(installation.client_id)}>{t('credentials')}</button><button className="button small" onClick={()=>void rotate(installation.client_id)}>{t('rotate')}</button></span>{credentials[installation.client_id]?.map((credential:Credential)=><div className="credential" key={credential.id}><code>v{credential.token_version} · {credential.id.slice(0,8)}</code><span>{credential.revoked_at ? t('disabled') : t('enabled')} · {formatDate(credential.expires_at,locale,t('never'))}</span>{!credential.revoked_at && <button className="button danger small" onClick={()=>void revoke(installation.client_id,credential.id)}>{t('revoke')}</button>}</div>)}</div>)}</div></section></div>;
}

function ReviewPanel({ records, api, reload, locale, t }: any) { const [reasons,setReasons]=useState<Record<string,string>>({}); const staged=records.filter((record:RecordView)=>record.publication_status==='staged'); async function decide(record:RecordView,action:'publish'|'reject'){const reason=(reasons[record.id]??'').trim(); if(reason.length<10) throw new Error(t('reasonRequired')); await api[action](record.id,reason); await reload();} return <section className="panel"><header><h2>{t('review')}</h2><span>{staged.length}</span></header>{staged.length===0?<p className="empty">{t('noData')}</p>:<div className="cards">{staged.map((record:RecordView)=><article className="record-card" key={record.id}><div><span className="tag">{record.latest_tlp}</span><span className="tag neutral">{record.source_kind}</span></div><h3>{record.title}</h3><p>{record.provider} · {record.external_id}</p><small>{formatDate(record.latest_modified_at,locale,t('never'))} · rev {record.latest_revision}</small><textarea minLength={10} placeholder={t('reason')} value={reasons[record.id]??''} onChange={e=>setReasons({...reasons,[record.id]:e.target.value})}/><div className="actions"><button className="button primary" onClick={()=>void decide(record,'publish')}>{t('publish')}</button><button className="button danger" onClick={()=>void decide(record,'reject')}>{t('reject')}</button></div></article>)}</div>}</section>; }
function ImportsPanel({ imports, locale, t }: any){return <section className="panel"><header><h2>{t('imports')}</h2></header><div className="table"><div className="row head"><span>{t('feed')}</span><span>{t('status')}</span><span>{t('items')}</span><span>{t('actor')}</span><span>{t('completed')}</span></div>{imports.map((run:ImportRun)=><div className="row" key={run.id}><span><strong>{run.feed_id}</strong><small>{run.feed_version}</small></span><span className={`status ${run.status}`}>{run.status}</span><span>{run.item_count}</span><span>{run.actor}</span><span>{formatDate(run.completed_at,locale,t('never'))}{run.error_code&&<small>{run.error_code}</small>}</span></div>)}</div></section>}
function KeysPanel({keys,locale,t}:any){return <section className="panel"><header><h2>{t('keys')}</h2>{keys&&<span>{keys.active_key_id}</span>}</header>{!keys?<p className="empty">{t('noData')}</p>:<div className="cards">{keys.keys.map((key:any)=><article className="key-card" key={key.key_id}><span className={`status ${key.status}`}>{key.status}</span><h3>{key.key_id}</h3><dl><div><dt>{t('fingerprint')}</dt><dd><code>{key.fingerprint_sha256}</code></dd></div><div><dt>{t('validFrom')}</dt><dd>{formatDate(key.not_before,locale,t('never'))}</dd></div><div><dt>{t('validTo')}</dt><dd>{formatDate(key.not_after,locale,t('never'))}</dd></div></dl></article>)}</div>}</section>}
function SecretDialog({secret,close,t}:any){const[copied,setCopied]=useState(false);return <div className="modal-backdrop"><section className="modal" role="dialog" aria-modal="true"><h2>{t('oneTimeKey')}</h2><p>{secret.label}</p><code className="secret">{secret.value}</code><p>{t('serviceTokenHint')}</p><div className="actions"><button className="button primary" onClick={()=>void navigator.clipboard.writeText(secret.value).then(()=>setCopied(true))}>{copied?t('copied'):t('copy')}</button><button className="button" onClick={close}>OK</button></div></section></div>}

export function AppShell({ fetchImpl }: { fetchImpl?: typeof fetch }) { return <PublisherWorkspace fetchImpl={fetchImpl} />; }
export default function App({ oidcConfiguration, oidcDependencies, fetchImpl }: AppProps) { return <I18nProvider><OidcAuthProvider configuration={oidcConfiguration ?? readOidcConfiguration()} dependencies={oidcDependencies}><AppShell fetchImpl={fetchImpl} /></OidcAuthProvider></I18nProvider>; }
