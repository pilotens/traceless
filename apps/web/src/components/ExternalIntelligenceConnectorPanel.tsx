import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';

import type {
  ExternalIntelligenceConnectorUpdate,
  ExternalIntelligenceConnectorView,
  ExternalIntelligencePullResult,
  ExternalIntelligenceSyncRun,
  ExternalIntelligenceSyncRunList,
  ExternalIntelligenceSyncStatus,
  OperationalApi,
} from '../api';
import { OperationalApiError } from '../api';
import { Icon } from './Icon';

const DEFAULT_MAX_PAGES = 10;
const RUN_PAGE_SIZE = 10;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Ett oväntat fel inträffade.';
}

function formatDate(value: string | null | undefined): string {
  if (!value) return 'Ej tillgängligt';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Ogiltig tidpunkt';
  return new Intl.DateTimeFormat('sv-SE', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

function runStatusLabel(status: ExternalIntelligenceSyncRun['status']) {
  return {
    running: 'Pågår',
    partial: 'Delvis hämtad',
    completed: 'Slutförd',
    failed: 'Misslyckad',
    quarantined: 'Karantän',
  }[status];
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function scheduleLabel(status: ExternalIntelligenceSyncStatus): string {
  if (!status.configured) return 'Inte konfigurerad';
  return {
    manual: 'Endast manuell',
    disabled: 'Inaktiverad',
    scheduled: 'Schemalagd',
    due: 'Inväntar worker',
  }[status.schedule_state ?? 'manual'];
}

interface ExternalIntelligenceConnectorPanelProps {
  api: OperationalApi;
  canAdminister: boolean;
  canSync: boolean;
  onSynced: (result: ExternalIntelligencePullResult) => Promise<void>;
}

export function ExternalIntelligenceConnectorPanel({
  api,
  canAdminister,
  canSync,
  onSynced,
}: ExternalIntelligenceConnectorPanelProps) {
  const [connector, setConnector] = useState<ExternalIntelligenceConnectorView | null>(null);
  const [status, setStatus] = useState<ExternalIntelligenceSyncStatus | null>(null);
  const [runPage, setRunPage] = useState<ExternalIntelligenceSyncRunList>({
    items: [],
    total: 0,
    limit: RUN_PAGE_SIZE,
    offset: 0,
  });
  const [endpoint, setEndpoint] = useState('');
  const [authScheme, setAuthScheme] = useState<'Bearer' | 'X-API-Key'>('Bearer');
  const [credentialReference, setCredentialReference] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [syncIntervalMinutes, setSyncIntervalMinutes] = useState('');
  const [busy, setBusy] = useState<'load' | 'save' | 'sync' | null>('load');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  function applyConnector(nextConnector: ExternalIntelligenceConnectorView): void {
    setConnector(nextConnector);
    setEndpoint(nextConnector.endpoint);
    setAuthScheme(nextConnector.auth_scheme);
    setCredentialReference(nextConnector.credential_reference);
    setEnabled(nextConnector.enabled);
    setSyncIntervalMinutes(
      nextConnector.sync_interval_seconds === null
        ? ''
        : String(nextConnector.sync_interval_seconds / 60),
    );
  }

  async function loadStatus(): Promise<ExternalIntelligenceSyncStatus> {
    const nextStatus = await api.getExternalIntelligenceSyncStatus();
    setStatus(nextStatus);
    return nextStatus;
  }

  async function loadRunPage(offset: number): Promise<ExternalIntelligenceSyncRunList> {
    const page = await api.listExternalIntelligenceSyncRuns({
      limit: RUN_PAGE_SIZE,
      offset,
    });
    setRunPage(page);
    return page;
  }

  useEffect(() => {
    let active = true;
    setBusy('load');
    setError(null);
    const requests: Array<Promise<unknown>> = [
      api.getExternalIntelligenceSyncStatus().then((nextStatus) => {
        if (active) setStatus(nextStatus);
      }),
      api.listExternalIntelligenceSyncRuns({ limit: RUN_PAGE_SIZE, offset: 0 }).then((page) => {
        if (active) setRunPage(page);
      }),
    ];
    if (canAdminister) {
      requests.push(
        api
          .getExternalIntelligenceConnector()
          .then((nextConnector) => {
            if (active) applyConnector(nextConnector);
          })
          .catch((reason: unknown) => {
            if (reason instanceof OperationalApiError && reason.status === 404) return;
            throw reason;
          }),
      );
    }
    Promise.all(requests)
      .catch((reason: unknown) => {
        if (active) setError(errorMessage(reason));
      })
      .finally(() => {
        if (active) setBusy(null);
      });
    return () => {
      active = false;
    };
  }, [api, canAdminister]);

  function handleSave(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const interval = syncIntervalMinutes.trim();
    const normalizedEndpoint = endpoint.trim();
    if (!normalizedEndpoint.startsWith('https://')) {
      setError('Connectorns endpoint måste använda HTTPS.');
      setNotice(null);
      return;
    }
    const payload: ExternalIntelligenceConnectorUpdate = {
      endpoint: normalizedEndpoint,
      auth_scheme: authScheme,
      credential_reference: credentialReference.trim(),
      enabled,
      sync_interval_seconds: interval ? Math.round(Number(interval) * 60) : null,
    };
    setBusy('save');
    setError(null);
    setNotice(null);
    api
      .configureExternalIntelligenceConnector(payload)
      .then(async (nextConnector) => {
        applyConnector(nextConnector);
        await loadStatus();
        setNotice('Connectorinställningen sparades för organisationen.');
      })
      .catch((reason: unknown) => setError(errorMessage(reason)))
      .finally(() => setBusy(null));
  }

  function handleSync(): void {
    setBusy('sync');
    setError(null);
    setNotice(null);
    api
      .syncExternalIntelligence(DEFAULT_MAX_PAGES)
      .then(async (result) => {
        await Promise.all([loadStatus(), loadRunPage(0), onSynced(result)]);
        setNotice(
          result.complete
            ? `Synkningen slutfördes: ${result.records_fetched} poster och ${result.correlation_jobs_queued} korrelationsjobb köades.`
            : `En begränsad del hämtades. Beständig checkpoint finns för fortsatt synkning.`,
        );
      })
      .catch((reason: unknown) => setError(errorMessage(reason)))
      .finally(() => setBusy(null));
  }

  function handleRunPage(offset: number): void {
    setBusy('load');
    setError(null);
    loadRunPage(offset)
      .catch((reason: unknown) => setError(errorMessage(reason)))
      .finally(() => setBusy(null));
  }

  const latestRun = status?.latest_run ?? null;

  return (
    <section className="op-connector" aria-label="Extern datapunktsconnector">
      <header className="op-section-heading">
        <div>
          <span className="section-kicker">SEPARAT INSAMLINGSPROGRAM</span>
          <h3>Extern datapunktsconnector</h3>
        </div>
        <small>
          Traceless hämtar endast normaliserade datapunkter. Scraping och källinsamling sker i
          det separata programmet.
        </small>
      </header>

      {error && <div className="op-feedback op-feedback--error" role="alert"><Icon name="alert" size={16} /> {error}</div>}
      {notice && <div className="op-feedback op-feedback--success" role="status"><Icon name="check" size={16} /> {notice}</div>}

      <div className="op-connector__status">
        <div>
          <span className={`op-status-dot op-status-dot--${latestRun?.status === 'failed' ? 'failed' : latestRun?.status === 'running' ? 'running' : 'completed'}`} />
          <span>
            <strong>{status ? scheduleLabel(status) : 'Läser status…'}</strong>
            <small>
              {status?.configured
                ? `${status.endpoint ?? 'Endpoint dold'} · credential ${status.credential_available ? 'tillgänglig' : 'saknas'}`
                : 'Ingen connector har registrerats för organisationen.'}
            </small>
          </span>
        </div>
        <dl>
          <div><dt>Nästa körning</dt><dd>{formatDate(status?.next_sync_at)}</dd></div>
          <div>
            <dt>Checkpoint</dt>
            <dd>
              {status?.checkpoint
                ? `${status.checkpoint.records_completed} poster · ${formatBytes(status.checkpoint.bytes_completed)}`
                : 'Saknas'}
            </dd>
          </div>
          <div><dt>Konfigurationsversion</dt><dd>{status?.config_version ?? '–'}</dd></div>
        </dl>
      </div>

      <details className="op-connector__run" open>
        <summary>Körstatus och beständig historik</summary>
        {runPage.items.length === 0 ? (
          <p>Ingen beständig synkkörning finns ännu.</p>
        ) : (
          <div className="op-connector__runs">
            {runPage.items.map((run) => (
              <article key={run.id}>
                <span className={`op-status-dot op-status-dot--${run.status === 'failed' || run.status === 'quarantined' ? 'failed' : run.status === 'running' || run.status === 'partial' ? 'running' : 'completed'}`} />
                <span>
                  <strong>{runStatusLabel(run.status)} · {run.feed_id ?? 'Okänd feed'}</strong>
                  <small>{formatDate(run.started_at)} · {run.records_fetched} poster · {formatBytes(run.bytes_fetched)}</small>
                </span>
                <span>
                  <strong>{run.created_count} / {run.updated_count} / {run.quarantined_count}</strong>
                  <small>skapade / uppdaterade / karantän</small>
                </span>
                {run.error_code && <small role="alert">{run.error_code}</small>}
              </article>
            ))}
          </div>
        )}
        {runPage.total > runPage.limit && (
          <nav className="op-pagination" aria-label="Synkhistorik">
            <button
              className="secondary-button"
              disabled={busy !== null || runPage.offset === 0}
              onClick={() => handleRunPage(Math.max(0, runPage.offset - runPage.limit))}
              type="button"
            >
              Föregående
            </button>
            <span>{runPage.offset + 1}–{Math.min(runPage.offset + runPage.items.length, runPage.total)} av {runPage.total}</span>
            <button
              className="secondary-button"
              disabled={busy !== null || runPage.offset + runPage.items.length >= runPage.total}
              onClick={() => handleRunPage(runPage.offset + runPage.limit)}
              type="button"
            >
              Nästa
            </button>
          </nav>
        )}
      </details>

      {canAdminister && (
        <details className="op-connector__configuration" open={!connector}>
          <summary>{connector ? 'Redigera tenantkonfiguration' : 'Konfigurera connector'}</summary>
          <form className="op-form-grid" onSubmit={handleSave}>
            <label className="op-form-grid__wide">
              <span>Fast HTTPS-endpoint</span>
              <input
                aria-label="Extern datapunktsendpoint"
                maxLength={2000}
                minLength={12}
                placeholder="https://intel.example.test/api/datapoints"
                required
                type="url"
                value={endpoint}
                onChange={(event) => setEndpoint(event.target.value)}
              />
            </label>
            <label>
              <span>Autentiseringsschema</span>
              <select value={authScheme} onChange={(event) => setAuthScheme(event.target.value as typeof authScheme)}>
                <option value="Bearer">Bearer</option>
                <option value="X-API-Key">X-API-Key</option>
              </select>
            </label>
            <label>
              <span>Credential-referens</span>
              <input
                aria-label="Credential-referens"
                pattern="[A-Za-z0-9][A-Za-z0-9._:/-]*"
                required
                value={credentialReference}
                onChange={(event) => setCredentialReference(event.target.value)}
              />
            </label>
            <label>
              <span>Intervall i minuter (tomt = manuellt)</span>
              <input
                aria-label="Synkintervall i minuter"
                min="1"
                max="43200"
                step="1"
                type="number"
                value={syncIntervalMinutes}
                onChange={(event) => setSyncIntervalMinutes(event.target.value)}
              />
            </label>
            <label className="op-confirmation">
              <input checked={enabled} onChange={(event) => setEnabled(event.target.checked)} type="checkbox" />
              <span>Connectorn är aktiverad</span>
            </label>
            <button className="secondary-button" disabled={busy !== null} type="submit">
              Spara connector
            </button>
          </form>
          <p className="op-caveat">Credential-värdet matas aldrig in i webbläsaren; endast referensen sparas.</p>
        </details>
      )}

      {canSync && status?.configured && status.enabled && (
        <button className="secondary-button" disabled={busy !== null} onClick={handleSync} type="button">
          <Icon name="history" size={15} /> {busy === 'sync' ? 'Synkar…' : 'Synka normaliserade datapunkter'}
        </button>
      )}
      {!canSync && status?.configured && status.enabled && (
        <p className="op-caveat">
          Manuell synk och tenantgemensam granskning kräver en organisationsomfattande
          analytiker- eller administratörsidentitet.
        </p>
      )}
    </section>
  );
}
