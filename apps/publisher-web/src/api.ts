export type PublisherEnvironment = 'production' | 'test' | 'development' | 'disaster_recovery';
export type Tlp = 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:AMBER+STRICT';

export interface Page<T> { items: T[]; total: number; limit: number; offset: number }
export interface Account { id: string; account_key: string; name: string; enabled: boolean; created_at: string; updated_at: string }
export interface Installation {
  id: string; account_id: string; client_id: string; installation_key: string;
  environment: PublisherEnvironment; region: string | null; name: string; enabled: boolean;
  max_tlp: string; entitlement_epoch: number; reset_generation: number;
  created_at: string; updated_at: string; last_seen_at: string | null;
}
export interface InstallationCredential { installation: Installation; api_key: string }
export interface Credential { id: string; token_version: number; not_before: string; expires_at: string | null; revoked_at: string | null; created_by: string; created_at: string }
export interface RecordView {
  id: string; provider: string; external_id: string; source_kind: string; record_type: string;
  title: string; latest_revision: number; latest_modified_at: string; latest_status: string;
  latest_tlp: string; publication_status: string; payload_sha256: string; created_at: string; updated_at: string;
}
export interface ImportRun {
  id: string; feed_id: string; feed_version: string; generated_at: string; item_count: number;
  manifest_sha256: string; status: 'running' | 'completed' | 'failed' | 'abandoned'; actor: string;
  heartbeat_at: string; lease_expires_at: string | null; attempt_count: number;
  error_code: string | null; result: Record<string, unknown> | null; created_at: string; completed_at: string | null;
}
export interface Decision { id: string; record_id: string; revision_id: string; decision: string; actor: string; reason: string; created_at: string }
export interface SigningKey { algorithm: 'Ed25519'; key_id: string; public_key_base64: string; fingerprint_sha256: string; status: string; not_before: string; not_after: string | null }
export interface SigningKeySet { schema_version: '1.0'; generated_at: string; active_key_id: string; keys: SigningKey[] }

export type PublisherSurface = 'admin' | 'ingest' | 'review' | 'feed';
interface ApiOptions { getToken(surface: PublisherSurface): string | null; fetchImpl?: typeof fetch }

function _surfaceName(surface: string): PublisherSurface {
  if (surface.includes('admin')) return 'admin';
  if (surface.includes('ingest')) return 'ingest';
  if (surface.includes('review')) return 'review';
  return 'feed';
}

export class PublisherApiError extends Error { constructor(public status: number, message: string) { super(message) } }

export function createPublisherApi({ getToken, fetchImpl = fetch }: ApiOptions) {
  async function request<T>(surface: string, path: string, init: RequestInit = {}): Promise<T> {
    const token = getToken(_surfaceName(surface));
    const headers = new Headers(init.headers);
    headers.set('Accept', 'application/json');
    if (init.body) headers.set('Content-Type', 'application/json');
    if (token) headers.set('Authorization', `Bearer ${token}`);
    const response = await fetchImpl(`${surface}${path}`, { ...init, headers });
    const text = await response.text();
    let body: unknown = null;
    if (text) {
      try { body = JSON.parse(text); } catch { body = text; }
    }
    if (!response.ok) {
      const detail = typeof body === 'object' && body !== null && 'detail' in body
        ? String((body as { detail: unknown }).detail)
        : `Publisher request failed (${response.status}).`;
      throw new PublisherApiError(response.status, detail);
    }
    return body as T;
  }

  return {
    listAccounts: () => request<Page<Account>>('/publisher-admin', '/admin/v2/accounts?limit=200&offset=0'),
    createAccount: (payload: { account_key: string; name: string; enabled: boolean }) => request<Account>('/publisher-admin', '/admin/v2/accounts', { method: 'POST', body: JSON.stringify(payload) }),
    listInstallations: () => request<Page<Installation>>('/publisher-admin', '/admin/v1/installations?limit=200&offset=0'),
    createInstallation: (accountKey: string, payload: { client_id: string; installation_key: string; name: string; environment: PublisherEnvironment; region: string | null; enabled: boolean; max_tlp: Tlp; allowed_providers: string[]; allowed_source_kinds: string[] }) => request<InstallationCredential>('/publisher-admin', `/admin/v2/accounts/${encodeURIComponent(accountKey)}/installations`, { method: 'POST', body: JSON.stringify(payload) }),
    listCredentials: (clientId: string) => request<Page<Credential>>('/publisher-admin', `/admin/v1/clients/${encodeURIComponent(clientId)}/credentials?limit=200&offset=0`),
    rotateCredential: (clientId: string) => request<{ api_key: string }>('/publisher-admin', `/admin/v2/installations/${encodeURIComponent(clientId)}/rotate-key`, { method: 'POST' }),
    revokeCredential: (clientId: string, credentialId: string) => request<Credential>('/publisher-admin', `/admin/v1/clients/${encodeURIComponent(clientId)}/credentials/${encodeURIComponent(credentialId)}`, { method: 'DELETE' }),
    listImports: () => request<Page<ImportRun>>('/publisher-admin', '/admin/v1/imports?limit=200&offset=0'),
    listRecords: () => request<Page<RecordView>>('/publisher-review', '/admin/v1/records?limit=200&offset=0'),
    listDecisions: (recordId: string) => request<Page<Decision>>('/publisher-review', `/admin/v1/records/${encodeURIComponent(recordId)}/decisions?limit=200&offset=0`),
    publish: (recordId: string, reason: string) => request<unknown>('/publisher-review', `/admin/v1/records/${encodeURIComponent(recordId)}/publish`, { method: 'POST', body: JSON.stringify({ reason }) }),
    reject: (recordId: string, reason: string) => request<unknown>('/publisher-review', `/admin/v1/records/${encodeURIComponent(recordId)}/reject`, { method: 'POST', body: JSON.stringify({ reason }) }),
    signingKeys: () => request<SigningKeySet>('/publisher-feed', '/.well-known/traceless-intelligence-signing-keys'),
  };
}
export type PublisherApi = ReturnType<typeof createPublisherApi>;
