import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import type { ReactNode } from 'react';

const TRANSACTION_MAX_AGE_MS = 10 * 60 * 1000;
export const OIDC_TRANSACTION_STORAGE_KEY = 'traceless.oidc.transaction';

export interface OidcConfig {
  authorizationUrl: string;
  tokenUrl: string;
  clientId: string;
  redirectUri: string;
  scopes: string;
}

export type OidcConfiguration =
  | { mode: 'disabled' }
  | { mode: 'invalid'; message: string }
  | { mode: 'configured'; config: OidcConfig };

interface OidcTransaction {
  state: string;
  verifier: string;
  createdAt: number;
}

interface TokenResult {
  accessToken: string;
  expiresIn: number | null;
}

export type OidcAuthStatus =
  | 'disabled'
  | 'checking'
  | 'signed_out'
  | 'redirecting'
  | 'authenticated'
  | 'error';

interface OidcAuthContextValue {
  status: OidcAuthStatus;
  enabled: boolean;
  canSignIn: boolean;
  accessToken: string | null;
  errorMessage: string | null;
  signIn(): Promise<void>;
  signOut(): void;
}

export interface OidcAuthDependencies {
  fetchImpl?: typeof fetch;
  cryptoImpl?: Crypto;
  storage?: Storage;
  getLocationHref?: () => string;
  replaceLocation?: (url: string) => void;
  navigate?: (url: string) => void;
  now?: () => number;
}

interface OidcAuthProviderProps {
  children: ReactNode;
  configuration?: OidcConfiguration;
  dependencies?: OidcAuthDependencies;
}

const OidcAuthContext = createContext<OidcAuthContextValue | null>(null);

function configuredValue(
  env: Record<string, string | boolean | undefined>,
  key: string,
): string {
  const value = env[key];
  return typeof value === 'string' ? value.trim() : '';
}

function isSecureBrowserUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    if (parsed.protocol === 'https:') return true;
    return (
      parsed.protocol === 'http:' &&
      (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')
    );
  } catch {
    return false;
  }
}

export function readOidcConfiguration(
  env: Record<string, string | boolean | undefined> = import.meta.env,
): OidcConfiguration {
  const values = {
    authorizationUrl: configuredValue(env, 'VITE_OIDC_AUTHORIZATION_URL'),
    tokenUrl: configuredValue(env, 'VITE_OIDC_TOKEN_URL'),
    clientId: configuredValue(env, 'VITE_OIDC_CLIENT_ID'),
    redirectUri: configuredValue(env, 'VITE_OIDC_REDIRECT_URI'),
    scopes: configuredValue(env, 'VITE_OIDC_SCOPES'),
  };
  const entries = Object.entries(values);
  if (entries.every(([, value]) => value === '')) return { mode: 'disabled' };

  const missing = entries.filter(([, value]) => value === '').map(([key]) => key);
  if (missing.length > 0) {
    return {
      mode: 'invalid',
      message: `OIDC-konfigurationen saknar: ${missing.join(', ')}.`,
    };
  }
  if (
    !isSecureBrowserUrl(values.authorizationUrl) ||
    !isSecureBrowserUrl(values.tokenUrl) ||
    !isSecureBrowserUrl(values.redirectUri)
  ) {
    return {
      mode: 'invalid',
      message: 'OIDC-adresser måste använda HTTPS (HTTP tillåts endast för localhost).',
    };
  }
  if (!values.scopes.split(/\s+/).includes('openid')) {
    return { mode: 'invalid', message: 'VITE_OIDC_SCOPES måste innehålla openid.' };
  }
  return { mode: 'configured', config: values };
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomValue(byteLength: number, cryptoImpl: Crypto): string {
  const bytes = new Uint8Array(byteLength);
  cryptoImpl.getRandomValues(bytes);
  return base64Url(bytes);
}

async function pkceChallenge(verifier: string, cryptoImpl: Crypto): Promise<string> {
  const digest = await cryptoImpl.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(verifier),
  );
  return base64Url(new Uint8Array(digest));
}

export async function createAuthorizationRequest(
  config: OidcConfig,
  options: Pick<OidcAuthDependencies, 'cryptoImpl' | 'storage' | 'now'> = {},
): Promise<string> {
  const cryptoImpl = options.cryptoImpl ?? globalThis.crypto;
  const storage = options.storage ?? window.sessionStorage;
  const now = options.now ?? Date.now;
  if (!cryptoImpl?.subtle) throw new Error('WebCrypto krävs för säker OIDC-inloggning.');

  const state = randomValue(32, cryptoImpl);
  const verifier = randomValue(64, cryptoImpl);
  const challenge = await pkceChallenge(verifier, cryptoImpl);
  const transaction: OidcTransaction = { state, verifier, createdAt: now() };
  storage.setItem(OIDC_TRANSACTION_STORAGE_KEY, JSON.stringify(transaction));

  const url = new URL(config.authorizationUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', config.redirectUri);
  url.searchParams.set('scope', config.scopes);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

function callbackTargetsRedirect(config: OidcConfig, locationHref: string): boolean {
  const callback = new URL(locationHref);
  const redirect = new URL(config.redirectUri);
  return callback.origin === redirect.origin && callback.pathname === redirect.pathname;
}

export function hasOidcCallback(config: OidcConfig, locationHref: string): boolean {
  if (!callbackTargetsRedirect(config, locationHref)) return false;
  const parameters = new URL(locationHref).searchParams;
  return parameters.has('code') || parameters.has('error');
}

export function oidcCallbackCleanupUrl(locationHref: string): string {
  const url = new URL(locationHref);
  for (const key of [
    'code',
    'state',
    'error',
    'error_description',
    'error_uri',
    'session_state',
    'iss',
  ]) {
    url.searchParams.delete(key);
  }
  return `${url.pathname}${url.search}${url.hash}`;
}

function readTransaction(storage: Storage, now: () => number): OidcTransaction {
  const serialized = storage.getItem(OIDC_TRANSACTION_STORAGE_KEY);
  storage.removeItem(OIDC_TRANSACTION_STORAGE_KEY);
  if (!serialized) throw new Error('Inloggningen saknar en giltig OIDC-transaktion.');

  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch {
    throw new Error('OIDC-transaktionen kunde inte valideras.');
  }
  if (
    typeof value !== 'object' ||
    value === null ||
    !('state' in value) ||
    typeof value.state !== 'string' ||
    !('verifier' in value) ||
    typeof value.verifier !== 'string' ||
    value.verifier.length < 43 ||
    value.verifier.length > 128 ||
    !('createdAt' in value) ||
    typeof value.createdAt !== 'number' ||
    now() - value.createdAt < 0 ||
    now() - value.createdAt > TRANSACTION_MAX_AGE_MS
  ) {
    throw new Error('OIDC-transaktionen är ogiltig eller har löpt ut.');
  }
  return value as OidcTransaction;
}

function oauthErrorMessage(body: unknown, status: number): string {
  if (typeof body === 'object' && body !== null && 'error_description' in body) {
    const description = body.error_description;
    if (typeof description === 'string' && description.trim()) {
      return description.trim().slice(0, 300);
    }
  }
  return `Tokenutbytet misslyckades (${status}).`;
}

export async function completeAuthorizationCallback(
  config: OidcConfig,
  locationHref: string,
  options: Pick<OidcAuthDependencies, 'fetchImpl' | 'storage' | 'now'> = {},
): Promise<TokenResult> {
  if (!callbackTargetsRedirect(config, locationHref)) {
    throw new Error('OIDC-svaret skickades till fel redirect-adress.');
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  const storage = options.storage ?? window.sessionStorage;
  const now = options.now ?? Date.now;
  const parameters = new URL(locationHref).searchParams;
  const transaction = readTransaction(storage, now);
  const returnedState = parameters.get('state');
  if (!returnedState || returnedState !== transaction.state) {
    throw new Error('OIDC state-valideringen misslyckades.');
  }

  const oauthError = parameters.get('error');
  if (oauthError) {
    const description = parameters.get('error_description');
    throw new Error((description || oauthError).slice(0, 300));
  }
  const code = parameters.get('code');
  if (!code) throw new Error('OIDC-svaret saknar authorization code.');

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    code_verifier: transaction.verifier,
  });
  const response = await fetchImpl(config.tokenUrl, {
    method: 'POST',
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    },
    body,
  });

  let tokenBody: unknown;
  try {
    tokenBody = await response.json();
  } catch {
    tokenBody = null;
  }
  if (!response.ok) throw new Error(oauthErrorMessage(tokenBody, response.status));
  if (
    typeof tokenBody !== 'object' ||
    tokenBody === null ||
    !('access_token' in tokenBody) ||
    typeof tokenBody.access_token !== 'string' ||
    !tokenBody.access_token
  ) {
    throw new Error('Token-svaret saknar access token.');
  }
  if (
    'token_type' in tokenBody &&
    (typeof tokenBody.token_type !== 'string' || tokenBody.token_type.toLowerCase() !== 'bearer')
  ) {
    throw new Error('Token-svaret använder en token-typ som inte stöds.');
  }
  const expiresIn =
    'expires_in' in tokenBody &&
    typeof tokenBody.expires_in === 'number' &&
    Number.isFinite(tokenBody.expires_in) &&
    tokenBody.expires_in > 0
      ? tokenBody.expires_in
      : null;

  // Deliberately return only the access token. A refresh_token in the response is ignored.
  return { accessToken: tokenBody.access_token, expiresIn };
}

function initialStatus(configuration: OidcConfiguration, locationHref: string): OidcAuthStatus {
  if (configuration.mode === 'disabled') return 'disabled';
  if (configuration.mode === 'invalid') return 'error';
  return hasOidcCallback(configuration.config, locationHref) ? 'checking' : 'signed_out';
}

export function OidcAuthProvider({
  children,
  configuration: configurationProp,
  dependencies = {},
}: OidcAuthProviderProps) {
  const configuration = useMemo(
    () => configurationProp ?? readOidcConfiguration(),
    [configurationProp],
  );
  const getLocationHref = dependencies.getLocationHref ?? (() => window.location.href);
  const replaceLocation =
    dependencies.replaceLocation ??
    ((url: string) => window.history.replaceState(window.history.state, '', url));
  const navigate = dependencies.navigate ?? ((url: string) => window.location.assign(url));
  const storage = dependencies.storage ?? window.sessionStorage;
  const [status, setStatus] = useState<OidcAuthStatus>(() =>
    initialStatus(configuration, getLocationHref()),
  );
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(
    configuration.mode === 'invalid' ? configuration.message : null,
  );
  const callbackHandled = useRef(false);

  useEffect(() => {
    if (configuration.mode !== 'configured' || callbackHandled.current) return;
    const locationHref = getLocationHref();
    if (!hasOidcCallback(configuration.config, locationHref)) return;
    callbackHandled.current = true;
    replaceLocation(oidcCallbackCleanupUrl(locationHref));

    void completeAuthorizationCallback(configuration.config, locationHref, {
      fetchImpl: dependencies.fetchImpl,
      storage,
      now: dependencies.now,
    })
      .then((result) => {
        setAccessToken(result.accessToken);
        setExpiresAt(result.expiresIn ? Date.now() + result.expiresIn * 1000 : null);
        setErrorMessage(null);
        setStatus('authenticated');
      })
      .catch((error: unknown) => {
        setAccessToken(null);
        setExpiresAt(null);
        setErrorMessage(error instanceof Error ? error.message : 'Inloggningen misslyckades.');
        setStatus('error');
      });
  }, [configuration, dependencies.fetchImpl, dependencies.now, getLocationHref, replaceLocation, storage]);

  useEffect(() => {
    if (status !== 'authenticated' || expiresAt === null) return;
    const remaining = expiresAt - Date.now();
    if (remaining <= 0) {
      setAccessToken(null);
      setExpiresAt(null);
      setStatus('signed_out');
      return;
    }
    const timer = window.setTimeout(() => {
      setAccessToken(null);
      setExpiresAt(null);
      setStatus('signed_out');
    }, Math.min(remaining, 2_147_483_647));
    return () => window.clearTimeout(timer);
  }, [expiresAt, status]);

  const signIn = useCallback(async () => {
    if (configuration.mode !== 'configured') return;
    setStatus('redirecting');
    setErrorMessage(null);
    try {
      const url = await createAuthorizationRequest(configuration.config, {
        cryptoImpl: dependencies.cryptoImpl,
        storage,
        now: dependencies.now,
      });
      navigate(url);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Inloggningen kunde inte startas.');
      setStatus('error');
    }
  }, [configuration, dependencies.cryptoImpl, dependencies.now, navigate, storage]);

  const signOut = useCallback(() => {
    storage.removeItem(OIDC_TRANSACTION_STORAGE_KEY);
    setAccessToken(null);
    setExpiresAt(null);
    setErrorMessage(null);
    setStatus(configuration.mode === 'disabled' ? 'disabled' : 'signed_out');
  }, [configuration.mode, storage]);

  const value = useMemo<OidcAuthContextValue>(
    () => ({
      status,
      enabled: configuration.mode !== 'disabled',
      canSignIn: configuration.mode === 'configured',
      accessToken,
      errorMessage,
      signIn,
      signOut,
    }),
    [accessToken, configuration.mode, errorMessage, signIn, signOut, status],
  );

  return <OidcAuthContext.Provider value={value}>{children}</OidcAuthContext.Provider>;
}

export function useOidcAuth(): OidcAuthContextValue {
  const context = useContext(OidcAuthContext);
  if (!context) throw new Error('useOidcAuth måste användas inom OidcAuthProvider.');
  return context;
}
