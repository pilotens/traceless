import { beforeEach, describe, expect, test, vi } from 'vitest';

import {
  OIDC_TRANSACTION_STORAGE_KEY,
  completeAuthorizationCallback,
  createAuthorizationRequest,
  oidcCallbackCleanupUrl,
  readOidcConfiguration,
  type OidcConfig,
} from './auth';

const config: OidcConfig = {
  authorizationUrl: 'https://identity.example.test/oauth2/authorize',
  tokenUrl: 'https://identity.example.test/oauth2/token',
  clientId: 'traceless-web',
  redirectUri: 'https://app.example.test/auth/callback',
  scopes: 'openid profile api://traceless/access',
};

describe('OIDC Authorization Code + PKCE', () => {
  beforeEach(() => window.sessionStorage.clear());

  test('is disabled only when no OIDC variables are present and rejects partial configuration', () => {
    expect(readOidcConfiguration({})).toEqual({ mode: 'disabled' });
    expect(
      readOidcConfiguration({ VITE_OIDC_CLIENT_ID: 'traceless-web' }),
    ).toMatchObject({ mode: 'invalid' });
    expect(
      readOidcConfiguration({
        VITE_OIDC_AUTHORIZATION_URL: config.authorizationUrl,
        VITE_OIDC_TOKEN_URL: config.tokenUrl,
        VITE_OIDC_CLIENT_ID: config.clientId,
        VITE_OIDC_REDIRECT_URI: config.redirectUri,
        VITE_OIDC_SCOPES: config.scopes,
      }),
    ).toEqual({ mode: 'configured', config });
  });

  test('creates an S256 request and stores only the short-lived PKCE transaction', async () => {
    const authorizationUrl = await createAuthorizationRequest(config, {
      storage: window.sessionStorage,
      now: () => 1_000,
    });
    const url = new URL(authorizationUrl);
    const transaction = JSON.parse(
      window.sessionStorage.getItem(OIDC_TRANSACTION_STORAGE_KEY) ?? '{}',
    ) as Record<string, unknown>;

    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe(config.clientId);
    expect(url.searchParams.get('redirect_uri')).toBe(config.redirectUri);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(url.searchParams.get('state')).toBe(transaction.state);
    expect(transaction.verifier).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(transaction).not.toHaveProperty('access_token');
    expect(transaction).not.toHaveProperty('refresh_token');
  });

  test('validates state, exchanges the code once and discards refresh tokens', async () => {
    const authorizationUrl = await createAuthorizationRequest(config, {
      storage: window.sessionStorage,
      now: () => 1_000,
    });
    const state = new URL(authorizationUrl).searchParams.get('state');
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'access-token-value',
          refresh_token: 'must-not-be-retained',
          token_type: 'Bearer',
          expires_in: 900,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    const result = await completeAuthorizationCallback(
      config,
      `${config.redirectUri}?code=one-time-code&state=${encodeURIComponent(state ?? '')}`,
      { fetchImpl: fetchMock as typeof fetch, storage: window.sessionStorage, now: () => 1_001 },
    );

    expect(result).toEqual({ accessToken: 'access-token-value', expiresIn: 900 });
    expect(result).not.toHaveProperty('refreshToken');
    expect(window.sessionStorage.getItem(OIDC_TRANSACTION_STORAGE_KEY)).toBeNull();
    const [tokenUrl, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(tokenUrl).toBe(config.tokenUrl);
    expect(init.credentials).toBe('omit');
    const body = init.body as URLSearchParams;
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('one-time-code');
    expect(body.get('code_verifier')).toHaveLength(86);
    expect(body.has('client_secret')).toBe(false);
  });

  test('rejects a state mismatch before contacting the token endpoint', async () => {
    await createAuthorizationRequest(config, {
      storage: window.sessionStorage,
      now: () => 1_000,
    });
    const fetchMock = vi.fn();

    await expect(
      completeAuthorizationCallback(
        config,
        `${config.redirectUri}?code=code&state=attacker-state`,
        { fetchImpl: fetchMock as typeof fetch, storage: window.sessionStorage, now: () => 1_001 },
      ),
    ).rejects.toThrow('state-valideringen');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem(OIDC_TRANSACTION_STORAGE_KEY)).toBeNull();
  });

  test('removes OAuth response parameters without removing application parameters', () => {
    expect(
      oidcCallbackCleanupUrl(
        'https://app.example.test/auth/callback?view=risks&code=secret&state=random#finding',
      ),
    ).toBe('/auth/callback?view=risks#finding');
  });
});
