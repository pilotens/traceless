import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, test, vi } from 'vitest';

import App from './App';
import { OIDC_TRANSACTION_STORAGE_KEY, type OidcConfiguration } from './auth';

afterEach(() => {
  window.sessionStorage.clear();
  window.history.replaceState({}, '', '/');
  vi.unstubAllGlobals();
});

describe('Traceless application shell', () => {
  test('opens directly in the operational product workspace', () => {
    render(<App />);

    expect(screen.getByRole('heading', { name: 'Säkerhetsöversikt' })).toBeInTheDocument();
    expect(screen.getByText('Auktoriserad användning krävs')).toBeInTheDocument();
    expect(screen.getByText('OPERATIV PRODUKTVY')).toBeInTheDocument();
    expect(screen.getByText(/visar endast API-data och importerad evidens/i)).toBeInTheDocument();
  });

  test('does not expose synthetic demo data or non-functional shell controls', async () => {
    const user = userEvent.setup();
    render(<App />);

    expect(screen.queryByText('Demo Organisation')).not.toBeInTheDocument();
    expect(screen.queryByText('Demo Admin')).not.toBeInTheDocument();
    expect(screen.queryByText('DEMOMILJÖ')).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: 'Sök' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Notiser' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Inställningar' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Översikt' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Öppna meny' }));
    expect(document.querySelector('.sidebar')).toHaveClass('sidebar--open');
    await user.click(screen.getAllByRole('button', { name: 'Stäng meny' }).at(-1)!);
    expect(document.querySelector('.sidebar')).not.toHaveClass('sidebar--open');
  });

  test('switches the application shell language without changing operational data', async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.selectOptions(screen.getByLabelText('Språk'), 'en');

    expect(screen.getByText('Operational security analysis')).toBeInTheDocument();
    expect(screen.getByText('OPERATIONAL PRODUCT VIEW')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Säkerhetsöversikt' })).toBeInTheDocument();
  });

  test('requires sign-in when OIDC is configured', () => {
    const configuration: OidcConfiguration = {
      mode: 'configured',
      config: {
        authorizationUrl: 'https://identity.example.test/authorize',
        tokenUrl: 'https://identity.example.test/token',
        clientId: 'traceless-web',
        redirectUri: `${window.location.origin}/auth/callback`,
        scopes: 'openid profile',
      },
    };

    render(<App oidcConfiguration={configuration} />);

    expect(screen.getByRole('heading', { name: 'Logga in' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Logga in' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Säkerhetsöversikt' })).not.toBeInTheDocument();
  });

  test('completes the callback in memory and signs out locally', async () => {
    const redirectUri = `${window.location.origin}/auth/callback`;
    const configuration: OidcConfiguration = {
      mode: 'configured',
      config: {
        authorizationUrl: 'https://identity.example.test/authorize',
        tokenUrl: 'https://identity.example.test/token',
        clientId: 'traceless-web',
        redirectUri,
        scopes: 'openid profile',
      },
    };
    window.sessionStorage.setItem(
      OIDC_TRANSACTION_STORAGE_KEY,
      JSON.stringify({ state: 'expected-state', verifier: 'v'.repeat(64), createdAt: Date.now() }),
    );
    window.history.replaceState(
      {},
      '',
      '/auth/callback?code=authorization-code&state=expected-state',
    );
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) === configuration.config.tokenUrl) {
        return new Response(
          JSON.stringify({ access_token: 'memory-token', token_type: 'Bearer', expires_in: 900 }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (String(input).endsWith('/api/v1/auth/me')) {
        return new Response(
          JSON.stringify({
            subject: 'analyst-1',
            actor: 'oidc:analyst-1',
            organization_id: 'organization-1',
            organization_name: 'Testorganisation',
            project_ids: null,
            system_ids: null,
            roles: ['analyst'],
            capabilities: ['read_operational', 'analyze', 'ingest_intelligence'],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (String(input).endsWith('/api/v1/operational/projects')) {
        return new Response(JSON.stringify([]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(null, { status: 404 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();

    render(
      <App
        oidcConfiguration={configuration}
        oidcDependencies={{ fetchImpl: fetchMock as typeof fetch }}
      />,
    );

    const signOut = await screen.findByRole('button', { name: 'Logga ut' });
    expect(window.location.search).toBe('');
    await user.click(signOut);
    expect(screen.getByRole('heading', { name: 'Logga in' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Logga ut' })).not.toBeInTheDocument();
  });
});
