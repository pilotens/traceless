import { useMemo, useState } from 'react';

import { createOperationalApi } from './api';
import {
  OidcAuthProvider,
  useOidcAuth,
  type OidcAuthDependencies,
  type OidcConfiguration,
} from './auth';
import { DemoWorkspace } from './components/DemoWorkspace';
import { Icon } from './components/Icon';
import { I18nProvider, useI18n } from './i18n';
import { OperationalWorkspace } from './components/OperationalWorkspace';

interface AppProps {
  oidcConfiguration?: OidcConfiguration;
  oidcDependencies?: OidcAuthDependencies;
}

type ProductView = 'operational' | 'demo';

function AuthenticationGate() {
  const auth = useOidcAuth();
  const { t } = useI18n();
  const busy = auth.status === 'checking' || auth.status === 'redirecting';
  return (
    <main className="auth-page">
      <section className="auth-card" aria-live="polite">
        <div className="brand__mark auth-card__mark" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <p className="eyebrow">Traceless Security Graph</p>
        <h1>{busy ? t('checking') : t('signIn')}</h1>
        <p>
          {auth.errorMessage ??
            (busy
              ? t('oidcConnecting')
              : t('oidcPrompt'))}
        </p>
        {!busy && auth.canSignIn && (
          <button className="primary-button auth-card__button" onClick={() => void auth.signIn()} type="button">
            {t('signIn')}
          </button>
        )}
      </section>
    </main>
  );
}

export function AppShell() {
  const auth = useOidcAuth();
  const { locale, setLocale, t } = useI18n();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [view, setView] = useState<ProductView>('operational');
  const api = useMemo(
    () => createOperationalApi({ getAccessToken: () => auth.accessToken }),
    [auth.accessToken],
  );

  if (auth.status !== 'disabled' && auth.status !== 'authenticated') {
    return <AuthenticationGate />;
  }

  return (
    <div className="app-shell app-shell--operational">
      <aside className={`sidebar ${sidebarOpen ? 'sidebar--open' : ''}`}>
        <div className="brand">
          <div className="brand__mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div>
            <strong>traceless</strong>
            <small>SECURITY GRAPH</small>
          </div>
          <button
            aria-label={t('closeMenu')}
            className="icon-button sidebar__close"
            onClick={() => setSidebarOpen(false)}
            type="button"
          >
            <Icon name="close" />
          </button>
        </div>

        <nav className="sidebar-nav" aria-label="Huvudmeny">
          <p className="sidebar-nav__label">{t('product')}</p>
          <button
            className={`sidebar-nav__item ${view === 'operational' ? 'is-active' : ''}`}
            aria-current={view === 'operational' ? 'page' : undefined}
            onClick={() => {
              setView('operational');
              setSidebarOpen(false);
            }}
            type="button"
          >
            <Icon name="scan" />
            <span>{t('operationalAnalysis')}</span>
          </button>
          <button
            className={`sidebar-nav__item ${view === 'demo' ? 'is-active' : ''}`}
            aria-current={view === 'demo' ? 'page' : undefined}
            onClick={() => {
              setView('demo');
              setSidebarOpen(false);
            }}
            type="button"
          >
            <Icon name="database" />
            <span>{locale === 'sv' ? 'Demo' : 'Demo'}</span>
          </button>
        </nav>

        <div className="sidebar__footer">
          <div className="collection-status">
            <span className="pulse-dot pulse-dot--neutral" />
            <span>
              <strong>{t('workspace')}</strong>
              <small>{t('workspaceHint')}</small>
            </span>
          </div>
        </div>
      </aside>

      {sidebarOpen && (
        <button
          aria-label={t('closeMenu')}
          className="sidebar-backdrop"
          onClick={() => setSidebarOpen(false)}
          type="button"
        />
      )}

      <main className="main-area main-area--workspace">
        <header className="topbar topbar--operational">
          <button
            aria-label={t('openMenu')}
            className="icon-button topbar__menu"
            onClick={() => setSidebarOpen(true)}
            type="button"
          >
            <Icon name="menu" />
          </button>
          <div className="topbar__context">
            <strong>{view === 'demo' ? (locale === 'sv' ? 'End-to-end-demo' : 'End-to-end demo') : t('topTitle')}</strong>
            <small>{view === 'demo' ? (locale === 'sv' ? 'Beständig data genom den riktiga API-kedjan' : 'Persisted data through the real API chain') : t('topHint')}</small>
          </div>
          <div className="topbar__actions">
            <span className="live-badge"><span /> {t('productView')}</span>
            <label className="language-control">
              <span>{t('language')}</span>
              <select aria-label={t('language')} value={locale} onChange={(event) => setLocale(event.target.value as 'sv' | 'en')}>
                <option value="sv">Svenska</option>
                <option value="en">English</option>
              </select>
            </label>
            {auth.status === 'authenticated' && (
              <button className="secondary-button auth-signout" onClick={auth.signOut} type="button">
                {t('signOut')}
              </button>
            )}
          </div>
        </header>

        {view === 'operational' ? (
          <OperationalWorkspace api={api} />
        ) : (
          <DemoWorkspace api={api} accessToken={auth.accessToken} locale={locale} />
        )}
      </main>
    </div>
  );
}

export default function App({ oidcConfiguration, oidcDependencies }: AppProps) {
  return (
    <I18nProvider>
      <OidcAuthProvider configuration={oidcConfiguration} dependencies={oidcDependencies}>
        <AppShell />
      </OidcAuthProvider>
    </I18nProvider>
  );
}
