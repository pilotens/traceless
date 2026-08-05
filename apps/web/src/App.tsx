import { useEffect, useMemo, useState } from 'react';

import { createOperationalApi } from './api';
import { LiveWorkspace } from './components/LiveWorkspace';
import { MockupWorkspace, type WorkspaceTab } from './components/MockupWorkspace';
import {
  OidcAuthProvider,
  readOidcConfiguration,
  useOidcAuth,
  type OidcAuthDependencies,
  type OidcConfiguration,
} from './auth';

interface AppProps {
  oidcConfiguration?: OidcConfiguration;
  oidcDependencies?: OidcAuthDependencies;
  fetchImpl?: typeof fetch;
}

const pathByTab: Record<WorkspaceTab, string> = {
  overview: 'overview',
  assets: 'assets',
  threats: 'threats',
  findings: 'vulnerabilities',
  risks: 'risks',
  architecture: 'architecture',
  reports: 'reports',
};

const tabByPath: Record<string, WorkspaceTab> = {
  overview: 'overview',
  analysis: 'overview',
  assets: 'assets',
  threats: 'threats',
  intelligence: 'threats',
  findings: 'findings',
  vulnerabilities: 'findings',
  risks: 'risks',
  'risk-graph': 'risks',
  architecture: 'architecture',
  reports: 'reports',
};

function readTab(): WorkspaceTab {
  const parts = window.location.pathname.split('/').filter(Boolean);
  return tabByPath[parts.at(-1) ?? ''] ?? 'overview';
}

function isDemoRoute(): boolean {
  return window.location.pathname === '/demo' || window.location.pathname.startsWith('/demo/');
}

function SignInView() {
  const auth = useOidcAuth();
  return (
    <main className="tm-auth">
      <section>
        <div className="tm-logo-mark" aria-hidden="true"><i /></div>
        <span className="tm-wordmark">traceless</span>
        <h1>Logga in till Traceless</h1>
        <p>Fortsätt till den operativa säkerhetsanalysen.</p>
        {auth.errorMessage && <div className="tm-auth-error">{auth.errorMessage}</div>}
        <button type="button" disabled={!auth.canSignIn} onClick={() => void auth.signIn()}>
          Logga in
        </button>
      </section>
    </main>
  );
}

function AppContent() {
  const auth = useOidcAuth();
  const [tab, setTab] = useState<WorkspaceTab>(readTab);
  const [demo, setDemo] = useState(isDemoRoute);
  const api = useMemo(() => createOperationalApi({
    getAccessToken: () => auth.status === 'authenticated' ? auth.accessToken : null,
  }), [auth.accessToken, auth.status]);

  useEffect(() => {
    const handleHistory = () => {
      setTab(readTab());
      setDemo(isDemoRoute());
    };
    window.addEventListener('popstate', handleHistory);
    return () => window.removeEventListener('popstate', handleHistory);
  }, []);

  if (auth.status !== 'disabled' && auth.status !== 'authenticated') {
    return <SignInView />;
  }

  function navigate(nextTab: WorkspaceTab) {
    if (nextTab === tab) return;
    const path = `${demo ? '/demo' : '/app'}/${pathByTab[nextTab]}`;
    window.history.pushState({}, '', path);
    setTab(nextTab);
  }

  if (demo) return <MockupWorkspace initialTab={tab} onTabChange={navigate} />;
  return <LiveWorkspace api={api} initialTab={tab} onTabChange={navigate} />;
}

export default function App({ oidcConfiguration, oidcDependencies, fetchImpl }: AppProps) {
  const configuration = oidcConfiguration ?? readOidcConfiguration();
  return (
    <OidcAuthProvider
      configuration={configuration}
      dependencies={{ ...(oidcDependencies ?? {}), fetchImpl }}
    >
      <AppContent />
    </OidcAuthProvider>
  );
}
