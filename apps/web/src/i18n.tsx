import { createContext, useContext, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

export type Locale = 'sv' | 'en';
const messages = {
  sv: {
    checking: 'Kontrollerar inloggning', signIn: 'Logga in', oidcConnecting: 'Säker anslutning till identitetsleverantören pågår.',
    oidcPrompt: 'Fortsätt via organisationens identitetsleverantör.', closeMenu: 'Stäng meny', openMenu: 'Öppna meny',
    product: 'Produkt', operationalAnalysis: 'Operativ analys', workspace: 'Operativ arbetsyta',
    workspaceHint: 'Visar endast API-data och importerad evidens', topTitle: 'Operativ säkerhetsanalys',
    topHint: 'Beständig data med källstatus och osäkerhet', productView: 'OPERATIV PRODUKTVY', signOut: 'Logga ut', language: 'Språk',
  },
  en: {
    checking: 'Checking sign-in', signIn: 'Sign in', oidcConnecting: 'Connecting securely to the identity provider.',
    oidcPrompt: 'Continue through your organization identity provider.', closeMenu: 'Close menu', openMenu: 'Open menu',
    product: 'Product', operationalAnalysis: 'Operational analysis', workspace: 'Operational workspace',
    workspaceHint: 'Shows API data and imported evidence only', topTitle: 'Operational security analysis',
    topHint: 'Persistent data with source status and uncertainty', productView: 'OPERATIONAL PRODUCT VIEW', signOut: 'Sign out', language: 'Language',
  },
} as const;
type Key = keyof typeof messages.sv;

const Context = createContext<{ locale: Locale; setLocale(value: Locale): void; t(key: Key): string } | null>(null);
export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<Locale>('sv');
  const value = useMemo(() => ({ locale, setLocale, t: (key: Key) => messages[locale][key] }), [locale]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}
export function useI18n() { const value = useContext(Context); if (!value) throw new Error('useI18n requires I18nProvider'); return value; }
