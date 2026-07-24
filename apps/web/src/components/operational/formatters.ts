import type {
  Criticality,
  Finding,
  FindingLifecycleStatus,
  GlobalIntelRecord,
  OperationalPrincipal,
  Report,
  ReportType,
  ScanJob,
} from '../../api';

export function dateTimeLocal(minutesFromNow: number): string {
  const value = new Date(Date.now() + minutesFromNow * 60_000);
  const pad = (part: number) => String(part).padStart(2, '0');
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}T${pad(value.getHours())}:${pad(value.getMinutes())}`;
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return 'Ej tillgängligt';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return 'Ogiltig tidpunkt';
  return new Intl.DateTimeFormat('sv-SE', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(parsed);
}

export function formatPercent(value: number | null | undefined): string {
  return value === null || value === undefined ? 'Okänd' : `${Math.round(value * 100)} %`;
}

export function scanStatusLabel(status: ScanJob['status']): string {
  return {
    queued: 'Köad',
    running: 'Körs av worker',
    completed: 'Slutförd',
    failed: 'Misslyckad',
    cancelled: 'Avbruten',
  }[status];
}

export function criticalityLabel(value: Criticality): string {
  return { low: 'Låg', medium: 'Medel', high: 'Hög', critical: 'Kritisk' }[value];
}

export function findingLifecycleLabel(value: FindingLifecycleStatus): string {
  return {
    open: 'Öppet',
    fixed: 'Åtgärdat',
    accepted: 'Accepterat',
    false_positive: 'Falsk positiv',
    out_of_scope: 'Utanför scope',
    reopened: 'Återöppnat',
  }[value];
}

export function findingTypeLabel(value: Finding['finding_type']): string {
  return {
    vulnerability: 'Sårbarhet',
    misconfiguration: 'Felkonfiguration',
    informational: 'Informationsfynd',
  }[value];
}

export function inventoryStatusLabel(
  value: 'current' | 'unobserved' | 'stale' | 'unknown',
): string {
  return {
    current: 'Aktuell inventering',
    unobserved: 'Inte observerad i aktuell fullständig scope',
    stale: 'Utanför aktuell scope eller inaktuell',
    unknown: 'Inventeringsstatus okänd',
  }[value];
}

export function canReadOrganizationIntelligence(
  principal: OperationalPrincipal,
): boolean {
  return (
    principal.capabilities.includes('analyze') &&
    principal.project_ids === null &&
    principal.system_ids === null
  );
}

export function reportTypeLabel(value: ReportType): string {
  return {
    management: 'Ledningsrapport',
    technical: 'Teknisk rapport',
    risk_register: 'Riskregister',
  }[value];
}

export function reportExportStatusLabel(value: Report['export_status']): string {
  return value === 'available' ? 'Tillgänglig för export' : 'Återkallad – export spärrad';
}

export function intelReviewStatusLabel(
  value: GlobalIntelRecord['review_status'],
): string {
  return {
    pending: 'Väntar på granskning',
    approved: 'Godkänd',
    rejected: 'Avvisad',
  }[value];
}

export function asErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Ett oväntat fel inträffade.';
}
