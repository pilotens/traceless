import type { ReactNode } from 'react';

import type { Page } from '../../api';
import { Icon } from '../Icon';

export function EmptyState({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="op-empty">
      <Icon name="layers" size={24} />
      <strong>{title}</strong>
      <p>{children}</p>
    </div>
  );
}

export function PaginationControls<T>({
  ariaLabel = 'Sidindelning',
  busy,
  onPage,
  page,
}: {
  ariaLabel?: string;
  busy: boolean;
  onPage: (offset: number) => void;
  page: Page<T>;
}) {
  if (page.total <= page.limit) return null;
  const start = page.total === 0 ? 0 : page.offset + 1;
  const end = Math.min(page.offset + page.items.length, page.total);
  return (
    <nav className="op-pagination" aria-label={ariaLabel}>
      <button
        className="secondary-button"
        disabled={busy || page.offset === 0}
        onClick={() => onPage(Math.max(0, page.offset - page.limit))}
        type="button"
      >
        Föregående
      </button>
      <span>{start}–{end} av {page.total}</span>
      <button
        className="secondary-button"
        disabled={busy || !page.has_more}
        onClick={() => onPage(page.offset + page.limit)}
        type="button"
      >
        Nästa
      </button>
    </nav>
  );
}

export function EntityCards({
  title,
  caveat,
  empty,
  children,
}: {
  title: string;
  caveat: string;
  empty: string;
  children: ReactNode;
}) {
  const items = Array.isArray(children) ? children.filter(Boolean) : children ? [children] : [];
  return (
    <div>
      <header className="op-section-heading">
        <div>
          <span className="section-kicker">SPÅRBARA RESULTAT</span>
          <h2>{title}</h2>
        </div>
        <small>{caveat}</small>
      </header>
      {items.length === 0 ? (
        <EmptyState title={empty}>{caveat}</EmptyState>
      ) : (
        <div className="op-card-grid">{children}</div>
      )}
    </div>
  );
}
