import { render, screen } from '@testing-library/react';
import { describe, expect, test, vi } from 'vitest';

import { RiskGovernanceWorkspace } from './RiskGovernanceWorkspace';

const jsonResponse = (value: unknown) =>
  Promise.resolve(
    new Response(JSON.stringify(value), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  );

describe('RiskGovernanceWorkspace', () => {
  test('renders portfolio metrics and the first governed system', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith('/projects')) {
          return jsonResponse([
            {
              id: 'project-1',
              name: 'Payments',
              description: '',
              created_at: '2026-07-29T10:00:00Z',
              updated_at: '2026-07-29T10:00:00Z',
            },
          ]);
        }
        if (url.endsWith('/portfolio/governance')) {
          return jsonResponse({
            systems: [],
            open_risks: 4,
            overdue_treatments: 1,
            risks_without_owner: 2,
            average_coverage_percent: 55,
          });
        }
        if (url.includes('/projects/project-1/systems')) {
          return jsonResponse([
            {
              id: 'system-1',
              project_id: 'project-1',
              name: 'Payment API',
              description: '',
              owner: 'Platform',
              criticality: 'critical',
              created_at: '2026-07-29T10:00:00Z',
              updated_at: '2026-07-29T10:00:00Z',
            },
          ]);
        }
        if (url.includes('/governance/overview')) {
          return jsonResponse({
            system_id: 'system-1',
            published_context: null,
            draft_context: null,
            open_risks: 4,
            risks_with_active_treatment: 2,
            risks_without_owner: 2,
            overdue_treatments: 1,
            controls: 1,
            controls_with_current_assessment: 0,
            coverage_percent: 55,
            latest_manifest: null,
          });
        }
        if (url.includes('/context/versions')) return jsonResponse([]);
        if (url.includes('/treatments')) return jsonResponse([]);
        if (url.includes('/controls')) return jsonResponse([]);
        if (url.includes('/risks?')) {
          return jsonResponse({ items: [], total: 0, limit: 200, offset: 0, has_more: false });
        }
        return jsonResponse([]);
      }),
    );

    render(<RiskGovernanceWorkspace accessToken={null} />);

    expect(await screen.findByText('Payment API')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Riskbeslut, åtgärder och verifiering/ })).toBeInTheDocument();
    expect(screen.getByText('55%')).toBeInTheDocument();
  });
});
