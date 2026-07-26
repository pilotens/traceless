
import { render, screen } from '@testing-library/react';
import { describe, expect, test } from 'vitest';

import type { CyberRiskGraphView } from '../api';
import { CyberRiskGraph } from './CyberRiskGraph';

const graph: CyberRiskGraphView = {
  system_id: 'system-1',
  business_context: {
    business_owner: 'Head of Payments',
    capabilities: ['Accept payments'],
    processes: ['Card authorization'],
    data_categories: ['Payment data'],
    regulations: ['DORA'],
    recovery_time_objective_hours: 2,
    recovery_point_objective_hours: 0.5,
    impact: {
      confidentiality: 5,
      integrity: 5,
      availability: 5,
      financial: 5,
      regulatory: 5,
      reputation: 4,
      safety: 1,
    },
  },
  summary: {
    security_score: 61,
    critical_risks: 2,
    high_risks: 1,
    open_findings: 5,
    kev_findings: 1,
    active_threats: 3,
    external_assets: 2,
    recommended_actions: ['Patcha gateway omedelbart.'],
  },
  nodes: [
    { id: 'system:1', kind: 'system', label: 'Payment API', severity: 'critical', status: 'operational', metadata: {} },
    { id: 'risk:1', kind: 'risk', label: 'Gateway compromise', severity: 'critical', status: 'open', metadata: {} },
  ],
  edges: [{ id: 'edge:1', source: 'risk:1', target: 'system:1', relationship: 'affects', metadata: {} }],
  truncated: false,
};

describe('CyberRiskGraph', () => {
  test('renders CISO metrics, business context and recommended actions', () => {
    render(<CyberRiskGraph graph={graph} />);
    expect(screen.getByText('61/100')).toBeInTheDocument();
    expect(screen.getByText('Head of Payments')).toBeInTheDocument();
    expect(screen.getByText('Accept payments')).toBeInTheDocument();
    expect(screen.getByText('Patcha gateway omedelbart.')).toBeInTheDocument();
    expect(screen.getByLabelText('Cyber Risk Graph')).toBeInTheDocument();
  });
});
