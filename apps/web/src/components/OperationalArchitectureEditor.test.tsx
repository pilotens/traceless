import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, test, vi } from 'vitest';

import type { ArchitectureSnapshot, ArchitectureVersionInput } from '../api';
import { OperationalArchitectureEditor } from './OperationalArchitectureEditor';

const createdAt = '2026-07-21T10:00:00Z';

function observedVersion(
  id: string,
  version: number,
  nodeIds: string[],
): ArchitectureSnapshot {
  return {
    id,
    system_id: 'system-1',
    source_scan_id: `scan-${version}`,
    base_snapshot_id: null,
    version,
    status: 'draft',
    source_type: 'scan',
    layer: 'observed',
    title: `Observed v${version}`,
    change_note: 'Scanner-derived topology',
    created_by: 'scanner-pipeline',
    created_at: createdAt,
    graph: {
      zones: [],
      edges: [],
      nodes: nodeIds.map((nodeId, index) => ({
        id: nodeId,
        name: nodeId,
        kind: 'server',
        zone_id: null,
        position: { x: 100 + index * 40, y: 100 },
        properties: {},
        provenance: 'observed',
      })),
    },
  };
}

test('preserves a dirty first-manual draft on its selected observed base when a scan arrives', async () => {
  const user = userEvent.setup();
  const onSave = vi.fn(async (_input: ArchitectureVersionInput) => undefined);
  const editedObserved = observedVersion('observed-1', 1, ['edited-base-node']);
  const newerObserved = observedVersion(
    'observed-2',
    2,
    ['new-scan-node-a', 'new-scan-node-b', 'new-scan-node-c'],
  );
  const commonProps = {
    analystIdentity: 'oidc:analyst-1',
    busy: false,
    canEdit: true,
    onSave,
    systemName: 'Payments',
  };
  const { rerender } = render(
    <OperationalArchitectureEditor
      {...commonProps}
      snapshot={editedObserved}
      versions={[editedObserved]}
    />,
  );

  await user.click(screen.getByRole('button', { name: /Databas/ }));
  expect(screen.getByText('2 komponenter')).toBeInTheDocument();
  expect(screen.getByText(/Osparade arkitekturändringar/)).toBeInTheDocument();

  // A refresh may return only the new head. The editor must retain the exact
  // historical object from which its local graph was derived.
  rerender(
    <OperationalArchitectureEditor
      {...commonProps}
      snapshot={newerObserved}
      versions={[newerObserved]}
    />,
  );

  expect(screen.getByText('2 komponenter')).toBeInTheDocument();
  const warning = screen.getByText((_, element) =>
    Boolean(
      element?.classList.contains('op-architecture__warning') &&
      element.textContent?.includes('En ny observerad topologi har kommit'),
    ),
  );
  expect(warning).toHaveTextContent(/v1 som bas/i);
  expect(warning).toHaveTextContent(/slås inte ihop automatiskt/i);
  expect(screen.getByRole('button', { name: /Spara som ny version/ })).toBeEnabled();

  await user.click(screen.getByRole('button', { name: /Spara som ny version/ }));
  await waitFor(() => expect(onSave).toHaveBeenCalledOnce());
  const saved = onSave.mock.calls[0]?.[0];
  expect(saved).toBeDefined();
  if (!saved) throw new Error('Expected the architecture draft to be saved');
  expect(saved.base_snapshot_id).toBe(editedObserved.id);
  expect(saved.graph.nodes.map((node) => node.id)).toContain('edited-base-node');
  expect(saved.graph.nodes.map((node) => node.id)).not.toContain('new-scan-node-a');
});

test('a read-only architecture cannot become dirty through drop or keyboard deletion', async () => {
  const user = userEvent.setup();
  const observed = observedVersion('observed-viewer', 1, ['viewer-node']);
  const { container } = render(
    <OperationalArchitectureEditor
      analystIdentity="oidc:viewer-1"
      busy={false}
      canEdit={false}
      onSave={vi.fn(async () => undefined)}
      snapshot={observed}
      systemName="Payments"
      versions={[observed]}
    />,
  );
  const flow = container.querySelector('.op-editor-flow');
  expect(flow).not.toBeNull();
  fireEvent.drop(flow!, {
    dataTransfer: {
      dropEffect: 'move',
      getData: () => 'database',
    },
  });
  expect(screen.getByText('1 komponenter')).toBeInTheDocument();

  await user.keyboard('{Delete}');
  expect(screen.getByText('1 komponenter')).toBeInTheDocument();
  expect(screen.queryByText(/Osparade arkitekturändringar/)).not.toBeInTheDocument();
  expect(
    screen.getByRole('button', { name: 'Ångra senaste diagramändringen' }),
  ).toBeDisabled();
});

test('persists analyst-verified exposure, reachability and controls in a new version', async () => {
  const user = userEvent.setup();
  const onSave = vi.fn(async (_input: ArchitectureVersionInput) => undefined);
  const assetId = '11111111-1111-4111-8111-111111111111';
  const observed: ArchitectureSnapshot = {
    ...observedVersion('observed-risk-context', 1, []),
    graph: {
      zones: [],
      edges: [],
      risk_contexts: [],
      nodes: [
        {
          id: assetId,
          name: 'Internet-facing API',
          kind: 'asset',
          zone_id: null,
          position: { x: 100, y: 100 },
          properties: { asset_id: assetId },
          provenance: 'observed',
        },
      ],
    },
  };
  render(
    <OperationalArchitectureEditor
      analystIdentity="oidc:analyst-1"
      busy={false}
      canEdit
      onSave={onSave}
      snapshot={observed}
      systemName="Payments"
      versions={[observed]}
    />,
  );

  await user.selectOptions(screen.getByLabelText('Verifierad exponering'), 'external');
  await user.selectOptions(screen.getByLabelText('Verifierad nåbarhet'), 'true');
  await user.type(screen.getByLabelText('Verifierad kontrolleffektivitet'), '75');
  await user.type(
    screen.getByLabelText('Riskkontext evidensreferens'),
    'Pentest PT-2026-17',
  );
  await user.click(screen.getByRole('button', { name: 'Lägg till riskkontext' }));

  expect(screen.getByText('1 verifierade riskkontexter')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: /Spara som ny version/ }));
  await waitFor(() => expect(onSave).toHaveBeenCalledOnce());
  expect(onSave.mock.calls[0]?.[0].graph.risk_contexts).toEqual([
    {
      asset_id: assetId,
      service_id: null,
      exposure: 'external',
      reachable: true,
      control_effectiveness: 0.75,
      evidence_reference: 'Pentest PT-2026-17',
    },
  ]);
});
