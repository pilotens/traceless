
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from '@xyflow/react';
import { useMemo } from 'react';
import '@xyflow/react/dist/style.css';

import type { CyberRiskGraphView, RiskGraphNodeKind } from '../api';

const columnOrder: Record<RiskGraphNodeKind, number> = {
  business_capability: 0,
  regulation: 0,
  system: 1,
  architecture_component: 2,
  asset: 2,
  service: 3,
  finding: 4,
  threat: 4,
  risk: 5,
  action: 6,
};

const kindLabel: Record<RiskGraphNodeKind, string> = {
  business_capability: 'Förmåga',
  regulation: 'Regelverk',
  system: 'System',
  architecture_component: 'Arkitektur',
  asset: 'Tillgång',
  service: 'Tjänst',
  finding: 'Fynd',
  threat: 'Hot',
  risk: 'Risk',
  action: 'Åtgärd',
};

interface CyberRiskGraphProps {
  graph: CyberRiskGraphView;
}

export function CyberRiskGraph({ graph }: CyberRiskGraphProps) {
  const layout = useMemo(() => {
    const counters = new Map<number, number>();
    const nodes: Node[] = graph.nodes.map((node) => {
      const column = columnOrder[node.kind];
      const row = counters.get(column) ?? 0;
      counters.set(column, row + 1);
      return {
        id: node.id,
        position: { x: column * 280, y: row * 116 },
        className: `op-risk-graph-node op-risk-graph-node--${node.kind}`,
        data: {
          label: (
            <span className="op-risk-graph-node__content">
              <small>{kindLabel[node.kind]}</small>
              <strong>{node.label}</strong>
              {node.status && <em>{node.status}</em>}
              {node.severity && <b className={`op-criticality op-criticality--${node.severity}`}>{node.severity}</b>}
            </span>
          ),
        },
      };
    });
    const edges: Edge[] = graph.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: edge.relationship.replaceAll('_', ' '),
      markerEnd: { type: MarkerType.ArrowClosed },
      className: 'op-risk-graph-edge',
    }));
    return { nodes, edges };
  }, [graph.edges, graph.nodes]);

  const context = graph.business_context;
  return (
    <div className="op-risk-graph-workspace">
      <section className="op-risk-graph-summary" aria-label="CISO-sammanfattning">
        {[
          ['Säkerhetspoäng', `${graph.summary.security_score}/100`],
          ['Kritiska risker', graph.summary.critical_risks],
          ['Höga risker', graph.summary.high_risks],
          ['KEV-fynd', graph.summary.kev_findings],
          ['Aktiva hot', graph.summary.active_threats],
          ['Externa tillgångar', graph.summary.external_assets],
        ].map(([label, value]) => (
          <article key={label}><strong>{value}</strong><small>{label}</small></article>
        ))}
      </section>

      <section className="op-risk-graph-context panel">
        <div>
          <span className="section-kicker">VERKSAMHETSKONTEXT</span>
          <h2>{context.business_owner || 'Affärsägare saknas'}</h2>
          <p>{context.capabilities.join(' · ') || 'Koppla verksamhetsförmågor i arkitekturvyn.'}</p>
        </div>
        <dl>
          <div><dt>Processer</dt><dd>{context.processes.join(', ') || 'Saknas'}</dd></div>
          <div><dt>Data</dt><dd>{context.data_categories.join(', ') || 'Saknas'}</dd></div>
          <div><dt>Regelverk</dt><dd>{context.regulations.join(', ') || 'Saknas'}</dd></div>
          <div><dt>RTO / RPO</dt><dd>{context.recovery_time_objective_hours ?? '–'} h / {context.recovery_point_objective_hours ?? '–'} h</dd></div>
        </dl>
      </section>

      {graph.summary.recommended_actions.length > 0 && (
        <section className="op-risk-graph-actions panel">
          <span className="section-kicker">REKOMMENDERADE BESLUT</span>
          <ol>{graph.summary.recommended_actions.map((action) => <li key={action}>{action}</li>)}</ol>
        </section>
      )}

      {graph.truncated && (
        <div className="op-collection-note" role="note">
          Grafen är begränsad för läsbarhet. Sammanfattningens totalsiffror omfattar hela systemet.
        </div>
      )}

      <section className="op-risk-graph-canvas panel" aria-label="Cyber Risk Graph">
        <ReactFlow
          edges={layout.edges}
          fitView
          fitViewOptions={{ padding: 0.18 }}
          nodes={layout.nodes}
          nodesConnectable={false}
          nodesDraggable={false}
          elementsSelectable
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
          <MiniMap pannable zoomable />
          <Controls showInteractive={false} />
        </ReactFlow>
      </section>
    </div>
  );
}
