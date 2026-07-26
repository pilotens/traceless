import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  addEdge,
  useEdgesState,
  useNodesState,
  type Connection,
  type Edge,
  type EdgeMouseHandler,
  type Node,
  type NodeMouseHandler,
  type NodeProps,
  type ReactFlowInstance,
} from '@xyflow/react';
import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent } from 'react';
import '@xyflow/react/dist/style.css';

import type {
  ArchitectureBusinessContextInput,
  ArchitectureEdgeInput,
  ArchitectureGraphInput,
  ArchitectureNodeInput,
  ArchitectureNodeKind,
  ArchitectureRiskContextInput,
  ArchitectureSnapshot,
  ArchitectureVersionInput,
  ArchitectureZoneInput,
} from '../api';
import { Icon } from './Icon';

interface EditorNodeData extends Record<string, unknown> {
  name: string;
  kind: ArchitectureNodeKind;
  zoneId: string | null;
  properties: Record<string, unknown>;
  provenance: 'manual' | 'observed' | 'imported';
}

type EditorNode = Node<EditorNodeData, 'architectureComponent'>;
interface EditorEdgeData extends Record<string, unknown> {
  protocol: string | null;
  encrypted: boolean | null;
  properties: Record<string, unknown>;
}
type EditorEdge = Edge<EditorEdgeData>;

interface OperationalArchitectureEditorProps {
  systemName: string;
  snapshot: ArchitectureSnapshot | null;
  versions: ArchitectureSnapshot[];
  busy: boolean;
  canEdit: boolean;
  analystIdentity: string;
  onSave: (input: ArchitectureVersionInput) => Promise<void>;
  onDirtyChange?: (dirty: boolean) => void;
}

interface EditorGraphState {
  nodes: EditorNode[];
  edges: EditorEdge[];
  zones: ArchitectureZoneInput[];
  riskContexts: EditorRiskContext[];
}

interface EditorRiskContext extends ArchitectureRiskContextInput {
  verified_by: string | null;
  verified_at: string | null;
}

const palette: Array<{
  kind: ArchitectureNodeKind;
  label: string;
  icon: Parameters<typeof Icon>[0]['name'];
}> = [
  { kind: 'application', label: 'Applikation', icon: 'architecture' },
  { kind: 'server', label: 'Server', icon: 'server' },
  { kind: 'database', label: 'Databas', icon: 'database' },
  { kind: 'gateway', label: 'Gateway', icon: 'globe' },
  { kind: 'user', label: 'Användare', icon: 'user' },
  { kind: 'security_control', label: 'Säkerhetskontroll', icon: 'shield' },
  { kind: 'queue', label: 'Meddelandekö', icon: 'layers' },
  { kind: 'cloud', label: 'Molntjänst', icon: 'activity' },
];

const allowedKinds = new Set<ArchitectureNodeKind>([
  'asset',
  'service',
  'server',
  'database',
  'user',
  'security_control',
  'gateway',
  'queue',
  'application',
  'cloud',
  'network',
  'other',
]);

function iconForKind(kind: ArchitectureNodeKind) {
  return (
    palette.find((item) => item.kind === kind)?.icon ??
    (kind === 'service' || kind === 'asset' ? 'server' : 'architecture')
  );
}

function ArchitectureComponentNode({ data, selected }: NodeProps<EditorNode>) {
  return (
    <div
      className={`op-editor-node op-editor-node--${data.provenance}${selected ? ' is-selected' : ''}`}
    >
      <Handle id="target" position={Position.Left} type="target" />
      <span className={`op-editor-node__icon op-editor-node__icon--${data.kind}`}>
        <Icon name={iconForKind(data.kind)} size={17} />
      </span>
      <span>
        <strong>{data.name}</strong>
        <small>{data.kind.replace('_', ' ')}</small>
        <em>{data.provenance === 'manual' ? 'Manuell' : data.provenance === 'observed' ? 'Observerad' : 'Importerad'}</em>
      </span>
      <Handle id="source" position={Position.Right} type="source" />
    </div>
  );
}

const nodeTypes = { architectureComponent: ArchitectureComponentNode };

function objectValue(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stringValue(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function graphArray(graph: Record<string, unknown>, key: string): Record<string, unknown>[] {
  const value = graph[key];
  return Array.isArray(value)
    ? value.filter(
        (item): item is Record<string, unknown> => typeof item === 'object' && item !== null,
      )
    : [];
}

const DEFAULT_BUSINESS_CONTEXT: ArchitectureBusinessContextInput = {
  business_owner: '',
  capabilities: [],
  processes: [],
  data_categories: [],
  regulations: [],
  recovery_time_objective_hours: null,
  recovery_point_objective_hours: null,
  impact: {
    confidentiality: 3,
    integrity: 3,
    availability: 3,
    financial: 3,
    regulatory: 3,
    reputation: 3,
    safety: 1,
  },
};

function stringListValue(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    : [];
}

function numericImpact(value: unknown, fallback: number): number {
  return typeof value === 'number' && value >= 1 && value <= 5 ? value : fallback;
}

function normalizeBusinessContext(graph: Record<string, unknown>): ArchitectureBusinessContextInput {
  const raw = objectValue(graph.business_context);
  const impact = objectValue(raw.impact);
  return {
    business_owner: stringValue(raw.business_owner) ?? '',
    capabilities: stringListValue(raw.capabilities),
    processes: stringListValue(raw.processes),
    data_categories: stringListValue(raw.data_categories),
    regulations: stringListValue(raw.regulations),
    recovery_time_objective_hours:
      typeof raw.recovery_time_objective_hours === 'number'
        ? raw.recovery_time_objective_hours
        : null,
    recovery_point_objective_hours:
      typeof raw.recovery_point_objective_hours === 'number'
        ? raw.recovery_point_objective_hours
        : null,
    impact: {
      confidentiality: numericImpact(impact.confidentiality, 3),
      integrity: numericImpact(impact.integrity, 3),
      availability: numericImpact(impact.availability, 3),
      financial: numericImpact(impact.financial, 3),
      regulatory: numericImpact(impact.regulatory, 3),
      reputation: numericImpact(impact.reputation, 3),
      safety: numericImpact(impact.safety, 1),
    },
  };
}

function parseCommaSeparated(value: string): string[] {
  return [...new Set(value.split(',').map((item) => item.trim()).filter(Boolean))];
}


function normalizeGraph(snapshot: ArchitectureSnapshot | null): {
  nodes: EditorNode[];
  edges: EditorEdge[];
  zones: ArchitectureZoneInput[];
  riskContexts: EditorRiskContext[];
  businessContext: ArchitectureBusinessContextInput;
} {
  if (!snapshot) {
    return { nodes: [], edges: [], zones: [], riskContexts: [], businessContext: DEFAULT_BUSINESS_CONTEXT };
  }
  const graph = snapshot.graph;
  const businessContext = normalizeBusinessContext(graph);
  const zones = graphArray(graph, 'zones').flatMap((zone, index) => {
    const id = stringValue(zone.id) ?? `zone:${index + 1}`;
    const name = stringValue(zone.name) ?? `Zon ${index + 1}`;
    const rawBoundary = stringValue(zone.trust_boundary);
    const trustBoundary: ArchitectureZoneInput['trust_boundary'] = [
      'external',
      'untrusted',
      'restricted',
      'trusted',
    ].includes(rawBoundary ?? '')
      ? (rawBoundary as ArchitectureZoneInput['trust_boundary'])
      : 'unconfirmed';
    return [{ id, name, trust_boundary: trustBoundary }];
  });
  const assetZones = new Map<string, string | null>();
  graphArray(graph, 'nodes').forEach((node) => {
    const id = stringValue(node.id);
    if (id) assetZones.set(id, stringValue(node.zone_id));
  });
  const nodes = graphArray(graph, 'nodes').flatMap((node, index) => {
    const id = stringValue(node.id);
    const name = stringValue(node.name);
    if (!id || !name) return [];
    const rawKind = stringValue(node.kind) as ArchitectureNodeKind | null;
    const kind = rawKind && allowedKinds.has(rawKind) ? rawKind : 'other';
    const rawPosition = objectValue(node.position);
    const position =
      typeof rawPosition.x === 'number' && typeof rawPosition.y === 'number'
        ? { x: rawPosition.x, y: rawPosition.y }
        : { x: 80 + (index % 4) * 220, y: 70 + Math.floor(index / 4) * 130 };
    const directZone = stringValue(node.zone_id);
    const inheritedZone = assetZones.get(stringValue(node.asset_id) ?? '') ?? null;
    const rawProvenance = stringValue(node.provenance);
    const provenance: EditorNodeData['provenance'] =
      rawProvenance === 'observed' || rawProvenance === 'imported'
        ? rawProvenance
        : snapshot.source_type === 'scan'
          ? 'observed'
          : 'manual';
    const properties = { ...objectValue(node.properties) };
    for (const bindingKey of ['asset_id', 'service_id', 'source_scan_id'] as const) {
      const bindingValue = stringValue(node[bindingKey]);
      if (bindingValue && properties[bindingKey] === undefined) {
        properties[bindingKey] = bindingValue;
      }
    }
    return [
      {
        id,
        type: 'architectureComponent' as const,
        position,
        data: {
          name,
          kind,
          zoneId: directZone ?? inheritedZone,
          properties,
          provenance,
        },
      },
    ];
  });
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graphArray(graph, 'edges').flatMap((edge, index) => {
    const source = stringValue(edge.source);
    const target = stringValue(edge.target);
    if (!source || !target || !nodeIds.has(source) || !nodeIds.has(target) || source === target) {
      return [];
    }
    return [
      {
        id: stringValue(edge.id) ?? `edge:${index + 1}`,
        source,
        target,
        label: stringValue(edge.label) ?? undefined,
        markerEnd: { type: MarkerType.ArrowClosed },
        data: {
          protocol: stringValue(edge.protocol),
          encrypted: typeof edge.encrypted === 'boolean' ? edge.encrypted : null,
          properties: objectValue(edge.properties),
        },
      },
    ];
  });
  const riskContexts = graphArray(graph, 'risk_contexts').flatMap((context) => {
    const assetId = stringValue(context.asset_id);
    const rawExposure = stringValue(context.exposure);
    const verifiedBy = stringValue(context.verified_by);
    const verifiedAt = stringValue(context.verified_at);
    const evidenceReference = stringValue(context.evidence_reference);
    if (!assetId || !evidenceReference) return [];
    const exposure: ArchitectureRiskContextInput['exposure'] = [
      'external',
      'internal',
      'isolated',
      'unknown',
    ].includes(rawExposure ?? '')
      ? (rawExposure as ArchitectureRiskContextInput['exposure'])
      : 'unknown';
    return [{
      asset_id: assetId,
      service_id: stringValue(context.service_id),
      exposure,
      reachable: typeof context.reachable === 'boolean' ? context.reachable : null,
      control_effectiveness:
        typeof context.control_effectiveness === 'number'
          ? context.control_effectiveness
          : null,
      evidence_reference: evidenceReference,
      verified_by: verifiedBy,
      verified_at: verifiedAt,
    }];
  });
  return { nodes, edges, zones, riskContexts, businessContext };
}

function makeId(prefix: string): string {
  const random = globalThis.crypto?.randomUUID?.().replaceAll('-', '') ?? `${Date.now()}`;
  return `${prefix}:${random.slice(0, 20)}`;
}

function formatVerifiedAt(value: string | null): string {
  if (!value) return 'Registreras av API:t vid sparning';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Ogiltig serverregistrerad tid';
  return new Intl.DateTimeFormat('sv-SE', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

function riskBinding(node: EditorNode | null): { assetId: string; serviceId: string | null } | null {
  if (!node) return null;
  const assetId =
    stringValue(node.data.properties.asset_id) ??
    (node.data.kind === 'asset' ? node.id : null);
  if (!assetId) return null;
  const serviceId =
    stringValue(node.data.properties.service_id) ??
    (node.data.kind === 'service' && node.id.startsWith('service:')
      ? node.id.slice('service:'.length)
      : null);
  return { assetId, serviceId };
}

const HISTORY_LIMIT = 50;

function cloneGraphState(
  nodes: EditorNode[],
  edges: EditorEdge[],
  zones: ArchitectureZoneInput[],
  riskContexts: EditorRiskContext[],
): EditorGraphState {
  return {
    nodes: nodes.map((node) => ({
      ...node,
      position: { ...node.position },
      data: {
        ...node.data,
        properties: { ...node.data.properties },
      },
    })),
    edges: edges.map((edge) => ({
      ...edge,
      data: edge.data
        ? { ...edge.data, properties: { ...edge.data.properties } }
        : undefined,
      markerEnd:
        typeof edge.markerEnd === 'object' && edge.markerEnd !== null
          ? { ...edge.markerEnd }
          : edge.markerEnd,
    })),
    zones: zones.map((zone) => ({ ...zone })),
    riskContexts: riskContexts.map((context) => ({ ...context })),
  };
}

function buildGraph(
  nodes: EditorNode[],
  edges: EditorEdge[],
  zones: ArchitectureZoneInput[],
  riskContexts: EditorRiskContext[],
  businessContext: ArchitectureBusinessContextInput,
): ArchitectureGraphInput {
  return {
    schema_version: '1.0',
    publication_state: 'draft',
    warning:
      'Manuellt redigerad arkitektur. Komponenter, trust boundaries och dataflöden måste granskas innan publicering.',
    business_context: businessContext,
    zones,
    nodes: nodes.map<ArchitectureNodeInput>((node) => ({
      id: node.id,
      name: node.data.name,
      kind: node.data.kind,
      position: { x: Math.round(node.position.x), y: Math.round(node.position.y) },
      zone_id: node.data.zoneId,
      properties: node.data.properties,
      provenance: node.data.provenance,
    })),
    edges: edges.map<ArchitectureEdgeInput>((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: typeof edge.label === 'string' && edge.label ? edge.label : null,
      protocol: edge.data?.protocol ?? null,
      encrypted: edge.data?.encrypted ?? null,
      properties: edge.data?.properties ?? {},
    })),
    risk_contexts: riskContexts.map(
      ({ verified_by: _verifiedBy, verified_at: _verifiedAt, ...context }) => ({
        ...context,
      }),
    ),
  };
}

function editorFingerprint(
  nodes: EditorNode[],
  edges: EditorEdge[],
  zones: ArchitectureZoneInput[],
  riskContexts: EditorRiskContext[],
  businessContext: ArchitectureBusinessContextInput,
  title: string,
  changeNote: string,
): string {
  return JSON.stringify({
    title: title.trim(),
    change_note: changeNote.trim(),
    graph: buildGraph(nodes, edges, zones, riskContexts, businessContext),
  });
}

export function OperationalArchitectureEditor({
  analystIdentity,
  systemName,
  snapshot,
  versions,
  busy,
  canEdit,
  onSave,
  onDirtyChange,
}: OperationalArchitectureEditorProps) {
  const [selectedVersionId, setSelectedVersionId] = useState(snapshot?.id ?? '');
  const retainedSelectedVersion = useRef<ArchitectureSnapshot | null>(snapshot);
  const currentSystemId = snapshot?.system_id ?? versions[0]?.system_id ?? '';
  const availableVersions = useMemo(() => {
    const items = snapshot && !versions.some((version) => version.id === snapshot.id)
      ? [snapshot, ...versions]
      : [...versions];
    const retained = retainedSelectedVersion.current;
    if (
      retained &&
      retained.id === selectedVersionId &&
      retained.system_id === currentSystemId &&
      !items.some((version) => version.id === retained.id)
    ) {
      items.push(retained);
    }
    return items.sort((left, right) => right.version - left.version);
  }, [currentSystemId, selectedVersionId, snapshot, versions]);
  const selectedVersion =
    availableVersions.find((version) => version.id === selectedVersionId) ?? snapshot;
  const manualVersions = useMemo(
    () => availableVersions.filter((version) => version.layer === 'manual' || version.source_type === 'manual'),
    [availableVersions],
  );
  const observedVersions = useMemo(
    () => availableVersions.filter((version) => version.layer === 'observed' || version.source_type === 'scan'),
    [availableVersions],
  );
  const latestManualVersion = manualVersions[0] ?? null;
  const latestObservedVersion = observedVersions[0] ?? null;
  const selectedLayer =
    selectedVersion?.layer ?? (selectedVersion?.source_type === 'scan' ? 'observed' : 'manual');
  const selectedLayerHead =
    selectedLayer === 'manual'
      ? latestManualVersion
      : selectedLayer === 'observed'
        ? latestObservedVersion
        : null;
  const normalized = useMemo(() => normalizeGraph(selectedVersion), [selectedVersion]);
  const [nodes, setNodes, onNodesChange] = useNodesState<EditorNode>(normalized.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<EditorEdge>(normalized.edges);
  const [zones, setZones] = useState<ArchitectureZoneInput[]>(normalized.zones);
  const [riskContexts, setRiskContexts] = useState<EditorRiskContext[]>(
    normalized.riskContexts,
  );
  const [businessContext, setBusinessContext] = useState<ArchitectureBusinessContextInput>(
    normalized.businessContext,
  );
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(
    normalized.nodes[0]?.id ?? null,
  );
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [title, setTitle] = useState(selectedVersion?.title ?? `${systemName} – arkitektur`);
  const [changeNote, setChangeNote] = useState('');
  const [newZoneName, setNewZoneName] = useState('');
  const [contextExposure, setContextExposure] = useState<ArchitectureRiskContextInput['exposure']>('unknown');
  const [contextReachable, setContextReachable] = useState('');
  const [contextControlEffectiveness, setContextControlEffectiveness] = useState('');
  const [contextEvidenceReference, setContextEvidenceReference] = useState('');
  const [saveError, setSaveError] = useState<string | null>(null);
  const [undoStack, setUndoStack] = useState<EditorGraphState[]>([]);
  const [redoStack, setRedoStack] = useState<EditorGraphState[]>([]);
  const [baselineFingerprint, setBaselineFingerprint] = useState(() =>
    editorFingerprint(
      normalized.nodes,
      normalized.edges,
      normalized.zones,
      normalized.riskContexts,
      normalized.businessContext,
      selectedVersion?.title ?? `${systemName} – arkitektur`,
      '',
    ),
  );
  const [flowInstance, setFlowInstance] = useState<ReactFlowInstance<EditorNode, EditorEdge> | null>(
    null,
  );
  const nodesRef = useRef(nodes);
  const edgesRef = useRef(edges);
  const zonesRef = useRef(zones);
  const riskContextsRef = useRef(riskContexts);
  nodesRef.current = nodes;
  edgesRef.current = edges;
  zonesRef.current = zones;
  riskContextsRef.current = riskContexts;

  const currentFingerprint = useMemo(
    () =>
      editorFingerprint(
        nodes,
        edges,
        zones,
        riskContexts,
        businessContext,
        title,
        changeNote,
      ),
    [businessContext, changeNote, edges, nodes, riskContexts, title, zones],
  );
  const dirty = currentFingerprint !== baselineFingerprint;

  const captureGraph = useCallback(
    () => cloneGraphState(
      nodesRef.current,
      edgesRef.current,
      zonesRef.current,
      riskContextsRef.current,
    ),
    [],
  );

  const rememberGraph = useCallback(() => {
    const current = captureGraph();
    setUndoStack((history) => [...history.slice(-(HISTORY_LIMIT - 1)), current]);
    setRedoStack([]);
  }, [captureGraph]);

  const restoreGraph = useCallback(
    (state: EditorGraphState) => {
      const restored = cloneGraphState(
        state.nodes,
        state.edges,
        state.zones,
        state.riskContexts,
      );
      setNodes(restored.nodes);
      setEdges(restored.edges);
      setZones(restored.zones);
      setRiskContexts(restored.riskContexts);
      setSelectedNodeId(null);
      setSelectedEdgeId(null);
    },
    [setEdges, setNodes],
  );

  useEffect(() => {
    if (!selectedVersionId && snapshot) setSelectedVersionId(snapshot.id);
  }, [selectedVersionId, snapshot]);

  useEffect(() => {
    if (selectedVersion) retainedSelectedVersion.current = selectedVersion;
  }, [selectedVersion]);

  useEffect(() => {
    const nextTitle = selectedVersion?.title ?? `${systemName} – arkitektur`;
    setNodes(normalized.nodes);
    setEdges(normalized.edges);
    setZones(normalized.zones);
    setRiskContexts(normalized.riskContexts);
    setBusinessContext(normalized.businessContext);
    setSelectedNodeId(normalized.nodes[0]?.id ?? null);
    setSelectedEdgeId(null);
    setTitle(nextTitle);
    setChangeNote('');
    setUndoStack([]);
    setRedoStack([]);
    setBaselineFingerprint(
      editorFingerprint(
        normalized.nodes,
        normalized.edges,
        normalized.zones,
        normalized.riskContexts,
        normalized.businessContext,
        nextTitle,
        '',
      ),
    );
  }, [selectedVersion?.id, setEdges, setNodes, systemName]);

  useEffect(() => {
    const animationFrame = window.requestAnimationFrame(() =>
      flowInstance?.fitView({ padding: 0.18 }),
    );
    return () => window.cancelAnimationFrame(animationFrame);
  }, [flowInstance, selectedVersion?.id]);

  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);

  useEffect(
    () => () => {
      onDirtyChange?.(false);
    },
    [onDirtyChange],
  );

  useEffect(() => {
    if (!dirty) return undefined;
    const warnBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', warnBeforeUnload);
    return () => window.removeEventListener('beforeunload', warnBeforeUnload);
  }, [dirty]);

  const selectedNode = nodes.find((node) => node.id === selectedNodeId) ?? null;
  const selectedEdge = edges.find((edge) => edge.id === selectedEdgeId) ?? null;
  const selectedRiskBinding = riskBinding(selectedNode);
  const selectedRiskContext = selectedRiskBinding
    ? riskContexts.find(
        (context) =>
          context.asset_id === selectedRiskBinding.assetId &&
          context.service_id === selectedRiskBinding.serviceId,
      ) ?? null
    : null;

  useEffect(() => {
    setContextExposure(selectedRiskContext?.exposure ?? 'unknown');
    setContextReachable(
      selectedRiskContext?.reachable === true
        ? 'true'
        : selectedRiskContext?.reachable === false
          ? 'false'
          : '',
    );
    setContextControlEffectiveness(
      selectedRiskContext?.control_effectiveness === null ||
      selectedRiskContext?.control_effectiveness === undefined
        ? ''
        : String(Math.round(selectedRiskContext.control_effectiveness * 100)),
    );
    setContextEvidenceReference(selectedRiskContext?.evidence_reference ?? '');
  }, [selectedNodeId, selectedRiskContext]);
  const selectedVersionIsHistorical = Boolean(
    selectedVersion && selectedLayerHead && selectedVersion.id !== selectedLayerHead.id,
  );
  const preservingObservedDraft = Boolean(
    dirty &&
    selectedVersionIsHistorical &&
    selectedVersion &&
    selectedLayer === 'observed' &&
    latestManualVersion === null,
  );
  const historical = selectedVersionIsHistorical && !preservingObservedDraft;
  const observedBehindManual = selectedLayer === 'observed' && latestManualVersion !== null;
  const readOnly = !canEdit || historical || selectedLayer === 'proposal' || observedBehindManual;
  // The graph in local state was derived from the selected version. Never silently
  // rebase it onto a scan or manual version that arrived while the analyst edited.
  const saveBaseVersion = selectedVersion ?? latestManualVersion ?? latestObservedVersion;

  const hasRiskSignal =
    contextExposure !== 'unknown' ||
    contextReachable !== '' ||
    contextControlEffectiveness !== '';
  const parsedControlEffectiveness = Number(contextControlEffectiveness);
  const validControlEffectiveness =
    contextControlEffectiveness === '' ||
    (Number.isFinite(parsedControlEffectiveness) &&
      parsedControlEffectiveness >= 0 &&
      parsedControlEffectiveness <= 100);

  function saveRiskContext(): void {
    if (
      readOnly ||
      !selectedRiskBinding ||
      !hasRiskSignal ||
      analystIdentity.trim().length < 2 ||
      contextEvidenceReference.trim().length < 2 ||
      !validControlEffectiveness
    ) return;
    rememberGraph();
    const nextContext: EditorRiskContext = {
      asset_id: selectedRiskBinding.assetId,
      service_id: selectedRiskBinding.serviceId,
      exposure: contextExposure,
      reachable:
        contextReachable === 'true' ? true : contextReachable === 'false' ? false : null,
      control_effectiveness:
        contextControlEffectiveness === ''
          ? null
          : Number(contextControlEffectiveness) / 100,
      evidence_reference: contextEvidenceReference.trim(),
      verified_by: null,
      verified_at: null,
    };
    setRiskContexts((current) => [
      ...current.filter(
        (context) =>
          context.asset_id !== nextContext.asset_id ||
          context.service_id !== nextContext.service_id,
      ),
      nextContext,
    ]);
  }

  function removeRiskContext(): void {
    if (readOnly || !selectedRiskBinding || !selectedRiskContext) return;
    rememberGraph();
    setRiskContexts((current) =>
      current.filter(
        (context) =>
          context.asset_id !== selectedRiskBinding.assetId ||
          context.service_id !== selectedRiskBinding.serviceId,
      ),
    );
  }

  function confirmDiscardChanges(): boolean {
    return (
      !dirty ||
      window.confirm(
        'Du har osparade arkitekturändringar. Vill du kasta dem och fortsätta?',
      )
    );
  }

  function undoGraph() {
    if (readOnly) return;
    const previous = undoStack.at(-1);
    if (!previous) return;
    const current = captureGraph();
    setUndoStack((history) => history.slice(0, -1));
    setRedoStack((history) => [...history.slice(-(HISTORY_LIMIT - 1)), current]);
    restoreGraph(previous);
  }

  function redoGraph() {
    if (readOnly) return;
    const next = redoStack.at(-1);
    if (!next) return;
    const current = captureGraph();
    setRedoStack((history) => history.slice(0, -1));
    setUndoStack((history) => [...history.slice(-(HISTORY_LIMIT - 1)), current]);
    restoreGraph(next);
  }

  const addNode = useCallback(
    (kind: ArchitectureNodeKind, position?: { x: number; y: number }) => {
      if (readOnly) return;
      rememberGraph();
      const paletteItem = palette.find((item) => item.kind === kind);
      const id = makeId('node');
      const next: EditorNode = {
        id,
        type: 'architectureComponent',
        position: position ?? { x: 160 + nodes.length * 22, y: 100 + nodes.length * 18 },
        data: {
          name: `Ny ${paletteItem?.label.toLowerCase() ?? 'komponent'}`,
          kind,
          zoneId: zones[0]?.id ?? null,
          properties: {},
          provenance: 'manual',
        },
      };
      setNodes((current) => [...current, next]);
      setSelectedNodeId(id);
      setSelectedEdgeId(null);
    },
    [nodes.length, readOnly, rememberGraph, setNodes, zones],
  );

  const onConnect = useCallback(
    (connection: Connection) => {
      if (readOnly) return;
      if (!connection.source || !connection.target || connection.source === connection.target) return;
      rememberGraph();
      setEdges((current) =>
        addEdge<EditorEdge>(
          {
            ...connection,
            id: makeId('edge'),
            markerEnd: { type: MarkerType.ArrowClosed },
            data: { protocol: null, encrypted: null, properties: {} },
          },
          current,
        ),
      );
    },
    [readOnly, rememberGraph, setEdges],
  );

  const onNodeClick = useCallback<NodeMouseHandler<EditorNode>>((_, node) => {
    setSelectedNodeId(node.id);
    setSelectedEdgeId(null);
  }, []);
  const onEdgeClick = useCallback<EdgeMouseHandler<EditorEdge>>((_, edge) => {
    setSelectedEdgeId(edge.id);
    setSelectedNodeId(null);
  }, []);

  function updateSelectedNode(patch: Partial<EditorNodeData>) {
    if (readOnly || !selectedNodeId) return;
    rememberGraph();
    setNodes((current) =>
      current.map((node) =>
        node.id === selectedNodeId ? { ...node, data: { ...node.data, ...patch } } : node,
      ),
    );
  }

  function updateSelectedEdge(patch: Partial<EditorEdgeData> & { label?: string }) {
    if (readOnly || !selectedEdgeId) return;
    rememberGraph();
    const { label: nextLabel, ...dataPatch } = patch;
    setEdges((current) =>
      current.map((edge) =>
        edge.id === selectedEdgeId
          ? {
              ...edge,
              label: nextLabel ?? edge.label,
              data: {
                protocol:
                  dataPatch.protocol !== undefined
                    ? dataPatch.protocol
                    : (edge.data?.protocol ?? null),
                encrypted:
                  dataPatch.encrypted !== undefined
                    ? dataPatch.encrypted
                    : (edge.data?.encrypted ?? null),
                properties: dataPatch.properties ?? edge.data?.properties ?? {},
              },
            }
          : edge,
      ),
    );
  }

  function removeSelection() {
    if (readOnly) return;
    if (selectedNodeId) {
      rememberGraph();
      setNodes((current) => current.filter((node) => node.id !== selectedNodeId));
      setEdges((current) =>
        current.filter(
          (edge) => edge.source !== selectedNodeId && edge.target !== selectedNodeId,
        ),
      );
      setSelectedNodeId(null);
    } else if (selectedEdgeId) {
      rememberGraph();
      setEdges((current) => current.filter((edge) => edge.id !== selectedEdgeId));
      setSelectedEdgeId(null);
    }
  }

  function addZone() {
    if (readOnly) return;
    const name = newZoneName.trim();
    if (!name) return;
    rememberGraph();
    setZones((current) => [
      ...current,
      { id: makeId('zone'), name, trust_boundary: 'unconfirmed' },
    ]);
    setNewZoneName('');
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    if (readOnly) return;
    const kind = event.dataTransfer.getData('application/traceless-architecture-kind');
    if (!allowedKinds.has(kind as ArchitectureNodeKind)) return;
    const position = flowInstance?.screenToFlowPosition({ x: event.clientX, y: event.clientY });
    addNode(kind as ArchitectureNodeKind, position);
  }

  async function saveVersion() {
    const graph = buildGraph(nodes, edges, zones, riskContexts, businessContext);
    setSaveError(null);
    try {
      await onSave({
        title: title.trim(),
        change_note: changeNote.trim(),
        base_snapshot_id: saveBaseVersion?.id ?? null,
        graph,
      });
      setBaselineFingerprint(
        editorFingerprint(
          nodes,
          edges,
          zones,
          riskContexts,
          businessContext,
          title,
          changeNote,
        ),
      );
      setUndoStack([]);
      setRedoStack([]);
      setSelectedVersionId('');
    } catch (error) {
      setSaveError(
        error instanceof Error
          ? error.message
          : 'Arkitekturversionen kunde inte sparas. Dina ändringar finns kvar.',
      );
    }
  }

  return (
    <div className="op-architecture-editor">
      <header className="op-editor-header">
        <div>
          <span className="section-kicker">VERSIONERAD ARKITEKTURMODELL</span>
          <h2>Rita komponenter och dataflöden</h2>
          <p>Drag komponenter till ytan. Koppla höger handtag till vänster handtag.</p>
        </div>
        <div className="op-editor-header__actions">
          <label>
            Version
            <select
              aria-label="Arkitekturversion"
              value={selectedVersion?.id ?? ''}
              onChange={(event) => {
                if (event.target.value === selectedVersion?.id || confirmDiscardChanges()) {
                  setSelectedVersionId(event.target.value);
                  setSaveError(null);
                }
              }}
            >
              {!selectedVersion && <option value="">Ny tom modell</option>}
              {manualVersions.length > 0 && (
                <optgroup label="Manuellt lager">
                  {manualVersions.map((version) => (
                    <option key={version.id} value={version.id}>v{version.version} · manuell · {version.status}</option>
                  ))}
                </optgroup>
              )}
              {observedVersions.length > 0 && (
                <optgroup label="Observerad topologi">
                  {observedVersions.map((version) => (
                    <option key={version.id} value={version.id}>v{version.version} · skanning · {version.status}</option>
                  ))}
                </optgroup>
              )}
            </select>
          </label>
          <div className="op-editor-history" role="group" aria-label="Ändringshistorik">
            <button
              aria-label="Ångra senaste diagramändringen"
              className="secondary-button"
              disabled={readOnly || undoStack.length === 0}
              onClick={undoGraph}
              type="button"
            >
              Ångra
            </button>
            <button
              aria-label="Gör om senaste diagramändringen"
              className="secondary-button"
              disabled={readOnly || redoStack.length === 0}
              onClick={redoGraph}
              type="button"
            >
              Gör om
            </button>
          </div>
          <button
            className="secondary-button"
            disabled={readOnly}
            type="button"
            onClick={() => {
              if (!confirmDiscardChanges()) return;
              rememberGraph();
              setNodes([]);
              setEdges([]);
              setZones([]);
              setRiskContexts([]);
              setSelectedNodeId(null);
              setSelectedEdgeId(null);
            }}
          >
            Ny tom yta
          </button>
        </div>
      </header>

      <div className="op-architecture-layers" role="note">
        <span className={`op-layer-badge op-layer-badge--${selectedLayer}`}>
          {selectedLayer === 'manual'
            ? 'Manuellt lager'
            : selectedLayer === 'observed'
              ? 'Observerad topologi'
              : 'Skrivskyddad version'}
        </span>
        <p>
          {selectedLayer === 'manual'
            ? 'Detta lager redigeras och versionshanteras av analytiker. Nya skanningar ersätter det inte.'
            : selectedLayer === 'observed'
              ? latestManualVersion
                ? 'Detta lager kommer från skanningsevidens och visas separat från analytikerns manuella modell.'
                : 'Detta lager kommer från skanningsevidens. Redigeringar sparas som ett nytt manuellt lager.'
              : 'Versionen kan granskas men inte redigeras i denna vy.'}
        </p>
        <div className="op-provenance-legend" aria-label="Komponentursprung">
          <span><i className="is-manual" /> Manuell</span>
          <span><i className="is-observed" /> Observerad</span>
          <span><i className="is-imported" /> Importerad</span>
        </div>
      </div>

      {historical && (
        <div className="op-architecture__warning">
          <Icon name="history" size={16} /> Du granskar en historisk version av detta lager. Växla
          till lagrets senaste version för att fortsätta.
        </div>
      )}

      {preservingObservedDraft && (
        <div className="op-architecture__warning">
          <Icon name="history" size={16} /> En ny observerad topologi har kommit. Dina osparade
          ändringar behålls och sparas med v{selectedVersion?.version} som bas; den nya skanningen
          slås inte ihop automatiskt.
        </div>
      )}

      {observedBehindManual && (
        <div className="op-architecture__warning">
          <Icon name="shield" size={16} /> Den observerade topologin visas skrivskyddad. Växla till
          senaste manuella versionen för att fortsätta redigera utan att en skanning ersätter arbetet.
        </div>
      )}

      {!canEdit && (
        <div className="op-architecture__warning">
          <Icon name="shield" size={16} /> Din roll har läsbehörighet. Endast analytiker kan spara
          manuella arkitekturversioner.
        </div>
      )}

      {dirty && (
        <div className="op-editor-unsaved" role="status">
          <Icon name="alert" size={16} /> Osparade arkitekturändringar. Spara en ny version eller
          ångra ändringarna innan du lämnar vyn.
        </div>
      )}



<section className="op-business-context panel" aria-label="Verksamhetskontext">
  <header className="op-section-heading">
    <div>
      <span className="section-kicker">CYBER RISK CONTEXT</span>
      <h2>Koppla arkitekturen till verksamheten</h2>
    </div>
    <small>Kontexten versionshanteras med den manuella arkitekturmodellen och används i riskgrafen.</small>
  </header>
  <div className="op-business-context__grid">
    <label><span>Affärsägare</span><input disabled={readOnly} value={businessContext.business_owner} onChange={(event) => setBusinessContext((current) => ({ ...current, business_owner: event.target.value }))} /></label>
    <label><span>Verksamhetsförmågor, kommaseparerade</span><input disabled={readOnly} value={businessContext.capabilities.join(', ')} onChange={(event) => setBusinessContext((current) => ({ ...current, capabilities: parseCommaSeparated(event.target.value) }))} /></label>
    <label><span>Processer, kommaseparerade</span><input disabled={readOnly} value={businessContext.processes.join(', ')} onChange={(event) => setBusinessContext((current) => ({ ...current, processes: parseCommaSeparated(event.target.value) }))} /></label>
    <label><span>Datakategorier, kommaseparerade</span><input disabled={readOnly} value={businessContext.data_categories.join(', ')} onChange={(event) => setBusinessContext((current) => ({ ...current, data_categories: parseCommaSeparated(event.target.value) }))} /></label>
    <label><span>Regelverk, kommaseparerade</span><input disabled={readOnly} value={businessContext.regulations.join(', ')} onChange={(event) => setBusinessContext((current) => ({ ...current, regulations: parseCommaSeparated(event.target.value) }))} /></label>
    <label><span>RTO, timmar</span><input disabled={readOnly} min={0} step="0.5" type="number" value={businessContext.recovery_time_objective_hours ?? ''} onChange={(event) => setBusinessContext((current) => ({ ...current, recovery_time_objective_hours: event.target.value === '' ? null : Number(event.target.value) }))} /></label>
    <label><span>RPO, timmar</span><input disabled={readOnly} min={0} step="0.5" type="number" value={businessContext.recovery_point_objective_hours ?? ''} onChange={(event) => setBusinessContext((current) => ({ ...current, recovery_point_objective_hours: event.target.value === '' ? null : Number(event.target.value) }))} /></label>
  </div>
  <div className="op-business-impact" role="group" aria-label="Konsekvensprofil">
    {([
      ['confidentiality', 'Konfidentialitet'],
      ['integrity', 'Riktighet'],
      ['availability', 'Tillgänglighet'],
      ['financial', 'Finansiell'],
      ['regulatory', 'Regulatorisk'],
      ['reputation', 'Anseende'],
      ['safety', 'Säkerhet för person'],
    ] as const).map(([key, label]) => (
      <label key={key}><span>{label}</span><select disabled={readOnly} value={businessContext.impact[key]} onChange={(event) => setBusinessContext((current) => ({ ...current, impact: { ...current.impact, [key]: Number(event.target.value) } }))}>{[1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}/5</option>)}</select></label>
    ))}
  </div>
</section>

      <div className="op-editor-shell">
        <aside className="op-editor-library">
          <span className="section-kicker">KOMPONENTER</span>
          <div className="op-editor-palette">
            {palette.map((item) => (
              <button
                disabled={readOnly}
                draggable
                key={item.kind}
                type="button"
                onClick={() => addNode(item.kind)}
                onDragStart={(event) =>
                  event.dataTransfer.setData(
                    'application/traceless-architecture-kind',
                    item.kind,
                  )
                }
              >
                <span><Icon name={item.icon} size={17} /></span>
                <strong>{item.label}</strong>
                <Icon name="plus" size={14} />
              </button>
            ))}
          </div>
          <div className="op-editor-zones">
            <span className="section-kicker">TRUST ZONES</span>
            {zones.map((zone) => (
              <div key={zone.id}>
                <i />
                <span><strong>{zone.name}</strong><small>{zone.trust_boundary}</small></span>
              </div>
            ))}
            <label>
              <span>Ny zon</span>
              <input
                aria-label="Namn på ny zon"
                disabled={readOnly}
                value={newZoneName}
                onChange={(event) => setNewZoneName(event.target.value)}
                placeholder="Exempel: DMZ"
              />
            </label>
            <button className="secondary-button" disabled={readOnly || !newZoneName.trim()} onClick={addZone}>
              <Icon name="plus" size={14} /> Lägg till zon
            </button>
          </div>
        </aside>

        <section className="op-editor-canvas">
          <div
            className="op-editor-flow"
            onDragOver={(event) => {
              event.preventDefault();
              event.dataTransfer.dropEffect = 'move';
            }}
            onDrop={handleDrop}
          >
            <ReactFlow<EditorNode, EditorEdge>
              deleteKeyCode={readOnly ? null : ['Backspace', 'Delete']}
              edges={edges}
              edgesReconnectable={!readOnly}
              elementsSelectable
              fitView
              fitViewOptions={{ padding: 0.18 }}
              maxZoom={1.8}
              minZoom={0.25}
              nodeTypes={nodeTypes}
              nodes={nodes}
              nodesConnectable={!readOnly}
              nodesDraggable={!readOnly}
              onConnect={onConnect}
              onEdgeClick={onEdgeClick}
              onEdgesChange={(changes) => {
                if (readOnly) return;
                if (changes.some((change) => change.type === 'remove')) rememberGraph();
                onEdgesChange(changes);
              }}
              onInit={setFlowInstance}
              onNodeClick={onNodeClick}
              onNodeDragStart={() => {
                if (!readOnly) rememberGraph();
              }}
              onNodesChange={(changes) => {
                if (readOnly) return;
                if (changes.some((change) => change.type === 'remove')) rememberGraph();
                onNodesChange(changes);
              }}
              snapGrid={[16, 16]}
              snapToGrid
            >
              <Background color="#cfd7e4" gap={18} size={1} variant={BackgroundVariant.Dots} />
              <MiniMap pannable zoomable />
              <Controls showInteractive={false} />
            </ReactFlow>
            {nodes.length === 0 && (
              <div className="op-editor-empty">
                <Icon name="architecture" size={28} />
                <strong>Börja rita arkitekturen</strong>
                <span>Dra in en komponent från biblioteket eller klicka på den.</span>
              </div>
            )}
          </div>
          <footer>
            <span><Icon name="check" size={14} /> {nodes.length} komponenter</span>
            <span>{edges.length} dataflöden</span>
            <span>{zones.length} trust zones</span>
            <span>{riskContexts.length} verifierade riskkontexter</span>
          </footer>
        </section>

        <aside className="op-editor-inspector">
          <span className="section-kicker">EGENSKAPER</span>
          {selectedNode ? (
            <>
              <h3>{selectedNode.data.name}</h3>
              <label>
                Namn
                <input
                  aria-label="Komponentnamn"
                  disabled={readOnly}
                  value={selectedNode.data.name}
                  onChange={(event) => updateSelectedNode({ name: event.target.value })}
                />
              </label>
              <label>
                Typ
                <select
                  aria-label="Komponenttyp"
                  disabled={readOnly}
                  value={selectedNode.data.kind}
                  onChange={(event) =>
                    updateSelectedNode({ kind: event.target.value as ArchitectureNodeKind })
                  }
                >
                  {[...allowedKinds].map((kind) => <option key={kind}>{kind}</option>)}
                </select>
              </label>
              <label>
                Trust zone
                <select
                  aria-label="Komponentens trust zone"
                  disabled={readOnly}
                  value={selectedNode.data.zoneId ?? ''}
                  onChange={(event) => updateSelectedNode({ zoneId: event.target.value || null })}
                >
                  <option value="">Ingen zon</option>
                  {zones.map((zone) => <option key={zone.id} value={zone.id}>{zone.name}</option>)}
                </select>
              </label>
              <label>
                Teknik
                <input
                  aria-label="Komponentteknik"
                  disabled={readOnly}
                  value={stringValue(selectedNode.data.properties.technology) ?? ''}
                  onChange={(event) =>
                    updateSelectedNode({
                      properties: { ...selectedNode.data.properties, technology: event.target.value },
                    })
                  }
                  placeholder="Exempel: PostgreSQL 16"
                />
              </label>
              <label>
                Adress / endpoint
                <input
                  aria-label="Komponentadress"
                  disabled={readOnly}
                  value={stringValue(selectedNode.data.properties.ip) ?? ''}
                  onChange={(event) =>
                    updateSelectedNode({
                      properties: { ...selectedNode.data.properties, ip: event.target.value },
                    })
                  }
                  placeholder="IP, FQDN eller URL"
                />
              </label>
              <small className="op-editor-provenance">
                Ursprung: {selectedNode.data.provenance} · {selectedNode.id}
              </small>
              <section className="op-risk-context-editor" aria-label="Verifierad riskkontext">
                <strong>Verifierad riskkontext</strong>
                {selectedRiskBinding ? (
                  <>
                    <small>
                      Kopplad till asset {selectedRiskBinding.assetId}
                      {selectedRiskBinding.serviceId ? ` / tjänst ${selectedRiskBinding.serviceId}` : ''}.
                    </small>
                    <label>
                      Exponering
                      <select
                        aria-label="Verifierad exponering"
                        disabled={readOnly}
                        value={contextExposure}
                        onChange={(event) => setContextExposure(event.target.value as ArchitectureRiskContextInput['exposure'])}
                      >
                        <option value="unknown">Okänd</option>
                        <option value="external">Extern</option>
                        <option value="internal">Intern</option>
                        <option value="isolated">Isolerad</option>
                      </select>
                    </label>
                    <label>
                      Nåbarhet
                      <select
                        aria-label="Verifierad nåbarhet"
                        disabled={readOnly}
                        value={contextReachable}
                        onChange={(event) => setContextReachable(event.target.value)}
                      >
                        <option value="">Ej verifierad</option>
                        <option value="true">Nåbar</option>
                        <option value="false">Inte nåbar</option>
                      </select>
                    </label>
                    <label>
                      Kontrollernas effektivitet (%)
                      <input
                        aria-label="Verifierad kontrolleffektivitet"
                        aria-invalid={!validControlEffectiveness}
                        disabled={readOnly}
                        min="0"
                        max="100"
                        step="1"
                        type="number"
                        value={contextControlEffectiveness}
                        onChange={(event) => setContextControlEffectiveness(event.target.value)}
                      />
                    </label>
                    {!validControlEffectiveness && (
                      <small className="op-error-copy">Ange ett värde mellan 0 och 100 procent.</small>
                    )}
                    <label>
                      Verifierad av
                      <input
                        aria-label="Riskkontext verifierad av"
                        readOnly
                        value={selectedRiskContext?.verified_by ?? analystIdentity}
                      />
                    </label>
                    <label>
                      Verifierad tid
                      <input
                        aria-label="Riskkontext verifierad tid"
                        readOnly
                        value={formatVerifiedAt(selectedRiskContext?.verified_at ?? null)}
                      />
                    </label>
                    <small>
                      Identitet och tid hämtas från den autentiserade användaren och serverklockan;
                      de kan inte anges av webbläsaren.
                    </small>
                    <label>
                      Evidensreferens
                      <input
                        aria-label="Riskkontext evidensreferens"
                        disabled={readOnly}
                        minLength={2}
                        placeholder="Ärende, testprotokoll eller käll-ID"
                        value={contextEvidenceReference}
                        onChange={(event) => setContextEvidenceReference(event.target.value)}
                      />
                    </label>
                    <button
                      className="secondary-button"
                      disabled={
                        readOnly ||
                        !hasRiskSignal ||
                        !validControlEffectiveness ||
                        analystIdentity.trim().length < 2 ||
                        contextEvidenceReference.trim().length < 2
                      }
                      onClick={saveRiskContext}
                      type="button"
                    >
                      {selectedRiskContext ? 'Uppdatera riskkontext' : 'Lägg till riskkontext'}
                    </button>
                    {selectedRiskContext && (
                      <button className="danger-button" disabled={readOnly} onClick={removeRiskContext} type="button">
                        Ta bort riskkontext
                      </button>
                    )}
                  </>
                ) : (
                  <small>
                    Komponenten saknar bindning till en observerad asset eller tjänst. Riskkontext
                    kan därför inte påverka riskmotorn.
                  </small>
                )}
              </section>
              <button className="danger-button" disabled={readOnly} type="button" onClick={removeSelection}>
                Ta bort komponent
              </button>
            </>
          ) : selectedEdge ? (
            <>
              <h3>Dataflöde</h3>
              <label>
                Etikett
                <input
                  aria-label="Dataflödesetikett"
                  disabled={readOnly}
                  value={typeof selectedEdge.label === 'string' ? selectedEdge.label : ''}
                  onChange={(event) => updateSelectedEdge({ label: event.target.value })}
                  placeholder="Exempel: Kunddata"
                />
              </label>
              <label>
                Protokoll
                <input
                  aria-label="Dataflödesprotokoll"
                  disabled={readOnly}
                  value={selectedEdge.data?.protocol ?? ''}
                  onChange={(event) => updateSelectedEdge({ protocol: event.target.value || null })}
                  placeholder="HTTPS, SQL, Kafka…"
                />
              </label>
              <label className="op-editor-checkbox">
                <input
                  checked={selectedEdge.data?.encrypted === true}
                  disabled={readOnly}
                  type="checkbox"
                  onChange={(event) => updateSelectedEdge({ encrypted: event.target.checked })}
                />
                Krypterat flöde
              </label>
              <small className="op-editor-provenance">
                {selectedEdge.source} → {selectedEdge.target}
              </small>
              <button className="danger-button" disabled={readOnly} type="button" onClick={removeSelection}>
                Ta bort dataflöde
              </button>
            </>
          ) : (
            <p>Välj en komponent eller ett dataflöde för att redigera dess egenskaper.</p>
          )}
        </aside>
      </div>

      {saveError && (
        <div className="op-feedback op-feedback--error" role="alert">
          <Icon name="alert" size={16} /> {saveError} Dina osparade ändringar finns kvar.
        </div>
      )}

      <footer className="op-editor-savebar">
        <label>
          Modellnamn
          <input disabled={readOnly} value={title} onChange={(event) => setTitle(event.target.value)} />
        </label>
        <label>
          Ändringsnotering
          <input
            disabled={readOnly}
            value={changeNote}
            onChange={(event) => setChangeNote(event.target.value)}
            placeholder="Vad ändrades i den här versionen?"
          />
        </label>
        <button
          className="primary-button"
          disabled={busy || readOnly || !dirty || title.trim().length < 2}
          onClick={() => void saveVersion()}
          type="button"
        >
          <Icon name="check" size={15} /> Spara som ny version
        </button>
      </footer>
    </div>
  );
}
