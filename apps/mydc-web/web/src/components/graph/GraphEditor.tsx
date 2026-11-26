// SPDX-License-Identifier: Apache-2.0

/**
 * 그래프로 작성·편집 (UI-39). Rete.js v2 + React 렌더.
 * app.yaml이 원본이다. 그래프를 고치면 원문을 고쳐 onChange로 돌려주고,
 * 밖에서 원문이 바뀌면(app.yaml 칸 직접 편집) 그래프를 다시 그린다. 배치 좌표는 원문에 넣지 않는다.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ClassicPreset, NodeEditor, type GetSchemes } from 'rete';
import { AreaExtensions, AreaPlugin } from 'rete-area-plugin';
import { ConnectionPlugin, Presets as ConnectionPresets } from 'rete-connection-plugin';
import { Presets, ReactPlugin, type ReactArea2D, type RenderEmit } from 'rete-react-plugin';
import { autoLayout, checkGraph, edgeId, edgeKindFor, graphToYaml, nodeId, yamlToGraph, type AppGraph, type EdgeKind, type GEdge, type GNode, type NodeKind } from '../../lib/appGraph';
import { Field } from '../ui';
import { PortsField } from '../PortsField';

// ── Rete 스킴 ──

const socket = new ClassicPreset.Socket('link');
class Block extends ClassicPreset.Node {
  width = 210;
  height = 0;
  constructor(
    public gid: string,
    public kind: NodeKind,
    label: string,
    public summary: string,
  ) {
    super(label);
  }
}
class Link extends ClassicPreset.Connection<Block, Block> {
  kind: EdgeKind = 'network';
  gid = '';
}
type Schemes = GetSchemes<Block, Link>;
type AreaExtra = ReactArea2D<Schemes>;

const KIND_LABEL: Record<NodeKind, string> = { service: '서비스', network: '망', volume: '데이터 저장소', secret: '비밀값', ingress: '외부 접속' };
const KIND_COLOR: Record<NodeKind, string> = { service: '#3b6fd8', network: '#2e9b5f', volume: '#b7791f', secret: '#9b4dca', ingress: '#178a9a' };
const EDGE_COLOR: Record<EdgeKind, string> = { network: '#2e9b5f', volume: '#b7791f', secret: '#9b4dca', depends: '#8a94a6', route: '#178a9a' };
const EDGE_LABEL: Record<EdgeKind, string> = { network: '망 연결', volume: '마운트', secret: '비밀값 공급', depends: '시작 순서', route: '외부 접속 경로' };
/** 나가는 연결점: 블록 종류별 */
const OUTPUTS: Partial<Record<NodeKind, { key: string; label: string; to: NodeKind }[]>> = {
  service: [
    { key: 'network', label: '망', to: 'network' },
    { key: 'volume', label: '저장소', to: 'volume' },
    { key: 'secret', label: '비밀값', to: 'secret' },
    { key: 'depends', label: '먼저 띄울 서비스', to: 'service' },
  ],
  ingress: [{ key: 'route', label: '경로 → 서비스', to: 'service' }],
};
const INPUT_LABEL: Record<NodeKind, string | undefined> = { service: '쓰는 쪽', network: '쓰는 서비스', volume: '쓰는 서비스', secret: '쓰는 서비스', ingress: undefined };

function summaryOf(n: GNode, g: AppGraph): string {
  if (n.kind === 'service') {
    const s = n.service!;
    return [s.image || '이미지 없음', s.replicas > 1 ? `복제본 ${s.replicas}` : '', s.node ? `서버 ${s.node}` : ''].filter(Boolean).join(' · ');
  }
  const users = g.edges.filter((e) => e.to === n.id).length;
  if (n.kind === 'ingress') return `경로 ${g.edges.filter((e) => e.from === n.id).length}개`;
  return users ? `서비스 ${users}개가 씀` : '쓰는 서비스 없음';
}

function makeBlock(n: GNode, g: AppGraph): Block {
  const b = new Block(n.id, n.kind, `${KIND_LABEL[n.kind]} · ${n.name}`, summaryOf(n, g));
  const inLabel = INPUT_LABEL[n.kind];
  if (inLabel) b.addInput('in', new ClassicPreset.Input(socket, inLabel, true));
  for (const o of OUTPUTS[n.kind] ?? []) b.addOutput(o.key, new ClassicPreset.Output(socket, o.label, true));
  // 화면 맞추기(zoomAt)가 쓰는 크기: 머리줄 + 연결점 줄
  b.height = 50 + (Object.keys(b.inputs).length + Object.keys(b.outputs).length) * 22 + 8;
  return b;
}

/** 블록: 머리줄(종류 색·이름) → 요약 → 나가는 연결점(오른쪽) → 들어오는 연결점(왼쪽) */
function BlockView({ data, emit }: { data: Block & { selected?: boolean }; emit: RenderEmit<Schemes> }) {
  const color = KIND_COLOR[data.kind];
  return (
    <div className={`g-node${data.selected ? ' selected' : ''}`} style={{ borderColor: color }} data-testid="node">
      <div className="g-title" style={{ background: color }} data-testid="title">
        {data.label}
        <small>{data.summary}</small>
      </div>
      {Object.entries(data.outputs).map(
        ([key, out]) =>
          out && (
            <div className="g-port out" key={key} data-testid={`output-${key}`}>
              <span>{out.label}</span>
              <Presets.classic.RefSocket name="output-socket" side="output" socketKey={key} nodeId={data.id} emit={emit} payload={out.socket} data-testid="output-socket" />
            </div>
          ),
      )}
      {Object.entries(data.inputs).map(
        ([key, inp]) =>
          inp && (
            <div className="g-port in" key={key} data-testid={`input-${key}`}>
              <Presets.classic.RefSocket name="input-socket" side="input" socketKey={key} nodeId={data.id} emit={emit} payload={inp.socket} data-testid="input-socket" />
              <span>{inp.label}</span>
            </div>
          ),
      )}
    </div>
  );
}

const defaultProps = (kind: EdgeKind, to: GNode): GEdge['props'] => {
  switch (kind) {
    case 'volume':
      return { target: `/data/${to.name}`, readOnly: false };
    case 'secret':
      return { mode: 'file', envName: '' };
    case 'route':
      return { path: '/', port: to.service?.ports[0]?.split(':').pop()?.split('/')[0] ?? '', gateway: 'local' };
    case 'network':
      return { alias: '' };
    default:
      return {};
  }
};

export interface GraphChoices {
  networks: string[];
  volumes: string[];
  secrets: string[];
  nodes: string[];
}

export default function GraphEditor({
  yaml,
  onChange,
  choices,
  positions,
  onPositions,
  readOnly = false,
}: {
  yaml: string;
  onChange: (yaml: string) => void;
  choices: GraphChoices;
  positions?: Record<string, { x: number; y: number }>;
  /** 블록을 옮긴 뒤(끌기 끝) 한 번 */
  onPositions?: (pos: Record<string, { x: number; y: number }>) => void;
  readOnly?: boolean;
}) {
  const host = useRef<HTMLDivElement>(null);
  const shell = useRef<HTMLDivElement>(null);
  const [graph, setGraph] = useState<AppGraph>();
  const [parseError, setParseError] = useState<string>();
  const [sel, setSel] = useState<{ node?: string; edge?: string }>({});
  const [notice, setNotice] = useState<string>();
  const [full, setFull] = useState(false);
  const ed = useRef<{ editor: NodeEditor<Schemes>; area: AreaPlugin<Schemes, AreaExtra> }>();
  const graphRef = useRef<AppGraph>();
  const yamlRef = useRef(yaml);
  const lastEmitted = useRef<string>();
  const posRef = useRef<Record<string, { x: number; y: number }>>({ ...(positions ?? {}) });
  const building = useRef(false);
  const selRef = useRef(setSel);
  const readOnlyRef = useRef(readOnly);
  readOnlyRef.current = readOnly;
  yamlRef.current = yaml;

  /** 모델을 바꾸고 원문을 다시 만든다 */
  const commit = useCallback(
    (next: AppGraph) => {
      graphRef.current = next;
      setGraph(next);
      const text = graphToYaml(next, yamlRef.current);
      lastEmitted.current = text;
      onChange(text);
    },
    [onChange],
  );
  const commitRef = useRef(commit);
  commitRef.current = commit;

  // ── 편집기 만들기(한 번) ──
  useEffect(() => {
    const container = host.current;
    if (!container) return;
    const editor = new NodeEditor<Schemes>();
    const area = new AreaPlugin<Schemes, AreaExtra>(container);
    const connection = new ConnectionPlugin<Schemes, AreaExtra>();
    const render = new ReactPlugin<Schemes, AreaExtra>({ createRoot });
    AreaExtensions.selectableNodes(area, AreaExtensions.selector(), { accumulating: AreaExtensions.accumulateOnCtrl() });
    render.addPreset(
      Presets.classic.setup({
        customize: {
          node() {
            return BlockView as never;
          },
          socket() {
            return () => <span className="g-socket" />;
          },
          connection() {
            return (props: { data: Link }) => {
              const kind = props.data.kind;
              // eslint-disable-next-line react-hooks/rules-of-hooks
              const { path } = Presets.classic.useConnection();
              if (!path) return null;
              return (
                <svg className="g-conn" data-kind={kind}>
                  <path d={path} fill="none" stroke="transparent" strokeWidth={14} style={{ pointerEvents: 'auto', cursor: 'pointer' }} onPointerDown={(e) => (e.stopPropagation(), selRef.current({ edge: props.data.gid }))} />
                  <path d={path} fill="none" stroke={EDGE_COLOR[kind]} strokeWidth={2.5} strokeDasharray={kind === 'depends' ? '6 5' : undefined} />
                </svg>
              );
            };
          },
        },
      }),
    );
    connection.addPreset(ConnectionPresets.classic.setup());
    editor.use(area);
    area.use(connection);
    area.use(render);
    AreaExtensions.simpleNodesOrder(area);

    editor.addPipe((ctx) => {
      if (building.current) return ctx;
      const g = graphRef.current;
      if (!g) return ctx;
      if (ctx.type === 'connectioncreate') {
        if (readOnlyRef.current) return undefined;
        const c = ctx.data;
        const from = editor.getNode(c.source);
        const to = editor.getNode(c.target);
        if (!from || !to) return undefined;
        const want = OUTPUTS[from.kind]?.find((o) => o.key === c.sourceOutput);
        const kind = edgeKindFor(from.kind, to.kind);
        if (!want || want.to !== to.kind || !kind) {
          setNotice(`${KIND_LABEL[from.kind]}의 '${want?.label ?? c.sourceOutput}' 연결점은 ${want ? KIND_LABEL[want.to] : '이 블록'}에만 이을 수 있습니다.`);
          return undefined;
        }
        if (from.gid === to.gid) {
          setNotice('자기 자신에게는 이을 수 없습니다.');
          return undefined;
        }
        if (g.edges.some((e) => e.from === from.gid && e.to === to.gid && e.kind === kind && kind !== 'route' && kind !== 'volume')) {
          setNotice('이미 이어져 있습니다.');
          return undefined;
        }
        return ctx;
      }
      if (ctx.type === 'connectioncreated') {
        const c = ctx.data as Link;
        const from = editor.getNode(c.source);
        const to = editor.getNode(c.target);
        if (!from || !to) return ctx;
        const kind = edgeKindFor(from.kind, to.kind)!;
        const toNode = g.nodes.find((n) => n.id === to.gid)!;
        const e: GEdge = { id: edgeId(), kind, from: from.gid, to: to.gid, props: defaultProps(kind, toNode) };
        c.kind = kind;
        c.gid = e.id;
        setNotice(undefined);
        commitRef.current({ ...g, edges: [...g.edges, e] });
        selRef.current({ edge: e.id });
        void area.update('connection', c.id);
      }
      if (ctx.type === 'connectionremoved') {
        const c = ctx.data as Link;
        if (c.gid) commitRef.current({ ...g, edges: g.edges.filter((e) => e.id !== c.gid) });
      }
      return ctx;
    });
    area.addPipe((ctx) => {
      if (ctx.type === 'nodepicked') {
        const b = editor.getNode(ctx.data.id);
        if (b) selRef.current({ node: b.gid });
      }
      if (ctx.type === 'nodetranslated' && !building.current) {
        const b = editor.getNode(ctx.data.id);
        if (b) posRef.current[b.gid] = { ...ctx.data.position };
      }
      if (ctx.type === 'nodedragged') onPosRef.current?.({ ...posRef.current });
      if (ctx.type === 'pointerdown' && (ctx.data.event.target as HTMLElement) === container) selRef.current({});
      return ctx;
    });
    ed.current = { editor, area };
    return () => {
      ed.current = undefined;
      area.destroy();
    };
  }, []);
  const onPosRef = useRef(onPositions);
  onPosRef.current = onPositions;

  // ── 원문 → 그래프 다시 그리기 ──
  // 다시 그리기는 하나씩 차례로 한다(겹치면 블록이 두 번 들어감). 밀린 요청은 마지막 것만 그린다.
  const queue = useRef(Promise.resolve());
  const want = useRef(0);
  const rebuild = useCallback((g: AppGraph, fit: boolean) => {
    const ticket = ++want.current;
    const run = queue.current.then(() => (ticket === want.current ? draw(g, fit) : undefined));
    queue.current = run.catch(() => undefined);
    return run;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const draw = async (g: AppGraph, fit: boolean) => {
    const e = ed.current;
    if (!e) return;
    building.current = true;
    try {
      await e.editor.clear();
      const missing = g.nodes.filter((n) => !posRef.current[n.id]);
      if (missing.length) {
        const auto = autoLayout(g);
        // 기존 좌표가 있으면 새 블록만 오른쪽 아래에 둔다
        const known = Object.keys(posRef.current).length > 0;
        const maxY = Math.max(0, ...Object.values(posRef.current).map((p) => p.y));
        missing.forEach((n, i) => (posRef.current[n.id] = known ? { x: auto[n.id].x, y: maxY + 180 + i * 40 } : auto[n.id]));
      }
      const blocks = new Map<string, Block>();
      for (const n of g.nodes) {
        const b = makeBlock(n, g);
        blocks.set(n.id, b);
        await e.editor.addNode(b);
        await e.area.translate(b.id, posRef.current[n.id]);
      }
      for (const x of g.edges) {
        const a = blocks.get(x.from);
        const b = blocks.get(x.to);
        if (!a || !b) continue;
        const c = new Link(a, x.kind === 'route' ? 'route' : x.kind, b, 'in');
        c.kind = x.kind;
        c.gid = x.id;
        await e.editor.addConnection(c);
      }
      if (fit) await AreaExtensions.zoomAt(e.area, e.editor.getNodes());
    } finally {
      building.current = false;
    }
  };

  useEffect(() => {
    if (yaml === lastEmitted.current && graphRef.current) return;
    let g: AppGraph;
    try {
      g = yamlToGraph(yaml);
      setParseError(undefined);
    } catch (e) {
      setParseError((e as Error).message);
      return;
    }
    const first = !graphRef.current;
    graphRef.current = g;
    setGraph(g);
    setSel({});
    void rebuild(g, first);
  }, [yaml, rebuild]);

  // 밖에서 좌표가 늦게 오면(배치 좌표 읽기) 다시 그린다
  useEffect(() => {
    if (!positions || !graphRef.current) return;
    posRef.current = { ...posRef.current, ...positions };
    void rebuild(graphRef.current, true);
  }, [positions, rebuild]);

  // 블록 요약(이미지·쓰는 서비스 수)이 바뀌면 다시 그린다
  const refreshLabels = useCallback(async (g: AppGraph) => {
    const e = ed.current;
    if (!e) return;
    for (const b of e.editor.getNodes()) {
      const n = g.nodes.find((x) => x.id === b.gid);
      if (!n) continue;
      b.label = `${KIND_LABEL[n.kind]} · ${n.name}`;
      b.summary = summaryOf(n, g);
      await e.area.update('node', b.id);
    }
  }, []);
  useEffect(() => {
    if (graph) void refreshLabels(graph);
  }, [graph, refreshLabels]);

  const issues = useMemo(() => (graph ? checkGraph(graph, choices) : []), [graph, choices]);

  // ── 도구 ──
  const addNode = async (kind: NodeKind, name: string) => {
    const g = graphRef.current;
    if (!g || !name) return;
    const id = nodeId(kind, name);
    if (g.nodes.some((n) => n.id === id)) {
      setNotice(`이미 '${name}' 블록이 있습니다.`);
      return;
    }
    const n: GNode = kind === 'service' ? { id, kind, name, key: undefined, service: { image: '', replicas: 1, ports: [], node: '' } } : { id, kind, name };
    const next = { ...g, nodes: [...g.nodes, n] };
    // 다른 블록과 겹치지 않게 맨 아래 왼쪽에 두고 전체를 화면에 맞춘다
    const all = Object.values(posRef.current);
    posRef.current[id] = all.length ? { x: Math.min(...all.map((p) => p.x)), y: Math.max(...all.map((p) => p.y)) + 200 } : { x: 0, y: 0 };
    commit(next);
    await rebuild(next, true);
    setSel({ node: id });
  };
  const removeSelected = async () => {
    const g = graphRef.current;
    if (!g) return;
    let next = g;
    if (sel.edge) next = { ...g, edges: g.edges.filter((e) => e.id !== sel.edge) };
    else if (sel.node) next = { nodes: g.nodes.filter((n) => n.id !== sel.node), edges: g.edges.filter((e) => e.from !== sel.node && e.to !== sel.node) };
    else return;
    setSel({});
    commit(next);
    await rebuild(next, false);
  };
  const arrange = async () => {
    const g = graphRef.current;
    if (!g) return;
    posRef.current = autoLayout(g);
    await rebuild(g, true);
    onPositions?.({ ...posRef.current });
  };
  const fit = () => ed.current && void AreaExtensions.zoomAt(ed.current.area, ed.current.editor.getNodes());
  const toggleFull = async () => {
    if (!document.fullscreenElement) await shell.current?.requestFullscreen?.().catch(() => setFull((f) => !f));
    else await document.exitFullscreen();
  };
  useEffect(() => {
    const on = () => setFull(document.fullscreenElement === shell.current);
    document.addEventListener('fullscreenchange', on);
    return () => document.removeEventListener('fullscreenchange', on);
  }, []);
  useEffect(() => {
    const t = setTimeout(fit, 50);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [full]);

  const updateNode = (id: string, patch: (n: GNode) => GNode) => {
    const g = graphRef.current;
    if (!g) return;
    const old = g.nodes.find((n) => n.id === id);
    if (!old) return;
    const n = patch(old);
    let next: AppGraph = { ...g, nodes: g.nodes.map((x) => (x.id === id ? n : x)) };
    if (n.id !== old.id) {
      // 이름이 바뀌면 블록 ID와 선을 옮긴다
      posRef.current[n.id] = posRef.current[old.id];
      next = { ...next, edges: next.edges.map((e) => ({ ...e, from: e.from === old.id ? n.id : e.from, to: e.to === old.id ? n.id : e.to })) };
      for (const b of ed.current?.editor.getNodes() ?? []) if (b.gid === old.id) b.gid = n.id;
      setSel({ node: n.id });
    }
    commit(next);
  };
  const updateEdge = (id: string, props: GEdge['props']) => {
    const g = graphRef.current;
    if (!g) return;
    commit({ ...g, edges: g.edges.map((e) => (e.id === id ? { ...e, props: { ...e.props, ...props } } : e)) });
  };

  const selNode = graph?.nodes.find((n) => n.id === sel.node);
  const selEdge = graph?.edges.find((e) => e.id === sel.edge);
  return (
    <div ref={shell} className={`graph-shell${full ? ' full' : ''}`}>
      <div className="graph-toolbar row">
        <AddMenu disabled={readOnly || !graph} choices={choices} graph={graph} onAdd={(k, n) => void addNode(k, n)} />
        <button className="btn sm" disabled={readOnly || (!sel.node && !sel.edge)} onClick={() => void removeSelected()}>
          고른 것 지우기
        </button>
        <span className="grow" />
        <button className="btn sm" onClick={() => void arrange()} disabled={!graph}>
          자동 정렬
        </button>
        <button className="btn sm" onClick={fit}>
          화면에 맞추기
        </button>
        <button className="btn sm" onClick={() => void toggleFull()}>
          {full ? '전체 화면 끝내기' : '전체 화면'}
        </button>
      </div>
      {parseError && <div className="note er small">app.yaml을 읽지 못해 그래프를 바꾸지 않았습니다: {parseError}</div>}
      {notice && (
        <div className="note wa small row between">
          <span>{notice}</span>
          <button className="btn ghost sm" onClick={() => setNotice(undefined)}>
            닫기
          </button>
        </div>
      )}
      <div className="graph-body">
        <div ref={host} className="graph-canvas" aria-label="앱 그래프" />
        <aside className="graph-side">
          {selNode ? (
            <NodePanel key={selNode.id} n={selNode} graph={graph!} choices={choices} readOnly={readOnly} onChange={(p) => updateNode(selNode.id, p)} />
          ) : selEdge ? (
            <EdgePanel key={selEdge.id} e={selEdge} graph={graph!} readOnly={readOnly} onChange={(p) => updateEdge(selEdge.id, p)} />
          ) : (
            <div className="small muted">
              <p style={{ marginTop: 0 }}>블록이나 선을 누르면 속성을 고칩니다.</p>
              <p>선은 블록 오른쪽 연결점에서 끌어 다른 블록 왼쪽에 놓습니다. 서비스 → 망·저장소·비밀값·먼저 띄울 서비스, 외부 접속 → 서비스만 이을 수 있습니다.</p>
              <p>망·데이터 저장소·비밀값은 작업 공간에 이미 있는 것을 이름으로 고릅니다. app.yaml에서 새로 만들지 않습니다.</p>
            </div>
          )}
          <Issues issues={issues} onPick={(i) => setSel(i.edge ? { edge: i.edge } : { node: i.node })} />
        </aside>
      </div>
    </div>
  );
}

function AddMenu({ disabled, choices, graph, onAdd }: { disabled: boolean; choices: GraphChoices; graph?: AppGraph; onAdd: (k: NodeKind, name: string) => void }) {
  const [kind, setKind] = useState<NodeKind>('service');
  const [name, setName] = useState('');
  const has = (k: NodeKind, n: string) => !!graph?.nodes.some((x) => x.id === nodeId(k, n));
  const pool = kind === 'network' ? choices.networks : kind === 'volume' ? choices.volumes : kind === 'secret' ? choices.secrets : undefined;
  const free = pool?.filter((n) => !has(kind, n));
  const add = () => {
    onAdd(kind, name.trim());
    setName('');
  };
  return (
    <span className="row" style={{ gap: 6 }}>
      <select value={kind} disabled={disabled} onChange={(e) => (setKind(e.target.value as NodeKind), setName(''))} aria-label="더할 블록 종류">
        {(Object.keys(KIND_LABEL) as NodeKind[]).map((k) => (
          <option key={k} value={k}>
            {KIND_LABEL[k]}
          </option>
        ))}
      </select>
      {free ? (
        <select value={name} disabled={disabled} onChange={(e) => setName(e.target.value)} aria-label="공유 자원 이름">
          <option value="">{free.length ? '이름 고르기' : '고를 것이 없습니다'}</option>
          {free.map((n) => (
            <option key={n}>{n}</option>
          ))}
        </select>
      ) : (
        <input value={name} disabled={disabled} placeholder={kind === 'service' ? '서비스 이름' : '호스트 이름'} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && add()} style={{ width: 150 }} />
      )}
      <button className="btn sm" disabled={disabled || !name.trim()} onClick={add}>
        블록 더하기
      </button>
    </span>
  );
}

function NodePanel({ n, graph, choices, readOnly, onChange }: { n: GNode; graph: AppGraph; choices: GraphChoices; readOnly: boolean; onChange: (p: (n: GNode) => GNode) => void }) {
  const links = graph.edges.filter((e) => e.from === n.id || e.to === n.id);
  const name = (id: string) => graph.nodes.find((x) => x.id === id)?.name ?? id;
  const s = n.service;
  return (
    <div className="form" style={{ gap: 10 }}>
      <div className="row between">
        <b>
          {KIND_LABEL[n.kind]} · {n.name}
        </b>
      </div>
      {n.kind === 'service' && s && (
        <>
          <Field label="이름">
            <input defaultValue={n.name} disabled={readOnly} onBlur={(e) => e.target.value.trim() && e.target.value !== n.name && onChange((x) => ({ ...x, name: e.target.value.trim(), id: nodeId('service', e.target.value.trim()) }))} />
          </Field>
          <Field label="이미지" hint="다이제스트(@sha256:…)로 고정하기를 권합니다">
            <input value={s.image} disabled={readOnly} onChange={(e) => onChange((x) => ({ ...x, service: { ...x.service!, image: e.target.value } }))} />
          </Field>
          <div className="row" style={{ flexWrap: 'nowrap' }}>
            <Field label="복제본">
              <input type="number" min={1} max={64} value={s.replicas} disabled={readOnly} onChange={(e) => onChange((x) => ({ ...x, service: { ...x.service!, replicas: Math.max(1, Number(e.target.value) || 1) } }))} style={{ width: 70 }} />
            </Field>
            <Field label="서버">
              <select value={s.node} disabled={readOnly} onChange={(e) => onChange((x) => ({ ...x, service: { ...x.service!, node: e.target.value } }))}>
                <option value="">자동</option>
                {[...new Set([...choices.nodes, ...(s.node ? [s.node] : [])])].map((x) => (
                  <option key={x}>{x}</option>
                ))}
              </select>
            </Field>
          </div>
          <GraphPorts key={n.id} ports={s.ports} readOnly={readOnly} onCommit={(ports) => onChange((x) => ({ ...x, service: { ...x.service!, ports } }))} />
          <p className="small muted" style={{ margin: 0 }}>
            환경 변수·명령·상태 검사 등 다른 칸은 app.yaml에서 고칩니다. 그래프는 건드리지 않고 그대로 둡니다.
          </p>
        </>
      )}
      {n.kind === 'ingress' && (
        <Field label="호스트 이름">
          <input defaultValue={n.name} disabled={readOnly} onBlur={(e) => e.target.value.trim() && e.target.value !== n.name && onChange((x) => ({ ...x, name: e.target.value.trim(), id: nodeId('ingress', e.target.value.trim()) }))} />
        </Field>
      )}
      {(n.kind === 'network' || n.kind === 'volume' || n.kind === 'secret') && <p className="small muted" style={{ margin: 0 }}>작업 공간의 공유 자원입니다. 이름으로만 참조하고 여기서 만들거나 지우지 않습니다.</p>}
      <div>
        <div className="small" style={{ fontWeight: 600, marginBottom: 4 }}>
          연결 {links.length}개
        </div>
        {links.length === 0 ? (
          <span className="small muted">없음</span>
        ) : (
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {links.map((e) => (
              <li key={e.id}>
                {EDGE_LABEL[e.kind]}: {name(e.from)} → {name(e.to)}
                {e.props.target ? ` (${e.props.target})` : ''}
                {e.props.path ? ` (${e.props.path})` : ''}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function EdgePanel({ e, graph, readOnly, onChange }: { e: GEdge; graph: AppGraph; readOnly: boolean; onChange: (p: GEdge['props']) => void }) {
  const from = graph.nodes.find((n) => n.id === e.from)!;
  const to = graph.nodes.find((n) => n.id === e.to)!;
  const p = e.props;
  return (
    <div className="form" style={{ gap: 10 }}>
      <b>
        {EDGE_LABEL[e.kind]}: {from.name} → {to.name}
      </b>
      {e.kind === 'network' && (
        <Field label="별칭" hint="이 망에서 이 서비스를 부를 다른 이름. 비우면 서비스 이름만">
          <input value={p.alias ?? ''} disabled={readOnly} onChange={(x) => onChange({ alias: x.target.value })} />
        </Field>
      )}
      {e.kind === 'volume' && (
        <>
          <Field label="마운트 경로">
            <input value={p.target ?? ''} disabled={readOnly} onChange={(x) => onChange({ target: x.target.value })} />
          </Field>
          <label className="row small">
            <input type="checkbox" checked={!!p.readOnly} disabled={readOnly} onChange={(x) => onChange({ readOnly: x.target.checked })} /> 읽기 전용
          </label>
        </>
      )}
      {e.kind === 'secret' && (
        <>
          <Field label="공급 방식">
            <select value={p.mode ?? 'file'} disabled={readOnly} onChange={(x) => onChange({ mode: x.target.value as 'file' | 'file+env', envName: x.target.value === 'file+env' ? p.envName || `${to.name.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}_FILE` : '' })}>
              <option value="file">파일로 넣기</option>
              <option value="file+env">파일 + 경로 변수</option>
              <option value="env" disabled>
                환경 변수 값으로 넣기
              </option>
              <option value="path" disabled>
                지정 경로에 파일
              </option>
            </select>
          </Field>
          <Field label="파일 이름" hint={`비우면 /run/secrets/${to.name}`}>
            <input value={p.target ?? ''} disabled={readOnly} onChange={(x) => onChange({ target: x.target.value || undefined })} />
          </Field>
          {p.mode === 'file+env' && (
            <Field label="경로 변수 이름" hint="이 환경 변수에 파일 경로가 들어갑니다">
              <input value={p.envName ?? ''} disabled={readOnly} onChange={(x) => onChange({ envName: x.target.value })} />
            </Field>
          )}
        </>
      )}
      {e.kind === 'route' && (
        <>
          <Field label="경로(앞부분)">
            <input value={p.path ?? '/'} disabled={readOnly} onChange={(x) => onChange({ path: x.target.value })} />
          </Field>
          <Field label="서비스 포트">
            <input value={p.port ?? ''} disabled={readOnly} onChange={(x) => onChange({ port: x.target.value })} style={{ width: 100 }} />
          </Field>
          <Field label="게이트웨이">
            <select value={p.gateway ?? 'local'} disabled={readOnly} onChange={(x) => onChange({ gateway: x.target.value as 'local' | 'external' | 'both' })}>
              <option value="local">로컬망</option>
              <option value="external">외부망</option>
              <option value="both">둘 다</option>
            </select>
          </Field>
        </>
      )}
      {e.kind === 'depends' && <p className="small muted" style={{ margin: 0 }}>{to.name}을 먼저 띄운 뒤 {from.name}을 띄웁니다.</p>}
    </div>
  );
}

function Issues({ issues, onPick }: { issues: ReturnType<typeof checkGraph>; onPick: (i: ReturnType<typeof checkGraph>[number]) => void }) {
  if (!issues.length) return <div className="small" style={{ color: 'var(--ok)', marginTop: 12 }}>검사: 문제 없음</div>;
  return (
    <div style={{ marginTop: 12 }}>
      <div className="small" style={{ fontWeight: 600, marginBottom: 4 }}>
        검사 {issues.length}건
      </div>
      <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
        {issues.map((i, k) => (
          <li key={k} style={{ color: i.level === 'error' ? 'var(--er)' : 'var(--wa)', cursor: 'pointer' }} onClick={() => onPick(i)}>
            {i.text}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** 속성 칸 포트: 입력 중에는 미리 보기만 바꾸고, 칸을 벗어날 때 그래프에 넣는다 */
function GraphPorts({ ports, readOnly, onCommit }: { ports: string[]; readOnly?: boolean; onCommit: (ports: string[]) => void }) {
  const [text, setText] = useState(ports.join(', '));
  return (
    <PortsField
      value={text}
      disabled={readOnly}
      onChange={setText}
      onBlur={() =>
        onCommit(
          text
            .split(',')
            .map((p) => p.trim())
            .filter(Boolean),
        )
      }
    />
  );
}
