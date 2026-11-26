// SPDX-License-Identifier: Apache-2.0

/**
 * app.yaml ⇄ 그래프 모델 (UI-39). app.yaml이 원본이고 그래프는 같은 원문을 고치는 다른 보기다.
 * graphToYaml은 원문 문서를 고쳐 쓴다: 그래프가 모르는 필드·주석·바인드 마운트는 그대로 둔다.
 * 망·데이터 저장소·비밀값은 작업 공간에 있는 것을 이름으로만 참조한다(external: true).
 */
import { portText } from './ports';
import YAML, { isMap, type Document, type YAMLMap } from 'yaml';

export type NodeKind = 'service' | 'network' | 'volume' | 'secret' | 'ingress';
export type EdgeKind = 'network' | 'volume' | 'secret' | 'depends' | 'route';

export interface ServiceProps {
  image: string;
  replicas: number;
  ports: string[];
  node: string;
}
export interface GNode {
  /** `${kind}:${name}` — 배치 좌표 키 */
  id: string;
  kind: NodeKind;
  name: string;
  /** 서비스: 원문에서의 키(이름 바꾸기 추적) */
  key?: string;
  service?: ServiceProps;
}
export interface EdgeProps {
  /** 망 별칭 */
  alias?: string;
  /** 저장소 마운트 경로 */
  target?: string;
  readOnly?: boolean;
  /** 비밀값 공급 방식 */
  mode?: 'file' | 'file+env';
  envName?: string;
  /** 외부 접속 경로 */
  path?: string;
  port?: string;
  gateway?: 'local' | 'external' | 'both';
}
export interface GEdge {
  id: string;
  kind: EdgeKind;
  from: string;
  to: string;
  props: EdgeProps;
  /** 원문 항목(고치지 않았으면 그대로 다시 쓴다) */
  raw?: unknown;
}
export interface AppGraph {
  nodes: GNode[];
  edges: GEdge[];
}

export const nodeId = (kind: NodeKind, name: string) => `${kind}:${name}`;
let seq = 0;
export const edgeId = () => `e${++seq}`;

/** 어떤 블록에서 어떤 블록으로 어떤 선을 그을 수 있나 */
export function edgeKindFor(from: NodeKind, to: NodeKind): EdgeKind | undefined {
  if (from === 'service' && to === 'network') return 'network';
  if (from === 'service' && to === 'volume') return 'volume';
  if (from === 'service' && to === 'secret') return 'secret';
  if (from === 'service' && to === 'service') return 'depends';
  if (from === 'ingress' && to === 'service') return 'route';
  return undefined;
}

const str = (v: unknown) => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '');
const asObj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const keysOf = (v: unknown): string[] => (Array.isArray(v) ? v.map(str).filter(Boolean) : Object.keys(asObj(v)));

/** 짧은 볼륨 문법 "name:/path[:ro]". 이름 볼륨이 아니면(경로로 시작) undefined */
export function parseVolume(item: unknown): { name: string; target: string; readOnly: boolean } | undefined {
  if (typeof item === 'string') {
    const [src, target, opt] = item.split(':');
    if (!src || !target || /^[./~]/.test(src)) return undefined;
    return { name: src, target, readOnly: (opt ?? '').split(',').includes('ro') };
  }
  const o = asObj(item);
  if ((o.type ?? 'volume') !== 'volume' || !str(o.source)) return undefined;
  return { name: str(o.source), target: str(o.target), readOnly: o.read_only === true };
}
const secretPath = (name: string, target?: string) => (target ? (target.startsWith('/') ? target : `/run/secrets/${target}`) : `/run/secrets/${name}`);

export function yamlToGraph(text: string): AppGraph {
  const doc = asObj(YAML.parse(text) ?? {});
  const nodes: GNode[] = [];
  const edges: GEdge[] = [];
  const have = new Set<string>();
  const add = (n: GNode) => {
    if (have.has(n.id)) return;
    have.add(n.id);
    nodes.push(n);
  };
  const services = asObj(doc.services);
  for (const [name, raw] of Object.entries(services)) {
    const s = asObj(raw);
    add({
      id: nodeId('service', name),
      kind: 'service',
      name,
      key: name,
      service: {
        image: str(s.image),
        replicas: Number(asObj(s.deploy).replicas ?? 1) || 1,
        ports: Array.isArray(s.ports) ? s.ports.map(portText).filter(Boolean) : [],
        node: str(asObj(s['x-mydc']).node),
      },
    });
  }
  for (const k of keysOf(doc.networks)) add({ id: nodeId('network', k), kind: 'network', name: k });
  for (const k of keysOf(doc.volumes)) add({ id: nodeId('volume', k), kind: 'volume', name: k });
  for (const k of keysOf(doc.secrets)) add({ id: nodeId('secret', k), kind: 'secret', name: k });

  for (const [name, raw] of Object.entries(services)) {
    const s = asObj(raw);
    const from = nodeId('service', name);
    const env = Array.isArray(s.environment)
      ? Object.fromEntries(s.environment.map((e) => str(e).split(/=(.*)/s).slice(0, 2)))
      : (asObj(s.environment) as Record<string, unknown>);
    if (Array.isArray(s.networks)) {
      for (const n of s.networks.map(str).filter(Boolean)) {
        add({ id: nodeId('network', n), kind: 'network', name: n });
        edges.push({ id: edgeId(), kind: 'network', from, to: nodeId('network', n), props: {} });
      }
    } else {
      for (const [n, v] of Object.entries(asObj(s.networks))) {
        add({ id: nodeId('network', n), kind: 'network', name: n });
        const aliases = asObj(v).aliases;
        edges.push({ id: edgeId(), kind: 'network', from, to: nodeId('network', n), props: { alias: Array.isArray(aliases) ? str(aliases[0]) : '' }, raw: v });
      }
    }
    if (Array.isArray(s.volumes)) {
      for (const item of s.volumes) {
        const v = parseVolume(item);
        if (!v) continue;
        add({ id: nodeId('volume', v.name), kind: 'volume', name: v.name });
        edges.push({ id: edgeId(), kind: 'volume', from, to: nodeId('volume', v.name), props: { target: v.target, readOnly: v.readOnly }, raw: item });
      }
    }
    if (Array.isArray(s.secrets)) {
      for (const item of s.secrets) {
        const sname = typeof item === 'string' ? item : str(asObj(item).source);
        if (!sname) continue;
        const target = typeof item === 'string' ? undefined : str(asObj(item).target) || undefined;
        const path = secretPath(sname, target);
        const envName = Object.entries(env).find(([, val]) => str(val) === path)?.[0];
        add({ id: nodeId('secret', sname), kind: 'secret', name: sname });
        edges.push({ id: edgeId(), kind: 'secret', from, to: nodeId('secret', sname), props: { target, mode: envName ? 'file+env' : 'file', envName: envName ?? '' }, raw: item });
      }
    }
    for (const d of keysOf(s.depends_on)) {
      edges.push({ id: edgeId(), kind: 'depends', from, to: nodeId('service', d), props: {} });
    }
  }
  const routes = asObj(asObj(doc['x-mydc']).ingress).routes;
  if (Array.isArray(routes)) {
    for (const r of routes) {
      const o = asObj(r);
      const host = str(o.host);
      if (!host) continue;
      add({ id: nodeId('ingress', host), kind: 'ingress', name: host });
      const svc = str(o.service);
      if (svc) {
        const gw = str(o.gateway);
        edges.push({
          id: edgeId(),
          kind: 'route',
          from: nodeId('ingress', host),
          to: nodeId('service', svc),
          props: { path: str(o.path) || '/', port: str(o.port), gateway: gw === 'external' || gw === 'both' ? gw : 'local' },
          raw: r,
        });
      }
    }
  }
  // 없는 서비스를 가리키는 선(원문 오류)은 그리지 않는다. 검사가 알려 준다.
  return { nodes, edges: edges.filter((e) => have.has(e.from) && have.has(e.to)) };
}

// ── 그래프 → app.yaml ──

const shortVolume = (name: string, p: EdgeProps) => `${name}:${p.target ?? ''}${p.readOnly ? ':ro' : ''}`;
const sameJSON = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/** 값이 원문과 같으면 손대지 않는다(흐름 문법·따옴표·주석을 지킨다). */
function setOrDelete(doc: Document, path: (string | number)[], value: unknown) {
  const cur = doc.getIn(path, true) as { toJSON?: () => unknown } | undefined;
  const curPlain = cur && typeof cur === 'object' && 'toJSON' in cur && cur.toJSON ? cur.toJSON() : doc.getIn(path);
  if (doc.hasIn(path) && sameJSON(curPlain, value)) return;
  if (value === undefined || (Array.isArray(value) && value.length === 0) || (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0)) {
    if (doc.hasIn(path)) doc.deleteIn(path);
    return;
  }
  doc.setIn(path, doc.createNode(value));
}

/** 그래프를 원문에 반영한다. 원문을 읽지 못하면 빈 문서에서 시작한다. */
export function graphToYaml(g: AppGraph, original: string): string {
  let doc: Document;
  try {
    doc = YAML.parseDocument(original || '{}');
    if (doc.errors.length) throw doc.errors[0];
  } catch {
    doc = new YAML.Document({});
  }
  if (!isMap(doc.contents)) doc.contents = doc.createNode({}) as unknown as typeof doc.contents;
  const plain = asObj(doc.toJS());
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const out = (id: string, kind: EdgeKind) => g.edges.filter((e) => e.from === id && e.kind === kind);

  // 서비스: 이름 바꾸기·지우기 먼저
  const services = g.nodes.filter((n) => n.kind === 'service');
  const oldServices = asObj(plain.services);
  if (!doc.hasIn(['services'])) doc.setIn(['services'], doc.createNode({}));
  const svcMap = doc.getIn(['services'], true) as YAMLMap;
  const kept = new Map<string, unknown>();
  for (const n of services) if (n.key && n.key in oldServices) kept.set(n.name, svcMap.get(n.key, true));
  for (const k of Object.keys(oldServices)) svcMap.delete(k);
  for (const n of services) svcMap.set(doc.createNode(n.name), kept.get(n.name) ?? doc.createNode({}));

  for (const n of services) {
    const p = ['services', n.name];
    const orig = asObj(oldServices[n.key ?? n.name]);
    const sp = n.service ?? { image: '', replicas: 1, ports: [], node: '' };
    setOrDelete(doc, [...p, 'image'], sp.image || undefined);
    if (sp.replicas > 1 || doc.hasIn([...p, 'deploy', 'replicas'])) {
      if (sp.replicas > 1 || asObj(orig.deploy).replicas !== undefined) doc.setIn([...p, 'deploy', 'replicas'], sp.replicas);
    }
    const origPorts = Array.isArray(orig.ports) ? orig.ports : [];
    const portsNow = yamlToGraph(YAML.stringify({ services: { x: { ports: origPorts } } })).nodes[0]?.service?.ports ?? [];
    if (!sameJSON(portsNow, sp.ports)) setOrDelete(doc, [...p, 'ports'], sp.ports.length ? sp.ports : undefined);
    if (sp.node) doc.setIn([...p, 'x-mydc', 'node'], sp.node);
    else if (doc.hasIn([...p, 'x-mydc', 'node'])) {
      doc.deleteIn([...p, 'x-mydc', 'node']);
      if (Object.keys(asObj(asObj(orig['x-mydc']))).length <= 1) doc.deleteIn([...p, 'x-mydc']);
    }

    // 망: 별칭이 하나라도 있으면 맵, 아니면 원문이 목록이었을 때 목록
    const nets = out(n.id, 'network');
    if (Array.isArray(orig.networks) && nets.every((e) => !e.props.alias)) setOrDelete(doc, [...p, 'networks'], nets.map((e) => byId.get(e.to)!.name));
    else
      setOrDelete(
        doc,
        [...p, 'networks'],
        Object.fromEntries(
          nets.map((e) => {
            const base = asObj(e.raw);
            const v = e.props.alias ? { ...base, aliases: [e.props.alias, ...(Array.isArray(base.aliases) ? base.aliases.slice(1) : [])] } : (() => {
              const { aliases: _a, ...rest } = base;
              return rest;
            })();
            return [byId.get(e.to)!.name, Object.keys(v).length || e.raw !== null ? v : null];
          }),
        ),
      );

    // 저장소: 이름 볼륨만 바꾸고 바인드 마운트는 그대로 뒤에 둔다
    const vols = out(n.id, 'volume').map((e) => {
      const name = byId.get(e.to)!.name;
      const was = e.raw !== undefined ? parseVolume(e.raw) : undefined;
      return was && was.name === name && was.target === e.props.target && was.readOnly === !!e.props.readOnly ? e.raw : shortVolume(name, e.props);
    });
    const binds = (Array.isArray(orig.volumes) ? orig.volumes : []).filter((v) => !parseVolume(v));
    setOrDelete(doc, [...p, 'volumes'], [...vols, ...binds]);

    // 비밀값과 파일 경로 변수
    const secs = out(n.id, 'secret');
    const secretItems = secs.map((e) => {
      const name = byId.get(e.to)!.name;
      const rawSource = typeof e.raw === 'string' ? e.raw : str(asObj(e.raw).source);
      const rawTarget = typeof e.raw === 'string' ? undefined : str(asObj(e.raw).target) || undefined;
      if (e.raw !== undefined && rawSource === name && rawTarget === e.props.target) return e.raw;
      return e.props.target ? { source: name, target: e.props.target } : name;
    });
    setOrDelete(doc, [...p, 'secrets'], secretItems);
    const envPath = [...p, 'environment'];
    const envIsList = Array.isArray(orig.environment);
    const env: Record<string, unknown> = envIsList ? Object.fromEntries((orig.environment as unknown[]).map((x) => str(x).split(/=(.*)/s).slice(0, 2))) : { ...asObj(orig.environment) };
    // 이 서비스가 원래 가리키던 비밀값 경로 변수는 지우고, 지금 선 기준으로 다시 넣는다.
    const origSecrets = Array.isArray(orig.secrets) ? orig.secrets : [];
    const oldPaths = new Set(origSecrets.map((it) => (typeof it === 'string' ? secretPath(it) : secretPath(str(asObj(it).source), str(asObj(it).target) || undefined))));
    for (const [k, v] of Object.entries(env)) if (oldPaths.has(str(v))) delete env[k];
    for (const e of secs) if (e.props.mode === 'file+env' && e.props.envName) env[e.props.envName] = secretPath(byId.get(e.to)!.name, e.props.target);
    const envBefore = envIsList ? Object.fromEntries((orig.environment as unknown[]).map((x) => str(x).split(/=(.*)/s).slice(0, 2))) : asObj(orig.environment);
    if (!sameJSON(env, envBefore)) setOrDelete(doc, envPath, envIsList ? Object.entries(env).map(([k, v]) => `${k}=${str(v)}`) : env);

    // 시작 순서
    const deps = out(n.id, 'depends').map((e) => byId.get(e.to)!.name);
    if (orig.depends_on && !Array.isArray(orig.depends_on)) {
      const om = asObj(orig.depends_on);
      setOrDelete(doc, [...p, 'depends_on'], Object.fromEntries(deps.map((d) => [d, om[d] ?? { condition: 'service_started' }])));
    } else setOrDelete(doc, [...p, 'depends_on'], deps);
  }

  // 공유 자원 선언: 원래 항목은 그대로, 새 것은 external: true
  for (const kind of ['network', 'volume', 'secret'] as const) {
    const top = `${kind}s`;
    const names = g.nodes.filter((n) => n.kind === kind).map((n) => n.name);
    const old = asObj(plain[top]);
    setOrDelete(doc, [top], names.length ? Object.fromEntries(names.map((nm) => [nm, old[nm] ?? { external: true }])) : undefined);
  }

  // 외부 접속 경로
  const routes = g.edges
    .filter((e) => e.kind === 'route')
    .map((e) => {
      const host = byId.get(e.from)!.name;
      const service = byId.get(e.to)!.name;
      const base = asObj(e.raw);
      const r: Record<string, unknown> = { ...base, host, path: e.props.path || '/', service };
      if (e.props.port) r.port = Number(e.props.port) || e.props.port;
      else delete r.port;
      r.gateway = e.props.gateway ?? 'local';
      return r;
    });
  const oldRoutes = asObj(asObj(plain['x-mydc']).ingress).routes;
  if (routes.length || Array.isArray(oldRoutes)) {
    if (!sameJSON(routes, oldRoutes)) setOrDelete(doc, ['x-mydc', 'ingress', 'routes'], routes);
    if (!routes.length && doc.hasIn(['x-mydc', 'ingress']) && Object.keys(asObj(asObj(doc.toJS())['x-mydc']).ingress ?? {}).length === 0) doc.deleteIn(['x-mydc', 'ingress']);
  }
  return doc.toString({ lineWidth: 0 });
}

// ── 검사 ──

export interface GraphIssue {
  node?: string;
  edge?: string;
  level: 'error' | 'warning';
  text: string;
}

export function checkGraph(g: AppGraph, choices?: { networks: string[]; volumes: string[]; secrets: string[] }): GraphIssue[] {
  const out: GraphIssue[] = [];
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const names = new Set<string>();
  for (const n of g.nodes) {
    if (n.kind === 'service') {
      if (!/^[a-z0-9][a-z0-9_.-]*$/.test(n.name)) out.push({ node: n.id, level: 'error', text: `서비스 이름 '${n.name}'은 소문자·숫자·-_.만 씁니다.` });
      if (names.has(n.name)) out.push({ node: n.id, level: 'error', text: `서비스 이름 '${n.name}'이 겹칩니다.` });
      names.add(n.name);
      if (!n.service?.image) out.push({ node: n.id, level: 'error', text: `${n.name}: 이미지가 없습니다.` });
    }
    const pool = choices && (n.kind === 'network' ? choices.networks : n.kind === 'volume' ? choices.volumes : n.kind === 'secret' ? choices.secrets : undefined);
    if (pool && pool.length && !pool.includes(n.name)) out.push({ node: n.id, level: 'warning', text: `작업 공간에 '${n.name}'이 없습니다. 먼저 공유 자원에서 만들어야 합니다.` });
    if (n.kind !== 'service' && n.kind !== 'ingress' && !g.edges.some((e) => e.to === n.id)) out.push({ node: n.id, level: 'warning', text: `${n.name}: 아무 서비스도 쓰지 않습니다.` });
  }
  for (const e of g.edges) {
    const from = byId.get(e.from);
    const to = byId.get(e.to);
    if (!from || !to) continue;
    if (e.kind === 'volume' && !e.props.target?.startsWith('/')) out.push({ edge: e.id, node: from.id, level: 'error', text: `${from.name} → ${to.name}: 마운트 경로는 /로 시작해야 합니다.` });
    if (e.kind === 'volume' && !e.props.readOnly && (from.service?.replicas ?? 1) > 1) out.push({ edge: e.id, node: from.id, level: 'warning', text: `${from.name}: 복제본이 ${from.service?.replicas}개인데 ${to.name}을 쓰기로 붙였습니다. 단일 쓰기 저장소면 배치가 막힙니다.` });
    if (e.kind === 'secret' && e.props.mode === 'file+env' && !e.props.envName) out.push({ edge: e.id, node: from.id, level: 'error', text: `${from.name} → ${to.name}: 경로 변수 이름이 없습니다.` });
    if (e.kind === 'depends' && e.from === e.to) out.push({ edge: e.id, node: from.id, level: 'error', text: `${from.name}: 자기 자신을 기다릴 수 없습니다.` });
    if (e.kind === 'route' && e.props.port && to.service && !to.service.ports.some((p) => p.split(':').pop()?.split('/')[0] === e.props.port)) {
      out.push({ edge: e.id, node: to.id, level: 'warning', text: `${from.name}${e.props.path ?? ''} → ${to.name}:${e.props.port}: 서비스가 이 포트를 열지 않았습니다.` });
    }
  }
  // 경로 변수 이름이 환경 변수와 겹치면 막는다(설계 UI-39).
  for (const n of g.nodes.filter((x) => x.kind === 'service')) {
    const envs = g.edges.filter((e) => e.from === n.id && e.kind === 'secret' && e.props.mode === 'file+env' && e.props.envName).map((e) => e.props.envName!);
    const dup = envs.find((x, i) => envs.indexOf(x) !== i);
    if (dup) out.push({ node: n.id, level: 'error', text: `${n.name}: 경로 변수 ${dup}가 두 번 쓰였습니다.` });
  }
  // 시작 순서 고리
  const deps = new Map<string, string[]>();
  for (const e of g.edges.filter((x) => x.kind === 'depends')) deps.set(e.from, [...(deps.get(e.from) ?? []), e.to]);
  const state = new Map<string, number>();
  const visit = (id: string): boolean => {
    if (state.get(id) === 1) return true;
    if (state.get(id) === 2) return false;
    state.set(id, 1);
    for (const d of deps.get(id) ?? []) if (visit(d)) return true;
    state.set(id, 2);
    return false;
  };
  for (const id of deps.keys()) if (visit(id)) {
    out.push({ node: id, level: 'error', text: '시작 순서(depends_on)가 고리를 이룹니다.' });
    break;
  }
  return out;
}

/** 배치 좌표가 없을 때: 외부 접속 → 서비스(시작 순서 깊이별) → 망 → 저장소 → 비밀값, 열마다 위에서 아래로 */
export function autoLayout(g: AppGraph): Record<string, { x: number; y: number }> {
  const depth = new Map<string, number>();
  const deps = (id: string) => g.edges.filter((e) => e.kind === 'depends' && e.from === id).map((e) => e.to);
  const d = (id: string, seen = new Set<string>()): number => {
    if (depth.has(id)) return depth.get(id)!;
    if (seen.has(id)) return 0;
    seen.add(id);
    const v = deps(id).length ? Math.max(...deps(id).map((x) => d(x, seen))) + 1 : 0;
    depth.set(id, v);
    return v;
  };
  const svc = g.nodes.filter((n) => n.kind === 'service');
  const maxD = Math.max(0, ...svc.map((n) => d(n.id)));
  const cols: string[][] = [];
  const put = (col: number, id: string) => (cols[col] ??= []).push(id);
  for (const n of g.nodes.filter((x) => x.kind === 'ingress')) put(0, n.id);
  // 기다리는 서비스(깊이 큼)가 왼쪽, 먼저 뜨는 서비스가 오른쪽
  for (const n of svc) put(1 + (maxD - d(n.id)), n.id);
  const resCol = 2 + maxD;
  for (const kind of ['network', 'volume', 'secret'] as const) for (const n of g.nodes.filter((x) => x.kind === kind)) put(resCol, n.id);
  const pos: Record<string, { x: number; y: number }> = {};
  cols.forEach((ids, c) => ids?.forEach((id, r) => (pos[id] = { x: c * 300, y: r * 170 })));
  return pos;
}

