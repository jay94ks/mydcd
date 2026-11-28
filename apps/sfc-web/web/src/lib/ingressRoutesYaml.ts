// SPDX-License-Identifier: Apache-2.0

// 외부 접속 매핑(UI-5E)을 앱 정의(app.yaml)나 클러스터 앱 경로 파일의 `x-sfc.ingress` route 목록에 더하고 빼고 고친다.
// 형식(devel/design/yaml-formats.md 3.1, Jay 2026-11-28 확정): x-sfc.ingress는 route 목록이고 항목마다
// node, host, prefix, service, port, network, health, gateway(external | local, 기본 external), balance.
// 클러스터 앱 경로 파일은 service·port·network·health가 없다. 주석·다른 칸은 그대로 두고 목록만 바꾼다.
import YAML, { isMap, isSeq, type Document } from 'yaml';

export type RouteGateway = 'external' | 'local';
export interface RouteSpec {
  /** 이 route를 여는 서버 */
  node: string;
  host: string;
  prefix: string;
  gateway: RouteGateway;
  /** 작업 공간 앱만. 클러스터 앱 경로에는 없다(backend는 sfcd가 정함) */
  service?: string;
  port?: number;
}
/** 고치거나 뺄 경로를 찾는 열쇠. prefix가 없는 항목은 '/' */
export interface RouteRef {
  host: string;
  prefix: string;
}

export class RouteEditError extends Error {}

const plain = (x: unknown) => (x && typeof x === 'object' ? (x as Record<string, unknown>) : {});
const prefixOf = (r: Record<string, unknown>) => (typeof r.prefix === 'string' && r.prefix ? r.prefix : '/');
const same = (r: Record<string, unknown>, ref: RouteRef) => String(r.host ?? '').toLowerCase() === ref.host.toLowerCase() && prefixOf(r) === ref.prefix;

function open(text: string): Document {
  const doc = YAML.parseDocument(text);
  if (doc.errors.length) throw new RouteEditError(`앱 정의를 읽지 못했습니다: ${doc.errors[0].message}`);
  const ing = doc.getIn(['x-sfc', 'ingress']);
  if (isMap(ing)) throw new RouteEditError('이 앱 정의는 예전 외부 접속 형식(x-sfc.ingress 객체)을 씁니다. x-sfc.ingress를 route 목록으로 바꾼 뒤 더하세요.');
  if (ing !== undefined && ing !== null && !isSeq(ing)) throw new RouteEditError('x-sfc.ingress는 route 목록이어야 합니다.');
  return doc;
}

/** 지금 경로 목록(평범한 값) */
export function readRoutes(text: string): Record<string, unknown>[] {
  try {
    const r = plain(plain(YAML.parse(text))['x-sfc']).ingress;
    return Array.isArray(r) ? r.map(plain) : [];
  } catch {
    return [];
  }
}

function entry(spec: RouteSpec, base: Record<string, unknown> = {}): Record<string, unknown> {
  const r: Record<string, unknown> = { node: spec.node, ...base, host: spec.host, prefix: spec.prefix };
  r.node = spec.node;
  if (spec.service !== undefined) r.service = spec.service;
  if (spec.port !== undefined) r.port = spec.port;
  r.gateway = spec.gateway;
  return r;
}

function write(doc: Document, routes: Record<string, unknown>[]) {
  if (routes.length) doc.setIn(['x-sfc', 'ingress'], doc.createNode(routes));
  else {
    doc.deleteIn(['x-sfc', 'ingress']);
    const x = doc.getIn(['x-sfc']);
    if (isMap(x) && x.items.length === 0) doc.deleteIn(['x-sfc']);
  }
  return doc.toString({ lineWidth: 0, flowCollectionPadding: false });
}

/** 한 앱(또는 route 파일)의 route는 모두 같은 서버에서 연다(#910 INGRESS_NODE_MIXED) */
export function routesNode(text: string): string | undefined {
  const n = readRoutes(text).find((r) => r.node)?.node;
  return typeof n === 'string' ? n : undefined;
}
function sameNode(others: Record<string, unknown>[], node: string) {
  const o = others.find((r) => r.node && r.node !== node);
  if (o) throw new RouteEditError(`이 앱의 다른 경로는 ${String(o.node)} 서버에서 엽니다. 한 앱의 경로는 모두 같은 서버에서 열어야 합니다.`);
}

/** 경로 하나를 더한다. 같은 호스트·접두사가 이미 있으면 막는다 */
export function addRoute(text: string, spec: RouteSpec): string {
  const doc = open(text);
  const routes = readRoutes(text);
  if (routes.some((r) => same(r, spec))) throw new RouteEditError(`이 앱 정의에 이미 ${spec.host}${spec.prefix} 경로가 있습니다.`);
  sameNode(routes, spec.node);
  return write(doc, [...routes, entry(spec)]);
}

/** 경로 하나를 고친다(다른 칸 — network·health·balance·id — 는 그대로) */
export function replaceRoute(text: string, ref: RouteRef, spec: RouteSpec): string {
  const doc = open(text);
  const routes = readRoutes(text);
  const i = routes.findIndex((r) => same(r, ref));
  if (i < 0) throw new RouteEditError(`앱 정의에서 ${ref.host}${ref.prefix} 경로를 찾지 못했습니다.`);
  if ((ref.host.toLowerCase() !== spec.host.toLowerCase() || ref.prefix !== spec.prefix) && routes.some((r, k) => k !== i && same(r, spec))) throw new RouteEditError(`이 앱 정의에 이미 ${spec.host}${spec.prefix} 경로가 있습니다.`);
  sameNode(routes.filter((_, k) => k !== i), spec.node);
  routes[i] = entry(spec, routes[i]);
  return write(doc, routes);
}

/** 경로 하나를 뺀다. 마지막 경로를 빼면 x-sfc.ingress가 없어진다(외부 접속 없음) */
export function removeRoute(text: string, ref: RouteRef): string {
  const doc = open(text);
  const routes = readRoutes(text);
  const rest = routes.filter((r) => !same(r, ref));
  if (rest.length === routes.length) throw new RouteEditError(`앱 정의에서 ${ref.host}${ref.prefix} 경로를 찾지 못했습니다.`);
  return write(doc, rest);
}

/** 앱 정의의 서비스와 컨테이너가 듣는 포트(ports의 컨테이너 쪽·expose). 매핑 다이얼로그의 서비스·포트 고르기 */
export function servicePorts(text: string): { service: string; ports: number[] }[] {
  let services: Record<string, unknown> = {};
  try {
    services = plain(plain(YAML.parse(text)).services);
  } catch {
    return [];
  }
  return Object.entries(services).map(([service, raw]) => {
    const s = plain(raw);
    const out = new Set<number>();
    const add = (v: unknown) => {
      const n = Number(v);
      if (Number.isInteger(n) && n > 0 && n < 65536) out.add(n);
    };
    for (const p of Array.isArray(s.ports) ? s.ports : []) {
      if (typeof p === 'number') add(p);
      else if (typeof p === 'string') add(p.split('/')[0].split(':').pop());
      else if (p && typeof p === 'object') add(plain(p).target);
    }
    for (const p of Array.isArray(s.expose) ? s.expose : []) add(String(p).split('/')[0]);
    return { service, ports: [...out].sort((a, b) => a - b) };
  });
}

/** 단순 검사: 호스트 이름과 접두사 모양 */
export function routeProblems(spec: { host: string; prefix: string }): string[] {
  const out: string[] = [];
  if (!/^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]+$|^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(spec.host)) out.push('호스트는 shop.example.com이나 *.example.com 같은 이름이어야 합니다.');
  if (!spec.prefix.startsWith('/') || /\s/.test(spec.prefix)) out.push('경로 접두사는 /로 시작하고 빈칸이 없어야 합니다.');
  return out;
}
