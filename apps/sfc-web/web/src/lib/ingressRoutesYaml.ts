// SPDX-License-Identifier: Apache-2.0

// 외부 접속 매핑(UI-5E)을 앱 정의(app.yaml)나 클러스터 앱 경로 파일의 `x-sfc.ingress.routes`에 더하고 빼고 고친다.
// sfcd 형식(internal/deployment IngressRouteDeclaration): host, prefix, service, network, port, health_path, gateway, balance.
// 주석·다른 칸은 그대로 두고 routes 목록만 바꾼다.
import YAML, { isMap, type Document } from 'yaml';

export type RouteGateway = 'external' | 'local' | 'both';
export interface RouteSpec {
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
  if (!isMap(ing)) throw new RouteEditError('이 앱 정의에는 외부 접속 설정(x-sfc.ingress)이 없습니다. 앱 정의에서 먼저 서버·수신 주소·한도를 정하세요.');
  const j = plain(ing.toJSON());
  if (typeof j.host === 'string' && j.host && !Array.isArray(j.routes)) throw new RouteEditError('이 앱 정의는 경로 목록(routes) 대신 단일 host 형식을 씁니다. 앱 정의에서 routes 형식으로 바꾼 뒤 더하세요.');
  return doc;
}

/** 지금 경로 목록(평범한 값) */
export function readRoutes(text: string): Record<string, unknown>[] {
  try {
    const r = plain(plain(plain(YAML.parse(text))['x-sfc']).ingress).routes;
    return Array.isArray(r) ? r.map(plain) : [];
  } catch {
    return [];
  }
}

function entry(spec: RouteSpec, base: Record<string, unknown> = {}): Record<string, unknown> {
  const r: Record<string, unknown> = { ...base, host: spec.host, prefix: spec.prefix };
  delete r.path;
  if (spec.service !== undefined) r.service = spec.service;
  if (spec.port !== undefined) r.port = spec.port;
  r.gateway = spec.gateway;
  return r;
}

function write(doc: Document, routes: Record<string, unknown>[]) {
  doc.setIn(['x-sfc', 'ingress', 'routes'], doc.createNode(routes));
  return doc.toString({ lineWidth: 0, flowCollectionPadding: false });
}

/** 경로 하나를 더한다. 같은 호스트·접두사가 이미 있으면 막는다 */
export function addRoute(text: string, spec: RouteSpec): string {
  const doc = open(text);
  const routes = readRoutes(text);
  if (routes.some((r) => same(r, spec))) throw new RouteEditError(`이 앱 정의에 이미 ${spec.host}${spec.prefix} 경로가 있습니다.`);
  return write(doc, [...routes, entry(spec)]);
}

/** 경로 하나를 고친다(다른 칸 — network·health_path·balance·id — 는 그대로) */
export function replaceRoute(text: string, ref: RouteRef, spec: RouteSpec): string {
  const doc = open(text);
  const routes = readRoutes(text);
  const i = routes.findIndex((r) => same(r, ref));
  if (i < 0) throw new RouteEditError(`앱 정의에서 ${ref.host}${ref.prefix} 경로를 찾지 못했습니다.`);
  if ((ref.host.toLowerCase() !== spec.host.toLowerCase() || ref.prefix !== spec.prefix) && routes.some((r, k) => k !== i && same(r, spec))) throw new RouteEditError(`이 앱 정의에 이미 ${spec.host}${spec.prefix} 경로가 있습니다.`);
  routes[i] = entry(spec, routes[i]);
  return write(doc, routes);
}

/** 경로 하나를 뺀다. 마지막 경로는 뺄 수 없다(빈 routes는 sfcd가 거절) */
export function removeRoute(text: string, ref: RouteRef): string {
  const doc = open(text);
  const routes = readRoutes(text);
  const rest = routes.filter((r) => !same(r, ref));
  if (rest.length === routes.length) throw new RouteEditError(`앱 정의에서 ${ref.host}${ref.prefix} 경로를 찾지 못했습니다.`);
  if (!rest.length) throw new RouteEditError('앱의 마지막 경로는 여기서 뺄 수 없습니다. 외부 접속을 통째로 끄려면 앱 정의에서 x-sfc.ingress를 지우세요.');
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
