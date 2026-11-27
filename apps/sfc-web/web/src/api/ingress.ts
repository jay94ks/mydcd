// SPDX-License-Identifier: Apache-2.0

// 외부 접속 (UI-5A~5C). 매핑 조회·요청 지표·긴급 차단은 sfcd 몫이다(REQ-22, 계약 docs/reference/web-api.md '외부 접속').
// 게이트웨이·분배·비우기·기록은 sfcd 관리 overlay(REQ-62~65, docs/reference/ingress-management.md 'Gateway·분배·drain 변경과 공개 이력').
// 각 record의 revision을 expected로 보낸다(처음 0). 앱·컨테이너 세대는 바꾸지 않는다.
// 화면이 바라는 모양: /mnt/project-files/w2/ingress-web-needs.md
import { ApiError, api, q } from './client';
import type { DOp } from './dto';

export type Gateway = 'external' | 'local';
/** sfcd가 보여 준 공유 수신 주소 바인딩 하나 */
export interface GatewayListener {
  id: string;
  address: string;
  http3: boolean;
  ready: boolean;
  error?: string;
}
export interface GatewayConf {
  /** 수신 주소 중 첫 IP(와일드카드면 없을 수 있음) */
  address?: string;
  iface?: string;
  ports: number[];
  rules: number;
  state: 'listening' | 'off' | 'error';
  listeners: GatewayListener[];
  /** 맞는 규칙이 없던 요청 수(시스템 관리자만) */
  unmatched?: number;
  /** 출발지 제한으로 거절한 요청 수(시스템 관리자만) */
  sourceRejected?: number;
}
/** 클러스터·파일 게이트웨이 설정 한쪽 (sfcd NodeGateways[].Configuration) */
export interface GatewaySetting {
  enabled: boolean;
  addresses: string[];
  ports: number[];
  /** 로컬망만 */
  sources?: string[];
  listeners: { id: string; address: string; tls?: boolean; http3: boolean }[];
}
export interface GatewayConfiguration {
  /** cluster 설정이 있으면 파일보다 우선 */
  source: 'file' | 'cluster';
  /** 이 서버 gateway record revision (클러스터 설정 없으면 0) */
  revision: number;
  /** 서버가 실제 적용한 revision. 목표보다 작으면 적용 대기 또는 bind 실패 */
  appliedRevision: number;
  error?: string;
  external?: GatewaySetting;
  local?: GatewaySetting;
}
export interface IngressNode {
  node: string;
  configuration?: GatewayConfiguration;
  module: boolean;
  isolated?: boolean;
  external?: GatewayConf;
  local?: GatewayConf;
  /** 이 서버 합계 (일반 사용자는 자기 작업 공간 몫만) */
  connections: number;
  connectionLimit: number;
  rps: number;
}
export interface Backend {
  id?: string;
  task: string;
  node: string;
  address: string;
  port: number;
  weight: number;
  generation: number;
  group?: string;
  health: { ok: boolean; at?: string; error?: string };
  rps: number;
  p95Ms?: number;
  slow?: boolean;
  /** 긴급 차단으로 빠짐 */
  blocked?: string;
  draining?: boolean;
}
/** 조건 하나: 위에서부터 처음 맞는 것의 묶음(group)으로 보낸다 (#174) */
export interface BalanceRule {
  kind: 'header' | 'cookie' | 'query' | 'method' | 'source' | 'percent';
  name?: string;
  /** equals | prefix | present */
  op?: string;
  value?: string;
  percent?: number;
  group: string;
}
export interface Balance {
  method: 'round-robin' | 'least-request' | 'hash' | 'random';
  hashKey?: string;
  locality: boolean;
  slowStartSeconds: number;
  /** 연결 실패일 때 다른 컨테이너로 다시 보내는 횟수(0~5, GET·HEAD만) */
  retry: number;
  /** 0이면 제한 없음 */
  weights?: Record<string, number>;
  rules: BalanceRule[];
  /** 묶음의 컨테이너가 모두 빠졌을 때: 기본으로 넘김 또는 503 */
  fallback?: 'default' | '503';
  /** 묶음 정의(읽기 전용, 쓰기 모양에는 없음) */
  groups?: Record<string, { labels?: Record<string, string>; version?: string; backends?: string[] }>;
  actual?: string;
}
const OP_NAME: Record<string, string> = { equals: '=', prefix: '로 시작', present: '있음' };
export function ruleText(r: BalanceRule): string {
  const KIND: Record<BalanceRule['kind'], string> = { header: '헤더', cookie: '쿠키', query: '쿼리', method: 'HTTP 메서드', source: '출발지', percent: '나머지 요청의' };
  if (r.kind === 'percent') return `나머지 요청의 ${r.percent ?? 0}%`;
  if (r.kind === 'method' || r.kind === 'source') return `${KIND[r.kind]} ${r.value ?? ''}`;
  const op = r.op ?? 'equals';
  return op === 'present' ? `${KIND[r.kind]} ${r.name ?? ''} 있음` : op === 'prefix' ? `${KIND[r.kind]} ${r.name ?? ''}이(가) ${r.value ?? ''}로 시작` : `${KIND[r.kind]} ${r.name ?? ''} ${OP_NAME.equals} ${r.value ?? ''}`;
}
export const retryText = (n: number) => (n > 0 ? `연결 실패일 때만 다른 컨테이너로 ${n}번 (GET·HEAD만)` : '안 함');
export interface IngressRoute {
  id: string;
  gateway: Gateway;
  port: number;
  host: string;
  prefix: string;
  service?: string;
  servicePort?: number;
  network?: string;
  redirect?: string;
  /** 이 호스트의 인증서 링크(알고리즘마다 하나, ECDSA 먼저). 실린 인증서가 없으면 error만 있는 항목 하나 */
  certificates?: { id?: string; alg?: 'ecdsa' | 'rsa' | string; error?: string }[];
  backends: Backend[];
  rps: number;
  err5xx?: number;
  p95Ms?: number;
  /** 이 규칙을 막는 차단 id */
  blocked?: string;
  /** 출발지 차단 수 등 */
  note?: string;
  balance?: Balance;
  /** 관리 적용 분배 값의 revision. 0이나 없음 = app.yaml 선언 그대로 */
  balanceRevision?: number;
}
export interface IngressInstance {
  /** 서버별 매핑 키 */
  key?: string;
  tenant: string;
  app: string;
  node: string;
  generation: number;
  ready: boolean;
  draining?: boolean;
  /** 비우기 record revision (drain/undrain의 expected, 처음 0) */
  drainRevision?: number;
  drainStartedAt?: string;
  /** 진행 요청을 끝내는 마감(이때 남은 flow는 끊김) */
  drainDeadline?: string;
  /** 앱의 마지막 매핑을 비움(앱·네이티브는 지우지 않음) */
  lastMapping?: boolean;
  error?: string;
  observedAt?: string;
  /** sfcd가 아직 그 서버의 실행 상태를 보지 못함: 수치·인증서·백엔드 상태가 없다 */
  observed?: false;
  routes: IngressRoute[];
}
export interface TenantIngress {
  tenant: string;
  external: boolean;
  hosts: string[];
  /** 작업 공간 × 서버 사용량 */
  usage: { node: string; instances: [number, number]; rules: [number, number]; requests: [number, number]; connections: [number, number]; bufferMiB: [number, number] }[];
}
export interface IngressView {
  nodes: IngressNode[];
  instances: IngressInstance[];
  tenants: TenantIngress[];
  summary: { rps: number; err5xx: number; p95Ms: number };
  observedAt: string;
}
export type BlockKind = 'route' | 'host' | 'task' | 'app' | 'source' | 'node' | 'tenant' | 'gateway';
export interface BlockScope {
  kind: BlockKind;
  tenant?: string;
  /** 서버별 매핑 키(읽을 때만) */
  key?: string;
  route?: string;
  app?: string;
  node?: string;
  host?: string;
  prefix?: string;
  task?: string;
  sources?: string[];
  gateway?: Gateway | 'all';
}
export interface IngressBlock {
  id: string;
  /** lifting: 해제했지만 아직 모든 서버가 해제를 적용하지 않음 */
  state: 'active' | 'lifting';
  scope: BlockScope;
  response: '503' | '403' | 'drop';
  until?: string;
  by: string;
  at: string;
  reason: string;
  nodes: { node: string; state: 'applied' | 'pending' | 'lifted' | 'unobserved'; ms?: number; error?: string }[];
  blockedRequests: number;
  revision: number;
  killConnections?: boolean;
  targetMissing?: boolean;
}
export interface NewBlock {
  opId: string;
  scope: BlockScope;
  response: IngressBlock['response'];
  minutes?: number;
  // 끝나는 시각(RFC 3339, 7일 안). '오늘 자정까지'는 브라우저 시간대 자정을 계산해 보낸다.
  until?: string;
  reason: string;
  killConnections: boolean;
  drainSeconds?: number;
}
export interface IngressEvent {
  at: string;
  what: string;
  by: string;
  action?: string;
  /** 원 요청 ID */
  request?: string;
  tenant?: string;
  app?: string;
  node?: string;
  route?: string;
  gateway?: Gateway;
  /** 바꾼 뒤 공개 설정(JSON). 예전 모양은 글 */
  detail?: unknown;
  /** 바꾸기 전 공개 설정(JSON) */
  previous?: unknown;
}
export interface RouteDetail {
  instance: IngressInstance;
  metrics: { rps: number; concurrent?: [number, number]; connections: [number, number]; codes: string; latency: string; proxyFailures: string; probeFailures?: number; budget?: string; windowSeconds?: number };
  errors: { at: string; status: number; method: string; path: string; task: string; reason: string; ms: number; source: string }[];
  balanceHistory: IngressEvent[];
}

export const ingress = (p: { node?: string; tenant?: string } = {}, signal?: AbortSignal) => api.get<IngressView>(`/ingress${q(p)}`, signal);
// sfcd는 응답을 503·403(숫자)이나 "drop"으로 준다. 화면은 문자열로 다룬다.
export const ingressBlocks = (signal?: AbortSignal) =>
  api.get<{ items: IngressBlock[] }>('/ingress/blocks', signal).then((r) => ({ items: (r.items ?? []).map((b) => ({ ...b, state: b.state ?? 'active', response: String(b.response) as IngressBlock['response'], nodes: b.nodes ?? [] })) }));
/** 차단 id: 웹이 opId로 만든다(sfcd는 호출한 쪽의 id를 쓰고 다시 쓰지 않는다). */
export const blockIdOf = (opId: string) => `web-${opId.replace(/-/g, '')}`;
// 차단 추가·연장·해제는 그 사람의 작업(op)이다. 실패·거절은 오류로 바꾸고, 결과가 불확실하면(네트워크) 같은 opId로 다시 보낸다.
function opDone(op: DOp): DOp {
  if (op.state === 'failed' || op.state === 'rejected') throw new ApiError(422, { code: op.errorCode || op.state, message: op.errorCode ? `작업이 ${op.state === 'rejected' ? '거절' : '실패'}했습니다 (${op.errorCode}).` : `작업이 ${op.state === 'rejected' ? '거절' : '실패'}했습니다.` });
  return op;
}
/** 차단을 만들고, 차단 id(web-…)로 다시 읽어 돌려준다. 아직 목록에 없으면 잠깐 기다렸다 다시 본다. */
export async function addBlock(b: NewBlock): Promise<IngressBlock> {
  const { op } = await api.post<{ op: DOp }>('/ingress/blocks', b);
  opDone(op);
  const id = blockIdOf(b.opId);
  for (let i = 0; i < 5; i++) {
    const { items } = await ingressBlocks();
    const hit = items.find((x) => x.id === id);
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 600));
  }
  throw new ApiError(504, { code: 'not-yet', message: '차단 요청은 받았지만 아직 목록에 보이지 않습니다. 잠시 뒤 다시 읽어 주세요.' });
}
export const extendBlock = async (id: string, opId: string, minutes: number, revision: number) => opDone((await api.put<{ op: DOp }>(`/ingress/blocks/${encodeURIComponent(id)}`, { opId, minutes, revision })).op);
export const removeBlock = async (id: string, opId: string) => opDone((await api.del<{ op: DOp }>(`/ingress/blocks/${encodeURIComponent(id)}`, { opId })).op);
/** 공개 변경 이력: 새것부터 8개씩, next를 after로 이어 읽는다 */
export const ingressHistory = (signal?: AbortSignal, p: { tenant?: string; app?: string; node?: string; after?: string } = {}) =>
  api.get<{ items: IngressEvent[]; next?: string }>(`/ingress/history${q(p)}`, signal).then((r) => ({ items: r.items ?? [], next: r.next || undefined }));
// 게이트웨이·분배 방식·비우기는 그 사람의 작업(op)이다(#174). 화면은 useMutation으로 보낸다.
export const gatewayPath = (node: string) => `/nodes/${encodeURIComponent(node)}/gateways`;
/** 서버에 실제로 있는 주소(web-api 55). 응답마다 그 서버가 읽은 값이고, 닿지 못하면 [] */
export interface LocalAddress {
  iface: string;
  address: string;
  cidr: string;
  scope: 'public' | 'private' | 'loopback' | string;
}
export const nodeLocalAddresses = (node: string, signal?: AbortSignal) =>
  api.get<{ localAddresses?: LocalAddress[] | null }>(gatewayPath(node), signal).then((r) => r.localAddresses ?? []);
/** 게이트웨이 주소로 먼저 제안하지 않을 주소: sfc 서버 IP(10.254.240.0/20)와 Docker·sfc 브리지·터널 */
export const internalAddress = (a: LocalAddress) => /^10\.254\.(2[4-5]\d)\./.test(a.address) || /^(docker|br-|veth|mt|sfc)/.test(a.iface);
/** 비어 있는 주소 칸에 넣을 제안: 외부망은 첫 공인 주소, 로컬망은 내부용이 아닌 첫 사설 주소 */
export function suggestGatewayAddresses(list: LocalAddress[]): { external?: string; local?: string } {
  return {
    external: list.find((a) => a.scope === 'public')?.address,
    local: list.find((a) => a.scope === 'private' && !internalAddress(a))?.address,
  };
}
export const balancePath = (tenant: string, app: string) => `/t/${encodeURIComponent(tenant)}/apps/${encodeURIComponent(app)}/ingress/balance`;
export const drainPath = (tenant: string, app: string) => `/t/${encodeURIComponent(tenant)}/apps/${encodeURIComponent(app)}/ingress/drain`;
/** 앱이 여러 서버에 있으면 node로 고른다(빼면 첫 매핑). */
export const ingressApp = (tenant: string, app: string, signal?: AbortSignal, node?: string) => api.get<RouteDetail>(`/t/${encodeURIComponent(tenant)}/apps/${encodeURIComponent(app)}/ingress${q({ node })}`, signal);

/** 수신 주소(listener) 목록: 주소 · HTTP/3 · 오류 */
export const listenerList = (g: GatewayConf) => g.listeners.map((l) => `${l.address}${l.http3 ? ' (h3)' : ''}${l.error ? ` ✗ ${l.error}` : !l.ready ? ' · 준비 안 됨' : ''}`).join(', ');
/** 맞는 규칙 없음·출발지 거절 수(시스템 관리자에게만 온다). 없으면 빈 글 */
export const gwCounters = (g: GatewayConf) => (g.unmatched === undefined && g.sourceRejected === undefined ? '' : `규칙 없음 ${(g.unmatched ?? 0).toLocaleString('ko-KR')} · 출발지 거절 ${(g.sourceRejected ?? 0).toLocaleString('ko-KR')}`);
export const GW_NAME: Record<Gateway, string> = { external: '외부망', local: '로컬망' };
export const GW_SHORT: Record<Gateway, string> = { external: '외부', local: '로컬' };
export const RESP_NAME: Record<IngressBlock['response'], string> = { '503': '503 점검', '403': '403 거부', drop: '연결 끊기' };
export const BALANCE_NAME: Record<Balance['method'], string> = { 'round-robin': '순환 (라운드 로빈)', 'least-request': '요청 적은 곳 먼저', hash: '같은 사용자 → 같은 컨테이너', random: '무작위 (가중치)' };
export const BLOCK_KIND_NAME: Record<BlockKind, string> = { route: '경로', host: '도메인', task: '컨테이너', app: '앱', source: '출발지', node: '서버', tenant: '작업 공간', gateway: '게이트웨이' };
/** 0.0.0.0/0, ::/0 같은 모든 출발지 */
export const allSources = (s: string) => /^(0\.0\.0\.0\/0|::\/0)$/.test(s.trim());
export const CIDR_RE = /^(\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?|[0-9a-f:]+(\/\d{1,3})?)$/i;
export function scopeText(s: BlockScope): string {
  switch (s.kind) {
    case 'route':
      return `${s.host ?? ''} ${s.prefix ?? '/'}`;
    case 'host':
      return `${s.host} 전체`;
    case 'task':
      return `컨테이너 ${s.task}${s.node ? ` @ ${s.node}` : ''}`;
    case 'app':
      return `${s.tenant}/${s.app} 전체`;
    case 'source':
      return `출발지 ${(s.sources ?? []).join(', ')}${s.app ? ` → ${s.app}` : ''}`;
    case 'node':
      return `서버 ${s.node}${s.gateway && s.gateway !== 'all' ? ` ${GW_NAME[s.gateway]}` : ''}`;
    case 'tenant':
      return `작업 공간 ${s.tenant}`;
    case 'gateway':
      return `${s.gateway && s.gateway !== 'all' ? GW_NAME[s.gateway] : '모든'} 게이트웨이`;
  }
}

/** 호스트가 이 도메인에 드는가 (도메인 자신, 하위 이름, *.하위) */
export const inDomain = (host: string, domain: string) => {
  const h = host.replace(/^\*\./, '').toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
};
/** 도메인 → 외부망으로 그 도메인 호스트를 받는 서버와 앱 수 (외부 도메인 화면의 '연결된 서버') */
export function domainServers(v: IngressView, domain: string): { nodes: IngressNode[]; apps: number } {
  const ins = v.instances.filter((i) => i.routes.some((r) => r.gateway === 'external' && inDomain(r.host, domain)));
  const names = new Set(ins.map((i) => i.node));
  return { nodes: v.nodes.filter((n) => names.has(n.node)), apps: new Set(ins.map((i) => `${i.tenant}/${i.app}`)).size };
}
/** 서버 → 그 서버 외부망이 받는 호스트가 속한 도메인 */
export const nodeDomains = (v: IngressView, node: string, domains: string[]) => domains.filter((d) => v.instances.some((i) => i.node === node && i.routes.some((r) => r.gateway === 'external' && inDomain(r.host, d))));
/** 외부 접속이 켜진 서버의 상태 글 */
export const nodeIngressState = (n: IngressNode): ['ok' | 'wa' | 'er' | 'un', string] => (n.isolated ? ['wa', '격리됨 · DNS에서 뺌'] : !n.module ? ['un', '외부 접속 꺼짐'] : n.external?.state === 'error' ? ['er', '오류'] : n.external?.state === 'listening' ? ['ok', '수신 중'] : ['un', '외부망 꺼짐']);
/** 404·405면 데몬에 아직 없는 조회 */
export const ingressMissing = (e: unknown) => e instanceof ApiError && (e.status === 404 || e.status === 405);

type CertOf = Pick<IngressRoute, 'certificates'>;
/** 경로 규칙의 인증서 한 줄: ID 앞 12자, 둘 이상이면 알고리즘을 붙인다 */
export function routeCertText(r: CertOf): string {
  const all = r.certificates ?? [];
  return all
    .filter((c) => c.id)
    .map((c) => `${c.id!.slice(0, 12)}${all.length > 1 && c.alg ? ` (${c.alg === 'rsa' ? 'RSA' : 'ECDSA'})` : ''}`)
    .join(' · ');
}
/** 경로 규칙에 인증서 정보가 있는가(TLS 규칙) */
export const hasRouteCert = (r: CertOf) => !!r.certificates?.length;
/** 경로 규칙 인증서의 오류(인증서 없음 등) */
export const routeCertError = (r: CertOf) => r.certificates?.find((c) => c.error)?.error;

/** 클러스터 앱(sfc-web) 경로 설정 (PR #614 · docs/reference/web-api/47). 시스템 관리자만, /ingress 매핑 목록에는 없다 */
export interface ClusterAppRoutes {
  app: string;
  /** 다음 변경의 expected. 0 = 한 번도 정하지 않음 */
  revision: number;
  removed: boolean;
  node?: string;
  routes: { id?: string; host: string; prefix?: string; gateway: 'local' | 'external' | 'both' }[];
  /** 고쳐서 다시 보낼 route 파일 원문. 한 번도 정하지 않았으면 없다 */
  file?: string;
}
export const clusterAppRoutesPath = (app = 'web') => `/cluster-apps/${encodeURIComponent(app)}/routes`;
export const clusterAppRoutes = (signal?: AbortSignal, app = 'web') => api.get<ClusterAppRoutes>(clusterAppRoutesPath(app), signal).then((r) => ({ ...r, routes: r.routes ?? [] }));
