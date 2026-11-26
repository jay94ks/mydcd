// SPDX-License-Identifier: Apache-2.0

// 외부 접속 목업 (UI-5A~5C, REQ-22). 캔버스의 node-a·node-b·node-c, php-shop·shop-api·grafana로 채운다.
import type { RawResponse } from '../client';
import type { Balance, BlockScope, IngressBlock, IngressEvent, IngressInstance, IngressNode, IngressView, NewBlock, RouteDetail, TenantIngress } from '../ingress';

interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string, extra?: Record<string, unknown>) => RawResponse;
  me: () => { username: string; systemAdmin: boolean };
  /** 읽을 수 있는 작업 공간 */
  tenants: () => string[];
  canWrite: (t: string) => boolean;
}

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const later = (s: number) => new Date(Date.now() + s * 1000).toISOString();

const nodes: IngressNode[] = [
  {
    node: 'node-a',
    module: true,
    external: { address: '203.0.113.10', ports: [443, 80], rules: 3, state: 'listening', listeners: [{ id: 'ext-443', address: '203.0.113.10:443', http3: true, ready: true }, { id: 'ext-80', address: '203.0.113.10:80', http3: false, ready: true }], unmatched: 214, sourceRejected: 0 },
    local: { address: '10.0.0.11', iface: 'eth1', ports: [443], rules: 1, state: 'listening', listeners: [{ id: 'loc-443', address: '10.0.0.11:443', http3: false, ready: true }], unmatched: 0, sourceRejected: 0 },
    configuration: {
      source: 'cluster',
      revision: 2,
      appliedRevision: 2,
      external: { enabled: true, addresses: ['203.0.113.10'], ports: [443, 80], listeners: [{ id: 'ext-443', address: '203.0.113.10:443', tls: true, http3: true }, { id: 'ext-80', address: '203.0.113.10:80', http3: false }] },
      local: { enabled: true, addresses: ['10.0.0.11'], ports: [443], sources: ['10.0.0.0/8', '192.168.0.0/16'], listeners: [{ id: 'loc-443', address: '10.0.0.11:443', tls: true, http3: false }] },
    },
    connections: 1840,
    connectionLimit: 8000,
    rps: 416,
  },
  { node: 'node-b', module: true, external: { address: '203.0.113.11', ports: [443], rules: 1, state: 'listening', listeners: [{ id: 'ext-443', address: '203.0.113.11:443', http3: false, ready: false }], unmatched: 37, sourceRejected: 0 }, configuration: { source: 'file', revision: 0, appliedRevision: 0, error: 'bind 203.0.113.11:443: address not available', external: { enabled: true, addresses: ['203.0.113.11'], ports: [443], listeners: [{ id: 'ext-443', address: '203.0.113.11:443', tls: true, http3: false }] } }, connections: 610, connectionLimit: 4000, rps: 233 },
  { node: 'node-c', module: false, isolated: true, connections: 0, connectionLimit: 0, rps: 0 },
];
const ok = (s: number) => ({ ok: true, at: ago(s) });
const balance: Balance = {
  method: 'round-robin',
  locality: true,
  slowStartSeconds: 30,
  retry: 1,
  rules: [
    { kind: 'header', name: 'X-Canary', op: 'equals', value: '1', group: 'canary' },
    { kind: 'cookie', name: 'session', op: 'present', group: 'stable' },
    { kind: 'percent', percent: 10, group: 'canary' },
  ],
  fallback: 'default',
  groups: { stable: { labels: { track: 'stable' } }, canary: { version: '7-canary' } },
  actual: 'web-1 51% · web-2 48% · web-3 1% (조건 1 · 3에 맞은 요청, 지금은 긴급 차단으로 빠짐 → 기본으로 넘김)',
};
const instances: IngressInstance[] = [
  {
    key: 'shop/php-shop@node-a',
    tenant: 'shop',
    app: 'php-shop',
    node: 'node-a',
    observedAt: ago(4),
    generation: 7,
    ready: true,
    routes: [
      {
        id: 'r-shop-root',
        gateway: 'external',
        port: 443,
        host: 'shop.example.com',
        prefix: '/',
        service: 'web',
        servicePort: 8080,
        network: 'shop-net',
        certificates: [{ id: '9c41d2e85f30a7b16c94e0d3f8a2b57e1c06d49a3b8e72f5c1d0a6e94b3f7e07a', alg: 'ecdsa' }],
        backends: [
          { task: 'web-1', node: 'node-a', address: '10.240.10.10', port: 8080, weight: 1, generation: 7, group: 'stable', health: ok(3), rps: 208, p95Ms: 170 },
          { task: 'web-2', node: 'node-b', address: '10.240.11.12', port: 8080, weight: 1, generation: 7, group: 'stable', health: ok(2), rps: 204, p95Ms: 190 },
          { task: 'web-3', node: 'node-b', address: '10.240.11.13', port: 8080, weight: 1, generation: 7, group: 'canary', health: { ok: false, error: '연결 거부' }, rps: 0 },
        ],
        rps: 412,
        err5xx: 0.1,
        p95Ms: 180,
        balance,
      },
      {
        id: 'r-shop-admin',
        gateway: 'external',
        port: 443,
        host: 'shop.example.com',
        prefix: '/admin',
        service: 'admin',
        servicePort: 8081,
        network: 'shop-net',
        certificates: [{ id: '9c41d2e85f30a7b16c94e0d3f8a2b57e1c06d49a3b8e72f5c1d0a6e94b3f7e07a', alg: 'ecdsa' }],
        backends: [{ task: 'web-1', node: 'node-a', address: '10.240.10.10', port: 8081, weight: 1, generation: 7, health: ok(3), rps: 0 }],
        rps: 0,
        p95Ms: 0,
      },
      { id: 'r-shop-80', gateway: 'external', port: 80, host: '*.shop.example.com', prefix: '', redirect: 'https', backends: [], rps: 31 },
    ],
  },
  // 같은 앱이 다른 서버에도 있다. mydcd가 그 서버의 실행 상태를 아직 못 봤다(observed:false, 수치·인증서·백엔드 상태 없음).
  {
    key: 'shop/php-shop@node-b',
    tenant: 'shop',
    app: 'php-shop',
    node: 'node-b',
    generation: 7,
    ready: false,
    observed: false,
    routes: [
      { id: 'r-shop-root', gateway: 'external', port: 443, host: 'shop.example.com', prefix: '/', service: 'web', servicePort: 8080, network: 'shop-net', backends: [], rps: 0 },
      { id: 'r-shop-admin', gateway: 'external', port: 443, host: 'shop.example.com', prefix: '/admin', service: 'admin', servicePort: 8081, network: 'shop-net', backends: [], rps: 0 },
    ],
  },
  {
    key: 'shop/shop-api@node-b',
    tenant: 'shop',
    app: 'shop-api',
    node: 'node-b',
    observedAt: ago(6),
    generation: 3,
    ready: true,
    routes: [
      {
        id: 'r-api',
        gateway: 'external',
        port: 443,
        host: 'api.shop.example.com',
        prefix: '/',
        service: 'api',
        servicePort: 9000,
        network: 'shop-net',
        certificates: [{ id: '4e7b19c0d35a82f6e1b04c9d7a3f58e2b6c10d94a7e35f8b2c6d01e9a4f73b28', alg: 'ecdsa' }],
        backends: [
          { task: 'api-1', node: 'node-b', address: '10.240.11.20', port: 9000, weight: 1, generation: 3, health: ok(4), rps: 118, p95Ms: 210 },
          { task: 'api-2', node: 'node-b', address: '10.240.11.21', port: 9000, weight: 1, generation: 3, health: ok(5), rps: 115, p95Ms: 1800, slow: true },
        ],
        rps: 233,
        err5xx: 2.4,
        p95Ms: 900,
      },
    ],
  },
  {
    key: 'internal/grafana@node-a',
    tenant: 'internal',
    app: 'grafana',
    node: 'node-a',
    observedAt: ago(4),
    generation: 2,
    ready: true,
    routes: [
      {
        id: 'r-grafana',
        gateway: 'local',
        port: 443,
        host: 'grafana.internal',
        prefix: '/',
        service: 'grafana',
        servicePort: 3000,
        network: 'internal-net',
        certificates: [{ id: 'b2a85f0c3e961d47a0c5e8b3f21d6a94c7e03b58d1f6a29e4c70b3d85a1e6f90', alg: 'ecdsa' }],
        backends: [{ task: 'grafana-1', node: 'node-a', address: '10.240.20.10', port: 3000, weight: 1, generation: 2, health: ok(6), rps: 4, p95Ms: 60 }],
        rps: 4,
        p95Ms: 60,
      },
    ],
  },
];
const tenantConf: TenantIngress[] = [
  {
    tenant: 'shop',
    external: true,
    hosts: ['*.shop.example.com'],
    usage: [
      { node: 'node-a', instances: [1, 2], rules: [3, 16], requests: [96, 512], connections: [1800, 4000], bufferMiB: [18, 64] },
      { node: 'node-b', instances: [1, 2], rules: [1, 16], requests: [470, 512], connections: [610, 2000], bufferMiB: [9, 32] },
    ],
  },
  { tenant: 'internal', external: false, hosts: ['*.internal'], usage: [{ node: 'node-a', instances: [1, 2], rules: [1, 16], requests: [4, 512], connections: [40, 1000], bufferMiB: [1, 32] }] },
  { tenant: 'lab', external: false, hosts: [], usage: [] },
];
const blocks: IngressBlock[] = [
  { id: 'web-0931a1b2c3d44e5f8a9b0c1d2e3f4a5b', state: 'active', scope: { kind: 'route', tenant: 'shop', app: 'php-shop', node: 'node-a', key: 'shop/php-shop@node-a', route: 'r-shop-admin', host: 'shop.example.com', prefix: '/admin', gateway: 'external' }, response: '503', by: 'alice', at: ago(12 * 60), reason: '관리자 페이지 무차별 로그인 시도', nodes: [{ node: 'node-a', state: 'applied', ms: 1400 }], blockedRequests: 4310, revision: 1, killConnections: false },
  { id: 'web-0930a1b2c3d44e5f8a9b0c1d2e3f4a5b', state: 'active', scope: { kind: 'source', tenant: 'shop', app: 'shop-api', sources: ['198.51.100.0/24'] }, response: 'drop', until: later(48 * 60), by: 'bob', at: ago(40 * 60), reason: '크리덴셜 스터핑 의심 (최근 1분 4xx 2,300건)', nodes: [{ node: 'node-b', state: 'applied', ms: 900 }], blockedRequests: 2300, revision: 2, killConnections: true },
  { id: 'web-0929a1b2c3d44e5f8a9b0c1d2e3f4a5b', state: 'active', scope: { kind: 'task', tenant: 'shop', app: 'php-shop', node: 'node-a', key: 'shop/php-shop@node-a', task: 'web-3' }, response: 'drop', by: 'alice', at: ago(14 * 60), reason: '상태 검사 반복 실패', nodes: [{ node: 'node-a', state: 'applied', ms: 800 }, { node: 'node-b', state: 'pending', error: 'gateway-not-ready' }], blockedRequests: 0, revision: 1, killConnections: false },
];
const history: IngressEvent[] = [
  { at: ago(4 * 60), what: '출발지 198.51.100.0/24 차단 연장 30분', by: 'bob', action: 'extend-ingress-block', request: 'web-0930a1b2', tenant: 'shop', app: 'shop-api' },
  { at: ago(12 * 60), what: '경로 /admin 차단 (503)', by: 'alice', action: 'block-ingress', request: 'web-0931a1b2', tenant: 'shop', app: 'php-shop', node: 'node-a', route: 'r-shop-admin' },
  { at: ago(14 * 60), what: '컨테이너 web-3 빼기', by: 'alice', action: 'block-ingress', request: 'web-0929a1b2', tenant: 'shop', app: 'php-shop', node: 'node-a' },
  { at: ago(50 * 60), what: '서버 node-a 게이트웨이 바꿈', by: 'alice', action: 'set-node-gateways', request: 'web-gw-a2', node: 'node-a', gateway: 'local', previous: { local: { ports: [443], sources: ['10.0.0.0/8'] } }, detail: { local: { ports: [443], sources: ['10.0.0.0/8', '192.168.0.0/16'] } } },
  { at: ago(2 * 3600), what: 'php-shop 분배 방식 · least-request → round-robin', by: 'alice', action: 'set-ingress-balance', request: 'web-bal-1', tenant: 'shop', app: 'php-shop', node: 'node-a', route: 'r-shop-root' },
  { at: ago(3 * 3600), what: 'shop-api 비우기 해제', by: 'bob', action: 'undrain-ingress', request: 'web-und-1', tenant: 'shop', app: 'shop-api', node: 'node-b' },
  { at: ago(3 * 3600 + 120), what: 'shop-api 비우기', by: 'bob', action: 'drain-ingress', request: 'web-drn-1', tenant: 'shop', app: 'shop-api', node: 'node-b' },
  { at: ago(5 * 3600), what: '도메인 shop.example.com 정책 바꿈', by: 'alice', action: 'set-ingress-host-policy', request: 'web-hp-1', tenant: 'shop' },
  { at: ago(26 * 3600), what: '서버 node-b 게이트웨이 바꿈', by: 'alice', action: 'set-node-gateways', request: 'web-gw-b1', node: 'node-b', gateway: 'external' },
];
const balanceHistory: IngressEvent[] = [
  { at: ago(2 * 86400), what: '조건 3 추가 · 나머지 10% → canary', by: 'alice', route: 'r-shop-root' },
  { at: ago(4 * 86400), what: '가중치 web-1 1 → 2', by: 'bob', route: 'r-shop-root' },
  { at: ago(20 * 86400), what: 'least-request → round-robin', by: 'alice', route: 'r-shop-root' },
];

function applyBlocks() {
  for (const i of instances)
    for (const r of i.routes) {
      r.blocked = blocks.find((b) => (b.state === 'active' && b.scope.kind === 'route' && b.scope.host === r.host && b.scope.prefix === r.prefix && (!b.scope.node || b.scope.node === i.node)) || (b.scope.kind === 'host' && b.scope.host === r.host) || (b.scope.kind === 'app' && b.scope.tenant === i.tenant && b.scope.app === i.app && (!b.scope.node || b.scope.node === i.node)) || (b.scope.kind === 'tenant' && b.scope.tenant === i.tenant) || (b.scope.kind === 'node' && b.scope.node === i.node && (b.scope.gateway === 'all' || b.scope.gateway === r.gateway)) || (b.scope.kind === 'gateway' && (b.scope.gateway === 'all' || b.scope.gateway === r.gateway)))?.id;
      const src = blocks.filter((b) => b.scope.kind === 'source' && (!b.scope.app || (b.scope.app === i.app && b.scope.tenant === i.tenant)));
      r.note = src.length ? `출발지 ${src.length}개 차단` : undefined;
      for (const be of r.backends) be.blocked = blocks.find((b) => b.state === 'active' && b.scope.kind === 'task' && b.scope.task === be.task && b.scope.app === i.app && (!b.scope.node || b.scope.node === i.node))?.id;
    }
}
applyBlocks();

export function registerIngress(ctx: Ctx) {
  const { on, ok: reply, err } = ctx;
  const admin = () => ctx.me().systemAdmin;
  const mine = (t?: string) => admin() || (!!t && ctx.tenants().includes(t));
  // 해제한 차단은 모든 서버가 적용할 때까지 lifting으로 남는다(목업: 3초).
  const lifting = new Map<string, number>();
  const sweep = () => {
    const now = Date.now();
    for (let i = blocks.length - 1; i >= 0; i--) {
      const b = blocks[i];
      const liftAt = lifting.get(b.id);
      if ((b.until && Date.parse(b.until) < now && b.state === 'active') || (liftAt !== undefined && liftAt < now)) {
        blocks.splice(i, 1);
        lifting.delete(b.id);
      }
    }
    applyBlocks();
  };
  const strip = (g?: IngressNode['external']) => g && (({ unmatched: _u, sourceRejected: _s, ...rest }) => rest)(g);
  on('GET', '/ingress', (_m, _b, q) => {
    sweep();
    const node = q.get('node');
    const t = q.get('tenant');
    const ins = instances.filter((i) => mine(i.tenant) && (!node || i.node === node) && (!t || i.tenant === t));
    const rps = ins.reduce((s, i) => s + i.routes.reduce((x, r) => x + r.rps, 0), 0);
    const v: IngressView = {
      // 맞는 규칙 없음·출발지 거절 수는 시스템 관리자에게만 붙인다.
      nodes: admin() ? nodes : nodes.map((n) => ({ ...n, external: strip(n.external), local: strip(n.local) })).filter((n) => ins.some((i) => i.node === n.node)).map((n) => ({ ...n, connections: ins.filter((i) => i.node === n.node).length * 600, rps: ins.filter((i) => i.node === n.node).reduce((s, i) => s + i.routes.reduce((x, r) => x + r.rps, 0), 0) })),
      instances: ins,
      tenants: tenantConf.filter((c) => mine(c.tenant)),
      summary: { rps, err5xx: 0.9, p95Ms: 210 },
      observedAt: ago(5),
    };
    return reply(v);
  });
  on('GET', '/ingress/blocks', () => {
    sweep();
    // mydcd는 503·403을 숫자로 준다.
    return reply({ items: blocks.filter((b) => mine(b.scope.tenant) || admin()).map((b) => ({ ...b, response: b.response === 'drop' ? 'drop' : Number(b.response) })) });
  });
  // 새것부터 8개씩, next(목업: 위치)를 after로
  on('GET', '/ingress/history', (_m, _b, q) => {
    const t = q.get('tenant');
    const a = q.get('app');
    const nd = q.get('node');
    const all = (admin() ? history : history.filter((h) => h.tenant && mine(h.tenant))).filter((h) => (!t || h.tenant === t) && (!a || h.app === a) && (!nd || h.node === nd));
    const from = Number(q.get('after') ?? 0) || 0;
    const items = all.slice(from, from + 8);
    return reply({ items, next: from + 8 < all.length ? String(from + 8) : '' });
  });
  // 차단 추가·연장·해제는 작업(op)으로 돌려준다. 차단 id는 웹이 opId로 만든 web-….
  const opOk = (opId: unknown, action: string, target: string, requestId?: string) => {
    const now = new Date().toISOString();
    return { op: { id: String(opId), requestId, action, target, state: 'applied', submittedAt: now, updatedAt: now } };
  };
  const opFail = (opId: unknown, action: string, target: string) => {
    const now = new Date().toISOString();
    return { op: { id: String(opId), action, target, state: 'failed', resultFound: true, resultCode: 1, submittedAt: now, updatedAt: now } };
  };
  const badOp = (opId: unknown) => !/^[0-9a-f-]{36}$/.test(String(opId ?? ''));
  on('POST', '/ingress/blocks', (_m, body) => {
    const b = body as unknown as NewBlock;
    const s = (b.scope ?? {}) as BlockScope;
    if (!/^[0-9a-f-]{36}$/.test(String(b.opId ?? ''))) return err(400, 'bad-request', 'opId는 소문자 UUID v4여야 합니다.');
    if (['node', 'tenant', 'gateway'].includes(s.kind) && !admin()) return err(403, 'denied', '시스템 관리자만 이 범위를 막을 수 있습니다.');
    if (!['node', 'gateway'].includes(s.kind) && !(admin() || (s.tenant && ctx.canWrite(s.tenant)))) return err(403, 'denied', '이 작업 공간에서 망(Network) 관리 권한이 있어야 긴급 차단할 수 있습니다.');
    if (!String(b.reason ?? '').trim()) return err(422, 'invalid', '이유를 적어 주세요.');
    if (s.kind === 'source') {
      const src = s.sources ?? [];
      if (src.length !== 1) return err(422, 'invalid', 'IP 또는 CIDR을 하나 적어 주세요.');
      if (src.some((x) => /^(0\.0\.0\.0\/0|::\/0)$/.test(x))) return err(422, 'all-sources', '모든 출발지를 막는 값입니다.');
    }
    if (s.kind === 'route' && !instances.some((i) => i.routes.some((r) => r.host === s.host && r.prefix === s.prefix))) return err(422, 'no-route', '규칙에 없는 경로는 막을 수 없습니다.');
    if (['route', 'task', 'app'].includes(s.kind)) {
      const onApp = instances.filter((i) => i.tenant === s.tenant && i.app === s.app && (!s.node || i.node === s.node));
      if (!onApp.length) return err(422, 'invalid', 'scope: the app has no external access instance there');
      if (onApp.length > 1) return err(422, 'scope.node', 'scope.node: the app runs on several servers; block it on one');
    }
    const dup = blocks.find((x) => JSON.stringify(x.scope) === JSON.stringify(s));
    if (dup) return err(409, 'exists', '같은 범위의 차단이 이미 있습니다.');
    const mins = Number(b.minutes ?? 0);
    if ((b as { untilMidnight?: unknown }).untilMidnight !== undefined) return err(422, 'invalid', 'untilMidnight는 받지 않습니다. until로 보내 주세요.');
    if (mins < 0) return err(422, 'invalid', 'minutes는 0 이상이어야 합니다.');
    if (b.until !== undefined && b.minutes !== undefined) return err(422, 'invalid', 'minutes와 until 중 하나만 보내 주세요.');
    if (b.until !== undefined) {
      const t = Date.parse(String(b.until));
      if (!Number.isFinite(t) || t <= Date.now() || t > Date.now() + 7 * 86400000) return err(422, 'invalid', 'until은 지금부터 7일 안이어야 합니다.');
    }
    const until = b.until !== undefined ? new Date(Date.parse(String(b.until))).toISOString() : mins > 0 ? later(mins * 60) : undefined;
    const affected = s.kind === 'node' ? [s.node!] : s.kind === 'gateway' || s.kind === 'tenant' ? nodes.filter((n) => n.module).map((n) => n.node) : [...new Set(instances.filter((i) => !s.tenant || i.tenant === s.tenant).filter((i) => !s.app || i.app === s.app).map((i) => i.node))];
    const nb: IngressBlock = { id: `web-${String(b.opId).replace(/-/g, '')}`, state: 'active', killConnections: !!b.killConnections, scope: s, response: b.response ?? '503', until, by: ctx.me().username, at: new Date().toISOString(), reason: String(b.reason).slice(0, 200), nodes: affected.map((n) => (n === 'node-c' ? { node: n, state: 'pending' as const, error: 'node-unreachable' } : { node: n, state: 'applied' as const, ms: 1200 + Math.round(Math.random() * 400) })), blockedRequests: 0, revision: 1 };
    blocks.unshift(nb);
    history.unshift({ at: nb.at, what: `${s.kind === 'task' ? `컨테이너 ${s.task} 빼기` : `${s.kind === 'route' ? `경로 ${s.prefix}` : s.kind === 'source' ? `출발지 ${(s.sources ?? []).join(', ')}` : s.kind === 'host' ? `도메인 ${s.host}` : s.kind === 'app' ? `앱 ${s.app}` : s.kind === 'node' ? `서버 ${s.node}` : s.kind === 'tenant' ? `작업 공간 ${s.tenant}` : '게이트웨이'} 차단 (${nb.response === 'drop' ? '연결 끊기' : nb.response})`}`, by: nb.by });
    applyBlocks();
    return reply(opOk(b.opId, 'ingress-block', `ingress/block/${nb.id}`, nb.id));
  });
  on('PUT', '/ingress/blocks/:id', (m, body) => {
    const b = blocks.find((x) => x.id === m[0]);
    if (!b || !(mine(b.scope.tenant) || admin())) return err(404, 'not-found', '없는 차단입니다.');
    if (badOp(body.opId)) return err(400, 'bad-request', 'opId는 소문자 UUID v4여야 합니다.');
    if (body.revision !== b.revision) return err(409, 'stale', '그사이 다른 사람이 바꿨습니다.');
    if (!b.until) return err(422, 'no-end', 'the block has no end; nothing to extend');
    const mins = Number(body.minutes ?? 0);
    if (!(mins >= 1 && mins <= 7 * 1440)) return err(422, 'invalid', 'minutes: 1분~7일');
    b.until = new Date(Math.max(Date.parse(b.until), Date.now()) + mins * 60000).toISOString();
    b.revision += 1;
    history.unshift({ at: new Date().toISOString(), what: `${b.id} 차단 연장 ${mins}분`, by: ctx.me().username });
    return reply(opOk(body.opId, 'ingress-block-extend', `ingress/block/${b.id}`));
  });
  on('DELETE', '/ingress/blocks/:id', (m, body) => {
    if (badOp(body?.opId)) return err(400, 'bad-request', 'opId는 소문자 UUID v4여야 합니다.');
    const i = blocks.findIndex((x) => x.id === m[0]);
    if (i < 0) return err(404, 'not-found', '없는 차단입니다.');
    const b = blocks[i];
    if (['node', 'tenant', 'gateway'].includes(b.scope.kind) ? !admin() : !(admin() || (b.scope.tenant && ctx.canWrite(b.scope.tenant)))) return err(403, 'denied', '이 차단을 풀 권한이 없습니다.');
    if (b.state === 'lifting') return err(404, 'not-found', '이미 해제한 차단입니다.');
    b.state = 'lifting';
    b.revision += 1;
    b.nodes = b.nodes.map((x) => ({ node: x.node, state: x.node === 'node-c' ? 'unobserved' : 'pending' }));
    lifting.set(b.id, Date.now() + 3000);
    setTimeout(() => b.nodes.forEach((x) => x.state === 'pending' && (x.state = 'lifted')), 1200);
    history.unshift({ at: new Date().toISOString(), what: `${b.id} 해제`, by: ctx.me().username });
    applyBlocks();
    return reply(opOk(body.opId, 'ingress-unblock', `ingress/block/${b.id}`));
  });
  on('GET', '/t/:t/apps/:a/ingress', (m, _b, q) => {
    if (!mine(m[0])) return err(403, 'denied', '이 작업 공간이 없거나 볼 권한이 없습니다.');
    sweep();
    // 여러 서버에 있으면 node로 고르고, 빼면 첫 매핑이다.
    const ins = instances.find((i) => i.tenant === m[0] && i.app === m[1] && (!q.get('node') || i.node === q.get('node')));
    if (!ins) return err(404, 'not-found', '이 앱에는 외부 접속이 없습니다.');
    const rps = ins.routes.reduce((s, r) => s + r.rps, 0);
    const d: RouteDetail = {
      instance: ins,
      metrics: { rps, concurrent: [96, 512], connections: [1800, 4000], codes: '2xx 97.8% · 3xx 1.9% · 4xx 0.2% · 5xx 0.1%', latency: 'p50 38 ms · p95 180 ms · p99 420 ms', proxyFailures: '12 · 마지막 upstream-reset 3분 전', windowSeconds: 60 },
      errors: [
        { at: ago(60), status: 502, method: 'POST', path: '/checkout', task: 'web-2', reason: 'upstream-reset', ms: 1200, source: '203.0.113.x' },
        { at: ago(91), status: 503, method: 'GET', path: '/admin/login', task: 'web-1', reason: '⛔ 긴급 차단', ms: 0, source: '198.51.100.x' },
        { at: ago(92), status: 503, method: 'GET', path: '/admin/login', task: 'web-1', reason: '⛔ 긴급 차단', ms: 0, source: '198.51.100.x' },
        { at: ago(250), status: 504, method: 'GET', path: '/report/2025', task: 'web-1', reason: 'request-deadline 30s', ms: 30000, source: '192.0.2.x' },
      ],
      balanceHistory,
    };
    return reply(d);
  });
  // 분배 방식·비우기·게이트웨이는 작업(op)이다(데몬 #174 계약). 값 검사는 mydcd 몫이라 목업은 큰 것만 본다.
  const RULE_KINDS = ['header', 'cookie', 'query', 'method', 'source', 'percent'];
  on('PUT', '/t/:t/apps/:a/ingress/balance', (m, body) => {
    if (badOp(body.opId)) return err(400, 'bad-request', 'opId는 소문자 UUID v4여야 합니다.');
    if (!(admin() || ctx.canWrite(m[0]))) return err(403, 'denied', '이 작업 공간의 배포 권한이 필요합니다.');
    const ins = instances.find((i) => i.tenant === m[0] && i.app === m[1]);
    const r = ins?.routes.find((x) => x.id === body.route);
    if (!ins || !r) return err(404, 'not-found', '없는 경로 규칙입니다.');
    const cur = r.balance;
    // 관리 분배 record revision이 expected(처음 0). 다르면 op failed(CAS)
    if (Number(body.revision ?? 0) !== (r.balanceRevision ?? 0)) return reply(opFail(body.opId, 'set-ingress-balance', `ingress/${m[0]}/${m[1]}/${r.id}`));
    const nb = body.balance as Balance;
    if (!Number.isInteger(nb.retry) || nb.retry < 0 || nb.retry > 8) return err(422, 'invalid', 'balance.retry: 0~8 정수');
    if (Number((nb as { perTaskLimit?: number }).perTaskLimit ?? 0) !== 0) return err(422, 'invalid', 'balance.perTaskLimit는 mydcd에 없습니다.');
    if (typeof nb.locality !== 'boolean') return err(422, 'invalid', 'balance.locality: bool');
    if ((nb.rules ?? []).some((x) => !RULE_KINDS.includes(x.kind) || !x.group)) return err(422, 'invalid', 'balance.rules');
    if ('actual' in nb) return err(400, 'bad-request', 'unknown field balance.actual');
    const what = cur && cur.method !== nb.method ? `${cur.method} → ${nb.method}` : nb.weights && JSON.stringify(nb.weights) !== JSON.stringify(cur?.weights) ? `가중치 ${Object.entries(nb.weights).map(([k, v]) => `${k} ${v}`).join(', ')}` : '분배 설정 바꿈';
    r.balance = { ...nb, groups: cur?.groups, actual: cur?.actual };
    r.balanceRevision = (r.balanceRevision ?? 0) + 1;
    if (nb.weights) for (const be of r.backends) if (nb.weights[be.task] !== undefined) be.weight = nb.weights[be.task];
    const at = new Date().toISOString();
    balanceHistory.unshift({ at, what, by: ctx.me().username, route: r.id });
    history.unshift({ request: `web-${Date.now().toString(36)}`, at, what: `${m[1]} 분배 방식 · ${what}`, by: ctx.me().username, action: 'set-ingress-balance', tenant: m[0], app: m[1], route: r.id, previous: cur, detail: nb });
    return reply(opOk(body.opId, 'set-ingress-balance', `ingress/${m[0]}/${m[1]}/${r.id}`));
  });
  const drain = (on: boolean) => (m: string[], body: Record<string, unknown>) => {
    if (badOp(body?.opId)) return err(400, 'bad-request', 'opId는 소문자 UUID v4여야 합니다.');
    if (!(admin() || ctx.canWrite(m[0]))) return err(403, 'denied', '이 작업 공간의 배포 권한이 필요합니다.');
    const ins = instances.find((i) => i.tenant === m[0] && i.app === m[1] && (!body.node || i.node === body.node));
    if (!ins) return err(404, 'not-found', '이 앱에는 외부 접속이 없습니다.');
    const secs = Number(body.drainSeconds ?? 0);
    if (on && (!Number.isInteger(secs) || secs < 0 || secs > 3600)) return err(422, 'invalid', 'drainSeconds: 0~3600');
    if (Number(body.revision ?? 0) !== (ins.drainRevision ?? 0)) return reply(opFail(body.opId, on ? 'drain-ingress' : 'undrain-ingress', `ingress/${m[0]}/${m[1]}`));
    ins.draining = on ? true : undefined;
    ins.ready = !on;
    ins.drainRevision = (ins.drainRevision ?? 0) + 1;
    ins.drainStartedAt = on ? new Date().toISOString() : undefined;
    ins.drainDeadline = on ? later(secs || 30) : undefined;
    ins.lastMapping = on && instances.filter((i) => i.tenant === m[0] && i.app === m[1] && !i.draining).length === 0 ? true : undefined;
    history.unshift({ request: `web-${Date.now().toString(36)}`, at: new Date().toISOString(), what: `${m[1]} ${on ? '비우기' : '비우기 해제'}`, by: ctx.me().username, action: on ? 'drain-ingress' : 'undrain-ingress', tenant: m[0], app: m[1], node: ins.node });
    return reply(opOk(body.opId, on ? 'drain-ingress' : 'undrain-ingress', `ingress/${m[0]}/${m[1]}`));
  };
  on('POST', '/t/:t/apps/:a/ingress/drain', drain(true));
  on('DELETE', '/t/:t/apps/:a/ingress/drain', drain(false));
  on('PUT', '/nodes/:n/gateways', (m, body) => {
    if (badOp(body.opId)) return err(400, 'bad-request', 'opId는 소문자 UUID v4여야 합니다.');
    if (!admin()) return err(403, 'denied', '시스템 관리자 권한이 필요합니다.');
    const n = nodes.find((x) => x.node === m[0]);
    if (!n) return err(404, 'not-found', '없는 서버입니다.');
    // 이 서버 gateway record revision이 expected(클러스터 설정이 없으면 0)
    const curRev = n.configuration?.source === 'cluster' ? n.configuration.revision : 0;
    if (Number(body.revision ?? 0) !== curRev) return reply(opFail(body.opId, 'set-node-gateways', `nodes/${n.node}/gateways`));
    for (const g of ['external', 'local'] as const) {
      const c = body[g] as (Partial<IngressNode['external']> & { enabled: boolean }) | undefined;
      if (!c) continue;
      if ('iface' in c) return err(422, 'invalid', `${g}.iface는 바꿀 수 없습니다.`);
      if (g === 'external' && 'sources' in c) return err(422, 'invalid', 'external.sources는 받지 않습니다.');
      if (c.enabled && /^(0\.0\.0\.0|::)$/.test(String(c.address ?? ''))) return err(422, 'invalid', '모든 주소 수신(0.0.0.0·::)은 쓸 수 없습니다.');
    }
    for (const g of ['external', 'local'] as const) {
      const c = body[g] as (Partial<IngressNode['external']> & { enabled: boolean }) | undefined;
      if (!c) continue;
      const prev = n[g];
      const addr = String((c as { addresses?: string[] }).addresses?.[0] ?? c.address ?? prev?.address ?? '');
      const ports = (c.ports as number[]) ?? prev?.ports ?? [443];
      n[g] = c.enabled ? { address: addr, iface: prev?.iface, ports, rules: prev?.rules ?? 0, state: 'listening', listeners: ports.map((p) => ({ id: `${g === 'external' ? 'ext' : 'loc'}-${p}`, address: `${addr}:${p}`, http3: g === 'external' && p === 443, ready: true })), unmatched: prev?.unmatched ?? 0, sourceRejected: prev?.sourceRejected ?? 0 } : undefined;
    }
    n.module = !!(n.external || n.local);
    const setting = (g: 'external' | 'local') => {
      const c = body[g] as { enabled?: boolean; addresses?: string[]; address?: string; ports?: number[]; sources?: string[]; listeners?: { id: string; address: string; tls?: boolean; http3: boolean }[] } | undefined;
      const old = n.configuration?.[g];
      if (!c) return old;
      return { enabled: !!c.enabled, addresses: c.addresses ?? (c.address ? [c.address] : old?.addresses ?? []), ports: c.ports ?? old?.ports ?? [], ...(g === 'local' ? { sources: c.sources ?? old?.sources ?? [] } : {}), listeners: c.listeners ?? old?.listeners ?? [] };
    };
    const rev = curRev + 1;
    const before = n.configuration ? { external: n.configuration.external, local: n.configuration.local } : undefined;
    n.configuration = { source: 'cluster', revision: rev, appliedRevision: curRev, external: setting('external'), local: setting('local') };
    // 수락과 실제 bind는 따로: 잠시 뒤 서버가 적용
    setTimeout(() => {
      if (n.configuration && n.configuration.revision === rev) n.configuration.appliedRevision = rev;
    }, 3000);
    history.unshift({ request: `web-${Date.now().toString(36)}`, at: new Date().toISOString(), what: `서버 ${n.node} 게이트웨이 바꿈`, by: ctx.me().username, action: 'set-node-gateways', node: n.node, previous: before, detail: { external: n.configuration.external, local: n.configuration.local } });
    return reply(opOk(body.opId, 'set-node-gateways', `nodes/${n.node}/gateways`));
  });
}
