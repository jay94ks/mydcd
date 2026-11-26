// SPDX-License-Identifier: Apache-2.0

// 웹훅 목업 (UI-BB). 캔버스의 shop-runbook-bot·pagerduty·ops-teams·internal-audit로 채운다.
// 서명 비밀은 만들 때와 바꿀 때 한 번만 돌려주고 여기에도 값을 남기지 않는다.
import type { RawResponse } from '../client';
import type { CdGate, Delivery, Webhook, WebhookLink } from '../webhooks';

interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string, extra?: Record<string, unknown>) => RawResponse;
  me: () => { username: string; systemAdmin: boolean };
  canWrite: (t: string) => boolean;
  reader: (t: string) => void;
  /** 자동 배포 앱이면 동기화 모드, 아니면 undefined */
  cdMode: (t: string, app: string) => string | undefined;
  automation: () => { configured: boolean; username?: string };
}

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const later = (s: number) => new Date(Date.now() + s * 1000).toISOString();
const secret = () => `whsec_${Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('')}`;

const hooks: Webhook[] = [
  { name: 'shop-runbook-bot', tenant: 'shop', kind: 'internal', target: { app: 'runbook-bot', service: 'api', port: 8080, path: '/decide', scheme: 'http' }, role: 'decide', format: 'mydc', sign: 'hmac', secret: { set: true }, state: 'ok', enabled: true, lastDelivery: { at: ago(120), status: 200, ms: 400 }, stats: { today: 128, failed: 0, avgMs: 400 }, revision: 3 },
  { name: 'pagerduty', kind: 'external', url: 'https://events.pagerduty.com/v2/enqueue', role: 'notify', format: 'pagerduty', sign: 'token', token: { set: true, last4: 'a91c' }, secret: { set: false }, state: 'ok', enabled: true, lastDelivery: { at: ago(120), status: 202, ms: 300 }, stats: { today: 14, failed: 0, avgMs: 300 }, revision: 2 },
  { name: 'ops-teams', kind: 'external', url: 'https://corp.webhook.office.com/webhookb2/3f0c…7d1', role: 'notify', format: 'teams', sign: 'none', secret: { set: false }, state: 'failing', enabled: true, error: '429 Too Many Requests', lastDelivery: { at: ago(60), status: 429, ms: 900, retry: { attempt: 2, of: 3 } }, stats: { today: 9, failed: 3, avgMs: 700 }, revision: 5 },
  { name: 'qa-gate', tenant: 'shop', kind: 'internal', target: { app: 'qa-runner', service: 'api', port: 8080, path: '/gate', scheme: 'http' }, role: 'decide', format: 'mydc', sign: 'hmac', secret: { set: true }, state: 'ok', enabled: true, lastDelivery: { at: ago(86400), status: 200, ms: 1200 }, stats: { today: 3, failed: 0, avgMs: 1200 }, revision: 2 },
  { name: 'smoke-test', tenant: 'shop', kind: 'internal', target: { app: 'qa-runner', service: 'api', port: 8080, path: '/smoke', scheme: 'http' }, role: 'decide', format: 'mydc', sign: 'hmac', secret: { set: true }, state: 'ok', enabled: true, lastDelivery: { at: ago(86400), status: 200, ms: 900 }, stats: { today: 2, failed: 0, avgMs: 900 }, revision: 1 },
  { name: 'internal-audit', tenant: 'internal', kind: 'internal', target: { app: 'audit-sink', service: 'http', port: 9000, path: '/mydc', scheme: 'http' }, role: 'notify', format: 'mydc', sign: 'hmac', secret: { set: true }, state: 'disabled', enabled: false, disabledReason: 'failures', error: 'SERVICE_NO_READY_TASK', lastDelivery: { at: ago(3600), status: 0, ms: 0 }, stats: { today: 0, failed: 3, avgMs: 0 }, revision: 4 },
];
const links: WebhookLink[] = [
  { id: 'l-1', point: 'incident', scope: { tenant: 'shop' }, events: ['detected', 'approval', 'mitigated', 'recovered', 'rejected'], webhook: 'shop-runbook-bot', role: 'decide', revision: 1, label: 'shop 앱' },
  { id: 'l-2', point: 'cd', scope: { tenant: 'shop', app: 'worker-batch' }, events: [], webhook: 'qa-gate', role: 'decide', revision: 1, label: '배포 전 확인: worker-batch CD', kind: 'pre-sync', waitSeconds: 20, onTimeout: 'hold', approver: { account: 'mydc-autofix', scope: 'ApproveCD shop/worker-batch', state: 'ok' }, last: { at: ago(86400), status: 200, ms: 1200, commit: '4e1a9c2', answer: 'pass' } },
  { id: 'l-10', point: 'cd', scope: { tenant: 'shop', app: 'worker-batch' }, events: [], webhook: 'smoke-test', role: 'decide', revision: 1, label: '배포 후 확인: worker-batch CD', kind: 'post-sync', waitSeconds: 60, onTimeout: 'pass', when: 'healthy', onFail: 'pause-rollback', openIncident: true, last: { at: ago(86400), status: 200, ms: 900, commit: '4e1a9c2', answer: 'ok' } },
  { id: 'l-11', point: 'cd', scope: { tenant: 'shop', app: 'worker-batch' }, events: ['candidate-created', 'approval-required', 'sync-succeeded', 'sync-failed', 'drift-detected', 'rolled-back'], webhook: 'ops-teams', role: 'notify', revision: 1, label: '알림: worker-batch CD', kind: 'notify' },
  { id: 'l-12', point: 'cd', scope: { tenant: 'shop', app: 'worker-batch' }, events: ['sync-failed', 'rolled-back'], webhook: 'pagerduty', role: 'notify', revision: 1, label: '알림: worker-batch CD', kind: 'notify', last: { at: ago(86400), status: 202, ms: 500 } },
  { id: 'l-3', point: 'incident', scope: {}, events: ['detected', 'approval'], webhook: 'pagerduty', role: 'notify', revision: 1, label: '모든 앱 (보통 이상)' },
  { id: 'l-4', point: 'ingress', scope: { gateway: 'external' }, events: ['down', 'error-rate'], condition: '5xx 5% 넘게 1분', webhook: 'pagerduty', role: 'notify', revision: 1, label: '외부망 게이트웨이, 경로 1' },
  { id: 'l-5', point: 'incident', scope: {}, events: ['detected'], webhook: 'ops-teams', role: 'notify', revision: 1, label: '클러스터' },
  { id: 'l-7', point: 'ingress', scope: { tenant: 'shop', app: 'php-shop', route: 'r-shop-admin' }, events: ['blocked'], condition: '긴급 차단 걸림·풀림', webhook: 'ops-teams', role: 'notify', revision: 1, label: '외부 접속: shop.example.com /admin', last: { at: ago(12 * 60), status: 200 } },
  { id: 'l-13', point: 'ingress', scope: { tenant: 'shop', app: 'php-shop', route: 'r-shop-root' }, events: ['error-rate'], condition: '5xx 2% 넘게 1분', webhook: 'pagerduty', role: 'notify', revision: 1, label: '외부 접속: shop.example.com /', last: { at: ago(16 * 3600), status: 202 } },
  { id: 'l-14', point: 'ingress', scope: { tenant: 'shop', app: 'php-shop', route: 'r-shop-root' }, events: ['no-backends'], condition: '받을 컨테이너 0개', webhook: 'shop-runbook-bot', role: 'decide', revision: 1, label: '외부 접속: shop.example.com /' },
  { id: 'l-8', point: 'incident', scope: { tenant: 'internal' }, events: ['detected'], webhook: 'internal-audit', role: 'notify', revision: 1, label: 'internal 앱' },
  { id: 'l-9', point: 'ingress', scope: { gateway: 'local' }, events: ['source-rejects'], webhook: 'internal-audit', role: 'notify', revision: 1, label: '로컬망 node-a' },
];
const sent: Record<string, Delivery[]> = {
  pagerduty: [
    { id: 'dlv-1', at: ago(20 * 60), point: 'incident', event: 'incident.detected inc-0412', status: 202, ms: 300 },
    { id: 'dlv-2', at: ago(32 * 60), point: 'ingress', event: 'ingress.blocked /admin', status: 202, ms: 200 },
    { id: 'dlv-3', at: ago(16 * 3600), point: 'ingress', event: 'ingress.error_rate shop /', status: 202, ms: 400 },
    { id: 'dlv-4', at: ago(20 * 3600), point: 'cd', event: 'deploy.failed php-shop', status: 202, ms: 500, retries: 1, firstStatus: 500 },
  ],
  'shop-runbook-bot': [{ id: 'dlv-9', at: ago(120), point: 'incident', event: 'incident.decide inc-0412', status: 200, ms: 400 }],
  'ops-teams': [{ id: 'dlv-7', at: ago(60), point: 'incident', event: 'incident.detected inc-0411', status: 429, ms: 900, retries: 2, error: '429 Too Many Requests' }],
};

export function registerWebhooks(ctx: Ctx) {
  const { on, ok, err } = ctx;
  const sees = (w: Webhook) => ctx.me().systemAdmin || (!!w.tenant && ctx.canWrite(w.tenant));
  const find = (n: string) => hooks.find((w) => w.name === n);
  on('GET', '/webhooks', (_m, _b, q) => {
    const t = q.get('tenant');
    return ok({ items: hooks.filter((w) => sees(w) && (!t || w.tenant === t)) });
  });
  on('POST', '/webhooks', (_m, b) => {
    const name = String(b.name ?? '');
    const tenant = b.tenant ? String(b.tenant) : undefined;
    if (!/^[a-z][a-z0-9-]{0,30}$/.test(name)) return err(422, 'invalid', 'name');
    if (find(name)) return err(409, 'exists', '같은 이름의 웹훅이 있습니다.');
    if (tenant ? !ctx.canWrite(tenant) : !ctx.me().systemAdmin) return err(403, 'denied', tenant ? '이 작업 공간의 관리자 권한이 필요합니다.' : '클러스터 웹훅은 시스템 관리자만 등록합니다.');
    const kind = b.kind === 'internal' ? 'internal' : 'external';
    if (kind === 'external') {
      const url = String(b.url ?? '');
      if (!/^https:\/\//.test(url)) return err(422, 'invalid', 'https 주소만 받습니다.');
      if (/^https:\/\/(localhost|127\.|10\.|192\.168\.|169\.254\.)/.test(url)) return err(422, 'private-address', "사설 주소입니다. 클러스터 안의 앱이면 '클러스터 내부'를 쓰세요.");
    } else if (!tenant || !b.target) return err(422, 'invalid', '클러스터 내부 웹훅은 작업 공간과 대상 서비스가 필요합니다.');
    const sign = (b.sign as Webhook['sign']) ?? 'hmac';
    const w: Webhook = {
      name,
      tenant,
      kind,
      ...(kind === 'external' ? { url: String(b.url) } : { target: b.target as Webhook['target'] }),
      role: b.role === 'decide' ? 'decide' : 'notify',
      format: (b.format as Webhook['format']) ?? 'mydc',
      sign,
      ...(sign === 'token' ? { token: { set: true, last4: String(b.token ?? '').slice(-4) } } : {}),
      secret: { set: sign === 'hmac' },
      state: 'ok',
      enabled: true,
      stats: { today: 0, failed: 0, avgMs: 0 },
      revision: 1,
    };
    hooks.push(w);
    return ok({ ...w, ...(sign === 'hmac' ? { secret: { set: true, value: secret() } } : {}) }, 201);
  });
  on('PUT', '/webhooks/:n', (mm, b) => {
    const w = find(mm[0]);
    if (!w || !sees(w)) return err(404, 'not-found', '없는 웹훅입니다.');
    if (b.revision !== w.revision) return err(409, 'stale', '그사이 다른 사람이 바꿨습니다.');
    if (typeof b.enabled === 'boolean') {
      w.enabled = b.enabled;
      w.state = b.enabled ? 'ok' : 'disabled';
      if (b.enabled) w.error = undefined;
      w.disabledReason = b.enabled ? undefined : 'manual';
    }
    if (b.url) w.url = String(b.url);
    if (b.role) w.role = b.role as Webhook['role'];
    if (b.format) w.format = b.format as Webhook['format'];
    w.revision += 1;
    return ok(w);
  });
  on('DELETE', '/webhooks/:n', (mm, b) => {
    const i = hooks.findIndex((w) => w.name === mm[0]);
    if (i < 0 || !sees(hooks[i])) return err(404, 'not-found', '없는 웹훅입니다.');
    if (b.confirmName !== mm[0]) return err(422, 'confirm-name', '이름이 맞지 않습니다.');
    hooks.splice(i, 1);
    for (let j = links.length - 1; j >= 0; j--) if (links[j].webhook === mm[0]) links.splice(j, 1);
    return ok(null, 204);
  });
  on('POST', '/webhooks/:n/rotate', (mm) => {
    const w = find(mm[0]);
    if (!w || !sees(w)) return err(404, 'not-found', '없는 웹훅입니다.');
    if (w.sign !== 'hmac') return err(422, 'invalid', 'HMAC 서명 웹훅만 비밀을 바꿉니다.');
    w.secret = { set: true, rotatingUntil: later(86400) };
    w.revision += 1;
    return ok({ secret: { set: true, value: secret(), rotatingUntil: w.secret.rotatingUntil } });
  });
  on('POST', '/webhooks/:n/test', (mm) => {
    const w = find(mm[0]);
    if (!w || !sees(w)) return err(404, 'not-found', '없는 웹훅입니다.');
    const internal = w.kind === 'internal';
    // 클러스터 내부는 데몬이 REQ-24 호출(POST /t/{t}/apps/{app}/call)로 보낸다. 호출 실패 code를 그대로 error에 싣는다.
    const fail = internal && w.target?.app === 'audit-sink' ? 'SERVICE_NO_READY_TASK' : undefined;
    const d: Delivery = {
      id: `dlv-${Math.random().toString(16).slice(2, 6)}`,
      at: new Date().toISOString(),
      point: 'test',
      event: 'incident.test',
      status: fail ? 0 : internal ? 200 : 202,
      ms: fail ? 0 : 380,
      ...(fail ? { error: fail } : {}),
      steps: fail
        ? [{ label: '주소 확인', detail: `${w.target?.app}/${w.target?.service} · 상태 검사 통과 컨테이너 없음 (${fail})` }]
        : [
            { label: '주소 확인', detail: internal ? `${w.target?.service}.${w.tenant}.svc → 컨테이너 2개 중 ${w.target?.app}-1` : (w.url ?? '').replace(/^https:\/\//, '').split('/')[0] },
            { label: '보냄', detail: 'incident.test · 412 B' },
            { label: '응답', detail: `${internal ? 200 : 202} · 0.38초` },
            ...(w.role === 'decide' ? [{ label: '판단 응답 형식', detail: 'actions 1개 · allowed_actions 안' }] : []),
          ],
    };
    const { steps, ...delivery } = d;
    (sent[w.name] ??= []).unshift(delivery);
    return ok({ delivery, steps });
  });
  on('GET', '/webhooks/:n/deliveries', (mm) => {
    const w = find(mm[0]);
    if (!w || !sees(w)) return err(404, 'not-found', '없는 웹훅입니다.');
    return ok({ items: sent[w.name] ?? [] });
  });
  on('GET', '/webhook-links', (_m, _b, q) => {
    const point = q.get('point');
    const t = q.get('tenant');
    const app = q.get('app');
    if (t) ctx.reader(t);
    const visible = new Set(hooks.filter(sees).map((w) => w.name));
    // 작업 공간 구성원은 자기 작업 공간 연결을 본다(웹훅 자체를 못 봐도)
    return ok({ items: links.filter((l) => (visible.has(l.webhook) || (!!t && l.scope.tenant === t)) && (!point || l.point === point) && (!t || l.scope.tenant === t) && (!app || l.scope.app === app)) });
  });
  // ── 자동 배포 연결 (cd-webhooks-contract.md) ──
  const cdCheck = (tenant: string, app: string, kind: string, b: Record<string, unknown>, self?: WebhookLink) => {
    const w = find(String(b.webhook ?? self?.webhook ?? ''));
    if (!w || !sees(w) || (w.tenant && w.tenant !== tenant)) return err(422, 'webhook', '이 작업 공간에서 쓸 수 있는 웹훅이 아닙니다.');
    if ((kind === 'notify') !== (w.role === 'notify')) return err(422, 'role', kind === 'notify' ? '알림은 알림 웹훅만 연결됩니다.' : '배포 전·후 확인은 판단 웹훅만 연결됩니다.');
    if (kind !== 'notify') {
      if (links.some((l) => l !== self && l.point === 'cd' && l.scope.tenant === tenant && l.scope.app === app && l.kind === kind)) return err(409, 'exists', `이 앱에는 이미 ${kind === 'pre-sync' ? '배포 전' : '배포 후'} 확인이 있습니다.`);
      const max = kind === 'pre-sync' ? 30 : 600;
      const ws = Number(b.waitSeconds ?? self?.waitSeconds ?? (kind === 'pre-sync' ? 10 : 60));
      if (!(ws >= 5 && ws <= max)) return err(422, 'invalid', `waitSeconds: 5~${max}`);
    }
    if (kind === 'pre-sync' && ctx.cdMode(tenant, app) !== 'manual') return err(422, 'cd-mode', "자동 배포를 '승인 후 배포'로 바꿔야 합니다");
    if (kind === 'notify' && !(Array.isArray(b.events ?? self?.events) && ((b.events ?? self?.events) as unknown[]).length)) return err(422, 'invalid', 'events: 하나 이상');
    return undefined;
  };
  const pick = (kind: string, b: Record<string, unknown>, base: Partial<WebhookLink> = {}): Partial<WebhookLink> => {
    const v = <K extends keyof WebhookLink>(k: K, d: WebhookLink[K]) => ((b[k] as WebhookLink[K]) ?? base[k] ?? d);
    if (kind === 'notify') return { events: v('events', []) as string[] };
    if (kind === 'pre-sync') return { waitSeconds: v('waitSeconds', 10), onTimeout: v('onTimeout', 'hold') };
    return { waitSeconds: v('waitSeconds', 60), onTimeout: v('onTimeout', 'pass'), when: v('when', 'healthy'), onFail: v('onFail', 'pause'), openIncident: v('openIncident', true) };
  };
  const approver = (tenant: string, app: string): WebhookLink['approver'] => {
    const a = ctx.automation();
    return { account: a.username ?? 'mydc-autofix', scope: `ApproveCD ${tenant}/${app}`, state: a.configured ? 'ok' : 'missing' };
  };
  on('POST', '/webhook-links', (_m, b) => {
    if (b.point === 'ingress') {
      const sc = (b.scope ?? {}) as { tenant?: string; app?: string; gateway?: string; route?: string };
      if (sc.gateway ? !ctx.me().systemAdmin : !sc.tenant || !ctx.canWrite(sc.tenant)) return err(403, 'denied', sc.gateway ? '게이트웨이 연결은 시스템 관리자만 합니다.' : '이 작업 공간의 관리자 권한이 필요합니다.');
      const w = find(String(b.webhook));
      if (!w) return err(404, 'not-found', '없는 웹훅입니다.');
      const events = Array.isArray(b.events) ? b.events.map(String) : [];
      if (!events.length) return err(422, 'invalid', '알릴 일을 하나 이상 고르세요.');
      // 데몬 #173 계약: 게이트웨이와 경로가 받는 이벤트가 다르고, 조건은 threshold·minutes로 받아 condition 글은 데몬이 만든다.
      const allowed = sc.gateway ? ['down', 'tls-rejects', 'source-rejects', 'error-rate', 'recovered', 'certificate-expiring', 'blocked', 'limit-90'] : ['error-rate', 'latency', 'no-backends', 'probe-failed', 'cert', 'blocked', 'balance-fallback'];
      if (events.some((e) => !allowed.includes(e))) return err(422, 'invalid', '이 범위에서 고를 수 없는 이벤트가 있습니다.');
      if (b.condition !== undefined) return err(400, 'bad-request', '모르는 필드입니다(condition).');
      const th = b.threshold === undefined ? undefined : Number(b.threshold);
      const mn = b.minutes === undefined ? undefined : Number(b.minutes);
      const metric = events.filter((e) => e === 'error-rate' || e === 'latency');
      if (th !== undefined && metric.length !== 1) return err(422, 'invalid', 'threshold는 error-rate나 latency 하나만 고를 때 줍니다.');
      if (th !== undefined && (metric[0] === 'error-rate' ? !(th > 0 && th <= 100) : !(th > 0 && th <= 60000))) return err(422, 'invalid', 'threshold 범위를 벗어났습니다.');
      if (mn !== undefined && !(Number.isInteger(mn) && mn >= 0 && mn <= 60)) return err(422, 'invalid', 'minutes: 0~60');
      const condition = th === undefined ? undefined : metric[0] === 'error-rate' ? `5xx ${th}% 넘게 ${mn ?? 1}분` : `p95 ${th}ms 넘게 ${mn ?? 1}분`;
      if (links.some((x) => x.point === 'ingress' && x.webhook === w.name && JSON.stringify(x.scope) === JSON.stringify(sc) && JSON.stringify(x.events) === JSON.stringify(events) && (x.condition ?? '') === (condition ?? ''))) return err(409, 'exists', '이미 연결돼 있습니다.');
      const l: WebhookLink = { id: `l-${Math.random().toString(16).slice(2, 8)}`, point: 'ingress', scope: sc, events, webhook: w.name, role: w.role, revision: 1, ...(condition ? { condition } : {}), label: sc.gateway ? `외부 접속: ${sc.gateway === 'local' ? '로컬망' : '외부망'} 게이트웨이` : `외부 접속: ${sc.tenant}/${sc.app ?? ''}` };
      links.push(l);
      return ok(l, 201);
    }
    if (b.point !== 'cd') return err(422, 'invalid', '목업은 point=cd·ingress만 받습니다.');
    const sc = (b.scope ?? {}) as { tenant?: string; app?: string };
    const tenant = String(sc.tenant ?? '');
    const app = String(sc.app ?? '');
    if (!tenant || !app || !ctx.cdMode(tenant, app)) return err(422, 'invalid', '자동 배포 앱이 아닙니다.');
    if (!ctx.canWrite(tenant)) return err(403, 'denied', '이 작업 공간의 관리자 권한이 필요합니다.');
    const kind = String(b.kind ?? '');
    if (!['pre-sync', 'post-sync', 'notify'].includes(kind)) return err(422, 'invalid', 'kind');
    const bad = cdCheck(tenant, app, kind, b);
    if (bad) return bad;
    const w = find(String(b.webhook))!;
    const l: WebhookLink = { id: `l-${Math.random().toString(16).slice(2, 8)}`, point: 'cd', scope: { tenant, app }, events: [], webhook: w.name, role: w.role, revision: 1, kind: kind as WebhookLink['kind'], label: `${kind === 'notify' ? '알림' : kind === 'pre-sync' ? '배포 전 확인' : '배포 후 확인'}: ${app} CD`, ...pick(kind, b), ...(kind === 'pre-sync' ? { approver: approver(tenant, app) } : {}) };
    links.push(l);
    if (kind === 'pre-sync') gateStart.set(`${tenant}/${app}`, Date.now());
    return ok(l, 201);
  });
  on('PUT', '/webhook-links/:id', (mm, b) => {
    const l = links.find((x) => x.id === mm[0]);
    if (!l || l.point !== 'cd') return err(404, 'not-found', '없는 연결입니다.');
    const { tenant = '', app = '' } = l.scope;
    if (!ctx.canWrite(tenant)) return err(403, 'denied', '이 작업 공간의 관리자 권한이 필요합니다.');
    if (b.revision !== l.revision) return err(409, 'stale', '그사이 다른 사람이 바꿨습니다.');
    const bad = cdCheck(tenant, app, l.kind!, b, l);
    if (bad) return bad;
    if (b.webhook) l.webhook = String(b.webhook);
    Object.assign(l, pick(l.kind!, b, l));
    l.revision += 1;
    return ok(l);
  });
  on('DELETE', '/webhook-links/:id', (mm) => {
    const i = links.findIndex((x) => x.id === mm[0]);
    if (i < 0 || (links[i].point !== 'cd' && links[i].point !== 'ingress')) return err(404, 'not-found', '없는 연결입니다.');
    if (links[i].scope.gateway ? !ctx.me().systemAdmin : !ctx.canWrite(links[i].scope.tenant ?? '')) return err(403, 'denied', '이 작업 공간의 관리자 권한이 필요합니다.');
    links.splice(i, 1);
    return ok(null, 204);
  });
}

/** 배포 전 확인을 시작한 때. 목업은 30초 동안 '확인 중', 그 뒤 '보류'로 본다 */
const gateStart = new Map<string, number>([['shop/worker-batch', Date.now()]]);
/** GET …/cd의 webhook (배포 전 확인 상태) */
export function cdGateOf(tenant: string, app: string, candidate?: string): { webhook?: CdGate; checks?: { 'pre-sync'?: CdGate; 'post-sync'?: CdGate } } {
  const pre = links.find((x) => x.point === 'cd' && x.kind === 'pre-sync' && x.scope.tenant === tenant && x.scope.app === app);
  const post = links.find((x) => x.point === 'cd' && x.kind === 'post-sync' && x.scope.tenant === tenant && x.scope.app === app);
  const checks: { 'pre-sync'?: CdGate; 'post-sync'?: CdGate } = {};
  // 직전 배포(4e1a9c2)의 배포 후 확인. 연결의 last와 같은 결과다(캔버스). 실패면 actions가 붙는다
  if (post) checks['post-sync'] = post.last?.answer === 'fail' ? { kind: 'post-sync', link: post.id, webhook: post.webhook, state: 'failed', at: post.last.at, candidate: post.last.commit, reason: '결제 스모크 2/5 실패', status: 200, actions: [{ kind: 'pause', state: 'done' }, { kind: 'rollback-request', state: 'done', incident: 'inc-0415' }] } : { kind: 'post-sync', link: post.id, webhook: post.webhook, state: 'ok', at: post.last?.at ?? new Date().toISOString(), candidate: post.last?.commit, status: 200 };
  if (pre && candidate) {
    const t0 = gateStart.get(`${tenant}/${app}`) ?? Date.now();
    gateStart.set(`${tenant}/${app}`, t0);
    const wait = (pre.waitSeconds ?? 10) * 1000;
    const base = { kind: 'pre-sync' as const, link: pre.id, webhook: pre.webhook, candidate };
    if (pre.approver && pre.approver.state !== 'ok') checks['pre-sync'] = { ...base, state: 'failed', at: new Date(t0).toISOString(), reason: '배포 확인 계정에 승인 권한이 없어 웹훅을 부르지 않았습니다. 사람이 승인해요' };
    else if (Date.now() - t0 < wait) checks['pre-sync'] = { ...base, state: 'checking', at: new Date(t0).toISOString() };
    else checks['pre-sync'] = { ...base, state: 'held', at: new Date(t0 + wait).toISOString(), reason: 'e2e 3개 실패 · 사람 확인 필요', status: 200 };
  }
  const all = [checks['pre-sync'], checks['post-sync']].filter((x): x is CdGate => !!x).sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
  return all.length ? { webhook: all[0], checks } : {};
}
