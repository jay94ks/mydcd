// SPDX-License-Identifier: Apache-2.0

// 컨테이너 상세·이력·로그·표본 목업과 옮기기 전 검사.
// 비밀값은 참조(secret:<object>/<key>)만 있고, 로그에 찍힌 값은 «가림: object/key»로 바꿔 보낸다.
import type { RawResponse } from '../client';
import type * as D from '../dto';
import * as fx from './fixtures';

type Applied = { code: number; errorCode?: string } | void;
interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string) => RawResponse;
  reader: (t: string) => { id: string; username: string };
  canWrite: (t: string) => boolean;
  submit: (body: Record<string, unknown>, action: string, apply: () => Applied) => RawResponse;
}
const now = () => Math.floor(Date.now() / 1000);
const MiB = 1 << 20;

/** 앱 Task 하나. 단독 컨테이너는 service = 이름, instance = '1' */
interface Sel {
  tenant: string;
  app: string;
  service: string;
  instance: string;
  standalone?: string;
}
const key = (s: Sel) => (s.standalone ? `${s.tenant}/~${s.standalone}` : `${s.tenant}/${s.app}/${s.service}/${s.instance}`);

/** sfcd 작업 키(workload/task/...). 목업은 fake처럼 instance까지 붙인다 */
export const taskLogKey = (s: Sel) => (s.standalone ? `workload/standalone/${s.tenant}/${s.standalone}` : `workload/task/${s.tenant}/${s.app}/${s.service}/${s.instance}`);
/** 목업 조작(스모크 시험): 로그 보관소에 닿지 않는 서버, 지운 작업 키 → 지운 시각 */
export const mockLogs = { down: new Set<string>(), cleared: new Map<string, number>() };

/** 재시작 흉내: 키별 시작 시각과 추가 종료 기록 */
const restarted = new Map<string, { at: number; exits: D.DTaskExit[] }>();

function findTask(s: Sel): D.DTask | undefined {
  if (s.standalone) {
    const x = fx.standalone.find((v) => v.tenant === s.tenant && v.name === s.standalone);
    if (!x) return undefined;
    return { tenant: s.tenant, app: '', service: x.name, instance: '1', node: x.node, image: x.image, generation: x.revision, desired: 'running', observed: x.state === 'exited' ? 'exited' : 'running', health: 'none', restarts: x.restarts, observedAt: x.observedAt ?? now() };
  }
  return fx.tasks.find((t) => t.tenant === s.tenant && t.app === s.app && t.service === s.service && t.instance === s.instance);
}

function detail(s: Sel, t: D.DTask): D.DTaskDetail {
  const web = s.service === 'web';
  const db = s.service === 'db';
  const env: D.DTaskEnv[] = web
    ? [
        { key: 'APP_ENV', value: 'prod' },
        { key: 'DB_HOST', value: 'db' },
        { key: 'DB_PASSWORD', secret: 'secret:db-password/password' },
        { key: 'DB_PASSWORD_FILE', value: '/run/secrets/db-password' },
        { key: 'TZ', value: 'Asia/Seoul' },
        { key: 'PHP_MEMORY_LIMIT', value: '192M' },
      ]
    : db
      ? [
          { key: 'MYSQL_DATABASE', value: 'shop' },
          { key: 'MYSQL_ROOT_PASSWORD', secret: 'secret:mysql/root-password' },
        ]
      : [{ key: 'QUEUE', value: 'default' }];
  const mounts: D.DTaskMount[] = web
    ? [
        { kind: 'volume', source: 'uploads', target: '/var/www/uploads', readOnly: false },
        { kind: 'secret', source: 'secret:db-password/password', target: '/run/secrets/db-password', readOnly: true, mode: '0400' },
        { kind: 'tmpfs', target: '/tmp', readOnly: false },
        { kind: 'tmpfs', target: '/run/apache2', readOnly: false },
      ]
    : db
      ? [{ kind: 'volume', source: 'mysql-data', target: '/var/lib/mysql', readOnly: false }]
      : [];
  const n = Number(s.instance) || 1;
  const app = s.standalone ?? s.app;
  return {
    selection: s.standalone ? { standalone: s.standalone } : { app: s.app, service: s.service, instance: s.instance },
    node: t.node,
    name: s.standalone ? `sfc-${s.tenant}-sa-${s.standalone}` : `sfc-${s.tenant}-${s.app}-${s.service}-${s.instance}`,
    nativeID: `4f1c9e${(n * 7919).toString(16).padStart(4, '0')}b2d8e6a0`,
    image: web ? 'registry-shop.sfc:5000/shop/web:v2.14.0' : t.image.replace(/@sha256:.*/, ''),
    digest: `sha256:${(t.image.split('sha256:')[1] ?? 'a1f3b9e07c44d2e8f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8').slice(0, 64)}`,
    command: web ? ['apache2-foreground'] : db ? ['mysqld'] : ['php', 'artisan', 'queue:work'],
    user: web ? '10001:10001' : undefined,
    readOnly: web,
    capAdd: undefined,
    privileged: false,
    cpus: web ? 0.5 : db ? 2 : 0.25,
    memoryBytes: (web ? 256 : db ? 2048 : 128) * MiB,
    logDriver: app === 'worker-batch' ? 'syslog' : 'local',
    logOptions: app === 'worker-batch' ? { 'syslog-address': 'udp://10.0.0.5:514' } : { 'max-size': '10m', 'max-file': '3', compress: 'true' },
    env,
    mounts,
    networks: [{ name: s.tenant === 'shop' ? 'shop-net' : `${s.tenant}-net`, ip: `10.240.10.${9 + n}`, aliases: web ? ['web', `web.${app}.sfc.test`] : [s.service], dns: ['10.240.10.1'] }],
    ports: web ? [{ port: 8080, protocol: 'tcp', ingress: 'shop.example', published: [{ hostIp: '127.0.0.1', hostPort: '18080' }] }] : db ? [{ port: 3306, protocol: 'tcp' }] : undefined,
    stopSignal: 'SIGTERM',
    stopGrace: 30,
    generation: t.generation,
    drift: web && n === 2 ? ['services.web.deploy.resources.limits.memory'] : undefined,
    observedAt: t.observedAt,
  };
}

function history(s: Sel, t: D.DTask): D.DTaskHistory {
  const at = now();
  const extra = restarted.get(key(s))?.exits ?? [];
  const exits: D.DTaskExit[] = [...extra];
  for (let i = 0; i < Math.min(t.restarts, 5); i++) exits.push({ at: at - 3 * 3600 - i * 9000, reason: i === 0 && s.service === 'web' ? 'oom' : t.health === 'unhealthy' ? 'health' : 'exit', exitCode: i === 0 && s.service === 'web' ? 137 : 1, generation: t.generation, nativeID: `9a${i}e44c1b70` });
  const results: D.DTaskCheckResult[] = [];
  for (let i = 0; i < 12; i++) {
    const bad = t.health === 'unhealthy' ? i < 4 : i === 9;
    results.push({ at: at - 40 - i * 30, ok: !bad, durationMs: bad ? 0 : 10 + (i % 5), message: bad ? '연결 거부 (127.0.0.1:8080)' : '/readyz 200' });
  }
  return {
    selection: { app: s.app, service: s.service, instance: s.instance },
    exits,
    checks: t.health === 'none' ? [] : [{ checker: 'http /readyz', consecutiveFailures: t.health === 'unhealthy' ? 4 : 0, results }],
  };
}

const LOGS = [
  ['stdout', '10.240.10.3 - - "GET /readyz HTTP/1.1" 200 2'],
  ['stdout', '10.240.30.2 - - "GET /cart HTTP/1.1" 200 5123'],
  ['stderr', '[php:warn] Undefined array key "coupon" in /var/www/html/src/Cart.php on line 88'],
  ['stdout', '10.240.30.2 - - "POST /checkout HTTP/1.1" 302 0'],
  ['stderr', '[php:error] PDOException: SQLSTATE[HY000] [2002] Connection refused (db:3306)'],
  ['stderr', '#0 /var/www/html/src/Db.php(41): PDO->__construct()'],
  ['stdout', '10.240.10.3 - - "GET /readyz HTTP/1.1" 200 2'],
  ['stdout', '10.240.30.2 - - "GET /product/18 HTTP/1.1" 200 8812'],
  ['stdout', '10.240.30.2 - - "GET /static/app.js HTTP/1.1" 304 0'],
  ['stderr', 'db connect with password «가림: db-password/password» failed, retrying'],
] as const;
const TOTAL = 1200;
/** seq 1..TOTAL, 2초 간격으로 지금 끝난다. 10줄마다 비밀값 가림 줄이 하나 있다. */
function logs(cursor: string | null, limit: number): D.DTaskLogPage {
  const end = cursor ? Math.max(0, Number(cursor) - 1) : TOTAL;
  const start = Math.max(1, end - (limit || 200) + 1);
  const at = now();
  const lines: D.DTaskLogLine[] = [];
  for (let seq = start; seq <= end; seq++) {
    const [stream, text] = LOGS[seq % LOGS.length];
    lines.push({ seq, time: at - (TOTAL - seq) * 2, stream, text });
  }
  return { lines, cursor: start > 1 ? String(start) : undefined, masked: lines.filter((l) => l.text.includes('«가림')).length };
}

function stats(s: Sel, t: D.DTask): D.DTaskStats[] {
  const d = detail(s, t);
  const at = now();
  const out: D.DTaskStats[] = [];
  const base = Math.floor(at / 30) * 30;
  for (let i = 119; i >= 0; i--) {
    const k = 119 - i;
    out.push({
      at: base - i * 30,
      cpuPercent: Math.round((8 + 6 * Math.sin(k / 6) + (k % 7)) * 10) / 10,
      memUsed: Math.round((d.memoryBytes ?? 256 * MiB) * (0.55 + 0.15 * Math.sin(k / 15) + (k > 100 ? 0.02 : 0))),
      memLimit: d.memoryBytes ?? 0,
      netRxBytes: 4.1e9 + k * 36e6,
      netTxBytes: 9.8e9 + k * 102e6,
      blockRead: 220e6,
      blockWrite: 41e6 + k * 3e6,
      pids: 14,
    });
  }
  return out;
}

export function registerTasks(c: Ctx) {
  const sel = (m: string[], q: URLSearchParams, standalone: boolean): Sel => (standalone ? { tenant: m[0], app: '', service: m[1], instance: '1', standalone: m[1] } : { tenant: m[0], app: m[1], service: q.get('service') ?? '', instance: q.get('instance') ?? '' });
  const get = (s: Sel) => {
    const t = findTask(s);
    if (!t) return undefined;
    const r = restarted.get(key(s));
    return r ? { ...t, startedAt: r.at, restarts: t.restarts + r.exits.length } : t;
  };
  for (const standalone of [false, true]) {
    const base = standalone ? '/t/:t/standalone/:n/task' : '/t/:t/apps/:a/task';
    const read = (h: (s: Sel, t: D.DTask, q: URLSearchParams) => RawResponse) => (m: string[], _b: Record<string, unknown>, q: URLSearchParams) => {
      c.reader(m[0]);
      const s = sel(m, q, standalone);
      if (!standalone && (!s.service || !s.instance)) return c.err(400, 'bad-request', 'service와 instance가 필요합니다.');
      const t = get(s);
      return t ? h(s, t, q) : c.err(404, 'not-found', '그런 컨테이너가 없습니다.');
    };
    c.on('GET', base, read((s, t) => c.ok(detail(s, t))));
    c.on(
      'GET',
      `${base}/history`,
      read((s, t, q) => {
        const limit = Number(q.get('limit') ?? 0);
        if (limit < 0 || limit > 200) return c.err(400, 'bad-request', 'limit must be 0..200');
        const h = history(s, t);
        const n = limit || 20;
        return c.ok({ ...h, exits: h.exits.slice(0, n), checks: h.checks.map((x) => ({ ...x, results: x.results.slice(0, n) })) });
      }),
    );
    c.on(
      'GET',
      `${base}/logs`,
      read((_s, _t, q) => {
        const limit = Number(q.get('limit') ?? 0);
        if (limit < 0 || limit > 5000) return c.err(400, 'bad-request', 'limit must be 0..5000');
        return c.ok(logs(q.get('cursor'), limit));
      }),
    );
    c.on('GET', `${base}/stats`, read((s, t) => c.ok({ items: stats(s, t) })));
  }
  c.on('POST', '/t/:t/apps/:a/task/restart', (m, body) => {
    c.reader(m[0]);
    const s: Sel = { tenant: m[0], app: m[1], service: String(body.service ?? ''), instance: String(body.instance ?? '') };
    if (!s.service || !s.instance) return c.err(422, 'invalid', 'service and instance: the task to restart');
    if (!fx.apps.some((a) => a.tenant === m[0] && a.app === m[1])) return c.err(404, 'not-found', 'no such app');
    return c.submit({ ...body, tenant: m[0], target: `app/${m[1]}` }, 'restart-task', () => {
      if (!c.canWrite(m[0])) return { code: 4 };
      const t = findTask(s);
      if (!t) return { code: 3, errorCode: 'not-found' };
      const r = restarted.get(key(s)) ?? { at: now(), exits: [] };
      r.exits.unshift({ at: now(), reason: 'user', exitCode: 0, generation: t.generation, nativeID: '7e21c0a9f3d4' });
      r.at = now();
      restarted.set(key(s), r);
    });
  });

  // container-observe 로그 단발 (sfcd에 있음). 24 KiB를 넘으면 앞부분을 자르고 truncated.
  for (const standalone of [false, true]) {
    c.on('POST', standalone ? '/t/:t/standalone/:n/observe' : '/t/:t/apps/:a/observe', (m, body) => {
      c.reader(m[0]);
      const s: Sel = standalone ? { tenant: m[0], app: '', service: m[1], instance: '1', standalone: m[1] } : { tenant: m[0], app: m[1], service: String(body.service ?? ''), instance: String(body.instance ?? '1') };
      const t = findTask(s);
      if (!t) return c.err(404, 'not-found', '그런 컨테이너가 없습니다.');
      if (body.kind !== 'logs') return c.err(400, 'bad-request', '목업은 logs만 흉내 냅니다.');
      const tail = Number(body.tail ?? 0) || 200;
      const since = Number(body.since ?? 0);
      const until = Number(body.until ?? 0);
      if (until && since && until < since) return c.err(400, 'bad-request', 'until must not be before since');
      const cut = mockLogs.cleared.get(taskLogKey(s)) ?? 0;
      let lines = logs(null, Math.min(TOTAL, since ? TOTAL : tail)).lines.filter((l) => l.time > cut && (!since || l.time >= since) && (!until || l.time <= until));
      let bytes = 0;
      let truncated = false;
      const kept: typeof lines = [];
      for (let i = lines.length - 1; i >= 0; i--) {
        bytes += lines[i].text.length + 30;
        if (bytes > 24 * 1024) {
          truncated = true;
          break;
        }
        kept.unshift(lines[i]);
      }
      lines = kept;
      const d = detail(s, t);
      // sfcd container-observe는 가림을 하지 않는다. 목업도 가린 줄을 원래 값 대신 «값»으로만 둔다.
      return c.ok({ node: t.node, nativeID: d.nativeID, kind: 'logs', logs: lines.map(({ time, stream, text }) => ({ time, stream, text: text.replace(/«가림: [^»]+»/, '«값»') })), truncated, logDriver: d.logDriver, observedAt: now() });
    });
  }

  // 로그 지우기 (sfcd logs-clear · stored-logs, #761). 서버마다 자기 로그 보관소를 지우고 컨테이너는 건드리지 않는다.
  // opId도 op도 없다. 닿지 않는 서버(mockLogs.down)는 로그를 남기고, 같은 요청을 다시 보내면 그때 지운다.
  const logSel = (b: Record<string, unknown>) => ({ app: String(b.app ?? ''), standalone: String(b.standalone ?? ''), service: String(b.service ?? ''), key: String(b.key ?? '') });
  const badSel = (x: ReturnType<typeof logSel>) => !x.app === !x.standalone || (!!x.standalone && (!!x.service || !!x.key));
  const picked = (t: string, x: ReturnType<typeof logSel>) =>
    x.standalone
      ? fx.standalone.filter((v) => v.tenant === t && v.name === x.standalone).map((v) => ({ sel: { tenant: t, app: '', service: v.name, instance: '1', standalone: v.name } as Sel, node: v.node }))
      : fx.tasks.filter((v) => v.tenant === t && v.app === x.app && (!x.service || v.service === x.service)).map((v) => ({ sel: { tenant: t, app: v.app, service: v.service, instance: v.instance } as Sel, node: v.node })).filter((v) => !x.key || taskLogKey(v.sel) === x.key);
  const liveNodes = () => fx.members.filter((n) => n.phase !== 'pending').map((n) => n.id);
  c.on('GET', '/t/:t/logs/stored', (m, _b, q) => {
    c.reader(m[0]);
    const x = logSel(Object.fromEntries(q.entries()));
    if (badSel(x)) return c.err(400, 'bad-request', 'one of app or standalone is required (service and key only with app)');
    const node = q.get('node') ?? '';
    if (node && !liveNodes().includes(node)) return c.err(404, 'not-found', '그런 서버가 없습니다.');
    const rows = picked(m[0], x);
    return c.ok({
      nodes: liveNodes()
        .filter((n) => !node || n === node)
        .map((n) =>
          mockLogs.down.has(n)
            ? { node: n, code: 'unreachable', logs: [] }
            : {
                node: n,
                code: 'ok',
                logs: rows
                  .filter((r) => r.node === n)
                  .flatMap((r) => {
                    const d = detail(r.sel, findTask(r.sel)!);
                    const k = taskLogKey(r.sel);
                    const left = mockLogs.cleared.has(k) ? 0 : 400;
                    const live = { container: d.nativeID ?? '', name: d.name, service: r.sel.standalone ? undefined : r.sel.service, key: r.sel.standalone ? undefined : k, lines: left, size: left * 96 };
                    // 앞 세대 컨테이너(지금은 없음)의 로그도 보관소에 남아 있다
                    const gone = !mockLogs.cleared.has(k) && r.sel.service === 'web' ? [{ ...live, container: `${(d.nativeID ?? '').slice(0, 6)}0ld000000`, lines: 1200, size: 1200 * 90 }] : [];
                    return left || gone.length ? [...(left ? [live] : []), ...gone] : [];
                  }),
              },
        ),
    });
  });
  c.on('POST', '/t/:t/logs/clear', (m, body) => {
    c.reader(m[0]);
    const x = logSel(body);
    if (badSel(x)) return c.err(400, 'bad-request', 'one of app or standalone is required (service and key only with app)');
    const rows = picked(m[0], x);
    const deploy = c.canWrite(m[0]);
    const nodes = liveNodes().map((n) => {
      if (mockLogs.down.has(n)) return { node: n, code: 'unreachable', containers: 0, removed: 0 };
      if (!deploy) return { node: n, code: 'denied', containers: 0, removed: 0 };
      const here = rows.filter((r) => r.node === n);
      let removed = 0;
      for (const r of here) {
        const k = taskLogKey(r.sel);
        if (!mockLogs.cleared.has(k)) removed += r.sel.service === 'web' ? 1600 : 400;
        mockLogs.cleared.set(k, now());
      }
      return { node: n, code: 'ok', containers: here.length, removed };
    });
    return c.ok({ nodes, cleared: nodes.filter((n) => n.code === 'ok').length, total: nodes.length });
  });

  c.on('GET', '/t/:t/apps/:a/relocation-check', (m, _b, q) => {
    c.reader(m[0]);
    // 계획 권한이 없는 보기 전용 사용자는 403
    if (!c.canWrite(m[0])) return c.err(403, 'denied', '이 작업 공간의 배포 권한이 필요합니다.');
    const service = q.get('service') ?? '';
    const node = q.get('node') ?? '';
    if (!service || !node) return c.err(400, 'bad-request', 'service and node are required');
    const ts = fx.tasks.filter((t) => t.tenant === m[0] && t.app === m[1] && t.service === service);
    const from = ts[0]?.node ?? '';
    const member = fx.members.find((x) => x.id === node);
    const ready = !!member && member.phase === 'active' && member.admitsWork;
    const vols = fx.volumes.filter((v) => v.tenant === m[0] && v.writer === `${m[1]}/${service}`);
    const volumes = vols.map((v) => ({ name: v.name, kind: v.kind, node: v.node, step: v.kind === 'fixed' && !v.app ? 'not-movable' : 'move' }));
    // sfcd가 계획해서 판단한 결과 하나. 실패하면 detail에 입력 오류 코드
    const checks = [{ name: 'plan', ok: ready, detail: !member ? 'node-not-allowed' : ready ? undefined : 'node-not-ready' }];
    const ok = checks.every((x) => x.ok) && volumes.every((v) => v.step !== 'not-movable');
    return c.ok({ tenant: m[0], app: m[1], service, from, to: node, ok, checks, volumes, steps: vols.length ? ['volume-move'] : ['app'] });
  });
}
