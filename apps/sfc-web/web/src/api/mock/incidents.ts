// SPDX-License-Identifier: Apache-2.0

// 장애 대응 목업 (UI-B3~B5·B8). 사건은 캔버스의 inc-0412·0411·0409·0407·0406·0402와 오래된 사건으로 채운다.
// 승인은 승인한 사람의 op(보통 op 흐름)로, 거절·만료는 기록만 남긴다.
import type { RawResponse } from '../client';
import { guideSummaries } from './guides';
import type { AppIncidentConf, AppPolicyRow, AppVersionMark, Incident, IncidentRow, Level, MitigationAction, Policy } from '../incidents';

interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string, extra?: Record<string, unknown>) => RawResponse;
  me: () => { username: string; systemAdmin: boolean };
  /** 작업 공간을 볼 수 있는지 (없으면 403으로 멈춘다) */
  reader: (t: string) => void;
  canWrite: (t: string) => boolean;
  submit: (body: Record<string, unknown>, action: string) => RawResponse;
  automation: () => { configured: boolean; username?: string };
}

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const later = (s: number) => new Date(Date.now() + s * 1000).toISOString();
const m = 60;

export const ACTIONS: MitigationAction[] = [
  { id: 'restart-task', scope: 'app', label: '재시작 반복 중인 컨테이너 재시작', floor: 'low', auto: 'allow' },
  { id: 'pause-cd', scope: 'app', label: '자동 배포 일시 정지', floor: 'low', auto: 'allow' },
  { id: 'cd-rollback', scope: 'app', label: '자동 배포 직후 되돌리기 (조건 모두 충족 시)', floor: 'low', auto: 'allow' },
  { id: 'rollback-previous', scope: 'app', label: '직전 버전으로 되돌리기 (그 밖의 경우)', floor: 'medium', auto: 'approval' },
  { id: 'move-service', scope: 'app', label: '다른 서버로 재배치', floor: 'medium', auto: 'approval' },
  { id: 'cordon-node', scope: 'cluster', label: '문제 서버를 새 배치에서 잠시 제외', floor: 'low', auto: 'allow' },
  { id: 'reconnect-tunnel', scope: 'cluster', label: '서버 간 망 다시 연결', floor: 'low', auto: 'allow' },
  { id: 'restart-registry', scope: 'cluster', label: '이미지 저장소 다시 시작', floor: 'low', auto: 'allow' },
  { id: 'prune-images', scope: 'cluster', label: '서버 이미지 캐시 정리', floor: 'medium', auto: 'approval' },
  { id: 'drain-node', scope: 'cluster', label: '서버 비우기', floor: 'high', auto: 'human' },
];
const apps: AppPolicyRow[] = [
  { tenant: 'shop', app: 'php-shop', level: 'auto-low', ratePerHour: 2, quiet: [], cdRollback: { enabled: true, windowMinutes: 30, alwaysApprove: false } },
  { tenant: 'shop', app: 'shop-api', level: 'auto-low', ratePerHour: 2, quiet: ['02:00-03:00'], cdRollback: { enabled: true, windowMinutes: 15, alwaysApprove: false } },
  { tenant: 'shop', app: 'mysql', level: 'off', ratePerHour: 0, quiet: [], cdRollback: { enabled: false, windowMinutes: 30, alwaysApprove: true } },
  { tenant: 'internal', app: 'metrics', level: 'suggest', ratePerHour: 2, quiet: [], cdRollback: { enabled: false, windowMinutes: 30, alwaysApprove: false } },
];
const APPROVER_OPTIONS: NonNullable<Policy['approverOptions']> = [
  { to: 'system-admins', label: '시스템 관리자 2명' },
  { to: 'system-and-tenant-admins', label: '시스템 관리자 2명 + 그 앱의 작업 공간 관리자' },
];
const pol: Omit<Policy, 'actions' | 'apps'> = {
  level: 'suggest',
  stopped: false,
  ratePerHour: 5,
  approvers: { label: '시스템 관리자 2명', deadlineMinutes: 30, banner: true, to: 'system-admins' },
  approverOptions: APPROVER_OPTIONS,
  quiet: [],
  decide: ['ai', 'webhook', 'rules'],
  decideNow: 'ai',
  newAppDefault: 'suggest',
  models: { diagnosis: 'Claude Opus 5.5', impact: 'OpenAI gpt-5.1' },
  revision: 7,
};
type Conf = Omit<AppIncidentConf, 'available' | 'clusterLevel'>;
const appConf = new Map<string, Conf>();
const confOf = (t: string, a: string): Conf => {
  const k = `${t}/${a}`;
  if (!appConf.has(k)) {
    const r = apps.find((x) => x.tenant === t && x.app === a);
    appConf.set(k, {
      level: r?.level ?? pol.newAppDefault,
      ratePerHour: r?.ratePerHour || 2,
      quiet: r?.quiet ?? [],
      approvers: `${t} 작업 공간 관리자 · 30분`,
      decide: ['ai', 'webhook', 'rules'],
      decideNow: 'ai',
      cdRollback: r?.cdRollback ?? { enabled: false, windowMinutes: 30, alwaysApprove: false },
      actions: Object.fromEntries(ACTIONS.filter((x) => x.scope === 'app' && x.auto === 'allow').map((x) => [x.id, true])),
      revision: 1,
    });
  }
  return appConf.get(k)!;
};
const marks = new Map<string, AppVersionMark[]>();
const marksOf = (t: string, a: string) => {
  const k = `${t}/${a}`;
  if (!marks.has(k))
    marks.set(k, [
      { version: 15, summary: '이미지 태그 2.4.1 → 2.4.2', by: '자동 배포', cd: true, at: ago(2 * 3600), migration: false },
      { version: 14, summary: '환경 변수 1개, 복제본 2 → 3', by: '자동 배포', cd: true, at: ago(26 * 3600), migration: false },
      { version: 13, summary: '데이터 저장소 shop-media 추가', by: 'alice', cd: false, at: ago(4 * 86400), migration: true, auto: '데이터 저장소 변경' },
    ]);
  return marks.get(k)!;
};

const A = (scope: IncidentRow['scope'], o: Partial<IncidentRow> & Pick<IncidentRow, 'id' | 'signal' | 'mitigation' | 'impact' | 'decision' | 'state' | 'at'>): IncidentRow => ({ scope, ...o });
const rows: Incident[] = [
  {
    ...A('app', { id: 'inc-0412', tenant: 'shop', app: 'php-shop', signal: 'worker 재시작 반복 (10분에 4회)', mitigation: '컨테이너 재시작', impact: 'low', decision: { kind: 'auto', note: '회복됨' }, state: 'recovered', at: ago(20 * m) }),
    title: 'php-shop worker 재시작 반복',
    timeline: [
      { at: ago(20 * m), kind: 'detect', text: '규칙 "10분에 재시작 3회 이상" · worker 재시작 4회' },
      { at: ago(20 * m), kind: 'diagnose', text: '메모리 한도 초과로 종료(OOM) 반복. 후보: ① 컨테이너 재시작 ② 자동 배포 일시 정지', model: 'Claude Opus 5.5', inputs: ['로그 200줄(가림 적용)', '이벤트 12', '설정', 'mcp.grafana.query_range'], candidates: [{ action: '컨테이너 재시작', note: 'OOM 종료 반복, 재시작이 임시로 회복시킴' }, { action: '자동 배포 일시정지', note: '최근 배포와 무관해 보류' }] },
      { at: ago(19 * m), kind: 'assess', text: '① 낮음 · 확신 0.86 · ② 낮음', model: 'OpenAI gpt-5.1', inputs: ['코드가 모은 사실 5개 (로그 원문·진단 추론 없음)'] },
      { at: ago(19 * m), kind: 'auto', text: '컨테이너 재시작', op: 'rt-77a0', signer: 'sfc-autofix' },
      { at: ago(14 * m), kind: 'recover', text: '5분 동안 재시작 없음' },
      { at: ago(14 * m), kind: 'propose', text: 'worker 메모리 256m → 512m (승인 필요)', conversation: true },
    ],
    assessment: {
      provider: 'OpenAI',
      model: 'gpt-5.1',
      sameProvider: false,
      facts: [
        { label: '조치', value: '컨테이너 재시작' },
        { label: '대상 상태', value: '이미 종료됨 (재시작 반복)' },
        { label: '데이터 저장소', value: '없음' },
        { label: '같은 서버 다른 앱', value: '2개 (영향 없음)' },
        { label: '최근 1시간 자동 조치', value: '0회 / 한도 2회' },
      ],
      level: 'low',
      reversible: true,
      blast: 1,
      dataRisk: 'none',
      confidence: 0.86,
      reasons: ['이미 종료된 컨테이너라 재시작이 더 나빠지지 않음', '데이터 저장소 없음'],
      floor: { level: 'low', reason: '이미 멈춘 컨테이너' },
      final: 'low',
      policy: 'php-shop: 낮은 영향 자동 · 클러스터: 허용',
    },
    guides: { cluster: { version: 2 }, tenant: { version: 1 }, app: { version: 3, current: 4 } },
    mcpCalls: { grafana: 2, sentry: 1 },
  },
  {
    ...A('cluster', { id: 'inc-0411', node: 'node-c', signal: 'node-c 응답 없음 (3분)', mitigation: 'node-c 새 배치에서 제외', impact: 'medium', decision: { kind: 'pending', expiresAt: later(24 * m) }, state: 'open', at: ago(24 * m) }),
    title: 'node-c 응답 없음',
    timeline: [
      { at: ago(24 * m), kind: 'detect', text: '규칙 "서버 응답 없음 3분" · node-c' },
      { at: ago(24 * m), kind: 'diagnose', text: '서버 관측이 3분째 없음. 후보: ① 새 배치에서 제외', model: 'Claude Opus 5.5', inputs: ['서버 상태', '최근 이벤트 8'], candidates: [{ action: 'node-c 새 배치에서 제외', note: '기존 컨테이너는 그대로' }] },
      { at: ago(23 * m), kind: 'assess', text: '① 보통 · 확신 0.74', model: 'OpenAI gpt-5.1' },
      { at: ago(23 * m), kind: 'notify', text: '클러스터 정책이 \'제안만\'이라 승인 요청을 보냄 · 시스템 관리자 2명' },
    ],
    assessment: {
      provider: 'OpenAI',
      model: 'gpt-5.1',
      facts: [
        { label: '조치', value: '서버를 새 배치에서 제외' },
        { label: '대상 상태', value: '3분째 응답 없음' },
        { label: '서버 수', value: '3대 중 1대' },
        { label: '최근 1시간 자동 조치', value: '1회 / 한도 5회' },
      ],
      level: 'medium',
      reversible: true,
      blast: 3,
      dataRisk: 'none',
      confidence: 0.74,
      floor: { level: 'low', reason: '기존 컨테이너는 그대로' },
      final: 'medium',
      policy: '클러스터: 제안만',
    },
    approval: {
      title: 'node-c를 새 배치 대상에서 잠시 제외',
      fields: [
        { label: '신호', value: 'node-c 3분째 응답 없음' },
        { label: '평가', value: '보통 · 서버 3대 중 1대, 기존 컨테이너는 그대로' },
        { label: '왜 자동이 아님', value: "클러스터 정책이 '제안만'" },
        { label: '되돌리기', value: '제외 해제 (승인 필요)' },
      ],
      expiresAt: later(24 * m),
      basisHash: 'h-0411-1',
    },
    guides: { cluster: { version: 2 } },
  },
  {
    // MCP 조치 후보(propose-approve) 승인 대기: 승인하면 op 대신 {mcp}가 온다
    ...A('app', { id: 'inc-0410', tenant: 'shop', app: 'shop-api', signal: '5xx 비율 8% (5분)', mitigation: 'mcp.pagerduty.create_incident', impact: 'low', decision: { kind: 'pending', expiresAt: later(28 * m) }, state: 'open', at: ago(6 * m) }),
    title: 'shop-api 5xx 증가 · 당직자 호출',
    timeline: [
      { at: ago(6 * m), kind: 'detect', text: '외부 접속 이벤트 error-rate · shop.example.com/api' },
      { at: ago(5 * m), kind: 'diagnose', text: '최근 배포와 무관. 후보: ① 당직자 호출(PagerDuty)', model: 'Claude Opus 5.5', inputs: ['외부 접속 지표', 'mcp.grafana.query_range'], candidates: [{ action: 'mcp.pagerduty.create_incident', note: 'service=shop-api · title=5xx 8%' }] },
      { at: ago(5 * m), kind: 'notify', text: "MCP 도구는 '항상 승인'이라 승인 요청을 보냄 · shop 작업 공간 관리자" },
    ],
    approval: {
      title: 'PagerDuty로 당직자 호출',
      action: 'mcp.pagerduty.create_incident',
      fields: [
        { label: '신호', value: '5xx 비율 8% (5분)' },
        { label: '도구', value: 'mcp.pagerduty.create_incident' },
        { label: '인자', value: 'service=shop-api · title=shop-api 5xx 8%' },
        { label: '왜 자동이 아님', value: "도구 설정이 '항상 승인'" },
      ],
      expiresAt: later(28 * m),
      basisHash: 'h-0410-1',
    },
    mcpCalls: { grafana: 1 },
  },
  {
    ...A('app', { id: 'inc-0409', tenant: 'shop', app: 'mysql', signal: '상태 검사 5회 연속 실패', mitigation: '다른 서버로 재배치', impact: 'high', decision: { kind: 'rejected', note: '고정 저장소' }, state: 'open', at: ago(100 * m) }),
    title: 'mysql 상태 검사 실패',
    timeline: [
      { at: ago(100 * m), kind: 'detect', text: '규칙 "상태 검사 5회 연속 실패" · mysql-db' },
      { at: ago(99 * m), kind: 'diagnose', text: '디스크 지연으로 응답이 느림. 후보: ① 다른 서버로 재배치', model: 'Claude Opus 5.5' },
      { at: ago(99 * m), kind: 'webhook', text: '판단 웹훅이 후보 ①을 골랐습니다', webhook: 'shop-runbook-bot', status: 200, accepted: true, reason: '같은 서버에서 디스크 지연 3번째' },
      { at: ago(99 * m), kind: 'assess', text: '① 높음 · 고정 데이터 저장소', model: 'OpenAI gpt-5.1' },
      { at: ago(99 * m), kind: 'reject', text: '영향 높음은 반려 · 고정 저장소. 사람에게 알림' },
    ],
    guides: { cluster: { version: 2 }, tenant: { version: 1 } },
  },
  {
    ...A('app', { id: 'inc-0407', tenant: 'shop', app: 'shop-api', signal: '자동 배포 v16 뒤 시작 직후 종료 반복 (배포 8분 후)', mitigation: '자동 배포 직후 되돌리기 v16→v15', impact: 'low', decision: { kind: 'auto', note: '자동 배포 멈춤 · 회복됨' }, state: 'recovered', at: ago(150 * m) }),
    title: 'shop-api v16 시작 실패',
    timeline: [
      { at: ago(150 * m), kind: 'detect', text: '자동 배포 v16 완료 8분 뒤 종료 반복' },
      { at: ago(149 * m), kind: 'auto', text: '자동 배포 직후 되돌리기 v16→v15 · 자동 배포 멈춤', op: 'rb-11c2', signer: 'sfc-autofix' },
      { at: ago(144 * m), kind: 'recover', text: '5분 동안 종료 없음' },
    ],
  },
  {
    ...A('cluster', { id: 'inc-0406', signal: '서버 간 망 node-a↔node-b 끊김', mitigation: '터널 다시 연결', impact: 'low', decision: { kind: 'auto', note: '회복됨' }, state: 'recovered', at: ago(220 * m) }),
    title: 'node-a↔node-b 망 끊김',
    timeline: [
      { at: ago(220 * m), kind: 'detect', text: '터널 node-a↔node-b down 2분' },
      { at: ago(219 * m), kind: 'auto', text: '터널 다시 연결', op: 'tn-0a31', signer: 'sfc-autofix' },
      { at: ago(218 * m), kind: 'recover', text: '연결됨' },
    ],
  },
  {
    ...A('app', { id: 'inc-0402', tenant: 'shop', app: 'billing', signal: '사람이 올린 v9 뒤 실패 증가', mitigation: '직전 버전으로 되돌리기', impact: 'medium', decision: { kind: 'approved', by: 'bob', note: '임시 조치 중' }, state: 'mitigating', at: ago(26 * 3600) }),
    title: 'billing v9 실패 증가',
    timeline: [
      { at: ago(26 * 3600), kind: 'detect', text: '5xx 비율 4% (평소 0.2%)' },
      { at: ago(26 * 3600), kind: 'approve', text: 'bob 승인 · 직전 버전으로 되돌리기', op: 'rb-0f77', signer: 'bob' },
    ],
  },
];
for (let i = 0; i < 122; i++) {
  const n = 401 - i;
  rows.push({
    ...A(i % 3 ? 'app' : 'cluster', { id: `inc-0${n}`, ...(i % 3 ? { tenant: i % 5 ? 'shop' : 'internal', app: ['php-shop', 'shop-api', 'metrics', 'billing'][i % 4] } : {}), signal: i % 3 ? '재시작 반복' : '서버 간 망 끊김', mitigation: i % 3 ? '컨테이너 재시작' : '터널 다시 연결', impact: 'low', decision: { kind: 'auto', note: '회복됨' }, state: 'closed', at: ago(86400 * (2 + i)) }),
    title: '지난 사건',
    timeline: [{ at: ago(86400 * (2 + i)), kind: 'detect', text: '지난 사건' }],
  });
}
const row = (x: Incident): IncidentRow => ({ id: x.id, scope: x.scope, tenant: x.tenant, app: x.app, node: x.node, signal: x.signal, mitigation: x.mitigation, impact: x.impact, decision: x.decision, state: x.state, at: x.at });
const expire = (x: Incident) => {
  if (x.decision.kind === 'pending' && x.decision.expiresAt && Date.parse(x.decision.expiresAt) < Date.now()) {
    x.decision = { kind: 'expired', note: '응답 없음' };
    x.timeline.push({ at: new Date().toISOString(), kind: 'expire', text: '승인 요청이 응답 없이 만료됨. 아무것도 실행하지 않음' });
  }
};
const LEVELS: Level[] = ['off', 'suggest', 'auto-low'];
const mcpResults = new Map<string, { opId: string; mcp: { ok: boolean; server: string; tool: string; error?: string } }>();

export function registerIncidents(ctx: Ctx) {
  const { on, ok, err } = ctx;
  const automation = ctx.automation;
  const polView = () => ({ ...pol, actions: ACTIONS, apps, automation: automation() });
  // 볼 수 있는 사건: 클러스터 사건은 시스템 관리자, 앱 사건은 그 작업 공간을 볼 수 있는 사람
  const visible = (x: Incident) => {
    const u = ctx.me();
    if (x.scope === 'cluster') return u.systemAdmin;
    try {
      ctx.reader(x.tenant!);
      return true;
    } catch {
      return false;
    }
  };
  const find = (id: string) => {
    const x = rows.find((r) => r.id === id);
    if (!x || !visible(x)) return undefined;
    expire(x);
    return x;
  };
  on('GET', '/incidents', (_m, _b, qs) => {
    rows.forEach(expire);
    const scope = qs.get('scope');
    const dec = qs.get('decision');
    const text = (qs.get('q') ?? '').toLowerCase();
    const t = qs.get('tenant');
    const a = qs.get('app');
    const all = rows.filter(visible).sort((x, y) => y.at.localeCompare(x.at));
    const items = all.filter((x) => (!scope || x.scope === scope) && (!dec || x.decision.kind === dec) && (!t || x.tenant === t) && (!a || x.app === a) && (!text || `${x.id} ${x.app ?? ''} ${x.node ?? ''} ${x.signal} ${x.mitigation}`.toLowerCase().includes(text)));
    const limit = Math.min(100, Number(qs.get('limit') ?? 20) || 20);
    const from = Number(qs.get('cursor') ?? 0) || 0;
    return ok({ items: items.slice(from, from + limit).map(row), cursor: from + limit < items.length ? String(from + limit) : undefined, total: items.length, pending: all.filter((x) => x.decision.kind === 'pending').length, level: ctx.me().systemAdmin ? (pol.stopped ? 'off' : pol.level) : null, stopped: pol.stopped, watcher: automation().configured ? { state: 'running', at: new Date().toISOString() } : { state: 'no-automation', at: new Date().toISOString() } });
  });
  on('GET', '/incidents/policy', () => {
    if (!ctx.me().systemAdmin) return err(403, 'denied', '시스템 관리자 권한이 필요합니다.');
    return ok(polView());
  });
  on('PUT', '/incidents/policy', (_m, b) => {
    if (!ctx.me().systemAdmin) return err(403, 'denied', '시스템 관리자 권한이 필요합니다.');
    if (b.revision !== pol.revision) return err(409, 'stale', '그사이 다른 사람이 정책을 바꿨습니다.');
    if (!LEVELS.includes(b.level as Level)) return err(422, 'invalid', 'level');
    const rate = Number(b.ratePerHour);
    if (!Number.isInteger(rate) || rate < 1 || rate > 30) return err(422, 'invalid', 'ratePerHour must be 1..30');
    let approvers = pol.approvers;
    if (b.approvers) {
      const a = b.approvers as Policy['approvers'];
      const o = APPROVER_OPTIONS.find((x) => x.to === (a.to ?? 'system-and-tenant-admins'));
      if (!o) return err(422, 'invalid', 'approvers.to');
      const dm = Number(a.deadlineMinutes);
      if (!Number.isInteger(dm) || dm < 5 || dm > 240) return err(422, 'invalid', 'approvers.deadlineMinutes: 5~240');
      approvers = { to: o.to, label: o.label, deadlineMinutes: dm, banner: !!a.banner };
    }
    Object.assign(pol, { level: b.level, ratePerHour: rate, approvers, quiet: b.quiet ?? pol.quiet, newAppDefault: b.newAppDefault ?? pol.newAppDefault, revision: pol.revision + 1 });
    const acts = (b.actions ?? {}) as Record<string, string>;
    for (const [id, v] of Object.entries(acts)) {
      const x = ACTIONS.find((a) => a.id === id);
      if (!x || !['allow', 'approval', 'human'].includes(v)) return err(422, 'invalid', `actions.${id}`);
      if (v === 'allow' && x.floor !== 'low') return err(422, 'floor', '하한이 보통 이상인 조치는 자동으로 둘 수 없습니다.');
    }
    if (b.level !== 'off' && !automation().configured) return err(422, 'automation-missing', '자동 대응 계정을 먼저 만들어야 합니다.');
    for (const [id, v] of Object.entries(acts)) ACTIONS.find((a) => a.id === id)!.auto = v as MitigationAction['auto'];
    return ok(polView());
  });
  on('POST', '/incidents/stop', () => {
    if (!ctx.me().systemAdmin) return err(403, 'denied', '시스템 관리자 권한이 필요합니다.');
    if (pol.stopped) return err(409, 'unchanged', '이미 멈춰 있습니다.');
    pol.stopped = true;
    pol.revision++;
    return ok(polView());
  });
  on('POST', '/incidents/resume', () => {
    if (!ctx.me().systemAdmin) return err(403, 'denied', '시스템 관리자 권한이 필요합니다.');
    if (!pol.stopped) return err(409, 'unchanged', '멈춰 있지 않습니다.');
    pol.stopped = false;
    pol.revision++;
    return ok(polView());
  });
  on('GET', '/incidents/:id', (mm) => {
    const x = find(mm[0]);
    return x ? ok(x) : err(404, 'not-found', 'no such incident');
  });
  on('POST', '/incidents/:id/approve', (mm, b) => {
    const x = find(mm[0]);
    if (!x) return err(404, 'not-found', 'no such incident');
    if (x.decision.kind === 'expired') return err(410, 'expired', '승인 기한이 지났습니다.');
    if (x.decision.kind !== 'pending' && !(x.decision.kind === 'approved' && x.timeline.some((t) => t.op === b.opId))) return err(409, 'not-pending', '승인 대기 중인 사건이 아닙니다.');
    if (x.decision.kind === 'pending' && b.basisHash !== x.approval?.basisHash) return err(409, 'incident-changed', '그사이 사건의 임시 조치나 대상이 바뀌었습니다.');
    if (x.scope === 'cluster' && !ctx.me().systemAdmin) return err(403, 'denied', '시스템 관리자 권한이 필요합니다.');
    if (x.tenant && !ctx.canWrite(x.tenant)) return err(403, 'denied', '이 작업 공간의 관리자 권한이 필요합니다.');
    // MCP 후보는 op 대신 {mcp}. 같은 opId 재시도는 기록한 결과를 준다.
    const mcpAct = x.approval?.action ?? (x.mitigation.startsWith('mcp.') ? x.mitigation : undefined);
    const done = mcpResults.get(x.id);
    if (done) return done.opId === b.opId ? ok({ mcp: done.mcp }) : err(409, 'proposal-approved', '이미 다른 승인으로 실행했습니다.');
    if (mcpAct?.startsWith('mcp.')) {
      const [, server, tool] = mcpAct.split('.');
      const by = ctx.me().username;
      const res = { ok: true, server, tool };
      mcpResults.set(x.id, { opId: String(b.opId), mcp: res });
      x.decision = { kind: 'approved', by, note: 'MCP 도구 호출' };
      x.approval = undefined;
      x.mcpCalls = { ...(x.mcpCalls ?? {}), [server]: (x.mcpCalls?.[server] ?? 0) + 1 };
      x.timeline.push({ at: new Date().toISOString(), kind: 'approve', text: `${by} 승인 · ${mcpAct} 호출 성공`, signer: by });
      return ok({ mcp: res });
    }
    const res = ctx.submit({ opId: b.opId, tenant: x.tenant, target: x.node ?? x.app }, x.scope === 'cluster' ? 'cordon-node' : 'restart-task');
    if (res.status < 300 && x.decision.kind === 'pending') {
      const by = ctx.me().username;
      x.decision = { kind: 'approved', by, note: '임시 조치 중' };
      x.state = 'mitigating';
      x.approval = undefined;
      x.timeline.push({ at: new Date().toISOString(), kind: 'approve', text: `${by} 승인 · ${x.mitigation}`, op: String(b.opId), signer: by });
    }
    return res;
  });
  on('POST', '/incidents/:id/reject', (mm, b) => {
    const x = find(mm[0]);
    if (!x) return err(404, 'not-found', 'no such incident');
    if (x.decision.kind !== 'pending') return err(409, 'not-pending', '승인 대기 중인 사건이 아닙니다.');
    const by = ctx.me().username;
    const NAMES: Record<string, string> = { 'handled-by-person': '사람이 직접 처리함', 'wrong-action': '조치가 맞지 않음', 'not-now': '지금은 실행하면 안 됨', other: '기타' };
    if (typeof b.reason !== 'string' || !(b.reason in NAMES)) return err(422, 'invalid', 'reason');
    if (b.reason === 'other' && !(typeof b.note === 'string' && b.note.trim())) return err(422, 'invalid', 'note is required for other');
    const reason = NAMES[b.reason];
    x.decision = { kind: 'rejected', by, note: reason };
    x.approval = undefined;
    x.timeline.push({ at: new Date().toISOString(), kind: 'reject', text: `${by} 반려 · ${reason}${typeof b.note === 'string' && b.note ? ` · ${b.note}` : ''}` });
    return ok(null, 204);
  });
  on('DELETE', '/incidents/:id', (mm, b) => {
    const x = find(mm[0]);
    if (!x) return err(404, 'not-found', 'no such incident');
    if (b.confirmName !== x.id) return err(422, 'confirm-name', '사건 ID가 맞지 않습니다.');
    if (x.tenant ? !ctx.canWrite(x.tenant) : !ctx.me().systemAdmin) return err(403, 'denied', '지울 권한이 없습니다.');
    rows.splice(rows.indexOf(x), 1);
    return ok(null, 204);
  });

  const appView = (c: Conf, t: string, a: string): AppIncidentConf => ({ ...c, guides: guideSummaries(t, a), available: ACTIONS.filter((x) => x.scope === 'app'), clusterLevel: pol.stopped ? 'off' : pol.level });
  on('GET', '/t/:t/apps/:a/incident', (mm) => {
    ctx.reader(mm[0]);
    return ok(appView(confOf(mm[0], mm[1]), mm[0], mm[1]));
  });
  on('PUT', '/t/:t/apps/:a/incident', (mm, b) => {
    ctx.reader(mm[0]);
    if (!ctx.canWrite(mm[0])) return err(403, 'denied', '이 작업 공간의 관리자 권한이 필요합니다.');
    const c = confOf(mm[0], mm[1]);
    if (b.revision !== c.revision) return err(409, 'revision-changed', '그사이 다른 사람이 바꿨습니다.');
    if (!LEVELS.includes(b.level as Level)) return err(422, 'invalid', 'level');
    const rate = Number(b.ratePerHour);
    if (!Number.isInteger(rate) || rate < 1 || rate > 10) return err(422, 'invalid', 'ratePerHour must be 1..10');
    const w = Number((b.cdRollback as AppIncidentConf['cdRollback'] | undefined)?.windowMinutes ?? 30);
    if (w < 5 || w > 120) return err(422, 'invalid', 'cdRollback.windowMinutes must be 5..120');
    const next: Conf = { ...c, level: b.level as Level, ratePerHour: Number(b.ratePerHour) || c.ratePerHour, quiet: (b.quiet as string[]) ?? c.quiet, cdRollback: (b.cdRollback as AppIncidentConf['cdRollback']) ?? c.cdRollback, actions: (b.actions as Record<string, boolean>) ?? c.actions, revision: c.revision + 1 };
    appConf.set(`${mm[0]}/${mm[1]}`, next);
    const r = apps.find((x) => x.tenant === mm[0] && x.app === mm[1]);
    const rowNext = { tenant: mm[0], app: mm[1], level: next.level, ratePerHour: next.ratePerHour, quiet: next.quiet, cdRollback: next.cdRollback };
    if (r) Object.assign(r, rowNext);
    else apps.push(rowNext);
    return ok(appView(next, mm[0], mm[1]));
  });
  on('GET', '/t/:t/apps/:a/incident/versions', (mm) => {
    ctx.reader(mm[0]);
    return ok({ items: marksOf(mm[0], mm[1]) });
  });
  on('PUT', '/t/:t/apps/:a/incident/versions/:v', (mm, b) => {
    ctx.reader(mm[0]);
    if (!ctx.canWrite(mm[0])) return err(403, 'denied', '이 작업 공간의 관리자 권한이 필요합니다.');
    const v = marksOf(mm[0], mm[1]).find((x) => x.version === Number(mm[2]));
    if (!v) return err(404, 'not-found', 'no such version');
    if (v.auto && !b.migration) return err(409, 'auto-marked', `${v.auto}이라 자동으로 표시됐습니다.`);
    v.migration = !!b.migration;
    return ok(v);
  });
}
