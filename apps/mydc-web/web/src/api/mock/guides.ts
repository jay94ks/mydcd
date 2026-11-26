// SPDX-License-Identifier: Apache-2.0

// 행동 지침 목업 (UI-BA). 캔버스의 php-shop v4·shop v1·클러스터 v2로 채운다.
import type { RawResponse } from '../client';
import type { Guide, GuideFields, GuideSummary, GuideTestRun, GuideVersion } from '../guides';
import { ACTIONS } from './incidents';
import { mcpChoices } from './mcp';

interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string, extra?: Record<string, unknown>) => RawResponse;
  me: () => { username: string; systemAdmin: boolean };
  reader: (t: string) => void;
  canWrite: (t: string) => boolean;
}

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const d = 86400;
const empty = (): GuideFields => ({ prefer: [], avoid: { actions: [], services: [] }, mcpServers: [], notify: [], critical: [] });

interface Ver {
  version: number;
  text: string;
  fields: GuideFields;
  updatedBy: string;
  updatedAt: string;
  summary: string;
  incidents: number;
}
interface Rec {
  revision: number;
  deliver: { diagnose: boolean; coordinator: boolean };
  versions: Ver[];
}

const PHP_V4 = `# php-shop 장애 대응 지침 (v4)
- 결제(/checkout) 오류가 늘면 먼저 Grafana의 payment-gw 지표를 보세요. 외부 결제사 장애면 우리 쪽 조치는 하지 말고 알림만 보냅니다.
- worker가 재시작을 반복하면 큐 길이(redis queue:jobs)부터 확인합니다. 큐가 10만을 넘으면 재시작보다 자동 배포 일시 정지를 먼저 제안하세요.
- 평일 09–18시에는 되돌리기 제안 전에 #shop-oncall에 먼저 알립니다.
- mysql 서비스는 어떤 임시 조치도 제안하지 마세요(사람만).
- 근본 원인 추정에는 Sentry 프로젝트 php-shop의 최근 릴리스를 함께 보세요.`;
const PHP_FIELDS: GuideFields = {
  prefer: ['pause-cd', 'restart-task'],
  avoid: { actions: ['move-service'], services: ['mysql'] },
  mcpServers: ['grafana', 'sentry', 'slack'],
  notify: ['#shop-oncall (slack)', '승인 요청은 웹 알림과 함께'],
  critical: ['결제 경로 있음'],
};
const store = new Map<string, Rec>([
  [
    'cluster',
    {
      revision: 2,
      deliver: { diagnose: true, coordinator: true },
      versions: [
        { version: 1, text: '- 합의 위험이면 서버 격리를 제안하지 말 것', fields: empty(), updatedBy: 'alice', updatedAt: ago(30 * d), summary: '처음 작성', incidents: 4 },
        {
          version: 2,
          text: '- 합의 위험이면 서버 격리를 제안하지 말 것\n- 서버 비우기는 언제나 사람에게 넘길 것\n- 망 끊김은 2분 기다린 뒤 판단할 것\n- 이미지 저장소 정지는 디스크부터 볼 것',
          fields: { ...empty(), avoid: { actions: ['move-service'], services: [] } },
          updatedBy: 'alice',
          updatedAt: ago(12 * d),
          summary: '재배치 제안 막음 · 3줄 추가',
          incidents: 6,
        },
      ],
    },
  ],
  ['tenant/shop', { revision: 1, deliver: { diagnose: true, coordinator: true }, versions: [{ version: 1, text: '- 알림은 #shop-oncall\n- 결제 관련 앱은 낮은 영향이라도 먼저 알릴 것', fields: { ...empty(), notify: ['#shop-oncall (slack)'] }, updatedBy: 'bob', updatedAt: ago(20 * d), summary: '처음 작성', incidents: 5 }] }],
  [
    'app/shop/php-shop',
    {
      revision: 4,
      deliver: { diagnose: true, coordinator: true },
      versions: [
        { version: 1, text: '# php-shop 장애 대응 지침\n- worker 재시작 반복이면 큐 길이부터 확인', fields: empty(), updatedBy: 'alice', updatedAt: ago(20 * d), summary: '처음 작성', incidents: 2 },
        { version: 2, text: PHP_V4.replace('\n- 근본 원인 추정에는 Sentry 프로젝트 php-shop의 최근 릴리스를 함께 보세요.', '').replace('\n- mysql 서비스는 어떤 임시 조치도 제안하지 마세요(사람만).', '').replace('10만', '5만'), fields: { ...PHP_FIELDS, avoid: { actions: ['move-service'], services: [] } }, updatedBy: 'alice', updatedAt: new Date(new Date().getFullYear(), 10, 9, 21, 30).toISOString(), summary: '평일 알림 순서', incidents: 1 },
        { version: 3, text: PHP_V4.replace('\n- 근본 원인 추정에는 Sentry 프로젝트 php-shop의 최근 릴리스를 함께 보세요.', '').replace('\n- mysql 서비스는 어떤 임시 조치도 제안하지 마세요(사람만).', ''), fields: { ...PHP_FIELDS, avoid: { actions: ['move-service'], services: [] } }, updatedBy: 'bob', updatedAt: new Date(new Date().getFullYear(), 10, 18, 10, 2).toISOString(), summary: '큐 길이 기준 10만', incidents: 3 },
        { version: 4, text: PHP_V4, fields: PHP_FIELDS, updatedBy: 'alice', updatedAt: ago(2 * 3600), summary: 'mysql 제외 추가 · Sentry 줄 추가', incidents: 0 },
      ],
    },
  ],
]);

const SERVICES: Record<string, string[]> = { 'shop/php-shop': ['web', 'worker', 'mysql'], 'shop/shop-api': ['api', 'cache'] };

const last = (r?: Rec) => r?.versions[r.versions.length - 1];
const lineCount = (t: string) => t.split('\n').filter((l) => l.trim() && !l.startsWith('#')).length;
function quote(t: string): string {
  const ls = t.split('\n').filter((l) => l.trim() && !l.startsWith('#'));
  if (!ls.length) return '비어 있음';
  const first = ls[0].replace(/^-\s*/, '');
  return `"${first.length > 28 ? `${first.slice(0, 28)}…` : first}"${ls.length > 1 ? ` 외 ${ls.length - 1}줄` : ''}`;
}
/** 저장할 때 찾는 경고: 목록 밖 조치·등급 완화·지우기·비밀값 요구로 보이는 줄 */
function warn(text: string): Guide['warnings'] {
  const out: Guide['warnings'] = [];
  text.split('\n').forEach((l, i) => {
    const m = /(재부팅|reboot)/i.test(l) ? '목록 밖' : /(지우|삭제|rm -rf|drop )/i.test(l) ? '지우기' : /(비밀번호|비밀값|password|토큰)/i.test(l) ? '비밀값' : /(등급|영향).*(낮춰|낮게)/.test(l) ? '등급' : '';
    if (!m) return;
    const q = l.replace(/^-\s*/, '').trim();
    const t = m === '목록 밖' ? `“${q}”는 임시 조치 목록에 없어 AI가 고를 수 없습니다. 지침에서 빼거나 사람이 할 일로 적으세요.` : m === '지우기' ? `“${q}”는 지우기를 요구하는 것으로 보입니다. AI는 지우기를 고를 수 없습니다.` : m === '비밀값' ? `“${q}”는 비밀값을 요구하는 것으로 보입니다. AI에게 비밀값은 넘어가지 않습니다.` : `“${q}”는 영향 등급을 낮추려는 것으로 보입니다. 지침으로 등급을 낮출 수 없습니다.`;
    out.push({ line: i + 1, text: t });
  });
  return out;
}

export function guideSummaries(t: string, a: string): Record<'cluster' | 'tenant' | 'app', { version: number; summary: string } | undefined> {
  const one = (k: string) => {
    const v = last(store.get(k));
    return v && { version: v.version, summary: quote(v.text) };
  };
  return { cluster: one('cluster'), tenant: one(`tenant/${t}`), app: one(`app/${t}/${a}`) };
}

export function registerGuides(ctx: Ctx) {
  const { on, ok, err } = ctx;
  const can = (key: string, write: boolean) => {
    const [kind, t] = key.split('/');
    if (kind === 'cluster') return ctx.me().systemAdmin;
    ctx.reader(t);
    return write ? ctx.canWrite(t) : true;
  };
  const choices = (key: string): Guide['choices'] => {
    const [kind, t, a] = key.split('/');
    const upper = kind === 'cluster' ? [] : [['cluster', last(store.get('cluster'))?.fields.avoid.actions ?? []] as const, ...(kind === 'app' ? [['tenant', last(store.get(`tenant/${t}`))?.fields.avoid.actions ?? []] as const] : [])];
    const acts = ACTIONS.filter((x) => kind === 'cluster' || x.scope === 'app').map((x) => {
      const by = upper.find(([, list]) => list.includes(x.id))?.[0];
      return { id: x.id, label: x.label.replace(/ \(.*\)$/, ''), ...(by ? { blockedBy: by } : {}) };
    });
    return { actions: acts, services: kind === 'app' ? (SERVICES[`${t}/${a}`] ?? ['web']) : undefined, mcpServers: mcpChoices(kind === 'cluster' ? undefined : t) };
  };
  const view = (key: string): Guide => {
    const [kind, t, a] = key.split('/');
    const r = store.get(key);
    const v = last(r);
    return {
      scope: kind as Guide['scope'],
      ...(t ? { tenant: t } : {}),
      ...(a ? { app: a } : {}),
      version: v?.version ?? 0,
      revision: r?.revision ?? 0,
      text: v?.text ?? '',
      fields: v?.fields ?? empty(),
      updatedBy: v?.updatedBy,
      updatedAt: v?.updatedAt,
      warnings: warn(v?.text ?? ''),
      deliver: r?.deliver ?? { diagnose: true, coordinator: true },
      choices: choices(key),
    };
  };
  const keyOf = (mm: string[], kind: string) => (kind === 'cluster' ? 'cluster' : kind === 'tenant' ? `tenant/${mm[0]}` : `app/${mm[0]}/${mm[1]}`);
  const routes: [string, string][] = [
    ['cluster', '/guides/cluster'],
    ['tenant', '/guides/tenant/:t'],
    ['app', '/guides/app/:t/:a'],
  ];

  on('GET', '/guides', () => {
    const items: GuideSummary[] = [];
    for (const [key, r] of store) {
      const [kind, t, a] = key.split('/');
      try {
        if (!can(key, false)) continue;
      } catch {
        continue;
      }
      const v = last(r)!;
      items.push({ scope: kind as GuideSummary['scope'], ...(t ? { tenant: t } : {}), ...(a ? { app: a } : {}), version: v.version, updatedBy: v.updatedBy, updatedAt: v.updatedAt, summary: quote(v.text), lines: lineCount(v.text) });
    }
    return ok({ items });
  });
  for (const [kind, p] of routes) {
    on('GET', p, (mm) => {
      const key = keyOf(mm, kind);
      if (!can(key, false)) return err(403, 'denied', '클러스터 지침은 시스템 관리자만 볼 수 있습니다.');
      return ok(view(key));
    });
    on('PUT', p, (mm, b) => {
      const key = keyOf(mm, kind);
      if (!can(key, true)) return err(403, 'denied', kind === 'cluster' ? '시스템 관리자 권한이 필요합니다.' : '이 작업 공간의 관리자 권한이 필요합니다.');
      const r = store.get(key) ?? { revision: 0, deliver: { diagnose: true, coordinator: true }, versions: [] };
      if (b.revision !== r.revision) return err(409, 'stale', '그사이 다른 사람이 지침을 바꿨습니다.');
      const text = String(b.text ?? '');
      if (text.length > 4000) return err(422, 'invalid', 'text는 4,000자까지입니다.');
      const f = b.fields as GuideFields;
      const ids = new Set(ACTIONS.map((x) => x.id));
      for (const id of [...(f?.prefer ?? []), ...(f?.avoid?.actions ?? [])]) if (!ids.has(id)) return err(422, 'invalid', `목록 밖 조치: ${id}`);
      const ch = choices(key)!;
      const blocked = ch.actions.filter((x) => x.blockedBy).map((x) => x.id);
      if (f.prefer.some((x) => blocked.includes(x))) return err(422, 'invalid', '위 단계 지침이 막은 조치를 먼저 고려할 조치로 둘 수 없습니다.');
      const okMcp = new Set((ch.mcpServers ?? []).map((x) => x.name));
      if (f.mcpServers.some((x) => !okMcp.has(x))) return err(422, 'invalid', '이 범위에서 쓸 수 없는 MCP 서버가 있습니다.');
      const prev = last(r);
      const summary = prev ? (prev.text === text ? '정해진 칸만 바꿈' : `${text.split('\n').length - prev.text.split('\n').length >= 0 ? '줄 고침·추가' : '줄 뺌'}`) : '처음 작성';
      r.versions.push({ version: (prev?.version ?? 0) + 1, text, fields: f, updatedBy: ctx.me().username, updatedAt: new Date().toISOString(), summary, incidents: 0 });
      r.revision += 1;
      if (b.deliver) r.deliver = b.deliver as Rec['deliver'];
      store.set(key, r);
      return ok(view(key));
    });
    on('GET', `${p}/versions`, (mm) => {
      const key = keyOf(mm, kind);
      if (!can(key, false)) return err(403, 'denied', '권한이 없습니다.');
      const r = store.get(key);
      const vs = r?.versions ?? [];
      const items: GuideVersion[] = vs.map((v, i) => ({ version: v.version, updatedBy: v.updatedBy, updatedAt: v.updatedAt, summary: v.summary, incidents: v.incidents, current: i === vs.length - 1 })).reverse();
      return ok({ items });
    });
    on('POST', `${p}/restore`, (mm, b) => {
      const key = keyOf(mm, kind);
      if (!can(key, true)) return err(403, 'denied', '권한이 없습니다.');
      const r = store.get(key);
      if (!r || b.revision !== r.revision) return err(409, 'stale', '그사이 다른 사람이 지침을 바꿨습니다.');
      const old = r.versions.find((v) => v.version === b.version);
      if (!old) return err(404, 'not-found', '그 버전이 없습니다.');
      r.versions.push({ ...old, version: last(r)!.version + 1, updatedBy: ctx.me().username, updatedAt: new Date().toISOString(), summary: `v${old.version}으로 되돌림`, incidents: 0 });
      r.revision += 1;
      return ok(view(key));
    });
    on('POST', `${p}/test`, (mm, b) => {
      const key = keyOf(mm, kind);
      if (!can(key, false)) return err(403, 'denied', '권한이 없습니다.');
      if (!b.incident) return err(422, 'invalid', 'incident');
      const cur: GuideTestRun = { hypothesis: '큐 적체로 worker 시간 초과', candidates: [{ action: 'restart-task', label: '컨테이너 재시작', impact: 'low' }, { action: 'pause-cd', label: '자동 배포 일시 정지' }], mcpCalls: {}, tokens: { total: 18000, cachedRatio: 0.82 } };
      const draft: GuideTestRun | undefined =
        b.text !== undefined || b.fields !== undefined
          ? { hypothesis: '큐 적체 · 큐 11만', candidates: [{ action: 'pause-cd', label: '자동 배포 일시 정지', impact: 'low' }, { action: 'restart-task', label: '컨테이너 재시작' }], mcpCalls: { grafana: 2, sentry: 1 }, tokens: { total: 21000, cachedRatio: 0 } }
          : undefined;
      return ok({ current: cur, ...(draft ? { draft } : {}) });
    });
  }
}
