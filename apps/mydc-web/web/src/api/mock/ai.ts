// SPDX-License-Identifier: Apache-2.0

// AI 설정 목업 (UI-B7). 키 값은 받자마자 끝 4자리만 남기고 버린다(데몬은 봉인 파일에 둔다).
// 키 검사: Claude는 sk-ant-, OpenAI는 sk-로 시작해야 하고, '-down'이 들어 있으면 공급자 응답 없음으로 본다.
import { ApiError, type RawResponse } from '../client';
import type { AiChip, AiContext, AiConversation, AiConversationFull, AiMessage, AiProposal, AiStreamEvent, AiTool, AiAuditRow, AiData, AiLimits, AiModel, AiProvider, AiProviderRow, AiRole, AiRoleConf, AiSettings, AiUsageRow } from '../ai';
import { AI_ROLES } from '../ai';

interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string, extra?: Record<string, unknown>) => RawResponse;
  /** 시스템 관리자가 아니면 403으로 멈춘다 */
  admin: () => { id: string; username: string };
  sealReady: () => boolean;
}

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const day = 86400;

const CLAUDE: AiModel[] = [
  { id: 'claude-opus-5-5', displayName: 'Claude Opus 5.5', createdAt: ago(day * 40), hidden: false },
  { id: 'claude-sonnet-5-5', displayName: 'Claude Sonnet 5.5', createdAt: ago(day * 41), hidden: false },
  { id: 'claude-fable-5-2', displayName: 'Claude Fable 5.2', createdAt: ago(day * 70), hidden: false },
  { id: 'claude-haiku-5-5', displayName: 'Claude Haiku 5.5', createdAt: ago(day * 72), hidden: false },
  { id: 'claude-opus-5', displayName: 'Claude Opus 5', createdAt: ago(day * 200), hidden: false },
  { id: 'claude-opus-4-8', displayName: 'Claude Opus 4.8', createdAt: ago(day * 330), hidden: false },
];
const OPENAI: AiModel[] = [
  ...['gpt-5.1', 'gpt-5.1-mini', 'gpt-5.1-nano', 'gpt-5', 'gpt-5-mini', 'gpt-5-nano', 'o5', 'o5-mini', 'gpt-4.5', 'gpt-4.1', 'gpt-4.1-mini', 'gpt-4o', 'gpt-4o-mini', 'o4-mini'].map((id, i) => ({ id, createdAt: ago(day * (20 + i * 30)), hidden: false })),
  ...Array.from({ length: 47 }, (_, i) => ({ id: ['text-embedding-3-large', 'tts-1', 'whisper-1', 'dall-e-3', 'omni-moderation'][i % 5] + (i >= 5 ? `-${i}` : ''), createdAt: ago(day * (60 + i * 9)), hidden: true })),
];
const catalog: Record<AiProvider, AiModel[]> = { claude: CLAUDE, openai: OPENAI };

const keys: Record<AiProvider, { last4?: string; setBy?: string; setAt?: string; catalogAt?: string; error?: string }> = {
  claude: { last4: '8c1d', setBy: 'alice', setAt: ago(day), catalogAt: ago(1800) },
  openai: { last4: '41fa', setBy: 'alice', setAt: ago(day), catalogAt: ago(1800) },
};
const state: { revision: number; roles: Record<AiRole, AiRoleConf>; data: AiData; limits: AiLimits } = {
  revision: 3,
  roles: {
    coordinator: { main: { provider: 'claude', model: 'claude-opus-5-5' }, fallback: { provider: 'claude', model: 'claude-sonnet-5-5' }, effort: 'medium', thinking: 'auto', maxOutputTokens: 8000, stream: true },
    diagnosis: { main: { provider: 'claude', model: 'claude-opus-5-5' }, fallback: { provider: 'openai', model: 'gpt-5.1' }, effort: 'high', thinking: 'auto', maxOutputTokens: 8000, stream: false },
    impact: { main: { provider: 'openai', model: 'gpt-5.1' }, fallback: { provider: 'claude', model: 'claude-sonnet-5-5' }, effort: 'medium', thinking: 'auto', maxOutputTokens: 2000, stream: false },
    simple: { main: { provider: 'claude', model: 'claude-haiku-5-5' }, fallback: { provider: 'openai', model: 'gpt-5.1-mini' }, effort: 'low', thinking: 'off', maxOutputTokens: 500, stream: false },
  },
  data: { maskSecretLikeEnv: true, logTailLines: 200, excludeTenants: ['finance'] },
  limits: { dailyTokensPerUser: 2_000_000, toolCallsPerConversation: 0, tokensPerConversation: 0, compaction: { enabled: true, triggerTokens: 150_000 } },
};
const audit: AiAuditRow[] = [
  ...Array.from({ length: 409 }, (_, i): AiAuditRow => ({ at: ago(600 + i * 1500), user: i % 3 ? 'alice' : 'bob', kind: 'request', provider: i % 4 ? 'claude' : 'openai', model: i % 4 ? 'claude-opus-5-5' : 'gpt-5.1', tokens: 4000 + ((i * 731) % 9000), cacheRead: 3000 + ((i * 331) % 5000) })),
  { at: ago(day), user: 'alice', kind: 'key-set', provider: 'claude' } as AiAuditRow,
  { at: ago(day), user: 'alice', kind: 'key-set', provider: 'openai' } as AiAuditRow,
  { at: ago(day), user: 'alice', kind: 'settings' },
].sort((a, b) => b.at.localeCompare(a.at));

const has = (p: AiProvider, model: string) => !!keys[p].last4 && catalog[p].some((m) => m.id === model);
const providerRow = (p: AiProvider): AiProviderRow => {
  const k = keys[p];
  return { provider: p, configured: !!k.last4, last4: k.last4, setBy: k.setBy, setAt: k.setAt, catalogAt: k.last4 ? k.catalogAt : undefined, models: k.last4 ? catalog[p].filter((m) => !m.hidden).length : 0, modelsTotal: k.last4 ? catalog[p].length : 0, error: k.error };
};
const view = (sealReady: boolean): AiSettings => ({
  sealReady,
  revision: state.revision,
  providers: (['claude', 'openai'] as AiProvider[]).map(providerRow),
  roles: Object.fromEntries(
    AI_ROLES.map((r) => {
      const c = state.roles[r];
      return [r, { ...c, mainMissing: !c.main || !has(c.main.provider, c.main.model), fallbackMissing: !!c.fallback && !has(c.fallback.provider, c.fallback.model), sameProvider: !!c.main && !!c.fallback && c.main.provider === c.fallback.provider }];
    }),
  ) as Record<AiRole, AiRoleConf>,
  data: state.data,
  limits: state.limits,
});

// 최근 7일 사용량. 역할별 적중률이 캔버스 값(91·84·96·88%)에 가깝게
const USAGE: [AiRole, AiProvider, string, number, number, number][] = [
  ['coordinator', 'claude', 'claude-opus-5-5', 1_800_000, 170_000, 9_000],
  ['diagnosis', 'claude', 'claude-opus-5-5', 400_000, 70_000, 6_000],
  ['impact', 'openai', 'gpt-5.1', 600_000, 20_000, 5_000],
  ['simple', 'claude', 'claude-haiku-5-5', 900_000, 50_000, 72_000],
];
function usage(days: number): { items: AiUsageRow[]; roles: Partial<Record<AiRole, { hitRate: number }>> } {
  const items: AiUsageRow[] = [];
  for (let d = 0; d < days; d++) {
    const date = new Date(Date.now() - d * day * 1000).toISOString().slice(0, 10);
    for (const [role, provider, model, read, write, input] of USAGE) {
      const f = d < 7 ? 1 / 7 : 0.6 / 7;
      items.push({ day: date, role, provider, model, fallback: false, requests: Math.round(40 * f * 7), inputTokens: Math.round(input * f), outputTokens: Math.round(input * f * 0.4), cacheReadTokens: Math.round(read * f), cacheWriteTokens: Math.round(write * f) });
    }
  }
  const roles: Partial<Record<AiRole, { hitRate: number }>> = {};
  for (const r of AI_ROLES) {
    const xs = items.filter((x) => x.role === r);
    const read = xs.reduce((a, x) => a + x.cacheReadTokens, 0);
    const all = xs.reduce((a, x) => a + x.inputTokens + x.cacheReadTokens + x.cacheWriteTokens, 0);
    if (all) roles[r] = { hitRate: read / all };
  }
  return { items, roles };
}

export function registerAi(ctx: Ctx) {
  const { on, ok, err, admin } = ctx;
  const provider = (s: string): AiProvider | undefined => (s === 'claude' || s === 'openai' ? s : undefined);

  on('GET', '/system/ai', () => (admin(), ok(view(ctx.sealReady()))));
  on('PUT', '/system/ai/keys/:p', (m, b) => {
    const u = admin();
    const p = provider(m[0]);
    if (!p) return err(404, 'not-found', 'no such provider');
    if (Object.keys(b).some((k) => k !== 'key')) return err(400, 'bad-request', 'unknown field');
    if (!ctx.sealReady()) return err(503, 'seal-unavailable', '봉인 키가 없어 키를 저장할 수 없습니다.');
    const key = typeof b.key === 'string' ? b.key.trim() : '';
    if (!key) return err(422, 'invalid', 'key is required');
    if (key.includes('-down')) return err(422, 'key-rejected', '공급자가 응답하지 않습니다.', { detail: 'unavailable' });
    if (!key.startsWith(p === 'claude' ? 'sk-ant-' : 'sk-') || key.length < 16) return err(422, 'key-rejected', '키가 폐기됐거나 틀렸습니다.', { detail: 'auth' });
    keys[p] = { last4: key.slice(-4), setBy: u.username, setAt: new Date().toISOString(), catalogAt: new Date().toISOString() };
    audit.unshift({ at: new Date().toISOString(), user: u.username, kind: 'key-set', provider: p });
    return ok(providerRow(p));
  });
  on('DELETE', '/system/ai/keys/:p', (m) => {
    const u = admin();
    const p = provider(m[0]);
    if (!p) return err(404, 'not-found', 'no such provider');
    keys[p] = {};
    audit.unshift({ at: new Date().toISOString(), user: u.username, kind: 'key-deleted', provider: p });
    return ok(null, 204);
  });
  on('POST', '/system/ai/models/:p/refresh', (m) => {
    admin();
    const p = provider(m[0]);
    if (!p) return err(404, 'not-found', 'no such provider');
    if (!keys[p].last4) return err(409, 'no-key', '키가 없습니다.');
    keys[p].catalogAt = new Date().toISOString();
    return ok(providerRow(p));
  });
  on('GET', '/system/ai/models/:p', (m, _b, q) => {
    admin();
    const p = provider(m[0]);
    if (!p) return err(404, 'not-found', 'no such provider');
    const items = keys[p].last4 ? catalog[p].filter((x) => q.get('all') === '1' || !x.hidden).sort((a, b) => b.createdAt.localeCompare(a.createdAt)) : [];
    return ok({ provider: p, fetchedAt: keys[p].catalogAt, items });
  });
  on('PUT', '/system/ai/settings', (_m, b) => {
    const u = admin();
    if (Object.keys(b).some((k) => !['revision', 'roles', 'data', 'limits'].includes(k))) return err(400, 'bad-request', 'unknown field');
    if (b.revision !== state.revision) return err(409, 'revision-changed', '그사이 다른 사람이 AI 설정을 바꿨습니다.');
    const roles = b.roles as Record<AiRole, AiRoleConf>;
    const limits = b.limits as AiLimits;
    for (const r of AI_ROLES) {
      const c = roles?.[r];
      if (!c) return err(422, 'invalid', `roles.${r} is required`);
      for (const ref of [c.main, c.fallback]) if (ref && !has(ref.provider, ref.model)) return err(422, 'model-not-in-catalog', `${ref.provider}/${ref.model}`);
    }
    if (!limits?.compaction?.enabled && (limits.toolCallsPerConversation === 0 || limits.tokensPerConversation === 0)) return err(422, 'unlimited-needs-compaction', '무제한은 자동 compaction이 켜져 있어야 합니다.');
    state.roles = Object.fromEntries(AI_ROLES.map((r) => [r, { main: roles[r].main, fallback: roles[r].fallback, effort: roles[r].effort, thinking: roles[r].thinking, maxOutputTokens: roles[r].maxOutputTokens, stream: roles[r].stream }])) as Record<AiRole, AiRoleConf>;
    if (b.data) state.data = b.data as AiData;
    state.limits = limits;
    state.revision++;
    audit.unshift({ at: new Date().toISOString(), user: u.username, kind: 'settings' });
    return ok(view(ctx.sealReady()));
  });
  on('GET', '/system/ai/usage', (_m, _b, q) => {
    admin();
    const days = Number(q.get('days') ?? 7);
    if (!Number.isInteger(days) || days < 1 || days > 90) return err(422, 'invalid', 'days must be 1..90');
    return ok(usage(days));
  });
  on('GET', '/system/ai/audit', (_m, _b, q) => {
    admin();
    const limit = Math.min(200, Number(q.get('limit') ?? 50) || 50);
    const from = Number(q.get('cursor') ?? 0) || 0;
    const items = audit.slice(from, from + limit);
    return ok({ items, cursor: from + limit < audit.length ? String(from + limit) : undefined, total: audit.length });
  });
  on('DELETE', '/system/ai/audit', (_m, b) => {
    admin();
    const before = typeof b.before === 'string' ? Date.parse(b.before) : NaN;
    if (Number.isNaN(before)) return err(422, 'invalid', 'before must be RFC 3339');
    const keep = audit.filter((x) => Date.parse(x.at) >= before);
    const deleted = audit.length - keep.length;
    audit.splice(0, audit.length, ...keep);
    return ok({ deleted });
  });
}

// ── 코디네이터 (UI-B0·B1·B2) ──
// 사용자마다 대화를 따로 둔다. 답은 정해 둔 각본이다: '디스크'가 들어가면 캔버스의 node-b 정리(제안 2개), 아니면 읽기만 한 짧은 답.
const seeded = new Set<string>();
let seedSubmit: ((body: Record<string, unknown>, action: string) => RawResponse) | undefined;
type Conv = AiConversationFull & { owner: string; createdAt: string; updatedAt: string };
const convs: Conv[] = [];
const proposals: AiProposal[] = [];
let seq = 100;
const nid = (p: string) => `${p}-${(seq++).toString(36)}${Math.random().toString(36).slice(2, 6)}`;
const later = (s: number) => new Date(Date.now() + s * 1000).toISOString();

function diskProposals(conv: string, decided: boolean, by: string): AiProposal[] {
  const a: AiProposal = {
    id: nid('pr'),
    conversation: conv,
    title: '안 쓰는 이미지 정리',
    index: 1,
    total: 2,
    tool: 'node.images.prune',
    action: 'prune-node-images',
    target: 'node-b',
    payload: { node: 'node-b', images: Array.from({ length: 12 }, (_, i) => `img-${i}`) },
    preview: [
      { label: '대상', value: '서버 node-b' },
      { label: '작업', value: 'node.images.prune' },
      { label: '지울 이미지', value: '12개 · 18.4 GiB' },
      { label: '실행 중 영향', value: '없음 (쓰는 이미지는 제외)' },
      { label: '되돌리기', value: '필요하면 다시 받음' },
    ],
    items: [
      { name: 'shop/web:pr-401', size: 211e6, lastUsed: ago(day * 40) },
      { name: 'shop/web:v2.12.0', size: 209e6, lastUsed: ago(day * 52) },
      ...Array.from({ length: 10 }, (_, i) => ({ name: `shop/worker:v1.${30 + i}`, size: 1.8e9 - i * 3e7, lastUsed: ago(day * (60 + i * 4)) })),
    ],
    impact: 'low',
    revert: '필요하면 다시 받음',
    irreversible: false,
    expected: 412,
    basisHash: nid('h'),
    expiresAt: later(540),
    edited: false,
    state: decided ? 'approved' : 'pending',
    ...(decided ? { decidedBy: by, decidedAt: ago(3600), op: 'img-4c1e' } : {}),
  };
  const b: AiProposal = {
    id: nid('pr'),
    conversation: conv,
    title: 'php-shop-worker 로그 보관량 줄이기',
    index: 2,
    total: 2,
    after: a.id,
    tool: 'app.update',
    action: 'begin-app',
    tenant: 'shop',
    target: 'php-shop',
    payload: { app: 'php-shop', version: 16 },
    preview: [
      { label: '대상', value: '앱 php-shop (작업 공간 shop)' },
      { label: '작업', value: 'app.yaml 변경 → 새 버전 16 배포' },
      { label: '변경점', value: 'logging.max-size: 10g → 500m' },
      { label: '실행 중 영향', value: 'worker 컨테이너 1개 교체 (약 5초 멈춤)' },
    ],
    diff: '--- php-shop 버전 15\n+++ php-shop 버전 16\n@@ services.worker @@\n   worker:\n     logging:\n-      max-size: 10g\n+      max-size: 500m\n',
    impact: 'medium',
    revert: '버전 15로 되돌리기',
    irreversible: false,
    expected: 15,
    basisHash: nid('h'),
    expiresAt: later(540),
    edited: false,
    state: decided ? 'rejected' : 'pending',
    ...(decided ? { decidedBy: by, decidedAt: ago(3500), reason: '다음 정기 배포 때 함께 반영' } : {}),
  };
  return [a, b];
}
const DISK_TOOLS: AiTool[] = [
  { name: 'tool_search', kind: 'find', summary: '서버 디스크 사용량, 이미지 캐시 정리, 컨테이너 로그 크기', args: { query: '디스크 정리' } },
  { name: 'node.disk.usage', kind: 'read', summary: 'node-b 디스크 92% (184 / 200 GiB)', args: { node: 'node-b' } },
  { name: 'node.images.list', kind: 'read', summary: 'node-b 이미지 31개 중 안 쓰는 이미지 12개 (18.4 GiB)', args: { node: 'node-b', unused: 'true' } },
  { name: 'task.logs.size', kind: 'read', summary: 'php-shop-worker 로그 9.8 GiB', args: { tenant: 'shop', task: 'php-shop-worker', token: '«가림»' } },
];
const DISK_TEXT = 'node-b 디스크의 큰 원인은 두 가지입니다. 안 쓰는 이미지 12개(18.4 GiB)와 php-shop-worker의 로그(9.8 GiB)입니다. 이미지 정리는 실행 중인 컨테이너에 영향이 없습니다. 로그는 앱 설정에서 보관량을 줄이는 게 근본 조치라 따로 제안할게요. 아래 작업을 승인하면 실행합니다.';

/** MCP 도구 호출 제안 (PR #164): tool mcp.{server}.{tool}, action mcp-call, target mcp/{server}, change면 medium */
function mcpProposal(conv: string): AiProposal {
  return {
    id: nid('pr'),
    conversation: conv,
    title: 'grafana 알림 1시간 묵음',
    index: 1,
    total: 1,
    tool: 'mcp.grafana.create_silence',
    action: 'mcp-call',
    target: 'mcp/grafana',
    payload: { duration: '60m', matchers: 'app=php-shop', comment: 'MyDC 코디네이터 · php-shop 배포 중 묵음' },
    preview: [
      { label: '대상', value: 'MCP 서버 grafana · 도구 create_silence' },
      { label: '인자', value: 'duration 60m · matchers app=php-shop' },
      { label: '실행 중 영향', value: 'php-shop 알림이 1시간 동안 오지 않음' },
    ],
    impact: 'medium',
    revert: 'grafana에서 묵음 지우기 (delete_silence)',
    irreversible: false,
    basisHash: nid('h'),
    expiresAt: later(600),
    edited: false,
    state: 'pending',
    mcp: { server: 'grafana', tool: 'create_silence' },
  };
}
const MCP_TOOLS: AiTool[] = [
  { name: 'tool_search', kind: 'find', summary: '알림 묵음 · grafana', args: { query: '알림 묵음' } },
  { name: 'mcp.grafana.list_alerts', kind: 'read', summary: 'php-shop 경보 3개 울리는 중', args: { app: 'php-shop' } },
];
const MCP_TEXT = 'php-shop 경보 3개가 배포 때문에 울리고 있습니다. grafana MCP 서버의 create_silence로 1시간 묵음을 걸 수 있어요. 아래 카드를 승인하면 호출합니다.';

function seed(owner: string) {
  if (seeded.has(owner)) return;
  seeded.add(owner);
  const mk = (title: string, s: number, msgs: AiMessage[], tenant = 'shop'): Conv => ({ id: nid('cv'), owner, title, model: 'Claude Opus 5.5', tenant, createdAt: ago(s + 600), updatedAt: ago(s), messages: msgs });
  const first = mk('node-b 디스크 정리', 30, []);
  const ps = diskProposals(first.id, true, owner);
  // 승인된 카드가 GET /ops/{id}로 실제 작업 상태를 읽을 수 있게 목업 작업을 하나 만들어 둔다
  for (const p of ps.filter((x) => x.state === 'approved' && seedSubmit)) {
    const opId = crypto.randomUUID();
    if (seedSubmit!({ opId, tenant: p.tenant, target: p.target }, p.action).status < 300) p.op = opId;
    else delete p.op;
  }
  proposals.push(...ps);
  first.messages = [
    { id: nid('m'), role: 'user', text: 'node-b 디스크가 꽉 찼다는 알림이 왔어. 원인 보고 정리해 줘', at: ago(3700) },
    { id: nid('m'), role: 'assistant', text: DISK_TEXT, at: ago(3690), model: 'Claude Opus 5.5', tools: DISK_TOOLS, proposals: ps.map((p) => p.id) },
  ];
  const simple = (title: string, s: number, q: string, a: string) => mk(title, s, [
    { id: nid('m'), role: 'user', text: q, at: ago(s + 60) },
    { id: nid('m'), role: 'assistant', text: a, at: ago(s), model: 'Claude Opus 5.5', tools: [{ name: 'tool_search', kind: 'find', summary: '관련 도구' }] },
  ]);
  convs.push(
    first,
    { ...simple('php-shop 메모리 한도', day / 2, 'inc-0412 근본 조치로 worker 메모리를 늘리려면?', 'worker 메모리 한도를 256m에서 512m로 올리는 app.yaml 변경을 제안할 수 있습니다.'), chips: [{ kind: 'incident', id: 'inc-0412' }] },
    simple('php-shop 배포 실패 원인', day, 'php-shop 배포가 왜 실패했어?', '버전 15 배포에서 worker 상태 검사가 30초 안에 통과하지 못했습니다. 이미지 시작이 느려 보입니다.'),
    simple('shop 작업 공간 사용 한도 늘리기', day * 3, 'shop 메모리 한도를 늘리려면?', '작업 공간 설정의 서버 한도에서 메모리를 바꿀 수 있습니다. 시스템 관리자 권한이 필요합니다.'),
    simple('mysql 백업 일정 확인', day * 4, 'mysql 백업은 언제 돌아?', 'mysql-data 저장소의 예약 백업은 매일 03:00입니다. 마지막 백업은 오늘 03:00에 끝났습니다.'),
    simple('새 서버 node-c 추가 절차', day * 10, '서버를 하나 더 붙이려면?', '서버 화면의 ‘서버 추가’에서 가입 토큰을 만들고 새 서버에서 mydc node join을 실행합니다.'),
  );
  for (let i = 0; i < 18; i++) convs.push(simple(`지난 대화 ${i + 1}`, day * (12 + i), '질문', '답'));
}
const mine = (owner: string) => (seed(owner), convs.filter((c) => c.owner === owner));
const row = (c: Conv): AiConversation => ({ id: c.id, title: c.title, model: c.model, tenant: c.tenant, createdAt: c.createdAt, updatedAt: c.updatedAt, pendingProposals: proposals.filter((p) => p.conversation === c.id && p.state === 'pending').length, ...(incidentOf(c) ? { incident: incidentOf(c) } : {}) });
const incidentOf = (c: Conv) => (c.chips ?? []).find((x) => x.kind === 'incident')?.id;

export function registerCoordinator(ctx: Omit<Ctx, 'admin' | 'sealReady'> & { me: () => { username: string }; submit: (body: Record<string, unknown>, action: string) => RawResponse }) {
  const { on, ok, err } = ctx;
  seedSubmit = ctx.submit;
  const conv = (id: string) => {
    const c = mine(ctx.me().username).find((x) => x.id === id);
    return c;
  };
  on('GET', '/ai/conversations', () => ok({ items: mine(ctx.me().username).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).map(row) }));
  on('POST', '/ai/conversations', (_m, b) => {
    const owner = ctx.me().username;
    mine(owner);
    const inc = typeof b.incident === 'string' && b.incident ? b.incident : undefined;
    const chips = [...(Array.isArray(b.chips) ? (b.chips as AiChip[]) : []), ...(inc ? [{ kind: 'incident', id: inc }] : [])].slice(0, 8);
    const c: Conv = { id: nid('cv'), owner, title: typeof b.title === 'string' && b.title ? b.title : inc ? `사건 ${inc}` : '새 대화', model: 'Claude Opus 5.5', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), chips, messages: [] };
    convs.push(c);
    return ok(row(c), 201);
  });
  on('GET', '/ai/conversations/:id', (m) => {
    const c = conv(m[0]);
    if (!c) return err(404, 'not-found', 'no such conversation');
    const { owner: _o, ...rest } = c;
    return ok(rest);
  });
  on('PATCH', '/ai/conversations/:id', (m, b) => {
    const c = conv(m[0]);
    if (!c) return err(404, 'not-found', 'no such conversation');
    if ('chips' in b) c.chips = Array.isArray(b.chips) ? (b.chips as AiChip[]).slice(0, 8) : [];
    if ('title' in b) {
      const t = typeof b.title === 'string' ? b.title.trim() : '';
      if (!t || t.length > 120) return err(422, 'invalid', 'title must be 1..120 characters');
      c.title = t;
    }
    return ok(null, 204);
  });
  on('DELETE', '/ai/conversations/:id', (m) => {
    const c = conv(m[0]);
    if (!c) return err(404, 'not-found', 'no such conversation');
    convs.splice(convs.indexOf(c), 1);
    return ok(null, 204);
  });
  on('DELETE', '/ai/conversations', () => {
    const owner = ctx.me().username;
    for (const c of convs.filter((x) => x.owner === owner)) convs.splice(convs.indexOf(c), 1);
    return ok(null, 204);
  });
  on('POST', '/ai/conversations/:id/stop', () => ok(null, 204));
  const prop = (id: string) => {
    const p = proposals.find((x) => x.id === id);
    if (!p || !conv(p.conversation)) return undefined;
    if (p.state === 'pending' && Date.parse(p.expiresAt) < Date.now()) p.state = 'expired';
    return p;
  };
  on('GET', '/ai/proposals/:id', (m) => {
    const p = prop(m[0]);
    return p ? ok(p) : err(404, 'not-found', 'no such proposal');
  });
  on('POST', '/ai/proposals/:id/approve', (m, b) => {
    const p = prop(m[0]);
    if (!p) return err(404, 'not-found', 'no such proposal');
    if (p.state === 'expired') return err(410, 'expired', '제안이 만료됐습니다.');
    const mp = p as AiProposal & { mcpOpId?: string };
    if (p.mcp && p.state === 'approved' && mp.mcpOpId === b.opId) return ok({ mcp: { ok: !p.reason, server: p.mcp.server, tool: p.mcp.tool, ...(p.reason ? { error: p.reason } : {}) } });
    if (p.state !== 'pending' && !(p.state === 'approved' && p.op === b.opId)) return err(409, 'proposal-changed', '이미 처리된 제안입니다.');
    if (b.basisHash !== p.basisHash) return err(409, 'proposal-changed', '제안 내용이 바뀌었습니다.');
    if (p.after) {
      const a = proposals.find((x) => x.id === p.after);
      if (a && a.state !== 'approved') return err(409, 'waiting', '먼저 끝나야 하는 제안이 있습니다.');
    }
    if (p.irreversible && b.confirmName !== p.confirmName) return err(422, 'confirm-name', '이름이 맞지 않습니다.');
    if (p.mcp) {
      // MCP 도구 호출은 op가 없다. 같은 opId로 다시 보내면 같은 결과
      Object.assign(p, { state: 'approved', decidedBy: ctx.me().username, decidedAt: new Date().toISOString(), mcpOpId: String(b.opId) });
      return ok({ mcp: { ok: true, server: p.mcp.server, tool: p.mcp.tool } });
    }
    const res = ctx.submit({ opId: b.opId, tenant: p.tenant, target: p.target }, p.action);
    if (res.status < 300) Object.assign(p, { state: 'approved', decidedBy: ctx.me().username, decidedAt: new Date().toISOString(), op: String(b.opId) });
    return res;
  });
  on('POST', '/ai/proposals/:id/reject', (m, b) => {
    const p = prop(m[0]);
    if (!p) return err(404, 'not-found', 'no such proposal');
    if (p.state !== 'pending') return err(409, 'proposal-changed', '이미 처리된 제안입니다.');
    Object.assign(p, { state: 'rejected', decidedBy: ctx.me().username, decidedAt: new Date().toISOString(), reason: typeof b.reason === 'string' ? b.reason : '' });
    return ok(null, 204);
  });
  on('PUT', '/ai/proposals/:id', (m, b) => {
    const p = prop(m[0]);
    if (!p) return err(404, 'not-found', 'no such proposal');
    if (p.state !== 'pending') return err(409, 'proposal-changed', '이미 처리된 제안입니다.');
    const pl = b.payload as Record<string, unknown> | undefined;
    if (!pl || typeof pl !== 'object') return err(422, 'invalid', 'payload is required');
    if (p.tool === 'node.images.prune') {
      const keep = Array.isArray(pl.items) ? (pl.items as string[]) : [];
      if (!keep.length) return err(422, 'invalid', '지울 이미지를 하나 이상 고르세요.');
      p.items = (p.items ?? []).filter((x) => keep.includes(x.name));
      const bytes = p.items.reduce((a, x) => a + (x.size ?? 0), 0);
      p.preview = p.preview.map((r) => (r.label === '지울 이미지' ? { ...r, value: `${p.items!.length}개 · ${(bytes / 1024 ** 3).toFixed(1)} GiB` } : r));
    }
    p.payload = { ...p.payload, ...pl };
    p.edited = true;
    p.basisHash = nid('h');
    return ok(p);
  });
}

const wait = (ms: number, signal: AbortSignal) =>
  new Promise<void>((res, rej) => {
    const t = setTimeout(res, ms);
    signal.addEventListener('abort', () => (clearTimeout(t), rej(new DOMException('aborted', 'AbortError'))));
  });

export async function mockChat(id: string, body: { text: string; context: AiContext }, onEvent: (e: AiStreamEvent) => void, signal: AbortSignal): Promise<void> {
  const { currentUser } = await import('./router');
  const { users } = await import('./fixtures');
  const owner = users.find((u) => u.id === currentUser())?.username ?? '';
  const c = mine(owner).find((x) => x.id === id);
  if (!c) throw new ApiError(404, { code: 'not-found', message: 'no such conversation' });
  if ((c as Conv & { busy?: boolean }).busy) throw new ApiError(409, { code: 'busy', message: '이 대화는 답하는 중입니다.' });
  (c as Conv & { busy?: boolean }).busy = true;
  try {
    c.messages.push({ id: nid('m'), role: 'user', text: body.text, at: new Date().toISOString() });
    if (c.title === '새 대화') c.title = /디스크|disk/i.test(body.text) ? 'node-b 디스크 정리' : body.text.slice(0, 24);
    c.updatedAt = new Date().toISOString();
    const disk = /디스크|disk/i.test(body.text);
    const silence = !disk && /묵음|silence|grafana/i.test(body.text);
    const tools: AiTool[] = disk ? DISK_TOOLS : silence ? MCP_TOOLS : [{ name: 'tool_search', kind: 'find', summary: '지금 화면과 관련된 읽기 도구', args: { query: body.text.slice(0, 40) } }, { name: 'screen.read', kind: 'read', summary: `${body.context.screen} 요약`, args: { screen: body.context.screen } }];
    for (const t of tools) {
      await wait(350, signal);
      onEvent({ type: 'tool', tool: t });
    }
    const text = disk ? DISK_TEXT : silence ? MCP_TEXT : `지금 보시는 ‘${body.context.screen}’ 화면을 읽었습니다. 바꾸는 작업이 필요하면 승인 카드로 제안드릴게요. (목업 답입니다)`;
    let sent = '';
    for (const w of text.split(/(?<= )/)) {
      await wait(30, signal);
      sent += w;
      onEvent({ type: 'delta', text: w });
    }
    const ps = disk ? diskProposals(c.id, false, owner) : silence ? [mcpProposal(c.id)] : [];
    proposals.push(...ps);
    for (const p of ps) {
      await wait(200, signal);
      onEvent({ type: 'proposal', proposal: structuredClone(p) });
    }
    const mid = nid('m');
    c.messages.push({ id: mid, role: 'assistant', text: sent, at: new Date().toISOString(), model: c.model, tools, proposals: ps.map((p) => p.id) });
    onEvent({ type: 'done', messageId: mid, usage: { inputTokens: 1200, cacheReadTokens: 9800 } });
  } finally {
    (c as Conv & { busy?: boolean }).busy = false;
  }
}
