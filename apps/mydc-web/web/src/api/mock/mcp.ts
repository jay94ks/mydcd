// SPDX-License-Identifier: Apache-2.0

// MCP 연동 목업 (UI-B9). 캔버스의 grafana·slack·sentry·runbook-wiki로 채운다. 토큰은 끝 4자리만 남긴다.
import type { RawResponse } from '../client';
import type { McpServer, McpTool, ToolPatch } from '../mcp';
import { autoMissing } from '../mcp';

interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, query: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string, extra?: Record<string, unknown>) => RawResponse;
  admin: () => void;
}

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const tool = (name: string, description: string, read: boolean, p: Partial<McpTool> = {}): McpTool => ({ name, description, readOnlyHint: read, kind: read ? 'read' : 'change', coordinator: true, incident: 'off', tenants: 'all', new: false, ...p });
const filler = (n: number, read: boolean) => Array.from({ length: n }, (_, i) => tool(`${read ? 'get' : 'set'}_item_${i + 1}`, read ? '항목 읽기' : '항목 바꾸기', read, { coordinator: false }));

const servers: McpServer[] = [
  {
    name: 'grafana',
    url: 'https://grafana.internal/api/mcp',
    auth: { kind: 'bearer', set: true, last4: '9f2a' },
    state: 'ok',
    checkedAt: ago(60),
    catalogRevision: 3,
    info: { serverName: 'grafana-mcp', version: '0.9' },
    enabled: true,
    usedBy: ['app/shop/php-shop'],
    users: { systemAdmins: true, tenants: [] },
    revision: 5,
    tools: [
      tool('query_prometheus', 'PromQL 질의 결과', true, { incident: 'diagnose', args: [{ name: 'query', type: 'string', required: true }, { name: 'range', type: 'string' }] }),
      tool('query_loki_logs', 'Loki 로그 검색', true, { incident: 'diagnose', hint: '질의 범위 최근 1시간', args: [{ name: 'query', type: 'string', required: true }, { name: 'since', type: 'string' }] }),
      tool('search_dashboards', '대시보드 찾기', true, { args: [{ name: 'query', type: 'string' }] }),
      tool('list_alert_rules', '알림 규칙 목록', true, { incident: 'diagnose' }),
      tool('create_silence', '알림 묵음 만들기', false, {
        incident: 'propose-auto',
        tenants: ['shop'],
        hint: '알림 폭주를 막을 때만. 원인 해결로 보지 말 것',
        args: [
          { name: 'duration', type: 'string', required: true },
          { name: 'matchers', type: 'array', required: true },
          { name: 'comment', type: 'string' },
          { name: 'createdBy', type: 'string' },
        ],
        auto: { floor: 'low', inputs: { duration: { kind: 'max', value: '60m' }, matchers: { kind: 'incident', value: 'app' }, comment: { kind: 'template', value: 'MyDC 사건 {id} 자동 묵음' }, createdBy: { kind: 'fixed', value: 'mydc-autofix' } }, perIncident: 1, perDay: 10, revert: { tool: 'delete_silence' }, signals: ['5xx 급증', '지연 증가'] },
      }),
      tool('update_dashboard', '대시보드 고치기', false, { coordinator: false }),
      tool('delete_silence', '알림 묵음 지우기', false, { coordinator: true }),
      ...filler(6, true),
      ...filler(0, false),
    ],
  },
  {
    name: 'slack',
    url: 'https://mcp.slack.com/mcp',
    auth: { kind: 'bearer', set: true, last4: 'x01b' },
    state: 'ok',
    checkedAt: ago(120),
    catalogRevision: 1,
    info: { serverName: 'slack-mcp', version: '1.2' },
    enabled: true,
    usedBy: ['app/shop/php-shop', 'cluster'],
    users: { systemAdmins: true, tenants: ['shop', 'internal'] },
    revision: 2,
    tools: [tool('post_message', '채널에 메시지 보내기', false, { kind: 'notify', incident: 'notify', args: [{ name: 'channel', type: 'string', required: true }, { name: 'text', type: 'string', required: true }] }), tool('list_channels', '채널 목록', true), tool('read_thread', '스레드 읽기', true), tool('search_messages', '메시지 찾기', true), ...filler(5, false).map((t) => ({ ...t, coordinator: false }))],
  },
  {
    name: 'sentry',
    url: 'https://mcp.sentry.dev/mcp',
    auth: { kind: 'bearer', set: true, last4: '77aa' },
    state: 'ok',
    checkedAt: ago(300),
    catalogRevision: 2,
    enabled: true,
    usedBy: ['app/shop/php-shop'],
    users: { systemAdmins: true, tenants: ['shop'] },
    revision: 1,
    tools: [tool('search_issues', '이슈 찾기', true, { incident: 'diagnose' }), tool('get_release', '릴리스 정보', true, { incident: 'diagnose' }), ...filler(9, true)],
  },
  {
    name: 'runbook-wiki',
    url: 'https://wiki.corp/mcp',
    auth: { kind: 'none', set: false },
    state: 'error',
    error: '503 Service Unavailable',
    checkedAt: ago(180),
    catalogRevision: 1,
    enabled: true,
    usedBy: [],
    users: { systemAdmins: true, tenants: [] },
    revision: 1,
    tools: [tool('search_pages', '문서 찾기', true), tool('get_page', '문서 읽기', true)],
  },
];

/** 지침 화면 '쓸 바깥 도구' 고르기 목록 */
export function mcpChoices(tenant?: string) {
  return servers
    .filter((s) => !tenant || s.users.tenants.includes(tenant))
    .map((s) => {
      const r = s.tools.filter((t) => t.kind === 'read').length;
      return { name: s.name, summary: `도구 ${s.tools.length}개 (읽기 ${r} · 바꾸기 ${s.tools.length - r})`, state: s.enabled === false ? ('off' as const) : s.state };
    });
}

const pendingOauth = new Map<string, { url: string; at: number }>();
function newServer(name: string, url: string, auth: { kind?: string; token?: string }): McpServer {
  return {
    name,
    url,
    auth: auth.kind === 'bearer' ? { kind: 'bearer', set: true, last4: auth.token!.slice(-4) } : auth.kind === 'oauth' ? { kind: 'oauth', set: true, expiresAt: new Date(Date.now() + 7 * 86400_000).toISOString() } : { kind: 'none', set: false },
    state: 'ok',
    checkedAt: new Date().toISOString(),
    catalogRevision: 1,
    info: { serverName: `${name}-mcp`, version: '1.0' },
    enabled: true,
    usedBy: [],
    users: { systemAdmins: true, tenants: [] },
    revision: 1,
    tools: [tool('query', '질의 결과', true, { coordinator: false }), tool('search', '찾기', true, { coordinator: false }), tool('create_note', '메모 만들기', false, { coordinator: false })],
  };
}

export function registerMcp(ctx: Ctx) {
  const { on, ok, err } = ctx;
  const find = (n: string) => servers.find((s) => s.name === n);
  on('GET', '/system/mcp', () => {
    ctx.admin();
    return ok({ servers });
  });
  on('POST', '/system/mcp', (_m, b) => {
    ctx.admin();
    const name = String(b.name ?? '');
    const url = String(b.url ?? '');
    const auth = (b.auth ?? {}) as { kind?: string; token?: string };
    if (!/^[a-z][a-z0-9-]{0,30}$/.test(name)) return err(422, 'invalid', 'name');
    if (find(name)) return err(409, 'exists', '같은 이름의 MCP 서버가 있습니다.');
    if (!/^https:\/\//.test(url)) return err(422, 'invalid', 'https 주소만 받습니다.');
    if (/^https:\/\/(localhost|127\.|10\.|192\.168\.|169\.254\.)/.test(url)) return err(422, 'invalid', '사설·루프백·링크 로컬 주소는 받지 않습니다.');
    if (auth.kind === 'oauth' && auth.token) return err(422, 'invalid', 'auth.token: not with oauth');
    if (auth.kind === 'oauth') {
      // 목업: 로그인 창 없이 3초 뒤 로그인을 마친 것으로 친다. 주소에 'deny'가 있으면 거절로 끝난다.
      pendingOauth.set(name, { url, at: Date.now() });
      return ok({ name, loginUrl: `${url.replace(/\/+$/, '')}/authorize?client_id=mydc-web&state=mock`, expiresAt: new Date(Date.now() + 10 * 60_000).toISOString() }, 202);
    }
    if (auth.kind === 'bearer' && (!auth.token || auth.token === 'bad')) return err(422, 'mcp-connect', '연결 시험에 실패했습니다.', { error: '401 Unauthorized' });
    if (/fail/.test(url)) return err(422, 'mcp-connect', '연결 시험에 실패했습니다.', { error: '연결 시간 초과 (15초)' });
    const s = newServer(name, url, auth);
    servers.push(s);
    return ok(s, 201);
  });
  on('GET', '/system/mcp/:n/oauth', (mm) => {
    ctx.admin();
    const p = pendingOauth.get(mm[0]);
    const s = find(mm[0]);
    if (!p) return s?.auth.kind === 'oauth' ? ok({ state: 'connected', server: s }) : err(404, 'not-found', '진행 중인 로그인이 없습니다.');
    if (Date.now() - p.at < 3000) return ok({ state: 'login' });
    pendingOauth.delete(mm[0]);
    if (/deny/.test(p.url)) return ok({ state: 'failed', error: '로그인 화면에서 거절했습니다 (access_denied)' });
    if (s) {
      s.auth = { kind: 'oauth', set: true, expiresAt: new Date(Date.now() + 7 * 86400_000).toISOString() };
      s.revision++;
      return ok({ state: 'connected', server: s });
    }
    const n = newServer(mm[0], p.url, { kind: 'oauth' });
    servers.push(n);
    return ok({ state: 'connected', server: n });
  });
  on('POST', '/system/mcp/:n/oauth/login', (mm) => {
    ctx.admin();
    const s = find(mm[0]);
    if (!s) return err(404, 'not-found', '없는 MCP 서버입니다.');
    if (s.auth.kind !== 'oauth') return err(422, 'invalid', 'OAuth로 연결한 서버가 아닙니다.');
    pendingOauth.set(s.name, { url: s.url, at: Date.now() });
    return ok({ name: s.name, loginUrl: `${s.url.replace(/\/+$/, '')}/authorize?client_id=mydc-web&state=mock`, expiresAt: new Date(Date.now() + 10 * 60_000).toISOString() });
  });
  on('PUT', '/system/mcp/:n', (mm, b) => {
    ctx.admin();
    const s = find(mm[0]);
    if (!s) return err(404, 'not-found', '없는 MCP 서버입니다.');
    if (b.revision !== s.revision) return err(409, 'stale', '그사이 다른 사람이 바꿨습니다.');
    const patch = (b.tools ?? {}) as Record<string, ToolPatch>;
    const next = s.tools.map((t) => ({ ...t }));
    for (const [n, p] of Object.entries(patch)) {
      const t = next.find((x) => x.name === n);
      if (!t) return err(422, 'invalid', `tools.${n}`);
      if (p.kind && t.kind !== 'read' && p.kind === 'read') return err(422, 'kind', '바꾸기 도구를 읽기로 내릴 수 없습니다.');
      if (p.kind && t.readOnlyHint === false && p.kind === 'read') return err(422, 'kind', '서버가 바꾸기로 표시한 도구는 읽기로 둘 수 없습니다.');
      Object.assign(t, p, { new: false });
      if (t.incident === 'diagnose' && t.kind !== 'read') return err(422, 'invalid', '진단에는 읽기 도구만 쓸 수 있습니다.');
      if (t.incident !== 'off' && t.incident !== 'diagnose' && t.kind === 'read') return err(422, 'invalid', '알림·조치 후보에는 바꾸기·알림 도구만 쓸 수 있습니다.');
      const badIn = Object.entries(t.auto?.inputs ?? {}).find(([, r]) => r.kind === 'incident' && !['id', 'tenant', 'app', 'node', 'target', 'signal', 'title'].includes(r.value ?? ''));
      if (badIn) return err(422, 'invalid', `inputs.${badIn[0]}: id|tenant|app|node|target|signal|title`);
      if (t.incident === 'propose-auto') {
        const miss = autoMissing(t, t.auto);
        if (miss.length) return err(422, 'auto-incomplete', `빠진 것: ${miss.join(', ')}`, { missing: miss });
      }
    }
    s.tools = next;
    if (b.url) s.url = String(b.url);
    const auth = b.auth as { kind: 'bearer' | 'none'; token?: string } | undefined;
    if (auth) {
      if (auth.kind === 'bearer' && auth.token === 'bad') return err(422, 'mcp-connect', '연결 시험에 실패했습니다.', { error: '401 Unauthorized' });
      s.auth = auth.kind === 'bearer' ? { kind: 'bearer', set: true, last4: (auth.token ?? s.auth.last4 ?? '').slice(-4) } : { kind: 'none', set: false };
    }
    if (b.users) s.users = b.users as McpServer['users'];
    if (typeof b.enabled === 'boolean') s.enabled = b.enabled;
    s.revision += 1;
    return ok(s);
  });
  on('POST', '/system/mcp/:n/refresh', (mm) => {
    ctx.admin();
    const s = find(mm[0]);
    if (!s) return err(404, 'not-found', '없는 MCP 서버입니다.');
    if (s.name === 'runbook-wiki') {
      s.checkedAt = new Date().toISOString();
      return err(422, 'mcp-connect', '연결 시험에 실패했습니다.', { error: '503 Service Unavailable' });
    }
    s.state = 'ok';
    s.error = undefined;
    s.checkedAt = new Date().toISOString();
    if (s.name === 'grafana' && !s.tools.some((t) => t.name === 'run_query_v2')) {
      s.tools.push(tool('delete_annotation', '주석 지우기', false, { coordinator: false, new: true }), tool('run_query_v2', '질의 결과 (새 형식)', true, { coordinator: false, new: true }));
      s.catalogRevision += 1;
    }
    s.revision += 1;
    return ok(s);
  });
  on('DELETE', '/system/mcp/:n', (mm, b) => {
    ctx.admin();
    const i = servers.findIndex((s) => s.name === mm[0]);
    if (i < 0) return err(404, 'not-found', '없는 MCP 서버입니다.');
    if (b.confirmName !== mm[0]) return err(422, 'confirm-name', '이름이 맞지 않습니다.');
    servers.splice(i, 1);
    return ok(null, 204);
  });
  on('POST', '/system/mcp/:n/tools/:t/test', (mm, b) => {
    ctx.admin();
    const s = find(mm[0]);
    const t = s?.tools.find((x) => x.name === mm[1]);
    if (!t) return err(404, 'not-found', '없는 도구입니다.');
    const inc = String(b.incident ?? '');
    if (!inc) return err(422, 'invalid', 'incident');
    const auto = t.incident === 'propose-auto' && t.auto;
    return ok({
      steps: [
        { label: `${inc} 불러옴` },
        { label: '진단 A', detail: `${t.name} 제안${auto && t.auto?.inputs.duration ? ' · duration 30분' : ''}` },
        { label: '영향 평가 B', detail: `낮음 (하한 ${t.auto?.floor === 'medium' ? '보통' : t.auto?.floor === 'high' ? '높음' : '낮음'})` },
      ],
      result: auto ? '자동 실행했을 것 · 실제 호출 안 함' : t.incident === 'propose-approve' ? '승인 요청을 만들었을 것 · 실제 호출 안 함' : '이 도구는 쓰지 않았을 것',
    });
  });
}
