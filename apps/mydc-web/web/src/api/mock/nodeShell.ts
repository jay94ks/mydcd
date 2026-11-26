// SPDX-License-Identifier: Apache-2.0

// 서버 셸 목업. 고정 자료: 클러스터 정책 켜짐, node-b sudo 허용, node-c 이 서버만 끄기(준비 안 됨),
// bob은 node-b 셸 권한과 열린 세션 하나. PTY는 몇 가지 명령만 아는 줄 셸이다.
// 실제처럼 소켓이 열리기 전 거절은 이유 없이 끊는다(화면이 정책을 다시 읽어 이유를 짐작한다).
import type { RawResponse } from '../client';
import type { NodeShellNode, NodeShellSession, ShellEvent, ShellHandle, ShellMode } from '../nodeShell';
import { mockControls, currentUser } from './router';
import * as fx from './fixtures';

type Applied = { code: number; errorCode?: string } | void;
interface Ctx {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>, q: URLSearchParams) => RawResponse) => void;
  ok: (json: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string) => RawResponse;
  user: () => { id: string; username: string; systemAdmin: boolean };
  submit: (user: fx.MockUser, body: Record<string, unknown>, action: string, apply: () => Applied) => RawResponse;
}

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const state = {
  policy: { enabled: true, maxSessions: 4, idleSeconds: 1800, account: 'mydc-shell', revision: 3 },
  nodes: { 'node-b': { shell: 'inherit' as ShellMode, sudo: true }, 'node-c': { shell: 'off' as ShellMode, sudo: false } } as Record<string, { shell: ShellMode; sudo: boolean }>,
  notReady: { 'node-c': 'sudo-unavailable' } as Record<string, string>,
  grants: { 'u-bob': ['node-b'] } as Record<string, string[]>,
  sessions: [
    { sessionId: 'shell-6d02c1a4-0f3e-4b7a-9c11-2e5f8a90b7d3', state: 'opened', user: 'u-bob', username: 'bob', node: 'node-b', account: 'mydc-shell', sudo: true, createdAt: ago(3841), openedAt: ago(3840), lastActivity: ago(720), bytesIn: 120_000, bytesOut: 9_700_000 },
  ] as NodeShellSession[],
  live: new Map<string, (reason: string, by?: { user: string; username: string }) => void>(),
};

/** 목업 조작(스모크 시험): 세션을 서버 쪽에서 끝낸다 */
export const mockShell = {
  end: (sessionId: string, reason: 'idle' | 'closed' | 'exit' | 'policy' = 'idle') => state.live.get(sessionId)?.(reason),
  sessions: () => state.sessions,
};

function nodeView(node: string): NodeShellNode {
  const x = state.nodes[node] ?? { shell: 'inherit' as ShellMode, sudo: false };
  const m = fx.members.find((n) => n.id === node);
  const enabled = x.shell === 'on' || (x.shell === 'inherit' && state.policy.enabled);
  const why = !m || m.phase !== 'active' ? 'server is not active' : state.notReady[node];
  return { node, shell: x.shell, sudo: x.sudo, enabled, ready: !why, ...(why ? { notReady: why } : {}) };
}
/** 정책·권한이 바뀌어 mydcd가 닫는 세션 (reason policy, 데몬 #325) */
const closeWhere = (f: (s: NodeShellSession) => boolean) => {
  for (const x of state.sessions.filter(f)) {
    const live = state.live.get(x.sessionId);
    if (live) live('policy');
    else state.sessions = state.sessions.filter((y) => y !== x);
  }
};
const userOf = (id: string) => fx.users.find((u) => u.id === id);
const mayOpen = (u: fx.MockUser, node: string) => u.systemAdmin || (state.grants[u.id] ?? []).includes(node);

export function registerNodeShell({ on, ok, err, user, submit }: Ctx) {
  const me = () => userOf(user().id)!;
  const admin = () => {
    if (!user().systemAdmin) throw Object.assign(new Error('denied'), { res: err(403, 'denied', '시스템 관리자 권한이 필요합니다.') });
  };
  const guard = (f: () => RawResponse) => {
    try {
      return f();
    } catch (e) {
      const r = (e as { res?: RawResponse }).res;
      if (r) return r;
      throw e;
    }
  };
  on('GET', '/node-shell', () => {
    const u = me();
    const nodes = fx.members.map((m) => nodeView(m.id)).filter((n) => u.systemAdmin || (state.grants[u.id] ?? []).includes(n.node));
    if (!u.systemAdmin && !nodes.length) return err(403, 'forbidden', '서버 셸 권한이 없습니다.');
    const grants = Object.entries(state.grants)
      .filter(([id]) => u.systemAdmin || id === u.id)
      .map(([id, ns]) => ({ user: id, nodes: ns }));
    return ok({ ...state.policy, nodes, grants });
  });
  on('PUT', '/node-shell', (_m, body) =>
    guard(() => {
      admin();
      const p = state.policy;
      const max = body.maxSessions === undefined ? p.maxSessions : Number(body.maxSessions);
      const idle = body.idleSeconds === undefined ? p.idleSeconds : Number(body.idleSeconds);
      if (!(max >= 1 && max <= 16) || !(idle >= 60 && idle <= 86400)) return err(422, 'invalid', 'maxSessions 1–16, idleSeconds 60–86400');
      const expected = Number(body.expected ?? 0) || p.revision;
      return submit(me(), { ...body, target: 'node-shell' }, 'set-node-shell-policy', () => {
        if (expected !== p.revision) return { code: 1 };
        const was = p.enabled;
        Object.assign(p, { enabled: body.enabled === undefined ? p.enabled : !!body.enabled, maxSessions: max, idleSeconds: idle, revision: p.revision + 1 });
        if (was && !p.enabled) closeWhere((x) => !nodeView(x.node).enabled);
      });
    }),
  );
  on('PUT', '/node-shell/nodes/:node', (m, body) =>
    guard(() => {
      admin();
      const node = m[0];
      if (!['inherit', 'on', 'off'].includes(String(body.shell))) return err(422, 'invalid', 'shell: inherit, on or off');
      const expected = Number(body.expected ?? 0) || state.policy.revision;
      return submit(me(), { ...body, target: `node-shell/${node}` }, 'set-node-shell-node', () => {
        if (expected !== state.policy.revision) return { code: 1 };
        if (!fx.members.some((x) => x.id === node)) return { code: 2, errorCode: 'not-found' };
        state.nodes[node] = { shell: body.shell as ShellMode, sudo: !!body.sudo };
        state.policy.revision++;
        if (!nodeView(node).enabled) closeWhere((x) => x.node === node);
      });
    }),
  );
  on('PUT', '/node-shell/grants/:user', (m, body) =>
    guard(() => {
      admin();
      const nodes = [...new Set((body.nodes as string[] | undefined) ?? [])].sort();
      const expected = Number(body.expected ?? 0) || state.policy.revision;
      return submit(me(), { ...body, target: `node-shell/grant/${m[0]}` }, 'set-node-shell-grant', () => {
        if (expected !== state.policy.revision) return { code: 1 };
        if (!userOf(m[0])) return { code: 2, errorCode: 'not-found' };
        if (nodes.some((n) => !fx.members.some((x) => x.id === n))) return { code: 2, errorCode: 'invalid' };
        if (nodes.length) state.grants[m[0]] = nodes;
        else delete state.grants[m[0]];
        state.policy.revision++;
        if (!userOf(m[0])?.systemAdmin) closeWhere((x) => x.user === m[0] && !nodes.includes(x.node));
      });
    }),
  );
  // 데몬처럼 8개씩, sessionId 순서로 after/next
  on('GET', '/node-shell/sessions', (_m, _b, q) => {
    const u = me();
    const all = state.sessions.filter((s) => u.systemAdmin || s.user === u.id).sort((a, b) => a.sessionId.localeCompare(b.sessionId));
    // active=1이면 닫히지 않은 것을 한 번에(next 없음)
    if (q?.get('active') === '1') return ok({ items: all.filter((s) => s.state !== 'closed'), next: '', total: all.length });
    const after = q?.get('after');
    const rest = after ? all.filter((s) => s.sessionId > after) : all;
    const items = rest.slice(0, 8);
    return ok({ items, total: all.length, ...(rest.length > 8 ? { next: items[items.length - 1].sessionId } : {}) });
  });
  on('POST', '/node-shell/sessions/:id/close', (m, body) => {
    const u = me();
    const s = state.sessions.find((x) => x.sessionId === m[0]);
    return submit(u, { ...body, target: `node-shell/session/${m[0]}` }, 'close-node-shell', () => {
      const cur = state.sessions.find((x) => x.sessionId === m[0]);
      if (!cur) return { code: 2, errorCode: 'not-found' };
      if (!u.systemAdmin && s?.user !== u.id) return { code: 4, errorCode: 'forbidden' };
      const live = state.live.get(m[0]);
      if (live) live('closed', { user: u.id, username: u.username });
      else state.sessions = state.sessions.filter((x) => x.sessionId !== m[0]);
    });
  });
}


export function mockOpenShell(node: string, p: { opId: string; cols: number; rows: number }, onEvent: (e: ShellEvent) => void): ShellHandle {
  const uid = currentUser();
  const u = userOf(uid);
  let finished = false;
  const finish = (e: ShellEvent) => {
    if (finished) return;
    finished = true;
    onEvent(e);
  };
  let sess: NodeShellSession | undefined;
  let line = '';
  let root = false;
  const enc = new TextEncoder();
  const out = (s: string) => {
    if (finished || !sess) return;
    sess.bytesOut += enc.encode(s).length;
    onEvent({ type: 'stdout', bytes: enc.encode(s) });
  };
  const prompt = () => (root ? `root@${node}:~# ` : `\x1b[32mmydc-shell@${node}\x1b[0m:\x1b[34m~\x1b[0m$ `);
  const record = (state: 'running' | 'applied' | 'failed', code?: number, errorCode?: string) => {
    const now = new Date().toISOString();
    const o = fx.ops.find((x) => x.id === p.opId);
    if (o) Object.assign(o, { state, resultFound: state !== 'running', resultCode: code, errorCode, updatedAt: now });
    else fx.ops.unshift({ id: p.opId, requestId: `shell-${p.opId}`, action: 'open-node-shell', target: `node/${node}`, state, resultFound: false, submittedAt: now, updatedAt: now, user: uid, digest: 'open-node-shell' });
  };
  const end = (reason: string, code = 0, closedBy?: { user: string; username: string }) => {
    if (!sess) return;
    state.live.delete(sess.sessionId);
    state.sessions = state.sessions.filter((x) => x !== sess);
    record('applied', code, reason === 'exit' ? undefined : reason);
    finish({ type: 'end', code, reason, ...(closedBy ? { closedBy } : {}) });
  };
  let idle: ReturnType<typeof setTimeout> | undefined;
  const touch = () => {
    if (!sess) return;
    sess.lastActivity = new Date().toISOString();
    clearTimeout(idle);
    idle = setTimeout(() => end('idle', 130), state.policy.idleSeconds * 1000);
  };
  setTimeout(() => {
    if (finished) return;
    const n = nodeView(node);
    // 데몬 #322처럼 거절은 소켓 메시지 {type:error, code} 하나로 온다
    const refuse = (code: string, message: string) => finish({ type: 'refused', code, message });
    if (fx.ops.some((o) => o.id === p.opId)) return refuse('shell-used', 'this opId already opened a shell; use a new opId');
    if (!u || !mayOpen(u, node)) return refuse('forbidden', 'no NodeShell for this server');
    if (!n.enabled) return refuse('node-shell-disabled', 'shell is off on this server');
    if (!n.ready) return refuse('node-shell-not-ready', n.notReady ?? '');
    if (state.sessions.filter((s) => s.user === uid && s.node === node).length >= state.policy.maxSessions) return refuse('limit', `at most ${state.policy.maxSessions} sessions`);
    const now = new Date().toISOString();
    sess = { sessionId: `shell-${p.opId}`, state: 'opened', createdAt: now, user: uid, username: u.username, node, account: state.policy.account, sudo: n.sudo, openedAt: now, lastActivity: now, bytesIn: 0, bytesOut: 0 };
    state.sessions.push(sess);
    state.live.set(sess.sessionId, (reason, by) => end(reason, reason === 'exit' ? 0 : 130, by));
    record('running');
    onEvent({ type: 'session', session: { ...sess } });
    touch();
    out(`\x1b[90mMyDC 세션 ${sess.sessionId} · ${node} · 계정 ${sess.account} · sudo ${n.sudo ? '허용' : '막기'} · ${u.username}가 열음\x1b[0m\r\n`);
    out(`\x1b[90mWelcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-49-generic x86_64) · 목업 셸: whoami, id, hostname, df -h, sudo -i, exit\x1b[0m\r\n`);
    out(prompt());
  }, mockControls.latencyMs);
  const run = (cmd: string): string => {
    const c = cmd.trim();
    if (!c) return '';
    if (c === 'exit') {
      if (root) {
        root = false;
        return 'logout\r\n';
      }
      setTimeout(() => end('exit', 0));
      return 'logout\r\n';
    }
    if (c === 'whoami') return `${root ? 'root' : 'mydc-shell'}\r\n`;
    if (c === 'id') return root ? 'uid=0(root) gid=0(root) groups=0(root)\r\n' : 'uid=998(mydc-shell) gid=998(mydc-shell) groups=998(mydc-shell)\r\n';
    if (c === 'hostname') return `${node}\r\n`;
    if (c.startsWith('df')) return 'Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/nvme0n1p3  900G  120G  780G  14% /srv/mydc\r\n';
    if (c.startsWith('echo ')) return c.slice(5) + '\r\n';
    if (c === 'sudo -i' || c === 'sudo su') {
      if (!sess?.sudo) return 'mydc-shell is not in the sudoers file.\r\n';
      root = true;
      return '';
    }
    return `${c.split(/\s+/)[0]}: command not found\r\n`;
  };
  return {
    stdin: (d) => {
      if (!sess || finished) return;
      sess.bytesIn += enc.encode(d).length;
      touch();
      for (const ch of d) {
        if (ch === '\r') {
          out('\r\n');
          const r = run(line);
          line = '';
          if (r) out(r);
          if (!finished) out(prompt());
        } else if (ch === '\x7f') {
          if (line) {
            line = line.slice(0, -1);
            out('\b \b');
          }
        } else if (ch === '\x03') {
          line = '';
          out('^C\r\n' + prompt());
        } else if (ch >= ' ') {
          line += ch;
          out(ch);
        }
      }
    },
    resize: () => undefined,
    close: () => {
      clearTimeout(idle);
      if (sess) end('closed', 130);
      else finish({ type: 'end', code: 130, reason: 'closed' });
    },
  };
}
