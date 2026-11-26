// SPDX-License-Identifier: Apache-2.0

// 서버 셸. 권한·정책 판단은 mydcd가 하고 웹 데몬은 PTY를 중계만 한다.
// 키 입력과 화면 내용은 어디에도 저장하지 않는다(브라우저 메모리의 터미널 화면뿐).
import { ApiError, api } from './client';
import { fromB64, toB64 } from './streams';

export type ShellMode = 'inherit' | 'on' | 'off';
export interface NodeShellNode {
  node: string;
  shell: ShellMode;
  sudo: boolean;
  /** 실제로 열 수 있는지(정책 반영) */
  enabled: boolean;
  ready: boolean;
  notReady?: string;
}
export interface NodeShellGrant {
  user: string;
  nodes: string[];
}
export interface NodeShellPolicy {
  enabled: boolean;
  maxSessions: number;
  idleSeconds: number;
  account: string;
  nodes: NodeShellNode[];
  grants: NodeShellGrant[];
  revision: number;
}
/** 세션 상태(docs/reference/node-shell.md). closed는 목록에서 뺀다 */
export type ShellSessionState = 'queued' | 'opened' | 'closing' | 'closed';
export interface NodeShellSession {
  /** "shell-" + opId */
  sessionId: string;
  state: ShellSessionState;
  createdAt?: string;
  user: string;
  username: string;
  node: string;
  account: string;
  sudo: boolean;
  /** 열리기 전(queued)에는 createdAt으로 채운다 */
  openedAt: string;
  closedAt?: string;
  lastActivity: string;
  bytesIn: number;
  bytesOut: number;
}

const arr = <T>(x: T[] | null | undefined): T[] => x ?? [];

export const nodeShellPolicy = async (signal?: AbortSignal): Promise<NodeShellPolicy> => {
  const r = await api.get<NodeShellPolicy>('/node-shell', signal);
  return { ...r, nodes: arr(r.nodes), grants: arr(r.grants).map((g) => ({ ...g, nodes: arr(g.nodes) })) };
};
type RawSession = Omit<NodeShellSession, 'openedAt' | 'state' | 'lastActivity'> & { openedAt?: string; lastActivity?: string; state?: ShellSessionState };
/** 닫히지 않은 세션 전부(queued·opened·closing). `active=1`이면 데몬이 끝까지 읽어 한 번에 준다.
 * 예전 데몬처럼 next가 오면 이어 읽는다(최대 50쪽). */
export const nodeShellSessions = async (signal?: AbortSignal): Promise<NodeShellSession[]> => {
  const out: NodeShellSession[] = [];
  let after: string | undefined;
  for (let page = 0; page < 50; page++) {
    const r = await api.get<{ items: RawSession[] | null; next?: string; partial?: boolean }>(`/node-shell/sessions?${new URLSearchParams({ active: '1', ...(after ? { after } : {}) })}`, signal);
    for (const x of arr(r.items)) {
      const state = x.state ?? 'opened';
      const openedAt = x.openedAt ?? x.createdAt ?? x.lastActivity ?? new Date().toISOString();
      if (state !== 'closed') out.push({ ...x, state, openedAt, lastActivity: x.lastActivity ?? openedAt, bytesIn: x.bytesIn ?? 0, bytesOut: x.bytesOut ?? 0 });
    }
    if (!r.next || r.next === after) break;
    after = r.next;
  }
  return out;
};
/** 닫기를 보낼 수 있는 상태 */
export const canCloseSession = (s: NodeShellSession) => s.state === 'queued' || s.state === 'opened';
export const SESSION_STATE_KO: Record<ShellSessionState, string> = { queued: '여는 중', opened: '열림', closing: '닫는 중', closed: '닫힘' };

export const NODE_SHELL_PATH = '/node-shell';
export const nodeShellNodePath = (node: string) => `/node-shell/nodes/${encodeURIComponent(node)}`;
export const nodeShellGrantPath = (user: string) => `/node-shell/grants/${encodeURIComponent(user)}`;
export const nodeShellClosePath = (id: string) => `/node-shell/sessions/${encodeURIComponent(id)}/close`;
export const nodeShellOpenPath = (node: string, p: { opId: string; cols: number; rows: number }) =>
  `/nodes/${encodeURIComponent(node)}/shell?${new URLSearchParams({ opId: p.opId, cols: String(p.cols), rows: String(p.rows) })}`;

/** 서버별 셸 설정 이름 */
export const SHELL_MODE_KO: Record<ShellMode, string> = { inherit: '정책 따르기', on: '이 서버만 켜기', off: '이 서버만 끄기' };

/** 셸 소켓 이벤트. 'refused'는 소켓이 열리기 전에 끊긴 것(이유는 HTTP라 브라우저가 못 읽는다) */
export type ShellEvent =
  | { type: 'session'; session: NodeShellSession }
  | { type: 'stdout'; bytes: Uint8Array }
  /** closedBy는 REQ-68 뒤 다른 사람이 닫았을 때 온다 */
  | { type: 'end'; code: number; reason: 'exit' | 'idle' | 'closed' | string; closedBy?: { user: string; username: string } }
  | { type: 'error'; code: string }
  /** 셸이 열리기 전 거절. code가 없으면 소켓 전 HTTP 거절이라 이유를 모른다(Origin 등) */
  | { type: 'refused'; code?: string; message?: string };

export interface ShellHandle {
  stdin(data: string): void;
  resize(cols: number, rows: number): void;
  /** 서버에 세션을 닫으라고 한다 */
  close(): void;
}

/** 셸을 연다. opId는 셸마다 새로 만든다(같은 opId는 409 shell-used). 끝(end·error·refused)은 한 번만 알린다. */
export async function openNodeShell(node: string, p: { opId: string; cols: number; rows: number }, onEvent: (e: ShellEvent) => void): Promise<ShellHandle> {
  if (import.meta.env.VITE_API !== 'real') return (await import('./mock/nodeShell')).mockOpenShell(node, p, onEvent);
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/api/v1${nodeShellOpenPath(node, p)}`);
  let started = false;
  let finished = false;
  const finish = (e: ShellEvent) => {
    if (finished) return;
    finished = true;
    onEvent(e);
  };
  const queue: string[] = [];
  const send = (m: object) => {
    const s = JSON.stringify(m);
    if (ws.readyState === WebSocket.OPEN) ws.send(s);
    else if (ws.readyState === WebSocket.CONNECTING) queue.push(s);
  };
  ws.onopen = () => {
    for (const s of queue.splice(0)) ws.send(s);
  };
  ws.onmessage = (m) => {
    let j: { type?: string; data?: string; code?: unknown; message?: string; reason?: string; session?: NodeShellSession; closedBy?: { user: string; username: string } };
    try {
      j = JSON.parse(String(m.data));
    } catch {
      return;
    }
    if (j.type === 'session' && j.session) {
      started = true;
      onEvent({ type: 'session', session: j.session });
    }
    else if (j.type === 'stdout') onEvent({ type: 'stdout', bytes: fromB64(j.data) });
    else if (j.type === 'end') finish({ type: 'end', code: Number(j.code ?? 0), reason: j.reason ?? 'exit', closedBy: j.closedBy });
    // 세션 전에 온 error는 거절이다(데몬 #322: {type:"error", status, code, message} 뒤 닫음)
    else if (j.type === 'error') finish(started ? { type: 'error', code: String(j.code ?? 'disconnected') } : { type: 'refused', code: String(j.code ?? ''), message: j.message });
  };
  ws.onerror = () => finish(started ? { type: 'error', code: 'disconnected' } : { type: 'refused' });
  ws.onclose = () => finish(started ? { type: 'error', code: 'disconnected' } : { type: 'refused' });
  const enc = new TextEncoder();
  return {
    stdin: (d) => send({ type: 'stdin', data: toB64(enc.encode(d)) }),
    resize: (cols, rows) => send({ type: 'resize', cols, rows }),
    close: () => {
      send({ type: 'close' });
      // 서버가 end를 보내지 않아도 잠시 뒤 소켓을 닫는다.
      setTimeout(() => ws.readyState <= WebSocket.OPEN && ws.close(), 3000);
    },
  };
}

export type ShellRefusal = 'forbidden' | 'node-shell-disabled' | 'node-shell-not-ready' | 'limit' | 'node-unreachable';

/**
 * 거절 코드 없이 끊겼을 때(소켓 전 HTTP 거절: Origin 등, 또는 예전 데몬) 이유를 짐작한다. 데몬은 거절을 HTTP 상태로 주지만 브라우저 WebSocket은
 * 그 상태를 읽지 못한다. 지금 정책과 내 세션 수로 맞춰 보고, 어느 것도 아니면 서버 응답 없음으로 본다.
 */
export async function explainRefusal(node: string, me: string): Promise<{ code: ShellRefusal; notReady?: string; max?: number }> {
  let p: NodeShellPolicy;
  try {
    p = await nodeShellPolicy();
  } catch (e) {
    return { code: e instanceof ApiError && e.status === 403 ? 'forbidden' : 'node-unreachable' };
  }
  const n = p.nodes.find((x) => x.node === node);
  if (!n) return { code: 'forbidden' };
  if (!n.enabled) return { code: 'node-shell-disabled' };
  if (!n.ready) return { code: 'node-shell-not-ready', notReady: n.notReady };
  try {
    const mine = (await nodeShellSessions()).filter((s) => s.user === me && s.node === node).length;
    if (mine >= p.maxSessions) return { code: 'limit', max: p.maxSessions };
  } catch {
    /* 세션 목록을 못 읽으면 아래로 */
  }
  return { code: 'node-unreachable' };
}

/** mydcd NotReady 코드(docs/reference/node-shell.md '노드의 로컬 준비')를 사람 말로. 모르는 값은 그대로 */
const NOT_READY_KO: Record<string, string> = {
  'account-unavailable': '전용 계정(mydc-shell)을 준비하지 못했습니다',
  'key-unavailable': '전용 계정의 로그인 키를 준비하지 못했습니다',
  'ssh-unavailable': '이 서버의 SSH(127.0.0.1:22)에 접속하지 못했습니다',
  'sudo-unavailable': 'sudo 설정을 반영하지 못했습니다',
};
export const notReadyText = (code?: string) => (code ? NOT_READY_KO[code] ?? code : undefined);
