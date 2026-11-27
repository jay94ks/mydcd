// SPDX-License-Identifier: Apache-2.0

/**
 * 컨테이너 스트림(purpose15): 로그 따라가기·top/stats 감시(SSE)와 터미널(WebSocket).
 * 계약: docs/reference/web-api.md "컨테이너 스트림".
 *
 * SSE는 EventSource 대신 fetch로 읽는다. 다시 잇기 요청에 X-SFC-Background 헤더를 붙여야 하고
 * (EventSource는 헤더를 못 붙임), 401·403 같은 HTTP 오류를 그대로 받아야 해서다.
 */
import { ApiError, apiEvents, q, enc } from './client';
import type { ApiErrorBody } from './types';

export type StreamKind = 'logs' | 'top' | 'stats';

export interface StreamTargetView {
  tenant: string;
  app: string;
  service: string;
  node: string;
  instance: string;
  generation: number;
  revision: number;
  nativeID?: string;
  startedAt?: string;
}
export interface StatsView {
  sampleAt: string;
  cpuPercent?: number;
  cpuStatus?: string;
  memoryBytes?: number;
  memoryWorkingSetBytes?: number;
  memoryLimitBytes?: number;
  networkRXBytes?: number;
  networkTXBytes?: number;
  blockReadBytes?: number;
  blockWriteBytes?: number;
  pids?: number;
}
export interface SampleView {
  kind: StreamKind;
  observedAt: string;
  tty: boolean;
  truncated: boolean;
  titles?: string[];
  processes?: string[][];
  stats?: StatsView;
}
export interface ExecReceiptView {
  execID?: string;
  phase: 'creating' | 'created' | 'start-sent' | 'started' | 'finished' | string;
  stdinClosed?: boolean;
  outputEnded?: boolean;
  detached?: boolean;
  exitCode?: number;
}

export type StreamEvent =
  | { type: 'target'; target: StreamTargetView }
  | { type: 'stdout' | 'stderr'; sequence: number; text: string; bytes: Uint8Array }
  | { type: 'sample'; sample: SampleView }
  | { type: 'receipt'; receipt: ExecReceiptView }
  | { type: 'output-eof' }
  | { type: 'end' }
  | { type: 'error'; code: string };

interface RawRecord {
  type: string;
  sequence?: number;
  data?: string;
  text?: string;
  sample?: SampleView;
  receipt?: ExecReceiptView;
  code?: string;
}

export const fromB64 = (s?: string) => (s ? Uint8Array.from(atob(s), (c) => c.charCodeAt(0)) : new Uint8Array());
export const toB64 = (u: Uint8Array) => {
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
};
const decoder = new TextDecoder();

/** 서버 레코드(JSON)를 화면 이벤트로 */
export function toStreamEvent(name: string, raw: unknown): StreamEvent | undefined {
  if (name === 'target') return { type: 'target', target: raw as StreamTargetView };
  const r = (raw ?? {}) as RawRecord;
  const type = r.type || name;
  switch (type) {
    case 'stdout':
    case 'stderr': {
      const bytes = fromB64(r.data);
      return { type, sequence: r.sequence ?? 0, bytes, text: r.text ?? decoder.decode(bytes) };
    }
    case 'sample':
      return r.sample ? { type: 'sample', sample: r.sample } : undefined;
    case 'receipt':
      return r.receipt ? { type: 'receipt', receipt: r.receipt } : undefined;
    case 'output-eof':
      return { type: 'output-eof' };
    case 'end':
      return { type: 'end' };
    case 'error':
      return { type: 'error', code: r.code || 'disconnected' };
  }
  return undefined;
}

/** SSE 본문을 한 덩어리씩 넣으면 완성된 이벤트를 돌려준다. 주석(": ping")은 버린다. */
export function sseParser() {
  let buf = '';
  return (chunk: string): { event: string; data: string }[] => {
    buf += chunk.replace(/\r\n?/g, '\n');
    const out: { event: string; data: string }[] = [];
    let i: number;
    while ((i = buf.indexOf('\n\n')) >= 0) {
      const block = buf.slice(0, i);
      buf = buf.slice(i + 2);
      let event = 'message';
      const data: string[] = [];
      for (const line of block.split('\n')) {
        if (!line || line.startsWith(':')) continue;
        const c = line.indexOf(':');
        const field = c < 0 ? line : line.slice(0, c);
        const value = c < 0 ? '' : line.slice(c + 1).replace(/^ /, '');
        if (field === 'event') event = value;
        else if (field === 'data') data.push(value);
      }
      if (data.length) out.push({ event, data: data.join('\n') });
    }
    return out;
  };
}

/** 스트림 대상: 앱 컨테이너(app·service·instance) 또는 단독 컨테이너(standalone). TaskView가 그대로 맞는다. */
export interface StreamScope {
  tenant: string;
  app: string;
  standalone?: string;
}
/** 앱이면 /t/{t}/apps/{app}, 단독 컨테이너면 /t/{t}/standalone/{name} */
export const scopeBase = (s: StreamScope) => (s.standalone ? `/t/${enc(s.tenant)}/standalone/${enc(s.standalone)}` : `/t/${enc(s.tenant)}/apps/${enc(s.app)}`);

export interface FollowParams {
  kind: StreamKind;
  service: string;
  instance: string;
  tail?: number;
  stdout?: boolean;
  stderr?: boolean;
  /** top/stats 간격(초) */
  intervalSec?: number;
}

/**
 * 로그 따라가기·감시를 연다. target-changed면 같은 조건으로 스스로 다시 연다(사람의 활동이 아님).
 * 반환값을 부르면 닫는다. 끝(end·error)은 onEvent로 한 번 알린다.
 */
export function follow(scope: StreamScope, p: FollowParams, onEvent: (e: StreamEvent) => void): () => void {
  let closed = false;
  let ctl: AbortController | undefined;
  const sa = !!scope.standalone;
  const path = `${scopeBase(scope)}/stream${q({
    kind: p.kind,
    service: sa ? undefined : p.service,
    instance: sa ? undefined : p.instance,
    tail: p.kind === 'logs' ? p.tail : undefined,
    stdout: p.kind === 'logs' && p.stdout === false ? 0 : undefined,
    stderr: p.kind === 'logs' && p.stderr === false ? 0 : undefined,
    interval: p.kind !== 'logs' && p.intervalSec ? `${p.intervalSec}s` : undefined,
  })}`;
  const open = async (background: boolean) => {
    ctl = new AbortController();
    const signal = ctl.signal;
    let reopen = false;
    try {
      // import.meta.env로 직접 분기해야 운영 빌드에서 목업 묶음이 빠진다(API_MODE 상수는 모듈을 넘으면 접히지 않음).
      const events = import.meta.env.VITE_API !== 'real' ? (await import('./mock/streams')).mockFollow(scope, p, signal) : realSse(path, background, signal);
      for await (const e of events) {
        if (closed) return;
        if (e.type === 'error' && e.code === 'target-changed') {
          reopen = true;
          break;
        }
        onEvent(e);
        if (e.type === 'end' || e.type === 'error') return;
      }
      if (!reopen && !closed) onEvent({ type: 'error', code: 'closed' });
    } catch (e) {
      if (closed || (e as Error).name === 'AbortError') return;
      onEvent({ type: 'error', code: e instanceof ApiError ? e.code : 'disconnected' });
      return;
    }
    if (reopen && !closed) void open(true);
  };
  void open(false);
  return () => {
    closed = true;
    ctl?.abort();
  };
}

async function* realSse(path: string, background: boolean, signal: AbortSignal): AsyncGenerator<StreamEvent> {
  const headers: Record<string, string> = { Accept: 'text/event-stream' };
  if (background) headers['X-SFC-Background'] = '1';
  let res: Response;
  try {
    res = await fetch('/api/v1' + path, { headers, credentials: 'same-origin', signal, cache: 'no-store' });
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e;
    throw new ApiError(0, { code: 'transport', message: '웹 서버에 연결하지 못했습니다.' });
  }
  if (!res.ok || !res.body) {
    let body: ApiErrorBody = { code: 'transport', message: `HTTP ${res.status}` };
    try {
      body = ((await res.json()) as { error?: ApiErrorBody }).error ?? body;
    } catch {
      /* 본문 없음 */
    }
    if (res.status === 401 && body.code === 'session-expired') apiEvents.dispatchEvent(new Event('session-expired'));
    throw new ApiError(res.status, body);
  }
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  const parse = sseParser();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    for (const m of parse(value)) {
      let json: unknown;
      try {
        json = JSON.parse(m.data);
      } catch {
        continue;
      }
      const e = toStreamEvent(m.event, json);
      if (e) yield e;
    }
  }
}

/** 스트림 끝 코드를 사람 말로 */
export function streamEndText(code: string): string {
  switch (code) {
    case 'closed':
    case 'disconnected':
    case 'transport':
      return '연결이 끊겼습니다.';
    case 'denied':
      return '이 컨테이너를 볼 권한이 없습니다.';
    case 'not-found':
      return '컨테이너를 찾지 못했습니다. 다시 배치됐을 수 있습니다.';
    case 'session-expired':
      return '로그인이 만료됐습니다.';
    case 'unavailable':
      return '서버가 지금 응답하지 않습니다.';
    default:
      return `스트림이 끝났습니다 (${code}).`;
  }
}

// ── 터미널 ──────────────────────────────────────────────

export interface ExecParams {
  opId: string;
  service: string;
  instance: string;
  cmd: string[];
  tty: boolean;
  stdin: boolean;
  rows?: number;
  cols?: number;
}
export interface ExecHandle {
  stdin(data: string | Uint8Array): void;
  closeStdin(): void;
  resize(rows: number, cols: number): void;
  /** 입출력만 끝낸다. 프로세스는 죽이지 않는다 */
  cancel(): void;
  close(): void;
}

export function execPath(scope: StreamScope, p: ExecParams): string {
  const s = new URLSearchParams(scope.standalone ? { opId: p.opId } : { opId: p.opId, service: p.service, instance: p.instance });
  for (const c of p.cmd) s.append('cmd', c);
  if (p.tty) {
    s.set('tty', '1');
    s.set('rows', String(p.rows ?? 24));
    s.set('cols', String(p.cols ?? 80));
  }
  if (p.stdin) s.set('stdin', '1');
  return `${scopeBase(scope)}/exec?${s}`;
}

/** 터미널을 연다. 끝(end·error)은 onEvent로 한 번 알린다. 끊긴 뒤의 결과는 POST /ops/{opId}/result로 본다. */
export async function openExec(scope: StreamScope, p: ExecParams, onEvent: (e: StreamEvent) => void): Promise<ExecHandle> {
  if (import.meta.env.VITE_API !== 'real') return (await import('./mock/streams')).mockExec(scope, p, onEvent);
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/api/v1${execPath(scope, p)}`);
  let finished = false;
  const finish = (e: StreamEvent) => {
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
    let json: unknown;
    try {
      json = JSON.parse(String(m.data));
    } catch {
      return;
    }
    const e = toStreamEvent((json as RawRecord).type, json);
    if (!e) return;
    if (e.type === 'end' || e.type === 'error') finish(e);
    else onEvent(e);
  };
  // 업그레이드 전 거부(403 csrf, 401 등)는 브라우저가 이유를 주지 않는다.
  ws.onerror = () => finish({ type: 'error', code: 'disconnected' });
  ws.onclose = () => finish({ type: 'error', code: 'closed' });
  const enc8 = new TextEncoder();
  return {
    stdin: (d) => send({ type: 'stdin', data: toB64(typeof d === 'string' ? enc8.encode(d) : d) }),
    closeStdin: () => send({ type: 'close-stdin' }),
    resize: (rows, cols) => send({ type: 'resize', rows, cols }),
    cancel: () => send({ type: 'cancel' }),
    close: () => {
      finished = true;
      ws.close();
    },
  };
}

/** 끊긴 터미널의 결과(POST /ops/{opId}/result → {op, exec}) */
export interface ExecStatusView {
  receipt?: ExecReceiptView;
  running?: boolean;
  observedAt?: string;
}
