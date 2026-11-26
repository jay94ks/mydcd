// SPDX-License-Identifier: Apache-2.0

/** 목업 컨테이너 스트림. 실제와 같은 이벤트 순서(target → 내용 → end/error)를 흉내 낸다. */
import { currentUser, mockControls } from './router';
import * as fx from './fixtures';
import type { ExecHandle, ExecParams, FollowParams, StreamEvent, StreamScope, StreamTargetView } from '../streams';

const enc = new TextEncoder();
const out = (type: 'stdout' | 'stderr', sequence: number, text: string): StreamEvent => ({ type, sequence, text, bytes: enc.encode(text) });
const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => {
      clearTimeout(t);
      reject(new DOMException('aborted', 'AbortError'));
    });
  });

function target(scope: StreamScope, service: string, instance: string): StreamTargetView | undefined {
  const { tenant, app } = scope;
  if (scope.standalone) {
    const x = fx.standalone.find((s) => s.tenant === tenant && s.name === scope.standalone);
    if (!x || x.state === 'pending' || x.state === 'missing') return undefined;
    return { tenant, app: '', service: x.name, instance: '1', node: x.node, generation: x.revision, revision: x.revision, nativeID: 'mock-' + x.name, startedAt: new Date(x.createdAt * 1000).toISOString() };
  }
  const t = fx.tasks.find((x) => x.tenant === tenant && x.app === app && x.service === service && x.instance === instance);
  return t && { tenant, app, service, instance, node: t.node, generation: t.generation, revision: t.generation, nativeID: 'mock' + t.instance, startedAt: new Date(Date.now() - 3600_000).toISOString() };
}

const LINES = ['GET /index.php 200 12ms', 'GET /cart 200 31ms', 'POST /checkout 302 88ms', 'GET /static/app.css 304 1ms', 'GET /health 200 0ms'];

export async function* mockFollow(scope: StreamScope, p: FollowParams, signal: AbortSignal): AsyncGenerator<StreamEvent> {
  await sleep(mockControls.latencyMs, signal);
  if (mockControls.nextMutation === 'disconnected') {
    mockControls.nextMutation = 'none';
    yield { type: 'error', code: 'disconnected' };
    return;
  }
  const tg = target(scope, p.service, p.instance);
  if (!tg) {
    yield { type: 'error', code: 'not-found' };
    return;
  }
  yield { type: 'target', target: tg };
  let seq = 0;
  yield { type: 'sample', sample: { kind: p.kind, observedAt: new Date().toISOString(), tty: false, truncated: false } };
  if (p.kind === 'logs') {
    const tail = Math.min(p.tail ?? 100, 40);
    for (let i = 0; i < tail; i++) {
      const err = i % 9 === 4;
      if ((err && p.stderr === false) || (!err && p.stdout === false)) continue;
      yield out(err ? 'stderr' : 'stdout', ++seq, `${new Date(Date.now() - (tail - i) * 2000).toISOString()} [${p.service}] ${err ? 'WARN slow query 1.2s' : LINES[i % LINES.length]}\n`);
    }
    for (;;) {
      await sleep(1500 + Math.random() * 1500, signal);
      yield out('stdout', ++seq, `${new Date().toISOString()} [${p.service}] ${LINES[seq % LINES.length]}\n`);
    }
  }
  const iv = (p.intervalSec ?? 5) * 1000;
  for (;;) {
    const now = new Date().toISOString();
    if (p.kind === 'stats') {
      yield {
        type: 'sample',
        sample: {
          kind: 'stats',
          observedAt: now,
          tty: false,
          truncated: false,
          stats: { sampleAt: now, cpuPercent: Math.round(Math.random() * 400) / 10, cpuStatus: 'ok', memoryBytes: 180e6 + Math.round(Math.random() * 40e6), memoryLimitBytes: 1 << 30, networkRXBytes: 12e6 + seq * 1e4, networkTXBytes: 4e6 + seq * 5e3, pids: 7 },
        },
      };
    } else {
      yield {
        type: 'sample',
        sample: {
          kind: 'top',
          observedAt: now,
          tty: false,
          truncated: false,
          titles: ['PID', 'USER', 'TIME', 'COMMAND'],
          processes: [
            ['1', 'root', '0:02', `${p.service} --foreground`],
            ['17', 'www-data', '0:00', `${p.service} worker`],
            ['18', 'www-data', '0:00', `${p.service} worker`],
          ],
        },
      };
    }
    seq++;
    await sleep(iv, signal);
  }
}

/** 아주 작은 가짜 셸: echo, ls, pwd, whoami, exit 정도만 안다. */
export function mockExec(scope: StreamScope, p: ExecParams, onEvent: (e: StreamEvent) => void): ExecHandle {
  const { tenant, app } = scope;
  // 실제처럼 열기 전에 작업 기록에 남긴다(action exec, 처음 state running).
  const now = new Date().toISOString();
  const op = { id: p.opId, requestId: `exec-${p.opId}`, action: 'exec', tenant, target: scope.standalone ? `standalone/${scope.standalone}` : `${app}/${p.service}/${p.instance}`, state: 'running' as const, resultFound: false, submittedAt: now, updatedAt: now, user: currentUser(), digest: 'exec' };
  if (!fx.ops.some((o) => o.id === p.opId)) fx.ops.unshift(op);
  const record = (code: number) => {
    const o = fx.ops.find((x) => x.id === p.opId);
    if (o) Object.assign(o, { state: 'applied', resultFound: true, resultCode: 0, errorCode: code ? `exit-${code}` : undefined, updatedAt: new Date().toISOString() });
  };
  let seq = 0;
  let done = false;
  let line = '';
  const tg = target(scope, p.service, p.instance);
  const emit = (s: string) => !done && onEvent(out('stdout', ++seq, s));
  // 단독 컨테이너면 연결 수를 센다(끊기면 유예 시작).
  const sa = scope.standalone ? fx.standalone.find((x) => x.tenant === tenant && x.name === scope.standalone) : undefined;
  let attached = false;
  const detach = () => {
    if (!sa || !attached) return;
    attached = false;
    sa.connections = Math.max(0, sa.connections - 1);
    if (!sa.connections) sa.disconnectedAt = fx.nowSec();
  };
  const finish = (code: number) => {
    if (done) return;
    detach();
    record(code);
    onEvent({ type: 'receipt', receipt: { phase: 'finished', exitCode: code, outputEnded: true } });
    onEvent({ type: 'output-eof' });
    done = true;
    onEvent({ type: 'end' });
  };
  setTimeout(() => {
    if (!tg) {
      done = true;
      onEvent({ type: 'error', code: 'not-found' });
      return;
    }
    if (sa) {
      attached = true;
      sa.connections++;
      sa.disconnectedAt = undefined;
    }
    onEvent({ type: 'receipt', receipt: { phase: 'started', execID: 'mock-exec' } });
    if (!p.stdin) {
      emit(`(목업) ${p.cmd.join(' ')}\r\n`);
      finish(0);
      return;
    }
    emit(`목업 셸입니다. echo, ls, pwd, whoami, exit만 압니다.\r\n${p.service}:/# `);
  }, mockControls.latencyMs);
  const run = (cmd: string) => {
    const [c, ...args] = cmd.trim().split(/\s+/);
    if (!c) return '';
    if (c === 'exit') {
      finish(Number(args[0]) || 0);
      return undefined;
    }
    if (c === 'echo') return args.join(' ') + '\r\n';
    if (c === 'pwd') return '/\r\n';
    if (c === 'whoami') return 'root\r\n';
    if (c === 'ls') return 'bin  etc  srv  tmp  usr  var\r\n';
    return `sh: ${c}: not found\r\n`;
  };
  return {
    stdin: (d) => {
      if (done) return;
      const s = typeof d === 'string' ? d : new TextDecoder().decode(d);
      for (const ch of s) {
        if (ch === '\r' || ch === '\n') {
          emit('\r\n');
          const r = run(line);
          line = '';
          if (r === undefined) return;
          emit(r + `${p.service}:/# `);
        } else if (ch === '\x7f') {
          if (line) {
            line = line.slice(0, -1);
            emit('\b \b');
          }
        } else if (ch === '\x03') {
          line = '';
          emit(`^C\r\n${p.service}:/# `);
        } else if (ch >= ' ') {
          line += ch;
          emit(ch);
        }
      }
    },
    closeStdin: () => finish(0),
    resize: () => undefined,
    cancel: () => {
      if (done) return;
      done = true;
      detach();
      onEvent({ type: 'end' });
    },
    close: () => {
      done = true;
      detach();
    },
  };
}
