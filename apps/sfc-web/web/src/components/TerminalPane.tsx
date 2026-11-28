// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { newOpId } from '../api/client';
import { execResult } from '../api/endpoints';
import { openExec, streamEndText, type ExecHandle, type ExecReceiptView } from '../api/streams';
import type { OpView, TaskView } from '../api/types';
import { Badge, Field, OpBadge } from './ui';
import { ErrorBand } from './states';

type Phase = 'idle' | 'open' | 'ended';

/** 셸 명령을 argv로. 따옴표로 묶은 칸은 한 인자로 둔다. */
export function splitArgs(s: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

/**
 * 터미널(WebSocket). 열 때마다 새 작업 ID 하나. 끊겨도 프로세스는 계속 돌 수 있어서
 * 결과 확인(POST /ops/{opId}/result)으로 상태를 본다. 같은 ID로 다시 열어도 다시 실행하지 않는다.
 */
export default function TerminalPane({ task }: { task: TaskView }) {
  const [cmd, setCmd] = useState('/bin/sh');
  const [phase, setPhase] = useState<Phase>('idle');
  const [opId, setOpId] = useState<string>();
  const [end, setEnd] = useState<string>();
  const [receipt, setReceipt] = useState<ExecReceiptView>();
  const [result, setResult] = useState<{ op: OpView; running?: boolean; receipt?: ExecReceiptView }>();
  const [error, setError] = useState<unknown>();
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal>();
  const fit = useRef<FitAddon>();
  const handle = useRef<ExecHandle>();

  // 터미널 안의 Esc는 다이얼로그를 닫지 않는다.
  useEffect(() => {
    const el = host.current;
    const stop = (e: KeyboardEvent) => e.key === 'Escape' && e.stopPropagation();
    el?.addEventListener('keydown', stop);
    return () => el?.removeEventListener('keydown', stop);
  }, []);

  useEffect(() => {
    const t = new Terminal({ fontSize: 13, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', cursorBlink: true, convertEol: false, scrollback: 5000 });
    const f = new FitAddon();
    t.loadAddon(f);
    if (host.current) t.open(host.current);
    f.fit();
    term.current = t;
    fit.current = f;
    const onData = t.onData((d) => handle.current?.stdin(d));
    const onResize = t.onResize(({ rows, cols }) => handle.current?.resize(rows, cols));
    const ro = new ResizeObserver(() => fit.current?.fit());
    if (host.current) ro.observe(host.current);
    return () => {
      ro.disconnect();
      onData.dispose();
      onResize.dispose();
      handle.current?.close();
      handle.current = undefined;
      t.dispose();
    };
  }, []);

  const connect = async () => {
    const argv = splitArgs(cmd);
    const t = term.current;
    if (!argv.length || !t) return;
    const id = newOpId();
    setOpId(id);
    setEnd(undefined);
    setReceipt(undefined);
    setResult(undefined);
    setError(undefined);
    setPhase('open');
    t.reset();
    fit.current?.fit();
    try {
      handle.current = await openExec(task, { opId: id, service: task.service, instance: task.instance, cmd: argv, tty: true, stdin: true, rows: t.rows, cols: t.cols }, (e) => {
        if (e.type === 'stdout' || e.type === 'stderr') t.write(e.bytes);
        else if (e.type === 'receipt') setReceipt(e.receipt);
        else if (e.type === 'end' || e.type === 'error') {
          handle.current = undefined;
          setEnd(e.type === 'end' ? 'end' : e.code);
          setPhase('ended');
        }
      });
      t.focus();
    } catch (e) {
      setError(e);
      setPhase('ended');
    }
  };
  const check = async () => {
    if (!opId) return;
    setError(undefined);
    try {
      const r = await execResult(opId);
      setResult({ op: r.op, running: r.exec?.running, receipt: r.exec?.receipt });
    } catch (e) {
      setError(e);
    }
  };
  const exit = receipt?.exitCode;
  return (
    <div>
      {phase === 'open' ? (
        <div className="row between small" style={{ marginBottom: 8 }}>
          <span className="row">
            <Badge tone="ok">연결됨</Badge>
            <code>{cmd}</code>
            {receipt && <span className="muted">· {receipt.phase === 'started' ? '실행 중' : receipt.phase}</span>}
          </span>
          <span className="row">
            <button type="button" className="btn sm" onClick={() => handle.current?.closeStdin()} title="입력 끝(EOF)을 보냅니다">
              입력 닫기
            </button>
            <button type="button" className="btn sm" onClick={() => handle.current?.cancel()} title="화면 연결만 끊습니다. 프로세스는 계속 돌 수 있습니다">
              연결 끊기
            </button>
          </span>
        </div>
      ) : (
        <div className="row" style={{ marginBottom: 8, alignItems: 'flex-end' }}>
          <Field label="실행할 명령" hint="컨테이너 안에서 실행합니다. 이 작업은 작업 기록에 남습니다.">
            <input value={cmd} onChange={(e) => setCmd(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void connect()} style={{ width: 280 }} />
          </Field>
          <button type="button" className="btn primary" disabled={!splitArgs(cmd).length} onClick={() => void connect()}>
            {phase === 'ended' ? '새 터미널 열기' : '터미널 열기'}
          </button>
        </div>
      )}
      {phase === 'ended' && (
        <div className="note small" style={{ marginBottom: 8 }}>
          {end === 'end' && exit !== undefined ? `프로세스가 끝났습니다(종료 코드 ${exit}).` : `${end === 'end' ? '화면 연결이 끝났습니다.' : streamEndText(end ?? 'closed')} 프로세스는 계속 돌고 있을 수 있습니다.`}
          {opId && (
            <>
              {' '}
              <button type="button" className="btn sm" onClick={() => void check()}>
                결과 확인
              </button>
            </>
          )}
          {result && (
            <span className="row" style={{ marginTop: 6 }}>
              <OpBadge state={result.op.state} />
              {result.running ? '아직 실행 중입니다.' : result.receipt?.exitCode !== undefined ? `종료 코드 ${result.receipt.exitCode}` : result.receipt ? `단계 ${result.receipt.phase}` : '상태를 읽지 못했습니다.'}
              <span className="muted">작업 {opId?.slice(0, 8)}</span>
            </span>
          )}
        </div>
      )}
      {error !== undefined && <ErrorBand error={error} what="터미널을 열지 못했습니다" />}
      <div ref={host} className="terminal-host" />
    </div>
  );
}
