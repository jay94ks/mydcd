// SPDX-License-Identifier: Apache-2.0

import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { follow, streamEndText, type SampleView, type StreamEvent, type StreamTargetView } from '../api/streams';
import type { TaskView } from '../api/types';
import { Dialog } from './Dialog';
import { Badge, Segmented, Tile, type Tone } from './ui';
import { fmtBytes, hhmmss } from '../lib/format';

const TerminalPane = lazy(() => import('./TerminalPane'));

type Tab = 'logs' | 'stats' | 'top' | 'exec';
type Phase = 'connecting' | 'live' | 'ended' | 'failed';

const PHASE: Record<Phase, [Tone, string]> = {
  connecting: ['pr', '연결 중'],
  live: ['ok', '따라가는 중'],
  ended: ['un', '끝남'],
  failed: ['er', '끊김'],
};

/** follow()를 열고 상태·대상을 관리한다. key가 바뀌면 다시 연다. */
export function useFollow(task: TaskView, params: Parameters<typeof follow>[1], onData: (e: StreamEvent) => void) {
  const [phase, setPhase] = useState<Phase>('connecting');
  const [target, setTarget] = useState<StreamTargetView>();
  const [endCode, setEndCode] = useState<string>();
  const [gen, setGen] = useState(0);
  const cb = useRef(onData);
  cb.current = onData;
  const key = JSON.stringify(params);
  useEffect(() => {
    setPhase('connecting');
    setEndCode(undefined);
    return follow(task, params, (e) => {
      if (e.type === 'target') {
        setTarget(e.target);
        setPhase('live');
      } else if (e.type === 'end') setPhase('ended');
      else if (e.type === 'error') {
        setEndCode(e.code);
        setPhase('failed');
      } else cb.current(e);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [task.tenant, task.app, task.standalone, key, gen]);
  return { phase, target, endCode, reconnect: () => setGen((g) => g + 1) };
}

export function StatusLine({ phase, target, endCode, onReconnect, extra }: { phase: Phase; target?: StreamTargetView; endCode?: string; onReconnect: () => void; extra?: React.ReactNode }) {
  const [tone, label] = PHASE[phase];
  return (
    <div className="row between small" style={{ marginBottom: 8 }}>
      <span className="row">
        <Badge tone={tone}>{label}</Badge>
        {target && (
          <span className="muted">
            {target.node} · 세대 {target.generation}
            {target.startedAt ? ` · 시작 ${hhmmss(target.startedAt)}` : ''}
          </span>
        )}
        {phase === 'failed' && endCode && <span>{streamEndText(endCode)}</span>}
        {phase === 'ended' && <span className="muted">서버가 스트림을 끝냈습니다.</span>}
      </span>
      <span className="row">
        {extra}
        {(phase === 'failed' || phase === 'ended') && (
          <button className="btn sm" onClick={onReconnect}>
            다시 잇기
          </button>
        )}
      </span>
    </div>
  );
}

interface Line {
  seq: number;
  err: boolean;
  text: string;
}
const MAX_LINES = 5000;

function LogsPane({ task }: { task: TaskView }) {
  const [tail, setTail] = useState(200);
  const [stdout, setStdout] = useState(true);
  const [stderr, setStderr] = useState(true);
  const [follow_, setFollow] = useState(true);
  const [lines, setLines] = useState<Line[]>([]);
  const [find, setFind] = useState('');
  const partial = useRef<{ out: string; err: string }>({ out: '', err: '' });
  const box = useRef<HTMLPreElement>(null);
  const params = { kind: 'logs' as const, service: task.service, instance: task.instance, tail, stdout, stderr };
  const s = useFollow(task, params, (e) => {
    if (e.type !== 'stdout' && e.type !== 'stderr') return;
    const isErr = e.type === 'stderr';
    const k = isErr ? 'err' : 'out';
    const parts = (partial.current[k] + e.text).split('\n');
    partial.current[k] = parts.pop() ?? '';
    if (!parts.length) return;
    setLines((old) => {
      const next = old.concat(parts.map((text, i) => ({ seq: e.sequence * 1000 + i, err: isErr, text })));
      return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
    });
  });
  // 새로 열면(조건 바뀜·다시 잇기) 화면을 비운다. 서버가 tail부터 다시 보낸다.
  useEffect(() => {
    if (s.phase === 'connecting') {
      setLines([]);
      partial.current = { out: '', err: '' };
    }
  }, [s.phase]);
  useEffect(() => {
    if (follow_ && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines, follow_]);
  const shown = find ? lines.filter((l) => l.text.toLowerCase().includes(find.toLowerCase())) : lines;
  return (
    <>
      <div className="row small" style={{ marginBottom: 8 }}>
        <label className="row">
          처음에
          <select value={tail} onChange={(e) => setTail(Number(e.target.value))}>
            {[50, 200, 1000, 5000].map((n) => (
              <option key={n} value={n}>
                {n}줄
              </option>
            ))}
          </select>
        </label>
        <label className="row">
          <input type="checkbox" checked={stdout} onChange={(e) => setStdout(e.target.checked)} /> 표준 출력
        </label>
        <label className="row">
          <input type="checkbox" checked={stderr} onChange={(e) => setStderr(e.target.checked)} /> 오류 출력
        </label>
        <label className="row">
          <input type="checkbox" checked={follow_} onChange={(e) => setFollow(e.target.checked)} /> 끝 따라가기
        </label>
        <input type="search" placeholder="줄 찾기" value={find} onChange={(e) => setFind(e.target.value)} style={{ width: 160 }} />
      </div>
      <StatusLine
        {...s}
        onReconnect={s.reconnect}
        extra={
          <>
            <span className="muted">{lines.length}줄</span>
            <button className="btn sm" onClick={() => setLines([])}>
              화면 비우기
            </button>
          </>
        }
      />
      <pre ref={box} className="console" aria-live="off" onScroll={(e) => {
        const el = e.currentTarget;
        const atEnd = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
        if (atEnd !== follow_) setFollow(atEnd);
      }}>
        {shown.map((l) => (
          <div key={l.seq} className={l.err ? 'err' : undefined}>
            {l.text || ' '}
          </div>
        ))}
        {shown.length === 0 && <span className="muted">{s.phase === 'connecting' ? '연결하는 중…' : find ? '찾는 줄이 없습니다.' : '아직 로그가 없습니다.'}</span>}
      </pre>
    </>
  );
}

function StatsPane({ task }: { task: TaskView }) {
  const [sample, setSample] = useState<SampleView>();
  const params = { kind: 'stats' as const, service: task.service, instance: task.instance, intervalSec: 5 };
  const s = useFollow(task, params, (e) => e.type === 'sample' && e.sample.stats && setSample(e.sample));
  const st = sample?.stats;
  return (
    <>
      <StatusLine {...s} onReconnect={s.reconnect} extra={st && <span className="muted">{hhmmss(st.sampleAt)} 기준 · 5초마다</span>} />
      {!st ? (
        <p className="muted">{s.phase === 'connecting' ? '연결하는 중…' : '아직 표본이 없습니다.'}</p>
      ) : (
        <div className="grid tiles">
          <Tile label="CPU" value={st.cpuPercent !== undefined ? `${st.cpuPercent.toFixed(1)}%` : '—'} sub={st.cpuStatus && st.cpuStatus !== 'ok' ? st.cpuStatus : undefined} />
          <Tile label="메모리" value={fmtBytes(st.memoryBytes)} sub={st.memoryLimitBytes ? `한도 ${fmtBytes(st.memoryLimitBytes)}` : undefined} />
          <Tile label="네트워크 받음 / 보냄" value={`${fmtBytes(st.networkRXBytes)} / ${fmtBytes(st.networkTXBytes)}`} />
          <Tile label="디스크 읽기 / 쓰기" value={`${fmtBytes(st.blockReadBytes)} / ${fmtBytes(st.blockWriteBytes)}`} />
          <Tile label="프로세스 수" value={st.pids ?? '—'} />
        </div>
      )}
    </>
  );
}

export function TopPane({ task, intervalSec = 5 }: { task: TaskView; intervalSec?: number }) {
  const [sample, setSample] = useState<SampleView>();
  const params = { kind: 'top' as const, service: task.service, instance: task.instance, intervalSec };
  const s = useFollow(task, params, (e) => e.type === 'sample' && e.sample.titles && setSample(e.sample));
  return (
    <>
      <StatusLine {...s} onReconnect={s.reconnect} extra={sample && <span className="muted">{hhmmss(sample.observedAt)} 기준 · {intervalSec}초마다</span>} />
      {!sample?.titles ? (
        <p className="muted">{s.phase === 'connecting' ? '연결하는 중…' : '아직 표본이 없습니다.'}</p>
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                {sample.titles.map((t, i) => (
                  <th key={i}>{t}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(sample.processes ?? []).map((p, i) => (
                <tr key={i}>
                  {p.map((c, j) => (
                    <td key={j} className={j === p.length - 1 ? 'wrap' : undefined}>
                      <code>{c}</code>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

/** 휴대폰 프로세스 목록 (UI-M10 ②): 'PID · 명령' 한 줄 + 오른쪽 CPU·메모리, 누르면 나머지 칸 */
export function MTopList({ task, pids }: { task: TaskView; pids?: number }) {
  const [sample, setSample] = useState<SampleView>();
  const [all, setAll] = useState(false);
  const [open, setOpen] = useState<number>();
  const params = { kind: 'top' as const, service: task.service, instance: task.instance, intervalSec: 30 };
  const s = useFollow(task, params, (e) => e.type === 'sample' && e.sample.titles && setSample(e.sample));
  const t = (sample?.titles ?? []).map((x) => x.toUpperCase());
  const col = (...names: string[]) => t.findIndex((x) => names.includes(x));
  const pid = col('PID');
  const cmd = col('CMD', 'COMMAND', 'ARGS') >= 0 ? col('CMD', 'COMMAND', 'ARGS') : t.length - 1;
  const cpu = col('%CPU', 'C');
  const mem = col('RSS', '%MEM', 'VSZ');
  const memText = (v: string) => (t[mem] === 'RSS' || t[mem] === 'VSZ' ? `${(Number(v) / 1024).toFixed(1)} MiB` : `${v}%`);
  const rows = [...(sample?.processes ?? [])].sort((a, b) => (cpu >= 0 ? Number(b[cpu]) - Number(a[cpu]) : 0));
  const shown = all ? rows : rows.slice(0, 5);
  return (
    <>
      <div className="m-sec">
        <span>
          프로세스 {rows.length || pids || ''}
          {cpu >= 0 ? ' · CPU 높은 순' : ''}
        </span>
        {(s.phase === 'ended' || s.phase === 'failed') && (
          <button type="button" className="linkish" onClick={s.reconnect}>
            다시 연결
          </button>
        )}
      </div>
      {!sample?.titles ? (
        <span className="muted small">{s.phase === 'connecting' ? '연결하는 중…' : '아직 표본이 없습니다.'}</span>
      ) : (
        <div className="li">
          {shown.map((p, i) => (
            <button key={i} type="button" className="mono" style={{ fontSize: 12, flexWrap: 'wrap' }} onClick={() => setOpen(open === i ? undefined : i)}>
              <span className="el">
                {p[pid] ?? '—'} · {p[cmd]}
              </span>
              <span className="r">{[cpu >= 0 ? `${p[cpu]}%` : '', mem >= 0 ? memText(p[mem]) : ''].filter(Boolean).join(' · ')}</span>
              {open === i && (
                <span className="muted" style={{ flexBasis: '100%', whiteSpace: 'normal' }}>
                  {t.map((h, j) => (j === pid || j === cmd ? null : `${h} ${p[j]}`)).filter(Boolean).join(' · ')}
                </span>
              )}
            </button>
          ))}
          {rows.length > shown.length && (
            <button type="button" style={{ color: 'var(--accent)', fontSize: 13 }} onClick={() => setAll(true)}>
              {rows.length - shown.length}개 더 보기
            </button>
          )}
        </div>
      )}
    </>
  );
}

/** 컨테이너 하나의 로그·자원 사용·프로세스·터미널. 닫으면 모든 스트림을 닫는다. */
export function ContainerConsole({ task, canExec, onClose, initial = 'logs' }: { task: TaskView; canExec: boolean; onClose: () => void; initial?: Tab }) {
  const [tab, setTab] = useState<Tab>(initial);
  return (
    <Dialog title={<code>{task.standalone ?? `${task.app}-${task.service}-${task.instance}`}</code>} onClose={onClose} width={800}>
      <div className="row between" style={{ marginBottom: 10 }}>
        <Segmented
          label="보기"
          value={tab}
          onChange={setTab}
          options={[
            ['logs', '로그'],
            ['stats', '자원 사용'],
            ['top', '프로세스'],
            ['exec', '터미널'],
          ]}
        />
        <span className="muted small">
          {task.tenant} · {task.standalone ? '단독 컨테이너 · ' : ''}
          {task.node}
        </span>
      </div>
      {tab === 'logs' && <LogsPane task={task} />}
      {tab === 'stats' && <StatsPane task={task} />}
      {tab === 'top' && <TopPane task={task} />}
      {tab === 'exec' &&
        (canExec ? (
          <Suspense fallback={<p className="muted">터미널을 불러오는 중…</p>}>
            <TerminalPane task={task} />
          </Suspense>
        ) : (
          <p className="note small">터미널은 이 작업 공간의 관리자만 열 수 있습니다.</p>
        ))}
    </Dialog>
  );
}
