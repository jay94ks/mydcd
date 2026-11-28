// SPDX-License-Identifier: Apache-2.0

// 망의 터널 연결 (RQ4, 데몬 #307). 끊긴 서버 쌍만 다시 연결한다.
// 실제로는 시스템 관리자만 되지만 판단은 sfcd가 한다: 웹은 미리 막지 않고 거절을 그대로 보여 준다.
import { useEffect, useState } from 'react';
import { ApiError, noEndpoint } from '../api/client';
import { networkTunnels, tunnelReconnect, tunnelReconnectPath } from '../api/endpoints';
import type { DTunnelLink, DTunnelReconnect } from '../api/dto';
import type { OpView } from '../api/types';
import { Badge, type Tone } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { Refresh } from '../components/Refresh';
import { usePoll } from '../lib/usePoll';
import { when } from './WebBackup';
import { networkStateLive } from '../lib/liveTopics';

const STATE: Record<string, [string, Tone]> = { up: ['연결됨', 'ok'], degraded: ['불안정', 'wa'], down: ['끊김', 'er'], pending: ['연결 준비 중', 'un'] };
const stateBadge = (st: string) => {
  const [t, tone] = STATE[st] ?? [st, 'un' as Tone];
  return <Badge tone={tone}>{t}</Badge>;
};
const since = (sec: number) => (sec ? when(new Date(sec * 1000).toISOString()) : '—');

export function TunnelsDialog({ tenant, name, onClose }: { tenant: string; name: string; onClose: () => void }) {
  const q = usePoll((s) => networkTunnels(tenant, name, s), [tenant, name], 10_000, networkStateLive(tenant));
  const wait = !!q.error && noEndpoint(q.error);
  return (
    <Dialog title={`${name} 터널 연결`} width={720} onClose={onClose} footer={<button type="button" className="btn" onClick={onClose}>닫기</button>}>
      <div className="row between">
        <span className="small muted">이 망의 서버 쌍마다 터널 상태입니다. ‘다시 연결’은 끊긴 쌍에만 있고, 누르면 그 줄 아래에 진행이 나옵니다. 시스템 관리자만 할 수 있지만 미리 막지 않고 거절을 보여 줍니다. 계속 끊기면 서버 › 서버 간 연결에서 원인을 봅니다.</span>
        <Refresh q={q} poll={false} />
      </div>
      {wait ? (
        <div className="note small">터널 상태 보기 · 다시 연결: 서버 기능 대기</div>
      ) : (
        <Load q={q} what="터널 상태를 읽지 못했습니다">
          {(items) => (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>서버 쌍</th>
                    <th>상태</th>
                    <th>그때부터</th>
                    <th aria-label="동작" />
                  </tr>
                </thead>
                <tbody>
                  {items.map((l) => (
                    <TunnelRow key={l.pairId || `${l.from}/${l.to}`} tenant={tenant} name={name} l={l} onDone={() => void q.refresh()} />
                  ))}
                  {!items.length && (
                    <tr>
                      <td colSpan={4} className="muted">
                        서버가 하나뿐이라 터널이 없습니다.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </Load>
      )}
    </Dialog>
  );
}

/** 접수(op applied) 뒤 결과: GET /tunnel-reconnects/op-{opId}를 끝날 때까지 읽는다 */
function useReconnect(opId: string | undefined, onEnd: () => void) {
  const [r, setR] = useState<DTunnelReconnect>();
  const [error, setError] = useState<unknown>();
  useEffect(() => {
    if (!opId) return;
    const ac = new AbortController();
    let timer = 0;
    const tick = () =>
      tunnelReconnect(opId, ac.signal)
        .then((x) => {
          setR(x);
          setError(undefined);
          if (x.state === 'done' || x.state === 'failed') onEnd();
          else timer = window.setTimeout(tick, 1500);
        })
        .catch((e) => {
          if (ac.signal.aborted) return;
          setError(e);
          // 다시 읽어도 달라지지 않는 오류(모르는 operation 404, 권한 403)는 멈춘다
          if (e instanceof ApiError && (e.status === 404 || e.status === 403)) return;
          timer = window.setTimeout(tick, 3000);
        });
    void tick();
    return () => (ac.abort(), window.clearTimeout(timer));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opId]);
  return { r, error };
}

const RESULT: Record<string, string> = { reconnected: '다시 연결했습니다', 'already-connected': '이미 연결돼 있었습니다', failed: '다시 연결하지 못했습니다' };
const hms = (ms: number) => new Date(ms).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
function ReconnectStatus({ r, error }: { r?: DTunnelReconnect; error?: unknown }) {
  if (!r) return error !== undefined ? <ErrorBand error={error} what="다시 연결 진행을 읽지 못했습니다" /> : <span className="small muted">접수됨 · 진행을 읽는 중…</span>;
  if (r.state === 'queued') return <span className="small muted">접수됨 · {r.node}에서 차례를 기다리는 중</span>;
  if (r.state === 'running') return <span className="small muted">{r.node}가 {r.peer}에 다시 연결하는 중…</span>;
  const ok = r.state === 'done' && r.result !== 'failed';
  if (!ok)
    return (
      <div className="note er small">
        다시 연결하지 못했습니다{r.error ? `: ${r.error}` : ''} {r.code && <span className="mono">{r.code}</span>}
      </div>
    );
  return (
    <div className="note ok small">
      {RESULT[r.result ?? ''] ?? '끝났습니다'}
      {r.handshakeAt ? ` · 핸드셰이크 ${hms(r.handshakeAt)}` : ''}
      {r.keptExisting ? ' · 기존 연결 유지' : ''}
    </div>
  );
}

/**
 * 터널 다시 연결 동작(망 › 터널 연결 창과 서버 › 서버 간 연결 드로어가 같이 쓴다).
 * op applied는 접수일 뿐이라 /tunnel-reconnects/op-{opId}로 끝까지 읽는다. 권한은 sfcd 거절을 그대로 보인다.
 */
export type ReconnectTry = { path: string; body: Record<string, unknown> };
export function useReconnectAction(tries: ReconnectTry[], onDone: () => void) {
  const m = useMutation();
  const [sent, setSent] = useState(false);
  // 계획은 다이얼하는 쪽(owner)에 최근 down 관측이 있어야 한다. 한쪽만 끊김을 봤으면 409 not-down이므로 반대 방향으로 한 번 더 보낸다(새 opId)
  const [idx, setIdx] = useState(0);
  const accepted = m.op?.state === 'applied' ? m.op.id : undefined;
  const rc = useReconnect(accepted, onDone);
  const notDown = m.error instanceof ApiError && m.error.code === 'not-down';
  useEffect(() => {
    if (!sent || !notDown || idx + 1 >= tries.length) return;
    const next = idx + 1;
    setIdx(next);
    m.reset();
    void m.run(tries[next].path, tries[next].body);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [notDown, sent]);
  const refused = !!m.op && (m.op.state === 'failed' || m.op.state === 'rejected') && (m.op.errorCode === 'forbidden' || m.op.resultCode === 4);
  const working = m.busy || (!!accepted && (!rc.r || rc.r.state === 'queued' || rc.r.state === 'running'));
  const send = () => {
    setSent(true);
    if (m.op?.state === 'applied' || notDown) {
      // 끝난 시도 뒤에는 처음 방향부터 새로 보낸다
      setIdx(0);
      m.reset();
      void m.run(tries[0].path, tries[0].body);
      return;
    }
    void sendOp(m, tries[idx].path, tries[idx].body);
  };
  const view =
    sent && (m.op || m.error !== undefined) ? (
      <>
        {notDown ? (
          <div className="note small">끊긴 링크가 아니라 다시 연결하지 않았습니다.</div>
        ) : m.error instanceof ApiError && m.error.status === 404 ? (
          <ErrorBand error={m.error} what="이 서버 쌍을 찾지 못했습니다" />
        ) : (
          <MutationError error={m.error} />
        )}
        {refused ? (
          <div className="note er small">
            시스템 관리자만 터널을 다시 연결할 수 있습니다 <span className="mono">{m.op?.errorCode ?? 'forbidden'}</span>
          </div>
        ) : (
          m.op && m.op.state !== 'applied' && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />
        )}
        {accepted && <ReconnectStatus r={rc.r} error={rc.error} />}
      </>
    ) : null;
  return { send, working, busy: m.busy, view };
}

function TunnelRow({ tenant, name, l, onDone }: { tenant: string; name: string; l: DTunnelLink; onDone: () => void }) {
  const path = tunnelReconnectPath(tenant, name);
  const act = useReconnectAction(
    [
      { path, body: { from: l.from, to: l.to } },
      { path, body: { from: l.to, to: l.from } },
    ],
    onDone,
  );
  // sfcd는 down인 링크만 다시 연결한다(아니면 409 not-down)
  const down = l.state === 'down';
  return (
    <>
      <tr>
        <td className="mono">
          {l.from} ↔ {l.to}
        </td>
        <td>{stateBadge(l.state)}</td>
        <td>{since(l.since)}</td>
        <td className="row" style={{ justifyContent: 'flex-end' }}>
          {down && (
            <button type="button" className="btn sm" disabled={act.working} onClick={act.send}>
              다시 연결
            </button>
          )}
        </td>
      </tr>
      {act.view && (
        <tr>
          <td colSpan={4}>{act.view}</td>
        </tr>
      )}
    </>
  );
}
