// SPDX-License-Identifier: Apache-2.0

// 서버 상세 '고급 ▾'의 비우기·투표 서버에서 내리기·서버 신원 교체·강제 제거 (REQ-51, 데몬 #130).
// 계획은 sfcd의 것이다. 웹은 읽은 계획을 보여 주고 그 plan 값을 그대로 보내며,
// 할 수 있는지는 sfcd가 정한다(바뀌었으면 409 plan-changed, 거절은 op 결과).
import { useState } from 'react';
import type { ReactNode } from 'react';
import { ApiError } from '../api/client';
import { nodeActionPath, nodeDrainPlan, nodeDrainStatus, nodeForceRemovePlan, nodeVoterPlan } from '../api/endpoints';
import type { NodeView, OpView } from '../api/types';
import { Field } from '../components/ui';
import { ErrorBand } from '../components/states';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';
import { fmtTime } from '../lib/format';
import { eulReul } from '../lib/josa';
import { drainStateText } from '../lib/drain';

const VOTER_WHY: Record<string, string> = {
  NOT_VOTER: '투표 서버가 아닙니다.',
  LAST_VOTER: '마지막 투표 서버라 내릴 수 없습니다. 다른 서버를 먼저 투표 서버로 올리세요.',
  QUORUM_LOSS: '내리면 투표 서버 과반을 잃습니다. 투표 서버를 먼저 늘리세요.',
  NODE_REACHABLE: '이 서버는 응답하고 있어 강제 제거할 수 없습니다. 보통의 서버 제거를 쓰세요.',
  NODE_RESPONDING: '이 서버는 응답하고 있어 강제 제거할 수 없습니다. 보통의 서버 제거를 쓰세요.',
  NODE_OPERATION_PENDING: '이 서버에 진행 중인 작업이 있습니다. 끝난 뒤 다시 하세요.',
  SELF_REMOVAL: '지금 응답하는 sfcd 서버 자신은 뺄 수 없습니다. 다른 서버에 연결된 웹에서 하세요.',
};
const BLOCKED: Record<string, string> = { FIXED_VOLUME: '못 옮김 · 고정 데이터 저장소', NO_TARGET: '못 옮김 · 받을 서버 없음', PINNED_TO_NODE: '못 옮김 · 이 서버에 고정됨' };
const whyText = (code: string, detail?: string) => `${VOTER_WHY[code] ?? code}${detail ? ` (${detail})` : ''}`;

/** 거절 사유 목록. code만 있고 blockers가 비면 code 하나 */
function Blockers({ code, blockers }: { code?: string; blockers: { code: string; detail?: string }[] }) {
  const list = blockers.length ? blockers : code ? [{ code }] : [];
  if (!list.length) return null;
  return list.length === 1 ? (
    <div className="note wa small">{whyText(list[0].code, list[0].detail)}</div>
  ) : (
    <div className="note wa small">
      지금은 할 수 없습니다:
      <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
        {list.map((b) => (
          <li key={b.code + (b.detail ?? '')}>{whyText(b.code, b.detail)}</li>
        ))}
      </ul>
    </div>
  );
}

/** 비우기 진행 (drain-status). 끝날 때까지 읽는다 */
export function DrainProgress({ node, operation }: { node: string; operation: string }) {
  const q = usePoll((s) => nodeDrainStatus(node, operation, s), [node, operation], 5_000);
  const d = q.data;
  if (q.error) return <ErrorBand error={q.error} what="비우기 진행을 읽지 못했습니다" onRetry={q.refresh} />;
  if (!d) return <span className="muted small">진행을 읽는 중…</span>;
  return (
    <div className="small">
      <b>{drainStateText(d.state)}</b> · 옮김 {d.moved}/{d.total}
      {d.blocked ? <span className="wa-text"> · 그대로 둠 {d.blocked}</span> : null} <span className="muted mono">{d.operation}</span>
      <div className="bar" role="progressbar" aria-valuemin={0} aria-valuemax={d.total} aria-valuenow={d.moved} style={{ margin: '6px 0' }}>
        <i style={{ width: `${d.total ? Math.round((d.moved / d.total) * 100) : 100}%` }} />
      </div>
      {d.jobs.length > 0 && (
        <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
          {d.jobs.map((j) => (
            <li key={j.operation}>
              {j.tenant}/{j.app} · {drainStateText(j.state)} {j.moved}/{j.total}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** 계획 + op 한 벌. plan-changed면 새로 읽게 한다 */
function usePlanOp() {
  const m = useMutation();
  const changed = m.error instanceof ApiError && m.error.code === 'plan-changed';
  const done = m.op?.state === 'applied';
  return { m, changed, done };
}

function Shell({ title, onClose, done, busy, ok, danger, label, onSend, children, width = 560 }: { title: string; onClose: () => void; done: boolean; busy: boolean; ok: boolean; danger?: boolean; label: string; onSend: () => void; children: ReactNode; width?: 420 | 560 | 720 }) {
  return (
    <Dialog
      title={title}
      width={width}
      onClose={onClose}
      footer={
        done ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className={danger ? 'btn danger solid' : 'btn primary'} disabled={busy || !ok} onClick={onSend}>
              {busy ? '보내는 중…' : label}
            </button>
          </>
        )
      }
    >
      {children}
    </Dialog>
  );
}

function Changed({ what, onReload }: { what: string; onReload: () => void }) {
  return (
    <div className="note wa small row between">
      <span>그사이 {what}이 바뀌었습니다. 새 계획을 읽은 뒤 다시 하세요.</span>
      <button className="btn sm" onClick={onReload}>
        새로 읽기
      </button>
    </div>
  );
}

const Confirm = ({ node, typed, set, disabled }: { node: string; typed: string; set: (v: string) => void; disabled: boolean }) => (
  <Field label={`확인하려면 ${node} 을(를) 입력하세요`}>
    <input className="mono" value={typed} disabled={disabled} onChange={(e) => set(e.target.value.trim())} />
  </Field>
);

/** 비우기 (drain-node): 컨테이너를 옮기고 새 배치를 막는다. 서버는 클러스터에 남는다.
 * 계획이 돌려준 operation을 다시 읽을 때와 보낼 때 그대로 쓰고, 진행은 drain-status로 읽는다. */
export function DrainDialog({ node, onClose }: { node: NodeView; onClose: () => void }) {
  const [operation, setOperation] = useState<string>();
  const q = usePoll((s) => nodeDrainPlan(node.id, s, operation), [node.id, operation]);
  const { m, changed, done } = usePlanOp();
  const [leave, setLeave] = useState(false);
  const [sent, setSent] = useState<string>();
  const p = q.data;
  if (p && !operation && p.operation) setOperation(p.operation);
  const blocked = p?.tasks.filter((t) => !t.movable).length ?? 0;
  const send = () => {
    setSent(p!.plan);
    return sendOp(m, nodeActionPath(node.id, 'drain'), { plan: p!.plan, operation: p!.operation, ...(blocked ? { leaveBlocked: leave } : {}) });
  };
  const ok = !!p && !p.code && p.tasks.length > 0 && (!blocked || leave) && !(changed && sent === p.plan);
  return (
    <Shell title={`${node.id} 비우기`} width={720} onClose={onClose} done={done} busy={m.busy} ok={ok} label="비우기 시작" onSend={() => void send()}>
      <p style={{ margin: 0 }}>이 서버의 컨테이너를 다른 서버로 옮기고 새 배치를 막습니다. 서버는 클러스터에 남습니다.</p>
      {q.error ? (
        <ErrorBand error={q.error} what="비우기 계획을 읽지 못했습니다" onRetry={q.refresh} />
      ) : !p ? (
        <span className="muted">읽는 중…</span>
      ) : (
        <>
          <Blockers code={p.code} blockers={p.blockers} />
          {!p.tasks.length ? (
            <div className="note ok small">옮길 컨테이너가 없습니다.</div>
          ) : (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>컨테이너</th>
                    <th>옮길 곳</th>
                    <th>비고</th>
                  </tr>
                </thead>
                <tbody>
                  {p.tasks.map((t) => (
                    <tr key={`${t.tenant}/${t.app}/${t.service}/${t.task}`}>
                      <td className="mono small">
                        {t.task}
                        <span className="muted"> · {t.tenant}</span>
                      </td>
                      <td>{t.target || '—'}</td>
                      <td>{!t.movable ? <span className="wa-text">{BLOCKED[t.reason ?? ''] ?? `못 옮김${t.reason ? ` · ${t.reason}` : ''}`}</span> : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {p.jobs.length > 0 && <span className="small muted">앱별 이동 {p.jobs.length}건: {p.jobs.map((j) => `${j.tenant}/${j.app} → ${j.target}${j.moveVolume ? ' (데이터 함께)' : ''}`).join(', ')}</span>}
        </>
      )}
      {blocked > 0 && (
        <label className="check">
          <input type="checkbox" checked={leave} disabled={m.busy || done} onChange={(e) => setLeave(e.target.checked)} />
          못 옮기는 것 {blocked}개는 그대로 두고 알림
        </label>
      )}
      {changed && <Changed what="이 서버의 컨테이너" onReload={() => void q.refresh()} />}
      {!changed && <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
      {done && p && <DrainProgress node={node.id} operation={p.operation} />}
    </Shell>
  );
}

/** 투표 서버에서 내리기 (demote-node) */
export function DemoteDialog({ node, onClose }: { node: NodeView; onClose: () => void }) {
  const q = usePoll((s) => nodeVoterPlan(node.id, s), [node.id]);
  const { m, done } = usePlanOp();
  const [typed, setTyped] = useState('');
  const p = q.data;
  // 계획을 읽은 순간의 expected를 그대로 보낸다
  const [expected, setExpected] = useState<number>();
  if (p && expected === undefined) setExpected(p.expected);
  const can = !!p && p.demotable && !p.code;
  const send = () => sendOp(m, nodeActionPath(node.id, 'demote'), expected ? { expected } : {});
  return (
    <Shell title={`${node.id}${eulReul(node.id)} 투표 서버에서 내릴까요?`} onClose={onClose} done={done} busy={m.busy} ok={can && typed === node.id} label="내리기" danger onSend={() => void send()}>
      {q.error ? (
        <ErrorBand error={q.error} what="투표 계획을 읽지 못했습니다" onRetry={q.refresh} />
      ) : !p ? (
        <span className="muted">읽는 중…</span>
      ) : !can ? (
        <Blockers code={p.code ?? 'NOT_VOTER'} blockers={p.blockers} />
      ) : (
        <p style={{ margin: 0 }}>
          투표 서버 {p.votersBefore} → {p.votersAfter}대. 과반은 {p.quorumAfter}대라 견딜 수 있는 장애가 {p.faultToleranceAfter}대가 됩니다. 서버와 컨테이너는 그대로 남습니다.
        </p>
      )}
      {can && <Confirm node={node.id} typed={typed} set={setTyped} disabled={m.busy || done} />}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
    </Shell>
  );
}

/** 서버 신원 교체 (rotate-node-identity) */
export function RotateIdentityDialog({ node, onClose }: { node: NodeView; onClose: () => void }) {
  const { m, done } = usePlanOp();
  // sfcd는 신원 교체를 노드 생애 revision이 아니라 멤버 항목 revision(joinRevision)으로 확인한다
  const [rev] = useState(node.joinRevision);
  const send = () => sendOp(m, nodeActionPath(node.id, 'rotate-identity'), rev ? { expected: rev } : {});
  return (
    <Shell title={`${node.id} 서버 신원 교체`} onClose={onClose} done={done} busy={m.busy} ok label="교체" onSend={() => void send()}>
      <p style={{ margin: 0 }}>이 서버의 노드 키를 새로 만들어 클러스터에 등록하고 옛 키를 무효로 합니다. 서버가 응답해야 하며, 응답하지 않으면 거절됩니다. 컨테이너는 그대로 돕니다.</p>
      <span className="small muted">
        지금 키 <span className="mono">{node.key ? `${node.key.slice(0, 8)}…${node.key.slice(-8)}` : '—'}</span>
        {node.identity ? ` · 마지막 교체 ${node.identityRotatedAt ? fmtTime(node.identityRotatedAt) : '—'} · ${node.identity.operation} (${node.identity.phase}${node.identity.failure ? ` · ${node.identity.failure}` : ''})` : ''}
      </span>
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
    </Shell>
  );
}

/** 강제 제거 (force-remove-node): 응답 없는 서버를 closure 없이 뺀다. sfcd가 계획을 읽을 때 그 서버에 probe를 보낸다 */
export function ForceRemoveDialog({ node, onClose, onRemoved }: { node: NodeView; onClose: () => void; onRemoved: () => void }) {
  const [operation, setOperation] = useState<string>();
  const q = usePoll((s) => nodeForceRemovePlan(node.id, s, operation), [node.id, operation]);
  const { m, changed, done } = usePlanOp();
  const [typed, setTyped] = useState('');
  const [sent, setSent] = useState<string>();
  const p = q.data;
  if (p && !operation && p.operation) setOperation(p.operation);
  const can = !!p && p.forceable && !p.code;
  const send = () => {
    setSent(p!.plan);
    return sendOp(m, nodeActionPath(node.id, 'force-remove'), { plan: p!.plan, operation: p!.operation });
  };
  const fixed = p?.volumes.filter((v) => v.fixed) ?? [];
  return (
    <Shell
      title={`${node.id}${eulReul(node.id)} 강제로 제거할까요?`}
      onClose={done ? onRemoved : onClose}
      done={done}
      busy={m.busy}
      ok={can && typed === node.id && !(changed && sent === p!.plan)}
      label="강제 제거"
      danger
      onSend={() => void send()}
    >
      <p style={{ margin: 0 }}>응답하지 않는 서버를 서버의 확인 없이 클러스터 구성에서 뺍니다. 되돌릴 수 없습니다. 다시 쓰려면 새로 가입시켜야 합니다.</p>
      {q.error ? (
        <ErrorBand error={q.error} what="강제 제거 계획을 읽지 못했습니다" onRetry={q.refresh} />
      ) : !p ? (
        <span className="muted">이 서버가 응답하는지 확인하는 중…</span>
      ) : (
        <>
          {p.probe && (
            <span className="small muted">
              응답 확인 {p.probe.finishedAt ? fmtTime(p.probe.finishedAt) : ''} · {p.probe.responding ? '응답함' : '응답 없음'}
            </span>
          )}
          {!can ? (
            <Blockers code={p.code} blockers={p.blockers} />
          ) : (
            <>
              {p.votersBefore !== p.votersAfter && (
                <span>
                  투표 서버 {p.votersBefore} → {p.votersAfter}대 · 과반 {p.quorumAfter}대 · 견딜 수 있는 장애 {p.faultToleranceAfter}대
                </span>
              )}
              {fixed.length > 0 && (
                <div className="note er small">
                  함께 잃는 고정 데이터 저장소 {fixed.length}개: <span className="mono">{fixed.map((v) => `${v.tenant}/${v.id}`).join(', ')}</span>
                </div>
              )}
              {p.tasks.length > 0 && (
                <div className="note wa small">
                  ‘찾을 수 없음’이 되는 컨테이너 {p.tasks.length}개: <span className="mono">{p.tasks.map((t) => `${t.tenant}/${t.task}`).join(', ')}</span>
                </div>
              )}
              <Confirm node={node.id} typed={typed} set={setTyped} disabled={m.busy || done} />
            </>
          )}
        </>
      )}
      {changed && <Changed what="강제 제거 계획" onReload={() => void q.refresh()} />}
      {!changed && <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
    </Shell>
  );
}
