// SPDX-License-Identifier: Apache-2.0

// 데이터 저장소 이관 (UI-64, 캔버스 Volumes · VolumesIx). 계약: docs/reference/web-api.md "데이터 저장소 옮기기 (UI-64)".
// 웹은 옮기기 상태를 따로 두지 않는다. 진행은 저장소 행(phase Moving, moveID, targetNode, movePhase)에서 읽는다.
// 묶음 승인 비밀번호는 ApprovalPrompt 입력 칸에만 있고 보낸 뒤 지운다.
import { useState } from 'react';
import { ApiError } from '../api/client';
import { dashboard, volumeMovePlan, volumePath } from '../api/endpoints';
import type { DVolumeMovePlan } from '../api/dto';
import type { VolumeView } from '../api/types';
import { Badge, Card, Field } from '../components/ui';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';
import { fmtBytes, fmtTime } from '../lib/format';
import { ApprovalPrompt } from './VaultApproval';

type Plan = Omit<DVolumeMovePlan, 'services'> & { services: NonNullable<DVolumeMovePlan['services']> };

const ERR: Record<string, string> = {
  'no-app': '앱에 딸린 데이터 저장소만 옮길 수 있습니다.',
  moving: '이미 옮기는 중입니다. 끝나거나 취소한 뒤에 다시 하세요.',
  'app-not-running': '앱이 내려가 있어 옮길 수 없습니다. 앱을 다시 올린 뒤 하세요.',
  'digest-mismatch': '계획한 뒤에 앱 정의가 바뀌었습니다. 다시 계획하세요.',
  'plan-invalid': '서버가 준 계획이 요청과 맞지 않습니다. 다시 계획하세요.',
  'not-moving': '지금 옮기는 중이 아닙니다. 새로 읽어 주세요.',
  'not-retained': '이 원본은 이미 지우는 중이거나 없어졌습니다.',
  ambiguous: '같은 이름의 데이터 저장소가 여러 앱에 있습니다. 새로 읽은 뒤 다시 하세요.',
};
const Err = ({ e }: { e: unknown }) => {
  if (e === undefined) return null;
  if (e instanceof ApiError && ERR[e.code]) return <div className="note wa">{ERR[e.code]}</div>;
  return <MutationError error={e} />;
};
const appOf = (v: VolumeView) => (v.app ? { app: v.app } : {});

/** 이관을 시작할 수 없는 까닭. 없으면 undefined */
export function moveBlocked(v: VolumeView, canDeploy: boolean): string | undefined {
  if (v.kind === 'fixed' && !v.app) return '고정 데이터 저장소는 옮길 수 없습니다';
  if (!canDeploy) return '작업 공간 관리자 권한 필요';
  if (!v.app) return ERR['no-app'];
  if (v.movePhase) return ERR.moving;
  return undefined;
}

// sfcd 옮기기 단계(workload/volumes Phase)를 화면 4단계로 묶는다
const COPYING = ['Prepared', 'SourceFenced', 'Copying', 'Verified'];
const APPLYING = ['OwnerCommitted', 'Activating', 'Active', 'Completed'];
const PHASE: Record<string, string> = {
  Prepared: '접수됨 · 서버 준비',
  SourceFenced: '쓰기 멈춤',
  Copying: '전송 중',
  Verified: '전송 확인',
  OwnerCommitted: '새 서버로 확정',
  Activating: '새 서버에서 시작',
  Active: '새 서버에서 실행',
  Completed: '끝남',
  Cancelling: '취소하는 중',
  Cancelled: '취소됨',
};
const RETAINED: Record<string, [string, 'wa' | 'pr' | 'un']> = { retained: ['보존됨', 'wa'], deleting: ['지우는 중', 'pr'], removed: ['지움', 'un'] };

/** UI-64 · 이관 카드. 진행 단계, 이관 취소, 남긴 원본 지우기 */
export function MoveCard({ tenant, v, canDeploy, onRefresh, onStart }: { tenant: string; v: VolumeView; canDeploy: boolean; onRefresh: () => void; onStart: () => void }) {
  const [cancel, setCancel] = useState(false);
  const [del, setDel] = useState<VolumeView['retained'][number]>();
  const p = v.movePhase;
  const committed = !!p && APPLYING.includes(p);
  const cls = (done: boolean, now: boolean) => ({ color: done ? 'var(--ok)' : now ? 'var(--pr)' : undefined, fontWeight: now ? 600 : undefined });
  const retained = v.retained.filter((r) => r.state !== 'removed');
  const blocked = moveBlocked(v, canDeploy);
  return (
    <Card title="이관">
      {p ? (
        <ol style={{ margin: 0, paddingLeft: 18, fontSize: 13, lineHeight: '22px' }}>
          <li style={cls(true, false)}>
            계획: {v.node ?? '—'} → {v.targetNode ?? '—'}
            {v.moveId && <span className="mono muted"> · {v.moveId}</span>}
          </li>
          <li style={cls(committed, COPYING.includes(p) || p === 'Cancelling')} className={committed || COPYING.includes(p) || p === 'Cancelling' ? undefined : 'muted'}>
            쓰기 멈춤 · 사용 중지 확인 · 전송 중{COPYING.includes(p) || p === 'Cancelling' ? ` (${PHASE[p] ?? p})` : ''}
          </li>
          <li style={cls(false, committed)} className={committed ? undefined : 'muted'}>
            적용{committed ? ` (${PHASE[p] ?? p})` : ''}
          </li>
          <li className="muted">원본은 원래 서버에 보존 · 원본 삭제(별도 확인)</li>
        </ol>
      ) : (
        <p className="small muted" style={{ margin: 0 }}>
          진행 중인 이관이 없습니다.
        </p>
      )}
      {retained.length > 0 && (
        <div className="col" style={{ gap: 6 }}>
          <span className="small muted">이관이 남긴 원본입니다. 직접 지울 때까지 남습니다.</span>
          {retained.map((r) => (
            <div key={r.moveID} className="row" style={{ justifyContent: 'space-between' }}>
              <span>
                {r.node} <span className="mono muted">{r.moveID}</span> <Badge tone={RETAINED[r.state]?.[1] ?? 'un'}>{RETAINED[r.state]?.[0] ?? r.state}</Badge>
              </span>
              <button type="button" className="btn sm danger" disabled={!canDeploy || r.state !== 'retained'} title={canDeploy ? undefined : '작업 공간 관리자 권한 필요'} onClick={() => setDel(r)}>
                원본 삭제
              </button>
            </div>
          ))}
        </div>
      )}
      <div className="row" style={{ gap: 8 }}>
        <button type="button" className="btn" onClick={onRefresh}>
          결과 조회
        </button>
        {p ? (
          <button type="button" className="btn danger" disabled={!canDeploy || committed || p === 'Cancelling'} title={committed ? '새 서버로 확정한 뒤에는 취소할 수 없습니다' : !canDeploy ? '작업 공간 관리자 권한 필요' : undefined} onClick={() => setCancel(true)}>
            이관 취소
          </button>
        ) : (
          <button type="button" className="btn" disabled={!!blocked} title={blocked} onClick={onStart}>
            이관…
          </button>
        )}
      </div>
      {cancel && <CancelMoveDialog tenant={tenant} v={v} onClose={() => setCancel(false)} onDone={onRefresh} />}
      {del && <RetainedDeleteDialog tenant={tenant} v={v} r={del} onClose={() => setDel(undefined)} onDone={onRefresh} />}
    </Card>
  );
}

/** 이관 시작: 옮길 서버 고르기 → 계획 → 보내기(→ 묶음 승인) */
export function MoveDialog({ tenant, v, initialNode = '', onClose, onDone }: { tenant: string; v: VolumeView; initialNode?: string; onClose: () => void; onDone: () => void }) {
  const dash = usePoll((s) => dashboard(tenant, s), [tenant]);
  const nodes = (dash.data?.nodes ?? []).filter((n) => n.id !== v.node);
  const [node, setNode] = useState(initialNode);
  const target = node || nodes.find((n) => n.phase === 'ready')?.id || '';
  const [plan, setPlan] = useState<Plan>();
  const [planErr, setPlanErr] = useState<unknown>();
  const [planning, setPlanning] = useState(false);
  const m = useMutation();
  const makePlan = async () => {
    setPlanning(true);
    setPlanErr(undefined);
    try {
      setPlan(await volumeMovePlan(tenant, v.name, { ...appOf(v), node: target }));
    } catch (e) {
      setPlanErr(e);
    } finally {
      setPlanning(false);
    }
  };
  const start = async () => {
    if (!plan) return;
    // 계획을 다시 받은 뒤에는 새 opId로 보낸다(같은 opId·다른 내용은 op-conflict)
    if (m.error && !(m.error instanceof ApiError && m.error.status >= 500)) m.reset();
    const o = await m.run(`${volumePath(tenant, v.name)}/move`, { ...appOf(v), node: plan.to, digest: plan.digest });
    if (o) onDone();
  };
  const replan = () => {
    setPlan(undefined);
    m.reset();
  };
  const stale = m.error instanceof ApiError && (m.error.code === 'digest-mismatch' || m.error.code === 'plan-invalid');
  const sent = !!m.op;
  return (
    <Dialog
      title={`${v.name} 이관`}
      width={560}
      onClose={onClose}
      footer={
        sent ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : plan ? (
          <>
            <button type="button" className="btn" onClick={stale ? replan : onClose}>
              {stale ? '다시 계획' : '취소'}
            </button>
            <button type="button" className="btn danger solid" disabled={m.busy || stale} onClick={() => void start()}>
              {m.busy ? '보내는 중…' : '이관 시작'}
            </button>
          </>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn primary" disabled={!target || planning} onClick={() => void makePlan()}>
              {planning ? '계획하는 중…' : '이관 계획'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        {!plan ? (
          <>
            <Field label="옮길 서버" hint={`지금 서버: ${v.node ?? '—'}`}>
              <select value={target} onChange={(e) => setNode(e.target.value)} disabled={!nodes.length}>
                {!nodes.length && <option value="">{dash.data ? '옮길 수 있는 다른 서버가 없습니다' : '불러오는 중…'}</option>}
                {nodes.map((n) => (
                  <option key={n.id} value={n.id} disabled={n.phase !== 'ready'}>
                    {n.id}
                    {n.disk ? ` (여유 ${fmtBytes(n.disk.total - n.disk.used)})` : ''}
                    {n.phase !== 'ready' ? ` · ${n.phase === 'joining' ? '가입 대기' : n.phase === 'isolated' ? '격리' : '쓸 수 없음'}` : ''}
                  </option>
                ))}
              </select>
            </Field>
            <div className="note">
              옮기는 동안 {v.writer ? `쓰기 앱 ${v.writer}` : '이 데이터 저장소를 쓰는 앱'}가 멈춥니다.
            </div>
            <div className="kv2">
              <span className="muted">원본</span>
              <span>이관 뒤 원래 서버에 보존 · 직접 지울 때까지 남습니다</span>
            </div>
            <Err e={planErr} />
          </>
        ) : (
          <>
            <div className="kv2">
              <span className="muted">옮기기</span>
              <span>
                {plan.from} → <b>{plan.to}</b>
              </span>
              <span className="muted">크기</span>
              <span>
                용량 {fmtBytes(plan.capacityBytes)} · 옮길 자료 상한 {fmtBytes(plan.maxBytes)}
              </span>
              <span className="muted">복사 마감</span>
              <span>{fmtTime(plan.expiresAt)}</span>
              <span className="muted">앱</span>
              <span>
                {plan.app} {plan.cd && <Badge tone="wa">자동 배포 중</Badge>}
              </span>
            </div>
            {plan.services.length > 0 && (
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>서비스</th>
                      <th>서버</th>
                      <th>변화</th>
                    </tr>
                  </thead>
                  <tbody>
                    {plan.services.map((s) => (
                      <tr key={s.name}>
                        <td>{s.name}</td>
                        <td>{s.node || '—'}</td>
                        <td>{{ add: '추가', update: '변경', remove: '삭제', keep: '유지' }[s.change] ?? s.change}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <div className="note wa">
              데이터를 {plan.to}로 옮기는 동안 {v.writer ?? '쓰는 앱'}가 멈춥니다. 실패하거나 취소하면 원래 서버의 데이터로 다시 시작합니다.
            </div>
            {plan.cd && <span className="small muted">자동 배포 앱이라 CD를 등록한 사람이 묶음 사용을 승인합니다.</span>}
            <Err e={m.error} />
            {m.op && (
              <>
                <OpPanel op={m.op} onChange={(o) => (m.setOp(o), onDone())} onContinue={m.again} />
                <ApprovalPrompt tenant={tenant} op={m.op} onOp={m.setOp} />
                {m.op.state === 'applied' && <div className="note ok small">접수했습니다. 서버들이 복사를 시작합니다. 진행은 이관 카드에서 봅니다.</div>}
              </>
            )}
          </>
        )}
      </div>
    </Dialog>
  );
}

function CancelMoveDialog({ tenant, v, onClose, onDone }: { tenant: string; v: VolumeView; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const send = async () => {
    if (m.op || m.error) m.reset();
    const o = await m.run(`${volumePath(tenant, v.name)}/move/cancel`, { ...appOf(v), ...(v.moveId ? { id: v.moveId } : {}) });
    if (o?.state === 'applied') onDone();
  };
  return (
    <Dialog
      title="이관을 취소할까요?"
      danger
      width={420}
      onClose={onClose}
      footer={
        m.op?.state === 'applied' ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn danger solid" disabled={m.busy} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '이관 취소'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <div>전송을 멈추고 원본으로 쓰기 앱을 다시 시작합니다. 받은 쪽 일부 데이터는 지웁니다.</div>
        <Err e={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

function RetainedDeleteDialog({ tenant, v, r, onClose, onDone }: { tenant: string; v: VolumeView; r: VolumeView['retained'][number]; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const send = async () => {
    if (m.op || m.error) m.reset();
    const o = await m.run(`${volumePath(tenant, v.name)}/retained/${encodeURIComponent(r.moveID)}`, appOf(v), 'DELETE');
    if (o?.state === 'applied') onDone();
  };
  return (
    <Dialog
      title={`${r.node}의 원본을 지울까요?`}
      danger
      width={420}
      onClose={onClose}
      footer={
        m.op?.state === 'applied' ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn danger solid" disabled={m.busy} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '삭제'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <div>
          이관({r.moveID})이 {r.node}에 남긴 {v.name} 원본을 지웁니다. 되돌릴 수 없습니다.
        </div>
        <Err e={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}
