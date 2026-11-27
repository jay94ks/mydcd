// SPDX-License-Identifier: Apache-2.0

// 이 변경 되돌리기 (UI-A4, 캔버스 v226 OpsRevert). 계약: docs/reference/web-api/52-ops-revert.md
// 계획을 읽어 원 작업이 바꾼 칸만 보이고, 그 뒤 누가 또 바꾼 칸(changedSince)은 기본으로 끈다.
// 보낼 때는 계획의 expected(지금 revision)와 고른 칸 이름만 보낸다. 고르지 않은 칸은 지금 값 그대로다.
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { appPath } from '../api/endpoints';
import { ApiError } from '../api/client';
import type { OpView } from '../api/types';
import { REVERT_REASON, fieldName, revertPath, revertPlan, showValue, type RevertField, type RevertPlan } from '../api/revert';
import { fmtTime } from '../lib/format';
import { Dialog } from './Dialog';
import { ErrorBand } from './states';
import { MutationError, OpPanel, sendOp, useMutation } from './OpPanel';
import { useToast } from './Toast';

/** 링크로 이어 주는 화면 */
export function revertLinkTo(l: NonNullable<RevertPlan['link']>): [string, string] | undefined {
  if (l.kind === 'app-revisions' && l.tenant && l.app) return [`${appPath(l.tenant, l.app)}/revisions`, '앱 › 버전 기록에서 되돌리기'];
  if (l.kind === 'archived-apps') return ['/deploy/archived', '내린 앱에서 다시 올리기'];
  return undefined;
}

/** 원 작업이 바꾼 칸을 보이는 한 줄: 바꾸기 전 · 되돌릴 변경 뒤 · 지금 */
function setText(f: RevertField) {
  const add = f.added ?? [];
  const rm = f.removed ?? [];
  return { before: rm.length ? rm.map(showValue).join(', ') : '없음', after: add.length ? add.map(showValue).join(', ') : '없음' };
}

export function RevertDialog({ op, onClose, onDone }: { op: OpView; onClose: () => void; onDone?: (o: OpView) => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const [plan, setPlan] = useState<RevertPlan>();
  const [loadErr, setLoadErr] = useState<unknown>();
  const [pick, setPick] = useState<Set<string>>(new Set());
  const [reload, setReload] = useState(0);
  const m = useMutation();
  useEffect(() => {
    const ac = new AbortController();
    setLoadErr(undefined);
    revertPlan(op.id, ac.signal).then(
      (p) => {
        setPlan(p);
        setPick(new Set((p.fields ?? []).filter((f) => !f.changedSince).map((f) => f.path)));
      },
      (e) => !ac.signal.aborted && setLoadErr(e),
    );
    return () => ac.abort();
  }, [op.id, reload]);
  const short = op.id.slice(0, 8);
  const fields = plan?.fields ?? [];
  const moved = fields.filter((f) => f.changedSince);
  const stale = m.error instanceof ApiError && m.error.status === 409 && m.error.code === 'stale';
  const done = m.op?.state === 'applied';
  const send = async () => {
    if (!plan) return;
    const v = await sendOp(m, revertPath(op.id), { expected: plan.expected, fields: fields.filter((f) => pick.has(f.path)).map((f) => f.path) });
    if (v?.state === 'applied') {
      toast(`✓ ${short}을 되돌렸습니다 · 새 작업 ${v.id.slice(0, 8)}`);
      onDone?.(v);
    }
  };
  const all = fields.length > 0 && pick.size === fields.length && !moved.length;
  const link = plan?.revert === 'link' && plan.link ? revertLinkTo(plan.link) : undefined;
  const footer = done ? (
    <button className="btn primary" onClick={onClose}>
      닫기
    </button>
  ) : (
    <>
      <button className="btn" onClick={onClose}>
        취소
      </button>
      {link && (
        <button className="btn primary" onClick={() => (onClose(), navigate(link[0]))}>
          {link[1]}
        </button>
      )}
      {plan?.revert === 'here' && !plan.reason && fields.length > 0 && (
        <button className="btn primary" disabled={!pick.size || m.busy || (!!m.op && m.op.state !== 'unknown')} onClick={() => void send()}>
          {m.busy ? '보내는 중…' : all ? '되돌리기 보내기' : '고른 칸만 되돌리기'}
        </button>
      )}
    </>
  );
  return (
    <Dialog title={`${short} 되돌리기${plan?.target ? ` · ${plan.target}` : op.target ? ` · ${op.target}` : ''}`} width={moved.length ? 720 : 560} onClose={onClose} footer={footer}>
      {loadErr !== undefined && <ErrorBand error={loadErr} what="되돌릴 내용을 읽지 못했습니다" />}
      {!plan && loadErr === undefined && <span className="small muted">지금 값을 읽는 중…</span>}
      {plan && (
        <>
          <p className="small muted">
            {fmtTime(op.submittedAt)}에 보낸 {plan.action ?? op.action} 변경을 반대로 보냅니다. 바꾼 칸만 되돌리고, 고르지 않은 칸은 지금 값 그대로 둡니다.
          </p>
          {plan.revert === 'link' && <div className="note info small">이 작업은 다른 화면에서 되돌립니다.</div>}
          {plan.revert === 'no' && <div className={`note ${plan.reason === 'unsettled' || plan.reason === 'target-gone' ? 'wa' : 'er'} small`}>{plan.reason ? REVERT_REASON[plan.reason] : '이 작업은 되돌릴 수 없습니다.'}</div>}
          {plan.revert === 'here' && plan.reason && <div className="note wa small">{REVERT_REASON[plan.reason]}</div>}
          {plan.revert === 'here' && !plan.reason && fields.length > 0 && (
            <>
              {moved.length > 0 && <div className="note wa small">이 작업 뒤에 {moved.map((f) => fieldName(f.path)).join(', ')} 칸을 누가 또 바꿨습니다. 되돌리면 그 변경도 덮어씁니다. 그 칸은 기본으로 꺼 둡니다.</div>}
              <div className="gtbl">
                <div className="gr th" style={{ gridTemplateColumns: '28px 1.1fr 1fr 1fr 1fr' }}>
                  <span />
                  <span>칸</span>
                  <span>바꾸기 전</span>
                  <span>되돌릴 변경 뒤</span>
                  <span>지금</span>
                </div>
                {fields.map((f) => {
                  const s = f.kind === 'set' ? setText(f) : undefined;
                  return (
                    <label key={f.path} className="gr" style={{ gridTemplateColumns: '28px 1.1fr 1fr 1fr 1fr', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        aria-label={`${fieldName(f.path)} 되돌리기`}
                        checked={pick.has(f.path)}
                        disabled={m.busy || done}
                        onChange={(e) => {
                          const n = new Set(pick);
                          if (e.target.checked) n.add(f.path);
                          else n.delete(f.path);
                          setPick(n);
                        }}
                      />
                      <span>
                        {fieldName(f.path)}
                        {f.kind === 'set' && <span className="muted small"> · 줄 목록</span>}
                      </span>
                      <span className="mono small">{s ? (s.before === '없음' ? '—' : `뺀 줄 ${s.before}`) : showValue(f.before)}</span>
                      <span className="mono small">{s ? (s.after === '없음' ? '—' : `더한 줄 ${s.after}`) : showValue(f.after)}</span>
                      <span className="mono small">{s ? `${Array.isArray(f.now) ? f.now.length : 0}줄` : f.changedSince ? <b>{showValue(f.now)}</b> : showValue(f.now)}</span>
                    </label>
                  );
                })}
              </div>
              <span className="small muted">
                지금 버전 rev {plan.expected ?? '—'}에서 보냅니다. 줄 목록은 원 작업이 더한 줄을 빼고 뺀 줄을 다시 더합니다. 되돌리기도 새 작업으로 남아 다시 되돌릴 수 있습니다.
              </span>
            </>
          )}
        </>
      )}
      {stale ? (
        <div className="note wa small">
          그사이 대상이 바뀌었습니다.{' '}
          <button type="button" className="linkish" onClick={() => (m.reset(), setPlan(undefined), setReload((x) => x + 1))}>
            지금 값을 다시 읽기
          </button>
        </div>
      ) : (
        <MutationError error={m.error} />
      )}
      {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone?.(o))} />}
    </Dialog>
  );
}
