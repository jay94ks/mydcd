// SPDX-License-Identifier: Apache-2.0

// 데이터 저장소 바꾸기·지우기 (UI-60 행 메뉴, UI-62 백업, UI-63 복원). 이관(UI-64)은 VolumeMove.tsx
// 계약: docs/reference/web-api.md "데이터 저장소 백업·복원·용량·삭제". 응답은 모두 {op}.
import { useState } from 'react';
import { ApiError } from '../api/client';
import { backupLimitPath, backupLimits, volumeDetail, volumePath } from '../api/endpoints';
import type { DBackupLimit, DVolumeBackup as DBackup, DVolumeRestore } from '../api/dto';

type DVolumeBackup = Omit<DBackup, 'createdAt'> & { createdAt: string };
import type { DiffLine, OpView, VolumeView } from '../api/types';
import { DiffView } from '../components/Code';
import { Badge, Card, Field, type Tone } from '../components/ui';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { DEFAULT_POLL_MS, usePoll } from '../lib/usePoll';
import { fmtBytes, fmtTime, middle } from '../lib/format';

export const NO_APP = '앱에 딸린 데이터 저장소만 백업할 수 있습니다.';

const GiB = 1024 ** 3;
const TiB = 1024 * GiB;

const ERR: Record<string, string> = {
  'no-app': NO_APP,
  ambiguous: '같은 이름의 데이터 저장소가 여러 앱에 있습니다. 새로 읽은 뒤 다시 하세요.',
  'backup-not-ready': '완료된 백업만 복원할 수 있습니다.',
  'restore-new-only': '새 데이터 저장소로만 복원할 수 있습니다.',
  'restore-too-large': '복원에 필요한 공간이 1 TiB를 넘습니다.',
  'capacity-grow-only': '용량은 늘리기만 할 수 있습니다.',
  'not-found': '데이터 저장소가 없습니다. 이미 지워졌을 수 있습니다.',
};
export function volErr(e: unknown) {
  if (!(e instanceof ApiError) || !ERR[e.code]) return undefined;
  return <div className="note wa">{ERR[e.code]}</div>;
}
const Err = ({ e }: { e: unknown }) => (e === undefined ? null : (volErr(e) ?? <MutationError error={e} />));

const appOf = (v: VolumeView) => (v.app ? { app: v.app } : {});

const BACKUP: Record<string, [string, Tone]> = {
  Reserved: ['진행 중', 'pr'],
  Ready: ['완료', 'ok'],
  Failed: ['실패', 'er'],
  Cancelling: ['취소 중', 'wa'],
  Cancelled: ['취소됨', 'un'],
  Deleting: ['지우는 중', 'wa'],
};
const RESTORE: Record<string, [string, Tone]> = {
  Reserved: ['복원 중', 'pr'],
  Cancelling: ['취소 중', 'wa'],
  Restored: ['완료', 'ok'],
  Cancelled: ['취소됨', 'un'],
};
const phaseBadge = (map: Record<string, [string, Tone]>, p: string) => {
  const [label, tone] = map[p] ?? [p, 'un' as Tone];
  return <Badge tone={tone}>{label}</Badge>;
};

/** 선택한 저장소의 백업·복원 행을 읽는다(진행 중이 있으면 기본 주기로 다시 읽음) */
export function useVolumeDetail(tenant: string, v: VolumeView | undefined) {
  return usePoll((s) => (v ? volumeDetail(tenant, v.name, v.app, s) : Promise.resolve(undefined)), [tenant, v?.name, v?.app], DEFAULT_POLL_MS);
}
type Detail = ReturnType<typeof useVolumeDetail>;

/** UI-62 · {name} 백업 */
export function BackupCard({ tenant, v, q, canDeploy, isAdmin, onChanged }: { tenant: string; v: VolumeView; q: Detail; canDeploy: boolean; isAdmin: boolean; onChanged: () => void }) {
  const m = useMutation();
  const [cancel, setCancel] = useState<DVolumeBackup>();
  const [del, setDel] = useState<DVolumeBackup>();
  const [limitEdit, setLimitEdit] = useState(false);
  const lq = usePoll((s) => (v.node ? backupLimits(tenant, v.node, s) : Promise.resolve([])), [tenant, v.node]);
  const ws = lq.data?.find((x) => x.scope === 'workspace');
  const server = lq.data?.find((x) => x.scope === 'server');
  // 백업·복원은 서버 전체 행과 작업 공간 행이 모두 있어야 된다(sfcd)
  const noLimit = lq.data && (!ws || !server) ? `${!ws ? '이 작업 공간' : `서버 ${v.node}`}에 백업 한도가 정해지지 않아 백업할 수 없습니다. 시스템 관리자에게 한도를 요청하세요.` : undefined;
  const full = ws && ws.used.count >= ws.count ? `작업 공간 백업 한도(${ws.count}개)를 다 썼습니다. 오래된 백업을 지운 뒤 하세요.` : undefined;
  const rows = (q.data?.backups ?? []).filter((b) => b.phase !== 'Deleted').sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const reason = !canDeploy ? '작업 공간 관리자 권한 필요' : !v.app ? NO_APP : (noLimit ?? full);
  const start = () => {
    // 끝난 작업 뒤의 새 백업은 새 opId로 보낸다(같은 opId는 같은 백업을 다시 돌려준다)
    if (m.op && m.op.state !== 'unknown') m.reset();
    void m.run(`${volumePath(tenant, v.name)}/backups`, appOf(v)).then(() => (q.refresh(), onChanged()));
  };
  return (
    <Card title={`${v.name} · 백업 (UI-62)`}>
      {rows.length === 0 ? (
        <span className="small muted">{q.data ? '백업이 없습니다.' : '불러오는 중…'}</span>
      ) : (
        <div style={{ overflowX: 'auto' }}>
        <table className="tbl">
          <tbody>
            {rows.map((b) => (
              <tr key={b.id}>
                <td title={b.id}>
                  <span className="mono">{middle(b.id, 10, 4)}</span>
                  <div className="small muted">
                    {fmtTime(b.createdAt)}
                    {b.bytes > 0 && ` · ${fmtBytes(b.bytes)}`}
                  </div>
                </td>
                <td className="wrap">
                  {phaseBadge(BACKUP, b.phase)}
                  {b.failure && <div className="small muted">{b.failure}</div>}
                </td>
                <td style={{ textAlign: 'right' }}>
                  {b.phase === 'Reserved' && (
                    <button className="btn sm" disabled={!canDeploy} onClick={() => setCancel(b)}>
                      취소
                    </button>
                  )}
                  {b.phase === 'Ready' && (
                    <button className="btn sm danger" disabled={!canDeploy} onClick={() => setDel(b)}>
                      지우기
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
      {v.app && noLimit && <div className="note er">{noLimit}</div>}
      <div className="row between">
        <span className="small muted" title={ws ? `작업 공간 한도: ${ws.count}개 · ${fmtBytes(ws.bytes)} (사용 ${ws.used.count}개 · ${fmtBytes(ws.used.bytes)})` : undefined}>
          {ws ? (
            <>
              보존 한도 {ws.count}개 · {fmtBytes(ws.bytes)}
              <span> (사용 {ws.used.count}개)</span>
            </>
          ) : lq.data ? (
            '보존 한도 없음'
          ) : (
            '보존 한도 …'
          )}
          {isAdmin && lq.data && (
            <>
              {' '}
              <button className="btn sm" onClick={() => setLimitEdit(true)}>
                한도 바꾸기…
              </button>
            </>
          )}
        </span>
        <button className="btn primary" disabled={!!reason || m.busy} title={reason} onClick={start}>
          지금 백업
        </button>
      </div>
      {limitEdit && v.node && <BackupLimitDialog tenant={tenant} node={v.node} rows={lq.data ?? []} onClose={() => setLimitEdit(false)} onDone={() => void lq.refresh()} />}
      <Err e={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), void q.refresh())} />}
      {cancel && (
        <OpConfirm
          title={`${cancel.id}를 취소할까요?`}
          danger
          action="백업 취소"
          path={`${volumePath(tenant, v.name)}/backups/${encodeURIComponent(cancel.id)}/cancel`}
          body={appOf(v)}
          onClose={() => setCancel(undefined)}
          onDone={() => void q.refresh()}
        >
          <p>지금까지 복사한 부분을 지웁니다. 다른 백업에는 영향이 없습니다.</p>
        </OpConfirm>
      )}
      {del && (
        <OpConfirm
          title={`${del.id}를 지울까요?`}
          danger
          action="백업 지우기"
          method="DELETE"
          path={`${volumePath(tenant, v.name)}/backups/${encodeURIComponent(del.id)}`}
          body={appOf(v)}
          onClose={() => setDel(undefined)}
          onDone={() => void q.refresh()}
        >
          <p>
            백업 {del.id}({fmtBytes(del.bytes)})를 지웁니다. 되돌릴 수 없습니다. 이 백업에서 진행 중인 복원이 있으면 지울 수 없습니다.
          </p>
        </OpConfirm>
      )}
    </Card>
  );
}

/** UI-63 복원. sfcd는 새 데이터 저장소로만 복원한다 */
export function RestoreCard({ tenant, v, q, canDeploy, taken, onChanged }: { tenant: string; v: VolumeView; q: Detail; canDeploy: boolean; taken: string[]; onChanged: () => void }) {
  const ready = (q.data?.backups ?? []).filter((b) => b.phase === 'Ready');
  const [pick, setPick] = useState('');
  const [name, setName] = useState(`${v.name}-restored`);
  const [plan, setPlan] = useState<DVolumeBackup>();
  const [cancel, setCancel] = useState<DVolumeRestore>();
  const b = ready.find((x) => x.id === pick) ?? ready[0];
  const restores = (q.data?.restores ?? []).filter((r) => r.phase !== 'Cancelled');
  const nameErr = !/^[a-z0-9][a-z0-9-]{0,62}$/.test(name) ? "소문자·숫자·'-'로 씁니다." : taken.includes(name) ? '이미 있는 이름입니다.' : undefined;
  return (
    <Card title="복원 (UI-63)">
      <Field label="백업">
        <select value={b?.id ?? ''} onChange={(e) => setPick(e.target.value)} disabled={ready.length === 0}>
          {ready.length === 0 && <option value="">완료된 백업이 없습니다</option>}
          {ready.map((x) => (
            <option key={x.id} value={x.id}>
              {x.id} · {fmtTime(x.createdAt)}
            </option>
          ))}
        </select>
      </Field>
      <Field label="대상" hint="새 데이터 저장소로만 복원합니다. 백업이 있는 서버에 만들어집니다." error={nameErr}>
        <input className="mono" aria-label="새 데이터 저장소 이름" value={name} onChange={(e) => setName(e.target.value.trim())} />
      </Field>
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="btn primary" disabled={!b || !!nameErr || !canDeploy} title={canDeploy ? undefined : '작업 공간 관리자 권한 필요'} onClick={() => setPlan(b)}>
          복원 계획
        </button>
      </div>
      {restores.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
        <table className="tbl">
          <tbody>
            {restores.map((r) => (
              <tr key={r.id}>
                <td className="small" title={`${r.id} · 백업 ${r.backup}`}>
                  → <span className="mono">{r.target}</span>
                </td>
                <td>{phaseBadge(RESTORE, r.phase)}</td>
                <td style={{ textAlign: 'right' }}>
                  {r.phase === 'Reserved' && (
                    <button className="btn sm" disabled={!canDeploy} onClick={() => setCancel(r)}>
                      취소
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
      {plan && <RestorePlanDialog tenant={tenant} v={v} b={plan} target={name} onClose={() => setPlan(undefined)} onDone={() => (void q.refresh(), onChanged())} />}
      {cancel && (
        <OpConfirm
          title={`${cancel.id} 복원을 취소할까요?`}
          danger
          action="복원 취소"
          path={`${volumePath(tenant, v.name)}/restores/${encodeURIComponent(cancel.id)}/cancel`}
          body={appOf(v)}
          onClose={() => setCancel(undefined)}
          onDone={() => void q.refresh()}
        >
          <p>복원을 멈추고 새 데이터 저장소 {cancel.target}에 쓴 부분을 지웁니다. 백업은 그대로 남습니다.</p>
        </OpConfirm>
      )}
    </Card>
  );
}

function RestorePlanDialog({ tenant, v, b, target, onClose, onDone }: { tenant: string; v: VolumeView; b: DVolumeBackup; target: string; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  // 연 순간의 대상·백업을 고정한다(같은 opId로 다시 보낼 때 본문이 같아야 한다)
  const [body] = useState(() => ({ ...appOf(v), backup: b.id, target: { name: target, ...appOf(v) } }));
  return (
    <Dialog
      title={`${b.id} 복원 계획`}
      onClose={onClose}
      footer={
        m.op ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={m.busy} onClick={() => void m.run(`${volumePath(tenant, v.name)}/restore`, body).then((o) => o?.state === 'applied' && onDone())}>
              복원 시작
            </button>
          </>
        )
      }
    >
      <dl className="kv">
        <dt>대상</dt>
        <dd>
          새 데이터 저장소 <span className="mono">{target}</span>
        </dd>
        <dt>크기</dt>
        <dd>{b.bytes > 0 ? fmtBytes(b.bytes) : '—'}</dd>
        <dt>서버</dt>
        <dd>{b.node}</dd>
      </dl>
      <p className="small muted">기존 {v.name}에는 복원할 수 없습니다. 새 데이터 저장소로만 복원하며, 백업이 있는 서버에 만들어집니다.</p>
      <Err e={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

/** 용량 늘리기(시스템 관리자만, 늘리기만) */
export function CapacityDialog({ tenant, v, onClose, onDone }: { tenant: string; v: VolumeView; onClose: () => void; onDone: () => void }) {
  const now = v.capacityBytes ?? 0;
  const [gib, setGib] = useState(String(Math.ceil(now / GiB) || 10));
  const [sent, setSent] = useState<number>();
  const m = useMutation();
  const bytes = Math.round(Number(gib) * GiB);
  const bad = !(Number(gib) > 0) ? '용량을 GiB로 넣으세요.' : bytes <= now ? `지금(${fmtBytes(now)})보다 커야 합니다.` : bytes > TiB ? '1 TiB까지입니다.' : undefined;
  const go = () => {
    const b = sent ?? bytes;
    setSent(b);
    void m.run(`${volumePath(tenant, v.name)}/capacity`, { ...appOf(v), bytes: b }, 'PUT').then((o) => o?.state === 'applied' && onDone());
  };
  return (
    <Dialog
      title={`${v.name} 용량 늘리기`}
      onClose={onClose}
      footer={
        m.op ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={(!!bad && sent === undefined) || m.busy} onClick={go}>
              늘리기
            </button>
          </>
        )
      }
    >
      <p>
        지금 용량 {now ? fmtBytes(now) : '없음'}
        {v.usedBytes !== undefined && ` · 사용 ${fmtBytes(v.usedBytes)}`}
      </p>
      <Field label="새 용량 (GiB)" error={sent === undefined ? bad : undefined} hint="늘리기만 됩니다. 줄일 수 없습니다.">
        <input inputMode="decimal" value={gib} onChange={(e) => setGib(e.target.value)} disabled={sent !== undefined} />
      </Field>
      <Err e={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

/** 삭제(공유) / 등록 해제(고정). 이름을 넣어야 켜진다 */
export function DeleteVolumeDialog({ tenant, v, onClose, onDone }: { tenant: string; v: VolumeView; onClose: () => void; onDone: () => void }) {
  const fixed = v.kind === 'fixed';
  return (
    <OpConfirm
      title={fixed ? `${v.name} 등록을 해제할까요?` : `${v.name}를 삭제할까요?`}
      danger
      action={fixed ? '등록 해제' : '삭제'}
      method="DELETE"
      path={volumePath(tenant, v.name)}
      body={appOf(v)}
      confirmName={v.name}
      onClose={onClose}
      onDone={onDone}
    >
      {fixed ? (
        <p>
          등록만 해제합니다. 서버 {v.node}
          {v.storage ? ` · ${v.storage}` : ''}의 데이터는 그대로 남습니다.
        </p>
      ) : (
        <p>{v.usedBytes !== undefined ? `${fmtBytes(v.usedBytes)} 데이터를 지웁니다.` : '데이터를 지웁니다.'} 되돌릴 수 없습니다.</p>
      )}
      {v.consumers > 0 && <div className="note wa">쓰는 컨테이너가 {v.consumers}개 있어 지금은 지울 수 없습니다. 먼저 앱에서 떼세요.</div>}
    </OpConfirm>
  );
}

/** 확인 한 번으로 보내는 작업(취소·지우기). confirmName이 있으면 이름을 넣어야 켜진다 */
function OpConfirm({ title, action, danger, path, body, method = 'POST', confirmName, children, onClose, onDone }: { title: string; action: string; danger?: boolean; path: string; body: Record<string, unknown>; method?: 'POST' | 'DELETE'; confirmName?: string; children: React.ReactNode; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [typed, setTyped] = useState('');
  return (
    <Dialog
      title={title}
      danger={danger}
      width={420}
      onClose={onClose}
      footer={
        m.op ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className={danger ? 'btn danger solid' : 'btn primary'} disabled={m.busy || (!!confirmName && typed !== confirmName)} onClick={() => void m.run(path, body, method).then((o) => o?.state === 'applied' && onDone())}>
              {action}
            </button>
          </>
        )
      }
    >
      {children}
      {confirmName && (
        <Field label={<>확인하려면 <b className="mono">{confirmName}</b>을(를) 입력하세요</>}>
          <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value)} disabled={!!m.op} />
        </Field>
      )}
      <Err e={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

/** 백업 한도 바꾸기(시스템 관리자만). 작업 공간 행과 서버 전체 행을 따로 정한다. 변경 검토 뒤 적용 */
function BackupLimitDialog({ tenant, node, rows, onClose, onDone }: { tenant: string; node: string; rows: DBackupLimit[]; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [scope, setScope] = useState<'workspace' | 'server'>('workspace');
  const [review, setReview] = useState(false);
  // 연 순간의 행을 고정한다(expected와 지금 값이 보내는 동안 흔들리지 않게)
  const [fixed] = useState(rows);
  const row = fixed.find((x) => x.scope === scope);
  const init = (r?: DBackupLimit) => ({ count: String(r?.count ?? 5), gib: String(r ? Math.round((r.bytes / GiB) * 10) / 10 : 50), sc: String(r?.stagingCount ?? 1), sgib: String(r ? Math.round((r.stagingBytes / GiB) * 10) / 10 : 10) });
  const [f, setF] = useState(() => ({ workspace: init(fixed.find((x) => x.scope === 'workspace')), server: init(fixed.find((x) => x.scope === 'server')) }));
  const cur = f[scope];
  const set = (k: keyof typeof cur) => (e: { target: { value: string } }) => setF((x) => ({ ...x, [scope]: { ...x[scope], [k]: e.target.value } }));
  const int = (x: string) => (/^\d+$/.test(x.trim()) ? Number(x) : NaN);
  const body = { scope, count: int(cur.count), bytes: Math.round(Number(cur.gib) * GiB), stagingCount: int(cur.sc), stagingBytes: Math.round(Number(cur.sgib) * GiB), expected: row?.revision ?? 0 };
  const bad = [body.count, body.stagingCount].some((x) => !Number.isInteger(x) || x < 0) || !(body.bytes >= 0) || !(body.stagingBytes >= 0) ? '개수는 0 이상의 정수, 크기는 GiB로 넣으세요.' : undefined;
  const hidden = row?.hidden;
  const toReview = () => {
    // 다른 값으로 다시 보내면 새 작업이다(같은 opId에 다른 본문은 op-conflict)
    if (m.op || m.error !== undefined) m.reset();
    setReview(true);
  };
  const lines: DiffLine[] = [];
  const pair = (k: string, a: string | undefined, b: string) => {
    if (a === b) lines.push({ op: ' ', text: `${k}: ${b}` });
    else {
      if (a !== undefined) lines.push({ op: '-', text: `${k}: ${a}` });
      lines.push({ op: '+', text: `${k}: ${b}` });
    }
  };
  pair('보존 개수', row && !hidden ? String(row.count) : undefined, String(body.count));
  pair('보존 크기', row && !hidden ? fmtBytes(row.bytes) : undefined, fmtBytes(body.bytes));
  pair('동시 진행 개수', row && !hidden ? String(row.stagingCount) : undefined, String(body.stagingCount));
  pair('임시 보관 크기', row && !hidden ? fmtBytes(row.stagingBytes) : undefined, fmtBytes(body.stagingBytes));
  return (
    <Dialog
      title={review ? `${scope === 'server' ? `서버 전체 (${node})` : `${tenant} · ${node}`} 백업 한도 변경` : '백업 한도 바꾸기'}
      onClose={onClose}
      footer={
        m.op?.state === 'applied' ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : review ? (
          <>
            <button className="btn" disabled={m.busy} onClick={() => setReview(false)}>
              취소
            </button>
            <button className="btn primary" disabled={m.busy} onClick={() => void m.run(backupLimitPath(tenant, node), body, 'PUT').then((o) => o?.state === 'applied' && onDone())}>
              적용
            </button>
          </>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={!!bad || hidden} onClick={toReview}>
              변경 검토
            </button>
          </>
        )
      }
    >
      {review ? (
        <DiffView lines={lines} compact={false} />
      ) : (
        <>
          <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
            <label className="check">
              <input type="radio" name="limit-scope" checked={scope === 'workspace'} onChange={() => setScope('workspace')} /> 이 작업 공간 ({tenant})
            </label>
            <label className="check">
              <input type="radio" name="limit-scope" checked={scope === 'server'} onChange={() => setScope('server')} /> 서버 전체 ({node})
            </label>
          </div>
          <div className="g2">
            <Field label="보존 개수">
              <input inputMode="numeric" value={cur.count} onChange={set('count')} />
            </Field>
            <Field label="보존 크기 (GiB)">
              <input inputMode="decimal" value={cur.gib} onChange={set('gib')} />
            </Field>
            <Field label="동시 진행 개수">
              <input inputMode="numeric" value={cur.sc} onChange={set('sc')} />
            </Field>
            <Field label="임시 보관 크기 (GiB)">
              <input inputMode="decimal" value={cur.sgib} onChange={set('sgib')} />
            </Field>
          </div>
          {row && !hidden && (
            <span className="small muted">
              지금 사용 {row.used.count}개 · {fmtBytes(row.used.bytes)} · 진행 {row.used.stagingCount}개 · {fmtBytes(row.used.stagingBytes)}. 이미 잡힌 양보다 작게 하면 거절됩니다.
            </span>
          )}
          {!row && <span className="small muted">아직 한도가 없습니다. 적용하면 새로 만듭니다.</span>}
          <span className="small muted">한도는 넘으면 새 백업을 막는 상한입니다. 오래된 백업을 자동으로 지우지 않습니다.</span>
          {bad && <div className="note er small">{bad}</div>}
        </>
      )}
      <Err e={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}
