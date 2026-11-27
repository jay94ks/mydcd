// SPDX-License-Identifier: Apache-2.0

// 비밀번호 묶음 승인 (UI-72, 데몬 #64·#66·#67, 캔버스 Vault '묶음 승인' 카드 · VaultIx '승인 · 승인 회수').
// 비밀번호는 입력 칸에만 있다가 보낼 때 꺼내고 바로 비운다. 어디에도 저장하지 않는다.
// 승인 서버로 한 번 지나가는 일은 웹 서버가 한다(SecretInput approve). 권한·비밀번호 판단은 sfcd 몫이다.
import { useEffect, useState, type ReactNode } from 'react';
import { ApiError, api, enc } from '../api/client';
import { apps as fetchApps, buildApprovePath, cdApprovals, externalBindApprovePath, cdApprovalsPath, deployApprovePath, grantedApprovals, pendingApprovals, toOp } from '../api/endpoints';
import type { DOp } from '../api/dto';
import type { GrantedApproval, GroupApproval, OpView, SecretView } from '../api/types';
import { Badge } from '../components/ui';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, casFailed, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { fmtTime } from '../lib/format';

const DAY = 86400;
export const ageText = (s?: number) => (!s ? '제한 없음' : s % DAY === 0 ? `${s / DAY}일` : s >= 3600 ? `${Math.round(s / 360) / 10}시간` : `${s}초`);

const ERR: Record<string, string> = {
  'approval-denied': '비밀번호가 맞지 않거나 이 묶음을 승인할 권한이 없습니다.',
  'approval-unknown': '승인 서버의 답을 받지 못했습니다. 비밀번호를 다시 넣어 보내 주세요.',
  'not-required': '이 묶음은 더 이상 승인을 기다리지 않습니다.',
  'already-approved': '이미 승인되었습니다.',
  'no-approver': '지금 이 묶음을 승인할 서버가 없습니다. 잠시 뒤 다시 해 주세요.',
};
function ApprovalErr({ e }: { e: unknown }) {
  if (e === undefined) return null;
  if (e instanceof ApiError && ERR[e.code]) return <div className={`note small ${e.code === 'approval-denied' ? 'er' : 'wa'}`}>{ERR[e.code]}</div>;
  return <MutationError error={e} />;
}
const settled = (e: unknown) => e instanceof ApiError && (e.code === 'not-required' || e.code === 'already-approved');

/** 비밀번호 한 칸과 승인 버튼. send가 끝나면(성공·실패 모두) 칸을 비운다 */
export function PasswordApprove({ children, send, off, onSettled }: { children: ReactNode; send: (password: string) => Promise<unknown>; off?: string; onSettled?: () => void }) {
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [e, setE] = useState<unknown>();
  useEffect(() => () => setPw(''), []);
  const go = async () => {
    const p = pw;
    setPw('');
    setBusy(true);
    setE(undefined);
    try {
      await send(p);
    } catch (x) {
      setE(x);
      if (settled(x)) onSettled?.();
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="col" style={{ gap: 8 }}>
      <span style={{ fontSize: 13, color: 'var(--text-2)' }}>{children}</span>
      <label className="field">
        <span>묶음 비밀번호</span>
        <span className="row" style={{ flexWrap: 'nowrap' }}>
          <input
            type="password"
            autoComplete="off"
            value={pw}
            disabled={!!off || busy}
            style={{ flex: 1, minWidth: 0 }}
            onChange={(x) => setPw(x.target.value)}
            onKeyDown={(x) => x.key === 'Enter' && pw && !busy && void go()}
          />
          <button className="btn primary" disabled={!pw || busy || !!off} title={off} onClick={() => void go()}>
            {busy ? '보내는 중…' : '승인'}
          </button>
        </span>
      </label>
      <ApprovalErr e={e} />
    </div>
  );
}

const svcText = (a: GroupApproval) => (a.services.length ? ` · 서비스 ${a.services.join(', ')}` : '');
const groupName = (a: GroupApproval, tenant: string) => (a.realm && a.realm !== tenant ? `${a.realm}/${a.group}` : a.group);

/**
 * 배포·빌드 작업이 묶음 승인을 기다릴 때(errorCode approval-required) 작업 패널 아래에 붙는다.
 * 승인되면 웹 서버가 같은 원본(begin-app, begin-image-build)을 보내고 갱신된 작업을 돌려준다.
 */
export function ApprovalPrompt({ tenant, op, onOp, kind = 'deploy', source = '' }: { tenant: string; op: OpView; onOp: (op: OpView) => void; kind?: 'deploy' | 'build' | 'registry-bind' | 'standalone'; source?: string }) {
  // 단독 컨테이너 up도 배포 승인 끝점을 쓴다(승인 목록의 kind = standalone)
  const what = kind === 'build' ? '빌드' : kind === 'registry-bind' ? '서버 연결' : kind === 'standalone' ? '실행' : '배포';
  const path = (t: string, id: string) => (kind === 'build' ? buildApprovePath(t, id) : kind === 'registry-bind' ? externalBindApprovePath(t, source, id) : deployApprovePath(t, id));
  if (op.errorCode !== 'approval-required' || !op.approvals?.length) return null;
  const reload = async () => {
    const r = await api.get<{ op: DOp }>(`/ops/${enc(op.id)}`);
    onOp(toOp(r.op));
  };
  return (
    <div className="note wa col" style={{ gap: 12 }}>
      <b>비밀번호 승인이 필요합니다</b>
      <span className="small">
        이 {what}{kind === 'registry-bind' || kind === 'standalone' ? '은' : '는'} 비밀번호로 보호된 묶음을 씁니다. 묶음마다 비밀번호를 넣어 승인하면 이어서 {kind === 'registry-bind' ? '연결' : what}합니다. 비밀번호는 승인 서버로 한 번 지나가고 어디에도 남지 않습니다.
      </span>
      {op.approvals.map((a) =>
        a.state === 'approved' ? (
          <span key={`${a.realm}/${a.group}`} className="row small">
            묶음 <b>{groupName(a, tenant)}</b>
            {svcText(a)} <Badge tone="ok">승인됨</Badge>
          </span>
        ) : (
          <PasswordApprove
            key={`${a.realm}/${a.group}`}
            onSettled={() => void reload()}
            send={async (password) => {
              const r = await api.post<{ op: DOp }>(path(tenant, op.id), { realm: a.realm, group: a.group, password });
              onOp(toOp(r.op));
            }}
          >
            묶음 <b>{groupName(a, tenant)}</b>
            {svcText(a)} {a.state === 'unknown' && <Badge tone="wa">답을 받지 못함 · 다시 보내기</Badge>}
          </PasswordApprove>
        ),
      )}
    </div>
  );
}

type CdWait = { app: string; candidate: string; digest: string; approvals: GroupApproval[] };

/** 자동 배포 후보가 기다리는 묶음 승인. CD를 등록한 사람만 읽을 수 있어서 403은 '내 일 아님'으로 넘긴다 */
async function cdWaits(tenant: string, signal: AbortSignal): Promise<CdWait[]> {
  const list = (await fetchApps(tenant, signal)).items.filter((a) => a.cd?.candidateDigest);
  const out: CdWait[] = [];
  for (const a of list) {
    try {
      const approvals = await cdApprovals(tenant, a.app, a.cd!.candidateDigest!, signal);
      if (approvals.some((x) => x.state !== 'approved')) out.push({ app: a.app, candidate: a.cd!.candidate || a.cd!.candidateDigest!.slice(0, 7), digest: a.cd!.candidateDigest!, approvals });
    } catch (e) {
      if (!(e instanceof ApiError && (e.status === 403 || e.status === 404 || e.status === 422))) throw e;
    }
  }
  return out;
}

/** 비밀값 보관함의 '묶음 승인 (UI-72)' 카드: 기다리는 승인(내 배포 · 내가 등록한 자동 배포 후보). 승인하면 onApproved로 승인 목록을 새로 읽는다 */
export function ApprovalCard({ tenant, items, canDeploy, onApproved }: { tenant: string; items: SecretView[]; canDeploy: boolean; onApproved?: () => void }) {
  const toast = useToast();
  const pend = usePoll((s) => pendingApprovals(tenant, s), [tenant]);
  const cd = usePoll((s) => cdWaits(tenant, s), [tenant]);
  const age = (group: string) => ageText(items.find((v) => v.kind === 'group' && v.id === group)?.maxApprovalAge);
  const off = canDeploy ? undefined : '이 작업 공간의 배포 권한이 필요합니다';
  const refresh = () => {
    void pend.refresh();
    void cd.refresh();
    onApproved?.();
  };
  const waits = (pend.data ?? []).filter((a) => a.state !== 'approved');
  const cdRows = (cd.data ?? []).flatMap((c) => c.approvals.filter((a) => a.state !== 'approved').map((a) => ({ c, a })));
  const done = (what: string) => {
    toast(what);
    refresh();
  };

  return (
    <section className="card">
      <h2>묶음 승인 (UI-72)</h2>
      {waits.length === 0 && cdRows.length === 0 ? (
        <span className="small muted">{pend.loading || cd.loading ? '불러오는 중…' : '기다리는 묶음 승인이 없습니다. 비밀번호로 보호된 묶음을 쓰는 앱 배포·빌드·외부 저장소 연결은 여기서 승인합니다.'}</span>
      ) : (
        <>
          {waits.map((a) => (
            <div key={`${a.opId}/${a.realm}/${a.group}`} className="col" style={{ gap: 6 }}>
              <PasswordApprove
                off={off}
                onSettled={refresh}
                send={async (password) => {
                  const path = a.kind === 'build' ? buildApprovePath(tenant, a.opId) : a.kind === 'registry-bind' ? externalBindApprovePath(tenant, a.source ?? '', a.opId) : deployApprovePath(tenant, a.opId);
                  const r = await api.post<{ op: DOp }>(path, { realm: a.realm, group: a.group, password });
                  const op = toOp(r.op);
                  const what = a.kind === 'build' ? `${a.context} 빌드` : a.kind === 'registry-bind' ? `${a.source} 서버 연결` : a.kind === 'standalone' ? `${a.standalone} 실행` : `${a.app} 배포`;
                  if (op.state === 'failed' && op.errorCode === 'approval-rejected') return done(`승인이 늦어 ${what}이 거절됐습니다. 다시 시작해 주세요.`);
                  done(
                    op.state === 'applied'
                      ? a.kind === 'build'
                        ? `${a.context} 빌드를 대기열에 넣었습니다.`
                        : a.kind === 'registry-bind'
                          ? `외부 저장소 ${a.source}을(를) ${a.node}에 연결했습니다.`
                          : a.kind === 'standalone'
                            ? `단독 컨테이너 ${a.standalone} 실행을 이어서 마쳤습니다.`
                            : `${a.app} 배포를 이어서 마쳤습니다.`
                      : `묶음 ${a.group}을 승인했습니다.`,
                  );
                }}
              >
                {a.kind === 'build' ? (
                  <>
                    빌드 컨텍스트 <b>{a.context}</b> 빌드가 비밀값 묶음 <b>{groupName(a, tenant)}</b> 사용 승인을 기다립니다.
                  </>
                ) : a.kind === 'registry-bind' ? (
                  <>
                    외부 저장소 <b>{a.source}</b>를 서버 {a.node}에 연결하려면 로그인 정보가 든 묶음 <b>{groupName(a, tenant)}</b> 승인이 필요합니다.
                  </>
                ) : a.kind === 'standalone' ? (
                  <>
                    단독 컨테이너 <b>{a.standalone}</b> 실행이 묶음 <b>{groupName(a, tenant)}</b> 사용 승인을 기다립니다{svcText(a)}.
                  </>
                ) : (
                  <>
                    앱 <b>{a.app}</b> 배포가 묶음 <b>{groupName(a, tenant)}</b> 사용 승인을 기다립니다{svcText(a)}.
                  </>
                )}
              </PasswordApprove>
              <span className="small muted">승인 유효 {age(a.group)}</span>
            </div>
          ))}
          {cdRows.map(({ c, a }) => (
            <div key={`cd/${c.app}/${a.realm}/${a.group}`} className="col" style={{ gap: 6 }}>
              <PasswordApprove
                off={off}
                onSettled={refresh}
                send={async (password) => {
                  await api.post(cdApprovalsPath(tenant, c.app), { candidate: c.digest, realm: a.realm, group: a.group, password });
                  done(`자동 배포 후보 ${c.candidate}의 묶음 ${a.group} 사용을 승인했습니다.`);
                }}
              >
                자동 배포 후보 <span className="mono">{c.candidate}</span>(앱 {c.app})이 묶음 <b>{groupName(a, tenant)}</b> 사용 승인을 요청합니다.
              </PasswordApprove>
              <span className="small muted">승인 유효 {age(a.group)}</span>
            </div>
          ))}
        </>
      )}
    </section>
  );
}

/** 이미 승인된 묶음 사용(REQ-42 · 데몬 #67). 철회한 것도 남는다. 회수는 목록의 collection을 expected로 보낸다 */
export function GrantedCard({ tenant, reload }: { tenant: string; reload: number }) {
  const granted = usePoll((s) => grantedApprovals(tenant, s), [tenant, reload]);
  const [revoke, setRevoke] = useState<{ g: GrantedApproval; expected: number }>();
  const grantedForbidden = granted.error instanceof ApiError && granted.error.status === 403;
  return (
    <section className="card">
      <h2>승인된 묶음 사용</h2>
      {grantedForbidden ? (
        <span className="small muted">승인 목록을 볼 권한이 없습니다.</span>
      ) : !granted.data ? (
        granted.error ? <MutationError error={granted.error} /> : <span className="small muted">불러오는 중…</span>
      ) : granted.data.items.length === 0 ? (
        <span className="small muted">아직 승인된 묶음 사용이 없습니다.</span>
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>묶음</th>
                <th>앱 · 서비스</th>
                <th>승인</th>
                <th>끝</th>
                <th>상태</th>
                <th aria-label="승인 회수" />
              </tr>
            </thead>
            <tbody>
              {granted.data.items.map((g) => (
                <tr key={g.id}>
                  <td>{g.realm !== tenant && g.realm ? `${g.realm}/${g.group}` : g.group}</td>
                  <td>
                    {g.standalone ? `${g.standalone} (단독 컨테이너)` : (g.app ?? g.purpose ?? '—')}
                    {g.deployment ? <span className="muted"> ({g.deployment})</span> : null}
                    {g.services.length > 0 && <span className="small muted"> · {g.services.join(', ')}</span>}
                    {g.nodes.length > 0 && <div className="small muted">서버 {g.nodes.join(', ')}</div>}
                  </td>
                  <td>
                    <span className="small">{fmtTime(g.approvedAt)}</span>
                    <div className="small muted">{g.user}</div>
                  </td>
                  <td className="small">{g.expiresAt ? fmtTime(g.expiresAt) : '제한 없음'}</td>
                  <td>{g.revoking ? <Badge tone="pr">회수 중{g.consumers ? ` · 쓰는 곳 ${g.consumers}` : ''}</Badge> : g.expiresAt && Date.parse(g.expiresAt) < Date.now() ? <Badge tone="un">끝남</Badge> : <Badge tone="ok">유효</Badge>}</td>
                  <td>
                    {!g.revoking && (
                      <button className="btn sm danger" onClick={() => setRevoke({ g, expected: granted.data!.collection })}>
                        승인 회수
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {revoke && <RevokeApprovalDialog tenant={tenant} g={revoke.g} expected={revoke.expected} onClose={() => setRevoke(undefined)} onDone={() => void granted.refresh()} />}
    </section>
  );
}

/** 승인 회수. expected는 창을 연 순간 목록의 collection(데몬 #67: 빼면 보낼 때 다시 읽은 값이 쓰여 화면과 어긋나도 막지 못함) */
function RevokeApprovalDialog({ tenant, g, expected, onClose, onDone }: { tenant: string; g: GrantedApproval; expected: number; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const finished = m.op?.state === 'applied';
  const send = async () => {
    if (m.op || m.error) m.reset();
    const o = await m.run(`/t/${enc(tenant)}/vault/approvals/granted/${enc(g.id)}/revoke`, { expected });
    if (o?.state === 'applied') onDone();
  };
  return (
    <Dialog
      title="승인을 회수할까요?"
      danger
      width={420}
      onClose={onClose}
      footer={
        finished ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn danger solid" disabled={m.busy} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '승인 회수'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 10 }}>
        <div>
          앱 {g.app}의 {g.group} 사용 승인을 거둡니다. 그 앱이 이 묶음의 비밀값을 다시 쓰려면 비밀번호로 다시 승인받아야 합니다.
        </div>
        {m.op && casFailed(m.op) && <div className="note wa small">그사이 승인 목록이 바뀌었습니다. 닫고 다시 해 주세요.</div>}
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
        <MutationError error={m.error} />
      </div>
    </Dialog>
  );
}
