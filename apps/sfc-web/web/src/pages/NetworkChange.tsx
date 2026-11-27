// SPDX-License-Identifier: Apache-2.0

// 망 변경 단계 화면(UI-51)과 망 지우기(UI-50 행 메뉴).
// 멤버(서버) 하나씩 계획 → 비우기 → 막기(사용 중지 확인) → 확정. payload는 데몬이 멤버 행에서 만들고, 판단은 sfcd가 한다.
// 막기(사용 중지 확인)와 서버 빼기는 데몬이 서버가 서명한 정리 보고(closure)를 넣는다. 아직 쓰는 컨테이너가 있으면 409 in-use.
import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, ApiError, newOpId } from '../api/client';
import { networkChange, networkPath, toOp } from '../api/endpoints';
import { eulReul } from '../lib/josa';
import { inSystem, parseCidr, SYSTEM_TEXT } from '../lib/cidr';
import type { DNetworkChange, DNetworkClosure, DOp } from '../api/dto';
import type { BridgeView, DiffLine, NetworkDnsView, NetworkView, OpView } from '../api/types';
import { DiffView } from '../components/Code';
import { useTenantRole } from '../auth/session';
import { Badge, Card, Field, HelpBox, PageHeader } from '../components/ui';
import { Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { StepsDialog, type Step } from '../components/StepsDialog';
import { DEFAULT_POLL_MS, usePoll } from '../lib/usePoll';
import { NoTenant } from './Deploy';
import { usePhone } from '../lib/viewport';
import { MDetail, MSec, useReadOnlyTop } from '../mobile/ReadOnly';
import { ResourceUsersDialog } from './ResourceUsers';
import { bridgeEnds } from './Bridges';

type Member = DNetworkChange['members'][number];
type Tone = 'ok' | 'pr' | 'wa' | 'er' | 'un';

const CIDR = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
const cidrShape = (v: string) => {
  const m = CIDR.exec(v.trim());
  return !!m && m.slice(1, 5).every((x) => Number(x) <= 255) && Number(m[5]) >= 8 && Number(m[5]) <= 29;
};
/** 주소(CIDR 또는 터널 주소 하나)가 시스템 망 대역(10.254.0.0/16)과 겹치는가 */
const systemHit = (v: string) => {
  const t = v.trim();
  const c = parseCidr(t.includes('/') ? t : `${t}/32`);
  if (c) return inSystem(c);
  const m = /^(\d{1,3})\.(\d{1,3})\./.exec(t);
  return !!m && m[1] === '10' && m[2] === '254';
};
const validCidr = (v: string) => cidrShape(v) && !systemHit(v);
const cidrMsg = (v: string) => (systemHit(v) ? SYSTEM_TEXT : 'IPv4 CIDR(/8~/29)로 넣으세요');

const ERR: Record<string, string> = {
  'in-use': '아직 옛 주소를 쓰는 컨테이너가 있어 막을 수 없습니다. 그 컨테이너를 다시 시작하거나 멈춘 뒤 다시 하세요.',
  unreachable: '서버가 응답하지 않아 정리 보고를 받을 수 없습니다. 서버가 돌아온 뒤 다시 하세요.',
  'not-draining': '비우는 중인 서버만 사용 중지를 확인할 수 있습니다. 새로 읽은 뒤 다시 하세요.',
  'not-drained': '먼저 비워야 뺄 수 있습니다.',
  'not-fenced': '모든 참여 서버가 사용 중지되어야 합니다.',
  'not-reserved': '비우기를 시작한 뒤에는 취소할 수 없습니다.',
  'change-pending': '이미 진행 중인 변경이 있습니다. 새로 읽은 뒤 다시 하세요.',
  'dns-enabled': '도메인 이름을 먼저 꺼야 지울 수 있습니다.',
  'bridge-attached': '이 망에 가상 브릿지가 남아 있어 지울 수 없습니다. 먼저 가상 브릿지 탭에서 브릿지를 끊으세요.',
  'toggle-not-allowed': '‘이 서버에서만’ 망에는 서버를 더할 수 없습니다. 먼저 망 줄 ⋯에서 ‘다른 서버와 잇게 바꾸기’를 하세요.',
};
export function netErr(e: unknown) {
  if (!(e instanceof ApiError) || !ERR[e.code]) return undefined;
  return (
    <div className="note wa">
      {ERR[e.code]}
      {e.code === 'in-use' && e.message ? <span className="small muted"> ({e.message})</span> : null}
    </div>
  );
}

/** 아직 쓰는 컨테이너 수. sfcd가 재지 않았으면 null(0으로 짐작하지 않는다, 데몬 #298) */
const pendingOf = (c?: DNetworkClosure): number | null => (!c ? null : c.closed || c.state === 'closed' ? 0 : c.pendingEndpoints);

/** '남은 사용' 칸: 비운 서버의 정리 보고 */
export function Remaining({ c }: { c?: DNetworkClosure }) {
  if (!c) return <span className="muted">—</span>;
  if (c.unreachable || c.state === 'unreachable') return <Badge tone="er">서버 응답 없음</Badge>;
  const n = pendingOf(c);
  if (n === null) return <span className="muted" title="서버가 아직 정리 보고를 세지 않았습니다">확인 중</span>;
  if (n === 0) return <span>0</span>;
  return <span>{n} 컨테이너</span>;
}

const PHASE: Record<string, [string, Tone]> = {
  none: ['변경 없음', 'un'],
  reserved: ['계획됨', 'pr'],
  draining: ['비우는 중 · 사용 중지 확인 대기', 'pr'],
  fenced: ['사용 중지됨', 'ok'],
};
const STAGE: Record<string, [number, string]> = { '': [1, ''], drain: [2, '비우기 대기'], fence: [3, '사용 중지 확인 단계'], commit: [4, '적용 단계'] };
const STEPS = ['계획', '비우는 중', '참여 서버 사용 중지 확인', '적용'];

const post = (path: string, body: Record<string, unknown>) => (opId: string) => api.post<{ op: DOp }>(path, { ...body, opId });

export function NetworkChangePage() {
  return usePhone() ? <MNetworkChange /> : <DesktopNetworkChange />;
}

/** 휴대폰 망 변경 (UI-M1 보기만 상세): 단계 · 변경 내용 · 참여 서버별 진행을 읽기만 한다 */
function MNetworkChange() {
  const { name = '' } = useParams();
  const { tenant } = useTenantRole();
  const q = usePoll((s) => (tenant ? networkChange(tenant, name, s) : Promise.resolve(undefined)), [tenant, name], DEFAULT_POLL_MS);
  useReadOnlyTop(`${name} 변경`, tenant ? `망 · 작업 공간 ${tenant}` : '망', '계획·비우기·사용 중지 확인·적용·취소는 넓은 화면에서', [name, tenant]);
  if (!tenant) return <NoTenant />;
  return (
    <Load q={q} what="망을 불러오지 못했습니다">
      {(d) => {
        if (!d) return null;
        const active = d.members.some((m) => m.phase !== 'none');
        const [cur, label] = STAGE[d.next ?? ''] ?? [1, ''];
        const chgId = d.members.find((m) => m.phase !== 'none')?.change?.id;
        return (
          <>
            <MDetail
              title={name}
              badge={active ? ['pr', label || STEPS[cur - 1]] : ['un', '진행 중인 변경 없음']}
              rows={[
                ['단계', active ? `${cur}/${STEPS.length} ${STEPS[cur - 1]}` : '—'],
                chgId && ['변경 ID', <span key="c" className="mono">{chgId}</span>],
                ['원 버전', <code key="r">{d.networksRevision}</code>],
              ]}
            />
            <MSec>참여 서버 {d.members.length}</MSec>
            {d.members.map((m) => {
              const [t, tone] = PHASE[m.phase] ?? [m.phase, 'un'];
              return (
                <MDetail
                  key={m.node}
                  title={m.node}
                  badge={[tone, t]}
                  rows={[
                    ['현재', <span key="c" className="mono">{m.cidr}</span>],
                    ['목표', <span key="t" className="mono">{m.target === m.cidr ? `${m.cidr} (유지)` : m.target}</span>],
                    ['남은 사용', <Remaining key="r" c={d.closure.find((c) => c.node === m.node)} />],
                  ]}
                />
              );
            })}
          </>
        );
      }}
    </Load>
  );
}

function DesktopNetworkChange() {
  const { name = '' } = useParams();
  const { tenant, canDeploy } = useTenantRole();
  const q = usePoll((s) => (tenant ? networkChange(tenant, name, s) : Promise.resolve(undefined)), [tenant, name], DEFAULT_POLL_MS);
  const [targets, setTargets] = useState<Record<string, string>>({});
  const [dlg, setDlg] = useState<'plan' | 'drain' | 'cancel' | 'commit' | 'reconf'>();
  const [fence, setFence] = useState<string>();
  const [want, setWant] = useState<string>();
  if (!tenant) return <NoTenant />;
  const v = q.data;
  const base = networkPath(tenant, name);
  const active = v?.members.some((m) => m.phase !== 'none');
  const [cur, label] = STAGE[v?.next ?? ''] ?? [1, ''];
  const stageOf = (i: number) => (!active ? (i === 0 ? 'on' : '') : i + 1 < cur ? 'done' : i + 1 === cur ? 'on' : '');
  const edit = (m: Member) => targets[m.node] ?? m.target;
  const changed = (v?.members ?? []).filter((m) => m.phase === 'none' && edit(m).trim() !== m.cidr);
  // 확정(commit)은 모든 멤버의 change 버전을 넣으므로, 하나라도 바꾸면 그대로 두는 서버도 같은 주소로 계획·비우기를 한다.
  const planned = changed.length ? (v?.members ?? []).filter((m) => m.phase === 'none') : [];
  const bad = changed.some((m) => !validCidr(edit(m)));
  const done = () => {
    setTargets({});
    q.refresh();
  };
  const reserved = (v?.members ?? []).filter((m) => m.phase === 'reserved');
  const draining = (v?.members ?? []).filter((m) => m.phase === 'draining');
  const notFenced = (v?.members ?? []).filter((m) => m.phase !== 'fenced');
  const tun = v?.kind === 'tun';
  const chgId = v?.members.find((m) => m.phase !== 'none')?.change?.id;
  return (
    <>
      <PageHeader
        crumbs={
          <>
            <Link to="/shared/networks">망</Link> / {name} / 변경
          </>
        }
        title={`${name} 변경`}
        ids="UI-51"
        actions={
          <>
            {label && <Badge tone="pr">{label}</Badge>}
            <Refresh q={q} />
            <button className="btn danger" disabled={!canDeploy || !reserved.length} title={!reserved.length ? (active ? '비우기를 시작한 뒤에는 취소할 수 없습니다' : '진행 중인 변경이 없습니다') : undefined} onClick={() => setDlg('cancel')}>
              변경 취소
            </button>
          </>
        }
      />
      <HelpBox terms="참여 서버 (member) · 사용 중지 확인 (fence) · 적용 (commit)">
        <b>이 화면은</b> 이미 쓰는 망의 주소 범위 같은 설정을 바꾸는 단계별 절차입니다. 참여 서버가 모두 옛 설정 사용을 멈춘 것을 확인한 뒤에만 적용합니다.
      </HelpBox>
      <ol className="steps">
        {STEPS.map((s, i) => {
          const st = stageOf(i);
          return (
            <li key={s} className={st}>
              {st === 'done' ? '✓ ' : ''}
              {i + 1} {s}
            </li>
          );
        })}
      </ol>
      <Load q={q} what="망을 불러오지 못했습니다">
        {(d) =>
          !d ? null : (
            <>
              <div className="grid-2">
                <Card title="변경 내용">
                  <div className="table-wrap">
                    <table className="tbl">
                      <thead>
                        <tr>
                          <th>참여 서버</th>
                          <th>현재</th>
                          <th>목표</th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.members.map((m) => (
                          <tr key={m.node}>
                            <td>{m.node}</td>
                            <td className="mono">{m.cidr}</td>
                            <td>
                              {m.phase === 'none' && tun && canDeploy ? (
                                <input className="mono" aria-label={`${m.node} 목표 CIDR`} value={edit(m)} onChange={(e) => setTargets((t) => ({ ...t, [m.node]: e.target.value }))} style={{ width: 170 }} />
                              ) : m.target === m.cidr ? (
                                <span className="mono">{m.cidr} (유지)</span>
                              ) : (
                                <b className="mono" style={{ color: 'var(--accent)' }}>
                                  {m.target}
                                </b>
                              )}
                              {m.phase === 'none' && edit(m).trim() !== m.cidr && !validCidr(edit(m)) && <div className="small" style={{ color: 'var(--er)' }}>{cidrMsg(edit(m))}</div>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <span className="small muted">
                    {chgId ? (
                      <>
                        변경 ID <span className="mono">{chgId}</span> ·{' '}
                      </>
                    ) : null}
                    원 버전 {d.networksRevision} · CIDR 후보는 예약되어 다른 망이 쓸 수 없습니다.
                  </span>
                  <div className="note">새 앱·논리 망 입장만 막히고, 이미 배포된 앱의 원 참조는 유지됩니다.</div>
                  {!active && tun && (
                    <div className="row" style={{ justifyContent: 'flex-end' }}>
                      <button className="btn primary" disabled={!canDeploy || !changed.length || bad} onClick={() => setDlg('plan')}>
                        변경 계획
                      </button>
                    </div>
                  )}
                  {reserved.length > 0 && (
                    <div className="row" style={{ justifyContent: 'flex-end' }}>
                      <button className="btn primary" disabled={!canDeploy} onClick={() => setDlg('drain')}>
                        비우기 시작
                      </button>
                    </div>
                  )}
                </Card>
                <Card title="참여 서버별 진행">
                  <div className="table-wrap">
                    <table className="tbl">
                      <thead>
                        <tr>
                          <th>참여 서버</th>
                          <th>상태</th>
                          <th>남은 사용</th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.members.map((m) => {
                          const [t, tone] = PHASE[m.phase] ?? [m.phase, 'un'];
                          return (
                            <tr key={m.node}>
                              <td>{m.node}</td>
                              <td>
                                <Badge tone={tone}>{t}</Badge>
                              </td>
                              <td>
                                <Remaining c={d.closure.find((c) => c.node === m.node)} />
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  <span className="small muted">모든 참여 서버가 사용 중지됨이 되어야 적용할 수 있습니다. 적용은 실제 통신 재개와 별도로 표시됩니다.</span>
                  <div className="row" style={{ justifyContent: 'flex-end', flexWrap: 'wrap' }}>
                    {draining.map((m) => (
                      <button key={m.node} className="btn" disabled={!canDeploy} onClick={() => setFence(m.node)}>
                        {m.node} 사용 중지 확인
                      </button>
                    ))}
                    <button className="btn primary" disabled={!canDeploy || notFenced.length > 0 || !tun} title={notFenced.length ? `${notFenced.map((m) => m.node).join(', ')}가 아직 사용 중지되지 않아 적용할 수 없습니다.` : undefined} onClick={() => setDlg('commit')}>
                      적용
                    </button>
                  </div>
                </Card>
              </div>
              {tun && (
                <Card title="서버 간 재구성 (참여 서버 추가·제거)">
                  <span className="small">참여 서버 목록 전체를 목표로 지정합니다. 빈 목록은 도메인 이름 해제·원 정산 뒤 망 전체 폐기를 뜻합니다.</span>
                  <div className="row" style={{ alignItems: 'flex-end', flexWrap: 'wrap' }}>
                    <Field label="목표 참여 서버">
                      <input className="mono" value={want ?? d.members.map((m) => m.node).join(', ')} onChange={(e) => setWant(e.target.value)} style={{ minWidth: 300 }} />
                    </Field>
                    <button className="btn" disabled={!canDeploy || notFenced.length > 0} title={notFenced.length ? '모든 참여 서버가 사용 중지되어야 재구성할 수 있습니다' : undefined} onClick={() => setDlg('reconf')}>
                      재구성 계획
                    </button>
                  </div>
                </Card>
              )}
              {dlg === 'plan' && (
                <StepsDialog
                  title={`${name} 변경 계획`}
                  action="계획 · 비우기 시작"
                  renderError={netErr}
                  intro={<span>참여 서버마다 계획을 만들고 바로 비우기를 시작합니다. 적용은 모든 참여 서버를 함께 다시 만들므로 주소를 그대로 두는 서버도 포함합니다. 비우기를 시작하면 그 서버에 새 사용이 막히고, 변경을 취소할 수 없습니다.</span>}
                  steps={planned.flatMap((m): Step[] => [
                    { key: `plan/${m.node}`, label: `${m.node} 계획: ${edit(m).trim() === m.cidr ? `${m.cidr} 유지` : `${m.cidr} → ${edit(m).trim()}`}`, send: post(`${base}/change`, { node: m.node, cidr: edit(m).trim() }) },
                    { key: `drain/${m.node}`, label: `${m.node} 비우기`, send: post(`${base}/change/drain`, { node: m.node }) },
                  ])}
                  onClose={() => setDlg(undefined)}
                  onDone={done}
                />
              )}
              {dlg === 'drain' && <StepsDialog title={`${name} 비우기`} renderError={netErr} steps={reserved.map((m) => ({ key: `drain/${m.node}`, label: `${m.node} 비우기`, send: post(`${base}/change/drain`, { node: m.node }) }))} onClose={() => setDlg(undefined)} onDone={done} />}
              {dlg === 'cancel' && (
                <StepsDialog
                  title={`${chgId ?? name}을 취소할까요?`}
                  action="변경 취소"
                  renderError={netErr}
                  intro={<span>예약한 CIDR 후보를 돌려줍니다. 비우기를 시작한 서버의 변경은 취소할 수 없습니다.</span>}
                  steps={reserved.map((m) => ({ key: `cancel/${m.node}`, label: `${m.node} 계획 취소`, send: post(`${base}/change/cancel`, { node: m.node }) }))}
                  onClose={() => setDlg(undefined)}
                  onDone={done}
                />
              )}
              {fence && <FenceDialog base={base} tenant={tenant} name={name} node={fence} closure={d.closure.find((c) => c.node === fence)} reload={q.refresh} loading={q.loading} onClose={() => setFence(undefined)} onDone={done} />}
              {dlg === 'commit' && <CommitDialog base={base} name={name} view={d} onClose={() => setDlg(undefined)} onDone={done} />}
              {dlg === 'reconf' && <ReconfigureDialog base={base} name={name} view={d} want={(want ?? d.members.map((m) => m.node).join(',')).split(/[\s,]+/).filter(Boolean)} onClose={() => setDlg(undefined)} onDone={done} />}
            </>
          )
        }
      </Load>
    </>
  );
}

/**
 * UI-51 '{node} 사용 중지 확인'. 데몬이 그 서버의 정리 보고를 넣어 fence-network-change를 보낸다.
 * 옛 주소를 쓰는 컨테이너가 남아 있으면 sfcd가 거절(in-use)하므로 버튼을 끄고, 화면 주기(30초)와 새로고침으로 다시 읽는다.
 */
function FenceDialog({ base, tenant, name, node, closure: c, reload, loading, onClose, onDone }: { base: string; tenant: string; name: string; node: string; closure?: DNetworkClosure; reload: () => void; loading: boolean; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [users, setUsers] = useState(false);
  const left = pendingOf(c);
  // 보낸 뒤에는 새로 읽은 보고로 창이 바뀌지 않게 한다. 아직 세지 않은 보고(null)도 기다린다
  const busy = left !== 0 && !m.op;
  return (
    <Dialog
      title={busy || c?.unreachable ? `${node} 사용 중지 확인` : `${node} 사용 중지를 확인할까요?`}
      onClose={onClose}
      footer={
        m.op ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              {busy ? '닫기' : '취소'}
            </button>
            <button className="btn primary" disabled={m.busy || busy || !!c?.unreachable} onClick={() => void m.run(`${base}/change/fence`, { node }).then((o) => o?.state === 'applied' && onDone())}>
              사용 중지 확인
            </button>
          </>
        )
      }
    >
      {c?.unreachable ? (
        <div className="note wa">{node} 서버가 응답하지 않아 정리 보고를 읽지 못했습니다. 서버가 돌아온 뒤 확인하세요.</div>
      ) : busy ? (
        <>
          <div className="row between">
            <span className="small muted">
              {left === null ? `${node} 서버가 아직 옛 주소를 쓰는 컨테이너를 세지 않았습니다. 잠시 뒤 새로고침하세요.` : `${node}에 아직 옛 주소를 쓰는 컨테이너가 ${left}개 있습니다.`}
            </span>
            <button className="btn sm" title="새로고침" aria-label="새로고침" disabled={loading} onClick={reload}>
              ↻
            </button>
          </div>
          <button className="btn sm" style={{ alignSelf: 'flex-start' }} onClick={() => setUsers(true)}>
            어느 컨테이너인지 보기
          </button>
          <div className="note wa">이 컨테이너를 새 주소로 다시 시작하거나 멈춰야 사용 중지를 확인할 수 있습니다.</div>
        </>
      ) : (
        <span className="small muted">옛 주소를 쓰는 컨테이너가 없습니다. 확인하면 {node}의 옛 주소 범위를 닫고 다음 단계(적용)로 갑니다.</span>
      )}
      {m.error !== undefined && (netErr(m.error) ?? <MutationError error={m.error} />)}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      {users && <ResourceUsersDialog tenant={tenant} kind="network" name={name} onClose={() => setUsers(false)} />}
    </Dialog>
  );
}

function CommitDialog({ base, name, view, onClose, onDone }: { base: string; name: string; view: DNetworkChange; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  // 본 화면의 networksRevision을 expected로 고정한다(그 사이 다른 변경이 있으면 막힌다).
  const [expected] = useState(view.networksRevision);
  // 적용 뒤 새로 읽어도 보낸 내용이 그대로 보이게 연 때의 멤버를 고정한다.
  const [rows] = useState(view.members);
  return (
    <Dialog
      title={`${name} 변경을 적용할까요?`}
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
            <button className="btn primary" disabled={m.busy} onClick={() => void m.run(`${base}/change/commit`, { expected }).then((o) => o?.state === 'applied' && onDone())}>
              적용
            </button>
          </>
        )
      }
    >
      <div className="table-wrap">
        <table className="tbl">
          <tbody>
            {rows.map((x) => (
              <tr key={x.node}>
                <td>{x.node}</td>
                <td className="mono">{x.target === x.cidr ? `${x.cidr} (유지)` : `${x.cidr} → ${x.target}`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <span className="small muted">참여 서버들이 새 설정으로 다시 만들어집니다. 적용은 실제 통신 재개와 별도로 표시됩니다.</span>
      {m.error !== undefined && (netErr(m.error) ?? <MutationError error={m.error} />)}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

function ReconfigureDialog({ base, name, view, want, onClose, onDone }: { base: string; name: string; view: DNetworkChange; want: string[]; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [expected] = useState(view.networksRevision);
  const [add, setAdd] = useState<Record<string, { cidr: string }>>({});
  const have = new Set(view.members.map((x) => x.node));
  const rows = [...view.members.map((x) => ({ node: x.node, kind: want.includes(x.node) ? 'keep' : 'drop' })), ...want.filter((n) => !have.has(n)).map((node) => ({ node, kind: 'add' }))];
  const nw = (n: string) => add[n] ?? { cidr: '' };
  const missing = rows.some((r) => r.kind === 'add' && (!validCidr(nw(r.node).cidr) || systemHit(nw(r.node).cidr)));
  const empty = want.length === 0;
  const send = () =>
    empty
      ? m.run(`${base}/retire`, { expected })
      : m.run(`${base}/reconfigure`, { expected, members: want.map((n) => (have.has(n) ? { node: n } : { node: n, cidr: nw(n).cidr.trim() })) });
  return (
    <Dialog
      title={`${name} 재구성`}
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
            <button className={`btn ${empty ? 'danger solid' : 'primary'}`} disabled={m.busy || missing} onClick={() => void send().then((o) => o?.state === 'applied' && onDone())}>
              계획 만들기
            </button>
          </>
        )
      }
    >
      <div className="table-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>서버</th>
              <th>목표</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.node}>
                <td>{r.node}</td>
                <td>
                  {r.kind === 'keep' ? (
                    '유지'
                  ) : r.kind === 'drop' ? (
                    <Badge tone="wa">제거</Badge>
                  ) : (
                    <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                      <Badge tone="pr">추가</Badge>
                      <input className="mono" aria-label={`${r.node} CIDR`} placeholder="CIDR" value={nw(r.node).cidr} onChange={(e) => setAdd((a) => ({ ...a, [r.node]: { ...nw(r.node), cidr: e.target.value } }))} style={{ width: 150 }} />
                      {systemHit(nw(r.node).cidr) && (
                        <span className="small" style={{ color: 'var(--er)', flexBasis: '100%' }}>
                          {SYSTEM_TEXT}
                        </span>
                      )}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="note wa">빈 목록은 망 전체 폐기를 뜻합니다.</div>
      {m.error !== undefined && (netErr(m.error) ?? <MutationError error={m.error} />)}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

/** 망을 쓰는 앱 수(행의 apps). 이전 데몬은 없다 */
export const appCount = (net: NetworkView) => (net.apps === undefined ? '—' : String(net.apps));

/** 캐시 TTL 상한 기본값(초) */
export const DNS_TTL_DEFAULT = 10;

/** 망 도메인 이름 정책 전체(configure-network-dns는 정책을 통째로 바꾼다). 행에 없는 칸은 빼서 보낸다 */
export function dnsBody(d: NetworkDnsView, over: Partial<NetworkDnsView> = {}) {
  const v = { ...d, ...over };
  return {
    zone: v.zone,
    enabled: v.enabled,
    ...(v.upstreams ? { upstreams: v.upstreams } : {}),
    ...(v.ttl !== undefined ? { ttl: v.ttl } : {}),
    ...(v.negativeTtl !== undefined ? { negativeTtl: v.negativeTtl } : {}),
    ...(v.reverse !== undefined ? { reverse: v.reverse } : {}),
    expected: d.revision,
  };
}

/**
 * 망 지우기(UI-50). 한 번에 지우는 동작은 없다: 도메인 이름을 끈 뒤 서버마다 비우기(change/drain) → 쓰는 컨테이너가
 * 없어지면 빼기(members/leave)를 차례로 하고, 마지막 서버가 빠지면 망이 없어진다. 창이 열려 있는 동안 다음 단계를 이어 보낸다.
 */
export function DeleteNetworkDialog({ tenant, net, bridges = [], onClose, onDone }: { tenant: string; net: NetworkView; bridges?: BridgeView[]; onClose: () => void; onDone: () => void }) {
  const navigate = useNavigate();
  const dnsOff = useMutation();
  const [confirm, setConfirm] = useState('');
  // 연 순간의 참여 서버(뺀 서버를 '끝남'으로 보여 주려고 고정한다)
  const [nodes0] = useState(() => (net.members.length ? net.members.map((x) => x.node) : net.nodes));
  const [cidrs] = useState(() => (net.members.length ? net.members.map((x) => x.cidr) : [net.cidr]));
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<unknown>();
  const ids = useRef<Record<string, string>>({});
  const busy = useRef(false);
  const q = usePoll((s) => networkChange(tenant, net.name, s), [tenant, net.name], DEFAULT_POLL_MS);
  const base = networkPath(tenant, net.name);
  // 마지막 서버가 빠지면 망 행이 없어진다(404)
  const gone = q.error instanceof ApiError && q.error.status === 404;
  const members = gone ? [] : (q.data?.members ?? []);
  const dnsOn = !gone && (dnsOff.op?.state === 'applied' ? false : (q.data?.dnsEnabled ?? !!net.dns?.enabled));
  const closureOf = (node: string) => q.data?.closure.find((c) => c.node === node);
  const free = (c?: DNetworkClosure) => !!c && !c.unreachable && c.state !== 'unreachable' && pendingOf(c) === 0;
  const started = nodes0.some((n) => !members.some((x) => x.node === n)) || members.some((x) => x.draining);
  // 브릿지가 남은 망은 sfcd가 bridge-attached로 막는다. 이미 시작한 지우기는 이어 간다
  const attached = bridges.length > 0 && !started && !running;
  const send = async (key: string, path: string, body: Record<string, unknown>) => {
    const id = (ids.current[key] ??= newOpId());
    const r = await api.post<{ op: DOp }>(path, { ...body, opId: id });
    const o = toOp(r.op);
    if (o.state === 'failed' || o.state === 'rejected') {
      delete ids.current[key];
      throw new ApiError(409, { code: o.errorCode ?? 'failed', message: o.errorCode ?? '' });
    }
  };
  // 비우지 않은 서버는 모두 비우고, 쓰는 곳이 없어진 서버를 하나씩 뺀다
  useEffect(() => {
    if (!running || !q.data || gone || dnsOn || busy.current) return;
    const todo = members.find((x) => !x.draining && !ids.current[`drain/${x.node}`]);
    const out = members.find((x) => x.draining && free(closureOf(x.node)) && !ids.current[`leave/${x.node}`]);
    const next = todo ? (['drain', todo.node, `${base}/change/drain`] as const) : out ? (['leave', out.node, `${base}/members/leave`] as const) : undefined;
    if (!next) return;
    busy.current = true;
    void send(`${next[0]}/${next[1]}`, next[2], { node: next[1] })
      .catch((e) => (setError(e), setRunning(false)))
      .finally(() => ((busy.current = false), q.refresh()));
  }); // eslint-disable-line react-hooks/exhaustive-deps
  const done = useRef(false);
  useEffect(() => {
    if (gone && !done.current) (done.current = true), onDone();
  }, [gone, onDone]);
  const turnOff = () => void dnsOff.run(`${base}/dns`, dnsBody(net.dns!, { enabled: false })).then(() => q.refresh());
  const stepState = (node: string): [string, 'done' | 'run' | 'wait' | 'er'] => {
    const m = members.find((x) => x.node === node);
    if (q.data && !m) return ['끝남', 'done'];
    if (!m || !m.draining) return [running ? '비우는 중' : '', running ? 'run' : 'wait'];
    const c = closureOf(node);
    if (c?.unreachable || c?.state === 'unreachable') return ['서버가 응답하지 않습니다', 'er'];
    const n = pendingOf(c);
    if (free(c)) return ['빼는 중', 'run'];
    return [n === null ? '쓰는 곳 확인 중' : '쓰는 컨테이너 기다리는 중', 'run'];
  };
  const mark = (st: 'done' | 'run' | 'wait' | 'er') => <span style={{ width: 18, textAlign: 'center', color: st === 'done' ? 'var(--ok)' : st === 'er' ? 'var(--er)' : st === 'run' ? 'var(--pr)' : 'var(--muted)' }}>{st === 'done' ? '✓' : st === 'er' ? '!' : st === 'run' ? '●' : '○'}</span>;
  return (
    <Dialog
      title={`${net.name}${eulReul(net.name)} 지울까요?`}
      danger
      onClose={onClose}
      footer={
        gone ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              {started || running ? '닫기' : '취소'}
            </button>
            {dnsOn && net.dns && (
              <button className="btn" disabled={dnsOff.busy} onClick={turnOff}>
                도메인 이름 끄기
              </button>
            )}
            {attached && (
              <button className="btn" onClick={() => navigate('/shared/networks/bridges')}>
                가상 브릿지 보기
              </button>
            )}
            <button className="btn danger solid" disabled={confirm !== net.name || dnsOn || attached || running || !q.data} onClick={() => (setError(undefined), setRunning(true))}>
              {started ? '지우기 계속' : '지우기'}
            </button>
          </>
        )
      }
    >
      <p style={{ margin: 0 }}>
        사용 앱 {appCount(net)}개. 서버 {nodes0.length}대의 CIDR <span className="mono">{cidrs.join(' · ')}</span>{eulReul(cidrs[cidrs.length - 1] ?? '')} 돌려받습니다.
      </p>
      {attached && (
        <div className="note wa">
          가상 브릿지 {bridges.length}개({bridges.map((b) => `${bridgeEnds(b)}${b.state === 'waiting-me' || b.state === 'waiting-peer' ? ' 승인 대기' : b.state === 'closing' ? ' 끊는 중' : ''}`).join(', ')})가 남아 있어 지울 수 없습니다. 먼저 브릿지를 끊으세요.
        </div>
      )}
      {dnsOn && net.dns ? (
        <div className="note wa">
          도메인 이름({net.dns.zone})이 켜져 있어 지울 수 없습니다. 먼저 도메인 이름을 끄세요.
        </div>
      ) : (
        <div className="col" style={{ gap: 4, fontSize: 13 }}>
          <div className="row" style={{ gap: 8 }}>
            {mark('done')}
            <span>도메인 이름 끄기</span>
            <span className="muted small" style={{ marginLeft: 'auto' }}>
              꺼져 있음
            </span>
          </div>
          {nodes0.map((n) => {
            const [text, st] = stepState(n);
            const last = members.length === 1 && members[0].node === n;
            return (
              <div key={n} className="row" style={{ gap: 8 }}>
                {mark(st)}
                <span>
                  {n} 비우고 빼기{last ? <span className="muted"> · 마지막 서버</span> : null}
                </span>
                <span className="muted small" style={{ marginLeft: 'auto' }}>
                  {text}
                </span>
              </div>
            );
          })}
          <div className="row" style={{ gap: 8 }}>
            {mark(gone ? 'done' : 'wait')}
            <span>망 없어짐</span>
          </div>
        </div>
      )}
      <MutationError error={dnsOff.error} />
      {!gone && (
        <Field label={<>확인하려면 <b className="mono">{net.name}</b>을(를) 입력하세요</>}>
          <input className="mono" value={confirm} onChange={(e) => setConfirm(e.target.value)} disabled={running} />
        </Field>
      )}
      {error !== undefined && (netErr(error) ?? <MutationError error={error} />)}
    </Dialog>
  );
}

const IP = /^\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?$/;
const ZONE = /^[a-z0-9.-]+\.[a-z0-9-]+$/;

/** UI-52 도메인 이름 설정의 고칠 값. 연 순간의 정책을 고정한다(적용 중 목록이 새로 읽혀도 검토와 expected가 흔들리지 않게) */
export function useDnsDraft(net: NetworkView) {
  const [d, setD] = useState<NetworkDnsView>(() => net.dns ?? { zone: '', enabled: true, revision: 0 });
  const [zone, setZone] = useState(d.zone);
  const [ups, setUps] = useState((d.upstreams ?? []).join(', '));
  const [ttl, setTtl] = useState(d.ttl !== undefined ? String(d.ttl) : '');
  /** 지금 값으로 되돌린다(새로 읽은 정책 기준) */
  const reset = (n: NetworkView) => {
    const x = n.dns ?? { zone: '', enabled: true, revision: 0 };
    setD(x);
    setZone(x.zone);
    setUps((x.upstreams ?? []).join(', '));
    setTtl(x.ttl !== undefined ? String(x.ttl) : '');
  };
  const upList = ups.split(/[,\s]+/).filter(Boolean);
  // 빈 칸은 기본 10초(Jay 결정, 캔버스 v220). 데몬 기본값에 기대지 않고 적어 보낸다
  const ttlN = ttl.trim() === '' ? DNS_TTL_DEFAULT : Number(ttl);
  const problems = [
    !ZONE.test(zone) && '도메인 영역은 shop.sfc.test 같은 도메인 이름이어야 합니다.',
    upList.length > 4 && '외부 이름 확인 서버는 4개까지입니다.',
    upList.some((u) => !IP.test(u)) && '외부 이름 확인 서버는 1.1.1.1 또는 9.9.9.9:5353 모양이어야 합니다.',
    !(Number.isInteger(ttlN) && ttlN >= 1 && ttlN <= 3600) && '캐시 TTL 상한은 1~3600초입니다.',
  ].filter(Boolean) as string[];
  const next: NetworkDnsView = { ...d, zone, enabled: true, upstreams: upList.length || d.upstreams ? upList : undefined, ttl: ttlN };
  if (next.negativeTtl !== undefined && next.ttl !== undefined && next.negativeTtl > next.ttl) next.negativeTtl = next.ttl;
  const line = (k: string, v: unknown) => (v === undefined || v === '' ? undefined : `${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`);
  const diff: DiffLine[] = [];
  const changed = zone !== d.zone || ups !== (d.upstreams ?? []).join(', ') || ttl !== (d.ttl !== undefined ? String(d.ttl) : '');
  const pair = (k: string, a: unknown, b: unknown) => {
    const x = line(k, a);
    const y = line(k, b);
    if (x === y) {
      if (x) diff.push({ op: ' ', text: x });
      return;
    }
    if (x) diff.push({ op: '-', text: x });
    if (y) diff.push({ op: '+', text: y });
  };
  pair('zone', d.zone || undefined, next.zone);
  // 처음 연 순간 정책이 있었는지(적용 뒤 목록이 새로 읽혀도 검토 내용이 바뀌지 않게 d로 본다)
  const had = !!net.dns && d.revision > 0;
  pair('enabled', had ? d.enabled : undefined, true);
  pair('upstream', d.upstreams, next.upstreams);
  pair('max_ttl', d.ttl, next.ttl);
  // 데몬이 아직 정책 전체를 주지 않으면, 빈 칸은 sfcd 기본값으로 돌아간다
  const partial = had && (d.upstreams === undefined || d.ttl === undefined);
  return { d, zone, setZone, ups, setUps, ttl, setTtl, problems, next, diff, changed, partial, reset };
}
export type DnsDraft = ReturnType<typeof useDnsDraft>;

/** 도메인 이름 설정 변경 검토 → 적용 */
export function DnsReviewDialog({ tenant, net, draft, onClose, onDone }: { tenant: string; net: NetworkView; draft: DnsDraft; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  return (
    <Dialog
      title={`${net.name} 도메인 이름 변경`}
      onClose={onClose}
      footer={
        m.op ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose} disabled={m.busy}>
              취소
            </button>
            <button className="btn primary" disabled={m.busy} onClick={() => void m.run(`${networkPath(tenant, net.name)}/dns`, dnsBody(draft.d, draft.next)).then((o) => o?.state === 'applied' && onDone())}>
              적용
            </button>
          </>
        )
      }
    >
      <DiffView lines={draft.diff} compact={false} />
      {draft.partial && <div className="note wa">지금 외부 이름 확인 서버·캐시 TTL 값을 읽지 못했습니다. 빈 칸은 기본값(TTL 10초, 외부 이름 확인 서버 없음)으로 바뀝니다.</div>}
      {m.error !== undefined && (netErr(m.error) ?? <MutationError error={m.error} />)}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}
