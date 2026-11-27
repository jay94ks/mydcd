// SPDX-License-Identifier: Apache-2.0

import { useRef, useState } from 'react';
import { Link, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api, ApiError, enc } from '../api/client';
import { apps, limitPath, networks, nodesOverview, tenantLimits, tenantList, tenantMembers, tenantRetirement, users, volumes } from '../api/endpoints';
import type { OpView, TenantMember, TenantRetirement } from '../api/types';
import type { DOp } from '../api/dto';
import { useAuth, useSession } from '../auth/session';
import { Badge, Card, Field, HelpBox, PageHeader } from '../components/ui';
import { Empty, Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { Dialog } from '../components/Dialog';
import { DataTable } from '../components/DataTable';
import { casFailed, MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { StepsDialog, type Step } from '../components/StepsDialog';
import { DEFAULT_POLL_MS, usePoll } from '../lib/usePoll';
import { tenantsLive } from '../lib/liveTopics';
import { fmtBytes } from '../lib/format';
import { usePhone } from '../lib/viewport';
import { MCards, MDetail, MSec, MTiles, useReadOnlyTop } from '../mobile/ReadOnly';

function CreateTenantDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [id, setId] = useState('');
  const m = useMutation();
  const valid = /^[a-z0-9][a-z0-9-]{0,62}$/.test(id);
  return (
    <Dialog
      title="새 작업 공간"
      width={420}
      onClose={onClose}
      footer={
        m.op ? (
          <button className="btn primary" onClick={() => (onDone(), onClose())}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={!valid || m.busy} onClick={() => void m.submit({ action: 'create-tenant', payload: { ID: id }, tenant: id, target: id })}>
              만들기
            </button>
          </>
        )
      }
    >
      <Field label="작업 공간 ID" hint="소문자·숫자·-. 만든 뒤 바꿀 수 없습니다." error={id && !valid ? '형식이 맞지 않습니다' : undefined}>
        <input value={id} onChange={(e) => setId(e.target.value.trim())} readOnly={!!m.op} />
      </Field>
      <p className="small muted">만든 뒤 구성원·허용 서버를 따로 설정합니다.</p>
      {casFailed(m.op) && <div className="note wa small">같은 ID의 작업 공간이 이미 있습니다.</div>}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}

export function TenantsPage() {
  return usePhone() ? <MTenants /> : <DesktopTenants />;
}

/** 휴대폰 작업 공간 (UI-M11 ④ 모양) */
function MTenants() {
  const session = useSession();
  const { tenant } = useAuth();
  const list = usePoll((s) => tenantList(s), [], 0, tenantsLive);
  const navigate = useNavigate();
  useReadOnlyTop('작업 공간', session.user.systemAdmin ? '시스템 관리자' : '내 작업 공간', '만들기·구성원·허용 서버·종료는 넓은 화면에서');
  return (
    <Load q={list} what="작업 공간을 불러오지 못했습니다">
      {(items) => (
        <>
          <MTiles
            items={[
              { label: '작업 공간', value: items.length, sub: `관리 ${items.filter((t) => t.role === 'manager').length} · 읽기 ${items.filter((t) => t.role !== 'manager').length}` },
              { label: '지금 고른 곳', value: tenant || '—', sub: '위쪽 막대에서 바꿈' },
            ]}
          />
          <MCards
            empty="작업 공간이 없습니다."
            items={items.map((t) => ({
              key: t.id,
              title: t.id,
              badge: t.role === 'manager' ? ['ok', '관리'] : ['un', '읽기'],
              lines: [`내 권한 ${t.role === 'manager' ? '읽기 · 배포 · 관리' : '읽기'}`],
              meta: `버전 ${t.revision}`,
              onOpen: () => navigate(`/system/tenants/${t.id}`),
            }))}
          />
        </>
      )}
    </Load>
  );
}

function DesktopTenants() {
  const session = useSession();
  const admin = session.user.systemAdmin;
  const list = usePoll((s) => tenantList(s), [], 0, tenantsLive);
  // 대시보드 시작하기 카드의 '만들기'는 ?new=1로 바로 연다
  const [sp] = useSearchParams();
  const [creating, setCreating] = useState(() => admin && sp.get('new') === '1');
  const navigate = useNavigate();
  return (
    <>
      <PageHeader
        title="작업 공간"
        ids="UI-20 · UI-22"
        actions={
          <>
            <Refresh q={list} poll={false} />
            <button className="btn primary" disabled={!admin} title={admin ? undefined : '시스템 관리자 권한이 필요합니다'} onClick={() => setCreating(true)}>
              작업 공간 만들기
            </button>
          </>
        }
      />
      <HelpBox terms="작업 공간 (tenant) · 구성원 (membership) · 허용 서버 (tenant nodes) · 작업 공간 종료 (tenant retirement)">
        <b>이 화면은</b> 팀이나 서비스별로 앱·자원·권한을 나누는 단위인 작업 공간을 만들고 구성원과 허용 서버를 정합니다.
      </HelpBox>
      <Load q={list}>
        {(items) => (
          <DataTable
            rows={items}
            rowKey={(t) => t.id}
            onRowClick={(t) => navigate(`/system/tenants/${t.id}`)}
            emptyTitle="작업 공간이 없습니다"
            columns={[
              { key: 'id', header: '작업 공간', value: (t) => t.id, render: (t) => <Link to={`/system/tenants/${t.id}`}>{t.id}</Link> },
              { key: 'role', header: '내 권한', value: (t) => t.role, render: (t) => (t.role === 'manager' ? '관리' : '읽기') },
              { key: 'rev', header: '버전', value: (t) => t.revision, render: (t) => t.revision },
            ]}
          />
        )}
      </Load>
      {creating && <CreateTenantDialog onClose={() => setCreating(false)} onDone={list.refresh} />}
    </>
  );
}

/** GET /tenants/{t}(select-tenant). 모양이 아직 정해지지 않아 쓰는 필드만 고른다. */
interface TenantInfo {
  id: string;
  revision?: number;
  nodes?: string[] | null;
}

export function TenantDetailPage() {
  return usePhone() ? <MTenantDetail /> : <DesktopTenantDetail />;
}

/** 휴대폰 작업 공간 상세 (UI-M1 보기만 상세): 구성원 · 허용 서버·사용 한도 */
function MTenantDetail() {
  const { id = '' } = useParams();
  const session = useSession();
  const admin = session.user.systemAdmin;
  const list = usePoll((s) => tenantList(s), [], 0, tenantsLive);
  const retire = usePoll((s) => (admin ? tenantRetirement(id, s) : Promise.resolve(undefined)), [id, admin], DEFAULT_POLL_MS);
  const members = usePoll((s) => tenantMembers(id, s), [id]);
  const limits = usePoll((s) => tenantLimits(id, s), [id]);
  const path = useLocation().pathname.replace(/\/$/, '');
  const nodesTab = path.endsWith('/nodes');
  const base = `/system/tenants/${id}`;
  useReadOnlyTop(id, nodesTab ? '허용 서버·사용 한도' : '구성원 · 권한', '구성원·허용 서버·한도 바꾸기와 종료는 넓은 화면에서', [id, nodesTab]);
  const row = list.data?.find((t) => t.id === id);
  const r = retire.data;
  return (
    <>
      <Tabs
        label="작업 공간 탭"
        items={[
          { to: base, label: '구성원 · 권한' },
          { to: `${base}/nodes`, label: '허용 서버·사용 한도' },
        ]}
      />
      <MDetail
        title={id}
        badge={r?.phase === 'deleted' ? ['un', '종료함'] : r?.retiring ? ['wa', '종료하는 중'] : row ? (row.role === 'manager' ? ['ok', '관리'] : ['un', '읽기']) : undefined}
        rows={[
          ['내 권한', row ? (row.role === 'manager' ? '읽기 · 배포 · 관리' : '읽기') : '—'],
          ['버전', <code key="v">{row?.revision ?? '—'}</code>],
          r?.retiring && ['종료 진행', `정리 대상 ${r.targetCount} · 닫힘 ${r.closedOwners}/${r.ownerCount} · 남음 ${r.remainingCount}`],
        ]}
      />
      {nodesTab ? (
        <Load q={limits} what="사용 한도를 불러오지 못했습니다">
          {(ls) => (
            <>
              <MSec>허용 서버 {ls.length}</MSec>
              <MCards
                empty="허용 서버가 없습니다."
                items={ls.map((l) => ({
                  key: l.node,
                  title: l.node,
                  lines: [`CPU ${l.cpus}${l.nodeCpus ? ` / ${l.nodeCpus}` : ''} · 메모리 ${fmtBytes(l.memoryBytes)}${l.nodeMemoryBytes ? ` / ${fmtBytes(l.nodeMemoryBytes)}` : ''}`, `컨테이너 최대 ${l.maxContainers}`],
                  meta: `버전 ${l.revision}`,
                }))}
              />
            </>
          )}
        </Load>
      ) : (
        <Load q={members} what="구성원을 불러오지 못했습니다">
          {(ms) => (
            <>
              <MSec>구성원 {ms.items.length}</MSec>
              <MCards
                empty="구성원이 없습니다."
                items={ms.items.map((m: TenantMember) => ({
                  key: m.user,
                  title: m.username,
                  badge: !m.enabled ? ['un', '꺼짐'] : m.role === 'manager' ? ['ok', '관리'] : ['un', '읽기'],
                  lines: [m.role === 'manager' ? '읽기 · 배포 · 관리' : '읽기'],
                  meta: `버전 ${m.revision}`,
                }))}
              />
            </>
          )}
        </Load>
      )}
    </>
  );
}

function DesktopTenantDetail() {
  const { id = '' } = useParams();
  const session = useSession();
  const admin = session.user.systemAdmin;
  const info = usePoll(
    async (s) => {
      const [t, list] = await Promise.all([api.get<TenantInfo>(`/tenants/${enc(id)}`, s).catch(() => ({ id }) as TenantInfo), tenantList(s)]);
      const row = list.find((x) => x.id === id);
      return { ...t, revision: row?.revision ?? t.revision ?? 0, role: row?.role };
    },
    [id],
  );
  const retire = usePoll((s) => (admin ? tenantRetirement(id, s) : Promise.resolve(undefined)), [id, admin], DEFAULT_POLL_MS);
  const [dlg, setDlg] = useState<'begin' | 'finish'>();
  const r = retire.data;
  const gone = r?.phase === 'deleted';
  const done = () => (retire.refresh(), info.refresh());
  const base = `/system/tenants/${id}`;
  return (
    <>
      <PageHeader
        crumbs={
          <>
            <Link to="/system/tenants">작업 공간</Link> / {id}
          </>
        }
        title={id}
        ids="UI-21 · UI-16 · UI-22"
        actions={
          <>
            <Refresh q={info} poll={false} />
            {admin && !gone && (
              <button className="btn danger" disabled={!r || r.retiring} title={r?.retiring ? '이미 종료하는 중입니다' : undefined} onClick={() => setDlg('begin')}>
                작업 공간 종료…
              </button>
            )}
          </>
        }
      />
      <Tabs
        label="작업 공간 탭"
        items={[
          { to: base, label: '구성원 · 권한' },
          { to: `${base}/nodes`, label: '허용 서버·사용 한도' },
        ]}
      />
      {gone && <div className="note">종료한 작업 공간입니다. 앱 정의는 보관된 앱에 남아 있습니다.</div>}
      {r?.retiring && (
        <Card title={`작업 공간 종료 진행 · ${id}`} actions={<Refresh q={retire} />}>
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>정리 대상</th>
                  <th>소유</th>
                  <th>닫힘</th>
                  <th>남음</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>{r.targetCount}</td>
                  <td>{r.ownerCount}</td>
                  <td>{r.closedOwners}</td>
                  <td>{r.remainingCount}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <span className="small muted">{r.remaining.length > 0 ? `남은 목록: ${r.remaining.join(' · ')}` : r.ready ? '남은 것 없음 · 모든 서버가 정리를 마쳤습니다.' : '서버들의 정리 보고를 기다립니다.'}</span>
          {r.operation && (
            <span className="small muted">
              작업 <span className="mono">{r.operation}</span>
            </span>
          )}
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <button className="btn danger sm" disabled={!r.ready} title={r.ready ? undefined : '모든 서버가 정리를 마치고 남은 것이 없어야 마칠 수 있습니다'} onClick={() => setDlg('finish')}>
              종료 마치기…
            </button>
          </div>
        </Card>
      )}
      {dlg && r && <RetireDialog kind={dlg} tenant={id} status={r} fallbackRevision={info.data?.revision} onClose={() => setDlg(undefined)} onDone={done} />}
      <Load q={info} what="작업 공간을 불러오지 못했습니다">
        {(d) => (
          <Routes>
            <Route index element={<Members tenant={id} revision={d.revision} canManage={!gone && (admin || d.role === 'manager')} onDone={info.refresh} />} />
            <Route path="nodes" element={<NodesTab tenant={id} revision={d.revision} allowed={d.nodes ?? undefined} readOnly={gone} onDone={info.refresh} />} />
          </Routes>
        )}
      </Load>
    </>
  );
}

function RetireDialog({ kind, tenant, status, fallbackRevision, onClose, onDone }: { kind: 'begin' | 'finish'; tenant: string; status: TenantRetirement; fallbackRevision?: number; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [confirm, setConfirm] = useState('');
  // 대화상자를 연 때의 revision을 expected로 고정한다(다른 사람이 먼저 바꾸면 CAS로 막힌다).
  const [expected] = useState(status.revision ?? fallbackRevision ?? 0);
  const counts = usePoll(
    async (s) => {
      if (kind !== 'begin') return undefined;
      const n = (p: Promise<{ items: unknown[] }>) => p.then((x) => x.items.length).catch(() => undefined);
      const [a, nw, v] = await Promise.all([n(apps(tenant, s)), n(networks(tenant, s)), n(volumes(tenant, s))]);
      return { a, nw, v };
    },
    [tenant, kind],
    0,
  );
  const c = counts.data;
  const cnt = (x: number | undefined, unit: string) => (x === undefined ? unit : `${unit} ${x}개`);
  const path = `/tenants/${enc(tenant)}/retire${kind === 'finish' ? '/finish' : ''}`;
  // 마치기는 시작 뒤 revision이 바뀌므로 처음 보낼 때 상태를 다시 읽어 그 값을 쓴다.
  // 응답을 잃어 같은 opId로 다시 보낼 때는 처음 정한 값을 그대로 써야 op-conflict가 나지 않는다.
  const sent = useRef<number>();
  const send = async () => {
    if (sent.current === undefined) sent.current = kind === 'finish' ? ((await tenantRetirement(tenant).catch(() => undefined))?.revision ?? expected) : expected;
    return m.run(path, { expected: sent.current });
  };
  return (
    <Dialog
      title={kind === 'begin' ? `${tenant}을 종료할까요?` : `${tenant} 종료를 마칠까요?`}
      danger
      onClose={onClose}
      width={560}
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
            <button className="btn danger solid" disabled={confirm !== tenant || m.busy} onClick={() => void send().then((op) => op?.state === 'applied' && onDone())}>
              {kind === 'begin' ? '종료 시작' : '종료 마치기'}
            </button>
          </>
        )
      }
    >
      <p>{kind === 'begin' ? `새 입장을 막고 ${cnt(c?.a, '앱')}를 내리고, ${cnt(c?.nw, '망')}·${cnt(c?.v, '데이터 저장소')}의 소유권을 정산합니다. 앱 정의는 보관된 앱에 남습니다. 끝까지 몇 분~몇 시간 걸립니다. 모든 서버가 정리를 마치면 상세 위 카드의 ‘종료 마치기’로 끝냅니다.` : '모든 서버가 정리를 마쳤습니다. 작업 공간을 지우고 종료를 끝냅니다. 되돌릴 수 없습니다.'}</p>
      <Field
        label={
          <>
            확인하려면 <b className="mono">{tenant}</b>을(를) 입력하세요
          </>
        }
      >
        <input className="mono" value={confirm} onChange={(e) => setConfirm(e.target.value)} disabled={!!m.op} />
      </Field>
      {casFailed(m.op) && <div className="note wa small">{kind === 'begin' ? '그 사이 작업 공간이 바뀌었거나 이미 종료 중입니다. 닫고 다시 확인하세요.' : '그 사이 종료 상태가 바뀌었거나 아직 마칠 수 없습니다. 닫고 다시 확인하세요.'}</div>}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

function Members({ tenant, revision, canManage, onDone }: { tenant: string; revision: number; canManage: boolean; onDone: () => void }) {
  const { session } = useAuth();
  const admin = !!session?.user.systemAdmin;
  const list = usePoll((s) => tenantMembers(tenant, s), [tenant]);
  const all = usePoll((s) => (admin ? users(s) : Promise.resolve(undefined)), [admin]);
  const [user, setUser] = useState('');
  const [role, setRole] = useState<'viewer' | 'manager'>('viewer');
  const [removing, setRemoving] = useState<TenantMember>();
  const m = useMutation();
  const send = (target: string, label: string, enabled: boolean, r: 'viewer' | 'manager') =>
    m.submit({ action: 'set-membership', expected: revision, tenant, target: label, payload: { Tenant: tenant, User: target, Role: r, Enabled: enabled } }).then((op) => {
      if (op) {
        list.refresh();
        onDone();
      }
    });
  return (
    <div className="grid-2">
      <Card className="primary" title="구성원 · 권한" actions={<Refresh q={list} poll={false} />}>
        <Load q={list}>
          {(p) => (
            <DataTable
              rows={p.items}
              rowKey={(x) => x.user}
              pageInfo={p}
              emptyTitle="구성원이 없습니다"
              columns={[
                { key: 'user', header: '사용자', value: (x) => x.username, render: (x) => x.username },
                { key: 'role', header: '역할', value: (x) => x.role, render: (x) => (x.role === 'manager' ? '관리(읽기 · 배포)' : '읽기') },
                { key: 'en', header: '계정', value: (x) => String(x.enabled), render: (x) => <Badge tone={x.enabled ? 'ok' : 'un'}>{x.enabled ? '활성' : '비활성'}</Badge> },
                {
                  key: 'act',
                  header: '',
                  render: (x) =>
                    canManage && (
                      <button className="btn sm danger" onClick={() => (m.reset(), setRemoving(x))}>
                        빼기
                      </button>
                    ),
                },
              ]}
            />
          )}
        </Load>
        <span className="small muted">작업 공간 버전 {revision}을 기대값으로 보냅니다.</span>
      </Card>
      <Card className="aside" title="구성원 추가 · 바꾸기">
        {!canManage ? (
          <Empty kind="scope" title="이 작업 공간의 관리자만 구성원을 바꿉니다" />
        ) : (
          <>
            <Field label="사용자" hint={admin ? undefined : '사용자 ID를 넣습니다(목록은 시스템 관리자만 봅니다)'}>
              {admin && all.data ? (
                <select value={user} onChange={(e) => setUser(e.target.value)}>
                  <option value="">고르세요</option>
                  {all.data.items.map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.username}
                      {u.enabled ? '' : ' (비활성)'}
                    </option>
                  ))}
                </select>
              ) : (
                <input value={user} onChange={(e) => setUser(e.target.value.trim())} />
              )}
            </Field>
            <Field label="역할">
              <select value={role} onChange={(e) => setRole(e.target.value as typeof role)}>
                <option value="viewer">읽기</option>
                <option value="manager">관리(읽기 · 배포)</option>
              </select>
            </Field>
            <button className="btn primary" disabled={!user || m.busy || !!m.op} onClick={() => void send(user, all.data?.items.find((u) => u.id === user)?.username ?? user, true, role)}>
              적용 (기대 버전 {revision})
            </button>
          </>
        )}
        {casFailed(m.op) && <div className="note wa small">그사이 작업 공간이 바뀌었습니다. 새로 읽은 뒤 다시 해 주세요.</div>}
        <MutationError error={m.error} />
        {m.op && !removing && (
          <>
            <OpPanel op={m.op} onChange={m.setOp} />
            <button className="btn sm" onClick={() => (m.reset(), setUser(''))}>
              다른 구성원
            </button>
          </>
        )}
      </Card>
      {removing && (
        <Dialog
          title="구성원 빼기"
          width={420}
          onClose={() => (setRemoving(undefined), m.reset())}
          footer={
            m.op ? (
              <button className="btn primary" onClick={() => (setRemoving(undefined), m.reset())}>
                닫기
              </button>
            ) : (
              <>
                <button className="btn" onClick={() => setRemoving(undefined)}>
                  취소
                </button>
                <button className="btn danger solid" disabled={m.busy} onClick={() => void send(removing.user, removing.username, false, removing.role)}>
                  빼기
                </button>
              </>
            )
          }
        >
          <p className="small">
            <b>{removing.username}</b>은(는) 이 작업 공간({tenant})을 더 이상 보지 못합니다. 계정은 그대로입니다.
          </p>
          <MutationError error={m.error} />
          {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
        </Dialog>
      )}
    </div>
  );
}

const GiB = 1024 ** 3;
const cores = (n: number) => String(Math.round(n * 100) / 100);
const gib = (b: number) => String(Math.round((b / GiB) * 100) / 100);

interface LimitEdit {
  on: boolean;
  cpus: string;
  mem: string;
}

function NodesTab({ tenant, revision, allowed, readOnly, onDone }: { tenant: string; revision: number; allowed?: string[]; readOnly?: boolean; onDone: () => void }) {
  const { session } = useAuth();
  // 종료한 작업 공간은 읽기만 한다(편집 칸·변경 검토 감춤).
  const admin = !!session?.user.systemAdmin && !readOnly;
  const limits = usePoll((s) => tenantLimits(tenant, s), [tenant]);
  const cluster = usePoll((s) => (admin ? nodesOverview(s) : Promise.resolve(undefined)), [admin]);
  const [edit, setEdit] = useState<Record<string, LimitEdit>>({});
  const [review, setReview] = useState(false);
  const lim = (n: string) => limits.data?.find((l) => l.node === n);
  const nodes = admin ? (cluster.data?.nodes.map((n) => n.id) ?? []) : [...new Set([...(allowed ?? []), ...(limits.data ?? []).map((l) => l.node)])];
  const base = (n: string): LimitEdit => {
    const l = lim(n);
    // 허용 목록을 모르면 한도는 모든 서버에서 고칠 수 있게 둔다. 허용 체크는 바꿀 수 없다.
    return { on: allowed === undefined ? true : allowed.includes(n), cpus: l ? cores(l.cpus) : '', mem: l ? gib(l.memoryBytes) : '' };
  };
  const cur = (n: string) => edit[n] ?? base(n);
  const set = (n: string, patch: Partial<LimitEdit>) => setEdit((e) => ({ ...e, [n]: { ...cur(n), ...patch } }));
  const problem = (n: string): string | undefined => {
    const e = cur(n);
    if (!e.on) return undefined;
    const l = lim(n);
    const c = Number(e.cpus);
    const g = Number(e.mem);
    if (!e.cpus && !e.mem && !l) return undefined;
    if (!(c > 0) || !(g > 0)) return 'CPU와 메모리를 0보다 크게 넣으세요';
    if (l?.nodeCpus !== undefined && c > l.nodeCpus) return `서버 전체 한도 ${cores(l.nodeCpus)}코어를 넘습니다`;
    if (l?.nodeMemoryBytes !== undefined && g * GiB > l.nodeMemoryBytes) return `서버 전체 한도 ${fmtBytes(l.nodeMemoryBytes)}를 넘습니다`;
    return undefined;
  };
  const nextAllowed = nodes.filter((n) => cur(n).on);
  const allowChanged = admin && allowed !== undefined && (nextAllowed.length !== allowed.length || nextAllowed.some((n) => !allowed.includes(n)));
  const limitChanges = nodes.filter((n) => {
    const e = cur(n);
    const l = lim(n);
    if (!e.on || !e.cpus || !e.mem) return false;
    return !l || Number(e.cpus) !== Number(cores(l.cpus)) || Number(e.mem) !== Number(gib(l.memoryBytes));
  });
  const bad = nodes.some((n) => problem(n));
  const steps = (): Step[] => [
    ...(allowChanged
      ? [
          {
            key: 'nodes',
            label: `허용 서버: ${(allowed ?? []).join(', ') || '없음'} → ${nextAllowed.join(', ') || '없음'}`,
            send: (opId: string) => api.post<{ op: DOp }>('/ops', { opId, action: 'set-nodes', principal: session?.user.id ?? '', expected: revision, payload: { Tenant: tenant, Add: nextAllowed.filter((n) => !(allowed ?? []).includes(n)), Remove: (allowed ?? []).filter((n) => !nextAllowed.includes(n)) }, rootRevision: 0, tenant, target: tenant }),
          },
        ]
      : []),
    ...limitChanges.map((n) => {
      const l = lim(n);
      const e = cur(n);
      return {
        key: `limit/${n}`,
        label: `${n} 사용 한도: ${l ? `CPU ${cores(l.cpus)} · ${fmtBytes(l.memoryBytes)}` : '없음'} → CPU ${e.cpus} · ${e.mem} GiB`,
        send: (opId: string) => api.put<{ op: DOp }>(limitPath(tenant, n), { opId, cpus: Number(e.cpus), memoryBytes: Math.round(Number(e.mem) * GiB), expected: l?.revision ?? 0 }),
      };
    }),
  ];
  return (
    <div className="grid-2">
      <Card title="허용 서버·사용 한도 (UI-16)" actions={<Refresh q={limits} poll={false} />}>
        {allowed === undefined && <div className="note">서버 기능 대기 · 허용 서버 목록은 sfcd가 아직 알려 주지 않아 허용 칸을 보여 주거나 바꿀 수 없습니다. 사용 한도는 바꿀 수 있습니다.</div>}
        <Load q={limits}>
          {() =>
            nodes.length === 0 ? (
              <span className="small muted">허용한 서버가 없습니다.</span>
            ) : (
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>서버</th>
                      <th>허용</th>
                      <th>CPU 상한</th>
                      <th>메모리 상한</th>
                      <th>컨테이너 수</th>
                    </tr>
                  </thead>
                  <tbody>
                    {nodes.map((n) => {
                      const e = cur(n);
                      const l = lim(n);
                      const err = problem(n);
                      return (
                        <tr key={n}>
                          <td>{n}</td>
                          <td>{allowed === undefined ? <span className="muted" title="REQ-32 대기">모름</span> : admin ? <input type="checkbox" aria-label={`${n} 허용`} checked={e.on} onChange={(x) => set(n, { on: x.target.checked })} /> : e.on ? '허용' : '—'}</td>
                          {admin && e.on ? (
                            <>
                              <td>
                                <input aria-label={`${n} CPU 상한`} inputMode="decimal" value={e.cpus} onChange={(x) => set(n, { cpus: x.target.value.trim() })} style={{ width: 80 }} placeholder="코어" />
                                {l?.nodeCpus !== undefined && <span className="small muted"> / {cores(l.nodeCpus)} 코어</span>}
                              </td>
                              <td>
                                <input aria-label={`${n} 메모리 상한`} inputMode="decimal" value={e.mem} onChange={(x) => set(n, { mem: x.target.value.trim() })} style={{ width: 80 }} placeholder="GiB" /> <span className="small muted">GiB{l?.nodeMemoryBytes !== undefined ? ` / ${gib(l.nodeMemoryBytes)}` : ''}</span>
                                {err && <div className="small" style={{ color: 'var(--er)' }}>{err}</div>}
                              </td>
                            </>
                          ) : (
                            <>
                              <td className={l ? '' : 'muted'}>{l ? `${cores(l.cpus)} 코어` : '—'}</td>
                              <td className={l ? '' : 'muted'}>{l ? fmtBytes(l.memoryBytes) : '—'}</td>
                            </>
                          )}
                          <td className={l ? '' : 'muted'}>{l ? l.maxContainers : '—'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )
          }
        </Load>
        {admin && (
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <span className="small muted">허용을 끄면 새 배치만 막습니다. 정한 사용 한도는 그대로 남습니다.</span>
            <button className="btn primary" disabled={bad || (!allowChanged && !limitChanges.length)} onClick={() => setReview(true)}>
              변경 검토
            </button>
          </div>
        )}
      </Card>
      {review && (
        <StepsDialog
          title="허용 서버·사용 한도 변경"
          steps={steps()}
          renderError={overNode}
          onClose={() => setReview(false)}
          onDone={() => {
            setEdit({});
            limits.refresh();
            onDone();
          }}
        />
      )}
    </div>
  );
}

/** 422 limit-over-node: 서버 전체 한도(max)를 넘거나, 서버 전체 한도가 아직 없음(max 0, 0). */
function overNode(e: unknown) {
  if (!(e instanceof ApiError) || e.code !== 'limit-over-node') return undefined;
  const max = (e.body?.raw as { error?: { max?: { cpus?: number; memoryBytes?: number } } } | undefined)?.error?.max;
  const none = !max?.cpus && !max?.memoryBytes;
  return <div className="note er">{none ? '이 서버에는 서버 전체 한도가 아직 없어 작업 공간 한도를 정할 수 없습니다. 먼저 서버 전체 한도를 정하세요(CLI).' : `서버 전체 한도(CPU ${cores(max!.cpus ?? 0)}코어 · ${fmtBytes(max!.memoryBytes)})를 넘습니다. 값을 줄여 다시 검토하세요.`}</div>;
}

/** 검토한 변경을 차례로 보낸다. 작업 ID는 단계마다 한 번 만들고, 다시 보내도 같은 ID를 쓴다. */
