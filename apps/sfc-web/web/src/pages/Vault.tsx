// SPDX-License-Identifier: Apache-2.0

// 비밀값 보관함 (UI-70 · UI-71, 캔버스 Vault · VaultIx). 트리 + 고른 항목 상세.
// 값은 화면에 오지 않는다. 새 값·비밀번호는 입력 칸에만 있고 보낸 뒤·닫을 때 지운다.
// 객체 정책 끝점(데몬 #58)은 {opId, id, …, expected}를 받는다. expected는 창을 연 순간의 객체 revision으로 고정한다.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { ApiError, noEndpoint } from '../api/client';
import { CLUSTER_VAULT, tenantVault, vaultList, vaultUsages, type VaultScope } from '../api/endpoints';
import type { OpView, SecretView, VaultUsage } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Badge, Field, HelpBox, PageHeader, type Tone } from '../components/ui';
import { useSearchParams } from 'react-router-dom';
import { Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { Dialog } from '../components/Dialog';
import { ContextMenu, type MenuItem } from '../components/Menu';
import { MutationError, OpPanel, casFailed, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { eulReul } from '../lib/josa';
import { NoTenant } from './Deploy';
import { MFrame, SHARED_TABS } from './Shared';
import { usePhone } from '../lib/viewport';
import { MCards, MTiles, MWideNote } from '../mobile/ReadOnly';
import { VaultGroupDialog, VaultPasswordDialog, VaultSecretDialog } from './SharedCreate';
import { ApprovalCard, GrantedCard, ageText } from './VaultApproval';

const DAY = 86400;

const NEED = '작업 공간 관리자 권한 필요';
const WAIT_USERS = '서버 기능 대기';

/** 그 객체를 쓰는 곳. 끝점이 없는 데몬이면 wait */
function useUsages(scope: VaultScope, id: string) {
  const q = usePoll((s) => vaultUsages(scope, id, s), [scope.base, id]);
  return { list: q.data, wait: noEndpoint(q.error), error: q.error, q };
}
type Usages = ReturnType<typeof useUsages>;
const userName = (u: VaultUsage) => (u.standalone ? `${u.standalone} (단독 컨테이너)` : u.app ? [u.app, u.service].filter(Boolean).join('/') : (u.purpose ?? u.id ?? '—'));
const liveOf = (u?: Usages) => (u?.list ?? []).filter((x) => x.live);
function usageText(u: Usages) {
  if (u.wait) return <span className="muted">{WAIT_USERS}</span>;
  if (!u.list) return <span className="muted">{u.error ? '읽지 못했습니다' : '불러오는 중…'}</span>;
  const live = liveOf(u);
  const gone = u.list.length - live.length;
  if (!live.length) return <span className="muted">쓰는 앱 없음{gone ? ` (내린 앱 ${gone}개)` : ''}</span>;
  return (
    <span>
      {[...new Set(live.map(userName))].join(', ')}
      {gone ? <span className="small muted"> · 내린 앱 {gone}개</span> : null}
    </span>
  );
}

const STATUS: Record<SecretView['status'], [string, Tone] | undefined> = {
  active: undefined,
  'password-pending': ['비밀번호 설정 중', 'wa'],
  revoking: ['무효화됨', 'er'],
  retired: ['폐기됨', 'un'],
  'reference-pending': ['참조 확인 중', 'wa'],
};
const StatusBadge = ({ v }: { v: SecretView }) => {
  const s = STATUS[v.status];
  return s ? <Badge tone={s[1]}>{s[0]}</Badge> : null;
};

const ERR: Record<string, string> = {
  'not-active': '지금 상태에서는 바꿀 수 없습니다. 무효화되었거나 설정 중인 항목입니다.',
  'not-group': '묶음에만 승인 유효 기간이 있습니다.',
  'not-revoking': '먼저 무효화해야 폐기할 수 있습니다.',
  'not-found': '이 항목이 없어졌습니다. 목록을 새로 고쳐 주세요.',
};
function VaultErr({ e }: { e: unknown }) {
  if (e === undefined) return null;
  if (e instanceof ApiError && ERR[e.code]) return <div className="note wa">{ERR[e.code]}</div>;
  return <MutationError error={e} />;
}

// ── 트리 ────────────────────────────────────────────

interface TNode {
  id: string;
  row?: SecretView;
  children: TNode[];
}

/** 부모 ID로 트리를 만든다. 목록에 없는 부모(행이 없는 묶음)는 뿌리 아래 이름만 있는 마디로 둔다 */
function buildTree(items: SecretView[], rootId: string): TNode {
  // 뿌리 묶음이 한 행으로 오면(parent "") 그 행이 뿌리 마디다
  const root: TNode = { id: rootId, row: items.find((v) => v.id === rootId), children: [] };
  const byId = new Map<string, TNode>([[rootId, root]]);
  const rest = items.filter((v) => v.id !== rootId);
  for (const v of rest) byId.set(v.id, { id: v.id, row: v, children: [] });
  for (const v of rest) {
    let parent = byId.get(v.parent);
    if (!parent) {
      parent = { id: v.parent, children: [] };
      byId.set(v.parent, parent);
      root.children.push(parent);
    }
    parent.children.push(byId.get(v.id)!);
  }
  const sort = (n: TNode) => {
    n.children.sort((a, b) => Number(!isGroup(a)) - Number(!isGroup(b)) || a.id.localeCompare(b.id));
    n.children.forEach(sort);
  };
  sort(root);
  return root;
}
const isGroup = (n: TNode) => !n.row || n.row.kind === 'group';

/** 이 항목 위(자기 포함) 묶음 중 비밀번호가 걸린 것이 있는가 */
function guarded(items: SecretView[], id: string, root: string) {
  const seen = new Set<string>();
  for (let cur = items.find((v) => v.id === id); cur && !seen.has(cur.id); cur = cur.parent === root ? undefined : items.find((v) => v.id === cur!.parent)) {
    seen.add(cur.id);
    if (cur.kind === 'group' && cur.protected) return true;
  }
  return false;
}

/** 아래에 있는 모든 ID(이동 대상에서 뺀다) */
function below(items: SecretView[], id: string): Set<string> {
  const out = new Set<string>([id]);
  for (let grew = true; grew; ) {
    grew = false;
    for (const v of items)
      if (out.has(v.parent) && !out.has(v.id)) {
        out.add(v.id);
        grew = true;
      }
  }
  return out;
}

/** "허용: a, b · 거부: 없음". 서비스 이름은 app/service 모양이라 사용자와 구별된다 */
function aclText(v: SecretView) {
  const allow = [...v.acl.users, ...v.acl.services];
  const deny = [...v.acl.denyUsers, ...v.acl.denyServices];
  return `허용: ${allow.length ? allow.join(', ') : '제한 없음'} · 거부: ${deny.length ? deny.join(', ') : '없음'}`;
}


type Dlg = { kind: 'group' | 'secret' | 'acl' | 'move' | 'age' | 'password' | 'revoke' | 'retire' | 'users' | 'init'; v?: SecretView };

const EMPTY = (): Awaited<ReturnType<typeof vaultList>> => ({ items: [], next: '', revision: 0, asOf: new Date().toISOString(), initialized: undefined, root: undefined });

export function VaultPage() {
  return usePhone() ? <MVault /> : <DesktopVault />;
}

/** 휴대폰 비밀값 보관함 (UI-M11 ③ 모양): 값은 어디에도 보이지 않고 이름·쓰는 곳만 */
function MVault() {
  const { tenant, isAdmin } = useTenantRole();
  const [which, setWhich] = useState<'tenant' | 'cluster'>('tenant');
  const cluster = isAdmin && which === 'cluster';
  const base: VaultScope | undefined = cluster ? CLUSTER_VAULT : tenant ? tenantVault(tenant) : undefined;
  const q = usePoll((s) => (base ? vaultList(base, s) : Promise.resolve(EMPTY())), [base?.base]);
  const rootId = q.data?.root || q.data?.items.find((v) => v.parent === '')?.id || base?.root || '';
  const items = (q.data?.items ?? []).filter((v) => v.id !== rootId);
  const groups = items.filter((v) => v.kind === 'group' && v.status !== 'retired');
  const secrets = items.filter((v) => v.kind === 'object' && v.status !== 'retired');
  const waiting = items.filter((v) => v.status === 'password-pending' || v.status === 'reference-pending').length;
  return (
    <MFrame title="비밀값 보관함" wide="비밀값 만들기·값 넣기·묶음 비밀번호·무효화는 넓은 화면에서">
      {isAdmin && (
        <div className="mchips">
          <button type="button" className={`mchip${!cluster ? ' on' : ''}`} onClick={() => setWhich('tenant')}>
            작업 공간 보관함
          </button>
          <button type="button" className={`mchip${cluster ? ' on' : ''}`} onClick={() => setWhich('cluster')}>
            클러스터 보관함
          </button>
        </div>
      )}
      {cluster && noEndpoint(q.error) ? (
        <div className="bn info">클러스터 보관함은 서버 기능 대기입니다.</div>
      ) : (
        <Load q={q} what="보관함을 불러오지 못했습니다">
          {() => (
            <>
              <MTiles
                items={[
                  { label: '비밀값', value: secrets.length, sub: `묶음 ${groups.length} · 보호 ${groups.filter((g) => g.protected).length}` },
                  { label: '기다리는 것', value: waiting, sub: waiting ? '비밀번호 · 참조 대기' : '없음', warn: waiting > 0 },
                ]}
              />
              <MCards
                empty="비밀값이 없습니다."
                items={items.map((v) => {
                  const st = STATUS[v.status];
                  const parent = v.parent && v.parent !== rootId ? items.find((x) => x.id === v.parent) : undefined;
                  return {
                    key: v.id,
                    title: v.path || v.id,
                    badge: st ? [st[1], st[0]] : v.kind === 'group' ? (v.protected ? ['wa', '비밀번호 보호'] : ['un', '보호 없음']) : undefined,
                    tone: v.status === 'retired' ? undefined : v.status === 'revoking' ? 'er' : undefined,
                    lines: [
                      v.kind === 'group' ? `묶음${v.protected ? ' · 비밀번호 보호' : ''}` : `비밀값 · 키 ${v.keys.length}개${v.keys.length ? ` (${v.keys.slice(0, 3).join(', ')}${v.keys.length > 3 ? ' …' : ''})` : ''}`,
                      parent ? `묶음 ${parent.path || parent.id} 안` : undefined,
                    ],
                    meta: `허용 사용자 ${v.acl.users.length} · 서비스 ${v.acl.services.length}`,
                  };
                })}
              />
              <MWideNote>값은 이 화면 어디에도 나오지 않습니다</MWideNote>
            </>
          )}
        </Load>
      )}
    </MFrame>
  );
}

function DesktopVault() {
  const role = useTenantRole();
  const { tenant, isAdmin } = role;
  // 클러스터 보관함은 시스템 관리자만 본다(sfcd --cluster, realm ""). 이전 데몬에서 끝점이 없으면 '서버 기능 대기'
  // 작업 공간 · 클러스터 보관함은 2단 탭(?box=cluster)으로 나눈다
  const [sp] = useSearchParams();
  const cluster = isAdmin && sp.get('box') === 'cluster';
  const base: VaultScope | undefined = cluster ? CLUSTER_VAULT : tenant ? tenantVault(tenant) : undefined;
  const canDeploy = cluster ? isAdmin : role.canDeploy;
  const q = usePoll((s) => (base ? vaultList(base, s) : Promise.resolve(EMPTY())), [base?.base]);
  // 뿌리 묶음 ID: 응답의 root, 없으면 parent가 빈 행, 그것도 없으면 작업 공간 이름
  const rootId = q.data?.root || q.data?.items.find((v) => v.parent === '')?.id || base?.root || '';
  const scope: VaultScope | undefined = base && { ...base, root: rootId };
  const uninit = cluster && q.data?.initialized === false;
  const [dlg, setDlg] = useState<Dlg>();
  const [sel, setSel] = useState<string>();
  const [ctx, setCtx] = useState<{ at: { x: number; y: number }; v: SecretView }>();
  const [grantTick, setGrantTick] = useState(0);
  const items = q.data?.items ?? [];
  const close = () => setDlg(undefined);
  const done = () => void q.refresh();
  useEffect(() => setSel(undefined), [base?.base]);
  const current = items.find((v) => v.id === sel) ?? items.find((v) => v.kind === 'object' && v.status !== 'retired') ?? items.find((v) => v.id !== rootId) ?? items[0];
  const waiting = cluster && noEndpoint(q.error);

  return (
    <>
      <PageHeader
        title="공유 자원"
        ids="UI-70 · UI-71 · UI-72"
        actions={
          <span className="row">
            <Refresh q={q} poll={false} />
            <button className="btn" disabled={!canDeploy || !scope || waiting || uninit} title={canDeploy ? undefined : NEED} onClick={() => setDlg({ kind: 'group' })}>
              묶음 만들기
            </button>
            <button className="btn primary" disabled={!canDeploy || !scope || waiting || uninit} title={canDeploy ? undefined : NEED} onClick={() => setDlg({ kind: 'secret' })}>
              비밀값 만들기
            </button>
          </span>
        }
      />
      <Tabs label="공유 자원 탭" items={SHARED_TABS} />
      {isAdmin && (
        <Tabs
          label="보관함 탭"
          sub
          items={[
            { to: '/shared/vault', label: '작업 공간 보관함', current: !cluster },
            { to: '/shared/vault?box=cluster', label: '클러스터 보관함', current: cluster },
          ]}
        />
      )}
      <HelpBox terms="비밀값 보관함 (Vault) · 비밀값 (Secret) · 묶음 (Group, 비밀번호로 사용을 승인받는 비밀값 모음) · 접근 권한 (ACL) · 무효화 (revoke)">
        <b>이 화면은</b> DB 비밀번호 같은 비밀값을 보관합니다. 값은 화면에 절대 나오지 않고, 이름과 쓰는 곳 같은 정보만 보입니다.
        {cluster && <> 클러스터 보관함은 모든 작업 공간이 함께 쓰는 비밀값이고, 시스템 관리자만 다룹니다. 작업 공간이 쓰려면 뿌리에 그 작업 공간 허용이 있어야 합니다.</>}
      </HelpBox>
      {!scope ? (
        <NoTenant />
      ) : waiting ? (
        <section className="card">
          <h2>클러스터 보관함</h2>
          <span className="muted">서버 기능 대기: 웹 서버에 클러스터 보관함 끝점이 아직 없습니다. 지금은 CLI(<code>sfcli secret --cluster</code>)로 관리합니다.</span>
        </section>
      ) : uninit ? (
        <section className="card">
          <h2>클러스터 보관함 (아직 초기화 안 됨)</h2>
          <div className="note">클러스터 보관함이 아직 초기화되지 않았습니다. 초기화하면 클러스터 범위의 묶음·비밀값을 만들 수 있습니다.</div>
          <span>
            <button className="btn primary" onClick={() => setDlg({ kind: 'init' })}>
              초기화…
            </button>
          </span>
        </section>
      ) : (
        <Load q={q} what="비밀값 목록을 불러오지 못했습니다">
          {(p) => (
            <div className="side-main">
              <section className="card vault-tree">
                <h2>트리</h2>
                <Tree
                  root={buildTree(p.items, scope.root)}
                  rootLabel={scope.cluster ? '클러스터' : scope.root}
                  sel={current?.id}
                  onPick={setSel}
                  onMenu={(v, at) => {
                    setSel(v.id);
                    setCtx({ v, at });
                  }}
                />
                <span className="small muted">이름 같은 공개 정보만 표시합니다. 값은 어디에도 표시되지 않습니다.</span>
              </section>
              <div className="vault-side">
                {current ? (
                  <>
                    <Detail key={current.id} scope={scope} v={current} isRoot={current.id === rootId} canDeploy={canDeploy} open={(kind) => setDlg({ kind, v: current })} />
                    <div className="grid-2">
                      {current.kind === 'object' && <NewValueCard key={`${scope.base}/${current.id}/${current.revision}`} scope={scope} v={current} canDeploy={canDeploy} onDone={done} />}
                      {!scope.cluster && <ApprovalCard tenant={scope.root} items={items} canDeploy={canDeploy} onApproved={() => setGrantTick((x) => x + 1)} />}
                    </div>
                    {!scope.cluster && <GrantedCard tenant={scope.root} reload={grantTick} />}
                  </>
                ) : (
                  <section className="card">
                    <h2>비밀값이 없습니다</h2>
                    <span className="muted">‘비밀값 만들기’로 첫 비밀값을 만드세요. 비밀번호로 사용을 승인받으려면 먼저 묶음을 만듭니다.</span>
                  </section>
                )}
              </div>
            </div>
          )}
        </Load>
      )}
      {ctx && <ContextMenu at={ctx.at} items={menuItems(ctx.v, canDeploy, ctx.v.id === rootId, (kind) => setDlg({ kind, v: ctx.v }))} onClose={() => setCtx(undefined)} />}
      {scope && (
        <>
          {dlg?.kind === 'group' && <VaultGroupDialog scope={scope} items={items} onClose={close} onDone={done} />}
          {dlg?.kind === 'secret' && <VaultSecretDialog scope={scope} items={items} group={current?.kind === 'group' && current.status === 'active' ? current.id : undefined} onClose={close} onDone={done} />}
          {dlg?.kind === 'password' && dlg.v && <VaultPasswordDialog scope={scope} group={dlg.v} onClose={close} onDone={done} />}
          {dlg?.kind === 'acl' && dlg.v && <AclDialog scope={scope} v={dlg.v} onClose={close} onDone={done} />}
          {dlg?.kind === 'move' && dlg.v && <MoveDialog scope={scope} v={dlg.v} items={items} onClose={close} onDone={done} />}
          {dlg?.kind === 'age' && dlg.v && <AgeDialog scope={scope} v={dlg.v} onClose={close} onDone={done} />}
          {dlg?.kind === 'revoke' && dlg.v && <RevokeDialog scope={scope} v={dlg.v} onClose={close} onDone={done} />}
          {dlg?.kind === 'retire' && dlg.v && <RetireDialog scope={scope} v={dlg.v} onClose={close} onDone={done} />}
          {dlg?.kind === 'users' && dlg.v && <UsagesDialog scope={scope} v={dlg.v} onClose={close} />}
          {dlg?.kind === 'init' && <InitDialog onClose={close} onDone={done} />}
        </>
      )}
    </>
  );
}

function Tree({ root, rootLabel, sel, onPick, onMenu }: { root: TNode; rootLabel: string; sel?: string; onPick: (id: string) => void; onMenu: (v: SecretView, at: { x: number; y: number }) => void }) {
  const [shut, setShut] = useState<Set<string>>(new Set());
  const toggle = (id: string) => setShut((s) => (s.has(id) ? new Set([...s].filter((x) => x !== id)) : new Set([...s, id])));
  const rows: ReactNode[] = [];
  const walk = (n: TNode, depth: number) => {
    const open = !shut.has(n.id);
    const v = n.row;
    const kids = n.children.length > 0;
    const arrow = kids || isGroup(n) ? (open ? '▾ ' : '▸ ') : '';
    rows.push(
      <div
        key={`${depth}/${n.id}`}
        role="treeitem"
        aria-selected={!!v && v.id === sel}
        aria-expanded={kids ? open : undefined}
        tabIndex={0}
        className={`vnode${depth === 0 ? ' root' : ''}${v && v.id === sel ? ' on' : ''}${v?.status === 'retired' ? ' gone' : ''}${v?.kind === 'object' && v.id === sel ? ' leaf' : ''}`}
        style={{ paddingLeft: 10 + depth * 20 - (depth ? 4 : 0) }}
        onClick={() => (v ? onPick(v.id) : kids && toggle(n.id))}
        onDoubleClick={() => kids && toggle(n.id)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            if (v) onPick(v.id);
          } else if ((e.key === 'ArrowLeft' && open) || (e.key === 'ArrowRight' && !open)) kids && toggle(n.id);
          else if (e.key === 'ContextMenu' && v) {
            const r = e.currentTarget.getBoundingClientRect();
            onMenu(v, { x: r.left + 24, y: r.bottom });
          }
        }}
        onContextMenu={(e) => {
          if (!v) return;
          e.preventDefault();
          onMenu(v, { x: e.clientX, y: e.clientY });
        }}
      >
        {kids || isGroup(n) ? (
          <span
            className="vnode-arrow"
            onClick={(e) => {
              if (!kids) return;
              e.stopPropagation();
              toggle(n.id);
            }}
          >
            {arrow}
          </span>
        ) : null}
        <span>{depth === 0 ? rootLabel : v?.kind === 'group' ? `묶음 ${n.id}` : n.id}</span>
        {v?.kind === 'group' && v.status === 'active' && (v.protected ? <Badge tone="wa">비밀번호 보호</Badge> : <Badge tone="un">보호 없음</Badge>)}
        {v && <StatusBadge v={v} />}
      </div>,
    );
    if (open) n.children.forEach((c) => walk(c, depth + 1));
  };
  walk(root, 0);
  return (
    <div role="tree" aria-label="비밀값 트리" className="col" style={{ gap: 2 }}>
      {rows}
    </div>
  );
}

type Act = Exclude<Dlg['kind'], 'group' | 'secret' | 'init'>;

/** 상태별로 켤 수 있는 일. 없으면 꺼진 이유 */
function why(v: SecretView, act: Act | 'write', canDeploy: boolean, isRoot = false): string | undefined {
  if (act === 'users') return undefined;
  if (!canDeploy) return NEED;
  if (isRoot && (act === 'move' || act === 'revoke' || act === 'retire')) return '뿌리 묶음은 옮기거나 지울 수 없습니다';
  if (v.status === 'retired') return '폐기된 항목입니다';
  switch (act) {
    case 'revoke':
      return v.status === 'revoking' ? '이미 무효화했습니다' : undefined;
    case 'retire':
      return v.status !== 'revoking' ? '무효화한 뒤에 켜짐' : undefined;
    default:
      if (v.status !== 'active') return '무효화했거나 설정 중인 항목은 바꿀 수 없습니다';
      if (act === 'write' && v.pendingWrite) return '진행 중인 쓰기가 있습니다';
      return undefined;
  }
}

function menuItems(v: SecretView, canDeploy: boolean, isRoot: boolean, open: (k: Act) => void): MenuItem[] {
  const items: MenuItem[] = [];
  if (v.kind === 'object') items.push({ label: '새 값 쓰기', disabledReason: why(v, 'write', canDeploy), onSelect: () => document.getElementById('vault-new-value')?.querySelector('input')?.focus() });
  else items.push({ label: v.protected ? '비밀번호 바꾸기' : '비밀번호 정하기', disabledReason: why(v, 'password', canDeploy), onSelect: () => open('password') });
  items.push({ label: '접근 권한 편집', disabledReason: why(v, 'acl', canDeploy), onSelect: () => open('acl') });
  if (v.kind === 'group') items.push({ label: '승인 유효 기간…', disabledReason: why(v, 'age', canDeploy), onSelect: () => open('age') });
  items.push({ label: '쓰는 곳 보기', onSelect: () => open('users') });
  items.push({ label: '다른 묶음으로 이동…', disabledReason: why(v, 'move', canDeploy, isRoot), onSelect: () => open('move') });
  items.push({ label: '', sep: true });
  items.push({ label: '무효화…', disabledReason: why(v, 'revoke', canDeploy, isRoot), onSelect: () => open('revoke') });
  items.push({ label: '폐기…', danger: true, disabledReason: why(v, 'retire', canDeploy, isRoot), onSelect: () => open('retire') });
  return items;
}

function Detail({ scope, v, isRoot, canDeploy, open }: { scope: VaultScope; v: SecretView; isRoot: boolean; canDeploy: boolean; open: (k: Act) => void }) {
  const users = useUsages(scope, v.id);
  const live = liveOf(users);
  const btn = (k: Act, label: string, danger = false) => {
    const off = (k === 'retire' && v.status === 'revoking' && live.length ? `아직 쓰는 앱이 ${live.length}개 있습니다` : undefined) ?? why(v, k, canDeploy, isRoot);
    return (
      <button key={k} className={`btn${danger ? ' danger' : ''}`} disabled={!!off} title={off} onClick={() => open(k)}>
        {label}
      </button>
    );
  };
  const rows: [string, ReactNode][] =
    v.kind === 'object'
      ? [
          ['마지막 쓰기', v.pendingWrite ? <Badge tone="pr">쓰는 중</Badge> : v.status === 'active' ? <Badge tone="ok">게시됨</Badge> : <StatusBadge v={v} />],
          ['사용 중', usageText(users)],
          ['접근 권한', aclText(v)],
          ['키', <span className="mono">{v.keys.join(', ') || '—'}</span>],
        ]
      : [
          ['보호', v.protected ? <Badge tone="wa">비밀번호 보호</Badge> : <Badge tone="un">보호 없음</Badge>],
          ['승인 유효', ageText(v.maxApprovalAge)],
          ['사용 중', usageText(users)],
          ['접근 권한', aclText(v)],
        ];
  return (
    <section className="card">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <span className="row">
          <h2>{v.id}</h2>
          <StatusBadge v={v} />
        </span>
        <span className="mono muted">
          rev {v.revision}
          {v.kind === 'group' ? ' · 묶음' : v.group ? ` · Group ${v.group}` : ''}
        </span>
      </div>
      <div className="kv2">
        {rows.map(([k, x]) => (
          <span key={k} style={{ display: 'contents' }}>
            <span className="muted">{k}</span>
            <span>{x}</span>
          </span>
        ))}
      </div>
      {v.status === 'revoking' && <div className="note wa small">무효화했습니다. 쓰는 앱은 다음 시작 때 이 {v.kind === 'group' ? '묶음의 비밀값' : '비밀값'}을 받지 못합니다. 아래 남은 것과 쓰는 곳이 없으면 폐기할 수 있습니다.</div>}
      <div className="row">
        {btn('acl', '접근 권한 편집')}
        {v.kind === 'group' && btn('password', v.protected ? '비밀번호 바꾸기' : '비밀번호 정하기')}
        {v.kind === 'group' && btn('age', '승인 유효 기간')}
        {!isRoot && btn('move', '이동')}
        {!isRoot && btn('revoke', '무효화', true)}
        {!isRoot && btn('retire', '폐기', true)}
      </div>
    </section>
  );
}

// ── 새 값 쓰기 (UI-71) ─────────────────────────────

function NewValueCard({ scope, v, canDeploy, onDone }: { scope: VaultScope; v: SecretView; canDeploy: boolean; onDone: () => void }) {
  const m = useMutation();
  const toast = useToast();
  const [vals, setVals] = useState<Record<string, [string, string]>>({});
  // 다른 항목으로 가거나 화면을 떠나면 입력한 값을 지운다
  useEffect(() => () => setVals({}), []);
  const off = why(v, 'write', canDeploy);
  const keys = v.keys;
  const mismatch = keys.filter((k) => (vals[k]?.[0] ?? '') !== (vals[k]?.[1] ?? ''));
  const ready = keys.length > 0 && keys.every((k) => vals[k]?.[0]) && !mismatch.length;
  const path = `${scope.base}/value`;
  const body = (withValue: boolean) => ({ path: v.path, keys, ...(withValue ? { values: Object.fromEntries(keys.map((k) => [k, vals[k]?.[0] ?? ''])) } : {}) });
  const after = (o?: OpView) => {
    if (o?.state !== 'applied') return;
    setVals({});
    toast(`${v.id}의 새 값을 게시했습니다. 쓰는 앱은 다음 시작부터 새 값을 씁니다.`);
    onDone();
  };
  const start = async () => {
    if (m.op || m.error) m.reset();
    after(await m.run(path, body(true)));
  };
  const op = m.op;
  return (
    <section className="card" id="vault-new-value" style={{ borderColor: 'var(--accent-line)' }}>
      <h2>새 값 쓰기 (UI-71)</h2>
      {keys.map((k) => (
        <div key={k} className={keys.length > 1 ? 'g2' : 'col'} style={{ gap: 12 }}>
          <Field label={keys.length > 1 ? `새 값 · ${k}` : '새 값'}>
            <input type="password" autoComplete="new-password" disabled={!!off || m.busy} value={vals[k]?.[0] ?? ''} onChange={(e) => setVals((x) => ({ ...x, [k]: [e.target.value, x[k]?.[1] ?? ''] }))} />
          </Field>
          <Field label="확인" error={vals[k]?.[1] && mismatch.includes(k) ? '값이 다릅니다' : undefined}>
            <input type="password" autoComplete="new-password" disabled={!!off || m.busy} value={vals[k]?.[1] ?? ''} onChange={(e) => setVals((x) => ({ ...x, [k]: [x[k]?.[0] ?? '', e.target.value] }))} />
          </Field>
        </div>
      ))}
      <span className="small muted">값은 보호 입력으로 한 번만 서버를 지나며 저장·로그되지 않습니다.</span>
      <ol className="small muted" style={{ margin: 0, paddingLeft: 18, lineHeight: '20px' }}>
        <li>쓰기 준비</li>
        <li>보호 입력 전송</li>
        <li>공급자 결과 확인 뒤 게시</li>
      </ol>
      {op && (
        <div className="col" style={{ gap: 6 }}>
          {casFailed(op) && <div className="note wa small">그사이 다른 쓰기가 있었습니다. 새로 읽은 뒤 다시 넣어 주세요.</div>}
          <OpPanel op={op} onChange={(o) => (m.setOp(o), after(o))} />
          {op.state !== 'applied' && !m.busy && (
            <div className="row">
              {op.errorCode === 'needs-input' && (
                <button className="btn sm primary" disabled={!ready} onClick={() => void m.run(path, body(true)).then(after)}>
                  같은 작업으로 값 다시 보내기
                </button>
              )}
              {op.errorCode === 'input-unknown' && (
                <button className="btn sm primary" onClick={() => void m.run(path, body(false)).then(after)}>
                  결과 확인 (값은 다시 보내지 않음)
                </button>
              )}
              {op.state === 'failed' && op.errorCode === 'write-not-applied' && (
                <button className="btn sm primary" disabled={!ready} onClick={() => (m.reset(), void m.run(path, body(true)).then(after))}>
                  새 작업으로 다시 넣기
                </button>
              )}
            </div>
          )}
        </div>
      )}
      <VaultErr e={m.error} />
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="btn primary" disabled={!!off || !ready || m.busy} title={off} onClick={() => void start()}>
          {m.busy ? '보내는 중…' : '쓰기 시작'}
        </button>
      </div>
    </section>
  );
}

// ── 객체 정책 다이얼로그 ───────────────────────────

/** 정책 변경 한 건을 보내는 틀. body는 창을 연 순간의 expected를 담아 둔다 */
function PolicyDialog({ title, action, danger, method = 'POST', path, body, valid = true, confirmName, children, onClose, onDone }: { title: string; action: string; danger?: boolean; method?: 'POST' | 'PUT' | 'PATCH'; path: string; body: Record<string, unknown>; valid?: boolean; confirmName?: string; children: ReactNode; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [typed, setTyped] = useState('');
  const send = async () => {
    // 오류나 끝난 작업 뒤에 내용을 바꿔 다시 보내면 새 작업이다
    if (m.op || m.error) m.reset();
    const o = await m.run(path, body, method);
    if (o?.state === 'applied') onDone();
  };
  const finished = m.op?.state === 'applied';
  return (
    <Dialog
      title={title}
      danger={danger}
      width={danger ? 420 : 560}
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
            <button className={danger ? 'btn danger solid' : 'btn primary'} disabled={m.busy || !valid || (!!confirmName && typed !== confirmName)} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : action}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        {children}
        {confirmName && (
          <Field label={<>확인하려면 <b className="mono">{confirmName}</b>{eulReul(confirmName)} 입력하세요</>}>
            <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value)} disabled={finished} autoComplete="off" spellCheck={false} />
          </Field>
        )}
        <VaultErr e={m.error} />
        {m.op && casFailed(m.op) && <div className="note wa small">그사이 다른 사람이 바꿨습니다. 닫고 다시 해 주세요.</div>}
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

type AclRow = { who: 'user' | 'service'; name: string; deny: boolean };
const aclRows = (v: SecretView): AclRow[] => [
  ...v.acl.users.map((name): AclRow => ({ who: 'user', name, deny: false })),
  ...v.acl.services.map((name): AclRow => ({ who: 'service', name, deny: false })),
  ...v.acl.denyUsers.map((name): AclRow => ({ who: 'user', name, deny: true })),
  ...v.acl.denyServices.map((name): AclRow => ({ who: 'service', name, deny: true })),
];

type AclLists = { users: string[]; services: string[]; denyUsers: string[]; denyServices: string[] };
const aclKeys = ['users', 'services', 'denyUsers', 'denyServices'] as const;
// 서버는 바뀐 이름만 받는다(R17): 원래 목록과 비교해 더할 것과 뺄 것을 나눈다.
export const aclDelta = (cur: AclLists, next: AclLists) => {
  const add = {} as AclLists;
  const remove = {} as AclLists;
  for (const k of aclKeys) {
    const was = new Set(cur[k]);
    const now = new Set(next[k]);
    add[k] = next[k].filter((n) => !was.has(n));
    remove[k] = cur[k].filter((n) => !now.has(n));
  }
  return { add, remove, changed: aclKeys.some((k) => add[k].length > 0 || remove[k].length > 0) };
};

function AclDialog({ scope, v, onClose, onDone }: { scope: VaultScope; v: SecretView; onClose: () => void; onDone: () => void }) {
  const [expected] = useState(v.revision);
  const [rows, setRows] = useState<AclRow[]>(() => aclRows(v));
  const set = (i: number, r: Partial<AclRow>) => setRows((xs) => xs.map((x, j) => (j === i ? { ...x, ...r } : x)));
  const names = (who: AclRow['who'], deny: boolean) => [...new Set(rows.filter((r) => r.who === who && r.deny === deny && r.name.trim()).map((r) => r.name.trim()))].sort();
  const bad = rows.find((r) => r.name.trim().length > 200);
  const dup = rows.find((r, i) => r.name.trim() && rows.findIndex((x) => x.who === r.who && x.name.trim() === r.name.trim()) !== i);
  const delta = aclDelta(v.acl, { users: names('user', false), services: names('service', false), denyUsers: names('user', true), denyServices: names('service', true) });
  const body = { id: v.id, ...delta, expected };
  return (
    <PolicyDialog title={`${v.id} 접근 권한`} action="저장" method="PATCH" path={`${scope.base}/acl`} body={body} valid={!bad && !dup && delta.changed} onClose={onClose} onDone={onDone}>
      <div className="table-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>누구</th>
              <th>종류</th>
              <th>허용 / 거부</th>
              <th aria-label="지우기" />
            </tr>
          </thead>
          <tbody>
            {!scope.cluster && (
              <tr>
                <td>작업 공간 {scope.root} (배포)</td>
                <td className="muted">고정</td>
                <td className="muted">{rows.some((r) => !r.deny) ? '허용 목록에 든 것만' : '허용'}</td>
                <td />
              </tr>
            )}
            {rows.map((r, i) => (
              <tr key={i}>
                <td>
                  <input className="mono" aria-label="이름" value={r.name} placeholder={r.who === 'user' ? 'alice' : 'php-shop/web'} onChange={(e) => set(i, { name: e.target.value })} />
                </td>
                <td>
                  <select aria-label="종류" value={r.who} onChange={(e) => set(i, { who: e.target.value as AclRow['who'] })}>
                    <option value="user">사용자</option>
                    <option value="service">앱 서비스</option>
                  </select>
                </td>
                <td>
                  <select aria-label="허용 또는 거부" value={r.deny ? 'deny' : 'allow'} onChange={(e) => set(i, { deny: e.target.value === 'deny' })}>
                    <option value="allow">허용</option>
                    <option value="deny">거부</option>
                  </select>
                </td>
                <td>
                  <button className="btn sm" aria-label="이 줄 지우기" onClick={() => setRows((xs) => xs.filter((_, j) => j !== i))}>
                    ✕
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <span>
        <button className="btn" onClick={() => setRows((xs) => [...xs, { who: 'user', name: '', deny: false }])}>
          ＋ 추가
        </button>
      </span>
      {dup && <div className="note wa small">{dup.name.trim()}이(가) 두 번 들어 있습니다.</div>}
      <span className="small muted">허용 목록이 비어 있으면 작업 공간 안에서 제한이 없습니다. 거부가 허용보다 앞서고, 위 묶음의 규칙도 모두 통과해야 합니다. 읽기와 쓰기를 따로 주지는 않습니다.</span>
    </PolicyDialog>
  );
}

function MoveDialog({ scope, v, items, onClose, onDone }: { scope: VaultScope; v: SecretView; items: SecretView[]; onClose: () => void; onDone: () => void }) {
  const root = scope.root;
  const [expected] = useState(v.revision);
  const options = useMemo(() => {
    const skip = below(items, v.id);
    const groups = items.filter((g) => g.kind === 'group' && g.status === 'active' && !skip.has(g.id) && g.id !== v.parent);
    return [...(v.parent !== root ? [{ id: root, label: `${scope.cluster ? '클러스터' : root} (맨 위)` }] : []), ...groups.map((g) => ({ id: g.id, label: `${g.id} (${guarded(items, g.id, root) ? '비밀번호 보호' : '보호 없음'})` }))];
  }, [items, v, root, scope.cluster]);
  const [to, setTo] = useState(options[0]?.id ?? '');
  const losesGuard = !!to && guarded(items, v.parent, root) && !(to !== root && guarded(items, to, root));
  return (
    <PolicyDialog title={`${v.id} 이동`} action="이동" path={`${scope.base}/move`} body={{ id: v.id, parent: to, expected }} valid={!!to} onClose={onClose} onDone={onDone}>
      <Field label="옮길 묶음">
        <select value={to} onChange={(e) => setTo(e.target.value)} disabled={!options.length}>
          {!options.length && <option value="">옮길 수 있는 묶음 없음</option>}
          {options.map((o) => (
            <option key={o.id} value={o.id}>
              {o.label}
            </option>
          ))}
        </select>
      </Field>
      {losesGuard && <div className="note wa">비밀번호로 보호된 묶음에서 보호 없는 묶음으로 옮기면 앱이 비밀번호 승인 없이 쓸 수 있게 됩니다.</div>}
    </PolicyDialog>
  );
}

function AgeDialog({ scope, v, onClose, onDone }: { scope: VaultScope; v: SecretView; onClose: () => void; onDone: () => void }) {
  const [expected] = useState(v.revision);
  const [days, setDays] = useState(v.maxApprovalAge ? String(Math.round((v.maxApprovalAge / DAY) * 100) / 100) : '0');
  const n = Number(days);
  const err = days.trim() === '' || !Number.isFinite(n) || n < 0 || n > 366 ? '0 ~ 366일' : undefined;
  const seconds = err ? 0 : Math.round(n * DAY);
  return (
    <PolicyDialog title={`${v.id} 승인 유효 기간`} action="저장" method="PUT" path={`${scope.base}/approval-age`} body={{ id: v.id, seconds, expected }} valid={!err} onClose={onClose} onDone={onDone}>
      <Field label="승인 유효 (일)" error={err} hint="0이면 제한 없음 · 366일까지">
        <input inputMode="decimal" value={days} onChange={(e) => setDays(e.target.value.replace(/[^\d.]/g, ''))} />
      </Field>
      <span className="small muted">지금: {ageText(v.maxApprovalAge)}. 이 묶음의 비밀값 사용 승인은 이 기간이 지나면 끝나고, 앱을 다시 배포할 때 다시 승인받습니다.</span>
    </PolicyDialog>
  );
}

function RevokeDialog({ scope, v, onClose, onDone }: { scope: VaultScope; v: SecretView; onClose: () => void; onDone: () => void }) {
  const [expected] = useState(v.revision);
  const users = useUsages(scope, v.id);
  const names = [...new Set(liveOf(users).map(userName))];
  return (
    <PolicyDialog title={`${v.id}${eulReul(v.id)} 무효화할까요?`} action="무효화" danger confirmName={v.id} path={`${scope.base}/revoke`} body={{ id: v.id, expected }} onClose={onClose} onDone={onDone}>
      <div>
        {names.length ? `쓰는 앱 ${names.length}개(${names.join(', ')})가` : v.kind === 'group' ? '이 묶음 아래 비밀값을 쓰는 앱이' : '이 비밀값을 쓰는 앱이'} 다음 시작 때 이 비밀값을 받지 못합니다. 지금 도는 컨테이너는 그대로입니다.
      </div>
      <span className="small muted">
        {users.wait ? `쓰는 앱 목록은 아직 볼 수 없습니다(${WAIT_USERS}). ` : users.list && !names.length ? '지금 쓰는 앱은 없습니다. ' : ''}무효화한 뒤에는 폐기만 할 수 있습니다.
      </span>
    </PolicyDialog>
  );
}

function RetireDialog({ scope, v, onClose, onDone }: { scope: VaultScope; v: SecretView; onClose: () => void; onDone: () => void }) {
  const [expected] = useState(v.revision);
  const users = useUsages(scope, v.id);
  const live = liveOf(users);
  return (
    <PolicyDialog title={`${v.id}${eulReul(v.id)} 폐기할까요?`} action="폐기" danger confirmName={v.id} path={`${scope.base}/retire`} body={{ id: v.id, expected }} valid={!live.length} onClose={onClose} onDone={onDone}>
      <div>모든 리비전을 지웁니다. 되돌릴 수 없습니다.</div>
      {live.length > 0 ? (
        <div className="note er small">
          아직 쓰는 앱이 있어 폐기할 수 없습니다: {[...new Set(live.map(userName))].join(', ')}. 이 앱들을 내리거나 다른 비밀값으로 바꾼 뒤 다시 해 주세요.
        </div>
      ) : (
        <span className="small muted">아래에 남은 항목, 진행 중인 쓰기, 아직 쓰는 앱이 있으면 서버가 거절합니다.</span>
      )}
    </PolicyDialog>
  );
}

// ── 쓰는 곳 · 클러스터 보관함 초기화 ─────────────────

function UsagesDialog({ scope, v, onClose }: { scope: VaultScope; v: SecretView; onClose: () => void }) {
  const users = useUsages(scope, v.id);
  const list = users.list ?? [];
  const label = v.kind === 'group' ? `${v.id} 묶음` : v.id;
  return (
    <Dialog
      title={`${label}${eulReul(label)} 쓰는 곳`}
      width={720}
      onClose={onClose}
      footer={
        <button className="btn primary" onClick={onClose}>
          닫기
        </button>
      }
    >
      <div className="col" style={{ gap: 12 }}>
        {users.wait ? (
          <div className="note small">{WAIT_USERS}</div>
        ) : (
          <Load q={users.q} what="쓰는 곳">
            {() =>
              !list.length ? (
                <div className="muted">이 항목을 쓰는 앱이 없습니다.</div>
              ) : (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>앱 / 서비스</th>
                    <th>서버</th>
                    <th>비밀값</th>
                    <th>상태</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((u, i) => (
                    <tr key={i}>
                      <td>
                        {userName(u)}
                        {!u.standalone && u.deployment && <div className="small muted mono">{u.deployment}</div>}
                      </td>
                      <td className="mono">{u.node || '—'}</td>
                      <td className="mono small">
                        {u.secrets.join(', ') || '—'}
                      </td>
                      <td>{u.live ? <Badge tone="ok">쓰는 중</Badge> : <Badge tone="un">내림</Badge>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
              )
            }
          </Load>
        )}
        <span className="small muted">{v.kind === 'group' ? '이 묶음 아래 비밀값을 받는 앱까지 나옵니다. ' : ''}쓰는 중인 앱이 있으면 폐기할 수 없습니다.</span>
      </div>
    </Dialog>
  );
}

function InitDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const send = async () => {
    if (m.op || m.error) m.reset();
    const o = await m.run(`${CLUSTER_VAULT.base}/init`, {});
    if (o?.state === 'applied') onDone();
  };
  // 이미 누가 초기화했으면 목록만 새로 읽는다
  const exists = m.error instanceof ApiError && m.error.code === 'exists';
  const [refreshed, setRefreshed] = useState(false);
  useEffect(() => {
    if (exists && !refreshed) (setRefreshed(true), onDone());
  }, [exists, refreshed, onDone]);
  const finished = m.op?.state === 'applied' || exists;
  return (
    <Dialog
      title="클러스터 보관함을 초기화할까요?"
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
            <button className="btn primary" disabled={m.busy} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '초기화'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <div>클러스터 범위의 보관함 뿌리를 만듭니다. 한 번만 하면 됩니다. 작업 공간 보관함에는 영향이 없습니다.</div>
        {exists ? <div className="note small">이미 초기화되어 있습니다. 목록을 새로 읽었습니다.</div> : <VaultErr e={m.error} />}
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}
