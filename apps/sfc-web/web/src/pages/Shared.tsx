// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState, type ReactNode } from 'react';
import { usePhone } from '../lib/viewport';
import { MCards, MTiles, MWideNote, useReadOnlyTop } from '../mobile/ReadOnly';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useTenantRole } from '../auth/session';
import { networkPath, networks, registries, volumes } from '../api/endpoints';
import type { NetworkView, Page, VolumeView } from '../api/types';
import { Badge, Card, HelpBox, PageHeader } from '../components/ui';
import { Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { DataTable } from '../components/DataTable';
import { usePoll } from '../lib/usePoll';
import { ago, fmtBytes } from '../lib/format';
import { NoTenant } from './Deploy';
import { Menu } from '../components/Menu';
import { appCount, DeleteNetworkDialog } from './NetworkChange';
import { NetFrame, useNetLists } from './NetFrame';
import { ResourceUsersDialog } from './ResourceUsers';
import { RoutesTable } from './Routes';
import { BridgeLinks, bridgesOf, InboundDialog, inboundOn } from './Bridges';
import { TunnelsDialog } from './Tunnels';
import { BackupCard, CapacityDialog, DeleteVolumeDialog, NO_APP, RestoreCard, useVolumeDetail } from './VolumeOps';
import { MoveCard, MoveDialog, moveBlocked } from './VolumeMove';
import { FixedVolumeDialog, ManagedVolumeDialog, NetworkCreateDialog, useAllowedRoots } from './SharedCreate';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { ApiError } from '../api/client';
import { eulReul } from '../lib/josa';

/** 공유 자원 다섯 화면이 모두 위에 두는 1단 탭 줄. (Jay 2026-11-27, 캔버스 v235) */
export const SHARED_TABS = [
  { to: '/shared/networks', label: '망', end: false },
  { to: '/shared/ingress', label: '외부 접속', end: false },
  { to: '/shared/volumes', label: '데이터 저장소' },
  { to: '/shared/vault', label: '비밀값' },
  { to: '/shared/lifecycle', label: '상태 검사 규칙' },
];

const empty = <T,>(): Page<T> => ({ items: [], next: '', revision: 0, asOf: new Date().toISOString() });

function useTenantList<T>(load: (t: string, s: AbortSignal) => Promise<Page<T>>) {
  const { tenant } = useTenantRole();
  const q = usePoll((s) => (tenant ? load(tenant, s) : Promise.resolve(empty<T>())), [tenant]);
  return { tenant, q };
}

function Frame({ title, ids, help, q, actions, children, after, sub }: { title: string; ids: string; help: React.ReactNode; q: Parameters<typeof Refresh>[0]['q']; actions?: React.ReactNode; children: React.ReactNode; after?: React.ReactNode; sub?: React.ReactNode }) {
  const { tenant } = useTenantRole();
  return (
    <>
      <PageHeader title="공유 자원" ids={ids} actions={<Refresh q={q} poll={false} />} />
      <Tabs label="공유 자원 탭" items={SHARED_TABS} />
      {help}
      {tenant && sub}
      {!tenant ? <NoTenant /> : <Card title={`${title} · 작업 공간 ${tenant}`} actions={actions}>{children}</Card>}
      {tenant && after}
    </>
  );
}

const NEED = '작업 공간 관리자 권한 필요';

/** 작업 공간 간 연결 탭 (UI-53) */
export function NetworkRoutesPage() {
  const { tenant, nq, rq, bq } = useNetLists();
  const { canDeploy } = useTenantRole();
  const [proposing, setProposing] = useState(false);
  return (
    <NetFrame
      ids="UI-53"
      q={rq}
      nq={nq}
      rq={rq}
      bq={bq}
      actions={
        <button type="button" className="btn primary" disabled={!canDeploy || !rq.data || !nq.data} title={canDeploy ? undefined : NEED} onClick={() => setProposing(true)}>
          연결 제안
        </button>
      }
      help={
        <HelpBox terms="연결 (route) · 보내는 쪽 (source) · 받는 쪽 (destination) · 승인 (approve) · 철회 (withdraw)">
          <b>이 화면은</b> 다른 작업 공간의 망과 정해진 포트로 잇는 연결을 관리합니다. 한쪽이 제안하고 양쪽 작업 공간 관리자가 모두 승인해야 열립니다. 어느 쪽이든 철회하면 닫힙니다. 망은 작업 공간마다 따로 있는 자원이라, 다른 작업 공간의 망과는 이 연결이나 가상 브릿지로만 닿습니다. 같은 작업 공간의 망끼리는 잇지 않습니다.
          <br />
          <b>가상 브릿지와 다른 점</b> 이 연결은 망을 잇지 않고, 서버 한 대에서 상대 망으로 정한 포트만 통과시키는 게이트웨이(gateway)입니다. 망 전체를 이으려면 <Link to="/shared/networks/bridges">가상 브릿지</Link>를 쓰세요.
        </HelpBox>
      }
    >
      <Card>
        <RoutesTable tenant={tenant ?? ''} nets={nq.data?.items ?? []} canDeploy={canDeploy} q={rq} proposing={proposing} onProposeClose={() => setProposing(false)} />
      </Card>
    </NetFrame>
  );
}

/** 카드 머리의 만들기 버튼 둘(보조 · 주) */
function CreateButtons({ second, primary, onSecond, onPrimary }: { second: string; primary: string; onSecond: () => void; onPrimary: () => void }) {
  const { canDeploy } = useTenantRole();
  return (
    <span className="row">
      <button type="button" className="btn" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={onSecond}>
        {second}
      </button>
      <button type="button" className="btn primary" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={onPrimary}>
        {primary}
      </button>
    </span>
  );
}

/** 참여 서버 칸: "node-a 10.x · node-b 10.y" (멤버가 없는 이전 데몬은 서버 목록과 CIDR) */
function memberText(n: NetworkView) {
  if (n.members.length) return n.members.map((m) => `${m.node} ${m.cidr}`).join(' · ');
  return [n.nodes.join(', '), n.cidr].filter(Boolean).join(' ');
}

export function NetworksPage() {
  return usePhone() ? <MNetworks /> : <DesktopNetworks />;
}

/** 휴대폰 공유 자원 머리: 탭 줄 + '보기만' 한 줄 (UI-M11 ③ 모양) */
export function MFrame({ title, wide, children }: { title: string; wide: string; children: ReactNode }) {
  const { tenant } = useTenantRole();
  useReadOnlyTop(title, tenant ? `작업 공간 ${tenant}` : '공유 자원', wide, [tenant]);
  return (
    <>
      <Tabs label="공유 자원 탭" items={SHARED_TABS} />
      {!tenant ? <NoTenant /> : children}
    </>
  );
}

function MNetworks() {
  const { q } = useTenantList(networks);
  const [users, setUsers] = useState<NetworkView>();
  const { tenant } = useTenantRole();
  return (
    <MFrame title="망" wide="망 만들기·변경·지우기는 넓은 화면에서">
      <Load q={q} what="망을 불러오지 못했습니다">
        {(p) => {
          const local = p.items.filter(isLocal).length;
          const busy = p.items.filter((n) => n.members.some((x) => x.phase || x.draining)).length;
          return (
            <>
              <MTiles
                items={[
                  { label: '망', value: p.items.length, sub: `다른 서버와 ${p.items.length - local} · 이 서버에서만 ${local}` },
                  { label: '변경 중', value: busy, sub: busy ? '변경 계획 · 비우는 중' : '모두 활성', warn: busy > 0 },
                ]}
              />
              <MCards
                empty="망이 없습니다."
                items={p.items.map((n) => {
                  const draining = n.members.some((x) => x.draining);
                  const changing = n.members.some((x) => x.phase);
                  return {
                    key: n.key,
                    title: n.name,
                    badge: deleting(n) ? ['wa', '지우는 중'] : draining ? ['wa', '비우는 중'] : changing ? ['pr', '변경 계획'] : ['ok', '활성'],
                    tone: draining ? 'wa' : undefined,
                    lines: [
                      `${scopeText(n)} · ${n.apps === undefined ? '사용 앱 —' : n.apps === 0 && !n.standalones ? '사용 앱 없음' : `사용 앱 ${appCount(n)}개`}${n.standalones ? ` · 단독 ${n.standalones}` : ''}`,
                      <span className="mono" style={{ fontSize: 12 }}>
                        {memberText(n) || '—'}
                      </span>,
                    ],
                    meta: n.dns ? `도메인 영역 ${n.dns.zone}${n.dns.enabled ? '' : ' (꺼짐)'}` : undefined,
                    onOpen: () => setUsers(n),
                  };
                })}
              />
              <MWideNote>카드를 누르면 쓰는 앱 · 연결(경로)과 도메인 이름 설정은 넓은 화면에서</MWideNote>
            </>
          );
        }}
      </Load>
      {users && <ResourceUsersDialog tenant={tenant} kind="network" name={users.name} onClose={() => setUsers(undefined)} />}
    </MFrame>
  );
}

/** 이 서버에서만 쓰는 망(local 옵션) */
const isLocal = (n: NetworkView) => n.toggles.includes('local');
const scopeText = (n: NetworkView) => (isLocal(n) ? '이 서버에서만' : '다른 서버와 이음');
/** 지우는 중: 변경 계획 없이 비우는 서버가 있음 */
const deleting = (n: NetworkView) => n.members.some((x) => x.draining && !x.phase);

function DesktopNetworks() {
  const { tenant, nq: q, rq, bq } = useNetLists();
  const { canDeploy } = useTenantRole();
  const nav = useNavigate();
  const [inbound, setInbound] = useState<NetworkView>();
  const brs = bq.data?.items ?? [];
  const [dlg, setDlg] = useState<'create'>();
  const [del, setDel] = useState<NetworkView>();
  const [users, setUsers] = useState<NetworkView>();
  const [tunnels, setTunnels] = useState<NetworkView>();
  const [scope, setScope] = useState<NetworkView>();
  const nets = q.data?.items ?? [];
  const changing = (n: NetworkView) => n.members.some((x) => x.phase);
  const draining = (n: NetworkView) => n.members.some((x) => x.draining);
  const go = (n: NetworkView) => nav(`/shared/networks/${encodeURIComponent(n.name)}/change`);
  const dnsOf = (n: NetworkView) => `/shared/networks/dns?net=${encodeURIComponent(n.name)}`;
  const close = () => setDlg(undefined);
  const serverCount = (n: NetworkView) => (n.members.length || n.nodes.length);
  return (
    <NetFrame
      ids="UI-50"
      q={q}
      nq={q}
      rq={rq}
      bq={bq}
      actions={
        <button type="button" className="btn primary" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => setDlg('create')}>
          망 만들기
        </button>
      }
      help={
        <HelpBox terms="망 (network) · 쓰는 범위 (이 서버에서만 / 다른 서버와 이음) · 참여 서버 (member) · 비우기 (drain)">
          <b>이 화면은</b> 이 작업 공간({tenant})의 앱끼리 통신하는 망을 만들고, 바꾸고, 지웁니다. 망은 작업 공간마다 따로 있는 자원이라 다른 작업 공간에서는 보이지 않고, 이름이 같아도 서로 다른 망입니다. 망 안의 이름은 ‘도메인 이름’ 탭에서, 다른 작업 공간과 잇는 것은 ‘가상 브릿지’·‘작업 공간 간 연결’ 탭에서 다룹니다.
        </HelpBox>
      }
    >
     <Card>
      <Load q={q}>
        {(p) => (
          <DataTable
            rows={p.items}
            rowKey={(n) => n.key}
            pageInfo={p}
            emptyTitle="망이 없습니다"
            columns={[
              { key: 'name', header: '이름', value: (n) => n.name, render: (n) => <b>{n.name}</b> },
              { key: 'scope', header: '쓰는 범위', value: (n) => scopeText(n), render: (n) => scopeText(n) },
              { key: 'members', header: '참여 서버 (서버 · CIDR)', value: (n) => memberText(n), render: (n) => <span className="mono">{memberText(n) || '—'}</span> },
              { key: 'dns', header: '도메인 영역', value: (n) => n.dns?.zone ?? '', render: (n) => (n.dns ? <Link className={n.dns.enabled ? 'mono' : 'mono muted'} to={dnsOf(n)}>{n.dns.zone}{n.dns.enabled ? '' : ' (꺼짐)'}</Link> : <span className="muted">—</span>) },
              { key: 'bridges', header: '가상 브릿지', value: (n) => bridgesOf(brs, tenant ?? '', n.name).length, render: (n) => <BridgeLinks list={bridgesOf(brs, tenant ?? '', n.name)} tenant={tenant ?? ''} net={n.name} /> },
              { key: 'apps', header: '앱', value: (n) => n.apps ?? -1, render: (n) => (n.apps === undefined ? <span className="muted">—</span> : <span>{n.apps}{n.standalones ? <span className="small muted"> · 단독 {n.standalones}</span> : null}</span>) },
              {
                key: 'state',
                header: '상태',
                value: (n) => (deleting(n) ? 3 : draining(n) ? 2 : changing(n) ? 1 : 0),
                render: (n) =>
                  deleting(n) ? (
                    <span className="col" style={{ gap: 2 }}>
                      <Badge tone="wa">지우는 중</Badge>
                      <span className="muted" style={{ fontSize: 11 }}>
                        서버 {n.members.filter((x) => x.draining).length}/{n.members.length} 비움
                      </span>
                    </span>
                  ) : draining(n) ? (
                    <Badge tone="wa">비우는 중</Badge>
                  ) : changing(n) ? (
                    <Badge tone="pr">변경 계획</Badge>
                  ) : (
                    <Badge tone="ok">활성</Badge>
                  ),
              },
              {
                key: 'act',
                header: '',
                render: (n) => {
                  const local = isLocal(n);
                  const one = serverCount(n) === 1;
                  return (
                    <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                      {deleting(n) ? (
                        <button type="button" className="btn sm danger" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => setDel(n)}>
                          지우기 계속
                        </button>
                      ) : (
                        <button type="button" className="btn sm" onClick={() => go(n)}>
                          변경
                        </button>
                      )}
                      <Menu
                        label={`${n.name} 작업`}
                        items={[
                          { label: '쓰는 앱 보기', onSelect: () => setUsers(n) },
                          ...(!local ? [{ label: '터널 연결 보기…', onSelect: () => setTunnels(n) }] : []),
                          { label: '도메인 이름 설정', onSelect: () => nav(dnsOf(n)) },
                          { label: '변경…', onSelect: () => go(n), hint: changing(n) ? '진행 중 이어 하기' : '서버 더하기·빼기' },
                          local
                            ? { label: '다른 서버와 잇게 바꾸기…', onSelect: () => setScope(n), disabledReason: !canDeploy ? NEED : undefined }
                            : {
                                label: '이 서버에서만 쓰게 바꾸기',
                                onSelect: () => setScope(n),
                                disabledReason: !canDeploy ? NEED : !one ? '서버가 하나일 때만' : undefined,
                                tip: canDeploy && !one ? `서버가 ${serverCount(n)}대인 망입니다. 서버를 하나만 남기면 바꿀 수 있습니다.` : undefined,
                              },
                          { label: '다른 작업 공간의 브릿지 받기…', hint: inboundOn(n) ? '켜짐' : '꺼짐', onSelect: () => setInbound(n), disabledReason: !canDeploy ? NEED : undefined },
                          { label: '', sep: true },
                          { label: '지우기…', danger: true, onSelect: () => setDel(n), disabledReason: !canDeploy ? NEED : undefined },
                        ]}
                      />
                    </span>
                  );
                },
              },
            ]}
          />
        )}
      </Load>
      <span className="small muted">CIDR은 클러스터 전역에서 겹칠 수 없습니다. 실제 컨테이너 주소는 Docker IPAM이 할당합니다. ‘이 서버에서만’ 망은 언제든 다른 서버와 잇는 망으로 바꿀 수 있습니다. 반대로 바꾸려면 참여 서버가 하나만 남아야 합니다. 망을 지우면 서버를 하나씩 비우고 빼며, 마지막 서버가 빠지면 망이 없어집니다.</span>
     </Card>
      {tunnels && <TunnelsDialog tenant={tenant} name={tunnels.name} onClose={() => setTunnels(undefined)} />}
      {users && <ResourceUsersDialog tenant={tenant} kind="network" name={users.name} onClose={() => setUsers(undefined)} />}
      {del && <DeleteNetworkDialog tenant={tenant} net={del} bridges={bridgesOf(brs, tenant ?? '', del.name)} onClose={() => setDel(undefined)} onDone={() => void q.refresh()} />}
      {inbound && <InboundDialog tenant={tenant ?? ''} net={inbound} bridges={brs} onClose={() => setInbound(undefined)} onDone={() => (void q.refresh(), void bq.refresh())} />}
      {scope && <NetworkScopeDialog tenant={tenant} net={scope} onClose={() => setScope(undefined)} onDone={() => void q.refresh()} />}
      {dlg === 'create' && <NetworkCreateDialog tenant={tenant} nets={nets} onClose={close} onDone={() => void q.refresh()} />}
    </NetFrame>
  );
}

/** 쓰는 범위 바꾸기(set-network-toggle local). 컨테이너와 연결은 끊기지 않는다. 거절되면 알림으로 */
function NetworkScopeDialog({ tenant, net, onClose, onDone }: { tenant: string; net: NetworkView; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const toast = useToast();
  const local = isLocal(net);
  const node = net.members[0]?.node ?? net.nodes[0];
  const count = net.members.length || net.nodes.length;
  const send = async () => {
    try {
      const o = await m.run(`${networkPath(tenant, net.name)}/toggles`, { toggle: 'local', on: !local });
      if (o?.state === 'applied') (onDone(), onClose());
    } catch {
      /* m.error가 보여 준다 */
    }
  };
  // 서버 수가 맞지 않아 거절되면 알림으로 보여 주고 창을 닫는다
  const refused = m.error instanceof ApiError && m.error.code === 'toggle-not-allowed';
  useEffect(() => {
    if (!refused) return;
    toast(`${net.name}은 서버가 ${count}대라 ‘이 서버에서만’으로 바꿀 수 없습니다. 먼저 ‘변경…’에서 서버를 하나만 남기세요.`, 'er');
    onClose();
  }, [refused]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <Dialog
      title={local ? `${net.name}${eulReul(net.name)} 다른 서버와 이을 수 있게 바꿀까요?` : `${net.name}${eulReul(net.name)} 이 서버에서만 쓰게 바꿀까요?`}
      onClose={onClose}
      footer={
        m.op && m.op.state !== 'applied' ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn primary" disabled={m.busy} onClick={() => void send()}>
              바꾸기
            </button>
          </>
        )
      }
    >
      <p style={{ margin: 0 }}>
        {local ? `지금은 ${node}에서만 쓰는 망입니다. 바꾼 뒤 ‘변경…’에서 서버를 더할 수 있습니다. 바꾸는 동안 끊기는 것은 없습니다.` : `${node}에서만 쓰는 망이 됩니다. 다른 서버의 컨테이너는 붙을 수 없습니다. 바꾸는 동안 끊기는 것은 없습니다.`}
      </p>
      {!refused && <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && (onDone(), onClose()))} />}
    </Dialog>
  );
}

/** 종류: 고정 / 앱 소유(소속 앱) / 관리(작업 공간 공유) */
// 앱이 정한 저장소는 서버에 묶여 있어도(kind fixed) 앱 소유다. 등록한 고정 저장소만 '고정'
const volKind = (v: VolumeView) => (v.app ? '앱 소유' : v.kind === 'fixed' ? '고정' : '관리');

export function VolumesPage() {
  return usePhone() ? <MVolumes /> : <DesktopVolumes />;
}

function MVolumes() {
  const { tenant, q } = useTenantList(volumes);
  const [users, setUsers] = useState<VolumeView>();
  return (
    <MFrame title="데이터 저장소" wide="만들기·백업·복원·이관·삭제는 넓은 화면에서">
      <Load q={q} what="데이터 저장소를 불러오지 못했습니다">
        {(p) => {
          const moving = p.items.filter((v) => v.movePhase).length;
          const used = p.items.reduce((a, v) => a + (v.usedBytes ?? 0), 0);
          const cap = p.items.reduce((a, v) => a + (v.kind === 'shared' ? v.capacityBytes ?? 0 : 0), 0);
          return (
            <>
              <MTiles
                items={[
                  { label: '데이터 저장소', value: p.items.length, sub: `사용 중 ${p.items.filter((v) => v.consumers > 0).length}${moving ? ` · 이관 중 ${moving}` : ''}` },
                  { label: '관측 사용량', value: fmtBytes(used), sub: cap ? `공유 저장소 용량 ${fmtBytes(cap)}` : '고정 저장소는 관측만' },
                ]}
              />
              <MCards
                empty="데이터 저장소가 없습니다."
                items={p.items.map((v) => ({
                  key: v.key,
                  title: v.name,
                  badge: v.movePhase ? ['pr', '이관 중'] : v.consumers > 0 ? ['ok', '사용 중'] : ['un', '미사용'],
                  lines: [
                    `${volKind(v)} · ${v.node ? `${v.node}${v.kind === 'fixed' && v.storage ? ` · ${v.storage}` : ''}` : '서버 —'}`,
                    v.kind === 'fixed' || !v.capacityBytes ? (v.usedBytes !== undefined ? `관측 ${fmtBytes(v.usedBytes)}` : '용량 —') : `${v.usedBytes !== undefined ? fmtBytes(v.usedBytes) : '—'} / ${fmtBytes(v.capacityBytes)}`,
                  ],
                  meta: v.writer ? `${v.writer} (쓰기 앱)` : v.consumers > 0 ? `${v.app ? `${v.app} · ` : ''}컨테이너 ${v.consumers}개` : '쓰는 앱 없음',
                  onOpen: () => setUsers(v),
                }))}
              />
              <MWideNote>관측 사용량은 강제 한도나 일관 백업의 증거가 아닙니다</MWideNote>
            </>
          );
        }}
      </Load>
      {users && <ResourceUsersDialog tenant={tenant} kind="volume" name={users.name} app={users.app} onClose={() => setUsers(undefined)} />}
    </MFrame>
  );
}

/**
 * 서버별 기본 저장 경로(#684, Jay 요청 "용량 제한 없는 기본 데이터 저장소가 노드별로 보이게").
 * 서버가 초기화 때 스스로 등록한 id "default" 경로이고, 처음에는 모든 작업 공간이 한도 없이 쓴다.
 * 저장 경로를 못 읽는 계정(보기 권한만)에는 보이지 않는다.
 */
function DefaultRootsCard({ tenant, isAdmin, canDeploy, volumes, onRegister }: { tenant: string; isAdmin: boolean; canDeploy: boolean; volumes: VolumeView[]; onRegister: (at: string) => void }) {
  const q = useAllowedRoots(tenant, isAdmin);
  if (!q.data || q.data.wait) return null;
  const roots = q.data.roots.filter((r) => r.isDefault).sort((a, b) => a.node.localeCompare(b.node));
  return (
    <Card title="서버별 기본 저장 경로" actions={<span className="small muted">서버가 처음 켜질 때 스스로 등록합니다</span>}>
      {!roots.length ? (
        <span className="small muted">이 작업 공간이 쓸 수 있는 기본 저장 경로가 없습니다. 서버를 새로 초기화하면 생기고, 시스템 관리자가 서버 › 저장 경로에서 허용을 바꿀 수 있습니다.</span>
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>서버</th>
                <th>경로</th>
                <th>용량 한도</th>
                <th>이 작업 공간 고정 데이터 저장소</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {roots.map((r) => (
                <tr key={`${r.node}/${r.name}`}>
                  <td>
                    <Link to={`/servers/${encodeURIComponent(r.node)}`}>{r.node}</Link>
                  </td>
                  <td>
                    <code>{r.path || '—'}</code>
                  </td>
                  <td>{r.capacityBytes === undefined ? '—' : r.capacityBytes ? fmtBytes(r.capacityBytes) : '제한 없음'}</td>
                  <td>{volumes.filter((v) => v.kind === 'fixed' && v.node === r.node && v.storage === r.name).length}개</td>
                  <td style={{ textAlign: 'right' }}>
                    <button type="button" className="btn sm" disabled={!canDeploy || r.draining || r.allowed === false} title={!canDeploy ? NEED : r.draining ? '비우는 중인 경로입니다' : undefined} onClick={() => onRegister(`${r.node}/${r.name}`)}>
                      여기에 고정 데이터 저장소 등록
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function DesktopVolumes() {
  const { tenant, q } = useTenantList(volumes);
  const { isAdmin, canDeploy } = useTenantRole();
  const [dlg, setDlg] = useState<'managed' | 'fixed'>();
  const [fixedAt, setFixedAt] = useState<string>();
  const [search] = useSearchParams();
  const [selKey, setSelKey] = useState<string>();
  const [cap, setCap] = useState<VolumeView>();
  const [move, setMove] = useState<VolumeView>();
  const [del, setDel] = useState<VolumeView>();
  const [users, setUsers] = useState<VolumeView>();
  const items = q.data?.items ?? [];
  const taken = items.map((v) => v.name);
  // 고른 저장소. 처음에는 백업할 수 있는 첫 저장소
  const sel = items.find((v) => v.key === selKey) ?? items.find((v) => v.kind === 'shared' && v.app) ?? items.find((v) => v.app) ?? items.find((v) => v.kind === 'shared');
  const detail = useVolumeDetail(tenant, sel);
  const close = () => setDlg(undefined);
  const pick = (v: VolumeView) => {
    setSelKey(v.key);
    requestAnimationFrame(() => document.getElementById('volume-ops')?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  };
  return (
    <Frame
      title="데이터 저장소"
      ids="UI-60 ~ UI-64"
      q={q}
      actions={<CreateButtons second="고정 데이터 저장소 등록" primary="관리 데이터 저장소 만들기" onSecond={() => setDlg('fixed')} onPrimary={() => setDlg('managed')} />}
      help={
        <HelpBox terms="데이터 저장소 (Volume) · 백업 (backup) · 복원 (restore) · 보존됨 (retained)">
          <b>이 화면은</b> 앱 데이터가 저장되는 공간을 관리합니다. 관리 데이터 저장소는 클러스터가 백업·이동을 맡고, 고정 데이터 저장소는 한 서버의 경로에 묶입니다.
        </HelpBox>
      }
      after={
        <>
          <DefaultRootsCard tenant={tenant} isAdmin={isAdmin} canDeploy={canDeploy} volumes={items} onRegister={(at) => (setFixedAt(at), setDlg('fixed'))} />
          {sel && (
          <div className="grid-3" id="volume-ops">
            <BackupCard key={`b-${sel.key}`} tenant={tenant} v={sel} q={detail} canDeploy={canDeploy} isAdmin={isAdmin} onChanged={() => void q.refresh()} />
            <RestoreCard key={`r-${sel.key}`} tenant={tenant} v={sel} q={detail} canDeploy={canDeploy} taken={taken} onChanged={() => void q.refresh()} />
            <MoveCard key={`m-${sel.key}`} tenant={tenant} v={sel} canDeploy={canDeploy} onRefresh={() => void q.refresh()} onStart={() => setMove(sel)} />
          </div>
          )}
        </>
      }
    >
      <Load q={q}>
        {(p) => (
          <DataTable
            rows={p.items}
            rowKey={(v) => v.key}
            pageInfo={p}
            initialQuery={search.get('q') ?? ''}
            selectedKey={sel?.key}
            emptyTitle="데이터 저장소가 없습니다"
            columns={[
              { key: 'name', header: '이름', value: (v) => v.name, render: (v) => <b>{v.name}</b> },
              { key: 'kind', header: '종류', value: (v) => volKind(v), render: (v) => volKind(v) },
              { key: 'where', header: '서버', value: (v) => `${v.node ?? ''}/${v.storage ?? ''}`, render: (v) => (v.node ? `${v.node}${v.kind === 'fixed' && v.storage ? ` · ${v.storage}` : ''}` : '—') },
              {
                key: 'use',
                header: '용량',
                value: (v) => v.usedBytes ?? 0,
                render: (v) => (
                  <span title={v.usageObservedAt ? `${ago(v.usageObservedAt)} 측정` : '최근 30분 안 측정 없음 (모름)'}>
                    {v.kind === 'fixed' || !v.capacityBytes ? (
                      <span className="muted">{v.usedBytes !== undefined ? `관측 ${fmtBytes(v.usedBytes)}` : '—'}</span>
                    ) : (
                      `${v.usedBytes !== undefined ? fmtBytes(v.usedBytes) : '—'} / ${fmtBytes(v.capacityBytes)}`
                    )}
                  </span>
                ),
              },
              { key: 'cons', header: '사용 앱', value: (v) => v.writer ?? (v.consumers ? `~${v.consumers}` : ''), render: (v) => (v.writer ? <span>{v.writer} (쓰기 앱)</span> : v.consumers > 0 ? <span>{v.app ? `${v.app} · ` : ''}컨테이너 {v.consumers}개</span> : <span className="muted">없음</span>) },
              {
                key: 'state',
                header: '상태',
                value: (v) => (v.movePhase ? 2 : v.consumers > 0 ? 1 : 0),
                render: (v) => (v.movePhase ? <Badge tone="pr">이관 중</Badge> : v.consumers > 0 ? <Badge tone="ok">사용 중</Badge> : <Badge tone="un">미사용</Badge>),
              },
              {
                key: 'act',
                header: '',
                render: (v) => (
                  <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                    {v.kind === 'fixed' && !v.app ? (
                      <button type="button" className="btn sm danger" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => setDel(v)}>
                        등록 해제
                      </button>
                    ) : (
                      <>
                        <button type="button" className="btn sm" onClick={() => pick(v)}>
                          백업
                        </button>
                        <button type="button" className="btn sm" disabled={!!moveBlocked(v, canDeploy)} title={moveBlocked(v, canDeploy)} onClick={() => (pick(v), setMove(v))}>
                          이관
                        </button>
                      </>
                    )}
                    <Menu
                      label={`${v.name} 작업`}
                      items={[
                        { label: '쓰는 앱 보기', onSelect: () => setUsers(v) },
                        { label: '백업 목록', onSelect: () => pick(v), disabledReason: v.app ? undefined : NO_APP },
                        { label: '용량 늘리기…', onSelect: () => setCap(v), disabledReason: !isAdmin ? '시스템 관리자만 바꿀 수 있습니다' : undefined },
                        { label: '', sep: true },
                        { label: '이관…', onSelect: () => (pick(v), setMove(v)), disabledReason: moveBlocked(v, canDeploy) },
                        { label: v.kind === 'fixed' ? '등록 해제…' : '삭제…', danger: true, onSelect: () => setDel(v), disabledReason: !canDeploy ? NEED : undefined },
                      ]}
                    />
                  </span>
                ),
              },
            ]}
          />
        )}
      </Load>
      <span className="small muted">사용량은 소유 서버가 주기적으로 잰 값이고, 최근 30분 안에 잰 값이 없으면 —입니다. 강제 사용 한도나 일관 백업의 증거가 아닙니다. 고정 데이터 저장소를 등록 해제해도 원 데이터는 삭제되지 않습니다.</span>
      {users && <ResourceUsersDialog tenant={tenant} kind="volume" name={users.name} app={users.app} onClose={() => setUsers(undefined)} />}
      {move && <MoveDialog tenant={tenant} v={move} onClose={() => setMove(undefined)} onDone={() => void q.refresh()} />}
      {cap && <CapacityDialog tenant={tenant} v={cap} onClose={() => setCap(undefined)} onDone={() => void q.refresh()} />}
      {del && <DeleteVolumeDialog tenant={tenant} v={del} onClose={() => setDel(undefined)} onDone={() => void q.refresh()} />}
      {dlg === 'managed' && <ManagedVolumeDialog tenant={tenant} taken={taken} onClose={close} onDone={() => void q.refresh()} />}
      {dlg === 'fixed' && <FixedVolumeDialog tenant={tenant} isAdmin={isAdmin} taken={taken} initial={fixedAt} onClose={() => (setFixedAt(undefined), close())} onDone={() => void q.refresh()} />}
    </Frame>
  );
}

/** 이미지 화면에서도 쓰는 저장소 목록 */
export function RegistriesCard() {
  const { tenant, q } = useTenantList(registries);
  if (!tenant) return null;
  return (
    <Card title="이미지 저장소" actions={<Refresh q={q} poll={false} />}>
      <Load q={q}>
        {(p) => (
          <DataTable
            rows={p.items}
            rowKey={(r) => r.id}
            pageInfo={p}
            emptyTitle="연결된 저장소가 없습니다"
            columns={[
              { key: 'name', header: '이름', value: (r) => r.name, render: (r) => <b>{r.name}</b> },
              { key: 'ep', header: '주소', value: (r) => r.endpoint, render: (r) => <code>{r.endpoint}</code> },
              { key: 'repo', header: '저장소 수', value: (r) => r.repositories, render: (r) => r.repositories },
              { key: 'act', header: '상태', value: (r) => String(r.active), render: (r) => <Badge tone={r.active ? 'ok' : 'un'}>{r.active ? '사용 중' : '꺼짐'}</Badge> },
            ]}
          />
        )}
      </Load>
    </Card>
  );
}
