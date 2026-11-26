// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from 'react';
import { drainRunning } from '../lib/drain';
import { Link, useNavigate } from 'react-router-dom';
import { nodeTunnelReconnectPath, ledger, mesh as fetchMesh, nodeDisks, nodesOverview, raft, raftCompact, raftCompactPlan, raftCompaction, type RaftCompactRun, type RaftCompactView } from '../api/endpoints';
import { Drawer } from '../components/Drawer';
import { useReconnectAction } from './Tunnels';
import { ApiError } from '../api/client';
import type { DiskView, MeshLink, NodeView, RaftView } from '../api/types';
import { Badge, Card, Field, HelpBox, KV, PageHeader, PhaseBadge, Tile, UsageBar } from '../components/ui';
import { MutationError, OpPanel, uncertain, useMutation } from '../components/OpPanel';
import type { OpView } from '../api/types';
import { ErrorBand, Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { Dialog } from '../components/Dialog';
import { Popover } from '../components/Popover';
import { useToast } from '../components/Toast';
import { useTenantRole } from '../auth/session';
import { AddServerWizard, joinInProgress } from './NodeAdd';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { cordonNote } from './ServerDetail';
import { ContextMenu, type MenuItem } from '../components/Menu';
import { ShellSettingsDialog, shellBlocked, useShellPolicy } from './NodeShell';
import { ago, fmtBytes, fmtTime, pct } from '../lib/format';

export const SERVER_TABS = [
  { to: '/servers', label: '서버 목록' },
  { to: '/servers/consensus', label: '합의 상태' },
];

function MeshGraph({ nodes, links, selected, onSelect, onLink }: { nodes: NodeView[]; links: MeshLink[]; selected?: string; onSelect: (id: string) => void; onLink: (l: MeshLink) => void }) {
  const W = 520;
  const H = 320;
  const r = Math.min(W, H) / 2 - 56;
  const pos = new Map(nodes.map((n, i) => [n.id, { x: W / 2 + r * Math.cos((2 * Math.PI * i) / nodes.length - Math.PI / 2), y: H / 2 + r * Math.sin((2 * Math.PI * i) / nodes.length - Math.PI / 2) }]));
  const stroke: Record<MeshLink['state'], string> = { up: '#1a7f37', slow: '#c4500a', down: '#cf222e', pending: '#8a919c' };
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="서버 간 Mesh 링크 그래프" style={{ width: '100%', height: 'auto', maxHeight: 360 }}>
      {links.map((l) => {
        const a = pos.get(l.a);
        const b = pos.get(l.b);
        if (!a || !b) return null;
        return (
          <g key={`${l.a}-${l.b}`} onClick={() => onLink(l)} style={{ cursor: 'pointer' }} role="button" aria-label={`${l.a} ↔ ${l.b} 링크`}>
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="transparent" strokeWidth={14} />
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={stroke[l.state]} strokeWidth={l.state === 'up' ? 2.5 : 2} strokeDasharray={l.state === 'pending' ? '6 5' : l.state === 'slow' ? '2 3' : undefined} />
            {l.rttMs !== undefined && (
              <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 6} fontSize="11" textAnchor="middle" fill="#3d4450">
                {l.rttMs} ms{l.lossPct ? ` · 손실 ${l.lossPct}%` : ''}
              </text>
            )}
          </g>
        );
      })}
      {nodes.map((n) => {
        const p = pos.get(n.id)!;
        const sel = selected === n.id;
        return (
          <g key={n.id} onClick={() => onSelect(n.id)} style={{ cursor: 'pointer' }} role="button" aria-label={`${n.id} 선택`}>
            <circle cx={p.x} cy={p.y} r={30} fill={sel ? '#eef4fd' : '#fff'} stroke={sel ? '#1f5fbf' : n.phase === 'ready' ? '#1a7f37' : '#8a919c'} strokeWidth={sel ? 3 : 2} strokeDasharray={n.phase === 'joining' ? '4 3' : undefined} />
            <text x={p.x} y={p.y + 4} fontSize="12" textAnchor="middle" fontWeight="600" fill="#16191f">
              {n.id}
            </text>
            <text x={p.x} y={p.y + 46} fontSize="11" textAnchor="middle" fill="#5b6370">
              {n.leader ? '★ 리더' : n.phase === 'joining' ? '가입 대기' : n.roleUnknown ? '' : n.voter ? '투표' : '투표권 없음'}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

const LINK_STATE: Record<MeshLink['state'], [string, 'ok' | 'wa' | 'er' | 'un']> = { up: ['연결됨', 'ok'], slow: ['느림', 'wa'], down: ['끊김', 'er'], pending: ['가입 대기', 'un'] };
/** 그래프·표에서 링크를 누르면 여는 드로어(캔버스 NodesIx '그래프 · 링크 누름'). 다시 연결은 터널 연결 창과 같다 */
function LinkDrawer({ l, onClose, onDone }: { l: MeshLink; onClose: () => void; onDone: () => void }) {
  const act = useReconnectAction(
    [
      { path: nodeTunnelReconnectPath(l.a, l.b), body: {} },
      { path: nodeTunnelReconnectPath(l.b, l.a), body: {} },
    ],
    onDone,
  );
  const [text, tone] = LINK_STATE[l.state];
  return (
    <Drawer title={`${l.a} ↔ ${l.b} 링크`} onClose={onClose}>
      <dl className="kv">
        <dt>상태</dt>
        <dd>
          <Badge tone={tone}>{text}</Badge>
          {l.stale && (
            <>
              {' '}
              <Badge tone="wa">오래된 관측</Badge>
            </>
          )}
        </dd>
        <dt>왕복 지연</dt>
        <dd>{l.rttMs !== undefined ? `${l.rttMs} ms` : '—'}</dd>
        <dt>손실</dt>
        <dd>{l.lossPct !== undefined ? `${l.lossPct}%` : '—'}</dd>
        <dt>마지막 관측</dt>
        <dd>{l.observedAt ? ago(l.observedAt) : '—'}</dd>
      </dl>
      <span className="small muted">링크 관측은 REQ-13. 망 화면의 ‘터널 연결 보기’에서 경로를 바꿀 수 있습니다.</span>
      {act.view}
      <div className="row" style={{ justifyContent: 'flex-end', alignItems: 'center' }}>
        <span className="small muted">시스템 관리자만 · 진행은 터널 연결 창과 같음</span>
        <button className="btn" disabled={act.working} onClick={act.send}>
          다시 연결
        </button>
      </div>
    </Drawer>
  );
}

export function DisksTable({ disks }: { disks: DiskView[] }) {
  if (!disks.length) return <span className="muted small">보고된 디스크가 없습니다.</span>;
  return (
    <div className="table-wrap">
      <table className="tbl">
        <thead>
          <tr>
            <th>마운트 위치</th>
            <th>장치</th>
            <th>형식</th>
            <th>용도</th>
            <th>전체</th>
            <th>사용</th>
            <th>남음</th>
            <th style={{ width: 160 }}>사용률</th>
          </tr>
        </thead>
        <tbody>
          {disks.map((d) => {
            const p = pct(d.used, d.total);
            return (
              <tr key={d.mount}>
                <td>
                  <code>{d.mount}</code>
                  {d.stale && (
                    <>
                      {' '}
                      <Badge tone="wa">오래된 관측</Badge>
                    </>
                  )}
                </td>
                <td>{d.device ?? '—'}</td>
                <td>{d.fs}</td>
                <td>{d.purpose}</td>
                <td>{fmtBytes(d.total)}</td>
                <td>{fmtBytes(d.used)}</td>
                <td>{fmtBytes(d.free ?? (d.total !== undefined && d.used !== undefined ? d.total - d.used : undefined))}</td>
                <td>
                  {d.used === undefined || !d.total ? (
                    <span className="muted">—</span>
                  ) : (
                    <span className="row" style={{ flexWrap: 'nowrap' }}>
                      <span className="bar" style={{ flex: 1 }}>
                        <i className={p >= 90 ? 'crit' : p >= 80 ? 'hi' : ''} style={{ width: `${p}%` }} />
                      </span>
                      <span style={{ color: p >= 90 ? 'var(--er)' : p >= 80 ? 'var(--wa)' : undefined }}>{p}%</span>
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function ServersPage() {
  const navigate = useNavigate();
  const { isAdmin, tenant } = useTenantRole();
  // 관리자가 아니면 작업 공간 보기로 읽는다(tenant 없이는 시스템 관리자만, 데몬 #373)
  const scope = isAdmin ? undefined : tenant || undefined;
  const nodes = usePoll((s) => nodesOverview(s, scope), [scope], DEFAULT_POLL_MS);
  const mesh = usePoll((s) => fetchMesh(s, scope), [scope], DEFAULT_POLL_MS);
  const [filter, setFilter] = useState<'all' | 'ready' | 'problem' | 'joining'>('all');
  const [sel, setSel] = useState<string>();
  const [adding, setAdding] = useState<{ node?: string }>();
  const [link, setLink] = useState<string>();
  const openLink = link ? mesh.data?.find((l) => `${l.a}/${l.b}` === link) : undefined;
  const shell = useShellPolicy(0);
  const [shellSettings, setShellSettings] = useState(false);
  const [rowMenu, setRowMenu] = useState<{ node: string; at: { x: number; y: number } }>();
  const selected = sel ?? nodes.data?.nodes[0]?.id;
  // 서버 줄 ⋯ (캔버스 NodesIx v156). 가입 대기 서버는 가입 이어 하기만
  const rowMenuItems = (id: string): MenuItem[] => {
    const n = nodes.data?.nodes.find((x) => x.id === id);
    if (n && joinInProgress(n)) return [{ label: '가입 이어 하기', onSelect: () => setAdding({ node: id }), disabledReason: isAdmin ? undefined : '시스템 관리자만 할 수 있습니다' }];
    const go = (act: string) => () => navigate(`/servers/${id}?act=${act}`);
    return [
      { label: '서버 상세', onSelect: () => navigate(`/servers/${id}`) },
      { label: '셸 열기', hint: 'SSH · 켜진 서버만', disabledReason: shellBlocked(id, shell.q.data, shell.forbidden), onSelect: () => navigate(`/servers/${id}/shell?new=1`) },
      { label: '이 서버의 컨테이너', onSelect: () => navigate(`/servers/${id}/containers`) },
      { label: '디스크 보기', onSelect: () => setSel(id) },
      { label: '', sep: true },
      { label: '격리…', onSelect: go('isolate'), disabledReason: n?.phase === 'isolated' ? '이미 격리됨' : undefined },
      { label: '비우기…', hint: '컨테이너 옮기기', onSelect: go('drain'), disabledReason: n?.drain && drainRunning(n.drain.state) ? '비우는 중입니다' : undefined },
      { label: '서버 제거…', danger: true, onSelect: go('remove') },
    ];
  };
  const disks = usePoll((s) => (selected ? nodeDisks(selected, s, scope) : Promise.resolve([] as DiskView[])), [selected, scope], DEFAULT_POLL_MS);

  return (
    <>
      <PageHeader
        title="서버"
        ids="UI-11 · UI-13 · UI-18 · UI-19"
        actions={
          <>
            <Refresh q={nodes} />
            {isAdmin && (
              <button className="btn" onClick={() => setShellSettings(true)}>
                서버 셸 설정…
              </button>
            )}
            <button className="btn primary" disabled={!isAdmin} title={isAdmin ? undefined : '시스템 관리자만 서버를 추가할 수 있습니다'} onClick={() => setAdding({})}>
              서버 추가
            </button>
          </>
        }
      />
      <Tabs label="서버 탭" items={SERVER_TABS} />
      <HelpBox terms="서버 (node) · Mesh 링크 (서버 간 망, TUN tunnel) · 투표 서버 (voter) · 투표권 없음 (non-voter) · 저장 경로 (node storage root)">
        <b>이 화면은</b> 클러스터에 참여한 서버 목록과 서버끼리 이어진 Mesh 링크 그래프를 함께 봅니다. 서버를 고르면 그래프에서 강조되고 아래에 그 서버의 디스크 목록이 나옵니다. 새 서버는 '서버 추가'에서 가입을 승인하고, 새 서버에서 안내된 명령을 실행해 가입시킵니다.
      </HelpBox>
      <Load q={nodes} what="서버 목록을 불러오지 못했습니다">
        {(p) => {
          const list = p.nodes.filter((n) => filter === 'all' || (filter === 'ready' ? n.phase === 'ready' : filter === 'joining' ? n.phase === 'joining' : n.phase !== 'ready' && n.phase !== 'joining'));
          return (
            <div className="split rev">
              <Card className="aside" title="서버 목록">
                <div className="segmented" role="radiogroup" aria-label="상태 거르기">
                  {(
                    [
                      ['all', '전체'],
                      ['ready', '준비됨'],
                      ['problem', '문제 있음'],
                      ['joining', '가입 대기'],
                    ] as const
                  ).map(([v, l]) => (
                    <button key={v} type="button" className={filter === v ? 'on' : ''} aria-checked={filter === v} role="radio" onClick={() => setFilter(v)}>
                      {l}
                    </button>
                  ))}
                </div>
                <div className="col" style={{ gap: 8 }}>
                  {list.map((n) => (
                    <button
                      key={n.id}
                      type="button"
                      className={`tnode ${selected === n.id ? 'selected' : ''}`}
                      style={{ flexDirection: 'column', alignItems: 'stretch', gap: 6 }}
                      onClick={() => setSel(n.id)}
                      onDoubleClick={() => navigate(`/servers/${n.id}`)}
                    >
                      <span className="row between">
                        <b>{n.id}</b>
                        <span className="row">
                          <PhaseBadge phase={n.phase} />
                          {n.cordoned && (
                            <Badge tone="wa" title={cordonNote(n)}>
                              새 배치 막음
                            </Badge>
                          )}
                          {!n.roleUnknown && <span className="small muted">{n.leader ? '투표 서버 · 리더' : n.voter ? '투표 서버' : '투표권 없음'}</span>}
                        </span>
                      </span>
                      <UsageBar label="CPU" used={n.cpuPercent} total={n.cpuPercent === undefined ? undefined : 100} text={n.cpuPercent === undefined ? '—' : `${Math.round(n.cpuPercent)}%`} />
                      <UsageBar label="메모리" used={n.memory?.used} total={n.memory?.total} text={n.memory ? `${fmtBytes(n.memory.used)}/${fmtBytes(n.memory.total)}` : n.memUsed !== undefined ? `${fmtBytes(n.memUsed)} 사용` : '—'} />
                      <UsageBar label="디스크" used={n.disk?.used} total={n.disk?.total} text={n.disk ? `${pct(n.disk.used, n.disk.total)}%` : '—'} />
                      <span className="row between">
                        <Link to={`/servers/${n.id}`} className="small" onClick={(e) => e.stopPropagation()}>
                          자세히 →
                        </Link>
                        <span className="row" style={{ gap: 4 }}>
                        {isAdmin && joinInProgress(n) && (
                          <span
                            role="link"
                            tabIndex={0}
                            className="small"
                            style={{ color: '#1F5FBF', cursor: 'pointer' }}
                            onClick={(e) => (e.stopPropagation(), setAdding({ node: n.id }))}
                            onKeyDown={(e) => e.key === 'Enter' && (e.stopPropagation(), setAdding({ node: n.id }))}
                          >
                            가입 이어 하기
                          </span>
                        )}
                        <span
                          role="button"
                          tabIndex={0}
                          aria-label={`${n.id} 메뉴`}
                          className="small muted"
                          style={{ cursor: 'pointer', padding: '0 6px' }}
                          onClick={(e) => {
                            e.stopPropagation();
                            const r = e.currentTarget.getBoundingClientRect();
                            setRowMenu({ node: n.id, at: { x: r.left, y: r.bottom + 4 } });
                          }}
                          onKeyDown={(e) => {
                            if (e.key !== 'Enter') return;
                            e.stopPropagation();
                            const r = e.currentTarget.getBoundingClientRect();
                            setRowMenu({ node: n.id, at: { x: r.left, y: r.bottom + 4 } });
                          }}
                        >
                          ⋯
                        </span>
                        </span>
                      </span>
                    </button>
                  ))}
                </div>
                <span className="small muted">
                  {p.nodes.length}대{p.voters ? ` · 투표 서버 ${p.voters} · 과반 ${p.quorum}` : ''}{p.revision ? ` · 기준 버전 ${p.revision}` : ''}
                </span>
              </Card>
              <div className="primary col" style={{ gap: 20 }}>
                <Card title="Mesh 링크" actions={<Refresh q={mesh} poll={false} />}>
                  <Load q={mesh}>
                    {(m) => (
                      <>
                        <MeshGraph nodes={p.nodes} links={m} selected={selected} onSelect={setSel} onLink={(l) => setLink(`${l.a}/${l.b}`)} />
                        <div className="row small muted">
                          <span>
                            <span style={{ color: '#1a7f37' }}>━</span> 연결됨
                          </span>
                          <span>
                            <span style={{ color: '#c4500a' }}>┅</span> 느림·손실
                          </span>
                          <span>
                            <span style={{ color: '#cf222e' }}>━</span> 끊김
                          </span>
                          <span>
                            <span style={{ color: '#8a919c' }}>╌</span> 가입 대기
                          </span>
                        </div>
                        <div className="table-wrap">
                          <table className="tbl">
                            <thead>
                              <tr>
                                <th>링크</th>
                                <th>상태</th>
                                <th>지연 · 손실</th>
                                <th>마지막 관측</th>
                              </tr>
                            </thead>
                            <tbody>
                              {m.map((l) => (
                                <tr key={`${l.a}-${l.b}`} className={selected && (l.a === selected || l.b === selected) ? 'selected' : ''} style={{ cursor: 'pointer' }} onClick={() => setLink(`${l.a}/${l.b}`)}>
                                  <td>
                                    {l.a} ↔ {l.b}
                                  </td>
                                  <td>
                                    <Badge tone={l.state === 'up' ? 'ok' : l.state === 'slow' ? 'wa' : l.state === 'down' ? 'er' : 'un'}>{{ up: '연결됨', slow: '느림', down: '끊김', pending: '가입 대기' }[l.state]}</Badge>
                                    {l.stale && (
                                      <>
                                        {' '}
                                        <Badge tone="wa">오래된 관측</Badge>
                                      </>
                                    )}
                                  </td>
                                  <td>{l.rttMs !== undefined ? `${l.rttMs} ms${l.lossPct ? ` · 손실 ${l.lossPct}%` : ''}` : '—'}</td>
                                  <td className="muted">{l.observedAt ? ago(l.observedAt) : '—'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        <span className="small muted">링크 관측은 mydcd REQ-13이 들어오면 실제 값으로 바뀝니다.</span>
                      </>
                    )}
                  </Load>
                </Card>
                {selected && (
                  <Card title={`${selected} 디스크`} actions={<Refresh q={disks} />}>
                    <Load q={disks}>{(d) => <DisksTable disks={d} />}</Load>
                    <span className="small muted">
                      사용량은 관측값이며 사용 한도 보장이 아닙니다. 같은 파일 시스템을 공유하는 경로는 남은 공간을 한 번만 셉니다. 시스템·컨테이너 디스크는 REQ-12.
                    </span>
                  </Card>
                )}
              </div>
            </div>
          );
        }}
      </Load>
      {openLink && <LinkDrawer l={openLink} onClose={() => setLink(undefined)} onDone={() => void mesh.refresh()} />}
      {shellSettings && <ShellSettingsDialog onClose={() => (setShellSettings(false), void shell.q.refresh())} />}
      {rowMenu && (
        <ContextMenu
          at={rowMenu.at}
          onClose={() => setRowMenu(undefined)}
          items={rowMenuItems(rowMenu.node)}
        />
      )}
      {adding && <AddServerWizard initial={adding.node} onClose={() => (setAdding(undefined), void nodes.refresh())} />}
    </>
  );
}

export function ConsensusPage() {
  const r = usePoll((s) => raft(s), [], DEFAULT_POLL_MS);
  const led = usePoll((s) => ledger(s), [], DEFAULT_POLL_MS);
  const cq = usePoll((s) => raftCompact(s), [], DEFAULT_POLL_MS);
  const [rotating, setRotating] = useState(false);
  const [compacting, setCompacting] = useState(false);
  const [lastOpen, setLastOpen] = useState(false);
  const cMissing = cq.error instanceof ApiError && (cq.error.status === 404 || cq.error.status === 405);
  const cRun = cq.data?.last;
  const cBusy = cRun?.state === 'running';
  const toast = useToast();
  // 압축 중에는 2초마다 다시 읽고, 끝나면 알림을 띄운다.
  const wasBusy = useRef<string | undefined>(undefined);
  const refreshC = cq.refresh;
  useEffect(() => {
    if (!cBusy) return;
    const t = setInterval(() => refreshC(), 2000);
    return () => clearInterval(t);
  }, [cBusy, refreshC]);
  useEffect(() => {
    if (cBusy) wasBusy.current = cRun?.id ?? cRun?.at;
    else if (cRun && wasBusy.current === (cRun.id ?? cRun.at)) {
      wasBusy.current = undefined;
      toast(compactDoneText(cRun), cRun.state === 'failed' ? 'er' : 'info');
    }
  }, [cBusy, cRun, toast]);
  return (
    <>
      <PageHeader title="서버" ids="UI-17" actions={<Refresh q={r} />} />
      <Tabs label="서버 탭" items={SERVER_TABS} />
      <HelpBox terms="합의 (quorum) · 리더 (leader) · 임기 (term) · 커밋 위치 (commit index) · 스냅샷 (snapshot) · 합의 로그 압축 (Raft log compaction)">
        <b>이 탭은</b> 클러스터가 결정을 내릴 수 있는 상태인지, 몇 대까지 멈춰도 되는지, 투표 서버마다 얼마나 따라왔는지 보여 줍니다.
      </HelpBox>
      <Load q={r} what="합의 상태를 불러오지 못했습니다">
        {(v) => (
          <>
            <div className="grid tiles">
              <Tile label="합의" value={v.quorum ? '확보' : '없음'} tone={v.quorum ? 'ok' : 'er'} sub={`리더 ${v.leader || '없음'} · 임기 ${v.term}`} />
              <Tile label="커밋 위치" value={v.commitIndex.toLocaleString()} sub={`구성 버전 ${v.configIndex.toLocaleString()}`} />
              <Tile label="멈춰도 되는 서버" value={`${v.tolerate}대`} sub={`투표 서버 ${v.voters}${v.responding !== undefined ? ` · 응답 ${v.responding}` : ''} · 과반 ${v.quorumSize}`} />
              <Tile label="스냅샷" value={v.snapshotIndex?.toLocaleString() ?? '—'} sub={v.snapshotAt ? `${fmtTime(v.snapshotAt)} 찍음${v.observedBy ? ` · ${v.observedBy} 관측` : ''}` : '아직 없음'} />
            </div>
            {compacting && cq.data && <CompactDialog v={v} c={cq.data} onClose={() => setCompacting(false)} onDone={() => cq.refresh()} />}
            {lastOpen && cRun && (
              <Drawer title={`수동 압축 ${fmtTime(cRun.at)}`} onClose={() => setLastOpen(false)}>
                <KV
                  items={[
                    ['상태', `${cRun.state === 'running' ? '진행 중' : cRun.state === 'done' ? '완료' : '일부 실패'} · ${cRun.nodes.filter((x) => x.state === 'done').length}/${cRun.nodes.length}`],
                    ['요청', `${cRun.by} · ${cRun.mode === 'minimal' ? '보관 로그까지 줄이기' : '보관 로그 유지'}`],
                    ...cRun.nodes.map((x): [string, string] => [x.node, compactNodeText(x)]),
                    ...(cRun.id ? ([['작업 기록', cRun.id]] as [string, string][]) : []),
                  ]}
                />
              </Drawer>
            )}
            {rotating && led.data?.epoch !== undefined && (
              <LedgerDialog
                epoch={led.data.epoch}
                quorum={`${v.quorum ? '확보' : '없음'} · 투표 서버 ${v.voters}`}
                onClose={() => setRotating(false)}
                onDone={() => led.refresh()}
              />
            )}
            {v.tolerate === 0 && <div className="note wa">투표 서버가 한 대라도 멈추면 합의를 잃습니다. 투표 서버를 3대 이상으로 두면 1대까지 견딥니다.</div>}
            <Card title="투표 서버별 복제">
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>서버</th>
                      <th>역할</th>
                      <th>복제 위치</th>
                      <th>뒤처짐</th>
                      <th>적용 위치</th>
                      <th>마지막 연락</th>
                      <th>로그 크기</th>
                    </tr>
                  </thead>
                  <tbody>
                    {v.members.map((m) => (
                      <tr key={m.node}>
                        <td>
                          <Link to={`/servers/${m.node}`}>{m.node}</Link> {m.node === v.leader && <Badge tone="tag">리더</Badge>}
                        </td>
                        <td>
                          {roleText(m)}
                          {m.stale && (
                            <>
                              {' '}
                              <Badge tone="wa">오래된 관측</Badge>
                            </>
                          )}
                        </td>
                        <td>{m.match?.toLocaleString() ?? '—'}</td>
                        <td style={{ color: (m.lag ?? 0) > 100 ? 'var(--er)' : undefined }}>{m.lag ?? '—'}</td>
                        <td>{m.applied?.toLocaleString() ?? '—'}</td>
                        <td className="muted">{m.lastContactAt ? ago(m.lastContactAt) : '—'}</td>
                        <td>{fmtBytes(m.logBytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
            <div className="grid wide">
              <Card title="리더 선거 · 구성 변경 기록">
                <KV items={v.events.map((e) => [fmtTime(e.at), e.text])} />
              </Card>
              <Card title="스냅샷 · 원장 유지보수" actions={<span className="small muted">고급 · 시스템 관리자</span>}>
                <KV
                  items={[
                    ['마지막 스냅샷', v.snapshotAt ? `위치 ${v.snapshotIndex?.toLocaleString() ?? '—'} · ${fmtTime(v.snapshotAt)}${v.observedBy ? ` · ${v.observedBy} 관측` : ''}` : '아직 없음'],
                    ['원장(ledger) 세대', led.data?.epoch !== undefined ? `epoch ${led.data.epoch}` : led.error ? '읽지 못함' : '웹 서버가 아직 알려 주지 않음'],
                    ...(cq.data ? ([['로그 보관', `스냅샷 뒤 ${cq.data.retain.toLocaleString()}건 유지 · 서버마다 ${compactRange(v.members.map((x) => x.logBytes))}`]] as [string, React.ReactNode][]) : []),
                    [
                      '마지막 수동 압축',
                      cMissing ? (
                        <span className="muted" key="c">서버 기능 대기</span>
                      ) : cBusy && cRun ? (
                        <CompactProgress key="c" run={cRun} />
                      ) : cRun ? (
                        <button key="c" className="linkish" onClick={() => setLastOpen(true)}>
                          {compactSummary(cRun)}
                        </button>
                      ) : (
                        '아직 없음'
                      ),
                    ],
                  ]}
                />
                {cRun?.state === 'failed' &&
                  cRun.nodes
                    .filter((x) => x.state === 'failed')
                    .map((x) => (
                      <div key={x.node} className="note er small">
                        <b>{x.node} 압축 실패</b> · {x.error ?? '원인 모름'}. 기존 스냅샷과 로그는 그대로입니다. 다른 서버는 계속했습니다.
                      </div>
                    ))}
                <span className="small muted">
                  <b>지금 압축 (compact)</b>은 고른 서버가 바로 스냅샷을 찍고 그 앞의 로그를 지웁니다. 결정 저장은 멈추지 않으며 서버마다 따로 합니다. 원장 교체는 확인 다이얼로그(이름 재입력)를 거칩니다. 둘 다 작업 기록에 남습니다.
                </span>
                <div className="row">
                  <button
                    className="btn"
                    disabled={cMissing || !cq.data || cBusy}
                    title={cMissing ? '서버 기능 대기' : cBusy ? '이미 압축 중입니다. 끝난 뒤 다시 누를 수 있습니다.' : undefined}
                    onClick={() => setCompacting(true)}
                  >
                    지금 압축…
                  </button>
                  <button
                    className="btn danger"
                    disabled={led.data?.epoch === undefined || !v.quorum}
                    title={led.data?.epoch === undefined ? '웹 서버가 원장 세대를 아직 알려 주지 않습니다' : !v.quorum ? '합의가 없어 지금은 바꿀 수 없습니다' : undefined}
                    onClick={() => setRotating(true)}
                  >
                    원장 교체…
                  </button>
                </div>
              </Card>
            </div>
          </>
        )}
      </Load>
    </>
  );
}

/** 원장 교체(rotate-ledger). expected = 지금 세대, payload = 다음 세대. 되돌릴 수 없어 다음 세대를 입력해 확인한다. */
function LedgerDialog({ epoch: now, quorum, onClose, onDone }: { epoch: number; quorum: string; onClose: () => void; onDone: () => void }) {
  // 열 때의 세대로 고정한다(적용 뒤 목록이 새로 읽혀도 다이얼로그 내용은 그대로).
  const [epoch] = useState(now);
  const m = useMutation();
  const [confirm, setConfirm] = useState('');
  const [why, setWhy] = useState<'busy' | 'moved'>();
  const want = `epoch ${epoch + 1}`;
  // mydcd는 진행 중 작업과 세대가 이미 바뀐 경우를 같은 condition-failed로 준다. 세대를 다시 읽어 나눈다.
  const done = (o?: OpView) => {
    if (o?.state === 'applied') onDone();
    if (o?.state === 'failed' && o.resultCode === 1)
      void ledger().then(
        (l) => (setWhy(l.epoch === epoch ? 'busy' : 'moved'), onDone()),
        () => undefined,
      );
  };
  return (
    <Dialog
      title="원장을 교체할까요?"
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
            <button className="btn danger solid" disabled={confirm.trim() !== want || m.busy} onClick={() => void m.run('/ledger/rotate', { expected: epoch }).then(done)}>
              원장 교체
            </button>
          </>
        )
      }
    >
      <p>합의 원장(ledger)을 새 세대(epoch {epoch + 1})로 교체합니다. 교체하는 동안 잠깐 결정 저장이 멈춥니다. 되돌릴 수 없고 작업 기록에 남습니다.</p>
      <KV
        items={[
          ['현재 세대', `epoch ${epoch}`],
          ['합의', quorum],
        ]}
      />
      <Field label={<>확인하려면 <b className="mono">{want}</b>을(를) 입력하세요</>}>
        <input className="mono" value={confirm} onChange={(e) => setConfirm(e.target.value)} disabled={!!m.op} />
      </Field>
      <MutationError error={m.error} />
      {m.op && (
        <>
          {why === 'busy' && <div className="note wa">끝나지 않은 작업(데이터 저장소·앱·보관함·저장 경로 등)이 있어 지금은 교체할 수 없습니다. 진행 중인 작업이 끝난 뒤 다시 하세요.</div>}
          {why === 'moved' && <div className="note wa">다른 사람이 먼저 원장을 교체했습니다. 창을 닫고 지금 세대를 확인하세요.</div>}
          <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), done(o))} />
        </>
      )}
    </Dialog>
  );
}

const ROLE_KO: Record<string, string> = { leader: '투표 서버 · 리더', follower: '투표 서버', candidate: '투표 서버 · 선거 중', 'non-voter': '투표권 없음', pending: '가입 대기' };
/** 데몬 #367의 role이 있으면 그걸, 없으면 suffrage로 */
const roleText = (m: RaftView['members'][number]) => (m.role ? ROLE_KO[m.role.toLowerCase()] ?? m.role : m.voter ? '투표 서버' : '투표권 없음');
const compactRange = (bs: (number | undefined)[]) => {
  const xs = bs.filter((b): b is number => !!b && b > 0);
  if (!xs.length) return '—';
  const lo = Math.min(...xs);
  const hi = Math.max(...xs);
  return fmtBytes(lo) === fmtBytes(hi) ? fmtBytes(lo) : `${fmtBytes(lo)}~${fmtBytes(hi)}`;
};
function compactNodeText(x: RaftCompactRun['nodes'][number]): string {
  if (x.state === 'queued') return '기다리는 중';
  if (x.state === 'running') return `스냅샷 쓰는 중${x.snapshotBytes ? ` · ${fmtBytes(x.snapshotBytes)}` : ''}`;
  if (x.state === 'skipped') return `건너뜀 · ${x.error ?? '응답하지 않음'}`;
  if (x.state === 'failed') return `실패 · ${x.error ?? '원인 모름'}`;
  return `스냅샷 ${x.snapshotIndex?.toLocaleString() ?? '—'} · ${fmtBytes(x.logBytesBefore)} → ${fmtBytes(x.logBytesAfter)}${x.durationMs ? ` · ${(x.durationMs / 1000).toFixed(1)}초` : ''}`;
}
function compactSummary(r: RaftCompactRun): string {
  const done = r.nodes.filter((x) => x.state === 'done');
  const before = done.reduce((a, x) => a + (x.logBytesBefore ?? 0), 0);
  const after = done.reduce((a, x) => a + (x.logBytesAfter ?? 0), 0);
  if (r.state === 'running') return `${fmtTime(r.at)} · ${r.by} · 진행 중 ${done.length}/${r.nodes.length}`;
  return `${fmtTime(r.at)} · ${r.nodes.map((x) => x.node).join('·')} · ${r.by}${done.length ? ` · 로그 ${fmtBytes(before)} → ${fmtBytes(after)}` : ''}`;
}

function compactDoneText(r: RaftCompactRun): string {
  const done = r.nodes.filter((x) => x.state === 'done');
  const before = done.reduce((a, x) => a + (x.logBytesBefore ?? 0), 0);
  const after = done.reduce((a, x) => a + (x.logBytesAfter ?? 0), 0);
  const sizes = done.length ? ` · 로그 합계 ${fmtBytes(before)} → ${fmtBytes(after)}` : '';
  if (r.state === 'failed') return `압축을 마쳤지만 ${r.nodes.length - done.length}대가 실패했습니다. ${done.length}/${r.nodes.length}대 완료${sizes}.`;
  return `압축을 마쳤습니다. ${done.length}대 모두 새 스냅샷${sizes}.`;
}

/** 압축 진행: 다른 진행 표시(배포 후 확인 등)와 같은 팝오버 */
function CompactProgress({ run }: { run: RaftCompactRun }) {
  const done = run.nodes.filter((x) => x.state === 'done' || x.state === 'failed' || x.state === 'skipped').length;
  const running = run.nodes.some((x) => x.state === 'running') ? 0.5 : 0;
  const w = Math.round(((done + running) / Math.max(1, run.nodes.length)) * 100);
  return (
    <Popover
      button={
        <span className="small">
          진행 보기 · <Badge tone="pr">압축 중 {done}/{run.nodes.length}</Badge>
        </span>
      }
      className="linkish"
      width={360}
      align="left"
    >
      {() => (
        <div style={{ display: 'grid', gap: 8 }}>
          <b>
            합의 로그 압축 · {run.nodes.length}대 중 {done}대 완료
          </b>
          <div className="steps-list">
            {run.nodes.map((x) => (
              <div key={x.node}>
                <i className={x.state === 'done' ? 'ok' : x.state === 'running' ? 'pr' : x.state === 'failed' ? 'er' : ''} />
                <span>
                  {x.node} <span className="muted">{x.state === 'queued' ? '' : compactNodeText(x)}</span>
                </span>
              </div>
            ))}
          </div>
          <span className="bar">
            <i style={{ width: `${w}%` }} />
          </span>
        </div>
      )}
    </Popover>
  );
}

const COMPACT_STATE: Record<string, string> = { queued: '대기', running: '진행 중', done: '끝', failed: '실패', skipped: '건너뜀' };
function CompactDialog({ v, c, onClose, onDone }: { v: RaftView; c: RaftCompactView; onClose: () => void; onDone: () => void }) {
  const voters = v.members.filter((x) => x.voter);
  // 5초 넘게 응답이 없으면 고를 수 없다.
  const alive = (x: RaftView['members'][number]) => !!x.lastContactAt && Date.now() - Date.parse(x.lastContactAt) < 5000;
  const [pick, setPick] = useState(() => new Set(voters.filter((x) => x.node === v.leader || alive(x)).map((x) => x.node)));
  const [mode, setMode] = useState<'keep' | 'minimal'>('keep');
  const [serial, setSerial] = useState(true);
  const m = useMutation();
  const cols = { gridTemplateColumns: '28px 0.8fr 1.2fr 1fr 0.8fr' };
  const picked = [...pick].sort();
  // 미리보기는 고른 서버·방식이 바뀔 때마다 다시 읽는다(데몬 #387)
  const plan = usePoll((s) => (picked.length ? raftCompactPlan(picked, mode, serial, s) : Promise.resolve(undefined)), [picked.join(','), mode, serial]);
  const changed = m.error instanceof ApiError && m.error.code === 'plan-changed';
  // 접수 뒤 진행은 /raft/compactions/op-<opId>에서 끝날 때까지 읽는다
  const operation = m.op?.state === 'applied' ? `op-${m.op.id}` : undefined;
  const prog = usePoll((s) => (operation ? raftCompaction(operation, s) : Promise.resolve(undefined)), [operation]);
  const complete = !!prog.data?.complete;
  const { setInterval: setProgInterval } = prog;
  useEffect(() => setProgInterval(operation && !complete ? 2000 : 0), [operation, complete, setProgInterval]);
  const send = () => {
    // 거절(구성 바뀜 등) 뒤에는 새 작업으로
    if (m.error && !uncertain(m.error)) m.reset();
    return m.run('/raft/compact', { nodes: picked, mode, serial, plan: plan.data!.plan }).then((o) => o?.state === 'applied' && onDone());
  };
  return (
    <Dialog
      title="합의 로그 지금 압축 (compact)"
      width={560}
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
            <button className="btn primary" disabled={!pick.size || m.busy || !plan.data?.plan} onClick={() => void send()}>
              압축 시작
            </button>
          </>
        )
      }
    >
      {prog.data && (
        <div className={`note small ${prog.data.failed ? 'er' : prog.data.complete ? 'ok' : 'info'}`}>
          {prog.data.complete ? '압축 끝' : '압축 중'} · 완료 {prog.data.done}/{prog.data.total}
          {prog.data.running ? ` · 진행 ${prog.data.running}` : ''}
          {prog.data.queued ? ` · 대기 ${prog.data.queued}` : ''}
          {prog.data.failed ? ` · 실패 ${prog.data.failed}` : ''}
          {prog.data.skipped ? ` · 건너뜀 ${prog.data.skipped}` : ''}
          {prog.data.nodes.length > 0 && <div>{prog.data.nodes.map((x) => `${x.node} ${COMPACT_STATE[x.state] ?? x.state}${x.code ? ` (${x.code})` : ''}`).join(' · ')}</div>}
        </div>
      )}
      <div className="gtbl">
        <div className="gr th" style={cols}>
          <span />
          <span>서버</span>
          <span>역할</span>
          <span>스냅샷 뒤 로그</span>
          <span>로그 크기</span>
        </div>
        {voters.map((x) => {
          const ok = x.node === v.leader || alive(x);
          return (
            <div key={x.node} className="gr" style={cols} title={ok ? undefined : `${x.node}가 응답하지 않아 고를 수 없습니다. 응답하는 서버만 압축할 수 있습니다.`}>
              <input type="checkbox" aria-label={`${x.node} 압축`} disabled={!ok || !!m.op} checked={pick.has(x.node)} onChange={(e) => setPick((p) => (e.target.checked ? new Set([...p, x.node]) : new Set([...p].filter((n) => n !== x.node))))} />
              <span>{x.node}</span>
              <span>{x.node === v.leader ? '리더' : `팔로워${x.lag ? ` · ${x.lag.toLocaleString()} 뒤처짐` : ''}`}{ok ? '' : ' · 응답 없음'}</span>
              <span>{c.entries[x.node] !== undefined ? `${c.entries[x.node].toLocaleString()}건` : '—'}</span>
              <span>{fmtBytes(x.logBytes)}</span>
            </div>
          );
        })}
      </div>
      <label className="check">
        <input type="radio" name="compact-mode" checked={mode === 'keep'} disabled={!!m.op} onChange={() => setMode('keep')} />
        <span>
          보관 로그 유지 (스냅샷 뒤 {c.retain.toLocaleString()}건)
          <br />
          <span className="small muted">뒤처진 팔로워가 로그로 따라잡을 수 있습니다. 보통 이것으로 충분합니다.</span>
        </span>
      </label>
      <label className="check">
        <input type="radio" name="compact-mode" checked={mode === 'minimal'} disabled={!!m.op} onChange={() => setMode('minimal')} />
        <span>
          보관 로그까지 줄이기 ({c.minimal.toLocaleString()}건만 남김)
          <br />
          <span className="small muted">디스크를 가장 많이 비웁니다. {c.minimal.toLocaleString()}건 넘게 뒤처진 서버는 스냅샷 전체를 다시 받습니다.</span>
        </span>
      </label>
      <label className="check">
        <input type="checkbox" checked={serial} disabled={!!m.op} onChange={(e) => setSerial(e.target.checked)} />
        <span>
          한 대씩 차례로 (리더는 마지막)
          <br />
          <span className="small muted">동시에 하면 디스크 쓰기가 몰립니다.</span>
        </span>
      </label>
      {plan.data && !m.op && (
        <span className="small">
          실행 순서{plan.data.parallel ? ' (동시에)' : ''}: <b>{plan.data.nodes.join(plan.data.parallel ? ' · ' : ' → ')}</b> · {plan.data.total}대
          {plan.data.retain !== undefined ? ` · 스냅샷 뒤 ${plan.data.retain.toLocaleString()}건 남김` : ''}
        </span>
      )}
      {!!plan.error && !m.op && <ErrorBand error={plan.error} what="압축 미리보기를 읽지 못했습니다" onRetry={plan.refresh} />}
      <div className="note info small">결정 저장은 멈추지 않습니다. 서버마다 스냅샷을 쓰는 동안(보통 1~3초) 그 서버의 디스크 쓰기가 늘어납니다. 원장 세대(epoch)는 바뀌지 않습니다.</div>
      {changed && (
        <div className="note wa small row between">
          <span>읽는 사이 서버 구성이 바뀌었습니다. 미리보기를 새로 읽은 뒤 다시 시작하세요.</span>
          <button className="btn sm" onClick={() => (m.reset(), plan.refresh())}>
            새로 읽기
          </button>
        </div>
      )}
      {!changed && <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}
