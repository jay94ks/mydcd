// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react';
import { usePhone } from '../lib/viewport';
import { MHome } from '../mobile/MHome';
import { Link } from 'react-router-dom';
import { appPath, dashboard } from '../api/endpoints';
import type { AttentionItem, NodeView } from '../api/types';
import { useAuth, useSession } from '../auth/session';
import { Badge, HealthBadge, HelpBox, PageHeader, PhaseBadge, Tile, UsageBar, type Tone } from '../components/ui';
import { Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { ago, fmtBytes, fmtTime, pct } from '../lib/format';

export const ATTN: Record<AttentionItem['kind'], [Tone, string]> = {
  approval: ['wa', '승인 대기'],
  problem: ['er', '문제'],
  disk: ['wa', '디스크'],
  'unknown-op': ['un', '결과 불명'],
  progress: ['pr', '진행 중'],
  incident: ['er', '사건'],
  'ingress-block': ['wa', '외부 접속 차단'],
  cert: ['wa', '인증서'],
  webhook: ['un', '웹훅'],
};

export function NodeCard({ n, admin }: { n: NodeView; admin: boolean }) {
  const role = n.leader ? '리더' : n.voter ? '투표 서버' : '투표권 없음';
  return (
    <section className="card" style={{ padding: '16px 18px' }}>
      <div className="row between">
        <span className="row">
          {admin ? (
            <Link to={`/servers/${n.id}`} style={{ fontSize: 16, fontWeight: 600 }}>
              {n.id}
            </Link>
          ) : (
            <b style={{ fontSize: 16 }}>{n.id}</b>
          )}
          {!n.roleUnknown && <Badge tone="tag">{role}</Badge>}
        </span>
        <span className="row">
          {n.stale && <Badge tone="wa">오래된 관측</Badge>}
          <PhaseBadge phase={n.phase} />
        </span>
      </div>
      {n.endpoint && <span className="small muted break-any">{n.endpoint}</span>}
      <div className="col" style={{ gap: 8 }}>
        <UsageBar label="CPU" used={n.cpuPercent} total={n.cpuPercent === undefined ? undefined : 100} text={n.cpuPercent === undefined ? '—' : `${Math.round(n.cpuPercent)}%`} />
        <UsageBar label="메모리" used={n.memory?.used} total={n.memory?.total} text={n.memory ? `${fmtBytes(n.memory.used)} / ${fmtBytes(n.memory.total)}` : n.memUsed !== undefined ? `${fmtBytes(n.memUsed)} 사용` : '—'} />
        <UsageBar label="디스크" used={n.disk?.used} total={n.disk?.total} text={n.disk ? `${pct(n.disk.used, n.disk.total)}% · ${fmtBytes(n.disk.total - n.disk.used)} 남음` : '—'} />
      </div>
      <div className="row between small" style={{ borderTop: '1px solid var(--line-2)', paddingTop: 10 }}>
        {n.containers !== undefined ? (
          <span>
            컨테이너 <b>{n.containers}</b>개
          </span>
        ) : (
          <span className="muted">관측 정보 없음</span>
        )}
        {n.observedAt && <span className="muted">마지막 보고 {ago(n.observedAt)}</span>}
      </div>
    </section>
  );
}

export function DashboardPage() {
  return usePhone() ? <MHome /> : <DesktopDashboard />;
}

function DesktopDashboard() {
  const session = useSession();
  const { tenant } = useAuth();
  const admin = session.user.systemAdmin;
  const [filter, setFilter] = useState<string>(admin ? '' : tenant);
  const scopeTenant = admin ? filter : tenant;
  const [sort, setSort] = useState<'name' | 'problem' | 'usage'>('name');
  const d = usePoll((s) => dashboard(scopeTenant || undefined, s), [scopeTenant], DEFAULT_POLL_MS);

  return (
    <>
      <PageHeader title="대시보드" ids={`UI-10 · ${admin ? '시스템 관리자 보기' : '작업 공간 보기'}`} actions={<Refresh q={d} />} />
      <HelpBox terms="서버 (node) · 리더 (leader) · 투표 서버 (voter) · 투표권 없음 (non-voter) · 컨테이너 (Task)">
        <b>이 화면은</b> 클러스터의 서버 현황을 한눈에 보여 줍니다. 보이는 범위는 로그인한 사용자의 권한을 따릅니다. 시스템 관리자는 모든 서버와 모든 작업 공간을, 일반 사용자는 자기 작업 공간에 허용된 서버와 그 작업 공간의 컨테이너만 봅니다.
      </HelpBox>
      <div className="row card" style={{ padding: '10px 14px', flexDirection: 'row' }}>
        <b>보기 범위</b>
        <Badge tone="ok">{d.data?.scope === 'cluster' ? '클러스터 전체' : `작업 공간 ${scopeTenant || tenant}`}</Badge>
        <span className="muted small">{admin ? '시스템 관리자 권한' : '선택한 작업 공간의 허용 서버와 그 몫만'}</span>
        <span className="grow" />
        {admin && (
          <label className="row small">
            작업 공간 필터
            <select value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="">전체</option>
              {session.tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.id}
                </option>
              ))}
            </select>
          </label>
        )}
      </div>
      <Load q={d} what="대시보드를 불러오지 못했습니다" rows={8}>
        {(v) => {
          const ready = v.nodes.filter((n) => n.phase === 'ready').length;
          const joining = v.nodes.filter((n) => n.phase === 'joining');
          const notReady = v.nodes.length - ready - joining.length;
          const containers = v.nodes.reduce((a, n) => a + (n.containers ?? 0), 0);
          const count = (h: string) => v.apps.filter((a) => a.health === h).length;
          const nodes = [...v.nodes].sort((a, b) =>
            sort === 'name' ? a.id.localeCompare(b.id) : sort === 'problem' ? Number(b.phase !== 'ready') - Number(a.phase !== 'ready') : pct(b.disk?.used, b.disk?.total) - pct(a.disk?.used, a.disk?.total),
          );
          return (
            <>
              <div className="grid tiles">
                <Tile label="서버" value={`${ready} / ${v.nodes.length} 준비됨`} sub={joining.length ? `가입 대기 ${joining.length} (${joining.map((n) => n.id).join(', ')})` : notReady ? `준비 안 됨 ${notReady}` : '모두 준비됨'} />
                <Tile label="컨테이너" value={`${containers}개`} sub="보이는 서버의 합" />
                <Tile label="앱" value={v.apps.length} sub={`정상 ${count('healthy')} · 진행 중 ${count('progressing')} · 일부 문제 ${count('degraded')}${count('unhealthy') ? ` · 문제 ${count('unhealthy')}` : ''}${count('unknown') ? ` · 확인 불가 ${count('unknown')}` : ''}`} />
                <Tile label="주의" value={`${v.attention.length}건`} tone={v.attention.length ? 'wa' : 'ok'} sub={v.attention.length ? '아래 목록 참고' : '지금 주의할 것 없음'} />
              </div>
              <section className="col">
                <div className="row between">
                  <h2 style={{ fontSize: 17 }}>서버 현황</h2>
                  <span className="row">
                    <select value={sort} onChange={(e) => setSort(e.target.value as typeof sort)} aria-label="정렬">
                      <option value="name">정렬: 이름</option>
                      <option value="problem">정렬: 문제 먼저</option>
                      <option value="usage">정렬: 사용률 높은 순</option>
                    </select>
                    {admin && (
                      <Link className="btn" to="/servers">
                        서버 관리
                      </Link>
                    )}
                  </span>
                </div>
                <div className="grid cards">
                  {nodes.map((n) => (
                    <NodeCard key={n.id} n={n} admin={admin} />
                  ))}
                </div>
              </section>
              <div className="grid wide">
                <section className="card">
                  <div className="card-head">
                    <h2>주의가 필요한 것</h2>
                    <Link to="/notifications" className="small">
                      알림 모두 보기
                    </Link>
                  </div>
                  {v.attention.length === 0 ? (
                    <span className="muted small">지금 주의할 것이 없습니다.</span>
                  ) : (
                    <div className="table-wrap">
                      <table className="tbl">
                        <tbody>
                          {[...v.attention]
                            .sort((a, b) => (a.kind === 'approval' ? -1 : b.kind === 'approval' ? 1 : 0))
                            .map((a, i) => (
                              <tr key={i}>
                                <td style={{ width: 120 }}>
                                  <Badge tone={ATTN[a.kind][0]}>{ATTN[a.kind][1]}</Badge>
                                </td>
                                <td className="wrap">{a.link ? <Link to={a.link}>{a.text}</Link> : a.text}</td>
                                <td className="muted" style={{ width: 80 }}>
                                  {fmtTime(a.at)}
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </section>
                <section className="card">
                  <div className="card-head">
                    <h2>앱 상태</h2>
                    <Link to="/deploy" className="small">
                      배포된 앱
                    </Link>
                  </div>
                  {v.apps.length === 0 ? (
                    <span className="muted small">아직 배포된 앱이 없습니다.</span>
                  ) : (
                    <div className="table-wrap">
                      <table className="tbl">
                        <thead>
                          <tr>
                            <th>앱</th>
                            <th>작업 공간</th>
                            <th>상태</th>
                            <th>버전</th>
                          </tr>
                        </thead>
                        <tbody>
                          {v.apps.map((a) => (
                            <tr key={`${a.tenant}/${a.app}`}>
                              <td>
                                <Link to={appPath(a.tenant, a.app)}>{a.app}</Link>
                              </td>
                              <td>{a.tenant}</td>
                              <td>
                                <HealthBadge health={a.health} />
                              </td>
                              <td>{a.revision}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </section>
              </div>
            </>
          );
        }}
      </Load>
    </>
  );
}
