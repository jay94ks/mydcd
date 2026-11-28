// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { appPath, apps as fetchApps, archived as fetchArchived } from '../api/endpoints';
import type { AppView, ArchivedApp, Page } from '../api/types';

const emptyPage = <T,>(): Page<T> => ({ items: [], next: '', revision: 0, asOf: new Date().toISOString() });
import { useTenantRole } from '../auth/session';
import { Badge, HealthBadge, HelpBox, PageHeader, Segmented } from '../components/ui';
import { Empty, Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { DataTable } from '../components/DataTable';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { ago } from '../lib/format';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { appsLive } from '../lib/liveTopics';

export function DeployTabs({ archivedCount }: { archivedCount?: number }) {
  return (
    <Tabs
      label="배포 탭"
      items={[
        { to: '/deploy', label: '배포된 앱' },
        { to: '/deploy/new', label: '새 앱 배포', end: false },
        { to: '/deploy/archived', label: `보관된 앱${archivedCount ? ` (${archivedCount})` : ''}` },
      ]}
    />
  );
}

export function NoTenant() {
  return <Empty kind="scope" title="작업 공간을 고르세요">상단 바에서 작업 공간을 고르면 그 작업 공간의 앱이 보입니다. 접근할 수 있는 작업 공간이 없으면 관리자에게 요청하세요.</Empty>;
}

function LastOp({ a }: { a: AppView }) {
  if (!a.lastOp) return <>최근 작업 없음</>;
  const tone = a.lastOp.failed ? 'er' : a.health === 'progressing' ? 'pr' : 'ok';
  return (
    <>
      <Badge tone={tone}>{a.lastOp.status || '—'}</Badge> {a.lastOp.submitter ?? ''}
      {a.lastOp.at ? ` · ${ago(a.lastOp.at)}` : ''}
    </>
  );
}

function AppCard({ a }: { a: AppView }) {
  return (
    <Link to={appPath(a.tenant, a.app)} className="card" style={{ textDecoration: 'none', color: 'inherit', padding: '16px 18px' }}>
      <div className="row between">
        <b style={{ fontSize: 16 }}>{a.app}</b>
        <HealthBadge health={a.health} reason={a.reason} />
      </div>
      <span className="small muted">
        배포 구성 {a.deployment} · 버전 {a.revision}
        {a.claims ? ` · 점유 자원 ${a.claims}` : ''}
      </span>
      {a.observedAt && <span className="small muted">마지막 관측 {ago(a.observedAt)}</span>}
      <div className="row small muted" style={{ borderTop: '1px solid var(--line-2)', paddingTop: 8 }}>
        <LastOp a={a} />
        {a.cd && <Badge tone="tag">자동 배포{a.cd.paused ? ' · 멈춤' : ''}</Badge>}
      </div>
    </Link>
  );
}

/** 휴대폰 배포된 앱 (UI-M4 ①): 카드 목록, 승인 대기·사건 같은 할 일을 한 줄로 */
function MAppsList() {
  const { tenant } = useTenantRole();
  const navigate = useNavigate();
  const [find, setFind] = useState<string>();
  const apps = usePoll((s) => (tenant ? fetchApps(tenant, s) : Promise.resolve(emptyPage<AppView>())), [tenant], DEFAULT_POLL_MS, appsLive(tenant));
  const archived = usePoll((s) => (tenant ? fetchArchived(tenant, s) : Promise.resolve(emptyPage<ArchivedApp>())), [tenant]);
  useMobileTop(
    {
      title: '배포된 앱',
      sub: `작업 공간 ${tenant || '—'}`,
      right: (
        <button type="button" className="ic" aria-label="찾기" onClick={() => setFind((f) => (f === undefined ? '' : undefined))}>
          🔍
        </button>
      ),
    },
    [tenant],
  );
  if (!tenant) return <NoTenant />;
  return (
    <>
      {find !== undefined && <input type="search" className="m-find" autoFocus placeholder="앱 이름 찾기" value={find} onChange={(e) => setFind(e.target.value)} />}
      <div className="mchips">
        <button type="button" className="mchip on">
          배포된 앱 {apps.data?.items.length ?? ''}
        </button>
        <button type="button" className="mchip" onClick={() => navigate('/deploy/archived')}>
          보관된 앱 {archived.data?.items.length ?? ''}
        </button>
      </div>
      <Load q={apps} what="앱 목록을 불러오지 못했습니다">
        {(p) => {
          const rows = p.items.filter((a) => !find || a.app.includes(find.trim()));
          return rows.length === 0 ? (
            <span className="muted small">{p.items.length ? '조건에 맞는 앱이 없습니다.' : '아직 배포된 앱이 없습니다.'}</span>
          ) : (
            <>
              {rows.map((a) => {
                const bad = a.health === 'unhealthy' || a.health === 'degraded';
                return (
                  <Link key={a.app} to={appPath(a.tenant, a.app)} className={`mc${bad ? ' xer' : ''}`}>
                    <div className="hd">
                      <b>{a.app}</b>
                      <HealthBadge health={a.health} reason={a.reason} />
                    </div>
                    <div className="ln">
                      버전 {a.revision} · 배포 구성 {a.deployment}
                      {a.cd ? ` · Git 자동 배포${a.cd.paused ? ' (멈춤)' : ''}` : ''}
                    </div>
                    {a.cd?.candidate && <div className="ln" style={{ color: 'var(--pr)' }}>자동 배포 후보 · {a.cd.candidate.slice(0, 7)}</div>}
                    {a.lastOp?.failed && <div className="ln" style={{ color: 'var(--er)' }}>최근 작업 실패 · {a.lastOp.status}{a.lastOp.at ? ` · ${ago(a.lastOp.at)}` : ''}</div>}
                  </Link>
                );
              })}
            </>
          );
        }}
      </Load>
      <div className="muted small" style={{ textAlign: 'center' }}>
        ‘새 앱 배포’는 넓은 화면에서
      </div>
    </>
  );
}

export function DeployedAppsPage() {
  return usePhone() ? <MAppsList /> : <DesktopDeployedApps />;
}

function DesktopDeployedApps() {
  const { tenant, canDeploy } = useTenantRole();
  const navigate = useNavigate();
  const [view, setView] = useState<'cards' | 'table'>('cards');
  const apps = usePoll((s) => (tenant ? fetchApps(tenant, s) : Promise.resolve(emptyPage<AppView>())), [tenant], DEFAULT_POLL_MS, appsLive(tenant));
  const archived = usePoll((s) => (tenant ? fetchArchived(tenant, s) : Promise.resolve(emptyPage<ArchivedApp>())), [tenant]);
  return (
    <>
      <PageHeader
        title="배포"
        ids="UI-30 · UI-32"
        actions={
          <>
            <Refresh q={apps} />
            <button type="button" className="btn primary" disabled={!canDeploy} title={canDeploy ? undefined : '이 작업 공간의 배포 권한이 필요합니다'} onClick={() => navigate('/deploy/new')}>
              새 앱 배포
            </button>
          </>
        }
      />
      <DeployTabs archivedCount={archived.data?.items.length} />
      <HelpBox terms="앱 (app) · 배포 구성 (deployment) · 목표 (Desired) · 적용됨 (Applied) · 실제 상태 (Observed)">
        <b>이 탭은</b> 작업 공간 <b>{tenant || '—'}</b>에 배포된 앱입니다. 앱을 고르면 개요 · 편집 · 배치 · 자동 배포 · 버전 기록 탭이 열립니다.
      </HelpBox>
      {!tenant ? (
        <NoTenant />
      ) : (
        <Load q={apps} what="앱 목록을 불러오지 못했습니다">
          {(p) =>
            p.items.length === 0 ? (
              <Empty title="아직 배포된 앱이 없습니다" action={canDeploy ? <Link className="btn primary" to="/deploy/new">새 앱 배포</Link> : undefined}>
                app.yaml을 올리거나 폼으로 첫 앱을 배포하세요.
              </Empty>
            ) : (
              <>
                <div className="row between">
                  <Segmented
                    label="보기"
                    value={view}
                    onChange={setView}
                    options={[
                      ['cards', '카드'],
                      ['table', '표'],
                    ]}
                  />
                  <span className="small muted">
                    {p.items.length}개 · 기준 버전 {p.revision}
                  </span>
                </div>
                {view === 'cards' ? (
                  <div className="grid-3">
                    {p.items.map((a) => (
                      <AppCard key={a.app} a={a} />
                    ))}
                  </div>
                ) : (
                  <DataTable
                    rows={p.items}
                    rowKey={(a) => a.app}
                    pageInfo={p}
                    onRowClick={(a) => navigate(appPath(a.tenant, a.app))}
                    columns={[
                      { key: 'app', header: '앱', value: (a) => a.app, render: (a) => <b>{a.app}</b> },
                      { key: 'dep', header: '배포 구성', value: (a) => a.deployment, render: (a) => a.deployment },
                      { key: 'h', header: '상태', value: (a) => a.health, render: (a) => <HealthBadge health={a.health} reason={a.reason} /> },
                      { key: 'rev', header: '버전', value: (a) => a.revision, render: (a) => a.revision },
                      { key: 'obs', header: '마지막 관측', value: (a) => a.observedAt ?? '', render: (a) => (a.observedAt ? ago(a.observedAt) : '—') },
                      { key: 'op', header: '최근 작업', render: (a) => <LastOp a={a} /> },
                      { key: 'cd', header: '자동 배포', value: (a) => (a.cd ? 1 : 0), render: (a) => (a.cd ? `${a.cd.branch} · ${a.cd.mode}` : '—') },
                    ]}
                  />
                )}
              </>
            )
          }
        </Load>
      )}
    </>
  );
}
