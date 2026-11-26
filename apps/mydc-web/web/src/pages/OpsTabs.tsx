// SPDX-License-Identifier: Apache-2.0

// 작업 기록의 탭 (캔버스 Operations UI-A0~A3, 모바일 UI-M1 ①): 내 작업 · cluster.yaml 적용 · 공유 자원 전체 · 웹 설정 변경
import { useState, type ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useMobileTop } from '../mobile/top';
import { resourcesPage } from '../api/endpoints';
import type { DResourceEntry } from '../api/dto';
import { useAuth } from '../auth/session';
import { Card, HelpBox, PageHeader } from '../components/ui';
import { DataTable } from '../components/DataTable';
import { ErrorBand, Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { usePhone } from '../lib/viewport';
import { fmtBytes } from '../lib/format';

export function OpsTabs() {
  const phone = usePhone();
  return (
    <Tabs
      label="작업 기록 탭"
      items={[
        { to: '/system/ops', label: '내 작업' },
        { to: '/system/ops/cluster', label: 'cluster.yaml 적용' },
        { to: '/system/ops/resources', label: phone ? '공유 자원' : '공유 자원 전체' },
        { to: '/system/ops/web', label: phone ? '웹 설정' : '웹 설정 변경' },
      ]}
    />
  );
}

/** 네 탭이 함께 쓰는 머리: 제목 · 도움말 · 탭 */
export function OpsHeader({ actions }: { actions?: ReactNode }) {
  const phone = usePhone();
  const path = useLocation().pathname;
  const tab = path.endsWith('/cluster') ? 'cluster.yaml 적용' : path.endsWith('/resources') ? '공유 자원' : path.endsWith('/web') ? '웹 설정 변경' : '내 작업';
  useMobileTop({ title: '작업 기록', sub: tab }, [tab]);
  // 휴대폰은 도움말 없이 탭만 (UI-M1 ①), 새로 고침은 끌어 내리기로
  if (phone) return <OpsTabs />;
  return (
    <>
      <PageHeader title="작업 기록" ids="UI-A0 · UI-A1 · UI-A2 · UI-A3" actions={actions} />
      <HelpBox terms="작업 (operation) · 결과 불명 (응답 유실) · 공유 자원 (managed resource)">
        <b>이 화면은</b> 내가 보낸 작업과 그 결과를 모아 봅니다. 응답이 끊겨 결과를 모르는 작업은 같은 작업으로 결과를 다시 묻거나 이어서 실행합니다.
      </HelpBox>
      <OpsTabs />
    </>
  );
}

/** cluster.yaml 적용 (UI-A1): 웹에서 부분 cluster.yaml을 보내는 기능이 아직 없다 */
export function OpsClusterPage() {
  return (
    <>
      <OpsHeader />
      <Card title="부분 cluster.yaml 적용 (UI-A1)">
        <div className="note un small">웹 기능 준비 중입니다. 지금은 CLI의 manage apply로 보낸 적용만 있고, 웹에서 보낸 부분 cluster.yaml 적용 기록은 아직 없습니다.</div>
        <span className="small muted">확정된 앞 단계는 되돌린 것처럼 표시하지 않습니다. 누락한 객체는 유지되며 삭제되지 않습니다.</span>
      </Card>
    </>
  );
}

const kindOf = (e: DResourceEntry): [string, string, number | undefined, string] =>
  e.network
    ? ['망', e.network.name, e.network.revision, `${e.network.kind} · ${e.network.cidr}`]
    : e.route
      ? ['외부 접속 경로', `${e.route.host}${e.route.path}`, e.route.revision, `${e.route.app}/${e.route.service}:${e.route.port}`]
      : e.limit
        ? ['사용 한도', e.limit.node || e.tenant, e.limit.revision, `CPU ${e.limit.cpus} · 메모리 ${fmtBytes(e.limit.memoryBytes)} · 컨테이너 ${e.limit.maxContainers}`]
        : ['기타', e.key, undefined, ''];

/** 공유 자원 전체 (UI-A2): 지금 작업 공간의 resources 목록을 쪽 단위로 */
export function OpsResourcesPage() {
  const { tenant } = useAuth();
  const first = usePoll((s) => (tenant ? resourcesPage(tenant, undefined, s) : Promise.resolve(undefined)), [tenant], DEFAULT_POLL_MS);
  const [more, setMore] = useState<{ items: DResourceEntry[]; next: string; for?: Date }>();
  const [moreErr, setMoreErr] = useState<unknown>();
  const extra = more && more.for === first.asOf ? more : undefined;
  const rows = [...(first.data?.items ?? []), ...(extra?.items ?? [])];
  const next = extra ? extra.next : first.data?.next;
  const loadMore = async () => {
    if (!next || !tenant) return;
    setMoreErr(undefined);
    try {
      const r = await resourcesPage(tenant, next);
      // 목록 기준 버전이 바뀐 쪽은 합치지 않는다 (web-api 목록 규칙)
      if (first.data && r.revision !== first.data.revision) {
        setMoreErr(new Error('그사이 자원 목록이 바뀌었습니다. 새로 고침한 뒤 다시 이어 보세요.'));
        return;
      }
      setMore({ items: [...(extra?.items ?? []), ...r.items], next: r.next, for: first.asOf });
    } catch (e) {
      setMoreErr(e);
    }
  };
  if (!tenant) return <Navigate to="/system/ops" replace />;
  return (
    <>
      <OpsHeader actions={<Refresh q={first} />} />
      <Card title={`공유 자원 전체 (UI-A2) · 작업 공간 ${tenant}`} flush>
        <span className="small muted" style={{ padding: '0 14px' }}>
          위쪽 막대에서 고른 작업 공간의 공유 자원만 보입니다. 종류는 망 · 외부 접속 경로 · 사용 한도입니다.
        </span>
        <Load q={first} what="공유 자원을 불러오지 못했습니다">
          {() => (
            <DataTable
              rows={rows}
              rowKey={(e) => e.key}
              emptyTitle="공유 자원이 없습니다"
              columns={[
                { key: 'k', header: '종류', value: (e) => kindOf(e)[0], render: (e) => kindOf(e)[0], m: 'badge' },
                { key: 'n', header: '이름', value: (e) => kindOf(e)[1], render: (e) => <b>{kindOf(e)[1]}</b>, m: 'title' },
                { key: 'd', header: '내용', value: (e) => kindOf(e)[3], render: (e) => <span className="muted">{kindOf(e)[3]}</span> },
                { key: 'v', header: '버전', value: (e) => kindOf(e)[2] ?? 0, render: (e) => <code>{kindOf(e)[2] ?? '—'}</code> },
              ]}
            />
          )}
        </Load>
        <div className="row between small" style={{ padding: '10px 14px' }}>
          <span className="muted">{first.data ? `자원 목록 기준 버전 ${first.data.revision} · ${rows.length}개` : ''}</span>
          {next ? (
            <button className="btn sm" onClick={() => void loadMore()}>
              다음 페이지
            </button>
          ) : null}
        </div>
        {moreErr !== undefined && <ErrorBand error={moreErr} what="다음 쪽을 읽지 못했습니다" />}
      </Card>
    </>
  );
}
