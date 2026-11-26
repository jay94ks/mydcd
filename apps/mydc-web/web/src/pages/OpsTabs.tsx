// SPDX-License-Identifier: Apache-2.0

// 작업 기록의 탭 (캔버스 v198 Operations · OperationsChanges · OperationsResources · OperationsWeb, 모바일 UI-M1 ①): 내 작업 · 관리 변경 · 공유 자원 전체 · 웹 설정 변경
import { useState, type ReactNode } from 'react';
import { Link, Navigate, useLocation } from 'react-router-dom';
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
        { to: '/system/ops/changes', label: '관리 변경' },
        { to: '/system/ops/resources', label: phone ? '공유 자원' : '공유 자원 전체' },
        { to: '/system/ops/web', label: phone ? '웹 설정' : '웹 설정 변경' },
      ]}
    />
  );
}

/** 탭마다 머리 번호와 도움말이 다르다 (캔버스 v198) */
const TAB_HELP: Record<string, { ids: string; terms: string; body: ReactNode }> = {
  mine: { ids: 'UI-A0', terms: '작업 (operation) · 결과 불명 (응답 유실)', body: '내가 보낸 작업과 그 결과를 모아 봅니다. 응답이 끊겨 결과를 모르는 작업은 같은 작업으로 결과를 다시 묻거나 이어서 실행합니다.' },
  changes: {
    ids: 'UI-A1',
    terms: '관리 변경 (typed change) · 변경 묶음 · 기준 버전 (expected) · 확정 · 결과 불명 · 재개',
    body: (
      <>
        CLI의 관리 변경(<code>mydc manage apply</code>)으로 할 수 있는 동작을 파일 없이 화면에서 골라 만들고, 여러 개를 묶어 차례로 보냅니다. 전용 화면이 있는 동작은 그 화면으로 가는 길도 함께 보입니다. 변경 파일(JSON)을 불러오거나 내보낼 수도 있습니다.
      </>
    ),
  },
  resources: { ids: 'UI-A2', terms: '공유 자원 (managed resource) · 버전', body: '작업 공간의 공유 자원을 종류와 상관없이 한 목록으로 봅니다. 각 줄의 ‘보기’는 그 자원을 다루는 화면으로 갑니다.' },
  web: { ids: 'UI-A3', terms: '웹 설정 변경 기록 (web-audit)', body: '웹 앱에서 바꾼 설정(AI, MCP 연동, 행동 지침, 웹훅, 외부 도메인, 웹 앱 설정)의 기록을 봅니다.' },
};

/** 네 탭이 함께 쓰는 머리: 제목 · 도움말 · 탭 */
export function OpsHeader({ actions }: { actions?: ReactNode }) {
  const phone = usePhone();
  const path = useLocation().pathname;
  const key = path.endsWith('/changes') ? 'changes' : path.endsWith('/resources') ? 'resources' : path.endsWith('/web') ? 'web' : 'mine';
  const tab = { changes: '관리 변경', resources: '공유 자원', web: '웹 설정 변경', mine: '내 작업' }[key];
  useMobileTop({ title: '작업 기록', sub: tab }, [tab]);
  // 휴대폰은 도움말 없이 탭만 (UI-M1 ①), 새로 고침은 끌어 내리기로
  if (phone) return <OpsTabs />;
  const h = TAB_HELP[key];
  return (
    <>
      <PageHeader title="작업 기록" ids={h.ids} actions={actions} />
      <HelpBox terms={h.terms}>
        <b>이 화면은</b> {h.body}
      </HelpBox>
      <OpsTabs />
    </>
  );
}

/** 종류 · 이름 · 버전 · 내용 · 다루는 화면 */
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
  const [kind, setKind] = useState('');
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
  const kinds = [...new Set(rows.map((e) => kindOf(e)[0]))];
  const shown = kind ? rows.filter((e) => kindOf(e)[0] === kind) : rows;
  const viewOf = (e: DResourceEntry) => (e.network ? '/shared/networks' : e.route ? '/shared/ingress' : e.limit ? `/system/tenants/${encodeURIComponent(e.tenant)}` : undefined);
  return (
    <>
      <OpsHeader actions={<Refresh q={first} />} />
      <Card title={`공유 자원 전체 · 작업 공간 ${tenant}`} flush>
        <div className="row wrap" style={{ padding: '0 14px', gap: 12 }}>
          <select aria-label="종류" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">종류: 전체</option>
            {kinds.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
          <span className="small muted">위쪽 막대에서 고른 작업 공간의 공유 자원만 보입니다. 버전은 자원이 바뀔 때마다 오르는 번호입니다.</span>
        </div>
        <Load q={first} what="공유 자원을 불러오지 못했습니다">
          {() => (
            <DataTable
              rows={shown}
              rowKey={(e) => e.key}
              emptyTitle="공유 자원이 없습니다"
              columns={[
                { key: 'k', header: '종류', value: (e) => kindOf(e)[0], render: (e) => kindOf(e)[0], m: 'badge' },
                { key: 'n', header: '이름', value: (e) => kindOf(e)[1], render: (e) => <b title={kindOf(e)[3] || undefined}>{kindOf(e)[1]}</b>, m: 'title' },
                { key: 'v', header: '버전', value: (e) => kindOf(e)[2] ?? 0, render: (e) => <code>{kindOf(e)[2] ?? '—'}</code> },
                {
                  key: 'go',
                  header: '',
                  render: (e) => {
                    const to = viewOf(e);
                    return to ? (
                      <Link className="btn sm" to={to}>
                        보기
                      </Link>
                    ) : null;
                  },
                },
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
