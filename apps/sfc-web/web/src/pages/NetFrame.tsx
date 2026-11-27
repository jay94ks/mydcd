// SPDX-License-Identifier: Apache-2.0

// 망 화면의 틀 (캔버스 v214 Networks · NetworkDns · NetworkRoutes): 제목 '공유 자원', 공유 자원 탭 줄, 그 아래 망 2단 탭,
// 탭마다 자기 설명(이 화면은)과 자기 내용. 가상 브릿지 탭(UI-5D)은 #704 계약.
import type { ReactNode } from 'react';
import { useTenantRole } from '../auth/session';
import { bridges, networks } from '../api/endpoints';
import type { Page, NetworkView } from '../api/types';
import { PageHeader } from '../components/ui';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { usePoll } from '../lib/usePoll';
import { NoTenant } from './Deploy';
import { useRoutes, type RoutesQ } from './Routes';
import { SHARED_TABS } from './Shared';
import { networksLive } from '../lib/liveTopics';

export const NET_NEED = '작업 공간 관리자 권한 필요';

const emptyNets = (): Page<NetworkView> => ({ items: [], next: '', revision: 0, asOf: new Date().toISOString() });

/** 탭 줄 숫자와 화면 내용이 같이 쓰는 두 목록 */
export function useNetLists() {
  const { tenant } = useTenantRole();
  const nq = usePoll((s) => (tenant ? networks(tenant, s) : Promise.resolve(emptyNets())), [tenant], 0, networksLive(tenant));
  const rq = useRoutes(tenant ?? '');
  const bq = usePoll((s) => (tenant ? bridges(tenant, s) : Promise.resolve({ items: [], revision: 0 })), [tenant]);
  return { tenant, nq, rq, bq };
}
export type BridgesQ = ReturnType<typeof useNetLists>['bq'];
export type NetsQ = ReturnType<typeof useNetLists>['nq'];

const count = (n?: number) => (n === undefined ? '' : ` (${n})`);

export function netTabs(nets?: number, routes?: number, brs?: number) {
  return [
    { to: '/shared/networks', label: `망${count(nets)}` },
    { to: '/shared/networks/dns', label: '도메인 이름' },
    { to: '/shared/networks/bridges', label: `가상 브릿지${count(brs)}` },
    { to: '/shared/networks/routes', label: `작업 공간 간 연결${count(routes)}` },
  ];
}

export function NetFrame({ ids, actions, help, q, nq, rq, bq, children }: { ids: string; actions?: ReactNode; help: ReactNode; q: Parameters<typeof Refresh>[0]['q']; nq: NetsQ; rq: RoutesQ; bq?: BridgesQ; children: ReactNode }) {
  const { tenant } = useTenantRole();
  return (
    <>
      <PageHeader
        title="공유 자원"
        ids={ids}
        actions={
          <>
            <Refresh q={q} poll={false} />
            {tenant && actions}
          </>
        }
      />
      <Tabs label="공유 자원 탭" items={SHARED_TABS} />
      <Tabs label="망 탭" sub items={netTabs(nq.data?.items.length, rq.data?.items.length, bq?.data?.items.length)} />
      {help}
      {!tenant ? <NoTenant /> : children}
    </>
  );
}
