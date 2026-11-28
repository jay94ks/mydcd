// SPDX-License-Identifier: Apache-2.0

import { ApiError } from '../api/client';
import { tenantOne } from '../api/endpoints';
import type * as V from '../api/types';
import type { LiveRef } from './live';
import type { LiveTopic } from './usePoll';

/**
 * 목록 하나를 바뀐 항목만으로 고친다. 지운 항목과 더는 볼 수 없는 항목(403·404)은 빼고,
 * 바뀐 항목은 그 자리에서, 새 항목은 key 순서 자리에 넣는다.
 */
export async function patchList<T>(list: T[], refs: LiveRef[], key: (x: T) => string, read: (r: LiveRef) => Promise<T>): Promise<T[]> {
  let out = list.slice();
  for (const r of refs) {
    let next: T | undefined;
    if (!r.deleted) {
      try {
        next = await read(r);
      } catch (e) {
        if (!(e instanceof ApiError) || (e.status !== 404 && e.status !== 403)) throw e;
      }
    }
    const at = out.findIndex((x) => key(x) === r.name);
    if (next === undefined) {
      if (at >= 0) out = out.filter((_, i) => i !== at);
    } else if (at >= 0) out[at] = next;
    else {
      const k = key(next);
      const pos = out.findIndex((x) => key(x) > k);
      out.splice(pos < 0 ? out.length : pos, 0, next);
    }
  }
  return out;
}

/** 작업 공간 목록 (GET /tenants) */
export const tenantsLive: LiveTopic<V.TenantAccess[]> = {
  match: (r) => r.kind === 'tenant',
  patch: (list, refs, signal) => patchList(list, refs, (t) => t.id, (r) => tenantOne(r.name, signal)),
};

// 웹 데몬 자체 기록(bbolt). 목록은 거르기·순서가 화면마다 달라 바뀌면 그 목록을 한 번 다시 읽는다.

/** 내 알림 (GET /notifications). 이름이 비어 있으면 여러 건이 한꺼번에 바뀐 것(모두 읽음) */
export const notificationsLive: LiveTopic<never> = { match: (r) => r.kind === 'notification' };
/** 내 작업 기록 (GET /ops) */
export const opsLive: LiveTopic<never> = { match: (r) => r.kind === 'op' };
/** 장애 대응 사건 목록 (GET /incidents) */
export const incidentsLive: LiveTopic<never> = { match: (r) => r.kind === 'incident' };
/** 사건 하나 (GET /incidents/{id}) */
export const incidentLive = (id: string | undefined): LiveTopic<never> => ({ match: (r) => r.kind === 'incident' && !!id && r.name === id });

// 서버 보고(sfcd가 받아 저장한 값이 바뀜)와 서버 기록. name은 서버 ID다.
// engine.*는 그 서버 엔진의 사건(컨테이너 시작·종료·OOM·압박·health, 엔진 재시작·사건 밀림)
const SERVER_KINDS = new Set(['node', 'node-observation', 'node-report', 'diagnostic', 'engine.container', 'engine.node']);

/** 서버 목록·요약 */
export const serversLive: LiveTopic<never> = { match: (r) => SERVER_KINDS.has(r.kind) };
/** 서버 하나의 상세·작업·디스크 */
export const serverLive = (id: string | undefined): LiveTopic<never> => ({ match: (r) => SERVER_KINDS.has(r.kind) && !!id && r.name === id });
/** 대시보드: 보이는 것이 거의 모든 것을 모아 만든 값이라 내 작업 기록·알림 말고는 다 다시 읽는다 */
export const dashboardLive: LiveTopic<never> = { match: (r) => r.kind !== 'op' && r.kind !== 'notification' };

// 작업 공간 자원. 앱은 앱 기록과 그 앱 작업의 서버 관측(상태가 바뀜)으로 다시 읽는다.
const appObs = (r: LiveRef, tenant: string, app?: string) =>
  (r.kind === 'node-observation' || r.kind === 'engine.container') && r.tenant === tenant && !!r.app && (app === undefined || r.app === app);

/** 작업 공간의 앱 목록 */
export const appsLive = (tenant: string | undefined): LiveTopic<never> => ({ match: (r) => !!tenant && ((r.kind === 'app' && r.tenant === tenant) || appObs(r, tenant)) });
/** 앱 하나(상세·작업·버전) */
export const appLive = (tenant: string | undefined, app: string | undefined): LiveTopic<never> => ({ match: (r) => !!tenant && !!app && ((r.kind === 'app' && r.tenant === tenant && r.name === app) || appObs(r, tenant, app)) });
/** 작업 공간의 데이터 저장소 */
export const volumesLive = (tenant: string | undefined): LiveTopic<never> => ({ match: (r) => !!tenant && r.kind === 'volume' && r.tenant === tenant });
/** 작업 공간의 망 (시스템 망 구성원 바뀜 포함) */
export const networksLive = (tenant: string | undefined): LiveTopic<never> => ({ match: (r) => !!tenant && r.kind === 'network' && (r.tenant === tenant || !r.tenant) });

/** 웹 데몬 자체 기록 종류로 고르기 (웹훅·연결·장애 대응 안내·AI 대화·MCP 서버·웹 설정) */
export const kindsLive = (...kinds: string[]): LiveTopic<never> => ({ match: (r) => kinds.includes(r.kind) });
/** 웹훅 하나의 배달 기록 */
export const deliveriesLive = (webhook: string | undefined): LiveTopic<never> => ({ match: (r) => r.kind === 'webhook-delivery' && !!webhook && r.name === webhook });

// 클러스터 기록(sfcd 책)에서 오는 종류. ingress 이름은 그 부분: block/<id>, host-policy, balance/…, drain/…,
// gateway/<서버>, cluster-app-route/<앱>, history. 앱 매핑은 앱 기록이 바뀌면 같이 바뀐다.

/** 작업 공간의 내장 Registry 목록·상세 (정리 작업 포함) */
export const registriesLive = (tenant: string | undefined): LiveTopic<never> => ({
  match: (r) => !!tenant && (r.kind === 'registry' || r.kind === 'registry-maintenance') && r.tenant === tenant,
});
const ingressRef = (r: LiveRef, tenant?: string) =>
  (r.kind === 'ingress' && (tenant === undefined || r.tenant === tenant || !r.tenant)) || (r.kind === 'app' && (tenant === undefined || r.tenant === tenant)) || r.kind === 'node';
/**
 * 공개 경로 화면(ingress 보기·차단·앱 경로). 요청 수·지연·서버별 적용 상태는 서버에서 잰 값이라
 * 주기를 남기고(measured), 설정이 바뀌면 바로 다시 읽는다.
 */
export const ingressLive = (tenant?: string): LiveTopic<never> => ({ match: (r) => ingressRef(r, tenant), measured: true });
/** 공개 변경 이력 (새 기록이 붙으면 history가 바뀐다) */
export const ingressHistoryLive: LiveTopic<never> = { match: (r) => r.kind === 'ingress' && r.name === 'history' };
/** 클러스터 앱(sfc-web) 공개 경로 */
export const clusterAppRoutesLive: LiveTopic<never> = { match: (r) => r.kind === 'ingress' && r.name.startsWith('cluster-app-route/') };
/** 망 하나의 관리 DNS 이름: DNS 설정과, 이름이 되는 그 작업 공간 앱. 서버마다 반영 상태는 잰 값이라 주기를 남긴다 */
export const networkDnsLive = (tenant: string | undefined, network: string | undefined): LiveTopic<never> => ({
  measured: true,
  match: (r) => !!tenant && r.tenant === tenant && ((r.kind === 'dns' && r.name === network) || r.kind === 'app' || (r.kind === 'network' && r.name === network)),
});
/** 인증서 저장소 (인증서·클러스터 도메인 목록·HTTP-01 응답 주소) */
export const certStoreLive: LiveTopic<never> = { match: (r) => r.kind === 'certificate' || r.kind === 'domain' || r.kind === 'acme-responder' };
/** 인증서 하나 */
export const certLive = (id: string | undefined): LiveTopic<never> => ({ match: (r) => (r.kind === 'certificate' && !!id && r.name === id) || r.kind === 'domain' });
/** 도메인 목록: 클러스터 도메인 목록(domain)과 웹이 가진 외부 DNS 연결(dns-domain), 연결된 인증서 */
export const domainListLive: LiveTopic<never> = { match: (r) => r.kind === 'domain' || r.kind === 'dns-domain' || r.kind === 'certificate' };
/** 도메인 하나: 그 행·관리 표시·변경 이력·서버 연결. 레코드 값은 DNS 업체가 가진 것이라 오지 않는다 */
export const domainLive = (domain: string | undefined): LiveTopic<never> => ({ match: (r) => !!domain && r.name === domain && (r.kind === 'dns-domain' || r.kind === 'domain') });
/** DNS 업체 연결 */
export const dnsProvidersLive: LiveTopic<never> = { match: (r) => r.kind === 'dns-provider' };
/** ACME 인증서(발급 정의·주문)와 계정. 발급 상태는 인증서 저장소 쪽도 본다 */
export const acmeLive: LiveTopic<never> = { match: (r) => r.kind === 'acme-cert' || r.kind === 'acme-account' || r.kind === 'certificate' };
/** ACME 인증서 하나 */
export const acmeCertLive = (name: string | undefined): LiveTopic<never> => ({ match: (r) => (r.kind === 'acme-cert' && !!name && r.name === name) || r.kind === 'certificate' });

// 잰 값이 섞인 조회: 관련 기록·보고가 바뀌면 바로 다시 읽고, 주기도 남긴다(measured).
const measured = (t: LiveTopic<never>): LiveTopic<never> => ({ match: t.match, measured: true });

/** 서버 Raft·로그 장부·압축 상태: 적용 번호 같은 값은 쓰기마다 움직여 주기를 남긴다 */
export const raftLive = measured(serversLive);
/** 서버 비우기 진행: 서버 기록, 옮겨지는 앱, 서버 보고 */
export const drainLive: LiveTopic<never> = { match: (r) => SERVER_KINDS.has(r.kind) || r.kind === 'app', measured: true };
/** 망 하나의 바뀜 적용 진행·터널 상태: 망 기록과 서버 기록. 서버별 적용·터널 상태는 잰 값이다 */
export const networkStateLive = (tenant: string | undefined): LiveTopic<never> => ({ match: (r) => r.kind === 'node' || networksLive(tenant).match(r), measured: true });
/** 데이터 저장소 하나의 상세(서버별 사용량은 잰 값) */
export const volumeDetailLive = (tenant: string | undefined) => measured(volumesLive(tenant));
/** 작업 공간 하나에 속한 모든 것 (자원 목록·퇴역 진행) */
export const tenantAllLive = (tenant: string | undefined): LiveTopic<never> => ({ match: (r) => !!tenant && r.tenant === tenant });
/** 작업 공간 퇴역 진행: 그 작업 공간의 기록이 줄어드는 것을 따라가고, 서버 쪽 정리는 잰 값이라 주기를 남긴다 */
export const tenantRetireLive = (tenant: string | undefined) => measured(tenantAllLive(tenant));
/** 내린 앱 보관 목록 (남겨 둔 데이터 저장소 포함) */
export const archivedLive = (tenant: string | undefined): LiveTopic<never> => ({ match: (r) => !!tenant && r.tenant === tenant && (r.kind === 'archived-app' || r.kind === 'volume') });
/** 휴지통: 웹이 지운 것과 내린 앱 */
export const trashLive: LiveTopic<never> = { match: (r) => r.kind === 'trash' || r.kind === 'archived-app' };
/**
 * 서버가 말이 없어진 것(연결 끊김·보고 오래됨)은 읽을 때 관측 나이로 계산해 알림이 오지 않는다.
 * 그런 값을 보이는 조회는 서버 보고에 맞춰 바로 다시 읽고 주기도 남긴다.
 */
export const serversMeasured = measured(serversLive);
export const serverMeasured = (id: string | undefined) => measured(serverLive(id));
export const dashboardMeasured = measured(dashboardLive);
export const appMeasured = (tenant: string | undefined, app: string | undefined) => measured(appLive(tenant, app));
