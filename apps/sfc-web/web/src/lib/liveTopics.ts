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
const SERVER_KINDS = new Set(['node', 'node-observation', 'node-report', 'diagnostic']);

/** 서버 목록·요약 */
export const serversLive: LiveTopic<never> = { match: (r) => SERVER_KINDS.has(r.kind) };
/** 서버 하나의 상세·작업·디스크 */
export const serverLive = (id: string | undefined): LiveTopic<never> => ({ match: (r) => SERVER_KINDS.has(r.kind) && !!id && r.name === id });
/** 대시보드: 보이는 것이 거의 모든 것을 모아 만든 값이라 내 작업 기록·알림 말고는 다 다시 읽는다 */
export const dashboardLive: LiveTopic<never> = { match: (r) => r.kind !== 'op' && r.kind !== 'notification' };

// 작업 공간 자원. 앱은 앱 기록과 그 앱 작업의 서버 관측(상태가 바뀜)으로 다시 읽는다.
const appObs = (r: LiveRef, tenant: string, app?: string) => r.kind === 'node-observation' && r.tenant === tenant && !!r.app && (app === undefined || r.app === app);

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
