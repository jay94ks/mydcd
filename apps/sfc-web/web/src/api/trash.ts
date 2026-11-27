// SPDX-License-Identifier: Apache-2.0

// 지운 것 되살리기 (UI-A5, docs/reference/web-api/53-ops-trash.md). 웹이 지운 정의를 보관 기간 동안 남긴다.
// 비밀 값(서명 비밀·토큰·OAuth 로그인)은 남지 않는다. 되살릴 때 받은 새 서명 비밀은 화면에 한 번만 보이고 저장하지 않는다.
import { api } from './client';
import type { DOp } from './dto';

export type TrashKind = 'webhook' | 'mcp-server' | 'guide' | 'dns-record' | 'cluster-app-route' | 'app';
export interface TrashItem {
  id: string;
  kind: TrashKind | string;
  tenant?: string;
  name: string;
  deletedBy: string;
  deletedAt: string;
  expiresAt?: string;
  restore: 'here' | 'link';
  link?: { kind: string; tenant?: string; app?: string };
  /** sfcd 정의를 뺀 내 작업 ID */
  op?: string;
  lost?: ('secret' | 'token' | 'login' | string)[] | null;
  detail?: Record<string, unknown>;
}
export interface TrashList {
  retentionDays: number;
  items: TrashItem[] | null;
}
export interface TrashRef {
  id: string;
  expiresAt: string;
}
export interface RestoreReply {
  restored?: { kind: string; name: string; enabled?: boolean; version?: number };
  secret?: { set: boolean; value?: string };
  op?: DOp;
}

const enc = encodeURIComponent;
export const trash = (signal?: AbortSignal) => api.get<TrashList>('/trash', signal);
export const trashItem = (id: string, signal?: AbortSignal) => api.get<{ item: TrashItem }>(`/trash/${enc(id)}`, signal);
export const restorePath = (id: string) => `/trash/${enc(id)}/restore`;
export const restoreTrash = (id: string, b: { name?: string; replace?: boolean }) => api.post<RestoreReply>(restorePath(id), b);
export const purgeTrash = (id: string) => api.del<void>(`/trash/${enc(id)}`);
/** sfcd 정의는 opId를 붙여 변경으로 보낸다 */
export const restoreIsOp = (k: string) => k === 'dns-record' || k === 'cluster-app-route';

export const TRASH_KIND: Record<string, string> = {
  webhook: '웹훅',
  'mcp-server': 'MCP 서버 연결',
  guide: '장애 대응 지침',
  'dns-record': '망 도메인 이름',
  'cluster-app-route': '클러스터 앱 경로',
  app: '앱',
};
export const LOST_NAME: Record<string, string> = { secret: '서명 비밀', token: '토큰', login: 'OAuth 로그인' };

/** 남은 기간(일, 올림) */
export const daysLeft = (expiresAt?: string, now = Date.now()) => (expiresAt ? Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / 86400000)) : undefined);
