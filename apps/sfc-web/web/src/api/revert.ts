// SPDX-License-Identifier: Apache-2.0

// 변경 되돌리기 (UI-A4, docs/reference/web-api/52-ops-revert.md). 내 작업만 되돌린다.
// 되돌리기는 같은 대상에 보내는 새 변경이다: 지금 값에서 고른 칸만 바꾸기 전 값으로, 지금 revision을 expected로.
import { api } from './client';

export type RevertReason = 'unsettled' | 'not-applied' | 'irreversible' | 'unsupported' | 'no-record' | 'created' | 'target-gone' | 'nothing';
export interface RevertField {
  path: string;
  kind: 'value' | 'set';
  before: unknown;
  after: unknown;
  now: unknown;
  added?: unknown[] | null;
  removed?: unknown[] | null;
  changedSince: boolean;
}
export interface RevertPlan {
  revert: 'here' | 'link' | 'no';
  reason?: RevertReason;
  link?: { kind: 'app-revisions' | 'archived-apps' | string; tenant?: string; app?: string };
  action?: string;
  target?: string;
  expected?: number;
  fields?: RevertField[] | null;
}

const enc = encodeURIComponent;
export const revertPlan = (id: string, signal?: AbortSignal) => api.get<RevertPlan>(`/ops/${enc(id)}/revert`, signal);
export const revertPath = (id: string) => `/ops/${enc(id)}/revert`;

export const REVERT_REASON: Record<RevertReason, string> = {
  unsettled: '결과가 불명인 작업은 먼저 결과를 확인해야 되돌릴 수 있습니다.',
  'not-applied': '적용되지 않은 작업이라 바뀐 것이 없습니다.',
  irreversible: '이 변경은 되돌릴 수 없습니다. 데이터·볼륨·백업 지우기, 원장 교체, 키·세션 회수, 비밀값 폐기처럼 이미 되돌릴 수 없는 일을 한 작업입니다.',
  unsupported: '이 종류의 작업은 아직 이 화면에서 되돌리지 못합니다. 그 대상을 다루는 화면에서 바꾸세요.',
  'no-record': '보낼 때의 대상 기록이 없어 되돌릴 수 없습니다(이 기능 전에 보낸 작업).',
  created: '이 작업은 대상을 새로 만들었습니다. 되돌리려면 그 화면에서 지우세요.',
  'target-gone': '대상이 지워져 되돌릴 수 없습니다. 지운 것은 작업 기록 › 지운 것에서 되살립니다.',
  nothing: '이 작업이 바꾼 칸이 없습니다.',
};

/** payload 칸 이름 → 화면 이름 (마지막 마디로 찾는다) */
const FIELD_NAME: Record<string, string> = {
  Enabled: '켜기',
  Reverse: '역방향 이름',
  Zone: '영역 (zone)',
  ClientZone: '클라이언트 영역',
  TTL: '캐시 TTL 상한',
  NegativeTTL: '없는 이름 TTL',
  Transports: '전송',
  Upstreams: '외부 이름 확인 서버',
  MaxQueries: '동시 질의 상한',
  MaxCacheEntries: '캐시 항목 상한',
  MaxResponseBytes: '응답 크기 상한',
  MaxConnections: '연결 상한',
  RequestTimeoutMS: '요청 시간 제한 (ms)',
  Records: '직접 더한 이름',
  On: '켜짐',
  Capacity: '자원 한도',
  Networks: '망 수',
  MaxConsumers: '소비자 수',
  Role: '역할',
  Nodes: '서버',
  Operations: '동작 범위',
  KeyOnly: '키로만 로그인',
  disable_node_cli_operation: '서버 CLI 막기',
  MaxSessions: '세션 상한',
  IdleSeconds: '유휴 끊김 (초)',
  Shell: '셸',
  Sudo: 'sudo',
  Ingress: '외부 접속 경로',
};
export const fieldName = (path: string) => FIELD_NAME[path.split('.').pop() ?? path] ?? path;

/** 칸 값을 한 줄로 */
export function showValue(v: unknown): string {
  if (v === null || v === undefined) return '없음';
  if (typeof v === 'boolean') return v ? '켬' : '끔';
  if (Array.isArray(v)) return v.length ? v.map(showValue).join(', ') : '없음';
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    // DNS 레코드 줄
    if ('Name' in o && 'Type' in o) return `${String(o.Name)} ${String(o.Type)} ${String(o.Value ?? '')}`.trim();
    return JSON.stringify(v);
  }
  return String(v);
}
