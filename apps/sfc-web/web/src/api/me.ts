// SPDX-License-Identifier: Apache-2.0

// 내 계정 › 열린 세션 · 최근 로그인 (docs/reference/web-api/48-own-logins.md, 49-own-sessions.md).
// 기록은 각 서버(sfcd)가 남기고 답하는 서버가 합친다. 답하지 않은 서버는 missing.
import { api, q } from './client';

export interface OwnLogin {
  at: string;
  /** 묶인 실패의 마지막 시도 */
  lastAt?: string;
  count: number;
  ok: boolean;
  reason?: 'denied' | 'throttled' | string;
  method: 'password' | 'token' | 'private-key' | string;
  /** 쓴 자격 증명 ID */
  credential?: string;
  session?: string;
  expiresAt?: string;
  /** 브라우저 user agent (참고용) */
  client?: string;
  address: string;
  source?: string;
  node: string;
}
export interface OwnLogins {
  items: OwnLogin[];
  next?: string;
  missing: string[];
  budgetLeft?: number;
  budgetMax?: number;
}
export interface OwnSession {
  id: string;
  current?: boolean;
  method: string;
  credential?: string;
  at: string;
  expiresAt: string;
  client?: string;
  address: string;
  source?: string;
  node: string;
}

export const ownLogins = (after?: string, signal?: AbortSignal) =>
  api.get<OwnLogins>(`/me/logins${q({ after })}`, signal).then((r) => ({ ...r, items: r.items ?? [], missing: r.missing ?? [] }));
export const ownSessions = (signal?: AbortSignal) => api.get<{ items: OwnSession[] | null; missing?: string[] | null }>('/me/sessions', signal).then((r) => ({ items: r.items ?? [], missing: r.missing ?? [] }));
export const sessionPath = (id: string) => `/me/sessions/${encodeURIComponent(id)}`;

export const LOGIN_METHOD: Record<string, string> = { password: '비밀번호', token: 'API 토큰', 'private-key': '개인키', key: '개인키' };

/** user agent → 'Chrome · Windows' · 'sfcli CLI'. 모르면 그대로 짧게 */
export function clientText(ua?: string): string {
  if (!ua) return 'sfcli CLI';
  if (/^sfc\b/i.test(ua)) return 'sfcli CLI';
  const b = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl\//i.test(ua) ? 'curl' : '';
  const o = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  if (!b) return ua.length > 32 ? `${ua.slice(0, 32)}…` : ua;
  return o ? `${b} · ${o}` : b;
}
