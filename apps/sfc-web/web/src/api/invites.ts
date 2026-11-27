// SPDX-License-Identifier: Apache-2.0

// 초대 링크 (UI-23A, docs/reference/web-api/51-invite-links.md). 시스템 관리자가 한 번 쓰는 링크를 만들고,
// 받은 사람이 자기 브라우저에서 키를 만들어 등록한다. 링크 코드는 # 뒤에 있어 서버 기록에 남지 않고,
// 화면은 코드를 상태에만 잠깐 두며 저장하지 않는다. 링크는 만든 응답에서 한 번만 받는다.
import { api } from './client';
import type { DOp } from './dto';

export type InviteExpiry = '1h' | '24h' | '7d';
export const INVITE_EXPIRY: [InviteExpiry, string][] = [
  ['1h', '1시간'],
  ['24h', '24시간'],
  ['7d', '7일'],
];
const enc = encodeURIComponent;

/** 관리자: 초대 만들기. user는 사용자 이름. link·expiresAt은 이번 요청이 applied일 때만 온다(같은 opId로 다시 보내면 op만).
 * 켜진 초대가 이미 있으면 op가 failed다(먼저 revoke) */
export const createInvite = (user: string, b: { opId: string; expires: InviteExpiry }) => api.post<{ op: DOp; link?: string; expiresAt?: string }>(`/users/${enc(user)}/invites`, b);
export const revokeInvitePath = (user: string) => `/users/${enc(user)}/invites/revoke`;

/** 받는 사람: 초대 열기(코드가 이때 소비된다). 10분 안에 finish */
export interface InviteTicket {
  ticket: string;
  userId: string;
  username: string;
  accountRevision: number;
  clusterId: string;
  expiresAt: string;
}
export const openInvite = (b: { username: string; code: string }) => api.post<InviteTicket>('/login/invite/open', b);
export const finishInvite = (b: { ticket: string; credential: { id: string; publicKey: string }; label?: string; challenge: string; proof: string }) =>
  api.post<{ credential: string; username: string }>('/login/invite/finish', b);

/** 초대 자격 증명 ID: invite-<만료 Unix 초>-<8hex> */
export const isInviteCredential = (id: string) => id.startsWith('invite-');
export function inviteExpiresAt(id: string): Date | undefined {
  const m = /^invite-(\d+)-/.exec(id);
  return m ? new Date(Number(m[1]) * 1000) : undefined;
}

/** 링크에서 사용자 이름과 코드를 꺼낸다(/login/invite?u=…#code) */
export function parseInviteLink(search: string, hash: string): { username: string; code: string } {
  return { username: new URLSearchParams(search).get('u') ?? '', code: decodeURIComponent(hash.replace(/^#/, '')) };
}

export const INVITE_ERROR: Record<string, string> = {
  'invite-invalid': '이 초대 링크는 쓸 수 없습니다. 이미 썼거나 만료됐거나 취소된 초대입니다. 초대한 사람에게 새 링크를 요청하세요.',
  'ticket-expired': '키 등록을 10분 안에 끝내지 못했습니다. 이 링크는 이미 쓴 것으로 처리돼, 초대한 사람에게 새 링크를 요청해야 합니다.',
};

/** '23시간 남음' · '12분 남음' · '3일 남음' · '만료' */
export function inviteLeft(expiresAt: string | undefined, now = Date.now()): string {
  if (!expiresAt) return '';
  const s = Math.floor((Date.parse(expiresAt) - now) / 1000);
  if (s <= 0) return '만료';
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))}분 남음`;
  if (s < 86400 * 2) return `${Math.floor(s / 3600)}시간 남음`;
  return `${Math.floor(s / 86400)}일 남음`;
}
/** 상대 경로로 온 링크는 지금 주소를 붙여 보인다 */
export const fullLink = (link: string, origin = window.location.origin) => new URL(link, origin).href;
