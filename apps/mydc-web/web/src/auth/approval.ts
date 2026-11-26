// SPDX-License-Identifier: Apache-2.0

// 개인키 로그인의 세션 승인(R02). 서명 전에 승인 바이트가 맞는지 본다.
import { decodeBase64 } from './keystore';

const APPROVAL_DOMAIN = 'mydc-user-session-approval-1\0';
const hexOf = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
/** JSON 값이 hex 문자열과 같은 바이트인지(hex 문자열·base64 문자열·숫자 배열 모두 받는다). 모르는 모양이면 undefined */
function sameBytes(v: unknown, hex: string): boolean | undefined {
  const want = hex.toLowerCase();
  if (Array.isArray(v)) return v.every((n) => typeof n === 'number') ? hexOf(Uint8Array.from(v as number[])) === want : undefined;
  if (typeof v !== 'string') return undefined;
  if (v.toLowerCase() === want) return true;
  try {
    return hexOf(decodeBase64(v)) === want;
  } catch {
    return false;
  }
}
/** 세션 승인 바이트 검사: 도메인이 맞고, 들어 있는 키·세션이 내 키·응답의 sessionDigest와 같아야 서명한다 */
export function checkApproval(bytes: Uint8Array, publicKey: string, sessionDigest: string) {
  const domain = new TextEncoder().encode(APPROVAL_DOMAIN);
  if (bytes.length <= domain.length || domain.some((b, i) => bytes[i] !== b)) throw new Error('서버가 세션 승인이 아닌 바이트에 서명을 요청했습니다. 서명하지 않았습니다.');
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(new TextDecoder().decode(bytes.slice(domain.length)));
  } catch {
    throw new Error('세션 승인 내용을 읽지 못했습니다. 서명하지 않았습니다.');
  }
  const field = (name: string) => Object.entries(body).find(([k]) => k.toLowerCase() === name)?.[1];
  // 두 필드가 모두 있고 같을 때만 서명한다(없거나 모르는 모양이면 거절)
  if (sameBytes(field('publickey'), publicKey) !== true) throw new Error('서버가 다른 키의 세션 승인을 보냈습니다. 서명하지 않았습니다.');
  if (sameBytes(field('session'), sessionDigest) !== true) throw new Error('세션 승인이 이 로그인의 세션과 다릅니다. 서명하지 않았습니다.');
}
