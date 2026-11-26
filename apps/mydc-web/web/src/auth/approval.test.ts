// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { checkApproval } from './approval';

const key = 'ab'.repeat(32);
const digest = 'cd'.repeat(32);
const enc = (s: string) => new TextEncoder().encode(s);
const b64 = (h: string) => btoa(String.fromCharCode(...h.match(/../g)!.map((x) => parseInt(x, 16))));

describe('checkApproval', () => {
  it('맞는 승인은 통과한다(hex·base64)', () => {
    expect(() => checkApproval(enc('mydc-user-session-approval-1\0' + JSON.stringify({ Schema: 1, PublicKey: key, Session: digest })), key, digest)).not.toThrow();
    expect(() => checkApproval(enc('mydc-user-session-approval-1\0' + JSON.stringify({ Schema: 1, PublicKey: b64(key), Session: b64(digest) })), key, digest)).not.toThrow();
  });
  it('다른 도메인은 서명하지 않는다', () => {
    expect(() => checkApproval(enc('mydc-user-key-proof-1\0{}'), key, digest)).toThrow(/세션 승인이 아닌/);
  });
  it('Go [32]byte처럼 숫자 배열이어도 맞으면 통과한다', () => {
    const arr = (h: string) => h.match(/../g)!.map((x) => parseInt(x, 16));
    expect(() => checkApproval(enc('mydc-user-session-approval-1\0' + JSON.stringify({ Schema: 1, PublicKey: arr(key), Session: arr(digest) })), key, digest)).not.toThrow();
  });
  it('키나 세션 필드가 없으면 서명하지 않는다', () => {
    expect(() => checkApproval(enc('mydc-user-session-approval-1\0' + JSON.stringify({ Session: digest })), key, digest)).toThrow(/다른 키/);
    expect(() => checkApproval(enc('mydc-user-session-approval-1\0' + JSON.stringify({ PublicKey: key })), key, digest)).toThrow(/세션과 다릅니다/);
  });
  it('다른 키·다른 세션은 서명하지 않는다', () => {
    expect(() => checkApproval(enc('mydc-user-session-approval-1\0' + JSON.stringify({ PublicKey: 'ef'.repeat(32), Session: digest })), key, digest)).toThrow(/다른 키/);
    expect(() => checkApproval(enc('mydc-user-session-approval-1\0' + JSON.stringify({ PublicKey: key, Session: 'ef'.repeat(32) })), key, digest)).toThrow(/세션과 다릅니다/);
  });
});
