// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { changeLines } from './endpoints';
import { RECHECK_MS, recheckDelay } from '../auth/session';

describe('단독 컨테이너 계획 줄 차이 (데몬은 { yaml }만 받음)', () => {
  it('before는 -, after는 +, 문자열 아닌 값은 JSON', () => {
    expect(
      changeLines([
        { field: 'image', before: 'a:1', after: 'a:2' },
        { field: 'env', after: { A: '1' } },
        { field: 'user', before: 'app', after: null },
      ]),
    ).toEqual([
      { op: '-', text: 'image: a:1' },
      { op: '+', text: 'image: a:2' },
      { op: '+', text: 'env: {"A":"1"}' },
      { op: '-', text: 'user: app' },
    ]);
  });
});

describe('sfcd 끊김 다시 확인 간격', () => {
  it('2·4·8·16초 뒤 30초마다', () => {
    expect([0, 1, 2, 3, 4, 5, 50].map(recheckDelay)).toEqual([2000, 4000, 8000, 16000, 30000, 30000, 30000]);
    expect(Math.max(...RECHECK_MS)).toBe(30000);
  });
});
