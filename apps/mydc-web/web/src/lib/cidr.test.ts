// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { cidrProblem, hostIn, parseCidr, suggestCidr } from './cidr';

describe('CIDR', () => {
  it('데몬과 같은 규칙으로 읽는다', () => {
    expect(parseCidr('10.40.0.0/24')).toBeTruthy();
    expect(parseCidr('10.40.0.1/24')).toBeUndefined();
    expect(parseCidr('10.40.0.0')).toBeUndefined();
    expect(cidrProblem('10.40.9.0/30', [])).toMatch('/29');
  });
  it('겹침과 추천', () => {
    const taken = [{ name: 'shop-net', cidr: '10.40.0.0/24' }, { name: 'shop-db', node: 'node-a', cidr: '10.40.1.0/26' }];
    expect(cidrProblem('10.40.1.0/25', taken)).toBe('shop-db(node-a)의 10.40.1.0/26와 겹칩니다');
    expect(cidrProblem('10.40.2.0/24', taken)).toBeUndefined();
    expect(suggestCidr(taken.map((t) => t.cidr))).toBe('10.40.2.0/24');
  });
  it('게이트웨이는 망 안의 호스트 주소', () => {
    const c = parseCidr('10.40.2.0/24')!;
    expect(hostIn(c, '10.40.2.1')).toBe(true);
    expect(hostIn(c, '10.40.2.0')).toBe(false);
    expect(hostIn(c, '10.40.3.1')).toBe(false);
  });
});
