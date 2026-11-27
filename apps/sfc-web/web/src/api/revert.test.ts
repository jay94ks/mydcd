// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { fieldName, showValue } from './revert';
import { daysLeft } from './trash';

describe('되돌리기 · 지운 것 표시', () => {
  it('칸 이름은 마지막 마디로 화면 이름을 찾는다', () => {
    expect(fieldName('Policy.TTL')).toBe('캐시 TTL 상한');
    expect(fieldName('Policy.Records')).toBe('직접 더한 이름');
    expect(fieldName('Something.Unknown')).toBe('Something.Unknown');
  });
  it('값을 한 줄로 보인다', () => {
    expect(showValue(null)).toBe('없음');
    expect(showValue(true)).toBe('켬');
    expect(showValue(['1.1.1.1:53', '8.8.8.8:53'])).toBe('1.1.1.1:53, 8.8.8.8:53');
    expect(showValue({ Name: 'www', Type: 'CNAME', Value: 'web.' })).toBe('www CNAME web.');
  });
  it('남은 기간은 일 단위로 올린다', () => {
    const now = Date.parse('2026-11-27T00:00:00Z');
    expect(daysLeft('2026-12-04T00:00:00Z', now)).toBe(7);
    expect(daysLeft('2026-11-27T01:00:00Z', now)).toBe(1);
    expect(daysLeft('2026-11-26T00:00:00Z', now)).toBe(0);
    expect(daysLeft(undefined, now)).toBeUndefined();
  });
});
