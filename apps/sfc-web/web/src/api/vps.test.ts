// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { canResumeCapped, gbText, won, type VpsServer } from './vps';

const capped = (cap: number, month: string): VpsServer => ({ name: 'v', account: 'a', zone: 'KR1', image: 'i', flavor: 'f', capKRW: cap, voter: false, phase: 'capped', capStop: { at: 0, month, capKRW: 20000, soFarKRW: 20000, projectedKRW: 31400 } });

describe('vps', () => {
  it('resumes a capped server only in a new month or above the projection', () => {
    const now = new Date(2026, 10, 27);
    expect(canResumeCapped(capped(20000, '2026-11'), now)).toBe(false);
    expect(canResumeCapped(capped(31400, '2026-11'), now)).toBe(false);
    expect(canResumeCapped(capped(35000, '2026-11'), now)).toBe(true);
    expect(canResumeCapped(capped(20000, '2026-10'), now)).toBe(true);
  });
  it('formats money and traffic', () => {
    expect(won(19800)).toBe('₩19,800');
    expect(won(undefined)).toBe('—');
    expect(gbText(412)).toBe('412 GB');
    expect(gbText(1900)).toBe('1.9 TB');
  });
});
