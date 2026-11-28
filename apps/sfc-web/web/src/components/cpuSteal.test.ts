// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { cpuStealText } from './ui';

describe('다른 VM이 가져간 CPU 몫 (#907)', () => {
  it('없거나 반올림해 0이면 숨기고, 있으면 정수 %', () => {
    expect(cpuStealText(undefined)).toBeUndefined();
    expect(cpuStealText(0)).toBeUndefined();
    expect(cpuStealText(0.4)).toBeUndefined();
    expect(cpuStealText(7.4)).toBe('다른 VM 사용 7%');
  });
});
