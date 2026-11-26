// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { eulReul, eunNeun, iGa } from './josa';

describe('eulReul', () => {
  it('picks by the final sound', () => {
    expect(eulReul('shop-net')).toBe('을');
    expect(eulReul('uploads')).toBe('를');
    expect(eulReul('mysql-data')).toBe('를');
    expect(eulReul('node-1')).toBe('을');
    expect(eulReul('저장소')).toBe('를');
    expect(eulReul('망')).toBe('을');
    expect(eulReul('stable')).toBe('을');
    expect(eulReul('latest')).toBe('을');
    expect(eunNeun('stable')).toBe('은');
    expect(eunNeun('v2.0')).toBe('은');
    expect(eunNeun('node-c')).toBe('는');
    expect(eulReul('node-b')).toBe('를');
    expect(eulReul('zone-m')).toBe('을');
  });
});

describe('iGa', () => {
  it('받침으로 고른다', () => {
    expect(iGa('php-shop · web')).toBe('이');
    expect(iGa('worker')).toBe('가');
    expect(iGa('보관된 앱')).toBe('이');
  });
});
