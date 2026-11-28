// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import type { DDiskBundle } from '../api/dto';
import { bundleNameError, bundleState, fuseProblems } from './DiskBundles';

describe('bundleNameError', () => {
  it('sfcd 이름 규칙을 따른다', () => {
    expect(bundleNameError('pool2')).toBeUndefined();
    expect(bundleNameError('')).toBeDefined();
    expect(bundleNameError('Pool')).toBeDefined();
    expect(bundleNameError('a/b')).toBeDefined();
    expect(bundleNameError('a'.repeat(33))).toBeDefined();
  });
});

describe('bundleState', () => {
  const b = (state: DDiskBundle['state'], syncPercent?: number) => ({ name: 'p', backend: 'lvm', mode: 'mirror', size: 1, state, syncPercent, members: [] }) as DDiskBundle;
  it('상태별 배지', () => {
    expect(bundleState(b('syncing', 40), true)).toEqual(['pr', '재동기화 중 40%']);
    expect(bundleState(b('degraded'), true)[0]).toBe('er');
    expect(bundleState(b('missing'), false)[0]).toBe('er');
    expect(bundleState(b('ok'), true)).toEqual(['ok', '마운트됨']);
    expect(bundleState(b('ok'), false)[0]).toBe('wa');
  });
});

describe('fuseProblems', () => {
  const G = 2 ** 30;
  const pk = (part: string, disk: string, gib: number, copy: number, avail = 500 * G) => ({ disk, part, bytes: gib * G, copy, available: avail, total: 1000 * G });
  it('이어 붙이기는 합, 미러는 사본 합 중 작은 쪽', () => {
    expect(fuseProblems([pk('sdb1', 'sdb', 100, 1), pk('sdc1', 'sdc', 50, 1)], 'linear', 'grow').size).toBe(150 * G);
    const m = fuseProblems([pk('sdb1', 'sdb', 100, 1), pk('sdc1', 'sdc', 50, 2), pk('sdd1', 'sdd', 80, 2)], 'mirror', 'grow');
    expect(m.all).toBeUndefined();
    expect(m.size).toBe(100 * G);
  });
  it('64MiB 미만, reserve 여유 초과, 파티션 초과', () => {
    const r = fuseProblems([{ disk: 'sdb', part: 'sdb1', bytes: 1024, copy: 1 }, pk('sdc1', 'sdc', 600, 1), pk('sdd1', 'sdd', 1200, 1)], 'linear', 'reserve');
    expect(Object.keys(r.row).sort()).toEqual(['sdb1', 'sdc1', 'sdd1']);
    expect(fuseProblems([pk('sdc1', 'sdc', 600, 1)], 'linear', 'grow').row.sdc1).toBeUndefined();
  });
  it('미러 사본 번호·같은 디스크', () => {
    expect(fuseProblems([pk('sdb1', 'sdb', 10, 1), pk('sdc1', 'sdc', 10, 1)], 'mirror', 'grow').all).toBeDefined();
    expect(fuseProblems([pk('sdb1', 'sdb', 10, 1), pk('sdc1', 'sdc', 10, 3)], 'mirror', 'grow').all).toBeDefined();
    expect(fuseProblems([pk('sdb1', 'sdb', 10, 1), pk('sdb2', 'sdb', 10, 2)], 'mirror', 'grow').all).toBeDefined();
    expect(fuseProblems([pk('sdb1', 'sdb', 10, 1), pk('sdb2', 'sdb', 10, 1), pk('sdc1', 'sdc', 10, 2)], 'mirror', 'grow').all).toBeUndefined();
  });
});
