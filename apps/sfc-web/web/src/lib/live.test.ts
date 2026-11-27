// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { GATHER_MS, liveTestHooks, resetLiveForTest, subscribeLive, type LiveRef } from './live';

const ref = (name: string, deleted = false): LiveRef => ({ kind: 'app', tenant: 't', name, deleted });

describe('live burst', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    resetLiveForTest();
    vi.useRealTimers();
  });

  it('gathers a burst into one delivery per window, one entry per record', () => {
    const got: LiveRef[][] = [];
    subscribeLive({ match: (r) => r.kind === 'app', onRefs: (r) => got.push(r), onResync: () => undefined });
    for (let i = 0; i < 100; i++) liveTestHooks.deliver([ref(`a${i % 3}`), { kind: 'op', name: 'x' }]);
    liveTestHooks.deliver([ref('a1', true)]);
    expect(got).toHaveLength(0);
    vi.advanceTimersByTime(GATHER_MS);
    expect(got).toHaveLength(1);
    expect(got[0].map((r) => `${r.name}${r.deleted ? '-' : ''}`)).toEqual(['a0', 'a1-', 'a2']);
    // 끊이지 않는 흐름도 창마다 한 번은 반영된다
    for (let t = 0; t < 3; t++) {
      liveTestHooks.deliver([ref('b')]);
      vi.advanceTimersByTime(GATHER_MS);
    }
    expect(got).toHaveLength(4);
  });

  it('turns a burst with a resync into one reread, and spreads many rereads out', () => {
    const counts = Array.from({ length: 10 }, () => ({ refs: 0, resync: 0 }));
    for (const c of counts) subscribeLive({ match: () => true, onRefs: () => c.refs++, onResync: () => c.resync++ });
    liveTestHooks.deliver([ref('a')]);
    liveTestHooks.resyncAll();
    liveTestHooks.deliver([ref('b')]);
    vi.advanceTimersByTime(GATHER_MS + 1);
    expect(counts.filter((c) => c.resync === 1)).toHaveLength(4);
    vi.advanceTimersByTime(1000);
    expect(counts.every((c) => c.resync === 1 && c.refs === 0)).toBe(true);
  });
});
