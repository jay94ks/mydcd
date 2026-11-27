// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it } from 'vitest';
import { clearAllDrafts, loadDraft, saveDraft } from './drafts';

const mem = new Map<string, string>();
beforeEach(() => {
  mem.clear();
  (globalThis as any).localStorage = {
    getItem: (k: string) => mem.get(k) ?? null,
    setItem: (k: string, v: string) => void mem.set(k, v),
    removeItem: (k: string) => void mem.delete(k),
    key: (i: number) => [...mem.keys()][i] ?? null,
    get length() {
      return mem.size;
    },
  };
  // Object.keys(localStorage)를 흉내
  (globalThis as any).localStorage = new Proxy((globalThis as any).localStorage, { ownKeys: () => [...mem.keys()], getOwnPropertyDescriptor: () => ({ enumerable: true, configurable: true }) });
});

describe('초안', () => {
  it('다른 사용자에게는 보이지 않고, 로그아웃하면 지워진다', () => {
    saveDraft('alice', 'standalone', 'shop', { yaml: 'name: a' });
    expect(loadDraft<{ yaml: string }>('alice', 'standalone', 'shop')?.yaml).toBe('name: a');
    expect(loadDraft('bob', 'standalone', 'shop')).toBeUndefined();
    clearAllDrafts();
    expect(loadDraft('alice', 'standalone', 'shop')).toBeUndefined();
  });
});
