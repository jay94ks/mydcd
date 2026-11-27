// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { storagePolicyDelta } from './ServerDetail';
import type { StorageRoot } from '../api/types';

const root = (x: Partial<StorageRoot>): StorageRoot => ({ node: 'n', name: 'r', path: '/srv', tenants: [], draining: false, revision: 7, generation: 1, ...x });

describe('storagePolicyDelta (#684)', () => {
  it('sends only added and removed workspaces', () => {
    expect(storagePolicyDelta(root({ tenants: ['a', 'b'], capacityBytes: 0 }), { tenants: ['b', 'c'], all: false, capacityBytes: 0 })).toEqual({ addTenants: ['c'], removeTenants: ['a'], expected: 7 });
  });
  it('switches to every workspace with allTenants alone', () => {
    expect(storagePolicyDelta(root({ tenants: ['a'] }), { tenants: ['a'], all: true, capacityBytes: 0 })).toEqual({ allTenants: true, expected: 7 });
  });
  it('switches back to a list through addTenants', () => {
    expect(storagePolicyDelta(root({ allTenants: true, capacityBytes: 0 }), { tenants: ['b', 'a'], all: false, capacityBytes: 0 })).toEqual({ allTenants: false, addTenants: ['a', 'b'], expected: 7 });
  });
  it('sends the capacity only when it changes', () => {
    expect(storagePolicyDelta(root({ allTenants: true, capacityBytes: 0 }), { tenants: [], all: true, capacityBytes: 5 })).toEqual({ capacityBytes: 5, expected: 7 });
    expect(storagePolicyDelta(root({ allTenants: true, capacityBytes: 5 }), { tenants: [], all: true, capacityBytes: 0 })).toEqual({ capacityBytes: 0, expected: 7 });
  });
  it('leaves an untouched, non-GiB-aligned limit alone on a workspace-only edit', () => {
    // CLI --capacity 500GB = 500e9 bytes, shown as 465.66 GiB in the dialog
    const r = root({ tenants: ['a'], capacityBytes: 500e9 });
    expect(storagePolicyDelta(r, { tenants: ['a', 'b'], all: false })).toEqual({ addTenants: ['b'], expected: 7 });
    expect(storagePolicyDelta(r, { tenants: ['a'], all: false, capacityBytes: 500e9 })).toEqual({ expected: 7 });
  });
});
