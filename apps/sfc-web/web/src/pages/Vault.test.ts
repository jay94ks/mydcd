// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { aclDelta } from './Vault';

describe('aclDelta', () => {
  it('sends only added and removed names', () => {
    const cur = { users: ['alice', 'bob'], services: [], denyUsers: ['eve'], denyServices: [] };
    const d = aclDelta(cur, { users: ['bob', 'carol'], services: [], denyUsers: ['eve'], denyServices: ['shop/web'] });
    expect(d.changed).toBe(true);
    expect(d.add).toEqual({ users: ['carol'], services: [], denyUsers: [], denyServices: ['shop/web'] });
    expect(d.remove).toEqual({ users: ['alice'], services: [], denyUsers: [], denyServices: [] });
  });
  it('reports no change for the same lists', () => {
    const cur = { users: ['alice'], services: [], denyUsers: [], denyServices: [] };
    expect(aclDelta(cur, { ...cur }).changed).toBe(false);
  });
});
