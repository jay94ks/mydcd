// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { NetworkView } from '../api/types';
import { dnsState, groupNames } from './NetworkDns';

const net = (members: NetworkView['members']): NetworkView => ({ key: 'k', name: 'n', kind: 'tun', cidr: '10.0.0.0/24', nodes: [], revision: 1, dns: { zone: 'z', enabled: true, revision: 4 }, members, toggles: [] }) as unknown as NetworkView;

describe('망 도메인 이름', () => {
  it('서버별 반영 상태로 센다', () => {
    const m = (node: string, ready: boolean | undefined, state = 'ready') => ({ node, cidr: '10.0.0.0/25', draining: false, resolver: '10.0.0.1', dns: { state, ready, resolvers: ['10.0.0.1:53'] } });
    expect(dnsState(net([m('a', true), m('b', true)])).text).toBe('반영됨');
    expect(dnsState(net([m('a', true), m('b', false, 'not-ready')])).text).toBe('반영 중 1/2');
    expect(dnsState(net([m('a', true), m('b', undefined, 'unreachable')])).text).toBe('반영 중 1/2 · 연결 안 됨 1');
  });
  it('이름별로 주소를 묶는다', () => {
    const g = groupNames({ managed: true, enabled: true, revision: 1, names: [
      { name: 'web.a.z.', app: 'a', service: 'web', task: 'w1', family: 'ipv4', address: '10.0.0.2' },
      { name: 'web.a.z.', app: 'a', service: 'web', task: 'w2', family: 'ipv4', address: '10.0.0.3' },
      { name: 'web.a.z.', app: 'a', service: 'web', family: 'ipv6', address: 'fd00::2' },
    ], records: [], servers: [] });
    expect(g).toHaveLength(2);
    expect(g[0]).toMatchObject({ name: 'web.a.z', addresses: ['10.0.0.2', '10.0.0.3'], tasks: 2 });
  });
});
