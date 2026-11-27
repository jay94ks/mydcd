// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { bridgeEnds, bridgePortText, bridgesOf } from './Bridges';
import type { BridgeView } from '../api/types';

const b = (x: Partial<BridgeView>): BridgeView => ({ key: 'bridge/shop/x', state: 'open', kind: 'bridge', owner: 'shop', name: 'x', a: { tenant: 'shop', network: 'shop-net' }, b: { tenant: 'shop', network: 'shop-db' }, direction: 'both', protocol: 'all', ports: [], phase: 'open', approvals: [], generation: 1, revision: 1, ...x });

describe('가상 브릿지 (UI-5D)', () => {
  it('양 끝과 방향', () => {
    expect(bridgeEnds(b({}))).toBe('shop/shop-net ⇄ shop/shop-db');
    expect(bridgeEnds(b({ direction: 'a-to-b', b: { tenant: 'internal', network: 'mon-net' } }))).toBe('shop/shop-net → internal/mon-net');
    expect(bridgeEnds(b({ direction: 'b-to-a' }))).toBe('shop/shop-net ← shop/shop-db');
  });
  it('포트 문구', () => {
    expect(bridgePortText(b({}))).toBe('모든 포트');
    expect(bridgePortText(b({ protocol: 'tcp', ports: [{ first: 9090, last: 9100 }, { first: 443, last: 443 }] }))).toBe('tcp 9090-9100, 443');
    expect(bridgePortText(b({ protocol: 'udp', ports: [] }))).toBe('udp 모든 포트');
  });
  it('망 하나에 걸린 브릿지: 이 작업 공간의 그 이름만', () => {
    const list = [b({}), b({ name: 'y', a: { tenant: 'internal', network: 'shop-db' }, b: { tenant: 'shop', network: 'shop-net' } }), b({ name: 'z', a: { tenant: 'internal', network: 'shop-net' }, b: { tenant: 'lab', network: 'c' } })];
    expect(bridgesOf(list, 'shop', 'shop-net').map((x) => x.name)).toEqual(['x', 'y']);
    expect(bridgesOf(list, 'shop', 'shop-db').map((x) => x.name)).toEqual(['x']);
  });
});
