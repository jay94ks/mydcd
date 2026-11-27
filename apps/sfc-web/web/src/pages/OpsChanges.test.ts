// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { OpView } from '../api/types';
import { groupRequests, requestState } from './OpsChanges';

const op = (id: string, batch: string, index: number, state: OpView['state'], at = '2026-11-26T10:00:00Z'): OpView => ({ id, requestId: `req-${id}`, batch, index, action: 'set-node-quota', target: 'node-b', state, submittedAt: at, updatedAt: at });

describe('관리 변경 › 보낸 요청', () => {
  it('batch로 묶고(requestId는 작업마다 다름) 보낸 순서로 놓는다', () => {
    const r = groupRequests([op('b', 'r1', 1, 'unknown'), op('a', 'r1', 0, 'applied'), op('c', 'r2', 0, 'applied', '2026-11-26T11:00:00Z')]);
    expect(r.map((x) => x.id)).toEqual(['r2', 'r1']);
    expect(r[1].ops.map((o) => o.id)).toEqual(['a', 'b']);
    // batch 없는 작업은 하나가 요청 하나
    expect(groupRequests([op('x', '', 0, 'applied'), op('y', '', 0, 'applied')]).map((g) => g.id).sort()).toEqual(['x', 'y']);
  });
  it('먼저 나온 거부·불명을 순번과 함께 보인다', () => {
    const [r] = groupRequests([op('a', 'r1', 0, 'applied'), op('b', 'r1', 1, 'applied'), op('c', 'r1', 2, 'unknown')]);
    expect(requestState(r)).toMatchObject({ key: 'unknown', label: '불명 · 3번째' });
    const [x] = groupRequests([op('a', 'r9', 0, 'rejected')]);
    expect(requestState(x)).toMatchObject({ key: 'rejected', label: '거부' });
  });
});
