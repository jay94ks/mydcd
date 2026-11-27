// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { NodeView } from '../api/types';
import { startSteps } from './StartCard';

const node = (id: string, phase: NodeView['phase'], voter = true) => ({ id, phase, voter }) as NodeView;

describe('시작하기 단계', () => {
  it('빈 클러스터', () => {
    const s = startSteps({ nodes: [node('a', 'ready'), node('b', 'joining', false)], apps: [] }, {});
    expect(s.map((x) => x.done)).toEqual([true, false, false, false, false, false]);
    expect(s[0].title).toBe('서버 2대 · 투표 서버 1');
  });
  it('모두 끝남', () => {
    const s = startSteps({ nodes: [node('a', 'ready')], apps: [{} as never] }, { key: 'alice · laptop', tenants: 1, networks: 2, hosts: 1 });
    expect(s.every((x) => x.done)).toBe(true);
    expect(s[1].sub).toBe('alice · laptop');
  });
});
