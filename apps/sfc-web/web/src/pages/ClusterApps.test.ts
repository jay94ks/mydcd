// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { DClusterApp } from '../api/dto';
import { groupClusterApps } from './ClusterApps';
import { portRank, refusedBy } from '../components/clusterApps';

const app = (state: string, more: Partial<DClusterApp> = {}): DClusterApp => ({ name: 'web', image: 'sfc/web', state, restarts: 0, control: 'node-config', actions: [], ...more });

describe('서버 › 클러스터 앱', () => {
  it('앱 이름으로 모으고, 도는 서버의 행을 대표로 쓴다', () => {
    const r = groupClusterApps([
      { id: 'node-c', clusterApps: [app('image-not-found')] },
      { id: 'node-a', clusterApps: [app('running', { address: '10.254.0.11' })] },
      { id: 'node-b' },
    ]);
    expect(r).toHaveLength(1);
    expect(r[0].running).toBe('node-a');
    expect(r[0].main.address).toBe('10.254.0.11');
    expect(r[0].enabled.map((x) => `${x.node}:${x.state}`)).toEqual(['node-a:running', 'node-c:image-not-found']);
  });
  it('도는 서버가 없으면 켠 서버 중 첫 행을 보이고 도는 서버는 비운다', () => {
    const [r] = groupClusterApps([{ id: 'node-b', stale: true, clusterApps: [app('exited')] }]);
    expect(r.running).toBeUndefined();
    expect(r.main.node).toBe('node-b');
    expect(r.main.stale).toBe(true);
  });
  it('거부됨은 도는 서버로 치지 않고, 이미 돌리는 서버를 알린다', () => {
    const [r] = groupClusterApps([
      { id: 'node-a', clusterApps: [app('running')] },
      { id: 'node-c', clusterApps: [app('refused', { reason: 'already-running', runningOn: 'node-a' })] },
    ]);
    expect(r.running).toBe('node-a');
    expect(refusedBy(r.enabled[1])).toBe('node-a');
    expect(refusedBy(r.enabled[0])).toBeUndefined();
  });
  it('포트는 web · direct · acme 순, 모르는 이름은 뒤에', () => {
    const names = ['acme', 'metrics', 'direct', 'web'].sort((a, b) => portRank(a) - portRank(b));
    expect(names).toEqual(['web', 'direct', 'acme', 'metrics']);
  });
});
