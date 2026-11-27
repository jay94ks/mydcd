// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { mergeNodes, parseDiff, putUserPayload, scopeDelta, toNotification, toSession, toTask, toUser, withAutomationKey } from './endpoints';
import { auditChange } from '../pages/Audit';
import { lineDiff } from '../lib/diff';

describe('계약 DTO → 화면 모델', () => {
  it('세션: private-key는 key로, rootRevision은 기본 0', () => {
    const s = toSession({ user: { id: 'u', username: 'a', revision: 1, systemAdmin: false }, tenants: [], expiresAt: 'x', method: 'private-key' });
    expect(s.method).toBe('key');
    expect(s.rootRevision).toBe(0);
  });

  it('서버: 가입 대기는 관측보다 가입 정보가 우선', () => {
    const nodes = mergeNodes(
      [{ id: 'n1', key: 'k', endpoint: 'e', revision: 1, phase: 'pending', voter: false, admitsWork: false }],
      [{ node: 'n1', status: 'ready', role: 'non-voter', cpuPercent: 3, memUsed: 1, memTotal: 2, diskUsed: 1, diskTotal: 2, containers: 0, observedAt: 1 }],
    );
    expect(nodes[0].phase).toBe('joining');
    expect(nodes[0].cpuPercent).toBe(3);
  });

  it('컨테이너: 상태 이름을 화면 말로 바꾸고 오래된 보고는 stale', () => {
    const t = toTask({ tenant: 't', app: 'a', service: 's', instance: '1', node: 'n', image: 'i', generation: 1, desired: 'running', observed: 'created', health: 'unhealthy', restarts: 0, observedAt: 1 });
    expect(t.observed).toBe('starting');
    expect(t.health).toBe('fail');
    expect(t.stale).toBe(true);
  });

  it('계획 diff 문자열에서 머리줄을 뺀다', () => {
    expect(parseDiff('--- a\n+++ b\n@@ -1 +1 @@\n a\n-b\n+c\n')).toEqual([
      { op: ' ', text: 'a' },
      { op: '-', text: 'b' },
      { op: '+', text: 'c' },
    ]);
  });

  it('사용자: 0으로 찬 공개키는 없는 것으로 본다', () => {
    const u = toUser({ id: 'u', username: 'a', revision: 1, enabled: true, systemAdmin: false, credentials: [{ id: 'pw', method: 'password', publicKey: '00'.repeat(32), enabled: true }] });
    expect(u.credentials[0].publicKey).toBeUndefined();
  });

  it('put-user payload는 계정 자체의 칸만 보낸다', () => {
    const p = putUserPayload({ id: 'u', username: 'a', enabled: true, systemAdmin: false }, { SystemAdmin: true });
    expect(p).toEqual({ ID: 'u', Username: 'a', Enabled: true, SystemAdmin: true });
  });

  it('동작 범위는 변경분으로 보낸다', () => {
    const cur = { user: 'u', actions: ['deploy', 'observe'], keyOnly: false, revision: 7 };
    expect(scopeDelta(cur, ['observe', 'restart-task'], false)).toEqual({ expected: 7, add: ['restart-task'], remove: ['deploy'] });
    expect(scopeDelta(cur, [], true)).toEqual({ expected: 7, unlimited: true, keyOnly: true });
    expect(scopeDelta(cur, ['deploy', 'observe'], false)).toBeUndefined();
    expect(scopeDelta({ ...cur, actions: [] }, ['deploy'], false)).toEqual({ expected: 7, add: ['deploy'] });
  });

  it('자동 작업 키는 add-credential로 더한다', () => {
    const u = { id: 'u', username: 'a', revision: 3, enabled: true, systemAdmin: false, credentials: [{ id: 'web-auto', method: 'private-key', publicKey: '02'.repeat(32), enabled: true }] };
    expect(withAutomationKey(u, '01'.repeat(32))).toEqual({ id: 'web-auto-2', payload: { User: 'u', Credential: { ID: 'web-auto-2', Method: 'private-key', PublicKey: new Array(32).fill(1) } } });
    expect(withAutomationKey(u, '02'.repeat(32))).toBeUndefined();
  });
});

describe('알림 · 설정 변경 기록', () => {
  it('알림: readAt이 없거나 0시각이면 안 읽음, action은 할 일', () => {
    const base = { id: 'n', kind: 'op-unknown', severity: 'warning', title: 't', action: true, createdAt: '2026-11-21T00:00:00Z' };
    expect(toNotification(base).read).toBe(false);
    expect(toNotification({ ...base, readAt: '0001-01-01T00:00:00Z' }).read).toBe(false);
    expect(toNotification({ ...base, readAt: '2026-11-21T01:00:00Z' }).read).toBe(true);
    expect(toNotification(base).todo).toBe(true);
    expect(toNotification({ ...base, severity: 'critical' }).severity).toBe('info');
  });

  it('기록: 바뀐 키만 전 → 후', () => {
    expect(auditChange({ a: 1, b: 2 }, { a: 1, b: 3 })).toEqual(['b: 2 → 3']);
    expect(auditChange(undefined, undefined)).toEqual([]);
    expect(auditChange(undefined, { bytes: 5 })).toEqual(['없음 → {"bytes":5}']);
  });
});

describe('줄 diff', () => {
  it('바뀐 줄만 +/-', () => {
    expect(lineDiff('a\nb\n', 'a\nc\n').map((l) => l.op + l.text)).toEqual([' a', '-b', '+c']);
  });
});
