// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import type { DMember, DNodeSummary } from './dto';
import { fromSummary, mergeNodes } from './endpoints';

describe('늦은 서버 대기 중 (R18 waiting)', () => {
  const s: DNodeSummary = { node: 'n1', status: 'ready', ready: true, containers: 3, observedAt: 1, cpuPercent: 10, waiting: true };
  it('waiting이면 단계는 대기 중, 나머지는 저장된 값 그대로', () => {
    const v = fromSummary(s);
    expect(v.phase).toBe('waiting');
    expect(v.cpuPercent).toBe(10);
    expect(fromSummary({ ...s, waiting: undefined }).phase).toBe('ready');
  });
  it('가입 대기·제거 중·격리는 늦어도 그 단계 그대로', () => {
    expect(fromSummary({ ...s, status: 'removing' }).phase).toBe('removing');
    expect(fromSummary({ ...s, status: 'pending' }).phase).toBe('joining');
    expect(fromSummary({ ...s, status: 'isolated' }).phase).toBe('isolated');
  });
  it('가입 정보와 합쳐도 대기 중', () => {
    const m = { id: 'n1', phase: 'active', voter: true } as DMember;
    expect(mergeNodes([m], [s])[0].phase).toBe('waiting');
  });
});

describe('서버 오류 사유', () => {
  it('작업을 받지 않는 서버와 맞추기 실패를 가른다', () => {
    const s: DNodeSummary = { node: 'n2', status: 'degraded', ready: false, containers: 0, observedAt: 1 };
    const work = mergeNodes([{ id: 'n2', phase: 'active', voter: true, admitsWork: true } as DMember], [s])[0];
    expect(work.phase).toBe('problem');
    expect(work.phaseReason).toContain('reconciliation failed');
    const gw = mergeNodes([{ id: 'n2', phase: 'active', voter: false, admitsWork: false } as DMember], [s])[0];
    expect(gw.phaseReason).toContain('작업을 받지 않는');
    expect(mergeNodes([{ id: 'n2', phase: 'active', voter: true } as DMember], [{ ...s, status: 'ready', ready: true }])[0].phaseReason).toBeUndefined();
  });
});

describe('sfcd 오류 사유 코드', () => {
  const s: DNodeSummary = { node: 'n3', status: 'degraded', ready: false, containers: 0, observedAt: 1 };
  const m = { id: 'n3', phase: 'active', voter: true, admitsWork: true } as DMember;
  it('MODULE_PASS_FAILED는 실패 단계와 시작 시각', () => {
    const n = mergeNodes([m], [{ ...s, reason: 'MODULE_PASS_FAILED', failedSteps: ['system-network', 'event-log', 'new-step'], failingSince: 1700000000 }])[0];
    expect(n.phaseReason).toContain('시스템 망(system-network) · 사건 기록(event-log) · new-step 맞추기가 실패');
    expect(n.failingSince).toBe(new Date(1700000000 * 1000).toISOString());
  });
  it('HOST_READ_FAILED·UNKNOWN', () => {
    expect(mergeNodes([m], [{ ...s, reason: 'HOST_READ_FAILED' }])[0].phaseReason).toContain('CPU·메모리');
    expect(mergeNodes([m], [{ ...s, reason: 'UNKNOWN' }])[0].phaseReason).toContain('이전 버전');
  });
  it('작업 안 받는 서버는 ready면 오류 아님', () => {
    const n = mergeNodes([{ ...m, admitsWork: false }], [{ ...s, status: 'ready', admitsWork: false }])[0];
    expect(n.phase).toBe('ready');
    expect(n.admitsWork).toBe(false);
  });
});
