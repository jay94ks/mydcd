// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { buildBlocked, buildText } from './endpoints';

describe('buildBlocked (#693)', () => {
  it('blocks only a server that reports it cannot build', () => {
    expect(buildBlocked({ build: { enabled: true } })).toBeUndefined();
    expect(buildBlocked({ build: { enabled: false, reason: 'ENGINE_BUILD_OFF' } })).toContain('엔진');
    expect(buildBlocked({ build: { enabled: false, reason: 'WORKLOAD_OFF' } })).toContain('작업 모듈');
  });
  it('does not block when unknown or not reported', () => {
    expect(buildBlocked({ build: { enabled: false, reason: 'UNKNOWN' } })).toBeUndefined();
    expect(buildBlocked({})).toBeUndefined();
    expect(buildBlocked(undefined)).toBeUndefined();
    expect(buildText({ build: { enabled: false, reason: 'UNKNOWN' } })).toContain('모름');
  });
});
