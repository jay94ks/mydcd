// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { healthReasonText, toApp } from './endpoints';

describe('앱 상태 사유 한 줄', () => {
  it('코드별 쉬운 말과 서버', () => {
    expect(healthReasonText({ code: 'TASK_EXITED', name: 'worker', node: 'node-b', exit: 1 })).toBe('worker 종료 코드 1 · node-b');
    expect(healthReasonText({ code: 'TASK_FAILED', name: 'api', failure: 'IMAGE_NOT_FOUND' })).toBe('api 시작 실패 · 이미지 없음');
    expect(healthReasonText({ code: 'APP_CHECK_FAILED' })).toBe('앱 상태 검사 실패');
    expect(healthReasonText({ code: 'NEW_CODE', name: 'web' })).toBe('web');
    expect(healthReasonText(undefined)).toBeUndefined();
  });
  it('건강하지 않을 때만 붙는다', () => {
    const base = { tenant: 't', app: 'a', deployment: 'main', revision: 1, operation: { id: 'x', status: 'succeeded', completedAt: 1, submitter: 'u', failed: false, epoch: 1 }, claims: 0 };
    expect(toApp({ ...base, health: 'degraded', healthReason: { code: 'NOT_RUNNING', name: 'db' } }).reason).toBe('db 실행 안 됨');
    expect(toApp({ ...base, health: 'healthy', healthReason: { code: 'NOT_RUNNING', name: 'db' } }).reason).toBeUndefined();
  });
});
