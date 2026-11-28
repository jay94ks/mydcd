// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { applySummary, applyWay, interruptionText } from './planChanges';

describe('배포 미리보기 적용 방식 (Z9)', () => {
  it('교체는 interruption이 있으면 끊김 있음, 없으면 끊김 없는 교체', () => {
    expect(applyWay({ action: 'Replace', key: 'task/web/1', interruption: 'VOLUME_WRITER' })).toBe('interrupt');
    expect(applyWay({ action: 'Replace', key: 'task/web/1' })).toBe('seamless');
    expect(applyWay({ action: 'RuntimeUpdate', key: 'ingress/web' })).toBe('inplace');
    expect(applyWay({ action: 'MoveRequired', key: 'volume/db' })).toBe('move');
    expect(applyWay({ action: 'Frobnicate', key: 'x' })).toBe('other');
  });
  it('끊김 까닭은 코드로 문장을 만들고, 모르는 코드는 그대로', () => {
    expect(interruptionText('HOST_PORT')).toContain('서버 포트');
    expect(interruptionText('NEW_CODE')).toBe('NEW_CODE');
  });
  it('요약은 그대로인 항목을 빼고 정한 순서로 센다', () => {
    const s = applySummary([
      { action: 'Keep', key: 'a' },
      { action: 'Replace', key: 'b', interruption: 'SINGLE_INSTANCE' },
      { action: 'RuntimeUpdate', key: 'c' },
      { action: 'Replace', key: 'd' },
      { action: 'Replace', key: 'e' },
    ]);
    expect(s).toEqual([
      { way: 'inplace', count: 1 },
      { way: 'seamless', count: 2 },
      { way: 'interrupt', count: 1 },
    ]);
  });
});
