// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { applyPrefs, pollText, prefPollMs, prefTimeZone, tzLabel, validTimeZone } from './uiPrefs';
import { fmtTime } from './format';

describe('화면 설정', () => {
  it('자동 갱신 주기와 시간대를 적용한다', () => {
    applyPrefs({ pollSeconds: 60, timeZone: 'Asia/Seoul' });
    expect(prefPollMs()).toBe(60_000);
    expect(prefTimeZone()).toBe('Asia/Seoul');
    applyPrefs({});
    expect(prefPollMs()).toBeUndefined();
    expect(prefTimeZone()).toBeUndefined();
  });
  it('주기와 시간대 글', () => {
    expect(pollText(30)).toBe('30초');
    expect(pollText(300)).toBe('5분');
    expect(pollText(0)).toBe('멈춤');
    expect(tzLabel('Asia/Seoul')).toBe('Asia/Seoul (UTC+9)');
  });
  it('이 브라우저가 모르는 시간대는 버린다(시각 표시가 깨지지 않게)', () => {
    expect(validTimeZone('Asia/Seoul')).toBe('Asia/Seoul');
    expect(validTimeZone('Mars/Olympus')).toBeUndefined();
    expect(validTimeZone(3)).toBeUndefined();
    applyPrefs({ timeZone: 'Mars/Olympus' });
    expect(prefTimeZone()).toBeUndefined();
    expect(() => fmtTime('2026-11-26T10:00:00Z')).not.toThrow();
    applyPrefs({});
  });
});
