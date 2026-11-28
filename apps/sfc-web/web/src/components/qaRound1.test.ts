// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { ApiError } from '../api/client';
import { errorLine, errorText } from './states';
import { shownIds } from './ui';
import { certTitle } from '../pages/CertDetail';

describe('웹 UI 검수 1차', () => {
  it('화면 번호는 목업에서만 보인다', () => {
    expect(shownIds('UI-59', true)).toBe('UI-59');
    expect(shownIds('UI-59', false)).toBeUndefined();
    expect(shownIds('UI-60 ~ UI-64', false)).toBeUndefined();
    expect(shownIds('UI-10 · 시스템 관리자 보기', false)).toBeUndefined();
  });
  it('오류 띠 본문에는 코드와 영어 원문이 없다', () => {
    const e = new ApiError(404, { code: 'missing', message: 'no such certificate' });
    expect(errorLine(e)).toBe('찾지 못했습니다');
    const k = new ApiError(400, { code: 'invalid', message: '이름이 비었습니다' });
    expect(errorLine(k)).toBe('입력이 맞지 않습니다 · 이름이 비었습니다');
    expect(errorText(new ApiError(500, { code: 'weird-new-code' })).title).toBe('요청을 처리하지 못했습니다');
  });
  it('없는 앱은 화면 오류가 아니라 사실 그대로', () => {
    const e = Object.assign(new Error('이 앱이 없거나 볼 권한이 없습니다.'), { name: 'NotFound' });
    expect(errorLine(e)).toBe('이 앱이 없거나 볼 권한이 없습니다.');
  });
  it('인증서 상세 제목은 첫 이름, 없으면 발급 정의 이름', () => {
    expect(certTitle({ names: ['shop.example.com', '*.shop.example.com'] })).toBe('shop.example.com');
    expect(certTitle({ names: [] }, 'shop-example')).toBe('shop-example');
    expect(certTitle(undefined)).toBeUndefined();
  });
});
