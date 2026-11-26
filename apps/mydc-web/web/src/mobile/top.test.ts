// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { isTabRoot, isWideOnly, parentOf, titleFor } from './top';
import { deviceLabel } from './MLogin';

describe('휴대폰 틀 주소 규칙', () => {
  it('편집기·설정은 보기만', () => {
    expect(isWideOnly('/deploy/new')).toBe(true);
    expect(isWideOnly('/deploy/apps/shop/php-shop/edit')).toBe(true);
    expect(isWideOnly('/deploy/apps/shop/php-shop/place')).toBe(true);
    expect(isWideOnly('/deploy/apps/shop/php-shop/c/web/1/exec')).toBe(true);
    expect(isWideOnly('/shared/networks')).toBe(true);
    expect(isWideOnly('/system/web')).toBe(true);
    // 장애 대응 정책·지침·웹훅 탭은 휴대폰 전용 보기만 화면이 있어 띠를 두지 않는다 (UI-M8)
    expect(isWideOnly('/incidents/policy')).toBe(false);
  });
  it('확인·승인 화면은 그대로', () => {
    expect(isWideOnly('/')).toBe(false);
    expect(isWideOnly('/incidents')).toBe(false);
    expect(isWideOnly('/deploy/apps/shop/php-shop')).toBe(false);
    expect(isWideOnly('/deploy/apps/shop/php-shop/cd')).toBe(false);
    expect(isWideOnly('/deploy/apps/shop/php-shop/c/web/1/logs')).toBe(false);
    expect(isWideOnly('/system/ops')).toBe(false);
    expect(isWideOnly('/servers/node-a')).toBe(false);
  });
  it('아래 탭 첫 화면과 뒤로', () => {
    expect(isTabRoot('/')).toBe(true);
    expect(isTabRoot('/incidents')).toBe(true);
    expect(isTabRoot('/incidents/inc-1')).toBe(false);
    expect(parentOf('/shared/networks')).toBe('/more');
    expect(parentOf('/deploy/apps/shop/php-shop/c/web/1/logs')).toBe('/deploy/apps/shop/php-shop');
    expect(parentOf('/incidents/inc-1')).toBe('/incidents');
    expect(titleFor('/system/ops')).toBe('작업 기록');
  });
  it('키 이름 기본값은 기기-브라우저', () => {
    expect(deviceLabel('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1')).toBe('iphone-safari');
    expect(deviceLabel('Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile Safari/537.36')).toBe('android-chrome');
  });
});
