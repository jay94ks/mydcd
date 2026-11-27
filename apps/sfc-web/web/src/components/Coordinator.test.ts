// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { screenContext } from './Coordinator';

describe('screenContext', () => {
  it('앱 화면은 작업 공간·앱을 맥락에 넣는다', () => {
    expect(screenContext('/deploy/apps/shop/php-shop')).toEqual({ screen: '배포 › php-shop', path: '/deploy/apps/shop/php-shop', selection: { tenant: 'shop', app: 'php-shop' } });
  });
  it('컨테이너 화면은 서비스·인스턴스까지 넣는다', () => {
    const c = screenContext('/deploy/apps/shop/php-shop/c/web/2/logs');
    expect(c.selection).toEqual({ tenant: 'shop', app: 'php-shop', service: 'web', instance: '2' });
    expect(c.screen).toBe('배포 › php-shop › 컨테이너 web-2');
  });
});
