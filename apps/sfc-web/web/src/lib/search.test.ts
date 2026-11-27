// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { searchHits, type Hit } from './search';

const H: Hit[] = [
  { kind: '화면', label: '작업 공간 › shop › 권한', to: '/system/tenants/shop' },
  { kind: '망', label: 'shop-net', sub: 'shop · 서버 2', to: '/shared/networks?net=shop-net' },
  { kind: '앱', label: 'php-shop', sub: 'shop · 정상', to: '/deploy/apps/shop/php-shop' },
  { kind: '앱', label: 'shop-api', sub: 'shop · 진행 중', to: '/deploy/apps/shop/shop-api' },
  { kind: '작업 공간', label: 'shop', to: '/system/tenants/shop' },
  { kind: '서버', label: 'node-a', to: '/servers/node-a' },
];

describe('전체 찾기', () => {
  it('빈 찾기는 아무것도 없다', () => expect(searchHits(H, '  ')).toEqual([]));
  it('같은 이름, 앞이 같은 이름, 들어 있는 이름 순, 같으면 종류 순', () => {
    expect(searchHits(H, 'shop').map((h) => `${h.kind}:${h.label}`)).toEqual(['작업 공간:shop', '앱:shop-api', '망:shop-net', '앱:php-shop', '화면:작업 공간 › shop › 권한']);
  });
  it('여러 낱말은 모두 들어 있어야 한다(설명 포함)', () => {
    expect(searchHits(H, 'shop 진행').map((h) => h.label)).toEqual(['shop-api']);
  });
  it('작업 ID 꼴이면 작업 기록 바로 가기', () => {
    const r = searchHits(H, '1c9f9caa-47c0');
    expect(r[0]).toMatchObject({ kind: '작업 ID', to: '/system/ops?focus=1c9f9caa-47c0' });
    expect(searchHits(H, 'node')[0].kind).toBe('서버');
  });
});
