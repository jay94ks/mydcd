// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { IngressView } from '../api/ingress';
import { buildMappings, clash, fallbackOf, gwOf } from './IngressRoutes';

const route = (id: string, gateway: 'external' | 'local', host: string, prefix: string, rps = 1, extra = {}) => ({ id, gateway, port: 443, host, prefix, service: 'web', servicePort: 8080, backends: [], rps, ...extra });
const V: IngressView = {
  nodes: [],
  tenants: [],
  summary: { rps: 0, err5xx: 0, p95Ms: 0 },
  observedAt: '',
  instances: [
    { tenant: 'shop', app: 'php-shop', node: 'node-a', generation: 1, ready: true, routes: [route('a', 'external', 'shop.example.com', '/', 10), route('b', 'local', 'shop.example.com', '/', 2), route('c', 'external', 'shop.example.com', '/admin')] },
    { tenant: 'shop', app: 'php-shop', node: 'node-b', generation: 1, ready: true, routes: [route('a', 'external', 'shop.example.com', '/', 5)] },
    { tenant: 'shop', app: 'shop-api', node: 'node-b', generation: 1, ready: true, routes: [route('d', 'external', 'Shop.example.com', '/api/v2'), { ...route('e', 'external', '*.shop.example.com', ''), port: 80, service: undefined, redirect: 'https' }] },
  ],
};

describe('도메인·경로별 매핑', () => {
  const all = buildMappings(V, { app: 'web', revision: 1, removed: false, node: 'node-a', routes: [{ host: 'sfc.example.com', gateway: 'local' }] });
  it('서버·게이트웨이별 매핑을 앱 정의의 경로 하나로 모은다', () => {
    const root = all.find((m) => m.app === 'php-shop' && m.prefix === '/')!;
    expect(gwOf(root.gateways)).toBe('external');
    expect(root.gateways.sort()).toEqual(['external', 'local']);
    expect(root.nodes.sort()).toEqual(['node-a', 'node-b']);
    expect(root.flats).toHaveLength(3);
    expect(all.find((m) => m.redirect)?.prefix).toBe('/');
    const web = all.find((m) => m.cluster)!;
    expect(web.prefix).toBe('/');
    expect(web.gateways).toEqual(['local']);
    expect(web.nodes).toEqual(['node-a']);
  });
  it('같은 호스트·접두사에 게이트웨이가 겹치면 막고, 자기 자신은 빼고 본다', () => {
    expect(clash(all, 'shop.example.com', '/admin', 'external')?.app).toBe('php-shop');
    expect(clash(all, 'shop.example.com', '/admin', 'local')).toBeUndefined();
    expect(clash(all, 'SHOP.example.com', '/api/v2', 'external')?.app).toBe('shop-api');
    const self = all.find((m) => m.prefix === '/admin')!;
    expect(clash(all, 'shop.example.com', '/admin', 'external', self)).toBeUndefined();
  });
  it('새 접두사가 받을 요청은 가장 긴 다른 접두사가 받던 것', () => {
    expect(fallbackOf(all, 'shop.example.com', '/api/v2/x', 'external')?.prefix).toBe('/api/v2');
    expect(fallbackOf(all, 'shop.example.com', '/shop', 'external')?.app).toBe('php-shop');
    expect(fallbackOf(all, 'other.example.com', '/x', 'external')).toBeUndefined();
  });
  it('지운 클러스터 앱 경로는 표에 없다', () => {
    expect(buildMappings(V, { app: 'web', revision: 2, removed: true, node: 'node-a', routes: [{ host: 'sfc.example.com', gateway: 'local' }] }).some((m) => m.cluster)).toBe(false);
  });
});
