// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import { addRoute, readRoutes, removeRoute, replaceRoute, routeProblems, RouteEditError, servicePorts } from './ingressRoutesYaml';
import { graphToYaml, yamlToGraph } from './appGraph';

const SRC = `# 상점
name: shop
x-sfc:
  ingress:
    routes:
      # 첫 경로
      - host: shop.example.com
        prefix: /
        service: web
        port: 80
        gateway: external
        health_path: /healthz
services:
  web:
    image: nginx
    ports: ["8080:80", { target: 443 }]
    expose: ["9000/tcp"]
  api:
    image: api
`;

describe('ingressRoutesYaml', () => {
  it('더하면 주석과 다른 칸은 그대로', () => {
    const out = addRoute(SRC, { host: 'shop.example.com', prefix: '/api', gateway: 'both', service: 'api', port: 8080 });
    expect(out).toContain('# 상점');
    // 손대지 않은 흐름 목록 모양은 그대로(yaml 기본값은 [ a ]로 바꾼다)
    expect(out).toContain('expose: ["9000/tcp"]');
    const r = readRoutes(out);
    expect(r).toHaveLength(2);
    expect(r[1]).toEqual({ host: 'shop.example.com', prefix: '/api', service: 'api', port: 8080, gateway: 'both' });
    expect(r[0].health_path).toBe('/healthz');
  });
  it('같은 호스트·접두사는 막는다(대소문자 무시)', () => {
    expect(() => addRoute(SRC, { host: 'SHOP.example.com', prefix: '/', gateway: 'local', service: 'web', port: 80 })).toThrow(RouteEditError);
  });
  it('고치면 다른 칸을 지키고 path를 prefix로 바꾼다', () => {
    const src = SRC.replace('prefix: /', 'path: /');
    const out = replaceRoute(src, { host: 'shop.example.com', prefix: '/' }, { host: 'shop.example.com', prefix: '/v2', gateway: 'local', service: 'web', port: 80 });
    const r = readRoutes(out)[0];
    expect(r.prefix).toBe('/v2');
    expect(r.path).toBeUndefined();
    expect(r.health_path).toBe('/healthz');
  });
  it('마지막 경로는 뺄 수 없고, 둘이면 뺀다', () => {
    expect(() => removeRoute(SRC, { host: 'shop.example.com', prefix: '/' })).toThrow(/마지막/);
    const two = addRoute(SRC, { host: 'a.example.com', prefix: '/', gateway: 'local', service: 'api', port: 1 });
    expect(readRoutes(removeRoute(two, { host: 'shop.example.com', prefix: '/' })).map((r) => r.host)).toEqual(['a.example.com']);
  });
  it('외부 접속 설정이 없거나 단일 host 형식이면 거절', () => {
    expect(() => addRoute('name: x\nservices: {}\n', { host: 'a.b', prefix: '/', gateway: 'local' })).toThrow(/x-sfc.ingress/);
    expect(() => addRoute('name: x\nx-sfc:\n  ingress:\n    host: a.b\n', { host: 'c.d', prefix: '/', gateway: 'local' })).toThrow(/단일 host/);
  });
  it('클러스터 앱 경로는 service·port 없이', () => {
    const f = 'name: cluster-app/web\nx-sfc:\n  ingress:\n    routes:\n      - host: web.example.com\n        gateway: local\n';
    const r = readRoutes(addRoute(f, { host: 'web.example.com', prefix: '/admin', gateway: 'external' }));
    expect(r[1]).toEqual({ host: 'web.example.com', prefix: '/admin', gateway: 'external' });
  });
  it('서비스와 컨테이너 포트', () => {
    expect(servicePorts(SRC)).toEqual([
      { service: 'web', ports: [80, 443, 9000] },
      { service: 'api', ports: [] },
    ]);
  });
  it('호스트·접두사 모양 검사', () => {
    expect(routeProblems({ host: 'shop.example.com', prefix: '/api' })).toEqual([]);
    expect(routeProblems({ host: '*.example.com', prefix: '/' })).toEqual([]);
    expect(routeProblems({ host: 'Bad Host', prefix: 'api' })).toHaveLength(2);
  });
  it('그래프 편집기도 prefix를 읽고 쓴다(path는 읽기만)', () => {
    const src = SRC.replace('prefix: /', 'path: /x');
    const g = yamlToGraph(src);
    expect(g.edges.find((e) => e.kind === 'route')?.props.path).toBe('/x');
    const r = (YAML.parse(graphToYaml(g, src)) as { 'x-sfc': { ingress: { routes: Record<string, unknown>[] } } })['x-sfc'].ingress.routes[0];
    expect(r.prefix).toBe('/x');
    expect(r.path).toBeUndefined();
  });
});
