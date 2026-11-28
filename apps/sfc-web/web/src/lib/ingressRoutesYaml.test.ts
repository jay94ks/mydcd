// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import { addRoute, readRoutes, removeRoute, replaceRoute, routeProblems, RouteEditError, servicePorts } from './ingressRoutesYaml';
import { graphToYaml, yamlToGraph } from './appGraph';

const SRC = `# 상점
name: shop
x-sfc:
  ingress:
    # 첫 경로
    - node: node-a
      host: shop.example.com
      prefix: /
      service: web
      port: 80
      gateway: external
      health: /healthz
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
    const out = addRoute(SRC, { node: 'node-a', host: 'shop.example.com', prefix: '/api', gateway: 'local', service: 'api', port: 8080 });
    expect(out).toContain('# 상점');
    // 손대지 않은 흐름 목록 모양은 그대로(yaml 기본값은 [ a ]로 바꾼다)
    expect(out).toContain('expose: ["9000/tcp"]');
    const r = readRoutes(out);
    expect(r).toHaveLength(2);
    expect(r[1]).toEqual({ node: 'node-a', host: 'shop.example.com', prefix: '/api', service: 'api', port: 8080, gateway: 'local' });
    expect(r[0].health).toBe('/healthz');
  });
  it('한 앱의 경로는 모두 같은 서버(INGRESS_NODE_MIXED)', () => {
    expect(() => addRoute(SRC, { node: 'node-b', host: 'x.example.com', prefix: '/', gateway: 'local', service: 'api', port: 8080 })).toThrow(/같은 서버/);
  });
  it('같은 호스트·접두사는 막는다(대소문자 무시)', () => {
    expect(() => addRoute(SRC, { node: 'node-a', host: 'SHOP.example.com', prefix: '/', gateway: 'local', service: 'web', port: 80 })).toThrow(RouteEditError);
  });
  it('고치면 다른 칸을 지키고 서버를 바꾼다', () => {
    const out = replaceRoute(SRC, { host: 'shop.example.com', prefix: '/' }, { node: 'node-c', host: 'shop.example.com', prefix: '/v2', gateway: 'local', service: 'web', port: 80 });
    const r = readRoutes(out)[0];
    expect(r.prefix).toBe('/v2');
    expect(r.node).toBe('node-c');
    expect(r.health).toBe('/healthz');
  });
  it('마지막 경로를 빼면 x-sfc.ingress가 없어진다', () => {
    const two = addRoute(SRC, { node: 'node-a', host: 'a.example.com', prefix: '/', gateway: 'local', service: 'api', port: 1 });
    expect(readRoutes(removeRoute(two, { host: 'shop.example.com', prefix: '/' })).map((r) => r.host)).toEqual(['a.example.com']);
    const none = YAML.parse(removeRoute(SRC, { host: 'shop.example.com', prefix: '/' })) as Record<string, unknown>;
    expect(none['x-sfc']).toBeUndefined();
  });
  it('외부 접속이 없으면 목록을 새로 만들고, 예전 객체 형식은 거절', () => {
    const r = readRoutes(addRoute('name: x\nservices: {}\n', { node: 'node-a', host: 'a.b', prefix: '/', gateway: 'external' }));
    expect(r).toEqual([{ node: 'node-a', host: 'a.b', prefix: '/', gateway: 'external' }]);
    expect(() => addRoute('name: x\nx-sfc:\n  ingress:\n    routes: []\n', { node: 'n', host: 'c.d', prefix: '/', gateway: 'local' })).toThrow(/예전 외부 접속 형식/);
  });
  it('클러스터 앱 경로는 service·port 없이', () => {
    const f = 'name: cluster-app/web\nx-sfc:\n  ingress:\n    - {node: node-a, host: web.example.com, prefix: /, gateway: local}\n';
    const r = readRoutes(addRoute(f, { node: 'node-a', host: 'web.example.com', prefix: '/admin', gateway: 'external' }));
    expect(r[1]).toEqual({ node: 'node-a', host: 'web.example.com', prefix: '/admin', gateway: 'external' });
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
  it('그래프 편집기도 같은 route 목록을 읽고 쓴다(node·health는 그대로)', () => {
    const g = yamlToGraph(SRC);
    const e = g.edges.find((x) => x.kind === 'route')!;
    expect(e.props.path).toBe('/');
    expect(e.props.node).toBe('node-a');
    e.props.path = '/x';
    const r = (YAML.parse(graphToYaml(g, SRC)) as { 'x-sfc': { ingress: Record<string, unknown>[] } })['x-sfc'].ingress[0];
    expect(r).toMatchObject({ node: 'node-a', prefix: '/x', health: '/healthz', gateway: 'external' });
  });
});
