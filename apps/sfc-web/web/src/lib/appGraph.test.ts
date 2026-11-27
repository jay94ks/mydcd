// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import { autoLayout, checkGraph, edgeId, graphToYaml, nodeId, yamlToGraph } from './appGraph';

const SRC = `# 상점
name: php-shop
x-sfc:
  ingress:
    routes:
      - host: shop.example.com
        prefix: /
        service: web
        port: 80
        gateway: external
        certificate: auto
services:
  web:
    image: php:8.3-apache
    ports: ["8080:80"]
    depends_on: [db]
    networks:
      backend:
        aliases: [www]
    volumes:
      - uploads:/var/www/uploads
      - ./conf:/etc/conf:ro
    secrets:
      - db-pass
    environment:
      DB_PASS_FILE: /run/secrets/db-pass
      MODE: prod
    healthcheck:
      test: ["CMD", "true"]
  db:
    image: mysql:8.4
    networks: [backend]
    x-sfc:
      node: node-b
networks:
  backend: { external: true }
volumes:
  uploads: { external: true }
secrets:
  db-pass: { external: true }
`;

describe('app.yaml ⇄ 그래프', () => {
  it('블록과 선을 읽는다(바인드 마운트는 선이 아님)', () => {
    const g = yamlToGraph(SRC);
    expect(g.nodes.map((n) => n.id).sort()).toEqual(['ingress:shop.example.com', 'network:backend', 'secret:db-pass', 'service:db', 'service:web', 'volume:uploads']);
    const kinds = g.edges.map((e) => `${e.kind}:${e.from}>${e.to}`).sort();
    expect(kinds).toEqual([
      'depends:service:web>service:db',
      'network:service:db>network:backend',
      'network:service:web>network:backend',
      'route:ingress:shop.example.com>service:web',
      'secret:service:web>secret:db-pass',
      'volume:service:web>volume:uploads',
    ]);
    expect(g.edges.find((e) => e.kind === 'secret')!.props).toMatchObject({ mode: 'file+env', envName: 'DB_PASS_FILE' });
    expect(g.edges.find((e) => e.kind === 'network' && e.from === 'service:web')!.props.alias).toBe('www');
    expect(g.nodes.find((n) => n.id === 'service:db')!.service!.node).toBe('node-b');
  });

  it('고치지 않으면 원문 그대로(주석·모르는 필드 유지)', () => {
    const out = graphToYaml(yamlToGraph(SRC), SRC);
    expect(YAML.parse(out)).toEqual(YAML.parse(SRC));
    expect(out).toContain('# 상점');
  });

  it('선을 지우고 더하면 해당 칸만 바뀐다', () => {
    const g = yamlToGraph(SRC);
    g.edges = g.edges.filter((e) => e.kind !== 'secret' && e.kind !== 'depends');
    g.nodes.push({ id: nodeId('volume', 'cache'), kind: 'volume', name: 'cache' });
    g.edges.push({ id: edgeId(), kind: 'volume', from: 'service:db', to: 'volume:cache', props: { target: '/var/lib/mysql', readOnly: false } });
    const doc = YAML.parse(graphToYaml(g, SRC));
    expect(doc.services.web.secrets).toBeUndefined();
    expect(doc.services.web.depends_on).toBeUndefined();
    // 비밀값 경로 변수도 함께 빠지고 다른 변수는 남는다
    expect(doc.services.web.environment).toEqual({ MODE: 'prod' });
    expect(doc.services.web.volumes).toEqual(['uploads:/var/www/uploads', './conf:/etc/conf:ro']);
    expect(doc.services.db.volumes).toEqual(['cache:/var/lib/mysql']);
    expect(doc.volumes.cache).toEqual({ external: true });
    expect(doc.services.web.healthcheck).toEqual({ test: ['CMD', 'true'] });
    expect(doc.secrets['db-pass']).toEqual({ external: true });
  });

  it('서비스 이름을 바꾸면 키를 옮기고 경로도 따라간다', () => {
    const g = yamlToGraph(SRC);
    const web = g.nodes.find((n) => n.id === 'service:web')!;
    web.name = 'front';
    web.id = 'service:front';
    for (const e of g.edges) {
      if (e.from === 'service:web') e.from = 'service:front';
      if (e.to === 'service:web') e.to = 'service:front';
    }
    const doc = YAML.parse(graphToYaml(g, SRC));
    expect(Object.keys(doc.services)).toEqual(['front', 'db']);
    expect(doc.services.front.image).toBe('php:8.3-apache');
    expect(doc['x-sfc'].ingress.routes[0]).toMatchObject({ service: 'front', certificate: 'auto', port: 80 });
  });

  it('빈 원문에서 새 앱을 만든다', () => {
    const g = { nodes: [{ id: 'service:web', kind: 'service' as const, name: 'web', service: { image: 'nginx', replicas: 2, ports: ['80:80'], node: '' } }, { id: 'network:front', kind: 'network' as const, name: 'front' }], edges: [{ id: 'x', kind: 'network' as const, from: 'service:web', to: 'network:front', props: { alias: 'site' } }] };
    const doc = YAML.parse(graphToYaml(g, 'name: a\n'));
    expect(doc.services.web).toEqual({ image: 'nginx', deploy: { replicas: 2 }, ports: ['80:80'], networks: { front: { aliases: ['site'] } } });
    expect(doc.networks).toEqual({ front: { external: true } });
  });

  it('검사: 이미지 없음, 상대 마운트 경로, 시작 순서 고리, 열지 않은 포트', () => {
    const g = yamlToGraph(SRC);
    g.nodes.find((n) => n.id === 'service:db')!.service!.image = '';
    g.edges.find((e) => e.kind === 'volume')!.props.target = 'data';
    g.edges.push({ id: 'c', kind: 'depends', from: 'service:db', to: 'service:web', props: {} });
    g.edges.find((e) => e.kind === 'route')!.props.port = '81';
    const texts = checkGraph(g).map((i) => i.text);
    expect(texts.some((t) => t.includes('이미지가 없습니다'))).toBe(true);
    expect(texts.some((t) => t.includes('/로 시작'))).toBe(true);
    expect(texts.some((t) => t.includes('고리'))).toBe(true);
    expect(texts.some((t) => t.includes('열지 않았습니다'))).toBe(true);
  });

  it('자동 정렬: 외부 접속 < 기다리는 서비스 < 먼저 뜨는 서비스 < 공유 자원', () => {
    const p = autoLayout(yamlToGraph(SRC));
    expect(p['ingress:shop.example.com'].x).toBeLessThan(p['service:web'].x);
    expect(p['service:web'].x).toBeLessThan(p['service:db'].x);
    expect(p['service:db'].x).toBeLessThan(p['network:backend'].x);
  });
});
