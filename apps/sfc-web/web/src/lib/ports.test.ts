// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import { parsePort, portText, publishText } from './ports';
import { graphToYaml, yamlToGraph } from './appGraph';
import { emptyStandalone, standaloneFromYaml, standaloneToYaml } from './standalone';

describe('portText', () => {
  it('짧은 모양은 그대로', () => {
    expect(portText('127.0.0.1:18080:8080/tcp')).toBe('127.0.0.1:18080:8080/tcp');
    expect(portText(8080)).toBe('8080');
  });
  it('긴 모양은 같은 뜻의 짧은 글로', () => {
    expect(portText({ target: 8080, published: 18080, host_ip: '127.0.0.1', protocol: 'tcp' })).toBe('127.0.0.1:18080:8080/tcp');
    expect(portText({ target: 53, published: 53, protocol: 'udp' })).toBe('53:53/udp');
    expect(portText({ target: 80 })).toBe('80');
    expect(portText({ target: 80, published: 8080, host_ip: '::1' })).toBe('[::1]:8080:80');
  });
});

describe('ports 보존', () => {
  const src = `services:
  web:
    image: nginx
    ports:
      - "127.0.0.1:18080:8080/tcp"
      - target: 53
        published: 5353
        host_ip: 10.0.0.5
        protocol: udp
`;
  it('그래프를 고치지 않으면 원문 ports가 그대로 남는다', () => {
    const g = yamlToGraph(src);
    expect(g.nodes.find((n) => n.kind === 'service')?.service?.ports).toEqual(['127.0.0.1:18080:8080/tcp', '10.0.0.5:5353:53/udp']);
    const out = YAML.parse(graphToYaml(g, src));
    expect(out.services.web.ports).toEqual(YAML.parse(src).services.web.ports);
  });
});

describe('단독 컨테이너 ports', () => {
  it('긴 모양도 폼으로 읽고 같은 뜻으로 쓴다', () => {
    const r = standaloneFromYaml(`name: dns\nlifetime: fixed\nimage: coredns\nports:\n  - target: 53\n    published: 5353\n    host_ip: 127.0.0.1\n    protocol: udp\n  - "127.0.0.1:18080:8080/tcp"\n`);
    if ('error' in r) throw new Error(r.error);
    expect(r.form.ports).toEqual([
      { port: '53', host: '127.0.0.1', publish: '5353', proto: 'udp', expose: true },
      { port: '8080', host: '127.0.0.1', publish: '18080', proto: 'tcp', expose: true },
    ]);
    expect(YAML.parse(standaloneToYaml(r.form)).ports).toEqual(['127.0.0.1:5353:53/udp', '127.0.0.1:18080:8080/tcp']);
  });
});

describe('parsePort', () => {
  it('세 모양과 IPv6', () => {
    expect(parsePort('8080')).toEqual({ host: '', published: '', target: '8080', proto: 'tcp' });
    expect(parsePort('15353:53/udp')).toEqual({ host: '', published: '15353', target: '53', proto: 'udp' });
    expect(parsePort('127.0.0.1:18080:8080/tcp')).toEqual({ host: '127.0.0.1', published: '18080', target: '8080', proto: 'tcp' });
    expect(parsePort('127.0.0.1::8080')).toEqual({ host: '127.0.0.1', published: '', target: '8080', proto: 'tcp' });
    expect(parsePort('[::1]:8080:80')).toEqual({ host: '::1', published: '8080', target: '80', proto: 'tcp' });
    expect(parsePort('20000-20010:80')?.published).toBe('20000-20010');
    expect(parsePort('a:b')).toBeUndefined();
    expect(parsePort('80/sctp')).toBeUndefined();
  });
  it('미리 보기 글', () => {
    expect(publishText(parsePort('8080')!)).toBe('서버가 고름');
    expect(publishText(parsePort('127.0.0.1:18080:9000')!)).toBe('127.0.0.1:18080');
  });
});

describe('단독 컨테이너 망 안 포트', () => {
  it('공개하지 않는 포트는 ports에 쓰지 않고, 경로가 가리키면 다시 읽는다', () => {
    const f = { ...emptyStandalone(), name: 'adm', lifetime: 'fixed' as const, image: 'adminer', ports: [{ port: '8080', proto: 'tcp' as const, expose: false, host: '', publish: '' }], routes: [{ node: 'node-a', host: 'a.example', path: '/', port: '8080', gateway: 'local' as const }] };
    const y = standaloneToYaml(f);
    expect(YAML.parse(y).ports).toBeUndefined();
    const r = standaloneFromYaml(y);
    if ('error' in r) throw new Error(r.error);
    expect(r.form.ports).toEqual([{ port: '8080', proto: 'tcp', expose: false, host: '', publish: '' }]);
  });
});
