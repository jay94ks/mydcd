// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import { checkStandalone, emptyStandalone, importAppService, parseDur, quickShell, standaloneFromYaml, standaloneToObject, standaloneToYaml } from './standalone';

describe('단독 컨테이너 정의', () => {
  it('고정: 평평한 원문(name·lifetime·restart·mode + 서비스 칸 + x-sfc)', () => {
    const f = { ...emptyStandalone(), name: 'report-cron', image: 'registry.local/shop/report:2.1', node: 'node-b', command: '/app/report --every 1h', networks: [{ name: 'shop-back', alias: '' }], volumes: [{ name: 'reports', target: '/data/reports', readOnly: false }], cpus: '0.5', memory: '256 MiB' };
    const o = standaloneToObject(f);
    expect(o).toMatchObject({ name: 'report-cron', lifetime: 'fixed', restart: 'on-failure', mode: 'entrypoint', image: 'registry.local/shop/report:2.1', command: ['/app/report', '--every', '1h'], networks: ['shop-back'], volumes: ['reports:/data/reports'], deploy: { resources: { limits: { cpus: '0.5', memory: '256M' } } }, 'x-sfc': { node: 'node-b' } });
    expect(o).not.toHaveProperty('ttl');
  });

  it('임시 쉘: ttl·grace, TTY+stdin, 기본 /bin/sh', () => {
    const o = standaloneToObject(quickShell('docker.io/library/busybox:1.36', 'shop-net', ''));
    expect(o).toMatchObject({ lifetime: 'temp', ttl: '1h', grace: '10m', mode: 'shell', command: ['/bin/sh'], tty: true, stdin_open: true, networks: ['shop-net'] });
    expect(o).not.toHaveProperty('restart');
    expect(String(o.name)).toMatch(/^temp-[0-9a-f]{4}$/);
  });

  it('원문 → 폼 → 원문이 같다(폼에 있는 칸)', () => {
    const f = { ...emptyStandalone(), name: 'adminer', restart: 'always' as const, image: 'adminer:4.8', ports: [{ port: '8080', proto: 'tcp' as const, expose: false, host: '', publish: '' }, { port: '53', proto: 'udp' as const, expose: true, host: '127.0.0.1', publish: '15353' }], routes: [{ node: 'node-b', host: 'adminer.shop.example', path: '/', port: '8080', gateway: 'local' as const }], env: [{ key: 'A', value: '1' }], secrets: [{ name: 'db-password', target: '/run/secrets/db', mode: '0400' }], health: 'cmd' as const, healthCmd: 'wget -q localhost', healthInterval: '30s' };
    const y = standaloneToYaml(f);
    const back = standaloneFromYaml(y);
    if (!('form' in back)) throw new Error('parse');
    expect(back.lost).toEqual([]);
    expect(standaloneToYaml(back.form)).toBe(y);
  });

  it('정의 고치기: 바뀐 칸만 바꾸고 나머지 원문 모양은 그대로', () => {
    const orig = 'name: report-cron\nlifetime: fixed\nrestart: on-failure\nmode: entrypoint\nimage: shop/worker:v5\ncommand: [/app/report, --every, 1h]\nnetworks: [shop-net]\nhealthcheck: {test: [CMD, /app/report, --ping], interval: 30s}\n';
    const r = standaloneFromYaml(orig);
    if (!('form' in r)) throw new Error('parse');
    expect(standaloneToYaml(r.form, orig)).toBe(orig);
    const next = standaloneToYaml({ ...r.form, command: '/app/report --every 30m' }, orig);
    expect(next).toBe(orig.replace('--every, 1h]', '--every, 30m]'));
  });

  it('폼에 없는 칸은 lost, 문법 오류는 줄 번호', () => {
    const r = standaloneFromYaml('name: a\nlifetime: fixed\nimage: x\ncap_add: [NET_ADMIN]\n');
    expect('form' in r && r.lost).toEqual(['cap_add']);
    const e = standaloneFromYaml('name: [a\n');
    expect('error' in e && e.error).toBeTruthy();
  });

  it('검사: 고정은 이름 필수, 임시 수명은 24시간까지', () => {
    expect(checkStandalone({ ...emptyStandalone(), image: 'x' })).toContain('고정 컨테이너는 이름이 있어야 합니다.');
    expect(checkStandalone({ ...emptyStandalone(), name: 't', lifetime: 'temp', ttl: '25h', image: 'x' })).toContain('임시 수명은 1분~24시간입니다.');
    expect(parseDur('1h30m')).toBe(5400);
    expect(parseDur('abc')).toBeUndefined();
  });

  it('앱 서비스 가져오기: 저장소는 읽기 전용, 외부 접속은 고를 때만', () => {
    const app = YAML.stringify({ name: 'php-shop', services: { web: { image: 'shop/web:v14', command: ['php-fpm'], depends_on: ['db'], networks: { 'shop-net': {} }, volumes: ['uploads:/srv/uploads'], ports: ['8080'], deploy: { replicas: 2 } } }, 'x-sfc': { ingress: [{ node: 'node-a', host: 'shop.example', service: 'web', port: 8080 }] } });
    const f = importAppService(emptyStandalone(), app, 'php-shop', 'web', { imageCmd: true, netEnv: true, volumes: true, secrets: true, ingress: false });
    expect(f).toMatchObject({ image: 'shop/web:v14', command: 'php-fpm', networks: [{ name: 'shop-net', alias: '' }], volumes: [{ name: 'uploads', target: '/srv/uploads', readOnly: true }], ports: [], routes: [], importedFrom: { app: 'php-shop', service: 'web', items: ['imageCmd', 'netEnv', 'volumes', 'secrets'] } });
    const g = importAppService(emptyStandalone(), app, 'php-shop', 'web', { imageCmd: true, netEnv: false, volumes: false, secrets: false, ingress: true });
    expect(g.routes).toEqual([{ node: 'node-a', host: 'shop.example', path: '/', port: '8080', gateway: 'external' }]);
    expect(standaloneToObject({ ...g, name: 'w' })).not.toHaveProperty('depends_on');
  });
});
