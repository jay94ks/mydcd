// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import { appYamlOldKeys } from './appYamlKeys';

const check = (y: string) => appYamlOldKeys(YAML.parse(y) as Record<string, unknown>);

describe('app.yaml A1 형식(#894)', () => {
  it('x-sfc.secrets 블록을 받는다', () => {
    expect(check('services:\n  web:\n    x-sfc:\n      secrets:\n        from: [db, group/app, cluster/tls]\n        env: [{source: db, name: DB_PASSWORD}]\n')).toBe('');
  });
  it('옛 키와 모르는 키, 값 있는 socket을 거절한다', () => {
    expect(check('services:\n  web:\n    x-sfc:\n      secrets_from: [db]\n')).toMatch(/secrets_from: 받지 않는 키/);
    expect(check('services:\n  web:\n    x-sfc:\n      secret_env: []\n')).toMatch(/secret_env/);
    expect(check('services:\n  web:\n    x-sfc:\n      secrets: {mount: [db]}\n')).toMatch(/secrets\.mount/);
    expect(check('services:\n  web:\n    x-sfc:\n      secrets: {socket: [db]}\n')).toMatch(/secrets\.socket/);
    expect(check('services:\n  web:\n    x-sfc:\n      secrets: {socket: []}\n')).toBe('');
  });
  it('balance는 warmup, 클러스터 전용 키는 거절', () => {
    expect(check('services: {}\nx-sfc:\n  ingress:\n    - {node: n1, host: a.example, balance: {slow_start: 30s}}\n')).toMatch(/warmup/);
    expect(check('services: {}\nx-sfc:\n  ingress:\n    - {node: n1, host: a.example, balance: {warmup: 30s}}\n')).toBe('');
    expect(check('services: {}\nx-sfc:\n  vault: {}\n')).toMatch(/x-sfc\.vault/);
    expect(check('services: {}\nnetworks:\n  n1: {driver: bridge}\n')).toMatch(/networks\.n1\.driver/);
  });
});

describe('app.yaml A2 형식(#910)', () => {
  it('ingress는 같은 서버의 route 목록', () => {
    expect(check('services: {}\nx-sfc:\n  ingress:\n    routes: []\n')).toMatch(/route 목록/);
    expect(check('services: {}\nx-sfc:\n  ingress:\n    - {node: n1, host: a.example}\n    - {node: n2, host: b.example}\n')).toMatch(/INGRESS_NODE_MIXED/);
    expect(check('services: {}\nx-sfc:\n  ingress:\n    - {id: route-2, node: n1, host: a.example}\n    - {node: n1, host: b.example}\n')).toMatch(/겹칩니다/);
    expect(check('services: {}\nx-sfc:\n  ingress:\n    - {node: n1, host: a.example, listeners: []}\n')).toMatch(/listeners/);
  });
  it("A3': x-sfc.delivery는 받지 않고 x-sfc.cd를 검사한다", () => {
    expect(check('services: {}\nx-sfc:\n  delivery: {repository: r}\n')).toMatch(/x-sfc.delivery: 받지 않는 키/);
    expect(check('services: {}\nx-sfc:\n  cd: {repository: https://git.example/a.git, branch: main, path: app.yaml, poll: 1m, sync: auto, drift: report, prune: false}\n')).toBe('');
    expect(check('services: {}\nx-sfc:\n  cd: {repository: r, branch: main}\n')).toMatch(/cd.path: 꼭/);
    expect(check('services: {}\nx-sfc:\n  cd: {repository: r, branch: main, path: a.yaml, sync: automatic}\n')).toMatch(/cd.sync/);
    expect(check('services: {}\nx-sfc:\n  cd: {repository: r, branch: main, path: a.yaml, drift: fix}\n')).toMatch(/cd.drift/);
    expect(check('services: {}\nx-sfc:\n  cd: {repository: r, branch: main, path: a.yaml, poll: soon}\n')).toMatch(/cd.poll/);
    expect(check('services: {}\nx-sfc:\n  cd: {repository: r, branch: main, path: a.yaml, poll: 1h30m}\n')).toBe('');
    expect(check('services: {}\nx-sfc:\n  cd: {repository: r, branch: main, path: a.yaml, poll: 500ms}\n')).toMatch(/1s 이상/);
    expect(check('services: {}\nx-sfc:\n  cd: {repository: r, branch: main, path: a.yaml, poll: 25h}\n')).toMatch(/24h 이하/);
    expect(check('services: {}\nx-sfc:\n  cd: {repository: r, branch: main, path: a.yaml, poll: 1.5s}\n')).toMatch(/초 단위/);
    expect(check('services: {}\nx-sfc:\n  cd: {repository: r, branch: main, path: a.yaml, mode: auto}\n')).toMatch(/cd.mode: 받지 않는 키/);
  });
});
