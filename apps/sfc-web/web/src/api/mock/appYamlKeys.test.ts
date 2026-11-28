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
    expect(check('services: {}\nx-sfc:\n  ingress:\n    routes:\n      - host: a.example\n        balance: {slow_start: 30s}\n')).toMatch(/warmup/);
    expect(check('services: {}\nx-sfc:\n  ingress:\n    routes:\n      - host: a.example\n        balance: {warmup: 30s}\n')).toBe('');
    expect(check('services: {}\nx-sfc:\n  vault: {}\n')).toMatch(/x-sfc\.vault/);
    expect(check('services: {}\nnetworks:\n  n1: {driver: bridge}\n')).toMatch(/networks\.n1\.driver/);
  });
});
