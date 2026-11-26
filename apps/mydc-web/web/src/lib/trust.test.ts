// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { matchRule, splitImage } from './trust';

describe('splitImage', () => {
  it('저장소 주소와 경로로 나눈다', () => {
    expect(splitImage('docker.io/library/mysql:8.4')).toEqual({ registry: 'docker.io', path: 'library/mysql' });
    expect(splitImage('mysql')).toEqual({ registry: 'docker.io', path: 'library/mysql' });
    expect(splitImage('team/app:1')).toEqual({ registry: 'docker.io', path: 'team/app' });
    expect(splitImage('registry.mydc.local:5000/shop/web@sha256:abc')).toEqual({ registry: 'registry.mydc.local:5000', path: 'shop/web' });
  });
});

describe('matchRule', () => {
  it('** = 그 저장소 전부, 아니면 정확히 같은 경로 (mydcd CheckImageTrust)', () => {
    expect(matchRule({ registry: 'docker.io', repository: '**' }, 'docker.io/library/mysql:8.4')).toBe(true);
    expect(matchRule({ registry: 'docker.io', repository: 'library/mysql' }, 'docker.io/library/mysql:8.4')).toBe(true);
    expect(matchRule({ registry: 'docker.io', repository: 'library/mysql' }, 'mysql@sha256:abc')).toBe(true);
    expect(matchRule({ registry: 'docker.io', repository: 'library/mysql' }, 'docker.io/library/mysqlx:1')).toBe(false);
    expect(matchRule({ registry: 'quay.io', repository: 'prometheus/**' }, 'quay.io/prometheus/node:1')).toBe(false);
    expect(matchRule({ registry: 'ghcr.io', repository: '**' }, 'docker.io/library/mysql:8.4')).toBe(false);
  });
});
