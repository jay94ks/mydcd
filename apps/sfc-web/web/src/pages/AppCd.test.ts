// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { connectPolicy, fieldPath, fieldValue } from './AppCd';

describe('fieldPath', () => {
  it('서비스 칸만 받는다', () => {
    expect(fieldPath('services.web.image')).toEqual(['services', 'web', 'image']);
    expect(fieldPath(' services.web.environment.APP_MODE ')).toEqual(['services', 'web', 'environment', 'APP_MODE']);
    expect(fieldPath('services.web.healthcheck.interval')).toEqual(['services', 'web', 'healthcheck', 'interval']);
    expect(fieldPath('services.web')).toBeUndefined();
    expect(fieldPath('networks.front.name')).toBeUndefined();
    expect(fieldPath('services.web.environment.1BAD')).toBeUndefined();
    expect(fieldPath('services.web.healthcheck.nope')).toBeUndefined();
  });
});

describe('fieldValue', () => {
  it('JSON으로 읽히면 그 값, 아니면 문자열', () => {
    expect(fieldValue('3')).toBe(3);
    expect(fieldValue('["a","b"]')).toEqual(['a', 'b']);
    expect(fieldValue('true')).toBe(true);
    expect(fieldValue('php:8.3')).toBe('php:8.3');
  });
});

describe('connectPolicy', () => {
  it('Git 연결 입력으로 처음 정책을 만든다(app.yaml은 그대로)', () => {
    const p = connectPolicy({ repository: ' https://git.example/team/shop.git ', branch: 'main', path: 'app.yaml', credential: '', mode: 'manual' });
    expect(p.source).toEqual({ kind: 'git', repository: 'https://git.example/team/shop.git', ref: 'main', path: 'app.yaml', credential: '' });
    expect(p.enabled).toBe(true);
    expect(p.sync).toEqual({ mode: 'manual', drift: 'report', prune: false, allowEmpty: false });
    // sfcd 검사 범위: fetch 1..300, bytes 1..4MiB, queued·active 1
    expect(p.limits).toEqual({ fetch: 30, bytes: 4194304, queued: 1, active: 1 });
    expect(p.runtime).toEqual({ mode: 'require-explicit-override', expiry: 'manual-release' });
    expect(connectPolicy({ repository: 'git@x:y.git', branch: 'dev', path: 'a.yaml', credential: 'git-ro', mode: 'automatic' }).source.credential).toBe('git-ro');
  });
});
