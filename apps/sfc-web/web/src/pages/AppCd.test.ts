// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import { fieldPath, fieldValue, withDelivery } from './AppCd';

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

describe('withDelivery', () => {
  it('x-sfc.delivery만 넣고 다른 줄·주석은 둔다', () => {
    const src = 'name: shop # 앱\nx-sfc:\n  ingress:\n    routes: []\nservices:\n  web: {image: php}\n';
    const out = withDelivery(src, { repository: 'https://git.example/team/shop.git', branch: 'main', path: 'app.yaml', credential: '', mode: 'manual' });
    expect(out).toContain('name: shop # 앱');
    expect(out).toContain('  web: {image: php}');
    const d = YAML.parse(out)['x-sfc'];
    expect(d.ingress).toEqual({ routes: [] });
    expect(d.delivery.source).toEqual({ kind: 'git', repository: 'https://git.example/team/shop.git', ref: 'main', path: 'app.yaml' });
    expect(d.delivery.sync.mode).toBe('manual');
    const withCred = YAML.parse(withDelivery(src, { repository: 'git@x:y.git', branch: 'dev', path: 'a.yaml', credential: 'git-ro', mode: 'automatic' }))['x-sfc'].delivery;
    expect(withCred.source.credential_profile).toBe('git-ro');
    expect(withCred.sync.mode).toBe('automatic');
  });
});
