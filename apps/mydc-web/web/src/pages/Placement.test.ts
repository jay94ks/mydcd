// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { withNodes } from './Placement';

describe('withNodes', () => {
  it('바꾼 서비스의 x-mydc.node만 고치고 다른 줄·주석은 둔다', () => {
    const src = 'name: shop # 앱\nservices:\n  web:\n    image: nginx\n    x-mydc:\n      node: node-b\n  worker:\n    image: busybox\n';
    const out = withNodes(src, { web: 'node-a', worker: 'node-c' });
    expect(out).toContain('name: shop # 앱');
    expect(out).toContain('    x-mydc:\n      node: node-a');
    expect(out).toMatch(/worker:\n {4}image: busybox\n {4}x-mydc:\n {6}node: node-c/);
  });
});

describe('withNodes 흐름 표기', () => {
  it('[a] · {k: v} 표기를 그대로 둔다', () => {
    const src = 'services:\n  web:\n    networks: [shop-net]\n    x-mydc:\n      node: node-a\n      health: {ref: {name: http-ready, revision: 2}}\n';
    const out = withNodes(src, { web: 'node-b' });
    expect(out).toBe(src.replace('node: node-a', 'node: node-b'));
  });
});
