// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { acmePathHits, hitRows } from './acmePath';

describe('acmePathHits', () => {
  it('finds a block route and points at its item', () => {
    const y = 'name: shop\nx-sfc:\n  ingress:\n    routes:\n      - host: shop.example.com\n        path: /.well-known/acme-challenge/\n        port: 80\n';
    const h = acmePathHits(y);
    expect(h).toEqual([{ from: 5, to: 6, path: '/.well-known/acme-challenge/' }]);
    expect(hitRows(h[0])).toBe('5–6행');
  });
  it('finds inline flow maps, quoted and sub paths', () => {
    const y = "routes:\n  - {host: a.example, path: '/.well-known/acme-challenge/x', port: 80}\n  - {host: b.example, path: /.well-known/acme-challenge, port: 80}\n";
    expect(acmePathHits(y).map((x) => [x.to, x.path])).toEqual([
      [2, '/.well-known/acme-challenge/x'],
      [3, '/.well-known/acme-challenge'],
    ]);
  });
  it('ignores other paths, look-alikes and comments', () => {
    const y = 'routes:\n  - {host: a, path: /}\n  - {host: b, path: /.well-known/acme-challenger}\n# path: /.well-known/acme-challenge/\n  - {host: c, path: /.well-known/security.txt}\n';
    expect(acmePathHits(y)).toEqual([]);
  });
});
