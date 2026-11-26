// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { hasRouteCert, routeCertError, routeCertText } from './ingress';

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);

describe('routeCertText', () => {
  it('shows store links by ID, with the algorithm when there are two', () => {
    expect(routeCertText({ certificates: [{ id: A, alg: 'ecdsa' }] })).toBe('aaaaaaaaaaaa');
    expect(routeCertText({ certificates: [{ id: A, alg: 'ecdsa' }, { id: B, alg: 'rsa' }] })).toBe('aaaaaaaaaaaa (ECDSA) · bbbbbbbbbbbb (RSA)');
  });
  it('reports a missing certificate as an error-only entry', () => {
    const r = { certificates: [{ error: 'CERTIFICATE_MISSING' }] };
    expect(routeCertText(r)).toBe('');
    expect(routeCertError(r)).toBe('CERTIFICATE_MISSING');
    expect(hasRouteCert(r)).toBe(true);
  });
  it('treats a route without certificates as plain HTTP', () => {
    expect(hasRouteCert({})).toBe(false);
    expect(routeCertText({})).toBe('');
  });
});
