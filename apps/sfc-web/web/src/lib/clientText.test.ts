// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { clientText } from '../api/me';

describe('clientText', () => {
  it('브라우저 · 운영체제', () => {
    expect(clientText('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36')).toBe('Chrome · Windows');
    expect(clientText('Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:132.0) Gecko/20100101 Firefox/132.0')).toBe('Firefox · macOS');
    expect(clientText('Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/131.0 Safari/537.36 Edg/131.0')).toBe('Edge · Windows');
  });
  it('CLI와 모르는 값', () => {
    expect(clientText(undefined)).toBe('sfcli CLI');
    expect(clientText('sfc/0.9')).toBe('sfcli CLI');
    expect(clientText('x'.repeat(40))).toHaveLength(33);
  });
});
