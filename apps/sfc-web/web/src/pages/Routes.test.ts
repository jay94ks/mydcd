// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { parsePorts } from './Routes';

describe('parsePorts', () => {
  it('reads single ports, ranges and lists', () => {
    expect(parsePorts('443')).toEqual([{ first: 443, last: 443 }]);
    expect(parsePorts('80, 8000-8010')).toEqual([
      { first: 80, last: 80 },
      { first: 8000, last: 8010 },
    ]);
  });
  it('rejects bad input', () => {
    for (const s of ['', '0', '70000', '10-5', 'http', '1-2-3']) expect(parsePorts(s)).toBeUndefined();
  });
});
