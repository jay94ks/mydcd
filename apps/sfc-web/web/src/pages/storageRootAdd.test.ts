// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { subPathError } from './StorageRootAdd';

describe('subPathError (sfcd prepare-storage 하위 경로 규칙)', () => {
  it('빈 값과 평범한 이름 8단까지 받는다', () => {
    expect(subPathError('')).toBeUndefined();
    expect(subPathError('data3')).toBeUndefined();
    expect(subPathError('a/b.c/d-e/f_g/1/2/3/4')).toBeUndefined();
  });
  it('9단, .·.., 빈 조각, 다른 글자는 거절한다', () => {
    for (const s of ['a/b/c/d/e/f/g/h/i', '../x', 'a/./b', 'a//b', '/a', 'a/', 'a b', '한글']) expect(subPathError(s)).toBeDefined();
  });
});
