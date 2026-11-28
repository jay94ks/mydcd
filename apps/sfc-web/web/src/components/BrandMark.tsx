// SPDX-License-Identifier: Apache-2.0

import mark from '../assets/brand/cluster-mark-64.png';
import mark2x from '../assets/brand/cluster-mark-128.png';
import markDark from '../assets/brand/cluster-mark-on-dark-64.png';
import markDark2x from '../assets/brand/cluster-mark-on-dark-128.png';

/**
 * Seafield Cluster 마크(원본: docs/brand). 글자 옆 장식이라 alt는 비운다.
 * onDark: 늘 어두운 바탕(상단 막대)에 놓일 때. 아니면 화면 테마(data-theme)에 맞는 쪽을 CSS가 고른다.
 */
export function BrandMark({ size, onDark = false }: { size: number; onDark?: boolean }) {
  const img = (src: string, src2x: string, cls?: string) => (
    <img className={cls} src={src} srcSet={`${src} 1x, ${src2x} 2x`} width={size} height={size} alt="" draggable={false} />
  );
  if (onDark) return img(markDark, markDark2x, 'brand-mark');
  return (
    <>
      {img(mark, mark2x, 'brand-mark brand-light')}
      {img(markDark, markDark2x, 'brand-mark brand-dark')}
    </>
  );
}
