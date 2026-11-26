// SPDX-License-Identifier: Apache-2.0

import type { DiffLine } from '../api/types';

/** 줄 단위 LCS diff. app.yaml 크기(수백 줄)에 맞춘 단순 구현이다. */
export function lineDiff(before: string, after: string): DiffLine[] {
  const a = before === '' ? [] : before.replace(/\n$/, '').split('\n');
  const b = after === '' ? [] : after.replace(/\n$/, '').split('\n');
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ op: ' ', text: a[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ op: '-', text: a[i++] });
    } else {
      out.push({ op: '+', text: b[j++] });
    }
  }
  while (i < n) out.push({ op: '-', text: a[i++] });
  while (j < m) out.push({ op: '+', text: b[j++] });
  return out;
}

/** 바뀐 줄 앞뒤 context 줄만 남긴다. 생략은 '…' 줄로 표시한다. */
export function compactDiff(lines: DiffLine[], context = 3): (DiffLine | { op: '…'; text: string })[] {
  const keep = new Array<boolean>(lines.length).fill(false);
  lines.forEach((l, idx) => {
    if (l.op !== ' ') for (let k = Math.max(0, idx - context); k <= Math.min(lines.length - 1, idx + context); k++) keep[k] = true;
  });
  const out: (DiffLine | { op: '…'; text: string })[] = [];
  let skipped = 0;
  lines.forEach((l, idx) => {
    if (keep[idx]) {
      if (skipped) out.push({ op: '…', text: `${skipped}줄 같음` });
      skipped = 0;
      out.push(l);
    } else skipped++;
  });
  if (skipped) out.push({ op: '…', text: `${skipped}줄 같음` });
  return out;
}

export function diffCounts(lines: DiffLine[]): { add: number; remove: number } {
  let add = 0;
  let remove = 0;
  for (const l of lines) {
    if (l.op === '+') add++;
    else if (l.op === '-') remove++;
  }
  return { add, remove };
}
