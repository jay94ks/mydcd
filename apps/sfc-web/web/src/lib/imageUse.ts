// SPDX-License-Identifier: Apache-2.0

// image-usage(#242) 결과를 화면 문구로. 쓰는 곳 판단은 sfcd가, 내린 앱(archived)은 웹이 더한다.
import type { ImageUse } from '../api/endpoints';

const KIND: Record<string, string> = {
  'cd-candidate': '자동 배포 후보',
  'app-previous': '되돌리기용 앞 버전',
};
/** 한 행의 이름: 'php-shop · web', '단독 tools', 'php-shop (자동 배포 후보)' */
export function useRowLabel(r: ImageUse['rows'][number]): string {
  const k = KIND[r.kind];
  if (r.app) return `${r.app}${r.service ? ` · ${r.service}` : ''}${k ? ` (${k})` : ''}`;
  if (r.service || r.instance) return `단독 ${r.service ?? r.instance}`;
  return k ?? r.kind;
}
/** 쓰는 곳 한 줄: 'php-shop · web, worker / 보관된 앱 legacy'. app = 첫 앱(링크용) */
export function usedText(u: ImageUse | undefined): { text: string; app?: string; guess: boolean } {
  if (!u) return { text: '', guess: false };
  const apps = new Map<string, Set<string>>();
  const other: string[] = [];
  for (const r of u.rows) {
    if (r.app) {
      const s = apps.get(r.app) ?? new Set<string>();
      if (r.service) s.add(r.service);
      if (KIND[r.kind]) s.add(KIND[r.kind]);
      apps.set(r.app, s);
    } else other.push(useRowLabel(r));
  }
  const parts = [...apps].map(([a, s]) => (s.size ? `${a} · ${[...s].join(', ')}` : a));
  parts.push(...new Set(other), ...u.archived.map((a) => `보관된 앱 ${a.app}`));
  if (u.truncated) parts.push('더 있음');
  return { text: parts.join(' / '), app: apps.size ? [...apps.keys()][0] : undefined, guess: u.rows.length > 0 && u.rows.every((r) => r.match === 'repository-unknown') };
}
/** 쓰는 곳 수(컨테이너 수가 아니다). 보관된 앱 포함 */
export const usesOf = (u: ImageUse | undefined) => (u ? u.rows.length + u.archived.length : 0);
/** 실제로 쓰는 곳(sfcd 행)만 */
export const liveUses = (u: ImageUse | undefined) => (u ? u.rows.length : 0);
