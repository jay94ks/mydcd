// SPDX-License-Identifier: Apache-2.0

// 전체 찾기(Ctrl K, 캔버스 v224 StartSearch UI-10A): 기존 목록 API로 모은 항목에서 이름으로 찾는다.
// 내 권한으로 읽을 수 있는 목록만 모으므로 결과도 그 범위다.

export type HitKind = '앱' | '서버' | '망' | '외부 접속' | '데이터 저장소' | '이미지' | '작업 공간' | '사용자' | '작업 ID' | '화면' | '동작';
export interface Hit {
  kind: HitKind;
  label: string;
  /** 오른쪽 작은 설명 */
  sub?: string;
  to: string;
  /** 열기 전에 고를 작업 공간 */
  tenant?: string;
  /** 찾기에만 쓰는 다른 이름(예: 경로) */
  keys?: string;
}

const ORDER: HitKind[] = ['앱', '서버', '망', '외부 접속', '데이터 저장소', '이미지', '작업 공간', '사용자', '작업 ID', '화면', '동작'];
const OP_ID = /^[0-9a-f]{8}(-?[0-9a-f]{4}){0,3}(-?[0-9a-f]{0,12})$/i;

/** q로 hits를 거른다. 이름이 q로 시작하는 것 먼저, 그다음 종류 순서. 작업 ID 꼴이면 작업 기록 바로 가기를 더한다 */
export function searchHits(hits: Hit[], q: string, limit = 30): Hit[] {
  const s = q.trim().toLowerCase();
  if (!s) return [];
  const words = s.split(/\s+/);
  const scored = hits
    .map((h) => {
      const name = h.label.toLowerCase();
      const hay = `${name} ${(h.sub ?? '').toLowerCase()} ${(h.keys ?? '').toLowerCase()}`;
      if (!words.every((w) => hay.includes(w))) return undefined;
      const rank = name === s ? 0 : name.startsWith(s) ? 1 : name.includes(s) ? 2 : 3;
      return { h, rank };
    })
    .filter((x): x is { h: Hit; rank: number } => !!x)
    .sort((a, b) => a.rank - b.rank || ORDER.indexOf(a.h.kind) - ORDER.indexOf(b.h.kind) || (a.h.label < b.h.label ? -1 : a.h.label > b.h.label ? 1 : 0));
  const out = scored.map((x) => x.h);
  if (OP_ID.test(s) && s.length >= 8) out.unshift({ kind: '작업 ID', label: s, sub: '작업 기록에서 보기', to: `/system/ops?focus=${encodeURIComponent(s)}` });
  // 같은 곳을 가리키는 같은 이름은 하나만
  const seen = new Set<string>();
  return out.filter((h) => {
    const k = `${h.kind}/${h.label}/${h.to}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  }).slice(0, limit);
}
