// SPDX-License-Identifier: Apache-2.0

/**
 * 쓰다 만 정의 초안(이 브라우저의 localStorage). 정의 원문에는 환경 변수 값이 들어 있으므로
 * 키에 사용자를 넣어 다른 사용자에게 보이지 않게 하고, 로그아웃하면 모두 지운다.
 */
const PREFIX = 'sfc.drafts.';
export const DRAFT_DAYS = 7;
const key = (user: string, kind: string, tenant: string) => `${PREFIX}${user}.${kind}.${tenant}`;

export function loadDraft<T extends object>(user: string, kind: string, tenant: string): (T & { at: string }) | undefined {
  try {
    const v = JSON.parse(localStorage.getItem(key(user, kind, tenant)) ?? 'null');
    if (!v || typeof v !== 'object') return undefined;
    // 초안은 7일 둔다(캔버스 v224 UnsavedGuard)
    if (typeof v.at === 'string' && Date.now() - Date.parse(v.at) > DRAFT_DAYS * 86_400_000) {
      localStorage.removeItem(key(user, kind, tenant));
      return undefined;
    }
    return v;
  } catch {
    return undefined;
  }
}
export function saveDraft(user: string, kind: string, tenant: string, value: object) {
  try {
    localStorage.setItem(key(user, kind, tenant), JSON.stringify({ ...value, at: new Date().toISOString() }));
  } catch {
    /* 저장 못 해도 나가기는 막지 않는다 */
  }
}
export function clearDraft(user: string, kind: string, tenant: string) {
  try {
    localStorage.removeItem(key(user, kind, tenant));
  } catch {
    /* 무시 */
  }
}
/** 로그아웃: 이 브라우저의 초안을 모두 지운다 */
export function clearAllDrafts() {
  try {
    for (const k of Object.keys(localStorage)) if (k.startsWith(PREFIX)) localStorage.removeItem(k);
  } catch {
    /* 무시 */
  }
}
