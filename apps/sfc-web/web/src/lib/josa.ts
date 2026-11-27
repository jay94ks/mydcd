// SPDX-License-Identifier: Apache-2.0

/**
 * 이름 뒤 을/를. 한글은 받침으로, 영문·숫자는 읽는 소리의 끝으로 고른다(shop-net을, uploads를).
 */
export function eulReul(name: string): string {
  const c = name.trim().slice(-1);
  if (!c) return '을(를)';
  const code = c.charCodeAt(0);
  if (code >= 0xac00 && code <= 0xd7a3) return (code - 0xac00) % 28 ? '을' : '를';
  if (/[0-9]/.test(c)) return '013678'.includes(c) ? '을' : '를';
  // node-c·sh-b처럼 끝이 글자 하나면 글자 이름(씨, 비, 엘)으로 읽는다. l·m·n·r만 받침
  if (/(^|[^a-z])[a-z]$/i.test(name.trim())) return 'lmnr'.includes(c.toLowerCase()) ? '을' : '를';
  // -le(스테이블)·-me(네임)는 받침으로 읽는다
  if (/(le|me)$/i.test(name.trim())) return '을';
  if (/[a-z]/i.test(c)) return 'bcklmnpt'.includes(c.toLowerCase()) ? '을' : '를';
  return '을(를)';
}

/** 이름 뒤 이/가. 을/를과 같은 받침 규칙. */
export function iGa(name: string): string {
  const r = eulReul(name);
  return r === '을' ? '이' : r === '를' ? '가' : '이(가)';
}

/** 이름 뒤 은/는. 을/를과 같은 받침 규칙. */
export function eunNeun(name: string): string {
  const r = eulReul(name);
  return r === '을' ? '은' : r === '를' ? '는' : '은(는)';
}

/** 이름 뒤 과/와. 을/를과 같은 받침 규칙. */
export function gwaWa(name: string): string {
  const r = eulReul(name);
  return r === '을' ? '과' : r === '를' ? '와' : '과(와)';
}
