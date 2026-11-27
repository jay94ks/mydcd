// SPDX-License-Identifier: Apache-2.0

// 이미지 신뢰 출처 규칙 맞추기(화면 안내용). 실제 검사는 sfcd CheckImageTrust다.
export type Rule = { registry: string; repository: string };

/** 정규화된 이미지 참조 → 저장소 주소와 경로(태그·다이제스트 뺌) */
export function splitImage(image: string): { registry: string; path: string } {
  const at = image.indexOf('@');
  let s = at >= 0 ? image.slice(0, at) : image;
  const slash = s.indexOf('/');
  const colon = s.lastIndexOf(':');
  if (colon > slash) s = s.slice(0, colon);
  if (slash < 0) return { registry: 'docker.io', path: `library/${s}` };
  const head = s.slice(0, slash);
  if (!/[.:]/.test(head) && head !== 'localhost') return { registry: 'docker.io', path: s };
  return { registry: head, path: s.slice(slash + 1) };
}
/** sfcd CheckImageTrust와 같다: 저장소 주소가 같고, 경로가 ** 이거나 정확히 같은 경로 */
export function matchRule(rule: Rule, image: string): boolean {
  const { registry, path } = splitImage(image);
  return registry === rule.registry && (rule.repository === '**' || rule.repository === path);
}
