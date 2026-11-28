// SPDX-License-Identifier: Apache-2.0

// 배포 미리보기의 항목별 적용 방식(Z9, 웹 계약 #932, 범위 문서 "컨테이너 무중단 적용 범위").
// sfcd가 정한 action과 interruption 코드로 "바로 적용 / 끊김 없는 교체 / 끊김 있음(이유)"를 만든다.

import type { PlanReply } from '../api/types';
import type { Tone } from '../components/ui';

export type PlanChange = PlanReply['changes'][number];
export type ApplyWay = 'create' | 'inplace' | 'seamless' | 'interrupt' | 'move' | 'remove' | 'keep' | 'other';

export const APPLY_WAY: Record<ApplyWay, [Tone, string]> = {
  create: ['ok', '새로 만듦'],
  inplace: ['ok', '바로 적용'],
  seamless: ['pr', '끊김 없는 교체'],
  interrupt: ['wa', '끊김 있음'],
  move: ['wa', '옮기기 필요'],
  remove: ['er', '내림'],
  keep: ['un', '그대로'],
  other: ['tag', '바뀜'],
};

/** 교체 동안 서비스가 멈추는 까닭. 모르는 코드는 코드 그대로 보인다 */
const INTERRUPTION: Record<string, string> = {
  SINGLE_INSTANCE: '다른 서버에 받아 줄 복제본이 없어, 교체하는 동안 멈춥니다.',
  VOLUME_WRITER: '쓰기 Volume을 써서 새 컨테이너와 옛 컨테이너를 함께 띄울 수 없습니다(데이터를 지키려고 막음).',
  HOST_PORT: '서버 포트(ports)를 직접 열어 같은 포트를 둘이 열 수 없습니다. 외부 접속(ingress route)으로 받으면 끊기지 않습니다.',
  STATIC_ADDRESS: '고정 주소(ipv4_address·ipv6_address)를 두 컨테이너가 함께 가질 수 없습니다.',
  VOLUME_MOVE: 'Volume을 다른 서버로 옮기는 동안 쓰기를 멈춥니다.',
  QUOTA: '작업 공간 할당량이 남지 않아 새 컨테이너를 먼저 띄울 수 없습니다.',
};

export function interruptionText(code: string): string {
  return INTERRUPTION[code] ?? code;
}

export function applyWay(c: PlanChange): ApplyWay {
  switch (c.action) {
    case 'Create':
      return 'create';
    case 'Keep':
      return 'keep';
    case 'Remove':
      return 'remove';
    case 'RuntimeUpdate':
      return 'inplace';
    case 'MoveRequired':
      return 'move';
    case 'Replace':
      return c.interruption ? 'interrupt' : 'seamless';
    default:
      return 'other';
  }
}

/** 그대로인 항목을 빼고 센다. 미리보기 머리의 요약 */
export function applySummary(changes: PlanChange[]): { way: ApplyWay; count: number }[] {
  const n = new Map<ApplyWay, number>();
  for (const c of changes) {
    const w = applyWay(c);
    if (w !== 'keep') n.set(w, (n.get(w) ?? 0) + 1);
  }
  const order: ApplyWay[] = ['inplace', 'seamless', 'interrupt', 'move', 'create', 'remove', 'other'];
  return order.filter((w) => n.has(w)).map((w) => ({ way: w, count: n.get(w)! }));
}
