// SPDX-License-Identifier: Apache-2.0

// 화면 폭 구간 (캔버스 UI-M0, v135). 768px 이상은 데스크톱 화면 그대로(좁아지면 데스크톱 배치 규칙대로 줄어듦), 767px 이하는 휴대폰 틀.
import { useSyncExternalStore } from 'react';

export type Viewport = 'desktop' | 'phone';
const PHONE = '(max-width: 767px)';

function current(): Viewport {
  if (typeof window === 'undefined' || !window.matchMedia) return 'desktop';
  return window.matchMedia(PHONE).matches ? 'phone' : 'desktop';
}

function subscribe(cb: () => void) {
  if (typeof window === 'undefined' || !window.matchMedia) return () => undefined;
  const m = window.matchMedia(PHONE);
  m.addEventListener('change', cb);
  return () => m.removeEventListener('change', cb);
}

export function useViewport(): Viewport {
  return useSyncExternalStore(subscribe, current, () => 'desktop');
}
export const usePhone = () => useViewport() === 'phone';
