// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef } from 'react';
import { NavLink, useLocation } from 'react-router-dom';

/** 화면 안 구역 전환은 모두 이 탭으로 한다(라벨 모양 segmented는 거르기·보기 방식에만). 탭마다 주소가 달라 새로고침·링크 공유가 된다. 최대 2단계(sub).
 *  current를 주면 주소 비교 대신 그 값으로 지금 탭을 정한다(?tab= 같은 쿼리로 나눈 탭). 탭 줄이 넘치면 지금 탭이 보이게 옆으로 민다 (캔버스 UI-M1 v136). */
export function Tabs({ items, sub = false, label }: { items: { to: string; label: string; end?: boolean; active?: boolean; current?: boolean }[]; sub?: boolean; label: string }) {
  const ref = useRef<HTMLElement>(null);
  const path = useLocation().pathname;
  useEffect(() => {
    const nav = ref.current;
    const on = nav?.querySelector<HTMLElement>('a.active');
    if (!nav || !on || nav.scrollWidth <= nav.clientWidth) return;
    nav.scrollLeft = Math.max(0, on.offsetLeft - (nav.clientWidth - on.offsetWidth) / 2);
  }, [path]);
  return (
    <nav ref={ref} className={`tabs ${sub ? 'sub' : ''}`} aria-label={label}>
      {items.map((t) => (
        <NavLink key={t.to} to={t.to} end={t.end ?? true} className={({ isActive }) => ((t.current ?? (isActive || t.active)) ? 'active' : '')}>
          {t.label}
        </NavLink>
      ))}
    </nav>
  );
}
