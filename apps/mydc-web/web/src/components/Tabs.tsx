// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef } from 'react';
import { NavLink, useLocation } from 'react-router-dom';

/** 탭마다 주소가 달라 새로고침·링크 공유가 된다. 최대 2단계. 탭 줄이 넘치면 지금 탭이 보이게 옆으로 민다 (캔버스 UI-M1 v136). */
export function Tabs({ items, sub = false, label }: { items: { to: string; label: string; end?: boolean; active?: boolean }[]; sub?: boolean; label: string }) {
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
        <NavLink key={t.to} to={t.to} end={t.end ?? true} className={({ isActive }) => (isActive || t.active ? 'active' : '')}>
          {t.label}
        </NavLink>
      ))}
    </nav>
  );
}
