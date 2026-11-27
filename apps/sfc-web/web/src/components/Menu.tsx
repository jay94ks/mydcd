// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';

export interface MenuItem {
  label: string;
  onSelect?: () => void;
  danger?: boolean;
  /** 권한 없는 항목은 숨기지 않고 흐리게 + 이유 */
  disabledReason?: string;
  sep?: boolean;
  /** 항목 옆 작은 설명 */
  hint?: string;
  /** 흐린 항목의 툴팁. 없으면 disabledReason */
  tip?: string;
}

export function Menu({ label = '더보기', items, button, align = 'right', className = 'btn sm' }: { label?: string; items: MenuItem[]; button?: ReactNode; align?: 'left' | 'right'; className?: string }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left?: number; right?: number | 'auto' }>();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', esc);
    const away = (e: Event) => !ref.current?.contains(e.target as Node) && setOpen(false);
    window.addEventListener('scroll', away, true);
    window.addEventListener('resize', away);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', esc);
      window.removeEventListener('scroll', away, true);
      window.removeEventListener('resize', away);
    };
  }, [open]);
  // 위험 항목은 맨 아래
  const sorted = [...items.filter((i) => !i.danger), ...items.filter((i) => i.danger)];
  return (
    <div className="menu-wrap" ref={ref}>
      <button
        type="button"
        className={className}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={label}
        onClick={(e) => {
          // 표 칸(overflow: hidden) 안에서도 잘리지 않게 화면 기준으로 띄운다.
          const r = e.currentTarget.getBoundingClientRect();
          setPos(align === 'left' ? { top: r.bottom + 4, left: r.left, right: 'auto' } : { top: r.bottom + 4, right: window.innerWidth - r.right });
          setOpen((o) => !o);
        }}
      >
        {button ?? '⋯'}
      </button>
      {open && <MenuList items={sorted} style={{ position: 'fixed', ...pos }} onPick={() => setOpen(false)} />}
    </div>
  );
}

function MenuList({ items, style, onPick }: { items: MenuItem[]; style: CSSProperties; onPick: () => void }) {
  return (
    <div className="menu" role="menu" style={style}>
      {items.map((it, i) =>
        it.sep ? (
          <hr key={i} />
        ) : (
          <button
            key={i}
            type="button"
            role="menuitem"
            className={it.danger ? 'danger' : ''}
            aria-disabled={!!it.disabledReason}
            title={it.tip ?? it.disabledReason}
            onClick={() => {
              if (it.disabledReason) return;
              onPick();
              it.onSelect?.();
            }}
          >
            <span>{it.label}</span>
            {(it.disabledReason || it.hint) && <small>{it.disabledReason ?? it.hint}</small>}
          </button>
        ),
      )}
    </div>
  );
}

/** 오른쪽 클릭 메뉴. at은 화면 좌표. 순서는 items 그대로(구분선 포함) */
export function ContextMenu({ at, items, onClose }: { at: { x: number; y: number }; items: MenuItem[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && onClose();
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', esc);
    window.addEventListener('scroll', onClose, true);
    window.addEventListener('resize', onClose);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', esc);
      window.removeEventListener('scroll', onClose, true);
      window.removeEventListener('resize', onClose);
    };
  }, [onClose]);
  return (
    <div ref={ref}>
      <MenuList items={items} style={{ position: 'fixed', top: at.y, left: Math.min(at.x, window.innerWidth - 240) }} onPick={onClose} />
    </div>
  );
}
