// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState, type ReactNode } from 'react';

/** 버튼 아래에 뜨는 작은 상자. 바깥을 누르거나 Esc·스크롤이면 닫힌다. 표 칸 안에서도 잘리지 않게 화면 기준으로 띄운다 */
export function Popover({ button, label, className = 'btn sm', align = 'left', width, disabled, title, children }: { button: ReactNode; label?: string; className?: string; align?: 'left' | 'right'; width?: number; disabled?: boolean; title?: string; children: (close: () => void) => ReactNode }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top?: number | 'auto'; bottom?: number; left?: number; right?: number }>();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    const away = (e: Event) => !ref.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', esc);
    window.addEventListener('scroll', away, true);
    window.addEventListener('resize', away);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', esc);
      window.removeEventListener('scroll', away, true);
      window.removeEventListener('resize', away);
    };
  }, [open]);
  return (
    <div className="menu-wrap" ref={ref}>
      <button
        type="button"
        className={className}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-label={label}
        disabled={disabled}
        title={title}
        onClick={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          // 화면 아래쪽이면 위로 띄운다
          const v = r.bottom > window.innerHeight * 0.6 ? { top: 'auto' as const, bottom: window.innerHeight - r.top + 4 } : { top: r.bottom + 4 };
          setPos(align === 'left' ? { ...v, left: Math.max(8, Math.min(r.left, window.innerWidth - (width ?? 240) - 8)) } : { ...v, right: window.innerWidth - r.right });
          setOpen((o) => !o);
        }}
      >
        {button}
      </button>
      {open && (
        <div className="menu popbox" role="dialog" aria-label={label} style={{ position: 'fixed', ...pos, width }}>
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  );
}
