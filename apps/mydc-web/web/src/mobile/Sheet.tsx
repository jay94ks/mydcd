// SPDX-License-Identifier: Apache-2.0

// 아래 시트 · 동작 시트 (캔버스 UI-M1 ②③). 바깥을 누르거나 아래로 끌면 닫힌다(= 취소).
import { useEffect, useId, useRef, type ReactNode } from 'react';

export function Sheet({
  title,
  onClose,
  children,
  footer,
  danger = false,
  closeText = false,
  className = '',
}: {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  danger?: boolean;
  /** 머리 오른쪽에 '닫기' 글자 (동작 시트 · 고르기 시트) */
  closeText?: boolean;
  className?: string;
}) {
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  const drag = useRef<{ y: number; dy: number } | null>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.querySelector<HTMLElement>('input, select, textarea')?.focus();
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      prev?.focus?.();
    };
  }, [onClose]);
  const start = (e: React.TouchEvent) => {
    drag.current = { y: e.touches[0].clientY, dy: 0 };
  };
  const move = (e: React.TouchEvent) => {
    if (!drag.current || !ref.current) return;
    const dy = Math.max(0, e.touches[0].clientY - drag.current.y);
    drag.current.dy = dy;
    ref.current.style.transform = `translateY(${dy}px)`;
  };
  const end = () => {
    const d = drag.current;
    drag.current = null;
    if (!ref.current) return;
    ref.current.style.transform = '';
    if (d && d.dy > 80) onClose();
  };
  return (
    <>
      <div className="m-ov" onClick={onClose} />
      <div ref={ref} className={`m-sheet ${className}${danger ? ' danger' : ''}`} role="dialog" aria-modal="true" aria-labelledby={id}>
        <div className="m-grip-zone" onTouchStart={start} onTouchMove={move} onTouchEnd={end}>
          <div className="m-grip" />
          <header>
            <span id={id}>{title}</span>
            {closeText && (
              <button type="button" className="m-close" onClick={onClose}>
                닫기
              </button>
            )}
          </header>
        </div>
        <div className="m-sbody">{children}</div>
        {footer ? <footer>{footer}</footer> : <div className="m-sfoot-pad" />}
      </div>
    </>
  );
}

export interface ActionItem {
  label: string;
  onSelect?: () => void;
  /** 위험한 항목 · 맨 아래 빨강 */
  danger?: boolean;
  /** 모바일에서 안 되는 항목: '넓은 화면에서'라고 적는다 */
  wide?: boolean;
  sub?: string;
}

export function ActionSheet({ title, items, onClose }: { title: ReactNode; items: ActionItem[]; onClose: () => void }) {
  const sorted = [...items.filter((i) => !i.danger), ...items.filter((i) => i.danger)];
  return (
    <Sheet title={title} onClose={onClose} closeText className="as">
      <div className="m-as">
        {sorted.map((it) => (
          <button
            key={it.label}
            type="button"
            className={it.danger ? 'red' : ''}
            onClick={() => {
              onClose();
              it.onSelect?.();
            }}
          >
            {it.label}
            {(it.wide || it.sub) && <span className="sub">{it.wide ? '넓은 화면에서' : it.sub}</span>}
          </button>
        ))}
      </div>
    </Sheet>
  );
}
