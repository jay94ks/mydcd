// SPDX-License-Identifier: Apache-2.0

import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { usePhone } from '../lib/viewport';
import { Sheet } from '../mobile/Sheet';

export function Dialog({
  title,
  onClose,
  children,
  footer,
  width = 560,
  danger = false,
}: {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: 420 | 560 | 720;
  danger?: boolean;
}) {
  // 휴대폰에서는 아래 시트 (UI-M1 ③): 내용만큼 높이, 단추는 아래에 가로로 꽉 차게
  if (usePhone())
    return (
      <Sheet title={title} onClose={onClose} footer={footer} danger={danger}>
        {children}
      </Sheet>
    );
  return <DesktopDialog title={title} onClose={onClose} footer={footer} width={width} danger={danger}>{children}</DesktopDialog>;
}

function DesktopDialog({
  title,
  onClose,
  children,
  footer,
  width,
  danger,
}: {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width: 420 | 560 | 720;
  danger: boolean;
}) {
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>('input, select, textarea, button:not(.x)');
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    ref.current?.addEventListener('keydown', onKey);
    const el = ref.current;
    return () => {
      el?.removeEventListener('keydown', onKey);
      prev?.focus?.();
    };
  }, [onClose]);
  return (
    <div className="backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} className={`dialog w${width}`} role="dialog" aria-modal="true" aria-labelledby={id}>
        <header className={danger ? 'danger' : ''}>
          <h2 id={id}>{title}</h2>
          <button type="button" className="x" aria-label="닫기" onClick={onClose}>
            ×
          </button>
        </header>
        <div className="dbody">{children}</div>
        {footer && <footer>{footer}</footer>}
      </div>
    </div>
  );
}

/** 되돌릴 수 없는 변경: 빨간 띠 + 대상 이름 재입력 */
export function ConfirmDialog({
  title,
  target,
  children,
  actionLabel,
  onConfirm,
  onClose,
  busy,
}: {
  title: string;
  target: string;
  children: ReactNode;
  actionLabel: string;
  onConfirm: () => void;
  onClose: () => void;
  busy?: boolean;
}) {
  const [typed, setTyped] = useState('');
  return (
    <Dialog
      title={title}
      onClose={onClose}
      danger
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn danger solid" disabled={typed !== target || busy} onClick={onConfirm}>
            {busy ? '보내는 중…' : actionLabel}
          </button>
        </>
      }
    >
      {children}
      <label className="field">
        <span>
          확인을 위해 <code>{target}</code>을(를) 그대로 입력하세요.
        </span>
        <input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
      </label>
    </Dialog>
  );
}
