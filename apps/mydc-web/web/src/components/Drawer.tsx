// SPDX-License-Identifier: Apache-2.0

import { useEffect, type ReactNode } from 'react';
import { usePhone } from '../lib/viewport';

export function Drawer({ title, onClose, children }: { title: ReactNode; onClose: () => void; children: ReactNode }) {
  const phone = usePhone();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  // 휴대폰에서는 전체 화면 하위 화면 (‹ 뒤로) (UI-M1)
  if (phone)
    return (
      <aside className="m-sub" role="complementary" aria-label="상세">
        <header className="m-top">
          <button type="button" className="ic" aria-label="뒤로" onClick={onClose}>
            ‹
          </button>
          <span className="tt">{title}</span>
        </header>
        <div className="m-body">{children}</div>
      </aside>
    );
  return (
    <aside className="drawer" role="complementary" aria-label="상세">
      <header>
        <b style={{ fontSize: 15 }}>{title}</b>
        <button type="button" className="x" aria-label="닫기" onClick={onClose}>
          ×
        </button>
      </header>
      <div className="dbody">{children}</div>
    </aside>
  );
}
