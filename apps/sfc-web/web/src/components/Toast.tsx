// SPDX-License-Identifier: Apache-2.0

import { createContext, useCallback, useContext, useState, type ReactNode } from 'react';

interface ToastItem {
  id: number;
  text: ReactNode;
  tone: 'info' | 'er';
}
/** ms: 보이는 시간(기본 6초). 실행 취소 토스트는 10초 */
const Ctx = createContext<(text: ReactNode, tone?: 'info' | 'er', ms?: number) => void>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const push = useCallback((text: ReactNode, tone: 'info' | 'er' = 'info', ms = 6000) => {
    const id = Date.now() + Math.random();
    setItems((x) => [...x, { id, text, tone }]);
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), ms);
  }, []);
  return (
    <Ctx.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`toast ${t.tone === 'er' ? 'er' : ''}`}>
            {t.text}
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export const useToast = () => useContext(Ctx);
