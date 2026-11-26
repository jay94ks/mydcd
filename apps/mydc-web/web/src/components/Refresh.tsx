// SPDX-License-Identifier: Apache-2.0

import type { Loaded } from '../lib/usePoll';
import { POLL_CHOICES } from '../lib/usePoll';
import { hhmmss } from '../lib/format';

/** 주기 감시 카드 옆: 'HH:MM:SS 기준' · 간격 고르기 · ↻ 새로고침(즉시 읽고 간격 시계를 다시 셈) */
export function Refresh({ q, poll = true }: { q: Loaded<unknown>; poll?: boolean }) {
  return (
    <span className="refresh">
      <span aria-live="polite">{q.asOf ? `${hhmmss(q.asOf)} 기준` : '읽는 중'}</span>
      {poll && (
        <label className="row" style={{ gap: 4 }}>
          <span className="sr-only">자동 갱신 간격</span>
          <select value={q.interval} onChange={(e) => q.setInterval(Number(e.target.value))} aria-label="자동 갱신 간격">
            {POLL_CHOICES.map((c) => (
              <option key={c.ms} value={c.ms}>
                {c.ms ? `${c.label}마다` : c.label}
              </option>
            ))}
          </select>
        </label>
      )}
      <button type="button" className="btn sm" onClick={q.refresh} disabled={q.loading}>
        ↻ 새로고침
      </button>
    </span>
  );
}
