// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';
import { reconnectLive, useLiveStatus, type LiveStatus } from '../lib/live';
import { refreshAll } from '../lib/usePoll';

const hhmmss = (d?: Date) => (d ? d.toLocaleTimeString('ko-KR', { hour12: false }) : '');

const dot = (color: string) => <i aria-hidden style={{ width: 8, height: 8, borderRadius: 4, background: color, display: 'block' }} />;

function tip(s: LiveStatus): string {
  const last = s.lastChange ? `${hhmmss(s.lastChange)}에 마지막 변경 받음` : '아직 받은 변경 없음';
  const head = s.state === 'live' ? '연결됨' : s.state === 'down' ? '연결 안 됨' : '다시 잇는 중';
  return `${head} · ${last}\n끊기면 1·2·4·8초…최대 30초 간격으로 다시 잇습니다`;
}

/** 위 막대의 실시간 연결 표시 (캔버스 ㉟). 세션 만료 앞에 둔다. */
export function LiveIndicator() {
  const s = useLiveStatus();
  if (s.state === 'off') return null;
  if (s.state === 'live')
    return (
      <span className="meta" title={tip(s)} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        {dot('#3FB950')}실시간
      </span>
    );
  if (s.state === 'retrying')
    return (
      <span className="meta" title={tip(s)} role="status" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        {dot('#D29922')}실시간 연결 끊김 · 다시 잇는 중{s.retryIn ? ` (${s.retryIn}초 뒤)` : ''}
      </span>
    );
  return (
    <>
      <span className="meta" title={tip(s)} role="status" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        {dot('#F85149')}실시간 연결 안 됨
      </span>
      <button type="button" className="live-retry" onClick={reconnectLive}>
        다시 잇기
      </button>
    </>
  );
}

/** 10초 넘게 끊기면 화면 맨 위에 한 번 띄우는 띠 (캔버스 ㉟) */
export function LiveBand() {
  const s = useLiveStatus();
  const [, tick] = useState(0);
  const away = s.state === 'retrying' || s.state === 'down';
  useEffect(() => {
    if (!away) return;
    const t = window.setTimeout(() => tick((x) => x + 1), 10_500);
    return () => window.clearTimeout(t);
  }, [away, s.since]);
  if (!away || !s.since || Date.now() - s.since.getTime() < 10_000) return null;
  return (
    <div className="banner-live" role="alert">
      실시간 연결이 끊겨 {hhmmss(s.since)} 이후 바뀐 것이 보이지 않을 수 있습니다. 다시 이으면 놓친 변경을 한 번에 다시 읽습니다.{' '}
      <button type="button" className="btn sm" onClick={refreshAll}>
        지금 다시 읽기
      </button>
    </div>
  );
}
