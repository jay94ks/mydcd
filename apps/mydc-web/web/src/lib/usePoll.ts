// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from 'react';
import { markBackground } from '../api/client';

export const POLL_CHOICES = [
  { ms: 30_000, label: '30초' },
  { ms: 60_000, label: '1분' },
  { ms: 300_000, label: '5분' },
  { ms: 0, label: '멈춤' },
] as const;
export const DEFAULT_POLL_MS = 30_000;
/** 휴대폰 틀에서 끌어 내리기·다시 열기·다시 연결 때 보이는 모든 조회를 바로 다시 읽게 하는 신호 (UI-M7) */
export const REFRESH_ALL = 'mydc:refresh-all';
export const refreshAll = () => window.dispatchEvent(new Event(REFRESH_ALL));

export interface Loaded<T> {
  data: T | undefined;
  error: unknown;
  loading: boolean;
  /** 마지막으로 성공한 읽기 시각 */
  asOf: Date | undefined;
  /** 즉시 다시 읽고 간격 시계를 다시 센다 */
  refresh: () => void;
  interval: number;
  setInterval: (ms: number) => void;
}

/**
 * 조회 + 주기 감시. interval 0이면 한 번만 읽는다(감시 없음).
 * 다시 읽는 동안 이전 내용을 유지한다(내용 유지 + 진행 표시).
 */
export function usePoll<T>(load: (signal: AbortSignal) => Promise<T>, deps: unknown[], initialInterval = 0): Loaded<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  const [asOf, setAsOf] = useState<Date>();
  const [interval, setIntervalMs] = useState(initialInterval);
  const [tick, setTick] = useState(0);
  // 시계가 부른 다시 읽기는 사람의 활동이 아니다(X-MyDC-Background). 처음 읽기·새로고침 버튼은 활동이다.
  const timerTick = useRef(false);
  const loadRef = useRef(load);
  loadRef.current = load;
  const depKey = JSON.stringify(deps);
  const lastKey = useRef(depKey);

  useEffect(() => {
    const ctl = new AbortController();
    // 의존 값이 바뀌면 이전 대상의 내용은 버린다.
    if (lastKey.current !== depKey) {
      lastKey.current = depKey;
      setData(undefined);
      setError(undefined);
    }
    setLoading(true);
    if (timerTick.current) markBackground(ctl.signal);
    timerTick.current = false;
    loadRef
      .current(ctl.signal)
      .then((d) => {
        if (ctl.signal.aborted) return;
        setData(d);
        setError(undefined);
        setAsOf(new Date());
      })
      .catch((e: unknown) => {
        if (ctl.signal.aborted || (e as Error)?.name === 'AbortError') return;
        setError(e);
      })
      .finally(() => {
        if (!ctl.signal.aborted) setLoading(false);
      });
    return () => ctl.abort();
  }, [depKey, tick]);

  useEffect(() => {
    if (!interval) return;
    const t = window.setTimeout(() => {
      timerTick.current = true;
      setTick((x) => x + 1);
    }, interval);
    return () => window.clearTimeout(t);
  }, [interval, tick, asOf]);

  const refresh = useCallback(() => setTick((x) => x + 1), []);
  useEffect(() => {
    window.addEventListener(REFRESH_ALL, refresh);
    return () => window.removeEventListener(REFRESH_ALL, refresh);
  }, [refresh]);
  return { data, error, loading, asOf, refresh, interval, setInterval: setIntervalMs };
}
