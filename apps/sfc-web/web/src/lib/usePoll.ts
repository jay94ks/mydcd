// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from 'react';
import { markBackground } from '../api/client';
import { prefPollMs } from './uiPrefs';
import { liveAvailable, subscribeLive, type LiveRef } from './live';

export const POLL_CHOICES = [
  { ms: 30_000, label: '30초' },
  { ms: 60_000, label: '1분' },
  { ms: 300_000, label: '5분' },
  { ms: 0, label: '멈춤' },
] as const;
export const DEFAULT_POLL_MS = 30_000;
/** 휴대폰 틀에서 끌어 내리기·다시 열기·다시 연결 때 보이는 모든 조회를 바로 다시 읽게 하는 신호 (UI-M7) */
export const REFRESH_ALL = 'sfc:refresh-all';
export const refreshAll = () => window.dispatchEvent(new Event(REFRESH_ALL));

/**
 * 실시간 반영 주제 (lib/live.ts). 주면 시계로 다시 읽지 않고, 맞는 참조가 올 때만 고친다.
 * patch가 있으면 바뀐 항목만 읽어 지금 값에 끼워 넣고(목록), 없으면 그 조회를 한 번 다시 읽는다(항목 하나짜리 조회).
 */
export interface LiveTopic<T> {
  match: (r: LiveRef) => boolean;
  patch?(data: T, refs: LiveRef[], signal: AbortSignal): Promise<T>;
}

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
  /** 실시간 주제로 고쳐지는 조회(주기 없음). 카드 머리가 '실시간 · 기준'으로 보인다 */
  live: boolean;
}

/**
 * 조회 + 주기 감시. interval 0이면 한 번만 읽는다(감시 없음).
 * 다시 읽는 동안 이전 내용을 유지한다(내용 유지 + 진행 표시).
 */
export function usePoll<T>(load: (signal: AbortSignal) => Promise<T>, deps: unknown[], initialInterval = 0, live?: LiveTopic<T>): Loaded<T> {
  // 실시간 주제가 있으면 주기는 없다(목업 계층에는 소켓이 없어 예전처럼 주기로 읽는다)
  if (live && liveAvailable()) initialInterval = 0;
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  const [asOf, setAsOf] = useState<Date>();
  // 기본 주기(30초)로 감시하는 화면은 내 화면 설정의 자동 갱신 주기를 따른다
  const [interval, setIntervalMs] = useState(() => (initialInterval === DEFAULT_POLL_MS ? (prefPollMs() ?? initialInterval) : initialInterval));
  const [tick, setTick] = useState(0);
  // 시계가 부른 다시 읽기는 사람의 활동이 아니다(X-SFC-Background). 처음 읽기·새로고침 버튼은 활동이다.
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

  // 실시간: 맞는 참조가 오면 바뀐 항목만 읽어 고친다. 이어 받을 수 없으면(resync) 한 번 다시 읽는다.
  const liveRef = useRef(live);
  liveRef.current = live;
  const dataRef = useRef(data);
  dataRef.current = data;
  const hasLive = !!live && liveAvailable();
  useEffect(() => {
    if (!hasLive) return;
    const ctl = new AbortController();
    const reload = () => {
      timerTick.current = true;
      setTick((x) => x + 1);
    };
    // 끼워 넣기는 한 번에 하나씩: 하는 중에 온 참조는 끝난 뒤 이어서 한다(뒤의 값이 앞의 값을 덮지 않게)
    let busy = false;
    let queued: LiveRef[] = [];
    const patchNext = () => {
      const patch = liveRef.current?.patch;
      const cur = dataRef.current;
      const refs = queued;
      queued = [];
      if (!refs.length) return;
      if (!patch || cur === undefined) return reload();
      busy = true;
      markBackground(ctl.signal);
      patch(cur, refs, ctl.signal)
        .then((d) => {
          if (ctl.signal.aborted) return;
          dataRef.current = d;
          setData(d);
          setError(undefined);
          setAsOf(new Date());
        })
        .catch((e: unknown) => {
          if (ctl.signal.aborted || (e as Error)?.name === 'AbortError') return;
          queued = [];
          reload();
        })
        .finally(() => {
          busy = false;
          if (!ctl.signal.aborted) patchNext();
        });
    };
    const off = subscribeLive({
      match: (r) => liveRef.current?.match(r) ?? false,
      onResync: () => {
        queued = [];
        reload();
      },
      onRefs: (refs) => {
        queued = queued.concat(refs);
        if (!busy) patchNext();
      },
    });
    return () => {
      off();
      ctl.abort();
    };
  }, [hasLive, depKey]);
  useEffect(() => {
    window.addEventListener(REFRESH_ALL, refresh);
    return () => window.removeEventListener(REFRESH_ALL, refresh);
  }, [refresh]);
  return { data, error, loading, asOf, refresh, interval, setInterval: setIntervalMs, live: hasLive };
}
