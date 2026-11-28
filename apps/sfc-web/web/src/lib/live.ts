// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';
import { API_MODE, apiEvents } from '../api/client';

/**
 * 실시간 반영 (devel/design/web-live-updates.md, docs/reference/web-api/56-live.md).
 * 로그인한 탭마다 WebSocket 하나(/api/v1/live)로 바뀐 기록의 참조를 받는다.
 * 내용은 오지 않는다: 그 참조가 가리키는 항목만 화면이 다시 읽는다. 시계로 다시 읽지 않는다.
 */

export interface LiveRef {
  kind: string;
  tenant?: string;
  name: string;
  deleted?: boolean;
  /** 서버 보고(kind node-observation): 관측 종류와 그 관측이 속한 앱 */
  source?: string;
  app?: string;
  /** 엔진 사건(kind engine.container·engine.node): 컨테이너 ID와, 쉼표로 이은 다시 읽을 까닭 */
  container?: string;
  reasons?: string;
}

type Frame = { type: 'changes'; index: number; resync?: boolean; refs?: LiveRef[] } | { type: 'state'; state: 'live' | 'reconnecting' } | { type: 'error'; code: string };

export interface LiveStatus {
  /** off: 목업 계층(소켓 없음) · live: 이어짐 · retrying: 다시 잇는 중 · down: 여러 번 실패 */
  state: 'off' | 'live' | 'retrying' | 'down';
  /** retrying일 때 다음 시도까지 남은 초 */
  retryIn?: number;
  /** 마지막으로 바뀐 것을 받은 시각 */
  lastChange?: Date;
  /** 끊긴 시각 (이어지면 없음) */
  since?: Date;
}

interface Listener {
  match: (r: LiveRef) => boolean;
  onRefs: (refs: LiveRef[]) => void;
  onResync: () => void;
}

const DOWN_AFTER = 5; // 이만큼 잇따라 실패하면 빨강 + 다시 잇기
const RETRY_MAX = 30_000;

let socket: WebSocket | undefined;
let lastIndex = 0;
let failures = 0;
let retryTimer: number | undefined;
let countdown: number | undefined;
let wanted = false;
let status: LiveStatus = { state: API_MODE === 'mock' ? 'off' : 'retrying' };
/**
 * 몰림(burst) 대비: 화면마다 참조를 GATHER_MS 동안 모아 한 번에 넘긴다. 첫 참조에서 시계가 시작하고
 * 늘어나지 않으므로, 사건이 끊이지 않아도 GATHER_MS마다 한 번씩은 반영된다. resync가 끼면 모은 참조는 버리고
 * 한 번 다시 읽는다. 여러 화면이 한꺼번에 다시 읽게 되면 RESYNC_BATCH개씩 RESYNC_STEP_MS 간격으로 나눠 부른다.
 */
export const GATHER_MS = 300;
const RESYNC_BATCH = 4;
const RESYNC_STEP_MS = 150;

interface Pending {
  refs: LiveRef[];
  resync: boolean;
  timer?: ReturnType<typeof setTimeout>;
}
const listeners = new Map<Listener, Pending>();
let resyncQueue: Listener[] = [];
let resyncTimer: ReturnType<typeof setTimeout> | undefined;

// 한 번에 RESYNC_BATCH개를 부르고 RESYNC_STEP_MS를 쉰다. 쉬는 동안 온 것은 다음 차례로 간다.
function runResyncs() {
  resyncTimer = undefined;
  const now = resyncQueue.splice(0, RESYNC_BATCH);
  if (!now.length) return;
  for (const l of now) if (listeners.has(l)) l.onResync();
  resyncTimer = setTimeout(runResyncs, RESYNC_STEP_MS);
}

function flush(l: Listener) {
  const p = listeners.get(l);
  if (!p) return;
  const { refs, resync } = p;
  listeners.set(l, { refs: [], resync: false });
  if (resync) {
    if (!resyncQueue.includes(l)) resyncQueue.push(l);
    if (resyncTimer === undefined) resyncTimer = setTimeout(runResyncs, 0);
  } else if (refs.length) l.onRefs(refs);
}

function gather(l: Listener, refs: LiveRef[] | 'resync') {
  const p = listeners.get(l);
  if (!p) return;
  if (refs === 'resync') {
    p.resync = true;
    p.refs = [];
  } else if (!p.resync) {
    // 같은 참조는 하나로 (뒤의 deleted가 이긴다)
    for (const r of refs) {
      const at = p.refs.findIndex((x) => x.kind === r.kind && x.tenant === r.tenant && x.name === r.name && x.source === r.source && x.app === r.app);
      if (at >= 0) p.refs[at] = r;
      else p.refs.push(r);
    }
  }
  if (p.timer === undefined) p.timer = setTimeout(() => flush(l), GATHER_MS);
}
const watchers = new Set<(s: LiveStatus) => void>();

function setStatus(s: Partial<LiveStatus>) {
  status = { ...status, ...s };
  for (const w of watchers) w(status);
}

function deliver(refs: LiveRef[]) {
  for (const l of listeners.keys()) {
    const mine = refs.filter(l.match);
    if (mine.length) gather(l, mine);
  }
}

function resyncAll() {
  for (const l of listeners.keys()) gather(l, 'resync');
}

function scheduleRetry() {
  if (!wanted) return;
  failures++;
  const delay = Math.min(1000 * 2 ** Math.min(failures - 1, 5), RETRY_MAX);
  const at = Date.now() + delay;
  const down = failures >= DOWN_AFTER;
  setStatus({ state: down ? 'down' : 'retrying', retryIn: Math.ceil(delay / 1000), since: status.since ?? new Date() });
  window.clearInterval(countdown);
  countdown = window.setInterval(() => setStatus({ retryIn: Math.max(0, Math.ceil((at - Date.now()) / 1000)) }), 1000);
  retryTimer = window.setTimeout(open, delay);
}

function open() {
  window.clearTimeout(retryTimer);
  window.clearInterval(countdown);
  if (!wanted || socket) return;
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/api/v1/live${lastIndex ? `?from=${lastIndex}` : ''}`);
  socket = ws;
  let ended = false;
  ws.onmessage = (ev) => {
    let f: Frame;
    try {
      f = JSON.parse(String(ev.data)) as Frame;
    } catch {
      return;
    }
    if (f.type === 'state') {
      if (f.state === 'live') {
        failures = 0;
        setStatus({ state: 'live', retryIn: undefined, since: undefined });
        // 웹 데몬이 sfcd를 다시 보고 있다: 끊김 띠가 떠 있으면 앱 셸이 곧바로 다시 확인한다
        apiEvents.dispatchEvent(new Event('live'));
      } else setStatus({ state: 'retrying', retryIn: undefined, since: status.since ?? new Date() });
      return;
    }
    if (f.type === 'error') {
      // 로그인이 끝난 것만 멈춘다(재로그인 다이얼로그가 맡고, 다시 로그인하면 앱 셸이 새로 연다).
      // 다른 오류는 소켓이 닫힌 뒤 보통처럼 간격을 두고 다시 잇는다.
      if (f.code === 'session-expired') {
        ended = true;
        wanted = false;
        apiEvents.dispatchEvent(new Event('session-expired'));
      }
      return;
    }
    if (f.type !== 'changes') return;
    const first = lastIndex === 0;
    lastIndex = f.index;
    if (f.resync) {
      setStatus({ lastChange: new Date() });
      resyncAll();
    } else if (f.refs?.length) {
      setStatus({ lastChange: new Date() });
      deliver(f.refs);
    } else if (first) {
      // 시작점: 화면이 소켓보다 먼저 읽었으면 그 사이 바뀐 것을 놓쳤을 수 있으니 한 번 다시 읽는다
      resyncAll();
    }
  };
  ws.onclose = () => {
    if (socket === ws) socket = undefined;
    if (ended || !wanted) {
      setStatus({ state: 'down', retryIn: undefined, since: status.since ?? new Date() });
      return;
    }
    scheduleRetry();
  };
}

/** 망이 돌아오거나 탭이 다시 보이면 기다리던 간격을 건너뛰고 지금 다시 잇는다 */
function wake() {
  if (wanted && !socket && document.visibilityState !== 'hidden') {
    failures = 0;
    open();
  }
}

/** 앱 셸이 로그인 동안 부른다. 돌려준 함수로 닫는다. */
export function startLive(): () => void {
  if (API_MODE === 'mock') return () => {};
  wanted = true;
  failures = 0;
  open();
  window.addEventListener('online', wake);
  document.addEventListener('visibilitychange', wake);
  return () => {
    wanted = false;
    window.removeEventListener('online', wake);
    document.removeEventListener('visibilitychange', wake);
    window.clearTimeout(retryTimer);
    window.clearInterval(countdown);
    socket?.close();
    socket = undefined;
  };
}

/** '다시 잇기': 기다리지 않고 지금 다시 잇는다 */
export function reconnectLive() {
  if (API_MODE === 'mock') return;
  wanted = true;
  failures = 0;
  if (!socket) open();
}

/** 화면이 자기 주제의 참조를 받는다. 돌려준 함수로 그만 받는다. */
export function subscribeLive(l: Listener): () => void {
  listeners.set(l, { refs: [], resync: false });
  return () => {
    clearTimeout(listeners.get(l)?.timer);
    listeners.delete(l);
  };
}

export const liveAvailable = () => API_MODE !== 'mock';

export function useLiveStatus(): LiveStatus {
  const [s, set] = useState(status);
  useEffect(() => {
    watchers.add(set);
    set(status);
    return () => {
      watchers.delete(set);
    };
  }, []);
  return s;
}

/** 시험용: 상태를 처음으로 */
export function resetLiveForTest() {
  wanted = false;
  socket = undefined;
  lastIndex = 0;
  failures = 0;
  for (const p of listeners.values()) clearTimeout(p.timer);
  listeners.clear();
  clearTimeout(resyncTimer);
  resyncTimer = undefined;
  resyncQueue = [];
  status = { state: API_MODE === 'mock' ? 'off' : 'retrying' };
}

/** 시험용: 소켓 없이 참조·resync를 넣는다 */
export const liveTestHooks = { deliver, resyncAll, wake };
