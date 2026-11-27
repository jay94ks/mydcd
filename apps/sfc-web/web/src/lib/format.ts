// SPDX-License-Identifier: Apache-2.0

import { prefTimeZone } from './uiPrefs';

export function fmtBytes(n: number | undefined): string {
  if (n === undefined || n === null || Number.isNaN(n)) return '—';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}

export function pct(used?: number, total?: number): number {
  if (!used || !total) return 0;
  return Math.max(0, Math.min(100, Math.round((used / total) * 100)));
}

export function hhmmss(d: Date | string | undefined): string {
  if (!d) return '—';
  const x = typeof d === 'string' ? new Date(d) : d;
  return x.toLocaleTimeString('ko-KR', { hour12: false, timeZone: prefTimeZone() });
}

/** 'HH:MM' (화면 설정 시간대) */
export function hhmm(d: Date | string | undefined): string {
  if (!d) return '—';
  const x = typeof d === 'string' ? new Date(d) : d;
  return x.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: prefTimeZone() });
}

export function fmtTime(iso: string | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const today = new Date();
  const tz = prefTimeZone();
  const day = (x: Date) => x.toLocaleDateString('en-CA', { timeZone: tz });
  if (day(d) === day(today)) return d.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: tz });
  return d.toLocaleString('ko-KR', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: tz });
}

/** '오늘 07:12' · '어제 22:05' · '11월 25일 22:05' (화면 설정 시간대) */
export function dayTime(iso: string | undefined, now = new Date()): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const tz = prefTimeZone();
  const day = (x: Date) => x.toLocaleDateString('en-CA', { timeZone: tz });
  const hm = d.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: tz });
  if (day(d) === day(now)) return `오늘 ${hm}`;
  if (day(d) === day(new Date(now.getTime() - 86_400_000))) return `어제 ${hm}`;
  return `${d.toLocaleDateString('ko-KR', { month: 'long', day: 'numeric', timeZone: tz })} ${hm}`;
}
export function ago(iso: string | undefined): string {
  if (!iso) return '—';
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 0) return '방금';
  if (s < 60) return `${s}초 전`;
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`;
  return `${Math.floor(s / 86400)}일 전`;
}

export function until(iso: string | undefined): string {
  if (!iso) return '—';
  const s = Math.round((Date.parse(iso) - Date.now()) / 1000);
  if (s <= 0) return '만료됨';
  if (s < 60) return `${s}초 후`;
  return `${Math.floor(s / 60)}분 후`;
}

export function uptime(sec?: number): string {
  if (!sec) return '—';
  if (sec < 3600) return `${Math.floor(sec / 60)}분`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}시간`;
  return `${Math.floor(sec / 86400)}일`;
}

/** 해시·ID 가운데 줄임 */
export function middle(s: string, head = 8, tail = 6): string {
  return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
}
