// SPDX-License-Identifier: Apache-2.0

// 화면 설정 (내 계정 › 화면 설정, 캔버스 v215): 계정별로 웹 앱 데이터(GET/PUT /prefs)에 저장해 다른 브라우저에서도 같다.
// /prefs는 계정별 JSON 하나라, 다른 키를 지우지 않게 읽은 값에 덮어 쓴다(revision 없음, 마지막에 쓴 값이 이김).
import { api } from '../api/client';

export interface UiPrefs {
  /** IANA 시간대. 비면 브라우저 시간대 */
  timeZone?: string;
  /** 화면 밝기(캔버스 v224 DarkTheme). 기본은 시스템 설정 따름 */
  theme?: 'system' | 'light' | 'dark';
  /** 자동 갱신 기본 주기(초). 0 = 멈춤 */
  pollSeconds?: number;
  density?: 'normal' | 'compact';
  /** 대시보드 시작하기 카드를 숨김(캔버스 v224 StartSearch) */
  hideStart?: boolean;
}

export const DEFAULT_PREFS: Required<Omit<UiPrefs, 'timeZone'>> & { timeZone: string } = { timeZone: '', theme: 'system', pollSeconds: 30, density: 'normal', hideStart: false };
export const POLL_SECONDS = [30, 60, 300, 0];
export const pollText = (s: number) => (s === 0 ? '멈춤' : s < 60 ? `${s}초` : `${s / 60}분`);

let current: UiPrefs = {};
/** 지금 적용된 시간대(없으면 undefined = 브라우저 시간대) */
export const prefTimeZone = () => current.timeZone || undefined;
/** 화면이 기본 주기(30초)로 감시할 때 대신 쓸 주기(ms) */
/** 대시보드 시작하기 카드를 숨겼는지 */
export const prefHideStart = () => current.hideStart === true;
export const prefPollMs = () => (current.pollSeconds === undefined ? undefined : current.pollSeconds * 1000);

type Theme = NonNullable<UiPrefs['theme']>;
// 다음에 열 때 로그인 화면부터 깜박이지 않게 고른 밝기만 이 브라우저에 기억한다(비밀 아님)
const THEME_KEY = 'sfc.theme';
let themeMq: MediaQueryList | undefined;
const followSystem = () => {
  document.documentElement.dataset.theme = themeMq?.matches ? 'dark' : 'light';
};
/** 화면 밝기를 적용한다. 'system'이면 운영 체제 설정이 바뀔 때도 따라간다 */
export function applyTheme(t: Theme | undefined) {
  try {
    const want: Theme = t === 'light' || t === 'dark' ? t : 'system';
    themeMq?.removeEventListener('change', followSystem);
    themeMq = undefined;
    if (want === 'system') {
      themeMq = window.matchMedia?.('(prefers-color-scheme: dark)');
      themeMq?.addEventListener('change', followSystem);
      followSystem();
    } else document.documentElement.dataset.theme = want;
    try {
      localStorage.setItem(THEME_KEY, want);
    } catch {
      // 저장소를 막은 브라우저
    }
  } catch {
    // 문서 없이 도는 테스트
  }
}
/** 앱을 열 때: 이 브라우저가 기억한 밝기(없으면 시스템 따름) */
export function applyStoredTheme() {
  let t: string | null = null;
  try {
    t = localStorage.getItem(THEME_KEY);
  } catch {
    t = null;
  }
  applyTheme(t === 'light' || t === 'dark' ? t : 'system');
}

/** 받은 값을 화면에 적용한다: 시간대·기본 갱신 주기는 다음 그리기부터, 표 밀도·밝기는 바로 */
export function applyPrefs(p: UiPrefs) {
  current = { ...p, timeZone: validTimeZone(p.timeZone) };
  try {
    document.documentElement.dataset.density = p.density === 'compact' ? 'compact' : 'normal';
  } catch {
    // 문서 없이 도는 테스트
  }
  applyTheme(p.theme);
}

type Stored = { prefs?: Record<string, unknown> | null };
/** 이 브라우저가 아는 IANA 시간대만 받는다. 모르는 이름이면 시각을 그릴 때마다 RangeError가 나니 버린다 */
export function validTimeZone(tz: unknown): string | undefined {
  if (typeof tz !== 'string' || !tz) return undefined;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return tz;
  } catch {
    return undefined;
  }
}
const pick = (raw: Record<string, unknown>): UiPrefs => ({
  timeZone: validTimeZone(raw.timeZone),
  theme: raw.theme === 'light' || raw.theme === 'dark' || raw.theme === 'system' ? raw.theme : undefined,
  pollSeconds: typeof raw.pollSeconds === 'number' && POLL_SECONDS.includes(raw.pollSeconds) ? raw.pollSeconds : undefined,
  density: raw.density === 'compact' || raw.density === 'normal' ? raw.density : undefined,
  hideStart: typeof raw.hideStart === 'boolean' ? raw.hideStart : undefined,
});

export async function loadPrefs(signal?: AbortSignal): Promise<UiPrefs> {
  const r = await api.get<Stored>('/prefs', signal);
  return pick(r.prefs ?? {});
}

/** 다른 키는 그대로 두고 화면 설정만 바꿔 저장한다 */
export async function savePrefs(p: UiPrefs): Promise<UiPrefs> {
  const r = await api.get<Stored>('/prefs');
  const next = { ...(r.prefs ?? {}), ...p };
  const w = await api.put<Stored>('/prefs', { prefs: next });
  return pick(w.prefs ?? next);
}

/** 이 브라우저가 아는 시간대 목록(없으면 자주 쓰는 몇 개) */
export function timeZones(): string[] {
  const own = Intl.DateTimeFormat().resolvedOptions().timeZone;
  let all: string[] = [];
  try {
    all = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.('timeZone') ?? [];
  } catch {
    all = [];
  }
  if (!all.length) all = ['Asia/Seoul', 'UTC', 'Asia/Tokyo', 'Europe/London', 'America/New_York', 'America/Los_Angeles'];
  return [...new Set([own, ...all])];
}

/** 'Asia/Seoul (UTC+9)' */
export function tzLabel(tz: string): string {
  try {
    const part = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'shortOffset' }).formatToParts(new Date()).find((x) => x.type === 'timeZoneName')?.value ?? '';
    return `${tz} (${part.replace('GMT', 'UTC') || 'UTC'})`;
  } catch {
    return tz;
  }
}
