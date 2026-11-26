// SPDX-License-Identifier: Apache-2.0

// 휴대폰 틀의 위쪽 막대 내용 (캔버스 UI-M0 ①). 화면이 제목·부제·⋯ 동작을 알려 주고, 알려 주지 않으면 주소로 정한다.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { ActionItem } from './Sheet';

export interface MobileTop {
  title: ReactNode;
  sub?: ReactNode;
  /** 왼쪽: 기본은 하위 화면이면 ‹ 뒤로 */
  left?: ReactNode;
  /** 오른쪽: 기본은 탭 첫 화면이면 작업 공간·계정, 하위 화면이면 ⋯(menu가 있을 때) */
  right?: ReactNode;
  menu?: ActionItem[];
  /** 아래 탭 첫 화면처럼 작업 공간·계정을 보인다 */
  root?: boolean;
  /** 위쪽 막대에 붙는 가로 탭 */
  tabs?: ReactNode;
  /** 휴대폰 전용 보기만 화면 (UI-M11 ③ ④): 큰 띠 대신 '보기만 · …' 한 줄을 보이고, 화면이 스스로 읽기만 한다 */
  wide?: string;
}

type Level = 'sub' | 'page' | 'auto';
type Ctx = { top?: MobileTop; set: (level: Level, t?: MobileTop) => void };
const TopCtx = createContext<Ctx>({ set: () => undefined });

export function MobileTopProvider({ children }: { children: ReactNode }) {
  const [tops, setTops] = useState<Partial<Record<Level, MobileTop>>>({});
  const set = useCallback((level: Level, t?: MobileTop) => setTops((x) => ({ ...x, [level]: t })), []);
  const v = useMemo(() => ({ top: tops.sub ?? tops.page ?? tops.auto, set }), [tops, set]);
  return <TopCtx.Provider value={v}>{children}</TopCtx.Provider>;
}

export const useMobileTopState = () => useContext(TopCtx).top;

/**
 * 화면이 휴대폰 위쪽 막대를 정한다. deps가 바뀌면 다시 정하고, 화면을 떠나면 지운다.
 * level 'auto'는 PageHeader가 제목만 알려 줄 때 쓰고, 화면이 직접 정한 'page'가 이긴다. 탭 안 하위 화면은 'sub'로 화면 것을 덮는다.
 */
export function useMobileTop(t: MobileTop | undefined, deps: unknown[], level: Level = 'page') {
  const { set } = useContext(TopCtx);
  useEffect(() => {
    set(level, t);
    return () => set(level, undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

// ── 주소 → 제목 (화면이 정하지 않았을 때) ──
const TITLES: [RegExp, string][] = [
  [/^\/$/, '홈'],
  [/^\/notifications/, '알림'],
  [/^\/incidents\/policy/, '장애 대응 정책'],
  [/^\/incidents\/guide/, '행동 지침'],
  [/^\/incidents\/hooks/, '웹훅'],
  [/^\/incidents/, '장애 대응'],
  [/^\/coordinator/, '✦ 코디네이터'],
  [/^\/more/, '더보기'],
  [/^\/more\/shared/, '공유 자원'],
  [/^\/account/, '내 계정'],
  [/^\/servers\/consensus/, '합의'],
  [/^\/servers/, '서버'],
  [/^\/deploy\/new/, '새 앱 배포'],
  [/^\/deploy\/archived/, '보관된 앱'],
  [/^\/deploy/, '배포된 앱'],
  [/^\/standalone/, '단독 컨테이너'],
  [/^\/images/, '이미지 관리'],
  [/^\/shared\/networks/, '망 · 도메인 이름 · 연결'],
  [/^\/shared\/ingress/, '외부 접속'],
  [/^\/shared\/volumes/, '데이터 저장소'],
  [/^\/shared\/vault/, '비밀값 보관함'],
  [/^\/shared\/lifecycle/, '상태 검사'],
  [/^\/system\/tenants/, '작업 공간'],
  [/^\/system\/domains/, '외부 도메인'],
  [/^\/system\/users/, '사용자'],
  [/^\/system\/ops/, '작업 기록'],
  [/^\/system\/audit/, '설정 변경 기록'],
  [/^\/system\/ai/, 'AI 설정'],
  [/^\/system\/web/, '웹 앱 설정'],
  [/^\/system/, '시스템'],
];
export const titleFor = (path: string) => TITLES.find(([re]) => re.test(path))?.[1] ?? 'MyDC';

/** 아래 탭 5개의 첫 화면 */
export const TAB_ROOTS = ['/', '/notifications', '/incidents', '/coordinator', '/more'];
export const isTabRoot = (path: string) => TAB_ROOTS.includes(path.replace(/\/+$/, '') || '/');

/** 하위 화면의 ‹ 뒤로가 갈 곳: 브라우저 기록이 없을 때 쓴다 */
export function parentOf(path: string): string {
  const seg = path.split('/').filter(Boolean);
  if (seg[0] === 'system' || seg[0] === 'shared') return seg.length > 2 ? `/${seg.slice(0, 2).join('/')}` : '/more';
  if (seg[0] === 'deploy' && seg[1] === 'apps') return seg.length > 4 ? `/${seg.slice(0, 4).join('/')}` : '/deploy';
  if (seg.length <= 1) return seg[0] === 'incidents' || seg[0] === 'notifications' ? '/' : '/more';
  return `/${seg.slice(0, -1).join('/')}`;
}

/**
 * 휴대폰에서 보기만 하는 화면 (UI-M1 ④, 계획 문서 '보기만 + 넓은 화면에서 열기').
 * 편집기·마법사·설정·공유 자원·이미지·단독 컨테이너·사용자·작업 공간이다.
 */
const WIDE_ONLY: RegExp[] = [
  /^\/deploy\/new/,
  /^\/deploy\/apps\/[^/]+\/[^/]+\/(edit|place)(\/|$)/,
  /^\/deploy\/apps\/[^/]+\/[^/]+\/c\/[^/]+\/[^/]+\/exec/,
  /^\/standalone/,
  /^\/images/,
  /^\/shared\//,
  /^\/system\/(tenants|domains|users|ai|web)/,
];
export const isWideOnly = (path: string) => WIDE_ONLY.some((re) => re.test(path));
