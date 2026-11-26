// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from 'react';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { API_MODE } from '../api/client';
import { notifications, notifyPrefs } from '../api/endpoints';
import { useAuth, useSession } from '../auth/session';
import { until } from '../lib/format';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { ReloginDialog } from '../pages/Login';
import { MockBar } from './MockBar';
import { CoordinatorPanel, CoordinatorProvider, useCoordinator } from '../components/Coordinator';
import { incidents } from '../api/incidents';
import { nodeShellPolicy } from '../api/nodeShell';
import { useViewport } from '../lib/viewport';
import { MobileShell } from '../mobile/MobileShell';
import { MobileTopProvider } from '../mobile/top';

interface NavItem {
  to: string;
  label: string;
  admin?: boolean;
  /** 서버 셸 권한만 받은 사람(시스템 관리자 아님)에게만 */
  shellOnly?: boolean;
  later?: string;
}
export const NAV: { sect?: string; items: NavItem[] }[] = [
  {
    items: [
      { to: '/', label: '대시보드' },
      { to: '/servers', label: '서버', admin: true },
      { to: '/deploy', label: '배포' },
      { to: '/node-shell', label: '서버 셸', shellOnly: true },
      { to: '/standalone', label: '단독 컨테이너' },
      { to: '/images', label: '이미지 관리' },
      { to: '/incidents', label: '장애 대응' },
    ],
  },
  {
    sect: '공유 자원',
    items: [
      { to: '/shared/networks', label: '망 · 도메인 이름 · 연결' },
      { to: '/shared/ingress', label: '외부 접속' },
      { to: '/shared/volumes', label: '데이터 저장소' },
      { to: '/shared/vault', label: '비밀값 보관함' },
      { to: '/shared/lifecycle', label: '상태 검사' },
    ],
  },
  {
    sect: '시스템',
    items: [
      { to: '/system/tenants', label: '작업 공간' },
      { to: '/system/domains', label: '외부 도메인', admin: true },
      { to: '/system/users', label: '사용자', admin: true },
      { to: '/system/ops', label: '작업 기록' },
      { to: '/system/ai', label: 'AI 설정', admin: true },
      { to: '/system/web', label: '웹 앱 설정', admin: true },
    ],
  },
];

function useNow(ms: number) {
  const [, setT] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setT((x) => x + 1), ms);
    return () => clearInterval(t);
  }, [ms]);
}

/** 알림 설정에서 브라우저 알림을 켰으면, 탭이 열려 있는 동안 새로 온 읽지 않은 알림을 띄운다(웹 푸시 없음). */
function useBrowserNotify(items: { id: string; title: string; text: string }[] | undefined) {
  const seen = useRef<Set<string> | null>(null);
  useEffect(() => {
    if (!items) return;
    const first = seen.current === null;
    const fresh = first ? [] : items.filter((n) => !seen.current!.has(n.id));
    seen.current = new Set([...(seen.current ?? []), ...items.map((n) => n.id)]);
    if (!fresh.length || typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
    void notifyPrefs()
      .then((p) => {
        if (!p.prefs.browser) return;
        for (const n of fresh.slice(0, 3)) new Notification(n.title, { body: n.text, tag: n.id });
      })
      .catch(() => undefined);
  }, [items]);
}

export function AppShell() {
  return (
    <CoordinatorProvider>
      <MobileTopProvider>
        <Shell />
      </MobileTopProvider>
    </CoordinatorProvider>
  );
}

function CoordChip() {
  const { open, setOpen } = useCoordinator();
  const loc = useLocation();
  const full = loc.pathname.startsWith('/coordinator');
  return (
    <button type="button" className={`chip${open && !full ? ' on' : ''}`} aria-pressed={open && !full} onClick={() => setOpen(full ? true : !open)}>
      ✦ 코디네이터
    </button>
  );
}

function Shell() {
  const session = useSession();
  const { tenant, setTenant, expired, disconnected, clearDisconnected } = useAuth();
  const navigate = useNavigate();
  useNow(30_000);
  const notes = usePoll((s) => notifications(s, true, 20), [session.user.username], DEFAULT_POLL_MS);
  const unread = notes.data?.unread ?? 0;
  useBrowserNotify(notes.data?.items);
  const admin = session.user.systemAdmin;
  const vp = useViewport();
  // 서버 셸 권한만 받은 사람에게 '서버 셸' 메뉴. 허용 서버가 0개면(또는 403) 없다
  const shellGrant = usePoll((s) => (admin ? Promise.resolve(0) : nodeShellPolicy(s).then((p) => p.nodes.length).catch(() => 0)), [admin, session.user.username], DEFAULT_POLL_MS);
  // 아래 탭 '장애 대응' 숫자: 승인 대기 사건 수 (휴대폰 틀에서만 읽는다)
  const inc = usePoll((s) => (vp === 'phone' ? incidents({ limit: 1 }, s).catch(() => undefined) : Promise.resolve(undefined)), [vp, session.user.username], DEFAULT_POLL_MS);

  if (vp === 'phone')
    return (
      <div className="m-root">
        {API_MODE === 'mock' && <MockBar />}
        <MobileShell unread={unread} pending={inc.data?.pending ?? 0} />
        {expired && <ReloginDialog onLoggedOut={() => navigate('/login')} />}
      </div>
    );

  return (
    <div className="shell">
      <header className="top">
        <Link to="/" className="brand">
          MyDC
        </Link>
        <span className="cluster">클러스터</span>
        <label>
          작업 공간
          <select value={tenant} onChange={(e) => setTenant(e.target.value)} aria-label="작업 공간 선택">
            {session.tenants.length === 0 && <option value="">없음</option>}
            {session.tenants.map((t) => (
              <option key={t.id} value={t.id}>
                {t.id}
                {t.role === 'viewer' ? ' (읽기)' : ''}
              </option>
            ))}
          </select>
        </label>
        <span className="grow" />
        <Link to="/notifications" className="chip" title={`알림 ${unread}건`} aria-label={`알림, 읽지 않음 ${unread}건`}>
          🔔{unread > 0 && <span className="count">{unread}</span>}
        </Link>
        <CoordChip />
        <span className="meta" title={new Date(session.expiresAt).toLocaleString('ko-KR')}>
          세션 만료 {until(session.expiresAt)}
        </span>
        <Link to="/account" className="user">
          {session.user.username}
        </Link>
      </header>
      {API_MODE === 'mock' && <MockBar />}
      {disconnected && (
        <div className="banner-global" role="alert">
          <b>mydcd 연결이 끊겼습니다.</b> 변경은 잠시 막아 둡니다. 보이는 내용은 마지막으로 읽은 값입니다.
          <button type="button" className="btn sm" onClick={clearDisconnected}>
            다시 확인
          </button>
        </div>
      )}
      <div className="body">
        <nav className="nav" aria-label="주 메뉴">
          {NAV.map((g, i) => (
            <div key={i} style={{ display: 'contents' }}>
              {g.sect && <span className="sect">{g.sect}</span>}
              {g.items
                .filter((it) => (!it.admin || admin) && (!it.shellOnly || (!admin && !!shellGrant.data)))
                .map((it) => (
                  <NavLink key={it.to} to={it.to} end={it.to === '/'} className={({ isActive }) => (isActive ? 'active' : '')}>
                    {it.label}
                    {it.later && <span className="later">{it.later}</span>}
                  </NavLink>
                ))}
            </div>
          ))}
        </nav>
        <main className="main" id="main">
          <div className="page">
            <Outlet />
          </div>
        </main>
        <PanelSlot />
      </div>
      {expired && <ReloginDialog onLoggedOut={() => navigate('/login')} />}
    </div>
  );
}

function PanelSlot() {
  const loc = useLocation();
  return loc.pathname.startsWith('/coordinator') ? null : <CoordinatorPanel />;
}
