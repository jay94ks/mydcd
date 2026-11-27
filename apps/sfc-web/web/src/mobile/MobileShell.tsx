// SPDX-License-Identifier: Apache-2.0

// 휴대폰 틀 (캔버스 UI-M0): 위쪽 막대 52px + 아래 탭 5개. 본문은 한 단이고, 데이터·권한·주소는 데스크톱과 같다.
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth, useSession } from '../auth/session';
import { ago, until } from '../lib/format';
import { refreshAll } from '../lib/usePoll';
import { useToast } from '../components/Toast';
import { useCoordinator } from '../components/Coordinator';
import { ReloginDialog } from '../pages/Login';
import { ActionSheet, Sheet } from './Sheet';
import { isTabRoot, isWideOnly, parentOf, titleFor, useMobileTopState } from './top';

// ── 연결 상태: 끊기면 승인 단추를 흐리게 한다 (UI-M7) ──
const OfflineCtx = createContext(false);
export const useOffline = () => useContext(OfflineCtx);

function useConnection() {
  const { disconnected, clearDisconnected } = useAuth();
  const [online, setOnline] = useState(() => (typeof navigator === 'undefined' ? true : navigator.onLine));
  const [since, setSince] = useState<string>();
  const [tries, setTries] = useState(0);
  const off = !online || disconnected;
  useEffect(() => {
    const up = () => setOnline(true);
    const down = () => setOnline(false);
    window.addEventListener('online', up);
    window.addEventListener('offline', down);
    return () => {
      window.removeEventListener('online', up);
      window.removeEventListener('offline', down);
    };
  }, []);
  useEffect(() => {
    if (!off) {
      setSince(undefined);
      setTries(0);
      return;
    }
    setSince((s) => s ?? new Date().toISOString());
    // 다시 연결: 10초마다 세션을 물어 되면 바로 새로 읽는다
    const t = window.setInterval(() => {
      setTries((n) => n + 1);
      api
        .get('/auth/session')
        .then(() => {
          setOnline(true);
          clearDisconnected();
          refreshAll();
        })
        .catch(() => undefined);
    }, 10_000);
    return () => window.clearInterval(t);
  }, [off, clearDisconnected]);
  return { off, since, tries };
}

// ── 끌어 내려 새로 고침 ──
function usePullToRefresh(ref: React.RefObject<HTMLDivElement>) {
  const [pull, setPull] = useState(0);
  const [busy, setBusy] = useState(false);
  const st = useRef<{ y: number; on: boolean }>({ y: 0, on: false });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const start = (e: TouchEvent) => {
      st.current = { y: e.touches[0].clientY, on: el.scrollTop <= 0 };
    };
    const move = (e: TouchEvent) => {
      if (!st.current.on) return;
      const dy = e.touches[0].clientY - st.current.y;
      setPull(dy > 0 ? Math.min(dy, 90) : 0);
    };
    const end = () => {
      if (st.current.on) {
        setPull((p) => {
          if (p >= 60) {
            setBusy(true);
            refreshAll();
            window.setTimeout(() => setBusy(false), 900);
          }
          return 0;
        });
      }
      st.current.on = false;
    };
    el.addEventListener('touchstart', start, { passive: true });
    el.addEventListener('touchmove', move, { passive: true });
    el.addEventListener('touchend', end);
    return () => {
      el.removeEventListener('touchstart', start);
      el.removeEventListener('touchmove', move);
      el.removeEventListener('touchend', end);
    };
  }, [ref]);
  return { pull, busy };
}

const TABS = [
  { to: '/', icon: '⌂', label: '홈' },
  { to: '/notifications', icon: '🔔', label: '알림' },
  { to: '/incidents', icon: '⚑', label: '장애 대응' },
  { to: '/coordinator', icon: '✦', label: '코디네이터' },
  { to: '/more', icon: '☰', label: '더보기' },
];
function tabOf(path: string) {
  if (path === '/' || path === '') return '/';
  for (const t of TABS.slice(1, 4)) if (path === t.to || path.startsWith(`${t.to}/`)) return t.to;
  return '/more';
}

export function MobileShell({ unread, pending, onFind }: { unread: number; pending: number; onFind?: () => void }) {
  const session = useSession();
  const { tenant, expired } = useAuth();
  const loc = useLocation();
  const navigate = useNavigate();
  const top = useMobileTopState();
  const conn = useConnection();
  const body = useRef<HTMLDivElement>(null);
  const { pull, busy } = usePullToRefresh(body);
  const [sheet, setSheet] = useState<'ws' | 'me' | 'menu' | 'relogin'>();
  const path = loc.pathname;
  const root = top?.root ?? isTabRoot(path);
  const wide = isWideOnly(path);
  const tab = tabOf(path);

  // 화면이 바뀌면 맨 위로
  useEffect(() => {
    body.current?.scrollTo({ top: 0 });
    setSheet(undefined);
  }, [path]);
  // 브라우저를 내렸다가 다시 열면 바로 새로 읽는다
  useEffect(() => {
    const vis = () => document.visibilityState === 'visible' && refreshAll();
    document.addEventListener('visibilitychange', vis);
    return () => document.removeEventListener('visibilitychange', vis);
  }, []);

  const back = () => {
    const idx = (window.history.state as { idx?: number } | null)?.idx ?? 0;
    if (idx > 0) navigate(-1);
    else navigate(parentOf(path));
  };
  const soon = new Date(session.expiresAt).getTime() - Date.now() < 10 * 60_000;

  return (
    <OfflineCtx.Provider value={conn.off}>
      <div className="m-shell">
        <header className="m-top">
          {top?.left ?? (!root && (
            <button type="button" className="ic" aria-label="뒤로" onClick={back}>
              ‹
            </button>
          ))}
          <span className="tt">
            {top?.title ?? titleFor(path)}
            <span className="sub">{top?.sub ?? '클러스터'}</span>
          </span>
          {top?.right ??
            (root ? (
              <>
                {onFind && (
                  <button type="button" className="ic" aria-label="전체 찾기" onClick={onFind}>
                    ⌕
                  </button>
                )}
                <button type="button" className="ws" onClick={() => setSheet('ws')} aria-label="작업 공간 고르기">
                  {tenant || '없음'} ▾
                </button>
                <button type="button" className="av" onClick={() => setSheet('me')} aria-label="계정">
                  {session.user.username.slice(0, 1)}
                </button>
              </>
            ) : (
              top?.menu?.length && (
                <button type="button" className="ic" aria-label="더 보기" onClick={() => setSheet('menu')}>
                  ⋯
                </button>
              )
            ))}
        </header>
        {top?.tabs}
        {conn.off && (
          <div className="m-off" role="status">
            <span>연결 끊김 · 다시 연결 중{conn.tries ? ` (${conn.tries}번째)` : ''}</span>
            {conn.since && <span>마지막 보고 {ago(conn.since)}</span>}
          </div>
        )}
        {!conn.off && soon && !expired && (
          <button type="button" className="m-soon" onClick={() => setSheet('relogin')}>
            <b>세션 만료 {until(session.expiresAt)}</b> · 누르면 다시 로그인합니다
          </button>
        )}
        <main className="m-body" id="main" ref={body}>
          {(pull > 0 || busy) && (
            <div className="m-ptr" style={{ height: busy ? 32 : pull / 2 }}>
              <i />
              {busy || pull >= 60 ? '새로 읽는 중' : '끌어 내려 새로 고침'}
            </div>
          )}
          {top?.wide ? (
            <div className="m-wide" style={{ padding: '10px 12px' }}>
              <span>보기만 · {top.wide}</span>
            </div>
          ) : (
            wide && <WideBand />
          )}
          {wide && !top?.wide ? (
            <fieldset className="m-ro" disabled>
              <Outlet />
            </fieldset>
          ) : (
            <Outlet />
          )}
        </main>
        <nav className="m-tabbar" aria-label="아래 탭">
          {TABS.map((t) => {
            const n = t.to === '/notifications' ? unread : t.to === '/incidents' ? pending : 0;
            return (
              <button
                key={t.to}
                type="button"
                className={tab === t.to ? 'on' : ''}
                aria-current={tab === t.to ? 'page' : undefined}
                onClick={() => {
                  // 같은 탭을 다시 누르면 맨 위로 · 하위 화면이면 탭 첫 화면으로
                  if (tab === t.to && path === t.to) body.current?.scrollTo({ top: 0, behavior: 'smooth' });
                  else navigate(t.to);
                }}
              >
                <b aria-hidden>{t.icon}</b>
                {t.label}
                {n > 0 && <em>{n}</em>}
              </button>
            );
          })}
        </nav>
        {sheet === 'ws' && <WorkspaceSheet onClose={() => setSheet(undefined)} />}
        {sheet === 'me' && <AccountSheet onClose={() => setSheet(undefined)} />}
        {sheet === 'relogin' && <ReloginDialog title="다시 로그인" onClose={() => setSheet(undefined)} onLoggedOut={() => navigate('/login')} />}
        {sheet === 'menu' && top?.menu && <ActionSheet title={top.title} items={top.menu} onClose={() => setSheet(undefined)} />}
      </div>
    </OfflineCtx.Provider>
  );
}

/** 넓은 화면에서 열기 띠 (UI-M1 ④) */
function WideBand() {
  const loc = useLocation();
  const navigate = useNavigate();
  const toast = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      toast('주소를 복사했습니다.');
    } catch {
      toast('주소를 복사하지 못했습니다.', 'er');
    }
  };
  return (
    <div className="m-wide">
      <b>이 화면은 넓은 화면에서 고칩니다</b>
      <span>폭이 768px 이상인 화면(태블릿 가로 · PC)에서 같은 주소로 열면 고칠 수 있습니다. 여기서는 지금 내용을 읽기만 합니다.</span>
      <div className="ft">
        <button type="button" className="mbtn sm" onClick={() => void copy()}>
          주소 복사
        </button>
        <button type="button" className="mbtn sm" onClick={() => navigate('/coordinator', { state: { from: loc.pathname } })}>
          ✦ 코디네이터에게 부탁
        </button>
      </div>
    </div>
  );
}

function WorkspaceSheet({ onClose }: { onClose: () => void }) {
  const session = useSession();
  const { tenant, setTenant } = useAuth();
  return (
    <Sheet title="작업 공간" onClose={onClose} closeText>
      <div className="m-rads">
        {session.tenants.length === 0 && <span className="muted">들어갈 수 있는 작업 공간이 없습니다.</span>}
        {session.tenants.map((t) => (
          <button
            key={t.id}
            type="button"
            className="rad"
            aria-pressed={t.id === tenant}
            onClick={() => {
              setTenant(t.id);
              onClose();
            }}
          >
            <i className={t.id === tenant ? 'y' : ''} />
            <span>
              {t.id}
              <small>내 권한: {t.role === 'manager' ? '읽기 · 배포 · 관리' : '읽기'}</small>
            </span>
          </button>
        ))}
      </div>
      <div className="bn info">고르면 바로 바뀌고 시트가 닫힙니다. 알림·장애 대응·작업 기록도 고른 작업 공간만 보입니다.</div>
    </Sheet>
  );
}

function AccountSheet({ onClose }: { onClose: () => void }) {
  const session = useSession();
  const { logout } = useAuth();
  const navigate = useNavigate();
  return (
    <ActionSheet
      title={session.user.username}
      onClose={onClose}
      items={[
        { label: `세션 만료 ${until(session.expiresAt)}`, sub: session.user.systemAdmin ? '시스템 관리자' : undefined },
        { label: '계정', onSelect: () => navigate('/account') },
        {
          label: '로그아웃',
          danger: true,
          onSelect: () => {
            void logout().then(() => navigate('/login'));
          },
        },
      ]}
    />
  );
}

/** 탭 첫 화면 공통: 위쪽 막대 아래 본문 */
export function MSection({ title, link, children }: { title: ReactNode; link?: ReactNode; children?: ReactNode }) {
  return (
    <>
      <div className="m-sec">
        <span>{title}</span>
        {link}
      </div>
      {children}
    </>
  );
}

/** 코디네이터 패널은 휴대폰에서 탭이 되므로, 패널을 열려던 동작은 코디네이터 탭으로 옮긴다 */
export function useOpenCoordinatorTab() {
  const navigate = useNavigate();
  const loc = useLocation();
  const { setOpen } = useCoordinator();
  return () => {
    setOpen(false);
    navigate('/coordinator', { state: { from: loc.pathname } });
  };
}
