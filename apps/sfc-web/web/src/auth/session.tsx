// SPDX-License-Identifier: Apache-2.0

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, apiEvents, ApiError, markBackground } from '../api/client';
import { refreshAll } from '../lib/usePoll';
import type { CredentialChallengeReply, CredentialMethod, SessionView } from '../api/types';
import type { DKeyChallenge, DKeyLoginReply, DSession } from '../api/dto';
import { toSession } from '../api/endpoints';
import { clearAllDrafts } from '../lib/drafts';
import { decodeBase64, forgetKey, sign, unlockKey, type StoredKey } from './keystore';
import { checkApproval } from './approval';

interface AuthState {
  session: SessionView | null;
  loading: boolean;
  /** 세션이 만료돼 그 자리 재로그인이 필요한 상태 */
  expired: boolean;
  /** sfcd 연결이 끊긴 상태. 끊긴 동안 스스로 다시 묻고, 되면 저절로 풀린다 */
  disconnected: boolean;
  tenant: string;
  setTenant: (t: string) => void;
  refresh: () => Promise<void>;
  loginCredential: (username: string, method: CredentialMethod, secret: string) => Promise<void>;
  /** username은 이번에 로그인할 사용자. 같은 키를 여러 사용자가 쓸 수 있어 키에 적힌 이름과 다를 수 있다. */
  loginKey: (key: StoredKey, passphrase: string, username: string) => Promise<void>;
  logout: () => Promise<void>;
  /** '다시 확인': 기다리지 않고 지금 sfcd 연결을 묻는다. 되면 풀고 화면을 다시 읽는다 */
  clearDisconnected: () => void;
}

/** 끊긴 뒤 다시 묻는 간격: 2·4·8·16초, 그다음 30초마다 */
export const RECHECK_MS = [2000, 4000, 8000, 16000, 30000];
export const recheckDelay = (tries: number) => RECHECK_MS[Math.min(tries, RECHECK_MS.length - 1)];

const Ctx = createContext<AuthState | null>(null);

// 이 세션을 연 개인키의 공개키(hex). 비밀이 아니라 sessionStorage에 두어 새로고침해도 남고 탭을 닫으면 지워진다.
// 내 계정에서 지금 세션 키를 끌 때 경고에 쓴다.
const SESSION_KEY = 'sfc.session.publicKey';
function setSessionKey(k: string | undefined) {
  try {
    if (k) sessionStorage.setItem(SESSION_KEY, k);
    else sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // 저장소를 못 쓰면 경고만 없다
  }
}
export function currentSessionKey(): string | undefined {
  try {
    return sessionStorage.getItem(SESSION_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

const prefKey = (u: string) => `sfc.prefs.${u}.tenant`;
function readPref(u: string): string {
  try {
    return localStorage.getItem(prefKey(u)) ?? '';
  } catch {
    return '';
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionView | null>(null);
  const [loading, setLoading] = useState(true);
  const [expired, setExpired] = useState(false);
  const [disconnected, setDisconnected] = useState(false);
  const [tenant, setTenantState] = useState('');

  const adopt = useCallback((s: SessionView) => {
    setSession(s);
    setExpired(false);
    const pref = readPref(s.user.username);
    const ids = s.tenants.map((t) => t.id);
    setTenantState((cur) => (cur && ids.includes(cur) ? cur : ids.includes(pref) ? pref : (ids[0] ?? '')));
  }, []);

  const refresh = useCallback(async () => {
    try {
      adopt(toSession(await api.get<DSession>('/auth/session')));
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setSession((cur) => {
          if (cur) setExpired(true);
          return cur;
        });
      }
    } finally {
      setLoading(false);
    }
  }, [adopt]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // sfcd 연결이 끊기면(disconnected) 세션 조회로 다시 묻는다. /auth/session은 sfcd를 거치므로 되면 연결이 돌아온 것이다.
  // 돌아오면 띠를 내리고 모든 화면을 한 번 다시 읽는다. 새로고침하지 않아도 된다.
  const [recheck, setRecheck] = useState(0);
  useEffect(() => {
    if (!disconnected) return;
    let tries = 0;
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const ctl = new AbortController();
    markBackground(ctl.signal);
    const probe = async () => {
      try {
        await api.get('/auth/session', ctl.signal);
        if (stop) return;
        setDisconnected(false);
        refreshAll();
      } catch (e) {
        if (stop || (e as Error).name === 'AbortError') return;
        // 세션이 끝났으면 재로그인 다이얼로그가 맡는다
        if (e instanceof ApiError && e.status === 401) return;
        timer = setTimeout(probe, recheckDelay(++tries));
      }
    };
    timer = setTimeout(probe, recheck ? 0 : recheckDelay(0));
    return () => {
      stop = true;
      clearTimeout(timer);
      ctl.abort();
    };
  }, [disconnected, recheck]);
  const clearDisconnected = useCallback(() => setRecheck((n) => n + 1), []);

  useEffect(() => {
    const onExpired = () => setExpired(true);
    const onDisc = () => setDisconnected(true);
    // 실시간 소켓이 다시 이어졌으면 다음 간격을 기다리지 않고 지금 확인한다
    const onLive = () => setRecheck((n) => n + 1);
    apiEvents.addEventListener('session-expired', onExpired);
    apiEvents.addEventListener('disconnected', onDisc);
    apiEvents.addEventListener('live', onLive);
    return () => {
      apiEvents.removeEventListener('session-expired', onExpired);
      apiEvents.removeEventListener('disconnected', onDisc);
      apiEvents.removeEventListener('live', onLive);
    };
  }, []);

  // 만료 시각이 지나면 서버에 묻기 전에도 재로그인 다이얼로그를 띄운다.
  useEffect(() => {
    if (!session) return;
    const ms = Date.parse(session.expiresAt) - Date.now();
    const t = setTimeout(() => setExpired(true), Math.max(0, Math.min(ms, 2 ** 31 - 1)));
    return () => clearTimeout(t);
  }, [session]);

  const loginCredential = useCallback(
    async (username: string, method: CredentialMethod, secret: string) => {
      // 확인 문구(ticket)는 sfcd 연결에 묶여 있고 연결은 30초 쉬면 닫힌다. 입력을 다 받은 뒤 곧바로 잇는다.
      const ch = await api.post<CredentialChallengeReply>('/auth/credential/challenge', { username, method });
      adopt(toSession(await api.post<DSession>('/auth/credential/login', { ticketId: ch.ticketId, secret })));
      setSessionKey(undefined);
    },
    [adopt],
  );

  const loginKey = useCallback(
    async (key: StoredKey, passphrase: string, username: string) => {
      // 키를 먼저 풀어 둔다. 확인 문구를 받은 뒤에는 곧바로 서명해 보낸다(연결 30초 제한).
      const priv = await unlockKey(key, passphrase);
      try {
        const ch = await api.post<DKeyChallenge>('/auth/key/challenge', { username, publicKey: key.publicKey });
        // 서명 전에 확인 문구가 고른 계정·키의 것인지 본다.
        if (ch.ticket.username !== username) throw new Error('서버가 다른 계정의 확인 문구를 보냈습니다. 서명하지 않았습니다.');
        if (ch.ticket.userKey && ch.ticket.userKey.toLowerCase() !== key.publicKey.toLowerCase()) throw new Error('서버가 다른 키의 확인 문구를 보냈습니다. 서명하지 않았습니다.');
        if (ch.ticket.deadline * 1000 <= Date.now()) throw new Error('확인 문구가 이미 만료됐습니다.');
        // 서명할 원문이 로그인 증명 도메인(sfc-user-key-proof-1\0)인지 본다. 다른 용도의 바이트에는 서명하지 않는다.
        const proof = decodeBase64(ch.proof);
        const domain = new TextEncoder().encode('sfc-user-key-proof-1\0');
        if (proof.length <= domain.length || domain.some((b, i) => proof[i] !== b)) throw new Error('서버가 로그인 증명이 아닌 바이트에 서명을 요청했습니다. 서명하지 않았습니다.');
        const signature = await sign(priv, proof);
        const r = await api.post<DKeyLoginReply | DSession>('/auth/key/login', { ticketId: ch.ticketId, signature });
        // 예전 데몬은 여기서 바로 세션을 준다
        if (!('approve' in r && r.approve)) {
          adopt(toSession(r as DSession));
          setSessionKey(key.publicKey.toLowerCase());
          return;
        }
        // R02: 발급된 세션을 이 키로 승인한다. 승인 도메인이고 내 키·이 세션의 것인지 본 뒤에만 서명한다.
        const approval = decodeBase64(r.approval);
        checkApproval(approval, key.publicKey, r.sessionDigest);
        const approveSig = await sign(priv, approval);
        adopt(toSession(await api.post<DSession>('/auth/key/approve', { ticketId: r.ticketId, signature: approveSig })));
        setSessionKey(key.publicKey.toLowerCase());
      } finally {
        forgetKey(priv);
      }
    },
    [adopt],
  );

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      clearAllDrafts();
      setSessionKey(undefined);
      setSession(null);
      setExpired(false);
    }
  }, []);

  const setTenant = useCallback(
    (t: string) => {
      setTenantState(t);
      if (session) {
        try {
          localStorage.setItem(prefKey(session.user.username), t);
        } catch {
          /* 편의 기능 */
        }
      }
    },
    [session],
  );

  const value = useMemo<AuthState>(
    () => ({
      session,
      loading,
      expired,
      disconnected,
      tenant,
      setTenant,
      refresh,
      loginCredential,
      loginKey,
      logout,
      clearDisconnected,
    }),
    [session, loading, expired, disconnected, tenant, setTenant, refresh, loginCredential, loginKey, logout, clearDisconnected],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error('AuthProvider 밖에서 useAuth를 불렀습니다.');
  return v;
}

/** 로그인된 화면에서만 쓴다. */
export function useSession(): SessionView {
  const { session } = useAuth();
  if (!session) throw new Error('로그인되지 않았습니다.');
  return session;
}

export function useTenantRole(): { tenant: string; canDeploy: boolean; isAdmin: boolean } {
  const { session, tenant } = useAuth();
  const isAdmin = !!session?.user.systemAdmin;
  const role = session?.tenants.find((t) => t.id === tenant)?.role;
  return { tenant, canDeploy: isAdmin || role === 'manager', isAdmin };
}
