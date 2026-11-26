// SPDX-License-Identifier: Apache-2.0

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, apiEvents, ApiError } from '../api/client';
import type { CredentialChallengeReply, CredentialMethod, SessionView } from '../api/types';
import type { DKeyChallenge, DKeyLoginReply, DSession } from '../api/dto';
import { toSession } from '../api/endpoints';
import { clearAllDrafts } from '../lib/drafts';
import { decodeBase64, sign, unlockKey, type StoredKey } from './keystore';
import { checkApproval } from './approval';

interface AuthState {
  session: SessionView | null;
  loading: boolean;
  /** 세션이 만료돼 그 자리 재로그인이 필요한 상태 */
  expired: boolean;
  disconnected: boolean;
  tenant: string;
  setTenant: (t: string) => void;
  refresh: () => Promise<void>;
  loginCredential: (username: string, method: CredentialMethod, secret: string) => Promise<void>;
  loginKey: (key: StoredKey, passphrase: string) => Promise<void>;
  logout: () => Promise<void>;
  clearDisconnected: () => void;
}

const Ctx = createContext<AuthState | null>(null);

const prefKey = (u: string) => `mydc.prefs.${u}.tenant`;
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

  useEffect(() => {
    const onExpired = () => setExpired(true);
    const onDisc = () => setDisconnected(true);
    apiEvents.addEventListener('session-expired', onExpired);
    apiEvents.addEventListener('disconnected', onDisc);
    return () => {
      apiEvents.removeEventListener('session-expired', onExpired);
      apiEvents.removeEventListener('disconnected', onDisc);
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
      // 확인 문구(ticket)는 mydcd 연결에 묶여 있고 연결은 30초 쉬면 닫힌다. 입력을 다 받은 뒤 곧바로 잇는다.
      const ch = await api.post<CredentialChallengeReply>('/auth/credential/challenge', { username, method });
      adopt(toSession(await api.post<DSession>('/auth/credential/login', { ticketId: ch.ticketId, secret })));
    },
    [adopt],
  );

  const loginKey = useCallback(
    async (key: StoredKey, passphrase: string) => {
      // 키를 먼저 풀어 둔다. 확인 문구를 받은 뒤에는 곧바로 서명해 보낸다(연결 30초 제한).
      const priv = await unlockKey(key, passphrase);
      const ch = await api.post<DKeyChallenge>('/auth/key/challenge', { username: key.username, publicKey: key.publicKey });
      // 서명 전에 확인 문구가 고른 계정·키의 것인지 본다.
      if (ch.ticket.username !== key.username) throw new Error('서버가 다른 계정의 확인 문구를 보냈습니다. 서명하지 않았습니다.');
      if (ch.ticket.userKey && ch.ticket.userKey.toLowerCase() !== key.publicKey.toLowerCase()) throw new Error('서버가 다른 키의 확인 문구를 보냈습니다. 서명하지 않았습니다.');
      if (ch.ticket.deadline * 1000 <= Date.now()) throw new Error('확인 문구가 이미 만료됐습니다.');
      // 서명할 원문이 로그인 증명 도메인(mydc-user-key-proof-1\0)인지 본다. 다른 용도의 바이트에는 서명하지 않는다.
      const proof = decodeBase64(ch.proof);
      const domain = new TextEncoder().encode('mydc-user-key-proof-1\0');
      if (proof.length <= domain.length || domain.some((b, i) => proof[i] !== b)) throw new Error('서버가 로그인 증명이 아닌 바이트에 서명을 요청했습니다. 서명하지 않았습니다.');
      const signature = await sign(priv, proof);
      const r = await api.post<DKeyLoginReply | DSession>('/auth/key/login', { ticketId: ch.ticketId, signature });
      // 예전 데몬은 여기서 바로 세션을 준다
      if (!('approve' in r && r.approve)) return adopt(toSession(r as DSession));
      // R02: 발급된 세션을 이 키로 승인한다. 승인 도메인이고 내 키·이 세션의 것인지 본 뒤에만 서명한다.
      const approval = decodeBase64(r.approval);
      checkApproval(approval, key.publicKey, r.sessionDigest);
      const approveSig = await sign(priv, approval);
      adopt(toSession(await api.post<DSession>('/auth/key/approve', { ticketId: r.ticketId, signature: approveSig })));
    },
    [adopt],
  );

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      clearAllDrafts();
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
      clearDisconnected: () => setDisconnected(false),
    }),
    [session, loading, expired, disconnected, tenant, setTenant, refresh, loginCredential, loginKey, logout],
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
