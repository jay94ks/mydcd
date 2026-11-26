// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState, type FormEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/session';
import { ed25519Supported, listKeys, shortKey, type StoredKey } from '../auth/keystore';
import { errorText } from '../components/states';
import { Dialog } from '../components/Dialog';
import { API_MODE, api } from '../api/client';
import { usePhone } from '../lib/viewport';
import { MLogin, offerKey } from '../mobile/MLogin';

export type Method = 'key' | 'password' | 'token';

export function LoginForm({ fixedUser, onDone, phone = false }: { fixedUser?: string; onDone: (info: { method: Method; username: string }) => void; phone?: boolean }) {
  const { loginCredential, loginKey } = useAuth();
  const [supported, setSupported] = useState<boolean>();
  const [keys] = useState<StoredKey[]>(() => listKeys());
  const usable = keys.filter((k) => k.registered && (!fixedUser || k.username === fixedUser));
  const [method, setMethod] = useState<Method>(usable.length ? 'key' : 'password');
  const [username, setUsername] = useState(fixedUser ?? '');
  // 계정을 명시적으로 고른다. 최근 키로 자동 선택하지 않는다.
  const [keyId, setKeyId] = useState(usable.length === 1 && fixedUser ? usable[0].id : '');
  const [secret, setSecret] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  // 키 로그인을 웹 앱 설정에서 껐는지 (세션 없이 읽는다). 못 읽으면 막지 않는다 — 꺼져 있으면 서버가 403으로 거절한다.
  const [keyAllowed, setKeyAllowed] = useState(true);
  useEffect(() => {
    void ed25519Supported().then(setSupported);
    const ac = new AbortController();
    api
      .get<{ credential: boolean; key: boolean }>('/auth/methods', ac.signal)
      .then((m) => {
        if (m.key === false) {
          setKeyAllowed(false);
          setMethod((x) => (x === 'key' ? 'password' : x));
        }
      })
      .catch(() => undefined);
    return () => ac.abort();
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    setBusy(true);
    try {
      if (method === 'key') {
        const key = usable.find((k) => k.id === keyId);
        if (!key) throw new Error('이 브라우저의 키를 골라 주세요.');
        await loginKey(key, secret);
      } else {
        await loginCredential(username, method, secret);
      }
      setSecret('');
      onDone({ method, username: method === 'key' ? (usable.find((k) => k.id === keyId)?.username ?? '') : username });
    } catch (err) {
      const t = errorText(err);
      setError(t.message || t.title);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="col" style={{ gap: 16 }} onSubmit={submit}>
      <div className="segmented" role="radiogroup" aria-label="로그인 방식">
        {(
          [
            ['key', '브라우저 개인키'],
            ['password', '비밀번호'],
            ['token', '토큰'],
          ] as [Method, string][]
        ).map(([m, l]) => (
          <button key={m} type="button" role="radio" aria-checked={method === m} className={method === m ? 'on' : ''} disabled={m === 'key' && !keyAllowed} title={m === 'key' && !keyAllowed ? '관리자가 개인 키 로그인을 꺼 두었습니다' : undefined} onClick={() => (setMethod(m), setError(undefined), setSecret(''))}>
            {l}
          </button>
        ))}
      </div>
      {method === 'key' ? (
        supported === false ? (
          <div className="note wa">이 브라우저는 Ed25519 WebCrypto를 지원하지 않아 개인키 로그인을 쓸 수 없습니다.</div>
        ) : usable.length === 0 ? (
          <div className="note un">
            이 브라우저에 등록된 키가 없습니다. 비밀번호나 토큰으로 로그인한 뒤 '내 계정'에서 이 브라우저의 키를 만들고 등록하세요.
          </div>
        ) : (
          <>
            <label className="field">
              이 브라우저의 키
              <select value={keyId} onChange={(e) => setKeyId(e.target.value)} required>
                <option value="" disabled>
                  계정과 키를 고르세요
                </option>
                {usable.map((k) => (
                  <option key={k.id} value={k.id}>
                    {k.username} · {k.label}
                    {phone ? '' : ` (ed25519 ${shortKey(k.publicKey)})`}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              키 암호 문구
              <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="current-password" required />
            </label>
          </>
        )
      ) : (
        <>
          <label className="field">
            사용자 이름
            <input value={username} onChange={(e) => setUsername(e.target.value)} readOnly={!!fixedUser} autoComplete="username" required />
          </label>
          <label className="field">
            {method === 'password' ? '비밀번호' : '토큰'}
            <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete={method === 'password' ? 'current-password' : 'off'} required />
          </label>
        </>
      )}
      {error && (
        <span className="note er" role="alert">
          {error}
        </span>
      )}
      <button type="submit" className="btn primary" disabled={busy || (method === 'key' && (supported === false || usable.length === 0))}>
        {busy ? '확인 중…' : '로그인'}
      </button>
      {method === 'key' && (
        <p className="small muted" style={{ lineHeight: '18px' }}>
          개인키는 이 브라우저 밖으로 나가지 않습니다. 서버가 보낸 확인 문구에 브라우저가 서명하고, 이후 변경은 이번 세션 키로 서명됩니다.
        </p>
      )}
      {phone && method === 'key' && keyAllowed && supported !== false && (
        <button type="button" className="m-link" onClick={() => (setMethod('password'), setError(undefined), setSecret(''))}>
          키가 없나요? 비밀번호로 로그인 후 등록
        </button>
      )}
    </form>
  );
}

export function LoginPage() {
  const { session, loading } = useAuth();
  const navigate = useNavigate();
  const loc = useLocation();
  const phone = usePhone();
  if (loading) return null;
  const from = (loc.state as { from?: string } | null)?.from ?? '/';
  if (session) {
    // 휴대폰에서 비밀번호·토큰으로 들어왔고 이 브라우저에 키가 없으면 이 브라우저용 키를 권한다 (UI-M2 ②)
    if (phone && session.method !== 'key' && offerKey(session.user.username)) return <Navigate to="/login/key" state={{ from }} replace />;
    return <Navigate to={from} replace />;
  }
  if (phone) return <MLogin onDone={() => undefined} />;
  return (
    <div className="login-wrap">
      <section className="login-card" aria-labelledby="login-title">
        <div className="col" style={{ gap: 6 }}>
          <span id="login-title" style={{ fontSize: 22, fontWeight: 700 }}>
            MyDC
          </span>
          <span className="muted">관리 웹 · 로그인</span>
        </div>
        <LoginForm onDone={() => navigate(from, { replace: true })} />
        <div className="row between small" style={{ borderTop: '1px solid var(--line-2)', paddingTop: 14 }}>
          <span className="muted">최초 관리자 등록은 CLI에서: <code>mydc enroll-admin</code></span>
        </div>
        {API_MODE === 'mock' && (
          <div className="note wa small">
            목업 계층: <code>alice/alice</code>(시스템 관리자), <code>bob/bob</code>(shop 읽기)로 로그인할 수 있습니다.
          </div>
        )}
      </section>
    </div>
  );
}

/** ㉜ 세션 만료: 그 자리에서 다시 로그인하고 하던 입력을 잇는다. */
export function ReloginDialog({ onLoggedOut, title = '세션이 만료됐습니다', onClose }: { onLoggedOut: () => void; title?: string; onClose?: () => void }) {
  const { session, logout } = useAuth();
  return (
    <Dialog
      title={title}
      width={420}
      onClose={onClose ?? (() => undefined)}
      footer={
        <button type="button" className="btn" onClick={() => void logout().then(onLoggedOut)}>
          로그아웃
        </button>
      }
    >
      <p className="small">세션은 최대 1시간입니다. 다시 로그인하면 보던 화면과 입력이 그대로 이어집니다(비밀값 칸 제외). 진행 중이던 작업은 작업 기록에서 결과를 조회할 수 있습니다.</p>
      <LoginForm fixedUser={session?.user.username} onDone={() => onClose?.()} />
    </Dialog>
  );
}
