// SPDX-License-Identifier: Apache-2.0

// 휴대폰 로그인 (캔버스 UI-M2). 방식과 문구는 데스크톱 로그인(UI-01)과 같다.
// 개인키는 브라우저마다 따로라서, 휴대폰에서 처음 쓰면 비밀번호로 들어와 이 브라우저용 키를 등록한다.
import { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { API_MODE, api } from '../api/client';
import { myCredentials } from '../api/endpoints';
import { useSession } from '../auth/session';
import { ed25519Supported, listKeys } from '../auth/keystore';
import { ErrorBand } from '../components/states';
import { BrandMark } from '../components/BrandMark';
import { MutationError, OpPanel } from '../components/OpPanel';
import { LoginForm } from '../pages/Login';
import { useKeyRegistration } from '../pages/Account';
import { usePoll } from '../lib/usePoll';

const LATER = 'sfc.mobile.keyLater';
/** 이 브라우저에 그 사용자의 등록된 키가 없고, 이번 창에서 '나중에'를 누르지 않았으면 권한다 */
export function offerKey(username: string) {
  try {
    if (sessionStorage.getItem(LATER) === username) return false;
  } catch {
    // 못 읽으면 권한다
  }
  return !listKeys().some((k) => k.registered && k.username === username);
}

/** 키 이름 기본값: 기기-브라우저 (예: iphone-safari) */
export function deviceLabel(ua = typeof navigator === 'undefined' ? '' : navigator.userAgent) {
  const dev = /iPhone/.test(ua) ? 'iphone' : /iPad/.test(ua) ? 'ipad' : /Android/.test(ua) ? 'android' : /Mac OS X/.test(ua) ? 'mac' : /Windows/.test(ua) ? 'windows' : 'linux';
  const br = /SamsungBrowser/.test(ua) ? 'samsung' : /Edg\//.test(ua) ? 'edge' : /Firefox|FxiOS/.test(ua) ? 'firefox' : /Chrome|CriOS/.test(ua) ? 'chrome' : /Safari/.test(ua) ? 'safari' : 'browser';
  return `${dev}-${br}`;
}

export function MLogin({ onDone }: { onDone: () => void }) {
  return (
    <div className="m-login">
      <div className="m-login-head">
        <span className="m-login-mark">
          <BrandMark size={56} />
        </span>
        <b>Seafield Cluster</b>
        <span className="muted">관리 웹 · 로그인</span>
      </div>
      <LoginForm phone onDone={onDone} />
      <span className="muted small">최초 관리자 등록은 넓은 화면에서 · CLI: <code>sfcli enroll-admin</code></span>
      {API_MODE === 'mock' && (
        <div className="bn warn small">
          목업 계층: <code>alice/alice</code>(시스템 관리자), <code>bob/bob</code>(shop 읽기)로 로그인할 수 있습니다.
        </div>
      )}
    </div>
  );
}

/** 로그인 뒤 이 브라우저용 키 만들기 (UI-M2 ②) */
export function MKeySetupPage() {
  const session = useSession();
  const navigate = useNavigate();
  const loc = useLocation();
  const from = (loc.state as { from?: string } | null)?.from ?? '/';
  const creds = usePoll((s) => myCredentials(s), []);
  const [label, setLabel] = useState(deviceLabel);
  const [p1, setP1] = useState('');
  const [p2, setP2] = useState('');
  const [ok, setOk] = useState<boolean>();
  const reg = useKeyRegistration(session.user.username, session.user.id, creds.data?.accountRevision ?? session.user.revision, () => undefined);
  useEffect(() => {
    const ac = new AbortController();
    Promise.all([ed25519Supported(), api.get<{ key: boolean }>('/auth/methods', ac.signal).then((m) => m.key !== false).catch(() => true)])
      .then(([a, b]) => setOk(a && b))
      .catch(() => setOk(false));
    return () => ac.abort();
  }, []);
  const later = () => {
    try {
      sessionStorage.setItem(LATER, session.user.username);
    } catch {
      // 다음 로그인에서 다시 물어도 괜찮다
    }
    navigate(from, { replace: true });
  };
  if (ok === false) return <Navigate to={from} replace />;
  const done = reg.step === 'done' && reg.m.op?.state === 'applied';
  const valid = p1.length >= 8 && p1 === p2;
  return (
    <div className="m-login" style={{ paddingTop: 20, gap: 14 }}>
      <div className="bn ok">
        {session.method === 'token' ? '토큰' : '비밀번호'}으로 로그인했습니다 · {session.user.username}
      </div>
      <b style={{ fontSize: 18 }}>이 브라우저용 키 만들기</b>
      <div className="muted" style={{ fontSize: 13, lineHeight: '19px' }}>
        이 휴대폰 브라우저에서 개인키를 만들고 공개키만 서버에 등록합니다. 다음부터는 이 키로 로그인합니다.
      </div>
      {reg.step === 'done' && reg.m.op ? (
        <>
          <OpPanel op={reg.m.op} onChange={(o) => reg.m.setOp(o)} />
          <button type="button" className="mbtn pri" style={{ height: 48 }} onClick={() => navigate(from, { replace: true })}>
            {done ? '계속' : '나중에 확인'}
          </button>
        </>
      ) : (
        <>
          <label className="fld">
            키 이름
            <span className="in">
              <span className="muted">{session.user.username} · </span>
              <input value={label} onChange={(e) => setLabel(e.target.value)} aria-label="키 이름" />
            </span>
          </label>
          <label className="fld">
            키 암호 문구
            <input className="in" type="password" placeholder="8자 이상" value={p1} onChange={(e) => setP1(e.target.value)} autoComplete="new-password" />
          </label>
          <label className="fld">
            암호 문구 확인
            <input className="in" type="password" placeholder="한 번 더" value={p2} onChange={(e) => setP2(e.target.value)} autoComplete="new-password" />
            {p2 && p1 !== p2 && <span className="small" style={{ color: 'var(--er)' }}>두 암호 문구가 다릅니다</span>}
          </label>
          <button type="button" className="mbtn pri" style={{ height: 48 }} disabled={!valid || reg.step === 'working'} onClick={() => void reg.run(label, p1)}>
            {reg.step === 'working' ? '만드는 중…' : '키 만들고 등록'}
          </button>
          <button type="button" className="mbtn" style={{ height: 48 }} disabled={reg.step === 'working'} onClick={later}>
            나중에
          </button>
        </>
      )}
      {reg.error ? <ErrorBand error={reg.error} what="키를 만들지 못했습니다" /> : null}
      <MutationError error={reg.m.error} />
      <div className="bn warn">휴대폰 브라우저 데이터를 지우면 이 키도 지워집니다. 그때는 다시 비밀번호로 로그인해 새로 등록합니다. 계정 › 키 목록에서 안 쓰는 키를 지울 수 있습니다.</div>
    </div>
  );
}
