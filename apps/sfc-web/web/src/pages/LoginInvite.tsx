// SPDX-License-Identifier: Apache-2.0

// 초대 링크를 연 화면 (/login/invite?u=…#code, UI-23A 캔버스 v227). 로그인하지 않은 사람이 연다.
// 순서(docs/reference/web-api/51-invite-links.md): 키 만들기·암호 문구 확인을 먼저 끝내고 → 초대 열기(코드 소비, 10분 표)
// → 새 키로 증명에 서명해 등록 → 보통 키 로그인 → 쓴 초대 자격 증명 끄기.
// 링크 코드는 주소 표시줄에서 바로 지우고 화면 상태에만 둔다. 암호 문구도 저장하지 않는다.
import { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { ApiError, api, newOpId } from '../api/client';
import { myCredentials } from '../api/endpoints';
import { INVITE_ERROR, finishInvite, isInviteCredential, openInvite, parseInviteLink } from '../api/invites';
import { credentialAdditionBytes } from '../auth/credentialProof';
import { createKey, forgetKey, hex, markRegistered, removeKey, sign, unlockKey, type StoredKey } from '../auth/keystore';
import { useAuth } from '../auth/session';
import { Field } from '../components/ui';
import { ErrorBand } from '../components/states';
import { credentialIdFor } from './Account';

type Step = 'form' | 'key' | 'open' | 'finish' | 'login' | 'cleanup' | 'done';
const STEPS: [Step, string, string, string?][] = [
  ['key', '키를 만들었습니다', '키를 만드는 중…'],
  ['open', '초대를 열었습니다 (이때 링크가 쓰인 것으로 처리)', '초대를 여는 중…', '10분 안에 끝내야 함'],
  ['finish', '새 키로 서명해 등록했습니다', '새 키로 서명해 등록하는 중…'],
  ['login', '로그인했습니다', '로그인하는 중…'],
];
const order: Step[] = ['form', 'key', 'open', 'finish', 'login', 'cleanup', 'done'];
const fromHex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));

export function LoginInvitePage() {
  const loc = useLocation();
  const navigate = useNavigate();
  const { session, loginKey } = useAuth();
  // 코드는 처음 한 번만 읽고 주소 표시줄에서 지운다(새로 고치면 링크를 다시 열어야 한다)
  const [link] = useState(() => parseInviteLink(loc.search, loc.hash));
  useEffect(() => {
    if (loc.hash) window.history.replaceState(window.history.state, '', loc.pathname + loc.search);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const [label, setLabel] = useState('');
  const [p1, setP1] = useState('');
  const [p2, setP2] = useState('');
  const [step, setStep] = useState<Step>('form');
  const [error, setError] = useState<unknown>();
  const [cleanupFailed, setCleanupFailed] = useState(false);
  const key = useRef<StoredKey>();
  const ok = link.username && link.code;
  const ready = !!ok && p1.length >= 8 && p1 === p2 && step === 'form';
  const at = order.indexOf(step);

  const run = async () => {
    setError(undefined);
    let opened = false;
    try {
      // ① 키를 먼저 만든다. 여기서 실패하면 초대는 아직 쓰이지 않았다
      setStep('key');
      key.current ??= await createKey(link.username, label.trim() || 'browser', p1);
      const k = key.current;
      // ② 초대 열기: 코드가 소비된다
      setStep('open');
      const t = await openInvite({ username: link.username, code: link.code });
      opened = true;
      // ③ 새 키로 증명에 서명해 등록
      setStep('finish');
      const id = credentialIdFor(k);
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const unlocked = await unlockKey(k, p1);
      let proof: string;
      try {
        const sig = fromHex(await sign(unlocked, credentialAdditionBytes(t.clusterId, t.accountRevision, { user: t.userId, id, method: 'private-key', label: k.label, publicKey: k.publicKey, challenge })));
        proof = btoa(String.fromCharCode(...sig));
      } finally {
        forgetKey(unlocked);
      }
      await finishInvite({ ticket: t.ticket, credential: { id, publicKey: k.publicKey }, label: k.label, challenge: hex(challenge), proof });
      markRegistered(k.id, true);
      // ④ 보통 키 로그인
      setStep('login');
      await loginKey(k, p1, t.username);
      // ⑤ 쓴 초대 자격 증명을 끈다. 실패해도 로그인은 됐으니 안내만 한다
      setStep('cleanup');
      try {
        // 끌 때마다 계정 revision을 다시 읽는다(한 번에 몇 오르는지 가정하지 않는다)
        for (;;) {
          const own = await myCredentials();
          const c = own.credentials.find((x) => isInviteCredential(x.id) && x.enabled);
          if (!c) break;
          const r = await api.post<{ op: { state: string; revision?: number } }>('/ops', { opId: newOpId(), action: 'disable-credential', principal: own.userId, expected: own.accountRevision, payload: { User: own.userId, Credential: c.id }, rootRevision: 0, target: c.id });
          if (r.op.state !== 'applied') throw new Error(r.op.state);
        }
      } catch {
        setCleanupFailed(true);
      }
      setP1('');
      setP2('');
      setStep('done');
    } catch (e) {
      setError(e);
      setStep('form');
      // 등록하지 못한 키는 로그인에 쓸 수 없으니 남기지 않는다(초대를 연 뒤면 링크도 이미 쓰였다)
      if (key.current && (opened || (e instanceof ApiError && e.status === 410))) {
        removeKey(key.current.id);
        key.current = undefined;
      }
    }
  };

  const code = error instanceof ApiError ? error.code : '';
  return (
    <div className="login-wrap">
      <section className="login-card" aria-labelledby="invite-title">
        <div className="col" style={{ gap: 6 }}>
          <span id="invite-title" style={{ fontSize: 18, fontWeight: 700 }}>
            Seafield에 초대받았습니다
          </span>
          {link.username && (
            <span className="small muted">
              계정 <b>{link.username}</b> · 이 브라우저에서 키를 만들어 등록합니다
            </span>
          )}
        </div>
        {!ok ? (
          <div className="note er small">링크가 온전하지 않습니다. 받은 초대 링크 전체를 다시 열어 주세요. 이 화면을 새로 고쳤다면 링크를 다시 여세요(코드는 화면에 남기지 않습니다).</div>
        ) : step === 'done' ? (
          <>
            <div className="note ok small">키를 등록하고 로그인했습니다. 내 계정에서 키를 내보내 백업해 두세요.</div>
            {cleanupFailed && <div className="note wa small">쓴 초대 자격 증명을 끄지 못했습니다. 내 계정 › 로그인 수단에서 ‘초대 링크’ 줄을 꺼 주세요. 이미 쓴 링크라 다시 쓸 수는 없습니다.</div>}
            <button className="btn primary" onClick={() => navigate('/account', { replace: true })}>
              내 계정으로
            </button>
          </>
        ) : (
          <>
            {session && session.user.username !== link.username && <div className="note wa small">지금 {session.user.username}(으)로 로그인돼 있습니다. 등록을 마치면 {link.username}(으)로 다시 로그인합니다.</div>}
            <Field label="키 이름" hint="이 브라우저를 알아보기 위한 이름">
              <input value={label} placeholder={`${link.username}-laptop`} onChange={(e) => setLabel(e.target.value)} disabled={step !== 'form'} autoFocus />
            </Field>
            <Field label="암호 문구" hint="이 브라우저에 저장하는 개인키를 암호화합니다. 잊으면 이 키는 다시 열 수 없습니다. 8자 이상">
              <input type="password" value={p1} onChange={(e) => setP1(e.target.value)} autoComplete="new-password" disabled={step !== 'form'} />
            </Field>
            <Field label="암호 문구 확인" error={p2 && p1 !== p2 ? '두 암호 문구가 다릅니다' : undefined}>
              <input type="password" value={p2} onChange={(e) => setP2(e.target.value)} autoComplete="new-password" disabled={step !== 'form'} />
            </Field>
            <button className="btn primary" disabled={!ready} onClick={() => void run()}>
              {step === 'form' ? '키 만들고 등록' : '등록하는 중…'}
            </button>
            {step !== 'form' && (
              <ol className="steps-v small" aria-label="진행">
                {STEPS.map(([s, done, now, note]) => {
                  const i = order.indexOf(s);
                  const st = at > i ? 'done' : at === i ? 'now' : 'wait';
                  return (
                    <li key={s} className={st}>
                      <span>{st === 'now' ? now : st === 'done' ? done : now.replace(' 중…', '')}</span>
                      {note && <span className="muted"> · {note}</span>}
                    </li>
                  );
                })}
              </ol>
            )}
            {error !== undefined &&
              (INVITE_ERROR[code] ? (
                <div className="note er small">
                  {INVITE_ERROR[code]} <span className="mono">{code}</span>
                </div>
              ) : (
                <ErrorBand error={error} what="키를 등록하지 못했습니다" />
              ))}
            <span className="small muted">① 브라우저가 Ed25519 키를 만듭니다 ② 초대를 열고 새 키로 서명해 공개키만 보냅니다 ③ 바로 로그인합니다. 개인키는 이 브라우저 밖으로 나가지 않습니다.</span>
          </>
        )}
      </section>
    </div>
  );
}
