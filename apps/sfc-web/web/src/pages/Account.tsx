// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { myCredentials } from '../api/endpoints';
import { useAuth, useSession } from '../auth/session';
import type { UserCredential } from '../api/types';
import { createKey, ed25519Supported, forgetKey, listKeys, markRegistered, removeKey, shortKey, unlockKey, type StoredKey } from '../auth/keystore';
import { selfAdditionPayload } from '../auth/credentialProof';
import { Badge, Field } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';
import { until } from '../lib/format';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { ActionSheet } from '../mobile/Sheet';
import { useToast } from '../components/Toast';
import { AccountDesktop } from './AccountDesktop';

export const credentialIdFor = (k: StoredKey) => `browser-${k.publicKey.slice(0, 12)}`;
export const keyBytes = (hexKey: string) => (hexKey.match(/../g) ?? []).map((x) => parseInt(x, 16));

/**
 * 이 브라우저의 키를 내 계정에 더하는 add-credential 페이로드. 새 키로 증명에 서명한다(#642).
 * 클러스터 ID와 계정 revision은 방금 읽은 /me/credentials 값을 쓴다(증명이 그 revision에 묶임).
 */
export async function selfKeyPayload(k: StoredKey, passphrase: string, userId: string, fallbackRevision: number) {
  const own = await myCredentials();
  if (!own.clusterId) throw new Error('서버가 클러스터 ID를 주지 않아 키 등록 증명을 만들 수 없습니다.');
  const revision = own.accountRevision ?? fallbackRevision;
  const unlocked = await unlockKey(k, passphrase);
  try {
    const payload = await selfAdditionPayload(unlocked, own.clusterId, revision, { user: userId, id: credentialIdFor(k), method: 'private-key', label: k.label, publicKey: k.publicKey });
    return { revision, payload };
  } finally {
    forgetKey(unlocked);
  }
}

/** 이 브라우저에서 키를 만들고 공개키를 내 계정에 등록한다. 데스크톱 다이얼로그와 휴대폰 로그인 뒤 등록(UI-M2 ②)이 같이 쓴다. */
export function useKeyRegistration(username: string, userId: string, accountRevision: number, onDone: () => void) {
  const [step, setStep] = useState<'form' | 'working' | 'done'>('form');
  const [error, setError] = useState<unknown>();
  const key = useRef<StoredKey>();
  const m = useMutation();

  const run = async (label: string, p1: string) => {
    setError(undefined);
    setStep('working');
    try {
      // 다시 눌러도 같은 키·같은 작업 ID를 쓴다.
      key.current ??= await createKey(username, label || 'browser', p1);
      const k = key.current;
      const { revision, payload } = await selfKeyPayload(k, p1, userId, accountRevision);
      const op = await m.submit({ action: 'add-credential', expected: revision, target: k.label, payload });
      if (!op) {
        setStep('form');
        return;
      }
      if (op.state === 'applied') markRegistered(k.id, true);
      // 거부·실패한 키는 로그인에 쓸 수 없으니 남기지 않는다. 결과 불명이면 정산될 때까지 둔다.
      if (op.state === 'failed' || op.state === 'rejected') {
        removeKey(k.id);
        key.current = undefined;
      }
      setStep('done');
      onDone();
    } catch (e) {
      setError(e);
      setStep('form');
    }
  };
  return { run, step, error, m, key };
}

export function NewKeyDialog({ username, userId, accountRevision, onClose, onDone }: { username: string; userId: string; accountRevision: number; onClose: () => void; onDone: () => void }) {
  const [label, setLabel] = useState('');
  const [p1, setP1] = useState('');
  const [p2, setP2] = useState('');
  const { run: register, step, error, m, key } = useKeyRegistration(username, userId, accountRevision, onDone);
  const run = () => register(label, p1);
  const valid = p1.length >= 8 && p1 === p2;
  return (
    <Dialog
      title="새 키 만들기"
      width={560}
      onClose={onClose}
      footer={
        step === 'done' ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose} disabled={step === 'working'}>
              취소
            </button>
            <button type="button" className="btn primary" disabled={!valid || step === 'working'} onClick={() => void run()}>
              {step === 'working' ? '만드는 중…' : '만들고 등록'}
            </button>
          </>
        )
      }
    >
      <p className="small">
        ① 브라우저가 Ed25519 키 쌍을 만듭니다 ② 암호 문구로 개인키를 암호화해 이 브라우저에 저장합니다 ③ 공개키만 내 로그인 수단으로 등록합니다.
      </p>
      {step !== 'done' ? (
        <>
          <Field label="키 이름" hint="예: laptop-chrome">
            <input value={label} onChange={(e) => setLabel(e.target.value)} autoFocus />
          </Field>
          <Field label="암호 문구" hint="8자 이상">
            <input type="password" value={p1} onChange={(e) => setP1(e.target.value)} autoComplete="new-password" />
          </Field>
          <Field label="암호 문구 확인" error={p2 && p1 !== p2 ? '두 암호 문구가 다릅니다' : undefined}>
            <input type="password" value={p2} onChange={(e) => setP2(e.target.value)} autoComplete="new-password" />
          </Field>
          <div className="note wa small">브라우저 저장소를 지우면 이 키도 사라집니다. 다른 키나 비밀번호로 로그인할 수 있게 해 두세요.</div>
        </>
      ) : (
        m.op && (
          <OpPanel
            op={m.op}
            onChange={(o) => {
              m.setOp(o);
              if (o.state === 'applied' && key.current) markRegistered(key.current.id, true);
              onDone();
            }}
          />
        )
      )}
      {error ? <ErrorBand error={error} what="키를 만들지 못했습니다" /> : null}
      <MutationError error={m.error} />
    </Dialog>
  );
}

export function AccountPage() {
  const session = useSession();
  const { logout } = useAuth();
  const navigate = useNavigate();
  const creds = usePoll((s) => myCredentials(s), []);
  const [local, setLocal] = useState<StoredKey[]>(() => listKeys());
  const [supported, setSupported] = useState<boolean>();
  const [creating, setCreating] = useState(false);
  const [disabling, setDisabling] = useState<UserCredential>();
  const dis = useMutation();
  useEffect(() => {
    void ed25519Supported().then(setSupported);
  }, []);
  const reloadLocal = () => setLocal(listKeys());
  // 같은 개인키를 여러 사용자가 쓸 수 있으니, 이 계정에 등록된 공개키와 같은 키도 내 키로 본다.
  const myKeys = new Set((creds.data?.credentials ?? []).map((c) => c.publicKey?.toLowerCase()).filter(Boolean));
  const mine = local.filter((k) => k.username === session.user.username || myKeys.has(k.publicKey.toLowerCase()));
  const phone = usePhone();

  return (
    <>
      {phone ? (
        <MAccountBody
          creds={creds}
          mine={mine}
          supported={supported}
          onCreate={() => setCreating(true)}
          onDisable={(k) => (dis.reset(), setDisabling(k))}
          onLogout={() => void logout().then(() => navigate('/login'))}
        />
      ) : (
        <AccountDesktop creds={creds} />
      )}
      {creating && (
        <NewKeyDialog
          username={session.user.username}
          userId={session.user.id}
          accountRevision={creds.data?.accountRevision ?? session.user.revision}
          onClose={() => setCreating(false)}
          onDone={() => {
            reloadLocal();
            creds.refresh();
          }}
        />
      )}
      {disabling && (
        <Dialog
          title="로그인 수단 끄기"
          width={420}
          onClose={() => setDisabling(undefined)}
          footer={
            dis.op ? (
              <button type="button" className="btn primary" onClick={() => setDisabling(undefined)}>
                닫기
              </button>
            ) : (
              <>
                <button type="button" className="btn" onClick={() => setDisabling(undefined)}>
                  취소
                </button>
                <button type="button"
                  className="btn danger solid"
                  disabled={dis.busy}
                  onClick={() =>
                    void dis
                      .submit({ action: 'disable-credential', expected: creds.data?.accountRevision ?? 0, target: disabling.id, payload: { User: session.user.id, Credential: disabling.id } })
                      .then((op) => {
                      if (op?.state === 'applied') {
                        const k = mine.find((m) => m.publicKey === disabling.publicKey);
                        if (k) markRegistered(k.id, false);
                        reloadLocal();
                      }
                      creds.refresh();
                    })
                  }
                >
                  비활성화
                </button>
              </>
            )
          }
        >
          <p className="small">
            <code>{disabling.id}</code>
            {disabling.publicKey ? ` (${shortKey(disabling.publicKey)})` : ''}(으)로는 더 이상 로그인할 수 없습니다. 기록은 지우지 않고 꺼 둡니다.
          </p>
          <MutationError error={dis.error} />
          {dis.op && <OpPanel op={dis.op} onChange={dis.setOp} />}
        </Dialog>
      )}
    </>
  );
}

const METHOD_KO: Record<string, string> = { key: '개인키 로그인', password: '비밀번호 로그인', token: '토큰 로그인' };

/** 휴대폰 내 계정 (UI-M11 ①): 계정 카드 · 작업 공간 · 로그인 키 · 알림 받는 방법 · 로그아웃 */
function MAccountBody({
  creds,
  mine,
  supported,
  onCreate,
  onDisable,
  onLogout,
}: {
  creds: ReturnType<typeof usePoll<import('../api/types').OwnCredentials>>;
  mine: StoredKey[];
  supported?: boolean;
  onCreate: () => void;
  onDisable: (k: UserCredential) => void;
  onLogout: () => void;
}) {
  const session = useSession();
  const { tenant, setTenant } = useAuth();
  const [menu, setMenu] = useState<UserCredential>();
  const toast = useToast();
  useMobileTop({ title: '내 계정', sub: session.user.username }, [session.user.username]);
  const hm = new Date(session.expiresAt).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', hour12: false });
  const enabled = creds.data?.credentials.filter((x) => x.enabled).length ?? 0;
  return (
    <>
      <div className="mc">
        <div className="hd">
          <b>{session.user.username}</b>
          {session.user.systemAdmin ? <Badge tone="pr">시스템 관리자</Badge> : <Badge tone="un">일반 사용자</Badge>}
        </div>
        <dl className="mkv">
          <dt>세션</dt>
          <dd>
            {METHOD_KO[session.method]} · {hm}까지
          </dd>
          <dt>남은 시간</dt>
          <dd>{until(session.expiresAt)}</dd>
        </dl>
      </div>
      <div className="m-sec">
        <span>접근 가능한 작업 공간</span>
      </div>
      <div className="li">
        {session.tenants.map((t) => (
          <button key={t.id} type="button" onClick={() => setTenant(t.id)}>
            <b>{t.id}</b>
            <span className="r">
              {t.role === 'manager' ? '읽기 · 배포 · 관리' : '읽기'}
              {t.id === tenant ? ' · 현재' : ''}
            </span>
          </button>
        ))}
        {session.tenants.length === 0 && <div className="muted">없음</div>}
      </div>
      <div className="m-sec">
        <span>로그인 키</span>
        <button type="button" className="linkish" disabled={supported === false} title={supported === false ? '이 페이지에서 안전한 난수를 만들 수 없어 키를 만들 수 없습니다' : undefined} onClick={onCreate}>
          이 브라우저에서 새 키 만들기
        </button>
      </div>
      <Load q={creds} what="로그인 수단을 읽지 못했습니다">
        {(c) => (
          <div className="li">
            {c.credentials.map((k, i) => {
              const here = k.publicKey ? mine.find((m) => m.publicKey === k.publicKey) : undefined;
              const current = !!here && session.method === 'key';
              const other = k.kind === 'key' && !here;
              const label = k.kind === 'key' ? here?.label ?? k.id : k.kind === 'password' ? 'password' : k.id;
              const sub = k.kind !== 'key' ? '서버 검증값' : here ? `이 브라우저${current ? ' · 현재 세션' : ''}` : `다른 브라우저 · ${k.publicKey ? shortKey(k.publicKey) : '—'}`;
              return (
                <div key={k.id || `${k.kind}-${i}`}>
                  <span className="el">
                    {label}
                    <span style={{ display: 'block', fontSize: 12, color: 'var(--muted)' }}>{sub}</span>
                  </span>
                  <span className="r" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    <Badge tone={k.enabled ? 'ok' : 'un'}>{k.enabled ? '활성' : '꺼짐'}</Badge>
                    {other && k.enabled && (
                      <button type="button" className="ic" aria-label={`${label} 메뉴`} style={{ border: 0, background: 'none', fontSize: 16, padding: '0 4px' }} onClick={() => setMenu(k)}>
                        ⋯
                      </button>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </Load>
      {mine.some((k) => !k.registered) && <div className="bn warn">이 브라우저에 등록되지 않은 키가 있습니다. 넓은 화면의 내 계정에서 지울 수 있습니다.</div>}
      <div className="li">
        <Link to="/account/notify">
          알림 받는 방법<span className="r">›</span>
        </Link>
        <button type="button" style={{ color: 'var(--er)' }} onClick={onLogout}>
          로그아웃
        </button>
      </div>
      {menu && (
        <ActionSheet
          title={menu.publicKey ? shortKey(menu.publicKey) : menu.id}
          items={[{ label: '비활성화…', danger: true, sub: enabled <= 1 ? '마지막 로그인 수단은 끌 수 없습니다' : undefined, onSelect: () => (enabled <= 1 ? toast('마지막 로그인 수단은 끌 수 없습니다', 'er') : onDisable(menu)) }]}
          onClose={() => setMenu(undefined)}
        />
      )}
    </>
  );
}
