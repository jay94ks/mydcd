// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { accountScope, myCredentials } from '../api/endpoints';
import { noEndpoint } from '../api/client';
import { useAuth, useSession } from '../auth/session';
import type { UserCredential } from '../api/types';
import { createKey, ed25519Supported, listKeys, markRegistered, removeKey, shortKey, type StoredKey } from '../auth/keystore';
import { Badge, Card, Field, HelpBox, KV, PageHeader } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';
import { fmtTime, until } from '../lib/format';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { ActionSheet } from '../mobile/Sheet';
import { useToast } from '../components/Toast';

const credentialIdFor = (k: StoredKey) => `browser-${k.publicKey.slice(0, 12)}`;
const keyBytes = (hexKey: string) => (hexKey.match(/../g) ?? []).map((x) => parseInt(x, 16));

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
      const op = await m.submit({
        action: 'add-credential',
        expected: accountRevision,
        target: k.label,
        payload: { User: userId, Credential: { ID: credentialIdFor(k), Method: 'private-key', PublicKey: keyBytes(k.publicKey) }, Label: k.label },
      });
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

function NewKeyDialog({ username, userId, accountRevision, onClose, onDone }: { username: string; userId: string; accountRevision: number; onClose: () => void; onDone: () => void }) {
  const [label, setLabel] = useState('');
  const [p1, setP1] = useState('');
  const [p2, setP2] = useState('');
  const { run: register, step, error, m, key } = useKeyRegistration(username, userId, accountRevision, onDone);
  const run = () => register(label, p1);
  const valid = p1.length >= 8 && p1 === p2;
  return (
    <Dialog
      title="이 브라우저에서 새 키 만들기"
      onClose={onClose}
      footer={
        step === 'done' ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose} disabled={step === 'working'}>
              취소
            </button>
            <button className="btn primary" disabled={!valid || step === 'working'} onClick={() => void run()}>
              {step === 'working' ? '만드는 중…' : '생성하고 등록'}
            </button>
          </>
        )
      }
    >
      <p className="small">
        브라우저가 Ed25519 키 쌍을 만들고, 입력한 암호 문구로 개인키를 암호화해 이 브라우저에 저장합니다. 공개키만 내 계정의 로그인 수단으로 등록합니다.
      </p>
      {step !== 'done' ? (
        <>
          <Field label="키 이름" hint="예: laptop-chrome">
            <input value={label} onChange={(e) => setLabel(e.target.value)} />
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
  const { tenant, setTenant, logout } = useAuth();
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
  const mine = local.filter((k) => k.username === session.user.username);
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
        <>
      <PageHeader title="내 계정" ids="UI-04 · UI-05" />
      <HelpBox terms="로그인 수단 (credential, 비밀번호·토큰·개인키) · 작업 공간 (tenant)">
        <b>이 화면은</b> 내 로그인 수단과 권한을 관리합니다. 이 브라우저에서 만든 개인키를 등록하거나 끌 수 있습니다.
      </HelpBox>
      <div className="grid wide">
        <Card
          title="계정"
          actions={
            <button className="btn" onClick={() => void logout().then(() => navigate('/login'))}>
              로그아웃
            </button>
          }
        >
          <KV
            items={[
              ['사용자', session.user.username],
              ['권한', session.user.systemAdmin ? '시스템 관리자' : '일반 사용자'],
              ['로그인 방식', { key: '브라우저 개인키', password: '비밀번호', token: '토큰' }[session.method]],
              ['세션 만료', `${fmtTime(session.expiresAt)} (${until(session.expiresAt)})`],
              ['계정 버전', session.user.revision],
              ['동작 범위', <MyScope id={session.user.id} />],
            ]}
          />
        </Card>
        <Card title="접근 가능한 작업 공간">
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>작업 공간</th>
                  <th>권한</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {session.tenants.map((t) => (
                  <tr key={t.id}>
                    <td>{t.id}</td>
                    <td>{t.role === 'manager' ? '읽기 · 배포 · 관리' : '읽기'}</td>
                    <td>
                      {t.id === tenant ? (
                        <Badge tone="ok">현재 선택</Badge>
                      ) : (
                        <button className="btn sm" onClick={() => setTenant(t.id)}>
                          선택
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <span className="small muted">선택은 화면 상태이며 서버에 기본 작업 공간을 만들지 않습니다.</span>
        </Card>
      </div>
      <Card
        title="로그인 수단"
        actions={
          <button className="btn primary" disabled={supported === false} title={supported === false ? '이 브라우저는 Ed25519 WebCrypto를 지원하지 않습니다' : undefined} onClick={() => setCreating(true)}>
            이 브라우저에서 새 키 만들기
          </button>
        }
      >
        <Load q={creds}>
          {(c) => (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>종류 · 이름</th>
                    <th>공개키</th>
                    <th>위치</th>
                    <th>상태</th>
                    <th>ID</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {c.credentials.map((k, i) => {
                    const here = k.publicKey && mine.find((m) => m.publicKey === k.publicKey);
                    return (
                      <tr key={k.id || `${k.kind}-${i}`}>
                        <td>{k.kind === 'key' ? (here ? `개인키 · ${here.label}` : '개인키') : k.kind === 'password' ? '비밀번호' : '토큰'}</td>
                        <td>{k.publicKey ? <code>{shortKey(k.publicKey)}</code> : '—'}</td>
                        <td>{k.kind !== 'key' ? '서버 검증값' : here ? '이 브라우저' : '다른 브라우저'}</td>
                        <td>
                          <Badge tone={k.enabled ? 'ok' : 'un'}>{k.enabled ? '활성' : '꺼짐'}</Badge>
                        </td>
                        <td className="muted">
                          <code>{k.id}</code>
                        </td>
                        <td>
                          {k.enabled && (
                            <button
                              className="btn sm danger"
                              disabled={c.credentials.filter((x) => x.enabled).length <= 1}
                              title={c.credentials.filter((x) => x.enabled).length <= 1 ? '마지막 로그인 수단은 끌 수 없습니다' : undefined}
                              onClick={() => (dis.reset(), setDisabling(k))}
                            >
                              비활성화
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Load>
        {mine.some((k) => !k.registered) && (
          <div className="note wa small">
            이 브라우저에 등록되지 않은 키가 있습니다.{' '}
            {mine
              .filter((k) => !k.registered)
              .map((k) => (
                <button key={k.id} className="btn sm" onClick={() => (removeKey(k.id), reloadLocal())}>
                  {k.label} 지우기
                </button>
              ))}
          </div>
        )}
        <span className="small muted">키 등록·비활성화는 add-credential·disable-credential 작업으로 보냅니다(mydcd REQ-4).</span>
      </Card>
        </>
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
              <button className="btn primary" onClick={() => setDisabling(undefined)}>
                닫기
              </button>
            ) : (
              <>
                <button className="btn" onClick={() => setDisabling(undefined)}>
                  취소
                </button>
                <button
                  className="btn danger solid"
                  disabled={dis.busy}
                  onClick={() =>
                    void dis
                      .submit({ action: 'disable-credential', expected: creds.data?.accountRevision ?? 0, target: disabling.id, payload: { User: session.user.id, ID: disabling.id } })
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

/** 내 동작 범위. 읽기만 하고, 바꾸는 것은 시스템 관리자가 사용자 화면에서 한다 */
function MyScope({ id }: { id: string }) {
  const q = usePoll((sig) => accountScope(id, sig), [id], 0);
  if (q.error) return <span className="small muted">{noEndpoint(q.error) ? '서버 기능 대기' : '읽지 못했습니다'}</span>;
  const sc = q.data;
  if (!sc) return <span className="muted">…</span>;
  const parts = [sc.actions.length ? `허용 동작 ${sc.actions.join(', ')}` : '', sc.keyOnly ? '키로만 로그인' : ''].filter(Boolean);
  return (
    <span>
      {parts.length ? parts.join(' · ') : '제한 없음'}
      <br />
      <span className="small muted">바꾸려면 시스템 관리자에게 요청합니다.</span>
    </span>
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
        <button type="button" className="linkish" disabled={supported === false} title={supported === false ? '이 브라우저는 Ed25519 WebCrypto를 지원하지 않습니다' : undefined} onClick={onCreate}>
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
        <button type="button" style={{ color: '#A0111F' }} onClick={onLogout}>
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
