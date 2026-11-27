// SPDX-License-Identifier: Apache-2.0

// 내 계정 (UI-04 · UI-05, 캔버스 v215 Account · AccountIx): 계정 · 접근 가능한 작업 공간 · 내 로그인 수단(한 표) · 열린 세션 ·
// 최근 로그인 · 이 브라우저에 저장된 키 · 화면 설정. 열린 세션 · 최근 로그인은 /me/sessions · /me/logins(#621). 로그인 수단 이름 바꾸기 · 비밀번호 바꾸기는 데몬 API가 생기면 채운다.
import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api, newOpId, noEndpoint } from '../api/client';
import type { DOp } from '../api/dto';
import { clientText, LOGIN_METHOD, ownLogins, ownSessions, sessionPath, type OwnLogin, type OwnSession } from '../api/me';
import { accountScope } from '../api/endpoints';
import { currentSessionKey, useAuth, useSession } from '../auth/session';
import type { OwnCredentials, UserCredential } from '../api/types';
import { ed25519Supported, listKeys, markRegistered, removeKey, setKeyUser, shortKey, type StoredKey } from '../auth/keystore';
import { Badge, Card, Field, HelpBox, KV, PageHeader } from '../components/ui';
import { Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { Menu, type MenuItem } from '../components/Menu';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { usePoll, type Loaded } from '../lib/usePoll';
import { dayTime, fmtTime, until } from '../lib/format';
import { applyPrefs, DEFAULT_PREFS, loadPrefs, POLL_SECONDS, pollText, savePrefs, timeZones, tzLabel, type UiPrefs } from '../lib/uiPrefs';
import { NewKeyDialog, selfKeyPayload } from './Account';
import { ImportKeyDialog, ReloginDialog } from './Login';

const KIND: Record<UserCredential['kind'], string> = { key: '개인키', password: '비밀번호', token: 'API 토큰' };
const METHOD: Record<string, string> = { key: '개인키', password: '비밀번호', token: 'API 토큰' };
const day = (iso?: string) => (iso ? new Date(iso).toLocaleDateString('ko-KR', { month: 'long', day: 'numeric' }) : '—');
const WAIT = '서버가 아직 주지 않습니다';

type Creds = Loaded<OwnCredentials>;

export function AccountDesktop({ creds }: { creds: Creds }) {
  const session = useSession();
  const [local, setLocal] = useState<StoredKey[]>(() => listKeys());
  const reloadLocal = () => setLocal(listKeys());
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [supported, setSupported] = useState<boolean>();
  useEffect(() => {
    void ed25519Supported().then(setSupported);
  }, []);
  const refresh = () => (reloadLocal(), creds.refresh());
  const rev = creds.data?.accountRevision ?? session.user.revision;
  const sq = usePoll((s) => ownSessions(s), [], 30_000);
  return (
    <>
      <PageHeader title="내 계정" ids="UI-04 · UI-05" />
      <HelpBox terms="로그인 수단 (credential) · 승인 키 (approval key, 독립 승인에 쓰는 키) · 세션 (session) · 작업 공간 (tenant)">
        <b>이 화면은</b> 내 로그인 수단(개인키·비밀번호·API 토큰), 이 브라우저에 저장된 키, 지금 열린 세션과 최근 로그인을 한곳에서 봅니다. 개인키는 이 브라우저에서 만들거나 가져오고, 비밀번호는 여기서 바꾸며, API 토큰은 관리자가 발급하고 나는 보거나 회수만 합니다.
      </HelpBox>
      <div className="grid-2">
        <AccountCard sq={sq} />
        <TenantsCard />
      </div>
      <CredentialsCard creds={creds} local={local} onImport={() => setImporting(true)} onCreate={() => setCreating(true)} createDisabled={supported === false} onChange={refresh} />
      <div className="main-side">
        <SessionsCard sq={sq} creds={creds.data} local={local} />
        <LoginsCard creds={creds.data} local={local} />
      </div>
      <div className="grid-2">
        <BrowserKeysCard local={local} creds={creds.data} rev={rev} onChange={refresh} />
        <PrefsCard />
      </div>
      {creating && <NewKeyDialog username={session.user.username} userId={session.user.id} accountRevision={rev} onClose={() => setCreating(false)} onDone={refresh} />}
      {importing && (
        <ImportKeyDialog
          fixedUser={session.user.username}
          onClose={() => setImporting(false)}
          onDone={() => {
            setImporting(false);
            reloadLocal();
          }}
        />
      )}
    </>
  );
}

function AccountCard({ sq }: { sq: SessionsQ }) {
  const session = useSession();
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [dlg, setDlg] = useState<'relogin' | 'logout'>();
  const [others, setOthers] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>();
  const rest = (sq.data?.items ?? []).filter((x) => !x.current);
  const out = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      if (others) await revokeAll(rest);
      await logout();
      navigate('/login');
    } catch (e) {
      setErr(e);
      setBusy(false);
    }
  };
  return (
    <Card title="계정">
      <KV
        items={[
          ['사용자', <b>{session.user.username}</b>],
          ['권한', session.user.systemAdmin ? '시스템 관리자' : '일반 사용자'],
          [
            '이 세션',
            <>
              {METHOD[session.method]} · {fmtTime(session.expiresAt)}까지 <span className="muted small">({until(session.expiresAt)})</span>
            </>,
          ],
          ['동작 범위', <MyScope id={session.user.id} />],
        ]}
      />
      <div className="row">
        <button className="btn" onClick={() => setDlg('relogin')}>
          세션 새로 로그인
        </button>
        <button className="btn danger" onClick={() => setDlg('logout')}>
          로그아웃
        </button>
      </div>
      {dlg === 'relogin' && <ReloginDialog title="세션을 새로 받을까요?" onLoggedOut={() => navigate('/login')} onClose={() => setDlg(undefined)} />}
      {dlg === 'logout' && (
        <Dialog
          title="로그아웃"
          width={420}
          onClose={() => setDlg(undefined)}
          footer={
            <>
              <button className="btn" onClick={() => setDlg(undefined)}>
                취소
              </button>
              <button className="btn danger solid" disabled={busy} onClick={() => void out()}>
                로그아웃
              </button>
            </>
          }
        >
          <p className="small">세션 키를 지우고 로그인 화면으로 갑니다.</p>
          <label className="row" style={{ gap: 6 }}>
            <input type="checkbox" checked={others} disabled={!rest.length} onChange={(e) => setOthers(e.target.checked)} />
            <span className="small">
              다른 브라우저의 내 세션도 모두 끝내기 <span className="muted">{rest.length ? `서버에서 내 세션 ${rest.length}개를 회수합니다` : sq.data ? '다른 세션이 없습니다' : '세션 목록을 읽지 못했습니다'}</span>
            </span>
          </label>
          {err !== undefined && <MutationError error={err} />}
        </Dialog>
      )}
    </Card>
  );
}

function TenantsCard() {
  const session = useSession();
  const { tenant, setTenant } = useAuth();
  const toast = useToast();
  return (
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
                <td>{t.role === 'manager' ? '읽기 · 배포 · 관리 권한 전체' : '읽기'}</td>
                <td>
                  {t.id === tenant ? (
                    <Badge tone="ok">현재 선택</Badge>
                  ) : (
                    <button className="btn sm" onClick={() => (setTenant(t.id), toast(`작업 공간을 ${t.id}로 바꿨습니다. 이 화면 상태만 바뀌며 서버에는 저장하지 않습니다.`))}>
                      선택
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <span className="small muted">선택은 화면 상태이며 서버에 기본 작업 공간을 만들지 않습니다. 권한을 바꾸려면 시스템 관리자에게 요청하세요.</span>
    </Card>
  );
}

/** 이 브라우저에 같은 공개키가 있으면 그 키 */
const localOf = (local: StoredKey[], c: UserCredential) => (c.publicKey ? local.find((k) => k.publicKey === c.publicKey) : undefined);
const credName = (c: UserCredential, here?: StoredKey) => c.label ?? here?.label;

function CredentialsCard({ creds, local, onImport, onCreate, createDisabled, onChange }: { creds: Creds; local: StoredKey[]; onImport: () => void; onCreate: () => void; createDisabled: boolean; onChange: () => void }) {
  const toast = useToast();
  const [, setSp] = useSearchParams();
  const showCred = (id: string) => {
    setSp({ cred: id }, { replace: true });
    document.getElementById('sessions')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  const [disabling, setDisabling] = useState<UserCredential>();
  const copy = (text: string, what: string) => void navigator.clipboard?.writeText(text).then(() => toast(`${what}를 복사했습니다.`), () => toast(`${what}를 복사하지 못했습니다.`, 'er'));
  const n = creds.data?.credentials.length;
  return (
    <Card
      title={`내 로그인 수단${n === undefined ? '' : ` (${n})`}`}
      actions={
        <>
          <button className="btn" onClick={onImport}>
            개인키 가져오기…
          </button>
          <button className="btn primary" disabled={createDisabled} title={createDisabled ? '이 페이지에서 안전한 난수를 만들 수 없어 키를 만들 수 없습니다' : undefined} onClick={onCreate}>
            이 브라우저에서 새 키 만들기
          </button>
        </>
      }
    >
      <Load q={creds}>
        {(c) => {
          const enabled = c.credentials.filter((x) => x.enabled).length;
          const last = (k: UserCredential) => k.enabled && enabled <= 1;
          return (
            <div className="table-wrap">
              <table className="tbl" style={{ minWidth: 900 }}>
                <thead>
                  <tr>
                    <th>종류</th>
                    <th>이름</th>
                    <th>공개키 · 값</th>
                    <th>만든 날</th>
                    <th>마지막 사용</th>
                    <th>상태</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {c.credentials.map((k, i) => {
                    const here = localOf(local, k);
                    const name = credName(k, here);
                    const expired = !!k.expiresAt && Date.parse(k.expiresAt) < Date.now();
                    const items: MenuItem[] =
                      k.kind === 'key'
                        ? [
                            { label: '이름 바꾸기', disabledReason: WAIT },
                            { label: '공개키 복사', onSelect: () => k.publicKey && copy(k.publicKey, '공개키') },
                            { label: '', sep: true },
                            { label: '비활성화…', danger: true, onSelect: () => setDisabling(k), disabledReason: !k.enabled ? '이미 꺼져 있습니다' : last(k) ? '마지막 로그인 수단은 끌 수 없습니다' : undefined },
                          ]
                        : k.kind === 'password'
                          ? [
                              { label: '비밀번호 바꾸기…', disabledReason: WAIT },
                              { label: '비밀번호 로그인 끄기…', danger: true, onSelect: () => setDisabling(k), disabledReason: !k.enabled ? '이미 꺼져 있습니다' : last(k) ? '마지막 로그인 수단은 끌 수 없습니다' : undefined },
                            ]
                          : [
                              { label: '토큰 끝자리 복사', onSelect: () => k.tail && copy(k.tail, '토큰 끝자리'), disabledReason: k.tail ? undefined : WAIT },
                              { label: '이 토큰의 세션 보기', onSelect: () => showCred(k.id) },
                              { label: '', sep: true },
                              { label: '회수…', danger: true, onSelect: () => setDisabling(k), disabledReason: !k.enabled ? '이미 꺼져 있습니다' : last(k) ? '마지막 로그인 수단은 끌 수 없습니다' : undefined },
                            ];
                    return (
                      <tr key={k.id || `${k.kind}-${i}`}>
                        <td>{KIND[k.kind]}</td>
                        <td>
                          {name ? k.approvalKey ? <><b>{name}</b> <span className="muted" style={{ fontSize: 11 }}>승인 키</span></> : name : <span className="muted">{k.kind === 'password' ? '—' : <code>{k.id}</code>}</span>}
                        </td>
                        <td>{k.kind === 'key' && k.publicKey ? <span className="mono">ed25519 {shortKey(k.publicKey)}</span> : k.kind === 'password' ? <span className="muted">서버 검증값만 보관</span> : k.tail ? <span className="mono">sfc_tk_…{k.tail}</span> : <span className="muted">—</span>}</td>
                        <td>{k.createdAt ? `${day(k.createdAt)}${k.createdBy ? ` · ${k.createdBy} 발급` : ''}` : <span className="muted">—</span>}</td>
                        <td>{k.lastUsedAt ? fmtTime(k.lastUsedAt) : <span className="muted">—</span>}</td>
                        <td>
                          <span className="col" style={{ gap: 2 }}>
                            {expired ? <Badge tone="un">만료됨</Badge> : <Badge tone={k.enabled ? 'ok' : 'un'}>{k.enabled ? '활성' : '꺼짐'}</Badge>}
                            {k.expiresAt && !expired && <span className="muted" style={{ fontSize: 11 }}>{day(k.expiresAt)} 만료</span>}
                          </span>
                        </td>
                        <td>
                          <Menu label={`${KIND[k.kind]} ${name ?? ''} 작업`} items={items} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          );
        }}
      </Load>
      <span className="small muted">마지막 활성 수단은 끌 수 없습니다. 비활성화한 수단은 관리자가 사용자 화면에서 다시 켭니다. API 토큰은 관리자가 발급하며, 여기서는 회수만 할 수 있습니다.</span>
      {disabling && creds.data && <DisableDialog c={disabling} own={creds.data} local={local} onClose={() => setDisabling(undefined)} onDone={onChange} />}
    </Card>
  );
}

/** 개인키·비밀번호 끄기, 토큰 회수 (disable-credential) */
function DisableDialog({ c, own, local, onClose, onDone }: { c: UserCredential; own: OwnCredentials; local: StoredKey[]; onClose: () => void; onDone: () => void }) {
  const session = useSession();
  const m = useMutation();
  const here = localOf(local, c);
  const name = credName(c, here) ?? c.id;
  // 이 브라우저가 이 세션을 연 키(메모리에 기억한 공개키)와 같으면 지금 세션 키다
  const current = c.kind === 'key' && !!c.publicKey && c.publicKey.toLowerCase() === currentSessionKey();
  const [confirm, setConfirm] = useState('');
  const title = c.kind === 'token' ? `${name} 토큰 회수` : c.kind === 'password' ? '비밀번호 로그인 끄기' : `${name} 키를 비활성화할까요?`;
  const verb = c.kind === 'token' ? '회수' : c.kind === 'password' ? '끄기' : '비활성화';
  const body =
    c.kind === 'token'
      ? '회수하면 이 토큰으로 열린 세션도 끝나고, 이 토큰을 쓰는 스크립트는 바로 실패합니다. 다시 쓰려면 관리자에게 새 토큰을 받아야 합니다.'
      : c.kind === 'password'
        ? '비밀번호로는 더 로그인할 수 없습니다. 다시 켜려면 관리자가 사용자 화면에서 켜야 합니다.'
        : current
          ? '지금 이 세션이 쓰는 키입니다. 비활성화하면 이 세션은 곧 끝나고, 이 키로는 다시 로그인할 수 없습니다. 다른 키나 비밀번호가 있는지 확인하세요.'
          : '그 키로 열린 세션도 함께 회수합니다. 다시 켜려면 관리자가 사용자 화면에서 켜야 합니다.';
  const run = () =>
    void m.submit({ action: 'disable-credential', expected: own.accountRevision, target: c.id, payload: { User: session.user.id, Credential: c.id } }).then((op) => {
      if (op?.state === 'applied' && here) markRegistered(here.id, false);
      onDone();
    });
  return (
    <Dialog
      title={title}
      width={420}
      onClose={onClose}
      footer={
        m.op ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn danger solid" disabled={m.busy || (current && confirm !== name)} onClick={run}>
              {verb}
            </button>
          </>
        )
      }
    >
      {current ? <div className="note wa small">{body}</div> : <p className="small">{body}</p>}
      {current && !m.op && (
        <Field label={<>확인하려면 <b className="mono">{name}</b>을(를) 입력하세요</>}>
          <input className="mono" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
        </Field>
      )}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), onDone())} />}
    </Dialog>
  );
}

/** 데몬 API가 없으면(404) 기다리는 중이라고 말한다 */
function useOptional<T>(load: (s: AbortSignal) => Promise<T>) {
  const [st, setSt] = useState<{ data?: T; wait?: boolean; error?: unknown }>({});
  useEffect(() => {
    const ctl = new AbortController();
    load(ctl.signal).then(
      (data) => setSt({ data }),
      (error: unknown) => !ctl.signal.aborted && setSt(noEndpoint(error) ? { wait: true } : { error }),
    );
    return () => ctl.abort();
  }, []);
  return st;
}

type SessionsQ = Loaded<{ items: OwnSession[]; missing: string[] }>;

/** 세션들을 차례로 끊는다(지금 세션은 서버가 422로 거절하므로 보내지 않는다) */
async function revokeAll(list: OwnSession[]) {
  for (const x of list) {
    const r = await api.del<{ op?: DOp }>(sessionPath(x.id), { opId: newOpId() });
    if (r.op && (r.op.state === 'failed' || r.op.state === 'rejected')) throw new Error(`${clientText(x.client)} (${x.node}) 세션을 끝내지 못했습니다${r.op.errorCode ? ` (${r.op.errorCode})` : ''}.`);
  }
}

/** 자격 증명 ID → 화면 이름(비밀번호는 이름 없음) */
function credLabel(id: string | undefined, method: string, creds?: OwnCredentials, local: StoredKey[] = []): string {
  const kind = LOGIN_METHOD[method] ?? method;
  if (!id || method === 'password') return kind;
  const c = creds?.credentials.find((x) => x.id === id);
  const name = c ? credName(c, localOf(local, c)) : undefined;
  return `${kind} ${name ?? (id.length > 14 ? `${id.slice(0, 12)}…` : id)}`;
}
const missingNote = (m: string[]) => (m.length ? <div className="note wa small">{m.join(', ')} 서버가 답하지 않아 그 서버가 연 세션·기록은 빠져 있을 수 있습니다.</div> : null);

function SessionsCard({ sq, creds, local }: { sq: SessionsQ; creds?: OwnCredentials; local: StoredKey[] }) {
  const session = useSession();
  const [sp, setSp] = useSearchParams();
  const cred = sp.get('cred') ?? '';
  const [ending, setEnding] = useState<OwnSession[]>();
  const wait = noEndpoint(sq.error);
  const all = sq.data?.items ?? [];
  const rows = cred ? all.filter((x) => x.credential === cred) : all;
  const rest = all.filter((x) => !x.current);
  const credName0 = cred ? credLabel(cred, creds?.credentials.find((x) => x.id === cred)?.kind === 'token' ? 'token' : 'private-key', creds, local) : '';
  return (
    <div id="sessions">
      <Card
        title={`열린 세션${sq.data ? ` (${all.length})` : ''}`}
        actions={
          <button className="btn danger" disabled={!rest.length} title={wait ? WAIT : !rest.length ? '다른 세션이 없습니다' : undefined} onClick={() => setEnding(rest)}>
            이 세션 말고 모두 끝내기
          </button>
        }
      >
        {cred && (
          <div className="note info small">
            {credName0}로 열린 세션만 봅니다.{' '}
            <button type="button" className="linkish" onClick={() => setSp({}, { replace: true })}>
              모두 보기
            </button>
          </div>
        )}
        {wait ? (
          <SessionsWaiting />
        ) : (
          <Load q={sq} what="열린 세션을 읽지 못했습니다">
            {() => (
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>브라우저 · 주소</th>
                      <th>로그인 수단</th>
                      <th>서버</th>
                      <th>남은 시간</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {!rows.length && (
                      <tr>
                        <td colSpan={5} className="muted">
                          {cred ? '이 수단으로 열린 세션이 없습니다.' : '열린 세션이 없습니다.'}
                        </td>
                      </tr>
                    )}
                    {rows.map((x) => (
                      <tr key={x.id}>
                        <td>
                          <b>{clientText(x.client)}</b> {x.current && <Badge tone="pr">이 세션</Badge>}
                          <div className="mono small muted">{x.address}</div>
                        </td>
                        <td>{credLabel(x.credential, x.method, creds, local)}</td>
                        <td className="mono">{x.node}</td>
                        <td>{until(x.current ? session.expiresAt : x.expiresAt)}</td>
                        <td style={{ textAlign: 'right' }}>
                          {!x.current && (
                            <button className="btn sm" onClick={() => setEnding([x])}>
                              끝내기
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Load>
        )}
        {sq.data && missingNote(sq.data.missing)}
        <span className="small muted">세션은 최대 1시간입니다. 끝내면 그 세션의 다음 요청부터 거절됩니다. 이 세션은 로그아웃으로 끝냅니다.</span>
        {ending && <EndSessionsDialog list={ending} onClose={() => setEnding(undefined)} onDone={() => void sq.refresh()} />}
      </Card>
    </div>
  );
}

function SessionsWaiting() {
  const session = useSession();
  return (
    <>
      <div className="table-wrap">
        <table className="tbl">
          <tbody>
            <tr>
              <td>
                <b>이 브라우저</b> <Badge tone="pr">이 세션</Badge>
              </td>
              <td>{METHOD[session.method]}</td>
              <td>{until(session.expiresAt)}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <span className="small muted">다른 브라우저·CLI 세션 목록은 서버가 아직 주지 않습니다.</span>
    </>
  );
}

function EndSessionsDialog({ list, onClose, onDone }: { list: OwnSession[]; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      await revokeAll(list);
      toast(`세션 ${list.length}개를 끝냈습니다.`);
      onDone();
      onClose();
    } catch (e) {
      setErr(e);
      onDone();
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={list.length > 1 ? `다른 세션 ${list.length}개 끝내기` : '세션 끝내기'}
      width={420}
      danger
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger solid" disabled={busy} onClick={() => void go()}>
            {busy ? '끝내는 중…' : '끝내기'}
          </button>
        </>
      }
    >
      <p className="small">
        {list.map((x) => `${clientText(x.client)} (${x.node})`).join(', ')} 세션을 끝냅니다. 그 세션의 다음 요청부터 거절되고, 다시 로그인해야 합니다. 로그인 수단은 그대로입니다.
      </p>
      {err !== undefined && <MutationError error={err} />}
    </Dialog>
  );
}

function LoginsCard({ creds, local }: { creds?: OwnCredentials; local: StoredKey[] }) {
  const lq = usePoll((s) => ownLogins(undefined, s), [], 60_000);
  const [more, setMore] = useState<OwnLogin[]>([]);
  const [next, setNext] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>();
  // 새로 읽으면 더 본 쪽은 버린다
  useEffect(() => {
    setMore([]);
    setNext(lq.data?.next);
  }, [lq.data]);
  const loadMore = async () => {
    if (!next) return;
    setBusy(true);
    try {
      const r = await ownLogins(next);
      setMore((m) => [...m, ...r.items]);
      setNext(r.next);
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  const wait = noEndpoint(lq.error);
  const line = (x: OwnLogin) => {
    const who = credLabel(x.credential, x.method, creds, local);
    if (x.ok) return [who, x.client ? clientText(x.client) : '', x.address, x.node].filter(Boolean).join(' · ');
    return [`${x.reason === 'throttled' ? '시도 한도 초과' : '실패'} · ${who}`, x.address, x.count > 1 ? `${x.count}번 (마지막 ${fmtTime(x.lastAt)})` : '', x.node].filter(Boolean).join(' · ');
  };
  const d = lq.data;
  return (
    <Card title="최근 로그인" actions={d?.budgetMax !== undefined && <span className="small muted" title="이 사용자 이름으로 지금 더 받아 주는 비밀번호·토큰 시도 수(답한 서버 기준, 12초마다 하나씩 다시 참)">시도 한도 {d.budgetLeft ?? 0}/{d.budgetMax} 남음</span>}>
      {wait ? (
        <span className="small muted">로그인 기록은 서버가 아직 주지 않습니다.</span>
      ) : (
        <Load q={lq} what="로그인 기록을 읽지 못했습니다">
          {(r) => (
            <div className="col" style={{ gap: 6 }}>
              {![...r.items, ...more].length && <span className="small muted">최근 30일 로그인 기록이 없습니다.</span>}
              {[...r.items, ...more].map((x, i) => (
                <div key={`${x.node}/${x.at}/${i}`} className="row" style={{ gap: 10, alignItems: 'baseline' }}>
                  <span className="small muted" style={{ minWidth: 110 }}>
                    {dayTime(x.at)}
                  </span>
                  <span className={`small ${x.ok ? '' : 'er'}`}>{line(x)}</span>
                </div>
              ))}
              {next && (
                <button type="button" className="linkish small" disabled={busy} onClick={() => void loadMore()}>
                  {busy ? '읽는 중…' : '더 보기'}
                </button>
              )}
              {err !== undefined && <MutationError error={err} />}
              {missingNote(r.missing)}
            </div>
          )}
        </Load>
      )}
      <Link to="/system/operations/web" className="small">
        전체 기록 (작업 기록 › 웹)
      </Link>
    </Card>
  );
}

function BrowserKeysCard({ local, creds, rev, onChange }: { local: StoredKey[]; creds?: OwnCredentials; rev: number; onChange: () => void }) {
  const session = useSession();
  const [user, setUser] = useState<StoredKey>();
  const [del, setDel] = useState<StoredKey>();
  const [reg, setReg] = useState<StoredKey>();
  const mine = (k: StoredKey) => !!creds?.credentials.some((c) => c.kind === 'key' && c.enabled && c.publicKey === k.publicKey);
  return (
    <Card title={`이 브라우저에 저장된 키 (${local.length})`} actions={<span className="muted small">이 브라우저에만 있음 · 암호화됨</span>}>
      {local.length === 0 ? (
        <span className="small muted">이 브라우저에 저장된 키가 없습니다.</span>
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>키 이름</th>
                <th>기본 사용자</th>
                <th>공개키</th>
                <th>이 계정에 등록</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {local.map((k) => (
                <tr key={k.id}>
                  <td>{k.username === session.user.username ? <b>{k.label}</b> : k.label}</td>
                  <td>{k.username}</td>
                  <td className="mono">{shortKey(k.publicKey)}</td>
                  <td>{creds ? mine(k) ? <Badge tone="ok">등록됨</Badge> : <Badge tone="un">이 계정엔 없음</Badge> : <span className="muted">…</span>}</td>
                  <td>
                    <Menu
                      label={`${k.label} 키 작업`}
                      items={[
                        { label: '기본 사용자 바꾸기…', onSelect: () => setUser(k) },
                        ...(creds && !mine(k) ? [{ label: '이 계정에 등록…', onSelect: () => setReg(k) }] : []),
                        { label: '내보내기…', hint: '암호화된 PEM', disabledReason: '아직 지원하지 않습니다' },
                        { label: '', sep: true },
                        { label: '이 브라우저에서 지우기…', danger: true, onSelect: () => setDel(k) },
                      ]}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <span className="small muted">같은 키를 여러 사용자가 쓸 수 있습니다. 기본 사용자는 로그인 화면에서 이름 칸이 비어 있을 때 채우는 이름입니다. 브라우저 저장소를 지우면 이 키들도 사라지니, 다른 수단을 남겨 두세요.</span>
      {user && <KeyUserDialog k={user} onClose={() => setUser(undefined)} onDone={onChange} />}
      {del && <RemoveKeyDialog k={del} registered={mine(del)} onClose={() => setDel(undefined)} onDone={onChange} />}
      {reg && <RegisterKeyDialog k={reg} rev={rev} onClose={() => setReg(undefined)} onDone={onChange} />}
    </Card>
  );
}

function KeyUserDialog({ k, onClose, onDone }: { k: StoredKey; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(k.username);
  const ok = name.trim() !== '';
  return (
    <Dialog
      title={`${k.label} 기본 사용자`}
      width={420}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!ok} onClick={() => (setKeyUser(k.id, name.trim()), onDone(), onClose())}>
            바꾸기
          </button>
        </>
      }
    >
      <Field label="기본 사용자" hint="로그인 화면에서 이 키를 고르고 이름 칸이 비어 있으면 채웁니다. 이 브라우저에만 저장합니다.">
        <input value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />
      </Field>
    </Dialog>
  );
}

function RemoveKeyDialog({ k, registered, onClose, onDone }: { k: StoredKey; registered: boolean; onClose: () => void; onDone: () => void }) {
  return (
    <Dialog
      title={`${k.label} 키를 이 브라우저에서 지울까요?`}
      width={420}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger solid" onClick={() => (removeKey(k.id), onDone(), onClose())}>
            지우기
          </button>
        </>
      }
    >
      <p className="small">
        이 브라우저 저장소에서만 지웁니다. {registered ? '서버에 등록된 공개키는 그대로라 다른 곳에 같은 키가 있으면 계속 로그인할 수 있습니다. ' : ''}원본 키를 따로 보관하지 않았다면 이 브라우저에서는 이 키로 다시 로그인할 수 없습니다.
      </p>
    </Dialog>
  );
}

/** 이 브라우저의 키를 내 계정의 로그인 수단으로 등록 (add-credential). 공개키와, 그 키로 서명한 증명만 보낸다(#642) */
function RegisterKeyDialog({ k, rev, onClose, onDone }: { k: StoredKey; rev: number; onClose: () => void; onDone: () => void }) {
  const session = useSession();
  const m = useMutation();
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>();
  const run = async () => {
    setErr(undefined);
    setBusy(true);
    try {
      const { revision, payload } = await selfKeyPayload(k, pass, session.user.id, rev);
      setPass('');
      const op = await m.submit({ action: 'add-credential', expected: revision, target: k.label, payload });
      if (op?.state === 'applied') markRegistered(k.id, true);
      onDone();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`${k.label} 키를 이 계정에 등록`}
      width={420}
      onClose={onClose}
      footer={
        m.op ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={m.busy || busy || !pass} onClick={() => void run()}>
              {busy || m.busy ? '서명하는 중…' : '등록'}
            </button>
          </>
        )
      }
    >
      <p className="small">
        공개키 <span className="mono">{shortKey(k.publicKey)}</span>만 {session.user.username}의 로그인 수단으로 등록합니다. 개인키는 이 브라우저 밖으로 나가지 않습니다.
      </p>
      {!m.op && (
        <Field label="이 키의 암호 문구" hint="이 키가 맞다는 증명에 이 키로 한 번 서명합니다. 암호 문구는 어디에도 저장하지 않습니다.">
          <input type="password" autoComplete="current-password" value={pass} onChange={(e) => setPass(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && pass && !busy && void run()} autoFocus />
        </Field>
      )}
      {err !== undefined && <MutationError error={err} />}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && markRegistered(k.id, true), onDone())} />}
    </Dialog>
  );
}

function PrefsCard() {
  const toast = useToast();
  const session = useSession();
  const st = useOptional(loadPrefs);
  const [p, setP] = useState<UiPrefs>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  useEffect(() => {
    if (st.data) setP(st.data);
  }, [st.data]);
  const v = { ...DEFAULT_PREFS, ...Object.fromEntries(Object.entries(p).filter(([, x]) => x !== undefined)) } as typeof DEFAULT_PREFS;
  const own = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const saved = await savePrefs(p);
      applyPrefs(saved);
      toast('✓ 화면 설정을 저장했습니다. 다른 브라우저에도 다음 로그인부터 적용됩니다.');
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const set = (k: keyof UiPrefs, x: unknown) => setP((cur) => ({ ...cur, [k]: x }));
  return (
    <Card title="화면 설정">
      <div className="g2">
        <Field label="시간대">
          <select value={v.timeZone} onChange={(e) => set('timeZone', e.target.value || undefined)} disabled={!st.data}>
            <option value="">브라우저 따름 · {tzLabel(own)}</option>
            {timeZones().map((tz) => (
              <option key={tz} value={tz}>
                {tzLabel(tz)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="화면 밝기">
          <select value={v.theme} onChange={(e) => set('theme', e.target.value as UiPrefs['theme'])} disabled={!st.data}>
            <option value="system">시스템 설정 따름</option>
            <option value="light">밝게</option>
            <option value="dark">어둡게</option>
          </select>
        </Field>
        <Field label="자동 갱신 주기">
          <select value={v.pollSeconds} onChange={(e) => set('pollSeconds', Number(e.target.value))} disabled={!st.data}>
            {POLL_SECONDS.map((s) => (
              <option key={s} value={s}>
                {pollText(s)}
                {s === 30 ? ' (기본)' : ''}
              </option>
            ))}
          </select>
        </Field>
        <Field label="표 밀도">
          <select value={v.density} onChange={(e) => set('density', e.target.value as UiPrefs['density'])} disabled={!st.data}>
            <option value="normal">보통</option>
            <option value="compact">좁게</option>
          </select>
        </Field>
        {session.user.systemAdmin && (
          <Field label="대시보드 시작하기 카드" group>
            <label className="row small" style={{ gap: 6 }}>
              <input type="checkbox" checked={!v.hideStart} onChange={(e) => set('hideStart', !e.target.checked)} disabled={!st.data} />
              보이기 (모든 단계를 마치면 저절로 사라짐)
            </label>
          </Field>
        )}
      </div>
      <span className="small muted">{st.wait ? '이 서버는 아직 화면 설정을 저장하지 않습니다.' : '이 설정은 내 계정에 저장돼 다른 브라우저에서도 같습니다(웹 앱 데이터).'}</span>
      <MutationError error={error ?? st.error} />
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="btn primary" disabled={!st.data || busy} onClick={() => void save()}>
          저장
        </button>
      </div>
    </Card>
  );
}

/** 내 동작 범위. 읽기만 하고, 바꾸는 것은 시스템 관리자가 사용자 화면에서 한다 */
export function MyScope({ id }: { id: string }) {
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
