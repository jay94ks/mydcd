// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react';
import { usePhone } from '../lib/viewport';
import { MCards, MTiles, useReadOnlyTop } from '../mobile/ReadOnly';
import { accountScope, accountScopePath, sameActions, scopeDelta, putUserPayload, rawUser, users } from '../api/endpoints';
import type { AccountScope } from '../api/endpoints';
import { ApiError, noEndpoint } from '../api/client';
import type { UserRecord } from '../api/types';
import { Badge, Card, Field, HelpBox, KV, PageHeader } from '../components/ui';
import { Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Dialog } from '../components/Dialog';
import { Drawer } from '../components/Drawer';
import { DataTable } from '../components/DataTable';
import { casFailed, MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';
import { shortKey } from '../auth/keystore';
import { UserShellSection } from './NodeShell';
import { inviteLeft, isInviteCredential, type InviteExpiry } from '../api/invites';
import { ExpirySelect, InviteDialog, InviteResult, RevokeInviteDialog, revokeBlocked, useCopyLink, useInviteCreate } from './UserInvite';
import { dayTime } from '../lib/format';

function newUserId(): string {
  return 'u-' + Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, '0')).join('');
}

function NewUserDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [username, setUsername] = useState('');
  const [systemAdmin, setSystemAdmin] = useState(false);
  const [first, setFirst] = useState<'invite' | 'cli'>('invite');
  const [expiry, setExpiry] = useState<InviteExpiry>('24h');
  const [id] = useState(newUserId);
  const m = useMutation();
  const inv = useInviteCreate();
  const copy = useCopyLink();
  const valid = /^[a-z][a-z0-9_.-]{1,31}$/.test(username);
  const create = async () => {
    // 사용자를 만든 뒤(applied) 곧바로 초대를 만든다. 사용자 결과를 모르면 초대는 상세에서 따로 만든다
    const op = m.op?.state === 'applied' ? m.op : await m.submit({ action: 'put-user', expected: 0, target: username, payload: { ID: id, Username: username, Revision: 0, Enabled: true, SystemAdmin: systemAdmin, Credentials: [] } });
    if (op?.state === 'applied' && first === 'invite') await inv.send(username, expiry);
  };
  const userDone = m.op?.state === 'applied';
  const finished = inv.result || (m.op && (first === 'cli' || m.op.state !== 'applied'));
  const retryInvite = userDone && first === 'invite' && !inv.result && !inv.busy && (!inv.op || ['unknown', 'rejected', 'failed'].includes(inv.op.state));
  return (
    <Dialog
      title={inv.result ? `${username} 초대 링크` : '사용자 만들기'}
      width={inv.result ? 560 : 420}
      onClose={() => (m.op && onDone(), onClose())}
      footer={
        inv.result ? (
          <>
            <button className="btn" onClick={() => void copy(inv.result!.link)}>
              복사
            </button>
            <button className="btn primary" onClick={() => (onDone(), onClose())}>
              닫기
            </button>
          </>
        ) : finished && !retryInvite ? (
          <button className="btn primary" onClick={() => (onDone(), onClose())}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={() => (m.op && onDone(), onClose())}>
              {m.op ? '닫기' : '취소'}
            </button>
            <button className="btn primary" disabled={!valid || m.busy || inv.busy || (!!m.op && !userDone)} onClick={() => void create()}>
              {m.busy || inv.busy ? '보내는 중…' : retryInvite ? '초대 링크 다시 만들기' : '만들기'}
            </button>
          </>
        )
      }
    >
      {inv.result ? (
        <>
          <div className="note ok small">사용자 {username}을(를) 만들었습니다.</div>
          <InviteResult username={username} link={inv.result.link} expiresAt={inv.result.expiresAt} expiry={expiry} />
        </>
      ) : (
        <>
          <Field label="사용자 이름" hint="영문 소문자로 시작, 2~32자" error={username && !valid ? '형식이 맞지 않습니다' : undefined}>
            <input value={username} onChange={(e) => setUsername(e.target.value.trim())} autoComplete="off" disabled={!!m.op} />
          </Field>
          <fieldset className="col" style={{ gap: 8, border: 0, padding: 0, margin: 0 }} disabled={!!m.op}>
            <legend className="small" style={{ padding: 0, marginBottom: 6 }}>
              첫 로그인 수단
            </legend>
            <label className="check">
              <input type="radio" name="first" checked={first === 'invite'} onChange={() => setFirst('invite')} /> 초대 링크 (권장)
            </label>
            <span className="small muted" style={{ marginLeft: 24 }}>
              받은 사람이 자기 브라우저에서 키를 만들어 등록합니다. 개인키는 그 브라우저 밖으로 나가지 않습니다.
            </span>
            <label className="check">
              <input type="radio" name="first" checked={first === 'cli'} onChange={() => setFirst('cli')} /> 나중에 CLI로 붙이기
            </label>
            <span className="small muted" style={{ marginLeft: 24 }}>
              임시 비밀번호·토큰은 아직 웹에서 발급하지 못합니다. 만든 뒤 CLI로 로그인 수단을 붙여 주세요.
            </span>
          </fieldset>
          {first === 'invite' && <ExpirySelect value={expiry} onChange={setExpiry} disabled={!!m.op} />}
          <label className="check">
            <input type="checkbox" checked={systemAdmin} onChange={(e) => setSystemAdmin(e.target.checked)} disabled={!!m.op} /> 시스템 관리자
          </label>
        </>
      )}
      <MutationError error={m.error} />
      {m.op && !inv.result && <OpPanel op={m.op} onChange={m.setOp} />}
      {userDone && first === 'invite' && !inv.result && (
        <>
          <MutationError error={inv.error} />
          {inv.op && <OpPanel op={inv.op} onChange={inv.setOp} />}
          {inv.op?.state === 'applied' && <div className="note wa small">초대는 만들어졌지만 링크를 받지 못했습니다. 닫은 뒤 사용자 상세에서 ‘초대 링크 다시 만들기’로 새 링크를 만드세요.</div>}
        </>
      )}
      {m.op && m.op.state === 'unknown' && first === 'invite' && <div className="note info small">사용자가 만들어진 것을 확인한 뒤 사용자 상세에서 초대 링크를 만드세요.</div>}
    </Dialog>
  );
}

function UserDrawer({ u, onClose, onDone }: { u: UserRecord; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [err, setErr] = useState<unknown>();
  const [inv, setInv] = useState<'new' | 'again' | 'recover' | 'revoke'>();
  const live = u.credentials.some((c) => c.enabled && !isInviteCredential(c.id));
  const toggle = async (patch: { Enabled?: boolean; SystemAdmin?: boolean }) => {
    m.reset(); // 다른 변경이므로 새 작업 ID
    setErr(undefined);
    try {
      // 계정 자체의 칸만 보낸다(로그인 수단은 그대로). 버전은 화면에 보이던 값으로 지킨다.
      const raw = await rawUser(u.username);
      const op = await m.submit({ action: 'put-user', expected: u.revision, target: u.username, payload: putUserPayload(raw, patch) });
      if (op) onDone();
    } catch (e) {
      setErr(e);
    }
  };
  return (
    <Drawer title={u.username} onClose={onClose}>
      <KV
        items={[
          ['상태', <Badge tone={u.enabled ? 'ok' : 'un'}>{u.enabled ? '활성' : '비활성'}</Badge>],
          ['시스템 관리자', u.systemAdmin ? '예' : '아니요'],
          ['사용자 ID', <code>{u.id}</code>],
          ['계정 버전', u.revision],
          ...(u.invite ? [['초대', <Badge tone={u.invite.state === 'active' ? 'pr' : 'wa'}>{u.invite.state === 'active' ? `초대됨 · ${inviteLeft(u.invite.expiresAt)}` : `초대 만료 · ${dayTime(u.invite.expiresAt)}`}</Badge>] as [string, JSX.Element]] : []),
        ]}
      />
      <div className="row">
        <button className="btn sm" disabled={m.busy} onClick={() => void toggle({ Enabled: !u.enabled })}>
          {u.enabled ? '비활성화' : '활성화'}
        </button>
        <button className="btn sm" disabled={m.busy} onClick={() => void toggle({ SystemAdmin: !u.systemAdmin })}>
          {u.systemAdmin ? '관리자 권한 빼기' : '관리자로 지정'}
        </button>
      </div>
      <span className="small muted">기대 버전 {u.revision}으로 보냅니다. 그사이 버전이 바뀌면 적용하지 않습니다(결과 1). 목록을 다시 읽은 뒤 해 주세요.</span>
      {casFailed(m.op) && <div className="note wa small">그사이 이 사용자가 바뀌었습니다. 새로 읽은 값으로 다시 해 주세요.</div>}
      <MutationError error={m.error ?? err} />
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
      <hr className="sep" />
      <b>로그인 수단</b>
      <div className="row">
        {u.invite ? (
          <>
            <button className="btn sm" onClick={() => setInv('again')}>
              초대 링크 다시 만들기…
            </button>
            <button className="btn sm danger" disabled={revokeBlocked(u)} title={revokeBlocked(u) ? '시스템 관리자 계정은 로그인 수단이 하나는 남아야 합니다' : undefined} onClick={() => setInv('revoke')}>
              초대 취소…
            </button>
          </>
        ) : live ? (
          <button className="btn sm" onClick={() => setInv('recover')}>
            초대 링크로 키 다시 등록…
          </button>
        ) : (
          <button className="btn sm" onClick={() => setInv('new')}>
            초대 링크 만들기…
          </button>
        )}
      </div>
      <div className="table-wrap">
        <table className="tbl">
          <tbody>
            {u.credentials.map((c, i) => (
              <tr key={c.id || i}>
                <td>{isInviteCredential(c.id) ? '초대 링크' : c.kind === 'key' ? '개인키' : c.kind === 'password' ? '비밀번호' : '토큰'}</td>
                <td>
                  <code>{c.id}</code>
                </td>
                <td>{c.publicKey ? <code>{shortKey(c.publicKey)}</code> : '—'}</td>
                <td>
                  <Badge tone={c.enabled ? 'ok' : 'un'}>{c.enabled ? '활성' : '꺼짐'}</Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ScopeSection u={u} />
      <UserShellSection u={u} />
      <span className="small muted">작업 공간 권한은 작업 공간 화면의 구성원 탭에서 바꿉니다.</span>
      {inv === 'revoke' && <RevokeInviteDialog u={u} onClose={() => setInv(undefined)} onDone={onDone} />}
      {inv && inv !== 'revoke' && <InviteDialog u={u} mode={inv} onClose={() => setInv(undefined)} onDone={onDone} />}
    </Drawer>
  );
}

/** 허용 동작 · 로그인 방식 요약. 본인 화면(내 계정)과 함께 쓴다 */
export function ScopeSummary({ sc }: { sc: AccountScope }) {
  return (
    <KV
      items={[
        ['허용 동작', sc.actions.length ? <span className="mono">{sc.actions.join(' · ')}</span> : '제한 없음'],
        ['로그인', sc.keyOnly ? '키로만 (비밀번호·토큰 막음)' : '모든 로그인 수단'],
      ]}
    />
  );
}

/** 동작 범위 (REQ-9 set-account-scope). 시스템 관리자만 바꾼다 */
function ScopeSection({ u }: { u: UserRecord }) {
  const q = usePoll((sig) => accountScope(u.id, sig), [u.id], 0);
  const [edit, setEdit] = useState<AccountScope>();
  const wait = !!q.error && noEndpoint(q.error);
  return (
    <>
      <hr className="sep" />
      <div className="row between">
        <b>동작 범위</b>
        <button className="btn sm" disabled={!q.data} onClick={() => setEdit(q.data)}>
          바꾸기…
        </button>
      </div>
      {wait ? (
        <span className="small muted">동작 범위: 서버 기능 대기</span>
      ) : (
        <Load q={q} what="동작 범위를 읽지 못했습니다">
          {(sc) => <ScopeSummary sc={sc} />}
        </Load>
      )}
      <span className="small muted">비우면 제한 없음. 가진 권한을 넓히지 않고 쓸 수 있는 동작만 줄입니다. 시스템 관리자만 바꾸고, 본인은 내 계정에서 읽기만 합니다.</span>
      {edit && <ScopeDialog u={u} cur={edit} onClose={() => (setEdit(undefined), void q.refresh())} />}
    </>
  );
}

const parseActions = (s: string) => [...new Set(s.split(/[\s,·]+/).map((a) => a.trim()).filter(Boolean))];

function ScopeDialog({ u, cur, onClose }: { u: UserRecord; cur: AccountScope; onClose: () => void }) {
  const m = useMutation();
  const [text, setText] = useState(cur.actions.join(', '));
  const [keyOnly, setKeyOnly] = useState(cur.keyOnly);
  const actions = parseActions(text);
  const hasKey = u.credentials.some((c) => c.kind === 'key' && c.enabled);
  const bad = actions.length > 64 ? '64개까지입니다' : actions.find((a) => a.length > 64 || !/^[a-z0-9][a-z0-9-]*$/.test(a)) ? '동작 이름은 restart-task처럼 소문자·숫자·-로 씁니다' : undefined;
  const same = sameActions(actions, cur.actions) && keyOnly === cur.keyOnly;
  const done = m.op?.state === 'applied';
  const locked = m.busy || done;
  const send = () => {
    const delta = scopeDelta(cur, actions, keyOnly);
    return delta ? sendOp(m, accountScopePath(u.id), delta, 'PATCH') : Promise.resolve(undefined);
  };
  const noKey = m.error instanceof ApiError && m.error.code === 'no-key';
  return (
    <Dialog
      title={`${u.username} 동작 범위`}
      width={560}
      onClose={onClose}
      footer={
        done ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={locked || !!bad || same || (keyOnly && !hasKey)} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '변경 검토'}
            </button>
          </>
        )
      }
    >
      <Field label="허용 동작" hint="비우면 제한 없음 (그 사람의 권한 안에서 모두)" error={bad}>
        <input className="mono" value={text} disabled={locked} placeholder="예: deploy, cd-approve, observe" onChange={(e) => setText(e.target.value)} />
      </Field>
      <label className="check">
        <input type="checkbox" checked={keyOnly} disabled={locked || (!hasKey && !keyOnly)} onChange={(e) => setKeyOnly(e.target.checked)} />
        <span>
          키로만 로그인 (keyOnly)
          <br />
          <span className="small muted">비밀번호·토큰 로그인을 막습니다. 공개키가 하나 이상 있어야 켤 수 있습니다{!hasKey && ' · 지금 켜진 공개키가 없습니다'}</span>
        </span>
      </label>
      <span className="small muted">시스템 관리자만 바꿉니다. 권한을 넓히지는 않고, 이미 가진 권한 중 쓸 수 있는 동작만 줄입니다.</span>
      {casFailed(m.op) && <div className="note wa small">그사이 동작 범위가 바뀌었습니다. 창을 닫고 다시 열어 주세요.</div>}
      {noKey ? <div className="note wa small">켜진 공개키가 없어 키로만 로그인을 켤 수 없습니다.</div> : <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}

export function UsersPage() {
  return usePhone() ? <MUsers /> : <DesktopUsers />;
}

const CRED_KO = { key: '키', password: '비밀번호', token: '토큰' } as const;
/** 상태 칸: 초대됨 · 초대 만료 · 시스템 관리자 · 활성 · 비활성 */
const statusOf = (u: UserRecord): ['ok' | 'pr' | 'wa' | 'un', string] =>
  !u.enabled ? ['un', '비활성'] : u.invite?.state === 'active' ? ['pr', '초대됨'] : u.invite?.state === 'expired' ? ['wa', '초대 만료'] : ['ok', '활성'];
/** 로그인 수단 칸. 초대 자격 증명은 ‘초대 링크 · n시간 남음’ */
function credText(u: UserRecord): string {
  const rest: string[] = u.credentials.filter((c) => c.enabled && !isInviteCredential(c.id)).map((c) => CRED_KO[c.kind]);
  if (u.invite?.state === 'active') rest.unshift(`초대 링크 · ${inviteLeft(u.invite.expiresAt)}`);
  if (!rest.length) return u.invite?.state === 'expired' ? `없음 · ${dayTime(u.invite.expiresAt)} 만료` : '없음';
  return rest.join(' · ');
}

/** 휴대폰 사용자 (UI-M11 ④ 모양) */
function MUsers() {
  const list = usePoll((s) => users(s), []);
  useReadOnlyTop('사용자', '시스템 관리자', '만들기·비활성화·로그인 수단·권한 바꾸기는 넓은 화면에서');
  return (
    <Load q={list} what="사용자를 불러오지 못했습니다">
      {(p) => (
        <>
          <MTiles
            items={[
              { label: '사용자', value: p.items.length, sub: `활성 ${p.items.filter((u) => u.enabled).length} · 비활성 ${p.items.filter((u) => !u.enabled).length}` },
              { label: '시스템 관리자', value: p.items.filter((u) => u.systemAdmin).length, sub: '클러스터 전체 권한' },
            ]}
          />
          <MCards
            empty="사용자가 없습니다."
            items={p.items.map((u) => ({
              key: u.username,
              title: u.username,
              badge: u.invite && u.enabled ? statusOf(u) : u.enabled ? (u.systemAdmin ? ['pr', '시스템 관리자'] : ['ok', '활성']) : ['un', '비활성'],
              lines: [`로그인 수단 ${credText(u)}`],
              meta: `버전 ${u.revision}`,
            }))}
          />
        </>
      )}
    </Load>
  );
}

function DesktopUsers() {
  const list = usePoll((s) => users(s), []);
  const [creating, setCreating] = useState(false);
  const [sel, setSel] = useState<string>();
  const selected = list.data?.items.find((u) => u.username === sel);
  return (
    <>
      <PageHeader
        title="사용자"
        ids="UI-23"
        actions={
          <>
            <Refresh q={list} poll={false} />
            <button className="btn primary" onClick={() => setCreating(true)}>
              사용자 만들기
            </button>
          </>
        }
      />
      <HelpBox terms="로그인 수단 (credential) · 버전 (revision) · 시스템 관리자 (system admin)">
        <b>이 화면은</b> 클러스터 사용자와 로그인 수단을 관리합니다. 사용자를 지우지 않고 비활성화합니다.
      </HelpBox>
      <Card>
        <Load q={list}>
          {(p) => (
            <DataTable
              rows={p.items}
              rowKey={(u) => u.username}
              pageInfo={p}
              selectedKey={sel}
              onRowClick={(u) => setSel(u.username)}
              columns={[
                { key: 'u', header: '사용자', value: (u) => u.username, render: (u) => <b>{u.username}</b> },
                { key: 's', header: '상태', value: (u) => (u.enabled ? 1 : 0), render: (u) => <Badge tone={statusOf(u)[0]}>{statusOf(u)[1]}</Badge> },
                { key: 'a', header: '권한', value: (u) => (u.systemAdmin ? 1 : 0), render: (u) => (u.systemAdmin ? '시스템 관리자' : '일반') },
                { key: 'c', header: '로그인 수단', value: (u) => u.credentials.length, render: (u) => credText(u) },
                { key: 'r', header: '버전', value: (u) => u.revision, render: (u) => u.revision },
              ]}
            />
          )}
        </Load>
      </Card>
      {creating && <NewUserDialog onClose={() => setCreating(false)} onDone={list.refresh} />}
      {selected && <UserDrawer key={selected.username} u={selected} onClose={() => setSel(undefined)} onDone={list.refresh} />}
    </>
  );
}
