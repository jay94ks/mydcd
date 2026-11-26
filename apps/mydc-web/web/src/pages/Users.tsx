// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react';
import { usePhone } from '../lib/viewport';
import { MCards, MTiles, useReadOnlyTop } from '../mobile/ReadOnly';
import { accountScope, accountScopePath, sameActions, putUserPayload, rawUser, users } from '../api/endpoints';
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

function newUserId(): string {
  return 'u-' + Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, '0')).join('');
}

function NewUserDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [username, setUsername] = useState('');
  const [systemAdmin, setSystemAdmin] = useState(false);
  const [id] = useState(newUserId);
  const m = useMutation();
  const valid = /^[a-z][a-z0-9_.-]{1,31}$/.test(username);
  return (
    <Dialog
      title="사용자 만들기"
      width={400}
      onClose={onClose}
      footer={
        m.op ? (
          <button className="btn primary" onClick={() => (onDone(), onClose())}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button
              className="btn primary"
              disabled={!valid || m.busy}
              onClick={() => void m.submit({ action: 'put-user', expected: 0, target: username, payload: { ID: id, Username: username, Revision: 0, Enabled: true, SystemAdmin: systemAdmin, Credentials: [] } })}
            >
              만들기
            </button>
          </>
        )
      }
    >
      <Field label="사용자 이름" hint="영문 소문자로 시작, 2~32자" error={username && !valid ? '형식이 맞지 않습니다' : undefined}>
        <input value={username} onChange={(e) => setUsername(e.target.value.trim())} autoComplete="off" />
      </Field>
      <label className="check">
        <input type="checkbox" checked={systemAdmin} onChange={(e) => setSystemAdmin(e.target.checked)} /> 시스템 관리자
      </label>
      <div className="note wa small">처음 비밀번호·토큰은 아직 웹에서 발급하지 못합니다. 만든 뒤 CLI로 로그인 수단을 붙여 주세요.</div>
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}

function UserDrawer({ u, onClose, onDone }: { u: UserRecord; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [err, setErr] = useState<unknown>();
  const toggle = async (patch: { Enabled?: boolean; SystemAdmin?: boolean }) => {
    m.reset(); // 다른 변경이므로 새 작업 ID
    setErr(undefined);
    try {
      // 보낼 때 원 레코드를 다시 읽어 다른 로그인 수단을 그대로 보존한다. 버전은 화면에 보이던 값으로 지킨다.
      const raw = await rawUser(u.username);
      const op = await m.submit({ action: 'put-user', expected: u.revision, target: u.username, payload: { ...putUserPayload(raw, patch), Revision: u.revision } });
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
      <div className="table-wrap">
        <table className="tbl">
          <tbody>
            {u.credentials.map((c, i) => (
              <tr key={c.id || i}>
                <td>{c.kind === 'key' ? '개인키' : c.kind === 'password' ? '비밀번호' : '토큰'}</td>
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
  const send = () => sendOp(m, accountScopePath(u.id), { actions, keyOnly, ...(cur.revision ? { expected: cur.revision } : {}) }, 'PUT');
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
              badge: u.enabled ? (u.systemAdmin ? ['pr', '시스템 관리자'] : ['ok', '활성']) : ['un', '비활성'],
              lines: [`로그인 수단 ${u.credentials.map((c) => CRED_KO[c.kind]).join(' · ') || '없음'}`],
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
      <Card flush>
        <div style={{ padding: 16 }}>
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
                  { key: 's', header: '상태', value: (u) => (u.enabled ? 1 : 0), render: (u) => <Badge tone={u.enabled ? 'ok' : 'un'}>{u.enabled ? '활성' : '비활성'}</Badge> },
                  { key: 'a', header: '권한', value: (u) => (u.systemAdmin ? 1 : 0), render: (u) => (u.systemAdmin ? '시스템 관리자' : '일반') },
                  { key: 'c', header: '로그인 수단', value: (u) => u.credentials.length, render: (u) => u.credentials.map((c) => ({ key: '키', password: '비밀번호', token: '토큰' })[c.kind]).join(' · ') },
                  { key: 'r', header: '버전', value: (u) => u.revision, render: (u) => u.revision },
                ]}
              />
            )}
          </Load>
        </div>
      </Card>
      {creating && <NewUserDialog onClose={() => setCreating(false)} onDone={list.refresh} />}
      {selected && <UserDrawer key={selected.username} u={selected} onClose={() => setSel(undefined)} onDone={list.refresh} />}
    </>
  );
}
