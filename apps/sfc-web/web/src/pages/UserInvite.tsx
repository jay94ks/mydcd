// SPDX-License-Identifier: Apache-2.0

// 사용자 › 초대 링크 (UI-23A, 캔버스 v227 UserInvite). 계약: docs/reference/web-api/51-invite-links.md
// 링크는 만든 응답에서 한 번만 온다. 화면은 링크를 상태에만 두고 저장하지 않으며, 닫으면 다시 볼 수 없다.
// 결과를 모르면 같은 opId로 다시 물어도 링크는 오지 않으므로(op만) 새 링크를 만들게 안내한다.
import { useRef, useState } from 'react';
import { ApiError, newOpId } from '../api/client';
import { toOp } from '../api/endpoints';
import { INVITE_EXPIRY, createInvite, fullLink, isInviteCredential, revokeInvitePath, type InviteExpiry } from '../api/invites';
import type { OpView, UserRecord } from '../api/types';
import { dayTime } from '../lib/format';
import { Dialog } from '../components/Dialog';
import { Field, KV } from '../components/ui';
import { MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';

export const EXPIRY_HINT = '1시간 · 24시간 · 7일. 한 번 쓰면 끝납니다.';

/** 초대만 남은 시스템 관리자는 취소할 수 없다(로그인 수단이 하나는 남아야 한다) */
export const revokeBlocked = (u: UserRecord) => u.systemAdmin && !u.credentials.some((c) => c.enabled && !isInviteCredential(c.id));

/** 초대 만들기 요청. 같은 opId는 결과를 모를 때만 다시 쓴다 */
export function useInviteCreate() {
  const opId = useRef(newOpId());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [op, setOp] = useState<OpView>();
  const [result, setResult] = useState<{ link: string; expiresAt?: string }>();
  const send = async (user: string, expires: InviteExpiry) => {
    // 거절·실패 뒤에는 새 opId. 결과를 모르는(unknown) 것만 같은 opId로 다시 물어본다
    if (op && op.state !== 'unknown') opId.current = newOpId();
    if (error instanceof ApiError && error.status < 500) opId.current = newOpId();
    setBusy(true);
    setError(undefined);
    try {
      const r = await createInvite(user, { opId: opId.current, expires });
      const v = toOp(r.op);
      setOp(v);
      if (v.state === 'applied' && r.link) setResult({ link: r.link, expiresAt: r.expiresAt });
      return v;
    } catch (e) {
      setError(e);
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { send, busy, error, op, setOp, result };
}

/** 링크 결과. 만든 뒤 한 번만 보인다 */
export function InviteResult({ username, link, expiresAt, expiry }: { username: string; link: string; expiresAt?: string; expiry: InviteExpiry }) {
  const href = fullLink(link);
  return (
    <>
      <Field label="초대 링크">
        <input className="mono" readOnly value={href} onFocus={(e) => e.currentTarget.select()} autoComplete="off" spellCheck={false} />
      </Field>
      <div className="note wa small">
        이 창을 닫으면 링크를 다시 볼 수 없습니다. 메신저 등 {username}만 보는 곳으로 보내세요. 링크를 연 사람은 {username} 계정에 키를 하나 등록할 수 있으므로 비밀번호처럼 다룹니다.
      </div>
      <KV
        items={[
          ['만료', `${dayTime(expiresAt)} (${INVITE_EXPIRY.find(([k]) => k === expiry)?.[1] ?? expiry})`],
          ['쓸 수 있는 횟수', '1번'],
          ['등록되는 것', '브라우저 키 1개 (Ed25519)'],
        ]}
      />
    </>
  );
}

export function useCopyLink() {
  const toast = useToast();
  return async (link: string) => {
    try {
      await navigator.clipboard.writeText(fullLink(link));
      toast('✓ 초대 링크를 복사했습니다.');
      return true;
    } catch {
      toast('복사하지 못했습니다. 링크를 직접 골라 복사하세요.');
      return false;
    }
  };
}

export function ExpirySelect({ value, onChange, disabled }: { value: InviteExpiry; onChange: (v: InviteExpiry) => void; disabled?: boolean }) {
  return (
    <Field label="링크 유효 시간" hint={EXPIRY_HINT}>
      <select value={value} onChange={(e) => onChange(e.target.value as InviteExpiry)} disabled={disabled}>
        {INVITE_EXPIRY.map(([k, t]) => (
          <option key={k} value={k}>
            {t}
          </option>
        ))}
      </select>
    </Field>
  );
}

/** 초대 링크 만들기 · 다시 만들기 · 키 다시 등록 */
export function InviteDialog({ u, mode, onClose, onDone }: { u: UserRecord; mode: 'new' | 'again' | 'recover'; onClose: () => void; onDone: () => void }) {
  const [expiry, setExpiry] = useState<InviteExpiry>('24h');
  const c = useInviteCreate();
  const copy = useCopyLink();
  // 다시 만들기: 켜진 초대가 있으면 새로 만들 수 없어(op failed) 먼저 끈다(revoke). 끈 뒤에는 다시 끄지 않는다
  const rv = useMutation();
  const revoked = rv.op?.state === 'applied';
  const blocked = mode === 'again' && revokeBlocked(u);
  const go = async () => {
    if (mode === 'again' && !revoked) {
      const v = await sendOp(rv, revokeInvitePath(u.username), { expected: u.accountRevision ?? u.revision });
      if (v?.state !== 'applied') return;
    }
    await c.send(u.username, expiry);
  };
  const title = mode === 'again' ? `${u.username} 초대 링크 다시 만들기` : mode === 'recover' ? `${u.username} 초대 링크로 키 다시 등록` : `${u.username} 초대 링크`;
  const close = () => {
    if (c.op || rv.op) onDone();
    onClose();
  };
  const lost = c.op && c.op.state === 'applied' && !c.result;
  return (
    <Dialog
      title={title}
      width={560}
      onClose={close}
      footer={
        c.result ? (
          <>
            <button className="btn" onClick={() => void copy(c.result!.link)}>
              복사
            </button>
            <button className="btn primary" onClick={close}>
              닫기
            </button>
          </>
        ) : (
          <>
            <button className="btn" onClick={close}>
              {c.op ? '닫기' : '취소'}
            </button>
            {!lost && (
              <button className="btn primary" disabled={blocked || c.busy || rv.busy || (!!c.op && !['unknown', 'rejected', 'failed'].includes(c.op.state))} onClick={() => void go()}>
                {c.busy || rv.busy ? '만드는 중…' : c.op?.state === 'unknown' ? '같은 요청 다시 보내기' : '초대 링크 만들기'}
              </button>
            )}
          </>
        )
      }
    >
      {c.result ? (
        <InviteResult username={u.username} link={c.result.link} expiresAt={c.result.expiresAt} expiry={expiry} />
      ) : (
        <>
          {mode === 'again' && !blocked && <div className="note info small">지금 초대를 먼저 끄고 새 링크를 만듭니다. 이전 링크는 바로 못 씁니다.</div>}
          {blocked && <div className="note wa small">시스템 관리자 계정은 로그인 수단이 하나는 남아야 해서, 초대만 있으면 그 초대를 끄고 다시 만들 수 없습니다. CLI로 다른 로그인 수단을 붙인 뒤 하세요.</div>}
          {mode === 'recover' && (
            <div className="note info small">키를 모두 잃은 사람에게 같은 초대 링크로 새 키를 등록하게 합니다. 지금 있는 키·비밀번호는 그대로이며, 필요하면 따로 끕니다.</div>
          )}
          <ExpirySelect value={expiry} onChange={setExpiry} disabled={c.busy || !!c.op} />
          <span className="small muted">
            {u.username}이(가) 링크를 열어 자기 브라우저에서 키를 만들어 등록합니다. 개인키는 {u.username}의 브라우저 밖으로 나가지 않습니다. 서버에는 링크 코드의 해시만 남습니다.
          </span>
        </>
      )}
      {lost && <div className="note wa small">초대는 만들어졌지만 링크를 받지 못했습니다. 링크는 한 번만 오므로, 닫고 ‘초대 링크 다시 만들기’로 새 링크를 만드세요.</div>}
      {revoked && !c.result && !c.op && <div className="note small">지금 초대를 껐습니다. 새 링크를 만드는 중이거나, 만들기에 실패했다면 다시 누르세요.</div>}
      <MutationError error={rv.error ?? c.error} />
      {rv.op && rv.op.state !== 'applied' && <OpPanel op={rv.op} onChange={rv.setOp} />}
      {c.op?.state === 'failed' && <div className="note wa small">켜진 초대가 남아 있어 만들지 못했습니다. 목록을 다시 읽은 뒤 ‘초대 링크 다시 만들기’로 하세요.</div>}
      {c.op && !c.result && <OpPanel op={c.op} onChange={c.setOp} />}
    </Dialog>
  );
}

/** 초대 취소 */
export function RevokeInviteDialog({ u, onClose, onDone }: { u: UserRecord; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const toast = useToast();
  const blocked = revokeBlocked(u);
  const noInvite = m.error instanceof ApiError && m.error.code === 'no-invite';
  const send = async () => {
    const v = await sendOp(m, revokeInvitePath(u.username), { expected: u.accountRevision ?? u.revision });
    if (v?.state === 'applied') {
      toast(`✓ ${u.username} 초대를 취소했습니다.`);
      onDone();
      onClose();
    }
  };
  return (
    <Dialog
      title={`${u.username} 초대를 취소할까요?`}
      width={420}
      danger
      onClose={() => (m.op && onDone(), onClose())}
      footer={
        <>
          <button className="btn" onClick={() => (m.op && onDone(), onClose())}>
            닫기
          </button>
          <button className="btn danger" disabled={blocked || m.busy || noInvite || (!!m.op && m.op.state !== 'unknown' && m.op.state !== 'failed')} onClick={() => void send()}>
            {m.busy ? '보내는 중…' : '초대 취소'}
          </button>
        </>
      }
    >
      <p className="small">
        링크를 바로 못 쓰게 됩니다.{' '}
        {u.credentials.some((c) => c.enabled && !isInviteCredential(c.id)) ? `${u.username}의 다른 로그인 수단은 그대로입니다.` : `사용자 ${u.username}은(는) 로그인 수단 없이 남고, 나중에 새 초대를 만들 수 있습니다.`}
      </p>
      {blocked && <div className="note wa small">시스템 관리자 계정은 로그인 수단이 하나는 남아야 해서 초대를 취소할 수 없습니다. CLI로 다른 로그인 수단을 붙인 뒤 하세요.</div>}
      {noInvite ? <div className="note info small">취소할 초대가 없습니다. 이미 쓰였거나 취소됐습니다.</div> : <MutationError error={m.error} />}
      {m.op && m.op.state === 'failed' && <div className="note wa small">그사이 이 계정이 바뀌었습니다. 목록을 다시 읽은 뒤 해 주세요.</div>}
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}
