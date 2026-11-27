// SPDX-License-Identifier: Apache-2.0

// 웹 앱 설정 › 웹 데이터 카드의 자동 작업 계정 (REQ-9, 캔버스 WebSettings · WebSettingsIx v112).
// 키 쌍은 웹 데몬이 만들고 개인키는 봉인 파일에만 있다. 화면에는 공개키 지문만 보인다.
// 키를 그 계정의 로그인 수단으로 등록(put-user)하고 동작 범위를 정하는 일(set-account-scope)은
// 시스템 관리자가 자기 세션으로 서명하는 보통 op다. 무엇을 할 수 있는지는 sfcd가 정한다.
import { useState } from 'react';
import { ApiError, noEndpoint } from '../api/client';
import { accountScope, accountScopePath, sameActions, scopeDelta, automation, checkAutomation, putAutomation, rawUser, withAutomationKey } from '../api/endpoints';
import type { AccountScope, AutomationCheck, AutomationView } from '../api/endpoints';
import { Badge, Field } from '../components/ui';
import { Dialog } from '../components/Dialog';
import { casFailed, MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';
import type { Loaded } from '../lib/usePoll';

const DEFAULT_NAME = 'sfc-web-auto';
const BACKUP_ACTIONS = ['volume-file-put', 'volume-file-delete', 'volume-file-list'];
const STEPS = ['키 만들기', '로그인 수단 등록', '동작 범위 정하기', '확인'];
/** SHA256:5b2e…a71c 에서 짧은 지문 */
const shortFp = (fp?: string) => (fp ? fp.replace(/^SHA256:/, '') : '');

export function useAutomation() {
  return usePoll((s) => automation(s), [], 0);
}

/** 웹 데이터 카드의 '자동 작업 계정' 줄 */
export function AutomationRow({ q }: { q: Loaded<AutomationView> }) {
  const a = q.data;
  const sc = usePoll(async (s) => (a?.userId ? accountScope(a.userId, s) : undefined), [a?.userId], 0);
  if (q.error) return <span className="muted">{noEndpoint(q.error) ? '서버 기능 대기' : '읽지 못했습니다'}</span>;
  if (!a) return <span className="muted">읽는 중…</span>;
  if (!a.configured) return <span className="muted">없음 · 사람이 없을 때 자동 백업을 쓰려면 켜 주세요</span>;
  const c = a.lastCheck;
  return (
    <>
      <span className="mono">{a.username}</span> · 키 {shortFp(a.fingerprint)}
      {sc.data?.keyOnly ? ' · 키로만 로그인' : ''}{' '}
      {!c ? <Badge tone="un">확인 안 함</Badge> : c.ok ? <Badge tone="ok">확인됨</Badge> : <Badge tone="er" title={c.error}>로그인 실패</Badge>}
    </>
  );
}

/** '자동 작업 계정 켜기…' 4단계 */
export function AutomationWizard({ cur, onClose }: { cur?: AutomationView; onClose: () => void }) {
  const [step, setStep] = useState(1);
  const [name, setName] = useState(cur?.username ?? DEFAULT_NAME);
  const [view, setView] = useState<AutomationView>();
  const [userId, setUserId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  // 2단계: put-user
  const reg = useMutation();
  const [plan, setPlan] = useState<{ id: string; revision: number; payload: Record<string, unknown> } | 'present'>();
  // 3단계: set-account-scope
  const scopeM = useMutation();
  const [scope, setScope] = useState<AccountScope>();
  const [actionsText, setActionsText] = useState(BACKUP_ACTIONS.join(', '));
  const [keyOnly, setKeyOnly] = useState(true);
  // 4단계
  const [check, setCheck] = useState<AutomationCheck & { scopeOk?: boolean }>();

  const go = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    try {
      await fn();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  // 1 → 2: 웹 데몬이 키 쌍을 만든다(이름이 같으면 있던 키 그대로). 사용자는 먼저 있어야 한다.
  const makeKey = () =>
    go(async () => {
      const u = await rawUser(name).catch((e) => {
        if (e instanceof ApiError && e.status === 404) throw new Error(`${name} 사용자가 없습니다. 사용자 화면에서 먼저 만드세요.`);
        throw e;
      });
      const v = await putAutomation(name);
      setView(v);
      setUserId(u.id);
      const add = withAutomationKey(u, v.publicKey ?? '');
      setPlan(add ? { id: add.id, revision: u.revision, payload: add.payload } : 'present');
      reg.reset();
      setStep(2);
    });

  // 2 → 3: 공개키를 로그인 수단으로 등록(관리자 서명). 이미 있으면 건너뛴다.
  const register = async () => {
    if (plan === 'present' || reg.op?.state === 'applied') return toScope();
    if (!plan) return;
    const op = await reg.submit({ action: 'add-credential', expected: plan.revision, target: name, payload: plan.payload });
    if (op?.state === 'applied') await toScope();
  };
  const toScope = () =>
    go(async () => {
      const sc = await accountScope(userId);
      setScope(sc);
      // revision은 계정 revision이라 늘 0이 아니다. 범위가 정해졌는지는 내용으로 본다
      if (sc.actions.length || sc.keyOnly) {
        setActionsText(sc.actions.join(', '));
        setKeyOnly(sc.keyOnly);
      }
      scopeM.reset();
      setStep(3);
    });

  const actions = [...new Set(actionsText.split(/[\s,·]+/).filter(Boolean))];
  const badAction = actions.find((a) => a.length > 64 || !/^[a-z0-9][a-z0-9-]*$/.test(a));
  const scopeSame = !!scope && (scope.actions.length > 0 || scope.keyOnly) && scope.keyOnly === keyOnly && sameActions(scope.actions, actions);
  // 3 → 4: 동작 범위 저장 후 그 키로 로그인해 본다
  const saveScope = async () => {
    if (scopeSame || scopeM.op?.state === 'applied') return runCheck();
    const delta = scope && scopeDelta(scope, actions, keyOnly);
    if (!delta) return runCheck();
    const op = await sendOp(scopeM, accountScopePath(userId), delta, 'PATCH');
    if (op?.state === 'applied') await runCheck();
  };
  const runCheck = () =>
    go(async () => {
      const r = await checkAutomation();
      let scopeOk: boolean | undefined;
      if (r.ok) {
        const sc = await accountScope(userId);
        scopeOk = sc.keyOnly === keyOnly && sameActions(sc.actions, actions);
      }
      setCheck({ ...r, scopeOk });
      setStep(4);
    });

  const rotate = () =>
    go(async () => {
      const v = await putAutomation(name, true);
      const u = await rawUser(name);
      setView(v);
      const add = withAutomationKey(u, v.publicKey ?? '');
      setPlan(add ? { id: add.id, revision: u.revision, payload: add.payload } : 'present');
      reg.reset();
    });

  const nameBad = name && !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(name) ? '소문자·숫자·. _ - 로 64자까지' : undefined;
  const footer =
    step === 1 ? (
      <>
        <button className="btn" onClick={onClose}>
          취소
        </button>
        <button className="btn primary" disabled={busy || !name || !!nameBad} onClick={() => void makeKey()}>
          {busy ? '만드는 중…' : cur?.configured && cur.username === name ? '다음' : '키 만들기'}
        </button>
      </>
    ) : step === 2 ? (
      <>
        <button className="btn" disabled={reg.busy || busy} onClick={() => setStep(1)}>
          이전
        </button>
        <button className="btn primary" disabled={reg.busy || busy || casFailed(reg.op)} onClick={() => void register()}>
          {reg.busy ? '서명하는 중…' : plan === 'present' || reg.op?.state === 'applied' ? '다음' : '서명하고 등록'}
        </button>
      </>
    ) : step === 3 ? (
      <>
        <button className="btn" disabled={scopeM.busy || busy} onClick={() => setStep(2)}>
          이전
        </button>
        <button className="btn primary" disabled={scopeM.busy || busy || !!badAction || actions.length > 64 || casFailed(scopeM.op)} onClick={() => void saveScope()}>
          {scopeM.busy ? '보내는 중…' : scopeSame || scopeM.op?.state === 'applied' ? '다음' : '저장'}
        </button>
      </>
    ) : (
      <>
        {!check?.ok && (
          <button className="btn" disabled={busy} onClick={() => void runCheck()}>
            다시 확인
          </button>
        )}
        <button className="btn primary" onClick={onClose}>
          닫기
        </button>
      </>
    );

  return (
    <Dialog title={`자동 작업 계정 켜기 (${step}/4)`} width={560} onClose={onClose} footer={footer}>
      <ol className="steps3">
        {STEPS.map((t, i) => (
          <li key={t} className={i + 1 < step ? 'done' : i + 1 === step ? 'on' : ''}>
            {t}
          </li>
        ))}
      </ol>
      {step === 1 && (
        <>
          <Field label="계정" hint="이미 있는 사용자 · 없으면 사용자 화면에서 먼저 만듭니다" error={nameBad}>
            <input className="mono" value={name} disabled={busy} onChange={(e) => setName(e.target.value.trim())} />
          </Field>
          <span className="small muted">개인키는 웹 앱 봉인 파일에만 있고 화면에 나오지 않습니다. 공개키 지문만 보입니다.</span>
          {cur?.configured && cur.username !== name && <div className="note wa small">이름을 바꾸면 새 키 쌍을 만듭니다. {cur.username}에 등록된 옛 공개키는 사용자 화면에서 따로 끄세요.</div>}
          {view === undefined && cur?.sealReady === false && <div className="note wa small">봉인 키가 준비되지 않아 키를 만들 수 없습니다. SFC_WEB_SEAL_KEY를 확인하세요.</div>}
        </>
      )}
      {step === 2 && view && (
        <>
          <span>
            키 <span className="mono">ed25519 · {shortFp(view.fingerprint)}</span>
          </span>
          {plan === 'present' ? (
            <div className="note ok small">이 공개키는 이미 {name}의 로그인 수단으로 등록돼 있습니다.</div>
          ) : (
            plan && (
              <>
                <pre className="code small">
                  user: {name}
                  {'\n'}+ credentials: [key {plan.id} {shortFp(view.fingerprint)}]
                </pre>
                <span className="small muted">
                  시스템 관리자 서명이 필요합니다. 내 키로 승인합니다. 다른 로그인 수단은 그대로 둡니다.{' '}
                  <button className="linkish" disabled={busy || reg.busy} onClick={() => void rotate()}>
                    키 새로 만들기
                  </button>
                </span>
              </>
            )
          )}
          {casFailed(reg.op) && <div className="note wa small">그사이 {name} 계정이 바뀌었습니다. 이전으로 돌아가 다시 진행하세요.</div>}
          <MutationError error={reg.error} />
          {reg.op && <OpPanel op={reg.op} onChange={reg.setOp} />}
        </>
      )}
      {step === 3 && (
        <>
          {!!scope?.revision && <span className="small muted mono">rev {scope.revision}</span>}
          <Field label="허용 동작" hint="웹 앱이 쓰는 것만 · 자동 백업용" error={badAction ? '동작 이름은 restart-task처럼 소문자·숫자·-로 씁니다' : undefined}>
            <input className="mono" value={actionsText} disabled={scopeM.busy || scopeM.op?.state === 'applied'} onChange={(e) => setActionsText(e.target.value)} />
          </Field>
          <label className="check">
            <input type="checkbox" checked={keyOnly} disabled={scopeM.busy || scopeM.op?.state === 'applied'} onChange={(e) => setKeyOnly(e.target.checked)} />
            <span>
              키로만 로그인 (keyOnly)
              <br />
              <span className="small muted">비밀번호·토큰으로는 로그인할 수 없습니다</span>
            </span>
          </label>
          {casFailed(scopeM.op) && <div className="note wa small">그사이 동작 범위가 바뀌었습니다. 이전으로 돌아갔다가 다시 진행하세요.</div>}
          <MutationError error={scopeM.error} />
          {scopeM.op && <OpPanel op={scopeM.op} onChange={scopeM.setOp} />}
        </>
      )}
      {step === 4 && check && (
        <>
          {check.ok ? (
            <div className={`note ${check.scopeOk ? 'ok' : 'wa'} small`}>
              <b>{check.scopeOk ? '로그인 · 범위 일치' : '로그인됨 · 범위 다름'}</b>
              <br />
              {check.scopeOk
                ? `${check.username ?? name}로 로그인했고 동작 범위가 맞습니다. 이제 자동 백업 폴더 위임을 할 수 있습니다.`
                : `${check.username ?? name}로 로그인했지만 동작 범위가 정한 값과 다릅니다. 그사이 누가 바꿨는지 사용자 화면에서 확인하세요.`}
              {check.systemAdmin && <><br />이 계정은 시스템 관리자입니다. 자동 작업 계정에는 관리자 권한을 주지 않는 것이 좋습니다.</>}
            </div>
          ) : (
            <div className="note er small">
              <b>로그인하지 못했습니다</b> ({check.error ?? '이유 없음'})
              <br />
              {check.error === 'automation-account-missing'
                ? `${name} 사용자가 없습니다. 사용자 화면에서 만든 뒤 다시 하세요.`
                : '등록한 키가 꺼졌거나, 계정이 비활성이거나, 키가 아직 반영되지 않았을 수 있습니다. 잠시 뒤 다시 확인하세요.'}
            </div>
          )}
        </>
      )}
      {error !== undefined && (error instanceof ApiError && error.code === 'seal-unavailable' ? <div className="note er small">봉인 키가 준비되지 않아 키를 만들 수 없습니다. SFC_WEB_SEAL_KEY를 확인하고 웹 앱을 다시 시작하세요.</div> : error instanceof Error && !(error instanceof ApiError) ? <div className="note er small">{error.message}</div> : <MutationError error={error} />)}
    </Dialog>
  );
}
