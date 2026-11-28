// SPDX-License-Identifier: Apache-2.0

import { useCallback, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, ApiError, newOpId } from '../api/client';
import { toOp } from '../api/endpoints';
import type { DOp } from '../api/dto';
import { ResultCodeName, type OpView } from '../api/types';
import { useAuth } from '../auth/session';
import { fmtTime } from '../lib/format';
import { OpBadge } from './ui';
import { ACTION_TITLE } from '../pages/opActionText';
import { ErrorBand } from './states';

/** POST /ops 한 건의 내용. payload 키는 sfcd Go 필드 이름(PascalCase). */
export interface Change {
  action: string;
  payload?: unknown;
  /** 대상 자원의 현재 버전(CAS). 새로 만들 때는 0 */
  expected?: number;
  tenant?: string;
  /** 표시용 */
  target?: string;
}

const ERROR_TEXT: Record<string, string> = {
  denied: '권한이 없어 sfcd가 실행 전에 거부했습니다.',
  invalid: '요청 내용이 잘못돼 sfcd가 실행 전에 거부했습니다.',
  unsupported: '이 sfcd가 아직 지원하지 않는 작업입니다.',
  expired: '요청 유효 시간이 지났습니다.',
  'ledger-full': '기록 공간이 부족합니다.',
  'not-session-issuer': '이 세션을 발급한 서버가 아니라 거부됐습니다. 다시 로그인해 주세요.',
  unknown: '응답이 유실됐습니다.',
  'not-leader': '보낸 서버가 리더가 아니었습니다.',
  unavailable: '합의를 확보하지 못했습니다.',
  closed: 'sfcd 연결이 닫혔습니다.',
  disconnected: 'sfcd 연결이 끊겼습니다.',
  'step-unknown': '단계 하나의 결과를 모릅니다. 그 단계의 결과를 먼저 조회한 뒤 같은 작업으로 이어 갑니다.',
  'limit-user-temp': '내 임시 단독 컨테이너 수가 상한에 닿았습니다.',
  'limit-tenant': '작업 공간 단독 컨테이너 수가 상한에 닿았습니다.',
  'limit-node': '이 서버의 단독 컨테이너 수가 상한(서버당 64개, 모든 작업 공간 합)에 닿았습니다. 다른 서버를 고르세요.',
  'needs-input': '값을 보내기 직전에 멈췄습니다. 같은 작업으로 값을 다시 보내면 이어 갑니다.',
  'input-unknown': '값이 받는 서버에 닿았는지 모릅니다. 같은 작업으로 결과만 확인합니다(값은 다시 보내지 않음).',
  'write-not-applied': '값이 받는 서버에 닿지 않았습니다. 새 작업으로 다시 넣어야 합니다.',
  'write-changed': '그사이 다른 쓰기가 있었습니다. 새로 읽은 뒤 다시 넣어 주세요.',
  'observation-mismatch': '받는 서버의 관측이 계획과 다릅니다. 적용하지 않았습니다.',
  'no-receiver': '값을 받을 서버가 없습니다.',
  'approval-required': '비밀번호로 보호된 묶음의 승인을 기다립니다. 묶음마다 비밀번호를 넣어 승인하면 이어서 진행합니다.',
  'bridge-exists': '같은 두 망 사이에 가상 브릿지가 이미 있습니다. 같은 두 망은 하나만 이을 수 있습니다.',
  'peer-closed': '상대 망이 없거나, 다른 작업 공간의 브릿지를 받지 않거나, 바뀌는 중입니다. 상대 관리자에게 확인해 주세요.',
  'network-changing': '망이 바뀌는 중이라 지금은 할 수 없습니다. 변경이 끝난 뒤 다시 해 주세요.',
  'bridge-attached': '이 망에 가상 브릿지가 남아 있어 지우거나 마지막 서버를 뺄 수 없습니다. 먼저 브릿지를 끊으세요.',
  'approval-rejected': '승인이 늦어 앞서 한 승인의 유효 시간이 지났고, sfcd가 작업을 거절했습니다. 새로 시작해 주세요.',
};

/**
 * 변경 한 건. 같은 의도(같은 다이얼로그)를 다시 보내면 같은 opId를 쓴다.
 * 응답이 불명이면 새 ID로 다시 제출하지 않고 같은 작업으로 결과를 묻거나 재개만 한다.
 */
type Method = 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export interface McpCallResult {
  ok: boolean;
  server: string;
  tool: string;
  error?: string;
}

export function useMutation() {
  const { session } = useAuth();
  const opId = useRef<string>(newOpId());
  const last = useRef<{ path: string; body: Record<string, unknown>; method: Method }>();
  const [op, setOp] = useState<OpView>();
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  /** op 없이 끝나는 응답(MCP 도구 호출 승인: {mcp:{ok, server, tool, error?}}) */
  const [mcp, setMcp] = useState<McpCallResult>();

  /** 전용 끝점(down, deploy, uploads abort 등)에 opId를 붙여 보낸다. */
  const run = useCallback(async (path: string, body: Record<string, unknown> = {}, method: Method = 'POST'): Promise<OpView | undefined> => {
    setBusy(true);
    setError(undefined);
    last.current = { path, body, method };
    try {
      const send = method === 'PUT' ? api.put : method === 'PATCH' ? api.patch : method === 'DELETE' ? api.del : api.post;
      const r = await send<{ op?: DOp; mcp?: McpCallResult }>(path, { ...body, opId: opId.current });
      if (!r.op) {
        if (r.mcp) setMcp(r.mcp);
        return undefined;
      }
      const v = toOp(r.op);
      setOp(v);
      return v;
    } catch (e) {
      setError(e);
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);

  /** 일반 변경: POST /ops. rootRevision 0이면 데몬이 보내기 직전 값으로 채운다. */
  const submit = useCallback(
    (c: Change) =>
      run('/ops', {
        action: c.action,
        principal: session?.user.id ?? '',
        expected: c.expected ?? 0,
        payload: c.payload ?? {},
        rootRevision: 0,
        ...(c.tenant ? { tenant: c.tenant } : {}),
        ...(c.target ? { target: c.target } : {}),
      }),
    [run, session],
  );

  /** 같은 opId·같은 내용으로 다시 보낸다(배포 이어 가기). */
  const again = useCallback(async () => {
    if (last.current) await run(last.current.path, last.current.body, last.current.method);
  }, [run]);

  const reset = useCallback(() => {
    opId.current = newOpId();
    last.current = undefined;
    setOp(undefined);
    setError(undefined);
    setMcp(undefined);
  }, []);

  return { run, submit, again, op, setOp, error, busy, reset, opId: opId.current, mcp };
}

type Mutation = ReturnType<typeof useMutation>;
/** 답을 못 받은 요청(연결 끊김·5xx)만 결과를 모른다. 4xx는 데몬이 op를 만들기 전에 거절한 것 */
export const uncertain = (e: unknown) => e !== undefined && (!(e instanceof ApiError) || e.status >= 500);
/** 결과를 모르는 요청은 같은 opId·같은 본문으로, 거절·실패 뒤에는 새 opId로 */
export const sendOp = (m: Mutation, path: string, body: Record<string, unknown>, method: 'POST' | 'PUT' | 'PATCH' | 'DELETE' = 'POST') => {
  if (uncertain(m.error) || (m.op && ['unknown', 'pending', 'running'].includes(m.op.state))) return m.again();
  if (m.op || m.error !== undefined) m.reset();
  return m.run(path, body, method);
};

export function OpPanel({ op, onChange, onContinue }: { op: OpView; onChange?: (op: OpView) => void; onContinue?: () => Promise<void> }) {
  const [busy, setBusy] = useState<'' | 'result' | 'resume' | 'step' | 'continue'>('');
  const [error, setError] = useState<unknown>();
  const [stepOp, setStepOp] = useState<OpView>();
  // 단계 원본(<opId>.<n>)을 가진 작업: 배포, 보관함 쓰기(값 넣기·묶음 비밀번호)
  const isJob = op.action === 'deploy' || op.action === 'vault-value' || op.action === 'vault-password';
  // 단계 번호는 0부터. 데몬은 0이면 step을 생략한다.
  const stepNo = op.step ?? 0;
  const stepId = isJob ? `${op.id}.${stepNo}` : '';

  const ask = async (kind: 'result' | 'resume') => {
    setBusy(kind);
    setError(undefined);
    try {
      const r = await api.post<{ op: DOp }>(`/ops/${encodeURIComponent(op.id)}/${kind}`);
      onChange?.(toOp(r.op));
    } catch (e) {
      setError(e);
    } finally {
      setBusy('');
    }
  };
  const settleStep = async () => {
    setBusy('step');
    setError(undefined);
    try {
      const r = await api.post<{ op: DOp }>(`/ops/${encodeURIComponent(stepId)}/result`);
      setStepOp(toOp(r.op));
    } catch (e) {
      setError(e);
    } finally {
      setBusy('');
    }
  };
  const cont = async () => {
    if (!onContinue) return;
    setBusy('continue');
    setError(undefined);
    try {
      await onContinue();
      setStepOp(undefined);
    } finally {
      setBusy('');
    }
  };

  return (
    <div className="inset col" style={{ gap: 8 }} aria-live="polite">
      <div className="row between">
        <span className="row">
          <OpBadge state={op.state} />
          <b title={op.action}>{ACTION_TITLE[op.action] ?? op.action}</b>
          <span className="muted">{op.target}</span>
        </span>
        <Link to={`/system/ops?focus=${encodeURIComponent(op.id)}`} className="small">
          작업 기록에서 보기
        </Link>
      </div>
      <div className="small muted">
        작업 ID <code>{op.id}</code> · 제출 {fmtTime(op.submittedAt)}
        {op.resultCode !== undefined && ` · 결과 ${op.resultCode} (${ResultCodeName[op.resultCode] ?? '?'})`}
        {op.index ? ` · 위치 ${op.index}` : ''}
        {op.steps ? ` · 단계 ${op.state === 'applied' ? op.steps : stepNo}/${op.steps} 완료` : ''}
      </div>
      {op.errorCode && op.state !== 'applied' && !op.errorCode.startsWith('result-') && <div className="small">{ERROR_TEXT[op.errorCode] ?? op.errorCode}</div>}
      {op.state === 'unknown' && !isJob && (
        <>
          <div className="note un small">결과를 모릅니다. 같은 원 작업으로 결과를 다시 묻거나 명시적으로 재개하세요. 새 ID로 다시 제출하지 않습니다.</div>
          <div className="row">
            <button type="button" className="btn sm" disabled={!!busy} onClick={() => ask('result')}>
              {busy === 'result' ? '묻는 중…' : '결과 조회'}
            </button>
            <button type="button" className="btn sm" disabled={!!busy} onClick={() => ask('resume')}>
              {busy === 'resume' ? '재개 중…' : '재개'}
            </button>
          </div>
        </>
      )}
      {op.state === 'unknown' && isJob && op.errorCode !== 'input-unknown' && (
        <>
          <div className="note un small">
            {stepNo + 1}번째 단계(<code>{stepId}</code>)의 결과를 모릅니다. 먼저 그 단계의 결과를 조회해 정산한 뒤, 같은 작업으로 다시 보내면 다음 단계부터 이어 갑니다.
          </div>
          {stepOp && (
            <div className="row small">
              <OpBadge state={stepOp.state} /> {stepOp.action} · {stepOp.state === 'unknown' ? '아직 원 결과를 찾지 못했습니다(미실행 증거 아님). 잠시 뒤 다시 물어보세요.' : '정산됐습니다.'}
            </div>
          )}
          <div className="row">
            <button type="button" className="btn sm" disabled={!!busy || !stepId} onClick={settleStep}>
              {busy === 'step' ? '묻는 중…' : `${stepNo + 1}번째 단계 결과 조회`}
            </button>
            <button
              type="button"
              className="btn sm primary"
              disabled={!!busy || !onContinue || !stepOp || stepOp.state === 'unknown'}
              title={!onContinue ? '이 화면에서는 이어 갈 수 없습니다. 배포 화면에서 같은 원문으로 이어 가세요.' : !stepOp ? '먼저 단계 결과를 조회해 주세요.' : undefined}
              onClick={cont}
            >
              {busy === 'continue' ? '이어 가는 중…' : '같은 작업으로 이어 가기'}
            </button>
          </div>
        </>
      )}
      {error ? <ErrorBand error={error} what="작업 상태를 묻지 못했습니다" /> : null}
    </div>
  );
}

/** 변경 실패 오류를 사람이 읽을 문장으로 */
export function MutationError({ error }: { error: unknown }) {
  if (!error) return null;
  const what = error instanceof ApiError && error.code === 'op-conflict' ? '같은 작업 ID로 다른 내용이 이미 제출됐습니다. 창을 닫고 다시 시작해 주세요.' : '변경을 보내지 못했습니다';
  return <ErrorBand error={error} what={what} />;
}

/** op가 조건 불일치(버전 바뀜)로 실패했는지 */
export const casFailed = (op?: OpView) => op?.state === 'failed' && op.resultCode === 1;
