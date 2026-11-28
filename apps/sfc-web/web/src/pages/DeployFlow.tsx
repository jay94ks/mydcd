// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from 'react';
import YAML from 'yaml';
import { Link } from 'react-router-dom';
import { enc } from '../api/client';
import { appPath, plan as fetchPlan } from '../api/endpoints';
import type { PlanReply } from '../api/types';
import { Badge, Card, type Tone } from '../components/ui';
import { ErrorBand } from '../components/states';
import { DiffView, yamlCheck } from '../components/Code';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { ApprovalPrompt } from './VaultApproval';
import { acmePathHits, hitRows } from '../lib/acmePath';
import { sha256Hex } from '../lib/cryptoCompat';
import { APPLY_WAY, applySummary, applyWay, interruptionText } from '../lib/planChanges';

export type FlowStep = 1 | 2 | 3 | 4;

export function Steps({ step }: { step: FlowStep }) {
  const names = ['작성·검사', '변경 미리보기', '업로드·제출', '진행'];
  return (
    <ol className="steps" aria-label="배포 단계">
      {names.map((n, i) => {
        const s = (i + 1) as FlowStep;
        return (
          <li key={n} className={s < step ? 'done' : s === step ? 'on' : ''} aria-current={s === step ? 'step' : undefined}>
            {s < step ? '✓ ' : ''}
            {s} {n}
          </li>
        );
      })}
    </ol>
  );
}

/** 배포 본문의 digest: yaml 자체의 SHA-256 hex(계획 응답의 digest와 다르다). */
export async function yamlDigest(text: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(text));
}

const CHANGE: Record<PlanReply['services'][number]['change'], [Tone, string]> = { add: ['ok', '추가'], update: ['wa', '변경'], remove: ['er', '제거'], keep: ['un', '유지'] };

/**
 * app.yaml → 검사·변경 미리보기(plan) → 업로드·제출(deploy) → 진행.
 * app.yaml · 폼 · 그래프 어느 방식이든 이 경로 하나로 배포한다(별도 배포 로직 없음).
 */
const DROPPED_KEYS = ['schema', 'tenant', 'deployment_id'];

export function DeployFlow({
  tenant,
  yaml,
  canDeploy,
  onStep,
  gitWarning,
  deployment,
  currentVersion,
}: {
  tenant: string;
  yaml: string;
  canDeploy: boolean;
  onStep?: (s: FlowStep) => void;
  gitWarning?: boolean;
  deployment?: string;
  currentVersion?: number;
}) {
  const [plan, setPlan] = useState<PlanReply>();
  const [planFor, setPlanFor] = useState<string>();
  const [planError, setPlanError] = useState<unknown>();
  const [planning, setPlanning] = useState(false);
  const [reviewed, setReviewed] = useState(false);
  const m = useMutation();
  const stale = plan && planFor !== yaml;
  const step: FlowStep = m.op ? 4 : plan && !stale ? (reviewed ? 3 : 2) : 1;
  useEffect(() => onStep?.(step), [step, onStep]);

  // 내용이 바뀌면 이전 계획·확인은 무효
  useEffect(() => {
    if (stale) setReviewed(false);
  }, [stale]);

  const check = yamlCheck(yaml);
  // app.yaml 새 형식: 작업 공간은 요청 범위, 배포 구성 ID는 서버가 정하므로 x-sfc.schema·tenant·deployment_id는 거절된다
  const dropped = useMemo(() => {
    try {
      const xm = (YAML.parse(yaml) as { 'x-sfc'?: Record<string, unknown> } | null)?.['x-sfc'];
      return xm && typeof xm === 'object' ? DROPPED_KEYS.filter((k) => k in xm) : [];
    } catch {
      return [];
    }
  }, [yaml]);
  const tenantMismatch = dropped.length > 0;
  const acmeHits = useMemo(() => acmePathHits(yaml), [yaml]);
  const acmeWarn = acmeHits.length > 0 && (
    <div className="note wa small">
      ⚠ {acmeHits.map(hitRows).join(', ')}: <code>/.well-known/acme-challenge/</code> 경로는 인증서 자동화가 쓰므로 무시됩니다. 이 경로의 요청은 언제나 웹 앱의 HTTP 확인 응답기로 갑니다. 배포는 그대로 진행합니다.
    </div>
  );
  const runPlan = async () => {
    setPlanning(true);
    setPlanError(undefined);
    try {
      const r = await fetchPlan(tenant, yaml, deployment);
      setPlan(r);
      setPlanFor(yaml);
      setReviewed(false);
      if (!m.op) m.reset();
    } catch (e) {
      setPlan(undefined);
      setPlanError(e);
    } finally {
      setPlanning(false);
    }
  };
  const deploy = async () => {
    const digest = await yamlDigest(yaml);
    await m.run(`/t/${enc(tenant)}/apps/deploy`, { yaml, digest, ...(deployment ? { deployment } : {}) });
  };

  return (
    <Card title="변경 미리보기" actions={currentVersion !== undefined && <span className="small muted">실행 중 버전 {currentVersion}</span>}>
      {!plan || stale ? (
        <>
          <p className="small muted">{stale ? '내용이 바뀌었습니다. 다시 검사하세요.' : '검사를 누르면 서버가 계획을 계산해 무엇이 바뀌는지 보여 줍니다. 아직 아무것도 바뀌지 않습니다.'}</p>
          {tenantMismatch && (
            <div className="note er small">
              app.yaml 맨 위 x-sfc의 {dropped.map((k, i) => (
                <span key={k}>
                  {i ? ', ' : ''}
                  <code>{k}</code>
                </span>
              ))}
              는 이제 쓰지 않아 거절됩니다. 지우고 다시 검사하세요. 작업 공간은 상단에서 고른 곳(<code>{tenant}</code>)으로, 배포 구성은 서버가 앱 이름으로 정합니다.
            </div>
          )}
          {acmeWarn}
          <button className="btn primary" disabled={!check.ok || planning || tenantMismatch} onClick={() => void runPlan()}>
            {planning ? '계산 중…' : '검사하고 변경 미리보기'}
          </button>
        </>
      ) : (
        <>
          <div className="row small">
            <span>
              <b>{plan.app}</b>
              {deployment ? ` · 배포 구성 ${deployment}` : ''}
            </span>
            <Badge tone="ok">추가 {plan.counts.add}</Badge>
            <Badge tone="wa">변경 {plan.counts.change}</Badge>
            {plan.counts.remove > 0 && <Badge tone="er">제거 {plan.counts.remove}</Badge>}
            <Badge tone="un">유지 {plan.counts.keep}</Badge>
          </div>
          {plan.services.length > 0 && (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>서비스</th>
                    <th>서버</th>
                    <th>이미지</th>
                    <th>변화</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.services.map((sv) => (
                    <tr key={sv.name}>
                      <td>{sv.name}</td>
                      <td>{sv.node || '—'}</td>
                      <td>
                        <code title={sv.image}>{sv.image.replace(/@sha256:(.{8}).*/, '@sha256:$1…')}</code>
                      </td>
                      <td>
                        <Badge tone={CHANGE[sv.change][0]}>{CHANGE[sv.change][1]}</Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {plan.changes.length > 0 ? <PlanChanges plan={plan} /> : plan.diff.length > 0 ? <DiffView lines={plan.diff} /> : <span className="small muted">원문 차이를 받지 못했습니다.</span>}
          {acmeWarn}
          {gitWarning && <div className="note wa small">자동 배포(Git) 앱입니다. 여기서 바꾸면 Git과 달라집니다.</div>}
          {!m.op ? (
            <>
              <label className="check">
                <input type="checkbox" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} /> 바뀌는 점을 확인했습니다
              </label>
              <div className="small muted">
                작업 ID <code>{m.opId}</code> · 같은 제출을 다시 누르면 같은 작업으로 이어 갑니다(새로 올리지 않음).
              </div>
              <div className="row between">
                <button className="btn" onClick={() => (setPlan(undefined), setReviewed(false))}>
                  이전
                </button>
                <button
                  className="btn primary"
                  disabled={!reviewed || !canDeploy || m.busy}
                  title={canDeploy ? undefined : '이 작업 공간의 배포 권한이 필요합니다'}
                  onClick={() => void deploy()}
                >
                  {m.busy ? '보내는 중…' : '업로드하고 제출'}
                </button>
              </div>
            </>
          ) : null}
          <MutationError error={m.error} />
          {m.op && (
            <>
              <OpPanel op={m.op} onChange={m.setOp} onContinue={m.again} />
              <ApprovalPrompt tenant={tenant} op={m.op} onOp={m.setOp} />
              {m.op.state === 'applied' && (
                <Link className="btn primary" to={appPath(tenant, plan.app)}>
                  앱 개요로 →
                </Link>
              )}
            </>
          )}
        </>
      )}
      {planError ? <ErrorBand error={planError} what="검사하지 못했습니다" onRetry={() => void runPlan()} /> : null}
    </Card>
  );
}

/** 바뀐 항목마다 적용 방식(Z9): 바로 적용 · 끊김 없는 교체 · 끊김 있음(이유). 그대로인 항목은 접는다 */
export function PlanChanges({ plan }: { plan: PlanReply }) {
  const [showKeep, setShowKeep] = useState(false);
  const keep = plan.changes.filter((c) => c.action === 'Keep').length;
  const rows = showKeep ? plan.changes : plan.changes.filter((c) => c.action !== 'Keep');
  const summary = applySummary(plan.changes);
  return (
    <div className="col" style={{ gap: 8 }}>
      <div className="row small" style={{ gap: 6, flexWrap: 'wrap' }}>
        <b>바뀌는 항목</b>
        {summary.length === 0 && <span className="muted">바뀌는 항목이 없습니다.</span>}
        {summary.map((s) => (
          <Badge key={s.way} tone={APPLY_WAY[s.way][0]}>
            {APPLY_WAY[s.way][1]} {s.count}
          </Badge>
        ))}
        {keep > 0 && (
          <button className="btn sm ghost" onClick={() => setShowKeep(!showKeep)}>
            {showKeep ? '그대로인 항목 숨기기' : `그대로인 항목 ${keep}개 보기`}
          </button>
        )}
      </div>
      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="tbl plan-changes">
            <thead>
              <tr>
                <th>항목</th>
                <th>적용 방식</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c, i) => {
                const w = applyWay(c);
                return (
                  <tr key={`${c.key}-${i}`}>
                    <td>
                      <code title={c.reason}>{c.key}</code>
                    </td>
                    <td>
                      <Badge tone={APPLY_WAY[w][0]} title={w === 'other' ? c.action : undefined}>
                        {APPLY_WAY[w][1]}
                      </Badge>
                      {c.interruption && <span className="small"> {interruptionText(c.interruption)}</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {plan.changes.some((c) => c.interruption) && <div className="note wa small">끊김 있음 항목은 교체하는 동안 그 서비스가 잠시 멈춥니다. 데이터를 지키는 쪽이 무중단보다 먼저입니다.</div>}
    </div>
  );
}
