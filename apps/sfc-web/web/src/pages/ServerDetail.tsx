// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { ErrorBand } from '../components/states';
import { Link, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { buildText, nodeDevices, appPath, containerPath, node as fetchNode, nodeCordonPath, nodeDiagnosticsUrl, nodeDrainStatus, nodeIsolatePath, nodeRemovePlan, nodeRemovePath, nodeDisks, imagePrune, nodeImagePrunePath, nodeImagePrunePlan, nodeStorage, nodeTasks, opsList, tenantList } from '../api/endpoints';
import { API_MODE, ApiError, noEndpoint } from '../api/client';
import { useToast } from '../components/Toast';
import { drainRunning, drainStateText } from '../lib/drain';
import { DemoteDialog, DrainDialog, ForceRemoveDialog, RotateIdentityDialog } from './NodeAdvanced';
import { eulReul, iGa } from '../lib/josa';
import type { NodeView, OpView, StorageRoot, TaskView } from '../api/types';
import { CLUSTER_APP_REASON, CLUSTER_APP_STATE, ClusterAppAddress, ClusterAppImage, clusterAppNote } from '../components/clusterApps';
import { Badge, Card, Field, HelpBox, KV, PageHeader, PhaseBadge, Tile, UsageBar, Hash, type Tone } from '../components/ui';
import { Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { NodeShellTab, ShellBadges } from './NodeShell';
import { Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { DataTable } from '../components/DataTable';
import { MutationError, OpPanel, sendOp, uncertain, useMutation } from '../components/OpPanel';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { ago, fmtBytes, fmtTime, pct } from '../lib/format';
import { DisksTable } from './Servers';
import { GatewayDialog } from './Ingress';
import { EngineTab } from './NodeEngine';
import { FirewallTab } from './NodeFirewall';
import { DiskGroups, type DiskDlg } from './NodeDisks';
import { AddRootDialog } from './StorageRootAdd';
import { DiskActionDialog } from './DiskActions';
import { GW_NAME, gwCounters, ingress, ingressMissing, listenerList, type Gateway as GatewayKind, type GatewayConf, type IngressNode } from '../api/ingress';
import { ContainerConsole } from '../components/ContainerConsole';
import { useSession, useTenantRole } from '../auth/session';
import { Sheet } from '../mobile/Sheet';
import { M_BADGE, opLine, opTitle } from './Operations';
import { ingressLive, opsLive, serverLive } from '../lib/liveTopics';

export function TaskTable({ tasks, showNode = false, showApp = true }: { tasks: TaskView[]; showNode?: boolean; showApp?: boolean }) {
  const session = useSession();
  const [open, setOpen] = useState<TaskView>();
  const canExec = (t: TaskView) => session.user.systemAdmin || session.tenants.some((x) => x.id === t.tenant && x.role === 'manager');
  const tone = (t: TaskView) => (t.observed === 'running' && !t.stale ? 'ok' : t.observed === 'exited' ? 'er' : t.observed === 'restarting' || t.observed === 'starting' ? 'pr' : 'un');
  const label: Record<TaskView['observed'], string> = { running: '실행 중', starting: '시작 중', restarting: '재시작 중', exited: '종료됨', unknown: '확인 불가' };
  return (
    <>
    <DataTable
      rows={tasks}
      rowKey={(t) => t.id}
      searchPlaceholder="컨테이너·앱·서비스 찾기"
      emptyTitle="이 범위에 컨테이너가 없습니다"
      columns={[
        { key: 'name', header: '컨테이너', value: (t) => `${t.app}-${t.service}-${t.instance}`, render: (t) => (t.standalone ? <code>{t.standalone}</code> : <Link to={containerPath(t.tenant, t.app, t.service, t.instance)} onClick={(e) => e.stopPropagation()}><code>{`${t.app}-${t.service}-${t.instance}`}</code></Link>) },
        ...(showApp
          ? [
              {
                key: 'app',
                header: '앱 / 서비스',
                value: (t: TaskView) => `${t.tenant}/${t.app}/${t.service}`,
                render: (t: TaskView) => (
                  <Link to={appPath(t.tenant, t.app)}>
                    {t.tenant} / {t.app} / {t.service}
                  </Link>
                ),
              },
            ]
          : []),
        ...(showNode ? [{ key: 'node', header: '서버', value: (t: TaskView) => t.node, render: (t: TaskView) => t.node }] : []),
        {
          key: 'state',
          header: '목표 / 실제',
          value: (t) => t.observed,
          render: (t) => (
            <span className="row" style={{ flexWrap: 'nowrap' }}>
              <span className="muted small">{t.desired === 'running' ? '실행' : '정지'} →</span>
              <Badge tone={tone(t)}>{t.stale ? '확인 불가 (보고 늦음)' : label[t.observed]}</Badge>
            </span>
          ),
        },
        { key: 'health', header: '상태 검사', value: (t) => t.health ?? '', render: (t) => (t.health === 'pass' ? '통과' : t.health === 'fail' ? <span style={{ color: 'var(--er)' }}>실패</span> : '—') },
        { key: 'restarts', header: '재시작', value: (t) => t.restarts, render: (t) => `${t.restarts}회${t.exitCode !== undefined ? ` · 종료 코드 ${t.exitCode}` : ''}` },
        { key: 'gen', header: '세대', value: (t) => t.generation, render: (t) => t.generation },
        { key: 'image', header: '이미지', value: (t) => t.image, render: (t) => <code title={t.image}>{t.image.replace(/@sha256:(.{8}).*/, '@sha256:$1…')}</code> },
        { key: 'obs', header: '마지막 보고', value: (t) => t.observedAt, render: (t) => <span className="muted">{ago(t.observedAt)}</span> },
        { key: 'check', header: '마지막 검사', value: (t) => t.lastCheck ?? '', render: (t) => <span className="muted small">{t.lastCheck ?? '—'}</span> },
        {
          key: 'console',
          header: '',
          render: (t) => (
            <button className="btn sm" onClick={(e) => (e.stopPropagation(), setOpen(t))} title="로그 따라가기 · 자원 사용 · 프로세스 · 터미널">
              로그 · 터미널
            </button>
          ),
        },
      ]}
    />
    {open && <ContainerConsole task={open} canExec={canExec(open)} onClose={() => setOpen(undefined)} />}
    </>
  );
}

/** 진단 묶음은 sfcd가 만든 tar.gz를 그대로 내려받는다. 웹은 저장하지 않는다 */
function downloadDiagnostics(node: string, toast: (s: string) => void) {
  const a = document.createElement('a');
  a.href = nodeDiagnosticsUrl(node);
  a.download = '';
  document.body.appendChild(a);
  a.click();
  a.remove();
  toast(`${node} 진단 묶음을 내려받습니다. 비밀값·개인키는 들어 있지 않습니다.`);
}

function NodeActions({ node, onDone }: { node: NodeView; onDone: () => void }) {
  const [act, setAct] = useState<'isolate' | 'restore'>();
  // 창을 연 순간의 서버 revision이 expected
  const [actRev, setActRev] = useState<number>();
  const openAct = (a: 'isolate' | 'restore') => (setActRev(node.revision), setAct(a));
  const [dlg, setDlg] = useState<'cordon' | 'uncordon' | 'prune' | 'remove' | 'drain' | 'demote' | 'rotate' | 'force'>();
  // 가장 최근 비우기: 서버 행의 drain이 없으면(REQ-70은 operation 없는 drain-status만) drain-status로 본다. 없으면 404
  const ds = usePoll((s) => nodeDrainStatus(node.id, node.drain?.operation, s), [node.id, node.drain?.operation], 30_000);
  const drainState = ds.data?.state ?? node.drain?.state;
  const toast = useToast();
  const navigate = useNavigate();
  const m = useMutation();
  // 서버 목록 줄 ⋯에서 온 ?act=isolate|drain|remove 는 그 창을 바로 연다
  const [params, setParams] = useSearchParams();
  useEffect(() => {
    const a = params.get('act');
    if (!a) return;
    params.delete('act');
    setParams(params, { replace: true });
    if (a === 'isolate' && node.phase !== 'isolated') openAct('isolate');
    else if (a === 'drain' || a === 'remove') setDlg(a);
    // 한 번만
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const close = () => {
    setAct(undefined);
    m.reset();
    onDone();
  };
  const titles = { isolate: `${node.id} 격리`, restore: `${node.id}${eulReul(node.id)} 복귀할까요?` };
  const labels = { isolate: '격리', restore: '복귀' };
  const body = {
    isolate: `${node.id}${eulReul(node.id)} 격리하면 새 업무 입장이 막히고, 시스템 관리자 복구 로그인·조회·원 작업의 종료/이관만 허용됩니다. 실행 중인 컨테이너는 정책에 따라 정리됩니다.`,
    restore: '격리를 풀고 새 배치를 다시 받습니다. 옮겨 간 컨테이너는 되돌아오지 않습니다(다음 배포·재배치 때 고루 놓임).',
  };
  return (
    <>
      <button className="btn" onClick={() => openAct('isolate')} disabled={node.phase === 'isolated'} title={node.phase === 'isolated' ? '이미 격리됨' : undefined}>
        격리
      </button>
      <button className="btn" onClick={() => openAct('restore')} disabled={node.phase !== 'isolated'} title={node.phase !== 'isolated' ? '격리된 서버만' : undefined}>
        복귀
      </button>
      <button className="btn danger" onClick={() => setDlg('remove')}>
        서버 제거
      </button>
      <Menu
        label="고급"
        button="고급 ▾"
        className="btn"
        items={[
          node.cordoned
            ? { label: '새 배치 다시 받기…', onSelect: () => setDlg('uncordon') }
            : { label: '새 배치 막기…', onSelect: () => setDlg('cordon'), disabledReason: node.phase === 'isolated' ? '격리된 서버는 이미 새 배치를 받지 않습니다' : undefined },
          { label: '이미지 캐시 정리…', onSelect: () => setDlg('prune') },
          { label: '', sep: true },
          { label: '비우기 (drain)…', onSelect: () => setDlg('drain'), disabledReason: drainState && drainRunning(drainState) ? `비우는 중 (${ds.data ? `${ds.data.moved}/${ds.data.total}` : drainStateText(drainState)})` : undefined },
          { label: '투표 서버에서 내리기…', onSelect: () => setDlg('demote'), disabledReason: !node.voter ? '투표 서버가 아닙니다' : undefined },
          { label: '서버 신원 교체…', onSelect: () => setDlg('rotate') },
          { label: 'sfcd 진단 묶음 받기', onSelect: () => downloadDiagnostics(node.id, toast), disabledReason: API_MODE === 'mock' ? '목업에는 내려받을 파일이 없습니다' : undefined },
          { label: '', sep: true },
          { label: '강제 제거…', danger: true, onSelect: () => setDlg('force') },
        ]}
      />
      {(dlg === 'cordon' || dlg === 'uncordon') && <CordonDialog node={node} on={dlg === 'cordon'} onClose={() => (setDlg(undefined), onDone())} />}
      {dlg === 'remove' && <RemoveDialog node={node} onClose={() => (setDlg(undefined), onDone())} />}
      {dlg === 'drain' && <DrainDialog node={node} onClose={() => (setDlg(undefined), onDone())} />}
      {dlg === 'demote' && <DemoteDialog node={node} onClose={() => (setDlg(undefined), onDone())} />}
      {dlg === 'rotate' && <RotateIdentityDialog node={node} onClose={() => (setDlg(undefined), onDone())} />}
      {dlg === 'force' && <ForceRemoveDialog node={node} onClose={() => setDlg(undefined)} onRemoved={() => navigate('/servers')} />}
      {dlg === 'prune' && <PruneDialog node={node.id} onClose={() => setDlg(undefined)} />}
      {act ? (
        <Dialog
          title={titles[act]}
          onClose={close}
          width={560}
          footer={
            m.op?.state === 'applied' ? (
              <button className="btn primary" onClick={close}>
                닫기
              </button>
            ) : (
              <>
                <button className="btn" onClick={close}>
                  취소
                </button>
                <button className={act === 'isolate' ? 'btn danger solid' : 'btn primary'} disabled={m.busy} onClick={() => void sendOp(m, nodeIsolatePath(node.id, act), actRev ? { expected: actRev } : {})}>
                  {m.busy ? '보내는 중…' : labels[act]}
                </button>
              </>
            )
          }
        >
          <p>{body[act]}</p>
          {m.error instanceof ApiError && m.error.code === 'unchanged' ? <div className="note small">{act === 'isolate' ? '이미 격리된 서버입니다.' : '격리된 서버가 아닙니다.'}</div> : <MutationError error={m.error} />}
          {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
        </Dialog>
      ) : null}
    </>
  );
}

/** 서버 제거 (remove-node). 미리 보기 remove-plan의 blockers가 있으면 막고, 같은 코드가 op 결과로도 온다 */
function RemoveDialog({ node, onClose }: { node: NodeView; onClose: () => void }) {
  const m = useMutation();
  const navigate = useNavigate();
  const [typed, setTyped] = useState('');
  const [rev] = useState(node.revision);
  const done = m.op?.state === 'applied';
  const unchanged = m.error instanceof ApiError && m.error.code === 'unchanged';
  const send = () => sendOp(m, nodeRemovePath(node.id), rev ? { expected: rev } : {});
  const plan = usePoll((sig) => nodeRemovePlan(node.id, sig), [node.id]);
  const p = plan.data;
  return (
    <Dialog
      title={`${node.id}${eulReul(node.id)} 클러스터에서 제거할까요?`}
      width={560}
      onClose={done ? () => navigate('/servers') : onClose}
      footer={
        done ? (
          <button className="btn primary" onClick={() => navigate('/servers')}>
            서버 목록으로
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn danger solid" disabled={m.busy || typed !== node.id || (!!p && !p.removable)} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '제거'}
            </button>
          </>
        )
      }
    >
      {plan.error && !noEndpoint(plan.error) ? (
        <ErrorBand error={plan.error} what="제거 계획을 읽지 못했습니다" onRetry={plan.refresh} />
      ) : !p ? (
        <>
          <p style={{ margin: 0 }}>
            {node.voter ? '투표 서버라 제거하면 투표 서버가 한 대 줄고, 견딜 수 있는 장애 수가 줄 수 있습니다. ' : ''}
            이 서버의 컨테이너와 저장 경로를 먼저 비워야 합니다. 막히는 이유는 작업 결과로 옵니다.
          </p>
          {plan.error ? <div className="note small">제거 전 미리 보기를 읽지 못했습니다. 막히는 이유는 작업 결과로 확인합니다.</div> : <span className="muted">읽는 중…</span>}
        </>
      ) : (
        <>
          <p style={{ margin: 0 }}>
            {p.votersBefore !== p.votersAfter
              ? `투표 서버라 제거하면 투표 서버가 ${p.votersBefore}대 → ${p.votersAfter}대가 되고, 견딜 수 있는 장애가 ${Math.floor((p.votersBefore - 1) / 2)}대 → ${p.faultToleranceAfter}대가 됩니다. `
              : ''}
            {p.tasks.length || p.storage.some((x) => !x.closed)
              ? `이 서버의 ${[p.tasks.length ? `컨테이너 ${p.tasks.length}개` : '', p.storage.filter((x) => !x.closed).length ? `닫히지 않은 저장 경로 ${p.storage.filter((x) => !x.closed).length}개${p.storage.some((x) => x.draining && !x.closed) ? '(비우는 중 포함)' : ''}` : ''].filter(Boolean).join('와 ')}를 먼저 비워야 합니다.`
              : '이 서버에는 컨테이너와 저장 경로가 없습니다.'}
          </p>
          {!p.removable && (
            <div className="note er small">
              지금은 제거할 수 없습니다:
              <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
                {p.blockers.map((b) => (
                  <li key={b.code + (b.detail ?? '')}>
                    {REMOVE_WHY[b.code] ?? b.code}
                    {b.detail ? ` (${b.detail})` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
      <Field label={`확인하려면 ${node.id} 을(를) 입력하세요`}>
        <input className="mono" value={typed} disabled={m.busy || done} onChange={(e) => setTyped(e.target.value.trim())} />
      </Field>
      {unchanged ? <div className="note small">이미 제거된 서버입니다.</div> : <MutationError error={m.error} />}
      {m.op?.errorCode && REMOVE_WHY[m.op.errorCode] && <div className="note wa small">{REMOVE_WHY[m.op.errorCode]}</div>}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
    </Dialog>
  );
}
const REMOVE_WHY: Record<string, string> = {
  LAST_VOTER: '마지막 투표 서버라 제거할 수 없습니다. 다른 서버를 투표 서버로 올린 뒤 하세요.',
  QUORUM_LOSS: '제거하면 투표 서버 과반을 잃어 제거할 수 없습니다. 투표 서버를 먼저 늘리세요.',
  SELF_REMOVAL: '지금 응답하는 sfcd 서버 자신은 제거할 수 없습니다. 다른 서버에 연결된 웹에서 하세요.',
  NODE_OPERATION_PENDING: '이 서버에 진행 중인 작업이 있습니다. 끝난 뒤 다시 하세요.',
  FIXED_VOLUME_PRESENT: '이 서버에 고정 데이터 저장소가 남아 있습니다. 먼저 옮기거나 지우세요.',
  NODE_STORAGE_NOT_DRAINED: '이 서버의 저장 경로를 아직 비우지 않았습니다. 저장 경로 탭에서 먼저 비우세요.',
};

/** 막은 사람·시각. 아직 없으면 사유만 */
const cordonWho = (n: NodeView) => [n.cordonedBy, n.cordonedAt && fmtTime(n.cordonedAt)].filter(Boolean).join(' · ');
/** '새 배치 막음' 배지 툴팁: 사유 · 누가 · 언제 */
const IDENTITY_PHASE: Record<string, string> = { preparing: '준비 중', prepared: '준비됨', activated: '새 키 사용 중', installed: '끝남' };
/** 신원 교체 단계 (데몬 #380): Preparing → Prepared → Activated → Installed */
const identityText = (phase: string) => IDENTITY_PHASE[phase.toLowerCase()] ?? phase;
export const cordonNote = (n: NodeView) => [n.cordonReason, cordonWho(n)].filter(Boolean).join(' · ') || undefined;

/** 새 배치 제외. 지금 도는 컨테이너는 그대로 두고, 새 컨테이너만 이 서버에 놓지 않는다 */
function CordonDialog({ node, on, onClose }: { node: NodeView; on: boolean; onClose: () => void }) {
  const m = useMutation();
  const [reason, setReason] = useState('');
  // 연 순간의 막기 행 revision이 expected(데몬 #380). 없으면 데몬이 그 값을 쓴다
  const [rev] = useState(node.schedulingRevision);
  const long = [...reason].length > 256;
  const send = () => sendOp(m, nodeCordonPath(node.id, on), { ...(on && reason.trim() ? { reason: reason.trim() } : {}), ...(rev ? { expected: rev } : {}) });
  const done = m.op?.state === 'applied';
  const unchanged = m.error instanceof ApiError && m.error.code === 'unchanged';
  return (
    <Dialog
      title={on ? `${node.id}에 새 배치 막기` : `${node.id}${iGa(node.id)} 새 배치를 다시 받게 할까요?`}
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
            <button className="btn primary" disabled={m.busy || long} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : on ? '새 배치 막기' : '다시 받기'}
            </button>
          </>
        )
      }
    >
      <p style={{ margin: 0 }}>
        {on
          ? '이미 도는 컨테이너는 그대로 두고, 새 배포·재배치·단독 컨테이너가 이 서버에 놓이지 않게 합니다. 비우기(drain)와 달리 아무것도 옮기지 않습니다.'
          : `${node.cordonReason ? `사유 “${node.cordonReason}”로 막아 둔 것을 풉니다` : '막아 둔 것을 풉니다'}${cordonWho(node) ? `(${cordonWho(node)})` : ''}. 이미 다른 서버로 간 컨테이너는 돌아오지 않습니다.`}
      </p>
      {on ? (
        <Field label="사유" hint="최대 256자 · 서버 목록과 이 화면 머리에 보입니다" error={long ? '256자를 넘었습니다' : undefined}>
          <input value={reason} disabled={m.busy || done} placeholder="예: 디스크 교체 예정" onChange={(e) => setReason(e.target.value)} />
        </Field>
      ) : null}
      {unchanged ? <div className="note small">이미 {on ? '새 배치를 막은' : '새 배치를 받는'} 서버입니다.</div> : <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
    </Dialog>
  );
}

const PRUNE_STATE: Record<string, string> = { queued: '정리 대기', running: '정리 중', done: '정리 끝', failed: '정리 실패' };
const PART_STATE: Record<string, [string, 'ok' | 'er' | 'un']> = { removed: ['지움', 'ok'], 'already-absent': ['이미 없음', 'ok'], failed: ['실패', 'er'], skipped: ['건너뜀', 'un'] };
function prunePart(p?: { state: string; code?: string; error?: string }) {
  if (!p) return <span className="muted">대기</span>;
  const [t, tone] = PART_STATE[p.state] ?? [p.state, 'un'];
  return (
    <span title={p.error}>
      <Badge tone={tone}>{t}</Badge>
      {p.code ? <span className="small muted"> {p.code}</span> : null}
    </span>
  );
}
/** 서버 이미지 캐시 정리. 그 서버의 Task·단독 컨테이너가 안 쓰는 이미지만. 목록이 그새 바뀌면 409 plan-changed */
function PruneDialog({ node, onClose }: { node: string; onClose: () => void }) {
  const q = usePoll((s) => nodeImagePrunePlan(node, s), [node]);
  const m = useMutation();
  // 보여 준 계획 그대로 보낸다
  const [plan, setPlan] = useState<string>();
  const shown = q.data;
  const changed = m.error instanceof ApiError && m.error.code === 'plan-changed';
  const accepted = m.op?.state === 'applied';
  // 접수 뒤 진행은 /image-prunes/op-<opId>에서 읽는다. 끝나면 더 읽지 않는다
  const opId = accepted ? m.op!.id : undefined;
  const [finished, setFinished] = useState(false);
  const pr = usePoll((s) => (opId ? imagePrune(opId, s) : Promise.resolve(undefined)), [opId]);
  const prState = pr.data?.state;
  const { setInterval: setPrInterval } = pr;
  useEffect(() => {
    if (prState === 'done' || prState === 'failed') setFinished(true);
  }, [prState]);
  // 접수된 뒤 끝날 때까지 2초마다 읽는다
  useEffect(() => setPrInterval(opId && !finished ? 2000 : 0), [opId, finished, setPrInterval]);
  const done = accepted;
  const send = () => {
    // 결과를 모르면 같은 계획으로 다시, 아니면 지금 보이는 계획으로 새 작업
    if (!uncertain(m.error) && !(m.op && ['unknown', 'pending', 'running'].includes(m.op.state))) setPlan(shown!.plan);
    return sendOp(m, nodeImagePrunePath(node), { plan: shown!.plan });
  };
  return (
    <Dialog
      title={`${node} 이미지 캐시 정리`}
      width={720}
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
            <button className="btn danger solid" disabled={m.busy || !shown || !shown.images.length || (changed && plan === shown.plan)} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : shown ? `${shown.images.length}개 지우기 · ${fmtBytes(shown.bytes)}` : '지우기'}
            </button>
          </>
        )
      }
    >
      <p style={{ margin: 0 }}>이 서버에 받아 둔 이미지 중 어느 컨테이너도 쓰지 않는 것입니다. 지워도 다음 배포 때 다시 받습니다.</p>
      {q.error ? (
        <ErrorBand error={q.error} what="정리 계획을 읽지 못했습니다" onRetry={q.refresh} />
      ) : !shown ? (
        <span className="muted">읽는 중…</span>
      ) : shown.images.length === 0 ? (
        <div className="note ok small">지울 이미지가 없습니다.</div>
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>이미지</th>
                <th>digest</th>
                <th>크기</th>
                {pr.data && <th>결과</th>}
              </tr>
            </thead>
            <tbody>
              {shown.images.map((x) => (
                <tr key={x.digest + x.ref}>
                  <td className="mono small break-any">
                    {x.ref || <span className="muted">(이름 없음)</span>}
                    {(x.aliases?.length ?? 0) > 1 && <span className="muted"> 외 {x.aliases!.length - 1}개 이름</span>}
                  </td>
                  <td className="mono small">{x.digest.replace(/^sha256:/, '').slice(0, 12)}</td>
                  <td>{fmtBytes(x.bytes)}</td>
                  {pr.data && <td>{prunePart(pr.data.parts.find((p) => p.digest === x.digest))}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {shown && (shown.remaining !== undefined || shown.inUse !== undefined) && (
        <span className="small muted">
          {shown.total !== undefined ? `받아 둔 이미지 ${shown.total}개 · ` : ''}쓰는 중이라 남김 {shown.inUse ?? '—'}개{shown.remaining ? ` · 한 번에 8개까지라 ${shown.remaining}개는 다음 정리로 넘어갑니다` : ''}. 크기는 Docker가 알린 값의 합이며 실제로 비는 공간과 다를 수 있습니다.
        </span>
      )}
      {pr.data && (
        <div className={`note small ${pr.data.state === 'failed' ? 'er' : pr.data.state === 'done' ? 'ok' : 'info'}`}>
          {PRUNE_STATE[pr.data.state] ?? pr.data.state} · 지움 {pr.data.parts.filter((p) => p.state === 'removed' || p.state === 'already-absent').length}/{pr.data.images.length || shown?.images.length || 0}
          {pr.data.state === 'done' && shown?.remaining ? ` · 남은 ${shown.remaining}개는 계획을 새로 읽어 다시 정리하세요` : ''}
        </div>
      )}
      {!!pr.error && !pr.data && <ErrorBand error={pr.error} what="정리 진행을 읽지 못했습니다" onRetry={pr.refresh} />}
      {changed && (
        <div className="note wa small row between">
          <span>그사이 이 서버의 이미지가 바뀌었습니다. 새 계획을 읽은 뒤 다시 지우세요.</span>
          <button className="btn sm" onClick={() => void q.refresh()}>
            새로 읽기
          </button>
        </div>
      )}
      {!changed && <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
    </Dialog>
  );
}

/** 휴대폰 서버 개요 (UI-M4 ④): 보기만. 서버를 바꾸는 작업은 넓은 화면에서 */
function MServerOverview({ node }: { node: NodeView }) {
  const tasks = usePoll((s) => nodeTasks(node.id, undefined, s), [node.id], DEFAULT_POLL_MS, serverLive(node.id));
  const list = tasks.data?.items ?? [];
  const bad = list.filter((t) => t.stale || t.observed !== 'running');
  const byTenant = Object.entries(list.reduce<Record<string, number>>((m, t) => ((m[t.tenant] = (m[t.tenant] ?? 0) + 1), m), {}));
  const gib = (b?: number) => (b === undefined ? '—' : (b / 1024 ** 3).toFixed(1).replace(/\.0$/, ''));
  return (
    <>
      <div className="mc">
        <div className="hd">
          <b>{PHASE_KO[node.phase] ?? node.phase}</b>
          <Badge tone="pr">{node.leader ? '리더' : node.voter ? '투표 서버' : '투표권 없음'}</Badge>
        </div>
        <div className="ln">마지막 보고 {node.observedAt ? ago(node.observedAt) : '—'}</div>
      </div>
      <div className="mtiles">
        <div className="mtile">
          <small>CPU</small>
          <b>{node.cpuPercent === undefined ? '—' : `${Math.round(node.cpuPercent)}%`}</b>
        </div>
        <div className="mtile">
          <small>메모리</small>
          <b>{gib(node.memory?.used)}</b>
          <span>/ {gib(node.memory?.total)} GiB</span>
        </div>
        <div className="mtile">
          <small>디스크</small>
          <b>{gib(node.disk?.used)}</b>
          <span>/ {gib(node.disk?.total)} GiB</span>
        </div>
        <div className="mtile">
          <small>컨테이너</small>
          <b>{node.containers ?? list.length}</b>
          <span>{bad.length ? `문제 ${bad.length}` : '문제 없음'}</span>
        </div>
      </div>
      {bad.length > 0 && (
        <>
          <div className="m-sec">
            <span>문제 있는 컨테이너</span>
          </div>
          <div className="li">
            {bad.map((t) => (
              <Link key={t.id} to={containerPath(t.tenant, t.app, t.service, t.instance)}>
                <Badge tone={t.observed === 'exited' ? 'er' : 'un'}>{t.stale || t.observed === 'unknown' ? '확인 불가' : t.observed === 'exited' ? '문제' : '진행 중'}</Badge>
                <span className="el">
                  {t.app}/{t.service}
                  {t.exitCode !== undefined ? ` · 종료 코드 ${t.exitCode}` : ''}
                </span>
                <span className="r">›</span>
              </Link>
            ))}
          </div>
        </>
      )}
      {byTenant.length > 0 && (
        <>
          <div className="m-sec">
            <span>작업 공간</span>
          </div>
          <div className="li">
            {byTenant.map(([t, c]) => (
              <div key={t}>
                {t}
                <span className="r">{c}</span>
              </div>
            ))}
          </div>
        </>
      )}
      <div className="muted small">비우기 · 내보내기 · 역할 바꾸기는 넓은 화면에서</div>
    </>
  );
}
const PHASE_KO: Record<string, string> = { ready: '준비됨', joining: '가입 대기', isolated: '격리됨', removing: '제거 중', problem: '오류', unknown: '확인 불가' };

export function ServerDetailPage() {
  const admin = !!useSession().user.systemAdmin;
  const phone = usePhone();
  return admin || phone ? <FullServerDetail /> : <ShellOnlyDetail />;
}

/** 서버 읽기 권한 없이 서버 셸 권한만 받은 사람: 셸 탭만 (캔버스 NodeShellIx v156) */
function ShellOnlyDetail() {
  const { id = '' } = useParams();
  const base = `/servers/${id}`;
  const onShell = useLocation().pathname.startsWith(`${base}/shell`);
  if (!onShell) return <Navigate to={`${base}/shell`} replace />;
  return (
    <>
      <PageHeader
        crumbs={
          <>
            <Link to="/node-shell">서버 셸</Link> / {id}
          </>
        }
        title={id}
        after={<ShellBadges node={id} />}
        ids="UI-1A"
      />
      <Tabs label="서버 상세 탭" items={[{ to: `${base}/shell`, label: '셸' }]} />
      <NodeShellTab node={id} />
    </>
  );
}

function FullServerDetail() {
  const { id = '' } = useParams();
  const n = usePoll((s) => fetchNode(id, s), [id], DEFAULT_POLL_MS, serverLive(id));
  const base = `/servers/${id}`;
  const phone = usePhone();
  const admin = !!useSession().user.systemAdmin;
  const loc = useLocation();
  const onShell = !phone && loc.pathname.startsWith(`${base}/shell`);
  const navigate = useNavigate();
  useMobileTop(
    phone
      ? {
          title: id,
          sub: n.data ? `${n.data.leader ? '리더' : n.data.voter ? '투표 서버' : '투표권 없음'}${n.data.endpoint ? ` · ${n.data.endpoint}` : ''}` : '서버',
          menu: [
            { label: '✦ 코디네이터에게 물어보기', onSelect: () => navigate('/coordinator', { state: { from: base } }) },
            { label: '비우기', wide: true },
            { label: '내보내기', wide: true, danger: true },
          ],
        }
      : undefined,
    [phone, id, n.data?.leader, n.data?.voter, n.data?.endpoint],
  );
  return (
    <>
      <PageHeader
        crumbs={
          <>
            <Link to="/servers">서버</Link> / {id}
          </>
        }
        title={id}
        after={
          n.data?.cordoned || onShell ? (
            <>
              {n.data?.cordoned && <Badge tone="wa" title={cordonNote(n.data)}>새 배치 막음</Badge>}
              {onShell && <ShellBadges node={id} />}
            </>
          ) : undefined
        }
        ids={onShell ? 'UI-1A' : loc.pathname.startsWith(`${base}/firewall`) ? 'UI-1G' : 'UI-12 · UI-14 · UI-15'}
        actions={
          phone ? undefined : <>
            <Refresh q={n} />
            {n.data && <NodeActions node={n.data} onDone={n.refresh} />}
          </>
        }
      />
      <Tabs
        label="서버 상세 탭"
        items={[
          { to: base, label: '개요' },
          { to: `${base}/containers`, label: '컨테이너' },
          { to: `${base}/storage`, label: '저장 경로' },
          ...(admin ? [{ to: `${base}/disks`, label: '디스크' }] : []),
          { to: `${base}/gateway`, label: '게이트웨이' },
          { to: `${base}/engine`, label: '엔진' },
          ...(admin ? [{ to: `${base}/firewall`, label: '방화벽 설정' }] : []),
          ...(phone ? [{ to: `${base}/ops`, label: '작업' }] : [{ to: `${base}/shell`, label: '셸' }]),
        ]}
      />
      {/* 제목 → 탭 → 내용 순서는 모든 화면이 같다. 요약 타일은 탭 아래 */}
      {n.data && !phone && <ServerTiles node={n.data} />}
      {/* 셸은 서버 읽기 권한과 따로다(서버 셸 권한만 있는 사람도 연다) */}
      {onShell ? (
        <NodeShellTab node={id} />
      ) : (
      <Load q={n} what="서버를 불러오지 못했습니다">
        {(node) => (
          <Routes>
            <Route index element={phone ? <MServerOverview node={node} /> : <Overview node={node} />} />
            <Route path="containers" element={phone ? <MContainers id={id} /> : <Containers id={id} node={node} />} />
            <Route path="storage" element={phone ? <MStorage id={id} /> : <Storage id={id} />} />
            <Route path="gateway" element={phone ? <MGateway id={id} /> : <Gateway id={id} />} />
            <Route path="engine" element={<EngineTab node={node} />} />
            {admin && <Route path="disks" element={<DiskTab id={id} />} />}
            {admin && <Route path="firewall" element={<FirewallTab node={id} />} />}
            {phone && <Route path="ops" element={<MServerOps id={id} />} />}
          </Routes>
        )}
      </Load>
      )}
    </>
  );
}

const OBSERVE_LIMIT_SEC = 300;

/** 이 서버의 가장 최근 비우기. 서버 행의 drain.operation(데몬 #341)으로, 없으면 operation 없이 drain-status를 읽는다. 없으면(404) 그리지 않는다 */
function DrainTile({ node, operation }: { node: string; operation?: string }) {
  const q = usePoll((s) => nodeDrainStatus(node, operation, s), [node, operation], 10_000);
  const d = q.data;
  if (!d) return null;
  return <Tile label="비우기" value={`${drainStateText(d.state)} ${d.moved}/${d.total}`} sub={d.blocked ? `그대로 둠 ${d.blocked}` : undefined} />;
}

/** 위쪽 요약 타일 (캔버스 NodeDetail v114): 역할 · 접속 주소 · CPU/메모리 · 마지막 보고, 있으면 비우기 · 서버 신원 교체 */
function ServerTiles({ node }: { node: NodeView }) {
  const gib = (b: number) => (b / 1024 ** 3).toFixed(1).replace(/\.0$/, '');
  const d = node.drain;
  // 응답 없음은 sfcd status(unreachable)를 따르고, 근접만 관측 한도(REQ-53, 오기 전에는 5분)의 절반으로 계산한다
  const limit = node.observeLimitSeconds || OBSERVE_LIMIT_SEC;
  const age = node.observedAt ? (Date.now() - new Date(node.observedAt).getTime()) / 1000 : undefined;
  const late = node.phase === 'unknown' ? 'over' : age !== undefined && age > limit / 2 ? 'near' : undefined;
  return (
    <div className="grid tiles sm">
      <Tile label="역할" value={node.leader ? '투표 서버 · 리더' : node.voter ? '투표 서버' : '투표권 없음'} />
      <Tile
        label="접속 주소"
        value={node.endpoint ? <span className="mono">{node.endpoint}</span> : '—'}
        sub={
          node.systemAddress ? (
            <>
              고정 주소 <span className="mono">{node.systemAddress}</span> · sfcd가 정함, 망 터널 주소로 씀
            </>
          ) : undefined
        }
      />
      <Tile
        label="CPU / 메모리"
        value={`${node.cpuPercent === undefined ? '—' : `${Math.round(node.cpuPercent)}%`} · ${node.memory ? `${gib(node.memory.used)}/${gib(node.memory.total)} GiB` : '—'}`}
      />
      <Tile
        label="마지막 보고"
        value={node.observedAt ? ago(node.observedAt) : '—'}
        tone={late === 'over' ? 'er' : undefined}
        sub={late === 'over' ? '응답 없음' : late === 'near' ? <span className="wa-text">관측 한도 근접</span> : undefined}
      />
      <DrainTile node={node.id} operation={d?.operation} />
      {node.identity && <Tile label="서버 신원 교체" value={identityText(node.identity.phase)} tone={node.identity.failure ? 'er' : undefined} sub={node.identity.failure ?? `${node.identityRotatedAt ? `${fmtTime(node.identityRotatedAt)} · ` : ''}${node.identity.operation}`} />}
    </div>
  );
}

function Overview({ node }: { node: NodeView }) {
  const { tenant, isAdmin } = useTenantRole();
  const scope = isAdmin ? undefined : tenant;
  const disks = usePoll((s) => nodeDisks(node.id, s, scope), [node.id, scope], DEFAULT_POLL_MS, serverLive(node.id));
  return (
    <>
      <div className="grid-2">
        <Card title="서버 정보">
          {/* 역할·접속 주소·마지막 보고는 위 요약 타일에 있어 여기서는 되풀이하지 않는다 */}
          <KV
            items={[
              [
                '상태',
                node.phaseReason ? (
                  <span>
                    <PhaseBadge phase={node.phase} /> <span className="small">{node.phaseReason}</span>
                    {node.failingSince && <span className="small muted"> · {fmtTime(node.failingSince)}부터 ({ago(node.failingSince)})</span>}
                  </span>
                ) : (
                  <PhaseBadge phase={node.phase} />
                ),
              ],
              ['작업 받기', node.admitsWork === undefined ? '—' : node.admitsWork ? '받음' : '받지 않음'],
              ...(node.build ? ([['이미지 빌드', node.build.enabled ? '빌드함' : <span><Badge tone={node.build.reason === 'UNKNOWN' ? 'un' : 'wa'}>{node.build.reason === 'UNKNOWN' ? '모름' : '빌드 안 함'}</Badge> · {buildText(node)}</span>]] as [string, React.ReactNode][]) : []),
              ...(node.cordoned ? ([['새 배치', <span><Badge tone="wa">막음</Badge> · 사유 {node.cordonReason ?? '—'}{cordonWho(node) ? ` · ${cordonWho(node)}` : ''}</span>]] as [string, React.ReactNode][]) : []),
              ['서버 키', node.key ? <Hash value={node.key} /> : '—'],
              ['버전', node.revision ?? '—'],
              ...(node.identity ? ([['서버 신원 교체', `${identityText(node.identity.phase)} · ${node.identityRotatedAt ? fmtTime(node.identityRotatedAt) : '—'} · ${node.identity.operation}${node.identity.failure ? ` · ${node.identity.failure}` : ''}`]] as [string, React.ReactNode][]) : []),
            ]}
          />
          {node.pendingOperation && (
            <div className="note un small">
              진행 중인 가입 작업 <code>{node.pendingOperation}</code>
            </div>
          )}
        </Card>
        <Card title="자원 사용">
          <UsageBar label="CPU" used={node.cpuPercent} total={node.cpuPercent === undefined ? undefined : 100} text={node.cpuPercent === undefined ? '—' : `${Math.round(node.cpuPercent)}%`} />
          <UsageBar label="메모리" used={node.memory?.used} total={node.memory?.total} text={node.memory ? `${fmtBytes(node.memory.used)} / ${fmtBytes(node.memory.total)}` : '—'} />
          <UsageBar label="디스크" used={node.disk?.used} total={node.disk?.total} text={node.disk ? `${pct(node.disk.used, node.disk.total)}%` : '—'} />
          {node.containers !== undefined && <span className="small">컨테이너 {node.containers}개</span>}
        </Card>
      </div>
      <Card title="디스크" actions={<Refresh q={disks} />}>
        <Load q={disks}>{(d) => <DisksTable disks={d} />}</Load>
      </Card>
    </>
  );
}

function Containers({ id, node }: { id: string; node: NodeView }) {
  const t = usePoll((s) => nodeTasks(id, undefined, s), [id], DEFAULT_POLL_MS, serverLive(id));
  const { isAdmin } = useTenantRole();
  return (
    <>
      <HelpBox terms="컨테이너 (Task) · 목표 (Desired) · 실제 상태 (Observed) · 세대 (generation) · 클러스터 앱 (cluster app)">
        <b>이 탭은</b> 이 서버에서 도는 컨테이너를 봅니다. 컨테이너를 직접 시작·정지하지 않습니다. 앱 단위로 바꾸려면 앱 이름을 눌러 배포 화면으로 가세요.
      </HelpBox>
      <Card title="컨테이너" actions={<Refresh q={t} />}>
        <Load q={t}>{(p) => <TaskTable tasks={p.items} />}</Load>
        <span className="small muted">컨테이너 목록은 이 서버가 보낸 마지막 관측입니다.</span>
      </Card>
      {isAdmin && <ClusterAppsCard node={node} />}
    </>
  );
}

/** 클러스터 앱 (캔버스 NodeDetail v202 #builtin). 보기만: 켜고 끄기는 node.yaml의 cluster_apps가 정한다 */
function ClusterAppsCard({ node }: { node: NodeView }) {
  const apps = node.clusterApps ?? [];
  return (
    <Card
      title="클러스터 앱 (cluster apps)"
      actions={
        <span className="muted" style={{ fontSize: 12 }}>
          보기만 · 서버 설정 node.yaml의 <span className="mono">cluster_apps</span>가 정함
        </span>
      }
    >
      {apps.length === 0 ? (
        <span className="small muted">이 서버에서 켠 클러스터 앱이 없습니다.</span>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>앱</th>
                <th>클러스터 앱 이미지 (cluster app image)</th>
                <th>상태</th>
                <th>주소</th>
                <th>올리기 · 내리기</th>
              </tr>
            </thead>
            <tbody>
              {apps.map((a) => {
                const [tone, label] = node.stale ? (['un', '확인 불가 (보고 늦음)'] as [Tone, string]) : CLUSTER_APP_STATE[a.state] ?? (['un', a.state] as [Tone, string]);
                const note = clusterAppNote(a.name);
                return (
                  <tr key={a.name}>
                    <td>
                      <span className="col" style={{ gap: 2 }}>
                        <b>{a.name}</b>
                        {note && <span className="muted" style={{ fontSize: 11 }}>{note}</span>}
                      </span>
                    </td>
                    <td>
                      <ClusterAppImage a={a} />
                    </td>
                    <td>
                      <span className="col" style={{ gap: 2 }}>
                        <Badge tone={tone}>{label}</Badge>
                        {a.restarts > 0 && <span className="muted" style={{ fontSize: 11 }}>재시작 {a.restarts}</span>}
                        {a.reason && a.state !== 'refused' && <span className="wa-text" style={{ fontSize: 11 }}>{CLUSTER_APP_REASON[a.reason] ?? a.reason}</span>}
                      </span>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {a.state === 'refused' ? (
                        <>
                          이미 {a.runningOn ? <Link to={`/servers/${encodeURIComponent(a.runningOn)}/containers`}>{a.runningOn}</Link> : '다른 서버'}에서 실행 중
                        </>
                      ) : a.address || a.ports?.length ? (
                        <ClusterAppAddress a={a} />
                      ) : (
                        '—'
                      )}
                    </td>
                    <td>
                      {a.control === 'node-config' ? (
                        <span className="col" style={{ gap: 2 }}>
                          <span>node.yaml로만</span>
                          <span className="muted" style={{ fontSize: 11 }}>웹·CLI에서 내리기 · 지우기 · 다시 시작 없음</span>
                        </span>
                      ) : (
                        <span className="mono small">{a.control}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <span className="small muted">
        클러스터 앱은 sfcd에 들어 있는 클러스터 앱 이미지로 띄우는 클러스터 공용 앱입니다. 같은 앱은 클러스터 전체에서 한 서버에서만 돕니다. 서버의 node.yaml에서 켜도 다른 서버에서 이미 돌고 있으면 거부됩니다. 작업 공간에 속하지 않아 배포된 앱 목록, 이미지 목록, 위 컨테이너 표에는 나오지 않습니다. 클러스터 전체는 <Link to="/servers/cluster-apps">서버 › 클러스터 앱</Link>에서 봅니다. 할 수 있는 조작은 앱마다 정한 정책을 따르고, 정책이 허용하지 않는 조작 버튼은 두지 않습니다. 이미지는 sfcd를 새 버전으로 바꿀 때 함께 바뀝니다.
      </span>
    </Card>
  );
}

/** 디스크 탭 (#689): 시스템 관리자만. 포맷·마운트·마운트 풀기·기록 지우기(3단계), 마운트에 '여기에 저장 경로 만들기' → 저장 경로 추가 창(경로 채움) */
function DiskTab({ id }: { id: string }) {
  const dev = usePoll((s) => nodeDevices(id, s), [id], 0, serverLive(id));
  const r = usePoll((s) => nodeStorage(id, s), [id], 0, serverLive(id));
  const [path, setPath] = useState<string>();
  const [dlg, setDlg] = useState<DiskDlg>();
  const changed = () => {
    r.refresh();
    dev.refresh();
  };
  return (
    <>
      <Load q={dev} what="디스크 목록을 읽지 못했습니다">
        {(d) => <DiskGroups dev={d} live={dev.live} refresh={<Refresh q={dev} poll={false} />} roots={r.data?.items ?? []} onMakeRoot={setPath} onAction={setDlg} />}
      </Load>
      {path !== undefined && <AddRootDialog node={id} dev={dev.data} taken={r.data?.items ?? []} initialMount={path} onClose={() => setPath(undefined)} onDone={changed} onReload={() => dev.refresh()} />}
      {dlg && dev.data && <DiskActionDialog node={id} dlg={dlg} dev={dev.data} roots={r.data?.items ?? []} onClose={() => setDlg(undefined)} onChanged={changed} />}
    </>
  );
}

function Storage({ id }: { id: string }) {
  const nav = useNavigate();
  const r = usePoll((s) => nodeStorage(id, s), [id], 0, serverLive(id));
  const disks = usePoll((s) => nodeDisks(id, s), [id], 0, serverLive(id));
  const dev = usePoll((s) => nodeDevices(id, s), [id], 0, serverLive(id));
  const [dlg, setDlg] = useState<{ kind: 'add' } | { kind: 'policy' | 'drain' | 'remove'; root: StorageRoot }>();
  const close = () => setDlg(undefined);
  const used = (x: StorageRoot) => disks.data?.find((d) => d.roots.includes(x.name));
  const state = (x: StorageRoot) =>
    x.closed ? <Badge tone="un">비움 · 등록 해제 가능</Badge> : x.draining ? <Badge tone="wa">비우기 중</Badge> : x.attested === false ? <Badge tone="wa">서버 확인 대기</Badge> : <Badge tone="ok">사용 중</Badge>;
  return (
    <>
      <HelpBox terms="저장 경로 (node storage root) · 비우기 (drain)">
        <b>이 탭은</b> 이 서버에서 데이터 저장소를 둘 수 있는 경로와 허용 작업 공간을 관리합니다. 경로를 더할 때 디스크를 고르면 그 마운트 위치 아래에 하위 경로를 만들고, 미사용 디스크는 포맷·마운트까지 합니다.
      </HelpBox>
      <Card
        title="저장 경로"
        actions={
          <>
            <Refresh q={r} poll={false} />
            <button className="btn primary" onClick={() => setDlg({ kind: 'add' })}>
              경로 추가
            </button>
          </>
        }
      >
        <Load q={r}>
          {(p) => (
            <DataTable
              rows={p.items}
              rowKey={(x) => x.name}
              pageInfo={p}
              emptyTitle="등록한 저장 경로가 없습니다"
              columns={[
                {
                  key: 'name',
                  header: 'ID',
                  value: (x) => x.name,
                  render: (x) => (
                    <span className="row" style={{ gap: 6 }}>
                      <b>{x.name}</b>
                      {x.isDefault && <Badge tone="tag">기본</Badge>}
                    </span>
                  ),
                },
                { key: 'path', header: '경로', value: (x) => x.path, render: (x) => <code>{x.path}</code> },
                { key: 'tenants', header: '허용 작업 공간', value: (x) => (x.allTenants ? '*' : x.tenants.join(',')), render: (x) => (x.allTenants ? '모든 작업 공간' : x.tenants.join(', ') || '—') },
                {
                  key: 'use',
                  header: '사용',
                  value: (x) => used(x)?.used ?? 0,
                  render: (x) => {
                    const d = used(x);
                    if (x.draining || x.closed || x.attested === false) return state(x);
                    return (
                      <span className="col" style={{ gap: 2 }}>
                        <span>{d ? `${fmtBytes(d.used)} / ${fmtBytes(d.total)}` : '—'}</span>
                        <span className="small muted">
                          데이터 저장소 {x.volumes ?? '—'}개 · {capText(x.capacityBytes)}
                        </span>
                      </span>
                    );
                  },
                },
                {
                  key: 'menu',
                  header: '',
                  render: (x) => (
                    <Menu
                      label={`${x.name} 작업`}
                      items={[
                        { label: '허용 작업 공간·용량 한도 바꾸기', onSelect: () => setDlg({ kind: 'policy', root: x }), disabledReason: x.draining ? '비우는 중인 경로는 바꿀 수 없습니다' : undefined },
                        { label: '이 경로의 데이터 저장소 보기', onSelect: () => nav(`/shared/volumes?q=${encodeURIComponent(`${x.node}/${x.name}`)}`) },
                        { label: '', sep: true },
                        { label: '비우기…', onSelect: () => setDlg({ kind: 'drain', root: x }), disabledReason: x.draining ? '이미 비우는 중' : undefined },
                        {
                          label: '등록 해제…',
                          danger: true,
                          hint: '비어 있을 때만',
                          onSelect: () => setDlg({ kind: 'remove', root: x }),
                          disabledReason: !x.draining ? '먼저 비우기를 하세요' : !x.closed ? '서버가 아직 비움을 확인하지 않았습니다' : x.volumes ? `등록된 데이터 저장소 ${x.volumes}개가 남아 있습니다` : undefined,
                        },
                      ]}
                    />
                  ),
                },
              ]}
            />
          )}
        </Load>
        <span className="small muted">디스크를 고르면 하위 경로를 sfcd가 만듭니다. 직접 마운트한 곳은 ‘경로 직접 적기’로 이미 있는 경로를 적습니다.</span>
      </Card>
      {dlg?.kind === 'add' && <AddRootDialog node={id} dev={dev.data} taken={r.data?.items ?? []} onClose={close} onDone={() => (r.refresh(), dev.refresh())} onReload={() => dev.refresh()} />}
      {dlg?.kind === 'policy' && <RootDialog node={id} root={dlg.root} taken={[]} onClose={close} onDone={() => r.refresh()} />}
      {(dlg?.kind === 'drain' || dlg?.kind === 'remove') && <RootStepDialog kind={dlg.kind} root={dlg.root} onClose={close} onDone={() => r.refresh()} />}
    </>
  );
}

const GiB = 1024 ** 3;
/** 저장 경로 용량 한도 글: 0·없음 = 한도 없음 */
export const capText = (b?: number) => (b === undefined ? '한도 모름' : b === 0 ? '한도 없음' : `한도 ${fmtBytes(b)}`);

/**
 * 바뀐 것만 보낸다(#684). 모든 작업 공간으로 바꾸면 allTenants만, 목록으로 돌아오면 allTenants:false와 새 목록을 addTenants로,
 * 그대로면 더하거나 뺀 작업 공간. 용량 한도는 칸을 고쳤을 때만(undefined = 손대지 않음, 0 = 한도 없음).
 * GiB로 반올림해 보여 주므로, 고치지 않은 한도를 다시 보내면 CLI로 정한 바이트 값이 바뀔 수 있다.
 */
export function storagePolicyDelta(root: StorageRoot, next: { tenants: string[]; all: boolean; capacityBytes?: number }) {
  const wasAll = !!root.allTenants;
  const before = new Set(wasAll ? [] : root.tenants);
  const after = new Set(next.all ? [] : next.tenants);
  const add = [...after].filter((t) => !before.has(t)).sort();
  const remove = wasAll ? [] : [...before].filter((t) => !after.has(t)).sort();
  return {
    ...(next.all !== wasAll ? { allTenants: next.all } : {}),
    ...(next.all ? {} : { ...(add.length ? { addTenants: add } : {}), ...(remove.length ? { removeTenants: remove } : {}) }),
    ...(next.capacityBytes !== undefined && next.capacityBytes !== (root.capacityBytes ?? 0) ? { capacityBytes: next.capacityBytes } : {}),
    expected: root.revision,
  };
}

function RootDialog({ node, root, taken, initialPath, onClose, onDone }: { node: string; root?: StorageRoot; taken: StorageRoot[]; initialPath?: string; onClose: () => void; onDone: () => void }) {
  const ts = usePoll((s) => tenantList(s), []);
  const [rid, setRid] = useState('');
  const [path, setPath] = useState(initialPath ?? '');
  const [all, setAll] = useState(!!root?.allTenants);
  const [tenants, setTenants] = useState<string[]>(root?.allTenants ? [] : (root?.tenants ?? []));
  const [cap, setCap] = useState(root?.capacityBytes ? String(Math.round((root.capacityBytes / GiB) * 100) / 100) : '');
  const [capTouched, setCapTouched] = useState(false);
  const m = useMutation();
  const idErr = !root && !m.op && rid && (!/^[a-z][a-z0-9-]{0,62}$/.test(rid) ? '영문 소문자로 시작하고 영문 소문자·숫자·-만 씁니다(63자까지)' : taken.some((x) => x.name === rid) ? '이 서버에 같은 ID가 있습니다' : undefined);
  const pathErr = !root && !m.op && path && (!path.startsWith('/') || path === '/' || /(^|\/)\.\.?(\/|$)/.test(path) || path.includes('//') ? '/로 시작하는 정리된 절대 경로여야 합니다(/ 자체, .., // 안 됨)' : taken.some((x) => x.path === path.replace(/\/$/, '')) ? '이미 등록한 경로입니다' : undefined);
  const capBytes = cap.trim() ? Math.round(Number(cap) * GiB) : 0;
  const capErr = (!root || capTouched) && cap.trim() && !(Number(cap) > 0 && capBytes <= 2 ** 60) ? '0보다 큰 GiB 값(비우면 한도 없음)' : undefined;
  const next = { tenants, all, capacityBytes: root && !capTouched ? undefined : capBytes };
  const delta = root ? storagePolicyDelta(root, next) : undefined;
  const changed = !!delta && Object.keys(delta).some((k) => k !== 'expected');
  const ready = !capErr && (root ? changed : rid && path && !idErr && !pathErr);
  const send = () =>
    root
      ? m.run(`/nodes/${encodeURIComponent(node)}/storage/${encodeURIComponent(root.name)}`, storagePolicyDelta(root, next), 'PATCH')
      : m.run(`/nodes/${encodeURIComponent(node)}/storage`, { id: rid, path: path.replace(/\/$/, ''), tenants: all ? [] : [...tenants].sort(), ...(all ? { allTenants: true } : {}), ...(capBytes ? { capacityBytes: capBytes } : {}) });
  return (
    <Dialog
      title={root ? `${root.name} 허용 작업 공간·용량 한도` : `저장 경로 추가 (${node})`}
      onClose={onClose}
      width={560}
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
            <button className="btn primary" disabled={!ready || m.busy} onClick={() => void send().then((op) => op?.state === 'applied' && onDone())}>
              {root ? '저장' : '추가'}
            </button>
          </>
        )
      }
    >
      {!root && (
        <>
          <Field label="ID" error={idErr}>
            <input className="mono" value={rid} onChange={(e) => setRid(e.target.value.trim())} placeholder="ssd-2" disabled={!!m.op} />
          </Field>
          <Field label="경로 (이미 마운트된 절대 경로)" error={pathErr}>
            <input className="mono" value={path} onChange={(e) => setPath(e.target.value.trim())} placeholder="/srv/sfc/ssd2" disabled={!!m.op} />
          </Field>
        </>
      )}
      <Field label="허용 작업 공간" group hint={all ? '새로 생기는 작업 공간도 씁니다' : undefined}>
        <label className="check">
          <input type="checkbox" checked={all} disabled={!!m.op} onChange={(e) => setAll(e.target.checked)} /> 모든 작업 공간
        </label>
        {!all && (
          <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
            {(ts.data ?? []).map((t) => (
              <label key={t.id} className={`choice ${tenants.includes(t.id) ? 'on' : ''}`}>
                <input type="checkbox" checked={tenants.includes(t.id)} disabled={!!m.op} onChange={(e) => setTenants(e.target.checked ? [...tenants, t.id] : tenants.filter((x) => x !== t.id))} /> {t.id}
              </label>
            ))}
          </span>
        )}
      </Field>
      <Field label="용량 한도 (GiB, 비우면 제한 없음)" error={capErr} hint={`이 경로에 등록하는 고정 데이터 저장소 용량의 합 상한입니다. 한도가 있으면 용량을 적은 등록만 받습니다.${root?.volumes !== undefined ? ` 지금 데이터 저장소 ${root.volumes}개` : ''}`}>
        <input inputMode="decimal" value={cap} onChange={(e) => (setCap(e.target.value.replace(/[^\d.]/g, '')), setCapTouched(true))} disabled={!!m.op} placeholder="제한 없음" style={{ width: 160 }} />
      </Field>
      {root?.isDefault && <div className="note info small">서버가 스스로 등록한 기본 저장 경로입니다. 처음에는 모든 작업 공간이 한도 없이 씁니다.</div>}
      {!root && <div className="note">추가하면 서버가 경로(있는지·파일 시스템·남은 공간·다른 경로와 겹침)를 확인합니다. 확인이 끝날 때까지 목록에 ‘서버 확인 대기’로 보입니다.</div>}
      {m.op?.state === 'failed' && <div className="note wa small">서버가 받지 않았습니다. 그사이 경로가 바뀌었거나, 용량 한도가 이미 등록된 용량 합보다 작습니다. 목록을 다시 읽은 뒤 해 주세요.</div>}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

function RootStepDialog({ kind, root, onClose, onDone }: { kind: 'drain' | 'remove'; root: StorageRoot; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [confirm, setConfirm] = useState('');
  const path = `/nodes/${encodeURIComponent(root.node)}/storage/${encodeURIComponent(root.name)}`;
  // 비우기 뒤 서버가 닫힘을 알리면 revision이 한 번 더 오르므로, 지우기 직전에 행을 다시 읽어 그 값을 쓴다.
  const send = async () => {
    if (kind === 'drain') return m.run(`${path}/drain`, { expected: root.revision });
    const fresh = (await nodeStorage(root.node).catch(() => undefined))?.items.find((x) => x.name === root.name);
    return m.run(path, { expected: fresh?.revision ?? root.revision }, 'DELETE');
  };
  return (
    <Dialog
      title={kind === 'drain' ? `${root.name} 비우기` : `${root.name} 등록을 해제할까요?`}
      danger={kind === 'remove'}
      onClose={onClose}
      width={560}
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
            <button className={`btn ${kind === 'drain' ? 'primary' : 'danger solid'}`} disabled={confirm !== root.name || m.busy} onClick={() => void send().then((op) => op?.state === 'applied' && onDone())}>
              {kind === 'drain' ? '비우기 시작' : '등록 해제'}
            </button>
          </>
        )
      }
    >
      <p>
        {kind === 'drain'
          ? '이 경로에 새 데이터 저장소를 두지 않습니다. 이미 있는 데이터 저장소는 그대로 남으니, 옮기거나 지운 뒤 등록을 해제하세요. 비우기는 되돌릴 수 없습니다.'
          : '서버가 비움을 확인한 경로를 목록에서 지웁니다. 디스크의 파일은 지우지 않습니다.'}
      </p>
      <Field label={<>확인하려면 <b className="mono">{root.name}</b>을(를) 입력하세요</>}>
        <input className="mono" value={confirm} onChange={(e) => setConfirm(e.target.value)} disabled={!!m.op} />
      </Field>
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

/** 외부 접속 게이트웨이 (캔버스 NodeDetail 'UI-5A') */
function Gateway({ id }: { id: string }) {
  const admin = !!useSession().user.systemAdmin;
  const q = usePoll((s) => ingress({ node: id }, s), [id], DEFAULT_POLL_MS, ingressLive());
  const [edit, setEdit] = useState<IngressNode>();
  const x = q.data?.nodes.find((n) => n.node === id);
  const cols = { gridTemplateColumns: '90px minmax(0,1.3fr) minmax(0,1fr) minmax(0,1.2fr) 70px' };
  const row = (kind: GatewayKind, g?: GatewayConf) => (
    <div key={kind} className="gr" style={cols}>
      <span>{GW_NAME[kind]}</span>
      <span className={g ? 'mono' : 'muted'}>{g ? `${g.address} ${g.ports.map((p) => `:${p}`).join(' ')}` : '꺼짐'}</span>
      <span>{!g ? <Badge tone="un">꺼짐</Badge> : g.state === 'listening' ? <Badge tone="ok">정상</Badge> : g.state === 'error' ? <Badge tone="er">오류</Badge> : <Badge tone="un">꺼짐</Badge>}</span>
      <span className={g?.listeners.length ? 'mono small' : 'muted'} title={g ? gwCounters(g) || undefined : undefined}>{g ? listenerList(g) || '—' : '—'}</span>
      <span>{g?.rules ?? '—'}</span>
    </div>
  );
  return (
    <Card
      title="외부 접속 게이트웨이"
      actions={
        <button className="btn" disabled={!admin || !x} title={admin ? undefined : '시스템 관리자만 바꿉니다'} onClick={() => x && setEdit(x)}>
          게이트웨이 설정
        </button>
      }
    >
      {q.error !== undefined && ingressMissing(q.error) ? (
        <p className="small muted">이 서버의 외부망·로컬망 받는 주소, 수신 주소, 규칙 수를 보여 줍니다. 서버 기능 대기.</p>
      ) : (
        <Load q={q} rows={2} what="게이트웨이를 읽지 못했습니다">
          {() =>
            !x || !x.module ? (
              <div className="note un small">이 서버는 외부 접속이 꺼져 있습니다(서버 설정 modules.ingress){x?.isolated ? ' · 격리됨' : ''}.</div>
            ) : (
              <>
                <div className="gtbl">
                  <div className="gr th" style={cols}>
                    <span>종류</span>
                    <span>받는 주소</span>
                    <span>상태</span>
                    <span>수신 주소</span>
                    <span>규칙</span>
                  </div>
                  {row('external', x.external)}
                  {row('local', x.local)}
                </div>
                <span className="small muted">
                  주소는 이 서버에 실제로 있는 주소만 고를 수 있고, 함께 쓰는 :443/:80에는 0.0.0.0을 쓸 수 없습니다. 지금 요청 {x.rps.toLocaleString('ko-KR')}/s · 연결 {x.connections.toLocaleString('ko-KR')} / {x.connectionLimit.toLocaleString('ko-KR')} · <Link to={`/shared/ingress?view=node&pick=${id}`}>외부 접속 화면에서 보기</Link>
                </span>
              </>
            )
          }
        </Load>
      )}
      {edit && <GatewayDialog x={edit} onClose={() => setEdit(undefined)} onDone={q.refresh} />}
    </Card>
  );
}

// ── 휴대폰 서버 탭 (UI-M10 ③ ④) ─────────────────────

const M_STATE: Record<string, string> = { all: '실제 상태', running: '실행 중', starting: '시작 중', restarting: '재시작 중', exited: '종료됨', unknown: '확인 불가' };
const taskState = (t: TaskView): ['ok' | 'er' | 'wa' | 'pr' | 'un', string] =>
  t.stale || t.observed === 'unknown' ? ['un', '확인 불가'] : t.observed === 'running' ? ['ok', '실행 중'] : t.observed === 'restarting' ? ['wa', '재시작 중'] : t.observed === 'exited' ? ['er', '종료됨'] : ['pr', '시작 중'];
const checkText = (t: TaskView) =>
  t.health === 'pass' ? `통과${t.lastCheck ? ` ${isNaN(Date.parse(t.lastCheck)) ? t.lastCheck : ago(t.lastCheck)}` : ''}` : t.health === 'fail' ? `실패${t.exitCode ? ` · 종료 코드 ${t.exitCode}` : ''}` : t.health === 'starting' ? '검사 시작 중' : '검사 없음';

/** 컨테이너 탭: 작업 공간 칩 + 실제 상태 시트, 카드를 누르면 컨테이너 상세 */
function MContainers({ id }: { id: string }) {
  const t = usePoll((s) => nodeTasks(id, undefined, s), [id], DEFAULT_POLL_MS, serverLive(id));
  const nav = useNavigate();
  const [tenant, setTenant] = useState('');
  const [state, setState] = useState('all');
  const [sheet, setSheet] = useState(false);
  const all = t.data?.items ?? [];
  const tenants = [...new Set(all.map((x) => x.tenant))].sort();
  const stateOf = (x: TaskView) => (x.stale ? 'unknown' : x.observed);
  const rows = all.filter((x) => (!tenant || x.tenant === tenant) && (state === 'all' || stateOf(x) === state));
  return (
    <>
      <div className="mchips">
        <button type="button" className={`mchip${tenant === '' ? ' on' : ''}`} onClick={() => setTenant('')}>
          전체
        </button>
        {tenants.map((x) => (
          <button key={x} type="button" className={`mchip${tenant === x ? ' on' : ''}`} onClick={() => setTenant(tenant === x ? '' : x)}>
            {x}
          </button>
        ))}
        <button type="button" className={`mchip${state !== 'all' ? ' on' : ''}`} onClick={() => setSheet(true)}>
          {M_STATE[state]} ▾
        </button>
      </div>
      <Load q={t} what="컨테이너를 불러오지 못했습니다">
        {() =>
          rows.length === 0 ? (
            <span className="muted small">{all.length ? '조건에 맞는 컨테이너가 없습니다.' : '이 서버에 컨테이너가 없습니다.'}</span>
          ) : (
            <>
              {rows.map((x) => {
                const [tone, label] = taskState(x);
                const bad = x.health === 'fail' || (x.observed === 'restarting' && !x.stale);
                const name = x.standalone ?? `${x.app}-${x.service}-${x.instance}`;
                return (
                  <button
                    key={x.id}
                    type="button"
                    className={`mc${bad ? ' xer' : tone === 'un' ? ' xwa' : ''}`}
                    style={{ textAlign: 'left', font: 'inherit' }}
                    onClick={() => nav(x.standalone ? '/standalone' : containerPath(x.tenant, x.app, x.service, x.instance))}
                  >
                    <div className="hd">
                      <b>{name}</b>
                      <Badge tone={tone}>{label}</Badge>
                    </div>
                    <div className="ln">
                      {x.standalone ? '단독 컨테이너' : `${x.app} / ${x.service}`} · {x.tenant}
                      {x.restarts ? ` · 재시작 ${x.restarts}` : ''} · {checkText(x)}
                    </div>
                  </button>
                );
              })}
            </>
          )
        }
      </Load>
      {sheet && (
        <Sheet title="실제 상태" onClose={() => setSheet(false)}>
          <div className="li">
            {Object.entries(M_STATE).map(([k, l]) => (
              <button key={k} type="button" onClick={() => (setState(k), setSheet(false))}>
                {k === 'all' ? '전체' : l}
                <span className="r">{state === k ? '✓' : ''}</span>
              </button>
            ))}
          </div>
        </Sheet>
      )}
    </>
  );
}

/** 저장 경로 탭: 경로마다 카드 (ID + 경로, 허용 작업 공간 · 사용) */
function MStorage({ id }: { id: string }) {
  const r = usePoll((s) => nodeStorage(id, s), [id], 0, serverLive(id));
  const disks = usePoll((s) => nodeDisks(id, s), [id], 0, serverLive(id));
  return (
    <>
      <Load q={r} what="저장 경로를 불러오지 못했습니다">
        {(p) =>
          p.items.length === 0 ? (
            <span className="muted small">등록한 저장 경로가 없습니다.</span>
          ) : (
            <>
              {p.items.map((x) => {
                const d = disks.data?.find((k) => k.roots.includes(x.name));
                return (
                  <div key={x.name} className="mc">
                    <div className="hd">
                      <b>{x.name}</b>
                      <span className="muted mono" style={{ fontSize: 12 }}>
                        {x.path}
                      </span>
                    </div>
                    <div className="ln">
                      {x.tenants.join(', ') || '허용 작업 공간 없음'} · {d ? `${fmtBytes(d.used)} / ${fmtBytes(d.total)}` : '사용량 모름'}
                    </div>
                    {(x.draining || x.closed || x.attested === false) && (
                      <div className="ln">
                        {x.closed ? <Badge tone="un">비움 · 등록 해제 가능</Badge> : x.draining ? <Badge tone="wa">비우기 중</Badge> : <Badge tone="wa">서버 확인 대기</Badge>}
                      </div>
                    )}
                  </div>
                );
              })}
            </>
          )
        }
      </Load>
      <span className="muted small" style={{ textAlign: 'center' }}>
        ‘경로 추가’ · 허용 작업 공간 바꾸기 · 비우기는 넓은 화면에서
      </span>
    </>
  );
}

/** 게이트웨이 탭: 종류별 카드 */
function MGateway({ id }: { id: string }) {
  const q = usePoll((s) => ingress({ node: id }, s), [id], DEFAULT_POLL_MS, ingressLive());
  const x = q.data?.nodes.find((n) => n.node === id);
  const card = (kind: GatewayKind, g?: GatewayConf) => (
    <div key={kind} className={`mc${g?.state === 'error' ? ' xer' : ''}`}>
      <div className="hd">
        <b>{GW_NAME[kind]}</b>
        {!g ? <Badge tone="un">꺼짐</Badge> : g.state === 'listening' ? <Badge tone="ok">정상</Badge> : g.state === 'error' ? <Badge tone="er">오류</Badge> : <Badge tone="un">꺼짐</Badge>}
      </div>
      {g && (
        <dl className="mkv">
          <dt>받는 주소</dt>
          <dd>
            <span className="mono">{g.address}</span> {g.ports.map((p) => `:${p}`).join(' ')}
          </dd>
          <dt>수신 주소</dt>
          <dd className="mono">{listenerList(g) || '—'}</dd>
          <dt>규칙</dt>
          <dd>{g.rules}</dd>
        </dl>
      )}
    </div>
  );
  if (q.error !== undefined && ingressMissing(q.error)) return <div className="bn info">이 서버의 게이트웨이는 서버 기능 대기</div>;
  return (
    <Load q={q} what="게이트웨이를 읽지 못했습니다">
      {() =>
        !x || !x.module ? (
          <div className="bn info">이 서버는 외부 접속이 꺼져 있습니다(서버 설정 modules.ingress){x?.isolated ? ' · 격리됨' : ''}.</div>
        ) : (
          <>
            {card('external', x.external)}
            {card('local', x.local)}
            <span className="muted" style={{ fontSize: 12 }}>
              지금 요청 {x.rps.toLocaleString('ko-KR')}/s · 연결 {x.connections.toLocaleString('ko-KR')} / {x.connectionLimit.toLocaleString('ko-KR')}
            </span>
            <div className="li">
              <Link to={`/shared/ingress?view=node&pick=${encodeURIComponent(id)}`}>
                외부 접속 화면에서 보기<span className="r">›</span>
              </Link>
            </div>
            <span className="muted small" style={{ textAlign: 'center' }}>
              ‘게이트웨이 설정’은 넓은 화면에서
            </span>
          </>
        )
      }
    </Load>
  );
}

/** 작업 탭: 작업 기록 카드 (UI-M1 ①)와 같은 모양, 이 서버를 대상으로 한 작업만 */
function MServerOps({ id }: { id: string }) {
  const list = usePoll((s) => opsList(undefined, s), [], DEFAULT_POLL_MS, opsLive);
  const nav = useNavigate();
  const hit = (o: OpView) => o.target === id || o.target.split(/[/ ·:]/).includes(id);
  const rows = (list.data ?? []).filter(hit);
  return (
    <Load q={list} what="작업 기록을 불러오지 못했습니다">
      {() =>
        rows.length === 0 ? (
          <span className="muted small">이 서버를 대상으로 내가 보낸 작업이 없습니다.</span>
        ) : (
          <>
            {rows.map((o) => {
              const [tone, label] = M_BADGE[o.state] ?? M_BADGE.unknown;
              return (
                <button key={o.id} type="button" className={`mc${o.state === 'unknown' ? ' xwa' : ''}`} style={{ textAlign: 'left', font: 'inherit' }} onClick={() => nav(`/system/ops?focus=${encodeURIComponent(o.id)}`)}>
                  <div className="hd">
                    <b>{opTitle(o)}</b>
                    <Badge tone={tone}>{label}</Badge>
                  </div>
                  {(o.state === 'failed' || o.state === 'rejected') && o.errorCode && <div className="ln">{o.errorCode}</div>}
                  <div className="ln mono">{opLine(o)}</div>
                </button>
              );
            })}
          </>
        )
      }
    </Load>
  );
}
