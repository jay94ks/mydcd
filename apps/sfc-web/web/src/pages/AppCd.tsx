// SPDX-License-Identifier: Apache-2.0

// 배포 › 앱 › 자동 배포 탭 (UI-40 상태 · UI-41 정책 · UI-42 승인 · UI-43 값 고정, 캔버스 CD · CDIx).
// 계약: docs/reference/web-api.md "자동 배포 (UI-40~43)". 후보 고르기·계획·권한은 sfcd 몫이고 웹은 CAS 값만 채운다.
// 묶음 비밀번호는 PasswordApprove 입력 칸에만 있고 보낸 뒤 지운다.
import { useEffect, useState, type ReactNode } from 'react';
import YAML from 'yaml';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError, api, noEndpoint } from '../api/client';
import { appCd, cdProbe, type CdProbe, cdApprovals, cdApprovalsPath, cdApprovers, cdChanges, cdField, cdHistory, cdLocal, cdPath, cdValues } from '../api/endpoints';
import type { DCdHistory, DCdLocal, DCdPolicy, DCdState } from '../api/dto';
import type { AppView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Badge, Card, Field, HelpBox, KV, Segmented, type Tone } from '../components/ui';
import { Empty, ErrorBand, Load, errorText } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Dialog } from '../components/Dialog';
import { DiffView } from '../components/Code';
import { MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { lineDiff } from '../lib/diff';
import { eulReul, eunNeun } from '../lib/josa';
import { ago, fmtBytes, fmtTime } from '../lib/format';
import { Drawer } from '../components/Drawer';
import { DEFAULT_POLL_MS, refreshAll, usePoll } from '../lib/usePoll';
import { PasswordApprove } from './VaultApproval';
import { CdGateNote, CdHooksCard } from './CdHooks';
import { CD_KIND_NAME, webhookLinks } from '../api/webhooks';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { Sheet } from '../mobile/Sheet';
import { ApproveBar, ConfirmApproveSheet } from '../mobile/Approve';
import { cdLive, cdStateLive, kindsLive } from '../lib/liveTopics';

type Cd = Omit<DCdState, 'overridePaths'> & { overridePaths: string[][] };
const NEED = '이 작업 공간의 배포 권한이 필요합니다';
const short = (c?: string) => (c ? c.slice(0, 7) : '—');
const WAIT_VALUE = '서버 기능 대기';

const SYNC: Record<string, [string, Tone]> = {
  InSync: ['Git과 같음', 'ok'],
  OutOfSync: ['Git과 다름', 'wa'],
  Paused: ['일시정지', 'un'],
  Unknown: ['확인 중', 'un'],
};
const BLOCKED: Record<string, string> = {
  unavailable: '후보를 아직 받지 못했습니다(Git을 읽는 중이거나 읽지 못함).',
  'current-inputs': '실행 중 입력이 바뀌어 다시 계획해야 합니다.',
  'current-authority': '등록한 사람의 권한이 바뀌어 다시 계획해야 합니다.',
  'group-approval': '비밀값 묶음 사용 승인이 필요합니다.',
};
const ERR: Record<string, string> = {
  'not-cd': '이 앱은 자동 배포가 아닙니다.',
  'candidate-changed': '그사이 후보가 바뀌었습니다. 새로 읽은 뒤 다시 하세요.',
  'no-candidate': '동기화할 후보가 없습니다.',
  'no-ref': '이 서비스에는 고정할 배포 객체가 아직 없습니다.',
  'no-override': '이 칸은 고정되어 있지 않습니다.',
  'op-conflict': '같은 작업 번호로 다른 내용을 보냈습니다. 창을 닫고 다시 여세요.',
  unchanged: '웹에서 추가한 서비스가 없어 지울 것이 없습니다.',
};
const manualOf = (cd: Cd) => (cd.policy?.sync.mode ?? cd.mode) === 'manual';
/** 후보가 바뀌었거나 없어서 거절됨: 같은 창에서 다시 보내지 않고 새로 열게 한다 */
const stale = (e: unknown) => e instanceof ApiError && (e.code === 'candidate-changed' || e.code === 'no-candidate');
const Err = ({ e }: { e: unknown }) => {
  if (e === undefined) return null;
  if (e instanceof ApiError && ERR[e.code]) return <div className="note wa small">{ERR[e.code]}</div>;
  return <MutationError error={e} />;
};

type Act = 'sync' | 'recover' | 'replan' | 'pause' | 'resume' | 'abandon';

export function CdTab({ a, current }: { a: AppView; current?: string }) {
  const { canDeploy } = useTenantRole();
  const phone = usePhone();
  // CD를 처음 켜면(a.cd가 생기면) 다시 읽는다
  const q = usePoll((s) => (a.cd ? appCd(a.tenant, a.app, s) : Promise.resolve(undefined as never)), [a.tenant, a.app, !!a.cd], DEFAULT_POLL_MS, cdStateLive(a.tenant, a.app));
  const [act, setAct] = useState<Act>();
  // 연 순간의 상태로 창을 띄운다(승인·반려 뒤 후보가 사라져도 결과를 보이게)
  const [approveCd, setApproveCd] = useState<Cd>();
  const candidate = useSearchParams()[0].get('view') === 'candidate';
  if (!a.cd && phone) return <div className="bn info">자동 배포가 꺼져 있습니다. Git 저장소 연결은 넓은 화면에서 합니다.</div>;
  if (!a.cd) return <ConnectTab a={a} current={current} canDeploy={canDeploy} />;
  if (q.error && noEndpoint(q.error)) return <Empty title="서버 기능 대기">웹 서버에 자동 배포 끝점이 아직 없습니다.</Empty>;
  // 휴대폰: 요약 탭 (UI-M9 ①), 이력 줄을 누르면 후보 화면 (?view=candidate, UI-M5 ③)
  if (phone)
    return (
      <Load q={q} what="자동 배포 상태를 읽지 못했습니다">
        {(cd) => (candidate ? <MCdCandidate a={a} cd={cd} canDeploy={canDeploy} onDone={() => void q.refresh()} /> : <MCdTab a={a} cd={cd} canDeploy={canDeploy} onDone={() => void q.refresh()} />)}
      </Load>
    );
  return (
    <Load q={q} what="자동 배포 상태를 읽지 못했습니다">
      {(cd) => {
        const sync = SYNC[cd.effectiveSync ?? cd.sync ?? ''] ?? [cd.effectiveSync ?? cd.sync ?? '—', 'un'];
        const busy = !!(cd.activeOperation || cd.transition);
        const off = (k: Act) => (!canDeploy ? NEED : k === 'sync' && !cd.candidate ? ERR['no-candidate'] : k === 'sync' && cd.paused ? '일시정지 중에는 동기화하지 않습니다' : k === 'abandon' && !busy ? '진행 중인 동기화가 없습니다' : undefined);
        const btn = (k: Act, label: string, cls = 'btn') => (
          <button type="button" className={cls} disabled={!!off(k)} title={off(k)} onClick={() => setAct(k)}>
            {label}
          </button>
        );
        return (
          <>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <span className="row">
                <Badge tone={sync[1]}>{sync[0]}</Badge>
                {cd.sourceError && <Badge tone="er">Git 읽기 실패</Badge>}
                <span className="small muted">rev {cd.revision}</span>
              </span>
              <span className="row" style={{ gap: 8 }}>
                <Refresh q={q} />
                {btn('sync', '동기화', 'btn primary')}
                {btn('replan', '다시 계획')}
                {cd.paused ? btn('resume', '다시 켜기') : btn('pause', '일시정지')}
                {btn('abandon', '진행 중 동기화 포기', 'btn danger')}
              </span>
            </div>
            <HelpBox terms="자동 배포 (CD) · 동기화 (sync, Git 내용대로 맞추기) · Git과 차이 (drift) · 설정 임시 변경 (field override) · 정리 (prune, Git에서 빠진 것 지우기)">
              <b>이 탭은</b> Git 저장소의 app.yaml을 지켜보다가 바뀌면 자동으로 배포하는 설정입니다. 후보 커밋과, Git과 다르게 잠시 바꿔 둔 설정을 함께 관리합니다. 자동 배포 앱의 app.yaml을 직접 고치면 Git과 차이가 생기므로, 고칠 때는 Git에 커밋하거나 아래 '설정 임시 변경'을 씁니다.
            </HelpBox>
            <div className="grid-2">
              <Card title="가져올 곳 (Git)">
                <KV
                  items={[
                    ['Git 저장소', <code className="break-any">{cd.policy?.source.repository || cd.repository}</code>],
                    ['브랜치 · 파일 경로', `${cd.branch || cd.policy?.source.ref || '—'} · ${cd.policy?.source.path || 'app.yaml'}`],
                    ['Git 접속 정보', cd.policy?.source.credential || <span className="muted">없음 (공개 저장소)</span>],
                    ['현재 실행', <code>{short(cd.running)}</code>],
                    ['최신 후보', cd.candidate ? <code>{short(cd.candidate)}</code> : <span className="muted">없음</span>],
                    ['상태', `${cd.operation ?? '—'} · ${cd.health ?? '—'}${cd.changeCount ? ` · 바뀐 칸 ${cd.changeCount}` : ''}`],
                  ]}
                />
                {cd.sourceError && <div className="note er small">Git을 읽지 못했습니다: {cd.sourceError}</div>}
                {cd.blocked && (
                  <div className="note wa small row" style={{ justifyContent: 'space-between' }}>
                    <span>
                      <b>차단 사유</b> 후보 <code>{short(cd.candidate)}</code>: {BLOCKED[cd.blocked] ?? cd.blocked}
                    </span>
                    {cd.blocked === 'group-approval' && (
                      <button type="button" className="btn sm" onClick={() => setApproveCd(cd)}>
                        승인으로 이동
                      </button>
                    )}
                  </div>
                )}
                <CdGateNote a={a} cd={cd} />
                {busy && (
                  <div className="note small">
                    진행 중: <code>{cd.activeOperation ?? cd.transition}</code>
                    {cd.transitionPhase ? ` · ${cd.transitionPhase}` : ''}
                  </div>
                )}
              </Card>
              <HistoryCard a={a} cd={cd} canDeploy={canDeploy} onRecover={() => setAct('recover')} onApprove={() => cd.candidateDigest && setApproveCd(cd)} />
            </div>
            <PolicyCard a={a} cd={cd} canDeploy={canDeploy} onDone={() => void q.refresh()} />
            <OverrideCard a={a} cd={cd} canDeploy={canDeploy} onDone={() => void q.refresh()} />
            <div className="grid-2">
              <LocalCard a={a} cd={cd} canDeploy={canDeploy} onDone={() => void q.refresh()} />
              <ApproversCard a={a} cd={cd} canDeploy={canDeploy} onDone={() => void q.refresh()} />
            </div>
            <CdHooksCard a={a} cd={cd} canManage={canDeploy} onChange={() => void q.refresh()} />
            {act && <ActDialog a={a} cd={cd} act={act} onClose={() => setAct(undefined)} onDone={() => void q.refresh()} />}
            {approveCd && <CdApproveDialog a={a} cd={approveCd} onClose={() => setApproveCd(undefined)} onDone={() => void q.refresh()} />}
          </>
        );
      }}
    </Load>
  );
}

// ── 휴대폰: 후보 승인 (캔버스 UI-M5 ③) ──────────────────────────────
// 후보·실행 이력의 '승인 대기' 행과 승인 창(UI-42)을 한 화면에. 영향은 배포라 '보통'으로 보고 확인 시트를 한 번 더 띄운다.
function MCdCandidate({ a, cd, canDeploy, onDone }: { a: AppView; cd: Cd; canDeploy: boolean; onDone: () => void }) {
  const toast = useToast();
  const digest = cd.candidateDigest;
  const decide = manualOf(cd) && !cd.paused && !!digest && !!cd.candidate;
  const appr = usePoll((s) => (digest ? cdApprovals(a.tenant, a.app, digest, s) : Promise.resolve([])), [a.tenant, a.app, digest ?? '']);
  const chg = usePoll((s) => (cd.candidate ? cdChanges(a.tenant, a.app, s).catch(() => undefined) : Promise.resolve(undefined)), [a.tenant, a.app, cd.candidate ?? '']);
  const left = (appr.data ?? []).filter((x) => x.state !== 'approved');
  const [act, setAct] = useState<Act>();
  const [vault, setVault] = useState<(typeof left)[number]>();
  const [confirm, setConfirm] = useState(false);
  const mA = useMutation();
  const mR = useMutation();
  const [which, setWhich] = useState<'approve' | 'reject'>();
  const m = which === 'reject' ? mR : mA;
  const sync = SYNC[cd.effectiveSync ?? cd.sync ?? ''] ?? [cd.effectiveSync ?? cd.sync ?? '—', 'un'];
  useMobileTop(
    {
      title: cd.candidate ? `후보 ${short(cd.candidate)}` : '자동 배포',
      sub: `${a.app} · 자동 배포`,
      menu: [
        cd.paused ? { label: '자동 배포 다시 켜기', onSelect: () => setAct('resume') } : { label: '자동 배포 일시정지', onSelect: () => setAct('pause') },
        { label: '다시 계획', onSelect: () => setAct('replan') },
        { label: '정책 보기', wide: true },
      ].map((x) => (canDeploy || x.wide ? x : { ...x, onSelect: () => toast(NEED, 'er') })),
    },
    [cd.candidate, cd.paused, canDeploy],
    'sub',
  );
  const go = async (k: 'approve' | 'reject') => {
    setWhich(k);
    const o = await sendOp(k === 'approve' ? mA : mR, `${cdPath(a.tenant, a.app)}/candidate/${k}`, { candidate: digest });
    setConfirm(false);
    if (o?.state === 'applied') {
      toast(k === 'approve' ? `후보 ${short(cd.candidate)}을 승인해 배포를 시작했습니다.` : `후보 ${short(cd.candidate)}을 반려했습니다.`);
      onDone();
    }
  };
  const paths = (chg.data?.services ?? []).flatMap((x) => (x.fields.length ? x.fields.map((f) => f.path.join('.')) : [`services.${x.service}`]));
  const changes = [...paths, ...(chg.data?.added ?? []).map((x) => `+ ${x}`), ...(chg.data?.removed ?? []).map((x) => `− ${x}`)];
  const busy = mA.busy || mR.busy;
  const gone = stale(mA.error) || stale(mR.error);
  return (
    <>
      <div className={`mc${decide ? ' ap' : ''}`}>
        <div className="hd">
          <b>{decide ? '승인 대기' : sync[0]}</b>
          {cd.blocked ? <Badge tone="wa">{BLOCKED[cd.blocked] ?? cd.blocked}</Badge> : cd.paused ? <Badge tone="un">일시정지</Badge> : null}
        </div>
        <dl className="mkv">
          <dt>현재 실행</dt>
          <dd className="mono">{short(cd.running)}</dd>
          <dt>후보</dt>
          <dd className="mono">{cd.candidate ? short(cd.candidate) : '없음'}</dd>
          {digest && (
            <>
              <dt>후보 지문</dt>
              <dd className="mono">sha256:{digest.replace(/^sha256:/, '').slice(0, 4)}…</dd>
            </>
          )}
        </dl>
        <CdGateNote a={a} cd={cd} />
      </div>
      {cd.sourceError && <div className="bn err">Git을 읽지 못했습니다: {cd.sourceError}</div>}
      {changes.length > 0 && (
        <>
          <div className="m-sec">
            <span>변경점 {chg.data?.count ?? changes.length}</span>
            {/^https?:/.test(cd.repository ?? '') && (
              <a href={cd.repository} target="_blank" rel="noreferrer">
                Git에서 보기 ↗
              </a>
            )}
          </div>
          <div className="li">
            {changes.slice(0, 12).map((x) => (
              <div key={x} className="mono" style={{ fontSize: 12 }}>
                <span className="el">{x}</span>
              </div>
            ))}
          </div>
        </>
      )}
      {left.map((x) => (
        <div key={`${x.realm}/${x.group}`} className="mc xwa">
          <div className="hd">
            <b>비밀값 묶음 {x.group} 승인 필요</b>
          </div>
          <div className="ln">이 후보는 비밀값 묶음을 새로 씁니다. 사람이 먼저 승인해야 하며 웹훅이 대신할 수 없습니다.</div>
          <div className="ft">
            <button type="button" className="mbtn sm" onClick={() => setVault(x)}>
              비밀값 묶음 승인…
            </button>
          </div>
        </div>
      ))}
      {appr.error instanceof ApiError && appr.error.status === 403 && <div className="bn warn">자동 배포를 등록한 사람({cd.principal ?? '—'})만 이 후보의 비밀값 묶음을 승인할 수 있습니다.</div>}
      {!decide && <div className="bn info">{cd.paused ? '일시정지 중입니다. Git이 바뀌어도 배포하지 않고 후보만 쌓습니다.' : manualOf(cd) ? '지금 승인할 후보가 없습니다.' : '자동 모드라 후보는 승인 없이 실행됩니다. 비밀값 묶음 승인만 여기서 받습니다.'}</div>}
      <span className="muted small" style={{ textAlign: 'center' }}>
        정책 · 설정 임시 변경 · 웹훅은 넓은 화면에서
      </span>
      {gone ? <div className="bn warn">{ERR[(m.error as ApiError).code]}</div> : <Err e={m.error} />}
      {m.op && m.op.state !== 'applied' && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      {decide && !(m.op?.state === 'applied') && (
        <ApproveBar
          note={left.length ? `비밀값 묶음 ${left.map((x) => x.group).join(', ')} 승인 뒤에 실행할 수 있습니다` : !canDeploy ? NEED : undefined}
          disabled={!canDeploy || left.length > 0 || !appr.data || gone}
          busy={busy}
          onReject={canDeploy ? () => void go('reject') : undefined}
          onApprove={() => setConfirm(true)}
        />
      )}
      {confirm && <ConfirmApproveSheet what={`후보 ${short(cd.candidate)} 배포`} impact="medium" busy={mA.busy} onClose={() => setConfirm(false)} onConfirm={() => void go('approve')} />}
      {vault && digest && (
        <Sheet title={`비밀값 묶음 ${vault.group} 승인`} onClose={() => setVault(undefined)}>
          <PasswordApprove
            onSettled={() => void appr.refresh()}
            send={async (password) => {
              await api.post(cdApprovalsPath(a.tenant, a.app), { candidate: digest, realm: vault.realm, group: vault.group, password });
              toast(`후보 ${short(cd.candidate)}의 묶음 ${vault.group} 사용을 승인했습니다.`);
              setVault(undefined);
              void appr.refresh();
              onDone();
            }}
          >
            묶음 <b>{vault.group}</b>
            {vault.services.length ? ` · 서비스 ${vault.services.join(', ')}` : ''}
          </PasswordApprove>
        </Sheet>
      )}
      {act && <ActDialog a={a} cd={cd} act={act} onClose={() => setAct(undefined)} onDone={onDone} />}
    </>
  );
}

/** 휴대폰 자동 배포 탭 (UI-M9 ①): 요약 · 승인 안내 · 이력 · 보기만 하위 화면 · 일시정지/다시 계획 */
function MCdTab({ a, cd, canDeploy, onDone }: { a: AppView; cd: Cd; canDeploy: boolean; onDone: () => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const h = usePoll((s) => cdHistory(a.tenant, a.app, s).catch(() => undefined), [a.tenant, a.app, cd.revision], 0, cdLive(a.tenant, a.app));
  const links = usePoll((s) => webhookLinks({ point: 'cd', tenant: a.tenant, app: a.app }, s).catch(() => undefined), [a.tenant, a.app], 0, kindsLive('webhook-link'));
  const [act, setAct] = useState<Act>();
  const [view, setView] = useState<'policy' | 'override' | 'hooks'>();
  const sync = SYNC[cd.effectiveSync ?? cd.sync ?? ''] ?? [cd.effectiveSync ?? cd.sync ?? '—', 'un'];
  const manual = manualOf(cd);
  const open = () => navigate('?view=candidate');
  const ask = (k: Act) => (canDeploy ? setAct(k) : toast(NEED, 'er'));
  const rows = (h.data?.items ?? []).slice(0, 6);
  const overrides = cd.overridePaths.length || cd.overrideCount || 0;
  return (
    <>
      <div className="mc">
        <div className="hd">
          <b>{sync[0]}</b>
          {cd.paused ? <Badge tone="un">일시정지</Badge> : <Badge tone={manual ? 'wa' : 'ok'}>{manual ? '동기화 수동' : '동기화 자동'}</Badge>}
        </div>
        <dl className="mkv">
          <dt>Git</dt>
          <dd className="el mono">{(cd.policy?.source.repository || cd.repository).replace(/^https?:\/\//, '')}</dd>
          <dt>브랜치 · 파일</dt>
          <dd>
            {cd.branch || cd.policy?.source.ref || '—'} · {cd.policy?.source.path || 'app.yaml'}
          </dd>
          <dt>현재 실행</dt>
          <dd className="mono">{short(cd.running)}</dd>
          <dt>최신 후보</dt>
          <dd className="mono">{cd.candidate ? `${short(cd.candidate)}${rows[0]?.commit === cd.candidate ? ` · ${ago(new Date(rows[0].plannedAt * 1000).toISOString())}` : ''}` : '없음'}</dd>
        </dl>
      </div>
      {cd.sourceError && <div className="bn err">Git을 읽지 못했습니다: {cd.sourceError}</div>}
      {cd.blocked === 'group-approval' ? (
        <div className="bn warn">
          후보 <span className="mono">{short(cd.candidate)}</span>은 비밀값 묶음 승인이 필요합니다.{' '}
          <a href="?view=candidate" onClick={(e) => (e.preventDefault(), open())}>
            승인으로 이동 ›
          </a>
        </div>
      ) : cd.blocked ? (
        <div className="bn warn">{BLOCKED[cd.blocked] ?? cd.blocked}</div>
      ) : null}
      <div className="m-sec">
        <span>후보·실행 이력</span>
      </div>
      {h.data === undefined && !h.loading ? (
        <div className="li">
          {cd.candidate && (
            <button type="button" onClick={open}>
              <span className="mono">{short(cd.candidate)}</span>
              <span className="r">
                <Badge tone="pr">후보</Badge>
              </span>
            </button>
          )}
          <div>
            <span className="mono">{short(cd.running)}</span>
            <span className="r">
              <Badge tone="ok">실행 중</Badge>
            </span>
          </div>
        </div>
      ) : rows.length === 0 ? (
        <span className="muted small">{h.loading ? '이력을 읽는 중…' : '아직 계획한 후보가 없습니다.'}</span>
      ) : (
        <div className="li">
          {rows.map((r, i) => {
            const live = r.result === 'succeeded' && r.commit === cd.running;
            const isCand = r.commit === cd.candidate && (r.result === 'candidate' || r.result === 'blocked');
            const [label, tone]: [string, Tone] = live
              ? ['실행 중', 'ok']
              : isCand && (r.reason === 'group-approval' || (manual && !cd.paused))
                ? ['승인 대기', 'pr']
                : r.result === 'succeeded'
                  ? ['이전', 'un']
                  : r.result === 'abandoned' && r.reason === 'superseded'
                    ? ['새 후보에 밀림', 'un']
                    : RESULT[r.result] ?? [r.result, 'un'];
            const checks = (['pre-sync', 'post-sync'] as const).flatMap((k) => {
              const g = r.checks?.[k];
              if (!g) return [];
              const [l, t] = CHECK_NAME[g.state] ?? [g.state, 'wa'];
              return [
                <Badge key={k} tone={t}>
                  {k === 'pre-sync' ? (g.state === 'checking' ? '배포 전 확인 중' : `배포 전 확인 ${l}`) : `배포 후 ${l}`}
                </Badge>,
              ];
            });
            const body = (
              <>
                <span className="mono">{short(r.commit)}</span>
                <span className="r" style={{ display: 'flex', gap: 4 }}>
                  <Badge tone={tone}>{label}</Badge>
                  {checks}
                </span>
              </>
            );
            return isCand ? (
              <button key={`${r.candidateDigest}/${i}`} type="button" onClick={open}>
                {body}
              </button>
            ) : (
              <div key={`${r.candidateDigest}/${i}`}>{body}</div>
            );
          })}
        </div>
      )}
      <div className="li">
        <button type="button" onClick={() => setView('policy')}>
          자동 배포 정책<span className="r">policy rev {cd.policyRevision} · 보기만 ›</span>
        </button>
        <button type="button" onClick={() => setView('override')}>
          설정 임시 변경<span className="r">{overrides}개 · 보기만 ›</span>
        </button>
        <button type="button" onClick={() => setView('hooks')}>
          자동 배포 웹훅<span className="r">{links.data ? `${links.data.items.length}개 · ` : ''}보기만 ›</span>
        </button>
      </div>
      <span className="muted small" style={{ textAlign: 'center' }}>
        ‘동기화’ ‘진행 중 동기화 포기’는 넓은 화면에서
      </span>
      <div className="m-stick">
        <div className="mbar">
          <button type="button" className="mbtn fl" onClick={() => ask(cd.paused ? 'resume' : 'pause')}>
            {cd.paused ? '⏵ 다시 켜기' : '⏸ 일시정지'}
          </button>
          <button type="button" className="mbtn fl" onClick={() => ask('replan')}>
            다시 계획
          </button>
        </div>
      </div>
      {view === 'policy' && (
        <Drawer title={`자동 배포 정책 · rev ${cd.policyRevision}`} onClose={() => setView(undefined)}>
          {cd.policy ? (
            <div className="mc">
            <dl className="mkv">
              <dt>가져올 곳</dt>
              <dd className="el mono">{cd.policy.source.repository}</dd>
              <dt>브랜치 · 파일</dt>
              <dd>
                {cd.policy.source.ref} · {cd.policy.source.path}
              </dd>
              <dt>Git 접속 정보</dt>
              <dd>{cd.policy.source.credential || '없음 (공개 저장소)'}</dd>
              <dt>살피는 주기</dt>
              <dd>{cd.policy.poll}초</dd>
              <dt>동기화</dt>
              <dd>{cd.policy.sync.mode === 'manual' ? '수동 (승인 뒤 실행)' : '자동'}</dd>
              <dt>Git과 차이</dt>
              <dd>{cd.policy.sync.drift}</dd>
              <dt>정리 (prune)</dt>
              <dd>{cd.policy.sync.prune ? '켬' : '끔'}</dd>
            </dl>
            </div>
          ) : (
            <span className="muted small">정책을 읽지 못했습니다.</span>
          )}
          <span className="muted small">정책 바꾸기는 넓은 화면에서</span>
        </Drawer>
      )}
      {view === 'override' && (
        <Drawer title="설정 임시 변경" onClose={() => setView(undefined)}>
          {cd.overridePaths.length ? (
            <div className="li">
              {cd.overridePaths.map((p) => (
                <div key={p.join('.')} className="mono" style={{ fontSize: 12 }}>
                  <span className="el">{p.join('.')}</span>
                </div>
              ))}
            </div>
          ) : (
            <span className="muted small">Git과 다르게 잠시 바꿔 둔 설정이 없습니다.</span>
          )}
          <span className="muted small">값 보기 · 바꾸기 · 풀기는 넓은 화면에서</span>
        </Drawer>
      )}
      {view === 'hooks' && (
        <Drawer title="자동 배포 웹훅" onClose={() => setView(undefined)}>
          {links.data?.items.length ? (
            links.data.items.map((l) => (
              <div key={l.id} className="mc">
                <div className="hd">
                  <b>{l.webhook}</b>
                  {l.kind && <Badge tone="tag">{CD_KIND_NAME[l.kind]}</Badge>}
                </div>
                {l.waitSeconds !== undefined && <div className="ln muted">답을 {l.waitSeconds}초 기다림{l.onTimeout ? ` · 넘으면 ${l.onTimeout}` : ''}</div>}
              </div>
            ))
          ) : (
            <span className="muted small">{links.data ? '연결된 웹훅이 없습니다.' : '웹훅 연결을 읽지 못했습니다.'}</span>
          )}
          <span className="muted small">연결 · 끊기는 넓은 화면에서</span>
        </Drawer>
      )}
      {act && <ActDialog a={a} cd={cd} act={act} onClose={() => setAct(undefined)} onDone={onDone} />}
    </>
  );
}

/** 앱 머리 ⋯의 자동 배포 일시정지·다시 켜기 (휴대폰 UI-M4 ②) */
export function CdPauseDialog({ a, onClose }: { a: AppView; onClose: () => void }) {
  const q = usePoll((s) => appCd(a.tenant, a.app, s), [a.tenant, a.app]);
  if (!q.data) return null;
  return <ActDialog a={a} cd={q.data} act={q.data.paused ? 'resume' : 'pause'} onClose={onClose} onDone={() => undefined} />;
}

// ── 동작 확인 (UI-40) ──────────────────────────────

const ACT: Record<Act, { title: (cd: Cd) => string; body: (cd: Cd) => ReactNode; action: string; danger?: boolean; confirm?: (cd: Cd) => string | undefined }> = {
  sync: { title: (cd) => `${short(cd.candidate)}으로 동기화할까요?`, body: () => 'Git 최신 후보로 배포합니다.', action: '동기화', danger: true },
  recover: { title: (cd) => `${short(cd.candidate)}으로 복구할까요?`, body: () => '실패하거나 멈춘 동기화를 지금 후보로 다시 맞춥니다. Git은 바뀌지 않습니다.', action: '복구', danger: true },
  replan: { title: () => '다시 계획할까요?', body: () => 'Git을 다시 읽어 후보를 새로 계획합니다. 아직 배포하지 않습니다.', action: '다시 계획' },
  pause: { title: () => '자동 배포 일시정지', body: () => 'Git이 바뀌어도 배포하지 않고 후보만 쌓습니다. 다시 켤 때까지 그대로입니다.', action: '일시정지' },
  resume: { title: () => '자동 배포를 다시 켤까요?', body: () => '다시 켜면 최신 후보를 정책대로 배포합니다.', action: '다시 켜기' },
  abandon: {
    title: () => '진행 중인 동기화를 포기할까요?',
    body: (cd) => `${cd.activeOperation ?? cd.transition ?? '진행 중인 작업'}이 지금 단계에서 멈춥니다. 이미 바뀐 컨테이너는 그대로 남아 Git과 다를 수 있습니다.`,
    action: '포기',
    danger: true,
    confirm: (cd) => cd.activeOperation ?? cd.transition,
  },
};

function ActDialog({ a, cd, act, onClose, onDone }: { a: AppView; cd: Cd; act: Act; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const toast = useToast();
  const d = ACT[act];
  // 창을 연 순간의 후보 지문. 그새 바뀌면 데몬이 409 candidate-changed
  // 창 제목·본문도 연 순간 상태로 둔다(완료 뒤 새로 읽은 상태로 바뀌지 않게)
  const [snap] = useState(cd);
  const candidate = snap.candidateDigest;
  const [typed, setTyped] = useState('');
  const need = d.confirm?.(snap);
  const send = async () => {
    if (m.op || m.error) m.reset();
    const body = act === 'sync' || act === 'recover' ? (candidate ? { candidate } : {}) : {};
    const o = await m.run(`${cdPath(a.tenant, a.app)}/${act}`, body);
    if (o?.state === 'applied') {
      onDone();
      if (act === 'replan') (toast('Git을 다시 읽어 계획했습니다.'), onClose());
    }
  };
  const finished = m.op?.state === 'applied';
  return (
    <Dialog
      title={d.title(snap)}
      danger={d.danger}
      width={420}
      onClose={onClose}
      footer={
        finished ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className={d.danger ? 'btn danger solid' : 'btn primary'} disabled={m.busy || (!!need && typed !== need)} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : d.action}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <div>{d.body(snap)}</div>
        {(act === 'sync' || act === 'recover') && snap.blocked === 'group-approval' && <div className="note wa small">후보가 비밀값 묶음 승인 대기 중이라 지금은 막힙니다.</div>}
        {need && (
          <Field label={<>확인하려면 <b className="mono">{need}</b>{eulReul(need)} 입력하세요</>}>
            <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value)} disabled={finished} autoComplete="off" spellCheck={false} />
          </Field>
        )}
        <Err e={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

// ── 후보 승인 (UI-42) ──────────────────────────────

function CdApproveDialog({ a, cd, onClose, onDone }: { a: AppView; cd: Cd; onClose: () => void; onDone: () => void }) {
  // 창을 연 순간의 후보. 그새 바뀌면 데몬이 409 candidate-changed
  const [snap] = useState(cd);
  const digest = snap.candidateDigest!;
  const q = usePoll((s) => cdApprovals(a.tenant, a.app, digest, s), [a.tenant, a.app, digest]);
  const toast = useToast();
  const left = (q.data ?? []).filter((x) => x.state !== 'approved');
  // 후보 승인·반려는 수동 모드에서 일시정지가 아닐 때만. 자동 모드는 묶음 승인만 받는다
  const decide = manualOf(snap) && !snap.paused;
  const [reason, setReason] = useState('');
  const mA = useMutation();
  const mR = useMutation();
  const [which, setWhich] = useState<'approve' | 'reject'>();
  const m = which === 'reject' ? mR : mA;
  const finished = m.op?.state === 'applied';
  const go = async (k: 'approve' | 'reject') => {
    setWhich(k);
    const o = await sendOp(k === 'approve' ? mA : mR, `${cdPath(a.tenant, a.app)}/candidate/${k}`, { candidate: digest, ...(reason.trim() ? { reason: reason.trim() } : {}) });
    if (o?.state === 'applied') {
      toast(k === 'approve' ? `후보 ${short(snap.candidate)}을 승인해 배포를 시작했습니다.` : `후보 ${short(snap.candidate)}을 반려했습니다.`);
      onDone();
    }
  };
  const tooLong = [...reason].length > 512;
  const busy = mA.busy || mR.busy;
  const gone = stale(mA.error) || stale(mR.error);
  return (
    <Dialog
      title={decide ? `후보 ${short(snap.candidate)} 승인` : `후보 ${short(snap.candidate)} · 묶음 승인`}
      width={560}
      onClose={onClose}
      footer={
        finished || !decide ? (
          <button type="button" className="btn" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn danger" disabled={busy || tooLong || gone} onClick={() => void go('reject')}>
              {mR.busy ? '보내는 중…' : '반려'}
            </button>
            <button type="button" className="btn primary" disabled={busy || tooLong || gone || !q.data || left.length > 0} title={left.length ? '비밀값 묶음 승인을 먼저 받아야 합니다' : undefined} onClick={() => void go('approve')}>
              {mA.busy ? '보내는 중…' : '승인'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <KV
          items={[
            ['커밋', <code>{short(snap.candidate)}</code>],
            ['지문', <span className="mono">sha256:{digest.slice(0, 4)}…</span>],
            ['요구', q.data ? (q.data.length ? q.data.map((x) => `비밀값 묶음 ${x.group} 사용 승인`).join(', ') : decide ? '후보 승인 (수동 모드)' : '없음') : '—'],
          ]}
        />
        {q.error instanceof ApiError && q.error.status === 403 ? (
          <div className="note wa small">자동 배포를 등록한 사람({snap.principal ?? '—'})만 이 후보의 비밀값 묶음을 승인할 수 있습니다.</div>
        ) : q.error ? (
          <ErrorBand error={q.error} what="승인 목록을 읽지 못했습니다" onRetry={q.refresh} />
        ) : (
          <>
            <div className="note info small">
              {decide ? '승인하면 이 지문의 후보만 배포할 수 있습니다. 반려한 커밋은 새 커밋이 오거나 다시 계획할 때까지 후보로 돌아오지 않습니다.' : '자동 모드라 후보는 승인 없이 실행됩니다. 비밀값 묶음 승인만 여기서 받습니다.'}
            </div>
            {left.map((x) => (
              <PasswordApprove
                key={`${x.realm}/${x.group}`}
                onSettled={() => void q.refresh()}
                send={async (password) => {
                  await api.post(cdApprovalsPath(a.tenant, a.app), { candidate: digest, realm: x.realm, group: x.group, password });
                  toast(`후보 ${short(snap.candidate)}의 묶음 ${x.group} 사용을 승인했습니다.`);
                  void q.refresh();
                  onDone();
                }}
              >
                묶음 <b>{x.group}</b>
                {x.services.length ? ` · 서비스 ${x.services.join(', ')}` : ''}
              </PasswordApprove>
            ))}
            {q.data && q.data.length > 0 && !left.length && <div className="note ok small">비밀값 묶음 승인을 모두 받았습니다.{decide ? ' 이제 후보를 승인할 수 있습니다.' : ' 이제 정책대로 배포됩니다.'}</div>}
          </>
        )}
        {decide && (
          <Field label="메모" hint="512자까지 · 이력과 이벤트에 남습니다" error={tooLong ? '512자를 넘었습니다' : undefined}>
            <input value={reason} disabled={busy || finished} onChange={(e) => setReason(e.target.value)} />
          </Field>
        )}
        {gone ? <div className="note wa small">{ERR[(m.error as ApiError).code]} 이 창을 닫고 새 후보로 다시 여세요.</div> : <Err e={m.error} />}
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

// ── 웹에서 추가한 서비스 ──────────────────────────────

type Svc = Record<string, unknown>;
const parseLocal = (doc: string): Record<string, Svc> => {
  if (!doc.trim()) return {};
  const v = YAML.parse(doc) as { services?: Record<string, Svc> } | null;
  return v?.services ?? {};
};
const localDoc = (svcs: Record<string, Svc>) => (Object.keys(svcs).length ? YAML.stringify({ services: svcs }) : '');
const svcImage = (v: Svc) => (typeof v?.image === 'string' ? v.image : '—');
const svcNode = (v: Svc) => ((v?.['x-sfc'] as { node?: string } | undefined)?.node ?? '');
const NAME_RE = /^[a-z][a-z0-9-]{0,62}$/;

function LocalCard({ a, cd, canDeploy, onDone }: { a: AppView; cd: Cd; canDeploy: boolean; onDone: () => void }) {
  const q = usePoll((s) => cdLocal(a.tenant, a.app, s), [a.tenant, a.app, cd.revision]);
  const [dlg, setDlg] = useState<{ kind: 'edit' | 'remove'; name?: string }>();
  const wait = !!q.error && noEndpoint(q.error);
  let svcs: Record<string, Svc> = {};
  let bad: string | undefined;
  try {
    svcs = parseLocal(q.data?.document ?? '');
  } catch (e) {
    bad = (e as Error).message;
  }
  const download = () => {
    const url = URL.createObjectURL(new Blob([q.data?.document ?? ''], { type: 'application/yaml' }));
    const el = document.createElement('a');
    el.href = url;
    el.download = `${a.app}-web-services.yaml`;
    el.click();
    URL.revokeObjectURL(url);
  };
  return (
    <Card
      title="웹에서 추가한 서비스"
      actions={
        wait ? (
          <Badge tone="wa">서버 기능 대기</Badge>
        ) : (
          <button type="button" className="btn sm primary" disabled={!canDeploy || !q.data || !!bad} title={!canDeploy ? NEED : undefined} onClick={() => setDlg({ kind: 'edit' })}>
            ＋ 서비스 추가
          </button>
        )
      }
    >
      {wait ? (
        <span className="small muted">Git에서 온 서비스는 잠겨 있어 웹에서 고칠 수 없습니다. 웹에서 서비스를 추가하는 기능은 서버가 지원하면 켜집니다.</span>
      ) : (
        <Load q={q} what="웹에서 추가한 서비스를 읽지 못했습니다">
          {(l) => (
            <>
              <span className="small muted">
                Git에서 온 서비스({l.gitServices.join(', ') || '없음'})는 🔒 잠겨 있어 웹에서 고칠 수 없습니다. 웹에서는 서비스를 <b>추가</b>만 할 수 있고, 추가분은 동기화·정리(prune) 때 지워지거나 덮어쓰이지 않습니다. 추가·편집·제거는 바로 배포하지 않고 다음 동기화나 후보 승인 때 반영됩니다.
              </span>
              {bad && <div className="note er small">웹 추가분을 읽지 못했습니다: {bad}</div>}
              {l.conflicts.length > 0 && (
                <div className="note er small">
                  Git에 같은 이름의 서비스가 생겨 동기화를 멈췄습니다(이름 충돌): <b>{l.conflicts.join(', ')}</b>. 웹 추가분 이름을 바꾸거나 Git으로 옮긴 뒤 다시 동기화하세요.
                </div>
              )}
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>서비스</th>
                      <th>이미지</th>
                      <th>서버</th>
                      <th aria-label="동작" />
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(svcs).map(([n, v]) => (
                      <tr key={n}>
                        <td>
                          {n} {l.conflicts.includes(n) && <Badge tone="er">이름 충돌</Badge>}
                        </td>
                        <td className="mono small break-any">{svcImage(v)}</td>
                        <td>{svcNode(v) || <span className="muted">자동</span>}</td>
                        <td className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                          <button type="button" className="btn sm" disabled={!canDeploy} title={!canDeploy ? NEED : undefined} onClick={() => setDlg({ kind: 'edit', name: n })}>
                            편집
                          </button>
                          <button type="button" className="btn sm danger" disabled={!canDeploy} title={!canDeploy ? NEED : undefined} onClick={() => setDlg({ kind: 'remove', name: n })}>
                            제거…
                          </button>
                        </td>
                      </tr>
                    ))}
                    {!Object.keys(svcs).length && (
                      <tr>
                        <td colSpan={4} className="muted">
                          웹에서 추가한 서비스가 없습니다.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              <span className="small muted">
                Git에 같은 이름의 서비스가 생기면 동기화를 멈추고 '이름 충돌'로 알립니다. 웹 추가분을 Git에 반영하려면{' '}
                <button type="button" className="linkish" disabled={!Object.keys(svcs).length} onClick={download}>
                  추가분 app.yaml 내려받기
                </button>
                로 받아 커밋하면 됩니다.
              </span>
              {dlg && <LocalDialog a={a} local={l} svcs={svcs} kind={dlg.kind} name={dlg.name} onClose={() => setDlg(undefined)} onDone={() => (setDlg(undefined), void q.refresh(), onDone())} />}
            </>
          )}
        </Load>
      )}
    </Card>
  );
}

function LocalDialog({ a, local, svcs, kind, name, onClose, onDone }: { a: AppView; local: DCdLocal; svcs: Record<string, Svc>; kind: 'edit' | 'remove'; name?: string; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const toast = useToast();
  const isNew = kind === 'edit' && !name;
  const [n, setN] = useState(name ?? '');
  const [body, setBody] = useState(() => (name && svcs[name] ? YAML.stringify(svcs[name]) : 'image: \n'));
  const [typed, setTyped] = useState('');
  // 창을 연 순간의 CD revision이 expected
  const [rev] = useState(local.revision);
  const finished = m.op?.state === 'applied';
  let parsed: Svc | undefined;
  let problem: string | undefined;
  if (kind === 'edit') {
    try {
      const v = YAML.parse(body) as unknown;
      if (!v || typeof v !== 'object' || Array.isArray(v)) problem = '서비스 내용은 키: 값 모양이어야 합니다.';
      else if (typeof (v as Svc).image !== 'string' || !(v as Svc).image) problem = 'image가 필요합니다.';
      else parsed = v as Svc;
    } catch (e) {
      problem = `YAML이 맞지 않습니다: ${(e as Error).message.split('\n')[0]}`;
    }
    if (!NAME_RE.test(n)) problem = '서비스 이름은 영문 소문자로 시작하고 소문자·숫자·-만 씁니다(63자까지).';
    else if (local.gitServices.includes(n)) problem = `${n}은 Git이 가진 서비스라 웹에서 추가할 수 없습니다.`;
    else if (isNew && svcs[n]) problem = `${n}은 이미 웹에서 추가한 서비스입니다.`;
  }
  const next = kind === 'remove' ? Object.fromEntries(Object.entries(svcs).filter(([k]) => k !== name)) : { ...svcs, [n]: parsed! };
  const send = async () => {
    const o = await sendOp(m, `${cdPath(a.tenant, a.app)}/local`, { document: localDoc(next), expected: rev }, 'PUT');
    if (o?.state === 'applied') {
      toast(kind === 'remove' ? `${name}을 다음 배포 때 앱에서 뺍니다.` : `${n}을 저장했습니다. 다음 배포 때 더해집니다.`);
      onDone();
    }
  };
  const ready = kind === 'remove' ? typed === name : !problem;
  return (
    <Dialog
      title={kind === 'remove' ? `${name}${eulReul(name!)} 제거할까요?` : isNew ? '웹에서 서비스 추가' : `${name} 편집`}
      danger={kind === 'remove'}
      width={kind === 'remove' ? 420 : 560}
      onClose={onClose}
      footer={
        finished ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className={kind === 'remove' ? 'btn danger solid' : 'btn primary'} disabled={m.busy || !ready} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : kind === 'remove' ? '제거' : isNew ? '추가' : '저장'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        {kind === 'remove' ? (
          <>
            <div>웹에서 추가한 서비스 {name}{eulReul(name!)} 다음 배포(동기화나 후보 승인) 때 앱에서 뺍니다. 지금 바로 배포하지 않으며 Git에는 영향이 없습니다.</div>
            <Field label={<>확인하려면 <b className="mono">{name}</b>{eulReul(name!)} 입력하세요</>}>
              <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value)} disabled={finished} autoComplete="off" spellCheck={false} />
            </Field>
          </>
        ) : (
          <>
            <Field label="서비스 이름" hint={`Git 서비스(${local.gitServices.join(', ') || '없음'})와 겹치면 안 됩니다`}>
              <input className="mono" value={n} disabled={!isNew || finished} onChange={(e) => setN(e.target.value.trim())} spellCheck={false} autoComplete="off" />
            </Field>
            <Field label="서비스 내용 (app.yaml의 services 아래 그대로)" hint="Git 서비스를 가리키는 depends_on은 서버가 거절합니다. 비밀값은 secrets로 참조만 넣습니다.">
              <textarea className="mono" rows={10} value={body} disabled={finished} onChange={(e) => setBody(e.target.value)} spellCheck={false} />
            </Field>
            {problem && <div className="note wa small">{problem}</div>}
            <div className="note info small">지금 바로 배포하지 않습니다. 다음 동기화나 후보 승인 때 Git 문서에 더해져 배포됩니다. 동기화·정리 때도 웹 추가분은 남습니다.</div>
          </>
        )}
        <Err e={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

// ── 후보 승인 담당 ──────────────────────────────

function ApproversCard({ a, cd, canDeploy, onDone }: { a: AppView; cd: Cd; canDeploy: boolean; onDone: () => void }) {
  // 목록을 읽은 순간의 CD revision을 함께 둔다: 보낼 때 expected는 화면에 보인 목록의 revision
  const q = usePoll(async (s) => ({ list: await cdApprovers(a.tenant, a.app, s), rev: cd.revision }), [a.tenant, a.app, cd.revision]);
  const wait = !!q.error && noEndpoint(q.error);
  const m = useMutation();
  const [user, setUser] = useState('');
  const [last, setLast] = useState<{ user: string; add: boolean }>();
  const [drop, setDrop] = useState<string>();
  // 창이 아니라 카드에서 보내므로, 확정되면 새로 읽는다
  useEffect(() => {
    if (m.op?.state === 'applied') (void q.refresh(), onDone());
  }, [m.op?.state]); // eslint-disable-line react-hooks/exhaustive-deps
  const go = async (u: string, add: boolean) => {
    // 다른 사람·다른 동작이면 새 작업
    if (last && (last.user !== u || last.add !== add)) m.reset();
    setLast({ user: u, add });
    await sendOp(m, `${cdPath(a.tenant, a.app)}/approvers`, { user: u, expected: q.data!.rev }, add ? 'POST' : 'DELETE');
    if (add) setUser('');
  };
  return (
    <Card title="후보 승인 담당" actions={wait ? <Badge tone="wa">서버 기능 대기</Badge> : undefined}>
      <span className="small muted">이 앱 후보의 승인·반려만 맡는 사람입니다. 수동 모드일 때 씁니다.</span>
      {!wait && (
        <Load q={q} what="승인 담당을 읽지 못했습니다">
          {({ list: us }) => (
            <>
              <div className="row wrap" style={{ gap: 6 }}>
                {us.map((u) => (
                  <span key={u} className="chip">
                    {u}
                    <button type="button" className="linkish" aria-label={`${u} 빼기`} disabled={!canDeploy || m.busy} title={!canDeploy ? NEED : '승인 담당에서 빼기'} onClick={() => setDrop(u)}>
                      ✕
                    </button>
                  </span>
                ))}
                {!us.length && <span className="muted small">아직 없습니다. 작업 공간의 배포 권한이 있는 사람만 승인합니다.</span>}
              </div>
              <div className="row" style={{ gap: 8 }}>
                <input className="mono" placeholder="사용자 이름 (이 작업 공간 구성원)" aria-label="사용자 이름" value={user} disabled={!canDeploy || m.busy} onChange={(e) => setUser(e.target.value.trim())} style={{ flex: 1 }} />
                <button type="button" className="btn" disabled={!canDeploy || m.busy || !user || us.includes(user)} title={!canDeploy ? NEED : us.includes(user) ? '이미 승인 담당입니다' : undefined} onClick={() => void go(user, true)}>
                  추가
                </button>
              </div>
              <span className="small muted">추가하면 그 사람은 이 앱 후보의 승인·반려만 할 수 있습니다. 동기화·일시정지·다른 앱·비밀값 묶음 승인은 못 합니다. 서명을 한 번 받습니다.</span>
            </>
          )}
        </Load>
      )}
      {m.error instanceof ApiError && m.error.code === 'not-found' ? <div className="note wa small">{last?.user ?? '그 사용자'}{eunNeun(last?.user ?? '그 사용자')} 이 작업 공간 구성원이 아닙니다. 구성원만 승인 담당이 될 수 있습니다.</div> : <Err e={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o) => m.setOp(o)} />}
      {drop && (
        <Dialog
          danger
          title={`${drop}${eulReul(drop)} 후보 승인 담당에서 뺄까요?`}
          width={420}
          onClose={() => setDrop(undefined)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setDrop(undefined)}>
                취소
              </button>
              <button type="button" className="btn danger solid" onClick={() => (setDrop(undefined), void go(drop, false))}>
                빼기
              </button>
            </>
          }
        >
          {drop}{eunNeun(drop)} 이제 {a.app} 후보를 승인·반려할 수 없습니다. 작업 공간의 다른 권한은 그대로입니다.
        </Dialog>
      )}
    </Card>
  );
}

// ── 정책 (UI-41) ───────────────────────────────────

const policyLines = (p: DCdPolicy) =>
  [
    `enabled: ${p.enabled}`,
    `source.repository: ${p.source.repository}`,
    `source.ref: ${p.source.ref}`,
    `source.path: ${p.source.path}`,
    `source.credential: ${p.source.credential || '""'}`,
    `poll: ${p.poll}`,
    `sync.mode: ${p.sync.mode}`,
    `sync.drift: ${p.sync.drift}`,
    `sync.prune: ${p.sync.prune}`,
    `sync.allowEmpty: ${p.sync.allowEmpty}`,
  ].join('\n');

function PolicyCard({ a, cd, canDeploy, onDone }: { a: AppView; cd: Cd; canDeploy: boolean; onDone: () => void }) {
  const links = usePoll((s) => webhookLinks({ point: 'cd', tenant: a.tenant, app: a.app }, s), [a.tenant, a.app], 0, kindsLive('webhook-link'));
  const [edit, setEdit] = useState<DCdPolicy>();
  const [review, setReview] = useState(false);
  const p = edit ?? cd.policy;
  if (!p)
    return (
      <Card title="자동 배포 정책">
        <span className="muted">정책을 읽지 못했습니다.</span>
      </Card>
    );
  const set = (f: (x: DCdPolicy) => DCdPolicy) => setEdit(f(structuredClone(p)));
  const dirty = !!edit && policyLines(edit) !== policyLines(cd.policy!);
  const pollBad = !(p.poll >= 1 && p.poll <= 86400);
  // 배포 전 확인 웹훅(UI-44)은 수동 모드에서만 걸린다(cd-mode)
  const gate = !!links.data?.items.some((l) => l.kind === 'pre-sync');
  return (
    <Card title="자동 배포 정책" actions={<span className="small muted">policy rev {cd.policyRevision}</span>}>
      <div className="g2">
        <Field label="동기화 모드">
          <Segmented
            label="동기화 모드"
            value={p.sync.mode}
            onChange={(v) => set((x) => ((x.sync.mode = v), x))}
            options={[
              ['manual', '수동'],
              ['automatic', '자동'],
            ]}
            disabled={gate ? { automatic: '배포 전 확인 웹훅이 연결돼 있어 자동으로 바꿀 수 없습니다. 먼저 연결을 끊으세요' } : undefined}
          />
        </Field>
        <Field label="Git과 차이">
          <Segmented
            label="Git과 차이"
            value={p.sync.drift}
            onChange={(v) => set((x) => ((x.sync.drift = v), x))}
            options={[
              ['report', '알리기만'],
              ['reconcile', 'Git대로 맞추기'],
            ]}
          />
        </Field>
        <Field label="정리 (prune)" hint="Git에서 빠진 서비스를 지웁니다">
          <Segmented
            label="정리"
            value={String(p.sync.prune)}
            onChange={(v) => set((x) => ((x.sync.prune = v === 'true'), x))}
            options={[
              ['false', 'false'],
              ['true', 'true'],
            ]}
          />
        </Field>
        <Field label="Git 확인 간격(초)" error={pollBad ? '1 ~ 86400초' : undefined}>
          <input inputMode="numeric" value={String(p.poll)} disabled={!canDeploy} onChange={(e) => set((x) => ((x.poll = Number(e.target.value.replace(/\D/g, '') || 0)), x))} />
        </Field>
        <Field label="Git 접속 정보" hint="서버에 설치된 접속 정보 이름만 넣습니다">
          <input className="mono" value={p.source.credential} disabled={!canDeploy} placeholder="git-readonly" onChange={(e) => set((x) => ((x.source.credential = e.target.value.trim()), x))} />
        </Field>
        <Field label="runtime 편집">
          <span className="mono small">{p.runtime.mode || 'require-explicit-override'}</span>
        </Field>
      </div>
      <span className="small muted">Git 비밀번호나 키 자체는 여기서 입력받지 않습니다. 서버에 미리 설치된 Git 접속 정보의 이름만 고릅니다. 허용하는 Git 출처는 서버가 판단합니다.</span>
      <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
        {dirty && (
          <button type="button" className="btn" onClick={() => setEdit(undefined)}>
            되돌리기
          </button>
        )}
        <button type="button" className="btn primary" disabled={!canDeploy || !dirty || pollBad} title={!canDeploy ? NEED : undefined} onClick={() => setReview(true)}>
          정책 변경 검토
        </button>
      </div>
      {review && edit && <PolicyReview a={a} cd={cd} next={edit} onClose={() => setReview(false)} onDone={() => (setEdit(undefined), onDone())} />}
    </Card>
  );
}

function PolicyReview({ a, cd, next, onClose, onDone }: { a: AppView; cd: Cd; next: DCdPolicy; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  // 검토 창을 연 순간의 CD revision을 expected로 고정한다. 그사이 다른 사람이 바꿨으면 op가 failed다.
  const [body] = useState(() => ({ policy: next, expected: cd.revision }));
  const send = async () => {
    if (m.op || m.error) m.reset();
    const o = await m.run(`${cdPath(a.tenant, a.app)}/policy`, body, 'PUT');
    if (o?.state === 'applied') onDone();
  };
  const finished = m.op?.state === 'applied';
  return (
    <Dialog
      title={`자동 배포 정책 rev ${cd.policyRevision} → ${cd.policyRevision + 1}`}
      width={560}
      onClose={onClose}
      footer={
        finished ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn primary" disabled={m.busy} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '저장'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <DiffView lines={lineDiff(policyLines(cd.policy!), policyLines(next)).filter((l) => l.op !== ' ')} />
        {next.sync.prune && !cd.policy!.sync.prune && <div className="note wa small">정리(prune)를 켜면 Git에 없는 서비스를 지웁니다.</div>}
        <Err e={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

// ── 값 고정 (UI-43) ────────────────────────────────

const FIELD_KEYS = ['image', 'command', 'entrypoint', 'user', 'stop_signal', 'stop_grace_period', 'cpus', 'mem_limit', 'dns', 'dns_search', 'logging'];
/** services.<svc>.<key>, services.<svc>.environment.<KEY>, services.<svc>.healthcheck.<key> */
export function fieldPath(text: string): string[] | undefined {
  const p = text.trim().split('.');
  if (p[0] !== 'services' || !p[1]) return undefined;
  if (p.length === 3 && FIELD_KEYS.includes(p[2])) return p;
  if (p.length === 4 && p[2] === 'environment' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(p[3])) return p;
  if (p.length === 4 && p[2] === 'healthcheck' && ['test', 'interval', 'timeout', 'retries', 'start_period', 'start_interval', 'disable'].includes(p[3])) return p;
  return undefined;
}
/** 입력을 JSON 값으로. JSON으로 읽히면 그대로, 아니면 문자열 */
export function fieldValue(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function OverrideCard({ a, cd, canDeploy, onDone }: { a: AppView; cd: Cd; canDeploy: boolean; onDone: () => void }) {
  const [set, setSet] = useState<string[] | 'new'>();
  const [release, setRelease] = useState<string[]>();
  return (
    <Card
      title="설정 임시 변경"
      actions={
        <button type="button" className="btn sm" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => setSet('new')}>
          ＋ 임시 변경
        </button>
      }
    >
      <div className="table-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>설정 항목</th>
              <th>Git 값</th>
              <th>지금 값</th>
              <th>상태</th>
              <th aria-label="작업" />
            </tr>
          </thead>
          <tbody>
            {cd.overridePaths.map((p) => (
              <OverrideRow key={p.join('.')} a={a} p={p} rev={cd.overrideRevision} canDeploy={canDeploy} onSet={() => setSet(p)} onRelease={() => setRelease(p)} />
            ))}
            {!cd.overridePaths.length && (
              <tr>
                <td colSpan={5} className="muted">
                  임시로 바꾼 설정이 없습니다.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <span className="small muted">Git 값과 다르게 잠시 둔 설정입니다. 해제하면 Git 값으로 돌아가며 그 서비스가 다시 시작됩니다. 비밀값은 환경 변수로 고정하지 말고 비밀값 보관함을 쓰세요. 고정한 값은 서명한 원본에 그대로 남습니다.</span>
      {set && <OverrideDialog a={a} path={set === 'new' ? undefined : set} onClose={() => setSet(undefined)} onDone={onDone} />}
      {release && <ReleaseDialog a={a} path={release} onClose={() => setRelease(undefined)} onDone={onDone} />}
    </Card>
  );
}

function OverrideDialog({ a, path, onClose, onDone }: { a: AppView; path?: string[]; onClose: () => void; onDone: () => void }) {
  const [text, setText] = useState(path?.join('.') ?? 'services.');
  const [value, setValue] = useState('');
  const [checked, setChecked] = useState<{ path: string; ok: boolean; e?: unknown }>();
  const m = useMutation();
  const p = fieldPath(text);
  const isEnv = p?.[2] === 'environment';
  const check = async () => {
    if (!p) return;
    try {
      await cdField(a.tenant, a.app, p);
      setChecked({ path: text, ok: true });
    } catch (e) {
      setChecked({ path: text, ok: false, e });
    }
  };
  const send = async () => {
    if (!p) return;
    if (m.op || m.error) m.reset();
    const o = await m.run(`${cdPath(a.tenant, a.app)}/overrides`, { path: p, value: fieldValue(value) }, 'PUT');
    if (o?.state === 'applied') onDone();
  };
  const finished = m.op?.state === 'applied';
  const ready = !!p && checked?.path === text && checked.ok && value.trim() !== '';
  return (
    <Dialog
      title={`설정 임시 변경${p ? ` · ${p.join('.')}` : ''}`}
      width={560}
      onClose={onClose}
      footer={
        finished ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn primary" disabled={m.busy || !ready} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '임시 변경'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <Field label="설정 항목" error={text && !p ? 'services.<서비스>.image · cpus · mem_limit … 또는 environment.<KEY> · healthcheck.<항목>' : undefined}>
          <span className="row" style={{ flexWrap: 'nowrap' }}>
            <input className="mono" style={{ flex: 1 }} value={text} disabled={!!path || finished} onChange={(e) => (setText(e.target.value), setChecked(undefined))} spellCheck={false} />
            {!path && (
              <button type="button" className="btn" disabled={!p} onClick={() => void check()}>
                확인
              </button>
            )}
          </span>
        </Field>
        {path && checked === undefined && <AutoCheck run={check} />}
        {checked && !checked.ok && <Err e={checked.e} />}
        {checked?.ok && <div className="note ok small">고정할 수 있는 항목입니다.</div>}
        {checked?.ok && checked.path === text && p && <GitValue a={a} p={p} />}
        <Field label="임시 값" hint="숫자·true/false·배열은 JSON으로 읽고, 그 밖에는 글자 그대로 씁니다">
          <input className="mono" value={value} disabled={finished} onChange={(e) => setValue(e.target.value)} spellCheck={false} autoComplete="off" />
        </Field>
        {isEnv && <div className="note wa small">비밀값은 환경 변수로 고정하지 말고 비밀값 보관함을 쓰세요. 여기 넣은 값은 서명한 원본에 그대로 남습니다.</div>}
        <span className="small muted">다음 Git 변경이 와도 직접 해제할 때까지 이 값을 씁니다.</span>
        <Err e={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

/** 이미 고정된 칸을 열면 한 번 확인한다 */
function AutoCheck({ run }: { run: () => Promise<void> }) {
  useState(() => void run());
  return null;
}

function ReleaseDialog({ a, path, onClose, onDone }: { a: AppView; path: string[]; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const name = path[path.length - 1];
  const send = async () => {
    if (m.op || m.error) m.reset();
    const o = await m.run(`${cdPath(a.tenant, a.app)}/overrides`, { path }, 'DELETE');
    if (o?.state === 'applied') onDone();
  };
  const finished = m.op?.state === 'applied';
  return (
    <Dialog
      title={`${name} 임시 변경을 풀까요?`}
      danger
      width={420}
      onClose={onClose}
      footer={
        finished ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn danger solid" disabled={m.busy} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '해제'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <div>
          Git 값으로 돌아가며 {path[1]}이(가) 다시 시작됩니다. <span className="mono small">{path.join('.')}</span>
        </div>
        <Err e={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

// ── 자동 배포 켜기 (CDIx '자동 배포 켜기 (꺼진 앱)') ──────────────────────────────
// CD 정책은 PUT /cd/policy로도 정하고, app.yaml의 x-sfc.cd로도 정한다(#957). 나중에 보낸 쪽이 이긴다.
// CD가 없는 앱에 처음 보내면 sfcd가 등록하고(configure-app-cd, PolicyRevision 0), expected는 앱 revision이다.

export interface ConnectInput {
  repository: string;
  branch: string;
  path: string;
  credential: string;
  mode: 'manual' | 'automatic';
}

/** 처음 켤 때의 CD 정책. 나머지는 CLI 기본값과 같다(1분마다 확인, 어긋남은 알리기만, 정리 안 함, 가져오기 30초·4MiB·대기 1·동시 1). sfcd가 limits 범위를 검사한다(compose_parse.go) */
export function connectPolicy(c: ConnectInput): DCdPolicy {
  return {
    enabled: true,
    source: { kind: 'git', repository: c.repository.trim(), ref: c.branch.trim(), path: c.path.trim(), credential: c.credential.trim() },
    poll: 60,
    sync: { mode: c.mode, drift: 'report', prune: false, allowEmpty: false },
    runtime: { mode: 'require-explicit-override', expiry: 'manual-release' },
    limits: { fetch: 30, bytes: 4 << 20, queued: 1, active: 1 },
  };
}

function ConnectTab({ a, canDeploy }: { a: AppView; current?: string; canDeploy: boolean }) {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState<ConnectInput>();
  const m = useMutation();
  // 카드를 연 순간의 앱 revision을 expected로 고정한다. 그사이 앱이 바뀌었으면 op가 failed다.
  const [expected, setExpected] = useState(a.revision);
  const send = async () => {
    if (!input) return;
    if (m.error) m.reset();
    const o = await m.run(`${cdPath(a.tenant, a.app)}/policy`, { policy: connectPolicy(input), expected }, 'PUT');
    if (o?.state === 'applied') refreshAll();
  };
  return (
    <>
      <Empty title="자동 배포가 꺼져 있습니다">
        Git 저장소를 연결하면 새 커밋을 계획하고, 정책대로 배포합니다.
        <div className="row" style={{ justifyContent: 'center', marginTop: 12 }}>
          <button type="button" className="btn primary" disabled={!canDeploy} title={!canDeploy ? NEED : undefined} onClick={() => setOpen(true)}>
            자동 배포 켜기
          </button>
        </div>
      </Empty>
      {input && (
        <Card title="자동 배포 켜기 · 확인" actions={<span className="small muted">앱 버전 {expected} 기준</span>}>
          <span className="small">
            <code className="break-any">{input.repository}</code> · {input.branch} · {input.path} · 동기화 {input.mode === 'manual' ? '수동' : '자동'}
            {input.credential ? ` · 자격 증명 ${input.credential}` : ''}
          </span>
          <span className="small muted">앱 정의는 그대로 두고 자동 배포 정책만 등록합니다. 등록하면 서버가 Git을 읽어 첫 후보를 계획합니다.</span>
          <Err e={m.error} />
          {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && refreshAll())} />}
          {!m.op && (
            <div className="row" style={{ justifyContent: 'flex-end' }}>
              <button type="button" className="btn sm" onClick={() => setInput(undefined)}>
                취소
              </button>
              <button type="button" className="btn sm primary" disabled={m.busy || !canDeploy} onClick={() => void send()}>
                {m.busy ? '보내는 중…' : '자동 배포 켜기'}
              </button>
            </div>
          )}
        </Card>
      )}
      {open && <ConnectDialog a={a} onClose={() => setOpen(false)} onNext={(c) => (m.reset(), setExpected(a.revision), setInput(c), setOpen(false))} />}
    </>
  );
}

const PROBE_ERR: Record<string, string> = {
  'auth-failed': '저장소에 로그인하지 못했습니다. 접속 정보 이름을 확인하세요',
  'no-repository': '저장소를 찾지 못했습니다',
  'no-branch': '그 브랜치가 없습니다',
  'no-file': '그 경로에 파일이 없습니다',
  'no-credential': '서버에 그 이름의 접속 정보가 없습니다',
  timeout: '저장소가 제때 답하지 않았습니다. 잠시 뒤 다시 확인하세요',
  'too-large': '그 파일이 너무 큽니다. app.yaml 경로가 맞는지 확인하세요',
  'source-error': '저장소를 읽다가 오류가 났습니다. 잠시 뒤 다시 확인하세요',
  'rate-limited': '너무 자주 확인했습니다. 잠시 뒤 다시 누르세요',
};

function ConnectDialog({ a, onClose, onNext }: { a: AppView; onClose: () => void; onNext: (c: ConnectInput) => void }) {
  const [c, setC] = useState<ConnectInput>({ repository: '', branch: 'main', path: 'app.yaml', credential: '', mode: 'manual' });
  const [probe, setProbe] = useState<{ busy?: boolean; r?: CdProbe; error?: unknown; wait?: boolean }>({});
  const set = (k: keyof ConnectInput) => (e: { target: { value: string } }) => (setC((x) => ({ ...x, [k]: e.target.value })), setProbe((p) => (p.wait ? p : {})));
  const check = async () => {
    setProbe({ busy: true });
    try {
      setProbe({ r: await cdProbe(a.tenant, a.app, { repository: c.repository.trim(), branch: c.branch.trim(), path: c.path.trim(), ...(c.credential.trim() ? { credential: c.credential.trim() } : {}) }) });
    } catch (e) {
      setProbe(noEndpoint(e) ? { wait: true } : { error: e });
    }
  };
  // sfcd는 https:// 저장소만 받는다(사용자 정보·쿼리·조각 없이, compose_parse.go INVALID_GIT_SOURCE)
  const ok = /^https:\/\/[^\s@?#]+$/.test(c.repository.trim()) && !!c.branch.trim() && !!c.path.trim();
  return (
    <Dialog
      title="Git 저장소 연결"
      width={560}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn primary" disabled={!ok} onClick={() => onNext(c)}>
            다음
          </button>
        </>
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <Field label="Git 저장소" error={c.repository && !/^https:\/\/[^\s@?#]+$/.test(c.repository.trim()) ? 'https:// 주소만 됩니다(로그인 정보는 주소에 넣지 말고 접속 정보 이름으로)' : undefined}>
          <input className="mono" value={c.repository} onChange={set('repository')} placeholder="https://git.example/team/shop.git" spellCheck={false} autoComplete="off" />
        </Field>
        <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <Field label="브랜치">
            <input className="mono" value={c.branch} onChange={set('branch')} spellCheck={false} />
          </Field>
          <Field label="파일 경로">
            <input className="mono" value={c.path} onChange={set('path')} spellCheck={false} />
          </Field>
        </div>
        <Field label="Git 접속 정보" hint="비밀번호·키는 여기서 받지 않습니다. 서버에 설치된 접속 정보 이름만 넣습니다. 비우면 공개 저장소입니다.">
          <input className="mono" value={c.credential} onChange={set('credential')} placeholder="git-readonly" spellCheck={false} autoComplete="off" />
        </Field>
        <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <button type="button" className="btn sm" disabled={!ok || probe.busy || probe.wait} title={probe.wait ? '서버 기능 대기' : undefined} onClick={() => void check()}>
            {probe.busy ? '읽는 중…' : '읽기 확인'}
          </button>
          {probe.r ? (
            <span className="small">
              <Badge tone="ok">읽음</Badge> 최신 커밋 <code>{short(probe.r.commit)}</code> · {c.path.trim()} {fmtBytes(probe.r.size)}
              {probe.r.node ? <span className="muted"> · {probe.r.node}에서</span> : null}
            </span>
          ) : probe.error !== undefined ? (
            <span className="small" style={{ color: 'var(--er)' }}>
              {PROBE_ERR[(probe.error as ApiError).code ?? ''] ?? errorText(probe.error).message}
            </span>
          ) : (
            <span className="small muted">{probe.wait ? '읽기 확인: 서버 기능 대기. 제출한 뒤 상태의 ‘가져올 곳’에서 읽기 결과를 봅니다.' : '서버가 Git을 한 번 읽어 최신 커밋과 파일 크기를 보여 줍니다. 아무것도 바꾸지 않습니다.'}</span>
          )}
        </div>
        <Field label="동기화 모드">
          <select value={c.mode} onChange={set('mode')}>
            <option value="manual">수동 (처음엔 권장)</option>
            <option value="automatic">자동</option>
          </select>
        </Field>
      </div>
    </Dialog>
  );
}

// ── 후보·실행 이력 ──────────────────────────────

const RESULT: Record<string, [string, Tone]> = {
  candidate: ['후보', 'pr'],
  running: ['진행 중', 'pr'],
  succeeded: ['성공', 'un'],
  failed: ['실패', 'er'],
  abandoned: ['버려짐', 'un'],
  blocked: ['막힘', 'wa'],
  rejected: ['반려됨', 'un'],
};
const CHECK_NAME: Record<string, [string, 'ok' | 'wa' | 'er']> = { checking: ['확인 중', 'wa'], held: ['보류', 'wa'], passed: ['통과', 'ok'], rejected: ['거부', 'er'], timeout: ['시간 초과', 'wa'], failed: ['실패', 'er'], ok: ['정상', 'ok'] };
/** 이력 행의 웹훅 확인 (데몬 #168, 캔버스 v127): 상태 배지 옆 작은 테두리 배지, 툴팁은 웹훅 이름 · 이유 */
function checkBadges(c?: DCdHistory['checks']) {
  if (!c) return null;
  return (['pre-sync', 'post-sync'] as const).map((k) => {
    const g = c[k];
    if (!g) return null;
    const [l, t] = CHECK_NAME[g.state] ?? [g.state, 'wa'];
    return (
      <span key={k} className={`cbadge ${t}`} title={[g.webhook, g.reason ?? (g.status ? String(g.status) : undefined)].filter(Boolean).join(' · ')}>
        {k === 'pre-sync' ? (g.state === 'checking' ? '배포 전 확인 중' : `배포 전 확인 ${l}`) : `배포 후 ${l}`}
      </span>
    );
  });
}
const unix = (sec?: number) => (sec ? fmtTime(new Date(sec * 1000).toISOString()) : '—');

function HistoryCard({ a, cd, canDeploy, onRecover, onApprove }: { a: AppView; cd: Cd; canDeploy: boolean; onRecover: () => void; onApprove: () => void }) {
  const h = usePoll((s) => cdHistory(a.tenant, a.app, s), [a.tenant, a.app, cd.revision], 0, cdLive(a.tenant, a.app));
  const [changes, setChanges] = useState(false);
  if (h.error && noEndpoint(h.error)) return <HistoryFallback cd={cd} canDeploy={canDeploy} onRecover={onRecover} onApprove={onApprove} />;
  return (
    <Card title="후보·실행 이력" actions={<span className="muted small">상태 옆 작은 배지는 자동 배포 웹훅 확인 결과 · 올리면 웹훅 이름과 이유</span>}>
      <Load q={h} what="이력을 읽지 못했습니다">
        {(p) => (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>커밋</th>
                  <th>후보 지문</th>
                  <th>상태</th>
                  <th>작업</th>
                  <th aria-label="동작" />
                </tr>
              </thead>
              <tbody>
                {p.items.map((r, i) => {
                  const live = r.result === 'succeeded' && r.commit === cd.running;
                  const isCand = r.commit === cd.candidate && (r.result === 'candidate' || r.result === 'blocked');
                  const [label, tone] = live ? (['실행 중', 'ok'] as [string, Tone]) : r.result === 'blocked' && r.reason === 'group-approval' ? (['승인 대기', 'wa'] as [string, Tone]) : r.result === 'abandoned' && r.reason === 'superseded' ? (['새 후보에 밀림', 'un'] as [string, Tone]) : RESULT[r.result] ?? [r.result, 'un'];
                  return (
                    <tr key={`${r.candidateDigest}/${i}`} title={`계획 ${unix(r.plannedAt)}${r.finishedAt ? ` · 끝 ${unix(r.finishedAt)}` : ''}${r.reason ? ` · ${BLOCKED[r.reason] ?? r.reason}` : ''}`}>
                      <td>
                        <code>{short(r.commit)}</code>
                      </td>
                      <td className="mono small">{r.candidateDigest ? `sha256:${r.candidateDigest.slice(0, 4)}…` : '—'}</td>
                      <td>
                        <span className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
                          <Badge tone={tone}>{label}</Badge>
                          {checkBadges(r.checks)}
                        </span>
                      </td>
                      <td className="mono small">{r.operation ?? '—'}</td>
                      <td className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                        {isCand && (
                          <button type="button" className="btn sm" onClick={() => setChanges(true)}>
                            변경점
                          </button>
                        )}
                        {isCand && (r.reason === 'group-approval' || (manualOf(cd) && !cd.paused)) && (
                          <button type="button" className="btn sm" onClick={onApprove}>
                            승인
                          </button>
                        )}
                        {live && (
                          <button type="button" className="btn sm" disabled={!canDeploy || !cd.candidate} title={!canDeploy ? NEED : !cd.candidate ? ERR['no-candidate'] : '실패한 동기화를 후보로 다시 맞추고 고칩니다'} onClick={onRecover}>
                            복구
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {!p.items.length && (
                  <tr>
                    <td colSpan={5} className="muted">
                      아직 계획한 후보가 없습니다.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Load>
      {h.data?.next && <span className="small muted">더 오래된 이력이 있습니다(최신 {h.data.items.length}개만 보입니다).</span>}
      {changes && <ChangesDialog a={a} onClose={() => setChanges(false)} />}
    </Card>
  );
}

/** 이력 끝점이 없는 옛 데몬: 실행 중과 최신 후보만 */
function HistoryFallback({ cd, canDeploy, onRecover, onApprove }: { cd: Cd; canDeploy: boolean; onRecover: () => void; onApprove: () => void }) {
  const setAct = (_: 'recover') => onRecover();
  const setApprove = (_: boolean) => onApprove();
  return (
    <Card title="후보·실행 이력">
      <div className="table-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>커밋</th>
              <th>후보 지문</th>
              <th>상태</th>
              <th aria-label="작업" />
            </tr>
          </thead>
          <tbody>
            {cd.candidate && cd.candidate !== cd.running && (
              <tr>
                <td>
                  <code>{short(cd.candidate)}</code>
                </td>
                <td className="mono small">{cd.candidateDigest ? `sha256:${cd.candidateDigest.slice(0, 4)}…` : '—'}</td>
                <td>{cd.blocked === 'group-approval' ? <Badge tone="wa">승인 대기</Badge> : cd.blocked ? <Badge tone="wa">막힘</Badge> : <Badge tone="pr">후보</Badge>}</td>
                <td className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                  {(cd.blocked === 'group-approval' || (manualOf(cd) && !cd.paused)) && (
                    <button type="button" className="btn sm" onClick={() => setApprove(true)}>
                      승인
                    </button>
                  )}
                </td>
              </tr>
            )}
            <tr>
              <td>
                <code>{short(cd.running)}</code>
              </td>
              <td className="mono small muted">—</td>
              <td>
                <Badge tone="ok">실행 중</Badge>
              </td>
              <td className="row" style={{ justifyContent: 'flex-end' }}>
                <button type="button" className="btn sm" disabled={!canDeploy || !cd.candidate} title={!canDeploy ? NEED : !cd.candidate ? ERR['no-candidate'] : '실패한 동기화를 후보로 다시 맞추고 고칩니다'} onClick={() => setAct('recover')}>
                  복구
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <span className="small muted">마지막 성공 커밋 {short(cd.lastSuccessCommit)}. 지난 후보·실행 이력: 서버 기능 대기. 지금은 실행 중과 최신 후보만 보입니다.</span>
    </Card>
  );
}

const show = (v: unknown) => (v === undefined ? undefined : typeof v === 'string' ? v : JSON.stringify(v));

function ChangesDialog({ a, onClose }: { a: AppView; onClose: () => void }) {
  const q = usePoll((s) => cdChanges(a.tenant, a.app, s), [a.tenant, a.app]);
  return (
    <Dialog title={q.data ? `${short(q.data.running)} → ${short(q.data.candidate)}` : '변경점'} onClose={onClose} footer={<button type="button" className="btn" onClick={onClose}>닫기</button>}>
      <Load q={q} what="변경점을 읽지 못했습니다">
        {(c) => (
          <div className="col" style={{ gap: 12 }}>
            <span className="small muted">Git 변경 · 바뀐 칸 {c.count}</span>
            {c.count === 0 && !c.added.length && !c.removed.length ? (
              <span className="small muted">실행 중 버전과 후보가 같습니다.</span>
            ) : (
              <DiffView
                lines={[
                  ...c.services.flatMap((s) => [
                    { op: ' ' as const, text: `${s.service}:` },
                    ...s.fields.flatMap((f) => {
                      const k = f.path.slice(2).join('.');
                      const b = show(f.before);
                      const n = show(f.after);
                      return [...(b !== undefined ? [{ op: '-' as const, text: `  ${k}: ${b}` }] : []), ...(n !== undefined ? [{ op: '+' as const, text: `  ${k}: ${n}` }] : [])];
                    }),
                  ]),
                  ...c.added.map((x) => ({ op: '+' as const, text: `${x}: (추가)` })),
                  ...c.removed.map((x) => ({ op: '-' as const, text: `${x}: (제거)` })),
                ]}
              />
            )}
            <span className="small muted">비밀값은 참조만 보입니다.</span>
          </div>
        )}
      </Load>
    </Dialog>
  );
}

/** 임시 변경 칸의 Git 값·지금 값 (REQ-46 cd/values) */
function useValues(a: AppView, path: string[] | undefined, rev: number) {
  const key = path?.join('.') ?? '';
  const q = usePoll((s) => (path ? cdValues(a.tenant, a.app, path, s) : Promise.resolve(undefined)), [a.tenant, a.app, key, rev]);
  const wait = !!q.error && noEndpoint(q.error);
  const fmt = (v: unknown) => (wait ? <span className="muted" title={WAIT_VALUE}>—</span> : q.data?.secrets ? <span className="muted">비밀값 참조</span> : v === undefined ? <span className="muted">—</span> : <code className="break-any">{show(v)}</code>);
  return { q, wait, git: fmt(q.data?.gitRunning), candidate: q.data && show(q.data.gitCandidate) !== show(q.data.gitRunning) ? fmt(q.data.gitCandidate) : undefined, current: fmt(q.data?.current) };
}

function OverrideRow({ a, p, rev, canDeploy, onSet, onRelease }: { a: AppView; p: string[]; rev: number; canDeploy: boolean; onSet: () => void; onRelease: () => void }) {
  const v = useValues(a, p, rev);
  return (
    <tr>
      <td className="mono">{p.join('.')}</td>
      <td className="small">{v.git}</td>
      <td className="small">{v.current}</td>
      <td>
        <Badge tone="wa">임시 변경 중</Badge>
      </td>
      <td className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
        <button type="button" className="btn sm" disabled={!canDeploy} onClick={onSet}>
          값 바꾸기
        </button>
        <button type="button" className="btn sm danger" disabled={!canDeploy} onClick={onRelease}>
          해제
        </button>
      </td>
    </tr>
  );
}

function GitValue({ a, p }: { a: AppView; p: string[] }) {
  const v = useValues(a, p, 0);
  return (
    <KV
      items={[
        ['Git 값', v.git],
        ...(v.candidate ? ([['후보의 Git 값', v.candidate]] as [ReactNode, ReactNode][]) : []),
        ['지금 값', v.current],
      ]}
    />
  );
}
