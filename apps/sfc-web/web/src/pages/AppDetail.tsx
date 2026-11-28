// SPDX-License-Identifier: Apache-2.0

import { changedLines, DraftBand, useStoredDraft, useUnsaved } from '../components/Unsaved';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import YAML from 'yaml';
import { enc } from '../api/client';
import { app as fetchApp, appPath, appRevisions, appSource, appTasks, containerPath } from '../api/endpoints';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import type { AppRevision, AppView, DiffLine, TaskView } from '../api/types';
import { useAuth, useTenantRole } from '../auth/session';
import { Badge, Card, Hash, HealthBadge, HelpBox, KV, PageHeader, Segmented } from '../components/ui';
import { GraphView } from '../components/graph/GraphView';
import { Empty, ErrorBand, Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { Drawer } from '../components/Drawer';
import { ConfirmDialog, Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { DataTable } from '../components/DataTable';
import { CodeView, DiffView, YamlEditor } from '../components/Code';
import { casFailed, MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { lineDiff } from '../lib/diff';
import { iGa } from '../lib/josa';
import { ago, fmtTime } from '../lib/format';
import { TaskTable } from './ServerDetail';
import { DeployFlow, Steps, type FlowStep } from './DeployFlow';
import { PlacementTab } from './Placement';
import { CdPauseDialog, CdTab } from './AppCd';
import { AppIncidentTab } from './AppIncident';
import { appLive } from '../lib/liveTopics';

/** app.yaml에서 화면에 그릴 앱 구성을 뽑는다. 원문이 기준이고, 모르는 키는 무시한다. */
interface Shape {
  services: { name: string; image: string; node: string; replicas: number; networks: string[]; volumes: string[]; secrets: string[] }[];
  networks: string[];
  volumes: string[];
  secrets: string[];
}
function shapeOf(text: string): Shape | undefined {
  try {
    const doc = YAML.parse(text) as Record<string, unknown>;
    const keys = (v: unknown) => (Array.isArray(v) ? v.map(String) : v && typeof v === 'object' ? Object.keys(v) : []);
    const services = Object.entries((doc.services ?? {}) as Record<string, Record<string, unknown>>).map(([name, v]) => ({
      name,
      image: String(v?.image ?? ''),
      node: String(((v?.['x-sfc'] ?? {}) as Record<string, unknown>).node ?? ''),
      replicas: Number(((v?.deploy ?? {}) as Record<string, unknown>).replicas ?? 1),
      networks: keys(v?.networks),
      volumes: ((v?.volumes as unknown[]) ?? []).map((x) => (typeof x === 'string' ? x.split(':')[0] : String((x as Record<string, unknown>)?.source ?? ''))),
      secrets: ((v?.secrets as unknown[]) ?? []).map((x) => (typeof x === 'string' ? x : String((x as Record<string, unknown>)?.source ?? ''))),
    }));
    return { services, networks: keys(doc.networks), volumes: keys(doc.volumes), secrets: keys(doc.secrets) };
  } catch {
    return undefined;
  }
}

function DownDialog({ a, volumes, onClose }: { a: AppView; volumes: string[]; onClose: () => void }) {
  const { session } = useAuth();
  const navigate = useNavigate();
  const m = useMutation();
  const down = () =>
    void m.run(`/t/${enc(a.tenant)}/apps/${enc(a.app)}/down`, {
      action: 'down-app',
      principal: session?.user.id ?? '',
      expected: a.revision,
      payload: { Tenant: a.tenant, App: a.app, Operation: `down-${m.opId.slice(0, 8)}` },
      rootRevision: 0,
      tenant: a.tenant,
      target: a.app,
      volumes,
    });
  if (m.op)
    return (
      <Dialog
        title="앱 내리기"
        width={560}
        onClose={onClose}
        footer={
          m.op.state === 'applied' ? (
            <button className="btn primary" onClick={() => navigate('/deploy/archived')}>
              보관된 앱으로
            </button>
          ) : (
            <button className="btn" onClick={onClose}>
              닫기
            </button>
          )
        }
      >
        {casFailed(m.op) && <div className="note wa small">그사이 앱 버전이 바뀌어 내리지 않았습니다. 새로 읽은 뒤 다시 해 주세요.</div>}
        <OpPanel op={m.op} onChange={m.setOp} />
      </Dialog>
    );
  return (
    <ConfirmDialog title="앱 내리기" target={a.app} actionLabel="내리기" busy={m.busy} onClose={onClose} onConfirm={down}>
      <p>
        앱 <b>{a.app}</b>의 컨테이너를 모두 멈추고 지웁니다. 내리기 직전 실행 중 app.yaml(버전 {a.revision})을 웹 앱에 보관하므로 '보관된 앱'에서 다시 올릴 수 있습니다.
      </p>
      {volumes.length > 0 && <div className="note un small">데이터 저장소 {volumes.join(', ')}는 지우지 않고 남깁니다.</div>}
      <MutationError error={m.error} />
    </ConfirmDialog>
  );
}

export function AppDetailPage() {
  const { tenant = '', app = '' } = useParams();
  const { canDeploy } = useTenantRole();
  const phone = usePhone();
  const navigate = useNavigate();
  const loc = useLocation();
  const a = usePoll((s) => fetchApp(tenant, app, s), [tenant, app], DEFAULT_POLL_MS, appLive(tenant, app));
  const src = usePoll((s) => appSource(tenant, app, 0, s), [tenant, app, a.data?.revision]);
  const [downing, setDowning] = useState(false);
  const [pausing, setPausing] = useState(false);
  const base = appPath(tenant, app);
  const shape = useMemo(() => (src.data ? shapeOf(src.data.yaml) : undefined), [src.data]);
  // 휴대폰 위쪽 막대: 앱 이름 · 배포 구성 · 버전, ⋯에는 앱 머리 단추 (UI-M4 ②)
  useMobileTop(
    phone
      ? {
          title: app,
          sub: a.data ? `배포 구성 ${a.data.deployment} · 버전 ${a.data.revision}` : tenant,
          menu: [
            ...(a.data?.cd ? [{ label: a.data.cd.paused ? '자동 배포 다시 켜기' : '자동 배포 일시정지', onSelect: () => (canDeploy ? setPausing(true) : undefined) }] : []),
            { label: '✦ 코디네이터에게 물어보기', onSelect: () => navigate('/coordinator', { state: { from: loc.pathname } }) },
            { label: '앱 내리기', wide: true, danger: true },
          ],
        }
      : undefined,
    [phone, app, a.data?.deployment, a.data?.revision, a.data?.cd?.paused, canDeploy],
  );
  return (
    <>
      <PageHeader
        crumbs={
          <>
            <Link to="/deploy">배포</Link> / {tenant} / {app}
          </>
        }
        title={
          <span className="row">
            {app} {a.data && <HealthBadge health={a.data.health} />}
          </span>
        }
        ids="UI-31 · UI-35 · UI-38"
        actions={
          phone ? undefined : <>
            <Refresh q={a} />
            <Menu
              label="앱 작업"
              button="앱 작업 ▾"
              items={[{ label: '내리기…', danger: true, onSelect: () => setDowning(true), disabledReason: !canDeploy ? '이 작업 공간의 배포 권한이 필요합니다' : !a.data ? '앱을 읽는 중' : undefined }]}
            />
          </>
        }
      />
      <Tabs
        label="앱 탭"
        items={[
          { to: base, label: '개요' },
          { to: `${base}/edit`, label: '편집' },
          { to: `${base}/place`, label: '배치' },
          { to: `${base}/cd`, label: '자동 배포' },
          { to: `${base}/incident`, label: '장애 대응' },
          { to: `${base}/revisions`, label: '버전 기록' },
        ]}
      />
      <Load q={a} what="앱을 불러오지 못했습니다">
        {(v) => (
          <Routes>
            <Route index element={phone ? <MOverview a={v} shape={shape} /> : <Overview a={v} shape={shape} srcError={src.error} />} />
            <Route path="edit" element={<Edit a={v} current={src.data?.yaml} />} />
            <Route path="place" element={<PlacementTab a={v} current={src.data?.yaml} services={shape?.services} />} />
            <Route path="revisions" element={phone ? <MRevisions a={v} /> : <Revisions a={v} />} />
            <Route path="cd" element={<CdTab a={v} current={src.data?.yaml} />} />
            <Route path="incident" element={<AppIncidentTab a={v} />} />
          </Routes>
        )}
      </Load>
      {pausing && a.data && <CdPauseDialog a={a.data} onClose={() => (setPausing(false), a.refresh())} />}
      {downing && a.data && <DownDialog a={a.data} volumes={shape?.volumes ?? []} onClose={() => (setDowning(false), a.refresh())} />}
    </>
  );
}

/** 휴대폰 앱 개요 (UI-M4 ②): 목표·적용됨·실제, 컨테이너 목록, 빌린 자원. 리소스 트리는 넓은 화면에서 */
function MOverview({ a, shape }: { a: AppView; shape?: Shape }) {
  const tasks = usePoll((s) => appTasks(a.tenant, a.app, s), [a.tenant, a.app], DEFAULT_POLL_MS, appLive(a.tenant, a.app));
  const list = tasks.data?.items ?? [];
  const running = list.filter((t) => t.observed === 'running' && !t.stale).length;
  const unknown = list.filter((t) => t.stale || t.observed === 'unknown').length;
  const other = list.length - running - unknown;
  const tone = (t: TaskView) => (t.observed === 'running' && !t.stale ? 'ok' : t.observed === 'exited' ? 'er' : t.observed === 'restarting' || t.observed === 'starting' ? 'pr' : 'un');
  const label = (t: TaskView) => (t.stale ? '확인 불가' : { running: '실행', starting: '시작 중', restarting: '재시작 중', exited: '종료', unknown: '확인 불가' }[t.observed]);
  const shared = shape ? [...new Set(shape.services.flatMap((s) => s.networks))] : [];
  const vols = shape ? [...new Set(shape.services.flatMap((s) => s.volumes).filter(Boolean))] : [];
  const secrets = shape ? [...new Set(shape.services.flatMap((s) => s.secrets).filter(Boolean))] : [];
  return (
    <>
      <div className="li">
        <div>
          <span style={{ width: 72, color: 'var(--muted)', flex: 'none' }}>목표</span>
          <span className="el">
            버전 {a.revision}
            {shape ? ` · ${shape.services.map((s) => `${s.name} ×${s.replicas}`).join(', ')}` : ''}
          </span>
        </div>
        <div>
          <span style={{ width: 72, color: 'var(--muted)', flex: 'none' }}>적용됨</span>
          <span className="el">
            버전 {a.revision}
            {tasks.data ? ` · ${running}/${list.length}` : ''}
          </span>
        </div>
        <div>
          <span style={{ width: 72, color: 'var(--muted)', flex: 'none' }}>실제</span>
          <span className="el">
            <HealthBadge health={a.health} /> 실행 중 {running}
            {other > 0 && ` · 그 밖 ${other}`}
            {unknown > 0 && <b style={{ color: 'var(--wa)' }}> · 확인 불가 {unknown}</b>}
          </span>
        </div>
      </div>
      {a.lastOp?.failed && <div className="bn err">마지막 작업이 실패했습니다. 버전 기록에서 바뀐 점을 확인하세요.</div>}
      <div className="m-sec">
        <span>컨테이너 {list.length}</span>
        <span className="muted">목록 · 트리는 넓은 화면에서</span>
      </div>
      <Load q={tasks}>
        {() =>
          list.length === 0 ? (
            <span className="muted small">컨테이너가 없습니다.</span>
          ) : (
            <div className="li">
              {list.map((t) => (
                <Link key={t.id} to={containerPath(t.tenant, t.app, t.service, t.instance)}>
                  <Badge tone={tone(t)}>{label(t)}</Badge>
                  <span className="el">
                    {t.service}-{t.instance} @ {t.node || '—'}
                  </span>
                  <span className="r">›</span>
                </Link>
              ))}
            </div>
          )
        }
      </Load>
      {(shared.length > 0 || vols.length > 0 || secrets.length > 0) && (
        <>
          <div className="m-sec">
            <span>빌린 자원 · 연결</span>
          </div>
          <div className="li">
            {shared.map((n) => (
              <Link key={`n-${n}`} to="/shared/networks">
                <span className="ic">⇄</span>망 {n}
                <span className="r">공유 자원</span>
              </Link>
            ))}
            {vols.map((n) => (
              <Link key={`v-${n}`} to="/shared/volumes">
                <span className="ic">▤</span>데이터 저장소 {n}
                <span className="r">빌림</span>
              </Link>
            ))}
            {secrets.map((n) => (
              <Link key={`s-${n}`} to="/shared/vault">
                <span className="ic">⚿</span>비밀값 묶음 {n}
                <span className="r" />
              </Link>
            ))}
          </div>
        </>
      )}
    </>
  );
}

function Overview({ a, shape, srcError }: { a: AppView; shape?: Shape; srcError?: unknown }) {
  const tasks = usePoll((s) => appTasks(a.tenant, a.app, s), [a.tenant, a.app], DEFAULT_POLL_MS, appLive(a.tenant, a.app));
  return (
    <>
      <HelpBox terms="앱 (app) · 서비스 (service) · 컨테이너 (Task) · 망 · 데이터 저장소 · 비밀값 (이름 참조)">
        <b>이 탭은</b> 앱의 지금 상태와 app.yaml이 가리키는 자원을 함께 보여 줍니다. 망·데이터 저장소·비밀값은 작업 공간의 공유 자원을 이름으로 빌려 씁니다.
      </HelpBox>
      <div className="grid-2">
        <Card title="상태">
          <KV
            items={[
              ['상태', <HealthBadge health={a.health} />],
              ['실행 중 버전', a.revision],
              ['배포 구성', a.deployment],
              ['최근 작업', a.lastOp ? `${a.lastOp.status} · ${a.lastOp.submitter ?? '—'}${a.lastOp.at ? ` · ${fmtTime(a.lastOp.at)}` : ''}` : '—'],
              ['최근 작업 ID', a.lastOp ? <code>{a.lastOp.id}</code> : '—'],
              ['마지막 관측', a.observedAt ? ago(a.observedAt) : '—'],
              ['점유 자원', a.claims],
            ]}
          />
          {a.lastOp?.failed && <div className="note er small">마지막 작업이 실패했습니다. 버전 기록에서 바뀐 점을 확인하세요.</div>}
        </Card>
        <Card title="앱 구성 (app.yaml 기준)">
          {srcError ? (
            <ErrorBand error={srcError} what="실행 중 app.yaml을 읽지 못했습니다" />
          ) : !shape ? (
            <span className="small muted">원문을 읽는 중이거나 해석하지 못했습니다.</span>
          ) : (
            <ul className="res-tree">
              {shape.services.map((s) => (
                <li key={s.name}>
                  <b>{s.name}</b> <span className="small muted">×{s.replicas}{s.node ? ` · ${s.node}` : ''}</span>
                  <div className="small">
                    <code title={s.image}>{s.image.replace(/@sha256:(.{8}).*/, '@sha256:$1…')}</code>
                  </div>
                  <div className="row small" style={{ gap: 4 }}>
                    {s.networks.map((n) => (
                      <Badge key={`n-${n}`} tone="tag">
                        망 {n}
                      </Badge>
                    ))}
                    {s.volumes.filter(Boolean).map((n) => (
                      <Badge key={`v-${n}`} tone="tag">
                        저장소 {n}
                      </Badge>
                    ))}
                    {s.secrets.filter(Boolean).map((n) => (
                      <Badge key={`s-${n}`} tone="tag">
                        비밀값 {n}
                      </Badge>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
      <Card title="컨테이너" actions={<Refresh q={tasks} />}>
        <Load q={tasks}>{(p) => <TaskTable tasks={p.items} showNode showApp={false} />}</Load>
      </Card>
    </>
  );
}

function Edit({ a, current }: { a: AppView; current?: string }) {
  const { canDeploy } = useTenantRole();
  const loc = useLocation();
  const carried = (loc.state as { yaml?: string; from?: string } | null) ?? null;
  const [text, setText] = useState<string>();
  const [step, setStep] = useState<FlowStep>(1);
  const [view, setView] = useState<'yaml' | 'graph'>('yaml');
  const value = text ?? carried?.yaml ?? current ?? '';
  const scope = `${a.tenant}/${a.app}`;
  const stored = useStoredDraft<string>('app-edit', carried?.yaml ? undefined : scope);
  const dirty = current !== undefined && value !== current && step < 4;
  const lines = current !== undefined ? changedLines(current, value) : 0;
  const un = useUnsaved({ dirty, what: `${a.app} 앱 편집`, count: lines, unit: '줄', draft: { kind: 'app-edit', scope, value, rev: a.revision } });
  // 제출하면 초안은 필요 없다
  useEffect(() => {
    if (step === 4) (un.clear(), stored.drop());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);
  if (current === undefined && !carried?.yaml) return <Empty title="실행 중 app.yaml을 읽는 중입니다" />;
  return (
    <>
      {un.guard}
      {stored.draft && text === undefined && <DraftBand draft={stored.draft} what={a.app} rev={a.revision} unit="줄" onResume={() => (setText(stored.draft!.value), stored.drop())} onDiscard={stored.drop} />}
      <HelpBox terms="변경 미리보기 (plan / diff) · 배포 구성 (deployment)">
        <b>이 탭은</b> 실행 중인 app.yaml을 고쳐 새 버전으로 올립니다. 새 앱 배포와 같은 경로(검사 → 변경 미리보기 → 업로드 → 제출)를 탑니다.
      </HelpBox>
      {carried?.from && <div className="note un small">{carried.from}의 원문으로 시작했습니다.</div>}
      {!canDeploy && <div className="note wa small">이 작업 공간에서는 읽기 권한만 있어 검사까지만 할 수 있습니다.</div>}
      <div className="row">
        <Segmented
          label="편집 방식"
          value={view}
          onChange={setView}
          options={[
            ['yaml', 'app.yaml'],
            ['graph', '그래프'],
          ]}
        />
        <span className="small muted">폼으로 고치려면 app.yaml을 복사해 새 앱 배포의 폼을 쓰세요.</span>
        <span className="grow" />
        {un.badge}
      </div>
      <Steps step={step} />
      {view === 'graph' && <GraphView tenant={a.tenant} yaml={value} onChange={setText} app={{ name: a.app, deployment: a.deployment }} canSave={canDeploy} />}
      <div className="main-side">
        <div className="primary col" style={{ gap: 16 }}>
          <YamlEditor value={value} onChange={setText} />
          {value !== current && current !== undefined && (
            <button className="btn sm" style={{ alignSelf: 'flex-start' }} onClick={() => setText(current)}>
              실행 중 원문으로 되돌리기
            </button>
          )}
        </div>
        <div className="aside">
          <DeployFlow tenant={a.tenant} yaml={value} canDeploy={canDeploy} onStep={setStep} deployment={a.deployment} currentVersion={a.revision} gitWarning={!!a.cd} />
        </div>
      </div>
    </>
  );
}

function Revisions({ a }: { a: AppView }) {
  const list = usePoll((s) => appRevisions(a.tenant, a.app, s), [a.tenant, a.app], 0, appLive(a.tenant, a.app));
  const navigate = useNavigate();
  const [pick, setPick] = useState<number[]>([]);
  const [from, to] = [...pick].sort((x, y) => x - y);
  const left = usePoll((s) => (from ? appSource(a.tenant, a.app, from, s) : Promise.resolve(undefined)), [a.tenant, a.app, from]);
  const right = usePoll((s) => (to ? appSource(a.tenant, a.app, to, s) : Promise.resolve(undefined)), [a.tenant, a.app, to]);
  const toggle = (r: AppRevision) => setPick((p) => (p.includes(r.version) ? p.filter((x) => x !== r.version) : [...p, r.version].slice(-2)));
  const statusTone = (st: string) => (st === 'succeeded' ? 'ok' : st === 'failed' ? 'er' : st === 'running' || st === 'pending' ? 'pr' : 'un');
  return (
    <>
      <HelpBox terms="버전 (app version) · 원문 digest">
        <b>이 탭은</b> 이 앱에 올린 app.yaml 버전을 봅니다. 두 버전을 고르면 원문 차이를 보여 주고, 예전 버전을 편집 탭으로 가져가 다시 올릴 수 있습니다.
      </HelpBox>
      <Card title="버전 기록" actions={<Refresh q={list} poll={false} />}>
        <Load q={list}>
          {(p) => (
            <DataTable
              rows={p.items}
              rowKey={(r) => String(r.version)}
              pageInfo={p}
              onRowClick={toggle}
              emptyTitle="기록된 버전이 없습니다"
              columns={[
                { key: 'pick', header: '비교', render: (r) => <input type="checkbox" checked={pick.includes(r.version)} onChange={() => toggle(r)} aria-label={`버전 ${r.version} 비교에 넣기`} onClick={(e) => e.stopPropagation()} /> },
                { key: 'v', header: '버전', value: (r) => r.version, render: (r) => <b>{r.version}{r.version === a.revision ? ' (실행 중)' : ''}</b> },
                { key: 'st', header: '결과', value: (r) => r.status, render: (r) => <Badge tone={statusTone(r.status)}>{r.status || '—'}</Badge> },
                { key: 'by', header: '올린 사람', value: (r) => r.submitter, render: (r) => r.submitter },
                { key: 'at', header: '시각', value: (r) => r.at, render: (r) => fmtTime(r.at) },
                { key: 'dg', header: '원문 digest', render: (r) => <Hash value={r.digest} /> },
                {
                  key: 'act',
                  header: '',
                  render: (r) =>
                    r.version !== a.revision && (
                      <button
                        className="btn sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          void appSource(a.tenant, a.app, r.version).then((s) => navigate(`${appPath(a.tenant, a.app)}/edit`, { state: { yaml: s.yaml, from: `버전 ${r.version}` } }));
                        }}
                      >
                        이 버전으로 편집
                      </button>
                    ),
                },
              ]}
            />
          )}
        </Load>
      </Card>
      {from && to ? (
        <Card title={`버전 ${from} → ${to} 차이`}>
          {left.error || right.error ? (
            <ErrorBand error={left.error ?? right.error} what="원문을 읽지 못했습니다(이력 정리로 지워졌을 수 있습니다)" />
          ) : left.data && right.data ? (
            <DiffView lines={lineDiff(left.data.yaml, right.data.yaml)} />
          ) : (
            <span className="small muted">원문을 읽는 중…</span>
          )}
        </Card>
      ) : pick.length === 1 ? (
        <Card title={`버전 ${pick[0]} 원문`}>
          <VersionSource a={a} version={pick[0]} />
        </Card>
      ) : null}
    </>
  );
}

function VersionSource({ a, version }: { a: AppView; version: number }) {
  const s = usePoll((sig) => appSource(a.tenant, a.app, version, sig), [a.tenant, a.app, version]);
  return <Load q={s}>{(v) => <CodeView text={v.yaml} />}</Load>;
}


// ── 휴대폰 버전 기록 (UI-M9 ② ③) ──────────────────────

type Origin = 'user' | 'cd' | 'incident';
/** 계약에 올린 경로 칸이 없어 작업 ID·올린 사람으로 가른다: cd-… 자동 배포, inc-…/fix-…·autofix 장애 대응 */
const originOf = (r: AppRevision): Origin =>
  r.submitter === 'cd' || r.operation.startsWith('cd-') ? 'cd' : /^(inc|fix)-/.test(r.operation) || r.submitter.includes('autofix') ? 'incident' : 'user';
const whoOf = (r: AppRevision) => {
  const o = originOf(r);
  return o === 'cd' ? `⟳ 자동 배포 ${r.operation.replace(/^cd-/, '').slice(0, 7)}` : o === 'incident' ? `⚑ 장애 대응 · ${r.submitter}` : r.submitter;
};
const monthDay = (iso: string) => {
  const d = new Date(iso);
  return `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
};
/** 오늘 10:41 · 어제 18:02 · 11-19 09:12 */
export function dayTime(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const hm = d.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', hour12: false });
  const day = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(new Date()) - day(d)) / 86_400_000);
  const md = monthDay(iso);
  return diff === 0 ? `오늘 ${hm}` : diff === 1 ? `어제 ${hm}` : `${md} ${hm}`;
}
const tagOf = (img: string) => {
  const noDigest = img.split('@')[0];
  const last = noDigest.split('/').pop() ?? noDigest;
  return last.includes(':') ? last.split(':')[1] : last || img.replace(/.*@sha256:(.{6}).*/, '@$1');
};
/** 두 원문에서 사람이 읽을 바뀐 점 한 줄 (서비스 추가·삭제 · 이미지 · 개수), 나머지는 줄 수 */
export function changeLine(prev: string | undefined, cur: string): string {
  if (prev === undefined) return '처음 올린 버전';
  const a = shapeOf(prev);
  const b = shapeOf(cur);
  const out: string[] = [];
  if (a && b) {
    const before = new Map(a.services.map((x) => [x.name, x]));
    for (const s of b.services) {
      const o = before.get(s.name);
      if (!o) out.push(`${s.name} 추가`);
      else {
        if (o.image !== s.image) out.push(tagOf(o.image) !== tagOf(s.image) ? `${s.name} 이미지 ${tagOf(o.image)} → ${tagOf(s.image)}` : `${s.name} 이미지 바꿈`);
        if (o.replicas !== s.replicas) out.push(`${s.name} ${o.replicas}→${s.replicas}개`);
        if (o.node !== s.node) out.push(`${s.name} 서버 ${o.node || '자동'} → ${s.node || '자동'}`);
      }
      before.delete(s.name);
    }
    for (const n of before.keys()) out.push(`${n} 삭제`);
  }
  if (out.length) return out.slice(0, 3).join(', ');
  const n = lineDiff(prev, cur).filter((l) => l.op !== ' ').length;
  return n ? `그 밖 ${n}줄 바뀜` : '원문 같음';
}
/** 바뀐 줄과 앞뒤 한 줄만, 사이는 접는다 */
function changedOnly(lines: DiffLine[]) {
  const keep = lines.map((l, i) => l.op !== ' ' || lines[i - 1]?.op === '+' || lines[i - 1]?.op === '-' || lines[i + 1]?.op === '+' || lines[i + 1]?.op === '-');
  const out: (DiffLine | null)[] = [];
  lines.forEach((l, i) => (keep[i] ? out.push(l) : out[out.length - 1] !== null && out.push(null)));
  return out;
}

/** 버전 원문을 한 번씩만 읽어 둔다. 회수된 원문은 null */
function useSources(a: AppView, versions: number[]) {
  const cache = useRef(new Map<number, string | null>());
  const [, bump] = useState(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const key = versions.join(',');
  useEffect(() => {
    for (const v of versions) {
      if (cache.current.has(v)) continue;
      cache.current.set(v, undefined as unknown as string);
      appSource(a.tenant, a.app, v)
        .then((s) => cache.current.set(v, s.yaml))
        .catch(() => cache.current.set(v, null))
        .finally(() => mounted.current && bump((x) => x + 1));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [a.tenant, a.app, key]);
  return (v: number) => cache.current.get(v);
}

const ORIGIN_CHIPS: [string, (r: AppRevision) => boolean][] = [
  ['사용자', (r) => originOf(r) === 'user'],
  ['자동 배포', (r) => originOf(r) === 'cd'],
  ['장애 대응', (r) => originOf(r) === 'incident'],
  ['실패만', (r) => r.status === 'failed'],
];

function MRevisions({ a }: { a: AppView }) {
  const list = usePoll((s) => appRevisions(a.tenant, a.app, s), [a.tenant, a.app], 0, appLive(a.tenant, a.app));
  const [chip, setChip] = useState('');
  const [shown, setShown] = useState(10);
  const [pick, setPick] = useState<number[]>([]);
  const [open, setOpen] = useState<{ v: number; with?: number }>();
  const press = useRef<{ t?: number; long?: boolean }>({});
  const all = list.data?.items ?? [];
  const rows = all.filter((r) => !chip || ORIGIN_CHIPS.find(([k]) => k === chip)?.[1](r));
  const view = rows.slice(0, shown);
  // 각 카드의 바뀐 점은 바로 앞 버전 원문과 견줘 만든다
  const prevOf = (v: number) => all.find((r) => r.version < v)?.version;
  const src = useSources(a, [...new Set(view.flatMap((r) => [r.version, prevOf(r.version)].filter((x): x is number => x !== undefined)))]);
  const toggle = (v: number) => setPick((p) => (p.includes(v) ? p.filter((x) => x !== v) : [...p, v].slice(-2)));
  const down = (v: number) => {
    press.current = { t: window.setTimeout(() => ((press.current.long = true), toggle(v), navigator.vibrate?.(20)), 500) };
  };
  const up = () => window.clearTimeout(press.current.t);
  const tap = (v: number) => {
    if (press.current.long) return void (press.current.long = false);
    if (pick.length) return toggle(v);
    setOpen({ v });
  };
  const [lo, hi] = [...pick].sort((x, y) => x - y);
  return (
    <>
      <div className="mchips">
        <button type="button" className={`mchip${chip === '' ? ' on' : ''}`} onClick={() => setChip('')}>
          전체 {all.length}
        </button>
        {ORIGIN_CHIPS.map(([k]) => (
          <button key={k} type="button" className={`mchip${chip === k ? ' on' : ''}`} onClick={() => setChip(chip === k ? '' : k)}>
            {k}
          </button>
        ))}
      </div>
      <Load q={list} what="버전 기록을 읽지 못했습니다">
        {() =>
          view.length === 0 ? (
            <span className="muted small">{all.length ? '고른 조건에 맞는 버전이 없습니다.' : '기록된 버전이 없습니다.'}</span>
          ) : (
            <>
              {view.map((r) => {
                const cur = src(r.version);
                const prev = prevOf(r.version);
                const pv = prev === undefined ? undefined : src(prev);
                const failed = r.status === 'failed';
                const [label, tone]: [string, 'ok' | 'er' | 'pr' | 'un'] =
                  r.version === a.revision ? ['실행 중', 'ok'] : failed ? ['실패', 'er'] : r.status === 'running' || r.status === 'pending' ? ['진행 중', 'pr'] : ['이전', 'un'];
                const on = pick.includes(r.version);
                return (
                  <button
                    key={r.version}
                    type="button"
                    className={`mc${failed ? ' xer' : ''}`}
                    style={{ textAlign: 'left', font: 'inherit', ...(on ? { outline: '2px solid var(--accent)', outlineOffset: -1 } : {}) }}
                    aria-pressed={pick.length ? on : undefined}
                    onPointerDown={() => down(r.version)}
                    onPointerUp={up}
                    onPointerLeave={up}
                    onContextMenu={(e) => e.preventDefault()}
                    onClick={() => tap(r.version)}
                  >
                    <div className="hd">
                      <b>버전 {r.version}</b>
                      <span className="row" style={{ gap: 4 }}>
                        {cur === null && <Badge tone="un">원문 없음</Badge>}
                        <Badge tone={tone}>{label}</Badge>
                      </span>
                    </div>
                    <div className="ln">{cur === null ? '원문이 이력 정리로 회수됐습니다' : pv === null ? '앞 버전 원문이 없어 바뀐 점을 모릅니다' : cur === undefined || (prev !== undefined && pv === undefined) ? '…' : changeLine(pv, cur)}</div>
                    <div className="ln muted" style={{ fontSize: 12 }}>
                      {dayTime(r.at)} · {whoOf(r)}
                      {originOf(r) === 'user' && r.operation ? ` · ${r.operation}` : ''}
                    </div>
                  </button>
                );
              })}
              {rows.length > shown && (
                <button type="button" className="linkish muted" style={{ fontSize: 12, alignSelf: 'center' }} onClick={() => setShown((n) => n + 10)}>
                  이전 기록 더 보기
                </button>
              )}
              <span className="muted small" style={{ textAlign: 'center' }}>
                카드를 길게 눌러 두 버전을 고르면 비교합니다 · 이력 회수 설정은 넓은 화면에서
              </span>
            </>
          )
        }
      </Load>
      {pick.length > 0 && (
        <div className="m-stick">
          <div className="m-stick-note" style={{ color: 'var(--muted)' }}>
            {pick.length === 1 ? `버전 ${pick[0]}을 골랐습니다. 하나 더 길게 누르세요.` : `버전 ${lo}과 ${hi}를 비교합니다.`}
          </div>
          <div className="mbar" style={{ borderTop: 0 }}>
            <button type="button" className="mbtn fl" onClick={() => setPick([])}>
              고르기 취소
            </button>
            <button type="button" className="mbtn fl pri" disabled={pick.length < 2} onClick={() => setOpen({ v: hi, with: lo })}>
              비교
            </button>
          </div>
        </div>
      )}
      {open && (
        <MVersion
          a={a}
          r={all.find((x) => x.version === open.v)}
          version={open.v}
          against={open.with ?? (open.v === a.revision ? prevOf(open.v) : a.revision)}
          onClose={() => (setOpen(undefined), setPick([]))}
        />
      )}
    </>
  );
}

function MVersion({ a, r, version, against, onClose }: { a: AppView; r?: AppRevision; version: number; against?: number; onClose: () => void }) {
  const src = useSources(a, against === undefined ? [version] : [version, against]);
  const [raw, setRaw] = useState(false);
  const cur = src(version);
  const other = against === undefined ? undefined : src(against);
  const next = usePoll((s) => appRevisions(a.tenant, a.app, s), [a.tenant, a.app], 0, appLive(a.tenant, a.app)).data?.items.find((x) => x.version === version + 1);
  const result = !r ? '—' : r.status === 'failed' ? '실패' : r.status === 'running' || r.status === 'pending' ? '진행 중' : version === a.revision ? '완료 · 실행 중' : next ? `완료 → ${dayTime(next.at).replace(/^(오늘|어제) /, '')}에 버전 ${next.version}${iGa(String(next.version))} 대체` : '완료';
  // 비교는 옛 버전 → 새 버전 방향
  const [from, to] = against === undefined ? [undefined, cur] : against < version ? [other, cur] : [cur, other];
  const lines = typeof from === 'string' && typeof to === 'string' ? lineDiff(from, to) : undefined;
  const add = lines?.filter((l) => l.op === '+').length ?? 0;
  const del = lines?.filter((l) => l.op === '-').length ?? 0;
  const download = () => {
    if (typeof cur !== 'string') return;
    const url = URL.createObjectURL(new Blob([cur], { type: 'text/yaml' }));
    const el = document.createElement('a');
    el.href = url;
    el.download = `${a.app}-v${version}.yaml`;
    el.click();
    URL.revokeObjectURL(url);
  };
  const tone = !r ? 'un' : r.status === 'failed' ? 'er' : version === a.revision ? 'ok' : 'un';
  return (
    <Drawer
      title={
        <>
          버전 {version}
          <span className="sub">{a.app}</span>
        </>
      }
      onClose={onClose}
    >
      <div className={`mc${r?.status === 'failed' ? ' xer' : ''}`}>
        <div className="hd">
          <b>버전 {version}</b>
          <Badge tone={tone}>{version === a.revision ? '실행 중' : r?.status === 'failed' ? '실패' : '이전'}</Badge>
        </div>
        <dl className="mkv">
          <dt>올린 시각</dt>
          <dd>{r ? (/^(오늘|어제)/.test(dayTime(r.at)) ? `${dayTime(r.at)} (${monthDay(r.at)})` : dayTime(r.at)) : '—'}</dd>
          <dt>누가</dt>
          <dd>{r ? whoOf(r) : '—'}</dd>
          <dt>결과</dt>
          <dd>{result}</dd>
          <dt>작업 기록</dt>
          <dd>{r?.operation ? <Link to={`/system/ops?focus=${encodeURIComponent(r.operation)}`} className="mono">{r.operation}</Link> : '—'}</dd>
          <dt>원문 지문</dt>
          <dd className="mono">{r?.digest ? `${r.digest.replace(/^(sha256:)?(.{4}).*(.{4})$/, 'sha256:$2…$3')}` : '—'}</dd>
        </dl>
      </div>
      {cur === null ? (
        <div className="bn info">이 버전의 원문은 이력 정리로 회수돼 비교할 수 없습니다.</div>
      ) : (
        <>
          <div className="m-sec">
            <span>{raw ? '원문' : against === undefined ? '처음 올린 버전' : `버전 ${against}와 비교 · 바뀐 줄만`}</span>
            <button type="button" className="linkish" onClick={() => setRaw(!raw)}>
              {raw ? '바뀐 줄만' : '원문 보기'}
            </button>
          </div>
          {raw || against === undefined ? (
            typeof cur === 'string' ? (
              <div className="mdif">
                {cur.replace(/\n$/, '').split('\n').map((l, i) => (
                  <div key={i}>{l || ' '}</div>
                ))}
              </div>
            ) : (
              <span className="muted small">원문을 읽는 중…</span>
            )
          ) : other === null ? (
            <div className="bn info">버전 {against}의 원문이 회수돼 비교할 수 없습니다.</div>
          ) : !lines ? (
            <span className="muted small">원문을 읽는 중…</span>
          ) : add + del === 0 ? (
            <span className="muted small">두 버전의 원문이 같습니다.</span>
          ) : (
            <div className="mdif">
              {changedOnly(lines).map((l, i) =>
                l === null ? (
                  <div key={i} className="c">
                    {'  · · ·'}
                  </div>
                ) : (
                  <div key={i} className={l.op === '+' ? 'a' : l.op === '-' ? 'r' : 'c'}>
                    {l.op === ' ' ? ' ' : l.op} {l.text}
                  </div>
                ),
              )}
              <div className="c">
                {'  · · · '}추가 {add}줄 · 삭제 {del}줄
              </div>
            </div>
          )}
        </>
      )}
      <div className="li">
        <button type="button" disabled={typeof cur !== 'string'} onClick={download}>
          원문 내려받기<span className="r">⇩</span>
        </button>
        <div style={{ color: 'var(--faint)' }}>
          이 버전으로 되돌리기…<span className="r">넓은 화면에서</span>
        </div>
      </div>
    </Drawer>
  );
}
