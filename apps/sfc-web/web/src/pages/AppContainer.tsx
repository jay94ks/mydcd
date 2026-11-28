// SPDX-License-Identifier: Apache-2.0

// 배포 › 앱 › 서비스 › 컨테이너 상세 (UI-3A, 캔버스 AppContainer · AppContainerIx · AppContainerLogs).
// 읽기는 sfcd가 서버에서 읽어 비밀값을 가린 값이고, 웹은 로그·표본을 저장하지 않는다.
// 실시간 따라가기·프로세스·터미널은 기존 컨테이너 스트림을 쓴다.
import { Fragment, lazy, Suspense, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import { app as fetchApp, appPath, appTasks, containerPath, imageManifest, imageTrust, opsList, registries, clearLogs, storedLogs, type LogsSelection, observeLogs, restartTaskPath, taskDetail, taskHistory, taskLogs, taskStats, type TaskRef } from '../api/endpoints';
import type * as D from '../api/dto';
import type { TaskView } from '../api/types';
import { useSession } from '../auth/session';
import { incidentPath, incidents } from '../api/incidents';
import { useCoordinator } from '../components/Coordinator';
import { Badge, Card, HelpBox, PageHeader, Segmented, type Tone } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { Tabs } from '../components/Tabs';
import { Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { MTopList, TopPane, useFollow } from '../components/ContainerConsole';
import { streamEndText } from '../api/streams';
import { Drawer } from '../components/Drawer';
import { useToast } from '../components/Toast';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { ActionSheet } from '../mobile/Sheet';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { uncertain } from '../lib/opRetry';
import { matchRule } from '../lib/trust';
import { fmtBytes, hhmmss } from '../lib/format';
import type { RegistryView } from '../api/types';
import type { RegistryImage } from '../api/endpoints';
import { appLive, incidentsLive, opsLive, registriesLive } from '../lib/liveTopics';

const LayersDialog = lazy(() => import('./ImageTools').then((m) => ({ default: m.LayersDialog })));

/** 이 작업 공간 Seafield Cluster 저장소의 이미지면 저장소와 이미지 줄을 만든다(레이어 보기·크기용). 바깥 이미지는 undefined */
function ownImage(image: string, digest: string | undefined, regs: RegistryView[] | undefined): { reg: RegistryView; img: RegistryImage; tag: string } | undefined {
  if (!regs || !digest) return undefined;
  const slash = image.indexOf('/');
  if (slash < 0) return undefined;
  const host = image.slice(0, slash);
  const reg = regs.find((r) => r.endpoint === host && !r.deleted);
  if (!reg) return undefined;
  const rest = image.slice(slash + 1).split('@')[0];
  const colon = rest.lastIndexOf(':');
  const repository = colon > rest.lastIndexOf('/') ? rest.slice(0, colon) : rest;
  const tag = colon > rest.lastIndexOf('/') ? rest.slice(colon + 1) : 'latest';
  return { reg, tag, img: { registry: reg.id, repository, digest, tags: [tag], bytes: 0, pushedAt: 0, inUse: 0 } as unknown as RegistryImage };
}

const TerminalPane = lazy(() => import('../components/TerminalPane'));

// ── 작은 도우미 ──

const MiB = 1 << 20;
const fromUnix = (s?: number) => (s ? new Date(s * 1000) : undefined);
const isToday = (d: Date) => d.toDateString() === new Date().toDateString();
const isYesterday = (d: Date) => d.toDateString() === new Date(Date.now() - 86400_000).toDateString();
const p2 = (n: number) => String(n).padStart(2, '0');
const hm = (d: Date) => `${p2(d.getHours())}:${p2(d.getMinutes())}`;
const clock = (s: number) => {
  const d = new Date(s * 1000);
  return `${hm(d)}:${p2(d.getSeconds())}`;
};
/** 오늘 10:41 · 어제 10:41 · 11월 19일 10:41 */
function day(s?: number): string {
  const d = fromUnix(s);
  if (!d) return '—';
  if (isToday(d)) return `오늘 ${hm(d)}`;
  if (isYesterday(d)) return `어제 ${hm(d)}`;
  return `${d.getMonth() + 1}월 ${d.getDate()}일 ${hm(d)}`;
}
/** 이벤트 줄 왼쪽: 오늘이면 13:40, 어제면 '어제', 그 전이면 11/19 */
function short(s: number): string {
  const d = new Date(s * 1000);
  return isToday(d) ? hm(d) : isYesterday(d) ? '어제' : `${d.getMonth() + 1}/${d.getDate()}`;
}
function span(sec: number): string {
  const m = Math.max(0, Math.floor(sec / 60));
  if (m < 60) return `${m}분째`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}시간 ${m % 60}분째`;
  return `${Math.floor(h / 24)}일째`;
}
function agoSec(s?: number): string {
  if (!s) return '—';
  const d = Math.max(0, Math.round(Date.now() / 1000 - s));
  return d < 60 ? `${d}초 전` : d < 3600 ? `${Math.floor(d / 60)}분 전` : d < 86400 ? `${Math.floor(d / 3600)}시간 전` : `${Math.floor(d / 86400)}일 전`;
}
const mib = (n?: number) => (n === undefined ? '—' : `${Math.round(n / MiB)}`);
const rate = (n?: number) => (n === undefined ? '—' : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB/s` : `${(n / 1e3).toFixed(1)} KB/s`);
const shortDigest = (d: string) => d.replace(/^(sha256:.{4}).*(.{2})$/, '$1…$2');
const shortId = (s: string) => (s.length > 10 ? `${s.slice(0, 6)}…${s.slice(-3)}` : s);
const nativeOf = (x: { nativeID?: string; nativeId?: string }) => x.nativeID ?? x.nativeId ?? '';
/** secret:<object>/<key> → object */
const secretObject = (ref?: string) => (ref ?? '').replace(/^secret:/, '').split('/')[0];

const EXIT: Record<string, string> = { exit: '종료', oom: '메모리 부족', health: '상태 검사 실패', 'node-restart': '서버 재시작', user: '사용자가 다시 시작' };
const exitText = (e: D.DTaskExit) => (e.reason === 'user' || e.reason === 'node-restart' ? EXIT[e.reason] : `종료 코드 ${e.exitCode} · ${EXIT[e.reason] ?? e.reason}`);

/** drift 경로(services.web.image 등)가 이 칸에 걸리는지. keys는 서비스 아래 첫 칸 이름 */
function drifted(d: D.DTaskDetail, keys: string[]): string[] {
  return (d.drift ?? []).filter((p) => {
    const rest = p.split('.').slice(2).join('.');
    return keys.some((k) => rest === k || rest.startsWith(`${k}.`));
  });
}
const DRIFT_KEYS = {
  image: ['image'],
  command: ['command', 'entrypoint', 'working_dir'],
  user: ['user'],
  security: ['read_only', 'cap_add', 'cap_drop', 'privileged', 'security_opt'],
  limits: ['deploy.resources', 'cpus', 'mem_limit'],
  env: ['environment', 'env_file'],
  stop: ['stop_signal', 'stop_grace_period'],
  networks: ['networks'],
  ports: ['ports', 'x-sfc.ingress'],
  storage: ['volumes', 'secrets', 'tmpfs'],
  logging: ['logging'],
};
function Cell({ d, keys, children, mono }: { d: D.DTaskDetail; keys: string[]; children: ReactNode; mono?: boolean }) {
  const hit = drifted(d, keys);
  return (
    <span className={`${mono ? 'mono ' : ''}${hit.length ? 'drift' : ''}`} title={hit.length ? `목표와 다름: ${hit.join(', ')}` : undefined}>
      {children}
    </span>
  );
}

function Spark({ values, max }: { values: (number | undefined)[]; max?: number }) {
  const top = max || Math.max(1, ...values.map((v) => v ?? 0));
  return (
    <div className="spark" aria-hidden>
      {values.map((v, i) => (v === undefined ? <i key={i} className="none" style={{ height: '100%' }} /> : <i key={i} style={{ height: `${Math.max(2, Math.min(100, (v / top) * 100))}%` }} />))}
    </div>
  );
}

type Row = D.DTaskLogLine;
function LogLine({ l, time = true, stream = false }: { l: Row; time?: boolean; stream?: boolean }) {
  const err = l.stream === 'stderr';
  const cls = /error|exception|fatal/i.test(l.text) ? 'e' : err || /warn/i.test(l.text) ? 'w' : undefined;
  if (!stream)
    return (
      <div>
        {time && <span className="t">{clock(l.time)}</span>} {cls ? <span className={cls}>{l.text}</span> : l.text}
      </div>
    );
  return (
    <div className={time ? 'lgrow' : 'lgrow nt'}>
      {time && <span className="t">{clock(l.time)}</span>}
      <span style={{ color: err ? '#FF9AA2' : 'var(--faint)' }}>{l.stream}</span>
      <span>{cls ? <span className={cls}>{l.text}</span> : l.text}</span>
    </div>
  );
}

// ── 페이지 ──

/** 서버 포트 공개 실제 바인딩 → '127.0.0.1:18080 → 8080/tcp' */
const publishedText = (d: { ports?: D.DTaskPort[] }) =>
  (d.ports ?? []).flatMap((p) => (p.published ?? []).map((b) => `${b.hostIp ? `${b.hostIp.includes(':') ? `[${b.hostIp}]` : b.hostIp}:` : ''}${b.hostPort} → ${p.port}/${p.protocol}`));

export function AppContainerPage() {
  const { tenant = '', app = '', service = '', instance = '' } = useParams();
  const session = useSession();
  const navigate = useNavigate();
  const loc = useLocation();
  const toast = useToast();
  const canDeploy = session.user.systemAdmin || session.tenants.some((x) => x.id === tenant && x.role === 'manager');
  const ref: TaskRef = useMemo(() => ({ tenant, app, service, instance }), [tenant, app, service, instance]);
  const detail = usePoll((s) => taskDetail(ref, s), [ref], DEFAULT_POLL_MS);
  const hist = usePoll((s) => taskHistory(ref, 50, s), [ref], DEFAULT_POLL_MS);
  const tasks = usePoll((s) => appTasks(tenant, app, s), [tenant, app], DEFAULT_POLL_MS, appLive(tenant, app));
  const a = usePoll((s) => fetchApp(tenant, app, s), [tenant, app], 0, appLive(tenant, app));
  const [restarting, setRestarting] = useState(false);
  const [raw, setRaw] = useState(false);
  const [layers, setLayers] = useState(false);
  const regs = usePoll((s) => registries(tenant, s), [tenant], 0, registriesLive(tenant));
  // 장애 대응 사건 열기: 이 앱의 아직 끝나지 않은 최근 사건. 사건은 앱 단위라 컨테이너 대신 앱으로 찾는다
  const incs = usePoll((s) => incidents({ tenant, app, limit: 20 }, s), [tenant, app], 0, incidentsLive);
  const liveInc = incs.data?.items.find((x) => x.state === 'open' || x.state === 'mitigating');
  const coord = useCoordinator();
  const askCoord = () => void coord.openNew().catch(() => toast('코디네이터 대화를 열지 못했습니다.', 'er'));
  const incReason = liveInc ? undefined : incs.error ? '장애 대응 사건을 읽지 못했습니다' : incs.data ? '이 앱에 진행 중인 사건이 없습니다' : '읽는 중…';
  const task = tasks.data?.items.find((t) => t.service === service && t.instance === instance);
  const siblings = (tasks.data?.items ?? []).filter((t) => t.service === service);
  const base = containerPath(tenant, app, service, instance);
  const d = detail.data;
  const checks = hist.data?.checks.reduce((n, c) => n + c.results.length, 0) ?? 0;
  const events = hist.data ? eventsOf(hist.data).length : 0;
  const name = `${service}-${instance}`;
  const node = d?.node ?? task?.node ?? '';
  const status = statusOf(task);
  const phone = usePhone();
  const tab = loc.pathname.slice(base.length).replace(/^\//, '');
  // 휴대폰: ⋯ 동작 시트 (UI-M1 ②) · 데스크톱 ⋯ 메뉴와 같은 항목·순서
  useMobileTop(
    phone
      ? {
          title: tab === 'logs' ? `${name} · 로그` : tab === 'res' ? `${name} · 자원 사용` : `${name} @ ${node || '—'}`,
          sub: tab === 'logs' || tab === 'res' ? `${app} · ${node || '—'}` : `${app} · 서비스 ${service}`,
          menu: [
            { label: '로그 보기', onSelect: () => navigate(`${base}/logs`) },
            { label: '자원 사용 · 프로세스', onSelect: () => navigate(`${base}/res`) },
            { label: '상태 검사 · 이벤트', onSelect: () => navigate(`${base}/checks`) },
            { label: '터미널', wide: true, onSelect: () => navigate(`${base}/exec`) },
            { label: '실제 설정 복사', onSelect: () => copyInspect() },
            ...(liveInc ? [{ label: `장애 대응 사건 열기 · ${liveInc.id}`, onSelect: () => navigate(incidentPath(liveInc.id)) }] : []),
            { label: '코디네이터에게 묻기', onSelect: askCoord },
            { label: '다시 시작…', danger: true, onSelect: () => (canDeploy && task ? setRestarting(true) : toast('이 작업 공간의 배포 권한이 필요합니다', 'er')) },
          ],
        }
      : undefined,
    [phone, tab, name, node, app, service, canDeploy, !!task, !!d, liveInc?.id],
  );
  const copyInspect = () => {
    if (!d) return;
    void navigator.clipboard?.writeText(JSON.stringify(d, null, 2)).then(
      () => toast('✓ 실제 설정을 복사했습니다.'),
      () => toast('복사하지 못했습니다. 브라우저가 클립보드를 막았습니다.', 'er'),
    );
  };
  const copyId = () => {
    const id = d ? nativeOf(d) : '';
    if (!id) return;
    void navigator.clipboard?.writeText(id).then(
      () => toast(<>✓ {shortId(id)}를 복사했습니다.</>),
      () => toast('복사하지 못했습니다. 브라우저가 클립보드를 막았습니다.', 'er'),
    );
  };
  return (
    <>
      <PageHeader
        crumbs={
          <>
            <Link to="/deploy">배포</Link> / <Link to={appPath(tenant, app)}>{app}</Link> / 서비스 {service} / 컨테이너
          </>
        }
        title={
          <span className="row" style={{ gap: 10 }}>
            <span className="mono" style={{ fontSize: 24 }}>
              {name} @ {node || '—'}
            </span>
          </span>
        }
        ids={/\/(logs|res)$/.test(loc.pathname) ? 'UI-3C' : /\/exec$/.test(loc.pathname) ? 'UI-3D' : 'UI-3A'}
        after={
          phone ? undefined : <>
            {status && <Badge tone={status[0]}>{status[1]}</Badge>}
            <span className="muted small">관측 {agoSec(d?.observedAt ?? (task ? Date.parse(task.observedAt) / 1000 : undefined))}</span>
          </>
        }
        actions={
          phone ? undefined : <span className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <select aria-label="컨테이너 바꾸기" title="같은 서비스의 다른 복제본으로 바꿉니다" value={instance} style={{ width: 'auto', height: 34 }} onChange={(e) => navigate(containerPath(tenant, app, service, e.target.value) + loc.pathname.slice(base.length))}>
              {(siblings.length ? siblings : [{ instance, node }]).map((t) => (
                <option key={t.instance} value={t.instance}>
                  {service}-{t.instance} @ {t.node}
                </option>
              ))}
            </select>
            <button className="btn" disabled={!canDeploy || !task} title={!canDeploy ? '이 작업 공간의 배포 권한이 필요합니다' : undefined} onClick={() => setRestarting(true)}>
              다시 시작…
            </button>
            <Menu
              label="컨테이너 메뉴"
              button="⋯"
              className="btn"
              items={[
                { label: 'Docker ID 복사', onSelect: copyId, disabledReason: d && nativeOf(d) ? undefined : '아직 읽지 못했습니다' },
                { label: '원 JSON 보기', onSelect: () => setRaw(true), disabledReason: d ? undefined : '아직 읽지 못했습니다' },
                { label: `서버 ${node} 열기`, onSelect: () => navigate(`/servers/${encodeURIComponent(node)}`), disabledReason: node ? undefined : '서버를 모릅니다' },
                {
                  label: '이미지 레이어 보기',
                  onSelect: () => setLayers(true),
                  disabledReason: !d ? '아직 읽지 못했습니다' : ownImage(d.image, d.digest, regs.data?.items) ? undefined : regs.error ? '저장소 목록을 읽지 못했습니다' : '이 작업 공간 Seafield Cluster 저장소의 이미지만 볼 수 있습니다',
                },
                { label: liveInc ? `장애 대응 사건 열기 · ${liveInc.id}` : '장애 대응 사건 열기', onSelect: () => liveInc && navigate(incidentPath(liveInc.id)), disabledReason: incReason },
                { label: '코디네이터에게 묻기 · 이 컨테이너 문맥', onSelect: askCoord },
              ]}
            />
          </span>
        }
      />
      <Tabs
        label="컨테이너 탭"
        items={
          phone
            ? [
                { to: base, label: '개요', end: true },
                { to: `${base}/logs`, label: '로그' },
                { to: `${base}/res`, label: '자원 사용' },
                { to: `${base}/checks`, label: '상태 검사' },
                { to: `${base}/events`, label: '이벤트' },
              ]
            : [
                { to: base, label: '개요', end: true },
                { to: `${base}/logs`, label: '로그' },
                { to: `${base}/res`, label: '자원 사용 · 프로세스' },
                { to: `${base}/exec`, label: '터미널' },
                { to: `${base}/checks`, label: `상태 검사${hist.data ? ` (${checks})` : ''}` },
                { to: `${base}/events`, label: `이벤트${hist.data ? ` (${events})` : ''}` },
                { to: `${base}/inspect`, label: '실제 설정' },
              ]
        }
      />
      <Load q={detail} what="컨테이너를 읽지 못했습니다">
        {(d) => (
          <Routes>
            <Route index element={phone ? <MOverview r={ref} d={d} task={task} hist={hist.data} revision={a.data?.revision} /> : <Overview r={ref} d={d} task={task} hist={hist.data} revision={a.data?.revision} base={base} onRefresh={() => (detail.refresh(), hist.refresh())} />} />
            <Route path="logs" element={<LogsTab r={ref} d={d} task={task} canDeploy={canDeploy} />} />
            <Route path="res" element={phone ? <MRes r={ref} d={d} task={task} /> : <ResTab r={ref} d={d} task={task} base={base} />} />
            <Route
              path="exec"
              element={
                !task ? (
                  <p className="muted">컨테이너 목록을 읽는 중입니다.</p>
                ) : canDeploy ? (
                  <Card>
                    <Suspense fallback={<p className="muted">터미널을 불러오는 중…</p>}>
                      <TerminalPane task={task} />
                    </Suspense>
                  </Card>
                ) : (
                  <div className="note wa">터미널을 열 수 없습니다 · 작업 공간 {tenant}의 배포 권한이 필요합니다. 로그·자원 사용은 읽기 권한으로 볼 수 있습니다.</div>
                )
              }
            />
            <Route path="checks" element={<ChecksTab q={hist} />} />
            <Route path="events" element={<EventsTab q={hist} />} />
            <Route path="inspect" element={<InspectTab d={d} />} />
          </Routes>
        )}
      </Load>
      {restarting && task && <RestartDialog r={ref} task={task} siblings={siblings} d={d} expected={a.data?.revision} onClose={() => (setRestarting(false), detail.refresh(), hist.refresh(), tasks.refresh())} />}
      {layers && d && (() => {
        const own = ownImage(d.image, d.digest, regs.data?.items);
        return own ? (
          <Suspense fallback={null}>
            <LayersDialog tenant={tenant} reg={own.reg} img={own.img} tag={own.tag} onClose={() => setLayers(false)} />
          </Suspense>
        ) : null;
      })()}
      {raw && d && (
        <Dialog title={`${name} 원 JSON`} width={720} onClose={() => setRaw(false)}>
          <pre className="preview-yaml">{JSON.stringify(d, null, 2)}</pre>
          <span className="small muted">서버가 보고한 그대로입니다. 비밀값은 참조만 있고 값은 없습니다.</span>
        </Dialog>
      )}
    </>
  );
}

function statusOf(t?: TaskView): [Tone, string] | undefined {
  if (!t) return undefined;
  if (t.stale) return ['un', '확인 불가 (보고 늦음)'];
  const run = { running: '실행 중', starting: '시작 중', restarting: '재시작 중', exited: '종료됨', unknown: '확인 불가' }[t.observed];
  const hc = t.health === 'pass' ? ' · 상태 검사 통과' : t.health === 'fail' ? ' · 상태 검사 실패' : t.health === 'starting' ? ' · 상태 검사 기다림' : '';
  const tone: Tone = t.observed === 'running' ? (t.health === 'fail' ? 'wa' : 'ok') : t.observed === 'exited' ? 'er' : t.observed === 'unknown' ? 'un' : 'pr';
  return [tone, run + hc];
}

interface Ev {
  at: number;
  tone: string;
  text: string;
}
/** 종료 이력과 상태 검사 결과가 바뀐 때를 최신 순으로 */
function eventsOf(h: D.DTaskHistory): Ev[] {
  const out: Ev[] = h.exits.map((e) => ({ at: e.at, tone: e.reason === 'user' ? 'var(--accent)' : 'var(--wa-strong)', text: `${exitText(e)} → 다시 시작 (세대 ${e.generation})` }));
  for (const c of h.checks) {
    const rs = [...c.results].reverse();
    rs.forEach((r, i) => {
      if (i > 0 && rs[i - 1].ok === r.ok) return;
      out.push({ at: r.at, tone: r.ok ? 'var(--ok-strong)' : 'var(--danger)', text: `상태 검사 ${r.ok ? '통과' : '실패'} (${c.checker}${r.message ? ` · ${r.message}` : ''})` });
    });
  }
  return out.sort((x, y) => y.at - x.at);
}

const OP_STATE: Record<string, string> = { applied: '적용', failed: '실패', rejected: '거절', running: '진행 중', pending: '대기', unknown: '결과 모름' };
function opEvents(ops: import('../api/types').OpView[], r: TaskRef): Ev[] {
  return ops
    .filter((o) => o.tenant === r.tenant && (o.target === r.app || o.target.startsWith(`${r.app}/`) || o.target.endsWith(`/${r.app}`)) && /deploy|secret|vault/.test(o.action))
    .map((o) => ({
      at: Date.parse(o.submittedAt),
      tone: o.state === 'applied' ? 'var(--accent)' : o.state === 'failed' || o.state === 'rejected' ? 'var(--danger)' : 'var(--faint)',
      text: `${/deploy/.test(o.action) ? '배포' : '비밀값 교체'} ${OP_STATE[o.state] ?? o.state} · 작업 ${o.id.slice(0, 8)}`,
    }));
}

// ── 개요 ──

function Overview({ r, d, task, hist, revision, base, onRefresh }: { r: TaskRef; d: D.DTaskDetail; task?: TaskView; hist?: D.DTaskHistory; revision?: number; base: string; onRefresh: () => void }) {
  const toast = useToast();
  const stats = usePoll((s) => taskStats(r, s), [r], DEFAULT_POLL_MS);
  const trust = usePoll((s) => imageTrust(r.tenant, s), [r.tenant]);
  const ops = usePoll((s) => opsList(undefined, s), [], DEFAULT_POLL_MS, opsLive);
  // 크기: Seafield Cluster 저장소 이미지면 매니페스트의 레이어 합(압축 크기)
  const size = usePoll(
    async (s) => {
      const own = ownImage(d.image, d.digest, (await registries(r.tenant, s)).items);
      if (!own) return { external: true as const };
      const m = await imageManifest(r.tenant, own.reg.id, own.img.repository, d.digest, undefined, s);
      const layers = m.layers ?? [];
      return { bytes: layers.reduce((a, l) => a + l.bytes, 0), layers: layers.length };
    },
    [r.tenant, d.image, d.digest],
  );
  const [stream, setStream] = useState<'all' | 'stdout' | 'stderr'>('all');
  const [envOpen, setEnvOpen] = useState(false);
  const logs = usePoll((s) => taskLogs(r, undefined, 60, s), [r], DEFAULT_POLL_MS);
  const lastExit = hist?.exits[0];
  const started = task?.startedAt ? Date.parse(task.startedAt) / 1000 : undefined;
  const items = stats.data ?? [];
  const last = items[items.length - 1];
  const prev = items[items.length - 2];
  const dt = last && prev ? last.at - prev.at : 0;
  const per = (k: 'netRxBytes' | 'netTxBytes' | 'blockWrite') => (dt > 0 && last[k] >= prev[k] ? (last[k] - prev[k]) / dt : undefined);
  const memRatio = last && last.memLimit ? last.memUsed / last.memLimit : 0;
  const oomToday = hist?.exits.filter((e) => e.reason === 'oom' && isToday(new Date(e.at * 1000))).length ?? 0;
  const rule = trust.data?.rules.find((x) => matchRule(x, d.image));
  const tmpfs = d.mounts.filter((m) => m.kind === 'tmpfs');
  const secretEnv = (obj: string) => d.env.filter((e) => e.secret && secretObject(e.secret) === obj).map((e) => e.key);
  const fileEnv = (target: string) => d.env.filter((e) => e.value === target).map((e) => e.key);
    // sfcd가 모든 컨테이너에 읽기 전용 루트 · cap_drop ALL · no-new-privileges를 강제한다(다르면 배포 거부)
  const security = ['읽기 전용 루트 · cap_drop ALL · no-new-privileges', d.capAdd?.length ? `cap_add ${d.capAdd.join(', ')}` : ''].filter(Boolean).join(' · ');
  const ingress = (d.ports ?? []).filter((p) => p.ingress);
  const published = publishedText(d);
  const recent = (logs.data?.lines ?? []).filter((l) => stream === 'all' || l.stream === stream).slice(-6);
  // 배포·비밀값 교체: 작업 기록에서 이 앱 대상인 것을 모은다(내가 볼 수 있는 작업만)
  const evs = [...(hist ? eventsOf(hist) : []), ...opEvents(ops.data ?? [], r)].sort((x, y) => y.at - x.at);
  const logOpts = d.logOptions ?? {};
  return (
    <>
      <HelpBox terms="컨테이너 (Task) · 컨테이너 세대 (generation) · 실제 설정 (inspect) · 재시작 (restart) · 종료 코드 (exit code)">
        <b>이 화면은</b> 앱을 이루는 컨테이너 하나를 자세히 봅니다. 앱에서 정한 값(목표)과 서버가 보고한 실제 상태를 함께 보여 주고, 다르면 노란색으로 표시합니다. 비밀값 원문은 보이지 않습니다.
      </HelpBox>
      <div className="grid-3">
        <Card title="상태">
          <div className="kv2 c120">
            <span>목표 / 실제</span>
            <span>
              {task ? (task.desired === 'running' ? '실행' : '정지') : '—'} / <b style={{ color: task?.observed === 'running' ? 'var(--ok)' : task?.observed === 'exited' ? 'var(--er)' : undefined }}>{statusOf(task)?.[1].split(' · ')[0] ?? '—'}</b>
            </span>
            <span>시작</span>
            <span>{started ? `${day(started)} (${span(Date.now() / 1000 - started)})` : '—'}</span>
            <span>재시작</span>
            <span>
              {task?.restarts ?? hist?.exits.length ?? 0}회
              {lastExit && (
                <>
                  {' '}
                  · 마지막 {day(lastExit.at)} <span className="muted">({exitText(lastExit)})</span>
                </>
              )}
            </span>
            <span>컨테이너 세대</span>
            <span>
              {d.generation}
              {revision ? ` · 앱 버전 ${revision}` : ''}
            </span>
            <span>Docker 이름</span>
            <span className="mono">{d.name}</span>
            <span>Docker ID</span>
            <span className="mono">
              {shortId(nativeOf(d)) || '—'}{' '}
              {nativeOf(d) && (
                <a href="#" className="small" style={{ fontFamily: 'var(--font)' }} onClick={(e) => (e.preventDefault(), void navigator.clipboard?.writeText(nativeOf(d)).then(() => toast(<>✓ {shortId(nativeOf(d))}를 복사했습니다.</>)))}>
                  복사
                </a>
              )}
            </span>
          </div>
        </Card>
        <Card title="이미지">
          <div className="kv2 c120">
            <span>이미지</span>
            <Cell d={d} keys={DRIFT_KEYS.image} mono>
              <span style={{ wordBreak: 'break-all' }}>{d.image}</span>
            </Cell>
            <span>다이제스트</span>
            <span className="mono" title={d.digest}>
              {shortDigest(d.digest)}
            </span>
            <span>크기</span>
            <span className={size.data && 'bytes' in size.data ? '' : 'muted'}>
              {size.data ? ('bytes' in size.data ? `${fmtBytes(size.data.bytes)} · 레이어 ${size.data.layers}개 (압축)` : '바깥 저장소 이미지라 모름') : size.error ? '읽지 못함' : '읽는 중…'}
            </span>
            <span>신뢰 출처</span>
            {trust.data ? rule ? <span style={{ color: 'var(--ok)' }}>✓ {rule.registry}/{rule.repository}</span> : <span style={{ color: 'var(--wa)' }}>! 맞는 규칙 없음</span> : <span className="muted">—</span>}
          </div>
        </Card>
        <Card
          title={
            <h2>
              자원 사용{' '}
              <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}>
                최근 1시간 · 30초 간격
              </span>
            </h2>
          }
          actions={
            <button className="btn sm" title="지금 바로 다시 읽기" disabled={stats.manual} onClick={stats.refreshByUser}>
              {stats.manual ? '읽는 중…' : '↻ 새로고침'}
            </button>
          }
        >
          {stats.error || (stats.data && !stats.data.length) ? (
            <span className="small muted">보관 표본 · 서버 기능 대기. 지금 값은 '자원 사용 · 프로세스' 탭에서 봅니다.</span>
          ) : (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 14 }}>
                <div>
                  <div className="row between small">
                    <b>CPU</b>
                    <Cell d={d} keys={DRIFT_KEYS.limits}>
                      {last ? (last.cpuPercent / 100).toFixed(2) : '—'} / {d.cpus ?? '한도 없음'}
                    </Cell>
                  </div>
                  <Spark values={items.slice(-24).map((x) => x.cpuPercent)} max={d.cpus ? d.cpus * 100 : undefined} />
                </div>
                <div>
                  <div className="row between small">
                    <b>메모리</b>
                    <span style={memRatio >= 0.7 ? { color: 'var(--wa)' } : undefined}>
                      {mib(last?.memUsed)} / {last?.memLimit ? `${mib(last.memLimit)} MiB` : '한도 없음'}
                    </span>
                  </div>
                  <Spark values={items.slice(-24).map((x) => x.memUsed)} max={last?.memLimit || undefined} />
                </div>
              </div>
              <div className="kv2 c120">
                <span>망 입출력</span>
                <span>
                  ↓ {rate(per('netRxBytes'))} · ↑ {rate(per('netTxBytes'))}
                </span>
                <span>디스크 쓰기</span>
                <span>{rate(per('blockWrite'))} (tmpfs 제외)</span>
                <span>프로세스</span>
                <span>{last ? `${last.pids}개` : '—'}</span>
              </div>
              {memRatio >= 0.7 && (
                <span className="small" style={{ color: 'var(--wa)' }}>
                  ! 메모리가 한도의 {Math.round(memRatio * 100)}%{oomToday ? `이고 오늘 메모리 부족(137)으로 ${oomToday}번 재시작했습니다` : '입니다'}. 한도를 늘리려면 <Link to={`${appPath(r.tenant, r.app)}/edit`}>편집 탭</Link>에서 바꿉니다.
                </span>
              )}
            </>
          )}
        </Card>
        <Card
          title={
            <h2>
              실행 설정{' '}
              <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}>
                {d.drift?.length ? <span style={{ color: 'var(--wa)' }}>목표와 다른 칸 {d.drift.length}개</span> : '목표 = 실제'}
              </span>
            </h2>
          }
        >
          <div className="kv2 c120">
            <span>명령</span>
            <Cell d={d} keys={DRIFT_KEYS.command} mono>
              {[...(d.entrypoint ?? []), ...(d.command ?? [])].join(' ') || '이미지 기본값'}
            </Cell>
            <span>사용자</span>
            <Cell d={d} keys={DRIFT_KEYS.user} mono>
              {d.user || '이미지 기본값'}
            </Cell>
            <span>보안</span>
            <Cell d={d} keys={DRIFT_KEYS.security}>
              {security}
            </Cell>
            <span>한도</span>
            <Cell d={d} keys={DRIFT_KEYS.limits}>
              CPU {d.cpus ?? '없음'} · 메모리 {d.memoryBytes ? `${Math.round(d.memoryBytes / MiB)}m` : '없음'}
            </Cell>
            <span>환경 변수</span>
            <Cell d={d} keys={DRIFT_KEYS.env}>
              {d.env.length}개{' '}
              <span className="mono">
                {d.env
                  .slice(0, 3)
                  .map((e) => `${e.key}=${e.secret ? '«가림»' : e.value ?? ''}`)
                  .join(' · ')}
                {d.env.length > 3 ? ' …' : ''}
              </span>{' '}
              {d.env.length > 0 && (
                <a href="#" className="small" onClick={(e) => (e.preventDefault(), setEnvOpen(true))}>
                  모두
                </a>
              )}
            </Cell>
            <span>종료</span>
            <Cell d={d} keys={DRIFT_KEYS.stop}>
              {d.stopSignal || 'SIGTERM'} · 유예 {d.stopGrace}초
            </Cell>
          </div>
        </Card>
        <Card title="망">
          <div className="kv2 c120">
            {d.networks.length === 0 && (
              <>
                <span>망</span>
                <span className="muted">없음</span>
              </>
            )}
            {d.networks.map((n, i) => (
              <NetRows key={n.name} d={d} n={n} first={i === 0} />
            ))}
            <span>외부 접속</span>
            <Cell d={d} keys={DRIFT_KEYS.ports}>
              {ingress.length ? ingress.map((p) => `${p.ingress} → :${p.port}`).join(', ') : <span className="muted">없음</span>}
            </Cell>
            <span>포트</span>
            <Cell d={d} keys={DRIFT_KEYS.ports} mono>
              {d.ports?.length ? d.ports.map((p) => `${p.port}/${p.protocol}`).join(', ') : <span className="muted">없음</span>}
            </Cell>
            {published.length > 0 && (
              <>
                <span>서버에 공개</span>
                <Cell d={d} keys={DRIFT_KEYS.ports} mono>
                  {published.join(', ')}{' '}
                  <span className="small muted" style={{ fontFamily: 'var(--font)' }}>
                    {d.node} · 실제 설정에서 확인
                  </span>
                </Cell>
              </>
            )}
          </div>
        </Card>
        <Card title="저장소 · 비밀값">
          <div className="table-wrap">
            <table className="tbl" style={{ fontSize: 12 }}>
              <thead>
                <tr>
                  <th>무엇</th>
                  <th>컨테이너 안 위치</th>
                  <th>방식</th>
                </tr>
              </thead>
              <tbody>
                {d.mounts
                  .filter((m) => m.kind !== 'tmpfs')
                  .map((m) => {
                    const obj = secretObject(m.source);
                    const envs = m.kind === 'secret' ? [...fileEnv(m.target)] : [];
                    const both = m.kind === 'secret' && (envs.length > 0 || secretEnv(obj).length > 0);
                    return (
                      <tr key={m.target}>
                        <td className="wrap">{m.kind === 'volume' ? `데이터 저장소 ${m.source}` : m.kind === 'secret' ? `비밀값 ${obj}` : `${m.kind} ${m.source ?? ''}`}</td>
                        <td className="wrap mono">
                          {m.target}
                          {m.mode ? ` · ${m.mode}` : ''}
                          {envs.length ? ` + ${envs.join(', ')}` : ''}
                        </td>
                        <td>{m.kind === 'secret' ? (both ? '파일+변수' : '파일') : m.readOnly ? '읽기 전용' : '읽기·쓰기'}</td>
                      </tr>
                    );
                  })}
                {d.env
                  .filter((e) => e.secret && !d.mounts.some((m) => m.kind === 'secret' && secretObject(m.source) === secretObject(e.secret)))
                  .map((e) => (
                    <tr key={e.key}>
                      <td className="wrap">비밀값 {secretObject(e.secret)}</td>
                      <td className="wrap mono">{e.key}</td>
                      <td>변수</td>
                    </tr>
                  ))}
                {tmpfs.length > 0 && (
                  <tr>
                    <td>임시 (tmpfs)</td>
                    <td className="wrap mono">{tmpfs.map((m) => m.target).join(' · ')}</td>
                    <td>메모리</td>
                  </tr>
                )}
                {d.mounts.length === 0 && !d.env.some((e) => e.secret) && (
                  <tr>
                    <td colSpan={3} className="muted">
                      없음
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <span className="muted small">비밀값은 공급 방식과 위치만 보이고 값은 보이지 않습니다.</span>
        </Card>
      </div>
      <div className="main-side" style={{ marginTop: 20 }}>
        <Card
         
          title="최근 로그"
          actions={
            <span className="row" style={{ gap: 6 }}>
              <Segmented
                label="로그 종류"
                value={stream}
                onChange={setStream}
                options={[
                  ['all', '전체'],
                  ['stdout', 'stdout'],
                  ['stderr', 'stderr'],
                ]}
              />
              <Link className="btn sm" to={`${base}/logs`}>
                ● 따라가기
              </Link>
              <Link to={`${base}/logs`} className="small">
                로그 탭에서 보기
              </Link>
            </span>
          }
        >
          {logs.error ? (
            <ErrorBand error={logs.error} what="로그를 읽지 못했습니다" />
          ) : (
            <pre className="lg">
              {recent.map((l) => (
                <LogLine key={l.seq} l={l} />
              ))}
              {logs.data && recent.length === 0 && <span className="t">줄이 없습니다.</span>}
              {!logs.data && <span className="t">읽는 중…</span>}
            </pre>
          )}
          <span className="muted small">
            마지막 줄들 · 비밀값으로 표시된 값이 로그에 나오면 «가림»으로 바꿔 보여 줍니다{logs.data?.masked ? ` (이 중 ${logs.data.masked}줄)` : ''}. 로그는 서버에서 읽어 오며 웹 데이터에 저장하지 않습니다. 로그 방식 {d.logDriver}
            {logOpts['max-size'] ? ` · 최대 ${logOpts['max-size']} × ${logOpts['max-file'] ?? 1}개` : ''}.
          </span>
        </Card>
        <Card title="최근 이벤트">
          <div className="tl">
            {evs.slice(0, 5).map((e, i) => (
              <div key={i}>
                <span className="muted">{short(e.at)}</span>
                <i style={{ background: e.tone }} />
                <span>{e.text}</span>
              </div>
            ))}
            {hist && evs.length === 0 && <span className="muted small">기록된 이벤트가 없습니다.</span>}
          </div>
          <span className="muted small">배포·비밀값 교체는 작업 기록에서 이 앱 것을 함께 보여 줍니다.</span>
          <Link to={`${base}/events`} className="small">
            이벤트 {evs.length}개 모두
          </Link>
        </Card>
      </div>
      <span className="small muted" style={{ display: 'block', marginTop: 8 }}>
        <a href="#" onClick={(e) => (e.preventDefault(), onRefresh(), stats.refresh(), logs.refresh())}>
          모두 다시 읽기
        </a>
      </span>
      {envOpen && (
        <Dialog title={`환경 변수 ${d.env.length}개`} width={560} onClose={() => setEnvOpen(false)}>
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>키</th>
                  <th>값</th>
                </tr>
              </thead>
              <tbody>
                {d.env.map((e) => (
                  <tr key={e.key}>
                    <td className="mono">{e.key}</td>
                    <td className="wrap mono">{e.secret ? <span title={`보관함 ${e.secret.replace(/^secret:/, '')}`}>«가림»</span> : e.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <span className="small muted">보관함에서 오는 값은 보이지 않고 참조만 있습니다.</span>
        </Dialog>
      )}
    </>
  );
}

// ── 휴대폰 (UI-M10 ① ②) ──

/** 휴대폰 컨테이너 개요: 상태 카드 + 자원 두 칸 + 접힌 목록. 최근 로그 카드는 로그 탭으로 */
function MOverview({ r, d, task, hist, revision }: { r: TaskRef; d: D.DTaskDetail; task?: TaskView; hist?: D.DTaskHistory; revision?: number }) {
  const toast = useToast();
  const stats = usePoll((s) => taskStats(r, s), [r], DEFAULT_POLL_MS);
  const [view, setView] = useState<'run' | 'net' | 'store'>();
  const items = stats.data ?? [];
  const last = items[items.length - 1];
  const memRatio = last && last.memLimit ? last.memUsed / last.memLimit : 0;
  const oomToday = hist?.exits.filter((e) => e.reason === 'oom' && isToday(new Date(e.at * 1000))).length ?? 0;
  const lastExit = hist?.exits[0];
  const started = task?.startedAt ? Date.parse(task.startedAt) / 1000 : undefined;
  const status = statusOf(task);
  const want = task ? (task.desired === 'running' ? '실행' : '정지') : '—';
  const off = !!task && (task.desired === 'running') !== (task.observed === 'running' && !task.stale);
  const failing = hist?.checks.some((c) => c.consecutiveFailures > 0);
  const checked = hist && hist.checks.length > 0;
  const secretObjs = new Set([...d.mounts.filter((m) => m.kind === 'secret').map((m) => secretObject(m.source)), ...d.env.filter((e) => e.secret).map((e) => secretObject(e.secret))]);
  const stores = d.mounts.filter((m) => m.kind !== 'tmpfs' && m.kind !== 'secret').length + secretObjs.size;
  const copy = (text: string, what: string) =>
    void navigator.clipboard?.writeText(text).then(
      () => toast(`✓ ${what}를 복사했습니다.`),
      () => toast('복사하지 못했습니다. 브라우저가 클립보드를 막았습니다.', 'er'),
    );
  const hold = (text: string, what: string) => {
    let t = 0;
    return {
      onPointerDown: () => (t = window.setTimeout(() => copy(text, what), 500)),
      onPointerUp: () => window.clearTimeout(t),
      onPointerLeave: () => window.clearTimeout(t),
      onContextMenu: (e: { preventDefault: () => void }) => e.preventDefault(),
    };
  };
  const primary = d.networks[0];
  return (
    <>
      <div className={`mc${failing ? ' xer' : ''}`}>
        <div className="hd">
          <b>{status?.[1].split(' · ')[0] ?? '—'}</b>
          {checked ? <Badge tone={failing ? 'er' : 'ok'}>{failing ? '상태 검사 실패' : '상태 검사 통과'}</Badge> : <Badge tone="un">검사 없음</Badge>}
        </div>
        <dl className="mkv">
          <dt className={off ? 'wa-row' : undefined}>목표 / 실제</dt>
          <dd className={off ? 'wa-row' : undefined}>
            {want} / {status?.[1].split(' · ')[0] ?? '—'}
          </dd>
          <dt>시작</dt>
          <dd>{started ? `${day(started)} (${span(Date.now() / 1000 - started)})` : '—'}</dd>
          <dt>재시작</dt>
          <dd>
            {task?.restarts ?? hist?.exits.length ?? 0}회{lastExit ? ` · 마지막 ${day(lastExit.at).replace(/^오늘 /, '')} (${lastExit.reason === 'oom' ? '137 · 메모리 부족' : exitText(lastExit)})` : ''}
          </dd>
          <dt>세대</dt>
          <dd>
            {d.generation}
            {revision ? ` · 앱 버전 ${revision}` : ''}
          </dd>
          <dt className={drifted(d, DRIFT_KEYS.image).length ? 'wa-row' : undefined}>이미지</dt>
          <dd className={`el mono${drifted(d, DRIFT_KEYS.image).length ? ' wa-row' : ''}`} {...hold(d.image, '이미지 이름')}>
            {d.image.split('@')[0]}
          </dd>
        </dl>
      </div>
      <div className="mtiles">
        <div className="mtile">
          <small>CPU</small>
          <b>{last ? (last.cpuPercent / 100).toFixed(2) : '—'}</b>
          <span>/ {d.cpus ?? '한도 없음'}</span>
        </div>
        <div className="mtile">
          <small>메모리</small>
          <b style={memRatio >= 0.7 ? { color: 'var(--wa)' } : undefined}>{mib(last?.memUsed)}</b>
          <span>/ {last?.memLimit ? `${mib(last.memLimit)} MiB` : '한도 없음'}</span>
        </div>
      </div>
      {(memRatio >= 0.7 || oomToday > 0) && (
        <div className="bn warn">
          {memRatio >= 0.7 ? `메모리가 한도의 ${Math.round(memRatio * 100)}%` : '메모리는 한도 안이지만'}
          {oomToday ? `${memRatio >= 0.7 ? '이고' : ''} 오늘 메모리 부족(137)으로 ${oomToday}번 재시작했습니다` : '입니다'}. 한도를 늘리려면 편집 탭에서 바꿉니다.
        </div>
      )}
      {stats.error || (stats.data && !stats.data.length) ? <span className="muted small">자원 표본 · 서버 기능 대기</span> : null}
      <div className="li">
        <button type="button" onClick={() => setView('run')}>
          실행 설정<span className="r" style={d.drift?.length ? { color: 'var(--wa)' } : undefined}>{d.drift?.length ? `목표와 다름 ${d.drift.length} ›` : '목표 = 실제 ›'}</span>
        </button>
        <button type="button" onClick={() => setView('net')}>
          망<span className="r">{primary ? `${primary.name} · ${primary.ip || '—'}${d.networks.length > 1 ? ` 외 ${d.networks.length - 1}` : ''} ›` : '없음 ›'}</span>
        </button>
        <button type="button" onClick={() => setView('store')}>
          저장소 · 비밀값<span className="r">{stores} ›</span>
        </button>
      </div>
      {view === 'run' && (
        <Drawer title="실행 설정" onClose={() => setView(undefined)}>
          <div className="mc">
            <dl className="mkv">
              {(
                [
                  ['명령', DRIFT_KEYS.command, [...(d.entrypoint ?? []), ...(d.command ?? [])].join(' ') || '이미지 기본값', true],
                  ['사용자', DRIFT_KEYS.user, d.user || '이미지 기본값', true],
                  ['보안', DRIFT_KEYS.security, ['읽기 전용 루트 · cap_drop ALL · no-new-privileges', d.capAdd?.length ? `cap_add ${d.capAdd.join(', ')}` : ''].filter(Boolean).join(' · '), false],
                  ['한도', DRIFT_KEYS.limits, `CPU ${d.cpus ?? '없음'} · 메모리 ${d.memoryBytes ? `${Math.round(d.memoryBytes / MiB)}m` : '없음'}`, false],
                  ['환경 변수', DRIFT_KEYS.env, `${d.env.length}개`, false],
                  ['종료', DRIFT_KEYS.stop, `${d.stopSignal || 'SIGTERM'} · 유예 ${d.stopGrace}초`, false],
                ] as [string, string[], string, boolean][]
              ).map(([k, keys, v, mono]) => {
                const hit = drifted(d, keys).length > 0;
                return (
                  <Fragment key={k}>
                    <dt className={hit ? 'wa-row' : undefined}>{k}</dt>
                    <dd className={`${mono ? 'mono ' : ''}${hit ? 'wa-row' : ''}`}>{v}</dd>
                  </Fragment>
                );
              })}
              <dt>Docker 이름</dt>
              <dd className="mono" {...hold(d.name, 'Docker 이름')}>
                {d.name}
              </dd>
              <dt>Docker ID</dt>
              <dd className="mono" {...hold(nativeOf(d), 'Docker ID')}>
                {shortId(nativeOf(d)) || '—'}
              </dd>
            </dl>
          </div>
          {d.env.length > 0 && (
            <>
              <div className="m-sec">
                <span>환경 변수 {d.env.length}</span>
              </div>
              <div className="li">
                {d.env.map((e) => (
                  <div key={e.key} className="mono" style={{ fontSize: 12 }}>
                    <span className="el">
                      {e.key}={e.secret ? '«가림»' : e.value ?? ''}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
          <span className="muted small">이름·ID는 길게 눌러 복사 · 보관함 값은 보이지 않습니다</span>
        </Drawer>
      )}
      {view === 'net' && (
        <Drawer title="망" onClose={() => setView(undefined)}>
          {d.networks.map((n) => (
            <div key={n.name} className="mc">
              <div className="hd">
                <b>{n.name}</b>
                <span className="mono muted" style={{ fontSize: 12 }}>
                  {n.ip || '—'}
                </span>
              </div>
              {n.aliases?.length ? <div className="ln mono">별칭 {n.aliases.join(', ')}</div> : null}
              {n.dns?.length ? <div className="ln mono">DNS {n.dns.join(', ')}</div> : null}
            </div>
          ))}
          {d.networks.length === 0 && <span className="muted small">연결된 망이 없습니다.</span>}
          <dl className="mkv">
            <dt>외부 접속</dt>
            <dd>{(d.ports ?? []).filter((p) => p.ingress).map((p) => `${p.ingress} → :${p.port}`).join(', ') || '없음'}</dd>
            <dt>포트</dt>
            <dd className="mono">{d.ports?.length ? d.ports.map((p) => `${p.port}/${p.protocol}`).join(', ') : '없음'}</dd>
            {publishedText(d).length > 0 && (
              <>
                <dt>서버에 공개</dt>
                <dd className="mono">{publishedText(d).join(', ')}</dd>
              </>
            )}
          </dl>
        </Drawer>
      )}
      {view === 'store' && (
        <Drawer title="저장소 · 비밀값" onClose={() => setView(undefined)}>
          <div className="li">
            {d.mounts
              .filter((m) => m.kind !== 'tmpfs')
              .map((m) => (
                <div key={m.target} style={{ flexDirection: 'column', alignItems: 'stretch', gap: 2 }}>
                  <span>{m.kind === 'volume' ? `데이터 저장소 ${m.source}` : m.kind === 'secret' ? `비밀값 ${secretObject(m.source)}` : `${m.kind} ${m.source ?? ''}`}</span>
                  <span className="mono muted" style={{ fontSize: 12 }}>
                    {m.target} · {m.kind === 'secret' ? '파일' : m.readOnly ? '읽기 전용' : '읽기·쓰기'}
                  </span>
                </div>
              ))}
            {d.env
              .filter((e) => e.secret && !d.mounts.some((m) => m.kind === 'secret' && secretObject(m.source) === secretObject(e.secret)))
              .map((e) => (
                <div key={e.key} style={{ flexDirection: 'column', alignItems: 'stretch', gap: 2 }}>
                  <span>비밀값 {secretObject(e.secret)}</span>
                  <span className="mono muted" style={{ fontSize: 12 }}>
                    {e.key} · 변수
                  </span>
                </div>
              ))}
          </div>
          {stores === 0 && <span className="muted small">없음</span>}
          <span className="muted small">비밀값은 위치와 방식만 보이고 값은 보이지 않습니다.</span>
        </Drawer>
      )}
    </>
  );
}

/** svg 꺾은선 (휴대폰 자원 사용) */
function MSpark({ values, max, color }: { values: (number | undefined)[]; max?: number; color: string }) {
  const v = values.map((x) => x ?? 0);
  if (v.length < 2) return <span className="muted small">표본이 아직 없습니다.</span>;
  const top = max || Math.max(1, ...v);
  const pts = v.map((x, i) => `${Math.round((i / (v.length - 1)) * 340)},${Math.round(54 - Math.min(1, x / top) * 50)}`).join(' ');
  return (
    <svg className="mspark" viewBox="0 0 340 56" preserveAspectRatio="none" aria-hidden>
      <polyline points={pts} fill="none" stroke={color} strokeWidth={2} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** 휴대폰 자원 사용 · 프로세스 (UI-M10 ②) */
function MRes({ r, d, task }: { r: TaskRef; d: D.DTaskDetail; task?: TaskView }) {
  const stats = usePoll((s) => taskStats(r, s), [r], DEFAULT_POLL_MS);
  const [paused, setPaused] = useState(false);
  const items = stats.data ?? [];
  const last = items[items.length - 1];
  useEffect(() => {
    stats.setInterval(paused ? 0 : DEFAULT_POLL_MS);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paused]);
  return (
    <>
      <div className="mchips">
        <span className="mchip">최근 1시간 · 30초</span>
        <button type="button" className="mchip" aria-label="지금 바로 다시 읽기" disabled={stats.manual} onClick={stats.refreshByUser}>
          ↻
        </button>
        <button type="button" className={`mchip${paused ? ' on' : ''}`} aria-label={paused ? '다시 읽기' : '멈춤'} onClick={() => setPaused((p) => !p)}>
          {paused ? '▶' : '⏸'}
        </button>
        <span className="muted" style={{ fontSize: 12, alignSelf: 'center', marginLeft: 'auto', flex: 'none' }}>
          {stats.asOf ? `${hhmmss(stats.asOf)} 기준` : ''}
        </span>
      </div>
      {stats.error || (stats.data && !stats.data.length) ? <div className="bn info">보관 표본(최근 1시간) · 서버 기능 대기</div> : null}
      <div className="mc">
        <div className="hd">
          <b>CPU {last ? `${Math.round(last.cpuPercent)}%` : '—'}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            코어 1개 기준 · 한도 {d.cpus ?? '없음'}
          </span>
        </div>
        <MSpark values={items.slice(-40).map((x) => x.cpuPercent)} max={d.cpus ? d.cpus * 100 : undefined} color="var(--accent)" />
      </div>
      <div className="mc">
        <div className="hd">
          <b>메모리 {last ? `${mib(last.memUsed)} MiB` : '—'}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            한도 {last?.memLimit ? mib(last.memLimit) : '없음'}
          </span>
        </div>
        <MSpark values={items.slice(-40).map((x) => x.memUsed)} max={last?.memLimit || undefined} color="var(--wa)" />
      </div>
      <div className="mtiles">
        <div className="mtile">
          <small>망 누계</small>
          <span>
            ↓ {fmtBytes(last?.netRxBytes)} · ↑ {fmtBytes(last?.netTxBytes)}
          </span>
        </div>
        <div className="mtile">
          <small>디스크 누계</small>
          <span>
            읽기 {fmtBytes(last?.blockRead)} · 쓰기 {fmtBytes(last?.blockWrite)}
          </span>
        </div>
      </div>
      {task ? <MTopList task={task} pids={last?.pids} /> : <span className="muted small">컨테이너 목록을 읽는 중입니다.</span>}
    </>
  );
}

function NetRows({ d, n, first }: { d: D.DTaskDetail; n: D.DTaskNetwork; first: boolean }) {
  return (
    <>
      <span>{first ? '망' : ''}</span>
      <Cell d={d} keys={DRIFT_KEYS.networks}>
        {n.name} · {n.ip || '—'}
      </Cell>
      {n.aliases?.length ? (
        <>
          <span>별칭</span>
          <span className="mono">{n.aliases.join(', ')}</span>
        </>
      ) : null}
      {n.dns?.length ? (
        <>
          <span>DNS</span>
          <span className="mono">{n.dns.join(', ')}</span>
        </>
      ) : null}
    </>
  );
}

// ── 다시 시작 ──

function RestartDialog({ r, task, siblings, d, expected, onClose }: { r: TaskRef; task: TaskView; siblings: TaskView[]; d?: D.DTaskDetail; expected?: number; onClose: () => void }) {
  const m = useMutation();
  const [wait, setWait] = useState(true);
  // 열 때 본 앱 버전으로 고정한다. 열려 있는 동안 앱 정보가 새로 읽혀도 바뀌지 않는다.
  const [pinned] = useState(expected);
  const others = siblings.filter((t) => t.instance !== task.instance);
  const name = `${task.service}-${task.instance}`;
  const send = () => (uncertain(m) ? void m.again() : void m.run(restartTaskPath(r.tenant, r.app), { service: r.service, instance: r.instance, ...(pinned ? { expected: pinned } : {}) }));
  const after = useRestartWatch(r, m.op?.state === 'applied' && wait);
  return (
    <Dialog
      title={`${name} 다시 시작`}
      width={560}
      onClose={onClose}
      footer={
        m.op && !uncertain(m) ? (
          <button className="btn" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={m.busy} onClick={send}>
              {uncertain(m) ? '같은 작업 ID로 다시 보내기' : '다시 시작'}
            </button>
          </>
        )
      }
    >
      <p>
        이 컨테이너만 다시 시작합니다.{' '}
        {others.length ? (
          <>
            같은 서비스의 {others.map((t) => `${t.service}-${t.instance}`).join(', ')}는 계속 응답합니다.
          </>
        ) : (
          <>이 서비스의 컨테이너가 하나뿐이라 다시 시작하는 동안 응답하지 않습니다.</>
        )}
      </p>
      <div className="kv2 c120">
        <span>방식</span>
        <span>
          정상 종료 ({d?.stopSignal || 'SIGTERM'}, 유예 {d?.stopGrace ?? 10}초)
        </span>
      </div>
      <label className="row small" style={{ gap: 6 }}>
        <input type="checkbox" checked={wait} disabled={!!m.op} onChange={(e) => setWait(e.target.checked)} /> 다시 시작 뒤 상태 검사 통과까지 기다리기
      </label>
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
      {after && <div className={`note ${after.tone} small`}>{after.text}</div>}
    </Dialog>
  );
}

/** 작업이 적용된 뒤 컨테이너 목록을 몇 초마다 다시 읽어 상태 검사 통과를 기다린다 */
function useRestartWatch(r: TaskRef, on: boolean): { tone: string; text: string } | undefined {
  const [state, setState] = useState<{ tone: string; text: string }>();
  const since = useRef(0);
  useEffect(() => {
    if (!on) return;
    since.current = Date.now();
    let stop = false;
    const tick = async () => {
      while (!stop) {
        try {
          const ts = await appTasks(r.tenant, r.app);
          const t = ts.items.find((x) => x.service === r.service && x.instance === r.instance);
          if (t && !t.stale && t.observed === 'running' && (t.health === 'pass' || t.health === 'none')) {
            setState({ tone: 'ok', text: t.health === 'pass' ? '✓ 다시 시작했고 상태 검사를 통과했습니다.' : '✓ 다시 시작했습니다. 이 서비스에는 상태 검사가 없습니다.' });
            return;
          }
          setState({ tone: 'un', text: `상태 검사 통과를 기다리는 중… (${t ? statusOf(t)?.[1] : '컨테이너를 찾는 중'})` });
        } catch {
          setState({ tone: 'wa', text: '상태를 읽지 못했습니다. 잠시 뒤 다시 읽습니다.' });
        }
        if (Date.now() - since.current > 120_000) {
          setState({ tone: 'wa', text: '2분이 지나도 상태 검사를 통과하지 않았습니다. 상태 검사 탭을 확인하세요.' });
          return;
        }
        await new Promise((res) => setTimeout(res, 3000));
      }
    };
    void tick();
    return () => {
      stop = true;
    };
  }, [on, r]);
  return state;
}

// ── 로그 (UI-3C) ──

const MAX_LINES = 5000;
type Range = 'tail200' | 'tail1000' | '15m' | '1h' | 'custom';
const RANGE: [Range, string][] = [
  ['tail200', '마지막 200줄'],
  ['tail1000', '마지막 1000줄'],
  ['15m', '최근 15분'],
  ['1h', '최근 1시간'],
  ['custom', '기간 직접…'],
];
/** datetime-local 값 ↔ Unix 초 */
const toLocal = (s: number) => {
  const d = new Date(s * 1000);
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}T${hm(d)}`;
};
const fromLocal = (v: string) => (v ? Math.floor(new Date(v).getTime() / 1000) : undefined);

function LogsTab({ r, d, task, canDeploy }: { r: TaskRef; d: D.DTaskDetail; task?: TaskView; canDeploy: boolean }) {
  const [stream, setStream] = useState<'all' | 'stdout' | 'stderr'>('all');
  const [range, setRange] = useState<Range>('tail200');
  const [from, setFrom] = useState(() => toLocal(Math.floor(Date.now() / 1000) - 3600));
  const [to, setTo] = useState('');
  const [find, setFind] = useState('');
  const [time, setTime] = useState(true);
  const [followOn, setFollowOn] = useState(true);
  /** 따라가기 스트림이 거부·끊김으로 멈춘 이유(코드). 다시 따라가면 지운다 */
  const [followErr, setFollowErr] = useState<string>();
  const [followTry, setFollowTry] = useState(0);
  const [lines, setLines] = useState<Row[]>([]);
  const [truncated, setTruncated] = useState(false);
  /** REQ-20(task/logs)로 읽었을 때만 안다 */
  const [masked, setMasked] = useState<number>();
  const [req20, setReq20] = useState<'unknown' | 'ok' | 'waiting'>('unknown');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();
  const [unseen, setUnseen] = useState(0);
  const [gen, setGen] = useState(0);
  const [clearing, setClearing] = useState(false);
  const box = useRef<HTMLPreElement>(null);
  const atEnd = useRef(true);
  const toast = useToast();
  const phone = usePhone();
  const [atTop, setAtTop] = useState(false);
  const [rangeSheet, setRangeSheet] = useState(false);

  const until = range === 'custom' ? fromLocal(to) : undefined;
  const since = range === '15m' ? Math.floor(Date.now() / 1000) - 900 : range === '1h' ? Math.floor(Date.now() / 1000) - 3600 : range === 'custom' ? fromLocal(from) : undefined;
  // 기간 끝을 정하면 따라가지 않는다
  const following = followOn && !until;

  // 단발 읽기: sfcd container-observe(tail 또는 since). 한 번에 24 KiB까지이고 넘으면 앞부분이 잘린다.
  useEffect(() => {
    let dead = false;
    setLoading(true);
    setError(undefined);
    setLines([]);
    setUnseen(0);
    setMasked(undefined);
    const tail = range === 'tail1000' ? 1000 : range === 'tail200' ? 200 : 10000;
    observeLogs(r, { tail, ...(since ? { since } : {}), ...(until ? { until } : {}) }).then(
      (x) => {
        if (dead) return;
        const ls = x.logs ?? [];
        setLines(ls.map((l, i) => ({ seq: i + 1, ...l })));
        setTruncated(!!x.truncated);
        setLoading(false);
      },
      (e) => {
        if (dead) return;
        setError(e);
        setLoading(false);
      },
    );
    return () => {
      dead = true;
    };
    // since는 범위를 고를 때 정해진다
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [r, range, range === 'custom' ? from : '', range === 'custom' ? to : '', gen]);

  /** 더 앞 줄 읽기 (REQ-20 이어 읽기). 가린 줄 수도 이때 안다. 지원하지 않으면 '서버 기능 대기' */
  const older = async () => {
    try {
      const p = await taskLogs(r, undefined, Math.min(5000, lines.length + 200));
      setLines(p.lines.filter((l) => !until || l.time <= until));
      setMasked(p.masked);
      setTruncated(!!p.cursor);
      setReq20('ok');
    } catch {
      setReq20('waiting');
    }
  };

  const shown = lines.filter((l) => (stream === 'all' || l.stream === stream) && (!find || l.text.toLowerCase().includes(find.toLowerCase())));
  useEffect(() => {
    if (atEnd.current && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [shown.length]);

  const download = () => {
    const text = shown.map((l) => `${new Date(l.time * 1000).toISOString()} ${l.stream} ${l.text}`).join('\n') + '\n';
    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    const now = new Date();
    const name = `${r.service}-${r.instance}-${now.getFullYear()}-${p2(now.getMonth() + 1)}-${p2(now.getDate())}T${p2(now.getHours())}${p2(now.getMinutes())}.log`;
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast(
      <>
        ✓ {name} ({fmtBytes(blob.size)}, {shown.length}줄)을 내려받았습니다. 화면에 받은 만큼만 담깁니다.
      </>,
    );
  };

  const opts = d.logOptions ?? {};
  if (phone) {
    const STREAM_NEXT = { all: 'stdout', stdout: 'stderr', stderr: 'all' } as const;
    return (
      <>
        <div className="mchips">
          <button type="button" className="mchip on" onClick={() => setStream(STREAM_NEXT[stream])}>
            {stream === 'all' ? 'stdout + stderr' : stream}
          </button>
          <button type="button" className="mchip" onClick={() => setRangeSheet(true)}>
            {RANGE.find(([v]) => v === range)?.[1] ?? '범위'} ▾
          </button>
          <button type="button" className="mchip" aria-label="내려받기" onClick={download} disabled={!shown.length}>
            ⇩
          </button>
        </div>
        <div className="muted small">
          {truncated ? '앞부분 잘림 · 24 KiB까지 · ' : ''}비밀값 가림 {masked ?? lines.filter((l) => l.text.includes('«가림')).length}줄
        </div>
        {error ? <ErrorBand error={error} what="로그를 읽지 못했습니다" /> : null}
        <pre
          ref={box}
          className="lg box m-log"
          onScroll={(e) => {
            const el = e.currentTarget;
            atEnd.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
            setAtTop(el.scrollTop < 8);
            if (atEnd.current) setUnseen(0);
            setFollowOn(atEnd.current);
          }}
        >
          {!loading && atTop && (truncated || req20 !== 'ok') && (
            <div style={{ fontFamily: 'var(--font)', marginBottom: 6 }}>
              {req20 === 'waiting' ? (
                <span className="t">더 앞 줄 이어 읽기 · 서버 기능 대기</span>
              ) : (
                <button className="btn sm" onClick={() => void older()} disabled={lines.length >= 5000}>
                  더 앞 200줄 읽기
                </button>
              )}
            </div>
          )}
          {shown.map((l) => (
            <LogLine key={l.seq} l={l} time={time} />
          ))}
          {loading && <span className="t">읽는 중…</span>}
          {!loading && shown.length === 0 && <span className="t">이 범위에 로그가 없습니다.</span>}
          {following && task && !loading && <Follower key={followTry} task={task} d={d} onFail={setFollowErr} onRetry={() => (setFollowErr(undefined), setFollowTry((n) => n + 1))} onLine={(l) => (setLines((old) => old.concat(l).slice(-MAX_LINES)), atEnd.current ? undefined : setUnseen((n) => n + 1))} onReload={() => setGen((g) => g + 1)} />}
        </pre>
        <button
          type="button"
          className="m-fab"
          onClick={() => {
            if (box.current) box.current.scrollTop = box.current.scrollHeight;
            atEnd.current = true;
            setUnseen(0);
            setFollowOn(true);
          }}
        >
          {following ? (followErr ? '⚠ 따라가기 멈춤' : '● 따라가는 중') : `↓ 맨 아래로${unseen ? ` · 새 줄 ${unseen}` : ''}`}
        </button>
        <span className="muted small" style={{ textAlign: 'center' }}>
          ‘로그 지우기…’는 넓은 화면에서
        </span>
        {rangeSheet && <ActionSheet title="읽을 범위" onClose={() => setRangeSheet(false)} items={RANGE.filter(([v]) => v !== 'custom').map(([v, l]) => ({ label: l, onSelect: () => setRange(v) }))} />}
      </>
    );
  }
  return (
    <>
      <HelpBox terms="따라가기 (follow) · 표본 (stats) · 로그 지우기 (서버별 로그 보관소 삭제) · 로그 방식 (log driver)">
        <b>이 화면은</b> 컨테이너 하나의 로그와 자원 사용·프로세스를 봅니다. 서버가 Docker에서 바로 읽어 보내 주며 웹은 로그를 저장하지 않습니다. ‘로그 지우기…’는 컨테이너를 다시 만들지 않고 각 서버에 쌓인 로그 보관소만 지웁니다. 지운 로그는 되살릴 수 없습니다.
      </HelpBox>
      <Card>
        <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
          <Segmented
            label="로그 종류"
            value={stream}
            onChange={setStream}
            options={[
              ['all', 'stdout + stderr'],
              ['stdout', 'stdout'],
              ['stderr', 'stderr'],
            ]}
          />
          <select aria-label="읽을 범위" value={range} style={{ width: 'auto', height: 34 }} onChange={(e) => setRange(e.target.value as Range)}>
            {RANGE.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
          {range === 'custom' && (
            <span className="row small" style={{ gap: 6 }}>
              <input type="datetime-local" aria-label="기간 시작" value={from} max={to || undefined} onChange={(e) => setFrom(e.target.value)} style={{ width: 'auto', height: 34 }} />
              ~
              <input type="datetime-local" aria-label="기간 끝" value={to} min={from || undefined} onChange={(e) => setTo(e.target.value)} style={{ width: 'auto', height: 34 }} />
            </span>
          )}
          <input type="search" placeholder="이 화면 안에서 찾기" value={find} onChange={(e) => setFind(e.target.value)} style={{ flex: '1 1 200px', height: 34 }} />
          <label className="row small" style={{ gap: 6 }}>
            <input type="checkbox" checked={time} onChange={(e) => setTime(e.target.checked)} style={{ width: 16, height: 16 }} />
            시각
          </label>
          <button className={`btn${following ? ' primary' : ''}`} onClick={() => setFollowOn((f) => !f)} aria-pressed={following} disabled={!!until} title={until ? '기간 끝을 정하면 따라가기는 꺼집니다' : undefined}>
            {following ? (followErr ? '⚠ 따라가기 멈춤' : '● 따라가는 중') : '○ 따라가기'}
          </button>
          <button className="btn" onClick={download} disabled={!shown.length}>
            내려받기
          </button>
          <button className="btn danger" onClick={() => setClearing(true)} disabled={!canDeploy} title={!canDeploy ? '이 작업 공간의 배포 권한이 필요합니다' : undefined}>
            로그 지우기…
          </button>
        </div>
        <div className="row small" style={{ flexWrap: 'wrap', gap: 8 }}>
          <span className="pill">
            로그 방식 {d.logDriver}
            {opts['max-size'] ? ` · 최대 ${opts['max-size']} × ${opts['max-file'] ?? 1}개` : ''}
            {opts.compress === 'true' ? ' · 압축' : ''}
          </span>
          <span className="pill" style={{ background: 'var(--bg)', color: 'var(--text-2)' }}>
            TTY 아님 (stdout·stderr 따로)
          </span>
          {truncated && (
            <span className="pill" style={{ background: 'var(--wa-soft)', color: 'var(--wa)' }} title="한 번에 받는 로그는 24 KiB까지입니다. 넘으면 앞부분이 잘립니다. 더 앞을 보려면 기간을 좁히거나 줄 수를 줄이세요.">
              앞부분 잘림 · 한 번에 24 KiB까지
            </span>
          )}
          <span className="pill" style={{ background: 'var(--bg)', color: 'var(--text-2)' }}>
            비밀값 가림 {masked ?? lines.filter((l) => l.text.includes('«가림')).length}줄
          </span>
        </div>
        {error ? <ErrorBand error={error} what="로그를 읽지 못했습니다" /> : null}
        {following && followErr && (
          <div className="note er small" role="alert">
            새 줄 따라가기를 열지 못했습니다 · {streamEndText(followErr)}{' '}
            <button className="btn sm" onClick={() => (setFollowErr(undefined), setFollowTry((n) => n + 1))}>
              다시 따라가기
            </button>
          </div>
        )}
        <pre
          ref={box}
          className="lg box"
          onScroll={(e) => {
            const el = e.currentTarget;
            atEnd.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
            if (atEnd.current) setUnseen(0);
          }}
        >
          {!loading && (truncated || req20 !== 'ok') && (
            <div style={{ fontFamily: 'var(--font)', marginBottom: 6 }}>
              {req20 === 'waiting' ? (
                <span className="t">더 앞 줄 이어 읽기 · 서버 기능 대기</span>
              ) : (
                <button className="btn sm" onClick={() => void older()} disabled={lines.length >= 5000}>
                  더 앞 200줄 읽기
                </button>
              )}
            </div>
          )}
          {shown.map((l) => (
            <LogLine key={l.seq} l={l} time={time} stream />
          ))}
          {loading && <span className="t">읽는 중…</span>}
          {!loading && shown.length === 0 && <span className="t">{find ? '찾는 줄이 없습니다.' : '이 범위에 로그가 없습니다.'}</span>}
          {following && task && !loading && <Follower key={followTry} task={task} d={d} onFail={setFollowErr} onRetry={() => (setFollowErr(undefined), setFollowTry((n) => n + 1))} onLine={(l) => (setLines((old) => old.concat(l).slice(-MAX_LINES)), atEnd.current ? undefined : setUnseen((n) => n + 1))} onReload={() => setGen((g) => g + 1)} />}
        </pre>
        {unseen > 0 && (
          <button className="btn sm" style={{ alignSelf: 'center' }} onClick={() => box.current && (box.current.scrollTop = box.current.scrollHeight)}>
            새 줄 {unseen}개 ↓
          </button>
        )}
        <span className="muted small">
          비밀값으로 표시한 값이 로그에 찍히면 서버가 «가림»으로 바꿔 보낼 예정입니다(아직 지원하지 않음). 지금은 이 화면 사용자에게만 보이고 AI로는 보내지 않습니다.
          {truncated ? ' 앞부분은 24 KiB 상한으로 잘렸습니다. 더 앞을 보려면 기간을 좁히세요.' : ''} 로그는 웹 데이터에 저장하지 않습니다.
        </span>
      </Card>
      {clearing && <LogClearDialog r={r} nativeID={d.nativeID ?? d.nativeId} onClose={() => setClearing(false)} onDone={() => setGen((g) => g + 1)} />}
    </>
  );
}

/** 로그 지우기 (#761, 캔버스 v267 AppContainerIx). 서버마다 자기 로그 보관소를 지우고 컨테이너는 다시 만들지 않는다.
 *  opId·op가 없는 바로 요청이라 다시 보내도 같은 요청이다. 못 지운 서버가 있으면 같은 요청을 다시 보낸다(지운 서버는 지울 것이 없다). */
type ClearScope = 'task' | 'service' | 'app';
const CLEAR_CODE: Record<string, [string, Tone]> = {
  ok: ['지움', 'ok'],
  denied: ['권한 없음', 'er'],
  unreachable: ['연결 안 됨', 'wa'],
  unavailable: ['엔진 없음', 'wa'],
};
export function LogClearDialog({ r, nativeID, onClose, onDone }: { r: TaskRef; nativeID?: string; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [scope, setScope] = useState<ClearScope>('task');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>();
  const [res, setRes] = useState<D.DLogsClear>();
  const name = r.standalone ?? `${r.service}-${r.instance}`;
  // 이 컨테이너의 작업 키는 서비스 목록에서 지금 컨테이너(nativeID)로 찾는다
  const svc = usePoll((s) => (r.standalone ? Promise.resolve(undefined) : storedLogs(r.tenant, { app: r.app, service: r.service }, s)), [r.tenant, r.app, r.service, r.standalone]);
  const key = svc.data?.nodes.flatMap((n) => n.logs).find((l) => l.container === nativeID)?.key;
  const selection = (x: ClearScope): LogsSelection | undefined =>
    r.standalone ? { standalone: r.standalone } : x === 'app' ? { app: r.app } : x === 'service' ? { app: r.app, service: r.service } : key ? { app: r.app, key } : undefined;
  const sel = selection(r.standalone ? 'app' : scope);
  const list = usePoll((s) => (sel ? storedLogs(r.tenant, sel, s) : Promise.resolve(undefined)), [JSON.stringify(sel ?? null)]);
  const rows = (list.data?.nodes ?? []).flatMap((n) => n.logs.map((l) => ({ ...l, node: n.node })));
  const down = (list.data?.nodes ?? []).filter((n) => n.code !== 'ok');
  const lines = rows.reduce((a, l) => a + l.lines, 0);
  const size = rows.reduce((a, l) => a + l.size, 0);
  const scopeText = r.standalone ? r.standalone : scope === 'app' ? `앱 전체 (${r.app})` : scope === 'service' ? `서비스 전체 (${r.service})` : `이 컨테이너만 (${name})`;
  const send = async () => {
    if (!sel) return;
    setBusy(true);
    setErr(undefined);
    try {
      const out = await clearLogs(r.tenant, sel);
      setRes(out);
      const removed = out.nodes.reduce((a, n) => a + (n.code === 'ok' ? n.removed : 0), 0);
      toast(`✓ ${r.standalone ?? r.app} 로그를 지웠습니다 · ${removed.toLocaleString()}줄 (${out.total}대 중 ${out.cleared}대)`, out.cleared < out.total ? 'er' : 'info');
      onDone();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  const missed = res ? res.nodes.filter((n) => n.code !== 'ok') : [];
  const shortName = (l: (typeof rows)[number]) => (l.service && r.app && l.name.endsWith(`-${l.service}-${l.name.split('-').pop()}`) ? `${l.service}-${l.name.split('-').pop()}` : l.name);
  return (
    <Dialog
      title={res ? '로그 지우기 결과' : `${r.standalone ? `${r.standalone} ` : ''}로그 지우기`}
      width={560}
      danger={!res}
      onClose={onClose}
      footer={
        res ? (
          <>
            {missed.length > 0 && (
              <button className="btn" disabled={busy} onClick={() => void send()}>
                {busy ? '보내는 중…' : '다시 보내기'}
              </button>
            )}
            <button className="btn primary" onClick={onClose}>
              닫기
            </button>
          </>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn danger solid" disabled={busy || !sel} onClick={() => void send()}>
              {busy ? '지우는 중…' : '로그 지우기'}
            </button>
          </>
        )
      }
    >
      {res ? (
        <>
          <b>
            {scopeText} · {res.total}대 중 {res.cleared}대 지움
          </b>
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>서버</th>
                  <th>결과</th>
                  <th>컨테이너</th>
                  <th>지운 줄</th>
                </tr>
              </thead>
              <tbody>
                {res.nodes.map((n) => (
                  <tr key={n.node}>
                    <td>{n.node}</td>
                    <td>
                      <Badge tone={(CLEAR_CODE[n.code] ?? [n.code, 'un'])[1]}>{(CLEAR_CODE[n.code] ?? [n.code])[0]}</Badge>
                    </td>
                    <td>{n.code === 'ok' ? n.containers : '—'}</td>
                    <td>{n.code === 'ok' ? n.removed.toLocaleString() : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {missed.length > 0 && <div className="note wa small">{missed.map((n) => n.node).join(', ')}는 지우지 못했습니다. 나머지는 다시 시도하세요.</div>}
          <span className="muted small">결과 종류: 지움 · 권한 없음 · 연결 안 됨 · 엔진 없음. 다시 보내기는 같은 요청을 모든 서버에 보내고, 이미 지운 서버는 지울 것이 없습니다.</span>
          {err !== undefined && <MutationError error={err} />}
        </>
      ) : (
        <>
          {r.standalone ? (
            <span className="muted small">단독 컨테이너는 범위를 고르지 않고 그 컨테이너 전체만 지웁니다.</span>
          ) : (
            <div className="field" role="radiogroup" aria-label="범위">
              <span>범위</span>
              {(
                [
                  ['task', `이 컨테이너만 (${name})`, !key ? (svc.loading ? '작업 키를 찾는 중…' : '이 컨테이너의 보관소 로그를 찾지 못했습니다') : undefined],
                  ['service', `서비스 전체 (${r.service})`, `지워진 ${r.service} 컨테이너의 로그도 포함`],
                  ['app', `앱 전체 (${r.app})`, undefined],
                ] as [ClearScope, string, string | undefined][]
              ).map(([v, label, sub]) => (
                <label key={v} className="row" style={{ gap: 8, alignItems: 'flex-start', cursor: 'pointer' }}>
                  <input type="radio" name="log-clear-scope" checked={scope === v} onChange={() => setScope(v)} style={{ marginTop: 3 }} />
                  <span>
                    {label}
                    {sub && (
                      <span className="muted small" style={{ display: 'block' }}>
                        {sub}
                      </span>
                    )}
                  </span>
                </label>
              ))}
            </div>
          )}
          <span className="small" style={{ fontWeight: 600 }}>
            지울 로그
          </span>
          {list.error ? (
            <ErrorBand error={list.error} what="지울 로그 목록을 읽지 못했습니다" />
          ) : !list.data && sel ? (
            <p className="muted">지울 로그를 읽는 중…</p>
          ) : (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>서버</th>
                    <th>컨테이너</th>
                    <th>줄</th>
                    <th>크기</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((l) => (
                    <tr key={`${l.node}/${l.container}`}>
                      <td>{l.node}</td>
                      <td>
                        {shortName(l)}
                        {l.key && l.key === key && l.container !== nativeID ? <span className="muted"> · 지워짐</span> : l.container === nativeID ? <span className="muted"> · 지금</span> : null}
                      </td>
                      <td>{l.lines.toLocaleString()}</td>
                      <td>{fmtBytes(l.size)}</td>
                    </tr>
                  ))}
                  {!rows.length && (
                    <tr>
                      <td colSpan={4} className="muted">
                        보관소에 남은 로그가 없습니다.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
          {down.length > 0 && <div className="note wa small">{down.map((n) => `${n.node}(${(CLEAR_CODE[n.code] ?? [n.code])[0]})`).join(', ')}의 목록은 읽지 못했습니다. 지우기는 그 서버에도 보내지만, 닿지 않으면 남습니다.</div>}
          <span className="small">
            {rows.length ? `합계 ${lines.toLocaleString()}줄 · ${fmtBytes(size)}. ` : ''}지운 로그는 되살릴 수 없습니다.{r.standalone ? '' : ' 외부로 보낸 로그는 남습니다.'}
          </span>
          {err !== undefined && <MutationError error={err} />}
        </>
      )}
    </Dialog>
  );
}

function Follower({ task, d, onLine, onReload, onFail, onRetry }: { task: TaskView; d: D.DTaskDetail; onLine: (l: Row) => void; onReload: () => void; onFail: (code?: string) => void; onRetry: () => void }) {
  const partial = useRef({ out: '', err: '' });
  const seq = useRef(1e12);
  const s = useFollow(task, { kind: 'logs', service: task.service, instance: task.instance, tail: 0, stdout: true, stderr: true }, (e) => {
    if (e.type !== 'stdout' && e.type !== 'stderr') return;
    const k = e.type === 'stderr' ? 'err' : 'out';
    const parts = (partial.current[k] + e.text).split('\n');
    partial.current[k] = parts.pop() ?? '';
    for (const text of parts) onLine({ seq: ++seq.current, time: Math.floor(Date.now() / 1000), stream: e.type, text });
  });
  // 거부·끊김을 위쪽 따라가기 단추와 안내에도 알린다
  useEffect(() => onFail(s.phase === 'failed' ? (s.endCode ?? 'closed') : undefined), [s.phase, s.endCode]); // eslint-disable-line react-hooks/exhaustive-deps
  const changed = s.target && s.target.generation !== d.generation;
  return (
    <div style={{ fontFamily: 'var(--font)', marginTop: 6 }}>
      {changed ? (
        <div className="note wa small">
          컨테이너가 바뀌었습니다 (세대 {d.generation} → {s.target?.generation}) ·{' '}
          <a href="#" onClick={(e) => (e.preventDefault(), onReload())}>
            새로 따라가기
          </a>
        </div>
      ) : s.phase === 'failed' ? (
        <div className="note er small">
          따라가기가 멈췄습니다 · {streamEndText(s.endCode ?? 'closed')}
          {s.endCode === 'session-expired' ? " 다시 로그인한 뒤 '다시 따라가기'를 누르세요." : ''} 이미 받은 줄은 그대로 둡니다.{' '}
          <button className="btn sm" onClick={onRetry}>
            다시 따라가기
          </button>
        </div>
      ) : (
        <span className="t">· · · {s.phase === 'live' ? '따라가는 중 — 새 줄을 기다립니다' : s.phase === 'connecting' ? '따라가기 연결 중' : '스트림이 끝났습니다'}</span>
      )}
    </div>
  );
}

// ── 자원 사용 · 프로세스 (UI-3C) ──

function ResTab({ r, d, task, base }: { r: TaskRef; d: D.DTaskDetail; task?: TaskView; base: string }) {
  const stats = usePoll((s) => taskStats(r, s), [r], DEFAULT_POLL_MS);
  const [paused, setPaused] = useState(false);
  const items = stats.data ?? [];
  const last = items[items.length - 1];
  const memRatio = last && last.memLimit ? last.memUsed / last.memLimit : 0;
  useEffect(() => {
    stats.setInterval(paused ? 0 : DEFAULT_POLL_MS);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paused]);
  const tile = (label: string, value: ReactNode, sub: ReactNode, warn = false) => (
    <div className="card" style={{ gap: 2, padding: '12px 14px' }}>
      <span className="muted small">{label}</span>
      <b style={{ fontSize: 20, color: warn ? 'var(--wa)' : 'var(--text)' }}>{value}</b>
      <span className="muted small">{sub}</span>
    </div>
  );
  return (
    <>
      {stats.error || (stats.data && !stats.data.length) ? <div className="note un small">보관 표본(최근 1시간) · 서버 기능 대기. 아래 프로세스는 스트림으로 지금 값을 봅니다.</div> : null}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
        {tile('CPU', last ? `${Math.round(last.cpuPercent)}%` : '—', `코어 1개 기준 · 한도 ${d.cpus ?? '없음'}`)}
        {tile('메모리', last ? `${mib(last.memUsed)} MiB` : '—', `한도 ${last?.memLimit ? mib(last.memLimit) : '없음'}`, memRatio >= 0.7)}
        {tile(
          '망 누계',
          <>
            <span style={{ display: 'block', whiteSpace: 'nowrap' }}>↓ {fmtBytes(last?.netRxBytes)}</span>
            <span style={{ display: 'block', whiteSpace: 'nowrap' }}>↑ {fmtBytes(last?.netTxBytes)}</span>
          </>,
          '시작 뒤 누계',
        )}
        {tile(
          '디스크 누계',
          <>
            <span style={{ display: 'block', whiteSpace: 'nowrap' }}>읽기 {fmtBytes(last?.blockRead)}</span>
            <span style={{ display: 'block', whiteSpace: 'nowrap' }}>쓰기 {fmtBytes(last?.blockWrite)}</span>
          </>,
          '시작 뒤 누계',
        )}
        {tile('프로세스', last?.pids ?? '—', 'PID 수')}
      </div>
      <div className="grid-2" style={{ marginTop: 20 }}>
        <Card
          title={
            <h2>
              자원 사용{' '}
              <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}>
                최근 1시간 · 30초 간격{stats.asOf ? ` · ${hhmmss(stats.asOf)} 기준` : ''}
              </span>
            </h2>
          }
          actions={
            <span className="row" style={{ gap: 6 }}>
              <button className="btn sm" title="지금 바로 다시 읽기" disabled={stats.manual} onClick={stats.refreshByUser}>
                {stats.manual ? '읽는 중…' : '↻ 새로고침'}
              </button>
              <button className="btn sm" onClick={() => setPaused((p) => !p)}>
                {paused ? '▶ 다시 읽기' : '⏸ 멈춤'}
              </button>
            </span>
          }
        >
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 14 }}>
            <div>
              <b className="small">CPU</b>
              <Spark values={items.slice(-40).map((x) => x.cpuPercent)} max={d.cpus ? d.cpus * 100 : undefined} />
            </div>
            <div>
              <b className="small">메모리</b>
              <Spark values={items.slice(-40).map((x) => x.memUsed)} max={last?.memLimit || undefined} />
            </div>
          </div>
          <span className="muted small">서버가 30초마다 모아 둔 최근 1시간 표본입니다. 웹은 표본을 저장하지 않습니다. '↻ 새로고침'은 간격을 기다리지 않고 바로 다시 읽고, 간격 시계를 그때부터 다시 셉니다. 값이 없으면 0 대신 '—'로 둡니다.</span>
        </Card>
        <Card
          title="프로세스"
          actions={
            <Link to={`${base}/exec`} className="small">
              터미널 열기
            </Link>
          }
        >
          {task ? <TopPane task={task} intervalSec={30} /> : <p className="muted">컨테이너 목록을 읽는 중입니다.</p>}
          <span className="muted small">PID는 서버(호스트) 기준 번호입니다. 열 이름은 Docker가 준 그대로입니다.</span>
        </Card>
      </div>
    </>
  );
}

// ── 상태 검사 · 이벤트 · 실제 설정 ──

function ChecksTab({ q }: { q: ReturnType<typeof usePoll<D.DTaskHistory>> }) {
  return (
    <Load q={q} what="상태 검사 기록을 읽지 못했습니다">
      {(h) =>
        h.checks.length === 0 ? (
          <Card>
            <span className="muted">이 컨테이너에는 상태 검사가 없습니다. 앱 편집 › 서비스 › healthcheck에서 정합니다.</span>
          </Card>
        ) : (
          <>
            {h.checks.map((c) => (
              <Card key={c.checker} title={c.checker} actions={c.consecutiveFailures ? <Badge tone="er">연속 실패 {c.consecutiveFailures}회</Badge> : <Badge tone="ok">통과 중</Badge>}>
                <div className="table-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>언제</th>
                        <th>결과</th>
                        <th>걸림</th>
                        <th>내용</th>
                      </tr>
                    </thead>
                    <tbody>
                      {c.results.map((x, i) => (
                        <tr key={i}>
                          <td>{hm(new Date(x.at * 1000))}</td>
                          <td>{x.ok ? <span style={{ color: 'var(--ok)' }}>통과</span> : <span style={{ color: 'var(--er)' }}>실패</span>}</td>
                          <td>{x.ok ? `${x.durationMs} ms` : '—'}</td>
                          <td className="wrap">{x.message ?? ''}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            ))}
          </>
        )
      }
    </Load>
  );
}

function EventsTab({ q }: { q: ReturnType<typeof usePoll<D.DTaskHistory>> }) {
  return (
    <Load q={q} what="이벤트를 읽지 못했습니다">
      {(h) => {
        const evs = eventsOf(h);
        return (
          <Card title={`이벤트 ${evs.length}개`}>
            <div className="tl">
              {evs.map((e, i) => (
                <div key={i}>
                  <span className="muted">{short(e.at)}</span>
                  <i style={{ background: e.tone }} />
                  <span>
                    {e.text} <span className="muted small">{day(e.at)}</span>
                  </span>
                </div>
              ))}
              {evs.length === 0 && <span className="muted">기록된 이벤트가 없습니다.</span>}
            </div>
            <span className="muted small">종료·재시작 이력과 상태 검사 결과가 바뀐 때를 최신 순으로 보여 줍니다. 서버가 보관한 최근 기록까지입니다.</span>
          </Card>
        );
      }}
    </Load>
  );
}

function InspectTab({ d }: { d: D.DTaskDetail }) {
  const [only, setOnly] = useState(false);
  const rows: [string, unknown, string[]][] = [
    ['Image', d.image, DRIFT_KEYS.image],
    ['Digest', d.digest, []],
    ['Entrypoint', d.entrypoint, DRIFT_KEYS.command],
    ['Cmd', d.command, DRIFT_KEYS.command],
    ['WorkingDir', d.workingDir, DRIFT_KEYS.command],
    ['User', d.user, DRIFT_KEYS.user],
    ['ReadonlyRootfs', d.readOnly, DRIFT_KEYS.security],
    ['Privileged', d.privileged, DRIFT_KEYS.security],
    ['CapAdd', d.capAdd, DRIFT_KEYS.security],
    ['NanoCpus', d.cpus, DRIFT_KEYS.limits],
    ['Memory', d.memoryBytes, DRIFT_KEYS.limits],
    ['LogConfig', { Type: d.logDriver, Config: d.logOptions }, DRIFT_KEYS.logging],
    ['Env', d.env.map((e) => (e.secret ? `${e.key}=«가림: ${e.secret.replace(/^secret:/, '')}»` : `${e.key}=${e.value ?? ''}`)), DRIFT_KEYS.env],
    ['Mounts', d.mounts, DRIFT_KEYS.storage],
    ['Networks', d.networks, DRIFT_KEYS.networks],
    ['Ports', d.ports, DRIFT_KEYS.ports],
    ['StopSignal', d.stopSignal, DRIFT_KEYS.stop],
    ['StopTimeout', d.stopGrace, DRIFT_KEYS.stop],
  ];
  const shown = rows.filter(([, v, k]) => v !== undefined && (!only || drifted(d, k).length));
  return (
    <Card
      title="실제 설정"
      actions={
        <button className={`btn sm${only ? ' primary' : ''}`} onClick={() => setOnly((x) => !x)} disabled={!d.drift?.length} title={d.drift?.length ? '목표와 다른 칸만 거릅니다' : undefined}>
          {d.drift?.length ? `목표와 다른 칸 ${d.drift.length}개${only ? ' · 모두 보기' : ''}` : '목표 = 실제'}
        </button>
      }
    >
      <pre className="preview-yaml">
        {shown.map(([k, v, keys]) => {
          const hit = drifted(d, keys).length > 0;
          return (
            <div key={k} className={hit ? 'drift' : undefined} title={hit ? `목표와 다름: ${drifted(d, keys).join(', ')}` : undefined} style={hit ? { background: '#3a2a10', color: '#f5c97a' } : undefined}>
              "{k}": {JSON.stringify(v, null, 2)},
            </div>
          );
        })}
        {shown.length === 0 && <span className="d">목표와 다른 칸이 없습니다.</span>}
      </pre>
      <span className="muted small">
        서버가 Docker에서 읽은 값(inspect)을 Docker 이름으로 보여 줍니다. 목표와 다른 칸만 노랗게 표시합니다. 관측 {day(d.observedAt)} · 세대 {d.generation}.{d.drift?.length ? ` 다른 칸: ${d.drift.join(', ')}` : ''}
      </span>
    </Card>
  );
}
