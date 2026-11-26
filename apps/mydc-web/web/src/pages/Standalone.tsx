// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { enc } from '../api/client';
import { networks, standaloneGet, standaloneList, standaloneTask } from '../api/endpoints';
import type { StandaloneView } from '../api/types';
import { useAuth, useTenantRole } from '../auth/session';
import { Badge, Card, OpId, HelpBox, PageHeader, Segmented, type Tone } from '../components/ui';
import { Empty, Load } from '../components/states';
import { Dialog, ConfirmDialog } from '../components/Dialog';
import { Menu, type MenuItem } from '../components/Menu';
import { CodeView } from '../components/Code';
import { MutationError, OpPanel, casFailed, useMutation } from '../components/OpPanel';
import { ContainerConsole } from '../components/ContainerConsole';
import { ImageInput, rememberImage } from '../components/ImageField';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { fmtTime, hhmmss, middle } from '../lib/format';
import { IMPORT_ITEM_LABEL, RESTART_LABEL, fmtDur, quickShell, standaloneFromYaml, standaloneToYaml, type ImportedFrom, type RestartPolicy } from '../lib/standalone';
import { NoTenant } from './Deploy';
import { usePhone } from '../lib/viewport';
import { ApprovalPrompt } from './VaultApproval';
import { MCards, MWideNote, useReadOnlyTop } from '../mobile/ReadOnly';

const NEED = '배포 권한 필요';
type Filter = 'all' | 'temp' | 'fixed' | 'ended';

function useTick(ms: number) {
  const [, set] = useState(0);
  useEffect(() => {
    const t = setInterval(() => set((x) => x + 1), ms);
    return () => clearInterval(t);
  }, [ms]);
}
const secLeft = (iso?: string) => (iso ? (Date.parse(iso) - Date.now()) / 1000 : 0);
const graceLeft = (s: StandaloneView) => (s.disconnectedAt && s.graceSeconds !== undefined ? s.graceSeconds - (Date.now() - Date.parse(s.disconnectedAt)) / 1000 : undefined);
const disconnected = (s: StandaloneView) => s.lifetime === 'temp' && s.mode === 'shell' && s.state === 'running' && s.connections === 0 && !!s.disconnectedAt;
const hasIngress = (s: StandaloneView) => /\bingress:/.test(s.yaml);
/** 쉘이 아닌데 TTY도 없는 임시: 터미널로 붙지 않고 출력만 본다 */
const outputOnly = (s: StandaloneView) => s.mode === 'entrypoint' && !/^tty: true$/m.test(s.yaml);

export function LifetimeCell({ s }: { s: StandaloneView }) {
  if (s.lifetime === 'fixed')
    return (
      <span className="row nowrap">
        <Badge tone="ok">고정</Badge> {s.restartPolicy ?? 'on-failure'}
      </span>
    );
  const g = graceLeft(s);
  return (
    <span className="row nowrap">
      <Badge tone="un">임시</Badge> {s.state === 'removed' ? '지움' : disconnected(s) && g !== undefined ? `유예 ${fmtDur(Math.max(0, g))}` : `${fmtDur(Math.max(0, secLeft(s.expiresAt)))} 남음`}
    </span>
  );
}
const modeText = (s: StandaloneView) => (s.mode === 'shell' ? (s.state === 'removed' ? '쉘' : s.connections > 0 ? `쉘 · 연결 ${s.connections}` : '쉘 · 끊김') : '엔트리포인트');

export function StateBadge({ s }: { s: StandaloneView }) {
  const [tone, text] = stateOf(s);
  return <Badge tone={tone}>{text}</Badge>;
}
function stateOf(s: StandaloneView): [Tone, string] {
  return (
    s.state === 'removed'
      ? [s.exitCode ? 'er' : 'un', s.exitCode !== undefined ? `끝남 · 종료 ${s.exitCode}` : '끝남']
      : s.state === 'pending'
        ? ['pr', '만드는 중']
        : s.state === 'starting'
          ? ['pr', '시작 중']
          : s.state === 'restarting'
            ? ['wa', `다시 시작 중 · ${s.restarts}회`]
            : s.state === 'exited'
              ? [s.exitCode ? 'er' : 'un', `멈춤 · 종료 ${s.exitCode ?? 0}`]
              : s.state === 'unknown'
                ? ['un', s.lifetime === 'fixed' ? '서버 없음' : '관측 없음']
                : disconnected(s)
                  ? ['wa', '연결 끊김']
                  : s.lifetime === 'temp' && outputOnly(s)
                    ? ['un', '실행 중 · 출력만']
                    : s.lifetime === 'fixed' && hasIngress(s)
                      ? ['ok', '실행 중 · 외부 접속']
                      : s.lifetime === 'fixed'
                        ? ['ok', `실행 중 · 재시작 ${s.restarts}`]
                        : ['ok', '실행 중']);
}

type Dlg =
  | { kind: 'pin' | 'end' | 'remove' | 'restart' | 'stop' | 'start' | 'yaml' | 'attach'; s: StandaloneView }
  | { kind: 'quick' };

export function StandalonePage() {
  return usePhone() ? <MStandalone /> : <DesktopStandalone />;
}

/** 휴대폰 단독 컨테이너 (UI-M11 ③ 모양): 카드를 누르면 로그만 본다. 만들기·터미널·끝내기는 넓은 화면에서 */
function MStandalone() {
  const { tenant } = useTenantRole();
  const [scope, setScope] = useState<'mine' | 'all'>('mine');
  const [filter, setFilter] = useState<Filter>('all');
  const [logs, setLogs] = useState<StandaloneView>();
  const q = usePoll((sig) => (tenant ? standaloneList(tenant, scope === 'all', sig) : Promise.resolve(undefined)), [tenant, scope], DEFAULT_POLL_MS);
  useTick(15_000);
  useReadOnlyTop('단독 컨테이너', tenant ? `작업 공간 ${tenant}` : undefined, '만들기·터미널·고정·끝내기는 넓은 화면에서', [tenant]);
  if (!tenant) return <NoTenant />;
  const all = q.data?.items ?? [];
  const live = all.filter((x) => x.state !== 'removed');
  const rows = all.filter((x) => (filter === 'ended' ? x.state === 'removed' : x.state !== 'removed' && (filter === 'all' || x.lifetime === filter)));
  const chips: [Filter, string][] = [
    ['all', `전체 ${live.length}`],
    ['temp', '임시'],
    ['fixed', '고정'],
    ['ended', '끝난 것'],
  ];
  return (
    <>
      <div className="mchips">
        {chips.map(([k, l]) => (
          <button key={k} type="button" className={`mchip${filter === k ? ' on' : ''}`} onClick={() => setFilter(k)}>
            {l}
          </button>
        ))}
        <button type="button" className={`mchip${scope === 'all' ? ' on' : ''}`} onClick={() => setScope(scope === 'all' ? 'mine' : 'all')}>
          {scope === 'all' ? '모두의 것' : '내 것'}
        </button>
      </div>
      <Load q={q} what="단독 컨테이너를 불러오지 못했습니다">
        {() => (
          <MCards
            empty={all.length ? '조건에 맞는 컨테이너가 없습니다.' : '단독 컨테이너가 없습니다.'}
            items={rows.map((x) => {
              const [tone, text] = stateOf(x);
              const g = graceLeft(x);
              return {
                key: x.name,
                title: x.name,
                badge: [tone, text],
                tone: tone === 'er' ? 'er' : tone === 'wa' ? 'wa' : undefined,
                lines: [
                  <span className="mono" style={{ fontSize: 12 }}>
                    {middle(x.image, 24, 14)}
                  </span>,
                  `${x.node || '—'} · ${modeText(x)}`,
                ],
                meta:
                  x.lifetime === 'fixed'
                    ? `고정 · ${x.restartPolicy ?? 'on-failure'}${scope === 'all' ? ` · ${x.ownerName}` : ''}`
                    : `임시 · ${x.state === 'removed' ? '지움' : disconnected(x) && g !== undefined ? `유예 ${fmtDur(Math.max(0, g))}` : `${fmtDur(Math.max(0, secLeft(x.expiresAt)))} 남음`}${scope === 'all' ? ` · ${x.ownerName}` : ''}`,
                onOpen: x.state === 'removed' ? undefined : () => setLogs(x),
              };
            })}
          />
        )}
      </Load>
      <MWideNote>카드를 누르면 로그를 봅니다</MWideNote>
      {logs && <ContainerConsole task={standaloneTask(logs)} canExec={false} initial="logs" onClose={() => setLogs(undefined)} />}
    </>
  );
}

function DesktopStandalone() {
  const { tenant, canDeploy } = useTenantRole();
  const { session } = useAuth();
  const navigate = useNavigate();
  const me = session?.user.id ?? '';
  const isManager = canDeploy;
  const [scope, setScope] = useState<'mine' | 'all'>('mine');
  const [filter, setFilter] = useState<Filter>('all');
  const [find, setFind] = useState('');
  const [selName, setSelName] = useState<string>();
  const [dlg, setDlg] = useState<Dlg>();
  const [console_, setConsole] = useState<{ s: StandaloneView; tab: 'logs' | 'exec' }>();
  const q = usePoll((sig) => (tenant ? standaloneList(tenant, scope === 'all', sig) : Promise.resolve(undefined)), [tenant, scope], DEFAULT_POLL_MS);
  useTick(15_000);

  const all = q.data?.items ?? [];
  const live = all.filter((s) => s.state !== 'removed');
  const counts = { all: live.length, temp: live.filter((s) => s.lifetime === 'temp').length, fixed: live.filter((s) => s.lifetime === 'fixed').length, ended: all.length - live.length };
  const rows = all.filter((s) => {
    if (filter === 'ended' ? s.state !== 'removed' : s.state === 'removed') return false;
    if (filter === 'temp' && s.lifetime !== 'temp') return false;
    if (filter === 'fixed' && s.lifetime !== 'fixed') return false;
    return !find || `${s.name} ${s.image}`.toLowerCase().includes(find.toLowerCase());
  });
  const sel = all.find((s) => s.name === selName) ?? rows[0];
  const close = () => (setDlg(undefined), q.refresh());

  const openTerminal = (s: StandaloneView) => (s.lifetime === 'temp' && s.owner !== me ? setDlg({ kind: 'attach', s }) : setConsole({ s, tab: 'exec' }));
  const editPath = (s: StandaloneView) => navigate('/standalone/new', { state: { yaml: s.yaml, expected: s.revision, edit: s.name, importedFrom: carryImport(s) } });
  const menuFor = (s: StandaloneView): MenuItem[] => {
    const dis = canDeploy ? undefined : NEED;
    if (s.state === 'removed') return [{ label: '정의 YAML 보기', onSelect: () => setDlg({ kind: 'yaml', s }) }, { label: '같은 정의로 다시 실행', onSelect: () => navigate('/standalone/new', { state: { yaml: s.yaml } }), disabledReason: dis }];
    if (s.lifetime === 'temp')
      return [
        { label: '터미널 열기', onSelect: () => openTerminal(s), disabledReason: dis ?? (outputOnly(s) ? '출력만 보는 방식입니다' : undefined) },
        { label: '자세히', onSelect: () => setConsole({ s, tab: 'logs' }) },
        { label: '수명 늘리기…', onSelect: () => setSelName(s.name), disabledReason: dis, hint: '요약 카드에서 고릅니다' },
        { label: '📌 고정으로 바꾸기…', onSelect: () => setDlg({ kind: 'pin', s }), disabledReason: dis },
        { label: '정의 YAML 보기', onSelect: () => setDlg({ kind: 'yaml', s }) },
        { label: '끝내기…', danger: true, onSelect: () => setDlg({ kind: 'end', s }), disabledReason: dis },
      ];
    return [
      { label: '자세히 (개요·로그·자원·상태 검사·이벤트)', onSelect: () => setConsole({ s, tab: 'logs' }) },
      { label: '터미널 열기 (exec)', onSelect: () => openTerminal(s), disabledReason: dis ?? (s.state !== 'running' ? '실행 중일 때만' : undefined) },
      { label: '정의 고치기…', hint: '다시 만듦', onSelect: () => editPath(s), disabledReason: dis },
      { label: '다시 시작', onSelect: () => setDlg({ kind: 'restart', s }), disabledReason: dis },
      s.state === 'exited' ? { label: '시작', onSelect: () => setDlg({ kind: 'start', s }), disabledReason: dis } : { label: '멈추기', onSelect: () => setDlg({ kind: 'stop', s }), disabledReason: dis },
      { label: '지우기…', danger: true, onSelect: () => setDlg({ kind: 'remove', s }), disabledReason: dis },
    ];
  };

  if (!tenant) return <NoTenant />;
  return (
    <>
      <PageHeader
        title="단독 컨테이너"
        ids="UI-3E"
        actions={
          <>
            <span className="pill">작업 공간 {tenant}</span>
            <button className="btn" title="지금 바로 다시 읽기" onClick={() => q.refresh()}>
              ↻ 새로고침
            </button>
            <button className="btn" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => setDlg({ kind: 'quick' })}>
              ▶ 임시로 바로 쉘
            </button>
            <button className="btn primary" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => navigate('/standalone/new')}>
              ＋ 새로 실행
            </button>
          </>
        }
      />
      <HelpBox terms="단독 컨테이너 (standalone) · 임시 (temp, TTL) · 고정 (fixed) · 고정으로 바꾸기 (pin) · 쉘 (TTY+stdin) · 엔트리포인트 (ENTRYPOINT/CMD)">
        <b>이 화면은</b> 앱으로 묶지 않고 컨테이너 하나를 작업 공간에서 바로 띄웁니다. 앱 컨테이너와 똑같이 망·포트·외부 접속·데이터 저장소·비밀값·상태 검사·로그·터미널을 쓸 수 있고, 다른 점은 앱 단위가 아니라 컨테이너 하나로 돈다는 것뿐입니다. <b>임시</b>는 수명이 다하거나 끝내면 지워지고, <b>고정</b>은 지울 때까지 남아 재시작 정책대로 다시 뜹니다. 임시는 언제든 고정으로 바꿀 수 있습니다.
      </HelpBox>
      <Card>
        <div className="row" style={{ gap: 8 }}>
          <Segmented
            label="수명으로 거르기"
            value={filter}
            onChange={setFilter}
            options={[
              ['all', `전체 ${counts.all}`],
              ['temp', `임시 ${counts.temp}`],
              ['fixed', `고정 ${counts.fixed}`],
              ['ended', counts.ended ? `끝남 ${counts.ended}` : '끝남'],
            ]}
          />
          <select value={scope} onChange={(e) => setScope(e.target.value as 'mine' | 'all')} aria-label="임시 범위" style={{ width: 'auto' }}>
            <option value="mine">임시: 내 것만</option>
            <option value="all" disabled={!isManager}>
              작업 공간 전체 (관리자)
            </option>
          </select>
          <input type="search" placeholder="이름·이미지 찾기" value={find} onChange={(e) => setFind(e.target.value)} style={{ flex: '1 1 200px' }} aria-label="이름·이미지 찾기" />
          <span className="small muted">30초마다 · {q.asOf ? `${hhmmss(q.asOf)} 기준` : '읽는 중'}</span>
        </div>
        <Load q={q}>
          {() =>
            all.length === 0 ? (
              <Empty
                title="이 작업 공간에 단독 컨테이너가 없습니다."
                action={
                  <span className="row">
                    <button className="btn" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => setDlg({ kind: 'quick' })}>
                      ▶ 임시로 바로 쉘
                    </button>
                    <button className="btn primary" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => navigate('/standalone/new')}>
                      ＋ 새로 실행
                    </button>
                  </span>
                }
              >
                임시로 바로 쉘: 망에서 이름 풀기·포트 확인 같은 점검을 바로 합니다. 새로 실행: 앱 없이 작은 서비스를 고정으로 띄웁니다.
              </Empty>
            ) : rows.length === 0 ? (
              <Empty kind="filtered" title="조건에 맞는 단독 컨테이너가 없습니다" />
            ) : (
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>이름</th>
                      <th>이미지</th>
                      <th>서버</th>
                      <th>수명</th>
                      <th>방식</th>
                      <th>상태</th>
                      <th aria-label="메뉴" />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((s) => (
                      <tr
                        key={s.name + s.state}
                        className={sel?.name === s.name ? 'selected' : undefined}
                        aria-selected={sel?.name === s.name}
                        onClick={() => setSelName(s.name)}
                        onDoubleClick={() => (s.state === 'removed' ? undefined : s.lifetime === 'temp' && canDeploy && !outputOnly(s) ? openTerminal(s) : setConsole({ s, tab: 'logs' }))}
                        style={{ cursor: 'pointer' }}
                      >
                        <td>
                          <button type="button" className="linkish mono" onClick={(e) => (e.stopPropagation(), s.state !== 'removed' && setConsole({ s, tab: 'logs' }))}>
                            <b>{s.name}</b>
                          </button>
                          {s.lifetime === 'temp' && s.owner !== me && <span className="small muted"> · {s.ownerName}</span>}
                        </td>
                        <td className="mono el" style={{ maxWidth: 320 }} title={s.image}>
                          {s.image}
                        </td>
                        <td>{s.node || '서버가 고름'}</td>
                        <td>
                          <LifetimeCell s={s} />
                        </td>
                        <td>{modeText(s)}</td>
                        <td>
                          <StateBadge s={s} />
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          <Menu label={`${s.name} 메뉴`} items={menuFor(s)} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </Load>
        <span className="small muted">어느 앱에도 속하지 않고 작업 공간에 속합니다. 앱 목록·앱 내리기·자동 배포와 관계없고, 작업 공간 자원 한도에는 잡힙니다. 끝난 임시는 기록만 1시간 보입니다.</span>
      </Card>
      {sel && (
        <Summary
          s={sel}
          me={me}
          canDeploy={canDeploy}
          onConsole={(tab) => (tab === 'exec' ? openTerminal(sel) : setConsole({ s: sel, tab }))}
          onDialog={(kind) => setDlg({ kind, s: sel })}
          onEdit={() => editPath(sel)}
          onChanged={() => q.refresh()}
        />
      )}
      {console_ && <ContainerConsole task={standaloneTask(console_.s)} canExec={canDeploy && !outputOnly(console_.s)} initial={console_.tab} onClose={() => (setConsole(undefined), q.refresh())} />}
      {dlg?.kind === 'quick' && <QuickShellDialog tenant={tenant} onClose={close} onOpened={(s) => (close(), setSelName(s.name), setConsole({ s, tab: 'exec' }))} />}
      {dlg && dlg.kind !== 'quick' && dlg.kind === 'pin' && <PinDialog s={dlg.s} onClose={close} onRenamed={setSelName} />}
      {dlg && dlg.kind !== 'quick' && (dlg.kind === 'end' || dlg.kind === 'restart' || dlg.kind === 'stop' || dlg.kind === 'start') && <SimpleOpDialog kind={dlg.kind} s={dlg.s} onClose={close} />}
      {dlg && dlg.kind === 'remove' && <RemoveDialog s={dlg.s} onClose={close} />}
      {dlg && dlg.kind === 'yaml' && <YamlDrawer s={dlg.s} onClose={() => setDlg(undefined)} />}
      {dlg && dlg.kind === 'attach' && (
        <Dialog
          title={`${dlg.s.ownerName}의 ${dlg.s.name}에 붙을까요?`}
          onClose={() => setDlg(undefined)}
          footer={
            <>
              <button className="btn" onClick={() => setDlg(undefined)}>
                취소
              </button>
              <button className="btn primary" onClick={() => (setConsole({ s: dlg.s, tab: 'exec' }), setDlg(undefined))}>
                붙기
              </button>
            </>
          }
        >
          <p>
            작업 공간 관리자라 붙을 수 있습니다. 붙으면 {dlg.s.ownerName}의 화면과 같은 터미널을 봅니다. 작업 기록에 ‘{session?.user.username}이(가) {dlg.s.ownerName}의 임시 컨테이너에 붙음’이 남습니다.
          </p>
        </Dialog>
      )}
    </>
  );
}

/** 고른 단독 컨테이너 요약 카드(캔버스 UI-3E 아래 카드) */
function Summary({ s, me, canDeploy, onConsole, onDialog, onEdit, onChanged }: { s: StandaloneView; me: string; canDeploy: boolean; onConsole: (tab: 'logs' | 'exec') => void; onDialog: (k: 'pin' | 'end' | 'remove' | 'restart' | 'stop' | 'start' | 'yaml') => void; onEdit: () => void; onChanged: () => void }) {
  const parsed = useMemo(() => standaloneFromYaml(s.yaml), [s.yaml]);
  const f = 'form' in parsed ? parsed.form : undefined;
  const dis = canDeploy ? undefined : NEED;
  const ended = s.state === 'removed';
  const left = secLeft(s.expiresAt);
  const g = graceLeft(s);
  const headBadge = s.lifetime === 'temp' ? <Badge tone="un">{ended ? '임시 · 지움' : `임시 · ${fmtDur(Math.max(0, left))} 남음`}</Badge> : <Badge tone="ok">고정 · {s.restartPolicy}</Badge>;
  const kv: [string, ReactNode][] = [
    ['만든 사람', `${s.ownerName} · ${s.createdAt ? fmtTime(s.createdAt) : '—'}`],
    ['작업 ID', s.operation ? <OpId id={s.operation} /> : '—'],
    ['이미지', <span className="mono">{s.image.replace(/@sha256:[0-9a-f]{64}$/, '')}{s.digest ? ` · ${middle(s.digest, 11, 4)}` : ''}</span>],
    ['서버', s.node || '서버가 고름'],
    ['방식', s.mode === 'shell' ? `쉘 · ${f?.command || '/bin/sh'} · TTY` : `엔트리포인트${f?.command ? ` · ${f.command}` : ' · 이미지 기본값'}${f?.tty ? ' · TTY' : ''}`],
    ['망 · 포트', f ? `${f.networks.map((n) => `${n.name} · 별칭 ${n.alias || s.name}`).join(', ') || '없음'} · ${f.ports.length ? f.ports.map((p) => `${p.port}/${p.proto}`).join(', ') : '포트 없음'}` : '—'],
    ['외부 접속', f?.routes.length ? f.routes.map((r) => `${r.host}${r.path}`).join(', ') : '없음'],
    ['데이터 저장소', f?.volumes.length ? f.volumes.map((v) => `${v.name} · ${v.readOnly ? '읽기 전용' : '읽기·쓰기'}`).join(', ') : '없음'],
    ['비밀값', f?.secrets.length ? f.secrets.map((x) => x.name).join(', ') : '없음'],
    ['상태 검사', f?.health === 'cmd' ? `명령 ${f.healthCmd} · ${f.healthInterval}` : f?.health === 'http' ? `HTTP ${f.healthUrl} · ${f.healthInterval}` : s.lifetime === 'temp' ? '없음 (임시)' : '없음'],
    ['자원 상한', f && (f.cpus || f.memory) ? `${f.cpus ? `CPU ${f.cpus}` : ''}${f.cpus && f.memory ? ' · ' : ''}${f.memory ? `메모리 ${f.memory}` : ''}` : '작업 공간 기본'],
    ['수명', s.lifetime === 'temp' ? `${f ? (f.ttl === '1h' ? '1시간' : f.ttl) : ''} · 끊긴 뒤 유예 ${fmtDur(s.graceSeconds ?? 600)}` : `지울 때까지 · ${RESTART_LABEL[s.restartPolicy ?? 'on-failure']}`],
    ['가져온 설정', s.importedFrom ? `${s.importedFrom.app} / ${s.importedFrom.service} · ${s.importedFrom.items.map((k) => IMPORT_ITEM_LABEL[k as keyof typeof IMPORT_ITEM_LABEL] ?? k).join(', ')}${s.importedFrom.at ? ` · ${fmtTime(s.importedFrom.at)}` : ''}` : '—'],
    [
      '정의',
      <span>
        rev {s.revision} ·{' '}
        <button type="button" className="linkish" onClick={() => onDialog('yaml')}>
          YAML 보기
        </button>
      </span>,
    ],
  ];
  return (
    <Card
      title={
        <span className="row">
          <span className="mono">{s.name}</span> {headBadge}
          {s.lifetime === 'temp' && s.owner !== me && <span className="small muted">{s.ownerName}의 임시</span>}
        </span>
      }
      actions={
        ended ? (
          <button className="btn" onClick={() => onDialog('yaml')}>
            정의 YAML 보기
          </button>
        ) : s.lifetime === 'temp' ? (
          <>
            <button className="btn" disabled={!!dis || outputOnly(s)} title={dis ?? (outputOnly(s) ? '출력만 보는 방식입니다' : undefined)} onClick={() => onConsole('exec')}>
              터미널 열기
            </button>
            <button className="btn" onClick={() => onConsole('logs')}>
              자세히 (개요·로그·자원·상태 검사)
            </button>
            <ExtendMenu s={s} disabled={dis} onDone={onChanged} />
            <button className="btn primary" disabled={!!dis} title={dis} onClick={() => onDialog('pin')}>
              📌 고정으로 바꾸기…
            </button>
            <button className="btn danger" disabled={!!dis} title={dis} onClick={() => onDialog('end')}>
              끝내기…
            </button>
          </>
        ) : (
          <>
            <button className="btn" onClick={() => onConsole('logs')}>
              자세히 (개요·로그·자원·상태 검사·이벤트)
            </button>
            <button className="btn" disabled={!!dis || s.state !== 'running'} title={dis} onClick={() => onConsole('exec')}>
              터미널 열기 (exec)
            </button>
            <button className="btn" disabled={!!dis} title={dis} onClick={onEdit}>
              정의 고치기…
            </button>
            <button className="btn" disabled={!!dis} title={dis} onClick={() => onDialog('restart')}>
              다시 시작
            </button>
            {s.state === 'exited' ? (
              <button className="btn" disabled={!!dis} title={dis} onClick={() => onDialog('start')}>
                시작
              </button>
            ) : (
              <button className="btn" disabled={!!dis} title={dis} onClick={() => onDialog('stop')}>
                멈추기
              </button>
            )}
            <button className="btn danger" disabled={!!dis} title={dis} onClick={() => onDialog('remove')}>
              지우기…
            </button>
          </>
        )
      }
    >
      {disconnected(s) && g !== undefined && (
        <div className="note un small row between">
          <span>
            ⓘ {s.name} 연결이 끊겼습니다. {fmtDur(Math.max(0, g))} 안에 다시 붙지 않으면 지웁니다.
          </span>
          <button className="btn sm" disabled={!!dis} onClick={() => onConsole('exec')}>
            다시 붙기
          </button>
        </div>
      )}
      {s.lifetime === 'fixed' && (s.state === 'restarting' || s.restarts >= 5) && (
        <div className="note er small row between">
          <span>
            {s.name}이(가) {s.restarts}번 다시 시작됐습니다{s.exitCode !== undefined ? `(종료 코드 ${s.exitCode})` : ''}. 로그를 확인하거나 멈추세요.
          </span>
          <span className="row">
            <button className="btn sm" onClick={() => onConsole('logs')}>
              로그 보기
            </button>
            <button className="btn sm" disabled={!!dis} onClick={() => onDialog('stop')}>
              멈추기
            </button>
          </span>
        </div>
      )}
      {s.lifetime === 'fixed' && s.state === 'unknown' && (
        <div className="note wa small">{s.name}이(가) 묶인 서버 {s.node}의 관측이 없습니다. 고정 단독 컨테이너는 다른 서버로 옮기지 않습니다. 서버가 클러스터에서 빠졌다면 정의를 고쳐 다른 서버로 다시 만들거나 지우세요.</div>
      )}
      {ended && <div className="note un small">{s.endedAt ? `${fmtTime(s.endedAt)}에 끝나 컨테이너와 쓰기 계층을 지웠습니다.` : '끝나 컨테이너를 지웠습니다.'} 기록만 1시간 보입니다.</div>}
      <div className="kv4">
        {kv.map(([k, v]) => (
          <span key={k} style={{ display: 'contents' }}>
            <span className="muted">{k}</span>
            <span>{v}</span>
          </span>
        ))}
      </div>
      {s.lifetime === 'temp' && !ended && <span className="small muted">고정으로 바꾸면 같은 컨테이너가 그대로 남습니다(지금까지 만든 파일 유지). 수명이 사라지고, 서버가 다시 뜨면 재시작 정책대로 다시 뜹니다.</span>}
    </Card>
  );
}

/** '수명 늘리기…' 메뉴: 남은 시간에 더하기, 최대 24시간(만든 때부터) */
function ExtendMenu({ s, disabled, onDone }: { s: StandaloneView; disabled?: string; onDone: () => void }) {
  const m = useMutation();
  const maxLeft = s.createdAt ? 24 * 3600 - (Math.max(Date.parse(s.expiresAt ?? ''), Date.now()) - Date.parse(s.createdAt)) / 1000 : 0;
  const add = (_ttl: string, sec: number): MenuItem => ({
    label: `+${fmtDur(sec)}`,
    disabledReason: sec > maxLeft ? '24시간을 넘습니다' : undefined,
    onSelect: () => {
      m.reset();
      // 새 만료 = mydcd가 서명 시각 + ttlSeconds로 정한다(지금 만료보다 크고 만든 뒤 24시간 이하)
      void m.run(saPath(s, 'extend'), { expected: s.revision, ttlSeconds: Math.round(secLeft(s.expiresAt) + sec) }).then(onDone);
    },
  });
  if (disabled)
    return (
      <button className="btn" disabled title={disabled}>
        수명 늘리기…
      </button>
    );
  return (
    <span className="col" style={{ gap: 4 }}>
      <Menu
        label="수명 늘리기"
        align="left"
        button="수명 늘리기…"
        items={[
          { label: `남은 ${fmtDur(Math.max(0, secLeft(s.expiresAt)))}에 더하기`, disabledReason: '최대 24시간. 그보다 오래 쓰려면 고정으로 바꾸세요.' },
          add('30m', 1800),
          add('1h', 3600),
          add('4h', 4 * 3600),
          { label: '최대 24시간까지', disabledReason: maxLeft < 60 ? '이미 24시간입니다' : undefined, onSelect: () => add(`${Math.floor(maxLeft / 60)}m`, Math.floor(maxLeft / 60) * 60).onSelect?.() },
        ]}
      />
      {m.op && m.op.state !== 'applied' && <OpPanel op={m.op} onChange={m.setOp} />}
      <MutationError error={m.error} />
    </span>
  );
}

/** 결과(OpPanel)까지 보여 주는 변경 다이얼로그 틀 */
function OpDialog({ title, children, actionLabel, danger, busy, onRun, onClose, op, onOp, error, disabled }: { title: string; children: ReactNode; actionLabel: string; danger?: boolean; busy: boolean; onRun: () => void; onClose: () => void; op?: ReturnType<typeof useMutation>['op']; onOp: (o: NonNullable<ReturnType<typeof useMutation>['op']>) => void; error: unknown; disabled?: boolean }) {
  return (
    <Dialog
      title={title}
      onClose={onClose}
      danger={danger}
      footer={
        op ? (
          <button className="btn" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className={`btn ${danger ? 'danger solid' : 'primary'}`} disabled={busy || disabled} onClick={onRun}>
              {busy ? '보내는 중…' : actionLabel}
            </button>
          </>
        )
      }
    >
      {op ? (
        <>
          {casFailed(op) && <div className="note wa small">그사이 다른 사람이 바꿨습니다. 새로 읽은 뒤 다시 해 주세요.</div>}
          <OpPanel op={op} onChange={onOp} />
          {op.action === 'standalone-up' && op.tenant && <ApprovalPrompt tenant={op.tenant} op={op} onOp={onOp} kind="standalone" />}
        </>
      ) : (
        children
      )}
      <MutationError error={error} />
    </Dialog>
  );
}

function PinDialog({ s, onClose, onRenamed }: { s: StandaloneView; onClose: () => void; onRenamed: (n: string) => void }) {
  const m = useMutation();
  const [name, setName] = useState(s.name);
  const [restart, setRestart] = useState<RestartPolicy>('on-failure');
  const bad = !/^[a-z0-9][a-z0-9-]{0,62}$/.test(name);
  return (
    <OpDialog
      title={`${s.name}를 고정으로 바꾸기 (standalone-pin)`}
      actionLabel="고정으로 바꾸기"
      busy={m.busy}
      op={m.op}
      onOp={m.setOp}
      error={m.error}
      disabled={bad}
      onClose={onClose}
      onRun={() =>
        void m.run(saPath(s, 'pin'), { expected: s.revision, ...(name === s.name ? {} : { newName: name }), restart }).then((o) => o?.state === 'applied' && onRenamed(name))
      }
    >
      <div className="col" style={{ gap: 10 }}>
        <label className="field">
          <span>이름</span>
          <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} />
          <small className="muted">작업 공간 안에서 유일. 망 안 별칭도 이 이름으로 바뀝니다</small>
        </label>
        <label className="field">
          <span>재시작 정책</span>
          <select value={restart} onChange={(e) => setRestart(e.target.value as RestartPolicy)}>
            {(['on-failure', 'always', 'no'] as const).map((r) => (
              <option key={r} value={r}>
                {RESTART_LABEL[r]}
              </option>
            ))}
          </select>
        </label>
        <p className="small">
          같은 컨테이너를 그대로 둡니다. 지금까지 만든 파일이 남고, 수명({fmtDur(Math.max(0, secLeft(s.expiresAt)))})과 끊긴 뒤 유예가 사라집니다. 서버가 다시 뜨면 재시작 정책대로 다시 뜹니다.
        </p>
        {s.mode === 'shell' && <div className="note wa small">지금 쉘 방식(TTY)으로 떠 있습니다. 고정으로 바꿔도 이 프로세스가 끝나면 재시작 정책대로 같은 명령(/bin/sh)이 다시 뜹니다. 상시 서비스로 쓰려면 바꾼 뒤 정의를 고쳐 엔트리포인트로 다시 만드세요.</div>}
        <span className="small muted">
          작업 ID <OpId id={m.opId} />
        </span>
      </div>
    </OpDialog>
  );
}

/** 단독 컨테이너 동작 끝점(#291): POST /t/{t}/standalone/{name}/{verb} {opId, expected?, …} */
const saPath = (s: StandaloneView, verb: 'pin' | 'remove' | 'extend' | 'stop' | 'start' | 'restart') => `/t/${enc(s.tenant)}/standalone/${enc(s.name)}/${verb}`;

const SIMPLE = {
  end: { action: 'remove', title: (n: string) => `${n}를 끝낼까요?`, label: '끝내기', danger: true, body: '컨테이너를 멈추고 쓰기 계층까지 지웁니다. 안에서 만든 파일은 남지 않습니다. 남기려면 먼저 ‘고정으로 바꾸기’를 하세요.' },
  restart: { action: 'restart', title: (n: string) => `${n}을(를) 다시 시작할까요?`, label: '다시 시작', danger: false, body: '같은 정의로 컨테이너를 멈췄다가 다시 띄웁니다. 쓰기 계층은 남습니다. 연결된 터미널은 끊깁니다.' },
  stop: { action: 'stop', title: (n: string) => `${n}를 멈출까요?`, label: '멈추기', danger: false, body: '컨테이너를 멈추고 남겨 둡니다. 재시작 정책과 상관없이 ‘시작’을 누를 때까지 멈춰 있습니다.' },
  start: { action: 'start', title: (n: string) => `${n}을(를) 시작할까요?`, label: '시작', danger: false, body: '멈춘 컨테이너를 같은 정의로 다시 띄웁니다. 쓰기 계층은 그대로입니다.' },
} as const;

function SimpleOpDialog({ kind, s, onClose }: { kind: keyof typeof SIMPLE; s: StandaloneView; onClose: () => void }) {
  const m = useMutation();
  const d = SIMPLE[kind];
  return (
    <OpDialog
      title={d.title(s.name)}
      actionLabel={d.label}
      danger={d.danger}
      busy={m.busy}
      op={m.op}
      onOp={m.setOp}
      error={m.error}
      onClose={onClose}
      onRun={() => void m.run(saPath(s, d.action), { expected: s.revision })}
    >
      <p>
        {d.body}
        {kind === 'stop' && hasIngress(s) ? ' 외부 접속 경로는 그동안 503을 돌려줍니다.' : ''}
      </p>
    </OpDialog>
  );
}

function RemoveDialog({ s, onClose }: { s: StandaloneView; onClose: () => void }) {
  const m = useMutation();
  const parsed = useMemo(() => standaloneFromYaml(s.yaml), [s.yaml]);
  const routes = 'form' in parsed ? parsed.form.routes.length : 0;
  if (m.op)
    return (
      <Dialog
        title={`${s.name} 지우기`}
        onClose={onClose}
        footer={
          <button className="btn" onClick={onClose}>
            닫기
          </button>
        }
      >
        {casFailed(m.op) && <div className="note wa small">그사이 다른 사람이 바꿨습니다. 새로 읽은 뒤 다시 해 주세요.</div>}
        <OpPanel op={m.op} onChange={m.setOp} />
      </Dialog>
    );
  return (
    <ConfirmDialog
      title={`${s.name}을(를) 지울까요?`}
      target={s.name}
      actionLabel="지우기"
      busy={m.busy}
      onClose={onClose}
      onConfirm={() => void m.run(saPath(s, 'remove'), { expected: s.revision })}
    >
      <p>
        고정 단독 컨테이너를 멈추고 지웁니다.{routes ? ` 외부 접속 경로 ${routes}개와` : ''} 망 별칭도 함께 빠집니다. 데이터 저장소의 데이터는 지우지 않습니다.
      </p>
      <MutationError error={m.error} />
    </ConfirmDialog>
  );
}

/** 정의 YAML 보기(드로어): 복사·내려받기. 새 앱의 서비스로 옮겨 붙일 수 있다. */
function YamlDrawer({ s, onClose }: { s: StandaloneView; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const download = () => {
    const url = URL.createObjectURL(new Blob([s.yaml], { type: 'text/yaml' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `${s.name}.standalone.yaml`;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <Dialog
      title={
        <span>
          {s.name} · rev {s.revision} <small className="muted">app.yaml 서비스와 같은 형식</small>
        </span>
      }
      onClose={onClose}
      width={720}
      footer={
        <>
          <button className="btn" onClick={() => void navigator.clipboard?.writeText(s.yaml).then(() => setCopied(true))}>
            {copied ? '복사했습니다' : '복사'}
          </button>
          <button className="btn" onClick={download}>
            내려받기
          </button>
        </>
      }
    >
      <CodeView text={s.yaml} />
      <span className="small muted">
        만든 사람 {s.ownerName}
        {s.createdAt ? ` · ${fmtTime(s.createdAt)}` : ''}
        {s.operation ? ` · 작업 ID ${s.operation.slice(0, 8)}` : ''}
      </span>
    </Dialog>
  );
}

/** ▶ 임시로 바로 쉘: 이미지·망·서버만 고르고 바로 띄워 터미널을 연다. */
function QuickShellDialog({ tenant, onClose, onOpened }: { tenant: string; onClose: () => void; onOpened: (s: StandaloneView) => void }) {
  const m = useMutation();
  const nets = usePoll((sig) => networks(tenant, sig), [tenant]);
  const [image, setImage] = useState('docker.io/library/busybox:1.36');
  const [net, setNet] = useState('');
  const [node, setNode] = useState('');
  const [form] = useState(() => quickShell('', '', ''));
  const yaml = standaloneToYaml({ ...form, image, node, networks: net ? [{ name: net, alias: '' }] : [] });
  // 만든 뒤 컨테이너가 뜨면 터미널을 연다.
  const [waiting, setWaiting] = useState(false);
  const opened = useRef(onOpened);
  opened.current = onOpened;
  const applied = m.op?.state === 'applied';
  useEffect(() => {
    if (!applied) return;
    setWaiting(true);
    let stop = false;
    const poll = async () => {
      for (let i = 0; i < 20 && !stop; i++) {
        const s = await standaloneGet(tenant, form.name).catch(() => undefined);
        if (stop) return;
        if (s && s.state === 'running') return opened.current(s);
        await new Promise((res) => setTimeout(res, 1000));
      }
    };
    void poll();
    return () => {
      stop = true;
    };
  }, [applied, tenant, form.name]);
  return (
    <OpDialog
      title="임시 쉘 띄우기"
      actionLabel="띄우고 터미널 열기"
      busy={m.busy}
      op={m.op}
      onOp={m.setOp}
      error={m.error}
      disabled={!image}
      onClose={onClose}
      onRun={() => {
        rememberImage(image, '임시 쉘');
        void m.run(`/t/${enc(tenant)}/standalone/up`, { yaml, expected: 0 });
      }}
    >
      <div className="col" style={{ gap: 10 }}>
        <div className="field" role="group" aria-label="이미지">
          <span>이미지</span>
          <ImageInput tenant={tenant} value={image} onChange={setImage} />
          <small className="muted">이미지 고르기 다이얼로그(목록·직접 입력·최근 사용)를 엽니다</small>
        </div>
        <label className="field">
          <span>망</span>
          <select value={net} onChange={(e) => setNet(e.target.value)}>
            <option value="">망 없음</option>
            {(nets.data?.items ?? []).map((n) => (
              <option key={n.name} value={n.name}>
                {n.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>서버</span>
          <select value={node} onChange={(e) => setNode(e.target.value)}>
            <option value="">서버가 고름</option>
            {[...new Set((nets.data?.items ?? []).flatMap((n) => n.nodes ?? []))].map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
        </label>
        <p className="small muted">명령 /bin/sh · 수명 1시간 · 끊긴 뒤 유예 10분 · 데이터 저장소·비밀값 없음. 더 고치려면 ‘새로 실행’을 쓰세요.</p>
      </div>
      {waiting && <p className="small muted">컨테이너가 뜨기를 기다리는 중…</p>}
    </OpDialog>
  );
}

/** 고칠 때 출처를 그대로 넘긴다(출처 없이 up하면 서버가 지운다). */
const carryImport = (s: StandaloneView): ImportedFrom | undefined =>
  s.importedFrom && { app: s.importedFrom.app, deployment: s.importedFrom.deployment, service: s.importedFrom.service, items: s.importedFrom.items as ImportedFrom['items'] };
