// SPDX-License-Identifier: Apache-2.0

// 이미지 관리 › 빌드 (UI-85 빌드 컨텍스트, 캔버스 ImageBuilds · ImageBuildsIx v140~142).
// 계약: docs/reference/web-api.md '이미지 빌드'(mydcd 실제 계약). 빌드 실행·신뢰 검사·권한·기록 CAS는 mydcd 몫이고,
// 빌드 비밀값은 보관함 마운트만 보인다(값은 웹 어디에도 없다).
import { useRowLabel } from '../lib/imageUse';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, NavLink, Route, Routes, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { api, ApiError, newOpId } from '../api/client';
import {
  buildCache,
  buildContexts,
  buildFileText,
  buildLog,
  buildPath,
  buildPolicy,
  builds,
  buildTree,
  contextPath,
  imageUsage,
  registries,
  tenantStorage,
  usableRoot,
  toOp,
  type Build,
  type BuildContext,
  type BuildLog,
  type BuildPolicy,
  type BuildVersion,
} from '../api/endpoints';
import type { BuildKind, DOp } from '../api/dto';
import type { OpView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Badge, Card, Field, HelpBox, KV, OpBadge, type Tone } from '../components/ui';
import { Empty, Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { ApprovalPrompt } from './VaultApproval';
import { Drawer } from '../components/Drawer';
import { CodeView } from '../components/Code';
import { Menu, type MenuItem } from '../components/Menu';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { ago, fmtBytes } from '../lib/format';
import { eulReul } from '../lib/josa';
import { sendOnce, uncertain } from '../lib/opRetry';
import { usePoll } from '../lib/usePoll';
import { BuildCacheTab } from './BuildCache';
import { BuildEditPage } from './BuildEdit';

export const NEED = '이 작업 공간의 관리 권한이 필요합니다';
export const KIND: Record<BuildKind, [string, string]> = { git: ['⎇', 'Git'], upload: ['⇪', '업로드'], draft: ['✎', '직접 작성'] };
export const agoMs = (ms?: number) => (ms ? ago(new Date(ms).toISOString()) : '—');
export const dur = (a?: number, b?: number) => {
  if (!a || !b) return '—';
  const s = Math.max(0, Math.round((b - a) / 1000));
  return `${Math.floor(s / 60)}분 ${String(s % 60).padStart(2, '0')}초`;
};
/** '2분' · '2분 10초' */
const elapsed = (a?: number, secs = false) => {
  if (!a) return '';
  const s = Math.max(0, Math.round((Date.now() - a) / 1000));
  const m = Math.floor(s / 60);
  return secs ? (m ? `${m}분 ${s % 60}초` : `${s}초`) : m ? `${m}분` : `${s}초`;
};
export const CODE: Record<string, string> = {
  UNTRUSTED_BASE: 'FROM 미신뢰',
  TIMEOUT: '시간 초과',
  SOURCE_FETCH: '소스 받기 실패',
  BUILD_FAILED: '빌드 실패',
  PERMISSION_REVOKED: '권한 없어짐',
  CONFLICT: '설정이 바뀜',
  STORAGE_UNAVAILABLE: '저장 경로를 못 씀',
  CANCELLED: '취소됨',
};
export const live = (b?: Build) => !!b && (b.phase === 'running' || b.phase === 'queued');
export function buildStatus(b: Build): [string, Tone] {
  if (b.phase === 'succeeded') return ['성공 · 올림', 'ok'];
  if (b.phase === 'failed') return [`실패 · ${CODE[b.result?.code ?? ''] ?? b.result?.code ?? ''}`, 'er'];
  if (b.phase === 'cancelled') return ['취소됨', 'un'];
  if (b.phase === 'unknown') return ['결과 불명', 'wa'];
  if (b.cancel) return ['취소 중', 'pr'];
  if (b.phase === 'queued') return ['대기 중', 'pr'];
  return ['빌드 중', 'pr'];
}
const host = (repo: string) => repo.replace(/^https?:\/\//, '').replace(/\.git$/, '').replace(/^([^/]+?)\.example\//, '$1/');
const dfPath = (c: BuildContext) => `./${c.git?.path ? `${c.git.path.replace(/\/$/, '')}/` : ''}${c.dockerfile}`;
export const source = (c: BuildContext) => {
  const v = c.versions[0];
  if (c.kind === 'git' && c.git) return `${host(c.git.repository)}@${c.git.ref} · ${dfPath(c)}`;
  if (c.kind === 'upload') return v ? `올린 zip v${v.number}${c.versions.length > 1 ? ` (버전 ${c.versions.length}개)` : ` · ${fmtBytes(v.expandedBytes)}`}` : '아직 올린 zip 없음';
  return v ? `${c.dockerfile} · v${v.number}${v.entries > 1 ? ` · 파일 ${v.entries - 1}개` : ' · 컨텍스트 없음'}` : `${c.dockerfile} · 아직 저장한 버전 없음`;
};
const verOf = (c: BuildContext | undefined, n: number) => c?.versions.find((v) => v.number === n);
const srcOf = (b: Build, c?: BuildContext) => {
  const v = verOf(c, b.version);
  if (!b.version) return '지운 버전';
  if (v?.commit) return `${c?.git?.ref ?? ''}@${v.commit}`;
  return c?.kind === 'upload' ? `올린 zip v${b.version}` : `v${b.version}`;
};
/** 태그 틀 그대로 · 결과 이미지 줄 */
export const tagText = (c: BuildContext) => `${c.repository}:${c.tags.join(' · ')}`;
const resolveTags = (c: BuildContext | undefined, v?: BuildVersion) => (c?.tags ?? []).map((t) => t.replace(/\{version\}/g, String(v?.number ?? '')).replace(/\{commit\}/g, v?.commit ?? ''));
const shortDigest = (image?: string) => {
  const d = image?.split('@')[1];
  return d ? `${d.slice(0, 11)}…${d.slice(-2)}` : '';
};
const argText = (c: BuildContext) =>
  Object.entries(c.args)
    .map(([k, v]) => `${k}=${v}`)
    .join(', ') || '없음';
export const cacheTotal = (k?: { nodes: { reportedBytes: number }[] }) => k?.nodes.reduce((n, x) => n + x.reportedBytes, 0);
export const policyText = (p: BuildPolicy, cacheUsed?: number, queued?: number, registryName?: string) =>
  [
    `빌드 서버 ${p.nodes.map((n) => `${n.node} (저장 경로 ${n.root.id})`).join(', ') || '없음'}`,
    `동시 ${p.concurrency}개${queued ? `(대기 ${queued})` : ''}`,
    `한 빌드 ${Math.round(p.seconds / 60)}분`,
    `CPU ${+(p.cpuMillis / 1000).toFixed(2)}`,
    fmtBytes(p.memoryBytes),
    `빌드 입력 예산 ${fmtBytes(p.workspaceBytes)}`,
    `캐시 ${cacheUsed !== undefined ? `${fmtBytes(cacheUsed)} ` : ''}(정리 목표 ${fmtBytes(p.cacheBytes)})`,
    `올릴 저장소 ${registryName ?? (p.registry === 'builtin' ? '내장 저장소' : p.registry)}`,
    p.platforms.join(', '),
  ].join(' · ');

/** 머리 오른쪽 '＋ 빌드 컨텍스트 ▾' */
export function BuildNewMenu() {
  const { canDeploy } = useTenantRole();
  const navigate = useNavigate();
  const go = (k: BuildKind) => navigate(`/images/builds/new?kind=${k}`);
  const items: MenuItem[] = [
    { label: '⇪ Dockerfile 업로드', hint: 'Dockerfile과 COPY할 파일 전부를 담은 .zip 하나를 올립니다', onSelect: () => go('upload'), disabledReason: canDeploy ? undefined : NEED },
    {
      label: '⎇ Git에서 가져오기',
      hint: '저장소를 받아(git clone) 그 안의 Dockerfile로 빌드합니다. 새 커밋 때 자동 빌드 가능',
      onSelect: () => go('git'),
      disabledReason: canDeploy ? undefined : NEED,
    },
    { label: '✎ Dockerfile 직접 작성', hint: '편집기에서 Dockerfile을 쓰거나 템플릿에서 시작합니다', onSelect: () => go('draft'), disabledReason: canDeploy ? undefined : NEED },
  ];
  return <Menu label="빌드 컨텍스트 만들기" items={items} className="btn sm primary" button="＋ 빌드 컨텍스트 ▾" />;
}

/** /images/builds/* */
export function BuildsTab() {
  const path = useLocation().pathname.replace(/\/$/, '');
  const sub = path === '/images/builds' || path === '/images/builds/cache';
  return (
    <>
      {sub && <BuildSubTabs />}
      <Routes>
        <Route index element={<ContextsView />} />
        <Route path="cache" element={<BuildCacheTab />} />
        <Route path="new" element={<BuildEditPage />} />
        <Route path=":id/edit" element={<BuildEditPage />} />
      </Routes>
    </>
  );
}
function BuildSubTabs() {
  const { tenant } = useTenantRole();
  const c = usePoll((s) => buildContexts(tenant, s), [tenant], 0);
  const k = usePoll((s) => buildCache(tenant, s), [tenant], 0);
  const used = cacheTotal(k.data);
  return (
    <div className="segmented" style={{ marginBottom: 14, alignSelf: 'flex-start', width: 'fit-content' }}>
      <NavLink to="/images/builds" end className={({ isActive }) => (isActive ? 'on' : '')}>
        빌드 컨텍스트{c.data ? ` (${c.data.items.length})` : ''}
      </NavLink>
      <NavLink to="/images/builds/cache" className={({ isActive }) => (isActive ? 'on' : '')}>
        빌드 캐시{used !== undefined ? ` · ${fmtBytes(used)}` : ''}
      </NavLink>
    </div>
  );
}

type Filter = 'all' | BuildKind | 'failed';
const FILTER: Record<Filter, string> = { all: '전체', git: '⎇ Git', upload: '⇪ 업로드', draft: '✎ 직접 작성', failed: '실패한 것만' };

function ContextsView() {
  const { tenant, canDeploy } = useTenantRole();
  const toast = useToast();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const ctxQ = usePoll((s) => buildContexts(tenant, s), [tenant]);
  const polQ = usePoll((s) => buildPolicy(tenant, s), [tenant], 0);
  const cacheQ = usePoll((s) => buildCache(tenant, s), [tenant], 0);
  const regQ = usePoll((s) => registries(tenant, s), [tenant], 0);
  const anyLive = (ctxQ.data?.items ?? []).some((c) => live(c.lastBuild));
  const buildsQ = usePoll((s) => builds(tenant, undefined, s), [tenant], anyLive ? 5000 : 30_000);
  const [filter, setFilter] = useState<Filter>('all');
  const sel = params.get('context') ?? undefined;
  const setSel = (id?: string) => setParams((p) => (id ? p.set('context', id) : p.delete('context'), p), { replace: true });
  const [histOnly, setHistOnly] = useState(false);
  const [rebuild, setRebuild] = useState<BuildContext>();
  const [cancel, setCancel] = useState<Build>();
  const [clone, setClone] = useState<BuildContext>();
  const [del, setDel] = useState<BuildContext>();
  // ?policy=1 · ?policy=cache(빌드 캐시 화면의 '빌드 설정에서 바꾸기')
  const policy = params.get('policy');
  const setPolicy = (v?: string) => setParams((p) => (v ? p.set('policy', v) : p.delete('policy'), p), { replace: true });
  const [log, setLog] = useState<string>();
  const histRef = useRef<HTMLDivElement>(null);
  const autoM = useMutation();
  const refreshAll = () => (ctxQ.refresh(), buildsQ.refresh());
  useEffect(() => {
    if (!anyLive) return;
    const t = window.setInterval(() => ctxQ.refresh(), 5000);
    return () => window.clearInterval(t);
  }, [anyLive]); // eslint-disable-line react-hooks/exhaustive-deps

  const rows = ctxQ.data?.items ?? [];
  const shown = rows.filter((c) => (filter === 'all' ? true : filter === 'failed' ? c.lastBuild?.phase === 'failed' : c.kind === filter));
  const cur = rows.find((c) => c.id === sel) ?? rows[0];
  const allBuilds = buildsQ.data?.items ?? [];
  const hist = allBuilds.filter((b) => !histOnly || !cur || b.context === cur.id);
  const pol = polQ.data;
  const noPolicy = !!pol && (!pol.exists || !pol.nodes.length);
  const blockReason = !canDeploy ? NEED : noPolicy ? '빌드 설정에 빌드 서버가 없습니다. 먼저 빌드 설정을 바꾸세요' : undefined;
  const queued = allBuilds.filter((b) => b.phase === 'queued').length;
  const regName = regQ.data?.items.find((r) => r.id === pol?.registry)?.name;

  const toggleAuto = async (c: BuildContext) => {
    if (!c.git) return;
    const on = !c.git.automatic;
    const o = await sendOnce(autoM, contextPath(tenant, c.id), { context: { ...ctxBody(c), git: { ...gitBody(c), automatic: on } }, expected: c.revision }, 'PUT');
    if (o?.state === 'applied') toast(`${c.id} 자동 빌드를 ${on ? '켰' : '껐'}습니다.`);
    else if (o) toast(`${c.id} 자동 빌드를 바꾸지 못했습니다(${o.state}).`);
    ctxQ.refresh();
  };
  const menu = (c: BuildContext): MenuItem[] => [
    { label: '편집', onSelect: () => navigate(`/images/builds/${encodeURIComponent(c.id)}/edit`), disabledReason: canDeploy ? undefined : NEED },
    { label: '복제', onSelect: () => setClone(c), disabledReason: canDeploy ? undefined : NEED },
    { label: '빌드 기록', onSelect: () => (setSel(c.id), setHistOnly(true), histRef.current?.scrollIntoView({ behavior: 'smooth' })) },
    ...(c.kind === 'git'
      ? [
          {
            label: c.git?.automatic ? '자동 빌드 끄기' : '자동 빌드 켜기',
            hint: 'Git',
            onSelect: () => void toggleAuto(c),
            disabledReason: canDeploy ? (uncertain(autoM) ? '앞 변경의 결과를 확인하는 중입니다' : undefined) : NEED,
          },
        ]
      : []),
    { label: '', sep: true },
    { label: '지우기…', danger: true, onSelect: () => setDel(c), disabledReason: canDeploy ? undefined : NEED },
  ];

  return (
    <>
      <HelpBox terms="빌드 컨텍스트 (build context) · 빌드 (build) · 저장소에 올림 (push) · 빌드 인자 (build-arg) · 빌드 비밀값 (build secret) · 빌드 서버 (builder node)">
        <b>이 화면은</b> 이미지를 만드는 재료인 <b>빌드 컨텍스트</b>(Dockerfile과 함께 쓰는 파일)를 모아 두는 곳입니다. 업로드한 것, Git에서 가져온 것, 직접 작성한 것이 모두 아래 목록에 남고, 고르면
        파일과 Dockerfile을 볼 수 있습니다. <b>다시 빌드</b>를 누르면 그 컨텍스트로 이미지를 다시 만들어 내장 저장소에 올리는 데까지 한 번에 진행합니다.
      </HelpBox>
      <div className="inset row" style={{ gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <b className="small">빌드 설정</b>
        {pol ? (
          <span className="small">{noPolicy ? <Badge tone="wa">빌드 설정이 없습니다 · 빌드하려면 빌드 서버와 저장 경로를 정하세요</Badge> : policyText(pol, cacheTotal(cacheQ.data), queued, regName)}</span>
        ) : (
          <span className="small muted">불러오는 중…</span>
        )}
        <span className="grow" />
        <button className="btn sm" disabled={!canDeploy || !pol} title={canDeploy ? undefined : NEED} onClick={() => setPolicy('1')}>
          설정 바꾸기
        </button>
      </div>
      <Card
        title={`빌드 컨텍스트 (${rows.length})`}
        actions={
          <Menu
            label="종류로 거르기"
            align="right"
            items={(Object.keys(FILTER) as Filter[]).map((k) => ({ label: FILTER[k], hint: k === filter ? '고름' : undefined, onSelect: () => setFilter(k) }))}
            button={`종류: ${FILTER[filter].replace(/^\S+ /, '')} ▾`}
          />
        }
        flush
      >
        <Load q={ctxQ} what="빌드 컨텍스트를 불러오지 못했습니다">
          {() =>
            !rows.length ? (
              <Empty title="빌드 컨텍스트가 없습니다" action={<BuildNewMenu />}>
                Dockerfile을 올리거나, Git에서 가져오거나, 직접 작성해 시작하세요.
              </Empty>
            ) : !shown.length ? (
              <Empty
                kind="filtered"
                title={`${FILTER[filter]}에 맞는 컨텍스트가 없습니다`}
                action={
                  <button className="btn sm" onClick={() => setFilter('all')}>
                    전체 보기
                  </button>
                }
              />
            ) : (
              <table className="tbl">
                <thead>
                  <tr>
                    <th>이름</th>
                    <th>종류</th>
                    <th>소스</th>
                    <th>올릴 이미지</th>
                    <th>마지막 빌드</th>
                    <th aria-label="동작" />
                  </tr>
                </thead>
                <tbody>
                  {shown.map((c) => {
                    const lb = c.lastBuild;
                    return (
                      <tr key={c.id} className={`clickable${c.id === cur?.id ? ' selected' : ''}`} onClick={() => setSel(c.id)}>
                        <td>
                          <b>{c.id}</b>
                        </td>
                        <td className="small">
                          {KIND[c.kind][0]} {KIND[c.kind][1]}
                        </td>
                        <td className="mono small">{source(c)}</td>
                        <td className="mono small">{c.repository}</td>
                        <td className="small">
                          <LastBuild b={lb} />
                        </td>
                        <td onClick={(e) => e.stopPropagation()} style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
                          {live(lb) ? (
                            <button className="btn sm" disabled={!canDeploy || lb!.cancel} title={!canDeploy ? NEED : lb!.cancel ? '취소를 요청했습니다' : undefined} onClick={() => setCancel(lb)}>
                              취소
                            </button>
                          ) : (
                            <button className="btn sm" disabled={!!blockReason || !c.version} title={blockReason ?? (c.version ? undefined : '아직 저장한 버전이 없습니다')} onClick={() => setRebuild(c)}>
                              ↻ 다시 빌드
                            </button>
                          )}{' '}
                          <Menu label={`${c.id} 메뉴`} items={menu(c)} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )
          }
        </Load>
        <div className="small muted" style={{ padding: '10px 14px' }}>
          다시 빌드: Git은 지금 브랜치의 최신 커밋을 받아서, 업로드·직접 작성은 저장된 마지막 버전 그대로 빌드합니다. 성공하면 태그(v{'{version}'} · main-{'{commit}'} 등)로 저장소에 올리고 이미지 목록에 바로
          나옵니다. 같은 컨텍스트가 이미 빌드 중이면 버튼이 '취소'로 바뀝니다.
        </div>
      </Card>
      <MutationError error={autoM.error} />
      {cur && <ContextDetail key={`${cur.id}/${cur.revision}`} c={cur} blockReason={blockReason} onRebuild={() => setRebuild(cur)} onClone={() => setClone(cur)} />}
      <div ref={histRef}>
        <Card
          title="빌드 기록"
          actions={
            <label className="small row" style={{ gap: 6, alignItems: 'center' }}>
              <input type="checkbox" checked={histOnly} disabled={!cur} onChange={(e) => setHistOnly(e.target.checked)} />
              {cur ? `${cur.id}의 기록만` : '컨텍스트를 고르면 그 기록만'}
            </label>
          }
          flush
        >
          <Load q={buildsQ} what="빌드 기록을 불러오지 못했습니다">
            {() =>
              !hist.length ? (
                <Empty title="빌드 기록이 없습니다">다시 빌드를 누르면 여기에 남습니다.</Empty>
              ) : (
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>번호</th>
                      <th>컨텍스트</th>
                      <th>소스</th>
                      <th>시작</th>
                      <th>걸린 시간</th>
                      <th>상태</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hist.map((b) => {
                      const [label, tone] = buildStatus(b);
                      return (
                        <tr key={b.id} className={`clickable${b.id === log ? ' selected' : ''}`} onClick={() => setLog(b.id)}>
                          <td className="mono">{b.label}</td>
                          <td>{b.context}</td>
                          <td className="mono small">
                            {srcOf(
                              b,
                              rows.find((c) => c.id === b.context),
                            )}
                          </td>
                          <td className="small">{agoMs(b.createdAt)}</td>
                          <td className="small">{b.closedAt ? dur(b.createdAt, b.closedAt) : '—'}</td>
                          <td>
                            <Badge tone={tone}>{label}</Badge>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )
            }
          </Load>
        </Card>
      </div>
      {policy && pol && <PolicyDialog tenant={tenant} p={pol} focusCache={policy === 'cache'} onClose={() => setPolicy()} onDone={() => (polQ.refresh(), cacheQ.refresh())} />}
      {rebuild && <RebuildDialog tenant={tenant} c={rebuild} onClose={() => setRebuild(undefined)} onDone={(id) => (refreshAll(), setLog(id))} />}
      {cancel && <CancelDialog tenant={tenant} b={cancel} onClose={() => setCancel(undefined)} onDone={refreshAll} />}
      {clone && <CloneDialog tenant={tenant} c={clone} taken={rows.map((r) => r.id)} onClose={() => setClone(undefined)} onDone={(id) => (ctxQ.refresh(), setSel(id))} />}
      {del && <DeleteFlow tenant={tenant} c={del} jobs={allBuilds.filter((b) => b.context === del.id)} onClose={() => setDel(undefined)} onChanged={refreshAll} onDone={() => (setSel(undefined), refreshAll())} />}
      {log && (
        <LogDrawer
          tenant={tenant}
          id={log}
          b={allBuilds.find((b) => b.id === log)}
          c={rows.find((c) => c.id === allBuilds.find((b) => b.id === log)?.context)}
          onCancel={(b) => setCancel(b)}
          onRebuild={(c) => setRebuild(c)}
          onClose={() => setLog(undefined)}
          onEnded={refreshAll}
        />
      )}
    </>
  );
}

function LastBuild({ b }: { b?: Build }) {
  if (!b) return <span className="muted">빌드한 적 없음</span>;
  if (live(b)) return <Badge tone="pr">{b.cancel ? '취소 중' : b.phase === 'queued' ? '대기 중' : `빌드 중 · ${elapsed(b.createdAt)}`}</Badge>;
  if (b.phase === 'failed')
    return (
      <Badge tone="er">
        {b.label} 실패 · {CODE[b.result?.code ?? '']?.replace(' 미신뢰', '') ?? b.result?.code}
      </Badge>
    );
  if (b.phase === 'unknown') return <Badge tone="wa">{b.label} 결과 불명</Badge>;
  if (b.phase === 'cancelled') return <>{b.label} 취소됨</>;
  return (
    <>
      {b.label} · {agoMs(b.closedAt ?? b.createdAt)}
    </>
  );
}

export const gitBody = (c: BuildContext) =>
  c.git && { repository: c.git.repository, ref: c.git.ref, path: c.git.path || undefined, credentialProfile: c.git.credentialProfile || undefined, automatic: !!c.git.automatic };
/** PUT 본문의 context: 행 그대로(이름 = ID, 서버는 저장 뒤 못 바꿈) */
export const ctxBody = (c: BuildContext) => ({
  kind: c.kind,
  node: c.node,
  git: gitBody(c),
  dockerfile: c.dockerfile,
  args: c.args,
  secrets: c.secrets,
  repository: c.repository,
  tags: c.tags,
  platforms: c.platforms,
});

function ContextDetail({ c, blockReason, onRebuild, onClone }: { c: BuildContext; blockReason?: string; onRebuild: () => void; onClone: () => void }) {
  const { tenant, canDeploy } = useTenantRole();
  const navigate = useNavigate();
  const v = c.versions[0];
  const treeQ = usePoll((s) => (v ? buildTree(tenant, c.id, v.number, s) : Promise.resolve(undefined)), [tenant, c.id, v?.number], 0);
  const dfQ = usePoll((s) => (v ? buildFileText(tenant, c.id, `${c.git?.path ? `${c.git.path.replace(/\/$/, '')}/` : ''}${c.dockerfile}`, v.number, s) : Promise.resolve(undefined)), [tenant, c.id, v?.number, c.dockerfile], 0);
  const lb = c.lastBuild?.phase === 'succeeded' ? c.lastBuild : undefined;
  const usesQ = usePoll(() => (lb?.result?.image ? imageUsage(tenant, [lb.result.image]) : Promise.resolve(undefined)), [tenant, lb?.result?.image], 0);
  const use = usesQ.data?.[0];
  const users = use ? [...new Set(use.rows.map(useRowLabel))] : [];
  const lbTags = resolveTags(c, verOf(c, lb?.version ?? 0));
  return (
    <Card
      title={
        <h2>
          {c.id}{' '}
          <span className="small muted">
            {KIND[c.kind][0]} {KIND[c.kind][1]}
          </span>
        </h2>
      }
    >
      <KV
        items={[
          ['소스', c.kind === 'git' && c.git ? `${host(c.git.repository)} · ${c.git.ref} · ${dfPath(c)}` : source(c)],
          ['올릴 이미지', <code key="i">{tagText(c)}</code>],
          ['빌드 인자', argText(c)],
          ['빌드 비밀값', c.secrets.map((s) => `${s.id} (보관함)`).join(', ') || '없음'],
          ['빌드 서버', `${c.node} · ${c.root}`],
          ...(c.kind === 'git' ? [['자동 빌드', c.git?.automatic ? '새 커밋 때 (1분마다 확인)' : '끔'] as [string, string]] : []),
        ]}
      />
      <Load q={treeQ} what="컨텍스트 파일을 불러오지 못했습니다" rows={3}>
        {(t) =>
          !t ? (
            <span className="small muted">{c.kind === 'upload' ? "아직 올린 버전이 없습니다. '편집'에서 zip을 올리세요." : c.kind === 'draft' ? "아직 저장한 버전이 없습니다. '편집'에서 초안을 저장하세요." : '아직 받은 커밋이 없습니다.'}</span>
          ) : (
            <div className="grid" style={{ gridTemplateColumns: 'minmax(0,1fr) minmax(0,1.6fr)', gap: 12 }}>
              <pre className="code small" style={{ margin: 0 }}>
                {`${c.id} · ${c.kind === 'git' && c.git && v?.commit ? `${host(c.git.repository)}@${v.commit}` : `v${t.version}`}\n`}
                {treeLines(t.files.map((f) => f.path)).join('\n')}
              </pre>
              <div className="col" style={{ gap: 6 }}>
                {dfQ.error ? (
                  <span className="small muted">Dockerfile 내용을 읽지 못했습니다{dfQ.error instanceof ApiError && dfQ.error.status === 413 ? ' (읽을 수 있는 크기보다 큼)' : ''}.</span>
                ) : (
                  <CodeView text={dfQ.data ?? '…'} />
                )}
              </div>
            </div>
          )
        }
      </Load>
      <div className="row" style={{ gap: 8, justifyContent: 'flex-end' }}>
        <button className="btn" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => navigate(`/images/builds/${encodeURIComponent(c.id)}/edit`)}>
          편집
        </button>
        <button className="btn" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={onClone}>
          복제
        </button>
        <button
          className="btn primary"
          disabled={!!blockReason || live(c.lastBuild) || !c.version}
          title={live(c.lastBuild) ? '이미 빌드 중입니다' : (blockReason ?? (c.version ? undefined : '아직 저장한 버전이 없습니다'))}
          onClick={onRebuild}
        >
          ↻ 다시 빌드하고 올리기
        </button>
      </div>
      {lb && (
        <KV
          items={[
            ['마지막 결과', <code key="r">{`${c.repository}:${lbTags[0] ?? ''} · ${shortDigest(lb.result?.image)}`}</code>],
            ['쓰는 앱', users.length ? users.join(', ') : usesQ.loading ? '확인 중…' : '없음'],
          ]}
        />
      )}
      <span className="small muted">
        파일은 읽기 전용으로 보입니다. 업로드 컨텍스트는 '편집'에서 새 zip을 올리면 버전이 늘고(v1, v2…), 직접 작성은 편집기로 열립니다. 지우기 전에 남은 버전과 그 버전을 쓴 빌드 기록을 먼저 정리합니다(⋯ › 지우기에서 안내).
      </span>
    </Card>
  );
}

/** 경로 목록 → 트리 줄. 폴더에 파일이 많으면 접는다 */
export function treeLines(paths: string[], fold = 6): string[] {
  type Node = { name: string; kids: Map<string, Node>; file: boolean; count: number };
  const root: Node = { name: '', kids: new Map(), file: false, count: 0 };
  for (const p of [...paths].sort()) {
    let n = root;
    p.split('/').forEach((seg, i, all) => {
      n.count++;
      if (!n.kids.has(seg)) n.kids.set(seg, { name: seg, kids: new Map(), file: i === all.length - 1, count: 0 });
      n = n.kids.get(seg)!;
    });
  }
  const out: string[] = [];
  const walk = (n: Node, pre: string) => {
    const kids = [...n.kids.values()];
    kids.forEach((k, i) => {
      const last = i === kids.length - 1;
      if (k.file) out.push(`${pre}${last ? '└─' : '├─'} ${k.name}`);
      else if (k.count > fold) out.push(`${pre}${last ? '└─' : '├─'} ${k.name}/ (${k.count}개 파일)`);
      else {
        out.push(`${pre}${last ? '└─' : '├─'} ${k.name}/`);
        walk(k, pre + (last ? '   ' : '│  '));
      }
    });
  };
  walk(root, '');
  return out;
}

const GiB = 1 << 30;
const PLATFORMS = ['linux/amd64', 'linux/arm64', 'linux/arm/v7'];
const gib = (b: number, d: number) => String(+((b || d * GiB) / GiB).toFixed(1));
const POLICY_ERR: Record<string, string> = {
  'root-unknown': '고른 저장 경로를 이 작업 공간에서 쓸 수 없습니다. 목록을 새로 읽고 다시 고르세요.',
  'builder-digest': '빌더 이미지의 다이제스트를 찾지 못했습니다. 이름과 태그를 확인하거나 @sha256:… 로 적으세요.',
  invalid: '범위를 벗어난 값이 있습니다. 동시 빌드 1~16, 한 빌드 1분~24시간, 정리 % 1~100을 확인하세요.',
};

export function PolicyDialog({ tenant, p, focusCache, onClose, onDone }: { tenant: string; p: BuildPolicy; focusCache?: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const m = useMutation();
  const rootsQ = usePoll((s) => tenantStorage(tenant, s), [tenant], 0);
  const regQ = usePoll((s) => registries(tenant, s), [tenant], 0);
  const [f, setF] = useState(() => ({
    nodes: p.nodes.map((n) => ({ node: n.node, root: n.root.id })),
    concurrency: String(p.concurrency || 1),
    minutes: String(Math.round((p.seconds || 1800) / 60)),
    cpus: String(+((p.cpuMillis || 2000) / 1000).toFixed(2)),
    mem: gib(p.memoryBytes, 4),
    workspace: gib(p.workspaceBytes, 8),
    cache: gib(p.cacheBytes, 20),
    high: String(p.cleanup.highWaterPercent || 80),
    unused: String(p.cleanup.unusedDays ?? 14),
    registry: p.registry || 'builtin',
    platforms: p.platforms.length ? p.platforms : ['linux/amd64'],
    builder: p.builderImage,
  }));
  const [expected] = useState(p.revision);
  const cacheRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (focusCache) cacheRef.current?.focus();
  }, [focusCache]);
  const set = (x: Partial<typeof f>) => setF((v) => ({ ...v, ...x }));
  const roots = (rootsQ.data?.items ?? []).filter(usableRoot);
  const byNode = (n: string) => roots.filter((r) => r.node === n);
  const kept = (n: string) => p.nodes.find((x) => x.node === n);
  const freeNodes = [...new Set(roots.map((r) => r.node))].filter((n) => !f.nodes.some((x) => x.node === n));
  const errs: string[] = [];
  if (!f.nodes.length) errs.push('빌드 서버를 하나 이상 고르세요');
  if (f.nodes.some((n) => !n.root)) errs.push('서버마다 저장 경로를 고르세요');
  if (!(Number(f.concurrency) >= 1 && Number(f.concurrency) <= 16)) errs.push('동시 빌드는 1~16');
  if (!(Number(f.minutes) >= 1 && Number(f.minutes) <= 1440)) errs.push('한 빌드 최대 시간은 1분~24시간');
  if (!(Number(f.cpus) > 0) || !(Number(f.mem) > 0) || !(Number(f.workspace) > 0) || !(Number(f.cache) > 0)) errs.push('CPU·메모리·빌드 입력 예산·캐시 정리 목표는 0보다 커야 합니다');
  if (!(Number(f.high) >= 1 && Number(f.high) <= 100)) errs.push('정리 %는 1~100');
  if (!(Number(f.unused) >= 0)) errs.push('며칠은 0 이상');
  if (!f.platforms.length) errs.push('허용 플랫폼을 하나 이상');
  if (!f.builder.trim()) errs.push('빌더 이미지를 적으세요');
  const save = async () => {
    const o = await sendOnce(
      m,
      buildPath(tenant, '/build-policy'),
      {
        policy: {
          nodes: f.nodes,
          concurrency: Number(f.concurrency),
          seconds: Math.round(Number(f.minutes) * 60),
          cpuMillis: Math.round(Number(f.cpus) * 1000),
          memoryBytes: Math.round(Number(f.mem) * GiB),
          workspaceBytes: Math.round(Number(f.workspace) * GiB),
          cacheBytes: Math.round(Number(f.cache) * GiB),
          registry: f.registry,
          platforms: f.platforms,
          ...(f.builder.trim() !== p.builderImage ? { builderImage: f.builder.trim() } : {}),
          cleanup: { highWaterPercent: Number(f.high), unusedDays: Number(f.unused) },
        },
        ...(expected ? { expected } : {}),
      },
      'PUT',
    );
    if (o?.state === 'applied') {
      toast('빌드 설정을 저장했습니다.');
      onDone();
    }
  };
  const done = m.op?.state === 'applied';
  const locked = !!m.op || m.error !== undefined;
  const errCode = m.error instanceof ApiError ? m.error.code : '';
  return (
    <Dialog
      title="빌드 설정"
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
            <button className="btn primary" disabled={m.busy || errs.length > 0} onClick={() => void save()}>
              {m.busy ? '저장하는 중…' : uncertain(m) && !POLICY_ERR[errCode] ? '같은 작업으로 다시 보내기' : '저장'}
            </button>
          </>
        )
      }
    >
      <fieldset disabled={locked && !m.op?.state.match(/failed|rejected/) && !POLICY_ERR[errCode]} style={{ border: 0, padding: 0, margin: 0 }} className="col">
        <b className="small">빌드 서버와 저장 경로</b>
        <table className="tbl">
          <thead>
            <tr>
              <th>서버</th>
              <th>저장 경로 (서버마다 하나)</th>
              <th aria-label="빼기" />
            </tr>
          </thead>
          <tbody>
            {f.nodes.map((n, i) => {
              const opts = byNode(n.node);
              const k = kept(n.node);
              return (
                <tr key={n.node}>
                  <td className="mono">{n.node}</td>
                  <td>
                    <select aria-label={`${n.node} 저장 경로`} value={n.root} onChange={(e) => set({ nodes: f.nodes.map((x, j) => (j === i ? { ...x, root: e.target.value } : x)) })}>
                      {!n.root && <option value="">고르세요</option>}
                      {k && !opts.some((r) => r.name === k.root.id) && <option value={k.root.id}>{k.root.id} (지금 설정)</option>}
                      {opts.map((r) => (
                        <option key={r.name} value={r.name}>
                          {r.name}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button type="button" className="btn sm ghost" aria-label={`${n.node} 빼기`} onClick={() => set({ nodes: f.nodes.filter((_, j) => j !== i) })}>
                      ✕
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div className="row small" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <Menu
            label="서버 추가"
            items={
              freeNodes.length
                ? freeNodes.map((n) => ({ label: n, hint: byNode(n).map((r) => r.name).join(', '), onSelect: () => set({ nodes: [...f.nodes, { node: n, root: byNode(n)[0]?.name ?? '' }] }) }))
                : [{ label: rootsQ.error ? '저장 경로 목록을 읽지 못했습니다' : '더 고를 서버가 없습니다', disabledReason: '이 작업 공간에 허용된 저장 경로가 있는 서버만 고릅니다' }]
            }
            className="btn sm"
            button="＋ 서버 추가"
          />
          <span className="muted">이 작업 공간에 허용된 저장 경로만 고릅니다</span>
        </div>
        <div className="grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0,1fr))', gap: 10 }}>
          <Field label="동시 빌드">
            <input type="number" min={1} max={16} value={f.concurrency} onChange={(e) => set({ concurrency: e.target.value })} />
          </Field>
          <Field label="한 빌드 최대 (분)">
            <input type="number" min={1} value={f.minutes} onChange={(e) => set({ minutes: e.target.value })} />
          </Field>
          <Field label="CPU">
            <input type="number" min={0.5} step={0.5} value={f.cpus} onChange={(e) => set({ cpus: e.target.value })} />
          </Field>
          <Field label="메모리 (GiB)">
            <input type="number" min={0.5} step={0.5} value={f.mem} onChange={(e) => set({ mem: e.target.value })} />
          </Field>
          <Field label="빌드 입력 예산 (GiB)" hint="컨텍스트를 풀거나 빌드 입력을 받을 때 넘으면 거부합니다. 디스크 쓰기 강제 상한은 아닙니다">
            <input type="number" min={1} value={f.workspace} onChange={(e) => set({ workspace: e.target.value })} />
          </Field>
          <Field label="캐시 정리 목표 (GiB)" hint="강제 상한이 아닙니다. 넘으면 자동 정리가 오래 안 쓴 것부터 지웁니다">
            <input ref={cacheRef} type="number" min={1} value={f.cache} onChange={(e) => set({ cache: e.target.value })} />
          </Field>
          <Field label="정리 목표의 몇 %를 넘으면 정리">
            <input type="number" min={1} max={100} value={f.high} onChange={(e) => set({ high: e.target.value })} />
          </Field>
          <Field label="안 쓴 지 며칠 지나면 지움">
            <input type="number" min={0} value={f.unused} onChange={(e) => set({ unused: e.target.value })} />
          </Field>
          <Field label="올릴 저장소">
            <select value={f.registry} onChange={(e) => set({ registry: e.target.value })}>
              {!(regQ.data?.items ?? []).some((r) => r.id === f.registry) && <option value={f.registry}>{f.registry === 'builtin' ? '내장 저장소' : f.registry}</option>}
              {(regQ.data?.items ?? []).map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="허용 플랫폼" hint="컨텍스트는 이 안에서 대상 플랫폼을 고릅니다">
            <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
              {f.platforms.map((x) => (
                <span key={x} className="chip mono">
                  {x}{' '}
                  <button type="button" className="chip-x" aria-label={`${x} 빼기`} onClick={() => set({ platforms: f.platforms.filter((y) => y !== x) })}>
                    ✕
                  </button>
                </span>
              ))}
              {PLATFORMS.filter((x) => !f.platforms.includes(x)).map((x) => (
                <button key={x} type="button" className="btn sm ghost mono" onClick={() => set({ platforms: [...f.platforms, x] })}>
                  ＋ {x}
                </button>
              ))}
            </div>
          </Field>
        </div>
        <Field label="빌더 이미지 (다이제스트 고정)" hint="바꾸면 이전 빌더로 만든 캐시는 다시 쓰지 않습니다. 이름:태그로 적으면 저장할 때 다이제스트로 고정합니다">
          <input className="mono" value={f.builder} onChange={(e) => set({ builder: e.target.value })} />
        </Field>
      </fieldset>
      {errs.length > 0 && (
        <div className="small" style={{ color: 'var(--er)' }}>
          {errs[0]}
        </div>
      )}
      {POLICY_ERR[errCode] ? <div className="note er small">{POLICY_ERR[errCode]}</div> : <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

function RebuildDialog({ tenant, c, onClose, onDone }: { tenant: string; c: BuildContext; onClose: () => void; onDone: (id: string) => void }) {
  const toast = useToast();
  const m = useMutation();
  const [snap, setSnap] = useState(() => ({ id: `build-${newOpId()}` }));
  const finish = async () => {
    try {
      const all = (await builds(tenant, c.id)).items;
      const b = all.find((x) => x.id === snap.id);
      const wait = all.filter((x) => x.phase === 'queued').length;
      toast(`◔ ${b?.label ?? '새'} 빌드를 대기열에 넣었습니다${wait ? ` (대기 ${wait})` : ''}.`);
    } catch {
      toast('빌드를 대기열에 넣었습니다.');
    }
    onDone(snap.id);
    onClose();
  };
  const start = async () => {
    const o = await sendOnce(m, contextPath(tenant, c.id, '/build'), { build: snap.id }, 'POST');
    if (o?.state === 'applied') await finish();
  };
  // 승인이 늦어 mydcd가 원본을 거절함(#226): 새 opId·새 빌드 ID로 다시 시작
  const rejected = m.op?.state === 'failed' && m.op.errorCode === 'approval-rejected';
  const restart = async () => {
    const id = `build-${newOpId()}`;
    setSnap({ id });
    m.reset();
    const o = await m.run(contextPath(tenant, c.id, '/build'), { build: id }, 'POST');
    if (o?.state === 'applied') {
      snap.id = id;
      await finish();
    }
  };
  const waiting = m.op?.errorCode === 'approval-required' && m.op.state === 'running';
  const v = c.versions[0];
  const noVersion = m.error instanceof ApiError && m.error.code === 'no-version';
  return (
    <Dialog
      title={`${c.id} 다시 빌드`}
      width={400}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          {rejected ? (
            <button className="btn primary" disabled={m.busy} onClick={() => void restart()}>
              {m.busy ? '보내는 중…' : '↻ 새로 빌드'}
            </button>
          ) : (
            <button className="btn primary" disabled={m.busy || noVersion || waiting} title={waiting ? '아래에서 묶음 비밀번호로 승인하면 이어서 빌드합니다' : undefined} onClick={() => void start()}>
              {m.busy ? '보내는 중…' : uncertain(m) && !noVersion && !waiting ? '같은 작업으로 다시 보내기' : '빌드'}
            </button>
          )}
        </>
      }
    >
      <span>
        {c.kind === 'git'
          ? `${c.git?.ref ?? ''} 브랜치의 최신 커밋을 받아 빌드합니다.`
          : c.kind === 'upload'
            ? `올린 zip v${v?.number ?? ''}을 그대로 다시 빌드합니다.`
            : `저장한 마지막 버전(v${v?.number ?? ''})을 빌드합니다. 저장하지 않은 초안은 들어가지 않습니다.`}
      </span>
      {noVersion ? <div className="note wa small">아직 저장한 버전이 없어 빌드할 수 없습니다. '편집'에서 먼저 저장하세요.</div> : <MutationError error={m.error} />}
      {m.op && !waiting && !rejected && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && void finish())} />}
      {m.op && waiting && <ApprovalPrompt tenant={tenant} op={m.op} kind="build" onOp={(o) => (m.setOp(o), o.state === 'applied' && void finish())} />}
      {rejected && <div className="note er small">승인이 늦어 빌드가 거절됐습니다. 앞서 한 승인의 유효 시간이 그 사이 지났습니다. ‘새로 빌드’로 다시 시작하세요.</div>}
    </Dialog>
  );
}

function CancelDialog({ tenant, b, onClose, onDone }: { tenant: string; b: Build; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const toast = useToast();
  const go = async () => {
    const o = await sendOnce(m, buildPath(tenant, `/builds/${encodeURIComponent(b.id)}/cancel`), {}, 'POST');
    if (o?.state === 'applied') {
      toast(`${b.label} 취소를 요청했습니다.`);
      onDone();
      onClose();
    }
  };
  return (
    <Dialog
      title={`${b.label} 빌드를 취소할까요?`}
      width={400}
      danger
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger" disabled={m.busy} onClick={() => void go()}>
            {m.busy ? '보내는 중…' : uncertain(m) ? '같은 작업으로 다시 보내기' : '빌드 취소'}
          </button>
        </>
      }
    >
      <span>취소를 요청합니다. 서버가 빌드를 멈추고 정리를 확인하면 '취소됨'으로 바뀌고, 그때까지는 '취소 중'으로 보입니다. 이미 올리기가 끝났다면 성공으로 남을 수 있습니다. 캐시는 남습니다.</span>
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}

function CloneDialog({ tenant, c, taken, onClose, onDone }: { tenant: string; c: BuildContext; taken: string[]; onClose: () => void; onDone: (id: string) => void }) {
  const toast = useToast();
  const m = useMutation();
  const [name, setName] = useState(`${c.id}-copy`);
  const [repo, setRepo] = useState(`${c.repository}-copy`);
  const [withArgs, setWithArgs] = useState(true);
  const [frozen] = useState(taken);
  const bad = !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(name)
    ? '소문자·숫자·- 로 63자까지'
    : frozen.includes(name)
      ? '이미 있는 이름입니다'
      : !repo.startsWith(`${tenant}/`)
        ? `올릴 이미지는 ${tenant}/ 로 시작해야 합니다`
        : undefined;
  const go = async () => {
    const o = await sendOnce(m, contextPath(tenant, name), { context: { ...ctxBody(c), repository: repo, args: withArgs ? c.args : {}, secrets: withArgs ? c.secrets : [] }, expected: 0 }, 'PUT');
    if (o?.state === 'applied') {
      toast(`${c.id}${eulReul(c.id)} ${name}(으)로 복제했습니다.`);
      onDone(name);
      onClose();
    }
  };
  return (
    <Dialog
      title={`${c.id} 복제`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={m.busy || !!bad} onClick={() => void go()}>
            {m.busy ? '보내는 중…' : uncertain(m) ? '같은 작업으로 다시 보내기' : '복제'}
          </button>
        </>
      }
    >
      <fieldset disabled={!!m.op || m.error !== undefined} style={{ border: 0, padding: 0, margin: 0 }} className="col">
        <Field label="새 이름" error={bad && !bad.startsWith('올릴') ? bad : undefined}>
          <input value={name} onChange={(e) => setName(e.target.value.trim())} />
        </Field>
        <Field label="올릴 이미지" error={bad?.startsWith('올릴') ? bad : undefined}>
          <input value={repo} onChange={(e) => setRepo(e.target.value.trim())} className="mono" />
        </Field>
        <label className="row small" style={{ gap: 6, alignItems: 'center' }}>
          <input type="checkbox" checked={withArgs} onChange={(e) => setWithArgs(e.target.checked)} /> 빌드 인자·비밀값도 복사
        </label>
      </fieldset>
      <span className="small muted">
        빌드 서버는 {c.node}({c.root}) 그대로입니다.{' '}
        {c.kind === 'git' ? '같은 저장소의 최신 커밋을 받아 시작합니다.' : c.kind === 'upload' ? '설정만 복사합니다. 새 컨텍스트에는 zip을 다시 올리세요.' : '설정만 복사합니다. 새 컨텍스트는 빈 초안으로 시작합니다.'}
      </span>
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}

// ── 지우기 흐름 (v142): 남은 버전 → 막는 빌드 기록 → 버전 → 컨텍스트(이름 확인) ──

/** 변경 하나를 보내고 결과가 정해질 때까지 잠깐 묻는다. 결과를 모르면 같은 opId로 다시 보낼 수 있게 남긴다 */
export async function sendAndWait(path: string, body: Record<string, unknown>, opId: string): Promise<OpView> {
  const r = await api.post<{ op: DOp }>(path, { ...body, opId });
  let op = toOp(r.op);
  for (let i = 0; i < 30 && (op.state === 'pending' || op.state === 'running'); i++) {
    await new Promise((res) => window.setTimeout(res, 1000));
    op = toOp((await api.get<{ op: DOp }>(`/ops/${encodeURIComponent(op.id)}`)).op);
  }
  return op;
}
type Item = { key: string; label: string; path: string; op?: OpView; error?: unknown };
type Group = { title: string; items: Item[] };

function DeleteFlow({ tenant, c, jobs, onClose, onChanged, onDone }: { tenant: string; c: BuildContext; jobs: Build[]; onClose: () => void; onChanged: () => void; onDone: () => void }) {
  const [mode, setMode] = useState<'blocked' | 'all' | 'one'>(c.versions.length ? 'blocked' : 'one');
  const [one, setOne] = useState<Group>();
  const blockers = (v: BuildVersion) => jobs.filter((b) => b.versionId === v.id);
  const jobItem = (b: Build): Item => ({ key: `job/${b.id}`, label: b.label, path: buildPath(tenant, `/builds/${encodeURIComponent(b.id)}/delete`) });
  const verItem = (v: BuildVersion): Item => ({ key: `ver/${v.number}`, label: `v${v.number}`, path: contextPath(tenant, c.id, `/versions/${v.number}/delete`) });
  if (mode === 'one' && !c.versions.length) return <DeleteContextDialog tenant={tenant} c={c} onClose={onClose} onDone={onDone} />;
  if (mode === 'all')
    return (
      <CleanAllDialog
        tenant={tenant}
        c={c}
        groups={[
          { title: '빌드 기록', items: c.versions.flatMap((v) => blockers(v)).map(jobItem) },
          { title: '버전', items: [...c.versions].reverse().map(verItem) },
        ]}
        onClose={onClose}
        onChanged={onChanged}
        onDone={onDone}
      />
    );
  if (one)
    return (
      <CleanAllDialog
        tenant={tenant}
        c={c}
        groups={[one]}
        partial
        onClose={() => setOne(undefined)}
        onChanged={onChanged}
        onDone={() => {
          setOne(undefined);
          onChanged();
        }}
      />
    );
  return (
    <Dialog
      title={`${c.id}${eulReul(c.id).replace('를', '을')} 아직 지울 수 없습니다`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            닫기
          </button>
          <button className="btn danger" disabled={c.versions.some((v) => blockers(v).some(live))} title={c.versions.some((v) => blockers(v).some(live)) ? '진행 중인 빌드가 끝나야 정리할 수 있습니다' : undefined} onClick={() => setMode('all')}>
            기록·버전 모두 정리…
          </button>
        </>
      }
    >
      <span>먼저 아래를 정리해야 합니다. 이미 만든 이미지는 이미지 목록에 남습니다.</span>
      <table className="tbl">
        <thead>
          <tr>
            <th>버전</th>
            <th>막는 것</th>
            <th aria-label="동작" />
          </tr>
        </thead>
        <tbody>
          {c.versions.map((v) => {
            const bs = blockers(v);
            const running = bs.some(live);
            return (
              <tr key={v.number}>
                <td className="mono">v{v.number}</td>
                <td className="small">{bs.length ? `빌드 기록 ${bs.map((b) => b.label).join(' · ')} (${running ? '진행 중' : '끝남'})` : '없음'}</td>
                <td style={{ textAlign: 'right' }}>
                  {bs.length ? (
                    <button className="btn sm" disabled={running} title={running ? '진행 중인 빌드가 끝나야 정리할 수 있습니다' : undefined} onClick={() => setOne({ title: '빌드 기록', items: bs.map(jobItem) })}>
                      기록 지우기…
                    </button>
                  ) : (
                    <button className="btn sm" onClick={() => setOne({ title: '버전', items: [verItem(v)] })}>
                      버전 지우기
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <span className="small muted">진행 중인 빌드가 쓰는 버전은 빌드가 끝나야 정리할 수 있습니다. 버전을 지워도 디스크 공간은 서버가 정리를 마친 뒤에 돌아옵니다.</span>
    </Dialog>
  );
}

/** 묶음마다 차례로 서명해 보낸다. 막히면 멈추고 남은 것을 보여 준다. partial이 아니면 마지막에 이름 확인 뒤 컨텍스트를 지운다 */
function CleanAllDialog({ tenant, c, groups: initial, partial, onClose, onChanged, onDone }: { tenant: string; c: BuildContext; groups: Group[]; partial?: boolean; onClose: () => void; onChanged: () => void; onDone: () => void }) {
  const toast = useToast();
  const [groups, setGroups] = useState(initial);
  const [ctxStep, setCtxStep] = useState<Item>({ key: 'ctx', label: c.id, path: contextPath(tenant, c.id, '/delete') });
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const ids = useRef<Record<string, string>>({});
  const okItems = groups.every((g) => g.items.every((i) => i.op?.state === 'applied'));
  const finished = okItems && (partial || ctxStep.op?.state === 'applied');
  const run1 = async (it: Item, body: Record<string, unknown>): Promise<Item> => {
    const id = (ids.current[it.key] ??= newOpId());
    try {
      const op = await sendAndWait(it.path, body, id);
      if (op.state !== 'applied' && op.state !== 'unknown') delete ids.current[it.key];
      return { ...it, op, error: undefined };
    } catch (e) {
      return { ...it, error: e };
    }
  };
  const run = async () => {
    setBusy(true);
    const next = groups.map((g) => ({ ...g, items: [...g.items] }));
    let stopped = false;
    for (const g of next) {
      for (let i = 0; i < g.items.length && !stopped; i++) {
        if (g.items[i].op?.state === 'applied') continue;
        g.items[i] = await run1(g.items[i], {});
        setGroups(next.map((x) => ({ ...x })));
        if (g.items[i].op?.state !== 'applied') stopped = true;
      }
      if (stopped) break;
    }
    onChanged();
    if (!stopped && !partial && typed === c.id && ctxStep.op?.state !== 'applied') {
      const r = await run1(ctxStep, { expected: c.revision });
      setCtxStep(r);
      if (r.op?.state === 'applied') {
        toast(`${c.id} 빌드 컨텍스트를 지웠습니다.`);
        onDone();
      }
    } else if (!stopped && partial) onDone();
    setBusy(false);
  };
  const state = (items: Item[]) =>
    items.every((i) => i.op?.state === 'applied') ? (
      <Badge tone="ok">끝남</Badge>
    ) : items.some((i) => i.error !== undefined || (i.op && i.op.state !== 'applied')) ? (
      (() => {
        const bad = items.find((i) => i.error !== undefined || (i.op && i.op.state !== 'applied'))!;
        return bad.op ? <OpBadge state={bad.op.state} /> : <Badge tone="er">못 보냄</Badge>;
      })()
    ) : busy && items.some((i) => !i.op) && items.some((i) => i.op) ? (
      <Badge tone="pr">진행 중</Badge>
    ) : busy ? (
      <Badge tone="pr">진행 중</Badge>
    ) : (
      <Badge tone="un">대기</Badge>
    );
  const jobs = groups.find((g) => g.title === '빌드 기록')?.items ?? [];
  const vers = groups.find((g) => g.title === '버전')?.items ?? [];
  const title = partial ? `${groups[0].title} ${groups[0].items.map((i) => i.label).join(' · ')} 지우기` : `${c.id} 기록과 버전을 정리할까요?`;
  return (
    <Dialog
      title={title}
      danger
      onClose={onClose}
      footer={
        finished ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn danger" disabled={busy || (okItems && !partial && typed !== c.id)} onClick={() => void run()}>
              {busy ? '보내는 중…' : groups.some((g) => g.items.some((i) => i.op || i.error)) ? (okItems ? '컨텍스트 지우기' : '남은 것 다시 보내기') : partial ? '지우기' : '정리 시작'}
            </button>
          </>
        )
      }
    >
      <span>
        {partial
          ? `${groups[0].items.map((i) => i.label).join(', ')}${groups[0].title === '빌드 기록' ? '의 기록과 로그를' : '을(를)'} 지웁니다. 하나씩 내 키로 서명해 차례로 보냅니다.`
          : `${jobs.length ? `빌드 기록 ${jobs.length}개(${jobs.map((i) => i.label).join(', ')})를 지운 다음 ` : ''}버전 ${vers.map((i) => i.label).join('·')}${eulReul(vers.at(-1)?.label ?? 'v')} 지웁니다. 하나씩 내 키로 서명해 차례로 보냅니다. 중간에 막히면 거기서 멈추고 남은 것을 보여 줍니다.`}
      </span>
      <div className="col" style={{ gap: 8 }}>
        {groups
          .filter((g) => g.items.length)
          .map((g) => (
            <div key={g.title} className="col" style={{ gap: 4 }}>
              <span className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="grow">
                  {g.title} {g.items.map((i) => i.label).join(' · ')} 지우기
                </span>
                {state(g.items)}
              </span>
              {g.items.map((i) =>
                i.error !== undefined ? (
                  <MutationError key={i.key} error={i.error} />
                ) : i.op && i.op.state !== 'applied' ? (
                  <span key={i.key} className="small muted">
                    {i.label}: {i.op.state === 'failed' ? '서버가 거절했습니다(아직 쓰이고 있거나 그 사이 바뀜). ' : ''}
                    <Link to={`/system/ops?focus=${encodeURIComponent(i.op.id)}`}>작업 기록에서 보기</Link>
                  </span>
                ) : null,
              )}
            </div>
          ))}
        {!partial && (
          <div className="col" style={{ gap: 4 }}>
            <span className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="grow">컨텍스트 지우기 (이름 확인 뒤)</span>
              {ctxStep.op ? <OpBadge state={ctxStep.op.state} /> : <Badge tone="un">대기</Badge>}
            </span>
            <Field
              label={
                <>
                  확인하려면 <code>{c.id}</code>
                  {eulReul(c.id)} 입력하세요
                </>
              }
            >
              <input value={typed} onChange={(e) => setTyped(e.target.value)} disabled={busy || ctxStep.op?.state === 'applied'} />
            </Field>
            {ctxStep.error !== undefined && <MutationError error={ctxStep.error} />}
          </div>
        )}
      </div>
    </Dialog>
  );
}

function DeleteContextDialog({ tenant, c, onClose, onDone }: { tenant: string; c: BuildContext; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const m = useMutation();
  const [typed, setTyped] = useState('');
  const [snap] = useState(c);
  const go = async () => {
    const o = await sendOnce(m, contextPath(tenant, snap.id, '/delete'), { expected: snap.revision }, 'POST');
    if (o?.state === 'applied') {
      toast(`${snap.id} 빌드 컨텍스트를 지웠습니다.`);
      onDone();
      onClose();
    }
  };
  const left = m.error instanceof ApiError && m.error.code === 'versions-left';
  return (
    <Dialog
      title={`${snap.id} 빌드 컨텍스트를 지울까요?`}
      danger
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger" disabled={m.busy || typed !== snap.id || left} onClick={() => void go()}>
            {m.busy ? '보내는 중…' : uncertain(m) && !left ? '같은 작업으로 다시 보내기' : '지우기'}
          </button>
        </>
      }
    >
      <span>설정을 지웁니다. 남은 버전과 빌드 기록은 없습니다. 이미 만든 이미지는 이미지 목록에 남습니다.</span>
      <Field
        label={
          <>
            확인하려면 <code>{snap.id}</code>
            {eulReul(snap.id)} 입력하세요
          </>
        }
      >
        <input value={typed} onChange={(e) => setTyped(e.target.value)} disabled={!!m.op} />
      </Field>
      {left ? <div className="note wa small">그 사이 버전이 생겼습니다({(m.error as ApiError).message}). 창을 닫고 다시 여세요.</div> : <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}

// ── 로그: 바이트 쪽(24 KiB)으로 읽고 줄은 화면이 나눈다 ──

const PAGE = 24 * 1024;
const enc = new TextEncoder();
const dec = new TextDecoder();
interface LogState {
  bytes: Uint8Array;
  /** 들고 있는 바이트가 로그의 어디서 시작하는지. 0이면 처음부터 다 있음 */
  start: number;
  cursor: string;
  last?: BuildLog;
  readAt?: number;
  reading: boolean;
  error?: unknown;
}
const join = (a: Uint8Array, b: Uint8Array) => {
  if (!b.length) return a;
  const x = new Uint8Array(a.length + b.length);
  x.set(a);
  x.set(b, a.length);
  return x;
};
/** 처음엔 끝 한 쪽(tail=1)만 읽고 그 뒤로 이어 읽는다. '새로 읽기'는 마지막 next부터, '앞부분'은 처음부터 start까지 */
function useBuildLog(tenant: string, id: string) {
  const [s, setS] = useState<LogState>({ bytes: new Uint8Array(), start: 0, cursor: '', reading: true });
  const ref = useRef(s);
  ref.current = s;
  const gen = useRef(0);
  const read = async (fresh: boolean) => {
    const my = ++gen.current;
    let bytes = fresh ? new Uint8Array() : ref.current.bytes;
    let start = fresh ? 0 : ref.current.start;
    let cursor = fresh ? 'tail' : ref.current.cursor;
    let last = fresh ? undefined : ref.current.last;
    setS((x) => ({ ...x, reading: true, error: undefined, ...(fresh ? { bytes, start, cursor, last } : {}) }));
    try {
      for (let i = 0; i < 400; i++) {
        const p = await buildLog(tenant, id, cursor || undefined);
        if (my !== gen.current) return;
        if (cursor === 'tail') start = p.offset;
        const chunk = enc.encode(p.text);
        bytes = join(bytes, chunk);
        last = p;
        if (p.next) cursor = p.next;
        else if (cursor === 'tail') cursor = '';
        setS({ bytes, start, cursor, last, readAt: Date.now(), reading: true });
        if (!p.next || !chunk.length || p.offset + chunk.length >= p.total) break;
      }
      setS({ bytes, start, cursor, last, readAt: Date.now(), reading: false });
    } catch (e) {
      if (my === gen.current) setS((x) => ({ ...x, reading: false, error: e }));
    }
  };
  /** 아직 안 읽은 앞부분(0..start)을 처음부터 읽어 앞에 붙인다. 끝나면 전체 바이트 */
  const head = async (): Promise<Uint8Array> => {
    const cur = ref.current;
    if (!cur.start) return cur.bytes;
    const my = ++gen.current;
    setS((x) => ({ ...x, reading: true, error: undefined }));
    try {
      let pre = new Uint8Array();
      let after = '';
      for (let i = 0; i < 400 && pre.length < cur.start; i++) {
        const p = await buildLog(tenant, id, after || undefined);
        if (my !== gen.current) return ref.current.bytes;
        pre = join(pre, enc.encode(p.text));
        if (!p.next || !p.text) break;
        after = p.next;
      }
      const bytes = join(pre.subarray(0, cur.start), ref.current.bytes);
      setS((x) => ({ ...x, bytes, start: 0, reading: false }));
      return bytes;
    } catch (e) {
      if (my === gen.current) setS((x) => ({ ...x, reading: false, error: e }));
      throw e;
    }
  };
  useEffect(() => {
    void read(true);
    return () => void gen.current++;
  }, [tenant, id]); // eslint-disable-line react-hooks/exhaustive-deps
  return { ...s, more: () => void read(false), head };
}

function LogBands({ l }: { l?: BuildLog }) {
  if (!l) return null;
  if (!l.available || !l.total) return <div className="note small">아직 로그가 없습니다</div>;
  return (
    <>
      {l.truncated && <div className="note wa small">잘림 · 로그가 8 MiB를 넘어 그 뒤 출력은 남지 않았습니다. 빌드 결과에는 영향이 없습니다.</div>}
      {l.gap && <div className="note wa small">빈 구간 · 로그가 중간에 끊겼다가 다시 이어졌습니다. 그 사이 출력은 없습니다.</div>}
      {l.unclosed && <div className="note small">끝 기록 없음 · 로그가 정상으로 닫히지 않았습니다. 빌드가 아직 돈다는 뜻은 아닙니다. 상태는 위 배지를 보세요.</div>}
    </>
  );
}

function LogDrawer({
  tenant,
  id,
  b,
  c,
  onClose,
  onCancel,
  onRebuild,
  onEnded,
}: {
  tenant: string;
  id: string;
  b?: Build;
  c?: BuildContext;
  onClose: () => void;
  onCancel: (b: Build) => void;
  onRebuild: (c: BuildContext) => void;
  onEnded: () => void;
}) {
  const { canDeploy } = useTenantRole();
  const toast = useToast();
  const navigate = useNavigate();
  const lg = useBuildLog(tenant, id);
  const [shown, setShown] = useState(PAGE);
  const [showUnknownLog, setShowUnknownLog] = useState(false);
  const [, tick] = useState(0);
  const preRef = useRef<HTMLPreElement>(null);
  const wasLive = useRef(live(b));
  useEffect(() => {
    const t = window.setInterval(() => tick((x) => x + 1), 5000);
    return () => window.clearInterval(t);
  }, []);
  useEffect(() => {
    if (wasLive.current && b && !live(b)) {
      onEnded();
      lg.more();
    }
    wasLive.current = live(b);
  }, [b?.phase]); // eslint-disable-line react-hooks/exhaustive-deps
  const total = lg.bytes.length;
  const from = Math.max(0, total - shown);
  const view = useMemo(() => {
    let t = dec.decode(lg.bytes.subarray(from));
    // 잘라 낸 앞 줄 조각은 뺀다
    if (from > 0 || lg.start > 0) t = t.slice(t.indexOf('\n') + 1);
    return t.replace(/\n$/, '');
  }, [lg.bytes, from, lg.start]);
  const full = async () => dec.decode(await lg.head());
  useEffect(() => {
    const el = preRef.current;
    if (el && from === Math.max(0, total - PAGE)) el.scrollTop = el.scrollHeight;
  }, [view]); // eslint-disable-line react-hooks/exhaustive-deps
  const [label, tone] = b ? buildStatus(b) : ['', 'un' as Tone];
  const v = verOf(c, b?.version ?? 0);
  const tags = resolveTags(c, v);
  const logMenu: MenuItem[] = [
    { label: '로그 복사', onSelect: () => void full().then((t) => navigator.clipboard?.writeText(t)).then(() => toast('로그를 복사했습니다.'), () => toast('로그를 다 읽지 못했습니다.')) },
    {
      label: '로그 내려받기 (.log)',
      onSelect: async () => {
        const text = await full().catch(() => undefined);
        if (text === undefined) return toast('로그를 다 읽지 못했습니다.');
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
        a.download = `${b?.label ?? id}.log`;
        a.click();
        URL.revokeObjectURL(a.href);
      },
    },
    ...(c?.secrets.length ? [{ label: '비밀값 가림 확인됨', hint: `${c.secrets.map((s) => s.id).join(', ')} «가림»`, disabledReason: '빌드 비밀값은 로그에 «가림»으로만 남습니다' }] : []),
  ];
  const sizeLine = lg.last && lg.last.total > 0 && (
    <span className="small muted">
      {total - from < lg.last.total ? `로그 ${fmtBytes(lg.last.total)} 중 끝 ${fmtBytes(total - from)}` : `로그 ${fmtBytes(lg.last.total)}`}
      {lg.reading ? ' · 읽는 중' : lg.readAt ? ` · 마지막으로 읽은 때 ${agoMs(lg.readAt)}` : ''}
    </span>
  );
  const unknown = b?.phase === 'unknown';
  return (
    <Drawer
      title={
        <>
          {b?.label ?? id}
          {c ? ` · ${c.id}` : ''}
        </>
      }
      onClose={onClose}
    >
      {b && (
        <div className="row" style={{ gap: 8, alignItems: 'center' }}>
          <Badge tone={tone}>
            {label}
            {live(b) && b.phase === 'running' ? ` · ${elapsed(b.createdAt, true)}` : ''}
          </Badge>
          <span className="small muted">
            {b.closedAt ? dur(b.createdAt, b.closedAt) : ''} · {b.node} · {b.user}
            {b.automatic ? ' · 자동' : ''}
          </span>
          <span className="grow" />
          <Menu label="로그 메뉴" items={logMenu} />
        </div>
      )}
      {unknown && (
        <>
          <span>빌드 서버와 연결이 끊겨 이 빌드가 어떻게 끝났는지 확인하지 못했습니다. 서버가 원래 실행을 계속 확인하고, 확인되면 성공 · 실패 · 취소로 바뀝니다. 다시 시도하지 않습니다.</span>
          <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <button className="btn" onClick={() => setShowUnknownLog((x) => !x)}>
              로그 보기
            </button>
            <button className="btn" disabled={!canDeploy || !c || !c.version} title={canDeploy ? undefined : NEED} onClick={() => c && onRebuild(c)}>
              ↻ 새로 빌드
            </button>
            <span className="small muted">'새로 빌드'는 새 번호로 시작하고 {b?.label} 기록은 그대로 둡니다.</span>
          </div>
        </>
      )}
      {b?.phase === 'failed' && b.result?.code === 'UNTRUSTED_BASE' && (
        <>
          <b className="small">기본 이미지 신뢰 확인 실패 (UNTRUSTED_BASE)</b>
          <div className="row" style={{ gap: 8 }}>
            <Link className="btn" to="/images/trust">
              신뢰 출처 추가…
            </Link>
            {c && (
              <Link className="btn" to={`/images/builds/${encodeURIComponent(c.id)}/edit`}>
                Dockerfile 고치기
              </Link>
            )}
          </div>
        </>
      )}
      {(!unknown || showUnknownLog) && (
        <>
          <LogBands l={lg.last} />
          {lg.last && lg.last.available && lg.last.total > 0 && (
            <pre ref={preRef} className="code small" style={{ margin: 0, maxHeight: 360, overflow: 'auto', whiteSpace: 'pre-wrap' }}>
              {view}
            </pre>
          )}
          {!lg.last && lg.reading && <span className="small muted">로그를 읽는 중…</span>}
          {lg.error !== undefined && <MutationError error={lg.error} />}
          <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            {sizeLine}
            <span className="grow" />
            {(from > 0 || lg.start > 0) && (
              <button
                className="btn sm"
                disabled={lg.reading}
                onClick={() => (from > 0 ? setShown((x) => x + PAGE) : void lg.head().then(() => setShown((x) => x + PAGE), () => undefined))}
              >
                ‹ 앞부분 더 읽기
              </button>
            )}
            <button className="btn sm" disabled={lg.reading} onClick={() => lg.more()}>
              ↻ 새로 읽기
            </button>
            {b && live(b) && (
              <button className="btn sm danger" disabled={!canDeploy || b.cancel} title={!canDeploy ? NEED : b.cancel ? '취소를 요청했습니다' : undefined} onClick={() => onCancel(b)}>
                빌드 취소
              </button>
            )}
          </div>
        </>
      )}
      {b?.phase === 'succeeded' && b.result?.image && (
        <>
          <span className="small">
            결과{' '}
            <code>
              {b.result.image.split('@')[0]}:{tags[0] ?? ''}
              {tags.length > 1 ? ` (+ ${tags.slice(1).join(', ')})` : ''}
            </code>{' '}
            · {shortDigest(b.result.image)} · {fmtBytes(b.result.bytes)}
          </span>
          <div className="row" style={{ gap: 8 }}>
            <Link className="btn" to="/images">
              이미지 목록에서 보기
            </Link>
            <button className="btn" onClick={() => navigate('/deploy/new', { state: { image: b.result!.image } })}>
              이 이미지로 배포…
            </button>
          </div>
        </>
      )}
      <span className="small muted">
        로그는 페이지로 읽습니다(실시간 스트림이 아님). 빌드 중에는 '새로 읽기'로 이어서 읽고, 로그에 잘림 · 빈 구간 · 끝 기록 없음이 있으면 로그 위에 띠로 알립니다. 비밀값은 «가림»으로 남습니다.
      </span>
    </Drawer>
  );
}
