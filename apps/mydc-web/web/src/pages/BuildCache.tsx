// SPDX-License-Identifier: Apache-2.0

// 이미지 관리 › 빌드 › 빌드 캐시 (UI-87, 캔버스 ImageBuildCache · ImageBuildCacheIx v140).
// 계약: docs/reference/web-api.md '이미지 빌드' 캐시 절. 캐시는 서버·컨텍스트마다 따로(범위 하나 = cache hex).
// 크기는 빌드 도구가 알려 준 '보고된 크기'이고 정리 목표는 강제 상한이 아니다. 무엇을 지울지는 mydcd가 정하고(쓰는 항목은 남김),
// 수락은 끝이 아니라 진행은 cleaning에서 본다.
import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { newOpId } from '../api/client';
import { buildCache, buildCacheEntries, buildPath, builds, nodeDisks, type BuildCacheEntry, type BuildCacheScope, type BuildCleaning } from '../api/endpoints';
import type { OpView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Badge, Card, HelpBox, OpBadge, type Tone } from '../components/ui';
import { Empty, Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { Menu, type MenuItem } from '../components/Menu';
import { MutationError } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { fmtBytes } from '../lib/format';
import { eulReul } from '../lib/josa';
import { usePoll } from '../lib/usePoll';
import { agoMs, NEED, sendAndWait } from './ImageBuilds';

/** BuildKit 기록 종류 → 화면 말 */
const KIND: Record<string, string> = {
  regular: '이미지 단계',
  'exec.cachemount': '캐시 마운트',
  'source.git.checkout': '소스 받기',
  'source.local': '올린 파일',
  internal: '내부',
  frontend: '내부',
  other: '기타',
};
const KIND_SUM: [string, string[]][] = [
  ['이미지 단계', ['regular']],
  ['캐시 마운트', ['exec.cachemount']],
  ['소스 (받은 Git · 올린 파일)', ['source.git.checkout', 'source.local']],
];
const IDLE = 7;
const MAX_PICK = 64;
// 끝난 행에만 code가 있다(OK, 실패는 FAILED·PERMISSION_REVOKED·TIMEOUT). 기다리는 이유는 mydcd가 알려 주지 않는다
const FAIL: Record<string, string> = { FAILED: '빌더가 정리에 실패함', PERMISSION_REVOKED: '보낸 사람의 권한이 사라짐', TIMEOUT: '시간 안에 끝나지 않음' };
export function cleaningState(c: BuildCleaning): [string, Tone, string?] {
  if (c.state === 'queued') return ['기다림', 'pr', '빌더가 맡기를 기다림'];
  if (c.state === 'running') return ['정리 중', 'pr'];
  if (c.state === 'succeeded') return ['끝남', 'ok'];
  if (c.state === 'failed') return ['실패', 'er', (c.code && FAIL[c.code]) ?? c.code];
  return ['결과 모름', 'wa', '결과를 아직 모릅니다'];
}
/** 마지막 관측이 정리 뒤인지(observedKind, PR #218). 없으면 cleanup 유무로 짐작 */
const afterPrune = (u: { observedKind?: string; cleanup?: unknown }) => (u.observedKind !== undefined ? u.observedKind === 'cache-prune' : !!u.cleanup);
const filterText = (c: BuildCleaning) =>
  c.automatic ? '자동' : c.filter.mode === 'all' ? '전체' : c.filter.mode === 'unused' ? `${c.filter.unusedDays ?? 0}일 넘게 안 쓴 것` : `고른 항목 ${c.filter.ids.length}개`;
const active = (c: BuildCleaning) => c.state === 'queued' || c.state === 'running' || c.state === 'unknown';
const REPORTED = '빌드 도구가 알려 준 항목 크기의 합입니다. 여러 항목이 함께 쓰는 부분도 각각 더해져 실제 디스크 사용량보다 클 수 있습니다.';
const short = (id: string) => (id.length > 10 ? `${id.slice(0, 6)}…${id.slice(-2)}` : id);

type Prune = { title: string; text: string; scopes: { s: BuildCacheScope; filter: Record<string, unknown> }[]; typed?: string; action?: string; done: string };

/** 범위 하나의 항목을 모두 읽는다(쪽을 따라감). 고르기·7일 세기에 쓴다 */
async function allEntries(tenant: string, s: BuildCacheScope, signal?: AbortSignal) {
  const out: BuildCacheEntry[] = [];
  let after: string | undefined;
  for (let i = 0; i < 64; i++) {
    const p = await buildCacheEntries(tenant, s.node, s.cache, after, signal);
    out.push(...p.entries);
    if (!p.next) break;
    after = p.next;
  }
  return out;
}

export function BuildCacheTab() {
  const { tenant, canDeploy, isAdmin } = useTenantRole();
  const navigate = useNavigate();
  const toast = useToast();
  const cacheQ = usePoll((s) => buildCache(tenant, s), [tenant]);
  const buildsQ = usePoll((s) => builds(tenant, undefined, s), [tenant], 30_000);
  const busy = (cacheQ.data?.cleaning ?? []).some(active);
  useEffect(() => {
    if (!busy) return;
    const t = window.setInterval(() => cacheQ.refresh(), 3000);
    return () => window.clearInterval(t);
  }, [busy]); // eslint-disable-line react-hooks/exhaustive-deps
  const [node, setNode] = useState('');
  const [sel, setSel] = useState<string>();
  const [prune, setPrune] = useState<Prune>();
  const k = cacheQ.data;
  const nodes = k?.nodes ?? [];
  const cur = node || nodes[0]?.node || '';
  const scopes = (k?.caches ?? []).filter((s) => s.node === cur).sort((a, b) => (b.usage?.reportedBytes ?? -1) - (a.usage?.reportedBytes ?? -1));
  const okScopes = scopes.filter((s) => s.usage?.available);
  const curScope = scopes.find((s) => s.cache === sel) ?? okScopes[0];
  const nodeRow = nodes.find((n) => n.node === cur);
  const jobs = buildsQ.data?.items ?? [];
  const jobLabel = (id: string) => jobs.find((b) => b.id === id)?.label ?? id;
  const runningOn = (s: BuildCacheScope) => jobs.find((b) => b.context === s.context && b.node === s.node && (b.phase === 'running' || b.phase === 'queued'));
  const cleaningOf = (s: BuildCacheScope) => (k?.cleaning ?? []).find((c) => c.cache === s.cache && c.node === s.node && active(c));
  const root = scopes[0]?.root;
  const diskQ = usePoll((s) => (isAdmin && cur ? nodeDisks(cur, s) : Promise.resolve(undefined)), [cur, isAdmin], 60_000);
  const disk = diskQ.data?.find((d) => d.roots.includes(root));
  const diskFree = disk ? (disk.free ?? (disk.total !== undefined && disk.used !== undefined ? disk.total - disk.used : undefined)) : undefined;
  const no = canDeploy ? undefined : NEED;

  const scopeLabel = (s: BuildCacheScope) => `${s.node} · ${s.context}`;
  const askUnused = async (s: BuildCacheScope) => {
    try {
      const es = await allEntries(tenant, s);
      const cut = Date.now() - IDLE * 86400_000;
      const old = es.filter((e) => !e.inUse && (e.lastUsedAt ?? 0) < cut);
      setPrune({
        title: `${IDLE}일 넘게 안 쓴 캐시를 비울까요?`,
        text: `${scopeLabel(s)}에서 ${IDLE}일 넘게 안 쓴 항목을 지웁니다. 관측 기준 ${old.length}개 · 보고된 크기 ${fmtBytes(old.reduce((n, e) => n + e.bytes, 0))}이고, 실제로 늘어나는 디스크 여유는 다를 수 있습니다. 다음 빌드에서 필요하면 다시 받습니다. 결과 이미지는 같습니다.`,
        scopes: [{ s, filter: { mode: 'unused', unusedDays: IDLE } }],
        action: '비우기',
        done: `${scopeLabel(s)}의 ${IDLE}일 넘게 안 쓴 캐시 정리를 맡겼습니다.`,
      });
    } catch {
      toast('캐시 항목을 읽지 못했습니다.');
    }
  };
  const askAll = () => {
    const waiting = okScopes.map(runningOn).filter(Boolean);
    setPrune({
      title: `${cur}의 빌드 캐시를 모두 비울까요?`,
      text: `컨텍스트 ${okScopes.length}곳 · 보고된 크기 ${fmtBytes(nodeRow?.reportedBytes ?? 0)}. 컨텍스트마다 따로 정리하며, ${
        waiting.length ? `${waiting.map((b) => `${b!.context}는 ${b!.label} 빌드가 끝난 뒤에`).join(', ')} 정리합니다(그동안 '빌드 기다림'). ` : ''
      }다음 빌드는 처음부터라 느려집니다.`,
      scopes: okScopes.map((s) => ({ s, filter: { mode: 'all' } })),
      typed: cur,
      action: '전체 비우기',
      done: `${cur}의 캐시 정리를 맡겼습니다.`,
    });
  };
  const askScope = (s: BuildCacheScope) =>
    setPrune({
      title: `${s.context} 캐시를 비울까요?`,
      text: `${scopeLabel(s)} 캐시를 모두 비웁니다 (보고된 크기 ${fmtBytes(s.usage?.reportedBytes ?? 0)}). 캐시는 컨텍스트마다 따로라 다른 컨텍스트에는 영향이 없습니다.`,
      scopes: [{ s, filter: { mode: 'all' } }],
      action: '비우기',
      done: `${s.context} 캐시 정리를 맡겼습니다.`,
    });
  const askEntries = (s: BuildCacheScope, es: BuildCacheEntry[]) =>
    setPrune({
      title: es.length === 1 ? '이 항목을 비울까요?' : `고른 ${es.length}개를 비울까요?`,
      text: `${scopeLabel(s)}의 항목 ${es.length}개 · 보고된 크기 ${fmtBytes(es.reduce((n, e) => n + e.bytes, 0))}. 관측 뒤에 다시 쓰이기 시작한 항목은 서버가 남깁니다.`,
      scopes: [{ s, filter: { mode: 'entries', ids: es.map((e) => e.id) } }],
      action: '비우기',
      done: `항목 ${es.length}개 정리를 맡겼습니다.`,
    });

  return (
    <>
      <HelpBox terms="빌드 캐시 (build cache) · 이미지 단계 (layer) · 캐시 마운트 (cache mount) · 자동 정리 (prune policy)">
        <b>이 화면은</b> 빌드 서버가 다음 빌드를 빠르게 하려고 남겨 둔 <b>빌드 캐시</b>를 보고 비웁니다. 캐시를 지워도 이미지 결과는 같고, 다음 빌드가 처음부터 다시 받고 실행하느라 느려질 뿐입니다.
        저장소에 올린 이미지는 지워지지 않습니다.
      </HelpBox>
      <Load q={cacheQ} what="빌드 캐시를 불러오지 못했습니다" rows={2}>
        {(k) =>
          !k.caches.length ? (
            <Card>
              <Empty title="빌드 캐시가 없습니다">빌드 설정에서 빌드 서버를 정하고 한 번 빌드하면 캐시가 여기 보입니다.</Empty>
            </Card>
          ) : (
            <div className="grid" style={{ gridTemplateColumns: 'minmax(0,1fr) minmax(240px, 300px)', gap: 14, alignItems: 'start' }}>
              <div className="col" style={{ gap: 14, minWidth: 0 }}>
                <Card
                  title="서버·컨텍스트별 캐시"
                  actions={
                    <>
                      <Menu
                        label="서버 고르기"
                        items={nodes.map((n) => ({ label: n.node, hint: n.node === cur ? '고름' : `${n.scopes}곳`, onSelect: () => (setNode(n.node), setSel(undefined)) }))}
                        button={`서버: ${cur} ▾`}
                      />{' '}
                      <button className="btn sm" disabled={!!no || !curScope} title={no ?? (curScope ? undefined : '관측된 캐시가 없습니다')} onClick={() => curScope && void askUnused(curScope)}>
                        {IDLE}일 넘게 안 쓴 것 비우기…
                      </button>{' '}
                      <button className="btn sm danger" disabled={!!no || !okScopes.length} title={no} onClick={askAll}>
                        전체 비우기…
                      </button>
                    </>
                  }
                  flush
                >
                  <div className="col" style={{ gap: 8, padding: '12px 14px' }}>
                    <span>
                      <b>{fmtBytes(nodeRow?.reportedBytes ?? 0)}</b>{' '}
                      <span title={REPORTED} className="small">
                        보고된 크기 ⓘ
                      </span>{' '}
                      · 항목 {nodeRow?.entries ?? 0}개 · 정리 목표는 서버·컨텍스트마다 {fmtBytes(k.cacheBytes)}
                    </span>
                    <span className="small muted">
                      보고된 크기는 빌드 도구가 알려 준 캐시 항목 크기의 합입니다. 디스크에서 실제로 차지하는 양이나 비웠을 때 늘어나는 여유 공간과 다를 수 있습니다. 정리 목표는 강제 상한이 아니라, 넘으면
                      자동 정리가 오래 안 쓴 것부터 지우는 기준입니다. 각 줄은 마지막 관측 때 값입니다.
                    </span>
                    {disk && (
                      <span className="small">
                        디스크 여유{' '}
                        <b style={{ color: diskFree !== undefined && disk.total ? (diskFree / disk.total < 0.05 ? 'var(--er)' : diskFree / disk.total < 0.15 ? 'var(--wa)' : undefined) : undefined }}>
                          {cur} · {root} {fmtBytes(diskFree)} 남음
                        </b>{' '}
                        / {fmtBytes(disk.total)}
                        {diskQ.asOf ? ` 관측 ${agoMs(diskQ.asOf.getTime())}` : ''} · 같은 디스크를 쓰는 앱 데이터도 함께 줄어듭니다
                      </span>
                    )}
                  </div>
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>서버</th>
                        <th>컨텍스트</th>
                        <th>보고된 크기</th>
                        <th>항목</th>
                        <th>마지막 관측</th>
                        <th>정리</th>
                        <th aria-label="동작" />
                      </tr>
                    </thead>
                    <tbody>
                      {scopes.map((s) => {
                        const u = s.usage;
                        const cl = cleaningOf(s);
                        const rb = runningOn(s);
                        const ctxName = `${s.context}${s.contextDeleted ? ' (지운 컨텍스트)' : ''}`;
                        if (!u || !u.available)
                          return (
                            <tr key={s.cache}>
                              <td className="mono">{s.node}</td>
                              <td>{ctxName}</td>
                              <td colSpan={3} className="small muted">
                                {!u ? '관측 없음 — 아직 성공한 관측이 없음' : '서버 응답 없음 — 합계에 넣지 않음'}
                              </td>
                              <td className="muted">—</td>
                              <td />
                            </tr>
                          );
                        const [cs, ct, ch] = cl ? cleaningState(cl) : ['', 'un' as Tone];
                        return (
                          <tr key={s.cache} className={`clickable${s.cache === curScope?.cache ? ' selected' : ''}`} onClick={() => setSel(s.cache)}>
                            <td className="mono">{s.node}</td>
                            <td>{ctxName}</td>
                            <td>{fmtBytes(u.reportedBytes)}</td>
                            <td>{u.count}</td>
                            <td className="small">
                              {afterPrune(u) ? '정리 끝' : s.job ? `${jobLabel(s.job)} 빌드 끝` : '관측'} · {agoMs(u.observedAt)}
                            </td>
                            <td className="small">
                              {cl ? (
                                <Badge tone={ct} title={ch}>
                                  {cs}
                                </Badge>
                              ) : rb ? (
                                `빌드 중 (${rb.label})`
                              ) : (
                                <span className="muted">—</span>
                              )}
                            </td>
                            <td onClick={(e) => e.stopPropagation()} style={{ textAlign: 'right' }}>
                              {!cl && (
                                <button className="btn sm" disabled={!!no} title={no} onClick={() => askScope(s)}>
                                  비우기
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  <div className="small muted" style={{ padding: '10px 14px' }}>
                    캐시는 서버와 컨텍스트마다 따로라, 한 컨텍스트를 비워도 다른 컨텍스트 캐시는 그대로입니다. '관측 없음'은 0이 아니라 아직 잰 적이 없다는 뜻이고, 서버가 응답하지 않는 줄은 합계에 넣지
                    않습니다. 디스크 여유는 빌드 저장 경로가 있는 디스크의 관측값이며, 데이터 저장소 관리 권한이 있을 때만 보입니다. 강제 상한이 없으므로 여유가 15% 아래면 주황, 5% 아래면 빨강으로 알립니다.
                  </div>
                </Card>
                {curScope && (
                  <EntriesCard
                    key={`${curScope.node}/${curScope.cache}/${curScope.usage?.observedAt}`}
                    tenant={tenant}
                    s={curScope}
                    observed={`${curScope.usage && afterPrune(curScope.usage) ? '정리 끝에' : curScope.job ? `${jobLabel(curScope.job)} 빌드 끝에` : ''} 관측 · ${agoMs(curScope.usage?.observedAt)}`}
                    no={no}
                    onPrune={(es) => askEntries(curScope, es)}
                    onBuilds={() => navigate(`/images/builds?context=${encodeURIComponent(curScope.context)}`)}
                  />
                )}
              </div>
              <div className="col" style={{ gap: 14 }}>
                <Card title="자동 정리">
                  <div className="col small" style={{ gap: 6 }}>
                    <span>
                      <span className="muted">기준</span> 정리 목표 {fmtBytes(k.cacheBytes)}의 {k.cleanup.highWaterPercent}%를 넘으면 오래 안 쓴 것부터 · {k.cleanup.unusedDays}일 넘게 안 쓴 항목
                    </span>
                    <span>
                      <span className="muted">언제</span> 빌드가 끝난 뒤, 그리고 빌드가 없는 동안 틈틈이(5분 넘게 쉰 캐시)
                    </span>
                    <button className="btn sm" style={{ width: 'fit-content' }} disabled={!!no} title={no} onClick={() => navigate('/images/builds?policy=cache')}>
                      빌드 설정에서 바꾸기
                    </button>
                  </div>
                </Card>
                <Card title="정리 기록" flush>
                  {!k.cleaning.length ? (
                    <div className="small muted" style={{ padding: '10px 14px' }}>
                      아직 정리한 적이 없습니다.
                    </div>
                  ) : (
                    <table className="tbl">
                      <tbody>
                        {k.cleaning.slice(0, 20).map((c) => {
                          const [label, tone, hint] = cleaningState(c);
                          return (
                            <tr key={c.id}>
                              <td className="small">
                                <div>
                                  {c.context} · {filterText(c)}
                                </div>
                                <div className="muted">
                                  {c.automatic ? '' : `${c.user} · `}
                                  {agoMs(c.acceptedAt)}
                                  {c.state === 'succeeded' && c.reportedBytes ? ` · ${fmtBytes(c.reportedBytes)} 줄어듦` : ''}
                                </div>
                              </td>
                              <td style={{ textAlign: 'right' }}>
                                <Badge tone={tone} title={hint}>
                                  {label}
                                </Badge>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                  <div className="small muted" style={{ padding: '10px 14px' }}>
                    줄어든 크기도 보고된 크기 기준입니다. 쓰는 빌드가 있으면 빌드가 끝난 뒤 정리합니다. 정리 중에 시작한 빌드는 정리가 끝날 때까지 '캐시 정리 기다림'으로 대기합니다.
                  </div>
                </Card>
              </div>
            </div>
          )
        }
      </Load>
      {prune && <PruneDialog tenant={tenant} p={prune} onClose={() => setPrune(undefined)} onDone={() => (toast(prune.done), cacheQ.refresh())} />}
    </>
  );
}

function EntriesCard({ tenant, s, observed, no, onPrune, onBuilds }: { tenant: string; s: BuildCacheScope; observed: string; no?: string; onPrune: (es: BuildCacheEntry[]) => void; onBuilds: () => void }) {
  const toast = useToast();
  const [cursors, setCursors] = useState<string[]>(['']);
  const [at, setAt] = useState(0);
  const q = usePoll((sig) => buildCacheEntries(tenant, s.node, s.cache, cursors[at] || undefined, sig), [tenant, s.node, s.cache, cursors[at]], 0);
  const [kind, setKind] = useState('');
  const [sort, setSort] = useState<'bytes' | 'lastUsed'>('bytes');
  const [picked, setPicked] = useState<Map<string, BuildCacheEntry>>(new Map());
  const kinds = s.usage?.kinds ?? [];
  const sumKinds = KIND_SUM.map(([label, ks]) => [label, kinds.filter((x) => ks.includes(x.kind)).reduce((n, x) => n + x.reportedBytes, 0)] as const);
  const rows = useMemo(
    () => (q.data?.entries ?? []).filter((e) => !kind || KIND[e.kind] === kind || e.kind === kind).sort((a, b) => (sort === 'bytes' ? b.bytes - a.bytes : (b.lastUsedAt ?? 0) - (a.lastUsedAt ?? 0))),
    [q.data, kind, sort],
  );
  const toggle = (e: BuildCacheEntry, on: boolean) =>
    setPicked((m) => {
      const n = new Map(m);
      if (on && n.size < MAX_PICK) n.set(e.id, e);
      else n.delete(e.id);
      return n;
    });
  const sel = [...picked.values()];
  const menu = (e: BuildCacheEntry): MenuItem[] => [
    { label: '항목 ID 복사', onSelect: () => void navigator.clipboard?.writeText(e.id).then(() => toast('항목 ID를 복사했습니다.')) },
    { label: '이 캐시를 쓴 빌드 보기', onSelect: onBuilds },
    { label: '', sep: true },
    { label: '이것만 비우기', danger: true, onSelect: () => onPrune([e]), disabledReason: no },
  ];
  const off = q.data?.offset ?? 0;
  const kindNames = [...new Set((s.usage?.kinds ?? []).map((x) => KIND[x.kind] ?? x.kind))];
  return (
    <Card
      title={
        <h2>
          {s.node} · {s.context} 캐시 항목 <span className="small muted">{observed}</span>
        </h2>
      }
      flush
    >
      <div className="col" style={{ gap: 8, padding: '12px 14px' }}>
        <div className="row small" style={{ gap: 16, flexWrap: 'wrap' }}>
          {sumKinds.map(([label, b]) => (
            <span key={label}>
              <span className="muted">{label}</span> <b>{fmtBytes(b)}</b>
            </span>
          ))}
        </div>
        <div className="row small" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <Menu label="종류" items={[{ label: '전체', onSelect: () => setKind('') }, ...kindNames.map((x) => ({ label: x, onSelect: () => setKind(x) }))]} button={`종류: ${kind || '전체'} ▾`} />
          <Menu
            label="정렬"
            items={[
              { label: '크기', onSelect: () => setSort('bytes') },
              { label: '마지막 사용', onSelect: () => setSort('lastUsed') },
            ]}
            button={`정렬: ${sort === 'bytes' ? '크기' : '마지막 사용'} ▼`}
          />
        </div>
        {sel.length > 0 && (
          <div className="inset row" style={{ gap: 10, alignItems: 'center' }}>
            <b>{sel.length}개 고름</b>
            <span className="small">보고된 크기 합 {fmtBytes(sel.reduce((n, e) => n + e.bytes, 0))}</span>
            <span className="grow" />
            <button className="btn sm danger" disabled={!!no} title={no} onClick={() => onPrune(sel)}>
              고른 것 비우기…
            </button>
          </div>
        )}
      </div>
      <Load q={q} what="캐시 항목을 읽지 못했습니다" rows={4}>
        {(p) =>
          !p.available ? (
            <div className="small muted" style={{ padding: '10px 14px' }}>
              서버가 응답하지 않아 항목을 볼 수 없습니다{p.lastAttemptCode ? ` (${p.lastAttemptCode})` : ''}.
            </div>
          ) : (
            <>
              <table className="tbl">
                <thead>
                  <tr>
                    <th aria-label="고르기" />
                    <th>항목 ID</th>
                    <th>종류</th>
                    <th>크기 {sort === 'bytes' ? '▼' : ''}</th>
                    <th>마지막 사용</th>
                    <th>쓴 횟수</th>
                    <th>관측 때</th>
                    <th aria-label="메뉴" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((e) => (
                    <tr key={e.id}>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`${e.id} 고르기`}
                          checked={picked.has(e.id)}
                          disabled={!picked.has(e.id) && picked.size >= MAX_PICK}
                          onChange={(x) => toggle(e, x.target.checked)}
                        />
                      </td>
                      <td className="mono small" title={e.id}>
                        {short(e.id)}
                      </td>
                      <td className="small">{KIND[e.kind] ?? e.kind}</td>
                      <td>{fmtBytes(e.bytes)}</td>
                      <td className="small">{agoMs(e.lastUsedAt)}</td>
                      <td>{e.uses}</td>
                      <td className="small">{[e.inUse && '사용 중', e.shared && '공유'].filter(Boolean).join(' · ')}</td>
                      <td style={{ textAlign: 'right' }}>
                        <Menu label={`${short(e.id)} 메뉴`} items={menu(e)} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="row small" style={{ gap: 8, padding: '10px 14px', alignItems: 'center' }}>
                <span className="muted">
                  {p.entries.length ? `${off + 1}–${off + p.entries.length}` : '0'} / {p.count}개 (상위 크기순)
                </span>
                <span className="grow" />
                {at > 0 && (
                  <button className="btn sm" onClick={() => setAt(at - 1)}>
                    ‹ 앞
                  </button>
                )}
                {p.next && (
                  <button
                    className="btn sm"
                    onClick={() => {
                      setCursors((c) => [...c.slice(0, at + 1), p.next!]);
                      setAt(at + 1);
                    }}
                  >
                    다음 ›
                  </button>
                )}
              </div>
            </>
          )
        }
      </Load>
      <div className="small muted" style={{ padding: '0 14px 12px' }}>
        빌드 도구는 항목 내용(명령 · 주소)을 남기지 않아 종류와 ID로만 보입니다. '관측 때 사용 중'은 마지막 관측 당시 값이라 지금과 다를 수 있고, 비울 때 서버가 다시 확인해 쓰는 중인 항목은 남깁니다. 한 번에{' '}
        {MAX_PICK}개까지 고를 수 있습니다.
      </div>
    </Card>
  );
}

function PruneDialog({ tenant, p, onClose, onDone }: { tenant: string; p: Prune; onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<{ op?: OpView; error?: unknown }[]>([]);
  const [ids] = useState(() => p.scopes.map(() => newOpId()));
  const finished = res.length === p.scopes.length && res.every((r) => r.op?.state === 'applied');
  const go = async () => {
    setBusy(true);
    const out = [...res];
    for (let i = 0; i < p.scopes.length; i++) {
      if (out[i]?.op?.state === 'applied') continue;
      const { s, filter } = p.scopes[i];
      try {
        out[i] = { op: await sendAndWait(buildPath(tenant, '/build-cache/prune'), { node: s.node, cache: s.cache, filter }, ids[i]) };
        if (out[i].op!.state === 'failed' || out[i].op!.state === 'rejected') ids[i] = newOpId();
      } catch (e) {
        out[i] = { error: e };
      }
      setRes([...out]);
      if (out[i].op?.state !== 'applied') break;
    }
    setBusy(false);
    if (out.length === p.scopes.length && out.every((r) => r.op?.state === 'applied')) {
      onDone();
      onClose();
    }
  };
  const sent = res.length > 0;
  return (
    <Dialog
      title={p.title}
      danger
      width={p.typed ? 560 : 400}
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
            <button className="btn danger" disabled={busy || (!!p.typed && typed !== p.typed)} onClick={() => void go()}>
              {busy ? '보내는 중…' : sent ? '남은 것 다시 보내기' : (p.action ?? '비우기')}
            </button>
          </>
        )
      }
    >
      <span>{p.text}</span>
      {p.typed && (
        <label className="col small" style={{ gap: 4 }}>
          <span>
            확인하려면 <code>{p.typed}</code>
            {eulReul(p.typed)} 입력하세요
          </span>
          <input value={typed} onChange={(e) => setTyped(e.target.value)} disabled={busy || sent} />
        </label>
      )}
      {sent && p.scopes.length > 1 && (
        <div className="col small" style={{ gap: 4 }}>
          {p.scopes.map(({ s }, i) => (
            <span key={s.cache} className="row" style={{ gap: 8 }}>
              {res[i]?.op ? <OpBadge state={res[i].op!.state} /> : <Badge tone="un">대기</Badge>} {s.context}
            </span>
          ))}
        </div>
      )}
      {res.map((r, i) => (r.error !== undefined ? <MutationError key={i} error={r.error} /> : null))}
      <span className="small muted">수락은 끝이 아닙니다. 진행은 오른쪽 '정리 기록'에서 봅니다.</span>
    </Dialog>
  );
}
