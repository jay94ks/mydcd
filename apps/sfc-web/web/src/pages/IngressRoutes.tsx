// SPDX-License-Identifier: Apache-2.0

// 외부 접속 › 도메인·경로별 (UI-5E, 캔버스 v213 IngressRoutes · IngressRoutesIx): 매핑을 호스트로 묶어 보이고 여기서 더하고 고치고 뺀다.
// 작업 공간 앱의 매핑은 그 앱의 app.yaml x-sfc.ingress.routes에 저장되므로 앱 배포(/t/{t}/apps/deploy)로 바꾼다.
// 클러스터 앱(sfc-web) 매핑은 클러스터 앱 경로 설정(/cluster-apps/web/routes, 시스템 관리자만)에 저장한다.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { appPath, appSource, apps } from '../api/endpoints';
import { clusterAppRoutes, clusterAppRoutesPath, GW_NAME, hasRouteCert, inDomain, routeCertError, routeCertText, type BlockScope, type ClusterAppRoutes, type Gateway, type IngressBlock, type IngressView } from '../api/ingress';
import { dnsDomainList } from '../api/dns';
import type { AppView, DiffLine } from '../api/types';
import { useSession } from '../auth/session';
import { Card, Field, Segmented } from '../components/ui';
import { ErrorBand } from '../components/states';
import { DiffView } from '../components/Code';
import { Dialog } from '../components/Dialog';
import { ContextMenu, Menu } from '../components/Menu';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { lineDiff } from '../lib/diff';
import { usePoll } from '../lib/usePoll';
import { addRoute, readRoutes, removeRoute, replaceRoute, routeProblems, RouteEditError, servicePorts, type RouteGateway, type RouteSpec } from '../lib/ingressRoutesYaml';
import { yamlDigest } from './DeployFlow';
import { routeStatus, flatten, type Flat } from './Ingress';
import { clusterAppRoutesLive, domainListLive } from '../lib/liveTopics';

type GwFilter = 'all' | Gateway;
type StateFilter = 'all' | 'blocked' | 'problem' | 'nocert';
const NEED_DEPLOY = '이 작업 공간의 앱 배포 권한이 있어야 매핑을 바꿀 수 있습니다';
const NEED_NET = '이 작업 공간에서 망(Network) 관리 권한이 있어야 긴급 차단할 수 있습니다';
const ACME = '/.well-known/acme-challenge/';
const n = (x: number) => x.toLocaleString('ko-KR');
const pfx = (p?: string) => p || '/';
const lc = (s: string) => s.toLowerCase();

/** 표의 한 줄: 앱 정의의 경로 하나(서버·게이트웨이별 매핑을 모은 것) 또는 클러스터 앱 경로 하나 */
export interface Mapping {
  key: string;
  host: string;
  prefix: string;
  gateways: Gateway[];
  cluster?: boolean;
  tenant?: string;
  app?: string;
  service?: string;
  servicePort?: number;
  redirect?: string;
  nodes: string[];
  flats: Flat[];
}
/** route 하나의 게이트웨이(external | local). 여러 서버에서 둘 다 보이면 외부망 */
export const gwOf = (g: Gateway[]): RouteGateway => (g.includes('external') ? 'external' : 'local');
const gwList = (g: RouteGateway): Gateway[] => [g];

/** 서버·게이트웨이마다 따로 오는 매핑을 앱 정의의 경로 하나로 모으고, 클러스터 앱 경로를 붙인다 */
export function buildMappings(v: IngressView, cluster?: ClusterAppRoutes): Mapping[] {
  const by = new Map<string, Mapping>();
  for (const f of flatten(v)) {
    const prefix = pfx(f.r.prefix);
    const key = `${f.i.tenant}/${f.i.app}/${lc(f.r.host)}${prefix}${f.r.redirect ? '#r' : ''}`;
    const m = by.get(key) ?? { key, host: f.r.host, prefix, gateways: [], tenant: f.i.tenant, app: f.i.app, service: f.r.service, servicePort: f.r.servicePort, redirect: f.r.redirect, nodes: [], flats: [] };
    if (!m.gateways.includes(f.r.gateway)) m.gateways.push(f.r.gateway);
    if (!m.nodes.includes(f.i.node)) m.nodes.push(f.i.node);
    m.flats.push(f);
    by.set(key, m);
  }
  const out = [...by.values()];
  if (cluster && !cluster.removed)
    for (const r of cluster.routes) out.push({ key: `cluster/web/${lc(r.host)}${pfx(r.prefix)}`, host: r.host, prefix: pfx(r.prefix), gateways: gwList(r.gateway), cluster: true, nodes: cluster.node ? [cluster.node] : [], flats: [] });
  return out;
}
const rpsOf = (m: Mapping) => m.flats.reduce((s, f) => s + (f.r.rps ?? 0), 0);
const err5xxOf = (m: Mapping) => Math.max(0, ...m.flats.map((f) => f.r.err5xx ?? 0));
const blockedOf = (m: Mapping) => m.flats.find((f) => f.r.blocked)?.r;
const problemOf = (m: Mapping) => m.flats.some((f) => !!f.r.note || (f.r.err5xx ?? 0) >= 2 || f.r.backends.some((b) => b.slow || !b.health.ok || b.blocked));
const noCertOf = (m: Mapping) => !m.redirect && m.gateways.includes('external') && m.flats.length > 0 && m.flats.every((f) => !hasRouteCert(f.r));
const sameTarget = (a: Mapping, b: Mapping) => a.key === b.key;
/** 같은 호스트·접두사이고 게이트웨이가 겹치는 다른 매핑 */
export const clash = (all: Mapping[], host: string, prefix: string, gw: RouteGateway, self?: Mapping) =>
  all.find((m) => !m.redirect && lc(m.host) === lc(host) && m.prefix === prefix && m.gateways.some((g) => gwList(gw).includes(g)) && !(self && sameTarget(m, self)));
/** 새 접두사가 생기기 전에 그 요청을 받던 매핑(같은 호스트의 가장 긴 접두사) */
export const fallbackOf = (all: Mapping[], host: string, prefix: string, gw: RouteGateway, self?: Mapping) =>
  all
    .filter((m) => !m.redirect && lc(m.host) === lc(host) && m.prefix !== prefix && prefix.startsWith(m.prefix) && m.gateways.some((g) => gwList(gw).includes(g)) && !(self && sameTarget(m, self)))
    .sort((a, b) => b.prefix.length - a.prefix.length)[0];
const targetText = (m?: Mapping): ReactNode =>
  !m ? '—' : m.cluster ? (
    <>
      클러스터 앱 <b>web</b> <span className="muted">(sfc-web)</span>
    </>
  ) : (
    <>
      {m.tenant} › <b>{m.app}</b> › {m.service}
      {m.servicePort ? <span className="mono"> :{m.servicePort}</span> : null}
    </>
  );
const targetPlain = (m: Mapping) => (m.cluster ? '클러스터 앱 web' : `${m.tenant} › ${m.app} › ${m.service ?? ''}${m.servicePort ? ` :${m.servicePort}` : ''}`);

export function GwPills({ g }: { g: Gateway[] }) {
  return (
    <span className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
      {(['external', 'local'] as Gateway[])
        .filter((x) => g.includes(x))
        .map((x) => (
          <span key={x} className={`gwp ${x === 'external' ? 'ext' : ''}`}>
            {GW_NAME[x]}
          </span>
        ))}
    </span>
  );
}

/** 대화 상자를 여는 값: 새 매핑(호스트만 채울 수 있음) 또는 고칠 매핑 */
export type MapDialog = { kind: 'add'; host?: string } | { kind: 'edit'; m: Mapping } | { kind: 'remove'; m: Mapping };

export function useClusterRoutes(admin: boolean) {
  return usePoll((s) => (admin ? clusterAppRoutes(s).catch(() => undefined) : Promise.resolve(undefined)), [admin], 0, clusterAppRoutesLive);
}

export function RoutesTab({ v, gw, find, blocks, cluster, onDialog, onBlock }: { v: IngressView; gw: GwFilter; find: string; blocks: IngressBlock[]; cluster?: ClusterAppRoutes; onDialog: (d: MapDialog) => void; onBlock: (s: BlockScope) => void }) {
  const session = useSession();
  const admin = !!session.user.systemAdmin;
  const nav = useNavigate();
  const canDeploy = (t?: string) => admin || (!!t && session.tenants.some((x) => x.id === t && x.role === 'manager'));
  const [state, setState] = useState<StateFilter>('all');
  const [ctx, setCtx] = useState<{ at: { x: number; y: number }; host: string; ms: Mapping[] }>();
  const dq = usePoll((s) => dnsDomainList(s).catch(() => ({ items: [], cluster: false })), [], 60_000, domainListLive);
  const domains = (dq.data?.items ?? []).map((d) => d.domain);
  const all = useMemo(() => buildMappings(v, cluster), [v, cluster]);
  const q = lc(find.trim());
  const rows = all.filter(
    (m) =>
      (gw === 'all' || m.gateways.includes(gw)) &&
      (!q || lc(`${m.host}${m.prefix}`).includes(q) || lc(`${m.host} ${m.prefix} ${m.app ?? 'web'} ${m.service ?? ''}`).includes(q)) &&
      (state === 'blocked' ? !!blockedOf(m) : state === 'problem' ? problemOf(m) : state === 'nocert' ? noCertOf(m) : true),
  );
  // 도메인 계층 순(shop.example.com → api.shop… → *.shop…), 클러스터 앱만 쓰는 호스트는 끝에
  const order = (h: string) => `${rows.every((m) => lc(m.host) !== h || m.cluster) ? 1 : 0}${h.split('.').reverse().join('.').replace(/\*/g, '~')}`;
  const hosts = [...new Set(rows.map((m) => lc(m.host)))].sort((a, b) => (order(a) < order(b) ? -1 : order(a) > order(b) ? 1 : 0));
  const cols = 'minmax(0,1fr) 92px minmax(0,1.5fr) minmax(0,0.9fr) 96px 88px 112px 40px';
  const hostLine = (h: string, ms: Mapping[]) => {
    const nodes = [...new Set(ms.flatMap((m) => m.nodes))].sort().join(', ');
    if (ms.every((m) => m.cluster)) return `클러스터 앱 · 시스템 관리자만${nodes ? ` · ${nodes}` : ''}`;
    if (ms.every((m) => m.redirect)) return ':80만 · https로 넘김';
    const d = domains.find((x) => inDomain(h, x));
    const local = ms.every((m) => !m.gateways.includes('external'));
    return [d ? `등록된 도메인 ${d} 아래` : dq.data ? `등록된 도메인 아님${local ? ' · 로컬망 전용' : ''}` : '', `경로 ${ms.length}`, nodes].filter(Boolean).join(' · ');
  };
  const menu = (m: Mapping) => {
    const auto = m.redirect ? 'sfcd가 :443 경로에 맞춰 저절로 둔 넘김 규칙입니다' : m.prefix === ACME ? '인증서 자동화가 쓰는 경로입니다' : undefined;
    const may = m.cluster ? (admin ? undefined : '시스템 관리자만 바꿉니다') : canDeploy(m.tenant) ? undefined : NEED_DEPLOY;
    const f = m.flats.find((x) => !x.r.blocked) ?? m.flats[0];
    const canNet = admin || session.tenants.some((x) => x.id === m.tenant && x.role === 'manager');
    return (
      <Menu
        label={`${m.host}${m.prefix} 메뉴`}
        button="⋯"
        items={[
          { label: '고치기…', onSelect: () => onDialog({ kind: 'edit', m }), disabledReason: auto ?? may },
          m.cluster ? { label: '클러스터 앱에서 보기', hint: 'web', onSelect: () => nav('/servers/cluster-apps') } : { label: '앱 정의에서 보기', hint: `${m.app} › 외부 접속`, onSelect: () => nav(`${appPath(m.tenant!, m.app!)}/edit`) },
          { label: '컨테이너까지 흐름 보기', onSelect: () => nav(`/shared/ingress/${m.tenant}/${m.app}`), disabledReason: m.cluster ? '클러스터 앱은 서버 › 클러스터 앱에서 봅니다' : undefined },
          { label: '⛔ 긴급 차단…', danger: true, onSelect: () => f && onBlock({ kind: 'route', tenant: m.tenant!, app: m.app!, node: f.i.node, host: f.r.host, prefix: f.r.prefix, gateway: f.r.gateway }), disabledReason: m.cluster ? '클러스터 앱 경로는 여기서 막지 않습니다' : !f ? '아직 서버에 반영되지 않았습니다' : canNet ? undefined : NEED_NET },
          { label: '매핑 빼기…', danger: true, onSelect: () => onDialog({ kind: 'remove', m }), disabledReason: auto ?? may },
        ]}
      />
    );
  };
  const status = (m: Mapping) => {
    if (m.cluster) return <span className="small muted">{m.nodes.length ? `${m.nodes.join(', ')}에서 엶` : '—'}</span>;
    const b = blockedOf(m);
    if (b) return routeStatus(b, blocks);
    const f = m.flats.find((x) => x.r.note) ?? m.flats.find((x) => (x.r.err5xx ?? 0) >= 2 || x.r.backends.some((y) => y.slow)) ?? m.flats[0];
    return routeStatus(f.r, blocks, m.flats.some((x) => x.i.observed !== false));
  };
  const cert = (m: Mapping) => {
    if (m.cluster || m.redirect || !m.flats.length) return <span className="muted">—</span>;
    const r = m.flats.find((x) => hasRouteCert(x.r))?.r ?? m.flats[0].r;
    const e = routeCertError(r);
    return <span className={`small ${e ? 'er' : ''}`}>{routeCertText(r) || '—'}</span>;
  };
  const met = (m: Mapping) => {
    if (m.cluster || m.flats.every((f) => f.i.observed === false)) return '—';
    const e = err5xxOf(m);
    return `${n(rpsOf(m))}/s${e > 0 ? ` · ${e}%` : ''}`;
  };
  return (
    <Card
      title={`매핑 · 호스트 ${new Set(all.map((m) => lc(m.host))).size} · 경로 ${all.length}`}
      actions={
        <Segmented<StateFilter>
          label="상태 거르기"
          value={state}
          onChange={setState}
          options={[
            ['all', '전체'],
            ['blocked', '차단 중'],
            ['problem', '오류'],
            ['nocert', '인증서 없음'],
          ]}
        />
      }
    >
      <div className="table-x">
        <div className="gtbl" style={{ minWidth: 1040 }}>
          <div className="gr th" style={{ gridTemplateColumns: cols }}>
            <span>경로 (접두사)</span>
            <span>게이트웨이</span>
            <span>대상 (작업 공간 › 앱 › 서비스 :포트)</span>
            <span>인증서</span>
            <span>어디에 저장</span>
            <span>요청 · 5xx</span>
            <span>상태</span>
            <span />
          </div>
          {!hosts.length && (
            <div className="gr" style={{ gridTemplateColumns: '1fr' }}>
              <span className="muted">{all.length ? '거른 조건에 맞는 매핑이 없습니다.' : '매핑이 없습니다. ＋ 매핑 추가로 앱 서비스를 호스트·경로에 잇습니다.'}</span>
            </div>
          )}
          {hosts.map((h) => {
            const ms = rows.filter((m) => lc(m.host) === h).sort((a, b) => a.prefix.localeCompare(b.prefix));
            const cl = ms.every((m) => m.cluster);
            const addable = cl ? admin : ms.some((m) => canDeploy(m.tenant)) || admin;
            return (
              <div key={h} style={{ display: 'contents' }}>
                <div
                  className="gr grp"
                  style={{ gridTemplateColumns: cols }}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setCtx({ at: { x: e.clientX, y: e.clientY }, host: ms[0].host, ms });
                  }}
                >
                  <span className="row" style={{ gridColumn: '1/-1', gap: 10 }}>
                    <b className="mono">{ms[0].host}</b>
                    <span className="small muted">{hostLine(h, ms)}</span>
                    <span style={{ flex: 1 }} />
                    {addable && !ms.every((m) => m.redirect) && (
                      <button type="button" className="linkish small" onClick={() => onDialog({ kind: 'add', host: ms[0].host })}>
                        ＋ 이 호스트에 경로 추가
                      </button>
                    )}
                  </span>
                </div>
                {ms.map((m) => (
                  <div key={m.key} className={`gr ${blockedOf(m) ? 'blk' : ''}`} style={{ gridTemplateColumns: cols }}>
                    <span className="mono">{m.prefix}</span>
                    <GwPills g={m.gateways} />
                    <span>{m.redirect ? <span className="muted">→ {m.redirect} 넘김 (같은 호스트)</span> : targetText(m)}</span>
                    {cert(m)}
                    <span className="muted small">{m.cluster ? '클러스터 앱' : '앱 정의'}</span>
                    <span className="mono small">{met(m)}</span>
                    <span>{status(m)}</span>
                    <span>{menu(m)}</span>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>
      {ctx && (
        <ContextMenu
          at={ctx.at}
          onClose={() => setCtx(undefined)}
          items={(() => {
            const d = domains.find((x) => inDomain(lc(ctx.host), x));
            const app = ctx.ms.find((m) => !m.cluster && !m.redirect) ?? ctx.ms.find((m) => !m.cluster);
            const canNet = !!app && (admin || session.tenants.some((x) => x.id === app.tenant && x.role === 'manager'));
            return [
              { label: '외부 도메인에서 보기', hint: d, onSelect: () => d && nav(`/system/domains/${encodeURIComponent(d)}`), disabledReason: d ? undefined : '등록된 도메인 아래 호스트가 아닙니다' },
              { label: '이 호스트 전체 긴급 차단…', danger: true, onSelect: () => app && onBlock({ kind: 'host', tenant: app.tenant, app: app.app, host: ctx.host }), disabledReason: !app ? '클러스터 앱 호스트는 여기서 막지 않습니다' : canNet ? undefined : NEED_NET },
            ];
          })()}
        />
      )}
      <span className="small muted">
        같은 게이트웨이에서 같은 호스트·경로는 한 대상만 가질 수 있습니다. 더 긴 경로 접두사가 먼저 맞습니다(/api/v2 가 / 보다 먼저). 행 메뉴(⋯)에서 고치기 · 앱 정의에서 보기 · 긴급 차단 · 매핑 빼기를 합니다. 빼면 그 경로는 다른 더 짧은 접두사 매핑으로 가거나, 없으면 404를 돌려줍니다. 등록된 도메인 아래 호스트는 DNS 공급자가 있으면 레코드를 저절로 맞춥니다(<Link to="/system/domains">외부 도메인</Link>).
      </span>
    </Card>
  );
}

// ── 매핑 추가·고치기·빼기 ─────────────────────────────

interface AppPick {
  tenant: string;
  app: AppView;
}
/** 앱 정의를 바꾼 결과 하나: 어느 앱의 원문이 어떻게 바뀌는지 */
interface Change {
  tenant?: string;
  app?: string;
  deployment?: string;
  cluster?: { expected: number };
  before: string;
  after?: string;
  error?: string;
}
const diffOf = (c: Change): DiffLine[] => (c.after !== undefined ? lineDiff(c.before, c.after) : []);
const editErr = (e: unknown) => (e instanceof RouteEditError ? e.message : e instanceof Error ? e.message : String(e));

/** 대상 앱의 원문(작업 공간 앱) 또는 클러스터 앱 경로 파일을 읽는다 */
function useSource(t?: { tenant: string; app: string } | 'cluster') {
  const [s, setS] = useState<{ key: string; yaml?: string; revision?: number; error?: unknown }>();
  const key = !t ? '' : t === 'cluster' ? 'cluster' : `${t.tenant}/${t.app}`;
  useEffect(() => {
    if (!t) return;
    let live = true;
    const ac = new AbortController();
    const p = t === 'cluster' ? clusterAppRoutes(ac.signal).then((r) => ({ yaml: r.file, revision: r.revision })) : appSource(t.tenant, t.app, 0, ac.signal).then((r) => ({ yaml: r.yaml, revision: r.version }));
    p.then((r) => live && setS({ key, ...r })).catch((error) => live && setS({ key, error }));
    return () => {
      live = false;
      ac.abort();
    };
  }, [key]);
  return s?.key === key ? s : undefined;
}

export function MappingDialog({ d, v, cluster, onClose, onDone, onShow }: { d: Extract<MapDialog, { kind: 'add' | 'edit' }>; v: IngressView; cluster?: ClusterAppRoutes; onClose: () => void; onDone: () => void; onShow: (q: string) => void }) {
  const session = useSession();
  const admin = !!session.user.systemAdmin;
  const orig = d.kind === 'edit' ? d.m : undefined;
  const all = useMemo(() => buildMappings(v, cluster), [v, cluster]);
  const deployable = useMemo(() => [...new Set([...(admin ? v.tenants.map((t) => t.tenant) : []), ...session.tenants.filter((t) => admin || t.role === 'manager').map((t) => t.id)])].sort(), [admin, v, session]);
  const [list, setList] = useState<AppPick[]>();
  useEffect(() => {
    const ac = new AbortController();
    Promise.all(deployable.map((t) => apps(t, ac.signal).then((p) => p.items.map((a) => ({ tenant: t, app: a }))).catch(() => [] as AppPick[]))).then((x) => setList(x.flat()));
    return () => ac.abort();
  }, [deployable.join(',')]);

  const [host, setHost] = useState(orig?.host ?? (d.kind === 'add' ? (d.host ?? '') : ''));
  const [prefix, setPrefix] = useState(orig?.prefix ?? '/');
  const [gw, setGw] = useState<RouteGateway>(orig ? gwOf(orig.gateways) : 'external');
  // route를 여는 서버: 외부 접속 모듈이 켜져 있고 고른 게이트웨이가 있는 서버
  const gwNodes = v.nodes.filter((x) => x.module && !!x[gw]).map((x) => x.node);
  const [node, setNode] = useState(orig?.nodes[0] ?? '');
  useEffect(() => {
    if (!node || !gwNodes.includes(node)) {
      if (gwNodes.length) setNode(gwNodes[0]);
    }
  }, [gw, v]);
  const [dest, setDest] = useState<'app' | 'cluster'>(orig?.cluster ? 'cluster' : 'app');
  const [appKey, setAppKey] = useState(orig && !orig.cluster ? `${orig.tenant}/${orig.app}` : '');
  const [service, setService] = useState(orig?.service ?? '');
  const [port, setPort] = useState(orig?.servicePort ? String(orig.servicePort) : '');
  // 처음 열 때 앱 하나를 미리 고른다(지금 작업 공간 먼저)
  useEffect(() => {
    if (!appKey && list?.length) {
      const h = d.kind === 'add' && d.host ? lc(d.host) : '';
      const there = all.find((m) => !m.cluster && !m.redirect && lc(m.host) === h);
      const own = (there && list.find((x) => x.tenant === there.tenant && x.app.app === there.app)) ?? list.find((x) => x.tenant === session.tenants[0]?.id) ?? list[0];
      setAppKey(`${own.tenant}/${own.app.app}`);
    }
  }, [list]);
  const target = dest === 'cluster' ? ('cluster' as const) : appKey ? { tenant: appKey.split('/')[0], app: appKey.slice(appKey.indexOf('/') + 1) } : undefined;
  const src = useSource(target);
  const origTarget = orig && !orig.cluster ? { tenant: orig.tenant!, app: orig.app! } : orig?.cluster ? ('cluster' as const) : undefined;
  const moved = !!orig && (dest === 'cluster' ? !orig.cluster : orig.cluster || `${orig.tenant}/${orig.app}` !== appKey);
  const origSrc = useSource(moved ? origTarget : undefined);
  const svcs = useMemo(() => (src?.yaml && dest === 'app' ? servicePorts(src.yaml) : []), [src?.yaml, dest]);
  // 한 앱의 경로는 모두 같은 서버: 고른 앱에 이미 경로가 있으면 그 서버로 맞춘다(고치는 경로 하나뿐이면 자유)
  const fixedNode = useMemo(() => {
    if (!src?.yaml) return undefined;
    try {
      const rs = readRoutes(src.yaml).filter((r) => !(orig && !moved && lc(String(r.host ?? '')) === lc(orig.host) && String(r.prefix ?? '/') === (orig.prefix || '/')));
      const n = rs.find((r) => r.node)?.node;
      return typeof n === 'string' ? n : undefined;
    } catch {
      return undefined;
    }
  }, [src?.yaml, moved]);
  useEffect(() => {
    if (fixedNode && fixedNode !== node) setNode(fixedNode);
  }, [fixedNode]);
  // 고른 앱의 서비스·포트 칸을 그 앱 정의에 맞춘다
  useEffect(() => {
    if (dest !== 'app' || !svcs.length) return;
    const s = svcs.find((x) => x.service === service) ?? svcs.find((x) => x.ports.length) ?? svcs[0];
    if (s.service !== service) setService(s.service);
    if (!s.ports.includes(Number(port))) setPort(s.ports[0] ? String(s.ports[0]) : '');
  }, [svcs]);

  const tenantExternal = dest === 'cluster' || !target || target === 'cluster' ? true : (v.tenants.find((t) => t.tenant === target.tenant)?.external ?? true);
  const spec: RouteSpec = dest === 'cluster' ? { node, host: host.trim().toLowerCase(), prefix: prefix.trim(), gateway: gw } : { node, host: host.trim().toLowerCase(), prefix: prefix.trim(), gateway: gw, service, port: Number(port) || undefined };
  const problems = [...(!node ? ['이 경로를 열 서버를 고르세요.'] : []), ...(host.trim() ? routeProblems(spec) : []), ...(dest === 'app' && !service ? ['서비스를 고르세요.'] : []), ...(dest === 'app' && !spec.port ? ['포트를 고르거나 적으세요.'] : []), ...(spec.prefix.startsWith(ACME) ? [`${ACME} 경로는 인증서 자동화가 씁니다.`] : []), ...(!tenantExternal && gw !== 'local' ? ['이 작업 공간은 외부망 노출이 허용되지 않았습니다.'] : [])];
  const self = orig;
  const taken = host.trim() ? clash(all, spec.host, spec.prefix, gw, self) : undefined;
  const before = host.trim() && !taken ? fallbackOf(all, spec.host, spec.prefix, gw, self) : undefined;

  // 바뀌는 원문(들). 대상 앱을 바꾸면 원래 앱에서 빼고 새 앱에 더한다
  const changes: Change[] = useMemo(() => {
    if (!src || !host.trim() || problems.length || taken) return [];
    const mk = (base: Omit<Change, 'before' | 'after' | 'error'>, yaml: string | undefined, f: (t: string) => string): Change => {
      if (yaml === undefined) return { ...base, before: '', error: base.cluster ? '클러스터 앱 경로가 아직 정해지지 않았습니다. 첫 설정(서버·수신 주소)은 CLI(sfcli deploy -f)로 정합니다.' : '앱 정의를 읽지 못했습니다.' };
      try {
        return { ...base, before: yaml, after: f(yaml) };
      } catch (e) {
        return { ...base, before: yaml, error: editErr(e) };
      }
    };
    const into = (t: typeof target, s: typeof src, f: (y: string) => string): Change =>
      t === 'cluster' ? mk({ cluster: { expected: s?.revision ?? 0 } }, s?.yaml, f) : mk({ tenant: t!.tenant, app: t!.app, deployment: list?.find((x) => x.tenant === t!.tenant && x.app.app === t!.app)?.app.deployment }, s?.yaml, f);
    const ref = orig ? { host: orig.host, prefix: orig.prefix } : undefined;
    if (!orig) return [into(target, src, (y) => addRoute(y, spec))];
    if (!moved) return [into(target, src, (y) => replaceRoute(y, ref!, spec))];
    if (!origSrc) return [];
    return [into(origTarget, origSrc, (y) => removeRoute(y, ref!)), into(target, src, (y) => addRoute(y, spec))];
  }, [src, origSrc, host, prefix, gw, node, service, port, dest, appKey, list, problems.length, taken]);
  const ready = changes.length > 0 && changes.every((c) => c.after !== undefined) && changes.some((c) => c.before !== c.after);

  const m1 = useMutation();
  const m2 = useMutation();
  const sent = !!m1.op;
  const send = async () => {
    const ms = [m1, m2];
    for (let k = 0; k < changes.length; k++) {
      const c = changes[k];
      const m = ms[k];
      if (m.op) continue;
      const op = c.cluster ? await m.run(clusterAppRoutesPath(), { expected: c.cluster.expected, file: c.after }, 'PUT') : await m.run(`/t/${encodeURIComponent(c.tenant!)}/apps/deploy`, { yaml: c.after, digest: await yamlDigest(c.after!), ...(c.deployment ? { deployment: c.deployment } : {}) });
      if (!op || op.state === 'failed' || op.state === 'rejected') return;
    }
    onDone();
  };
  const cert = useMemo(() => {
    const same = all.find((m) => lc(m.host) === lc(spec.host) && m.flats.some((f) => hasRouteCert(f.r)));
    return same ? `자동 (${routeCertText(same.flats.find((f) => hasRouteCert(f.r))!.r)}가 이 호스트를 덮음)` : '자동 (외부 도메인에 등록된 이름이면 저절로 받음)';
  }, [all, spec.host]);
  const dq = usePoll((s) => dnsDomainList(s).catch(() => undefined), [], 0, domainListLive);
  const registered = !dq.data || !spec.host || dq.data.items.some((x) => inDomain(spec.host, x.domain));
  const isCluster = dest === 'cluster';
  const verb = isCluster ? '저장' : orig ? '고치고 배포' : '더하고 배포';
  return (
    <Dialog
      title={orig ? '매핑 고치기' : '매핑 추가'}
      width={720}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {sent ? '닫기' : '취소'}
          </button>
          {!sent || m1.error !== undefined || m2.error !== undefined || (changes.length > 1 && !m2.op) ? (
            <button className="btn primary" disabled={!ready || m1.busy || m2.busy} onClick={() => void send()}>
              {m1.busy || m2.busy ? '보내는 중…' : verb}
            </button>
          ) : null}
        </>
      }
    >
      <div className="fields2">
        <Field label="호스트" hint="등록된 도메인 아래 이름이거나 직접 입력 · 와일드카드 *.는 :443 인증서가 있어야 함">
          <input className="mono" value={host} onChange={(e) => setHost(e.target.value)} placeholder="shop.example.com" disabled={sent} autoFocus={!host} />
        </Field>
        <Field label="경로 접두사" hint="/로 시작 · 더 긴 접두사가 먼저 맞음">
          <input className="mono" value={prefix} onChange={(e) => setPrefix(e.target.value)} placeholder="/" disabled={sent} />
        </Field>
      </div>
      <Field label="게이트웨이" group hint={tenantExternal ? undefined : '작업 공간에 외부망 허용이 없어 외부망은 고를 수 없습니다.'}>
        <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
          {(
            [
              ['external', '외부망', '인터넷 쪽 주소 :443 · 기본'],
              ['local', '로컬망', '사내망 주소만'],
            ] as [RouteGateway, string, string][]
          ).map(([k, l, h]) => (
            <label key={k} className="row" style={{ gap: 6 }} title={!tenantExternal && k !== 'local' ? '작업 공간에 외부망 허용이 없습니다' : undefined}>
              <input type="radio" name="map-gw" checked={gw === k} disabled={sent || (!tenantExternal && k !== 'local')} onChange={() => setGw(k)} />
              <span>
                {l} {h && <span className="small muted">{h}</span>}
              </span>
            </label>
          ))}
        </div>
      </Field>
      <Field label="여는 서버" hint={fixedNode ? `한 앱의 경로는 모두 같은 서버에서 엽니다 · 이 앱은 ${fixedNode}` : gwNodes.length ? `이 서버의 ${GW_NAME[gw]} 게이트웨이가 받습니다` : `${GW_NAME[gw]} 게이트웨이가 있는 서버가 없습니다. 서버 › 게이트웨이에서 먼저 켜세요`}>
        <select value={node} onChange={(e) => setNode(e.target.value)} disabled={sent || !!fixedNode} title={fixedNode ? `이 앱의 다른 경로가 ${fixedNode}에서 열려 같은 서버로 정해집니다` : undefined}>
          {!node && <option value="">고르세요</option>}
          {[...new Set([...gwNodes, ...(node ? [node] : [])])].map((x) => (
            <option key={x} value={x}>
              {x}
              {gwNodes.includes(x) ? '' : ' (게이트웨이 없음)'}
            </option>
          ))}
        </select>
      </Field>
      <Field label="보낼 곳" group>
        <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
          <label className="row" style={{ gap: 6 }}>
            <input type="radio" name="map-dest" checked={dest === 'app'} disabled={sent} onChange={() => setDest('app')} />
            <span>
              작업 공간의 앱 서비스 <span className="small muted">앱 정의에 저장</span>
            </span>
          </label>
          <label className="row" style={{ gap: 6 }} title={admin ? undefined : '시스템 관리자만 고를 수 있습니다'}>
            <input type="radio" name="map-dest" checked={dest === 'cluster'} disabled={sent || !admin} onChange={() => setDest('cluster')} />
            <span>
              클러스터 앱 <span className="small muted">시스템 관리자만 · 클러스터 앱 경로 설정에 저장</span>
            </span>
          </label>
        </div>
      </Field>
      {isCluster ? (
        <Field label="클러스터 앱" hint="sfc-web · 경로마다 서비스·포트는 sfcd가 정함">
          <input value="web" readOnly disabled />
        </Field>
      ) : (
        <div className="fields2">
          <Field label="작업 공간 · 앱">
            <select value={appKey} onChange={(e) => setAppKey(e.target.value)} disabled={sent || !list}>
              {!list && <option value="">불러오는 중…</option>}
              {list && !list.length && <option value="">배포 권한이 있는 앱이 없습니다</option>}
              {list?.map((x) => (
                <option key={`${x.tenant}/${x.app.app}`} value={`${x.tenant}/${x.app.app}`}>
                  {x.tenant} › {x.app.app}
                </option>
              ))}
            </select>
          </Field>
          <Field label="서비스 · 포트" hint="앱 정의에 있는 서비스 · 컨테이너가 듣는 포트">
            <span className="row" style={{ gap: 6 }}>
              <select value={service} onChange={(e) => setService(e.target.value)} disabled={sent || !svcs.length} style={{ flex: 1 }}>
                {!svcs.length && <option value="">—</option>}
                {svcs.map((s) => (
                  <option key={s.service} value={s.service}>
                    {s.service}
                  </option>
                ))}
              </select>
              <input className="mono" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} placeholder="포트" list="map-ports" style={{ width: 90 }} disabled={sent} aria-label="포트" />
              <datalist id="map-ports">
                {(svcs.find((s) => s.service === service)?.ports ?? []).map((p) => (
                  <option key={p} value={p} />
                ))}
              </datalist>
            </span>
          </Field>
        </div>
      )}
      <Field label="인증서" hint="호스트마다 클러스터 인증서 저장소가 정합니다">
        <input value={gw === 'local' ? '자동 (로컬망은 저장소에 있으면 씀)' : cert} readOnly disabled />
      </Field>
      {host.trim() && problems.map((p) => <div key={p} className="note er small">{p}</div>)}
      {taken && (
        <div className="note er small">
          겹침 · 같은 게이트웨이에서 <span className="mono">{taken.host}{taken.prefix}</span>은 이미 {targetPlain(taken)}이 씁니다. 한 호스트·경로는 한 대상만 가질 수 있습니다.{' '}
          <button type="button" className="linkish" onClick={() => (onShow(`${taken.host}${taken.prefix}`), onClose())}>
            그 매핑 보기
          </button>
        </div>
      )}
      {host.trim() && !taken && !problems.length && (
        <div className="note ok small">
          겹침 없음 · 같은 게이트웨이의 <span className="mono">{spec.host}{spec.prefix}</span>를 쓰는 다른 매핑이 없습니다.
          {before ? ` 지금은 ${before.prefix} → ${targetPlain(before)}이 받던 요청입니다${before.flats.length ? `(최근 1분 ${n(rpsOf(before))}/s)` : ''}.` : ''}
        </div>
      )}
      {!registered && gw !== 'local' && <div className="note wa small">{spec.host}은 등록된 도메인 아래가 아니라 인증서를 자동으로 받을 수 없습니다. 외부 도메인에 먼저 등록하거나 로컬망으로 쓰세요.</div>}
      {src?.error !== undefined && <ErrorBand error={src.error} what={isCluster ? '클러스터 앱 경로를 읽지 못했습니다' : '앱 정의를 읽지 못했습니다'} />}
      {changes.map((c, k) =>
        c.error ? (
          <div key={k} className="note er small">
            {c.error}
          </div>
        ) : (
          <Field key={k} label={`바뀌는 ${c.cluster ? '클러스터 앱 경로 · web' : `앱 정의 · ${c.app}`}`}>
            <DiffView lines={diffOf(c)} />
          </Field>
        ),
      )}
      {changes.length > 1 && <span className="small muted">대상 앱이 바뀌어 원래 앱에서 빼고 새 앱에 더하는 두 변경이 차례로 일어납니다.</span>}
      {isCluster && <span className="small muted">클러스터 앱 경로는 배포 없이 바로 반영됩니다.</span>}
      <MutationError error={m1.error} />
      {m1.op && <OpPanel op={m1.op} onChange={m1.setOp} />}
      <MutationError error={m2.error} />
      {m2.op && <OpPanel op={m2.op} onChange={m2.setOp} />}
    </Dialog>
  );
}

export function RemoveMappingDialog({ m, v, cluster, onClose, onDone }: { m: Mapping; v: IngressView; cluster?: ClusterAppRoutes; onClose: () => void; onDone: () => void }) {
  const all = useMemo(() => buildMappings(v, cluster), [v, cluster]);
  const src = useSource(m.cluster ? 'cluster' : { tenant: m.tenant!, app: m.app! });
  const deployment = useDeployment(m);
  const change = useMemo((): Change | undefined => {
    if (!src || src.yaml === undefined) return undefined;
    try {
      return { before: src.yaml, after: removeRoute(src.yaml, { host: m.host, prefix: m.prefix }) };
    } catch (e) {
      const msg = editErr(e);
      return { before: src.yaml, error: m.cluster && /마지막/.test(msg) ? '클러스터 앱의 마지막 경로는 여기서 뺄 수 없습니다. 경로 설정을 통째로 지우려면 CLI에서 sfcli app down cluster-app/web을 씁니다.' : msg };
    }
  }, [src]);
  const after = fallbackOf(all, m.host, m.prefix, gwOf(m.gateways), m);
  const sharesHost = all.some((x) => x.key !== m.key && lc(x.host) === lc(m.host));
  const mu = useMutation();
  const go = async () => {
    if (!change?.after) return;
    const op = m.cluster ? await mu.run(clusterAppRoutesPath(), { expected: src?.revision ?? 0, file: change.after }, 'PUT') : await mu.run(`/t/${encodeURIComponent(m.tenant!)}/apps/deploy`, { yaml: change.after, digest: await yamlDigest(change.after), ...(deployment ? { deployment } : {}) });
    if (op && op.state !== 'failed' && op.state !== 'rejected') onDone();
  };
  const rps = rpsOf(m);
  return (
    <Dialog
      title="매핑 빼기"
      danger
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            {mu.op ? '닫기' : '취소'}
          </button>
          {!mu.op && (
            <button className="btn danger solid" disabled={!change?.after || mu.busy} onClick={() => void go()}>
              {mu.busy ? '보내는 중…' : m.cluster ? '빼고 저장' : '빼고 배포'}
            </button>
          )}
        </>
      }
    >
      <span className="small">
        <span className="mono">
          {m.host}
          {m.prefix}
        </span>{' '}
        → {targetPlain(m)} 매핑을 뺍니다. {m.cluster ? '클러스터 앱 경로 설정에서 지우고 바로 반영합니다.' : `${m.app} 앱 정의의 외부 접속 경로에서 지우고 배포합니다.`}
      </span>
      {src?.error !== undefined && <ErrorBand error={src.error} what="원문을 읽지 못했습니다" />}
      {!src && <span className="small muted">원문을 읽는 중…</span>}
      {change?.error && <div className="note er small">{change.error}</div>}
      {change?.after !== undefined && <DiffView lines={lineDiff(change.before, change.after)} />}
      <div className="note wa small" hidden={!!change?.error}>
        빼면 이 경로의 요청{m.flats.length ? `(최근 1분 ${n(rps)}/s)` : ''}은 {after ? `더 짧은 접두사 매핑 ${after.prefix} → ${targetPlain(after)}으로 갑니다. 그쪽에서 처리하지 않는 경로면 404가 납니다.` : '받을 매핑이 없어 404가 납니다.'}
      </div>
      {sharesHost && <span className="small muted">인증서와 DNS 레코드는 그대로 둡니다. 다른 매핑이 같은 호스트를 계속 쓰기 때문입니다.</span>}
      <MutationError error={mu.error} />
      {mu.op && <OpPanel op={mu.op} onChange={mu.setOp} />}
    </Dialog>
  );
}

function useDeployment(m: Mapping) {
  const [d, setD] = useState<string>();
  useEffect(() => {
    if (m.cluster || !m.tenant) return;
    const ac = new AbortController();
    apps(m.tenant, ac.signal)
      .then((p) => setD(p.items.find((a) => a.app === m.app)?.deployment))
      .catch(() => undefined);
    return () => ac.abort();
  }, [m.key]);
  return d;
}
