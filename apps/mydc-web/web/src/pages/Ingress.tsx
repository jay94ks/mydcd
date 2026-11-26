// SPDX-License-Identifier: Apache-2.0

// 공유 자원 › 외부 접속 (UI-5A 매핑 · UI-5C 긴급 차단, 캔버스 Ingress · IngressTenant · IngressBlock · IngressIx).
// 매핑 조회·요청 지표·긴급 차단 적용은 mydcd 몫이다. 데몬 계약이 오기 전까지 api/ingress.ts 모양으로 목업을 쓴다.
// 차단은 앱 정의(app.yaml)를 바꾸지 않고 작업 기록에 남는다. 서버·작업 공간·게이트웨이 범위는 시스템 관리자만 고른다.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError, newOpId } from '../api/client';
import { BLOCK_KIND_NAME, CIDR_RE, GW_NAME, GW_SHORT, RESP_NAME, addBlock, allSources, extendBlock, ingress, ingressBlocks, ingressHistory, gatewayPath, removeBlock, routeCertError, routeCertText, scopeText, type BlockKind, type BlockScope, type Gateway, type GatewayConf, type IngressBlock, type IngressInstance, type IngressNode, type IngressRoute, type IngressView, type IngressEvent } from '../api/ingress';
import { createLink, deleteLink, webhookLinks, webhooks, type Webhook, type WebhookLink } from '../api/webhooks';
import { useAuth, useSession } from '../auth/session';
import { Badge, Card, Field, HelpBox, KV, PageHeader, Segmented } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { Popover } from '../components/Popover';
import { useToast } from '../components/Toast';
import { ago, fmtTime } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { eulReul } from '../lib/josa';
import { lastBadge } from './IncidentHooks';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { Drawer } from '../components/Drawer';

type Tab = 'map' | 'blocks' | 'limits' | 'history';
type View = 'node' | 'tenant';
type GwFilter = 'all' | Gateway;
type RowFilter = 'all' | 'blocked' | 'problem';
const NEED_NET = '이 작업 공간에서 망(Network) 관리 권한이 있어야 긴급 차단할 수 있습니다. 작업 공간 관리자에게 요청하세요.';
const n = (x: number) => x.toLocaleString('ko-KR');
const left = (iso?: string) => {
  if (!iso) return '해제할 때까지';
  const m = Math.max(0, Math.round((Date.parse(iso) - Date.now()) / 60000));
  return m >= 60 ? `${Math.floor(m / 60)}시간 ${m % 60}분 남음` : `${m}분 남음`;
};
const since = (iso: string) => `${Math.max(1, Math.round((Date.now() - Date.parse(iso)) / 60000))}분째`;

export interface Flat {
  i: IngressInstance;
  r: IngressRoute;
}
export const flatten = (v: IngressView, gw: GwFilter = 'all') => v.instances.flatMap((i) => i.routes.filter((r) => gw === 'all' || r.gateway === gw).map((r) => ({ i, r })));
const problem = (f: Flat) => !!f.r.note || (f.r.err5xx ?? 0) >= 2 || f.r.backends.some((b) => b.slow || !b.health.ok || b.blocked);
export function routeStatus(r: IngressRoute, blocks: IngressBlock[], observed = true): ReactNode {
  if (r.blocked) {
    const b = blocks.find((x) => x.id === r.blocked);
    return <Badge tone="er">⛔ {b ? (b.response === 'drop' ? '끊김' : b.response) : '차단'}</Badge>;
  }
  if (r.note) return <Badge tone="wa">{r.note}</Badge>;
  // mydcd가 그 서버의 실행 상태를 아직 못 봄: 수치가 없으니 정상이라 하지 않는다.
  if (!observed) return <Badge tone="un">관찰 전</Badge>;
  if ((r.err5xx ?? 0) >= 2 || r.backends.some((b) => b.slow)) return <Badge tone="wa">느림·오류</Badge>;
  return <Badge tone="ok">정상</Badge>;
}
export function backendsText(r: IngressRoute): ReactNode {
  if (r.redirect) return `→ ${r.redirect} 넘김`;
  if (!r.backends.length) return '—';
  return r.backends.map((b, k) => (
    <span key={b.task}>
      {k > 0 && ' · '}
      <span style={b.blocked || !b.health.ok ? { color: 'var(--er, #A0111F)' } : undefined}>
        {b.task} @{b.node.replace(/^node-/, '')}
        {b.blocked ? ' 빠짐' : b.slow ? ' (느림)' : ''}
      </span>
    </span>
  ));
}
const metric = (r: IngressRoute) => (r.blocked ? `${r.rps}/s (차단)` : `${n(r.rps)}/s${r.err5xx !== undefined && r.err5xx > 0 ? ` · 5xx ${r.err5xx}%` : ''}`);

export function IngressPage() {
  return usePhone() ? <MIngress /> : <DesktopIngress />;
}

/** 휴대폰 외부 접속 (UI-M11 ③): 보기만 한 줄 · 차단 카드 · 요약 두 칸 · 호스트·경로 규칙 목록 */
function MIngress() {
  const session = useSession();
  const admin = !!session?.user.systemAdmin;
  const navigate = useNavigate();
  const q = usePoll((s) => ingress({}, s), [], 5_000);
  const bq = usePoll((s) => ingressBlocks(s), [], 5_000);
  // 해제 중(lifting)인 차단은 걸린 차단으로 세지 않는다.
  const blocks = (bq.data?.items ?? []).filter((b) => b.state !== 'lifting');
  const [view, setView] = useState<'blocks' | Flat>();
  useMobileTop(
    {
      title: '외부 접속',
      sub: admin ? '서버별 · 시스템 관리자' : '작업 공간별',
      wide: '차단 만들기·규칙 바꾸기는 넓은 화면에서',
      menu: [
        { label: '✦ 코디네이터에게 차단 부탁', onSelect: () => navigate('/coordinator', { state: { from: '/shared/ingress' } }) },
        { label: '⛔ 긴급 차단', wide: true, danger: true },
      ],
    },
    [admin],
  );
  const appOf = (b: IngressBlock) => b.scope.app ?? q.data?.instances.find((i) => i.routes.some((r) => r.host === b.scope.host))?.app;
  const blockLine = (b: IngressBlock) => (
    <>
      {appOf(b) ? `${appOf(b)} · ` : ''}
      <span className="mono">{b.scope.kind === 'route' ? `${b.scope.host}${b.scope.prefix}` : b.scope.kind === 'source' ? (b.scope.sources ?? []).join(', ') : scopeText(b.scope)}</span>
      {b.scope.kind === 'source' ? ' 출발지' : ''} → {RESP_NAME[b.response]} · {b.by} · {b.until ? left(b.until) : since(b.at)}
    </>
  );
  return (
    <>
      {blocks.length > 0 && (
        <div className="mc xer">
          <div className="hd">
            <b>⛔ 차단 중 {blocks.length}</b>
            <button type="button" className="linkish" style={{ fontSize: 13 }} onClick={() => setView('blocks')}>
              차단 목록 ›
            </button>
          </div>
          {blocks.slice(0, 2).map((b) => (
            <div key={b.id} className="ln">
              {blockLine(b)}
            </div>
          ))}
        </div>
      )}
      <Load q={q} what="외부 접속을 읽지 못했습니다">
        {(v) => {
          const up = (k: 'external' | 'local') => v.nodes.filter((x) => x.module && x[k]?.state === 'listening').length;
          const dead = v.nodes.filter((x) => x.module && x.external?.state !== 'listening' && x.local?.state !== 'listening').map((x) => x.node);
          const rows = flatten(v);
          return (
            <>
              <div className="mtiles">
                <div className="mtile">
                  <small>게이트웨이</small>
                  <b>
                    {up('external')} · {up('local')}
                  </b>
                  <span>{dead.length ? `${dead.join(', ')} 모두 꺼짐` : '외부망 · 로컬망 받는 중'}</span>
                </div>
                <div className="mtile">
                  <small>요청 (1분)</small>
                  <b>{n(v.summary.rps)}/s</b>
                  <span>
                    5xx {v.summary.err5xx}% · p95 {v.summary.p95Ms} ms
                  </span>
                </div>
              </div>
              <div className="m-sec">
                <span>호스트 · 경로 규칙</span>
                <span className="muted">{rows.length}</span>
              </div>
              {rows.length === 0 ? (
                <span className="muted small">경로 규칙이 없습니다.</span>
              ) : (
                <div className="li">
                  {rows.map((f) => (
                    <button key={`${f.i.tenant}/${f.i.app}/${f.r.id}`} type="button" onClick={() => setView(f)}>
                      <span className="el">
                        {f.r.host} {f.r.prefix}
                      </span>
                      <span className="r">{f.r.blocked ? <Badge tone="er">차단 중</Badge> : f.r.note || (f.r.err5xx ?? 0) >= 2 ? <Badge tone="wa">{f.r.note ?? '느림·오류'}</Badge> : f.i.app}</span>
                    </button>
                  ))}
                </div>
              )}
              <span className="muted small" style={{ textAlign: 'center' }}>
                매핑 그림 · 한도·사용량 · 기록은 넓은 화면에서
              </span>
            </>
          );
        }}
      </Load>
      {view === 'blocks' && (
        <Drawer title="차단 목록" onClose={() => setView(undefined)}>
          {blocks.map((b) => (
            <div key={b.id} className="mc xer">
              <div className="hd">
                <b>{BLOCK_KIND_NAME[b.scope.kind]}</b>
                <Badge tone="er">{RESP_NAME[b.response]}</Badge>
              </div>
              <div className="ln">{blockLine(b)}</div>
              <div className="ln muted" style={{ fontSize: 12 }}>
                {b.reason} · 막은 요청 {n(b.blockedRequests)}
              </div>
            </div>
          ))}
          {blocks.length === 0 && <span className="muted small">차단이 없습니다.</span>}
          <span className="muted small">해제·연장은 넓은 화면에서 · 급하면 코디네이터에게 부탁하세요</span>
        </Drawer>
      )}
      {view && view !== 'blocks' && (
        <Drawer title={`${view.r.host}${view.r.prefix}`} onClose={() => setView(undefined)}>
          <div className="mc">
            <div className="hd">
              <b>{view.i.app}</b>
              {routeStatus(view.r, blocks, view.i.observed !== false)}
            </div>
            <dl className="mkv">
              <dt>작업 공간</dt>
              <dd>{view.i.tenant}</dd>
              <dt>게이트웨이</dt>
              <dd>
                {GW_NAME[view.r.gateway]} :{view.r.port}
              </dd>
              <dt>서비스</dt>
              <dd>{view.r.redirect ? `→ ${view.r.redirect} 넘김` : `${view.r.service ?? '—'}${view.r.servicePort ? `:${view.r.servicePort}` : ''}`}</dd>
              <dt>인증서</dt>
              <dd>
                {view.r.certificates?.some((c) => c.id) ? (
                  view.r.certificates
                    .filter((c) => c.id)
                    .map((c, i) => (
                      <span key={c.id}>
                        {i > 0 && ' · '}
                        {admin ? (
                          <Link className="mono" to={`/system/domains/certs/${c.id}`}>
                            {c.id!.slice(0, 12)}
                          </Link>
                        ) : (
                          <span className="mono">{c.id!.slice(0, 12)}</span>
                        )}
                        {view.r.certificates!.length > 1 && c.alg ? ` (${c.alg === 'rsa' ? 'RSA' : 'ECDSA'})` : ''}
                      </span>
                    ))
                ) : routeCertText(view.r) ? (
                  routeCertText(view.r)
                ) : (
                  '없음'
                )}
                {routeCertError(view.r) && <span className="muted small"> · {routeCertError(view.r)}</span>}
              </dd>
              <dt>요청</dt>
              <dd>{metric(view.r)}</dd>
            </dl>
          </div>
          <div className="m-sec">
            <span>컨테이너 {view.r.backends.length}</span>
          </div>
          <div className="li">
            {view.r.backends.map((b) => (
              <div key={b.task}>
                <span className="el mono" style={{ fontSize: 12 }}>
                  {b.task} @ {b.node}
                </span>
                <span className="r">{b.blocked ? <Badge tone="er">빠짐</Badge> : !b.health.ok ? <Badge tone="er">검사 실패</Badge> : b.slow ? <Badge tone="wa">느림</Badge> : <Badge tone="ok">정상</Badge>}</span>
              </div>
            ))}
            {view.r.backends.length === 0 && <div className="muted">없음</div>}
          </div>
        </Drawer>
      )}
    </>
  );
}

function DesktopIngress() {
  const session = useSession();
  const admin = !!session?.user.systemAdmin;
  const [sp, setSp] = useSearchParams();
  const tab = (sp.get('tab') as Tab) || 'map';
  const view: View = admin ? ((sp.get('view') as View) || 'node') : 'tenant';
  const pick = sp.get('pick') ?? '';
  const [gw, setGw] = useState<GwFilter>('all');
  const set = (k: string, v: string) => {
    const p = new URLSearchParams(sp);
    if (v) p.set(k, v);
    else p.delete(k);
    if (k === 'view') p.delete('pick');
    setSp(p, { replace: true });
  };
  const q = usePoll((s) => ingress(view === 'node' && pick ? { node: pick } : view === 'tenant' && pick ? { tenant: pick } : {}, s), [view, pick], 5_000);
  const bq = usePoll((s) => ingressBlocks(s), [], 5_000);
  const [block, setBlock] = useState<BlockScope | 'new'>();
  // 차단 탭은 해제 중인 것까지 보여 주고, 나머지(띠·지도)는 걸린 것만 쓴다.
  const allBlocks = bq.data?.items ?? [];
  const blocks = allBlocks.filter((b) => b.state !== 'lifting');
  const all = usePoll((s) => ingress({}, s), [], 30_000);
  const nodeNames = all.data?.nodes.map((x) => x.node) ?? [];
  const tenantNames = all.data?.tenants.map((x) => x.tenant) ?? [];
  return (
    <div className="page">
      <PageHeader
        title="외부 접속"
        ids="UI-5A"
        after={
          <>
            <Badge tone="un">{admin ? '서버별 · 시스템 관리자' : '작업 공간별 · 작업 공간 사용자는 자기 작업 공간만'}</Badge>
            {q.data && <Badge tone="ok">실시간 · {ago(q.data.observedAt)}</Badge>}
          </>
        }
        actions={
          <>
            <Link className="btn" to="/system/domains">
              외부 도메인 ↗
            </Link>
            <button className="btn estop" onClick={() => setBlock('new')}>
              ⛔ 긴급 차단
            </button>
          </>
        }
      />
      <div className="row between" style={{ flexWrap: 'wrap', gap: 12 }}>
        <span className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
          <Segmented<View> label="보기" value={view} onChange={(v) => set('view', v)} options={[['node', '서버별'], ['tenant', '작업 공간별']]} disabled={admin ? undefined : { node: '서버별 보기는 시스템 관리자만 봅니다' }} />
          <select value={pick} onChange={(e) => set('pick', e.target.value)} style={{ height: 32 }} aria-label={view === 'node' ? '서버' : '작업 공간'}>
            <option value="">
              {view === 'node' ? `서버: 전체 (${nodeNames.length})` : `작업 공간: 전체 (${tenantNames.length})`}
            </option>
            {(view === 'node' ? nodeNames : tenantNames).map((x) => (
              <option key={x} value={x}>
                {x}
              </option>
            ))}
          </select>
          <Segmented<GwFilter>
            label="게이트웨이"
            value={gw}
            onChange={setGw}
            options={[
              ['all', '게이트웨이 전체'],
              ['external', '외부망'],
              ['local', '로컬망'],
            ]}
          />
        </span>
        <nav className="tabs sub" style={{ border: 0 }}>
          {(
            [
              ['map', '매핑'],
              ['blocks', `차단 (${blocks.length})`],
              ['limits', '한도·사용량'],
              ['history', '기록'],
            ] as [Tab, string][]
          ).map(([k, l]) => (
            <a
              key={k}
              href={`?tab=${k}`}
              className={tab === k ? 'active' : ''}
              onClick={(e) => {
                e.preventDefault();
                set('tab', k === 'map' ? '' : k);
              }}
            >
              {l}
            </a>
          ))}
        </nav>
      </div>
      {view === 'node' && (
        <HelpBox terms="외부 접속 (ingress gateway) · 외부망 게이트웨이 (external gateway) · 로컬망 게이트웨이 (local gateway) · 공유 수신 주소 (shared listener) · L7 경로 규칙 (route: 호스트 + 경로 접두사) · 서비스 (service) · 컨테이너 (backend task) · 긴급 차단 (emergency block) · 출발지 (source IP/CIDR)">
          <b>이 화면은</b> 바깥에서 들어온 요청이 어느 서버의 어느 수신 주소로 들어와, 어떤 호스트·경로 규칙을 거쳐, 어떤 서비스의 어느 컨테이너로 가는지 보여 줍니다. 게이트웨이는 서버마다 두 종류입니다. <b>외부망 게이트웨이</b>는 인터넷 쪽 주소로 들어오는 요청을, <b>로컬망 게이트웨이</b>는 사내·로컬 네트워크 쪽 주소로만 받습니다. 앱은 경로 규칙마다 어느 게이트웨이로 노출할지 고르고(기본은 로컬망), 각 게이트웨이의 :443·:80 하나를 여러 앱·작업 공간이 호스트 이름으로 나눠 씁니다(HTTP/HTTPS만, 인증서는 호스트마다). 문제가 생기면 <b>긴급 차단</b>으로 경로 규칙·도메인·컨테이너·앱·출발지 IP·서버·작업 공간 단위로 바로 막고, 원인을 고친 뒤 해제합니다. 차단은 앱 정의(app.yaml)를 바꾸지 않으며 모두 작업 기록에 남습니다.
        </HelpBox>
      )}
      {blocks.length > 0 && tab !== 'blocks' && <BlockBand blocks={blocks} onList={() => set('tab', 'blocks')} view={q.data} />}
      <Load q={q} what="외부 접속을 읽지 못했습니다">
        {(v) => (
          <>
            {tab === 'map' && <MapTab v={v} gw={gw} view={view} admin={admin} blocks={blocks} onBlock={setBlock} onRelease={() => (void bq.refresh(), void q.refresh())} />}
            {tab === 'blocks' && <BlocksTab blocks={allBlocks} admin={admin} v={v} onChange={() => (void bq.refresh(), void q.refresh())} />}
            {tab === 'limits' && <LimitsTab v={v} />}
            {tab === 'history' && <HistoryTab />}
          </>
        )}
      </Load>
      {block && all.data && (
        <BlockDialog
          v={all.data}
          preset={block === 'new' ? undefined : block}
          admin={admin}
          onClose={() => setBlock(undefined)}
          onDone={() => {
            void bq.refresh();
            void q.refresh();
          }}
        />
      )}
    </div>
  );
}

function BlockBand({ blocks, onList, view }: { blocks: IngressBlock[]; onList: () => void; view?: IngressView }) {
  const appOf = (b: IngressBlock) => b.scope.app ?? view?.instances.find((i) => i.routes.some((r) => r.host === b.scope.host))?.app;
  return (
    <div className="band-er">
      <b style={{ fontSize: 14 }}>⛔ 차단 중 {blocks.length}</b>
      {blocks.slice(0, 3).map((b, k) => (
        <span key={b.id}>
          {k > 0 && <span className="muted">· </span>}
          {appOf(b) ? `${appOf(b)} ` : ''}
          <span className="mono">{b.scope.kind === 'route' ? `${b.scope.host}${b.scope.prefix}` : b.scope.kind === 'source' ? (b.scope.sources ?? []).join(', ') : scopeText(b.scope)}</span>
          {b.scope.kind === 'source' ? ' 출발지' : ''} → {RESP_NAME[b.response]} · {b.by} · {b.until ? left(b.until) : `${since(b.at)} · 해제할 때까지`}
        </span>
      ))}
      <span style={{ flex: 1 }} />
      <button className="textbtn plain" style={{ fontWeight: 600 }} onClick={onList}>
        차단 목록 →
      </button>
    </div>
  );
}

// ── 매핑 탭 ──────────────────────────────

function MapTab({ v, gw, view, admin, blocks, onBlock, onRelease }: { v: IngressView; gw: GwFilter; view: View; admin: boolean; blocks: IngressBlock[]; onBlock: (s: BlockScope) => void; onRelease: () => void }) {
  const rows = flatten(v, gw);
  const ext = v.nodes.filter((x) => x.external).length;
  const loc = v.nodes.filter((x) => x.local).length;
  const offNotes = v.nodes
    .filter((x) => !x.external || !x.local)
    .map((x) => (!x.module ? `${x.node} 모두 꺼짐` : `${x.node} ${!x.external ? '외부망' : '로컬망'} 꺼짐`))
    .join(' · ');
  const listeners = new Set(rows.map((f) => `${f.i.node}/${f.r.gateway}/${f.r.port}`));
  const tenants = new Set(v.instances.map((i) => i.tenant));
  const routeBlocks = blocks.filter((b) => ['route', 'host', 'app'].includes(b.scope.kind)).length;
  const srcBlocks = blocks.filter((b) => b.scope.kind === 'source').length;
  return (
    <>
      {view === 'node' && (
        <div className="grid tiles">
          <div className="tile">
            <span className="label">게이트웨이 (외부망 · 로컬망)</span>
            <b>
              {ext} · {loc}
            </b>
            <span className="small muted">{offNotes || '모든 서버 수신 중'}</span>
          </div>
          <div className="tile">
            <span className="label">공유 수신 주소 · 호스트 규칙</span>
            <b>
              {listeners.size} · {rows.filter((f) => !f.r.redirect).length + rows.filter((f) => f.r.redirect).length}
            </b>
            <span className="small muted">
              앱 {v.instances.length}개 · 작업 공간 {tenants.size}개 · HTTP/HTTPS
            </span>
          </div>
          <div className="tile">
            <span className="label">요청 (최근 1분)</span>
            <b>{n(v.summary.rps)}/s</b>
            <span className="small muted">
              5xx {v.summary.err5xx}% · p95 {v.summary.p95Ms} ms
            </span>
          </div>
          <div className="tile">
            <span className="label">긴급 차단</span>
            <b>{blocks.length}</b>
            <span className="small muted">
              경로 {routeBlocks} · 출발지 {srcBlocks}
              {blocks.length - routeBlocks - srcBlocks > 0 ? ` · 그 밖 ${blocks.length - routeBlocks - srcBlocks}` : ''}
            </span>
          </div>
        </div>
      )}
      {view === 'node' && <FlowCard v={v} gw={gw} blocks={blocks} onBlock={onBlock} />}
      <MapTable v={v} gw={gw} view={view} blocks={blocks} onBlock={onBlock} onRelease={onRelease} />
      {view === 'tenant' && <TenantLimits v={v} />}
      {view === 'node' && admin && <GatewaysCard v={v} onDone={onRelease} />}
      {view === 'node' && <GatewayHooks admin={admin} nodes={v.nodes} />}
    </>
  );
}

// 매핑 그림: 게이트웨이·수신 주소 → 호스트·경로 → 서비스 → 컨테이너
const COLS = [
  { x: 0, w: 230, title: '게이트웨이 · 수신 주소' },
  { x: 290, w: 250, title: '호스트 · 경로 규칙' },
  { x: 600, w: 190, title: '서비스' },
  { x: 850, w: 230, title: '컨테이너 (서버 · 상태)' },
];
const ROW = 58;
const TOP = 24;
const BOX = 46;
interface FNode {
  id: string;
  col: number;
  title: string;
  sub: string;
  cls?: 'bad' | 'off';
  menu?: { label: string; scope: BlockScope };
  info?: string;
}
interface FEdge {
  a: string;
  b: string;
  color: string;
  dash?: boolean;
}
function buildFlow(v: IngressView, gw: GwFilter, blocks: IngressBlock[]) {
  const nodes = new Map<string, FNode>();
  const edges: FEdge[] = [];
  const add = (x: FNode) => !nodes.has(x.id) && nodes.set(x.id, x);
  const color = (g: Gateway) => (g === 'external' ? '#1F5FBF' : '#6E40C9');
  for (const { i, r } of flatten(v, gw)) {
    const conf = v.nodes.find((x) => x.node === i.node)?.[r.gateway];
    const lid = `l:${i.node}/${r.gateway}/${r.port}`;
    add({ id: lid, col: 0, title: `${i.node} · ${GW_NAME[r.gateway]} :${r.port}`, sub: r.redirect ? 'http → https 넘김' : `${conf?.address ?? ''}${r.gateway === 'local' ? ' · 사내망만' : ''}` });
    // 같은 앱이 여러 서버에 있으면 규칙 id가 겹치므로 서버를 붙인다.
    const rid = `r:${i.node}/${r.id}`;
    const blk = r.blocked ? blocks.find((b) => b.id === r.blocked) : undefined;
    add({ id: rid, col: 1, title: `${r.host} ${r.prefix}`.trim(), sub: blk ? `⛔ 차단 중 · ${RESP_NAME[blk.response]}` : r.redirect ? '→ https 넘김' : `${i.app}${i.tenant !== 'shop' ? ` (${i.tenant})` : ''}${r.note ? ` · ${r.note}` : routeCertText(r) ? ` · 인증서 ${routeCertText(r)}` : ''}`, cls: blk ? 'bad' : undefined, menu: { label: '⛔ 이 경로 차단…', scope: { kind: 'route', tenant: i.tenant, app: i.app, node: i.node, host: r.host, prefix: r.prefix, gateway: r.gateway } }, info: `${i.app} · ${n(r.rps)}/s${r.err5xx ? ` · 5xx ${r.err5xx}%` : ''}${r.p95Ms ? ` · p95 ${r.p95Ms}ms` : ''}` });
    edges.push({ a: lid, b: rid, color: blk ? '#CF222E' : r.redirect ? '#8A919C' : color(r.gateway), dash: !!blk || !!r.redirect });
    if (!r.service) continue;
    const sid = `s:${i.tenant}/${i.app}/${r.service}`;
    add({ id: sid, col: 2, title: `${r.service} :${r.servicePort}`, sub: `${i.app} · ${i.tenant}`, cls: blk ? 'off' : undefined });
    edges.push({ a: rid, b: sid, color: blk ? '#CF222E' : color(r.gateway), dash: !!blk });
    for (const b of r.backends) {
      const bid = `b:${i.tenant}/${i.app}/${b.task}`;
      add({ id: bid, col: 3, title: `${b.task} @ ${b.node}`, sub: b.blocked ? `⛔ 빠짐 (긴급) · 0 req/s` : !b.health.ok ? `상태 검사 실패 · ${b.health.error ?? ''}` : b.slow ? `느림 · p95 ${((b.p95Ms ?? 0) / 1000).toFixed(1)}초` : `정상 · 가중치 ${b.weight} · ${b.rps} req/s${b.node !== i.node ? ' · 원격' : ''}`, cls: b.blocked || !b.health.ok ? 'bad' : undefined, menu: { label: '⛔ 이 컨테이너 빼기…', scope: { kind: 'task', tenant: i.tenant, app: i.app, node: i.node, task: b.task } } });
      if (!edges.some((e) => e.a === sid && e.b === bid)) edges.push({ a: sid, b: bid, color: b.blocked || blk ? '#CF222E' : b.slow ? '#BF8700' : color(r.gateway), dash: !!b.blocked || !!blk });
    }
  }
  // 열마다 위에서부터 차례로 둔다
  const byCol = [0, 1, 2, 3].map((c) => [...nodes.values()].filter((x) => x.col === c));
  const pos = new Map<string, number>();
  byCol.forEach((list) => list.forEach((x, k) => pos.set(x.id, TOP + k * ROW)));
  const height = TOP + Math.max(...byCol.map((l) => l.length), 1) * ROW;
  return { nodes: [...nodes.values()], edges, pos, height };
}
function FlowCard({ v, gw, blocks, onBlock }: { v: IngressView; gw: GwFilter; blocks: IngressBlock[]; onBlock: (s: BlockScope) => void }) {
  const [sel, setSel] = useState<string>();
  const nav = useNavigate();
  const f = useMemo(() => buildFlow(v, gw, blocks), [v, gw, blocks]);
  // 누른 상자와 이어진 흐름 (앞뒤로)
  const lit = useMemo(() => {
    if (!sel) return undefined;
    const s = new Set([sel]);
    let grew = true;
    while (grew) {
      grew = false;
      for (const e of f.edges) {
        const ca = f.nodes.find((x) => x.id === e.a)!.col;
        const cs = f.nodes.find((x) => x.id === sel)!.col;
        if (s.has(e.b) && ca < cs && !s.has(e.a)) (s.add(e.a), (grew = true));
        if (s.has(e.a) && ca >= cs && !s.has(e.b)) (s.add(e.b), (grew = true));
      }
    }
    return s;
  }, [sel, f]);
  const y = (id: string) => (f.pos.get(id) ?? 0) + BOX / 2;
  const selNode = f.nodes.find((x) => x.id === sel);
  return (
    <Card
      title="매핑 그림"
      actions={
        <span className="row small muted" style={{ gap: 10 }}>
          <span>
            <b style={{ color: '#1F5FBF' }}>━</b> 외부망
          </span>
          <span>
            <b style={{ color: '#6E40C9' }}>━</b> 로컬망
          </span>
          <span>
            <b style={{ color: '#CF222E' }}>┅</b> 차단됨
          </span>
          <span>
            <b style={{ color: '#8A919C' }}>┅</b> 넘김·대기
          </span>
          <span>
            <b style={{ color: '#BF8700' }}>━</b> 느림
          </span>
        </span>
      }
    >
      <div className="flow-wrap">
        <div className="flow" style={{ height: f.height + 8 }}>
          <svg width={1080} height={f.height + 8} aria-hidden>
            {f.edges.map((e, k) => {
              const a = f.nodes.find((x) => x.id === e.a)!;
              const b = f.nodes.find((x) => x.id === e.b)!;
              const x1 = COLS[a.col].x + COLS[a.col].w;
              const x2 = COLS[b.col].x;
              const mx = (x1 + x2) / 2;
              const dim = lit && !(lit.has(e.a) && lit.has(e.b));
              return <path key={k} d={`M${x1},${y(e.a)} C${mx},${y(e.a)} ${mx},${y(e.b)} ${x2},${y(e.b)}`} fill="none" stroke={e.color} strokeWidth={lit && !dim ? 3 : 2} strokeDasharray={e.dash ? '5 4' : undefined} opacity={dim ? 0.18 : 1} />;
            })}
          </svg>
          {COLS.map((c) => (
            <div key={c.title} className="fh" style={{ left: c.x, width: c.w }}>
              {c.title}
            </div>
          ))}
          {f.nodes.map((x) => (
            <div
              key={x.id}
              className={`fn ${x.cls ?? ''} ${sel === x.id ? 'sel' : ''}`}
              style={{ left: COLS[x.col].x, top: f.pos.get(x.id), width: COLS[x.col].w, height: BOX, opacity: lit && !lit.has(x.id) ? 0.35 : 1 }}
              role="button"
              tabIndex={0}
              onClick={() => setSel(sel === x.id ? undefined : x.id)}
              onKeyDown={(e) => e.key === 'Enter' && setSel(sel === x.id ? undefined : x.id)}
              onContextMenu={(e) => {
                if (!x.menu) return;
                e.preventDefault();
                onBlock(x.menu.scope);
              }}
              title={x.menu ? '오른쪽 클릭으로 긴급 차단' : undefined}
            >
              <b>{x.title}</b>
              <span>{x.sub}</span>
            </div>
          ))}
        </div>
      </div>
      {selNode ? (
        <div className="row small" style={{ gap: 8, flexWrap: 'wrap' }}>
          <b>{selNode.title}</b>
          {selNode.info && <span className="muted">{selNode.info}</span>}
          {selNode.id.startsWith('b:') && (
            <button className="btn sm" onClick={() => nav(`/deploy/apps/${selNode.id.slice(2).split('/')[0]}/${selNode.id.slice(2).split('/')[1]}`)}>
              앱 열기
            </button>
          )}
          {selNode.id.startsWith('r:') && (
            <button className="btn sm" onClick={() => nav(`/shared/ingress/${selNode.menu!.scope.tenant}/${selNode.menu!.scope.app}?node=${encodeURIComponent(selNode.menu!.scope.node ?? '')}`)}>
              경로 상세
            </button>
          )}
          {selNode.menu && (
            <button className="btn sm danger" onClick={() => onBlock(selNode.menu!.scope)}>
              {selNode.menu.label}
            </button>
          )}
        </div>
      ) : (
        <span className="small muted">상자를 누르면 그 상자와 이어진 흐름만 강조됩니다. 상자 오른쪽 클릭(또는 아래 단추)으로 그 단위를 바로 긴급 차단할 수 있습니다.</span>
      )}
    </Card>
  );
}

function MapTable({ v, gw, view, blocks, onBlock, onRelease }: { v: IngressView; gw: GwFilter; view: View; blocks: IngressBlock[]; onBlock: (s: BlockScope) => void; onRelease: () => void }) {
  const [filter, setFilter] = useState<RowFilter>('all');
  const [find, setFind] = useState('');
  const [release, setRelease] = useState<IngressBlock>();
  const nav = useNavigate();
  const { tenants } = useSession();
  const admin = !!useSession().user.systemAdmin;
  const canNet = (t: string) => admin || tenants.some((x) => x.id === t && x.role === 'manager');
  const rows = flatten(v, gw).filter((f) => (filter === 'blocked' ? !!f.r.blocked || f.r.backends.some((b) => b.blocked) : filter === 'problem' ? problem(f) : true) && (!find || `${f.r.host}${f.r.prefix} ${f.i.app} ${f.r.backends.map((b) => b.task).join(' ')}`.toLowerCase().includes(find.toLowerCase())));
  const groups = view === 'node' ? v.nodes.map((x) => ({ key: x.node, rows: rows.filter((f) => f.i.node === x.node), node: x })) : v.tenants.map((t) => ({ key: t.tenant, rows: rows.filter((f) => f.i.tenant === t.tenant), t }));
  const cols = view === 'node' ? '0.8fr 1.35fr 1.2fr 1.3fr 0.9fr 0.85fr 72px' : '1.1fr 1fr 1.35fr 1.3fr 0.9fr 0.75fr 72px';
  const act = (f: Flat) => {
    if (f.r.blocked) {
      const b = blocks.find((x) => x.id === f.r.blocked);
      return (
        <button className="btn sm" disabled={!b || !canNet(f.i.tenant)} title={canNet(f.i.tenant) ? undefined : NEED_NET} onClick={(e) => (e.stopPropagation(), b && setRelease(b))}>
          해제
        </button>
      );
    }
    return (
      <Menu
        label={`${f.r.host}${f.r.prefix} 차단`}
        button="⛔ 차단"
        className="btn sm stop"
        items={[
          { label: '이 경로 차단', hint: `${f.r.host} ${f.r.prefix}`, onSelect: () => onBlock({ kind: 'route', tenant: f.i.tenant, app: f.i.app, node: f.i.node, host: f.r.host, prefix: f.r.prefix, gateway: f.r.gateway }), disabledReason: canNet(f.i.tenant) ? undefined : NEED_NET },
          { label: '이 앱 전체 차단', hint: f.i.app, onSelect: () => onBlock({ kind: 'app', tenant: f.i.tenant, app: f.i.app }), disabledReason: canNet(f.i.tenant) ? undefined : NEED_NET },
          { label: '컨테이너 하나만 빼기…', hint: f.r.backends.map((b) => b.task).join(' · ') || '—', onSelect: () => onBlock({ kind: 'task', tenant: f.i.tenant, app: f.i.app, task: f.r.backends.find((b) => !b.blocked)?.task }), disabledReason: !f.r.backends.length ? '넘김 규칙에는 컨테이너가 없습니다' : canNet(f.i.tenant) ? undefined : NEED_NET },
        ]}
      />
    );
  };
  return (
    <Card
      title={`매핑 표 · ${view === 'node' ? '서버별' : '작업 공간별'}`}
      actions={
        <span className="row" style={{ gap: 8 }}>
          {view === 'node' && <input placeholder="호스트·경로·컨테이너 찾기" value={find} onChange={(e) => setFind(e.target.value)} style={{ height: 32, width: 220 }} />}
          <Segmented<RowFilter>
            label="줄 거르기"
            value={filter}
            onChange={setFilter}
            options={[
              ['all', '전체'],
              ['blocked', '차단 중'],
              ['problem', '문제 있음'],
            ]}
          />
        </span>
      }
    >
      <div className="table-x">
        <div className="gtbl" style={{ minWidth: 1000 }}>
          <div className="gr th" style={{ gridTemplateColumns: cols }}>
            {view === 'node' ? (
              <>
                <span>게이트웨이 · 포트</span>
                <span>호스트 · 경로</span>
                <span>서비스</span>
                <span>컨테이너</span>
                <span>요청 · 오류</span>
                <span>상태</span>
                <span />
              </>
            ) : (
              <>
                <span>앱 · 서비스</span>
                <span>서버 · 게이트웨이</span>
                <span>호스트 · 경로</span>
                <span>컨테이너</span>
                <span>요청 · 5xx</span>
                <span>상태</span>
                <span />
              </>
            )}
          </div>
          {groups.map((g) => (
            <div key={g.key} style={{ display: 'contents' }}>
              <div className="gr grp" style={{ gridTemplateColumns: cols }}>
                <span style={{ gridColumn: '1/-1', color: 'node' in g && !g.node.module ? 'var(--muted)' : 't' in g && !g.rows.length ? 'var(--muted)' : undefined }}>{'node' in g ? nodeLine(g.node, v) : tenantLine(g.t!, v)}</span>
              </div>
              {g.rows.map((f) => (
                <div key={`${f.i.node}/${f.i.tenant}/${f.i.app}/${f.r.id}`} className={`gr click ${f.r.blocked ? 'blk' : ''}`} style={{ gridTemplateColumns: cols }} role="link" tabIndex={0} onClick={() => nav(`/shared/ingress/${f.i.tenant}/${f.i.app}?node=${encodeURIComponent(f.i.node)}`)} onKeyDown={(e) => e.key === 'Enter' && nav(`/shared/ingress/${f.i.tenant}/${f.i.app}?node=${encodeURIComponent(f.i.node)}`)}>
                  {view === 'node' ? (
                    <>
                      <span className="mono" style={f.r.gateway === 'local' ? { color: '#6E40C9' } : undefined}>
                        {GW_SHORT[f.r.gateway]} :{f.r.port}
                      </span>
                      <span className="mono small">{`${f.r.host} ${f.r.prefix}`.trim()}</span>
                      <span>{f.r.service ? `${f.i.app} · ${f.r.service} :${f.r.servicePort}` : `→ ${f.r.redirect} 넘김`}</span>
                    </>
                  ) : (
                    <>
                      <span>
                        <b>{f.i.app}</b>
                        {f.r.service ? ` · ${f.r.service}` : ''}
                      </span>
                      <span className="mono">
                        {f.i.node} {GW_SHORT[f.r.gateway]} :{f.r.port}
                      </span>
                      <span className="mono small">{`${f.r.host} ${f.r.prefix}`.trim()}</span>
                    </>
                  )}
                  {f.i.observed === false ? <span className="muted">—</span> : <span className="small">{backendsText(f.r)}</span>}
                  {f.i.observed === false ? <span className="mono small muted">—</span> : <span className="mono small">{metric(f.r)}</span>}
                  <span>{routeStatus(f.r, blocks, f.i.observed !== false)}</span>
                  <span onClick={(e) => e.stopPropagation()}>{act(f)}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
      <span className="small muted">줄을 누르면 그 경로의 상세(UI-5B)가 열립니다. 컨테이너 이름은 상세에서 컨테이너 화면(UI-3A)으로 이어집니다. 숫자는 최근 1분 평균이며 서버별 외부 접속 관측에서 옵니다.</span>
      {release && <ReleaseDialog b={release} onClose={() => setRelease(undefined)} onDone={onRelease} />}
    </Card>
  );
}
function nodeLine(x: IngressNode, v: IngressView): string {
  if (!x.module) return `${x.node} · 외부 접속 꺼짐 (서버 설정 modules.ingress)${x.isolated ? ' · 격리됨' : ''}`;
  const rules = flatten(v).filter((f) => f.i.node === x.node).length;
  const apps = new Set(v.instances.filter((i) => i.node === x.node).map((i) => i.app)).size;
  const gw = (g?: IngressNode['external']) => (g ? `${g.address} (${g.ports.map((p) => `:${p}`).join(' ')})` : '꺼짐');
  return `${x.node} · 외부망 ${gw(x.external)} · 로컬망 ${gw(x.local)} · 호스트 규칙 ${rules} · 앱 ${apps} · 연결 ${n(x.connections)} / 한도 ${n(x.connectionLimit)} · 요청 ${n(x.rps)}/s`;
}
function tenantLine(t: IngressView['tenants'][number], v: IngressView): string {
  const ins = v.instances.filter((i) => i.tenant === t.tenant);
  if (!ins.length) return `${t.tenant} · 외부 접속 없음${t.usage.length ? '' : ' · 한도 없음 (서버별 한도를 주지 않음)'}`;
  const rules = ins.reduce((s, i) => s + i.routes.length, 0);
  const conns = t.usage.reduce((s, u) => s + u.connections[0], 0);
  const lim = t.usage.reduce((s, u) => s + u.connections[1], 0);
  const insLim = t.usage.reduce((s, u) => s + u.instances[1], 0);
  const rps = ins.reduce((s, i) => s + i.routes.reduce((x, r) => x + r.rps, 0), 0);
  return `${t.tenant} · 앱 ${new Set(ins.map((i) => i.app)).size} · 인스턴스 ${ins.length}/${insLim} · 호스트 규칙 ${rules}${t.external ? '' : ' · 외부망 쓰지 않음'} · 연결 ${n(conns)}/${n(lim)} · 요청 ${n(rps)}/s`;
}

function TenantLimits({ v }: { v: IngressView }) {
  const shown = v.tenants.filter((t) => t.usage.length);
  return (
    <>
      {shown.map((t) => (
        <Card key={t.tenant} title={`${t.tenant} · 서버별 외부 접속 한도와 사용량`} actions={<Link to={`/system/tenants/${t.tenant}`}>한도 바꾸기 (작업 공간 상세) →</Link>}>
          <UsageTable t={t} />
          <span className="small muted">한도는 작업 공간 × 서버마다 정해진 값(MaxIngressInstances·Listeners·Requests·Connections·BufferBytes)입니다. 넘으면 새 배포가 거부되고 실행 중에는 새 요청을 거절합니다.</span>
        </Card>
      ))}
    </>
  );
}
function UsageTable({ t, buffer = true }: { t: IngressView['tenants'][number]; buffer?: boolean }) {
  const cell = ([u, l]: [number, number], unit = '') => {
    const txt = `${n(u)}${unit} / ${n(l)}${unit}`;
    return u / l >= 0.9 ? <Badge tone="wa">{txt}</Badge> : <span>{txt}</span>;
  };
  const cols = buffer ? '0.7fr 1fr 1fr 1fr 1fr 1fr' : '0.7fr 1fr 1fr 1fr 1fr';
  return (
    <div className="gtbl">
      <div className="gr th" style={{ gridTemplateColumns: cols }}>
        <span>서버</span>
        <span>인스턴스</span>
        <span>호스트 규칙</span>
        <span>동시 요청</span>
        <span>연결</span>
        {buffer && <span>버퍼</span>}
      </div>
      {t.usage.map((u) => (
        <div key={u.node} className="gr" style={{ gridTemplateColumns: cols }}>
          <b>{u.node}</b>
          {cell(u.instances)}
          {cell(u.rules)}
          {cell(u.requests)}
          {cell(u.connections)}
          {buffer && cell(u.bufferMiB, ' MiB')}
        </div>
      ))}
    </div>
  );
}

function GatewaysCard({ v, onDone }: { v: IngressView; onDone: () => void }) {
  const [edit, setEdit] = useState<IngressNode>();
  const conf = (g?: IngressNode['external'], local = false) =>
    g ? (
      <span>
        <span className="mono">{g.address ?? '—'}</span>
        {g.iface ? ` (${g.iface})` : ''} · {g.ports.map((p) => `:${p}${g.listeners.some((l) => l.http3 && l.address.endsWith(`:${p}`)) ? ' (h3)' : ''}`).join(' ')} · {local ? '규칙' : '호스트 규칙'} {g.rules}
        {g.listeners.some((l) => l.error || !l.ready) && <span style={{ color: 'var(--er)' }}> · 수신 주소 {g.listeners.filter((l) => l.error || !l.ready).length}개 준비 안 됨</span>}
      </span>
    ) : (
      <span className="muted">꺼짐{local ? ' (로컬망 주소를 정하지 않음)' : ''}</span>
    );
  // 맞는 규칙 없음·출발지 거절 수는 시스템 관리자에게만 온다. 서버마다 두 게이트웨이를 더해 한 줄로.
  const counters = v.nodes.flatMap((x) => {
    const gs = [x.external, x.local].filter((g): g is GatewayConf => !!g && (g.unmatched !== undefined || g.sourceRejected !== undefined));
    if (!gs.length) return [];
    const sum = (k: 'unmatched' | 'sourceRejected') => gs.reduce((n, g) => n + (g[k] ?? 0), 0).toLocaleString('ko-KR');
    return [`${x.node} 최근 규칙 없음 ${sum('unmatched')} · 출발지 거절 ${sum('sourceRejected')}`];
  });
  return (
    <Card title="서버별 게이트웨이 구성" actions={<Menu label="게이트웨이 설정" className="btn" button="게이트웨이 설정…" items={v.nodes.map((x) => ({ label: x.node, onSelect: () => setEdit(x) }))} />}>
      <div className="gtbl">
        <div className="gr th" style={{ gridTemplateColumns: '0.5fr 1.6fr 1.6fr 0.7fr' }}>
          <span>서버</span>
          <span>외부망 게이트웨이 (인터넷 쪽)</span>
          <span>로컬망 게이트웨이 (사내·로컬 네트워크 쪽)</span>
          <span>상태</span>
        </div>
        {v.nodes.map((x) => (
          <div key={x.node} className="gr click" style={{ gridTemplateColumns: '0.5fr 1.6fr 1.6fr 0.7fr' }} role="button" tabIndex={0} onClick={() => setEdit(x)} onKeyDown={(e) => e.key === 'Enter' && setEdit(x)}>
            <b>{x.node}</b>
            {x.module ? conf(x.external) : <span className="muted">꺼짐</span>}
            {x.module ? conf(x.local, true) : <span className="muted">꺼짐</span>}
            <span className="row" style={{ gap: 4 }}>
              {!x.module ? <Badge tone="un">외부 접속 모듈 꺼짐</Badge> : x.external && x.local ? <Badge tone="ok">둘 다 수신 중</Badge> : <Badge tone="ok">{x.external ? '외부망만' : '로컬망만'}</Badge>}
              <GatewayConfBadge c={x.configuration} />
            </span>
          </div>
        ))}
      </div>
      {counters.length > 0 && (
        <span className="small" style={{ color: 'var(--text-2)' }}>
          {counters.join(' \u00a0·\u00a0 ')} <span className="muted">(시스템 관리자에게만 보임)</span>
        </span>
      )}
      <span className="small muted">두 게이트웨이는 서로 다른 주소에서 따로 받습니다. 외부망 주소에 로컬망 규칙이 새는 일은 없습니다(0.0.0.0·:: 같은 모든 주소 수신은 공유 수신 주소에서 쓸 수 없음). 작업 공간마다 외부망 노출 허용 여부와 호스트 이름 목록을 게이트웨이별로 정합니다(작업 공간 상세). 주소는 서버 설정 또는 이 화면에서 시스템 관리자가 정합니다.</span>
      <TenantExposure v={v} />
      {edit && <GatewayDialog x={edit} onClose={() => setEdit(undefined)} onDone={onDone} />}
    </Card>
  );
}
/** 설정 출처와 실제 적용 (mydcd NodeGateways: 수락과 bind는 따로) */
export function GatewayConfBadge({ c }: { c?: IngressNode['configuration'] }) {
  if (!c) return null;
  return (
    <>
      <Badge tone="tag" title={c.source === 'cluster' ? '이 화면에서 정한 클러스터 설정 (서버 파일보다 우선)' : '서버 설정 파일의 값'}>
        {c.source === 'cluster' ? `클러스터 설정 r${c.revision}` : '서버 파일'}
      </Badge>
      {c.error ? (
        <Badge tone="er" title={c.error}>
          적용 실패
        </Badge>
      ) : c.appliedRevision < c.revision ? (
        <Badge tone="pr" title={`서버가 적용한 것은 r${c.appliedRevision}`}>적용 중</Badge>
      ) : null}
    </>
  );
}
function TenantExposure({ v }: { v: IngressView }) {
  return (
    <div className="gtbl">
      <div className="gr th" style={{ gridTemplateColumns: '0.6fr 1fr 2fr' }}>
        <span>작업 공간</span>
        <span>외부망 노출</span>
        <span>쓸 수 있는 호스트</span>
      </div>
      {v.tenants.map((t) => (
        <div key={t.tenant} className="gr" style={{ gridTemplateColumns: '0.6fr 1fr 2fr' }}>
          <b>{t.tenant}</b>
          <span>{t.external ? <Badge tone="ok">허용</Badge> : <span className="muted">안 됨 (로컬망만)</span>}</span>
          <span className="mono small">{t.hosts.length ? `${t.hosts.join(', ')}${t.external ? ' · 외부망과 로컬망 모두' : ''}` : '—'}</span>
        </div>
      ))}
      <div className="gr" style={{ gridTemplateColumns: '1fr' }}>
        <span className="small muted">
          작업 공간 상세(UI-70)에서 시스템 관리자가 정합니다. 허용되지 않은 작업 공간이 app.yaml에 <span className="mono">gateway: external</span>을 쓰면 배포가 거부됩니다.
        </span>
      </div>
    </div>
  );
}
export function GatewayDialog({ x, onClose, onDone }: { x: IngressNode; onClose: () => void; onDone?: () => void }) {
  const toast = useToast();
  const c = x.configuration;
  // 지금 설정(mydcd configuration)을 먼저, 없으면 관측한 바인딩에서 채운다
  const [extOn, setExtOn] = useState(c?.external ? c.external.enabled : !!x.external);
  const [locOn, setLocOn] = useState(c?.local ? c.local.enabled : !!x.local);
  const [ext, setExt] = useState(c?.external?.addresses[0] ?? x.external?.address ?? '');
  const [loc, setLoc] = useState(c?.local?.addresses[0] ?? x.local?.address ?? '');
  const [extPorts, setExtPorts] = useState((c?.external?.ports ?? x.external?.ports ?? [443, 80]).join(', '));
  const [locPorts, setLocPorts] = useState((c?.local?.ports ?? x.local?.ports ?? [443]).join(', '));
  const [src, setSrc] = useState((c?.local?.sources ?? ['10.0.0.0/8', '192.168.0.0/16']).join(', '));
  const m = useMutation();
  const anyAddr = (s: string) => /^(0\.0\.0\.0|::)$/.test(s.trim());
  const ports = (s: string) => s.split(',').map((p) => Number(p.trim())).filter((p) => p > 0 && p < 65536);
  const srcList = src.split(',').map((s) => s.trim()).filter(Boolean);
  const bad = (extOn && (!ext.trim() || anyAddr(ext) || !ports(extPorts).length)) || (locOn && (!loc.trim() || anyAddr(loc) || !ports(locPorts).length)) || srcList.some((s) => !CIDR_RE.test(s));
  const applied = m.op?.state === 'applied';
  const stale = m.op?.state === 'failed' && m.op.resultCode === 1;
  useEffect(() => {
    if (!applied) return;
    toast(`${x.node} 게이트웨이 설정을 받았습니다. 서버가 적용하면 상태에 보입니다.`);
    onDone?.();
    onClose();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applied]);
  // 수신 주소(listener)는 포트마다 하나. 같은 포트의 TLS·HTTP/3 설정은 그대로 이어 쓴다.
  const listeners = (g: 'external' | 'local', addr: string, ps: number[]) =>
    ps.map((p) => {
      const old = c?.[g]?.listeners.find((l) => l.address.endsWith(`:${p}`));
      const seen = x[g]?.listeners.find((l) => l.address.endsWith(`:${p}`));
      return { id: old?.id ?? `${g === 'external' ? 'ext' : 'loc'}-${p}`, address: `${addr}:${p}`, http3: old?.http3 ?? seen?.http3 ?? false, ...(old?.tls ? { tls: true } : {}) };
    });
  const save = async () => {
    if (m.error || (m.op && m.op.state !== 'applied')) m.reset();
    const e = ext.trim();
    const l = loc.trim();
    // 외부망은 출발지를 받지 않는다(외부망 sources는 422). revision은 이 서버 gateway record의 것(처음 0).
    await m.run(
      gatewayPath(x.node),
      {
        revision: c?.source === 'cluster' ? c.revision : 0,
        external: extOn ? { enabled: true, addresses: [e], ports: ports(extPorts), listeners: listeners('external', e, ports(extPorts)) } : { enabled: false },
        local: locOn ? { enabled: true, addresses: [l], ports: ports(locPorts), sources: srcList, listeners: listeners('local', l, ports(locPorts)) } : { enabled: false },
      },
      'PUT',
    );
  };
  const busy = m.busy;
  return (
    <Dialog
      title={`${x.node} 게이트웨이`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={busy || bad} onClick={() => void save()}>
            저장
          </button>
        </>
      }
    >
      {c && (
        <div className="row small" style={{ gap: 6 }}>
          <span className="muted">지금 설정</span>
          <GatewayConfBadge c={c} />
          {c.source === 'file' && <span className="muted">저장하면 클러스터 설정이 생겨 서버 파일보다 우선합니다.</span>}
        </div>
      )}
      {c?.error && <div className="note er small">서버가 마지막 설정을 적용하지 못했습니다: {c.error}</div>}
      <div className="g2">
        <Field label="외부망 주소" hint="인터넷 쪽, 이 서버의 실제 주소 · 0.0.0.0 안 됨" error={extOn && anyAddr(ext) ? '모든 주소 수신은 쓸 수 없습니다' : undefined}>
          <input className="mono" value={ext} disabled={!extOn} onChange={(e) => setExt(e.target.value)} />
        </Field>
        <Field label="로컬망 주소" hint="사내망 쪽, 이 서버의 실제 주소" error={locOn && anyAddr(loc) ? '모든 주소 수신은 쓸 수 없습니다' : undefined}>
          <input className="mono" value={loc} disabled={!locOn} onChange={(e) => setLoc(e.target.value)} />
        </Field>
        <Field label="외부망 포트" hint="HTTP/HTTPS만">
          <input className="mono" value={extPorts} disabled={!extOn} onChange={(e) => setExtPorts(e.target.value)} />
        </Field>
        <Field label="로컬망 포트">
          <input className="mono" value={locPorts} disabled={!locOn} onChange={(e) => setLocPorts(e.target.value)} />
        </Field>
      </div>
      <Field label="로컬망이 받을 출발지" hint="이 밖에서 온 요청은 연결 단계에서 거부" error={srcList.some((s) => !CIDR_RE.test(s)) ? 'IP 또는 CIDR, 쉼표로 나눔' : undefined}>
        <input className="mono" value={src} disabled={!locOn} onChange={(e) => setSrc(e.target.value)} />
      </Field>
      <label className="check">
        <input type="checkbox" checked={extOn} onChange={(e) => setExtOn(e.target.checked)} /> 외부망 게이트웨이 켜기
      </label>
      <label className="check">
        <input type="checkbox" checked={locOn} onChange={(e) => setLocOn(e.target.checked)} /> 로컬망 게이트웨이 켜기
      </label>
      {extOn && x.external && ext.trim() !== x.external.address && (
        <div className="note wa small">
          외부망 주소를 바꾸면 이 서버의 외부망 규칙 {x.external.rules}개가 새 주소에서 받습니다. DNS가 옛 주소를 가리키면 <Link to="/system/domains">외부 도메인</Link> 화면에서 같이 바꾸세요.
        </div>
      )}
      <span className="small muted">서버가 주소와 포트를 미리 확인한 뒤 받습니다. 앱·단독 컨테이너의 ports와 겹치면 거절됩니다. 받은 뒤 실제 수신은 서버가 따로 적용하고, 실패하면 이 서버 줄에 ‘적용 실패’로 보입니다.</span>
      {stale && <div className="note wa small">그사이 이 서버의 게이트웨이 설정이 바뀌었습니다. 창을 닫고 다시 열어 주세요.</div>}
      {m.op && m.op.state !== 'applied' && !stale && <OpPanel op={m.op} onChange={m.setOp} />}
      <MutationError error={m.error} />
    </Dialog>
  );
}

// ── 게이트웨이 장애 웹훅 ──────────────────────────────

const ING_EVENTS: [string, string][] = [
  ['down', '수신 주소가 닫힘'],
  ['recovered', '회복'],
  ['certificate-expiring', '인증서 만료 임박'],
  ['error-rate', '5xx 5% 넘게 1분'],
  ['tls-rejects', 'TLS 거부 급증'],
  ['source-rejects', '허용 밖 출발지 거부 급증'],
  ['blocked', '긴급 차단 걸림·풀림'],
  ['limit-90', '한도 90% 넘음'],
];
const ING_NAME = Object.fromEntries(ING_EVENTS);
function GatewayHooks({ admin, nodes }: { admin: boolean; nodes: IngressNode[] }) {
  const lq = usePoll((s) => webhookLinks({ point: 'ingress' }, s), []);
  const hq = usePoll((s) => webhooks(undefined, s), []);
  const [add, setAdd] = useState(false);
  const [del, setDel] = useState<WebhookLink>();
  const hookOf = (name: string) => hq.data?.items.find((w) => w.name === name);
  const gwText = (l: WebhookLink) => {
    const g = l.scope.gateway;
    if (!g || g === 'all') return '모든 게이트웨이';
    if (g === 'public' || g === 'external') return '외부망 · 모든 서버';
    if (g === 'local') return '로컬망 · 모든 서버';
    return `로컬망 · ${g}`;
  };
  const rows = (lq.data?.items ?? []).filter((l) => !l.scope.app);
  return (
    <Card
      title="장애 시 웹훅 · 게이트웨이별"
      actions={
        <button className="btn" disabled={!admin} title={admin ? undefined : '게이트웨이 웹훅은 시스템 관리자만 연결합니다'} onClick={() => setAdd(true)}>
          + 웹훅 연결
        </button>
      }
    >
      <Load q={lq} rows={3} what="웹훅 연결을 읽지 못했습니다">
        {() =>
          rows.length ? (
            <div className="gtbl">
              <div className="gr th" style={{ gridTemplateColumns: '1fr 2fr 0.9fr 0.9fr 0.8fr 40px' }}>
                <span>게이트웨이</span>
                <span>언제</span>
                <span>부를 웹훅</span>
                <span>종류</span>
                <span>최근</span>
                <span />
              </div>
              {rows.map((l) => {
                const w = hookOf(l.webhook);
                return (
                  <div key={l.id} className="gr" style={{ gridTemplateColumns: '1fr 2fr 0.9fr 0.9fr 0.8fr 40px' }}>
                    <span>{gwText(l)}</span>
                    <span>{l.events.map((e) => ING_NAME[e] ?? e).join(' · ')}</span>
                    <span>{l.webhook}</span>
                    <span>{w ? <span className={`kind ${w.kind === 'internal' ? 'int' : 'ext'}`}>{w.kind === 'internal' ? '⌂ 클러스터 내부' : '↗ 외부 호출'}</span> : '—'}</span>
                    <span>{w ? lastBadge(w) : '—'}</span>
                    <Menu label={`${l.webhook} 연결`} button="⋯" items={[{ label: '연결 끊기…', danger: true, onSelect: () => setDel(l), disabledReason: admin ? undefined : '시스템 관리자만 바꿉니다' }]} />
                  </div>
                );
              })}
            </div>
          ) : (
            <span className="muted small">연결된 웹훅이 없습니다.</span>
          )
        }
      </Load>
      <span className="small muted">경로 규칙별 웹훅은 외부 접속 상세(UI-5B)에서 연결합니다. 게이트웨이 웹훅은 시스템 관리자만, 경로 규칙 웹훅은 그 작업 공간의 Network 관리 권한으로 연결합니다. 바깥 장애로 게이트웨이 전체가 끊겨도 부를 수 있게 외부 호출 웹훅을 하나 이상 두기를 권합니다.</span>
      {add && <IngressHookDialog nodes={nodes} hooks={hq.data?.items ?? []} onClose={() => setAdd(false)} onDone={() => void lq.refresh()} />}
      {del && <UnlinkDialog l={del} onClose={() => setDel(undefined)} onDone={() => void lq.refresh()} />}
    </Card>
  );
}
function IngressHookDialog({ nodes, hooks, onClose, onDone }: { nodes: IngressNode[]; hooks: Webhook[]; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [gw, setGw] = useState('external');
  const [events, setEvents] = useState<string[]>(['down', 'tls-rejects', 'error-rate']);
  const usable = hooks.filter((w) => w.role === 'notify' && !w.tenant);
  const [hook, setHook] = useState(usable[0]?.name ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const w = hooks.find((x) => x.name === hook);
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      // 'recovered'는 recover: true와 같다(데몬 #176).
      const evs = events.filter((e) => e !== 'recovered');
      // 이름표 '5xx 5% 넘게 1분'을 그대로 기준으로 보낸다.
      await createLink({ point: 'ingress', scope: { gateway: gw }, events: evs, webhook: hook, recover: events.includes('recovered'), ...(evs.includes('error-rate') ? { threshold: 5, minutes: 1 } : {}) });
      toast(`${hook}${eulReul(hook)} 게이트웨이 장애에 연결했습니다.`);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title="게이트웨이 장애 웹훅"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={busy || !hook || !events.some((e) => e !== 'recovered')} onClick={() => void save()}>
            연결
          </button>
        </>
      }
    >
      <Field label="게이트웨이">
        <select value={gw} onChange={(e) => setGw(e.target.value)}>
          <option value="external">외부망 · 모든 서버</option>
          <option value="local">로컬망 · 모든 서버</option>
          <option value="all">모든 게이트웨이</option>
          {nodes
            .filter((x) => x.local)
            .map((x) => (
              <option key={x.node} value={x.node}>
                로컬망 · {x.node}
              </option>
            ))}
        </select>
      </Field>
      <Field label="언제" error={!events.length ? '하나 이상 고르세요' : undefined}>
        <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
          {ING_EVENTS.map(([k, l]) => {
            const on = events.includes(k);
            return (
              <button key={k} type="button" className={`chip ${on ? 'on' : ''}`} aria-pressed={on} onClick={() => setEvents(on ? events.filter((x) => x !== k) : [...events, k])}>
                {on ? '✓ ' : ''}
                {l}
              </button>
            );
          })}
        </span>
      </Field>
      <Field label="부를 웹훅" error={!usable.length ? '클러스터 알림 웹훅이 없습니다. 장애 대응 › 웹훅에서 먼저 등록하세요.' : undefined}>
        <select value={hook} onChange={(e) => setHook(e.target.value)}>
          {usable.map((x) => (
            <option key={x.name} value={x.name}>
              {x.name} · {x.kind === 'internal' ? '⌂ 클러스터 내부' : '↗ 외부 호출'}
            </option>
          ))}
        </select>
      </Field>
      {w?.kind === 'internal' && <div className="note wa small">클러스터 내부 웹훅은 게이트웨이와 같은 망 장애에 함께 막힐 수 있습니다. 외부 호출 웹훅도 하나 연결해 두세요.</div>}
      {error !== undefined && <ErrorBand error={error} what="연결하지 못했습니다" />}
    </Dialog>
  );
}
export function UnlinkDialog({ l, onClose, onDone }: { l: WebhookLink; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  return (
    <Dialog
      title={`${l.webhook} 연결을 끊을까요?`}
      width={400}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button
            className="btn danger"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await deleteLink(l.id);
                toast(`${l.webhook} 연결을 끊었습니다.`);
                onDone();
                onClose();
              } catch (e) {
                setError(e);
                setBusy(false);
              }
            }}
          >
            연결 끊기
          </button>
        </>
      }
    >
      <span className="small">웹훅 자체를 지우지 않고 이 연결만 끊습니다. 웹훅은 장애 대응 › 웹훅에 남습니다.</span>
      {error !== undefined && <ErrorBand error={error} what="끊지 못했습니다" />}
    </Dialog>
  );
}

// ── 차단 탭 ──────────────────────────────

function BlocksTab({ blocks, admin, v, onChange }: { blocks: IngressBlock[]; admin: boolean; v: IngressView; onChange: () => void }) {
  const [open, setOpen] = useState<string>();
  const [release, setRelease] = useState<IngressBlock>();
  const session = useSession();
  const canNet = (b: IngressBlock) => (['node', 'tenant', 'gateway'].includes(b.scope.kind) ? admin : admin || !!session?.tenants.some((t) => t.id === b.scope.tenant && t.role === 'manager'));
  const cols = '0.6fr 1.8fr 0.8fr 1fr 1fr 150px';
  void v;
  const NODE_STATE = (x: IngressBlock['nodes'][number], lifting: boolean) =>
    x.state === 'applied' ? (
      <Badge tone="ok">적용 · {((x.ms ?? 0) / 1000).toFixed(1)}초</Badge>
    ) : x.state === 'lifted' ? (
      <Badge tone="ok">해제 적용</Badge>
    ) : x.state === 'unobserved' ? (
      <Badge tone="un">{lifting ? '관찰 전 · 해제 적용을 아직 모름' : '관찰 전'}</Badge>
    ) : (
      <Badge tone="wa">대기 · 연락 없음</Badge>
    );
  return (
    <Card title={`차단 (${blocks.filter((b) => b.state !== 'lifting').length})`}>
      {blocks.length ? (
        <div className="gtbl">
          <div className="gr th" style={{ gridTemplateColumns: cols }}>
            <span>대상</span>
            <span />
            <span>응답</span>
            <span>누가 · 언제</span>
            <span>남은 시간</span>
            <span />
          </div>
          {blocks.map((b) => (
            <div key={b.id} style={{ display: 'contents' }}>
              <div className={`gr click ${b.state === 'lifting' ? '' : 'blk'}`} style={{ gridTemplateColumns: cols, color: b.state === 'lifting' ? 'var(--muted)' : undefined }} role="button" tabIndex={0} aria-expanded={open === b.id} onClick={() => setOpen(open === b.id ? undefined : b.id)} onKeyDown={(e) => e.key === 'Enter' && setOpen(open === b.id ? undefined : b.id)}>
                <span>{BLOCK_KIND_NAME[b.scope.kind]}</span>
                <span className="mono small">{b.scope.kind === 'route' ? `${b.scope.host} ${b.scope.prefix}` : scopeText(b.scope).replace(/^(컨테이너|출발지) /, '')}</span>
                <span>{RESP_NAME[b.response]}</span>
                <span>
                  {b.by} · {fmtTime(b.at)}
                </span>
                <span>{b.state === 'lifting' ? <Badge tone="pr">해제 중 · 서버 적용 {b.nodes.filter((x) => x.state === 'lifted').length}/{b.nodes.length}</Badge> : b.until ? left(b.until) : '해제할 때까지'}</span>
                <span className="row" style={{ gap: 6 }} onClick={(e) => e.stopPropagation()}>
                  {b.state !== 'lifting' && (
                    <>
                      {b.until && <ExtendPop b={b} disabled={!canNet(b)} onDone={onChange} />}
                      <button className="btn sm" disabled={!canNet(b)} title={canNet(b) ? undefined : NEED_NET} onClick={() => setRelease(b)}>
                        해제
                      </button>
                    </>
                  )}
                </span>
              </div>
              {open === b.id && (
                <div className="gr" style={{ gridTemplateColumns: '1fr' }}>
                  <div className="kv2" style={{ gridTemplateColumns: '110px minmax(0,1fr)' }}>
                    {b.nodes.map((x) => (
                      <span key={x.node} style={{ display: 'contents' }}>
                        <span className="muted">{x.node}</span>
                        <span>
                          {NODE_STATE(x, b.state === 'lifting')}
                          {x.error && (
                            <>
                              {' '}
                              <span className="mono small" style={{ color: 'var(--er)' }}>
                                {x.error}
                              </span>
                            </>
                          )}
                        </span>
                      </span>
                    ))}
                    <span className="muted">막은 요청</span>
                    <span>
                      {n(b.blockedRequests)}건 ({RESP_NAME[b.response]})
                    </span>
                    <span className="muted">이유</span>
                    <span>{b.reason}</span>
                    {b.targetMissing && (
                      <>
                        <span className="muted">대상</span>
                        <span className="wa-text">막을 대상이 지금 없습니다(앱·규칙이 바뀌었을 수 있음)</span>
                      </>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <span className="muted small">걸린 차단이 없습니다.</span>
      )}
      <span className="small muted">지난 차단은 기록 탭과 작업 기록에 남습니다. 서버별 적용 상태는 줄을 펼치면 보입니다. 해제한 차단은 모든 서버가 해제를 적용할 때까지 이 표에 남고(기간·해제 단추 없음), 위쪽 띠·매핑 그림·차단 개수에서는 빠집니다.</span>
      {release && <ReleaseDialog b={release} onClose={() => setRelease(undefined)} onDone={onChange} />}
    </Card>
  );
}
// 결과가 불확실할 때(응답을 못 받음)만 같은 opId로 다시 보낸다. 서버가 답한 오류면 새 opId.
const nextOpId = (e: unknown, cur: string) => (e instanceof ApiError ? newOpId() : cur);
function ExtendPop({ b, disabled, onDone }: { b: IngressBlock; disabled: boolean; onDone: () => void }) {
  const toast = useToast();
  const [mins, setMins] = useState(30);
  const [opId, setOpId] = useState(() => newOpId());
  const [error, setError] = useState<unknown>();
  return (
    <Popover button="기간" className="btn sm" disabled={disabled} width={240} align="right">
      {(close) => (
        <div className="col" style={{ gap: 8 }}>
          <span className="small muted">남은 시간 {left(b.until).replace(' 남음', '')}</span>
          <Field label="얼마 동안">
            <select value={mins} onChange={(e) => setMins(Number(e.target.value))}>
              <option value={15}>15분 더</option>
              <option value={30}>30분 더</option>
              <option value={60}>1시간 더</option>
              <option value={240}>4시간 더</option>
            </select>
          </Field>
          {error !== undefined && <ErrorBand error={error} what="바꾸지 못했습니다" />}
          <div className="row" style={{ justifyContent: 'flex-end', gap: 6 }}>
            <button className="btn sm" onClick={close}>
              취소
            </button>
            <button
              className="btn sm primary"
              onClick={async () => {
                try {
                  await extendBlock(b.id, opId, mins, b.revision);
                  setOpId(newOpId());
                  toast('차단 기간을 늘렸습니다.');
                  onDone();
                  close();
                } catch (e) {
                  setOpId(nextOpId(e, opId));
                  setError(e);
                }
              }}
            >
              바꾸기
            </button>
          </div>
        </div>
      )}
    </Popover>
  );
}
export function ReleaseDialog({ b, onClose, onDone }: { b: IngressBlock; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const what = b.scope.kind === 'route' ? b.scope.prefix : b.scope.kind === 'task' ? b.scope.task : scopeText(b.scope);
  const [opId, setOpId] = useState(() => newOpId());
  return (
    <Dialog
      title={`${what} 차단을 해제할까요?`}
      width={400}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button
            className="btn primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await removeBlock(b.id, opId);
                toast(`${what} 차단을 해제했습니다.`);
                onDone();
                onClose();
              } catch (e) {
                setOpId(nextOpId(e, opId));
                setError(e);
                setBusy(false);
              }
            }}
          >
            해제
          </button>
        </>
      }
    >
      <span className="small">
        {b.scope.kind === 'route' ? `${b.scope.host} ${b.scope.prefix} 요청이 다시 서비스로 갑니다.` : b.scope.kind === 'task' ? `${b.scope.task}이(가) 상태 검사를 통과하면 다시 요청을 받습니다.` : `${scopeText(b.scope)} 차단을 풉니다.`} {since(b.at).replace('째', '')} 동안 막혀 있었고 그동안 {b.response === 'drop' ? '연결 끊기' : b.response} {n(b.blockedRequests)}건을 돌려줬습니다.
      </span>
      {error !== undefined && <ErrorBand error={error} what="해제하지 못했습니다" />}
    </Dialog>
  );
}

// ── 한도·사용량 · 기록 탭 ──────────────────────────────

function LimitsTab({ v }: { v: IngressView }) {
  return (
    <>
      {v.tenants
        .filter((t) => t.usage.length)
        .map((t) => (
          <Card key={t.tenant} title={`${t.tenant} · 서버별 한도와 사용량`} actions={<Link to={`/system/tenants/${t.tenant}`}>한도 바꾸기 →</Link>}>
            <UsageTable t={t} buffer={false} />
          </Card>
        ))}
      <span className="small muted">작업 공간 × 서버 한도는 작업 공간 상세(UI-70)에서 바꿉니다.</span>
    </>
  );
}
function HistoryTab() {
  const q = usePoll((s) => ingressHistory(s), [], 15_000);
  // 다음 쪽은 next를 after로 이어 읽어 붙인다(새로 고침하면 첫 쪽부터)
  const [more, setMore] = useState<{ items: IngressEvent[]; next?: string }>();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>();
  const [open, setOpen] = useState<IngressEvent>();
  useEffect(() => setMore(undefined), [q.data]);
  const next = more ? more.next : q.data?.next;
  const loadMore = async () => {
    if (!next) return;
    setBusy(true);
    setErr(undefined);
    try {
      const r = await ingressHistory(undefined, { after: next });
      setMore((m) => ({ items: [...(m?.items ?? []), ...r.items], next: r.next }));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  const where = (h: IngressEvent) => [h.tenant && h.app ? `${h.tenant}/${h.app}` : h.tenant, h.node, h.route, h.gateway && GW_SHORT[h.gateway]].filter(Boolean).join(' · ');
  return (
    <Card title="기록">
      <Load q={q} rows={4} what="기록을 읽지 못했습니다">
        {(d) => (
          <div className="gtbl">
            <div className="gr th" style={{ gridTemplateColumns: '0.6fr 2fr 1fr 0.6fr' }}>
              <span>언제</span>
              <span>무엇</span>
              <span>어디</span>
              <span>누가</span>
            </div>
            {[...d.items, ...(more?.items ?? [])].map((h, k) => (
              <div key={k} className={`gr${h.detail !== undefined || h.previous !== undefined ? ' click' : ''}`} style={{ gridTemplateColumns: '0.6fr 2fr 1fr 0.6fr' }} onClick={() => (h.detail !== undefined || h.previous !== undefined) && setOpen(h)}>
                <span>{fmtTime(h.at)}</span>
                <span>{h.what}</span>
                <span className="small muted">{where(h) || '—'}</span>
                <span>{h.by}</span>
              </div>
            ))}
          </div>
        )}
      </Load>
      {next && (
        <div>
          <button className="btn sm" disabled={busy} onClick={() => void loadMore()}>
            {busy ? '읽는 중…' : '더 보기'}
          </button>
        </div>
      )}
      {err !== undefined && <MutationError error={err} />}
      <span className="small muted">
        게이트웨이·분배·비우기·도메인 정책·차단의 수락 기록입니다(서버에 실제 적용된 것과는 따로). 자세한 작업 내용은 <Link to="/system/ops">작업 기록</Link>에 남습니다.
      </span>
      {open && (
        <Drawer title={open.what} onClose={() => setOpen(undefined)}>
          <KV items={[['언제', fmtTime(open.at)], ['누가', open.by], ['동작', <span className="mono">{open.action ?? '—'}</span>], ['요청', <span className="mono">{open.request ?? '—'}</span>], ['어디', where(open) || '—']]} />
          {open.previous !== undefined && (
            <>
              <b className="small">바꾸기 전</b>
              <pre className="code small">{typeof open.previous === 'string' ? open.previous : JSON.stringify(open.previous, null, 2)}</pre>
            </>
          )}
          {open.detail !== undefined && (
            <>
              <b className="small">바꾼 뒤</b>
              <pre className="code small">{typeof open.detail === 'string' ? open.detail : JSON.stringify(open.detail, null, 2)}</pre>
            </>
          )}
          <Link className="small" to="/system/ops">
            작업 기록에서 보기 →
          </Link>
        </Drawer>
      )}
    </Card>
  );
}

// ── 긴급 차단 다이얼로그 (UI-5C) ──────────────────────────────

const KINDS: [BlockKind, string, (s: BlockScope) => string, boolean][] = [
  ['route', '경로 규칙', (s) => `정확히 같은 규칙 하나${s.host ? ` (${s.host} ${s.prefix ?? ''})` : ''}`, false],
  ['host', '도메인 전체', (s) => `호스트 이름 하나의 모든 경로${s.host ? ` (${s.host})` : ''}`, false],
  ['task', '컨테이너', () => '그 컨테이너로만 요청을 보내지 않음', false],
  ['app', '앱 전체', () => '이 앱의 모든 호스트 규칙 (같은 :443의 다른 앱은 그대로)', false],
  ['source', '출발지 IP', () => 'IP·CIDR에서 오는 요청 (모든 앱 또는 고른 앱)', false],
  ['node', '서버', () => '그 서버의 게이트웨이 전부 또는 외부망만 · 시스템 관리자', true],
  ['tenant', '작업 공간', () => '작업 공간의 모든 앱 · 시스템 관리자', true],
  ['gateway', '게이트웨이', () => '외부망 게이트웨이 전체 (모든 서버) · 시스템 관리자', true],
];
export function BlockDialog({ v, preset, admin, onClose, onDone }: { v: IngressView; preset?: BlockScope; admin: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const { tenant: cur } = useAuth();
  const session = useSession();
  const canNet = (t?: string) => admin || (!!t && !!session?.tenants.some((x) => x.id === t && x.role === 'manager'));
  const rows = flatten(v);
  const hosts = [...new Set(rows.filter((f) => canNet(f.i.tenant)).map((f) => f.r.host))];
  const [kind, setKind] = useState<BlockKind>(preset?.kind ?? 'route');
  const [host, setHost] = useState(preset?.host ?? hosts[0] ?? '');
  const hostRoutes = rows.filter((f) => f.r.host === host);
  const [prefix, setPrefix] = useState(preset?.prefix ?? hostRoutes.find((f) => !f.r.blocked)?.r.prefix ?? hostRoutes[0]?.r.prefix ?? '/');
  const apps = [...new Map(v.instances.filter((i) => canNet(i.tenant)).map((i) => [`${i.tenant}/${i.app}`, i])).values()];
  const [appKey, setAppKey] = useState(preset?.app ? `${preset.tenant}/${preset.app}` : (apps.find((i) => i.tenant === cur) ?? apps[0]) ? `${(apps.find((i) => i.tenant === cur) ?? apps[0]).tenant}/${(apps.find((i) => i.tenant === cur) ?? apps[0]).app}` : '');
  // route·task·app 차단은 서버 하나의 매핑에 걸린다. 앱이 여러 서버에 있으면 서버를 고른다(없으면 422 scope.node).
  const [pickNode, setPickNode] = useState(preset?.node ?? '');
  const appInsts = v.instances.filter((i) => `${i.tenant}/${i.app}` === appKey);
  const inst = appInsts.find((i) => i.node === pickNode) ?? appInsts[0];
  const routeAt = hostRoutes.filter((x) => x.r.prefix === prefix);
  const routeF = routeAt.find((x) => x.i.node === pickNode) ?? routeAt[0];
  const prefixes = [...new Map(hostRoutes.map((f) => [f.r.prefix, f])).values()];
  const nodeChoices = kind === 'route' ? routeAt.map((x) => x.i) : kind === 'task' || kind === 'app' ? appInsts : [];
  const tasks = inst ? [...new Map(inst.routes.flatMap((r) => r.backends.map((b) => [b.task, { b, r }] as const))).values()] : [];
  const [task, setTask] = useState(preset?.task ?? tasks.find(({ b }) => !b.blocked)?.b.task ?? '');
  const [sources, setSources] = useState((preset?.sources ?? []).join(', '));
  const [srcApp, setSrcApp] = useState(preset?.app ? `${preset.tenant}/${preset.app}` : '');
  const [node, setNode] = useState(preset?.node ?? v.nodes.find((x) => x.module)?.node ?? '');
  const [nodeGw, setNodeGw] = useState<'all' | 'external'>('external');
  const [tenantSel, setTenantSel] = useState(preset?.tenant ?? v.tenants[0]?.tenant ?? '');
  const [gwSel, setGwSel] = useState<'external' | 'local' | 'all'>('external');
  const [response, setResponse] = useState<IngressBlock['response']>(preset?.kind === 'source' ? 'drop' : '503');
  const [dur, setDur] = useState('0');
  const [reason, setReason] = useState('');
  const [kill, setKill] = useState(false);
  const [drainSec, setDrainSec] = useState(30);
  const [typed, setTyped] = useState('');
  const [opId, setOpId] = useState(() => newOpId());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [done, setDone] = useState<IngressBlock>();
  const srcList = sources.split(',').map((s) => s.trim()).filter(Boolean);
  const srcBad = kind === 'source' && (srcList.length > 1 ? '한 번에 하나씩 막습니다. 여러 출발지는 차단을 따로 거세요.' : srcList.some((s) => !CIDR_RE.test(s)) ? 'IP 또는 CIDR (IPv4·IPv6)' : srcList.some(allSources) ? '모든 출발지를 막는 값입니다. 앱 전체를 막으려면 범위를 “앱 전체”로 고르세요.' : undefined);
  const typedTarget = kind === 'node' ? node : kind === 'tenant' ? tenantSel : kind === 'gateway' ? (gwSel === 'all' ? '모든 게이트웨이' : GW_NAME[gwSel]) : '';
  const scope = (): BlockScope => {
    switch (kind) {
      case 'route': {
        const f = routeF;
        return { kind, tenant: f?.i.tenant, app: f?.i.app, node: f?.i.node, route: f?.r.id, host, prefix, gateway: f?.r.gateway };
      }
      case 'host':
        return { kind, tenant: hostRoutes[0]?.i.tenant, host };
      case 'task':
        return { kind, tenant: inst?.tenant, app: inst?.app, node: inst?.node, task };
      case 'app':
        return { kind, tenant: inst?.tenant, app: inst?.app, node: inst?.node };
      case 'source': {
        const i = v.instances.find((x) => `${x.tenant}/${x.app}` === srcApp);
        return { kind, tenant: i?.tenant ?? (admin ? undefined : cur), app: i?.app, sources: srcList };
      }
      case 'node':
        return { kind, node, gateway: nodeGw };
      case 'tenant':
        return { kind, tenant: tenantSel };
      case 'gateway':
        return { kind, gateway: gwSel };
    }
  };
  const impact = (): ReactNode => {
    switch (kind) {
      case 'route': {
        const f = routeF;
        const others = hostRoutes.filter((x) => x.r.prefix !== prefix);
        return f ? (
          <>
            {f.i.node} {GW_NAME[f.r.gateway]} :{f.r.port}의 <span className="mono">{`${host} ${prefix}`}</span> 규칙에 맞는 요청 약 <b>{f.r.rps || 6}/s</b>가 {RESP_NAME[response]}{response === 'drop' ? '' : '를 받습니다'}. {others.length ? `같은 호스트의 다른 경로(${others.map((o) => `${o.r.prefix} ${o.r.rps}/s`).join(', ')})는 그대로입니다. ` : ''}앱 정의(app.yaml)와 컨테이너는 바뀌지 않습니다.
          </>
        ) : null;
      }
      case 'host': {
        const same = rows.filter((f) => f.r.host !== host && hostRoutes.some((h) => h.i.node === f.i.node && h.r.port === f.r.port));
        return (
          <>
            {host}의 모든 경로가 막힙니다.{same.length ? ` 같은 ${hostRoutes[0]?.i.node} :${hostRoutes[0]?.r.port}의 ${[...new Set(same.map((f) => f.r.host))].join(', ')}은 그대로입니다.` : ''}
          </>
        );
      }
      case 'task': {
        const t = tasks.find(({ b }) => b.task === task);
        const rest = tasks.filter(({ b }) => b.task !== task && !b.blocked && b.health.ok);
        const moved = t?.b.rps ?? 0;
        return t ? <>남는 컨테이너 {rest.map(({ b }) => b.task).join(', ') || '없음'}{rest.length ? `이(가) ${n(rest.reduce((s, x) => s + x.b.rps, 0) + moved)}/s를 받습니다.` : ' · 받을 컨테이너가 없어 이 서비스는 503을 돌려줍니다.'}</> : null;
      }
      case 'app':
        return inst ? <>{inst.app}의 호스트 규칙 {inst.routes.length}개(요청 약 {n(inst.routes.reduce((s, r) => s + r.rps, 0))}/s)가 막힙니다. 같은 수신 주소를 쓰는 다른 앱은 그대로입니다.</> : null;
      case 'source':
        return srcList.length ? <>{srcList.join(', ')}에서 오는 요청을 {srcApp ? srcApp.split('/')[1] : '모든 앱'}에서 {RESP_NAME[response]}로 막습니다.</> : null;
      case 'node': {
        const r = rows.filter((f) => f.i.node === node && (nodeGw === 'all' || f.r.gateway === nodeGw));
        return <>{GW_NAME.external}{nodeGw === 'all' ? '·로컬망' : ''} 규칙 {r.length}개, 요청 약 {n(r.reduce((s, f) => s + f.r.rps, 0))}/s가 {RESP_NAME[response]}{response === 'drop' ? '' : '를 받습니다'}. {nodeGw === 'external' ? '로컬망 게이트웨이와 ' : ''}다른 서버는 그대로입니다.</>;
      }
      case 'tenant':
        return <>{tenantSel}의 모든 앱 외부 접속이 막힙니다. 다른 작업 공간은 그대로입니다.</>;
      case 'gateway':
        return <>{gwSel === 'all' ? '모든 게이트웨이' : `${GW_NAME[gwSel]} 게이트웨이`}가 모든 서버에서 막힙니다.</>;
    }
  };
  const adminOnly = KINDS.find(([k]) => k === kind)?.[3];
  const blocked = busy || !reason.trim() || !!srcBad || (kind === 'source' && !srcList.length) || (adminOnly && typed !== typedTarget) || (kind === 'task' && !task) || ((kind === 'app' || kind === 'task') && !inst) || ((kind === 'route' || kind === 'host') && !host);
  const submit = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const minutes = Number(dur);
      const b = await addBlock({ opId, scope: scope(), response, ...(dur === 'midnight' ? { until: new Date(new Date().setHours(24, 0, 0, 0)).toISOString() } : minutes > 0 ? { minutes } : {}), reason: reason.trim(), killConnections: kill, ...(kind === 'task' ? { drainSeconds: drainSec } : {}) });
      setDone(b);
      onDone();
    } catch (e) {
      // 서버가 답한 오류면 새 opId, 응답을 못 받았으면 같은 opId로 다시 보낸다.
      if (e instanceof ApiError) setOpId(newOpId());
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  if (done) {
    const pending = done.nodes.filter((x) => x.state === 'pending');
    const applied = done.nodes.filter((x) => x.state === 'applied');
    return (
      <Dialog
        title={`⛔ ${scopeText(done.scope)} 차단`}
        onClose={onClose}
        footer={
          <>
            <button
              className="btn"
              onClick={async () => {
                const ok = await removeBlock(done.id, newOpId()).then(() => true, () => false);
                toast(ok ? '차단을 해제했습니다.' : '해제하지 못했습니다. 걸린 차단 목록에서 다시 해제하세요.');
                onDone();
                onClose();
              }}
            >
              해제
            </button>
            <button className="btn primary" onClick={onClose}>
              닫기
            </button>
          </>
        }
      >
        <div className="steps-list">
          <div>
            <i className="ok" />
            <span>요청 기록</span>
            <span className="muted mono">ingress-block {done.id}</span>
          </div>
          {applied.map((x) => (
            <div key={x.node}>
              <i className="ok" />
              <span>{x.node} 적용</span>
              <span className="muted">{((x.ms ?? 0) / 1000).toFixed(1)}초</span>
            </div>
          ))}
          {pending.map((x) => (
            <div key={x.node}>
              <i className="pr" />
              <span>{x.node} 대기</span>
              <span className="muted">연락 없음</span>
            </div>
          ))}
        </div>
        <div className="note ok small">✓ 차단했습니다. {applied.map((x) => `${x.node}가 ${((x.ms ?? 0) / 1000).toFixed(1)}초 만에 적용했습니다.`).join(' ')}</div>
        {pending.length > 0 && <div className="note wa small">{pending.map((x) => x.node).join(', ')}이(가) 응답하지 않아 그 서버에는 아직 적용되지 않았습니다. 서버가 돌아오면 바로 적용합니다.</div>}
      </Dialog>
    );
  }
  return (
    <Dialog
      title={
        <>
          ⛔ 긴급 차단 <span className="ids">UI-5C</span>
        </>
      }
      width={800}
      danger
      onClose={onClose}
      footer={
        <>
          <span className="small muted" style={{ marginRight: 'auto' }}>
            적용까지 보통 2초 · 서버별 적용 확인을 보여 줍니다
          </span>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn estop" disabled={blocked} onClick={() => void submit()}>
            {kind === 'task' ? '빼기' : adminOnly ? `${kind === 'node' ? (nodeGw === 'external' ? '외부망' : '서버') : kind === 'tenant' ? '작업 공간' : '게이트웨이'} 차단` : '지금 차단'}
          </button>
        </>
      }
    >
      <span className="small muted">무엇을 막을까요</span>
      <div className="opt-grid">
        {KINDS.map(([k, l, d, needAdmin]) => {
          const off = needAdmin && !admin;
          return (
            <label key={k} className={`opt ${kind === k ? 'on' : ''} ${off ? 'off' : ''}`} title={off ? '시스템 관리자만 고를 수 있습니다. 작업 공간 사용자는 자기 작업 공간 안의 경로·컨테이너·앱·출발지만 막습니다.' : undefined}>
              <input type="radio" name="blk-kind" checked={kind === k} disabled={off} onChange={() => (setKind(k), setTyped(''), setResponse(k === 'source' ? 'drop' : '503'))} />
              <span>
                <b>{l}</b>
                <small>{d(kind === k ? scope() : { kind: k, host, prefix })}</small>
              </span>
            </label>
          );
        })}
      </div>
      {(kind === 'route' || kind === 'host') && (
        <div className="g2">
          <Field label="호스트">
            <select value={host} onChange={(e) => (setHost(e.target.value), setPrefix(rows.find((f) => f.r.host === e.target.value)?.r.prefix ?? '/'))}>
              {hosts.map((h) => (
                <option key={h} value={h}>
                  {h} ({rows.find((f) => f.r.host === h)?.i.app})
                </option>
              ))}
            </select>
          </Field>
          {kind === 'route' && (
            <Field label="경로 규칙 (있는 규칙에서 고르기)">
              <select className="mono" value={prefix} onChange={(e) => setPrefix(e.target.value)}>
                {prefixes.map((f) => {
                  const all = hostRoutes.filter((x) => x.r.prefix === f.r.prefix).every((x) => x.r.blocked);
                  return (
                    <option key={f.r.prefix} value={f.r.prefix} disabled={all}>
                      {f.r.prefix || '(모든 경로)'} → {f.r.service ? `${f.r.service} :${f.r.servicePort}` : `${f.r.redirect} 넘김`}
                      {all ? ' · 이미 차단' : ''}
                    </option>
                  );
                })}
              </select>
            </Field>
          )}
        </div>
      )}
      {kind === 'route' && <span className="small muted">외부 접속의 최소 매핑 단위는 경로 규칙입니다. 규칙과 정확히 같은 것만 막을 수 있고, 규칙에 없는 하위 경로(/admin/login)는 막을 수 없습니다. 하위 경로만 막아야 하면 app.yaml에 그 경로 규칙을 먼저 추가합니다. 차단된 요청은 더 짧은 규칙(/)으로 넘어가지 않습니다.</span>}
      {kind === 'host' && (
        <div className="gtbl">
          <div className="gr th" style={{ gridTemplateColumns: '1fr 1.4fr 0.8fr' }}>
            <span>경로 규칙</span>
            <span>서비스</span>
            <span>요청</span>
          </div>
          {hostRoutes.map((f) => (
            <div key={`${f.i.node}/${f.r.id}`} className="gr" style={{ gridTemplateColumns: '1fr 1.4fr 0.8fr' }}>
              <span className="mono">{f.r.prefix || '*'}</span>
              <span>{f.r.service ? `${f.i.app} · ${f.r.service}` : `→ ${f.r.redirect}`}</span>
              <span>{f.r.blocked ? `${f.r.rps}/s (이미 차단)` : `${f.r.rps}/s`}</span>
            </div>
          ))}
        </div>
      )}
      {(kind === 'task' || kind === 'app') && (
        <Field label="앱">
          <select value={appKey} onChange={(e) => (setAppKey(e.target.value), setTask(''))}>
            {apps.map((i) => (
              <option key={`${i.tenant}/${i.app}`} value={`${i.tenant}/${i.app}`}>
                {i.tenant} / {i.app}
              </option>
            ))}
          </select>
        </Field>
      )}
      {nodeChoices.length > 1 && (
        <Field label="서버" hint="이 앱은 여러 서버에 있습니다. 차단은 서버 하나에 겁니다.">
          <select value={(kind === 'route' ? routeF?.i.node : inst?.node) ?? ''} onChange={(e) => (setPickNode(e.target.value), kind === 'task' && setTask(''))}>
            {nodeChoices.map((i) => (
              <option key={i.node} value={i.node}>
                {i.node}
                {i.observed === false ? ' · 관찰 전' : ''}
              </option>
            ))}
          </select>
        </Field>
      )}
      {kind === 'task' && (
        <>
          <div className="gtbl">
            <div className="gr th" style={{ gridTemplateColumns: '24px 1.2fr 1fr 0.8fr' }}>
              <span />
              <span>컨테이너</span>
              <span>상태 검사</span>
              <span>요청</span>
            </div>
            {tasks.map(({ b }) => (
              <label key={b.task} className="gr click" style={{ gridTemplateColumns: '24px 1.2fr 1fr 0.8fr' }}>
                <input type="radio" name="blk-task" checked={task === b.task} disabled={!!b.blocked} onChange={() => setTask(b.task)} />
                <span>
                  {b.task} @ {b.node}
                </span>
                <span>{b.blocked ? '이미 빠짐' : b.health.ok ? '통과' : `실패 · ${b.health.error ?? ''}`}</span>
                <span>{b.rps}/s</span>
              </label>
            ))}
          </div>
          <Field label="진행 중인 요청">
            <select value={drainSec} onChange={(e) => setDrainSec(Number(e.target.value))}>
              <option value={30}>끝날 때까지 기다림 (최대 30초)</option>
              <option value={0}>바로 끊기</option>
            </select>
          </Field>
        </>
      )}
      {kind === 'source' && (
        <div className="g2">
          <Field label="IP 또는 CIDR" hint="IPv4·IPv6 · 하나씩" error={srcBad}>
            <input className="mono" value={sources} onChange={(e) => setSources(e.target.value)} placeholder="198.51.100.0/24" />
          </Field>
          <Field label="적용 앱">
            <select value={srcApp} onChange={(e) => setSrcApp(e.target.value)}>
              {admin && <option value="">모든 앱</option>}
              {apps.map((i) => (
                <option key={`${i.tenant}/${i.app}`} value={`${i.tenant}/${i.app}`}>
                  {i.app} ({i.tenant})
                </option>
              ))}
            </select>
          </Field>
        </div>
      )}
      {kind === 'node' && (
        <div className="g2">
          <Field label="서버">
            <select value={node} onChange={(e) => (setNode(e.target.value), setTyped(''))}>
              {v.nodes
                .filter((x) => x.module)
                .map((x) => (
                  <option key={x.node} value={x.node}>
                    {x.node}
                  </option>
                ))}
            </select>
          </Field>
          <Field label="게이트웨이">
            <select value={nodeGw} onChange={(e) => setNodeGw(e.target.value as 'all' | 'external')}>
              <option value="external">외부망만</option>
              <option value="all">외부망·로컬망 모두</option>
            </select>
          </Field>
        </div>
      )}
      {kind === 'tenant' && (
        <Field label="작업 공간">
          <select value={tenantSel} onChange={(e) => (setTenantSel(e.target.value), setTyped(''))}>
            {v.tenants.map((t) => (
              <option key={t.tenant} value={t.tenant}>
                {t.tenant}
              </option>
            ))}
          </select>
        </Field>
      )}
      {kind === 'gateway' && (
        <Field label="게이트웨이">
          <select value={gwSel} onChange={(e) => (setGwSel(e.target.value as 'external' | 'local' | 'all'), setTyped(''))}>
            <option value="external">외부망 (모든 서버)</option>
            <option value="local">로컬망 (모든 서버)</option>
            <option value="all">모든 게이트웨이</option>
          </select>
        </Field>
      )}
      <div className="g2">
        <Field label="응답">
          <select value={response} onChange={(e) => setResponse(e.target.value as IngressBlock['response'])} disabled={kind === 'task'}>
            <option value="503">503 점검 페이지 (Retry-After)</option>
            <option value="403">403 거부</option>
            <option value="drop">연결 끊기 (응답 없음)</option>
          </select>
        </Field>
        <Field label="얼마 동안">
          <select value={dur} onChange={(e) => setDur(e.target.value)}>
            <option value="0">해제할 때까지</option>
            <option value="15">15분</option>
            <option value="60">1시간</option>
            <option value="midnight">오늘 자정까지</option>
          </select>
        </Field>
      </div>
      <Field label="이유 (작업 기록·알림에 남음)" error={reason.length > 512 ? '512자까지' : undefined}>
        <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="예: 관리자 페이지 무차별 로그인 시도" maxLength={200} />
      </Field>
      {kind !== 'task' && (
        <label className="check">
          <input type="checkbox" checked={kill} onChange={(e) => setKill(e.target.checked)} /> 지금 열린 연결도 끊기 (기본은 새 요청부터)
        </label>
      )}
      <div className="note small" style={{ background: '#FFF8F8', borderColor: '#F3B6BC' }}>
        <b>바로 영향</b> · {impact()}
      </div>
      {adminOnly && (
        <Field label={`확인하려면 ${typedTarget}${eulReul(typedTarget)} 입력하세요`}>
          <input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
        </Field>
      )}
      {error !== undefined && <ErrorBand error={error} what={error instanceof ApiError && error.code === 'exists' ? '이미 같은 차단이 있습니다' : '차단하지 못했습니다'} />}
    </Dialog>
  );
}
