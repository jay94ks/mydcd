// SPDX-License-Identifier: Apache-2.0

// 공유 자원 › 외부 접속 › 앱 상세 (UI-5B, 캔버스 IngressDetail · IngressIx).
// 수신 주소·경로 규칙·컨테이너·분배 방식·경로별 웹훅·차단·오류 표본을 한 앱 단위로 본다. 관측과 적용은 sfcd 몫이고, 지금은 목업이다.
import { useEffect, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { BALANCE_NAME, GW_NAME, RESP_NAME, balancePath, hasRouteCert, routeCertError, routeCertText, drainPath, ingress, ingressApp, ingressBlocks, retryText, ruleText, type Backend, type Balance, type BlockScope, type IngressBlock, type IngressInstance, type IngressRoute, type IngressView, type RouteDetail } from '../api/ingress';
import { createLink, testWebhook, webhookLinks, webhooks, type Webhook, type WebhookLink } from '../api/webhooks';
import { useSession } from '../auth/session';
import { Badge, Card, Field, PageHeader } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { ConfirmDialog, Dialog } from '../components/Dialog';
import { Drawer } from '../components/Drawer';
import { Menu } from '../components/Menu';
import { useToast } from '../components/Toast';
import { ago, fmtTime } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { usePhone } from '../lib/viewport';
import { MIngressDetail } from './MIngressDetail';
import { eulReul } from '../lib/josa';
import { BlockDialog, ReleaseDialog, UnlinkDialog } from './Ingress';
import { ingressLive, kindsLive } from '../lib/liveTopics';

const n = (x: number) => x.toLocaleString('ko-KR');
const NEED_NET = '이 작업 공간에서 망(Network) 관리 권한이 있어야 긴급 차단할 수 있습니다. 작업 공간 관리자에게 요청하세요.';
const since = (iso: string) => {
  const m = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 60000));
  return m < 60 ? `${m}분째` : fmtTime(iso);
};
const hhmmss = (iso: string) => new Date(iso).toLocaleTimeString('ko-KR', { hour12: false });
const routeText = (r: IngressRoute) => `${r.host} ${r.prefix || ''}`.trim();
/** 출발지 x.x.x.x → 같은 /24 */
const cidr24 = (src: string) => src.replace(/\.(x|\d+)$/, '.0/24');

export function IngressDetailPage() {
  return usePhone() ? <MIngressDetail /> : <DesktopIngressDetail />;
}

function DesktopIngressDetail() {
  const { tenant = '', app = '' } = useParams();
  // 앱이 여러 서버에 있으면 ?node=로 고른다(빼면 첫 매핑).
  const [sp] = useSearchParams();
  const pickNode = sp.get('node') ?? undefined;
  const session = useSession();
  const admin = !!session.user.systemAdmin;
  const canNet = admin || session.tenants.some((t) => t.id === tenant && t.role === 'manager');
  const dq = usePoll((s) => ingressApp(tenant, app, s, pickNode), [tenant, app, pickNode], 30_000, ingressLive(tenant));
  const bq = usePoll((s) => ingressBlocks(s), [], 30_000, ingressLive(tenant));
  const vq = usePoll((s) => ingress({ tenant }, s), [tenant], 0, ingressLive(tenant));
  const [block, setBlock] = useState<BlockScope | 'app'>();
  const [release, setRelease] = useState<IngressBlock>();
  const [drain, setDrain] = useState(false);
  const refresh = () => {
    dq.refresh();
    bq.refresh();
    vq.refresh();
  };
  // 걸린 차단만(해제 중 제외). 서버 하나에 걸린 차단은 지금 보는 서버 것만.
  const blocks = (bq.data?.items ?? []).filter((b) => b.state !== 'lifting' && (!b.scope.node || !dq.data || ['tenant', 'source', 'host'].includes(b.scope.kind) || b.scope.node === dq.data.instance.node)).filter((b) => (b.scope.tenant === tenant && (!b.scope.app || b.scope.app === app)) || (b.scope.kind === 'task' && dq.data?.instance.routes.some((r) => r.backends.some((x) => x.task === b.scope.task))));
  const ins = dq.data?.instance;
  const otherNodes = (vq.data?.instances ?? []).filter((i) => i.tenant === tenant && i.app === app && i.node !== ins?.node).map((i) => i.node);
  return (
    <div className="page">
      <PageHeader
        crumbs={
          <>
            <Link to="/shared/ingress">외부 접속</Link> / {ins ? <Link to={`/shared/ingress?view=node&pick=${ins.node}`}>{ins.node}</Link> : '…'} / {app}
          </>
        }
        title={app}
        ids="UI-5B"
        after={
          ins && (
            <>
              <Badge>작업 공간 {tenant}</Badge>
              <Badge>{ins.node}</Badge>
              {ins.observed === false ? <Badge tone="un">관찰 전</Badge> : ins.draining ? <Badge tone="wa">{drainText(ins)}</Badge> : ins.ready ? <Badge tone="ok">준비됨 · 세대 {ins.generation}</Badge> : <Badge tone="er">{ins.error ?? '준비 안 됨'}</Badge>}
              {ins.routes.some((r) => r.blocked) && <Badge tone="er">경로 {ins.routes.filter((r) => r.blocked).length}개 차단 중</Badge>}
              {otherNodes.map((nd) => (
                <Link key={nd} style={{ fontSize: 13 }} to={`/shared/ingress/${encodeURIComponent(tenant)}/${encodeURIComponent(app)}?node=${encodeURIComponent(nd)}`} title="같은 앱의 다른 서버">
                  {nd} 보기
                </Link>
              ))}
            </>
          )
        }
        actions={
          <>
            <Link className="btn" to={`/deploy/apps/${tenant}/${app}`}>
              앱 개요
            </Link>
            <Link className="btn" to={`/deploy/apps/${tenant}/${app}/edit`}>
              app.yaml에서 고치기
            </Link>
            <button type="button" className="btn" disabled={!canNet || !ins} title={canNet ? undefined : NEED_NET} onClick={() => setDrain(true)}>
              {ins?.draining ? '비우기 해제…' : '비우기 (drain)…'}
            </button>
            <button type="button" className="btn estop" disabled={!canNet || !vq.data} title={canNet ? undefined : NEED_NET} onClick={() => setBlock('app')}>
              ⛔ 이 앱 전체 차단
            </button>
          </>
        }
      />
      <Load q={dq} rows={8} what="이 앱의 외부 접속을 읽지 못했습니다">
        {(d) => (
          <>
            {d.instance.observed === false && <div className="note">sfcd가 아직 {d.instance.node}의 실행 상태를 보지 못했습니다. 요청 수·인증서·컨테이너 상태는 관찰된 뒤에 보입니다.</div>}
            <ListenersCard d={d} v={vq.data} tenant={tenant} />
            <RoutesCard d={d} blocks={blocks} canNet={canNet} onBlock={setBlock} onRelease={setRelease} />
            {d.instance.routes
              .filter((r) => r.balance)
              .map((r) => (
                <BalanceCard key={r.id} d={d} r={r} tenant={tenant} app={app} canEdit={canNet} onDone={refresh} />
              ))}
            <RouteHooks d={d} tenant={tenant} app={app} canEdit={canNet} />
            <AppBlocks blocks={blocks} canNet={canNet} onRelease={setRelease} />
            <ErrorsCard d={d} canNet={canNet} onBlockSource={(src) => setBlock({ kind: 'source', tenant, app, sources: [src] })} />
          </>
        )}
      </Load>
      {block && vq.data && <BlockDialog v={vq.data} admin={admin} preset={block === 'app' ? { kind: 'app', tenant, app, node: ins?.node } : block} onClose={() => setBlock(undefined)} onDone={refresh} />}
      {release && <ReleaseDialog b={release} onClose={() => setRelease(undefined)} onDone={refresh} />}
      {drain && ins && <DrainDialog tenant={tenant} app={app} ins={ins} undo={!!ins.draining} onClose={() => setDrain(false)} onDone={refresh} />}
    </div>
  );
}

function ListenersCard({ d, v, tenant }: { d: RouteDetail; v?: IngressView; tenant: string }) {
  const ins = d.instance;
  const node = v?.nodes.find((x) => x.node === ins.node);
  const listeners = [...new Map(ins.routes.map((r) => [`${r.gateway}:${r.port}`, r])).values()];
  const gws = [...new Set(ins.routes.map((r) => r.gateway))];
  const m = d.metrics;
  return (
    <Card title="수신 주소 · 호스트">
      <div className="gtbl">
        <div className="gr th" style={{ gridTemplateColumns: '1.3fr 0.8fr 2fr 0.8fr' }}>
          <span>게이트웨이 · 수신 주소</span>
          <span>프로토콜</span>
          <span>호스트 → 인증서</span>
          <span>상태</span>
        </div>
        {listeners.map((l) => {
          const g = node?.[l.gateway];
          const rs = ins.routes.filter((r) => r.gateway === l.gateway && r.port === l.port);
          const https = rs.some(hasRouteCert);
          return (
            <div key={`${l.gateway}:${l.port}`} className="gr" style={{ gridTemplateColumns: '1.3fr 0.8fr 2fr 0.8fr' }}>
              <span className="mono" style={l.gateway === 'local' ? { color: '#6E40C9' } : undefined}>
                {GW_NAME[l.gateway]} {g?.address ?? '…'}:{l.port}
              </span>
              <span className="mono small">{https ? 'h1 h2 h3' : 'h1'}</span>
              <span className="mono small">
                {https
                  ? [...new Map(rs.filter(hasRouteCert).map((r) => [r.host, r])).values()].map((r) => (
                      <span key={r.host} style={{ display: 'block' }}>
                        {r.host} → {routeCertText(r) || '—'}
                        {routeCertError(r) && <span style={{ color: 'var(--er)' }}> · {routeCertError(r)}</span>}
                      </span>
                    ))
                  : rs.some((r) => r.redirect)
                    ? '— (https로 넘김)'
                    : '—'}
              </span>
              <span>{!g ? <Badge tone="un">꺼짐</Badge> : g.state === 'listening' ? <Badge tone="ok">수신 중</Badge> : g.state === 'error' ? <Badge tone="er">오류</Badge> : <Badge tone="un">꺼짐</Badge>}</span>
            </div>
          );
        })}
      </div>
      <p className="small muted" style={{ margin: '10px 0 0' }}>
        이 앱의 규칙은 모두 {gws.map((g) => GW_NAME[g]).join('·')} 게이트웨이로 노출됩니다(app.yaml <span className="mono">gateway: {gws.join(', ')}</span>
        {gws.includes('external') ? `, 작업 공간 ${tenant}에 외부망 ${v?.tenants.find((t) => t.tenant === tenant)?.external === false ? '허용 안 됨' : '허용됨'}` : ''}). 같은 {GW_NAME[gws[0] ?? 'external']} :{listeners[0]?.port ?? 443}을 다른 앱이 함께 쓸 수 있습니다. 이 앱을 차단·재배포해도 그 앱은 끊기지 않습니다. HTTP/HTTPS만 받습니다.
      </p>
      {ins.observed !== false && (
        <>
      <h3 style={{ margin: '16px 0 8px', fontSize: 13 }}>지금 (최근 {m.windowSeconds && m.windowSeconds % 60 ? `${m.windowSeconds}초` : `${(m.windowSeconds ?? 60) / 60}분`})</h3>
      <div className="kv2" style={{ gridTemplateColumns: '110px minmax(0,1fr)', fontSize: 13 }}>
        <span className="muted">요청</span>
        <span className="mono">
          {n(m.rps)}/s{m.concurrent ? ` · 동시 ${n(m.concurrent[0])} / ${n(m.concurrent[1])}` : ''}
        </span>
        <span className="muted">연결</span>
        <span className="mono">
          {n(m.connections[0])} / {n(m.connections[1])}
        </span>
        <span className="muted">응답</span>
        <span className="mono">{m.codes}</span>
        <span className="muted">지연</span>
        <span className="mono">{m.latency}</span>
        <span className="muted">프록시 실패</span>
        <span className="mono">{m.proxyFailures}</span>
        {m.probeFailures !== undefined && (
          <>
            <span className="muted">상태 검사 실패</span>
            <span className="mono">{m.probeFailures}</span>
          </>
        )}
        {m.budget && (
          <>
            <span className="muted">예산</span>
            <span className="mono">{m.budget}</span>
          </>
        )}
      </div>
        </>
      )}
    </Card>
  );
}

function RoutesCard({ d, blocks, canNet, onBlock, onRelease }: { d: RouteDetail; blocks: IngressBlock[]; canNet: boolean; onBlock: (s: BlockScope) => void; onRelease: (b: IngressBlock) => void }) {
  const ins = d.instance;
  const cols = '1.2fr 1.1fr 0.5fr 0.5fr 1.1fr 1.1fr 70px';
  const blockOf = (id?: string) => (id ? blocks.find((b) => b.id === id) : undefined);
  const health = (b: Backend) => (b.health.ok ? <Badge tone="ok">{`통과${b.health.at ? ` · ${ago(b.health.at)}` : ''}`}</Badge> : <Badge tone="er">{`실패 · ${b.health.error ?? '응답 없음'}`}</Badge>);
  const pulled = ins.routes.flatMap((r) => r.backends).filter((b) => b.blocked);
  return (
    <Card
      title={
        <h2>
          경로 규칙 → 서비스 → 컨테이너 <span className="small muted" style={{ fontWeight: 400 }}>규칙은 위에서부터 정확한 호스트 → 와일드카드 → 긴 경로 순</span>
        </h2>
      }
    >
      <div className="table-x">
        <div className="gtbl" style={{ minWidth: 860 }}>
          <div className="gr th" style={{ gridTemplateColumns: cols }}>
            <span>호스트 · 경로 → 서비스</span>
            <span>컨테이너</span>
            <span>가중치</span>
            <span>세대</span>
            <span>상태 검사</span>
            <span>요청 · 지연</span>
            <span />
          </div>
          {ins.routes
            .filter((r) => !r.redirect)
            .map((r) => {
              const rb = blockOf(r.blocked);
              return (
                <div key={r.id} style={{ display: 'contents' }}>
                  <div className={`gr grp ${rb ? 'blk' : ''}`} style={{ gridTemplateColumns: cols }}>
                    <span style={{ gridColumn: '1/-1', color: rb ? 'var(--er)' : undefined }}>
                      <span className="mono">{routeText(r)}</span> → {r.service} :{r.servicePort}
                      {r.network ? ` (망 ${r.network})` : ''}
                      {rb && ` · ⛔ 긴급 차단 (${RESP_NAME[rb.response]}) · ${rb.by} · ${since(rb.at)} · 이유: ${rb.reason}`}
                    </span>
                  </div>
                  {r.backends.map((b) => {
                    const tb = blockOf(b.blocked);
                    return (
                      <div key={`${r.id}/${b.task}`} className={`gr ${tb ? 'blk' : ''}`} style={{ gridTemplateColumns: cols }}>
                        <span className="mono small">
                          {b.address}:{b.port}
                        </span>
                        <span>
                          <Link to={`/deploy/apps/${ins.tenant}/${ins.app}/c/${r.service}/${b.task}`}>{b.task}</Link> @ {b.node}
                        </span>
                        <span className="mono">
                          {b.weight}
                          {tb ? ' → 0' : ''}
                        </span>
                        <span className="mono">{b.generation}</span>
                        <span>{health(b)}</span>
                        <span className="mono small">{rb ? `${n(b.rps)}/s (차단)` : `${n(b.rps)}/s${b.p95Ms ? ` · p95 ${b.p95Ms}ms` : ''}`}</span>
                        <span>
                          {tb ? (
                            <button type="button" className="btn sm" disabled={!canNet} title={canNet ? undefined : NEED_NET} onClick={() => onRelease(tb)}>
                              해제
                            </button>
                          ) : rb ? (
                            <button type="button" className="btn sm" disabled={!canNet} title={canNet ? undefined : NEED_NET} onClick={() => onRelease(rb)}>
                              해제
                            </button>
                          ) : (
                            <button type="button" className="btn stop" disabled={!canNet} title={canNet ? '이 컨테이너로 요청을 보내지 않습니다' : NEED_NET} onClick={() => onBlock({ kind: 'task', tenant: ins.tenant, app: ins.app, task: b.task })}>
                              ⛔ 차단
                            </button>
                          )}
                        </span>
                      </div>
                    );
                  })}
                </div>
              );
            })}
        </div>
      </div>
      {pulled.map((b) => {
        const tb = blockOf(b.blocked);
        return (
          tb && (
            <div key={b.task} className="note wa small" style={{ marginTop: 10 }}>
              {b.task}은 {fmtTime(tb.at)} {tb.by}가 ‘이 컨테이너 빼기’로 긴급 차단했습니다(상태 검사 실패와 별개로 요청을 보내지 않음). 해제하면 상태 검사가 통과할 때 다시 받습니다.
            </div>
          )
        );
      })}
    </Card>
  );
}

const METHODS: [Balance['method'], string][] = [
  ['round-robin', '가중치 비율대로 차례로 돌림'],
  ['least-request', '처리 중인 요청 ÷ 가중치가 가장 적은 컨테이너'],
  ['hash', '출발지 IP · 쿠키 · 헤더 값으로 고정 (일관 해시)'],
  ['random', '상태가 같은 컨테이너가 많을 때'],
];

function BalanceCard({ d, r, tenant, app, canEdit, onDone }: { d: RouteDetail; r: IngressRoute; tenant: string; app: string; canEdit: boolean; onDone: () => void }) {
  const b = r.balance!;
  const [edit, setEdit] = useState(false);
  const [hist, setHist] = useState(false);
  return (
    <Card
      title={
        <h2>
          분배 방식 · <span className="mono">{routeText(r)}</span> → {r.service} :{r.servicePort}{' '}
          {r.balanceRevision ? <Badge tone="pr">관리 설정 적용 중 · r{r.balanceRevision}</Badge> : <Badge>app.yaml 선언 그대로</Badge>}
        </h2>
      }
      actions={
        <>
          <button type="button" className="btn" onClick={() => setHist(true)}>
            분배 기록
          </button>
          <button type="button" className="btn" disabled={!canEdit} title={canEdit ? undefined : '이 작업 공간의 배포 권한이 필요합니다'} onClick={() => setEdit(true)}>
            분배 방식 바꾸기…
          </button>
        </>
      }
    >
      <div className="grid" style={{ gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)', gap: 16 }}>
        <div>
          <span className="small muted">기본 방식 (조건에 맞지 않는 요청)</span>
          <div style={{ display: 'grid', gap: 6, marginTop: 6 }}>
            {METHODS.map(([k, desc]) => (
              <div key={k} className={`opt ${b.method === k ? 'on' : ''}`} style={b.method === k ? { borderColor: 'var(--accent)', background: 'var(--accent-bg)' } : undefined}>
                <span>
                  <b>{BALANCE_NAME[k]}</b>
                  <small>
                    {desc}
                    {b.method === k ? ' · 지금 방식' : ''}
                    {k === 'hash' && b.method === k && b.hashKey ? ` · 키 ${b.hashKey}` : ''}
                  </small>
                </span>
              </div>
            ))}
          </div>
        </div>
        <div className="kv2" style={{ gridTemplateColumns: '110px minmax(0,1fr)', fontSize: 13, alignContent: 'start' }}>
          <span className="muted">같은 서버 우선</span>
          <span>{b.locality ? `켬 · 게이트웨이와 같은 서버(${d.instance.node})의 컨테이너가 꽉 차거나 상태 검사에 실패할 때만 다른 서버로` : '끔'}</span>
          <span className="muted">천천히 늘리기</span>
          <span>{b.slowStartSeconds ? `새 컨테이너는 ${b.slowStartSeconds}초 동안 몫을 0 → 100%로 늘림` : '끔'}</span>
          <span className="muted">실패하면 다시</span>
          <span>{retryText(b.retry)}</span>
        </div>
      </div>
      <h3 style={{ margin: '16px 0 8px', fontSize: 13 }}>조건 (위에서부터 처음 맞는 것 하나)</h3>
      <div className="gtbl">
        <div className="gr th" style={{ gridTemplateColumns: '28px 1.5fr 1.3fr' }}>
          <span>#</span>
          <span>조건</span>
          <span>보낼 컨테이너 묶음</span>
        </div>
        {b.rules.map((x, k) => (
          <div key={k} className="gr" style={{ gridTemplateColumns: '28px 1.5fr 1.3fr' }}>
            <span className="mono">{k + 1}</span>
            <span className="mono" style={{ fontSize: 12 }}>{ruleText(x)}</span>
            <span>{x.group}</span>
          </div>
        ))}
        <div className="gr" style={{ gridTemplateColumns: '28px 1.5fr 1.3fr', color: 'var(--muted)' }}>
          <span>—</span>
          <span>그 밖의 요청</span>
          <span>전체 ({r.backends.map((x) => x.task).join(', ')})</span>
        </div>
      </div>
      <p className="small muted" style={{ margin: '10px 0 0' }}>
        조건으로 쓸 수 있는 것: 헤더 · 쿠키 · 쿼리 값(같음·접두사·있음), HTTP 메서드, 출발지 IP/CIDR, 비율(%). 컨테이너 묶음은 앱 정의의 서비스 레이블·버전으로 나눕니다. 묶음 안에서는 위의 기본 분배 방식을 그대로 씁니다(조건마다 방식을 따로 두지 않음). 묶음의 컨테이너가 모두 빠지면 {b.fallback === '503' ? '503을 돌려줍니다' : '기본으로 넘깁니다'}.
      </p>
      {b.actual && <p className="small" style={{ margin: '6px 0 0' }}>지난 1분 실제 분배 · {b.actual}</p>}
      <div className="note info small" style={{ marginTop: 10 }}>
        {r.balanceRevision ? <>지금 관리 설정(r{r.balanceRevision})이 적용 중입니다. </> : <>지금은 앱 정의(app.yaml <span className="mono">routes[].balance</span>)의 선언 그대로입니다. </>}
        여기서 바꾼 값은 app.yaml을 고치지 않고 클러스터의 관리 설정으로 위에 얹힙니다. 바꾸면 컨테이너는 그대로 두고 외부 접속 규칙만 다시 적용합니다(진행 중 요청은 끊지 않음). 엔진은 지금 가중치 순환만 지원합니다.
      </div>
      {edit && <BalanceDialog r={r} tenant={tenant} app={app} onClose={() => setEdit(false)} onDone={onDone} />}
      {hist && (
        <Drawer title="분배 방식 바뀐 기록" onClose={() => setHist(false)}>
          <div className="gtbl">
            <div className="gr th" style={{ gridTemplateColumns: '110px 1fr 70px' }}>
              <span>언제</span>
              <span>무엇</span>
              <span>누가</span>
            </div>
            {d.balanceHistory.map((h, k) => (
              <div key={k} className="gr" style={{ gridTemplateColumns: '110px 1fr 70px' }}>
                <span className="mono small">{fmtTime(h.at)}</span>
                <span>{h.what}</span>
                <span>{h.by}</span>
              </div>
            ))}
          </div>
          <p className="small muted">
            <Link to={`/deploy/apps/${tenant}/${app}/versions`}>앱 버전 기록</Link>에서 되돌릴 수 있습니다.
          </p>
        </Drawer>
      )}
    </Card>
  );
}

function BalanceDialog({ r, tenant, app, onClose, onDone }: { r: IngressRoute; tenant: string; app: string; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const b0 = r.balance!;
  const [method, setMethod] = useState(b0.method);
  const k0 = b0.hashKey ?? 'cookie:session';
  const [keyKind, setKeyKind] = useState<'cookie' | 'header' | 'source-ip'>(k0 === 'source-ip' ? 'source-ip' : k0.startsWith('header:') ? 'header' : 'cookie');
  const [keyName, setKeyName] = useState(k0.includes(':') ? k0.slice(k0.indexOf(':') + 1) : 'session');
  const hashKey = keyKind === 'source-ip' ? 'source-ip' : `${keyKind}:${keyName.trim()}`;
  const badKey = method === 'hash' && keyKind !== 'source-ip' && !/^[A-Za-z0-9_-]{1,64}$/.test(keyName.trim());
  const [weights, setWeights] = useState<Record<string, number>>(() => Object.fromEntries(r.backends.map((x) => [x.task, x.weight])));
  const [locality, setLocality] = useState(b0.locality);
  const [slow, setSlow] = useState(b0.slowStartSeconds);
  const [retry, setRetry] = useState(b0.retry ?? 0);
  const m = useMutation();
  const busy = m.busy;
  const changedW = r.backends.filter((x) => weights[x.task] !== x.weight);
  const badW = Object.values(weights).some((w) => !Number.isInteger(w) || w < 0 || w > 100);
  const badSlow = !Number.isInteger(slow) || slow < 0 || slow > 600;
  const applied = m.op?.state === 'applied';
  useEffect(() => {
    if (!applied) return;
    toast('분배 방식을 저장했습니다. 외부 접속 규칙만 다시 적용합니다.');
    onDone();
    onClose();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applied]);
  // revision은 이 경로의 관리 설정 revision(처음은 0). 다른 사람이 먼저 바꾸면 거절된다. actual·groups는 쓰기 모양에 없다.
  const save = async () => {
    if (m.error || (m.op && m.op.state !== 'applied')) m.reset();
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { actual, groups, ...rest } = b0;
    const balance: Balance = { ...rest, method, hashKey: method === 'hash' ? hashKey : undefined, locality, slowStartSeconds: slow, retry, weights: changedW.length || b0.weights ? { ...(b0.weights ?? {}), ...weights } : undefined };
    await m.run(balancePath(tenant, app), { route: r.id, revision: r.balanceRevision ?? 0, balance }, 'PUT');
  };
  return (
    <Dialog
      title={
        <>
          분배 방식 · <span className="mono">{routeText(r)}</span> → {r.service}
        </>
      }
      width={560}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn primary" disabled={busy || badW || badSlow || badKey} onClick={() => void save()}>
            저장 · 적용
          </button>
        </>
      }
    >
      <div style={{ display: 'grid', gap: 6 }}>
        {METHODS.map(([k]) => (
          <label key={k} className={`opt ${method === k ? 'on' : ''}`} style={method === k ? { borderColor: 'var(--accent)', background: 'var(--accent-bg)' } : undefined}>
            <input type="radio" name="bal" checked={method === k} onChange={() => setMethod(k)} style={{ accentColor: 'var(--accent)' }} />
            <span>
              <b>{k === 'hash' ? '같은 사용자 → 같은 컨테이너 고름' : BALANCE_NAME[k]}</b>
              <small>{{ 'round-robin': '가중치 비율대로 차례로', 'least-request': '처리 중 요청 ÷ 가중치', hash: '키: 출발지 IP / 쿠키 / 헤더', random: '' }[k]}</small>
            </span>
          </label>
        ))}
      </div>
      {method === 'hash' && (
        <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <Field label="고정할 키">
            <select value={keyKind} onChange={(e) => setKeyKind(e.target.value as typeof keyKind)}>
              <option value="cookie">쿠키</option>
              <option value="header">헤더</option>
              <option value="source-ip">출발지 IP</option>
            </select>
          </Field>
          {keyKind !== 'source-ip' && (
            <Field label="이름" error={badKey ? '영문·숫자·_·-, 64자까지' : undefined}>
              <input value={keyName} onChange={(e) => setKeyName(e.target.value)} className="mono" placeholder={keyKind === 'cookie' ? 'session' : 'X-User'} />
            </Field>
          )}
        </div>
      )}
      <h3 style={{ margin: '14px 0 6px', fontSize: 13 }}>컨테이너 가중치</h3>
      <div className="gtbl">
        <div className="gr th" style={{ gridTemplateColumns: '1.4fr 80px 1fr' }}>
          <span>컨테이너</span>
          <span>가중치</span>
          <span>묶음</span>
        </div>
        {r.backends.map((x) => (
          <div key={x.task} className="gr" style={{ gridTemplateColumns: '1.4fr 80px 1fr' }}>
            <span>
              {x.task} @ {x.node}
            </span>
            <input type="number" min={0} max={100} value={weights[x.task]} onChange={(e) => setWeights({ ...weights, [x.task]: Number(e.target.value) })} style={{ width: 64, height: 28 }} aria-label={`${x.task} 가중치`} />
            <span>{x.group ?? '—'}</span>
          </div>
        ))}
      </div>
      {badW && <div className="note er small">가중치는 0~100 정수입니다. 0이면 요청을 보내지 않습니다.</div>}
      <div style={{ display: 'grid', gap: 8, margin: '12px 0' }}>
        <label className="check">
          <input type="checkbox" checked={locality} onChange={(e) => setLocality(e.target.checked)} /> 같은 서버 우선 <span className="small muted">꽉 차거나 실패할 때만 다른 서버</span>
        </label>
        <label className="check">
          천천히 늘리기 <input type="number" min={0} max={600} value={slow} onChange={(e) => setSlow(Number(e.target.value))} style={{ width: 70, height: 28 }} />초
          {badSlow && <span className="small" style={{ color: 'var(--er)' }}> 0~600초</span>}
        </label>
        <label className="check">
          실패하면 다시{' '}
          <select value={retry} onChange={(e) => setRetry(Number(e.target.value))} style={{ height: 28 }} aria-label="실패하면 다시 보낼 횟수">
            {[0, 1, 2, 3, 4, 5].map((n) => (
              <option key={n} value={n}>
                {n ? `${n}번` : '안 함'}
              </option>
            ))}
          </select>{' '}
          <span className="small muted">연결 실패만 · GET/HEAD</span>
        </label>
      </div>
      <pre className="code small">
        {`routes:\n  - host: ${r.host}\n    service: ${r.service}\n${method !== b0.method || locality !== b0.locality || changedW.length ? `-   balance: {method: ${b0.method}}\n+   balance:\n+     method: ${method}${method === 'hash' ? `\n+     key: ${hashKey}` : ''}${locality ? '\n+     locality: same-node' : ''}${changedW.length ? `\n+     weights: {${changedW.map((x) => `${x.task}: ${weights[x.task]}`).join(', ')}}` : ''}` : `    balance: {method: ${method}}`}`}
      </pre>
      <p className="small muted">저장하면 앱의 새 버전이 되고 외부 접속 규칙만 다시 적용됩니다. 컨테이너는 다시 만들지 않습니다.</p>
      {m.op?.state === 'failed' && m.op.resultCode === 1 ? (
        <div className="note wa small">그사이 이 경로의 분배 설정이 바뀌었습니다. 창을 닫고 다시 열어 주세요.</div>
      ) : (
        m.op && m.op.state !== 'applied' && <OpPanel op={m.op} onChange={m.setOp} />
      )}
      <MutationError error={m.error} />
    </Dialog>
  );
}

const ROUTE_EVENTS: [string, string][] = [
  ['error-rate', '5xx 비율이 넘을 때'],
  ['latency', '지연 p95가 넘을 때'],
  ['no-backends', '받을 컨테이너 0개'],
  ['probe-failed', '상태 검사 실패'],
  ['cert', '인증서 없음/만료 임박'],
  ['blocked', '긴급 차단 걸림/풀림'],
  ['balance-fallback', '분배 조건 묶음이 비어 기본으로 넘김'],
];
const kindText = (w?: Webhook) => (!w ? '—' : w.kind === 'internal' ? '⌂ 클러스터 내부' : '↗ 외부 호출');

function RouteHooks({ d, tenant, app, canEdit }: { d: RouteDetail; tenant: string; app: string; canEdit: boolean }) {
  const toast = useToast();
  const lq = usePoll((s) => webhookLinks({ point: 'ingress', tenant, app }, s), [tenant, app], 0, kindsLive('webhook-link'));
  const hq = usePoll((s) => webhooks(tenant, s), [tenant], 0, kindsLive('webhook'));
  const [add, setAdd] = useState(false);
  const [del, setDel] = useState<WebhookLink>();
  const rows = (lq.data?.items ?? []).filter((l) => l.scope.app === app && l.scope.tenant === tenant);
  const hookOf = (name: string) => hq.data?.items.find((w) => w.name === name);
  const routeOf = (id?: string) => d.instance.routes.find((r) => r.id === id);
  const cols = '1.8fr 1fr 0.9fr 1fr 40px';
  return (
    <Card
      title="장애 시 웹훅 · 경로 규칙별"
      actions={
        <button type="button" className="btn" disabled={!canEdit} title={canEdit ? undefined : '이 작업 공간의 관리자 권한이 필요합니다'} onClick={() => setAdd(true)}>
          + 웹훅 연결
        </button>
      }
    >
      <Load q={lq} rows={3} what="웹훅 연결을 읽지 못했습니다">
        {() => (
          <div className="gtbl">
            <div className="gr th" style={{ gridTemplateColumns: cols }}>
              <span>언제 (경로 규칙 · 조건)</span>
              <span>부를 웹훅</span>
              <span>종류</span>
              <span>최근</span>
              <span />
            </div>
            {rows.length ? (
              rows.map((l) => {
                const r = routeOf(l.scope.route);
                return (
                  <div key={l.id} className="gr" style={{ gridTemplateColumns: cols }}>
                    <span>
                      <span className="mono">{r ? routeText(r) : '앱 전체'}</span> · {l.condition ?? l.events.map((e) => ROUTE_EVENTS.find((x) => x[0] === e)?.[1] ?? e).join(', ')}
                    </span>
                    <span>
                      <Link to={`/incidents/hooks?hook=${encodeURIComponent(l.webhook)}`}>{l.webhook}</Link>
                    </span>
                    <span className="small">{kindText(hookOf(l.webhook))}</span>
                    <span className="small">{l.last ? <Badge tone={l.last.status && l.last.status >= 200 && l.last.status < 300 ? 'ok' : 'er'} title={l.last.error}>{`${fmtTime(l.last.at)} · ${l.last.status ?? '실패'}`}</Badge> : <span className="muted">없음</span>}</span>
                    <Menu
                      label="⋯"
                      items={[
                        {
                          label: '시험 보내기',
                          onSelect: async () => {
                            try {
                              const x = await testWebhook(l.webhook);
                              toast(`${l.webhook} 시험 전송 · ${x.status}`);
                            } catch (e) {
                              toast(`${l.webhook} 시험 전송 실패`);
                              void e;
                            }
                          },
                        },
                        { label: '', sep: true },
                        { label: '연결 끊기…', danger: true, onSelect: () => setDel(l), disabledReason: canEdit ? undefined : '이 작업 공간의 관리자 권한이 필요합니다' },
                      ]}
                    />
                  </div>
                );
              })
            ) : (
              <div className="gr muted" style={{ gridTemplateColumns: '1fr' }}>
                연결된 웹훅이 없습니다.
              </div>
            )}
          </div>
        )}
      </Load>
      <p className="small muted" style={{ margin: '10px 0 0' }}>
        조건: 5xx 비율 · 지연 p95 · 받을 컨테이너 0개 · 상태 검사 실패 · 인증서 없음/만료 임박 · 긴급 차단 걸림/풀림 · 분배 조건 묶음이 비어 기본으로 넘김. 같은 조건은 풀릴 때 한 번 더(회복) 부르고, 10분 안에 같은 알림은 묶습니다. 웹훅 자체(주소·서명 비밀)는 <Link to="/incidents/hooks">장애 대응 › 웹훅</Link>에 한 번 등록하고 여기서는 연결만 합니다.
      </p>
      {add && <RouteHookDialog d={d} tenant={tenant} app={app} hooks={hq.data?.items ?? []} onClose={() => setAdd(false)} onDone={lq.refresh} />}
      {del && <UnlinkDialog l={del} onClose={() => setDel(undefined)} onDone={lq.refresh} />}
    </Card>
  );
}

function RouteHookDialog({ d, tenant, app, hooks, onClose, onDone }: { d: RouteDetail; tenant: string; app: string; hooks: Webhook[]; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const routes = d.instance.routes.filter((r) => !r.redirect);
  const [route, setRoute] = useState(routes[0]?.id ?? '');
  const [ev, setEv] = useState('error-rate');
  const [limit, setLimit] = useState(2);
  const [mins, setMins] = useState(1);
  const usable = hooks.filter((w) => !w.tenant || w.tenant === tenant);
  const [hook, setHook] = useState(usable[0]?.name ?? '');
  const [recover, setRecover] = useState(true);
  const [group, setGroup] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const r = routes.find((x) => x.id === route);
  const threshold = ev === 'error-rate' || ev === 'latency';
  const badLimit = threshold && (ev === 'error-rate' ? !(limit > 0 && limit <= 100) : !(limit > 0 && limit <= 60000));
  const badMins = threshold && !(Number.isInteger(mins) && mins >= 1 && mins <= 60);
  const w = hooks.find((x) => x.name === hook);
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await createLink({ point: 'ingress', scope: { tenant, app, route }, events: [ev], webhook: hook, ...(threshold ? { threshold: limit, minutes: mins } : {}), recover, group });
      toast(`${hook}${eulReul(hook)} ${r ? routeText(r) : app} 장애에 연결했습니다.`);
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
      title="장애 시 웹훅 연결"
      width={560}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button"
            className="btn"
            disabled={!hook}
            onClick={async () => {
              try {
                const x = await testWebhook(hook);
                toast(`${hook} 시험 전송 · ${x.status}`);
              } catch {
                toast(`${hook} 시험 전송 실패`);
              }
            }}
          >
            시험 보내기
          </button>
          <button type="button" className="btn primary" disabled={busy || !hook || !route || badLimit || badMins} onClick={() => void save()}>
            연결
          </button>
        </>
      }
    >
      <Field label="경로 규칙">
        <select value={route} onChange={(e) => setRoute(e.target.value)}>
          {routes.map((x) => (
            <option key={x.id} value={x.id}>
              {routeText(x)} → {x.service}
            </option>
          ))}
        </select>
      </Field>
      <Field label="언제">
        <select value={ev} onChange={(e) => (setEv(e.target.value), setLimit(e.target.value === 'latency' ? 1000 : 2))}>
          {ROUTE_EVENTS.map(([k, l]) => (
            <option key={k} value={k}>
              {l}
            </option>
          ))}
        </select>
      </Field>
      {threshold && (
        <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <Field label="기준" error={badLimit ? (ev === 'error-rate' ? '0보다 크고 100% 이하' : '1~60000ms') : undefined}>
            <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <input type="number" value={limit} onChange={(e) => setLimit(Number(e.target.value))} style={{ width: 90 }} /> {ev === 'error-rate' ? '%' : 'ms'}
            </span>
          </Field>
          <Field label="지속 시간" error={badMins ? '1~60분' : undefined}>
            <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <input type="number" value={mins} onChange={(e) => setMins(Number(e.target.value))} style={{ width: 70 }} /> 분
            </span>
          </Field>
        </div>
      )}
      <Field label="부를 웹훅">
        <select value={hook} onChange={(e) => setHook(e.target.value)}>
          {usable.map((x) => (
            <option key={x.name} value={x.name}>
              {x.name} · {kindText(x)}
            </option>
          ))}
        </select>
      </Field>
      <div style={{ display: 'grid', gap: 6, marginBottom: 10 }}>
        <label className="check">
          <input type="checkbox" checked={recover} onChange={(e) => setRecover(e.target.checked)} /> 회복될 때도 부르기
        </label>
        <label className="check">
          <input type="checkbox" checked={group} onChange={(e) => setGroup(e.target.checked)} /> 10분 안 같은 알림은 묶기
        </label>
      </div>
      {w?.kind === 'internal' && <div className="note wa small">클러스터 내부 웹훅은 이 경로와 같은 망 장애에 함께 막힐 수 있습니다. 외부 호출 웹훅도 하나 연결해 두세요.</div>}
      <p className="small muted">목록에 없는 웹훅은 장애 대응 › 웹훅에서 먼저 등록합니다. 작업 공간 사용자는 자기 작업 공간이 등록한 웹훅과 시스템 관리자가 공개한 웹훅만 고를 수 있습니다.</p>
      {error !== undefined && <ErrorBand error={error} what="연결하지 못했습니다" />}
    </Dialog>
  );
}

function AppBlocks({ blocks, canNet, onRelease }: { blocks: IngressBlock[]; canNet: boolean; onRelease: (b: IngressBlock) => void }) {
  const cols = '1.6fr 1fr 1fr 70px';
  return (
    <Card title="이 앱에 걸린 차단">
      {blocks.length ? (
        <div className="gtbl">
          <div className="gr th" style={{ gridTemplateColumns: cols }}>
            <span>범위</span>
            <span>응답</span>
            <span>누가 · 언제</span>
            <span />
          </div>
          {blocks.map((b) => (
            <div key={b.id} className="gr blk" style={{ gridTemplateColumns: cols }}>
              <span>
                {b.scope.kind === 'route' ? (
                  <>
                    경로 <span className="mono">{b.scope.prefix}</span>
                  </>
                ) : b.scope.kind === 'task' ? (
                  <>
                    컨테이너 <span className="mono">{b.scope.task}</span>
                  </>
                ) : b.scope.kind === 'source' ? (
                  <>
                    출발지 <span className="mono">{(b.scope.sources ?? []).join(', ')}</span>
                  </>
                ) : b.scope.kind === 'app' ? (
                  '앱 전체'
                ) : (
                  <span className="mono">{b.scope.host}</span>
                )}
              </span>
              <span>{b.scope.kind === 'task' ? '요청 안 보냄' : RESP_NAME[b.response]}</span>
              <span>
                {b.by} · {b.scope.kind === 'route' ? since(b.at) : fmtTime(b.at)}
              </span>
              <span>
                <button type="button" className="btn sm" disabled={!canNet} title={canNet ? undefined : NEED_NET} onClick={() => onRelease(b)}>
                  해제
                </button>
              </span>
            </div>
          ))}
        </div>
      ) : (
        <p className="muted small" style={{ margin: 0 }}>
          걸린 차단이 없습니다.
        </p>
      )}
    </Card>
  );
}

function ErrorsCard({ d, canNet, onBlockSource }: { d: RouteDetail; canNet: boolean; onBlockSource: (cidr: string) => void }) {
  const [pick, setPick] = useState<RouteDetail['errors'][number]>();
  const node = (task: string) => d.instance.routes.flatMap((r) => r.backends).find((b) => b.task === task)?.node;
  return (
    <Card title="최근 오류 요청 (표본)">
      <div className="code dark" style={{ padding: 0 }}>
        {d.errors.length ? (
          d.errors.map((e, k) => (
            <div key={k} role="button" tabIndex={0} className="mono small" style={{ padding: '4px 12px', cursor: 'pointer', whiteSpace: 'pre' }} onClick={() => setPick(e)} onKeyDown={(x) => x.key === 'Enter' && setPick(e)}>
              {`${hhmmss(e.at)}  ${e.status}  ${e.method.padEnd(5)}${e.path.padEnd(16)}${e.task.padEnd(7)}${e.reason}${e.ms >= 1000 ? `  ${(e.ms / 1000).toFixed(1)}s` : ''}`}
            </div>
          ))
        ) : (
          <div className="mono small" style={{ padding: '8px 12px' }}>
            최근 오류 요청이 없습니다.
          </div>
        )}
      </div>
      <p className="small muted" style={{ margin: '8px 0 0' }}>
        오류 응답만 최근 200개를 서버가 보관합니다(요청 본문·쿠키 없음, 출발지 IP 끝자리 가림).
      </p>
      {pick && (
        <Drawer
          title={
            <>
              {hhmmss(pick.at)} {pick.method} {pick.path} → {pick.status}
            </>
          }
          onClose={() => setPick(undefined)}
        >
          <div className="kv2" style={{ gridTemplateColumns: '90px minmax(0,1fr)', fontSize: 13 }}>
            <span className="muted">컨테이너</span>
            <span>
              {pick.task} @ {node(pick.task) ?? '—'}
            </span>
            <span className="muted">실패</span>
            <span>
              {pick.reason}
              {pick.ms ? ` (${pick.ms >= 1000 ? `${(pick.ms / 1000).toFixed(1)}초` : `${pick.ms}ms`})` : ''}
            </span>
            <span className="muted">출발지</span>
            <span className="mono">{pick.source}</span>
            <span className="muted">헤더</span>
            <span>user-agent만 · 쿠키·본문 없음</span>
          </div>
          <div style={{ marginTop: 14 }}>
            <button type="button"
              className="btn stop"
              disabled={!canNet}
              title={canNet ? undefined : NEED_NET}
              onClick={() => {
                const src = cidr24(pick.source);
                setPick(undefined);
                onBlockSource(src);
              }}
            >
              이 출발지 차단…
            </button>
          </div>
        </Drawer>
      )}
    </Card>
  );
}

/** 비우는 중 배지 글: 남은 기다림 시간과 마지막 서버 여부 */
function drainText(ins: IngressInstance) {
  const left = ins.drainDeadline ? Math.ceil((Date.parse(ins.drainDeadline) - Date.now()) / 1000) : undefined;
  const t = left === undefined ? '비우는 중' : left > 0 ? `비우는 중 · ${left >= 60 ? `${Math.ceil(left / 60)}분` : `${left}초`} 뒤 남은 요청 끊음` : '비움 · 남은 요청 끊음';
  return ins.lastMapping ? `${t} · 마지막 서버` : t;
}

function DrainDialog({ tenant, app, ins, undo, onClose, onDone }: { tenant: string; app: string; ins: IngressInstance; undo: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const m = useMutation();
  const [secs, setSecs] = useState(30);
  const stale = m.op?.state === 'failed' && m.op.resultCode === 1;
  const badSecs = !undo && (!Number.isInteger(secs) || secs < 1 || secs > 3600);
  const applied = m.op?.state === 'applied';
  useEffect(() => {
    if (!applied) return;
    toast(undo ? `${app}의 비우기를 풀었습니다. 다시 새 연결을 받습니다.` : `${app}${eulReul(app)} 비우는 중입니다. 작업 기록에서 진행을 봅니다.`);
    onDone();
    onClose();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applied]);
  // revision은 이 앱 비우기 기록의 revision(처음은 0). 다른 사람이 먼저 바꾸면 거절된다.
  const body = { node: ins.node, revision: ins.drainRevision ?? 0, ...(undo ? {} : { drainSeconds: secs }) };
  return (
    <ConfirmDialog
      title={undo ? `${app} 비우기를 풀까요?` : `${app} 외부 접속을 비울까요?`}
      target={app}
      actionLabel={undo ? '비우기 해제' : '비우기'}
      busy={m.busy || badSecs}
      onClose={onClose}
      onConfirm={async () => {
        if (m.error || (m.op && m.op.state !== 'applied')) m.reset();
        await m.run(drainPath(tenant, app), body, undo ? 'DELETE' : 'POST');
      }}
    >
      {undo ? (
        <p>{ins.node}의 이 인스턴스가 같은 설정으로 다시 새 연결을 받습니다.</p>
      ) : (
        <>
          <p>{ins.node}에서 새 연결을 받지 않고, 열린 요청은 정한 시간까지 끝내게 둡니다. 시간이 되면 남은 요청을 끊습니다. 비우는 동안 이 인스턴스는 준비 안 됨으로 보입니다.</p>
          <Field label="열린 요청을 기다릴 시간(초)" hint="기본 30초, 최대 3600초">
            <input className="input mono" type="number" min={1} max={3600} value={secs} onChange={(e) => setSecs(Number(e.target.value))} style={{ width: 120 }} />
          </Field>
          {ins.lastMapping && <div className="note wa small">이 앱이 외부에 노출된 마지막 서버입니다. 비우면 외부에서 이 앱에 닿을 곳이 없어집니다(앱과 설정은 지우지 않음).</div>}
        </>
      )}
      {stale && <div className="note wa small">그사이 이 앱의 비우기 설정이 바뀌었습니다. 창을 닫고 다시 열어 주세요.</div>}
      {m.op && m.op.state !== 'applied' && !stale && <OpPanel op={m.op} onChange={m.setOp} />}
      <MutationError error={m.error} />
    </ConfirmDialog>
  );
}
