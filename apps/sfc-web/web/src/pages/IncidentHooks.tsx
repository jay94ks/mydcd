// SPDX-License-Identifier: Apache-2.0

// 장애 대응 › 웹훅 (UI-BB, 캔버스 IncidentHooks · IncidentHooksIx). 등록·서명·전송 기록은 웹 데몬 몫, 클러스터 내부 전달은 데몬이 sfcd 서비스 호출로 한다.
// 계약: /mnt/project-files/w2/guides-mcp-webhooks-contract.md '웹훅' + webhooks-web-needs.md.
// 서명 비밀은 만들 때·바꿀 때 한 번만 보이고 닫으면 상태에서 지운다. 헤더 토큰도 보낸 뒤 바로 지운다.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { ApiError } from '../api/client';
import { appTasks, apps } from '../api/endpoints';
import { policy } from '../api/incidents';
import { FORMAT_NAME, callError, HOOK_NAME_RE, POINT_NAME, ROLE_NAME, SIGN_NAME, createWebhook, deleteWebhook, deliveries, privateHost, putWebhook, rotateWebhook, secretValue, targetText, testWebhook, webhookLinks, webhooks, type Delivery, type HookFormat, type HookKind, type HookRole, type HookSign, type Webhook, type WebhookLink } from '../api/webhooks';
import { useSession } from '../auth/session';
import { ConfirmDialog, Dialog } from '../components/Dialog';
import { Drawer } from '../components/Drawer';
import { Menu } from '../components/Menu';
import { useToast } from '../components/Toast';
import { useUndoToast } from '../components/UndoToast';
import { restoreTrash } from '../api/trash';
import { ErrorBand, Load, errorText } from '../components/states';
import { Badge, Field, HelpBox, PageHeader } from '../components/ui';
import { ago, fmtTime as shortTime } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { IncidentTabs } from './Incidents';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { appLive, appsLive, deliveriesLive, kindsLive } from '../lib/liveTopics';

type Filter = 'all' | HookKind;
const POINT_SHORT: Record<WebhookLink['point'], string> = { incident: '장애', cd: '배포', ingress: '외부 접속' };
const sec = (ms: number) => `${(ms / 1000).toFixed(1)}초`;
const linkText = (l: WebhookLink) => (l.label && l.label.includes(':') ? l.label : `${POINT_SHORT[l.point]}: ${l.label ?? ([l.scope.tenant, l.scope.app, l.scope.gateway].filter(Boolean).join('/') || '전체')}`);
function signText(w: Webhook): string {
  if (w.sign) return SIGN_NAME[w.sign];
  return w.secret.set ? 'HMAC' : '—';
}
export function lastBadge(w: Webhook): ReactNode {
  if (w.enabled === false || w.state === 'disabled') return <Badge tone={w.disabledReason === 'failures' ? 'er' : 'un'}>{w.disabledReason === 'failures' ? '연결 없음 · 꺼짐' : '꺼짐'}</Badge>;
  const d = w.lastDelivery;
  if (!d) return <span className="muted">아직 없음</span>;
  if (d.retry) return <Badge tone="wa">{`재시도 ${d.retry.attempt}/${d.retry.of} · ${d.status}`}</Badge>;
  if (d.status >= 200 && d.status < 300) return <Badge tone="ok">{`${d.status} · ${sec(d.ms)} · ${ago(d.at)}`}</Badge>;
  return <Badge tone="er">{d.status ? `${d.status} · ${ago(d.at)}` : `실패 · ${ago(d.at)}`}</Badge>;
}

export function IncidentHooksPage() {
  return usePhone() ? <MHooks /> : <DesktopHooks />;
}

// ── 휴대폰 웹훅 탭 (UI-M8 ④): 보기만, 카드를 누르면 전송 기록 ──
function MHooks() {
  const q = usePoll((s) => webhooks(undefined, s), [], 0, kindsLive('webhook'));
  const lq = usePoll((s) => webhookLinks({}, s), [], 0, kindsLive('webhook-link'));
  const [filter, setFilter] = useState<'all' | 'failing' | 'off'>('all');
  const [sel, setSel] = useState<Webhook>();
  useMobileTop({ title: '장애 대응', root: true }, []);
  const links = lq.data?.items ?? [];
  const off = (w: Webhook) => w.enabled === false || w.state === 'disabled';
  const failing = (w: Webhook) => !off(w) && (w.state === 'failing' || !!w.lastDelivery?.retry || (!!w.lastDelivery && (w.lastDelivery.status < 200 || w.lastDelivery.status >= 300)));
  return (
    <>
      <IncidentTabs />
      <Load q={q} rows={4} what="웹훅을 불러오지 못했습니다">
        {(d) => {
          const all = d.items;
          const shown = all.filter((w) => (filter === 'all' ? true : filter === 'failing' ? failing(w) : off(w)));
          return (
            <>
              <div className="mchips">
                <button type="button" className={`mchip${filter === 'all' ? ' on' : ''}`} onClick={() => setFilter('all')}>
                  전체 {all.length}
                </button>
                <button type="button" className={`mchip${filter === 'failing' ? ' on' : ''}`} onClick={() => setFilter('failing')}>
                  실패{all.filter(failing).length ? ` ${all.filter(failing).length}` : ''}
                </button>
                <button type="button" className={`mchip${filter === 'off' ? ' on' : ''}`} onClick={() => setFilter('off')}>
                  꺼짐
                </button>
              </div>
              {!shown.length && <span className="muted small">{all.length ? '맞는 웹훅이 없습니다.' : '아직 등록한 웹훅이 없습니다.'}</span>}
              {shown.map((w) => {
                const pts = [...new Set(links.filter((l) => l.webhook === w.name).map((l) => POINT_NAME[l.point]))];
                const retry = w.lastDelivery?.retry;
                return (
                  <button key={w.name} type="button" className={`mc${failing(w) ? ' xwa' : ''}`} style={{ textAlign: 'left', font: 'inherit' }} onClick={() => setSel(w)}>
                    <div className="hd">
                      <b>{w.name}</b>
                      {lastBadge(w)}
                    </div>
                    <div className="ln">{[w.kind === 'internal' ? '⌂ 클러스터 내부' : '↗ 외부 호출', ROLE_NAME[w.role], ...(pts.length ? pts : ['연결 없음'])].join(' · ')}</div>
                    {retry && <div className="ln muted" style={{ fontSize: 12 }}>다시 시도 중 · 계속 실패하면 꺼짐</div>}
                    {w.error && !retry && <div className="ln muted" style={{ fontSize: 12 }}>{w.error}</div>}
                  </button>
                );
              })}
              <span className="muted small" style={{ textAlign: 'center' }}>
                등록 · 끄기 · 지우기 · 연결은 넓은 화면에서
              </span>
            </>
          );
        }}
      </Load>
      {sel && <DeliveriesDrawer w={sel} onClose={() => setSel(undefined)} />}
    </>
  );
}

function DesktopHooks() {
  const session = useSession();
  const q = usePoll((s) => webhooks(undefined, s), [], 0, kindsLive('webhook'));
  const lq = usePoll((s) => webhookLinks({}, s), [], 0, kindsLive('webhook-link'));
  const [adding, setAdding] = useState(false);
  const canAdd = session.user.systemAdmin || session.tenants.some((t) => t.role === 'manager');
  const refresh = () => {
    q.refresh();
    lq.refresh();
  };
  return (
    <>
      <PageHeader
        title="장애 대응"
        ids="UI-BB"
        actions={
          <button className="btn primary" disabled={!canAdd} title={canAdd ? undefined : '작업 공간 관리자 이상 권한이 필요합니다'} onClick={() => setAdding(true)}>
            ＋ 웹훅 등록
          </button>
        }
      />
      <IncidentTabs />
      <HelpBox terms="웹훅 (webhook) · 외부 호출 (outbound HTTPS) · 클러스터 내부 엔드포인트 (in-cluster service endpoint) · 판단 웹훅 (decision webhook) · 서명 (HMAC-SHA256)">
        <b>이 화면은</b> 장애 대응을 웹훅으로 넓힙니다. AI 모델을 연결하지 않아도 됩니다. 사건이 생기거나 바뀌면 등록한 웹훅을 부르고, <b>알림</b> 웹훅은 소식만 받고, <b>판단</b> 웹훅은 어떤 임시 조치를 할지 답합니다. 보내는 곳은 두 종류입니다. <b>외부 호출</b>은 인터넷의 https 주소로, <b>클러스터 내부</b>는 작업 공간 안에서 돌고 있는 앱 서비스로 보냅니다(밖으로 열지 않아도 됨). 판단 웹훅의 답도 AI와 같은 규칙(임시 조치 목록, 규칙 하한, 승인)을 거칩니다.
      </HelpBox>
      <div className="grid-3">
        <DecideCard links={lq.data?.items} admin={session.user.systemAdmin} />
        <section className="card">
          <h2>지켜지는 규칙</h2>
          <div className="rulebox">
            <span>
              · 판단 웹훅은 보낸 <span className="mono">allowed_actions</span> 안에서만 고를 수 있습니다. 목록 밖·형식 오류 답은 버리고 다음 단계로 넘어갑니다.
            </span>
            <span>
              · 영향 등급은 규칙 하한입니다. 웹훅은 등급을 <b>올리기만</b> 할 수 있습니다(<span className="mono">raise_level</span>). 그래서 자동 실행은 정책이 '낮은 영향 자동'이고 하한이 '낮음'인 조치뿐이고, 나머지는 승인 요청이 됩니다.
            </span>
            <span>· 웹훅은 Seafield를 직접 바꾸지 못합니다. 실행은 언제나 자동 대응 계정(자동) 또는 승인한 사람이 합니다.</span>
            <span>· 보내는 내용에 비밀값·환경 변수 값·로그 원문은 넣지 않습니다. 신호·대상·최근 변경·허용 조치만.</span>
            <span>
              · 서명 비밀은 봉인 파일에. 받은 쪽은 <span className="mono">X-SFC-Signature</span>의 시각이 5분 넘으면 버리세요(재전송 공격 막기).
            </span>
          </div>
        </section>
      </div>
      <Load q={q} rows={5} what="웹훅 목록을 불러오지 못했습니다">
        {(d) => <Body hooks={d.items} links={lq.data?.items ?? []} onChange={refresh} />}
      </Load>
      {adding && <AddDialog onClose={() => setAdding(false)} onSaved={refresh} />}
    </>
  );
}

function DecideCard({ links, admin }: { links?: WebhookLink[]; admin: boolean }) {
  const pq = usePoll((s) => (admin ? policy(s) : Promise.resolve(undefined)), [admin]);
  const ai = admin ? (pq.data ? !!pq.data.models?.diagnosis && pq.data.decide.includes('ai') : undefined) : undefined;
  const hook = links ? links.some((l) => l.point === 'incident' && l.role === 'decide') : undefined;
  const now = ai ? 'ai' : hook ? 'webhook' : 'rules';
  const rows: [string, string, string, ReactNode][] = [
    ['ai', '1 AI 진단', 'AI 키가 있고 진단 모델이 응답할 때', ai === undefined ? <span className="muted">{admin ? '불러오는 중…' : '시스템 관리자만 봄'}</span> : ai ? <Badge tone="ok">지금 쓰는 것</Badge> : <Badge tone="un">키 없음 · 건너뜀</Badge>],
    ['webhook', '2 판단 웹훅', '사건 범위에 맞는 판단 웹훅 (앱 → 작업 공간 → 클러스터 순으로 하나)', hook === undefined ? <span className="muted">—</span> : now === 'webhook' ? <Badge tone="ok">지금 쓰는 것</Badge> : hook ? <span className="muted">AI 다음 대안</span> : <Badge tone="un">연결 없음 · 건너뜀</Badge>],
    ['rules', '3 규칙만', '신호마다 정한 기본 조치(예: 재시작 반복 → 컨테이너 재시작)를 후보로', now === 'rules' ? <Badge tone="ok">지금 쓰는 것</Badge> : <span className="muted">마지막 대안</span>],
  ];
  return (
    <section className="card">
      <div className="row between">
        <h2>판단 방식</h2>
        <span className="muted small">클러스터 기본 · 앱 장애 대응 탭에서 앱마다 바꿈</span>
      </div>
      <div className="layer decide">
        {rows.map(([k, a, b, c]) => (
          <div key={k} className={now === k ? 'us sel' : ''}>
            <b>{a}</b>
            <span>{b}</span>
            <span>{c}</span>
          </div>
        ))}
      </div>
      <span className="muted small">앞 단계가 없거나 실패·시간 초과(판단 웹훅 10초)면 다음 단계로 넘어갑니다. 알림 웹훅은 판단 방식과 상관없이 항상 받습니다.</span>
    </section>
  );
}

function Body({ hooks, links, onChange }: { hooks: Webhook[]; links: WebhookLink[]; onChange: () => void }) {
  const toast = useToast();
  const [filter, setFilter] = useState<Filter>('all');
  const [sel, setSel] = useState<string>();
  const [drawer, setDrawer] = useState<Webhook>();
  const [del, setDel] = useState<Webhook>();
  const [rotate, setRotate] = useState<Webhook>();
  const [secret, setSecret] = useState<{ name: string; value: string }>();
  const [test, setTest] = useState<Webhook>();
  const shown = hooks.filter((w) => filter === 'all' || w.kind === filter);
  const w = hooks.find((x) => x.name === sel) ?? hooks[0];
  const linksOf = (n: string) => links.filter((l) => l.webhook === n);
  const toggle = async (x: Webhook) => {
    try {
      await putWebhook(x.name, { revision: x.revision, enabled: x.enabled === false });
      toast(x.enabled === false ? `✓ ${x.name}을 다시 켰습니다.` : `✓ ${x.name}을 껐습니다. 연결은 그대로입니다.`);
    } catch (e) {
      toast(`바꾸지 못했습니다 · ${errorText(e).title}`);
    }
    onChange();
  };
  return (
    <>
      <section className="card">
        <div className="row between wrap">
          <h2>등록한 웹훅 ({hooks.length})</h2>
          <span className="segmented" role="radiogroup" aria-label="종류">
            {(
              [
                ['all', '전체'],
                ['external', '외부 호출'],
                ['internal', '클러스터 내부'],
              ] as [Filter, string][]
            ).map(([k, l]) => (
              <button key={k} type="button" role="radio" aria-checked={filter === k} className={filter === k ? 'on' : ''} onClick={() => setFilter(k)}>
                {l}
              </button>
            ))}
          </span>
        </div>
        {!shown.length ? (
          <div className="note un">{hooks.length ? '이 종류의 웹훅이 없습니다.' : '아직 등록한 웹훅이 없습니다. ‘＋ 웹훅 등록’으로 시작하세요.'}</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <div className="gtbl" style={{ minWidth: 1100 }}>
              <div className="gr th hooks">
                <span>이름</span>
                <span>종류</span>
                <span>보내는 곳</span>
                <span>역할</span>
                <span>연결된 곳</span>
                <span>서명</span>
                <span>최근 전송</span>
              </div>
              {shown.map((x) => {
                const ls = linksOf(x.name);
                return (
                  <div key={x.name} className={`gr hooks ${x.name === w?.name ? 'on' : ''}`}>
                    <button className="textbtn" style={{ fontWeight: 600, textAlign: 'left' }} onClick={() => setSel(x.name)}>
                      {x.name}
                    </button>
                    <span className={`kind ${x.kind === 'internal' ? 'int' : 'ext'}`}>{x.kind === 'internal' ? '⌂ 클러스터 내부' : '↗ 외부 호출'}</span>
                    <span className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>
                      {targetText(x)}
                    </span>
                    <span>{ROLE_NAME[x.role]}</span>
                    <span>{ls.length ? ls.map(linkText).join(' · ') : <span className="muted">연결 없음</span>}</span>
                    <span>{signText(x)}</span>
                    <span>{lastBadge(x)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
        <span className="muted small">웹훅은 여기 한 번 등록하고 장애 대응·자동 배포(CD 탭)·외부 접속(경로 규칙·게이트웨이)에서 연결해 씁니다. AI 키가 없어도 동작합니다. 시스템 관리자는 모든 웹훅, 작업 공간 관리자는 자기 작업 공간 웹훅만 등록합니다. 클러스터 내부 웹훅은 그 작업 공간의 앱 서비스만 고를 수 있습니다.</span>
      </section>
      {w && (
        <div className="grid-2">
          <section className="card sel-card">
            <div className="row between wrap">
              <h2>
                {w.name} · {w.kind === 'internal' ? '클러스터 내부' : '외부 호출'} · {ROLE_NAME[w.role]}
              </h2>
              <span className="row" style={{ gap: 8 }}>
                <button className="btn" disabled={w.enabled === false} title={w.enabled === false ? '꺼진 웹훅입니다' : undefined} onClick={() => setTest(w)}>
                  시험 보내기
                </button>
                <button className="btn" disabled={w.sign !== undefined ? w.sign !== 'hmac' : !w.secret.set} title={(w.sign ?? (w.secret.set ? 'hmac' : 'none')) !== 'hmac' ? 'HMAC 서명 웹훅만 비밀을 바꿉니다' : undefined} onClick={() => setRotate(w)}>
                  비밀 바꾸기
                </button>
                <Menu
                  label={`${w.name} 더보기`}
                  className="btn"
                  items={[
                    { label: '전송 기록', onSelect: () => setDrawer(w) },
                    { label: w.enabled === false ? '다시 켜기' : '끄기', onSelect: () => toggle(w), disabledReason: w.enabled === undefined ? '웹 기능 준비 중' : undefined },
                    { sep: true, label: '' },
                    { label: '지우기…', danger: true, onSelect: () => setDel(w) },
                  ]}
                />
              </span>
            </div>
            {w.disabledReason === 'failures' && (
              <div className="note wa small">
                <b>{w.name}</b> · {w.kind === 'internal' && w.target ? `${w.tenant}/${w.target.app}/${w.target.service} 서비스에 상태 검사를 통과한 컨테이너가 없습니다. ` : ''}3번 실패 후 꺼졌습니다.{' '}
                <button className="textbtn" onClick={() => toggle(w)}>
                  다시 켜기
                </button>
              </div>
            )}
            {w.disabledReason === 'restored' && <div className="note wa small">지운 것에서 꺼진 채로 되살렸습니다. 헤더 토큰은 되살아나지 않으니 새 토큰을 넣고 켜세요.</div>}
            {w.lastDelivery?.retry && (
              <div className="note wa small">
                {w.name} 전송이 {w.lastDelivery.retry.attempt}번 실패했습니다({w.lastDelivery.status}). 다시 시도하고, 계속 실패하면 꺼집니다.{' '}
                <button className="textbtn" onClick={() => setDrawer(w)}>
                  전송 기록
                </button>
              </div>
            )}
            <div className="kv2" style={{ gridTemplateColumns: '140px minmax(0,1fr)', fontSize: 13 }}>
              <span className="muted">보내는 곳</span>
              <span>{w.kind === 'internal' && w.target ? `작업 공간 ${w.tenant} · 앱 ${w.target.app} · 서비스 ${w.target.service} · 포트 ${w.target.port} · 경로 ${w.target.path}${w.target.scheme === 'https' ? ` · https${w.target.insecureSkipVerify ? ' (인증서 확인 안 함)' : ''}` : ''}` : <span className="mono">{w.url}</span>}</span>
              <span className="muted">가는 길</span>
              <span>{w.kind === 'internal' && w.target ? `sfc-web → 클러스터 내부 호출 → ${w.tenant} 망 안 ${w.target.app} 컨테이너. 컨테이너가 여러 개면 상태 검사 통과한 것 중 하나` : 'sfc-web → https 외부 호출 (리디렉션 따라가지 않음)'}</span>
              <span className="muted">받는 사건</span>
              <span>{linksOf(w.name).length ? linksOf(w.name).map((l) => `${POINT_NAME[l.point]} · ${l.label ?? ''} (${l.events.length}가지)`).join(' / ') : '연결 없음 · 장애 대응·자동 배포·외부 접속에서 연결하세요'}</span>
              <span className="muted">시간 초과 · 재시도</span>
              <span>
                {w.role === 'decide' ? '판단 10초 · 재시도 없음 (다음 단계로) · 알림은 3회 (1초·10초·1분)' : '알림 3회 (1초·10초·1분)'}
                {/* 내부 호출은 sfcd가 한 번만 보낸다. 앱에 닿지 않은 것이 확실할 때만 다시 보낸다(#264). */}
                {w.kind === 'internal' && <span className="small muted" style={{ display: 'block' }}>클러스터 내부는 답한 429·5xx와 준비된 컨테이너 없음·횟수 제한일 때만 다시 보냅니다. 시간 초과·연결 거부는 앱이 이미 받았을 수 있어 다시 보내지 않습니다.</span>}
              </span>
              <span className="muted">최근 전송</span>
              <span>{w.stats ? `오늘 ${w.stats.today}건 · 실패 ${w.stats.failed} · 평균 ${sec(w.stats.avgMs)}` : w.lastDelivery ? `${w.lastDelivery.status} · ${ago(w.lastDelivery.at)}` : '—'}</span>
              {w.secret.rotatingUntil && (
                <>
                  <span className="muted">서명 비밀</span>
                  <span>바꾸는 중 · {shortTime(w.secret.rotatingUntil)}까지 두 서명을 함께 보냄</span>
                </>
              )}
              {w.sign === 'token' && (
                <>
                  <span className="muted">헤더 토큰</span>
                  <span>봉인 · ··{w.token?.last4 ?? '????'}</span>
                </>
              )}
            </div>
            <pre className="code dark hook-code">{requestSample(w)}</pre>
          </section>
          <section className="card">
            <h2>판단 웹훅 응답</h2>
            <pre className="code dark hook-code">{RESPONSE_SAMPLE}</pre>
            <div className="rulebox">
              <span>
                · <span className="mono">actions</span>는 순서대로 최대 3개. 각 조치는 규칙 하한으로 등급을 매기고, 정책에 따라 자동 실행·승인 요청·반려로 나뉩니다.
              </span>
              <span>
                · <span className="mono">actions: []</span>는 "조치 없음 · 사람에게"입니다.
              </span>
              <span>· 응답은 사건 기록에 그대로 남습니다(64 KB까지).</span>
            </div>
            <div className="kv2" style={{ gridTemplateColumns: '140px minmax(0,1fr)', fontSize: 13 }}>
              <span className="muted">외부 호출 규칙</span>
              <span>https만 · 사설 주소(10.x, 192.168.x)는 '클러스터 내부'를 쓰라는 안내와 함께 막음 · 리디렉션 따라가지 않음</span>
              <span className="muted">전송 기록</span>
              <span>웹훅마다 최근 1,000건(본문 요약·응답 코드·시간) · 사건에는 판단 응답 전문</span>
            </div>
          </section>
        </div>
      )}
      {drawer && <DeliveriesDrawer w={drawer} onClose={() => setDrawer(undefined)} />}
      {test && <TestDialog w={test} onClose={() => (setTest(undefined), onChange())} />}
      {rotate && (
        <RotateDialog
          w={rotate}
          onClose={() => setRotate(undefined)}
          onDone={(v) => {
            setRotate(undefined);
            setSecret({ name: rotate.name, value: v });
            onChange();
          }}
        />
      )}
      {secret && <SecretDialog name={secret.name} value={secret.value} onClose={() => setSecret(undefined)} />}
      {del && <DeleteDialog w={del} links={linksOf(del.name)} onClose={() => setDel(undefined)} onDone={onChange} onSecret={(name, value) => setSecret({ name, value })} />}
    </>
  );
}

function requestSample(w: Webhook): string {
  const decide = w.role === 'decide';
  return [
    '// POST · Content-Type: application/json',
    `// X-SFC-Event: ${decide ? 'incident.decide' : 'incident.detected'} · X-SFC-Delivery: dlv-81c2`,
    w.sign === 'token' ? '// Authorization: 헤더 토큰 (봉인)' : w.sign === 'none' ? '// 서명 없음 · 주소가 비밀' : '// X-SFC-Signature: t=1795245600,v1=hmac_sha256(secret, t.body)',
    '{',
    '  "incident": "inc-0412", "scope": "app",',
    `  "target": {"tenant":"${w.tenant ?? 'shop'}", "app":"php-shop", "service":"worker"},`,
    '  "signal": {"rule":"restart-loop", "count":4, "window_s":600},',
    '  "recent_changes": [{"version":15, "by":"cd", "at":"…"}],',
    '  "allowed_actions": ["restart-task", "pause-cd", "cd-rollback"],',
    decide ? '  "respond_within_s": 10' : '  "level": "low"',
    '}',
  ].join('\n');
}
const RESPONSE_SAMPLE = `// 판단 웹훅의 응답 (200)
{
  "actions": [
    {"action":"pause-cd", "reason":"큐 11만, 배포 멈춤 먼저"},
    {"action":"restart-task", "task":"worker-2"}
  ],
  "notify": "#shop-oncall",
  "raise_level": "보통"   // 올리기만 가능
}`;

export function DeliveriesDrawer({ w, onClose }: { w: Webhook; onClose: () => void }) {
  const q = usePoll((s) => deliveries(w.name, undefined, s), [w.name], 0, deliveriesLive(w.name));
  return (
    <Drawer title={`${w.name} · 전송 기록`} onClose={onClose}>
      <Load q={q} rows={4} what="전송 기록을 불러오지 못했습니다">
        {(d) =>
          d.items.length ? (
            <div className="gtbl">
              <div className="gr th dlv">
                <span>언제</span>
                <span>사건</span>
                <span>어디서</span>
                <span>응답</span>
                <span>시간</span>
              </div>
              {d.items.map((x: Delivery) => (
                <div key={x.id} className="gr dlv" title={x.error}>
                  <span>{shortTime(x.at)}</span>
                  <span className="ellip" title={x.event}>
                    {x.event}
                  </span>
                  <span>{POINT_NAME[x.point]}</span>
                  <span>{x.firstStatus && x.firstStatus !== x.status ? `${x.firstStatus} → ${x.status || '실패'}` : x.status || '실패'}</span>
                  <span>{x.retries ? `재시도 ${x.retries}` : x.ms ? sec(x.ms) : '—'}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="muted small">아직 보낸 것이 없습니다.</div>
          )
        }
      </Load>
      <div className="muted small">웹훅마다 최근 1,000건(본문 요약·응답 코드·시간). 본문 전체는 사건 기록에만 남습니다.</div>
    </Drawer>
  );
}

function Steps({ d }: { d: Delivery }) {
  const okd = d.status >= 200 && d.status < 300;
  const steps = d.steps ?? [{ label: '응답', detail: d.status ? `${d.status} · ${sec(d.ms)}` : (d.error ?? '실패') }];
  return (
    <div className="steps-list">
      {steps.map((s, i) => (
        <div key={i}>
          <i className={okd || i < steps.length - 1 ? 'ok' : 'er'} />
          <span>{s.label}</span>
          <span className="muted">{s.detail ?? ''}</span>
        </div>
      ))}
    </div>
  );
}

export function TestDialog({ w, onClose }: { w: Webhook; onClose: () => void }) {
  const [d, setD] = useState<Delivery>();
  const [error, setError] = useState<unknown>();
  useEffect(() => {
    let live = true;
    testWebhook(w.name)
      .then((r) => live && setD(r))
      .catch((e) => live && setError(e));
    return () => {
      live = false;
    };
  }, [w.name]);
  return (
    <Dialog
      title="시험 보내기"
      width={420}
      onClose={onClose}
      footer={
        <button className="btn" onClick={onClose}>
          닫기
        </button>
      }
    >
      {!d && error === undefined && <div className="muted small">보내는 중…</div>}
      {d && <Steps d={d} />}
      {d && (d.status >= 200 && d.status < 300 ? <div className="note ok small">✓ 시험 전송이 성공했습니다.</div> : <div className="note er small">✗ 시험 전송이 실패했습니다{d.error ? ` · ${callError(d.error)}` : ''}.</div>)}
      {error !== undefined && <ErrorBand error={error} what="보내지 못했습니다" />}
    </Dialog>
  );
}

export function SecretDialog({ name, value, onClose }: { name: string; value: string; onClose: () => void }) {
  const toast = useToast();
  const close = async (copy: boolean) => {
    if (copy) {
      try {
        await navigator.clipboard.writeText(value);
        toast(`✓ ${name} 서명 비밀을 복사했습니다.`);
      } catch {
        toast('복사하지 못했습니다. 직접 골라 복사하세요.');
        return;
      }
    }
    onClose();
  };
  return (
    <Dialog
      title="서명 비밀"
      onClose={() => close(false)}
      footer={
        <button className="btn primary" onClick={() => close(true)}>
          복사하고 닫기
        </button>
      }
    >
      <Field label="비밀" hint="지금 복사하세요. 닫으면 다시 볼 수 없고 바꾸기만 됩니다">
        <input className="mono" readOnly value={value} onFocus={(e) => e.currentTarget.select()} autoComplete="off" spellCheck={false} />
      </Field>
      <pre className="code dark">{'t = X-SFC-Signature의 t\nv1 = hex(hmac_sha256(secret, t + "." + body))\n|now - t| > 300초면 버리기'}</pre>
    </Dialog>
  );
}

function RotateDialog({ w, onClose, onDone }: { w: Webhook; onClose: () => void; onDone: (secret: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await rotateWebhook(w.name);
      onDone(r.secret);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      danger
      width={420}
      title={`${w.name} 서명 비밀을 바꿀까요?`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger" disabled={busy} onClick={go}>
            바꾸기
          </button>
        </>
      }
    >
      <div>새 비밀을 만들고 24시간 동안 옛 비밀과 새 비밀 두 서명을 함께 보냅니다(v1=…,v1=…). 받는 쪽을 바꾼 뒤 옛 비밀을 지금 끝낼 수 있습니다.</div>
      {error !== undefined && <ErrorBand error={error} what="바꾸지 못했습니다" />}
    </Dialog>
  );
}

function DeleteDialog({ w, links, onClose, onDone, onSecret }: { w: Webhook; links: WebhookLink[]; onClose: () => void; onDone: () => void; onSecret: (name: string, value: string) => void }) {
  const undoToast = useUndoToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const counts = (['incident', 'cd', 'ingress'] as const).map((p) => [p, links.filter((l) => l.point === p).length] as const).filter(([, n]) => n);
  return (
    <ConfirmDialog
      title={`${w.name} 웹훅을 지울까요?`}
      target={w.name}
      actionLabel="지우기"
      busy={busy}
      onClose={onClose}
      onConfirm={async () => {
        setBusy(true);
        setError(undefined);
        try {
          const r = await deleteWebhook(w.name, w.name);
          // 실행 취소 = 지운 것 되살리기. HMAC 웹훅은 새 서명 비밀을 한 번만 받아 보여 준다
          undoToast(`✓ ${w.name} 웹훅을 지웠습니다.`, r?.trash, async (id) => {
            const x = await restoreTrash(id, {});
            onDone();
            if (x.secret?.value) onSecret(x.restored?.name ?? w.name, x.secret.value);
          });
          onDone();
          onClose();
        } catch (e) {
          setError(e);
        } finally {
          setBusy(false);
        }
      }}
    >
      <div>
        {counts.length ? `${counts.map(([p, n]) => `${POINT_NAME[p]} ${n}곳`).join(', ')}에 연결돼 있습니다. 지우면 그 연결도 모두 끊깁니다. ` : '연결된 곳이 없습니다. '}잠시 멈추려면 “끄기”를 쓰세요.
      </div>
      <div className="small muted">지운 뒤에도 보관 기간 동안 작업 기록 › 지운 것에서 되살릴 수 있습니다. 서명 비밀·토큰은 되살아나지 않습니다.</div>
      {error !== undefined && <ErrorBand error={error} what="지우지 못했습니다" />}
    </ConfirmDialog>
  );
}

function AddDialog({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const session = useSession();
  const tenants = useMemo(() => session.tenants.filter((t) => session.user.systemAdmin || t.role === 'manager').map((t) => t.id), [session]);
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [kind, setKind] = useState<HookKind>('external');
  const [name, setName] = useState('');
  const [tenant, setTenant] = useState<string>(session.user.systemAdmin ? '' : (tenants[0] ?? ''));
  const [role, setRole] = useState<HookRole>('notify');
  const [url, setUrl] = useState('https://');
  const [sign, setSign] = useState<HookSign>('hmac');
  const [token, setToken] = useState('');
  const [format, setFormat] = useState<HookFormat>('sfc');
  const [app, setApp] = useState('');
  const [service, setService] = useState('');
  const [port, setPort] = useState('8080');
  const [path, setPath] = useState('/');
  const [scheme, setScheme] = useState<'http' | 'https'>('http');
  const [skipVerify, setSkipVerify] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [result, setResult] = useState<{ d?: Delivery; testError?: unknown }>();
  const [secret, setSecret] = useState<string>();
  const appsQ = usePoll((s) => (kind === 'internal' && tenant ? apps(tenant, s) : Promise.resolve(undefined)), [kind, tenant], 0, appsLive(tenant));
  const tasksQ = usePoll((s) => (kind === 'internal' && tenant && app ? appTasks(tenant, app, s) : Promise.resolve(undefined)), [kind, tenant, app], 0, appLive(tenant, app));
  const services = [...new Set((tasksQ.data?.items ?? []).map((t) => t.service))];
  const nameBad = name !== '' && !HOOK_NAME_RE.test(name);
  const urlPrivate = privateHost(url);
  const urlBad = url !== 'https://' && (!/^https:\/\/[^\s/]+/.test(url) || urlPrivate);
  const portN = Number(port);
  const step1Ok = !!name && !nameBad && (kind === 'external' || !!tenant);
  const step2Ok = kind === 'external' ? url !== 'https://' && !urlBad && (sign !== 'token' || !!token) : !!app && !!service && Number.isInteger(portN) && portN > 0 && portN < 65536 && path.startsWith('/');
  const send = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await createWebhook({
        name,
        ...(tenant ? { tenant } : {}),
        kind,
        role,
        format: kind === 'internal' ? 'sfc' : format,
        ...(kind === 'external' ? { url, sign, ...(sign === 'token' ? { token } : {}) } : { target: { app, service, port: portN, path, scheme, ...(scheme === 'https' && skipVerify ? { insecureSkipVerify: true } : {}) }, sign: 'hmac' as const }),
      });
      setToken('');
      setSecret(secretValue(r.secret));
      onSaved();
      try {
        setResult({ d: await testWebhook(name) });
      } catch (e) {
        setResult({ testError: e });
      }
      setStep(3);
    } catch (e) {
      setToken('');
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const done = () => {
    setSecret(undefined);
    onSaved();
    onClose();
  };
  const steps = (
    <div className="steps-list">
      {(['종류', '보내는 곳 · 서명', '시험'] as const).map((l, i) => (
        <div key={l}>
          <i className={i + 1 < step ? 'ok' : i + 1 === step ? 'pr' : ''} />
          <span>{l}</span>
          <span />
        </div>
      ))}
    </div>
  );
  if (step === 3)
    return (
      <>
        <Dialog
          title={`${name} · 시험 보내기`}
          width={420}
          onClose={() => (secret ? undefined : done())}
          footer={
            !secret && (
              <button className="btn primary" onClick={done}>
                닫기
              </button>
            )
          }
        >
          {steps}
          {result?.d && <Steps d={result.d} />}
          {result?.d && (result.d.status >= 200 && result.d.status < 300 ? <div className="note ok small">✓ 시험 전송이 성공했습니다.{secret ? ' 서명 비밀은 아래에 한 번만 보입니다.' : ''}</div> : <div className="note er small">✗ 시험 전송이 실패했습니다{result.d.error ? ` · ${callError(result.d.error)}` : ''}. 웹훅은 등록됐습니다.</div>)}
          {result?.testError !== undefined && <ErrorBand error={result.testError} what="시험하지 못했습니다 · 웹훅은 등록됐습니다" />}
        </Dialog>
        {secret && <SecretDialog name={name} value={secret} onClose={done} />}
      </>
    );
  return (
    <Dialog
      title={step === 1 ? '웹훅 등록' : `${name} · 보내는 곳`}
      onClose={onClose}
      footer={
        step === 1 ? (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={!step1Ok} onClick={() => setStep(2)}>
              다음
            </button>
          </>
        ) : (
          <>
            <button className="btn" onClick={() => setStep(1)}>
              뒤로
            </button>
            <button className="btn primary" disabled={busy || !step2Ok} onClick={send}>
              {busy ? '보내는 중…' : '시험 보내기'}
            </button>
          </>
        )
      }
    >
      {steps}
      {step === 1 ? (
        <>
          <label className="check" style={{ alignItems: 'flex-start' }}>
            <input type="radio" name="hook-kind" checked={kind === 'external'} onChange={() => setKind('external')} />
            <span>
              ↗ 외부 호출
              <span className="muted small" style={{ display: 'block' }}>
                인터넷의 https 주소로 보냅니다 (PagerDuty, Slack, Teams, 사내 봇 등)
              </span>
            </span>
          </label>
          <label className="check" style={{ alignItems: 'flex-start' }}>
            <input type="radio" name="hook-kind" checked={kind === 'internal'} onChange={() => (setKind('internal'), !tenant && tenants[0] && setTenant(tenants[0]))} />
            <span>
              ⌂ 클러스터 내부
              <span className="muted small" style={{ display: 'block' }}>
                작업 공간 안에서 돌고 있는 앱 서비스로 보냅니다. 밖으로 열지 않아도 됩니다
              </span>
            </span>
          </label>
          <div className="g2">
            <Field label="이름" hint="영문 소문자·숫자·-" error={nameBad ? '영문 소문자로 시작, 영문 소문자·숫자·-만, 31자까지' : undefined}>
              <input className="mono" value={name} autoComplete="off" spellCheck={false} onChange={(e) => setName(e.target.value.trim())} />
            </Field>
            <Field label="작업 공간">
              <select value={tenant} onChange={(e) => setTenant(e.target.value)}>
                {session.user.systemAdmin && (
                  <option value="" disabled={kind === 'internal'}>
                    클러스터 (시스템 관리자)
                  </option>
                )}
                {tenants.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <Field label="역할">
            <select value={role} onChange={(e) => setRole(e.target.value as HookRole)}>
              <option value="notify">알림 (소식만)</option>
              <option value="decide">판단 (조치·결정을 답함)</option>
            </select>
          </Field>
        </>
      ) : kind === 'external' ? (
        <>
          <Field label="주소" hint="https만 · 사설 주소 안 됨 · 리다이렉트 따라가지 않음" error={urlPrivate ? "사설 주소입니다. 클러스터 안의 앱이면 '클러스터 내부'를 쓰세요." : urlBad ? 'https:// 주소를 넣으세요' : undefined}>
            <input className="mono" value={url} autoComplete="off" spellCheck={false} onChange={(e) => setUrl(e.target.value.trim())} />
          </Field>
          <Field label="서명">
            <select value={sign} onChange={(e) => setSign(e.target.value as HookSign)}>
              <option value="hmac">HMAC-SHA256 (X-SFC-Signature)</option>
              <option value="token">헤더 토큰</option>
              <option value="none">없음</option>
            </select>
          </Field>
          {sign === 'token' && (
            <Field label="헤더 토큰" hint="봉인 파일에 저장 · 다시 보이지 않음">
              <input type="password" value={token} autoComplete="new-password" onChange={(e) => setToken(e.target.value)} />
            </Field>
          )}
          <Field label="본문 형식">
            <select value={format} onChange={(e) => setFormat(e.target.value as HookFormat)}>
              {(Object.keys(FORMAT_NAME) as HookFormat[]).map((f) => (
                <option key={f} value={f}>
                  {FORMAT_NAME[f]}
                </option>
              ))}
            </select>
          </Field>
        </>
      ) : (
        <>
          <Field label="작업 공간">
            <select value={tenant} onChange={(e) => (setTenant(e.target.value), setApp(''), setService(''))}>
              {tenants.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </Field>
          <div className="g2">
            <Field label="앱">
              <select value={app} onChange={(e) => (setApp(e.target.value), setService(''))}>
                <option value="">고르세요</option>
                {(appsQ.data?.items ?? []).map((a) => (
                  <option key={a.app} value={a.app}>
                    {a.app}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="서비스">
              <select value={service} onChange={(e) => setService(e.target.value)} disabled={!app}>
                <option value="">{app ? (tasksQ.loading ? '불러오는 중…' : '고르세요') : '앱을 먼저 고르세요'}</option>
                {services.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <div className="g2">
            <Field label="포트">
              <input className="mono" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.trim())} />
            </Field>
            <Field label="경로">
              <input className="mono" value={path} onChange={(e) => setPath(e.target.value.trim())} />
            </Field>
          </div>
          <Field label="프로토콜">
            <select value={scheme} onChange={(e) => setScheme(e.target.value as 'http' | 'https')}>
              <option value="http">http (망 안이라 평문 허용)</option>
              <option value="https">https (작업 공간 CA로 인증서 확인)</option>
            </select>
          </Field>
          {scheme === 'https' && (
            <label className="check small">
              <input type="checkbox" checked={skipVerify} onChange={(e) => setSkipVerify(e.target.checked)} /> 작업 공간 CA가 믿지 않는 인증서도 받기 <span className="muted">(자체 서명 인증서 · 권하지 않음)</span>
            </label>
          )}
          <div className="note info small">sfc가 이 서비스의 상태 검사 통과 컨테이너 하나로 대신 전달합니다. 아무 IP나 적을 수는 없고, 고른 작업 공간의 앱 서비스만 됩니다.</div>
          <div className="kv2" style={{ gridTemplateColumns: '60px minmax(0,1fr)', fontSize: 12 }}>
            <span className="muted">서명</span>
            <span>HMAC-SHA256 · 비밀은 지금 만들어 한 번만 보여 줌</span>
          </div>
        </>
      )}
      {error !== undefined && (error instanceof ApiError && error.code === 'private-address' ? <div className="note er small">{error.body.message}</div> : <ErrorBand error={error} what="등록하지 못했습니다" />)}
    </Dialog>
  );
}
