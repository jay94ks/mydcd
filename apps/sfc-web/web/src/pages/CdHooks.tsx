// SPDX-License-Identifier: Apache-2.0

// 배포 › 앱 › 자동 배포 탭 › 자동 배포 웹훅 (UI-44, 캔버스 CD · CDHooksIx).
// 계약: /mnt/project-files/w2/cd-webhooks-contract.md. 연결·호출·판단 응답 처리는 웹 데몬 몫이고, 후보 승인·반려·ApproveCD 위임은 sfcd다.
// 웹훅 등록(주소·서명 비밀)은 장애 대응 › 웹훅에서 하고 여기서는 연결만 한다.
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ApiError } from '../api/client';
import type { DCdState } from '../api/dto';
import type { AppView } from '../api/types';
import { CD_EVENTS, CD_KIND_NAME, createCdLink, deleteLink, putLink, webhookLinks, webhooks, type CdGate, type CdHookKind, type CdLinkInput, type Webhook, type WebhookLink } from '../api/webhooks';
import { Badge, Card, Field, ScreenIds } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { Popover } from '../components/Popover';
import { useToast } from '../components/Toast';
import { ago } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { eulReul } from '../lib/josa';
import { DeliveriesDrawer, TestDialog, lastBadge } from './IncidentHooks';
import { kindsLive } from '../lib/liveTopics';

const NEED = '이 작업 공간의 관리자 권한이 필요합니다';
const short = (c?: string) => (c ? c.slice(0, 7) : '—');
/** 화면의 알림 사건 칸. 일시정지와 다시 시작은 한 칸이다(캔버스) */
const EVENT_UI: [string[], string][] = CD_EVENTS.filter(([k]) => k !== 'resumed').map(([k, n]) => (k === 'paused' ? [['paused', 'resumed'], '일시정지 · 다시 시작'] : [[k], n]));
const eventGroups = (ev: string[]) => EVENT_UI.filter(([ks]) => ks.some((k) => ev.includes(k)));
const TIMEOUT_NAME: Record<string, string> = { hold: '보류 (사람 승인 대기)', pass: '통과', reject: '거부 (후보 반려)', fail: '실패로 보기' };
const KindBadge = ({ w }: { w?: Webhook }) => (w ? <span className={`kind ${w.kind === 'internal' ? 'int' : 'ext'}`}>{w.kind === 'internal' ? '⌂ 클러스터 내부' : '↗ 외부 호출'}</span> : <span className="muted">—</span>);
const hookLabel = (w: Webhook) => `${w.name} · ${w.kind === 'internal' ? '⌂ 클러스터 내부' : '↗ 외부 호출'} · ${w.role === 'decide' ? '판단' : '알림'}`;

function whenText(l: WebhookLink): string {
  if (l.kind === 'pre-sync') return '새 후보가 생기고 승인 조건을 통과한 뒤';
  if (l.kind === 'post-sync') return l.when === 'synced' ? `동기화 성공 직후 (최대 ${l.waitSeconds ?? 60}초)` : `동기화 성공 · 상태 검사 통과 뒤 (최대 ${l.waitSeconds ?? 60}초)`;
  const ev = eventGroups(l.events).map(([, n]) => n);
  return ev.length <= 2 ? `${ev.join(' · ')}만` : ev.join(' · ');
}
function answerText(l: WebhookLink): string {
  if (l.kind === 'pre-sync') return `통과 → 자동 승인 · 보류 → 사람 승인 대기 · 거부 → 후보 반려${l.onTimeout && l.onTimeout !== 'hold' ? ` · 시간 초과 → ${TIMEOUT_NAME[l.onTimeout]}` : ''}`;
  if (l.kind === 'post-sync') return `정상 → 끝 · 실패 → 자동 배포 일시정지${l.onFail === 'pause-rollback' ? ' + 되돌리기 승인 요청' : ''}`;
  return '—';
}
const ANSWER: Record<string, [string, 'ok' | 'wa' | 'er']> = { pass: ['통과', 'ok'], hold: ['보류', 'wa'], reject: ['거부', 'er'], ok: ['정상', 'ok'], fail: ['실패', 'er'] };
function recent(l: WebhookLink, w?: Webhook): ReactNode {
  const x = l.last;
  if (!x) return w ? lastBadge(w) : <span className="muted">아직 없음</span>;
  const sec = x.ms !== undefined ? `${(x.ms / 1000).toFixed(1)}초` : '';
  if (x.answer && ANSWER[x.answer]) {
    const [t, tone] = ANSWER[x.answer];
    return <Badge tone={tone}>{[t, short(x.commit), l.kind === 'post-sync' ? sec : ago(x.at)].filter(Boolean).join(' · ')}</Badge>;
  }
  return <Badge tone={x.status && x.status >= 200 && x.status < 300 ? 'ok' : 'er'}>{`${x.status || '실패'} · ${ago(x.at)}`}</Badge>;
}

/** 자동 배포 웹훅 카드. 후보의 배포 전 확인 상태는 CdGateNote가 보인다 */
export function CdHooksCard({ a, cd, canManage, onChange }: { a: AppView; cd: DCdState; canManage: boolean; onChange: () => void }) {
  const lq = usePoll((s) => webhookLinks({ point: 'cd', tenant: a.tenant, app: a.app }, s), [a.tenant, a.app], 0, kindsLive('webhook-link'));
  const hq = usePoll((s) => webhooks(undefined, s), [], 0, kindsLive('webhook'));
  const [add, setAdd] = useState(false);
  const [edit, setEdit] = useState<WebhookLink>();
  const [del, setDel] = useState<WebhookLink>();
  const [test, setTest] = useState<Webhook>();
  const [drawer, setDrawer] = useState<Webhook>();
  const hooks = hq.data?.items ?? [];
  const hookOf = (n: string) => hooks.find((w) => w.name === n);
  const refresh = () => (void lq.refresh(), onChange());
  const kindsOf = (n: string) => [...new Set(sortLinks(lq.data?.items ?? []).filter((l) => l.webhook === n && l.kind).map((l) => CD_KIND_NAME[l.kind!]))].join(' · ');
  const linked = [...new Set((lq.data?.items ?? []).map((l) => l.webhook))].map(hookOf).filter((w): w is Webhook => !!w);
  return (
    <Card
      title={
        <h2>
          자동 배포 웹훅 <ScreenIds ids="UI-44" />
        </h2>
      }
      actions={
        <span className="row" style={{ gap: 8 }}>
          <Menu label="전송 기록" className="btn" button="전송 기록" items={linked.length ? linked.map((w) => ({ label: w.name, hint: kindsOf(w.name), onSelect: () => setDrawer(w) })) : [{ label: '연결된 웹훅이 없습니다', disabledReason: '먼저 웹훅을 연결하세요' }]} />
          <button className="btn primary" disabled={!canManage} title={canManage ? undefined : NEED} onClick={() => setAdd(true)}>
            ＋ 웹훅 연결
          </button>
        </span>
      }
    >
      <span className="small" style={{ color: 'var(--text-2, #3D4450)' }}>
        자동 배포의 세 지점에 웹훅을 답니다. <b>배포 전 확인</b>은 새 후보를 실행하기 전에 웹훅에 물어 <b>통과 · 보류 · 거부</b>를 받고, <b>배포 후 확인</b>은 실행이 끝난 뒤 웹훅(예: 스모크 테스트)이 <b>정상 · 실패</b>를 답하며, <b>알림</b>은 소식만 보냅니다. 종류는 장애 대응 웹훅과 같이 인터넷으로 나가는 <b>외부 호출</b>과 작업 공간 안의 앱 서비스로 보내는 <b>클러스터 내부</b> 두 가지입니다. AI 없이 동작합니다.
      </span>
      <Load q={lq} rows={3} what="웹훅 연결을 읽지 못했습니다">
        {(d) =>
          d.items.length ? (
            <div className="gtbl">
              <div className="gr th cdh">
                <span>지점</span>
                <span>언제</span>
                <span>웹훅</span>
                <span>종류</span>
                <span>답에 따라</span>
                <span>최근</span>
                <span />
              </div>
              {sortLinks(d.items).map((l) => {
                const w = hookOf(l.webhook);
                return (
                  <div key={l.id} className="gr cdh">
                    <span>
                      <b>{l.kind ? CD_KIND_NAME[l.kind] : '—'}</b>
                      {l.kind === 'pre-sync' && l.approver && <ApproverPop l={l} />}
                      {l.kind === 'post-sync' && <PostProgress l={l} g={cd.checks?.['post-sync'] ?? (cd.webhook?.kind === 'post-sync' ? cd.webhook : undefined)} />}
                    </span>
                    <span>{whenText(l)}</span>
                    <span>{l.webhook}</span>
                    <span>
                      <KindBadge w={w} />
                    </span>
                    <span>{answerText(l)}</span>
                    <span>{recent(l, w)}</span>
                    <span>
                      <Menu
                        label={`${l.webhook} 연결 더보기`}
                        button="⋯"
                        items={[
                          { label: '설정…', onSelect: () => setEdit(l), disabledReason: canManage ? undefined : NEED },
                          { label: '시험 보내기', onSelect: () => w && setTest(w), disabledReason: w ? undefined : '웹훅을 볼 권한이 없습니다' },
                          { label: '전송 기록', onSelect: () => w && setDrawer(w), disabledReason: w ? undefined : '웹훅을 볼 권한이 없습니다' },
                          { sep: true, label: '' },
                          { label: '연결 끊기…', danger: true, onSelect: () => setDel(l), disabledReason: canManage ? undefined : NEED },
                        ]}
                      />
                    </span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="muted small">연결된 웹훅이 없습니다. ‘＋ 웹훅 연결’로 배포 전·후 확인이나 알림을 답니다.</div>
          )
        }
      </Load>
      <div className="grid-2">
        <pre className="code dark hook-code">{PRE_SAMPLE(a, cd, lq.data?.items.find((l) => l.kind === 'pre-sync')?.waitSeconds ?? 10)}</pre>
        <div className="col" style={{ gap: 8, fontSize: 13, lineHeight: '20px' }}>
          <div className="note small" style={{ background: 'var(--surface-2)' }}>
            · 배포 전 확인은 동기화 모드가 <b>‘수동’</b>(승인 후 배포)일 때만 겁니다. 웹훅이 통과를 주면 sfc-web이 <b>배포 확인 계정</b>(자동 작업 계정 sfc-autofix에 이 앱의 ApproveCD만 준 것)으로 승인해 실행합니다.
            <br />· 시간 초과·잘못된 답은 기본이 <b>보류</b>입니다(사람 승인 대기, 연결 설정에서 통과·거부로 바꿀 수 있음). 웹훅이 승인을 대신할 수는 있어도 비밀값 묶음 승인처럼 사람이 해야 하는 승인은 건너뛰지 못합니다.
            <br />· 배포 후 확인이 실패하면 자동 배포를 멈추고, 고르면 되돌리기를 승인 요청으로 엽니다. 웹훅이 되돌리기를 직접 실행하지는 않습니다.
            <br />· 요청에 비밀값·환경 변수 값은 넣지 않습니다(키 이름만).
          </div>
          <span className="muted small">
            웹훅 등록(주소·서명 비밀)은 <Link to="/incidents/hooks">장애 대응 › 웹훅</Link>에서 한 번만 하고 여기서는 연결만 합니다. 클러스터 내부 웹훅은 sfc가 앱 서비스로 대신 전달합니다.
          </span>
        </div>
      </div>
      {add && <LinkDialog a={a} cd={cd} hooks={hooks} links={lq.data?.items ?? []} onClose={() => setAdd(false)} onSaved={refresh} />}
      {edit && <LinkDialog a={a} cd={cd} hooks={hooks} links={lq.data?.items ?? []} link={edit} onClose={() => setEdit(undefined)} onSaved={refresh} />}
      {del && <UnlinkDialog l={del} onClose={() => setDel(undefined)} onDone={refresh} />}
      {test && <TestDialog w={test} onClose={() => setTest(undefined)} />}
      {drawer && <DeliveriesDrawer w={drawer} onClose={() => setDrawer(undefined)} />}
    </Card>
  );
}

const ORDER: Record<string, number> = { 'pre-sync': 0, 'post-sync': 1, notify: 2 };
const sortLinks = (ls: WebhookLink[]) => [...ls].sort((x, y) => (ORDER[x.kind ?? ''] ?? 3) - (ORDER[y.kind ?? ''] ?? 3));

const PRE_SAMPLE = (a: AppView, cd: DCdState, wait: number) => `// 배포 전 확인 요청 · X-SFC-Event: pre-sync · HMAC 서명
{
  "event": "pre-sync", "deliveryId": "dlv-9a41", "at": "…",
  "tenant": "${a.tenant}", "app": "${a.app}",
  "candidate": {"id": "…", "commit": "${short(cd.candidate ?? 'b77d210')}", "from": "${short(cd.running ?? '4e1c9a0')}"},
  "deadline": "…(${wait}초 뒤)", "allowed": ["pass", "hold", "reject"]
}
// 응답
{ "decision": "pass" | "hold" | "reject", "reason": "e2e 212개 통과" }`;

function ApproverPop({ l }: { l: WebhookLink }) {
  const ap = l.approver!;
  return (
    <span style={{ display: 'block' }}>
      <Popover button={ap.state === 'ok' ? '배포 확인 계정' : '배포 확인 계정 · 확인 필요'} className={`textbtn small ${ap.state === 'ok' ? '' : 'er'}`} width={340}>
        {() => (
          <div className="col" style={{ gap: 8 }}>
            <b>배포 확인 계정</b>
            <div className="kv2" style={{ gridTemplateColumns: '96px minmax(0,1fr)', fontSize: 12 }}>
              <span className="muted">계정</span>
              <span>{ap.account} (자동 작업 계정)</span>
              <span className="muted">권한</span>
              <span className="mono">{ap.scope}</span>
              <span className="muted">키</span>
              <span>웹 앱 설정의 자동 작업 계정 · 봉인 파일</span>
              <span className="muted">하는 일</span>
              <span>웹훅이 통과를 주면 이 앱 후보 승인 · 거부면 반려</span>
              <span className="muted">못 하는 일</span>
              <span>비밀값 묶음 승인 · 다른 앱</span>
            </div>
            <span className="small muted">배포 전 확인 연결을 끊으면 이 앱 권한만 거둡니다. 계정은 그대로입니다.</span>
            {ap.state !== 'ok' && (
              <div className="note wa small">
                자동 작업 계정이 없어(또는 sfc가 권한을 거부해) 연결은 저장됐지만 웹훅을 부르지 않습니다. <Link to="/incidents/policy">자동 작업 계정 만들기</Link>
              </div>
            )}
          </div>
        )}
      </Popover>
    </span>
  );
}

const POST_STATE: Record<string, [string, 'ok' | 'er' | 'wa' | 'un']> = { checking: ['확인 중', 'un'], ok: ['정상', 'ok'], failed: ['실패', 'er'], timeout: ['시간 초과', 'wa'] };
/** 배포 후 확인 진행: 동기화 성공 → 확인 → 자동 배포 일시정지 → 되돌리기 승인 요청 */
function PostProgress({ l, g }: { l: WebhookLink; g?: CdGate }) {
  if (!g) return <span className="small muted" style={{ display: 'block' }}>아직 확인한 배포 없음</span>;
  const [label, tone] = POST_STATE[g.state] ?? [g.state, 'un'];
  const act = (k: 'pause' | 'rollback-request') => g.actions?.find((x) => x.kind === k);
  const step = (cls: string, text: ReactNode) => (
    <div>
      <i className={cls} />
      <span>{text}</span>
    </div>
  );
  const ai = (k: 'pause' | 'rollback-request') => {
    const a = act(k);
    return !a ? 'pr' : a.state === 'done' ? 'ok' : 'er';
  };
  const failed = g.state === 'failed' || (g.state === 'timeout' && l.onTimeout === 'fail');
  return (
    <Popover button={<span className="small" style={{ display: 'block' }}>진행 보기 · <Badge tone={tone}>{label}</Badge></span>} className="linkish" width={340} align="left">
      {() => (
        <div style={{ display: 'grid', gap: 8 }}>
          <b>
            배포 후 확인 · <code>{short(g.candidate)}</code> · {ago(g.at)}
          </b>
          <div className="steps-list">
            {step('ok', '동기화 성공')}
            {step(g.state === 'checking' ? 'pr' : g.state === 'ok' ? 'ok' : 'er', <>{g.webhook ?? l.webhook} 확인 · {label}{g.reason ? ` · “${g.reason}”` : ''}</>)}
            {failed && step(ai('pause'), <>자동 배포 일시정지{act('pause')?.state === 'failed' ? ` 실패${act('pause')?.code ? ` (${act('pause')?.code})` : ''}` : ''}</>)}
            {failed && l.onFail === 'pause-rollback' && step(ai('rollback-request'), act('rollback-request')?.incident ? <>되돌리기 승인 요청 · <Link to={`/incidents/${act('rollback-request')!.incident}`}>{act('rollback-request')!.incident}</Link></> : <>되돌리기 승인 요청{act('rollback-request')?.state === 'failed' ? ' 실패' : ''}</>)}
          </div>
          {failed && <span className="small muted">되돌리기는 늘 사람이 승인합니다. 원인을 고친 뒤 자동 배포를 다시 시작하세요.</span>}
        </div>
      )}
    </Popover>
  );
}

/** 가져올 곳 카드 안: 후보의 배포 전 확인 상태 */
export function CdGateNote({ a, cd }: { a: AppView; cd: DCdState }) {
  const lq = usePoll((s) => webhookLinks({ point: 'cd', tenant: a.tenant, app: a.app }, s), [a.tenant, a.app], 0, kindsLive('webhook-link'));
  const g = cd.checks?.['pre-sync'] ?? (cd.webhook && cd.webhook.kind !== 'post-sync' ? cd.webhook : undefined);
  if (!g || !cd.candidate) return null;
  const l = lq.data?.items.find((x) => x.id === g.link);
  const name = g.webhook ?? l?.webhook ?? '배포 전 확인 웹훅';
  const c = short(g.candidate ?? cd.candidate);
  if (g.state === 'checking') {
    const el = Math.max(0, Math.round((Date.now() - Date.parse(g.at)) / 1000));
    return (
      <div className="note small row" style={{ gap: 8 }}>
        <Badge tone="un">웹훅 확인 중</Badge>
        <span>
          <code>{c}</code> · {name} · {Math.min(el, l?.waitSeconds ?? el)}초 / {l?.waitSeconds ?? '—'}초
        </span>
      </div>
    );
  }
  if (g.state === 'held' || g.state === 'timeout' || g.state === 'failed')
    return (
      <div className="note wa small">
        <b>{c} 보류</b> · {name}: {g.state === 'held' ? `“${g.reason ?? '이유 없음'}”` : g.state === 'timeout' ? '시간 안에 답하지 않았습니다' : g.reason ?? `응답을 받지 못했습니다${g.status ? ` (${g.status})` : ''}`}. 사람이 승인하면 실행됩니다.
      </div>
    );
  if (g.state === 'rejected')
    return (
      <div className="note er small">
        <b>{c} 거부</b> · {name}: “{g.reason ?? '이유 없음'}”. 후보를 반려했고 지금 버전({short(cd.running)})은 그대로입니다.
      </div>
    );
  return (
    <div className="note ok small">
      {name} 통과{g.reason ? ` · ${g.reason}` : ''}
    </div>
  );
}

function LinkDialog({ a, cd, hooks, links, link, onClose, onSaved }: { a: AppView; cd: DCdState; hooks: Webhook[]; links: WebhookLink[]; link?: WebhookLink; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const has = (k: CdHookKind) => links.some((l) => l.kind === k && l.id !== link?.id);
  const first: CdHookKind = link?.kind ?? (!has('pre-sync') ? 'pre-sync' : !has('post-sync') ? 'post-sync' : 'notify');
  const [kind, setKind] = useState<CdHookKind>(first);
  const usable = hooks.filter((w) => (!w.tenant || w.tenant === a.tenant) && (kind === 'notify' ? w.role === 'notify' : w.role === 'decide'));
  const [hook, setHook] = useState(link?.webhook ?? '');
  const webhook = usable.some((w) => w.name === hook) ? hook : (usable[0]?.name ?? '');
  const [wait, setWait] = useState(String(link?.waitSeconds ?? (first === 'pre-sync' ? 10 : 60)));
  const [onTimeout, setOnTimeout] = useState<string>(link?.onTimeout ?? (first === 'post-sync' ? 'pass' : 'hold'));
  const [when, setWhen] = useState(link?.when ?? 'healthy');
  const [onFail, setOnFail] = useState(link?.onFail ?? 'pause-rollback');
  const [openIncident, setOpenIncident] = useState(link?.openIncident ?? true);
  const [events, setEvents] = useState<string[]>(link?.events?.length ? link.events : ['candidate-created', 'approval-required', 'sync-succeeded', 'sync-failed', 'drift-detected', 'rolled-back']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [test, setTest] = useState<Webhook>();
  const ws = Number(wait);
  const waitBad = kind !== 'notify' && !(Number.isInteger(ws) && ws >= 5 && ws <= (kind === 'pre-sync' ? 30 : 600));
  const manual = (cd.policy?.sync.mode ?? cd.mode) === 'manual';
  const pick = (k: CdHookKind) => {
    setKind(k);
    setOnTimeout(k === 'post-sync' ? 'pass' : 'hold');
    if (!link) setWait(k === 'pre-sync' ? '10' : '60');
  };
  const body = (): CdLinkInput => ({
    webhook,
    kind,
    ...(kind === 'notify' ? { events } : { waitSeconds: ws, onTimeout: onTimeout as CdLinkInput['onTimeout'] }),
    ...(kind === 'post-sync' ? { when, onFail, openIncident } : {}),
  });
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      if (link) await putLink(link.id, { ...body(), revision: link.revision });
      else await createCdLink(a.tenant, a.app, body());
      toast(link ? `${CD_KIND_NAME[kind]} 연결을 바꿨습니다.` : `${webhook}${eulReul(webhook)} ${CD_KIND_NAME[kind]}에 연결했습니다.`);
      onSaved();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const radio = (k: CdHookKind, label: string, note: string) => {
    const off = !link && k !== 'notify' && has(k) ? `이미 ${label}이 있습니다` : link && link.kind !== k ? '연결 종류는 바꿀 수 없습니다. 끊고 새로 연결하세요' : undefined;
    return (
      <label className="check" style={{ alignItems: 'flex-start' }} title={off}>
        <input type="radio" name="cd-kind" checked={kind === k} disabled={!!off} onChange={() => pick(k)} />
        <span>
          {label}
          <span className="muted small" style={{ display: 'block' }}>
            {note}
          </span>
        </span>
      </label>
    );
  };
  const blocked = !webhook || waitBad || (kind === 'notify' && !events.length) || (kind === 'pre-sync' && !manual);
  return (
    <Dialog
      title={link ? CD_KIND_NAME[link.kind ?? 'notify'] : '자동 배포 웹훅 연결'}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          {!link && (
            <button className="btn" disabled={!webhook} onClick={() => setTest(hooks.find((w) => w.name === webhook))}>
              시험 보내기
            </button>
          )}
          <button className="btn primary" disabled={busy || blocked} title={kind === 'pre-sync' && !manual ? "동기화 모드를 '수동'으로 바꾼 뒤 연결하세요" : undefined} onClick={() => void save()}>
            {link ? '저장' : '연결'}
          </button>
        </>
      }
    >
      {!link && (
        <div className="col" style={{ gap: 8 }}>
          {radio('pre-sync', '배포 전 확인', '실행 전에 통과·보류·거부를 묻습니다 (판단 웹훅만)')}
          {radio('post-sync', '배포 후 확인', '실행 뒤 정상·실패를 묻습니다 (판단 웹훅만)')}
          {radio('notify', '알림', '소식만 보냅니다')}
        </div>
      )}
      <Field label="웹훅" error={!usable.length ? `${kind === 'notify' ? '알림' : '판단'} 웹훅이 없습니다. 장애 대응 › 웹훅에서 먼저 등록하세요.` : undefined}>
        <select value={webhook} onChange={(e) => setHook(e.target.value)} disabled={!usable.length}>
          {usable.map((w) => (
            <option key={w.name} value={w.name}>
              {hookLabel(w)}
            </option>
          ))}
        </select>
      </Field>
      {kind === 'pre-sync' && (
        <div className="g2">
          <Field label="응답 기다림" hint="5~30초 (클러스터 내부 호출 한도)" error={waitBad ? '5 ~ 30초' : undefined}>
            <span className="row" style={{ gap: 6 }}>
              <input inputMode="numeric" value={wait} onChange={(e) => setWait(e.target.value.replace(/\D/g, ''))} style={{ width: 90 }} />초
            </span>
          </Field>
          <Field label="시간 초과·잘못된 답">
            <select value={onTimeout} onChange={(e) => setOnTimeout(e.target.value)}>
              <option value="hold">보류 (사람 승인 대기)</option>
              <option value="pass">통과</option>
              <option value="reject">거부 (후보 반려)</option>
            </select>
          </Field>
        </div>
      )}
      {kind === 'post-sync' && (
        <>
          <div className="g2">
            <Field label="언제">
              <select value={when} onChange={(e) => setWhen(e.target.value as 'synced' | 'healthy')}>
                <option value="healthy">동기화 성공 + 상태 검사 통과 후</option>
                <option value="synced">동기화 성공 직후</option>
              </select>
            </Field>
            <Field label="기다림" hint="5~600초" error={waitBad ? '5 ~ 600초' : undefined}>
              <span className="row" style={{ gap: 6 }}>
                <input inputMode="numeric" value={wait} onChange={(e) => setWait(e.target.value.replace(/\D/g, ''))} style={{ width: 90 }} />초
              </span>
            </Field>
          </div>
          <div className="g2">
            <Field label="시간 초과">
              <select value={onTimeout} onChange={(e) => setOnTimeout(e.target.value)}>
                <option value="pass">기록만</option>
                <option value="fail">실패로 보기</option>
              </select>
            </Field>
            <Field label="실패하면">
              <select value={onFail} onChange={(e) => setOnFail(e.target.value as 'pause' | 'pause-rollback')}>
                <option value="pause-rollback">자동 배포 일시정지 + 되돌리기 승인 요청</option>
                <option value="pause">자동 배포 일시정지만</option>
              </select>
            </Field>
          </div>
          <label className="check">
            <input type="checkbox" checked={openIncident} onChange={(e) => setOpenIncident(e.target.checked)} />
            실패 답을 받으면 장애 사건 열기
          </label>
          <span className="small muted">시간 초과는 ‘기록만’ 또는 ‘실패로 보기’를 고릅니다. 되돌리기는 늘 승인 요청으로 엽니다.</span>
        </>
      )}
      {kind === 'notify' && (
        <Field label="보낼 사건" error={!events.length ? '하나 이상 고르세요' : undefined}>
          <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
            {EVENT_UI.map(([ks, n]) => {
              const on = ks.some((k) => events.includes(k));
              return (
                <button key={n} type="button" className={`chip ${on ? 'on' : ''}`} aria-pressed={on} onClick={() => setEvents(on ? events.filter((x) => !ks.includes(x)) : CD_EVENTS.map(([x]) => x).filter((x) => ks.includes(x) || events.includes(x)))}>
                  {on ? '✓ ' : ''}
                  {n}
                </button>
              );
            })}
          </span>
        </Field>
      )}
      {kind === 'pre-sync' &&
        (manual ? (
          <div className="note info small">
            배포 전 확인은 동기화 모드가 ‘수동’(승인 후 배포)일 때만 연결됩니다. 연결하면 자동 작업 계정 <b>sfc-autofix</b>에 이 앱 후보의 승인·반려만 하는 권한(ApproveCD {a.tenant}/{a.app})을 내 세션으로 줍니다.
          </div>
        ) : (
          <div className="note wa small">동기화 모드가 ‘자동’이라 배포 전 확인을 걸 수 없습니다. 정책에서 ‘수동’으로 바꾼 뒤 연결하세요.</div>
        ))}
      {error !== undefined && <ErrorBand error={error} what={error instanceof ApiError && error.code === 'cd-mode' ? '동기화 모드가 맞지 않습니다' : '저장하지 못했습니다'} />}
      {test && <TestDialog w={test} onClose={() => setTest(undefined)} />}
    </Dialog>
  );
}

function UnlinkDialog({ l, onClose, onDone }: { l: WebhookLink; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
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
  };
  return (
    <Dialog
      title={`${l.webhook} 연결을 끊을까요?`}
      width={420}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger" disabled={busy} onClick={() => void go()}>
            연결 끊기
          </button>
        </>
      }
    >
      <span className="small">
        {l.kind ? CD_KIND_NAME[l.kind] : '연결'}에서 {l.webhook}
        {eulReul(l.webhook)} 뺍니다. 웹훅 자체는 장애 대응 › 웹훅에 남습니다.
        {l.kind === 'pre-sync' && ' 자동 작업 계정의 이 앱 승인 권한(ApproveCD)도 거둡니다. 계정은 그대로이고, 동기화 모드는 ‘수동’ 그대로입니다.'}
      </span>
      {error !== undefined && <ErrorBand error={error} what="끊지 못했습니다" />}
    </Dialog>
  );
}
