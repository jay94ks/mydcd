// SPDX-License-Identifier: Apache-2.0

// 장애 대응 (W2.3) · 사건 (UI-B3 · B4, 캔버스 Incidents · IncidentsIx) · 정책 (UI-B5, 캔버스 IncidentPolicy · IncidentPolicyIx).
// 진단·영향 평가·정책·사건 기록은 웹 데몬 몫이고, 승인하면 승인한 사람 세션으로 서명한 mydcd op가 나간다.
// 계약 초안: /mnt/project-files/w2/incident-web-needs.md. 데몬 W2.3 초안이 오면 맞춘다.
import { useEffect, useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import { ApiError, noEndpoint } from '../api/client';
import { accountScope, deleteAutomation } from '../api/endpoints';
import {
  IMPACT_NAME,
  decideChain,
  decideNowText,
  IMPACT_TONE,
  LEVEL_NAME,
  approveIncidentPath,
  deleteIncident,
  incident,
  incidents,
  policy,
  putPolicy,
  rejectIncident,
  resumeAll,
  stopAll,
  type Incident,
  type IncidentRow,
  type Level,
  type Policy,
  type TimelineItem,
  type Watcher,
  type MitigationAction,
  type RejectReason,
  REJECT_NAME,
} from '../api/incidents';
import { useSession } from '../auth/session';
import { useCoordinator } from '../components/Coordinator';
import { Dialog, ConfirmDialog } from '../components/Dialog';
import { Drawer } from '../components/Drawer';
import { MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { Popover } from '../components/Popover';
import { Tabs } from '../components/Tabs';
import { useToast } from '../components/Toast';
import { Badge, Field, HelpBox, OpId, PageHeader, Segmented, type Tone } from '../components/ui';
import { ErrorBand, Load, errorText } from '../components/states';
import { usePoll } from '../lib/usePoll';
import { AutomationWizard, useAutomation } from './Automation';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { ActionSheet, Sheet } from '../mobile/Sheet';
import { ApproveBar, ConfirmApproveSheet, needsConfirm } from '../mobile/Approve';

const PAGE = 5;

/** 표의 시각: 오늘이면 13:02, 어제면 '어제', 그 전이면 11월 18일 */
export const shortWhen = (iso: string) => {
  const d = new Date(iso);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', hour12: false });
  const y = new Date(now);
  y.setDate(now.getDate() - 1);
  if (d.toDateString() === y.toDateString()) return '어제';
  return `${d.getMonth() + 1}월 ${d.getDate()}일`;
};
const hm = (iso: string) => new Date(iso).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', hour12: false });
const minutesLeft = (iso?: string) => (iso ? Math.max(0, Math.ceil((Date.parse(iso) - Date.now()) / 60000)) : 0);

export const scopeText = (r: Pick<IncidentRow, 'scope' | 'app'>) => (r.scope === 'cluster' ? '클러스터' : `앱 · ${r.app}`);
export function decisionText(d: IncidentRow['decision']) {
  switch (d.kind) {
    case 'auto':
      return `자동 실행${d.note ? ` · ${d.note}` : ''}`;
    case 'pending':
      return `승인 대기 · ${minutesLeft(d.expiresAt)}분 남음`;
    case 'approved':
      return `승인됨${d.by ? ` · ${d.by}` : ''}${d.note ? ` · ${d.note}` : ''}`;
    case 'rejected':
      return `반려${d.note ? ` · ${d.note}` : ''}`;
    case 'expired':
      return '만료 · 응답 없음';
    case 'stopped':
      return '모두 멈춤 중 · 실행 안 함';
    default:
      return '조치 없음';
  }
}
const STATE: Record<Incident['state'], [Tone, string]> = { open: ['wa', '열림'], mitigating: ['pr', '임시 조치 중'], recovered: ['ok', '회복됨'], closed: ['un', '닫힘'] };
export const LEVEL_TONE: Record<Level, Tone> = { off: 'un', suggest: 'wa', 'auto-low': 'ok' };

const WATCHER: Record<Exclude<Watcher['state'], 'running'>, string> = {
  stopped: '장애 감지가 멈춰 있습니다. 새 사건을 만들지 않습니다.',
  'no-automation': '자동 대응 계정이 없어 장애 감지가 멈춰 있습니다. 정책 탭에서 계정을 만드세요.',
  'login-failed': '자동 대응 계정으로 로그인하지 못해 장애 감지가 멈췄습니다. 정책 탭에서 계정을 확인하세요.',
  'cursor-expired': '이벤트를 너무 오래 못 읽어 일부 신호를 놓쳤을 수 있습니다. 감지는 지금부터 다시 이어 갑니다.',
};

// ── 머리 · 탭 ──
export function IncidentTabs() {
  const loc = useLocation();
  const fixed = /^\/incidents\/(policy|guide|hooks)/.test(loc.pathname);
  return (
    <Tabs
      label="장애 대응"
      items={[
        { to: '/incidents', label: '사건', active: !fixed },
        { to: '/incidents/policy', label: '정책' },
        { to: '/incidents/guide', label: '행동 지침' },
        { to: '/incidents/hooks', label: '웹훅' },
      ]}
    />
  );
}

// ── 사건 (UI-B3 · B4) ──
const DECISIONS: [string, string][] = [
  ['', '결정: 전체'],
  ['pending', '승인 대기'],
  ['auto', '자동 실행'],
  ['rejected', '반려'],
  ['approved', '승인됨'],
  ['expired', '만료'],
];

export function IncidentsPage() {
  const { id } = useParams();
  const phone = usePhone();
  if (phone) return id ? <MIncident key={id} id={id} /> : <MIncidentList />;
  return <DesktopIncidents id={id} />;
}

// ── 휴대폰 (캔버스 UI-M5 ①②④) ──
const M_DECISIONS: [string, string][] = [
  ['', '전체'],
  ['pending', '승인 대기'],
  ['auto', '자동 실행'],
  ['rejected', '반려'],
];

function MIncidentList() {
  const navigate = useNavigate();
  const [decision, setDecision] = useState('');
  const [scope, setScope] = useState<'' | 'app' | 'cluster'>('');
  const [scopeSheet, setScopeSheet] = useState(false);
  const [limit, setLimit] = useState(20);
  const list = usePoll((s) => incidents({ ...(scope ? { scope } : {}), ...(decision ? { decision } : {}), limit }, s), [scope, decision, limit], 30_000);
  const level = list.data?.level;
  useMobileTop({ title: '장애 대응', sub: list.data?.stopped ? '클러스터: 모두 멈춤' : level ? `클러스터: ${LEVEL_NAME[level]}` : undefined, root: true }, [level, list.data?.stopped]);
  const watcher = list.data?.watcher;
  return (
    <>
      <IncidentTabs />
      <div className="mchips">
        {M_DECISIONS.map(([v, l]) => (
          <button key={v} type="button" className={`mchip${decision === v ? ' on' : ''}`} onClick={() => setDecision(v)}>
            {l}
            {v === 'pending' && list.data ? ` ${list.data.pending}` : ''}
          </button>
        ))}
        <button type="button" className={`mchip${scope ? ' on' : ''}`} onClick={() => setScopeSheet(true)}>
          {scope === 'app' ? '앱' : scope === 'cluster' ? '클러스터' : '앱 · 클러스터'} ▾
        </button>
      </div>
      {watcher && watcher.state !== 'running' && <div className="bn warn">{WATCHER[watcher.state]}</div>}
      <Load q={list} rows={5} what="사건을 불러오지 못했습니다">
        {(d) => {
          const rows = [...d.items].sort((a, b) => Number(b.decision.kind === 'pending') - Number(a.decision.kind === 'pending'));
          return rows.length === 0 ? (
            <span className="muted small">{decision || scope ? '맞는 사건이 없습니다.' : '아직 감지한 사건이 없습니다.'}</span>
          ) : (
            <>
              {rows.map((r) =>
                r.decision.kind === 'pending' ? (
                  <div key={r.id} className="mc ap">
                    <div className="hd">
                      <b>
                        {r.id} · {r.signal}
                      </b>
                      <Badge tone="pr">{minutesLeft(r.decision.expiresAt)}분 남음</Badge>
                    </div>
                    <div className="ln">
                      {scopeText(r)} · {r.mitigation} · 영향 {IMPACT_NAME[r.impact]}
                    </div>
                    <div className="ft">
                      <button type="button" className="mbtn sm pri" onClick={() => navigate(`/incidents/${encodeURIComponent(r.id)}`)}>
                        승인 카드 열기
                      </button>
                    </div>
                  </div>
                ) : (
                  <Link key={r.id} to={`/incidents/${encodeURIComponent(r.id)}`} className="mc">
                    <div className="hd">
                      <b>
                        {r.id} · {r.scope === 'cluster' ? '클러스터' : r.app}
                      </b>
                      <Badge tone={r.decision.kind === 'rejected' ? 'er' : STATE[r.state][0]}>{r.decision.kind === 'rejected' ? '반려' : STATE[r.state][1]}</Badge>
                    </div>
                    <div className="ln">
                      {r.signal} → {r.mitigation} · {IMPACT_NAME[r.impact]} · {decisionText(r.decision)} · {shortWhen(r.at)}
                    </div>
                  </Link>
                ),
              )}
              {d.cursor && (
                <button type="button" className="mbtn" onClick={() => setLimit((n) => n + 20)}>
                  더 보기
                </button>
              )}
            </>
          );
        }}
      </Load>
      <span className="muted small" style={{ textAlign: 'center' }}>
        ‘사건 기록 지우기…’는 넓은 화면에서
      </span>
      {scopeSheet && (
        <ActionSheet
          title="범위"
          onClose={() => setScopeSheet(false)}
          items={[
            { label: '앱 · 클러스터', onSelect: () => setScope('') },
            { label: '앱', onSelect: () => setScope('app') },
            { label: '클러스터', onSelect: () => setScope('cluster') },
          ]}
        />
      )}
    </>
  );
}

function MIncident({ id }: { id: string }) {
  const q = usePoll((s) => incident(id, s), [id], 30_000);
  const x = q.data;
  const ap = x?.approval;
  const pending = !!ap && x?.decision.kind === 'pending';
  const left = minutesLeft(ap?.expiresAt);
  useMobileTop(
    {
      title: pending ? `${id} · 승인 요청` : id,
      sub: x ? (pending ? <span style={left < 5 ? { color: '#F2A35E' } : undefined}>영향 {IMPACT_NAME[x.impact]} · {left}분 뒤 만료</span> : `${x.scope === 'cluster' ? '클러스터' : x.app} · ${x.title}`) : undefined,
      menu: pending ? undefined : [{ label: '사건 기록 지우기…', wide: true, danger: true }],
    },
    [id, pending, left, x?.impact, x?.state, x?.title],
  );
  return (
    <Load q={q} rows={6} what="사건을 불러오지 못했습니다">
      {(v) => <MIncidentBody x={v} onDone={q.refresh} />}
    </Load>
  );
}

function MIncidentBody({ x, onDone }: { x: Incident; onDone: () => void }) {
  const session = useSession();
  const toast = useToast();
  const navigate = useNavigate();
  const m = useMutation();
  const [confirm, setConfirm] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const [facts, setFacts] = useState(false);
  const [drawer, setDrawer] = useState<TimelineItem>();
  const ap = x.approval;
  const pending = !!ap && x.decision.kind === 'pending';
  const allowed = x.scope === 'cluster' ? session.user.systemAdmin : session.user.systemAdmin || session.tenants.some((t) => t.id === x.tenant && t.role === 'manager');
  const need = x.scope === 'cluster' ? '시스템 관리자 권한이 필요합니다' : '이 작업 공간의 관리자 권한이 필요합니다';
  const expiredNow = pending && Date.parse(ap!.expiresAt) <= Date.now();
  const expired = expiredNow || x.decision.kind === 'expired' || (m.error instanceof ApiError && (m.error.status === 410 || m.error.code === 'expired'));
  const changed = m.error instanceof ApiError && m.error.code === 'incident-changed';
  const isMcp = !!ap && (ap.action ?? x.mitigation).startsWith('mcp.');
  useEffect(() => {
    if (!m.mcp) return;
    setConfirm(false);
    toast(m.mcp.ok ? `${x.id} 승인 · mcp.${m.mcp.server}.${m.mcp.tool} 호출 성공` : `! ${x.id} 승인했지만 mcp.${m.mcp.server}.${m.mcp.tool} 호출이 실패했습니다${m.mcp.error ? ` · ${m.mcp.error}` : ''}`, m.mcp.ok ? 'info' : 'er');
    onDone();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m.mcp]);
  const approve = async () => {
    if (!ap) return;
    const v = await sendOp(m, approveIncidentPath(x.id), { basisHash: ap.basisHash });
    setConfirm(false);
    if (v) {
      toast(
        <>
          <span>
            ✓ 승인함 · 작업 <span className="mono">{v.id.slice(0, 8)}</span> {v.state === 'applied' ? '완료' : v.state === 'failed' || v.state === 'rejected' ? '실패' : '진행 중'}
          </span>
          <Link to="/system/ops" style={{ marginLeft: 'auto' }}>
            작업 기록
          </Link>
        </>,
      );
      onDone();
    }
  };
  const a = x.assessment;
  const { openNew } = useCoordinator();
  // 이 사건을 맥락 칩으로 코디네이터 탭을 연다 (UI-M8 ①)
  const openCoord = async () => {
    try {
      await openNew({ incident: x.id });
      navigate('/coordinator', { state: { from: `/incidents/${x.id}` } });
    } catch (e) {
      toast(`코디네이터를 열지 못했습니다: ${errorText(e).message}`, 'er');
    }
  };
  return (
    <>
      {pending && ap ? (
        <div className="mc ap">
          <div className="hd">
            <b>{ap.title}</b>
            <Badge tone={IMPACT_TONE[x.impact]}>영향 {IMPACT_NAME[x.impact]}</Badge>
          </div>
          <dl className="mkv">
            {ap.fields.map((f) => (
              <Frag key={f.label} k={f.label} v={f.value} />
            ))}
            <Frag k="서명" v={`내 세션 키 (${session.user.username})`} />
          </dl>
        </div>
      ) : null}
      {expired && <div className="bn warn">만료됨 · 기록만 남음. 아무것도 실행하지 않았습니다.</div>}
      {changed && (
        <div className="bn warn">
          그사이 사건의 임시 조치나 대상이 바뀌어 승인하지 않았습니다.{' '}
          <button type="button" className="m-link" onClick={() => (m.reset(), onDone())}>
            새로 읽기
          </button>
        </div>
      )}
      {!changed && !confirm && <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
      {pending && a && (
        <>
          <div className="m-sec">
            <span>영향 평가 (별도 컨텍스트)</span>
          </div>
          <div className="mc">
            <div className="ln">
              {a.provider}
              {a.sameProvider === undefined ? '' : a.sameProvider ? ' · 진단과 같은 공급자' : ' · 진단과 다른 공급자'} · 확신 {a.confidence.toFixed(2)}
            </div>
            {!!a.reasons?.length && <div className="ln">평가 근거: {a.reasons.join(' · ')}</div>}
            <button type="button" className="m-link" style={{ fontSize: 13 }} onClick={() => setFacts(true)}>
              입력 사실 · 규칙 하한 보기 ›
            </button>
          </div>
        </>
      )}
      {pending && !expired && <div className="bn info">승인하면 내 세션 키로 서명해 실행합니다. 응답이 없으면 만료되고 기록만 남습니다.</div>}
      {pending ? (
        <div className="m-sec">
          <span>타임라인</span>
          <button type="button" onClick={() => navigate('/system/ops')}>
            작업 기록 ›
          </button>
        </div>
      ) : null}
      <div className="mc">
        {!pending && (
          <>
            <div className="hd">
              <b>{STATE[x.state][1]}</b>
              <Badge tone={x.decision.kind === 'rejected' ? 'er' : IMPACT_TONE[x.impact]}>
                {IMPACT_NAME[x.impact]} · {DECISION_SHORT[x.decision.kind] ?? decisionText(x.decision)}
              </Badge>
            </div>
            <div className="ln">{incidentLine(x)}</div>
          </>
        )}
        <div className="tl">
          {x.timeline.map((t, i) => {
            const [color, name] = TL[t.kind];
            const open = t.kind === 'diagnose' || (t.kind === 'assess' && (pending || !a));
            return (
              <div key={i}>
                <span className="muted">{t.at ? hm(t.at) : ''}</span>
                <i style={{ background: color }} />
                {open ? (
                  <button type="button" className="textbtn plain" style={{ textAlign: 'left' }} onClick={() => setDrawer(t)}>
                    <b>{name}</b> · {t.text}
                  </button>
                ) : (
                  <span>
                    <b>{name}</b> · {t.text}
                    {t.op && (
                      <>
                        {' '}
                        · 작업 <OpId id={t.op} />
                      </>
                    )}
                    {t.kind === 'assess' && a && !pending && (
                      <>
                        {' '}
                        <button type="button" className="m-link" onClick={() => setFacts(true)}>
                          자세히 ›
                        </button>
                      </>
                    )}
                  </span>
                )}
              </div>
            );
          })}
        </div>
        {!pending && (
          <div className="ft">
            <button type="button" className="mbtn sm" onClick={() => void openCoord()}>
              ✦ 코디네이터로 열기
            </button>
            <button type="button" className="mbtn sm" onClick={() => navigate('/incidents/guide')}>
              쓴 지침
            </button>
            <button type="button" className="mbtn sm" onClick={() => navigate('/system/ops')}>
              작업 기록
            </button>
          </div>
        )}
      </div>
      {pending && !expired && !m.op && (
        <ApproveBar
          note={allowed ? undefined : need}
          disabled={!allowed || changed}
          busy={m.busy}
          onReject={allowed ? () => setRejecting(true) : undefined}
          onApprove={() => (needsConfirm(x.impact) ? setConfirm(true) : void approve())}
        />
      )}
      {confirm && ap && (
        <ConfirmApproveSheet
          what={isMcp ? `MCP 도구 ${ap.action ?? x.mitigation} 부르기` : ap.title}
          impact={x.impact}
          busy={m.busy}
          onClose={() => setConfirm(false)}
          onConfirm={() => void approve()}
        />
      )}
      {rejecting && <MRejectSheet x={x} onClose={() => setRejecting(false)} onDone={(r) => (toast(`${x.id}를 반려했습니다 · ${r}`), onDone())} />}
      {facts && a && <MAssessment x={x} onClose={() => setFacts(false)} />}
      {drawer && (
        <Drawer title={drawer.kind === 'diagnose' ? '진단 · 컨텍스트 A' : '영향 평가 · 컨텍스트 B'} onClose={() => setDrawer(undefined)}>
          <dl className="mkv">
            <dt>모델</dt>
            <dd>{drawer.model ?? '—'}</dd>
            <dt>입력</dt>
            <dd>{drawer.inputs?.length ? drawer.inputs.join(' · ') : '—'}</dd>
            {(drawer.candidates ?? []).map((c, i) => (
              <Frag key={i} k={`후보 ${'①②③④⑤'[i] ?? i + 1}`} v={`${c.action} — ${c.note}`} />
            ))}
            {!drawer.candidates && <Frag k="결과" v={drawer.text} />}
          </dl>
        </Drawer>
      )}
    </>
  );
}

const DECISION_SHORT: Partial<Record<Incident['decision']['kind'], string>> = { auto: '자동 실행', approved: '승인 실행', rejected: '반려', expired: '만료', stopped: '모두 멈춤', none: '조치 없음' };
/** 사건 카드 둘째 줄: 범위 · 감지 시각 · 회복 확인 시각 */
function incidentLine(x: Incident) {
  const det = x.timeline.find((t) => t.kind === 'detect')?.at ?? x.at;
  const rec = x.timeline.find((t) => t.kind === 'recover')?.at;
  return [scopeText(x), det && `${hm(det)} 감지`, rec && `${hm(rec)} 회복 확인`].filter(Boolean).join(' · ');
}

/** 영향 평가 자세히 (UI-M8 ②): 하위 화면, 보기만 */
function MAssessment({ x, onClose }: { x: Incident; onClose: () => void }) {
  const a = x.assessment!;
  const dataRisk = ({ none: '없음', low: '낮음', high: '높음' } as const)[a.dataRisk as 'none'] ?? a.dataRisk;
  return (
    <aside className="m-sub" aria-label="영향 평가">
      <header className="m-top">
        <button type="button" className="ic" aria-label="뒤로" onClick={onClose}>
          ‹
        </button>
        <span className="tt">
          영향 평가<span className="sub">{x.id} · 별도 컨텍스트</span>
        </span>
      </header>
      <div className="m-body">
        <div className="mc">
          <div className="ln">
            {a.provider}
            {a.fallback ? ' (대체 모델)' : ''}
            {a.sameProvider === undefined ? '' : a.sameProvider ? ' · 진단과 같은 공급자' : ' · 진단과 다른 공급자'}
          </div>
          <div className="ln muted" style={{ fontSize: 12 }}>
            진단의 추론과 로그 원문은 보지 않고, 코드가 모은 사실만 받아 평가합니다. 대체 모델로 평가했으면 ‘(대체 모델)’이 붙습니다.
          </div>
        </div>
        <div className="m-sec">
          <span>입력 사실</span>
        </div>
        <div className="li">
          {a.facts.map((f) => (
            <div key={f.label}>
              <span style={{ width: 120, flex: 'none', color: 'var(--muted)' }}>{f.label}</span>
              <span className="el">{f.value}</span>
            </div>
          ))}
        </div>
        <div className="mc">
          <dl className="mkv">
            <dt>평가 결과</dt>
            <dd>
              <b>{IMPACT_NAME[a.level]}</b> · {a.reversible ? '되돌릴 수 있음' : '되돌릴 수 없음'} · 영향 범위 {a.blast} · 데이터 위험 {dataRisk} · 확신 {a.confidence.toFixed(2)}
            </dd>
            {!!a.reasons?.length && (
              <>
                <dt>평가 근거</dt>
                <dd>{a.reasons.slice(0, 5).join(' · ')}</dd>
              </>
            )}
            <dt>규칙 하한</dt>
            <dd>
              {IMPACT_NAME[a.floor.level]} ({a.floor.reason})
            </dd>
            <dt>최종 등급</dt>
            <dd>
              <b>{IMPACT_NAME[a.final]}</b> = max(평가, 규칙)
            </dd>
            <dt>정책</dt>
            <dd>{a.policy}</dd>
          </dl>
        </div>
      </div>
    </aside>
  );
}

function MRejectSheet({ x, onClose, onDone }: { x: Incident; onClose: () => void; onDone: (reason: string) => void }) {
  const [reason, setReason] = useState<RejectReason>('handled-by-person');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await rejectIncident(x.id, reason, note.trim() || undefined);
      onClose();
      onDone(REJECT_NAME[reason]);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Sheet
      title={`${x.id} 반려`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="mbtn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="mbtn dng" disabled={busy || (reason === 'other' && !note.trim())} onClick={() => void go()}>
            {busy ? '보내는 중…' : '반려'}
          </button>
        </>
      }
    >
      <label className="fld">
        사유
        <select className="in" value={reason} onChange={(e) => setReason(e.target.value as RejectReason)}>
          {(Object.keys(REJECT_NAME) as RejectReason[]).map((r) => (
            <option key={r} value={r}>
              {REJECT_NAME[r]}
            </option>
          ))}
        </select>
      </label>
      <label className="fld">
        {reason === 'other' ? '메모 (기타면 꼭 적어 주세요)' : '메모'}
        <input className="in" value={note} maxLength={256} onChange={(e) => setNote(e.target.value)} />
      </label>
      {error !== undefined && <ErrorBand error={error} what="반려하지 못했습니다" />}
    </Sheet>
  );
}

function DesktopIncidents({ id }: { id?: string }) {
  const navigate = useNavigate();
  const [scope, setScope] = useState<'' | 'app' | 'cluster'>('');
  const [decision, setDecision] = useState('');
  const [find, setFind] = useState('');
  const [from, setFrom] = useState(0);
  useEffect(() => setFrom(0), [scope, decision, find]);
  const list = usePoll((s) => incidents({ ...(scope ? { scope } : {}), ...(decision ? { decision } : {}), ...(find.trim() ? { q: find.trim() } : {}), ...(from ? { cursor: String(from) } : {}), limit: PAGE }, s), [scope, decision, find, from], 30_000);
  const items = list.data?.items ?? [];
  const selId = id ?? items[0]?.id;
  const sel = usePoll((s) => (selId ? incident(selId, s) : Promise.resolve(undefined)), [selId]);
  // 고른 사건이 승인 대기가 아니면 첫 승인 대기 사건의 승인 카드를 옆에 둔다
  const pend = usePoll((s) => incidents({ decision: 'pending', limit: 1 }, s), [list.data?.pending]);
  const pendId = sel.data?.approval ? undefined : pend.data?.items[0]?.id;
  const pendQ = usePoll((s) => (pendId ? incident(pendId, s) : Promise.resolve(undefined)), [pendId]);
  const refresh = () => (list.refresh(), sel.refresh(), pend.refresh(), pendQ.refresh());
  const level = list.data?.level;
  const watcher = list.data?.watcher;
  const appr = sel.data?.approval ? sel.data : pendQ.data?.approval ? pendQ.data : undefined;
  return (
    <>
      <PageHeader title="장애 대응" ids="UI-B3 · UI-B4" after={level && (list.data?.stopped ? <Badge tone="er">클러스터: 모두 멈춤</Badge> : <Badge tone={level === 'off' ? 'un' : 'ok'}>클러스터: {LEVEL_NAME[level]}</Badge>)} />
      <IncidentTabs />
      <HelpBox terms="사건 (incident) · 임시 조치 (mitigation) · 진단 (컨텍스트 A) · 영향 평가 (컨텍스트 B, impact assessment) · 규칙 하한 (rule floor)">
        <b>이 화면은</b> 앱과 클러스터에서 감지한 장애와, 그에 대한 임시 조치를 모아 봅니다. 영향이 낮고 정책이 허용한 조치만 자동으로 실행하고, 보통이면 승인을 요청하며, 높으면 반려합니다. 영향 평가는 진단과 분리된 별도 컨텍스트에서 합니다. 기록은 지우기 전까지 남습니다.
      </HelpBox>
      {watcher && watcher.state !== 'running' && <div className="note wa small">{WATCHER[watcher.state]}{watcher.error ? ` (${watcher.error})` : ''}</div>}
      <section className="card">
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <Segmented label="범위" value={scope} options={[['', '전체'], ['app', '앱'], ['cluster', '클러스터']]} onChange={setScope} />
          <select value={decision} onChange={(e) => setDecision(e.target.value)} aria-label="결정">
            {DECISIONS.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
          <input placeholder="사건·앱·서버 찾기" value={find} onChange={(e) => setFind(e.target.value)} aria-label="사건 찾기" style={{ flex: '1 1 200px' }} />
          {list.data && (
            <button className="textbtn plain" style={{ color: 'var(--muted)', fontSize: 12 }} onClick={() => setDecision('pending')}>
              승인 대기 {list.data.pending}
            </button>
          )}
        </div>
        <Load q={list} rows={6} what="사건을 불러오지 못했습니다">
          {(d) => (
            <>
              <div style={{ overflowX: 'auto' }}>
                <div className="gtbl" style={{ minWidth: 980 }}>
                  <div className="gr th inc">
                    <span>사건</span>
                    <span>범위</span>
                    <span>신호</span>
                    <span>임시 조치 후보</span>
                    <span>영향</span>
                    <span>결정</span>
                    <span>시각</span>
                  </div>
                  {!d.items.length && <div className="gr muted">{decision || scope || find ? '맞는 사건이 없습니다.' : '아직 감지한 사건이 없습니다.'}</div>}
                  {d.items.map((r) => (
                    <div
                      key={r.id}
                      className={`gr inc click${r.id === selId ? ' on' : ''}`}
                      role="button"
                      tabIndex={0}
                      aria-current={r.id === selId}
                      onClick={() => navigate(`/incidents/${encodeURIComponent(r.id)}`)}
                      onKeyDown={(e) => e.key === 'Enter' && navigate(`/incidents/${encodeURIComponent(r.id)}`)}
                    >
                      <span className="mono">{r.id}</span>
                      <span>{scopeText(r)}</span>
                      <span className="el">{r.signal}</span>
                      <span className="el">{r.mitigation}</span>
                      <Badge tone={IMPACT_TONE[r.impact]}>{IMPACT_NAME[r.impact]}</Badge>
                      <span className="el">{decisionText(r.decision)}</span>
                      <span className="muted">{shortWhen(r.at)}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="row between muted small">
                <span>{d.total ? `${from + 1}–${from + d.items.length} / ${d.total}` : '0 / 0'}</span>
                <span className="row" style={{ gap: 6 }}>
                  <button className="btn sm" disabled={!from} onClick={() => setFrom(Math.max(0, from - PAGE))}>
                    이전
                  </button>
                  <button className="btn sm" disabled={!d.cursor} onClick={() => setFrom(Number(d.cursor))}>
                    다음
                  </button>
                </span>
              </div>
            </>
          )}
        </Load>
      </section>
      {selId && (
        <div className="inc-grid">
          <Load q={sel} rows={6} what="사건을 불러오지 못했습니다">
            {(x) => (x ? <IncidentCard x={x} onDeleted={() => (navigate('/incidents'), refresh())} /> : null)}
          </Load>
          {sel.data?.assessment && <AssessmentCard x={sel.data} />}
          {appr && <ApprovalCard key={appr.id} x={appr} onDone={refresh} />}
        </div>
      )}
    </>
  );
}

const TL: Record<TimelineItem['kind'], [string, string]> = {
  detect: ['#8A919C', '감지'],
  diagnose: ['#1F5FBF', '진단 (컨텍스트 A)'],
  assess: ['#6E40C9', '영향 평가 (컨텍스트 B)'],
  auto: ['#1A7F37', '자동 실행'],
  approve: ['#1A7F37', '승인 · 실행'],
  reject: ['#CF222E', '반려'],
  recover: ['#1A7F37', '회복 확인'],
  propose: ['#BC4C00', '근본 조치 제안'],
  expire: ['#8A919C', '만료'],
  notify: ['#8A919C', '알림'],
  webhook: ['#BC4C00', '웹훅 판단'],
};

function IncidentCard({ x, onDeleted }: { x: Incident; onDeleted: () => void }) {
  const navigate = useNavigate();
  const { openNew } = useCoordinator();
  const toast = useToast();
  const [drawer, setDrawer] = useState<TimelineItem>();
  const [del, setDel] = useState(false);
  const [tone, label] = STATE[x.state];
  return (
    <section className="card">
      <div className="row between">
        <h2>
          {x.id} · {x.title}
        </h2>
        <Badge tone={tone}>{label}</Badge>
      </div>
      {x.decision.kind === 'expired' && <div className="note un">{x.id} 승인 요청이 응답 없이 만료됐습니다. 아무것도 실행하지 않았습니다.</div>}
      <div className="tl">
        {x.timeline.map((t, i) => {
          const [color, name] = TL[t.kind];
          const open = t.kind === 'diagnose' || t.kind === 'assess';
          const body = (
            <>
              <b>{name}</b> · {t.text}
              {t.kind === 'webhook' && (
                <>
                  {' '}
                  · {t.webhook} {t.status ? `${t.status} ` : ''}
                  <Badge tone={t.accepted ? 'ok' : 'wa'}>{t.accepted ? '받아들임' : '버리고 규칙으로'}</Badge>
                  {t.reason ? ` · “${t.reason}”` : ''}
                </>
              )}
              {t.op && (
                <>
                  {' '}
                  · 작업 <OpId id={t.op} />
                </>
              )}
              {t.signer && (
                <>
                  {' '}
                  · 서명 <span className="mono">{t.signer}</span>
                </>
              )}
              {t.conversation && (
                <>
                  {' '}
                  <button
                    className="textbtn"
                    style={{ color: 'var(--accent)' }}
                    onClick={() => {
                      // 사건을 맥락 칩으로 붙여 새 대화를 연다(POST /ai/conversations {incident}). 근본 조치 제안 카드 연결은 W2.3 다음 단계
                      openNew({ incident: x.id }).catch((e) => toast(`코디네이터를 열지 못했습니다: ${errorText(e).message}`));
                    }}
                  >
                    코디네이터로 열기
                  </button>
                </>
              )}
            </>
          );
          return (
            <div key={i}>
              <span className="muted">{hm(t.at)}</span>
              <i style={{ background: color }} />
              {open ? (
                <button className="textbtn plain" style={{ textAlign: 'left' }} onClick={() => setDrawer(t)}>
                  {body}
                </button>
              ) : (
                <span>{body}</span>
              )}
            </div>
          );
        })}
      </div>
      <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
        <button className="btn danger" onClick={() => setDel(true)}>
          사건 기록 지우기…
        </button>
        {(x.guides || x.mcpCalls) && (
          <Popover button="쓴 지침" label={`${x.id}에 쓴 지침`} className="btn" align="right" width={280}>
            {() => (
              <div className="col" style={{ gap: 8, padding: '8px 10px' }}>
                <b style={{ fontSize: 13 }}>{x.id}에 쓴 지침</b>
                <div className="kv2" style={{ gridTemplateColumns: '100px minmax(0,1fr)', fontSize: 12 }}>
                  <span className="muted">클러스터</span>
                  <span>{x.guides?.cluster ? `v${x.guides.cluster.version}` : '없음'}</span>
                  {x.tenant && (
                    <>
                      <span className="muted">작업 공간 {x.tenant}</span>
                      <span>{x.guides?.tenant ? `v${x.guides.tenant.version}` : '없음'}</span>
                    </>
                  )}
                  {x.app && (
                    <>
                      <span className="muted">앱 {x.app}</span>
                      <span>{x.guides?.app ? `v${x.guides.app.version}${x.guides.app.current === 0 ? ' (지금은 지워짐)' : x.guides.app.current && x.guides.app.current !== x.guides.app.version ? ` (지금은 v${x.guides.app.current})` : ''}` : '없음'}</span>
                    </>
                  )}
                  <span className="muted">MCP 호출</span>
                  <span>{x.mcpCalls && Object.keys(x.mcpCalls).length ? Object.entries(x.mcpCalls).map(([k, n]) => `${k} ${n}`).join(' · ') : '없음'}</span>
                </div>
              </div>
            )}
          </Popover>
        )}
        <button className="btn" onClick={() => navigate('/system/ops')}>
          작업 기록 보기
        </button>
      </div>
      {drawer && (
        <Drawer title={drawer.kind === 'diagnose' ? '진단 · 컨텍스트 A' : '영향 평가 · 컨텍스트 B'} onClose={() => setDrawer(undefined)}>
          <dl className="kv">
            <dt>모델</dt>
            <dd>{drawer.model ?? '—'}</dd>
            <dt>입력</dt>
            <dd>{drawer.inputs?.length ? drawer.inputs.join(' · ') : '—'}</dd>
            {(drawer.candidates ?? []).map((c, i) => (
              <Frag key={i} k={`후보 ${'①②③④⑤'[i] ?? i + 1}`} v={`${c.action} — ${c.note}`} />
            ))}
            {!drawer.candidates && (
              <>
                <dt>결과</dt>
                <dd>{drawer.text}</dd>
              </>
            )}
          </dl>
        </Drawer>
      )}
      {del && <DeleteDialog x={x} onClose={() => setDel(false)} onDone={onDeleted} />}
    </section>
  );
}
const Frag = ({ k, v }: { k: string; v: ReactNode }) => (
  <>
    <dt>{k}</dt>
    <dd>{v}</dd>
  </>
);

function DeleteDialog({ x, onClose, onDone }: { x: Incident; onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    try {
      await deleteIncident(x.id, typed);
      onClose();
      onDone();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Dialog
      danger
      width={420}
      title={`${x.id} 기록을 지울까요?`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger solid" disabled={busy || typed !== x.id} onClick={() => void go()}>
            지우기
          </button>
        </>
      }
    >
      <p style={{ margin: 0 }}>사건 타임라인과 진단·평가 기록을 지웁니다. 실행된 작업은 작업 기록에 남습니다.</p>
      <Field label={`확인하려면 ${x.id} 을(를) 입력하세요`}>
        <input value={typed} onChange={(e) => setTyped(e.target.value.trim())} autoComplete="off" />
      </Field>
      {error !== undefined && <ErrorBand error={error} what="지우지 못했습니다" />}
    </Dialog>
  );
}

function AssessmentCard({ x }: { x: Incident }) {
  const a = x.assessment!;
  return (
    <section className="card" style={{ borderColor: '#C9B8EB' }}>
      <div className="row between">
        <h2>영향 평가 (별도 컨텍스트)</h2>
        <span className="muted small">
          {a.provider}
          {a.fallback ? ' (대체 모델)' : ''}
          {a.sameProvider === undefined ? '' : a.sameProvider ? ' · 진단과 같은 공급자' : ' · 진단과 다른 공급자'}
        </span>
      </div>
      <span className="muted small">진단의 추론과 로그 원문은 보지 않고, 코드가 모은 사실만 받아 평가합니다.</span>
      <div className="gtbl">
        <div className="gr th facts">
          <span>입력 사실</span>
          <span>값</span>
        </div>
        {a.facts.map((f) => (
          <div key={f.label} className="gr facts">
            <span>{f.label}</span>
            <span>{f.value}</span>
          </div>
        ))}
      </div>
      <div className="kv2" style={{ gridTemplateColumns: '120px minmax(0,1fr)', fontSize: 12 }}>
        <span className="muted">평가 결과</span>
        <span>
          <Badge tone={IMPACT_TONE[a.level]}>{IMPACT_NAME[a.level]}</Badge> · {a.reversible ? '되돌릴 수 있음' : '되돌릴 수 없음'} · 영향 범위 {a.blast} · 데이터 위험 {({ none: '없음', low: '낮음', high: '높음' } as const)[a.dataRisk] ?? a.dataRisk} · 확신 {a.confidence.toFixed(2)}
        </span>
        {!!a.reasons?.length && (
          <>
            <span className="muted">평가 근거</span>
            <span>{a.reasons.join(' · ')}</span>
          </>
        )}
        <span className="muted">규칙 하한</span>
        <span>
          {IMPACT_NAME[a.floor.level]} ({a.floor.reason})
        </span>
        <span className="muted">최종 등급</span>
        <span>
          <b>{IMPACT_NAME[a.final]}</b> = max(평가, 규칙)
        </span>
        <span className="muted">정책</span>
        <span>{a.policy}</span>
      </div>
    </section>
  );
}


function ApprovalCard({ x, onDone }: { x: Incident; onDone: () => void }) {
  const session = useSession();
  const toast = useToast();
  const m = useMutation();
  const [confirm, setConfirm] = useState(false);
  const ap = x.approval!;
  const allowed = x.scope === 'cluster' ? session.user.systemAdmin : session.user.systemAdmin || session.tenants.some((t) => t.id === x.tenant && t.role === 'manager');
  const need = x.scope === 'cluster' ? '시스템 관리자 권한이 필요합니다' : '이 작업 공간의 관리자 권한이 필요합니다';
  // MCP 조치 후보는 op 대신 {mcp:{ok, server, tool, error?}}가 온다(#177)
  const isMcp = (ap.action ?? x.mitigation).startsWith('mcp.');
  useEffect(() => {
    if (!m.mcp) return;
    setConfirm(false);
    toast(m.mcp.ok ? `${x.id} 승인 · mcp.${m.mcp.server}.${m.mcp.tool} 호출 성공` : `! ${x.id} 승인했지만 mcp.${m.mcp.server}.${m.mcp.tool} 호출이 실패했습니다${m.mcp.error ? ` · ${m.mcp.error}` : ''}`, m.mcp.ok ? 'info' : 'er');
    onDone();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m.mcp]);
  const approve = async () => {
    const v = await sendOp(m, approveIncidentPath(x.id), { basisHash: ap.basisHash });
    if (v) {
      setConfirm(false);
      toast(`${x.id} 승인 · 작업 ${v.id.slice(0, 8)} ${v.state === 'applied' ? '완료' : v.state === 'failed' || v.state === 'rejected' ? '실패 · 작업 기록에서 까닭을 보세요' : '실행 중'}`);
      onDone();
    }
  };
  const expired = m.error instanceof ApiError && (m.error.status === 410 || m.error.code === 'expired');
  const changed = m.error instanceof ApiError && m.error.code === 'incident-changed';
  const undo = ap.fields.find((f) => f.label === '되돌리기')?.value;
  return (
    <section className="card" style={{ borderColor: '#F0C9A0' }}>
      <div className="row between">
        <h2>{x.id} · 승인 요청</h2>
        <Badge tone={IMPACT_TONE[x.impact]}>영향 {IMPACT_NAME[x.impact]}</Badge>
      </div>
      <div className="ap" style={{ borderColor: '#F0C9A0' }}>
        <header style={{ background: '#FFF4E5', borderColor: '#F0C9A0' }}>
          <b>{ap.title}</b>
          <span className="muted small">{minutesLeft(ap.expiresAt)}분 뒤 만료</span>
        </header>
        <div className="bd">
          <div className="kv2" style={{ fontSize: 12 }}>
            {ap.fields.map((f) => (
              <Frag2 key={f.label} k={f.label} v={f.value} />
            ))}
          </div>
          {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
          {expired ? (
            <div className="note un small">승인 기한이 지나 만료됐습니다. 아무것도 실행하지 않았습니다.</div>
          ) : changed ? (
            <div className="note wa small">
              그사이 사건의 임시 조치나 대상이 바뀌어 승인하지 않았습니다.{' '}
              <button className="textbtn" onClick={() => (m.reset(), onDone())}>
                새로 읽기
              </button>
            </div>
          ) : (
            !confirm && <MutationError error={m.error} />
          )}
        </div>
        {!m.op && !expired && (
          <footer>
            <RejectPopover x={x} disabled={!allowed} title={allowed ? undefined : need} onDone={(r) => (toast(`${x.id}를 반려했습니다 · ${r}`), onDone())} />
            <button className="btn sm primary" disabled={!allowed || m.busy} title={allowed ? undefined : need} onClick={() => setConfirm(true)}>
              승인하고 실행
            </button>
          </footer>
        )}
      </div>
      <span className="muted small">승인하면 내 세션 키로 서명해 실행합니다. 응답이 없으면 만료되고 기록만 남습니다.</span>
      {confirm && (
        <Dialog
          danger
          width={420}
          title={`${ap.title.replace(/잠시 제외$/, '제외')}할까요?`}
          onClose={() => setConfirm(false)}
          footer={
            <>
              <button className="btn" onClick={() => setConfirm(false)}>
                취소
              </button>
              <button className="btn danger solid" disabled={m.busy} onClick={() => void approve()}>
                {m.busy ? '보내는 중…' : '승인하고 실행'}
              </button>
            </>
          }
        >
          <p style={{ margin: 0 }}>
            {isMcp ? `MCP 도구 ${ap.action ?? x.mitigation}을(를) 한 번 부릅니다. 결과 본문은 저장하지 않고 성공·실패만 사건에 남깁니다.` : `내 세션 키로 서명해 실행합니다.${undo ? ` 되돌리기: ${undo}.` : ''}`} 승인 기한은 {minutesLeft(ap.expiresAt)}분 남았습니다.
          </p>
          {!changed && <MutationError error={m.error} />}
        </Dialog>
      )}
    </section>
  );
}
const Frag2 = ({ k, v }: { k: string; v: ReactNode }) => (
  <>
    <span className="muted">{k}</span>
    <span>{v}</span>
  </>
);

function RejectPopover({ x, disabled, title, onDone }: { x: Incident; disabled?: boolean; title?: string; onDone: (reason: string) => void }) {
  const [reason, setReason] = useState<RejectReason>('handled-by-person');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  return (
    <Popover button="반려" className="btn sm" label={`${x.id} 반려`} width={300} align="right" disabled={disabled} title={title}>
      {(close) => (
        <div className="col" style={{ gap: 8, padding: 6 }}>
          <b style={{ fontSize: 13 }}>{x.id} 반려</b>
          <Field label="사유">
            <select value={reason} onChange={(e) => setReason(e.target.value as RejectReason)}>
              {(Object.keys(REJECT_NAME) as RejectReason[]).map((r) => (
                <option key={r} value={r}>
                  {REJECT_NAME[r]}
                </option>
              ))}
            </select>
          </Field>
          <Field label={reason === 'other' ? '메모 (기타면 꼭 적어 주세요)' : '메모'}>
            <input value={note} maxLength={256} onChange={(e) => setNote(e.target.value)} />
          </Field>
          {error !== undefined && <span className="small" style={{ color: 'var(--er)' }}>{errorText(error).message}</span>}
          <div className="row" style={{ justifyContent: 'flex-end', gap: 6 }}>
            <button className="btn sm" onClick={close}>
              취소
            </button>
            <button
              className="btn sm primary"
              disabled={busy || (reason === 'other' && !note.trim())}
              onClick={async () => {
                setBusy(true);
                setError(undefined);
                try {
                  await rejectIncident(x.id, reason, note.trim() || undefined);
                  close();
                  onDone(REJECT_NAME[reason]);
                } catch (e) {
                  setError(e);
                } finally {
                  setBusy(false);
                }
              }}
            >
              반려
            </button>
          </div>
        </div>
      )}
    </Popover>
  );
}

// ── 정책 (UI-B5) ──
const LEVEL_CONFIRM: Record<Level, (p: Policy) => [string, string]> = {
  'auto-low': (p) => {
    const on = p.apps.filter((a) => a.level === 'auto-low').map((a) => a.app);
    return ['낮은 영향 자동으로 바꿀까요?', `앱별로 ‘낮은 영향 자동’을 고른 앱 ${on.length}개${on.length ? `(${on.join(', ')})` : ''}에서 영향 평가가 ‘낮음’인 조치가 사람 승인 없이 실행됩니다.`];
  },
  suggest: () => ['제안만으로 바꿀까요?', '자동 실행을 멈추고 모든 임시 조치를 승인 요청으로 보냅니다. 감지와 기록은 계속합니다.'],
  off: () => ['장애 자동 대응을 끌까요?', '모든 앱에서 임시 조치도 승인 요청도 만들지 않습니다. 감지와 사건 기록은 계속합니다.'],
};

export function IncidentPolicyPage() {
  const phone = usePhone();
  const q = usePoll((s) => policy(s), []);
  if (phone) return <MPolicy q={q} />;
  return (
    <>
      <PageHeader title="장애 대응" ids="UI-B5" />
      <IncidentTabs />
      <HelpBox terms="끔 · 제안만 (승인 요청만) · 낮은 영향 자동 · 자동 대응 계정 (automation account) · 차단기 (circuit breaker)">
        <b>이 화면은</b> 클러스터 전체의 장애 자동 대응을 정하고 앱별 설정을 한눈에 봅니다. 앱 설정은 각 앱 페이지의 장애 대응 탭에서 바꿉니다. 클러스터가 끔이면 모든 앱이 멈추고, 앱은 클러스터가 허용한 범위 안에서만 자동 실행을 켤 수 있습니다. 자동 실행은 이 기능을 켤 때 만든 자동 대응 계정으로 서명합니다.
      </HelpBox>
      <Load q={q} rows={8} what="정책을 불러오지 못했습니다">
        {(p) => <PolicyBody p={p} onChange={q.refresh} />}
      </Load>
    </>
  );
}

// ── 휴대폰 정책 탭 (UI-M8 ③): 보기만, '⏻ 지금 모두 멈추기'만 된다 ──
function MPolicy({ q }: { q: ReturnType<typeof usePoll<Policy>> }) {
  const navigate = useNavigate();
  const p = q.data;
  const [stop, setStop] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [acts, setActs] = useState(false);
  useMobileTop({ title: '장애 대응', sub: p ? (p.stopped ? '클러스터: 모두 멈춤' : `클러스터: ${LEVEL_NAME[p.level]}`) : undefined, root: true }, [p?.level, p?.stopped]);
  const stopGo = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await stopAll();
      setStop(false);
      q.refresh();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <IncidentTabs />
      <Load q={q} rows={6} what="정책을 불러오지 못했습니다">
        {(p) => {
          const autoOn = p.apps.filter((a) => a.level === 'auto-low').length;
          return (
            <>
              <div className="mc">
                <div className="hd">
                  <b>클러스터 정책</b>
                  <span className="ro">보기만</span>
                </div>
                <div className="mseg ro-seg" aria-label="클러스터 장애 자동 대응">
                  {(['off', 'suggest', 'auto-low'] as Level[]).map((l) => (
                    <span key={l} className={p.level === l ? 'on' : ''}>
                      {LEVEL_NAME[l]}
                    </span>
                  ))}
                </div>
                <dl className="mkv">
                  <dt>횟수 한도</dt>
                  <dd>시간당 {p.ratePerHour}회</dd>
                  <dt>승인 받는 사람</dt>
                  <dd>
                    {p.approvers.label} · {p.approvers.deadlineMinutes}분
                  </dd>
                  <dt>자동 대응 계정</dt>
                  <dd>{p.automation?.configured ? `${p.automation.username ?? '—'} · 활성` : '없음'}</dd>
                </dl>
                {p.stopped ? (
                  <>
                    <div className="bn err">장애 자동 대응을 모두 멈춘 상태입니다. 새 조치는 승인 요청도 만들지 않습니다.</div>
                    <span className="muted small">‘⏵ 다시 켜기’는 넓은 화면에서</span>
                  </>
                ) : (
                  <button type="button" className="mbtn dng" style={{ width: '100%' }} onClick={() => (setError(undefined), setStop(true))}>
                    ⏻ 지금 모두 멈추기
                  </button>
                )}
              </div>
              <div className="li">
                <button type="button" onClick={() => setActs(true)}>
                  임시 조치<span className="r">{p.actions.length}개 ›</span>
                </button>
              </div>
              <div className="m-sec">
                <span>앱별 현황</span>
              </div>
              <div className="li">
                {!p.apps.length && <div className="muted">아직 앱이 없습니다.</div>}
                {p.apps.map((a) => (
                  <button key={`${a.tenant}/${a.app}`} type="button" onClick={() => navigate(`/deploy/apps/${encodeURIComponent(a.tenant)}/${encodeURIComponent(a.app)}/incident`)}>
                    <span className="el">
                      <b>{a.app}</b> · {a.tenant}
                    </span>
                    <span className="r">
                      {LEVEL_NAME[a.level]}
                      {a.level !== 'off' ? ` · ${a.ratePerHour}/시간` : ''}
                    </span>
                  </button>
                ))}
              </div>
              {p.level !== 'auto-low' && autoOn > 0 && (
                <span className="muted small">
                  클러스터 정책이 ‘{LEVEL_NAME[p.level]}’이라 지금은 ‘낮은 영향 자동’으로 둔 앱도 {p.level === 'off' ? '아무것도 하지 않습니다' : '승인 요청만 만듭니다'}.
                </span>
              )}
              <span className="muted small" style={{ textAlign: 'center' }}>
                정책·횟수 한도·임시 조치 바꾸기는 넓은 화면에서
              </span>
              {acts && (
                <Drawer title={`임시 조치 ${p.actions.length}개`} onClose={() => setActs(false)}>
                  {p.actions.map((a) => (
                    <div key={a.id} className="mc">
                      <div className="hd">
                        <b>{a.label}</b>
                        <Badge tone={IMPACT_TONE[a.floor]}>{IMPACT_NAME[a.floor]}</Badge>
                      </div>
                      <div className="ln">
                        {a.scope === 'app' ? '앱' : '클러스터'} · {a.auto === 'human' ? '사람만' : a.auto === 'allow' ? '자동 실행 허용' : '승인 필요'}
                      </div>
                    </div>
                  ))}
                </Drawer>
              )}
            </>
          );
        }}
      </Load>
      {stop && (
        <Dialog
          danger
          title="장애 자동 대응을 모두 멈출까요?"
          onClose={() => setStop(false)}
          footer={
            <>
              <button className="btn" onClick={() => setStop(false)}>
                취소
              </button>
              <button className="btn danger solid" disabled={busy} onClick={() => void stopGo()}>
                {busy ? '보내는 중…' : '모두 멈추기'}
              </button>
            </>
          }
        >
          <p style={{ margin: 0 }}>진행 중 자동 조치는 끝까지 하고, 새 조치는 승인 요청도 만들지 않습니다. 다시 켜기 전까지 유지됩니다.</p>
          {error !== undefined && <ErrorBand error={error} what="바꾸지 못했습니다" />}
        </Dialog>
      )}
    </>
  );
}

function PolicyBody({ p, onChange }: { p: Policy; onChange: () => void }) {
  const toast = useToast();
  const [lv, setLv] = useState<Level>();
  const [stop, setStop] = useState(false);
  const [detail, setDetail] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const base = { revision: p.revision, level: p.level, ratePerHour: p.ratePerHour, approvers: p.approvers, quiet: p.quiet, newAppDefault: p.newAppDefault };
  const save = async (b: Partial<typeof base> & { actions?: Record<string, MitigationAction['auto']> }, done?: () => void) => {
    setBusy(true);
    setError(undefined);
    try {
      await putPolicy({ ...base, ...b });
      done?.();
      onChange();
    } catch (e) {
      const stale = e instanceof ApiError && (e.code === 'stale' || e.code === 'revision-changed');
      if (stale) toast('그사이 다른 사람이 정책을 바꿔 새로 읽었습니다. 다시 확인해 주세요.');
      if (!done) toast(`정책을 저장하지 못했습니다: ${errorText(e).message}`);
      if (e instanceof ApiError && e.code === 'automation-missing') toast('자동 대응 계정을 먼저 만들어야 끔 밖으로 올릴 수 있습니다.');
      setError(e);
      if (stale) onChange();
    } finally {
      setBusy(false);
    }
  };
  const stopGo = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await (p.stopped ? resumeAll() : stopAll());
      setStop(false);
      onChange();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const autoOn = p.apps.filter((a) => a.level === 'auto-low').length;
  return (
    <>
      <div className="grid wide">
        <section className="card">
          <div className="row between">
            <h2>클러스터 정책</h2>
            <span className="muted small">시스템 관리자</span>
          </div>
          <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
            <Segmented label="클러스터 장애 자동 대응" value={p.level} options={(['off', 'suggest', 'auto-low'] as Level[]).map((l) => [l, LEVEL_NAME[l]])} onChange={(l) => l !== p.level && (setError(undefined), setLv(l))} />
            <button className="btn danger" onClick={() => (setError(undefined), setStop(true))}>
              {p.stopped ? '⏵ 다시 켜기' : '⏻ 지금 모두 멈추기'}
            </button>
          </div>
          {p.stopped && <div className="note er small">장애 자동 대응을 모두 멈춘 상태입니다. 새 조치는 승인 요청도 만들지 않습니다.</div>}
          <div className="kv2" style={{ gridTemplateColumns: '150px minmax(0,1fr)' }}>
            <span className="muted">클러스터 횟수 한도</span>
            <span>
              <button className="textbtn" onClick={() => setDetail(true)}>
                시간당 {p.ratePerHour}회
              </button>{' '}
              (넘으면 승인 요청으로 전환)
            </span>
            <span className="muted">승인 요청 받는 사람</span>
            <span>
              <button className="textbtn" onClick={() => setDetail(true)}>
                {p.approvers.label} · 응답 기한 {p.approvers.deadlineMinutes}분
              </button>
            </span>
            <span className="muted">자동 실행 막는 시간</span>
            <span>{p.quiet.length ? p.quiet.map((x) => `매일 ${x.replace('-', '–')}`).join(', ') : '없음'}</span>
            <span className="muted">판단 방식</span>
            <span>
              {decideChain(p.decide)}
              {p.decideNow && <span className="muted"> · {decideNowText(p.decideNow, p.decideSkip)}</span>} (<Link to="/incidents/hooks">웹훅</Link>)
            </span>
            <span className="muted">진단 · 영향 평가 모델</span>
            <span>
              {p.models?.diagnosis ?? '—'} · {p.models?.impact?.split(' ')[0] ?? '—'} (<Link to="/system/ai">AI 설정</Link>에서 변경)
            </span>
          </div>
        </section>
        <AutomationCard p={p} />
      </div>
      <section className="card">
        <h2>임시 조치 목록</h2>
        <span className="muted small">목록 밖의 작업은 장애 자동 대응이 만들 수 없습니다. 지우기·데이터 저장소·비밀값·사용자·cluster.yaml·합의 변경은 목록에 넣을 수 없습니다.</span>
        <div className="gtbl">
          <div className="gr th acts">
            <span>수준</span>
            <span>임시 조치</span>
            <span>규칙 하한</span>
            <span>자동 실행 허용</span>
          </div>
          {p.actions.map((a) => (
            <div key={a.id} className="gr acts">
              <span>{a.scope === 'app' ? '앱' : '클러스터'}</span>
              <span>{a.label}</span>
              <Badge tone={IMPACT_TONE[a.floor]}>{IMPACT_NAME[a.floor]}</Badge>
              {a.floor === 'low' && a.auto !== 'human' ? (
                <label className="check">
                  <input type="checkbox" checked={a.auto === 'allow'} disabled={busy} onChange={(e) => void save({ actions: { [a.id]: e.target.checked ? 'allow' : 'approval' } })} />
                  허용
                </label>
              ) : (
                <span className="muted small">{a.auto === 'human' ? '사람만 (자동 대응이 제안하지 않음)' : '승인 필요 (자동 불가)'}</span>
              )}
            </div>
          ))}
        </div>
      </section>
      <section className="card">
        <div className="row between">
          <h2>앱별 현황</h2>
          <span className="muted small">바꾸기는 각 앱 페이지의 장애 대응 탭에서 (작업 공간 관리자) · 새 앱 기본값: {LEVEL_NAME[p.newAppDefault]}</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <div className="gtbl" style={{ minWidth: 820 }}>
            <div className="gr th apps">
              <span>작업 공간</span>
              <span>앱</span>
              <span>장애 자동 대응</span>
              <span>횟수 한도</span>
              <span>자동 실행 막는 시간</span>
              <span>자동 배포 후 되돌리기</span>
              <span />
            </div>
            {!p.apps.length && <div className="gr muted">아직 앱이 없습니다.</div>}
            {p.apps.map((a) => {
              const to = `/deploy/apps/${encodeURIComponent(a.tenant)}/${encodeURIComponent(a.app)}/incident`;
              return (
                <div key={`${a.tenant}/${a.app}`} className="gr apps">
                  <span>{a.tenant}</span>
                  <Link to={to}>{a.app}</Link>
                  <Badge tone={LEVEL_TONE[a.level]}>{LEVEL_NAME[a.level]}</Badge>
                  <span>{a.level === 'off' ? '—' : `${a.ratePerHour}/시간`}</span>
                  <span className="muted">{a.quiet.length ? a.quiet.map((x) => `매일 ${x.replace('-', '–')}`).join(', ') : '—'}</span>
                  <span className={a.cdRollback.enabled ? '' : 'muted'}>{a.cdRollback.enabled ? `${a.cdRollback.alwaysApprove ? '승인' : '자동'} · ${a.cdRollback.windowMinutes}분` : a.cdRollback.alwaysApprove ? '끔 · 항상 승인' : '끔'}</span>
                  <Link to={to} className="small">
                    설정 ›
                  </Link>
                </div>
              );
            })}
          </div>
        </div>
        {p.level !== 'auto-low' && autoOn > 0 && <span className="muted small">클러스터 정책이 '{LEVEL_NAME[p.level]}'이라 지금은 '낮은 영향 자동'으로 둔 앱도 {p.level === 'off' ? '아무것도 하지 않습니다' : '승인 요청만 만듭니다'}.</span>}
      </section>
      {lv && (
        <Dialog
          danger={lv === 'auto-low'}
          width={420}
          title={LEVEL_CONFIRM[lv](p)[0]}
          onClose={() => setLv(undefined)}
          footer={
            <>
              <button className="btn" onClick={() => setLv(undefined)}>
                취소
              </button>
              <button className={`btn ${lv === 'auto-low' ? 'danger solid' : 'primary'}`} disabled={busy} onClick={() => void save({ level: lv }, () => setLv(undefined))}>
                바꾸기
              </button>
            </>
          }
        >
          <p style={{ margin: 0 }}>{LEVEL_CONFIRM[lv](p)[1]}</p>
          {error !== undefined && <ErrorBand error={error} what="바꾸지 못했습니다" />}
        </Dialog>
      )}
      {stop && (
        <Dialog
          danger={!p.stopped}
          width={420}
          title={p.stopped ? '장애 자동 대응을 다시 켤까요?' : '장애 자동 대응을 모두 멈출까요?'}
          onClose={() => setStop(false)}
          footer={
            <>
              <button className="btn" onClick={() => setStop(false)}>
                취소
              </button>
              <button className={`btn ${p.stopped ? 'primary' : 'danger solid'}`} disabled={busy} onClick={() => void stopGo()}>
                {p.stopped ? '다시 켜기' : '모두 멈추기'}
              </button>
            </>
          }
        >
          <p style={{ margin: 0 }}>{p.stopped ? `클러스터 정책 ‘${LEVEL_NAME[p.level]}’으로 다시 동작합니다.` : '진행 중 자동 조치는 끝까지 하고, 새 조치는 승인 요청도 만들지 않습니다. 다시 켜기 전까지 유지됩니다.'}</p>
          {error !== undefined && <ErrorBand error={error} what="바꾸지 못했습니다" />}
        </Dialog>
      )}
      {detail && <PolicyDetail p={p} busy={busy} error={error} onClose={() => (setDetail(false), setError(undefined))} onSave={(b) => void save(b, () => setDetail(false))} />}
    </>
  );
}

function PolicyDetail({ p, busy, error, onClose, onSave }: { p: Policy; busy: boolean; error: unknown; onClose: () => void; onSave: (b: { ratePerHour: number; approvers: Policy['approvers'] }) => void }) {
  const [rate, setRate] = useState(String(p.ratePerHour));
  const [deadline, setDeadline] = useState(p.approvers.deadlineMinutes);
  const [banner, setBanner] = useState(p.approvers.banner);
  const opts = p.approverOptions ?? [];
  const [to, setTo] = useState(p.approvers.to ?? opts[0]?.to);
  const n = Number(rate);
  const bad = !Number.isInteger(n) || n < 1 || n > 30;
  return (
    <Dialog
      title="클러스터 정책 상세"
      width={420}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={busy || bad} onClick={() => onSave({ ratePerHour: n, approvers: { ...p.approvers, ...(opts.length && to ? { to } : {}), deadlineMinutes: deadline, banner } })}>
            저장
          </button>
        </>
      }
    >
      <Field label="횟수 한도 (시간당)" error={bad ? '1에서 30 사이 정수' : undefined}>
        <input type="number" min={1} max={30} value={rate} onChange={(e) => setRate(e.target.value)} />
      </Field>
      <Field label="승인 요청 받는 사람" hint={opts.length ? '앱 사건은 앱 설정의 받는 사람을 따릅니다' : '웹 기능 준비 중'}>
        {opts.length ? (
          <select value={to} onChange={(e) => setTo(e.target.value as typeof to)}>
            {opts.map((o) => (
              <option key={o.to} value={o.to}>
                {o.label.replace(/ (\d+)명/, ' ($1명)')}
              </option>
            ))}
          </select>
        ) : (
          <select value={p.approvers.label} disabled>
            <option>{p.approvers.label}</option>
          </select>
        )}
      </Field>
      <Field label="응답 기한">
        <select value={deadline} onChange={(e) => setDeadline(Number(e.target.value))}>
          {[10, 30, 60, 120].map((m) => (
            <option key={m} value={m}>
              {m}분
            </option>
          ))}
        </select>
      </Field>
      <label className="check">
        <input type="checkbox" checked={banner} onChange={(e) => setBanner(e.target.checked)} />
        승인 요청을 대시보드 상단 띠로도 알리기
      </label>
      {error !== undefined && <ErrorBand error={error} what="저장하지 못했습니다" />}
    </Dialog>
  );
}

function AutomationCard({ p }: { p: Policy }) {
  const q = useAutomation();
  const a = q.data;
  const sc = usePoll(async (s) => (a?.userId ? accountScope(a.userId, s) : undefined), [a?.userId]);
  const [wiz, setWiz] = useState(false);
  const [revoke, setRevoke] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const allowed = p.actions.filter((x) => x.auto === 'allow').map((x) => x.id);
  const fp = a?.fingerprint?.replace(/^SHA256:/, '') ?? '';
  return (
    <section className="card">
      <div className="row between">
        <h2>자동 대응 계정</h2>
        {a && (a.configured ? <Badge tone={a.lastCheck && !a.lastCheck.ok ? 'er' : 'ok'}>{a.lastCheck && !a.lastCheck.ok ? '로그인 실패' : '활성'}</Badge> : <Badge tone="un">없음</Badge>)}
      </div>
      {q.error !== undefined ? (
        <span className="muted">{noEndpoint(q.error) ? '서버 기능 대기' : '읽지 못했습니다'}</span>
      ) : !a ? (
        <span className="muted">읽는 중…</span>
      ) : !a.configured ? (
        <span className="muted small">자동 실행은 이 계정의 키로 서명합니다. 계정을 만들기 전에는 ‘낮은 영향 자동’이어도 승인 요청만 만듭니다.</span>
      ) : (
        <div className="kv2" style={{ gridTemplateColumns: '120px minmax(0,1fr)' }}>
          <span className="muted">계정</span>
          <span className="mono">{a.username}</span>
          <span className="muted">키</span>
          <span className="mono">
            ed25519 · …{fp.slice(-4)}
            {a.createdAt ? ` · ${new Date(a.createdAt).getMonth() + 1}월 ${new Date(a.createdAt).getDate()}일` : ''}
            {a.createdBy ? ` ${a.createdBy} 생성` : ''}
          </span>
          <span className="muted">키 보관</span>
          <span>mydc-web 컨테이너 봉인 파일 (밖으로 나가지 않음)</span>
          <span className="muted">허용 동작</span>
          <span>{sc.data ? (sc.data.actions.length ? sc.data.actions.join(', ') : '없음') : allowed.join(', ')}</span>
          <span className="muted">작업 공간</span>
          <span>
            <Link to="/system/users">사용자</Link> 화면의 작업 공간 소속을 따름
          </span>
        </div>
      )}
      {a && (
        <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
          {a.configured ? (
            <>
              <button className="btn" onClick={() => setWiz(true)}>
                키 교체
              </button>
              <button className="btn" onClick={() => setWiz(true)}>
                설정 다시 하기
              </button>
              <button className="btn danger" onClick={() => setRevoke(true)}>
                계정 키 무효화…
              </button>
            </>
          ) : (
            <button className="btn primary" disabled={!a.sealReady} title={a.sealReady ? undefined : '웹 앱 설정에서 봉인 키를 먼저 준비하세요'} onClick={() => setWiz(true)}>
              자동 대응 계정 만들기…
            </button>
          )}
        </div>
      )}
      {wiz && <AutomationWizard cur={a?.configured ? a : undefined} onClose={() => (setWiz(false), q.refresh())} />}
      {revoke && a?.username && (
        <ConfirmDialog
          title={`${a.username} 키를 무효화할까요?`}
          target={a.username}
          actionLabel="무효화"
          busy={busy}
          onClose={() => setRevoke(false)}
          onConfirm={async () => {
            setBusy(true);
            setError(undefined);
            try {
              await deleteAutomation();
              setRevoke(false);
              q.refresh();
            } catch (e) {
              setError(e);
            } finally {
              setBusy(false);
            }
          }}
        >
          자동 대응이 즉시 멈춥니다. 다시 쓰려면 ‘설정 다시 하기’로 새 키를 만들어야 합니다.
          {error !== undefined && <ErrorBand error={error} what="무효화하지 못했습니다" />}
        </ConfirmDialog>
      )}
    </section>
  );
}

// ── 행동 지침 · 웹훅: 데몬 W2.3 초안이 오면 만든다 ──
