// SPDX-License-Identifier: Apache-2.0

// 배포 › 앱 › 장애 대응 탭 (UI-B8, 캔버스 AppIncident · AppIncidentIx). 웹 데몬 몫(정책·사건 기록).
// 계약 초안: /mnt/project-files/w2/incident-web-needs.md "앱 탭".
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ApiError } from '../api/client';
import { IMPACT_NAME, IMPACT_TONE, LEVEL_NAME, appIncident, decideChain, decideNowText, appVersionMarks, incidents, putAppIncident, putVersionMark, type AppIncidentConf, type AppVersionMark, type CdRollback, type Level, type MitigationAction } from '../api/incidents';
import type { AppView } from '../api/types';
import { useSession } from '../auth/session';
import { Dialog } from '../components/Dialog';
import { useToast } from '../components/Toast';
import { Badge, Field, HelpBox, Segmented } from '../components/ui';
import { ErrorBand, Load, errorText } from '../components/states';
import { usePoll } from '../lib/usePoll';
import { LEVEL_TONE, decisionText, shortWhen } from './Incidents';
import { usePhone } from '../lib/viewport';
import { Drawer } from '../components/Drawer';

const NEED = '이 작업 공간의 관리자 권한이 필요합니다';
const QUIET_RE = /^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$/;
const quietText = (q: string) => `매일 ${q.replace('-', '–')}`;

export function AppIncidentTab({ a }: { a: AppView }) {
  const session = useSession();
  const canWrite = session.user.systemAdmin || session.tenants.some((t) => t.id === a.tenant && t.role === 'manager');
  const q = usePoll((s) => appIncident(a.tenant, a.app, s), [a.tenant, a.app]);
  const base = `/deploy/apps/${encodeURIComponent(a.tenant)}/${encodeURIComponent(a.app)}`;
  const phone = usePhone();
  if (phone) return <Load q={q} what="장애 대응 설정을 불러오지 못했습니다">{(c) => <MAppIncident a={a} c={c} />}</Load>;
  return (
    <>
      <HelpBox terms="임시 조치 (mitigation) · 규칙 하한 (rule floor) · 데이터 이전 (migration, 새 버전이 데이터 형식을 바꾸는 배포)">
        <b>이 탭은</b> 이 앱에 장애가 났을 때 자동으로 할 일을 정합니다. 클러스터 정책이 허용한 범위 안에서만 켤 수 있고, 영향이 낮은 조치만 자동으로 실행합니다. 나머지는 승인 요청을 보냅니다. 클러스터 전체 정책과 모든 사건은 <Link to="/incidents/policy">장애 대응</Link> 메뉴에서 봅니다.
      </HelpBox>
      <Load q={q} rows={6} what="장애 대응 설정을 불러오지 못했습니다">
        {(c) => <Body key={c.revision} a={a} c={c} canWrite={canWrite} onSaved={q.refresh} base={base} />}
      </Load>
    </>
  );
}

type Draft = Pick<AppIncidentConf, 'level' | 'ratePerHour' | 'quiet' | 'cdRollback' | 'actions'>;
const draftOf = (c: AppIncidentConf): Draft => ({ level: c.level, ratePerHour: c.ratePerHour, quiet: c.quiet, cdRollback: c.cdRollback, actions: c.actions });

/** 저장 전 바뀐 것: [이름, 전, 후] */
function changes(c: AppIncidentConf, d: Draft): [string, string, string][] {
  const out: [string, string, string][] = [];
  const cd = (x: CdRollback) => `${x.enabled ? 'on' : 'off'}, ${x.windowMinutes}m${x.alwaysApprove ? ', always-approve' : ''}`;
  if (c.level !== d.level) out.push(['level', c.level, d.level]);
  if (c.ratePerHour !== d.ratePerHour) out.push(['rate', `${c.ratePerHour}/h`, `${d.ratePerHour}/h`]);
  if (c.quiet.join(',') !== d.quiet.join(',')) out.push(['quiet', c.quiet.join(', ') || '없음', d.quiet.join(', ') || '없음']);
  if (cd(c.cdRollback) !== cd(d.cdRollback)) out.push(['cd-rollback', cd(c.cdRollback), cd(d.cdRollback)]);
  for (const k of new Set([...Object.keys(c.actions), ...Object.keys(d.actions)])) if (!!c.actions[k] !== !!d.actions[k]) out.push([`auto.${k}`, String(!!c.actions[k]), String(!!d.actions[k])]);
  return out;
}

function Body({ a, c, canWrite, onSaved, base }: { a: AppView; c: AppIncidentConf; canWrite: boolean; onSaved: () => void; base: string }) {
  const toast = useToast();
  const [d, setD] = useState<Draft>(() => draftOf(c));
  const [rate, setRate] = useState(String(c.ratePerHour));
  const [addQuiet, setAddQuiet] = useState<string>();
  const [review, setReview] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  useEffect(() => {
    const n = Number(rate);
    if (Number.isInteger(n) && n >= 1 && n <= 10) setD((o) => ({ ...o, ratePerHour: n }));
  }, [rate]);
  const rateBad = !(Number.isInteger(Number(rate)) && Number(rate) >= 1 && Number(rate) <= 10);
  const diff = changes(c, d);
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await putAppIncident(a.tenant, a.app, { ...d, revision: c.revision });
      setReview(false);
      toast(`✓ ${a.app} 장애 대응 설정을 저장했습니다.`);
      onSaved();
    } catch (e) {
      setError(e);
      if (e instanceof ApiError && (e.code === 'stale' || e.code === 'revision-changed')) {
        setReview(false);
        toast('그사이 다른 사람이 바꿔 새로 읽었습니다. 다시 확인해 주세요.');
        onSaved();
      }
    } finally {
      setBusy(false);
    }
  };
  const cluster = c.clusterLevel;
  const rank: Record<Level, number> = { off: 0, suggest: 1, 'auto-low': 2 };
  const capped = rank[cluster] < rank[d.level];
  const cd = d.cdRollback;
  const setCd = (p: Partial<CdRollback>) => setD((o) => ({ ...o, cdRollback: { ...o.cdRollback, ...p } }));
  const title = canWrite ? undefined : NEED;
  return (
    <>
      <div className="g2 wide">
        <section className="card">
          <div className="row between">
            <h2>이 앱의 장애 자동 대응</h2>
            <span className="muted small">작업 공간 관리자</span>
          </div>
          <span title={title} style={{ width: 'fit-content' }}>
            <fieldset disabled={!canWrite} style={{ border: 0, padding: 0, margin: 0 }}>
              <Segmented label="이 앱의 장애 자동 대응" value={d.level} options={(['off', 'suggest', 'auto-low'] as Level[]).map((l) => [l, LEVEL_NAME[l]])} onChange={(level) => setD((o) => ({ ...o, level }))} />
            </fieldset>
          </span>
          <div className="kv2" style={{ gridTemplateColumns: '150px minmax(0,1fr)', fontSize: 12 }}>
            <span className="muted">클러스터 정책</span>
            <span>
              <Badge tone={LEVEL_TONE[cluster]}>{LEVEL_NAME[cluster]}</Badge> {capped ? (cluster === 'off' ? '지금은 이 앱도 아무것도 하지 않습니다' : '지금은 이 앱도 승인 요청만 만듭니다') : '이 앱 설정대로 동작합니다'}
            </span>
            <span className="muted">횟수 한도</span>
            <span className="row" style={{ gap: 4 }}>
              시간당 <input type="number" min={1} max={10} value={rate} disabled={!canWrite} aria-label="횟수 한도 (시간당)" aria-invalid={rateBad} onChange={(e) => setRate(e.target.value)} style={{ width: 64, height: 28 }} />회 (넘으면 승인 요청)
            </span>
            <span className="muted">자동 실행 막는 시간</span>
            <span className="col" style={{ gap: 6 }}>
              <span>
                {d.quiet.length ? (
                  d.quiet.map((x) => (
                    <span key={x} className="pillc" style={{ marginRight: 6 }}>
                      {quietText(x)}{' '}
                      {canWrite && (
                        <button className="textbtn plain" aria-label={`${x} 빼기`} onClick={() => setD((o) => ({ ...o, quiet: o.quiet.filter((y) => y !== x) }))}>
                          ✕
                        </button>
                      )}
                    </span>
                  ))
                ) : (
                  '없음'
                )}
                {canWrite && addQuiet === undefined && (
                  <>
                    {' · '}
                    <button className="textbtn" style={{ color: 'var(--accent)' }} onClick={() => setAddQuiet('')}>
                      추가
                    </button>
                  </>
                )}
              </span>
              {addQuiet !== undefined && (
                <Field label="막는 시간" hint="백업 시간 등. 이 시간에는 모든 조치를 승인 요청으로 바꿉니다." error={addQuiet && !QUIET_RE.test(addQuiet) ? '02:00-03:00 꼴로 적어 주세요' : undefined}>
                  <span className="row" style={{ gap: 6 }}>
                    <input autoFocus placeholder="02:00-03:00" value={addQuiet} onChange={(e) => setAddQuiet(e.target.value.trim())} style={{ width: 140 }} />
                    <button
                      className="btn sm"
                      disabled={!QUIET_RE.test(addQuiet)}
                      onClick={() => {
                        setD((o) => ({ ...o, quiet: o.quiet.includes(addQuiet) ? o.quiet : [...o.quiet, addQuiet] }));
                        setAddQuiet(undefined);
                      }}
                    >
                      넣기
                    </button>
                    <button className="btn sm" onClick={() => setAddQuiet(undefined)}>
                      취소
                    </button>
                  </span>
                </Field>
              )}
            </span>
            <span className="muted">승인 요청 받는 사람</span>
            <span>{c.approvers ?? '—'}</span>
            <span className="muted">판단 방식</span>
            <span>
              {!c.decide ? '클러스터 기본' : typeof c.decide === 'string' ? c.decide : decideChain(c.decide)}
              {c.decideNow && <span className="muted"> · {decideNowText(c.decideNow, c.decideSkip)}</span>}
            </span>
          </div>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <button className="btn primary" disabled={!canWrite || !diff.length || rateBad} title={title} onClick={() => (setError(undefined), setReview(true))}>
              변경 저장
            </button>
          </div>
        </section>
        <section className="card">
          <div className="row between">
            <h2>자동 배포 후 되돌리기</h2>
            {cd.enabled ? <Badge tone={cd.alwaysApprove ? 'wa' : 'ok'}>{cd.alwaysApprove ? '항상 승인' : '자동 허용'} · {cd.windowMinutes}분</Badge> : <Badge tone="un">끔</Badge>}
          </div>
          <label className="check" title={title}>
            <input type="checkbox" checked={cd.enabled} disabled={!canWrite} onChange={(e) => setCd({ enabled: e.target.checked })} />
            자동 배포가 올린 새 버전이 바로 장애를 내면 직전 버전으로 자동 되돌리기
          </label>
          <div className="row" style={{ gap: 16, alignItems: 'flex-end', flexWrap: 'wrap' }}>
            <Field label="허용 시간 (배포 완료 후)">
              <select value={cd.windowMinutes} disabled={!canWrite || !cd.enabled} onChange={(e) => setCd({ windowMinutes: Number(e.target.value) })} style={{ width: 140 }}>
                {[10, 15, 30, 60].map((m) => (
                  <option key={m} value={m}>
                    {m}분
                  </option>
                ))}
              </select>
            </Field>
            <label className="check" style={{ paddingBottom: 8 }}>
              <input type="checkbox" checked={cd.alwaysApprove} disabled={!canWrite} onChange={(e) => setCd({ alwaysApprove: e.target.checked })} />이 앱은 항상 승인
            </label>
          </div>
          <div className="conds">
            <b>모두 참일 때만 자동</b>
            <span>✓ 자동 배포가 올린 버전 · 허용 시간 안 · 바로 직전 버전으로만</span>
            <span>✓ 차이가 이미지 태그·환경 변수·복제본 수·자원 한도·상태 검사 설정뿐</span>
            <span>✓ '데이터 이전 있음' 표시 없음 · 데이터 저장소·망·비밀값·lifecycle 변경 없음</span>
            <span>✓ 장애 신호가 배포 전에는 없었음 · 24시간 안에 자동 되돌림 없음</span>
            <span className="muted">되돌리면 자동 배포도 함께 멈춥니다. 다시 켜는 것은 사람이 합니다.</span>
          </div>
        </section>
      </div>
      <section className="card">
        <div className="row between">
          <h2>행동 지침 (AI에게 넘김)</h2>
          <Link to={`/incidents/guide?scope=app&app=${encodeURIComponent(a.app)}`} className="small">
            편집 ›
          </Link>
        </div>
        <div className="kv2" style={{ gridTemplateColumns: '150px minmax(0,1fr)', fontSize: 12 }}>
          <span className="muted">이 앱 지침</span>
          {c.guides ? <span>{c.guides.app ? `v${c.guides.app.version} · ${c.guides.app.summary}` : '없음'}</span> : <span className="muted">웹 기능 준비 중</span>}
          <span className="muted">함께 들어가는 지침</span>
          {c.guides ? (
            <span>
              {[c.guides.cluster && `클러스터 v${c.guides.cluster.version}`, c.guides.tenant && `작업 공간 ${a.tenant} v${c.guides.tenant.version}`].filter(Boolean).join(' · ') || '없음'}
            </span>
          ) : (
            <span className="muted">웹 기능 준비 중</span>
          )}
          <span className="muted">넘길 곳</span>
          <span>장애 진단 · 코디네이터 (영향 평가에는 '제안하지 말 것'·'중요도'만)</span>
          <span className="muted">바깥 도구 (MCP)</span>
          <span>
            <Link to="/system/ai/mcp">MCP 연동</Link>에서 정합니다
          </span>
        </div>
      </section>
      <section className="card">
        <h2>이 앱에서 쓸 임시 조치</h2>
        <span className="muted small">클러스터가 허용한 조치만 보입니다. '보통'은 이 앱에서도 자동으로 바꿀 수 없습니다.</span>
        <div className="gtbl">
          <div className="gr th aacts">
            <span>임시 조치</span>
            <span>규칙 하한</span>
            <span>이 앱에서</span>
          </div>
          {c.available.map((x) => (
            <div key={x.id} className="gr aacts">
              <span>{x.label.replace(/ \(조건 모두 충족 시\)$/, '')}</span>
              <Badge tone={IMPACT_TONE[x.floor]}>{IMPACT_NAME[x.floor]}</Badge>
              {x.auto === 'allow' ? (
                <label className="check" title={title}>
                  <input type="checkbox" checked={!!d.actions[x.id]} disabled={!canWrite} onChange={(e) => setD((o) => ({ ...o, actions: { ...o.actions, [x.id]: e.target.checked } }))} />
                  자동 실행 허용
                  {x.id === 'cd-rollback' && <span className="muted small"> · 위 되돌리기 조건을 모두 채울 때만</span>}
                </label>
              ) : (
                <span className="muted small">{x.auto === 'approval' ? '승인 요청만' : '사람만'}</span>
              )}
            </div>
          ))}
        </div>
      </section>
      <Versions a={a} canWrite={canWrite} base={base} />
      <Recent a={a} />
      {review && (
        <Dialog
          title={`${a.app} 장애 대응 변경`}
          width={560}
          onClose={() => setReview(false)}
          footer={
            <>
              <button className="btn" onClick={() => setReview(false)}>
                취소
              </button>
              <button className="btn primary" disabled={busy} onClick={() => void save()}>
                {busy ? '저장 중…' : '저장'}
              </button>
            </>
          }
        >
          <pre className="dnsdiff">
            {diff.map(([k, b, n]) => (
              <span key={k}>
                <span className="r">- {k}: {b}</span>
                <span className="a">+ {k}: {n}</span>
              </span>
            ))}
          </pre>
          {error !== undefined && <ErrorBand error={error} what="저장하지 못했습니다" />}
        </Dialog>
      )}
    </>
  );
}

function Versions({ a, canWrite, base }: { a: AppView; canWrite: boolean; base: string }) {
  const q = usePoll((s) => appVersionMarks(a.tenant, a.app, s), [a.tenant, a.app]);
  const toast = useToast();
  const [ask, setAsk] = useState<AppVersionMark>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const set = async (v: AppVersionMark, migration: boolean) => {
    setBusy(true);
    setError(undefined);
    try {
      await putVersionMark(a.tenant, a.app, v.version, migration);
      setAsk(undefined);
      q.refresh();
    } catch (e) {
      if (!migration) toast(`표시를 풀지 못했습니다: ${errorText(e).message}`);
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="card">
      <div className="row between">
        <h2>버전별 데이터 이전 표시</h2>
        <Link to={`${base}/revisions`} className="small">
          버전 기록 전체
        </Link>
      </div>
      <span className="muted small">데이터 형식을 바꾼 버전에 표시하면, 그 버전에서 이전 버전으로의 자동 되돌리기는 하지 않습니다. 데이터 저장소·망·비밀값 변경은 자동으로 표시됩니다.</span>
      <Load q={q} rows={3} what="버전을 불러오지 못했습니다">
        {(d) => (
          <div className="gtbl">
            <div className="gr th vers">
              <span>버전</span>
              <span>바뀐 것</span>
              <span>올린 주체</span>
              <span>완료</span>
              <span>데이터 이전 있음</span>
            </div>
            {!d.items.length && <div className="gr muted">아직 버전이 없습니다.</div>}
            {d.items.map((v, i) => (
              <div key={v.version} className="gr vers">
                <span className="mono">v{v.version}</span>
                <span className="el">{v.summary}</span>
                <span>{v.by}</span>
                <span className="muted">{shortWhen(v.at)}</span>
                <label className="check" title={v.auto ? `${v.auto}이라 자동으로 표시됐습니다` : canWrite ? undefined : NEED}>
                  <input type="checkbox" checked={v.migration} disabled={!canWrite || !!v.auto || busy} onChange={(e) => (e.target.checked ? (setError(undefined), setAsk(v)) : void set(v, false))} />
                  <span className="muted small">{v.auto ? `${v.auto} · 자동 대상 아님` : i === 0 && v.cd && !v.migration ? '조건 충족 시 자동 되돌리기 대상' : ''}</span>
                </label>
              </div>
            ))}
          </div>
        )}
      </Load>
      {ask && (
        <Dialog
          width={400}
          title={`v${ask.version}에 데이터 이전 표시를 할까요?`}
          onClose={() => setAsk(undefined)}
          footer={
            <>
              <button className="btn" onClick={() => setAsk(undefined)}>
                취소
              </button>
              <button className="btn primary" disabled={busy} onClick={() => void set(ask, true)}>
                표시
              </button>
            </>
          }
        >
          <p style={{ margin: 0 }}>
            v{ask.version}에서 v{ask.version - 1}로의 자동 되돌리기가 막히고, 되돌리기는 승인 요청으로 바뀝니다.
          </p>
          {error !== undefined && <ErrorBand error={error} what="표시하지 못했습니다" />}
        </Dialog>
      )}
    </section>
  );
}

function Recent({ a }: { a: AppView }) {
  const q = usePoll((s) => incidents({ tenant: a.tenant, app: a.app, limit: 5 }, s), [a.tenant, a.app], 30_000);
  return (
    <section className="card">
      <div className="row between">
        <h2>이 앱의 최근 사건</h2>
        <Link to="/incidents" className="small">
          모든 사건
        </Link>
      </div>
      <Load q={q} rows={2} what="사건을 불러오지 못했습니다">
        {(d) => (
          <div className="gtbl">
            <div className="gr th ainc">
              <span>사건</span>
              <span>신호</span>
              <span>임시 조치</span>
              <span>영향</span>
              <span>결정</span>
              <span>시각</span>
            </div>
            {!d.items.length && <div className="gr muted">이 앱에서 감지한 사건이 없습니다.</div>}
            {d.items.map((r) => (
              <div key={r.id} className="gr ainc">
                <Link to={`/incidents/${encodeURIComponent(r.id)}`} className="mono">
                  {r.id}
                </Link>
                <span className="el">{r.signal}</span>
                <span className="el">{r.mitigation}</span>
                <Badge tone={IMPACT_TONE[r.impact]}>{IMPACT_NAME[r.impact]}</Badge>
                <span className="el">{decisionText(r.decision)}</span>
                <span className="muted">{shortWhen(r.at)}</span>
              </div>
            ))}
          </div>
        )}
      </Load>
    </section>
  );
}

/** 휴대폰 앱 장애 대응 탭 (UI-M9 ④): 보기만. 바꾸기는 넓은 화면에서 (작업 공간 관리자) */
function MAppIncident({ a, c }: { a: AppView; c: AppIncidentConf }) {
  const [view, setView] = useState<'actions' | 'versions'>();
  const marks = usePoll((s) => (view === 'versions' ? appVersionMarks(a.tenant, a.app, s) : Promise.resolve(undefined)), [a.tenant, a.app, view]);
  const rank: Record<Level, number> = { off: 0, suggest: 1, 'auto-low': 2 };
  const capped = rank[c.clusterLevel] < rank[c.level];
  const cd = c.cdRollback;
  const guide = c.guides?.app;
  const here = (x: MitigationAction) => (x.auto === 'allow' ? (c.actions[x.id] ? '자동 실행 허용' : '승인 요청 (자동 허용 안 함)') : x.auto === 'approval' ? '승인 요청만' : '사람만');
  return (
    <>
      <div className="mc">
        <div className="hd">
          <b>이 앱의 장애 자동 대응</b>
          <span className="ro">보기만</span>
        </div>
        <div className="mseg ro-seg" role="radiogroup" aria-label="이 앱의 장애 자동 대응" aria-readonly>
          {(['off', 'suggest', 'auto-low'] as Level[]).map((l) => (
            <span key={l} role="radio" aria-checked={c.level === l} className={c.level === l ? 'on' : ''}>
              {LEVEL_NAME[l]}
            </span>
          ))}
        </div>
        {capped && (
          <div className="bn info" style={{ fontSize: 12 }}>
            클러스터 정책이 ‘{LEVEL_NAME[c.clusterLevel]}’{c.clusterLevel === 'off' ? '이라 지금은 이 앱도 아무것도 하지 않습니다' : '이라 지금은 이 앱도 승인 요청만 만듭니다'}
          </div>
        )}
        <dl className="mkv">
          <dt>횟수 한도</dt>
          <dd>시간당 {c.ratePerHour}회</dd>
          {c.quiet.length > 0 && (
            <>
              <dt>막는 시간</dt>
              <dd>{c.quiet.map(quietText).join(', ')}</dd>
            </>
          )}
          <dt>승인 받는 사람</dt>
          <dd>{c.approvers ?? '—'}</dd>
          <dt>판단 방식</dt>
          <dd>{!c.decide ? '클러스터 기본' : typeof c.decide === 'string' ? c.decide : decideChain(c.decide)}</dd>
        </dl>
      </div>
      <div className="mc">
        <div className="hd">
          <b>자동 배포 후 되돌리기</b>
          {cd.enabled ? <Badge tone={cd.alwaysApprove ? 'wa' : 'ok'}>{cd.alwaysApprove ? '항상 승인' : '자동 허용'} · {cd.windowMinutes}분</Badge> : <Badge tone="un">끔</Badge>}
        </div>
        <div className="ln">자동 배포가 올린 새 버전이 바로 장애를 내면 직전 버전으로 자동 되돌리기 · 되돌리면 자동 배포도 멈춤</div>
      </div>
      <div className="li">
        <Link to={`/incidents/guide?scope=app&app=${encodeURIComponent(a.app)}`}>
          행동 지침<span className="r">{guide ? `v${guide.version} ›` : c.guides ? '없음 ›' : '›'}</span>
        </Link>
        <button type="button" onClick={() => setView('actions')}>
          쓸 임시 조치<span className="r">{c.available.length}개 ›</span>
        </button>
        <button type="button" onClick={() => setView('versions')}>
          버전별 데이터 이전 표시<span className="r">›</span>
        </button>
      </div>
      <span className="muted small" style={{ textAlign: 'center' }}>
        바꾸기는 넓은 화면에서 (작업 공간 관리자)
      </span>
      {view === 'actions' && (
        <Drawer title="쓸 임시 조치" onClose={() => setView(undefined)}>
          <span className="muted small">클러스터가 허용한 조치만 보입니다. ‘보통’은 이 앱에서도 자동으로 바꿀 수 없습니다.</span>
          {c.available.map((x) => (
            <div key={x.id} className="mc">
              <div className="hd">
                <b>{x.label.replace(/ \(조건 모두 충족 시\)$/, '')}</b>
              </div>
              <div className="ln">
                규칙 하한 <Badge tone={IMPACT_TONE[x.floor]}>{IMPACT_NAME[x.floor]}</Badge>
              </div>
              <div className="ln muted">이 앱에서: {here(x)}</div>
            </div>
          ))}
          {!c.available.length && <span className="muted small">클러스터가 허용한 앱 임시 조치가 없습니다.</span>}
        </Drawer>
      )}
      {view === 'versions' && (
        <Drawer title="버전별 데이터 이전 표시" onClose={() => setView(undefined)}>
          <span className="muted small">데이터 형식을 바꾼 버전에서 이전 버전으로는 자동으로 되돌리지 않습니다.</span>
          <Load q={marks} what="버전을 불러오지 못했습니다">
            {(d) =>
              d?.items.length ? (
                <>
                  {d.items.map((v) => (
                    <div key={v.version} className="mc">
                      <div className="hd">
                        <b>버전 {v.version}</b>
                        {v.migration ? <Badge tone="wa">데이터 이전 있음{v.auto ? ' · 자동' : ''}</Badge> : <Badge tone="un">없음</Badge>}
                      </div>
                      <div className="ln">{v.summary}</div>
                      <div className="ln muted" style={{ fontSize: 12 }}>
                        {shortWhen(v.at)} · {v.cd ? '⟳ 자동 배포' : v.by}
                      </div>
                    </div>
                  ))}
                </>
              ) : (
                <span className="muted small">표시할 버전이 없습니다.</span>
              )
            }
          </Load>
        </Drawer>
      )}
    </>
  );
}
