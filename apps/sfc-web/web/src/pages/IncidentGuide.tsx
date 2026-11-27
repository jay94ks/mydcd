// SPDX-License-Identifier: Apache-2.0

// 장애 대응 › 행동 지침 (UI-BA, 캔버스 IncidentGuide · IncidentGuideIx). 웹 데몬 몫(지침 글·버전, AI에 넘기기).
// 계약: /mnt/project-files/w2/guides-mcp-webhooks-contract.md '행동 지침' + guides-web-needs.md.
import { DraftBand, useStoredDraft, useUnsaved } from '../components/Unsaved';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ApiError } from '../api/client';
import { apps } from '../api/endpoints';
import { GUIDE_MAX, guide, guideVersions, guides, putGuide, restoreGuide, scopeKey, testGuide, type Guide, type GuideFields, type GuideChoices, type GuideScope, type GuideSummary, type GuideTestRun, type GuideVersion } from '../api/guides';
import { IMPACT_NAME, incidents, type IncidentRow } from '../api/incidents';
import { useAuth, useSession } from '../auth/session';
import { DiffView } from '../components/Code';
import { Dialog } from '../components/Dialog';
import { Popover } from '../components/Popover';
import { useToast } from '../components/Toast';
import { ErrorBand, Load } from '../components/states';
import { Badge, HelpBox, PageHeader } from '../components/ui';
import { lineDiff } from '../lib/diff';
import { usePoll } from '../lib/usePoll';
import { IncidentTabs, shortWhen } from './Incidents';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { Drawer } from '../components/Drawer';
import { appsLive, incidentsLive, kindsLive } from '../lib/liveTopics';

type Kind = GuideScope['kind'];
const scopeName = (s: GuideScope) => (s.kind === 'cluster' ? '클러스터' : s.kind === 'tenant' ? `작업 공간 ${s.tenant}` : s.app);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const splitList = (s: string) =>
  s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
const tokens = (t?: GuideTestRun['tokens']) => (t ? `${Math.round(t.total / 1000)}k${t.cachedRatio !== undefined ? ` (캐시 ${Math.round(t.cachedRatio * 100)}%)` : ''}` : '—');
const mcpText = (m?: Record<string, number>) => (m && Object.keys(m).length ? Object.entries(m).map(([k, n]) => `${k} ${n}회`).join(' · ') : '—');

export function IncidentGuidePage() {
  return usePhone() ? <MGuides /> : <DesktopGuide />;
}

// ── 휴대폰 행동 지침 탭 (UI-M8 ④ 메모): 지침별 카드 + 본문 보기, 고치기는 넓은 화면에서 ──
const guideScope = (g: GuideSummary): GuideScope => (g.scope === 'cluster' ? { kind: 'cluster' } : g.scope === 'tenant' ? { kind: 'tenant', tenant: g.tenant ?? '' } : { kind: 'app', tenant: g.tenant ?? '', app: g.app ?? '' });
const guideName = (g: Pick<GuideSummary, 'scope' | 'tenant' | 'app'>) => (g.scope === 'cluster' ? '클러스터' : g.scope === 'tenant' ? `작업 공간 ${g.tenant}` : `${g.app} · ${g.tenant}`);

function MGuides() {
  const q = usePoll((s) => guides(s), [], 0, kindsLive('guide'));
  const [sel, setSel] = useState<GuideSummary>();
  useMobileTop({ title: '장애 대응', root: true }, []);
  return (
    <>
      <IncidentTabs />
      <Load q={q} rows={4} what="행동 지침을 불러오지 못했습니다">
        {(d) =>
          d.items.length === 0 ? (
            <span className="muted small">아직 쓴 행동 지침이 없습니다.</span>
          ) : (
            <>
              {d.items.map((g) => (
                <button key={scopeKey(guideScope(g))} type="button" className="mc" style={{ textAlign: 'left', font: 'inherit' }} onClick={() => setSel(g)}>
                  <div className="hd">
                    <b>{guideName(g)}</b>
                    <Badge tone="tag">v{g.version}</Badge>
                  </div>
                  <div className="ln">{g.summary}</div>
                  <div className="ln muted" style={{ fontSize: 12 }}>
                    {[g.lines !== undefined && `${g.lines}줄`, g.updatedBy, g.updatedAt && shortWhen(g.updatedAt)].filter(Boolean).join(' · ')}
                  </div>
                </button>
              ))}
            </>
          )
        }
      </Load>
      <span className="muted small" style={{ textAlign: 'center' }}>
        지침 고치기 · 되돌리기 · 시험은 넓은 화면에서
      </span>
      {sel && <MGuideBody g={sel} onClose={() => setSel(undefined)} />}
    </>
  );
}

function MGuideBody({ g, onClose }: { g: GuideSummary; onClose: () => void }) {
  const q = usePoll((s) => guide(guideScope(g), s), [scopeKey(guideScope(g))], 0, kindsLive('guide'));
  return (
    <Drawer title={`행동 지침 · ${guideName(g)}`} onClose={onClose}>
      <Load q={q} rows={6} what="지침을 불러오지 못했습니다">
        {(v) => (
          <>
            <span className="muted small">
              v{v.version}
              {v.updatedBy ? ` · ${v.updatedBy}` : ''}
              {v.updatedAt ? ` · ${shortWhen(v.updatedAt)}` : ''}
            </span>
            <pre className="mc" style={{ whiteSpace: 'pre-wrap', margin: 0, fontSize: 13, lineHeight: '20px', fontFamily: 'inherit' }}>
              {v.text || '(비어 있음)'}
            </pre>
          </>
        )}
      </Load>
    </Drawer>
  );
}

function DesktopGuide() {
  const session = useSession();
  const { tenant } = useAuth();
  const [sp, setSp] = useSearchParams();
  const isAdmin = session.user.systemAdmin;
  const isManager = isAdmin || session.tenants.some((t) => t.id === tenant && t.role === 'manager');
  const kind = (['cluster', 'tenant', 'app'].includes(sp.get('scope') ?? '') ? sp.get('scope') : 'app') as Kind;
  const appsQ = usePoll((s) => apps(tenant, s), [tenant], 0, appsLive(tenant));
  const appName = sp.get('app') ?? appsQ.data?.items[0]?.app;
  const scope: GuideScope | undefined = kind === 'cluster' ? { kind } : kind === 'tenant' ? { kind, tenant } : appName ? { kind: 'app', tenant, app: appName } : undefined;
  const canWrite = kind === 'cluster' ? isAdmin : isManager;
  const set = (k: Kind, app?: string) => setSp((p) => {
    const n = new URLSearchParams(p);
    n.set('scope', k);
    if (app) n.set('app', app);
    return n;
  }, { replace: true });
  const scopeRow = (
    <div className="row wrap" style={{ gap: 10, fontSize: 13 }}>
      <span className="muted">지침 범위</span>
      <span className="segmented" role="radiogroup" aria-label="지침 범위">
        <button type="button" role="radio" aria-checked={kind === 'cluster'} className={kind === 'cluster' ? 'on' : ''} disabled={!isAdmin} title={isAdmin ? undefined : '클러스터 지침은 시스템 관리자만 보고 고칠 수 있습니다.'} onClick={() => set('cluster')}>
          클러스터
        </button>
        <button type="button" role="radio" aria-checked={kind === 'tenant'} className={kind === 'tenant' ? 'on' : ''} onClick={() => set('tenant')}>
          작업 공간 {tenant}
        </button>
        <button type="button" role="radio" aria-checked={kind === 'app'} className={kind === 'app' ? 'on' : ''} onClick={() => set('app')}>
          앱 {appName ?? ''}
        </button>
      </span>
      {kind === 'app' && (
        <select aria-label="앱" value={appName ?? ''} onChange={(e) => set('app', e.target.value)} style={{ width: 220, height: 32, fontSize: 13 }}>
          {(appsQ.data?.items ?? []).map((a) => (
            <option key={a.app} value={a.app}>
              {tenant} / {a.app}
            </option>
          ))}
        </select>
      )}
      <span className="muted">작업 공간 관리자 이상 · 클러스터 지침은 시스템 관리자</span>
    </div>
  );
  const top = (actions?: ReactNode) => (
    <>
      <PageHeader title="장애 대응" ids="UI-BA" actions={actions} />
      <IncidentTabs />
      <HelpBox terms="행동 지침 (runbook instructions) · 장애 진단 (컨텍스트 A) · 영향 평가 (컨텍스트 B) · 코디네이터 (coordinator)">
        <b>이 화면은</b> 장애 자동 대응과 코디네이터에게 넘길 <b>행동 지침</b>을 적습니다. "이 앱은 무엇을 먼저 보고, 무엇은 하지 말라" 같은 우리 팀의 대응 방식을 AI가 따르게 합니다. 지침은 클러스터 → 작업 공간 → 앱 순서로 쌓여 들어갑니다. 지침은 고를 수 있는 조치를 <b>줄이거나 순서를 정할</b> 수만 있고, 목록 밖 조치를 추가하거나 영향 등급·자동 실행 조건을 느슨하게 할 수는 없습니다.
      </HelpBox>
      {scopeRow}
    </>
  );
  if (!scope)
    return (
      <>
        {top()}
        {appsQ.error ? <ErrorBand error={appsQ.error} what="앱 목록을 불러오지 못했습니다" onRetry={appsQ.refresh} /> : <div className="note un">{appsQ.loading ? '앱 목록을 불러오는 중…' : '이 작업 공간에 앱이 없습니다. 작업 공간 지침을 고르세요.'}</div>}
      </>
    );
  return <Scoped key={scopeKey(scope)} scope={scope} canWrite={canWrite} top={top} />;
}

function Scoped({ scope, canWrite, top }: { scope: GuideScope; canWrite: boolean; top: (actions?: ReactNode) => ReactNode }) {
  const q = usePoll((s) => guide(scope, s), [scopeKey(scope)], 0, kindsLive('guide'));
  const list = usePoll((s) => guides(s), [scopeKey(scope)], 0, kindsLive('guide'));
  const vers = usePoll((s) => guideVersions(scope, s), [scopeKey(scope)], 0, kindsLive('guide'));
  if (!q.data)
    return (
      <>
        {top()}
        <Load q={q} rows={8} what="행동 지침을 불러오지 못했습니다">
          {() => null}
        </Load>
      </>
    );
  const refresh = () => {
    q.refresh();
    list.refresh();
    vers.refresh();
  };
  return <Editor key={q.data.revision} scope={scope} g={q.data} canWrite={canWrite} top={top} layers={list.data?.items} versions={vers.data?.items} onSaved={refresh} />;
}

interface Draft {
  text: string;
  fields: GuideFields;
  notify: string;
  critical: string;
  deliver?: Guide['deliver'];
}
const fieldsOf = (d: Draft): GuideFields => ({ ...d.fields, notify: splitList(d.notify), critical: splitList(d.critical) });

function Editor({ scope, g, canWrite, top, layers, versions, onSaved }: { scope: GuideScope; g: Guide; canWrite: boolean; top: (actions?: ReactNode) => ReactNode; layers?: GuideSummary[]; versions?: GuideVersion[]; onSaved: () => void }) {
  const [d, setD] = useState<Draft>(() => ({ text: g.text, fields: g.fields, notify: g.fields.notify.join(', '), critical: g.fields.critical.join(', '), deliver: g.deliver }));
  const [dialog, setDialog] = useState<'save' | 'test' | { restore: number }>();
  const fields = fieldsOf(d);
  const dirty = d.text !== g.text || !same(fields, g.fields) || !same(d.deliver, g.deliver);
  // 저장 안 한 입력 지키기(캔버스 v224 UnsavedGuard)
  const count = [d.text !== g.text, ...(Object.keys(fields) as (keyof GuideFields)[]).map((k) => !same(fields[k], g.fields[k])), !same(d.deliver, g.deliver)].filter(Boolean).length;
  const stored = useStoredDraft<Draft>('incident-guide', canWrite ? scopeKey(scope) : undefined);
  const un = useUnsaved({ dirty, what: `${scopeName(scope)} 장애 대응 지침`, count, draft: { kind: 'incident-guide', scope: scopeKey(scope), value: d, rev: g.revision } });
  const saved = () => {
    un.clear();
    stored.drop();
    onSaved();
  };
  const over = d.text.length > GUIDE_MAX;
  const next = g.version + 1;
  const need = scope.kind === 'cluster' ? '시스템 관리자 권한이 필요합니다' : '이 작업 공간의 관리자 권한이 필요합니다';
  const ch = g.choices;
  const label = (id: string) => ch?.actions.find((x) => x.id === id)?.label ?? id;
  const setF = (p: Partial<GuideFields>) => setD((o) => ({ ...o, fields: { ...o.fields, ...p } }));
  const togglePrefer = (id: string) => setF({ prefer: d.fields.prefer.includes(id) ? d.fields.prefer.filter((x) => x !== id) : [...d.fields.prefer, id] });
  const lines = d.text.split('\n').filter((l) => l.trim() && !l.startsWith('#')).length;
  const actions = (
    <>
      <button className="btn" onClick={() => setDialog('test')}>
        지난 사건으로 시험…
      </button>
      <button className="btn primary" disabled={!canWrite || !dirty || over} title={!canWrite ? need : !dirty ? '바뀐 것이 없습니다' : over ? `${GUIDE_MAX.toLocaleString()}자를 넘었습니다` : undefined} onClick={() => setDialog('save')}>
        저장 (v{next})
      </button>
    </>
  );
  return (
    <>
      {top(actions)}
      {un.guard}
      {stored.draft && !dirty && <DraftBand draft={stored.draft} what="지침" rev={g.revision} onResume={() => (setD(stored.draft!.value), stored.drop())} onDiscard={stored.drop} />}
      <div className="main-side">
        <section className="card">
          <div className="row between wrap">
            <span className="row" style={{ gap: 8 }}>
              <h2>지침 (자유 글)</h2>
              {un.badge}
            </span>
            <span className={`small ${over ? 'error' : 'muted'}`}>
              {d.text.length.toLocaleString()} / {GUIDE_MAX.toLocaleString()}자 · 마크다운
            </span>
          </div>
          <textarea className="guide-ed" aria-label="지침 (자유 글)" value={d.text} readOnly={!canWrite} title={canWrite ? undefined : need} placeholder={`# ${scopeName(scope)} 장애 대응 지침\n- 무엇을 먼저 볼지, 무엇은 하지 말지 적으세요.`} onChange={(e) => setD((o) => ({ ...o, text: e.target.value }))} />
          {g.warnings.map((w) => (
            <div key={`${w.line}-${w.text}`} className="note wa small">
              {w.line ? <span className="mono">{w.line}줄 · </span> : null}
              {w.text}
            </div>
          ))}
          <div className="row wrap" style={{ gap: 16, fontSize: 13 }}>
            <span style={{ fontWeight: 600 }}>넘길 곳</span>
            <label className="check" title={d.deliver ? undefined : '웹 기능 준비 중'}>
              <input type="checkbox" checked={d.deliver?.diagnose ?? true} disabled={!canWrite || !d.deliver} onChange={(e) => setD((o) => ({ ...o, deliver: { ...o.deliver!, diagnose: e.target.checked } }))} />
              장애 진단
            </label>
            <label className="check" title={d.deliver ? undefined : '웹 기능 준비 중'}>
              <input type="checkbox" checked={d.deliver?.coordinator ?? true} disabled={!canWrite || !d.deliver} onChange={(e) => setD((o) => ({ ...o, deliver: { ...o.deliver!, coordinator: e.target.checked } }))} />
              코디네이터 ({scope.kind === 'app' ? '이 앱을 다룰 때' : scope.kind === 'tenant' ? '이 작업 공간을 다룰 때' : '모든 대화'})
            </label>
            <label className="check" style={{ opacity: 0.55 }}>
              <input type="checkbox" checked={false} disabled />
              영향 평가 (넘기지 않음)
            </label>
          </div>
          <div style={{ fontSize: 13, fontWeight: 600 }}>정해진 칸</div>
          {!ch ? (
            <div className="note un small">웹 기능 준비 중 · 고를 수 있는 조치·서비스·MCP 목록을 웹 데몬이 아직 주지 않습니다.</div>
          ) : (
            <div className="col" style={{ gap: 10, fontSize: 13 }}>
              <div>
                <div style={{ fontWeight: 600, marginBottom: 6 }}>먼저 고려할 임시 조치</div>
                <span className="row wrap" style={{ gap: 6 }}>
                  {[...d.fields.prefer.map((id) => ch.actions.find((x) => x.id === id)).filter((x): x is GuideChoices['actions'][number] => !!x), ...ch.actions.filter((x) => !d.fields.prefer.includes(x.id))].map((x) => {
                    const on = d.fields.prefer.includes(x.id);
                    const avoided = d.fields.avoid.actions.includes(x.id);
                    const why = x.blockedBy ? `${x.blockedBy === 'cluster' ? '클러스터' : '작업 공간'} 지침이 “${x.label}”를 제안하지 말라고 정했습니다. ${scope.kind === 'app' ? '앱' : '작업 공간'} 지침에서 다시 켤 수 없습니다.` : avoided ? '‘제안하지 말 것’에 들어 있습니다.' : !canWrite ? need : undefined;
                    return (
                      <button key={x.id} type="button" className={`chip ${on ? 'on' : ''}`} aria-pressed={on} disabled={!canWrite || !!x.blockedBy || avoided} title={why} onClick={() => togglePrefer(x.id)}>
                        {x.label}
                      </button>
                    );
                  })}
                </span>
              </div>
              <div>
                <div style={{ fontWeight: 600, marginBottom: 6 }}>제안하지 말 것</div>
                <span className="row wrap" style={{ gap: 6 }}>
                  {d.fields.avoid.services.map((s) => (
                    <span key={`s-${s}`} className="chip no">
                      {s} 서비스의 모든 조치
                      {canWrite && (
                        <button type="button" className="chip-x" aria-label={`${s} 빼기`} onClick={() => setF({ avoid: { ...d.fields.avoid, services: d.fields.avoid.services.filter((y) => y !== s) } })}>
                          ✕
                        </button>
                      )}
                    </span>
                  ))}
                  {d.fields.avoid.actions.map((id) => (
                    <span key={`a-${id}`} className="chip no">
                      {label(id)}
                      {canWrite && (
                        <button type="button" className="chip-x" aria-label={`${label(id)} 빼기`} onClick={() => setF({ avoid: { ...d.fields.avoid, actions: d.fields.avoid.actions.filter((y) => y !== id) } })}>
                          ✕
                        </button>
                      )}
                    </span>
                  ))}
                  {canWrite && (
                    <Popover button="＋" label="제안하지 말 것 더하기" className="chip" width={260}>
                      {(close) => (
                        <>
                          <div className="grp">임시 조치</div>
                          {ch.actions
                            .filter((x) => !d.fields.avoid.actions.includes(x.id) && !x.blockedBy)
                            .map((x) => (
                              <button key={x.id} type="button" onClick={() => (setF({ avoid: { ...d.fields.avoid, actions: [...d.fields.avoid.actions, x.id] }, prefer: d.fields.prefer.filter((y) => y !== x.id) }), close())}>
                                {x.label}
                              </button>
                            ))}
                          {!!ch.services?.length && <div className="grp">서비스 (모든 조치)</div>}
                          {(ch.services ?? [])
                            .filter((s) => !d.fields.avoid.services.includes(s))
                            .map((s) => (
                              <button key={s} type="button" onClick={() => (setF({ avoid: { ...d.fields.avoid, services: [...d.fields.avoid.services, s] } }), close())}>
                                {s} 서비스의 모든 조치
                              </button>
                            ))}
                        </>
                      )}
                    </Popover>
                  )}
                </span>
              </div>
              <div>
                <div style={{ fontWeight: 600, marginBottom: 6 }}>이 지침에서 쓸 바깥 도구 (MCP)</div>
                <span className="row wrap" style={{ gap: 6 }}>
                  {!ch.mcpServers && <span className="muted small">웹 기능 준비 중</span>}
                  {d.fields.mcpServers.map((n) => {
                    const s = ch.mcpServers?.find((x) => x.name === n);
                    return (
                      <span key={n} className={`chip ${s?.state === 'error' || s?.state === 'off' ? 'no' : 'on'}`}>
                        {n}
                        {s?.state === 'off' ? ' · 잠시 끔' : s?.summary ? ` · ${s.summary}` : ''}
                        {canWrite && (
                          <button type="button" className="chip-x" aria-label={`${n} 빼기`} onClick={() => setF({ mcpServers: d.fields.mcpServers.filter((y) => y !== n) })}>
                            ✕
                          </button>
                        )}
                      </span>
                    );
                  })}
                  {canWrite && ch.mcpServers && (
                    <Popover button="＋" label="MCP 서버 더하기" className="chip" width={280}>
                      {(close) => (
                        <>
                          <div className="grp">연결한 MCP 서버 (이 {scope.kind === 'cluster' ? '클러스터' : '작업 공간'}에서 쓸 수 있는 것)</div>
                          {ch.mcpServers!.filter((x) => !d.fields.mcpServers.includes(x.name)).length === 0 && <div className="grp">더 고를 서버가 없습니다</div>}
                          {ch.mcpServers!
                            .filter((x) => !d.fields.mcpServers.includes(x.name))
                            .map((x) => (
                              <button key={x.name} type="button" aria-disabled={x.state === 'error' || x.state === 'off'} disabled={x.state === 'error' || x.state === 'off'} onClick={() => (setF({ mcpServers: [...d.fields.mcpServers, x.name] }), close())}>
                                {x.name}
                                <small>{x.state === 'error' ? '연결 실패' : x.state === 'off' ? '잠시 끔' : x.summary}</small>
                              </button>
                            ))}
                        </>
                      )}
                    </Popover>
                  )}
                </span>
                <span className="muted small" style={{ display: 'block', marginTop: 4 }}>
                  진단에 쓸 서버입니다. 하나라도 고르면 그 서버만 쓰고, 비우면 쓸 수 있는 서버를 모두 씁니다.
                </span>
              </div>
              <div className="kv2" style={{ gridTemplateColumns: '130px minmax(0,1fr)', fontSize: 12, alignItems: 'center' }}>
                <span className="muted">알림 받을 곳</span>
                {canWrite ? <input aria-label="알림 받을 곳" value={d.notify} placeholder="쉼표로 나눕니다 · 예: #shop-oncall (slack)" onChange={(e) => setD((o) => ({ ...o, notify: e.target.value }))} style={{ height: 30, fontSize: 12 }} /> : <span>{fields.notify.join(' · ') || '없음'}</span>}
                <span className="muted">중요도 표시</span>
                <span className="col" style={{ gap: 2 }}>
                  {canWrite ? <input aria-label="중요도 표시" value={d.critical} placeholder="쉼표로 나눕니다 · 예: 결제 경로 있음" onChange={(e) => setD((o) => ({ ...o, critical: e.target.value }))} style={{ height: 30, fontSize: 12 }} /> : <span>{fields.critical.join(' · ') || '없음'}</span>}
                  {fields.critical.length > 0 && <span className="muted">영향 평가가 등급을 낮추지 못함</span>}
                </span>
              </div>
            </div>
          )}
        </section>
        <div className="col" style={{ gap: 20 }}>
          <Layers scope={scope} layers={layers} self={{ version: g.version, lines, chars: d.text.length }} />
          <section className="card">
            <h2>지켜지는 규칙</h2>
            <div className="rulebox">
              <span>· 영향 평가(컨텍스트 B)에는 자유 글을 넘기지 않습니다. '중요도 표시'와 '제안하지 말 것'처럼 <b>등급을 올리거나 막는 칸</b>만 사실로 넘깁니다.</span>
              <span>· 지침이 목록 밖 조치·지우기·비밀값을 요구해도 진단은 고를 수 없습니다(구조화 출력 그대로).</span>
              <span>· 지침과 클러스터 정책이 부딪치면 정책이 이깁니다. 위 단계 지침의 '제안하지 말 것'은 아래 단계가 풀 수 없습니다.</span>
              <span>· 사건마다 쓴 지침 버전을 남겨, 결과가 이상하면 어떤 지침 때문인지 볼 수 있습니다.</span>
            </div>
          </section>
        </div>
      </div>
      <section className="card">
        <div className="row between">
          <h2>버전 기록</h2>
          <span className="muted small">지울 때까지 보관 · 되돌리기 가능</span>
        </div>
        {!versions ? (
          <div className="muted small">불러오는 중…</div>
        ) : !versions.length ? (
          <div className="muted small">아직 저장한 버전이 없습니다.</div>
        ) : (
          <div className="gtbl">
            <div className="gr th gvers">
              <span>버전</span>
              <span>언제</span>
              <span>누가</span>
              <span>바뀐 것</span>
              <span>사건</span>
              <span />
            </div>
            {versions.map((v) => {
              const cur = v.current ?? v.version === g.version;
              return (
                <div key={v.version} className="gr gvers">
                  {cur ? <b>v{v.version}</b> : <span>v{v.version}</span>}
                  <span>{shortWhen(v.updatedAt)}</span>
                  <span>{v.updatedBy}</span>
                  <span>{v.summary}</span>
                  <span>{cur ? <Badge tone="ok">지금</Badge> : v.incidents === undefined ? <span className="muted">—</span> : v.incidents ? <Badge tone="un">사건 {v.incidents}건</Badge> : <span className="muted">사건 없음</span>}</span>
                  <span>
                    {!cur && (
                      <button className="textbtn small" disabled={!canWrite} title={canWrite ? undefined : need} onClick={() => setDialog({ restore: v.version })}>
                        되돌리기…
                      </button>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </section>
      {dialog === 'save' && <SaveDialog scope={scope} g={g} text={d.text} fields={fields} deliver={d.deliver} onClose={() => setDialog(undefined)} onSaved={saved} />}
      {dialog === 'test' && <TestDialog scope={scope} g={g} dirty={dirty} text={d.text} fields={fields} canSave={canWrite && dirty && !over} onClose={() => setDialog(undefined)} onSave={() => setDialog('save')} />}
      {typeof dialog === 'object' && <RestoreDialog scope={scope} g={g} version={dialog.restore} onClose={() => setDialog(undefined)} onSaved={saved} />}
    </>
  );
}

function Layers({ scope, layers, self }: { scope: GuideScope; layers?: GuideSummary[]; self: { version: number; lines: number; chars: number } }) {
  const tenant = scope.kind === 'cluster' ? undefined : scope.tenant;
  const find = (k: GuideSummary['scope']) => layers?.find((x) => x.scope === k && (k === 'cluster' || x.tenant === tenant) && (k !== 'app' || (scope.kind === 'app' && x.app === scope.app)));
  const rows: [GuideSummary['scope'], string, string][] = [
    ['cluster', '클러스터 지침', '캐시 · 클러스터 공유'],
    ...(scope.kind !== 'cluster' ? ([['tenant', `작업 공간 지침 · ${tenant}`, '캐시 · 작업 공간']] as [GuideSummary['scope'], string, string][]) : []),
    ...(scope.kind === 'app' ? ([['app', `앱 지침 · ${scope.app}`, '캐시 · 앱']] as [GuideSummary['scope'], string, string][]) : []),
  ];
  return (
    <section className="card">
      <h2>AI에게 가는 순서</h2>
      <div className="layer">
        <div className="fx">
          <b>1 고정 시스템 프롬프트</b>
          <span>역할 · 안전 규칙 · 임시 조치 목록 · 평가 기준 (바꿀 수 없음)</span>
          <span className="muted">캐시 · 모두 공유</span>
        </div>
        {rows.map(([k, name, cache], i) => {
          const mine = k === scope.kind;
          const s = find(k);
          const v = mine ? self.version : s?.version;
          return (
            <div key={k} className={`us ${mine ? 'sel' : ''}`}>
              <b>
                {i + 2} {name}
                {v ? ` v${v}` : ''}
              </b>
              <span>{mine ? `이 편집기 · ${self.lines}줄 · ${self.chars.toLocaleString()}자` : s ? `${s.updatedBy ? `${s.updatedBy} · ` : ''}${s.summary}` : layers ? (k === 'cluster' ? '없음 또는 볼 수 없음' : '없음') : '불러오는 중…'}</span>
              <span className="muted">{cache}</span>
            </div>
          );
        })}
        <div>
          <b>{rows.length + 2} 사건 사실</b>
          <span>신호 · 최근 변경 · 수집한 사실 (매번 다름)</span>
          <span className="muted">캐시 안 함</span>
        </div>
      </div>
      <span className="muted small">지침은 고정 시스템 프롬프트 뒤, 사건 사실 앞에 붙습니다. 지침마다 캐시 지점을 두어 같은 앱의 다음 사건은 지침까지 캐시에서 읽습니다. 지침을 고치면 다음 사건부터 새 버전을 씁니다.</span>
    </section>
  );
}

const fieldLines = (f: GuideFields) => [
  `먼저 고려: ${f.prefer.join(', ') || '없음'}`,
  `제안하지 말 것: ${[...f.avoid.actions, ...f.avoid.services.map((s) => `${s} 서비스`)].join(', ') || '없음'}`,
  `MCP: ${f.mcpServers.join(', ') || '없음'}`,
  `알림 받을 곳: ${f.notify.join(', ') || '없음'}`,
  `중요도 표시: ${f.critical.join(', ') || '없음'}`,
];

function SaveDialog({ scope, g, text, fields, deliver, onClose, onSaved }: { scope: GuideScope; g: Guide; text: string; fields: GuideFields; deliver?: Guide['deliver']; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const next = g.version + 1;
  const textDiff = lineDiff(g.text, text);
  const fieldDiff = lineDiff(fieldLines(g.fields).join('\n'), fieldLines(fields).join('\n'));
  const deliverDiff = deliver && g.deliver && !same(deliver, g.deliver);
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await putGuide(scope, { revision: g.revision, text, fields, ...(g.deliver && deliver ? { deliver } : {}) });
      toast(r.warnings.length ? `✓ ${scopeName(scope)} 지침 v${r.version}을 저장했습니다. 확인할 문장 ${r.warnings.length}개가 있습니다.` : `✓ ${scopeName(scope)} 지침 v${r.version}을 저장했습니다.`);
      onClose();
      onSaved();
    } catch (e) {
      setError(e);
      if (e instanceof ApiError && e.code === 'stale') {
        toast('그사이 다른 사람이 지침을 바꿨습니다. 새로 읽은 뒤 다시 고쳐 주세요.');
        onClose();
        onSaved();
      }
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`${scopeName(scope)} 지침 v${next} 저장`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={busy} onClick={save}>
            저장
          </button>
        </>
      }
    >
      {textDiff.some((l) => l.op !== ' ') && <DiffView lines={textDiff} />}
      {fieldDiff.some((l) => l.op !== ' ') && <DiffView lines={fieldDiff} />}
      {deliverDiff && (
        <div className="small">
          넘길 곳: 장애 진단 {deliver.diagnose ? '넘김' : '안 넘김'} · 코디네이터 {deliver.coordinator ? '넘김' : '안 넘김'}
        </div>
      )}
      <div className="muted small">다음 사건부터 v{next}를 씁니다. 진행 중인 사건은 쓰던 버전으로 끝납니다.</div>
      {error !== undefined && <ErrorBand error={error} what="저장하지 못했습니다" />}
    </Dialog>
  );
}

function RestoreDialog({ scope, g, version, onClose, onSaved }: { scope: GuideScope; g: Guide; version: number; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await restoreGuide(scope, g.revision, version);
      toast(`✓ v${version} 내용을 v${r.version}으로 저장했습니다.`);
      onClose();
      onSaved();
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
      title={`v${version}으로 되돌릴까요?`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger" disabled={busy} onClick={go}>
            되돌리기
          </button>
        </>
      }
    >
      <div>
        v{version} 내용을 새 버전 v{g.version + 1}로 저장합니다. 기록은 지워지지 않습니다.
      </div>
      {error !== undefined && <ErrorBand error={error} what="되돌리지 못했습니다" />}
    </Dialog>
  );
}

function TestDialog({ scope, g, dirty, text, fields, canSave, onClose, onSave }: { scope: GuideScope; g: Guide; dirty: boolean; text: string; fields: GuideFields; canSave: boolean; onClose: () => void; onSave: () => void }) {
  const p = scope.kind === 'cluster' ? { scope: 'cluster' } : scope.kind === 'tenant' ? { tenant: scope.tenant } : { tenant: scope.tenant, app: scope.app };
  const list = usePoll((s) => incidents({ ...p, limit: 20 }, s), [scopeKey(scope)], 0, incidentsLive);
  const items: IncidentRow[] = useMemo(() => list.data?.items ?? [], [list.data]);
  const [inc, setInc] = useState<string>();
  const [res, setRes] = useState<{ current: GuideTestRun; draft?: GuideTestRun }>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  useEffect(() => {
    if (!inc && items[0]) setInc(items[0].id);
  }, [inc, items]);
  useEffect(() => {
    if (!inc) return;
    let live = true;
    setBusy(true);
    setError(undefined);
    setRes(undefined);
    testGuide(scope, { incident: inc, ...(dirty ? { text, fields } : {}) })
      .then((r) => live && setRes(r))
      .catch((e) => live && setError(e))
      .finally(() => live && setBusy(false));
    return () => {
      live = false;
    };
    // 편집 중 내용은 연 순간 것으로 돌린다
  }, [inc]);
  const cols = res?.draft ? '0.6fr 1.2fr 1.2fr' : '0.6fr 2.4fr';
  const cand = (r: GuideTestRun | undefined, i: number, strong: boolean) => {
    const c = r?.candidates[i];
    if (!c) return '—';
    const t = `${c.label ?? c.action}${c.impact ? ` · ${IMPACT_NAME[c.impact]}` : ''}`;
    return strong ? <b>{t}</b> : t;
  };
  const n = Math.max(res?.current.candidates.length ?? 0, res?.draft?.candidates.length ?? 0, 1);
  return (
    <Dialog
      title="지침 시험 (실행 안 함)"
      width={720}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            닫기
          </button>
          {dirty && (
            <button className="btn primary" disabled={!canSave} onClick={onSave}>
              v{g.version + 1} 저장
            </button>
          )}
        </>
      }
    >
      <label className="field">
        사건
        <select value={inc ?? ''} onChange={(e) => setInc(e.target.value)} disabled={!items.length}>
          {!items.length && <option value="">{list.loading ? '불러오는 중…' : '이 범위의 지난 사건이 없습니다'}</option>}
          {items.map((x) => (
            <option key={x.id} value={x.id}>
              {x.id} · {x.app ?? x.node ?? ''} {x.signal}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        비교
        <select disabled value="x">
          <option value="x">{dirty ? `v${g.version} (지금) ↔ 편집 중 v${g.version + 1}` : `v${g.version} (지금) · 편집 중인 내용 없음`}</option>
        </select>
      </label>
      {busy && <div className="muted small">진단을 다시 돌리는 중…</div>}
      {error !== undefined && <ErrorBand error={error} what="시험하지 못했습니다" />}
      {res && (
        <div className="gtbl">
          <div className="gr th" style={{ gridTemplateColumns: cols }}>
            <span />
            <span>v{g.version}</span>
            {res.draft && <span>v{g.version + 1} (편집 중)</span>}
          </div>
          <div className="gr" style={{ gridTemplateColumns: cols }}>
            <span>가설</span>
            <span>{res.current.hypothesis}</span>
            {res.draft && <span>{res.draft.hypothesis}</span>}
          </div>
          {Array.from({ length: n }, (_, i) => {
            const changed = !!res.draft && res.draft.candidates[i]?.action !== res.current.candidates[i]?.action;
            return (
              <div key={i} className="gr" style={{ gridTemplateColumns: cols }}>
                <span>후보 {i + 1}</span>
                <span>{cand(res.current, i, false)}</span>
                {res.draft && <span>{cand(res.draft, i, changed)}</span>}
              </div>
            );
          })}
          <div className="gr" style={{ gridTemplateColumns: cols }}>
            <span>MCP</span>
            <span>{mcpText(res.current.mcpCalls)}</span>
            {res.draft && <span>{mcpText(res.draft.mcpCalls)}</span>}
          </div>
          <div className="gr" style={{ gridTemplateColumns: cols }}>
            <span>토큰</span>
            <span>{tokens(res.current.tokens)}</span>
            {res.draft && (
              <span>
                {tokens(res.draft.tokens)}
                {res.draft.tokens?.cachedRatio === 0 ? ' · 새 지침' : ''}
              </span>
            )}
          </div>
        </div>
      )}
      <div className="muted small">진단(A)만 다시 돌립니다. 영향 평가·실행은 하지 않으며 결과는 저장하지 않습니다.</div>
    </Dialog>
  );
}
