// SPDX-License-Identifier: Apache-2.0

// 시스템 › AI 설정 › 키 · 모델 (UI-B7, 캔버스 AiSettings · AiSettingsIx).
// 모두 웹 데몬 몫이다(키는 봉인 파일, 카탈로그·사용량·감사는 웹 bbolt). 키 값은 교체 창의 입력 칸에만 잠깐 있고, 보낸 뒤 바로 비운다.
import { useEffect, useMemo, useState } from 'react';
import { AI_PROVIDERS, AI_ROLES, aiAudit, aiModels, aiSettings, aiUsage, deleteAiAudit, deleteAiKey, putAiKey, putAiSettings, refreshAiModels, type AiData, type AiLimits, type AiModel, type AiProvider, type AiProviderRow, type AiRole, type AiRoleConf, type AiSettings } from '../api/ai';
import { ApiError } from '../api/client';
import { tenantList } from '../api/endpoints';
import { useUnsaved } from '../components/Unsaved';
import { Badge, Card, Field, HelpBox, PageHeader, type Tone } from '../components/ui';
import { ErrorBand, Load, errorText } from '../components/states';
import { Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { Popover } from '../components/Popover';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { fmtTime } from '../lib/format';
import { eulReul } from '../lib/josa';
import { when } from './WebBackup';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { Drawer } from '../components/Drawer';

export const PROVIDER_NAME: Record<AiProvider, string> = { claude: 'Claude', openai: 'OpenAI' };
const PROVIDER_FULL: Record<AiProvider, string> = { claude: 'Claude (Anthropic)', openai: 'OpenAI' };
const KEY_HINT: Record<AiProvider, string> = { claude: 'sk-ant-', openai: 'sk-proj-' };
export const ROLE_NAME: Record<AiRole, string> = { coordinator: '코디네이터', diagnosis: '장애 진단 (컨텍스트 A)', impact: '영향 평가 (컨텍스트 B)', simple: '단순 결정' };
const ROLE_SHORT: Record<AiRole, string> = { coordinator: '코디네이터', diagnosis: '장애 진단', impact: '영향 평가', simple: '단순 결정' };
const CACHE_AT: Record<AiRole, string> = { coordinator: '도구·시스템 1시간 + 대화 자동', diagnosis: '조치 목록 5분', impact: '평가 기준표 5분', simple: '작업 지시문 5분' };
const EFFORT: Record<string, string> = { low: '낮음', medium: '보통', high: '높음' };
const THINK: Record<string, string> = { auto: '자동', off: '끔' };
const KEY_ERR: Record<string, string> = { auth: '키가 폐기됐거나 틀렸습니다', unavailable: '공급자가 응답하지 않습니다', 'rate-limited': '사용량 제한에 걸렸습니다' };

export function AiTabs() {
  return (
    <Tabs
      label="AI 설정"
      items={[
        { to: '/system/ai', label: '키 · 모델', end: true },
        { to: '/system/ai/mcp', label: 'MCP 연동' },
      ]}
    />
  );
}

export function AiSettingsPage() {
  return usePhone() ? <MAiSettings /> : <DesktopAiSettings />;
}

/** 휴대폰 AI 설정 (UI-M11 ④): 보기만 한 줄 · 공급자 카드 · 역할별 모델 · 사용량 */
function MAiSettings() {
  const q = usePoll((s) => aiSettings(s), []);
  const [open, setOpen] = useState<'' | 'usage' | AiRole>('');
  const usage = usePoll((s) => (open === 'usage' ? aiUsage(7, s) : Promise.resolve(undefined)), [open]);
  useMobileTop({ title: 'AI 설정', sub: '시스템 관리자', wide: '키 교체·모델 바꾸기는 넓은 화면에서' }, []);
  const ref = (m: AiRoleConf['main']) => (m ? `${m.model}` : '없음');
  return (
    <>
    <AiTabs />
    <Load q={q} what="AI 설정을 읽지 못했습니다">
      {(d) => (
        <>
          {!d.sealReady && <div className="bn warn">봉인 키가 없어 API 키를 저장할 수 없습니다.</div>}
          {AI_PROVIDERS.map((p) => {
            const row = d.providers.find((x) => x.provider === p) ?? { provider: p, configured: false, models: 0 };
            const [tone, label]: [Tone, string] = !row.configured ? ['un', '키 없음'] : row.error ? ['er', '연결 실패'] : ['ok', '연결 확인됨'];
            return (
              <div key={p} className={`mc${row.error ? ' xer' : ''}`}>
                <div className="hd">
                  <b>{PROVIDER_FULL[p]}</b>
                  <Badge tone={tone}>{label}</Badge>
                </div>
                <div className="ln">{row.configured ? `끝 4자리 …${row.last4} · 다시 보여 주지 않음` : '키가 없으면 이 공급자의 모델은 쓰지 않습니다'}</div>
                {row.error && <div className="ln">연결 실패: {row.error}</div>}
              </div>
            );
          })}
          <div className="m-sec">
            <span>역할별 모델</span>
          </div>
          <div className="li">
            {AI_ROLES.map((r) => {
              const c = d.roles[r];
              return (
                <button key={r} type="button" onClick={() => setOpen(open === r ? '' : r)} style={{ flexWrap: 'wrap' }}>
                  <span className="el">{ROLE_SHORT[r]}</span>
                  <span className="r" style={c?.mainMissing ? { color: 'var(--er)' } : undefined}>
                    {ref(c?.main ?? null)}
                  </span>
                  {open === r && (
                    <span className="muted" style={{ flexBasis: '100%', fontSize: 12 }}>
                      예비 {ref(c?.fallback ?? null)}
                      {c?.effort ? ` · 생각 ${c.effort}` : ''}
                      {c?.maxOutputTokens ? ` · 출력 ${c.maxOutputTokens.toLocaleString('ko-KR')} 토큰` : ''}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
          <div className="li">
            <button type="button" onClick={() => setOpen('usage')}>
              사용량 · 캐시<span className="r">최근 7일 ›</span>
            </button>
          </div>
          {open === 'usage' && (
            <Drawer title="사용량 · 캐시 (최근 7일)" onClose={() => setOpen('')}>
              <Load q={usage} what="사용량을 읽지 못했습니다">
                {(u) =>
                  u && (
                    <div className="li">
                      {AI_ROLES.map((r) => {
                        const xs = u.items.filter((x) => x.role === r);
                        const tokens = xs.reduce((a, x) => a + x.inputTokens + x.outputTokens, 0);
                        const hit = u.roles[r]?.hitRate;
                        return (
                          <div key={r}>
                            <span className="el">
                              {ROLE_SHORT[r]}
                              <span style={{ display: 'block', fontSize: 12, color: 'var(--muted)' }}>
                                요청 {xs.reduce((a, x) => a + x.requests, 0).toLocaleString('ko-KR')} · {xs.length ? mtok(tokens) : '—'} 토큰
                              </span>
                            </span>
                            <span className="r">{hit === undefined ? '—' : <Badge tone={hit >= 0.8 ? 'ok' : hit >= 0.7 ? 'wa' : 'er'}>캐시 {Math.round(hit * 100)}%</Badge>}</span>
                          </div>
                        );
                      })}
                    </div>
                  )
                }
              </Load>
            </Drawer>
          )}
        </>
      )}
    </Load>
    </>
  );
}

function DesktopAiSettings() {
  const q = usePoll((s) => aiSettings(s), []);
  return (
    <>
      <PageHeader title="AI 설정" ids="UI-B7" actions={<Refresh q={q} poll={false} />} after={<span className="muted small">시스템 관리자</span>} />
      <AiTabs />
      <HelpBox terms="공급자 (provider: Claude · OpenAI) · 프롬프트 캐시 (prompt caching) · 캐시 적중 (cache hit) · 봉인 파일 (sealed file)">
        <b>이 화면은</b> 코디네이터와 장애 자동 대응이 쓰는 AI 공급자 키, 역할별 모델, 보낼 데이터 범위, 사용량과 프롬프트 캐시 상태를 관리합니다. 키는 sfc-web 컨테이너의 봉인 파일에만 있고 브라우저로 다시 보내지 않습니다.
      </HelpBox>
      <Load q={q}>
        {(d) => (
          <>
            {!d.sealReady && <div className="note wa">봉인 키(SFC_WEB_SEAL_KEY)가 없어 API 키를 저장할 수 없습니다. 웹 앱 설정의 ‘봉인 키 · 봉인 파일’을 먼저 확인하세요.</div>}
            <KeysCard d={d} onChanged={q.refresh} />
            <Editor key={d.revision} d={d} onSaved={q.refresh} />
          </>
        )}
      </Load>
    </>
  );
}

// ── API 키 ──
function KeysCard({ d, onChanged }: { d: AiSettings; onChanged: () => void }) {
  return (
    <Card title="API 키">
      <div className="g2">
        {AI_PROVIDERS.map((p) => {
          const row = d.providers.find((x) => x.provider === p) ?? { provider: p, configured: false, models: 0 };
          return <ProviderBox key={p} row={row} d={d} sealReady={d.sealReady} onChanged={onChanged} />;
        })}
      </div>
      <span className="muted small">
        연결 시험은 키로 모델 카탈로그를 한 번 읽는 것으로 합니다. 성공하면 받은 목록을 역할별 모델 칸에 씁니다(웹 bbolt <span className="mono">ai-model-catalog</span>, 키는 넣지 않음).
      </span>
    </Card>
  );
}

function ProviderBox({ row, d, sealReady, onChanged }: { row: AiProviderRow; d: AiSettings; sealReady: boolean; onChanged: () => void }) {
  const p = row.provider;
  const toast = useToast();
  const [dlg, setDlg] = useState<'' | 'key' | 'delete'>('');
  const [test, setTest] = useState<{ busy: boolean; ok?: number; error?: unknown }>({ busy: false });
  const [tone, label]: [Tone, string] = !row.configured ? ['un', '키 없음'] : row.error ? ['er', '연결 실패'] : ['ok', '연결 확인됨'];
  const runTest = async () => {
    setTest({ busy: true });
    try {
      const r = await refreshAiModels(p);
      setTest({ busy: false, ok: r.models });
      onChanged();
    } catch (e) {
      setTest({ busy: false, error: e });
    }
  };
  const refresh = async () => {
    try {
      const r = await refreshAiModels(p);
      toast(`${PROVIDER_NAME[p]} 모델 목록을 다시 받았습니다 (${r.models}개).`);
      onChanged();
    } catch (e) {
      toast(`모델 목록을 받지 못했습니다: ${errorText(e).message}`);
    }
  };
  const users = AI_ROLES.filter((r) => d.roles[r]?.main?.provider === p);
  return (
    <div className="subbox">
      <div className="row between">
        <b>{PROVIDER_FULL[p]}</b>
        <span className="row" style={{ gap: 6 }}>
          <Badge tone={tone}>{label}</Badge>
          {row.configured && <Menu label={`${PROVIDER_NAME[p]} 키 메뉴`} items={[{ label: '키 지우기…', danger: true, onSelect: () => setDlg('delete') }]} />}
        </span>
      </div>
      <div className="row" style={{ gap: 6 }}>
        <input className="mono grow" type="password" readOnly value={row.last4 ? `${KEY_HINT[p]}••••••••••••${row.last4}` : ''} placeholder="API 키 붙여넣기" aria-label={`${PROVIDER_NAME[p]} API 키`} onFocus={() => !row.configured && sealReady && setDlg('key')} />
        <button className="btn" disabled={!row.configured || test.busy} onClick={() => void runTest()}>
          {test.busy ? '시험 중…' : '연결 시험'}
        </button>
        <button className="btn primary" disabled={!sealReady} title={sealReady ? undefined : '봉인 키가 없습니다'} onClick={() => setDlg('key')}>
          {row.configured ? '교체' : '등록'}
        </button>
      </div>
      {row.configured ? (
        <span className="muted small">
          끝 4자리 …{row.last4}
          {row.setAt ? ` · ${when(row.setAt)}` : ''}
          {row.setBy ? ` ${row.setBy} 등록` : ''} · 다시 보여 주지 않음
        </span>
      ) : (
        <span className="muted small">키가 없으면 이 공급자의 모델 칸은 비활성입니다.</span>
      )}
      {row.error && <div className="note er small">연결 실패: {row.error}</div>}
      {test.ok !== undefined && <div className="note ok small">✓ 키로 모델 카탈로그 읽기 · {test.ok}개</div>}
      {test.error !== undefined && <div className="note er small">! {PROVIDER_NAME[p]} 연결 실패: {keyError(test.error)}</div>}
      {row.configured && (
        <div className="strip">
          <span>모델 카탈로그</span>
          <b>{row.modelsTotal && row.modelsTotal > row.models ? `${row.models}개 (전체 ${row.modelsTotal}개 중 대화용)` : `${row.models}개`}</b>
          {row.catalogAt && <span className="muted">{fmtTime(row.catalogAt)} 받음</span>}
          <span className="grow" />
          <button className="linkish" onClick={() => void refresh()}>
            목록 새로고침
          </button>
        </div>
      )}
      {dlg === 'key' && <KeyDialog p={p} replace={row.configured} onClose={() => setDlg('')} onDone={onChanged} />}
      {dlg === 'delete' && <DeleteKeyDialog p={p} roles={users} onClose={() => setDlg('')} onDone={onChanged} />}
    </div>
  );
}

function keyError(e: unknown): string {
  if (e instanceof ApiError && e.code === 'key-rejected') {
    const detail = (e.body as { detail?: string }).detail;
    return `${e.status} · ${KEY_ERR[detail ?? ''] ?? e.body.message ?? '키를 받지 않았습니다'}`;
  }
  if (e instanceof ApiError && e.code === 'seal-unavailable') return '봉인 키가 없어 저장하지 못했습니다';
  return errorText(e).message;
}

function KeyDialog({ p, replace, onClose, onDone }: { p: AiProvider; replace: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await putAiKey(p, key.trim());
      setKey('');
      toast(`${PROVIDER_NAME[p]} 키를 ${replace ? '바꿨' : '등록했'}습니다 · 끝 4자리 …${r.last4 ?? ''}`);
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
      title={`${PROVIDER_NAME[p]} API 키 ${replace ? '교체' : '등록'}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={busy || !key.trim()} onClick={() => void go()}>
            {busy ? '시험하는 중…' : `시험하고 ${replace ? '교체' : '등록'}`}
          </button>
        </>
      }
    >
      <Field label="새 API 키" hint="저장 후 끝 4자리만 보입니다. 키는 봉인 파일에 두고 웹 데이터·브라우저에 남기지 않습니다">
        <input className="mono" type="password" autoComplete="off" spellCheck={false} placeholder={`${KEY_HINT[p]}…`} value={key} onChange={(e) => setKey(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && key.trim() && !busy && void go()} />
      </Field>
      <label className="check">
        <input type="checkbox" checked disabled />
        저장 전에 연결 시험 <span className="muted small">(시험에 실패하면 저장하지 않습니다)</span>
      </label>
      {error !== undefined && <div className="note er small">! 연결 실패: {keyError(error)}</div>}
    </Dialog>
  );
}

function DeleteKeyDialog({ p, roles, onClose, onDone }: { p: AiProvider; roles: AiRole[]; onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const name = PROVIDER_NAME[p];
  const go = async () => {
    setBusy(true);
    try {
      await deleteAiKey(p);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Dialog
      danger
      title={`${name} 키를 지울까요?`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger solid" disabled={busy || typed !== name} onClick={() => void go()}>
            지우기
          </button>
        </>
      }
    >
      <p style={{ margin: 0 }}>{roles.length ? `이 공급자를 메인으로 쓰는 역할 ${roles.length}개(${roles.map((r) => ROLE_SHORT[r]).join('·')})가 예비 모델로 넘어갑니다.` : '이 공급자를 메인으로 쓰는 역할은 없습니다.'}</p>
      <Field label={`확인하려면 ${name} ${eulReul(name)} 입력하세요`}>
        <input value={typed} onChange={(e) => setTyped(e.target.value.trim())} />
      </Field>
      {error !== undefined && <ErrorBand error={error} what="키를 지우지 못했습니다" />}
    </Dialog>
  );
}

// ── 역할별 모델 · 데이터 보내기 범위 (한 번에 저장) ──
type Draft = { roles: Record<AiRole, AiRoleConf>; data?: AiData; limits: AiLimits };
const strip = (c: AiRoleConf): AiRoleConf => ({ main: c.main, fallback: c.fallback, effort: c.effort, thinking: c.thinking, maxOutputTokens: c.maxOutputTokens, stream: c.stream });

function Editor({ d, onSaved }: { d: AiSettings; onSaved: () => void }) {
  const toast = useToast();
  const init: Draft = useMemo(() => ({ roles: Object.fromEntries(AI_ROLES.map((r) => [r, strip(d.roles[r] ?? { main: null, fallback: null })])) as Record<AiRole, AiRoleConf>, data: d.data, limits: d.limits }), [d]);
  const [draft, setDraft] = useState<Draft>(init);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const cat = useCatalogs(d);
  const rolesDirty = JSON.stringify(draft.roles) !== JSON.stringify(init.roles);
  const dataDirty = JSON.stringify([draft.data, draft.limits]) !== JSON.stringify([init.data, init.limits]);
  const un = useUnsaved({ dirty: (rolesDirty || dataDirty) && !busy, what: 'AI 설정', noDraft: '이 화면은 초안을 남기지 않습니다. 나가면 바꾼 값이 사라집니다.' });
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await putAiSettings({ revision: d.revision, roles: draft.roles, ...(draft.data ? { data: draft.data } : {}), limits: draft.limits });
      toast('AI 설정을 저장했습니다.');
      onSaved();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  const setRole = (r: AiRole, c: AiRoleConf) => setDraft({ ...draft, roles: { ...draft.roles, [r]: c } });
  const footer = (show: boolean) =>
    show && (
      <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
        <button className="btn" disabled={busy} onClick={() => setDraft(init)}>
          되돌리기
        </button>
        <button className="btn primary" disabled={busy} onClick={() => void save()}>
          {busy ? '저장 중…' : '변경 저장'}
        </button>
      </div>
    );
  const err = error !== undefined && <SaveError error={error} />;
  return (
    <>
      {un.guard}
      <Card title={<div className="row" style={{ gap: 8 }}><h2>역할별 모델</h2>{un.badge}</div>}>
        <div className="gtbl">
          <div className="gr th roles">
            <span>역할</span>
            <span>메인 (공급자 · 모델)</span>
            <span>예비 (공급자 · 모델)</span>
            <span>설정</span>
          </div>
          {AI_ROLES.map((r) => (
            <RoleRow key={r} role={r} c={draft.roles[r]} orig={d.roles[r]} cat={cat} providers={d.providers} diagMain={draft.roles.diagnosis.main?.provider} onChange={(c) => setRole(r, c)} />
          ))}
        </div>
        <div className="rules">
          <span>
            · 모델 칸은 직접 입력하지 않고, 고른 공급자의 <b>모델 목록</b>에서 고릅니다. 목록은 키를 연결 시험할 때 공급자의 모델 카탈로그 API(Claude <span className="mono">GET /v1/models</span>, OpenAI <span className="mono">GET /v1/models</span>)를 읽어 채웁니다.
          </span>
          <span>· 이름(표시 이름)과 모델 ID를 함께 보이고, 최신순으로 정렬합니다. OpenAI 목록의 임베딩·음성·이미지·검열 전용 모델은 숨기고 ‘모두 보기’로만 엽니다.</span>
          <span>· 공급자의 키가 없으면 모델 칸은 비활성이며 ‘먼저 키를 연결하세요’를 보여 줍니다.</span>
          <span>
            · 고른 모델이 나중에 목록에서 사라지면 칸에 <Badge tone="wa">목록에 없음</Badge>을 띄우고, 그 역할은 예비 모델로 돌며 관리자에게 알립니다.
          </span>
        </div>
        <div className="inset rules">
          <b>예비 모델로 넘어가는 때</b>
          <span>· 메인 공급자가 응답하지 않음(시간 초과·5xx) 또는 사용량 제한(429)이 재시도 2회 뒤에도 계속될 때</span>
          <span>· 메인이 거부(refusal)로 답했을 때, 메인 모델이 목록에서 사라졌을 때, 메인 공급자 키가 무효일 때</span>
          <span>· 넘어가면 그 대화·사건이 끝날 때까지 예비로 계속합니다(중간에 다시 바꾸면 캐시가 깨짐). 15분 뒤 새 대화부터 메인을 다시 시도합니다.</span>
          <span>· 예비로 처리된 답에는 ‘예비 모델’ 표시가 붙고 감사 기록에 남습니다. 예비도 실패하면 코디네이터는 오류를, 장애 자동 대응은 승인 요청(자동 실행 안 함)을 냅니다.</span>
          <span className="muted">메인과 예비는 다른 공급자로 두기를 권합니다. 같은 공급자면 공급자 장애 때 둘 다 멈춥니다.</span>
        </div>
        {rolesDirty && err}
        {footer(rolesDirty)}
      </Card>
      <div className="grid-2">
        <CacheCard />
        <DataCard draft={draft} setDraft={setDraft} />
      </div>
      {dataDirty && !rolesDirty && (
        <Card>
          {err}
          {footer(true)}
        </Card>
      )}
    </>
  );
}

function SaveError({ error }: { error: unknown }) {
  if (error instanceof ApiError && error.code === 'revision-changed') return <div className="note wa small">그사이 다른 사람이 AI 설정을 바꿨습니다. 새로고침한 뒤 다시 고치세요.</div>;
  if (error instanceof ApiError && error.code === 'model-not-in-catalog') return <div className="note er small">목록에 없는 모델이 있습니다({error.body.message}). 키와 모델 목록을 확인하세요.</div>;
  if (error instanceof ApiError && error.code === 'unlimited-needs-compaction') return <div className="note er small">무제한은 자동 compaction이 켜져 있을 때만 고를 수 있습니다.</div>;
  return <ErrorBand error={error} what="AI 설정을 저장하지 못했습니다" />;
}

type Catalogs = Partial<Record<AiProvider, { all: AiModel[]; at?: string; error?: unknown }>>;
function useCatalogs(d: AiSettings): Catalogs {
  const [c, setC] = useState<Catalogs>({});
  const sig = d.providers.map((p) => `${p.provider}:${p.configured}:${p.catalogAt ?? ''}`).join(',');
  useEffect(() => {
    const ac = new AbortController();
    for (const p of d.providers.filter((x) => x.configured))
      aiModels(p.provider, true, ac.signal)
        .then((r) => setC((o) => ({ ...o, [p.provider]: { all: r.items, at: r.fetchedAt } })))
        .catch((e) => !ac.signal.aborted && setC((o) => ({ ...o, [p.provider]: { all: [], error: e } })));
    return () => ac.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig]);
  return c;
}

const year = (iso: string) => `${new Date(iso).getFullYear()}년`;
const modelName = (m: AiModel | undefined, id: string) => m?.displayName ?? m?.id ?? id;

function RoleRow({ role, c, orig, cat, providers, diagMain, onChange }: { role: AiRole; c: AiRoleConf; orig?: AiRoleConf; cat: Catalogs; providers: AiProviderRow[]; diagMain?: AiProvider; onChange: (c: AiRoleConf) => void }) {
  return (
    <div className="gr roles">
      <span>{ROLE_NAME[role]}</span>
      <ModelCell which="메인" value={c.main} missing={!!orig?.mainMissing && JSON.stringify(orig.main) === JSON.stringify(c.main)} cat={cat} providers={providers} onChange={(v) => onChange({ ...c, main: v })} />
      <ModelCell which="예비" value={c.fallback} missing={!!orig?.fallbackMissing && JSON.stringify(orig.fallback) === JSON.stringify(c.fallback)} cat={cat} providers={providers} onChange={(v) => onChange({ ...c, fallback: v })} />
      <span className="muted small">
        <RoleOptions role={role} c={c} onChange={onChange} />
        {role === 'impact' && (
          <>
            <br />
            구조화 출력
            {c.fallback && c.fallback.provider === diagMain && (
              <>
                <br />
                <span className="wa-text">예비로 넘어가면 진단과 같은 공급자가 될 수 있음 · 사건에 표시</span>
              </>
            )}
          </>
        )}
        {role === 'simple' && (
          <>
            <br />
            빠름 · 짧은 출력
            <br />
            <span className="wa-text">제목·요약·분류만. 작업 제안·영향 판단은 못 함</span>
          </>
        )}
      </span>
    </div>
  );
}

function RoleOptions({ role, c, onChange }: { role: AiRole; c: AiRoleConf; onChange: (c: AiRoleConf) => void }) {
  const summary = [c.effort && `노력 ${EFFORT[c.effort]}`, c.thinking && `생각 ${THINK[c.thinking]}`].filter(Boolean).join(' · ') || '설정';
  if (c.effort === undefined && c.thinking === undefined && c.maxOutputTokens === undefined && c.stream === undefined) return <span>—</span>;
  return (
    <Popover button={summary} className="textbtn" align="right" label={`${ROLE_SHORT[role]} 설정`} width={260}>
      {() => (
        <div className="col" style={{ gap: 8, padding: 6 }}>
          <b style={{ fontSize: 13 }}>{ROLE_SHORT[role]} 설정</b>
          {c.effort !== undefined && (
            <Field label="추론 강도">
              <select value={c.effort} onChange={(e) => onChange({ ...c, effort: e.target.value as AiRoleConf['effort'] })}>
                {Object.entries(EFFORT).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </select>
            </Field>
          )}
          {c.thinking !== undefined && (
            <Field label="확장 사고">
              <select value={c.thinking} onChange={(e) => onChange({ ...c, thinking: e.target.value as AiRoleConf['thinking'] })}>
                <option value="auto">자동 (adaptive)</option>
                <option value="off">끔</option>
              </select>
            </Field>
          )}
          {c.maxOutputTokens !== undefined && (
            <Field label="최대 출력 토큰">
              <input type="number" min={1} value={c.maxOutputTokens} onChange={(e) => onChange({ ...c, maxOutputTokens: Math.max(1, Number(e.target.value) || 1) })} />
            </Field>
          )}
          {c.stream !== undefined && (
            <label className="check">
              <input type="checkbox" checked={c.stream} onChange={(e) => onChange({ ...c, stream: e.target.checked })} />
              스트리밍
            </label>
          )}
        </div>
      )}
    </Popover>
  );
}

function ModelCell({ which, value, missing, cat, providers, onChange }: { which: string; value: AiRoleConf['main']; missing: boolean; cat: Catalogs; providers: AiProviderRow[]; onChange: (v: AiRoleConf['main']) => void }) {
  const p = value?.provider ?? 'claude';
  const configured = (x: AiProvider) => !!providers.find((r) => r.provider === x)?.configured;
  const list = cat[p]?.all ?? [];
  const cur = list.find((m) => m.id === value?.model);
  const pickFirst = (np: AiProvider) => {
    const first = (cat[np]?.all ?? []).find((m) => !m.hidden);
    onChange(first ? { provider: np, model: first.id } : null);
  };
  return (
    <div className="row" style={{ gap: 6, minWidth: 0, flexWrap: 'nowrap' }}>
      <select aria-label={`${which} 공급자`} style={{ width: 100, height: 32, fontSize: 13, flex: 'none' }} value={p} onChange={(e) => pickFirst(e.target.value as AiProvider)}>
        {AI_PROVIDERS.map((x) => (
          <option key={x} value={x} disabled={!configured(x)}>
            {PROVIDER_NAME[x]}
            {configured(x) ? '' : ' (키 없음)'}
          </option>
        ))}
      </select>
      {!configured(p) ? (
        <span className="picker off">먼저 키를 연결하세요</span>
      ) : (
        <Popover
          className={`picker${missing ? ' bad' : ''}`}
          label={`${which} 모델`}
          width={440}
          button={
            <>
              <span className="el">
                {value ? (
                  <>
                    {modelName(cur, value.model)} <span className="mono muted" style={{ fontSize: 11 }}>{value.model}</span>
                  </>
                ) : (
                  <span className="muted">고르기</span>
                )}
              </span>
              {missing ? <Badge tone="wa">목록에 없음</Badge> : <span className="muted">▾</span>}
            </>
          }
        >
          {(close) => <ModelList p={p} list={list} at={cat[p]?.at} value={value?.model} onPick={(id) => (onChange({ provider: p, model: id }), close())} />}
        </Popover>
      )}
    </div>
  );
}

function ModelList({ p, list, at, value, onPick }: { p: AiProvider; list: AiModel[]; at?: string; value?: string; onPick: (id: string) => void }) {
  const [find, setFind] = useState('');
  const [all, setAll] = useState(false);
  const visible = list.filter((m) => !m.hidden);
  const hidden = list.length - visible.length;
  const shown = (all ? list : visible).filter((m) => !find || `${m.displayName ?? ''} ${m.id}`.toLowerCase().includes(find.toLowerCase()));
  return (
    <>
      <div className="grp">
        {PROVIDER_NAME[p]} 모델 목록 · 카탈로그에서 {visible.length}개{at ? ` · ${fmtTime(at)} 받음` : ''}
      </div>
      <div style={{ padding: '4px 6px' }}>
        <input placeholder="모델 찾기" value={find} autoFocus onChange={(e) => setFind(e.target.value)} style={{ height: 30, fontSize: 13, width: '100%' }} />
      </div>
      <div style={{ maxHeight: 260, overflowY: 'auto' }}>
        {shown.map((m) => (
          <button key={m.id} type="button" className={`pick${m.id === value ? ' on' : ''}`} onClick={() => onPick(m.id)}>
            <span className="tick">{m.id === value ? '✓' : ''}</span>
            <span>{m.displayName ?? m.id}</span>
            {m.displayName && <span className="mono muted" style={{ fontSize: 11 }}>{m.id}</span>}
            <span className="tag-r">{m.hidden ? '대화용 아님' : year(m.createdAt)}</span>
          </button>
        ))}
        {!shown.length && <div className="muted small" style={{ padding: '6px 10px' }}>맞는 모델이 없습니다.</div>}
      </div>
      <hr />
      <div className="muted small" style={{ padding: '4px 10px', whiteSpace: 'normal' }}>
        목록에 없는 모델은 고를 수 없습니다. 새로고침은 API 키 카드에서.
        {hidden > 0 && (
          <>
            {' '}
            <button className="linkish" onClick={() => setAll(!all)}>
              {all ? '대화용만 보기' : `모두 보기 (${list.length}개)`}
            </button>
          </>
        )}
      </div>
    </>
  );
}

// ── 프롬프트 캐시 ──
const mtok = (n: number) => `${n >= 1e6 ? (n / 1e6).toFixed(1) : String(Number((n / 1e6).toFixed(2)))}M`;
function CacheCard() {
  const q = usePoll((s) => aiUsage(7, s), []);
  return (
    <Card title={<div className="row between" style={{ width: '100%' }}><h2>프롬프트 캐시 (최근 7일)</h2><span className="muted small">토큰</span></div>}>
      <Load q={q} rows={4}>
        {(u) => (
          <div className="gtbl">
            <div className="gr th cache">
              <span>역할</span>
              <span>캐시 적중</span>
              <span>캐시 읽기</span>
              <span>캐시 쓰기</span>
              <span>캐시 위치</span>
            </div>
            {AI_ROLES.map((r) => {
              const xs = u.items.filter((x) => x.role === r);
              const read = xs.reduce((a, x) => a + x.cacheReadTokens, 0);
              const write = xs.reduce((a, x) => a + x.cacheWriteTokens, 0);
              const hit = u.roles[r]?.hitRate;
              return (
                <div key={r} className="gr cache">
                  <span>{ROLE_SHORT[r]}</span>
                  <span>
                    {hit === undefined ? (
                      <span className="muted">—</span>
                    ) : (
                      <span title={hit < 0.7 ? '적중이 70% 아래입니다. 시스템 프롬프트가 자주 바뀌는지 확인하세요.' : undefined}>
                        <Badge tone={hit >= 0.8 ? 'ok' : hit >= 0.7 ? 'wa' : 'er'}>{Math.round(hit * 100)}%</Badge>
                      </span>
                    )}
                  </span>
                  <span className="mono">{xs.length ? mtok(read) : '—'}</span>
                  <span className="mono">{xs.length ? mtok(write) : '—'}</span>
                  <span className="muted small">{CACHE_AT[r]}</span>
                </div>
              );
            })}
          </div>
        )}
      </Load>
      <span className="muted small">고정된 도구 목록·시스템 프롬프트를 앞에 두고, 화면 맥락은 대화 뒤에 덧붙여 캐시를 지킵니다. 적중이 갑자기 떨어지면 앞부분이 바뀐 것이니 배포 이력을 확인하세요.</span>
    </Card>
  );
}

// ── 데이터 보내기 범위 ──
const TOOL_CALLS = [10, 20, 40, 80, 150];
const CONV_TOKENS = [250_000, 500_000, 1_000_000, 2_000_000];
const num = (n: number) => n.toLocaleString('ko-KR');

function DataCard({ draft, setDraft }: { draft: Draft; setDraft: (d: Draft) => void }) {
  const [dlg, setDlg] = useState<'' | 'tenants' | 'audit'>('');
  const data = draft.data;
  const l = draft.limits;
  const setData = (x: Partial<AiData>) => data && setDraft({ ...draft, data: { ...data, ...x } });
  const setLimits = (x: Partial<AiLimits>) => setDraft({ ...draft, limits: { ...l, ...x } });
  const setCompaction = (enabled: boolean) =>
    setLimits({
      compaction: { ...l.compaction, enabled },
      // 끄면 무제한은 기본값으로 돌아간다
      ...(enabled ? {} : { toolCallsPerConversation: l.toolCallsPerConversation || 40, tokensPerConversation: l.tokensPerConversation || 1_000_000 }),
    });
  const audit = usePoll((s) => aiAudit(1, undefined, s), []);
  const opt = (v: number, label: string, disabled = false) => (
    <option key={v} value={v} disabled={disabled}>
      {label}
    </option>
  );
  return (
    <Card title="데이터 보내기 범위">
      {data ? (
        <>
          <label className="check">
            <input type="checkbox" checked={data.maskSecretLikeEnv} onChange={(e) => setData({ maskSecretLikeEnv: e.target.checked })} />
            환경 변수 값 가리기: 비밀 값으로 마킹한 변수 + 이름이 비밀처럼 보이는 변수 (PASSWORD·SECRET·TOKEN·KEY)
          </label>
          <label className="check">
            <input type="checkbox" checked={data.logTailLines > 0} onChange={(e) => setData({ logTailLines: e.target.checked ? 200 : 0 })} />
            {data.logTailLines > 0 ? `로그는 뒤에서 ${data.logTailLines}줄까지만` : '로그는 보내지 않음'}
          </label>
        </>
      ) : (
        <span className="muted small">환경 변수 가리기 · 로그 줄 수: 웹 기능 준비 중</span>
      )}
      <label className="check">
        <input type="checkbox" checked disabled />
        비밀값 보관함 값은 보내지 않음 (끌 수 없음)
      </label>
      <dl className="kv2" style={{ gridTemplateColumns: '200px minmax(0, 1fr)' }}>
        <dt>외부 AI로 보내지 않는 작업 공간</dt>
        <dd>
          {data ? (
            <>
              {data.excludeTenants.length ? data.excludeTenants.join(', ') : <span className="muted">없음</span>} ·{' '}
              <button className="linkish" onClick={() => setDlg('tenants')}>
                바꾸기…
              </button>
            </>
          ) : (
            <span className="muted">웹 기능 준비 중</span>
          )}
        </dd>
        <dt>사용자별 하루 한도</dt>
        <dd className="row" style={{ gap: 6 }}>
          <input inputMode="numeric" value={l.dailyTokensPerUser ? `${num(l.dailyTokensPerUser)} 토큰` : ''} placeholder="무제한" onChange={(e) => setLimits({ dailyTokensPerUser: Number(e.target.value.replace(/\D/g, '')) || 0 })} style={{ height: 30, fontSize: 13, width: 170 }} aria-label="사용자별 하루 토큰 한도" />
          <span className="muted small">넘으면 그 사용자의 코디네이터만 다음 날까지 멈춥니다. 장애 대응은 한도와 따로.</span>
        </dd>
        <dt>자동 compaction</dt>
        <dd className="col" style={{ gap: 6 }}>
          <label className="check">
            <input type="checkbox" checked={l.compaction.enabled} onChange={(e) => setCompaction(e.target.checked)} />
            대화가 길어지면 앞부분을 요약해 이어 가기
          </label>
          {l.compaction.enabled && (
            <span className="row muted small" style={{ gap: 8 }}>
              입력이 <input inputMode="numeric" value={num(l.compaction.triggerTokens)} onChange={(e) => setLimits({ compaction: { ...l.compaction, triggerTokens: Number(e.target.value.replace(/\D/g, '')) || 0 } })} style={{ height: 28, width: 100, fontSize: 12 }} aria-label="요약 시작 토큰" /> 토큰을 넘으면 요약
            </span>
          )}
        </dd>
        <dt>대화당 도구 호출 상한</dt>
        <dd className="col" style={{ gap: 4 }}>
          <select style={{ height: 30, fontSize: 13, width: 200 }} value={l.toolCallsPerConversation} onChange={(e) => setLimits({ toolCallsPerConversation: Number(e.target.value) })}>
            {opt(0, '무제한', !l.compaction.enabled)}
            {[...new Set([...TOOL_CALLS, l.toolCallsPerConversation].filter(Boolean))].sort((a, b) => a - b).map((v) => opt(v, `${v}`))}
          </select>
          <span className="muted small">무제한은 자동 compaction이 켜져 있을 때만 고를 수 있습니다. 끄면 40으로 돌아갑니다. 하루 토큰 한도는 그대로 적용됩니다.</span>
        </dd>
        <dt>대화당 토큰 상한</dt>
        <dd>
          <select style={{ height: 30, fontSize: 13, width: 200 }} value={l.tokensPerConversation} onChange={(e) => setLimits({ tokensPerConversation: Number(e.target.value) })}>
            {opt(0, '무제한 (하루 한도만)', !l.compaction.enabled)}
            {[...new Set([...CONV_TOKENS, l.tokensPerConversation].filter(Boolean))].sort((a, b) => a - b).map((v) => opt(v, num(v)))}
          </select>
        </dd>
        <dt>감사 기록</dt>
        <dd>
          승인·거절·모델·토큰 기록{audit.data?.total !== undefined ? ` ${num(audit.data.total)}건` : ''} ·{' '}
          <button className="linkish" onClick={() => setDlg('audit')}>
            기간 골라 지우기…
          </button>
        </dd>
      </dl>
      {dlg === 'tenants' && data && <ExcludeDialog value={data.excludeTenants} onClose={() => setDlg('')} onSave={(v) => (setData({ excludeTenants: v }), setDlg(''))} />}
      {dlg === 'audit' && <AuditDeleteDialog total={audit.data?.total} onClose={() => setDlg('')} onDone={audit.refresh} />}
    </Card>
  );
}

function ExcludeDialog({ value, onClose, onSave }: { value: string[]; onClose: () => void; onSave: (v: string[]) => void }) {
  const q = usePoll((s) => tenantList(s), []);
  const [sel, setSel] = useState(new Set(value));
  return (
    <Dialog
      title="외부 AI 제외 작업 공간"
      width={420}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" onClick={() => onSave([...sel].sort())}>
            저장
          </button>
        </>
      }
    >
      <Load q={q} rows={3}>
        {(ts) => (
          <div className="col" style={{ gap: 6 }}>
            {[...new Set([...ts.map((t) => t.id), ...value])].sort().map((t) => (
              <label key={t} className="check">
                <input
                  type="checkbox"
                  checked={sel.has(t)}
                  onChange={(e) => {
                    const n = new Set(sel);
                    if (e.target.checked) n.add(t);
                    else n.delete(t);
                    setSel(n);
                  }}
                />
                {t}
              </label>
            ))}
          </div>
        )}
      </Load>
      <span className="muted small">제외한 작업 공간의 화면에서는 코디네이터가 맥락을 받지 않고 장애 진단도 하지 않습니다. 아래 ‘변경 저장’을 눌러야 반영됩니다.</span>
    </Dialog>
  );
}

function AuditDeleteDialog({ total, onClose, onDone }: { total?: number; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [date, setDate] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    try {
      const r = await deleteAiAudit(new Date(`${date}T00:00:00`).toISOString());
      toast(`감사 기록 ${num(r.deleted)}건을 지웠습니다.`);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Dialog
      danger
      title="감사 기록 지우기"
      width={420}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger solid" disabled={!date || busy} onClick={() => void go()}>
            지우기
          </button>
        </>
      }
    >
      <Field label="이 날짜 전의 기록을 지웁니다" hint={total !== undefined ? `지금 ${num(total)}건` : undefined}>
        <input type="date" value={date} max={new Date().toISOString().slice(0, 10)} onChange={(e) => setDate(e.target.value)} />
      </Field>
      <span className="muted small">승인·거절·모델·토큰 기록만 지웁니다. 대화와 작업 기록은 그대로입니다. 되돌릴 수 없습니다.</span>
      {error !== undefined && <ErrorBand error={error} what="지우지 못했습니다" />}
    </Dialog>
  );
}

