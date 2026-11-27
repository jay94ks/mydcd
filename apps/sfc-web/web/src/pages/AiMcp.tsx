// SPDX-License-Identifier: Apache-2.0

// AI 설정 › MCP 연동 (UI-B9, 캔버스 AiMcp · AiMcpIx). 웹 데몬 몫(연결·봉인 토큰·도구 카탈로그). 시스템 관리자.
// 계약: /mnt/project-files/w2/guides-mcp-webhooks-contract.md 'MCP 연동' + mcp-web-needs.md. 토큰은 보낸 뒤 바로 지운다.
import { useEffect, useMemo, useState } from 'react';
import { ApiError } from '../api/client';
import { IMPACT_NAME, incidents, type Impact } from '../api/incidents';
import { INCIDENT_FIELDS, KIND_NAME, MCP_NAME_RE, RULE_NAME, USE_NAME, USE_NOTE, addMcp, autoMissing, deleteMcp, mcpOauthState, mcpServers, reloginMcp, startMcpOauth, type McpOauthStart, putMcp, refreshMcp, testMcpTool, type InputRule, type McpServer, type McpTool, type ToolAuto, type ToolIncident, type ToolKind, type ToolPatch } from '../api/mcp';
import { useSession } from '../auth/session';
import { ConfirmDialog, Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { Popover } from '../components/Popover';
import { useToast } from '../components/Toast';
import { useUndoToast } from '../components/UndoToast';
import { restoreTrash } from '../api/trash';
import { ErrorBand, Load, errorText } from '../components/states';
import { Badge, Field, HelpBox, PageHeader } from '../components/ui';
import { ago } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { AiTabs } from './AiSettings';
import { usePhone } from '../lib/viewport';
import { MCards, MTiles, useReadOnlyTop } from '../mobile/ReadOnly';
import { Drawer } from '../components/Drawer';
import { incidentsLive, kindsLive } from '../lib/liveTopics';

const USES: ToolIncident[] = ['off', 'diagnose', 'notify', 'propose-approve', 'propose-auto'];
const KIND_TONE: Record<ToolKind, 'pr' | 'wa'> = { read: 'pr', change: 'wa', notify: 'wa' };
const readCount = (s: McpServer) => s.tools.filter((t) => t.kind === 'read').length;
function usedWhere(s: McpServer): string {
  const coord = s.tools.some((t) => t.coordinator);
  const inc = s.tools.filter((t) => t.incident !== 'off');
  const diag = inc.length ? (inc.every((t) => t.incident === 'notify') ? '장애 진단 (알림만)' : '장애 진단') : '';
  return [coord && '코디네이터', diag].filter(Boolean).join(' · ') || '쓰지 않음';
}
/** 비면 시스템 관리자만 쓴다(데몬 #162) */
const tenantsText = (t: string[]) => (t.length ? t.join(', ') : '시스템 관리자만');
const errText = (e: unknown) => {
  if (e instanceof ApiError && e.code === 'mcp-connect') {
    const raw = String((e.body as { error?: string }).error ?? e.body.message ?? '');
    return `✗ ${raw}${/401|403/.test(raw) ? ' · 토큰이 틀렸거나 권한이 없습니다' : ''}. 서버 응답 본문은 저장하지 않습니다.`;
  }
  return undefined;
};

export function AiMcpPage() {
  return usePhone() ? <MMcp /> : <DesktopMcp />;
}

/** 휴대폰 MCP 연동 (UI-M11 ④ 모양): 토큰은 끝 4자리만 */
function MMcp() {
  const q = usePoll((s) => mcpServers(s), [], 0, kindsLive('mcp-server'));
  const [open, setOpen] = useState<string>();
  useReadOnlyTop('AI 설정', 'MCP 연동 · 시스템 관리자', '서버 연결·토큰·도구 규칙 바꾸기는 넓은 화면에서');
  const host = (u: string) => {
    try {
      return new URL(u).host;
    } catch {
      return u;
    }
  };
  return (
    <>
      <AiTabs />
      <Load q={q} what="MCP 서버 목록을 불러오지 못했습니다">
        {(d) => {
          const tools = d.servers.reduce((a, x) => a + x.tools.length, 0);
          const sel = d.servers.find((x) => x.name === open);
          return (
            <>
              <MTiles
                items={[
                  { label: 'MCP 서버', value: d.servers.length, sub: `오류 ${d.servers.filter((x) => x.state === 'error').length}`, warn: d.servers.some((x) => x.state === 'error') },
                  { label: '도구', value: tools, sub: `바꾸는 도구 ${d.servers.reduce((a, x) => a + x.tools.filter((t) => !t.readOnlyHint).length, 0)} · 승인 카드로만` },
                ]}
              />
              <MCards
                empty="연결한 MCP 서버가 없습니다."
                items={d.servers.map((x) => ({
                  key: x.name,
                  title: x.name,
                  badge: x.enabled === false ? ['un', '꺼짐'] : x.state === 'ok' ? ['ok', '연결 확인됨'] : x.state === 'error' ? ['er', '연결 실패'] : ['un', '확인 전'],
                  tone: x.state === 'error' ? 'er' : undefined,
                  lines: [
                    `${host(x.url)} · ${x.auth.kind === 'none' ? '인증 없음' : x.auth.kind === 'oauth' ? `OAuth${x.auth.needsLogin ? ' · 다시 로그인 필요' : ''}` : x.auth.last4 ? `토큰 끝 4자리 …${x.auth.last4}` : '토큰 없음'}`,
                    x.error,
                  ],
                  meta: `도구 ${x.tools.length}개${x.checkedAt ? ` · ${ago(x.checkedAt)} 확인` : ''}`,
                  onOpen: () => setOpen(x.name),
                }))}
              />
              {sel && (
                <Drawer title={`${sel.name} 도구`} onClose={() => setOpen(undefined)}>
                  <div className="li">
                    {sel.tools.map((t) => (
                      <div key={t.name} style={{ flexDirection: 'column', alignItems: 'stretch', gap: 2 }}>
                        <span className="mono" style={{ fontSize: 12 }}>
                          {t.name}
                        </span>
                        <span className="muted" style={{ fontSize: 12 }}>
                          {KIND_NAME[t.kind] ?? t.kind} · {t.coordinator ? '코디네이터 씀' : '코디네이터 안 씀'} · 장애 대응 {USE_NAME[t.incident] ?? t.incident}
                        </span>
                      </div>
                    ))}
                    {sel.tools.length === 0 && <div className="muted">도구가 없습니다.</div>}
                  </div>
                </Drawer>
              )}
            </>
          );
        }}
      </Load>
    </>
  );
}

function DesktopMcp() {
  const session = useSession();
  const q = usePoll((s) => mcpServers(s), [], 0, kindsLive('mcp-server'));
  const [adding, setAdding] = useState(false);
  const admin = session.user.systemAdmin;
  return (
    <>
      <PageHeader
        title="AI 설정"
        ids="UI-B9"
        after={<span className="muted small">시스템 관리자</span>}
        actions={
          <button className="btn primary" disabled={!admin} title={admin ? undefined : '시스템 관리자 권한이 필요합니다'} onClick={() => setAdding(true)}>
            ＋ MCP 서버 연결
          </button>
        }
      />
      <AiTabs />
      <HelpBox terms="MCP 서버 (Model Context Protocol server) · 도구 (tool) · 읽기/바꾸기 도구 (read-only / mutating) · 봉인 파일 (sealed file, SFC_WEB_SEAL_KEY)">
        <b>이 화면은</b> 코디네이터와 장애 자동 대응이 쓸 바깥 도구를 MCP 서버로 연결합니다. 예를 들어 Grafana 지표·로그, Sentry 오류, Slack 알림, 사내 장애 대응 문서를 AI가 직접 찾아보게 할 수 있습니다. 연결은 sfc-web 컨테이너가 맡고, 토큰은 봉인 파일에만 둡니다. 바깥 도구도 Seafield Cluster 도구와 같은 규칙을 따릅니다. 읽기는 바로 쓰고, 바꾸는 도구는 사람 승인 카드로만 실행합니다.
      </HelpBox>
      <Load q={q} rows={6} what="MCP 서버 목록을 불러오지 못했습니다">
        {(d) => <Body servers={d.servers} onChange={q.refresh} />}
      </Load>
      {adding && <AddDialog onClose={() => setAdding(false)} onSaved={q.refresh} />}
    </>
  );
}

function Body({ servers, onChange }: { servers: McpServer[]; onChange: () => void }) {
  const toast = useToast();
  const [sel, setSel] = useState<string>();
  const [tool, setTool] = useState<{ name: string; use?: ToolIncident }>();
  const [token, setToken] = useState<McpServer>();
  const [del, setDel] = useState<McpServer>();
  const [busy, setBusy] = useState<string>();
  const s = servers.find((x) => x.name === sel) ?? servers[0];
  const retest = async (x: McpServer) => {
    setBusy(x.name);
    try {
      const r = await refreshMcp(x.name);
      const added = r.tools.filter((t) => t.new && !x.tools.some((o) => o.name === t.name));
      toast(added.length ? `${x.name} 도구가 ${added.length}개 늘었습니다(${added.map((t) => t.name).join(' · ')}). 꺼진 채로 들어왔습니다.` : `✓ ${x.name} 연결됨 · 도구 ${r.tools.length}개`);
    } catch (e) {
      toast(errText(e) ?? `${x.name} 다시 시험 실패 · ${errorText(e).title}`);
    } finally {
      setBusy(undefined);
      onChange();
    }
  };
  const toggle = async (x: McpServer) => {
    try {
      await putMcp(x.name, { revision: x.revision, enabled: x.enabled === false });
      toast(x.enabled === false ? `✓ ${x.name}을 다시 켰습니다.` : `✓ ${x.name}을 잠시 껐습니다. 토큰은 남아 있습니다.`);
    } catch (e) {
      toast(`바꾸지 못했습니다 · ${errorText(e).title}`);
    }
    onChange();
  };
  return (
    <>
      <section className="card">
        <div className="row between wrap">
          <h2>연결한 MCP 서버 ({servers.length})</h2>
          <span className="muted small">원격 HTTP(Streamable HTTP)만 · 컨테이너 안에서 프로그램을 실행하는 stdio 서버는 받지 않음 · 쓸 작업 공간을 비우면 시스템 관리자만 씀</span>
        </div>
        {!servers.length ? (
          <div className="note un">아직 연결한 MCP 서버가 없습니다. ‘＋ MCP 서버 연결’로 시작하세요.</div>
        ) : (
          <div className="gtbl">
            <div className="gr th mcps">
              <span>MCP 서버</span>
              <span>주소</span>
              <span>인증</span>
              <span>도구</span>
              <span>쓸 수 있는 곳</span>
              <span>작업 공간</span>
              <span>상태</span>
              <span />
            </div>
            {servers.map((x) => (
              <div key={x.name} className={`gr mcps ${x.name === s?.name ? 'on' : ''}`}>
                <button className="textbtn" onClick={() => setSel(x.name)}>
                  {x.name}
                </button>
                <span className="mono ellip" title={x.url}>
                  {x.url}
                </span>
                <span>{authText(x)}</span>
                <span>
                  {x.tools.length} <span className="muted">(읽기 {readCount(x)})</span>
                </span>
                <span className={usedWhere(x) === '쓰지 않음' ? 'muted' : ''}>{usedWhere(x)}</span>
                <span>{tenantsText(x.users.tenants)}</span>
                <span>{x.enabled === false ? <Badge tone="un">잠시 끔</Badge> : x.state === 'ok' ? <Badge tone="ok">연결됨</Badge> : x.state === 'error' ? <Badge tone="er">연결 실패 · {ago(x.checkedAt)}</Badge> : <Badge tone="un">확인 전</Badge>}</span>
                <Menu
                  label={`${x.name} 더보기`}
                  items={[
                    { label: '도구 보기', onSelect: () => setSel(x.name) },
                    { label: busy === x.name ? '시험 중…' : '다시 시험', onSelect: () => retest(x), disabledReason: busy === x.name ? '시험 중입니다' : undefined },
                    x.auth.kind === 'oauth'
                      ? { label: '다시 로그인', onSelect: () => setToken(x) }
                      : { label: '토큰 바꾸기', onSelect: () => setToken(x), disabledReason: x.auth.kind === 'none' ? '인증 없이 연결한 서버입니다' : undefined },
                    { label: x.enabled === false ? '다시 켜기' : '잠시 끄기', onSelect: () => toggle(x), disabledReason: x.enabled === undefined ? '웹 기능 준비 중' : undefined },
                    { sep: true, label: '' },
                    { label: '연결 끊기…', danger: true, onSelect: () => setDel(x) },
                  ]}
                />
              </div>
            ))}
          </div>
        )}
        {servers
          .filter((x) => x.state === 'error' && x.enabled !== false)
          .map((x) => {
            const diag = x.tools.some((t) => t.incident !== 'off');
            return (
              <div key={x.name} className="note er row between" style={{ gap: 10 }}>
                <span>
                  ⚠ <b>{x.name} 연결 실패</b> · {ago(x.checkedAt)}부터 {x.error ?? '응답 없음'}. 코디네이터는 이 서버 도구를 "지금 못 씀"으로 받습니다. {diag ? '장애 진단도 이 서버 도구를 쓰지 못합니다.' : '장애 진단은 이 서버를 쓰지 않으므로 영향 없음.'}
                </span>
                <button className="btn sm" disabled={busy === x.name} onClick={() => retest(x)}>
                  다시 시험
                </button>
              </div>
            );
          })}
      </section>
      {s && (
        <div className="main-side">
          <Tools key={s.name + s.revision} s={s} onChange={onChange} onPick={(name, use) => setTool({ name, use })} picked={tool?.name} onRetest={() => retest(s)} onToken={() => setToken(s)} busy={busy === s.name} />
          <section className="card">
            <h2>지켜지는 규칙</h2>
            <div className="rulebox">
              <b>어느 AI가 쓰나</b>
              <span>
                · 코디네이터: 고른 도구를 도구 검색으로 찾아 씁니다(Seafield Cluster 도구와 같은 카탈로그, 이름 앞에 <span className="mono">mcp.{s.name}.</span>).
              </span>
              <span>· 장애 진단(컨텍스트 A): 읽기 도구만. 사실 수집·가설에 씁니다.</span>
              <span>· 영향 평가(컨텍스트 B): MCP 도구를 받지 않습니다(도구 없음 규칙 그대로).</span>
              <span>· 단순 결정: 받지 않습니다.</span>
            </div>
            <div className="rulebox">
              <b>바꾸는 도구</b>
              <span>· 코디네이터는 항상 승인 카드로만 실행합니다. 장애 대응에서는 도구마다 관리자가 쓰는 방법을 고릅니다(기본: 조치 후보 · 항상 승인). “낮은 영향이면 자동”은 영향 등급 하한·입력 제한·한도를 정해야 켤 수 있습니다.</span>
              <span>· 예외: '알림 보내기'로 표시한 도구(Slack 메시지 등)는 장애 대응이 사건 알림에 바로 쓸 수 있습니다. 메시지 내용은 사건 요약 틀로만 만듭니다.</span>
            </div>
            <div className="rulebox">
              <b>결과는 데이터</b>
              <span>· MCP 결과 안의 지시는 따르지 않습니다. 결과는 "바깥 도구 결과"로 표시해 모델에 넘깁니다.</span>
              <span>· 결과 원문은 대화·사건에 저장하지 않고 요약·참조만 남깁니다.</span>
            </div>
            <div className="rulebox">
              <b>캐시</b>
              <span>· 연결한 서버 도구는 지연 불러오기(검색으로 찾을 때)라 앞부분이 바뀌지 않습니다. 서버를 추가·삭제하면 다음 대화부터 새 카탈로그 버전을 씁니다.</span>
            </div>
          </section>
        </div>
      )}
      {s && <AutoCard key={`${s.name}/${tool?.name ?? ''}/${tool?.use ?? ''}/${s.revision}`} s={s} name={tool?.name} initialUse={tool?.use} onSaved={onChange} />}
      {token && (token.auth.kind === 'oauth' ? <ReloginDialog s={token} onClose={() => setToken(undefined)} onSaved={onChange} /> : <TokenDialog s={token} onClose={() => setToken(undefined)} onSaved={onChange} />)}
      {del && <DeleteDialog s={del} onClose={() => setDel(undefined)} onDone={onChange} />}
    </>
  );
}

function Tools({ s, onChange, onPick, picked, onRetest, onToken, busy }: { s: McpServer; onChange: () => void; onPick: (t: string, use?: ToolIncident) => void; picked?: string; onRetest: () => void; onToken: () => void; busy: boolean }) {
  const toast = useToast();
  const [all, setAll] = useState(false);
  const shown = all ? s.tools : s.tools.slice(0, 6);
  const patch = async (t: McpTool, p: ToolPatch) => {
    try {
      await putMcp(s.name, { revision: s.revision, tools: { [t.name]: p } });
    } catch (e) {
      toast(`${t.name} 바꾸지 못했습니다 · ${errorText(e).title}${e instanceof ApiError && e.body.message ? ` · ${e.body.message}` : ''}`);
    }
    onChange();
  };
  return (
    <section className="card sel-card">
      <div className="row between wrap">
        <h2>
          {s.name} · 도구 {s.tools.length}개
        </h2>
        <span className="row" style={{ gap: 6 }}>
          <button className="btn sm" disabled={busy} onClick={onRetest}>
            도구 목록 다시 읽기
          </button>
          <button className="btn sm" disabled={s.auth.kind === 'none'} title={s.auth.kind === 'none' ? '인증 없이 연결한 서버입니다' : undefined} onClick={onToken}>
            {s.auth.kind === 'oauth' ? '다시 로그인' : '토큰 바꾸기'}
          </button>
        </span>
      </div>
      <div className="gtbl">
        <div className="gr th mtools">
          <span>도구 ({s.name})</span>
          <span>종류</span>
          <span>설명 (서버가 준 것)</span>
          <span>코디네이터</span>
          <span>장애 진단</span>
          <span>자동 대응에서</span>
        </div>
        {shown.map((t) => (
          <div key={t.name} className={`gr mtools ${picked === t.name ? 'on' : ''}`}>
            <span className="mono ellip" title={t.name}>
              {t.name} {t.new && <Badge tone="pr">새 도구</Badge>}
            </span>
            <span>
              <KindPop t={t} onPatch={(p) => patch(t, p)} />
            </span>
            <span className="muted ellip" title={t.description}>
              {t.description}
            </span>
            <span>
              <button className="textbtn plain" aria-pressed={t.coordinator} title={t.coordinator ? '코디네이터에서 빼기' : '코디네이터에서 쓰기'} onClick={() => patch(t, { coordinator: !t.coordinator })}>
                {t.coordinator ? '✓ 씀' : <span className="muted">—</span>}
              </button>
            </span>
            <span>{t.incident === 'off' ? <span className="muted">—</span> : '✓ 씀'}</span>
            <span>
              <Popover button={<>{t.incident === 'diagnose' && t.hint ? `${USE_NAME.diagnose} · ${t.hint}` : t.kind !== 'read' && t.incident === 'off' && !t.coordinator ? '막음' : USE_NAME[t.incident]} ▾</>} label={`${t.name} 자동 대응에서`} className="textbtn plain" width={280} align="right">
                {(close) => (
                  <>
                    <div className="grp">
                      {t.name} ({KIND_NAME[t.kind]})
                    </div>
                    {USES.map((u) => {
                      const off = u === 'diagnose' && t.kind !== 'read' ? '읽기 도구만' : (u === 'propose-approve' || u === 'propose-auto' || u === 'notify') && t.kind === 'read' ? '바꾸기 도구만' : undefined;
                      return (
                        <button
                          key={u}
                          type="button"
                          aria-disabled={!!off}
                          title={off}
                          onClick={() => {
                            if (off) return;
                            close();
                            if (u === 'propose-auto') onPick(t.name, u);
                            else patch(t, { incident: u });
                          }}
                        >
                          <span>{USE_NAME[u]}</span>
                          {(off || u === 'propose-approve' || u === 'propose-auto') && <small>{off ?? (u === 'propose-approve' ? '기본' : '세부 설정 필요')}</small>}
                        </button>
                      );
                    })}
                    <hr />
                    <button
                      type="button"
                      onClick={() => {
                        close();
                        onPick(t.name);
                      }}
                    >
                      세부 설정…
                    </button>
                  </>
                )}
              </Popover>
            </span>
          </div>
        ))}
      </div>
      {s.tools.length > 6 && (
        <span className="muted small">
          <button className="textbtn" onClick={() => setAll((v) => !v)}>
            {all ? '줄이기' : `나머지 ${s.tools.length - 6}개`}
          </button>{' '}
          · 도구 종류는 서버의 읽기 표시(readOnlyHint)를 기본으로 하되 관리자가 '바꾸기'로 올릴 수 있습니다(내릴 수는 없음). 도구 목록이 바뀌면 새 도구는 꺼진 채로 들어오고 관리자에게 알립니다.
        </span>
      )}
      <div className="kv2" style={{ gridTemplateColumns: '120px minmax(0,1fr)', fontSize: 12 }}>
        <span className="muted">보내는 데이터</span>
        <span>도구 입력에 작업 공간 데이터가 들어가면 '외부 AI로 보내지 않음' 작업 공간은 막습니다. 가림 규칙(«가림: KEY»)을 입력에도 적용합니다.</span>
        <span className="muted">결과 크기</span>
        <span>호출당 20,000자까지 · 넘으면 잘라서 표시</span>
        <span className="muted">호출 한도</span>
        <span>대화당 20회 · 사건당 10회 · 시간 초과 15초</span>
        <span className="muted">쓰는 사용자</span>
        <span>
          코디네이터: 로그인 사용자 (이 서버 쓸 권한: {[s.users.systemAdmins && '시스템 관리자', s.users.tenants.length ? `${s.users.tenants.join('·')} 관리자` : ''].filter(Boolean).join(' · ') || '없음'}) · 자동 대응: 자동 대응 계정
        </span>
      </div>
    </section>
  );
}

function KindPop({ t, onPatch }: { t: McpTool; onPatch: (p: ToolPatch) => void }) {
  return (
    <Popover button={<Badge tone={KIND_TONE[t.kind]}>{t.kind === 'notify' ? '알림' : KIND_NAME[t.kind]}</Badge>} label={`${t.name} 종류 바꾸기`} className="textbtn plain" width={280}>
      {(close) => (
        <div className="col" style={{ gap: 8, padding: '8px 10px', fontSize: 13 }}>
          <b>{t.name}</b>
          <Field label="종류">
            <select
              value={t.kind === 'read' ? 'read' : 'change'}
              onChange={(e) => {
                if (e.target.value === 'change' && t.kind === 'read') {
                  close();
                  onPatch({ kind: 'change' });
                }
              }}
            >
              <option value="read" disabled={t.kind !== 'read'}>
                읽기
              </option>
              <option value="change">바꾸기 (승인 필요)</option>
            </select>
          </Field>
          <span className="muted small">서버가 읽기로 표시한 도구도 바꾸기로 올릴 수 있습니다. 바꾸기를 읽기로 내릴 수는 없습니다.</span>
          <label className="check" style={{ alignItems: 'flex-start' }}>
            <input
              type="checkbox"
              checked={t.kind === 'notify'}
              disabled={t.kind === 'read'}
              onChange={(e) => {
                close();
                onPatch({ kind: e.target.checked ? 'notify' : 'change' });
              }}
            />
            <span>
              알림 보내기 도구로 표시
              <span className="muted small" style={{ display: 'block' }}>
                장애 대응이 사건 알림에 바로 쓸 수 있음 (slack 메시지 등)
              </span>
            </span>
          </label>
        </div>
      )}
    </Popover>
  );
}

const blankAuto = (): ToolAuto => ({ floor: 'low', inputs: {}, perIncident: 1, perDay: 10, revert: {} });

function AutoCard({ s, name, initialUse, onSaved }: { s: McpServer; name?: string; initialUse?: ToolIncident; onSaved: () => void }) {
  const toast = useToast();
  const t = s.tools.find((x) => x.name === name) ?? s.tools.find((x) => x.incident === 'propose-auto' || x.incident === 'propose-approve') ?? s.tools.find((x) => x.kind !== 'read');
  const [use, setUse] = useState<ToolIncident>(() => initialUse ?? t?.incident ?? 'off');
  const [auto, setAuto] = useState<ToolAuto>(() => (t?.auto ? structuredClone(t.auto) : blankAuto()));
  const [tenants, setTenants] = useState(() => (t && t.tenants !== 'all' ? t.tenants.join(', ') : ''));
  const [hint, setHint] = useState(t?.hint ?? '');
  const [inputs, setInputs] = useState(false);
  const [test, setTest] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  if (!t)
    return (
      <section className="card">
        <h2>자동 대응에서 쓰는 방법</h2>
        <span className="muted small">이 서버에는 고를 도구가 없습니다.</span>
      </section>
    );
  const isAuto = use === 'propose-auto';
  const miss = isAuto ? autoMissing(t, auto) : [];
  const changeTools = s.tools.filter((x) => x.kind !== 'read' && x.name !== t.name);
  const save = async () => {
    setBusy(true);
    setError(undefined);
    const ts = tenants
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean);
    try {
      await putMcp(s.name, { revision: s.revision, tools: { [t.name]: { incident: use, tenants: ts.length ? ts : 'all', hint: hint || undefined, ...(isAuto ? { auto } : {}) } } });
      toast(`✓ ${t.name} · ${USE_NAME[use]}으로 저장했습니다. 작업 기록에 남았습니다.`);
      onSaved();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const ruleText = Object.entries(auto.inputs)
    .map(([k, r]) => `${k} ${r.kind === 'max' ? `≤ ${r.value ?? ''}` : r.kind === 'incident' ? `사건의 ${INCIDENT_FIELDS.find((f) => f[0] === r.value)?.[1] ?? r.value ?? '—'}` : r.kind === 'template' ? `틀 “${r.value ?? ''}”` : `= ${r.value ?? ''}`}`)
    .join(' · ');
  return (
    <section className="card">
      <div className="row between wrap">
        <h2>{t.name} · 자동 대응에서 쓰는 방법</h2>
        <span className="row" style={{ gap: 6 }}>
          <button className="btn" onClick={() => setTest(true)}>
            지난 사건으로 시험
          </button>
          <button className="btn primary" disabled={busy || miss.length > 0} title={miss.length ? `빠진 것: ${miss.join(', ')}` : undefined} onClick={save}>
            저장
          </button>
        </span>
      </div>
      <div className="grid-2">
        <div className="col" style={{ gap: 8 }}>
          <b>쓰는 방법</b>
          <div className="gtbl">
            {USES.map((u) => {
              const off = u === 'diagnose' && t.kind !== 'read' ? '읽기 도구만' : u !== 'off' && u !== 'diagnose' && t.kind === 'read' ? '바꾸기 도구만' : undefined;
              return (
                <label key={u} className="gr radio-row" title={off} style={{ opacity: off ? 0.5 : 1 }}>
                  <input type="radio" name={`use-${t.name}`} checked={use === u} disabled={!!off} onChange={() => setUse(u)} />
                  <span>
                    <b>{USE_NAME[u]}</b> <span className="muted">· {USE_NOTE[u]}</span>
                  </span>
                </label>
              );
            })}
          </div>
        </div>
        <div className="col" style={{ gap: 8 }}>
          <b>세부 설정</b>
          <div className="kv2" style={{ gridTemplateColumns: '110px minmax(0,1fr)', fontSize: 12, alignItems: 'center' }}>
            {isAuto && (
              <>
                <span className="muted">영향 등급 하한</span>
                <span className="row" style={{ gap: 6 }}>
                  <select aria-label="영향 등급 하한" value={auto.floor} onChange={(e) => setAuto((a) => ({ ...a, floor: e.target.value as Impact }))} style={{ height: 28, fontSize: 12 }}>
                    {(['low', 'medium', 'high'] as Impact[]).map((i) => (
                      <option key={i} value={i}>
                        {IMPACT_NAME[i]}
                      </option>
                    ))}
                  </select>
                  <span className="muted">영향 평가(B)는 이보다 낮게 줄 수 없음 (올리기만)</span>
                </span>
                <span className="muted">입력 제한</span>
                <span>
                  {ruleText || <span className="muted">정하지 않음</span>}{' '}
                  <button className="textbtn small" onClick={() => setInputs(true)}>
                    고치기…
                  </button>
                </span>
                <span className="muted">되돌리기</span>
                <span>
                  <select
                    aria-label="되돌리기"
                    value={auto.revert.irreversible ? '!' : (auto.revert.tool ?? '')}
                    onChange={(e) => setAuto((a) => ({ ...a, revert: e.target.value === '!' ? { irreversible: true } : e.target.value ? { tool: e.target.value } : {} }))}
                    style={{ height: 28, fontSize: 12 }}
                  >
                    <option value="">고르세요</option>
                    {changeTools.map((x) => (
                      <option key={x.name} value={x.name}>
                        짝 도구 {x.name}
                      </option>
                    ))}
                    <option value="!">되돌릴 수 없음 (하한 보통 이상)</option>
                  </select>
                  {auto.revert.tool && <span className="muted"> · 자동 실행한 것은 되돌리기 버튼 제공</span>}
                </span>
              </>
            )}
            <span className="muted">쓸 범위</span>
            <span className="row" style={{ gap: 6 }}>
              <input aria-label="쓸 작업 공간" value={tenants} placeholder="전체 · 쉼표로 작업 공간" onChange={(e) => setTenants(e.target.value)} style={{ height: 28, fontSize: 12, width: 200 }} />
              {auto.signals?.length ? <span className="muted">신호: {auto.signals.join(', ')}</span> : null}
            </span>
            {isAuto && (
              <>
                <span className="muted">한도</span>
                <span className="row" style={{ gap: 4 }}>
                  사건당 <input type="number" min={1} aria-label="사건당 한도" value={auto.perIncident} onChange={(e) => setAuto((a) => ({ ...a, perIncident: Number(e.target.value) }))} style={{ width: 56, height: 28 }} />번 · 하루 <input type="number" min={1} aria-label="하루 한도" value={auto.perDay} onChange={(e) => setAuto((a) => ({ ...a, perDay: Number(e.target.value) }))} style={{ width: 64, height: 28 }} />번
                </span>
              </>
            )}
            <span className="muted">설명 덧붙이기</span>
            <input aria-label="설명 덧붙이기" value={hint} placeholder="모델에 도구 설명과 함께 넘김" onChange={(e) => setHint(e.target.value)} style={{ height: 28, fontSize: 12 }} />
          </div>
          {isAuto && miss.length > 0 && (
            <div className="note er small">
              “낮은 영향이면 자동”은 영향 등급 하한, 입력 제한(모든 인자), 사건당·하루 한도, 되돌리기 방법을 모두 정해야 저장됩니다. 빠진 것: <b>{miss.join(', ')}</b>.
            </div>
          )}
          {isAuto && (
            <div className="note info small">
              <b>바꾸기 도구를 자동으로 돌리면</b> 이 관리자 설정이 근거가 됩니다. 저장할 때 누가 켰는지 작업 기록에 남고, 영향 등급 하한·입력 제한·한도가 모두 있어야 저장됩니다. 안전 규칙(영향 평가 B는 도구 없음, 높음은 반려, 행동 지침이 넓히지 못함)은 그대로입니다.
            </div>
          )}
          {error !== undefined && <ErrorBand error={error} what="저장하지 못했습니다" />}
        </div>
      </div>
      {inputs && <InputsDialog t={t} value={auto.inputs} onClose={() => setInputs(false)} onSave={(v) => (setAuto((a) => ({ ...a, inputs: v })), setInputs(false))} />}
      {test && <ToolTestDialog s={s} t={t} onClose={() => setTest(false)} />}
    </section>
  );
}

function InputsDialog({ t, value, onClose, onSave }: { t: McpTool; value: Record<string, InputRule>; onClose: () => void; onSave: (v: Record<string, InputRule>) => void }) {
  const names = t.args?.map((a) => a.name) ?? Object.keys(value);
  const [v, setV] = useState<Record<string, InputRule>>(() => Object.fromEntries(names.map((n) => [n, value[n] ?? { kind: 'fixed', value: '' }])));
  const bad = names.filter((n) => (v[n].kind === 'incident' ? !INCIDENT_FIELDS.some(([k]) => k === v[n].value) : !(v[n].value ?? '').trim()));
  return (
    <Dialog
      title={`${t.name} · 입력 제한`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={bad.length > 0} title={bad.length ? `값이 빈 인자: ${bad.join(', ')}` : undefined} onClick={() => onSave(v)}>
            저장
          </button>
        </>
      }
    >
      {!t.args && <div className="note un small">웹 기능 준비 중 · 서버 도구 설명의 인자 목록을 아직 받지 못해 지금 정한 인자만 보입니다.</div>}
      <div className="gtbl">
        <div className="gr th" style={{ gridTemplateColumns: '0.9fr 0.9fr 1.6fr' }}>
          <span>인자</span>
          <span>방식</span>
          <span>값</span>
        </div>
        {names.map((n) => (
          <div key={n} className="gr" style={{ gridTemplateColumns: '0.9fr 0.9fr 1.6fr' }}>
            <span className="mono" title={t.args?.find((a) => a.name === n)?.description}>
              {n}
            </span>
            <select aria-label={`${n} 방식`} value={v[n].kind} onChange={(e) => setV((o) => ({ ...o, [n]: { ...o[n], kind: e.target.value as InputRule['kind'] } }))} style={{ height: 28, fontSize: 12 }}>
              {(Object.keys(RULE_NAME) as InputRule['kind'][]).map((k) => (
                <option key={k} value={k}>
                  {RULE_NAME[k]}
                </option>
              ))}
            </select>
            {v[n].kind === 'incident' ? (
              <select aria-label={`${n} 값`} value={v[n].value ?? ''} onChange={(e) => setV((o) => ({ ...o, [n]: { ...o[n], value: e.target.value } }))} style={{ height: 28, fontSize: 12 }}>
                <option value="">사건의 어느 칸?</option>
                {INCIDENT_FIELDS.map(([k, l, ex]) => (
                  <option key={k} value={k}>
                    {l} ({k}={ex})
                  </option>
                ))}
              </select>
            ) : (
            <input aria-label={`${n} 값`} value={v[n].value ?? ''} placeholder={v[n].kind === 'template' ? '예: Seafield Cluster 사건 {id} 자동 묵음' : v[n].kind === 'max' ? '예: 60m' : '고정값'} onChange={(e) => setV((o) => ({ ...o, [n]: { ...o[n], value: e.target.value } }))} style={{ height: 28, fontSize: 12 }} />
            )}
          </div>
        ))}
      </div>
      <div className="muted small">‘사건에서 채움’은 사건 ID · 작업 공간 · 앱 · 서버 · 대상 · 신호 · 제목 중에서 고릅니다. 정하지 않은 인자는 모델이 채울 수 없습니다. 서버 도구 설명(inputSchema)에 없는 인자는 고를 수 없습니다.</div>
    </Dialog>
  );
}

function ToolTestDialog({ s, t, onClose }: { s: McpServer; t: McpTool; onClose: () => void }) {
  const list = usePoll((sig) => incidents({ limit: 20 }, sig), [], 0, incidentsLive);
  const items = useMemo(() => list.data?.items ?? [], [list.data]);
  const [inc, setInc] = useState<string>();
  const [res, setRes] = useState<{ steps: { label: string; detail?: string }[]; result: string }>();
  const [error, setError] = useState<unknown>();
  useEffect(() => {
    if (!inc && items[0]) setInc(items[0].id);
  }, [inc, items]);
  useEffect(() => {
    if (!inc) return;
    let live = true;
    setRes(undefined);
    setError(undefined);
    testMcpTool(s.name, t.name, inc)
      .then((r) => live && setRes(r))
      .catch((e) => live && setError(e));
    return () => {
      live = false;
    };
  }, [inc, s.name, t.name]);
  return (
    <Dialog
      title="지난 사건으로 시험"
      width={420}
      onClose={onClose}
      footer={
        <button className="btn" onClick={onClose}>
          닫기
        </button>
      }
    >
      <label className="field">
        사건
        <select value={inc ?? ''} onChange={(e) => setInc(e.target.value)} disabled={!items.length}>
          {!items.length && <option value="">{list.loading ? '불러오는 중…' : '지난 사건이 없습니다'}</option>}
          {items.map((x) => (
            <option key={x.id} value={x.id}>
              {x.id} · {x.app ?? x.node ?? ''} {x.signal}
            </option>
          ))}
        </select>
      </label>
      {error !== undefined && (error instanceof ApiError && (error.status === 404 || error.status === 405) ? <div className="note un small">웹 기능 준비 중 · 도구 시험은 웹 데몬이 아직 주지 않습니다.</div> : <ErrorBand error={error} what="시험하지 못했습니다" />)}
      {!res && error === undefined && inc && <div className="muted small">시험하는 중…</div>}
      {res && (
        <div className="steps-list">
          {res.steps.map((x, i) => (
            <div key={i}>
              <i className="ok" />
              <span>{x.label}</span>
              <span className="muted">{x.detail ?? ''}</span>
            </div>
          ))}
          <div>
            <i className="pr" />
            <span>결과</span>
            <span className="muted">{res.result}</span>
          </div>
        </div>
      )}
      <div className="muted small">시험은 MCP 도구를 실제로 부르지 않습니다.</div>
    </Dialog>
  );
}

function AddDialog({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [step, setStep] = useState<1 | 2>(1);
  const [name, setName] = useState('');
  const [url, setUrl] = useState('https://');
  const [kind, setKind] = useState<'bearer' | 'none' | 'oauth'>('bearer');
  const [login, setLogin] = useState<McpOauthStart>();
  // 웹 데몬이 아직 OAuth를 모르면(404·405, 또는 auth.kind 422) '웹 기능 준비 중'으로 둔다
  const [oauthWait, setOauthWait] = useState(false);
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [srv, setSrv] = useState<McpServer>();
  const [pick, setPick] = useState<Record<string, { coordinator: boolean; incident: boolean }>>({});
  const [tenants, setTenants] = useState('');
  const nameBad = name !== '' && !MCP_NAME_RE.test(name);
  const urlBad = url !== 'https://' && !/^https:\/\/[^\s/]+/.test(url);
  const connected = (r: McpServer) => {
    setSrv(r);
    setPick(Object.fromEntries(r.tools.map((t) => [t.name, { coordinator: t.kind === 'read', incident: t.kind === 'read' }])));
    setStep(2);
    onSaved();
  };
  // OAuth: 로그인 창에서 돌아올 때까지 2초마다 묻는다
  useEffect(() => {
    if (!login) return;
    const t = setInterval(async () => {
      try {
        const st = await mcpOauthState(login.name);
        if (st.state === 'connected' && st.server) (setLogin(undefined), connected(st.server));
        else if (st.state === 'failed' || st.state === 'expired') (setLogin(undefined), setError(new ApiError(422, { code: 'mcp-connect', message: st.error ?? '로그인 시간이 지났습니다', error: st.error ?? '로그인 시간이 지났습니다' } as ConstructorParameters<typeof ApiError>[1])));
      } catch (e) {
        setLogin(undefined);
        setError(e);
      }
    }, 2000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [login]);
  const connect = async () => {
    setBusy(true);
    setError(undefined);
    if (kind === 'oauth') {
      try {
        setLogin(await startMcpOauth({ name, url }));
      } catch (e) {
        if (e instanceof ApiError && (e.status === 404 || e.status === 405 || (e.status === 422 && /auth\.kind/.test(e.message)))) setOauthWait(true);
        else setError(e);
      } finally {
        setBusy(false);
      }
      return;
    }
    try {
      const r = await addMcp({ name, url, auth: kind === 'bearer' ? { kind, token } : { kind: 'none' } });
      setToken('');
      connected(r);
    } catch (e) {
      setToken('');
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const save = async () => {
    if (!srv) return;
    setBusy(true);
    setError(undefined);
    const ts = tenants
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean);
    try {
      await putMcp(srv.name, {
        revision: srv.revision,
        users: { systemAdmins: true, tenants: ts },
        tools: Object.fromEntries(srv.tools.map((t) => [t.name, { coordinator: pick[t.name].coordinator, incident: pick[t.name].incident ? (t.kind === 'read' ? 'diagnose' : 'propose-approve') : 'off' } as ToolPatch])),
      });
      toast(`✓ ${srv.name}을 연결했습니다.`);
      onSaved();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const steps = (
    <div className="steps-list">
      {(['주소 · 인증', '연결 시험 · 도구 받기', '쓸 곳 정하기'] as const).map((l, i) => (
        <div key={l}>
          <i className={step > 1 && i < 2 ? 'ok' : (step === 1 && i === 0) || (step === 2 && i === 2) ? 'pr' : ''} />
          <span>{l}</span>
          <span />
        </div>
      ))}
    </div>
  );
  if (step === 2 && srv) {
    const r = readCount(srv);
    return (
      <Dialog
        title={`${srv.name} · 쓸 곳 정하기`}
        onClose={onClose}
        footer={
          <>
            <button className="btn" onClick={onClose} title="연결은 이미 저장됐습니다. 도구는 꺼진 채로 둡니다.">
              나중에
            </button>
            <button className="btn primary" disabled={busy} onClick={save}>
              저장
            </button>
          </>
        }
      >
        {steps}
        <div className="note ok small">
          연결됨{srv.info ? ` · 서버 ${srv.info.serverName}${srv.info.version ? ` ${srv.info.version}` : ''}` : ''} · 도구 {srv.tools.length}개 (읽기 {r} · 바꾸기 {srv.tools.length - r})
        </div>
        <div className="gtbl">
          <div className="gr th" style={{ gridTemplateColumns: '1.4fr 0.6fr 0.8fr 0.8fr' }}>
            <span>도구</span>
            <span>종류</span>
            <span>코디네이터</span>
            <span>장애 진단</span>
          </div>
          {srv.tools.map((t) => (
            <div key={t.name} className="gr" style={{ gridTemplateColumns: '1.4fr 0.6fr 0.8fr 0.8fr' }}>
              <span className="mono ellip">{t.name}</span>
              <span>{KIND_NAME[t.kind]}</span>
              <label className="check">
                <input type="checkbox" aria-label={`${t.name} 코디네이터`} checked={pick[t.name]?.coordinator} onChange={(e) => setPick((o) => ({ ...o, [t.name]: { ...o[t.name], coordinator: e.target.checked } }))} />
              </label>
              <label className="check">
                <input type="checkbox" aria-label={`${t.name} 장애 진단`} checked={pick[t.name]?.incident} onChange={(e) => setPick((o) => ({ ...o, [t.name]: { ...o[t.name], incident: e.target.checked } }))} />
                {t.kind !== 'read' && <span className="muted small">(승인)</span>}
              </label>
            </div>
          ))}
        </div>
        <Field label="작업 공간" hint="비우면 시스템 관리자만 · 쉼표로 나눕니다">
          <input value={tenants} placeholder="시스템 관리자만" onChange={(e) => setTenants(e.target.value)} />
        </Field>
        <label className="check">
          <input type="checkbox" checked disabled />
          새로 생긴 도구는 꺼진 채로 받기
        </label>
        <div className="muted small">연결 시험이 성공하면 서버는 이미 저장되고 도구는 모두 꺼진 채입니다. ‘나중에’를 누르면 창을 닫고 쓸 곳은 도구 표에서 정합니다.</div>
        {error !== undefined && <ErrorBand error={error} what="저장하지 못했습니다" />}
      </Dialog>
    );
  }
  const fail = errText(error);
  return (
    <Dialog
      title="MCP 서버 연결"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={busy || !!login || (kind === 'oauth' && oauthWait) || !name || nameBad || urlBad || url === 'https://' || (kind === 'bearer' && !token)} onClick={connect}>
            {busy ? '시험 중…' : login ? '로그인 대기 중…' : kind === 'oauth' ? '로그인해서 연결' : '연결 시험'}
          </button>
        </>
      }
    >
      {steps}
      <Field label="이름" hint={`도구 이름 앞에 mcp.${name || '이름'}. 로 붙음`} error={nameBad ? '영어 소문자로 시작하고 소문자·숫자·-만, 31자까지' : undefined}>
        <input className="mono" value={name} autoComplete="off" spellCheck={false} onChange={(e) => setName(e.target.value.trim())} />
      </Field>
      <Field label="주소 (Streamable HTTP)" hint="https만 · stdio 서버는 받지 않음" error={urlBad ? 'https:// 주소를 넣으세요' : undefined}>
        <input className="mono" value={url} autoComplete="off" spellCheck={false} onChange={(e) => setUrl(e.target.value.trim())} />
      </Field>
      <Field label="인증">
        <select value={kind} disabled={!!login} onChange={(e) => setKind(e.target.value as 'bearer' | 'none' | 'oauth')}>
          <option value="bearer">토큰 (Authorization: Bearer)</option>
          <option value="none">없음</option>
          <option value="oauth">OAuth 로그인</option>
        </select>
      </Field>
      {kind === 'bearer' && (
        <Field label="토큰" hint="봉인 파일에 저장 · 다시 보이지 않음">
          <input type="password" value={token} autoComplete="new-password" onChange={(e) => setToken(e.target.value)} />
        </Field>
      )}
      {kind === 'oauth' && oauthWait ? (
        <div className="note un small">OAuth 로그인: 웹 기능 준비 중 · 지금은 토큰(Authorization: Bearer)으로 연결해 주세요.</div>
      ) : kind === 'oauth' && login ? (
        <div className="note info small row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <span>그 서버의 로그인 창에서 허용하면 이 창이 알아서 다음 단계로 넘어갑니다. 로그인 대기 중…</span>
          <a className="btn sm" href={login.loginUrl} target="_blank" rel="noopener noreferrer">
            로그인 창 열기 ↗
          </a>
        </div>
      ) : (
        <div className="note info small">OAuth 서버는 “로그인해서 연결”로 그 서버의 로그인 창을 띄우고, 받은 토큰을 sfc-web이 봉인 파일에 둡니다. 토큰 값은 브라우저에 오지 않습니다.</div>
      )}
      {fail ? <div className="note er small">{fail}</div> : error !== undefined && <ErrorBand error={error} what="연결하지 못했습니다" />}
    </Dialog>
  );
}

const authText = (x: McpServer) =>
  x.auth.kind === 'bearer'
    ? `토큰 · 봉인${x.auth.last4 ? ` ··${x.auth.last4}` : ''}`
    : x.auth.kind === 'oauth'
      ? `OAuth · 봉인${x.auth.needsLogin ? ' · 다시 로그인 필요' : x.auth.expiresAt ? ` · 토큰 ${daysTo(x.auth.expiresAt)}` : ''}`
      : '없음';
const daysTo = (iso: string) => {
  const d = Math.ceil((Date.parse(iso) - Date.now()) / 86400_000);
  return d <= 0 ? '만료됨' : `${d}일 뒤 만료`;
};

/** OAuth 다시 로그인: 로그인 창을 열고 돌아올 때까지 기다린다. 그동안 기존 토큰을 계속 쓴다. */
function ReloginDialog({ s, onClose, onSaved }: { s: McpServer; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [login, setLogin] = useState<McpOauthStart>();
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!login) return;
    const t = setInterval(async () => {
      try {
        const st = await mcpOauthState(s.name);
        if (st.state === 'connected') {
          setLogin(undefined);
          toast(`✓ ${s.name}에 다시 로그인했습니다.`);
          onSaved();
          onClose();
        } else if (st.state === 'failed' || st.state === 'expired') {
          setLogin(undefined);
          setError(new Error(st.error ?? '로그인 시간이 지났습니다'));
        }
      } catch (e) {
        setLogin(undefined);
        setError(e);
      }
    }, 2000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [login]);
  const start = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setLogin(await reloginMcp(s.name));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`${s.name} 다시 로그인`}
      width={420}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            닫기
          </button>
          {login ? (
            <a className="btn primary" href={login.loginUrl} target="_blank" rel="noopener noreferrer">
              로그인 창 열기 ↗
            </a>
          ) : (
            <button className="btn primary" disabled={busy} onClick={() => void start()}>
              로그인 시작
            </button>
          )}
        </>
      }
    >
      <div className="muted small">지금 토큰: {authText(s)}. 다시 로그인하는 동안에도 기존 토큰을 씁니다. 받은 새 토큰은 sfc-web 봉인 파일에 두고 브라우저에는 오지 않습니다.</div>
      {login && <div className="note info small">그 서버의 로그인 창에서 허용하면 이 창이 알아서 닫힙니다. 로그인 대기 중…</div>}
      {error !== undefined && <ErrorBand error={error} what="다시 로그인하지 못했습니다" />}
    </Dialog>
  );
}

function TokenDialog({ s, onClose, onSaved }: { s: McpServer; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await putMcp(s.name, { revision: s.revision, auth: { kind: 'bearer', token } });
      setToken('');
      toast(`✓ ${s.name} 토큰을 바꿨습니다 · ··${r.auth.last4 ?? ''}`);
      onSaved();
      onClose();
    } catch (e) {
      setToken('');
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const fail = errText(error);
  return (
    <Dialog
      title={`${s.name} 토큰 바꾸기`}
      width={420}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={busy || !token} onClick={go}>
            바꾸기
          </button>
        </>
      }
    >
      <div className="muted small">지금 토큰: ··{s.auth.last4 ?? '????'} (봉인 파일)</div>
      <Field label="새 토큰" hint="봉인 파일에 저장 · 다시 보이지 않음">
        <input type="password" value={token} autoComplete="new-password" onChange={(e) => setToken(e.target.value)} />
      </Field>
      {fail ? <div className="note er small">{fail}</div> : error !== undefined && <ErrorBand error={error} what="바꾸지 못했습니다" />}
    </Dialog>
  );
}

function DeleteDialog({ s, onClose, onDone }: { s: McpServer; onClose: () => void; onDone: () => void }) {
  const undoToast = useUndoToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const used = s.usedBy;
  const usedText = (x: string) => (x === 'cluster' ? '클러스터' : x.split('/').slice(-1)[0]);
  return (
    <ConfirmDialog
      title={`${s.name} 연결을 끊을까요?`}
      target={s.name}
      actionLabel="연결 끊기"
      busy={busy}
      onClose={onClose}
      onConfirm={async () => {
        setBusy(true);
        setError(undefined);
        try {
          const r = await deleteMcp(s.name, s.name);
          undoToast(`✓ ${s.name} 연결을 끊었습니다.`, r?.trash, async (id) => {
            await restoreTrash(id, {});
            onDone();
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
        토큰을 봉인 파일에서 지웁니다.{' '}
        {used === undefined ? '이 서버를 쓰는 행동 지침이 있으면 그 지침에서도 빠집니다.' : used.length ? `행동 지침 ${used.length}개(${used.map(usedText).join(', ')})가 ${s.name}을(를) 쓰고 있어 그 지침에서도 빠집니다.` : '이 서버를 쓰는 행동 지침은 없습니다.'}
      </div>
      <div className="small muted">보관 기간 동안 작업 기록 › 지운 것에서 되살릴 수 있습니다(지침 연결 포함). 토큰·OAuth 로그인은 다시 넣어야 합니다.</div>
      {error !== undefined && <ErrorBand error={error} what="연결을 끊지 못했습니다" />}
    </ConfirmDialog>
  );
}
