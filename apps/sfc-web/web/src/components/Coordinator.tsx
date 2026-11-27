// SPDX-License-Identifier: Apache-2.0

// 코디네이터 패널 (UI-B0·B1, 캔버스 Coordinator · CoordinatorIx)과 넓은 화면(UI-B2)이 함께 쓰는 대화 보기.
// 코디네이터는 웹 데몬이 로그인한 사용자 권한으로 돌린다. 바꾸는 작업은 제안 카드를 사람이 승인해야 그 사용자의 세션으로 서명·전송된다.
import { Fragment, createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { chipLabel, conversation, editProposal, setConversationChips, newConversation, proposal as getProposal, rejectProposal, sendMessage, stopConversation, type AiContext, type AiConversationFull, type AiMessage, type AiProposal, type AiTool } from '../api/ai';
import { ApiError, api } from '../api/client';
import { useAuth, useSession } from '../auth/session';
import { fmtBytes, fmtTime, until } from '../lib/format';
import { eulReul } from '../lib/josa';
import { Badge, OpId, type Tone } from './ui';
import { Drawer } from './Drawer';
import { MutationError, OpPanel, sendOp, useMutation } from './OpPanel';
import { Popover } from './Popover';
import { errorText } from './states';
import type { OpView } from '../api/types';
import { Sheet } from '../mobile/Sheet';
import { ConfirmApproveSheet, needsConfirm } from '../mobile/Approve';

// ── 열림 상태와 지금 대화 ──
const KEY = 'sfc.coordinator.conversation';
type Coord = { open: boolean; setOpen: (v: boolean) => void; conv?: string; setConv: (id?: string) => void; openNew: (o?: { incident?: string }) => Promise<void> };
const Ctx = createContext<Coord>({ open: false, setOpen: () => undefined, setConv: () => undefined, openNew: async () => undefined });
export const useCoordinator = () => useContext(Ctx);

export function CoordinatorProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [conv, setConvState] = useState<string | undefined>(() => {
    try {
      return localStorage.getItem(KEY) ?? undefined;
    } catch {
      return undefined;
    }
  });
  const setConv = useCallback((id?: string) => {
    setConvState(id);
    try {
      if (id) localStorage.setItem(KEY, id);
      else localStorage.removeItem(KEY);
    } catch {
      // 저장 못 해도 이번 창에서는 이어진다
    }
  }, []);
  /** 새 대화를 열고 패널을 연다. 사건을 주면 데몬이 그 사건을 맥락 칩으로 붙여 만든다('코디네이터로 열기') */
  const openNew = useCallback(
    async (o?: { incident?: string }) => {
      const c = await newConversation(o?.incident ? { incident: o.incident } : {});
      setConv(c.id);
      setOpen(true);
    },
    [setConv],
  );
  const v = useMemo(() => ({ open, setOpen, conv, setConv, openNew }), [open, conv, setConv, openNew]);
  return <Ctx.Provider value={v}>{children}</Ctx.Provider>;
}

// ── 지금 보는 화면 → 맥락 ──
const SCREENS: [RegExp, string][] = [
  [/^\/$/, '대시보드'],
  [/^\/servers/, '서버'],
  [/^\/deploy/, '배포'],
  [/^\/standalone/, '단독 컨테이너'],
  [/^\/images/, '이미지 관리'],
  [/^\/incidents/, '장애 대응'],
  [/^\/shared\/networks/, '망 · 연결'],
  [/^\/shared\/ingress/, '외부 접속'],
  [/^\/shared\/volumes/, '데이터 저장소'],
  [/^\/shared\/vault/, '비밀값 보관함'],
  [/^\/shared\/lifecycle/, '상태 검사'],
  [/^\/system\/tenants/, '작업 공간'],
  [/^\/system\/domains/, '외부 도메인'],
  [/^\/system\/users/, '사용자'],
  [/^\/system\/ops/, '작업 기록'],
  [/^\/system\/audit/, '설정 변경 기록'],
  [/^\/system\/ai/, 'AI 설정'],
  [/^\/system\/web/, '웹 앱 설정'],
  [/^\/notifications/, '알림'],
  [/^\/account/, '내 계정'],
  [/^\/coordinator/, '코디네이터'],
];
export function screenContext(path: string): AiContext {
  const name = SCREENS.find(([re]) => re.test(path))?.[1] ?? '화면';
  const seg = path.split('/').filter(Boolean);
  const sel: Record<string, string> = {};
  let label = name;
  if (seg[0] === 'servers' && seg[1] && seg[1] !== 'consensus') {
    sel.node = decodeURIComponent(seg[1]);
    label = `${name} › ${sel.node}`;
  } else if (seg[0] === 'deploy' && seg[1] === 'apps' && seg[3]) {
    sel.tenant = decodeURIComponent(seg[2]);
    sel.app = decodeURIComponent(seg[3]);
    label = `${name} › ${sel.app}`;
    // 컨테이너 화면(/deploy/apps/t/a/c/서비스/인스턴스): 그 컨테이너를 맥락에 넣는다
    if (seg[4] === 'c' && seg[5] && seg[6]) {
      sel.service = decodeURIComponent(seg[5]);
      sel.instance = decodeURIComponent(seg[6]);
      label = `${label} › 컨테이너 ${sel.service}-${sel.instance}`;
    }
  } else if (seg[0] === 'incidents' && seg[1]?.startsWith('inc-')) {
    sel.incident = decodeURIComponent(seg[1]);
    label = `${name} › ${sel.incident}`;
  } else if (seg[0] === 'system' && seg[1] === 'tenants' && seg[2]) {
    sel.tenant = decodeURIComponent(seg[2]);
    label = `${name} › ${sel.tenant}`;
  }
  return { screen: label, path, ...(Object.keys(sel).length ? { selection: sel } : {}) };
}

// ── 패널 ──
export function CoordinatorPanel() {
  const { open, setOpen, conv, setConv } = useCoordinator();
  const navigate = useNavigate();
  if (!open) return null;
  return (
    <aside className="coord" aria-label="코디네이터">
      <div className="coord-head">
        <b style={{ fontSize: 15 }}>✦ 코디네이터</b>
        <ModelBadge id={conv} />
        <span className="grow" />
        <button className="btn sm" onClick={() => navigate('/coordinator')}>
          대화 목록 · 넓게
        </button>
        <button className="btn sm" aria-label="코디네이터 닫기" onClick={() => setOpen(false)}>
          ✕
        </button>
      </div>
      <ChatView id={conv} onConv={setConv} variant="panel" />
    </aside>
  );
}

function ModelBadge({ id }: { id?: string }) {
  const [model, setModel] = useState<string>();
  useEffect(() => {
    if (!id) return setModel(undefined);
    const ac = new AbortController();
    conversation(id, ac.signal)
      .then((c) => setModel(c.model))
      .catch(() => undefined);
    return () => ac.abort();
  }, [id]);
  return model ? <Badge tone="pr">{model}</Badge> : null;
}

// ── 대화 보기 (패널·넓은 화면 공용) ──
type Live = { text: string; tools: AiTool[]; proposals: string[]; error?: { code: string; message: string } };
type Variant = 'panel' | 'full' | 'phone';
/** 제안 작업의 '수정'이 대화 입력 칸을 채운다 (휴대폰 UI-M6 ②) */
const ComposeCtx = createContext<(t: string) => void>(() => undefined);

export function ChatView({
  id,
  onConv,
  variant,
  ctxPath,
  onDropCtx,
}: {
  id?: string;
  onConv: (id: string) => void;
  variant: Variant;
  /** 휴대폰: 맥락으로 붙은 화면 주소 (‘✦ 코디네이터에게’를 누른 화면). 없으면 지금 주소 */
  ctxPath?: string;
  onDropCtx?: () => void;
}) {
  const session = useSession();
  const { tenant } = useAuth();
  const loc = useLocation();
  const ctx = screenContext(ctxPath ?? loc.pathname);
  const [conv, setConv] = useState<AiConversationFull>();
  const [loadErr, setLoadErr] = useState<unknown>();
  const [props, setProps] = useState<Record<string, AiProposal>>({});
  const [live, setLive] = useState<Live>();
  const [sendErr, setSendErr] = useState<unknown>();
  const [text, setText] = useState('');
  const ac = useRef<AbortController>();
  const scroller = useRef<HTMLDivElement>(null);

  const load = useCallback(
    async (cid: string, signal?: AbortSignal) => {
      try {
        const c = await conversation(cid, signal);
        setConv(c);
        setLoadErr(undefined);
        const ids = c.messages.flatMap((m) => m.proposals ?? []);
        const got = await Promise.all(ids.map((p) => getProposal(p, signal).catch(() => undefined)));
        setProps(Object.fromEntries(got.filter((p): p is AiProposal => !!p).map((p) => [p.id, p])));
      } catch (e) {
        if ((e as Error)?.name === 'AbortError') return;
        if (e instanceof ApiError && e.status === 404) {
          setConv(undefined);
          return;
        }
        setLoadErr(e);
      }
    },
    [],
  );
  useEffect(() => {
    setConv(undefined);
    setProps({});
    setLive(undefined);
    setSendErr(undefined);
    if (!id) return;
    const a = new AbortController();
    void load(id, a.signal);
    return () => a.abort();
  }, [id, load]);
  useEffect(() => {
    scroller.current?.scrollTo({ top: scroller.current.scrollHeight });
  }, [conv, live]);
  useEffect(() => () => ac.current?.abort(), []);

  const send = async (msg: string) => {
    const body = msg.trim();
    if (!body || live) return;
    setSendErr(undefined);
    let cid = id;
    try {
      if (!cid) {
        cid = (await newConversation()).id;
        onConv(cid);
      }
    } catch (e) {
      setSendErr(e);
      return;
    }
    setText('');
    const optimistic: AiMessage = { id: 'local', role: 'user', text: body, at: new Date().toISOString() };
    setConv((c) => (c && c.id === cid ? { ...c, messages: [...c.messages, optimistic] } : { id: cid!, title: '', messages: [optimistic] }));
    const cur: Live = { text: '', tools: [], proposals: [] };
    setLive({ ...cur });
    const a = new AbortController();
    ac.current = a;
    try {
      await sendMessage(cid, { text: body, context: { ...ctx, ...(tenant ? { selection: { tenant, ...ctx.selection } } : {}) } }, (e) => {
        if (e.type === 'delta') cur.text += e.text;
        else if (e.type === 'tool') cur.tools = [...cur.tools, e.tool];
        else if (e.type === 'proposal') {
          cur.proposals = [...cur.proposals, e.proposal.id];
          setProps((p) => ({ ...p, [e.proposal.id]: e.proposal }));
        } else if (e.type === 'error') cur.error = { code: e.code, message: e.message };
        setLive({ ...cur });
      }, a.signal);
    } catch (e) {
      if ((e as Error)?.name !== 'AbortError') setSendErr(e);
    } finally {
      ac.current = undefined;
      setLive(undefined);
      await load(cid);
      if (cur.error && cur.error.code !== 'stopped') setSendErr(new ApiError(200, { code: cur.error.code, message: cur.error.message }));
    }
  };
  const stop = () => {
    if (id) void stopConversation(id).catch(() => undefined);
    ac.current?.abort();
  };
  const newChat = async () => {
    try {
      const c = await newConversation();
      onConv(c.id);
    } catch (e) {
      setSendErr(e);
    }
  };
  const refreshProp = async (pid: string) => {
    try {
      const p = await getProposal(pid);
      setProps((o) => ({ ...o, [pid]: p }));
    } catch {
      // 다음 읽기에서
    }
  };

  // 칩은 대화와 함께 저장된다. ✕로만 뺀다
  const dropChip = async (i: number) => {
    if (!conv) return;
    const rest = (conv.chips ?? []).filter((_, j) => j !== i);
    try {
      await setConversationChips(conv.id, rest.length ? rest : null);
      setConv({ ...conv, chips: rest });
    } catch (e) {
      setSendErr(e);
    }
  };
  const msgs = conv?.messages ?? [];
  return (
    <ComposeCtx.Provider value={setText}>
      {variant === 'phone' && (
        <div className="mchips m-chat-ctx">
          {ctxPath && (
            <span className="mchip">
              지금 보는 화면: {ctx.screen}
              <button type="button" className="x" aria-label="화면 맥락 빼기" onClick={onDropCtx}>
                ✕
              </button>
            </span>
          )}
          {(conv?.chips ?? []).map((c, i) => (
            <span key={i} className="mchip">
              {chipLabel(c)}
              <button type="button" className="x" aria-label={`${chipLabel(c)} 맥락 빼기`} onClick={() => void dropChip(i)}>
                ✕
              </button>
            </span>
          ))}
          {tenant && <span className="mchip">{tenant}</span>}
        </div>
      )}
      {variant === 'panel' && (
        <div className="coord-ctx">
          <span className="muted">{session.user.username} 권한으로 동작</span>
          <span className="muted">·</span>
          <span className="pillc">지금 보는 화면: {ctx.screen}</span>
          {(conv?.chips ?? []).map((c, i) => (
            <span key={i} className="pillc">
              {chipLabel(c)}{' '}
              <button className="textbtn plain" aria-label={`${chipLabel(c)} 맥락 빼기`} onClick={() => void dropChip(i)}>
                ✕
              </button>
            </span>
          ))}
          {tenant && <span className="pillc">작업 공간 {tenant}</span>}
        </div>
      )}
      <div className={`coord-body ${variant}`} ref={scroller}>
        {loadErr !== undefined && <div className="note er small">대화를 읽지 못했습니다: {errorText(loadErr).message}</div>}
        {!msgs.length && !live && (
          <div className="muted small" style={{ padding: '8px 2px' }}>
            {variant === 'phone' && !ctxPath ? '무엇이든 물어보세요.' : `지금 보는 화면(${ctx.screen})을 맥락으로 묻습니다.`} 코디네이터는 {session.user.username} 권한 안에서 필요한 읽기 도구를 찾아 쓰고, 바꾸는 작업은 승인 카드로만 제안합니다.
          </div>
        )}
        {msgs.map((m) => (
          <Message key={m.id} m={m} variant={variant} props={props} onProp={refreshProp} setProp={(p) => setProps((o) => ({ ...o, [p.id]: p }))} />
        ))}
        {live && <Message m={{ id: 'live', role: 'assistant', text: live.text, at: '', tools: live.tools, proposals: live.proposals }} live variant={variant} props={props} onProp={refreshProp} setProp={(p) => setProps((o) => ({ ...o, [p.id]: p }))} />}
        {sendErr !== undefined && <SendError e={sendErr} />}
      </div>
      <Composer text={text} setText={setText} busy={!!live} variant={variant} ctxPath={ctxPath} onSend={(t) => void send(t)} onStop={stop} onNew={() => void newChat()} />
    </ComposeCtx.Provider>
  );
}

function SendError({ e }: { e: unknown }) {
  const code = e instanceof ApiError ? e.code : '';
  const msg =
    code === 'busy'
      ? '이 대화는 아직 답하는 중입니다. 끝난 뒤 보내세요.'
      : code === 'limit-reached' || code === 'daily-limit'
        ? '오늘 쓸 수 있는 토큰을 다 썼습니다. 내일 다시 쓸 수 있습니다.'
        : code === 'no-provider' || code === 'ai-unavailable'
          ? 'AI 공급자 키가 없거나 응답하지 않습니다. AI 설정을 확인하세요.'
          : code === 'ai-role-unavailable'
            ? '코디네이터에 쓸 모델이 정해지지 않았습니다. AI 설정의 역할별 모델을 확인하세요.'
            : code === 'ai-budget-exceeded'
              ? 'AI 사용 한도를 다 썼습니다. AI 설정의 한도를 확인하세요.'
              : code === 'tool-limit'
                ? '한 번에 부를 수 있는 도구 수를 넘어 멈췄습니다. 질문을 나눠서 물어보세요.'
                : code === 'conversation-limit'
                  ? '이 대화가 너무 길어졌습니다. 새 대화를 열어 이어 주세요.'
                  : errorText(e).message;
  return <div className="note er small">! {msg}</div>;
}

const TOOL_ICON: Record<AiTool['kind'], string> = { find: '🔎 도구 찾음', read: '📖 읽음', propose: '✎ 제안' };

function Message({ m, live, variant, props, onProp, setProp }: { m: AiMessage; live?: boolean; variant: Variant; props: Record<string, AiProposal>; onProp: (id: string) => void; setProp: (p: AiProposal) => void }) {
  const [openTools, setOpenTools] = useState(false);
  const [openSum, setOpenSum] = useState(false);
  if (m.role === 'user') return <div className="bub me">{m.text}</div>;
  if (m.role === 'summary')
    return (
      <div className="tool">
        <button className="linkish small" onClick={() => setOpenSum(!openSum)}>
          ⋯ 여기까지 요약해 이어 감 {openSum ? '▴' : '▾'}
        </button>
        {openSum && <div className="bub ai">{m.text}</div>}
      </div>
    );
  if (m.role === 'notice') return <div className="note info small">{m.text}</div>;
  const tools = m.tools ?? [];
  const finds = tools.filter((t) => t.kind === 'find').length;
  const reads = tools.filter((t) => t.kind === 'read').length;
  const showAll = variant === 'panel' || openTools || live;
  return (
    <>
      {tools.length > 0 &&
        (showAll ? (
          <div className="col" style={{ gap: 4 }}>
            {tools.map((t, i) => (
              <ToolLine key={i} t={t} />
            ))}
          </div>
        ) : variant === 'phone' ? (
          <div className="tool">
            {[finds && `🔎 도구 찾음${finds > 1 ? ` ${finds}` : ''}`, reads && `📖 읽음 ${reads}`].filter(Boolean).join(' · ')}{' '}
            <button type="button" className="linkish" onClick={() => setOpenTools(true)}>
              펼치기
            </button>
          </div>
        ) : (
          <button className="tool linkish" onClick={() => setOpenTools(true)}>
            {[finds && `🔎 도구 찾음 ${finds}`, reads && `📖 읽음 ${reads}`].filter(Boolean).join(' · ')} (요약만 보관)
          </button>
        ))}
      {m.fallback && <div className="note info small">메인 모델이 응답하지 않아 예비 모델{m.model ? ` ${m.model}` : ''}로 이어 답했습니다.</div>}
      {(m.text || live) && <div className="bub ai">{m.text || <span className="muted">생각하는 중…</span>}</div>}
      {(m.proposals ?? []).map((pid) => {
        const p = props[pid];
        if (!p) return null;
        const after = p.after ? props[p.after] : undefined;
        // 휴대폰에서 승인을 기다리는 카드는 요약 한 줄 + 단추 3개 (UI-M6 ①)
        return variant === 'phone' && p.state === 'pending' ? <MProposalCard key={pid} p={p} after={after} onChanged={() => onProp(pid)} /> : <ProposalCard key={pid} p={p} after={after} onChanged={() => onProp(pid)} setProp={setProp} />;
      })}
    </>
  );
}

function ToolLine({ t }: { t: AiTool }) {
  return (
    <Popover button={<span className="tool">{TOOL_ICON[t.kind]} · {t.summary}</span>} className="textbtn plain" label={`도구 ${t.name}`} width={360}>
      {() => (
        <div className="col" style={{ gap: 6, padding: 6, fontSize: 12 }}>
          <b style={{ fontSize: 13 }}>
            {TOOL_ICON[t.kind]} · {t.summary}
          </b>
          {t.args ? (
            <pre className="code dark">{`${t.name}(${Object.entries(t.args)
              .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
              .join(', ')})\n→ ${t.summary}`}</pre>
          ) : (
            <span className="mono">{t.name}</span>
          )}
          <span className="muted">{t.args ? '호출 인자와 결과 요약을 보여 줍니다. 비밀값 인자는 «가림». ' : ''}읽은 원문은 보관하지 않고 요약만 대화에 남깁니다.</span>
        </div>
      )}
    </Popover>
  );
}

// ── 제안 작업 카드 ──
const IMPACT: Record<AiProposal['impact'], [Tone, string]> = { low: ['ok', '영향 낮음'], medium: ['wa', '영향 보통'], high: ['er', '영향 높음'] };
const opDone = (op?: OpView) => op?.state === 'applied';
type OpKind = 'done' | 'failed' | 'running' | 'unknown';
const APPROVED: Record<OpKind, [Tone, string]> = { done: ['ok', '승인됨 · 완료'], failed: ['er', '승인됨 · 실패'], running: ['pr', '승인됨 · 실행 중'], unknown: ['un', '승인됨 · 결과 모름'] };
/** 승인된 카드의 작업 상태. GET /ops/{id}로 읽고, 실행 중이면 5초마다 다시 읽는다. 못 읽으면 결과 모름 */
function useOpState(id?: string): { kind: OpKind; op?: OpView } {
  const [r, setR] = useState<{ kind: OpKind; op?: OpView }>({ kind: 'unknown' });
  useEffect(() => {
    if (!id) return;
    const ac = new AbortController();
    let t: ReturnType<typeof setTimeout>;
    const load = async () => {
      try {
        const { op } = await api.get<{ op: OpView }>(`/ops/${encodeURIComponent(id)}`, ac.signal);
        const kind: OpKind = op.state === 'applied' ? 'done' : op.state === 'failed' || op.state === 'rejected' ? 'failed' : op.state === 'pending' || op.state === 'running' ? 'running' : 'unknown';
        setR({ kind, op });
        if (kind === 'running') t = setTimeout(() => void load(), 5000);
      } catch (e) {
        if (!ac.signal.aborted) setR({ kind: 'unknown' });
      }
    };
    void load();
    return () => (ac.abort(), clearTimeout(t));
  }, [id]);
  return r;
}

function ProposalCard({ p, after, onChanged, setProp }: { p: AiProposal; after?: AiProposal; onChanged: () => void; setProp: (p: AiProposal) => void }) {
  const m = useMutation();
  const [confirm, setConfirm] = useState('');
  const [edit, setEdit] = useState<Set<string>>();
  const [editErr, setEditErr] = useState<unknown>();
  const [diff, setDiff] = useState(false);
  const [rejErr, setRejErr] = useState<unknown>();
  // 앞 제안이 승인돼야 누를 수 있다. 그 작업이 아직 끝나지 않았으면 데몬이 409 waiting으로 막는다
  const waiting = !!after && after.state !== 'approved';
  const title = `제안 작업 ${p.index}/${p.total} · ${p.title}`;
  const [tone, label] = IMPACT[p.impact];
  const opRes = useOpState(p.state === 'approved' && !m.op ? p.op : undefined);

  const approve = async () => {
    const v = await sendOp(m, `/ai/proposals/${encodeURIComponent(p.id)}/approve`, { basisHash: p.basisHash, ...(p.irreversible ? { confirmName: confirm } : {}) });
    if (v) onChanged();
  };
  // 화면 API가 4xx로 거절하면 데몬이 제안을 무효로 바꾼다. 카드를 다시 읽되 오류는 그대로 보인다
  useEffect(() => {
    if (m.error instanceof ApiError && m.error.status >= 400 && m.error.status < 500 && !['proposal-changed', 'waiting', 'expired', 'confirm-name'].includes(m.error.code)) onChanged();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m.error]);
  useEffect(() => {
    if (m.op && opDone(m.op)) onChanged();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m.op?.state]);
  useEffect(() => {
    if (m.mcp) onChanged();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m.mcp]);
  // MCP 도구 호출 결과: 이번 승인 응답, 없으면 제안의 reason
  // 데몬 제안 view의 mcp는 {server, tool}뿐이다. 승인된 카드는 reason이 비면 성공, 있으면 실패
  const mcpRes = m.mcp ?? (p.mcp && p.state === 'approved' ? (p.mcp.ok !== undefined ? { ok: p.mcp.ok, server: p.mcp.server, tool: p.mcp.tool, error: p.mcp.error } : { ok: !p.reason, server: p.mcp.server, tool: p.mcp.tool, error: p.reason || undefined }) : undefined);

  // 승인·거절·만료가 끝난 카드
  if (p.state !== 'pending' && !m.op) {
    const [t2, l2, cls] =
      p.state === 'approved' && p.mcp ? (mcpRes ? (mcpRes.ok ? (['ok', '승인됨 · 호출 성공', 'done'] as const) : (['er', '승인됨 · 호출 실패', 'done'] as const)) : (['un', '승인됨 · 결과 모름', 'done'] as const)) : p.state === 'approved' ? ([...APPROVED[opRes.kind], 'done'] as const) : p.state === 'rejected' ? (['un', '거절됨', 'off'] as const) : p.state === 'expired' ? (['un', '만료됨', 'off'] as const) : (['er', '무효', 'off'] as const);
    return (
      <div className={`ap ${cls}`}>
        <header>
          <b>{title}</b>
          <Badge tone={t2}>{l2}</Badge>
        </header>
        <div className="bd">
          <span className="small">
            {p.state === 'approved' && (
              <>
                {p.decidedBy}가 {fmtTime(p.decidedAt)}에 승인{p.op && <> · 작업 <OpId id={p.op} /></>}
                {p.mcp ? (
                  <>
                    {' '}
                    · <span className="mono">mcp.{p.mcp.server}.{p.mcp.tool}</span> 호출{mcpRes ? (mcpRes.ok ? ' 성공' : ` 실패${mcpRes.error ? `: ${mcpRes.error}` : ''}`) : ''} · <Link to="/system/ai/mcp">MCP 설정</Link>
                  </>
                ) : (
                  <>
                    {' '}
                    · <Link to="/system/ops">작업 기록</Link>
                  </>
                )}
                {!p.mcp && opRes.kind === 'failed' && <span style={{ display: 'block', color: 'var(--er)' }}>작업이 실패했습니다{opRes.op?.errorCode ? ` (${opRes.op.errorCode})` : ''}. 작업 기록에서 원인을 볼 수 있습니다.</span>}
                {!p.mcp && opRes.kind === 'unknown' && <span className="muted" style={{ display: "block" }}>작업 결과를 아직 읽지 못했습니다(미실행 증거 아님). 작업 기록에서 확인하세요.</span>}
              </>
            )}
            {p.state === 'rejected' && (
              <>
                {p.decidedBy}가 {fmtTime(p.decidedAt)}에 거절{p.reason ? ` · 사유: ${p.reason}` : ''}
              </>
            )}
            {p.state === 'expired' && '승인하지 않은 채 10분이 지나 만료됐습니다. 아무것도 실행하지 않았습니다.'}
            {p.state === 'invalid' && (m.error !== undefined ? '실행이 거절돼 이 제안은 더 쓸 수 없습니다. 코디네이터에게 다시 물어보세요.' : '대상이 바뀌어 이 제안은 더 쓸 수 없습니다. 코디네이터에게 다시 물어보세요.')}
          </span>
          {p.state === 'invalid' && m.error !== undefined && <MutationError error={m.error} />}
        </div>
      </div>
    );
  }

  const changed = m.error instanceof ApiError && m.error.code === 'proposal-changed';
  const expired = m.error instanceof ApiError && (m.error.code === 'expired' || m.error.status === 410);
  const notYet = m.error instanceof ApiError && m.error.code === 'waiting';
  const saveEdit = async () => {
    setEditErr(undefined);
    try {
      const np = await editProposal(p.id, { ...p.payload, items: [...edit!] });
      setProp(np);
      setEdit(undefined);
    } catch (e) {
      setEditErr(e);
      // 대상(경로 값)은 바꿀 수 없다: 수정 칸을 닫고 카드 아래에 이유를 남긴다
    if (e instanceof ApiError && e.code === 'target-changed') setEdit(undefined);
    }
  };
  const itemsRow = p.items ? p.preview.findIndex((r) => r.value.startsWith(`${p.items!.length}개`)) : -1;
  return (
    <div className={`ap${waiting ? ' wait' : ''}`}>
      <header>
        <b>{title}</b>
        <span className="row" style={{ gap: 6 }}>
          {p.edited && <Badge tone="pr">사용자 수정</Badge>}
          <Badge tone={tone}>{label}</Badge>
        </span>
      </header>
      <div className="bd">
        {edit ? (
          <div className="col" style={{ gap: 6 }}>
            <span className="small">
              작업 <span className="mono">{p.tool}</span> · {p.items!.length}개 → <b>{edit.size}개</b>
            </span>
            <div className="ltbl" style={{ maxHeight: 200, overflowY: 'auto' }}>
              {p.items!.map((it) => (
                <label key={it.name} className="check" style={{ padding: '5px 10px', borderTop: '1px solid var(--line-2)' }}>
                  <input
                    type="checkbox"
                    checked={edit.has(it.name)}
                    onChange={(e) => {
                      const n = new Set(edit);
                      if (e.target.checked) n.add(it.name);
                      else n.delete(it.name);
                      setEdit(n);
                    }}
                  />
                  <span className="mono grow">{it.name}</span>
                  {it.size !== undefined && <span className="muted small">{fmtBytes(it.size)}</span>}
                </label>
              ))}
            </div>
            <span className="muted small">수정한 카드는 ‘사용자 수정’ 표시가 붙고 다시 승인해야 실행됩니다.</span>
            {editErr !== undefined && <div className="note er small">{errorText(editErr).message}</div>}
          </div>
        ) : (
          <dl className="kv2 c80" style={{ fontSize: 12, gridTemplateColumns: '96px minmax(0, 1fr)' }}>
            {p.preview.map((r, i) => (
              <Fragment key={i}>
                <dt>{r.label}</dt>
                <dd className={/^[a-z.]+$/.test(r.value) || r.value.includes(':') ? 'mono' : undefined}>
                  {r.value} {i === itemsRow && <ItemsPop p={p} />}
                </dd>
              </Fragment>
            ))}
            {p.expected !== undefined && p.state === 'pending' && !m.op && (
              <>
                <dt>기준 버전</dt>
                <dd className="mono">
                  자원 {p.expected} · {until(p.expiresAt).replace(' 후', ' 남음')}
                </dd>
              </>
            )}
          </dl>
        )}
        {waiting && <span className="muted small">{after!.index}번이 끝난 뒤 승인할 수 있습니다. {after!.index}번이 실패하거나 결과를 모르면 보내지 않습니다.</span>}
        {p.irreversible && !m.op && (
          <label className="field" style={{ fontSize: 12 }}>
            확인하려면 {p.confirmName} {eulReul(p.confirmName ?? '')} 입력하세요
            <input className="mono" value={confirm} onChange={(e) => setConfirm(e.target.value.trim())} />
          </label>
        )}
        {changed && <div className="note wa small">그사이 제안 내용이나 기준 버전이 바뀌었습니다. ‘새로 읽기’로 카드를 다시 읽고 확인한 뒤 승인하세요.</div>}
        {expired && <div className="note wa small">제안이 만료됐습니다. 아무것도 실행하지 않았습니다.</div>}
        {notYet && <div className="note wa small">앞 제안의 작업이 아직 끝나지 않았습니다. 끝난 뒤 다시 누르세요.</div>}
        {!changed && !expired && !notYet && <MutationError error={m.error} />}
        {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
        {m.op && opDone(m.op) && <span className="small ok-text">✓ {m.op.id} 완료.{p.total > p.index ? ` ${p.index + 1}번 제안을 승인할 수 있습니다.` : ''}</span>}
        {rejErr !== undefined && <div className="note er small">{errorText(rejErr).message}</div>}
      </div>
      {!m.op && (
        <footer>
          {edit ? (
            <>
              <button className="btn sm" onClick={() => setEdit(undefined)}>
                취소
              </button>
              <button className="btn sm primary" disabled={!edit.size} onClick={() => void saveEdit()}>
                고친 내용으로 바꾸기
              </button>
            </>
          ) : (
            <>
              <RejectButton onReject={async (reason) => {
                setRejErr(undefined);
                try {
                  await rejectProposal(p.id, reason);
                  onChanged();
                } catch (e) {
                  setRejErr(e);
                }
              }} />
              {p.diff ? (
                <button className="btn sm" onClick={() => setDiff(true)}>
                  변경점 열기
                </button>
              ) : p.items ? (
                <button className="btn sm" onClick={() => setEdit(new Set(p.items!.map((x) => x.name)))}>
                  수정
                </button>
              ) : null}
              <button
                className="btn sm primary"
                disabled={m.busy || waiting || (p.irreversible && confirm !== p.confirmName)}
                onClick={() => {
                  if (changed) {
                    m.reset();
                    onChanged();
                    return;
                  }
                  void approve();
                }}
              >
                {m.busy ? '보내는 중…' : changed ? '새로 읽기' : '승인하고 실행'}
              </button>
            </>
          )}
        </footer>
      )}
      {diff && (
        <Drawer title={`${p.target} 변경점 · 제안 작업 ${p.index}/${p.total}`} onClose={() => setDiff(false)}>
          <pre className="diff">
            {p.diff!.split('\n').map((l, i) => (
              <div key={i} className={l.startsWith('+') && !l.startsWith('+++') ? 'a' : l.startsWith('-') && !l.startsWith('---') ? 'r' : 'c'}>
                {l || ' '}
              </div>
            ))}
          </pre>
        </Drawer>
      )}
    </div>
  );
}

function ItemsPop({ p }: { p: AiProposal }) {
  return (
    <Popover button="목록 보기" className="linkish" label="지울 목록" width={380}>
      {() => (
        <div className="col" style={{ gap: 4, padding: 6, fontSize: 12 }}>
          <b style={{ fontSize: 13 }}>{p.preview.find((r) => r.value.startsWith(`${p.items!.length}개`))?.label ?? '목록'} {p.items!.length}개</b>
          <div className="gtbl">
            <div className="gr th items">
              <span>이름</span>
              <span>크기</span>
              <span>마지막 사용</span>
            </div>
            {p.items!.map((it) => (
              <div key={it.name} className="gr items">
                <span className="mono el">{it.name}</span>
                <span>{it.size !== undefined ? fmtBytes(it.size) : '—'}</span>
                <span className="muted">{it.lastUsed ? fmtTime(it.lastUsed) : '—'}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Popover>
  );
}

// ── 휴대폰 제안 작업 카드 · 자세히 (캔버스 UI-M6 ①②) ──
function MProposalCard({ p, after, onChanged }: { p: AiProposal; after?: AiProposal; onChanged: () => void }) {
  const m = useMutation();
  const compose = useContext(ComposeCtx);
  const [detail, setDetail] = useState(false);
  const [sheet, setSheet] = useState<'confirm' | 'reject'>();
  const [confirm, setConfirm] = useState('');
  const [reason, setReason] = useState('');
  const [rejBusy, setRejBusy] = useState(false);
  const [rejErr, setRejErr] = useState<unknown>();
  const [more, setMore] = useState(false);
  const waiting = !!after && after.state !== 'approved';
  const [tone, label] = IMPACT[p.impact];
  useEffect(() => {
    if (m.error instanceof ApiError && m.error.status >= 400 && m.error.status < 500 && !['proposal-changed', 'waiting', 'expired', 'confirm-name'].includes(m.error.code)) onChanged();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m.error]);
  useEffect(() => {
    if (m.op && opDone(m.op)) onChanged();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m.op?.state]);
  useEffect(() => {
    if (m.mcp) onChanged();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m.mcp]);
  const changed = m.error instanceof ApiError && m.error.code === 'proposal-changed';
  const expired = m.error instanceof ApiError && (m.error.code === 'expired' || m.error.status === 410);
  const notYet = m.error instanceof ApiError && m.error.code === 'waiting';
  const approve = async () => {
    const v = await sendOp(m, `/ai/proposals/${encodeURIComponent(p.id)}/approve`, { basisHash: p.basisHash, ...(p.irreversible ? { confirmName: confirm } : {}) });
    setSheet(undefined);
    if (v) onChanged();
  };
  const go = () => {
    if (changed) {
      m.reset();
      onChanged();
      return;
    }
    // 되돌릴 수 없는 작업은 이름 입력 칸이 있는 자세히 화면에서만 승인한다
    if (p.irreversible && confirm !== p.confirmName) return setDetail(true);
    if (needsConfirm(p.impact)) setSheet('confirm');
    else void approve();
  };
  const reject = async () => {
    setRejBusy(true);
    setRejErr(undefined);
    try {
      await rejectProposal(p.id, reason.trim());
      setSheet(undefined);
      setDetail(false);
      onChanged();
    } catch (e) {
      setRejErr(e);
    } finally {
      setRejBusy(false);
    }
  };
  const left = p.expiresAt ? until(p.expiresAt).replace(' 후', ' 남음') : '';
  // 요약 한 줄 (UI-M6 ①): 도구 이름은 빼고 앞 세 줄. 셋째 줄부터는 항목 이름을 붙인다 (예: '실행 중 영향 없음')
  const rows = p.preview.filter((r) => !/^[a-z._]+$/.test(r.value)).slice(0, 3);
  const summary = [...rows.map((r, i) => (i < 2 ? r.value : `${r.label} ${r.value.replace(/\s*\(.*\)$/, '')}`)), left].filter(Boolean).join(' · ');
  const itemsLabel = p.items ? (p.preview.find((r) => r.value.startsWith(`${p.items!.length}개`))?.label ?? '목록') : '';
  const notes = (
    <>
      {changed && <div className="bn warn">그사이 제안 내용이나 기준 버전이 바뀌었습니다. ‘새로 읽기’로 카드를 다시 읽고 확인한 뒤 승인하세요.</div>}
      {expired && <div className="bn warn">제안이 만료됐습니다. 아무것도 실행하지 않았습니다.</div>}
      {notYet && <div className="bn warn">앞 제안의 작업이 아직 끝나지 않았습니다. 끝난 뒤 다시 누르세요.</div>}
      {!changed && !expired && !notYet && <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
      {rejErr !== undefined && <div className="note er small">{errorText(rejErr).message}</div>}
    </>
  );
  const approveText = m.busy ? '보내는 중…' : changed ? '새로 읽기' : '승인하고 실행';
  return (
    <>
      <div className={`mc${waiting ? '' : ' ap'}`}>
        <div className="hd">
          <b>
            {p.index}/{p.total} · {p.title}
          </b>
          <span className="row" style={{ gap: 6, flex: 'none' }}>
            {p.edited && <Badge tone="pr">사용자 수정</Badge>}
            <Badge tone={tone}>{label}</Badge>
          </span>
        </div>
        <div className="ln">{waiting ? `${after!.index}번이 끝난 뒤 승인할 수 있습니다.` : summary}</div>
        {!detail && notes}
        {!waiting && !m.op && (
          <div className="ft">
            <button type="button" className="mbtn sm" onClick={() => setSheet('reject')}>
              거절
            </button>
            <button type="button" className="mbtn sm" onClick={() => setDetail(true)}>
              자세히
            </button>
            <button type="button" className="mbtn sm pri" disabled={m.busy} onClick={go}>
              {approveText}
            </button>
          </div>
        )}
      </div>
      {detail && (
        <aside className="m-sub" aria-label="제안 작업 자세히">
          <header className="m-top">
            <button type="button" className="ic" aria-label="뒤로" onClick={() => setDetail(false)}>
              ‹
            </button>
            <span className="tt">
              제안 작업 {p.index}/{p.total}
              <span className="sub">{p.title}</span>
            </span>
          </header>
          <div className="m-body">
            <div className={`mc${waiting ? '' : ' ap'}`}>
              <div className="hd">
                <b>{p.title}</b>
                <span className="row" style={{ gap: 6, flex: 'none' }}>
                  {p.edited && <Badge tone="pr">사용자 수정</Badge>}
                  <Badge tone={tone}>{label}</Badge>
                </span>
              </div>
              <dl className="mkv">
                {p.preview.map((r, i) => (
                  <Fragment key={i}>
                    <dt>{r.label}</dt>
                    <dd className={/^[a-z.]+$/.test(r.value) ? 'mono' : undefined}>{r.value}</dd>
                  </Fragment>
                ))}
                {p.expected !== undefined && !m.op && (
                  <>
                    <dt>기준 버전</dt>
                    <dd>
                      자원 {p.expected}
                      {left ? ` · ${left}` : ''}
                    </dd>
                  </>
                )}
              </dl>
            </div>
            {waiting && <div className="bn info">{after!.index}번이 끝난 뒤 승인할 수 있습니다. {after!.index}번이 실패하거나 결과를 모르면 보내지 않습니다.</div>}
            {p.items && (
              <>
                <div className="m-sec">
                  <span>
                    {itemsLabel} {p.items.length}
                  </span>
                </div>
                <div className="li">
                  {(more ? p.items : p.items.slice(0, 3)).map((it) => (
                    <div key={it.name} className="mono el" style={{ fontSize: 12 }}>
                      {it.name}
                      {it.size !== undefined ? ` · ${fmtBytes(it.size)}` : ''}
                    </div>
                  ))}
                  {!more && p.items.length > 3 && (
                    <button type="button" style={{ color: 'var(--accent)', fontSize: 13 }} onClick={() => setMore(true)}>
                      {p.items.length - 3}개 더 보기
                    </button>
                  )}
                </div>
              </>
            )}
            {p.diff && (
              <>
                <div className="m-sec">
                  <span>변경점 · {p.target}</span>
                </div>
                <details className="m-diff">
                  <summary>{p.diff.split('\n').filter((l) => /^[+-](?![+-]{2})/.test(l)).length}줄 바뀜 · 펼치기</summary>
                  <pre className="diff">
                    {p.diff.split('\n').map((l, i) => (
                      <div key={i} className={l.startsWith('+') && !l.startsWith('+++') ? 'a' : l.startsWith('-') && !l.startsWith('---') ? 'r' : 'c'}>
                        {l || ' '}
                      </div>
                    ))}
                  </pre>
                </details>
                <div className="muted small">넓게 보려면 넓은 화면에서</div>
              </>
            )}
            {p.irreversible && !m.op && (
              <label className="field">
                확인하려면 {p.confirmName} {eulReul(p.confirmName ?? '')} 입력하세요
                <input className="mono" value={confirm} autoCapitalize="off" autoCorrect="off" onChange={(e) => setConfirm(e.target.value.trim())} />
              </label>
            )}
            {notes}
            {!m.op && (
              <div className="m-stick">
                <div className="mbar">
                  <button type="button" className="mbtn fl" onClick={() => setSheet('reject')}>
                    거절
                  </button>
                  <button
                    type="button"
                    className="mbtn fl"
                    onClick={() => {
                      compose(`제안 작업 ${p.index}/${p.total} ‘${p.title}’${eulReul(p.title)} 이렇게 고쳐 줘: `);
                      setDetail(false);
                    }}
                  >
                    수정
                  </button>
                  <button type="button" className="mbtn fl pri" disabled={m.busy || waiting || (p.irreversible && confirm !== p.confirmName)} onClick={go}>
                    {approveText}
                  </button>
                </div>
              </div>
            )}
          </div>
        </aside>
      )}
      {sheet === 'confirm' && <ConfirmApproveSheet what={p.title} impact={p.impact} busy={m.busy} onClose={() => setSheet(undefined)} onConfirm={() => void approve()} />}
      {sheet === 'reject' && (
        <Sheet
          title="제안 거절"
          onClose={() => setSheet(undefined)}
          footer={
            <>
              <button type="button" className="mbtn" onClick={() => setSheet(undefined)} disabled={rejBusy}>
                취소
              </button>
              <button type="button" className="mbtn pri" onClick={() => void reject()} disabled={rejBusy}>
                {rejBusy ? '보내는 중…' : '거절'}
              </button>
            </>
          }
        >
          <label className="field">
            사유 (선택, 코디네이터에게 전달)
            <input value={reason} maxLength={256} onChange={(e) => setReason(e.target.value)} />
          </label>
          <span className="muted small">거절한 제안은 대화에 ‘거절됨’으로 남고 코디네이터는 다른 방법을 제안할 수 있습니다.</span>
          {rejErr !== undefined && <div className="note er small">{errorText(rejErr).message}</div>}
        </Sheet>
      )}
    </>
  );
}

function RejectButton({ onReject }: { onReject: (reason: string) => Promise<void> }) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  return (
    <Popover button="거절" className="btn sm" label="제안 거절" width={300} align="right">
      {(close) => (
        <div className="col" style={{ gap: 8, padding: 6 }}>
          <b style={{ fontSize: 13 }}>제안 거절</b>
          <label className="field" style={{ fontSize: 12 }}>
            사유 (선택, 코디네이터에게 전달)
            <input value={reason} maxLength={256} onChange={(e) => setReason(e.target.value)} />
          </label>
          <span className="muted small">거절한 제안은 대화에 ‘거절됨’으로 남고 코디네이터는 다른 방법을 제안할 수 있습니다.</span>
          <div className="row" style={{ justifyContent: 'flex-end', gap: 6 }}>
            <button className="btn sm" onClick={close}>
              취소
            </button>
            <button
              className="btn sm primary"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                await onReject(reason.trim());
                setBusy(false);
                close();
              }}
            >
              거절
            </button>
          </div>
        </div>
      )}
    </Popover>
  );
}

// ── 입력 칸 ──
const COMMANDS: [string, string][] = [
  ['/화면', '지금 화면을 다시 맥락으로'],
  ['/앱', '앱을 맥락에 추가'],
  ['/새 대화', ''],
  ['/요약', '지금 대화 요약'],
];
function Composer({ text, setText, busy, variant, ctxPath, onSend, onStop, onNew }: { text: string; setText: (s: string) => void; busy: boolean; variant: Variant; ctxPath?: string; onSend: (t: string) => void; onStop: () => void; onNew: () => void }) {
  const loc = useLocation();
  const cmds = text.startsWith('/') && !text.includes(' ') ? COMMANDS.filter(([c]) => c.startsWith(text)) : [];
  const run = (c: string) => {
    if (c === '/새 대화') {
      setText('');
      onNew();
    } else if (c === '/요약') onSend('지금까지 대화를 요약해 줘');
    else if (c === '/화면') onSend(`지금 화면(${screenContext(ctxPath ?? loc.pathname).screen})을 다시 읽어 줘`);
    else setText('@');
  };
  return (
    <div className={`coord-foot ${variant}`}>
      {cmds.length > 0 && (
        <div className="menu popbox" style={{ position: 'static', boxShadow: 'none' }}>
          {cmds.map(([c, d]) => (
            <button key={c} type="button" className="pick" onClick={() => run(c)}>
              <span className="mono">{c}</span>
              <span className="muted small">{d}</span>
            </button>
          ))}
        </div>
      )}
      {variant === 'phone' ? (
        <div className="m-inp">
          <input
            placeholder="메시지 보내기"
            value={text}
            aria-label="코디네이터에게 묻기"
            enterKeyHint="send"
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key !== 'Enter' || e.nativeEvent.isComposing) return;
              if (cmds.length === 1 || COMMANDS.some(([c]) => c === text)) run(cmds[0]?.[0] ?? text);
              else onSend(text);
            }}
          />
          {busy ? (
            <button type="button" className="mbtn" aria-label="멈춤" onClick={onStop}>
              ■
            </button>
          ) : (
            <button type="button" className="mbtn pri" aria-label="보내기" disabled={!text.trim()} onClick={() => onSend(text)}>
              ↑
            </button>
          )}
        </div>
      ) : (
      <div className="row" style={{ gap: 6, flexWrap: 'nowrap' }}>
        <input
          className="grow"
          placeholder={variant === 'full' ? '이어서 묻기' : '무엇이든 물어보세요. @로 앱·서버를 집어 넣을 수 있어요'}
          value={text}
          aria-label="코디네이터에게 묻기"
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key !== 'Enter' || e.nativeEvent.isComposing) return;
            if (cmds.length === 1 || COMMANDS.some(([c]) => c === text)) run(cmds[0]?.[0] ?? text);
            else onSend(text);
          }}
        />
        {busy ? (
          <button className="btn" onClick={onStop}>
            멈춤
          </button>
        ) : (
          <button className="btn primary" disabled={!text.trim()} onClick={() => onSend(text)}>
            보내기
          </button>
        )}
      </div>
      )}
      {variant === 'panel' && <span className="muted" style={{ fontSize: 11 }}>코디네이터는 읽기만 스스로 하고, 바꾸는 작업은 항상 승인 카드를 거칩니다. 비밀값은 읽지 못합니다.</span>}
    </div>
  );
}
