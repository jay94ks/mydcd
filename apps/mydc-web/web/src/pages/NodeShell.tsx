// SPDX-License-Identifier: Apache-2.0

// 서버 셸 (UI-1A, REQ-67, 캔버스 NodeShell · NodeShellIx v154)
import { forwardRef, useCallback, useEffect, useImperativeHandle, useRef, useState, type ReactNode } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { ApiError, newOpId } from '../api/client';
import { users } from '../api/endpoints';
import {
  NODE_SHELL_PATH,
  SHELL_MODE_KO,
  explainRefusal,
  notReadyText,
  nodeShellClosePath,
  nodeShellGrantPath,
  nodeShellNodePath,
  nodeShellPolicy,
  nodeShellSessions,
  canCloseSession,
  SESSION_STATE_KO,
  openNodeShell,
  type NodeShellNode,
  type NodeShellPolicy,
  type NodeShellSession,
  type ShellHandle,
  type ShellMode,
  type ShellRefusal,
} from '../api/nodeShell';
import type { UserRecord } from '../api/types';
import { useSession } from '../auth/session';
import { Dialog, ConfirmDialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { Badge, Card, HelpBox, PageHeader } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { DEFAULT_POLL_MS, usePoll, type Loaded } from '../lib/usePoll';
import { ago, fmtBytes } from '../lib/format';
import { eulReul, eunNeun, iGa } from '../lib/josa';

// ── 공통 ──

/** 정책을 읽는다. 셸 권한이 없는 사람은 403이라 데이터 대신 forbidden으로 둔다 */
export function useShellPolicy(poll = DEFAULT_POLL_MS) {
  const q = usePoll((s) => nodeShellPolicy(s), [], poll);
  const forbidden = q.error instanceof ApiError && q.error.status === 403;
  return { q, forbidden };
}

export const idleText = (sec: number) => (sec % 86400 === 0 ? `${sec / 86400}일` : sec % 3600 === 0 ? `${sec / 3600}시간` : sec >= 60 ? `${Math.round(sec / 60)}분` : `${sec}초`);

/** 연 지 얼마나 됐는지: 18분째, 1시간 4분째 */
export function elapsed(iso: string, now = Date.now()): string {
  const m = Math.max(0, Math.floor((now - Date.parse(iso)) / 60000));
  if (m < 1) return '방금 열림';
  if (m < 60) return `${m}분째`;
  const h = Math.floor(m / 60);
  return `${h}시간${m % 60 ? ` ${m % 60}분` : ''}째`;
}

/** 서버 셸 상태 꼬리표(서버 상세 머리) */
export function ShellBadges({ node }: { node: string }) {
  const { q } = useShellPolicy();
  const n = q.data?.nodes.find((x) => x.node === node);
  if (!n) return null;
  const how = n.shell === 'inherit' ? '클러스터 정책' : '이 서버 설정';
  return (
    <>
      <Badge tone={n.enabled ? 'ok' : 'un'}>{`셸 ${n.enabled ? '켜짐' : '꺼짐'} · ${how}`}</Badge>
      {n.sudo && <Badge tone="wa">sudo 허용</Badge>}
    </>
  );
}

/** 셸을 열 수 없는 이유(서버 목록 ⋯ 메뉴·셸 탭) */
export function shellBlocked(node: string, p: NodeShellPolicy | undefined, forbidden: boolean): string | undefined {
  if (forbidden) return '이 서버의 셸 권한이 없습니다';
  if (!p) return '셸 설정을 읽는 중입니다';
  const n = p.nodes.find((x) => x.node === node);
  if (!n) return '이 서버의 셸 권한이 없습니다';
  if (!n.enabled) return `${node}${eunNeun(node)} 셸이 꺼져 있습니다`;
  if (!n.ready) return `${node}의 전용 계정이 준비되지 않았습니다`;
  return undefined;
}

function disabledBand(n: NodeShellNode) {
  const why = n.shell === 'off' ? '서버 설정 ‘이 서버만 끄기’' : '클러스터 정책 꺼짐';
  return (
    <div className="bn warn">
      {n.node}
      {eunNeun(n.node)} 셸이 꺼져 있습니다({why}). 시스템 관리자가 켜야 열 수 있습니다.
    </div>
  );
}

// ── 터미널 하나 ──

interface TermApi {
  clear(): void;
  copy(): Promise<void>;
  close(): void;
  focus(): void;
}
interface TermStats {
  rx: number;
  tx: number;
}

type Ended = { kind: 'end'; reason: string; code: number; by?: string; self?: boolean } | { kind: 'error'; code: string } | { kind: 'refused'; why: ShellRefusal; notReady?: string; max?: number };

/** 세션 하나의 화면. opId가 바뀌면 같은 화면에 다시 연다(앞의 내용은 탭을 닫을 때까지 남는다). */
const ShellTerm = forwardRef<TermApi, { node: string; me: string; opId: string; fontSize: number; visible: boolean; stats: TermStats; onSession: (s: NodeShellSession) => void; onEnded: (e: Ended) => void }>(function ShellTerm(
  { node, me, opId, fontSize, visible, stats, onSession, onEnded },
  ref,
) {
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal>();
  const fit = useRef<FitAddon>();
  const handle = useRef<ShellHandle>();
  const cb = useRef({ onSession, onEnded });
  cb.current = { onSession, onEnded };

  useEffect(() => {
    const t = new Terminal({ fontSize, fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", cursorBlink: true, scrollback: 5000, theme: { background: '#0E1116', foreground: '#D5DAE1' } });
    const f = new FitAddon();
    t.loadAddon(f);
    if (host.current) t.open(host.current);
    term.current = t;
    fit.current = f;
    // 복사 Ctrl+Shift+C · 붙여넣기 Ctrl+Shift+V. 터미널 안의 Esc는 바깥 창을 닫지 않는다.
    t.attachCustomKeyEventHandler((e) => {
      if (e.type !== 'keydown') return true;
      if (e.key === 'Escape') e.stopPropagation();
      if (e.ctrlKey && e.shiftKey && e.code === 'KeyC') {
        const s = t.getSelection();
        if (s) void navigator.clipboard?.writeText(s);
        return false;
      }
      if (e.ctrlKey && e.shiftKey && e.code === 'KeyV') {
        void navigator.clipboard?.readText().then((s) => s && handle.current?.stdin(s));
        return false;
      }
      return true;
    });
    const onData = t.onData((d) => {
      stats.tx += new TextEncoder().encode(d).length;
      handle.current?.stdin(d);
    });
    const onResize = t.onResize(({ cols, rows }) => handle.current?.resize(cols, rows));
    const ro = new ResizeObserver(() => host.current?.offsetParent && fit.current?.fit());
    if (host.current) ro.observe(host.current);
    return () => {
      ro.disconnect();
      onData.dispose();
      onResize.dispose();
      t.dispose();
    };
    // 글꼴 크기는 아래에서 바꾼다
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const t = term.current;
    if (!t) return;
    t.options.fontSize = fontSize;
    if (visible) fit.current?.fit();
  }, [fontSize, visible]);

  useEffect(() => {
    const t = term.current;
    if (!t) return;
    fit.current?.fit();
    let gone = false;
    // 바로 열지 않고 한 박자 뒤에 연다. 개발 모드의 이중 effect가 같은 opId로 두 번 열지 않게.
    const timer = window.setTimeout(() => void start(), 0);
    const start = () => openNodeShell(node, { opId, cols: Math.max(1, t.cols), rows: Math.max(1, t.rows) }, (e) => {
      if (gone) return;
      if (e.type === 'session') {
        cb.current.onSession(e.session);
      } else if (e.type === 'stdout') {
        stats.rx += e.bytes.length;
        t.write(e.bytes);
      } else if (e.type === 'end') {
        handle.current = undefined;
        cb.current.onEnded({ kind: 'end', reason: e.reason, code: e.code, by: e.closedBy?.username, self: !!e.closedBy && e.closedBy.user === me });
      } else if (e.type === 'error') {
        handle.current = undefined;
        cb.current.onEnded({ kind: 'error', code: e.code });
      } else if (e.code) {
        handle.current = undefined;
        cb.current.onEnded({ kind: 'refused', why: e.code as ShellRefusal, notReady: notReadyText(e.message) });
      } else {
        handle.current = undefined;
        void explainRefusal(node, me).then((r) => !gone && cb.current.onEnded({ kind: 'refused', why: r.code, notReady: notReadyText(r.notReady), max: r.max }));
      }
    }).then((h) => {
      if (gone) h.close();
      else {
        handle.current = h;
        t.focus();
      }
    });
    return () => {
      gone = true;
      window.clearTimeout(timer);
      // 탭을 닫거나 화면을 떠나면 셸도 닫는다.
      handle.current?.close();
      handle.current = undefined;
    };
  }, [node, me, opId, stats]);

  useImperativeHandle(ref, () => ({
    clear: () => term.current?.clear(),
    copy: async () => {
      const t = term.current;
      if (!t) return;
      t.selectAll();
      const s = t.getSelection();
      t.clearSelection();
      await navigator.clipboard?.writeText(s);
    },
    close: () => handle.current?.close(),
    focus: () => term.current?.focus(),
  }));

  return <div ref={host} className="shell-term" style={{ display: visible ? undefined : 'none' }} />;
});

// ── 셸 탭 ──

interface Tab {
  key: number;
  name: string;
  opId: string;
  phase: 'opening' | 'open' | 'ended';
  session?: NodeShellSession;
  ended?: Ended;
  /** 내가 연결 끊기로 닫았는지 */
  byMe?: boolean;
  /** 한 번이라도 열렸는지(아니면 거절 띠만 보인다) */
  everOpened?: boolean;
  stats: TermStats;
}

const FONT_SIZES = [12, 13, 14, 16];

/** 서버 상세 › 셸 탭 */
export function NodeShellTab({ node }: { node: string }) {
  const session = useSession();
  const me = session.user.id;
  const admin = !!session.user.systemAdmin;
  const { q, forbidden } = useShellPolicy();
  const sessions = usePoll((s) => nodeShellSessions(s), [], DEFAULT_POLL_MS);
  const n = q.data?.nodes.find((x) => x.node === node);
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [active, setActive] = useState<number>();
  const [font, setFont] = useState(13);
  const [renaming, setRenaming] = useState<number>();
  const seq = useRef(0);
  const terms = useRef(new Map<number, TermApi>());
  const card = useRef<HTMLElement>(null);
  const [params, setParams] = useSearchParams();

  const patch = useCallback((key: number, f: (t: Tab) => Partial<Tab>) => setTabs((ts) => ts.map((t) => (t.key === key ? { ...t, ...f(t) } : t))), []);
  const open = useCallback(() => {
    const key = ++seq.current;
    setTabs((ts) => [...ts, { key, name: `세션 ${key}`, opId: newOpId(), phase: 'opening', stats: { rx: 0, tx: 0 } }]);
    setActive(key);
  }, []);
  const reopen = (key: number) => patch(key, () => ({ opId: newOpId(), phase: 'opening', ended: undefined, byMe: false, session: undefined, stats: { rx: 0, tx: 0 } }));
  const closeTab = (key: number) => {
    setTabs((ts) => {
      const rest = ts.filter((t) => t.key !== key);
      if (active === key) setActive(rest[rest.length - 1]?.key);
      return rest;
    });
    terms.current.delete(key);
    window.setTimeout(() => void sessions.refresh(), 500);
  };
  const disconnect = (key: number) => {
    patch(key, () => ({ byMe: true }));
    terms.current.get(key)?.close();
  };

  // 서버 목록의 '셸 열기'에서 왔으면 바로 하나 연다.
  const ready = !!n && n.enabled && n.ready;
  useEffect(() => {
    if (params.get('new') !== '1' || !ready) return;
    params.delete('new');
    setParams(params, { replace: true });
    open();
  }, [params, ready, open, setParams]);

  const cur = tabs.find((t) => t.key === active);
  const mine = (sessions.data ?? []).filter((s) => s.user === me && s.node === node).length;
  const blocked = shellBlocked(node, q.data, forbidden);
  const fullscreen = () => (document.fullscreenElement ? void document.exitFullscreen() : void card.current?.requestFullscreen?.());

  return (
    <div className="col" style={{ gap: 20 }}>
      <HelpBox terms="셸 (SSH shell) · 세션 (session) · 전용 계정 (mydc-shell) · sudo 허용 (root 전환)">
        <b>이 화면은</b> 이 서버에 SSH로 들어가는 터미널입니다. MyDC가 권한을 확인한 뒤 이 서버의 MyDC 전용 계정(<span className="mono">{q.data?.account ?? 'mydc-shell'}</span>, root 아님)으로 로그인해 줍니다. OS 비밀번호나 키는 넣지 않습니다. root가 필요하면 sudo를 쓰는데, 서버 설정에서 허용한 서버만 됩니다. 입력한 내용과 화면은 기록하지 않고, 누가·언제·얼마나 주고받았는지만 작업 기록에 남습니다.
      </HelpBox>
      {forbidden || (q.data && !n) ? (
        <div className="bn err">
          {node} 셸을 열 권한이 없습니다. 시스템 관리자에게 서버 셸 권한을 요청하세요. <code className="small">forbidden</code>
        </div>
      ) : q.error !== undefined && !q.data ? (
        <ErrorBand error={q.error} what="서버 셸 설정을 읽지 못했습니다" onRetry={q.refresh} />
      ) : n && !n.enabled ? (
        disabledBand(n)
      ) : null}
      <section ref={card} className="card shell-card" style={{ gap: 10 }}>
        <div className="row between" style={{ gap: 8 }}>
          <h2>SSH 세션</h2>
          <span className="row" style={{ gap: 8 }}>
            <button className="btn" disabled={!!blocked} title={blocked} onClick={open}>
              ＋ 새 세션
            </button>
            <Menu label="글꼴 크기" className="btn" button="글꼴 ▾" items={FONT_SIZES.map((s) => ({ label: `${s}px${s === font ? ' ✓' : ''}`, onSelect: () => setFont(s) }))} />
            <button className="btn" disabled={!tabs.length} onClick={fullscreen}>
              ⛶ 전체 화면
            </button>
            <button className="btn danger" disabled={cur?.phase !== 'open'} onClick={() => cur && disconnect(cur.key)}>
              연결 끊기
            </button>
          </span>
        </div>
        {!tabs.length ? (
          <div className="shell-empty">
            <span>{blocked ? blocked + '.' : '열린 세션이 없습니다. ‘＋ 새 세션’을 누르면 이 서버의 전용 계정으로 로그인합니다.'}</span>
            {!blocked && (
              <button className="btn primary" onClick={open}>
                ＋ 새 세션
              </button>
            )}
          </div>
        ) : (
          <div>
            <div className="shell-tabs" role="tablist" aria-label="셸 세션">
              {tabs.map((t) => (
                <span key={t.key} role="tab" aria-selected={t.key === active} className={t.key === active ? 'on' : ''} onClick={() => setActive(t.key)}>
                  {renaming === t.key ? (
                    <input
                      autoFocus
                      defaultValue={t.name}
                      aria-label="세션 이름"
                      onClick={(e) => e.stopPropagation()}
                      onBlur={(e) => (patch(t.key, () => ({ name: e.target.value.trim() || t.name })), setRenaming(undefined))}
                      onKeyDown={(e) => e.key === 'Enter' && (e.currentTarget as HTMLInputElement).blur()}
                    />
                  ) : (
                    <span>
                      {t.name} · {t.session?.account ?? q.data?.account ?? 'mydc-shell'}
                      {t.phase === 'opening' && ' …'}
                      {t.phase === 'ended' && ' (닫힘)'}
                    </span>
                  )}
                  <span className="shell-tab-more" onClick={(e) => e.stopPropagation()}>
                    <Menu
                      label={`${t.name} 메뉴`}
                      className="shell-tab-btn"
                      align="left"
                      items={[
                        { label: '이름 바꾸기', onSelect: () => setRenaming(t.key) },
                        { label: '같은 서버에 새 세션', onSelect: open, disabledReason: blocked },
                        { label: '화면 지우기', onSelect: () => terms.current.get(t.key)?.clear() },
                        { label: '화면 내용 복사', onSelect: () => void terms.current.get(t.key)?.copy() },
                        { sep: true, label: '' },
                        { label: '연결 끊기', onSelect: () => disconnect(t.key), disabledReason: t.phase === 'open' ? undefined : '열린 세션이 아닙니다' },
                      ]}
                    />
                  </span>
                  <button type="button" className="shell-tab-btn" aria-label={`${t.name} 닫기`} onClick={(e) => (e.stopPropagation(), closeTab(t.key))}>
                    ✕
                  </button>
                </span>
              ))}
              <button type="button" className="shell-tab-btn add" aria-label="새 세션" disabled={!!blocked} title={blocked} onClick={open}>
                ＋
              </button>
            </div>
            {cur?.ended && <EndBand tab={cur} node={node} idle={q.data?.idleSeconds} max={q.data?.maxSessions} onReopen={blocked ? undefined : () => reopen(cur.key)} />}
            {tabs.map((t) => (
              <ShellTerm
                key={t.key}
                ref={(x) => (x ? terms.current.set(t.key, x) : undefined)}
                node={node}
                me={me}
                opId={t.opId}
                fontSize={font}
                visible={t.key === active && (t.everOpened || t.ended?.kind !== 'refused')}
                stats={t.stats}
                onSession={(s) => (patch(t.key, () => ({ phase: 'open', session: s, everOpened: true })), void sessions.refresh())}
                onEnded={(e) => (patch(t.key, (x) => ({ phase: 'ended', ended: e, byMe: x.byMe || (e.kind === 'end' && e.self) })), void sessions.refresh(), void q.refresh())}
              />
            ))}
          </div>
        )}
        {cur?.session && cur.phase === 'open' && <StatusBar tab={cur} idle={q.data?.idleSeconds} mine={mine} max={q.data?.maxSessions} />}
      </section>
      <div className="shell-grid">
        {admin && q.data && n && <NodeSettingsCard node={n} policy={q.data} onDone={q.refresh} />}
        <OpenSessionsCard node={node} me={me} admin={admin} q={sessions} />
      </div>
    </div>
  );
}

function EndBand({ tab, node, idle, max, onReopen }: { tab: Tab; node: string; idle?: number; max?: number; onReopen?: () => void }) {
  const e = tab.ended!;
  const id = tab.session?.sessionId ?? '';
  const again = onReopen && e.kind !== 'refused' && (
    <>
      {' '}
      <button type="button" className="linkish" onClick={onReopen}>
        다시 열기
      </button>
    </>
  );
  const band = (tone: 'info' | 'warn' | 'err', body: ReactNode, code?: string) => (
    <div className={`bn ${tone}`} style={{ margin: '0 0 8px' }}>
      {body}
      {code && (
        <>
          {' '}
          <code className="small">{code}</code>
        </>
      )}
      {again}
    </div>
  );
  if (e.kind === 'refused') {
    switch (e.why) {
      case 'forbidden':
        return band('err', `${node} 셸을 열 권한이 없습니다. 시스템 관리자에게 서버 셸 권한을 요청하세요.`, 'forbidden');
      case 'node-shell-disabled':
        return band('warn', `${node}${eunNeun(node)} 셸이 꺼져 있습니다. 시스템 관리자가 켜야 열 수 있습니다.`, 'node-shell-disabled');
      case 'node-shell-not-ready':
        return band('err', `${node}의 전용 계정이 준비되지 않았습니다${e.notReady ? `: ${e.notReady}` : '.'}`, 'node-shell-not-ready');
      case 'limit':
        return band('warn', `${node}에서 내 세션이 이미 ${e.max ?? max ?? '최대'}개입니다. 하나를 닫고 다시 여세요.`, 'limit');
      case 'node-unreachable':
      case undefined:
        return band('err', `${node}${iGa(node)} 응답하지 않습니다.`, 'node-unreachable');
      default:
        return band('err', `${node} 셸을 열지 못했습니다${e.notReady ? `: ${e.notReady}` : '.'}`, e.why);
    }
  }
  if (e.kind === 'error') return band('err', `연결이 끊겼습니다(${e.code === 'node-unreachable' || e.code === 'disconnected' ? `${node} 응답 없음` : e.code}). 세션은 서버에서 닫혔습니다.`);
  if (e.reason === 'idle') return band('info', `${idle ? idleText(idle) : '한동안'} 동안 쓰지 않아 세션 ${id}${eulReul(id)} 닫았습니다.`);
  // 정책·권한이 바뀌어 mydcd가 닫음 (데몬 #325)
  if (e.reason === 'policy') return band('warn', `셸 정책이나 권한이 바뀌어 세션 ${id}${eulReul(id)} 닫았습니다.`);
  if (e.reason === 'closed') return tab.byMe ? band('info', `세션 ${id}${eulReul(id)} 닫았습니다.`) : band('warn', `시스템 관리자${e.by ? ` ${e.by}${iGa(e.by)}` : '가'} 세션 ${id}${eulReul(id)} 닫았습니다.`);
  return band('info', `세션 ${id}${iGa(id)} 끝났습니다(종료 코드 ${e.code}).`);
}

function StatusBar({ tab, idle, mine, max }: { tab: Tab; idle?: number; mine: number; max?: number }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => tick((x) => x + 1), 1000);
    return () => window.clearInterval(t);
  }, []);
  const s = tab.session!;
  return (
    <div className="shell-bar">
      <span>
        세션 <span className="mono">{s.sessionId}</span>
      </span>
      <span>
        계정 {s.account} · sudo {s.sudo ? '허용' : '막기'}
      </span>
      <span>{elapsed(s.openedAt)}</span>
      <span>
        ↓ {fmtBytes(tab.stats.rx)} · ↑ {fmtBytes(tab.stats.tx)}
      </span>
      {idle !== undefined && <span>유휴 {idleText(idle)}이면 닫힘</span>}
      {max !== undefined && (
        <span>
          이 서버의 내 세션 {mine} / {max}
        </span>
      )}
      <span style={{ marginLeft: 'auto' }}>복사 Ctrl+Shift+C · 붙여넣기 Ctrl+Shift+V</span>
    </div>
  );
}

// ── 이 서버의 셸 설정 (시스템 관리자) ──

function NodeSettingsCard({ node, policy, onDone }: { node: NodeShellNode; policy: NodeShellPolicy; onDone: () => void }) {
  const [shell, setShell] = useState<ShellMode>(node.shell);
  const [sudo, setSudo] = useState(node.sudo);
  const [confirm, setConfirm] = useState(false);
  const m = useMutation();
  const people = usePoll((s) => users(s), [], 0);
  useEffect(() => {
    if (m.busy || (m.op && m.op.state !== 'applied')) return;
    setShell(node.shell);
    setSudo(node.sudo);
    // 서버 값이 바뀌면 칸을 맞춘다
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [node.shell, node.sudo]);
  const same = shell === node.shell && sudo === node.sudo;
  const send = () => {
    setConfirm(false);
    void sendOp(m, nodeShellNodePath(node.node), { shell, sudo, expected: policy.revision }, 'PUT').then(() => onDone());
  };
  const granted = new Set(policy.grants.filter((g) => g.nodes.includes(node.node)).map((g) => g.user));
  const count = people.data ? people.data.items.filter((u: UserRecord) => u.enabled && (u.systemAdmin || granted.has(u.id))).length : undefined;
  return (
    <Card title={<h2>이 서버의 셸 설정</h2>} actions={<span className="muted small">시스템 관리자</span>}>
      <div className="shell-kv">
        <span className="muted">셸 열기</span>
        <span>
          <select value={shell} onChange={(e) => setShell(e.target.value as ShellMode)} disabled={m.busy}>
            <option value="inherit">클러스터 정책 따르기 (지금 {policy.enabled ? '켜짐' : '꺼짐'})</option>
            <option value="on">이 서버만 켜기</option>
            <option value="off">이 서버만 끄기</option>
          </select>
        </span>
        <span className="muted">sudo로 root 전환</span>
        <span>
          <select value={sudo ? 'allow' : 'block'} onChange={(e) => setSudo(e.target.value === 'allow')} disabled={m.busy}>
            <option value="allow">허용</option>
            <option value="block">막기 (기본)</option>
          </select>
        </span>
        <span className="muted">전용 계정</span>
        <span className="row" style={{ gap: 6 }}>
          <span className="mono">{policy.account}</span> ·{' '}
          {node.ready ? <Badge tone="ok">준비됨</Badge> : <Badge tone="er" title={node.notReady}>준비 안 됨</Badge>}
          {!node.ready && node.notReady && <span className="muted small">{notReadyText(node.notReady)}</span>}
        </span>
      </div>
      <span className="muted small">전용 계정과 그 계정의 로그인 키는 이 서버의 mydcd가 만들고 관리합니다. sudo 설정을 바꾸면 새 세션부터 적용되고, 열린 세션은 그대로입니다. 클러스터 정책은 서버 › 서버 셸 설정에서 바꿉니다.</span>
      {m.op?.state === 'failed' && m.op.resultCode === 1 && <div className="note wa small">그사이 셸 설정이 바뀌었습니다. 새로 읽은 값을 확인하고 다시 저장해 주세요.</div>}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="btn primary" disabled={same || m.busy} onClick={() => (sudo && !node.sudo ? setConfirm(true) : send())}>
          {m.busy ? '보내는 중…' : '저장'}
        </button>
      </div>
      {confirm && (
        <ConfirmDialog title={`${node.node}에서 sudo를 허용할까요?`} target={node.node} actionLabel="허용" onConfirm={send} onClose={() => setConfirm(false)}>
          <p style={{ margin: 0 }}>
            {node.node}에서 셸을 여는 사람은 <span className="mono">sudo</span>로 root가 될 수 있습니다. 컨테이너·데이터·MyDC 설정까지 모두 바꿀 수 있으니, 이 서버의 셸 권한이 있는 사람{count !== undefined ? `(지금 ${count}명: 시스템 관리자와 이 서버의 셸 권한을 받은 사람)` : ''}을 먼저 확인하세요.
          </p>
          <div className="note wa small">새 세션부터 적용됩니다. 열린 세션은 그대로입니다.</div>
        </ConfirmDialog>
      )}
    </Card>
  );
}

// ── 이 서버에 열린 세션 ──

function OpenSessionsCard({ node, me, admin, q }: { node: string; me: string; admin: boolean; q: Loaded<NodeShellSession[]> }) {
  const [closing, setClosing] = useState<NodeShellSession>();
  return (
    <Card title="이 서버에 열린 세션">
      <Load q={q} rows={2} what="열린 세션을 읽지 못했습니다">
        {(all) => {
          const list = all.filter((s) => s.node === node);
          return list.length ? (
            <div className="table-wrap">
              <table className="tbl" style={{ fontSize: 12 }}>
                <thead>
                  <tr>
                    <th>누가</th>
                    <th>세션</th>
                    <th>상태</th>
                    <th>언제부터</th>
                    <th>주고받음</th>
                    <th aria-label="닫기" />
                  </tr>
                </thead>
                <tbody>
                  {list.map((s) => (
                    <tr key={s.sessionId}>
                      <td>{s.user === me ? `${s.username} (나)` : s.username}</td>
                      <td className="mono">{s.sessionId}</td>
                      <td>
                        <Badge tone={s.state === 'opened' ? 'ok' : s.state === 'closing' ? 'wa' : 'un'}>{SESSION_STATE_KO[s.state]}</Badge>
                      </td>
                      <td>{elapsed(s.openedAt)}</td>
                      <td>
                        {fmtBytes(s.bytesIn + s.bytesOut)} · 마지막 {ago(s.lastActivity)}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        {admin && s.user !== me && canCloseSession(s) && (
                          <button className="btn danger sm" onClick={() => setClosing(s)}>
                            닫기…
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <span className="muted small">이 서버에 열린 세션이 없습니다.</span>
          );
        }}
      </Load>
      <span className="muted small">다른 사람의 세션을 닫는 것은 시스템 관리자만 할 수 있습니다. 열기·닫기는 작업 기록에 남습니다.</span>
      {closing && <CloseSessionDialog s={closing} onClose={() => (setClosing(undefined), void q.refresh())} />}
    </Card>
  );
}

function CloseSessionDialog({ s, onClose }: { s: NodeShellSession; onClose: () => void }) {
  const m = useMutation();
  const done = m.op?.state === 'applied';
  return (
    <Dialog
      title={`${s.username}의 세션 ${s.sessionId}${eulReul(s.sessionId)} 닫을까요?`}
      width={560}
      danger
      onClose={onClose}
      footer={
        done ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn danger solid" disabled={m.busy} onClick={() => void sendOp(m, nodeShellClosePath(s.sessionId), {})}>
              {m.busy ? '보내는 중…' : '닫기'}
            </button>
          </>
        )
      }
    >
      <p style={{ margin: 0 }}>
        {s.node} · {elapsed(s.openedAt)} · 마지막 활동 {ago(s.lastActivity)}. 실행 중인 명령도 함께 끝납니다. {s.username}의 화면에 ‘시스템 관리자가 닫음’이 뜹니다.
      </p>
      {m.op?.state === 'failed' && <div className="note wa small">이미 끝난 세션입니다.</div>}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}

// ── 서버 셸 설정 (서버 목록 위, 시스템 관리자) ──

const IDLE_CHOICES: [number, string][] = [
  [300, '5분'],
  [900, '15분'],
  [1800, '30분'],
  [3600, '1시간'],
  [14400, '4시간'],
  [28800, '8시간'],
  [86400, '1일'],
];

export function ShellSettingsDialog({ onClose }: { onClose: () => void }) {
  const q = usePoll((s) => nodeShellPolicy(s), [], 0);
  return (
    <Load q={q} what="서버 셸 설정을 읽지 못했습니다">
      {(p) => <ShellSettingsForm p={p} onClose={onClose} />}
    </Load>
  );
}

function ShellSettingsForm({ p, onClose }: { p: NodeShellPolicy; onClose: () => void }) {
  const [enabled, setEnabled] = useState(p.enabled);
  const [max, setMax] = useState(String(p.maxSessions));
  const [idle, setIdle] = useState(p.idleSeconds);
  const [showAll, setShowAll] = useState(false);
  const sessions = usePoll((s) => nodeShellSessions(s), [], 0);
  const m = useMutation();
  const maxN = Number(max);
  const bad = !Number.isInteger(maxN) || maxN < 1 || maxN > 16 ? '1에서 16 사이로 넣어 주세요' : undefined;
  const same = enabled === p.enabled && maxN === p.maxSessions && idle === p.idleSeconds;
  const done = m.op?.state === 'applied';
  const idleChoices = IDLE_CHOICES.some(([v]) => v === p.idleSeconds) ? IDLE_CHOICES : [...IDLE_CHOICES, [p.idleSeconds, idleText(p.idleSeconds)] as [number, string]].sort((a, b) => a[0] - b[0]);
  const effective = (n: NodeShellNode) => n.shell === 'on' || (n.shell === 'inherit' && enabled);
  return (
    <Dialog
      title="서버 셸 설정"
      width={560}
      onClose={onClose}
      footer={
        done ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={same || !!bad || m.busy} onClick={() => void sendOp(m, NODE_SHELL_PATH, { enabled, maxSessions: maxN, idleSeconds: idle, expected: p.revision }, 'PUT')}>
              {m.busy ? '보내는 중…' : '저장'}
            </button>
          </>
        )
      }
    >
      <label className="check" style={{ alignItems: 'flex-start' }}>
        <input type="checkbox" checked={enabled} disabled={m.busy || done} onChange={(e) => setEnabled(e.target.checked)} style={{ marginTop: 3 }} />
        <span>
          모든 서버에서 셸 열기 허용 (클러스터 정책)
          <br />
          <span className="small muted">서버별로 ‘켬/끔’을 정한 서버는 이 값을 따르지 않습니다.</span>
        </span>
      </label>
      <div className="shell-two">
        <label className="field">
          <span>한 사람의 서버당 세션</span>
          <input type="number" min={1} max={16} value={max} disabled={m.busy || done} onChange={(e) => setMax(e.target.value)} />
          {bad && <span className="small" style={{ color: 'var(--er)' }}>{bad}</span>}
        </label>
        <label className="field">
          <span>쓰지 않으면 닫기</span>
          <select value={idle} disabled={m.busy || done} onChange={(e) => setIdle(Number(e.target.value))}>
            {idleChoices.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="table-wrap">
        <table className="tbl" style={{ fontSize: 12 }}>
          <thead>
            <tr>
              <th>서버</th>
              <th>셸</th>
              <th>실제</th>
              <th>sudo</th>
              <th>전용 계정</th>
            </tr>
          </thead>
          <tbody>
            {p.nodes.map((n) => (
              <tr key={n.node}>
                <td>{n.node}</td>
                <td>{SHELL_MODE_KO[n.shell]}</td>
                <td>{effective(n) ? <Badge tone="ok">켜짐</Badge> : <Badge tone="un">꺼짐</Badge>}</td>
                <td>{n.sudo ? '허용' : '막기'}</td>
                <td>{n.ready ? <Badge tone="ok">준비됨</Badge> : <Badge tone="er" title={notReadyText(n.notReady)}>준비 안 됨</Badge>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <span className="small muted">
        서버별 셸·sudo 설정은 각 서버 상세의 셸 탭에서 바꿉니다. 지금 열린 세션 {sessions.data?.length ?? '…'}개 ·{' '}
        <button type="button" className="linkish" onClick={() => setShowAll((x) => !x)}>
          {showAll ? '접기' : '모두 보기'}
        </button>
      </span>
      {showAll && sessions.data && (
        <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
          {sessions.data.map((s) => (
            <li key={s.sessionId}>
              {s.username} · {s.node} · <span className="mono">{s.sessionId}</span> · {elapsed(s.openedAt)}
            </li>
          ))}
          {!sessions.data.length && <li className="muted">열린 세션이 없습니다.</li>}
        </ul>
      )}
      {m.op?.state === 'failed' && m.op.resultCode === 1 && <div className="note wa small">그사이 셸 설정이 바뀌었습니다. 창을 닫고 다시 열어 주세요.</div>}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}

// ── 사용자 상세 › 서버 셸 권한 ──

export function UserShellSection({ u }: { u: UserRecord }) {
  const q = usePoll((s) => nodeShellPolicy(s), [], 0);
  const [edit, setEdit] = useState(false);
  const grant = q.data?.grants.find((g) => g.user === u.id)?.nodes ?? [];
  return (
    <>
      <hr className="sep" />
      <div className="row between">
        <b>서버 셸</b>
        <button className="btn sm" disabled={!q.data} onClick={() => setEdit(true)}>
          바꾸기…
        </button>
      </div>
      <Load q={q} rows={1} what="서버 셸 권한을 읽지 못했습니다">
        {(p) => <ShellNodeChecks p={p} checked={grant} />}
      </Load>
      <span className="small muted">고른 서버에서만 셸을 열 수 있습니다. 시스템 관리자는 켜진 모든 서버에서 열 수 있습니다. 작업 공간 권한과는 따로입니다.</span>
      {edit && q.data && <GrantDialog u={u} p={q.data} cur={grant} onClose={() => (setEdit(false), void q.refresh())} />}
    </>
  );
}

function ShellNodeChecks({ p, checked, onToggle, disabled }: { p: NodeShellPolicy; checked: string[]; onToggle?: (node: string, on: boolean) => void; disabled?: boolean }) {
  return (
    <div className="col" style={{ gap: 6 }}>
      {p.nodes.map((n) => (
        <label key={n.node} className="check">
          <input type="checkbox" checked={checked.includes(n.node)} disabled={!onToggle || disabled} onChange={(e) => onToggle?.(n.node, e.target.checked)} />
          <span>
            {n.node}
            {n.sudo && <span className="small muted"> sudo 허용 서버</span>}
            {!n.enabled && <span className="small muted"> 셸 꺼짐</span>}
          </span>
        </label>
      ))}
    </div>
  );
}

function GrantDialog({ u, p, cur, onClose }: { u: UserRecord; p: NodeShellPolicy; cur: string[]; onClose: () => void }) {
  const [sel, setSel] = useState(cur);
  const m = useMutation();
  const done = m.op?.state === 'applied';
  const same = [...sel].sort().join() === [...cur].sort().join();
  return (
    <Dialog
      title={`${u.username} 서버 셸 권한`}
      width={420}
      onClose={onClose}
      footer={
        done ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={same || m.busy} onClick={() => void sendOp(m, nodeShellGrantPath(u.id), { nodes: [...sel].sort(), expected: p.revision }, 'PUT')}>
              {m.busy ? '보내는 중…' : '저장'}
            </button>
          </>
        )
      }
    >
      <ShellNodeChecks p={p} checked={sel} disabled={m.busy || done} onToggle={(n, on) => setSel((s) => (on ? [...s, n] : s.filter((x) => x !== n)))} />
      <span className="small muted">모두 끄면 서버 셸 권한을 회수합니다. 시스템 관리자만 바꿉니다.</span>
      {m.op?.state === 'failed' && m.op.resultCode === 1 && <div className="note wa small">그사이 셸 설정이 바뀌었습니다. 창을 닫고 다시 열어 주세요.</div>}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Dialog>
  );
}

// ── 서버 셸 목록 (셸 권한만 받은 사람의 왼쪽 메뉴, 캔버스 NodeShellIx v156) ──

export function NodeShellListPage() {
  const me = useSession().user.id;
  const { q, forbidden } = useShellPolicy();
  const sessions = usePoll((s) => nodeShellSessions(s), [], DEFAULT_POLL_MS);
  const navigate = useNavigate();
  return (
    <>
      <PageHeader title="서버 셸" ids="UI-1A" />
      <span className="small muted">셸을 열 수 있는 서버입니다. 시스템 관리자가 고른 서버만 보입니다.</span>
      {forbidden ? (
        <div className="bn err">서버 셸 권한이 없습니다. 시스템 관리자에게 서버 셸 권한을 요청하세요.</div>
      ) : (
        <Load q={q} what="서버 셸 설정을 읽지 못했습니다">
          {(p) => (
            <div className="table-wrap" style={{ marginTop: 12 }}>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>서버</th>
                    <th>셸</th>
                    <th>sudo</th>
                    <th>내 세션</th>
                    <th aria-label="셸 열기" />
                  </tr>
                </thead>
                <tbody>
                  {p.nodes.map((n) => {
                    const mine = (sessions.data ?? []).filter((s) => s.user === me && s.node === n.node).length;
                    const blocked = shellBlocked(n.node, p, false);
                    return (
                      <tr key={n.node}>
                        <td>{n.node}</td>
                        <td>{n.enabled ? <Badge tone="ok">켜짐</Badge> : <Badge tone="un">꺼짐</Badge>}</td>
                        <td>{n.sudo ? '허용' : '막기'}</td>
                        <td>{mine ? `${mine}개 열림` : '—'}</td>
                        <td style={{ textAlign: 'right' }}>
                          <button className={`btn sm${blocked ? '' : ' primary'}`} disabled={!!blocked} title={blocked} onClick={() => navigate(`/servers/${encodeURIComponent(n.node)}/shell?new=1`)}>
                            셸 열기
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Load>
      )}
    </>
  );
}
