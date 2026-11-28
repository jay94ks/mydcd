// SPDX-License-Identifier: Apache-2.0

// 코디네이터 대화 목록 · 넓게 (UI-B2, 캔버스 CoordinatorFull · CoordinatorFullIx). 본인 대화만 보인다.
import { useEffect, useRef, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import { ActionSheet } from '../mobile/Sheet';
import { Badge } from '../components/ui';
import { conversation, conversations, deleteAllConversations, deleteConversation, exportConversationUrl, newConversation, renameConversation, type AiConversation } from '../api/ai';
import { API_MODE, apiUrl } from '../api/client';
import { useSession } from '../auth/session';
import { ChatView, useCoordinator } from '../components/Coordinator';
import { Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { Field, HelpBox, PageHeader } from '../components/ui';
import { ErrorBand, Load, errorText } from '../components/states';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { when } from './WebBackup';
import { kindsLive } from '../lib/liveTopics';

const short = (iso: string) => {
  const s = (Date.now() - Date.parse(iso)) / 1000;
  return s < 120 ? '방금' : when(iso).replace(/^오늘 /, '').replace(/^어제 .*/, '어제');
};

export function CoordinatorPage() {
  return usePhone() ? <MCoordinator /> : <DesktopCoordinator />;
}

function DesktopCoordinator() {
  const { conv, setConv, setOpen } = useCoordinator();
  const session = useSession();
  const navigate = useNavigate();
  const toast = useToast();
  const q = usePoll((s) => conversations(s), [], 0, kindsLive('ai-conversation'));
  const [find, setFind] = useState('');
  const [renaming, setRenaming] = useState<string>();
  const [dlg, setDlg] = useState<{ kind: 'one'; c: AiConversation } | { kind: 'all'; n: number }>();
  const items = q.data?.items ?? [];
  const cur = items.find((c) => c.id === conv);
  // 지금 대화가 목록에 없으면 첫 대화를 연다
  useEffect(() => {
    if (q.data && !cur && items[0]) setConv(items[0].id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.data]);
  const shown = items.filter((c) => !find || c.title.toLowerCase().includes(find.toLowerCase()));
  const fresh = async () => {
    try {
      const c = await newConversation();
      setConv(c.id);
      q.refresh();
    } catch (e) {
      toast(`새 대화를 열지 못했습니다: ${errorText(e).message}`);
    }
  };
  const exportMd = async (c: AiConversation) => {
    const name = `${c.title.replace(/[\\/:*?"<>|\s]+/g, '-')}.md`;
    if (API_MODE === 'real') {
      const a = document.createElement('a');
      a.href = apiUrl(exportConversationUrl(c.id));
      a.download = name;
      a.click();
    } else {
      // 목업에는 내려받기 끝점이 없어 화면이 만든다
      const full = await conversation(c.id);
      const md = [`# ${full.title}`, '', ...full.messages.map((m) => `**${m.role === 'user' ? session.user.username : '코디네이터'}** · ${m.at}\n\n${m.text}\n`)].join('\n');
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([md], { type: 'text/markdown' }));
      a.download = name;
      a.click();
      URL.revokeObjectURL(a.href);
    }
    toast(`✓ ${name}를 내려받았습니다. 가린 값은 «가림»으로 남습니다.`);
  };
  return (
    <>
      <PageHeader
        title="✦ 코디네이터"
        ids="UI-B2"
        actions={
          <>
            <button type="button"
              className="btn"
              onClick={() => {
                setOpen(true);
                navigate(-1);
              }}
            >
              패널로 돌아가기
            </button>
            <button type="button" className="btn primary" onClick={() => void fresh()}>
              새 대화
            </button>
          </>
        }
      />
      <HelpBox terms="대화 (conversation) · 제안 작업 (proposal) · 감사 기록 (audit)">
        <b>이 화면은</b> 코디네이터 대화를 넓게 보고 지난 대화를 관리합니다. 대화와 제안 작업 기록은 직접 지우기 전까지 남습니다. 지난 대화를 열면 그때 읽은 값은 요약만 남아 있어, 최신 값이 필요하면 코디네이터가 다시 읽습니다.
      </HelpBox>
      <div className="coord-full">
        <section className="card coord-list">
          <input placeholder="대화 찾기" value={find} onChange={(e) => setFind(e.target.value)} aria-label="대화 찾기" />
          <Load q={q} rows={5}>
            {() => (
              <div className="col" style={{ gap: 2, maxHeight: '60vh', overflowY: 'auto' }}>
                {!shown.length && <span className="muted small">{items.length ? '맞는 대화가 없습니다.' : '아직 대화가 없습니다.'}</span>}
                {shown.map((c) =>
                  renaming === c.id ? (
                    <RenameRow key={c.id} c={c} onDone={() => (setRenaming(undefined), q.refresh())} />
                  ) : (
                    <div key={c.id} className={`citem${c.id === conv ? ' on' : ''}`} onClick={() => setConv(c.id)} role="button" tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && setConv(c.id)}>
                      <span className="el grow">{c.title}</span>
                      {c.pendingProposals > 0 && <span className="count-dot" title={`승인 대기 ${c.pendingProposals}건`}>{c.pendingProposals}</span>}
                      <span className="muted" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{short(c.updatedAt)}</span>
                      <span onClick={(e) => e.stopPropagation()}>
                        <Menu
                          label={`${c.title} 메뉴`}
                          className="btn xs ghost"
                          items={[
                            { label: '이름 바꾸기', onSelect: () => setRenaming(c.id) },
                            { label: '내보내기 (Markdown)', onSelect: () => void exportMd(c) },
                            { label: '대화 지우기…', danger: true, onSelect: () => setDlg({ kind: 'one', c }) },
                          ]}
                        />
                      </span>
                    </div>
                  ),
                )}
              </div>
            )}
          </Load>
          <div className="row between muted small">
            <span>대화 {items.length}개</span>
            <button type="button" className="btn sm danger" disabled={!items.length} onClick={() => setDlg({ kind: 'all', n: items.length })}>
              전체 지우기…
            </button>
          </div>
        </section>
        <section className="card coord-main">
          <div className="row between">
            <h2>{cur?.title ?? '새 대화'}</h2>
            <span className="muted small">{[session.user.username, cur?.tenant && `작업 공간 ${cur.tenant}`, cur?.model].filter(Boolean).join(' · ')}</span>
          </div>
          <ChatView id={conv} onConv={(id) => (setConv(id), q.refresh())} variant="full" />
        </section>
      </div>
      {dlg && <DeleteDialog d={dlg} onClose={() => setDlg(undefined)} onDone={() => (dlg.kind === 'all' || dlg.c.id === conv ? setConv(undefined) : undefined, q.refresh())} />}
    </>
  );
}

function RenameRow({ c, onDone }: { c: AiConversation; onDone: () => void }) {
  const [v, setV] = useState(c.title);
  const [err, setErr] = useState<unknown>();
  const save = async () => {
    try {
      if (v.trim() && v.trim() !== c.title) await renameConversation(c.id, v.trim());
      onDone();
    } catch (e) {
      setErr(e);
    }
  };
  return (
    <Field label="대화 이름" hint="Enter로 저장 · Esc로 취소" error={err !== undefined ? errorText(err).message : undefined}>
      <input autoFocus value={v} maxLength={120} onChange={(e) => setV(e.target.value)} onKeyDown={(e) => (e.key === 'Enter' ? void save() : e.key === 'Escape' ? onDone() : undefined)} />
    </Field>
  );
}

function DeleteDialog({ d, onClose, onDone }: { d: { kind: 'one'; c: AiConversation } | { kind: 'all'; n: number }; onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const all = d.kind === 'all';
  const go = async () => {
    setBusy(true);
    try {
      if (all) await deleteAllConversations();
      else await deleteConversation(d.c.id);
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
      title={all ? `대화 ${d.n}개를 모두 지울까요?` : '이 대화를 지울까요?'}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn danger solid" disabled={busy || (all && typed !== String(d.n))} onClick={() => void go()}>
            {all ? '전체 지우기' : '지우기'}
          </button>
        </>
      }
    >
      <p style={{ margin: 0 }}>{all ? '내 대화만 지웁니다. 되돌릴 수 없습니다.' : '대화와 제안 카드 기록을 지웁니다. 실행된 작업은 작업 기록에 그대로 남습니다.'}</p>
      {all && (
        <Field label={`확인하려면 ${d.n} 을(를) 입력하세요`}>
          <input value={typed} onChange={(e) => setTyped(e.target.value.trim())} />
        </Field>
      )}
      {error !== undefined && <ErrorBand error={error} what="지우지 못했습니다" />}
    </Dialog>
  );
}

// ── 휴대폰 코디네이터 탭 (캔버스 UI-M6 ①) ──
function MCoordinator() {
  const { conv, setConv, setOpen } = useCoordinator();
  const session = useSession();
  const navigate = useNavigate();
  const loc = useLocation();
  const toast = useToast();
  const from = (loc.state as { from?: string } | null)?.from;
  const [ctxPath, setCtxPath] = useState(from);
  useEffect(() => setCtxPath(from), [from]);
  // 패널은 휴대폰에서 쓰지 않는다
  useEffect(() => setOpen(false), [setOpen]);
  const q = usePoll((s) => conversations(s), [], 0, kindsLive('ai-conversation'));
  const items = q.data?.items ?? [];
  const cur = items.find((c) => c.id === conv);
  useEffect(() => {
    if (q.data && !cur && items[0] && !conv) setConv(items[0].id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.data]);
  const fresh = async () => {
    try {
      const c = await newConversation();
      setConv(c.id);
      q.refresh();
    } catch (e) {
      toast(`새 대화를 열지 못했습니다: ${errorText(e).message}`);
    }
  };
  useMobileTop(
    {
      title: '✦ 코디네이터',
      sub: `${cur?.model ?? '모델 확인 중'} · ${session.user.username} 권한`,
      left: (
        <button type="button" className="ic" aria-label="대화 목록" onClick={() => navigate('/coordinator/list')}>
          ☰
        </button>
      ),
      right: (
        <button type="button" className="ic" aria-label="새 대화" onClick={() => void fresh()}>
          ＋
        </button>
      ),
    },
    [cur?.model, session.user.username],
  );
  return (
    <div className="m-chat">
      <ChatView id={conv} onConv={(id) => (setConv(id), q.refresh())} variant="phone" ctxPath={ctxPath} onDropCtx={() => setCtxPath(undefined)} />
    </div>
  );
}

// ── 휴대폰 대화 목록 (캔버스 UI-M6 ④) ──
export function CoordinatorListPage() {
  const phone = usePhone();
  const { setConv } = useCoordinator();
  const navigate = useNavigate();
  const toast = useToast();
  const q = usePoll((s) => conversations(s), [], 0, kindsLive('ai-conversation'));
  const [kind, setKind] = useState<'mine' | 'incident'>('mine');
  const [find, setFind] = useState<string>();
  const [menu, setMenu] = useState<AiConversation>();
  const [renaming, setRenaming] = useState<AiConversation>();
  const [dlg, setDlg] = useState<{ kind: 'one'; c: AiConversation }>();
  const press = useRef<ReturnType<typeof setTimeout>>();
  const long = useRef(false);
  const fresh = async () => {
    try {
      const c = await newConversation();
      setConv(c.id);
      navigate('/coordinator');
    } catch (e) {
      toast(`새 대화를 열지 못했습니다: ${errorText(e).message}`);
    }
  };
  useMobileTop(
    {
      title: '대화 목록',
      sub: q.data ? `대화 ${q.data.items.length}개` : ' ',
      right: (
        <button type="button" className="ic" aria-label="새 대화" onClick={() => void fresh()}>
          ＋
        </button>
      ),
    },
    [q.data?.items.length],
  );
  if (!phone) return <Navigate to="/coordinator" replace />;
  const items = q.data?.items ?? [];
  const f = (find ?? '').trim().toLowerCase();
  const shown = items.filter((c) => (kind === 'incident' ? !!c.incident : true)).filter((c) => !f || c.title.toLowerCase().includes(f));
  const open = (c: AiConversation) => {
    if (long.current) return;
    setConv(c.id);
    navigate('/coordinator');
  };
  const startPress = (c: AiConversation) => {
    long.current = false;
    press.current = setTimeout(() => {
      long.current = true;
      setMenu(c);
    }, 500);
  };
  const endPress = () => clearTimeout(press.current);
  return (
    <>
      <div className="mchips">
        <button type="button" className={`mchip${kind === 'mine' ? ' on' : ''}`} onClick={() => setKind('mine')}>
          내 대화
        </button>
        <button type="button" className={`mchip${kind === 'incident' ? ' on' : ''}`} onClick={() => setKind('incident')}>
          장애 대응
        </button>
        <button type="button" className={`mchip${find !== undefined ? ' on' : ''}`} aria-label="찾기" onClick={() => setFind((x) => (x === undefined ? '' : undefined))}>
          🔍
        </button>
      </div>
      {find !== undefined && <input type="search" className="m-find" autoFocus placeholder="대화 찾기" value={find} onChange={(e) => setFind(e.target.value)} />}
      <Load q={q} rows={5}>
        {() =>
          shown.length === 0 ? (
            <span className="muted small">{items.length ? '맞는 대화가 없습니다.' : '아직 대화가 없습니다.'}</span>
          ) : (
            <div className="li">
              {shown.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => open(c)}
                  onTouchStart={() => startPress(c)}
                  onTouchEnd={endPress}
                  onTouchMove={endPress}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setMenu(c);
                  }}
                >
                  <span className="el">
                    <b>{c.title}</b>
                    <span className="sub2">{[c.incident && `${c.incident}`, c.pendingProposals > 0 && `승인 대기 ${c.pendingProposals}`, short(c.updatedAt)].filter(Boolean).join(' · ')}</span>
                  </span>
                  <span className="r">{c.pendingProposals > 0 ? <Badge tone="pr">대기</Badge> : '›'}</span>
                </button>
              ))}
            </div>
          )
        }
      </Load>
      <div className="muted small">대화 기록은 지우기 전까지 남습니다. 지우기는 대화를 길게 누름 → 동작 시트.</div>
      {menu && (
        <ActionSheet
          title={menu.title}
          onClose={() => setMenu(undefined)}
          items={[
            { label: '이름 바꾸기', onSelect: () => setRenaming(menu) },
            { label: '지우기…', danger: true, onSelect: () => setDlg({ kind: 'one', c: menu }) },
          ]}
        />
      )}
      {renaming && (
        <Dialog title="대화 이름 바꾸기" onClose={() => setRenaming(undefined)}>
          <RenameRow c={renaming} onDone={() => (setRenaming(undefined), q.refresh())} />
        </Dialog>
      )}
      {dlg && <DeleteDialog d={dlg} onClose={() => setDlg(undefined)} onDone={() => q.refresh()} />}
    </>
  );
}
