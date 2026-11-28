// SPDX-License-Identifier: Apache-2.0

// 작업 기록 › 지운 것 (UI-A5, 캔버스 v226 OpsTrash). 계약: docs/reference/web-api/53-ops-trash.md
// 웹이 지운 정의를 보관 기간 동안 남긴다. 되살리기는 같은 정의를 다시 만든다(sfcd 정의는 변경으로 보낸다).
// 비밀 값은 남지 않는다. 되살릴 때 새로 만든 서명 비밀은 이 창에 한 번만 보이고 어디에도 남기지 않는다.
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/client';
import { appPath } from '../api/endpoints';
import { LOST_NAME, TRASH_KIND, daysLeft, purgeTrash, restoreIsOp, restorePath, restoreTrash, trash, type RestoreReply, type TrashItem } from '../api/trash';
import { showValue } from '../api/revert';
import { Badge, Card, Field, KV } from '../components/ui';
import { ConfirmDialog, Dialog } from '../components/Dialog';
import { DataTable } from '../components/DataTable';
import { ErrorBand, Load } from '../components/states';
import { MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { Refresh } from '../components/Refresh';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { trashLive } from '../lib/liveTopics';
import { fmtTime } from '../lib/format';
import { OpsHeader } from './OpsTabs';
import { SecretDialog } from './IncidentHooks';

/** 되살린 뒤 마저 할 곳(토큰 넣기·켜기) */
const SCREEN: Record<string, [string, string]> = {
  webhook: ['/incidents/hooks', '웹훅 화면'],
  'mcp-server': ['/system/ai/mcp', 'AI 설정 › MCP'],
  guide: ['/incidents/guide', '대응 지침'],
  'dns-record': ['/shared/networks/dns', '망 · 연결 › 도메인 이름'],
};
const linkTo = (it: TrashItem): [string, string] | undefined =>
  it.link?.kind === 'archived-apps' ? ['/deploy/archived', '내린 앱 열기'] : it.link?.kind === 'app-revisions' && it.link.tenant && it.link.app ? [`${appPath(it.link.tenant, it.link.app)}/revisions`, '버전 기록 열기'] : undefined;

/** 409 exists의 current: 지금 그 자리에 있는 것 */
const currentText = (c: unknown): string =>
  Array.isArray(c) ? c.map(currentText).join(', ') : c && typeof c === 'object' ? Object.values(c as Record<string, unknown>).filter((v) => typeof v === 'string' || typeof v === 'number').join(' · ') : showValue(c);
const targetText = (t: unknown) => {
  if (!t || typeof t !== 'object') return undefined;
  const x = t as { app?: string; service?: string; port?: number; path?: string; scheme?: string };
  return `클러스터 안 ${x.app ?? ''}/${x.service ?? ''}:${x.port ?? ''}${x.path ?? ''}${x.scheme === 'https' ? ' (https)' : ''}`;
};

/** 종류별 보기 */
function detailRows(it: TrashItem): [string, string][] {
  const d = (it.detail ?? {}) as Record<string, unknown>;
  const s = (k: string) => (d[k] === undefined || d[k] === null || d[k] === '' ? undefined : showValue(d[k]));
  const rows: [string, string | undefined][] =
    it.kind === 'webhook'
      ? [
          ['주소', s('url') ?? targetText(d.target)],
          ['역할 · 형식', [s('role'), s('format')].filter(Boolean).join(' · ') || undefined],
          ['서명', s('sign')],
          ['연결', d.links !== undefined ? `${String(d.links)}곳 (함께 되살림)` : undefined],
        ]
      : it.kind === 'mcp-server'
        ? [
            ['주소', s('url')],
            ['인증', s('auth')],
            ['도구', s('tools')],
            ['쓰던 지침', s('guides')],
          ]
        : it.kind === 'guide'
          ? [
              ['범위', [s('scope'), s('app')].filter(Boolean).join(' · ') || undefined],
              ['버전', d.versions !== undefined ? `v${String(d.version ?? '')} · 지난 버전 ${String(d.versions)}개 함께` : s('version')],
            ]
          : it.kind === 'dns-record'
            ? [
                ['망', s('network')],
                ['이름', s('name')],
                ['종류 · 값', [s('type'), s('value')].filter(Boolean).join(' ') || undefined],
                ['TTL', d.ttl ? `${String(d.ttl)}초` : '망 기본'],
              ]
            : it.kind === 'cluster-app-route'
              ? [['클러스터 앱', s('app')]]
              : [];
  return [...(it.tenant ? [['작업 공간', it.tenant] as [string, string]] : []), ...rows.filter((r): r is [string, string] => r[1] !== undefined)];
}

export function OpsTrashPage() {
  const list = usePoll((s) => trash(s), [], 0, trashLive);
  const navigate = useNavigate();
  const [restoring, setRestoring] = useState<TrashItem>();
  const [purging, setPurging] = useState<TrashItem>();
  const items = list.data?.items ?? [];
  return (
    <>
      <OpsHeader actions={<Refresh q={list} />} />
      {restoring && <RestoreDialog item={restoring} onClose={() => setRestoring(undefined)} onDone={() => list.refresh()} />}
      {purging && <PurgeDialog item={purging} onClose={() => setPurging(undefined)} onDone={() => list.refresh()} />}
      <Card title={`지운 것${list.data ? ` (${items.length})` : ''}`} flush>
        <Load q={list} what="지운 것을 불러오지 못했습니다">
          {() => (
            <DataTable
              rows={items}
              rowKey={(it) => it.id}
              searchPlaceholder="이름·종류·지운 사람 찾기"
              emptyTitle="보관 중인 지운 것이 없습니다"
              columns={[
                { key: 'k', header: '종류', value: (it) => TRASH_KIND[it.kind] ?? it.kind, render: (it) => TRASH_KIND[it.kind] ?? it.kind, m: 'badge' },
                {
                  key: 'n',
                  header: '이름',
                  value: (it) => `${it.name} ${it.tenant ?? ''}`,
                  render: (it) => (
                    <span>
                      <b className="mono">{it.name}</b>
                      {it.tenant && <span className="muted small"> · {it.tenant}</span>}
                      {it.lost?.length ? <span className="muted small"> · {it.lost.map((x) => LOST_NAME[x] ?? x).join('·')} 없이</span> : null}
                    </span>
                  ),
                  m: 'title',
                },
                { key: 'by', header: '지운 사람 · 때', value: (it) => it.deletedAt, render: (it) => `${it.deletedBy} · ${fmtTime(it.deletedAt)}` },
                {
                  key: 'left',
                  header: '남은 기간',
                  value: (it) => it.expiresAt ?? '',
                  render: (it) => (it.restore === 'link' ? <span className="muted">내린 앱에서</span> : `${daysLeft(it.expiresAt) ?? '—'}일`),
                },
                {
                  key: 'go',
                  header: '',
                  render: (it) => {
                    const l = it.restore === 'link' ? linkTo(it) : undefined;
                    return (
                      <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                        {it.restore === 'here' ? (
                          <button type="button" className="btn sm" onClick={() => setRestoring(it)}>
                            되살리기…
                          </button>
                        ) : l ? (
                          <button type="button" className="btn sm" onClick={() => navigate(l[0])}>
                            {l[1]}
                          </button>
                        ) : null}
                        {it.restore === 'here' && (
                          <button type="button" className="btn sm danger" onClick={() => setPurging(it)}>
                            비우기…
                          </button>
                        )}
                      </span>
                    );
                  },
                },
              ]}
            />
          )}
        </Load>
        <div className="small muted" style={{ padding: '10px 14px' }}>
          지운 것은 웹 앱이 {list.data?.retentionDays ?? 7}일 동안 보관합니다(<Link to="/system/web">웹 앱 설정 › 기록 보관 기간</Link>). 되살리기는 같은 정의를 다시 만들고, 망 도메인 이름·클러스터 앱 경로는 변경으로 보냅니다. 서명 비밀·토큰·OAuth 로그인은 남기지 않으므로 되살린 뒤 새로 넣습니다. 데이터 저장소의 데이터, 망·작업 공간·서버는 되살리지 않습니다.
        </div>
      </Card>
    </>
  );
}

type Choice = 'close' | 'replace' | 'rename';

function RestoreDialog({ item, onClose, onDone }: { item: TrashItem; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const isOp = restoreIsOp(item.kind);
  const m = useMutation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [reply, setReply] = useState<RestoreReply>();
  const [secret, setSecret] = useState<string>();
  const [choice, setChoice] = useState<Choice>('close');
  const [name, setName] = useState('');
  const err = isOp ? m.error : error;
  const exists = err instanceof ApiError && err.status === 409 && err.code === 'exists' ? ((err.body.raw as { current?: unknown } | undefined)?.current ?? null) : undefined;
  const [conflict, setConflict] = useState<unknown>();
  const shownConflict = exists !== undefined ? exists : conflict;
  const what = TRASH_KIND[item.kind] ?? item.kind;
  const go = async (b: { name?: string; replace?: boolean }) => {
    if (exists !== undefined) setConflict(exists);
    if (isOp) {
      const v = await sendOp(m, restorePath(item.id), b);
      if (v?.state === 'applied') (toast(`✓ ${item.name}을(를) 되살렸습니다.`), onDone());
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const r = await restoreTrash(item.id, b);
      setReply(r);
      if (r.secret?.value) setSecret(r.secret.value);
      toast(`✓ ${r.restored?.name ?? item.name}을(를) 되살렸습니다.`);
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const done = isOp ? m.op?.state === 'applied' : !!reply;
  const working = busy || m.busy;
  const next = () => {
    if (shownConflict === undefined) return void go({});
    if (choice === 'close') return onClose();
    if (choice === 'replace') return void go({ replace: true });
    return void go({ name: name.trim() });
  };
  const screen = SCREEN[item.kind];
  if (secret) return <SecretDialog name={reply?.restored?.name ?? item.name} value={secret} onClose={() => (setSecret(undefined), onClose())} />;
  return (
    <Dialog
      title={`${item.name} 되살리기`}
      onClose={onClose}
      footer={
        done ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn primary" disabled={working || (shownConflict !== undefined && choice === 'rename' && !name.trim()) || (!!m.op && m.op.state !== 'unknown')} onClick={next}>
              {working ? '보내는 중…' : shownConflict !== undefined ? '계속' : isOp ? '되살리기 보내기' : '되살리기'}
            </button>
          </>
        )
      }
    >
      <KV items={[['종류', what], ...detailRows(item), ['지운 사람 · 때', `${item.deletedBy} · ${fmtTime(item.deletedAt)}`]]} />
      {item.lost?.length ? (
        <div className="note wa small">
          되살려도 돌아오지 않는 것: {item.lost.map((x) => LOST_NAME[x] ?? x).join(', ')}.
          {item.kind === 'webhook' && item.lost.includes('secret') && ' HMAC 서명 비밀은 새로 만들어 이 창에 한 번만 보여 줍니다.'}
          {item.lost.includes('token') && ' 꺼진 채로 되살리니 새 토큰을 넣고 켜세요.'}
          {item.lost.includes('login') && ' 되살린 뒤 OAuth 로그인을 다시 하세요.'}
        </div>
      ) : null}
      {isOp && <span className="small muted">같은 정의를 다시 만드는 변경을 보냅니다. 권한은 sfcd가 판단합니다.</span>}
      {shownConflict !== undefined && !done && (
        <>
          <div className="note wa small">
            같은 자리에 지금 다른 것이 있습니다: <span className="mono">{currentText(shownConflict)}</span>. 그대로 되살리면 덮어씁니다.
          </div>
          <Field label="어떻게 할까요" group>
            <label className="check small">
              <input type="radio" name="restore-choice" checked={choice === 'close'} onChange={() => setChoice('close')} /> 되살리지 않고 닫기
            </label>
            <label className="check small">
              <input type="radio" name="restore-choice" checked={choice === 'replace'} onChange={() => setChoice('replace')} /> 지금 것을 바꿔 넣기
            </label>
            <label className="check small">
              <input type="radio" name="restore-choice" checked={choice === 'rename'} onChange={() => setChoice('rename')} /> 다른 이름으로 되살리기
            </label>
            {choice === 'rename' && (
              <input aria-label="새 이름" className="mono" value={name} placeholder={item.kind === 'dns-record' ? 'zone 아래 이름 (예: www-old)' : '새 이름'} onChange={(e) => setName(e.target.value)} autoFocus />
            )}
          </Field>
        </>
      )}
      {err instanceof ApiError && err.code === 'zone-changed' && <div className="note wa small">그사이 망의 zone이 바뀌었습니다. 다른 이름으로 되살리세요.</div>}
      {exists === undefined && (isOp ? <MutationError error={m.error} /> : error !== undefined && <ErrorBand error={error} what="되살리지 못했습니다" />)}
      {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && (toast(`✓ ${item.name}을(를) 되살렸습니다.`), onDone()))} />}
      {reply?.restored && (
        <div className={`note ${reply.restored.enabled === false ? 'wa' : 'ok'} small`}>
          {reply.restored.name}을(를) 되살렸습니다{reply.restored.version !== undefined ? ` (v${reply.restored.version})` : ''}.
          {reply.restored.enabled === false && ' 꺼진 채로 되살렸습니다. 새 토큰을 넣고 켜세요.'}
          {screen && (
            <>
              {' '}
              <Link to={screen[0]} onClick={onClose}>
                {screen[1]}에서 보기
              </Link>
            </>
          )}
        </div>
      )}
      {done && isOp && <Badge tone="ok">되살림</Badge>}
    </Dialog>
  );
}

function PurgeDialog({ item, onClose, onDone }: { item: TrashItem; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  return (
    <ConfirmDialog
      title={`${item.name}을(를) 지금 비울까요?`}
      target={item.name}
      actionLabel="비우기"
      busy={busy}
      onClose={onClose}
      onConfirm={async () => {
        setBusy(true);
        setError(undefined);
        try {
          await purgeTrash(item.id);
          toast(`✓ ${item.name}을(를) 비웠습니다.`);
          onDone();
          onClose();
        } catch (e) {
          setError(e);
        } finally {
          setBusy(false);
        }
      }}
    >
      <div>보관 기간 전에 지웁니다. 비우면 다시 되살릴 수 없습니다.</div>
      {error !== undefined && <ErrorBand error={error} what="비우지 못했습니다" />}
    </ConfirmDialog>
  );
}
