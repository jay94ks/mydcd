// SPDX-License-Identifier: Apache-2.0

// 공급자 진단 로그 (UI-C1 · 캔버스 v171 WebSettings / WebSettingsIx)
// 바깥 공급자(Hostinger DNS · Let's Encrypt ACME) 호출의 요청·응답 요약을 모으는 스위치.
// 켤 때 받는 진단 도구용 임시 토큰은 이 창의 상태에만 있고 어디에도 저장하지 않는다.
import { Fragment, useEffect, useRef, useState } from 'react';
import { ApiError, noEndpoint } from '../api/client';
import { providerLogDisable, providerLogDownloadUrl, providerLogEnable, providerLogEntries, providerLogState } from '../api/endpoints';
import type { DProviderLogEnable, DProviderLogEntry, DProviderLogState } from '../api/dto';
import { Badge, Card, Field } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { Drawer } from '../components/Drawer';
import { useToast } from '../components/Toast';
import { DEFAULT_POLL_MS, usePoll } from '../lib/usePoll';
import { when } from './WebBackup';

const PROVIDER: Record<string, string> = { 'dns:hostinger': 'Hostinger', 'acme:letsencrypt': 'ACME', 'acme:letsencrypt-staging': 'ACME (시험)', 'sfc-web': '웹 앱' };
/** 호출 한 줄: 메서드 · 동작 · 메시지 */
const callText = (x: DProviderLogEntry) => [x.http?.method, x.op, x.msg].filter(Boolean).join(' ') || x.kind || '—';
/** 결과 배지: HTTP 상태가 있으면 그것, 없으면 수준 */
const result = (x: DProviderLogEntry): [string, 'ok' | 'wa' | 'er' | 'un'] => {
  const st = x.http?.status;
  if (st) return [String(st), st >= 200 && st < 300 ? 'ok' : st >= 400 ? 'er' : 'wa'];
  if (x.error || x.level === 'error') return ['오류', 'er'];
  if (x.level === 'warn') return ['경고', 'wa'];
  return ['정보', 'un'];
};
/** 이 빌드에 진단 로그가 없음(409 not-supported) 또는 아직 그 API가 없음 */
const unsupported = (e: unknown) => noEndpoint(e) || (e instanceof ApiError && e.code === 'not-supported');
const hm = (iso?: string) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
};
const hms = (iso: string) => {
  const d = new Date(iso);
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((x) => String(x).padStart(2, '0')).join(':');
};

export function ProviderLogCard() {
  const q = usePoll((s) => providerLogState(s), [], DEFAULT_POLL_MS);
  const toast = useToast();
  const [dlg, setDlg] = useState<'' | 'enable' | 'disable'>('');
  const [token, setToken] = useState<DProviderLogEnable>();
  const [drawer, setDrawer] = useState(false);
  const wait = !!q.error && unsupported(q.error);
  // 켜져 있다가 저절로 꺼지면 한 번 알린다
  const prev = useRef<DProviderLogState>();
  useEffect(() => {
    const p = prev.current;
    const s = q.data;
    const why = s?.disabledReason === 'idle' ? '1시간 동안 쓰이지 않아' : s?.disabledReason === 'limit' ? '켠 지 24시간이 지나' : undefined;
    if (p?.enabled && s && !s.enabled && why) toast(`공급자 진단 로그가 ${why} 꺼졌습니다. 토큰은 무효가 되었고 모은 항목 ${s.entries.toLocaleString()}개는 남아 있습니다.`);
    if (s) prev.current = s;
  }, [q.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const s = q.data;
  return (
    <Card
      title={
        <span className="row" style={{ gap: 8 }}>
          <h2>공급자 진단 로그</h2>
          {s && (s.enabled ? <Badge tone="wa">켜짐</Badge> : <Badge tone="un">꺼짐</Badge>)}
        </span>
      }
      actions={
        wait ? (
          <Badge tone="wa">서버 기능 대기</Badge>
        ) : s ? (
          s.enabled ? (
            <>
              <a className="btn" href={providerLogDownloadUrl} download="provider-log.jsonl">
                내려받기 (JSONL)
              </a>
              <button type="button" className="btn danger" onClick={() => setDlg('disable')}>
                끄기
              </button>
            </>
          ) : (
            <>
              <button type="button" className="btn" onClick={() => setDlg('enable')}>
                켜기
              </button>
              <a className="btn" href={providerLogDownloadUrl} download="provider-log.jsonl">
                내려받기
              </a>
            </>
          )
        ) : undefined
      }
    >
      <span className="small muted">바깥 공급자(Hostinger DNS, Let's Encrypt ACME) 호출의 요청·응답 요약을 모읍니다. 문제를 찾을 때만 켜세요. 기본은 꺼짐이고 시스템 관리자만 켜고 끕니다.</span>
      {!wait && (
        <Load q={q} what="진단 로그 상태를 읽지 못했습니다">
          {(st) => (
            <dl className="kv2" style={{ gridTemplateColumns: '140px minmax(0, 1fr)', fontSize: 13 }}>
              {st.enabled ? (
                <>
                  <dt>켜진 시각</dt>
                  <dd>
                    {when(st.enabledAt)}
                    {st.enabledBy ? ` · ${st.enabledBy}` : ''}
                  </dd>
                  <dt>마지막 활동</dt>
                  <dd>{hm(st.lastActivity)}</dd>
                  <dt>자동 꺼짐 예정</dt>
                  <dd>{hm(st.expiresAt)} · 1시간 동안 읽기도 새 항목도 없으면 (켠 지 24시간이면 늘 꺼짐)</dd>
                </>
              ) : (
                st.disabledAt && (
                  <>
                    <dt>꺼진 시각</dt>
                    <dd>
                      {hm(st.disabledAt)}
                      {st.disabledReason === 'idle' ? ' · 저절로 꺼짐' : st.disabledReason === 'limit' ? ' · 24시간이 지나 꺼짐' : st.disabledReason === 'restart' ? ' · 웹 앱이 다시 시작함' : ''}
                    </dd>
                  </>
                )
              )}
              <dt>모은 항목</dt>
              <dd>
                {st.entries.toLocaleString()}개
                {st.entries > 0 && (
                  <>
                    {' · '}
                    <button type="button" className="linkish" onClick={() => setDrawer(true)}>
                      최근 항목 보기
                    </button>
                  </>
                )}
              </dd>
            </dl>
          )}
        </Load>
      )}
      <span className="small muted">켤 때 진단 도구용 임시 토큰을 한 번만 보여 줍니다. 끄거나 자동으로 꺼지면 토큰도 무효가 되고, 다시 켜면 새 토큰이 나옵니다. 모은 항목은 꺼진 뒤에도 시스템 관리자가 보고 내려받을 수 있습니다.</span>
      {dlg === 'enable' && <EnableDialog onClose={() => setDlg('')} onDone={(t) => (setDlg(''), setToken(t), void q.refresh())} />}
      {dlg === 'disable' && s && <DisableDialog count={s.entries} onClose={() => setDlg('')} onDone={() => (setDlg(''), void q.refresh())} />}
      {token && <TokenDialog t={token} onClose={() => setToken(undefined)} />}
      {drawer && <ItemsDrawer onClose={() => setDrawer(false)} />}
    </Card>
  );
}

function EnableDialog({ onClose, onDone }: { onClose: () => void; onDone: (t: DProviderLogEnable) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      onDone(await providerLogEnable());
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title="공급자 진단 로그를 켤까요?"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn primary" disabled={busy} onClick={() => void go()}>
            {busy ? '켜는 중…' : '켜기'}
          </button>
        </>
      }
    >
      <div>Hostinger DNS와 Let's Encrypt ACME 호출의 요청·응답 요약을 모읍니다.</div>
      <div className="note wa small">로그에는 도메인 이름, DNS 레코드 값, ACME 주소가 남습니다. API 토큰·계정 키·개인키는 가려져 남지 않습니다.</div>
      <span className="small muted">1시간 동안 진단 도구가 읽지 않고 새 항목도 없으면 저절로 꺼집니다. 켜면 진단 도구용 임시 토큰을 한 번만 보여 줍니다.</span>
      {error !== undefined && <ErrorBand error={error} what="켜지 못했습니다" />}
    </Dialog>
  );
}

// 토큰은 이 창의 상태에만 있다. 닫으면 다시 볼 수 없다
function TokenDialog({ t, onClose }: { t: DProviderLogEnable; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const url = `${window.location.origin}/`;
  return (
    <Dialog
      title="진단 로그를 켰습니다"
      onClose={onClose}
      footer={
        <button type="button" className="btn primary" onClick={onClose}>
          토큰을 복사했습니다 · 닫기
        </button>
      }
    >
      <Field label="임시 토큰 · 이번 한 번만 보입니다" hint={`자동 꺼짐 예정 ${hm(t.state.expiresAt)} · 쓰면 1시간씩 늘어납니다 (켠 지 24시간이면 늘 꺼짐)`}>
        <div className="row" style={{ gap: 8, flexWrap: 'nowrap' }}>
          <input className="mono" readOnly value={t.token} aria-label="임시 토큰" style={{ flex: 1 }} onFocus={(e) => e.currentTarget.select()} autoComplete="off" spellCheck={false} />
          <button
            type="button"
            className="btn sm"
            onClick={() =>
              void navigator.clipboard?.writeText(t.token).then(() => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1200);
              })
            }
          >
            {copied ? '✓ 복사됨' : '⧉ 복사'}
          </button>
        </div>
      </Field>
      <Field label="진단 도구에서 읽기 (예)">
        <pre className="code">{`sfc-web provider-log --url ${url} \\\n  --token <token> --follow`}</pre>
      </Field>
      <span className="small muted">이 토큰은 진단 로그 읽기에만 쓸 수 있습니다. 다른 화면이나 API에는 쓸 수 없습니다.</span>
    </Dialog>
  );
}

function DisableDialog({ count, onClose, onDone }: { count: number; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await providerLogDisable();
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title="진단 로그를 끌까요?"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn danger" disabled={busy} onClick={() => void go()}>
            {busy ? '끄는 중…' : '끄기'}
          </button>
        </>
      }
    >
      <div>새 항목을 더 모으지 않고, 지금 토큰은 바로 무효가 됩니다. 모은 {count.toLocaleString()}개 항목은 남아 내려받을 수 있습니다.</div>
      {error !== undefined && <ErrorBand error={error} what="끄지 못했습니다" />}
    </Dialog>
  );
}

const PAGE = 50;
// 가장 새 50개를 받아 최근 것부터 보인다. '더 보기'는 지금 보이는 가장 오래된 것 앞의 50개
function ItemsDrawer({ onClose }: { onClose: () => void }) {
  const [items, setItems] = useState<DProviderLogEntry[]>([]);
  const [oldest, setOldest] = useState(0);
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<number>();
  const st = usePoll((s) => providerLogState(s), [], DEFAULT_POLL_MS);
  const newest = async (signal?: AbortSignal) => {
    setLoading(true);
    setError(undefined);
    try {
      const r = await providerLogEntries({ tail: PAGE }, signal);
      setItems([...r.page.entries].reverse());
      setOldest(r.page.oldest);
    } catch (e) {
      if (!signal?.aborted) setError(e);
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  };
  const older = async () => {
    const first = items[items.length - 1]?.seq;
    if (first === undefined) return;
    const from = Math.max(oldest - 1, first - 1 - PAGE);
    setLoading(true);
    setError(undefined);
    try {
      const r = await providerLogEntries({ after: from, limit: first - 1 - from });
      setItems((x) => [...x, ...r.page.entries.filter((e) => e.seq < first).reverse()]);
      setOldest(r.page.oldest);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  };
  // 새 항목은 맨 위에 붙도록, 가장 새 seq가 바뀌면 다시 읽는다
  useEffect(() => {
    const ctl = new AbortController();
    void newest(ctl.signal);
    return () => ctl.abort();
  }, [st.data?.last]); // eslint-disable-line react-hooks/exhaustive-deps
  const hasOlder = items.length > 0 && items[items.length - 1].seq > oldest;
  return (
    <Drawer
      title={
        <span className="col" style={{ gap: 2 }}>
          공급자 진단 로그
          <span className="small muted" style={{ fontWeight: 400 }}>
            {(st.data?.entries ?? items.length).toLocaleString()}개 · 최근 것부터
          </span>
        </span>
      }
      onClose={onClose}
    >
      {error !== undefined && <ErrorBand error={error} what="항목을 읽지 못했습니다" />}
      <div className="table-wrap">
        <table className="tbl" style={{ tableLayout: 'fixed' }}>
          <colgroup>
            <col style={{ width: 82 }} />
            <col style={{ width: 96 }} />
            <col />
            <col style={{ width: 70 }} />
          </colgroup>
          <thead>
            <tr>
              <th>시각</th>
              <th>공급자</th>
              <th>호출</th>
              <th>결과</th>
            </tr>
          </thead>
          <tbody>
            {items.map((x) => {
              const [label, tone] = result(x);
              return (
                <Fragment key={x.seq}>
                  <tr className={open === x.seq ? 'sel' : undefined} style={{ cursor: 'pointer' }} onClick={() => setOpen(open === x.seq ? undefined : x.seq)} title="눌러서 요청·응답 요약 보기">
                    <td className="small">{hms(x.at)}</td>
                    <td className="small">{PROVIDER[x.provider] ?? x.provider}</td>
                    <td className="mono small break-any">
                      <button type="button" className="linkish" aria-expanded={open === x.seq} style={{ textAlign: 'left', overflowWrap: 'anywhere', whiteSpace: 'normal' }}>
                        {callText(x)}
                      </button>
                    </td>
                    <td>
                      <Badge tone={tone}>{label}</Badge>
                    </td>
                  </tr>
                  {open === x.seq && (
                    <tr>
                      <td colSpan={4}>
                        <pre className="code" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(x, null, 1)}</pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {!loading && !items.length && (
              <tr>
                <td colSpan={4} className="muted">
                  모은 항목이 없습니다.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {loading && <span className="small muted">읽는 중…</span>}
      {hasOlder && !loading && (
        <button type="button" className="btn sm" onClick={() => void older()}>
          더 보기
        </button>
      )}
    </Drawer>
  );
}
