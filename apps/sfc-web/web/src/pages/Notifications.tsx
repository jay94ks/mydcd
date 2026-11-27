// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react';
import { usePhone } from '../lib/viewport';
import { MNotifications } from '../mobile/MHome';
import { Link, Navigate } from 'react-router-dom';
import { markAllNotificationsRead, markNotificationRead, notifications, notifyPrefs, putNotifyPrefs } from '../api/endpoints';
import type { DNotifyPrefs } from '../api/dto';
import type { NotificationView } from '../api/types';
import { useSession } from '../auth/session';
import { Badge, Card, HelpBox, PageHeader, Segmented, type Tone } from '../components/ui';
import { Empty, ErrorBand, Load, errorText } from '../components/states';
import { useToast } from '../components/Toast';
import { useMobileTop } from '../mobile/top';
import { Refresh } from '../components/Refresh';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { fmtTime } from '../lib/format';
import { notificationsLive } from '../lib/liveTopics';

const SEVERITY: Record<NotificationView['severity'], Tone> = { info: 'tag', warning: 'wa', error: 'er' };
/** 데몬이 만드는 알림 종류. 모르는 종류는 이름 그대로 보인다. */
export const KIND_LABEL: Record<string, string> = {
  'op-failed': '작업 실패',
  'op-unknown': '결과 불명',
  'deploy-done': '배포 완료',
};
const kindLabel = (k: string) => KIND_LABEL[k] ?? k;

/** 휴대폰 '알림 받는 방법' 줄의 이름·설명 (UI-M11 ②). 데몬이 주는 종류만 줄로 만든다 */
const KIND_ROW: Record<string, [string, string?]> = {
  'op-failed': ['작업 실패', '내 작업만'],
  'op-unknown': ['작업 결과 불명', '내 작업만'],
  'deploy-done': ['배포 완료'],
  incident: ['사건 · 내 작업 공간', '보통 이상'],
  'cd-result': ['자동 배포 결과', '실패만'],
  ingress: ['외부 접속 차단·장애'],
  'cert-expiry': ['인증서 만료', '14일 전부터'],
  'webhook-failed': ['웹훅 전송 실패'],
};

/** 휴대폰 알림 받는 방법 (UI-M11 ②): 켜고 끄기 줄, 바꾸면 바로 저장하고 실패하면 되돌린다 */
export function MNotifyPrefs() {
  const session = useSession();
  const toast = useToast();
  const q = usePoll((s) => notifyPrefs(s), []);
  const [cur, setCur] = useState<DNotifyPrefs>();
  const [busy, setBusy] = useState(false);
  useMobileTop({ title: '알림 받는 방법', sub: '계정' }, []);
  const prefs = cur ?? q.data?.prefs;
  const kinds = [...new Set([...(q.data?.kinds ?? Object.keys(KIND_LABEL)), ...(prefs?.mutedKinds ?? [])])];
  const save = async (next: DNotifyPrefs) => {
    const prev = prefs;
    setCur(next);
    setBusy(true);
    try {
      const r = await putNotifyPrefs(next);
      setCur(r.prefs);
    } catch (e) {
      setCur(prev);
      toast(`저장하지 못해 되돌렸습니다: ${errorText(e).message}`, 'er');
    } finally {
      setBusy(false);
    }
  };
  const flip = (list: string[] | null | undefined, v: string) => {
    const set = new Set(list ?? []);
    if (set.has(v)) set.delete(v);
    else set.add(v);
    return [...set];
  };
  const perm = typeof Notification === 'undefined' ? 'unsupported' : Notification.permission;
  const browser = async () => {
    if (!prefs) return;
    if (!prefs.browser && perm === 'default') await Notification.requestPermission();
    if (!prefs.browser && typeof Notification !== 'undefined' && Notification.permission !== 'granted') return toast('브라우저가 알림을 막아 두었습니다. 브라우저 설정에서 허용해 주세요.', 'er');
    await save({ ...prefs, browser: !prefs.browser });
  };
  const row = (key: string, name: string, sub: string | undefined, on: boolean, onClick?: () => void) => (
    <button key={key} type="button" className="tg" role="switch" aria-checked={on} disabled={!onClick || busy} onClick={onClick}>
      <span>
        {name}
        {sub && <small>{sub}</small>}
      </span>
      <span className={`sw${on ? ' y' : ''}`} />
    </button>
  );
  return (
    <Load q={q} what="알림 설정을 읽지 못했습니다">
      {() =>
        prefs && (
          <>
            <div className="mc" style={{ gap: 0, paddingTop: 0, paddingBottom: 0 }}>
              {row('approval', '승인 대기', '장애 대응 · 자동 배포 · 끌 수 없음', true)}
              {kinds.map((k) => {
                const [name, sub] = KIND_ROW[k] ?? [KIND_LABEL[k] ?? k];
                return row(k, name, sub, !(prefs.mutedKinds ?? []).includes(k), () => void save({ ...prefs, mutedKinds: flip(prefs.mutedKinds, k) }));
              })}
            </div>
            {session.tenants.length > 1 && (
              <>
                <div className="m-sec">
                  <span>받을 작업 공간</span>
                </div>
                <div className="mc" style={{ gap: 0, paddingTop: 0, paddingBottom: 0 }}>
                  {session.tenants.map((t) => row(`t-${t.id}`, t.id, undefined, !(prefs.mutedTenants ?? []).includes(t.id), () => void save({ ...prefs, mutedTenants: flip(prefs.mutedTenants, t.id) })))}
                </div>
              </>
            )}
            <button type="button" className="mbtn" disabled={busy || perm === 'unsupported'} onClick={() => void browser()}>
              {prefs.browser ? '브라우저 알림 끄기 (이 브라우저)' : '브라우저 알림 켜기 (이 브라우저)'}
            </button>
            {perm === 'denied' && <span className="muted small">이 브라우저에서 알림을 막아 두었습니다.</span>}
            <div className="bn warn">휴대폰은 브라우저를 내리거나 화면이 꺼지면 브라우저 알림이 오지 않습니다 (웹 푸시 아님). 놓치면 안 되는 알림은 웹훅(장애 대응 › 웹훅)으로 팀 채널에 보내세요.</div>
          </>
        )
      }
    </Load>
  );
}

/** /account/notify: 휴대폰은 알림 받는 방법 화면, 넓은 화면은 알림 화면의 설정 카드로 */
export function NotifyPrefsPage() {
  return usePhone() ? <MNotifyPrefs /> : <Navigate to="/notifications" replace />;
}

export function NotificationsPage() {
  return usePhone() ? <MNotifications /> : <DesktopNotifications />;
}

function DesktopNotifications() {
  const [filter, setFilter] = useState<'all' | 'unread'>('all');
  const q = usePoll((s) => notifications(s, filter === 'unread', 200), [filter], DEFAULT_POLL_MS, notificationsLive);
  const [error, setError] = useState<unknown>();
  const act = async (f: () => Promise<unknown>) => {
    setError(undefined);
    try {
      await f();
    } catch (e) {
      setError(e);
    }
    q.refresh();
  };
  return (
    <>
      <PageHeader
        title="알림"
        ids="UI-C0"
        actions={
          <>
            <Refresh q={q} />
            <button className="btn" disabled={!q.data?.unread} onClick={() => void act(markAllNotificationsRead)}>
              모두 읽음
            </button>
          </>
        }
      />
      <HelpBox terms="결과 불명 작업 (unknown operation)">
        <b>이 화면은</b> 내가 해야 할 일과 최근 일어난 일을 모아 봅니다. 할 일은 위에 둡니다. 알림은 90일 동안 남고, 원래 기록은 작업 기록에 있습니다.
      </HelpBox>
      {error !== undefined && <ErrorBand error={error} what="알림을 바꾸지 못했습니다" />}
      <Card
        title={`알림${q.data ? ` · 읽지 않음 ${q.data.unread}건` : ''}`}
        actions={
          <Segmented
            label="보기"
            value={filter}
            onChange={setFilter}
            options={[
              ['all', '전체'],
              ['unread', '읽지 않음'],
            ]}
          />
        }
      >
        <Load q={q}>
          {(d) =>
            d.items.length === 0 ? (
              <Empty kind={filter === 'unread' ? 'filtered' : 'first'} title={filter === 'unread' ? '읽지 않은 알림이 없습니다' : '알림이 없습니다'} />
            ) : (
              <div className="table-wrap">
                <table className="tbl">
                  <tbody>
                    {[...d.items]
                      .sort((a, b) => Number(b.todo && !b.read) - Number(a.todo && !a.read) || b.at.localeCompare(a.at))
                      .map((n) => (
                        <tr key={n.id} style={{ fontWeight: n.read ? undefined : 600 }}>
                          <td style={{ width: 120 }}>
                            <Badge tone={SEVERITY[n.severity]}>{kindLabel(n.kind)}</Badge>
                            {n.todo && !n.read && (
                              <>
                                {' '}
                                <Badge tone="wa">할 일</Badge>
                              </>
                            )}
                          </td>
                          <td>
                            {n.title}
                            {n.tenant && <div className="muted small">{n.tenant}</div>}
                          </td>
                          <td className="wrap">
                            {n.link ? (
                              <Link to={n.link} onClick={() => !n.read && void markNotificationRead(n.id).catch(() => undefined)}>
                                {n.text || '열기'}
                              </Link>
                            ) : (
                              n.text
                            )}
                          </td>
                          <td className="muted" style={{ width: 90 }}>
                            {fmtTime(n.at)}
                          </td>
                          <td style={{ width: 80 }}>
                            {!n.read && (
                              <button className="btn sm" onClick={() => void act(() => markNotificationRead(n.id))}>
                                읽음
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </Load>
      </Card>
      <PrefsCard />
    </>
  );
}

export function PrefsCard() {
  const session = useSession();
  const q = usePoll((s) => notifyPrefs(s), []);
  const [draft, setDraft] = useState<DNotifyPrefs>();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>();
  const [saved, setSaved] = useState(false);
  const cur: DNotifyPrefs | undefined = draft ?? q.data?.prefs;
  const kinds = [...new Set([...(q.data?.kinds ?? Object.keys(KIND_LABEL)), ...(cur?.mutedKinds ?? [])])];
  const tenants = [...new Set([...session.tenants.map((t) => t.id), ...(cur?.mutedTenants ?? [])])];
  const toggle = (list: string[] | null | undefined, v: string, on: boolean) => {
    const s = new Set(list ?? []);
    if (on) s.delete(v);
    else s.add(v);
    return [...s];
  };
  const change = (p: Partial<DNotifyPrefs>) => {
    if (!cur) return;
    setSaved(false);
    setDraft({ ...cur, ...p });
  };
  const askBrowser = async (on: boolean) => {
    if (on && typeof Notification !== 'undefined' && Notification.permission === 'default') await Notification.requestPermission();
    change({ browser: on });
  };
  const save = async () => {
    if (!draft) return;
    setSaving(true);
    setError(undefined);
    try {
      await putNotifyPrefs(draft);
      setDraft(undefined);
      setSaved(true);
      q.refresh();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };
  const denied = typeof Notification === 'undefined' || Notification.permission === 'denied';
  return (
    <Card
      title="알림 받기 설정"
      actions={
        <>
          {saved && <span className="muted small">저장했습니다</span>}
          <button className="btn primary" disabled={!draft || saving} onClick={() => void save()}>
            {saving ? '저장 중…' : '저장'}
          </button>
        </>
      }
    >
      <Load q={q}>
        {() =>
          cur && (
            <div className="form">
              {error !== undefined && <ErrorBand error={error} what="설정을 저장하지 못했습니다" />}
              <p className="muted small" style={{ margin: 0 }}>
                끈 종류와 작업 공간의 알림은 앞으로 만들지 않습니다. 이미 온 알림은 그대로 둡니다.
              </p>
              <fieldset className="row">
                <legend>받을 종류</legend>
                {kinds.map((k) => (
                  <label key={k} className="row small">
                    <input type="checkbox" checked={!(cur.mutedKinds ?? []).includes(k)} onChange={(e) => change({ mutedKinds: toggle(cur.mutedKinds, k, e.target.checked) })} />
                    {kindLabel(k)}
                  </label>
                ))}
              </fieldset>
              {tenants.length > 0 && (
                <fieldset className="row">
                  <legend>받을 작업 공간</legend>
                  {tenants.map((t) => (
                    <label key={t} className="row small">
                      <input type="checkbox" checked={!(cur.mutedTenants ?? []).includes(t)} onChange={(e) => change({ mutedTenants: toggle(cur.mutedTenants, t, e.target.checked) })} />
                      {t}
                    </label>
                  ))}
                </fieldset>
              )}
              <label className="row small">
                <input type="checkbox" checked={cur.browser} disabled={denied && !cur.browser} onChange={(e) => void askBrowser(e.target.checked)} />
                이 탭이 열려 있을 때 브라우저 알림 띄우기
                {denied && <span className="muted">(브라우저에서 알림을 막아 두었습니다)</span>}
              </label>
            </div>
          )
        }
      </Load>
    </Card>
  );
}
