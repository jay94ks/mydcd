// SPDX-License-Identifier: Apache-2.0

// 휴대폰 홈 · 알림 (캔버스 UI-M3). 데스크톱 대시보드(UI-10)·알림(UI-C0)과 같은 데이터이고, 승인 대기는 맨 위에 둔다.
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { appPath, dashboard, markAllNotificationsRead, markNotificationRead, notifications } from '../api/endpoints';
import type { AppView, NodeView, NotificationView } from '../api/types';
import { useAuth, useSession } from '../auth/session';
import { Badge, HealthBadge, PhaseBadge } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { ATTN } from '../pages/Dashboard';
import { KIND_LABEL, PrefsCard } from '../pages/Notifications';
import { ago, fmtBytes, fmtTime, pct } from '../lib/format';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { useMobileTop } from './top';
import { useOffline } from './MobileShell';
import { ActionSheet } from './Sheet';
import { dashboardMeasured, notificationsLive } from '../lib/liveTopics';

function ServerCard({ n, admin }: { n: NodeView; admin: boolean }) {
  const bad = n.phase !== 'ready';
  const disk = pct(n.disk?.used, n.disk?.total);
  const body = (
    <>
      <div className="hd">
        <b>{n.id}</b>
        <span style={{ display: 'flex', gap: 4 }}>
          {n.leader && <Badge tone="pr">리더</Badge>}
          <PhaseBadge phase={n.phase} reason={n.phaseReason} />
        </span>
      </div>
      {n.phase === 'joining' ? (
        <div className="ln">설치 확인(ACK) 대기{n.join ? ` · ${n.join}` : ''}</div>
      ) : (
        <dl className="mkv">
          <dt>CPU</dt>
          <dd>{n.cpuPercent === undefined ? '—' : `${Math.round(n.cpuPercent)}%`}</dd>
          <dt>메모리</dt>
          <dd>{n.memory ? `${fmtBytes(n.memory.used)} / ${fmtBytes(n.memory.total)}` : n.memUsed !== undefined ? `${fmtBytes(n.memUsed)} 사용` : '—'}</dd>
          <dt>디스크</dt>
          <dd style={disk >= 80 ? { color: 'var(--wa)', fontWeight: 600 } : undefined}>{n.disk ? `${fmtBytes(n.disk.used)} / ${fmtBytes(n.disk.total)}` : '—'}</dd>
          <dt>컨테이너</dt>
          <dd>{n.containers === undefined ? '관측 정보 없음' : `${n.containers} 실행`}</dd>
        </dl>
      )}
    </>
  );
  const cls = `mc${bad && n.phase !== 'joining' ? ' xer' : ''}`;
  return admin ? (
    <Link to={`/servers/${encodeURIComponent(n.id)}`} className={cls}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

function AppCard({ a }: { a: AppView }) {
  const bad = a.health === 'unhealthy' || a.health === 'degraded';
  return (
    <Link to={appPath(a.tenant, a.app)} className={`mc${bad ? ' xer' : ''}`}>
      <div className="hd">
        <b>{a.app}</b>
        <HealthBadge health={a.health} reason={a.reason} />
      </div>
      <div className="ln">
        버전 {a.revision}
        {a.cd ? ' · Git 자동 배포' : ''}
      </div>
      {a.cd?.candidate && <div className="ln" style={{ color: 'var(--pr)' }}>자동 배포 후보 승인 대기 · {a.cd.candidate.slice(0, 7)}</div>}
    </Link>
  );
}

export function MHome() {
  const session = useSession();
  const { tenant } = useAuth();
  const admin = session.user.systemAdmin;
  const offline = useOffline();
  const [sort, setSort] = useState<'problem' | 'name' | 'usage'>('problem');
  const [sortSheet, setSortSheet] = useState(false);
  const d = usePoll((s) => dashboard(admin ? undefined : tenant || undefined, s), [admin ? '' : tenant], DEFAULT_POLL_MS, dashboardMeasured);
  useMobileTop({ title: '홈', root: true }, []);
  return (
    <Load q={d} what="대시보드를 불러오지 못했습니다" rows={6}>
      {(v) => {
        const ready = v.nodes.filter((n) => n.phase === 'ready').length;
        const joining = v.nodes.filter((n) => n.phase === 'joining');
        const leader = v.nodes.find((n) => n.leader);
        const voters = v.nodes.filter((n) => n.voter);
        // 작업 공간 보기는 역할을 받지 못한다(데몬 #373)
        const roleKnown = v.nodes.some((n) => !n.roleUnknown);
        const containers = v.nodes.reduce((a, n) => a + (n.containers ?? 0), 0);
        const count = (h: string) => v.apps.filter((a) => a.health === h).length;
        const approvals = v.attention.filter((a) => a.kind === 'approval');
        const rest = v.attention.filter((a) => a.kind !== 'approval');
        const problems = v.attention.filter((a) => a.kind === 'problem').length;
        const stale = offline ? `${ago(d.asOf?.toISOString())} 값` : undefined;
        const nodes = [...v.nodes].sort((a, b) =>
          sort === 'name' ? a.id.localeCompare(b.id) : sort === 'problem' ? Number(b.phase !== 'ready') - Number(a.phase !== 'ready') || a.id.localeCompare(b.id) : pct(b.disk?.used, b.disk?.total) - pct(a.disk?.used, a.disk?.total),
        );
        return (
          <>
            {!offline && <div className="muted small">● 실시간 연결됨 · 마지막 보고 {ago(d.asOf?.toISOString())}</div>}
            <div className="mtiles">
              <div className="mtile">
                <small>서버</small>
                <b>
                  {ready} / {v.nodes.length}
                </b>
                <span>{stale ?? (joining.length ? `가입 대기 ${joining.length} (${joining.map((n) => n.id).join(', ')})` : '모두 준비됨')}</span>
              </div>
              <div className="mtile">
                <small>합의</small>
                <b>{leader ? '확보' : roleKnown ? '확인 불가' : '—'}</b>
                <span>{stale ?? (!roleKnown ? '시스템 관리자만 봅니다' : leader ? `투표 ${voters.filter((n) => n.phase === 'ready').length}/${voters.length} · 리더 ${leader.id}` : '리더 없음')}</span>
              </div>
              {!offline && (
                <>
                  <div className="mtile">
                    <small>컨테이너</small>
                    <b>{containers}</b>
                    <span>{problems ? `오류 ${problems}` : '오류 없음'}</span>
                  </div>
                  <div className="mtile">
                    <small>앱</small>
                    <b>{v.apps.length}</b>
                    <span>
                      {/* 데스크톱 대시보드 앱 타일과 같은 말 */}
                      정상 {count('healthy')} · 진행 중 {count('progressing')} · 일부 오류 {count('degraded')}
                      {count('unhealthy') ? ` · 오류 ${count('unhealthy')}` : ''}
                    </span>
                  </div>
                </>
              )}
            </div>
            <div className="m-sec">
              <span>주의가 필요한 것</span>
              <Link to="/notifications">알림 모두 ›</Link>
            </div>
            {approvals.length > 0 && (
              <Link to={approvals[0].link ?? '/notifications'} className="mc ap" style={offline ? { opacity: 0.6 } : undefined}>
                <div className="hd">
                  <b>승인 대기 {approvals.length}</b>
                </div>
                <div className="ln">{offline ? '연결이 돌아오면 승인할 수 있습니다' : approvals.map((a) => a.text).join(' · ')}</div>
              </Link>
            )}
            {rest.length === 0 && approvals.length === 0 ? (
              <span className="muted small">지금 주의할 것이 없습니다.</span>
            ) : (
              rest.length > 0 && (
                <div className="li">
                  {rest.slice(0, 6).map((a, i) => {
                    const inner = (
                      <>
                        <Badge tone={ATTN[a.kind][0]}>{ATTN[a.kind][1]}</Badge>
                        <span className="el">{a.text}</span>
                        <span className="r">{fmtTime(a.at)}</span>
                      </>
                    );
                    return a.link ? (
                      <Link key={i} to={a.link}>
                        {inner}
                      </Link>
                    ) : (
                      <div key={i}>{inner}</div>
                    );
                  })}
                </div>
              )
            )}
            {admin ? (
              <>
                <div className="m-sec">
                  <span>서버 현황</span>
                  <button type="button" onClick={() => setSortSheet(true)}>
                    정렬: {sort === 'problem' ? '오류 많은 순' : sort === 'name' ? '이름' : '사용률 높은 순'} ▾
                  </button>
                </div>
                {nodes.map((n) => (
                  <ServerCard key={n.id} n={n} admin={admin} />
                ))}
              </>
            ) : (
              <>
                <div className="m-sec">
                  <span>작업 공간 {tenant}의 앱</span>
                  <Link to="/deploy">배포된 앱 ›</Link>
                </div>
                {v.apps.length === 0 ? <span className="muted small">아직 배포된 앱이 없습니다.</span> : v.apps.map((a) => <AppCard key={`${a.tenant}/${a.app}`} a={a} />)}
              </>
            )}
            {sortSheet && (
              <ActionSheet
                title="서버 정렬"
                onClose={() => setSortSheet(false)}
                items={[
                  { label: '오류 많은 순', onSelect: () => setSort('problem') },
                  { label: '이름', onSelect: () => setSort('name') },
                  { label: '사용률 높은 순', onSelect: () => setSort('usage') },
                ]}
              />
            )}
          </>
        );
      }}
    </Load>
  );
}

// ── 알림 탭 ──
const dayOf = (iso: string) => {
  const d = new Date(iso);
  const t = new Date();
  const y = new Date(Date.now() - 86_400_000);
  if (d.toDateString() === t.toDateString()) return '오늘';
  if (d.toDateString() === y.toDateString()) return '어제';
  return d.toLocaleDateString('ko-KR', { month: 'long', day: 'numeric' });
};
const openLabel = (n: NotificationView) => (n.link?.startsWith('/incidents') ? '승인 카드 열기' : n.link?.includes('/cd') ? '후보 보기' : '열기');

export function MNotifications() {
  const navigate = useNavigate();
  const [filter, setFilter] = useState<'all' | 'unread' | 'todo'>('all');
  const [kind, setKind] = useState<string>();
  const [kindSheet, setKindSheet] = useState(false);
  const [prefs, setPrefs] = useState(false);
  const [error, setError] = useState<unknown>();
  const q = usePoll((s) => notifications(s, false, 200), [], 0, notificationsLive);
  useMobileTop({ title: '알림', sub: q.data ? `읽지 않음 ${q.data.unread}` : undefined, root: true }, [q.data?.unread]);
  const act = async (f: () => Promise<unknown>) => {
    setError(undefined);
    try {
      await f();
    } catch (e) {
      setError(e);
    }
    q.refresh();
  };
  const open = (n: NotificationView) => {
    if (!n.read) void markNotificationRead(n.id).catch(() => undefined);
    // 자동 배포 알림은 요약 탭이 아니라 후보 화면(UI-M5 ③)으로 바로 연다
    if (n.link) navigate(/\/cd\/?$/.test(n.link) ? `${n.link.replace(/\/$/, '')}?view=candidate` : n.link);
    else q.refresh();
  };
  return (
    <Load q={q}>
      {(d) => {
        const all = [...d.items].sort((a, b) => b.at.localeCompare(a.at));
        const todo = all.filter((n) => n.todo && !n.read);
        const kinds = [...new Set(all.map((n) => n.kind))];
        const shown = all.filter((n) => (filter === 'unread' ? !n.read : filter === 'todo' ? n.todo && !n.read : true) && (!kind || n.kind === kind));
        const rest = shown.filter((n) => !(n.todo && !n.read));
        const groups: [string, NotificationView[]][] = [];
        for (const n of rest) {
          const g = dayOf(n.at);
          const last = groups[groups.length - 1];
          if (last && last[0] === g) last[1].push(n);
          else groups.push([g, [n]]);
        }
        return (
          <>
            <div className="mchips">
              <button type="button" className={`mchip${filter === 'all' ? ' on' : ''}`} onClick={() => setFilter('all')}>
                모두 {all.length}
              </button>
              <button type="button" className={`mchip${filter === 'unread' ? ' on' : ''}`} onClick={() => setFilter('unread')}>
                읽지 않음 {d.unread}
              </button>
              <button type="button" className={`mchip${filter === 'todo' ? ' on' : ''}`} onClick={() => setFilter('todo')}>
                승인 대기 {todo.length}
              </button>
              <button type="button" className={`mchip${kind ? ' on' : ''}`} onClick={() => setKindSheet(true)}>
                {kind ? (KIND_LABEL[kind] ?? kind) : '종류'} ▾
              </button>
            </div>
            {error !== undefined && <ErrorBand error={error} what="알림을 바꾸지 못했습니다" />}
            {todo.length > 0 && filter !== 'unread' && (
              <>
                <div className="m-sec">
                  <span>지금 내가 할 일 · {todo.length}</span>
                </div>
                {todo
                  .filter((n) => !kind || n.kind === kind)
                  .map((n) => (
                    <div key={n.id} className="mc ap">
                      <div className="hd">
                        <b>{n.title}</b>
                        <Badge tone="pr">{fmtTime(n.at)}</Badge>
                      </div>
                      {n.text && <div className="ln">{n.text}</div>}
                      <div className="ft">
                        <button type="button" className="mbtn sm pri" onClick={() => open(n)}>
                          {openLabel(n)}
                        </button>
                      </div>
                    </div>
                  ))}
              </>
            )}
            {groups.length === 0 && todo.length === 0 && <span className="muted small">{filter === 'all' && !kind ? '알림이 없습니다.' : '조건에 맞는 알림이 없습니다.'}</span>}
            {groups.map(([g, items], i) => (
              <div key={g} className="m-col" style={{ gap: 12 }}>
                <div className="m-sec">
                  <span>{g}</span>
                  {i === 0 && d.unread > 0 && (
                    <button type="button" onClick={() => void act(markAllNotificationsRead)}>
                      모두 읽음
                    </button>
                  )}
                </div>
                <div className="li">
                  {items.map((n) => (
                    <button key={n.id} type="button" onClick={() => open(n)}>
                      <span className="ic" style={{ color: 'var(--accent)' }}>
                        {n.read ? '' : '●'}
                      </span>
                      <span className="el">
                        {n.title}
                        {n.text ? ` · ${n.text}` : ''}
                      </span>
                      <span className="r">{fmtTime(n.at)}</span>
                    </button>
                  ))}
                </div>
              </div>
            ))}
            <div className="li">
              <button type="button" onClick={() => setPrefs(!prefs)}>
                알림 받는 방법<span className="r">{prefs ? '접기' : '›'}</span>
              </button>
            </div>
            {prefs && (
              <>
                <div className="bn info">브라우저 알림은 이 탭이 열려 있을 때만 옵니다(웹 푸시 아님). 휴대폰은 브라우저를 내리면 오지 않으므로, 팀이 받을 알림은 장애 대응 › 웹훅으로 보내세요.</div>
                <PrefsCard />
              </>
            )}
            {kindSheet && (
              <ActionSheet
                title="종류"
                onClose={() => setKindSheet(false)}
                items={[{ label: '모든 종류', onSelect: () => setKind(undefined) }, ...kinds.map((k) => ({ label: KIND_LABEL[k] ?? k, onSelect: () => setKind(k) }))]}
              />
            )}
          </>
        );
      }}
    </Load>
  );
}
