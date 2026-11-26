// SPDX-License-Identifier: Apache-2.0

// 휴대폰 도메인 상세 (UI-M1 '보기만 화면의 상세 · 하위 탭'): 레코드 · 연결된 서버 · 배정 · 되돌리기 지점 · 바꾼 기록을 읽기만 한다.
import { useLocation, useParams } from 'react-router-dom';
import { useAuth } from '../auth/session';
import { dnsDomains, dnsHistory, dnsRecords, dnsServers, dnsSnapshots, fqdn, setText } from '../api/dns';
import { Empty, Load } from '../components/states';
import { Tabs } from '../components/Tabs';
import { usePoll } from '../lib/usePoll';
import { ago, fmtTime } from '../lib/format';
import { MCards, MDetail, MSec, useReadOnlyTop } from '../mobile/ReadOnly';
import { dnsErrorText, zoneState } from './Domains';

const TABS: Record<string, string> = { records: '레코드', servers: '연결된 서버', assign: '작업 공간 배정', snapshots: '되돌리기 지점', history: '바꾼 기록' };

export function MDomainDetail() {
  const { domain = '' } = useParams();
  const { session } = useAuth();
  const admin = !!session?.user.systemAdmin;
  const path = useLocation().pathname.replace(/\/$/, '');
  const last = path.split('/').pop() ?? '';
  const tab = TABS[last] ? last : 'records';
  const dq = usePoll((s) => dnsDomains(s).then((ds) => ds.find((d) => d.domain === domain)), [domain]);
  const zq = usePoll((s) => dnsRecords(domain, s), [domain]);
  useReadOnlyTop(domain, TABS[tab], '레코드·서버 연결·배정 바꾸기와 되돌리기는 넓은 화면에서', [domain, tab]);
  const base = `/system/domains/${encodeURIComponent(domain)}`;
  const z = zq.data;
  const st = zoneState(z, zq.error, dq.data ? !dq.data.provider : false);
  return (
    <>
      <Tabs
        label="도메인 탭"
        items={[
          { to: `${base}/records`, active: path === base, label: `레코드${z ? ` (${z.items.length})` : ''}` },
          { to: `${base}/servers`, label: '연결된 서버' },
          { to: `${base}/assign`, label: '배정' },
          ...(admin ? [{ to: `${base}/snapshots`, label: '되돌리기 지점' }] : []),
          { to: `${base}/history`, label: '바꾼 기록' },
        ]}
      />
      <Load q={dq} what="도메인을 불러오지 못했습니다">
        {(dd) =>
          !dd ? (
            <Empty kind="scope" title="이 도메인이 없거나 볼 권한이 없습니다" />
          ) : (
            <>
              <MDetail
                title={<span className="mono">{dd.domain}</span>}
                badge={[st.tone, st.text]}
                rows={[
                  ['공급자', dd.provider?.name ?? '없음 · HTTP 확인만'],
                  ['기본 TTL', `${dd.defaultTtl}초`],
                  z && ['읽은 때', `${ago(z.readAt)}`],
                  zq.error !== undefined && ['읽기 실패', dnsErrorText(zq.error)],
                  !admin && dd.myNames && ['내 범위', dd.myNames.map((n) => fqdn(n, dd.domain)).join(', ')],
                ]}
              />
              {tab === 'records' && (
                <Load q={zq} what="레코드를 읽지 못했습니다">
                  {(zz) => (
                    <>
                      <MSec>레코드 {zz.items.length}</MSec>
                      <MCards
                        empty="레코드가 없습니다."
                        items={zz.items.map((r) => {
                          const diff = !!r.managed && r.managed.fingerprint !== r.fingerprint;
                          return {
                            key: `${r.name}|${r.type}`,
                            title: <span className="mono">{fqdn(r.name, dd.domain)}</span>,
                            badge: diff ? ['wa', '값 다름'] : r.managed ? ['ok', 'MyDC'] : ['un', 'MyDC 밖'],
                            tone: diff ? 'wa' : undefined,
                            lines: [
                              <span key="v">
                                <b>{r.type}</b> <span className="mono">{setText(r)}</span>
                              </span>,
                            ],
                            meta: `TTL ${r.ttl}${r.managed?.app ? ` · ${r.managed.tenant}/${r.managed.app}` : ''}`,
                          };
                        })}
                      />
                      {(zz.orphans?.length ?? 0) > 0 && (
                        <>
                          <MSec>고아 기록 {zz.orphans!.length}</MSec>
                          <MCards
                            empty=""
                            items={zz.orphans!.map((o) => ({ key: `${o.name}|${o.type}`, title: <span className="mono">{fqdn(o.name, dd.domain)}</span>, badge: ['wa', o.type], tone: 'wa', meta: `${o.by} · ${fmtTime(o.at)}` }))}
                          />
                        </>
                      )}
                    </>
                  )}
                </Load>
              )}
              {tab === 'servers' && <MServers domain={dd.domain} />}
              {tab === 'assign' && (
                <>
                  <MSec>작업 공간 배정 {dd.assignments?.length ?? 0}</MSec>
                  <MCards
                    empty="배정한 작업 공간이 없습니다. 시스템 관리자만 바꿉니다."
                    items={(dd.assignments ?? []).map((a) => ({ key: a.tenant, title: a.tenant, lines: a.names.map((n) => <span key={n} className="mono">{fqdn(n, dd.domain)}</span>) }))}
                  />
                </>
              )}
              {tab === 'snapshots' && admin && <MSnapshots domain={dd.domain} />}
              {tab === 'history' && <MHistory domain={dd.domain} />}
            </>
          )
        }
      </Load>
    </>
  );
}

function MServers({ domain }: { domain: string }) {
  const q = usePoll((s) => dnsServers(domain, s), [domain]);
  return (
    <Load q={q} what="연결된 서버를 읽지 못했습니다">
      {(v) => (
        <>
          <MSec>서버 {v.items.length}</MSec>
          <MCards
            empty="서버가 없습니다."
            items={v.items.map((n) => ({
              key: n.node,
              title: n.node,
              badge: n.state === 'in-dns' ? ['ok', 'DNS에 있음'] : n.state === 'removed' ? ['er', '빠짐'] : ['un', '연결 안 함'],
              tone: n.state === 'removed' ? 'er' : undefined,
              lines: [n.addresses.length ? <span key="a" className="mono">{n.addresses.join(', ')}</span> : '주소 없음', `포트 ${n.listen.join(', ') || '—'} · ${n.addressSource === 'manual' ? '직접 입력' : '서버 외부망 주소'}`],
              meta: `${n.autoRemove ? '문제 생기면 자동으로 빼기' : '문제 생기면 알림만'}${n.reach ? ` · 바깥 확인 ${n.reach.ok ? '닿음' : '안 닿음'} ${ago(n.reach.at)}` : ''}`,
            }))}
          />
        </>
      )}
    </Load>
  );
}

function MSnapshots({ domain }: { domain: string }) {
  const q = usePoll((s) => dnsSnapshots(domain, s), [domain]);
  return (
    <Load q={q} what="되돌리기 지점을 읽지 못했습니다">
      {(items) => (
        <>
          <MSec>되돌리기 지점 {items.length}</MSec>
          <MCards empty="되돌리기 지점이 없습니다." items={items.map((s) => ({ key: s.id, title: fmtTime(s.createdAt), lines: [s.reason], meta: <span className="mono">{s.id}</span> }))} />
        </>
      )}
    </Load>
  );
}

function MHistory({ domain }: { domain: string }) {
  const q = usePoll((s) => dnsHistory(domain, s), [domain]);
  return (
    <Load q={q} what="바꾼 기록을 읽지 못했습니다">
      {(items) => (
        <>
          <MSec>바꾼 기록 {items.length}</MSec>
          <MCards
            empty="바꾼 기록이 없습니다."
            items={items.map((h) => ({
              key: h.id,
              title: fmtTime(h.at),
              badge: h.result === 'applied' ? ['ok', '적용함'] : h.result === 'failed' ? ['er', '실패'] : ['wa', '결과 모름'],
              tone: h.result === 'failed' ? 'er' : h.result === 'unknown' ? 'wa' : undefined,
              lines: [...h.changes.slice(0, 4).map((c, i) => <span key={i} className="mono">{`${c.after ? (c.before ? '바꿈' : '추가') : '지움'} ${fqdn(c.name, domain)} ${c.type}`}</span>), h.changes.length > 4 ? `외 ${h.changes.length - 4}개` : undefined, h.error],
              meta: `${h.username}${h.tenant ? ` · ${h.tenant}` : ''}${h.revertOf ? ' · 되돌리기' : ''}`,
            }))}
          />
        </>
      )}
    </Load>
  );
}
