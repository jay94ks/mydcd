// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from 'react';
import { usePhone } from '../lib/viewport';
import { MCards, MTiles, MWideNote, useReadOnlyTop } from '../mobile/ReadOnly';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/session';
import { ApiError } from '../api/client';
import {
  addDnsDomain,
  addDnsProvider,
  checkDnsProvider,
  deleteDnsDomain,
  deleteDnsDomainProvider,
  deleteDnsProvider,
  dnsDomainList,
  dnsDomains,
  dnsHistory,
  dnsImportable,
  dnsProviders,
  dnsRecords,
  dnsVendors,
  DNS_ERROR,
  idna,
  putDnsDomainProvider,
  putDnsToken,
  renameDnsProvider,
  setText,
  VENDOR_LOGO,
  type DnsDomain,
  type DnsHistory,
  type DnsImportable,
  type DnsProvider,
  type DnsVendor,
  type DnsZoneView,
} from '../api/dns';
import { acmeResponder } from '../api/acme';
import { domainServers, ingress, ingressMissing, nodeDomains, nodeIngressState } from '../api/ingress';
import { Badge, Card, Field, HelpBox, PageHeader, Segmented, type Tone } from '../components/ui';
import { Empty, ErrorBand, Load } from '../components/states';
import { ConfirmDialog, Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { Tabs } from '../components/Tabs';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { ago, fmtTime } from '../lib/format';

export const DOMAIN_TABS = (domains?: number, certs?: number) => [
  { to: '/system/domains', label: domains === undefined ? '도메인' : `도메인 (${domains})` },
  { to: '/system/domains/certs', label: certs === undefined ? '인증서' : `인증서 (${certs})` },
];

export function Logo({ vendor, sm }: { vendor: string; sm?: boolean }) {
  const [ch, bg] = VENDOR_LOGO[vendor] ?? [vendor.slice(0, 1).toUpperCase(), '#5B6370'];
  return (
    <span className={`logo ${sm ? 'sm' : ''}`} style={{ background: bg }} aria-hidden>
      {ch}
    </span>
  );
}

export const dnsErrorText = (e: unknown) => (e instanceof ApiError ? (DNS_ERROR[e.code] ?? e.message) : String(e));
const day = (iso?: string) => (iso ? iso.slice(0, 10) : '');

/** 도메인 하나의 상태: 공급자에서 읽은 값과 MyDC가 만든 때의 지문을 비교한다. */
export function zoneState(z: DnsZoneView | undefined, error: unknown, noProvider?: boolean): { tone: Tone; text: string; fix: boolean } {
  if (noProvider) return { tone: 'un', text: '공급자 없음', fix: false };
  if (error) return { tone: 'er', text: '읽기 실패', fix: true };
  if (!z) return { tone: 'un', text: '읽는 중', fix: false };
  const diff = z.items.filter((r) => r.managed && r.managed.fingerprint !== r.fingerprint).length;
  if (diff) return { tone: 'wa', text: `값 다름 ${diff}`, fix: true };
  const orphans = z.orphans?.length ?? 0;
  if (orphans) return { tone: 'wa', text: `고아 ${orphans}`, fix: true };
  return { tone: 'ok', text: '맞음', fix: false };
}

const assignText = (d: DnsDomain) =>
  d.assignments?.length ? d.assignments.map((a) => `${a.tenant}: ${a.names.map((n) => `${n}.${d.domain}`).join(', ')}`).join(' · ') : '(배정 없음, 시스템 관리자만)';

function useZones(domains: DnsDomain[] | undefined) {
  const [zones, setZones] = useState<Record<string, { z?: DnsZoneView; e?: unknown }>>({});
  const [hist, setHist] = useState<DnsHistory[]>([]);
  const key = domains?.map((d) => `${d.domain}:${d.provider?.id ?? ''}`).join(',') ?? '';
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!domains) return;
    const ac = new AbortController();
    setZones({});
    for (const d of domains.filter((x) => x.provider))
      dnsRecords(d.domain, ac.signal).then(
        (z) => setZones((x) => ({ ...x, [d.domain]: { z } })),
        (e) => (e as Error).name !== 'AbortError' && setZones((x) => ({ ...x, [d.domain]: { e } })),
      );
    Promise.all(domains.filter((x) => x.provider).map((d) => dnsHistory(d.domain, ac.signal).catch(() => [] as DnsHistory[]))).then(
      (hs) => setHist(hs.flat().sort((a, b) => b.at.localeCompare(a.at))),
      () => undefined,
    );
    return () => ac.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick]);
  return { zones, hist, reload: () => setTick((t) => t + 1) };
}

export function DomainsPage() {
  return usePhone() ? <MDomains /> : <DesktopDomains />;
}

/** 휴대폰 외부 도메인 (UI-M11 ③ 모양): 공급자 카드 · 도메인 목록 */
function MDomains() {
  const { session } = useAuth();
  const admin = !!session?.user.systemAdmin;
  const nav = useNavigate();
  const pq = usePoll((s) => (admin ? dnsProviders(s) : Promise.resolve([] as DnsProvider[])), [admin]);
  const dq = usePoll((s) => dnsDomains(s), []);
  const { zones } = useZones(dq.data);
  useReadOnlyTop('외부 도메인', admin ? '클러스터 전체 · 시스템 관리자' : '내게 배정된 이름', '공급자 연결·도메인 추가·레코드 바꾸기는 넓은 화면에서', [admin]);
  const domains = dq.data ?? [];
  const fix = domains.filter((d) => zoneState(zones[d.domain]?.z, zones[d.domain]?.e, !d.provider).fix).length;
  const providers = pq.data ?? [];
  return (
    <>
      <Tabs label="외부 도메인 탭" items={DOMAIN_TABS(dq.data?.length)} />
      <MTiles
        items={[
          { label: '도메인', value: domains.length, sub: fix ? `맞지 않음 ${fix}` : '모두 맞음', warn: fix > 0 },
          { label: 'DNS 공급자', value: admin ? providers.length : '—', sub: admin ? (providers.some((p) => !p.lastCheckOk) ? `연결 실패 ${providers.filter((p) => !p.lastCheckOk).length}` : '모두 정상') : '시스템 관리자만', warn: providers.some((p) => !p.lastCheckOk) },
        ]}
      />
      {admin && providers.length > 0 && (
        <MCards
          empty=""
          items={providers.map((p) => ({
            key: p.id,
            title: p.name,
            badge: p.lastCheckOk ? ['ok', '연결 정상'] : ['er', '연결 실패'],
            tone: p.lastCheckOk ? undefined : 'er',
            lines: [`${p.vendor}${p.account ? ` · ${p.account}` : ''} · 토큰 ${p.tokenHint}${p.tokenExpires ? ` · ${day(p.tokenExpires)} 만료` : ''}`, p.lastError],
            meta: p.remaining >= 0 ? `남은 요청 ${p.remaining}` : undefined,
          }))}
        />
      )}
      <div className="m-sec">
        <span>도메인</span>
      </div>
      <Load q={dq} what="도메인을 불러오지 못했습니다">
        {() =>
          domains.length === 0 ? (
            <span className="muted small">도메인이 없습니다.</span>
          ) : (
            <div className="li">
              {domains.map((d) => {
                const st = zoneState(zones[d.domain]?.z, zones[d.domain]?.e, !d.provider);
                return (
                  <button key={d.domain} type="button" onClick={() => nav(`/system/domains/${encodeURIComponent(d.domain)}`)}>
                    <span className="el">
                      {d.domain}
                      <span style={{ display: 'block', fontSize: 12, color: 'var(--muted)' }}>{d.provider?.name ?? '공급자 없음 · HTTP 확인만'}</span>
                    </span>
                    <span className="r">
                      <Badge tone={st.tone}>{st.text}</Badge>
                    </span>
                  </button>
                );
              })}
            </div>
          )
        }
      </Load>
      <MWideNote>토큰은 끝 몇 자리만 보이고 다시 보여 주지 않습니다</MWideNote>
    </>
  );
}

function DesktopDomains() {
  const { session } = useAuth();
  const admin = !!session?.user.systemAdmin;
  const toast = useToast();
  const nav = useNavigate();
  const vq = usePoll((s) => dnsVendors(s), []);
  const pq = usePoll((s) => (admin ? dnsProviders(s) : Promise.resolve([] as DnsProvider[])), [admin]);
  const lq = usePoll((s) => dnsDomainList(s), []);
  const dq = { ...lq, data: lq.data?.items };
  // 데몬이 아직 클러스터 도메인 목록을 쓰지 않으면 등록·빼기·공급자 붙이기·떼기는 기다린다
  const pending = lq.data && !lq.data.cluster ? '서버 기능 대기 · 웹 서버가 아직 클러스터 도메인 목록(mydcd domain)을 쓰지 않습니다' : undefined;
  const iq = usePoll((s) => ingress({}, s), []);
  const { zones, hist, reload } = useZones(dq.data);
  const [find, setFind] = useState('');
  const [only, setOnly] = useState<'all' | 'none' | 'fix'>('all');
  const rq = usePoll((s) => (admin ? acmeResponder(s) : Promise.resolve(undefined)), [admin]);
  const [dlg, setDlg] = useState<
    | { kind: 'connect'; provider?: DnsProvider }
    | { kind: 'token' | 'rename' | 'delete'; provider: DnsProvider }
    | { kind: 'register' }
    | { kind: 'remove' | 'attach' | 'detach'; domain: DnsDomain }
  >();
  const vendors = vq.data?.items ?? [];
  const vendorName = (id: string) => vendors.find((v) => v.id === id)?.name ?? id;
  const rate = (id: string) => (vendors.find((v) => v.id === id)?.capabilities as { rateLimit?: { requests: number } } | undefined)?.rateLimit?.requests;

  const refreshAll = () => {
    pq.refresh();
    dq.refresh();
    reload();
    toast(`공급자 연결과 도메인 목록을 다시 읽었습니다`);
  };
  const test = async (p: DnsProvider) => {
    try {
      const r = await checkDnsProvider(p.id);
      toast(`✓ ${p.name} 연결 정상${r.provider.remaining >= 0 ? ` · 남은 요청 ${r.provider.remaining}${rate(p.vendor) ? `/${rate(p.vendor)}` : ''}` : ''}${r.provider.tokenExpires ? ` · 토큰 ${day(r.provider.tokenExpires)} 만료` : ''}`);
    } catch (e) {
      toast(`! ${p.name} ${dnsErrorText(e)}`, 'er');
    }
    void pq.refresh();
  };

  const rows = (dq.data ?? []).filter((d) => {
    if (find && !d.domain.includes(find.trim().toLowerCase())) return false;
    if (only === 'none') return !d.provider;
    if (only === 'fix') return zoneState(zones[d.domain]?.z, zones[d.domain]?.e, !d.provider).fix;
    return true;
  });
  const servedBy = (d: DnsDomain) => {
    if (!iq.data) return undefined;
    const ds = domainServers(iq.data, d.domain);
    return ds.nodes.length ? `서빙 서버: ${ds.nodes.map((n) => `${n.node}${n.isolated ? ' (격리됨)' : ''}`).join(', ')} · 앱 ${ds.apps}` : undefined;
  };
  const close = () => setDlg(undefined);
  const after = () => {
    void pq.refresh();
    void dq.refresh();
  };

  return (
    <>
      <PageHeader
        title="외부 도메인"
        ids="UI-54"
        actions={
          <>
            {admin && <Badge tone="un">클러스터 전체 · 시스템 관리자</Badge>}
            <button className="btn" onClick={refreshAll}>
              목록 새로 받기
            </button>
            {admin && (
              <>
                <button className="btn" onClick={() => setDlg({ kind: 'connect' })}>
                  DNS 공급자 연결
                </button>
                <button className="btn primary" disabled={!!pending} title={pending} onClick={() => setDlg({ kind: 'register' })}>
                  ＋ 도메인 등록
                </button>
              </>
            )}
          </>
        }
      />
      <Tabs label="외부 도메인 탭" items={DOMAIN_TABS(dq.data?.length)} />
      <HelpBox terms="등록된 도메인 (클러스터 도메인 목록) · DNS 공급자 (provider) · 공급자 연결 (API 토큰 하나) · 레코드 (DNS record) · 공개 주소 (ingress public address) · 인증서 자동화 (DNS 확인 · HTTP 확인) · 작업 공간 배정">
        <b>이 화면은</b> 이 클러스터가 쓰는 도메인 목록입니다. 도메인을 등록하면 그 도메인과 그 아래 모든 이름(예: shop.example.com)에 인증서를 링크할 수 있고, 외부 접속이 그 이름으로 HTTPS를 내보냅니다. 목록은 클러스터(mydcd)가 가지며 DNS 공급자 없이도 등록합니다. Hostinger 같은 <b>DNS 공급자 연결</b>은 등록된 도메인에 붙이는 선택 기능으로, 붙이면 웹 UI가 레코드를 만들고 고치며 DNS 확인으로 와일드카드 인증서도 받습니다. 공급자 토큰과 레코드 기록은 웹 UI에만 있습니다.
      </HelpBox>
      {vq.data && !vq.data.sealReady && admin && (
        <div className="note wa">
          봉인 키가 준비되지 않아 공급자 토큰을 저장할 수 없습니다. <Link to="/system/web">웹 앱 설정</Link>에서 봉인 상태를 확인하세요.
        </div>
      )}
      {admin && (
        <Card title={`DNS 공급자 연결 (${pq.data?.length ?? 0})`} actions={<span className="small muted">토큰은 웹 컨테이너의 봉인 파일에만 있고 다시 보여 주지 않습니다</span>}>
          <Load q={pq}>
            {(ps) =>
              ps.length === 0 ? (
                <Empty title="연결한 공급자가 없습니다" action={<button className="btn primary" onClick={() => setDlg({ kind: 'connect' })}>＋ DNS 공급자 연결</button>}>
                  공급자 API 토큰 하나가 연결 하나입니다.
                </Empty>
              ) : (
                <div className="table-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>연결 이름</th>
                        <th>공급자</th>
                        <th>토큰</th>
                        <th>요청 여유 · 만료</th>
                        <th>마지막 시험</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {ps.map((p) => (
                        <tr key={p.id}>
                          <td>
                            <span className="row" style={{ gap: 8 }}>
                              <Logo vendor={p.vendor} />
                              <b>{p.name}</b>
                            </span>
                          </td>
                          <td>{vendorName(p.vendor)}</td>
                          <td className="mono">••••••{p.tokenHint.replace(/^…/, '')}</td>
                          <td>
                            {p.remaining >= 0 ? `${p.remaining}${rate(p.vendor) ? `/${rate(p.vendor)}` : ''}` : '—'} · {p.tokenExpires ? day(p.tokenExpires) : '만료 없음'}
                          </td>
                          <td>
                            {!p.lastCheck ? <Badge tone="un">시험 전</Badge> : p.lastCheckOk ? <Badge tone="ok">정상 · {ago(p.lastCheck)}</Badge> : <Badge tone="er" title={p.lastError}>{p.lastError === 'dns-auth-failed' ? '인증 실패' : '실패'} · {ago(p.lastCheck)}</Badge>}
                          </td>
                          <td>
                            <span className="row" style={{ gap: 6 }}>
                              {p.lastCheck && !p.lastCheckOk ? (
                                <button className="btn primary sm" onClick={() => setDlg({ kind: 'token', provider: p })}>
                                  토큰 바꾸기
                                </button>
                              ) : (
                                <button className="btn sm" onClick={() => void test(p)}>
                                  시험
                                </button>
                              )}
                              <Menu
                                items={[
                                  { label: '시험', onSelect: () => void test(p) },
                                  { label: '토큰 바꾸기', onSelect: () => setDlg({ kind: 'token', provider: p }) },
                                  { label: '이름 바꾸기', onSelect: () => setDlg({ kind: 'rename', provider: p }) },
                                  { label: '도메인 더 고르기', hint: '고른 것만 등록', onSelect: () => setDlg({ kind: 'connect', provider: p }) },
                                  { label: '연결 지우기…', danger: true, onSelect: () => setDlg({ kind: 'delete', provider: p }) },
                                ]}
                              />
                            </span>
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
      )}
      <Card
        title={`도메인 (${dq.data?.length ?? 0})`}
        actions={
          <>
            <input type="search" placeholder="도메인 찾기" aria-label="도메인 찾기" value={find} onChange={(e) => setFind(e.target.value)} style={{ width: 200 }} />
            <Segmented label="보기" value={only} onChange={setOnly} options={[['all', '전체'], ['none', '공급자 없음'], ['fix', '고칠 것 있음']]} />
          </>
        }
      >
        <Load q={dq}>
          {(ds) =>
            ds.length === 0 ? (
              <Empty title={admin ? '등록한 도메인이 없습니다' : '내 작업 공간에 배정된 도메인이 없습니다'} action={admin && !pending ? <button className="btn primary" onClick={() => setDlg({ kind: 'register' })}>＋ 도메인 등록</button> : undefined}>
                {admin ? '도메인을 등록하면 그 아래 이름에 인증서를 링크할 수 있습니다. DNS 공급자는 나중에 붙여도 됩니다.' : '시스템 관리자가 도메인의 이름 범위를 작업 공간에 배정하면 여기에 보입니다.'}
              </Empty>
            ) : rows.length === 0 ? (
              <Empty kind="filtered" title="조건에 맞는 도메인이 없습니다" />
            ) : (
              <div className="table-wrap">
                <table className="tbl" style={{ tableLayout: 'fixed', minWidth: 1000 }}>
                  <colgroup>
                    <col style={{ width: '15%' }} />
                    <col style={{ width: '10%' }} />
                    <col style={{ width: '14%' }} />
                    <col style={{ width: '15%' }} />
                    <col style={{ width: '12%' }} />
                    <col />
                    <col style={{ width: '10%' }} />
                    <col style={{ width: 56 }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>도메인</th>
                      <th>등록</th>
                      <th>DNS 공급자</th>
                      <th>인증서 자동화</th>
                      <th>링크된 호스트 · 인증서</th>
                      <th>작업 공간 배정</th>
                      <th>레코드</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((d) => {
                      const zz = zones[d.domain];
                      const st = zoneState(zz?.z, zz?.e, !d.provider);
                      const pv = d.provider ? pq.data?.find((p) => p.id === d.provider?.id) : undefined;
                      const base = `/system/domains/${encodeURIComponent(d.domain)}`;
                      return (
                        <tr key={d.domain}>
                          <td>
                            <Link className="mono el" style={{ fontSize: 13, fontWeight: 600, display: 'block' }} to={`${base}/records`} title={d.unicode ? `${d.unicode} (${d.domain})` : d.domain}>
                              {d.domain}
                            </Link>
                          </td>
                          <td className="muted small el">{[d.addedBy, d.addedAt && ago(d.addedAt)].filter(Boolean).join(' · ') || '—'}</td>
                          <td className="wrap">
                            {d.provider ? (
                              d.provider.name
                            ) : admin && !pending ? (
                              <>
                                <span className="muted">없음 · </span>
                                <button type="button" className="linkish small" onClick={() => setDlg({ kind: 'attach', domain: d })}>
                                  공급자 붙이기
                                </button>
                              </>
                            ) : (
                              <span className="muted">없음</span>
                            )}
                          </td>
                          <td>{!d.provider ? <Badge tone="pr">HTTP 확인만</Badge> : pv && pv.lastCheck && !pv.lastCheckOk ? <Badge tone="wa">DNS 확인 · 인증 실패</Badge> : <Badge tone="ok">DNS 확인 · 와일드카드</Badge>}</td>
                          <td className="small" title={servedBy(d)}>
                            {d.hosts === undefined ? '—' : `호스트 ${d.hosts} · 인증서 ${d.certificates ?? 0}`}
                          </td>
                          <td className="el" title={assignText(d)}>
                            {assignText(d)}
                          </td>
                          <td>
                            <Badge tone={st.tone} title={zz?.e ? dnsErrorText(zz.e) : undefined}>
                              {st.text}
                            </Badge>
                          </td>
                          <td>
                            <Menu
                              items={[
                                { label: '상세', onSelect: () => nav(`${base}/records`) },
                                { label: '반영 확인', onSelect: () => nav(`${base}/records?check=1`) },
                                { label: '연결된 서버', onSelect: () => nav(`${base}/servers`) },
                                { label: '인증서 보기', onSelect: () => nav('/system/domains/certs') },
                                ...(admin
                                  ? [
                                      { label: d.provider ? '공급자 붙이기 · 바꾸기' : '공급자 붙이기', disabledReason: pending, onSelect: () => setDlg({ kind: 'attach', domain: d }) },
                                      ...(d.provider ? [{ label: '공급자 떼기…', hint: '도메인은 목록에 남음', disabledReason: pending, onSelect: () => setDlg({ kind: 'detach', domain: d }) }] : []),
                                      { label: '도메인 빼기…', danger: true, hint: '링크가 모두 떨어짐', disabledReason: pending, onSelect: () => setDlg({ kind: 'remove', domain: d }) },
                                    ]
                                  : []),
                              ]}
                            />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )
          }
        </Load>
        {admin && (
          <div className="kv" style={{ gridTemplateColumns: '150px minmax(0,1fr)', fontSize: 12 }}>
            <span>HTTP 확인 응답기</span>
            <span>
              {rq.data?.address ? (
                <>
                  <span className="mono">{rq.data.address}</span> · 웹 앱이 시작할 때 설정{!rq.data.listening ? ' · 이 웹 앱의 응답기는 꺼짐' : ''} · 등록된 도메인의 :80 <span className="mono">/.well-known/acme-challenge/</span>를 웹 앱으로 보냄
                  {rq.data.listening && rq.data.advertised && rq.data.advertised !== rq.data.address && (
                    <span className="small" style={{ display: 'block', color: 'var(--wa)' }}>
                      이 웹 앱의 주소 <span className="mono">{rq.data.advertised}</span>와 다릅니다 · 웹 앱이 다시 시작하면 자기 주소로 바꿉니다
                    </span>
                  )}
                </>
              ) : rq.data && !rq.data.listening ? (
                <span className="muted">꺼짐 → HTTP 확인 불가 · 웹 앱 설정에서 응답기(-acme-listen)를 켜야 합니다</span>
              ) : rq.data?.advertised ? (
                <span className="muted">
                  클러스터에 등록 안 됨 → HTTP 확인 불가 · 웹 앱이 <span className="mono">{rq.data.advertised}</span>로 1분마다 등록을 시도합니다. 웹 자동 작업 계정이 시스템 관리자이고 <span className="mono">set-acme-responder</span>를 허용해야 합니다
                </span>
              ) : rq.data ? (
                <span className="muted">
                  클러스터에 등록 안 됨 → HTTP 확인 불가 · 웹 앱 설정에 ingress가 닿는 주소(-acme-advertise IP:PORT)를 넣거나 <span className="mono">mydc domain acme-responder set</span>으로 직접 정하세요
                </span>
              ) : rq.error !== undefined ? (
                <span className="muted">읽지 못했습니다</span>
              ) : (
                <span className="muted">읽는 중…</span>
              )}
            </span>
          </div>
        )}
        <span className="small muted">
          인증서 자동화: <b>DNS 확인</b> = 공급자가 붙어 TXT로 확인(와일드카드 가능) · <b>HTTP 확인만</b> = 공급자가 없어 외부 접속 :80으로 확인(와일드카드 불가). 레코드: <b>맞음</b> = MyDC가 만든 레코드가 지금 공개 주소와 같음 · <b>값 다름</b> = 공급자 쪽에서 누군가 바꿨거나 공개 주소가 바뀜 · <b>고아</b> = MyDC가 만든 레코드가 공급자에서 사라짐 · <b>읽기 실패</b> = 공급자 연결 문제. 공급자가 없는 도메인은 레코드를 직접 관리합니다.
        </span>
      </Card>
      <div className="grid wide">
        <IngressServersCard q={iq} domains={(dq.data ?? []).map((d) => d.domain)} first={dq.data?.[0]?.domain} />
        <Card title="최근 바꾼 기록">
          {hist.length === 0 ? (
            <span className="small muted">아직 바꾼 기록이 없습니다.</span>
          ) : (
            <div className="tl">
              {hist.slice(0, 8).map((h) => (
                <div key={h.id}>
                  <span className="muted">{fmtTime(h.at).slice(-5)}</span>
                  <i style={{ background: h.result === 'applied' ? '#1A7F37' : h.result === 'failed' ? '#A0111F' : '#8A919C' }} />
                  <span>
                    <Link to={`/system/domains/${encodeURIComponent(h.domain)}/history`}>
                      <b>{h.domain}</b>
                    </Link>{' '}
                    {h.changes.map((c) => `${c.after ? (c.before ? '~' : '+') : '−'} ${c.type} ${c.name}${c.after ? ` → ${setText(c.after)}` : ''}`).join(' · ')}
                    {h.result !== 'applied' && ` · ${h.result === 'failed' ? `실패${h.error ? ` (${h.error})` : ''}` : '결과 모름'}`} · {h.username}
                    {h.revertOf ? ' (되돌리기)' : ''}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {dlg?.kind === 'connect' && <ConnectDialog vendors={vendors} existing={dlg.provider} legacy={!!pending} domains={dq.data ?? []} onClose={close} onDone={after} />}
      {dlg?.kind === 'token' && <TokenDialog provider={dlg.provider} onClose={close} onDone={after} />}
      {dlg?.kind === 'rename' && <RenameDialog provider={dlg.provider} onClose={close} onDone={after} />}
      {dlg?.kind === 'delete' && <DeleteProviderDialog provider={dlg.provider} legacy={!!pending} domains={(dq.data ?? []).filter((d) => d.provider?.id === dlg.provider.id)} onClose={close} onDone={after} />}
      {dlg?.kind === 'register' && <RegisterDomainDialog onClose={close} onDone={after} />}
      {dlg?.kind === 'remove' && <RemoveDomainDialog domain={dlg.domain} onClose={close} onDone={after} />}
      {dlg?.kind === 'attach' && <AttachProviderDialog domain={dlg.domain} providers={pq.data ?? []} onClose={close} onDone={after} onConnect={() => setDlg({ kind: 'connect' })} />}
      {dlg?.kind === 'detach' && <DetachProviderDialog domain={dlg.domain} onClose={close} onDone={after} />}
    </>
  );
}

/** UI-55: ① 공급자 → ② 토큰 · 시험(시험을 통과해야 봉인한다) → ③ 붙일 도메인. existing이면 ③부터.
 * 고른 도메인만 붙인다. 클러스터 도메인 목록에 없는 도메인은 고른 것만 함께 등록한다(mydcd domain add). */
function ConnectDialog({ vendors, existing, domains, legacy, onClose, onDone }: { vendors: DnsVendor[]; existing?: DnsProvider; domains: DnsDomain[]; legacy?: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [step, setStep] = useState(existing ? 3 : 1);
  const [vendor, setVendor] = useState(existing?.vendor ?? vendors.find((v) => v.ready)?.id ?? '');
  const [name, setName] = useState(existing?.name ?? '');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [saved, setSaved] = useState<{ provider: DnsProvider; account?: { name: string; domains: number; remaining: number; expiresAt?: string } } | undefined>(existing ? { provider: existing } : undefined);
  const [list, setList] = useState<DnsImportable[]>();
  const [pick, setPick] = useState<Set<string>>(new Set());
  const v = vendors.find((x) => x.id === vendor);
  const rate = (v?.capabilities as { rateLimit?: { requests: number } } | undefined)?.rateLimit?.requests;

  const loadList = async (p: DnsProvider) => {
    try {
      const xs = await dnsImportable(p.id);
      setList(xs);
      // 고른 도메인만 등록한다: 이미 클러스터 목록에 있는 것만 미리 고르고, 목록에 없는 것은 사용자가 골라야 등록한다
      setPick(new Set(xs.filter((x) => x.hasZone && !x.connected && (legacy || x.registered)).map((x) => x.name)));
    } catch (e) {
      setError(e);
    }
  };
  useEffect(() => {
    if (existing) void loadList(existing);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await addDnsProvider({ vendor, name: name.trim(), token });
      setToken('');
      setSaved(r);
      setStep(3);
      onDone();
      await loadList(r.provider);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const importAll = async () => {
    if (!saved) return;
    setBusy(true);
    setError(undefined);
    const done: string[] = [];
    try {
      for (const d of pick) {
        if (!legacy && list?.find((x) => x.name === d)?.registered) await putDnsDomainProvider(d, saved.provider.id);
        else await addDnsDomain({ domain: d, provider: saved.provider.id });
        done.push(d);
      }
      toast(`${saved.provider.name} 연결 저장 · 도메인 ${done.length}개에 붙임`);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      if (done.length) {
        onDone();
        setPick((p) => new Set([...p].filter((x) => !done.includes(x))));
      }
    } finally {
      setBusy(false);
    }
  };
  const newCount = (list ?? []).filter((x) => pick.has(x.name) && !x.registered).length;
  const nameBad = !name.trim() ? '이름을 적으세요' : !/^[a-z0-9][a-z0-9-]{0,62}$/.test(name.trim()) ? '영문 소문자·숫자·- (예: hostinger-main)' : undefined;

  return (
    <Dialog
      title={
        <>
          DNS 공급자 연결 <span className="ids">UI-55</span>
        </>
      }
      width={800}
      onClose={onClose}
      footer={
        <>
          <button className="btn" disabled={step === 1 || busy || (step === 3 && !!saved)} onClick={() => setStep((s) => s - 1)}>
            이전
          </button>
          <span className="row">
            {step === 1 && (
              <button className="btn primary" disabled={!v?.ready} onClick={() => setStep(2)}>
                다음
              </button>
            )}
            {step === 2 && (
              <button className="btn primary" disabled={!!nameBad || !token || busy} onClick={() => void save()}>
                {busy ? '시험하는 중…' : '시험하고 저장'}
              </button>
            )}
            {step === 3 && (
              <>
                {saved && !existing && (
                  <button className="btn" disabled={busy} onClick={onClose}>
                    나중에 고르기
                  </button>
                )}
                <button className="btn primary" disabled={!saved || pick.size === 0 || busy} onClick={() => void importAll()}>
                  {busy ? '붙이는 중…' : `${existing ? '' : '연결 저장 · '}고른 도메인 ${pick.size}개${existing ? ' 붙이기' : ''}${!legacy && newCount ? ` (새로 등록 ${newCount})` : ''}`}
                </button>
              </>
            )}
          </span>
        </>
      }
    >
      <ol className="steps">
        {['공급자', '토큰 · 시험', '붙일 도메인'].map((t, i) => (
          <li key={t} className={i + 1 < step ? 'done' : i + 1 === step ? 'on' : ''}>
            {i + 1 < step ? '✓ ' : ''}
            {i + 1} {t}
          </li>
        ))}
      </ol>
      {error !== undefined && (
        <div className="note er">
          ✗ {step === 2 ? '연결 시험 실패 · ' : ''}
          {dnsErrorText(error)}
          {error instanceof ApiError && error.code === 'dns-auth-failed' && v?.tokenUrl && (
            <>
              {' '}
              <a href={v.tokenUrl} target="_blank" rel="noreferrer">
                새 토큰 만들기 ↗
              </a>
            </>
          )}
        </div>
      )}
      {step === 1 && (
        <div className="g2">
          {vendors.map((x) => (
            <button
              key={x.id}
              type="button"
              className={`vend ${x.id === vendor ? 'on' : ''} ${x.ready ? '' : 'off'}`}
              aria-pressed={x.id === vendor}
              aria-disabled={!x.ready}
              title={x.ready ? undefined : `${x.name} 어댑터는 준비 중입니다. 지금은 ${vendors.filter((y) => y.ready).map((y) => y.name).join('·')}만 연결할 수 있습니다.`}
              onClick={() => x.ready && setVendor(x.id)}
            >
              <Logo vendor={x.id} />
              <span>
                <b>{x.name}</b>
                <small>{x.ready ? [x.capabilities.recordTypes.length ? '레코드' : '', x.capabilities.validate ? '미리 검사' : '', x.capabilities.snapshots ? '되돌리기 지점' : '', x.capabilities.propagation ? '반영 확인' : ''].filter(Boolean).join(' · ') : (x.note ?? '어댑터 준비 중')}</small>
              </span>
            </button>
          ))}
        </div>
      )}
      {step === 2 && (
        <>
          <div className="g2">
            <Field label="연결 이름" error={name && nameBad}>
              <input value={name} placeholder={`${vendor}-main`} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="API 토큰">
              <input type="password" className="mono" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} />
            </Field>
          </div>
          <span className="small muted">
            토큰은 {v?.name} 계정 화면에서 만듭니다{v?.tokenUrl && (
              <>
                (<a href={v.tokenUrl} target="_blank" rel="noreferrer">발급 안내</a>)
              </>
            )}. 토큰은 만든 사용자의 권한을 그대로 가지므로, 이 도메인들만 가진 <b>전용 계정</b>에서 만료일을 정해 발급하길 권합니다. 저장하면 웹 컨테이너의 봉인 파일에만 남고 화면에는 끝 4자리만 보입니다.
          </span>
        </>
      )}
      {step === 3 && (
        <>
          {saved?.account && (
            <div className="note ok">
              <b>✓ 연결 시험 성공</b> 계정 {saved.account.name} · 도메인 {saved.account.domains}개 읽음{saved.account.remaining >= 0 ? ` · 요청 여유 ${saved.account.remaining}${rate ? `/${rate}` : ''}` : ''}
              {saved.account.expiresAt ? ` · 토큰 만료 ${day(saved.account.expiresAt)}` : ''}
            </div>
          )}
          {!list ? (
            <span className="muted small">가져올 도메인을 읽는 중…</span>
          ) : list.length === 0 ? (
            <Empty title="이 계정에 도메인이 없습니다" />
          ) : (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th />
                    <th>도메인 (이 공급자에 있는 것)</th>
                    <th>네임서버</th>
                    <th>클러스터 도메인 목록</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((x) => {
                    const can = x.hasZone && !x.connected;
                    return (
                      <tr key={x.name}>
                        <td>
                          <input
                            type="checkbox"
                            aria-label={`${x.name}에 붙이기`}
                            disabled={!can}
                            checked={pick.has(x.name)}
                            onChange={(e) => setPick((p) => (e.target.checked ? new Set(p).add(x.name) : new Set([...p].filter((y) => y !== x.name))))}
                          />
                        </td>
                        <td className="mono">{x.name}</td>
                        <td>{x.hasZone ? v?.name : `다른 곳${x.nameservers ? ` (${x.nameservers.split('.')[0]}.${x.nameservers.split('.')[1] ?? ''}…)` : ''}`}</td>
                        <td className={can ? '' : 'muted wrap'} title={x.hasZone ? undefined : `${x.name}의 DNS는 ${v?.name}에 없습니다(${x.nameservers ?? '다른 네임서버'}). 네임서버를 바꾸거나 그 공급자를 연결하세요.`}>
                          {(() => {
                            if (!x.hasZone) return `이 도메인의 DNS는 ${v?.name}에 없어 가져올 수 없음`;
                            const recs = x.records !== undefined ? ` · 레코드 ${x.records}` : '';
                            if (legacy) return x.connected ? '이미 가져옴' : '연결할 때 가져옴';
                            if (x.connected) return `등록됨 · 이미 이 공급자를 붙임${recs}`;
                            const other = domains.find((d) => d.domain === x.name)?.provider;
                            if (x.registered) return other ? `등록됨 · ${other.name}에서 이 공급자로 바꿈${recs}` : `등록됨 · 이 공급자를 붙임${recs}`;
                            return (
                              <>
                                <b style={{ fontWeight: 500 }}>목록에 없음</b> · {pick.has(x.name) ? '골랐으므로 등록' : '고르지 않음 (등록하지 않음)'}
                                {recs}
                              </>
                            );
                          })()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {(() => {
            const fresh = (list ?? []).filter((x) => x.hasZone && !x.connected && !x.registered);
            const add = fresh.filter((x) => pick.has(x.name)).map((x) => x.name);
            const skip = fresh.filter((x) => !pick.has(x.name)).map((x) => x.name);
            return fresh.length && !legacy ? (
              <div className="note info">
                고른 도메인만 등록합니다.
                {add.length > 0 && (
                  <>
                    {' '}
                    클러스터 도메인 목록에 추가: <span className="mono">{add.join(', ')}</span> · {saved && existing ? '붙일 때' : '연결 저장과'} 함께 등록합니다.
                  </>
                )}
                {skip.length > 0 && (
                  <>
                    {' '}
                    고르지 않은 도메인(<span className="mono">{skip.join(', ')}</span>)은 등록하지 않고, 나중에 공급자 줄 ⋯ › ‘도메인 더 고르기’로 고를 수 있습니다.
                  </>
                )}{' '}
                나중에 공급자를 떼도 등록한 도메인은 목록에 남습니다.
              </div>
            ) : null;
          })()}
          <span className="small muted">레코드는 읽기만 합니다. 기존 레코드는 'MyDC 밖 레코드'로 표시되고 바뀌지 않습니다. 연결할 서버는 붙인 뒤 도메인 상세에서 고릅니다.</span>
        </>
      )}
    </Dialog>
  );
}

function TokenDialog({ provider, onClose, onDone }: { provider: DnsProvider; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await putDnsToken(provider.id, token);
      setToken('');
      toast(`${provider.name} 토큰을 바꿨습니다`);
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
      title={`${provider.name} 토큰 바꾸기`}
      width={400}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!token || busy} onClick={() => void save()}>
            {busy ? '시험하는 중…' : '시험하고 저장'}
          </button>
        </>
      }
    >
      {error !== undefined && <div className="note er">✗ {dnsErrorText(error)} 옛 토큰을 그대로 씁니다.</div>}
      <Field label="새 API 토큰" hint="저장 전에 시험하고, 통과해야 바꿉니다. 저장 후 끝 4자리와 만료일만 보입니다">
        <input type="password" className="mono" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} />
      </Field>
    </Dialog>
  );
}

function RenameDialog({ provider, onClose, onDone }: { provider: DnsProvider; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(provider.name);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const bad = !/^[a-z0-9][a-z0-9-]{0,62}$/.test(name.trim()) ? '영문 소문자·숫자·-' : undefined;
  const save = async () => {
    setBusy(true);
    try {
      await renameDnsProvider(provider.id, name.trim());
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Dialog
      title="연결 이름 바꾸기"
      width={400}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!!bad || name.trim() === provider.name || busy} onClick={() => void save()}>
            저장
          </button>
        </>
      }
    >
      {error !== undefined && <ErrorBand error={error} what="이름을 바꾸지 못했습니다" />}
      <Field label="연결 이름" error={bad}>
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
    </Dialog>
  );
}

function DeleteProviderDialog({ provider, domains, legacy, onClose, onDone }: { provider: DnsProvider; domains: DnsDomain[]; legacy?: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      // 지금 데몬은 쓰는 도메인이 있으면 연결 지우기를 거절하므로 도메인을 먼저 웹에서 뺀다
      if (legacy) for (const d of domains) await deleteDnsDomain(d.domain);
      await deleteDnsProvider(provider.id);
      toast(`${provider.name} 연결을 지웠습니다${domains.length && !legacy ? ` · 도메인 ${domains.length}개는 목록에 남음` : ''}`);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      onDone();
      setBusy(false);
    }
  };
  return (
    <ConfirmDialog title={`${provider.name} 연결을 지울까요?`} target={provider.name} actionLabel="지우기" busy={busy} onClose={onClose} onConfirm={() => void go()}>
      {error !== undefined && <div className="note er">{dnsErrorText(error)}</div>}
      {legacy ? (
        <p>{domains.length ? `이 연결을 쓰는 도메인 ${domains.length}개(${domains.map((d) => d.domain).join(', ')})도 웹에서 빠집니다. ` : ''}공급자의 레코드는 그대로 남습니다. 봉인한 토큰은 지웁니다.</p>
      ) : (
      <p>
        {domains.length ? `이 연결을 쓰는 도메인 ${domains.length}개(${domains.map((d) => d.domain).join(', ')})에서 공급자가 떨어집니다. 도메인은 클러스터 목록에 남고 링크된 인증서도 그대로입니다. ` : ''}공급자의 레코드도 그대로 남습니다.
        {domains.length ? ' 그 도메인의 와일드카드 인증서는 자동 갱신이 멈추고, 와일드카드가 아닌 이름은 HTTP 확인으로 갱신합니다.' : ''} 봉인한 토큰은 지웁니다.
      </p>
      )}
    </ConfirmDialog>
  );
}

/** ＋ 도메인 등록: 클러스터 도메인 목록(mydcd domain add)에 넣는다. 공급자 없이 등록한다. */
function RegisterDomainDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [raw, setRaw] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const name = idna(raw);
  const go = async () => {
    if (!name) return;
    setBusy(true);
    setError(undefined);
    try {
      const r = await addDnsDomain({ domain: name });
      toast(
        <>
          {name}를 등록했습니다.{r.linked ? ` 미연결이던 인증서 ${r.linked}개가 링크됐습니다. ` : ' '}
          {r.linked ? <Link to="/system/domains/certs">인증서 보기</Link> : null}
        </>,
      );
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  const code = error instanceof ApiError ? error.code : undefined;
  return (
    <Dialog
      title="도메인 등록"
      width={560}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!name || busy} onClick={() => void go()}>
            {busy ? '등록하는 중…' : '등록'}
          </button>
        </>
      }
    >
      <Field label="도메인" error={raw.trim() && !name ? '도메인 이름 형식이 아닙니다 (예: example.com)' : undefined} hint={name ? undefined : '이 도메인과 그 아래 모든 이름이 등록됩니다'}>
        <input
          className="mono"
          autoFocus
          value={raw}
          placeholder="example.com"
          spellCheck={false}
          onChange={(e) => {
            setRaw(e.target.value);
            setError(undefined);
          }}
        />
      </Field>
      {name && (
        <span className="small muted" style={{ marginTop: -8 }}>
          저장 이름 <span className="mono">{name}</span> (소문자 IDNA) · 이 도메인과 그 아래 모든 이름이 등록됩니다
        </span>
      )}
      {code === 'public-suffix' ? (
        <div className="note er">
          ✗ <span className="mono">{name}</span>은 공개 접미사라 등록할 수 없습니다. <span className="mono">shop.{name}</span>처럼 그 아래 도메인을 넣으세요.
        </div>
      ) : (
        error !== undefined && <div className="note er">✗ {dnsErrorText(error)}</div>
      )}
      <div className="note info">DNS 공급자 없이 등록합니다. 공급자가 없으면 인증서는 HTTP 확인(외부 접속 :80)으로만 받고 와일드카드는 받을 수 없습니다. 공급자는 나중에 붙여도 됩니다.</div>
      <span className="small muted">등록하면 이미 보관함에 있는 인증서 가운데 이 도메인 아래 이름을 가진 것이 링크됩니다(미연결 → 연결됨).</span>
    </Dialog>
  );
}

/** 도메인 빼기: 서버는 링크가 있어도 거절하지 않으므로 이 확인이 마지막 단계다. */
function RemoveDomainDialog({ domain, onClose, onDone }: { domain: DnsDomain; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const hosts = domain.hosts ?? 0;
  const certs = domain.certificates ?? 0;
  const go = async () => {
    setBusy(true);
    try {
      const r = await deleteDnsDomain(domain.domain);
      const n = r ? r.unlinkedCertificates : undefined;
      toast(`${domain.domain}을(를) 도메인 목록에서 뺐습니다${n ? ` · 인증서 ${n}개 미연결` : ''}`);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <ConfirmDialog title={`${domain.domain}을(를) 도메인 목록에서 뺄까요?`} target={domain.domain} actionLabel="도메인 빼기" busy={busy} onClose={onClose} onConfirm={() => void go()}>
      {error !== undefined && <div className="note er">{dnsErrorText(error)}</div>}
      {hosts > 0 || certs > 0 ? (
        <div className="note wa">
          호스트 {hosts}개가 인증서 링크를 잃습니다. 외부 접속은 그 호스트의 HTTPS 접속을 거절합니다. 인증서 {certs}개가 <b>미연결</b>이 됩니다(다른 도메인 링크가 없으면).
        </div>
      ) : (
        <div className="note info">이 도메인 아래 링크된 호스트와 인증서가 없습니다.</div>
      )}
      <p>
        인증서는 지우지 않습니다.{domain.provider ? ` 붙은 DNS 공급자 ${domain.provider.name}도 떨어지지만 공급자의 레코드는 그대로 남습니다.` : ''} 다시 등록하면 남은 인증서로 링크를 다시 겁니다.
      </p>
    </ConfirmDialog>
  );
}

/** 공급자 붙이기 · 바꾸기: 등록된 도메인에 이미 있는 공급자 연결 하나를 붙인다 */
function AttachProviderDialog({ domain, providers, onClose, onDone, onConnect }: { domain: DnsDomain; providers: DnsProvider[]; onClose: () => void; onDone: () => void; onConnect: () => void }) {
  const toast = useToast();
  const [pick, setPick] = useState(domain.provider?.id ?? providers[0]?.id ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await putDnsDomainProvider(domain.domain, pick);
      toast(`${domain.domain}에 ${r.domain.provider?.name ?? pick}을(를) 붙였습니다`);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`${domain.domain}에 공급자 ${domain.provider ? '바꾸기' : '붙이기'}`}
      width={560}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!pick || pick === domain.provider?.id || busy} onClick={() => void go()}>
            {busy ? '붙이는 중…' : '붙이기'}
          </button>
        </>
      }
    >
      {error !== undefined && <div className="note er">✗ {dnsErrorText(error)}</div>}
      {providers.length === 0 ? (
        <Empty
          title="연결한 공급자가 없습니다"
          action={
            <button className="btn primary" onClick={onConnect}>
              DNS 공급자 연결
            </button>
          }
        >
          공급자 연결을 먼저 만드세요. 연결할 때 이 도메인을 고르면 함께 붙습니다.
        </Empty>
      ) : (
        <Field label="공급자 연결">
          <select value={pick} onChange={(e) => setPick(e.target.value)}>
            {providers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
      )}
      <span className="small muted">붙이면 웹 UI가 이 도메인의 레코드를 읽고, MyDC가 만든 레코드만 고칩니다. 기존 레코드는 'MyDC 밖 레코드'로 표시되고 바뀌지 않습니다. 인증서는 DNS 확인으로 받고 와일드카드도 받을 수 있습니다.</span>
    </Dialog>
  );
}

function DetachProviderDialog({ domain, onClose, onDone }: { domain: DnsDomain; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    try {
      await deleteDnsDomainProvider(domain.domain);
      toast(`${domain.domain}에서 ${domain.provider?.name}을(를) 뗐습니다 · 도메인은 목록에 남음`);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`${domain.domain}에서 ${domain.provider?.name}을(를) 뗄까요?`}
      width={560}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn danger" disabled={busy} onClick={() => void go()}>
            {busy ? '떼는 중…' : '떼기'}
          </button>
        </>
      }
    >
      {error !== undefined && <div className="note er">✗ {dnsErrorText(error)}</div>}
      <p>
        도메인 {domain.domain}는 목록에 남고{domain.certificates ? ` 링크된 인증서 ${domain.certificates}개도` : ' 링크된 인증서도'} 그대로입니다. 웹이 레코드를 더 고치지 않고, 이 도메인의 인증서는 HTTP 확인으로만 갱신합니다. 공급자의 레코드는 남습니다.
      </p>
    </Dialog>
  );
}

export const useVendorName = () => {
  const vq = usePoll((s) => dnsVendors(s), []);
  return useMemo(() => (id: string) => vq.data?.items.find((v) => v.id === id)?.name ?? id, [vq.data]);
};

/** 외부 접속이 켜진 서버와 공개 주소 (캔버스 ExtDomains '외부 접속 서버') */
function IngressServersCard({ q, domains, first }: { q: ReturnType<typeof usePoll<Awaited<ReturnType<typeof ingress>>>>; domains: string[]; first?: string }) {
  const nodes = (q.data?.nodes ?? []).filter((n) => n.module || n.isolated);
  const cols = { gridTemplateColumns: '0.8fr 1.7fr 1.3fr 0.9fr' };
  return (
    <Card title={q.data ? `외부 접속 서버 (${nodes.length})` : '외부 접속 서버'} actions={first ? <Link to={`/system/domains/${encodeURIComponent(first)}/servers`}>도메인에 연결하기 →</Link> : undefined}>
      <span className="small muted">외부 접속(ingress)이 켜진 서버만 나옵니다. 공개 주소는 바깥에서 그 서버에 닿는 IP로, NAT 뒤라면 서버 주소와 다릅니다. 도메인 상세의 '연결된 서버'에서 도메인마다 고릅니다.</span>
      {q.error !== undefined && ingressMissing(q.error) ? (
        <Empty kind="scope" title="서버 기능 대기">
          어느 서버에 외부 접속이 켜져 있고 어떤 주소로 받는지는 mydcd 외부 접속 조회가 들어오면 보여 줍니다.
        </Empty>
      ) : (
        <Load q={q} rows={3} what="외부 접속 서버를 읽지 못했습니다">
          {(v) =>
            nodes.length ? (
              <div className="gtbl">
                <div className="gr th" style={cols}>
                  <span>서버</span>
                  <span>공개 주소</span>
                  <span>연결된 도메인</span>
                  <span>상태</span>
                </div>
                {nodes.map((n) => {
                  const [tone, label] = nodeIngressState(n);
                  const ds = nodeDomains(v, n.node, domains);
                  return (
                    <div key={n.node} className="gr" style={cols}>
                      <b>{n.node}</b>
                      <span className="mono">{n.external?.address ?? '—'}</span>
                      <span className="mono small">{ds.join(', ') || '—'}</span>
                      <span>
                        <Badge tone={tone}>{label}</Badge>
                      </span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <Empty kind="filtered" title="외부 접속이 켜진 서버가 없습니다" />
            )
          }
        </Load>
      )}
    </Card>
  );
}
