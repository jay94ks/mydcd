// SPDX-License-Identifier: Apache-2.0

// 망 › 도메인 이름 탭 (UI-52, 캔버스 v214 NetworkDns): 망별 도메인 이름 설정 표, 고른 망에서 찾을 수 있는 이름, 설정 카드(변경 검토).
// 이름 목록·서버별 반영 상태는 GET /t/{t}/networks/{name}/dns/names(#625), 직접 더한 이름(A·AAAA·CNAME·TXT·MX·SRV·CAA, 캔버스 v221)은 PATCH …/dns/records(#631·#636, 읽은 revision 기준 변경분 remove·add).
import { DraftBand, useStoredDraft, useUnsaved } from '../components/Unsaved';
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTenantRole } from '../auth/session';
import type { NetworkView } from '../api/types';
import { dnsRecordsPath, networkDnsNames, type NetworkDnsNames } from '../api/endpoints';
import { checkSpec, countAfter, fullName, relName, groupRecords, MAX_RECORDS, MAX_SET, RECORD_TYPES, recordDelta, showValue, specOk, VALUE_COLS, valueParts, type RecordGroup, type RecordType } from '../lib/dnsRecords';
import { Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { useToast } from '../components/Toast';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';
import { ApiError } from '../api/client';
import { Badge, Card, Field, HelpBox } from '../components/ui';
import { Load } from '../components/states';
import { DataTable } from '../components/DataTable';
import { DNS_TTL_DEFAULT, DnsReviewDialog, useDnsDraft } from './NetworkChange';
import { NET_NEED, NetFrame, useNetLists } from './NetFrame';
import { networkDnsLive } from '../lib/liveTopics';

/** 지우는 중: 변경 계획 없이 비우는 서버가 있음 */
const deleting = (n: NetworkView) => n.members.some((x) => x.draining && !x.phase);
const on = (n: NetworkView) => !!n.dns?.enabled;
/** 서버마다 DNS가 실제로 듣는 주소(:53은 뺌). 반영 상태가 없는 데몬이면 멤버의 resolver */
const resolvers = (n: NetworkView) => [...new Set(n.members.flatMap((x) => (x.dns?.resolvers.length ? x.dns.resolvers.map((r) => r.replace(/:53$/, '')) : x.resolver ? [x.resolver] : [])))];

/** 반영 상태: 참여 서버 중 이름 확인 주소가 생긴 서버 수 */
export function dnsState(n: NetworkView): { tone?: 'ok' | 'pr'; text: string } {
  if (deleting(n)) return { text: '지우는 중' };
  if (!on(n)) return { text: n.dns ? '꺼짐' : '설정 없음' };
  const all = n.members.length;
  // 서버별 반영 상태(#625)가 있으면 그것으로, 없으면 이름 확인 주소가 생긴 서버 수로 센다
  const done = n.members.some((x) => x.dns) ? n.members.filter((x) => x.dns?.ready === true).length : n.members.filter((x) => x.resolver).length;
  const lost = n.members.filter((x) => x.dns?.state === 'unreachable').length;
  if (done >= all) return { tone: 'ok', text: '반영됨' };
  return { tone: 'pr', text: `반영 중 ${done}/${all}${lost ? ` · 연결 안 됨 ${lost}` : ''}` };
}

export function NetworkDnsPage() {
  const { tenant, nq, rq, bq } = useNetLists();
  const [sp, setSp] = useSearchParams();
  const pick = sp.get('net') ?? '';
  const select = (n: NetworkView) => setSp({ net: n.name }, { replace: true });
  const nameCounts = useNameCounts(tenant ?? '', nq.data?.items);
  return (
    <NetFrame
      ids="UI-52"
      q={nq}
      nq={nq}
      rq={rq}
      bq={bq}
      actions={<span className="muted" style={{ fontSize: 13 }}>망마다 따로 설정</span>}
      help={
        <HelpBox terms="도메인 영역 (zone) · 이름 확인 서버 (resolver) · 외부 이름 확인 서버 (forwarder) · 캐시 TTL 상한 (cache max TTL)">
          <b>이 화면은</b> 망 안에서 앱이 서로를 이름으로 찾는 도메인 이름(DNS)을 망마다 설정합니다. 앱 서비스는 <span className="mono">서비스.앱.도메인 영역</span> 이름을 저절로 얻습니다. 망 밖 이름은 외부 이름 확인 서버로 넘깁니다. 인터넷에 공개하는 도메인은 여기가 아니라 시스템 › 외부 도메인에서 다룹니다.
        </HelpBox>
      }
    >
      <Load q={nq} what="망을 불러오지 못했습니다">
        {(p) => {
          const cur = p.items.find((n) => n.name === pick) ?? p.items[0];
          const counts = Object.fromEntries(Object.entries(nameCounts).filter(([k]) => p.items.some((n) => n.key === k)));
          return (
            <>
              <Card title="망별 도메인 이름 설정">
                <DataTable
                  rows={p.items}
                  rowKey={(n) => n.key}
                  pageInfo={p}
                  emptyTitle="망이 없습니다"
                  onRowClick={select}
                  selectedKey={cur?.key}
                  columns={[
                    { key: 'name', header: '망', value: (n) => n.name, render: (n) => (n.key === cur?.key ? <b>{n.name}</b> : n.name) },
                    { key: 'zone', header: '도메인 영역', value: (n) => n.dns?.zone ?? '', render: (n) => <span className="mono">{n.dns?.zone || '—'}</span> },
                    { key: 'resolver', header: '이름 확인 서버', value: (n) => resolvers(n).join(' '), render: (n) => <span className="mono">{on(n) && resolvers(n).length ? resolvers(n).join(' · ') : '—'}</span> },
                    { key: 'ups', header: '외부 이름 확인 서버', value: (n) => (n.dns?.upstreams ?? []).join(' '), render: (n) => <span className="mono">{!n.dns ? '—' : n.dns.upstreams?.length ? n.dns.upstreams.join(', ') : '상위 망 따름'}</span> },
                    { key: 'ttl', header: '캐시 TTL 상한', value: (n) => n.dns?.ttl ?? -1, render: (n) => (n.dns?.ttl !== undefined ? `${n.dns.ttl}초` : '—') },
                    { key: 'names', header: '이름', value: (n) => counts[n.key] ?? -1, render: (n) => (counts[n.key] !== undefined ? counts[n.key] : <span className="muted">—</span>) },
                    {
                      key: 'state',
                      header: '상태',
                      value: (n) => dnsState(n).text,
                      render: (n) => {
                        const s = dnsState(n);
                        return s.tone ? <Badge tone={s.tone}>{s.text}</Badge> : <span className="muted">{s.text}</span>;
                      },
                    },
                  ]}
                />
                <span className="small muted">줄을 누르면 아래에서 그 망의 이름과 설정을 봅니다. 바꾼 설정은 그 망의 참여 서버마다 차례로 반영되며, 반영 중에도 이전 설정으로 이름 확인은 계속됩니다.</span>
              </Card>
              {cur && (
                <div className="main-side">
                  <NamesCard key={`names/${cur.key}`} tenant={tenant ?? ''} net={cur} />
                  <DnsSettingsCard key={`settings/${cur.key}`} tenant={tenant ?? ''} net={cur} onDone={() => void nq.refresh()} />
                </div>
              )}
            </>
          );
        }}
      </Load>
    </NetFrame>
  );
}

/** 망마다 이름 수(표의 '이름' 칸). 관리 DNS가 켜진 망만 읽는다 */
function useNameCounts(tenant: string, items?: NetworkView[]) {
  const [counts, setCounts] = useState<Record<string, number>>({});
  const keys = (items ?? []).filter((n) => n.dns).map((n) => `${n.key}@${n.dns!.revision}`).join(',');
  useEffect(() => {
    if (!tenant || !items) return;
    const ac = new AbortController();
    for (const n of items.filter((x) => x.dns))
      networkDnsNames(tenant, n.name, ac.signal)
        .then((r) => setCounts((c) => ({ ...c, [n.key]: new Set([...r.names, ...r.records].map((x) => x.name)).size })))
        .catch(() => undefined);
    return () => ac.abort();
  }, [tenant, keys]);
  return counts;
}

const SERVER_STATE: Record<string, string> = { ready: '반영됨', 'not-ready': '반영 중', unreachable: '연결 안 됨', unknown: '모름' };
const dot = (n: string) => n.replace(/\.$/, '');

/** 이름별로 묶은 줄: 복제본이 여럿이면 주소가 여럿 */
export function groupNames(r: NetworkDnsNames) {
  const by = new Map<string, { name: string; family: string; addresses: string[]; app: string; service: string; tasks: number }>();
  for (const x of r.names) {
    const k = `${x.name}/${x.family}`;
    const g = by.get(k) ?? { name: dot(x.name), family: x.family, addresses: [], app: x.app, service: x.service, tasks: 0 };
    if (!g.addresses.includes(x.address)) g.addresses.push(x.address);
    g.tasks += 1;
    by.set(k, g);
  }
  return [...by.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/** 고른 망에서 찾을 수 있는 이름과 서버마다 반영 상태 */
function NamesCard({ tenant, net }: { tenant: string; net: NetworkView }) {
  const { canDeploy } = useTenantRole();
  const [dlg, setDlg] = useState<{ kind: 'edit'; g?: RecordGroup } | { kind: 'remove'; g: RecordGroup }>();
  const q = usePoll((s) => (on(net) ? networkDnsNames(tenant, net.name, s) : Promise.resolve(undefined)), [tenant, net.name, net.dns?.revision, on(net)], 30_000, networkDnsLive(tenant, net.name));
  const [find, setFind] = useState('');
  const toast = useToast();
  const rows = useMemo(() => (q.data ? groupNames(q.data) : []), [q.data]);
  const recs = useMemo(() => (q.data ? groupRecords(q.data.records, q.data.zone) : []), [q.data]);
  const f = find.toLowerCase();
  const shown = rows.filter((r) => !f || `${r.name} ${r.addresses.join(' ')} ${r.app} ${r.service}`.toLowerCase().includes(f));
  const shownRecs = recs.filter((r) => !f || `${fullName(r.name, zone)} ${r.type} ${r.values.map((v) => showValue(r.type, v)).join(' ')}`.toLowerCase().includes(f));
  const zone = (q.data?.zone ?? net.dns?.zone ?? '').replace(/\.$/, '');
  const why = !canDeploy ? NET_NEED : !on(net) ? '도메인 이름이 꺼진 망입니다' : !q.data?.managed ? '관리 DNS 설정이 없습니다' : undefined;
  return (
    <Card
      title={`${net.name}에서 찾을 수 있는 이름${q.data ? ` (${rows.length + recs.length})` : ''}`}
      actions={
        <>
          <input placeholder="이름 찾기" value={find} onChange={(e) => setFind(e.target.value)} style={{ height: 32, width: 200, fontSize: 13 }} disabled={!rows.length && !recs.length} aria-label="이름 찾기" />
          <button className="btn" disabled={!!why} title={why} onClick={() => (q.data && q.data.records.length >= MAX_RECORDS ? toast(`${net.name}에 직접 더한 값이 ${MAX_RECORDS}개라 더 더할 수 없습니다. 쓰지 않는 이름을 먼저 빼세요.`, 'er') : setDlg({ kind: 'edit' }))}>
            ＋ 이름 더하기
          </button>
        </>
      }
    >
      {!on(net) ? (
        <span className="small muted">이 망은 도메인 이름이 꺼져 있습니다. 설정에서 도메인 영역을 정하면 켜집니다.</span>
      ) : (
        <Load q={q} what="이름 목록을 읽지 못했습니다">
          {(r) =>
            !r ? null : (
              <>
                <div className="table-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>이름</th>
                        <th>종류</th>
                        <th>값</th>
                        <th>어디서</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {!shown.length && !shownRecs.length && (
                        <tr>
                          <td colSpan={5} className="muted">
                            {rows.length || recs.length ? '찾는 이름이 없습니다.' : '아직 이름이 없습니다. 이 망에 붙은 앱 서비스가 배포되면 저절로 생깁니다.'}
                          </td>
                        </tr>
                      )}
                      {shown.map((x) => (
                        <tr key={`${x.name}/${x.family}`}>
                          <td className="mono">{x.name}</td>
                          <td>{x.family === 'ipv6' ? 'AAAA' : 'A'}</td>
                          <td className="mono small">{x.addresses.join(', ')}</td>
                          <td className="small">
                            앱 서비스 {x.app} › {x.service}
                            {x.tasks > 1 ? ` (${x.tasks})` : ''}
                          </td>
                          <td />
                        </tr>
                      ))}
                      {shownRecs.map((x) => (
                        <tr key={`rec/${x.name}/${x.type}`}>
                          <td className="mono">{fullName(x.name, zone)}</td>
                          <td>{x.type}</td>
                          <td className="mono small">
                            {x.values.map((v) => showValue(x.type, v)).join(', ')}
                            {x.ttl ? <span className="muted"> · TTL {x.ttl}초</span> : null}
                          </td>
                          <td className="small">
                            직접 더한 이름 {!x.served && <Badge tone="un">쉬는 중 · 앱 서비스가 같은 이름을 씀</Badge>}
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <Menu
                              label={`${x.name} 메뉴`}
                              items={[
                                { label: '고치기…', onSelect: () => setDlg({ kind: 'edit', g: x }), disabledReason: why },
                                { label: '빼기…', danger: true, onSelect: () => setDlg({ kind: 'remove', g: x }), disabledReason: why },
                              ]}
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {r.servers.length > 0 && (
                  <span className="small">
                    서버별 반영:{' '}
                    {r.servers.map((x, i) => (
                      <span key={x.node}>
                        {i ? ' · ' : ''}
                        <span className="mono">{x.node}</span> <span className={x.state === 'unreachable' ? 'er' : x.ready === false || x.state === 'not-ready' ? 'muted' : ''}>{x.ready === false && x.state === 'ready' ? '이전 설정' : (SERVER_STATE[x.state] ?? x.state)}</span>
                      </span>
                    ))}
                  </span>
                )}
              </>
            )
          }
        </Load>
      )}
      <span className="small muted">앱 서비스·가상 브릿지·연결이 만드는 이름은 저절로 생기고 지워집니다. 직접 더한 이름만 고치거나 지울 수 있습니다. 직접 더할 수 있는 종류는 A · AAAA · CNAME · TXT · MX · SRV · CAA입니다(PTR은 망의 역방향 이름 옵션이 저절로 만듦).</span>
      {dlg && q.data && (
        <RecordDialog
          tenant={tenant}
          net={net}
          data={q.data}
          group={dlg.g}
          remove={dlg.kind === 'remove'}
          others={recs.filter((r) => !(dlg.g && r.name === dlg.g.name && r.type === dlg.g.type))}
          appNames={[...new Set(rows.map((r) => relName(r.name, zone)))]}
          onClose={() => setDlg(undefined)}
          onDone={() => void q.refresh()}
        />
      )}
    </Card>
  );
}

function DnsSettingsCard({ tenant, net, onDone }: { tenant: string; net: NetworkView; onDone: () => void }) {
  const { canDeploy } = useTenantRole();
  const draft = useDnsDraft(net);
  const [review, setReview] = useState(false);
  const rev = net.dns?.revision ?? 0;
  // 적용 뒤 새로 읽은 정책으로 칸과 expected를 맞춘다(검토 창이 열려 있는 동안은 그대로)
  useEffect(() => {
    if (!review && rev !== (draft.d.revision ?? 0)) draft.reset(net);
  }, [rev, review]);
  const off = deleting(net);
  const why = !canDeploy ? NET_NEED : off ? '지우는 중인 망입니다' : undefined;
  // 저장 안 한 입력 지키기(캔버스 v224 UnsavedGuard)
  const d0 = draft.d;
  const count = [draft.zone !== d0.zone, draft.ups !== (d0.upstreams ?? []).join(', '), draft.ttl !== (d0.ttl !== undefined ? String(d0.ttl) : '')].filter(Boolean).length;
  const scope = `${tenant}/${net.name}`;
  const stored = useStoredDraft<{ zone: string; ups: string; ttl: string }>('network-dns', scope);
  const un = useUnsaved({ dirty: draft.changed && !review, what: `${net.name} 도메인 이름 설정`, count, draft: { kind: 'network-dns', scope, value: { zone: draft.zone, ups: draft.ups, ttl: draft.ttl }, rev } });
  return (
    <Card
      title={
        <span className="row" style={{ gap: 8 }}>
          <h2>설정 · {net.name}</h2>
          {un.badge}
        </span>
      }
    >
      {un.guard}
      {stored.draft && !draft.changed && !why && (
        <DraftBand
          draft={stored.draft}
          what={net.name}
          rev={rev}
          onResume={() => {
            const v = stored.draft!.value;
            draft.setZone(v.zone);
            draft.setUps(v.ups);
            draft.setTtl(v.ttl);
            stored.drop();
          }}
          onDiscard={stored.drop}
        />
      )}
      <Field label="도메인 영역">
        <input className="mono" value={draft.zone} onChange={(e) => draft.setZone(e.target.value.trim().toLowerCase())} placeholder="shop.sfc.test" disabled={!!why} />
      </Field>
      <Field label="이름 확인 서버 주소" hint="참여 서버마다 망의 첫 주소 · sfcd가 정함">
        <input className="mono" value={resolvers(net).join(' · ')} placeholder="—" readOnly disabled />
      </Field>
      <Field label="외부 이름 확인 서버">
        <input className="mono" value={draft.ups} onChange={(e) => draft.setUps(e.target.value)} placeholder="1.1.1.1, 8.8.8.8" disabled={!!why} />
      </Field>
      <Field label="캐시 TTL 상한 (초)" hint={`기본 ${DNS_TTL_DEFAULT}초 · 1–3600`}>
        <input inputMode="numeric" value={draft.ttl} onChange={(e) => draft.setTtl(e.target.value)} placeholder={String(DNS_TTL_DEFAULT)} disabled={!!why} />
      </Field>
      {draft.changed &&
        draft.problems.map((p) => (
          <div key={p} className="note er small">
            {p}
          </div>
        ))}
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="btn" disabled={!draft.changed} onClick={() => draft.reset(net)}>
          되돌리기
        </button>
        <button className="btn primary" disabled={!!why || !draft.changed || draft.problems.length > 0} title={why} onClick={() => setReview(true)}>
          변경 검토
        </button>
      </div>
      {review && <DnsReviewDialog tenant={tenant} net={net} draft={draft} onClose={() => setReview(false)} onDone={() => (un.clear(), onDone())} />}
    </Card>
  );
}

/** 이름 더하기·고치기·빼기. 읽은 revision(expected) 기준의 변경분(remove·add)만 보낸다. 그 사이 바뀌었으면 409 stale */
function RecordDialog({ tenant, net, data, group, remove, others, appNames, onClose, onDone }: { tenant: string; net: NetworkView; data: NetworkDnsNames; group?: RecordGroup; remove: boolean; others: RecordGroup[]; appNames: string[]; onClose: () => void; onDone: () => void }) {
  const zone = (data.zone ?? '').replace(/\.$/, '');
  const [name, setName] = useState(group ? group.name || '@' : '');
  const [type, setType] = useState<RecordType>(group?.type ?? 'CNAME');
  const blank = (t: RecordType) => VALUE_COLS[t].map(() => '');
  const [rows, setRows] = useState<string[][]>(group?.values.length ? group.values.map((v) => valueParts(group.type, v)) : [blank(group?.type ?? 'CNAME')]);
  const [ttl, setTtl] = useState(group?.ttl ? String(group.ttl) : '');
  const m = useMutation();
  const chk = checkSpec({ name, type, rows, ttl }, { zone, net: net.name, others, appNames, editing: group });
  const ok = specOk(chk);
  const delta = remove ? recordDelta(group) : ok ? recordDelta(group, { name: chk.rel!, type, values: chk.values, ttl: chk.ttl }) : { remove: [], add: [] };
  const tooMany = countAfter(data.records, delta) > MAX_RECORDS;
  const changed = delta.remove.length + delta.add.length > 0;
  const go = async () => {
    const op = await m.run(dnsRecordsPath(tenant, net.name), { expected: data.revision, ...delta }, 'PATCH');
    if (op && op.state !== 'failed' && op.state !== 'rejected') onDone();
  };
  const pickType = (t: RecordType) => {
    if (t === type) return;
    setType(t);
    setRows([blank(t)]);
  };
  const setCell = (i: number, j: number, v: string) => setRows((rs) => rs.map((r, k) => (k === i ? r.map((x, l) => (l === j ? v : x)) : r)));
  const touched = !!name || rows.some((r) => r.some((x) => x.trim())) || !!group;
  const show = touched && !m.op;
  const full = fullName(group?.name ?? '', zone);
  const title = remove ? `${full} 이름을 뺄까요?` : group ? '이름 고치기' : `이름 더하기 · ${net.name}`;
  const cols = VALUE_COLS[type];
  const multi = type !== 'CNAME';
  const grid = type === 'SRV' ? '0.7fr 0.7fr 0.7fr 1.6fr 24px' : type === 'MX' ? '0.6fr 1.8fr 24px' : type === 'CAA' ? '0.9fr 1.6fr 0.5fr 24px' : '1fr 24px';
  const ph: Record<RecordType, string[]> = { A: ['192.0.2.7'], AAAA: ['2001:db8::7'], CNAME: [`web.php-shop.${zone}`], TXT: ['"v=spf1 -all"'], MX: ['10', `mail.${zone}`], SRV: ['10', '50', '389', `ldap.${zone}`], CAA: ['issue', 'letsencrypt.org', '0'] };
  return (
    <Dialog
      title={title}
      width={remove ? 420 : 560}
      danger={remove}
      onClose={onClose}
      footer={
        m.op ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className={remove ? 'btn danger solid' : 'btn primary'} disabled={m.busy || (!remove && (!ok || !changed)) || tooMany} onClick={() => void go()}>
              {m.busy ? '보내는 중…' : remove ? '빼기' : group ? '고치기' : '더하기'}
            </button>
          </>
        )
      }
    >
      {remove ? (
        <p className="small">
          <span className="mono">{full}</span> {group!.type} → {group!.values.map((v) => showValue(group!.type, v)).join(', ')} 이름을 {net.name} 망의 DNS에서 뺍니다. 이 이름을 찾던 앱은 다음 캐시 만료 뒤부터 찾지 못합니다.
        </p>
      ) : (
        <>
          <Field label="이름" hint={type === 'SRV' ? '서비스·프로토콜을 밑줄로: _서비스._tcp 또는 _udp' : `비우면(@) 도메인 영역 자체 · ${fullName(chk.rel ?? 'www', zone)}로 답합니다`} error={show ? chk.name : undefined}>
            <span className="row" style={{ gap: 6 }}>
              <input className={`mono${show && chk.name ? ' bad' : ''}`} value={name} onChange={(e) => setName(e.target.value)} placeholder={type === 'SRV' ? '_ldap._tcp' : 'www'} disabled={!!m.op} autoFocus style={{ flex: 1 }} aria-label="이름" />
              <span className="mono muted">.{zone}</span>
            </span>
          </Field>
          <Field label="종류" error={show ? chk.type : undefined} group>
            {group ? (
              <input value={RECORD_TYPES.find((x) => x[0] === type)?.[1] ?? type} disabled title="고치기에서는 종류를 바꿀 수 없습니다" aria-label="종류" />
            ) : (
              <Menu label="종류" align="left" className={`picker${show && chk.type ? ' bad' : ''}`} button={<><span>{RECORD_TYPES.find((x) => x[0] === type)?.[1]}</span><span className="muted">▾</span></>} items={RECORD_TYPES.map(([t, label, hint]) => ({ label, hint, onSelect: () => pickType(t) }))} />
            )}
          </Field>
          {multi && cols.length > 1 ? (
            <Field label="값" error={show ? chk.value?.join(' ') : undefined} group>
              <div className="gtbl edit small">
                <div className="gr th" style={{ gridTemplateColumns: grid }}>
                  {cols.map((c) => (
                    <span key={c}>{c}</span>
                  ))}
                  <span />
                </div>
                {rows.map((r, i) => (
                  <div key={i} className="gr" style={{ gridTemplateColumns: grid }}>
                    {r.map((x, j) => (
                      <input key={j} className="mono" value={x} placeholder={ph[type][j]} onChange={(e) => setCell(i, j, e.target.value)} disabled={!!m.op} aria-label={`${cols[j]} ${i + 1}`} />
                    ))}
                    <RowX n={rows.length} onClick={() => setRows((rs) => rs.filter((_, k) => k !== i))} />
                  </div>
                ))}
              </div>
            </Field>
          ) : (
            <Field label={cols[0] === '값' ? '값' : cols[0]} hint={VALUE_HINT[type]} error={show ? chk.value?.join(' ') : undefined} group={multi}>
              {rows.map((r, i) => (
                <span key={i} className="row" style={{ gap: 6 }}>
                  <input className="mono" value={r[0]} placeholder={ph[type][0]} onChange={(e) => setCell(i, 0, e.target.value)} disabled={!!m.op} style={{ flex: 1 }} aria-label={`${cols[0]} ${i + 1}`} />
                  {multi && <RowX n={rows.length} onClick={() => setRows((rs) => rs.filter((_, k) => k !== i))} />}
                </span>
              ))}
            </Field>
          )}
          {multi && type !== 'TXT' && type !== 'A' && type !== 'AAAA' && VALUE_HINT[type] && <span className="small muted">{VALUE_HINT[type]}</span>}
          {multi && !m.op && (
            <button type="button" className="linkish small" style={{ alignSelf: 'flex-start' }} disabled={rows.length >= MAX_SET} title={rows.length >= MAX_SET ? `한 이름·종류에 값은 ${MAX_SET}개까지입니다` : undefined} onClick={() => setRows((rs) => [...rs, blank(type)])}>
              ＋ 값 더하기
            </button>
          )}
          <Field label="TTL (초, 선택)" hint="1–3600. 비우면 망의 캐시 TTL 상한(기본 10초)을 씁니다. 상한보다 크면 상한으로 줄여 답합니다. 같은 이름·종류의 값은 TTL이 같습니다." error={show ? chk.ttlError : undefined}>
            <input value={ttl} onChange={(e) => setTtl(e.target.value)} placeholder={String(DNS_TTL_DEFAULT)} inputMode="numeric" disabled={!!m.op} aria-label="TTL" />
          </Field>
        </>
      )}
      {tooMany && <div className="note er small">{net.name}에 직접 더한 값은 {MAX_RECORDS}개까지입니다. 쓰지 않는 이름을 먼저 빼세요.</div>}
      {!remove && <span className="small muted">직접 더한 이름은 역방향(PTR) 이름을 만들지 않습니다. 앱 서비스가 같은 이름을 갖게 되면 그동안 앱 서비스의 주소로 답합니다. 저장은 바뀐 값만 보냅니다.</span>}
      {stale(m.error) ? <div className="note wa small">그 사이 이 망의 도메인 이름 설정이 바뀌었습니다. 창을 닫고 새로 읽은 목록에서 다시 하세요.</div> : <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), onDone())} />}
    </Dialog>
  );
}
const VALUE_HINT: Record<RecordType, string> = {
  A: '0.0.0.0·멀티캐스트·255.255.255.255 제외',
  AAAA: '::·멀티캐스트·IPv4 매핑 제외',
  CNAME: '전체 이름 · 자기 자신은 안 됨',
  TXT: '따옴표 문자열 하나가 255바이트를 넘으면 255바이트 조각으로 나눕니다 · 최대 16조각, 전체 1024바이트',
  MX: '우선순위 0–65535 · 메일 서버는 전체 이름',
  SRV: '우선순위·가중치·포트는 0–65535 · 대상은 전체 이름',
  CAA: '태그 issue · issuewild · iodef · 플래그 128이면 모르는 태그를 거절(critical) · 값 255바이트',
};
function RowX({ n, onClick }: { n: number; onClick: () => void }) {
  if (n <= 1) return <span />;
  return (
    <button type="button" className="linkish muted" title="이 값 빼기" aria-label="이 값 빼기" onClick={onClick}>
      ✕
    </button>
  );
}
const stale = (e: unknown) => e instanceof ApiError && e.status === 409 && e.code === 'stale';
