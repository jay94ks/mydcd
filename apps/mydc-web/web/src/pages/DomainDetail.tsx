// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, Navigate, Route, Routes, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useAuth } from '../auth/session';
import { ApiError } from '../api/client';
import { tenantList } from '../api/endpoints';
import {
  applyDns,
  deleteDnsHistory,
  dnsDomains,
  dnsHistory,
  dnsPropagation,
  dnsRecords,
  dnsSnapshots,
  fqdn,
  inRange,
  keyOf,
  nameProblem,
  parseRecordLine,
  planDns,
  putDnsDomain,
  recordText,
  restoreDnsSnapshot,
  revertDns,
  setText,
  type DnsAssignment,
  type DnsChangeReq,
  type DnsDomain,
  type DnsHistory,
  type DnsKey,
  type DnsPlan,
  type DnsPlannedChange,
  type DnsPropagation,
  type DnsRecordView,
  type DnsZoneView,
  type RRSet,
  checkDnsServers,
  dnsServers,
  putDnsServer,
  type DnsServerLink,
  type DnsServersView,
} from '../api/dns';
import { Badge, Card, Field, HelpBox, KV, PageHeader, Segmented } from '../components/ui';
import { Empty, ErrorBand, Load } from '../components/states';
import { ingressMissing } from '../api/ingress';
import { ConfirmDialog, Dialog } from '../components/Dialog';
import { Drawer } from '../components/Drawer';
import { Menu, type MenuItem } from '../components/Menu';
import { Tabs } from '../components/Tabs';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { ago, fmtTime } from '../lib/format';
import { dnsErrorText, Logo, zoneState } from './Domains';
import { eulReul } from '../lib/josa';
import { usePhone } from '../lib/viewport';
import { MDomainDetail } from './MDomainDetail';

/** 응답을 잃어 결과를 모르는 실패. 같은 작업 ID로 다시 보내야 한다. */
const lostReply = (e: unknown) => e instanceof ApiError && (e.code === 'dns-unavailable' || e.code === 'transport' || e.status === 0 || e.status >= 500);

/** 고친 내용: 이름|형식 → 새 묶음(upsert) 또는 null(지우기). 바로 보내지 않고 모았다가 계획 → 적용한다. */
type Staged = Record<string, RRSet | null>;

const uuid = () => crypto.randomUUID();
const PURPOSE: Record<string, string> = { MX: '메일', CAA: '인증서 발급 허용' };
const purpose = (r: RRSet) => (r.type === 'TXT' && r.records.some((x) => /^v=spf1|^v=DMARC1|^google-site-verification/i.test(x.content)) ? '메일·검증' : (PURPOSE[r.type] ?? ''));

export function DomainDetailPage() {
  return usePhone() ? <MDomainDetail /> : <DesktopDomainDetail />;
}

function DesktopDomainDetail() {
  const { domain = '' } = useParams();
  const { session } = useAuth();
  const admin = !!session?.user.systemAdmin;
  const dq = usePoll((s) => dnsDomains(s).then((ds) => ds.find((d) => d.domain === domain)), [domain]);
  const zq = usePoll((s) => dnsRecords(domain, s), [domain]);
  const hq = usePoll((s) => dnsHistory(domain, s), [domain]);
  const [staged, setStaged] = useState<Staged>({});
  // 기록에서 되돌리기로 담은 내용. 손대지 않고 적용하면 기록에 '되돌리기'로 남긴다.
  const [revert, setRevert] = useState<{ of: string; key: string }>();
  const revertOf = revert && JSON.stringify(staged) === revert.key ? revert.of : undefined;
  // MyDC 밖 레코드 잠금. 이 화면(도메인 상세)을 떠나면 다시 잠긴다.
  const [unlocked, setUnlocked] = useState(false);
  const [search] = useSearchParams();
  const [check, setCheck] = useState<DnsKey | 'pick' | undefined>(search.get('check') ? 'pick' : undefined);
  const nav = useNavigate();
  const toast = useToast();
  const base = `/system/domains/${encodeURIComponent(domain)}`;
  const d = dq.data;
  const z = zq.data;
  const st = zoneState(z, zq.error, d ? !d.provider : false);
  const reread = () => {
    zq.refresh();
    hq.refresh();
    toast('공급자에서 다시 읽었습니다');
  };

  return (
    <>
      <PageHeader
        crumbs={
          <>
            <Link to="/system/domains">외부 도메인</Link> / {domain}
          </>
        }
        title={<span className="mono" style={{ fontSize: 'inherit' }}>{domain}</span>}
        ids="UI-56"
        actions={
          <>
            {d?.provider ? (
              <span className="row" style={{ gap: 6 }}>
                <Logo vendor={d.provider.vendor} sm />
                <span className="muted">{d.provider.name}</span>
              </span>
            ) : d ? (
              <span className="muted">DNS 공급자 없음 · HTTP 확인만</span>
            ) : null}
            <Badge tone={st.tone} title={zq.error ? dnsErrorText(zq.error) : undefined}>
              {st.text}
              {z ? ` · ${ago(z.readAt)} 읽음` : ''}
            </Badge>
            <button className="btn" disabled={d && !d.provider} onClick={reread}>
              다시 읽기
            </button>
            <button className="btn" disabled={!z?.capabilities.propagation} title={z && !z.capabilities.propagation ? '이 공급자는 반영 확인을 지원하지 않습니다' : undefined} onClick={() => setCheck('pick')}>
              반영 확인
            </button>
          </>
        }
      />
      <Tabs
        label="도메인 탭"
        items={[
          { to: `${base}/records`, label: `레코드${z ? ` (${z.items.length})` : ''}` },
          { to: `${base}/servers`, label: '연결된 서버' },
          { to: `${base}/assign`, label: `작업 공간 배정${d?.assignments ? ` (${d.assignments.length})` : ''}` },
          ...(admin ? [{ to: `${base}/snapshots`, label: '되돌리기 지점' }] : []),
          { to: `${base}/history`, label: '바꾼 기록' },
        ]}
      />
      <Load q={dq}>
        {(dd) =>
          !dd ? (
            <Empty kind="scope" title="이 도메인이 없거나 볼 권한이 없습니다">
              <Link to="/system/domains">외부 도메인 목록</Link>으로 돌아가세요.
            </Empty>
          ) : (
            <Routes>
              {/* 주소 끝이 '.com' 같은 확장자로 끝나면 정적 서버가 파일로 보고 404를 내므로 탭 이름을 늘 붙인다. */}
              <Route index element={<Navigate replace to={`${base}/records${search.toString() ? `?${search}` : ''}`} />} />
              <Route
                path="records"
                element={
                  !dd.provider ? (
                    <Empty kind="scope" title="DNS 공급자가 없는 도메인입니다">
                      레코드는 직접 관리합니다. <Link to="/system/domains">외부 도메인</Link>에서 공급자를 붙이면 웹 UI가 레코드를 읽고 MyDC가 만든 레코드를 고칩니다.
                    </Empty>
                  ) : (
                  <RecordsTab
                    domain={dd}
                    zq={zq}
                    admin={admin}
                    staged={staged}
                    setStaged={setStaged}
                    revertOf={revertOf}
                    unlocked={unlocked}
                    setUnlocked={setUnlocked}
                    onCheck={(k) => setCheck(k)}
                    onApplied={() => {
                      void zq.refresh();
                      void hq.refresh();
                    }}
                  />
                  )
                }
              />
              <Route
                path="servers"
                element={
                  <ServersTab
                    domain={dd}
                    admin={admin}
                    onStaged={(ch) => {
                      // 서버는 바꿀 내용을 저장하지 않는다. 받은 changes를 이 화면의 바꿀 내용에 담고, 레코드 탭에서 plan·apply한다.
                      setStaged((s) => {
                        const n = { ...s };
                        for (const u of ch.upsert) n[keyOf(u)] = u;
                        for (const k of ch.delete) n[keyOf(k)] = null;
                        return n;
                      });
                      void zq.refresh();
                    }}
                  />
                }
              />
              <Route path="assign" element={<AssignTab domain={dd} admin={admin} onChanged={() => void dq.refresh()} onShow={() => nav(`${base}/records`)} />} />
              <Route path="snapshots" element={<SnapshotsTab domain={dd} onRestored={() => void zq.refresh()} />} />
              <Route
                path="history"
                element={
                  <HistoryTab
                    domain={dd}
                    hq={hq}
                    admin={admin}
                    onRevert={(req, of) => {
                      const s: Staged = {};
                      for (const u of req.upsert ?? []) s[keyOf(u)] = u;
                      for (const k of req.delete ?? []) s[keyOf(k)] = null;
                      setStaged(s);
                      setRevert({ of, key: JSON.stringify(s) });
                      nav(`${base}/records`);
                      toast('되돌릴 내용을 바꿀 내용에 담았습니다. 검토하고 적용하세요');
                    }}
                  />
                }
              />
            </Routes>
          )
        }
      </Load>
      {check && <PropagationDrawer domain={domain} zone={z} initial={check === 'pick' ? undefined : check} onClose={() => setCheck(undefined)} />}
    </>
  );
}

// ── 레코드 탭 ──

function RecordsTab({
  domain,
  zq,
  admin,
  staged,
  setStaged,
  revertOf,
  unlocked,
  setUnlocked,
  onCheck,
  onApplied,
}: {
  domain: DnsDomain;
  zq: ReturnType<typeof usePoll<DnsZoneView>>;
  admin: boolean;
  staged: Staged;
  setStaged: (s: Staged | ((s: Staged) => Staged)) => void;
  revertOf?: string;
  unlocked: boolean;
  setUnlocked: (v: boolean) => void;
  onCheck: (k: DnsKey) => void;
  onApplied: () => void;
}) {
  const [view, setView] = useState<'all' | 'mydc' | 'outside' | 'orphan'>('all');
  const [find, setFind] = useState('');
  const [editing, setEditing] = useState<string>();
  const [dlg, setDlg] = useState<{ kind: 'add'; preset?: RRSet } | { kind: 'unlock' } | { kind: 'discard' } | { kind: 'del'; r: DnsRecordView } | { kind: 'ttl' }>();
  const z = zq.data;
  const caps = z?.capabilities;
  const nStaged = Object.keys(staged).length;
  const filtered = (z?.items ?? []).filter((r) => {
    if (view === 'mydc' && !r.managed) return false;
    if (view === 'outside' && !r.outside) return false;
    if (view === 'orphan') return false;
    const q = find.trim().toLowerCase();
    return !q || r.name.includes(q) || setText(r).toLowerCase().includes(q) || r.type.toLowerCase() === q;
  });
  // 새로 담은 묶음(공급자에 아직 없는 것)도 표에 보인다.
  const added = Object.entries(staged)
    .filter(([k, v]) => v && !(z?.items ?? []).some((r) => keyOf(r) === k))
    .map(([, v]) => v as RRSet);
  const stage = (k: string, v: RRSet | null) => setStaged((s) => ({ ...s, [k]: v }));
  const unstage = (k: string) =>
    setStaged((s) => {
      const { [k]: _, ...rest } = s;
      return rest;
    });
  const tenantOf = (name: string) => domain.assignments?.find((a) => inRange(name, a.names))?.tenant;


  const rowMenu = (r: DnsRecordView): MenuItem[] => {
    const k = keyOf(r);
    const items: MenuItem[] = [];
    if (staged[k] !== undefined) items.push({ label: '담은 변경 빼기', onSelect: () => unstage(k) });
    items.push({ label: '편집', onSelect: () => setEditing(k), disabledReason: r.writable ? undefined : '배정받은 범위 밖이거나 보기 권한만 있습니다' });
    items.push({ label: '값 복사', onSelect: () => void navigator.clipboard?.writeText(r.records.map(recordText).join('\n')) });
    if (caps?.propagation) items.push({ label: '반영 확인', onSelect: () => onCheck(r) });
    if (r.managed?.app && r.managed.tenant) items.push({ label: `만든 앱 열기 · ${r.managed.app} ↗`, onSelect: () => window.open(`/deploy/apps/${encodeURIComponent(r.managed!.tenant!)}/${encodeURIComponent(r.managed!.app!)}`, '_blank') });
    items.push({ label: '지우기 (바꿀 내용에 추가)', danger: true, disabledReason: r.writable ? undefined : '바꿀 권한이 없습니다', onSelect: () => (r.outside ? setDlg({ kind: 'del', r }) : stage(k, null)) });
    return items;
  };
  const locked = (r: DnsRecordView) => r.outside && !unlocked;

  return (
    <>
      <HelpBox terms="레코드 묶음 (같은 이름·형식, RRSet) · TTL (캐시 시간, 초) · 고아 표시 (MyDC가 만든 표시만 남고 공급자에서 사라진 레코드) · 반영 확인 (propagation)">
        <b>이 탭은</b> 공급자에 있는 이 도메인의 레코드를 그대로 보여 줍니다. <b>MyDC</b> 표시는 웹 UI가 만든 레코드이고, <b>MyDC 밖</b> 레코드(메일·검증용 등)는 기본으로 잠겨 있습니다. 고친 내용은 바로 보내지 않고 아래 '바꿀 내용'에 모았다가 미리 검사 → 확인 → 적용합니다. 적용 직전에 공급자 값을 다시 읽어, 그 사이 다른 곳에서 바뀌었으면 멈춥니다.
      </HelpBox>
      <Card
        title={
          <span className="row">
            <Segmented
              label="레코드 보기"
              value={view}
              onChange={setView}
              options={[
                ['all', '전체'],
                ['mydc', 'MyDC'],
                ['outside', 'MyDC 밖'],
                ['orphan', `고아 ${z?.orphans?.length ?? 0}`],
              ]}
            />
            <input type="search" placeholder="이름·값 찾기" aria-label="이름·값 찾기" value={find} onChange={(e) => setFind(e.target.value)} style={{ width: 180 }} />
          </span>
        }
        actions={
          <>
            {admin &&
              (unlocked ? (
                <button className="btn" onClick={() => setUnlocked(false)}>
                  🔓 MyDC 밖 레코드 다시 잠그기
                </button>
              ) : (
                <button className="btn" onClick={() => setDlg({ kind: 'unlock' })}>
                  MyDC 밖 레코드 잠금 풀기…
                </button>
              ))}
            <button className="btn primary" disabled={!admin && !domain.myNames?.length} title={!admin && !domain.myNames?.length ? '이 도메인에 바꿀 수 있는 이름 범위가 없습니다' : undefined} onClick={() => setDlg({ kind: 'add' })}>
              ＋ 레코드
            </button>
          </>
        }
      >
        <Load q={zq} what="공급자에서 레코드를 읽지 못했습니다">
          {(zz) =>
            view === 'orphan' ? (
              (zz.orphans ?? []).length === 0 ? (
                <Empty kind="filtered" title="고아 표시가 없습니다" />
              ) : (
                <>
                  <div className="table-wrap">
                    <table className="tbl">
                      <thead>
                        <tr>
                          <th>형식</th>
                          <th>이름</th>
                          <th>만든 곳</th>
                          <th>배정</th>
                          <th>만든 때</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(zz.orphans ?? []).map((o) => (
                          <tr key={keyOf(o)}>
                            <td>
                              <span className="rt">{o.type}</span>
                            </td>
                            <td className="mono">{o.name}</td>
                            <td>
                              <span className="mg">MyDC · {o.app ?? '배정 규칙'}</span>
                            </td>
                            <td className="muted">{o.tenant ? `작업 공간 ${o.tenant}` : '—'}</td>
                            <td className="muted">
                              {fmtTime(o.at)} · {o.by}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <span className="small muted">MyDC가 만든 표시는 남았지만 공급자에는 그 레코드가 없습니다. 공급자 화면에서 누군가 지운 것입니다. 같은 이름·형식으로 다시 만들면 표시가 새 값으로 바뀝니다.</span>
                </>
              )
            ) : (
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>형식</th>
                      <th>이름</th>
                      <th>값</th>
                      <th>TTL</th>
                      <th>만든 곳</th>
                      <th>배정 · 용도</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((r) => {
                      const k = keyOf(r);
                      const s = staged[k];
                      const cls = s === null ? 'del' : s ? 'chg' : '';
                      if (editing === k)
                        return (
                          <InlineEdit
                            key={k}
                            r={r}
                            minTtl={caps?.minTtl ?? 60}
                            onCancel={() => setEditing(undefined)}
                            onSave={(v) => {
                              stage(k, v);
                              setEditing(undefined);
                            }}
                          />
                        );
                      const drift = r.managed && r.managed.fingerprint !== r.fingerprint;
                      return (
                        <tr key={k} className={cls}>
                          <td>
                            <span className="rt">{r.type}</span>
                          </td>
                          <td className="mono">{r.name}</td>
                          <td className="mono el" title={setText(s ?? r)}>
                            {setText(s ?? r)}
                          </td>
                          <td>{s && s.ttl !== r.ttl ? `${r.ttl} → ${s.ttl}` : r.ttl}</td>
                          <td>
                            {r.managed ? <span className="mg">MyDC · {r.managed.app ?? '배정 규칙'}</span> : r.outside ? <span className="ext">MyDC 밖</span> : <span className="ext">배정 범위 · 직접</span>}
                            {drift && (
                              <>
                                {' '}
                                <Badge tone="wa" title="MyDC가 만든 뒤 공급자 쪽에서 값이 바뀌었습니다">
                                  값 다름
                                </Badge>
                              </>
                            )}
                          </td>
                          <td className="muted">{r.managed?.tenant ? `작업 공간 ${r.managed.tenant}` : tenantOf(r.name) ? `작업 공간 ${tenantOf(r.name)}` : purpose(r)}</td>
                          <td>
                            {s === null ? (
                              <span className="row" style={{ gap: 6 }}>
                                <Badge tone="er">지움</Badge>
                                <Menu items={rowMenu(r)} />
                              </span>
                            ) : s ? (
                              <span className="row" style={{ gap: 6 }}>
                                <Badge tone="wa">바뀜</Badge>
                                <Menu items={rowMenu(r)} />
                              </span>
                            ) : locked(r) ? (
                              <span className="muted" title="MyDC 밖 레코드는 잠겨 있습니다">
                                🔒
                              </span>
                            ) : (
                              <Menu items={rowMenu(r)} />
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {view !== 'outside' &&
                      added.map((a) => (
                        <tr key={keyOf(a)} className="add">
                          <td>
                            <span className="rt">{a.type}</span>
                          </td>
                          <td className="mono">{a.name}</td>
                          <td className="mono el">{setText(a)}</td>
                          <td>{a.ttl || domain.defaultTtl}</td>
                          <td>{tenantOf(a.name) ? <span className="mg">MyDC</span> : <span className="ext">MyDC 밖</span>}</td>
                          <td className="muted">{tenantOf(a.name) ? `작업 공간 ${tenantOf(a.name)}` : ''}</td>
                          <td>
                            <span className="row" style={{ gap: 6 }}>
                              <Badge tone="ok">추가</Badge>
                              <Menu items={[{ label: '담은 변경 빼기', onSelect: () => unstage(keyOf(a)) }]} />
                            </span>
                          </td>
                        </tr>
                      ))}
                    {filtered.length + added.length === 0 && (
                      <tr>
                        <td colSpan={7} className="muted">
                          {zz.items.length ? '조건에 맞는 레코드가 없습니다' : '레코드가 없습니다'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )
          }
        </Load>
        {caps && (
          <span className="small muted">
            공급자가 지원하는 형식: {caps.recordTypes.join(' · ')}
            {caps.wildcard ? ' · 와일드카드 가능' : ''} · 최소 TTL {caps.minTtl}. 지원하지 않는 기능은 버튼이 보이지 않습니다.
          </span>
        )}
      </Card>
      <div className="grid wide">
        <StagedCard
          domain={domain}
          zone={z}
          staged={staged}
          revertOf={revertOf}
          unlocked={unlocked}
          onDiscard={() => setDlg({ kind: 'discard' })}
          onUnlock={admin ? () => setDlg({ kind: 'unlock' }) : undefined}
          onClear={() => setStaged({})}
          // 지금 값으로 다시 계획: 내 변경은 그대로 두고 공급자 값을 다시 읽으면 계획이 새로 돈다.
          onReplan={() => zq.refresh()}
          onApplied={() => {
            setStaged({});
            onApplied();
          }}
        />
        <Card title="이 도메인의 설정" actions={admin && <button className="btn sm" onClick={() => setDlg({ kind: 'ttl' })}>설정 바꾸기</button>}>
          <KV
            items={[
              ['연결된 서버', <LinkedServersText key="s" domain={domain.domain} />],
              ['기본 TTL', `${domain.defaultTtl}초 · 새로 만드는 레코드에 씀`],
              ['작업 공간 배정', domain.assignments?.length ? domain.assignments.map((a) => `${a.tenant} (${a.names.length})`).join(', ') : '없음 · 시스템 관리자만'],
              ['연결한 사람', domain.addedBy ? `${domain.addedBy} · ${fmtTime(domain.addedAt)}` : '—'],
            ]}
          />
          {nStaged > 0 && <span className="small muted">바꿀 내용 {nStaged}개가 아직 공급자에 가지 않았습니다.</span>}
        </Card>
      </div>
      {dlg?.kind === 'add' && (
        <RecordDialog
          domain={domain}
          zone={z}
          admin={admin}
          onClose={() => setDlg(undefined)}
          onAdd={(set) => {
            stage(keyOf(set), set);
            setDlg(undefined);
          }}
        />
      )}
      {dlg?.kind === 'unlock' && (
        <ConfirmDialog title="MyDC 밖 레코드를 고칠 수 있게 할까요?" target={domain.domain} actionLabel="잠금 풀기" onClose={() => setDlg(undefined)} onConfirm={() => (setUnlocked(true), setDlg(undefined))}>
          <p>메일(MX·SPF)·도메인 검증용 TXT처럼 MyDC와 상관없는 레코드도 고치거나 지울 수 있게 됩니다. 잘못 바꾸면 메일이 끊길 수 있습니다. 이 화면을 떠나면 다시 잠깁니다.</p>
        </ConfirmDialog>
      )}
      {dlg?.kind === 'discard' && (
        <Dialog
          title={`바꿀 내용 ${nStaged}개를 모두 버릴까요?`}
          width={420}
          danger
          onClose={() => setDlg(undefined)}
          footer={
            <>
              <button className="btn" onClick={() => setDlg(undefined)}>
                취소
              </button>
              <button className="btn danger solid" onClick={() => (setStaged({}), setDlg(undefined))}>
                모두 버리기
              </button>
            </>
          }
        >
          <p>공급자에는 아직 아무것도 보내지 않았습니다. 버리면 이 화면에서 고친 내용이 사라집니다.</p>
        </Dialog>
      )}
      {dlg?.kind === 'del' && (
        <Dialog
          title={`${dlg.r.type} ${dlg.r.name} 레코드를 지울까요?`}
          width={420}
          danger
          onClose={() => setDlg(undefined)}
          footer={
            <>
              <button className="btn" onClick={() => setDlg(undefined)}>
                취소
              </button>
              <button className="btn danger solid" onClick={() => (stage(keyOf(dlg.r), null), setDlg(undefined))}>
                바꿀 내용에 추가
              </button>
            </>
          }
        >
          <p>
            <code>
              {dlg.r.type} {dlg.r.name} {setText(dlg.r)}
            </code>{' '}
            을(를) 지웁니다.{dlg.r.type === 'MX' ? ` ${domain.domain}으로 오는 메일을 받을 수 없게 됩니다.` : ' MyDC 밖 레코드라 다른 서비스가 쓰고 있을 수 있습니다.'}
          </p>
        </Dialog>
      )}
      {dlg?.kind === 'ttl' && <SettingsDialog domain={domain} onClose={() => setDlg(undefined)} onSaved={onApplied} />}
    </>
  );
}

function InlineEdit({ r, minTtl, onCancel, onSave }: { r: RRSet; minTtl: number; onCancel: () => void; onSave: (v: RRSet) => void }) {
  const [vals, setVals] = useState(r.records.map(recordText).join('\n'));
  const [ttl, setTtl] = useState(String(r.ttl));
  const parsed = vals.split('\n').filter((l) => l.trim()).map((l) => parseRecordLine(r.type, l));
  const bad = parsed.find((p) => typeof p === 'string') as string | undefined;
  const ttlBad = !(Number(ttl) >= minTtl) ? `최소 ${minTtl}` : undefined;
  return (
    <tr className="chg">
      <td>
        <span className="rt">{r.type}</span>
      </td>
      <td className="mono">{r.name}</td>
      <td className="wrap">
        <textarea aria-label="값 (줄마다 하나)" className="mono" rows={Math.max(1, r.records.length)} value={vals} onChange={(e) => setVals(e.target.value)} style={{ width: '100%', minHeight: 36 }} />
        {bad && <span className="small" style={{ color: 'var(--er)' }}>{bad}</span>}
      </td>
      <td>
        <input aria-label="TTL" value={ttl} onChange={(e) => setTtl(e.target.value)} style={{ width: 72 }} title={ttlBad} />
      </td>
      <td colSpan={3}>
        <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
          <button className="btn sm" onClick={onCancel}>
            취소
          </button>
          <button className="btn primary sm" disabled={!!bad || !!ttlBad || !parsed.length} onClick={() => onSave({ name: r.name, type: r.type, ttl: Number(ttl), records: parsed as RRSet['records'] })}>
            담기
          </button>
        </span>
      </td>
    </tr>
  );
}

function RecordDialog({ domain, zone, admin, onClose, onAdd }: { domain: DnsDomain; zone?: DnsZoneView; admin: boolean; onClose: () => void; onAdd: (s: RRSet) => void }) {
  const caps = zone?.capabilities;
  const types = (caps?.recordTypes ?? ['A', 'AAAA', 'CNAME', 'MX', 'TXT']).filter((t) => admin || t !== 'NS');
  const [type, setType] = useState('A');
  const [ttl, setTtl] = useState(String(domain.defaultTtl));
  const [name, setName] = useState('');
  const [vals, setVals] = useState('');
  const n = name.trim().toLowerCase().replace(new RegExp(`\\.?${domain.domain.replace(/\./g, '\\.')}\\.?$`), '') || (name.trim() ? '@' : '');
  const nameBad = nameProblem(n, caps?.wildcard ?? true) ?? (!admin && !inRange(n, domain.myNames ?? []) ? `배정받은 범위 밖입니다(${(domain.myNames ?? []).join(', ') || '없음'})` : undefined);
  const parsed = vals.split('\n').filter((l) => l.trim()).map((l) => parseRecordLine(type, l));
  const valBad = !parsed.length ? '값을 적으세요' : (parsed.find((p) => typeof p === 'string') as string | undefined) ?? (type === 'CNAME' && parsed.length > 1 ? 'CNAME은 값 하나만' : undefined);
  const ttlBad = !(Number(ttl) >= (caps?.minTtl ?? 60)) ? `최소 ${caps?.minTtl ?? 60}` : undefined;
  const exists = zone?.items.find((r) => r.name === n && r.type === type);
  const tenant = domain.assignments?.find((a) => inRange(n, a.names))?.tenant;
  const prio = type === 'MX' || type === 'SRV';
  return (
    <Dialog
      title="레코드 추가"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!!nameBad || !!valBad || !!ttlBad} onClick={() => onAdd({ name: n, type, ttl: Number(ttl), records: parsed as RRSet['records'] })}>
            {exists ? '그 묶음 바꾸기로 담기' : '바꿀 내용에 추가'}
          </button>
        </>
      }
    >
      <div className="g2">
        <Field label="형식">
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {types.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </Field>
        <Field label="TTL (초)" hint={`최소 ${caps?.minTtl ?? 60}`} error={ttlBad}>
          <input value={ttl} onChange={(e) => setTtl(e.target.value)} />
        </Field>
      </div>
      <Field label="이름" hint={`@ = 도메인 자신, *.shop = 와일드카드${n && !nameBad ? ` · ${fqdn(n, domain.domain)}` : ''}`} error={name && nameBad}>
        <span className="row" style={{ gap: 6 }}>
          <input className="mono grow" value={name} placeholder="api" onChange={(e) => setName(e.target.value)} />
          <span className="mono muted">.{domain.domain}</span>
        </span>
      </Field>
      <Field label={prio ? '값 (줄마다 "우선순위 값")' : '값 (줄마다 하나)'} error={vals && valBad}>
        <textarea className="mono" rows={3} value={vals} placeholder={prio ? '10 mx1.example.com.' : type === 'CNAME' ? 'shop.example.com.' : type === 'TXT' ? 'v=spf1 -all' : '203.0.113.10'} onChange={(e) => setVals(e.target.value)} />
      </Field>
      {exists && <div className="note un">같은 이름·형식 묶음이 이미 있습니다({setText(exists)}). 담으면 그 묶음 전체가 이 값으로 바뀝니다.</div>}
      {exists?.outside ? (
        <div className="note wa">MyDC 밖 레코드입니다. 적용하려면 잠금을 풀어야 합니다.</div>
      ) : (
        admin && n && !nameBad && !exists && !tenant && <div className="note un">어느 작업 공간에도 배정되지 않은 이름이라 MyDC 밖 레코드로 만듭니다. 적용하려면 잠금을 풀어야 합니다.</div>
      )}
      <KV items={[['배정 작업 공간', tenant ?? (admin ? '없음 · 시스템 관리자' : '—')]]} />
      <span className="small muted">어디로 가리키나: 연결된 서버의 공개 주소를 따라가게 하려면 '연결된 서버' 탭에서 서버를 연결하세요. 여기 값은 직접 입력한 고정 값입니다.</span>
    </Dialog>
  );
}

function diffText(c: { name: string; type: string; before: RRSet | null; after: RRSet | null }, domain: string) {
  const line = (sign: string, s: RRSet) => `${sign} ${s.type.padEnd(5)} ${fqdn(s.name, domain).padEnd(26)} ${String(s.ttl).padEnd(5)} ${setText(s)}`;
  return [c.before && line('-', c.before), c.after && line('+', c.after)].filter(Boolean) as string[];
}

function StagedCard({
  domain,
  zone,
  staged,
  revertOf,
  unlocked,
  onDiscard,
  onClear,
  onReplan,
  onApplied,
  onUnlock,
}: {
  domain: DnsDomain;
  zone?: DnsZoneView;
  staged: Staged;
  revertOf?: string;
  unlocked: boolean;
  onUnlock?: () => void;
  onDiscard: () => void;
  onClear: () => void;
  onReplan: (c: DnsPlannedChange[]) => void;
  onApplied: () => void;
}) {
  const toast = useToast();
  const [plan, setPlan] = useState<DnsPlan>();
  const [planErr, setPlanErr] = useState<unknown>();
  const [applying, setApplying] = useState<{ phase: 'send' | 'done' | 'changed' | 'error'; error?: unknown; changes?: DnsPlannedChange[]; history?: DnsHistory }>();
  const opId = useRef<string>();
  const req = useMemo<DnsChangeReq>(() => {
    const r: DnsChangeReq = { upsert: [], delete: [] };
    for (const [k, v] of Object.entries(staged)) {
      if (v) r.upsert.push(v);
      else {
        const [name, type] = k.split('|');
        r.delete.push({ name, type });
      }
    }
    return r;
  }, [staged]);
  // MyDC가 만들지 않았고 어느 작업 공간에도 배정되지 않은 이름(데몬이 outside:true를 요구한다)
  const all = (domain.assignments ?? []).flatMap((a) => a.names);
  const outsideKeys = Object.keys(staged).filter((k) => {
    const cur = zone?.items.find((x) => keyOf(x) === k);
    return cur ? cur.outside : !inRange(k.split('|')[0], all);
  });
  const needUnlock = outsideKeys.length > 0 && !unlocked;
  const outside = outsideKeys.length > 0 ? true : undefined;
  const n = req.upsert.length + req.delete.length;
  const key = JSON.stringify(req) + (zone?.readAt ?? '');

  // 바꿀 내용이 바뀌면 새 작업 ID로 다시 계획한다(아무것도 바꾸지 않는 미리 계산).
  useEffect(() => {
    setPlan(undefined);
    setPlanErr(undefined);
    opId.current = undefined;
    if (!n || needUnlock) return;
    let live = true;
    const t = setTimeout(() => {
      planDns(domain.domain, { ...req, outside }).then(
        (p) => live && setPlan(p),
        (e) => live && setPlanErr(e),
      );
    }, 250);
    return () => {
      live = false;
      clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, needUnlock]);

  const apply = async () => {
    if (!plan) return;
    opId.current ??= uuid();
    setApplying({ phase: 'send' });
    const basis = Object.fromEntries(plan.changes.map((c) => [`${c.name}|${c.type}`, c.fingerprint]));
    try {
      const r = await applyDns(domain.domain, { ...req, outside, revertOf, opId: opId.current, basis });
      setApplying({ phase: 'done', history: r.history });
      toast(`✓ ${domain.domain} 레코드 묶음 ${r.history.changes.length}개를 바꿨습니다`);
      opId.current = undefined;
      onApplied();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'zone-changed') {
        opId.current = undefined;
        setApplying({ phase: 'changed', changes: (e.body.raw as { changes?: DnsPlannedChange[] })?.changes ?? [] });
      } else {
        // 응답을 잃었으면(공급자 연결 끊김·웹 서버 연결 끊김·5xx) 같은 작업 ID로 다시 보내야 두 번 바꾸지 않는다.
        if (!lostReply(e)) opId.current = undefined;
        setApplying({ phase: 'error', error: e });
      }
    }
  };
  const lines = plan ? plan.changes.flatMap((c) => diffText(c, domain.domain)) : Object.entries(staged).flatMap(([k, v]) => diffText({ name: k.split('|')[0], type: k.split('|')[1], before: zone?.items.find((r) => keyOf(r) === k) ?? null, after: v }, domain.domain));

  return (
    <Card title={`바꿀 내용 (${n})`} actions={n > 0 && <button className="btn sm" onClick={onDiscard}>모두 취소</button>}>
      {n === 0 ? (
        <span className="small muted">표에서 고치거나 ＋ 레코드로 담으면 여기에 모입니다. 공급자에는 적용을 눌러야 갑니다.</span>
      ) : (
        <>
          <pre className="dnsdiff">
            {lines.map((l, i) => (
              <span key={i} className={l.startsWith('+') ? 'a' : 'r'}>
                {l}
              </span>
            ))}
          </pre>
          {needUnlock ? (
            <div className="note wa">
              MyDC 밖 레코드({outsideKeys.map((k) => k.replace('|', ' ')).join(', ')})가 들어 있습니다. 배정받지 않은 이름이라 MyDC 레코드로 표시하지 않습니다. 적용하려면 잠금을 풀어야 합니다.{' '}
              {onUnlock && (
                <button className="btn sm" onClick={onUnlock}>
                  잠금 풀기…
                </button>
              )}
            </div>
          ) : planErr !== undefined ? (
            <div className="note er">✗ {dnsErrorText(planErr)}</div>
          ) : !plan ? (
            <span className="small muted">공급자 값과 맞춰 계획하는 중…</span>
          ) : plan.problems.length ? (
            <div className="note er">
              ✗ 공급자 미리 검사에서 걸렸습니다
              <ul>
                {plan.problems.map((p, i) => (
                  <li key={i}>
                    {p.type} {p.name}: {p.message}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="note ok">✓ {zone?.capabilities.validate ? '공급자 미리 검사 통과 (validate)' : '계획 완료 · 이 공급자는 미리 검사를 하지 않습니다'}</div>
          )}
          {plan?.changes.some((c) => c.outside) && <div className="note wa">MyDC 밖 레코드가 들어 있습니다. 적용해도 MyDC 레코드로 표시하지 않습니다.</div>}
          <span className="small muted">{zone?.capabilities.snapshots ? '적용 직전 상태는 공급자 되돌리기 지점으로 남습니다. ' : ''}바꾼 기록에서 하나씩 되돌릴 수도 있습니다.</span>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <button className="btn primary" disabled={needUnlock || !plan || plan.problems.length > 0 || applying?.phase === 'send'} onClick={() => void apply()}>
              적용 (레코드 묶음 {n}개)
            </button>
          </div>
        </>
      )}
      {applying && applying.phase !== 'done' && (
        <ApplyDialog
          domain={domain.domain}
          state={applying}
          snapshots={!!zone?.capabilities.snapshots}
          staged={staged}
          zone={zone}
          onClose={() => setApplying(undefined)}
          onRetry={() => void apply()}
          onDiscard={() => {
            onClear();
            setApplying(undefined);
          }}
          onReplan={() => {
            onReplan(applying.changes ?? []);
            setApplying(undefined);
          }}
        />
      )}
    </Card>
  );
}

function ApplyDialog({
  domain,
  state,
  snapshots,
  staged,
  onClose,
  onRetry,
  onDiscard,
  onReplan,
}: {
  domain: string;
  state: { phase: 'send' | 'done' | 'changed' | 'error'; error?: unknown; changes?: DnsPlannedChange[] };
  snapshots: boolean;
  staged: Staged;
  zone?: DnsZoneView;
  onClose: () => void;
  onRetry: () => void;
  onDiscard: () => void;
  onReplan: () => void;
}) {
  if (state.phase === 'changed')
    return (
      <Dialog
        title="적용을 멈췄습니다"
        danger
        onClose={onClose}
        footer={
          <>
            <button className="btn" onClick={onDiscard}>
              바꿀 내용 버리기
            </button>
            <button className="btn primary" onClick={onReplan}>
              지금 값으로 다시 계획
            </button>
          </>
        }
      >
        <p>계획한 뒤 공급자 쪽에서 {state.changes?.map((c) => `${c.type} ${c.name}`).join(', ')} 묶음이 바뀌었습니다. 덮어쓰지 않으려고 아무것도 보내지 않았습니다.</p>
        {state.changes?.map((c) => (
          <pre key={`${c.name}|${c.type}`} className="dnsdiff">
            {`지금   : ${c.before ? `${c.type} ${c.name} ${c.before.ttl} ${setText(c.before)}` : '(없음)'}\n내 변경: ${staged[`${c.name}|${c.type}`] ? `${c.type} ${c.name} ${staged[`${c.name}|${c.type}`]!.ttl} ${setText(staged[`${c.name}|${c.type}`])}` : '지우기'}`}
          </pre>
        ))}
      </Dialog>
    );
  const err = state.phase === 'error' ? state.error : undefined;
  const unknown = lostReply(err);
  return (
    <Dialog
      title={`${domain}에 적용`}
      onClose={onClose}
      footer={
        state.phase === 'send' ? (
          <span className="small muted">공급자에 보내는 중입니다…</span>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              닫기
            </button>
            <button className="btn primary" onClick={onRetry}>
              {unknown ? '같은 작업으로 다시 보내기' : '다시 시도'}
            </button>
          </>
        )
      }
    >
      <ol className="steps" style={{ flexDirection: 'column' }}>
        <li className={state.phase === 'send' ? 'on' : 'done'}>공급자 값 다시 읽기 · 계획 때와 같은지</li>
        <li className={state.phase === 'send' ? '' : 'done'}>공급자 미리 검사 (validate)</li>
        {snapshots && <li className={state.phase === 'send' ? '' : 'done'}>되돌리기 지점 남기기</li>}
        <li className={state.phase === 'send' ? '' : err ? '' : 'done'}>묶음 {Object.keys(staged).length}개 바꾸기</li>
      </ol>
      {err !== undefined && (
        <div className="note er">
          {unknown ? '공급자 응답을 받지 못했습니다. 바뀌었는지 모르니, 같은 작업으로 다시 보내면 공급자를 두 번 부르지 않고 결과를 확인합니다. 바꾼 기록에도 "결과 모름"으로 남습니다.' : dnsErrorText(err)}
          {err instanceof ApiError && err.code === 'dns-auth-failed' && (
            <>
              {' '}
              <Link to="/system/domains">토큰 바꾸기</Link>
            </>
          )}
        </div>
      )}
    </Dialog>
  );
}

function SettingsDialog({ domain, onClose, onSaved }: { domain: DnsDomain; onClose: () => void; onSaved: () => void }) {
  const [ttl, setTtl] = useState(String(domain.defaultTtl));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const bad = !(Number(ttl) >= 60 && Number(ttl) <= 86400) ? '60~86400' : undefined;
  const save = async () => {
    setBusy(true);
    try {
      await putDnsDomain(domain.domain, { defaultTtl: Number(ttl), assignments: domain.assignments ?? [] });
      onSaved();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`${domain.domain} 설정`}
      width={420}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!!bad || busy} onClick={() => void save()}>
            저장
          </button>
        </>
      }
    >
      {error !== undefined && <ErrorBand error={error} what="저장하지 못했습니다" />}
      <Field label="기본 TTL (초)" hint="새로 만드는 MyDC 레코드에 씀" error={bad}>
        <input value={ttl} onChange={(e) => setTtl(e.target.value)} />
      </Field>
      <span className="small muted">배포가 끝나면 앱 외부 접속 호스트의 A·AAAA는 '연결된 서버' 탭의 공개 주소로 만들어집니다.</span>
    </Dialog>
  );
}

// ── 연결된 서버 탭 ──

type DnsChanges = NonNullable<DnsServersView['changes']>;
function ServersTab({ domain, admin, onStaged }: { domain: DnsDomain; admin: boolean; onStaged: (ch: DnsChanges) => void }) {
  const toast = useToast();
  const q = usePoll((s) => dnsServers(domain.domain, s), [domain.domain]);
  const [dlg, setDlg] = useState<{ kind: 'link'; node?: string } | { kind: 'edit'; x: DnsServerLink } | { kind: 'unlink'; x: DnsServerLink }>();
  const [checking, setChecking] = useState(false);
  const linked = (q.data?.items ?? []).filter((x) => x.linked);
  const check = async () => {
    setChecking(true);
    try {
      const r = await checkDnsServers(domain.domain);
      const bad = r.items.filter((x) => !x.ok);
      toast(bad.length ? `닿지 않는 서버: ${bad.map((x) => x.node).join(', ')}` : `연결된 서버 ${r.items.length}대 모두 바깥에서 닿습니다.`);
      void q.refresh();
    } catch (e) {
      toast(`반영 확인 실패: ${e instanceof ApiError ? e.message : String(e)}`);
    } finally {
      setChecking(false);
    }
  };
  const cols = { gridTemplateColumns: '0.7fr 0.8fr 1.6fr 1fr 1.2fr 0.9fr 60px' };
  const NEED_ADMIN = '시스템 관리자만 서버를 연결합니다';
  return (
    <Card
      title={q.data ? `연결된 서버 (${linked.length})` : '연결된 서버'}
      actions={
        <span className="row" style={{ gap: 8 }}>
          <button className="btn" disabled={checking || !linked.length} onClick={() => void check()}>
            반영 확인
          </button>
          <button className="btn primary" disabled={!admin || !q.data?.items.some((x) => !x.linked)} title={admin ? undefined : NEED_ADMIN} onClick={() => setDlg({ kind: 'link' })}>
            ＋ 서버 연결
          </button>
        </span>
      }
    >
      <span className="small muted">이 도메인의 MyDC 레코드(A·AAAA)는 아래 서버들의 공개 주소를 가리킵니다. 서버를 연결하거나 빼면 MyDC 레코드 전체의 바꿀 내용이 만들어지고, 검토 후 적용합니다.</span>
      {q.error !== undefined && ingressMissing(q.error) ? (
        <Empty kind="scope" title="웹 기능 준비 중">
          연결된 서버 목록과 연결·빼기는 웹 데몬에 이 기능이 들어오면 켭니다. 그때까지는 레코드 탭에서 A·AAAA를 직접 고칠 수 있습니다.
        </Empty>
      ) : (
      <Load q={q} rows={3} what="연결된 서버를 읽지 못했습니다">
        {(d) => (
          <>
          {admin && !!d.staged && d.changes && (
            <div className="note wa row between">
              <span>MyDC 레코드 {d.staged}개가 연결된 서버 주소와 다릅니다(서버가 빠졌거나 주소가 바뀜).</span>
              <button className="btn sm" onClick={() => onStaged(d.changes!)}>
                바꿀 내용에 담기
              </button>
            </div>
          )}
          {d.partial && <span className="small muted">연결한 서버만 보입니다. 서버 주소·격리 상태와 연결·끊기는 시스템 관리자만 봅니다.</span>}
          <div className="table-wrap">
            <div className="gtbl" style={{ minWidth: 860 }}>
              <div className="gr th" style={cols}>
                <span>서버</span>
                <span>외부 접속 수신</span>
                <span>공개 주소</span>
                <span>바깥에서 닿는지</span>
                <span>서버에 문제가 생기면</span>
                <span>상태</span>
                <span />
              </div>
              {d.items.map((x) => (
                <div key={x.node} className="gr" style={cols}>
                  {x.linked ? <b>{x.node}</b> : <span>{x.node}</span>}
                  <span className="mono">{x.listen.map((p) => `:${p}`).join(', ')}</span>
                  <span>
                    <span className="mono">{x.addresses.length ? x.addresses.join(' · ') : d.partial ? '서버 주소 (관리자만 봄)' : '—'}</span>
                    {x.linked && <span className="small muted" style={{ display: 'block' }}>{x.addressSource === 'manual' ? '직접 입력 (NAT 뒤)' : '서버 주소 그대로'}</span>}
                  </span>
                  <span>{!x.linked ? <span className="muted">—</span> : x.reach ? <Badge tone={x.reach.ok ? 'ok' : 'er'} title={x.reach.error}>{`${x.reach.ok ? '닿음' : '안 닿음'} · ${ago(x.reach.at)}`}</Badge> : <span className="muted">아직 확인 안 함</span>}</span>
                  <span>{!x.linked ? '—' : x.autoRemove ? 'DNS에서 자동으로 빼기' : '알림만'}</span>
                  <span>{!x.linked ? <Badge tone="un">연결 안 함</Badge> : x.state === 'removed' ? <Badge tone="wa">{x.missing ? '게이트웨이 없음 · DNS에서 뺌' : x.isolated ? '격리됨 · DNS에서 뺌' : 'DNS에서 뺌'}</Badge> : x.missing ? <Badge tone="er">게이트웨이 없음</Badge> : <Badge tone="ok">DNS에 있음</Badge>}</span>
                  <span>
                    {x.linked ? (
                      <Menu
                        items={[
                          { label: '설정…', onSelect: () => setDlg({ kind: 'edit', x }), disabledReason: admin ? undefined : NEED_ADMIN },
                          { label: '연결 끊기…', danger: true, onSelect: () => setDlg({ kind: 'unlink', x }), disabledReason: admin ? (linked.length <= 1 ? '마지막 서버는 끊을 수 없습니다' : undefined) : NEED_ADMIN },
                        ]}
                      />
                    ) : (
                      <button className="btn sm" disabled={!admin} title={admin ? undefined : NEED_ADMIN} onClick={() => setDlg({ kind: 'link', node: x.node })}>
                        연결
                      </button>
                    )}
                  </span>
                </div>
              ))}
            </div>
          </div>
          </>
        )}
      </Load>
      )}
      <span className="small muted">외부 접속이 켜진 서버만 고를 수 있습니다. '바깥에서 닿는지'는 웹 UI가 공개 해석기 경로로 그 주소의 :443에 접속해 이 클러스터의 외부 접속이 응답하는지 봅니다. 서버가 격리·중지되거나 외부 접속이 5분 넘게 멈추면 레코드에서 그 주소를 빼고(마지막 한 대는 빼지 않음), 돌아오면 다시 넣습니다. 끄면 알림만 합니다.</span>
      {q.data && dlg && dlg.kind !== 'unlink' && (
        <LinkServerDialog
          domain={domain.domain}
          items={q.data.items}
          revision={q.data.revision}
          edit={dlg.kind === 'edit' ? dlg.x : undefined}
          node={dlg.kind === 'link' ? dlg.node : undefined}
          onClose={() => setDlg(undefined)}
          onDone={(r) => (void q.refresh(), r.changes && onStaged(r.changes))}
        />
      )}
      {q.data && dlg?.kind === 'unlink' && (
        <ConfirmUnlink domain={domain.domain} x={dlg.x} revision={q.data.revision} onClose={() => setDlg(undefined)} onDone={(r) => (void q.refresh(), r.changes && onStaged(r.changes))} />
      )}
    </Card>
  );
}

function LinkServerDialog({ domain, items, revision, edit, node, onClose, onDone }: { domain: string; items: DnsServerLink[]; revision: number; edit?: DnsServerLink; node?: string; onClose: () => void; onDone: (r: DnsServersView) => void }) {
  const toast = useToast();
  const free = items.filter((x) => !x.linked);
  const [pick, setPick] = useState(edit?.node ?? node ?? free[0]?.node ?? '');
  const x = items.find((i) => i.node === pick);
  const [src, setSrc] = useState<'node' | 'manual'>(edit?.addressSource ?? 'node');
  const [addrs, setAddrs] = useState((edit?.addressSource === 'manual' ? edit.addresses : []).join(', '));
  const [auto, setAuto] = useState(edit?.autoRemove ?? true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [reach, setReach] = useState<{ ok: boolean; error?: string }>();
  const list = addrs.split(',').map((a) => a.trim()).filter(Boolean);
  const bad = src === 'manual' && (!list.length || list.some((a) => !/^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+)$/i.test(a)));
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await putDnsServer(domain, pick, { linked: true, addressSource: src, ...(src === 'manual' ? { addresses: list } : {}), autoRemove: auto, revision });
      toast(`${pick}${eulReul(pick)} ${domain}에 ${edit ? '저장' : '연결'}했습니다. 바꿀 내용 ${r.staged ?? 0}개를 담았습니다. 레코드 탭에서 검토 후 적용하세요.`);
      onDone(r);
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={edit ? `${edit.node} 연결 설정` : '＋ 서버 연결'}
      onClose={onClose}
      footer={
        <>
          <button
            className="btn"
            disabled={!pick || bad}
            onClick={async () => {
              try {
                const r = await checkDnsServers(domain, { node: pick, ...(src === 'manual' ? { addresses: list } : {}) });
                setReach(r.items[0]);
              } catch (e) {
                setError(e);
              }
            }}
          >
            바깥에서 닿는지 시험
          </button>
          <span style={{ flex: 1 }} />
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={busy || !pick || bad} onClick={() => void save()}>
            {edit ? '저장' : '연결'}
          </button>
        </>
      }
    >
      {!edit && (
        <Field label="서버" hint="외부 접속이 켜진 서버 중 아직 연결하지 않은 것">
          <select value={pick} onChange={(e) => (setPick(e.target.value), setReach(undefined))}>
            {free.map((i) => (
              <option key={i.node} value={i.node}>
                {i.node} · {i.listen.map((p) => `:${p}`).join(', ')}
                {i.isolated ? ' · 격리됨' : ''}
              </option>
            ))}
          </select>
        </Field>
      )}
      <Field label="공개 주소">
        <div style={{ display: 'grid', gap: 6 }}>
          <label className="check">
            <input type="radio" name="addr-src" checked={src === 'node'} onChange={() => setSrc('node')} /> 서버 주소 그대로 <span className="mono small muted">{x?.addressSource === 'node' || !x?.linked ? x?.addresses.join(', ') : ''}</span>
          </label>
          <label className="check">
            <input type="radio" name="addr-src" checked={src === 'manual'} onChange={() => setSrc('manual')} /> 직접 입력 (NAT 뒤)
          </label>
          {src === 'manual' && <input className="mono" value={addrs} placeholder="203.0.113.10, 2001:db8::10" onChange={(e) => (setAddrs(e.target.value), setReach(undefined))} aria-label="공개 주소" />}
          {bad && <span className="small" style={{ color: 'var(--er)' }}>IPv4·IPv6 주소, 여러 개는 쉼표</span>}
        </div>
      </Field>
      <Field label="서버에 문제가 생기면">
        <select value={auto ? 'auto' : 'notify'} onChange={(e) => setAuto(e.target.value === 'auto')}>
          <option value="auto">DNS에서 자동으로 빼기 (돌아오면 다시 넣음)</option>
          <option value="notify">알림만</option>
        </select>
      </Field>
      {reach && <div className={`note small ${reach.ok ? 'ok' : 'er'}`}>{reach.ok ? '바깥에서 :443에 닿습니다.' : `닿지 않습니다 · ${reach.error ?? '응답 없음'}`}</div>}
      <span className="small muted">저장하면 이 도메인의 MyDC 레코드(A·AAAA) 바꿀 내용이 만들어집니다. 레코드 탭에서 검토한 뒤 공급자에 적용합니다.</span>
      {error !== undefined && <ErrorBand error={error} what="저장하지 못했습니다" />}
    </Dialog>
  );
}

function ConfirmUnlink({ domain, x, revision, onClose, onDone }: { domain: string; x: DnsServerLink; revision: number; onClose: () => void; onDone: (r: DnsServersView) => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  return (
    <Dialog
      title={`${x.node} 연결을 끊을까요?`}
      width={420}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button
            className="btn danger"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setError(undefined);
              try {
                const r = await putDnsServer(domain, x.node, { linked: false, revision });
                toast(`${x.node} 연결을 끊었습니다. 바꿀 내용 ${r.staged ?? 0}개를 담았습니다. 레코드 탭에서 검토하세요.`);
                onDone(r);
                onClose();
              } catch (e) {
                setError(e);
              } finally {
                setBusy(false);
              }
            }}
          >
            연결 끊기
          </button>
        </>
      }
    >
      <p>{domain}의 MyDC 레코드에서 {x.addresses.join(', ')}를 빼는 바꿀 내용이 만들어집니다. 적용하기 전까지 DNS는 그대로입니다.</p>
      {error !== undefined && <ErrorBand error={error} what="끊지 못했습니다" />}
    </Dialog>
  );
}

// ── 작업 공간 배정 탭 ──

function AssignTab({ domain, admin, onChanged, onShow }: { domain: DnsDomain; admin: boolean; onChanged: () => void; onShow: () => void }) {
  const [dlg, setDlg] = useState<{ kind: 'edit'; a?: DnsAssignment } | { kind: 'drop'; a: DnsAssignment }>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const as = domain.assignments ?? [];
  const save = async (next: DnsAssignment[]) => {
    setBusy(true);
    setError(undefined);
    try {
      await putDnsDomain(domain.domain, { defaultTtl: domain.defaultTtl, assignments: next });
      onChanged();
      setDlg(undefined);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="grid wide">
      <Card title="작업 공간 배정" actions={admin && <button className="btn primary sm" onClick={() => setDlg({ kind: 'edit' })}>＋ 배정</button>}>
        {error !== undefined && !dlg && <ErrorBand error={error} what="배정을 바꾸지 못했습니다" />}
        {as.length === 0 ? (
          <Empty title="배정이 없습니다">배정이 없으면 시스템 관리자만 이 도메인의 레코드를 다룹니다.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>작업 공간</th>
                  <th>쓸 수 있는 이름</th>
                  <th>할 수 있는 일</th>
                  {admin && <th />}
                </tr>
              </thead>
              <tbody>
                {as.map((a) => (
                  <tr key={a.tenant}>
                    <td>
                      <b>{a.tenant}</b>
                    </td>
                    <td className="mono el" title={a.names.map((x) => fqdn(x, domain.domain)).join(', ')}>
                      {a.names.map((x) => fqdn(x, domain.domain)).join(', ')}
                    </td>
                    <td className="muted">관리자: 범위 안 레코드 만들기·바꾸기·지우기 · 보기 권한: 읽기만</td>
                    {admin && (
                      <td>
                        <Menu
                          items={[
                            { label: '배정 편집', onSelect: () => setDlg({ kind: 'edit', a }) },
                            { label: '이 범위의 레코드 보기', onSelect: onShow },
                            { label: '배정 해제…', danger: true, hint: '레코드는 남음', onSelect: () => setDlg({ kind: 'drop', a }) },
                          ]}
                        />
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <span className="small muted">작업 공간 사용자는 그 작업 공간의 관리자일 때 배정받은 이름 안에서만 레코드를 다룹니다. 배정 밖 레코드는 보이지 않습니다. 웹 UI가 범위를 검사한 뒤 클러스터 공용 토큰으로 대신 보내고, 바꾼 기록에 실제 요청자를 남깁니다.</span>
      </Card>
      <Card title="앱 외부 접속에서 쓰는 모습">
        <span className="small muted">배포 › 폼·그래프의 외부 접속 호스트 이름 고르기에 배정받은 범위(예: .{domain.domain})가 나오고, 배포 변경점 아래에 웹 UI가 덧붙이는 DNS 변경이 따로 보입니다. 이 연동은 외부 접속 조회와 함께 붙입니다.</span>
      </Card>
      {dlg?.kind === 'edit' && <AssignDialog domain={domain} current={dlg.a} busy={busy} error={error} onClose={() => (setDlg(undefined), setError(undefined))} onSave={(a) => void save(dlg.a ? as.map((x) => (x.tenant === dlg.a!.tenant ? a : x)) : [...as, a])} />}
      {dlg?.kind === 'drop' && (
        <ConfirmDialog title={`${dlg.a.tenant} 배정을 해제할까요?`} target={dlg.a.tenant} actionLabel="배정 해제" busy={busy} onClose={() => setDlg(undefined)} onConfirm={() => void save(as.filter((x) => x.tenant !== dlg.a.tenant))}>
          <p>작업 공간 {dlg.a.tenant}은(는) 이 도메인의 레코드를 더 보거나 바꾸지 못합니다. 이미 있는 레코드는 그대로 남습니다.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}

function AssignDialog({ domain, current, busy, error, onClose, onSave }: { domain: DnsDomain; current?: DnsAssignment; busy: boolean; error: unknown; onClose: () => void; onSave: (a: DnsAssignment) => void }) {
  const tq = usePoll((s) => tenantList(s), []);
  const [tenant, setTenant] = useState(current?.tenant ?? '');
  const [text, setText] = useState((current?.names ?? []).map((n) => fqdn(n, domain.domain)).join('\n'));
  const strip = (s: string) => {
    const t = s.trim().toLowerCase().replace(/\.$/, '');
    if (t === domain.domain) return '@';
    return t.endsWith(`.${domain.domain}`) ? t.slice(0, -domain.domain.length - 1) : t;
  };
  const names = text.split('\n').map(strip).filter(Boolean);
  const nameBad = names.map((n) => nameProblem(n)).find(Boolean);
  const others = (domain.assignments ?? []).filter((a) => a.tenant !== current?.tenant);
  const overlap = names.flatMap((n) => others.filter((o) => inRange(n, o.names) || o.names.some((p) => inRange(p, [n]))).map((o) => `${fqdn(n, domain.domain)} ↔ ${o.tenant}`));
  const taken = new Set(others.map((o) => o.tenant));
  return (
    <Dialog
      title={current ? `${current.tenant} 배정 편집` : '작업 공간에 이름 배정'}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!tenant || !names.length || !!nameBad || overlap.length > 0 || busy} onClick={() => onSave({ tenant, names })}>
            {current ? '저장' : '배정'}
          </button>
        </>
      }
    >
      {error !== undefined && <ErrorBand error={error} what="배정을 저장하지 못했습니다" />}
      <Field label="작업 공간">
        <select value={tenant} disabled={!!current} onChange={(e) => setTenant(e.target.value)}>
          <option value="">고르세요</option>
          {(tq.data ?? []).map((t) => (
            <option key={t.id} value={t.id} disabled={taken.has(t.id)}>
              {t.id}
              {taken.has(t.id) ? ' (이미 배정됨)' : ''}
            </option>
          ))}
        </select>
      </Field>
      <Field label="쓸 수 있는 이름 (줄마다 하나)" hint={`예: shop.${domain.domain} · *.shop.${domain.domain}`} error={nameBad}>
        <textarea className="mono" rows={3} value={text} onChange={(e) => setText(e.target.value)} />
      </Field>
      {overlap.length > 0 ? <div className="note er">다른 작업 공간에 배정된 이름과 겹칩니다: {overlap.join(', ')}</div> : names.length > 0 && <div className="note ok">지금 겹침 없음.</div>}
    </Dialog>
  );
}

// ── 되돌리기 지점 탭 (시스템 관리자) ──

function SnapshotsTab({ domain, onRestored }: { domain: DnsDomain; onRestored: () => void }) {
  const q = usePoll((s) => dnsSnapshots(domain.domain, s), [domain.domain]);
  const [pick, setPick] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const toast = useToast();
  const unsupported = q.error instanceof ApiError && (q.error.status === 501 || q.error.code === 'unsupported');
  const restore = async () => {
    if (!pick) return;
    setBusy(true);
    try {
      await restoreDnsSnapshot(domain.domain, pick);
      toast(`${domain.domain}을(를) 그 지점으로 되돌렸습니다`);
      onRestored();
      setPick(undefined);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="되돌리기 지점">
      {unsupported ? (
        <Empty kind="scope" title="이 공급자는 되돌리기 지점을 남기지 않습니다">
          바꾼 기록 탭에서 변경을 하나씩 되돌리세요.
        </Empty>
      ) : (
        <Load q={q}>
          {(ss) =>
            ss.length === 0 ? (
              <Empty title="되돌리기 지점이 없습니다">적용할 때마다 적용 직전 상태가 공급자 스냅숏으로 남습니다.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>만든 때</th>
                      <th>만든 곳</th>
                      <th>이유</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {ss.map((s) => (
                      <tr key={s.id}>
                        <td>{fmtTime(s.createdAt)}</td>
                        <td>공급자 스냅숏</td>
                        <td className="muted">{s.reason ?? '—'}</td>
                        <td>
                          <button className="btn sm" onClick={() => setPick(s.id)}>
                            되돌리기…
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </Load>
      )}
      {pick && (
        <ConfirmDialog title={`${fmtTime(q.data?.find((s) => s.id === pick)?.createdAt)} 지점으로 되돌릴까요?`} target={domain.domain} actionLabel="되돌리기" busy={busy} onClose={() => setPick(undefined)} onConfirm={() => void restore()}>
          {error !== undefined && <div className="note er">{dnsErrorText(error)}</div>}
          <p>공급자 스냅숏으로 도메인 전체 레코드를 그때 상태로 되돌립니다. 그 뒤 MyDC 밖에서 바꾼 레코드도 함께 되돌아갑니다.</p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

// ── 바꾼 기록 탭 ──

function HistoryTab({ domain, hq, admin, onRevert }: { domain: DnsDomain; hq: ReturnType<typeof usePoll<DnsHistory[]>>; admin: boolean; onRevert: (r: DnsChangeReq, revertOf: string) => void }) {
  const [open, setOpen] = useState<DnsHistory>();
  const [del, setDel] = useState<DnsHistory>();
  const [error, setError] = useState<unknown>();
  const { session } = useAuth();
  const canRevert = (h: DnsHistory) => admin || (!!h.tenant && session?.tenants.some((t) => t.id === h.tenant && t.role === 'manager'));
  const revert = async (h: DnsHistory) => {
    setError(undefined);
    try {
      const r = await revertDns(domain.domain, h.id);
      onRevert(r.request, r.revertOf);
    } catch (e) {
      setError(e);
    }
  };
  const summary = (h: DnsHistory) => h.changes.map((c) => `${c.after ? (c.before ? '~' : '+') : '−'} ${c.type} ${c.name}`).join(' · ');
  return (
    <Card title="바꾼 기록" actions={<span className="small muted">사용자가 지울 때까지 보관</span>}>
      {error !== undefined && <ErrorBand error={error} what="되돌릴 내용을 만들지 못했습니다" />}
      <Load q={hq}>
        {(hs) =>
          hs.length === 0 ? (
            <Empty title="바꾼 기록이 없습니다" />
          ) : (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>언제</th>
                    <th>누가</th>
                    <th>바꾼 것</th>
                    <th>결과</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {hs.map((h) => (
                    <tr key={h.id} className="clickable" onClick={() => setOpen(h)}>
                      <td>{fmtTime(h.at)}</td>
                      <td>
                        {h.username}
                        {h.tenant ? <span className="muted"> ({h.tenant})</span> : ''}
                      </td>
                      <td className="mono el" title={summary(h)}>
                        {summary(h)}
                        {h.revertOf ? ' (되돌리기)' : ''}
                      </td>
                      <td>
                        <Badge tone={h.result === 'applied' ? 'ok' : h.result === 'failed' ? 'er' : 'un'} title={h.error}>
                          {h.result === 'applied' ? '적용됨' : h.result === 'failed' ? '실패' : '결과 모름'}
                        </Badge>
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <span className="row" style={{ gap: 6 }}>
                          {h.result !== 'failed' && (
                            <button className="btn sm" disabled={!canRevert(h)} title={canRevert(h) ? undefined : '그 작업 공간의 관리자만 되돌립니다'} onClick={() => void revert(h)}>
                              되돌리기
                            </button>
                          )}
                          <button className="btn sm" onClick={() => setOpen(h)}>
                            자세히
                          </button>
                          {admin && <Menu items={[{ label: '기록 지우기…', danger: true, onSelect: () => setDel(h) }]} />}
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
      <span className="small muted">되돌리기는 바꾸기 전 값으로 되돌리는 변경을 바꿀 내용에 담습니다. 그대로 검토 → 적용하세요. '결과 모름'은 공급자 응답을 잃은 것으로, 레코드 탭의 지금 값과 비교하세요.</span>
      {open && (
        <Drawer title={`${fmtTime(open.at)} · ${open.username}`} onClose={() => setOpen(undefined)}>
          <KV
            items={[
              ['결과', open.result === 'applied' ? '적용됨' : open.result === 'failed' ? `실패 · ${open.error ?? ''}` : '결과 모름'],
              ['작업 공간', open.tenant ?? '— (시스템 관리자)'],
              ['되돌리기 지점', open.snapshot ?? '—'],
              ['작업 ID', <code key="id">{open.id}</code>],
            ]}
          />
          {open.changes.map((c) => (
            <pre key={`${c.name}|${c.type}`} className="dnsdiff">
              {diffText(c, domain.domain).map((l, i) => (
                <span key={i} className={l.startsWith('+') ? 'a' : 'r'}>
                  {l}
                </span>
              ))}
            </pre>
          ))}
        </Drawer>
      )}
      {del && <DeleteHistoryDialog domain={domain.domain} h={del} onClose={() => setDel(undefined)} onDone={() => void hq.refresh()} />}
    </Card>
  );
}

function DeleteHistoryDialog({ domain, h, onClose, onDone }: { domain: string; h: DnsHistory; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  return (
    <Dialog
      title="이 기록을 지울까요?"
      width={420}
      danger
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button
            className="btn danger solid"
            disabled={busy}
            onClick={() => {
              setBusy(true);
              deleteDnsHistory(domain, h.id).then(
                () => (onDone(), onClose()),
                (e) => (setError(e), setBusy(false)),
              );
            }}
          >
            지우기
          </button>
        </>
      }
    >
      {error !== undefined && <ErrorBand error={error} what="지우지 못했습니다" />}
      <p>
        {fmtTime(h.at)} {h.username}의 기록을 지웁니다. 공급자 레코드는 바뀌지 않고, 이 변경을 되돌리기로 다시 만들 수 없게 됩니다.
      </p>
    </Dialog>
  );
}

// ── 반영 확인 (드로어) ──

function PropagationDrawer({ domain, zone, initial, onClose }: { domain: string; zone?: DnsZoneView; initial?: DnsKey; onClose: () => void }) {
  const choices = (zone?.items ?? []).filter((r) => ['A', 'AAAA', 'CNAME', 'TXT', 'MX'].includes(r.type));
  const [key, setKey] = useState<string>(initial ? keyOf(initial) : choices.find((r) => r.managed)?.name ? keyOf(choices.find((r) => r.managed)!) : choices[0] ? keyOf(choices[0]) : '');
  const [res, setRes] = useState<DnsPropagation>();
  const [error, setError] = useState<unknown>();
  useEffect(() => {
    if (!key) return;
    const [name, type] = key.split('|');
    setRes(undefined);
    setError(undefined);
    dnsPropagation(domain, name, type).then(setRes, setError);
  }, [domain, key]);
  return (
    <Drawer title={`반영 확인${key ? ` · ${fqdn(key.split('|')[0], domain)} ${key.split('|')[1]}` : ''}`} onClose={onClose}>
      <Field label="확인할 레코드">
        <select value={key} onChange={(e) => setKey(e.target.value)}>
          {choices.map((r) => (
            <option key={keyOf(r)} value={keyOf(r)}>
              {fqdn(r.name, domain)} · {r.type}
            </option>
          ))}
        </select>
      </Field>
      {error !== undefined ? (
        error instanceof ApiError && error.code === 'not-supported' ? (
          <div className="note un">이 공급자 연결은 반영 확인을 지원하지 않습니다. 공개 해석기에서 직접 확인하세요.</div>
        ) : (
          <ErrorBand error={error} what="반영 확인을 하지 못했습니다" />
        )
      ) : !res ? (
        <span className="small muted">해석기에 묻는 중…</span>
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>해석기</th>
                <th>보이는 값</th>
                <th>상태</th>
              </tr>
            </thead>
            <tbody>
              {res.resolvers.map((r) => (
                <tr key={r.server}>
                  <td>
                    {r.kind === 'authoritative' ? '권한' : '공개'} <span className="mono">{r.server}</span>
                  </td>
                  <td className="mono el">{r.error ? '—' : r.values.join(', ') || '(없음)'}</td>
                  <td>{r.error ? <Badge tone="er">묻지 못함</Badge> : r.fresh ? <Badge tone="ok">새 값</Badge> : <Badge tone="wa">예전 값{r.ttlLeft ? ` · ${Math.ceil(r.ttlLeft / 60)}분 남음` : ''}</Badge>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <span className="small muted">공급자의 반영 확인과 공개 해석기 직접 질의를 함께 씁니다. 예전 값은 TTL이 지나면 사라집니다.</span>
    </Drawer>
  );
}

// 설정 카드의 '연결된 서버' 한 줄: 연결된 서버 이름과 공개 주소를 줄여 보여 준다.
function LinkedServersText({ domain }: { domain: string }) {
  const sq = usePoll((signal) => dnsServers(domain, signal), [domain], 0);
  if (sq.error !== undefined) return <span className="muted">{ingressMissing(sq.error) ? '웹 기능 준비 중' : '읽지 못함'}</span>;
  if (!sq.data) return <span className="muted">읽는 중…</span>;
  const on = sq.data.items.filter((s) => s.linked);
  if (!on.length) return <span className="muted">없음</span>;
  const addrs = Array.from(new Set(on.flatMap((s) => s.addresses)));
  return <span>{on.map((s) => s.node).join(', ')} · {addrs.join(', ')}</span>;
}
