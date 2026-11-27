// SPDX-License-Identifier: Apache-2.0

// 서버 › VPS 관리 (UI-12B, 캔버스 v230 VpsNodes·VpsNodesIx). 계약: docs/reference/web-api/54-vps.md
// 판단은 모두 sfcd가 한다. 화면은 목록·리더의 10분 감시를 보여 주고, 변경은 opId를 붙인 작업으로 보낸다.
// 공급자 키는 입력칸 상태에만 잠깐 두고 보낸 뒤 지운다. 초안·주소·저장소 어디에도 남기지 않는다.
import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/client';
import { nodeActionPath, nodeCordonPath, nodeDrainPlan, nodeDrainStatus, nodesOverview } from '../api/endpoints';
import type { OpView } from '../api/types';
import {
  VPS,
  VPS_ERROR,
  VPS_PHASE,
  GUARD_DEFAULT,
  canResumeCapped,
  capStopReason,
  guardError,
  mbpsText,
  clearVpsDnsHold,
  countingText,
  vendorCounting,
  flavorText,
  flavorTrafficText,
  fromUnix,
  IWINV_TIERS,
  gbText,
  tierIndex,
  tierRange,
  mbText,
  periodText,
  trafficVerdict,
  vpsBusy,
  vpsDnsPlan,
  vpsOffer,
  vpsView,
  won,
  type VpsAccount,
  type VpsOverageTier,
  type VpsOffer,
  type VpsServer,
  type VpsServerStatus,
  type VpsView,
} from '../api/vps';
import { Badge, Card, Field, HelpBox, KV, PageHeader, Tile } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { Dialog } from '../components/Dialog';
import { Menu, type MenuItem } from '../components/Menu';
import { MutationError, OpPanel, sendOp, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { drainRunning } from '../lib/drain';
import { ago, dayTime, fmtTime, hhmm } from '../lib/format';
import { SERVER_TABS } from './Servers';

const POLL_MS = 30_000;
/** 단계 배지: 생성 1 · 설치 2 · 가입 3 · (투표 서버면) 승격 4 */
function vpsPhaseText(s: VpsServer): [tone: 'ok' | 'pr' | 'wa' | 'er' | 'un', text: string] {
  const total = s.voter ? 4 : 3;
  if (s.phase === 'creating') return ['pr', `생성 중 · 1/${total}`];
  if (s.phase === 'installing') return s.joining ? ['pr', `가입 중 · 3/${total}`] : ['pr', `설치 중 · 2/${total}`];
  return VPS_PHASE[s.phase] ?? ['un', s.phase];
}
const errCode = (e: unknown) => (e instanceof ApiError ? e.code : '');
const errMsg = (e: unknown) => (e instanceof ApiError ? VPS_ERROR[e.code] ?? e.message : String(e));
const accountLabel = (a?: VpsAccount) => (a ? a.name : '—');

/** 계정마다 공급자 목록(타입 이름·월 요금). 읽지 못하면 빈 것 */
function useOffers(accounts: VpsAccount[]) {
  const key = accounts.map((a) => a.name).join(',');
  const [offers, setOffers] = useState<Record<string, VpsOffer | { error: unknown }>>({});
  useEffect(() => {
    const ac = new AbortController();
    for (const a of accounts)
      vpsOffer(a.name, undefined, ac.signal).then(
        (o) => setOffers((x) => ({ ...x, [a.name]: o })),
        (e) => !ac.signal.aborted && setOffers((x) => ({ ...x, [a.name]: { error: e } })),
      );
    return () => ac.abort();
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps
  return offers;
}
const offerOf = (o: VpsOffer | { error: unknown } | undefined) => (o && 'flavors' in o ? o : undefined);

type Dlg =
  | { kind: 'new' }
  | { kind: 'stop' | 'cap' | 'delete' | 'resume'; s: VpsServer }
  | { kind: 'account' }
  | { kind: 'rotate' | 'price' | 'unlink'; a: VpsAccount };

export function VpsNodesPage() {
  const q = usePoll((s) => vpsView(s), [], POLL_MS);
  const nodes = usePoll((s) => nodesOverview(s), [], POLL_MS);
  const [dlg, setDlg] = useState<Dlg>();
  const members = new Set((nodes.data?.nodes ?? []).map((n) => n.id));
  const close = () => (setDlg(undefined), q.refresh());
  return (
    <>
      <PageHeader
        title="서버"
        ids="UI-12B"
        actions={
<Refresh q={q} />
        }
      />
      <Tabs label="서버 탭" items={SERVER_TABS} />
      <HelpBox terms="VPS 서버 (VPS node) · 공급자 (provider) · 존 (zone) · 타입 (VPS 사양) · 투표 서버 (voter) · 투표권 없음 (non-voter) · 상한 (월 요금 상한) · 상한으로 중지됨 (상한 초과 예상으로 자동 중지)">
        <b>이 화면은</b> VPS 공급자(iwinv)에서 빌린 서버를 만들고, 멈추고, 지우는 곳입니다. 새 VPS 서버는 만들어지면 저절로 Seafield를 설치하고 클러스터에 가입합니다. 서버마다 월 요금 상한을 두고, 10분마다 트래픽을 읽어 월말 요금이 상한을 넘을 것으로 보이면 그 서버를 중지합니다. 시스템 관리자만 봅니다.
      </HelpBox>
      <Load q={q} what="VPS 목록을 불러오지 못했습니다">{(v) => <Body v={v} members={members} onDlg={setDlg} onRefresh={q.refresh} />}</Load>
      {dlg?.kind === 'new' && q.data && <NewVpsDialog v={q.data} onClose={close} />}
      {dlg?.kind === 'stop' && q.data && <StopDialog v={q.data} s={dlg.s} member={members.has(dlg.s.name)} onClose={close} />}
      {dlg?.kind === 'resume' && q.data && <ResumeDialog v={q.data} s={dlg.s} member={members.has(dlg.s.name)} onClose={close} onCap={() => setDlg({ kind: 'cap', s: dlg.s })} />}
      {dlg?.kind === 'cap' && q.data && <CapDialog v={q.data} s={dlg.s} onClose={close} />}
      {dlg?.kind === 'delete' && q.data && <DeleteDialog v={q.data} s={dlg.s} member={members.has(dlg.s.name)} onClose={close} />}
      {dlg?.kind === 'account' && <AccountDialog onClose={close} />}
      {dlg?.kind === 'rotate' && q.data && <RotateDialog v={q.data} a={dlg.a} onClose={close} />}
      {dlg?.kind === 'price' && q.data && <PriceDialog v={q.data} a={dlg.a} onClose={close} />}
      {dlg?.kind === 'unlink' && q.data && <UnlinkDialog v={q.data} a={dlg.a} onClose={close} />}
    </>
  );
}

function Body({ v, members, onDlg, onRefresh }: { v: VpsView; members: Set<string>; onDlg: (d: Dlg) => void; onRefresh: () => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const offers = useOffers(v.accounts);
  const [phase, setPhase] = useState('');
  const stat = new Map((v.status?.servers ?? []).map((x) => [x.name, x]));
  const flavor = (s: VpsServer) => offerOf(offers[s.account])?.flavors.find((f) => f.id === s.flavor);
  const zoneName = (s: VpsServer) => offerOf(offers[s.account])?.zones.find((z) => z.id === s.zone)?.name;
  // 이번 달 지금까지: 실행 중은 감시 값, 상한으로 멈춘 서버는 멈출 때 값
  const soFar = (s: VpsServer) => stat.get(s.name)?.soFarKRW ?? s.capStop?.soFarKRW;
  const running = v.servers.filter((s) => stat.has(s.name));
  const capped = v.servers.filter((s) => s.phase === 'capped');
  const rows = v.servers.filter((s) => !phase || s.phase === phase);
  const keep = async (s: VpsServer, domain: string) => {
    try {
      await clearVpsDnsHold(s.name, domain);
      toast(`✓ ${s.name} · ${domain} 표시를 지웠습니다`);
      onRefresh();
    } catch (e) {
      toast(`! ${errMsg(e)}`, 'er');
    }
  };
  const menu = (s: VpsServer): MenuItem[] => {
    const busy = vpsBusy(s.phase);
    const off = s.phase === 'stopped' || s.phase === 'capped';
    const why = busy ? '생성·설치·켜기·끄기·삭제 중에는 상한 변경만 됩니다' : undefined;
    return [
      off ? { label: '재개', onSelect: () => onDlg({ kind: 'resume', s }) } : { label: '중지…', onSelect: () => onDlg({ kind: 'stop', s }), disabledReason: s.phase !== 'running' ? why ?? '실행 중인 서버만 끕니다' : undefined },
      { label: '상한 변경…', onSelect: () => onDlg({ kind: 'cap', s }) },
      { label: '서버 상세 보기', onSelect: () => navigate(`/servers/${encodeURIComponent(s.name)}`), disabledReason: members.has(s.name) ? undefined : '아직 클러스터에 가입하지 않았습니다' },
      { label: '삭제…', danger: true, onSelect: () => onDlg({ kind: 'delete', s }), disabledReason: s.phase === 'deleting' ? '이미 삭제 중입니다' : undefined },
    ];
  };
  return (
    <>
      {v.statusError && <div className="note wa small">리더의 요금·트래픽 감시를 읽지 못했습니다({v.statusError}). 목록만 보입니다.</div>}
      {!v.dnsAuto && <div className="note wa small">웹 자동 작업 계정이 VPS 목록을 읽지 못해, 중지할 때 DNS 레코드를 저절로 빼거나 되돌리지 않습니다. 자동 작업 계정을 시스템 관리자로 두고 자동화를 켜세요.</div>}
      <div className="grid tiles">
        <Tile label="이번 달 지금까지" value={won(v.servers.reduce((n, s) => n + (soFar(s) ?? 0), 0))} sub={`VPS 서버 ${v.servers.length}대`} />
        <Tile label="월말 예상" value={v.status ? won(running.reduce((n, s) => n + (stat.get(s.name)!.judgeable ? stat.get(s.name)!.projectedKRW : stat.get(s.name)!.soFarKRW), 0)) : '—'} sub={`실행 중 ${running.length}대의 지금 속도로 계산`} />
        <Tile label="상한 합계" value={won(v.servers.reduce((n, s) => n + s.capKRW, 0))} sub="서버별 상한의 합" />
        <Tile label="상한으로 중지" value={`${capped.length}대`} tone={capped.length ? 'er' : undefined} sub={capped.length ? `${capped[0].name}${capped[0].capStop ? ` · ${dayTime(fromUnix(capped[0].capStop.at))}` : ''}` : '없음'} />
      </div>
      <Card
        title="VPS 서버"
        actions={
          <>
            <select aria-label="상태" value={phase} onChange={(e) => setPhase(e.target.value)} style={{ height: 30 }}>
              <option value="">상태: 전체</option>
              {Object.entries(VPS_PHASE).map(([k, [, t]]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
            </select>
            <button className="btn primary sm" disabled={!v.accounts.length} title={v.accounts.length ? undefined : '먼저 공급자를 연결하세요'} onClick={() => onDlg({ kind: 'new' })}>
              ＋ 새 VPS 서버
            </button>
          </>
        }
      >
        {!v.servers.length ? (
          <span className="small muted">VPS 서버가 없습니다.{v.accounts.length ? ' ‘새 VPS 서버’로 만드세요.' : ' 먼저 아래에서 공급자를 연결하세요.'}</span>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="tbl" style={{ minWidth: 980 }}>
              <thead>
                <tr>
                  <th>이름</th>
                  <th>공급자 · 존</th>
                  <th>타입</th>
                  <th>공인 IP</th>
                  <th>상태</th>
                  <th>투표</th>
                  <th>이번 달 요금</th>
                  <th>트래픽</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((s) => {
                  const x = stat.get(s.name);
                  const f = flavor(s);
                  const [tone, text] = vpsPhaseText(s);
                  const holds = s.dnsHolds ?? [];
                  const blocked = holds.filter((h) => (h.blocked ?? []).length);
                  return (
                    <tr key={s.name}>
                      <td>
                        <b className="mono">{s.name}</b>
                        <span className="small muted" style={{ display: 'block' }}>
                          VPS 서버 · {s.voter ? '투표 서버로 추가' : s.createdAt ? `${dayTime(fromUnix(s.createdAt))} 생성` : ''}
                          {s.createdBy ? ` · ${s.createdBy}` : ''}
                        </span>
                      </td>
                      <td>
                        iwinv · {accountLabel(v.accounts.find((a) => a.name === s.account))}
                        <span className="small muted" style={{ display: 'block' }}>
                          {s.zone}
                          {zoneName(s) ? ` (${zoneName(s)})` : ''}
                        </span>
                      </td>
                      <td className="small">
                        {f ? flavorText(f) : <span className="mono">{s.flavor}</span>}
                        {f?.full && <span className="muted" style={{ display: 'block' }}>월 {won(f.full.krw)}</span>}
                      </td>
                      <td className="mono small">{s.publicIP ?? '—'}</td>
                      <td>
                        <Badge tone={tone} title={s.failure}>
                          {text}
                        </Badge>
                        {s.phase === 'failed' && s.failure && <span className="small er-text" style={{ display: 'block' }}>{s.failure}</span>}
                        {s.phase === 'capped' && s.capStop && <span className="small muted" style={{ display: 'block' }}>{dayTime(fromUnix(s.capStop.at))} 중지 · {capStopReason(s.capStop)}</span>}
                        {s.phase === 'stopping' && s.stopAfter && <span className="small muted" style={{ display: 'block' }}>DNS를 빼고 {fmtTime(fromUnix(s.stopAfter))}에 끔</span>}
                        {holds.length > 0 && (
                          <span className="small wa-text" style={{ display: 'block' }}>
                            {blocked.length ? `DNS 원복 못 함 ${blocked.length}` : `DNS에서 임시로 뺌 (도메인 ${holds.length}개)`}
                          </span>
                        )}
                        {blocked.map((h) => (
                          <span key={h.domain} className="small" style={{ display: 'block' }}>
                            {h.domain} ·{' '}
                            <Link to={`/system/domains/${encodeURIComponent(h.domain)}/records`}>확인</Link> ·{' '}
                            <button type="button" className="linkish small" onClick={() => void keep(s, h.domain)}>
                              이대로 둠
                            </button>
                          </span>
                        ))}
                      </td>
                      <td>{s.voter ? <Badge tone="pr">투표 서버</Badge> : <span className="small muted">투표권 없음</span>}</td>
                      <td className="small">
                        <CostCell s={s} x={x} />
                      </td>
                      <td className="small">
                        {x ? (
                          <>
                            <TrafficCell x={x} off={offPhase(s)} />
                            <span className="muted" style={{ display: 'block' }}>{offPhase(s) ? '중지됨' : `10분 ${mbText(x.recentMB)}`}</span>
                            {x.failure && <span className="wa-text" style={{ display: 'block' }}>읽기 실패 · {x.failure}{x.failureAt ? ` · ${ago(fromUnix(x.failureAt))}` : ''}</span>}
                          </>
                        ) : s.phase === 'stopped' || s.phase === 'capped' ? (
                          <span className="muted">중지됨</span>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td>
                        <Menu items={menu(s)} label={`${s.name} 메뉴`} button="⋯" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <span className="small muted">
          행 메뉴(⋯)에서 중지 · 재개 · 상한 변경 · 삭제를 합니다. 중지할 때는 먼저 이 서버로 가는 DNS 레코드(외부 도메인의 연결된 서버)를 임시로 뺍니다. 손으로 중지하면 새 배치 막기·비우기 뒤 끄고, 상한으로 중지하면 비우지 않고 기다린 뒤 끕니다. 한 시간치 표본이 모이기 전에는 예상으로 판정하지 않습니다. 끄면 합의 여유가 0이 되는 투표 서버는 끄지 않고 ‘끄지 못함’으로 보입니다. 중지한 서버도 디스크 요금은 나올 수 있습니다(공급자 정책).
        </span>
      </Card>
      <TrafficBoard v={v} />
      <GuardBoard v={v} />
      <CostBoard v={v} />
      <Card title="공급자 계정" actions={<button className="btn sm" onClick={() => onDlg({ kind: 'account' })}>＋ 공급자 연결</button>}>
        {!v.accounts.length ? (
          <span className="small muted">연결한 공급자가 없습니다.</span>
        ) : (
          <div className="table-x">
            <table className="tbl">
              <thead>
                <tr>
                  <th>이름</th>
                  <th>종류</th>
                  <th>상태</th>
                  <th>마지막 확인</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {v.accounts.map((a) => {
                  const o = offers[a.name];
                  const st = v.status?.accounts?.find((x) => x.name === a.name);
                  const bad = (o && 'error' in o) || !!st?.failure;
                  const n = v.servers.filter((s) => s.account === a.name).length;
                  return (
                    <tr key={a.name}>
                      <td>
                        <b>{a.name}</b>
                        <span className="small muted" style={{ display: 'block' }}>
                          VPS 서버 {n}대 · {a.overageTiers?.length ? `초과 GB당 ${won(a.overageTiers[0].krwPerGB)}부터 (구간 요금, 부가세 별도)` : `초과 GB당 ${won(a.overageKRWPerGB)}`} · 키 …{a.keyHint ?? '????'}
                        </span>
                        <span className="small muted" style={{ display: 'block' }}>
                          트래픽 {accountTrafficText(v, a, o && 'at' in o ? o : undefined)}
                        </span>
                      </td>
                      <td>{a.vendor}</td>
                      <td>{!o ? <span className="small muted">확인 중…</span> : bad ? <Badge tone="er">키 거부됨</Badge> : <Badge tone="ok">연결됨</Badge>}</td>
                      <td className="small">
                        {o && 'at' in o ? ago(fromUnix(o.at)) : st ? ago(fromUnix(st.updatedAt)) : '—'}
                        {bad && <span className="er-text" style={{ display: 'block' }}>{o && 'error' in o ? errMsg(o.error) : st?.failure} · 키 교체 필요</span>}
                      </td>
                      <td>
                        <Menu
                          label={`${a.name} 메뉴`}
                          button="⋯"
                          items={[
                            { label: '키 교체…', onSelect: () => onDlg({ kind: 'rotate', a }) },
                            { label: '단가 바꾸기…', onSelect: () => onDlg({ kind: 'price', a }) },
                            {
                              label: '지금 연결 확인',
                              onSelect: () =>
                                void vpsOffer(a.name).then(
                                  (x) => toast(`✓ ${a.name} 연결 정상 · 존 ${x.zones.length}개 · 타입 ${x.flavors.length}개 · 이미지 ${x.images.length}개`),
                                  (e) => toast(`! ${a.name} 연결 실패 · ${errMsg(e)}`, 'er'),
                                ),
                            },
                            { label: '연결 해제…', danger: true, onSelect: () => onDlg({ kind: 'unlink', a }) },
                          ]}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <span className="small muted">Secret Key는 저장 뒤 다시 보이지 않습니다(쓰기 전용). 키는 투표 서버가 봉인해 sfcd에 둡니다. 키가 거부된 계정의 VPS 서버는 요금 조회와 상한 중지를 할 수 없으니 바로 교체하세요.</span>
      </Card>
    </>
  );
}

/** ₩19,800 / 예상 ₩24,600 / 상한 ₩30,000 + 경고 */
function CostCell({ s, x }: { s: VpsServer; x?: VpsServerStatus }) {
  const soFar = x?.soFarKRW ?? s.capStop?.soFarKRW;
  const off = offPhase(s);
  const proj = !x ? '—' : x.judgeable ? won(x.projectedKRW) : off ? '—' : '판정 전';
  return (
    <>
      <span style={{ display: 'block', whiteSpace: 'nowrap' }}>
        {soFar === undefined ? '—' : (
          <>
            {won(soFar)} <span className="muted">지금까지</span>
          </>
        )}
      </span>
      <span className="muted" style={{ display: 'block', whiteSpace: 'nowrap' }}>
        예상 {proj} · 상한 {won(s.capKRW)}
      </span>
      {s.capAction === 'notify' && <span className="muted" style={{ display: 'block' }}>넘으면 알림만</span>}
      {x && !x.judgeable && !off && <span className="muted" style={{ display: 'block' }}>1시간 모으는 중 · 그동안은 지금까지 요금이 상한을 넘을 때만 판정</span>}
      {x?.capBlocked ? (
        <span style={{ display: 'block' }}>
          <Badge tone="er" title="월말 예상이 상한을 넘지만, 끄면 합의 여유가 0이 되어 끄지 않습니다. 상한을 올리거나 투표 서버를 하나 더 두세요.">
            상한 넘음 · 투표 서버라 끄지 못함
          </Badge>
        </span>
      ) : x?.over ? (
        <span style={{ display: 'block' }}>
          <Badge tone="wa">예상이 상한 넘음</Badge>
        </span>
      ) : null}
    </>
  );
}

/** 목록의 트래픽 칸 (캔버스 v249): 일간이면 오늘 / 하루 제공량, 달 / 쌓인 제공량. 월간이면 달 / 월 제공량 */
function TrafficCell({ x, off }: { x: VpsServerStatus; off?: boolean }) {
  const day = x.includedPeriod === 'DAY';
  const month = x.includedMonthGB ?? (x.includedPeriod === 'MONTH' ? x.includedGB : undefined);
  const over = (used: number, inc: number | undefined) => (inc !== undefined && used > inc ? 'er-text' : undefined);
  return (
    <>
      {day && (
        <span style={{ display: 'block' }} className={over((x.todayMB ?? 0) / 1024, x.includedGB)}>
          오늘 {x.todayMB === undefined || off ? '—' : mbText(x.todayMB)} / {gbText(x.includedGB)}
        </span>
      )}
      <span style={{ display: 'block' }} className={over(x.usedGB, month)}>
        달 {gbText(x.usedGB)} / {month === undefined ? '제공량 모름' : gbText(month)}
      </span>
      {!day && x.includedPeriod === 'MONTH' && x.todayMB !== undefined && <span className="muted" style={{ display: 'block' }}>하루 한도 없음 · 오늘 {mbText(x.todayMB)}</span>}
    </>
  );
}

/** 트래픽 현황판 (캔버스 v240·v249): 서버별 판정 기준, 지난 7일 막대(점선 = 일 제공량), 이번 달 / 제공량, 판정 */
function TrafficBoard({ v }: { v: VpsView }) {
  const rows = (v.status?.servers ?? []).map((x) => ({ x, s: v.servers.find((s) => s.name === x.name) }));
  const stamp = Math.max(0, ...rows.map((r) => r.x.updatedAt));
  const perGB = (s?: VpsServer) => {
    const a = v.accounts.find((x) => x.name === s?.account);
    return a?.overageTiers?.length ? a.overageTiers[0].krwPerGB : a?.overageKRWPerGB;
  };
  return (
    <Card title="트래픽 현황판" actions={<span className="small muted">10분마다 갱신{stamp ? ` · ${fmtTime(fromUnix(stamp))} 기준` : ''} · 판정 기준은 공급자마다 다름</span>}>
      {!rows.length ? (
        <span className="small muted">{v.status ? '실행 중인 VPS 서버가 없습니다.' : '리더의 트래픽 감시를 읽지 못했습니다.'}</span>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl" style={{ minWidth: 820 }}>
            <thead>
              <tr>
                <th>서버 · 판정 기준</th>
                <th>지난 7일 (점선 = 일 제공량)</th>
                <th>이번 달 / 제공량</th>
                <th>판정</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ x, s }) => {
                const month = x.includedMonthGB ?? (x.includedPeriod === 'MONTH' ? x.includedGB : undefined);
                const verdict = s && offPhase(s) ? offVerdict(x, s, month) : trafficVerdict(x, perGB(s));
                return (
                  <tr key={x.name}>
                    <td>
                      <b>{x.name}</b>
                      <span className="small muted" style={{ display: 'block' }}>
                        {s ? `${vendorOf(v, s)} · ` : ''}
                        {periodText(x.includedGB, x.includedPeriod)} · {countingText(x.trafficCounting ?? (s ? vendorCounting(vendorOf(v, s)) : undefined))}
                      </span>
                    </td>
                    <td>
                      <DailyBars x={x} />
                    </td>
                    <td className="small">
                      {gbText(x.usedGB)} / {month === undefined ? '제공량 모름' : gbText(month)}
                      {x.includedPeriod === 'DAY' && x.includedGB ? (
                        <span className="muted" style={{ display: 'block' }}>
                          {month !== undefined ? `(${s?.createdAt && sameMonth(s.createdAt) ? `${new Date(s.createdAt * 1000).getMonth() + 1}월 ${new Date(s.createdAt * 1000).getDate()}일부터 ` : ''}${Math.round(month / x.includedGB)}일)` : ''}
                          {x.includedMaxGB && month !== undefined && month >= x.includedMaxGB ? ` · 월 최대 ${gbText(x.includedMaxGB)}` : ''}
                        </span>
                      ) : null}
                    </td>
                    <td className={`small${verdict.tone ? ` ${verdict.tone}-text` : ''}`}>{verdict.text}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <span className="small muted">
        꺼진 서버도 이번 달 요금이 드는 동안은 사용량을 보이지만 판정하지 않습니다. 일간 판정(iwinv): 제공량 = 이번 달 서비스 일수(이달 1일 또는 만든 날부터 오늘까지) × 하루 제공량, 월 최대까지. 월 최대는 iwinv API에 없어 일 한도 × 30으로 둡니다. 하루 제공량을 넘겨도 그날 바로 요금이 붙지 않고, 이번 달 누적이 제공량을 넘은 만큼 GB당 단가로 붙습니다. 월간 판정 공급자는 월 제공량 하나로 보고 점선을 긋지 않습니다. 월말 예상은 최근 1시간 속도로 계산합니다.
      </span>
    </Card>
  );
}

const offPhase = (s: VpsServer) => s.phase === 'stopping' || s.phase === 'stopped' || s.phase === 'capped';
/** 꺼진 서버의 현황판 판정: 넘은 양과 중지 사유만 */
function offVerdict(x: VpsServerStatus, s: VpsServer, month?: number): { tone?: 'wa' | 'er'; text: string } {
  const over = month !== undefined && x.usedGB > month ? `${gbText(x.usedGB - month)} 넘음 · ` : '';
  if (s.phase === 'capped') return { tone: 'er', text: `${over}상한으로 중지${s.capStop?.reason === 'traffic-soon' ? ' (15분 전 감시)' : ''}` };
  return { text: `${over}중지됨` };
}
const hm = (unix: number) => hhmm(new Date(unix * 1000));
/** 0.1 GB 단위까지 */
const gb1 = (n: number | undefined) => (n === undefined ? '—' : n < 10 ? `${Math.round(n * 10) / 10} GB` : gbText(n));

/** 트래픽 조기 감시 (캔버스 v253, #701): 1분마다 최근 창 속도로 앞으로 21분(15분 전 + 끄는 데 6분)을 내다본다 */
function GuardBoard({ v }: { v: VpsView }) {
  const rows = v.servers.map((s) => ({ s, x: v.status?.servers?.find((x) => x.name === s.name) })).filter((r) => r.x);
  if (!rows.length) return null;
  const at = Math.max(0, ...rows.map((r) => r.x?.guard?.at ?? 0));
  const acct = (s: VpsServer) => v.accounts.find((a) => a.name === s.account)?.guard;
  // 열 이름은 계정 설정을 따른다(계정마다 다르면 기본 이름)
  const ws = [...new Set(rows.map((r) => acct(r.s)?.windowMin || GUARD_DEFAULT.windowMin))];
  const as = [...new Set(rows.map((r) => acct(r.s)?.averageMin || GUARD_DEFAULT.averageMin))];
  const win = ws.length === 1 ? `${ws[0]}분` : '창';
  const avg = as.length === 1 ? `${as[0]}분` : '누적';
  return (
    <Card title="트래픽 조기 감시" actions={<span className="small muted">1분마다 판정{at ? ` · ${hm(at)} 기준` : ''} · 앞으로 21분(15분 전 + 끄는 데 6분)</span>}>
      <div style={{ overflowX: 'auto' }}>
        <table className="tbl" style={{ minWidth: 900 }}>
          <thead>
            <tr>
              <th>서버</th>
              <th>지금 속도 ({win})</th>
              <th>{avg} 평균</th>
              <th>앞으로 21분 예상</th>
              <th>지난 달 같은 시각 패턴</th>
              <th>상한까지 남은 양</th>
              <th>판정</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ s, x }) => {
              const g = x!.guard;
              return (
                <tr key={s.name}>
                  <td>
                    <b>{s.name}</b>
                  </td>
                  {!g ? (
                    <td colSpan={6} className="small muted">
                      {offPhase(s) ? (s.phase === 'capped' ? `감시 안 함 · ${capStopReason(s.capStop)}로 중지` : '감시 안 함 · 중지됨') : '측정 창 하나가 모이면 판정합니다'}
                    </td>
                  ) : (
                    <>
                      <td className="small">
                        {mbpsText(g.rateMbps)}
                        {g.prevMbps !== undefined && <span className="muted" style={{ display: 'block' }}>앞 {win} {mbpsText(g.prevMbps)}</span>}
                      </td>
                      <td className="small">{mbpsText(g.averageMbps)}</td>
                      <td className="small">{gb1(g.forecastGB)}</td>
                      <td className="small">
                        {g.patternUsed ? (
                          <>
                            {gb1(g.patternGB)}
                            <span className="muted" style={{ display: 'block' }}>패턴 · 기록 {g.patternDays ?? 0}일</span>
                          </>
                        ) : (
                          <span className="muted">— / 패턴 미사용 (기록 {g.patternDays ?? 0}일)</span>
                        )}
                      </td>
                      <td className="small">{g.unlimited ? '제한 없음' : gb1(g.remainingGB)}</td>
                      <td className="small">
                        {g.soon ? (
                          <>
                            <Badge tone="wa">곧 넘음</Badge>
                            {g.soonAt ? <span className="wa-text" style={{ display: 'block' }}>{hm(g.soonAt)}쯤 닿음 → 상한 동작({s.capAction === 'notify' ? '알림' : '끄기'}) 시작</span> : null}
                          </>
                        ) : (
                          <Badge tone="ok">여유</Badge>
                        )}
                      </td>
                    </>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <span className="small muted">
        1분마다 서버가 잰 송신량으로 앞으로 21분을 예측합니다. 지난 달 같은 시각대 기록이 7일 이상이면 패턴 예측도 씁니다. 21분 안에 상한에 닿으면 상한 동작을 시작합니다(끄는 데 약 6분). 창·평균 기간·패턴은 공급자 계정 설정에서 바꿉니다.
      </span>
    </Card>
  );
}

/** 트래픽 초과 요금 타일 설명: 'GB당 ₩10 · 쌓인 제공량(하루 20 GB씩, 월 최대 600 GB)을 넘은 만큼' */
function trafficSub(v: VpsView): string {
  const tiers = v.accounts.find((a) => a.overageTiers?.length)?.overageTiers;
  if (tiers) {
    const over = (v.status?.servers ?? []).reduce((n, x) => n + Math.max(0, x.usedGB - (x.includedMonthGB ?? Infinity)), 0);
    const i = tierIndex(tiers, over);
    return `${gbText(over)} × ${won(tiers[i].krwPerGB)} (${tierRange(tiers, i)} 구간, 부가세 별도)`;
  }
  const prices = [...new Set(v.accounts.map((a) => a.overageKRWPerGB))];
  const price = prices.length === 1 ? `GB당 ${won(prices[0])}` : '계정의 GB당 단가';
  const day = (v.status?.servers ?? []).find((x) => x.includedPeriod === 'DAY' && x.includedGB);
  return day ? `${price} · 쌓인 제공량(하루 ${gbText(day.includedGB)}씩${day.includedMaxGB ? `, 월 최대 ${gbText(day.includedMaxGB)}` : ''})을 넘은 만큼` : `${price} · 제공량을 넘은 만큼`;
}

const sameMonth = (unix: number, now = new Date()) => {
  const d = new Date(unix * 1000);
  return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth();
};
const vendorOf = (v: VpsView, s: VpsServer) => v.accounts.find((a) => a.name === s.account)?.vendor ?? s.account;

/** 지난 7일 일별 막대. 일간 판정이면 하루 제공량에 점선 */
function DailyBars({ x }: { x: VpsServerStatus }) {
  const days = x.daily ?? [];
  if (!days.length) return <span className="small muted">아직 없음</span>;
  const line = x.includedPeriod === 'DAY' ? x.includedGB : undefined;
  const top = Math.max(1, ...days.map((d) => d.mb / 1024), line ?? 0) * 1.1;
  const H = 36;
  const W = 14;
  const gap = 4;
  const w = days.length * (W + gap) - gap;
  return (
    <svg width={w} height={H} role="img" aria-label={`지난 ${days.length}일 사용량: ${days.map((d) => `${d.day.slice(5)} ${mbText(d.mb)}`).join(', ')}`}>
      {days.map((d, i) => {
        const h = Math.max(1, ((d.mb / 1024) / top) * H);
        const over = line !== undefined && d.mb / 1024 > line;
        return (
          <rect key={d.day} x={i * (W + gap)} y={H - h} width={W} height={h} rx={2} fill={over ? 'var(--wa-strong)' : 'var(--accent)'}>
            <title>{`${d.day} · ${mbText(d.mb)}`}</title>
          </rect>
        );
      })}
      {line !== undefined && <line x1={0} x2={w} y1={H - (line / top) * H} y2={H - (line / top) * H} stroke="currentColor" strokeDasharray="3 3" opacity={0.6} />}
    </svg>
  );
}

/** 요금 현황판: 서버별 막대(지금까지 · 월말 예상, 막대 끝 = 상한), 공급자 청구, 상한 중지 기록 */
function CostBoard({ v }: { v: VpsView }) {
  const stat = new Map((v.status?.servers ?? []).map((x) => [x.name, x]));
  const stamp = v.status?.servers?.[0]?.updatedAt;
  const stops = v.servers.filter((s) => s.capStop).sort((a, b) => b.capStop!.at - a.capStop!.at);
  const bills = v.status?.accounts ?? [];
  const totalBase = (v.status?.servers ?? []).reduce((n, x) => n + x.baseSoFarKRW, 0);
  const totalTraffic = (v.status?.servers ?? []).reduce((n, x) => n + x.trafficSoFarKRW, 0);
  return (
    <Card title="요금 현황판" actions={<span className="small muted">10분마다 갱신{stamp ? ` · ${fmtTime(fromUnix(stamp))} 기준` : ''}</span>}>
      {!v.status ? (
        <span className="small muted">리더의 요금 감시를 읽지 못했습니다{v.statusError ? ` (${v.statusError})` : ''}.</span>
      ) : (
        <>
          <span className="small muted">지금까지 · 월말 예상 · 막대 끝 = 서버별 상한</span>
          <div className="col" style={{ gap: 8 }}>
            {v.servers.map((s) => {
              const x = stat.get(s.name);
              const soFar = x?.soFarKRW ?? s.capStop?.soFarKRW ?? 0;
              const proj = x ? (x.judgeable ? x.projectedKRW : undefined) : undefined;
              const w = (n: number) => `${Math.min(100, (n / Math.max(1, s.capKRW)) * 100)}%`;
              return (
                <div key={s.name} className="vps-bar">
                  <span className="mono small">{s.name}</span>
                  <span className="bar" role="meter" aria-label={`${s.name} 이번 달 요금`} aria-valuenow={soFar} aria-valuemax={s.capKRW} style={{ position: 'relative' }}>
                    {proj !== undefined && <i className={proj > s.capKRW ? 'crit' : 'hi'} style={{ width: w(proj), position: 'absolute', opacity: 0.35 }} />}
                    <i className={soFar >= s.capKRW ? 'crit' : ''} style={{ width: w(soFar), position: 'relative' }} />
                  </span>
                  <span className="small">
                    {won(soFar)} / {x ? (x.judgeable ? won(x.projectedKRW) : '판정 전') : s.phase === 'capped' || s.phase === 'stopped' ? '중지' : '—'} / 상한 {won(s.capKRW)}
                    {x?.capBlocked && <span className="er-text"> · 상한 넘음 · 끄지 못함 (투표 서버)</span>}
                  </span>
                </div>
              );
            })}
          </div>
          <div className="grid tiles sm">
            {bills.map((b) => (
              <Tile
                key={b.name}
                label={`${b.name} · 공급자 실시간 요금`}
                value={b.failure ? '—' : won(b.billKRW)}
                sub={b.failure ? `읽기 실패 · ${b.failure}` : `우리 계산과 차이 ${won(Math.abs(b.oursKRW - b.billKRW))} · ${fmtTime(fromUnix(b.updatedAt))} 조회`}
              />
            ))}
            <Tile label="기본 요금 (월 정액, 일할)" value={won(totalBase)} sub="실행 중 서버 합 · 공인 IP 1개씩 포함" />
            <Tile label="트래픽 초과 요금" value={won(totalTraffic)} sub={trafficSub(v)} />
          </div>
          <b className="small">상한으로 중지한 기록</b>
          {!stops.length ? (
            <span className="small muted">없음</span>
          ) : (
            <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
              {stops.map((s) => (
                <li key={s.name}>
                  {dayTime(fromUnix(s.capStop!.at))} <b className="mono">{s.name}</b> 중지 · {s.capStop!.reason === 'traffic-soon' ? `${capStopReason(s.capStop)} · ` : ''}월말 {won(s.capStop!.projectedKRW)} 예상 &gt; 상한 {won(s.capStop!.capKRW)}
                  {(s.dnsHolds ?? []).length > 0 && ` · DNS 레코드 ${(s.dnsHolds ?? []).reduce((n, h) => n + (h.sets ?? []).length, 0)}개 임시로 뺌 (${(s.dnsHolds ?? []).map((h) => h.domain).join(', ')})`} ·{' '}
                  <Link to={`/system/ops?target=${encodeURIComponent(s.name)}`}>작업 기록</Link>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Card>
  );
}

// ── 다이얼로그 ─────────────────────────────────────────

function Footer({ m, label, ok, onSend, onClose, danger }: { m: ReturnType<typeof useMutation>; label: string; ok: boolean; onSend: () => void; onClose: () => void; danger?: boolean }) {
  const done = m.op?.state === 'applied';
  return done ? (
    <button className="btn primary" onClick={onClose}>
      닫기
    </button>
  ) : (
    <>
      <button className="btn" onClick={onClose}>
        취소
      </button>
      <button className={danger ? 'btn danger solid' : 'btn primary'} disabled={!ok || m.busy || (!!m.op && !['unknown', 'failed', 'rejected'].includes(m.op.state))} onClick={onSend}>
        {m.busy ? '보내는 중…' : label}
      </button>
    </>
  );
}
function OpErrors({ m }: { m: ReturnType<typeof useMutation> }) {
  const code = errCode(m.error);
  return (
    <>
      {VPS_ERROR[code] ? <div className="note er small">{VPS_ERROR[code]}</div> : <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => m.setOp(o)} />}
    </>
  );
}

function CapAction({ value, onChange, disabled }: { value: 'stop' | 'notify'; onChange: (v: 'stop' | 'notify') => void; disabled?: boolean }) {
  return (
    <fieldset className="col" style={{ gap: 6, border: 0, padding: 0, margin: 0 }} disabled={disabled}>
      <legend className="small" style={{ padding: 0, marginBottom: 4 }}>
        상한을 넘으면
      </legend>
      <label className="check">
        <input type="radio" checked={value === 'stop'} onChange={() => onChange('stop')} /> 끄기 (기본)
      </label>
      <span className="small muted" style={{ marginLeft: 24 }}>
        DNS에서 임시로 빼고 기다린 뒤 공급자에서 끕니다. 비우지 않습니다.
      </span>
      <label className="check">
        <input type="radio" checked={value === 'notify'} onChange={() => onChange('notify')} /> 알림만
      </label>
      <span className="small muted" style={{ marginLeft: 24 }}>
        끄지 않고 목록·현황판에 ‘예상이 상한 넘음’ 경고만 보입니다.
      </span>
    </fieldset>
  );
}

const capOk = (n: number) => Number.isInteger(n) && n > 0 && n <= 100_000_000;

function NewVpsDialog({ v, onClose }: { v: VpsView; onClose: () => void }) {
  const m = useMutation();
  const [account, setAccount] = useState(v.accounts[0]?.name ?? '');
  const [zone, setZone] = useState('');
  const offer = usePoll((s) => (account ? vpsOffer(account, zone || undefined, s) : Promise.resolve(undefined)), [account, zone]);
  const o = offer.data;
  const [image, setImage] = useState('');
  const [flavor, setFlavor] = useState('');
  const [name, setName] = useState('');
  const [cap, setCap] = useState('30000');
  const [act, setAct] = useState<'stop' | 'notify'>('stop');
  const [voter, setVoter] = useState(false);
  const zones = (o?.zones ?? []).filter((z) => z.usable);
  const images = (o?.images ?? []).filter((i) => i.linux && (!zone || !i.zones || i.zones.includes(zone)));
  const script = o?.scripts?.[0]?.id;
  useEffect(() => {
    if (o && !zone && zones[0]) setZone(zones[0].id);
    if (o && !images.some((i) => i.id === image) && images[0]) setImage(images[0].id);
  }, [o, zone]); // eslint-disable-line react-hooks/exhaustive-deps
  const f = o?.flavors.find((x) => x.id === flavor);
  const capN = Number(cap.replace(/,/g, ''));
  const nameOk = /^[a-z0-9][a-z0-9-]{0,62}$/.test(name) && !v.servers.some((s) => s.name === name);
  const voters = v.servers.filter((s) => s.voter).length;
  const ok = !!account && !!zone && !!image && !!flavor && nameOk && capOk(capN);
  // 이번 달 남은 날 일할
  const now = new Date();
  const days = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
  const left = days - now.getDate() + 1;
  const send = () => sendOp(m, VPS.servers, { name, account, zone, image, flavor, ...(script ? { script } : {}), capKRW: capN, capAction: act, voter, expected: v.revision });
  return (
    <Dialog title="새 VPS 서버" width={720} onClose={onClose} footer={<Footer m={m} label="만들기 · 요금 시작" ok={ok} onSend={() => void send()} onClose={onClose} />}>
      <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
        <Field label="공급자 계정">
          <select value={account} onChange={(e) => (setAccount(e.target.value), setZone(''), setFlavor(''))} disabled={!!m.op}>
            {v.accounts.map((a) => (
              <option key={a.name} value={a.name}>
                {a.name} · {a.vendor}
              </option>
            ))}
          </select>
        </Field>
        <Field label="존">
          <select value={zone} onChange={(e) => setZone(e.target.value)} disabled={!!m.op || !o}>
            {zones.map((z) => (
              <option key={z.id} value={z.id}>
                {z.id} ({z.name})
              </option>
            ))}
          </select>
        </Field>
        <Field label="이미지 (리눅스)" hint="Seafield Cluster 설치를 지원하는 이미지만 보입니다">
          <select value={image} onChange={(e) => setImage(e.target.value)} disabled={!!m.op || !o}>
            {images.map((i) => (
              <option key={i.id} value={i.id}>
                {i.name}
              </option>
            ))}
          </select>
        </Field>
      </div>
      {offer.error ? <ErrorBand error={offer.error} what="공급자 목록을 읽지 못했습니다" onRetry={offer.refresh} /> : !o && <span className="small muted">공급자 목록을 읽는 중…</span>}
      <Field label="이름" hint="서버 이름으로도 씁니다" error={name && !nameOk ? '소문자·숫자·- 만, 다른 서버와 겹치지 않게' : undefined}>
        <input className="mono" value={name} placeholder="vps-seoul-4" onChange={(e) => setName(e.target.value.trim())} disabled={!!m.op} autoComplete="off" />
      </Field>
      {o && (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th />
                <th>타입</th>
                <th>vCPU</th>
                <th>메모리</th>
                <th>디스크</th>
                <th>트래픽 제공량</th>
                <th>월 요금</th>
              </tr>
            </thead>
            <tbody>
              {o.flavors.map((x) => (
                <tr key={x.id} onClick={() => !m.op && setFlavor(x.id)} style={{ cursor: 'pointer' }}>
                  <td>
                    <input type="radio" name="flavor" aria-label={x.name} checked={flavor === x.id} onChange={() => setFlavor(x.id)} disabled={!!m.op} />
                  </td>
                  <td className="mono">{x.name}</td>
                  <td>{x.vcpu}</td>
                  <td>{x.memoryMiB >= 1024 ? `${Math.round(x.memoryMiB / 102.4) / 10} GB` : `${x.memoryMiB} MB`}</td>
                  <td>{x.diskGB} GB</td>
                  <td className="small">{flavorTrafficText(x.traffic, vendorCounting(v.accounts.find((a) => a.name === account)?.vendor))}</td>
                  <td>{x.full ? won(x.full.krw) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <span className="small muted">트래픽 제공량은 타입 목록에 없으면 공급자 기본값을 “추정”으로 보이고, 만든 뒤 서버가 알려 준 값으로 바뀝니다. 하루치가 쌓여 이번 달 제공량이 되고(만든 날부터, 월 최대까지), 이번 달 사용량이 그보다 많은 만큼만 계정의 GB당 단가로 계산합니다.</span>
      <Field label="월 요금 상한 (원)" hint="한 시간치 표본이 모인 뒤 월말 예상이 이 값을 넘으면 아래처럼 합니다" error={cap && !capOk(capN) ? '1 이상의 정수' : undefined}>
        <input inputMode="numeric" value={cap} onChange={(e) => setCap(e.target.value)} disabled={!!m.op} style={{ width: 160 }} />
      </Field>
      <CapAction value={act} onChange={setAct} disabled={!!m.op} />
      <label className="check">
        <input type="checkbox" checked={voter} onChange={(e) => setVoter(e.target.checked)} disabled={!!m.op || !script} /> 투표 서버로 추가
      </label>
      <span className="small muted" style={{ marginLeft: 24 }}>
        {!script
          ? '공급자에 설치 스크립트가 없어 리더가 SSH로 설치합니다. 이렇게 만든 서버는 투표 서버가 될 수 없습니다.'
          : voter
            ? `투표 서버가 ${voters}대 → ${voters + 1}대(VPS 기준)가 됩니다. VPS 서버는 상한으로 중지될 수 있어, 중지되면 합의 여유가 줄어듭니다. 홀수를 권합니다.`
            : '기본은 꺼짐 · 투표권 없이 가입합니다'}
      </span>
      <div className="note small">
        예상 월 요금 기본 {f?.full ? `${won(f.full.krw)}, 공인 IP 1개 포함` : '—'}
        {f?.full ? ` (이번 달은 남은 ${left}일 일할 ${won((f.full.krw * left) / days)})` : ''} · 트래픽 초과는 쓴 만큼 · 상한 {capOk(capN) ? won(capN) : '—'}
      </div>
      <div className="note wa small">만들기를 누르면 바로 요금이 나오기 시작합니다. 창을 닫아도 계속되고, 목록의 상태 칸이 생성 → 설치 → 실행 중을 보입니다.</div>
      <OpErrors m={m} />
    </Dialog>
  );
}

const OUTCOME: Record<string, [string, string]> = { withdraw: ['wa', '임시로 뺌'], 'keep-last': ['er', '남김 · 이 서버가 마지막'], manual: ['un', '직접 고치기 · 공급자를 읽지 못함'] };

/** 중지: 새 배치 막기 → 비우기(끝날 때까지) → DNS 빼기·TTL 기다림·끄기(sfcd) */
function StopDialog({ v, s, member, onClose }: { v: VpsView; s: VpsServer; member: boolean; onClose: () => void }) {
  const plan = usePoll((sig) => vpsDnsPlan(s.name, sig), [s.name]);
  const drain = usePoll((sig) => (member ? nodeDrainPlan(s.name, sig) : Promise.resolve(undefined)), [s.name, member]);
  const m = useMutation();
  const [step, setStep] = useState<'' | 'cordon' | 'drain' | 'stop' | 'done'>('');
  const [stepErr, setStepErr] = useState<string>();
  const p = plan.data;
  const d = drain.data;
  const runningVoters = v.servers.filter((x) => x.voter && x.phase === 'running').length;
  const rows = p?.rows ?? [];
  const lastOnes = rows.filter((r) => r.outcome === 'keep-last');
  const go = async () => {
    setStepErr(undefined);
    try {
      if (member) {
        setStep('cordon');
        await import('../api/client').then(({ api, newOpId }) =>
          api.post(nodeCordonPath(s.name, true), { opId: newOpId(), reason: 'VPS 중지' }).catch((e) => {
            if (!(e instanceof ApiError && e.code === 'unchanged')) throw e;
          }),
        );
        setStep('drain');
        const fresh = await nodeDrainPlan(s.name);
        if (fresh.tasks.length) {
          if (fresh.code || fresh.tasks.some((t) => !t.movable)) throw new Error('옮기지 못하는 컨테이너가 있습니다. 서버 상세에서 먼저 비우세요.');
          const { api, newOpId } = await import('../api/client');
          await api.post(nodeActionPath(s.name, 'drain'), { opId: newOpId(), plan: fresh.plan, operation: fresh.operation });
          for (;;) {
            await new Promise((r) => setTimeout(r, 2000));
            const stt = await nodeDrainStatus(s.name, fresh.operation);
            if (!drainRunning(stt.state)) {
              if (stt.blocked > 0 || /fail|partial/i.test(stt.state)) throw new Error(`비우기가 끝나지 않았습니다(${stt.moved}/${stt.total}). 서버 상세에서 확인하세요.`);
              break;
            }
          }
        }
      }
      setStep('stop');
      const op = await sendOp(m, VPS.stop(s.name), { dnsWaitSeconds: p?.waitSeconds ?? 300 });
      setStep(op?.state === 'applied' ? 'done' : 'stop');
    } catch (e) {
      setStepErr(e instanceof ApiError ? errMsg(e) : String((e as Error).message ?? e));
    }
  };
  const order: [string, string][] = [
    ['cordon', '새 배치 막기'],
    ['drain', `컨테이너 옮기기(비우기)${d ? ` · ${d.tasks.length}개` : ''}`],
    ['stop', `DNS 레코드 임시로 빼기 → ${p?.waitSeconds ?? 300}초 기다림 → iwinv에서 끄기`],
  ];
  const at = ['cordon', 'drain', 'stop', 'done'].indexOf(step);
  return (
    <Dialog
      title={`${s.name} 중지`}
      width={720}
      onClose={onClose}
      footer={<Footer m={m} label="중지" ok={!!p && !step} onSend={() => void go()} onClose={onClose} />}
    >
      <p style={{ margin: 0 }}>
        {member ? `컨테이너${d ? ` ${d.tasks.length}개` : ''}를 다른 서버로 옮긴 뒤(비우기) ` : ''}iwinv에서 서버를 끕니다. 클러스터 구성원으로는 남아 ‘중지됨’으로 보이고, 재개하면 다시 가입합니다.
      </p>
      {s.voter && runningVoters <= 1 && <div className="note er small">투표 서버를 끄면 합의 여유가 줄어듭니다. 여유가 0이 되면 sfcd가 거절합니다. 먼저 투표권 없음으로 바꾸세요.</div>}
      <b className="small">연동된 도메인 · DNS 레코드</b>
      {plan.error ? (
        <ErrorBand error={plan.error} what="DNS 계획을 읽지 못했습니다" onRetry={plan.refresh} />
      ) : !p ? (
        <span className="small muted">읽는 중…</span>
      ) : !rows.length ? (
        <span className="small muted">이 서버가 ‘연결된 서버’인 외부 도메인이 없습니다.</span>
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>이름</th>
                <th>종류</th>
                <th>값</th>
                <th>중지하면</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>
                  <td className="mono small">{r.name ? `${r.name === '@' ? '' : `${r.name}.`}${r.domain}` : r.domain}</td>
                  <td>{r.type || '—'}</td>
                  <td className="mono small">{r.value}</td>
                  <td className="small">
                    <Badge tone={OUTCOME[r.outcome]?.[0] as 'wa'}>{OUTCOME[r.outcome]?.[1] ?? r.outcome}</Badge>
                    {r.outcome === 'withdraw' && <span className="muted"> · 다른 주소 {r.others}개 남음</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {p && !p.dnsAuto && <div className="note wa small">웹 자동 작업 계정이 VPS 목록을 읽지 못해 DNS를 저절로 빼지 않습니다. 레코드는 직접 고치세요.</div>}
      <span className="small muted">중지 동안만 빼는 임시 변경입니다. 도메인의 ‘연결된 서버’ 설정은 그대로 두고, 재개해 서버가 다시 ‘실행 중’이 되면 같은 레코드를 저절로 되돌립니다.</span>
      {lastOnes.length > 0 && <div className="note wa small">{[...new Set(lastOnes.map((r) => r.domain))].join(', ')}은(는) 이 서버만 받고 있어 레코드를 남깁니다. 중지하면 그 이름은 접속되지 않습니다. 먼저 다른 서버를 그 도메인에 연결하세요.</div>}
      <ol className="steps-v small" aria-label="순서">
        {order
          .filter(([k]) => member || k === 'stop')
          .map(([k, t]) => {
            const i = ['cordon', 'drain', 'stop'].indexOf(k);
            const cls = step && at > i ? 'done' : at === i ? 'now' : 'wait';
            return (
              <li key={k} className={cls}>
                <span>{t}</span>
              </li>
            );
          })}
      </ol>
      {!member && <span className="small muted">아직 클러스터에 가입하지 않은 서버라 비우기 없이 끕니다.</span>}
      <span className="small muted">중지해도 디스크·공인 IP 요금은 공급자 정책에 따라 계속 나올 수 있습니다.</span>
      {stepErr && <div className="note er small">{stepErr}</div>}
      <OpErrors m={m} />
    </Dialog>
  );
}

/** 재개: 켜기 → (가입한 서버면) 새 배치 다시 받기 */
function ResumeDialog({ v, s, member, onClose, onCap }: { v: VpsView; s: VpsServer; member: boolean; onClose: () => void; onCap: () => void }) {
  const m = useMutation();
  const [uncordon, setUncordon] = useState<string>();
  const can = canResumeCapped(s);
  const holds = (s.dnsHolds ?? []).reduce((n, h) => n + (h.sets ?? []).length, 0);
  const go = async () => {
    const op = await sendOp(m, VPS.start(s.name), { expected: v.revision });
    if (op?.state === 'applied' && member) {
      const { api, newOpId } = await import('../api/client');
      try {
        await api.post(nodeCordonPath(s.name, false), { opId: newOpId() });
        setUncordon('ok');
      } catch (e) {
        setUncordon(e instanceof ApiError && e.code === 'unchanged' ? 'ok' : errMsg(e));
      }
    }
  };
  return (
    <Dialog title={`${s.name} 재개`} width={560} onClose={onClose} footer={<Footer m={m} label="재개" ok={can} onSend={() => void go()} onClose={onClose} />}>
      {!can ? (
        <div className="note wa small">
          {s.name}은(는) 상한 {won(s.capKRW)}에 닿아 재개할 수 없습니다. 이번 달 월말 예상 {won(s.capStop?.projectedKRW)}보다 상한을 높이거나 다음 달에 재개하세요.{' '}
          <button type="button" className="linkish" onClick={onCap}>
            상한 변경…
          </button>
        </div>
      ) : (
        <p style={{ margin: 0 }}>
          서버가 켜지고 다시 가입하면 ‘실행 중’이 됩니다.{holds ? ` 그때 임시로 뺐던 DNS 레코드 ${holds}개를 되돌립니다.` : ''}
          {member ? ' 켠 뒤 새 배치를 다시 받게 합니다.' : ''}
        </p>
      )}
      {m.op?.state === 'applied' && <div className="note info small">{s.name} 재개 중 · 서버가 켜지고 다시 가입하면 ‘실행 중’이 됩니다.</div>}
      {uncordon && uncordon !== 'ok' && <div className="note wa small">새 배치 다시 받기를 하지 못했습니다({uncordon}). 서버 상세에서 ‘새 배치 다시 받기’를 하세요.</div>}
      <OpErrors m={m} />
    </Dialog>
  );
}

function CapDialog({ v, s, onClose }: { v: VpsView; s: VpsServer; onClose: () => void }) {
  const m = useMutation();
  const x = v.status?.servers?.find((y) => y.name === s.name);
  const [cap, setCap] = useState(String(s.capKRW));
  const [act, setAct] = useState<'stop' | 'notify'>(s.capAction ?? 'stop');
  const capN = Number(cap.replace(/,/g, ''));
  const same = capN === s.capKRW && act === (s.capAction ?? 'stop');
  const proj = x ? (x.judgeable ? x.projectedKRW : undefined) : s.capStop?.projectedKRW;
  const soFar = x?.soFarKRW ?? s.capStop?.soFarKRW;
  const send = () => sendOp(m, VPS.cap(s.name), { ...(capN !== s.capKRW ? { capKRW: capN } : {}), ...(act !== (s.capAction ?? 'stop') ? { capAction: act } : {}), expected: v.revision });
  return (
    <Dialog title={`${s.name} 월 요금 상한`} width={560} onClose={onClose} footer={<Footer m={m} label="저장" ok={capOk(capN) && !same} onSend={() => void send()} onClose={onClose} />}>
      <Field label="월 요금 상한 (원)" error={cap && !capOk(capN) ? '1 이상의 정수' : undefined} hint={`이번 달 지금까지 ${won(soFar)}${proj !== undefined ? ` · 지금 속도면 월말 ${won(proj)}` : x && !x.judgeable ? ' · 월말 예상은 판정 전' : ''}`}>
        <input inputMode="numeric" value={cap} onChange={(e) => setCap(e.target.value)} disabled={m.op?.state === 'applied'} style={{ width: 160 }} />
      </Field>
      <CapAction value={act} onChange={setAct} disabled={m.op?.state === 'applied'} />
      {s.phase === 'capped' && capOk(capN) && proj !== undefined && (capN > proj ? <div className="note ok small">새 상한이 월말 예상보다 높습니다. 저장하면 재개할 수 있습니다.</div> : <div className="note wa small">새 상한이 월말 예상 {won(proj)} 이하라 저장해도 이번 달에는 재개할 수 없습니다.</div>)}
      <span className="small muted">상한은 서버마다 따로입니다. 10분마다 트래픽을 읽어 월말 예상이 상한을 넘으면 고른 대로 끄거나 알립니다.</span>
      <OpErrors m={m} />
    </Dialog>
  );
}

function DeleteDialog({ v, s, member, onClose }: { v: VpsView; s: VpsServer; member: boolean; onClose: () => void }) {
  const m = useMutation();
  const [typed, setTyped] = useState('');
  const x = v.status?.servers?.find((y) => y.name === s.name);
  const send = () => sendOp(m, VPS.server(s.name), { expected: v.revision }, 'DELETE');
  return (
    <Dialog title="VPS 서버 삭제" width={560} danger onClose={onClose} footer={<Footer m={m} label="영구 삭제" danger ok={typed === s.name && !member && !s.voter} onSend={() => void send()} onClose={onClose} />}>
      <p style={{ margin: 0 }}>iwinv에서 서버와 디스크를 지우고 클러스터에서 제거합니다. 되돌릴 수 없습니다. 이 서버의 데이터 저장소 복제본과 로컬 파일도 사라집니다.</p>
      <KV
        items={[
          ['공인 IP', s.publicIP ? `${s.publicIP} 반납` : '—'],
          ['이번 달 요금', `${won(x?.soFarKRW ?? s.capStop?.soFarKRW)} · 이미 쓴 만큼은 청구`],
          ['DNS', '이 서버를 ‘연결된 서버’로 둔 외부 도메인에서 빼고, 레코드는 되돌리지 않습니다(삭제만 영구 변경)'],
        ]}
      />
      {s.voter && <div className="note er small">투표 서버는 바로 지울 수 없습니다. 서버 상세에서 투표권 없음으로 바꾼 뒤 지우세요.</div>}
      {member && !s.voter && (
        <div className="note wa small">
          클러스터에 들어온 서버라 먼저 비우고 클러스터에서 제거해야 합니다. <Link to={`/servers/${encodeURIComponent(s.name)}`}>서버 상세</Link>의 ‘비우기…’와 ‘클러스터에서 제거…’를 한 뒤 다시 여세요.
        </div>
      )}
      <Field label={<>확인하려면 <b className="mono">{s.name}</b> 입력</>}>
        <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value.trim())} disabled={!!m.op} autoComplete="off" />
      </Field>
      <OpErrors m={m} />
    </Dialog>
  );
}

/** 키 입력칸. 값은 이 창 상태에만 있고 보낸 뒤 지운다 */
function KeyFields({ ak, sk, setAk, setSk, disabled, fresh }: { ak: string; sk: string; setAk: (v: string) => void; setSk: (v: string) => void; disabled: boolean; fresh?: boolean }) {
  return (
    <>
      <Field label={fresh ? '새 Access Key' : 'Access Key'}>
        <input className="mono" value={ak} onChange={(e) => setAk(e.target.value.trim())} disabled={disabled} autoComplete="off" spellCheck={false} />
      </Field>
      <Field label={fresh ? '새 Secret Key' : 'Secret Key'} hint="쓰기 전용 · 저장 뒤 다시 보이지 않음">
        <input type="password" className="mono" value={sk} onChange={(e) => setSk(e.target.value.trim())} disabled={disabled} autoComplete="new-password" spellCheck={false} />
      </Field>
    </>
  );
}

/** 저장 뒤 offer로 연결을 확인한다(sfcd는 저장 전 키 확인을 지원하지 않는다) */
function useCheck() {
  const [check, setCheck] = useState<{ ok: true; o: VpsOffer; ms: number } | { ok: false; e: unknown }>();
  const run = async (account: string) => {
    const t = performance.now();
    try {
      const o = await vpsOffer(account);
      setCheck({ ok: true, o, ms: performance.now() - t });
    } catch (e) {
      setCheck({ ok: false, e });
    }
  };
  const view = check ? (
    check.ok ? (
      <div className="note ok small">
        연결 확인됨 · 존 {check.o.zones.length}개 ({check.o.zones.map((z) => z.id).join(', ')}) · 타입 {check.o.flavors.length}개 · 이미지 {check.o.images.length}개 · {(check.ms / 1000).toFixed(1)}초
      </div>
    ) : (
      <div className="note er small">연결 실패 · {errMsg(check.e)} 키를 확인한 뒤 ‘키 교체’로 바꾸세요.</div>
    )
  ) : null;
  return { run, view };
}

function AccountDialog({ onClose }: { onClose: () => void }) {
  const m = useMutation();
  const chk = useCheck();
  const [name, setName] = useState('');
  const [ak, setAk] = useState('');
  const [sk, setSk] = useState('');
  // iwinv는 공급자 요금표(overageTiers)를 쓴다. 단가는 요금표가 없는 공급자용이라 기본값을 보낸다
  const priceN = 10;
  const nameOk = /^[a-z0-9][a-z0-9-]{0,31}$/.test(name);
  const ok = nameOk && !!ak && !!sk && Number.isFinite(priceN) && priceN >= 0;
  const send = async () => {
    const op = await sendOp(m, VPS.accounts, { name, vendor: 'iwinv', accessKey: ak, secretKey: sk, trafficPrice: priceN });
    if (op && op.state !== 'unknown') (setAk(''), setSk(''));
    if (op?.state === 'applied') await chk.run(name);
  };
  return (
    <Dialog title="공급자 연결" width={560} onClose={onClose} footer={<Footer m={m} label="저장하고 연결 확인" ok={ok} onSend={() => void send()} onClose={onClose} />}>
      <Field label="이름" error={name && !nameOk ? '소문자·숫자·- 만' : undefined}>
        <input value={name} placeholder="main" onChange={(e) => setName(e.target.value.trim())} disabled={!!m.op} autoComplete="off" />
      </Field>
      <Field label="종류">
        <select value="iwinv" disabled>
          <option value="iwinv">iwinv</option>
        </select>
      </Field>
      <KeyFields ak={ak} sk={sk} setAk={setAk} setSk={setSk} disabled={!!m.op} />
      <TierTable tiers={IWINV_TIERS} />
      <TrafficRules vendor="iwinv" />
      <Field label="트래픽 조기 감시 (15분 전)">
        <input readOnly value={`기본 · 측정 창 ${GUARD_DEFAULT.windowMin}분, 누적 평균 ${GUARD_DEFAULT.averageMin}분, 지난 달 패턴 씀 · 연결한 뒤 ⋯ › 단가 바꾸기에서 바꿉니다`} />
      </Field>
      <span className="small muted">키는 투표 서버가 봉인해 sfcd에 둡니다. 저장하기 전에 키를 확인하는 길은 없어, 저장한 뒤 공급자 목록을 읽어 연결을 확인합니다.</span>
      {chk.view}
      <OpErrors m={m} />
    </Dialog>
  );
}

function RotateDialog({ v, a, onClose }: { v: VpsView; a: VpsAccount; onClose: () => void }) {
  const m = useMutation();
  const chk = useCheck();
  const [ak, setAk] = useState('');
  const [sk, setSk] = useState('');
  const n = v.servers.filter((s) => s.account === a.name).length;
  const send = async () => {
    const op = await sendOp(m, VPS.rotate(a.name), { accessKey: ak, secretKey: sk, expected: v.revision });
    if (op && op.state !== 'unknown') (setAk(''), setSk(''));
    if (op?.state === 'applied') await chk.run(a.name);
  };
  return (
    <Dialog title={`${a.name} 키 교체`} width={560} onClose={onClose} footer={<Footer m={m} label="바꾸고 연결 확인" ok={!!ak && !!sk} onSend={() => void send()} onClose={onClose} />}>
      <KeyFields ak={ak} sk={sk} setAk={setAk} setSk={setSk} disabled={!!m.op} fresh />
      <span className="small muted">이 계정의 VPS 서버 {n}대는 그대로입니다. 계정 SSH 키도 새로 생겨, 공급자에 등록한 SSH 키 ID는 지워집니다. 바꾼 뒤 공급자 목록을 읽어 연결을 확인합니다.</span>
      {chk.view}
      <OpErrors m={m} />
    </Dialog>
  );
}

function PriceDialog({ v, a, onClose }: { v: VpsView; a: VpsAccount; onClose: () => void }) {
  const m = useMutation();
  const [price, setPrice] = useState(String(a.overageKRWPerGB));
  const [key, setKey] = useState(a.sshKeyID ?? '');
  const priceN = Number(price);
  // 조기 감시: 빈 칸 = 기본(0으로 보냄). 바꾼 칸만 보낸다
  const g0 = { win: a.guard?.windowMin ? String(a.guard.windowMin) : '', avg: a.guard?.averageMin ? String(a.guard.averageMin) : '', pattern: !a.guard?.patternOff };
  const [win, setWin] = useState(g0.win);
  const [avg, setAvg] = useState(g0.avg);
  const [pattern, setPattern] = useState(g0.pattern);
  const winN = win.trim() ? Number(win) : 0;
  const avgN = avg.trim() ? Number(avg) : 0;
  const gErr = guardError(winN, avgN);
  const guardDelta = {
    ...(win !== g0.win ? { guardWindowMin: winN } : {}),
    ...(avg !== g0.avg ? { guardAverageMin: avgN } : {}),
    ...(pattern !== g0.pattern ? { guardPattern: pattern } : {}),
  };
  const same = priceN === a.overageKRWPerGB && key === (a.sshKeyID ?? '') && !Object.keys(guardDelta).length;
  const send = () => sendOp(m, VPS.account(a.name), { ...(priceN !== a.overageKRWPerGB ? { trafficPrice: priceN } : {}), ...(key !== (a.sshKeyID ?? '') ? { sshKeyId: key } : {}), ...guardDelta, expected: v.revision }, 'PATCH');
  return (
    <Dialog title={`${a.name} 설정`} width={560} onClose={onClose} footer={<Footer m={m} label="저장" ok={!same && !gErr && Number.isFinite(priceN) && priceN >= 0} onSend={() => void send()} onClose={onClose} />}>
      {a.overageTiers?.length ? (
        <TierTable tiers={a.overageTiers} />
      ) : (
        <Field label="트래픽 초과 GB당 단가 (원)" hint="제공량을 넘은 트래픽의 요금 계산에 씁니다(공급자 API가 알려 주지 않습니다)">
          <input inputMode="numeric" value={price} onChange={(e) => setPrice(e.target.value)} disabled={m.op?.state === 'applied'} style={{ width: 120 }} />
        </Field>
      )}
      <TrafficRules vendor={a.vendor} />
      <GuardFields win={win} avg={avg} pattern={pattern} setWin={setWin} setAvg={setAvg} setPattern={setPattern} error={gErr} disabled={m.op?.state === 'applied'} />
      <Field label="공급자에 등록한 SSH 키 ID" hint="설치 스크립트 없이 만드는 서버에 씁니다. 비우면 지웁니다">
        <input className="mono" value={key} onChange={(e) => setKey(e.target.value.trim())} disabled={m.op?.state === 'applied'} autoComplete="off" />
      </Field>
      {a.sshPublic && (
        <Field label="계정 SSH 공개키" hint="공급자 콘솔에 이 공개키를 등록하고 그 ID를 위에 넣습니다">
          <input className="mono" readOnly value={a.sshPublic} onFocus={(e) => e.currentTarget.select()} />
        </Field>
      )}
      <OpErrors m={m} />
    </Dialog>
  );
}

/** 트래픽 조기 감시 (15분 전) 설정 칸 (캔버스 v253, #701) */
function GuardFields(p: { win: string; avg: string; pattern: boolean; setWin: (s: string) => void; setAvg: (s: string) => void; setPattern: (b: boolean) => void; error?: string; disabled?: boolean }) {
  return (
    <Field
      label="트래픽 조기 감시 (15분 전)"
      hint={`측정 창 1–60분, 누적 평균 기간은 창의 2배 이상·1440분 이하. 비우면 기본(창 ${GUARD_DEFAULT.windowMin}분, 평균 ${GUARD_DEFAULT.averageMin}분)`}
      error={p.error}
    >
      <div className="col" style={{ gap: 6 }}>
        <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
          <label className="row" style={{ gap: 6 }}>
            <span className="small">측정 창 (분)</span>
            <input inputMode="numeric" value={p.win} placeholder={String(GUARD_DEFAULT.windowMin)} onChange={(e) => p.setWin(e.target.value.trim())} disabled={p.disabled} style={{ width: 72 }} />
          </label>
          <label className="row" style={{ gap: 6 }}>
            <span className="small">누적 평균 기간 (분)</span>
            <input inputMode="numeric" value={p.avg} placeholder={String(GUARD_DEFAULT.averageMin)} onChange={(e) => p.setAvg(e.target.value.trim())} disabled={p.disabled} style={{ width: 84 }} />
          </label>
        </div>
        <label className="check">
          <input type="checkbox" checked={p.pattern} onChange={(e) => p.setPattern(e.target.checked)} disabled={p.disabled} /> 지난 달 같은 시각대 패턴도 예측에 씀
        </label>
      </div>
    </Field>
  );
}

/** 공급자가 공개한 초과 요금표(읽기 전용, 캔버스 v251·v252) */
function TierTable({ tiers }: { tiers: VpsOverageTier[] }) {
  return (
    <div className="col" style={{ gap: 4 }}>
      <b className="small">트래픽 초과 요금표</b>
      <table className="tbl" style={{ maxWidth: 360 }}>
        <thead>
          <tr>
            <th>제공량을 넘은 양</th>
            <th>GB당 (부가세 별도)</th>
          </tr>
        </thead>
        <tbody>
          {tiers.map((t, i) => (
            <tr key={i}>
              <td>{tierRange(tiers, i)}</td>
              <td>{won(t.krwPerGB)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <span className="small muted">공급자가 정한 요금이라 바꿀 수 없습니다. 들어오는 트래픽과 iwinv 내부 트래픽은 세지 않습니다.</span>
    </div>
  );
}

/** 공급자마다 정해진 트래픽 규칙(#698). 바꿀 수 없어 읽기 전용으로 보인다 */
function TrafficRules({ vendor }: { vendor: string }) {
  const iw = vendor === 'iwinv';
  return (
    <>
      <Field label="트래픽 세는 방식" hint="나가는 것만 (TX) · 들어오고 나가는 것 합 (RX+TX) · 모름. 공급자마다 정해진 값이라 바꿀 수 없습니다">
        <input readOnly value={iw ? '공급자가 정함 · iwinv는 나가는 것만 (TX)' : '공급자가 정함'} style={{ width: 300 }} />
      </Field>
      <Field label="판정 기준">
        <input readOnly value={iw ? `서버마다 공급자가 알려 줌 · iwinv는 일간 (하루 ${IWINV_DAY_GB} GB, 월 최대 ${IWINV_DAY_GB * 30} GB)` : '서버마다 공급자가 알려 줌'} />
      </Field>
    </>
  );
}

/** iwinv 보통 제공량(카탈로그에 없을 때 sfcd가 estimated로 채우는 값과 같다) */
const IWINV_DAY_GB = 20;

/** 계정 줄의 트래픽 규칙: 서버가 알려 준 값 → 타입 목록의 값 → 공급자 보통 값 */
function accountTrafficText(v: VpsView, a: VpsAccount, o?: VpsOffer): string {
  const names = new Set(v.servers.filter((s) => s.account === a.name).map((s) => s.name));
  const x = (v.status?.servers ?? []).find((s) => names.has(s.name) && s.includedGB !== undefined);
  const t = x ? { gb: x.includedGB!, period: x.includedPeriod ?? 'MONTH', maxGB: x.includedMaxGB } : o?.flavors.find((f) => f.traffic)?.traffic ?? (a.vendor === 'iwinv' ? { gb: IWINV_DAY_GB, period: 'DAY', maxGB: IWINV_DAY_GB * 30 } : undefined);
  const counting = countingText(x?.trafficCounting ?? vendorCounting(a.vendor));
    if (!t) return `제공량 모름 · ${counting}`;
  const rule = t.period === 'DAY' ? `일간 판정 · 하루 ${gbText(t.gb)}${t.maxGB ? ` (월 최대 ${gbText(t.maxGB)})` : ''}` : `월간 판정 · 월 ${gbText(t.gb)}`;
  return `${rule} · ${counting}`;
}

function UnlinkDialog({ v, a, onClose }: { v: VpsView; a: VpsAccount; onClose: () => void }) {
  const m = useMutation();
  const n = v.servers.filter((s) => s.account === a.name).length;
  const send = () => sendOp(m, VPS.account(a.name), { expected: v.revision }, 'DELETE');
  return (
    <Dialog title={`${a.name} 연결 해제`} width={560} danger onClose={onClose} footer={<Footer m={m} label="연결 해제" danger ok={!n} onSend={() => void send()} onClose={onClose} />}>
      {n ? (
        <div className="note er small">이 계정으로 만든 VPS 서버 {n}대가 남아 있습니다. 먼저 지우세요. 해제하면 요금 조회와 상한 중지를 할 수 없기 때문입니다.</div>
      ) : (
        <p style={{ margin: 0 }}>저장된 키를 지우고 계정을 목록에서 뺍니다. iwinv 쪽 계정과 키는 그대로입니다.</p>
      )}
      <OpErrors m={m} />
    </Dialog>
  );
}

/** 목록의 VPS 서버 이름(다른 화면에서 쓰기) */
export const useVpsNames = () => {
  const q = usePoll((s) => vpsView(s).catch(() => undefined), [], 60_000);
  return useMemo(() => new Set((q.data?.servers ?? []).map((s) => s.name)), [q.data]);
};
