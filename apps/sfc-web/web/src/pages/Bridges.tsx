// SPDX-License-Identifier: Apache-2.0

// 가상 브릿지 (UI-5D, 캔버스 NetworkBridges · NetworksIx). 망 두 개를 통째로 잇는다.
// 계약: docs/reference/web-api/46-ui-5d.md (#704). 행은 resources의 bridge/<만든 작업 공간>/<이름>,
// state는 이 작업 공간 기준(open / closing / waiting-me / waiting-peer). 상대 작업 공간 망은 이름만 보인다.
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ApiError } from '../api/client';
import { bridgeEndpoints, bridgePath, networkPath, tenantList } from '../api/endpoints';
import type { BridgeView, NetworkView, OpView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { Badge, Card, Field, HelpBox, type Tone } from '../components/ui';
import { eulReul, gwaWa, iGa } from '../lib/josa';
import { usePoll } from '../lib/usePoll';
import { NET_NEED, NetFrame, useNetLists } from './NetFrame';
import { parsePorts } from './Routes';

type End = BridgeView['a'];
const endText = (e: End) => `${e.tenant}/${e.network}`;
/** "shop/shop-net ⇄ shop/shop-db" */
export const bridgeEnds = (b: BridgeView) => `${endText(b.a)} ${b.direction === 'both' ? '⇄' : b.direction === 'a-to-b' ? '→' : '←'} ${endText(b.b)}`;
/** 이 작업 공간의 망 하나에 걸린 브릿지 */
export const bridgesOf = (list: BridgeView[], tenant: string, net: string) => list.filter((b) => (b.a.tenant === tenant && b.a.network === net) || (b.b.tenant === tenant && b.b.network === net));
/** 망 옵션 bridge-inbound: 다른 작업 공간이 이 망으로 브릿지를 만들 수 있다 */
export const inboundOn = (n: NetworkView) => n.toggles.includes('bridge-inbound');
export const bridgePortText = (b: Pick<BridgeView, 'protocol' | 'ports'>) =>
  b.protocol === 'all' || !b.protocol ? '모든 포트' : `${b.protocol} ${b.ports.length ? b.ports.map((p) => (p.first === p.last ? `${p.first}` : `${p.first}-${p.last}`)).join(', ') : '모든 포트'}`;

const STATE: Record<BridgeView['state'], [string, Tone]> = {
  open: ['이어짐', 'ok'],
  'waiting-me': ['내 승인 필요', 'wa'],
  'waiting-peer': ['상대 승인 대기', 'pr'],
  closing: ['끊는 중', 'un'],
};

/** 망 표의 '가상 브릿지' 칸: 이 망에서 본 방향과 상대 망 */
export function BridgeLinks({ list, tenant, net }: { list: BridgeView[]; tenant: string; net: string }) {
  if (!list.length) return <span className="muted">—</span>;
  const text = list.map((b) => {
    const mine = b.a.tenant === tenant && b.a.network === net;
    const other = mine ? b.b : b.a;
    const arrow = b.direction === 'both' ? '⇄' : (b.direction === 'a-to-b') === mine ? '→' : '←';
    const name = other.tenant === tenant ? other.network : endText(other);
    return `${arrow} ${name}${b.state === 'waiting-me' ? ' (내 승인 필요)' : b.state === 'waiting-peer' ? ' (상대 승인 대기)' : b.state === 'closing' ? ' (끊는 중)' : ''}`;
  });
  return (
    <Link to="/shared/networks/bridges" style={{ fontSize: 12 }}>
      {text.join(' · ')}
    </Link>
  );
}

/** 한쪽 끝: 작업 공간/망 + 이 작업 공간이면 서버·주소, 아니면 '망 이름만 보임' */
function EndCell({ e, tenant, nets }: { e: End; tenant: string; nets: NetworkView[] }) {
  const mine = e.tenant === tenant;
  const n = mine ? nets.find((x) => x.name === e.network) : undefined;
  const members = n ? (n.members.length ? n.members.map((m) => ({ node: m.node, cidr: m.cidr })) : n.nodes.map((node) => ({ node, cidr: n.cidr }))) : [];
  const sub = !mine ? '다른 작업 공간 · 망 이름만 보임' : !members.length ? '이 작업 공간' : members.length === 1 ? `${members[0].node} · ${members[0].cidr}` : `${members.map((m) => m.node).join(', ')} · 주소 묶음 ${members.length}개`;
  return (
    <span className="col" style={{ gap: 2 }}>
      <span className="mono">
        {endText(e)}
        {mine && (
          <>
            {' '}
            <span className="badge pr" style={{ fontSize: 11, padding: '0 6px' }}>
              이 작업 공간
            </span>
          </>
        )}
      </span>
      <span className="muted" style={{ fontSize: 12 }}>
        {sub}
      </span>
    </span>
  );
}

function ApprovalCell({ b, tenant }: { b: BridgeView; tenant: string }) {
  if (b.a.tenant === b.b.tenant) return <span className="muted" style={{ fontSize: 12 }}>같은 작업 공간 · 승인 필요 없음</span>;
  return (
    <span className="col" style={{ gap: 2, fontSize: 12 }}>
      {[b.a.tenant, b.b.tenant].map((t) => {
        const a = b.approvals.find((x) => x.tenant === t);
        if (a) return <span key={t}>✓ {t}{a.user ? ` · ${a.user}` : ''}</span>;
        if (b.phase !== 'pending') return <span key={t} className="muted">— {t}</span>;
        return t === tenant ? (
          <span key={t} style={{ color: 'var(--wa)' }}>… {t} 승인 필요</span>
        ) : (
          <span key={t} className="muted">… {t} 승인 기다림</span>
        );
      })}
    </span>
  );
}

type Act = { kind: 'approve' | 'close'; b: BridgeView };

/** 가상 브릿지 탭 (UI-5D) */
export function NetworkBridgesPage() {
  const { tenant, nq, rq, bq } = useNetLists();
  const { canDeploy } = useTenantRole();
  const [creating, setCreating] = useState(false);
  const [peer, setPeer] = useState<'' | 'same' | 'other'>('');
  const [st, setSt] = useState<'' | BridgeView['state']>('');
  const [act, setAct] = useState<Act>();
  const [inbound, setInbound] = useState<NetworkView>();
  const t = tenant ?? '';
  const nets = nq.data?.items ?? [];
  const all = bq.data?.items ?? [];
  const same = (b: BridgeView) => b.a.tenant === b.b.tenant;
  const rows = all.filter((b) => (!peer || (peer === 'same') === same(b)) && (!st || b.state === st));
  const need = canDeploy ? undefined : NET_NEED;
  /** 내가 승인할 쪽(b) 망이 받기를 껐으면 승인 단추를 끈다 */
  const approveOff = (b: BridgeView) => {
    const n = nets.find((x) => x.name === b.b.network);
    return n && !inboundOn(n) ? `${n.name}${iGa(n.name)} 다른 작업 공간의 브릿지를 받지 않게 돼 있어 승인할 수 없습니다. 받기를 켜거나 거절하세요.` : undefined;
  };
  return (
    <NetFrame
      ids="UI-5D"
      q={bq}
      nq={nq}
      rq={rq}
      bq={bq}
      actions={
        <button type="button" className="btn primary" disabled={!canDeploy || !nq.data || !bq.data} title={need} onClick={() => setCreating(true)}>
          가상 브릿지 만들기
        </button>
      }
      help={
        <HelpBox terms="가상 브릿지 (virtual bridge) · 잇기 · 끊기 · 승인 (approve) · 다른 작업 공간의 브릿지 받기 (망 옵션)">
          <b>이 화면은</b> 망 두 개를 통째로 잇는 가상 브릿지를 관리합니다. 이으면 두 망에 참여한 모든 서버의 컨테이너가 서로 닿습니다. 기본은 양방향 · 모든 포트이고, 방향이나 포트를 좁힐 수 있습니다. 같은 작업 공간의 망끼리는 바로 이어지고, 다른 작업 공간의 망과는 상대 망이 ‘다른 작업 공간의 브릿지 받기’를 켜 두었을 때만 요청할 수 있으며 상대 관리자가 승인해야 이어집니다. 브릿지는 양쪽 작업 공간에 모두 보이고, 상대 작업 공간의 망은 이름만 보입니다(CIDR은 보이지 않음).
          <br />
          <b>작업 공간 간 연결과 다른 점</b> 작업 공간 간 연결은 서버 한 대에서 상대 망으로 정한 포트만 통과시키는 게이트웨이(gateway)입니다. 가상 브릿지는 두 망을 통째로 이어 하나처럼 닿게 합니다.
        </HelpBox>
      }
    >
      <div className="bn info small">열린 브릿지로 패킷이 다니는 부분은 sfcd에서 아직 만드는 중입니다. 지금은 만들기·승인·끊기와 목록까지 됩니다.</div>
      <Card>
        <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
          <select aria-label="상대" value={peer} onChange={(e) => setPeer(e.target.value as typeof peer)}>
            <option value="">상대: 전체</option>
            <option value="same">같은 작업 공간</option>
            <option value="other">다른 작업 공간</option>
          </select>
          <select aria-label="상태" value={st} onChange={(e) => setSt(e.target.value as typeof st)}>
            <option value="">상태: 전체</option>
            <option value="waiting-me">내 승인 필요</option>
            <option value="waiting-peer">상대 승인 대기</option>
            <option value="open">이어짐</option>
            <option value="closing">끊는 중</option>
          </select>
        </div>
        {bq.error ? (
          <MutationError error={bq.error} />
        ) : !bq.data ? (
          <span className="small muted">불러오는 중…</span>
        ) : rows.length === 0 ? (
          <span className="small muted">{all.length ? '조건에 맞는 가상 브릿지가 없습니다.' : '가상 브릿지가 없습니다.'}</span>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="tbl" style={{ minWidth: 900 }}>
              <thead>
                <tr>
                  <th>이름</th>
                  <th>망</th>
                  <th>방향</th>
                  <th>이어진 망</th>
                  <th>포트</th>
                  <th>승인</th>
                  <th>상태</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((b) => {
                  const [label, tone] = STATE[b.state] ?? [b.phase, 'pr'];
                  const off = b.state === 'waiting-me' ? approveOff(b) : undefined;
                  return (
                    <tr key={b.key} style={b.state === 'waiting-me' ? { background: 'var(--wa-soft)' } : undefined}>
                      <td>
                        <span className="col" style={{ gap: 2 }}>
                          <b>{b.name}</b>
                          <span className="muted" style={{ fontSize: 11 }}>
                            만든 곳 {b.owner}
                          </span>
                        </span>
                      </td>
                      <td className="wrap">
                        <EndCell e={b.a} tenant={t} nets={nets} />
                      </td>
                      <td style={{ fontSize: 18 }} title={b.direction === 'both' ? '양방향' : `${endText(b.direction === 'a-to-b' ? b.a : b.b)}에서만 시작`}>
                        {b.direction === 'both' ? '⇄' : b.direction === 'a-to-b' ? '→' : '←'}
                      </td>
                      <td className="wrap">
                        <EndCell e={b.b} tenant={t} nets={nets} />
                      </td>
                      <td className="mono">{bridgePortText(b)}</td>
                      <td className="wrap">
                        <ApprovalCell b={b} tenant={t} />
                      </td>
                      <td className="wrap">
                        {b.state === 'closing' ? (
                          <span className="col" style={{ gap: 2 }}>
                            <Badge tone={tone}>{label}</Badge>
                            <span className="muted" style={{ fontSize: 11 }}>
                              모든 서버 확인 기다림
                            </span>
                          </span>
                        ) : (
                          <Badge tone={tone}>{label}</Badge>
                        )}
                      </td>
                      <td>
                        <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                          {b.state === 'waiting-me' && (
                            <>
                              <button type="button" className="btn sm primary" disabled={!canDeploy || !!off} title={need ?? off} onClick={() => setAct({ kind: 'approve', b })}>
                                승인
                              </button>
                              <button type="button" className="btn sm danger" disabled={!canDeploy} title={need} onClick={() => setAct({ kind: 'close', b })}>
                                거절…
                              </button>
                            </>
                          )}
                          {b.state === 'waiting-peer' && (
                            <button type="button" className="btn sm danger" disabled={!canDeploy} title={need} onClick={() => setAct({ kind: 'close', b })}>
                              요청 취소…
                            </button>
                          )}
                          {b.state === 'open' && (
                            <button type="button" className="btn sm danger" disabled={!canDeploy} title={need} onClick={() => setAct({ kind: 'close', b })}>
                              끊기…
                            </button>
                          )}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <span className="small muted">
          ⇄ 양방향 · → 왼쪽 망에서 오른쪽 망으로만 접속을 시작할 수 있음(응답은 돌아옴). 끊기: 이어진 브릿지는 ‘끊는 중’이 되고 모든 서버가 확인하면 목록에서 사라집니다. 승인 전 브릿지는 거절하거나 요청을 취소하면 바로 사라집니다. 망에 서버가 더해지거나 빠지면 브릿지도 따라갑니다. 브릿지는 망의 도메인 이름을 서로 넘기지 않습니다(상대 컨테이너는 주소로 접속).
        </span>
      </Card>
      <Card title="다른 작업 공간의 브릿지 받기" actions={<span className="small muted">망 옵션 · 기본 꺼짐 · 망 줄 메뉴에서도 바꿀 수 있음</span>}>
        <span className="small muted">
          켜 둔 망만 다른 작업 공간의 가상 브릿지 만들기 창에 나옵니다. 켜도 요청마다 이 작업 공간 관리자의 승인이 필요합니다. 끄면 새 요청만 막힙니다: 이어진 브릿지는 어느 쪽이 끊을 때까지 그대로이고, 승인 대기 중인 브릿지는 승인할 수 없게 되지만 끊을 수는 있습니다. 같은 작업 공간끼리의 브릿지와는 상관없습니다.
        </span>
        {nets.length === 0 ? (
          <span className="small muted">{nq.data ? '망이 없습니다.' : '불러오는 중…'}</span>
        ) : (
          <table className="tbl">
            <thead>
              <tr>
                <th>망</th>
                <th>서버 · 주소 묶음</th>
                <th>받기</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {nets.map((n) => {
                const on = inboundOn(n);
                const waiting = all.filter((b) => b.b.tenant === t && b.b.network === n.name && b.a.tenant !== t && b.phase === 'pending').length;
                const members = n.members.length ? n.members : n.nodes.map((node) => ({ node, cidr: n.cidr }));
                const deleting = n.members.some((x) => x.draining && !x.phase);
                return (
                  <tr key={n.key}>
                    <td>
                      <b>{n.name}</b>
                      {deleting && <span className="small muted"> 지우는 중</span>}
                    </td>
                    <td className="small">
                      {members.length === 1 ? `${members[0].node} · ${members[0].cidr}` : `${members.map((m) => m.node).join(', ')} · 주소 묶음 ${members.length}개`}
                      {waiting ? ` · 다른 작업 공간 브릿지 ${waiting}개(승인 대기)` : ''}
                    </td>
                    <td>
                      <Badge tone={on ? 'ok' : 'un'}>{on ? '켜짐' : '꺼짐'}</Badge>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button type="button" className="btn sm" disabled={!canDeploy} title={need} onClick={() => setInbound(n)}>
                        {on ? '끄기…' : '켜기…'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
      {creating && bq.data && <BridgeCreateDialog tenant={t} nets={nets} bridges={all} onClose={() => setCreating(false)} onDone={() => void bq.refresh()} />}
      {act && <BridgeActionDialog tenant={t} act={act} onClose={() => setAct(undefined)} onDone={() => void bq.refresh()} />}
      {inbound && <InboundDialog tenant={t} net={inbound} bridges={all} onClose={() => setInbound(undefined)} onDone={() => (void nq.refresh(), void bq.refresh())} />}
    </NetFrame>
  );
}

const NAME = /^[a-z0-9][a-z0-9-]*$/;

/** 만들기 거절 문구 (캔버스 NetworkBridges 오류 예시) */
function createErrText(code: string, x: { net: string; peer: string; peerTenant: string; existing?: string }): string | undefined {
  switch (code) {
    case 'bridge-exists':
      return `이미 ${x.net}${gwaWa(x.net)} ${x.peer}${eulReul(x.peer)} 잇는 가상 브릿지${x.existing ? `(${x.existing})` : ''}가 있습니다. 같은 두 망은 하나만 이을 수 있습니다.`;
    case 'peer-closed':
      return `${x.peer}${iGa(x.peer)} 없거나, 다른 작업 공간의 브릿지를 받지 않거나, 바뀌는 중입니다. ${x.peerTenant} 관리자에게 받기를 켜 달라고 하세요.`;
    case 'network-changing':
      return `${x.net}${iGa(x.net)} 바뀌는 중이라 지금은 이을 수 없습니다. 변경이 끝난 뒤 다시 만드세요.`;
  }
  return undefined;
}

function BridgeCreateDialog({ tenant, nets, bridges, onClose, onDone }: { tenant: string; nets: NetworkView[]; bridges: BridgeView[]; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const usable = nets.filter((n) => n.kind === 'tun' && !n.members.some((x) => x.draining && !x.phase));
  const [name, setName] = useState('');
  const [net, setNet] = useState(usable[0]?.name ?? '');
  const [pt, setPt] = useState(tenant);
  const [peerNet, setPeerNet] = useState('');
  const [dir, setDir] = useState<BridgeView['direction']>('both');
  const [portsOn, setPortsOn] = useState(false);
  const [proto, setProto] = useState<'tcp' | 'udp'>('tcp');
  const [ports, setPorts] = useState('');
  const [sent, setSent] = useState<Record<string, unknown>>();
  const tq = usePoll((s) => tenantList(s).catch(() => []), []);
  const others = (tq.data ?? []).map((x) => x.id).filter((x) => x !== tenant);
  const same = pt === tenant;
  const ptOk = !!pt && NAME.test(pt);
  // 다른 작업 공간: 받기를 켠 망(bridge-endpoints, #728)에서 고른다. 끝점을 못 읽으면(옛 데몬 등) 망 이름을 직접 쓴다
  const pq = usePoll((s) => (!same && ptOk ? bridgeEndpoints(tenant, pt, s) : Promise.resolve(undefined)), [same, ptOk ? pt : '']);
  const peerList: { key: string; name: string; view?: NetworkView }[] = same ? usable.filter((n) => n.name !== net).map((n) => ({ key: n.key, name: n.name, view: n })) : (pq.data ?? []).map((x) => ({ key: `${x.tenant}/${x.network}`, name: x.network }));
  const typed = !same && !!pq.error;
  const pr = portsOn ? parsePorts(ports) : [];
  const nameErr = name && !NAME.test(name) ? '영문 소문자, 숫자, -로 씁니다.' : bridges.some((b) => b.owner === tenant && b.name === name) ? '이 작업 공간에 같은 이름의 가상 브릿지가 있습니다.' : undefined;
  const ptErr = pt && !ptOk ? '작업 공간 이름을 씁니다.' : undefined;
  const portErr = portsOn && ports && !pr ? '1~65535 사이 포트나 범위(8000-8100)를 쉼표로 씁니다. 범위는 작은 수부터 씁니다.' : undefined;
  const peerText = same ? peerNet : `${pt}/${peerNet}`;
  const existing = m.op ? undefined : bridges.find((b) => {
    const x = endText(b.a), y = endText(b.b), p = `${tenant}/${net}`, q = `${pt}/${peerNet}`;
    return (x === p && y === q) || (x === q && y === p);
  });
  const ready = !!name && !nameErr && !!net && ptOk && !!peerNet && NAME.test(peerNet) && !(same && peerNet === net) && (!portsOn || (!!pr && !!ports)) && !existing;
  const body = () => ({
    name,
    network: net,
    peer: same ? { network: peerNet } : { tenant: pt, network: peerNet },
    ...(dir !== 'both' ? { direction: dir } : {}),
    ...(portsOn ? { protocol: proto, ports: pr } : {}),
  });
  const go = () => {
    const next = body();
    // 고친 본문은 새 작업으로 보낸다(같은 opId에 다른 본문은 op-conflict)
    if (sent && JSON.stringify(sent) !== JSON.stringify(next)) m.reset();
    setSent(next);
    void m.run(bridgePath(tenant), next).then((o) => o?.state === 'applied' && onDone());
  };
  const ctx = { net, peer: peerText || '상대 망', peerTenant: pt, existing: existing?.name };
  const apiErr = m.error instanceof ApiError ? createErrText(m.error.code, ctx) : undefined;
  const opErr = m.op?.errorCode && m.op.state !== 'applied' ? createErrText(m.op.errorCode, ctx) : undefined;
  const ownNet = (n: NetworkView) => {
    const ms = n.members.length ? n.members : n.nodes.map((node) => ({ node }));
    return `${n.name} · ${ms.map((x) => x.node).join(', ')}`;
  };
  return (
    <Dialog
      title="가상 브릿지 만들기"
      onClose={onClose}
      footer={
        m.op ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn primary" disabled={!ready || m.busy} onClick={go}>
              만들기
            </button>
          </>
        )
      }
    >
      <Field label="이름" error={nameErr}>
        <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} placeholder="net-cache" disabled={!!m.op} />
      </Field>
      <Field label="이 작업 공간의 망">
        <select value={net} onChange={(e) => (setNet(e.target.value), same && peerNet === e.target.value && setPeerNet(''))} disabled={!!m.op}>
          {usable.length === 0 && <option value="">망이 없습니다</option>}
          {usable.map((n) => (
            <option key={n.key} value={n.name}>
              {ownNet(n)}
            </option>
          ))}
        </select>
      </Field>
      <Field label="잇는 망의 작업 공간" error={ptErr}>
        <input className="mono" list="bridge-peer-tenant" value={pt} onChange={(e) => (setPt(e.target.value.trim()), setPeerNet(''))} disabled={!!m.op} />
        <datalist id="bridge-peer-tenant">
          <option value={tenant}>{tenant} (같은 작업 공간)</option>
          {others.map((x) => (
            <option key={x} value={x} />
          ))}
        </datalist>
      </Field>
      <Field
        label="잇는 망"
        hint={
          same
            ? undefined
            : typed
              ? `${pt}에서 브릿지를 받는 망 목록을 읽지 못해 이름을 직접 씁니다. 받기를 켠 망만 이어집니다.`
              : pq.data && !peerList.length
                ? `${pt}에 다른 작업 공간의 브릿지를 받는 망이 없습니다`
                : `${pt}${iGa(pt)} 다른 작업 공간의 브릿지 받기를 켠 망만 나옵니다`
        }
      >
        {typed ? (
          <input className="mono" value={peerNet} onChange={(e) => setPeerNet(e.target.value.trim())} placeholder="cache-net" disabled={!!m.op} />
        ) : (
          <select value={peerNet} onChange={(e) => setPeerNet(e.target.value)} disabled={!!m.op || !ptOk}>
            <option value="">{peerList.length ? '고르세요' : '고를 망이 없습니다'}</option>
            {peerList.map((n) => (
              <option key={n.key} value={n.name}>
                {n.view ? ownNet(n.view) : n.name}
              </option>
            ))}
          </select>
        )}
      </Field>
      <Field label="방향" group>
        {(
          [
            ['both', '양방향 ⇄'],
            ['a-to-b', `${net || '이 망'} → ${peerNet || '잇는 망'}만`],
            ['b-to-a', `${peerNet || '잇는 망'} → ${net || '이 망'}만`],
          ] as [BridgeView['direction'], string][]
        ).map(([v, l]) => (
          <label key={v} className="check">
            <input type="radio" name="bridge-dir" checked={dir === v} disabled={!!m.op} onChange={() => setDir(v)} /> {l}
          </label>
        ))}
      </Field>
      <Field label="포트" group error={portErr} hint="고른 포트는 한 프로토콜(tcp 또는 udp)에 대해 포트나 범위를 쉼표로 적습니다.">
        <label className="check">
          <input type="radio" name="bridge-ports" checked={!portsOn} disabled={!!m.op} onChange={() => setPortsOn(false)} /> 모든 포트
        </label>
        <span className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <label className="check">
            <input type="radio" name="bridge-ports" checked={portsOn} disabled={!!m.op} onChange={() => setPortsOn(true)} /> 고른 포트만
          </label>
          <select aria-label="프로토콜" value={proto} disabled={!portsOn || !!m.op} onChange={(e) => setProto(e.target.value as 'tcp' | 'udp')} style={{ width: 90 }}>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
          </select>
          <input className="mono" aria-label="포트" value={ports} disabled={!portsOn || !!m.op} onChange={(e) => setPorts(e.target.value)} placeholder="6379, 8000-8100" style={{ flex: 1, minWidth: 140 }} />
        </span>
      </Field>
      <div className="note small">
        {same
          ? '같은 작업 공간의 망이라 만들면 바로 이어집니다. 다른 작업 공간을 고르면 그 작업 공간이 ‘다른 작업 공간의 브릿지 받기’를 켠 망만 나오고, 상대 관리자가 승인해야 이어집니다(그동안 ‘상대 승인 대기’).'
          : `${pt || '상대 작업 공간'} 관리자가 승인해야 이어집니다. 그동안 목록에 ‘상대 승인 대기’로 보입니다.`}
      </div>
      {existing && <div className="note wa">{createErrText('bridge-exists', ctx)}</div>}
      {apiErr ? <div className="note wa">{apiErr}</div> : <MutationError error={m.error} />}
      {opErr && <div className="note wa">{opErr}</div>}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

/** 승인 · 끊기(이어진 것) · 거절(내 승인 대기) · 요청 취소(상대 승인 대기). 끊기는 모두 close-virtual-bridge */
function BridgeActionDialog({ tenant, act, onClose, onDone }: { tenant: string; act: Act; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const { b, kind } = act;
  // 창을 연 때의 브릿지 revision을 expected로 보낸다
  const [expected] = useState(b.revision);
  const ends = bridgeEnds(b);
  const verb = kind === 'approve' ? '승인' : b.state === 'waiting-me' ? '거절' : b.state === 'waiting-peer' ? '요청 취소' : '끊기';
  const title = kind === 'approve' ? `${ends} 가상 브릿지를 승인할까요?` : b.state === 'waiting-me' ? `${b.owner}의 ${b.name} 요청을 거절할까요?` : b.state === 'waiting-peer' ? `${b.name} 요청을 취소할까요?` : `${b.name}${eulReul(b.name)} 끊을까요?`;
  const err = m.error instanceof ApiError ? (m.error.code === 'closing' ? '이미 끊는 중인 가상 브릿지입니다.' : m.error.code === 'already-approved' ? '이 작업 공간이 승인할 것이 없습니다. 새로 읽어 주세요.' : undefined) : undefined;
  return (
    <Dialog
      title={title}
      danger={kind === 'close'}
      width={420}
      onClose={onClose}
      footer={
        m.op ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className={kind === 'close' ? 'btn danger solid' : 'btn primary'} disabled={m.busy} onClick={() => void m.run(`${bridgePath(tenant, b)}/${kind}`, { expected }).then((o) => o?.state === 'applied' && onDone())}>
              {verb}
            </button>
          </>
        )
      }
    >
      {kind === 'approve' ? (
        <p>
          {ends} ({bridgePortText(b)})를 잇습니다. 승인하면 바로 이어지고 두 망의 모든 서버 컨테이너가 서로 닿습니다. {b.b.network}의 CIDR은 상대에게 보이지 않습니다.
        </p>
      ) : b.phase === 'pending' ? (
        <p>{ends} 요청이 바로 사라집니다. 다시 이으려면 새로 만들어야 합니다.</p>
      ) : (
        <p>{ends} ({bridgePortText(b)})를 끊습니다. ‘끊는 중’이 되고 기존 접속이 끊기며, 모든 서버가 확인하면 목록에서 사라집니다. 다시 이으려면 새로 만들어야 합니다.</p>
      )}
      {err ? <div className="note wa">{err}</div> : <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

/** 다른 작업 공간의 브릿지 받기 켜기·끄기 (set-network-toggle bridge-inbound) */
export function InboundDialog({ tenant, net, bridges, onClose, onDone }: { tenant: string; net: NetworkView; bridges: BridgeView[]; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const on = inboundOn(net);
  const cross = bridges.filter((b) => b.b.tenant === tenant && b.b.network === net.name && b.a.tenant !== tenant);
  const waiting = cross.filter((b) => b.phase === 'pending');
  const open = cross.filter((b) => b.phase === 'open');
  return (
    <Dialog
      title={on ? `${net.name}${iGa(net.name)} 다른 작업 공간의 브릿지를 받지 않게 할까요?` : `${net.name}${iGa(net.name)} 다른 작업 공간의 브릿지를 받게 할까요?`}
      width={420}
      onClose={onClose}
      footer={
        m.op ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button type="button" className="btn primary" disabled={m.busy} onClick={() => void m.run(`${networkPath(tenant, net.name)}/toggles`, { toggle: 'bridge-inbound', on: !on }).then((o) => o?.state === 'applied' && (onDone(), onClose()))}>
              {on ? '끄기' : '켜기'}
            </button>
          </>
        )
      }
    >
      {on ? (
        <>
          <p style={{ margin: 0 }}>다른 작업 공간이 {net.name}에 새 브릿지를 요청할 수 없게 됩니다.</p>
          <p className="small" style={{ margin: 0 }}>
            {waiting.length ? `승인 대기 중인 ${waiting.map(bridgeEnds).join(', ')}는 끄는 동안 승인할 수 없습니다. 필요 없으면 거절하세요. ` : ''}
            {open.length ? `이어진 다른 작업 공간 브릿지 ${open.length}개는 어느 쪽이 끊을 때까지 그대로입니다.` : '이어진 다른 작업 공간 브릿지는 없습니다.'}
          </p>
        </>
      ) : (
        <p style={{ margin: 0 }}>켜면 다른 작업 공간의 가상 브릿지 만들기 창에 {net.name}{iGa(net.name)} 나옵니다. 상대가 요청하면 ‘내 승인 필요’로 들어오고, 승인해야 이어집니다. 상대에게는 망 이름만 보이고 CIDR은 보이지 않습니다.</p>
      )}
      <MutationError error={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && (onDone(), onClose()))} />}
    </Dialog>
  );
}
