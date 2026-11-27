// SPDX-License-Identifier: Apache-2.0

// 작업 공간 간 연결 (UI-53). sfcd의 propose-route / approve-route / withdraw-route.
// 계약: docs/reference/web-api.md "작업 공간 간 연결 (UI-53)"
import { useState } from 'react';
import { ApiError } from '../api/client';
import { routeEndpoints, routePath, routes, tenantList } from '../api/endpoints';
import type { DRoute } from '../api/dto';
import type { NetworkView, OpView } from '../api/types';
import { Badge, Field } from '../components/ui';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';

export type Route = Omit<DRoute, 'ports' | 'approvals'> & { ports: { first: number; last: number }[]; approvals: { tenant: string; user?: string }[] };

const portText = (r: Route) => `${r.protocol} ${r.ports.map((p) => (p.first === p.last ? `${p.first}` : `${p.first}-${p.last}`)).join(', ')}`;
const end = (e: { tenant: string; network: string; name?: string }) => `${e.tenant}/${e.name ?? e.network}`;

const ERR: Record<string, string> = {
  'already-approved': '이 작업 공간은 이미 승인했습니다.',
  revoking: '철회 중인 연결입니다.',
  'node-required': '보내는 쪽 망이 여러 서버에 있습니다. 보내는 쪽 서버를 고르세요.',
  'destination-node-required': '받는 쪽 망이 여러 서버에 있습니다. 받는 쪽 서버를 고르세요.',
  'destination-pool-required': '받는 쪽 서버에 주소 묶음이 여럿 있습니다. 주소 묶음을 고르세요.',
  'destination-not-open': '받는 쪽 작업 공간이 이 망을 연결용으로 열지 않았습니다. 그 작업 공간 관리자에게 열어 달라고 하세요.',
};
/** 전체 목록(UI-53 화면)의 상태 배지 */
const STATE_FULL: Record<Route['state'], [string, 'ok' | 'pr' | 'wa' | 'un']> = {
  active: ['열림', 'ok'],
  'waiting-peer': ['상대 승인 대기', 'pr'],
  'waiting-me': ['내 승인 필요', 'wa'],
  revoking: ['닫는 중', 'un'],
};

const RouteErr = ({ e }: { e: unknown }) => (e === undefined ? null : e instanceof ApiError && ERR[e.code] ? <div className="note wa">{ERR[e.code]}</div> : <MutationError error={e} />);

/** 연결 목록 읽기. 탭 줄 숫자와 연결 탭이 함께 쓴다 */
export const useRoutes = (tenant: string) => usePoll((s) => (tenant ? routes(tenant, s) : Promise.resolve({ items: [], networksRevision: 0 })), [tenant]);
export type RoutesQ = ReturnType<typeof useRoutes>;

/** 한쪽 끝: 작업 공간/망, 그 아래 서버 · CIDR. 이 작업 공간 쪽에 배지 */
function EndCell({ e, tenant }: { e: Route['source']; tenant: string }) {
  return (
    <span className="col" style={{ gap: 2 }}>
      <span className="mono">
        {end(e)}
        {e.tenant === tenant && (
          <>
            {' '}
            <span className="badge pr" style={{ fontSize: 11, padding: '0 6px' }}>
              이 작업 공간
            </span>
          </>
        )}
      </span>
      <span className="muted" style={{ fontSize: 12 }}>
        {/* 상대 작업 공간 망의 CIDR은 보이지 않는다(캔버스 v196) */}
        {[e.node, e.tenant === tenant ? e.cidr : undefined].filter(Boolean).join(' · ')}
      </span>
    </span>
  );
}

/** 승인 칸: 양쪽 작업 공간마다 ✓ 승인한 사람, 또는 기다림 */
function ApprovalCell({ r, tenant }: { r: Route; tenant: string }) {
  if (r.state === 'revoking') return <span className="muted" style={{ fontSize: 12 }}>철회됨</span>;
  return (
    <span className="col" style={{ gap: 2, fontSize: 12 }}>
      {[r.source.tenant, r.destination.tenant].map((t) => {
        const a = r.approvals.find((x) => x.tenant === t);
        if (a) return <span key={t}>✓ {t}{a.user ? ` · ${a.user}` : ''}</span>;
        return t === tenant ? (
          <span key={t} style={{ color: 'var(--wa)' }}>… {t} 승인 필요</span>
        ) : (
          <span key={t} className="muted">… {t} 대기</span>
        );
      })}
    </span>
  );
}

/** 작업 공간 간 연결 전체 목록 (UI-53 화면) */
export function RoutesTable({ tenant, nets, canDeploy, q, proposing, onProposeClose }: { tenant: string; nets: NetworkView[]; canDeploy: boolean; q: RoutesQ; proposing: boolean; onProposeClose: () => void }) {
  const [text, setText] = useState('');
  const [dir, setDir] = useState<'' | 'source' | 'destination'>('');
  const [st, setSt] = useState<'' | Route['state']>('');
  const [act, setAct] = useState<{ kind: 'approve' | 'withdraw'; r: Route }>();
  const need = canDeploy ? undefined : '작업 공간 관리자 권한 필요';
  const all: Route[] = q.data?.items ?? [];
  const needle = text.trim().toLowerCase();
  const rows = all.filter(
    (r) =>
      (!dir || r.side === dir) &&
      (!st || r.state === st) &&
      (!needle || [r.id, r.source.tenant, r.destination.tenant, end(r.source), end(r.destination)].some((x) => x.toLowerCase().includes(needle))),
  );
  return (
    <>
      <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
        <input placeholder="연결 이름·작업 공간 검색" aria-label="연결 이름·작업 공간 검색" value={text} onChange={(e) => setText(e.target.value)} style={{ flexGrow: 1 }} />
        <select aria-label="방향" value={dir} onChange={(e) => setDir(e.target.value as typeof dir)}>
          <option value="">방향: 전체</option>
          <option value="source">나가는 연결</option>
          <option value="destination">들어오는 연결</option>
        </select>
        <select aria-label="상태" value={st} onChange={(e) => setSt(e.target.value as typeof st)}>
          <option value="">상태: 전체</option>
          <option value="waiting-me">내 승인 필요</option>
          <option value="waiting-peer">상대 승인 대기</option>
          <option value="active">열림</option>
          <option value="revoking">닫는 중</option>
        </select>
      </div>
      {q.error ? (
        <MutationError error={q.error} />
      ) : !q.data ? (
        <span className="small muted">불러오는 중…</span>
      ) : rows.length === 0 ? (
        <span className="small muted">{all.length ? '조건에 맞는 연결이 없습니다.' : '연결이 없습니다.'}</span>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl" style={{ minWidth: 860 }}>
            <thead>
              <tr>
                <th>이름</th>
                <th>보내는 쪽</th>
                <th>받는 쪽</th>
                <th>포트</th>
                <th>승인</th>
                <th>상태</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const [label, tone] = STATE_FULL[r.state] ?? [r.phase, 'pr'];
                return (
                  <tr key={r.key} style={r.state === 'waiting-me' ? { background: 'var(--wa-soft)' } : undefined}>
                    <td style={{ fontWeight: 600 }}>{r.id}</td>
                    <td className="wrap">
                      <EndCell e={r.source} tenant={tenant} />
                    </td>
                    <td className="wrap">
                      <EndCell e={r.destination} tenant={tenant} />
                    </td>
                    <td className="mono">{portText(r)}</td>
                    <td className="wrap">
                      <ApprovalCell r={r} tenant={tenant} />
                    </td>
                    <td className="wrap">
                      {r.state === 'revoking' ? (
                        <span className="col" style={{ gap: 2 }}>
                          <Badge tone={tone}>{label}</Badge>
                          <span className="muted" style={{ fontSize: 11 }}>양쪽 서버 닫힘 확인 대기</span>
                        </span>
                      ) : (
                        <Badge tone={tone}>{label}</Badge>
                      )}
                    </td>
                    <td>
                      <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                        {r.state === 'waiting-me' && (
                          <button className="btn sm primary" disabled={!canDeploy} title={need} onClick={() => setAct({ kind: 'approve', r })}>
                            승인
                          </button>
                        )}
                        {r.phase !== 'revoking' && (
                          <button className="btn sm danger" disabled={!canDeploy} title={need} onClick={() => setAct({ kind: 'withdraw', r })}>
                            철회…
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
      <span className="small muted">연결은 서버 한 대의 망 주소 묶음끼리 잇습니다. 망이 여러 서버에 있으면 어느 서버 쪽을 이을지 고릅니다. 받는 쪽은 그 작업 공간이 연결을 받도록 연 망만 고를 수 있습니다. 철회하면 양쪽 서버가 닫았다고 보고한 뒤 목록에서 사라집니다.</span>
      {proposing && q.data && <ProposeDialog tenant={tenant} nets={nets} networksRevision={q.data.networksRevision} onClose={onProposeClose} onDone={() => void q.refresh()} />}
      {act && <RouteActionDialog kind={act.kind} tenant={tenant} r={act.r} onClose={() => setAct(undefined)} onDone={() => void q.refresh()} />}
    </>
  );
}

const NAME = /^[a-z0-9][a-z0-9-]*$/;
/** "443", "8000-8010", "80, 443" → 범위 목록 */
export function parsePorts(s: string): { first: number; last: number }[] | undefined {
  const parts = s.split(/[,\s]+/).filter(Boolean);
  if (parts.length === 0 || parts.length > 16) return undefined;
  const out: { first: number; last: number }[] = [];
  for (const p of parts) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(p);
    if (!m) return undefined;
    const first = Number(m[1]);
    const last = m[2] ? Number(m[2]) : first;
    if (first < 1 || last > 65535 || last < first) return undefined;
    out.push({ first, last });
  }
  return out;
}

function ProposeDialog({ tenant, nets, networksRevision, onClose, onDone }: { tenant: string; nets: NetworkView[]; networksRevision: number; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const [id, setId] = useState('');
  const [src, setSrc] = useState(nets[0]?.name ?? '');
  const [srcNode, setSrcNode] = useState('');
  const [dt, setDt] = useState('');
  // 받는 쪽 끝점: "망/서버/묶음"
  const [dstKey, setDstKey] = useState('');
  const [proto, setProto] = useState<'tcp' | 'udp'>('tcp');
  const [ports, setPorts] = useState('');
  // 처음 보낸 본문을 고정한다(같은 opId로 다시 보낼 때 같아야 한다). 고쳐 다시 보내면 새 opId
  const [sent, setSent] = useState<Record<string, unknown>>();
  const pr = parsePorts(ports);
  // 받는 작업 공간 후보: 내가 보는 다른 작업 공간. 목록에 없는 곳은 직접 쓴다
  const tq = usePoll((s) => tenantList(s).catch(() => []), []);
  const others = (tq.data ?? []).map((x) => x.id).filter((x) => x !== tenant);
  const dtOk = !!dt && NAME.test(dt) && dt !== tenant;
  const eq = usePoll((s) => (dtOk ? routeEndpoints(tenant, dt, s) : Promise.resolve(undefined)), [tenant, dtOk ? dt : '']);
  const open = eq.data ?? [];
  const pools = (n: string, node: string) => open.filter((x) => x.network === n && x.node === node).length;
  const dstOf = (k: string) => open.find((x) => `${x.network}/${x.node}/${x.pool}` === k);
  const dst = dstOf(dstKey);
  const net = nets.find((n) => n.name === src);
  const members = net ? (net.members.length ? net.members.map((x) => ({ node: x.node, cidr: x.cidr })) : net.nodes.map((node) => ({ node, cidr: '' }))) : [];
  const askSrcNode = members.length > 1;
  const idErr = id && !NAME.test(id) ? '영문 소문자, 숫자, -로 씁니다.' : undefined;
  const dtErr = dt && !NAME.test(dt) ? '작업 공간 이름을 씁니다.' : dt === tenant ? '같은 작업 공간끼리는 연결이 필요 없습니다.' : undefined;
  const portErr = ports && !pr ? '1~65535 사이 포트나 범위(8000-8010)를 쉼표로 씁니다.' : undefined;
  const dstHint = !dtOk ? '받는 작업 공간을 먼저 고르세요' : eq.error ? undefined : eq.data && open.length === 0 ? `${dt}이 연결을 받도록 연 망이 없습니다` : `${dt}이 연결을 받도록 연 망만 나옵니다`;
  const ready = !!id && !idErr && !!src && (!askSrcNode || !!srcNode) && dtOk && !!dst && !!pr;
  const body = () => ({
    id,
    source: { network: src, ...(srcNode ? { node: srcNode } : {}) },
    destination: { tenant: dt, network: dst?.network, node: dst?.node, ...(dst && pools(dst.network, dst.node) > 1 ? { pool: dst.pool } : {}) },
    protocol: proto,
    ports: pr,
    expected: networksRevision,
  });
  const go = () => {
    const next = body();
    // 고친 본문은 새 작업으로 보낸다(같은 opId에 다른 본문은 op-conflict)
    if (sent && JSON.stringify(sent) !== JSON.stringify(next)) m.reset();
    setSent(next);
    void m.run(routePath(tenant), next).then((o) => o?.state === 'applied' && onDone());
  };
  return (
    <Dialog
      title="연결 제안"
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
            <button className="btn primary" disabled={!ready || m.busy} onClick={go}>
              제안 보내기
            </button>
          </>
        )
      }
    >
      <Field label="이름" error={idErr}>
        <input className="mono" value={id} onChange={(e) => setId(e.target.value.trim())} placeholder="to-search" />
      </Field>
      <Field label={`보내는 쪽 망 (${tenant})`}>
        <select value={src} onChange={(e) => (setSrc(e.target.value), setSrcNode(''))}>
          {nets.length === 0 && <option value="">망이 없습니다</option>}
          {nets.map((n) => (
            <option key={n.key} value={n.name}>
              {n.name}
            </option>
          ))}
        </select>
      </Field>
      {askSrcNode && (
        <Field label="서버" hint="망이 여러 서버에 있어 골라야 합니다">
          <select value={srcNode} onChange={(e) => setSrcNode(e.target.value)}>
            <option value="">고르세요</option>
            {members.map((x) => (
              <option key={x.node} value={x.node}>
                {[x.node, x.cidr].filter(Boolean).join(' · ')}
              </option>
            ))}
          </select>
        </Field>
      )}
      <Field label="받는 작업 공간" error={dtErr}>
        <input className="mono" list="route-dst-tenant" value={dt} onChange={(e) => (setDt(e.target.value.trim()), setDstKey(''))} placeholder="search" />
        <datalist id="route-dst-tenant">
          {others.map((x) => (
            <option key={x} value={x} />
          ))}
        </datalist>
      </Field>
      <Field label="받는 쪽 망 · 서버" hint={dstHint} error={eq.error ? <MutationError error={eq.error} /> : undefined}>
        <select value={dstKey} onChange={(e) => setDstKey(e.target.value)} disabled={!dtOk || open.length === 0}>
          <option value="">{dtOk && eq.data && open.length === 0 ? '고를 망이 없습니다' : '고르세요'}</option>
          {open.map((x) => {
            const k = `${x.network}/${x.node}/${x.pool}`;
            return (
              <option key={k} value={k}>
                {x.network} · {x.node}
                {pools(x.network, x.node) > 1 ? ` · ${x.pool}` : ''}
              </option>
            );
          })}
        </select>
      </Field>
      <div style={{ display: 'grid', gridTemplateColumns: '100px 1fr', gap: 8 }}>
        <Field label="프로토콜">
          <select value={proto} onChange={(e) => setProto(e.target.value as 'tcp' | 'udp')}>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
          </select>
        </Field>
        <Field label="포트" error={portErr}>
          <input className="mono" value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="9200, 9300-9400" />
        </Field>
      </div>
      <p className="small muted">보내면 {tenant} 쪽도 승인해야 하고, {dtOk ? dt : '받는 작업 공간'} 관리자가 승인하면 열립니다.</p>
      <RouteErr e={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

function RouteActionDialog({ kind, tenant, r, onClose, onDone }: { kind: 'approve' | 'withdraw'; tenant: string; r: Route; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  // 창을 연 때의 연결 revision을 고정해 expected로 보낸다(그 사이 바뀌었으면 막힌다)
  const [expected] = useState(r.revision);
  const other = r.source.tenant === tenant ? r.destination.tenant : r.source.tenant;
  const withdraw = kind === 'withdraw';
  return (
    <Dialog
      title={withdraw ? `${r.source.tenant} → ${r.destination.tenant} 연결을 철회할까요?` : `${r.source.tenant} → ${r.destination.tenant} 연결을 승인할까요?`}
      danger={withdraw}
      width={420}
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
            <button className={withdraw ? 'btn danger solid' : 'btn primary'} disabled={m.busy} onClick={() => void m.run(`${routePath(tenant, r)}/${kind}`, { expected }).then((o) => o?.state === 'applied' && onDone())}>
              {withdraw ? '철회' : '승인'}
            </button>
          </>
        )
      }
    >
      {withdraw ? (
        <p>{portText(r)} 연결을 닫습니다. 기존 접속이 끊기고, 양쪽 서버가 닫았다고 보고하면 목록에서 사라집니다. 다시 열려면 새로 제안해야 합니다.</p>
      ) : (
        <p>
          {end(r.source)}에서 {end(r.destination)}의 {portText(r)}로 접속을 허락합니다. {r.approvals.some((a) => a.tenant === other) ? '상대도 승인했으므로 바로 열립니다.' : `${other}도 승인해야 열립니다.`}
        </p>
      )}
      <RouteErr e={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}
