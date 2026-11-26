// SPDX-License-Identifier: Apache-2.0

// 작업 공간 간 연결 (UI-53). mydcd의 propose-route / approve-route / withdraw-route.
// 계약: docs/reference/web-api.md "작업 공간 간 연결 (UI-53)"
import { useState } from 'react';
import { ApiError } from '../api/client';
import { routeEndpoints, routePath, routes } from '../api/endpoints';
import type { DRoute } from '../api/dto';
import type { NetworkView, OpView } from '../api/types';
import { Badge, Card, Field } from '../components/ui';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';

type Route = Omit<DRoute, 'ports' | 'approvals'> & { ports: { first: number; last: number }[]; approvals: { tenant: string; user?: string }[] };

const portText = (r: Route) => `${r.protocol} ${r.ports.map((p) => (p.first === p.last ? `${p.first}` : `${p.first}-${p.last}`)).join(', ')}`;
const end = (e: { tenant: string; network: string; name?: string }) => `${e.tenant}/${e.name ?? e.network}`;

/** 승인 칸: 데몬이 이 작업 공간 기준으로 정한 state */
const STATE: Record<Route['state'], [string, 'ok' | 'pr' | 'wa']> = {
  active: ['양측 승인 · 활성', 'ok'],
  'waiting-peer': ['상대 승인 대기', 'pr'],
  'waiting-me': ['내 승인 대기', 'wa'],
  revoking: ['무효화 중', 'wa'],
};
function approval(r: Route) {
  const [label, tone] = STATE[r.state] ?? [r.phase, 'pr'];
  return <Badge tone={tone}>{label}</Badge>;
}

const ERR: Record<string, string> = {
  'already-approved': '이 작업 공간은 이미 승인했습니다.',
  revoking: '철회 중인 연결입니다.',
  'node-required': '보내는 쪽 망이 여러 서버에 있습니다. 보내는 쪽 서버를 고르세요.',
  'destination-node-required': '받는 쪽 망이 여러 서버에 있습니다. 받는 쪽 서버를 고르세요.',
  'destination-pool-required': '받는 쪽 서버에 주소 묶음이 여럿 있습니다. 주소 묶음을 고르세요.',
  'destination-not-open': '받는 쪽 작업 공간이 이 망을 연결용으로 열지 않았습니다. 그 작업 공간 관리자에게 열어 달라고 하세요.',
};
const RouteErr = ({ e }: { e: unknown }) => (e === undefined ? null : e instanceof ApiError && ERR[e.code] ? <div className="note wa">{ERR[e.code]}</div> : <MutationError error={e} />);

export function RoutesCard({ tenant, nets, canDeploy }: { tenant: string; nets: NetworkView[]; canDeploy: boolean }) {
  const q = usePoll((s) => routes(tenant, s), [tenant]);
  const [sel, setSel] = useState<string>();
  const [dlg, setDlg] = useState<'propose' | 'approve' | 'withdraw'>();
  const rows: Route[] = q.data?.items ?? [];
  const cur = rows.find((r) => r.key === sel);
  const need = canDeploy ? undefined : '작업 공간 관리자 권한 필요';
  const canApprove = cur?.state === 'waiting-me';
  const canWithdraw = !!cur && cur.phase !== 'revoking';
  return (
    <Card
      title="작업 공간 간 연결 (UI-53)"
      actions={
        <button className="btn primary" disabled={!canDeploy || !q.data} title={need} onClick={() => setDlg('propose')}>
          연결 제안
        </button>
      }
    >
      {q.error ? (
        <MutationError error={q.error} />
      ) : rows.length === 0 ? (
        <span className="small muted">{q.data ? '연결이 없습니다.' : '불러오는 중…'}</span>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>보내는 쪽</th>
                <th>받는 쪽</th>
                <th>포트</th>
                <th>승인</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.key} className={r.key === sel ? 'selected' : undefined} onClick={() => setSel(r.key)} style={{ cursor: 'pointer' }} aria-selected={r.key === sel}>
                  <td className="mono">{end(r.source)}</td>
                  <td className="mono">{end(r.destination)}</td>
                  <td>{portText(r)}</td>
                  <td>{approval(r)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <span className="small muted">상대 작업 공간이 승인해야 개통됩니다. 관리자도 양쪽을 따로 승인합니다. 철회는 무효화 중으로 남고 기존 접속 종료 뒤 정리됩니다.</span>
      <div className="row">
        <button className="btn" disabled={!canApprove || !canDeploy} title={need ?? (cur ? undefined : '연결을 먼저 고르세요')} onClick={() => setDlg('approve')}>
          승인
        </button>
        <button className="btn danger" disabled={!canWithdraw || !canDeploy} title={need ?? (cur ? undefined : '연결을 먼저 고르세요')} onClick={() => setDlg('withdraw')}>
          철회
        </button>
      </div>
      {dlg === 'propose' && q.data && <ProposeDialog tenant={tenant} nets={nets} networksRevision={q.data.networksRevision} onClose={() => setDlg(undefined)} onDone={() => void q.refresh()} />}
      {(dlg === 'approve' || dlg === 'withdraw') && cur && <RouteActionDialog kind={dlg} tenant={tenant} r={cur} onClose={() => setDlg(undefined)} onDone={() => void q.refresh()} />}
    </Card>
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
  const [src, setSrc] = useState(nets[0]?.name ?? '');
  const [srcNode, setSrcNode] = useState('');
  const [dst, setDst] = useState('');
  const [dstNode, setDstNode] = useState('');
  const [pool, setPool] = useState('');
  const [proto, setProto] = useState<'tcp' | 'udp'>('tcp');
  const [ports, setPorts] = useState('');
  // 처음 보낸 본문을 고정한다(같은 opId로 다시 보낼 때 같아야 한다). 서버 칸을 더 채워 다시 보내면 새 opId
  const [sent, setSent] = useState<Record<string, unknown>>();
  const [dt, dn] = dst.split('/');
  const pr = parsePorts(ports);
  // 받는 쪽 작업 공간이 연결용으로 연 망. 못 읽으면(403 등) 직접 넣는다
  const dtOk = !!dt && NAME.test(dt) && dt !== tenant;
  const eq = usePoll((s) => (dtOk ? routeEndpoints(tenant, dt, s).catch(() => undefined) : Promise.resolve(undefined)), [tenant, dtOk ? dt : '']);
  const open = eq.data;
  const openNets = [...new Set((open ?? []).map((x) => x.network))];
  const here = (open ?? []).filter((x) => x.network === dn);
  const hereNodes = [...new Set(here.map((x) => x.node))];
  const herePools = [...new Set(here.filter((x) => !dstNode || x.node === dstNode).map((x) => x.pool))];
  const net = nets.find((n) => n.name === src);
  const srcNodes = net ? (net.members.length ? net.members.map((x) => x.node) : net.nodes) : [];
  const code = m.error instanceof ApiError ? m.error.code : '';
  const askSrcNode = srcNodes.length > 1;
  // 받는 쪽 서버·묶음: 연 망 목록에서 여럿이면 고르고, 목록을 못 읽었는데 데몬이 물으면 직접 넣는다
  const pickDst = hereNodes.length > 1 || new Set(here.map((x) => `${x.node}/${x.pool}`)).size > hereNodes.length;
  const askDstNode = pickDst || code === 'destination-node-required' || code === 'destination-pool-required' || !!dstNode || !!pool;
  const needNode = hereNodes.length > 1 || code === 'destination-node-required';
  const needPool = herePools.length > 1 || code === 'destination-pool-required';
  const dstErr = dst && !(dst.split('/').length === 2 && NAME.test(dt ?? '') && NAME.test(dn ?? '')) ? '작업 공간/망 모양으로 씁니다 (예: analytics/ingest).' : dt === tenant ? '같은 작업 공간끼리는 연결이 필요 없습니다.' : undefined;
  const portErr = ports && !pr ? '1~65535 사이 포트나 범위(8000-8010)를 쉼표로 씁니다.' : undefined;
  const nodeErr = dstNode && !NAME.test(dstNode) ? '서버 이름을 씁니다.' : pool && !NAME.test(pool) ? '주소 묶음 이름을 씁니다.' : undefined;
  const ready = !!src && !!dst && !dstErr && !!pr && !nodeErr && (!askSrcNode || !!srcNode) && (!needNode || !!dstNode) && (!needPool || !!pool);
  const body = () => ({
    source: { network: src, ...(srcNode ? { node: srcNode } : {}) },
    destination: { tenant: dt, network: dn, ...(dstNode ? { node: dstNode } : {}), ...(pool ? { pool } : {}) },
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
      title="작업 공간 간 연결 제안"
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
      <div className={askSrcNode ? 'g2' : undefined}>
        <Field label="보내는 쪽">
          <select value={src} onChange={(e) => (setSrc(e.target.value), setSrcNode(''))}>
            {nets.length === 0 && <option value="">망이 없습니다</option>}
            {nets.map((n) => (
              <option key={n.key} value={n.name}>
                {tenant}/{n.name}
              </option>
            ))}
          </select>
        </Field>
        {askSrcNode && (
          <Field label="보내는 쪽 서버">
            <select value={srcNode} onChange={(e) => setSrcNode(e.target.value)}>
              <option value="">고르세요</option>
              {srcNodes.map((x) => (
                <option key={x} value={x}>
                  {x}
                </option>
              ))}
            </select>
          </Field>
        )}
      </div>
      <Field label="받는 쪽 작업 공간 · 망" error={dstErr} hint={dtOk && open ? (openNets.length ? `${dt}이 연 망: ${openNets.join(', ')}` : `${dt}이 연결용으로 연 망이 없습니다`) : undefined}>
        <input className="mono" list="route-dst" value={dst} onChange={(e) => (setDst(e.target.value.trim()), setDstNode(''), setPool(''))} placeholder="analytics/ingest" />
        <datalist id="route-dst">
          {openNets.map((n) => (
            <option key={n} value={`${dt}/${n}`} />
          ))}
        </datalist>
      </Field>
      {askDstNode && (
        <div className="g2">
          <Field label="받는 쪽 서버" error={nodeErr} hint={needNode ? '받는 쪽 망이 있는 서버' : '선택'}>
            {hereNodes.length > 0 ? (
              <select value={dstNode} onChange={(e) => (setDstNode(e.target.value), setPool(''))}>
                <option value="">{needNode ? '고르세요' : '데몬이 고름'}</option>
                {hereNodes.map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </select>
            ) : (
              <input className="mono" value={dstNode} onChange={(e) => setDstNode(e.target.value.trim())} placeholder="node-b" />
            )}
          </Field>
          <Field label={needPool ? '주소 묶음' : '주소 묶음 (선택)'} hint={needPool ? undefined : '비우면 main'}>
            {herePools.length > 0 ? (
              <select value={pool} onChange={(e) => setPool(e.target.value)}>
                <option value="">{needPool ? '고르세요' : '기본'}</option>
                {herePools.map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </select>
            ) : (
              <input className="mono" value={pool} onChange={(e) => setPool(e.target.value.trim())} placeholder="main" />
            )}
          </Field>
        </div>
      )}
      <div className="g2">
        <Field label="프로토콜">
          <select value={proto} onChange={(e) => setProto(e.target.value as 'tcp' | 'udp')}>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
          </select>
        </Field>
        <Field label="포트" error={portErr}>
          <input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="443" />
        </Field>
      </div>
      <p className="small muted">받는 쪽 작업 공간 관리자가 승인해야 개통됩니다. 보내는 쪽도 제안 뒤 따로 승인합니다.</p>
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
      width={400}
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
        <p>{portText(r)} 연결이 무효화 중으로 바뀌고 기존 접속이 끊깁니다. 다시 열려면 새로 제안해야 합니다.</p>
      ) : (
        <p>
          {end(r.source)}에서 {end(r.destination)}의 {portText(r)}로 접속을 허락합니다. {r.approvals.some((a) => a.tenant === other) ? '상대도 승인했으므로 바로 개통됩니다.' : `${other}도 승인해야 개통됩니다.`}
        </p>
      )}
      <RouteErr e={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}
