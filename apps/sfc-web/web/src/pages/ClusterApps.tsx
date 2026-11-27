// SPDX-License-Identifier: Apache-2.0

// 서버 › 클러스터 앱 (캔버스 ClusterApps v202, UI-12A). 시스템 관리자만, 보기만.
// 서버 요약(GET /nodes/summary)의 서버별 클러스터 앱을 앱 이름으로 모은다. 같은 앱은 클러스터에서 한 서버에서만 돈다.
import { Link } from 'react-router-dom';
import { nodesOverview } from '../api/endpoints';
import type { DClusterApp } from '../api/dto';
import type { NodeView } from '../api/types';
import { Badge, Card, HelpBox, PageHeader, type Tone } from '../components/ui';
import { Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { CLUSTER_APP_STATE, ClusterAppAddress, ClusterAppImage, clusterAppNote, refusedBy } from '../components/clusterApps';
import { SERVER_TABS } from './Servers';

/** 앱 하나: 켠 서버마다의 행과, 실제로 도는 서버 */
export interface ClusterAppRow {
  name: string;
  /** 도는 서버의 행(없으면 켠 서버 중 첫 행) */
  main: DClusterApp & { node: string; stale?: boolean };
  running?: string;
  enabled: (DClusterApp & { node: string; stale?: boolean })[];
}

const LIVE = new Set(['running', 'starting', 'restarting', 'stopping']);

export function groupClusterApps(nodes: Pick<NodeView, 'id' | 'stale' | 'clusterApps'>[]): ClusterAppRow[] {
  const by = new Map<string, ClusterAppRow['enabled']>();
  for (const n of nodes) for (const a of n.clusterApps ?? []) by.set(a.name, [...(by.get(a.name) ?? []), { ...a, node: n.id, stale: n.stale }]);
  return [...by.entries()]
    .map(([name, xs]) => {
      const enabled = [...xs].sort((a, b) => a.node.localeCompare(b.node));
      const run = enabled.find((x) => LIVE.has(x.state));
      return { name, main: run ?? enabled[0], running: run?.node, enabled };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

const stateOf = (x: { state: string; stale?: boolean }): [Tone, string] => (x.stale ? ['un', '확인 불가 (보고 늦음)'] : CLUSTER_APP_STATE[x.state] ?? ['un', x.state]);

export function ClusterAppsPage() {
  const q = usePoll((s) => nodesOverview(s), [], DEFAULT_POLL_MS);
  return (
    <>
      <PageHeader title="서버" ids="UI-12A" actions={<Refresh q={q} />} />
      <Tabs label="서버 탭" items={SERVER_TABS} />
      <HelpBox terms="클러스터 앱 (cluster app) · 클러스터 앱 이미지 (cluster app image) · 거부됨 (이미 다른 서버에서 실행 중)">
        <b>이 화면은</b> 클러스터 전체의 클러스터 앱을 보여 줍니다. 클러스터 앱은 sfcd에 들어 있는 이미지로 띄우는 클러스터 공용 앱(웹 앱 sfc-web 등)이고, 같은 앱은 클러스터에서 한 서버에서만 돕니다. 서버마다 node.yaml로 켜고 끄며, 다른 서버에서 이미 돌고 있으면 켠 서버는 거부됩니다. 웹과 CLI에서는 보기만 합니다. 시스템 관리자만 봅니다.
      </HelpBox>
      <Card>
        <Load q={q} what="클러스터 앱을 불러오지 못했습니다">
          {(o) => {
            const rows = groupClusterApps(o.nodes);
            if (!rows.length) return <span className="small muted">켠 클러스터 앱이 없습니다.</span>;
            return (
              <div style={{ overflowX: 'auto' }}>
                <table className="tbl" style={{ minWidth: 900 }}>
                  <thead>
                    <tr>
                      <th>앱</th>
                      <th>클러스터 앱 이미지</th>
                      <th>도는 서버</th>
                      <th>상태</th>
                      <th>주소</th>
                      <th>켠 서버 (node.yaml)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => {
                      const [tone, label] = stateOf(r.main);
                      const note = clusterAppNote(r.name);
                      return (
                        <tr key={r.name}>
                          <td>
                            <span className="col" style={{ gap: 2 }}>
                              <b>{r.name}</b>
                              {note && <span className="muted" style={{ fontSize: 11 }}>{note}</span>}
                            </span>
                          </td>
                          <td>
                            <ClusterAppImage a={r.main} />
                          </td>
                          <td>{r.running ? <Link to={`/servers/${encodeURIComponent(r.running)}/containers`}>{r.running}</Link> : '—'}</td>
                          <td>
                            <Badge tone={tone}>{label}</Badge>
                          </td>
                          <td style={{ fontSize: 12 }}>{r.main.address || r.main.ports?.length ? <ClusterAppAddress a={r.main} /> : '—'}</td>
                          <td className="wrap">
                            <span className="col" style={{ gap: 2, fontSize: 12 }}>
                              {r.enabled.map((x) => {
                                const [t, l] = stateOf(x);
                                return (
                                  <span key={x.node} style={t === 'er' ? { color: 'var(--er)' } : undefined}>
                                    <Link to={`/servers/${encodeURIComponent(x.node)}/containers`}>{x.node}</Link> · {l}
                                    {!x.stale && refusedBy(x) && ` (이미 ${refusedBy(x)}에서 실행 중)`}
                                  </span>
                                );
                              })}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            );
          }}
        </Load>
        <span className="small muted">
          상태: 실행 중 · 시작 중 · 이미지 없음 · 이미지 불일치 · 멈춤 · 거부됨. 켠 서버가 둘 이상이면 먼저 띄운 서버만 돌고 나머지는 ‘거부됨’으로 남습니다. 도는 서버를 바꾸려면 그 서버의 node.yaml에서 끄고 다른 서버를 다시 시작합니다. 아무 서버에서도 켜지 않은 앱은 목록에 나오지 않습니다.
        </span>
      </Card>
    </>
  );
}
