// SPDX-License-Identifier: Apache-2.0

// 배포 › 앱 › 배치 탭 (UI-38, 캔버스 Relocate · RelocateIx).
// 데이터 저장소가 없는 서비스: app.yaml의 services.{svc}.x-sfc.node만 바꾼 새 버전을 배포 경로(검사 → 미리보기 → 제출)로 올린다.
// 데이터 저장소를 쓰는 서비스: 데이터 저장소 옮기기(UI-64, 계약 #69)로 보낸다. 데몬이 앱 정의에 새 서버를 적고 데이터와 함께 옮긴다.
// 옮기기 전 검사는 relocation-check로 서버마다 읽는다. 하나라도 걸리면 보내지 않는다.
// 여러 서버 복제본은 sfcd 기능이 없어 보여 주기만 한다.
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import YAML from 'yaml';
import { ApiError } from '../api/client';
import { appTasks, dashboard, relocationCheck, volumes as fetchVolumes } from '../api/endpoints';
import type { DRelocationCheck } from '../api/dto';
import type { AppView, VolumeView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Badge, Card, HelpBox } from '../components/ui';
import { Empty } from '../components/states';
import { DEFAULT_POLL_MS, usePoll } from '../lib/usePoll';
import { fmtBytes } from '../lib/format';
import { DeployFlow } from './DeployFlow';
import { MoveDialog } from './VolumeMove';
import { appLive, volumesLive } from '../lib/liveTopics';

export interface PlaceService {
  name: string;
  node: string;
  replicas: number;
  volumes: string[];
}

/** services.{svc}.x-sfc.node만 바꾼 원문. 다른 줄과 주석은 그대로 둔다 */
export function withNodes(text: string, to: Record<string, string>): string {
  const doc = YAML.parseDocument(text);
  for (const [svc, node] of Object.entries(to)) doc.setIn(['services', svc, 'x-sfc', 'node'], node);
  return doc.toString({ flowCollectionPadding: false });
}

export function PlacementTab({ a, current, services }: { a: AppView; current?: string; services?: PlaceService[] }) {
  const { canDeploy } = useTenantRole();
  const dash = usePoll((s) => dashboard(a.tenant, s), [a.tenant]);
  const vols = usePoll((s) => fetchVolumes(a.tenant, s), [a.tenant], 0, volumesLive(a.tenant));
  const tasks = usePoll((s) => appTasks(a.tenant, a.app, s), [a.tenant, a.app], DEFAULT_POLL_MS, appLive(a.tenant, a.app));
  const [to, setTo] = useState<Record<string, string>>({});
  const [moving, setMoving] = useState<{ v: VolumeView; node: string }>();
  const [checks, setChecks] = useState<Record<string, boolean | undefined>>({});
  const setCheck = (key: string, ok: boolean | undefined) => setChecks((x) => (x[key] === ok ? x : { ...x, [key]: ok }));
  const nodes = dash.data?.nodes ?? [];

  const rows = useMemo(
    () =>
      (services ?? []).map((s) => {
        const vs = s.volumes.filter(Boolean).flatMap((n) => (vols.data?.items ?? []).filter((v) => v.name === n && (!v.app || v.app === a.app)));
        const ts = (tasks.data?.items ?? []).filter((t) => t.service === s.name);
        const here = s.node || vs.find((v) => v.node)?.node || ts[0]?.node || '';
        const pinned = vs.find((v) => v.kind === 'fixed' && !v.app);
        const single = vs.some((v) => v.writer === `${a.app}/${s.name}`);
        return { ...s, vs, ts, here, pinned, single };
      }),
    [services, vols.data, tasks.data, a.app],
  );
  const changed = rows.filter((r) => to[r.name] && to[r.name] !== r.here);
  const withVol = changed.filter((r) => r.vs.length);
  const mixed = withVol.length > 0 && changed.length > 1;
  const yaml = useMemo(() => (current && changed.length && !withVol.length ? withNodes(current, Object.fromEntries(changed.map((r) => [r.name, to[r.name]]))) : undefined), [current, changed, withVol.length, to]);

  if (current === undefined || !services) return <Empty title="실행 중 app.yaml을 읽는 중입니다" />;
  const volMove = withVol.length === 1 && !mixed ? withVol[0] : undefined;
  const blocked = changed.some((r) => checks[`${r.name}>${to[r.name]}`] === false);
  const mv = volMove?.vs.find((v) => v.app);
  return (
    <>
      <HelpBox terms="배치 (placement, 서비스가 도는 서버) · 서비스 (service, 같은 설정의 컨테이너 묶음) · 데이터 저장소 이동 (volume move) · 고정 데이터 저장소는 옮길 수 없음">
        <b>이 탭은</b> 앱을 이루는 서비스(컨테이너)를 어느 서버에서 돌릴지 정합니다. 서비스마다 옮길 서버를 고르면, 웹 UI가 app.yaml의 배치 설정을 바꾼 새 버전을 만들고 옮기기 전에 검사와 변경 미리보기를 보여 줍니다. 서비스가 데이터 저장소를 쓰면 데이터도 함께 옮겨야 해서, 그동안 그 서비스는 잠시 멈춥니다.
      </HelpBox>
      <Card title="서비스별 배치" actions={<span className="small muted">{a.app}의 허용 서버: {nodes.map((n) => n.id).join(', ') || '—'}</span>}>
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>서비스</th>
                <th>지금 서버</th>
                <th>옮길 서버</th>
                <th>복제본</th>
                <th>컨테이너</th>
                <th>함께 옮길 것</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.name} style={to[r.name] && to[r.name] !== r.here ? { background: 'var(--accent-bg)' } : undefined}>
                  <td>
                    <b>{r.name}</b>
                  </td>
                  <td>{r.here || <span className="muted">서버가 고름</span>}</td>
                  <td>
                    <select aria-label={`${r.name} 옮길 서버`} value={to[r.name] ?? r.here} disabled={!canDeploy || !!r.pinned} title={r.pinned ? `고정 데이터 저장소 ${r.pinned.name}를 써서 옮길 수 없습니다` : !canDeploy ? '이 작업 공간의 배포 권한이 필요합니다' : undefined} onChange={(e) => setTo((x) => ({ ...x, [r.name]: e.target.value }))}>
                      {!r.here && <option value="">서버가 고름</option>}
                      {nodes.map((n) => (
                        <option key={n.id} value={n.id} disabled={n.id !== r.here && n.phase !== 'ready'}>
                          {n.id}
                          {n.id === r.here ? ' (그대로)' : n.phase === 'joining' ? ' (가입 대기)' : n.phase !== 'ready' ? ' (쓸 수 없음)' : ''}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="small">{r.single ? <span className="muted">{r.replicas} · 늘릴 수 없음 (단일 쓰기 데이터 저장소)</span> : r.replicas}</td>
                  <td className="small">
                    {r.ts.length ? r.ts.map((t) => `${t.instance} · ${t.observed === 'running' ? '실행 중' : t.observed === 'exited' ? '종료됨' : t.observed}`).join(', ') : <span className="muted">없음</span>}
                  </td>
                  <td className="small">
                    {r.vs.length ? (
                      r.vs.map((v) => (
                        <div key={v.key}>
                          데이터 저장소 {v.name} ({v.kind === 'fixed' && !v.app ? '고정 · 옮길 수 없음' : v.app ? '앱 소유' : '공유'}
                          {v.usedBytes !== undefined ? ` · ${fmtBytes(v.usedBytes)}` : ''})
                        </div>
                      ))
                    ) : (
                      <span className="muted">없음</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <span className="small muted">여러 서비스가 있는 앱은 서비스마다 옮길 서버를 따로 고릅니다. 데이터 저장소를 쓰지 않는 서비스는 여러 서버에 복제본을 둘 수 있습니다(아래, sfcd 기능 추가 뒤).</span>
      </Card>
      <Card title="여러 서버에 복제본 두기" actions={<Badge tone="wa">sfcd 기능 추가 필요</Badge>}>
        <div className="row small" style={{ gap: 16 }}>
          <span>복제본을 둘 서버</span>
          {nodes.map((n) => (
            <label key={n.id} className="row" style={{ gap: 6 }}>
              <input type="checkbox" disabled />
              {n.id}
              {n.phase === 'joining' ? ' (가입 대기)' : ''}
            </label>
          ))}
        </div>
        <span className="small muted">복제본은 같은 망 이름으로 묶여 요청이 나뉘고, 한 서버가 멈춰도 나머지가 계속 응답합니다. 쓰기 데이터 저장소를 쓰는 서비스는 복제본을 늘릴 수 없습니다. 서버가 이 기능을 지원하면 켜집니다.</span>
      </Card>
      {changed.length > 0 && (
        <Card title="옮기기 전 검사" actions={<span className="small muted">버전 {a.revision} → {a.revision + 1}</span>}>
          {mixed ? (
            <div className="note wa">데이터 저장소를 쓰는 서비스는 데이터와 함께 따로 옮깁니다. 이번에는 한 서비스만 고르세요.</div>
          ) : volMove ? (
            <>
              <span className="small">
                <span style={{ color: 'var(--ok)' }}>✓</span> {volMove.name}: {volMove.here} → {to[volMove.name]} · 데이터 저장소 {volMove.vs.map((v) => `${v.name}${v.usedBytes !== undefined ? ` (${fmtBytes(v.usedBytes)})` : ''}`).join(', ')}
              </span>
              <RelocCheck tenant={a.tenant} app={a.app} service={volMove.name} node={to[volMove.name]} onResult={setCheck} />
              <span className="small">
                <span style={{ color: 'var(--wa)' }}>!</span> 이동하는 동안 {volMove.name}가 멈춥니다
              </span>
              {mv ? (
                <>
                  <span className="small muted">데이터 저장소를 쓰는 서비스는 한 번에 하나씩 옮깁니다. 실패하면 원래 서버의 데이터로 다시 시작합니다.</span>
                  <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
                    <button type="button" className="btn" onClick={() => setTo({})}>
                      취소
                    </button>
                    <button type="button" className="btn primary" disabled={!canDeploy || !!mv.movePhase || blocked} title={mv.movePhase ? '이미 옮기는 중입니다' : blocked ? '옮기기 전 검사를 통과하지 못했습니다' : undefined} onClick={() => setMoving({ v: mv, node: to[volMove.name] })}>
                      재배치 시작
                    </button>
                  </div>
                </>
              ) : (
                <div className="note wa">이 서비스의 데이터 저장소는 앱 소유가 아니라 함께 옮길 수 없습니다.</div>
              )}
            </>
          ) : yaml ? (
            <>
              {changed.map((r) => (
                <span key={r.name} className="small">
                  <span style={{ color: 'var(--ok)' }}>✓</span> {r.name}: {r.here || '서버가 고름'} → {to[r.name]} · 데이터 저장소 없음
                </span>
              ))}
              {changed.map((r) => (
                <RelocCheck key={r.name} tenant={a.tenant} app={a.app} service={r.name} node={to[r.name]} onResult={setCheck} />
              ))}
              {blocked ? (
                <div className="note er small">옮기기 전 검사를 통과하지 못해 새 버전을 올리지 않습니다. 다른 서버를 고르거나 원인을 해결한 뒤 다시 고르세요.</div>
              ) : (
                <DeployFlow tenant={a.tenant} yaml={yaml} canDeploy={canDeploy} deployment={a.deployment} currentVersion={a.revision} gitWarning={!!a.cd} />
              )}
            </>
          ) : null}
        </Card>
      )}
      {volMove && mv && !mixed && (
        <Card title="진행">
          <span className="small muted">
            데이터 저장소를 쓰는 서비스는 '재배치 시작'이 데이터 저장소 이관 창(옮길 서버 채움)을 엽니다. 진행은 <Link to={`/shared/volumes?q=${encodeURIComponent(mv.name)}`}>데이터 저장소 &gt; 이관 카드</Link>에서 봅니다.
          </span>
        </Card>
      )}
      {moving && <MoveDialog tenant={a.tenant} v={moving.v} initialNode={moving.node} onClose={() => setMoving(undefined)} onDone={() => void vols.refresh()} />}
    </>
  );
}

// sfcd가 계획해서 판단한 결과 하나(plan). 실패하면 detail에 입력 오류 코드가 온다
const CHECK: Record<string, string> = { plan: '실행 계획' };

/** 옮기기 전 검사. 결과는 onResult(서비스>서버, ok)로 알린다. 읽지 못하면 undefined(막지 않음) */
function RelocCheck({ tenant, app, service, node, onResult }: { tenant: string; app: string; service: string; node: string; onResult: (key: string, ok: boolean | undefined) => void }) {
  const [c, setC] = useState<DRelocationCheck>();
  const [error, setError] = useState<unknown>();
  const key = `${service}>${node}`;
  useEffect(() => {
    const ctl = new AbortController();
    setC(undefined);
    setError(undefined);
    relocationCheck(tenant, app, service, node, ctl.signal).then(
      (x) => (setC(x), onResult(key, x.ok)),
      (e) => !ctl.signal.aborted && (setError(e), onResult(key, undefined)),
    );
    return () => ctl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenant, app, service, node]);
  if (error instanceof ApiError && error.status === 403) return <span className="small muted">· {service} → {node}: 옮기기 전 검사는 배포 권한이 있어야 볼 수 있습니다.</span>;
  if (error) return <span className="small" style={{ color: 'var(--wa)' }}>! {service} → {node}: 옮기기 전 검사를 읽지 못했습니다 ({error instanceof Error ? error.message : String(error)}). 서버가 보낼 때 다시 검사합니다.</span>;
  if (!c) return <span className="small muted">· {service} → {node}: 옮기기 전 검사 중…</span>;
  const bad = c.checks.filter((x) => !x.ok);
  const stuck = c.volumes.filter((v) => v.step === 'not-movable');
  return (
    <>
      <span className="small">
        {c.checks.map((x) => (
          <span key={x.name} title={x.detail} style={{ marginRight: 10, color: x.ok ? 'var(--ok)' : 'var(--er)' }}>
            {x.ok ? '✓' : '✕'} {CHECK[x.name] ?? x.name}
          </span>
        ))}
        <span className="muted"></span>
      </span>
      {bad.map((x) => (
        <span key={x.name} className="small" style={{ color: 'var(--er)' }}>
          ✕ {CHECK[x.name] ?? x.name}{x.detail ? `: ${x.detail}` : ''}
        </span>
      ))}
      {c.checks
        .filter((x) => x.ok && x.detail)
        .map((x) => (
          <span key={x.name} className="small muted">
            · {CHECK[x.name] ?? x.name}: {x.detail}
          </span>
        ))}
      {c.volumes.map((v) => (
        <span key={v.name} className="small" style={{ color: v.step === 'not-movable' ? 'var(--er)' : 'var(--wa)' }}>
          {v.step === 'not-movable' ? `✕ 데이터 저장소 ${v.name}(${v.kind})는 옮길 수 없습니다` : `! 데이터 저장소 ${v.name} 이동 필요 (${v.node} → ${c.to})`}
        </span>
      ))}
      {!c.ok && !bad.length && !stuck.length && <span className="small" style={{ color: 'var(--er)' }}>✕ 옮길 수 없습니다.</span>}
    </>
  );
}
