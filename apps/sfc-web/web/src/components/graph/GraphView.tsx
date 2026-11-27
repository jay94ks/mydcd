// SPDX-License-Identifier: Apache-2.0

import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { appLayout, dashboard, nodesOverview, putAppLayout } from '../../api/endpoints';
import { useAuth } from '../../auth/session';
import { usePoll } from '../../lib/usePoll';
import { useTenantChoices } from '../../pages/AppForm';
import type { GraphChoices } from './GraphEditor';

const GraphEditor = lazy(() => import('./GraphEditor'));

/**
 * 그래프 편집기 감싸기: 작업 공간 선택지(망·저장소·비밀값·서버)와 배치 좌표(배포된 앱만, 웹 bbolt)를 붙인다.
 * Rete 묶음은 이 보기를 열 때만 불러온다.
 */
export function GraphView({ tenant, yaml, onChange, app, canSave }: { tenant: string; yaml: string; onChange: (y: string) => void; app?: { name: string; deployment: string }; canSave: boolean }) {
  const { session } = useAuth();
  const c = useTenantChoices(tenant);
  const nodeQ = usePoll((s) => (session?.user.systemAdmin ? nodesOverview(s).then((o) => o.nodes.map((n) => n.id)) : dashboard(tenant || undefined, s).then((d) => d.nodes.map((n) => n.id))), [tenant, session?.user.systemAdmin]);
  const choices: GraphChoices = useMemo(
    () => ({ networks: c.networks.map((n) => n.name), volumes: c.volumes.map((v) => v.name), secrets: c.secrets.map((s) => s.path), nodes: nodeQ.data ?? [] }),
    [c.networks, c.volumes, c.secrets, nodeQ.data],
  );
  const layout = usePoll((s) => (app ? appLayout(tenant, app.name, app.deployment, s) : Promise.resolve(undefined)), [tenant, app?.name, app?.deployment]);
  const [saved, setSaved] = useState<'idle' | 'saving' | 'saved' | 'failed'>('idle');
  const timer = useRef<number>();
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const onPositions = (pos: Record<string, { x: number; y: number }>) => {
    if (!app || !canSave) return;
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      setSaved('saving');
      putAppLayout(tenant, app.name, app.deployment, { v: 1, pos })
        .then(() => setSaved('saved'))
        .catch(() => setSaved('failed'));
    }, 800);
  };
  // 배포된 앱은 저장된 좌표를 먼저 읽고 그린다(없으면 자동 정렬).
  if (app && layout.loading && layout.data === undefined && !layout.error) return <p className="muted small">블록 배치를 읽는 중…</p>;
  return (
    <div className="col" style={{ gap: 6 }}>
      <Suspense fallback={<p className="muted small">그래프 편집기를 불러오는 중…</p>}>
        <GraphEditor yaml={yaml} onChange={onChange} choices={choices} positions={layout.data?.pos} onPositions={onPositions} />
      </Suspense>
      <span className="small muted">
        app.yaml이 원본입니다. 그래프에서 고치면 아래 app.yaml이 바뀌고, app.yaml을 고치면 그래프를 다시 그립니다.
        {app
          ? canSave
            ? { idle: ' 블록 위치는 이 앱에 저장됩니다.', saving: ' 블록 위치 저장 중…', saved: ' 블록 위치를 저장했습니다.', failed: ' 블록 위치를 저장하지 못했습니다.' }[saved]
            : ' 읽기 권한이라 블록 위치는 저장하지 않습니다.'
          : ' 새 앱의 블록 위치는 저장하지 않습니다.'}
      </span>
    </div>
  );
}
