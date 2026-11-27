// SPDX-License-Identifier: Apache-2.0

import { changedLines, DraftBand, useStoredDraft, useUnsaved } from '../components/Unsaved';
import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { dashboard, nodesOverview, uploads } from '../api/endpoints';
import { useAuth, useTenantRole } from '../auth/session';
import { Card, HelpBox, PageHeader, Segmented } from '../components/ui';
import { Load } from '../components/states';
import { YamlEditor, CodeView } from '../components/Code';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';
import { DeployTabs, NoTenant } from './Deploy';
import { DeployFlow, Steps, type FlowStep } from './DeployFlow';
import { AppFormEditor, emptyForm, formToYaml, type AppFormState } from './AppForm';
import { GraphView } from '../components/graph/GraphView';

const starter = () => `name: my-app
services:
  web:
    image: docker.io/library/nginx:1.27 # 다이제스트(@sha256:…)로 고정하기를 권합니다
    x-sfc:
      node: node-a
`;

function Uploads({ tenant }: { tenant: string }) {
  const u = usePoll((s) => uploads(tenant, s), [tenant]);
  const m = useMutation();
  const [target, setTarget] = useState<string>();
  return (
    <Card title="끝나지 않은 업로드 (UI-34)" actions={<span className="small muted">웹 배포의 업로드는 같은 작업으로 다시 보내면 이어 올립니다</span>}>
      <Load q={u}>
        {(p) =>
          p.items.length === 0 ? (
            <span className="small muted">끝나지 않은 업로드가 없습니다.</span>
          ) : (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>업로드</th>
                    <th>앱</th>
                    <th>진행</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {p.items.map((x) => (
                    <tr key={x.id}>
                      <td>
                        <code>{x.id}</code>
                      </td>
                      <td>{x.app}</td>
                      <td>
                        {x.parts - x.missing.length}/{x.parts} 조각{x.missing.length ? ` · 누락 ${x.missing.join(', ')}` : ''}
                      </td>
                      <td>
                        <button
                          className="btn sm danger"
                          disabled={m.busy}
                          onClick={() => {
                            m.reset();
                            setTarget(x.id);
                            void m.submit({ action: 'abort-app-upload', tenant, target: x.id, payload: { Tenant: tenant, ID: x.id } }).then(() => u.refresh());
                          }}
                        >
                          중단
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
      {target && <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={m.setOp} />}
    </Card>
  );
}

export function DeployNewPage() {
  const { tenant, canDeploy } = useTenantRole();
  const { session } = useAuth();
  const loc = useLocation();
  // image: 이미지 관리의 '배포에 쓰기'(UI-84)에서 고른 이미지로 새 앱 폼을 연다
  const carried = loc.state as { yaml?: string; from?: string; image?: string } | null;
  const [mode, setMode] = useState<'yaml' | 'form' | 'graph'>(carried?.image ? 'form' : 'yaml');
  const [text, setText] = useState(() => carried?.yaml ?? starter());
  const [form, setForm] = useState<AppFormState>(() => {
    const f = emptyForm();
    return carried?.image ? { ...f, services: f.services.map((x, i) => (i === 0 ? { ...x, image: carried.image! } : x)) } : f;
  });
  const [step, setStep] = useState<FlowStep>(1);
  // 고를 수 있는 서버: 시스템 관리자는 클러스터 서버, 그 밖에는 이 작업 공간 범위의 관측 서버.
  const nodeQ = usePoll((s) => (session?.user.systemAdmin ? nodesOverview(s).then((o) => o.nodes.map((n) => n.id)) : dashboard(tenant || undefined, s).then((d) => d.nodes.map((n) => n.id))), [tenant, session?.user.systemAdmin]);
  const nodes = useMemo(() => nodeQ.data ?? [], [nodeQ.data]);
  const formYaml = useMemo(() => formToYaml(form), [form]);
  const yaml = mode === 'form' ? formYaml : text;
  // 저장 안 한 입력 지키기(캔버스 v224 UnsavedGuard): 처음 연 때의 정의와 다르고 아직 제출하지 않았으면
  const [base] = useState(() => (carried?.image ? formToYaml(form) : text));
  const dirty = yaml !== base && step < 4;
  type Draft = { mode: typeof mode; text: string; form: AppFormState };
  const stored = useStoredDraft<Draft>('deploy-new', carried?.yaml || carried?.image ? undefined : tenant);
  const un = useUnsaved<Draft>({ dirty, what: '새 앱 배포', count: changedLines(base, yaml), unit: '줄', draft: tenant ? { kind: 'deploy-new', scope: tenant, value: { mode, text, form } } : undefined });
  useEffect(() => {
    if (step === 4) (un.clear(), stored.drop());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  if (!tenant) return <NoTenant />;
  return (
    <>
      {un.guard}
      <PageHeader title="배포" ids="UI-32 · UI-33 · UI-34" after={un.badge} />
      <DeployTabs />
      {stored.draft && !dirty && (
        <DraftBand
          draft={stored.draft}
          what="새 앱"
          unit="줄"
          onResume={() => {
            const d = stored.draft!.value;
            setMode(d.mode);
            setText(d.text);
            setForm(d.form);
            stored.drop();
          }}
          onDiscard={stored.drop}
        />
      )}
      <HelpBox terms="배포 구성 (deployment) · 변경 미리보기 (plan / diff) · 망·저장소·비밀값은 이름으로만 참조">
        <b>이 탭은</b> 새 앱을 배포합니다. app.yaml(Compose 형식)을 붙여넣거나 파일로 올리고, app.yaml을 쓰기 어렵다면 '폼으로 작성'이나 '그래프로 작성'을 고릅니다. 배포 전에 검사 결과와 바뀌는 점을 먼저 보여 줍니다.
      </HelpBox>
      <div className="row">
        <Segmented
          label="작성 방식"
          value={mode}
          onChange={setMode}
          options={[
            ['yaml', 'app.yaml로 작성'],
            ['form', '폼으로 작성'],
            ['graph', '그래프로 작성'],
          ]}
        />
        <span className="small muted">
          이미 배포된 앱을 고치려면 <Link to="/deploy">배포된 앱</Link> 탭에서 앱을 고르세요.
        </span>
      </div>
      {carried?.image && (
        <div className="note un small">
          이미지 관리에서 고른 <code className="break-any">{carried.image}</code>로 폼을 채웠습니다.
        </div>
      )}
      {carried?.from && <div className="note un small">{carried.from}의 원문으로 시작했습니다. 일반 배포 경로(검사 → 변경 미리보기 → 업로드 → up)를 그대로 탑니다.</div>}
      {!canDeploy && <div className="note wa small">이 작업 공간에서는 읽기 권한만 있어 검사까지만 할 수 있습니다.</div>}
      <Steps step={step} />
      {mode === 'graph' && <GraphView tenant={tenant} yaml={text} onChange={setText} canSave={false} />}
      <div className="main-side">
        <div className="primary col" style={{ gap: 16 }}>
          {mode === 'yaml' || mode === 'graph' ? (
            <YamlEditor value={text} onChange={setText} />
          ) : (
            <>
              <AppFormEditor tenant={tenant} value={form} onChange={setForm} nodes={nodes} />
              <Card title="만들어질 app.yaml">
                <CodeView text={formYaml} />
                <button className="btn sm" style={{ alignSelf: 'flex-start' }} onClick={() => (setText(formYaml), setMode('yaml'))}>
                  app.yaml로 이어 고치기
                </button>
              </Card>
            </>
          )}
        </div>
        <div className="aside">
          <DeployFlow key={`${tenant}-${mode === 'form' ? 'form' : 'text'}`} tenant={tenant} yaml={yaml} canDeploy={canDeploy && !!session} onStep={setStep} />
        </div>
      </div>
      <Uploads tenant={tenant} />
    </>
  );
}
