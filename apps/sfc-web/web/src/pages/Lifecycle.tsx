// SPDX-License-Identifier: Apache-2.0

// 상태 검사 스크립트 (UI-90)와 상태 검사 정책 (UI-91).
// 계약: docs/reference/web-api.md "상태 검사 스크립트와 정책". sfcd: put-lifecycle-script / retire-·delete-lifecycle-script / set-lifecycle-policy.
// 웹은 원본 글도 정책도 저장하지 않는다. 원본 올리기·글 읽기·쓰는 앱(REQ-39~41)은 sfcd에 들어오기 전까지 가짜 어댑터에서만 동작한다.
import { changedLines, DraftBand, useStoredDraft, useUnsaved } from '../components/Unsaved';
import { useEffect, useRef, useState } from 'react';
import { ApiError } from '../api/client';
import { lifecycleDetail, lifecyclePath, lifecyclePolicy, lifecycleScripts } from '../api/endpoints';
import type { DLifecyclePolicy, DLifecycleUse } from '../api/dto';
import type { DiffLine, LifecycleView, OpView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Badge, Card, Field, HelpBox, PageHeader } from '../components/ui';
import { Refresh } from '../components/Refresh';
import { Tabs } from '../components/Tabs';
import { Dialog } from '../components/Dialog';
import { DiffView } from '../components/Code';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';
import { fmtBytes } from '../lib/format';
import { eulReul } from '../lib/josa';
import { NoTenant } from './Deploy';
import { MFrame, SHARED_TABS } from './Shared';
import { usePhone } from '../lib/viewport';
import { MCards, MTiles, MWideNote } from '../mobile/ReadOnly';
import { Load } from '../components/states';
import { useNodes } from './SharedCreate';

const NEED = '작업 공간 관리자 권한 필요';
const GiB = 1024 ** 3;

const HEAD = `package checker

import (
\t"context"

\tlifecycle "github.com/jay94ks/seafield/lifecycle/v1"
)

func Check(ctx context.Context, in lifecycle.Request, probe lifecycle.Probe) (lifecycle.Result, error) {
`;
const result = (status: string, reason: string) => `lifecycle.Result{Schema: 1, Status: lifecycle.${status}, Reason: "${reason}"}`;
const TEMPLATES: Record<string, string> = {
  http: `${HEAD}\tr, err := probe.Healthz(ctx, lifecycle.HTTPProbe{Service: "web", Path: "/readyz", Port: 8080})
\tif err != nil {
\t\treturn ${result('Unknown', 'probe-error')}, err
\t}
\tif r.StatusCode != 200 {
\t\treturn ${result('Fail', 'not-ready')}, nil
\t}
\treturn ${result('Pass', 'ready')}, nil
}
`,
  tcp: `${HEAD}\tr, err := probe.Connect(ctx, lifecycle.TCPProbe{Service: "redis", Port: 6379})
\tif err != nil {
\t\treturn ${result('Unknown', 'probe-error')}, err
\t}
\tif !r.Connected {
\t\treturn ${result('Fail', 'closed')}, nil
\t}
\treturn ${result('Pass', 'open')}, nil
}
`,
  empty: `${HEAD}\treturn ${result('Pass', 'ok')}, nil
}
`,
};

type Diag = { line: number; column: number; message: string };
/** 422 compile-error 의 진단 목록 */
const diagsOf = (e: unknown): Diag[] | undefined => (e instanceof ApiError && e.code === 'compile-error' ? (((e.body as { diagnostics?: Diag[] }).diagnostics ?? []) as Diag[]) : undefined);

const ERR: Record<string, string> = {
  'policy-disabled': '상태 검사 정책이 없거나 꺼져 있어 스크립트를 올릴 수 없습니다. 아래 정책을 먼저 저장하거나 켜세요.',
  'not-active': '이미 비활성인 버전입니다.',
  active: '활성 버전은 지울 수 없습니다. 먼저 폐기하세요.',
  deleted: '이미 지운 버전입니다.',
  'invalid-policy': '정책이 규칙에 어긋납니다.',
};
function LcErr({ e }: { e: unknown }) {
  if (e === undefined) return null;
  if (e instanceof ApiError && ERR[e.code])
    return (
      <div className="note wa">
        {ERR[e.code]}
        {e.code === 'invalid-policy' && e.message ? <span className="small"> ({e.message})</span> : null}
      </div>
    );
  return <MutationError error={e} />;
}

/** 목록 상태 칸 */
function stateOf(l: LifecycleView) {
  const live = l.versions.filter((v) => !v.deleted);
  if (live.some((v) => v.active)) return <Badge tone="ok">활성</Badge>;
  if (live.length) return <Badge tone="un">폐기됨</Badge>;
  return <Badge tone="un">지움</Badge>;
}

export function LifecyclePage() {
  return usePhone() ? <MLifecycle /> : <DesktopLifecycle />;
}

/** 휴대폰 상태 검사 규칙 (UI-M11 ③ 모양) */
function MLifecycle() {
  const { tenant } = useTenantRole();
  const q = usePoll((s) => (tenant ? lifecycleScripts(tenant, s) : Promise.resolve(undefined)), [tenant]);
  const items = q.data?.items ?? [];
  const pol = q.data?.policy;
  const forbidden = q.error instanceof ApiError && q.error.status === 403;
  const active = items.filter((l) => l.versions.some((v) => v.active && !v.deleted)).length;
  return (
    <MFrame title="상태 검사 규칙" wide="스크립트 만들기·올리기·폐기·정책 바꾸기는 넓은 화면에서">
      {forbidden ? (
        <div className="bn info">상태 검사 스크립트는 작업 공간 관리자만 볼 수 있습니다.</div>
      ) : (
        <Load q={q} what="상태 검사 스크립트를 불러오지 못했습니다">
          {() => (
            <>
              <MTiles
                items={[
                  { label: '스크립트', value: items.length, sub: `활성 ${active}` },
                  { label: '정책', value: !pol?.configured ? '없음' : pol.enabled ? '켜짐' : '꺼짐', sub: !pol?.configured ? '아직 저장하지 않음' : '스크립트 올리기 허용', warn: !!pol?.configured && !pol.enabled },
                ]}
              />
              <MCards
                empty="스크립트가 없습니다."
                items={items.map((l) => {
                  const live = l.versions.filter((v) => !v.deleted);
                  const cur = live.find((v) => v.active);
                  return {
                    key: l.name,
                    title: l.name,
                    badge: cur ? ['ok', '활성'] : live.length ? ['un', '폐기됨'] : ['un', '지움'],
                    lines: [`버전 ${l.latestRevision || '—'}${cur && cur.revision !== l.latestRevision ? ` · 쓰는 버전 ${cur.revision}` : ''} · 남은 버전 ${live.length}`, cur ? `모듈 ${cur.modules.length}개 · ${fmtBytes(cur.length)}` : undefined],
                  };
                })}
              />
              <MWideNote>기본 Docker 검사(HTTP·TCP·exec)는 엔진이 직접 합니다</MWideNote>
            </>
          )}
        </Load>
      )}
    </MFrame>
  );
}

function DesktopLifecycle() {
  const { tenant, canDeploy } = useTenantRole();
  const q = usePoll((s) => (tenant ? lifecycleScripts(tenant, s) : Promise.resolve(undefined)), [tenant]);
  const [selName, setSelName] = useState<string>();
  const [create, setCreate] = useState(false);
  const items = q.data?.items ?? [];
  const pol = q.data?.policy;
  const sel = items.find((l) => l.name === selName) ?? items[0];
  const forbidden = q.error instanceof ApiError && q.error.status === 403;
  return (
    <>
      <PageHeader
        title="공유 자원"
        ids="UI-90 · UI-91"
        actions={
          <>
            <Refresh q={q} poll={false} />
            {tenant && (
              <button className="btn primary" disabled={!canDeploy || (pol && (!pol.configured || !pol.enabled))} title={!canDeploy ? NEED : pol && !pol.configured ? '상태 검사 정책이 아직 없습니다' : pol && !pol.enabled ? '상태 검사 정책이 꺼져 있습니다' : undefined} onClick={() => setCreate(true)}>
                스크립트 만들기
              </button>
            )}
          </>
        }
      />
      <Tabs label="공유 자원 탭" items={SHARED_TABS} />
      <HelpBox terms="상태 검사 (lifecycle) · 폐기 (retire, 새로 쓰지 못하게 막되 기록은 남김) · 버전 (revision)">
        <b>이 화면은</b> 앱이 제대로 떠 있는지 확인하는 사용자 스크립트를 관리합니다. HTTP·TCP 같은 기본 검사는 Docker가 직접 하므로, 여기서는 Go로 쓴 추가 검사만 다룹니다.
      </HelpBox>
      {!tenant ? (
        <NoTenant />
      ) : (
        <>
          {pol && !pol.configured && <div className="note">상태 검사 정책이 아직 없어 스크립트를 올릴 수 없습니다. 아래 정책을 저장하면 기본값으로 시작합니다.</div>}
          {pol && pol.configured && !pol.enabled && <div className="note wa">상태 검사 정책이 꺼져 있어 스크립트를 올릴 수 없습니다. 아래 정책에서 켜세요.</div>}
          <div className="side-main">
            <Card title="이름 붙인 스크립트" className="lc-list">
              {forbidden ? (
                <span className="small muted">상태 검사 스크립트는 작업 공간 관리자만 볼 수 있습니다.</span>
              ) : q.error ? (
                <MutationError error={q.error} />
              ) : items.length === 0 ? (
                <span className="small muted">{q.data ? '스크립트가 없습니다.' : '불러오는 중…'}</span>
              ) : (
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>이름</th>
                      <th>버전</th>
                      <th>상태</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((l) => (
                      <tr key={l.name} className={l.name === sel?.name ? 'selected' : undefined} onClick={() => setSelName(l.name)} style={{ cursor: 'pointer' }} aria-selected={l.name === sel?.name}>
                        <td>{l.name}</td>
                        <td>{l.latestRevision || '—'}</td>
                        <td>{stateOf(l)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <span className="small muted">기본 Docker 검사(HTTP·TCP·exec)는 엔진이 직접 수행합니다. 여기서는 사용자 Go 스크립트만 관리합니다.</span>
            </Card>
            {sel && <ScriptCard key={sel.name} tenant={tenant} script={sel} canDeploy={canDeploy} policyOn={!!pol?.configured && !!pol.enabled} onChanged={() => void q.refresh()} />}
          </div>
          {!forbidden && <PolicyCard tenant={tenant} canDeploy={canDeploy} onChanged={() => void q.refresh()} />}
        </>
      )}
      {create && tenant && (
        <CreateScriptDialog
          tenant={tenant}
          taken={items.map((l) => l.name)}
          onClose={() => setCreate(false)}
          onDone={(name) => {
            setSelName(name);
            void q.refresh();
          }}
        />
      )}
    </>
  );
}

/** 잠글 모듈. zip은 실행 서버에 그 모듈이 없을 때 같이 올리는 ZIP(데몬 #315). 저장이 끝나면 버린다 */
type LockZip = { name: string; size: number; b64: string };
type LockItem = { path: string; version: string; zip?: LockZip };
type LockBad = Record<string, 'missing' | 'invalid'>;
const lockKey = (x: { path: string; version: string }) => `${x.path}@${x.version}`;
/** 저장 요청 한도(데몬 본문 8 MiB, base64로 늘어난 크기 기준) */
const LOCK_LIMIT = 8 << 20;
const b64Len = (n: number) => Math.ceil(n / 3) * 4;
const readB64 = (f: File) =>
  new Promise<string>((ok, no) => {
    const r = new FileReader();
    r.onload = () => ok(String(r.result).replace(/^data:[^,]*,/, ''));
    r.onerror = () => no(r.error);
    r.readAsDataURL(f);
  });

function ScriptCard({ tenant, script, canDeploy: canWrite, policyOn, onChanged }: { tenant: string; script: LifecycleView; canDeploy: boolean; policyOn: boolean; onChanged: () => void }) {
  const [rev, setRev] = useState<number>();
  const d = usePoll((s) => lifecycleDetail(tenant, script.name, rev ?? script.latestRevision, s), [tenant, script.name, rev ?? script.latestRevision]);
  const sc = d.data?.script ?? script;
  // 고칠 수 있는 기준 버전: 지우지 않은 가장 새 버전. 활성 버전은 여럿일 수 있다(앱이 버전을 고정한다)
  const base = sc.latestRevision;
  const shown = rev ?? base;
  const ver = sc.versions.find((v) => v.revision === shown);
  const old = shown !== base;
  const canDeploy = canWrite;
  const [text, setText] = useState<string>();
  const [lock, setLock] = useState<LockItem[]>();
  const [lockDlg, setLockDlg] = useState<false | LockBad>(false);
  const [dlg, setDlg] = useState<'retire' | 'delete'>();
  const m = useMutation();
  // 처음 보낸 본문을 고정한다. 다시 보내기는 같은 본문, 고친 뒤에는 새 opId
  const sent = useRef<{ source: string; expected: number; node?: string; lock?: { path: string; version: string; zip?: string }[] }>();
  // 데몬 #315: node를 비우면 sfcd가 실행 서버를 고르지만 첫 응답을 잃으면 복구하지 못한다. 서버 목록 첫 서버를 기본으로 보낸다(같은 opId면 같은 node)
  const nodes = useNodes(tenant);
  const node = nodes[0]?.id;
  useEffect(() => {
    if (d.data && text === undefined && !old) setText(d.data.source ?? '');
  }, [d.data, text, old]);
  const source = old ? (d.data?.source ?? '') : (text ?? d.data?.source ?? '');
  const curLock: LockItem[] = lock ?? (sc.versions.find((v) => v.revision === base)?.modules ?? []).map(({ path, version }) => ({ path, version }));
  const zips = curLock.filter((x) => x.zip);
  const dirty = !old && text !== undefined && d.data !== undefined && text.trim() !== '' && (text !== (d.data.source ?? '') || lock !== undefined);
  // 저장 안 한 입력 지키기(캔버스 v224 UnsavedGuard). 잠금 모듈 ZIP은 초안에 넣지 않는다
  const scope = `${tenant}/${script.name}`;
  const stored = useStoredDraft<string>('lifecycle', scope);
  const un = useUnsaved({ dirty, what: `${script.name} 상태 검사 스크립트`, count: d.data ? changedLines(d.data.source ?? '', text ?? '') : 0, unit: '줄', draft: { kind: 'lifecycle', scope, value: text ?? '', rev: sc.recordRevision } });
  const save = () => {
    const body = { source, expected: sc.recordRevision, ...(node ? { node } : {}), ...(curLock.length ? { lock: curLock.map(({ path, version, zip }) => ({ path, version, ...(zip ? { zip: zip.b64 } : {}) })) } : {}) };
    if (!sent.current || JSON.stringify(sent.current) !== JSON.stringify(body)) {
      // 다른 본문은 새 작업이다(끝난 작업 뒤에도 새 opId)
      if (sent.current || m.op || m.error !== undefined) m.reset();
      sent.current = body;
    }
    void m.run(lifecyclePath(tenant, script.name), sent.current, 'PUT').then((o) => {
      if (o?.state === 'applied') {
        un.clear();
        stored.drop();
        sent.current = undefined;
        setLock(undefined);
        setText(undefined);
        setRev(undefined);
        void d.refresh();
        onChanged();
      }
    });
  };
  const diags = diagsOf(m.error);
  // 422 module-missing: 실행 서버에 없는 잠금 모듈(ZIP 없이 고른 것). 422 invalid·module-invalid: 첨부한 ZIP이 핀과 다름
  const errCode = m.error instanceof ApiError ? m.error.code : undefined;
  const missing = errCode === 'module-missing' ? curLock.filter((x) => !x.zip) : [];
  const wrongZip = (errCode === 'invalid' || errCode === 'module-invalid') && zips.length ? zips.filter((x) => !(m.error as ApiError).message || (m.error as ApiError).message.includes(x.path) || zips.length === 1) : [];
  const badRows: LockBad = Object.fromEntries([...missing.map((x) => [lockKey(x), 'missing'] as const), ...wrongZip.map((x) => [lockKey(x), 'invalid'] as const)]);
  const lines = source.split('\n').length;
  const live = sc.versions.filter((v) => !v.deleted).sort((a, b) => b.revision - a.revision);
  const uses = d.data?.usedBy;
  const usesHere = uses?.filter((u) => u.revision === shown);
  return (
    <Card
      className="lc-script"
      title={
        <span className="row" style={{ gap: 8 }}>
          <h2>
            {script.name} · 버전 {shown || '—'}
          </h2>
          {un.badge}
          {un.guard}
        </span>
      }
      actions={
        <>
          <select aria-label="버전" value={shown} onChange={(e) => setRev(Number(e.target.value) === base ? undefined : Number(e.target.value))}>
            {live.map((v) => (
              <option key={v.revision} value={v.revision}>
                버전 {v.revision}
                {v.revision === base ? ' (현재)' : v.active ? ' (활성 · 읽기 전용)' : ' (읽기 전용)'}
              </option>
            ))}
          </select>
          <button className="btn danger" disabled={!canDeploy || !ver?.active} title={!canDeploy ? NEED : !ver?.active ? '활성 버전만 폐기할 수 있습니다' : undefined} onClick={() => setDlg('retire')}>
            폐기
          </button>
          <button className="btn danger" disabled={!canDeploy || !ver || ver.active || ver.deleted} title={!canDeploy ? NEED : ver?.active ? '활성 버전은 먼저 폐기하세요' : undefined} onClick={() => setDlg('delete')}>
            삭제
          </button>
        </>
      }
    >
      {d.error !== undefined && <MutationError error={d.error} />}
      {stored.draft && !dirty && !old && canDeploy && <DraftBand draft={stored.draft} what={script.name} rev={sc.recordRevision} unit="줄" onResume={() => (setText(stored.draft!.value), stored.drop())} onDiscard={stored.drop} />}
      {d.data && !d.data.sourceAvailable && (
        <div className="note">
          이 버전의 원문을 읽을 수 없습니다{ver ? ` (digest ${ver.digest.slice(0, 12)} · ${ver.length} B)` : ''}.{old ? '' : ' 새 원문을 넣으면 새 버전으로 올립니다.'}
        </div>
      )}
      <div className="editor">
        <div className="ed-head">
          <code>check.go</code>
          <span className="small muted">{old ? '읽기 전용' : `${lines}줄`}</span>
        </div>
        <textarea aria-label="스크립트 원문" spellCheck={false} value={source} readOnly={old || !canDeploy} onChange={(e) => setText(e.target.value)} style={{ minHeight: 260 }} />
      </div>
      {diags && (
        <div className="note er small">
          {diags.length === 0
            ? '컴파일하지 못했습니다.'
            : diags.map((x, i) => (
                <div key={i}>
                  {x.line > 0 ? `${x.line}행: ` : ''}
                  {x.message}
                </div>
              ))}
        </div>
      )}
      <div className="row between" style={{ flexWrap: 'wrap', gap: 8 }}>
        <span className="row small" style={{ gap: 8 }}>
          <button className="btn" disabled={!canDeploy || old} onClick={() => setLockDlg({})}>
            모듈 잠금…
          </button>
          <span className="muted">{curLock.length ? `모듈 ${curLock.length}개 잠금${zips.length ? ` · ZIP ${zips.length}개 첨부` : ''}` : '모듈 잠금 없음 · 표준 SDK만 사용'}</span>
        </span>
        <button className="btn primary" disabled={!canDeploy || old || !dirty || m.busy || !policyOn} title={!policyOn ? '상태 검사 정책이 없거나 꺼져 있습니다' : undefined} onClick={save}>
          새 리비전 저장 (버전 {sc.recordRevision + 1})
        </button>
      </div>
      <span className="small muted">스크립트 결과는 검사 결과일 뿐입니다. 시작·종료·재시작은 담당 서버의 sfcd가 정책으로 결정합니다.</span>
      {missing.length > 0 ? (
        <div className="note er small">
          실행 서버에 <span className="mono">{missing.map(lockKey).join(', ')}</span> 모듈이 없어 저장하지 못했습니다. 이 모듈의 ZIP을 골라 다시 저장하세요.{' '}
          <button className="linkish" onClick={() => setLockDlg(badRows)}>
            모듈 잠금 열기
          </button>
        </div>
      ) : wrongZip.length > 0 ? (
        <div className="note er small">
          <span className="mono">{wrongZip.map((x) => x.zip!.name).join(', ')}</span>의 내용이 잠근 버전(<span className="mono">{wrongZip.map(lockKey).join(', ')}</span>)과 다릅니다. 그 버전의 모듈 ZIP을 다시 고르세요.{' '}
          <button className="linkish" onClick={() => setLockDlg(badRows)}>
            모듈 잠금 열기
          </button>
        </div>
      ) : (
        m.error !== undefined && !diags && <LcErr e={m.error} />
      )}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && (void d.refresh(), onChanged()))} />}
      {lockDlg && <LockDialog tenant={tenant} chosen={curLock} bad={lockDlg} sourceBytes={new Blob([source]).size} onClose={() => setLockDlg(false)} onPick={(l) => (setLock(l), setLockDlg(false))} />}
      {dlg && ver && (
        <RetireDeleteDialog
          kind={dlg}
          tenant={tenant}
          name={script.name}
          revision={ver.revision}
          expected={sc.recordRevision}
          uses={usesHere}
          onClose={() => setDlg(undefined)}
          onDone={() => {
            setRev(undefined);
            void d.refresh();
            onChanged();
          }}
        />
      )}
    </Card>
  );
}

function RetireDeleteDialog({ kind, tenant, name, revision, expected, uses, onClose, onDone }: { kind: 'retire' | 'delete'; tenant: string; name: string; revision: number; expected: number; uses?: DLifecycleUse[]; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  // 연 때의 버전·기록 revision을 고정한다
  const [body] = useState({ revision, expected });
  const del = kind === 'delete';
  const inUse = m.error instanceof ApiError && m.error.code === 'in-use';
  const apps = [...new Set((uses ?? []).filter((u) => u.kind !== 'build-job').map((u) => (u.standalone ? `${u.standalone}(단독 컨테이너)` : (u.app ?? '?'))))];
  return (
    <Dialog
      title={del ? `${name} 버전 ${revision}${eulReul(String(revision))} 삭제할까요?` : `${name}${eulReul(name)} 폐기할까요?`}
      danger
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
            <button className="btn danger solid" disabled={m.busy || inUse || (del && (uses?.length ?? 0) > 0)} onClick={() => void m.run(del ? lifecyclePath(tenant, name) : `${lifecyclePath(tenant, name)}/retire`, body, del ? 'DELETE' : 'POST').then((o) => o?.state === 'applied' && onDone())}>
              {del ? '삭제' : '폐기'}
            </button>
          </>
        )
      }
    >
      {del ? <p>이 버전 기록을 지웁니다. 되돌릴 수 없습니다.</p> : <p>{uses === undefined ? '' : `쓰는 앱 ${apps.length}개는 지금 버전으로 계속 검사합니다. `}새 앱은 이 스크립트를 고를 수 없습니다.</p>}
      {del && ((uses?.length ?? 0) > 0 || inUse) && (
        <div className="note er">
          {name}는 {apps.length ? `앱 ${apps.length}개(${apps.join(', ')})` : '빌드 작업'}가 써서 삭제할 수 없습니다. 먼저 폐기하고 앱에서 빼세요.
        </div>
      )}
      {del && uses === undefined && <span className="small muted">쓰는 앱을 읽을 수 없습니다. 쓰는 곳이 있으면 sfcd가 거절합니다.</span>}
      {m.error !== undefined && !inUse && <LcErr e={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}

/** 모듈 잠금: 정책이 허용한 모듈(resolver.modules) 중에서 고르고, 실행 서버에 없을 모듈은 ZIP을 같이 올린다(데몬 #315). go.lock 파일 자리는 따로 없다 */
function LockDialog({ tenant, chosen, bad, sourceBytes, onClose, onPick }: { tenant: string; chosen: LockItem[]; bad: LockBad; sourceBytes: number; onClose: () => void; onPick: (l: LockItem[]) => void }) {
  const q = usePoll((s) => lifecyclePolicy(tenant, s), [tenant]);
  const mods = q.data?.policy.resolver.modules ?? [];
  const [sel, setSel] = useState(() => new Map(chosen.map((x) => [lockKey(x), x.zip] as const)));
  const [readErr, setReadErr] = useState<string>();
  const total = [...sel.values()].reduce((n, z) => n + (z ? z.b64.length : 0), 0);
  const over = total + b64Len(sourceBytes) > LOCK_LIMIT;
  const toggle = (k: string, on: boolean) =>
    setSel((s) => {
      const n = new Map(s);
      if (on) n.set(k, n.get(k));
      else n.delete(k);
      return n;
    });
  const pickZip = (k: string) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.zip,application/zip';
    input.onchange = () => {
      const f = input.files?.[0];
      if (!f) return;
      setReadErr(undefined);
      readB64(f)
        .then((b64) => setSel((s) => new Map(s).set(k, { name: f.name, size: f.size, b64 })))
        .catch(() => setReadErr(`${f.name}을(를) 읽지 못했습니다.`));
    };
    input.click();
  };
  const dropZip = (k: string) => setSel((s) => new Map(s).set(k, undefined));
  const mib = (n: number) => `${(n / (1 << 20)).toFixed(1)} MiB`;
  return (
    <Dialog
      title="모듈 잠금"
      width={560}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!q.data || over} onClick={() => onPick(mods.filter((x) => sel.has(lockKey(x))).map(({ path, version }) => ({ path, version, zip: sel.get(lockKey({ path, version })) })))}>
            고르기
          </button>
        </>
      }
    >
      <span className="small muted">정책이 허용한 모듈 중 이 스크립트가 쓸 것을 고릅니다. 고른 모듈의 ZIP이 실행 서버에 아직 없으면 여기서 ZIP을 함께 올립니다. 이미 있으면 비워 둬도 됩니다.</span>
      {!q.data ? (
        <span className="small muted">정책을 읽는 중…</span>
      ) : mods.length === 0 ? (
        <p className="muted">정책이 허용한 외부 모듈이 없습니다. 표준 SDK만 쓸 수 있습니다.</p>
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th aria-label="고르기" style={{ width: 28 }} />
                <th>모듈 · 버전</th>
                <th>ZIP (선택)</th>
              </tr>
            </thead>
            <tbody>
              {mods.map((x) => {
                const k = lockKey(x);
                const on = sel.has(k);
                const z = sel.get(k);
                const why = bad[k];
                return (
                  <tr key={k} style={why ? { background: 'var(--er-bg, #FFF8F8)' } : on ? undefined : { color: 'var(--muted)' }}>
                    <td>
                      <input type="checkbox" aria-label={`${k} 잠금`} checked={on} onChange={(e) => toggle(k, e.target.checked)} />
                    </td>
                    <td className="mono" style={{ wordBreak: 'break-all' }}>
                      {k}
                    </td>
                    <td>
                      {!on ? (
                        <span className="muted">—</span>
                      ) : z ? (
                        <span className="col" style={{ gap: 2 }}>
                          <span className="mono">{z.name}</span>
                          <span className="small muted">
                            {fmtBytes(z.size)} ·{' '}
                            <button className="linkish" onClick={() => pickZip(k)}>
                              바꾸기
                            </button>{' '}
                            ·{' '}
                            <button className="linkish" onClick={() => dropZip(k)}>
                              빼기
                            </button>
                          </span>
                          {why === 'invalid' && <span className="small" style={{ color: 'var(--er)' }}>내용이 잠근 버전과 다름 · 바꾸기</span>}
                        </span>
                      ) : (
                        <span className="col" style={{ gap: 2 }}>
                          <button className="btn sm" style={why ? { borderColor: 'var(--er)' } : undefined} onClick={() => pickZip(k)}>
                            ZIP 파일 고르기
                          </button>
                          {why === 'missing' && <span className="small" style={{ color: 'var(--er)' }}>서버에 없음 · ZIP 필요</span>}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {readErr && <div className="note er small">{readErr}</div>}
      <div className="col" style={{ gap: 4 }}>
        <span className="small" style={over ? { color: 'var(--er)' } : { color: 'var(--muted)' }}>
          첨부 합계 {mib(total)} / 8 MiB{over ? ' · 한도를 넘었습니다' : ''}
        </span>
        <span className="bar">
          <i className={over ? 'crit' : ''} style={{ width: `${Math.min(100, ((total + b64Len(sourceBytes)) / LOCK_LIMIT) * 100)}%` }} />
        </span>
        <span className="small muted">{over ? 'ZIP 하나를 빼고 저장한 뒤, 다음 리비전에서 나머지를 올리세요.' : '스크립트와 ZIP을 합쳐 저장 요청 한 번에 8 MiB까지 보냅니다(base64로 늘어난 크기 기준). 넘으면 ZIP을 나눠 다음 저장에 올리세요.'}</span>
      </div>
    </Dialog>
  );
}

const NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;
function CreateScriptDialog({ tenant, taken, onClose, onDone }: { tenant: string; taken: string[]; onClose: () => void; onDone: (name: string) => void }) {
  const m = useMutation();
  const [name, setName] = useState('');
  const [tpl, setTpl] = useState('http');
  const [sent, setSent] = useState<{ name: string; body: Record<string, unknown> }>();
  const err = sent ? undefined : name && !NAME.test(name) ? "소문자·숫자·'-'로 씁니다." : taken.includes(name) ? '이미 있는 이름입니다.' : undefined;
  const go = () => {
    const s = sent ?? { name, body: { source: TEMPLATES[tpl], expected: 0 } };
    setSent(s);
    void m.run(lifecyclePath(tenant, s.name), s.body, 'PUT').then((o) => o?.state === 'applied' && onDone(s.name));
  };
  const diags = diagsOf(m.error);
  return (
    <Dialog
      title="상태 검사 스크립트 만들기"
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
            <button className="btn primary" disabled={(!name || !!err) && !sent} onClick={go}>
              만들기
            </button>
          </>
        )
      }
    >
      <Field label="이름" error={err}>
        <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} placeholder="redis-ping" disabled={!!sent} />
      </Field>
      <Field label="템플릿">
        <select value={tpl} onChange={(e) => setTpl(e.target.value)} disabled={!!sent}>
          <option value="http">HTTP 응답</option>
          <option value="tcp">TCP 연결</option>
          <option value="empty">빈 스크립트</option>
        </select>
      </Field>
      {diags ? <div className="note er small">{diags.map((x) => `${x.line > 0 ? `${x.line}행: ` : ''}${x.message}`).join(' · ') || '컴파일하지 못했습니다.'}</div> : <LcErr e={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone(sent!.name))} />}
    </Dialog>
  );
}

/**
 * UI-91 상태 검사 정책. 캔버스의 실행 방식(해석 실행 / 컴파일 허용)은 build.nodes가 비었는지로 정한다.
 * PUT은 보낸 부분만 바꾸므로 enabled·build·compiledCacheBytes만 보낸다(build는 통째로 바뀐다).
 */
function PolicyCard({ tenant, canDeploy, onChanged }: { tenant: string; canDeploy: boolean; onChanged: () => void }) {
  const q = usePoll((s) => lifecyclePolicy(tenant, s), [tenant]);
  const nodes = useNodes(tenant);
  const [edit, setEdit] = useState<Partial<Form>>({});
  const [review, setReview] = useState(false);
  const p = q.data?.policy;
  const v: Form = { ...formOf(p), ...edit };
  const set = (k: keyof Form) => (e: { target: { value: string } }) => setEdit((x) => ({ ...x, [k]: e.target.value }));
  const cacheBytes = Math.round(Number(v.cache) * GiB);
  const jobs = Number(v.jobs);
  const compiled = v.mode === 'compiled';
  const res = p ? buildRes(p.build) : BUILD_DEFAULTS;
  const bad = !(cacheBytes >= 0) ? '컴파일 캐시 상한을 GiB로 넣으세요.' : compiled && cacheBytes < res.artifactBytes ? `컴파일하면 캐시 상한이 빌드 결과물 한도(${fmtBytes(res.artifactBytes)}) 이상이어야 합니다.` : compiled && !v.node ? '컴파일하려면 빌드 서버가 필요합니다.' : compiled && !(Number.isInteger(jobs) && jobs >= 1 && jobs <= 16) ? '동시 빌드 작업은 1~16입니다.' : compiled && !/@sha256:[0-9a-f]{64}$/.test(v.image.trim()) ? '빌드 이미지는 digest로 고정해야 합니다 (이름@sha256:…).' : compiled && !/^go1\.\d+(\.\d+)?$/.test(v.toolchain.trim()) ? '툴체인은 go1.24 같은 Go 버전입니다.' : undefined;
  return (
    <Card title={<h2>상태 검사 정책</h2>} actions={p && <span className="mono small muted">policy rev {p.revision}</span>}>
      {q.error !== undefined && <MutationError error={q.error} />}
      {q.data && !q.data.configured && <span className="small muted">정책이 아직 없습니다. 저장하면 기본값(해석 실행, 동시 4개, 5초)으로 시작합니다.</span>}
      <div className="g2" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
        <Field label="실행 방식">
          <select value={v.mode} onChange={set('mode')} disabled={!canDeploy}>
            <option value="yaegi">Yaegi 인터프리터</option>
            <option value="compiled">컴파일 CLI 허용</option>
          </select>
        </Field>
        <Field label="빌드 서버">
          <select value={v.node} onChange={set('node')} disabled={!canDeploy || !compiled}>
            <option value="">없음</option>
            {[...new Set([...nodes.map((n) => n.id), ...(p?.build.nodes ?? [])])].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </Field>
        <Field label="컴파일 캐시 상한 (GiB)">
          <input inputMode="decimal" value={v.cache} onChange={set('cache')} disabled={!canDeploy} />
        </Field>
        <Field label="동시 빌드 작업">
          <input inputMode="numeric" value={v.jobs} onChange={set('jobs')} disabled={!canDeploy || !compiled} />
        </Field>
        {compiled && (
          <>
            <Field label="빌드 이미지">
              <input className="mono" value={v.image} onChange={set('image')} disabled={!canDeploy} placeholder="registry/lifecycle-builder@sha256:…" />
            </Field>
            <Field label="툴체인">
              <input className="mono" value={v.toolchain} onChange={set('toolchain')} disabled={!canDeploy} placeholder="go1.24" />
            </Field>
          </>
        )}
      </div>
      {compiled && (
        <span className="small muted">
          빌드 자원: CPU {res.nanoCPU / 1e9} · 메모리 {fmtBytes(res.memoryBytes)} · 작업 공간 {fmtBytes(res.workspaceBytes)} · 결과물 {fmtBytes(res.artifactBytes)} · 제한 시간 {res.timeoutMS / 1000}초{p && !p.build.nanoCPU ? ' (기본값)' : ''}
        </span>
      )}
      <label className="check">
        <input type="checkbox" checked={v.enabled === 'on'} onChange={(e) => setEdit((x) => ({ ...x, enabled: e.target.checked ? 'on' : 'off' }))} disabled={!canDeploy} /> 상태 검사 스크립트 쓰기 (끄면 새 스크립트를 올릴 수 없습니다)
      </label>
      {bad && <div className="note er small">{bad}</div>}
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="btn primary" disabled={!p || !canDeploy || !!bad} title={canDeploy ? undefined : NEED} onClick={() => setReview(true)}>
          정책 변경 검토
        </button>
      </div>
      {review && p && (
        <PolicyDialog
          tenant={tenant}
          from={p}
          to={v}
          onClose={() => setReview(false)}
          onDone={() => {
            setEdit({});
            void q.refresh();
            onChanged();
          }}
        />
      )}
    </Card>
  );
}

type Form = { mode: string; node: string; cache: string; jobs: string; image: string; toolchain: string; enabled: 'on' | 'off' };
type Policy = DLifecyclePolicy & { build: { nodes: string[]; targets: string[] } };
const formOf = (p?: Policy): Form => ({
  mode: p?.build.nodes.length ? 'compiled' : 'yaegi',
  node: p?.build.nodes[0] ?? '',
  cache: p ? String(Math.round((p.compiledCacheBytes / GiB) * 10) / 10) : '0',
  jobs: String(p?.build.maxJobs || 1),
  image: p?.build.image ?? '',
  toolchain: p?.build.toolchain ?? '',
  enabled: p?.enabled === false ? 'off' : 'on',
});
/** 빌드 자원이 비어 있을 때 채우는 기본값(sfcd 규칙: CPU > 0, 메모리 32 MiB 이상, 결과물 ≤ 작업 공간 ≤ …, 시간 > 0) */
const BUILD_DEFAULTS = { nanoCPU: 1_000_000_000, memoryBytes: GiB, workspaceBytes: 2 * GiB, artifactBytes: 256 * 1024 ** 2, timeoutMS: 120_000 };
const buildRes = (b: Policy['build']) => ({ nanoCPU: b.nanoCPU || BUILD_DEFAULTS.nanoCPU, memoryBytes: b.memoryBytes || BUILD_DEFAULTS.memoryBytes, workspaceBytes: b.workspaceBytes || BUILD_DEFAULTS.workspaceBytes, artifactBytes: b.artifactBytes || BUILD_DEFAULTS.artifactBytes, timeoutMS: b.timeoutMS || BUILD_DEFAULTS.timeoutMS });
/** 화면 값 → PUT 본문(빌드 서버가 없으면 해석 실행만 하며 image·toolchain·targets를 비운다) */
function policyBody(p: Policy, v: Form) {
  const compiled = v.mode === 'compiled';
  const build = compiled ? { ...p.build, ...buildRes(p.build), nodes: [v.node], maxJobs: Number(v.jobs), image: v.image.trim(), toolchain: v.toolchain.trim(), targets: p.build.targets.length ? p.build.targets : ['linux/amd64'] } : { nodes: [], targets: [], image: '', toolchain: '', maxJobs: 0, nanoCPU: 0, memoryBytes: 0, workspaceBytes: 0, artifactBytes: 0, timeoutMS: 0 };
  return { enabled: v.enabled === 'on', build, compiledCacheBytes: Math.round(Number(v.cache) * GiB), expected: p.revision };
}

function PolicyDialog({ tenant, from, to, onClose, onDone }: { tenant: string; from: Policy; to: Form; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  // 연 순간의 값·비교·expected를 고정한다(적용 뒤 정책이 새로 읽혀도 창 내용이 바뀌지 않게)
  const [{ body, diff, rev }] = useState(() => {
    const a = formOf(from);
    const diff: DiffLine[] = [];
    const pair = (k: string, x: string, y: string) => (x === y ? diff.push({ op: ' ', text: `${k}: ${x}` }) : diff.push({ op: '-', text: `${k}: ${x}` }, { op: '+', text: `${k}: ${y}` }));
    pair('enabled', a.enabled === 'on' ? 'true' : 'false', to.enabled === 'on' ? 'true' : 'false');
    pair('mode', a.mode, to.mode);
    pair('build_nodes', a.mode === 'compiled' ? a.node : '—', to.mode === 'compiled' ? to.node : '—');
    if (a.mode === 'compiled' || to.mode === 'compiled') {
      pair('image', a.mode === 'compiled' ? a.image : '—', to.mode === 'compiled' ? to.image.trim() : '—');
      pair('toolchain', a.mode === 'compiled' ? a.toolchain : '—', to.mode === 'compiled' ? to.toolchain.trim() : '—');
      pair('concurrency', a.mode === 'compiled' ? a.jobs : '—', to.mode === 'compiled' ? to.jobs : '—');
    }
    pair('cache', fmtBytes(from.compiledCacheBytes), fmtBytes(Math.round(Number(to.cache) * GiB)));
    return { body: policyBody(from, to), diff, rev: from.revision };
  });
  return (
    <Dialog
      title={`상태 검사 정책 rev ${rev} → ${rev + 1}`}
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
            <button className="btn primary" disabled={m.busy} onClick={() => void m.run(`/t/${encodeURIComponent(tenant)}/lifecycle-policy`, body, 'PUT').then((o) => o?.state === 'applied' && onDone())}>
              저장
            </button>
          </>
        )
      }
    >
      <DiffView lines={diff} compact={false} />
      <LcErr e={m.error} />
      {m.op && <OpPanel op={m.op} onChange={(o: OpView) => (m.setOp(o), o.state === 'applied' && onDone())} />}
    </Dialog>
  );
}
