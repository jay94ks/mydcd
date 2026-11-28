// SPDX-License-Identifier: Apache-2.0

// 이미지 관리 › 신뢰 출처 탭 (UI-82, 캔버스 ImageTrust · ImageTrustIx).
// 계약: docs/reference/web-api.md "이미지 신뢰 출처". 받을 때 신뢰 검사는 sfcd 몫이다.
// PUT은 목록 전체를 바꾸므로 읽어 온 revision을 expected로 늘 함께 보낸다(다른 사람의 변경을 덮어쓰지 않게).
import { useEffect, useState } from 'react';
import { noEndpoint } from '../api/client';
import { imageTrust, imageTrustPath, imageTrustPreview, trustDelta, type ImageTrust, type TrustRule, type TrustUse } from '../api/endpoints';
import { useTenantRole } from '../auth/session';
import { Badge, Card, Field, HelpBox } from '../components/ui';
import { Empty, Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Dialog } from '../components/Dialog';
import { DiffView } from '../components/Code';
import { Menu } from '../components/Menu';
import { MutationError, OpPanel, casFailed, useMutation } from '../components/OpPanel';
import { eulReul } from '../lib/josa';
import { usePoll } from '../lib/usePoll';
import { matchRule } from '../lib/trust';

const NEED = '이 작업 공간의 관리 권한이 필요합니다';
type Rule = { registry: string; repository: string };
const key = (r: Rule) => `${r.registry}/${r.repository}`;

export const ORIGIN: Record<string, string> = { default: '기본값 (새 작업 공간)', builtin: '내장 저장소', direct: '직접 추가', external: '외부 저장소 등록과 함께 추가' };
export const PULL: Record<string, string> = { 'registry-credential': '내장', anonymous: '익명 받기' };

const useLabel = (u: TrustUse) => (u.app ? `${u.app}${u.service ? `/${u.service}` : ''}` : `단독 ${u.standalone}`);
const appsOf = (us: TrustUse[]) => [...new Set(us.map((u) => u.app ?? `단독 ${u.standalone}`))];

export function TrustTab() {
  const { tenant, canDeploy } = useTenantRole();
  const q = usePoll((s) => imageTrust(tenant, s), [tenant]);
  const [dlg, setDlg] = useState<{ kind: 'add' } | { kind: 'edit' | 'remove' | 'uses'; r: TrustRule }>();
  if (q.error && noEndpoint(q.error)) return <Empty title="서버 기능 대기">웹 서버에 신뢰 출처 끝점이 아직 없습니다.</Empty>;
  return (
    <>
      <HelpBox terms="신뢰 출처 (image trust) · 경로 (repository, ** = 그 저장소 전부)">
        <b>이 화면은</b> 이 작업 공간의 앱과 빌드가 쓸 수 있는 이미지 출처를 정합니다. 여기 없는 저장소·경로의 이미지는 배포와 빌드(FROM)에서 모두 거부됩니다. 새 작업 공간은 Docker Hub만 들어 있습니다.
      </HelpBox>
      <Load q={q} what="신뢰 출처를 읽지 못했습니다">
        {(v) => (
          <>
            <Card
              title="신뢰 출처"
              actions={
                <>
                  <span className="small muted">rev {v.revision}</span>
                  <Refresh q={q} poll={false} />
                  <button type="button" className="btn primary" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => setDlg({ kind: 'add' })}>
                    ＋ 신뢰 출처 추가
                  </button>
                </>
              }
            >
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>저장소 주소</th>
                      <th>경로</th>
                      <th>어디서 왔나</th>
                      <th>받기 방식</th>
                      <th aria-label="작업" />
                    </tr>
                  </thead>
                  <tbody>
                    {v.rules.map((r) => (
                      <tr key={key(r)}>
                        <td className="mono small">{r.registry}</td>
                        <td className="mono small">{r.repository}</td>
                        <td>
                          {ORIGIN[r.origin] ?? r.origin}
                          <div className="small muted">
                            쓰는 곳 {r.uses.length}
                            {r.only ? ` · 이 출처만 허용 ${r.only}` : ''}
                          </div>
                        </td>
                        <td>
                          <Badge tone="ok">{PULL[r.pull] ?? r.pull}</Badge>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <Menu
                            label={`${key(r)} 작업`}
                            button="⋯"
                            items={[
                              { label: '경로 바꾸기', onSelect: () => setDlg({ kind: 'edit', r }), disabledReason: canDeploy ? undefined : NEED },
                              { label: '맞는 이미지 보기', disabledReason: '이미지 목록 뒤에 켜짐' },
                              { label: '쓰는 앱 보기', onSelect: () => setDlg({ kind: 'uses', r }), hint: String(r.uses.length) },
                              { label: '', sep: true },
                              { label: '빼기…', danger: true, onSelect: () => setDlg({ kind: 'remove', r }), disabledReason: canDeploy ? undefined : NEED },
                            ]}
                          />
                        </td>
                      </tr>
                    ))}
                    {!v.rules.length && (
                      <tr>
                        <td colSpan={5} className="muted">
                          신뢰 출처가 없습니다. 이 작업 공간은 어떤 이미지도 받을 수 없습니다.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              <span className="small muted">항목을 빼면 이미 실행 중인 컨테이너는 그대로지만, 그 출처 이미지를 다시 받아야 하는 재시작·이동·배포는 막히고 해당 앱에 '신뢰 출처 아님' 경고가 붙습니다. 빼기 전에 영향받는 앱 목록을 보여 줍니다. 로그인이 필요한 외부 저장소는 외부 저장소 탭에서 등록합니다.</span>
            </Card>
            {v.untrusted.length > 0 && (
              <Card title="신뢰 출처 아님" actions={<Badge tone="wa">{v.untrusted.length}</Badge>}>
                <span className="small">지금 어느 출처도 허용하지 않는 이미지를 쓰는 곳입니다. 다음 재시작·이동·배포 때 막힙니다.</span>
                <UseList uses={v.untrusted} />
              </Card>
            )}
            {dlg?.kind === 'uses' && (
              <Dialog title={`${key(dlg.r)}를 쓰는 곳`} onClose={() => setDlg(undefined)} footer={<button type="button" className="btn" onClick={() => setDlg(undefined)}>닫기</button>}>
                <UseList uses={dlg.r.uses} only={dlg.r.index} />
              </Dialog>
            )}
            {(dlg?.kind === 'add' || dlg?.kind === 'edit') && <RuleDialog tenant={tenant} v={v} edit={dlg.kind === 'edit' ? dlg.r : undefined} onClose={() => setDlg(undefined)} onDone={() => void q.refresh()} />}
            {dlg?.kind === 'remove' && <RemoveDialog tenant={tenant} v={v} r={dlg.r} onClose={() => setDlg(undefined)} onDone={() => void q.refresh()} />}
          </>
        )}
      </Load>
    </>
  );
}

function UseList({ uses, only }: { uses: TrustUse[]; only?: number }) {
  if (!uses.length) return <span className="small muted">없음</span>;
  return (
    <div className="table-wrap">
      <table className="tbl">
        <thead>
          <tr>
            <th>쓰는 곳</th>
            <th>이미지</th>
            {only !== undefined && <th>다른 출처</th>}
          </tr>
        </thead>
        <tbody>
          {uses.map((u) => (
            <tr key={`${useLabel(u)}/${u.image}`}>
              <td>{useLabel(u)}</td>
              <td className="mono small break-any">{u.image}</td>
              {only !== undefined && <td className="small">{u.rules.filter((i) => i !== only).length ? '있음' : <span style={{ color: 'var(--wa)' }}>없음 (빼면 막힘)</span>}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** 바꾼 규칙만 보내는 공통 흐름: 영향 미리보기 → 저장(set-trust {add, remove}) */
function useSave(tenant: string, v: ImageTrust) {
  const m = useMutation();
  // 창을 연 순간의 목록과 revision을 기준으로 고정한다
  const [base] = useState(() => ({ rules: plain(v), expected: v.revision }));
  const save = async (rules: Rule[]) => {
    if (m.op || m.error) m.reset();
    return m.run(imageTrustPath(tenant), { ...trustDelta(base.rules, rules), expected: base.expected }, 'PATCH');
  };
  return { m, save };
}
function useAffected(tenant: string, v: ImageTrust, rules: Rule[] | undefined) {
  const [state, setState] = useState<{ affected?: TrustUse[]; error?: unknown }>({});
  const [before] = useState(() => plain(v));
  const sig = rules ? JSON.stringify(rules) : '';
  useEffect(() => {
    if (!rules) return;
    let live = true;
    setState({});
    imageTrustPreview(tenant, trustDelta(before, rules).remove).then(
      (a) => live && setState({ affected: a.map((x) => ({ ...x, rules: x.rules ?? [] })) }),
      (e) => live && setState({ error: e }),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenant, sig]);
  return state;
}
const plain = (v: ImageTrust): Rule[] => v.rules.map((r) => ({ registry: r.registry, repository: r.repository }));
const RULE_RE = { registry: /^[a-z0-9.-]+(:\d{1,5})?$/, repository: /^(\*\*|[a-z0-9._-]+(\/[a-z0-9._-]+)*)$/ };

function SaveFooter({ m, finished, label, disabled, onClose, onSend, danger }: { m: ReturnType<typeof useMutation>; finished: boolean; label: string; disabled: boolean; onClose: () => void; onSend: () => void; danger?: boolean }) {
  return finished ? (
    <button type="button" className="btn primary" onClick={onClose}>
      닫기
    </button>
  ) : (
    <>
      <button type="button" className="btn" onClick={onClose}>
        취소
      </button>
      <button type="button" className={danger ? 'btn danger solid' : 'btn primary'} disabled={m.busy || disabled} onClick={onSend}>
        {m.busy ? '보내는 중…' : label}
      </button>
    </>
  );
}
function OpResult({ m, onDone }: { m: ReturnType<typeof useMutation>; onDone: () => void }) {
  return (
    <>
      {m.error !== undefined && <MutationError error={m.error} />}
      {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      {casFailed(m.op) && <div className="note wa small">그사이 다른 사람이 신뢰 출처를 바꿨습니다. 창을 닫고 새로 읽은 뒤 다시 하세요.</div>}
    </>
  );
}

function RuleDialog({ tenant, v, edit, onClose, onDone }: { tenant: string; v: ImageTrust; edit?: TrustRule; onClose: () => void; onDone: () => void }) {
  const [registry, setRegistry] = useState(edit?.registry ?? '');
  const [repository, setRepository] = useState(edit?.repository ?? '');
  const [review, setReview] = useState<Rule[]>();
  const { m, save } = useSave(tenant, v);
  const r = { registry: registry.trim(), repository: repository.trim() };
  const regBad = r.registry !== '' && !RULE_RE.registry.test(r.registry);
  const repoBad = r.repository !== '' && !RULE_RE.repository.test(r.repository);
  const dup = v.rules.some((x) => key(x) === key(r) && x !== edit);
  const ok = RULE_RE.registry.test(r.registry) && RULE_RE.repository.test(r.repository) && !dup && (!edit || key(edit) !== key(r));
  const matching = ok ? v.uses.filter((u) => matchRule(r, u.image)) : [];
  const next = review;
  const affected = useAffected(tenant, v, edit ? next : undefined);
  const [before] = useState(() => plain(v));
  const send = async () => {
    if (!next) return;
    const o = await save(next);
    if (o?.state === 'applied') onDone();
  };
  const finished = m.op?.state === 'applied';
  if (next)
    return (
      <Dialog title="신뢰 출처 변경" onClose={onClose} footer={<SaveFooter m={m} finished={finished} label="저장 (set-trust)" disabled={!!edit && !affected.affected && !affected.error} onClose={onClose} onSend={() => void send()} />}>
        <div className="col" style={{ gap: 12 }}>
          <DiffView
            lines={[
              ...before.map((x) => ({ op: (next.some((y) => key(y) === key(x)) ? ' ' : '-') as ' ' | '-', text: key(x) })),
              ...next.filter((y) => !before.some((x) => key(x) === key(y))).map((y) => ({ op: '+' as const, text: key(y) })),
            ]}
          />
          {edit && affected.affected && affected.affected.length > 0 && <div className="note wa small">이 변경으로 신뢰를 잃는 곳 {affected.affected.length}개: {appsOf(affected.affected).join(', ')}. 새 패턴이 다시 허용하는지는 저장 뒤 목록에서 확인하세요.</div>}
          {affected.error !== undefined && <MutationError error={affected.error} />}
          <OpResult m={m} onDone={onDone} />
        </div>
      </Dialog>
    );
  return (
    <Dialog
      title={edit ? `${key(edit)} 경로 바꾸기` : '신뢰 출처 추가'}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn primary" disabled={!ok} onClick={() => setReview(edit ? before.map((x) => (key(x) === key(edit) ? r : x)) : [...before, r])}>
            변경 검토
          </button>
        </>
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <Field label="저장소 주소" hint="소문자 host[:포트]. Docker Hub는 docker.io" error={regBad ? '소문자 host[:포트]' : undefined}>
          <input className="mono" value={registry} onChange={(e) => setRegistry(e.target.value)} placeholder="quay.io" spellCheck={false} autoComplete="off" />
        </Field>
        <Field label="경로" hint="** = 그 저장소 전부, 아니면 정확한 경로 하나" error={repoBad ? '소문자 경로 하나 또는 **' : dup ? '이미 있는 출처입니다' : undefined}>
          <input className="mono" value={repository} onChange={(e) => setRepository(e.target.value)} placeholder="prometheus/node-exporter" spellCheck={false} autoComplete="off" />
        </Field>
        <Field label="받기 방식">
          <select disabled value="anonymous">
            <option value="anonymous">익명 받기 (로그인이 필요하면 외부 저장소로 등록)</option>
          </select>
        </Field>
        {ok && (
          <div className="note small">
            이 출처에 맞는 지금 쓰는 이미지: {matching.length}개{matching.length ? ` (${appsOf(matching).slice(0, 4).join(' · ')})` : ''}
          </div>
        )}
      </div>
    </Dialog>
  );
}

function RemoveDialog({ tenant, v, r, onClose, onDone }: { tenant: string; v: ImageTrust; r: TrustRule; onClose: () => void; onDone: () => void }) {
  const [next] = useState(() => plain(v).filter((x) => key(x) !== key(r)));
  const affected = useAffected(tenant, v, next);
  const { m, save } = useSave(tenant, v);
  const [typed, setTyped] = useState('');
  const hit = affected.affected ?? [];
  const send = async () => {
    const o = await save(next);
    if (o?.state === 'applied') onDone();
  };
  const finished = m.op?.state === 'applied';
  return (
    <Dialog
      title={`${key(r)}${eulReul(r.repository)} 뺄까요?`}
      danger
      onClose={onClose}
      footer={<SaveFooter m={m} finished={finished} label="빼기" danger disabled={(!affected.affected && affected.error === undefined) || (hit.length > 0 && typed !== r.registry)} onClose={onClose} onSend={() => void send()} />}
    >
      <div className="col" style={{ gap: 12 }}>
        {!affected.affected && affected.error === undefined && <span className="small muted">영향받는 곳을 계산하는 중…</span>}
        {affected.error !== undefined && <MutationError error={affected.error} />}
        {affected.affected &&
          (hit.length ? (
            <>
              <div>
                이 출처 이미지를 쓰는 {appsOf(hit).length}곳({appsOf(hit).slice(0, 3).join(', ')}
                {appsOf(hit).length > 3 ? ' 등' : ''})이 다음 재시작·이동·배포 때 막힙니다. 빌드의 FROM {r.registry}/… 도 막힙니다.
              </div>
              <UseList uses={hit} />
              <Field
                label={
                  <>
                    확인하려면 <b className="mono">{r.registry}</b>
                    {eulReul(r.registry)} 입력하세요
                  </>
                }
              >
                <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value)} disabled={finished} autoComplete="off" spellCheck={false} />
              </Field>
            </>
          ) : (
            <div>이 출처만으로 허용되는 지금의 이미지는 없습니다. 빼도 지금 쓰는 곳은 막히지 않습니다.</div>
          ))}
        <OpResult m={m} onDone={onDone} />
      </div>
    </Dialog>
  );
}
