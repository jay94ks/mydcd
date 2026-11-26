// SPDX-License-Identifier: Apache-2.0

// 이미지 관리 › 내장 저장소 탭 (UI-80, 캔버스 Registry · RegistryIx).
// 계약: docs/reference/web-api.md "내장 저장소 (UI-80)". 정의 검사·데이터 저장소 확인·서버 권한은 mydcd 몫이다.
// 켜짐(enabled)과 서비스 중(status=serving)은 다르다: 서비스 중은 서버 보고이지 외부 TLS 접속 검사가 아니다.
import { useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, api, noEndpoint } from '../api/client';
import { dashboard, imageTrust, imageTrustPath, registries, registryPath, volumes as fetchVolumes } from '../api/endpoints';
import type { RegistryStatus } from '../api/dto';
import type { RegistryView } from '../api/types';
import { Link } from 'react-router-dom';
import { useSession, useTenantRole } from '../auth/session';
import { Badge, Card, Field, HelpBox, KV, type Tone } from '../components/ui';
import { Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { Dialog } from '../components/Dialog';
import { DiffView } from '../components/Code';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { fmtBytes, until } from '../lib/format';
import { eulReul } from '../lib/josa';
import { usePoll } from '../lib/usePoll';

const NEED = '이 작업 공간의 관리 권한이 필요합니다';
const GiB = 1 << 30;

export const STATUS: Record<RegistryStatus, [string, Tone]> = {
  serving: ['서비스 중', 'ok'],
  pending: ['시작 대기', 'pr'],
  draining: ['비우는 중', 'wa'],
  stopping: ['멈추는 중', 'wa'],
  stopped: ['정지', 'un'],
  deleted: ['삭제됨', 'un'],
};

const ERR: Record<string, string> = {
  deleted: '지운 저장소 ID입니다. 다른 ID를 쓰세요.',
  'not-stopped': '멈춘 뒤에만 지울 수 있습니다. 먼저 정지하세요.',
};
const Err = ({ e }: { e: unknown }) => {
  if (e === undefined) return null;
  if (e instanceof ApiError && ERR[e.code]) return <div className="note wa small">{ERR[e.code]}</div>;
  return <MutationError error={e} />;
};

/** 저장소 주소(authority)를 쓰는 지금의 이미지 사용 수. 신뢰 출처 끝점이 없으면 undefined */
function useRegistryUses(tenant: string) {
  const q = usePoll((s) => imageTrust(tenant, s).catch((e) => (noEndpoint(e) ? undefined : Promise.reject(e))), [tenant]);
  return (endpoint: string) => {
    if (!q.data) return undefined;
    const apps = new Set(q.data.uses.filter((u) => u.image.startsWith(`${endpoint}/`)).map((u) => u.app ?? `단독 ${u.standalone}`));
    return [...apps];
  };
}

export function RegistryTab() {
  const { tenant, canDeploy } = useTenantRole();
  const q = usePoll((s) => registries(tenant, s), [tenant]);
  const usesOf = useRegistryUses(tenant);
  const [sel, setSel] = useState<string>();
  const [cred, setCred] = useState<string>();
  const [dlg, setDlg] = useState<{ kind: 'create' } | { kind: 'stop' | 'delete' | 'start'; r: RegistryView }>();
  const refresh = () => void q.refresh();
  return (
    <>
      <HelpBox terms="이미지 저장소 (Registry) · 접속 주소 (endpoint) · 받기/올리기 (pull/push)">
        <b>이 화면은</b> 앱 이미지를 올려 두고 받아 가는 이 작업 공간({tenant})의 이미지 저장소를 관리합니다. 이미지 저장소는 작업 공간마다 따로 있어서, 위에서 작업 공간을 바꾸면 그 작업 공간의 저장소만 보입니다. 다른 작업 공간의 앱은 이 저장소의 이미지를 받을 수 없습니다.
      </HelpBox>
      <Card
        title="내장 저장소"
        actions={
          <>
            <Refresh q={q} poll={false} />
            <button className="btn primary" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => setDlg({ kind: 'create' })}>
              이미지 저장소 만들기
            </button>
          </>
        }
      >
        <Load q={q} what="저장소 목록을 읽지 못했습니다">
          {(p) => {
            const rows = p.items;
            const cur = rows.find((r) => r.id === sel) ?? rows.find((r) => !r.deleted);
            return (
              <>
                <div className="table-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>접속 주소</th>
                        <th>서버</th>
                        <th>목표</th>
                        <th>관측</th>
                        <th aria-label="작업" />
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((r) => {
                        const st = r.status ? STATUS[r.status] : undefined;
                        const stopped = r.status === 'stopped';
                        return (
                          <tr key={r.id} className={cur?.id === r.id ? 'sel' : undefined} style={cur?.id === r.id ? { background: '#F5F9FF' } : undefined} onClick={() => !r.deleted && setSel(r.id)}>
                            <td>
                              <b>{r.id}</b>
                              {r.name && r.name !== r.id && <div className="small muted">{r.name}</div>}
                            </td>
                            <td className="mono small">{r.endpoint}</td>
                            <td>{r.node ?? '—'}</td>
                            <td>{r.enabled === undefined ? '—' : r.enabled ? <Badge tone="ok">켜짐</Badge> : <Badge tone="un">꺼짐</Badge>}</td>
                            <td>{st ? <Badge tone={st[1]}>{st[0]}</Badge> : <Badge tone={r.active ? 'ok' : 'un'}>{r.active ? '사용 중' : '꺼짐'}</Badge>}</td>
                            <td className="row" style={{ gap: 6, justifyContent: 'flex-end' }} onClick={(e) => e.stopPropagation()}>
                              {r.deleted ? null : r.enabled ? (
                                <button className="btn sm" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => setDlg({ kind: 'stop', r })}>
                                  정지
                                </button>
                              ) : (
                                <button className="btn sm" disabled={!canDeploy} title={canDeploy ? undefined : NEED} onClick={() => setDlg({ kind: 'start', r })}>
                                  시작
                                </button>
                              )}
                              {!r.deleted && !r.enabled && (
                                <button className="btn sm danger" disabled={!canDeploy || !stopped} title={!canDeploy ? NEED : !stopped ? '완전히 멈춘 뒤에 지울 수 있습니다' : undefined} onClick={() => setDlg({ kind: 'delete', r })}>
                                  삭제
                                </button>
                              )}
                              {!r.deleted && (
                                <button className="btn sm" disabled={!r.enabled} title={r.enabled ? undefined : '켜진 저장소에서만 발급합니다'} onClick={() => (setSel(r.id), setCred(r.id))}>
                                  자격 발급
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                      {!rows.length && (
                        <tr>
                          <td colSpan={6} className="muted">
                            이 작업 공간에 내장 저장소가 없습니다.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
                <span className="small muted">서비스 중은 서버 보고 관측이며 외부 TLS 접속 성공을 뜻하지 않습니다. 삭제는 정의만 지우고 데이터 저장소 데이터는 보존합니다.</span>
                <div className="grid wide">
                  {cur && cur.limits && <SettingsCard key={cur.id} tenant={tenant} r={cur} canDeploy={canDeploy} onDone={refresh} />}
                  {cur && !cur.deleted && <CredentialCard key={`cred/${cur.id}`} tenant={tenant} r={cur} focus={cred === cur.id} />}
                </div>
              </>
            );
          }}
        </Load>
      </Card>
      {dlg?.kind === 'create' && <CreateDialog tenant={tenant} taken={(q.data?.items ?? []).map((r) => r.id)} onClose={() => setDlg(undefined)} onDone={refresh} />}
      {dlg && dlg.kind !== 'create' && <ActDialog tenant={tenant} r={dlg.r} act={dlg.kind} apps={usesOf(dlg.r.endpoint)} onClose={() => setDlg(undefined)} onDone={refresh} />}
    </>
  );
}

// ── 설정 (변경 검토 → 적용) ──────────────────────────────

/** 노드가 보고한 보관함 인증서 ID. 시스템 관리자에게만 상세로 가는 링크 */
export function RegistryCert({ id }: { id?: string }) {
  const admin = !!useSession().user.systemAdmin;
  if (!id) return <span className="muted small">아직 보고 없음</span>;
  const short = id.slice(0, 12);
  return admin ? (
    <Link className="mono" to={`/system/domains/certs/${id}`} title={id}>
      {short}
    </Link>
  ) : (
    <span className="mono" title={id}>
      {short}
    </span>
  );
}

interface Form {
  endpoint: string;
  address: string;
  node: string;
  quotaGiB: string;
  maxRequests: string;
}
const formOf = (r: RegistryView): Form => ({
  endpoint: r.endpoint,
  address: r.address ?? '',
  node: r.node ?? '',
  quotaGiB: r.limits ? String(+(r.limits.blobs.totalBytes / GiB).toFixed(2)) : '',
  maxRequests: r.limits ? String(r.limits.maxRequests) : '',
});
const FORM_LABEL: Record<keyof Form, string> = { endpoint: 'authority', address: 'address', node: 'node', quotaGiB: 'quota', maxRequests: 'max_requests' };
const shown = (k: keyof Form, v: string) => (k === 'quotaGiB' ? `${v}GiB` : v);

/** authority(host[:port])의 포트. 없으면 443 */
export const authorityPort = (a: string) => {
  const m = /:(\d+)$/.exec(a.trim());
  return m ? m[1] : '443';
};
/** 바뀐 칸만 PUT 본문으로. limits는 읽은 값을 고쳐 통째로 보낸다 */
export function registryChanges(r: RegistryView, f: Form): Record<string, unknown> {
  const o = formOf(r);
  const body: Record<string, unknown> = {};
  if (f.endpoint.trim() !== o.endpoint) body.authority = f.endpoint.trim();
  if (f.address.trim() !== o.address) body.address = f.address.trim();
  if (f.node !== o.node) body.node = f.node;
  if (r.limits && (f.quotaGiB !== o.quotaGiB || f.maxRequests !== o.maxRequests)) {
    const total = Math.round(Number(f.quotaGiB) * GiB);
    body.limits = { ...r.limits, blobs: { ...r.limits.blobs, totalBytes: total, blobBytes: Math.min(r.limits.blobs.blobBytes, total) }, maxRequests: Number(f.maxRequests) };
  }
  return body;
}

function SettingsCard({ tenant, r, canDeploy, onDone }: { tenant: string; r: RegistryView; canDeploy: boolean; onDone: () => void }) {
  const nodes = usePoll((s) => dashboard(tenant, s), [tenant]);
  const [f, setF] = useState<Form>(() => formOf(r));
  const [review, setReview] = useState(false);
  // 적용 뒤(revision이 바뀌면) 칸을 새로 읽은 값으로 맞춘다. 검토 창은 닫지 않는다
  const rev = r.revision;
  useEffect(() => setF(formOf(r)), [rev]); // eslint-disable-line react-hooks/exhaustive-deps
  const set = (k: keyof Form) => (e: { target: { value: string } }) => setF((x) => ({ ...x, [k]: e.target.value }));
  const o = formOf(r);
  const dirty = (Object.keys(f) as (keyof Form)[]).filter((k) => f[k].trim() !== o[k]);
  const portBad = authorityPort(f.endpoint) !== (/:(\d+)$/.exec(f.address.trim())?.[1] ?? '');
  const numBad = !(Number(f.quotaGiB) > 0) || !(Number.isInteger(Number(f.maxRequests)) && Number(f.maxRequests) > 0);
  const off = !canDeploy || r.deleted;
  return (
    <Card title={`${r.id} 설정`}>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
        <Field label="접속 주소" hint="TLS 이름 host[:포트]">
          <input className="mono" value={f.endpoint} onChange={set('endpoint')} disabled={off} spellCheck={false} />
        </Field>
        <Field label="받는 주소" hint="서버에서 듣는 IP:포트" error={portBad ? '접속 주소의 포트와 같아야 합니다' : undefined}>
          <input className="mono" value={f.address} onChange={set('address')} disabled={off} spellCheck={false} />
        </Field>
        <Field label="TLS 인증서" hint="접속 주소의 호스트로 인증서 보관함에서 찾습니다">
          <RegistryCert id={r.certificateID} />
        </Field>
        <Field label="저장 데이터 저장소" hint="만든 뒤에는 바꿀 수 없습니다">
          <select value={r.volume ?? ''} disabled>
            <option>{r.volume ?? '—'} (보존 고정)</option>
          </select>
        </Field>
        <Field label="서버">
          <select value={f.node} onChange={set('node')} disabled={off}>
            {!(nodes.data?.nodes ?? []).some((n) => n.id === f.node) && <option value={f.node}>{f.node || '—'}</option>}
            {(nodes.data?.nodes ?? []).map((n) => (
              <option key={n.id} value={n.id} disabled={n.phase !== 'ready' && n.id !== o.node}>
                {n.id}
                {n.phase !== 'ready' ? ' (쓸 수 없음)' : ''}
              </option>
            ))}
          </select>
        </Field>
        <Field label="저장 상한 (GiB)" hint={r.limits ? `지금 ${fmtBytes(r.limits.blobs.totalBytes)}` : undefined}>
          <input type="number" min={1} value={f.quotaGiB} onChange={set('quotaGiB')} disabled={off} />
        </Field>
        <Field label="동시 요청 상한">
          <input type="number" min={1} value={f.maxRequests} onChange={set('maxRequests')} disabled={off} />
        </Field>
      </div>
      <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
        {dirty.length > 0 && (
          <button className="btn" onClick={() => setF(o)}>
            되돌리기
          </button>
        )}
        <button className="btn primary" disabled={off || !dirty.length || portBad || numBad} title={!canDeploy ? NEED : undefined} onClick={() => setReview(true)}>
          변경 검토
        </button>
      </div>
      {review && (
        <SettingsReview
          tenant={tenant}
          r={r}
          lines={dirty.flatMap((k) => [
            { op: '-' as const, text: `${FORM_LABEL[k]}: ${shown(k, o[k]) || '—'}` },
            { op: '+' as const, text: `${FORM_LABEL[k]}: ${shown(k, f[k].trim())}` },
          ])}
          body={registryChanges(r, f)}
          onClose={() => setReview(false)}
          onDone={onDone}
        />
      )}
    </Card>
  );
}

function SettingsReview({ tenant, r, lines, body, onClose, onDone }: { tenant: string; r: RegistryView; lines: { op: '+' | '-'; text: string }[]; body: Record<string, unknown>; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  // 검토 창을 연 순간의 revision을 expected로 고정한다
  const [sent] = useState(() => ({ ...body, expected: r.revision }));
  const [diff] = useState(lines);
  const send = async () => {
    if (m.op || m.error) m.reset();
    const o = await m.run(registryPath(tenant, r.id), sent, 'PUT');
    if (o?.state === 'applied') onDone();
  };
  const finished = m.op?.state === 'applied';
  return (
    <Dialog
      title={`${r.id} 설정 변경`}
      onClose={onClose}
      footer={
        finished ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={m.busy} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '적용'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <DiffView lines={diff} />
        {r.enabled && <span className="small muted">저장소가 잠깐 다시 시작됩니다.</span>}
        <Err e={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

// ── 정지 · 시작 · 삭제 ──────────────────────────────

function ActDialog({ tenant, r, act, apps, onClose, onDone }: { tenant: string; r: RegistryView; act: 'stop' | 'start' | 'delete'; apps?: string[]; onClose: () => void; onDone: () => void }) {
  const m = useMutation();
  const toast = useToast();
  const [typed, setTyped] = useState('');
  const need = act === 'start' ? undefined : r.id;
  const send = async () => {
    if (m.op || m.error) m.reset();
    const o = await m.run(`${registryPath(tenant, r.id)}/${act}`, { expected: r.revision });
    if (o?.state === 'applied') {
      onDone();
      if (act === 'start') (toast(`${r.id} 시작을 요청했습니다. 서비스 중이 되면 상태가 바뀝니다.`), onClose());
    }
  };
  const finished = m.op?.state === 'applied';
  const title = act === 'stop' ? `${r.id}${eulReul(r.id)} 정지할까요?` : act === 'delete' ? `${r.id}${eulReul(r.id)} 삭제할까요?` : `${r.id}${eulReul(r.id)} 시작할까요?`;
  return (
    <Dialog
      title={title}
      danger={act !== 'start'}
      width={act === 'start' ? 400 : 560}
      onClose={onClose}
      footer={
        finished ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className={act === 'start' ? 'btn primary' : 'btn danger solid'} disabled={m.busy || (!!need && typed !== need)} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : act === 'stop' ? '정지' : act === 'delete' ? '삭제' : '시작'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        {act === 'stop' && (
          <div>
            정지하는 동안 이 저장소에서 이미지를 받을 수 없습니다. 이미 받아 둔 이미지로 도는 컨테이너는 그대로지만 재시작·이동·배포는 실패합니다.
            {apps ? ` 쓰는 앱 ${apps.length}개${apps.length ? ` (${apps.slice(0, 3).join(', ')}${apps.length > 3 ? ' 등' : ''})` : ''}.` : ''}
          </div>
        )}
        {act === 'delete' && <div>저장소 정의만 지웁니다. 데이터 저장소 {r.volume ?? '—'}는 남고, 데이터 저장소 화면에서 따로 지울 수 있습니다. 지운 ID는 다시 쓸 수 없습니다.</div>}
        {act === 'start' && <div>{r.node ?? '서버'}에서 저장소를 다시 켭니다. 서버가 보고하면 서비스 중으로 바뀝니다.</div>}
        {need && (
          <Field
            label={
              <>
                확인하려면 <b className="mono">{need}</b>
                {eulReul(need)} 입력하세요
              </>
            }
          >
            <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value)} disabled={finished} autoComplete="off" spellCheck={false} />
          </Field>
        )}
        <Err e={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && onDone())} />}
      </div>
    </Dialog>
  );
}

// ── 만들기 ──────────────────────────────

const ID_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const AUTH_RE = /^[a-z0-9.-]+(:\d{1,5})?$/;

function CreateDialog({ tenant, taken: live, onClose, onDone }: { tenant: string; taken: string[]; onClose: () => void; onDone: () => void }) {
  const [taken] = useState(live);
  const vols = usePoll((s) => fetchVolumes(tenant, s), [tenant]);
  const nodes = usePoll((s) => dashboard(tenant, s), [tenant]);
  // 보존 고정 데이터 저장소만 저장소를 담을 수 있다(mydcd가 최종 판단)
  const candidates = useMemo(() => (vols.data?.items ?? []).filter((v) => v.kind === 'fixed' && v.retain && !v.app), [vols.data]);
  const [id, setId] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [volume, setVolume] = useState('');
  const [node, setNode] = useState('');
  const [trust, setTrust] = useState(true);
  const m = useMutation();
  const t = useMutation();
  const [trustErr, setTrustErr] = useState<unknown>();
  const vol = candidates.find((v) => v.name === volume);
  const idBad = id !== '' && (!ID_RE.test(id) || taken.includes(id));
  const epBad = endpoint !== '' && !AUTH_RE.test(endpoint.trim());
  const ok = ID_RE.test(id) && !taken.includes(id) && AUTH_RE.test(endpoint.trim()) && !!vol;
  // 내장 저장소는 작업 공간 전용이라 그 저장소 전부(**)를 믿는다(mydcd는 경로 ** 또는 정확한 경로만 받는다)
  const rule = { registry: endpoint.trim(), repository: '**' };
  const addTrust = async () => {
    setTrustErr(undefined);
    try {
      const cur = await imageTrust(tenant);
      if (cur.rules.some((x) => x.registry === rule.registry && x.repository === rule.repository)) return;
      if (t.op || t.error) t.reset();
      await t.run(imageTrustPath(tenant), { rules: [...cur.rules.map((x) => ({ registry: x.registry, repository: x.repository })), rule], expected: cur.revision }, 'PUT');
    } catch (e) {
      setTrustErr(e);
    }
  };
  const send = async () => {
    if (m.op || m.error) m.reset();
    const body: Record<string, unknown> = { authority: endpoint.trim(), volume };
    if (node && node !== vol?.node) body.node = node;
    const o = await m.run(registryPath(tenant, id), body, 'PUT');
    if (o?.state === 'applied') await applied();
  };
  // 적용은 send의 응답과 OpPanel 갱신 두 곳에서 올 수 있다. 한 번만 처리한다
  const done = useRef(false);
  const applied = async () => {
    if (done.current) return;
    done.current = true;
    onDone();
    if (trust) await addTrust();
  };
  const finished = m.op?.state === 'applied';
  return (
    <Dialog
      title="이미지 저장소 만들기"
      onClose={onClose}
      footer={
        finished ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={m.busy || !ok} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : '만들기'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <Field label="ID" error={idBad ? (taken.includes(id) ? '이미 있는 ID입니다' : '소문자·숫자·- , 63자 이하') : undefined}>
          <input className="mono" value={id} onChange={(e) => setId(e.target.value)} disabled={finished} placeholder="shop-ci" spellCheck={false} autoComplete="off" />
        </Field>
        <Field label="접속 주소" hint="TLS 이름 host[:포트]. 받는 주소는 0.0.0.0:같은 포트로 정해집니다" error={epBad ? '소문자 host[:포트]' : undefined}>
          <input className="mono" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} disabled={finished} placeholder="registry-ci.mydc:5000" spellCheck={false} autoComplete="off" />
        </Field>
        <Field label="저장 데이터 저장소" hint="이 작업 공간의 보존 고정 데이터 저장소. 저장소 서버는 기본으로 그 서버입니다">
          <select value={volume} onChange={(e) => (setVolume(e.target.value), setNode(''))} disabled={finished}>
            <option value="">고르세요</option>
            {candidates.map((v) => (
              <option key={v.key} value={v.name}>
                {v.name} · {v.node ?? '—'}
                {v.capacityBytes ? ` (${fmtBytes(v.capacityBytes)})` : ''}
              </option>
            ))}
          </select>
        </Field>
        {vols.data && !candidates.length && <div className="note wa small">보존 고정 데이터 저장소가 없습니다. 데이터 저장소 화면에서 먼저 만드세요.</div>}
        <Field label="서버">
          <select value={node || vol?.node || ''} onChange={(e) => setNode(e.target.value)} disabled={finished || !vol}>
            {!vol && <option value="">데이터 저장소를 먼저 고르세요</option>}
            {(nodes.data?.nodes ?? []).map((n) => (
              <option key={n.id} value={n.id} disabled={n.phase !== 'ready'}>
                {n.id}
                {n.id === vol?.node ? ' (데이터 저장소 서버)' : ''}
              </option>
            ))}
          </select>
        </Field>
        <KV
          items={[
            ['저장 상한 · 요청 상한', <span className="muted">기본값(저장 상한 = 데이터 저장소 용량). 만든 뒤 설정에서 바꿉니다.</span>],
            ['TLS 인증서', <span className="muted">접속 주소의 호스트로 인증서 보관함에서 찾습니다. 그 호스트가 등록된 도메인 아래에 있어야 합니다.</span>],
          ]}
        />
        <label className="row small" style={{ gap: 8 }}>
          <input type="checkbox" checked={trust} onChange={(e) => setTrust(e.target.checked)} disabled={finished} />
          이미지 신뢰 출처에 <code>{`${endpoint.trim() || '접속 주소'}/**`}</code> 추가
        </label>
        <Err e={m.error} />
        {m.op && <OpPanel op={m.op} onChange={(o) => (m.setOp(o), o.state === 'applied' && void applied())} />}
        {t.op && (
          <>
            <span className="small">신뢰 출처 추가</span>
            <OpPanel op={t.op} onChange={t.setOp} />
          </>
        )}
        {(t.error !== undefined || trustErr !== undefined) && (
          <>
            <div className="note wa small">저장소는 만들었지만 신뢰 출처를 추가하지 못했습니다. 신뢰 출처 탭에서 추가하세요.</div>
            <MutationError error={t.error ?? trustErr} />
          </>
        )}
      </div>
    </Dialog>
  );
}

// ── 접근 자격 발급 (UI-81) ──────────────────────────────
// op가 아니라 바로 응답한다(no-store). 토큰은 이 카드의 상태에만 두고, 닫거나 다른 저장소를 고르면 버린다.
// 저장소·로그·작업 기록·URL 어디에도 넣지 않는다.

interface Cred {
  username: string;
  token: string;
  authority: string;
  repository: string;
  access: string[];
  expiresAt: string;
}
const ACCESS: [string, string][] = [
  ['pull', '받기'],
  ['push', '올리기'],
  ['pull,push', '받기,올리기'],
];

function CredentialCard({ tenant, r, focus }: { tenant: string; r: RegistryView; focus: boolean }) {
  const toast = useToast();
  const [repo, setRepo] = useState(`${tenant}/`);
  const [access, setAccess] = useState('pull');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [cred, setCred] = useState<Cred>();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focus) ref.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [focus]);
  // 만료되면 토큰을 버린다
  useEffect(() => {
    if (!cred) return;
    const ms = Date.parse(cred.expiresAt) - Date.now();
    const t = setTimeout(() => setCred(undefined), Math.max(0, ms));
    return () => clearTimeout(t);
  }, [cred]);
  const okRepo = /^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*$/.test(repo);
  const issue = async () => {
    setBusy(true);
    setError(undefined);
    setCred(undefined);
    try {
      setCred(await api.post<Cred>(`${registryPath(tenant, r.id)}/credential`, { repository: repo, access }));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const login = cred ? `docker login ${cred.authority} -u ${cred.username} --password-stdin` : '';
  return (
    <Card title="접근 자격 발급 (UI-81)" className={focus ? 'focus' : undefined}>
      <div ref={ref} className="col" style={{ gap: 12 }}>
        <span className="small muted">
          {r.id} ({r.endpoint})에서 이미지를 받거나 올릴 짧은 자격을 발급합니다. 받기는 배포 권한, 올리기는 저장소 관리 권한이 필요합니다.
        </span>
        <div className="grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0,1fr))', gap: 12 }}>
          <Field label="이미지 이름" error={repo && !okRepo ? '소문자 경로 (예: shop/web)' : undefined}>
            <input className="mono" value={repo} onChange={(e) => setRepo(e.target.value.trim())} spellCheck={false} autoComplete="off" />
          </Field>
          <Field label="권한">
            <select value={access} onChange={(e) => setAccess(e.target.value)}>
              {ACCESS.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <button className="btn primary" style={{ width: 'fit-content' }} disabled={busy || !okRepo || !r.enabled} title={r.enabled ? undefined : '켜진 저장소에서만 발급합니다'} onClick={() => void issue()}>
          {busy ? '발급 중…' : '발급'}
        </button>
        {error !== undefined && (error instanceof ApiError && error.status === 403 ? <div className="note wa small">발급하지 못했습니다. 저장소가 멈췄거나 이 권한이 없습니다.</div> : <MutationError error={error} />)}
        {cred && (
          <div style={{ border: '1px solid #DDE1E6', borderRadius: 8, padding: 12, display: 'flex', flexDirection: 'column', gap: 8, background: '#F6F8FA' }}>
            <div className="row between small">
              <span>
                사용자 이름 <span className="mono">{cred.username}</span> · {cred.access.join(', ')} · <span className="mono">{cred.repository}</span>
              </span>
              <span className="muted">{until(cred.expiresAt)} 만료</span>
            </div>
            <div className="mono break-any" style={{ fontSize: 12 }}>
              {cred.token}
            </div>
            <div className="row between">
              <span className="small" style={{ color: '#8A3300' }}>
                이 카드를 닫으면 다시 볼 수 없습니다. 저장되지 않습니다.
              </span>
              <span className="row" style={{ gap: 6 }}>
                <button className="btn sm" onClick={() => void navigator.clipboard?.writeText(cred.token).then(() => toast(`토큰을 복사했습니다. ${until(cred.expiresAt)} 만료됩니다.`))}>
                  복사
                </button>
                <button className="btn sm" onClick={() => setCred(undefined)}>
                  닫기
                </button>
              </span>
            </div>
            <span className="small muted">
              <code className="break-any">{login}</code> 에 토큰을 표준 입력으로 넣으세요.
            </span>
          </div>
        )}
      </div>
    </Card>
  );
}
