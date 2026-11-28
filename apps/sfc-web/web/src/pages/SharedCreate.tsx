// SPDX-License-Identifier: Apache-2.0

// 공유 자원 만들기 다이얼로그(캔버스 v82 NetworksIx · VolumesIx · VaultIx).
// 칸 검사는 입력을 돕는 정도이고, 권한·중복·겹침의 최종 판단은 웹 서버(422)와 sfcd(결과 코드)가 한다.
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { enc } from '../api/client';
import { apps as fetchApps, dashboard, storageRoots, tenantStorage, usableRoot, vaultList, type VaultScope } from '../api/endpoints';
import type { NetworkView, OpView, SecretView, StorageRoot } from '../api/types';
import { Dialog } from '../components/Dialog';
import { Field } from '../components/ui';
import { MutationError, OpPanel, casFailed, useMutation } from '../components/OpPanel';
import { usePoll } from '../lib/usePoll';
import { fmtBytes } from '../lib/format';
import { cidrProblem, firstHost, hostIn, parseCidr, suggestCidr } from '../lib/cidr';
import { appsLive } from '../lib/liveTopics';

const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const nameProblem = (n: string, taken: string[], what: string) =>
  !n ? undefined : !NAME_RE.test(n) ? '소문자·숫자·-만 쓸 수 있습니다' : taken.includes(n) ? `같은 이름의 ${what}이(가) 있습니다` : undefined;
const GiB = 1024 ** 3;
const SERVER_WAIT = '서버 기능 대기';

/** 서버 고르기 칸에 쓸 서버 목록(남은 디스크 함께) */
export function useNodes(tenant: string) {
  const d = usePoll((s) => dashboard(tenant, s), [tenant]);
  return (d.data?.nodes ?? []).map((n) => ({ id: n.id, free: n.disk ? n.disk.total - n.disk.used : undefined }));
}
const nodeLabel = (n: { id: string; free?: number }) => (n.free !== undefined ? `${n.id} (남은 ${fmtBytes(n.free)})` : n.id);

type Step = {
  title: string;
  run: () => Promise<OpView | undefined>;
  /** 보관함 쓰기(값·비밀번호): 같은 opId로 이어 가기(값 함께 / 값 없이), 새 opId로 다시 */
  again?: (withValue: boolean) => Promise<OpView | undefined>;
  fresh?: () => Promise<OpView | undefined>;
};

/**
 * 만들기 다이얼로그 틀. review가 있으면 '변경 검토' → 요약 → '만들기', 없으면 바로 보낸다.
 * steps는 차례로 보낸다(앞 단계가 applied일 때만 다음).
 */
function CreateDialog({
  title,
  ok,
  review,
  valid,
  summary,
  steps,
  ms,
  onClose,
  onDone,
  children,
}: {
  title: string;
  ok: string;
  review: boolean;
  valid: boolean;
  summary: [string, ReactNode][];
  steps: Step[];
  ms: ReturnType<typeof useMutation>[];
  onClose: () => void;
  onDone: () => void;
  children: ReactNode;
}) {
  const [phase, setPhase] = useState<'edit' | 'review' | 'sent'>('edit');
  const [ops, setOps] = useState<(OpView | undefined)[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const done = useRef(false);
  /** from번째 단계부터 차례로 보낸다. first가 있으면 그 단계는 first로 보낸다(다시 보내기) */
  const sendFrom = async (from: number, first?: () => Promise<OpView | undefined>) => {
    setBusy(true);
    setError(undefined);
    setPhase('sent');
    const out = ops.slice(0, from);
    try {
      for (let i = from; i < steps.length; i++) {
        const op = await (i === from && first ? first() : steps[i].run());
        out[i] = op;
        setOps([...out]);
        if (!op || op.state !== 'applied') break;
      }
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
    if (out.length === steps.length && out.every((o) => o?.state === 'applied') && !done.current) {
      done.current = true;
      onDone();
    }
  };
  const send = () => sendFrom(0);
  const footer =
    phase === 'sent' ? (
      <>
        {!busy && ops.some((o) => !o) && (
          <button className="btn" onClick={() => setPhase(review ? 'review' : 'edit')}>
            뒤로
          </button>
        )}
        <button className="btn" onClick={onClose} disabled={busy}>
          닫기
        </button>
      </>
    ) : phase === 'review' ? (
      <>
        <button className="btn" onClick={() => setPhase('edit')}>
          뒤로
        </button>
        <button className="btn primary" disabled={busy} onClick={() => void send()}>
          만들기
        </button>
      </>
    ) : (
      <>
        <button className="btn" onClick={onClose}>
          취소
        </button>
        <button className="btn primary" disabled={!valid || busy} onClick={() => (review ? setPhase('review') : void send())}>
          {review ? '변경 검토' : ok}
        </button>
      </>
    );
  return (
    <Dialog title={title} onClose={busy ? () => undefined : onClose} footer={footer}>
      {phase === 'edit' && <div className="col" style={{ gap: 12 }}>{children}</div>}
      {phase === 'review' && (
        <div className="col" style={{ gap: 10 }}>
          <div className="kv2">
            {summary.map(([k, v]) => (
              <span key={k} style={{ display: 'contents' }}>
                <span className="muted">{k}</span>
                <span>{v}</span>
              </span>
            ))}
          </div>
          {steps.length > 1 && (
            <ol className="small" style={{ margin: 0, paddingLeft: 18 }}>
              {steps.map((s) => (
                <li key={s.title}>{s.title}</li>
              ))}
            </ol>
          )}
          <span className="small muted">‘만들기’를 누르면 작업 원본에 서명해 저장한 뒤 sfcd로 보냅니다.</span>
        </div>
      )}
      {phase === 'sent' && (
        <div className="col" style={{ gap: 10 }}>
          {ops.map((op, i) =>
            op ? (
              <div key={i} className="col" style={{ gap: 6 }}>
                {steps.length > 1 && <b className="small">{steps[i].title}</b>}
                {casFailed(op) && <div className="note wa small">그사이 다른 사람이 바꿨습니다. 닫고 다시 해 주세요.</div>}
                <OpPanel op={op} onChange={(o) => setOps((xs) => xs.map((x, j) => (j === i ? o : x)))} onContinue={steps[i].again ? () => sendFrom(i, () => steps[i].again!(true)) : undefined} />
                {steps[i].again && op.state !== 'applied' && !busy && (
                  <div className="row">
                    {op.errorCode === 'needs-input' && (
                      <button className="btn sm primary" onClick={() => void sendFrom(i, () => steps[i].again!(true))}>
                        같은 작업으로 값 다시 보내기
                      </button>
                    )}
                    {op.errorCode === 'input-unknown' && (
                      <button className="btn sm primary" onClick={() => void sendFrom(i, () => steps[i].again!(false))}>
                        결과 확인 (값은 다시 보내지 않음)
                      </button>
                    )}
                    {op.state === 'failed' && op.errorCode === 'write-not-applied' && steps[i].fresh && (
                      <button className="btn sm primary" onClick={() => void sendFrom(i, steps[i].fresh)}>
                        새 작업으로 다시 넣기
                      </button>
                    )}
                  </div>
                )}
              </div>
            ) : null,
          )}
          {busy && <span className="small muted">보내는 중…</span>}
        </div>
      )}
      <MutationError error={error} />
      <StepErrors ms={ms} />
    </Dialog>
  );
}

/**
 * useMutation 하나를 Step으로. secret(값·비밀번호 칸 이름)을 주면 보관함 쓰기 규칙을 따른다:
 * 같은 opId로 이어 갈 때 input-unknown이면 값을 빼고 보내고, write-not-applied면 새 opId로 다시 넣는다.
 */
function useStep(title: string, path: string, body: () => Record<string, unknown>, secret?: string) {
  const m = useMutation();
  const step: Step = {
    title,
    // 보내지 못하면 undefined. 오류는 m.error로 남아 StepErrors가 보여 준다.
    run: () => m.run(path, body()),
  };
  if (secret) {
    step.again = (withValue) => {
      const b = body();
      if (!withValue) delete b[secret];
      return m.run(path, b);
    };
    step.fresh = () => {
      m.reset();
      return m.run(path, body());
    };
  }
  return { m, step };
}

/** 단계별 보내기 오류(422 invalid 등) */
function StepErrors({ ms }: { ms: ReturnType<typeof useMutation>[] }) {
  return (
    <>
      {ms.map((m, i) => (
        <MutationError key={i} error={m.error} />
      ))}
    </>
  );
}

// ── 망 ─────────────────────────────────────────────

/** 망 만들기(UI-50). 쓰는 범위만 다르고 둘 다 같은 tun 망이다: '이 서버에서만'은 멤버 하나 + local 옵션 */
export function NetworkCreateDialog({ tenant, nets, onClose, onDone }: { tenant: string; nets: NetworkView[]; onClose: () => void; onDone: () => void }) {
  const nodes = useNodes(tenant);
  // 망마다 서버별 CIDR이 따로 있다(망 행의 cidr는 쉼표로 이은 글자)
  const used0 = nets.flatMap((n) => (n.members.length ? n.members.map((x) => ({ name: n.name, node: x.node, cidr: x.cidr })) : n.cidr.split(/,\s*/).map((c) => ({ name: n.name, node: undefined as string | undefined, cidr: c }))));
  const [name, setName] = useState('');
  const [scope, setScope] = useState<'local' | 'mesh'>('local');
  const [zone, setZone] = useState('');
  // 이 서버에서만: 서버 하나, CIDR, 고급(게이트웨이·MTU). 터널 주소는 sfcd가 서버마다 고정된 서버 주소로 채운다(#584)
  const [node, setNode] = useState('');
  const [cidr, setCidr] = useState(() => suggestCidr(used0.map((x) => x.cidr)));
  const [gateway, setGateway] = useState('');
  const [mtu, setMtu] = useState('');
  // 다른 서버와: 서버마다 CIDR
  const [rows, setRows] = useState<Record<string, { on: boolean; cidr: string }>>({});
  useEffect(() => {
    if (!node && nodes[0]) setNode(nodes[0].id);
  }, [node, nodes]);
  // 서버마다 겹치지 않는 /24를 차례로 추천한다. 처음 두 서버를 켜 둔다.
  useEffect(() => {
    if (!nodes.length || Object.keys(rows).length) return;
    const used = used0.map((x) => x.cidr);
    const next: typeof rows = {};
    nodes.forEach((n, i) => {
      const c = suggestCidr(used);
      used.push(c);
      next[n.id] = { on: i < 2, cidr: c };
    });
    setRows(next);
  }, [nodes, nets, rows]);
  const set = (id: string, patch: Partial<{ on: boolean; cidr: string }>) => setRows((x) => ({ ...x, [id]: { ...x[id], ...patch } }));
  const on = nodes.filter((n) => rows[n.id]?.on);
  const taken = used0;
  const cidrErr = (id: string) => {
    const others = on.filter((n) => n.id !== id).map((n) => ({ name: name || '이 망', node: n.id, cidr: rows[n.id].cidr }));
    return cidrProblem(rows[id]?.cidr ?? '', [...taken, ...others]);
  };
  const c = parseCidr(cidr);
  const localCidrErr = cidrProblem(cidr, taken);
  const gwErr = gateway && c && !hostIn(c, gateway) ? `${cidr} 안의 호스트 주소여야 합니다` : undefined;
  const mtuN = mtu ? Number(mtu) : 0;
  const mtuErr = mtu && !(mtuN >= 1280 && mtuN <= 9000) ? '1280 ~ 9000' : undefined;
  const nameErr = nameProblem(name, nets.map((n) => n.name), '망');
  const zoneErr = zone && !/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(zone) ? 'shop.sfc.test 같은 도메인 이름' : undefined;
  const local = scope === 'local';
  const valid = !!name && !nameErr && !zoneErr && (local ? !!node && !localCidrErr && !gwErr && !mtuErr : on.length >= 1 && on.every((n) => !cidrErr(n.id)));
  const body = () =>
    local
      ? { kind: 'tun', name, members: [{ node, cidr, ...(gateway ? { gateway } : {}) }], ...(mtuN ? { mtu: mtuN } : {}), toggles: { local: true } }
      : { kind: 'tun', name, members: on.map((n) => ({ node: n.id, cidr: rows[n.id].cidr })) };
  const create = useStep('망 만들기 (create-tun-network)', `/t/${enc(tenant)}/networks`, body);
  const dns = useStep('도메인 이름 규칙 (configure-network-dns)', `/t/${enc(tenant)}/networks/${enc(name)}/dns`, () => ({ zone, expected: 0 }));
  const radio = (k: 'local' | 'mesh', label: string, note: string) => (
    <label className="check" style={{ alignItems: 'flex-start' }}>
      <input type="radio" name="net-scope" checked={scope === k} onChange={() => setScope(k)} />
      <span>
        {label}
        <span className="muted small" style={{ display: 'block' }}>
          {note}
        </span>
      </span>
    </label>
  );
  return (
    <CreateDialog ms={[create.m, dns.m]}
      title="망 만들기"
      ok="만들기"
      review
      valid={valid}
      onClose={onClose}
      onDone={onDone}
      steps={zone ? [create.step, dns.step] : [create.step]}
      summary={[
        ['이름', <code key="n">{name}</code>],
        ['쓰는 범위', local ? '이 서버에서만 쓰는 망' : '다른 서버와 이을 수 있는 망'],
        ['참여 서버', local ? `${node} ${cidr}` : on.map((n) => `${n.id} ${rows[n.id].cidr}`).join(' / ')],
        ...(local ? ([['게이트웨이', <code key="g">{gateway || (c ? firstHost(c) : '')}</code>], ['MTU', mtuN || 1500]] as [string, ReactNode][]) : []),
        ['도메인 영역', zone || '없음'],
      ]}
    >
      <Field label="이름" error={nameErr}>
        <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} placeholder={local ? 'shop-cache' : 'shop-mesh'} />
      </Field>
      <div className="col" style={{ gap: 6 }}>
        <span className="small">쓰는 범위</span>
        {radio('local', '이 서버에서만 쓰는 망', '서버 한 대에 묶입니다. 다른 서버의 컨테이너는 붙을 수 없습니다.')}
        {radio('mesh', '다른 서버와 이을 수 있는 망', '서버를 여럿 고르거나, 하나로 시작해 나중에 더할 수 있습니다.')}
      </div>
      {local ? (
        <>
          <Field label="서버">
            <select value={node} onChange={(e) => setNode(e.target.value)}>
              {nodes.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.id}
                </option>
              ))}
            </select>
          </Field>
          <Field label="CIDR" error={localCidrErr} hint="직접 정합니다. 처음에는 겹치지 않는 추천 값이 채워집니다. 10.254.0.0/16은 시스템 망이 쓰므로 쓸 수 없습니다.">
            <input className="mono" value={cidr} onChange={(e) => setCidr(e.target.value.trim())} />
          </Field>
        </>
      ) : (
        <>
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 28 }} />
                  <th>서버</th>
                  <th>CIDR</th>
                </tr>
              </thead>
              <tbody>
                {nodes.map((n) => {
                  const r = rows[n.id];
                  const ce = r?.on ? cidrErr(n.id) : undefined;
                  return (
                    <tr key={n.id}>
                      <td>
                        <input type="checkbox" aria-label={`${n.id} 참여`} checked={!!r?.on} onChange={(e) => set(n.id, { on: e.target.checked })} />
                      </td>
                      <td>{n.id}</td>
                      <td>
                        {r?.on ? (
                          <>
                            <input className="mono" aria-label={`${n.id} CIDR`} value={r.cidr} onChange={(e) => set(n.id, { cidr: e.target.value.trim() })} />
                            {ce && <div className="small" style={{ color: 'var(--er)' }}>{ce}</div>}
                          </>
                        ) : (
                          '—'
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <span className="small muted">서버 하나만 골라도 됩니다(나중에 더하기). CIDR은 직접 정하고, 처음에는 겹치지 않는 추천 값이 채워집니다. 터널 주소는 서버마다 고정된 서버 주소를 sfcd가 씁니다. 10.254.0.0/16은 시스템 망이 쓰므로 쓸 수 없습니다.</span>
        </>
      )}
      <Field label="도메인 영역 (선택)" error={zoneErr} hint={local ? undefined : '넣으면 만든 뒤 이름 규칙까지 한 번의 변경 검토로 보여 줍니다'}>
        <input className="mono" value={zone} onChange={(e) => setZone(e.target.value.trim())} placeholder={local ? 'shop-cache.sfc.test' : 'shop-mesh.sfc.test'} />
      </Field>
      {local && (
        <details>
          <summary className="small linkish">고급 · 게이트웨이 · MTU</summary>
          <div className="g2" style={{ marginTop: 8 }}>
            <Field label="게이트웨이" error={gwErr} hint="비우면 첫 주소">
              <input className="mono" value={gateway} placeholder={c ? firstHost(c) : ''} onChange={(e) => setGateway(e.target.value.trim())} />
            </Field>
            <Field label="MTU" error={mtuErr} hint="비우면 1500">
              <input inputMode="numeric" value={mtu} placeholder="1500" onChange={(e) => setMtu(e.target.value.replace(/\D/g, ''))} />
            </Field>
          </div>
        </details>
      )}
    </CreateDialog>
  );
}

// ── 데이터 저장소 ──────────────────────────────────

const parseGiB = (s: string) => (s ? Math.round(Number(s) * GiB) : 0);
const gibProblem = (s: string) => (s && !(Number(s) > 0 && Number(s) <= 1024) ? '0보다 크고 1 TiB(1024 GiB) 이하' : undefined);

export function ManagedVolumeDialog({ tenant, taken, onClose, onDone }: { tenant: string; taken: string[]; onClose: () => void; onDone: () => void }) {
  const nodes = useNodes(tenant);
  const appList = usePoll((s) => fetchApps(tenant, s), [tenant], 0, appsLive(tenant));
  const appNames = useMemo(() => [...new Set((appList.data?.items ?? []).map((a) => a.app))], [appList.data]);
  const [name, setName] = useState('');
  const [app, setApp] = useState('');
  const [node, setNode] = useState('');
  const [size, setSize] = useState('');
  const [owner, setOwner] = useState('1000:1000');
  const [mode, setMode] = useState('0770');
  useEffect(() => {
    if (!node && nodes[0]) setNode(nodes[0].id);
    if (!app && appNames[0]) setApp(appNames[0]);
  }, [node, nodes, app, appNames]);
  const [uid, gid] = owner.split(':').map((x) => Number(x));
  const ownerErr = !/^\d+:\d+$/.test(owner) ? 'uid:gid 숫자로' : !uid || !gid ? 'root(0)는 안 됨' : uid >= 2 ** 32 - 1 || gid >= 2 ** 32 - 1 ? '너무 큰 값' : undefined;
  const nameErr = nameProblem(name, taken, '데이터 저장소');
  const appErr = app && !NAME_RE.test(app) ? '앱 이름 규칙(소문자·숫자·-)' : undefined;
  const valid = !!name && !nameErr && !!app && !appErr && !!node && !ownerErr && !gibProblem(size);
  const create = useStep('관리 데이터 저장소 만들기 (begin-volume-create)', `/t/${enc(tenant)}/volumes`, () => ({ kind: 'managed', name, app, node, uid, gid, mode, ...(size ? { capacityBytes: parseGiB(size) } : {}) }));
  return (
    <CreateDialog ms={[create.m]}
      title="관리 데이터 저장소 만들기"
      ok="만들기"
      review
      valid={valid}
      onClose={onClose}
      onDone={onDone}
      steps={[create.step]}
      summary={[
        ['이름', <code key="n">{name}</code>],
        ['소속 앱', app],
        ['서버', node],
        ['용량', size ? `${size} GiB` : '정하지 않음 (관측만)'],
        ['소유자', <code key="o">{owner}</code>],
        ['권한', <code key="m">{mode}</code>],
      ]}
    >
      <Field label="이름" error={nameErr}>
        <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} placeholder="shop-media" />
      </Field>
      <Field label="소속 앱" error={appErr} hint="이 앱 이름 아래에 만듭니다. 아직 배포하지 않은 앱 이름도 됩니다">
        <input className="mono" list="sa-apps" value={app} onChange={(e) => setApp(e.target.value.trim())} />
        <datalist id="sa-apps">
          {appNames.map((a) => (
            <option key={a} value={a} />
          ))}
        </datalist>
      </Field>
      <div className="g2">
        <Field label="서버" hint="저장 경로는 서버가 정합니다">
          <select value={node} onChange={(e) => setNode(e.target.value)}>
            {nodes.map((n) => (
              <option key={n.id} value={n.id}>
                {nodeLabel(n)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="용량 (GiB)" error={gibProblem(size)} hint="비우면 정하지 않음">
          <input inputMode="decimal" value={size} placeholder="50" onChange={(e) => setSize(e.target.value.replace(/[^\d.]/g, ''))} />
        </Field>
      </div>
      <div className="g2">
        <Field label="소유자 uid:gid" error={ownerErr} hint="root(0)는 안 됨">
          <input className="mono" value={owner} onChange={(e) => setOwner(e.target.value.trim())} />
        </Field>
        <Field label="권한">
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            {['0770', '0750', '0700'].map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </Field>
      </div>
      <span className="small muted">쓰기 방식(단일 쓰기 등)은 앱이 붙일 때 app.yaml에서 정합니다.</span>
      <label className="row small" title={SERVER_WAIT}>
        <input type="checkbox" disabled /> 매일 03:00 백업 (보존 5개) <span className="muted">· {SERVER_WAIT}</span>
      </label>
    </CreateDialog>
  );
}

/** 이 작업 공간이 쓸 수 있는 저장 경로(GET /t/{t}/storage, 관리 권한). 못 읽으면 시스템 관리자는 /storage를 거른다. */
export function useAllowedRoots(tenant: string, isAdmin: boolean) {
  return usePoll(
    async (s) => {
      try {
        const roots = (await tenantStorage(tenant, s)).items;
        if (!isAdmin) return { roots, wait: false };
        // 작업 공간 행에는 용량 한도가 없다. 시스템 관리자는 전체 목록에서 채운다
        const all = await storageRoots(s).then((p) => p.items, () => [] as StorageRoot[]);
        const full = new Map(all.map((r) => [`${r.node}/${r.name}`, r]));
        return { roots: roots.map((r) => ({ ...r, capacityBytes: full.get(`${r.node}/${r.name}`)?.capacityBytes, allTenants: full.get(`${r.node}/${r.name}`)?.allTenants })), wait: false };
      } catch (e) {
        if (!isAdmin) return { roots: [] as StorageRoot[], wait: true };
        const all = (await storageRoots(s)).items;
        return { roots: all.filter((r) => r.allTenants || r.tenants.includes(tenant)), wait: false, err: e };
      }
    },
    [tenant, isAdmin],
  );
}

export function FixedVolumeDialog({ tenant, isAdmin, taken, initial, onClose, onDone }: { tenant: string; isAdmin: boolean; taken: string[]; initial?: string; onClose: () => void; onDone: () => void }) {
  const q = useAllowedRoots(tenant, isAdmin);
  // 서버마다 기본 저장 경로를 먼저 둔다(#684)
  const roots = (q.data?.roots ?? []).filter(usableRoot).sort((a, b) => a.node.localeCompare(b.node) || Number(!!b.isDefault) - Number(!!a.isDefault));
  const [name, setName] = useState('');
  const [pick, setPick] = useState(initial ?? '');
  const [path, setPath] = useState('');
  const [size, setSize] = useState('');
  useEffect(() => {
    if (!pick && roots[0]) setPick(`${roots[0].node}/${roots[0].name}`);
  }, [pick, roots]);
  const root = roots.find((r) => `${r.node}/${r.name}` === pick);
  const nameErr = nameProblem(name, taken, '데이터 저장소');
  const pathErr = path && (path.startsWith('/') || path.split('/').includes('..')) ? '저장 경로 아래 상대 경로(.. 없이)' : undefined;
  // 한도가 있는 저장 경로는 용량을 적어야 받는다. 작업 공간 행에는 한도가 없어(모름) 그때는 서버가 정한다
  const needSize = !!root?.capacityBytes;
  const valid = !!name && !nameErr && !!root && !!path && !pathErr && !gibProblem(size) && (!needSize || !!size);
  const create = useStep('고정 데이터 저장소 등록 (register-fixed-volume)', `/t/${enc(tenant)}/volumes`, () => ({
    kind: 'fixed',
    name,
    node: root!.node,
    storage: root!.name,
    path,
    rootGeneration: root!.generation,
    ...(size ? { capacityBytes: parseGiB(size) } : {}),
  }));
  return (
    <CreateDialog ms={[create.m]} title="고정 데이터 저장소 등록" ok="등록" review={false} valid={valid} onClose={onClose} onDone={onDone} steps={[create.step]} summary={[]}>
      <Field label="이름" error={nameErr}>
        <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} placeholder="media-ssd" />
      </Field>
      <Field label="서버 · 저장 경로" hint={q.data?.wait ? '저장 경로 목록을 읽지 못했습니다(볼륨 또는 레지스트리 관리 권한이 필요합니다)' : '허용되고 비우는 중이 아닌 저장 경로만 보입니다'}>
        <select value={pick} onChange={(e) => setPick(e.target.value)} disabled={!roots.length}>
          {!roots.length && <option value="">{q.loading ? '불러오는 중…' : '허용된 저장 경로 없음'}</option>}
          {roots.map((r) => (
            <option key={`${r.node}/${r.name}`} value={`${r.node}/${r.name}`}>
              {r.node} · {r.name}
              {r.isDefault ? ' (기본)' : ''}
              {r.capacityBytes ? ` · 한도 ${fmtBytes(r.capacityBytes)}` : r.capacityBytes === 0 ? ' · 한도 없음' : ''}
            </option>
          ))}
        </select>
      </Field>
      <div className="g2">
        <Field label="하위 경로" error={pathErr} hint={root ? `${root.path}/${path || '…'}` : undefined}>
          <input className="mono" value={path} onChange={(e) => setPath(e.target.value.trim())} placeholder="media/" />
        </Field>
        <Field label={needSize ? '용량 (GiB)' : '용량 (선택, GiB)'} error={gibProblem(size)} hint={needSize ? `이 저장 경로는 한도 ${fmtBytes(root!.capacityBytes!)}가 있어 용량을 적어야 합니다` : undefined}>
          <input inputMode="decimal" value={size} onChange={(e) => setSize(e.target.value.replace(/[^\d.]/g, ''))} />
        </Field>
      </div>
      <div className="note small">고정 데이터 저장소는 클러스터가 백업·이동하지 않습니다. 그 서버에서만 쓸 수 있습니다. 이미 있는 폴더를 등록만 하고, 데이터를 만들거나 지우지 않습니다.</div>
    </CreateDialog>
  );
}

// ── 비밀값 ─────────────────────────────────────────

const groupsOf = (items: SecretView[]) => items.filter((v) => v.kind === 'group');

/**
 * 만든 뒤 값·비밀번호를 넣을 path. path 모양은 sfcd가 정하므로 목록을 다시 읽어 ID로 찾는다.
 * 못 찾으면 부모 path 아래로 짐작한다.
 */
async function vaultPathOf(scope: VaultScope, parent: string, id: string) {
  let after = '';
  for (let i = 0; i < 20; i++) {
    const p = await vaultList(scope, undefined, after);
    const hit = p.items.find((v) => v.id === id && v.parent === parent);
    if (hit) return hit.path;
    if (!p.next) break;
    after = p.next;
  }
  return id;
}

/** 보관함 쓰기 단계(값·비밀번호). path는 보내기 직전에 정한다. 이어 가기 규칙은 useStep과 같다 */
function useSecretStep(title: string, path: string, where: () => Promise<string>, body: (p: string) => Record<string, unknown>, secret: string) {
  const m = useMutation();
  const target = useRef<string>();
  const at = async () => (target.current ??= await where());
  const step: Step = {
    title,
    run: async () => m.run(path, body(await at())),
    again: async (withValue) => {
      const b = body(await at());
      if (!withValue) delete b[secret];
      return m.run(path, b);
    },
    fresh: async () => {
      m.reset();
      return m.run(path, body(await at()));
    },
  };
  return { m, step };
}

export function VaultGroupDialog({ scope, items, onClose, onDone }: { scope: VaultScope; items: SecretView[]; onClose: () => void; onDone: () => void }) {
  const root = scope.root;
  const [name, setName] = useState('');
  const [locked, setLocked] = useState(true);
  const [pw, setPw] = useState(['', '']);
  const [profile, setProfile] = useState('');
  const nameErr = nameProblem(name, items.filter((v) => v.parent === root).map((v) => v.id), '항목');
  const pwErr = locked && pw[1] && pw[0] !== pw[1] ? '비밀번호가 다릅니다' : undefined;
  const valid = !!name && !nameErr && (!locked || (pw[0].length >= 8 && pw[0] === pw[1] && !!profile));
  // 최상위 묶음의 ID는 작업 공간 이름이다
  const create = useStep('묶음 만들기 (vault-create)', scope.base, () => ({ kind: 'group', parent: root, id: name }));
  const lock = useSecretStep('묶음 비밀번호 설정 (vault-password)', `${scope.base}/password`, () => vaultPathOf(scope, root, name), (path) => ({ path, password: pw[0], profile }), 'password');
  useEffect(() => () => setPw(['', '']), []);
  return (
    <CreateDialog ms={[create.m, lock.m]} title="묶음 만들기" ok="만들기" review={false} valid={valid} onClose={onClose} onDone={() => (setPw(['', '']), onDone())} steps={locked ? [create.step, lock.step] : [create.step]} summary={[]}>
      <Field label="이름" error={nameErr}>
        <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} placeholder="payment-cred" />
      </Field>
      <label className="row small" style={{ alignItems: 'flex-start', flexWrap: 'nowrap' }}>
        <input type="checkbox" checked={locked} onChange={(e) => setLocked(e.target.checked)} />
        <span>
          비밀번호로 보호
          <span className="muted" style={{ display: 'block' }}>보호된 묶음의 비밀값을 앱이 쓸 때, 권한 있는 사람이 이 비밀번호를 넣어 승인합니다</span>
        </span>
      </label>
      {locked && (
        <div className="g2">
          <Field label="묶음 비밀번호" hint="보호 입력 · 웹에 남지 않음 · 8자 이상">
            <input type="password" autoComplete="new-password" value={pw[0]} onChange={(e) => setPw([e.target.value, pw[1]])} />
          </Field>
          <Field label="확인" error={pwErr}>
            <input type="password" autoComplete="new-password" value={pw[1]} onChange={(e) => setPw([pw[0], e.target.value])} />
          </Field>
        </div>
      )}
      {locked && (
        <Field label="검증값 보관 방식 (profile)" hint="비밀번호 검증값을 둘 쓰기 프로필 · 예: auth">
          <input className="mono" value={profile} onChange={(e) => setProfile(e.target.value.trim())} />
        </Field>
      )}
    </CreateDialog>
  );
}

/** 묶음 비밀번호 정하기·바꾸기(vault-password). 비밀번호는 입력 칸에만 있고 닫으면 지운다 */
export function VaultPasswordDialog({ scope, group, onClose, onDone }: { scope: VaultScope; group: SecretView; onClose: () => void; onDone: () => void }) {
  const [pw, setPw] = useState(['', '']);
  const pwErr = pw[1] && pw[0] !== pw[1] ? '비밀번호가 다릅니다' : undefined;
  // 처음 정할 때만 검증값을 둘 보관 방식이 필요하다. 그 뒤로는 묶음이 가진 것을 쓴다.
  const [profile, setProfile] = useState('');
  const first = !group.protected;
  const valid = pw[0].length >= 8 && pw[0] === pw[1] && (!first || !!profile);
  const path = group.path;
  const lock = useSecretStep('묶음 비밀번호 설정 (vault-password)', `${scope.base}/password`, async () => path, (p) => ({ path: p, password: pw[0], ...(first ? { profile } : {}) }), 'password');
  useEffect(() => () => setPw(['', '']), []);
  return (
    <CreateDialog ms={[lock.m]} title={`${group.id} 비밀번호 ${group.protected ? '바꾸기' : '정하기'}`} ok={group.protected ? '바꾸기' : '정하기'} review={false} valid={valid} onClose={onClose} onDone={() => (setPw(['', '']), onDone())} steps={[lock.step]} summary={[]}>
      <span className="small muted">
        {group.protected ? '바꾸면 앞으로의 승인은 새 비밀번호로 합니다. 이미 받은 승인은 그대로입니다.' : '정하면 이 묶음은 보호됩니다. 앱이 그 아래 비밀값을 쓰려면 권한 있는 사람이 이 비밀번호로 승인합니다.'}
      </span>
      <div className="g2">
        <Field label="새 비밀번호" hint="보호 입력 · 웹에 남지 않음 · 8자 이상">
          <input type="password" autoComplete="new-password" value={pw[0]} onChange={(e) => setPw([e.target.value, pw[1]])} />
        </Field>
        <Field label="확인" error={pwErr}>
          <input type="password" autoComplete="new-password" value={pw[1]} onChange={(e) => setPw([pw[0], e.target.value])} />
        </Field>
      </div>
      {first && (
        <Field label="검증값 보관 방식 (profile)" hint="비밀번호 검증값을 둘 쓰기 프로필 · 예: auth · 처음 정할 때만">
          <input className="mono" value={profile} onChange={(e) => setProfile(e.target.value.trim())} />
        </Field>
      )}
    </CreateDialog>
  );
}

export function VaultSecretDialog({ scope, items, group, onClose, onDone }: { scope: VaultScope; items: SecretView[]; group?: string; onClose: () => void; onDone: () => void }) {
  const root = scope.root;
  const groups = groupsOf(items).filter((g) => g.status === 'active');
  const [name, setName] = useState('');
  // 부모 묶음 ID. 최상위는 작업 공간 이름
  const [parent, setParent] = useState(group ?? root);
  const [keysText, setKeysText] = useState('value');
  const [values, setValues] = useState<Record<string, [string, string]>>({});
  const [profile, setProfile] = useState('');
  const [object, setObject] = useState('');
  const keys = [...new Set(keysText.split(',').map((k) => k.trim()).filter(Boolean))];
  const keysErr = !keys.length ? '키 이름을 하나 이상' : keys.length > 64 ? '64개까지' : keys.find((k) => !/^[A-Za-z0-9_.-]+$/.test(k)) ? '영문·숫자·_ . -만' : undefined;
  const nameErr = nameProblem(name, items.filter((v) => v.parent === parent).map((v) => v.id), '항목');
  const mismatch = keys.filter((k) => (values[k]?.[0] ?? '') !== (values[k]?.[1] ?? ''));
  const filled = keys.every((k) => values[k]?.[0]);
  const valid = !!name && !nameErr && !keysErr && filled && !mismatch.length;
  const create = useStep('비밀값 만들기 (vault-create)', scope.base, () => ({ kind: 'secret', parent, id: name, keys, ...(profile ? { profile } : {}), ...(object ? { object } : {}) }));
  const write = useSecretStep('값 넣기 (vault-value)', `${scope.base}/value`, () => vaultPathOf(scope, parent, name), (path) => ({ path, values: Object.fromEntries(keys.map((k) => [k, values[k][0]])), keys }), 'values');
  // 닫으면 입력한 값을 메모리에서도 지운다.
  useEffect(() => () => setValues({}), []);
  return (
    <CreateDialog ms={[create.m, write.m]} title="비밀값 만들기" ok="만들기" review={false} valid={valid} onClose={onClose} onDone={() => (setValues({}), onDone())} steps={[create.step, write.step]} summary={[]}>
      <Field label="이름" error={nameErr}>
        <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} placeholder="stripe-key" />
      </Field>
      <Field label="묶음">
        <select value={parent} onChange={(e) => setParent(e.target.value)}>
          <option value={root}>묶음 없음</option>
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.id}
            </option>
          ))}
        </select>
      </Field>
      <Field label="키 이름" error={keysErr} hint="여러 키면 쉼표로 · 1~64개">
        <input className="mono" value={keysText} onChange={(e) => setKeysText(e.target.value)} />
      </Field>
      {keys.slice(0, 8).map((k) => (
        <div key={k} className="g2">
          <Field label={keys.length > 1 ? `값 · ${k}` : '값'} hint="보호 입력(SecretInput) · 웹에 남지 않음">
            <input type="password" autoComplete="new-password" value={values[k]?.[0] ?? ''} onChange={(e) => setValues((v) => ({ ...v, [k]: [e.target.value, v[k]?.[1] ?? ''] }))} />
          </Field>
          <Field label="확인" error={values[k]?.[1] && mismatch.includes(k) ? '값이 다릅니다' : undefined}>
            <input type="password" autoComplete="new-password" value={values[k]?.[1] ?? ''} onChange={(e) => setValues((v) => ({ ...v, [k]: [v[k]?.[0] ?? '', e.target.value] }))} />
          </Field>
        </div>
      ))}
      {keys.length > 8 && <span className="small muted">키가 8개보다 많으면 나머지 값은 만든 뒤 ‘새 값 쓰기’로 넣습니다.</span>}
      <details>
        <summary className="small linkish">고급 · 보관 방식 · 대상</summary>
        <div className="g2" style={{ marginTop: 8 }}>
          <Field label="보관 방식 (profile)" hint="비우면 작업 공간 기본">
            <input className="mono" value={profile} onChange={(e) => setProfile(e.target.value.trim())} />
          </Field>
          <Field label="대상 (object)" hint="외부 보관소의 객체 이름">
            <input className="mono" value={object} onChange={(e) => setObject(e.target.value.trim())} />
          </Field>
        </div>
      </details>
    </CreateDialog>
  );
}
