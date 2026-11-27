// SPDX-License-Identifier: Apache-2.0

// 관리 변경 (UI-A1) › 변경 만들기 · 보낼 변경 묶음. 계약: docs/reference/web-api/46-management-change.md
// 동작 목록과 입력 칸은 서버가 준다(GET /ops/actions). 화면 이름·전용 화면 길은 opActionText.ts.
// 기준 버전은 base 방식대로 채우고, 보내기는 POST /ops(사유는 X-SFC-Reason, 한 묶음은 같은 batch).
// 비밀 값은 여기서 넣지 않는다(offer: no). 묶음은 이 화면 상태에만 있고 어디에도 저장하지 않는다.
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { api, newOpId, reasonHeaders } from '../api/client';
import { ACTION_SCREEN, ACTION_TITLE } from './opActionText';
import { opActionBase, opGet, toOp } from '../api/endpoints';
import type { DOp, DOpAction, DOpBase, DOpField } from '../api/dto';
import type { OpView } from '../api/types';
import { ApiError } from '../api/client';
import { Badge, Card, Field } from '../components/ui';
import { MutationError, OpPanel } from '../components/OpPanel';

export type OpAction = Omit<DOpAction, 'fields'> & { fields: DOpField[] };

export const CATEGORY: Record<string, string> = {
  users: '사용자 · 로그인 키',
  tenants: '작업 공간',
  nodes: '서버',
  networks: '망',
  reservations: '실행 예약',
  storage: '데이터 저장소',
  apps: '앱',
  registry: '이미지 저장소',
  builds: '이미지 빌드',
  vault: '비밀값',
  checks: '상태 검사',
  ingress: '외부 접속',
  certificates: '인증서',
  shell: '서버 셸',
  other: '그 밖',
};
const CATEGORY_ORDER = Object.keys(CATEGORY);
export const titleOf = (a: { action: string }) => ACTION_TITLE[a.action] ?? a.action;
const named = (a: { action: string }) => a.action in ACTION_TITLE;

// ── 칸 값 ──
type Val = unknown;
/** 처음 값: 목록 [], 맵 {}, 객체는 하위 칸마다 처음 값 */
export function emptyOf(f: DOpField): Val {
  switch (f.type) {
    case 'boolean':
      return false;
    case 'list':
      return f.length && f.items ? Array.from({ length: f.length }, () => emptyOf(f.items!)) : [];
    case 'map':
      return {};
    case 'object':
      return Object.fromEntries((f.fields ?? []).map((x) => [x.name, emptyOf(x)]));
    case 'json':
      return null;
    default:
      return '';
  }
}
/** 보낼 payload: 빈 문자열·빈 정수는 뺀다. replace 목록은 비어도 [](null 아님) */
export function cleanOf(f: DOpField, v: Val): Val | undefined {
  switch (f.type) {
    case 'string':
    case 'bytes':
      return typeof v === 'string' && v !== '' ? v : undefined;
    case 'integer':
    case 'number':
      return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
    case 'boolean':
      return !!v;
    case 'json':
      return v === null ? undefined : v;
    case 'list': {
      const raw = (Array.isArray(v) ? v : []).map((x) => (f.items ? cleanOf(f.items, x) : x));
      // 길이가 정해진 목록은 다 채웠을 때만(빈 칸이 있으면 보내지 않음)
      if (f.length) return raw.length === f.length && raw.every((x) => x !== undefined) ? raw : f.replace ? [] : undefined;
      const xs = raw.filter((x) => x !== undefined);
      return xs.length || f.replace ? xs : undefined;
    }
    case 'map': {
      const o = (v && typeof v === 'object' ? v : {}) as Record<string, Val>;
      const e = Object.entries(o)
        .filter(([k]) => k !== '')
        .map(([k, x]) => [k, f.items ? cleanOf(f.items, x) : x] as const)
        .filter(([, x]) => x !== undefined);
      return e.length || f.replace ? Object.fromEntries(e) : undefined;
    }
    case 'object': {
      const o = (v && typeof v === 'object' ? v : {}) as Record<string, Val>;
      const e = (f.fields ?? []).map((x) => [x.name, cleanOf(x, o[x.name])] as const).filter(([, x]) => x !== undefined);
      return e.length ? Object.fromEntries(e) : undefined;
    }
  }
}
export const payloadOf = (a: OpAction, vals: Record<string, Val>) => (cleanOf({ name: '', type: 'object', fields: a.fields }, vals) ?? {}) as Record<string, unknown>;

const PLACEHOLDER: Record<string, string> = { cidr: '10.40.0.0/24', ip: '10.0.0.11', 'ip-port': '10.0.0.11:7443', time: '2026-11-26T12:00:00Z', duration: '30m' };

function FieldInput({ f, value, onChange, depth = 0 }: { f: DOpField; value: Val; onChange: (v: Val) => void; depth?: number }) {
  const [raw, setRaw] = useState(() => (f.type === 'json' && value !== null ? JSON.stringify(value) : ''));
  const [jsonErr, setJsonErr] = useState<string>();
  switch (f.type) {
    case 'string':
      return <input className="mono" value={String(value ?? '')} onChange={(e) => onChange(e.target.value)} placeholder={f.format ? PLACEHOLDER[f.format] ?? f.format : undefined} />;
    case 'integer':
    case 'number':
      return (
        <input
          type="number"
          step={f.type === 'integer' ? 1 : 'any'}
          className="mono"
          value={typeof value === 'number' ? value : ''}
          placeholder={f.format === 'duration' ? '나노초' : undefined}
          onChange={(e) => onChange(e.target.value === '' ? undefined : Number(e.target.value))}
        />
      );
    case 'boolean':
      return (
        <label className="check small">
          <input type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} /> 켜기
        </label>
      );
    case 'bytes':
      return <textarea className="mono" rows={3} value={String(value ?? '')} onChange={(e) => onChange(e.target.value.trim())} placeholder="base64" />;
    case 'json':
      return (
        <>
          <textarea
            className="mono"
            rows={3}
            value={raw}
            onChange={(e) => {
              setRaw(e.target.value);
              if (!e.target.value.trim()) return setJsonErr(undefined), onChange(null);
              try {
                onChange(JSON.parse(e.target.value));
                setJsonErr(undefined);
              } catch {
                setJsonErr('JSON 모양이 아닙니다');
              }
            }}
          />
          {jsonErr && <span className="error small">{jsonErr}</span>}
        </>
      );
    case 'list': {
      const xs = Array.isArray(value) ? value : [];
      const item = f.items ?? { name: '', type: 'string' as const };
      if (f.length)
        return (
          <div className="col" style={{ gap: 6 }}>
            <span className="small muted">{f.length}개를 모두 채웁니다</span>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(64px, 1fr))', gap: 4 }}>
              {Array.from({ length: f.length }, (_, i) => (
                <FieldInput key={i} f={item} value={xs[i]} depth={depth + 1} onChange={(v) => onChange(Array.from({ length: f.length! }, (_, j) => (j === i ? v : xs[j])))} />
              ))}
            </div>
          </div>
        );
      return (
        <div className="col" style={{ gap: 6 }}>
          {xs.map((x, i) => (
            <div key={i} className="row" style={{ gap: 6, alignItems: 'flex-start' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <FieldInput f={item} value={x} depth={depth + 1} onChange={(v) => onChange(xs.map((y, j) => (j === i ? v : y)))} />
              </div>
              <button type="button" className="btn sm" aria-label={`${i + 1}번째 빼기`} onClick={() => onChange(xs.filter((_, j) => j !== i))}>
                ✕
              </button>
            </div>
          ))}
          <button type="button" className="btn sm" style={{ alignSelf: 'flex-start' }} onClick={() => onChange([...xs, emptyOf(item)])}>
            ＋ 더하기
          </button>
        </div>
      );
    }
    case 'map': {
      const o = (value && typeof value === 'object' ? value : {}) as Record<string, Val>;
      const es = Object.entries(o);
      const item = f.items ?? { name: '', type: 'string' as const };
      return (
        <div className="col" style={{ gap: 6 }}>
          {es.map(([k, x], i) => (
            <div key={i} className="row" style={{ gap: 6, alignItems: 'flex-start' }}>
              <input className="mono" style={{ width: 140 }} value={k} aria-label="키" onChange={(e) => onChange(Object.fromEntries(es.map(([kk, xx], j) => (j === i ? [e.target.value, xx] : [kk, xx]))))} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <FieldInput f={item} value={x} depth={depth + 1} onChange={(v) => onChange({ ...o, [k]: v })} />
              </div>
              <button type="button" className="btn sm" aria-label={`${k} 빼기`} onClick={() => onChange(Object.fromEntries(es.filter((_, j) => j !== i)))}>
                ✕
              </button>
            </div>
          ))}
          <button type="button" className="btn sm" style={{ alignSelf: 'flex-start' }} disabled={'' in o} onClick={() => onChange({ ...o, '': emptyOf(item) })}>
            ＋ 더하기
          </button>
        </div>
      );
    }
    case 'object': {
      const o = (value && typeof value === 'object' ? value : {}) as Record<string, Val>;
      return (
        <div className="col" style={{ gap: 8, border: '1px solid var(--line-2)', borderRadius: 8, padding: 10 }}>
          {(f.fields ?? []).map((x) => (
            <Field key={x.name} label={<span className="mono">{x.name}</span>} group={x.type === 'list' || x.type === 'map' || x.type === 'object'}>
              <FieldInput f={x} value={o[x.name]} depth={depth + 1} onChange={(v) => onChange({ ...o, [x.name]: v })} />
            </Field>
          ))}
        </div>
      );
    }
  }
}

/** 묶음의 한 줄 */
export interface BatchItem {
  uid: string;
  action: OpAction;
  vals: Record<string, Val>;
  payload: Record<string, unknown>;
  /** zero·input은 정한 값. current는 보낼 때 다시 읽는다 */
  expected?: number;
  /** 사유(선택). X-SFC-Reason 머리글로 싣는다 */
  reason?: string;
  /** 보내는 중 결과 */
  op?: OpView;
  error?: unknown;
}
const shortVal = (v: unknown): string => (Array.isArray(v) ? v.map(shortVal).join(', ') : v && typeof v === 'object' ? Object.values(v).map(shortVal).filter(Boolean).join(' · ') : typeof v === 'boolean' ? (v ? '켬' : '끔') : String(v ?? ''));
export const targetText = (p: Record<string, unknown>) => shortVal(p) || '—';

/** 지금 값 읽기(base: current). 지원하지 않으면 사람이 넣는다 */
function useBase(a: OpAction | undefined, payload: Record<string, unknown>) {
  const [st, setSt] = useState<{ key: string; data?: DOpBase; error?: unknown; unsupported?: boolean }>();
  const key = a ? `${a.action} ${JSON.stringify(payload)}` : '';
  useEffect(() => {
    if (!a || a.base !== 'current') return;
    const t = setTimeout(() => {
      opActionBase(a.action, payload).then(
        (data) => setSt({ key, data }),
        (error) => setSt({ key, error, unsupported: error instanceof ApiError && error.code === 'unsupported' }),
      );
    }, 500);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return st?.key === key ? st : undefined;
}

/** 동작 목록(분류별 접기) + 고른 동작의 입력 칸 */
export function ChangeBuilder({ actions, editing, onAdd }: { actions: OpAction[]; editing?: BatchItem; onAdd: (it: BatchItem) => void }) {
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [sel, setSel] = useState<string>();
  const [vals, setVals] = useState<Record<string, Val>>({});
  const [typed, setTyped] = useState<number | undefined>();
  const [reason, setReason] = useState('');
  const [now, setNow] = useState<{ op?: OpView; error?: unknown; busy?: boolean }>({});
  const opId = useRef(newOpId());
  // 묶음에서 '고치기'로 돌아온 줄
  useEffect(() => {
    if (!editing) return;
    setSel(editing.action.action);
    setVals(editing.vals);
    setTyped(editing.action.base === 'input' ? editing.expected : undefined);
    setReason(editing.reason ?? '');
    setOpen((o) => ({ ...o, [editing.action.category]: true }));
  }, [editing]);
  const a = actions.find((x) => x.action === sel);
  const payload = a ? payloadOf(a, vals) : {};
  const base = useBase(a, payload);
  const cats = [...new Set(actions.map((x) => x.category))].sort((x, y) => (CATEGORY_ORDER.indexOf(x) + 99) % 999 - (CATEGORY_ORDER.indexOf(y) + 99) % 999);
  const pick = (x: OpAction) => {
    setSel(x.action);
    setVals(Object.fromEntries(x.fields.map((f) => [f.name, emptyOf(f)])));
    setTyped(undefined);
    setReason('');
    setNow({});
    opId.current = newOpId();
  };
  const manual = a?.base === 'input' || !!base?.unsupported;
  const expected = !a ? undefined : a.base === 'zero' ? 0 : manual ? typed : base?.data?.expected;
  const ready = !!a && a.offer === 'here' && expected !== undefined && Object.keys(payload).length > 0;
  const sendNow = async () => {
    if (!a || expected === undefined) return;
    setNow({ busy: true });
    try {
      const r = await api.postWith<{ op: DOp }>('/ops', opBody(opId.current, a, expected, payload), reasonHeaders(reason));
      setNow({ op: toOp(r.op) });
    } catch (error) {
      setNow({ error });
    }
  };
  const add = () => {
    if (!a) return;
    onAdd({ uid: editing ? editUid(editing) : newOpId(), action: a, vals, payload, expected: a.base === 'current' && !manual ? undefined : expected, reason: reason.trim() || undefined });
    pick(a);
  };
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, 0.9fr) 1.4fr', gap: 20, alignItems: 'start' }} className="ops-builder">
      <div className="col" style={{ gap: 2 }}>
        {cats.map((c) => {
          const xs = actions.filter((x) => x.category === c);
          const on = !!open[c];
          return (
            <div key={c}>
              <button type="button" className="linkish" aria-expanded={on} onClick={() => setOpen((o) => ({ ...o, [c]: !on }))} style={{ fontWeight: 600, padding: '6px 4px' }}>
                {on ? '▾' : '▸'} {CATEGORY[c] ?? c} <span className="muted small">{xs.length}</span>
              </button>
              {on &&
                xs.map((x) => (
                  <div key={x.action} className={`row between small${x.action === sel ? ' selected' : ''}`} style={{ padding: '6px 8px 6px 20px', borderRadius: 6, gap: 8, cursor: 'pointer', background: x.action === sel ? 'var(--accent-bg)' : undefined }} onClick={() => pick(x)}>
                    <span className="col" style={{ gap: 0, minWidth: 0 }}>
                      <span>{titleOf(x)}</span>
                      {named(x) && <span className="mono muted" style={{ fontSize: 11 }}>{x.action}</span>}
                    </span>
                    {x.offer === 'here' && ACTION_SCREEN[x.action] ? (
                      <Link to={ACTION_SCREEN[x.action]} onClick={(e) => e.stopPropagation()} style={{ whiteSpace: 'nowrap' }}>
                        전용 화면 →
                      </Link>
                    ) : x.offer === 'no' ? (
                      <span className="muted" style={{ whiteSpace: 'nowrap' }}>여기서 안 됨</span>
                    ) : (
                      <span className="muted" style={{ whiteSpace: 'nowrap' }}>여기서만</span>
                    )}
                  </div>
                ))}
            </div>
          );
        })}
      </div>
      <div className="col" style={{ gap: 12, minWidth: 0 }}>
        {!a ? (
          <span className="small muted">왼쪽에서 동작을 고르면 입력 칸이 나옵니다.</span>
        ) : (
          <>
            <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              <h2 style={{ fontSize: 15 }}>{titleOf(a)}</h2>
              {named(a) && <span className="mono muted small">{a.action}</span>}
            </div>
            {a.offer === 'no' ? (
              <div className="note un small">이 동작은 여기서 보내지 않습니다(조각 올리기·비밀 값·새 키의 증명·셸 열기 같은 단계).</div>
            ) : ACTION_SCREEN[a.action] ? (
              <div className="note small">
                전용 화면이 있는 동작입니다. 여기서도 보낼 수 있지만, 확인 단계가 있는 <Link to={ACTION_SCREEN[a.action]}>전용 화면</Link>을 권합니다.
              </div>
            ) : (
              <span className="small muted">전용 화면이 없는 동작이라 여기서만 바꿉니다.</span>
            )}
            {a.offer !== 'no' && (
              <>
                {a.fields.map((f) => (
                  <Field key={f.name} label={<span className="mono">{f.name}{f.replace ? ' (통째로 바꿈)' : ''}</span>} group={f.type === 'list' || f.type === 'map' || f.type === 'object'}>
                    <FieldInput key={`${a.action}/${f.name}/${editing?.uid ?? ''}`} f={f} value={vals[f.name]} onChange={(v) => setVals((o) => ({ ...o, [f.name]: v }))} />
                  </Field>
                ))}
                <BaseLine a={a} base={base} manual={manual} typed={typed} setTyped={setTyped} />
                <Field label="사유 (선택)" hint="작업 기록에 함께 남습니다. 512자까지">
                  <input value={reason} maxLength={512} onChange={(e) => setReason(e.target.value)} />
                </Field>
                <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
                  <button className="btn" disabled={!ready || now.busy} onClick={() => void sendNow()}>
                    지금 바로 보내기
                  </button>
                  <button className="btn primary" disabled={Object.keys(payload).length === 0 || (manual && typed === undefined)} onClick={add}>
                    {editing ? '묶음에 고쳐 넣기' : '묶음에 더하기'}
                  </button>
                </div>
                {now.error !== undefined && <MutationError error={now.error} />}
                {now.op && <OpPanel op={now.op} onChange={(o) => setNow({ op: o })} />}
              </>
            )}
            <span className="small muted">입력 칸은 동작마다 서버가 정한 형식대로 나옵니다. 비밀 값은 여기서 넣지 않습니다(비밀값 보관함에서).</span>
          </>
        )}
      </div>
    </div>
  );
}

function BaseLine({ a, base, manual, typed, setTyped }: { a: OpAction; base?: { data?: DOpBase; error?: unknown }; manual: boolean; typed?: number; setTyped: (n: number | undefined) => void }) {
  if (a.base === 'zero') return <span className="small muted">기준 버전 0 (새로 만들기)</span>;
  if (manual)
    return (
      <Field label="기준 버전" hint="‘공유 자원 전체’에서 그 자원의 지금 버전을 확인해 넣습니다">
        <input type="number" className="mono" style={{ width: 140 }} value={typed ?? ''} onChange={(e) => setTyped(e.target.value === '' ? undefined : Number(e.target.value))} />
      </Field>
    );
  if (!base) return <span className="small muted">기준 버전: 칸을 채우면 지금 값을 읽어 자동으로 채웁니다.</span>;
  if (base.error !== undefined) return <MutationError error={base.error} />;
  const d = base.data!;
  return (
    <span className="small">
      기준 버전 <b>{d.expected}</b> <span className="muted">({d.found ? '지금 값을 읽어 자동으로 채움' : '아직 없는 대상 · 새로 만들기'})</span>
      {d.found && d.current !== undefined && <span className="muted"> · 지금: {targetText(d.current as Record<string, unknown>)}</span>}
    </span>
  );
}

const FINAL = new Set<OpView['state']>(['applied', 'rejected', 'failed', 'unknown']);
/** 작업이 끝날 때까지 기다린다(최대 60초, 넘으면 결과 불명으로 멈춘다) */
async function settle(op: OpView): Promise<OpView> {
  let cur = op;
  for (let i = 0; i < 60 && !FINAL.has(cur.state); i++) {
    await new Promise((r) => setTimeout(r, 1000));
    cur = await opGet(cur.id).catch(() => cur);
  }
  return cur;
}

/** 고칠 수 있는 줄: 아직 안 보냈거나, 거부·적용 안 됨으로 확정됐거나, 데몬이 받지 않은 요청 오류(4xx).
 *  불명·진행 중은 결과 조회·재개만 한다. 연결 오류·5xx는 도착했을 수 있어 같은 작업 ID로 다시 보내기만 한다 */
export function editable(x: BatchItem): boolean {
  if (x.op) return x.op.state === 'rejected' || x.op.state === 'failed';
  if (x.error === undefined) return true;
  return x.error instanceof ApiError && x.error.status >= 400 && x.error.status < 500;
}
/** 고쳐 넣는 줄의 작업 ID. 한 번 보낸 줄은 내용이 바뀌므로 새 작업 ID(같은 ID에 다른 내용은 409 op-conflict) */
export const editUid = (x: BatchItem) => (x.op || x.error !== undefined ? newOpId() : x.uid);

/** POST /ops 본문. principal은 비워 로그인한 사용자로(sfcli manage apply와 같다) */
export function opBody(opId: string, a: OpAction, expected: number, payload: Record<string, unknown>, batch?: string) {
  return { opId, action: a.action, expected, payload, ...(typeof payload.Tenant === 'string' ? { tenant: payload.Tenant } : {}), ...(batch ? { batch } : {}) };
}

/** 묶음을 위에서부터 하나씩 보낸다. 모두 같은 batch를 싣고, 거부·불명이 나오면 멈춘다 */
export async function sendBatch(items: BatchItem[], batch: string, update: (uid: string, patch: Partial<BatchItem>) => void): Promise<void> {
  for (const it of items) {
    if (it.op?.state === 'applied') continue;
    // 여기서 보내지 않는 동작(offer: no)은 보내지 않고 묶음을 멈춘다
    if (it.action.offer !== 'here') {
      update(it.uid, { error: new ApiError(0, { code: 'not-offered', message: '이 동작은 이 화면에서 보내지 않습니다' }) });
      return;
    }
    try {
      let expected = it.expected;
      if (expected === undefined) expected = (await opActionBase(it.action.action, it.payload)).expected;
      const r = await api.postWith<{ op: DOp }>('/ops', opBody(it.uid, it.action, expected, it.payload, batch), reasonHeaders(it.reason));
      const op = await settle(toOp(r.op));
      update(it.uid, { op, error: undefined });
      if (op.state !== 'applied') return;
    } catch (error) {
      update(it.uid, { error });
      return;
    }
  }
}

/** 변경 파일 (CLI와 같은 모양) */
export interface ChangeFile {
  schema: 1;
  action: string;
  expected: number;
  payload: Record<string, unknown>;
}
/** unknown: 모르는 동작·모양, blocked: 여기서 보내지 않는 동작(offer: no) */
export function parseChangeFile(text: string, actions: OpAction[]): { items: BatchItem[]; unknown: string[]; blocked: string[] } {
  const raw: unknown = JSON.parse(text);
  const list = (Array.isArray(raw) ? raw : [raw]) as Partial<ChangeFile>[];
  const items: BatchItem[] = [];
  const unknown: string[] = [];
  const blocked: string[] = [];
  for (const x of list) {
    const a = actions.find((y) => y.action === x.action);
    if (!a || x.schema !== 1 || typeof x.payload !== 'object' || x.payload === null) {
      unknown.push(String(x.action ?? '?'));
      continue;
    }
    if (a.offer !== 'here') {
      blocked.push(a.action);
      continue;
    }
    items.push({ uid: newOpId(), action: a, vals: x.payload as Record<string, Val>, payload: x.payload as Record<string, unknown>, expected: typeof x.expected === 'number' ? x.expected : undefined });
  }
  return { items, unknown, blocked };
}

const STATE: Record<OpView['state'], ['ok' | 'un' | 'er' | 'pr', string]> = {
  applied: ['ok', '확정'],
  unknown: ['un', '불명'],
  rejected: ['er', '거부'],
  failed: ['er', '적용 안 됨'],
  pending: ['pr', '진행 중'],
  running: ['pr', '진행 중'],
};

/** 보낼 변경 묶음 */
export function ChangeBatch({ items, setItems, actions, onEdit, onSent }: { items: BatchItem[]; setItems: (f: (x: BatchItem[]) => BatchItem[]) => void; actions: OpAction[]; onEdit: (it: BatchItem) => void; onSent: () => void }) {
  const [sending, setSending] = useState(false);
  const [drag, setDrag] = useState<number>();
  const [fileErr, setFileErr] = useState<string>();
  const fileRef = useRef<HTMLInputElement>(null);
  // 한 묶음 = 한 batch. 멈춘 뒤 다시 보내도 같은 값이고, 비우면 새로 만든다
  const batch = useRef(newOpId());
  const update = (uid: string, patch: Partial<BatchItem>) => setItems((xs) => xs.map((x) => (x.uid === uid ? { ...x, ...patch } : x)));
  const send = async () => {
    // 아직 하나도 보내지 않은 묶음이면 새 batch
    if (!items.some((x) => x.op || x.error !== undefined)) batch.current = newOpId();
    setSending(true);
    await sendBatch(items, batch.current, update);
    setSending(false);
    onSent();
  };
  const exportFile = () => {
    const body: ChangeFile[] = items.map((x) => ({ schema: 1, action: x.action.action, expected: x.expected ?? 0, payload: x.payload }));
    const url = URL.createObjectURL(new Blob([JSON.stringify(body.length === 1 ? body[0] : body, null, 2)], { type: 'application/json' }));
    const el = document.createElement('a');
    el.href = url;
    el.download = 'changes.json';
    el.click();
    URL.revokeObjectURL(url);
  };
  const importFile = async (f: File) => {
    setFileErr(undefined);
    try {
      const { items: got, unknown, blocked } = parseChangeFile(await f.text(), actions);
      setItems((xs) => [...xs, ...got]);
      const notes = [
        unknown.length ? `이 화면에서 모르는 동작은 뺐습니다: ${unknown.join(', ')}` : '',
        blocked.length ? `여기서 보내지 않는 동작은 뺐습니다(CLI로 보내세요): ${blocked.join(', ')}` : '',
      ].filter(Boolean);
      if (notes.length) setFileErr(notes.join(' · '));
    } catch {
      setFileErr('변경 파일(JSON)을 읽지 못했습니다');
    }
  };
  const move = (from: number, to: number) =>
    setItems((xs) => {
      const ys = [...xs];
      const [x] = ys.splice(from, 1);
      ys.splice(to, 0, x);
      return ys;
    });
  // 결과를 아직 모르는 변경(불명·진행 중)이 있으면 순서·내용을 바꾸지 않는다
  const locked = sending || items.some((x) => x.op && (x.op.state === 'unknown' || x.op.state === 'pending' || x.op.state === 'running'));
  const baseText = (x: BatchItem, i: number): ReactNode =>
    x.action.base === 'zero' ? '0 (새로)' : x.expected !== undefined ? String(x.expected) : i > 0 ? `보낼 때 읽음 (${i}번 뒤)` : '보낼 때 읽음';
  return (
    <Card
      title={`보낼 변경 묶음 (${items.length})`}
      actions={
        <span className="row" style={{ gap: 8 }}>
          <input ref={fileRef} type="file" accept="application/json,.json" hidden onChange={(e) => (e.target.files?.[0] && void importFile(e.target.files[0]), (e.target.value = ''))} />
          <button className="btn" disabled={sending} onClick={() => fileRef.current?.click()}>
            파일 불러오기
          </button>
          <button className="btn" disabled={!items.length} onClick={exportFile}>
            파일로 내보내기
          </button>
        </span>
      }
    >
      {fileErr && <div className="note wa small">{fileErr}</div>}
      {items.length === 0 ? (
        <span className="small muted">묶음이 비어 있습니다. 위에서 동작을 골라 ‘묶음에 더하기’를 누르거나 변경 파일을 불러옵니다.</span>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th />
                <th>#</th>
                <th>동작</th>
                <th>대상</th>
                <th>기준 버전</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((x, i) => {
                const st = x.op ? STATE[x.op.state] : undefined;
                return (
                  <tr
                    key={x.uid}
                    draggable={!locked}
                    onDragStart={() => setDrag(i)}
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={() => (drag !== undefined && drag !== i && move(drag, i), setDrag(undefined))}
                    style={drag === i ? { opacity: 0.5 } : undefined}
                  >
                    <td className="muted" style={{ cursor: locked ? undefined : 'grab' }} aria-hidden>
                      ⋮⋮
                    </td>
                    <td>{i + 1}</td>
                    <td className="wrap">
                      {titleOf(x.action)} {named(x.action) && <span className="mono muted small">{x.action.action}</span>}
                    </td>
                    <td className="mono">{targetText(x.payload)}</td>
                    <td className="mono">{baseText(x, i)}</td>
                    <td>
                      <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                        {st ? <Badge tone={st[0]}>{st[1]}</Badge> : x.error !== undefined ? <Badge tone="er">보내지 못함</Badge> : null}
                        {editable(x) && (
                          <>
                            <button className="btn sm" disabled={locked} onClick={() => (onEdit(x), setItems((xs) => xs.filter((y) => y.uid !== x.uid)))}>
                              고치기
                            </button>
                            <button className="btn sm" disabled={locked} aria-label={`${i + 1}번 빼기`} onClick={() => setItems((xs) => xs.filter((y) => y.uid !== x.uid))}>
                              ✕
                            </button>
                          </>
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
      {items.map((x) => (x.error !== undefined ? <MutationError key={x.uid} error={x.error} /> : null))}
      {items.map((x) => (x.op && x.op.state === 'unknown' ? <OpPanel key={x.uid} op={x.op} onChange={(o) => update(x.uid, { op: o })} /> : null))}
      <span className="small muted">
        줄을 끌어 순서를 바꿉니다. 위에서부터 하나씩 보내고, 거부되거나 결과를 모르는 변경이 나오면 그 뒤는 보내지 않습니다. 앞 변경에 기대는 기준 버전은 앞 변경이 확정된 뒤 채웁니다. 확정된 앞 변경은 되돌리지 않습니다.
      </span>
      <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
        <button className="btn" disabled={!items.length || sending} onClick={() => (setItems(() => []), (batch.current = newOpId()))}>
          비우기
        </button>
        <button className="btn primary" disabled={!items.length || sending || items.every((x) => x.op?.state === 'applied')} onClick={() => void send()}>
          {sending ? '보내는 중…' : `${items.filter((x) => x.op?.state !== 'applied').length}개 차례로 보내기`}
        </button>
      </div>
    </Card>
  );
}
