// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';
import { API_MODE, ApiError } from '../api/client';
import { images, registries, resolveImage } from '../api/endpoints';
import type { ImageResolveView, ImageView, Page } from '../api/types';
import { usePoll } from '../lib/usePoll';
import { ago, hhmmss, middle } from '../lib/format';
import { Dialog } from './Dialog';
import { Badge, Field, Segmented } from './ui';
import { Empty, Load } from './states';

/** 고른 이미지를 원문에 쓸 이름으로: 저장소 주소/repo:tag 또는 @digest(내용 고정) */
export function imageRef(i: ImageView, endpoint: string | undefined, pin: boolean): string {
  const host = endpoint ? `${endpoint.replace(/\/+$/, '')}/` : '';
  return pin && i.digest ? `${host}${i.repo}@${i.digest}` : `${host}${i.repo}:${i.tag}`;
}

/** 형식 검사(브라우저에서 할 수 있는 것만): 저장소/경로[:태그][@sha256:64hex] */
export function imageRefProblem(v: string): string | undefined {
  if (!v) return '이미지 참조를 넣어 주세요.';
  if (/\s/.test(v)) return '이미지 참조에 빈칸이 있습니다.';
  if (!/^[a-z0-9][a-z0-9._\-/:]*[a-z0-9](:[\w][\w.-]{0,127})?(@sha256:[0-9a-f]{64})?$/.test(v)) return '저장소/이름:태그 또는 @sha256:… 형식이 아닙니다.';
  return undefined;
}
const pinTo = (ref: string, digest?: string) => (digest ? `${ref.replace(/@sha256:[0-9a-f]{64}$/, '').replace(/:[\w][\w.-]{0,127}$/, (t) => (ref.lastIndexOf('/') < ref.lastIndexOf(t) ? '' : t))}@${digest}` : ref);

// 최근 사용: 이 브라우저에만(서버에 저장하지 않음). 저장이 막혀도 동작은 그대로.
const RECENT_KEY = 'sfc.recent-images';
interface Recent {
  ref: string;
  at: string;
  note?: string;
}
export function recentImages(): Recent[] {
  try {
    return (JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]') as Recent[]).slice(0, 10);
  } catch {
    return [];
  }
}
export function rememberImage(ref: string, note?: string) {
  try {
    const next = [{ ref, at: new Date().toISOString(), note }, ...recentImages().filter((r) => r.ref !== ref)].slice(0, 10);
    localStorage.setItem(RECENT_KEY, JSON.stringify(next));
  } catch {
    /* 저장 불가 */
  }
}

const emptyPage = (): Page<ImageView> => ({ items: [], next: '', revision: 0, asOf: new Date().toISOString() });
type Tab = 'list' | 'manual' | 'recent';

/** 이미지 참조 확인 실패 코드(#237, sfcd image-resolve) */
const RESOLVE_FAIL: Record<string, string> = {
  'not-found': '이 태그나 digest를 찾지 못했습니다',
  unauthorized: '저장소 로그인에 실패했습니다. 외부 저장소의 로그인 정보를 확인하세요',
  denied: '로그인은 됐지만 이 이미지를 읽을 권한이 없습니다',
  unavailable: '저장소에 닿지 않습니다',
  unsupported: '지원하지 않는 이미지 형식입니다',
  timeout: '저장소가 제때 답하지 않았습니다',
  cancelled: '확인이 취소됐습니다. 다시 확인해 보세요',
  'metadata-budget': '이미지 정보가 너무 커서 읽기를 멈췄습니다',
  'image-budget': '이미지가 받을 수 있는 크기를 넘습니다',
  'invalid-ca': '외부 저장소의 CA 인증서를 쓸 수 없습니다',
  'invalid-credential': '외부 저장소의 로그인 정보(비밀값)를 쓸 수 없습니다',
  'invalid-source': '외부 저장소 정의가 올바르지 않습니다',
};
function digestMiss(code?: string) {
  if (code === 'untrusted') return '신뢰 규칙에 없어 저장소에 묻지 않았습니다';
  if (code === 'source-revoked' || code === 'source-not-ready') return '저장소를 쓸 수 없어 묻지 않았습니다';
  return (code && RESOLVE_FAIL[code]) ?? (code ? `읽지 못했습니다 (${code})` : '읽지 못했습니다');
}
function findRow(r: ImageResolveView): ['ok' | 'er' | 'wa' | 'un', React.ReactNode] {
  const at = r.registry ? <code>{r.registry}</code> : null;
  if (r.code === 'source-revoked') return ['er', <>맞는 외부 저장소 정의{r.source ? ` ${r.source}` : ''}가 지워졌거나 꺼져 있습니다</>];
  if (r.code === 'source-not-ready') return ['wa', <>외부 저장소 {r.source ?? r.registry}를 읽을 서버가 없습니다. 외부 저장소 탭에서 서버를 연결하세요</>];
  if (r.registryKind === 'builtin') return ['ok', <>내장 저장소{r.source ? ` ${r.source}` : ''} {at}</>];
  if (r.registryKind === 'external') return ['ok', <>외부 저장소 {r.source ?? ''} {at}</>];
  return ['ok', <>공개 저장소 {at} · 로그인 없이 받음</>];
}
function TrustMiss({ r }: { r: ImageResolveView }) {
  const rules = r.rules ?? [];
  return (
    <span className="col" style={{ gap: 4 }}>
      <span>{r.reason ?? '신뢰 출처가 아님'}</span>
      {rules.length > 0 && (
        <span>
          이 작업 공간 규칙{' '}
          {rules.map((x, i) => (
            <span key={i}>
              <code style={{ whiteSpace: 'nowrap' }}>
                {x.registry}/{x.repository}
              </code>{' '}
            </span>
          ))}
        </span>
      )}
    </span>
  );
}

/** 직접 입력 확인 결과 네 줄(형식 → 저장소 → 신뢰 → digest). sfcd image-resolve(#237)는 신뢰를 먼저 보고, 신뢰 안 되면 저장소에 묻지 않는다. */
function ResolveSteps({ problem, r, waiting, failed }: { problem?: string; r?: ImageResolveView; waiting: boolean; failed?: string }) {
  const row = (label: string, tone: 'ok' | 'er' | 'wa' | 'un' | 'pr', text: React.ReactNode) => (
    <div className="row" style={{ gap: 8 }}>
      <Badge tone={tone}>{tone === 'ok' ? '✓' : tone === 'er' ? '✕' : tone === 'pr' ? '…' : '–'}</Badge>
      <b style={{ width: 90, flex: 'none' }}>{label}</b>
      <span className="muted" style={{ flex: 1, minWidth: 0 }}>
        {text}
      </span>
    </div>
  );
  if (problem) return <div className="col small">{row('형식 확인', 'er', problem)}</div>;
  return (
    <div className="col small" style={{ gap: 6 }}>
      {row('형식 확인', 'ok', '맞음')}
      {failed ? (
        row('저장소 찾기', 'un', failed)
      ) : waiting || !r ? (
        row('저장소 찾기', 'pr', '확인 중')
      ) : (
        <>
          {row('저장소 찾기', ...findRow(r))}
          {row('신뢰 정책', r.trusted !== false && r.code !== 'untrusted' ? 'ok' : 'er', r.trusted !== false && r.code !== 'untrusted' ? '신뢰 출처' : <TrustMiss r={r} />)}
          {row('digest 확인', r.digest && !r.code ? 'ok' : r.code === 'untrusted' || r.code === 'source-revoked' || r.code === 'source-not-ready' ? 'un' : 'er', r.digest && !r.code ? <code>{middle(r.digest, 11, 4)}</code> : digestMiss(r.code))}
        </>
      )}
    </div>
  );
}

/**
 * 이미지 고르기 다이얼로그(캔버스 UI-3F 눌렀을 때): 목록에서 고르기 / 직접 입력 / 최근 사용, 공통으로 digest 고정.
 * 목록은 이미지 관리(UI-84)와 같은 웹 캐시이고 sfcd 목록 조회 전까지 목업에만 있다.
 */
export function ImagePickDialog({ tenant, current = '', onPick, onClose }: { tenant: string; current?: string; onPick: (ref: string) => void; onClose: () => void }) {
  const listReady = API_MODE === 'mock';
  const [tab, setTab] = useState<Tab>(listReady ? 'list' : 'manual');
  const [pin, setPin] = useState(true);
  // 목록
  const list = usePoll((s) => (listReady ? images(tenant, s) : Promise.resolve(emptyPage())), [tenant], 0);
  const regs = usePoll((s) => registries(tenant, s), [tenant], 0);
  const [find, setFind] = useState('');
  const [reg, setReg] = useState('');
  const [sel, setSel] = useState<ImageView>();
  // 직접 입력
  const [manual, setManual] = useState(current);
  const [checked, setChecked] = useState<string>();
  const [res, setRes] = useState<ImageResolveView>();
  const [resFail, setResFail] = useState<string>();
  const [resolving, setResolving] = useState(false);
  // 최근
  const [recent] = useState(recentImages);
  const [recentSel, setRecentSel] = useState<string>();

  const problem = imageRefProblem(manual);
  const check = async () => {
    if (problem || checked === manual) return;
    setChecked(manual);
    setRes(undefined);
    setResFail(undefined);
    setResolving(true);
    try {
      setRes(await resolveImage(tenant, manual));
    } catch (e) {
      setResFail(
        e instanceof ApiError && e.code === 'invalid-ref'
          ? '이미지 참조 형식이 맞지 않습니다. 저장소/이름:태그 또는 @sha256:… 형식으로 넣으세요'
          : e instanceof ApiError && (e.status === 404 || e.status === 501)
            ? '서버 기능 대기: 실행 전 확인에서 검사합니다'
            : '확인하지 못했습니다. 실행 전 확인에서 다시 검사합니다',
      );
    } finally {
      setResolving(false);
    }
  };
  useEffect(() => {
    if (checked && checked !== manual) {
      setRes(undefined);
      setResFail(undefined);
    }
  }, [manual, checked]);

  const endpoint = (name: string) => regs.data?.items.find((r) => r.name === name)?.endpoint;
  const result: string | undefined =
    tab === 'list' ? (sel ? imageRef(sel, endpoint(sel.registry), pin) : undefined) : tab === 'recent' ? recentSel : problem ? undefined : pin && res?.digest && checked === manual ? (res.pinned ?? pinTo(manual, res.digest)) : manual;
  const use = () => {
    if (!result) return;
    rememberImage(result);
    onPick(result);
    onClose();
  };
  const regName = (n: string) => (n === 'builtin' ? '내장' : `외부 ${n}`);

  return (
    <Dialog
      title="이미지 고르기"
      onClose={onClose}
      width={720}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn primary" disabled={!result} onClick={use}>
            이 이미지 쓰기
          </button>
        </>
      }
    >
      <div style={{ marginBottom: 12 }}>
        <Segmented
          label="고르는 방법"
          value={tab}
          onChange={setTab}
          options={[
            ['list', '목록에서 고르기'],
            ['manual', '직접 입력'],
            ['recent', '최근 사용'],
          ]}
        />
      </div>
      {tab === 'list' &&
        (!listReady ? (
          <Empty kind="scope" title="서버 기능 대기">
            이미지 목록은 sfcd 이미지 목록 조회가 들어오면 이미지 관리와 같은 캐시로 보여 줍니다. 지금은 직접 입력을 쓰세요.
          </Empty>
        ) : (
          <div className="col" style={{ gap: 8 }}>
            <div className="row small">
              <Field label="찾기">
                <input type="search" value={find} onChange={(e) => setFind(e.target.value)} placeholder="이미지 이름" style={{ width: 220 }} />
              </Field>
              <Field label="저장소">
                <select value={reg} onChange={(e) => setReg(e.target.value)}>
                  <option value="">
                    전체 ({(regs.data?.items ?? []).map((r) => (r.name === 'builtin' ? '내장' : r.name)).join(' · ') || '…'})
                  </option>
                  {(regs.data?.items ?? []).map((r) => (
                    <option key={r.id} value={r.name}>
                      {regName(r.name)}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
            <Load q={list}>
              {(p) => {
                const rows = p.items.filter((i) => (!reg || i.registry === reg) && (!find || `${i.repo}:${i.tag}`.toLowerCase().includes(find.toLowerCase())));
                return rows.length === 0 ? (
                  <Empty kind={find || reg ? 'filtered' : 'first'} title={find || reg ? '찾는 이미지가 없습니다' : '이 작업 공간에 이미지가 없습니다'} />
                ) : (
                  <div className="table-wrap">
                    <table className="tbl">
                      <thead>
                        <tr>
                          <th>이미지 · 태그</th>
                          <th>저장소</th>
                          <th>올린 때</th>
                          <th>신뢰</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((i) => (
                          <tr key={i.registry + i.repo + i.tag} className={sel === i ? 'selected' : undefined} onClick={() => setSel(i)} onDoubleClick={() => (setSel(i), setTimeout(use))} style={{ cursor: 'pointer' }} aria-selected={sel === i}>
                            <td>
                              <code>{`${i.repo}:${i.tag}`}</code>
                            </td>
                            <td>{regName(i.registry)}</td>
                            <td>{ago(i.pushedAt)}</td>
                            <td>{i.trusted === false ? <Badge tone="er">신뢰 안 함</Badge> : <Badge tone="ok">신뢰함</Badge>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                );
              }}
            </Load>
            <label className="check small">
              <input type="checkbox" checked={pin} onChange={(e) => setPin(e.target.checked)} /> 태그 대신 digest로 고정
              <span className="muted">{sel ? ` ${middle(sel.digest, 11, 4)}로 넣어 나중에 태그가 바뀌어도 같은 이미지` : ' 나중에 태그가 바뀌어도 같은 이미지'}</span>
            </label>
            <span className="small muted">
              이미지 관리(UI-84)와 같은 목록(웹 캐시, {list.asOf ? `${hhmmss(list.asOf)} 기준` : '읽는 중'} ·{' '}
              <button type="button" className="btn ghost sm" onClick={() => list.refresh()}>
                ↻ 새로고침
              </button>
              )입니다. 신뢰하지 않는 이미지는 고를 수 있지만 실행 전 확인에서 막힙니다.
            </span>
          </div>
        ))}
      {tab === 'manual' && (
        <div className="col" style={{ gap: 10 }}>
          <Field group label="이미지 참조" hint="저장소/이름:태그 또는 @sha256:… 형식" error={manual && problem}>
            <span className="row" style={{ flexWrap: 'nowrap' }}>
              <input
                className="mono grow"
                value={manual}
                onChange={(e) => setManual(e.target.value.trim())}
                onBlur={() => void check()}
                onKeyDown={(e) => e.key === 'Enter' && void check()}
                placeholder="ghcr.io/acme/tools:1.4"
              />
              <button type="button" className="btn sm" disabled={!!problem} onClick={() => void check()}>
                확인
              </button>
            </span>
          </Field>
          {(checked || problem) && (
            <div className="card" style={{ padding: 12 }}>
              <b className="small">확인 결과</b>
              <ResolveSteps problem={manual ? problem : undefined} r={checked === manual ? res : undefined} waiting={resolving} failed={checked === manual ? resFail : undefined} />
            </div>
          )}
          <label className="check small">
            <input type="checkbox" checked={pin} onChange={(e) => setPin(e.target.checked)} /> 확인한 digest로 고정
          </label>
          {res && checked === manual && !!res.platforms?.length && (
            <span className="small muted">
              여러 플랫폼 이미지: {res.platforms.map((p) => p.platform ?? '플랫폼 미상').join(', ')}. 고정하면 목록 전체(index) digest로 고정하고, 서버가 자기 플랫폼을 고릅니다.
            </span>
          )}
          {res && checked === manual && (res.trusted === false || res.code === 'untrusted') && <div className="note er small">신뢰 출처가 아니라 이대로는 실행할 수 없습니다. 신뢰 출처(UI-82)에 추가하거나 다른 이미지를 고르세요.</div>}
          <span className="small muted">입력이 끝나면(포커스를 옮기거나 [확인]) 저장소에서 digest를 확인합니다. 목록에 없는 이미지도 쓸 수 있습니다.</span>
        </div>
      )}
      {tab === 'recent' &&
        (recent.length === 0 ? (
          <Empty title="최근에 고른 이미지가 없습니다">이 브라우저에서 고른 이미지가 여기에 남습니다.</Empty>
        ) : (
          <div className="col" style={{ gap: 6 }}>
            {recent.map((r) => (
              <label key={r.ref} className={`choice${recentSel === r.ref ? ' on' : ''}`}>
                <input type="radio" name="recent-image" checked={recentSel === r.ref} onChange={() => setRecentSel(r.ref)} />
                <code className="grow">{r.ref}</code>
                <span className="small muted">
                  {ago(r.at)}
                  {r.note ? ` · ${r.note}` : ''}
                </span>
              </label>
            ))}
            <span className="small muted">이 브라우저에서 내가 고른 이미지 10개. 서버에 저장하지 않습니다.</span>
          </div>
        ))}
    </Dialog>
  );
}

/** 이미지 칸: 고른 결과(참조·저장소·digest)만 보이고, 바꾸려면 언제나 '이미지 고르기…' 다이얼로그를 연다. */
export function ImageInput({ tenant, value, onChange, sub }: { tenant: string; value: string; onChange: (v: string) => void; sub?: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const digest = /@(sha256:[0-9a-f]{64})$/.exec(value)?.[1];
  return (
    <span className="image-field">
      <span className="col grow" style={{ minWidth: 0, gap: 0 }}>
        {value ? <b className="mono el">{value.replace(/@sha256:[0-9a-f]{64}$/, '')}</b> : <span className="muted">아직 고르지 않았습니다</span>}
        {value && <span className="muted mono small el">{sub ?? (digest ? `digest 고정 · ${middle(digest, 11, 4)}` : '태그 (digest 고정 아님)')}</span>}
      </span>
      <button type="button" className="btn sm" onClick={() => setOpen(true)}>
        이미지 고르기…
      </button>
      {open && <ImagePickDialog tenant={tenant} current={value} onPick={onChange} onClose={() => setOpen(false)} />}
    </span>
  );
}
