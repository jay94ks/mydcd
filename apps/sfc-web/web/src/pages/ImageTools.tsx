// SPDX-License-Identifier: Apache-2.0

// 이미지 목록의 태그 추가 창 · 레이어 보기(UI-89) · 이미지 업로드(UI-88). 캔버스 ImagesIx · ImageLayers · ImageUpload.
// 모두 웹 데몬이 내장 저장소 API를 직접 쓰는 웹 기능이다(op가 아님). 저장소 자격은 데몬만 갖고 브라우저에는 오지 않는다.
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/client';
import {
  addImageTag,
  deleteUpload,
  imageManifest,
  imageUpload,
  imageUploads,
  imageUsage,
  inspectUpload,
  layerFiles,
  pushUpload,
  putUploadChunk,
  registries,
  registryImagesAll,
  startImageUpload,
  type ImageUse,
  type RegistryImage,
} from '../api/endpoints';
import type { DImageManifest, DImageUpload, DLayerFile, DLayerFiles } from '../api/dto';
import type { RegistryView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Badge, Card, Field, HelpBox } from '../components/ui';
import { Dialog } from '../components/Dialog';
import { MutationError } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { fmtBytes } from '../lib/format';
import { eulReul, eunNeun } from '../lib/josa';
import { emptyStandalone, standaloneToYaml } from '../lib/standalone';
import { usePoll } from '../lib/usePoll';
import { when } from './WebBackup';
import { agoMs, short, usedText, usesOf } from './ImageList';
import { registriesLive } from '../lib/liveTopics';

const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const REPO_RE = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$/;
const tagProblem = (t: string) => (!t ? '태그를 적어 주세요' : TAG_RE.test(t) ? undefined : '영문·숫자·_ . - 128자까지 (. 이나 -로 시작하지 않음)');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const errText = (e: unknown) => (e instanceof ApiError ? e.body.message || e.code : (e as Error)?.message || '알 수 없는 오류');

// ── 태그 추가 ─────────────────────────────────────────────
/** 같은 저장소 이미지들(태그가 지금 무엇을 가리키는지 보려고 받는다) */
export function TagDialog({ tenant, reg, img, siblings, onClose, onDone }: { tenant: string; reg: RegistryView; img: RegistryImage; siblings: RegistryImage[]; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [tag, setTag] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  /** 서버가 알려 준 지금 그 태그의 이미지(목록 캐시가 낡았을 때) */
  const [server, setServer] = useState<{ tag: string; current: string }>();
  const t = tag.trim();
  const problem = t ? tagProblem(t) : undefined;
  const local = siblings.find((s) => s.repository === img.repository && s.tags.includes(t));
  const current = server?.tag === t ? server.current : local?.digest;
  const already = !!t && current === img.digest;
  const moves = !!t && !!current && current !== img.digest;
  const curTags = siblings.find((s) => s.digest === current)?.tags.filter((x) => x !== t) ?? [];
  const send = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await addImageTag(tenant, reg.id, { repository: img.repository, digest: img.digest, tag: t, ...(moves ? { overwrite: true } : {}) });
      toast(`${img.repository}:${t} 태그를 붙였습니다.`);
      onDone();
      onClose();
    } catch (e) {
      // 목록 캐시가 낡아 몰랐던 태그: 무엇을 가리키는지 보여 주고 한 번 더 누르게 한다
      if (e instanceof ApiError && e.code === 'tag-exists') setServer({ tag: t, current: String((e.body.raw as { current?: string } | undefined)?.current ?? '') });
      else setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`태그 추가 · ${img.repository}@${short(img.digest)}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn primary" disabled={busy || !t || !!problem || already} onClick={() => void send()}>
            {busy ? '붙이는 중…' : '태그 붙이기'}
          </button>
        </>
      }
    >
      <Field label="새 태그" error={problem} hint={already ? `이미 이 이미지를 가리킵니다` : img.tags.length ? `지금 태그: ${img.tags.join(', ')}` : '지금은 태그 없는 이미지입니다'}>
        <input className="mono" value={tag} onChange={(e) => setTag(e.target.value)} placeholder="stable" autoFocus onKeyDown={(e) => e.key === 'Enter' && t && !problem && !already && !busy && void send()} />
      </Field>
      {moves && (
        <div className="note wa small">
          {t}
          {eunNeun(t)} 지금 {short(current!)}
          {curTags.length ? `(${curTags.join(', ')})` : ''}
          {eulReul(curTags.length ? curTags[curTags.length - 1] : current!)} 가리킵니다. 바꾸면 {t}
          {eulReul(t)} 쓰는 자동 배포가 새 이미지를 받습니다.
        </div>
      )}
      <MutationError error={error} />
    </Dialog>
  );
}

// ── 레이어 보기 (UI-89) ──────────────────────────────────
interface LayerRow {
  n: number;
  createdBy: string;
  digest?: string;
  bytes: number;
}
/** history(빈 레이어 포함)와 레이어를 맞춘다. 수가 안 맞으면 레이어만 */
function layerRows(m: DImageManifest): LayerRow[] {
  const layers = m.layers ?? [];
  const hist = m.history ?? [];
  if (hist.length && hist.filter((h) => !h.emptyLayer).length === layers.length) {
    let i = 0;
    return hist.map((h, n) => {
      if (h.emptyLayer) return { n: n + 1, createdBy: cleanCmd(h.createdBy ?? h.comment ?? ''), bytes: 0 };
      const l = layers[i++];
      return { n: n + 1, createdBy: cleanCmd(h.createdBy ?? l.createdBy ?? ''), digest: l.digest, bytes: l.bytes };
    });
  }
  return layers.map((l, n) => ({ n: n + 1, createdBy: cleanCmd(l.createdBy ?? ''), digest: l.digest, bytes: l.bytes }));
}
/** docker history 꼴 '/bin/sh -c #(nop) ' 머리를 걷는다 */
const cleanCmd = (s: string) =>
  s
    .replace(/^\/bin\/sh -c #\(nop\)\s*/, '')
    .replace(/^\/bin\/sh -c /, 'RUN ')
    .replace(/\s*# buildkit$/, '')
    .trim() || '(명령 기록 없음)';
const SECRETISH = /pass|secret|token|key|credential|auth/i;

interface FileLine {
  sign: '+' | '−';
  /** 들여쓴 이름(가장 가까운 위 폴더 줄 기준 상대 경로) */
  name: string;
  note: string;
}
/** 바뀐 파일을 폴더 크기와 함께 줄로. 앞 max줄만 보이고 나머지는 '… N개 파일' */
function fileLines(files: DLayerFile[], max = 40): { lines: FileLine[]; more: number } {
  const norm = (f: DLayerFile) => {
    const p = '/' + f.path.replace(/^\.?\//, '').replace(/\/$/, '');
    return f.type === 'dir' ? p + '/' : p;
  };
  const all = files.map((f) => ({ ...f, path: norm(f) })).sort((a, b) => (a.path < b.path ? -1 : 1));
  const size = new Map<string, number>();
  for (const f of all)
    if (f.type !== 'dir' && !f.whiteout) {
      const parts = f.path.split('/');
      for (let i = 1; i < parts.length; i++) {
        const d = parts.slice(0, i).join('/') + '/';
        size.set(d, (size.get(d) ?? 0) + f.bytes);
      }
    }
  const lines: FileLine[] = [];
  /** 보여 준 폴더 줄(깊이 순) */
  const stack: string[] = [];
  for (const f of all) {
    if (lines.length >= max) break;
    while (stack.length && !f.path.startsWith(stack[stack.length - 1])) stack.pop();
    const parent = stack[stack.length - 1];
    const name = '  '.repeat(stack.length) + (parent ? f.path.slice(parent.length) : f.path);
    const isDir = f.type === 'dir';
    const note = f.whiteout ? '(아래 레이어 파일 지움)' : isDir ? fmtBytes(size.get(f.path) ?? 0) : f.type === 'symlink' ? `→ ${f.link ?? ''}` : f.type === 'hardlink' ? `= ${f.link ?? ''}` : fmtBytes(f.bytes);
    lines.push({ sign: f.whiteout ? '−' : '+', name, note });
    if (isDir) stack.push(f.path);
  }
  return { lines, more: all.length - lines.length };
}

export function LayersDialog({
  tenant,
  reg,
  img,
  tag,
  use,
  onClose,
}: {
  tenant: string;
  reg: RegistryView;
  img: RegistryImage;
  tag: string;
  use?: ImageUse;
  onClose: () => void;
}) {
  const toast = useToast();
  const navigate = useNavigate();
  const [platform, setPlatform] = useState('');
  const [tab, setTab] = useState<'layers' | 'config' | 'tags' | 'used'>('layers');
  const man = usePoll(
    async (s) => {
      const m = await imageManifest(tenant, reg.id, img.repository, img.digest, platform || undefined, s);
      // 여러 플랫폼 묶음이면 첫 플랫폼을 연다
      if (!platform && m.platforms?.length && !m.layers?.length) {
        const first = m.platforms.find((p) => p.platform === 'linux/amd64')?.platform ?? m.platforms[0].platform;
        const one = await imageManifest(tenant, reg.id, img.repository, img.digest, first, s);
        return { m: one, platforms: m.platforms, picked: first };
      }
      return { m, platforms: m.platforms, picked: platform };
    },
    [tenant, reg.id, img.repository, img.digest, platform],
    0,
  );
  const [plats, setPlats] = useState<string[]>([]);
  useEffect(() => {
    if (man.data?.platforms?.length) setPlats(man.data.platforms.map((p) => p.platform));
  }, [man.data]);
  const rows = useMemo(() => (man.data ? layerRows(man.data.m) : []), [man.data]);
  const [sel, setSel] = useState<number>();
  useEffect(() => {
    // 처음에는 가장 큰 레이어를 고른다
    if (!rows.length) return setSel(undefined);
    setSel((s) => (s !== undefined && rows[s] ? s : rows.reduce((b, r, i) => (r.bytes > rows[b].bytes ? i : b), 0)));
  }, [rows]);
  const cur = sel !== undefined ? rows[sel] : undefined;
  const cache = useRef(new Map<string, DLayerFiles | { error: unknown }>());
  const [, bump] = useState(0);
  useEffect(() => {
    const d = cur?.digest;
    if (!d || cache.current.has(d)) return;
    const ac = new AbortController();
    layerFiles(tenant, reg.id, img.repository, d, ac.signal).then(
      (f) => (cache.current.set(d, f), bump((x) => x + 1)),
      (e) => ((e as Error).name !== 'AbortError' && cache.current.set(d, { error: e }), bump((x) => x + 1)),
    );
    return () => ac.abort();
  }, [cur?.digest, tenant, reg.id, img.repository]);
  const files = cur?.digest ? cache.current.get(cur.digest) : undefined;

  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.focus();
    const prev = document.activeElement as HTMLElement | null;
    return () => prev?.focus?.();
  }, []);
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') return onClose();
    if (tab !== 'layers' || !rows.length || /INPUT|SELECT|TEXTAREA/.test((e.target as HTMLElement).tagName)) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      setSel((s) => Math.max(0, Math.min(rows.length - 1, (s ?? 0) + (e.key === 'ArrowDown' ? 1 : -1))));
    }
  };
  const pullRef = `${reg.endpoint}/${img.repository}@${img.digest}`;
  const copy = () => void navigator.clipboard?.writeText(img.digest).then(() => toast('다이제스트를 복사했습니다.'));
  const deploy = () => navigate('/standalone/new', { state: { yaml: standaloneToYaml({ ...emptyStandalone(), image: pullRef }) } });
  const nUse = usesOf(use);
  const usedParts = usedText(use).text.split(' / ').filter(Boolean);
  const total = rows.reduce((a, r) => a + r.bytes, 0);
  const cfg = man.data?.m.config?.config;
  const env = cfg?.Env ?? [];

  return (
    <div className="backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} tabIndex={-1} className="dialog w720" role="dialog" aria-modal="true" aria-label={`${img.repository}:${tag || short(img.digest)} 레이어`} onKeyDown={onKey}>
        <header style={{ alignItems: 'flex-start' }}>
          <div className="col" style={{ gap: 4, minWidth: 0 }}>
            <div className="row wrap" style={{ gap: 8 }}>
              <h2 className="mono" style={{ fontSize: 16 }}>
                {img.repository}:{tag || '(태그 없음)'}
              </h2>
              {nUse ? <Badge tone="ok">쓰는 앱 {nUse}</Badge> : <Badge tone="un">쓰는 앱 없음</Badge>}
              <span className="kind">내장 · {reg.id}</span>
            </div>
            <span className="mono muted" style={{ fontSize: 12 }}>
              {img.digest.slice(0, 13)}…{img.digest.slice(-6)}{' '}
              <button type="button" className="linkish" style={{ fontFamily: 'Inter, sans-serif', fontSize: 12 }} onClick={copy}>
                복사
              </button>{' '}
              · {fmtBytes(img.bytes)}
              {total ? ` (압축 시 ${fmtBytes(total)})` : ''} · {agoMs(img.pushedAt)}
            </span>
          </div>
          <span className="row" style={{ gap: 8 }}>
            {plats.length > 1 && (
              <select aria-label="플랫폼" value={man.data?.picked || platform} onChange={(e) => (setPlatform(e.target.value), setSel(undefined))} style={{ width: 'auto', height: 30, fontSize: 12 }}>
                {plats.map((p) => (
                  <option key={p}>{p}</option>
                ))}
              </select>
            )}
            <button type="button" className="btn sm" aria-label="닫기" onClick={onClose}>
              ✕
            </button>
          </span>
        </header>
        <div className="tabs" role="tablist" style={{ padding: '0 12px' }}>
          {(
            [
              ['layers', `레이어 (${rows.length || '…'})`],
              ['config', '설정'],
              ['tags', `태그 (${img.tags.length})`],
              ['used', `쓰는 앱 (${nUse})`],
            ] as const
          ).map(([k, label]) => (
            <button type="button" key={k} role="tab" aria-selected={tab === k} className={tab === k ? 'active' : ''} onClick={() => setTab(k)}>
              {label}
            </button>
          ))}
        </div>
        <div className="dbody" style={{ gap: 12, padding: '14px 20px' }}>
          {man.error ? (
            <div className="note er small">
              이미지 정보를 읽지 못했습니다: {errText(man.error)}
              {man.error instanceof ApiError && man.error.status === 403 ? ' (이 저장소를 받을 권한이 없습니다)' : ''}
            </div>
          ) : !man.data ? (
            <span className="muted small">이미지 정보를 읽는 중…</span>
          ) : tab === 'layers' ? (
            <>
              {total > 0 && (
                <div className="lsize" title="레이어 크기 비율">
                  {rows
                    .filter((r) => r.bytes > 0)
                    .map((r) => (
                      <span key={r.n} style={{ flex: r.bytes, background: cur?.n === r.n ? 'var(--accent)' : 'var(--accent-line)' }} />
                    ))}
                </div>
              )}
              <div className="ltbl" role="listbox" aria-label="레이어">
                <div className="lrow th">
                  <span>#</span>
                  <span>만든 명령</span>
                  <span>크기</span>
                </div>
                {rows.map((r, i) => (
                  <div key={r.n} role="option" aria-selected={sel === i} className={`lrow ${sel === i ? 'sel' : ''}`} onClick={() => setSel(i)}>
                    <span className="muted mono">{r.n}</span>
                    <span className="mono ell" title={r.createdBy}>
                      {r.createdBy}
                    </span>
                    <span className="row" style={{ gap: 6 }}>
                      <span className="lmeter">
                        <i style={{ width: `${total ? Math.round((r.bytes / total) * 100) : 0}%`, background: r.bytes === 0 ? 'var(--input)' : sel === i ? 'var(--accent)' : 'var(--accent-line)' }} />
                      </span>
                      {r.digest ? fmtBytes(r.bytes) : '0 B · 설정만'}
                    </span>
                  </div>
                ))}
              </div>
              {cur && (
                <div className="col" style={{ gap: 6 }}>
                  <div className="row between">
                    <b style={{ fontSize: 13 }}>#{cur.n} 레이어에서 바뀐 파일</b>
                    {cur.digest && (
                      <span className="mono muted" style={{ fontSize: 11 }}>
                        {short(cur.digest)} · {fmtBytes(cur.bytes)}
                      </span>
                    )}
                  </div>
                  <div className="ltree">
                    {!cur.digest ? (
                      <span className="muted">이 단계는 이미지 설정만 바꿔 파일이 없습니다.</span>
                    ) : !files ? (
                      <span className="muted">파일 목록을 읽는 중… (처음 여는 레이어는 서버가 레이어를 받아 읽습니다)</span>
                    ) : 'error' in files ? (
                      <span style={{ color: 'var(--er)' }}>
                        파일 목록을 읽지 못했습니다: {errText(files.error)}
                        {/zstd/i.test(errText(files.error)) ? ' (zstd 레이어는 아직 볼 수 없습니다)' : ''}
                      </span>
                    ) : (
                      <FileTree f={files} />
                    )}
                  </div>
                  <span className="muted" style={{ fontSize: 12 }}>
                    파일 목록은 레이어를 처음 열 때 서버가 읽어 웹 캐시에 둡니다(파일 내용은 보여 주지 않음). + 추가·바뀜 · − 지움(whiteout). 레이어 목록만으로는 추가와 바뀜을 가를 수 없어 하나로 표시합니다.
                  </span>
                </div>
              )}
            </>
          ) : tab === 'config' ? (
            <dl className="kv2 c120" style={{ fontSize: 13 }}>
              <dt>플랫폼</dt>
              <dd className="mono">{[man.data.m.config?.os, man.data.m.config?.architecture].filter(Boolean).join('/') || man.data.picked || '—'}</dd>
              <dt>만든 시각</dt>
              <dd>{man.data.m.config?.created ? agoMs(Date.parse(man.data.m.config.created)) : '—'}</dd>
              <dt>실행 사용자</dt>
              <dd className="mono">{cfg?.User || 'root (정하지 않음)'}</dd>
              <dt>작업 폴더</dt>
              <dd className="mono">{cfg?.WorkingDir || '—'}</dd>
              <dt>시작 명령</dt>
              <dd className="mono">{[...(cfg?.Entrypoint ?? []), ...(cfg?.Cmd ?? [])].join(' ') || '—'}</dd>
              <dt>열린 포트</dt>
              <dd className="mono">{Object.keys(cfg?.ExposedPorts ?? {}).join(', ') || '—'}</dd>
              <dt>환경 변수</dt>
              <dd className="mono col" style={{ gap: 2 }}>
                {env.length
                  ? env.map((e) => {
                      const [k, ...v] = e.split('=');
                      return (
                        <span key={k} className="ell" title={SECRETISH.test(k) ? '이름이 비밀값 같아 값을 가렸습니다' : e}>
                          {k}={SECRETISH.test(k) ? '«가림»' : v.join('=')}
                        </span>
                      );
                    })
                  : '—'}
              </dd>
              <dt>라벨</dt>
              <dd className="mono col" style={{ gap: 2 }}>
                {Object.entries(cfg?.Labels ?? {}).map(([k, v]) => (
                  <span key={k} className="ell" title={`${k}=${v}`}>
                    {k}={v}
                  </span>
                ))}
                {!Object.keys(cfg?.Labels ?? {}).length && '—'}
              </dd>
              <dt>다이제스트</dt>
              <dd className="mono ell" title={man.data.m.digest}>
                {man.data.m.digest}
              </dd>
            </dl>
          ) : tab === 'tags' ? (
            img.tags.length ? (
              <div className="col" style={{ gap: 4 }}>
                {img.tags.map((t) => (
                  <span key={t} className="mono">
                    {img.repository}:{t}
                  </span>
                ))}
              </div>
            ) : (
              <span className="muted small">태그 없는 이미지입니다. 다이제스트로만 받을 수 있습니다.</span>
            )
          ) : usedParts.length ? (
            <div className="col" style={{ gap: 4 }}>
              {usedParts.map((p) => (
                <span key={p}>{p}</span>
              ))}
            </div>
          ) : (
            <span className="muted small">{nUse ? `${nUse}곳에서 씁니다.` : '이 이미지를 쓰는 앱이 없습니다.'}</span>
          )}
        </div>
        <footer style={{ justifyContent: 'space-between', background: 'var(--surface-2)' }}>
          <span className="muted" style={{ fontSize: 12 }}>
            ↑↓ 레이어 이동 · Enter 파일 보기 · Esc 닫기
          </span>
          <span className="row" style={{ gap: 8 }}>
            <button type="button" className="btn" onClick={copy}>
              다이제스트 복사
            </button>
            <button type="button" className="btn" onClick={deploy}>
              이 이미지로 배포…
            </button>
            <button type="button" className="btn primary" onClick={onClose}>
              닫기
            </button>
          </span>
        </footer>
      </div>
    </div>
  );
}

function FileTree({ f }: { f: DLayerFiles }) {
  const { lines, more } = useMemo(() => fileLines(f.files), [f]);
  if (!f.files.length) return <span className="muted">바뀐 파일이 없습니다.</span>;
  const w = Math.min(48, Math.max(...lines.map((l) => l.name.length))) + 4;
  return (
    <>
      {lines.map((l, i) => (
        <div key={i}>
          <span style={{ color: l.sign === '−' ? 'var(--er)' : 'var(--ok)' }}>{l.sign}</span> {l.name.padEnd(w)} {l.note}
        </div>
      ))}
      {more > 0 && (
        <div>
          <span style={{ color: 'var(--ok)' }}>+</span> … {more.toLocaleString('ko-KR')}개 파일
        </div>
      )}
      {f.truncated && <div className="muted">파일이 너무 많아 앞 5만 개만 읽었습니다.</div>}
    </>
  );
}

// ── 이미지 업로드 (UI-88) ─────────────────────────────────
const PUSH_STATE: Record<string, string> = { preparing: '준비 중', pushing: '올리는 중', done: '올림', failed: '실패', canceled: '멈춤' };
const ACCEPT = /\.(tar|tar\.gz|tgz)$/i;
const MAX = 10 * 2 ** 30;
type Item = NonNullable<NonNullable<DImageUpload['inspect']>['items']>[number];
interface Target {
  repository: string;
  tag: string;
}
interface Pushed {
  state: 'waiting' | 'pushing' | 'done' | 'failed' | 'skipped' | 'canceled';
  pct?: number;
  digest?: string;
  skipped?: number;
  layers?: number;
  error?: string;
}

/** 파일 안 이름 'acme/billing-api:1.8.3' → 'shop/billing-api', '1.8.3' */
function suggest(tenant: string, it: Item): Target {
  const ref = it.refs?.[0];
  if (!ref) return { repository: '', tag: '' };
  const at = ref.lastIndexOf(':');
  const slash = ref.lastIndexOf('/');
  const name = at > slash ? ref.slice(0, at) : ref;
  const tag = at > slash ? ref.slice(at + 1) : 'latest';
  return { repository: `${tenant}/${name.split('/').pop()!.toLowerCase()}`, tag };
}

export function ImageUploadPage() {
  const { tenant, canDeploy } = useTenantRole();
  const navigate = useNavigate();
  const toast = useToast();
  const regs = usePoll((s) => registries(tenant, s), [tenant], 0, registriesLive(tenant));
  const usable = (regs.data?.items ?? []).filter((r) => !r.deleted && r.enabled);
  const [regId, setRegId] = useState('');
  const reg = usable.find((r) => r.id === regId) ?? usable[0];
  useEffect(() => {
    if (!regId && usable[0]) setRegId(usable[0].id);
  }, [regId, usable]);

  const [file, setFile] = useState<File>();
  const [fileErr, setFileErr] = useState('');
  const [up, setUp] = useState<DImageUpload>();
  const [phase, setPhase] = useState<'idle' | 'sending' | 'inspecting' | 'ready' | 'pushing' | 'finished'>('idle');
  const [error, setError] = useState<unknown>();
  const [targets, setTargets] = useState<Record<number, Target>>({});
  const [overwrite, setOverwrite] = useState(true);
  const [pushed, setPushed] = useState<Record<number, Pushed>>({});
  /** 이어 올릴 업로드(같은 파일을 다시 고르면 빠진 조각만 보낸다) */
  const [resume, setResume] = useState<DImageUpload>();
  const alive = useRef(true);
  const stop = useRef(false);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      stop.current = true;
    };
  }, []);

  const pending = usePoll((s) => (reg ? imageUploads(tenant, reg.id, s) : Promise.resolve([] as DImageUpload[])), [tenant, reg?.id], 0);
  const existing = usePoll((s) => (reg ? registryImagesAll(tenant, reg.id, {}, s) : Promise.resolve(undefined)), [tenant, reg?.id], 0);
  const imgs = existing.data?.items ?? [];
  const tagAt = (t: Target) => imgs.find((i) => i.repository === t.repository && i.tags.includes(t.tag));

  const items = up?.inspect?.state === 'done' ? (up.inspect.items ?? []) : [];
  useEffect(() => {
    if (!items.length) return;
    setTargets((cur) => Object.fromEntries(items.map((it) => [it.index, cur[it.index] ?? suggest(tenant, it)])));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [up?.id, items.length, tenant]);

  // 덮어쓸 태그가 가리키는 이미지를 쓰는 앱(미리 알린다)
  const overDigests = items.map((it) => tagAt(targets[it.index] ?? { repository: '', tag: '' })).filter((x): x is RegistryImage => !!x && x.digest !== undefined);
  const overKey = [...new Set(overDigests.map((x) => x.digest))].sort().join(',');
  const overUse = usePoll(() => (overKey ? imageUsage(tenant, overKey.split(',')) : Promise.resolve([] as ImageUse[])), [tenant, overKey], 0);

  const check = (it: Item): { tone: 'ok' | 'wa' | 'un' | 'er'; text: string; send: boolean; overwrite?: boolean } => {
    const t = targets[it.index] ?? { repository: '', tag: '' };
    if (!t.repository || !REPO_RE.test(t.repository)) return { tone: 'er', text: t.repository ? '이름 확인' : '이름을 정하세요', send: false };
    if (tagProblem(t.tag)) return { tone: 'er', text: t.tag ? '태그 확인' : '태그를 정하세요', send: false };
    const dup = items.some((o) => o.index < it.index && targets[o.index]?.repository === t.repository && targets[o.index]?.tag === t.tag);
    if (dup) return { tone: 'er', text: '위 줄과 같은 이름', send: false };
    const at = tagAt(t);
    if (!at) return { tone: 'ok', text: '새 태그', send: true };
    if (it.digest && at.digest === it.digest) return { tone: 'un', text: '같은 이미지 · 그대로', send: true };
    return overwrite ? { tone: 'wa', text: '태그 있음 · 덮어씀', send: true, overwrite: true } : { tone: 'un', text: '태그 있음 · 건너뜀', send: false };
  };
  const toSend = items.filter((it) => check(it).send);
  const blocking = items.some((it) => check(it).tone === 'er');

  // ── 1. 조각 보내기 ──
  const sendChunks = async (u: DImageUpload, f: File) => {
    setPhase('sending');
    setError(undefined);
    stop.current = false;
    let cur = u;
    const queue = async (missing: number[]) => {
      let next = 0;
      const worker = async () => {
        while (next < missing.length && !stop.current) {
          const n = missing[next++];
          const blob = f.slice(n * cur.chunkBytes, Math.min(f.size, (n + 1) * cur.chunkBytes));
          for (let k = 0; ; k++) {
            try {
              const r = await putUploadChunk(tenant, u.registry, u.id, n, blob);
              if (alive.current) setUp((x) => (x ? { ...x, received: r.received, missing: r.missing } : x));
              break;
            } catch (e) {
              // 4xx(길이·범위·없는 업로드)는 다시 보내도 같다
              if (k >= 2 || (e instanceof ApiError && e.status >= 400 && e.status < 500)) throw e;
              await sleep(800 * (k + 1));
            }
          }
        }
      };
      await Promise.all([worker(), worker(), worker()]);
    };
    try {
      // missing은 앞 200개만 오므로 다 받을 때까지 다시 묻는다
      for (let round = 0; round < 1000 && !stop.current; round++) {
        cur = await imageUpload(tenant, u.registry, u.id);
        if (!alive.current) return;
        setUp(cur);
        if (cur.received >= cur.chunks) break;
        await queue(cur.missing);
      }
      if (stop.current) return;
      await inspect(cur);
    } catch (e) {
      if (alive.current) (setError(e), setPhase('idle'));
    }
  };
  // ── 2. 안에 든 이미지 읽기 ──
  const inspect = async (u: DImageUpload) => {
    setPhase('inspecting');
    let cur = u;
    if (cur.inspect?.state !== 'done') {
      if (cur.inspect?.state !== 'running') cur = (await inspectUpload(tenant, u.registry, u.id)) as DImageUpload;
      for (let i = 0; alive.current && !stop.current && i < 600; i++) {
        cur = await imageUpload(tenant, u.registry, u.id);
        setUp(cur);
        if (cur.inspect?.state === 'done' || cur.inspect?.state === 'failed') break;
        await sleep(1000);
      }
    }
    if (!alive.current) return;
    setUp(cur);
    setPhase(cur.inspect?.state === 'done' ? 'ready' : 'idle');
  };

  const pick = async (f: File | undefined) => {
    setFileErr('');
    setError(undefined);
    if (!f || !reg) return;
    if (!ACCEPT.test(f.name)) return setFileErr(`${f.name}: .tar · .tar.gz · .tgz 파일만 받습니다${/\.zst$/i.test(f.name) ? ' (.tar.zst는 아직 받지 못합니다)' : ''}.`);
    if (f.size > MAX) return setFileErr(`${f.name}은 ${fmtBytes(f.size)}입니다. 10 GiB까지 올릴 수 있습니다.`);
    if (resume && (resume.fileName !== f.name || resume.bytes !== f.size)) return setFileErr(`이어 올리려면 처음 고른 파일(${resume.fileName} · ${fmtBytes(resume.bytes)})을 다시 골라 주세요.`);
    setFile(f);
    setPushed({});
    try {
      const same = resume ?? (pending.data ?? []).find((u) => u.fileName === f.name && u.bytes === f.size && !u.push);
      const u = same ?? (await startImageUpload(tenant, reg.id, f.name, f.size));
      setResume(undefined);
      setUp(u);
      void sendChunks(u, f);
    } catch (e) {
      setError(e);
    }
  };
  /** 조각이 다 온 업로드는 파일 없이 이어 간다 */
  const reopen = (u: DImageUpload) => {
    setError(undefined);
    setPushed({});
    if (u.received < u.chunks) return setResume(u);
    setFile(undefined);
    setUp(u);
    void inspect(u).catch((e) => (setError(e), setPhase('idle')));
  };
  const remove = async (u: DImageUpload) => {
    try {
      await deleteUpload(tenant, u.registry, u.id);
      pending.refresh();
    } catch (e) {
      setError(e);
    }
  };

  // ── 3. 저장소에 올리기(하나씩) ──
  const pushAll = async () => {
    if (!up) return;
    setPhase('pushing');
    setError(undefined);
    stop.current = false;
    const plan = items.map((it) => ({ it, c: check(it), t: targets[it.index] }));
    const res: Record<number, Pushed> = Object.fromEntries(plan.map(({ it, c }) => [it.index, { state: c.send ? 'waiting' : 'skipped' } as Pushed]));
    setPushed({ ...res });
    for (const { it, c, t } of plan) {
      if (!c.send || stop.current || !alive.current) continue;
      const set = (p: Pushed) => {
        res[it.index] = p;
        if (alive.current) setPushed({ ...res });
      };
      set({ state: 'pushing', pct: 0 });
      try {
        let u = await pushUpload(tenant, up.registry, up.id, { item: it.index, repository: t.repository, tag: t.tag, ...(c.overwrite ? { overwrite: true } : {}) });
        for (let i = 0; i < 3600 && alive.current && !stop.current; i++) {
          await sleep(1000);
          u = await imageUpload(tenant, up.registry, up.id);
          const p = u.push;
          if (!p) break;
          const ls = p.layers ?? [];
          const big = ls.filter((l) => l.state !== 'skipped');
          const pct = big.length ? Math.floor((big.reduce((a, l) => a + l.done, 0) / Math.max(1, big.reduce((a, l) => a + l.bytes, 0))) * 100) : p.state === 'done' ? 100 : 0;
          const skipped = ls.filter((l) => l.state === 'skipped').length;
          if (p.state === 'done') {
            set({ state: 'done', digest: p.digest, skipped, layers: ls.length });
            break;
          }
          if (p.state === 'failed' || p.state === 'canceled') {
            set({ state: p.state, error: p.error });
            break;
          }
          set({ state: 'pushing', pct, skipped, layers: ls.length });
        }
      } catch (e) {
        // 목록 캐시가 낡아 몰랐던 태그: 덮어쓰기를 껐으면 건너뛴다
        if (e instanceof ApiError && e.code === 'tag-exists') set({ state: 'skipped', error: '저장소에 그 태그가 이미 있어 건너뜀' });
        else set({ state: 'failed', error: errText(e) });
      }
    }
    if (!alive.current) return;
    setPhase('finished');
    existing.refresh();
    const bad = Object.values(res).some((p) => p.state === 'failed' || p.state === 'canceled');
    const n = Object.values(res).filter((p) => p.state === 'done').length;
    if (n) toast(`이미지 ${n}개를 올렸습니다. 이미지 목록을 갱신합니다.`);
    // 다 됐으면 올린 파일을 지운다. 실패한 줄이 있으면 다시 올릴 수 있게 남긴다(하루 뒤 서버가 지움)
    if (!bad) void deleteUpload(tenant, up.registry, up.id).then(() => pending.refresh(), () => undefined);
  };
  const cancel = async () => {
    stop.current = true;
    if (up && phase !== 'finished') await deleteUpload(tenant, up.registry, up.id).catch(() => undefined);
    navigate('/images');
  };

  const pct = up ? Math.floor((up.received / Math.max(1, up.chunks)) * 100) : 0;
  const status =
    !up
      ? ''
      : up.inspect?.state === 'failed'
        ? '다 올림 · 읽지 못함'
        : up.received < up.chunks
          ? phase === 'sending'
            ? `올리는 중 ${pct}%`
            : `멈춤 · ${pct}%`
          : up.inspect?.state === 'done'
            ? '다 올림 · 읽기 완료'
            : '다 올림 · 읽는 중…';
  const others = (pending.data ?? []).filter((u) => u.id !== up?.id);
  const busy = phase === 'sending' || phase === 'inspecting' || phase === 'pushing';
  const pushedList = items.filter((it) => pushed[it.index]);

  return (
    <>
      <div className="row wrap" style={{ gap: 12 }}>
        <Link to="/images" style={{ fontSize: 13 }}>
          ← 이미지 목록
        </Link>
        <h2>이미지 업로드</h2>
      </div>
      <HelpBox terms="이미지 파일 (image archive) · OCI 묶음 (OCI image layout) · 레이어 (layer) · 저장소에 올림 (push)">
        <b>이 화면은</b> 다른 곳에서 만든 이미지 파일을 이 작업 공간의 내장 저장소에 올립니다. <span className="mono">docker save</span>로 만든 파일이나 OCI 이미지 묶음을 올리면, 안에 든 이미지를 읽어
        이름·태그를 정한 뒤 저장소에 올립니다. 인터넷이 막힌 곳에 이미지를 옮길 때 씁니다.
      </HelpBox>
      {!canDeploy && <div className="note un small">이미지 업로드는 이 작업 공간의 관리자만 할 수 있습니다(올린 파일이 웹 서버 디스크를 씁니다).</div>}
      <div className="main-side">
        <Card>
          <h2>1. 파일 올리기</h2>
          <div
            className="dropzone"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              if (!busy && canDeploy) void pick(e.dataTransfer.files[0]);
            }}
          >
            <b>{resume ? `이어 올릴 파일 ${resume.fileName}을 다시 고르세요` : '이미지 파일을 끌어 놓거나 고르세요'}</b>
            <span className="muted" style={{ fontSize: 12 }}>
              받는 형식: <span className="mono">.tar</span> (docker save) · <span className="mono">.tar.gz</span> · <span className="mono">.tgz</span> · OCI 이미지 묶음(<span className="mono">oci-layout</span>이 든
              .tar/.tar.gz) · 최대 10 GiB
            </span>
            <label className={`btn sm ${busy || !canDeploy || !reg ? 'disabled' : ''}`} aria-disabled={busy || !canDeploy || !reg}>
              파일 고르기
              <input type="file" accept=".tar,.gz,.tgz,application/x-tar,application/gzip" hidden disabled={busy || !canDeploy || !reg} onChange={(e) => (void pick(e.target.files?.[0]), (e.target.value = ''))} />
            </label>
          </div>
          {fileErr && <div className="note er small">{fileErr}</div>}
          {up && (
            <div className="col" style={{ gap: 6, fontSize: 13 }}>
              <div className="row between">
                <span className="mono">
                  {up.fileName} · {fmtBytes(up.bytes)}
                </span>
                <span className="muted">{status}</span>
              </div>
              <div className={`upbar ${up.received >= up.chunks ? 'full' : ''}`}>
                <i style={{ width: `${pct}%` }} />
              </div>
              {up.inspect?.state === 'failed' && <div className="note er small">파일 안의 이미지를 읽지 못했습니다: {up.inspect.error}</div>}
              {phase === 'idle' && up.received < up.chunks && file && (
                <button type="button" className="btn sm" style={{ width: 'fit-content' }} onClick={() => void sendChunks(up, file)}>
                  이어 올리기
                </button>
              )}
            </div>
          )}
          <span className="muted" style={{ fontSize: 12 }}>
            조각으로 나눠 올려 끊겨도 이어 올립니다(새로고침 뒤에도).
          </span>
          {others.length > 0 && !busy && (
            <div className="col" style={{ gap: 4, marginTop: 4 }}>
              <b style={{ fontSize: 12 }}>끝나지 않은 업로드 ({others.length})</b>
              {others.map((u) => {
                const whole = u.received >= u.chunks;
                const got = Math.min(u.bytes, u.received * u.chunkBytes);
                return (
                  <div key={u.id} className="pending-up">
                    <span className="ell">
                      <span className="mono">{u.fileName}</span> · {whole ? fmtBytes(u.bytes) : `${fmtBytes(got)} / ${fmtBytes(u.bytes)}`} · {when(u.createdAt)}
                      {u.inspect?.state === 'failed' ? ' · 읽지 못함' : u.push ? ` · ${u.push.repository}:${u.push.tag} ${PUSH_STATE[u.push.state] ?? u.push.state}` : ''}
                    </span>
                    <span className="row" style={{ gap: 6 }}>
                      <button type="button" className="btn xs" disabled={whole} onClick={() => reopen(u)}>
                        이어 올리기
                      </button>
                      <button type="button" className="btn xs" disabled={!whole || u.inspect?.state === 'failed'} onClick={() => reopen(u)}>
                        이어서 하기
                      </button>
                      <button type="button" className="btn xs danger" onClick={() => void remove(u)}>
                        지우기
                      </button>
                    </span>
                  </div>
                );
              })}
              <span className="muted" style={{ fontSize: 11 }}>
                이 작업 공간에서 웹으로 올리다 멈춘 것입니다. 같은 파일을 다시 고르면 이어 올리고, 다 올린 것은 2번부터 이어서 합니다.
              </span>
            </div>
          )}

          <h2 style={{ marginTop: 4 }}>2. 안에 든 이미지{items.length ? ` (${items.length})` : ''} · 올릴 이름 정하기</h2>
          <div className="row wrap" style={{ gap: 10, fontSize: 13 }}>
            <span>올릴 저장소</span>
            <select value={reg?.id ?? ''} onChange={(e) => setRegId(e.target.value)} disabled={!!up || !usable.length} style={{ width: 'auto', height: 30 }} title={up ? '올린 파일이 이 저장소에 묶여 있습니다' : undefined}>
              {usable.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.id} ({r.endpoint})
                </option>
              ))}
            </select>
            <span className="muted" style={{ fontSize: 12 }}>
              {regs.data && !usable.length ? '켜진 내장 저장소가 없습니다' : '관리 권한이 있는 내장 저장소만'}
            </span>
          </div>
          {items.length > 0 ? (
            <>
              <div className="ltbl up">
                <div className="lrow th">
                  <span>파일 안 이름</span>
                  <span>플랫폼</span>
                  <span>크기</span>
                  <span>올릴 이미지 이름 · 태그</span>
                  <span>확인</span>
                </div>
                {items.map((it) => {
                  const t = targets[it.index] ?? { repository: '', tag: '' };
                  const c = check(it);
                  const set = (p: Partial<Target>) => setTargets((x) => ({ ...x, [it.index]: { ...t, ...p } }));
                  const locked = phase === 'pushing' || phase === 'finished';
                  return (
                    <div key={it.index} className="lrow">
                      <span className="mono ell" title={(it.refs ?? []).join(', ') || it.digest}>
                        {it.refs?.length ? it.refs.join(', ') : `(이름 없음) ${it.digest ? it.digest.slice(0, 11) + '…' : ''}`}
                      </span>
                      <span className="mono muted ell" title={(it.platforms ?? []).join(', ')}>
                        {(it.platforms ?? []).join(', ') || '—'}
                        {it.kind === 'index' ? ' (묶음)' : ''}
                      </span>
                      <span>{fmtBytes(it.bytes)}</span>
                      <span className="uprow">
                        <input className="mono" aria-label="올릴 이미지 이름" value={t.repository} placeholder={`${tenant}/이름`} disabled={locked} onChange={(e) => set({ repository: e.target.value.trim() })} />
                        <input className={`mono ${c.tone === 'wa' ? 'warn' : ''}`} aria-label="태그" value={t.tag} placeholder="태그" disabled={locked} onChange={(e) => set({ tag: e.target.value.trim() })} />
                      </span>
                      <span>
                        <Badge tone={c.tone}>{c.text}</Badge>
                      </span>
                    </div>
                  );
                })}
              </div>
              <label className="row" style={{ gap: 8, fontSize: 13 }}>
                <input type="checkbox" checked={overwrite} disabled={phase === 'pushing'} onChange={(e) => setOverwrite(e.target.checked)} />
                이미 있는 태그를 덮어쓰기 허용 (끄면 그 줄은 건너뜀)
              </label>
              {overwrite && (overUse.data ?? []).some((u) => usesOf(u) > 0) && (
                <div className="note wa small">
                  덮어쓸 태그의 지금 이미지를 쓰는 곳: {(overUse.data ?? []).filter((u) => usesOf(u) > 0).map((u) => usedText(u).text).join(' / ')}. 앱은 다이제스트로 고정돼 있어 바로 바뀌지 않습니다.
                </div>
              )}
            </>
          ) : (
            <span className="muted small">{phase === 'inspecting' ? '파일 안의 이미지를 읽는 중…' : '파일을 다 올리면 안에 든 이미지를 읽어 여기에 보여 줍니다.'}</span>
          )}
          <span className="muted" style={{ fontSize: 12, lineHeight: '18px' }}>
            파일 안 이름의 저장소 주소(acme/)는 버리고, 기본으로 <span className="mono">{tenant}/이름:태그</span>를 제안합니다. 태그가 없는 이미지는 직접 정해야 합니다. 덮어쓰면 옛 태그가 가리키던
            다이제스트는 태그 없는 이미지로 남고, 그 태그를 쓰는 앱이 있으면 미리 알려 줍니다(앱은 다이제스트로 고정돼 있어 바로 바뀌지 않음).
          </span>
          <MutationError error={error} />
          <div className="row" style={{ gap: 8, justifyContent: 'flex-end' }}>
            {phase === 'finished' ? (
              <button type="button" className="btn primary" onClick={() => navigate('/images')}>
                이미지 목록으로
              </button>
            ) : (
              <>
                <button type="button" className="btn" onClick={() => void cancel()}>
                  취소
                </button>
                <button type="button" className="btn primary" disabled={phase !== 'ready' || !toSend.length || blocking || !canDeploy} onClick={() => void pushAll()}>
                  {phase === 'pushing' ? '올리는 중…' : `${toSend.length}개 저장소에 올리기`}
                </button>
              </>
            )}
          </div>
        </Card>
        <Card>
          <h2>3. 올리는 중</h2>
          <div className="col" style={{ gap: 10, fontSize: 12 }}>
            {pushedList.length === 0 && <span className="muted">이름을 정하고 올리기를 누르면 이미지마다 진행을 보여 줍니다.</span>}
            {pushedList.map((it) => {
              const p = pushed[it.index];
              const t = targets[it.index];
              const name = `${t?.repository}:${t?.tag}`;
              return (
                <div key={it.index}>
                  <div className="row between">
                    <span className="mono">{name}</span>
                    <PushBadge p={p} />
                  </div>
                  {p.state === 'pushing' && (
                    <div className="upbar thin">
                      <i style={{ width: `${p.pct ?? 0}%` }} />
                    </div>
                  )}
                  {p.state === 'done' && (
                    <span className="muted">
                      레이어 {p.layers}개 중 {p.skipped}개는 이미 있어 건너뜀{p.digest ? ` · ${short(p.digest)}` : ''} ·{' '}
                      <Link to="/standalone/new" state={{ yaml: standaloneToYaml({ ...emptyStandalone(), image: `${reg?.endpoint}/${t?.repository}@${p.digest}` }) }}>
                        이 이미지로 배포
                      </Link>
                    </span>
                  )}
                  {p.error && <span className={p.state === 'skipped' ? 'muted' : ''} style={p.state === 'skipped' ? undefined : { color: 'var(--er)' }}>{p.error}</span>}
                </div>
              );
            })}
          </div>
          <dl className="kv2 c80" style={{ borderTop: '1px solid var(--line-2)', paddingTop: 10, fontSize: 12 }}>
            <dt>검사</dt>
            <dd>manifest·레이어 다이제스트 일치 확인, 플랫폼 표시, 크기 상한</dd>
            <dt>신뢰</dt>
            <dd>
              내장 저장소 이미지라 신뢰 출처 <span className="mono">{reg?.endpoint ?? '내장 저장소'}/**</span>로 바로 배포 가능
            </dd>
            <dt>기록</dt>
            <dd>저장소 쓰기라 작업 기록(op)에는 남지 않습니다</dd>
          </dl>
          <span className="muted" style={{ fontSize: 12, lineHeight: '18px' }}>
            다 올리면 이미지 목록 캐시를 바로 갱신하고 '이 이미지로 배포' 링크를 줍니다. 올린 파일은 모두 성공하면 바로 지웁니다. 실패한 줄이 있으면 다시 올릴 수 있게 하루 동안 남깁니다.
          </span>
        </Card>
      </div>
    </>
  );
}

function PushBadge({ p }: { p: Pushed }): ReactNode {
  switch (p.state) {
    case 'done':
      return <Badge tone="ok">올림</Badge>;
    case 'pushing':
      return <Badge tone="pr">{p.pct ?? 0}%</Badge>;
    case 'waiting':
      return <Badge tone="un">대기</Badge>;
    case 'skipped':
      return <Badge tone="un">건너뜀</Badge>;
    case 'canceled':
      return <Badge tone="wa">멈춤</Badge>;
    default:
      return <Badge tone="er">실패</Badge>;
  }
}
