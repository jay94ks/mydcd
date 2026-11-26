// SPDX-License-Identifier: Apache-2.0

// 이미지 관리 › 이미지 목록 탭 (UI-84 · 정리 UI-8A, 캔버스 Images · ImagesIx · ImagePrune).
// 계약: docs/reference/web-api.md '저장소 이미지와 정리'(mydcd 실제 계약 #242). 목록·쓰는 곳 판단·권한·삭제는 mydcd 몫이고,
// 웹은 목록 쪽을 잠깐 기억하고(데몬 메모리) 내린 앱(웹 bbolt)이 쓰는 이미지를 더해 알린다.
// 삭제·GC·정리 op의 applied는 수락일 뿐이고, 실제 진행은 registry-maintenance/web-<opId>로 본다.
// 태그 추가·레이어 보기(UI-89)·업로드(UI-88)는 ImageTools(웹 데몬이 내장 저장소 API를 직접 씀).
import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ApiError, api, newOpId } from '../api/client';
import {
  externalRegistries,
  imageUsage,
  maintenanceStatus,
  prunePreview,
  pruneResults,
  registries,
  registryImagesAll,
  registryPath,
  toOp,
  type ImageUse,
  type PrunePage,
  type RegistryImage,
  type RegistryImagePage,
} from '../api/endpoints';
import type { DMaintenanceStatus, DOp, DPruneConditions } from '../api/dto';
import type { OpView, RegistryView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { Badge, Card, Field, HelpBox, KV } from '../components/ui';
import { Empty, Load } from '../components/states';
import { Dialog } from '../components/Dialog';
import { Menu, type MenuItem } from '../components/Menu';
import { MutationError, OpPanel, useMutation } from '../components/OpPanel';
import { useToast } from '../components/Toast';
import { OpBadge } from '../components/ui';
import { fmtBytes } from '../lib/format';
import { usedText, usesOf } from '../lib/imageUse';
import { eulReul, iGa } from '../lib/josa';
import { emptyStandalone, standaloneToYaml } from '../lib/standalone';
import { usePoll, type Loaded } from '../lib/usePoll';
import { LayersDialog, TagDialog } from './ImageTools';
import { MCards, MTiles } from '../mobile/ReadOnly';

export { usedText, usesOf };
const NEED = '이 작업 공간의 관리 권한이 필요합니다';

// ── 목록 캐시: 머리글 버튼과 표가 같이 쓴다 ─────────────────
interface Group {
  /** 외부 저장소는 주소를 endpoint로 한 RegistryView 모양 */
  reg: RegistryView;
  external: boolean;
  page?: RegistryImagePage;
  error?: unknown;
}
interface Catalog {
  q: Loaded<Group[]>;
  /** 읽는 서버가 없어 목록을 못 읽는 외부 저장소(필터에 흐리게) */
  unread: string[];
  /** 다시 읽는다. refresh면 데몬 캐시를 건너뛰고(목록 새로 받기·이 웹의 변경 뒤) announce면 바뀐 수를 알린다 */
  reload: (refresh: boolean, announce?: boolean) => void;
  refreshing: boolean;
}
const Ctx = createContext<Catalog | undefined>(undefined);
const useCatalog = () => useContext(Ctx)!;
/** 탭 이름에 붙일 이미지 수(태그마다 한 줄). 받기 전에는 undefined */
export function useImageCount(): number | undefined {
  const g = useContext(Ctx)?.q.data;
  return g && g.length ? g.reduce((a, x) => a + (x.page?.items ?? []).reduce((b, i) => b + Math.max(1, i.tags.length), 0), 0) : undefined;
}
type Mut = ReturnType<typeof useMutation>;
/** 결과를 모르는 작업(보내기 오류·unknown·pending·running)은 새 작업 ID로 다시 내지 않는다 */
const uncertain = (m: Mut) => m.error !== undefined || (!!m.op && ['unknown', 'pending', 'running'].includes(m.op.state));
const ended = (m: Mut) => !!m.op && (m.op.state === 'failed' || m.op.state === 'rejected');
const extView = (id: string, authority: string): RegistryView => ({ id, name: id, endpoint: authority, repositories: 0, active: true, revision: 0, enabled: true });

export function ImageCatalog({ children }: { children: ReactNode }) {
  const { tenant } = useTenantRole();
  const on = useLocation().pathname.replace(/\/$/, '') === '/images';
  const refreshNext = useRef(false);
  const before = useRef<Group[]>();
  const [refreshing, setRefreshing] = useState(false);
  const [unread, setUnread] = useState<string[]>([]);
  const toast = useToast();
  const q = usePoll(
    async (s) => {
      if (!tenant || !on) return [];
      const refresh = refreshNext.current;
      refreshNext.current = false;
      const [regs, exts] = await Promise.all([registries(tenant, s), externalRegistries(tenant, s).catch(() => ({ items: [] }))]);
      // 외부 저장소는 읽는 서버가 연결된 켜진 정의만 목록을 읽을 수 있다
      setUnread(exts.items.filter((r) => !r.deleted && (!r.enabled || !r.reader || r.reader.draining)).map((r) => r.authority));
      const list: Omit<Group, 'page' | 'error'>[] = [
        ...regs.items.filter((r) => !r.deleted).map((reg) => ({ reg, external: false })),
        ...exts.items.filter((r) => !r.deleted && r.enabled && r.reader && !r.reader.draining).map((r) => ({ reg: extView(r.id, r.authority), external: true })),
      ];
      return Promise.all(
        list.map((g) =>
          registryImagesAll(tenant, g.reg.id, { external: g.external, refresh }, s).then(
            (page): Group => ({ ...g, page }),
            (error): Group => ({ ...g, error }),
          ),
        ),
      );
    },
    [tenant, on],
    10 * 60_000,
  );
  // 새로 받기를 누른 뒤 읽기가 한 번 시작하고 끝나면 알린다
  const sawLoading = useRef(false);
  useEffect(() => {
    if (!refreshing) return;
    if (q.loading) {
      sawLoading.current = true;
      return;
    }
    if (!sawLoading.current || !q.data) return;
    sawLoading.current = false;
    setRefreshing(false);
    const keys = (g: Group[] | undefined) => new Set((g ?? []).flatMap((x) => (x.page?.items ?? []).map((i) => `${x.reg.id}/${i.repository}@${i.digest}`)));
    const a = keys(before.current);
    const b = keys(q.data);
    const added = [...b].filter((k) => !a.has(k)).length;
    const gone = [...a].filter((k) => !b.has(k)).length;
    const failed = q.data.filter((g) => g.error || g.page?.code).length;
    toast(failed ? `저장소 ${failed}곳을 다시 읽지 못했습니다. 나머지는 갱신했습니다.` : `목록을 갱신했습니다. 새 이미지 ${added}개 · 사라진 이미지 ${gone}개.`);
  }, [refreshing, q.loading, q.data, toast]);
  const reload = (refresh: boolean, announce = refresh) => {
    refreshNext.current = refresh;
    if (announce) {
      before.current = q.data;
      setRefreshing(true);
    }
    q.refresh();
  };
  return <Ctx.Provider value={{ q, unread, reload, refreshing }}>{children}</Ctx.Provider>;
}

/**
 * 삭제·GC·정리 작업의 실제 진행(registry-maintenance/web-<opId>). op applied 뒤에만 읽고, done/failed면 멈춘다.
 * unknown(외부 DELETE 응답을 잃음)은 끝나지 않으므로 그대로 보여 준다.
 */
function useMaintenance(tenant: string, op: OpView | undefined, onEnd?: (s: DMaintenanceStatus) => void) {
  const [st, setSt] = useState<DMaintenanceStatus>();
  const [err, setErr] = useState<unknown>();
  const end = useRef(onEnd);
  end.current = onEnd;
  const id = op?.state === 'applied' ? op.id : undefined;
  useEffect(() => {
    if (!id) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async (n: number) => {
      try {
        const s = await maintenanceStatus(tenant, id);
        if (!live) return;
        setSt(s);
        setErr(undefined);
        if (s.state === 'done' || s.state === 'failed') return end.current?.(s);
      } catch (e) {
        if (!live) return;
        setErr(e);
      }
      timer = setTimeout(() => void tick(n + 1), Math.min(10_000, 1500 + n * 500));
    };
    void tick(0);
    return () => ((live = false), clearTimeout(timer));
  }, [tenant, id]);
  return { status: st, error: err };
}
const MSTATE: Record<string, ['ok' | 'er' | 'wa' | 'un' | 'pr', string]> = {
  queued: ['pr', '차례 기다림'],
  running: ['pr', '진행 중'],
  done: ['ok', '끝남'],
  failed: ['er', '실패'],
  unknown: ['wa', '결과 모름'],
};
const RESULT: Record<string, string> = {
  ok: '완료',
  'already-absent': '이미 없음',
  'image-in-use': '쓰는 중이라 건너뜀',
  'reference-changed': '그 사이 태그가 다른 이미지로 옮겨 가 지우지 않음',
  denied: '저장소가 거절함',
  'uploads-in-progress': '올리는 중인 이미지가 있어 미룸',
  'registry-budget': '저장소 한도에 걸림',
  partial: '일부만 처리됨',
  'preview-unavailable': '미리 보기를 다시 쓸 수 없음',
  unsupported: '이 저장소는 지원하지 않음(외부 저장소는 태그만 지우기 안 됨)',
};
const resultText = (code?: string) => (code ? (RESULT[code] ?? code) : '');
function MaintBadge({ s }: { s?: DMaintenanceStatus }) {
  if (!s) return <Badge tone="pr">진행 확인 중…</Badge>;
  const [tone, label] = MSTATE[s.state] ?? MSTATE.unknown;
  const code = s.result?.code;
  if (s.state === 'done' && code && code !== 'ok') return <Badge tone={code === 'already-absent' ? 'un' : 'wa'}>{resultText(code)}</Badge>;
  return <Badge tone={tone}>{label}</Badge>;
}

// ── 머리글 버튼 (정리 ▾ · 목록 새로 받기 · 빌드 · 이미지 업로드) ──
export function ImageListActions() {
  const { tenant, canDeploy } = useTenantRole();
  const { q, reload, refreshing } = useCatalog();
  const [dlg, setDlg] = useState<'' | 'gc' | 'prune'>('');
  const manageable = (q.data ?? []).filter((g) => g.reg.enabled && g.page && !g.page.code);
  const builtin = manageable.filter((g) => !g.external);
  const noReg = manageable.length ? undefined : '목록을 읽은 켜진 저장소가 없습니다';
  const items: MenuItem[] = [
    {
      label: '🧹 사용하지 않는 이미지 정리…',
      hint: '쓰는 앱이 없는 이미지를 조건에 맞춰 한 번에 지웁니다',
      disabledReason: canDeploy ? noReg : NEED,
      onSelect: () => setDlg('prune'),
    },
    {
      label: '⌫ 빌드 캐시 비우기…',
      disabledReason: '빌드가 들어오면 켜집니다',
    },
    {
      label: '♻ 저장소 공간 회수 (GC)…',
      hint: '지운 이미지가 남긴 레이어를 실제로 지워 공간을 돌려받습니다',
      disabledReason: canDeploy ? (builtin.length ? undefined : '켜진 내장 저장소가 없습니다(GC는 내장 저장소만)') : NEED,
      onSelect: () => setDlg('gc'),
    },
  ];
  return (
    <>
      <Menu label="정리" button="🧹 정리 ▾" items={items} />
      <button className="btn sm" disabled={refreshing || q.loading} onClick={() => reload(true)}>
        {refreshing ? '받는 중…' : '↻ 목록 새로 받기'}
      </button>
      <Link className="btn sm" to="/images/builds">
        빌드
      </Link>
      <Link className={`btn sm primary ${canDeploy ? '' : 'disabled'}`} to="/images/upload" title={canDeploy ? undefined : NEED} aria-disabled={!canDeploy}>
        ⇪ 이미지 업로드
      </Link>
      {dlg === 'gc' && <GcDialog tenant={tenant} groups={builtin} onClose={() => setDlg('')} onDone={() => reload(true, false)} />}
      {dlg === 'prune' && <PruneDialog tenant={tenant} groups={manageable} onClose={() => setDlg('')} onDone={() => reload(true, false)} />}
    </>
  );
}

// ── 표 ───────────────────────────────────────────────
/** 한 줄 = 태그 하나(태그 없는 다이제스트도 한 줄) */
interface Row {
  key: string;
  reg: RegistryView;
  img: RegistryImage;
  tag: string;
}
type Cond = { kind: 'bigger'; mb: number } | { kind: 'older'; days: number } | { kind: 'unused' } | { kind: 'deletable' } | { kind: 'untagged' } | { kind: 'tag'; pattern: string };
const condLabel = (c: Cond) =>
  c.kind === 'bigger'
    ? `크기 > ${c.mb} MB`
    : c.kind === 'older'
      ? `올린 지 ${c.days}일 넘음`
      : c.kind === 'unused'
        ? '쓰는 앱 없음'
        : c.kind === 'deletable'
          ? '삭제 가능'
          : c.kind === 'untagged'
            ? '태그 없음'
            : `태그 ${c.pattern}`;
const globRe = (pat: string) =>
  new RegExp(
    '^' +
      pat
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.') +
      '$',
  );

const COLS: { key: string; label: string; off?: string }[] = [
  { key: 'repo', label: '이미지' },
  { key: 'tag', label: '태그' },
  { key: 'digest', label: '다이제스트' },
  { key: 'size', label: '크기' },
  { key: 'at', label: '올린 시각' },
  { key: 'used', label: '쓰는 앱' },
  { key: 'platform', label: '플랫폼', off: '레이어 보기(UI-89) 뒤에 채웁니다' },
  {
    key: 'layers',
    label: '레이어 수',
    off: '레이어 보기(UI-89) 뒤에 채웁니다',
  },
  { key: 'build', label: '빌드 번호', off: '빌드 뒤에 채웁니다' },
];
const COLS_KEY = 'mydc.images.cols';
const loadCols = (): string[] => {
  try {
    const v = JSON.parse(localStorage.getItem(COLS_KEY) ?? 'null');
    if (Array.isArray(v)) return v.filter((x) => COLS.some((c) => c.key === x && !c.off));
  } catch {
    /* 저장소를 못 쓰면 기본 열 */
  }
  return COLS.filter((c) => !c.off).map((c) => c.key);
};
export const short = (d: string) => (d.length > 20 ? `${d.slice(0, 11)}…${d.slice(-2)}` : d);
export const agoMs = (ms: number | undefined) => {
  if (!ms) return '—';
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return '방금';
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`;
  const d = Math.floor(s / 86400);
  if (d === 1) return '어제';
  if (d < 14) return `${d}일 전`;
  if (d < 60) return `${Math.floor(d / 7)}주 전`;
  return `${Math.floor(d / 30)}달 전`;
};
const agoIso = (iso: string | undefined) => (iso ? agoMs(Date.parse(iso)) : '—');

function UsedCell({ tenant, use }: { tenant: string; use?: ImageUse }) {
  const t = usedText(use);
  if (!use) return <span className="muted">…</span>;
  if (!usesOf(use)) return <span className="muted">—</span>;
  return t.app ? (
    <Link to={`/deploy/apps/${encodeURIComponent(tenant)}/${encodeURIComponent(t.app)}`} className="ell" title={t.text}>
      {t.text}
    </Link>
  ) : (
    <span title={t.text}>{t.text}</span>
  );
}

export function ImageListTab() {
  const { tenant, canDeploy } = useTenantRole();
  const { q, reload, unread } = useCatalog();
  const toast = useToast();
  const navigate = useNavigate();
  const groups = q.data ?? [];
  // 목록에는 쓰는 곳이 없다. 모든 digest를 image-usage로 묻는다(내린 앱도 여기서 알게 된다)
  const digests = useMemo(() => [...new Set(groups.flatMap((g) => (g.page?.items ?? []).map((i) => i.digest)))].sort(), [groups]);
  const usage = usePoll(() => (digests.length ? imageUsage(tenant, digests) : Promise.resolve([] as ImageUse[])), [tenant, digests.join(',')], 0);
  const useBy = useMemo(() => new Map((usage.data ?? []).map((u) => [u.ref, u])), [usage.data]);

  const rows: Row[] = useMemo(
    () =>
      groups.flatMap((g) =>
        (g.page?.items ?? []).flatMap((img) =>
          (img.tags.length ? img.tags : ['']).map((tag) => ({
            key: `${g.reg.id}/${img.repository}@${img.digest}:${tag}`,
            reg: g.reg,
            img,
            tag,
          })),
        ),
      ),
    [groups],
  );
  const [find, setFind] = useState('');
  const [regs, setRegs] = useState<Set<string> | null>(null); // null = 모두
  const [conds, setConds] = useState<Cond[]>([]);
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 }>({
    key: 'at',
    dir: -1,
  });
  const [cols, setCols] = useState<string[]>(loadCols);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [pageSize, setPageSize] = useState(50);
  const [pageIdx, setPageIdx] = useState(0);
  const [del, setDel] = useState<Row[]>();
  const [layers, setLayers] = useState<Row>();
  const [tagFor, setTagFor] = useState<Row>();
  const findRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.key === '/' && !/INPUT|TEXTAREA|SELECT/.test(t.tagName) && !t.isContentEditable) {
        e.preventDefault();
        findRef.current?.focus();
      }
    };
    document.addEventListener('keydown', k);
    return () => document.removeEventListener('keydown', k);
  }, []);
  useEffect(() => {
    try {
      localStorage.setItem(COLS_KEY, JSON.stringify(cols));
    } catch {
      /* 기억하지 못해도 된다 */
    }
  }, [cols]);

  const used = (r: Row) => usesOf(useBy.get(r.img.digest)) > 0;
  const blocked = (r: Row): string | undefined => {
    if (!canDeploy) return NEED;
    if (!r.reg.enabled) return '멈춘 저장소의 이미지는 지울 수 없습니다';
    if (used(r)) {
      const t = usedText(useBy.get(r.img.digest)).text || '앱';
      return `${t}${iGa(t)} 쓰는 중이라 고를 수 없습니다. 앱이 다른 이미지로 바뀐 뒤 지울 수 있습니다.`;
    }
    return undefined;
  };
  const filtered = useMemo(() => {
    const f = find.trim().toLowerCase();
    const now = Date.now();
    let r = rows.filter((x) => !regs || regs.has(x.reg.id));
    if (f) r = r.filter((x) => `${x.img.repository} ${x.tag} ${x.img.digest}`.toLowerCase().includes(f));
    for (const c of conds)
      r = r.filter((x) =>
        c.kind === 'bigger'
          ? x.img.bytes > c.mb * 1_000_000
          : c.kind === 'older'
            ? !!x.img.pushedAt && now - x.img.pushedAt > c.days * 86400_000
            : c.kind === 'unused'
              ? !used(x)
              : c.kind === 'deletable'
                ? !blocked(x)
                : c.kind === 'untagged'
                  ? !x.tag
                  : !!x.tag && globRe(c.pattern).test(x.tag),
      );
    const val = (x: Row): string | number =>
      sort.key === 'repo'
        ? x.img.repository
        : sort.key === 'tag'
          ? x.tag
          : sort.key === 'digest'
            ? x.img.digest
            : sort.key === 'size'
              ? x.img.bytes
              : sort.key === 'used'
                ? usesOf(useBy.get(x.img.digest))
                : (x.img.pushedAt ?? 0);
    const order = groups.map((g) => g.reg.id);
    return [...r].sort((a, b) => order.indexOf(a.reg.id) - order.indexOf(b.reg.id) || (val(a) > val(b) ? 1 : val(a) < val(b) ? -1 : 0) * sort.dir);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, find, regs, conds, sort, useBy, canDeploy, groups]);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const cur = Math.min(pageIdx, pages - 1);
  const shown = filtered.slice(cur * pageSize, (cur + 1) * pageSize);
  const selRows = rows.filter((r) => sel.has(r.key));
  const pickable = shown.filter((r) => !blocked(r));
  const toggle = (k: string, on: boolean) => setSel((s) => (on ? new Set(s).add(k) : new Set([...s].filter((x) => x !== k))));
  // 목록이 바뀌어 고를 수 없게 된 줄은 뺀다
  useEffect(() => {
    setSel((s) => {
      const ok = new Set(rows.filter((r) => s.has(r.key) && !blocked(r)).map((r) => r.key));
      return ok.size === s.size ? s : ok;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, useBy]);

  const copy = (text: string, what: string) => void navigator.clipboard?.writeText(text).then(() => toast(`${what}을 복사했습니다.`));
  const pullRef = (r: Row) => `${r.reg.endpoint}/${r.img.repository}@${r.img.digest}`;
  const rowMenu = (r: Row): MenuItem[] => [
    { label: '레이어 보기', hint: '내장만', disabledReason: r.img.external ? '외부 저장소 이미지는 레이어를 보지 않습니다' : undefined, onSelect: () => setLayers(r) },
    {
      label: '다이제스트 복사',
      onSelect: () => copy(r.img.digest, '다이제스트'),
    },
    {
      label: '받기 명령 복사',
      hint: 'docker pull …',
      onSelect: () => copy(`docker pull ${pullRef(r)}`, '받기 명령'),
    },
    {
      label: '이 이미지로 배포…',
      hint: '단독 컨테이너 새로 실행',
      onSelect: () =>
        navigate('/standalone/new', {
          state: {
            yaml: standaloneToYaml({ ...emptyStandalone(), image: pullRef(r) }),
          },
        }),
    },
    { label: '빌드 기록 보기', disabledReason: '빌드 뒤에 켜집니다' },
    { sep: true, label: '' },
    {
      label: '태그 추가…',
      disabledReason: !canDeploy ? NEED : r.img.external ? '외부 저장소에는 태그를 붙이지 않습니다' : !r.reg.enabled ? '멈춘 저장소에는 태그를 붙일 수 없습니다' : undefined,
      onSelect: () => setTagFor(r),
    },
    {
      label: r.img.external && r.img.tags.length > 1 ? '삭제(모든 태그)…' : '삭제…',
      danger: true,
      hint: r.img.external && r.img.tags.length > 1 ? '외부 저장소는 이미지째 지웁니다' : undefined,
      disabledReason: blocked(r),
      onSelect: () => setDel([r]),
    },
  ];
  const visible = (k: string) => cols.includes(k);
  const sortBtn = (k: string, label: string) => (
    <button type="button" onClick={() => setSort((s) => (s.key === k ? { key: k, dir: s.dir === 1 ? -1 : 1 } : { key: k, dir: k === 'at' || k === 'size' ? -1 : 1 }))}>
      {label} {sort.key === k ? (sort.dir === 1 ? '▲' : '▼') : ''}
    </button>
  );
  const sortName = COLS.find((c) => c.key === sort.key)?.label ?? '';
  const failed = groups.filter((g) => g.error || g.page?.code);
  const oldest = groups.reduce<string | undefined>((a, g) => (g.page && (!a || g.page.cachedAt < a) ? g.page.cachedAt : a), undefined);
  const selBytes = [...new Map(selRows.map((r) => [r.img.digest, r.img.bytes])).values()].reduce((a, b) => a + b, 0);
  const selRegs = [...new Set(selRows.map((r) => r.reg.id))];
  const allShownPicked = pickable.length > 0 && pickable.every((r) => sel.has(r.key));
  const someShownPicked = pickable.some((r) => sel.has(r.key));
  const span = 2 + COLS.filter((c) => !c.off && visible(c.key)).length;

  return (
    <>
      <HelpBox terms="이미지 (repository) · 태그 (tag) · 다이제스트 (digest) · 목록 캐시 (catalog cache) · 저장소 정리 (garbage collection)">
        <b>이 화면은</b> 이 작업 공간이 쓰는 모든 저장소(내장 · 외부)의 이미지를 한곳에 모아 보여 줍니다. 저장소에 매번 묻지 않도록 목록을 웹 앱에 캐시해 두고 10분마다, 그리고 '목록 새로 받기'를 누를
        때 갱신합니다. 관리 권한이 있는 저장소의 이미지만 고르고 지울 수 있고, 앱이 쓰고 있는 이미지는 지울 수 없습니다.
      </HelpBox>
      {q.data && groups.length > 0 && (
        <div className="live-band">
          <b>목록 기준 {agoIso(oldest)}</b>
          <span>
            저장소 {groups.length}곳 중 {groups.length - failed.length}곳 갱신
            {failed.map((g) => ` · ${g.reg.id}은 읽지 못했습니다(${failText(g.error, g.page?.code)})`).join('')}
          </span>
          <span className="grow" />
          {failed.length > 0 && <Link to="/images/registry">내장 저장소 보기</Link>}
        </div>
      )}
      <Card>
        <Load q={q}>
          {() =>
            groups.length === 0 ? (
              <Empty kind="first" title="이미지 저장소가 없습니다" action={<Link to="/images/registry">내장 저장소 만들기</Link>}>
                내장 저장소를 만들거나 외부 저장소를 연결하면 이미지가 여기에 모입니다.
              </Empty>
            ) : (
              <div className="col" style={{ gap: 8 }}>
                <div className="list-toolbar">
                  <input
                    ref={findRef}
                    type="search"
                    placeholder="이미지 · 태그 · 다이제스트 찾기 (/)"
                    aria-label="이미지 찾기"
                    value={find}
                    onChange={(e) => (setFind(e.target.value), setPageIdx(0))}
                    style={{ width: 280 }}
                  />
                  <Pop chip on={!!regs} label={`저장소: ${regs ? `${regs.size}곳` : `전체 ${groups.length}곳`}`}>
                    {(close) => (
                      <div className="col" style={{ gap: 2, minWidth: 320 }}>
                        {groups.map((g) => (
                          <label key={g.reg.id} className="row pop-item">
                            <input
                              type="checkbox"
                              checked={!regs || regs.has(g.reg.id)}
                              onChange={(e) => {
                                const n = new Set(regs ?? groups.map((x) => x.reg.id));
                                if (e.target.checked) n.add(g.reg.id);
                                else n.delete(g.reg.id);
                                setRegs(n.size === groups.length ? null : n);
                                setPageIdx(0);
                              }}
                            />
                            <span className="grow">
                              {g.reg.id} ({g.external ? '외부' : '내장'})
                            </span>
                            <span className="muted small">{g.page && !g.page.code ? g.page.items.length : '읽지 못함'}</span>
                          </label>
                        ))}
                        {unread.map((a) => (
                          <label key={a} className="row pop-item muted" title="외부 저장소 탭에서 읽을 서버를 연결하면 나옵니다">
                            <input type="checkbox" disabled />
                            <span className="grow">{a} (외부)</span>
                            <span className="small" style={{ whiteSpace: 'nowrap' }}>
                              읽는 서버 없음
                            </span>
                          </label>
                        ))}
                        <hr />
                        <button className="pop-item" onClick={() => (setRegs(null), close())}>
                          모두
                        </button>
                        <button className="pop-item" onClick={() => (setRegs(canDeploy ? null : new Set()), close())}>
                          관리 권한 있는 곳만
                        </button>
                      </div>
                    )}
                  </Pop>
                  {conds.map((c, i) => (
                    <span key={i} className="chip on">
                      {condLabel(c)}
                      <button className="chip-x" aria-label={`${condLabel(c)} 조건 빼기`} onClick={() => setConds(conds.filter((_, j) => j !== i))}>
                        ✕
                      </button>
                    </span>
                  ))}
                  <Pop chip label={conds.length ? '＋ 조건' : '＋ 조건 (크기 · 올린 시각 · 삭제 가능)'}>
                    {(close) => <CondForm onAdd={(c) => (setConds([...conds, c]), setPageIdx(0), close())} />}
                  </Pop>
                  <span className="grow" />
                  <span className="muted small">
                    정렬: 저장소 › {sortName} {sort.dir === 1 ? '▲' : '▼'}
                  </span>
                  <Pop label="열 ▾" align="right">
                    {() => (
                      <div className="col" style={{ gap: 2, minWidth: 200 }}>
                        {COLS.map((c) => (
                          <label key={c.key} className={`row pop-item ${c.off ? 'muted' : ''}`} title={c.off}>
                            <input
                              type="checkbox"
                              disabled={!!c.off || (visible(c.key) && cols.length === 1)}
                              checked={!c.off && visible(c.key)}
                              onChange={(e) => setCols(e.target.checked ? COLS.filter((x) => x.key === c.key || cols.includes(x.key)).map((x) => x.key) : cols.filter((x) => x !== c.key))}
                            />
                            <span>{c.label}</span>
                          </label>
                        ))}
                      </div>
                    )}
                  </Pop>
                </div>
                {selRows.length > 0 && (
                  <div className="bulkbar dark">
                    <input
                      type="checkbox"
                      aria-label="선택 해제"
                      checked
                      ref={(el) => el && (el.indeterminate = selRows.length < rows.filter((r) => !blocked(r)).length)}
                      onChange={() => setSel(new Set())}
                    />
                    <b>{selRows.length}개 고름</b>
                    <span>
                      합계 {fmtBytes(selBytes)} · {selRegs.length === 1 ? `모두 ${selRegs[0]}` : `저장소 ${selRegs.length}곳`}
                    </span>
                    <span className="grow" />
                    <button className="btn sm" onClick={() => copy([...new Set(selRows.map((r) => r.img.digest))].join('\n'), '다이제스트')}>
                      다이제스트 복사
                    </button>
                    <button
                      className="btn sm"
                      disabled={new Set(selRows.map((r) => r.img.digest)).size !== 1}
                      title={new Set(selRows.map((r) => r.img.digest)).size !== 1 ? '이미지 하나만 고르면 새 앱 폼을 그 이미지로 엽니다' : '새 앱 폼을 이 이미지로 엽니다'}
                      onClick={() =>
                        navigate('/deploy/new', {
                          state: { image: pullRef(selRows[0]) },
                        })
                      }
                    >
                      배포에 쓰기
                    </button>
                    <button className="btn sm danger" onClick={() => setDel(selRows)}>
                      삭제…
                    </button>
                  </div>
                )}
                {filtered.length === 0 ? (
                  <Empty
                    kind="filtered"
                    title={rows.length ? '조건에 맞는 이미지가 없습니다' : '이미지가 없습니다'}
                    action={
                      rows.length ? (
                        <button className="btn sm" onClick={() => (setFind(''), setConds([]), setRegs(null))}>
                          조건 지우기
                        </button>
                      ) : undefined
                    }
                  />
                ) : (
                  <div className="table-wrap">
                    <table className="tbl">
                      <thead>
                        <tr>
                          <th style={{ width: 36 }}>
                            <input
                              type="checkbox"
                              aria-label="이 페이지에서 고를 수 있는 것 모두"
                              disabled={!pickable.length}
                              checked={allShownPicked}
                              ref={(el) => el && (el.indeterminate = someShownPicked && !allShownPicked)}
                              onChange={(e) =>
                                setSel((s) => {
                                  const n = new Set(s);
                                  pickable.forEach((r) => (e.target.checked ? n.add(r.key) : n.delete(r.key)));
                                  return n;
                                })
                              }
                            />
                          </th>
                          {visible('repo') && <th>{sortBtn('repo', '이미지')}</th>}
                          {visible('tag') && <th>{sortBtn('tag', '태그')}</th>}
                          {visible('digest') && <th>{sortBtn('digest', '다이제스트')}</th>}
                          {visible('size') && <th style={{ width: 90 }}>{sortBtn('size', '크기')}</th>}
                          {visible('at') && <th style={{ width: 110 }}>{sortBtn('at', '올린 시각')}</th>}
                          {visible('used') && <th>{sortBtn('used', '쓰는 앱')}</th>}
                          <th style={{ width: 60 }} />
                        </tr>
                      </thead>
                      <tbody>
                        {shown.map((r, i) => {
                          const b = blocked(r);
                          const g = groups.find((x) => x.reg.id === r.reg.id)!;
                          const head = i === 0 || shown[i - 1].reg.id !== r.reg.id;
                          return (
                            <GroupRows key={r.key} head={head ? <GroupHead g={g} span={span} canManage={canDeploy} /> : null}>
                              <tr className={sel.has(r.key) ? 'selected' : ''}>
                                <td>
                                  <input
                                    type="checkbox"
                                    aria-label={`${r.img.repository}:${r.tag || r.img.digest} 고르기`}
                                    disabled={!!b}
                                    title={b}
                                    checked={sel.has(r.key)}
                                    onChange={(e) => toggle(r.key, e.target.checked)}
                                  />
                                </td>
                                {visible('repo') && (
                                  <td className="mono" title={r.img.repository}>
                                    {r.img.repository}
                                  </td>
                                )}
                                {visible('tag') && <td className={`mono ${r.tag ? '' : 'muted'}`}>{r.tag || '(태그 없음)'}</td>}
                                {visible('digest') && (
                                  <td className="mono muted" title={r.img.digest}>
                                    {short(r.img.digest)}
                                  </td>
                                )}
                                {visible('size') && <td>{fmtBytes(r.img.bytes)}</td>}
                                {visible('at') && <td className="muted">{agoMs(r.img.pushedAt)}</td>}
                                {visible('used') && (
                                  <td>
                                    <UsedCell tenant={tenant} use={useBy.get(r.img.digest)} />
                                  </td>
                                )}
                                <td>
                                  <Menu label={`${r.img.repository}:${r.tag || '태그 없음'} 메뉴`} items={rowMenu(r)} />
                                </td>
                              </tr>
                            </GroupRows>
                          );
                        })}
                        {cur === pages - 1 &&
                          groups
                            .filter((g) => (!regs || regs.has(g.reg.id)) && !filtered.some((r) => r.reg.id === g.reg.id))
                            .map((g) => (
                              <GroupRows key={`empty/${g.reg.id}`} head={<GroupHead g={g} span={span} canManage={canDeploy} />}>
                                <tr>
                                  <td colSpan={span} className="muted small">
                                    {g.error || g.page?.code ? `목록을 읽지 못했습니다(${failText(g.error, g.page?.code)})` : g.page?.items.length ? '조건에 맞는 이미지가 없습니다' : '이미지가 없습니다'}
                                  </td>
                                </tr>
                              </GroupRows>
                            ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <div className="list-foot">
                  <span>
                    <b>{filtered.length ? `${cur * pageSize + 1}–${Math.min(filtered.length, (cur + 1) * pageSize)}` : 0}</b> / {filtered.length}개 (저장소 {groups.length}곳 · 전체 {rows.length})
                  </span>
                  <span className="muted">캐시 기준 {agoIso(oldest)}</span>
                  <span className="grow" />
                  <span className="row">
                    <label className="row" style={{ gap: 4 }}>
                      한 페이지에
                      <select value={pageSize} onChange={(e) => (setPageSize(Number(e.target.value)), setPageIdx(0))} style={{ height: 28, fontSize: 12 }}>
                        {[25, 50, 100].map((n) => (
                          <option key={n} value={n}>
                            {n}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button className="btn sm" disabled={cur === 0} onClick={() => setPageIdx(cur - 1)}>
                      이전
                    </button>
                    <button className="btn sm" disabled={cur >= pages - 1} onClick={() => setPageIdx(cur + 1)}>
                      다음 ›
                    </button>
                  </span>
                </div>
                <span className="small muted">
                  회색 칸은 고를 수 없는 이미지입니다: 🔒 관리 권한이 없는 저장소(보기만), 또는 앱이 쓰는 중. 쓰는 앱은 사용처 조회로 채우고, 실행 중인 앱, 자동 배포 후보, 보관된 앱(되살리기용
                  app.yaml)까지 셉니다. 같은 이미지 이름은 저장소 안에서 묶여 보이고, 태그 없는 다이제스트도 따로 한 줄입니다. 외부 저장소는 읽는 서버가 연결된 것만 나오고, 레이어 보기·태그 추가가
                  없으며, 삭제는 이미지(다이제스트)째로만 됩니다.
                </span>
              </div>
            )
          }
        </Load>
      </Card>
      {del && (
        <DeleteDialog
          key={del.map((r) => r.key).join('|')}
          tenant={tenant}
          rows={del}
          onClose={() => setDel(undefined)}
          onDone={(gone) => {
            setSel((s) => new Set([...s].filter((k) => !gone.includes(k))));
            reload(true, false);
          }}
        />
      )}
      {layers && <LayersDialog tenant={tenant} reg={layers.reg} img={layers.img} tag={layers.tag} use={useBy.get(layers.img.digest)} onClose={() => setLayers(undefined)} />}
      {tagFor && (
        <TagDialog
          tenant={tenant}
          reg={tagFor.reg}
          img={tagFor.img}
          siblings={groups.find((g) => g.reg.id === tagFor.reg.id)?.page?.items ?? []}
          onClose={() => setTagFor(undefined)}
          onDone={() => reload(true, false)}
        />
      )}
    </>
  );
}

const CODE_TEXT: Record<string, string> = { unauthorized: '로그인 실패', denied: '권한 없음', 'not-found': '저장소 없음', unsupported: '목록 조회를 지원하지 않음', unavailable: '닿지 않음' };
const failText = (e: unknown, code?: string) =>
  code ? (CODE_TEXT[code] ?? code) : e instanceof ApiError ? (e.status === 403 ? '권한 없음' : e.status === 404 ? '목록 조회 없음' : e.status === 409 ? '읽는 서버 없음' : `${e.status}`) : '연결 실패';

function GroupRows({ head, children }: { head: ReactNode; children: ReactNode }) {
  return (
    <>
      {head}
      {children}
    </>
  );
}

function GroupHead({ g, span, canManage }: { g: Group; span: number; canManage: boolean }) {
  const total = [...new Map((g.page?.items ?? []).map((i) => [i.digest, i.bytes])).values()].reduce((a, b) => a + b, 0);
  const bad = g.error || g.page?.code;
  return (
    <tr className="grp">
      <td colSpan={span}>
        <span className="row between">
          <b>
            {g.external ? '외부' : '내장'} · {g.reg.id} <span className="mono muted">({g.reg.endpoint})</span>
          </b>
          <span className="muted small">
            {bad
              ? `갱신 실패 · ${failText(g.error, g.page?.code)}`
              : `${canManage ? '관리 권한 있음' : '🔒 보기만'} · ${g.page?.items.length ?? 0}개 · ${fmtBytes(total)} · ${agoIso(g.page?.cachedAt)} 갱신${g.page?.live ? ' · 실시간 목록' : ''}${g.page?.truncated ? ' · 일부만 받음' : ''}`}
            {!g.reg.enabled && ' · 멈춤'}
          </span>
        </span>
      </td>
    </tr>
  );
}

/** 칩·버튼에서 여는 작은 창(바깥을 누르거나 Esc로 닫힘) */
function Pop({ label, chip, on, align = 'left', children }: { label: string; chip?: boolean; on?: boolean; align?: 'left' | 'right'; children: (close: () => void) => ReactNode }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', away);
    document.addEventListener('keydown', esc);
    return () => (document.removeEventListener('mousedown', away), document.removeEventListener('keydown', esc));
  }, [open]);
  return (
    <span ref={ref} className="menu-wrap">
      <button type="button" className={chip ? `chip ${on ? 'on' : ''}` : 'btn sm'} aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {label} {chip && <span className="muted">▾</span>}
      </button>
      {open && (
        <div className="menu pop" style={align === 'left' ? { left: 0, right: 'auto' } : undefined}>
          {children(() => setOpen(false))}
        </div>
      )}
    </span>
  );
}

function CondForm({ onAdd }: { onAdd: (c: Cond) => void }) {
  const [kind, setKind] = useState<Cond['kind']>('bigger');
  const [n, setN] = useState('200');
  const [pattern, setPattern] = useState('pr-*');
  const num = Number(n);
  const okNum = Number.isFinite(num) && num > 0;
  const add = () => onAdd(kind === 'bigger' ? { kind, mb: num } : kind === 'older' ? { kind, days: num } : kind === 'tag' ? { kind, pattern: pattern.trim() } : { kind });
  return (
    <div className="col" style={{ gap: 8, padding: 8, minWidth: 260 }}>
      <b className="small">조건 추가</b>
      <Field label="조건">
        <select value={kind} onChange={(e) => (setKind(e.target.value as Cond['kind']), setN(e.target.value === 'older' ? '30' : '200'))}>
          <option value="bigger">크기</option>
          <option value="older">올린 시각</option>
          <option value="unused">쓰는 앱 없음</option>
          <option value="deletable">삭제 가능</option>
          <option value="untagged">태그 없음</option>
          <option value="tag">태그 패턴</option>
        </select>
      </Field>
      {(kind === 'bigger' || kind === 'older') && (
        <div className="row" style={{ gap: 6 }}>
          <span className="small">{kind === 'bigger' ? '보다 큼' : '일 넘음'}</span>
          <input value={n} onChange={(e) => setN(e.target.value)} inputMode="numeric" style={{ width: 90 }} aria-label={kind === 'bigger' ? '크기 (MB)' : '일 수'} />
          <span className="small muted">{kind === 'bigger' ? 'MB' : '일'}</span>
        </div>
      )}
      {kind === 'tag' && <input className="mono" value={pattern} onChange={(e) => setPattern(e.target.value)} aria-label="태그 패턴" placeholder="pr-*" />}
      <span className="small muted">다른 조건: 올린 시각(n일 넘음) · 쓰는 앱 없음 · 삭제 가능 · 태그 없음 · 태그 패턴(pr-*)</span>
      <span className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="btn sm primary" disabled={((kind === 'bigger' || kind === 'older') && !okNum) || (kind === 'tag' && !pattern.trim())} onClick={add}>
          적용
        </button>
      </span>
    </div>
  );
}

// ── 삭제 (⑰ 확인) ─────────────────────────────────────
/** 보낼 삭제 하나. 한 이미지의 태그를 모두 골랐거나 외부 저장소면 digest째, 아니면 고른 태그만 */
interface Job {
  key: string;
  keys: string[];
  reg: RegistryView;
  img: RegistryImage;
  reference: string;
  label: string;
  whole: boolean;
}
function jobsOf(rows: Row[]): Job[] {
  const by = new Map<string, Row[]>();
  for (const r of rows) {
    const k = `${r.reg.id}/${r.img.repository}@${r.img.digest}`;
    by.set(k, [...(by.get(k) ?? []), r]);
  }
  return [...by].flatMap(([k, rs]): Job[] => {
    const img = rs[0].img;
    const picked = new Set(rs.map((r) => r.tag));
    const whole = img.external || picked.has('') || img.tags.every((t) => picked.has(t));
    if (whole) return [{ key: k, keys: rs.map((r) => r.key), reg: rs[0].reg, img, reference: img.digest, label: `${img.repository}@${short(img.digest)}${img.tags.length ? ` (태그 ${img.tags.join(', ')})` : ''}`, whole }];
    return rs.map((r) => ({ key: r.key, keys: [r.key], reg: r.reg, img, reference: r.tag, label: `${img.repository}:${r.tag}`, whole: false }));
  });
}
type Sent = { op?: OpView; error?: unknown; status?: DMaintenanceStatus; end?: DMaintenanceStatus };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const BUSY = 'busy';
function DeleteDialog({ tenant, rows, onClose, onDone }: { tenant: string; rows: Row[]; onClose: () => void; onDone: (gone: string[]) => void }) {
  const toast = useToast();
  // 연 순간의 줄과 쓰는 곳을 고정한다
  const [jobs] = useState(() => jobsOf(rows));
  const check = usePoll(() => imageUsage(tenant, [...new Set(jobs.map((j) => j.img.digest))]), [tenant], 0);
  const useBy = new Map((check.data ?? []).map((u) => [u.ref, u]));
  const [typed, setTyped] = useState('');
  const [sent, setSent] = useState<Record<string, Sent>>({});
  const [busy, setBusy] = useState(false);
  // 같은 삭제를 다시 보내면 같은 작업 ID(응답 불명 뒤 재시도도 안전)
  const ids = useRef(new Map<string, string>());
  const n = jobs.length;
  const reclaim = [...new Map(jobs.filter((j) => j.whole).map((j) => [j.img.digest, j.img.bytes])).values()].reduce((a, b) => a + b, 0);
  const skip = (j: Job) => usesOf(useBy.get(j.img.digest)) > 0;
  /** 한 저장소에는 정리 작업이 하나씩만 돈다(그 사이 보내면 409 busy). 그래서 하나가 끝날 때까지 기다린 뒤 다음을 보낸다 */
  const follow = async (j: Job, op: OpView) => {
    for (let n = 0; n < 120; n++) {
      try {
        const st = await maintenanceStatus(tenant, op.id);
        setSent((x) => ({ ...x, [j.key]: { ...x[j.key], status: st } }));
        if (st.state === 'done' || st.state === 'failed') return ended(j, st);
        if (st.state === 'unknown') return;
      } catch {
        /* 다음 차례에 다시 읽는다 */
      }
      await sleep(Math.min(5000, 1000 + n * 300));
    }
  };
  const send = async () => {
    setBusy(true);
    for (const j of jobs) {
      const s = sent[j.key];
      if (s?.op && s.op.state !== 'unknown' && s.op.state !== 'pending' && s.op.state !== 'running') continue;
      if (s?.error instanceof ApiError && s.error.status < 500 && s.error.code !== BUSY) continue;
      // 내린 앱만 쓰는 이미지는 mydcd가 막지 않는다. 웹이 먼저 뺀다
      if (skip(j)) continue;
      if (!ids.current.has(j.key)) ids.current.set(j.key, newOpId());
      const body = { opId: ids.current.get(j.key), ...(j.img.external ? { external: true } : {}), repository: j.img.repository, reference: j.reference, digest: j.img.digest };
      try {
        const res = await api.post<{ op: DOp }>(`${registryPath(tenant, j.reg.id)}/images/delete`, body);
        const op = toOp(res.op);
        setSent((x) => ({ ...x, [j.key]: { op } }));
        if (op.state === 'applied') await follow(j, op);
      } catch (e) {
        // busy는 같은 작업 ID로 다시 보내도 된다(보내지 않은 것)
        setSent((x) => ({ ...x, [j.key]: { error: e } }));
      }
    }
    setBusy(false);
  };
  const ended = (j: Job, st: DMaintenanceStatus) => {
    setSent((x) => ({ ...x, [j.key]: { ...x[j.key], end: st } }));
    const ok = st.state === 'done' && (st.result?.code === 'ok' || st.result?.code === 'already-absent');
    if (ok) {
      onDone(j.keys);
      toast(`${j.label}${eulReul(j.label)} 지웠습니다.${j.whole && !j.img.external ? ' 공간은 저장소 공간 회수(GC) 때 돌아옵니다.' : ''}`);
    }
  };
  const started = Object.keys(sent).length > 0;
  const settled = (j: Job) => {
    const s = sent[j.key];
    if (skip(j)) return true;
    if (s?.error !== undefined) return s.error instanceof ApiError && s.error.status < 500 && s.error.code !== BUSY;
    if (!s?.op) return false;
    if (s.op.state === 'failed' || s.op.state === 'rejected') return true;
    return s.op.state === 'applied' && (!!s.end || s.status?.state === 'unknown');
  };
  const allDone = !!check.data && jobs.every(settled);
  return (
    <Dialog
      danger
      title={`이미지 ${n}개 삭제`}
      onClose={onClose}
      footer={
        allDone ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              {started ? '닫기(진행은 계속됨)' : '취소'}
            </button>
            <button className="btn danger" disabled={busy || !check.data || typed.trim() !== String(n)} onClick={() => void send()}>
              {busy ? '보내는 중…' : started ? '남은 것 다시 보내기' : `${n}개 삭제`}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <div className="table-wrap">
          <table className="tbl">
            <tbody>
              {jobs.map((j) => {
                const u = useBy.get(j.img.digest);
                const s = sent[j.key];
                return (
                  <tr key={j.key}>
                    <td className="mono">
                      {j.label}
                      {j.whole && j.img.tags.length > 1 && <div className="small muted">이미지째 지움 · 태그 {j.img.tags.length}개 모두</div>}
                    </td>
                    <td style={{ width: 200, textAlign: 'right' }}>
                      {s?.op ? (
                        s.op.state === 'applied' ? (
                          <MaintBadge s={s.end ?? s.status} />
                        ) : (
                          <OpBadge state={s.op.state} />
                        )
                      ) : s?.error !== undefined ? (
                        s.error instanceof ApiError && s.error.code === 'image-in-use' ? (
                          <Badge tone="wa">쓰는 중이라 보내지 않음</Badge>
                        ) : s.error instanceof ApiError && s.error.code === BUSY ? (
                          <Badge tone="wa">저장소가 다른 작업 중</Badge>
                        ) : (
                          <Badge tone="er">보내지 못함</Badge>
                        )
                      ) : !check.data ? (
                        <span className="muted small">확인 중…</span>
                      ) : usesOf(u) ? (
                        <Badge tone="wa" title={usedText(u).text}>
                          쓰는 중 · 지우지 않음
                        </Badge>
                      ) : (
                        <Badge tone="ok">쓰는 곳 없음</Badge>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <KV
          items={[
            ['지울 것', '이미지째 지우는 줄은 그 이미지와 모든 태그를, 태그 줄은 그 태그만 지웁니다. 외부 저장소는 이미지째만 지울 수 있습니다'],
            ['공간 회수', reclaim ? `바로 줄지 않음 · 내장 저장소는 공간 회수(GC) 때 약 ${fmtBytes(reclaim)}` : '태그만 지우면 공간이 줄지 않음'],
            ['되돌리기', '불가. 다시 올리거나 빌드해야 함'],
          ]}
        />
        <div className="note wa small">
          보내기 전에 서버가 쓰는 곳을 다시 확인하고, 쓰는 중이면 보내지 않습니다. 그 사이 태그가 다른 이미지로 옮겨 갔으면 지우지 않습니다. 내린 앱(되살리기용)이 쓰는 이미지는 이 화면이 먼저 뺍니다.
        </div>
        <span className="small muted">
          상태: 차례 기다림 · 진행 중 · 끝남 · 이미 없음 · 쓰는 중이라 건너뜀 · 저장소가 다른 작업 중. 창을 닫아도 진행은 계속되고 <Link to="/system/ops">작업 기록</Link>에서 이어 봅니다.
        </span>
        {!allDone && !started && (
          <Field label={`확인을 위해 지울 개수 ${n}${eulReul(String(n))} 입력`}>
            <input value={typed} onChange={(e) => setTyped(e.target.value)} inputMode="numeric" disabled={busy} />
          </Field>
        )}
        {jobs.map((j) => {
          const s = sent[j.key];
          if (s?.error !== undefined && !(s.error instanceof ApiError && (s.error.code === 'image-in-use' || s.error.code === BUSY))) return <MutationError key={j.key} error={s.error} />;
          if (s?.op && ['unknown', 'pending', 'running'].includes(s.op.state))
            return <OpPanel key={j.key} op={s.op} onChange={(o) => (setSent((x) => ({ ...x, [j.key]: { op: o } })), o.state === 'applied' && void follow(j, o))} />;
          return null;
        })}
      </div>
    </Dialog>
  );
}
// ── 저장소 공간 회수 (GC, 내장 저장소만) ──────────────────────
function GcDialog({ tenant, groups, onClose, onDone }: { tenant: string; groups: Group[]; onClose: () => void; onDone: () => void }) {
  const [id, setId] = useState(groups[0]?.reg.id ?? '');
  const g = groups.find((x) => x.reg.id === id);
  const m = useMutation();
  const mt = useMaintenance(tenant, m.op, () => onDone());
  const finished = mt.status?.state === 'done' || mt.status?.state === 'failed';
  const send = async () => {
    if (uncertain(m) && !(m.error instanceof ApiError && m.error.status < 500)) return void (await m.again());
    if (ended(m) || m.error !== undefined) m.reset();
    await m.run(`${registryPath(tenant, id)}/gc`, {});
  };
  const mn = g?.reg.maintenance;
  const busy = m.error instanceof ApiError && m.error.code === BUSY;
  return (
    <Dialog
      title={`저장소 공간 회수 · ${id}`}
      width={560}
      onClose={onClose}
      footer={
        finished ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              {m.op?.state === 'applied' ? '닫기(진행은 계속됨)' : '취소'}
            </button>
            <button className="btn primary" disabled={m.busy || !g || m.op?.state === 'applied' || !!mn?.pendingOperation} onClick={() => void send()}>
              {m.busy ? '보내는 중…' : m.op && uncertain(m) ? '같은 작업으로 다시 보내기' : '회수 시작'}
            </button>
          </>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        {groups.length > 1 && (
          <Field label="저장소">
            <select value={id} onChange={(e) => (setId(e.target.value), m.reset())} disabled={!!m.op || m.busy}>
              {groups.map((x) => (
                <option key={x.reg.id} value={x.reg.id}>
                  {x.reg.id} ({x.reg.endpoint})
                </option>
              ))}
            </select>
          </Field>
        )}
        <KV
          items={[
            ['지난 회수', mn?.lastGCAt ? `${agoMs(mn.lastGCAt)} · ${fmtBytes(mn.reclaimedBytes)} 회수` : '없음'],
            ['진행 중 작업', mn?.pendingOperation ? `${mn.pendingOperation} (${MSTATE[mn.pendingState ?? '']?.[1] ?? mn.pendingState ?? '진행 중'})` : '없음'],
            ['회수량', '회수량은 끝난 뒤에 보임 · 쓰지 않는 레이어만 지웁니다'],
          ]}
        />
        {mn?.pendingOperation && !m.op && <div className="note wa small">이 저장소에 끝나지 않은 작업이 있어 지금은 회수를 시작할 수 없습니다. 그 작업이 끝난 뒤 다시 여세요.</div>}
        <div className="note wa small">회수하는 동안 {id}은 읽기 전용입니다. 이미지 올리기·빌드 올리기가 실패하고 다시 시도됩니다.</div>
        {busy ? <div className="note wa small">저장소에 다른 작업이 진행 중입니다. 끝난 뒤 다시 시작하세요.</div> : <MutationError error={m.error} />}
        {m.op && m.op.state !== 'applied' && <OpPanel op={m.op} onChange={(o) => m.setOp(o)} />}
        {m.op?.state === 'applied' && (
          <KV
            items={[
              ['상태', <MaintBadge key="s" s={mt.status} />],
              ...(mt.status?.result ? ([['결과', `${resultText(mt.status.result.code)} · ${fmtBytes(mt.status.result.reclaimedBytes)} 회수`]] as [string, ReactNode][]) : []),
            ]}
          />
        )}
      </div>
    </Dialog>
  );
}

// ── 사용하지 않는 이미지 정리 (UI-8A) ─────────────────────
// 조건을 고르면 데몬이 미리 보기(prune/preview)를 만들고 서명된 미리 보기 토큰을 준다. 다음 쪽·다른 part·실행은 받은 conditions와
// preview를 그대로 보낸다. 미리 보기는 10분 유효(expiresAt), 지났거나 저장소가 바뀌면 409 preview-expired.
const KEEP = [5, 0, 10];
const OLDER = [30, 7, 90, 0];
const RETAIN: Record<string, string> = {
  'image-in-use': '쓰는 중',
  protected: '보호됨(내린 앱 등)',
  'excluded-tag': '제외 패턴',
  recent: '최근 태그',
  'upload-time-unknown': '올린 시각 모름',
  'too-recent': '너무 최근',
  'untagged-excluded': '태그 없음 제외',
  'manifest-dependency': '다른 이미지가 참조',
  'repository-filter': '고른 저장소 밖',
};
const imgName = (i: { repository: string; reference: string; digest: string }) => `${i.repository}${i.reference.startsWith('sha256:') ? `@${short(i.reference)}` : `:${i.reference}`}`;
function PruneDialog({ tenant, groups, onClose, onDone }: { tenant: string; groups: Group[]; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [id, setId] = useState(groups[0]?.reg.id ?? '');
  const g = groups.find((x) => x.reg.id === id);
  const external = !!g?.external;
  const [skipped, setSkipped] = useState<string[]>([]); // 지울 것 표에서 체크를 끈 이미지 이름(이번 정리에서 뺌)
  const [keep, setKeep] = useState(5);
  const [older, setOlder] = useState(30);
  const [exclude, setExclude] = useState('release-*, stable');
  const [untagged, setUntagged] = useState(true);
  const [gc, setGc] = useState(true);
  const [typed, setTyped] = useState('');
  const m = useMutation();
  const patterns = exclude
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
  const badPattern = patterns.find((x) => x.includes('/')) ?? (patterns.length > 32 ? '32개까지' : undefined);
  // 올린 시각 기준은 미리 보기를 받을 때 정한다(같은 조건이면 같은 before)
  const [stamp, setStamp] = useState(() => Math.floor(Date.now() / 1000));
  const allRepos = g?.page?.repositories ?? [];
  const repos = skipped.length ? allRepos.filter((r) => !skipped.includes(r)) : [];
  /** 이름을 모두 뺐다(빈 repositories는 '전부'라서 보내지 않는다) */
  const noneLeft = skipped.length > 0 && repos.length === 0;
  const conditions: DPruneConditions = {
    repositories: repos,
    keepRecentPerRepository: keep,
    ...(older ? { before: stamp - older * 86400 } : {}),
    excludeTags: patterns,
    includeUntagged: untagged,
    gc: !external && gc,
  };
  const key = JSON.stringify([id, external, conditions]);
  const [part, setPart] = useState<'items' | 'retained'>('items');
  type Prev = { key: string; first?: PrunePage; pages: Record<string, PrunePage[]>; error?: unknown; more?: boolean };
  const [prev, setPrev] = useState<Prev>();
  const [tick, setTick] = useState(0);
  const locked = !!m.op || m.busy;
  useEffect(() => {
    if (locked || badPattern || noneLeft) return;
    let live = true;
    const t = setTimeout(() => {
      prunePreview(tenant, id, { ...(external ? { external: true } : {}), part: 'items', conditions }).then(
        (p) => live && setPrev({ key, first: p, pages: { items: [p] } }),
        (error) => live && setPrev({ key, pages: {}, error }),
      );
    }, 300);
    return () => ((live = false), clearTimeout(t));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tenant, tick]);
  const cur = prev?.key === key ? prev : undefined;
  const p = noneLeft ? undefined : cur?.first;
  const shown = cur?.pages[part] ?? [];
  const lastShown = shown[shown.length - 1];
  const [pageErr, setPageErr] = useState<unknown>();
  // 다음 쪽 또는 다른 part: 받은 conditions·preview를 그대로
  const load = async (pt: 'items' | 'retained', after?: string) => {
    if (!p?.preview) return;
    setPageErr(undefined);
    try {
      const r = await prunePreview(tenant, id, { ...(external ? { external: true } : {}), part: pt, conditions: p.conditions, preview: p.preview, after });
      setPrev((x) => (x && x.key === key ? { ...x, pages: { ...x.pages, [pt]: after ? [...(x.pages[pt] ?? []), r] : [r] } } : x));
    } catch (e) {
      setPageErr(e);
    }
  };
  useEffect(() => {
    if (p && part === 'retained' && !cur?.pages.retained) void load('retained');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [part, p]);
  const expired = [cur?.error, pageErr, m.error].some((e) => e instanceof ApiError && e.code === 'preview-expired');
  const count = p?.items ?? 0;
  const mt = useMaintenance(tenant, m.op, (st) => {
    onDone();
    if (st.state === 'done') toast(`정리를 마쳤습니다. 지움 ${st.result?.prune?.deleted ?? 0}개 · 건너뜀 ${st.result?.prune?.skipped ?? 0}개.`);
  });
  const finished = mt.status?.state === 'done' || mt.status?.state === 'failed';
  const send = async () => {
    if (m.op && uncertain(m)) return void (await m.again());
    if (m.error !== undefined && !(m.error instanceof ApiError && m.error.status < 500)) return void (await m.again());
    if (!p?.preview) return;
    m.reset();
    await m.run(`${registryPath(tenant, id)}/prune`, { ...(external ? { external: true } : {}), conditions: p.conditions, preview: p.preview });
  };
  /** 실패·거부·만료 뒤 새 미리 보기를 받아 새 작업으로 */
  const replan = () => {
    m.reset();
    setPrev(undefined);
    setPageErr(undefined);
    setTyped('');
    setStamp(Math.floor(Date.now() / 1000));
    setTick((x) => x + 1);
  };
  const busyErr = m.error instanceof ApiError && m.error.code === BUSY;
  return (
    <Dialog
      title="사용하지 않는 이미지 정리"
      width={720}
      onClose={onClose}
      footer={
        finished ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : m.op?.state === 'applied' ? (
          <button className="btn" onClick={onClose}>
            닫기(진행은 계속됨)
          </button>
        ) : (
          <span className="row between" style={{ width: '100%' }}>
            <label className="row small" style={{ gap: 6 }}>
              확인: {count} 입력
              <input value={typed} onChange={(e) => setTyped(e.target.value)} inputMode="numeric" style={{ width: 80 }} disabled={locked} aria-label={`확인: ${count} 입력`} />
            </label>
            <span className="row">
              <button className="btn" onClick={onClose}>
                취소
              </button>
              {ended(m) || expired ? (
                <button className="btn primary" onClick={replan}>
                  새 미리 보기 받기
                </button>
              ) : m.op && uncertain(m) ? (
                <button className="btn primary" disabled={m.busy} onClick={() => void send()}>
                  {m.busy ? '보내는 중…' : '같은 작업으로 다시 보내기'}
                </button>
              ) : (
                <button className="btn danger" disabled={m.busy || !!m.op || !p?.preview || !count || typed.trim() !== String(count)} onClick={() => void send()}>
                  {m.busy ? '보내는 중…' : conditions.gc ? `${count}개 지우고 공간 회수` : `${count}개 지우기`}
                </button>
              )}
            </span>
          </span>
        )
      }
    >
      <div className="col" style={{ gap: 12 }}>
        <div className="grid" style={{ gridTemplateColumns: 'repeat(4, minmax(0,1fr))', gap: 10 }}>
          <Field label="대상 저장소">
            <select value={id} onChange={(e) => (setId(e.target.value), setSkipped([]))} disabled={locked}>
              {groups.map((x) => (
                <option key={x.reg.id} value={x.reg.id}>
                  {x.reg.id} ({x.external ? '외부' : '내장'})
                </option>
              ))}
            </select>
          </Field>
          <Field label="저장소마다 남길 최근 태그">
            <select value={keep} onChange={(e) => setKeep(Number(e.target.value))} disabled={locked}>
              {KEEP.map((k) => (
                <option key={k} value={k}>
                  {k}개{k === 0 ? ' (모두 대상)' : ''}
                </option>
              ))}
            </select>
          </Field>
          <Field label="이보다 오래된 것만">
            <select value={older} onChange={(e) => (setOlder(Number(e.target.value)), setStamp(Math.floor(Date.now() / 1000)))} disabled={locked}>
              {OLDER.map((d) => (
                <option key={d} value={d}>
                  {d ? `${d}일` : '상관없음'}
                </option>
              ))}
            </select>
          </Field>
          <Field label="태그 이름 제외 (패턴)" error={badPattern ? `/ 없이 32개까지 (${badPattern})` : undefined}>
            <input className="mono" value={exclude} onChange={(e) => setExclude(e.target.value)} disabled={locked} spellCheck={false} />
          </Field>
        </div>
        {skipped.length > 0 && (
          <div className="row small" style={{ gap: 8, flexWrap: 'wrap' }}>
            <span className="muted">이번 정리에서 뺀 이름:</span>
            {skipped.map((r) => (
              <span key={r} className="chip on mono">
                {r}
                <button className="chip-x" aria-label={`${r} 다시 넣기`} disabled={locked} onClick={() => setSkipped(skipped.filter((x) => x !== r))}>
                  ✕
                </button>
              </span>
            ))}
          </div>
        )}
        <div className="row" style={{ gap: 16 }}>
          <label className="row small" style={{ gap: 6 }}>
            <input type="checkbox" checked={untagged} onChange={(e) => setUntagged(e.target.checked)} disabled={locked} />
            태그 없는 이미지(dangling)도 포함
          </label>
          <label className="row small" style={{ gap: 6 }} title={external ? '외부 저장소는 공간 회수를 하지 않습니다' : undefined}>
            <input type="checkbox" checked={!external && gc} onChange={(e) => setGc(e.target.checked)} disabled={locked || external} />
            끝나면 저장소 공간 회수(GC)까지 실행 <span className="muted">· 내장 저장소만 · 외부면 꺼짐</span>
          </label>
        </div>
        <div className="inset col small" style={{ gap: 4 }}>
          <b>항상 남기는 것</b>
          <span className="muted">
            쓰는 이미지(실행 중인 앱 · 자동 배포 후보 · 되돌리기용 앞 버전 · 단독 컨테이너) · 내린 앱의 app.yaml이 가리키는 이미지 · 다른 이미지가 참조하는 이미지 · 제외 패턴에 맞는 태그. 실행
            직전에 쓰이기 시작한 이미지는 서버가 건너뜁니다.
          </span>
        </div>
        {m.op?.state === 'applied' ? (
          <PruneProgress tenant={tenant} op={m.op} status={mt.status} />
        ) : cur?.error !== undefined ? (
          expired ? <div className="note wa small">미리 보기가 만료됐거나 그 사이 저장소가 바뀌었습니다. 새 미리 보기를 받으세요.</div> : <MutationError error={cur.error} />
        ) : !p ? (
          <span className="muted small">{noneLeft ? '이미지 이름을 모두 뺐습니다. 하나 이상 다시 넣으세요.' : badPattern ? '제외 패턴을 고치면 미리 보기를 받습니다.' : '미리 보기를 받는 중…'}</span>
        ) : (
          <>
            <div className="col" style={{ gap: 2 }}>
              <b>
                미리 보기: 지울 것 {p.items}개 · {fmtBytes(p.imageBytes)} · 남기는 것 {p.retained}개
              </b>
              <span className="muted small">
                {p.estimateKnown ? `예상 회수 ${fmtBytes(p.estimatedReclaimedBytes)}(공유 레이어 때문에 더 적을 수 있음)` : '예상 회수량은 끝나야 압니다'}
                {p.live ? ' · 외부 목록은 그 사이 바뀔 수 있음' : ''}
                {p.expiresAt ? ` · 이 미리 보기는 ${new Date(p.expiresAt).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' })}까지 유효` : ''}
              </span>
            </div>
            <div className="segmented" role="radiogroup" aria-label="미리 보기 나누기" style={{ width: 'fit-content' }}>
              {(
                [
                  ['items', `지울 것 ${p.items}`],
                  ['retained', `남기는 것 ${p.retained}`],
                ] as const
              ).map(([k, label]) => (
                <button key={k} type="button" role="radio" aria-checked={part === k} className={part === k ? 'on' : ''} onClick={() => setPart(k)}>
                  {label}
                </button>
              ))}
            </div>
            {part === 'items' ? (
              p.items === 0 ? (
                <Empty kind="filtered" title="이 조건으로 지울 이미지가 없습니다" />
              ) : (
                <div className="table-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th style={{ width: 36 }} />
                        <th>이미지</th>
                        <th style={{ width: 110 }}>크기</th>
                        <th style={{ width: 120 }}>올린 시각</th>
                        <th style={{ width: 120 }}>같은 이미지 태그</th>
                      </tr>
                    </thead>
                    <tbody>
                      {shown.flatMap((pg) => pg.rows).map((r) => (
                        <tr key={r.id}>
                          <td>
                            <input
                              type="checkbox"
                              checked
                              disabled={locked}
                              title={`${r.image.repository}의 이미지를 모두 이번 정리에서 뺍니다`}
                              aria-label={`${r.image.repository} 이번 정리에서 빼기`}
                              onChange={() => (setSkipped([...new Set([...skipped, r.image.repository])].sort()), setTyped(''))}
                            />
                          </td>
                          <td className="mono">{imgName(r.image)}</td>
                          <td>{fmtBytes(r.image.imageBytes)}</td>
                          <td className="muted">{agoIso(r.image.uploadedAt)}</td>
                          <td className="muted">{r.aliases > 1 ? `${r.aliases}개 함께` : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            ) : !cur?.pages.retained ? (
              <span className="muted small">남기는 것을 받는 중…</span>
            ) : (
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>이미지</th>
                      <th style={{ width: 200 }}>남기는 까닭</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.flatMap((pg) => pg.retainedRows).map((r, i) => (
                      <tr key={`${r.image.repository}/${r.image.reference}/${i}`}>
                        <td className="mono">{imgName(r.image)}</td>
                        <td>
                          <Badge tone={r.code === 'image-in-use' ? 'ok' : r.code === 'protected' ? 'pr' : 'un'}>{RETAIN[r.code] ?? r.code}</Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {lastShown?.next && (
              <button className="linkish small" style={{ width: 'fit-content' }} onClick={() => void load(part, lastShown.next)}>
                더 보기 ({shown.reduce((a, pg) => a + (part === 'items' ? pg.rows.length : pg.retainedRows.length), 0)} / {part === 'items' ? p.items : p.retained})
              </button>
            )}
            {pageErr !== undefined && !expired && <MutationError error={pageErr} />}
          </>
        )}
        {busyErr ? <div className="note wa small">저장소에 다른 작업이 진행 중입니다. 끝난 뒤 새 미리 보기로 다시 하세요.</div> : !expired && <MutationError error={m.error} />}
        {m.op && m.op.state !== 'applied' && <OpPanel op={m.op} onChange={(o) => m.setOp(o)} />}
      </div>
    </Dialog>
  );
}
/** 정리 진행과 항목별 결과(registry-maintenance/web-<opId>/items) */
function PruneProgress({ tenant, op, status }: { tenant: string; op: OpView; status?: DMaintenanceStatus }) {
  const sum = status?.result?.prune;
  const done = status?.state === 'done' || status?.state === 'failed';
  const [pages, setPages] = useState<PrunePage[]>([]);
  const [err, setErr] = useState<unknown>();
  const load = async (after?: string) => {
    try {
      const r = await pruneResults(tenant, op.id, after);
      setPages((x) => (after ? [...x, r] : [r]));
    } catch (e) {
      setErr(e);
    }
  };
  useEffect(() => {
    if (done) void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [done]);
  const rows = pages.flatMap((p) => p.rows);
  const last = pages[pages.length - 1];
  return (
    <div className="col" style={{ gap: 8 }}>
      <KV
        items={[
          ['상태', <MaintBadge key="s" s={status} />],
          ...(sum
            ? ([
                ['처리', `${sum.processed}개 중 지움 ${sum.deleted} · 건너뜀 ${sum.skipped} · 실패 ${sum.failed}`],
                ...(sum.gcCode ? ([['공간 회수', `${resultText(sum.gcCode)}${status?.result?.reclaimedBytes ? ` · ${fmtBytes(status.result.reclaimedBytes)} 회수` : ''}`]] as [string, ReactNode][]) : []),
              ] as [string, ReactNode][])
            : []),
          ...(status?.result && status.result.code !== 'ok' ? ([['결과', resultText(status.result.code)]] as [string, ReactNode][]) : []),
        ]}
      />
      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>이미지</th>
                <th style={{ width: 220 }}>결과</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{imgName(r.image)}</td>
                  <td>
                    <Badge tone={r.code === 'ok' || r.code === 'already-absent' ? 'ok' : r.code ? 'wa' : 'un'}>{r.code ? resultText(r.code) : '처리 전'}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {last?.next && (
        <button className="linkish small" style={{ width: 'fit-content' }} onClick={() => void load(last.next)}>
          더 보기
        </button>
      )}
      {err !== undefined && <MutationError error={err} />}
    </div>
  );
}

/** 휴대폰 이미지 목록 (UI-M11 ③ 모양): 저장소마다 이미지 카드, 태그 · 크기 */
export function MImageList() {
  const { q } = useCatalog();
  const groups = q.data ?? [];
  const imgs = groups.flatMap((g) => (g.page?.items ?? []).map((i) => ({ g, i })));
  const bytes = [...new Map(imgs.map((x) => [`${x.g.reg.id}@${x.i.digest}`, x.i.bytes])).values()].reduce((a, b) => a + b, 0);
  const bad = groups.filter((g) => g.error || g.page?.code).length;
  return (
    <Load q={q} what="이미지 목록을 불러오지 못했습니다">
      {() => (
        <>
          <MTiles
            items={[
              { label: '이미지', value: imgs.length, sub: `저장소 ${groups.length}곳${bad ? ` · 읽기 실패 ${bad}` : ''}`, warn: bad > 0 },
              { label: '크기', value: fmtBytes(bytes), sub: '같은 이미지는 한 번만 셈' },
            ]}
          />
          <MCards
            empty="이미지가 없습니다."
            items={imgs.map(({ g, i }) => ({
              key: `${g.reg.id}/${i.repository}@${i.digest}`,
              title: i.repository,
              badge: g.external ? ['un', '외부'] : ['ok', '내장'],
              lines: [i.tags.length ? i.tags.join(', ') : '태그 없음', `${fmtBytes(i.bytes)} · ${g.reg.id}${i.pushedAt ? ` · ${agoMs(i.pushedAt)}` : ''}`],
              meta: <span className="mono">{i.digest.replace(/^(sha256:.{8}).*/, '$1…')}</span>,
            }))}
          />
        </>
      )}
    </Load>
  );
}
