// SPDX-License-Identifier: Apache-2.0

// 보관된 앱(UI-36·37) + 내린 앱 저장소의 데이터 보관·되살리기(#920, 캔버스 ArchivedApps·ArchivedAppsIx).

import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, ApiError, newOpId } from '../api/client';
import type { DOp, DVolumeArchive } from '../api/dto';
import { archived as fetchArchived, archivedSource, purgeArchived, tenantStorage, toOp, usableRoot, volumeArchivePath, volumeDetail, volumePath } from '../api/endpoints';
import type { ArchivedApp, OpView, Page, StorageRoot, VolumeView } from '../api/types';
import { useTenantRole } from '../auth/session';
import { CodeView } from '../components/Code';
import { ConfirmDialog, Dialog } from '../components/Dialog';
import { Drawer } from '../components/Drawer';
import { Menu } from '../components/Menu';
import { MutationError } from '../components/OpPanel';
import { Refresh } from '../components/Refresh';
import { StepsDialog, type Step } from '../components/StepsDialog';
import { Empty, ErrorBand, Load, errorLine } from '../components/states';
import { useToast } from '../components/Toast';
import { Badge, HelpBox, OpBadge, PageHeader } from '../components/ui';
import { fmtBytes, fmtDate } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { archivedLive } from '../lib/liveTopics';
import { ARCHIVE_BUSY, ARCHIVE_PHASE, archiveFailure, archiveIdProblem, canArchive, currentArchive, restoreState } from './archiveText';
import { DeployTabs, NoTenant } from './Deploy';

/** 남은 데이터 저장소 한 줄 */
export interface VolLine {
  name: string;
  vol?: VolumeView;
  archive?: DVolumeArchive;
  /** 저장소가 이미 없다(지웠거나 다른 이름으로 되살림) */
  gone?: boolean;
  error?: unknown;
}
interface Row extends ArchivedApp {
  lines: VolLine[];
}
interface Data {
  page: Page<ArchivedApp>;
  rows: Row[];
  /** 클러스터 키와 관리자 키가 둘 다 있다. 저장소가 없어 모르면 참 */
  ready: boolean;
}

async function loadLines(t: string, a: ArchivedApp, signal: AbortSignal): Promise<{ lines: VolLine[]; ready: boolean }> {
  let ready = true;
  const lines = await Promise.all(
    a.volumes.map(async (name): Promise<VolLine> => {
      try {
        const d = await volumeDetail(t, name, a.app, signal);
        if (!d.archiveReady) ready = false;
        return { name, vol: d.volume, archive: currentArchive(d.volume.archiveId, d.archives) };
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) return { name, gone: true };
        if ((e as Error)?.name === 'AbortError') throw e;
        return { name, error: e };
      }
    }),
  );
  return { lines, ready };
}

const busyLine = (l: VolLine) => !!l.archive && ARCHIVE_BUSY.has(l.archive.phase);
const archivedLine = (l: VolLine) => l.archive?.phase === 'Archived';
const appBody = (app: string) => ({ app });

async function sendOp(path: string, body: Record<string, unknown>, method: 'POST' | 'DELETE', opId = newOpId()): Promise<{ op: DOp }> {
  const send = method === 'DELETE' ? api.del : api.post;
  return send<{ op: DOp }>(path, { ...body, opId });
}

/** 단계가 끝날 때까지 저장소 상세를 다시 읽는다(최대 2분). 완전 삭제가 보관본 지우기 뒤 저장소를 지우기 전에 쓴다 */
async function waitArchive(t: string, name: string, app: string, id: string, until: string[]): Promise<void> {
  const end = Date.now() + 120_000;
  for (;;) {
    const d = await volumeDetail(t, name, app);
    const a = d.archives.find((x) => x.id === id);
    if (!a || until.includes(a.phase)) return;
    if (Date.now() > end) throw new Error(`${name}: 보관 단계가 ${a.phase}에서 끝나지 않았습니다. 잠시 뒤 다시 보내세요.`);
    await new Promise((r) => setTimeout(r, 1500));
  }
}

export function ArchivedAppsPage() {
  const { tenant, canDeploy, isAdmin } = useTenantRole();
  const navigate = useNavigate();
  const toast = useToast();
  const q = usePoll(
    async (signal): Promise<Data> => {
      if (!tenant) return { page: { items: [], next: '', revision: 0, asOf: new Date().toISOString() }, rows: [], ready: true };
      const page = await fetchArchived(tenant, signal);
      let ready = true;
      const rows = await Promise.all(
        page.items.map(async (a) => {
          const r = await loadLines(tenant, a, signal);
          if (!r.ready) ready = false;
          return { ...a, lines: r.lines };
        }),
      );
      return { page, rows, ready };
    },
    [tenant],
    0,
    archivedLive(tenant),
  );
  // 보관 저장 경로: 관리 권한이 없으면 403이라 비워 두고 '서버 기본'만 보인다
  const roots = usePoll((s) => (tenant && canDeploy ? tenantStorage(tenant, s).then((p) => p.items).catch(() => [] as StorageRoot[]) : Promise.resolve([] as StorageRoot[])), [tenant, canDeploy]);
  const [yamlOf, setYamlOf] = useState<Row>();
  const [archiveOne, setArchiveOne] = useState<{ row: Row; line: VolLine }>();
  const [archiveAll, setArchiveAll] = useState<Row>();
  const [cancelOf, setCancelOf] = useState<{ row: Row; line: VolLine }>();
  const [restoreOf, setRestoreOf] = useState<Row>();
  const [purgeOf, setPurgeOf] = useState<Row>();
  const [purgeSteps, setPurgeSteps] = useState<{ row: Row; steps: Step[] }>();

  const data = q.data;
  const anyBusy = !!data?.rows.some((r) => r.lines.some(busyLine));
  // 서버가 일하는 동안(묶기·비우기·되살리기)과 다시 올리기 창이 열린 동안 3초마다 다시 읽는다
  const fast = anyBusy || !!restoreOf;
  useEffect(() => {
    q.setInterval(fast ? 3000 : 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fast]);
  const live = (r: Row | undefined) => (r ? data?.rows.find((x) => x.key === r.key) ?? r : undefined);
  const ready = data?.ready !== false;
  const archiveTitle = !canDeploy ? '배포 권한이 필요합니다' : !ready ? '관리자 키가 등록되지 않아 보관할 수 없습니다' : undefined;

  const reup = async (r: Row, rename = false) => {
    try {
      const yaml = await archivedSource(tenant, r.key);
      navigate('/deploy/new', { state: { yaml, from: `보관된 앱 ${r.app} 버전 ${r.version}${rename ? ' (다른 이름으로)' : ''}` } });
    } catch (e) {
      toast(`app.yaml을 읽지 못했습니다: ${errorLine(e)}`);
    }
  };
  const startReup = (r: Row) => (r.lines.some(archivedLine) || r.lines.some((l) => l.archive?.phase === 'Restoring') ? setRestoreOf(r) : void reup(r));

  const purgeDefinition = async (r: Row) => {
    try {
      await purgeArchived(tenant, r.key, r.app);
      toast(`보관된 앱 ${r.app}을(를) 완전히 지웠습니다.`);
    } catch (e) {
      toast(`보관된 정의를 지우지 못했습니다: ${errorLine(e)}`);
    }
    q.refresh();
  };

  return (
    <>
      <PageHeader title="배포" ids="UI-36 · UI-37" actions={<Refresh q={q} poll={false} />} />
      <DeployTabs archivedCount={data?.rows.length} />
      <HelpBox terms="보관된 앱 (웹 UI가 저장한 내린 앱의 정의, 클러스터에는 없음) · 데이터 보관 (내린 앱의 데이터 저장소를 압축·봉인해 같은 서버의 보관 위치에 두고 원래 자리를 비움) · 보관 위치 (보관본을 두는 저장 경로) · 다시 올리기 (보관된 데이터를 먼저 되살린 뒤 보관된 app.yaml로 새로 배포) · 완전 삭제 (보관된 정의를 지움, 되돌릴 수 없음)">
        <b>이 탭은</b> 내린 앱의 정의(app.yaml)와 남은 데이터를 보관하는 곳입니다. 앱을 내리면 클러스터에서는 정의가 지워지지만, 웹 UI가 내리기 직전의 app.yaml을 따로 저장해 둡니다. 남은 데이터 저장소는 원래 서버의 원래 자리에 그대로 남고, ‘데이터 보관’을 누르면 압축·봉인해 보관 위치로 옮기고 원래 자리를 비웁니다. 여기서 다시 올리거나, 더 필요 없으면 완전 삭제합니다.
      </HelpBox>
      {!tenant ? (
        <NoTenant />
      ) : (
        <Load q={q}>
          {(d) =>
            d.rows.length === 0 ? (
              <Empty title="보관된 앱이 없습니다">앱을 내리면 여기에 원문이 남습니다.</Empty>
            ) : (
              <>
                {!d.ready && (
                  <div className="bn warn" role="note">
                    데이터 보관을 쓰려면 관리자 키가 필요합니다. 시스템 관리자가 서버에서 <code>sfcli volume archive admin-key --key-file 키파일</code>로 등록하세요. 등록하기 전에도 남은 데이터는 원래 자리에 그대로 있습니다.
                  </div>
                )}
                <section className="card flush">
                  <div className="card-head">
                    <h2>보관된 앱</h2>
                  </div>
                  <div style={{ overflowX: 'auto' }}>
                  <table className="tbl archived-apps">
                    <thead>
                      <tr>
                        <th>앱</th>
                        <th>배포 구성 · 버전</th>
                        <th>내린 때</th>
                        <th>남은 데이터 (저장소 · 서버 · 상태)</th>
                        <th aria-label="더보기" />
                      </tr>
                    </thead>
                    <tbody>
                      {d.rows.map((r) => (
                        <AppRow
                          key={r.key}
                          tenant={tenant}
                          row={r}
                          canDeploy={canDeploy}
                          isAdmin={isAdmin}
                          archiveTitle={archiveTitle}
                          onYaml={() => setYamlOf(r)}
                          onArchive={(line) => setArchiveOne({ row: r, line })}
                          onArchiveAll={() => setArchiveAll(r)}
                          onCancel={(line) => setCancelOf({ row: r, line })}
                          onReup={() => startReup(r)}
                          onRename={() => void reup(r, true)}
                          onPurge={() => setPurgeOf(r)}
                        />
                      ))}
                    </tbody>
                  </table>
                  </div>
                </section>
                <p className="small muted">
                  보관된 정의는 이 웹 UI에만 저장됩니다(CLI에서는 보이지 않음). 작업 공간 구성원 중 읽기 권한이 있으면 볼 수 있고, 다시 올리기와 데이터 보관은 배포 권한이 필요합니다. 데이터 보관은 내릴 때 저절로 되지 않고, 누를 때만 합니다. 보관본은 같은 서버에만 있어 그 서버를 잃으면 함께 잃습니다.
                </p>
              </>
            )
          }
        </Load>
      )}
      {yamlOf && <YamlDrawer tenant={tenant} row={yamlOf} onClose={() => setYamlOf(undefined)} />}
      {archiveOne && (
        <ArchiveDialog
          tenant={tenant}
          row={archiveOne.row}
          line={archiveOne.line}
          roots={roots.data ?? []}
          onClose={() => setArchiveOne(undefined)}
          onDone={() => {
            setArchiveOne(undefined);
            toast(`${archiveOne.line.name} 보관을 시작했습니다.`);
            q.refresh();
          }}
        />
      )}
      {archiveAll && <ArchiveAllDialog tenant={tenant} row={archiveAll} roots={roots.data ?? []} onClose={() => (setArchiveAll(undefined), q.refresh())} onDone={() => q.refresh()} />}
      {cancelOf && <CancelDialog tenant={tenant} row={cancelOf.row} line={cancelOf.line} onClose={() => setCancelOf(undefined)} onDone={() => (setCancelOf(undefined), q.refresh())} />}
      {restoreOf && <RestoreDialog tenant={tenant} row={live(restoreOf)!} onClose={() => setRestoreOf(undefined)} onRefresh={q.refresh} onDeploy={(r) => (setRestoreOf(undefined), void reup(r))} />}
      {purgeOf && (
        <PurgeDialog
          row={live(purgeOf)!}
          onClose={() => setPurgeOf(undefined)}
          onConfirm={(withData) => {
            const r = live(purgeOf)!;
            setPurgeOf(undefined);
            const steps = withData ? purgeVolumeSteps(tenant, r) : [];
            if (steps.length === 0) void purgeDefinition(r);
            else setPurgeSteps({ row: r, steps });
          }}
        />
      )}
      {purgeSteps && (
        <StepsDialog
          title={`${purgeSteps.row.app} 완전 삭제`}
          steps={purgeSteps.steps}
          action="남은 데이터 지우고 완전 삭제"
          intro={<p className="small">남은 데이터를 먼저 지운 뒤 보관된 정의를 지웁니다. 데이터 저장소 삭제는 클러스터 작업으로 따로 제출되고 작업 기록에 남습니다.</p>}
          onClose={() => (setPurgeSteps(undefined), q.refresh())}
          onDone={() => {
            const r = purgeSteps.row;
            setPurgeSteps(undefined);
            void purgeDefinition(r);
          }}
        />
      )}
    </>
  );
}

function AppRow({
  tenant,
  row,
  canDeploy,
  isAdmin,
  archiveTitle,
  onYaml,
  onArchive,
  onArchiveAll,
  onCancel,
  onReup,
  onRename,
  onPurge,
}: {
  tenant: string;
  row: Row;
  canDeploy: boolean;
  isAdmin: boolean;
  archiveTitle?: string;
  onYaml: () => void;
  onArchive: (l: VolLine) => void;
  onArchiveAll: () => void;
  onCancel: (l: VolLine) => void;
  onReup: () => void;
  onRename: () => void;
  onPurge: () => void;
}) {
  const archivable = row.lines.filter((l) => l.vol && canArchive(l.archive));
  const packing = row.lines.some((l) => l.archive && ['Packing', 'Clearing', 'Cancelling'].includes(l.archive.phase));
  const reupTitle = !canDeploy ? '배포 권한이 필요합니다' : packing ? '보관 중인 저장소가 끝날 때까지 기다리세요' : undefined;
  const purgeTitle = isAdmin ? undefined : '시스템 관리자만 완전 삭제합니다';
  return (
    <tr>
      <td>
        <b>{row.app}</b>
      </td>
      <td>
        main · 버전 {row.version}
      </td>
      <td>
        {fmtDate(row.downAt)} · {row.downBy}
      </td>
      <td>
        <div className="col" style={{ gap: 8 }}>
          {row.lines.length === 0 ? (
            <span className="muted">없음</span>
          ) : (
            row.lines.map((l) => <VolumeLine key={l.name} line={l} archiveTitle={archiveTitle} onArchive={() => onArchive(l)} onCancel={() => onCancel(l)} canDeploy={canDeploy} />)
          )}
          <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
            <button type="button" className="btn sm" onClick={onYaml}>
              app.yaml 보기
            </button>
            <button type="button" className="btn sm primary" disabled={!!reupTitle} title={reupTitle} onClick={onReup}>
              다시 올리기
            </button>
            {archivable.length > 1 && (
              <button type="button" className="btn sm" disabled={!!archiveTitle} title={archiveTitle} onClick={onArchiveAll}>
                남은 데이터 모두 보관…
              </button>
            )}
            <button type="button" className="btn sm danger" disabled={!!purgeTitle} title={purgeTitle} onClick={onPurge}>
              완전 삭제
            </button>
          </div>
        </div>
      </td>
      <td>
        <Menu
          items={[
            { label: 'app.yaml 보기', onSelect: onYaml },
            { label: '내려받기', onSelect: () => void download(tenant, row) },
            { label: '다른 이름으로 새 배포', onSelect: onRename, disabledReason: canDeploy ? undefined : '배포 권한이 필요합니다' },
            { sep: true, label: '' },
            { label: '완전 삭제…', danger: true, onSelect: onPurge, disabledReason: purgeTitle },
          ]}
        />
      </td>
    </tr>
  );
}

async function download(tenant: string, row: Row) {
  const yaml = await archivedSource(tenant, row.key);
  const url = URL.createObjectURL(new Blob([yaml], { type: 'application/yaml' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `${row.app}-v${row.version}.yaml`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function VolumeLine({ line: l, archiveTitle, canDeploy, onArchive, onCancel }: { line: VolLine; archiveTitle?: string; canDeploy: boolean; onArchive: () => void; onCancel: () => void }) {
  const a = l.archive;
  const node = l.vol?.node ?? a?.node ?? '';
  const head = (
    <>
      <code>{l.name}</code>
      {node && <span className="muted">{node}</span>}
    </>
  );
  if (l.gone)
    return (
      <div className="row" style={{ gap: 8 }}>
        {head}
        <Badge tone="un">지워짐</Badge>
      </div>
    );
  if (l.error !== undefined)
    return (
      <div className="row" style={{ gap: 8 }}>
        {head}
        <span className="small er-text">{errorLine(l.error)}</span>
      </div>
    );
  const phase = a ? ARCHIVE_PHASE[a.phase] : undefined;
  const used = l.vol?.usedBytes;
  if (a && phase && a.phase !== 'Failed') {
    return (
      <div className="col" style={{ gap: 2 }}>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          {head}
          <Badge tone={phase[0]}>{phase[1]}</Badge>
          {a.phase === 'Archived' && (
            <span className="small">
              {fmtBytes(a.tarBytes ?? used)} → {fmtBytes(a.dataBytes)} · {a.compression === 'none' ? '압축 없음' : a.compression}
            </span>
          )}
          {a.phase === 'Packing' && (
            <button type="button" className="btn sm" disabled={!canDeploy} title={canDeploy ? undefined : '배포 권한이 필요합니다'} onClick={onCancel}>
              취소…
            </button>
          )}
        </div>
        {a.phase === 'Archived' && (
          <span className="small muted">
            보관 위치 {a.node} · {a.store}
          </span>
        )}
        {a.phase === 'Archived' && a.failure && <span className="small er-text">되살리지 못했습니다: {archiveFailure(a.failure).text}</span>}
      </div>
    );
  }
  const failed = a?.phase === 'Failed' ? archiveFailure(a.failure) : undefined;
  return (
    <div className="col" style={{ gap: 2 }}>
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        {head}
        {failed ? (
          <Badge tone="er" title={a?.failure}>
            보관하지 못함 · {failed.title}
          </Badge>
        ) : (
          <Badge tone="tag">원래 자리</Badge>
        )}
        <span className="small">{fmtBytes(used)}</span>
        {canArchive(a) && (
          <button type="button" className="btn sm" disabled={!!archiveTitle} title={archiveTitle} onClick={onArchive}>
            데이터 보관…
          </button>
        )}
      </div>
      {failed && <span className="small er-text">{failed.text}</span>}
    </div>
  );
}

function YamlDrawer({ tenant, row, onClose }: { tenant: string; row: Row; onClose: () => void }) {
  const src = usePoll((s) => archivedSource(tenant, row.key, s), [tenant, row.key]);
  return (
    <Drawer
      title={
        <>
          {row.app} · 버전 {row.version} (보관됨)
        </>
      }
      onClose={onClose}
    >
      <span className="small muted">
        {fmtDate(row.downAt)} {row.downBy}가 내림
      </span>
      <Load q={src}>{(text) => <CodeView text={text} />}</Load>
      <div className="row">
        <button type="button" className="btn sm" disabled={!src.data} onClick={() => void navigator.clipboard?.writeText(src.data ?? '')}>
          복사
        </button>
        <button type="button" className="btn sm" onClick={() => void download(tenant, row)}>
          내려받기
        </button>
      </div>
    </Drawer>
  );
}

/** 그 서버의 보관 위치 후보. '' = 서버 기본(그 서버의 기본 보관 위치, 없으면 default) */
function storeOptions(roots: StorageRoot[], node: string) {
  const mine = roots.filter((r) => r.node === node && usableRoot(r));
  const def = mine.find((r) => r.archiveDefault);
  const defLabel = def ? `서버 기본 · ${def.name} (기본 보관 위치)` : mine.some((r) => r.name === 'default') ? '서버 기본 · default 저장 경로' : '서버 기본';
  return [{ value: '', label: defLabel }, ...mine.filter((r) => r !== def).map((r) => ({ value: r.name, label: `${r.name} · ${r.path}` }))];
}

function useSend() {
  const [op, setOp] = useState<OpView>();
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [opId, setOpId] = useState(newOpId);
  const send = async (path: string, body: Record<string, unknown>, method: 'POST' | 'DELETE' = 'POST') => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await sendOp(path, body, method, opId);
      const v = toOp(r.op);
      setOp(v);
      // 거절·실패면 다음 시도는 새 opId, 결과 모름이면 같은 opId로 이어 간다
      if (v.state === 'failed' || v.state === 'rejected') setOpId(newOpId());
      return v;
    } catch (e) {
      setError(e);
      if (e instanceof ApiError && e.status < 500) setOpId(newOpId());
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { op, error, busy, opId, send };
}

function ArchiveDialog({ tenant, row, line, roots, onClose, onDone }: { tenant: string; row: Row; line: VolLine; roots: StorageRoot[]; onClose: () => void; onDone: () => void }) {
  const node = line.vol?.node ?? '';
  const opts = useMemo(() => storeOptions(roots, node), [roots, node]);
  const [store, setStore] = useState('');
  const [compress, setCompress] = useState(true);
  const [id, setId] = useState('');
  const m = useSend();
  const idErr = archiveIdProblem(id.trim());
  const start = async () => {
    const body: Record<string, unknown> = { app: row.app, compress };
    if (store) body.store = store;
    if (id.trim()) body.id = id.trim();
    const v = await m.send(`${volumePath(tenant, line.name)}/archive`, body);
    if (v?.state === 'applied') onDone();
  };
  return (
    <Dialog
      title={`${line.name} 데이터 보관`}
      onClose={onClose}
      width={560}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn primary" disabled={m.busy || !!idErr} onClick={() => void start()}>
            보관 시작
          </button>
        </>
      }
    >
      <p>
        내린 앱 {row.app}의 데이터 저장소 <code>{line.name}</code> ({node}, {fmtBytes(line.vol?.usedBytes)})를 압축·봉인해 보관 위치에 두고, 다시 읽어 확인한 뒤 원래 자리를 비웁니다.
      </p>
      <label className="field">
        <span>보관 위치 ({node}의 저장 경로)</span>
        <select value={store} onChange={(e) => setStore(e.target.value)}>
          {opts.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <span className="hint">서버 기본은 그 서버의 기본 보관 위치, 없으면 같은 서버의 default 저장 경로입니다. 같은 서버의 저장 경로만 고를 수 있습니다. 압축하면 줄어든 만큼 공간이 빕니다.</span>
      </label>
      <label className="check" style={{ alignItems: 'flex-start' }}>
        <input type="checkbox" checked={compress} onChange={(e) => setCompress(e.target.checked)} />
        <span>
          압축하기
          <br />
          <span className="small muted">zstd. 보통 크기가 1/2~1/4로 줄고 묶는 시간이 조금 늘어납니다. 끄면 압축 없이 봉인만 합니다.</span>
        </span>
      </label>
      <label className="field">
        <span>보관 이름</span>
        <input value={id} onChange={(e) => setId(e.target.value)} placeholder={`a-${m.opId.slice(0, 8)}…`} aria-invalid={!!idErr} />
        <span className={idErr ? 'error' : 'hint'}>{idErr ?? '비우면 a-작업번호. 소문자로 시작, 소문자·숫자·-'}</span>
      </label>
      <div className="note info small">보관하는 동안과 보관한 뒤에는 이 저장소를 붙일 수 없습니다. 다시 올리면 먼저 같은 자리로 되살린 뒤 배포합니다. 보관본은 클러스터 키와 관리자 키로 봉인됩니다.</div>
      {m.op && m.op.state !== 'applied' && (
        <div className="row small" style={{ gap: 8 }}>
          <OpBadge state={m.op.state} /> 보관이 적용되지 않았습니다. 작업 기록에서 이유를 보세요.
        </div>
      )}
      <MutationError error={m.error} />
    </Dialog>
  );
}

function ArchiveAllDialog({ tenant, row, roots, onClose, onDone }: { tenant: string; row: Row; roots: StorageRoot[]; onClose: () => void; onDone: () => void }) {
  const lines = row.lines.filter((l) => l.vol && canArchive(l.archive));
  const skipped = row.lines.filter((l) => !lines.includes(l));
  const [stores, setStores] = useState<Record<string, string>>({});
  const [compress, setCompress] = useState(true);
  const [steps, setSteps] = useState<Step[]>();
  if (steps)
    return (
      <StepsDialog
        title={`${row.app}의 남은 데이터 모두 보관`}
        steps={steps}
        action={`${steps.length}개 보관 시작`}
        intro={<p className="small">저장소마다 보관을 따로 보냅니다. 보내고 나면 보관된 앱 줄에 단계가 보입니다.</p>}
        onClose={onClose}
        onDone={onDone}
      />
    );
  const begin = () =>
    setSteps(
      lines.map((l) => ({
        key: l.name,
        label: `${l.name} 보관 · ${l.vol?.node ?? ''}`,
        send: (opId: string) => sendOp(`${volumePath(tenant, l.name)}/archive`, { app: row.app, compress, ...(stores[l.name] ? { store: stores[l.name] } : {}) }, 'POST', opId),
      })),
    );
  return (
    <Dialog
      title={`${row.app}의 남은 데이터 모두 보관`}
      onClose={onClose}
      width={720}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn primary" disabled={lines.length === 0} onClick={begin}>
            {lines.length}개 보관 시작
          </button>
        </>
      }
    >
      <table className="tbl">
        <thead>
          <tr>
            <th>저장소</th>
            <th>서버</th>
            <th>사용량</th>
            <th>보관 위치</th>
          </tr>
        </thead>
        <tbody>
          {lines.map((l) => (
            <tr key={l.name}>
              <td>
                <code>{l.name}</code>
              </td>
              <td>{l.vol?.node}</td>
              <td>{fmtBytes(l.vol?.usedBytes)}</td>
              <td>
                <select aria-label={`${l.name} 보관 위치`} value={stores[l.name] ?? ''} onChange={(e) => setStores({ ...stores, [l.name]: e.target.value })}>
                  {storeOptions(roots, l.vol?.node ?? '').map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <label className="check">
        <input type="checkbox" checked={compress} onChange={(e) => setCompress(e.target.checked)} />
        <span>
          압축하기 <span className="small muted">zstd · 끄면 봉인만</span>
        </span>
      </label>
      <span className="small muted">이미 보관됐거나 보관 중인 저장소, 정상 종료하지 않은 저장소는 빠집니다.</span>
      {skipped.length > 0 && <span className="small muted">빠진 저장소: {skipped.map((l) => l.name).join(', ')}</span>}
    </Dialog>
  );
}

function CancelDialog({ tenant, row, line, onClose, onDone }: { tenant: string; row: Row; line: VolLine; onClose: () => void; onDone: () => void }) {
  const m = useSend();
  const a = line.archive!;
  const cancel = async () => {
    const v = await m.send(`${volumeArchivePath(tenant, line.name, a.id)}/cancel`, appBody(row.app));
    if (v?.state === 'applied') onDone();
  };
  return (
    <Dialog
      title={`${line.name} 보관을 취소할까요?`}
      onClose={onClose}
      width={420}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            계속 보관
          </button>
          <button type="button" className="btn danger" disabled={m.busy} onClick={() => void cancel()}>
            보관 취소
          </button>
        </>
      }
    >
      <p>쓰던 보관본을 지우고 저장소를 원래 상태로 둡니다. 원래 자리의 데이터는 아직 그대로입니다.</p>
      {m.op && m.op.state !== 'applied' && (
        <div className="row small" style={{ gap: 8 }}>
          <OpBadge state={m.op.state} /> 취소가 적용되지 않았습니다. 이미 원래 자리를 비우기 시작했으면 취소할 수 없습니다.
        </div>
      )}
      <MutationError error={m.error} />
    </Dialog>
  );
}

/** 다시 올리기 전 되살리기: 보관된 저장소를 모두 unarchive하고 Restored가 되면 검사·배포로 넘어간다 */
function RestoreDialog({ tenant, row, onClose, onRefresh, onDeploy }: { tenant: string; row: Row; onClose: () => void; onRefresh: () => void; onDeploy: (r: Row) => void }) {
  const [sent, setSent] = useState<Record<string, number>>({});
  const [errors, setErrors] = useState<Record<string, unknown>>({});
  const [busy, setBusy] = useState(false);
  const targets = row.lines.filter((l) => l.archive && (l.archive.phase === 'Archived' || l.archive.phase === 'Restoring' || sent[l.name] !== undefined));
  const states = targets.map((l) => restoreState(l.archive, sent[l.name] ?? (l.archive?.phase === 'Restoring' ? l.archive.revision : undefined)));
  const allDone = states.every((s) => s === 'done');
  const pending = targets.filter((_l, i) => states[i] === 'idle' || states[i] === 'failed');
  const start = async () => {
    setBusy(true);
    const nextSent = { ...sent };
    const nextErr: Record<string, unknown> = {};
    for (const l of pending) {
      try {
        const r = await sendOp(`${volumePath(tenant, l.name)}/unarchive`, { app: row.app, id: l.archive!.id }, 'POST');
        const v = toOp(r.op);
        if (v.state === 'applied') nextSent[l.name] = l.archive!.revision;
        else nextErr[l.name] = new Error(`되살리기가 적용되지 않았습니다(${v.state}). 작업 기록에서 이유를 보세요.`);
      } catch (e) {
        nextErr[l.name] = e;
      }
    }
    setSent(nextSent);
    setErrors(nextErr);
    setBusy(false);
    onRefresh();
  };
  return (
    <Dialog
      title={`${row.app} 다시 올리기`}
      onClose={onClose}
      width={560}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            닫기
          </button>
          {pending.length > 0 ? (
            <button type="button" className="btn primary" disabled={busy} onClick={() => void start()}>
              {Object.keys(sent).length ? '못 되살린 저장소 다시 되살리기' : `${pending.length}개 되살리기`}
            </button>
          ) : (
            <button type="button" className="btn primary" disabled={!allDone} onClick={() => onDeploy(row)}>
              검사하고 다시 올리기
            </button>
          )}
        </>
      }
    >
      <p className="small">보관된 저장소를 모두 같은 서버의 원래 자리로 되살린 뒤, 보관된 app.yaml(버전 {row.version})을 지금 클러스터 기준으로 검사하고 변경 미리보기를 보여 줍니다.</p>
      <div className="col" style={{ gap: 6 }}>
        {targets.map((l, i) => {
          const s = states[i];
          return (
            <div key={l.name} className="col" style={{ gap: 2 }}>
              <div className="row" style={{ gap: 8 }}>
                <code>{l.name}</code>
                <span className="muted">되살리기 · {l.archive?.node}</span>
                {s === 'done' ? <Badge tone="ok">완료</Badge> : s === 'running' ? <Badge tone="pr">되살리는 중</Badge> : s === 'failed' ? <Badge tone="er">되살리지 못함</Badge> : <Badge tone="un">대기</Badge>}
              </div>
              {s === 'failed' && <span className="small er-text">{l.name}를 되살리지 못했습니다. {archiveFailure(l.archive?.failure).text} 배포하지 않았습니다.</span>}
              {errors[l.name] !== undefined && <ErrorBand error={errors[l.name]} what="되살리기를 보내지 못했습니다" />}
            </div>
          );
        })}
      </div>
      <span className="small muted">되살린 뒤 보관본은 지워집니다. 이 창을 닫아도 계속되고, 보관된 앱 줄에 단계가 보입니다.</span>
    </Dialog>
  );
}

function PurgeDialog({ row, onClose, onConfirm }: { row: Row; onClose: () => void; onConfirm: (withData: boolean) => void }) {
  const left = row.lines.filter((l) => !l.gone);
  const [withData, setWithData] = useState(false);
  const blocked = withData && left.some((l) => l.archive && ['Clearing', 'Restoring'].includes(l.archive.phase));
  const desc = left.map((l) => (l.archive?.phase === 'Archived' ? `${l.name} 보관본 ${fmtBytes(l.archive.dataBytes)}` : l.vol?.usedBytes !== undefined ? `${l.name} ${fmtBytes(l.vol.usedBytes)}` : l.name)).join(' · ');
  return (
    <ConfirmDialog title={`${row.app}을(를) 완전히 삭제할까요?`} target={row.app} actionLabel="완전 삭제" blocked={blocked} onClose={onClose} onConfirm={() => onConfirm(withData && left.length > 0)}>
      <p>보관된 정의를 지웁니다. 되돌릴 수 없고, 이후 이 앱은 다시 올릴 수 없습니다.</p>
      {left.length > 0 && (
        <label className="check" style={{ alignItems: 'flex-start' }}>
          <input type="checkbox" checked={withData} onChange={(e) => setWithData(e.target.checked)} />
          <span>
            남은 데이터 저장소도 지우기 ({desc})
            <br />
            <span className="small muted">보관된 저장소는 보관본을 먼저 지운 뒤 저장소를 지웁니다. 묶는 중인 저장소는 보관을 취소한 뒤 지웁니다. 따로 클러스터 작업으로 제출되고 작업 기록에 남습니다.</span>
          </span>
        </label>
      )}
      {left.length > 0 && !withData && <div className="note wa small">남은 데이터 저장소는 지우지 않습니다. 필요하면 데이터 저장소 화면에서 따로 지우세요.</div>}
      {withData && left.some((l) => l.archive?.phase === 'Packing') && (
        <div className="note wa small">
          묶는 중인 저장소({left.filter((l) => l.archive?.phase === 'Packing').map((l) => l.name).join(', ')})는 보관을 취소하면 데이터가 원래 자리에 그대로 돌아옵니다. 이어서 저장소를 지울 때 그 데이터가 지워집니다.
        </div>
      )}
      {blocked && <div className="note wa small">원래 자리를 비우거나 되살리는 중인 저장소가 있습니다. 끝난 뒤 다시 지우세요.</div>}
    </ConfirmDialog>
  );
}

/** 완전 삭제의 데이터 단계: 묶는 중이면 취소 → 보관됐으면 보관본 지우기 → 저장소 지우기. 단계마다 서버가 끝내길 기다린다 */
export function purgeVolumeSteps(tenant: string, row: Row): Step[] {
  const steps: Step[] = [];
  for (const l of row.lines) {
    if (l.gone || !l.vol) continue;
    const a = l.archive;
    if (a && (a.phase === 'Packing' || a.phase === 'Cancelling')) {
      if (a.phase === 'Packing') steps.push({ key: `${l.name}/cancel`, label: `${l.name} 보관 취소`, send: (opId) => sendOp(`${volumeArchivePath(tenant, l.name, a.id)}/cancel`, appBody(row.app), 'POST', opId) });
      steps.push({
        key: `${l.name}/delete`,
        label: `${l.name} 저장소 지우기 (취소가 끝난 뒤)`,
        send: async (opId) => {
          await waitArchive(tenant, l.name, row.app, a.id, ['Cancelled', 'Failed']);
          return sendOp(volumePath(tenant, l.name), appBody(row.app), 'DELETE', opId);
        },
      });
      continue;
    }
    if (a && (a.phase === 'Archived' || a.phase === 'Discarding')) {
      if (a.phase === 'Archived') steps.push({ key: `${l.name}/discard`, label: `${l.name} 보관본 지우기 (${fmtBytes(a.dataBytes)} 돌려줌)`, send: (opId) => sendOp(volumeArchivePath(tenant, l.name, a.id), appBody(row.app), 'DELETE', opId) });
      steps.push({
        key: `${l.name}/delete`,
        label: `${l.name} 저장소 지우기 (보관본이 지워진 뒤)`,
        send: async (opId) => {
          await waitArchive(tenant, l.name, row.app, a.id, ['Discarded']);
          return sendOp(volumePath(tenant, l.name), appBody(row.app), 'DELETE', opId);
        },
      });
      continue;
    }
    steps.push({ key: `${l.name}/delete`, label: `${l.name} 저장소 지우기`, send: (opId) => sendOp(volumePath(tenant, l.name), appBody(row.app), 'DELETE', opId) });
  }
  return steps;
}
