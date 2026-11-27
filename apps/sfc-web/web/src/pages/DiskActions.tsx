// SPDX-License-Identifier: Apache-2.0

// 서버 상세 › 디스크 탭의 창 (UI-1F, 캔버스 NodeDisksIx, #689 3단계 계약).
// 포맷·마운트·마운트 풀기·기록 지우기는 이 서버의 sfcd가 실행하고 Raft를 거치지 않는다.
// 같은 opId를 다시 보내면 처음 결과를 돌려주므로, 답을 못 받은 요청만 같은 opId로 다시 보낸다.
// 저장 경로 등록만 기존 POST /nodes/{node}/storage(합의)다.
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ApiError, newOpId } from '../api/client';
import type { DBlockDisk, DBlockPart, DDiskOp, DDiskRecord, DNodeDevices } from '../api/dto';
import { diskAction, diskOperation, type DiskAction } from '../api/endpoints';
import type { StorageRoot } from '../api/types';
import { Dialog } from '../components/Dialog';
import { MutationError, OpPanel, sendOp, uncertain, useMutation } from '../components/OpPanel';
import { Field } from '../components/ui';
import { fmtBytes } from '../lib/format';
import { diskNameError, MOUNT_BASE, mountPathError, rootIdFor, rootsUnder, shortUuid, type DiskDlg } from './NodeDisks';

/** 서버가 거절한 이유 (NodeDiskCodes) */
export const DISK_CODE: Record<string, string> = {
  'system-disk': '시스템 디스크입니다. 서버에 직접 접속해 수작업으로 하세요',
  busy: '마운트돼 있거나 스왑·LVM·RAID·암호화 장치가 쓰고 있습니다',
  'storage-root': '그 위에 저장 경로가 있습니다. 저장 경로 탭에서 먼저 비우고 빼 주세요',
  changed: '화면을 본 뒤 디스크가 바뀌었습니다',
  'not-found': '그 디스크나 파티션이 지금 없습니다',
  'not-ext4': 'ext4만 마운트할 수 있습니다',
  'mount-path': '마운트 위치를 쓸 수 없습니다(다른 마운트 안이거나 비어 있지 않은 디렉터리)',
  'not-managed': 'Seafield Cluster가 마운트한 것이 아닙니다. 서버에서 직접 푸세요',
  'in-use': '열린 파일이 있어 풀지 못했습니다',
  'operation-conflict': '같은 작업 ID가 다른 요청에 쓰였습니다. 다시 해 주세요',
  tool: 'mkfs.ext4가 실패했거나 서버에 없습니다',
  io: '장치를 읽거나 쓰지 못했습니다',
  interrupted: 'sfcd가 작업 중에 멈췄습니다',
};
const ACTION_TEXT: Record<DiskAction, string> = { format: '포맷', mount: '마운트', unmount: '마운트 풀기', forget: '기록 지우기' };
/** 실패한 디스크 작업 한 줄 */
export function diskOpText(o: DDiskOp): string {
  const why = DISK_CODE[o.code ?? ''] ?? o.error ?? o.code ?? '알 수 없는 이유';
  return `${o.disk ?? ''} ${ACTION_TEXT[o.action]}${o.action === 'forget' ? '를' : '을'} 거절했습니다: ${why}${o.code === 'interrupted' && o.step ? ` (마지막 단계: ${o.step})` : ''}.`;
}

type Fail = { op?: DDiskOp; error?: unknown };
type DiskBody = Omit<Parameters<typeof diskAction>[3], 'opId'>;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** 디스크 작업 하나를 보내고 running이면 끝날 때까지 2초마다 묻는다 */
function useDiskRunner(node: string, disk: string) {
  const ids = useRef<Partial<Record<DiskAction, string>>>({});
  const alive = useRef(true);
  useEffect(() => {
    // StrictMode가 효과를 두 번 돌리므로 다시 켠다
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const [fail, setFail] = useState<Fail>();
  const run = async (action: DiskAction, body: DiskBody, onOp: (o: DDiskOp) => void): Promise<DDiskOp | undefined> => {
    setFail(undefined);
    const opId = (ids.current[action] ??= newOpId());
    try {
      let o = await diskAction(node, disk, action, { ...body, opId });
      onOp(o);
      while (o.state === 'running' && alive.current) {
        await sleep(2000);
        try {
          o = await diskOperation(node, opId);
          onOp(o);
        } catch (e) {
          // 연결이 끊기거나 서버가 다시 켜지는 중이면 같은 작업 ID로 계속 묻는다
          if (e instanceof ApiError && e.status < 500 && e.status !== 404) throw e;
        }
      }
      if (o.state === 'failed') {
        delete ids.current[action];
        setFail({ op: o });
      }
      return o;
    } catch (e) {
      if (!uncertain(e)) delete ids.current[action];
      setFail({ error: e });
      return undefined;
    }
  };
  return { run, fail };
}

/** 실패 띠. changed면 다시 읽기 */
function FailBand({ fail, onReload }: { fail?: Fail; onReload: () => void }) {
  if (!fail) return null;
  if (fail.op)
    return (
      <div className="bn err small">
        {diskOpText(fail.op)}
        {fail.op.code === 'changed' && (
          <>
            {' '}
            다시 읽고 확인해 주세요.{' '}
            <button type="button" className="btn sm" onClick={onReload}>
              다시 읽기
            </button>
          </>
        )}
      </div>
    );
  return (
    <>
      <MutationError error={fail.error} />
      {uncertain(fail.error) && <div className="note small">답을 받지 못했습니다. 다시 누르면 같은 작업 ID로 물어 결과를 이어서 봅니다(두 번 실행하지 않습니다).</div>}
    </>
  );
}

type StepState = 'wait' | 'run' | 'done' | 'fail';
function Steps({ rows }: { rows: { label: ReactNode; state: StepState; detail?: ReactNode }[] }) {
  return (
    <div className="steps-list" aria-label="진행">
      {rows.map((r, i) => (
        <div key={i}>
          <i className={r.state === 'done' ? 'ok' : r.state === 'run' ? 'pr' : r.state === 'fail' ? 'er' : ''} />
          <span>{r.label}</span>
          <span className="muted">{r.detail ?? (r.state === 'run' ? '진행 중' : '')}</span>
        </div>
      ))}
    </div>
  );
}

/** 1초마다 다시 그려 진행 중 경과를 보인다 */
function useTicker(on: boolean) {
  const [, set] = useState(0);
  useEffect(() => {
    if (!on) return;
    const t = setInterval(() => set((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [on]);
}
const elapsed = (from?: number) => (from ? `진행 중 · ${Math.max(0, Math.round((Date.now() - from) / 1000))}초` : '진행 중');

function RootCheck({ on, set, disabled, id }: { on: boolean; set: (v: boolean) => void; disabled: boolean; id: string }) {
  return (
    <Field label="저장 경로" group hint={on ? `ID ${id || '—'} · 모든 작업 공간 · 용량 한도 없음 (등록은 클러스터 합의로 남습니다)` : '나중에 ‘여기에 저장 경로 만들기…’로 만들 수 있습니다'}>
      <label className="check">
        <input type="checkbox" checked={on} disabled={disabled} onChange={(e) => set(e.target.checked)} /> 이 자리를 저장 경로로 등록
      </label>
    </Field>
  );
}

/** 포맷·마운트·저장 경로 등록을 차례로. format이 없으면(마운트…) 마운트부터 */
function useFlow(node: string, disk: string, onChanged: () => void) {
  const r = useDiskRunner(node, disk);
  const m = useMutation();
  const [fmt, setFmt] = useState<DDiskOp>();
  const [mnt, setMnt] = useState<DDiskOp>();
  const [busy, setBusy] = useState(false);
  const [at, setAt] = useState<Partial<Record<'format' | 'mount' | 'root', number>>>({});
  useTicker(busy);
  const go = async (plan: { format?: DiskBody; mount: { part: string; uuid?: string }; mountPath: string; root?: string }) => {
    setBusy(true);
    try {
      let f = fmt;
      if (plan.format && f?.state !== 'done') {
        setAt((a) => ({ ...a, format: Date.now() }));
        f = await r.run('format', plan.format, setFmt);
        if (f?.state !== 'done') return;
        onChanged();
      }
      let mo = mnt;
      if (mo?.state !== 'done') {
        setAt((a) => ({ ...a, mount: Date.now() }));
        mo = await r.run('mount', { part: f?.part ?? plan.mount.part, uuid: f?.uuid ?? plan.mount.uuid, mountPath: plan.mountPath }, setMnt);
        if (mo?.state !== 'done') return;
        onChanged();
      }
      if (plan.root && m.op?.state !== 'applied') {
        setAt((a) => ({ ...a, root: Date.now() }));
        const op = await sendOp(m, `/nodes/${encodeURIComponent(node)}/storage`, { id: plan.root, path: mo?.mountPath ?? plan.mountPath, tenants: [], allTenants: true });
        if (op?.state === 'applied') onChanged();
      }
    } finally {
      setBusy(false);
    }
  };
  const stepOf = (o: DDiskOp | undefined, failed: boolean, step?: (o: DDiskOp) => boolean): StepState => (!o ? (failed ? 'fail' : 'wait') : o.state === 'done' ? 'done' : o.state === 'failed' ? 'fail' : step && !step(o) ? 'done' : 'run');
  const rootState: StepState = !m.op ? (m.error !== undefined ? 'fail' : 'wait') : m.op.state === 'applied' ? 'done' : m.op.state === 'failed' || m.op.state === 'rejected' ? 'fail' : 'run';
  const started = !!fmt || !!mnt || busy;
  const finished = (plan: { format: boolean; root: boolean }) => (!plan.format || fmt?.state === 'done') && mnt?.state === 'done' && (!plan.root || rootState === 'done');
  return { go, fmt, mnt, m, busy, fail: r.fail, at, stepOf, rootState, started, finished };
}

function FormatDialog({ node, disk, reformat, dev, roots, onClose, onChanged, onReload }: { node: string; disk: DBlockDisk; reformat: boolean; dev: DNodeDevices; roots: StorageRoot[]; onClose: () => void; onChanged: () => void; onReload: () => void }) {
  const [name, setName] = useState('');
  const [path, setPath] = useState('');
  const [pathTouched, setPathTouched] = useState(false);
  const [root, setRoot] = useState(true);
  const [typed, setTyped] = useState('');
  const [seen] = useState(dev.observedAt);
  const f = useFlow(node, disk.name, onChanged);
  const mountPath = pathTouched ? path : name ? `${MOUNT_BASE}/${name}` : '';
  const nameErr = name && !f.started ? diskNameError(name) ?? (root && roots.some((r) => r.name === name) ? '이 서버에 같은 저장 경로 ID가 있습니다' : undefined) : undefined;
  const pathErr = mountPath && f.mnt?.state !== 'done' ? mountPathError(mountPath, dev) : undefined;
  const formatted = f.fmt?.state === 'done';
  const ready = !!name && !nameErr && !!mountPath && !pathErr && typed === disk.name && !f.busy;
  const parts = disk.parts ?? [];
  const plan = { format: true, root };
  const done = f.finished(plan);
  const meta = [disk.model, disk.serial ? `serial ${disk.serial}` : disk.wwn ? `WWN ${disk.wwn}` : '', fmtBytes(disk.size)].filter(Boolean).join(' · ');
  const send = () =>
    void f.go({
      format: { part: disk.name, serial: disk.serial || undefined, wwn: disk.wwn || undefined, size: disk.size, tableId: disk.tableID || undefined, label: name },
      mount: { part: disk.name },
      mountPath,
      root: root ? name : undefined,
    });
  return (
    <Dialog
      title={`${node} · ${disk.name} ${reformat ? '다시 포맷하고 마운트' : '포맷하고 마운트'}`}
      onClose={onClose}
      width={560}
      danger={reformat}
      footer={
        done ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              {f.started ? '닫기' : '취소'}
            </button>
            <button type="button" className={reformat ? 'btn danger solid' : 'btn primary'} disabled={!ready} onClick={send}>
              {f.busy ? '진행 중…' : f.started ? '이어서 하기' : reformat ? '지우고 포맷' : '포맷하고 마운트'}
            </button>
          </>
        )
      }
    >
      {reformat && <div className="bn err small">이 디스크의 데이터가 모두 지워집니다. 파티션 표부터 새로 만듭니다.</div>}
      {reformat && parts.length > 0 && (
        <table className="tbl">
          <thead>
            <tr>
              <th>파티션</th>
              <th>형식 · label</th>
              <th>크기</th>
              <th>사용</th>
            </tr>
          </thead>
          <tbody>
            {parts.map((p) => (
              <tr key={p.name}>
                <td className="mono">{p.name}</td>
                <td className="small">
                  {p.fsType ?? '—'}
                  {p.label ? ` · ${p.label}` : ''}
                </td>
                <td className="small">{fmtBytes(p.size)}</td>
                <td className="small">{p.space ? fmtBytes(p.space.used) : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="kv small">
        <span className="muted">디스크</span>
        <span>
          <b className="mono">{disk.name}</b> · {meta}
        </span>
        {!reformat && (
          <>
            <span className="muted">지금</span>
            <span>파일시스템 서명 없음 (빈 디스크)</span>
          </>
        )}
        <span className="muted">본 시각</span>
        <span>{new Date(seen * 1000).toLocaleTimeString('en-GB')} · 이 사이 디스크가 바뀌면 서버가 거절합니다</span>
      </div>
      <Field label="이름" error={nameErr} hint="마운트 위치와 저장 경로 이름에 씁니다 (파일시스템 label)">
        <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} placeholder="fast1" disabled={f.started} autoComplete="off" />
      </Field>
      <Field label="마운트 위치" error={pathErr} hint={`기본은 ${MOUNT_BASE}/<이름>. 다른 절대 경로도 됩니다(시스템 경로·다른 마운트 안은 안 됨)`}>
        <input className="mono" value={mountPath} onChange={(e) => (setPath(e.target.value.trim()), setPathTouched(true))} placeholder={`${MOUNT_BASE}/fast1`} disabled={f.busy || f.mnt?.state === 'done'} />
      </Field>
      <div className="note small">GPT 파티션 표를 새로 만들고 파티션 하나를 ext4로 포맷합니다. fstab은 바꾸지 않고, 서버를 켤 때 sfcd가 이 자리에 다시 마운트합니다.</div>
      <RootCheck on={root} set={setRoot} disabled={f.busy || f.rootState === 'done'} id={name} />
      {!f.started && (
        <Field label="확인을 위해 디스크 이름을 입력하세요" hint={reformat ? '모델·serial이 맞는지 한 번 더 보세요' : undefined}>
          <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value.trim())} placeholder={disk.name} autoComplete="off" spellCheck={false} />
        </Field>
      )}
      {f.started && (
        <Steps
          rows={[
            { label: '파티션 표 만들기 (GPT)', state: f.stepOf(f.fmt, false, (o) => o.step === 'partition') },
            { label: 'ext4로 포맷', state: f.fmt?.step === 'partition' && f.fmt.state === 'running' ? 'wait' : f.stepOf(f.fmt, !!f.fail && !f.fmt), detail: f.fmt?.state === 'running' && f.fmt.step !== 'partition' ? elapsed(f.at.format) : undefined },
            { label: '마운트하고 로컬 기록에 남기기', state: f.stepOf(f.mnt, !!f.fail && formatted && !f.mnt), detail: f.mnt?.mountPath ? <span className="mono">{f.mnt.mountPath}</span> : undefined },
            ...(root ? [{ label: `저장 경로 ${name} 등록`, state: f.rootState }] : []),
          ]}
        />
      )}
      {f.started && <span className="small muted">작업 기록에도 남습니다. 끊겨도 같은 작업 ID로 이어서 결과를 봅니다.</span>}
      <FailBand fail={f.fail} onReload={onReload} />
      <MutationError error={f.m.error} />
      {f.m.op && f.rootState !== 'done' && <OpPanel op={f.m.op} onChange={(o) => (f.m.setOp(o), o.state === 'applied' && onChanged())} />}
    </Dialog>
  );
}

function MountDialog({ node, disk, part, dev, roots, onClose, onChanged, onReload }: { node: string; disk: DBlockDisk; part: DBlockPart; dev: DNodeDevices; roots: StorageRoot[]; onClose: () => void; onChanged: () => void; onReload: () => void }) {
  const [path, setPath] = useState(`${MOUNT_BASE}/${part.label && /^[A-Za-z0-9._-]+$/.test(part.label) ? part.label : part.name}`);
  const [root, setRoot] = useState(true);
  const f = useFlow(node, disk.name, onChanged);
  const id = rootIdFor(path, part.name);
  const pathErr = f.mnt?.state !== 'done' ? mountPathError(path, dev) : undefined;
  const idErr = root && !f.m.op && roots.some((r) => r.name === id) ? `이 서버에 같은 저장 경로 ID(${id})가 있습니다. 마운트 위치 끝 이름을 바꿔 주세요` : undefined;
  const done = f.finished({ format: false, root });
  return (
    <Dialog
      title={`${node} · ${part.name} 마운트`}
      onClose={onClose}
      width={560}
      footer={
        done ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              {f.started ? '닫기' : '취소'}
            </button>
            <button type="button" className="btn primary" disabled={!!pathErr || !!idErr || f.busy} onClick={() => void f.go({ mount: { part: part.name, uuid: part.uuid }, mountPath: path, root: root ? id : undefined })}>
              {f.busy ? '진행 중…' : f.started ? '이어서 하기' : '마운트'}
            </button>
          </>
        )
      }
    >
      <div className="kv small">
        <span className="muted">파일시스템</span>
        <span>
          {part.fsType}
          {part.label ? ` · label ${part.label}` : ''} · UUID <span className="mono">{shortUuid(part.uuid ?? '')}</span>
        </span>
        <span className="muted">크기 · 사용</span>
        <span>
          {fmtBytes(part.size)}
          {part.space ? ` · ${fmtBytes(part.space.used)}` : ''}
        </span>
      </div>
      <Field label="마운트 위치" error={pathErr ?? idErr} hint="비어 있거나 없는 곳만">
        <input className="mono" value={path} onChange={(e) => setPath(e.target.value.trim())} disabled={f.busy || f.mnt?.state === 'done'} />
      </Field>
      <RootCheck on={root} set={setRoot} disabled={f.busy || f.rootState === 'done'} id={id} />
      <div className="note small">ext4만 마운트할 수 있습니다. 데이터는 그대로 둡니다. fstab은 바꾸지 않고, 서버를 켤 때 sfcd가 이 자리에 다시 마운트합니다.</div>
      {f.started && (
        <Steps
          rows={[
            { label: '마운트하고 로컬 기록에 남기기', state: f.stepOf(f.mnt, !!f.fail && !f.mnt) },
            ...(root ? [{ label: `저장 경로 ${id} 등록`, state: f.rootState }] : []),
          ]}
        />
      )}
      <FailBand fail={f.fail} onReload={onReload} />
      <MutationError error={f.m.error} />
      {f.m.op && f.rootState !== 'done' && <OpPanel op={f.m.op} onChange={(o) => (f.m.setOp(o), o.state === 'applied' && onChanged())} />}
    </Dialog>
  );
}

/** 한 번에 끝나는 작업(마운트 풀기·기록 지우기) */
function OneShot({ node, disk, action, body, title, label, danger, children, onClose, onChanged, onReload }: { node: string; disk: string; action: 'unmount' | 'forget'; body: { part: string; uuid?: string }; title: string; label: string; danger?: boolean; children: ReactNode; onClose: () => void; onChanged: () => void; onReload: () => void }) {
  const r = useDiskRunner(node, disk);
  const [op, setOp] = useState<DDiskOp>();
  const [busy, setBusy] = useState(false);
  const done = op?.state === 'done';
  return (
    <Dialog
      title={title}
      onClose={onClose}
      width={560}
      danger={danger}
      footer={
        done ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              취소
            </button>
            <button
              type="button"
              className={danger ? 'btn danger solid' : 'btn primary'}
              disabled={busy}
              onClick={() => {
                setBusy(true);
                void r.run(action, body, setOp).then((o) => (setBusy(false), o?.state === 'done' && onChanged()));
              }}
            >
              {busy ? '보내는 중…' : label}
            </button>
          </>
        )
      }
    >
      {children}
      {done && <div className="bn ok small">{action === 'unmount' ? `마운트를 풀었습니다${op?.mountPath ? ` (${op.mountPath})` : ''}.` : '기록을 지웠습니다.'}</div>}
      <FailBand fail={r.fail} onReload={onReload} />
    </Dialog>
  );
}

function BlockedDialog({ dlg, roots, onClose }: { dlg: Extract<DiskDlg, { kind: 'blocked' }>; roots: StorageRoot[]; onClose: () => void }) {
  const rows: [ReactNode, ReactNode][] = [
    ...dlg.roots.map((id): [ReactNode, ReactNode] => {
      const v = roots.find((r) => r.name === id)?.volumes;
      return [
        <>
          저장 경로 <b>{id}</b>
          {v !== undefined ? ` (데이터 저장소 ${v}개)` : ''}
        </>,
        <>
          <Link to="../storage">저장 경로 탭</Link>에서 {v ? '비우고 빼기' : '빼기'}
        </>,
      ];
    }),
    ...dlg.runtime.map((m): [ReactNode, ReactNode] => [
      <>
        엔진 저장 위치 <span className="mono">{m}</span>
      </>,
      '서버에 직접 접속해 옮기기',
    ]),
    ...(dlg.fstab
      ? [
          [
            <>
              운영자가 직접 마운트함 (fstab) <span className="mono">{dlg.path}</span>
            </>,
            'Seafield Cluster가 마운트한 것만 풀 수 있습니다. 서버에 직접 접속해 푸세요',
          ] as [ReactNode, ReactNode],
        ]
      : []),
  ];
  return (
    <Dialog
      title={`${dlg.disk.name} 마운트를 풀 수 없습니다`}
      onClose={onClose}
      width={560}
      footer={
        <button type="button" className="btn primary" onClick={onClose}>
          닫기
        </button>
      }
    >
      <span>아래를 먼저 정리해야 합니다.</span>
      <table className="tbl">
        <thead>
          <tr>
            <th>그 위에 있는 것</th>
            <th>할 일</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([a, b], i) => (
            <tr key={i}>
              <td className="small">{a}</td>
              <td className="small">{b}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Dialog>
  );
}

/** 디스크 탭의 창 하나 */
export function DiskActionDialog({ node, dlg, dev, roots, onClose, onChanged }: { node: string; dlg: DiskDlg; dev: DNodeDevices; roots: StorageRoot[]; onClose: () => void; onChanged: () => void }) {
  const reload = () => (onChanged(), onClose());
  const p = { node, dev, roots, onClose, onChanged, onReload: reload };
  switch (dlg.kind) {
    case 'format':
      return <FormatDialog {...p} disk={dlg.disk} reformat={dlg.reformat} />;
    case 'mount':
      return <MountDialog {...p} disk={dlg.disk} part={dlg.part} />;
    case 'blocked':
      return <BlockedDialog dlg={dlg} roots={roots} onClose={onClose} />;
    case 'unmount':
      return (
        <OneShot {...p} disk={dlg.disk.name} action="unmount" body={{ part: dlg.part.name }} title={`${dlg.disk.name} 마운트를 풀까요?`} label="마운트 풀기">
          <div className="kv small">
            <span className="muted">마운트 지점</span>
            <span>
              <span className="mono">{dlg.path}</span> (Seafield Cluster가 마운트함)
            </span>
            <span className="muted">그 위</span>
            <span>저장 경로·엔진 저장 위치 없음</span>
          </div>
          <div className="note small">풀면 sfcd의 로컬 마운트 기록도 지워 서버를 켤 때 다시 마운트하지 않습니다. 디스크의 데이터는 그대로 남습니다.</div>
        </OneShot>
      );
    case 'forget':
      return <ForgetBody {...p} rec={dlg.rec} />;
  }
}

function ForgetBody({ rec, roots, ...p }: { node: string; rec: DDiskRecord; roots: StorageRoot[]; onClose: () => void; onChanged: () => void; onReload: () => void }) {
  const on = rootsUnder(roots, rec.path);
  return (
    <OneShot {...p} disk={rec.disk} action="forget" body={{ part: rec.part, uuid: rec.uuid }} title={`${rec.disk} 기록을 지울까요?`} label="기록 지우기" danger>
      <span>
        sfcd의 로컬 마운트 기록에서 {rec.disk}(UUID <span className="mono">{shortUuid(rec.uuid)}</span> → <span className="mono">{rec.path}</span>)를 지웁니다.
        {on.length > 0 && ` 그 위 저장 경로 ${on.map((r) => r.name).join(', ')}는 그대로 남아 ‘준비 안 됨’입니다.`} 디스크를 다시 연결해도 저절로 마운트하지 않습니다.
      </span>
    </OneShot>
  );
}
