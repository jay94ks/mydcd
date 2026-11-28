// SPDX-License-Identifier: Apache-2.0

// 디스크 묶음 (UI-1F, 캔버스 v273–v278 NodeDisks pool1 상자, NodeDisksIx 묶기·교체·묶음 풀기, #811 계약).
// LVM은 미사용 디스크를 지우고 묶어 ext4로 포맷·마운트한다. FUSE(#819)는 마운트된 파티션에 조각 파일을 두고 묶는다(포맷 안 함, 교체 없음).
// 묶음 작업도 디스크 작업처럼 그 서버의 sfcd가 하고 Raft를 거치지 않는다. 같은 opId를 다시 보내면 처음 결과다.
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { ApiError, newOpId } from '../api/client';
import type { DBlockDisk, DBlockPart, DDiskBundle, DDiskOp, DNodeDevices } from '../api/dto';
import { diskBundle, diskBundleAction, diskOperation, type BundleMember } from '../api/endpoints';
import type { StorageRoot } from '../api/types';
import { Dialog } from '../components/Dialog';
import { MutationError, uncertain } from '../components/OpPanel';
import { Badge, Field, type Tone } from '../components/ui';
import { fmtBytes } from '../lib/format';
import { elapsed, Steps, useTicker, diskOpText, type StepState } from './DiskActions';
import { canFormat, MOUNT_BASE, mountPathError, rootsUnder } from './NodeDisks';

const MODE: Record<string, string> = { linear: '이어 붙이기', mirror: '미러' };
const BACKEND: Record<string, string> = { lvm: 'LVM', fuse: 'FUSE' };
const MEMBER: Record<string, [Tone, string]> = { ok: ['ok', '정상'], missing: ['er', '찾지 못함'], syncing: ['pr', '재동기화 중'] };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const names = (xs: string[]) => xs.join(' · ');
/** 구성원 이름: fuse는 파티션, lvm은 디스크 */
const memberName = (m: { disk: string; part?: string }) => m.part || m.disk;
const GiB = 2 ** 30;
const MIN_FUSE = 64 * 2 ** 20;

/** 묶음 이름: 소문자·숫자·- 32자까지 (sfcd 규칙) */
export const bundleNameError = (n: string) => (!n ? '이름을 적어 주세요' : !/^[a-z0-9-]{1,32}$/.test(n) ? '영문 소문자·숫자·-만 씁니다(32자까지)' : undefined);

/** 묶음 상태 배지 */
export function bundleState(b: DDiskBundle, mounted: boolean): [Tone, string] {
  if (b.state === 'syncing') return ['pr', `재동기화 중 ${b.syncPercent ?? 0}%`];
  if (b.state === 'degraded') return ['er', '한쪽 고장'];
  if (b.state === 'missing') return ['er', '쓸 수 없음'];
  return mounted ? ['ok', '마운트됨'] : ['wa', '마운트 안 됨'];
}

/** 묶음을 이루는 디스크로 쓸 수 있는가: 포맷 펜스가 있는 미사용 디스크 */
export const bundleable = (d: DBlockDisk) => d.kind !== 'bundle' && canFormat(d);

/** 디스크 탭의 묶음 상자. 장치 행(kind bundle)이 없으면(쓸 수 없음) 구성원만 */
export function BundleBox({ b, d, roots, table, onMakeRoot, onUnbundle, onReplace }: { b: DDiskBundle; d?: DBlockDisk; roots: StorageRoot[]; table: ReactNode; onMakeRoot?: (path: string) => void; onUnbundle?: () => void; onReplace?: (member: string) => void }) {
  const mounts = (d?.parts ?? []).flatMap((p) => p.mounts ?? []);
  const on = mounts.flatMap((m) => rootsUnder(roots, m)).map((r) => r.name);
  const [tone, state] = bundleState(b, mounts.length > 0);
  const members = b.members ?? [];
  const lost = members.filter((m) => m.state === 'missing').map(memberName);
  const ok = members.filter((m) => m.state !== 'missing').map(memberName);
  const mirror = b.mode === 'mirror';
  const fuse = b.backend === 'fuse';
  const meta = `${names(members.map(memberName))} ${members.length}개를 ${BACKEND[b.backend] ?? b.backend} ${MODE[b.mode] ?? b.mode}로 묶음 · ${mirror ? '하나가 고장나도 데이터 유지' : '하나만 고장나도 묶음 전체를 잃음'} · ${fmtBytes(b.size)}`;
  return (
    <div className="col" style={{ border: `1px solid ${tone === 'er' ? 'var(--er-line)' : 'var(--line)'}`, borderRadius: 8, padding: '14px 16px', gap: 10 }}>
      <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <b className="mono">{b.name}</b>
        <Badge tone="tag">
          디스크 묶음 · {MODE[b.mode] ?? b.mode} · {BACKEND[b.backend] ?? b.backend}
        </Badge>
        {b.backend === 'fuse' && <Badge tone="wa">느린 저장소 · 백업·registry용</Badge>}
        <Badge tone={tone}>{state}</Badge>
        <span className="small muted">{meta}</span>
        <span style={{ marginLeft: 'auto' }} />
        {onMakeRoot && mounts.length === 1 && (
          <button type="button" className="btn sm" onClick={() => onMakeRoot(mounts[0])}>
            여기에 저장 경로 만들기…
          </button>
        )}
        {onUnbundle && (
          <button type="button" className={`btn sm danger${on.length ? ' dim' : ''}`} title={on.length ? `저장 경로(${on.join(', ')})를 모두 비우고 뺀 뒤에만` : undefined} disabled={on.length > 0} onClick={onUnbundle}>
            묶음 풀기…
          </button>
        )}
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>장치</th>
              <th>마운트 지점</th>
              <th>형식</th>
              <th>크기</th>
              <th>사용</th>
            </tr>
          </thead>
          <tbody>
            {table}
            {members.map((m) => {
              const [t, s] = MEMBER[m.state] ?? ['un', m.state];
              return (
                <tr key={memberName(m)}>
                  <td className="mono">└ {memberName(m)}</td>
                  <td className="muted">—</td>
                  <td className="small">{fuse ? '묶음 구성원 · 조각 파일' : '묶음 구성원'}</td>
                  <td className="small">{m.size ? fmtBytes(m.size) : '—'}</td>
                  <td>
                    <span className="row" style={{ gap: 6, alignItems: 'center' }}>
                      <Badge tone={t}>{m.state === 'syncing' ? `${s} ${b.syncPercent ?? 0}%` : s}</Badge>
                      {onReplace && mirror && !fuse && m.state === 'missing' && (
                        <button type="button" className="btn sm primary" disabled={b.state === 'syncing'} title={b.state === 'syncing' ? '재동기화가 끝난 뒤 다시 하세요' : undefined} onClick={() => onReplace(m.disk)}>
                          교체…
                        </button>
                      )}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {on.length > 0 && (
        <div className="row" style={{ gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          <span className="small muted">이 디스크 위</span>
          {on.map((r) => (
            <span key={r} className="chip">
              저장 경로 <b>{r}</b>
              {b.state === 'missing' ? ' (준비 안 됨)' : ''}
            </span>
          ))}
        </div>
      )}
      {b.state === 'degraded' && (
        <div className="bn err small">
          {names(lost)}를 찾지 못했습니다. 남은 {names(ok)}로 계속 동작하지만 하나 더 고장나면 데이터를 잃습니다.{' '}
          {fuse ? '다시 연결하면 sfcd가 빠진 동안 쓴 부분을 다시 복사합니다. FUSE 묶음은 구성원을 교체할 수 없으니 바꾸려면 풀고 다시 묶으세요.' : '같은 크기 이상의 미사용 디스크로 교체하세요.'}
        </div>
      )}
      {b.state === 'syncing' && <div className="note small">저장 경로는 계속 쓸 수 있습니다. 끝나면 정상으로 바뀝니다.</div>}
      {b.state === 'missing' && (
        <div className="bn err small">
          {names(lost)}를 찾지 못해 {b.name}를 마운트하지 않았습니다. 그 위 저장 경로는 ‘준비 안 됨’입니다. {BACKEND[b.backend] ?? b.backend} 이어 붙이기는 구성원이 모두 있어야 쓸 수 있습니다. 디스크를 다시 연결하면 sfcd가 저절로 마운트합니다.
        </div>
      )}
      {b.state !== 'missing' && <span className="small muted">Seafield Cluster가 묶고 마운트함 · 서버를 켤 때 sfcd가 묶음을 다시 맞추고 이 자리에 마운트합니다</span>}
    </div>
  );
}

/** 묶음 작업 하나를 보내고 running이면 끝날 때까지 2초마다 묻는다. 답을 못 받으면 같은 opId로 다시 보낸다 */
function useBundleRunner(node: string) {
  const id = useRef<string>();
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const [fail, setFail] = useState<{ op?: DDiskOp; error?: unknown }>();
  const run = async (send: (opId: string) => Promise<DDiskOp>, onOp: (o: DDiskOp) => void): Promise<DDiskOp | undefined> => {
    setFail(undefined);
    const opId = (id.current ??= newOpId());
    try {
      let o = await send(opId);
      onOp(o);
      while (o.state === 'running' && alive.current) {
        await sleep(2000);
        try {
          o = await diskOperation(node, opId);
          onOp(o);
        } catch (e) {
          if (e instanceof ApiError && e.status < 500 && e.status !== 404) throw e;
        }
      }
      if (o.state === 'failed') {
        id.current = undefined;
        setFail({ op: o });
      }
      return o;
    } catch (e) {
      if (!uncertain(e)) id.current = undefined;
      setFail({ error: e });
      return undefined;
    }
  };
  return { run, fail };
}

const BUNDLE_CODE: Record<string, string> = {
  'not-supported': '이 서버의 sfcd가 아직 이 구현 수단을 지원하지 않습니다',
  'not-mirror': '미러 묶음만 구성원을 교체할 수 있습니다',
  'too-small': '새 디스크가 묶음보다 작습니다',
  busy: '지금 재동기화 중입니다. 재동기화가 끝난 뒤 다시 하세요',
};
function BundleFail({ fail, onReload, explain }: { fail?: { op?: DDiskOp; error?: unknown }; onReload: () => void; explain?: (code: string) => string | undefined }) {
  if (!fail) return null;
  if (fail.op) {
    const mine = explain?.(fail.op.code ?? '');
    if (mine) return <div className="bn err small">{mine}</div>;
    const special = BUNDLE_CODE[fail.op.code ?? ''];
    return (
      <div className="bn err small">
        {special && !(fail.op.code === 'busy' && fail.op.action === 'bundle') ? `${fail.op.bundle ?? ''} 작업을 거절했습니다: ${special}.` : diskOpText(fail.op)}
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
  }
  return (
    <>
      <MutationError error={fail.error} />
      {uncertain(fail.error) && <div className="note small">답을 받지 못했습니다. 다시 누르면 같은 작업 ID로 물어 결과를 이어서 봅니다(두 번 실행하지 않습니다).</div>}
    </>
  );
}

const fence = (d: DBlockDisk): BundleMember => ({ disk: d.name, serial: d.serial || undefined, wwn: d.serial ? undefined : d.wwn || undefined, size: d.size });
const diskLine = (d: DBlockDisk) => `${d.name} · ${(d.parts ?? []).some((p) => p.fsType) ? 'ext4 있음 · 다시 포맷' : '빈 디스크'}${d.model ? ` · ${d.model}` : ''}`;

/** fuse 구성원 후보: 마운트된 파티션. 고를 수 없으면 why */
export interface FuseCand {
  disk: DBlockDisk;
  part: DBlockPart;
  mount: string;
  why?: string;
}
export function fuseCandidates(dev: DNodeDevices): FuseCand[] {
  const out: FuseCand[] = [];
  for (const d of dev.disks ?? []) {
    if (d.kind === 'bundle' || d.class === 'bundle-member') continue;
    for (const p of d.parts ?? []) {
      const mount = (p.mounts ?? [])[0];
      if (!mount || p.swap) continue;
      const why =
        d.class === 'system' || d.locked
          ? '시스템 디스크는 안 됨'
          : d.readOnly
            ? '읽기 전용'
            : !p.uuid
              ? '파일 시스템 UUID를 모름'
              : p.space && p.space.available < MIN_FUSE + 16 * 2 ** 20
                ? '여유가 거의 없음'
                : undefined;
      out.push({ disk: d, part: p, mount, why });
    }
  }
  return out.sort((a, b) => Number(!!a.why) - Number(!!b.why));
}

export interface FusePick {
  disk: string;
  part: string;
  bytes: number;
  copy: number;
  available?: number;
  total?: number;
}
/** sfcd CheckBundle(fuse)과 같은 확인: 64MiB 이상, 파티션 크기 안, reserve면 여유(+16MiB) 안, mirror 사본은 1부터·2개 이상·사본끼리 다른 디스크 */
export function fuseProblems(picks: FusePick[], mode: 'linear' | 'mirror', alloc: 'reserve' | 'grow') {
  const row: Record<string, string> = {};
  for (const p of picks) {
    if (!(p.bytes >= MIN_FUSE)) row[p.part] = '64 MiB 이상';
    else if (p.total !== undefined && p.bytes > p.total) row[p.part] = '파티션보다 큼';
    else if (alloc === 'reserve' && p.available !== undefined && p.bytes + 16 * 2 ** 20 > p.available) row[p.part] = '여유보다 큼';
  }
  let all: string | undefined;
  const copies = mode === 'mirror' ? [...new Set(picks.map((p) => p.copy))].sort((a, b) => a - b) : [1];
  if (mode === 'mirror' && picks.length) {
    if (copies.length < 2) all = '미러는 사본이 2개 이상이어야 합니다';
    else if (copies.some((c, i) => c !== i + 1)) all = '사본 번호는 1부터 빠짐없이 이어야 합니다';
    else if (picks.some((p) => picks.some((q) => q.disk === p.disk && q.copy !== p.copy))) all = '같은 디스크의 파티션은 서로 다른 사본에 넣을 수 없습니다';
  }
  const per = copies.map((c) => picks.filter((p) => mode !== 'mirror' || p.copy === c).reduce((n, p) => n + p.bytes, 0));
  const size = per.length ? Math.min(...per) : 0;
  return { row, all, per, size };
}

const gib = (s: string) => {
  const n = Number(s);
  return Number.isFinite(n) && n > 0 ? Math.floor(n * GiB) : 0;
};

/** 디스크 묶기. LVM: 미사용 디스크를 지우고 묶음. FUSE: 마운트된 파티션에 조각 파일을 두고 묶음(포맷 안 함) */
export function BundleDialog({ node, dev, initialBackend = 'lvm', onClose, onChanged, onReload }: { node: string; dev: DNodeDevices; initialBackend?: 'lvm' | 'fuse'; onClose: () => void; onChanged: () => void; onReload: () => void }) {
  const unused = (dev.disks ?? []).filter((d) => d.class === 'unused');
  const cands = fuseCandidates(dev);
  const [backend, setBackend] = useState<'lvm' | 'fuse'>(initialBackend);
  const fuse = backend === 'fuse';
  const [picked, setPicked] = useState<string[]>([]);
  const [fpick, setFpick] = useState<Record<string, { size: string; copy: number }>>({});
  const [alloc, setAlloc] = useState<'reserve' | 'grow'>('reserve');
  const [mode, setMode] = useState<'linear' | 'mirror'>('linear');
  const [name, setName] = useState('');
  const [path, setPath] = useState('');
  const [pathTouched, setPathTouched] = useState(false);
  const [typed, setTyped] = useState('');
  const [op, setOp] = useState<DDiskOp>();
  const [busy, setBusy] = useState(false);
  const [at, setAt] = useState<number>();
  // 보낸 구성원은 고정한다(끝나면 미사용 디스크·후보에서 빠지거나 바뀐다)
  const [sent, setSent] = useState<{ label: string[]; backend: 'lvm' | 'fuse'; fp?: FusePick[] }>();
  const r = useBundleRunner(node);
  useTicker(busy);
  const started = !!op || busy;
  const ds = unused.filter((d) => picked.includes(d.name));
  const fps: FusePick[] = cands
    .filter((c) => fpick[c.part.name])
    .map((c) => ({ disk: c.disk.name, part: c.part.name, bytes: gib(fpick[c.part.name].size), copy: mode === 'mirror' ? fpick[c.part.name].copy : 1, available: c.part.space?.available, total: c.part.space?.total }));
  const fchk = fuseProblems(sent?.fp ?? fps, mode, alloc);
  const sum = ds.reduce((n, d) => n + d.size, 0);
  const min = ds.length ? Math.min(...ds.map((d) => d.size)) : 0;
  const small = ds.find((d) => d.size === min);
  const mountPath = pathTouched ? path : name ? `${MOUNT_BASE}/${name}` : '';
  const nameErr = name && !started ? (bundleNameError(name) ?? ((dev.bundles ?? []).some((b) => b.name === name) || (dev.disks ?? []).some((d) => d.name === name) ? '같은 이름의 묶음이나 디스크가 있습니다' : undefined)) : undefined;
  const pathErr = mountPath && !started ? mountPathError(mountPath, dev) : undefined;
  const common = !!name && !nameErr && !!mountPath && !pathErr && !busy;
  const ready = fuse
    ? common && fps.length >= 2 && fps.length <= 32 && !Object.keys(fchk.row).length && !fchk.all
    : common && ds.length >= 2 && ds.length <= 32 && typed === name;
  const done = op?.state === 'done';
  const memberLabel = sent?.label ?? (fuse ? fps.map((p) => p.part) : ds.map((d) => d.name));
  const toggleFuse = (c: FuseCand, on: boolean) => {
    const next = { ...fpick };
    if (!on) delete next[c.part.name];
    else {
      const same = cands.find((x) => x.disk.name === c.disk.name && next[x.part.name]);
      const usedCopies = new Set(Object.values(next).map((v) => v.copy));
      let copy = same ? next[same.part.name].copy : 1;
      if (!same) while (usedCopies.has(copy)) copy++;
      const avail = c.part.space?.available ?? 0;
      next[c.part.name] = { size: String(Math.max(0.1, Math.floor(((avail * 0.9) / GiB) * 10) / 10)), copy };
    }
    setFpick(next);
  };
  const send = async () => {
    setBusy(true);
    setAt(Date.now());
    setSent({ label: memberLabel, backend, fp: fuse ? fps : undefined });
    const label = name.length <= 16 ? { label: name } : {};
    try {
      const o = await r.run(
        (opId) =>
          fuse
            ? diskBundle(node, {
                opId,
                name,
                backend: 'fuse',
                mode,
                allocation: alloc,
                mountPath,
                ...label,
                members: fps.map((p) => ({ disk: p.disk, part: p.part, uuid: cands.find((c) => c.part.name === p.part)!.part.uuid!, bytes: p.bytes, ...(mode === 'mirror' ? { copy: p.copy } : {}) })),
              })
            : diskBundle(node, { opId, name, backend: 'lvm', mode, members: ds.map(fence), mountPath, ...label }),
        setOp,
      );
      if (o?.state === 'done') onChanged();
    } finally {
      setBusy(false);
    }
  };
  const step = (o: DDiskOp | undefined, mine: string[], later: string[]): StepState => {
    if (!o) return r.fail ? 'fail' : 'wait';
    if (o.state === 'done') return 'done';
    if (mine.includes(o.step)) return o.state === 'failed' ? 'fail' : 'run';
    return later.includes(o.step) ? 'done' : 'wait';
  };
  const ORDER = ['members', 'create', 'format', 'mount'];
  const after = (k: string) => ORDER.slice(ORDER.indexOf(k) + 1);
  const sentFuse = (sent?.backend ?? backend) === 'fuse';
  // fuse 거절은 고른 파티션으로 풀어 쓴다
  const explain = (code: string): string | undefined => {
    if (!sentFuse) return undefined;
    const fp = sent?.fp ?? [];
    if (code === 'too-small') {
      const p = fp.find((x) => alloc === 'reserve' && x.available !== undefined && x.bytes + 16 * 2 ** 20 > x.available);
      return p
        ? `${p.part}의 여유(${fmtBytes(p.available ?? 0)})가 내줄 크기(${fmtBytes(p.bytes)})보다 작아 묶음을 만들지 않았습니다. 내줄 크기를 줄이거나 늘어나는 대로를 고르세요.`
        : `파티션 여유가 모자라 묶음을 만들지 않았습니다(내줄 크기는 64 MiB 이상, ${alloc === 'reserve' ? '미리 예약은 여유 안이어야 함' : '파티션 크기 안'}). 다시 읽고 내줄 크기를 줄여 보세요.`;
    }
    if (code === 'not-mounted') return `고른 파티션 중 마운트가 풀린 것이 있어 묶음을 만들지 않았습니다. 다시 읽고 확인해 주세요.`;
    if (code === 'members') return `미러 사본 번호가 1부터 이어지지 않거나 같은 디스크가 두 사본에 들어 있어 묶음을 만들지 않았습니다.`;
    if (code === 'system-disk') return `시스템 디스크의 파티션은 묶을 수 없습니다.`;
    if (code === 'busy') return `고른 파티션 중 이미 다른 묶음에 쓰이거나 읽기 전용·swap인 것이 있어 묶음을 만들지 않았습니다. 다시 읽고 확인해 주세요.`;
    return undefined;
  };
  return (
    <Dialog
      title={started ? `디스크 묶기 · ${done ? '끝남' : '진행 중'}` : `디스크 묶기 (${node})`}
      onClose={onClose}
      width={720}
      danger={!fuse}
      footer={
        done || (started && !busy && !r.fail) ? (
          <button type="button" className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              {started ? '닫기' : '취소'}
            </button>
            <button type="button" className={fuse ? 'btn primary' : 'btn danger solid'} disabled={!ready} onClick={() => void send()}>
              {busy ? '진행 중…' : r.fail ? '다시 하기' : fuse ? '묶기' : '묶고 포맷하기'}
            </button>
          </>
        )
      }
    >
      {!started ? (
        <>
          {!fuse && <span className="small">미사용 디스크 여러 개를 하나의 디스크로 묶고 포맷·마운트합니다. 묶은 디스크는 추가 디스크에 하나로 보입니다.</span>}
          {!fuse && (
            <Field label="묶을 디스크 (2개 이상)" group>
              {unused.map((d) => {
                const ok = bundleable(d);
                return (
                  <label key={d.name} className={`choice ${picked.includes(d.name) ? 'on' : ''}${ok ? '' : ' dim'}`} style={{ justifyContent: 'space-between', display: 'flex' }} title={ok ? undefined : '다른 장치가 쓰고 있거나 serial·WWN을 몰라 고를 수 없습니다'}>
                    <span>
                      <input type="checkbox" disabled={!ok} checked={picked.includes(d.name)} onChange={(e) => setPicked(e.target.checked ? [...picked, d.name] : picked.filter((x) => x !== d.name))} /> <span className="mono">{diskLine(d)}</span>
                      {!ok && <span className="small muted"> · 고를 수 없음</span>}
                    </span>
                    <span className="small">{fmtBytes(d.size)}</span>
                  </label>
                );
              })}
              {!unused.length && <span className="small muted">미사용 디스크가 없습니다.</span>}
            </Field>
          )}
          <Field label="구현 수단" group hint="한 번 만든 묶음의 구현 수단은 바꿀 수 없습니다(풀고 다시 묶기).">
            <label className={`choice ${!fuse ? 'on' : ''}`}>
              <input type="radio" checked={!fuse} onChange={() => setBackend('lvm')} /> <b>LVM</b> (기본) <span className="small muted">미사용 디스크를 묶음 · 포맷함 · 빠름</span>
            </label>
            <label className={`choice ${fuse ? 'on' : ''}`}>
              <input type="radio" checked={fuse} onChange={() => setBackend('fuse')} /> <b>FUSE</b> <Badge tone="wa">느린 저장소 · 백업·registry용</Badge>{' '}
              <span className="small muted">이미 마운트된 파티션의 남는 공간을 묶음 · 포맷하지 않고 기존 파일은 그대로 · 느림 · 빠르게 동작해야 하는 용도는 LVM으로 묶으세요.</span>
            </label>
          </Field>
          {fuse && (
            <Field label={`묶을 파티션${mode === 'mirror' ? ' · 미러' : ''} (2개 이상)`} group>
              <div style={{ overflowX: 'auto' }}>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th style={{ width: 24 }} />
                      <th>파티션 · 마운트 지점</th>
                      <th>여유</th>
                      <th style={{ width: 150 }}>내줄 크기</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cands.map((c) => {
                      const v = fpick[c.part.name];
                      const err = v ? fchk.row[c.part.name] : undefined;
                      return (
                        <tr key={c.part.name} className={c.why ? 'dim' : undefined}>
                          <td>
                            <input type="checkbox" aria-label={c.part.name} disabled={!!c.why} checked={!!v} onChange={(e) => toggleFuse(c, e.target.checked)} />
                          </td>
                          <td>
                            <span className="mono">{c.part.name}</span> · <span className="mono">{c.mount}</span>
                            {v && mode === 'mirror' && (
                              <>
                                {' '}
                                <select aria-label={`${c.part.name} 사본`} value={v.copy} onChange={(e) => setFpick({ ...fpick, [c.part.name]: { ...v, copy: Number(e.target.value) } })} style={{ width: 'auto', height: 26, fontSize: 12 }}>
                                  {Array.from({ length: Math.max(2, fps.length) }, (_, i) => i + 1).map((n) => (
                                    <option key={n} value={n}>
                                      사본 {n}
                                    </option>
                                  ))}
                                </select>
                              </>
                            )}
                          </td>
                          <td className="small">{c.part.space ? `여유 ${fmtBytes(c.part.space.available)}` : '—'}</td>
                          <td>
                            {c.why ? (
                              <span className="small muted">{c.why}</span>
                            ) : v ? (
                              <span className="col" style={{ gap: 2 }}>
                                <span className="row" style={{ gap: 4, alignItems: 'center' }}>
                                  <input className="mono" inputMode="decimal" aria-label={`${c.part.name} 내줄 크기`} value={v.size} onChange={(e) => setFpick({ ...fpick, [c.part.name]: { ...v, size: e.target.value.trim() } })} style={{ height: 28, width: 90 }} />
                                  <span className="small">GiB</span>
                                </span>
                                {err && <span className="small" style={{ color: 'var(--er)' }}>{err}</span>}
                              </span>
                            ) : null}
                          </td>
                        </tr>
                      );
                    })}
                    {!cands.length && (
                      <tr>
                        <td colSpan={4} className="small muted">
                          마운트된 파티션이 없습니다.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              {mode === 'mirror' && fps.length > 0 && (
                <span className="small muted">
                  같은 디스크의 파티션은 서로 다른 사본에 넣을 수 없습니다
                  {fchk.per.length >= 2 && !fchk.all ? ` · ${fchk.per.map((n, i) => `사본 ${i + 1} 합 ${fmtBytes(n)}`).join(', ')} → 묶음 크기는 가장 작은 쪽 ${fmtBytes(fchk.size)}` : ''}
                </span>
              )}
              {fchk.all && <span className="small" style={{ color: 'var(--er)' }}>{fchk.all}</span>}
            </Field>
          )}
          {fuse && (
            <span className="small">
              포맷하지 않습니다. 각 파티션의 <span className="mono">.sfc-disks/{name || '<이름>'}/</span> 아래에 이미지 조각 파일(하나 최대 64 GiB)을 두고 하나로 합쳐 ext4로 마운트합니다. 기존 파일은 그대로 둡니다.
            </span>
          )}
          <Field label="묶는 방식" group>
            <label className={`choice ${mode === 'linear' ? 'on' : ''}`}>
              <input type="radio" checked={mode === 'linear'} onChange={() => setMode('linear')} /> <b>이어 붙이기</b>{' '}
              {fuse ? (
                <span className="small muted">합계{fps.length ? ` ${fmtBytes(fps.reduce((n, p) => n + p.bytes, 0))}` : ''} · 구성원 하나만 없어도 묶음 전체를 못 씀</span>
              ) : (
                <span className="small muted">용량을 합칩니다{ds.length ? ` · ${fmtBytes(sum)}` : ''} · 디스크 하나만 고장나도 묶음 전체 데이터를 잃습니다</span>
              )}
            </label>
            <label className={`choice ${mode === 'mirror' ? 'on' : ''}`}>
              <input type="radio" checked={mode === 'mirror'} onChange={() => setMode('mirror')} /> <b>미러</b>{' '}
              {fuse ? (
                <span className="small muted">같은 데이터를 사본마다 씁니다 · 사본끼리는 서로 다른 디스크여야 함</span>
              ) : (
                <span className="small muted">같은 데이터를 모든 디스크에 씁니다{ds.length ? ` · ${fmtBytes(min)} (가장 작은 디스크)` : ''} · 하나가 남아 있으면 데이터 유지</span>
              )}
            </label>
          </Field>
          {fuse && (
            <Field label="공간 방식" group>
              <label className={`choice ${alloc === 'reserve' ? 'on' : ''}`}>
                <input type="radio" checked={alloc === 'reserve'} onChange={() => setAlloc('reserve')} /> <b>미리 예약 (reserve)</b> <span className="small muted">내줄 크기만큼 지금 잡아 둡니다 · 빠름 · 여유가 모자라면 만들지 않음</span>
              </label>
              <label className={`choice ${alloc === 'grow' ? 'on' : ''}`}>
                <input type="radio" checked={alloc === 'grow'} onChange={() => setAlloc('grow')} /> <b>늘어나는 대로 (grow)</b> <span className="small muted">쓴 만큼만 차지합니다</span>
              </label>
            </Field>
          )}
          {fuse && alloc === 'grow' && <div className="note wa small">늘어나는 대로는 파티션이 다른 용도로 차면 묶음에 쓰기가 실패할 수 있습니다. 파티션 여유를 지켜볼 수 있을 때만 쓰세요.</div>}
          {!fuse && mode === 'mirror' && small && ds.some((d) => d.size > min) && (
            <div className="note wa small">
              디스크 크기가 다릅니다. 미러는 가장 작은 디스크({small.name} {fmtBytes(min)})만큼만 씁니다.{' '}
              {ds
                .filter((d) => d.size > min)
                .map((d) => `${d.name}의 나머지 ${fmtBytes(d.size - min)}`)
                .join(', ')}
              는 쓰지 않습니다.
            </div>
          )}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <Field label="묶음 이름" error={nameErr} hint="마운트 위치 이름">
              <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} placeholder={fuse ? 'pool3' : 'pool2'} autoComplete="off" />
            </Field>
            <Field label="마운트 위치" error={pathErr} hint="바꿀 수 있음">
              <input className="mono" value={mountPath} onChange={(e) => (setPath(e.target.value.trim()), setPathTouched(true))} placeholder={`${MOUNT_BASE}/${fuse ? 'pool3' : 'pool2'}`} />
            </Field>
          </div>
          {!fuse && ds.length > 0 && (
            <div className="bn err small">
              {names(ds.map((d) => d.name))}의 모든 데이터가 지워집니다.{mode === 'linear' ? ' 이어 붙이기는 디스크 하나만 고장나도 묶음 전체를 잃으니 백업이 있는 데이터에 쓰세요.' : ''}
            </div>
          )}
          {!fuse && (
            <Field label={`확인: 묶음 이름 ${name || '…'} 입력`}>
              <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value.trim())} placeholder={name} autoComplete="off" spellCheck={false} />
            </Field>
          )}
        </>
      ) : (
        <>
          <Steps
            rows={[
              {
                label: sentFuse ? `조각 파일 만들고 잇기 (${names(memberLabel)}, ${MODE[mode]})` : `디스크 묶기 (${names(memberLabel)}, ${MODE[mode]})`,
                state: step(op, ['members', 'create', 'check'], after('create')),
                detail: op?.state === 'running' && ['members', 'create'].includes(op.step) ? elapsed(at) : undefined,
              },
              { label: `ext4 포맷 · ${name}`, state: step(op, ['format'], after('format')) },
              { label: '마운트', state: step(op, ['mount'], []), detail: <span className="mono">{op?.mountPath ?? mountPath}</span> },
            ]}
          />
          <span className="small muted">창을 닫아도 서버에서 계속됩니다. 결과는 작업 기록과 이 탭에 보입니다.</span>
        </>
      )}
      <BundleFail fail={r.fail} onReload={onReload} explain={explain} />
    </Dialog>
  );
}

/** 묶음 풀기: 그 위 저장 경로가 없을 때만. 구성원은 빈 미사용 디스크가 된다 */
export function UnbundleDialog({ node, b, onClose, onChanged, onReload }: { node: string; b: DDiskBundle; onClose: () => void; onChanged: () => void; onReload: () => void }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const r = useBundleRunner(node);
  const send = async () => {
    setBusy(true);
    try {
      const o = await r.run((opId) => diskBundleAction(node, b.name, 'unbundle', { opId }), () => undefined);
      if (o?.state === 'done') {
        onChanged();
        onClose();
      }
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`${b.name} 묶음 풀기`}
      onClose={onClose}
      width={560}
      danger
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn danger solid" disabled={typed !== b.name || busy} onClick={() => void send()}>
            {busy ? '진행 중…' : '묶음 풀기'}
          </button>
        </>
      }
    >
      <span>
        {b.backend === 'fuse'
          ? `마운트를 풀고 묶음을 해제합니다. ${names((b.members ?? []).map(memberName))}의 조각 파일(.sfc-disks/${b.name})을 지웁니다. 묶음의 데이터는 지워지고, 파티션의 다른 파일은 그대로 둡니다.`
          : `마운트를 풀고 묶음을 해제합니다. ${names((b.members ?? []).map((m) => m.disk))}는 미사용 디스크(빈 디스크)로 돌아가고 데이터는 지워집니다.`}
      </span>
      <Field label={`확인: 묶음 이름 ${b.name} 입력`}>
        <input className="mono" value={typed} onChange={(e) => setTyped(e.target.value.trim())} placeholder={b.name} autoComplete="off" spellCheck={false} />
      </Field>
      <BundleFail fail={r.fail} onReload={onReload} />
    </Dialog>
  );
}

/** 미러 구성원 교체: 묶음 크기 이상인 미사용 디스크로. 재동기화가 시작되면 창을 닫는다 */
export function ReplaceDialog({ node, dev, b, member, onClose, onChanged, onReload }: { node: string; dev: DNodeDevices; b: DDiskBundle; member: string; onClose: () => void; onChanged: () => void; onReload: () => void }) {
  const unused = (dev.disks ?? []).filter((d) => d.class === 'unused' && bundleable(d));
  const hasFs = (d: DBlockDisk) => (d.parts ?? []).some((p) => p.fsType);
  // 빈 디스크를 먼저, 그다음 작은 순
  const fit = unused.filter((d) => d.size >= b.size).sort((x, y) => Number(hasFs(x)) - Number(hasFs(y)) || x.size - y.size);
  const tooSmall = unused.filter((d) => d.size < b.size);
  const [pick, setPick] = useState(fit[0]?.name ?? '');
  const [busy, setBusy] = useState(false);
  const r = useBundleRunner(node);
  const old = (b.members ?? []).find((m) => m.disk === member);
  const keep = (b.members ?? []).filter((m) => m.disk !== member && m.state !== 'missing').map((m) => m.disk);
  const nd = fit.find((d) => d.name === pick);
  const send = async () => {
    if (!nd || !old) return;
    setBusy(true);
    try {
      const o = await r.run((opId) => diskBundleAction(node, b.name, 'replace-member', { opId, old: { disk: old.disk, serial: old.serial || undefined, wwn: old.serial ? undefined : old.wwn || undefined }, new: fence(nd) }), () => undefined);
      if (o?.state === 'done') {
        onChanged();
        onClose();
      }
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`${member} 교체 (${b.name})`}
      onClose={onClose}
      width={560}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            취소
          </button>
          <button type="button" className="btn primary" disabled={!nd || busy} onClick={() => void send()}>
            {busy ? '진행 중…' : '교체'}
          </button>
        </>
      }
    >
      <Field label="새 디스크" hint={`${b.name} 크기(${fmtBytes(b.size)}) 이상인 미사용 디스크만 목록에 나옵니다${tooSmall.length ? ` (${tooSmall.map((d) => `${d.name} ${fmtBytes(d.size)}`).join(', ')}는 작아서 빠짐)` : ''}`}>
        <select value={pick} onChange={(e) => setPick(e.target.value)} disabled={!fit.length}>
          {!fit.length && <option value="">고를 수 있는 디스크 없음</option>}
          {fit.map((d) => (
            <option key={d.name} value={d.name}>
              {diskLine(d)} · {fmtBytes(d.size)}
            </option>
          ))}
        </select>
      </Field>
      {nd && hasFs(nd) && <div className="bn err small">{nd.name}에 파일시스템이 있습니다. 교체하면 {nd.name}의 모든 데이터가 지워집니다.</div>}
      {!fit.length && <div className="note wa small">고를 수 있는 미사용 디스크가 없습니다. {fmtBytes(b.size)} 이상 디스크를 연결하면 목록에 나타납니다.</div>}
      <div className="note small">
        교체하면 {names(keep) || '남은 구성원'}의 데이터를 새 디스크로 복사합니다(재동기화). 재동기화가 시작되면 창이 닫히고 진행률은 묶음 줄에 보입니다. 그동안도 저장 경로는 계속 쓸 수 있습니다.
      </div>
      <BundleFail fail={r.fail} onReload={onReload} />
    </Dialog>
  );
}
