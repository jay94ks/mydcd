// SPDX-License-Identifier: Apache-2.0

// 서버 상세 › 디스크 탭 (UI-1F, 캔버스 v254–v256 NodeDisks, #689 1단계 계약).
// 관측한 장치를 시스템 / 추가 / 미사용 세 묶음으로 보인다. 시스템 디스크(locked)는 포맷·마운트 대신 수작업 안내.
// '여기에 저장 경로 만들기…'는 기존 add-node-storage. 포맷·마운트·마운트 풀기·기록 지우기는 #689 3단계 API(DiskActions.tsx).
import type { ReactNode } from 'react';
import type { DBlockDisk, DBlockPart, DDiskRecord, DNodeDevices } from '../api/dto';
import type { StorageRoot } from '../api/types';
import { Badge, Card, HelpBox, type Tone } from '../components/ui';
import { Menu } from '../components/Menu';
import { fmtBytes, hhmmss, pct } from '../lib/format';

export const LOCKED_TEXT = '시스템 디스크는 Seafield Cluster에서 포맷하거나 마운트를 바꿀 수 없습니다. 꼭 바꿔야 한다면 서버에 직접 접속해 수작업으로 하세요. 바꾼 뒤에는 이 화면이 다시 읽어 보여 줍니다.';

const KIND: Record<string, string> = { lvm: 'LVM', crypt: '암호화', raid: 'RAID', dm: '장치 매퍼' };
const GROUPS: { cls: string; title: string; sub: string; empty: string }[] = [
  { cls: 'system', title: '시스템 디스크', sub: '/ 가 있는 디스크와 그 디스크의 다른 파티션', empty: '시스템 디스크를 찾지 못했습니다.' },
  { cls: 'additional', title: '추가 디스크', sub: '시스템 디스크가 아니고 파일시스템이 마운트된 디스크', empty: '추가 디스크가 없습니다.' },
  { cls: 'unused', title: '미사용 디스크', sub: '시스템 디스크가 아니고 아무것도 마운트되지 않은 디스크', empty: '쓰지 않는 디스크가 없습니다.' },
];

const mountsOf = (p: DBlockPart) => [...(p.mounts ?? []), ...(p.holders ?? []).filter((h) => !h.swap).flatMap((h) => h.mounts ?? [])];

/** 디스크 단추가 여는 창 */
export type DiskDlg =
  | { kind: 'format'; disk: DBlockDisk; reformat: boolean }
  | { kind: 'mount'; disk: DBlockDisk; part: DBlockPart }
  | { kind: 'unmount'; disk: DBlockDisk; part: DBlockPart; path: string }
  | { kind: 'blocked'; disk: DBlockDisk; path: string; roots: string[]; runtime: string[]; fstab: boolean }
  | { kind: 'forget'; rec: DDiskRecord };

/** sfcd가 마운트해 기록한 것인가(마운트 풀기는 이것만) */
export const managedRecord = (dev: DNodeDevices, p: DBlockPart) => (p.uuid ? (dev.recorded ?? []).find((r) => r.uuid === p.uuid && !r.reason) : undefined);
/** 서버를 켤 때 찾지 못한 디스크의 마운트 기록 */
export const missingRecords = (dev: DNodeDevices) => (dev.recorded ?? []).filter((r) => r.reason === 'disk-not-found');
/** 마운트할 수 있는 파티션: ext4, UUID 있음, 마운트·스왑·holder 없음 */
export const mountableParts = (d: DBlockDisk) => (d.parts ?? []).filter((p) => p.fsType === 'ext4' && p.uuid && !(p.mounts ?? []).length && !p.swap && !(p.holders ?? []).length && !p.busy);
/** 포맷 펜스: serial이나 WWN을 모르면 서버가 받지 않는다 */
export const canFormat = (d: DBlockDisk) => !d.locked && d.class === 'unused' && !d.readOnly && !!(d.serial || d.wwn) && (d.parts ?? []).every((p) => !(p.holders ?? []).length && !p.busy && !p.swap);
/** 마운트 풀기 막는 것: 저장 경로, 엔진 저장 위치, 운영자 마운트(fstab) */
export function unmountBlock(dev: DNodeDevices, p: DBlockPart): { roots: string[]; runtime: string[]; fstab: boolean } {
  return { roots: [...(p.storageRoots ?? [])], runtime: (p.purposes ?? []).includes('container-runtime') ? (p.mounts ?? []) : [], fstab: !managedRecord(dev, p) };
}
export const shortUuid = (u: string) => (u.length > 10 ? `${u.slice(0, 4)}…${u.slice(-4)}` : u);
export const MOUNT_BASE = '/var/lib/sfc-disks';
const SYSTEM_PATHS = ['/bin', '/boot', '/dev', '/etc', '/lib', '/lib32', '/lib64', '/libx32', '/proc', '/root', '/run', '/sbin', '/snap', '/sys', '/tmp', '/usr', '/var/lib/docker', '/var/lib/sfe', '/var/lib/sfc', '/var/lib/containerd', '/var/log', '/var/cache', '/var/tmp'];
/** sfcd ValidDiskMountPath와 같은 검사 + 이미 있는 마운트 안·위는 안 됨 */
export function mountPathError(path: string, dev?: DNodeDevices): string | undefined {
  if (!path) return '마운트 위치를 적어 주세요';
  if (!path.startsWith('/') || path === '/' || /\/\/|\/\.\.?(\/|$)|\/$|\s/.test(path) || path.length > 1024) return '/로 시작하는 정리된 절대 경로여야 합니다(/ 자체, .., //, 끝 /, 빈칸 안 됨)';
  if (SYSTEM_PATHS.some((x) => path === x || path.startsWith(x + '/') || x.startsWith(path + '/')) || ['/var', '/var/lib', '/home', '/opt', '/srv', '/mnt', '/media'].includes(path)) return '시스템 경로와 그 위·안에는 마운트할 수 없습니다';
  const taken = [...(dev?.disks ?? []).flatMap((d) => (d.parts ?? []).flatMap(mountsOf)), ...(dev?.recorded ?? []).map((r) => r.path)].filter((m) => m !== '/');
  if (taken.some((m) => m === path || path.startsWith(m + '/') || m.startsWith(path + '/'))) return '다른 마운트 안이나 위에는 마운트할 수 없습니다';
  return undefined;
}
/** 이름: 파일시스템 label(16자까지)이자 저장 경로 ID */
export const diskNameError = (n: string) => (!n ? '이름을 적어 주세요' : !/^[a-z][a-z0-9-]{0,15}$/.test(n) ? '영문 소문자로 시작하고 영문 소문자·숫자·-만 씁니다(16자까지)' : undefined);
/** 마운트 위치 끝 이름에서 저장 경로 ID를 만든다 */
export function rootIdFor(path: string, fallback: string): string {
  const last = path.split('/').filter(Boolean).pop() ?? '';
  const id = last.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^[^a-z]+/, '').slice(0, 63);
  return /^[a-z][a-z0-9-]{0,62}$/.test(id) ? id : fallback.replace(/[^a-z0-9-]/g, '-');
}

/** '여기에 저장 경로 만들기…'를 붙일 마운트. 스왑·읽기 전용·/boot는 빼고, / 는 /srv/sfc 아래로 제안한다 */
export function rootCandidates(d: DBlockDisk): string[] {
  if (d.readOnly || d.class === 'unused') return [];
  return (d.parts ?? [])
    .filter((p) => !p.swap)
    .flatMap(mountsOf)
    .filter((m) => !m.startsWith('/boot'))
    .map((m) => (m === '/' ? '/srv/sfc' : m));
}

/** 디스크 상태 배지 (캔버스 NodeDisks) */
export function diskState(d: DBlockDisk): [Tone, string] {
  const parts = d.parts ?? [];
  if (d.class === 'system') return ['pr', '시스템'];
  if (d.class === 'additional') return ['ok', '마운트됨'];
  if (parts.some((p) => (p.holders ?? []).length && !mountsOf(p).length)) return ['un', '다른 장치가 사용 중'];
  if (!parts.length || parts.every((p) => !p.fsType)) return ['un', '빈 디스크'];
  return ['wa', '마운트 안 됨 · 파일시스템 있음'];
}

function UseBar({ s }: { s?: { total: number; used: number } }) {
  if (!s) return <span className="muted">—</span>;
  const p = pct(s.used, s.total);
  return (
    <span className="row" style={{ gap: 8, alignItems: 'center' }}>
      <span className="bar" role="meter" aria-label="사용" aria-valuenow={p} aria-valuemin={0} aria-valuemax={100} style={{ width: 90, flex: 'none' }}>
        <i className={p >= 90 ? 'crit' : p >= 80 ? 'hi' : ''} style={{ width: `${p}%` }} />
      </span>
      <span className="small" style={{ whiteSpace: 'nowrap' }}>
        {fmtBytes(s.used)} / {fmtBytes(s.total)} · {p}%
      </span>
    </span>
  );
}

/** 표 줄: 파티션 하나, 그 위 LVM·RAID·암호화 장치는 아래 줄로 */
function PartRows({ p }: { p: DBlockPart }) {
  const mounts = p.mounts ?? [];
  return (
    <>
      <tr>
        <td className="mono">
          {p.number === 0 ? '— (디스크 전체)' : p.name}
        </td>
        <td className="mono small">{p.swap ? 'swap' : mounts.length ? mounts.join(', ') : '—'}</td>
        <td className="small">
          {p.fsType ?? '—'}
          {p.label ? ` · label ${p.label}` : ''}
        </td>
        <td className="small">{fmtBytes(p.size)}</td>
        <td>{p.swap ? <span className="muted">—</span> : <UseBar s={p.space} />}</td>
      </tr>
      {(p.holders ?? []).map((h) => (
        <tr key={h.name}>
          <td className="mono small">
            └ {h.mapper ?? h.name}
            <span className="muted"> {KIND[h.kind] ?? h.kind} · 보기만</span>
          </td>
          <td className="mono small">{h.swap ? 'swap' : (h.mounts ?? []).length ? (h.mounts ?? []).join(', ') : '—'}</td>
          <td className="small">{h.fsType ?? '—'}</td>
          <td className="small">{h.space ? fmtBytes(h.space.total) : '—'}</td>
          <td>{h.swap ? <span className="muted">—</span> : <UseBar s={h.space} />}</td>
        </tr>
      ))}
    </>
  );
}

/** '이 디스크 위' 칩: 저장 경로, 엔진 저장 위치(컨테이너 실행) */
function OnDisk({ d }: { d: DBlockDisk }) {
  const parts = d.parts ?? [];
  const roots = [...new Set(parts.flatMap((p) => p.storageRoots ?? []))];
  const runtime = parts.filter((p) => (p.purposes ?? []).includes('container-runtime')).flatMap(mountsOf);
  if (!roots.length && !runtime.length) return null;
  return (
    <div className="row" style={{ gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
      <span className="small muted">이 디스크 위</span>
      {roots.map((r) => (
        <span key={r} className="chip">
          저장 경로 <b>{r}</b>
        </span>
      ))}
      {runtime.map((m) => (
        <span key={m} className="chip">
          엔진 저장 위치 <span className="mono">{m}</span>
        </span>
      ))}
    </div>
  );
}

function DiskBox({ d, dev, onMakeRoot, onAction }: { d: DBlockDisk; dev: DNodeDevices; onMakeRoot: (path: string) => void; onAction?: (a: DiskDlg) => void }) {
  const parts = d.parts ?? [];
  const mountable = mountableParts(d);
  const own = parts.filter((p) => !p.swap && (p.mounts ?? []).length);
  const unmount = (p: DBlockPart) => {
    const b = unmountBlock(dev, p);
    const path = (p.mounts ?? [])[0] ?? '';
    onAction?.(b.roots.length || b.runtime.length || b.fstab ? { kind: 'blocked', disk: d, path, ...b } : { kind: 'unmount', disk: d, part: p, path });
  };
  const blocked = (p: DBlockPart) => {
    const b = unmountBlock(dev, p);
    return b.roots.length > 0 || b.runtime.length > 0 || b.fstab;
  };
  const [tone, state] = diskState(d);
  const cands = [...new Set(rootCandidates(d))];
  const meta = [d.model, d.serial ? `serial ${d.serial}` : '', fmtBytes(d.size)].filter(Boolean).join(' · ');
  const viewOnly = parts.some((p) => (p.holders ?? []).length);
  return (
    <div className="col" style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '14px 16px', gap: 10 }}>
      <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <b className="mono">{d.name}</b>
        <Badge tone={tone}>{state}</Badge>
        <span className="small muted">{meta}</span>
        {d.readOnly && <Badge tone="un">읽기 전용</Badge>}
        {d.removable && <Badge tone="un">이동식</Badge>}
        <span style={{ marginLeft: 'auto' }} />
        {cands.length === 1 && (
          <button type="button" className="btn sm" onClick={() => onMakeRoot(cands[0])}>
            여기에 저장 경로 만들기…
          </button>
        )}
        {cands.length > 1 && <Menu label={`${d.name} 저장 경로 만들 곳`} button="여기에 저장 경로 만들기… ▾" items={cands.map((m) => ({ label: m, onSelect: () => onMakeRoot(m) }))} />}
        {onAction && !d.locked && d.class === 'additional' && own.length === 1 && (
          <button type="button" className={`btn sm${blocked(own[0]) ? ' dim' : ''}`} onClick={() => unmount(own[0])}>
            마운트 풀기…
          </button>
        )}
        {onAction && !d.locked && d.class === 'additional' && own.length > 1 && (
          <Menu label={`${d.name} 마운트 풀 곳`} button="마운트 풀기… ▾" items={own.map((p) => ({ label: `${p.name} · ${(p.mounts ?? [])[0]}`, onSelect: () => unmount(p) }))} />
        )}
        {onAction && d.class === 'unused' && state === '빈 디스크' && (
          <button type="button" className="btn sm primary" disabled={!canFormat(d)} title={canFormat(d) ? undefined : FORMAT_FENCE_TEXT} onClick={() => onAction({ kind: 'format', disk: d, reformat: parts.length > 0 })}>
            포맷하고 마운트…
          </button>
        )}
        {onAction && d.class === 'unused' && state === '마운트 안 됨 · 파일시스템 있음' && (
          <>
            {mountable.length <= 1 && (
              <button type="button" className="btn sm primary" disabled={!mountable.length} title={mountable.length ? undefined : 'ext4만 마운트할 수 있습니다'} onClick={() => onAction({ kind: 'mount', disk: d, part: mountable[0] })}>
                마운트…
              </button>
            )}
            {mountable.length > 1 && <Menu label={`${d.name} 마운트할 파티션`} button="마운트… ▾" items={mountable.map((p) => ({ label: `${p.name}${p.label ? ` · ${p.label}` : ''}`, onSelect: () => onAction({ kind: 'mount', disk: d, part: p }) }))} />}
            <button type="button" className="btn sm danger" disabled={!canFormat(d)} title={canFormat(d) ? undefined : FORMAT_FENCE_TEXT} onClick={() => onAction({ kind: 'format', disk: d, reformat: true })}>
              다시 포맷하고 마운트…
            </button>
          </>
        )}
      </div>
      {parts.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>파티션</th>
                <th>마운트 지점</th>
                <th>형식</th>
                <th>크기</th>
                <th>사용</th>
              </tr>
            </thead>
            <tbody>
              {parts.map((p) => (
                <PartRows key={p.name} p={p} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <OnDisk d={d} />
      {onAction && d.class === 'additional' && own.length > 0 && <MountOwner dev={dev} parts={own} />}
      {d.locked && <div className="note small">🔒 {LOCKED_TEXT}</div>}
      {viewOnly && <span className="small muted">LVM·RAID·암호화 장치는 보기만 합니다.</span>}
      {d.class === 'unused' && !parts.length && <span className="small muted">파일시스템 서명이 없습니다.{onAction ? '' : ' 서버에서 포맷하고 마운트하면 추가 디스크로 보입니다.'}</span>}
      {d.class === 'unused' && parts.length > 0 && state !== '다른 장치가 사용 중' && !onAction && <span className="small muted">파일시스템은 있지만 마운트되지 않았습니다. 서버에서 마운트하면 추가 디스크로 보입니다.</span>}
      {onAction && d.class === 'unused' && !canFormat(d) && !d.serial && !d.wwn && state !== '다른 장치가 사용 중' && <span className="small muted">{FORMAT_FENCE_TEXT}</span>}
    </div>
  );
}

const FORMAT_FENCE_TEXT = '서버가 이 디스크의 serial·WWN을 알리지 않아 여기서 포맷할 수 없습니다. 서버에 직접 접속해 하세요.';

/** 추가 디스크의 마운트를 누가 했나 */
function MountOwner({ dev, parts }: { dev: DNodeDevices; parts: DBlockPart[] }) {
  const managed = parts.filter((p) => managedRecord(dev, p));
  if (managed.length === parts.length) return <span className="small muted">Seafield Cluster가 마운트함 · 서버를 켤 때 sfcd가 이 자리에 다시 마운트합니다 (fstab 안 씀)</span>;
  if (!managed.length) return <span className="small muted">운영자가 직접 마운트함 (fstab) · 그대로 두고 저장 경로만 만들 수 있습니다</span>;
  return <span className="small muted">Seafield Cluster가 마운트함: {managed.map((p) => p.name).join(', ')} · 나머지는 운영자가 직접 마운트함 (fstab)</span>;
}

/** 서버를 켤 때 기록된 디스크를 찾지 못함 (recorded reason disk-not-found) */
function MissingBox({ rec, roots, onAction }: { rec: DDiskRecord; roots: StorageRoot[]; onAction?: (a: DiskDlg) => void }) {
  const on = rootsUnder(roots, rec.path);
  return (
    <div className="col" style={{ border: '1px solid var(--er-line)', borderRadius: 8, padding: '14px 16px', gap: 10 }}>
      <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <b className="mono">{rec.disk}</b>
        <Badge tone="er">디스크를 찾지 못함</Badge>
        <span className="small muted mono">{rec.part}</span>
        <span style={{ marginLeft: 'auto' }} />
        {onAction && (
          <button type="button" className="btn sm danger" onClick={() => onAction({ kind: 'forget', rec })}>
            기록 지우기…
          </button>
        )}
      </div>
      <div className="bn err small">
        서버를 켤 때 기록된 디스크(UUID <span className="mono">{shortUuid(rec.uuid)}</span>)를 찾지 못해 <span className="mono">{rec.path}</span> 에 마운트하지 않았습니다.
        {on.length > 0 && ` 그 위 저장 경로 ${on.map((r) => r.name).join(', ')}는 ‘준비 안 됨’이고, 그 경로를 쓰는 컨테이너는 띄우지 않았습니다.`} 디스크를 다시 연결하면 sfcd가 저절로 마운트합니다.
      </div>
      {on.length > 0 && (
        <div className="row" style={{ gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          <span className="small muted">이 디스크 위</span>
          {on.map((r) => (
            <span key={r.name} className="chip">
              저장 경로 <b>{r.name}</b> (준비 안 됨)
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
/** 마운트 위치 안의 저장 경로 */
export const rootsUnder = (roots: StorageRoot[], path: string) => roots.filter((r) => r.path === path || r.path.startsWith(path + '/'));

/** 디스크 탭 본문. dev가 없으면(옛 데몬) 안내만 */
export function DiskGroups({ dev, live, refresh, roots = [], onMakeRoot, onAction }: { dev: DNodeDevices | undefined; live?: boolean; refresh?: ReactNode; roots?: StorageRoot[]; onMakeRoot: (path: string) => void; onAction?: (a: DiskDlg) => void }) {
  const disks = dev?.disks ?? [];
  const lvm = disks.flatMap((d) => (d.parts ?? []).flatMap((p) => p.holders ?? [])).length;
  const total = disks.reduce((n, d) => n + d.size, 0);
  const used = disks.flatMap((d) => (d.parts ?? []).flatMap((p) => [p.space, ...(p.holders ?? []).map((h) => h.space)])).reduce((n, s) => n + (s?.used ?? 0), 0);
  return (
    <>
      <HelpBox terms="디스크 (disk) · 파티션 표 (partition table) · 포맷 (format, ext4) · 마운트 (mount) · 다른 장치가 사용 중 (LVM·RAID·암호화 holder)">
        <b>이 화면은</b> 이 서버에 붙은 디스크입니다. 마운트 지점에 따라 시스템 디스크·추가 디스크·미사용 디스크로 나눕니다.{' '}
        {onAction ? '추가·미사용 디스크는 여기서 포맷하고 마운트할 수 있고, 그 위에 저장 경로를 만들 수 있습니다. 디스크 작업은 이 서버 혼자의 일이라 합의(Raft)에 쓰지 않고 서명된 기록에 남깁니다.' : '마운트된 곳에는 저장 경로를 만들 수 있습니다.'}
      </HelpBox>
      {!dev ? (
        <div className="bn info small">
          이 서버가 아직 디스크 목록을 보고하지 않습니다. {refresh}
        </div>
      ) : (
        <>
          <div className="row small muted" style={{ justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
            <span>
              {live ? '실시간 · ' : ''}
              {hhmmss(new Date(dev.observedAt * 1000))} 기준 · 디스크 {disks.length}개{lvm ? ` · LVM 장치 ${lvm}개` : ''} · 시스템 관리자만 바꿀 수 있음
            </span>
            <span className="row" style={{ gap: 12, alignItems: 'center' }}>
              <span>
                합계 {fmtBytes(total)} · 사용 {fmtBytes(used)}
              </span>
              {refresh}
            </span>
          </div>
          {dev.stale && <div className="note wa small">디스크 목록이 오래됐습니다. 서버가 다시 보고하면 바뀝니다.</div>}
          {dev.truncated && <div className="note wa small">디스크가 많아 일부만 보입니다.</div>}
          {GROUPS.map((g) => {
            const list = disks.filter((d) => d.class === g.cls);
            const missing = g.cls === 'additional' ? missingRecords(dev).filter((r) => !disks.some((d) => d.name === r.disk)) : [];
            return (
              <Card key={g.cls} title={g.title} actions={<span className="small muted">{g.sub}</span>}>
                <div className="col" style={{ gap: 12 }}>
                  {!list.length && !missing.length ? <span className="small muted">{g.empty}</span> : list.map((d) => <DiskBox key={d.name} d={d} dev={dev} onMakeRoot={onMakeRoot} onAction={onAction} />)}
                  {missing.map((r) => (
                    <MissingBox key={r.uuid} rec={r} roots={roots} onAction={onAction} />
                  ))}
                </div>
              </Card>
            );
          })}
        </>
      )}
    </>
  );
}
