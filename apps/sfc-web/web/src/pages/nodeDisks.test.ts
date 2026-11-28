// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { canFormat, diskNameError, diskState, mountableParts, mountPathError, rootCandidates, rootIdFor, unmountBlock } from './NodeDisks';
import { diskOpText } from './DiskActions';
import type { DBlockDisk, DNodeDevices } from '../api/dto';

const disk = (cls: string, parts: DBlockDisk['parts'], extra: Partial<DBlockDisk> = {}): DBlockDisk => ({ name: 'sdb', class: cls, size: 1, parts, ...extra });

describe('디스크 탭 (#689, 캔버스 NodeDisks)', () => {
  it('저장 경로 후보: 마운트와 LVM 위 마운트, 스왑·/boot·읽기 전용·미사용은 빼고 / 는 /srv/sfc', () => {
    const d = disk('additional', [
      { name: 'sdb1', number: 1, size: 1, mounts: ['/var/lib/sfc-disks/data1'], storageRoots: ['data1'] },
      { name: 'sdb2', number: 2, size: 1, holders: [{ name: 'dm-0', kind: 'lvm', mounts: ['/mnt/media'] }] },
      { name: 'sdb3', number: 3, size: 1, swap: true },
    ]);
    expect(rootCandidates(d)).toEqual(['/var/lib/sfc-disks/data1', '/mnt/media']);
    const sys = disk('system', [{ name: 'p1', number: 1, size: 1, mounts: ['/boot/efi'] }, { name: 'p2', number: 2, size: 1, mounts: ['/'] }], { locked: true });
    expect(rootCandidates(sys)).toEqual(['/srv/sfc']);
    expect(rootCandidates({ ...d, readOnly: true })).toEqual([]);
    expect(rootCandidates(disk('unused', [{ name: 'sdh1', number: 1, size: 1, fsType: 'ext4' }]))).toEqual([]);
  });
  it('상태 배지', () => {
    expect(diskState(disk('unused', []))[1]).toBe('빈 디스크');
    expect(diskState(disk('unused', [{ name: 'sdh1', number: 1, size: 1, fsType: 'ext4' }]))[1]).toBe('마운트 안 됨 · 파일시스템 있음');
    expect(diskState(disk('unused', [{ name: 'sde1', number: 1, size: 1, fsType: 'LVM2_member', holders: [{ name: 'dm-0', kind: 'lvm' }] }]))[1]).toBe('다른 장치가 사용 중');
    expect(diskState(disk('additional', []))[1]).toBe('마운트됨');
  });
  it('마운트 위치 검사: sfcd ValidDiskMountPath와 같게 + 다른 마운트 안·위 안 됨', () => {
    const dev: DNodeDevices = { node: 'n', observedAt: 0, disks: [disk('additional', [{ name: 'sdb1', number: 1, size: 1, mounts: ['/srv/backup'] }])], recorded: [{ uuid: 'u', path: '/var/lib/sfc-disks/media', disk: 'sdd', part: 'sdd1', reason: 'disk-not-found' }] };
    expect(mountPathError('/var/lib/sfc-disks/fast1', dev)).toBeUndefined();
    expect(mountPathError('/data/x', dev)).toBeUndefined();
    for (const bad of ['', 'rel', '/', '/a//b', '/a/../b', '/a/', '/a b'])
      expect(mountPathError(bad, dev)).toBeDefined();
    for (const sys of ['/etc/x', '/var/lib/sfc/x', '/var/lib/sfe', '/usr', '/var', '/srv', '/mnt'])
      expect(mountPathError(sys, dev)).toMatch(/시스템/);
    expect(mountPathError('/srv/backup/x', dev)).toMatch(/다른 마운트/);
    expect(mountPathError('/var/lib/sfc-disks/media', dev)).toMatch(/다른 마운트/);
  });
  it('이름·저장 경로 ID', () => {
    expect(diskNameError('fast1')).toBeUndefined();
    expect(diskNameError('Fast')).toBeDefined();
    expect(diskNameError('a'.repeat(17))).toBeDefined();
    expect(rootIdFor('/var/lib/sfc-disks/old-backup', 'sdh1')).toBe('old-backup');
    expect(rootIdFor('/data/My_Disk', 'sdh1')).toBe('my-disk');
    expect(rootIdFor('/data/123', 'sdh1')).toBe('sdh1');
  });
  it('포맷 펜스·마운트할 파티션·마운트 풀기 막는 것', () => {
    expect(canFormat(disk('unused', [], { serial: 'S1' }))).toBe(true);
    expect(canFormat(disk('unused', []))).toBe(false);
    expect(canFormat(disk('system', [], { serial: 'S1', locked: true }))).toBe(false);
    expect(canFormat(disk('unused', [{ name: 'sde1', number: 1, size: 1, holders: [{ name: 'dm-0', kind: 'lvm' }] }], { serial: 'S1' }))).toBe(false);
    const fs = disk('unused', [
      { name: 'sdh1', number: 1, size: 1, fsType: 'ext4', uuid: 'a' },
      { name: 'sdh2', number: 2, size: 1, fsType: 'xfs', uuid: 'b' },
      { name: 'sdh3', number: 3, size: 1, fsType: 'ext4' },
    ]);
    expect(mountableParts(fs).map((p) => p.name)).toEqual(['sdh1']);
    const p = { name: 'sdc1', number: 1, size: 1, uuid: 'u1', mounts: ['/var/lib/sfc-disks/fast1'], storageRoots: [] };
    const dev: DNodeDevices = { node: 'n', observedAt: 0, disks: [], recorded: [{ uuid: 'u1', path: '/var/lib/sfc-disks/fast1', disk: 'sdc', part: 'sdc1' }] };
    expect(unmountBlock(dev, p)).toEqual({ roots: [], runtime: [], fstab: false, fuse: [] });
    expect(unmountBlock({ ...dev, bundles: [{ name: 'pool3', backend: 'fuse', mode: 'linear', size: 1, state: 'ok', syncPercent: 0, members: [{ disk: 'x', part: p.name, state: 'ok' }] }] }, p).fuse).toEqual(['pool3']);
    expect(unmountBlock({ ...dev, recorded: [] }, p).fstab).toBe(true);
    expect(unmountBlock(dev, { ...p, storageRoots: ['data1'] }).roots).toEqual(['data1']);
  });
  it('거절 문구', () => {
    expect(diskOpText({ operation: 'o', node: 'n', action: 'format', user: 'u', disk: 'sdh', state: 'failed', step: 'format', code: 'changed' })).toBe('sdh 포맷을 거절했습니다: 화면을 본 뒤 디스크가 바뀌었습니다.');
    expect(diskOpText({ operation: 'o', node: 'n', action: 'forget', user: 'u', disk: 'sdd', state: 'failed', step: 'record', code: 'interrupted' })).toMatch(/기록 지우기를 .*마지막 단계: record/);
  });
});
