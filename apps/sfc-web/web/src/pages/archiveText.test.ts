// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { DVolumeArchive } from '../api/dto';
import { archiveFailure, archiveIdProblem, canArchive, currentArchive, restoreState } from './archiveText';
import { purgeVolumeSteps, type VolLine } from './ArchivedApps';

const arc = (id: string, phase: string, extra: Partial<DVolumeArchive> = {}): DVolumeArchive => ({ id, node: 'node-a', store: 'default', phase, compression: 'zstd', maxBytes: 1, revision: 1, ...extra });
const vol = (name: string) => ({ key: name, name, kind: 'shared' as const, node: 'node-a', consumers: 0, retain: true, revision: 1, retained: [] });

describe('데이터 보관 문구와 판단 (#920)', () => {
  it('보관 이름은 소문자로 시작해야 한다(캔버스의 날짜 기본값은 서버가 거절)', () => {
    expect(archiveIdProblem('')).toBeUndefined();
    expect(archiveIdProblem('a-2026-11-28')).toBeUndefined();
    expect(archiveIdProblem('2026-11-28-1512')).toBe('소문자로 시작해야 합니다');
    expect(archiveIdProblem('a_b')).toBe('소문자·숫자·-만 쓸 수 있습니다');
    expect(archiveIdProblem('a'.repeat(62))).toBe('61자까지 쓸 수 있습니다');
  });
  it('저장소를 잡은 보관을 먼저, 없으면 마지막 기록', () => {
    const rows = [arc('a-1', 'Archived'), arc('a-2', 'Failed')];
    expect(currentArchive('a-1', rows)?.id).toBe('a-1');
    expect(currentArchive(undefined, rows)?.id).toBe('a-2');
    expect(currentArchive(undefined, [])).toBeUndefined();
  });
  it('정상 종료가 아니어서 실패하면 다시 보관할 수 없고, 확인 실패면 다시 보관한다', () => {
    expect(canArchive(undefined)).toBe(true);
    expect(canArchive(arc('a', 'Failed', { failure: 'unclean-exit' }))).toBe(false);
    expect(canArchive(arc('a', 'Failed', { failure: 'verify-failed' }))).toBe(true);
    expect(canArchive(arc('a', 'Packing'))).toBe(false);
    expect(canArchive(arc('a', 'Archived'))).toBe(false);
    expect(canArchive(arc('a', 'Restored'))).toBe(true);
  });
  it('실패 사유는 코드로 만들고, 모르는 코드는 일반 문구', () => {
    expect(archiveFailure('unclean-exit').title).toBe('정상 종료가 아님');
    expect(archiveFailure('verify-failed').text).toContain('다시 보관할 수 있습니다');
    expect(archiveFailure('zzz').title).toBe('처리하지 못함');
  });
  it('되살리기: 다시 Archived가 되고 revision이 오르면 실패', () => {
    expect(restoreState(arc('a', 'Archived', { revision: 3 }), undefined)).toBe('idle');
    expect(restoreState(arc('a', 'Archived', { revision: 3 }), 3)).toBe('running');
    expect(restoreState(arc('a', 'Restoring', { revision: 4 }), 3)).toBe('running');
    expect(restoreState(arc('a', 'Archived', { revision: 5, failure: 'package-damaged' }), 3)).toBe('failed');
    expect(restoreState(arc('a', 'Restored', { revision: 5 }), 3)).toBe('done');
  });
  it('완전 삭제의 데이터 단계: 취소 → 지우기, 보관본 지우기 → 지우기, 지워진 저장소는 건너뜀', () => {
    const lines: VolLine[] = [
      { name: 'thumbs', vol: vol('thumbs'), archive: arc('a-t', 'Packing') },
      { name: 'uploads', vol: vol('uploads'), archive: arc('a-u', 'Archived', { dataBytes: 1024 }) },
      { name: 'cache', vol: vol('cache') },
      { name: 'gone', gone: true },
    ];
    const steps = purgeVolumeSteps('shop', { key: 'k', tenant: 'shop', app: 'media-old', version: 1, digest: '', downBy: 'a', downAt: '', downOp: '', volumes: [], lines });
    expect(steps.map((s) => s.key)).toEqual(['thumbs/cancel', 'thumbs/delete', 'uploads/discard', 'uploads/delete', 'cache/delete']);
  });
});
