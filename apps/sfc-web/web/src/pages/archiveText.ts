// SPDX-License-Identifier: Apache-2.0

// 내린 앱 저장소 보관(#920) 화면 문구와 판단. 화면(ArchivedApps.tsx)과 시험이 같이 쓴다.

import type { DVolumeArchive } from '../api/dto';
import type { Tone } from '../components/ui';

/** 보관 단계 배지. 끝난 단계(Restored·Cancelled·Discarded)는 저장소가 원래 자리에 있다는 뜻이라 배지가 없다 */
export const ARCHIVE_PHASE: Record<string, [Tone, string]> = {
  Packing: ['pr', '묶는 중'],
  Clearing: ['pr', '원래 자리 비우는 중'],
  Archived: ['ok', '보관됨'],
  Restoring: ['pr', '되살리는 중'],
  Cancelling: ['pr', '취소하는 중'],
  Discarding: ['pr', '보관본 지우는 중'],
  Failed: ['er', '보관하지 못함'],
};

/** 끝나 저장소를 다시 놓아준 단계 */
export const ARCHIVE_DONE = new Set(['Restored', 'Cancelled', 'Discarded', 'Failed']);
/** 서버가 일하는 중이라 다른 작업을 보낼 수 없는 단계 */
export const ARCHIVE_BUSY = new Set(['Packing', 'Clearing', 'Restoring', 'Cancelling', 'Discarding']);

/** 보관 실패 사유(failure 코드). 강제로 보관하는 선택지는 두지 않는다 */
const FAILURE: Record<string, [string, string]> = {
  'unclean-exit': ['정상 종료가 아님', '마지막 컨테이너가 정상 종료하지 않아 파일이 온전하지 않을 수 있습니다. 데이터는 원래 자리에 그대로 있습니다. 앱을 다시 올려 정상 종료한 뒤 보관하세요.'],
  'too-large': ['보관 한도를 넘음', '저장소가 보관 한도보다 커서 묶지 못했습니다. 데이터는 원래 자리에 그대로 있습니다.'],
  'pack-failed': ['묶지 못함', '파일을 묶다가 멈췄습니다. 쓰던 보관본은 지웠고 데이터는 원래 자리에 그대로 있습니다. 다시 보관할 수 있습니다.'],
  'verify-failed': ['다시 읽어 확인하지 못함', '보관본을 지우고 저장소는 그대로 두었습니다. 다시 보관할 수 있습니다.'],
  'bad-manifest': ['보관본 목록이 맞지 않음', '보관본의 파일 목록이 맞지 않습니다. 보관본은 그대로 두었습니다.'],
  'no-manifest': ['보관본 목록이 없음', '보관본에서 파일 목록을 찾지 못했습니다. 보관본은 그대로 두었습니다.'],
  'package-damaged': ['보관본이 깨짐', '보관본이 깨졌거나 사라졌습니다. 보관본은 그대로 두었고 저장소는 보관됨 상태입니다.'],
  'restore-failed': ['되살리지 못함', '보관본을 원래 자리로 풀지 못했습니다. 보관본은 그대로 두었고 저장소는 보관됨 상태입니다.'],
};

/** 실패 사유의 짧은 이름과 설명. 모르는 코드는 일반 문구 */
export function archiveFailure(code: string | undefined): { title: string; text: string } {
  const f = code ? FAILURE[code] : undefined;
  return f ? { title: f[0], text: f[1] } : { title: '처리하지 못함', text: '서버가 이 단계를 끝내지 못했습니다. 작업 기록에서 자세한 내용을 보세요.' };
}

/** 저장소를 잡고 있는 보관(archiveID), 없으면 마지막 기록. sfcd는 저장소마다 끝난 기록을 하나만 남긴다 */
export function currentArchive(archiveId: string | undefined, rows: DVolumeArchive[]): DVolumeArchive | undefined {
  if (archiveId) {
    const held = rows.find((a) => a.id === archiveId);
    if (held) return held;
  }
  return rows[rows.length - 1];
}

/** 보관 이름(id): 비우면 서버가 "a-" + opId. 소문자로 시작, 소문자·숫자·-, 61자까지 */
export function archiveIdProblem(id: string): string | undefined {
  if (!id) return undefined;
  if (id.length > 61) return '61자까지 쓸 수 있습니다';
  if (!/^[a-z]/.test(id)) return '소문자로 시작해야 합니다';
  if (!/^[a-z][a-z0-9-]*$/.test(id)) return '소문자·숫자·-만 쓸 수 있습니다';
  return undefined;
}

/** 이 저장소에 "데이터 보관"을 보일 수 있는가. 정상 종료가 아니어서 실패했으면 다시 올리기 전에는 막는다 */
export function canArchive(a: DVolumeArchive | undefined): boolean {
  if (!a) return true;
  if (a.phase === 'Failed') return a.failure !== 'unclean-exit';
  return a.phase === 'Restored' || a.phase === 'Cancelled' || a.phase === 'Discarded';
}

/** 되살리기를 보낸 뒤 이 보관이 어디까지 왔나: 다시 Archived가 됐고 revision이 올랐으면 실패 */
export function restoreState(a: DVolumeArchive | undefined, sentRevision: number | undefined): 'idle' | 'running' | 'done' | 'failed' {
  if (!a) return 'done';
  if (a.phase === 'Restored') return 'done';
  if (a.phase === 'Restoring') return 'running';
  if (sentRevision === undefined) return 'idle';
  if (a.phase === 'Archived' && a.revision > sentRevision) return 'failed';
  return 'running';
}
