// SPDX-License-Identifier: Apache-2.0

// 결과를 모르는 작업(오류·unknown·pending·running)은 새 작업 ID로 다시 내지 않고 같은 ID로 다시 보낸다.
// 새 ID는 failed·rejected로 끝난 뒤에만 쓴다.
import type { useMutation } from '../components/OpPanel';

export type Mut = ReturnType<typeof useMutation>;
export const uncertain = (m: Mut) => m.error !== undefined || (!!m.op && ['unknown', 'pending', 'running'].includes(m.op.state));
export const ended = (m: Mut) => !!m.op && (m.op.state === 'failed' || m.op.state === 'rejected');
export async function sendOnce(m: Mut, path: string, body: Record<string, unknown>, method: 'PUT' | 'DELETE' | 'POST') {
  if (uncertain(m)) {
    await m.again();
    return undefined;
  }
  if (ended(m)) m.reset();
  return m.run(path, body, method);
}
