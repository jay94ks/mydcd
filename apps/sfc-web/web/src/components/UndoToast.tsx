// SPDX-License-Identifier: Apache-2.0

// 지운 바로 뒤 토스트의 [실행 취소] (캔버스 v226 OpsTrash). 10초 동안 보이고, 되살리기와 같은 요청을 바로 보낸다.
import { useState } from 'react';
import { daysLeft, type TrashRef } from '../api/trash';
import { errorText } from './states';
import { useToast } from './Toast';

function UndoButton({ onUndo, tail }: { onUndo: () => Promise<void>; tail: string }) {
  const [st, setSt] = useState<'' | 'busy' | 'done' | 'fail'>('');
  const [why, setWhy] = useState('');
  if (st === 'done') return <b>되살렸습니다.</b>;
  if (st === 'fail') return <span>되살리지 못했습니다: {why}</span>;
  return (
    <>
      <button
        type="button"
        className="linkish"
        style={{ color: 'inherit', textDecoration: 'underline' }}
        disabled={st === 'busy'}
        onClick={() => {
          setSt('busy');
          onUndo().then(
            () => setSt('done'),
            (e) => (setSt('fail'), setWhy(errorText(e).message)),
          );
        }}
      >
        {st === 'busy' ? '되살리는 중…' : '[실행 취소]'}
      </button>
      {tail}
    </>
  );
}

/** 지운 뒤 알림. ref가 없으면(보관하지 않는 데몬) 보통 알림 */
export function useUndoToast() {
  const toast = useToast();
  return (text: string, ref: TrashRef | undefined | null, undo: (id: string) => Promise<void>) => {
    if (!ref) return toast(text);
    const days = daysLeft(ref.expiresAt);
    toast(
      <span>
        {text} <UndoButton onUndo={() => undo(ref.id)} tail={` · ${days ?? 7}일 동안 작업 기록 › 지운 것에서 되살릴 수 있습니다.`} />
      </span>,
      'info',
      10000,
    );
  };
}
