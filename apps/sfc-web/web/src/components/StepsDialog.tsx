// SPDX-License-Identifier: Apache-2.0

import { useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { newOpId } from '../api/client';
import { toOp } from '../api/endpoints';
import type { DOp } from '../api/dto';
import type { OpView } from '../api/types';
import { Dialog } from './Dialog';
import { Badge, OpBadge } from './ui';
import { MutationError } from './OpPanel';

/** 차례로 보내는 변경 하나. send는 단계마다 고정된 opId로 다시 보낼 수 있어야 한다. */
export type Step = { key: string; label: string; send: (opId: string) => Promise<{ op: DOp }>; op?: OpView; error?: unknown };

/**
 * 여러 작업을 위에서부터 차례로 보내고, 하나가 적용되지 않으면 멈춘다.
 * 응답을 잃은(결과 모름) 단계는 같은 opId로, 거절·실패한 단계는 새 opId로 다시 보낸다.
 */
export function StepsDialog({ title, steps: initial, intro, action, renderError, casText, onClose, onDone, width = 560 }: { title: string; steps: Step[]; intro?: ReactNode; action?: string; renderError?: (e: unknown) => ReactNode | undefined; casText?: string; onClose: () => void; onDone: () => void; width?: 420 | 560 | 720 }) {
  const [steps, setSteps] = useState(initial);
  const ids = useRef<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const finished = steps.every((s) => s.op?.state === 'applied');
  const run = async () => {
    setBusy(true);
    const next = [...steps];
    for (let i = 0; i < next.length; i++) {
      if (next[i].op?.state === 'applied') continue;
      const id = (ids.current[next[i].key] ??= newOpId());
      try {
        const r = await next[i].send(id);
        next[i] = { ...next[i], op: toOp(r.op), error: undefined };
      } catch (e) {
        next[i] = { ...next[i], error: e };
      }
      setSteps([...next]);
      if (next[i].op?.state !== 'applied') break;
    }
    for (const s of next) if (s.op && s.op.state !== 'applied' && s.op.state !== 'unknown') delete ids.current[s.key];
    setBusy(false);
    if (next.every((s) => s.op?.state === 'applied')) onDone();
  };
  return (
    <Dialog
      title={title}
      onClose={onClose}
      width={width}
      footer={
        finished ? (
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        ) : (
          <>
            <button className="btn" onClick={onClose}>
              취소
            </button>
            <button className="btn primary" disabled={busy} onClick={() => void run()}>
              {steps.some((s) => s.op || s.error) ? '남은 변경 다시 보내기' : (action ?? `적용 (${steps.length}건)`)}
            </button>
          </>
        )
      }
    >
      {intro}
      <span className="small muted">위에서부터 차례로 보내고, 하나가 적용되지 않으면 멈춥니다.</span>
      <div className="col" style={{ gap: 8 }}>
        {steps.map((s) => (
          <div key={s.key} className="col" style={{ gap: 4 }}>
            <span className="row" style={{ gap: 8 }}>
              {s.op ? <OpBadge state={s.op.state} /> : <Badge tone="un">대기</Badge>}
              <span>{s.label}</span>
            </span>
            {s.error !== undefined && (renderError?.(s.error) ?? <MutationError error={s.error} />)}
            {s.op && s.op.state !== 'applied' && (
              <span className="small muted">
                {s.op.state === 'failed' && s.op.resultCode === 1 ? (casText ?? '그 사이 다른 사람이 바꿨습니다. 창을 닫고 새로 읽은 뒤 다시 검토하세요. ') : ''}
                <Link to={`/system/ops?focus=${encodeURIComponent(s.op.id)}`}>작업 기록에서 보기</Link>
              </span>
            )}
          </div>
        ))}
      </div>
    </Dialog>
  );
}
