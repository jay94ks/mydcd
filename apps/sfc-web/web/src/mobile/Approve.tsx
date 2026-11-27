// SPDX-License-Identifier: Apache-2.0

// 휴대폰 승인 공통 (캔버스 UI-M5): 아래에 늘 붙는 반려·승인 막대와, 영향이 '보통' 이상일 때 한 번 더 묻는 확인 시트.
import type { ReactNode } from 'react';
import { useSession } from '../auth/session';
import { Sheet } from './Sheet';
import { useOffline } from './MobileShell';

export type ImpactLevel = 'low' | 'medium' | 'high';
export const IMPACT_KO: Record<ImpactLevel, string> = { low: '낮음', medium: '보통', high: '높음' };
/** 영향이 보통 이상이면 휴대폰에서 확인 시트를 한 번 더 띄운다 (데스크톱은 그대로) */
export const needsConfirm = (impact?: ImpactLevel) => impact !== 'low';

export function ApproveBar({
  note,
  onReject,
  onApprove,
  approveLabel = '승인하고 실행',
  rejectLabel = '반려',
  disabled,
  busy,
  extra,
}: {
  /** 단추 위 주황 글자: 왜 아직 실행할 수 없는지 */
  note?: ReactNode;
  onReject?: () => void;
  onApprove: () => void;
  approveLabel?: string;
  rejectLabel?: string;
  disabled?: boolean;
  busy?: boolean;
  extra?: ReactNode;
}) {
  const offline = useOffline();
  return (
    <div className="m-stick">
      {(note || offline) && <div className="m-stick-note">{offline ? '연결이 돌아오면 승인할 수 있습니다' : note}</div>}
      <div className="mbar" style={note || offline ? { borderTop: 0 } : undefined}>
        {onReject && (
          <button type="button" className="mbtn fl dng" disabled={busy || offline} onClick={onReject}>
            {rejectLabel}
          </button>
        )}
        {extra}
        <button type="button" className="mbtn fl pri" disabled={disabled || busy || offline} onClick={onApprove}>
          {busy ? '보내는 중…' : approveLabel}
        </button>
      </div>
    </div>
  );
}

export function ConfirmApproveSheet({
  what,
  impact,
  onClose,
  onConfirm,
  busy,
  title = '승인하고 실행할까요?',
  action = '승인하고 실행',
}: {
  what: ReactNode;
  impact: ImpactLevel;
  onClose: () => void;
  onConfirm: () => void;
  busy?: boolean;
  title?: string;
  action?: string;
}) {
  const session = useSession();
  return (
    <Sheet
      title={title}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="mbtn" onClick={onClose} disabled={busy}>
            취소
          </button>
          <button type="button" className="mbtn pri" onClick={onConfirm} disabled={busy}>
            {busy ? '보내는 중…' : action}
          </button>
        </>
      }
    >
      <dl className="mkv">
        <dt>작업</dt>
        <dd>{what}</dd>
        <dt>영향</dt>
        <dd>{IMPACT_KO[impact]}</dd>
        <dt>서명</dt>
        <dd>{session.user.username} · 세션 키</dd>
      </dl>
      <div className="bn info">한 번 더 묻는 것은 영향이 ‘보통’ 이상이라서입니다. 낮음이면 바로 실행합니다.</div>
    </Sheet>
  );
}
