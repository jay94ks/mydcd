// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState, type ReactNode } from 'react';
import { ApiError } from '../api/client';
import type { Loaded } from '../lib/usePoll';
import { hhmmss } from '../lib/format';

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="skeleton" aria-busy="true" aria-label="불러오는 중">
      {Array.from({ length: rows }, (_, i) => (
        <i key={i} style={{ width: `${90 - ((i * 13) % 30)}%` }} />
      ))}
    </div>
  );
}

/** ㉘ 빈 상태: 처음 / 조건 결과 없음 / 권한·범위 */
export function Empty({ kind = 'first', title, children, action }: { kind?: 'first' | 'filtered' | 'scope'; title: ReactNode; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="state" data-kind={kind}>
      <b>{title}</b>
      {children && <span>{children}</span>}
      {action}
    </div>
  );
}

const CODE_TEXT: Record<string, string> = {
  denied: '권한이 없거나 대상이 없습니다',
  'key-login-disabled': '이 웹 앱은 개인 키 로그인을 꺼 두었습니다. 비밀번호나 토큰으로 로그인하세요',
  invalid: '입력이 맞지 않습니다',
  rejected: 'sfcd가 실행 전에 거절했습니다',
  'invalid-certificate': 'sfcd가 체인이나 키를 받지 않았습니다',
  unavailable: '지금은 클러스터가 응답할 수 없습니다(합의 없음 등)',
  unknown: '결과를 확인하지 못했습니다',
  expired: '요청 보존 시간이 지났습니다',
  'not-leader': '리더가 아닌 서버가 받았습니다',
  'ledger-full': '요청 기록 공간이 부족합니다',
  'session-expired': '세션이 만료됐습니다',
  'not-session-issuer': '이 서버는 로그인을 발급하지 않습니다(투표 서버가 아님)',
  disconnected: 'sfcd 연결이 끊겼습니다',
  'op-conflict': '같은 작업 ID에 다른 내용이 보내졌습니다',
  'condition-failed': '그사이 버전이 바뀌었습니다',
  csrf: '요청 확인 헤더가 없습니다',
  'not-found': '찾지 못했습니다',
  exists: '같은 이름의 파일이 이미 있습니다',
  'limit-user-temp': '내 임시 단독 컨테이너 수가 상한(8개)에 닿았습니다',
  'limit-tenant': '작업 공간 단독 컨테이너 수가 상한(32개)에 닿았습니다',
  'limit-node': '이 서버의 단독 컨테이너 수가 상한(서버당 64개)에 닿았습니다. 다른 서버를 고르세요',
  HOST_PORT_CONFLICT: '이 서버에서 이미 쓰는 서버 포트입니다. 다른 포트를 적거나 비워서 서버가 고르게 하세요',
  'host-port-conflict': '이 서버에서 이미 쓰는 서버 포트입니다. 다른 포트를 적거나 비워서 서버가 고르게 하세요',
  INVALID_PUBLISHED_PORTS: 'ports 값을 읽을 수 없습니다(컨테이너 포트·서버 포트·받을 주소·프로토콜 tcp/udp)',
  'volume-file-unknown': '처리 결과를 확인하지 못했습니다. 다시 보내면 같은 작업으로 이어 갑니다',
  'volume-file-mismatch': '받은 파일이 서버가 알려 준 길이·digest와 맞지 않습니다',
  transport: '웹 서버에 연결하지 못했습니다',
  'bad-request': '요청 모양이 맞지 않습니다',
  'confirm-mismatch': '확인용 입력이 맞지 않습니다',
  'ticket-expired': '로그인 확인 시간이 지났습니다. 처음부터 다시 해 주세요',
  settled: '이미 결과가 확정된 작업입니다',
  'system-range': '10.254.0.0/16은 시스템 망(sfc-system)이 쓰는 대역이라 쓸 수 없습니다',
  'bad-payload': '입력한 칸이 이 동작의 형식과 맞지 않습니다. 없는 칸이 있거나, 통째로 바꾸는 칸이 빠졌습니다',
  'system-range-overlap': '시스템 망(sfc-system) 대역과 겹쳐 sfcd가 거절했습니다. 시스템 망 대역이 바뀌었을 수 있으니 다른 CIDR을 고르세요',
  'cursor-expired': '목록 위치가 만료됐습니다. 처음부터 다시 읽어 주세요',
  missing: '찾지 못했습니다',
  unsupported: '아직 지원하지 않는 기능입니다',
  timeout: '응답 시간이 지났습니다',
  'digest-mismatch': '미리보기 뒤 app.yaml이 바뀌었습니다. 다시 미리보기 해 주세요',
  'upload-missing': '이어 올릴 업로드가 사라졌습니다. 새로 배포해 주세요',
  job: '배포 묶음에는 결과 조회·재개가 없습니다',
};

export function errorText(e: unknown): { code: string; title: string; message: string } {
  if (e instanceof ApiError) return { code: e.code, title: CODE_TEXT[e.code] ?? e.code, message: e.body.message ?? '' };
  const m = (e as Error)?.message ?? String(e);
  return { code: 'client', title: '화면 오류', message: m };
}

/** ㉚ 오류 띠: 무엇이·왜(코드)·기준 시각·다음 행동, 원문은 '자세히' */
export function ErrorBand({ error, what = '불러오지 못했습니다', onRetry, at }: { error: unknown; what?: string; onRetry?: () => void; at?: Date }) {
  const t = errorText(error);
  const raw = error instanceof ApiError ? JSON.stringify(error.body, null, 2) : t.message;
  return (
    <div className="errband" role="alert">
      <span className="title">{what}</span>
      <span>
        {t.title} <code>({t.code})</code>
        {t.message && t.message !== t.title ? ` · ${t.message}` : ''}
        {at ? <span className="muted"> · {hhmmss(at)} 기준</span> : null}
      </span>
      <div className="row">
        {onRetry && (
          <button type="button" className="btn sm" onClick={onRetry}>
            다시 시도
          </button>
        )}
        <details>
          <summary className="small muted">자세히</summary>
          <pre className="mono">{raw}</pre>
        </details>
      </div>
    </div>
  );
}

/** 불러오는 중 · 오류 · 내용을 같은 틀로. 다시 읽는 동안은 내용을 유지하고 진행 막대를 보인다. */
export function Load<T>({ q, children, what, rows }: { q: Loaded<T>; children: (data: T) => ReactNode; what?: string; rows?: number }) {
  const [slow, setSlow] = useState(false);
  useEffect(() => {
    if (!q.loading) {
      setSlow(false);
      return;
    }
    const t = setTimeout(() => setSlow(true), 10_000);
    return () => clearTimeout(t);
  }, [q.loading]);

  if (q.data === undefined) {
    if (q.error) return <ErrorBand error={q.error} what={what} onRetry={q.refresh} />;
    return (
      <div className="col">
        <Skeleton rows={rows} />
        {slow && <span className="small muted">응답을 10초 넘게 기다리고 있습니다(sfcd 조회).</span>}
      </div>
    );
  }
  return (
    <>
      {q.loading && <div className="progress-line" aria-hidden="true" />}
      {q.error ? <ErrorBand error={q.error} what="다시 읽지 못해 이전 내용을 보여 줍니다" onRetry={q.refresh} at={q.asOf} /> : null}
      {children(q.data)}
    </>
  );
}
