// SPDX-License-Identifier: Apache-2.0

// 저장 안 한 입력 지키기 (캔버스 v224 UnsavedGuard ㉝). 모든 편집 폼이 같은 확인 창·초안·표시를 쓴다.
// - 다른 화면으로 갈 때(메뉴·링크·뒤로 가기) 바뀐 칸이 있으면 확인 창. 탭을 닫거나 새로 고치면 브라우저 기본 확인 창.
// - 제목 옆 '저장 안 됨 · 칸 n개' 배지, 브라우저 탭 제목 앞 '•'.
// - 초안은 이 브라우저에 7일. 비밀 값이 든 폼은 초안을 남기지 않고(draft 없이 부름) 경고만 한다.
import { useEffect, useState, type ReactNode } from 'react';
import { useBlocker } from 'react-router-dom';
import { useSession } from '../auth/session';
import { clearDraft, loadDraft, saveDraft } from '../lib/drafts';
import { fmtTime } from '../lib/format';
import { Dialog } from './Dialog';
import { Badge } from './ui';

export interface DraftRecord<T> {
  value: T;
  at: string;
  rev?: number;
  count?: number;
}

export interface UnsavedOptions<T> {
  dirty: boolean;
  /** 확인 창에 쓰는 이름(예: 'php-shop 앱 편집') */
  what: string;
  /** 바뀐 칸 수(배지·확인 창) */
  count?: number;
  /** 바뀐 칸 설명(예: '이미지, 환경 변수 2개') */
  detail?: string;
  /** 바뀐 것을 세는 단위(기본 '칸') */
  unit?: string;
  /** 초안 자리. 없으면 초안을 남기지 않는다(비밀 값이 든 폼) */
  draft?: { kind: string; scope: string; value: T; rev?: number };
  /** 초안 없이 부를 때 확인 창 아래 줄(기본: 비밀 값이 있어 초안을 남기지 않는다) */
  noDraft?: string;
}

let dirtyForms = 0;
const baseTitle = () => document.title.replace(/^• /, '');
function markTitle() {
  try {
    document.title = dirtyForms > 0 ? `• ${baseTitle()}` : baseTitle();
  } catch {
    /* 문서 없이 도는 테스트 */
  }
}

/** 초안 읽기·지우기(화면이 처음 열릴 때 띠를 보이려고) */
export function useStoredDraft<T>(kind: string, scope: string | undefined) {
  const me = useSession().user.username;
  const [d, setD] = useState<DraftRecord<T> | undefined>(() => (scope ? loadDraft<DraftRecord<T>>(me, kind, scope) : undefined));
  const drop = () => {
    if (scope) clearDraft(me, kind, scope);
    setD(undefined);
  };
  return { draft: d && d.value !== undefined ? d : undefined, drop };
}

export function useUnsaved<T>(o: UnsavedOptions<T>): { guard: ReactNode; badge: ReactNode; clear: () => void } {
  const me = useSession().user.username;
  const blocker = useBlocker(({ currentLocation, nextLocation }) => o.dirty && currentLocation.pathname !== nextLocation.pathname);
  useEffect(() => {
    if (!o.dirty) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener('beforeunload', warn);
    dirtyForms++;
    markTitle();
    return () => {
      window.removeEventListener('beforeunload', warn);
      dirtyForms--;
      markTitle();
    };
  }, [o.dirty]);
  const unit = o.unit ?? '칸';
  const clear = () => o.draft && clearDraft(me, o.draft.kind, o.draft.scope);
  const guard =
    blocker.state === 'blocked' ? (
      <Dialog
        title="저장하지 않은 변경이 있습니다"
        width={560}
        onClose={() => blocker.reset()}
        footer={
          <>
            <button type="button" className="btn" onClick={() => blocker.reset()} autoFocus>
              머무르기
            </button>
            {o.draft && (
              <button type="button"
                className="btn"
                onClick={() => {
                  const d = o.draft!;
                  saveDraft(me, d.kind, d.scope, { value: d.value, rev: d.rev, count: o.count });
                  blocker.proceed();
                }}
              >
                나가기 (초안 남김)
              </button>
            )}
            <button type="button"
              className="btn danger"
              onClick={() => {
                clear();
                blocker.proceed();
              }}
            >
              버리고 나가기
            </button>
          </>
        }
      >
        <p className="small">
          {o.what}에서 {o.count ? `바꾼 ${unit} ${o.count}개${o.detail ? `(${o.detail})` : ''}가` : '바꾼 내용이'} 아직 저장되지 않았습니다.
        </p>
        <p className="small muted">{o.draft ? '나가도 이 브라우저에 초안으로 남아, 다시 열면 이어서 할 수 있습니다.' : (o.noDraft ?? '이 폼에는 비밀 값이 있어 초안을 남기지 않습니다. 나가면 입력이 사라집니다.')}</p>
      </Dialog>
    ) : null;
  const badge = o.dirty ? <Badge tone="wa">저장 안 됨{o.count ? ` · ${unit} ${o.count}개` : ''}</Badge> : null;
  return { guard, badge, clear };
}

/** 다시 열었을 때 초안 띠. 초안 뒤에 대상이 바뀌었으면(rev) 알린다 */
export function DraftBand<T>({ draft, what, rev, unit = '칸', onResume, onDiscard }: { draft: DraftRecord<T>; what: string; rev?: number; unit?: string; onResume: () => void; onDiscard: () => void }) {
  const moved = draft.rev !== undefined && rev !== undefined && draft.rev !== rev;
  return (
    <div className="note wa small" role="status">
      지난번에 저장하지 않은 입력이 있습니다 · {fmtTime(draft.at)}
      {draft.count ? ` · ${unit} ${draft.count}개` : ''}.{' '}
      <button type="button" className="linkish" onClick={onResume}>
        이어서 하기
      </button>{' '}
      ·{' '}
      <button type="button" className="linkish" onClick={onDiscard}>
        버리기
      </button>
      {moved && (
        <div style={{ marginTop: 4 }}>
          초안을 만든 뒤 {what}이 바뀌었습니다(rev {draft.rev} → {rev}). 이어서 하면 지금 값 위에 내 변경을 다시 얹어 변경 검토에서 차이를 보여 줍니다.
        </div>
      )}
    </div>
  );
}

/** 두 글에서 다른 줄 수(yaml 편집의 '바뀐 줄') */
export function changedLines(a: string, b: string): number {
  const x = a.split('\n');
  const y = b.split('\n');
  let n = 0;
  for (let i = 0; i < Math.max(x.length, y.length); i++) if (x[i] !== y[i]) n++;
  return n;
}
