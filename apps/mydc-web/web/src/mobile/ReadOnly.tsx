// SPDX-License-Identifier: Apache-2.0

// 휴대폰 보기만 화면의 공통 조각 (캔버스 UI-M11 ③ ④): 위쪽 막대의 '보기만' 한 줄 · 요약 칸 · 카드 목록.
// 바꾸기는 모두 넓은 화면에서 하고, 이 화면들은 읽기만 한다.
import { Fragment, type ReactNode } from 'react';
import { Badge, type Tone } from '../components/ui';
import { useMobileTop, type MobileTop } from './top';

/** 위쪽 막대: 제목 · 부제 · '보기만 · {wide}' 한 줄 */
export function useReadOnlyTop(title: string, sub: ReactNode | undefined, wide: string, deps: unknown[] = [], extra?: Partial<MobileTop>) {
  useMobileTop({ title, sub, wide, ...extra }, [title, wide, ...deps]);
}

export interface MTile {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  warn?: boolean;
}
/** 요약 칸 (두 칸씩) */
export function MTiles({ items }: { items: MTile[] }) {
  return (
    <div className="mtiles">
      {items.map((t) => (
        <div key={t.label} className="mtile">
          <small>{t.label}</small>
          <b style={t.warn ? { color: '#8A3300' } : undefined}>{t.value}</b>
          {t.sub !== undefined && <span>{t.sub}</span>}
        </div>
      ))}
    </div>
  );
}

export interface MCardSpec {
  key: string;
  title: ReactNode;
  badge?: [Tone, ReactNode];
  /** 머리 오른쪽에 배지 대신 둘 글 (경로 등) */
  aside?: ReactNode;
  lines?: ReactNode[];
  /** 흐린 셋째 줄 */
  meta?: ReactNode;
  tone?: 'er' | 'wa';
  onOpen?: () => void;
}
/** 카드 목록. onOpen이 있으면 누를 수 있다 */
export function MCards({ items, empty }: { items: MCardSpec[]; empty: string }) {
  if (!items.length) return <span className="muted small">{empty}</span>;
  return (
    <>
      {items.map((c) => {
        const cls = `mc${c.tone === 'er' ? ' xer' : c.tone === 'wa' ? ' xwa' : ''}`;
        const body = (
          <>
            <div className="hd">
              <b>{c.title}</b>
              {c.badge ? (
                <Badge tone={c.badge[0]}>{c.badge[1]}</Badge>
              ) : c.aside !== undefined ? (
                <span className="muted mono" style={{ fontSize: 12, textAlign: 'right' }}>
                  {c.aside}
                </span>
              ) : null}
            </div>
            {(c.lines ?? []).filter((l) => l !== undefined && l !== null && l !== false && l !== '').map((l, i) => (
              <div key={i} className="ln">
                {l}
              </div>
            ))}
            {c.meta !== undefined && (
              <div className="ln muted" style={{ fontSize: 12 }}>
                {c.meta}
              </div>
            )}
          </>
        );
        return c.onOpen ? (
          <button key={c.key} type="button" className={cls} style={{ textAlign: 'left', font: 'inherit' }} onClick={c.onOpen}>
            {body}
          </button>
        ) : (
          <div key={c.key} className={cls}>
            {body}
          </div>
        );
      })}
    </>
  );
}

/** 맨 아래 흐린 안내 한 줄 */
export const MWideNote = ({ children }: { children: ReactNode }) => (
  <span className="muted small" style={{ textAlign: 'center' }}>
    {children}
  </span>
);

export type MRow = [ReactNode, ReactNode] | false | null | undefined | '' | 0;
/** 상세 카드 (UI-M1 '보기만 화면의 상세 · 하위 탭'): 머리 + 이름·값 두 칸 */
export function MDetail({ title, badge, rows, children, tone }: { title?: ReactNode; badge?: [Tone, ReactNode]; rows: MRow[]; children?: ReactNode; tone?: 'er' | 'wa' }) {
  const shown = rows.filter((r): r is [ReactNode, ReactNode] => !!r);
  return (
    <div className={`mc${tone === 'er' ? ' xer' : tone === 'wa' ? ' xwa' : ''}`}>
      {(title !== undefined || badge) && (
        <div className="hd">
          <b>{title}</b>
          {badge && <Badge tone={badge[0]}>{badge[1]}</Badge>}
        </div>
      )}
      {shown.length > 0 && (
        <dl className="mkv">
          {shown.map(([k, v], i) => (
            <Fragment key={i}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </Fragment>
          ))}
        </dl>
      )}
      {children}
    </div>
  );
}

/** 구역 제목 한 줄 */
export const MSec = ({ children, right }: { children: ReactNode; right?: ReactNode }) => (
  <div className="m-sec">
    <span>{children}</span>
    {right}
  </div>
);
