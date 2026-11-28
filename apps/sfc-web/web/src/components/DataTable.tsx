// SPDX-License-Identifier: Apache-2.0

import { useMemo, useState, type ReactNode } from 'react';
import type { Page } from '../api/types';
import { Empty } from './states';
import { hhmmss } from '../lib/format';
import { usePhone } from '../lib/viewport';

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  /** 정렬·찾기에 쓰는 값 */
  value?: (row: T) => string | number;
  width?: string;
  wrap?: boolean;
  /** 휴대폰 카드에서의 자리 (UI-M1 ①): 제목 · 오른쪽 위 배지 · 숨김. 없으면 첫 열이 제목, 나머지는 아래 줄 */
  m?: 'title' | 'badge' | 'hide';
}

/**
 * ⑳~㉒ 리스팅 틀: 도구 막대(찾기·정렬·새로고침) → 선택 시 일괄 작업 막대 → 표 → 바닥 줄.
 * 서버 페이지는 cursor + 같은 기준 버전으로 이어 받는다(숫자 페이지·무한 스크롤 없음).
 */
export function DataTable<T>({
  rows,
  columns,
  rowKey,
  onRowClick,
  selectedKey,
  toolbar,
  bulk,
  emptyTitle = '아직 항목이 없습니다',
  emptyAction,
  searchPlaceholder = '찾기',
  pageInfo,
  onMore,
  pageSize: initialPageSize = 50,
  initialQuery = '',
}: {
  rows: T[];
  columns: Column<T>[];
  rowKey: (r: T) => string;
  onRowClick?: (r: T) => void;
  selectedKey?: string;
  toolbar?: ReactNode;
  bulk?: (selected: T[], clear: () => void) => ReactNode;
  emptyTitle?: string;
  emptyAction?: ReactNode;
  searchPlaceholder?: string;
  pageInfo?: Pick<Page<T>, 'next' | 'revision' | 'asOf'>;
  onMore?: () => void;
  pageSize?: number;
  /** 다른 화면에서 걸러서 들어올 때(예: 저장 경로의 데이터 저장소 보기) */
  initialQuery?: string;
}) {
  const [query, setQuery] = useState(initialQuery);
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [pageIdx, setPageIdx] = useState(0);

  const filtered = useMemo(() => {
    const qq = query.trim().toLowerCase();
    let r = rows;
    if (qq)
      r = r.filter((row) =>
        columns.some((c) => {
          const v = c.value?.(row);
          return v !== undefined && String(v).toLowerCase().includes(qq);
        }),
      );
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col?.value) r = [...r].sort((a, b) => (col.value!(a) > col.value!(b) ? 1 : col.value!(a) < col.value!(b) ? -1 : 0) * sort.dir);
    }
    return r;
  }, [rows, columns, query, sort]);

  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const cur = Math.min(pageIdx, pages - 1);
  const shown = filtered.slice(cur * pageSize, (cur + 1) * pageSize);
  const selected = rows.filter((r) => sel.has(rowKey(r)));
  const phone = usePhone();
  const mTitle = columns.find((c) => c.m === 'title') ?? columns.find((c) => !c.m);
  const mBadge = columns.find((c) => c.m === 'badge');
  const mRest = columns.filter((c) => c !== mTitle && c !== mBadge && c.m !== 'hide');

  return (
    <div className="col" style={{ gap: 8 }}>
      <div className="list-toolbar">
        <input type="search" placeholder={searchPlaceholder} aria-label={searchPlaceholder} value={query} onChange={(e) => (setQuery(e.target.value), setPageIdx(0))} />
        {toolbar}
      </div>
      {bulk && selected.length > 0 && (
        <div className="bulkbar">
          <b>{selected.length}개 선택</b>
          {bulk(selected, () => setSel(new Set()))}
          <span className="grow" />
          <button type="button" className="btn sm ghost" onClick={() => setSel(new Set())}>
            선택 해제
          </button>
        </div>
      )}
      {rows.length === 0 ? (
        <Empty kind="first" title={emptyTitle} action={emptyAction} />
      ) : filtered.length === 0 ? (
        <Empty kind="filtered" title="조건에 맞는 항목이 없습니다" action={<button type="button" className="btn sm" onClick={() => setQuery('')}>찾기 지우기</button>} />
      ) : phone ? (
        <div className="m-col" style={{ gap: 8 }}>
          {shown.map((r) => {
            const k = rowKey(r);
            return (
              <div key={k} className={`mc${selectedKey === k ? ' ap' : ''}`} onClick={onRowClick ? () => onRowClick(r) : undefined} role={onRowClick ? 'button' : undefined}>
                <div className="hd">
                  <b>{mTitle?.render(r)}</b>
                  {mBadge?.render(r)}
                </div>
                {mRest.length > 0 && (
                  <div className="ln">
                    {mRest.map((c, i) => (
                      <span key={c.key}>
                        {i > 0 && ' · '}
                        {c.render(r)}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                {bulk && (
                  <th style={{ width: 36 }}>
                    <input
                      type="checkbox"
                      aria-label="이 페이지 모두 선택"
                      checked={shown.length > 0 && shown.every((r) => sel.has(rowKey(r)))}
                      onChange={(e) => {
                        const n = new Set(sel);
                        shown.forEach((r) => (e.target.checked ? n.add(rowKey(r)) : n.delete(rowKey(r))));
                        setSel(n);
                      }}
                    />
                  </th>
                )}
                {columns.map((c) => (
                  <th key={c.key} style={{ width: c.width }} aria-sort={sort?.key === c.key ? (sort.dir === 1 ? 'ascending' : 'descending') : undefined}>
                    {c.value ? (
                      <button type="button" onClick={() => setSort((s) => (s?.key === c.key ? { key: c.key, dir: s.dir === 1 ? -1 : 1 } : { key: c.key, dir: 1 }))}>
                        {c.header} {sort?.key === c.key ? (sort.dir === 1 ? '▲' : '▼') : ''}
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => {
                const k = rowKey(r);
                return (
                  <tr key={k} className={`${onRowClick ? 'clickable' : ''} ${selectedKey === k ? 'selected' : ''}`} onClick={onRowClick ? () => onRowClick(r) : undefined}>
                    {bulk && (
                      <td onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          aria-label={`${k} 선택`}
                          checked={sel.has(k)}
                          onChange={(e) => {
                            const n = new Set(sel);
                            if (e.target.checked) n.add(k);
                            else n.delete(k);
                            setSel(n);
                          }}
                        />
                      </td>
                    )}
                    {columns.map((c) => {
                      const v = c.value?.(r);
                      return (
                        <td key={c.key} className={c.wrap ? 'wrap' : ''} title={typeof v === 'string' ? v : undefined}>
                          {c.render(r)}
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {rows.length > 0 && (
        <div className="list-foot">
          <span>
            {filtered.length ? `${cur * pageSize + 1}–${Math.min(filtered.length, (cur + 1) * pageSize)}` : 0} / {filtered.length}개
            {pageInfo && ` · 기준 버전 ${pageInfo.revision} · ${hhmmss(pageInfo.asOf)} 기준`}
            {pageInfo?.next && ' · 서버에 더 있음'}
          </span>
          <span className="row">
            <label className="row" style={{ gap: 4 }}>
              한 페이지
              <select value={pageSize} onChange={(e) => (setPageSize(Number(e.target.value)), setPageIdx(0))} style={{ height: 28, fontSize: 12 }}>
                {[25, 50, 100].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" className="btn sm" disabled={cur === 0} onClick={() => setPageIdx(0)}>
              처음
            </button>
            <button type="button" className="btn sm" disabled={cur === 0} onClick={() => setPageIdx(cur - 1)}>
              이전
            </button>
            <button
              type="button"
              className="btn sm"
              disabled={cur >= pages - 1 && !(pageInfo?.next && onMore)}
              onClick={() => (cur < pages - 1 ? setPageIdx(cur + 1) : onMore?.())}
            >
              다음
            </button>
          </span>
        </div>
      )}
    </div>
  );
}
