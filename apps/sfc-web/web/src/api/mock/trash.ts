// SPDX-License-Identifier: Apache-2.0

// 목업: 지운 것 (UI-A5, docs/reference/web-api/53-ops-trash.md). 지우는 곳이 addTrash로 남기고, 되살리기는 남긴 쪽이 준 함수로 한다.
import type { TrashItem, RestoreReply } from '../trash';
import type { RawResponse } from '../client';

export interface Restorer {
  /** 같은 자리에 지금 있는 것(없으면 undefined). name은 다른 이름으로 되살릴 때 */
  current: (name?: string) => unknown;
  /** 웹 자체 정의: 바로 되살린다 */
  put?: (name: string | undefined, replace: boolean) => RestoreReply;
  /** sfcd 정의: 변경으로 보낸다(변경 확정 뒤 목록에서 빠진다) */
  apply?: (name: string | undefined, replace: boolean, opId: string, done: () => void) => RawResponse | undefined;
}
type Entry = { item: TrashItem; r?: Restorer };
const items: Entry[] = [];
let seq = 1;
const DAY = 86400000;
let retentionDays = 7;
export const setTrashRetention = (d: number) => (retentionDays = d > 0 ? d : 7);

/** 지운 정의를 남긴다. 남긴 항목(실행 취소용 id·만료)을 돌려준다 */
export function addTrash(item: Omit<TrashItem, 'id' | 'deletedAt' | 'expiresAt' | 'restore'> & { restore?: TrashItem['restore'] }, r?: Restorer, at = Date.now()) {
  const it: TrashItem = { restore: 'here', ...item, id: `tr-${(seq++).toString(16).padStart(4, '0')}`, deletedAt: new Date(at).toISOString(), expiresAt: new Date(at + retentionDays * DAY).toISOString() };
  items.unshift({ item: it, r });
  return { id: it.id, expiresAt: it.expiresAt! };
}
export const dropTrash = (id: string) => {
  const i = items.findIndex((e) => e.item.id === id);
  if (i >= 0) items.splice(i, 1);
};

type Ctx = {
  on: (method: string, pattern: string, h: (m: string[], body: Record<string, unknown>) => RawResponse) => void;
  ok: (b: unknown, status?: number) => RawResponse;
  err: (status: number, code: string, message?: string) => RawResponse;
  /** 이 항목을 볼 수 있나 */
  sees: (it: TrashItem) => boolean;
  /** 내린 앱처럼 다른 곳에 남은 것(restore: link) */
  extra: () => TrashItem[];
};

export function registerTrash(ctx: Ctx) {
  const { on, ok, err } = ctx;
  const live = () => items.filter((e) => e.item.restore === 'link' || Date.parse(e.item.expiresAt ?? '') > Date.now());
  const find = (id: string) => live().find((e) => e.item.id === id && ctx.sees(e.item));
  on('GET', '/trash', () => ok({ retentionDays, items: [...live().filter((e) => ctx.sees(e.item)).map((e) => e.item), ...ctx.extra()].sort((a, b) => (a.deletedAt < b.deletedAt ? 1 : -1)) }));
  on('GET', '/trash/:id', (m) => {
    const e = find(m[0]);
    return e ? ok({ item: e.item }) : err(404, 'not-found', '없거나 보관 기간이 지났습니다.');
  });
  on('DELETE', '/trash/:id', (m) => {
    const e = find(m[0]);
    if (!e || e.item.restore !== 'here') return err(404, 'not-found', '없거나 보관 기간이 지났습니다.');
    dropTrash(e.item.id);
    return ok(null, 204);
  });
  on('POST', '/trash/:id/restore', (m, b) => {
    const e = find(m[0]);
    if (!e || e.item.restore !== 'here' || !e.r) return err(404, 'not-found', '없거나 보관 기간이 지났습니다.');
    const name = typeof b.name === 'string' && b.name.trim() ? b.name.trim() : undefined;
    const replace = b.replace === true;
    if (name && !/^[a-z0-9_][a-z0-9._-]{0,62}$/.test(name)) return err(422, 'invalid', 'name');
    const cur = e.r.current(name);
    if (cur !== undefined && !replace) return { status: 409, json: { error: { code: 'exists', message: '같은 자리에 지금 다른 것이 있습니다.' }, current: cur } };
    if (e.r.put) {
      const reply = e.r.put(name, replace);
      dropTrash(e.item.id);
      return ok(reply);
    }
    const id = e.item.id;
    const res = e.r.apply?.(name, replace, String(b.opId ?? ''), () => dropTrash(id));
    return res ?? err(422, 'target-gone', '대상이 없습니다.');
  });
}
