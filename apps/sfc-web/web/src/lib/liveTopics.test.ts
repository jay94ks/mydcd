// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { ApiError } from '../api/client';
import { appLive, appsLive, dashboardLive, incidentLive, networksLive, notificationsLive, opsLive, patchList, serverLive, serversLive, volumesLive } from './liveTopics';

type Row = { id: string; v: number };

describe('patchList', () => {
  const list: Row[] = [
    { id: 'a', v: 1 },
    { id: 'c', v: 1 },
  ];
  it('reads only the changed rows and keeps the others', async () => {
    const read: string[] = [];
    const out = await patchList(
      list,
      [{ kind: 'tenant', name: 'c' }, { kind: 'tenant', name: 'b' }, { kind: 'tenant', name: 'a', deleted: true }],
      (r) => r.id,
      async (r) => {
        read.push(r.name);
        return { id: r.name, v: 2 };
      },
    );
    expect(read).toEqual(['c', 'b']);
    expect(out).toEqual([
      { id: 'b', v: 2 },
      { id: 'c', v: 2 },
    ]);
    expect(list[1].v).toBe(1);
  });
  it('drops a row that can no longer be read', async () => {
    const out = await patchList(list, [{ kind: 'tenant', name: 'a' }], (r) => r.id, async () => {
      throw new ApiError(403, { code: 'forbidden', message: 'no' });
    });
    expect(out.map((r) => r.id)).toEqual(['c']);
  });
  it('fails on other errors so the screen reads again', async () => {
    await expect(
      patchList(list, [{ kind: 'tenant', name: 'a' }], (r) => r.id, async () => {
        throw new ApiError(500, { code: 'internal', message: 'x' });
      }),
    ).rejects.toBeInstanceOf(ApiError);
  });
});

describe('web-own topics', () => {
  it('match their own kinds, and one incident by id', () => {
    expect(opsLive.match({ kind: 'op', name: 'x' })).toBe(true);
    expect(opsLive.match({ kind: 'notification', name: 'x' })).toBe(false);
    expect(notificationsLive.match({ kind: 'notification', name: '' })).toBe(true);
    expect(incidentLive('i1').match({ kind: 'incident', name: 'i1' })).toBe(true);
    expect(incidentLive('i1').match({ kind: 'incident', name: 'i2' })).toBe(false);
    expect(incidentLive(undefined).match({ kind: 'incident', name: 'i1' })).toBe(false);
  });
});

describe('server topics', () => {
  it('match server records and reports of that server', () => {
    expect(serversLive.match({ kind: 'node-observation', name: 'n1' })).toBe(true);
    expect(serversLive.match({ kind: 'app', tenant: 't', name: 'web' })).toBe(false);
    expect(serverLive('n1').match({ kind: 'diagnostic', name: 'n1' })).toBe(true);
    expect(serverLive('n1').match({ kind: 'node-report', name: 'n2' })).toBe(false);
    expect(dashboardLive.match({ kind: 'op', name: 'x' })).toBe(false);
    expect(dashboardLive.match({ kind: 'node-observation', name: 'n1' })).toBe(true);
  });
});

describe('tenant resource topics', () => {
  it('match records and task observations of that tenant and app', () => {
    expect(appsLive('t').match({ kind: 'app', tenant: 't', name: 'web' })).toBe(true);
    expect(appsLive('t').match({ kind: 'app', tenant: 'u', name: 'web' })).toBe(false);
    expect(appsLive('t').match({ kind: 'node-observation', tenant: 't', app: 'web', name: 'n1' })).toBe(true);
    expect(appsLive('t').match({ kind: 'node-observation', tenant: 't', name: 'n1' })).toBe(false);
    expect(appLive('t', 'web').match({ kind: 'node-observation', tenant: 't', app: 'db', name: 'n1' })).toBe(false);
    expect(appLive('t', 'web').match({ kind: 'app', tenant: 't', name: 'web' })).toBe(true);
    expect(volumesLive('t').match({ kind: 'volume', tenant: 't', name: 'data' })).toBe(true);
    expect(networksLive('t').match({ kind: 'network', name: 'sys' })).toBe(true);
    expect(networksLive(undefined).match({ kind: 'network', tenant: 't', name: 'n' })).toBe(false);
  });
});
