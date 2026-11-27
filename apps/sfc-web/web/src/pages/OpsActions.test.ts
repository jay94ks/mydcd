// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { DOpField } from '../api/dto';
import { reasonHeaders } from '../api/client';
import { ApiError } from '../api/client';
import type { OpView } from '../api/types';
import { cleanOf, editable, editUid, emptyOf, opBody, parseChangeFile, payloadOf, sendBatch, titleOf, type BatchItem, type OpAction } from './OpsActions';

const nodes: DOpField = { name: 'Nodes', type: 'list', replace: true, items: { name: '', type: 'string' } };
const act: OpAction = { action: 'set-nodes', key: 'catalog', category: 'tenants', offer: 'here', base: 'current', fields: [{ name: 'Tenant', type: 'string' }, nodes, { name: 'Labels', type: 'map', items: { name: '', type: 'string' } }] };

describe('관리 변경 입력 칸', () => {
  it('replace 목록은 비어도 []로 보내고, 빈 칸은 뺀다', () => {
    const vals = Object.fromEntries(act.fields.map((f) => [f.name, emptyOf(f)]));
    expect(payloadOf(act, vals)).toEqual({ Nodes: [] });
    expect(cleanOf(nodes, ['node-a', ''])).toEqual(['node-a']);
    expect(payloadOf(act, { ...vals, Tenant: 'lab', Labels: { '': 'x', env: 'prod' } })).toEqual({ Tenant: 'lab', Nodes: [], Labels: { env: 'prod' } });
  });
  it('변경 파일은 CLI 모양 하나 또는 배열을 읽고 모르는 동작은 뺀다', () => {
    const one = parseChangeFile(JSON.stringify({ schema: 1, action: 'set-nodes', expected: 3, payload: { Tenant: 'lab', Nodes: ['node-b'] } }), [act]);
    expect(one.items).toHaveLength(1);
    expect(one.items[0].expected).toBe(3);
    const many = parseChangeFile(JSON.stringify([{ schema: 1, action: 'nope', expected: 0, payload: {} }]), [act]);
    expect(many.unknown).toEqual(['nope']);
  });
  it('길이가 정해진 목록은 다 채워야 보내고, number 칸은 소수를 받는다', () => {
    const digest: DOpField = { name: 'Owner', type: 'list', length: 3, items: { name: '', type: 'integer' } };
    expect(emptyOf(digest)).toEqual(['', '', '']);
    expect(cleanOf(digest, [1, '', 3])).toBeUndefined();
    expect(cleanOf(digest, [1, 2, 3])).toEqual([1, 2, 3]);
    expect(cleanOf({ name: 'Ratio', type: 'number' }, 0.5)).toBe(0.5);
  });
  it('보내기: 묶음은 같은 batch, 사유는 퍼센트 인코딩한 한 줄 머리글, 화면 이름은 프런트가 정한다', () => {
    expect(opBody('op-1', act, 3, { Tenant: 'lab', Nodes: [] }, 'b-1')).toEqual({ opId: 'op-1', action: 'set-nodes', expected: 3, payload: { Tenant: 'lab', Nodes: [] }, tenant: 'lab', batch: 'b-1' });
    expect(opBody('op-1', act, 0, {})).not.toHaveProperty('batch');
    expect(reasonHeaders('서버 교체\n준비')).toEqual({ 'X-SFC-Reason': encodeURIComponent('서버 교체 준비') });
    expect(reasonHeaders('  ')).toEqual({});
    expect(titleOf(act)).toBe('쓸 서버 정하기');
    expect(titleOf({ action: 'new-thing' })).toBe('new-thing');
  });
  it('보낸 줄을 고치면 새 작업 ID로 다시 보내고, 불명·진행 중이나 도착했을 수 있는 오류는 고치지 않는다', () => {
    const it0: BatchItem = { uid: 'u-1', action: act, vals: {}, payload: { Tenant: 'lab', Nodes: [] } };
    const withOp = (state: OpView['state']): BatchItem => ({ ...it0, op: { id: 'u-1', action: 'set-nodes', target: '', state, submittedAt: '', updatedAt: '' } });
    expect(editable(it0)).toBe(true);
    expect(editUid(it0)).toBe('u-1');
    expect(editable(withOp('rejected'))).toBe(true);
    expect(editUid(withOp('rejected'))).not.toBe('u-1');
    expect(editable(withOp('unknown'))).toBe(false);
    expect(editable(withOp('running'))).toBe(false);
    expect(editable({ ...it0, error: new ApiError(409, { code: 'op-conflict', message: '' }) })).toBe(true);
    expect(editUid({ ...it0, error: new ApiError(400, { code: 'bad-payload', message: '' }) })).not.toBe('u-1');
    expect(editable({ ...it0, error: new ApiError(0, { code: 'transport', message: '' }) })).toBe(false);
  });
  it('여기서 보내지 않는 동작(offer: no)은 불러오지 않고, 묶음에 있어도 보내지 않고 멈춘다', async () => {
    const no: OpAction = { ...act, action: 'open-node-shell', offer: 'no', base: 'input', fields: [{ name: 'Node', type: 'string' }] };
    const r = parseChangeFile(JSON.stringify([{ schema: 1, action: 'open-node-shell', expected: 0, payload: { Node: 'node-a' } }, { schema: 1, action: 'set-nodes', expected: 1, payload: { Tenant: 'lab', Nodes: [] } }]), [act, no]);
    expect(r.blocked).toEqual(['open-node-shell']);
    expect(r.items.map((x) => x.action.action)).toEqual(['set-nodes']);
    const patches: [string, Partial<BatchItem>][] = [];
    await sendBatch([{ uid: 'u-no', action: no, vals: {}, payload: { Node: 'node-a' }, expected: 0 }, { uid: 'u-next', action: act, vals: {}, payload: {}, expected: 1 }], 'b-1', (uid, p) => patches.push([uid, p]));
    expect(patches).toHaveLength(1);
    expect(patches[0][0]).toBe('u-no');
    expect((patches[0][1].error as ApiError).code).toBe('not-offered');
  });
});
