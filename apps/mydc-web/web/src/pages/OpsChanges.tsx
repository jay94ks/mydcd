// SPDX-License-Identifier: Apache-2.0

// 작업 기록 › 관리 변경 (캔버스 v198 OperationsChanges, UI-A1).
// '변경 만들기'는 동작별 입력 칸 정의 계약이 나온 뒤에 연다. 지금은 묶음 자리와, /ops에서 읽은 보낸 요청 목록·변경별 결과만 그린다.
import { useState } from 'react';
import { opsList } from '../api/endpoints';
import type { OpView } from '../api/types';
import { Badge, Card, Segmented, type Tone } from '../components/ui';
import { DataTable } from '../components/DataTable';
import { Load } from '../components/states';
import { OpPanel } from '../components/OpPanel';
import { Refresh } from '../components/Refresh';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { fmtTime } from '../lib/format';
import { OpsHeader } from './OpsTabs';

/** 보낸 요청 하나: 같은 요청 ID로 보낸 변경들(위치 순) */
export interface SentRequest {
  id: string;
  tenant?: string;
  ops: OpView[];
  submittedAt: string;
}
type Filter = 'all' | 'progress' | 'unknown' | 'applied' | 'rejected';

/** 작업을 요청 ID로 묶는다. 요청 ID가 없으면 작업 하나가 요청 하나 */
export function groupRequests(ops: OpView[]): SentRequest[] {
  const by = new Map<string, OpView[]>();
  for (const o of ops) {
    const k = o.requestId || o.id;
    by.set(k, [...(by.get(k) ?? []), o]);
  }
  return [...by.entries()]
    .map(([id, xs]) => {
      const sorted = [...xs].sort((a, b) => (a.index ?? 0) - (b.index ?? 0) || a.submittedAt.localeCompare(b.submittedAt));
      return { id, tenant: sorted[0].tenant, ops: sorted, submittedAt: sorted.reduce((m, o) => (o.submittedAt < m ? o.submittedAt : m), sorted[0].submittedAt) };
    })
    .sort((a, b) => b.submittedAt.localeCompare(a.submittedAt));
}

/** 요청 상태: 거부·불명·진행이 먼저 나온 변경의 순번과 함께 */
export function requestState(r: SentRequest): { key: Exclude<Filter, 'all'>; tone: Tone; label: string } {
  const at = (pred: (o: OpView) => boolean) => r.ops.findIndex(pred) + 1;
  const nth = (n: number) => (r.ops.length > 1 ? ` · ${n}번째` : '');
  const rej = at((o) => o.state === 'rejected' || o.state === 'failed');
  if (rej) return { key: 'rejected', tone: 'er', label: `거부${nth(rej)}` };
  const unk = at((o) => o.state === 'unknown');
  if (unk) return { key: 'unknown', tone: 'un', label: `불명${nth(unk)}` };
  const run = at((o) => o.state === 'pending' || o.state === 'running');
  if (run) return { key: 'progress', tone: 'pr', label: `진행 중${nth(run)}` };
  return { key: 'applied', tone: 'ok', label: '완료' };
}

const CHANGE: Record<OpView['state'], [Tone, string]> = {
  applied: ['ok', '확정'],
  unknown: ['un', '불명'],
  rejected: ['er', '거부'],
  failed: ['er', '적용 안 됨'],
  pending: ['pr', '진행 중'],
  running: ['pr', '진행 중'],
};

export function OpsChangesPage() {
  const list = usePoll((s) => opsList(undefined, s), [], DEFAULT_POLL_MS);
  const [filter, setFilter] = useState<Filter>('all');
  const [sel, setSel] = useState<string>();
  const [override, setOverride] = useState<Record<string, OpView>>({});
  const reqs = groupRequests((list.data ?? []).map((o) => override[o.id] ?? o));
  const rows = filter === 'all' ? reqs : reqs.filter((r) => requestState(r).key === filter);
  const cur = reqs.find((r) => r.id === sel);
  const stuck = cur?.ops.find((o) => o.state === 'unknown');
  return (
    <>
      <OpsHeader actions={<Refresh q={list} />} />
      <Card title="변경 만들기">
        <div className="note un small">
          동작마다 서버가 정한 입력 칸 정의가 아직 웹에 없어, 화면에서 변경을 만드는 기능은 준비 중입니다. 지금은 CLI의 <code>mydc manage apply</code>로 보내고, 보낸 요청과 결과는 아래에서 봅니다.
        </div>
        <span className="small muted">입력 칸은 동작마다 서버가 정한 형식대로 나옵니다. 비밀 값은 여기서 넣지 않습니다(비밀값 보관함에서).</span>
      </Card>
      <Card
        title="보낼 변경 묶음 (0)"
        actions={
          <span className="row" style={{ gap: 8 }}>
            <button className="btn" disabled title="변경 만들기가 준비되면 씁니다">
              파일 불러오기
            </button>
            <button className="btn" disabled title="묶음이 비어 있습니다">
              파일로 내보내기
            </button>
          </span>
        }
      >
        <span className="small muted">묶음이 비어 있습니다.</span>
        <span className="small muted">
          줄을 끌어 순서를 바꿉니다. 위에서부터 하나씩 보내고, 거부되거나 결과를 모르는 변경이 나오면 그 뒤는 보내지 않습니다. 앞 변경에 기대는 기준 버전은 앞 변경이 확정된 뒤 채웁니다. 확정된 앞 변경은 되돌리지 않습니다.
        </span>
        <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
          <button className="btn" disabled>
            비우기
          </button>
          <button className="btn primary" disabled>
            0개 차례로 보내기
          </button>
        </div>
      </Card>
      <Card title="보낸 요청">
        <div>
        <Segmented
          label="상태"
          value={filter}
          onChange={setFilter}
          options={[
            ['all', '전체'],
            ['progress', '진행 중'],
            ['unknown', '불명'],
            ['applied', '완료'],
            ['rejected', '거부'],
          ]}
        />
        </div>
        <Load q={list} what="보낸 요청을 불러오지 못했습니다">
          {() => (
            <DataTable
              rows={rows}
              rowKey={(r) => r.id}
              selectedKey={sel}
              onRowClick={(r) => setSel(r.id)}
              emptyTitle="보낸 요청이 없습니다"
              columns={[
                { key: 'id', header: '요청', value: (r) => r.id, render: (r) => <code>{r.id}</code>, m: 'title' },
                { key: 't', header: '작업 공간', value: (r) => r.tenant ?? '', render: (r) => r.tenant ?? '—' },
                { key: 'n', header: '변경', value: (r) => r.ops.length, render: (r) => `${r.ops.length}개` },
                { key: 'at', header: '제출', value: (r) => r.submittedAt, render: (r) => fmtTime(r.submittedAt) },
                {
                  key: 'st',
                  header: '상태',
                  value: (r) => requestState(r).label,
                  render: (r) => {
                    const s = requestState(r);
                    return <Badge tone={s.tone}>{s.label}</Badge>;
                  },
                  m: 'badge',
                },
              ]}
            />
          )}
        </Load>
        <span className="small muted">변경 묶음을 보내면 요청 하나가 생깁니다. 고른 요청의 변경별 결과는 아래에 나옵니다.</span>
      </Card>
      {cur && (
        <Card title={`${cur.id} · 변경별 결과`}>
          <span className="small muted">
            요청 {cur.id}
            {cur.tenant ? ` · 작업 공간 ${cur.tenant}` : ''} · 변경 {cur.ops.length}개
          </span>
          <div style={{ overflowX: 'auto' }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>#</th>
                  <th>변경</th>
                  <th>결과</th>
                </tr>
              </thead>
              <tbody>
                {cur.ops.map((o, i) => {
                  const [tone, label] = CHANGE[o.state] ?? ['un', o.state];
                  return (
                    <tr key={o.id}>
                      <td>{o.index !== undefined ? o.index + 1 : i + 1}</td>
                      <td className="mono">
                        {o.action}
                        {o.target ? ` ${o.target}` : ''}
                      </td>
                      <td>
                        <Badge tone={tone}>{label}</Badge>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <span className="small muted">확정된 앞 단계는 되돌린 것처럼 표시하지 않습니다. 누락한 객체는 유지되며 삭제되지 않습니다.</span>
          {stuck && <OpPanel op={stuck} onChange={(o) => (setOverride((x) => ({ ...x, [o.id]: o })), void list.refresh())} />}
        </Card>
      )}
    </>
  );
}
