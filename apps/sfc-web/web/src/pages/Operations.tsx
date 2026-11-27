// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { opsList, toOp } from '../api/endpoints';
import { api } from '../api/client';
import type { DOp } from '../api/dto';
import { ErrorBand } from '../components/states';
import { usePhone } from '../lib/viewport';
import { useMobileTop } from '../mobile/top';
import type { OpState, OpView } from '../api/types';
import { ResultCodeName } from '../api/types';
import { Badge, Card, KV, OpBadge, Segmented } from '../components/ui';
import { OpsTabs, OpsHeader } from './OpsTabs';
import { Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { DataTable } from '../components/DataTable';
import { OpPanel } from '../components/OpPanel';
import { RevertDialog } from '../components/RevertDialog';
import { usePoll, DEFAULT_POLL_MS } from '../lib/usePoll';
import { fmtTime } from '../lib/format';
import { opsLive } from '../lib/liveTopics';

type Filter = 'all' | OpState;

export function OperationsPage() {
  return usePhone() ? <MOperations /> : <DesktopOperations />;
}

function DesktopOperations() {
  const [params, setParams] = useSearchParams();
  const focus = params.get('focus') ?? '';
  const [filter, setFilter] = useState<Filter>('all');
  const [children, setChildren] = useState(false);
  const list = usePoll((s) => opsList(filter === 'all' ? undefined : filter, s, children), [filter, children], DEFAULT_POLL_MS, opsLive);
  const [override, setOverride] = useState<Record<string, OpView>>({});
  const rows = (list.data ?? []).map((o) => override[o.id] ?? o);
  const selected = rows.find((o) => o.id === focus);
  const unknown = rows.filter((o) => o.state === 'unknown').length;
  const [reverting, setReverting] = useState<OpView>();
  return (
    <>
      <OpsHeader actions={<Refresh q={list} />} />
      {reverting && <RevertDialog op={reverting} onClose={() => setReverting(undefined)} onDone={() => list.refresh()} />}
      {unknown > 0 && <div className="note un small">결과 불명 작업이 {unknown}건 있습니다. 하나씩 골라 결과를 확인해 주세요.</div>}
      <div className="row between">
        <Segmented
          label="상태 거르기"
          value={filter}
          onChange={setFilter}
          options={[
            ['all', '전체'],
            ['unknown', '결과 불명'],
            ['applied', '완료'],
            ['failed', '적용 안 됨'],
            ['rejected', '거부'],
          ]}
        />
        <label className="check small">
          <input type="checkbox" checked={children} onChange={(e) => setChildren(e.target.checked)} /> 배포 단계도 보기
        </label>
      </div>
      <div className="main-side">
        <div className="primary">
          <Load q={list} what="작업 기록을 불러오지 못했습니다">
            {() => (
              <DataTable
                rows={rows}
                rowKey={(o) => o.id}
                selectedKey={focus}
                onRowClick={(o) => setParams({ focus: o.id })}
                searchPlaceholder="작업 ID·종류·대상 찾기"
                emptyTitle="보낸 작업이 없습니다"
                columns={[
                  { key: 'st', header: '상태', value: (o) => o.state, render: (o) => <OpBadge state={o.state} /> },
                  { key: 'act', header: '종류', value: (o) => o.action, render: (o) => <b>{o.action}</b> },
                  { key: 'tg', header: '대상', value: (o) => `${o.tenant ?? ''}/${o.target}`, render: (o) => `${o.tenant ? `${o.tenant} · ` : ''}${o.target || '—'}` },
                  { key: 'id', header: '작업 ID', value: (o) => o.id, render: (o) => <code>{o.id.slice(0, 8)}{o.parent ? ` (${o.id.split('.').pop()}단계)` : ''}</code> },
                  { key: 'at', header: '제출', value: (o) => o.submittedAt, render: (o) => fmtTime(o.submittedAt) },
                ]}
              />
            )}
          </Load>
        </div>
        <Card className="aside" title={selected ? `작업 ${selected.id.slice(0, 8)}` : '작업 고르기'}>
          {selected ? (
            <>
              <OpPanel op={selected} onChange={(o) => (setOverride((x) => ({ ...x, [o.id]: o })), list.refresh())} />
              <KV
                items={[
                  ['작업 ID', <code className="break-any">{selected.id}</code>],
                  ['요청 ID', selected.requestId ?? '—'],
                  ['결과 코드', selected.resultCode !== undefined ? `${selected.resultCode} (${ResultCodeName[selected.resultCode] ?? '?'})` : '—'],
                  ['오류 코드', selected.errorCode || '—'],
                  ['위치', selected.index ?? '—'],
                  ['적용 버전', selected.revision ?? '—'],
                  ['묶음', selected.parent ? <code>{selected.parent}</code> : '—'],
                  ...(selected.revertOf ? [['되돌린 작업', <a href={`?focus=${encodeURIComponent(selected.revertOf)}`} onClick={(e) => (e.preventDefault(), setParams({ focus: selected.revertOf! }))}><code>{selected.revertOf.slice(0, 8)}</code></a>] as [string, JSX.Element]] : []),
                  ['마지막 갱신', fmtTime(selected.updatedAt)],
                ]}
              />
              {canRevert(selected) && (
                <div className="row">
                  <button className="btn" onClick={() => setReverting(selected)}>
                    {selected.revert === 'link' ? '이 변경 되돌리기 (다른 화면)…' : '이 변경 되돌리기…'}
                  </button>
                  <span className="small muted">바꾸기 전 값으로 가는 반대 변경을 보냅니다.</span>
                </div>
              )}
              {selected.action === 'deploy' && selected.state === 'unknown' && <span className="small muted">이어 가려면 같은 app.yaml로 배포 화면에서 다시 제출해야 합니다. 여기서는 단계 결과 조회까지만 합니다.</span>}
            </>
          ) : (
            <span className="small muted">왼쪽에서 작업을 고르면 자세한 내용과 결과 조회·재개 버튼이 나옵니다.</span>
          )}
        </Card>
      </div>
    </>
  );
}

// ── 휴대폰 (캔버스 UI-M1 ① 표 → 카드, UI-M6 ③ 결과 불명 작업) ──
type MFilter = 'all' | 'progress' | 'unknown' | 'applied' | 'rejected';
export const M_BADGE: Record<OpView['state'], ['ok' | 'er' | 'wa' | 'pr' | 'un', string]> = {
  applied: ['ok', '완료'],
  failed: ['er', '적용 안 됨'],
  rejected: ['er', '거부'],
  unknown: ['wa', '불명'],
  pending: ['pr', '진행'],
  running: ['pr', '진행'],
};
/** 메뉴 ‘이 변경 되돌리기’: 확정된 내 작업 중 데몬이 here·link라고 한 것 */
export const canRevert = (o: OpView) => o.state === 'applied' && (o.revert === 'here' || o.revert === 'link') && !o.parent;
const isJobOp = (o: OpView) => o.action === 'deploy' || o.action === 'vault-value' || o.action === 'vault-password';
export const opTitle = (o: OpView) => `${o.action}${o.target ? ` · ${o.target}` : ''}`;
export const opLine = (o: OpView) => [o.id.slice(0, 8), o.tenant, fmtTime(o.submittedAt)].filter(Boolean).join(' · ');

/** 결과 조회 · 재개: 같은 원 작업으로만 묻는다 (새 ID로 다시 보내지 않음) */
function useAskOp(onChange: (o: OpView) => void) {
  const [busy, setBusy] = useState<'' | 'result' | 'resume'>('');
  const [error, setError] = useState<unknown>();
  const ask = async (op: OpView, kind: 'result' | 'resume') => {
    setBusy(kind);
    setError(undefined);
    try {
      const r = await api.post<{ op: DOp }>(`/ops/${encodeURIComponent(op.id)}/${kind}`);
      onChange(toOp(r.op));
    } catch (e) {
      setError(e);
    } finally {
      setBusy('');
    }
  };
  return { busy, error, ask };
}

function MOperations() {
  const [params, setParams] = useSearchParams();
  const focus = params.get('focus') ?? '';
  const [filter, setFilter] = useState<MFilter>('all');
  const [find, setFind] = useState<string>();
  const list = usePoll((s) => opsList(undefined, s), [], DEFAULT_POLL_MS, opsLive);
  const [override, setOverride] = useState<Record<string, OpView>>({});
  const put = (o: OpView) => (setOverride((x) => ({ ...x, [o.id]: o })), list.refresh());
  const asker = useAskOp(put);
  const rows = (list.data ?? []).map((o) => override[o.id] ?? o);
  const selected = rows.find((o) => o.id === focus);
  const unknown = rows.filter((o) => o.state === 'unknown').length;
  useMobileTop(
    selected
      ? undefined
      : {
          title: '작업 기록',
          sub: '내 작업',
          right: (
            <button type="button" className="ic" aria-label="찾기" onClick={() => setFind((f) => (f === undefined ? '' : undefined))}>
              🔍
            </button>
          ),
        },
    [!!selected],
  );
  if (selected) return <MOpDetail op={selected} onChange={put} />;
  const q = (find ?? '').trim().toLowerCase();
  const shown = rows
    .filter((o) => (filter === 'all' ? true : filter === 'progress' ? o.state === 'pending' || o.state === 'running' : filter === 'rejected' ? o.state === 'rejected' || o.state === 'failed' : o.state === filter))
    .filter((o) => !q || `${o.id} ${o.action} ${o.target} ${o.tenant ?? ''}`.toLowerCase().includes(q));
  const chips: [MFilter, string][] = [
    ['all', '전체'],
    ['progress', '진행 중'],
    ['unknown', `불명${unknown ? ` ${unknown}` : ''}`],
    ['applied', '완료'],
    ['rejected', '거부'],
  ];
  return (
    <>
      <OpsTabs />
      {find !== undefined && <input type="search" className="m-find" autoFocus placeholder="작업 ID·종류·대상 찾기" value={find} onChange={(e) => setFind(e.target.value)} />}
      <div className="mchips">
        {chips.map(([k, l]) => (
          <button key={k} type="button" className={`mchip${filter === k ? ' on' : ''}`} onClick={() => setFilter(k)}>
            {l}
          </button>
        ))}
      </div>
      {asker.error !== undefined && <ErrorBand error={asker.error} what="작업 상태를 묻지 못했습니다" />}
      <Load q={list} what="작업 기록을 불러오지 못했습니다">
        {() =>
          shown.length === 0 ? (
            <span className="muted small">{rows.length ? '조건에 맞는 작업이 없습니다.' : '보낸 작업이 없습니다.'}</span>
          ) : (
            <>
              {shown.map((o) => {
                const [tone, label] = M_BADGE[o.state] ?? M_BADGE.unknown;
                const prog = (o.state === 'pending' || o.state === 'running') && o.steps ? ` ${o.step ?? 0}/${o.steps}` : '';
                const direct = o.state === 'unknown' && !isJobOp(o);
                return (
                  <div
                    key={o.id}
                    className={`mc${o.state === 'unknown' ? ' xwa' : ''}`}
                    role="button"
                    tabIndex={0}
                    onClick={() => setParams({ focus: o.id })}
                    onKeyDown={(e) => e.key === 'Enter' && setParams({ focus: o.id })}
                  >
                    <div className="hd">
                      <b>{opTitle(o)}</b>
                      <Badge tone={tone}>
                        {label}
                        {prog}
                      </Badge>
                    </div>
                    {(o.state === 'failed' || o.state === 'rejected') && o.errorCode && <div className="ln">{o.errorCode}</div>}
                    <div className="ln mono">{opLine(o)}</div>
                    {direct && (
                      <div className="ft" onClick={(e) => e.stopPropagation()}>
                        <button type="button" className="mbtn sm" disabled={!!asker.busy} onClick={() => void asker.ask(o, 'result')}>
                          {asker.busy === 'result' ? '묻는 중…' : '결과 조회'}
                        </button>
                        <button type="button" className="mbtn sm" disabled={!!asker.busy} onClick={() => void asker.ask(o, 'resume')}>
                          {asker.busy === 'resume' ? '재개 중…' : '재개'}
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </>
          )
        }
      </Load>
    </>
  );
}

function MOpDetail({ op, onChange }: { op: OpView; onChange: (o: OpView) => void }) {
  const asker = useAskOp(onChange);
  const navigate = useNavigate();
  const short = op.id.slice(0, 8);
  useMobileTop(
    {
      title: short,
      sub: `${op.action}${op.target ? ` · ${op.target}` : ''}`,
      left: (
        <button type="button" className="ic" aria-label="뒤로" onClick={() => navigate('/system/ops')}>
          ‹
        </button>
      ),
    },
    [op.id, op.action, op.target],
    'sub',
  );
  const job = isJobOp(op);
  const unknown = op.state === 'unknown';
  const [reverting, setReverting] = useState(false);
  const [tone, label] = M_BADGE[op.state] ?? M_BADGE.unknown;
  const stepNo = op.step ?? 0;
  return (
    <>
      <div className={`mc${unknown ? ' xwa' : op.state === 'failed' || op.state === 'rejected' ? ' xer' : ''}`}>
        <div className="hd">
          <b>{unknown ? '결과 불명' : label}</b>
          <Badge tone={tone}>{unknown ? '응답 유실' : label}</Badge>
        </div>
        <dl className="mkv">
          <dt>작업</dt>
          <dd className="mono">{short}</dd>
          <dt>내용</dt>
          <dd>{opTitle(op)}</dd>
          {op.tenant && (
            <>
              <dt>작업 공간</dt>
              <dd>{op.tenant}</dd>
            </>
          )}
          <dt>제출</dt>
          <dd>{fmtTime(op.submittedAt)}</dd>
          {op.resultCode !== undefined && (
            <>
              <dt>결과 코드</dt>
              <dd>
                {op.resultCode} ({ResultCodeName[op.resultCode] ?? '?'})
              </dd>
            </>
          )}
          {op.errorCode && (
            <>
              <dt>오류 코드</dt>
              <dd className="mono">{op.errorCode}</dd>
            </>
          )}
          {op.revision !== undefined && (
            <>
              <dt>적용 버전</dt>
              <dd>{op.revision}</dd>
            </>
          )}
        </dl>
      </div>
      {unknown && <div className="bn info">불명은 응답이 유실된 상태입니다. 같은 원 작업으로 결과 조회나 명시 재개만 할 수 있고, 새 ID로 다시 제출하지 않습니다.</div>}
      {op.steps ? (
        <>
          <div className="m-sec">
            <span>진행</span>
          </div>
          <div className="li">
            {Array.from({ length: op.steps }, (_, i) => {
              const done = op.state === 'applied' || i < stepNo;
              const cur = i === stepNo && !done;
              return (
                <div key={i}>
                  <Badge tone={done ? 'ok' : cur ? (unknown ? 'wa' : 'pr') : 'un'}>{done ? '확정' : cur ? (unknown ? '불명' : '진행') : '대기'}</Badge>
                  <span className="mono">
                    {op.id.slice(0, 8)}.{i}
                  </span>
                </div>
              );
            })}
          </div>
        </>
      ) : null}
      {job && unknown && <OpPanel op={op} onChange={onChange} />}
      {canRevert(op) && (
        <button type="button" className="mbtn" onClick={() => setReverting(true)}>
          이 변경 되돌리기…
        </button>
      )}
      {reverting && <RevertDialog op={op} onClose={() => setReverting(false)} />}
      {asker.error !== undefined && <ErrorBand error={asker.error} what="작업 상태를 묻지 못했습니다" />}
      {unknown && !job && (
        <div className="m-stick">
          <div className="mbar">
            <button type="button" className="mbtn fl" disabled={!!asker.busy} onClick={() => void asker.ask(op, 'result')}>
              {asker.busy === 'result' ? '묻는 중…' : '결과 조회'}
            </button>
            <button type="button" className="mbtn fl pri" disabled={!!asker.busy} onClick={() => void asker.ask(op, 'resume')}>
              {asker.busy === 'resume' ? '재개 중…' : '재개'}
            </button>
          </div>
        </div>
      )}
    </>
  );
}
