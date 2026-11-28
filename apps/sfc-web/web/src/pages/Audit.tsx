// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react';
import { useLocation } from 'react-router-dom';
import { OpsHeader } from './OpsTabs';
import { auditLog } from '../api/endpoints';
import type { DAudit } from '../api/dto';
import { useSession } from '../auth/session';
import { Badge, Card, HelpBox, PageHeader } from '../components/ui';
import { ErrorBand, Load } from '../components/states';
import { Refresh } from '../components/Refresh';
import { DataTable } from '../components/DataTable';
import { usePoll } from '../lib/usePoll';
import { fmtTime } from '../lib/format';
import { auditLive } from '../lib/liveTopics';

const AREA: Record<string, string> = {
  'web-settings': '웹 앱 설정',
  seal: '봉인 파일',
  'web-backup': '웹 백업',
  archived: '보관된 앱',
};

const show = (v: unknown) => (v === undefined || v === null ? '' : typeof v === 'string' ? v : JSON.stringify(v));

/** 바뀐 키만 "키: 전 → 후"로 줄인다. 객체가 아니면 통째로 보인다. */
export function auditChange(before: unknown, after: unknown): string[] {
  const obj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
  if (obj(before) && obj(after)) {
    return [...new Set([...Object.keys(before), ...Object.keys(after)])]
      .filter((k) => JSON.stringify(before[k]) !== JSON.stringify(after[k]))
      .map((k) => `${k}: ${show(before[k]) || '없음'} → ${show(after[k]) || '없음'}`);
  }
  if (before === undefined && after === undefined) return [];
  return [`${show(before) || '없음'} → ${show(after) || '없음'}`];
}

export function AuditPage() {
  const session = useSession();
  const [tenant, setTenant] = useState('');
  const first = usePoll((s) => auditLog(tenant || undefined, undefined, s), [tenant], 0, auditLive(tenant || undefined));
  const [more, setMore] = useState<{ items: DAudit[]; next: string }>();
  const [moreError, setMoreError] = useState<unknown>();
  // 첫 쪽이 다시 읽히면 이어 받은 쪽은 버린다(같은 기준으로 다시 이어 받는다).
  const [moreFor, setMoreFor] = useState<Date>();
  const extra = more && moreFor === first.asOf ? more : undefined;
  const rows = [...(first.data?.items ?? []), ...(extra?.items ?? [])];
  const next = extra ? extra.next : first.data?.next;
  const loadMore = async () => {
    if (!next) return;
    setMoreError(undefined);
    try {
      const r = await auditLog(tenant || undefined, next);
      setMore({ items: [...(extra?.items ?? []), ...r.items], next: r.next });
      setMoreFor(first.asOf);
    } catch (e) {
      setMoreError(e);
    }
  };
  // 작업 기록의 '웹 설정 변경' 탭 (UI-A3)
  const inOps = useLocation().pathname.startsWith('/system/ops');
  return (
    <>
      {inOps ? <OpsHeader actions={<Refresh q={first} />} /> : <PageHeader title="설정 변경 기록" ids="UI-A3" actions={<Refresh q={first} />} />}
      {!inOps && (
        <HelpBox terms="설정 변경 기록 (audit log)">
          <b>이 화면은</b> 웹 앱에서 누가 언제 무엇을 바꿨는지 보여 줍니다. 지울 수 없고 보관 기간(기본 1년)이 지나면 사라집니다. 비밀값은 바뀐 사실만 남습니다.
          {!session.user.systemAdmin && ' 내가 속한 작업 공간의 기록만 보입니다.'} 클러스터에 보낸 변경은 작업 기록에 있습니다.
        </HelpBox>
      )}
      <Card>
        <Load q={first}>
          {() => (
            <DataTable
              rows={rows}
              rowKey={(r) => r.id}
              emptyTitle="기록이 없습니다"
              toolbar={
                <label className="row small">
                  작업 공간
                  <select value={tenant} onChange={(e) => setTenant(e.target.value)}>
                    <option value="">전체</option>
                    {session.tenants.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.id}
                      </option>
                    ))}
                  </select>
                </label>
              }
              pageInfo={next ? { next, revision: 0, asOf: first.asOf?.toISOString() ?? '' } : undefined}
              onMore={next ? () => void loadMore() : undefined}
              columns={[
                { key: 'at', header: '시각', width: '130px', value: (r) => r.at, render: (r) => fmtTime(r.at) },
                { key: 'who', header: '누가', width: '110px', value: (r) => r.username, render: (r) => r.username || r.user },
                { key: 'area', header: '어디', width: '120px', value: (r) => r.area, render: (r) => <Badge>{AREA[r.area] ?? r.area}</Badge> },
                { key: 'action', header: '무엇을', value: (r) => `${r.action} ${r.target ?? ''}`, render: (r) => <code>{[r.action, r.target].filter(Boolean).join(' ')}</code> },
                { key: 'tenant', header: '작업 공간', width: '110px', value: (r) => r.tenant ?? '', render: (r) => r.tenant || <span className="muted">시스템</span> },
                {
                  key: 'change',
                  header: '바뀐 내용',
                  wrap: true,
                  render: (r) => {
                    const lines = auditChange(r.before, r.after);
                    return lines.length ? (
                      <div className="small">
                        {lines.map((l, i) => (
                          <div key={i}>{l}</div>
                        ))}
                      </div>
                    ) : (
                      <span className="muted">-</span>
                    );
                  },
                },
              ]}
            />
          )}
        </Load>
        {moreError !== undefined && <ErrorBand error={moreError} what="다음 쪽을 불러오지 못했습니다" />}
      </Card>
    </>
  );
}
