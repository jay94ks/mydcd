// SPDX-License-Identifier: Apache-2.0

// 휴대폰 이미지 관리 하위 탭 (UI-M1 '보기만 화면의 상세 · 하위 탭'): 내장 저장소 · 외부 저장소 · 빌드 · 신뢰 출처를 읽기만 한다.
import { buildCache, buildContexts, buildPolicy, externalRegistries, imageTrust, registries } from '../api/endpoints';
import { noEndpoint } from '../api/client';
import { useTenantRole } from '../auth/session';
import { Empty, Load } from '../components/states';
import { fmtBytes, fmtTime } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { MCards, MDetail, MSec, MTiles, useReadOnlyTop } from '../mobile/ReadOnly';
import { buildStatus, cacheTotal, policyText, source } from './ImageBuilds';
import { ORIGIN, PULL } from './ImageTrust';
import { RegistryCert, STATUS } from './Registry';

function useTop(tab: string, wide: string) {
  const { tenant } = useTenantRole();
  useReadOnlyTop('이미지 관리', tenant ? `${tab} · 작업 공간 ${tenant}` : tab, wide, [tenant, tab]);
  return tenant;
}

export function MRegistryTab() {
  const tenant = useTop('내장 저장소', '저장소 만들기·켜기·끄기·한도 바꾸기는 넓은 화면에서');
  const q = usePoll((s) => registries(tenant, s), [tenant]);
  return (
    <Load q={q} what="저장소 목록을 읽지 못했습니다">
      {(p) => {
        const rows = p.items.filter((r) => !r.deleted);
        return (
          <>
            <MSec>내장 저장소 {rows.length}</MSec>
            {rows.length === 0 && <span className="muted small">이 작업 공간에 내장 저장소가 없습니다.</span>}
            {rows.map((r) => {
              const st = r.status ? STATUS[r.status] : r.active ? (['사용 중', 'ok'] as const) : (['꺼짐', 'un'] as const);
              return (
                <MDetail
                  key={r.id}
                  title={r.name && r.name !== r.id ? `${r.id} · ${r.name}` : r.id}
                  badge={[st[1], st[0]]}
                  rows={[
                    ['접속 주소', <span key="e" className="mono">{r.endpoint}</span>],
                    ['서버', r.node ?? '—'],
                    ['목표', r.enabled === undefined ? '—' : r.enabled ? '켜짐' : '꺼짐'],
                    ['저장소', `${r.repositories}개`],
                    r.volume && ['데이터 저장소', r.volume],
                    ['인증서', <RegistryCert key="c" id={r.certificateID} />],
                    ['버전', <code key="v">{r.revision}</code>],
                  ]}
                />
              );
            })}
          </>
        );
      }}
    </Load>
  );
}

export function MExternalTab() {
  const tenant = useTop('외부 저장소', '등록·로그인 정보·경로 바꾸기와 로그인 시험은 넓은 화면에서');
  const q = usePoll((s) => externalRegistries(tenant, s), [tenant]);
  return (
    <Load q={q} what="외부 저장소를 읽지 못했습니다">
      {(p) => (
        <>
          <MSec>외부 저장소 {p.items.length}</MSec>
          <MCards
            empty="등록한 외부 저장소가 없습니다."
            items={p.items.filter((r) => !r.deleted).map((r) => {
              const last = (r.pulls ?? []).filter((x) => !x.stale).sort((a, b) => (b.completedAt ?? 0) - (a.completedAt ?? 0))[0];
              return {
              key: r.id,
              title: <span className="mono">{r.authority}</span>,
              badge: !r.enabled ? ['un', '꺼짐'] : r.auth === 'none' ? ['un', '공개'] : ['ok', '로그인'],
              tone: (last && last.code !== 'ok') || (r.enabled && !r.reader) ? 'wa' : undefined,
              lines: [
                <span key="p" className="mono">{r.repository}</span>,
                r.auth !== 'none' && r.credential ? `로그인 정보 · 보관함 ${r.credential.id}` : undefined,
                r.reader ? `읽는 서버 ${r.reader.node}${r.reader.draining ? ' · 연결 해제 중' : ''}` : '읽을 서버 없음',
                last ? `마지막 받기 ${last.code === 'ok' ? '성공' : last.code} · ${last.node} · ${fmtTime(new Date(last.completedAt).toISOString())}` : undefined,
              ],
              meta: `버전 ${r.revision}`,
              };
            })}
          />
        </>
      )}
    </Load>
  );
}

export function MBuildsTab() {
  const tenant = useTop('빌드', '빌드 만들기·고치기·시작·캐시 비우기는 넓은 화면에서');
  const ctxQ = usePoll((s) => buildContexts(tenant, s), [tenant]);
  const polQ = usePoll((s) => buildPolicy(tenant, s), [tenant], 0);
  const cacheQ = usePoll((s) => buildCache(tenant, s), [tenant], 0);
  const used = cacheTotal(cacheQ.data);
  const limit = cacheQ.data?.cacheBytes;
  return (
    <Load q={ctxQ} what="빌드 컨텍스트를 읽지 못했습니다">
      {(p) => {
        const failed = p.items.filter((c) => c.lastBuild?.phase === 'failed').length;
        return (
          <>
            <MTiles
              items={[
                { label: '빌드 컨텍스트', value: p.items.length, sub: failed ? `마지막 빌드 실패 ${failed}` : '실패 없음', warn: failed > 0 },
                { label: '빌드 캐시', value: used !== undefined ? fmtBytes(used) : '—', sub: limit ? `정리 목표 ${fmtBytes(limit)} (서버·컨텍스트마다)` : undefined },
              ]}
            />
            {polQ.data && <MDetail title="빌드 설정" rows={[['설정', polQ.data.exists ? policyText(polQ.data, used) : '빌드 설정이 없습니다']]} />}
            <MSec>빌드 컨텍스트</MSec>
            <MCards
              empty="빌드 컨텍스트가 없습니다."
              items={p.items.map((c) => {
                const st = c.lastBuild ? buildStatus(c.lastBuild) : undefined;
                return {
                  key: c.id,
                  title: c.id,
                  badge: st ? [st[1], st[0]] : ['un', '빌드 전'],
                  tone: st?.[1] === 'er' ? 'er' : undefined,
                  lines: [source(c), <span key="r" className="mono">{c.repository}</span>],
                  meta: c.lastBuild ? `${c.lastBuild.label} · ${c.lastBuild.user}${c.lastBuild.createdAt ? ` · ${fmtTime(new Date(c.lastBuild.createdAt).toISOString())}` : ''}` : undefined,
                };
              })}
            />
          </>
        );
      }}
    </Load>
  );
}

export function MTrustTab() {
  const tenant = useTop('신뢰 출처', '신뢰 출처 추가·경로 바꾸기·빼기는 넓은 화면에서');
  const q = usePoll((s) => imageTrust(tenant, s), [tenant]);
  if (q.error && noEndpoint(q.error)) return <Empty title="서버 기능 대기">웹 서버에 신뢰 출처 끝점이 아직 없습니다.</Empty>;
  return (
    <Load q={q} what="신뢰 출처를 읽지 못했습니다">
      {(v) => (
        <>
          {v.untrusted.length > 0 && (
            <MCards
              empty=""
              items={[
                {
                  key: 'untrusted',
                  title: `신뢰 출처 아님 ${v.untrusted.length}`,
                  tone: 'wa',
                  lines: v.untrusted.slice(0, 5).map((u, i) => <span key={i} className="mono">{`${u.app ? `${u.app}${u.service ? `/${u.service}` : ''}` : `단독 ${u.standalone}`} · ${u.image}`}</span>),
                  meta: '다음 재시작·이동·배포 때 막힙니다',
                },
              ]}
            />
          )}
          <MSec>신뢰 출처 {v.rules.length}</MSec>
          <MCards
            empty="신뢰 출처가 없습니다. 이 작업 공간은 어떤 이미지도 받을 수 없습니다."
            items={v.rules.map((r) => ({
              key: `${r.registry}/${r.repository}`,
              title: <span className="mono">{r.registry}</span>,
              badge: ['ok', PULL[r.pull] ?? r.pull],
              lines: [<span key="p" className="mono">{r.repository}</span>, ORIGIN[r.origin] ?? r.origin],
              meta: `쓰는 곳 ${r.uses.length}${r.only ? ` · 이 출처만 허용 ${r.only}` : ''}`,
            }))}
          />
          <span className="muted small">rev {v.revision}</span>
        </>
      )}
    </Load>
  );
}
