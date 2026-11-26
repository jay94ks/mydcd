// SPDX-License-Identifier: Apache-2.0

// 휴대폰 외부 접속 앱 상세 (UI-M1 '보기만 화면의 상세 · 하위 탭'): 수신 주소 · 경로 규칙 · 컨테이너 · 차단 · 오류 표본을 읽기만 한다.
import { useParams, useSearchParams } from 'react-router-dom';
import { BALANCE_NAME, GW_NAME, RESP_NAME, hasRouteCert, ingressApp, routeCertError, routeCertText, ingressBlocks, retryText, scopeText } from '../api/ingress';
import { Load } from '../components/states';
import { fmtTime } from '../lib/format';
import { usePoll } from '../lib/usePoll';
import { MCards, MDetail, MSec, MTiles, useReadOnlyTop } from '../mobile/ReadOnly';

const n = (x: number) => x.toLocaleString('ko-KR');

export function MIngressDetail() {
  const { tenant = '', app = '' } = useParams();
  const node = useSearchParams()[0].get('node') ?? undefined;
  const dq = usePoll((s) => ingressApp(tenant, app, s, node), [tenant, app, node], 30_000);
  const bq = usePoll((s) => ingressBlocks(s), [], 30_000);
  useReadOnlyTop(app, `외부 접속 · 작업 공간 ${tenant}`, '차단·분배 방식·웹훅 바꾸기는 넓은 화면에서', [tenant, app]);
  return (
    <Load q={dq} what="외부 접속을 읽지 못했습니다">
      {(d) => {
        const ins = d.instance;
        const tasks = new Set(ins.routes.flatMap((r) => r.backends.map((b) => b.task)));
        const blocks = (bq.data?.items ?? []).filter((b) => b.state !== 'lifting' && (!b.scope.node || ['tenant', 'source', 'host'].includes(b.scope.kind) || b.scope.node === d.instance.node)).filter((b) => (b.scope.tenant === tenant && (!b.scope.app || b.scope.app === app)) || (b.scope.kind === 'task' && !!b.scope.task && tasks.has(b.scope.task)));
        const m = d.metrics;
        return (
          <>
            {blocks.length > 0 && (
              <MCards
                empty=""
                items={blocks.map((b) => ({ key: b.id, title: `⛔ ${scopeText(b.scope)}`, tone: 'er', lines: [`${RESP_NAME[b.response]} · ${b.by}`, b.reason], meta: b.until ? `${fmtTime(b.until)}까지` : `${fmtTime(b.at)}부터` }))}
              />
            )}
            <MTiles
              items={[
                { label: '요청 (1분)', value: `${n(m.rps)}/s`, sub: m.latency },
                { label: '오류 표본', value: d.errors.length, sub: `연결 실패 ${m.proxyFailures}`, warn: d.errors.length > 0 },
              ]}
            />
            <MDetail
              title={app}
              badge={ins.observed === false ? ['un', '관찰 전'] : ins.error ? ['er', '오류'] : ins.draining ? ['wa', '비우는 중'] : ins.ready ? ['ok', '받는 중'] : ['un', '준비 중']}
              tone={ins.error ? 'er' : undefined}
              rows={[
                ['서버', ins.node],
                ['세대', <code key="g">{ins.generation}</code>],
                ['응답 코드', m.codes],
                m.concurrent && ['동시 요청', `${m.concurrent[0]} / ${m.concurrent[1]}`],
                ['연결', `${m.connections[0]} / ${m.connections[1]}`],
                m.budget && ['오류 예산', m.budget],
                ins.error && ['오류', ins.error],
              ]}
            />
            <MSec>경로 규칙 {ins.routes.length}</MSec>
            {ins.routes.map((r) => (
              <MDetail
                key={r.id}
                title={<span className="mono">{`${r.host}${r.prefix}`}</span>}
                badge={r.blocked ? ['er', '차단'] : [r.gateway === 'external' ? 'ok' : 'un', GW_NAME[r.gateway]]}
                tone={r.blocked ? 'er' : undefined}
                rows={[
                  ['받는 포트', r.port],
                  r.redirect ? ['넘겨 보냄', <span key="r" className="mono">{r.redirect}</span>] : ['보내는 곳', `${r.service ?? '—'}${r.servicePort ? `:${r.servicePort}` : ''}${r.network ? ` · ${r.network}` : ''}`],
                  hasRouteCert(r) && ['인증서', `${routeCertText(r) || '—'}${routeCertError(r) ? ` · ${routeCertError(r)}` : ''}`],
                  r.balance && ['분배', `${BALANCE_NAME[r.balance.method]}${r.balance.hashKey ? ` (${r.balance.hashKey})` : ''}`],
                  r.balance && ['다시 보내기', retryText(r.balance.retry)],
                  ['요청', `${n(r.rps)}/s${r.err5xx !== undefined ? ` · 5xx ${r.err5xx}%` : ''}${r.p95Ms !== undefined ? ` · p95 ${r.p95Ms} ms` : ''}`],
                  r.note && ['메모', r.note],
                ]}
              >
                {r.backends.length > 0 && (
                  <div className="ln muted" style={{ fontSize: 12 }}>
                    {r.backends.map((b) => `${b.task}${b.group ? `(${b.group})` : ''} ${b.health.ok ? '정상' : '이상'} · ${b.weight}`).join(' · ')}
                  </div>
                )}
              </MDetail>
            ))}
            {d.errors.length > 0 && (
              <>
                <MSec>오류 표본 {d.errors.length}</MSec>
                <MCards
                  empty=""
                  items={d.errors.slice(0, 20).map((e, i) => ({ key: String(i), title: <span className="mono">{`${e.status} ${e.method} ${e.path}`}</span>, tone: e.status >= 500 ? 'er' : 'wa', lines: [`${e.reason} · ${e.ms} ms`], meta: `${fmtTime(e.at)} · ${e.task} · ${e.source}` }))}
                />
              </>
            )}
          </>
        );
      }}
    </Load>
  );
}
