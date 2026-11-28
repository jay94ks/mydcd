// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ApiError, noEndpoint } from '../api/client';
import {
  acmeAccounts,
  acmeAuto,
  acmeCAs,
  AUTO_REASON,
  ignoreAutoHost,
  putAcmeAuto,
  type AcmeAuto,
  type AcmeAutoDomain,
  acmeCert,
  acmeCerts,
  acmeChainUrl,
  acmeErrorText,
  addAcmeAccount,
  addAcmeCert,
  daysLeft,
  DEFAULT_KEY_TYPES,
  isRsa,
  deleteAcmeAccount,
  deleteAcmeCert,
  issueAcmeCert,
  quickIssueAcmeCert,
  KEY_TYPE_LABEL,
  keyLabel,
  STEP_LABEL,
  STEP_ORDER,
  type AcmeAccount,
  type AcmeCA,
  type AcmeCert,
  type AcmeOrder,
} from '../api/acme';
import { dnsDomains, dnsRecords, type DnsDomain } from '../api/dns';
import { useAuth } from '../auth/session';
import { Badge, Card, Field, HelpBox, KV, PageHeader, Segmented, type Tone, ScreenIds } from '../components/ui';
import { Empty, ErrorBand, Load } from '../components/states';
import { ConfirmDialog, Dialog } from '../components/Dialog';
import { Menu } from '../components/Menu';
import { Tabs } from '../components/Tabs';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { usePhone } from '../lib/viewport';
import { MCerts } from './MCerts';
import { ago, fmtDate, fmtTime } from '../lib/format';
import { Popover } from '../components/Popover';
import { DOMAIN_TABS } from './Domains';
import { CERT_STATE, certChainUrl, certificates, deletable, issuerName, short, type StoreCert } from '../api/certs';
import { ingress, ingressMissing } from '../api/ingress';
import { DeleteCertDialog, DisableCertDialog, RevokeDialog, RsaWarn, UploadCertDialog } from './CertDetail';
import { randomUUID } from '../lib/cryptoCompat';
import { certStoreLive, domainListLive, ingressLive } from '../lib/liveTopics';

export const errText = (e: unknown) => (e instanceof ApiError ? acmeErrorText(e.code) || e.message : String(e));

/** 인증서 한 줄의 상태 */
export function certState(c: AcmeCert, staging: boolean): { tone: Tone; text: string } {
  const left = daysLeft(c.notAfter);
  if (c.running) return { tone: 'pr', text: c.fingerprint ? '갱신 중' : '발급 중' };
  if (!c.fingerprint) return { tone: 'un', text: '발급 전' };
  if (left !== undefined && left < 0) return { tone: 'er', text: '만료됨' };
  if (c.failures > 0) return { tone: 'er', text: `갱신 실패 ${c.failures}회` };
  if (c.renewBlocked) return { tone: 'wa', text: '직접 갱신 필요' };
  if (staging) return { tone: 'un', text: '시험용' };
  if (left !== undefined && left <= 14) return { tone: 'wa', text: '곧 만료' };
  return { tone: 'ok', text: '정상' };
}

export function nextText(c: AcmeCert): string {
  if (c.running) return '지금 도는 중';
  if (!c.autoRenew) return '자동 갱신 꺼짐';
  if (c.nextTry && c.failures) return `실패 · 다음 시도 ${fmtTime(c.nextTry)}`;
  if (c.renewBlocked) return '직접 갱신 필요(위임 계정 대기)';
  return c.nextRenew ? `${fmtDate(c.nextRenew)} 전후 자동 갱신` : '—';
}

export function useCaOf() {
  const aq = usePoll((s) => acmeAccounts(s), []);
  const cq = usePoll((s) => acmeCAs(s), []);
  const caOf = (account: string) => cq.data?.find((c) => c.id === aq.data?.find((a) => a.id === account)?.ca);
  return { aq, cq, caOf };
}

export function CertsPage() {
  return usePhone() ? <MCerts /> : <DesktopCertsPage />;
}

/** 목록 한 줄: 보관함 인증서(발급 정의가 있으면 함께) 또는 아직 보관함에 없는 발급 정의 */
export interface CertRow {
  key: string;
  cert?: StoreCert;
  def?: AcmeCert;
}
export function certRows(store: StoreCert[], defs: AcmeCert[]): CertRow[] {
  return [
    ...store.map((c) => ({ key: c.id, cert: c, def: defs.find((d) => (c.definition ? d.name === c.definition : d.fingerprint === c.id)) })),
    ...defs.filter((d) => !store.some((c) => c.id === d.fingerprint)).map((d) => ({ key: `def:${d.name}`, def: d })),
  ];
}
export const rowHref = (r: CertRow) => `/system/domains/certs/${encodeURIComponent(r.cert ? r.cert.id : r.def!.name)}`;
/** 상태 칸: 발급 진행·실패가 보관함 상태보다 먼저 */
export function rowState(r: CertRow): { tone: Tone; text: string } {
  const d = r.def;
  if (d?.running) return r.cert ? { tone: 'pr', text: '연결됨 · 갱신 중' } : { tone: 'pr', text: d.autoIssued ? '자동 발급 중' : '발급 중' };
  if (d && d.failures > 0 && (!r.cert || r.cert.state === 'linked')) return { tone: 'er', text: `갱신 실패 ${d.failures}회` };
  if (!r.cert) return d?.fingerprint ? { tone: 'un', text: '보관함에 없음' } : { tone: 'un', text: '발급 전' };
  if (r.cert.disabled) return { tone: 'wa', text: '파기 대기 · 끊음' };
  const [text, tone] = CERT_STATE[r.cert.state];
  return { tone, text };
}
export function linkText(c?: StoreCert) {
  if (!c) return '링크 없음';
  if (c.links.length) {
    const hosts = new Set(c.links.map((l) => l.host)).size;
    return `호스트 ${hosts}${c.links.every((l) => l.alg === 'rsa') ? ' · RSA 링크' : ''}`;
  }
  return c.disabled ? '0 · 끊음' : c.state === 'pending-destroy' ? '0 · 새 인증서가 가져감' : '0 · 등록된 도메인 없음';
}
/** ID 아래 작은 줄: 발급 정의 · 인증 기관 / 직접 올림 · 발급자 */
export function sourceText(r: CertRow, caName?: string) {
  if (r.def && (!r.cert || r.def.fingerprint === r.cert.id || r.cert.definition)) return r.def.autoIssued && !r.cert ? '자동 발급' : `정의 ${r.def.name}${caName ? ` · ${caName}` : ''}`;
  if (r.cert?.uploadedBy === 'sfc-web-tls' || (r.cert && r.cert.state === 'pending-destroy' && /Let's Encrypt/.test(r.cert.issuer))) return `이전 갱신분 · ${issuerName(r.cert.issuer)}`;
  return `직접 올림 · ${issuerName(r.cert?.issuer)}`;
}

type View = 'all' | 'linked' | 'unlinked' | 'pending' | 'soon' | 'failed';

function DesktopCertsPage() {
  const { session } = useAuth();
  const nav = useNavigate();
  const toast = useToast();
  const q = usePoll((s) => acmeCerts(s), [], 5000);
  const vq = usePoll((s) => certificates({}, s), [], 0, certStoreLive);
  const dq = usePoll((s) => dnsDomains(s), [], 0, domainListLive);
  const { aq, cq, caOf } = useCaOf();
  const [view, setView] = useState<View>('all');
  const [dlg, setDlg] = useState<
    { kind: 'issue' } | { kind: 'upload' } | { kind: 'account' } | { kind: 'delete'; c: AcmeCert } | { kind: 'delAccount'; a: AcmeAccount } | { kind: 'certDelete' | 'disable'; c: StoreCert; def?: AcmeCert } | { kind: 'revoke'; c: StoreCert; def: AcmeCert }
  >();
  if (!session?.user.systemAdmin)
    return (
      <>
        <PageHeader title="외부 도메인" ids="UI-57" />
        <Tabs label="외부 도메인 탭" items={DOMAIN_TABS()} />
        <Empty kind="scope" title="시스템 관리자만 인증서를 다룹니다" />
      </>
    );
  const defs = q.data?.items ?? [];
  const ready = vq.data !== undefined;
  const vMissing = (vq.error !== undefined && (noEndpoint(vq.error) || ingressMissing(vq.error)));
  const all = certRows(ready ? (vq.data ?? []) : [], defs);
  const soon = (r: CertRow) => (daysLeft(r.cert?.notAfter ?? r.def?.notAfter) ?? 999) <= 30;
  const failedRow = (r: CertRow) => !!r.def && r.def.failures > 0;
  const count = (st: StoreCert['state']) => all.filter((r) => r.cert?.state === st).length;
  const rows = all.filter((r) =>
    view === 'linked' ? r.cert?.state === 'linked' : view === 'unlinked' ? r.cert?.state === 'unlinked' : view === 'pending' ? r.cert?.state === 'pending-destroy' : view === 'soon' ? soon(r) : view === 'failed' ? failedRow(r) : true,
  );
  const failed = defs.filter((c) => c.failures > 0);
  const waitPending = vMissing ? '서버 기능 대기 · sfcd 인증서 보관함(certificate-store.md)이 들어오면 켭니다' : undefined;
  const renew = async (c: AcmeCert) => {
    try {
      await quickIssueAcmeCert(c.name);
      toast(`${c.name} 발급을 시작했습니다. 창을 닫아도 계속됩니다`);
      q.refresh();
    } catch (e) {
      toast(`! ${c.name} ${errText(e)}`, 'er');
    }
  };
  return (
    <>
      <PageHeader
        title="외부 도메인"
        ids="UI-57"
        actions={
          <>
            <Badge tone="un">클러스터 전체 · 시스템 관리자</Badge>
            <button className="btn" onClick={() => setDlg({ kind: 'account' })}>
              인증 기관 계정
            </button>
            <button className="btn" disabled={!!waitPending} title={waitPending} onClick={() => setDlg({ kind: 'upload' })}>
              ⇪ 인증서 올리기
            </button>
            <button className="btn primary" onClick={() => setDlg({ kind: 'issue' })}>
              ＋ 인증서 발급
            </button>
          </>
        }
      />
      <Tabs label="외부 도메인 탭" items={DOMAIN_TABS(dq.data?.length, all.length)} />
      <HelpBox terms="인증서 ID (leaf 지문 SHA-256 앞 12자) · 링크 (호스트+알고리즘 → 인증서) · 연결됨 / 미연결 (등록된 도메인 아래 이름이 없음) / 파기 대기 (링크를 모두 새 인증서가 가져감) · DNS 확인 (DNS-01) · HTTP 확인 (HTTP-01) · 발급 정의 (웹이 자동 발급·갱신에 쓰는 설정)">
        <b>이 탭은</b> 클러스터 인증서 보관함에 든 인증서를 보여 주고, 등록된 도메인 아래 이름의 인증서를 Let's Encrypt 같은 인증 기관에서 자동으로 받고 갱신합니다. 소유 확인은 DNS 공급자가 연결된 도메인이면 DNS 확인(와일드카드 가능), 아니면 HTTP 확인(외부 접속 :80)으로 합니다. 인증서는 이름 없이 올리고, 보관함이 인증서 안의 이름(SAN)을 읽어 호스트와 알고리즘마다 하나씩 <b>링크</b>합니다. 외부 접속은 접속한 호스트로 링크를 찾아 ECDSA를 먼저 씁니다.
      </HelpBox>
      <Card
        title={`인증서 (${all.length})`}
        actions={
          <Segmented
            label="인증서 보기"
            value={view}
            onChange={setView}
            options={[
              ['all', '전체'],
              ['linked', `연결됨 ${count('linked')}`],
              ['unlinked', `미연결 ${count('unlinked')}`],
              ['pending', `파기 대기 ${count('pending-destroy')}`],
              ['soon', '30일 안 만료'],
              ['failed', '실패'],
            ]}
          />
        }
      >
        <div className="note info">
          <b>등록된 도메인 아래 이름만 링크하고 자동 발급합니다.</b> <span className="mono">grafana.internal</span>처럼 도메인 목록에 없는 이름의 인증서는 올려도 <b>미연결</b>로 남습니다. 그 이름을 쓰려면 <Link to="/system/domains">외부 도메인</Link> 탭에서 도메인을 등록하세요(공급자 없이도 됩니다). 공개 인증 기관은 바깥에서 확인할 수 없는 이름에 발급하지 않으므로, 사내 이름은 사내 인증 기관에서 받아 ‘인증서 올리기’로 넣습니다.
        </div>
        {vMissing && <div className="note wa small">보관함 목록은 서버 기능 대기입니다. sfcd 인증서 보관함(ID·링크·상태)이 들어오기 전까지 웹 발급 정의만 보입니다.</div>}
        <Load q={q}>
          {() =>
            all.length === 0 ? (
              <Empty title="인증서가 없습니다" action={<button className="btn primary" onClick={() => setDlg({ kind: 'issue' })}>＋ 인증서 발급</button>}>
                등록된 도메인 아래 이름으로 인증서를 받거나, 직접 받은 인증서를 올리세요.
              </Empty>
            ) : rows.length === 0 ? (
              <Empty kind="filtered" title="조건에 맞는 인증서가 없습니다" />
            ) : (
              <div className="table-wrap">
                <table className="tbl" style={{ tableLayout: 'fixed', minWidth: 1000 }}>
                  <colgroup>
                    <col style={{ width: '17%' }} />
                    <col />
                    <col style={{ width: '12%' }} />
                    <col style={{ width: '9%' }} />
                    <col style={{ width: '13%' }} />
                    <col style={{ width: '13%' }} />
                    <col style={{ width: '14%' }} />
                    <col style={{ width: 56 }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>인증서 ID</th>
                      <th>포함한 이름</th>
                      <th>알고리즘</th>
                      <th>만료</th>
                      <th>다음 갱신</th>
                      <th>링크</th>
                      <th>상태</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => {
                      const { cert: c, def: d } = r;
                      const st = rowState(r);
                      const left = daysLeft(c?.notAfter ?? d?.notAfter);
                      const kt = c?.keyType ?? d?.keyType ?? d?.keyTypes[0];
                      const current = !!d && (!c || d.fingerprint === c.id);
                      const href = rowHref(r);
                      return (
                        <tr key={r.key} style={c && c.state !== 'linked' ? { opacity: 0.85 } : undefined}>
                          <td>
                            <Link className="mono" style={{ fontWeight: 600 }} to={href} title={c?.id}>
                              {c ? short(c.id) : 'ID 없음'}
                            </Link>
                            {!c && <span className="muted small">{d?.running ? ' (발급 중)' : ''}</span>}
                            <span className="small muted el" style={{ display: 'block' }}>
                              {sourceText(r, d ? caOf(d.account)?.name : undefined)}
                            </span>
                          </td>
                          <td className="mono el" title={(c?.names ?? d?.names ?? []).join(', ')}>
                            {(c?.names ?? d?.names ?? []).join(', ')}
                          </td>
                          <td>
                            {keyLabel(kt)}
                            {kt && isRsa(kt) && (
                              <>
                                {' '}
                                <Badge tone="wa">권장하지 않음</Badge>
                              </>
                            )}
                          </td>
                          <td>{left === undefined ? (d?.running ? '발급 중' : '—') : `${left}일 남음`}</td>
                          <td className="el small">{current && d ? (d.autoIssued && !c ? `새 호스트 규칙 감지 ${ago(d.autoIssued.detectedAt)}` : nextText(d)) : c?.state === 'linked' ? <span className="muted">자동 갱신 안 됨</span> : <span className="muted">—</span>}</td>
                          <td className="small el">{linkText(c)}</td>
                          <td>
                            <span className="row" style={{ gap: 6 }}>
                              <Badge tone={st.tone}>{st.text}</Badge>
                              {c && deletable(c) && (
                                <button type="button" className="linkish small" onClick={() => setDlg({ kind: 'certDelete', c, def: d })}>
                                  지우기
                                </button>
                              )}
                            </span>
                          </td>
                          <td>
                            <Menu
                              items={[
                                { label: '상세', onSelect: () => nav(href) },
                                ...(current && d ? [{ label: '지금 갱신', hint: '발급 정의가 있을 때', onSelect: () => void renew(d), disabledReason: d.running ? '이미 도는 중입니다' : undefined }] : []),
                                ...(c ? [{ label: '공개 체인 내려받기', onSelect: () => window.open(certChainUrl(c.id)) }] : d?.fingerprint ? [{ label: '공개 체인 내려받기', onSelect: () => window.open(acmeChainUrl(d.name)) }] : []),
                                ...(c && c.state === 'linked' ? [{ label: '끊기…', danger: true, hint: '키가 샜을 때 · 링크를 모두 뗌', onSelect: () => setDlg({ kind: 'disable', c, def: current ? d : undefined }) }] : []),
                                ...(c && current && d ? [{ label: '해지…', danger: true, hint: '인증 기관에', onSelect: () => setDlg({ kind: 'revoke', c, def: d }) }] : []),
                                ...(current && d ? [{ label: '정의 지우기…', danger: true, hint: '자동 발급 정의만', onSelect: () => setDlg({ kind: 'delete', c: d }) }] : []),
                                ...(c && deletable(c) ? [{ label: '지우기…', danger: true, hint: '미연결 · 파기 대기만', onSelect: () => setDlg({ kind: 'certDelete', c, def: d }) }] : []),
                              ]}
                            />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )
          }
        </Load>
        <span className="small muted">
          지우기는 <b>미연결 · 파기 대기</b>에서만 됩니다. 연결됨 인증서는 서버가 지우기를 거절합니다. 만료된 인증서는 서버가 자동으로 지우고 목록에서 사라집니다(작업 기록에 남음). 같은 호스트에 ECDSA와 RSA를 함께 둘 수 있고, 외부 접속은 ECDSA를 먼저 씁니다.
        </span>
        {failed.map((c) => {
          const left = daysLeft(c.notAfter);
          return (
            <div key={c.name} className="note er row between">
              <span>
                ⚠ <b>{c.name}</b> 갱신 실패 {c.failures}회{left !== undefined ? ` · ${left}일 남음` : ''}
                {c.nextTry ? ` · 다음 시도 ${fmtTime(c.nextTry)}` : ''}. <Link to={`/system/domains/certs/${encodeURIComponent(c.fingerprint && all.some((r) => r.cert?.id === c.fingerprint) ? c.fingerprint : c.name)}`}>기록 보기</Link>
              </span>
              <button className="btn sm" disabled={c.running} onClick={() => void renew(c)}>
                지금 다시 시도
              </button>
            </div>
          );
        })}
      </Card>
      <div className="grid-2">
        <AutoIssueCard accounts={aq.data ?? []} cas={cq.data ?? []} domains={dq.data ?? []} onUpload={() => setDlg({ kind: 'upload' })} />
        <Card title="인증 기관 계정" actions={<button className="btn sm" onClick={() => setDlg({ kind: 'account' })}>＋ 계정</button>}>
          <Load q={aq}>
            {(as) =>
              as.length === 0 ? (
                <Empty title="계정이 없습니다">인증서를 받으려면 인증 기관 계정이 하나 있어야 합니다.</Empty>
              ) : (
                <div className="table-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>인증 기관</th>
                        <th>연락 이메일</th>
                        <th>계정 키</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {as.map((a) => {
                        const ca = cq.data?.find((x) => x.id === a.ca);
                        return (
                          <tr key={a.id}>
                            <td>
                              {ca?.name ?? a.ca}
                              {a.eab ? <span className="muted"> · 외부 계정 연결</span> : ''}
                            </td>
                            <td>{a.email ?? '—'}</td>
                            <td className="muted">봉인 파일</td>
                            <td>
                              <Menu items={[{ label: '계정 지우기…', danger: true, onSelect: () => setDlg({ kind: 'delAccount', a }) }]} />
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )
            }
          </Load>
          <span className="small muted">ZeroSSL·Google 등은 외부 계정 연결(EAB) 키로, 사내 ACME는 디렉터리 주소와 루트 인증서로 추가합니다. 계정 키는 웹 컨테이너의 봉인 파일에만 있습니다.</span>
        </Card>
        <Card title={`자동 갱신 · 인증서 ${defs.filter((c) => c.autoRenew).length}/${defs.length}`}>
          <KV
            items={[
              ['검사', '1시간마다 · 남은 기간이 1/3 이하가 되면 갱신'],
              ['실패 때', '1시간 → 6시간 → 하루 간격 재시도, 14·7·3일 남으면 장애 대응 사건'],
              ['만료된 인증서', '서버가 만료 시각에 지웁니다(상태와 상관없이). 웹의 발급 정의는 남아 다시 발급할 수 있습니다.'],
              ['키 알고리즘', '인증서마다 선호 순서에서 인증 기관이 받는 첫 번째'],
              ['실행 계정', '웹 자동 작업 계정 · 인증서 보관함 올리기(put-certificate)만 위임. 계정이 없으면 "직접 갱신 필요" 알림을 남깁니다'],
            ]}
          />
        </Card>
      </div>
      {dlg?.kind === 'issue' && <IssueDialog domains={dq.data ?? []} accounts={aq.data ?? []} cas={cq.data ?? []} taken={defs.map((c) => c.name)} onClose={() => setDlg(undefined)} onChanged={() => q.refresh()} onAccount={() => setDlg({ kind: 'account' })} />}
      {dlg?.kind === 'upload' && <UploadCertDialog onClose={() => setDlg(undefined)} onDone={(id) => (vq.refresh(), nav(`/system/domains/certs/${id}`))} />}
      {dlg?.kind === 'certDelete' && <DeleteCertDialog c={dlg.c} all={vq.data ?? []} onClose={() => setDlg(undefined)} onDone={() => vq.refresh()} />}
      {dlg?.kind === 'disable' && <DisableCertDialog c={dlg.c} all={vq.data ?? []} def={dlg.def} onClose={() => setDlg(undefined)} onDone={() => (vq.refresh(), q.refresh())} />}
      {dlg?.kind === 'revoke' && <RevokeDialog c={dlg.c} def={dlg.def} onClose={() => setDlg(undefined)} onDone={() => q.refresh()} />}
      {dlg?.kind === 'account' && <AccountDialog cas={cq.data ?? []} onClose={() => setDlg(undefined)} onDone={() => aq.refresh()} />}
      {dlg?.kind === 'delete' && (
        <SimpleConfirm
          title={`${dlg.c.name} 정의를 지울까요?`}
          target={dlg.c.name}
          action="지우기"
          run={() => deleteAcmeCert(dlg.c.name)}
          onClose={() => setDlg(undefined)}
          onDone={() => q.refresh()}
        >
          웹의 자동 발급·갱신 정의만 지웁니다. 보관함의 인증서와 링크는 그대로이고, 자동 갱신은 멈춥니다.
        </SimpleConfirm>
      )}
      {dlg?.kind === 'delAccount' && (
        <SimpleConfirm title="이 인증 기관 계정을 지울까요?" target={dlg.a.email ?? dlg.a.id} action="지우기" run={() => deleteAcmeAccount(dlg.a.id)} onClose={() => setDlg(undefined)} onDone={() => aq.refresh()}>
          봉인한 계정 키를 지웁니다. 이 계정을 쓰는 인증서가 있으면 지울 수 없습니다.
        </SimpleConfirm>
      )}
    </>
  );
}

export function SimpleConfirm({ title, target, action, run, onClose, onDone, children }: { title: string; target: string; action: string; run: () => Promise<unknown>; onClose: () => void; onDone: () => void; children: React.ReactNode }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  return (
    <ConfirmDialog
      title={title}
      target={target}
      actionLabel={action}
      busy={busy}
      onClose={onClose}
      onConfirm={() => {
        setBusy(true);
        run().then(
          () => (onDone(), onClose()),
          (e) => (setError(e), setBusy(false)),
        );
      }}
    >
      {error !== undefined && <div className="note er">{errText(error)}</div>}
      <p>{children}</p>
    </ConfirmDialog>
  );
}

function AccountDialog({ cas, onClose, onDone }: { cas: AcmeCA[]; onClose: () => void; onDone: () => void }) {
  const [ca, setCa] = useState(cas.find((c) => c.ready && c.staging)?.id ?? cas.find((c) => c.ready)?.id ?? '');
  const [email, setEmail] = useState('');
  const [agree, setAgree] = useState(false);
  const [keyId, setKeyId] = useState('');
  const [hmac, setHmac] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const sel = cas.find((c) => c.id === ca);
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await addAcmeAccount({ ca, email: email.trim() || undefined, agreeTos: true, eab: sel?.needsEab ? { keyId, hmac } : undefined });
      setHmac('');
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Dialog
      title="인증 기관 계정 추가"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!sel?.ready || !agree || busy || (sel.needsEab && (!keyId || !hmac))} onClick={() => void save()}>
            {busy ? '만드는 중…' : '계정 만들기'}
          </button>
        </>
      }
    >
      {error !== undefined && <div className="note er">{errText(error)}</div>}
      <Field label="인증 기관">
        <select value={ca} onChange={(e) => setCa(e.target.value)}>
          {cas.map((c) => (
            <option key={c.id} value={c.id} disabled={!c.ready}>
              {c.name}
              {c.ready ? '' : ` (${c.note ?? '준비 중'})`}
            </option>
          ))}
        </select>
      </Field>
      <Field label="연락 이메일 (선택)" hint="만료 안내를 인증 기관이 보낼 곳">
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      {sel?.needsEab && (
        <div className="g2">
          <Field label="외부 계정 연결 키 ID">
            <input className="mono" value={keyId} onChange={(e) => setKeyId(e.target.value)} />
          </Field>
          <Field label="HMAC (base64)">
            <input type="password" className="mono" autoComplete="off" value={hmac} onChange={(e) => setHmac(e.target.value)} />
          </Field>
        </div>
      )}
      <label className="check">
        <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)} /> {sel?.name ?? '인증 기관'}의 이용 약관에 동의합니다
      </label>
      <span className="small muted">계정 키는 웹이 만들어 봉인 파일에 둡니다. 시험용 인증 기관으로 먼저 해 보면 요청 수 제한을 쓰지 않습니다.</span>
    </Dialog>
  );
}

/** 이름이 연결된 외부 도메인 중 어디에 속하나 */
const domainFor = (n: string, ds: DnsDomain[]) => {
  const base = n.replace(/^\*\./, '');
  return ds.filter((d) => base === d.domain || base.endsWith(`.${d.domain}`)).sort((a, b) => b.domain.length - a.domain.length)[0];
};

/** UI-58: ① 이름 → ② 인증 기관·키 → ③ 사전 검사 → ④ 발급(뒤에서 계속) */
function IssueDialog({ domains, accounts, cas, taken, onClose, onChanged, onAccount }: { domains: DnsDomain[]; accounts: AcmeAccount[]; cas: AcmeCA[]; taken: string[]; onClose: () => void; onChanged: () => void; onAccount: () => void }) {
  const [step, setStep] = useState(1);
  const [name, setName] = useState('');
  const [names, setNames] = useState<string[]>([]);
  const [typed, setTyped] = useState('');
  const [account, setAccount] = useState(accounts.find((a) => cas.find((c) => c.id === a.ca)?.staging)?.id ?? accounts[0]?.id ?? '');
  const [keys, setKeys] = useState<string[]>(DEFAULT_KEY_TYPES);
  const [auto, setAuto] = useState(true);
  const [checks, setChecks] = useState<{ label: string; ok: boolean | undefined; text: string }[]>();
  const [order, setOrder] = useState<AcmeOrder>();
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const opId = useRef(randomUUID());
  const ca = cas.find((c) => c.id === accounts.find((a) => a.id === account)?.ca);
  const nameBad = !name ? '이름을 적으세요' : !/^[a-z0-9][a-z0-9-]{0,62}$/.test(name) ? '영문 소문자·숫자·-' : taken.includes(name) ? '같은 이름의 발급 정의가 있습니다' : undefined;
  // 확인 방식은 이름마다 서버가 정한다: 공급자가 붙은 도메인 아래면 DNS 확인, 아니면 HTTP 확인, 와일드카드는 DNS 확인만
  const nameDomains = [...new Set(names.map((n) => domainFor(n, domains)).filter(Boolean))] as DnsDomain[];
  const methodOf = (n: string) => (domainFor(n, domains)?.provider ? 'dns-01' : n.startsWith('*.') ? null : 'http-01');
  const methods = names.map(methodOf);
  const usesDns = methods.includes('dns-01');
  const usesHttp = methods.includes('http-01');
  const blocked = names.filter((n) => methodOf(n) === null);
  const addName = () => {
    const n = typed.trim().toLowerCase().replace(/\.$/, '');
    if (!n || names.includes(n)) return;
    setNames([...names, n]);
    setTyped('');
    if (!name) setName(n.replace(/^\*\./, '').split('.').slice(0, 2).join('-').replace(/[^a-z0-9-]/g, '-'));
  };
  const typedBad = typed && !/^(\*\.)?([a-z0-9-]+\.)+[a-z0-9-]+$/i.test(typed.trim()) ? '도메인 이름 모양이 아닙니다' : typed && !domainFor(typed.trim(), domains) ? '등록된 도메인 아래 이름이 아닙니다' : undefined;

  // ③ 사전 검사: 이름마다 외부 도메인, CAA, 키 형식. 서버도 preflight 단계에서 다시 본다.
  useEffect(() => {
    if (step !== 3) return;
    let live = true;
    setChecks(undefined);
    (async () => {
      const out: { label: string; ok: boolean | undefined; text: string }[] = [];
      const ds = [...new Set(names.map((n) => domainFor(n, domains)).filter(Boolean))] as DnsDomain[];
      const missing = names.filter((n) => !domainFor(n, domains));
      out.push({ label: '외부 도메인 · DNS 공급자', ok: missing.length === 0, text: missing.length ? `등록된 도메인 아래가 아님: ${missing.join(', ')}` : ds.map((d) => `${d.domain} · ${d.provider ? `${d.provider.name} (레코드 쓰기 가능)` : '공급자 없음 · HTTP 확인'}`).join(', ') });
      for (const d of ds) {
        if (!d.provider) {
          out.push({ label: `CAA · ${d.domain}`, ok: undefined, text: '공급자가 없어 읽지 않음 · 서버가 발급할 때 봅니다' });
          continue;
        }
        try {
          const z = await dnsRecords(d.domain);
          const caa = z.items.filter((r) => r.type === 'CAA' && r.name === '@').flatMap((r) => r.records.map((x) => x.content));
          const issues = caa.filter((x) => /\bissue(wild)?\b/.test(x));
          const okCaa = issues.length === 0 || issues.some((x) => ca && x.includes(ca.caa));
          out.push({ label: `CAA · ${d.domain}`, ok: okCaa, text: issues.length ? issues.join(', ') + (okCaa ? ' 있음' : ` · ${ca?.caa}이(가) 없어 발급이 막힙니다`) : '없음 · 어느 인증 기관이든 발급 가능' });
        } catch {
          out.push({ label: `CAA · ${d.domain}`, ok: undefined, text: '공급자에서 읽지 못함 · 서버가 발급할 때 다시 봅니다' });
        }
      }
      const kt = keys.find((k) => ca?.keyTypes.includes(k));
      out.push({ label: '키 형식', ok: !!kt, text: kt ? `${KEY_TYPE_LABEL[kt]}${kt !== keys[0] ? ' (1순위가 아니라 알림을 남깁니다)' : ''}` : '인증 기관이 받는 형식이 없습니다' });
      if (live) setChecks(out);
    })();
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  // ④ 발급 진행: 창을 닫아도 서버에서 계속되고, 여기서는 2초마다 단계를 읽는다.
  useEffect(() => {
    if (step !== 4 || !order || order.state !== 'running') return;
    const t = setTimeout(() => {
      acmeCert(name).then(
        (r) => {
          const o = r.orders?.find((x) => x.id === order.id);
          if (o) setOrder(o);
          if (o && o.state !== 'running') onChanged();
        },
        () => undefined,
      );
    }, 2000);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, order]);

  const issue = async () => {
    setBusy(true);
    setError(undefined);
    try {
      if (!taken.includes(name)) await addAcmeCert({ name, names, account, keyTypes: keys, autoRenew: auto });
      onChanged();
      const r = await issueAcmeCert(name, opId.current);
      setOrder(r.order);
      setStep(4);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const canNext = step === 1 ? !nameBad && names.length > 0 : step === 2 ? !!account && keys.length > 0 && blocked.length === 0 : step === 3 ? !!checks && checks.every((c) => c.ok !== false) : false;

  return (
    <Dialog
      title={
        <>
          인증서 발급 <ScreenIds ids="UI-58" />
        </>
      }
      width={720}
      onClose={onClose}
      footer={
        step === 4 ? (
          <>
            <span className="small muted">{order?.state === 'running' ? '이 창을 닫아도 발급은 웹 UI에서 계속됩니다.' : ''}</span>
            <span className="row">
              {order?.state !== 'running' && (
                <Link className="btn" to={`/system/domains/certs/${encodeURIComponent(name)}`} onClick={onClose}>
                  상세 보기
                </Link>
              )}
              <button className="btn primary" onClick={onClose}>
                {order?.state === 'running' ? '닫기 (뒤에서 계속)' : '닫기'}
              </button>
            </span>
          </>
        ) : (
          <>
            <button className="btn" disabled={step === 1 || busy} onClick={() => setStep(step - 1)}>
              이전
            </button>
            {step < 3 ? (
              <button className="btn primary" disabled={!canNext} onClick={() => setStep(step + 1)}>
                다음
              </button>
            ) : (
              <button className="btn primary" disabled={!canNext || busy} onClick={() => void issue()}>
                {busy ? '시작하는 중…' : ca?.staging ? '시험용으로 발급' : '발급'}
              </button>
            )}
          </>
        )
      }
    >
      <ol className="steps">
        {['이름', '인증 기관·키', '사전 검사', '발급'].map((t, i) => (
          <li key={t} className={i + 1 < step ? 'done' : i + 1 === step ? 'on' : ''}>
            {i + 1 < step ? '✓ ' : ''}
            {i + 1} {t}
          </li>
        ))}
      </ol>
      {error !== undefined && <div className="note er">{errText(error)}</div>}
      {step === 1 && (
        <>
          <Field label="포함할 이름 (외부 도메인에 있는 것만)" hint="Enter로 추가. *.shop.example.com 처럼 와일드카드도 됩니다" error={typedBad}>
            <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
              {names.map((n) => (
                <span key={n} className="chip">
                  <span className="mono">{n}</span>
                  <button type="button" className="chip-x" aria-label={`${n} 빼기`} onClick={() => setNames(names.filter((x) => x !== n))}>
                    ×
                  </button>
                </span>
              ))}
              <input
                className="mono grow"
                list="cert-domains"
                value={typed}
                placeholder="shop.example.com"
                onChange={(e) => setTyped(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !typedBad) {
                    e.preventDefault();
                    addName();
                  }
                }}
              />
              <button type="button" className="btn sm" disabled={!typed || !!typedBad} onClick={addName}>
                추가
              </button>
            </span>
            <datalist id="cert-domains">
              {domains.flatMap((d) => [d.domain, `*.${d.domain}`]).map((x) => (
                <option key={x} value={x} />
              ))}
            </datalist>
          </Field>
          {domains.length === 0 && (
            <div className="note wa">
              등록된 도메인이 없습니다. <Link to="/system/domains">외부 도메인</Link>에서 먼저 도메인을 등록하세요(공급자 없이도 됩니다).
            </div>
          )}
          <Field label="발급 정의 이름 (웹)" hint="웹이 자동 발급·갱신에 쓰는 이름입니다. 보관함의 인증서에는 이름이 없고 ID로 구분합니다" error={name && nameBad}>
            <input className="mono" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
        </>
      )}
      {step === 2 && (
        <>
          {accounts.length === 0 ? (
            <div className="note wa row between">
              <span>인증 기관 계정이 없습니다.</span>
              <button className="btn sm" onClick={onAccount}>
                ＋ 계정
              </button>
            </div>
          ) : (
            <Field label="인증 기관">
              <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                {accounts.map((a) => {
                  const c = cas.find((x) => x.id === a.ca);
                  return (
                    <label key={a.id} className={`choice ${a.id === account ? 'on' : ''}`}>
                      <input type="radio" name="acct" checked={a.id === account} onChange={() => setAccount(a.id)} /> {c?.name ?? a.ca}
                      {a.email ? <span className="muted small">{a.email}</span> : ''}
                    </label>
                  );
                })}
              </span>
            </Field>
          )}
          <Field label="키 형식" hint="발급마다 새 키를 만듭니다">
            <select value={keys[0] ?? 'ec256'} onChange={(e) => setKeys([e.target.value])}>
              {Object.entries(KEY_TYPE_LABEL).map(([k, l]) => (
                <option key={k} value={k} disabled={!!ca && !ca.keyTypes.includes(k)}>
                  {l}
                  {k === 'ec256' ? ' (권장)' : isRsa(k) ? ' · 권장하지 않음' : ''}
                </option>
              ))}
            </select>
          </Field>
          {keys.some(isRsa) && <RsaWarn />}
          <Field label="확인 방식" group hint="이름마다 서버가 정합니다">
            <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
              <label className={`choice ${usesDns ? 'on' : ''}`}>
                <input type="checkbox" disabled checked={usesDns} readOnly /> DNS 확인
                {usesDns ? ` · ${[...new Set(nameDomains.filter((d) => d.provider).map((d) => d.provider!.name))].join(', ')}` : ''} <span className="muted small">(와일드카드 가능)</span>
              </label>
              <label className={`choice ${usesHttp ? 'on' : ''}`}>
                <input type="checkbox" disabled checked={usesHttp} readOnly /> HTTP 확인 · 외부 접속 :80 <span className="muted small">(와일드카드 불가)</span>
              </label>
            </span>
          </Field>
          {blocked.length > 0 && <div className="note er small">와일드카드 이름({blocked.join(', ')})은 DNS 공급자가 붙은 도메인에서만 받을 수 있습니다. 공급자를 붙이거나 와일드카드를 빼세요.</div>}
          <label className="check">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> 자동 갱신 (유효 기간이 1/3 남으면)
          </label>
          <KV items={[['쓸 외부 접속', <WillUse key="w" names={names} />]]} />
        </>
      )}
      {step === 3 && (
        <>
          <b>사전 검사 결과</b>
          {!checks ? (
            <span className="small muted">검사하는 중…</span>
          ) : (
            <KV items={checks.map((c) => [c.label, <span key={c.label} style={{ color: c.ok === false ? 'var(--er)' : undefined }}>{c.ok === false ? '✗' : c.ok ? '✓' : '·'} {c.text}</span>])} />
          )}
          <span className="small muted">요청 수 제한 미리 세기는 아직 없습니다. 같은 이름을 자주 받을 때는 시험용 인증 기관을 먼저 쓰세요.</span>
        </>
      )}
      {step === 4 && order && <OrderSteps order={order} />}
      {step === 4 && <span className="small muted">비공개 키는 웹 메모리에서 만들어 인증서 보관함에만 올리고, 화면·내려받기·웹 데이터에는 남기지 않습니다.</span>}
    </Dialog>
  );
}

export function OrderSteps({ order }: { order: AcmeOrder }) {
  const seen = new Map(order.steps.map((s) => [s.name, s]));
  const failedAt = order.steps.find((s) => s.state === 'failed')?.name;
  return (
    <>
      <ol className="steps" style={{ flexDirection: 'column' }}>
        {STEP_ORDER.map((n) => {
          const s = seen.get(n);
          const cls = s?.state === 'done' ? 'done' : s?.state === 'running' ? 'on' : '';
          return (
            <li key={n} className={cls} style={s?.state === 'failed' ? { background: 'var(--er-bg)', color: 'var(--er)' } : s?.state === 'skipped' || (!s && failedAt) ? { opacity: 0.55 } : undefined}>
              {s?.state === 'done' ? '✓ ' : s?.state === 'failed' ? '✗ ' : s?.state === 'running' ? '◔ ' : ''}
              {STEP_LABEL[n] ?? n}
              {s?.at && s.state !== 'running' ? <span className="small"> · {fmtTime(s.at).slice(-8)}</span> : ''}
              {s?.detail ? <span className="small"> · {s.detail}</span> : ''}
            </li>
          );
        })}
      </ol>
      {order.state === 'failed' && <div className="note er">발급 실패 · {acmeErrorText(order.errorCode)}</div>}
      {order.state === 'done' && <div className="note ok">✓ 발급했습니다{order.keyType ? ` · ${KEY_TYPE_LABEL[order.keyType] ?? order.keyType}` : ''}. 인증서 보관함에 새 버전으로 올렸습니다.</div>}
      {order.orphanTxt?.length ? <div className="note wa">지우지 못한 TXT: {order.orphanTxt.join(', ')} · 외부 도메인에서 지우세요.</div> : null}
    </>
  );
}

// ── 자동 발급 ─────────────────────────────

const KEY_NOTE: Record<string, string> = { ec256: '기본 · 권장', ec384: '보안 기준이 높을 때' };
const keyChain = (ks: string[]) => ks.map((k) => (KEY_TYPE_LABEL[k] ?? k).replace('ECDSA ', '')).join(' → ');

/** 자동 발급 도메인에 DNS 공급자가 없으면 HTTP 확인만(와일드카드 불가). 하위 이름(shop.example.com)은 등록된 상위 도메인을 따른다 */
export const httpOnly = (domain: string, ds: DnsDomain[]) => {
  const reg = ds.filter((d) => domain === d.domain || domain.endsWith(`.${d.domain}`)).sort((a, b) => b.domain.length - a.domain.length)[0];
  return reg ? !reg.provider : false;
};

function AutoIssueCard({ accounts, cas, domains, onUpload }: { accounts: AcmeAccount[]; cas: AcmeCA[]; domains: DnsDomain[]; onUpload: () => void }) {
  const toast = useToast();
  const q = usePoll((s) => acmeAuto(s), [], 30000);
  const [edit, setEdit] = useState(false);
  const missing = q.error !== undefined && q.error instanceof ApiError && (q.error.status === 404 || q.error.status === 405);
  const a = q.data;
  const cols = { gridTemplateColumns: '1.1fr 0.6fr 1.4fr 1.6fr 0.9fr' };
  return (
    <Card
      title="자동 발급"
      actions={
        <span className="row" style={{ gap: 8 }}>
          {a && <Badge tone={a.enabled ? 'ok' : 'un'}>{a.enabled ? '켜짐' : '꺼짐'}</Badge>}
          <button className="btn sm" disabled={!a} onClick={() => setEdit(true)}>
            설정
          </button>
        </span>
      }
    >
      <span className="small muted">외부 접속의 :443 호스트 규칙 중 맞는 인증서가 없는 호스트를 1분마다 찾아 바로 발급합니다. 외부 접속은 호스트와 맞는 인증서를 스스로 골라 쓰므로 앱을 다시 배포하지 않습니다.</span>
      {missing ? (
        <Empty kind="scope" title="웹 기능 준비 중">
          자동 발급 설정과 대기 목록은 웹 데몬에 이 기능이 들어오면 켭니다. 그때까지는 '＋ 인증서 발급'으로 직접 받으세요.
        </Empty>
      ) : (
        <Load q={q} rows={3} what="자동 발급 설정을 읽지 못했습니다">
          {(d) => (
            <>
              <div className="gtbl">
                <div className="gr th" style={cols}>
                  <span>외부 도메인</span>
                  <span>자동 발급</span>
                  <span>방식</span>
                  <span>키 알고리즘 (선호 순)</span>
                  <span>작업 공간 배정</span>
                </div>
                {d.domains.map((x) => (
                  <div key={x.domain} className="gr" style={cols}>
                    <span className="mono">{x.domain}</span>
                    <span>
                      <Badge tone={x.enabled ? 'ok' : 'un'}>{x.enabled ? '켬' : '끔'}</Badge>
                    </span>
                    <span>
                      {!x.enabled ? '직접 발급만' : x.mode === 'wildcard' && !httpOnly(x.domain, domains) ? `와일드카드로 묶기 (*.${x.domain})` : '호스트마다 따로'}
                      {x.enabled && httpOnly(x.domain, domains) && <span className="muted small"> · HTTP 확인 (공급자 없음 · 와일드카드 불가)</span>}
                    </span>
                    <span className={x.keyTypes ? '' : 'muted'}>{!x.enabled ? '—' : x.keyTypes ? `${keyChain(x.keyTypes)}${d.dualRsa ? ' + RSA 함께' : ''}` : `기본 (${keyChain(d.keyTypes)})`}</span>
                    <span>{!x.enabled || !x.tenants.length ? '—' : x.tenants.length > 1 ? '여러 곳' : x.tenants[0]}</span>
                  </div>
                ))}
              </div>
              {d.waiting.length > 0 && (
                <>
                  <b className="small">자동 발급 대기 ({d.waiting.length})</b>
                  <div className="gtbl">
                    {d.waiting.map((w) => (
                      <div key={w.host} className="gr" style={{ gridTemplateColumns: '1fr 3fr auto' }}>
                        <Popover button={<span className="mono">{w.host}</span>} className="linkish" width={360}>
                          {(close) => (
                            <div style={{ display: 'grid', gap: 10 }}>
                              <b>자동 발급 대기</b>
                              <KV
                                items={[
                                  ['호스트', <span key="h" className="mono">{w.host}</span>],
                                  ['쓰는 곳', `${w.app ?? '—'}${w.tenant ? ` (${w.tenant})` : ''} · ${w.node} ${w.listen}`],
                                  ['이유', AUTO_REASON[w.reason] ?? w.reason],
                                ]}
                              />
                              <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                                <Link className="btn sm" to="/system/domains">
                                  {w.reason === 'not-assigned' ? '작업 공간에 도메인 배정' : w.reason === 'no-domain' || w.reason === 'not-registered' ? '도메인 등록' : w.reason === 'wildcard-needs-provider' ? '공급자 붙이기' : '외부 도메인'}
                                </Link>
                                <button className="btn sm" onClick={() => (close(), onUpload())}>
                                  직접 받은 인증서 올리기
                                </button>
                                <button
                                  className="btn sm"
                                  onClick={async () => {
                                    try {
                                      await ignoreAutoHost(w.host);
                                      toast(`${w.host}을(를) 자동 발급에서 무시합니다.`);
                                      close();
                                      q.refresh();
                                    } catch (e) {
                                      toast(`! ${errText(e)}`, 'er');
                                    }
                                  }}
                                >
                                  이 호스트 무시
                                </button>
                              </div>
                            </div>
                          )}
                        </Popover>
                        <span className="small">
                          {AUTO_REASON[w.reason] ?? w.reason} · {w.node} {w.listen} · {ago(w.since).replace(' 전', '')}째
                        </span>
                        <Link to="/system/domains" className="small">
                          {w.reason === 'no-domain' || w.reason === 'not-registered' ? '도메인 등록' : w.reason === 'not-assigned' ? '도메인 배정' : '외부 도메인'}
                        </Link>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </>
          )}
        </Load>
      )}
      {edit && a && <AutoSettingsDialog a={a} accounts={accounts} cas={cas} regs={domains} onClose={() => setEdit(false)} onDone={() => q.refresh()} />}
    </Card>
  );
}

/** 키 알고리즘 선호 순서: 켠 것만 위에서부터 시도한다. */
function KeyOrder({ value, onChange, allowed }: { value: string[]; onChange: (v: string[]) => void; allowed: string[] }) {
  const off = allowed.filter((k) => !value.includes(k));
  const move = (i: number, d: number) => {
    const v = [...value];
    const j = i + d;
    if (j < 0 || j >= v.length) return;
    [v[i], v[j]] = [v[j], v[i]];
    onChange(v);
  };
  const cols = { gridTemplateColumns: '40px 1.2fr 1.4fr 90px' };
  return (
    <div className="gtbl">
      <div className="gr th" style={cols}>
        <span />
        <span>키 알고리즘</span>
        <span>메모</span>
        <span />
      </div>
      {value.map((k, i) => (
        <div key={k} className="gr" style={cols}>
          <span>{i + 1}</span>
          <span>{KEY_TYPE_LABEL[k] ?? k}</span>
          <span className="muted small">{isRsa(k) ? <Badge tone="wa">권장하지 않음</Badge> : KEY_NOTE[k] ?? ''}</span>
          <span className="row" style={{ gap: 4 }}>
            <button className="btn sm" aria-label={`${KEY_TYPE_LABEL[k]} 위로`} disabled={i === 0} onClick={() => move(i, -1)}>
              ↑
            </button>
            <button className="btn sm" aria-label={`${KEY_TYPE_LABEL[k]} 아래로`} disabled={i === value.length - 1} onClick={() => move(i, 1)}>
              ↓
            </button>
            <button className="btn sm" aria-label={`${KEY_TYPE_LABEL[k]} 빼기`} disabled={value.length === 1} onClick={() => onChange(value.filter((x) => x !== k))}>
              ×
            </button>
          </span>
        </div>
      ))}
      {off.filter((k) => !isRsa(k)).map((k) => (
        <div key={k} className="gr" style={cols}>
          <span />
          <span>
            <button className="btn sm" onClick={() => onChange([...value, k])}>
              ＋ {KEY_TYPE_LABEL[k] ?? k}
            </button>
          </span>
          <span className="muted small">넣지 않음{KEY_NOTE[k] && k !== 'ec256' ? ` · ${KEY_NOTE[k]}` : ''}</span>
          <span />
        </div>
      ))}
      {off.some(isRsa) && (
        <div className="gr" style={cols}>
          <span />
          <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
            {off.filter(isRsa).map((k) => (
              <button key={k} className="btn sm" onClick={() => onChange([...value, k])}>
                ＋ {KEY_TYPE_LABEL[k] ?? k}
              </button>
            ))}
          </span>
          <span>
            <Badge tone="wa">권장하지 않음</Badge>
          </span>
          <span />
        </div>
      )}
    </div>
  );
}
/** 선호 순서 표 + RSA를 넣으면 그 아래 경고 */
function KeyOrderWarn(props: { value: string[]; onChange: (v: string[]) => void; allowed: string[] }) {
  return (
    <>
      <KeyOrder {...props} />
      {props.value.some(isRsa) && <RsaWarn />}
    </>
  );
}

function AutoSettingsDialog({ a, accounts, cas, regs, onClose, onDone }: { a: AcmeAuto; accounts: AcmeAccount[]; cas: AcmeCA[]; regs: DnsDomain[]; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [enabled, setEnabled] = useState(a.enabled);
  const [account, setAccount] = useState(a.account ?? accounts[0]?.id ?? '');
  const [keys, setKeys] = useState(a.keyTypes);
  const [dual, setDual] = useState(a.dualRsa);
  const [notify, setNotify] = useState(a.notifyAfterMinutes);
  const [domains, setDomains] = useState<AcmeAutoDomain[]>(a.domains);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const ca = cas.find((c) => c.id === accounts.find((x) => x.id === account)?.ca);
  const allowed = (ca?.keyTypes ?? DEFAULT_KEY_TYPES).filter((k) => KEY_TYPE_LABEL[k]);
  const setD = (i: number, patch: Partial<AcmeAutoDomain>) => setDomains(domains.map((d, j) => (j === i ? { ...d, ...patch } : d)));
  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await putAcmeAuto({ enabled, account: account || undefined, keyTypes: keys, dualRsa: dual, notifyAfterMinutes: notify, domains, revision: a.revision });
      toast('자동 발급 설정을 저장했습니다.');
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  const cols = { gridTemplateColumns: '1.2fr 0.7fr 1.2fr 1.4fr' };
  return (
    <Dialog
      title="자동 발급"
      width={720}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={busy || !keys.length || (enabled && !account)} title={enabled && !account ? '자동 발급을 켜려면 인증 기관 계정이 있어야 합니다' : undefined} onClick={() => void save()}>
            저장
          </button>
        </>
      }
    >
      <label className="check">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        <span>
          자동 발급 켜기 (새 도메인의 기본값)
          <br />
          <span className="small muted">외부 접속 :443 호스트 규칙에 맞는 인증서가 없으면 바로 받습니다.</span>
        </span>
      </label>
      <div className="gtbl">
        <div className="gr th" style={cols}>
          <span>외부 도메인</span>
          <span>자동 발급</span>
          <span>방식</span>
          <span>알고리즘</span>
        </div>
        {domains.map((d, i) => (
          <div key={d.domain} className="gr" style={cols}>
            <span className="mono">{d.domain}</span>
            <label className="check">
              <input type="checkbox" checked={d.enabled} onChange={(e) => setD(i, { enabled: e.target.checked })} /> {d.enabled ? '켬' : '끔'}
            </label>
            <span>
              {d.enabled ? (
                <select value={d.mode} onChange={(e) => setD(i, { mode: e.target.value as AcmeAutoDomain['mode'] })} aria-label={`${d.domain} 방식`}>
                  <option value="per-host">호스트마다 따로</option>
                  <option value="wildcard" disabled={httpOnly(d.domain, regs)} title={httpOnly(d.domain, regs) ? '와일드카드 인증서는 DNS 확인으로만 받습니다. DNS 공급자가 있어야 합니다.' : undefined}>
                    와일드카드로 묶기{httpOnly(d.domain, regs) ? ' (DNS 공급자가 있어야 합니다)' : ''}
                  </option>
                </select>
              ) : (
                '—'
              )}
            </span>
            <span>
              {d.enabled ? (
                <DomainKeysPop d={d} base={keys} allowed={allowed} onChange={(k) => setD(i, { keyTypes: k })} />
              ) : (
                '—'
              )}
            </span>
          </div>
        ))}
      </div>
      <Field label="인증 기관">
        <select value={account} onChange={(e) => setAccount(e.target.value)}>
          {accounts.map((x) => {
            const c = cas.find((y) => y.id === x.ca);
            return (
              <option key={x.id} value={x.id}>
                {c ? (c.staging ? c.name : `${c.name} (실제)`) : x.ca}
              </option>
            );
          })}
        </select>
      </Field>
      <b className="small">선호 알고리즘 (위에서부터 시도)</b>
      <KeyOrderWarn value={keys} onChange={setKeys} allowed={allowed} />
      <span className="small muted">인증 기관이 1순위를 받지 않으면 다음 순위로 받습니다. 인증 기관이 지원하지 않는 알고리즘(Ed25519 등)은 목록에 나오지 않습니다.</span>
      <label className="check">
        <input type="checkbox" checked={dual} onChange={(e) => setDual(e.target.checked)} />
        <span>
          RSA 인증서도 함께 받기 (두 벌) <Badge tone="wa">권장하지 않음</Badge>
          <br />
          <span className="small muted">기본은 꺼짐. ECDSA를 못 쓰는 오래된 클라이언트에는 외부 접속이 RSA 인증서를 내보냅니다. 요청 수를 두 배로 씁니다.</span>
        </span>
      </label>
      {dual && <RsaWarn />}
      <Field label="못 받으면 알림">
        <select value={notify} onChange={(e) => setNotify(Number(e.target.value))}>
          {[10, 30, 60].map((m) => (
            <option key={m} value={m}>
              {m < 60 ? `${m}분 뒤` : '1시간 뒤'}
            </option>
          ))}
        </select>
      </Field>
      <div className="note info small">와일드카드로 묶으면 *.example.com 하나로 여러 호스트를 덮어 요청 수를 아낍니다. 받은 인증서는 호스트 이름(점은 ‘-’, 와일드카드는 wild-도메인) 이름으로 보관함에 올라가고 외부 접속이 알아서 골라 씁니다.</div>
      {error !== undefined && <ErrorBand error={error} what="저장하지 못했습니다" />}
    </Dialog>
  );
}

function DomainKeysPop({ d, base, allowed, onChange }: { d: AcmeAutoDomain; base: string[]; allowed: string[]; onChange: (k: string[] | undefined) => void }) {
  return (
    <Popover button={d.keyTypes ? keyChain(d.keyTypes) : '기본 목록'} className="linkish" width={420}>
      {(close) => <DomainKeysBody d={d} base={base} allowed={allowed} onSave={(k) => (onChange(k), close())} />}
    </Popover>
  );
}
function DomainKeysBody({ d, base, allowed, onSave }: { d: AcmeAutoDomain; base: string[]; allowed: string[]; onSave: (k: string[] | undefined) => void }) {
  const [own, setOwn] = useState(!!d.keyTypes);
  const [k, setK] = useState(d.keyTypes ?? base);
  return (
    <div style={{ display: 'grid', gap: 10 }}>
      <b>{d.domain}</b>
      <Field label="이 도메인 알고리즘">
        <select value={own ? 'own' : 'base'} onChange={(e) => setOwn(e.target.value === 'own')}>
          <option value="base">기본 목록</option>
          <option value="own">따로 정하기</option>
        </select>
      </Field>
      {own && <KeyOrderWarn value={k} onChange={setK} allowed={allowed} />}
      <span className="small muted">기본 목록 대신 이 순서를 씁니다. 이미 받은 인증서는 다음 갱신 때 바뀝니다.</span>
      <div className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
        <button className="btn sm" onClick={() => onSave(undefined)}>
          기본 목록으로
        </button>
        <button className="btn sm primary" onClick={() => onSave(own ? k : undefined)}>
          저장
        </button>
      </div>
    </div>
  );
}

/** 이 이름들을 쓰는 외부 접속 호스트 규칙. 외부 접속은 보관함에서 호스트와 맞는 인증서를 스스로 고른다. */
function WillUse({ names }: { names: string[] }) {
  const q = usePoll((s) => ingress({}, s), [], 0, ingressLive());
  if (q.error !== undefined) return <span className="muted">{ingressMissing(q.error) ? '서버 기능 대기' : '읽지 못함'} · 보관함에 올린 뒤 외부 접속이 이름으로 고릅니다</span>;
  if (!q.data) return <span className="muted">읽는 중…</span>;
  const hit = (h: string) => names.some((n) => (n.startsWith('*.') ? h.endsWith(n.slice(1)) && h.split('.').length === n.split('.').length : h === n));
  const uses = new Map<string, string>();
  for (const i of q.data.instances) for (const r of i.routes) if (r.port === 443 && hit(r.host)) uses.set(`${r.host}`, `${r.host} (${i.app})`);
  if (!uses.size) return <span className="muted">지금 이 이름을 쓰는 :443 규칙이 없습니다 · 규칙이 생기면 외부 접속이 이름으로 고릅니다</span>;
  return <span>{[...uses.values()].join(', ')} · 보관함에 올리면 재시작 없이 바꿔 씁니다</span>;
}
