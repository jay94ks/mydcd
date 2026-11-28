// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { acmeCert, acmeCerts, acmeChainUrl, deleteAcmeCert, acmeErrorText, daysLeft, quickIssueAcmeCert, KEY_TYPE_LABEL, keyLabel, isRsa, putAcmeCert, revokeAcmeCert, type AcmeCert, type AcmeOrder, METHOD_REASON, type MethodReason } from '../api/acme';
import { Badge, Card, Field, Hash, KV, PageHeader } from '../components/ui';
import { Empty, ErrorBand, Load } from '../components/states';
import { ConfirmDialog, Dialog } from '../components/Dialog';
import { Drawer } from '../components/Drawer';
import { useToast } from '../components/Toast';
import { usePoll } from '../lib/usePoll';
import { usePhone } from '../lib/viewport';
import { MCertDetail } from './MCerts';
import { fmtDate, fmtTime } from '../lib/format';
import { errText, nextText, OrderSteps, rowState, SimpleConfirm, useCaOf } from './Certs';
import { ALG_LABEL, CERT_STATE, certChainUrl, certificate, certificates, checkCertChain, deletable, deleteCertificate, disableCertificate, issuerName, nextLink, putCertificate, sharesName, short, type CertCheck, type StoreCert } from '../api/certs';
import { ApiError, noEndpoint } from '../api/client';
import { certLive, certStoreLive } from '../lib/liveTopics';

export function CertDetailPage() {
  return usePhone() ? <MCertDetail /> : <DesktopCertDetailPage />;
}

/** 경로 값이 인증서 ID(앞 12자 이상)이면 보관함 인증서, 아니면 아직 보관함에 없는 발급 정의 이름 */
export const isCertId = (x: string) => /^[0-9a-f]{12,64}$/.test(x);

function DesktopCertDetailPage() {
  const { name = '' } = useParams();
  return isCertId(name) ? <StoreCertDetail id={name} /> : <DefinitionDetail name={name} />;
}

function Crumbs({ last }: { last: string }) {
  return (
    <>
      <Link to="/system/domains">외부 도메인</Link> / <Link to="/system/domains/certs">인증서</Link> / <span className="mono">{last}</span>
    </>
  );
}

/** 발급·갱신 기록 표 (발급 정의가 있을 때) */
function OrdersCard({ orders }: { orders: AcmeOrder[] | null | undefined }) {
  const [log, setLog] = useState<AcmeOrder>();
  return (
    <Card title="발급·갱신 기록" actions={<span className="small muted">사용자가 지울 때까지 보관</span>}>
      {!orders?.length ? (
        <Empty title="아직 발급한 적이 없습니다" />
      ) : (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>언제</th>
                <th>누가</th>
                <th>결과</th>
                <th>요약</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {orders.map((o) => (
                <tr key={o.id}>
                  <td className="muted">{fmtTime(o.at)}</td>
                  <td>{o.auto ? '자동 갱신' : o.by}</td>
                  <td>
                    <Badge tone={o.state === 'done' ? 'ok' : o.state === 'failed' ? 'er' : 'pr'}>{o.state === 'done' ? '성공' : o.state === 'failed' ? '실패' : '진행 중'}</Badge>
                    {o.state === 'done' && o.fingerprint && (
                      <>
                        {' '}
                        <Link className="mono small" to={`/system/domains/certs/${o.fingerprint}`}>
                          {short(o.fingerprint)}
                        </Link>
                      </>
                    )}
                  </td>
                  <td className="el small">{o.state === 'failed' ? (o.steps.find((s) => s.state === 'failed')?.detail ?? acmeErrorText(o.errorCode)) : o.state === 'done' ? `${keyLabel(o.keyType)} · 보관함에 올림` : `${o.steps.filter((s) => s.state === 'done').length}/8 단계`}</td>
                  <td>
                    <button className="btn sm" onClick={() => setLog(o)}>
                      단계 로그
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {log && (
        <Drawer title={`${log.auto ? '자동 갱신' : '발급'} · ${fmtTime(log.at)}`} onClose={() => setLog(undefined)}>
          <OrderSteps order={orders?.find((o) => o.id === log.id) ?? log} />
          <span className="small muted">비공개 키·토큰 값은 로그에 남기지 않습니다.</span>
        </Drawer>
      )}
    </Card>
  );
}

/** 인증서 상세 제목: 포함한 이름 첫 번째, 이름이 없으면 발급 정의 이름 */
export function certTitle(c: { names: string[] } | undefined, defName?: string): string | undefined {
  return c?.names[0] || defName || undefined;
}

/** UI-59: 보관함 인증서 하나 (ID 기준) */
function StoreCertDetail({ id }: { id: string }) {
  const toast = useToast();
  const nav = useNavigate();
  const sq = usePoll((s) => certificate(id, s), [id], 0, certLive(id));
  const lq = usePoll((s) => certificates({}, s), [], 0, certStoreLive);
  const dq = usePoll((s) => acmeCerts(s), [], 5000);
  const c = sq.data;
  const def = c ? dq.data?.items.find((d) => (c.definition ? d.name === c.definition : d.fingerprint === c.id)) : undefined;
  const oq = usePoll((s) => (def ? acmeCert(def.name, s) : Promise.resolve(undefined)), [def?.name], 5000);
  const { caOf } = useCaOf();
  const [dlg, setDlg] = useState<'disable' | 'revoke' | 'delete' | 'defDelete' | 'keys'>();
  const all = lq.data ?? [];
  const others = c ? all.filter((x) => x.id !== c.id && sharesName(x, c)) : [];
  const [otherDel, setOtherDel] = useState<StoreCert>();
  const renew = async () => {
    if (!def) return;
    try {
      await quickIssueAcmeCert(def.name);
      toast(`${def.name} 발급을 시작했습니다. 창을 닫아도 계속됩니다`);
      dq.refresh();
    } catch (e) {
      toast(`! ${errText(e)}`, 'er');
    }
  };
  const left = daysLeft(c?.notAfter);
  const st = c ? rowState({ key: c.id, cert: c, def }) : undefined;
  const missing = sq.error !== undefined && noEndpoint(sq.error);
  return (
    <>
      <PageHeader
        crumbs={<Crumbs last={certTitle(c, def?.name) ?? short(id)} />}
        title={
          certTitle(c, def?.name) ? (
            <>
              {certTitle(c, def?.name)}
              {c && c.names.length > 1 && <span className="muted small" style={{ fontWeight: 400, marginLeft: 8 }}>외 {c.names.length - 1}개 이름</span>}
            </>
          ) : (
            <span className="mono" style={{ fontSize: 'inherit' }}>{short(id)}</span>
          )
        }
        sub={certTitle(c, def?.name) ? <span className="mono muted" style={{ fontSize: 11 }}>지문 {short(id)}</span> : undefined}
        ids="UI-59"
        actions={
          c && (
            <>
              {st && (
                <Badge tone={st.tone}>
                  {st.text}
                  {c.links.length ? ` · 링크 ${c.links.length}` : ''}
                </Badge>
              )}
              {left !== undefined && <Badge tone={left <= 14 ? 'wa' : 'un'}>{left}일 남음</Badge>}
              {def && <Badge tone="un">정의 {def.name}</Badge>}
              <a className="btn" href={certChainUrl(c.id)} download={`${short(c.id)}-chain.pem`}>
                공개 체인 내려받기
              </a>
              {def && (
                <button className="btn" disabled={def.running} onClick={() => void renew()}>
                  {def.running ? '발급 중…' : '지금 갱신'}
                </button>
              )}
              <button className="btn danger" disabled={c.state !== 'linked'} title={c.state !== 'linked' ? '연결된 인증서만 끊을 수 있습니다' : undefined} onClick={() => setDlg('disable')}>
                끊기…
              </button>
              {def && (
                <button className="btn danger" onClick={() => setDlg('revoke')}>
                  해지…
                </button>
              )}
            </>
          )
        }
      />
      {missing ? (
        <Empty kind="scope" title="서버 기능 대기">
          인증서 ID로 보는 상세는 sfcd 인증서 보관함(certificate-store.md)이 들어오면 켭니다.
        </Empty>
      ) : (
        <Load q={sq} what="인증서를 읽지 못했습니다">
          {(cc) => (
            <>
              {cc.disabled && <div className="note wa">이 인증서는 끊었습니다. 같은 ID로 다시 올려도 링크를 얻지 못합니다. 다시 쓰려면 지우고 올리세요.</div>}
              {!def && cc.state === 'linked' && left !== undefined && left <= 30 && (
                <div className="note wa">직접 올린 인증서라 자동 갱신할 수 없습니다. {left}일 남았습니다. 새 인증서를 올리거나 자동 발급으로 바꾸세요. 만료되면 서버가 지웁니다.</div>
              )}
              <Card title="인증서">
                <KV
                  items={[
                    ['인증서 ID', <span key="id" className="row" style={{ gap: 8 }}><span className="mono">{short(cc.id)}</span><Hash value={cc.id} /><span className="muted small">(leaf SHA-256)</span></span>],
                    ['포함한 이름', <span key="n" className="mono">{cc.names.join(', ')}</span>],
                    [
                      '알고리즘',
                      <span key="k">
                        {keyLabel(cc.keyType)}
                        {def ? ' · 발급마다 새 키' : ''}
                        {isRsa(cc.keyType) && (
                          <>
                            {' '}
                            <Badge tone="wa">권장하지 않음</Badge>
                          </>
                        )}
                      </span>,
                    ],
                    ['발급자', `${cc.issuer} · 일련번호 ${cc.serial}`],
                    ['유효 기간', `${fmtDate(cc.notBefore)} ~ ${fmtDate(cc.notAfter)}`],
                    ['올린 곳', `${def && cc.uploadedBy && cc.uploadedBy !== def.createdBy ? `자동 갱신 (${cc.uploadedBy})` : (cc.uploadedBy ?? '—')} · ${fmtTime(cc.uploadedAt)}`],
                    ...(def ? ([['다음 갱신', `${nextText(def)} · ${caOf(def.account)?.name ?? def.account}`]] as [string, ReactNode][]) : []),
                    ...(cc.chain?.length ? ([['체인', <span key="ch" className="mono small">{cc.chain.join(' → ')}</span>]] as [string, ReactNode][]) : []),
                    ['비공개 키', '클러스터 키로 암호화해 보관 · 링크된 호스트를 서빙하는 외부 접속 서버만 풉니다'],
                  ]}
                />
              </Card>
              <Card title={`링크 (${cc.links.length})`}>
                {cc.links.length === 0 ? (
                  <Empty title="링크가 없습니다">{cc.disabled ? '끊은 인증서는 링크를 얻지 못합니다.' : cc.state === 'pending-destroy' ? '이 인증서의 링크를 모두 다른 인증서가 가져갔습니다.' : '등록된 도메인 아래 이름이 없습니다. 외부 도메인 탭에서 도메인을 등록하면 링크됩니다.'}</Empty>
                ) : (
                  <div className="table-wrap">
                    <table className="tbl">
                      <thead>
                        <tr>
                          <th>호스트</th>
                          <th>알고리즘</th>
                          <th>서빙하는 외부 접속 서버</th>
                          <th>상태</th>
                        </tr>
                      </thead>
                      <tbody>
                        {cc.links.map((l) => (
                          <tr key={`${l.host}|${l.alg}`}>
                            <td className="mono">{l.host}</td>
                            <td>{ALG_LABEL[l.alg] ?? l.alg}</td>
                            <td>{l.servedBy?.length ? l.servedBy.join(', ') : <span className="muted">—</span>}</td>
                            <td>{l.servedBy?.length ? <Badge tone="ok">사용 중</Badge> : <Badge tone="un">서빙하는 서버 없음</Badge>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <span className="small muted">
                  링크는 호스트와 알고리즘마다 하나입니다. 같은 호스트·알고리즘의 새 인증서가 들어오고 더 늦게 만료되면 링크가 새 인증서로 옮겨 갑니다.
                  {(() => {
                    const rsa = others.filter((o) => o.state === 'linked' && o.links.some((l) => l.alg === 'rsa' && cc.names.includes(l.host)));
                    return rsa.length && !isRsa(cc.keyType) ? ` ${rsa.flatMap((o) => o.links.filter((l) => l.alg === 'rsa').map((l) => l.host)).join(', ')}에는 RSA 링크(${rsa.map((o) => short(o.id)).join(', ')})도 있어, ECDSA를 못 쓰는 클라이언트에만 그것을 씁니다.` : '';
                  })()}
                </span>
              </Card>
              <Card title="같은 이름의 다른 인증서" actions={<span className="small muted">포함한 이름이 겹치는 인증서</span>}>
                {others.length === 0 ? (
                  <span className="small muted">{lq.data ? '없습니다.' : '읽는 중…'}</span>
                ) : (
                  <div className="table-wrap">
                    <table className="tbl">
                      <thead>
                        <tr>
                          <th>인증서 ID</th>
                          <th>알고리즘</th>
                          <th>링크</th>
                          <th>남은 날</th>
                          <th>상태</th>
                        </tr>
                      </thead>
                      <tbody>
                        {others.map((o) => {
                          const [t, tone] = CERT_STATE[o.state];
                          return (
                            <tr key={o.id}>
                              <td>
                                <Link className="mono" to={`/system/domains/certs/${o.id}`}>
                                  {short(o.id)}
                                </Link>
                              </td>
                              <td>
                                {keyLabel(o.keyType)}
                                {isRsa(o.keyType) && (
                                  <>
                                    {' '}
                                    <Badge tone="wa">권장하지 않음</Badge>
                                  </>
                                )}
                              </td>
                              <td className="small">{o.links.length ? o.links.map((l) => `${l.host}${l.alg === 'rsa' ? ' (RSA)' : ''}`).join(', ') : o.disabled ? '0 · 끊음' : o.state === 'pending-destroy' ? '0 · 다른 인증서가 가져감' : '0'}</td>
                              <td>{daysLeft(o.notAfter)}일</td>
                              <td>
                                <span className="row" style={{ gap: 6 }}>
                                  <Badge tone={tone}>{t}</Badge>
                                  {deletable(o) && (
                                    <button type="button" className="linkish small" onClick={() => setOtherDel(o)}>
                                      지우기
                                    </button>
                                  )}
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
                {others.some((o) => o.state === 'pending-destroy') && (
                  <span className="small muted">파기 대기 인증서는 링크가 없어 어디에도 쓰이지 않습니다. 새 인증서에 문제가 있으면 새 인증서를 ‘끊기’로 떼세요. 그 호스트들은 남은 인증서 가운데 가장 나은 것(파기 대기 인증서 포함)에 다시 링크됩니다. 만료되면 서버가 지웁니다.</span>
                )}
              </Card>
              {def && <OrdersCard orders={oq.data?.orders} />}
              <Card title="지우기" className="danger-card">
                <div className="row small muted" style={{ gap: 16, flexWrap: 'wrap', alignItems: 'flex-start', lineHeight: '18px' }}>
                  {def && (
                    <div style={{ flex: '1 1 300px', display: 'flex', flexDirection: 'column', gap: 6 }}>
                      <button className="btn danger" style={{ width: 'fit-content' }} onClick={() => setDlg('defDelete')}>
                        정의 지우기…
                      </button>
                      <span>웹의 자동 발급·갱신 정의({def.name})만 지웁니다. 보관함의 인증서와 링크는 그대로입니다.</span>
                    </div>
                  )}
                  <div style={{ flex: '1 1 300px', display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <button className="btn danger" style={{ width: 'fit-content' }} disabled={!deletable(cc)} onClick={() => setDlg('delete')}>
                      지우기
                    </button>
                    <span>{deletable(cc) ? '체인과 암호화한 비공개 키를 지웁니다. 되돌릴 수 없습니다.' : <>연결됨 인증서는 지울 수 없습니다. 링크를 다른 인증서가 모두 가져가거나 ‘끊기’로 떼어 <b>파기 대기</b>가 되거나, 도메인을 빼서 <b>미연결</b>이 되면 지울 수 있습니다.</>}</span>
                  </div>
                </div>
              </Card>
              {dlg === 'disable' && <DisableCertDialog c={cc} all={all} def={def} onClose={() => setDlg(undefined)} onDone={() => (sq.refresh(), lq.refresh(), dq.refresh())} />}
              {dlg === 'revoke' && def && <RevokeDialog c={cc} def={def} onClose={() => setDlg(undefined)} onDone={() => dq.refresh()} />}
              {dlg === 'delete' && <DeleteCertDialog c={cc} all={all} onClose={() => setDlg(undefined)} onDone={() => nav('/system/domains/certs')} />}
              {otherDel && <DeleteCertDialog c={otherDel} all={all} onClose={() => setOtherDel(undefined)} onDone={() => lq.refresh()} />}
              {dlg === 'defDelete' && def && (
                <SimpleConfirm title={`${def.name} 정의를 지울까요?`} target={def.name} action="지우기" run={() => deleteAcmeCert(def.name)} onClose={() => setDlg(undefined)} onDone={() => dq.refresh()}>
                  웹의 자동 발급·갱신 정의만 지웁니다. 보관함의 인증서와 링크는 그대로이고, 자동 갱신은 멈춥니다.
                </SimpleConfirm>
              )}
            </>
          )}
        </Load>
      )}
    </>
  );
}

/** 아직 보관함 인증서가 없는 발급 정의 (발급 중·실패·지금 데몬) */
function DefinitionDetail({ name }: { name: string }) {
  const q = usePoll((s) => acmeCert(name, s), [name], 3000);
  const { caOf } = useCaOf();
  const toast = useToast();
  const nav = useNavigate();
  const [dlg, setDlg] = useState<'keys' | 'delete' | 'revoke'>();
  const c = q.data?.certificate;
  const renew = async () => {
    try {
      await quickIssueAcmeCert(name);
      toast(`${name} 발급을 시작했습니다`);
      q.refresh();
    } catch (e) {
      toast(`! ${errText(e)}`, 'er');
    }
  };
  const st = c ? rowState({ key: name, def: c }) : undefined;
  return (
    <>
      <PageHeader
        crumbs={<Crumbs last={name} />}
        title={name}
        ids="UI-59"
        actions={
          c && (
            <>
              {st && <Badge tone={st.tone}>{st.text}</Badge>}
              <Badge tone="un">정의 {name}</Badge>
              {c.fingerprint && (
                <Link className="btn" to={`/system/domains/certs/${c.fingerprint}`}>
                  보관함 인증서 {short(c.fingerprint)}
                </Link>
              )}
              <a className={`btn ${c.fingerprint ? '' : 'disabled'}`} aria-disabled={!c.fingerprint} href={c.fingerprint ? acmeChainUrl(name) : undefined} download={`${name}-chain.pem`}>
                공개 체인 내려받기
              </a>
              <button className="btn" disabled={c.running} onClick={() => void renew()}>
                {c.running ? '발급 중…' : '지금 갱신'}
              </button>
            </>
          )
        }
      />
      <Load q={q}>
        {({ certificate: cc, orders, methods, methodReasons }) => (
          <>
            {cc.renewBlocked && <div className="note wa">갱신할 때가 됐지만 웹 자동 작업 계정이 없어 사람 없는 갱신을 시작하지 않습니다. '지금 갱신'으로 직접 받으세요.</div>}
            <Card title="발급 정의 (웹)" actions={<button className="btn sm" onClick={() => setDlg('keys')}>발급 설정</button>}>
              <KV
                items={[
                  ['포함한 이름', <span key="n" className="mono">{cc.names.join(', ')}</span>],
                  ['인증 기관', caOf(cc.account)?.name ?? cc.account],
                  ['확인 방식', <MethodsText key="m" names={cc.names} methods={methods ?? cc.methods} reasons={methodReasons} />],
                  ['키 알고리즘', `선호 ${cc.keyTypes.map((k) => KEY_TYPE_LABEL[k] ?? k).join(' → ')}`],
                  ['다음 갱신', nextText(cc)],
                  ['보관함 인증서', cc.fingerprint ? <Link key="f" className="mono" to={`/system/domains/certs/${cc.fingerprint}`}>{short(cc.fingerprint)}</Link> : '아직 없음'],
                  ['만든 사람', cc.createdBy ? `${cc.createdBy} · 갱신 알림을 받음` : '—'],
                ]}
              />
            </Card>
            <OrdersCard orders={orders} />
            <Card title="지우기" className="danger-card">
              <div className="small muted" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <button className="btn danger" style={{ width: 'fit-content' }} onClick={() => setDlg('delete')}>
                  정의 지우기…
                </button>
                <span>웹의 자동 발급·갱신 정의만 지웁니다. 보관함의 인증서와 링크는 그대로입니다.</span>
              </div>
            </Card>
            {dlg === 'keys' && <KeysDialog c={cc} onClose={() => setDlg(undefined)} onDone={() => q.refresh()} />}
            {dlg === 'delete' && (
              <SimpleConfirm title={`${cc.name} 정의를 지울까요?`} target={cc.name} action="지우기" run={() => deleteAcmeCert(cc.name)} onClose={() => setDlg(undefined)} onDone={() => nav('/system/domains/certs')}>
                웹의 자동 발급·갱신 정의만 지웁니다. 보관함의 인증서와 링크는 그대로입니다.
              </SimpleConfirm>
            )}
          </>
        )}
      </Load>
    </>
  );
}

/** 끊기: 키가 샌 연결 인증서의 링크를 한 번에 떼고 파기 대기로 보낸다. 인증 기관 해지와는 따로다. */
export function DisableCertDialog({ c, all, def, onClose, onDone }: { c: StoreCert; all: StoreCert[]; def?: AcmeCert; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [reissue, setReissue] = useState(!!def?.autoRenew);
  const hosts = c.links.map((l) => l.host);
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await disableCertificate(c.id);
      if (reissue && def) await quickIssueAcmeCert(def.name).catch((e) => toast(`! 다시 발급을 시작하지 못했습니다: ${errText(e)}`, 'er'));
      toast(`${short(c.id)}을(를) 끊었습니다 · 링크 ${r.unlinkedHosts}개를 뗐습니다${reissue && def ? ` · ${def.name} 새 키로 다시 발급` : ''}`);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <ConfirmDialog title={`${short(c.id)}을(를) 끊을까요?`} target={short(c.id)} actionLabel="끊기" busy={busy} onClose={onClose} onConfirm={() => void go()}>
      {error !== undefined && <ErrorBand error={error} what="끊지 못했습니다" />}
      <p>
        링크 {c.links.length}개({hosts.join(', ')} · {[...new Set(c.links.map((l) => ALG_LABEL[l.alg] ?? l.alg))].join('·')})를 한 번에 떼고 <b>파기 대기</b>로 보냅니다. 떨어진 호스트는 남은 인증서 가운데 가장 나은 것에 다시 링크되고, 없으면 HTTPS 접속이 거절됩니다. 외부 접속 서버는 다음 반영 때 이 키를 메모리에서 지웁니다.
      </p>
      {c.links.length > 0 && (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>호스트</th>
                <th>끊은 뒤</th>
              </tr>
            </thead>
            <tbody>
              {c.links.map((l) => {
                const n = nextLink(all, c, l.host, l.alg);
                return (
                  <tr key={`${l.host}|${l.alg}`}>
                    <td className="mono">{l.host}</td>
                    <td>{n ? <span className="mono">{short(n.id)} ({daysLeft(n.notAfter)}일)</span> : <span className="er-text">인증서 없음 · HTTPS 거절</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <span className="small muted">끊은 인증서는 같은 ID로 다시 올려도 링크를 얻지 못합니다. 다시 쓰려면 지우고 올리세요.{def ? ' 자동 갱신이 켜져 있으면 새 키로 바로 다시 받는 것을 권합니다.' : ''}</span>
      {def && (
        <label className="check">
          <input type="checkbox" checked={reissue} onChange={(e) => setReissue(e.target.checked)} /> 끊은 뒤 바로 새 키로 다시 발급 ({def.name})
        </label>
      )}
    </ConfirmDialog>
  );
}

/** 지우기: 미연결·파기 대기만. 목록이 오래돼 연결됨이 된 인증서면 서버가 409 linked로 거절한다. */
export function DeleteCertDialog({ c, all, onClose, onDone }: { c: StoreCert; all: StoreCert[]; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const taker = c.state === 'pending-destroy' ? all.find((x) => x.id !== c.id && x.state === 'linked' && sharesName(x, c) && x.keyType.slice(0, 3) === c.keyType.slice(0, 3)) : undefined;
  const linked = error instanceof ApiError && error.code === 'linked' ? ((error.body.raw as { links?: { host: string; alg: string }[] } | undefined)?.links ?? []) : undefined;
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await deleteCertificate(c.id);
      toast(`${short(c.id)}을(를) 지웠습니다`);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  const [t] = CERT_STATE[c.state];
  return (
    <ConfirmDialog title={`${short(c.id)}을(를) 지울까요?`} target={short(c.id)} actionLabel="지우기" busy={busy} onClose={onClose} onConfirm={() => void go()}>
      {linked ? (
        <div className="note er small">
          {short(c.id)}을(를) 지우지 못했습니다: 연결된 인증서입니다.{linked.length ? ` 링크된 호스트 ${linked.map((l) => l.host).join(', ')} (${[...new Set(linked.map((l) => ALG_LABEL[l.alg] ?? l.alg))].join('·')}).` : ''} 새 인증서가 링크를 가져가면 파기 대기가 되어 지울 수 있습니다.
        </div>
      ) : (
        error !== undefined && <ErrorBand error={error} what="지우지 못했습니다" />
      )}
      <KV
        items={[
          ['상태', `${t}${c.disabled ? ' · 끊음' : taker ? ` · 링크를 모두 ${short(taker.id)}이(가) 가져감` : c.state === 'unlinked' ? ' · 등록된 도메인 아래 이름이 없음' : ''}`],
          ['포함한 이름', <span key="n" className="mono">{c.names.join(', ')}</span>],
          ['남은 날', `${daysLeft(c.notAfter)}일`],
          ['발급자', issuerName(c.issuer)],
        ]}
      />
      <p>체인과 암호화한 비공개 키를 지웁니다. 되돌릴 수 없습니다.</p>
    </ConfirmDialog>
  );
}

const REVOKE_REASON: [string, string][] = [
  ['keyCompromise', '키가 샌 것 같음 (keyCompromise)'],
  ['superseded', '새 인증서로 바꿈 (superseded)'],
  ['cessationOfOperation', '더 쓰지 않음 (cessationOfOperation)'],
  ['', '이유 없음 (unspecified)'],
];
/** 해지: 인증 기관에 해지를 요청한다(발급 정의가 받은 인증서만). 되돌릴 수 없다. */
export function RevokeDialog({ c, def, onClose, onDone }: { c: StoreCert; def: AcmeCert; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [reason, setReason] = useState('keyCompromise');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const go = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await revokeAcmeCert(def.name, reason || undefined);
      toast(`${short(c.id)} 해지를 요청했습니다`);
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  const hosts = [...new Set(c.links.map((l) => l.host))];
  return (
    <ConfirmDialog title={`${short(c.id)}을(를) 해지할까요?`} target={short(c.id)} actionLabel="해지" busy={busy} onClose={onClose} onConfirm={() => void go()}>
      {error !== undefined && <ErrorBand error={error} what="해지하지 못했습니다" />}
      <p>
        인증 기관에 해지를 요청합니다. 되돌릴 수 없고, {hosts.length ? `링크된 호스트 ${hosts.length}개(${hosts.join(', ')})는 같은 알고리즘의 다른 인증서가 링크되기 전까지 TLS가 거절됩니다.` : '이 인증서는 링크가 없습니다.'} 자동 갱신도 끕니다.
      </p>
      <Field label="이유">
        <select value={reason} onChange={(e) => setReason(e.target.value)}>
          {REVOKE_REASON.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      </Field>
    </ConfirmDialog>
  );
}

/** 직접 받은 인증서를 이름 없이 올린다. 보관함이 SAN을 읽어 링크한다.
 * 비공개 키는 이 대화상자 메모리에만 있다가 한 번 보내고 지운다. */
const METHOD_TEXT = { 'dns-01': 'DNS 확인', 'http-01': 'HTTP 확인' } as const;
/** 이름마다 서버가 정한 확인 방식 (null이면 받을 수 없음 · 이유는 대기 이유) */
function MethodsText({ names, methods, reasons }: { names: string[]; methods?: Record<string, 'dns-01' | 'http-01' | null>; reasons?: Record<string, MethodReason> }) {
  if (!methods) return <span className="muted">이름마다 서버가 정함</span>;
  const kinds = new Set(names.map((n) => methods[n] ?? null));
  const only = kinds.size === 1 ? [...kinds][0] : null;
  if (only) return <>{METHOD_TEXT[only]}</>;
  const no = (n: string) => (reasons?.[n] ? `받을 수 없음(${METHOD_REASON[reasons[n]] ?? reasons[n]})` : '받을 수 없음');
  return <>{names.map((n) => `${n}: ${methods[n] ? METHOD_TEXT[methods[n]!] : no(n)}`).join(' · ')}</>;
}

const INVALID: Record<string, string> = {
  expired: '이미 만료된 인증서입니다',
  'not-yet-valid': '아직 유효 기간이 시작되지 않은 인증서입니다',
  'unsupported-key': '지원하지 않는 키 형식입니다(ECDSA P-256·P-384, RSA 2048 이상)',
  'no-names': '인증서에 이름(SAN·CN)이 없습니다',
};

export function UploadCertDialog({ onClose, onDone }: { onClose: () => void; onDone: (id: string) => void }) {
  const toast = useToast();
  const [chain, setChain] = useState('');
  const [key, setKey] = useState('');
  const [keyFile, setKeyFile] = useState('');
  const [check, setCheck] = useState<CertCheck | { error: unknown }>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const close = () => {
    setKey('');
    onClose();
  };
  const readFile = (f: File | undefined, to: (t: string) => void) => {
    if (!f) return;
    void f.text().then(to);
  };
  const chainBad = chain.trim() !== '' && !chain.includes('-----BEGIN CERTIFICATE-----');
  const keyBad = key !== '' && !/-----BEGIN (EC |RSA )?PRIVATE KEY-----/.test(key);
  useEffect(() => {
    setCheck(undefined);
    if (!chain.trim() || chainBad) return;
    const t = setTimeout(() => {
      checkCertChain(chain.trim()).then(setCheck, (e) => setCheck({ error: e }));
    }, 300);
    return () => clearTimeout(t);
  }, [chain, chainBad]);
  const send = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const r = await putCertificate({ chain: chain.trim(), key });
      setKey('');
      toast(r.created ? `${short(r.id)}을(를) 올렸습니다 · 링크 ${r.links.length}개` : `${short(r.id)}은(는) 이미 보관함에 있습니다`);
      onDone(r.id);
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  const ok = check && !('error' in check) ? check : undefined;
  const invalid = ok?.invalid;
  const code = error instanceof ApiError ? error.code : undefined;
  const REFUSE: Record<string, string> = { mismatch: '체인의 공개 키와 비공개 키가 짝이 아닙니다', 'not-valid-now': '지금 유효한 인증서가 아닙니다(NotBefore·NotAfter)', 'unsupported-key': '지원하지 않는 키 형식입니다(ECDSA P-256·P-384, RSA 2048 이상)', 'no-names': '인증서에 이름(SAN·CN)이 없습니다' };
  return (
    <Dialog
      title="인증서 올리기"
      width={560}
      onClose={close}
      footer={
        <>
          <button className="btn" onClick={close}>
            취소
          </button>
          <button className="btn primary" disabled={busy || !chain.trim() || !key || chainBad || keyBad || !!invalid} onClick={() => void send()}>
            올리기
          </button>
        </>
      }
    >
      <span className="small muted">이름은 넣지 않습니다. 보관함이 인증서 안의 이름(SAN)을 읽어, 등록된 도메인 아래 호스트에 알고리즘마다 링크합니다.</span>
      <Field label="인증서 체인 (PEM)" hint="서버 인증서부터 중간 인증서까지 · 파일을 고르거나 붙여 넣기" error={chainBad ? 'BEGIN CERTIFICATE로 시작하는 PEM이 아닙니다' : undefined}>
        <input type="file" accept=".pem,.crt,.cer" onChange={(e) => readFile(e.target.files?.[0], setChain)} />
        <textarea className="mono" rows={4} value={chain} onChange={(e) => setChain(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
      </Field>
      <Field label="비공개 키 (PEM)" hint="보호 입력으로 한 번만 보내고 웹에 남기지 않습니다 · 보관함에서 봉인" error={keyBad ? 'PRIVATE KEY PEM 파일이 아닙니다' : undefined}>
        <input
          type="file"
          accept=".pem,.key"
          onChange={(e) => {
            const f = e.target.files?.[0];
            setKeyFile(f?.name ?? '');
            readFile(f, setKey);
            e.target.value = '';
          }}
        />
        {keyFile && <span className="small muted">{keyFile} 읽음 · ••••</span>}
      </Field>
      {ok && invalid && <div className="note er small">✗ {INVALID[invalid] ?? invalid}. 보관함이 이 인증서를 받지 않습니다.</div>}
      {ok && !invalid && (
        <div className="note ok small">
          ✓ 체인 확인 · {ok.names.join(', ')} · {keyLabel(ok.keyType)} · {fmtDate(ok.notAfter)}까지 · 발급자 {issuerName(ok.issuer)}
          <br />
          {ok.links.length ? (
            <>
              링크할 호스트: {ok.links.map((l) => `${l.host}${l.replaces ? ` (지금 ${short(l.replaces)} → 더 늦게 만료되면 옮김)` : ' (지금 링크 없음 → 새로 링크)'}`).join(', ')}
            </>
          ) : (
            <>등록된 도메인 아래 이름이 없어 <b>미연결</b>로 남습니다.</>
          )}
        </div>
      )}
      {ok && isRsa(ok.keyType) && <RsaWarn />}
      {check && 'error' in check && !noEndpoint(check.error) && <ErrorBand error={check.error} what="체인을 읽지 못했습니다" />}
      <span className="small muted">자동 갱신 없음 · 만료 30일 전 알림. 키 쌍이 맞는지는 보관함이 올릴 때 확인하고, 맞지 않으면 거절합니다.</span>
      {code && REFUSE[code] ? (
        <div className="note er small">sfcd가 이 체인이나 키를 받지 않았습니다: {REFUSE[code]}. 체인 순서, 키 쌍, 만료를 확인한 뒤 다시 올리세요.</div>
      ) : (
        error !== undefined && <ErrorBand error={error} what="올리지 못했습니다" />
      )}
    </Dialog>
  );
}

function KeysDialog({ c, onClose, onDone }: { c: AcmeCert; onClose: () => void; onDone: () => void }) {
  const [auto, setAuto] = useState(c.autoRenew);
  const [keys, setKeys] = useState(c.keyTypes);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const save = async () => {
    setBusy(true);
    try {
      await putAcmeCert(c.name, { autoRenew: auto, keyTypes: keys });
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`${c.name} 발급 설정`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            취소
          </button>
          <button className="btn primary" disabled={!keys.length || busy} onClick={() => void save()}>
            저장
          </button>
        </>
      }
    >
      {error !== undefined && <ErrorBand error={error} what="저장하지 못했습니다" />}
      <label className="check">
        <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> 자동 갱신 (유효 기간이 1/3 남으면)
      </label>
      <Field label="키 형식 (선호 순)" hint="다음 발급부터 씁니다" group>
        <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
          {Object.entries(KEY_TYPE_LABEL).map(([k, l]) => {
            const i = keys.indexOf(k);
            return (
              <label key={k} className={`choice ${i >= 0 ? 'on' : ''}`}>
                <input type="checkbox" checked={i >= 0} onChange={(e) => setKeys(e.target.checked ? [...keys, k] : keys.filter((x) => x !== k))} /> {i >= 0 ? `${i + 1}. ` : ''}
                {l}
                {k === 'ec256' ? ' (권장)' : isRsa(k) ? ' · 권장하지 않음' : ''}
              </label>
            );
          })}
        </span>
      </Field>
      {keys.some(isRsa) && <RsaWarn />}
    </Dialog>
  );
}

/** RSA를 고르면 그 자리 아래에 뜬다. 막지는 않는다 (캔버스 v173) */
export function RsaWarn() {
  return (
    <div className="note wa small">
      <b>권장하지 않는 알고리즘</b> · RSA는 ECDSA보다 느리고 키가 큽니다. ECDSA를 못 쓰는 오래된 클라이언트가 꼭 있을 때만 고르세요. 기본 목록은 ECDSA P-256 하나입니다.
    </div>
  );
}
