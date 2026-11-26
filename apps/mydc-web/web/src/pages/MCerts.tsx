// SPDX-License-Identifier: Apache-2.0

// 휴대폰 인증서 (UI-M1 '보기만 화면의 상세 · 하위 탭'): 외부 도메인의 인증서 탭과 인증서 상세를 읽기만 한다.
// 보관함은 인증서 ID(leaf SHA-256)로 줄을 세우고, 아직 보관함에 없는 발급 정의는 이름으로 보인다.
import { useNavigate, useParams } from 'react-router-dom';
import { acmeCert, acmeCerts, daysLeft, KEY_TYPE_LABEL, keyLabel } from '../api/acme';
import { ALG_LABEL, certificate, certificates, issuerName, short } from '../api/certs';
import { useAuth } from '../auth/session';
import { Empty, Load } from '../components/states';
import { Tabs } from '../components/Tabs';
import { usePoll } from '../lib/usePoll';
import { fmtTime } from '../lib/format';
import { MCards, MDetail, type MCardSpec, MSec, MTiles, useReadOnlyTop } from '../mobile/ReadOnly';
import { certRows, linkText, nextText, rowHref, rowState, sourceText, useCaOf } from './Certs';
import { DOMAIN_TABS } from './Domains';

const left = (iso?: string) => {
  const d = daysLeft(iso);
  return d === undefined ? '—' : d < 0 ? '만료됨' : `${d}일 남음`;
};
const isId = (x: string) => /^[0-9a-f]{12,64}$/.test(x);
const cardTone = (t: string) => (t === 'er' ? 'er' : t === 'wa' ? 'wa' : undefined);

export function MCerts() {
  const { session } = useAuth();
  const admin = !!session?.user.systemAdmin;
  const nav = useNavigate();
  const q = usePoll((s) => (admin ? acmeCerts(s) : Promise.resolve(undefined)), [admin], 5000);
  const vq = usePoll((s) => (admin ? certificates({}, s) : Promise.resolve(undefined)), [admin], 5000);
  const { caOf } = useCaOf();
  useReadOnlyTop('외부 도메인', '인증서 · 시스템 관리자', '발급·올리기·끊기·지우기는 넓은 화면에서', [admin]);
  const store = (vq.data ?? []).filter((c) => typeof c.id === 'string');
  const rows = certRows(store, q.data?.items ?? []);
  const linked = store.filter((c) => c.state === 'linked').length;
  const soon = store.filter((c) => c.state === 'linked' && (daysLeft(c.notAfter) ?? 999) <= 30).length;
  const failed = rows.filter((r) => (r.def?.failures ?? 0) > 0).length;
  return (
    <>
      <Tabs label="외부 도메인 탭" items={DOMAIN_TABS(undefined, admin ? rows.length : undefined)} />
      {!admin ? (
        <Empty kind="scope" title="시스템 관리자만 인증서를 다룹니다" />
      ) : (
        <Load q={q} what="인증서를 불러오지 못했습니다">
          {() => (
            <>
              <MTiles
                items={[
                  { label: '인증서', value: rows.length, sub: `보관함 ${store.length} · 연결됨 ${linked}` },
                  { label: '30일 안 만료', value: soon, sub: failed ? `갱신 실패 ${failed}` : '갱신 실패 없음', warn: soon > 0 || failed > 0 },
                ]}
              />
              <MCards
                empty="인증서가 없습니다."
                items={rows.map((r): MCardSpec => {
                  const st = rowState(r);
                  const c = r.cert;
                  return {
                    key: r.key,
                    title: c ? <span className="mono">{short(c.id)}</span> : r.def!.name,
                    badge: [st.tone, st.text],
                    tone: cardTone(st.tone),
                    lines: [<span key="n" className="mono">{(c?.names ?? r.def!.names).join(', ')}</span>, `${left(c?.notAfter ?? r.def?.notAfter)} · ${sourceText(r, r.def ? caOf(r.def.account)?.name : undefined)}`],
                    meta: c ? `링크 ${linkText(c)}` : r.def ? nextText(r.def) : undefined,
                    onOpen: () => nav(rowHref(r)),
                  };
                })}
              />
            </>
          )}
        </Load>
      )}
    </>
  );
}

export function MCertDetail() {
  const { name = '' } = useParams();
  return isId(name) ? <MStoreCertDetail id={name} /> : <MDefinitionDetail name={name} />;
}

function MStoreCertDetail({ id }: { id: string }) {
  const q = usePoll((s) => certificate(id, s), [id], 3000);
  const dq = usePoll((s) => acmeCerts(s).catch(() => undefined), [], 5000);
  useReadOnlyTop(short(id), '인증서', '끊기·지우기·해지는 넓은 화면에서', [id]);
  const c = q.data;
  if (!c) return q.error !== undefined ? <Empty kind="scope" title="이 인증서가 없거나 볼 권한이 없습니다" /> : <Load q={q} what="인증서를 불러오지 못했습니다">{() => null}</Load>;
  const def = (dq.data?.items ?? []).find((d) => (c.definition ? d.name === c.definition : d.fingerprint === c.id));
  const st = rowState({ key: c.id, cert: c, def });
  return (
    <>
      <MDetail
        title={short(c.id)}
        badge={[st.tone, st.text]}
        tone={cardTone(st.tone)}
        rows={[
          ['ID', <span key="i" className="mono">{c.id}</span>],
          ['이름', <span key="n" className="mono">{c.names.join(', ')}</span>],
          ['만료', `${fmtTime(c.notAfter)} · ${left(c.notAfter)}`],
          ['발급자', issuerName(c.issuer) || '—'],
          ['키', keyLabel(c.keyType)],
          ['올림', `${c.uploadedBy ?? '—'} · ${fmtTime(c.uploadedAt)}`],
          def && ['발급 정의', def.name],
          def && ['자동 갱신', nextText(def)],
        ]}
      />
      <MSec>링크 {c.links.length}</MSec>
      <MCards
        empty={linkText(c)}
        items={c.links.map((l) => ({
          key: `${l.host}|${l.alg}`,
          title: <span className="mono">{l.host}</span>,
          badge: ['un', ALG_LABEL[l.alg] ?? l.alg],
          lines: [l.servedBy?.length ? `서빙 ${l.servedBy.join(', ')}` : '서빙하는 서버 없음'],
        }))}
      />
    </>
  );
}

function MDefinitionDetail({ name }: { name: string }) {
  const q = usePoll((s) => acmeCert(name, s), [name], 3000);
  const { caOf } = useCaOf();
  useReadOnlyTop(name, '발급 정의', '발급·갱신·지우기는 넓은 화면에서', [name]);
  const c = q.data?.certificate;
  if (!c) return q.error !== undefined ? <Empty kind="scope" title="이 발급 정의가 없거나 볼 권한이 없습니다" /> : <Load q={q} what="발급 정의를 불러오지 못했습니다">{() => null}</Load>;
  const ca = caOf(c.account);
  const st = rowState({ key: c.name, def: c });
  return (
    <MDetail
      title={name}
      badge={[st.tone, st.text]}
      tone={cardTone(st.tone)}
      rows={[
        ['이름', <span key="n" className="mono">{c.names.join(', ')}</span>],
        ca && ['발급 기관', `${ca.name}${ca.staging ? ' (시험용)' : ''}`],
        ['키', c.keyTypes.map((k) => KEY_TYPE_LABEL[k] ?? k).join(' · ')],
        ['자동 갱신', nextText(c)],
        c.renewBlocked && ['갱신 막힘', c.renewBlocked],
        c.autoIssued && ['자동 발급', `${c.autoIssued.host} 감지 · ${fmtTime(c.autoIssued.detectedAt)}`],
      ]}
    />
  );
}
