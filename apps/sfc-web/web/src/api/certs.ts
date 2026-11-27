// SPDX-License-Identifier: Apache-2.0

// 클러스터 인증서 보관함 (devel/design/certificate-store.md 2~5절, UI-57·59).
// 인증서는 이름 없이 올리고, ID는 leaf DER의 SHA-256(hex 64자)이다. 보관함이 SAN을 읽어
// (호스트, 알고리즘 계열)마다 하나씩 링크한다. 비공개 키는 올릴 때 한 번만 보내고 브라우저에 남기지 않는다.
import { api, apiUrl } from './client';

/** linked: 링크가 하나 이상 · unlinked(미연결): 등록된 도메인 아래 이름이 없음 · pending-destroy(파기 대기): 링크를 모두 다른 인증서가 가져감 */
export type CertState = 'linked' | 'unlinked' | 'pending-destroy';
export interface CertLink {
  host: string;
  /** 알고리즘 계열(호스트·계열마다 링크 하나) */
  alg: 'ecdsa' | 'rsa' | string;
  /** 상세에서만: 이 호스트를 지금 서빙하는 외부 접속 서버 */
  servedBy?: string[];
}
export interface StoreCert {
  id: string;
  names: string[];
  /** ecdsa-p256 · ecdsa-p384 · rsa-2048 … (rsa-로 시작하면 권장하지 않음) */
  keyType: string;
  /** 발급자 DN */
  issuer: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  uploadedBy?: string;
  uploadedAt: string;
  state: CertState;
  /** certificate disable로 끊은 인증서. 같은 ID로 다시 올려도 링크를 얻지 못한다 */
  disabled?: boolean;
  links: CertLink[];
  /** 웹 발급 정의 이름. 그 정의가 마지막으로 받은 인증서일 때만 (웹이 붙임) */
  definition?: string;
  /** 상세에서만: 체인의 subject들 (leaf부터) */
  chain?: string[];
}

export const certificates = (q: { host?: string; state?: 'unlinked' | 'pending-destroy' } = {}, signal?: AbortSignal) => {
  const p = new URLSearchParams(Object.entries(q).filter(([, v]) => v) as [string, string][]);
  return api.get<{ items: StoreCert[] | null }>(`/certificates${p.size ? `?${p}` : ''}`, signal).then((r) => r.items ?? []);
};
/** id는 앞 12자 이상이면 된다 (하나뿐일 때) */
export const certificate = (id: string, signal?: AbortSignal) => api.get<StoreCert>(`/certificates/${encodeURIComponent(id)}`, signal);
/** 체인만 읽어 미리 본다(비공개 키는 보내지 않음). links: 올리면 걸릴 링크, replaces: 그 호스트·계열의 지금 링크 */
export interface CertCheck {
  id: string;
  names: string[];
  keyType: string;
  issuer: string;
  notAfter: string;
  /** 올리면 거절될 이유 */
  invalid?: 'expired' | 'not-yet-valid' | 'unsupported-key' | 'no-names';
  links: { host: string; alg: string; replaces?: string }[];
}
export const checkCertChain = (chain: string) => api.post<CertCheck>('/certificates/check', { chain });
/** 이름 없이 올린다. key는 이 요청에만 싣고 남기지 않는다. created=false면 같은 ID가 이미 있었다.
 * 422: mismatch · not-valid-now · unsupported-key · no-names */
export const putCertificate = (body: { chain: string; key: string }) => api.post<{ id: string; created: boolean; links: CertLink[] }>('/certificates', body);
/** 미연결·파기 대기만. 연결된 인증서면 409 linked (body.raw.links) */
export const deleteCertificate = (id: string) => api.del<void>(`/certificates/${encodeURIComponent(id)}`);
/** 끊기: 링크를 한 번에 모두 떼고 파기 대기로 보낸다 */
export const disableCertificate = (id: string) => api.post<{ unlinkedHosts: number }>(`/certificates/${encodeURIComponent(id)}/disable`);
/** 공개 체인 PEM (비공개 키 없음) */
export const certChainUrl = (id: string) => apiUrl(`/certificates/${encodeURIComponent(id)}/chain`);

// ── 화면 도우미 ──

export const short = (id?: string) => (id ? id.slice(0, 12) : '');
export const CERT_STATE: Record<CertState, [string, 'ok' | 'un' | 'wa']> = { linked: ['연결됨', 'ok'], unlinked: ['미연결', 'un'], 'pending-destroy': ['파기 대기', 'wa'] };
/** 지울 수 있는 상태 (연결됨은 서버가 거절) */
export const deletable = (c: Pick<StoreCert, 'state'>) => c.state !== 'linked';
/** 발급자 DN에서 보이는 이름 (O, 없으면 CN) */
export function issuerName(dn?: string) {
  if (!dn) return '';
  const o = /(?:^|,\s*)O=([^,]+)/.exec(dn)?.[1];
  const cn = /(?:^|,\s*)CN=([^,]+)/.exec(dn)?.[1];
  return (o ?? cn ?? dn).replace(/^"|"$/g, '');
}
export const ALG_LABEL: Record<string, string> = { ecdsa: 'ECDSA', rsa: 'RSA' };
/** 두 인증서의 이름이 겹치는가 (와일드카드는 글자 그대로 비교) */
export const sharesName = (a: StoreCert, b: StoreCert) => a.names.some((n) => b.names.includes(n));
/** 이 인증서가 호스트를 덮는가 (한 단계 와일드카드 포함) */
export const covers = (c: Pick<StoreCert, 'names'>, host: string) => c.names.includes(host) || (!host.startsWith('*.') && c.names.includes(`*.${host.split('.').slice(1).join('.')}`));
/** 끊은 뒤 이 호스트·계열을 가져갈 인증서 (지금 유효, 끊지 않음, 가장 늦게 만료) */
export function nextLink(all: StoreCert[], self: StoreCert, host: string, alg: string): StoreCert | undefined {
  const famOf = (k: string) => (k.startsWith('rsa') ? 'rsa' : 'ecdsa');
  const now = Date.now();
  return all
    .filter((c) => c.id !== self.id && !c.disabled && famOf(c.keyType) === alg && c.names.includes(host) && Date.parse(c.notBefore) <= now && Date.parse(c.notAfter) > now)
    .sort((a, b) => Date.parse(b.notAfter) - Date.parse(a.notAfter))[0];
}
