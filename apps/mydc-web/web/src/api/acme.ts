// SPDX-License-Identifier: Apache-2.0

// 인증서 자동화 (UI-57~59). 웹 전용 ACME라 데몬의 /acme 끝점을 그대로 쓴다(시스템 관리자).
// 비공개 키는 웹 메모리에서 만들어 인증서 보관함에만 넘기고 버린다. 이 화면은 공개 정보만 다룬다.
import { api, ApiError } from './client';

export interface AcmeCA {
  id: string;
  name: string;
  directory: string;
  staging: boolean;
  needsEab: boolean;
  caa: string;
  keyTypes: string[];
  ready: boolean;
  note?: string;
}
export interface AcmeAccount {
  id: string;
  ca: string;
  email?: string;
  url: string;
  eab: boolean;
  agreedAt: string;
  createdBy?: string;
  createdAt?: string;
}
export interface AcmeCert {
  name: string;
  names: string[];
  account: string;
  keyTypes: string[];
  autoRenew: boolean;
  fingerprint?: string;
  keyType?: string;
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  nextRenew?: string;
  nextTry?: string;
  renewBlocked?: string;
  failures: number;
  lastOrder?: string;
  createdBy?: string;
  createdAt?: string;
  running: boolean;
  /** 읽기 전용: 이름마다 서버가 정한 확인 방식. null이면 그 이름은 받을 수 없다(이유는 대기 이유) */
  methods?: Record<string, 'dns-01' | 'http-01' | null>;
  /** 자동 발급이 만든 인증서: 감지한 호스트와 시각 */
  autoIssued?: { host: string; detectedAt: string };
}
export interface AcmeStep {
  name: string;
  state: 'done' | 'failed' | 'skipped' | 'running';
  at: string;
  detail?: string;
}
export interface AcmeOrder {
  id: string;
  cert: string;
  at: string;
  by: string;
  auto: boolean;
  state: 'running' | 'done' | 'failed';
  errorCode?: string;
  steps: AcmeStep[];
  keyType?: string;
  fingerprint?: string;
  orphanTxt?: string[];
  storeOp?: string;
  updatedAt: string;
}

const enc = encodeURIComponent;
const c = (name: string) => `/acme/certs/${enc(name)}`;

export const acmeCAs = (s?: AbortSignal) => api.get<{ items: AcmeCA[] }>('/acme/cas', s).then((r) => r.items ?? []);
export const acmeAccounts = (s?: AbortSignal) => api.get<{ items: AcmeAccount[] }>('/acme/accounts', s).then((r) => r.items ?? []);
export const addAcmeAccount = (body: { ca: string; email?: string; agreeTos: true; eab?: { keyId: string; hmac: string } }) => api.post<{ account: AcmeAccount }>('/acme/accounts', body);
export const deleteAcmeAccount = (id: string) => api.del<void>(`/acme/accounts/${enc(id)}`);
export const acmeCerts = (s?: AbortSignal) => api.get<{ items: AcmeCert[]; certStore: boolean }>('/acme/certs', s);
export const addAcmeCert = (body: { name: string; names: string[]; account: string; keyTypes?: string[]; autoRenew?: boolean }) => api.post<{ certificate: AcmeCert }>('/acme/certs', body);
export const acmeCert = (name: string, s?: AbortSignal) => api.get<{ certificate: AcmeCert; orders: AcmeOrder[] | null }>(c(name), s);
export const putAcmeCert = (name: string, body: { autoRenew: boolean; keyTypes: string[] }) => api.put<{ certificate: AcmeCert }>(c(name), body);
export const deleteAcmeCert = (name: string) => api.del<void>(c(name));
export const issueAcmeCert = (name: string, opId: string) => api.post<{ order: AcmeOrder }>(`${c(name)}/issue`, { opId });
/** 인증 기관에 해지 요청. reason: RFC 5280 이유 코드 이름 (keyCompromise 등) */
export const revokeAcmeCert = (name: string, reason?: string) => api.post<{ certificate: AcmeCert }>(`${c(name)}/revoke`, { confirm: name, ...(reason ? { reason } : {}) });
// 빠른 갱신 버튼의 작업 ID. 응답을 잃었으면 같은 ID로 다시 보내 CA 주문을 겹쳐 만들지 않는다.
const pendingIssue = new Map<string, string>();
const lostReply = (e: unknown) => e instanceof ApiError && (e.code === 'transport' || e.status === 0 || e.status >= 500);
export async function quickIssueAcmeCert(name: string) {
  const opId = pendingIssue.get(name) ?? crypto.randomUUID();
  pendingIssue.set(name, opId);
  try {
    const r = await issueAcmeCert(name, opId);
    pendingIssue.delete(name);
    return r;
  } catch (e) {
    if (!lostReply(e)) pendingIssue.delete(name);
    throw e;
  }
}
/** 공개 체인 PEM 주소(비공개 키 없음). 브라우저가 바로 내려받는다. */
// ── 자동 발급(웹 몫): 외부 접속 :443 호스트 규칙 중 맞는 인증서가 없는 호스트를 찾아 받는다 ──
export interface AcmeAutoDomain {
  domain: string;
  enabled: boolean;
  /** per-host: 호스트마다 따로, wildcard: *.domain 하나로 묶기 */
  mode: 'per-host' | 'wildcard';
  /** 비우면 기본 목록 */
  keyTypes?: string[];
  tenants: string[];
}
export interface AcmeAutoWaiting {
  host: string;
  /** no-domain: 외부 도메인에 없는 이름, auto-off: 그 도메인 자동 발급 꺼짐, caa-blocked, rate-limit, not-assigned: 쓰는 작업 공간에 그 이름이 도메인 배정에 없음 */
  reason: string;
  tenant?: string;
  app?: string;
  node: string;
  listen: string;
  since: string;
}
export interface AcmeAuto {
  /** 새 도메인의 기본값 */
  enabled: boolean;
  account?: string;
  keyTypes: string[];
  /** RSA 인증서도 함께 받기(두 벌) */
  dualRsa: boolean;
  notifyAfterMinutes: number;
  domains: AcmeAutoDomain[];
  waiting: AcmeAutoWaiting[];
  revision: number;
}
export const acmeAuto = (s?: AbortSignal) => api.get<AcmeAuto>('/acme/auto', s);
export const putAcmeAuto = (body: Omit<AcmeAuto, 'waiting'>) => api.put<AcmeAuto>('/acme/auto', body);
export const ignoreAutoHost = (host: string) => api.post<AcmeAuto>('/acme/auto/ignore', { host });
export const AUTO_REASON: Record<string, string> = {
  'no-domain': '등록된 도메인 아래 이름이 아니라 받을 수 없습니다',
  'not-registered': '등록된 도메인 아래 이름이 아니라 받을 수 없습니다',
  'no-responder': 'HTTP 확인 응답기가 없습니다 (공급자 없는 도메인인데 응답기가 설정 안 됨)',
  'wildcard-needs-provider': '와일드카드는 DNS 공급자가 있어야 합니다',
  'not-assigned': '이 호스트를 쓰는 작업 공간에 그 이름이 배정되지 않았습니다',
  'auto-off': '이 도메인은 자동 발급이 꺼져 있습니다',
  'caa-blocked': 'CAA 레코드가 이 인증 기관을 막습니다',
  'rate-limit': '인증 기관 요청 수 한도에 닿았습니다',
};

/** HTTP 확인 응답기(mydcd `domain acme-responder`). 웹 앱이 시작할 때 자기 주소로 설정한다. address가 없으면 설정 안 됨 → HTTP 확인 불가 */
export interface AcmeResponder {
  /** 클러스터(mydcd)에 등록된 응답기 주소 */
  address?: string;
  setAt?: string;
  setBy?: string;
  /** 이 웹 앱에 응답기(-acme-listen)가 켜져 있는가 */
  listening: boolean;
  /** 이 웹 앱이 클러스터 설정에 채우는 주소(-acme-advertise, 또는 구체적인 -acme-listen). 못 정하면 없음 */
  advertised?: string;
}
export const acmeResponder = (s?: AbortSignal) => api.get<AcmeResponder>('/acme/responder', s);

export const acmeChainUrl = (name: string) => `/api/v1${c(name)}/chain`;

// ── 화면 도우미 ──

export const KEY_TYPE_LABEL: Record<string, string> = {
  ec256: 'ECDSA P-256',
  ec384: 'ECDSA P-384',
  rsa2048: 'RSA 2048',
  rsa3072: 'RSA 3072',
  rsa4096: 'RSA 4096',
};
/** 보관함(mydcd) 키 형식 이름(ecdsa-p256 · rsa-2048 …)도 같은 글자로 */
export const keyLabel = (k?: string) => (k ? (KEY_TYPE_LABEL[k] ?? k.replace(/^ecdsa-p(\d+)$/, 'ECDSA P-$1').replace(/^rsa-(\d+)$/, 'RSA $1')) : '');
/** 기본 선호 목록은 ECDSA P-256 하나(#481). RSA는 권장하지 않는다 */
export const DEFAULT_KEY_TYPES = ['ec256'];
export const isRsa = (k: string) => k.startsWith('rsa');

export const STEP_LABEL: Record<string, string> = {
  preflight: '사전 검사 · 계정·키 형식·외부 도메인·CAA',
  order: '주문 만들기',
  txt: '확인용 TXT 만들기',
  propagation: '반영 확인 · 권한 네임서버에 보이는지',
  validate: '인증 기관 검증',
  finalize: '키 만들기 · 발급',
  store: '인증서 보관함에 올리기 · 호스트 링크',
  cleanup: 'TXT 지우기',
};
export const STEP_ORDER = ['preflight', 'order', 'txt', 'propagation', 'validate', 'finalize', 'store', 'cleanup'];

export const ACME_ERROR: Record<string, string> = {
  'renew-account': '사람 없는 갱신은 위임 계정이 생길 때까지 할 수 없습니다 · 직접 갱신하세요',
  account: '인증 기관 계정 문제',
  'key-type': '인증 기관이 받는 키 형식이 없습니다',
  'no-domain': '등록된 도메인 아래가 아닌 이름이 있습니다',
  'caa-blocked': 'CAA 레코드가 이 인증 기관을 허용하지 않습니다',
  'ca-order': '인증 기관이 주문을 거절했습니다',
  propagation: 'TXT가 10분 안에 권한 네임서버에 보이지 않았습니다',
  'ca-validate': '인증 기관 검증 실패',
  'ca-finalize': '인증 기관이 발급을 거절했습니다',
  'store-prepare': '보관함에 올리기 전 실패 · 보내지 않았습니다(다시 발급하세요)',
  'store-rejected': 'mydcd가 보관함 올리기를 실행 전에 거절했습니다(예: 로그인 만료)',
  'store-failed': '보관함 올리기가 적용되지 않았습니다(예: 다른 사람이 먼저 바꿈)',
  'store-unknown': '보관함 올리기 결과를 모릅니다 · 작업 기록에서 결과를 확인하거나 재개하세요',
  'invalid-certificate': 'mydcd가 체인이나 키를 받지 않았습니다(키 쌍·이름·유효 기간)',
  running: '이미 도는 발급이 있습니다',
  'in-use': '이 계정을 쓰는 인증서가 있습니다',
  exists: '같은 이름의 인증서가 있습니다',
  'not-issued': '아직 발급하지 않았습니다',
  'ca-register': '인증 기관에 계정을 만들지 못했습니다',
  'ca-revoke': '인증 기관이 해지를 거절했습니다',
  'seal-unavailable': '봉인 파일을 쓸 수 없습니다 · 웹 앱 설정에서 봉인 키를 확인하세요',
};
export const acmeErrorText = (code?: string) => (code ? (ACME_ERROR[code] ?? (code.startsWith('dns-') ? `DNS 공급자 오류(${code})` : code)) : '');

export const daysLeft = (iso?: string) => (iso ? Math.floor((Date.parse(iso) - Date.now()) / 86400000) : undefined);
