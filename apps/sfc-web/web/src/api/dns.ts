// SPDX-License-Identifier: Apache-2.0

// 외부 DNS (UI-54~56). 웹 전용 기능이라 sfcd 계약이 아니라 데몬의 /dns 끝점을 그대로 쓴다.
// 이름은 도메인 안의 상대 이름이다("@" = 도메인 자신, "*.shop" = 와일드카드).
import { api } from './client';

export interface DnsCapabilities {
  recordTypes: string[];
  wildcard: boolean;
  minTtl: number;
  perRecordId: boolean;
  validate: boolean;
  snapshots: boolean;
  nameservers: boolean;
  propagation: boolean;
}
export interface DnsVendor {
  id: string;
  name: string;
  tokenUrl?: string;
  ready: boolean;
  note?: string;
  capabilities: DnsCapabilities;
}
export interface DnsProvider {
  id: string;
  vendor: string;
  name: string;
  tokenHint: string;
  tokenExpires?: string;
  account?: string;
  lastCheck?: string;
  lastCheckOk: boolean;
  lastError?: string;
  /** 지금 창에서 남은 요청 수. -1 = 모름 */
  remaining: number;
  createdBy?: string;
  createdAt?: string;
}
export interface DnsAccount {
  name: string;
  scope?: string;
  domains: number;
  remaining: number;
  expiresAt?: string;
}
export interface DnsAssignment {
  tenant: string;
  names: string[];
}
/** 도메인에 붙인 DNS 공급자 연결 (웹 몫) */
export interface DnsDomainProvider {
  id: string;
  vendor: string;
  name: string;
}
/** 클러스터 도메인 목록(sfcd `domain list`) 한 줄에 웹 몫(공급자·배정)을 더한 것 */
export interface DnsDomain {
  /** 소문자 IDNA(A-label) */
  domain: string;
  /** 표시용 유니코드 이름(A-label과 다를 때만) */
  unicode?: string;
  /** 없으면 공급자 없이 등록한 도메인: 레코드는 직접 관리, 인증서는 HTTP 확인만 */
  provider: DnsDomainProvider | null;
  /** 이 도메인 아래 링크된 호스트 수 · 링크가 있는 인증서 수 (sfcd) */
  hosts?: number;
  certificates?: number;
  defaultTtl: number;
  assignments: DnsAssignment[] | null;
  addedBy?: string;
  addedAt?: string;
  /** 시스템 관리자가 아니면: 내가 바꿀 수 있는 이름 범위 */
  myNames?: string[];
  /** false면 클러스터 도메인 목록에서 빠졌는데 웹 연결만 남은 것 (#651) */
  registered?: boolean;
}
export interface DnsRecord {
  content: string;
  priority?: number;
}
export interface RRSet {
  name: string;
  type: string;
  ttl: number;
  records: DnsRecord[];
}
export interface DnsManaged {
  name: string;
  type: string;
  tenant?: string;
  app?: string;
  by: string;
  fingerprint: string;
  at: string;
}
export interface DnsRecordView extends RRSet {
  fingerprint: string;
  managed?: DnsManaged;
  outside: boolean;
  writable: boolean;
}
export interface DnsZoneView {
  items: DnsRecordView[];
  orphans: DnsManaged[] | null;
  capabilities: DnsCapabilities;
  readAt: string;
}
export interface DnsKey {
  name: string;
  type: string;
}
export interface DnsChangeReq {
  upsert: RRSet[];
  delete: DnsKey[];
  outside?: boolean;
  tenant?: string;
  app?: string;
}
export interface DnsPlannedChange {
  name: string;
  type: string;
  before: RRSet | null;
  after: RRSet | null;
  fingerprint: string;
  tenant?: string;
  outside?: boolean;
}
export interface DnsProblem {
  name: string;
  type: string;
  message: string;
}
export interface DnsPlan {
  changes: DnsPlannedChange[];
  problems: DnsProblem[];
}
export interface DnsHistory {
  id: string;
  domain: string;
  at: string;
  user: string;
  username: string;
  tenant?: string;
  changes: { name: string; type: string; before: RRSet | null; after: RRSet | null }[];
  result: 'applied' | 'failed' | 'unknown';
  error?: string;
  snapshot?: string;
  revertOf?: string;
}
export interface DnsSnapshot {
  id: string;
  createdAt: string;
  reason?: string;
}
export interface DnsImportable {
  name: string;
  hasZone: boolean;
  /** 이 공급자 연결을 이미 붙임 */
  connected: boolean;
  /** 클러스터 도메인 목록에 있음 */
  registered?: boolean;
  /** 공급자의 레코드 수 (읽혔을 때) */
  records?: number;
  nameservers?: string;
}

const enc = encodeURIComponent;
const d = (domain: string) => `/dns/domains/${enc(domain)}`;

export const dnsVendors = (s?: AbortSignal) => api.get<{ items: DnsVendor[]; sealReady: boolean }>('/dns/vendors', s);
export const dnsProviders = (s?: AbortSignal) => api.get<{ items: DnsProvider[] }>('/dns/providers', s).then((r) => r.items ?? []);
export const addDnsProvider = (body: { vendor: string; name: string; token: string }) => api.post<{ provider: DnsProvider; account: DnsAccount }>('/dns/providers', body);
export const checkDnsProvider = (id: string) => api.post<{ provider: DnsProvider; account?: DnsAccount }>(`/dns/providers/${enc(id)}/check`);
export const putDnsToken = (id: string, token: string) => api.put<{ provider: DnsProvider }>(`/dns/providers/${enc(id)}/token`, { token });
/** 데몬에 아직 없다(요청함). 목업에서만 된다. */
export const renameDnsProvider = (id: string, name: string) => api.put<{ provider: DnsProvider }>(`/dns/providers/${enc(id)}`, { name });
export const deleteDnsProvider = (id: string) => api.del<void>(`/dns/providers/${enc(id)}`);
export const dnsImportable = (id: string, s?: AbortSignal) => api.get<{ items: DnsImportable[] }>(`/dns/providers/${enc(id)}/domains`, s).then((r) => r.items ?? []);

/** 지금 데몬 응답(provider 문자열 + providerName·vendor)도 같은 모양으로 읽는다 */
type RawDomain = Omit<DnsDomain, 'provider'> & { provider: DnsDomainProvider | string | null; providerName?: string; vendor?: string };
export const normDomain = ({ provider, providerName, vendor, ...d }: RawDomain): DnsDomain => ({
  ...d,
  provider: typeof provider === 'string' ? (provider ? { id: provider, vendor: vendor ?? '', name: providerName ?? provider } : null) : provider,
});
/** cluster: 데몬이 클러스터 도메인 목록(sfcd domain list)을 쓰는가. 아니면 등록·빼기·공급자 붙이기·떼기는 서버 기능 대기 */
export const dnsDomainList = (s?: AbortSignal) => api.get<{ items: RawDomain[] | null; cluster?: boolean }>('/dns/domains', s).then((r) => ({ items: (r.items ?? []).map(normDomain), cluster: !!r.cluster }));
export const dnsDomains = (s?: AbortSignal) => dnsDomainList(s).then((r) => r.items);
/** 클러스터 도메인 목록에 등록한다(sfcd `domain add`, 시스템 관리자). provider를 주면 공급자도 함께 붙인다.
 * linked: 등록으로 링크를 얻은 인증서 수(미연결 → 연결됨). 공개 접미사면 422 public-suffix. */
export const addDnsDomain = (body: { domain: string; provider?: string; defaultTtl?: number; assignments?: DnsAssignment[] }) => api.post<{ domain: DnsDomain; linked?: number }>('/dns/domains', body);
/** 등록된 도메인에 공급자를 붙이거나 바꾼다 */
export const putDnsDomainProvider = (domain: string, provider: string) => api.put<{ domain: DnsDomain }>(`${d(domain)}/provider`, { provider });
/** 공급자만 뗀다. 도메인은 목록에 남는다 */
export const deleteDnsDomainProvider = (domain: string) => api.del<{ domain: DnsDomain }>(`${d(domain)}/provider`);
export const putDnsDomain = (domain: string, body: { defaultTtl: number; assignments: DnsAssignment[] }) => api.put<{ domain: DnsDomain }>(d(domain), body);
/** 목록에서 뺀다(sfcd `domain remove`). 링크가 있어도 거절하지 않는다: 그 아래 링크가 모두 떨어지고 인증서는 미연결이 된다 */
export const deleteDnsDomain = (domain: string) => api.del<{ unlinkedHosts?: number; unlinkedCertificates?: number } | void>(d(domain));

/** 도메인 이름을 소문자 IDNA(A-label)로. 형식이 틀리면 undefined */
export function idna(raw: string): string | undefined {
  const t = raw.trim().replace(/\.$/, '');
  if (!t || /[\s/:@*?#]/.test(t) || !t.includes('.')) return undefined;
  try {
    const h = new URL(`http://${t}`).hostname.toLowerCase();
    return /^[a-z0-9.-]+$/.test(h) && h.split('.').every((l) => l && l.length <= 63 && !l.startsWith('-') && !l.endsWith('-')) ? h : undefined;
  } catch {
    return undefined;
  }
}
/** 이름이 등록된 도메인 아래인가 (와일드카드 *.x는 x 아래로) */
export const underDomain = (name: string, domain: string) => {
  const n = name.replace(/^\*\./, '');
  return n === domain || n.endsWith(`.${domain}`);
};
export const dnsRecords = (domain: string, s?: AbortSignal) => api.get<DnsZoneView>(`${d(domain)}/records`, s);
export const planDns = (domain: string, body: DnsChangeReq) => api.post<DnsPlan>(`${d(domain)}/plan`, body);
export const applyDns = (domain: string, body: DnsChangeReq & { opId: string; basis: Record<string, string>; revertOf?: string }) => api.post<{ history: DnsHistory }>(`${d(domain)}/apply`, body);
export const dnsHistory = (domain: string, s?: AbortSignal) => api.get<{ items: DnsHistory[] }>(`${d(domain)}/history`, s).then((r) => r.items ?? []);
export const revertDns = (domain: string, id: string) => api.post<{ request: DnsChangeReq; revertOf: string }>(`${d(domain)}/history/${enc(id)}/revert`);
export const deleteDnsHistory = (domain: string, id: string) => api.del<void>(`${d(domain)}/history/${enc(id)}`);
export const dnsSnapshots = (domain: string, s?: AbortSignal) => api.get<{ items: DnsSnapshot[] }>(`${d(domain)}/snapshots`, s).then((r) => r.items ?? []);
export const restoreDnsSnapshot = (domain: string, id: string) => api.post<unknown>(`${d(domain)}/snapshots/${enc(id)}/restore`, { confirm: domain });

/** 반영 확인. 데몬에 아직 없다(요청함). 목업에서만 된다. */
export interface DnsPropagation {
  name: string;
  type: string;
  want: string[];
  resolvers: { kind: 'authoritative' | 'public'; server: string; values: string[]; fresh: boolean; ttlLeft?: number; error?: string }[];
  checkedAt: string;
}
export const dnsPropagation = (domain: string, name: string, type: string) => api.get<DnsPropagation>(`${d(domain)}/propagation?name=${enc(name)}&type=${enc(type)}`);

// ── 화면 도우미 ──

export const keyOf = (k: DnsKey) => `${k.name}|${k.type}`;
/** "@" → 도메인, "shop" → shop.도메인 */
export const fqdn = (name: string, domain: string) => (name === '@' ? domain : `${name}.${domain}`);
export const recordText = (r: DnsRecord) => (r.priority !== undefined && r.priority !== 0 ? `${r.priority} ${r.content}` : r.content);
export const setText = (s: RRSet | null | undefined) => (s ? s.records.map(recordText).join(', ') : '');

/** 이름이 배정 범위("shop", "*.shop") 안인가. 데몬 dns.InRange와 같은 규칙. */
export function inRange(name: string, patterns: string[]): boolean {
  return patterns.some((p) => {
    if (p === name) return true;
    if (p.startsWith('*.')) {
      const base = p.slice(2);
      return name === `*.${base}` || name.endsWith(`.${base}`);
    }
    return false;
  });
}

/** 상대 이름 형식 검사. 비면 오류 문구를 돌려준다. */
export function nameProblem(name: string, wildcard = true): string | undefined {
  if (!name) return '이름을 적으세요';
  if (name === '@') return undefined;
  const labels = name.split('.');
  for (const [i, l] of labels.entries()) {
    if (l === '*' && i === 0) {
      if (!wildcard) return '이 공급자는 와일드카드를 지원하지 않습니다';
      continue;
    }
    if (!/^[a-z0-9_]([a-z0-9-_]{0,61}[a-z0-9])?$/i.test(l)) return '영문·숫자·-·_ 로 된 이름(점으로 구분)';
  }
  return undefined;
}

/** 값 한 줄 → 레코드. MX·SRV는 "우선순위 값". */
export function parseRecordLine(type: string, line: string): DnsRecord | string {
  const t = line.trim();
  if (!t) return '빈 값';
  if (type === 'MX' || type === 'SRV') {
    const m = /^(\d+)\s+(.+)$/.exec(t);
    if (!m) return `${type}는 "우선순위 값" 모양입니다(예: 10 mx1.example.com.)`;
    return { priority: Number(m[1]), content: m[2] };
  }
  if (type === 'A' && !/^(\d{1,3}\.){3}\d{1,3}$/.test(t)) return 'IPv4 주소가 아닙니다';
  if (type === 'AAAA' && !/^[0-9a-f:]+$/i.test(t)) return 'IPv6 주소가 아닙니다';
  return { content: t };
}

export const VENDOR_LOGO: Record<string, [string, string]> = {
  hostinger: ['H', '#673DE6'],
  cloudflare: ['C', '#F38020'],
  route53: ['R', '#232F3E'],
  rfc2136: ['⇄', '#5B6370'],
  fake: ['F', '#1F5FBF'],
};

export const DNS_ERROR: Record<string, string> = {
  'dns-auth-failed': '공급자 인증 실패 · 토큰이 틀렸거나 만료됐습니다',
  'dns-forbidden': '이 토큰으로는 그 도메인을 다룰 수 없습니다',
  'dns-not-found': '공급자에 그 도메인이 없습니다',
  'dns-rate-limited': '공급자 요청 수 초과 · 잠시 뒤 다시 하세요',
  'dns-invalid': '공급자가 이 변경을 거절했습니다',
  'dns-conflict': '공급자 쪽에서 충돌했습니다',
  'dns-unavailable': '공급자에 닿지 못했습니다',
  'seal-unavailable': '봉인 파일을 쓸 수 없습니다 · 웹 앱 설정에서 봉인 키를 확인하세요',
  'zone-changed': '계획한 뒤 공급자 쪽에서 레코드가 바뀌었습니다',
  'zone-elsewhere': '이 도메인의 DNS는 이 공급자에 없습니다',
  'out-of-range': '배정받은 이름 범위 밖입니다',
  outside: '클러스터 밖 레코드입니다 · 잠금을 풀어야 바꿀 수 있습니다',
  'in-use': '쓰고 있어서 지울 수 없습니다',
  exists: '이미 등록된 도메인입니다',
  'public-suffix': '공개 접미사라 등록할 수 없습니다',
  'invalid-domain': '도메인 이름 형식이 아닙니다',
};

// ── 도메인에 연결한 서버 (web 몫, 캔버스 ExtDomainDetail '연결된 서버'). 외부 접속 수신·주소는 sfcd REQ-22 조회에서 온다 ──
export interface DnsServerLink {
  node: string;
  /** 외부망 게이트웨이가 받는 포트 */
  listen: number[];
  /** 레코드가 가리킬 공개 주소 (IPv4·IPv6) */
  addresses: string[];
  /** node: 서버 외부망 주소 그대로 · manual: 직접 입력 (NAT 뒤) */
  addressSource: 'node' | 'manual';
  linked: boolean;
  /** 서버에 문제가 생기면 DNS에서 자동으로 빼기. 끄면 알림만 */
  autoRemove: boolean;
  reach?: { ok: boolean; at: string; error?: string };
  state: 'in-dns' | 'removed' | 'not-linked';
  isolated?: boolean;
  /** 외부망 게이트웨이가 sfcd에서 사라짐 */
  missing?: boolean;
}
/** GET·PUT 응답. changes는 Seafield Cluster A·AAAA를 연결된 서버 주소로 맞추는 바꿀 내용(서버는 저장하지 않음, plan·apply에 그대로 보냄) */
export interface DnsServersView {
  items: DnsServerLink[];
  revision: number;
  changes?: { upsert: RRSet[]; delete: DnsKey[] };
  staged?: number;
  /** 관리자가 아니면 연결한 서버만, 저장된 그대로 */
  partial?: boolean;
}
export const dnsServers = (domain: string, signal?: AbortSignal) => api.get<DnsServersView>(`/dns/domains/${enc(domain)}/servers`, signal);
/** 연결·설정 바꾸기·끊기. 저장하면 Seafield 레코드 바꿀 내용이 만들어진다(레코드 탭에서 검토 후 적용) */
export const putDnsServer = (domain: string, node: string, b: { linked: boolean; addressSource?: 'node' | 'manual'; addresses?: string[]; autoRemove?: boolean; revision: number }) =>
  api.put<DnsServersView>(`/dns/domains/${enc(domain)}/servers/${enc(node)}`, b);
/** 바깥에서 :443이 닿는지 (공개 해석기 경로). node가 없으면 연결한 서버 전부 */
export const checkDnsServers = (domain: string, b: { node?: string; addresses?: string[] } = {}) => api.post<{ items: { node: string; ok: boolean; at: string; error?: string }[] }>(`/dns/domains/${enc(domain)}/servers/check`, b);
