// SPDX-License-Identifier: Apache-2.0

// 서버 › VPS 관리 (UI-12B). 계약: docs/reference/web-api/54-vps.md. 시스템 관리자만.
// 모든 변경은 opId를 붙인 보통 작업이다. 금액은 원(VAT 포함), 시각은 Unix 초.
// 공급자 키(Access/Secret)는 보낼 때만 쓰고 화면 상태·초안·주소 어디에도 남기지 않는다.
import { api } from './client';

export interface VpsAccount {
  name: string;
  vendor: string;
  overageKRWPerGB: number;
  /** 트래픽 조기 감시 설정. 빠진 칸은 기본(창 5분, 평균 60분, 패턴 켬) (#701) */
  guard?: { windowMin?: number; averageMin?: number; patternOff?: boolean };
  /** 공급자가 공개한 초과 요금 구간(부가세 별도). 있으면 overageKRWPerGB 대신 쓴다. 마지막 upToGB 0 = 끝 없음 (#698) */
  overageTiers?: VpsOverageTier[] | null;
  /** Access Key 끝 네 글자 */
  keyHint?: string;
  sshPublic?: string;
  sshKeyID?: string;
  addedBy?: string;
  addedAt?: number;
  updatedBy?: string;
  updatedAt?: number;
}
export interface VpsOverageTier {
  upToGB: number;
  krwPerGB: number;
}
export type VpsPhase = 'creating' | 'installing' | 'running' | 'stopping' | 'stopped' | 'capped' | 'starting' | 'failed' | 'deleting';
export interface VpsDnsHold {
  domain: string;
  at: string;
  sets: { name: string; type: string; removed: string[]; after?: string }[] | null;
  kept: { name: string; type: string }[] | null;
  blocked: { name: string; type: string }[] | null;
}
export interface VpsServer {
  name: string;
  account: string;
  zone: string;
  image: string;
  flavor: string;
  script?: string;
  capKRW: number;
  capAction?: 'stop' | 'notify';
  voter: boolean;
  port?: number;
  createdBy?: string;
  createdAt?: number;
  phase: VpsPhase | string;
  /** installing이면서 초대가 발급됨 = 가입 중 */
  joining?: boolean;
  phaseAt?: number;
  stopAfter?: number;
  failure?: string;
  /** reason 'traffic-soon' = 1분 조기 감시가 21분 안에 상한에 닿는다고 보고 끔 (#701) */
  capStop?: { at: number; month: string; capKRW: number; soFarKRW: number; projectedKRW: number; reason?: string };
  instanceID?: string;
  publicIP?: string;
  dnsHolds?: VpsDnsHold[] | null;
}
export interface VpsServerStatus {
  name: string;
  updatedAt: number;
  capKRW: number;
  soFarKRW: number;
  projectedKRW: number;
  baseSoFarKRW: number;
  baseMonthKRW: number;
  trafficSoFarKRW: number;
  trafficMonthKRW: number;
  usedGB: number;
  /** 공급자가 알려 준 기본 제공량. 인스턴스를 읽은 뒤에만 온다 */
  includedGB?: number;
  includedPeriod?: 'MONTH' | 'DAY';
  projectedGB: number;
  recentMB: number;
  /** 초과 요금을 세는 이번 달 제공량(일간이면 하루 제공량 × 서비스 일수, includedMaxGB를 넘지 않음) */
  includedMonthGB?: number;
  /** 월 최대 제공량(iwinv: 하루 제공량 × 30). 0·없음 = 월 최대 없음 */
  includedMaxGB?: number;
  /** 오늘(한국 시각) 사용량 */
  todayMB?: number;
  /** 이번 달 최근 7일 일별 사용량, 오래된 날부터 */
  daily?: { day: string; mb: number }[] | null;
  /** 공급자가 트래픽을 세는 방식. 빠지면 모름(iwinv) */
  trafficCounting?: 'tx' | 'rx+tx' | string;
  judgeable: boolean;
  /** 1분 조기 감시의 마지막 판정. 꺼진 서버·창 하나가 모이기 전에는 없다 (#701) */
  guard?: VpsGuardStatus;
  over?: boolean;
  capBlocked?: boolean;
  failure?: string;
  failureAt?: number;
}
export interface VpsGuardStatus {
  at?: number;
  /** 최근 창 · 앞 창 · 누적 평균 송신 속도 */
  rateMbps?: number;
  prevMbps?: number;
  averageMbps?: number;
  /** 앞으로 21분 예측 */
  forecastGB?: number;
  /** 지난 달 같은 시각대 패턴 예측, 기록 날 수, 썼는지 */
  patternGB?: number;
  patternDays?: number;
  patternUsed?: boolean;
  monthGB?: number;
  /** 상한까지 남은 GB. unlimited면 없다 */
  remainingGB?: number;
  unlimited?: boolean;
  /** 21분 안에 닿음 */
  soon?: boolean;
  soonAt?: number;
}
export interface VpsAccountStatus {
  name: string;
  billKRW: number;
  oursKRW: number;
  updatedAt: number;
  failure?: string;
}
export interface VpsView {
  revision: number;
  accounts: VpsAccount[];
  servers: VpsServer[];
  dnsAuto: boolean;
  status: { leader: string; servers: VpsServerStatus[] | null; accounts: VpsAccountStatus[] | null } | null;
  statusError?: string;
}
/** 타입의 트래픽 제공량. maxGB 0 = 월 최대 없음. estimated = 카탈로그에 없어 공급자 보통 값으로 채움 */
export interface VpsFlavorTraffic {
  gb: number;
  period: 'MONTH' | 'DAY' | string;
  maxGB?: number;
  estimated?: boolean;
}
export interface VpsOffer {
  account: string;
  at: number;
  zones: { id: string; name: string; usable: boolean }[];
  images: { id: string; name: string; kind?: string; os?: string; linux: boolean; zones: string[] | null }[];
  flavors: { id: string; name: string; vcpu: number; memoryMiB: number; diskGB: number; full?: { krw: number; per: string }; traffic?: VpsFlavorTraffic }[];
  sshKeys: { id: string; name: string }[] | null;
  scripts: { id: string; name: string }[] | null;
}
export interface VpsDnsPlanRow {
  domain: string;
  name: string;
  type: string;
  value: string;
  ttl: number;
  outcome: 'withdraw' | 'keep-last' | 'manual';
  others: number;
}
export interface VpsDnsPlan {
  rows: VpsDnsPlanRow[];
  waitSeconds: number;
  dnsAuto: boolean;
}

const enc = encodeURIComponent;
const arr = <T,>(x: T[] | null | undefined): T[] => x ?? [];

export const vpsView = async (s?: AbortSignal): Promise<VpsView> => {
  const r = await api.get<VpsView>('/system/vps', s);
  return { ...r, accounts: arr(r.accounts), servers: arr(r.servers).map((x) => ({ ...x, dnsHolds: arr(x.dnsHolds) })) };
};
export const vpsOffer = async (account: string, zone?: string, s?: AbortSignal): Promise<VpsOffer> => {
  const r = await api.get<VpsOffer>(`/system/vps/accounts/${enc(account)}/offer${zone ? `?zone=${enc(zone)}` : ''}`, s);
  return { ...r, zones: arr(r.zones), images: arr(r.images), flavors: arr(r.flavors), sshKeys: arr(r.sshKeys), scripts: arr(r.scripts) };
};
export const vpsDnsPlan = async (name: string, s?: AbortSignal): Promise<VpsDnsPlan> => {
  const r = await api.get<VpsDnsPlan>(`/system/vps/servers/${enc(name)}/dns-plan`, s);
  return { ...r, rows: arr(r.rows) };
};
export const clearVpsDnsHold = (name: string, domain: string) => api.del<void>(`/system/vps/servers/${enc(name)}/dns-holds/${enc(domain)}`);

// 변경 경로(useMutation.run/sendOp으로 보낸다)
export const VPS = {
  accounts: '/system/vps/accounts',
  account: (a: string) => `/system/vps/accounts/${enc(a)}`,
  rotate: (a: string) => `/system/vps/accounts/${enc(a)}/rotate-key`,
  servers: '/system/vps/servers',
  server: (n: string) => `/system/vps/servers/${enc(n)}`,
  stop: (n: string) => `/system/vps/servers/${enc(n)}/stop`,
  start: (n: string) => `/system/vps/servers/${enc(n)}/start`,
  cap: (n: string) => `/system/vps/servers/${enc(n)}/cap`,
};

export const VPS_PHASE: Record<string, [tone: 'ok' | 'pr' | 'wa' | 'er' | 'un', text: string]> = {
  creating: ['pr', '생성 중'],
  installing: ['pr', '설치 중'],
  running: ['ok', '실행 중'],
  stopping: ['wa', '끄는 중'],
  stopped: ['un', '중지됨'],
  capped: ['wa', '상한으로 중지됨'],
  starting: ['pr', '켜는 중'],
  failed: ['er', '오류'],
  deleting: ['wa', '삭제 중'],
};
export const vpsBusy = (p: string) => ['creating', 'installing', 'starting', 'stopping', 'deleting'].includes(p);
export const VPS_ERROR: Record<string, string> = {
  unavailable: '공급자에 닿지 못했습니다. 웹이 붙은 서버가 투표 서버가 아니거나 공급자가 키를 거부했습니다.',
  exists: '같은 이름이 이미 있습니다.',
  unchanged: '바뀌는 것이 없습니다.',
  'in-use': '이 계정으로 만든 VPS 서버가 남아 있습니다. 먼저 지우세요.',
  phase: '지금 단계에서는 할 수 없습니다. 목록을 다시 읽어 주세요.',
  held: '아직 중지 중이라 빼 둔 레코드가 있습니다.',
};

export const won = (n: number | undefined) => (n === undefined || !Number.isFinite(n) ? '—' : `₩${Math.round(n).toLocaleString('ko-KR')}`);
export const fromUnix = (s: number | undefined) => (s ? new Date(s * 1000).toISOString() : undefined);
/** 1 vCPU · 2 GB · 25 GB */
export const flavorText = (f: VpsOffer['flavors'][number]) => `${f.vcpu} vCPU · ${f.memoryMiB >= 1024 ? `${Math.round(f.memoryMiB / 102.4) / 10} GB` : `${f.memoryMiB} MB`} · ${f.diskGB} GB`;
/** 412 GB · 1.9 TB */
export const gbText = (gb: number | undefined) => (gb === undefined ? '—' : gb >= 1000 ? `${Math.round(gb / 100) / 10} TB` : `${Math.round(gb)} GB`);
export const mbText = (mb: number | undefined) => (mb === undefined ? '—' : mb >= 1000 ? `${Math.round(mb / 100) / 10} GB` : `${Math.round(mb)} MB`);
/** 대기 사유: 상한으로 중지된 서버를 지금 상한으로 켤 수 있는가(새 달이거나 상한이 예상보다 높을 때) */
export function canResumeCapped(s: VpsServer, now = new Date()): boolean {
  if (s.phase !== 'capped' || !s.capStop) return true;
  const month = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  return s.capStop.month !== month || s.capKRW > s.capStop.projectedKRW;
}

/** 세는 방식: TX만 · RX+TX · 세는 방식 모름 (공급자마다 정해진 값, #698) */
export const countingText = (c: string | undefined) => (c === 'tx' ? 'TX만' : c === 'rx+tx' ? 'RX+TX' : '세는 방식 모름');
/** 공급자마다 정해진 세는 방식(서버 값이 아직 없을 때). iwinv는 나가는 것만 (Jay 확인, 캔버스 v250) */
export const vendorCounting = (vendor: string | undefined) => (vendor === 'iwinv' ? 'tx' : undefined);
/** 판정 기준: '일간 20 GB' · '월간 2 TB' · '제공량 모름' */
export const periodText = (gb: number | undefined, period: string | undefined) =>
  gb === undefined ? '제공량 모름' : period === 'DAY' ? `일간 ${gbText(gb)}` : `월간 ${gbText(gb)}`;
/** 타입 표의 트래픽 제공량: '하루 20 GB · 월 최대 600 GB · 추정' */
export function flavorTrafficText(t: VpsFlavorTraffic | undefined, counting?: string): string {
  if (!t) return '—';
  const head = t.period === 'DAY' ? `하루 ${gbText(t.gb)}` : `월 ${gbText(t.gb)}`;
  return `${head}${t.period === 'DAY' && t.maxGB ? ` · 월 최대 ${gbText(t.maxGB)}` : ''}${counting ? ` · ${countingText(counting)}` : ''}${t.estimated ? ' · 추정' : ''}`;
}
/** 이번 달 초과 판정: 남은 양 또는 넘은 양, 월말 예상 */
export function trafficVerdict(x: VpsServerStatus, perGB?: number, now = new Date()): { tone?: 'wa' | 'er'; text: string } {
  const inc = x.includedMonthGB ?? (x.includedPeriod === 'MONTH' ? x.includedGB : undefined);
  if (inc === undefined) return { text: '제공량 모름 · 초과 요금은 계산하지 않음' };
  const proj = x.judgeable ? x.projectedGB : undefined;
  // 일간 판정이면 월말 제공량은 남은 날만큼 더 쌓인다(월 최대까지)
  const last = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
  const endInc = x.includedPeriod === 'DAY' && x.includedGB !== undefined ? Math.min(inc + x.includedGB * (last - now.getDate()), x.includedMaxGB || Infinity) : inc;
  const over = proj === undefined ? 0 : proj - endInc;
  const overText = over > 0 ? ` → 초과 ${gbText(over)}${perGB ? ` (${won(over * perGB)})` : ''}` : '';
  if (x.usedGB > inc) return { tone: 'er', text: `이미 ${gbText(x.usedGB - inc)} 넘음${proj !== undefined ? ` · 월말 약 ${gbText(proj)}${overText}` : ''}` };
  const left = `남은 ${gbText(inc - x.usedGB)}`;
  if (proj === undefined) return { text: `${left} · 월말 예상은 판정 전` };
  if (over <= 0) return { text: `${left} · 월말 약 ${gbText(proj)} / ${gbText(endInc)} · 초과 없음 예상` };
  return { tone: 'wa', text: `${left} · 월말 약 ${gbText(proj)}${overText}` };
}

/** iwinv 공개 초과 요금(부가세 별도). 계정을 만들기 전 연결 창에서만 쓴다. 만든 뒤에는 accounts[].overageTiers */
export const IWINV_TIERS: VpsOverageTier[] = [
  { upToGB: 1000, krwPerGB: 70 },
  { upToGB: 2000, krwPerGB: 60 },
  { upToGB: 3000, krwPerGB: 50 },
  { upToGB: 4000, krwPerGB: 40 },
  { upToGB: 0, krwPerGB: 30 },
];
/** 구간 이름: '1,000 GB까지' · '1,000–2,000 GB' · '4,000 GB 넘음' */
export function tierRange(tiers: VpsOverageTier[], i: number): string {
  const n = (gb: number) => gb.toLocaleString('ko-KR');
  const lo = i ? tiers[i - 1].upToGB : 0;
  const hi = tiers[i].upToGB;
  if (!hi) return `${n(lo)} GB 넘음`;
  return lo ? `${n(lo)}–${n(hi)} GB` : `${n(hi)} GB까지`;
}
/** 넘은 양이 들어가는 구간 */
export const tierIndex = (tiers: VpsOverageTier[], overGB: number) => {
  const i = tiers.findIndex((t) => !t.upToGB || overGB <= t.upToGB);
  return i < 0 ? tiers.length - 1 : i;
};

/** 조기 감시 기본값과 범위 (#701): 창 1–60분, 평균은 창의 2배 이상–1440분 */
export const GUARD_DEFAULT = { windowMin: 5, averageMin: 60 };
export function guardError(windowMin: number, averageMin: number): string | undefined {
  const w = windowMin || GUARD_DEFAULT.windowMin;
  const a = averageMin || GUARD_DEFAULT.averageMin;
  if (!Number.isInteger(windowMin) || windowMin < 0 || windowMin > 60) return '측정 창은 1–60분입니다';
  if (!Number.isInteger(averageMin) || averageMin < 0 || averageMin > 1440) return '누적 평균 기간은 1440분 이하입니다';
  if (a < 2 * w) return `누적 평균 기간은 측정 창의 2배(${2 * w}분) 이상이어야 합니다`;
  return undefined;
}
export const capStopReason = (c?: { reason?: string }) => (c?.reason === 'traffic-soon' ? '트래픽 초과 직전 (15분 전 감시)' : '상한 초과 예상');
export const mbpsText = (n: number | undefined) => (n === undefined ? '—' : `${n >= 100 ? Math.round(n) : Math.round(n * 10) / 10} Mbps`);
