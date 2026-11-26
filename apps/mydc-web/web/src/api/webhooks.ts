// SPDX-License-Identifier: Apache-2.0

// 웹훅 (W2.3b, UI-BB·44). 등록·서명·전송 기록은 웹 데몬 몫이다. 클러스터 내부 웹훅은 데몬이 mydcd 서비스 호출(REQ-24, POST /t/{t}/apps/{app}/call)로 보낸다.
// 계약: /mnt/project-files/w2/guides-mcp-webhooks-contract.md '웹훅', 화면이 더 바라는 것은 webhooks-web-needs.md.
// 서명 비밀·헤더 토큰은 만들 때 한 번만 받거나 보내고 화면 상태에 남기지 않는다.
import { api, q } from './client';

export type HookKind = 'external' | 'internal';
export type HookRole = 'notify' | 'decide';
export type HookFormat = 'mydc' | 'slack' | 'teams' | 'pagerduty';
export type HookSign = 'hmac' | 'token' | 'none';
export type LinkPoint = 'incident' | 'cd' | 'ingress';
export interface HookTarget {
  app: string;
  service: string;
  port: number;
  path: string;
  scheme?: 'http' | 'https';
  /** https일 때 작업 공간 CA가 믿지 않는 인증서도 받기 */
  insecureSkipVerify?: boolean;
}
export interface Webhook {
  name: string;
  tenant?: string;
  kind: HookKind;
  url?: string;
  target?: HookTarget;
  role: HookRole;
  format: HookFormat;
  sign?: HookSign;
  token?: { set: boolean; last4?: string };
  secret: { set: boolean; rotatingUntil?: string };
  state: 'ok' | 'failing' | 'disabled';
  enabled?: boolean;
  disabledReason?: 'failures' | 'manual';
  error?: string;
  lastDelivery?: { at: string; status: number; ms: number; retry?: { attempt: number; of: number } };
  stats?: { today: number; failed: number; avgMs: number };
  revision: number;
}
export interface Delivery {
  id: string;
  at: string;
  point: LinkPoint | 'test';
  event: string;
  status: number;
  ms: number;
  error?: string;
  retries?: number;
  firstStatus?: number;
  steps?: { label: string; detail?: string }[];
}
export interface WebhookLink {
  id: string;
  point: LinkPoint;
  scope: { tenant?: string; app?: string; gateway?: string; /** 외부 접속 경로 규칙 id */ route?: string };
  /** 외부 접속 경로 규칙 웹훅의 조건 (예: 5xx 2% 넘게 1분) */
  condition?: string;
  events: string[];
  webhook: string;
  role: HookRole;
  revision: number;
  /** 화면 표시용 짧은 글 (예: "모든 앱 (보통 이상)") */
  label?: string;
  // point=cd (cd-webhooks-contract.md)
  kind?: CdHookKind;
  waitSeconds?: number;
  onTimeout?: 'hold' | 'pass' | 'reject' | 'fail';
  when?: 'synced' | 'healthy';
  onFail?: 'pause' | 'pause-rollback';
  openIncident?: boolean;
  approver?: { account: string; scope: string; state: 'ok' | 'missing' | 'denied' };
  /** 이 연결의 마지막 전송 (계약에 아직 없음, 없으면 웹훅의 lastDelivery를 쓴다) */
  last?: { at: string; status?: number; error?: string; ms?: number; commit?: string; answer?: string };
}
export type CdHookKind = 'pre-sync' | 'post-sync' | 'notify';
/** GET …/cd의 webhook (배포 전 확인 상태) */
/** GET …/cd의 webhook·checks (cd-webhooks-contract.md '공통') */
export interface CdGate {
  kind?: 'pre-sync' | 'post-sync';
  link: string;
  webhook?: string;
  /** pre-sync: checking|held|passed|rejected|timeout|failed · post-sync: checking|ok|failed|timeout */
  state: 'checking' | 'held' | 'passed' | 'rejected' | 'timeout' | 'failed' | 'ok';
  at: string;
  candidate?: string;
  reason?: string;
  status?: number;
  /** post-sync 실패 뒤 */
  actions?: { kind: 'pause' | 'rollback-request'; state: 'done' | 'failed'; code?: string; incident?: string }[];
}
export type CdLinkInput = { webhook: string; kind: CdHookKind; waitSeconds?: number; onTimeout?: WebhookLink['onTimeout']; when?: WebhookLink['when']; onFail?: WebhookLink['onFail']; openIncident?: boolean; events?: string[] };
export type NewWebhook = { name: string; tenant?: string; kind: HookKind; url?: string; target?: HookTarget; role: HookRole; format: HookFormat; sign?: HookSign; token?: string };

const enc = encodeURIComponent;
export const webhooks = (tenant?: string, signal?: AbortSignal) => api.get<{ items: Webhook[] }>(`/webhooks${q({ tenant })}`, signal);
/** 응답의 secret은 이때 한 번만 값이 온다(문자열 또는 {value}) */
export const createWebhook = (b: NewWebhook) => api.post<Omit<Webhook, 'secret'> & { secret?: string | (Webhook['secret'] & { value?: string }) }>('/webhooks', b);
export const secretValue = (s: unknown): string | undefined => (typeof s === 'string' ? s : s && typeof s === 'object' && typeof (s as { value?: unknown }).value === 'string' ? (s as { value: string }).value : undefined);
export const putWebhook = (name: string, b: Partial<NewWebhook> & { revision: number; enabled?: boolean }) => api.put<Webhook>(`/webhooks/${enc(name)}`, b);
export const deleteWebhook = (name: string, confirmName: string) => api.del<void>(`/webhooks/${enc(name)}`, { confirmName });
/** 응답 secret은 {set, value, rotatingUntil}(데몬) 또는 문자열. 값만 꺼내 돌려준다 */
export const rotateWebhook = async (name: string) => {
  const r = await api.post<{ secret: unknown }>(`/webhooks/${enc(name)}/rotate`);
  return { secret: secretValue(r.secret) ?? '' };
};
/** 데몬은 {delivery, steps}, 옛 목업은 Delivery 하나. 화면은 steps를 붙인 Delivery로 본다 */
export const testWebhook = async (name: string): Promise<Delivery> => {
  const r = await api.post<Delivery | { delivery: Delivery; steps?: Delivery['steps'] }>(`/webhooks/${enc(name)}/test`);
  return 'delivery' in r ? { ...r.delivery, status: r.delivery.status ?? 0, steps: r.steps ?? r.delivery.steps } : r;
};
export const deliveries = (name: string, cursor?: string, signal?: AbortSignal) => api.get<{ items: Delivery[]; cursor?: string }>(`/webhooks/${enc(name)}/deliveries${q({ cursor })}`, signal);
export const webhookLinks = (p: { point?: LinkPoint; tenant?: string; app?: string } = {}, signal?: AbortSignal) => api.get<{ items: WebhookLink[] }>(`/webhook-links${q(p)}`, signal);

export const createCdLink = (tenant: string, app: string, b: CdLinkInput) => api.post<WebhookLink>('/webhook-links', { point: 'cd', scope: { tenant, app }, ...b });
/** 지점 연결 (외부 접속 게이트웨이·경로 등). 자동 배포는 createCdLink */
// point=ingress: 조건은 threshold(error-rate는 5xx %, latency는 p95 ms)·minutes(0~60)로 보내고, 목록의 condition은 웹 데몬이 만든다.
export const createLink = (b: { point: LinkPoint; scope: WebhookLink['scope']; events: string[]; webhook: string; threshold?: number; minutes?: number; recover?: boolean; group?: boolean }) => api.post<WebhookLink>('/webhook-links', b);
export const putLink = (id: string, b: Partial<CdLinkInput> & { revision: number }) => api.put<WebhookLink>(`/webhook-links/${enc(id)}`, b);
export const deleteLink = (id: string) => api.del<void>(`/webhook-links/${enc(id)}`);

export const CD_EVENTS: [string, string][] = [
  ['candidate-created', '후보 생김'],
  ['approval-required', '승인 대기'],
  ['approved', '승인됨'],
  ['rejected', '반려됨'],
  ['sync-started', '동기화 시작'],
  ['sync-succeeded', '성공'],
  ['sync-failed', '실패'],
  ['drift-detected', 'Git과 다름'],
  ['paused', '일시정지'],
  ['resumed', '다시 시작'],
  ['rolled-back', '되돌림'],
];
export const CD_KIND_NAME: Record<CdHookKind, string> = { 'pre-sync': '배포 전 확인', 'post-sync': '배포 후 확인', notify: '알림' };
export const HOOK_NAME_RE = /^[a-z][a-z0-9-]{0,30}$/;
export const ROLE_NAME: Record<HookRole, string> = { notify: '알림', decide: '판단' };
export const FORMAT_NAME: Record<HookFormat, string> = { mydc: 'MyDC 기본 JSON', slack: 'Slack', teams: 'Teams', pagerduty: 'PagerDuty Events v2' };
export const SIGN_NAME: Record<HookSign, string> = { hmac: 'HMAC', token: '헤더 토큰', none: '없음 (주소가 비밀)' };
export const POINT_NAME: Record<LinkPoint | 'test', string> = { incident: '장애 대응', cd: '자동 배포', ingress: '외부 접속', test: '시험' };
export const targetText = (w: Webhook) => (w.kind === 'internal' && w.target ? `${w.tenant ?? ''} / ${w.target.app} / ${w.target.service} :${w.target.port} ${w.target.path}` : (w.url ?? '—'));
/** 사설·루프백·링크 로컬 주소: 외부 호출로는 막고 '클러스터 내부'를 안내한다 */
export const privateHost = (u: string) => /^https?:\/\/(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?|\[?f[cd])/i.test(u);
/** 클러스터 내부 호출 실패 code는 그대로 보이고 뜻을 붙인다 */
const CALL_ERR: Record<string, string> = {
  SERVICE_NO_READY_TASK: '상태 검사를 통과한 컨테이너 없음',
  SERVICE_CALL_TIMEOUT: '시간 초과',
  SERVICE_CALL_REFUSED: '연결 거부',
  SERVICE_CALL_TOO_LARGE: '본문·응답이 너무 큼',
  RATE_LIMITED: '호출 한도 초과',
  SERVICE_CALL_TLS: 'TLS 연결 실패',
};
export const callError = (e: string) => (CALL_ERR[e] ? `${e} (${CALL_ERR[e]})` : e);
