// SPDX-License-Identifier: Apache-2.0

// 장애 자동 대응 (W2.3, UI-B3~B8). 웹 데몬 몫이다(진단·영향 평가·정책·사건 기록). 실행하는 동작(restart-task, cordon-node 등)은 sfcd 것이다.
// 데몬 계약 초안 전이라 화면이 기대하는 모양(/mnt/project-files/w2/incident-web-needs.md)으로 목업을 둔다.
import { api, q } from './client';
import type { DOp } from './dto';

export type Level = 'off' | 'suggest' | 'auto-low';
export type Impact = 'low' | 'medium' | 'high';
export type DecisionKind = 'auto' | 'pending' | 'approved' | 'rejected' | 'expired' | 'none' | 'stopped';
export interface IncidentRow {
  id: string;
  scope: 'app' | 'cluster';
  tenant?: string;
  app?: string;
  node?: string;
  signal: string;
  mitigation: string;
  impact: Impact;
  decision: { kind: DecisionKind; by?: string; expiresAt?: string; note?: string };
  state: 'open' | 'mitigating' | 'recovered' | 'closed';
  at: string;
  fallback?: boolean;
}
export interface TimelineItem {
  at: string;
  kind: 'detect' | 'diagnose' | 'assess' | 'auto' | 'approve' | 'reject' | 'recover' | 'propose' | 'expire' | 'notify' | 'webhook';
  text: string;
  /** kind webhook: 판단 웹훅의 답 */
  webhook?: string;
  status?: number;
  accepted?: boolean;
  reason?: string;
  op?: string;
  signer?: string;
  model?: string;
  inputs?: string[];
  candidates?: { action: string; note: string }[];
  extra?: Record<string, string>;
  conversation?: boolean;
}
export interface Incident extends IncidentRow {
  title: string;
  rule?: string;
  target?: string;
  candidates?: { action: string; label: string; note?: string }[];
  op?: string;
  timeline: TimelineItem[];
  assessment?: {
    provider: string;
    model?: string;
    sameProvider?: boolean;
    facts: { label: string; value: string }[];
    level: Impact;
    reversible: boolean;
    blast: number;
    dataRisk: 'none' | 'low' | 'high';
    confidence: number;
    reasons?: string[];
    fallback?: boolean;
    floor: { level: Impact; reason: string };
    final: Impact;
    policy: string;
  };
  approval?: { title: string; fields: { label: string; value: string }[]; expiresAt: string; basisHash: string; action?: string; target?: string };
  revision?: number;
  /** 이 사건이 쓴 지침 버전. app.current는 지금 버전 */
  guides?: { cluster?: { version: number }; tenant?: { version: number }; app?: { version: number; current?: number } };
  mcpCalls?: Record<string, number>;
}
export interface Watcher {
  state: 'running' | 'stopped' | 'no-automation' | 'login-failed' | 'cursor-expired';
  at?: string;
  error?: string;
}
export interface IncidentList {
  items: IncidentRow[];
  cursor?: string;
  total: number;
  pending: number;
  /** 클러스터 수준(멈춤이면 off). 시스템 관리자가 아니면 null */
  level?: Level | null;
  stopped?: boolean;
  watcher?: Watcher;
}
export interface MitigationAction {
  id: string;
  scope: 'app' | 'cluster';
  label: string;
  floor: Impact;
  /** 관리자가 고른 값. 하한이 '보통' 이상이면 allow로 올릴 수 없다(422 floor) */
  auto: 'allow' | 'approval' | 'human';
}
export interface CdRollback {
  enabled: boolean;
  windowMinutes: number;
  alwaysApprove: boolean;
}
export interface AppPolicyRow {
  tenant: string;
  app: string;
  level: Level;
  ratePerHour: number;
  quiet: string[];
  cdRollback: CdRollback;
}
export type Decider = 'ai' | 'webhook' | 'rules';
export interface DecideSkip {
  ai?: 'no-key' | 'role-off' | 'excluded';
  webhook?: 'none-linked' | 'disabled';
}
export const DECIDE_NAME: Record<Decider, string> = { ai: 'AI 진단', webhook: '웹훅 판단기', rules: '규칙만' };
const SKIP_NAME: Record<string, string> = { 'no-key': 'AI 키 없음', 'role-off': '진단 역할 꺼짐', excluded: '이 작업 공간은 AI에서 뺌', 'none-linked': '연결된 판단 웹훅 없음', disabled: '판단 웹훅 꺼짐' };
/** 판단 순서 한 줄: AI 진단 → 안 되면 웹훅 판단기 → 규칙만 */
export const decideChain = (d: Decider[]) => d.map((x, i) => (i === 0 ? DECIDE_NAME[x] : i === 1 ? ` → 안 되면 ${DECIDE_NAME[x]}` : ` → ${DECIDE_NAME[x]}`)).join('');
/** 지금 판단할 곳과 건너뛰는 이유 */
export const decideNowText = (now?: Decider, skip?: DecideSkip) => {
  if (!now) return '';
  const why = [skip?.ai && `AI: ${SKIP_NAME[skip.ai]}`, skip?.webhook && `웹훅: ${SKIP_NAME[skip.webhook]}`].filter(Boolean).join(' · ');
  return `지금은 ${DECIDE_NAME[now]}${why ? ` (${why})` : ''}`;
};
/** 클러스터 사건의 승인 요청 받는 사람: 시스템 관리자 · 시스템 관리자와 그 앱의 작업 공간 관리자 */
export type ApproverTo = 'system-admins' | 'system-and-tenant-admins';
export interface Policy {
  level: Level;
  stopped: boolean;
  ratePerHour: number;
  approvers: { label: string; deadlineMinutes: number; banner: boolean; to?: ApproverTo };
  /** 고를 수 있는 받는 사람. 없으면 바꿀 수 없다. */
  approverOptions?: { to: ApproverTo; label: string }[];
  quiet: string[];
  decide: Decider[];
  /** 지금 사건이 나면 판단할 곳 */
  decideNow?: Decider;
  decideSkip?: DecideSkip;
  newAppDefault: Level;
  actions: MitigationAction[];
  apps: AppPolicyRow[];
  models?: { diagnosis?: string; impact?: string };
  automation?: { configured: boolean; username?: string };
  revision: number;
}
export interface AppIncidentConf {
  level: Level;
  ratePerHour: number;
  quiet: string[];
  approvers?: string;
  /** 예전 데몬은 문장, 지금은 순서 배열 */
  decide?: string | Decider[];
  decideNow?: Decider;
  decideSkip?: DecideSkip;
  cdRollback: CdRollback;
  actions: Record<string, boolean>;
  /** 클러스터가 허용한 앱 임시 조치(읽기 전용). 작업 공간 관리자는 클러스터 정책을 못 읽어서 함께 준다 */
  available: MitigationAction[];
  /** 클러스터 수준(멈춤이면 off) */
  clusterLevel: Level;
  /** 볼 수 있는 지침 요약 */
  guides?: Partial<Record<'cluster' | 'tenant' | 'app', { version: number; summary: string }>>;
  revision: number;
}
export interface AppVersionMark {
  version: number;
  summary: string;
  by: string;
  cd: boolean;
  at: string;
  migration: boolean;
  auto?: string;
}

const enc = encodeURIComponent;
export const incidents = (p: { scope?: string; decision?: string; q?: string; cursor?: string; limit?: number; tenant?: string; app?: string }, signal?: AbortSignal) => api.get<IncidentList>(`/incidents${q(p)}`, signal);
export const incident = (id: string, signal?: AbortSignal) => api.get<Incident>(`/incidents/${enc(id)}`, signal);
export const incidentPath = (id: string) => `/incidents/${enc(id)}`;
export type RejectReason = 'handled-by-person' | 'wrong-action' | 'not-now' | 'other';
export const REJECT_NAME: Record<RejectReason, string> = { 'handled-by-person': '사람이 직접 처리함', 'wrong-action': '조치가 맞지 않음', 'not-now': '지금은 실행하면 안 됨', other: '기타' };
export const rejectIncident = (id: string, reason: RejectReason, note?: string) => api.post<void>(`/incidents/${enc(id)}/reject`, { reason, ...(note ? { note } : {}) });
export const deleteIncident = (id: string, confirmName: string) => api.del<void>(`/incidents/${enc(id)}`, { confirmName });
export const approveIncidentPath = (id: string) => `/incidents/${enc(id)}/approve`;
export type { DOp };

export const policy = (signal?: AbortSignal) => api.get<Policy>('/incidents/policy', signal);
export const putPolicy = (b: Pick<Policy, 'revision' | 'level' | 'ratePerHour' | 'approvers' | 'quiet' | 'newAppDefault'> & { actions?: Record<string, MitigationAction['auto']> }) => api.put<Policy>('/incidents/policy', b);
export const stopAll = () => api.post<Policy>('/incidents/stop');
export const resumeAll = () => api.post<Policy>('/incidents/resume');

export const appIncident = (t: string, a: string, signal?: AbortSignal) => api.get<AppIncidentConf>(`/t/${enc(t)}/apps/${enc(a)}/incident`, signal);
export const putAppIncident = (t: string, a: string, b: Omit<AppIncidentConf, 'approvers' | 'decide' | 'available' | 'clusterLevel' | 'guides'>) => api.put<AppIncidentConf>(`/t/${enc(t)}/apps/${enc(a)}/incident`, b);
export const appVersionMarks = (t: string, a: string, signal?: AbortSignal) => api.get<{ items: AppVersionMark[] }>(`/t/${enc(t)}/apps/${enc(a)}/incident/versions`, signal);
export const putVersionMark = (t: string, a: string, v: number, migration: boolean) => api.put<AppVersionMark>(`/t/${enc(t)}/apps/${enc(a)}/incident/versions/${v}`, { migration });

export const LEVEL_NAME: Record<Level, string> = { off: '끔', suggest: '제안만', 'auto-low': '낮은 영향 자동' };
export const IMPACT_NAME: Record<Impact, string> = { low: '낮음', medium: '보통', high: '높음' };
export const IMPACT_TONE: Record<Impact, 'ok' | 'wa' | 'er'> = { low: 'ok', medium: 'wa', high: 'er' };
