// SPDX-License-Identifier: Apache-2.0

// MCP 연동 (W2.3a, UI-B9). 웹 데몬 몫이다(연결·봉인 토큰·도구 카탈로그). 토큰 값은 PUT·POST로 한 번 보내고 화면에 남기지 않는다.
// 계약: /mnt/project-files/w2/guides-mcp-webhooks-contract.md 'MCP 연동', 화면이 더 바라는 것은 mcp-web-needs.md.
import { api } from './client';
import type { Impact } from './incidents';

export type ToolKind = 'read' | 'change' | 'notify';
export type ToolIncident = 'off' | 'diagnose' | 'notify' | 'propose-approve' | 'propose-auto';
export type InputRule = { kind: 'max' | 'incident' | 'template' | 'fixed'; value?: string };
export interface ToolAuto {
  floor: Impact;
  inputs: Record<string, InputRule>;
  perIncident: number;
  perDay: number;
  revert: { tool?: string; irreversible?: boolean };
  signals?: string[];
}
export interface McpTool {
  name: string;
  title?: string;
  description: string;
  readOnlyHint: boolean;
  kind: ToolKind;
  coordinator: boolean;
  incident: ToolIncident;
  tenants: string[] | 'all';
  new: boolean;
  auto?: ToolAuto;
  hint?: string;
  args?: { name: string; type?: string; description?: string; required?: boolean }[];
}
export interface McpServer {
  name: string;
  url: string;
  /** oauth: 받은 토큰은 mydc-web 봉인 파일에. expiresAt은 접근 토큰 만료(갱신 토큰으로 알아서 늘린다) */
  auth: { kind: 'bearer' | 'none' | 'oauth'; set: boolean; last4?: string; expiresAt?: string; needsLogin?: boolean };
  state: 'ok' | 'error' | 'unchecked';
  error?: string;
  checkedAt?: string;
  catalogRevision: number;
  tools: McpTool[];
  users: { systemAdmins: boolean; tenants: string[] };
  revision: number;
  enabled?: boolean;
  usedBy?: string[];
  info?: { serverName: string; version?: string };
}
export type ToolPatch = Partial<Pick<McpTool, 'kind' | 'coordinator' | 'incident' | 'tenants' | 'auto' | 'hint'>>;

const enc = encodeURIComponent;
export const mcpServers = (signal?: AbortSignal) => api.get<{ servers: McpServer[] }>('/system/mcp', signal);
export const addMcp = (b: { name: string; url: string; auth: { kind: 'bearer' | 'none'; token?: string } }) => api.post<McpServer>('/system/mcp', b);
/** OAuth 연결: 저장 전 로그인 단계를 연다. 로그인 창(loginUrl)에서 돌아오면 웹 데몬이 토큰을 봉인하고 연결 시험까지 한다. */
export interface McpOauthStart {
  name: string;
  loginUrl: string;
  expiresAt: string;
}
export interface McpOauthState {
  state: 'login' | 'connected' | 'failed' | 'expired';
  error?: string;
  server?: McpServer;
}
export const startMcpOauth = (b: { name: string; url: string }) => api.post<McpOauthStart>('/system/mcp', { ...b, auth: { kind: 'oauth' } });
export const mcpOauthState = (name: string, signal?: AbortSignal) => api.get<McpOauthState>(`/system/mcp/${enc(name)}/oauth`, signal);
export const reloginMcp = (name: string) => api.post<McpOauthStart>(`/system/mcp/${enc(name)}/oauth/login`);
export const putMcp = (name: string, b: { revision: number; url?: string; auth?: { kind: 'bearer' | 'none'; token?: string }; users?: McpServer['users']; tools?: Record<string, ToolPatch>; enabled?: boolean }) => api.put<McpServer>(`/system/mcp/${enc(name)}`, b);
export const refreshMcp = (name: string) => api.post<McpServer>(`/system/mcp/${enc(name)}/refresh`);
export const deleteMcp = (name: string, confirmName: string) => api.del<void>(`/system/mcp/${enc(name)}`, { confirmName });
export const testMcpTool = (name: string, tool: string, incident: string) => api.post<{ steps: { label: string; detail?: string }[]; result: string }>(`/system/mcp/${enc(name)}/tools/${enc(tool)}/test`, { incident });

export const MCP_NAME_RE = /^[a-z][a-z0-9-]{0,30}$/;
export const KIND_NAME: Record<ToolKind, string> = { read: '읽기', change: '바꾸기', notify: '알림' };
export const USE_NAME: Record<ToolIncident, string> = { off: '안 씀', diagnose: '진단에 바로 씀', notify: '알림에 씀', 'propose-approve': '조치 후보 · 항상 승인', 'propose-auto': '조치 후보 · 낮은 영향이면 자동' };
export const USE_NOTE: Record<ToolIncident, string> = {
  off: '장애 대응은 이 도구를 모름',
  diagnose: '읽기 도구만 고를 수 있음',
  notify: '사건 알림을 보낼 때 바로 호출, 내용은 사건 요약 틀',
  'propose-approve': '승인 카드로만 실행',
  'propose-auto': '앱 정책이 “낮은 영향 자동”이고 영향 평가가 낮음일 때만',
};
/** kind incident일 때 value: 사건의 어느 칸으로 채울지 (데몬 #162) */
export const INCIDENT_FIELDS: [string, string, string][] = [
  ['id', '사건 ID', 'inc-0412'],
  ['tenant', '작업 공간', 'shop'],
  ['app', '앱', 'php-shop'],
  ['node', '서버', 'node-b'],
  ['target', '대상', 'php-shop-worker-1'],
  ['signal', '신호', '재시작 반복'],
  ['title', '제목', '…'],
];
export const RULE_NAME: Record<InputRule['kind'], string> = { max: '최대값', incident: '사건에서 채움', template: '틀', fixed: '고정' };
/** propose-auto 저장 전에 빠진 칸 (데몬 422 auto-incomplete와 같은 규칙) */
export function autoMissing(t: McpTool, a?: ToolAuto): string[] {
  if (!a) return ['영향 등급 하한', '입력 제한', '한도', '되돌리기'];
  const out: string[] = [];
  if (!a.floor) out.push('영향 등급 하한');
  const args = t.args?.map((x) => x.name) ?? Object.keys(a.inputs);
  if (!args.length || args.some((n) => !a.inputs[n])) out.push('입력 제한');
  if (!(a.perIncident >= 1) || !(a.perDay >= 1)) out.push('한도');
  if (!a.revert.tool && !a.revert.irreversible) out.push('되돌리기');
  if (a.revert.irreversible && a.floor === 'low') out.push('되돌릴 수 없으면 하한 보통 이상');
  return out;
}
