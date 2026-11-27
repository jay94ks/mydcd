// SPDX-License-Identifier: Apache-2.0

// AI (W2). 웹 데몬 몫이다(키 봉인·공급자 호출·대화 기록). 계약 초안은 /mnt/project-files/w2/ai-contract.md(데몬 스레드),
// 병합되면 docs/reference/web-api.md의 'AI' 절. 키 값은 PUT 한 번에만 보내고, 화면·저장소 어디에도 남기지 않는다.
import { api, ApiError, apiEvents } from './client';
import { sseParser } from './streams';
import type { ApiErrorBody } from './types';
import type { DOp } from './dto';

export type AiProvider = 'claude' | 'openai';
export type AiRole = 'coordinator' | 'diagnosis' | 'impact' | 'simple';
export const AI_ROLES: AiRole[] = ['coordinator', 'diagnosis', 'impact', 'simple'];
export const AI_PROVIDERS: AiProvider[] = ['claude', 'openai'];

export interface AiProviderRow {
  provider: AiProvider;
  configured: boolean;
  last4?: string;
  setBy?: string;
  setAt?: string;
  catalogAt?: string;
  models: number;
  modelsTotal?: number;
  error?: string;
}
export interface AiModelRef {
  provider: AiProvider;
  model: string;
}
export interface AiRoleConf {
  main: AiModelRef | null;
  fallback: AiModelRef | null;
  mainMissing?: boolean;
  fallbackMissing?: boolean;
  sameProvider?: boolean;
  effort?: 'low' | 'medium' | 'high';
  thinking?: 'auto' | 'off';
  maxOutputTokens?: number;
  stream?: boolean;
}
export interface AiData {
  maskSecretLikeEnv: boolean;
  logTailLines: number;
  excludeTenants: string[];
}
export interface AiLimits {
  dailyTokensPerUser: number;
  toolCallsPerConversation: number;
  tokensPerConversation: number;
  compaction: { enabled: boolean; triggerTokens: number };
}
export interface AiSettings {
  sealReady: boolean;
  revision: number;
  providers: AiProviderRow[];
  roles: Record<AiRole, AiRoleConf>;
  data?: AiData;
  limits: AiLimits;
}
export interface AiModel {
  id: string;
  displayName?: string;
  createdAt: string;
  hidden: boolean;
}
export interface AiUsageRow {
  day: string;
  role: AiRole;
  provider: AiProvider;
  model: string;
  fallback: boolean;
  requests: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}
export interface AiUsage {
  items: AiUsageRow[];
  roles: Partial<Record<AiRole, { hitRate: number }>>;
}
export interface AiAuditRow {
  at: string;
  user?: string;
  kind: string;
  provider?: AiProvider;
  model?: string;
  fallback?: boolean;
  reason?: string;
  tokens?: number;
  cacheRead?: number;
  proposal?: string;
  decision?: string;
}

const enc = encodeURIComponent;
export const aiSettings = (signal?: AbortSignal) => api.get<AiSettings>('/system/ai', signal);
export const putAiKey = (p: AiProvider, key: string) => api.put<AiProviderRow>(`/system/ai/keys/${p}`, { key });
export const deleteAiKey = (p: AiProvider) => api.del<void>(`/system/ai/keys/${p}`);
export const refreshAiModels = (p: AiProvider) => api.post<AiProviderRow>(`/system/ai/models/${p}/refresh`);
export const aiModels = (p: AiProvider, all = false, signal?: AbortSignal) => api.get<{ provider: AiProvider; fetchedAt?: string; items: AiModel[] }>(`/system/ai/models/${p}${all ? '?all=1' : ''}`, signal);
export const putAiSettings = (body: { revision: number; roles: Record<AiRole, AiRoleConf>; data?: AiData; limits: AiLimits }) => api.put<AiSettings>('/system/ai/settings', body);
export const aiUsage = (days = 7, signal?: AbortSignal) => api.get<AiUsage>(`/system/ai/usage?days=${days}`, signal);
export const aiAudit = (limit = 50, cursor?: string, signal?: AbortSignal) => api.get<{ items: AiAuditRow[]; cursor?: string; total?: number }>(`/system/ai/audit?limit=${limit}${cursor ? `&cursor=${enc(cursor)}` : ''}`, signal);
export const deleteAiAudit = (before: string) => api.del<{ deleted: number }>('/system/ai/audit', { before });

// ── 코디네이터 (UI-B0·B1·B2) ──
export interface AiConversation {
  id: string;
  title: string;
  model?: string;
  tenant?: string;
  createdAt: string;
  updatedAt: string;
  pendingProposals: number;
  /** 장애 대응 사건에서 연 대화면 그 사건 ID (휴대폰 대화 목록의 '장애 대응' 칩). 데몬이 아직 주지 않을 수 있다 */
  incident?: string;
}
export interface AiTool {
  name: string;
  kind: 'find' | 'read' | 'propose';
  summary: string;
  /** 호출 인자. 데몬이 비밀값처럼 보이는 값은 «가림»으로, 200자 넘는 값은 잘라서 준다. 없을 수 있다 */
  args?: Record<string, string>;
}
export interface AiMessage {
  id: string;
  role: 'user' | 'assistant' | 'summary' | 'notice';
  text: string;
  at: string;
  model?: string;
  fallback?: boolean;
  tools?: AiTool[];
  proposals?: string[];
}
/** 대화에 붙은 맥락 칩. 예: {kind:'incident', id}, {kind:'app', tenant, app} */
export type AiChip = { kind: string } & Record<string, string>;
export const chipLabel = (c: AiChip) => (c.kind === 'incident' ? `사건 ${c.id}` : c.kind === 'app' ? `앱 ${c.app}` : c.kind === 'node' ? `서버 ${c.id ?? c.node}` : `${c.kind} ${Object.entries(c).filter(([k]) => k !== 'kind').map(([, v]) => v).join(' ')}`);
export interface AiConversationFull extends Omit<AiConversation, 'pendingProposals' | 'createdAt' | 'updatedAt'> {
  createdAt?: string;
  updatedAt?: string;
  chips?: AiChip[];
  messages: AiMessage[];
}
export type AiImpact = 'low' | 'medium' | 'high';
export interface AiProposal {
  id: string;
  conversation: string;
  title: string;
  index: number;
  total: number;
  after?: string;
  tool: string;
  action: string;
  tenant?: string;
  target: string;
  payload: Record<string, unknown>;
  preview: { label: string; value: string }[];
  items?: { name: string; size?: number; lastUsed?: string }[];
  diff?: string;
  impact: AiImpact;
  revert: string;
  irreversible: boolean;
  confirmName?: string;
  expected?: number;
  basisHash: string;
  expiresAt: string;
  edited: boolean;
  state: 'pending' | 'approved' | 'rejected' | 'expired' | 'invalid';
  decidedBy?: string;
  decidedAt?: string;
  op?: string;
  reason?: string;
  /** MCP 도구 호출 제안 (tool mcp.{server}.{tool}, action mcp-call). 승인하면 op 대신 {mcp:{ok, server, tool, error?}}가 온다. 다시 읽은 view에는 ok가 없고 실패면 reason이 있다 */
  mcp?: { server: string; tool: string; ok?: boolean; error?: string };
}
export interface AiContext {
  screen: string;
  path: string;
  selection?: Record<string, string>;
}
export type AiStreamEvent =
  | { type: 'delta'; text: string }
  | { type: 'tool'; tool: AiTool }
  | { type: 'proposal'; proposal: AiProposal }
  | { type: 'done'; messageId: string; usage?: Record<string, number> }
  | { type: 'error'; code: string; message: string };

export const conversations = (signal?: AbortSignal) => api.get<{ items: AiConversation[] }>('/ai/conversations', signal);
export const newConversation = (o: { title?: string; incident?: string; chips?: AiChip[] } = {}) => api.post<AiConversation>('/ai/conversations', o);
export const setConversationChips = (id: string, chips: AiChip[] | null) => api.patch<void>(`/ai/conversations/${enc(id)}`, { chips });
export const conversation = (id: string, signal?: AbortSignal) => api.get<AiConversationFull>(`/ai/conversations/${enc(id)}`, signal);
export const renameConversation = (id: string, title: string) => api.patch<void>(`/ai/conversations/${enc(id)}`, { title });
export const deleteConversation = (id: string) => api.del<void>(`/ai/conversations/${enc(id)}`);
export const deleteAllConversations = () => api.del<void>('/ai/conversations');
export const exportConversationUrl = (id: string, format: 'md' | 'json' = 'md') => `/ai/conversations/${enc(id)}/export?format=${format}`;
export const stopConversation = (id: string) => api.post<void>(`/ai/conversations/${enc(id)}/stop`);
export const proposal = (id: string, signal?: AbortSignal) => api.get<AiProposal>(`/ai/proposals/${enc(id)}`, signal);
export const approveProposal = (id: string, body: { opId: string; basisHash: string; confirmName?: string }) => api.post<{ op: DOp }>(`/ai/proposals/${enc(id)}/approve`, body);
export const rejectProposal = (id: string, reason: string) => api.post<void>(`/ai/proposals/${enc(id)}/reject`, { reason });
export const editProposal = (id: string, payload: Record<string, unknown>) => api.put<AiProposal>(`/ai/proposals/${enc(id)}`, { payload });
export const messagesPath = (id: string) => `/ai/conversations/${enc(id)}/messages`;

/** 메시지 하나를 보내고 답을 흘려 받는다(text/event-stream). 끝나면 resolve, 오류면 ApiError */
export async function sendMessage(id: string, body: { text: string; context: AiContext }, onEvent: (e: AiStreamEvent) => void, signal: AbortSignal): Promise<void> {
  // import.meta.env로 직접 분기해야 운영 빌드에서 목업 묶음이 빠진다
  if (import.meta.env.VITE_API !== 'real') return (await import('./mock/ai')).mockChat(id, body, onEvent, signal);
  let res: Response;
  try {
    res = await fetch('/api/v1' + messagesPath(id), { method: 'POST', headers: { Accept: 'text/event-stream', 'Content-Type': 'application/json', 'X-SFC-Web': '1' }, body: JSON.stringify(body), credentials: 'same-origin', signal, cache: 'no-store' });
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e;
    throw new ApiError(0, { code: 'transport', message: '웹 서버에 연결하지 못했습니다.' });
  }
  if (!res.ok || !res.body) {
    let b: ApiErrorBody = { code: 'transport', message: `HTTP ${res.status}` };
    try {
      b = ((await res.json()) as { error?: ApiErrorBody }).error ?? b;
    } catch {
      /* 본문 없음 */
    }
    if (res.status === 401 && b.code === 'session-expired') apiEvents.dispatchEvent(new Event('session-expired'));
    throw new ApiError(res.status, b);
  }
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  const parse = sseParser();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    for (const m of parse(value)) {
      let d: Record<string, unknown>;
      try {
        d = JSON.parse(m.data) as Record<string, unknown>;
      } catch {
        continue;
      }
      if (m.event === 'delta') onEvent({ type: 'delta', text: String(d.text ?? '') });
      else if (m.event === 'tool') onEvent({ type: 'tool', tool: d as unknown as AiTool });
      else if (m.event === 'proposal') onEvent({ type: 'proposal', proposal: d as unknown as AiProposal });
      else if (m.event === 'done') onEvent({ type: 'done', messageId: String(d.messageId ?? ''), usage: d.usage as Record<string, number> | undefined });
      else if (m.event === 'error') onEvent({ type: 'error', code: String(d.code ?? 'error'), message: String(d.message ?? '') });
    }
  }
}
