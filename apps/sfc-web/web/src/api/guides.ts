// SPDX-License-Identifier: Apache-2.0

// 행동 지침 (W2.3a, UI-BA). 웹 데몬 몫이다(지침 글·버전은 웹 bbolt, AI에 넘기는 것도 웹).
// 계약: /mnt/project-files/w2/guides-mcp-webhooks-contract.md '행동 지침', 화면이 더 바라는 것은 guides-web-needs.md.
import { api } from './client';
import type { Impact } from './incidents';

export type GuideScope = { kind: 'cluster' } | { kind: 'tenant'; tenant: string } | { kind: 'app'; tenant: string; app: string };
const enc = encodeURIComponent;
/** 경로 조각이자 지울 때 confirmName (예: app/shop/php-shop) */
export const scopeKey = (s: GuideScope) => (s.kind === 'cluster' ? 'cluster' : s.kind === 'tenant' ? `tenant/${s.tenant}` : `app/${s.tenant}/${s.app}`);
const base = (s: GuideScope) => (s.kind === 'cluster' ? '/guides/cluster' : s.kind === 'tenant' ? `/guides/tenant/${enc(s.tenant)}` : `/guides/app/${enc(s.tenant)}/${enc(s.app)}`);

export interface GuideFields {
  prefer: string[];
  avoid: { actions: string[]; services: string[] };
  mcpServers: string[];
  notify: string[];
  critical: string[];
}
export const emptyFields = (): GuideFields => ({ prefer: [], avoid: { actions: [], services: [] }, mcpServers: [], notify: [], critical: [] });
export interface GuideChoices {
  actions: { id: string; label: string; blockedBy?: 'cluster' | 'tenant' }[];
  services?: string[];
  /** summary: "도구 N개 (읽기 a · 바꾸기 b)" · 잠시 끈 서버는 state off */
  mcpServers?: { name: string; summary?: string; state: 'ok' | 'error' | 'unchecked' | 'off' }[];
}
export interface Guide {
  scope: 'cluster' | 'tenant' | 'app';
  tenant?: string;
  app?: string;
  version: number;
  revision: number;
  text: string;
  fields: GuideFields;
  updatedBy?: string;
  updatedAt?: string;
  warnings: { line: number; text: string }[];
  /** 넘길 곳. 데몬이 주면 PUT에도 싣는다 */
  deliver?: { diagnose: boolean; coordinator: boolean };
  choices?: GuideChoices;
}
export interface GuideSummary {
  scope: 'cluster' | 'tenant' | 'app';
  tenant?: string;
  app?: string;
  version: number;
  updatedBy?: string;
  updatedAt?: string;
  summary: string;
  lines?: number;
}
export interface GuideVersion {
  version: number;
  updatedBy: string;
  updatedAt: string;
  summary: string;
  incidents?: number;
  current?: boolean;
}
export interface GuideTestRun {
  hypothesis: string;
  candidates: { action: string; label?: string; impact?: Impact }[];
  mcpCalls?: Record<string, number>;
  tokens?: { total: number; cachedRatio?: number };
}

export const guides = (signal?: AbortSignal) => api.get<{ items: GuideSummary[] }>('/guides', signal);
export const guide = (s: GuideScope, signal?: AbortSignal) => api.get<Guide>(base(s), signal);
export const putGuide = (s: GuideScope, b: { revision: number; text: string; fields: GuideFields; deliver?: Guide['deliver'] }) => api.put<Guide>(base(s), b);
export const guideVersions = (s: GuideScope, signal?: AbortSignal) => api.get<{ items: GuideVersion[] }>(`${base(s)}/versions`, signal);
export const restoreGuide = (s: GuideScope, revision: number, version: number) => api.post<Guide>(`${base(s)}/restore`, { revision, version });
export const testGuide = (s: GuideScope, b: { incident: string; text?: string; fields?: GuideFields }) => api.post<{ current: GuideTestRun; draft?: GuideTestRun }>(`${base(s)}/test`, b);
export const GUIDE_MAX = 4000;
