// SPDX-License-Identifier: Apache-2.0

import type { ApiErrorBody } from './types';
import { randomUUID } from '../lib/cryptoCompat';

export const API_MODE: 'mock' | 'real' = import.meta.env.VITE_API === 'real' ? 'real' : 'mock';
const BASE = '/api/v1';
/** 브라우저가 직접 여는 링크(파일 받기 등)용 주소 */
export const apiUrl = (path: string) => BASE + path;

export class ApiError extends Error {
  readonly status: number;
  readonly body: ApiErrorBody;
  constructor(status: number, body: ApiErrorBody) {
    super(body.message || body.code);
    this.status = status;
    this.body = body;
  }
  get code(): string {
    return this.body.code;
  }
}

/** 세션 만료·연결 끊김을 앱 셸이 듣는다. */
export const apiEvents = new EventTarget();

/** 사람이 하지 않은 요청(주기 조회·다시 잇기). 이 signal로 보낸 요청에 X-SFC-Background: 1을 붙인다. */
const background = new WeakSet<AbortSignal>();
export function markBackground(signal: AbortSignal): void {
  background.add(signal);
}
export const isBackground = (signal?: AbortSignal) => !!signal && background.has(signal);

export interface RawResponse {
  status: number;
  json: unknown;
}

async function send(method: string, path: string, body?: unknown, signal?: AbortSignal, asText = false, extra?: Record<string, string>): Promise<RawResponse> {
  if (API_MODE === 'mock') {
    const { mockFetch } = await import('./mock/router');
    return mockFetch(method, path, body, signal, extra);
  }
  const headers: Record<string, string> = { ...extra, Accept: asText ? '*/*' : 'application/json' };
  if (method !== 'GET') headers['X-SFC-Web'] = '1';
  if (isBackground(signal)) headers['X-SFC-Background'] = '1';
  const raw = body instanceof Blob;
  if (body !== undefined) headers['Content-Type'] = raw ? 'application/octet-stream' : 'application/json';
  let res: Response;
  try {
    res = await fetch(BASE + path, {
      method,
      headers,
      body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
      credentials: 'same-origin',
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e;
    throw new ApiError(0, { code: 'transport', message: '웹 서버에 연결하지 못했습니다.' });
  }
  const text = await res.text();
  // 텍스트 응답(파일 내용)은 성공일 때 그대로 넘기고, 오류 본문은 보통처럼 JSON으로 읽는다
  if (asText && res.ok) return { status: res.status, json: text };
  let json: unknown = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = { error: { code: 'transport', message: '응답을 해석하지 못했습니다.' } };
    }
  }
  return { status: res.status, json };
}

export async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal, asText = false, extra?: Record<string, string>): Promise<T> {
  const { status, json } = await send(method, path, body, signal, asText, extra);
  if (status >= 200 && status < 300) return json as T;
  const found = (json as { error?: ApiErrorBody } | null)?.error;
  // 오류 옆에 붙은 자료(예: zone-changed의 changes, dns-invalid의 problems)는 raw로 넘긴다.
  const err: ApiErrorBody = found ? { ...found, raw: json } : { code: 'transport', message: `HTTP ${status}` };
  if (status === 401 && err.code === 'session-expired') apiEvents.dispatchEvent(new Event('session-expired'));
  if (err.code === 'disconnected') apiEvents.dispatchEvent(new Event('disconnected'));
  throw new ApiError(status, err);
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>('GET', path, undefined, signal),
  /** 본문을 글자 그대로 받는다(파일 내용). 오류는 get과 같게 처리한다 */
  text: (path: string, signal?: AbortSignal) => request<string>('GET', path, undefined, signal, true).then(String),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  /** 머리글을 더해 보낸다(작업 사유 X-SFC-Reason 등) */
  postWith: <T>(path: string, body: unknown, headers: Record<string, string>) => request<T>('POST', path, body, undefined, false, headers),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body ?? {}),
  del: <T>(path: string, body?: unknown) => request<T>('DELETE', path, body),
  /** 본문을 파일 그대로 보낸다(되살리기) */
  upload: <T>(path: string, file: Blob) => request<T>('POST', path, file),
  /** 아무 메서드로. 본문이 Blob이면 원본 그대로 보낸다 */
  raw: <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown) => request<T>(method, path, body),
};

/** 변경 요청마다 한 번 만든다. 같은 작업을 다시 물을 때는 같은 값을 다시 보낸다. */
export function newOpId(): string {
  return randomUUID();
}

export function q(params: Record<string, string | number | undefined | null>): string {
  const s = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') s.set(k, String(v));
  const t = s.toString();
  return t ? `?${t}` : '';
}

export const enc = encodeURIComponent;

/** 작업 사유 머리글. 퍼센트 인코딩한 UTF-8 한 줄(데몬 incident.go: 사유 512자, 사고 ID 128바이트까지) */
export function reasonHeaders(reason?: string, incident?: string): Record<string, string> {
  const h: Record<string, string> = {};
  const one = (v?: string) => (v ?? '').replace(/[\r\n\t]+/g, ' ').trim();
  if (one(reason)) h['X-SFC-Reason'] = encodeURIComponent(one(reason));
  if (one(incident)) h['X-SFC-Incident'] = encodeURIComponent(one(incident));
  return h;
}

/** 데몬에 아직 없는 끝점(계약 대기). 다른 404(지운 항목 등)와 가른다 */
export const noEndpoint = (e: unknown) => e instanceof ApiError && e.status === 404 && /no such API endpoint/i.test(e.body.message ?? '');
