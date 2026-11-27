// SPDX-License-Identifier: Apache-2.0

// 보안 컨텍스트(HTTPS·localhost)에서만 있는 WebCrypto 기능의 대체.
// 첫 접속용 평문 HTTP(cluster_apps.web.port)에서도 화면이 돌게 한다.
// crypto.getRandomValues는 평문 HTTP에서도 있으므로 난수는 늘 그것을 쓴다.

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** RFC 4122 v4 UUID. crypto.randomUUID가 없으면 getRandomValues로 만든다. */
export function randomUUID(): string {
  if (typeof globalThis.crypto?.randomUUID === 'function') return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = toHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** SHA-256 hex. crypto.subtle이 없으면 @noble/hashes로 계산한다. */
export async function sha256Hex(data: Uint8Array | ArrayBuffer): Promise<string> {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  if (globalThis.crypto?.subtle) return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
  const { sha256 } = await import('@noble/hashes/sha2.js');
  return toHex(sha256(bytes));
}
