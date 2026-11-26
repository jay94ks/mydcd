// SPDX-License-Identifier: Apache-2.0

// 브라우저 개인키 보관. 키는 이 브라우저에서 만들고 밖으로 내보내지 않는다.
// 개인키(PKCS#8)는 passphrase → PBKDF2-SHA256 → AES-GCM 키로 암호화해 localStorage에 둔다.
// 풀어 낸 키는 non-extractable CryptoKey로 메모리에만 둔다.

const STORE_KEY = 'mydc.browser-keys.v1';
export const PBKDF2_ITERATIONS = 600_000;

export interface StoredKey {
  id: string;
  username: string;
  label: string;
  publicKey: string; // hex 64
  createdAt: string;
  kdf: { name: 'PBKDF2-SHA256'; iterations: number; salt: string };
  cipher: { name: 'AES-GCM'; iv: string; data: string };
  registered: boolean;
}

export const hex = (b: ArrayBuffer | Uint8Array) =>
  Array.from(b instanceof Uint8Array ? b : new Uint8Array(b))
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
const b64e = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...(b instanceof Uint8Array ? b : new Uint8Array(b))));
const b64d = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

let supportCache: Promise<boolean> | null = null;
/** Ed25519 WebCrypto 지원 여부. 지원하지 않으면 개인키 로그인을 끈다(JS 대체 구현 없음). */
export function ed25519Supported(): Promise<boolean> {
  supportCache ??= (async () => {
    try {
      if (!globalThis.crypto?.subtle) return false;
      await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
      return true;
    } catch {
      return false;
    }
  })();
  return supportCache;
}

export function listKeys(): StoredKey[] {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    return raw ? (JSON.parse(raw) as StoredKey[]) : [];
  } catch {
    return [];
  }
}

function writeKeys(keys: StoredKey[]) {
  localStorage.setItem(STORE_KEY, JSON.stringify(keys));
}

export function removeKey(id: string) {
  writeKeys(listKeys().filter((k) => k.id !== id));
}

export function markRegistered(id: string, registered: boolean) {
  writeKeys(listKeys().map((k) => (k.id === id ? { ...k, registered } : k)));
}

async function deriveWrapKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

function aad(username: string, publicKey: string) {
  return new TextEncoder().encode(`mydc-web-key-1\x00${username}\x00${publicKey}`);
}

/** 새 키 쌍을 만들고 암호화해 저장한다. 등록(서버 credential 추가)은 호출한 쪽이 따로 한다. */
export async function createKey(username: string, label: string, passphrase: string, iterations = PBKDF2_ITERATIONS): Promise<StoredKey> {
  if (passphrase.length < 8) throw new Error('암호 문구는 8자 이상이어야 합니다.');
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const publicKey = hex(await crypto.subtle.exportKey('raw', pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrap = await deriveWrapKey(passphrase, salt, iterations);
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(username, publicKey) }, wrap, pkcs8);
  pkcs8.fill(0);
  const key: StoredKey = {
    id: crypto.randomUUID(),
    username,
    label,
    publicKey,
    createdAt: new Date().toISOString(),
    kdf: { name: 'PBKDF2-SHA256', iterations, salt: b64e(salt) },
    cipher: { name: 'AES-GCM', iv: b64e(iv), data: b64e(data) },
    registered: false,
  };
  writeKeys([...listKeys(), key]);
  return key;
}

/** passphrase로 풀어 서명 전용(non-extractable) 키를 돌려준다. 틀리면 예외. */
export async function unlockKey(key: StoredKey, passphrase: string): Promise<CryptoKey> {
  const wrap = await deriveWrapKey(passphrase, b64d(key.kdf.salt), key.kdf.iterations);
  let pkcs8: Uint8Array;
  try {
    pkcs8 = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(key.cipher.iv), additionalData: aad(key.username, key.publicKey) }, wrap, b64d(key.cipher.data)),
    );
  } catch {
    throw new Error('암호 문구가 맞지 않습니다.');
  }
  try {
    return await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  } finally {
    pkcs8.fill(0);
  }
}

export async function sign(privateKey: CryptoKey, message: Uint8Array): Promise<string> {
  return hex(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, message));
}

export const decodeBase64 = b64d;

export function shortKey(publicKey: string) {
  return `${publicKey.slice(0, 4)}…${publicKey.slice(-4)}`;
}
