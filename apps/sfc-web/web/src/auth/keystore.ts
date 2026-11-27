// SPDX-License-Identifier: Apache-2.0

// 브라우저 개인키 보관. 키는 이 브라우저에서 만들고 밖으로 내보내지 않는다.
// 개인키(PKCS#8)는 passphrase → PBKDF2-SHA256 → AES-GCM 키로 암호화해 localStorage에 둔다.
// 풀어 낸 키는 메모리에만 둔다. WebCrypto Ed25519가 있으면 non-extractable CryptoKey로,
// 없으면(평문 HTTP처럼 crypto.subtle이 없는 페이지, Ed25519를 모르는 브라우저) 번들에 넣은
// @noble 구현(순수 JS)으로 같은 형식을 만들고 푼다. 두 경로가 만든 키는 서로 바꿔 풀 수 있다.

// @noble 모듈은 쓸 때만 불러온다(메인 번들에 넣지 않는다). 불러온 뒤에는 같은 Promise를 쓴다.
const noble = {
  ed25519: () => import('@noble/curves/ed25519.js').then((m) => m.ed25519),
  gcm: () => import('@noble/ciphers/aes.js').then((m) => m.gcm),
  pbkdf2: () => Promise.all([import('@noble/hashes/pbkdf2.js'), import('@noble/hashes/sha2.js')]).then(([p, h]) => ({ pbkdf2Async: p.pbkdf2Async, sha256: h.sha256 })),
};
import { randomUUID } from '../lib/cryptoCompat';

const STORE_KEY = 'sfc.browser-keys.v1';
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

let subtleCache: Promise<boolean> | null = null;
/** WebCrypto로 Ed25519를 쓸 수 있는지. 없으면 순수 JS 구현을 쓴다. */
function subtleEd25519(): Promise<boolean> {
  subtleCache ??= (async () => {
    try {
      if (!globalThis.crypto?.subtle) return false;
      await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
      return true;
    } catch {
      return false;
    }
  })();
  return subtleCache;
}

/** 개인키 로그인을 쓸 수 있는지. 순수 JS 대체 구현이 있으므로 안전한 난수(getRandomValues)만 있으면 된다. */
export function ed25519Supported(): Promise<boolean> {
  return Promise.resolve(typeof globalThis.crypto?.getRandomValues === 'function');
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

/** 기본 사용자(로그인 화면에서 이름 칸이 비어 있을 때 채우는 이름) 바꾸기 */
export function setKeyUser(id: string, username: string) {
  writeKeys(listKeys().map((k) => (k.id === id ? { ...k, username } : k)));
}

export function markRegistered(id: string, registered: boolean) {
  writeKeys(listKeys().map((k) => (k.id === id ? { ...k, registered } : k)));
}

// Ed25519 개인키 PKCS#8(RFC 8410) = 이 머리 16바이트 + seed 32바이트. WebCrypto exportKey('pkcs8')와 같다.
const PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

function seedToPkcs8(seed: Uint8Array) {
  const out = new Uint8Array(PKCS8_PREFIX.length + 32);
  out.set(PKCS8_PREFIX);
  out.set(seed, PKCS8_PREFIX.length);
  return out;
}

function pkcs8ToSeed(pkcs8: Uint8Array) {
  if (pkcs8.length !== PKCS8_PREFIX.length + 32 || PKCS8_PREFIX.some((b, i) => pkcs8[i] !== b)) throw new Error('저장된 키 형식이 Ed25519 PKCS#8이 아닙니다.');
  return pkcs8.slice(PKCS8_PREFIX.length);
}

/** AES-GCM 암호화·복호화. crypto.subtle이 있으면 그것을, 없으면 @noble 구현을 쓴다. 결과(암호문||태그)는 같다. */
interface Wrap {
  encrypt(iv: Uint8Array, aad: Uint8Array, plain: Uint8Array): Promise<Uint8Array>;
  decrypt(iv: Uint8Array, aad: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
}

async function deriveWrapKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<Wrap> {
  const pass = new TextEncoder().encode(passphrase);
  if (globalThis.crypto?.subtle) {
    const base = await crypto.subtle.importKey('raw', pass, 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return {
      encrypt: async (iv, additionalData, plain) => new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, key, plain)),
      decrypt: async (iv, additionalData, data) => new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData }, key, data)),
    };
  }
  const [{ pbkdf2Async, sha256 }, gcm] = await Promise.all([noble.pbkdf2(), noble.gcm()]);
  const key = await pbkdf2Async(sha256, pass, salt, { c: iterations, dkLen: 32 });
  pass.fill(0);
  return {
    encrypt: async (iv, additionalData, plain) => gcm(key, iv, additionalData).encrypt(plain),
    decrypt: async (iv, additionalData, data) => gcm(key, iv, additionalData).decrypt(data),
  };
}

/** 풀어 낸 서명 키. 메모리에만 둔다. 다 쓰면 forgetKey로 지운다. */
export type UnlockedKey = { kind: 'webcrypto'; key: CryptoKey } | { kind: 'js'; seed: Uint8Array };

function aad(username: string, publicKey: string) {
  return new TextEncoder().encode(`sfc-web-key-1\x00${username}\x00${publicKey}`);
}

/** 새 키 쌍을 만들고 암호화해 저장한다. 등록(서버 credential 추가)은 호출한 쪽이 따로 한다. */
export async function createKey(username: string, label: string, passphrase: string, iterations = PBKDF2_ITERATIONS): Promise<StoredKey> {
  if (passphrase.length < 8) throw new Error('암호 문구는 8자 이상이어야 합니다.');
  let publicKey: string;
  let pkcs8: Uint8Array;
  if (await subtleEd25519()) {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    publicKey = hex(await crypto.subtle.exportKey('raw', pair.publicKey));
    pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  } else {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    publicKey = hex((await noble.ed25519()).getPublicKey(seed));
    pkcs8 = seedToPkcs8(seed);
    seed.fill(0);
  }
  try {
    return await storeKey(username, label, publicKey, pkcs8, passphrase, iterations, false);
  } finally {
    pkcs8.fill(0);
  }
}

/**
 * 이미 가진 Ed25519 개인키(PKCS#8 PEM, `sfcli key import`가 받는 것과 같은 형식)를 이 브라우저로 가져온다.
 * 원문은 저장하지 않고 새 키처럼 암호 문구로 암호화해 둔다. 가져온 키는 이미 계정에 등록된 것으로 보고
 * registered로 둔다. 등록되지 않은 키면 로그인 때 서버가 거절한다.
 */
export async function importKey(username: string, label: string, pem: string, passphrase: string, iterations = PBKDF2_ITERATIONS): Promise<StoredKey> {
  if (!username.trim()) throw new Error('사용자 이름을 넣어 주세요.');
  if (passphrase.length < 8) throw new Error('암호 문구는 8자 이상이어야 합니다.');
  const pkcs8 = parsePrivateKeyPem(pem);
  try {
    const publicKey = await publicKeyOf(pkcs8);
    if (listKeys().some((k) => k.publicKey === publicKey)) throw new Error('같은 키가 이미 이 브라우저에 있습니다. 다른 사용자로 쓰려면 로그인할 때 사용자 이름만 바꾸세요.');
    return await storeKey(username, label, publicKey, pkcs8, passphrase, iterations, true);
  } finally {
    pkcs8.fill(0);
  }
}

/** PKCS#8 개인키의 공개키 hex. WebCrypto Ed25519가 있으면 JWK의 x로 얻고, 없으면 @noble로 계산한다. */
async function publicKeyOf(pkcs8: Uint8Array): Promise<string> {
  if (await subtleEd25519()) {
    const k = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
    const x = (await crypto.subtle.exportKey('jwk', k)).x ?? '';
    return hex(b64d(x.replace(/-/g, '+').replace(/_/g, '/')));
  }
  const seed = pkcs8ToSeed(pkcs8);
  try {
    return hex((await noble.ed25519()).getPublicKey(seed));
  } finally {
    seed.fill(0);
  }
}

/** `-----BEGIN PRIVATE KEY-----` PEM 하나를 PKCS#8 바이트로 푼다. 암호화된 PEM과 다른 형식은 받지 않는다. */
export function parsePrivateKeyPem(pem: string): Uint8Array {
  const m = /^\s*-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----\s*$/.exec(pem);
  if (!m) {
    if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem)) throw new Error('암호화된 PEM은 가져올 수 없습니다. 암호를 푼 PKCS#8 PEM(BEGIN PRIVATE KEY)을 넣어 주세요.');
    throw new Error('PKCS#8 PEM(-----BEGIN PRIVATE KEY-----) 하나만 넣어 주세요.');
  }
  let der: Uint8Array;
  try {
    der = b64d(m[1].replace(/\s+/g, ''));
  } catch {
    throw new Error('PEM 본문이 base64가 아닙니다.');
  }
  if (der.length !== PKCS8_PREFIX.length + 32 || PKCS8_PREFIX.some((b, i) => der[i] !== b)) {
    der.fill(0);
    throw new Error('Ed25519 개인키가 아닙니다. Ed25519 PKCS#8 PEM만 가져올 수 있습니다.');
  }
  return der;
}

async function storeKey(username: string, label: string, publicKey: string, pkcs8: Uint8Array, passphrase: string, iterations: number, registered: boolean): Promise<StoredKey> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrap = await deriveWrapKey(passphrase, salt, iterations);
  const data = await wrap.encrypt(iv, aad(username, publicKey), pkcs8);
  const key: StoredKey = {
    id: randomUUID(),
    username,
    label,
    publicKey,
    createdAt: new Date().toISOString(),
    kdf: { name: 'PBKDF2-SHA256', iterations, salt: b64e(salt) },
    cipher: { name: 'AES-GCM', iv: b64e(iv), data: b64e(data) },
    registered,
  };
  writeKeys([...listKeys(), key]);
  return key;
}

/** passphrase로 풀어 서명 키를 돌려준다. 틀리면 예외. */
export async function unlockKey(key: StoredKey, passphrase: string): Promise<UnlockedKey> {
  const wrap = await deriveWrapKey(passphrase, b64d(key.kdf.salt), key.kdf.iterations);
  let pkcs8: Uint8Array;
  try {
    pkcs8 = await wrap.decrypt(b64d(key.cipher.iv), aad(key.username, key.publicKey), b64d(key.cipher.data));
  } catch {
    throw new Error('암호 문구가 맞지 않습니다.');
  }
  try {
    if (await subtleEd25519()) return { kind: 'webcrypto', key: await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']) };
    const seed = pkcs8ToSeed(pkcs8);
    if (hex((await noble.ed25519()).getPublicKey(seed)) !== key.publicKey.toLowerCase()) {
      seed.fill(0);
      throw new Error('저장된 개인키가 공개키와 맞지 않습니다.');
    }
    return { kind: 'js', seed };
  } finally {
    pkcs8.fill(0);
  }
}

export async function sign(privateKey: UnlockedKey, message: Uint8Array): Promise<string> {
  if (privateKey.kind === 'webcrypto') return hex(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey.key, message));
  return hex((await noble.ed25519()).sign(message, privateKey.seed));
}

/** 다 쓴 서명 키를 지운다. JS 구현이면 seed 바이트를 0으로 덮는다. */
export function forgetKey(privateKey: UnlockedKey) {
  if (privateKey.kind === 'js') privateKey.seed.fill(0);
}

export const decodeBase64 = b64d;

export function shortKey(publicKey: string) {
  return `${publicKey.slice(0, 4)}…${publicKey.slice(-4)}`;
}
