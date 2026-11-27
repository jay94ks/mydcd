// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type KS = typeof import('./keystore');
const real = globalThis.crypto;
const ITER = 1000;

// keystore는 WebCrypto Ed25519 지원 여부를 모듈 안에 기억하므로 경로마다 새로 불러온다.
async function load(mode: 'webcrypto' | 'plain-http'): Promise<KS> {
  vi.resetModules();
  // 평문 HTTP 페이지: crypto.subtle·randomUUID가 없고 getRandomValues만 있다.
  vi.stubGlobal('crypto', mode === 'webcrypto' ? real : { getRandomValues: real.getRandomValues.bind(real) });
  return import('./keystore');
}

const bytes = (h: string) => Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16));
const verifies = async (publicKeyHex: string, msg: Uint8Array, sigHex: string) =>
  real.subtle.verify('Ed25519', await real.subtle.importKey('raw', bytes(publicKeyHex), 'Ed25519', false, ['verify']), bytes(sigHex), msg);
const toPem = (der: ArrayBuffer) => `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...new Uint8Array(der))).replace(/.{64}/g, '$&\n')}\n-----END PRIVATE KEY-----\n`;
const hexOf = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('');

beforeEach(() => {
  const m = new Map<string, string>();
  vi.stubGlobal('localStorage', { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) });
});
afterEach(() => vi.unstubAllGlobals());

const msg = new TextEncoder().encode('sfc-user-key-proof-1\0hello');

describe('keystore', () => {
  it('평문 HTTP에서도 키를 만들고 풀어 서명한다', async () => {
    const ks = await load('plain-http');
    expect(await ks.ed25519Supported()).toBe(true);
    const k = await ks.createKey('alice', 'laptop', 'passphrase-1', ITER);
    const priv = await ks.unlockKey(k, 'passphrase-1');
    expect(priv.kind).toBe('js');
    expect(await verifies(k.publicKey, msg, await ks.sign(priv, msg))).toBe(true);
    ks.forgetKey(priv);
    expect(priv.kind === 'js' && priv.seed.every((b) => b === 0)).toBe(true);
    await expect(ks.unlockKey(k, 'wrong-passphrase')).rejects.toThrow('암호 문구가 맞지 않습니다.');
  });

  it('WebCrypto로 만든 키를 평문 HTTP에서 풀고, 그 반대도 된다', async () => {
    let ks = await load('webcrypto');
    const a = await ks.createKey('alice', 'a', 'passphrase-1', ITER);
    ks = await load('plain-http');
    const b = await ks.createKey('alice', 'b', 'passphrase-2', ITER);
    const pa = await ks.unlockKey(a, 'passphrase-1');
    expect(await verifies(a.publicKey, msg, await ks.sign(pa, msg))).toBe(true);
    ks = await load('webcrypto');
    const pb = await ks.unlockKey(b, 'passphrase-2');
    expect(pb.kind).toBe('webcrypto');
    expect(await verifies(b.publicKey, msg, await ks.sign(pb, msg))).toBe(true);
  });

  it.each(['webcrypto', 'plain-http'] as const)('PKCS#8 PEM 개인키를 가져온다 (%s)', async (mode) => {
    const ks = await load(mode);
    const pair = (await real.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
    const pem = toPem(await real.subtle.exportKey('pkcs8', pair.privateKey));
    const pubHex = hexOf(await real.subtle.exportKey('raw', pair.publicKey));
    const k = await ks.importKey('admin', 'pem', pem, 'passphrase-1', ITER);
    expect(k.publicKey).toBe(pubHex);
    expect(k.registered).toBe(true);
    expect(JSON.stringify(ks.listKeys())).not.toContain(pem.split('\n')[1]);
    const priv = await ks.unlockKey(k, 'passphrase-1');
    expect(await verifies(pubHex, msg, await ks.sign(priv, msg))).toBe(true);
    await expect(ks.importKey('admin', 'again', pem, 'passphrase-1', ITER)).rejects.toThrow('이미');
  });

  it('Ed25519가 아니거나 암호화된 PEM은 받지 않는다', async () => {
    const ks = await load('plain-http');
    const ecPair = (await real.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])) as CryptoKeyPair;
    const ec = toPem(await real.subtle.exportKey('pkcs8', ecPair.privateKey));
    await expect(ks.importKey('admin', 'x', ec, 'passphrase-1', ITER)).rejects.toThrow('Ed25519 개인키가 아닙니다');
    await expect(ks.importKey('admin', 'x', '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n', 'passphrase-1', ITER)).rejects.toThrow('암호화된 PEM');
    await expect(ks.importKey('admin', 'x', 'hello', 'passphrase-1', ITER)).rejects.toThrow('PKCS#8 PEM');
  });
});
